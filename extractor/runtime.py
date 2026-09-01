"""Hermetic Angr runtime probe used by the extractor bootstrap."""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import site
import sys
from pathlib import Path
from typing import Any, Never

from extractor.native_runtime import (
    preload_libstdcxx as _preload_libstdcxx,
)
from extractor.native_runtime import (
    runfiles_root as _runfiles_root,
)

_EXPECTED_PYTHON = (3, 12, 13)
_EXPECTED_SOLVED_VALUE = 0x1234
_EXPECTED_VEX_INSTRUCTIONS = 2
_EXPECTED_TOP_LEVEL_VERSIONS = {
    "angr": "9.2.214",
    "coverage": "7.15.2",
    "hypothesis": "6.160.0",
    "mutmut": "3.6.0",
    "pytest": "9.1.1",
    "unicorn": "2.1.4",
}
_REQUIRED_MODULES = (
    "angr",
    "archinfo",
    "capstone",
    "claripy",
    "cle",
    "coverage",
    "hypothesis",
    "mutmut",
    "pytest",
    "pyvex",
    "unicorn",
    "z3",
)


_LIBSTDCXX = _preload_libstdcxx()

import angr  # noqa: E402
import claripy  # noqa: E402

__all__ = ["angr", "claripy"]


def _fixture_bytes() -> bytes:
    fixture_path = Path(__file__).with_name("amd64_smoke.hex")
    return bytes.fromhex(fixture_path.read_text(encoding="ascii"))


def _fail(message: str) -> Never:
    raise RuntimeError(message)


def _assert_python_environment() -> None:
    actual_python = sys.version_info[:3]
    if actual_python != _EXPECTED_PYTHON:
        message = f"unexpected Python: {actual_python!r}; expected {_EXPECTED_PYTHON!r}"
        _fail(message)
    if os.environ.get("PYTHONNOUSERSITE") != "1":
        _fail("PYTHONNOUSERSITE=1 is required")
    if os.environ.get("PYTHONSAFEPATH") != "1" or not sys.flags.safe_path:
        _fail("Python safe-path mode is required")
    if site.ENABLE_USER_SITE:
        _fail("user site-packages are enabled")


def _assert_clean_sys_path() -> None:
    user_site = Path(site.getusersitepackages()).resolve()
    for entry in sys.path:
        if not entry:
            _fail("the current working directory leaked into sys.path")
        if Path(entry).resolve() == user_site:
            _fail(f"user site-packages leaked into sys.path: {entry}")


def _module_origin(module_name: str, runfiles_root: Path) -> str:
    module = importlib.import_module(module_name)
    raw_origin = getattr(module, "__file__", None)
    if not raw_origin:
        _fail(f"{module_name} has no inspectable import origin")
    origin = Path(raw_origin).absolute()
    if not origin.is_relative_to(runfiles_root):
        message = "{} escaped Bazel runfiles: {} (root {})".format(
            module_name,
            origin,
            runfiles_root,
        )
        _fail(message)
    if not origin.is_file():
        _fail(f"{module_name} import is missing: {origin}")
    return str(origin)


def _assert_module_origins(runfiles_root: Path) -> dict[str, str]:
    return {
        module_name: _module_origin(module_name, runfiles_root)
        for module_name in _REQUIRED_MODULES
    }


def _assert_versions() -> None:
    for distribution, expected in _EXPECTED_TOP_LEVEL_VERSIONS.items():
        actual = importlib.metadata.version(distribution)
        if actual != expected:
            _fail(f"unexpected {distribution} version: {actual}; expected {expected}")


def _assert_hermetic_imports() -> dict[str, str]:
    _assert_python_environment()
    _assert_clean_sys_path()
    module_origins = _assert_module_origins(_runfiles_root())
    _assert_versions()
    return module_origins


def run_probe() -> dict[str, Any]:
    """Lift a declared AMD64 fixture and solve a small symbolic constraint."""
    module_origins = _assert_hermetic_imports()
    project = angr.load_shellcode(
        _fixture_bytes(),
        arch="amd64",
        load_address=0x400000,
    )
    block = project.factory.block(0x400000, size=4)
    mnemonics = [instruction.mnemonic for instruction in block.capstone.insns]
    if mnemonics != ["mov", "ret"]:
        _fail(f"unexpected Capstone decode: {mnemonics!r}")
    if (
        block.vex.instructions != _EXPECTED_VEX_INSTRUCTIONS
        or block.vex.jumpkind != "Ijk_Ret"
    ):
        message = "unexpected VEX lift: instructions={}, jumpkind={}".format(
            block.vex.instructions,
            block.vex.jumpkind,
        )
        _fail(message)

    symbolic = claripy.BVS("e1_smoke_value", 64)
    solver = claripy.Solver()
    solver.add(symbolic + 1 == _EXPECTED_SOLVED_VALUE + 1)
    solved = solver.eval(symbolic, 1)
    if solved != (_EXPECTED_SOLVED_VALUE,):
        _fail(f"unexpected Claripy result: {solved!r}")

    return {
        "arch": project.arch.name,
        "jumpkind": block.vex.jumpkind,
        "mnemonics": mnemonics,
        "module_origins": module_origins,
        "native_runtime": str(_LIBSTDCXX),
        "python": ".".join(str(part) for part in sys.version_info[:3]),
        "solution": solved[0],
    }
