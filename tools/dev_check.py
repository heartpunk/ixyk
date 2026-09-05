# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Check the development environment without launching builds or services."""

import ctypes
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys


def check() -> None:
    root = Path.cwd()
    if not (root / "flake.nix").is_file() or not (root / "lean-toolchain").is_file():
        raise ValueError("run ixyk-dev-check from the ixyk repository root")
    for name in (
        "python", "bazel", "lean", "lake", "ruff", "buildifier", "actionlint",
        "basedpyright", "git", "jj", "zstd",
    ):
        if not shutil.which(name):
            raise ValueError(f"missing {name}; enter nix develop or use ixyk-dev")
    python_root = os.environ.get("IXYK_NIX_PYTHON_ROOT", "")
    if not python_root.startswith("/nix/store/"):
        raise ValueError("IXYK_NIX_PYTHON_ROOT is missing; enter nix develop or use ixyk-dev")
    runtime_root = os.environ.get("IXYK_NIX_PYTHON_RUNTIME", "")
    if not runtime_root.startswith("/nix/store/") or not Path(runtime_root, "bin/python3.12").is_file():
        raise ValueError("IXYK_NIX_PYTHON_RUNTIME must identify the Nix Python runtime")
    if sys.version_info[:2] != (3, 12):
        raise ValueError(f"expected Python 3.12, got {sys.version}")
    selected_python = subprocess.check_output(
        ["python", "-c", "import sys; print(sys.executable)"], text=True
    ).strip()
    if Path(selected_python).resolve() != Path(python_root, "bin/python").resolve():
        raise ValueError("python on PATH differs from the declared Nix environment")
    for name, command, expected, pattern in (
        ("Bazel", ["bazel", "--version"], (root / ".bazelversion").read_text().strip(),
         r"bazel (\d+\.\d+\.\d+)(?:- \(@non-git\))?\s*$"),
        ("Lean", ["lean", "--version"],
         (root / "lean-toolchain").read_text().strip().removeprefix("leanprover/lean4:v"),
         r"Lean \(version ([^,\s]+)"),
    ):
        output = subprocess.check_output(command, text=True)
        match = re.search(pattern, output)
        if not match or match[1] != expected:
            raise ValueError(f"{name}: expected {expected}, got {output.strip()}")
        print(f"{name} {expected}: OK", flush=True)
    if not sys.flags.no_user_site or not sys.flags.safe_path:
        raise ValueError("Python user-site and unsafe path imports must be disabled")
    if platform.system() == "Linux":
        library_root = os.environ.get("IXYK_NIX_LIBSTDCXX_ROOT", "")
        if not library_root.startswith("/nix/store/"):
            raise ValueError("IXYK_NIX_LIBSTDCXX_ROOT must identify a Nix store output")
        ctypes.CDLL(str(Path(library_root) / "lib/libstdc++.so.6"))

    import angr
    import claripy
    import coverage
    import hypothesis
    import ipykernel
    import pytest
    import unicorn
    import z3

    # Import developer dependencies and exercise the native engines with tiny,
    # deterministic inputs. No repository imports or Bazel downloads are needed.
    _ = coverage, hypothesis, ipykernel, pytest
    x = claripy.BVS("dev_check", 8)
    solver = claripy.Solver()
    solver.add(x + 1 == 2)
    if solver.eval(x, 1) != (1,):
        raise ValueError("Claripy solver smoke check failed")
    if not z3.is_true(z3.simplify(z3.BitVecVal(1, 8) + 1 == 2)):
        raise ValueError("Z3 smoke check failed")
    project = angr.load_shellcode(b"\x90", arch="amd64", load_address=0x1000)
    if project.factory.block(0x1000, size=1).instructions != 1:
        raise ValueError("angr instruction lifting failed")
    emulator = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
    emulator.mem_map(0x1000, 0x1000)
    emulator.mem_write(0x1000, b"\x90")
    emulator.emu_start(0x1000, 0x1001, count=1)
    print("Python dependencies, native libraries, lifting and emulation: OK")
    if (platform.system(), platform.machine()) == ("Linux", "x86_64"):
        print("Linux x86-64 development environment: ready.")
        print("Bazel REAPI tests additionally require a compatible executor; none was started or checked.")
    else:
        print("Development tools: ready. Bazel validation requires a Linux x86-64 client and executor.")


if __name__ == "__main__":
    try:
        check()
    except (OSError, ValueError, ImportError, subprocess.CalledProcessError) as error:
        print(f"ixyk-dev-check: {error}", file=sys.stderr)
        raise SystemExit(1) from error
