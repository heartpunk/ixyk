# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Instruction-interface operations backed by XED, independent of model AU."""

from collections.abc import Mapping
from functools import cache
import json
import subprocess
from typing import TypedDict, cast

from extractor.native_runtime import runfiles_root


class EncodingError(ValueError):
    pass


# "class" is the field name in XED's process protocol.
RegisterInfo = TypedDict(
    "RegisterInfo",
    {"name": str, "parent": str, "width": int, "class": str, "value": int},
)


class OperandInfo(TypedDict):
    name: str
    visibility: str
    width: int
    action: str
    register: RegisterInfo


class InstructionInfo(TypedDict):
    hex: str
    length: int
    form: str
    iclass: str
    operands: list[OperandInfo]
    base: RegisterInfo
    index: RegisterInfo
    scale: int
    displacement: int
    displacement_width: int
    branch: int
    branch_width: int
    immediate: int
    immediate_signed: bool
    immediate_width: int


def _invoke(*arguments: str) -> object:
    executable = runfiles_root() / "_main/extractor/xed_bridge"
    result = subprocess.run(
        [str(executable), *arguments], capture_output=True, text=True
    )
    if result.returncode:
        raise EncodingError(result.stderr.strip())
    return cast(object, json.loads(result.stdout))


def decode(code: bytes) -> InstructionInfo:
    return cast(InstructionInfo, _invoke(code.hex()))


@cache
def registers() -> tuple[RegisterInfo, ...]:
    return tuple(cast(list[RegisterInfo], _invoke("registers")))


def shape(decoded: InstructionInfo) -> tuple[object, ...]:
    """The encoding form and operand structure that perturbations preserve."""
    return (
        decoded["form"],
        decoded["iclass"],
        decoded["length"],
        tuple(
            (
                op["name"],
                op["visibility"],
                op["width"],
                op["action"],
                op["register"]["class"],
                op["register"]["width"],
                op["register"]["name"] if op["visibility"] != "EXPLICIT" else None,
            )
            for op in decoded["operands"]
        ),
        decoded["branch_width"],
        decoded["displacement_width"],
        decoded["immediate_width"],
        decoded["immediate_signed"],
    )


def operand_values(decoded: InstructionInfo) -> dict[str, str | int]:
    return {
        operand["name"]: operand["register"]["name"]
        for operand in decoded["operands"]
        if operand["register"]["name"] != "INVALID"
    } | {
        "BASE0": decoded["base"]["name"],
        "INDEX": decoded["index"]["name"],
        "SCALE": decoded["scale"],
        "DISP": decoded["displacement"],
        "RELBR": decoded["branch"],
        "IMM0": decoded["immediate"],
    }


def encode(code: bytes, replacements: Mapping[str, str | int]) -> bytes:
    before = decode(code)
    arguments = [
        part for field, value in replacements.items() for part in (field, str(value))
    ]
    after = cast(InstructionInfo, _invoke(code.hex(), *arguments))
    if shape(before) != shape(after):
        raise EncodingError("encoding changed instruction form or length")
    if operand_values(after) != operand_values(before) | dict(replacements):
        raise EncodingError("encoded operands do not match request")
    return bytes.fromhex(after["hex"])


def relative_target(decoded: InstructionInfo, source: int) -> int:
    if not decoded["branch_width"]:
        raise EncodingError("instruction has no relative branch operand")
    return (source + decoded["length"] + decoded["branch"]) % (1 << 64)


@cache
def _native():
    import ctypes

    library = ctypes.CDLL(str(runfiles_root() / "_main/extractor/xed_native.so"))
    library.ixyk_native_init()
    library.ixyk_native_encode.argtypes = [
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint64),
        ctypes.c_uint,
    ]
    library.ixyk_native_encode.restype = ctypes.c_void_p
    library.ixyk_native_error.restype = ctypes.c_char_p
    library.ixyk_native_free.argtypes = [ctypes.c_void_p]
    return library


def encode_constructor(index: int, values) -> InstructionInfo:
    """Use the existing ENC2 constructor without launching a subprocess."""
    import ctypes

    library = _native()
    arguments = (ctypes.c_uint64 * len(values))(*values)
    pointer = library.ixyk_native_encode(index, arguments, len(values))
    if not pointer:
        raise EncodingError(library.ixyk_native_error().decode())
    try:
        return json.loads(ctypes.string_at(pointer))
    finally:
        library.ixyk_native_free(pointer)
