"""Canonical AMD64 symbolic state adapted from the mxoq extractor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from typing import cast

# Importing the boundary preloads libstdc++ before the Angr import below.
from extractor.angr_boundary import (
    Ast,
    State,
    angr as _angr,
    claripy as _claripy,
    expect_ast,
    expect_project,
    expect_state,
)
from extractor import z3_boundary as _z3
from extractor.artifact import MEM64_8, Declaration, TermSort

from angr.engines.vex.claripy import ccall as _angr_ccall
from claripy.backends.backend_z3 import BackendZ3
import z3


class Amd64AdapterError(RuntimeError):
    """The exact instruction does not satisfy the E5 adapter contract."""


GPR64 = (
    "rax",
    "rcx",
    "rdx",
    "rbx",
    "rsp",
    "rbp",
    "rsi",
    "rdi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
)
YMM256 = tuple(f"ymm{index}" for index in range(16))
FLAG_NAMES = ("CF", "ZF", "SF", "OF", "PF", "AF")
REGISTER_NAMES = GPR64 + YMM256 + ("rip",)
REGISTER_WIDTH = {name: 64 for name in (*GPR64, "rip")} | {
    name: 256 for name in YMM256
}
MEMORY_NAME = "mem"

LTS_EXTRACTION_CONTEXT = z3.Context()
_BZ3 = BackendZ3()
_U64_MAX = (1 << 64) - 1
_NO_STATEMENTS: frozenset[int] = frozenset()


def _ccall_constant(table: str, name: str) -> int:
    value = _angr_ccall.data["AMD64"][table][name]
    if value is None:
        raise Amd64AdapterError(f"missing AMD64 ccall constant: {table}.{name}")
    return value


_AMD64_OP_COPY = _ccall_constant("OpTypes", "G_CC_OP_COPY")
AMD64_FLAG_BIT: dict[str, int] = {
    "CF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_C"),
    "PF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_P"),
    "AF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_A"),
    "ZF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_Z"),
    "SF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_S"),
    "OF": _ccall_constant("CondBitOffsets", "G_CC_SHIFT_O"),
}


@dataclass(frozen=True, eq=False)
class MemoryWrite:
    address: z3.BitVecRef
    value: z3.BitVecRef
    size: int
    statement_index: int


def require_u64(value: object, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise Amd64AdapterError(f"{field} must be an unsigned 64-bit integer")
    return value


def _integer(value: object, field: str) -> int:
    if type(value) is not int:
        raise Amd64AdapterError(f"{field} is not an integer")
    return value


def require_bit_vector(value: object, field: str) -> z3.BitVecRef:
    if not isinstance(value, z3.BitVecRef):
        raise Amd64AdapterError(f"{field} is not a bit-vector expression")
    return value


def _expect_array(value: object, field: str) -> z3.ArrayRef:
    if not isinstance(value, z3.ArrayRef):
        raise Amd64AdapterError(f"{field} is not an array expression")
    return value


def require_boolean(value: object, field: str) -> z3.BoolRef:
    if not isinstance(value, z3.BoolRef):
        raise Amd64AdapterError(f"{field} is not a Boolean expression")
    return value


def _expect_bv_sort(value: object, field: str) -> z3.BitVecSortRef:
    if not isinstance(value, z3.BitVecSortRef):
        raise Amd64AdapterError(f"{field} is not a bit-vector sort")
    return value


def canonical_declarations() -> tuple[Declaration, ...]:
    return (
        tuple(
            Declaration(name, TermSort.bv(REGISTER_WIDTH[name]))
            for name in REGISTER_NAMES
        )
        + tuple(Declaration(f"rflags_{name}", TermSort.bv(1)) for name in FLAG_NAMES)
        + (Declaration(MEMORY_NAME, MEM64_8),)
    )


@lru_cache(maxsize=None)
def canonical_register(name: str) -> z3.BitVecRef:
    if name not in REGISTER_NAMES:
        raise Amd64AdapterError(f"unknown canonical AMD64 register {name!r}")
    return _z3.bit_vec(name, REGISTER_WIDTH[name], LTS_EXTRACTION_CONTEXT)


@lru_cache(maxsize=None)
def canonical_flag(name: str) -> z3.BitVecRef:
    if name not in FLAG_NAMES:
        raise Amd64AdapterError(f"unknown canonical AMD64 flag {name!r}")
    return _z3.bit_vec(
        f"rflags_{name}",
        1,
        LTS_EXTRACTION_CONTEXT,
    )


@lru_cache(maxsize=None)
def canonical_memory() -> z3.ArrayRef:
    address = _z3.bit_vec_sort(64, LTS_EXTRACTION_CONTEXT)
    byte = _z3.bit_vec_sort(8, LTS_EXTRACTION_CONTEXT)
    return _z3.array(MEMORY_NAME, address, byte)


def claripy_to_z3(ast: object) -> z3.ExprRef:
    """Cross the Angr boundary into the dedicated extraction context."""

    return _z3.translate(
        _BZ3,
        expect_ast(ast, "Claripy expression"),
        LTS_EXTRACTION_CONTEXT,
    )


def load_le(
    memory: z3.ArrayRef,
    address: z3.BitVecRef,
    size: int,
) -> z3.BitVecRef:
    """Load one byte-aligned little-endian value from canonical memory."""

    _require_memory_shape(memory, address)
    if type(size) is not int or size <= 0:
        raise Amd64AdapterError("memory access size must be positive")
    bytes_high_to_low = tuple(
        require_bit_vector(
            _z3.select(
                memory,
                address
                + _z3.bit_vec_val(
                    offset,
                    64,
                    LTS_EXTRACTION_CONTEXT,
                ),
            ),
            "memory load byte",
        )
        for offset in reversed(range(size))
    )
    if len(bytes_high_to_low) == 1:
        return bytes_high_to_low[0]
    return _z3.concat(*bytes_high_to_low)


def store_le(
    memory: z3.ArrayRef,
    address: z3.BitVecRef,
    value: z3.BitVecRef,
    size: int,
) -> z3.ArrayRef:
    """Store one byte-aligned little-endian value into canonical memory."""

    _require_memory_shape(memory, address)
    if (
        type(size) is not int
        or size <= 0
        or value.ctx != LTS_EXTRACTION_CONTEXT
        or value.size() != size * 8
    ):
        raise Amd64AdapterError("memory store value has the wrong width")
    result = memory
    for offset in range(size):
        result = _expect_array(
            _z3.store(
                result,
                address
                + _z3.bit_vec_val(
                    offset,
                    64,
                    LTS_EXTRACTION_CONTEXT,
                ),
                _z3.extract(offset * 8 + 7, offset * 8, value),
            ),
            "updated memory",
        )
    return result


def _require_memory_shape(
    memory: z3.ArrayRef,
    address: z3.BitVecRef,
) -> None:
    if (
        not z3.is_array(memory)
        or memory.ctx != LTS_EXTRACTION_CONTEXT
        or _expect_bv_sort(memory.domain(), "memory domain").size() != 64
        or _expect_bv_sort(memory.range(), "memory range").size() != 8
        or address.ctx != LTS_EXTRACTION_CONTEXT
        or address.size() != 64
    ):
        raise Amd64AdapterError(
            "memory and address must be extraction-context BV64-to-BV8/BV64"
        )


def source_rip_guard(source: int) -> z3.BoolRef:
    source = require_u64(source, "source")
    return require_boolean(
        canonical_register("rip")
        == _z3.bit_vec_val(
            source,
            64,
            LTS_EXTRACTION_CONTEXT,
        ),
        "source RIP guard",
    )


def require_mirrored_rip(
    target: z3.ExprRef,
    post_rip: z3.ExprRef,
) -> None:
    target_bv = require_bit_vector(target, "target")
    post_rip_bv = require_bit_vector(post_rip, "post-rip")
    if (
        target_bv.size() != 64
        or post_rip_bv.size() != 64
        or target_bv.ctx != LTS_EXTRACTION_CONTEXT
        or post_rip_bv.ctx != LTS_EXTRACTION_CONTEXT
    ):
        raise Amd64AdapterError(
            "target and post-rip must be extraction-context BV64 expressions"
        )
    solver = z3.Solver(ctx=LTS_EXTRACTION_CONTEXT)
    disagreement = require_boolean(target_bv != post_rip_bv, "RIP disagreement")
    _z3.solver_add(solver, disagreement)
    if _z3.solver_check(solver) != z3.unsat:
        raise Amd64AdapterError("target and post-rip disagree semantically")


def _seed_flag_bvs() -> dict[str, Ast]:
    return {
        name: _claripy.BVS(
            f"rflags_{name}",
            1,
            explicit_name=True,
        )
        for name in FLAG_NAMES
    }


def _initial_cc_dep1(flag_bvs: Mapping[str, Ast]) -> Ast:
    pieces: list[Ast] = []
    next_bit = 63
    for name, bit in sorted(
        AMD64_FLAG_BIT.items(),
        key=lambda item: -item[1],
    ):
        if next_bit > bit:
            pieces.append(_claripy.BVV(0, next_bit - bit))
        pieces.append(flag_bvs[name])
        next_bit = bit - 1
    if next_bit >= 0:
        pieces.append(_claripy.BVV(0, next_bit + 1))
    return _claripy.Concat(*pieces)


def _access_size(value: object, field: str) -> int:
    try:
        if type(value) is int:
            size = value
        else:
            ast = expect_ast(value, field)
            size = _integer(ast.args[0], field) if ast.op == "BVV" else 0
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        raise Amd64AdapterError(f"{field} has unknown or invalid width")
    return size


def _preserve_symbolic_memory_addresses(raw_state: object) -> None:
    """Keep hooked memory accesses parametric in their symbolic addresses."""

    state = expect_state(raw_state)
    if state.inspect.address_concretization_action in {"load", "store"}:
        state.inspect.address_concretization_add_constraints = False


def _memory_read_hook(raw_state: object) -> None:
    state = expect_state(raw_state)
    address = state.inspect.mem_read_address
    if address is None:
        raise Amd64AdapterError("memory read is missing its address")
    if state.inspect.mem_read_expr is not None:
        raise Amd64AdapterError("memory read already has a value before loading")
    size = _access_size(state.inspect.mem_read_length, "memory read")

    address_z3 = require_bit_vector(
        claripy_to_z3(address),
        "memory read address",
    )
    classified_address_z3 = address_z3

    def record(kind: str) -> None:
        events = _memory_read_events(state)
        state.globals["_ghot_memory_read_events"] = events + (
            (kind, size, str(_z3.simplify(classified_address_z3))),
        )

    fixed_bytes: list[int] = []
    for offset in range(size):
        byte_address = classified_address_z3 + _z3.bit_vec_val(
            offset,
            classified_address_z3.size(),
            LTS_EXTRACTION_CONTEXT,
        )
        matches = [
            value
            for expected, value in _fixed_byte_reads(state)
            if z3.is_true(
                _z3.simplify(
                    require_boolean(byte_address == expected, "fixed-byte match")
                )
            )
        ]
        if len(matches) > 1:
            raise Amd64AdapterError("memory read matches multiple fixed input bytes")
        if not matches:
            fixed_bytes = []
            break
        fixed_bytes.append(matches[0])
    if fixed_bytes:
        little_endian = sum(
            value << (offset * 8) for offset, value in enumerate(fixed_bytes)
        )
        state.inspect.mem_read_expr = _claripy.BVV(little_endian, size * 8)
        record("fixed")
        counts = _memory_read_counts(state)
        counts["fixed"] = counts.get("fixed", 0) + 1
        state.globals["_ghot_memory_read_counts"] = counts
        return

    record("symbolic")
    counts = _memory_read_counts(state)
    counts["symbolic"] = counts.get("symbolic", 0) + 1
    state.globals["_ghot_memory_read_counts"] = counts
    placeholders = memory_reads(state)
    name = f"__ghot_memory_read_{len(placeholders)}__"
    placeholder = _claripy.BVS(name, size * 8, explicit_name=True)
    placeholders[name] = (
        address,
        size,
        memory_expression(state),
    )
    state.globals["_ghot_memory_reads"] = placeholders
    state.inspect.mem_read_expr = placeholder


def _memory_write_hook(raw_state: object) -> None:
    state = expect_state(raw_state)
    address = state.inspect.mem_write_address
    value = state.inspect.mem_write_expr
    if address is None or value is None:
        raise Amd64AdapterError("memory write is missing address or value")
    size = _access_size(state.inspect.mem_write_length, "memory write")
    address_z3 = require_bit_vector(claripy_to_z3(address), "memory write address")
    value_z3 = require_bit_vector(claripy_to_z3(value), "memory write value")
    current = memory_expression(state)
    updated = store_le(current, address_z3, value_z3, size)
    writes = list(memory_writes(state))
    scratch: object = state.scratch
    statement_index = _integer(
        getattr(scratch, "stmt_idx", None), "VEX memory-write statement index"
    )
    writes.append(MemoryWrite(address_z3, value_z3, size, statement_index))
    state.globals["_ghot_memory_expr"] = updated
    state.globals["_ghot_memory_writes"] = tuple(writes)


def fresh_instruction_state(
    raw_project: object,
    source: int,
    vex_scratch_writes: frozenset[int] | None = None,
) -> State:
    """Create the canonical symbolic pre-state for one real instruction."""

    project = expect_project(raw_project)
    source = require_u64(source, "source")
    if project.arch.name != "AMD64" or project.arch.bits != 64:
        raise Amd64AdapterError(
            f"unexpected architecture: {project.arch.name}/{project.arch.bits}"
        )
    state = project.factory.blank_state(addr=source)
    state.options.add(_angr.options.TRACK_MEMORY_ACTIONS)
    state.options.add(_angr.options.TRACK_REGISTER_ACTIONS)
    state.options.add(_angr.options.SYMBOLIC_WRITE_ADDRESSES)
    state.options.add(_angr.options.UNDER_CONSTRAINED_SYMEXEC)
    state.options.discard(_angr.options.UNICORN)
    for name in (*GPR64, *YMM256):
        setattr(
            state.regs,
            name,
            _claripy.BVS(name, REGISTER_WIDTH[name], explicit_name=True),
        )
    state.regs.rip = _claripy.BVV(source, 64)

    flag_bvs = _seed_flag_bvs()
    state.regs.cc_op = _claripy.BVV(_AMD64_OP_COPY, 64)
    state.regs.cc_dep1 = _initial_cc_dep1(flag_bvs)
    state.regs.cc_dep2 = _claripy.BVV(0, 64)
    state.regs.cc_ndep = _claripy.BVV(0, 64)
    state.globals["_ghot_flag_bvs"] = flag_bvs
    state.globals["_ghot_memory_expr"] = canonical_memory()
    state.globals["_ghot_memory_reads"] = {}
    state.globals["_ghot_memory_writes"] = ()
    state.globals["_ghot_vex_scratch_writes"] = vex_scratch_writes or _NO_STATEMENTS
    state.inspect.b(
        "address_concretization",
        when=_angr.BP_BEFORE,
        action=_preserve_symbolic_memory_addresses,
    )
    state.inspect.b(
        "mem_read",
        when=_angr.BP_BEFORE,
        action=_memory_read_hook,
    )
    state.inspect.b(
        "mem_write",
        when=_angr.BP_AFTER,
        action=_memory_write_hook,
    )
    return state


MemoryReads = dict[str, tuple[Ast, int, z3.ArrayRef]]


def memory_expression(state: State) -> z3.ArrayRef:
    return _expect_array(state.globals["_ghot_memory_expr"], "current memory")


def memory_reads(state: State) -> MemoryReads:
    return cast(MemoryReads, state.globals.get("_ghot_memory_reads", {})).copy()


def memory_writes(state: State) -> tuple[MemoryWrite, ...]:
    return cast(tuple[MemoryWrite, ...], state.globals.get("_ghot_memory_writes", ()))


def architectural_memory_expression(state: State) -> z3.ArrayRef | None:
    """Exclude only stores tagged as documented VEX implementation scratch."""

    scratch = cast(
        frozenset[int], state.globals.get("_ghot_vex_scratch_writes", _NO_STATEMENTS)
    )
    result, retained = canonical_memory(), False
    for write in memory_writes(state):
        if write.statement_index not in scratch:
            result = store_le(result, write.address, write.value, write.size)
            retained = True
    return result if retained else None


def _fixed_byte_reads(state: State) -> tuple[tuple[z3.BitVecRef, int], ...]:
    return cast(
        tuple[tuple[z3.BitVecRef, int], ...],
        state.globals.get("_ghot_fixed_byte_reads", ()),
    )


def _memory_read_counts(state: State) -> dict[str, int]:
    return cast(
        dict[str, int], state.globals.get("_ghot_memory_read_counts", {})
    ).copy()


def _memory_read_events(state: State) -> tuple[tuple[str, int, str], ...]:
    return cast(
        tuple[tuple[str, int, str], ...],
        state.globals.get("_ghot_memory_read_events", ()),
    )


def resolve_memory_reads(
    expression: z3.ExprRef,
    reads: Mapping[str, tuple[Ast, int, z3.ArrayRef]],
) -> z3.ExprRef:
    replacements: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, (address, size, memory_at_read) in reads.items():
        address_z3 = require_bit_vector(claripy_to_z3(address), "memory read address")
        if replacements:
            address_z3 = require_bit_vector(
                _z3.substitute(address_z3, *replacements),
                "resolved memory read address",
            )
            memory_at_read = _expect_array(
                _z3.substitute(memory_at_read, *replacements),
                "resolved memory-at-read",
            )
        placeholder = _z3.bit_vec(
            name,
            size * 8,
            LTS_EXTRACTION_CONTEXT,
        )
        replacements.append((placeholder, load_le(memory_at_read, address_z3, size)))
    if replacements:
        return _z3.substitute(expression, *replacements)
    return expression
