"""Canonical AMD64 symbolic state adapted from the mxoq extractor."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
import logging
from typing import Any, ClassVar, override

# This import preloads libstdc++ before the Angr imports that follow it.
from extractor import runtime

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
FLAG_NAMES = ("CF", "ZF", "SF", "OF", "PF", "AF")
REGISTER_NAMES = GPR64 + ("rip",)
MEMORY_NAME = "mem"

LTS_EXTRACTION_CONTEXT = z3.Context()
_BZ3 = BackendZ3()
_U64_MAX = (1 << 64) - 1

_angr = runtime.angr
_claripy = runtime.claripy


class _ExpectedSymbolicExitFilter(logging.Filter):
    """Hide only Angr's expected diagnostic for our symbolic return edge."""

    _PREFIX: ClassVar[str] = (
        "Exit state has over 256 possible solutions. "
        "Likely unconstrained; skipping."
    )

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.getMessage().startswith(self._PREFIX)


logging.getLogger("angr.engines.successors").addFilter(
    _ExpectedSymbolicExitFilter()
)


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


@dataclass(frozen=True)
class CanonicalDeclaration:
    name: str
    sort: str
    width: int
    index_width: int | None = None


@dataclass(frozen=True)
class RegisterInstructionStep:
    source: int
    target: int
    source_guard: z3.BoolRef
    updates: Mapping[str, z3.ExprRef]


@dataclass(frozen=True, eq=False)
class MemoryWrite:
    address: z3.BitVecRef
    value: z3.BitVecRef
    size: int


@dataclass(frozen=True)
class MemoryInstructionStep:
    source: int
    target: int
    source_guard: z3.BoolRef
    updates: Mapping[str, z3.ExprRef]
    read_count: int
    writes: tuple[MemoryWrite, ...]


@dataclass(frozen=True)
class StaticOutcomeIdentity:
    outcome_id: int
    kind: str
    vex_exit_statement_index: int | None


@dataclass(frozen=True)
class InstructionOutcome:
    identity: StaticOutcomeIdentity
    guard: z3.BoolRef
    updates: Mapping[str, z3.ExprRef]
    target: z3.BitVecRef
    target_value: int | None
    jumpkind: str
    writes: tuple[MemoryWrite, ...]


@dataclass(frozen=True)
class InstructionOutcomeFamily:
    source: int
    source_guard: z3.BoolRef
    outcomes: tuple[InstructionOutcome, ...]


def _u64(value: Any, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise Amd64AdapterError(f"{field} must be an unsigned 64-bit integer")
    return value


def _expect_bv(value: object, field: str) -> z3.BitVecRef:
    if not isinstance(value, z3.BitVecRef):
        raise Amd64AdapterError(f"{field} is not a bit-vector expression")
    return value


def _expect_array(value: object, field: str) -> z3.ArrayRef:
    if not isinstance(value, z3.ArrayRef):
        raise Amd64AdapterError(f"{field} is not an array expression")
    return value


def _expect_bool(value: object, field: str) -> z3.BoolRef:
    if not isinstance(value, z3.BoolRef):
        raise Amd64AdapterError(f"{field} is not a Boolean expression")
    return value


def _expect_bv_sort(value: object, field: str) -> z3.BitVecSortRef:
    if not isinstance(value, z3.BitVecSortRef):
        raise Amd64AdapterError(f"{field} is not a bit-vector sort")
    return value


def canonical_declarations() -> tuple[CanonicalDeclaration, ...]:
    return (
        tuple(
            CanonicalDeclaration(name, "bv", 64)
            for name in REGISTER_NAMES
        )
        + tuple(
            CanonicalDeclaration(f"rflags_{name}", "bv", 1)
            for name in FLAG_NAMES
        )
        + (CanonicalDeclaration(MEMORY_NAME, "array", 8, 64),)
    )


def declaration(name: str) -> CanonicalDeclaration:
    for item in canonical_declarations():
        if item.name == name:
            return item
    raise Amd64AdapterError(f"unknown canonical AMD64 declaration {name!r}")


@lru_cache(maxsize=None)
def canonical_register(name: str) -> z3.BitVecRef:
    if name not in REGISTER_NAMES:
        raise Amd64AdapterError(f"unknown canonical AMD64 register {name!r}")
    return z3.BitVec(name, 64, ctx=LTS_EXTRACTION_CONTEXT)


@lru_cache(maxsize=None)
def canonical_flag(name: str) -> z3.BitVecRef:
    if name not in FLAG_NAMES:
        raise Amd64AdapterError(f"unknown canonical AMD64 flag {name!r}")
    return z3.BitVec(
        f"rflags_{name}",
        1,
        ctx=LTS_EXTRACTION_CONTEXT,
    )


@lru_cache(maxsize=None)
def canonical_memory() -> z3.ArrayRef:
    address = z3.BitVecSort(64, ctx=LTS_EXTRACTION_CONTEXT)
    byte = z3.BitVecSort(8, ctx=LTS_EXTRACTION_CONTEXT)
    return _expect_array(z3.Array(MEMORY_NAME, address, byte), "canonical memory")


def claripy_to_z3(ast: Any) -> z3.ExprRef:
    """Cross the Angr boundary into the dedicated extraction context."""

    return _BZ3.convert(ast).translate(LTS_EXTRACTION_CONTEXT)


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
        _expect_bv(
            z3.Select(
                memory,
                address + z3.BitVecVal(
                    offset,
                    64,
                    ctx=LTS_EXTRACTION_CONTEXT,
                ),
            ),
            "memory load byte",
        )
        for offset in reversed(range(size))
    )
    if len(bytes_high_to_low) == 1:
        return bytes_high_to_low[0]
    return _expect_bv(z3.Concat(*bytes_high_to_low), "memory load")


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
        or not z3.is_bv(value)
        or value.ctx != LTS_EXTRACTION_CONTEXT
        or value.size() != size * 8
    ):
        raise Amd64AdapterError("memory store value has the wrong width")
    result = memory
    for offset in range(size):
        result = _expect_array(
            z3.Store(
                result,
                address + z3.BitVecVal(
                    offset,
                    64,
                    ctx=LTS_EXTRACTION_CONTEXT,
                ),
                z3.Extract(offset * 8 + 7, offset * 8, value),
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
        or not z3.is_bv(address)
        or address.ctx != LTS_EXTRACTION_CONTEXT
        or address.size() != 64
    ):
        raise Amd64AdapterError(
            "memory and address must be extraction-context BV64-to-BV8/BV64"
        )


def source_rip_guard(source: int) -> z3.BoolRef:
    source = _u64(source, "source")
    return _expect_bool(
        canonical_register("rip")
        == z3.BitVecVal(
            source,
            64,
            ctx=LTS_EXTRACTION_CONTEXT,
        ),
        "source RIP guard",
    )


def require_mirrored_rip(
    target: z3.ExprRef,
    post_rip: z3.ExprRef,
) -> None:
    target_bv = _expect_bv(target, "target")
    post_rip_bv = _expect_bv(post_rip, "post-rip")
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
    solver.add(target_bv != post_rip_bv)
    if solver.check() != z3.unsat:
        raise Amd64AdapterError("target and post-rip disagree semantically")


def _seed_flag_bvs() -> dict[str, Any]:
    return {
        name: _claripy.BVS(
            f"rflags_{name}",
            1,
            explicit_name=True,
        )
        for name in FLAG_NAMES
    }


def _initial_cc_dep1(flag_bvs: Mapping[str, Any]) -> Any:
    pieces: list[Any] = []
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


def _access_size(value: Any, field: str) -> int:
    try:
        size = int(value) if not hasattr(value, "op") else (
            int(value.args[0]) if value.op == "BVV" else 0
        )
    except (TypeError, ValueError):
        size = 0
    if size <= 0:
        raise Amd64AdapterError(f"{field} has unknown or invalid width")
    return size


def _preserve_symbolic_memory_addresses(state: Any) -> None:
    """Keep hooked memory accesses parametric in their symbolic addresses."""

    if state.inspect.address_concretization_action in {"load", "store"}:
        state.inspect.address_concretization_add_constraints = False


def _memory_read_hook(state: Any) -> None:
    address = state.inspect.mem_read_address
    if address is None:
        raise Amd64AdapterError("memory read is missing its address")
    if state.inspect.mem_read_expr is not None:
        raise Amd64AdapterError("memory read already has a value before loading")
    size = _access_size(state.inspect.mem_read_length, "memory read")

    address_z3 = _expect_bv(claripy_to_z3(address), "memory read address")
    classified_address_z3 = address_z3

    def record(kind: str) -> None:
        events = tuple(state.globals.get("_ghot_memory_read_events", ()))
        state.globals["_ghot_memory_read_events"] = events + (
            (kind, size, str(z3.simplify(classified_address_z3))),
        )

    fixed_bytes = []
    for offset in range(size):
        byte_address = classified_address_z3 + z3.BitVecVal(
            offset,
            classified_address_z3.size(),
            ctx=LTS_EXTRACTION_CONTEXT,
        )
        matches = [
            value
            for expected, value in state.globals.get("_ghot_fixed_byte_reads", ())
            if z3.is_true(z3.simplify(byte_address == expected))
        ]
        if len(matches) > 1:
            raise Amd64AdapterError("memory read matches multiple fixed input bytes")
        if not matches:
            fixed_bytes = []
            break
        fixed_bytes.append(matches[0])
    if fixed_bytes:
        little_endian = sum(
            value << (offset * 8)
            for offset, value in enumerate(fixed_bytes)
        )
        state.inspect.mem_read_expr = _claripy.BVV(little_endian, size * 8)
        record("fixed")
        counts = dict(state.globals.get("_ghot_memory_read_counts", {}))
        counts["fixed"] = counts.get("fixed", 0) + 1
        state.globals["_ghot_memory_read_counts"] = counts
        return

    record("symbolic")
    counts = dict(state.globals.get("_ghot_memory_read_counts", {}))
    counts["symbolic"] = counts.get("symbolic", 0) + 1
    state.globals["_ghot_memory_read_counts"] = counts
    placeholders = dict(state.globals.get("_ghot_memory_reads", {}))
    name = f"__ghot_memory_read_{len(placeholders)}__"
    placeholder = _claripy.BVS(name, size * 8, explicit_name=True)
    placeholders[name] = (
        address,
        size,
        state.globals["_ghot_memory_expr"],
    )
    state.globals["_ghot_memory_reads"] = placeholders
    state.inspect.mem_read_expr = placeholder


def _memory_write_hook(state: Any) -> None:
    address = state.inspect.mem_write_address
    value = state.inspect.mem_write_expr
    if address is None or value is None:
        raise Amd64AdapterError("memory write is missing address or value")
    size = _access_size(state.inspect.mem_write_length, "memory write")
    address_z3 = _expect_bv(claripy_to_z3(address), "memory write address")
    value_z3 = _expect_bv(claripy_to_z3(value), "memory write value")
    current = _expect_array(state.globals["_ghot_memory_expr"], "current memory")
    updated = store_le(current, address_z3, value_z3, size)
    writes = list(state.globals.get("_ghot_memory_writes", ()))
    writes.append(MemoryWrite(address_z3, value_z3, size))
    state.globals["_ghot_memory_expr"] = updated
    state.globals["_ghot_memory_writes"] = tuple(writes)


def fresh_instruction_state(project: Any, source: int) -> Any:
    """Create the canonical symbolic pre-state for one real instruction."""

    source = _u64(source, "source")
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
    for name in GPR64:
        setattr(
            state.regs,
            name,
            _claripy.BVS(name, 64, explicit_name=True),
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


def _resolve_memory_reads(
    expression: z3.ExprRef,
    reads: Mapping[str, tuple[Any, int, z3.ArrayRef]],
) -> z3.ExprRef:
    replacements: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for name, (address, size, memory_at_read) in reads.items():
        address_z3 = _expect_bv(claripy_to_z3(address), "memory read address")
        if replacements:
            address_z3 = _expect_bv(
                z3.substitute(address_z3, *replacements),
                "resolved memory read address",
            )
            memory_at_read = _expect_array(
                z3.substitute(memory_at_read, *replacements),
                "resolved memory-at-read",
            )
        placeholder = z3.BitVec(
            name,
            size * 8,
            ctx=LTS_EXTRACTION_CONTEXT,
        )
        replacements.append(
            (placeholder, load_le(memory_at_read, address_z3, size))
        )
    if replacements:
        return z3.substitute(expression, *replacements)
    return expression


def _post_flag_updates(
    post: Any,
    source: int,
    reads: Mapping[str, tuple[Any, int, z3.ArrayRef]],
) -> dict[str, z3.ExprRef]:
    from angr.errors import SimCCallError, SimError

    errors: tuple[type[BaseException], ...] = (SimError, SimCCallError)

    try:
        post_rflags = post.regs.rflags
    except errors as exc:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has unsupported flag state"
        ) from exc

    updates: dict[str, z3.ExprRef] = {}
    for name in FLAG_NAMES:
        bit = AMD64_FLAG_BIT[name]
        value = _resolve_memory_reads(
            claripy_to_z3(_claripy.Extract(bit, bit, post_rflags)),
            reads,
        )
        if not value.eq(canonical_flag(name)):
            updates[f"rflags_{name}"] = value
    return updates


def _single_successor(
    project: Any,
    source: int,
) -> Any:
    source = _u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    instructions = list(block.capstone.insns)
    if block.vex.instructions != 1 or len(instructions) != 1:
        raise Amd64AdapterError(
            f"expected one decoded instruction at {source:#x}"
        )

    state = fresh_instruction_state(project, source)
    successors = list(
        project.factory.successors(state, num_inst=1).all_successors
    )
    if len(successors) != 1:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has {len(successors)} successors"
        )
    return successors[0]


def _post_updates(post: Any, source: int) -> dict[str, z3.ExprRef]:
    reads = post.globals.get("_ghot_memory_reads", {})
    updates: dict[str, z3.ExprRef] = {}
    for name in GPR64:
        value = _resolve_memory_reads(
            claripy_to_z3(getattr(post.regs, name)),
            reads,
        )
        if not value.eq(canonical_register(name)):
            updates[name] = value
    updates.update(_post_flag_updates(post, source, reads))
    return updates


def _resolved_writes(post: Any) -> tuple[MemoryWrite, ...]:
    reads = post.globals.get("_ghot_memory_reads", {})
    return tuple(
        MemoryWrite(
            _expect_bv(
                _resolve_memory_reads(write.address, reads),
                "resolved memory write address",
            ),
            _expect_bv(
                _resolve_memory_reads(write.value, reads),
                "resolved memory write value",
            ),
            write.size,
        )
        for write in post.globals.get("_ghot_memory_writes", ())
    )


def _symbolic_target_update(
    post: Any,
    updates: dict[str, z3.ExprRef],
) -> tuple[z3.BitVecRef, int | None]:
    target = _resolve_memory_reads(
        claripy_to_z3(post.regs.rip),
        post.globals.get("_ghot_memory_reads", {}),
    )
    target_bv = _expect_bv(target, "instruction target")
    if target_bv.size() != 64:
        raise Amd64AdapterError("instruction target is not BV64")
    updates["rip"] = target_bv
    require_mirrored_rip(target_bv, updates["rip"])
    simplified = z3.simplify(target_bv)
    target_value = (
        simplified.as_long()
        if isinstance(simplified, z3.BitVecNumRef)
        else None
    )
    return target_bv, target_value


def _concrete_target_update(
    post: Any,
    source: int,
    updates: dict[str, z3.ExprRef],
) -> int:
    post_rip_ast = post.regs.rip
    if post_rip_ast.op != "BVV":
        raise Amd64AdapterError(
            f"instruction at {source:#x} has symbolic post-rip"
        )
    target = _u64(int(post_rip_ast.args[0]), "target")
    post_rip = claripy_to_z3(post_rip_ast)
    target_expr = z3.BitVecVal(
        target,
        64,
        ctx=LTS_EXTRACTION_CONTEXT,
    )
    require_mirrored_rip(target_expr, post_rip)
    updates["rip"] = post_rip
    return target


def step_register_instruction(
    project: Any,
    source: int,
) -> RegisterInstructionStep:
    """Execute one exact non-memory-writing instruction."""

    source = _u64(source, "source")
    post = _single_successor(project, source)
    memory_writes = [
        action
        for action in post.history.recent_actions
        if action.type == "mem" and action.action == "write"
    ]
    if memory_writes:
        raise Amd64AdapterError(
            f"instruction at {source:#x} is not register-only"
        )

    updates = _post_updates(post, source)
    target = _concrete_target_update(post, source, updates)

    return RegisterInstructionStep(
        source=source,
        target=target,
        source_guard=source_rip_guard(source),
        updates=updates,
    )


def step_memory_instruction(
    project: Any,
    source: int,
) -> MemoryInstructionStep:
    """Execute one exact memory-reading or memory-writing instruction."""

    source = _u64(source, "source")
    post = _single_successor(project, source)
    reads = post.globals.get("_ghot_memory_reads", {})
    raw_writes = tuple(post.globals.get("_ghot_memory_writes", ()))
    if not reads and not raw_writes:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has no memory effect"
        )
    updates = _post_updates(post, source)
    writes = _resolved_writes(post)
    if writes:
        updates[MEMORY_NAME] = _resolve_memory_reads(
            post.globals["_ghot_memory_expr"],
            reads,
        )
    target = _concrete_target_update(post, source, updates)
    return MemoryInstructionStep(
        source=source,
        target=target,
        source_guard=source_rip_guard(source),
        updates=updates,
        read_count=len(reads),
        writes=writes,
    )


def step_instruction_outcomes(
    project: Any,
    source: int,
) -> InstructionOutcomeFamily:
    """Capture every structural VEX exit/default outcome of one instruction."""

    source = _u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    instructions = list(block.capstone.insns)
    if block.vex.instructions != 1 or len(instructions) != 1:
        raise Amd64AdapterError(
            f"expected one decoded instruction at {source:#x}"
        )
    exit_indices = tuple(
        index
        for index, statement in enumerate(block.vex.statements)
        if statement.__class__.__name__ == "Exit"
    )
    state = fresh_instruction_state(project, source)
    successors = list(
        project.factory.successors(state, num_inst=1).all_successors
    )
    if not successors:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has no outcomes"
        )

    outcomes: list[InstructionOutcome] = []
    exit_guards: list[z3.BoolRef] = []
    saw_default = False
    for post in successors:
        statement_index = int(post.scratch.exit_stmt_idx)
        if statement_index >= 0:
            if statement_index not in exit_indices:
                raise Amd64AdapterError(
                    f"instruction at {source:#x} has unknown VEX exit "
                    f"statement {statement_index}"
                )
            identity = StaticOutcomeIdentity(
                outcome_id=exit_indices.index(statement_index),
                kind="exit",
                vex_exit_statement_index=statement_index,
            )
            raw_guard = post.history.jump_guard
            if raw_guard is None:
                raise Amd64AdapterError(
                    f"instruction at {source:#x} exit has no guard"
                )
            guard = _expect_bool(
                _resolve_memory_reads(
                    claripy_to_z3(raw_guard),
                    post.globals.get("_ghot_memory_reads", {}),
                ),
                "instruction exit guard",
            )
            exit_guards.append(guard)
        else:
            if saw_default:
                raise Amd64AdapterError(
                    f"instruction at {source:#x} has duplicate default outcome"
                )
            saw_default = True
            identity = StaticOutcomeIdentity(
                outcome_id=len(exit_indices),
                kind="default",
                vex_exit_statement_index=None,
            )
            guard = z3.BoolVal(True, ctx=LTS_EXTRACTION_CONTEXT)

        updates = _post_updates(post, source)
        writes = _resolved_writes(post)
        if writes:
            updates[MEMORY_NAME] = _resolve_memory_reads(
                post.globals["_ghot_memory_expr"],
                post.globals.get("_ghot_memory_reads", {}),
            )
        target, target_value = _symbolic_target_update(post, updates)
        outcomes.append(
            InstructionOutcome(
                identity=identity,
                guard=guard,
                updates=updates,
                target=target,
                target_value=target_value,
                jumpkind=block.vex.jumpkind,
                writes=writes,
            )
        )

    if not saw_default:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has no default outcome"
        )
    default_guard = _expect_bool(
        (
            z3.And(*(z3.Not(guard) for guard in exit_guards))
            if exit_guards
            else z3.BoolVal(True, ctx=LTS_EXTRACTION_CONTEXT)
        ),
        "instruction default guard",
    )
    outcomes = [
        (
            InstructionOutcome(
                identity=outcome.identity,
                guard=default_guard,
                updates=outcome.updates,
                target=outcome.target,
                target_value=outcome.target_value,
                jumpkind=outcome.jumpkind,
                writes=outcome.writes,
            )
            if outcome.identity.kind == "default"
            else outcome
        )
        for outcome in outcomes
    ]
    outcomes.sort(key=lambda outcome: outcome.identity.outcome_id)
    expected_ids = tuple(range(len(exit_indices) + 1))
    actual_ids = tuple(outcome.identity.outcome_id for outcome in outcomes)
    if actual_ids != expected_ids:
        raise Amd64AdapterError(
            f"instruction at {source:#x} outcome identities are incomplete"
        )
    return InstructionOutcomeFamily(
        source=source,
        source_guard=source_rip_guard(source),
        outcomes=tuple(outcomes),
    )
