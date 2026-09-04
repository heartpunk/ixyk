# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Extract one AMD64 instruction into symbolic transition outcomes."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import ClassVar, cast, override

from extractor import z3_boundary as _z3
from extractor.amd64_state import (
    AMD64_FLAG_BIT,
    FLAG_NAMES,
    GPR64,
    LTS_EXTRACTION_CONTEXT,
    MEMORY_NAME,
    YMM256,
    Amd64AdapterError,
    MemoryReads,
    architectural_memory_expression,
    canonical_flag,
    canonical_declarations,
    canonical_register,
    claripy_to_z3,
    fresh_instruction_state,
    memory_reads,
    require_bit_vector,
    require_boolean,
    require_u64,
    resolve_memory_reads,
)
from extractor.angr_boundary import State, claripy as _claripy, expect_project
from extractor.artifact import InstructionModel, StepSummary
from extractor.typed_z3 import step_summary_from_z3

import z3


class _ExpectedSymbolicExitFilter(logging.Filter):
    """Hide only Angr's expected diagnostic for our symbolic return edge."""

    _PREFIX: ClassVar[str] = (
        "Exit state has over 256 possible solutions. Likely unconstrained; skipping."
    )

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        return not record.getMessage().startswith(self._PREFIX)


logging.getLogger("angr.engines.successors").addFilter(_ExpectedSymbolicExitFilter())


_MODELED_VEX_REGISTERS = (
    *GPR64,
    *YMM256,
    "rip",
    "cc_op",
    "cc_dep1",
    "cc_dep2",
    "cc_ndep",
)


def _integer_attribute(value: object, name: str, field: str) -> int:
    result: object = getattr(value, name, None)
    if type(result) is not int:
        raise Amd64AdapterError(f"{field} has no integer {name}")
    return result


def _expression_width(value: object, tyenv: object, field: str) -> int:
    raw: object = getattr(value, "result_size", None)
    if not callable(raw):
        raise Amd64AdapterError(f"{field} has no result width")
    bits: object = cast(Callable[[object], object], raw)(tyenv)
    if type(bits) is not int or bits <= 0 or bits % 8:
        raise Amd64AdapterError(f"{field} has invalid bit width {bits!r}")
    return bits // 8


def _require_register_closure(raw_project: object, block: object) -> None:
    """Reject instructions whose semantics escape the declared state."""

    project = expect_project(raw_project)
    vex: object = getattr(block, "vex", None)
    tyenv: object = getattr(vex, "tyenv", None)
    statements = cast(Sequence[object], getattr(vex, "statements", ()))
    modeled_bytes = {
        byte
        for name in _MODELED_VEX_REGISTERS
        for offset, size in (project.arch.registers[name],)
        for byte in range(offset, offset + size)
    }

    def require_access(value: object, width_source: object, operation: str) -> None:
        offset = _integer_attribute(value, "offset", f"VEX register {operation}")
        size = _expression_width(width_source, tyenv, f"VEX register {operation}")
        escaped = set(range(offset, offset + size)) - modeled_bytes
        if escaped:
            details = f"{operation} [{offset}, {offset + size}) escapes declared state"
            raise Amd64AdapterError(details)

    for statement in statements:
        kind = statement.__class__.__name__
        if kind in {"PutI", "Dirty"}:
            raise Amd64AdapterError(f"VEX {kind} escapes scalar state")
        if kind == "Put":
            require_access(statement, getattr(statement, "data", None), "write")
        expressions = cast(Sequence[object], getattr(statement, "expressions", ()))
        for expression in expressions:
            expression_kind = expression.__class__.__name__
            if expression_kind == "GetI":
                raise Amd64AdapterError("VEX GetI escapes scalar state")
            if expression_kind == "Get":
                require_access(expression, expression, "read")


def _vex_tmp(value: object) -> int | None:
    if value.__class__.__name__ != "RdTmp":
        return None
    tmp: object = getattr(value, "tmp", None)
    return tmp if type(tmp) is int else None


def _vex_constant(value: object) -> int | None:
    if value.__class__.__name__ != "Const":
        return None
    constant: object = getattr(value, "con", None)
    result: object = getattr(constant, "value", None)
    return result if type(result) is int else None


def _vex_binop(value: object, operation: str) -> tuple[object, object] | None:
    arguments = cast(Sequence[object], getattr(value, "args", ()))
    if (
        value.__class__.__name__ != "Binop"
        or getattr(value, "op", None) != operation
        or len(arguments) != 2
    ):
        return None
    return arguments[0], arguments[1]


def _vex_stack_scratch_writes(raw_project: object, block: object) -> frozenset[int]:
    """Recognize VEX's documented 288-byte client-stack scratch protocol."""

    project = expect_project(raw_project)
    vex: object = getattr(block, "vex", None)
    statements = cast(Sequence[object], getattr(vex, "statements", ()))
    definitions = {
        tmp: (index, getattr(statement, "data", None))
        for index, statement in enumerate(statements)
        if statement.__class__.__name__ == "WrTmp"
        and type(tmp := getattr(statement, "tmp", None)) is int
    }
    rsp_offset = project.arch.registers["rsp"][0]

    def puts_rsp(index: int, tmp: int) -> bool:
        return any(
            statement.__class__.__name__ == "Put"
            and getattr(statement, "offset", None) == rsp_offset
            and _vex_tmp(getattr(statement, "data", None)) == tmp
            for statement in statements[index:]
        )

    scratch: set[int] = set()
    for store_index, statement in enumerate(statements):
        if statement.__class__.__name__ != "Store":
            continue
        scratch_tmp = _vex_tmp(getattr(statement, "addr", None))
        if scratch_tmp is None or scratch_tmp not in definitions:
            continue
        subtract_index, subtract = definitions[scratch_tmp]
        operands = _vex_binop(subtract, "Iop_Sub64")
        if operands is None or _vex_constant(operands[1]) != 288:
            continue
        rsp_tmp = _vex_tmp(operands[0])
        if rsp_tmp is None or rsp_tmp not in definitions:
            continue
        rsp_index, rsp_get = definitions[rsp_tmp]
        if (
            rsp_get.__class__.__name__ != "Get"
            or getattr(rsp_get, "offset", None) != rsp_offset
            or not rsp_index < subtract_index < store_index
            or not puts_rsp(subtract_index + 1, scratch_tmp)
        ):
            continue
        restored = any(
            restore_index > store_index
            and (args := _vex_binop(value, "Iop_Add64")) is not None
            and _vex_tmp(args[0]) == scratch_tmp
            and _vex_constant(args[1]) == 288
            and puts_rsp(restore_index + 1, restore_tmp)
            for restore_tmp, (restore_index, value) in definitions.items()
        )
        if restored:
            scratch.add(store_index)
    return frozenset(scratch)


def extract(raw_project: object, source: int) -> InstructionModel:
    """Symbolically execute one exact instruction and extract every outcome."""

    project, source = expect_project(raw_project), require_u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    if block.vex.instructions != 1 or len(block.capstone.insns) != 1:
        raise Amd64AdapterError(f"expected one decoded instruction at {source:#x}")
    _require_register_closure(project, block)

    exit_indices = tuple(
        index
        for index, statement in enumerate(block.vex.statements)
        if statement.__class__.__name__ == "Exit"
    )
    pre = fresh_instruction_state(
        project, source, _vex_stack_scratch_writes(project, block)
    )
    posts = tuple(project.factory.successors(pre, num_inst=1).all_successors)
    if not posts:
        raise Amd64AdapterError(f"instruction at {source:#x} has no outcomes")

    classified = tuple((post, *_classify(post, source, exit_indices)) for post in posts)
    defaults = sum(guard is None for _, _, guard in classified)
    if defaults != 1:
        problem = "no" if defaults == 0 else "duplicate"
        raise Amd64AdapterError(
            f"instruction at {source:#x} has {problem} default outcome"
        )
    exit_guards = tuple(guard for _, _, guard in classified if guard is not None)
    default_guard = require_boolean(
        _z3.conjunction(*(_z3.negate(guard) for guard in exit_guards))
        if exit_guards
        else _z3.bool_val(True, LTS_EXTRACTION_CONTEXT),
        "instruction default guard",
    )

    outcome_ids = tuple(outcome_id for _, outcome_id, _ in classified)
    if tuple(sorted(outcome_ids)) != tuple(range(len(classified))):
        raise Amd64AdapterError(
            f"instruction at {source:#x} outcome identities are incomplete"
        )
    indexed_steps = (
        (
            outcome_id,
            _extract_step(
                post,
                default_guard if guard is None else guard,
                source,
            ),
        )
        for post, outcome_id, guard in classified
    )
    ordered = tuple(step for _, step in sorted(indexed_steps, key=lambda item: item[0]))
    return InstructionModel(source, canonical_declarations(), ordered)


def _classify(
    post: State,
    source: int,
    exit_indices: tuple[int, ...],
) -> tuple[int, z3.BoolRef | None]:
    statement_index = int(post.scratch.exit_stmt_idx)
    if statement_index < 0:
        return len(exit_indices), None
    if statement_index not in exit_indices:
        details = f"unknown VEX exit statement {statement_index}"
        raise Amd64AdapterError(f"instruction at {source:#x} has {details}")
    raw_guard = post.history.jump_guard
    if raw_guard is None:
        raise Amd64AdapterError(f"instruction at {source:#x} exit has no guard")
    return (
        exit_indices.index(statement_index),
        require_boolean(
            resolve_memory_reads(claripy_to_z3(raw_guard), memory_reads(post)),
            "instruction exit guard",
        ),
    )


def _extract_step(
    post: State,
    guard: z3.BoolRef,
    source: int,
) -> StepSummary:
    reads = memory_reads(post)
    updates = _extract_updates(post, source, reads)
    memory = architectural_memory_expression(post)
    if memory is not None:
        updates[MEMORY_NAME] = resolve_memory_reads(memory, reads)
    target, target_value = _extract_target(post, reads)
    updates["rip"] = target
    return step_summary_from_z3(
        canonical_declarations(),
        guard=guard,
        updates=updates,
        target=_terminal_target(post) or (
            target if target_value is None else target_value
        ),
        mirrored_pc=target,
    )


def _terminal_target(post: State) -> str | None:
    jumpkind = post.history.jumpkind
    if jumpkind in {"Ijk_Boring", "Ijk_Call", "Ijk_Ret"}:
        return None
    if jumpkind.startswith("Ijk_Sig"):
        return "error"
    raise Amd64AdapterError(f"unsupported VEX jump kind {jumpkind!r}")


def _extract_flag_updates(
    post: State,
    source: int,
    reads: MemoryReads,
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
        value = resolve_memory_reads(
            claripy_to_z3(_claripy.Extract(bit, bit, post_rflags)),
            reads,
        )
        if not _z3.structurally_equal(value, canonical_flag(name)):
            updates[f"rflags_{name}"] = value
    return updates


def _extract_updates(
    post: State,
    source: int,
    reads: MemoryReads,
) -> dict[str, z3.ExprRef]:
    updates: dict[str, z3.ExprRef] = {}
    for name in (*GPR64, *YMM256):
        value = resolve_memory_reads(
            claripy_to_z3(post.regs.__getattr__(name)),
            reads,
        )
        if not _z3.structurally_equal(value, canonical_register(name)):
            updates[name] = value
    updates.update(_extract_flag_updates(post, source, reads))
    return updates


def _extract_target(
    post: State,
    reads: MemoryReads,
) -> tuple[z3.BitVecRef, int | None]:
    target_bv = require_bit_vector(
        resolve_memory_reads(claripy_to_z3(post.regs.rip), reads),
        "instruction target",
    )
    if target_bv.size() != 64:
        raise Amd64AdapterError("instruction target is not BV64")
    simplified = _z3.simplify(target_bv)
    target_value = (
        simplified.as_long() if isinstance(simplified, z3.BitVecNumRef) else None
    )
    return target_bv, target_value
