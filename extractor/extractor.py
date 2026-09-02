"""Extract one AMD64 instruction into symbolic transition outcomes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import logging
from typing import ClassVar, override

from extractor import z3_boundary as _z3
from extractor.amd64_state import (
    AMD64_FLAG_BIT,
    FLAG_NAMES,
    GPR64,
    LTS_EXTRACTION_CONTEXT,
    MEMORY_NAME,
    Amd64AdapterError,
    MemoryReads,
    MemoryWrite,
    canonical_flag,
    canonical_register,
    claripy_to_z3,
    fresh_instruction_state,
    memory_expression,
    memory_reads,
    memory_writes,
    require_bit_vector,
    require_boolean,
    require_u64,
    resolve_memory_reads,
    source_rip_guard,
)
from extractor.angr_boundary import State, claripy as _claripy, expect_project

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


def extract(raw_project: object, source: int) -> InstructionOutcomeFamily:
    """Symbolically execute one exact instruction and extract every outcome."""

    project, source = expect_project(raw_project), require_u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    if block.vex.instructions != 1 or len(block.capstone.insns) != 1:
        raise Amd64AdapterError(f"expected one decoded instruction at {source:#x}")

    exit_indices = tuple(
        index
        for index, statement in enumerate(block.vex.statements)
        if statement.__class__.__name__ == "Exit"
    )
    pre = fresh_instruction_state(project, source)
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

    outcomes = [
        _extract_outcome(
            post,
            identity,
            default_guard if guard is None else guard,
            source,
            block.vex.jumpkind,
        )
        for post, identity, guard in classified
    ]
    outcomes.sort(key=lambda outcome: outcome.identity.outcome_id)
    if tuple(outcome.identity.outcome_id for outcome in outcomes) != tuple(
        range(len(exit_indices) + 1)
    ):
        raise Amd64AdapterError(
            f"instruction at {source:#x} outcome identities are incomplete"
        )
    return InstructionOutcomeFamily(
        source,
        source_rip_guard(source),
        tuple(outcomes),
    )


def _classify(
    post: State,
    source: int,
    exit_indices: tuple[int, ...],
) -> tuple[StaticOutcomeIdentity, z3.BoolRef | None]:
    statement_index = int(post.scratch.exit_stmt_idx)
    if statement_index < 0:
        return StaticOutcomeIdentity(len(exit_indices), "default", None), None
    if statement_index not in exit_indices:
        details = f"unknown VEX exit statement {statement_index}"
        raise Amd64AdapterError(f"instruction at {source:#x} has {details}")
    raw_guard = post.history.jump_guard
    if raw_guard is None:
        raise Amd64AdapterError(f"instruction at {source:#x} exit has no guard")
    return (
        StaticOutcomeIdentity(
            exit_indices.index(statement_index),
            "exit",
            statement_index,
        ),
        require_boolean(
            resolve_memory_reads(claripy_to_z3(raw_guard), memory_reads(post)),
            "instruction exit guard",
        ),
    )


def _extract_outcome(
    post: State,
    identity: StaticOutcomeIdentity,
    guard: z3.BoolRef,
    source: int,
    jumpkind: str,
) -> InstructionOutcome:
    reads = memory_reads(post)
    updates = _extract_updates(post, source, reads)
    writes = _extract_writes(post, reads)
    if writes:
        updates[MEMORY_NAME] = resolve_memory_reads(memory_expression(post), reads)
    target, target_value = _extract_target(post, reads)
    updates["rip"] = target
    return InstructionOutcome(
        identity,
        guard,
        updates,
        target,
        target_value,
        jumpkind,
        writes,
    )


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
    for name in GPR64:
        value = resolve_memory_reads(
            claripy_to_z3(post.regs.__getattr__(name)),
            reads,
        )
        if not _z3.structurally_equal(value, canonical_register(name)):
            updates[name] = value
    updates.update(_extract_flag_updates(post, source, reads))
    return updates


def _extract_writes(
    post: State,
    reads: MemoryReads,
) -> tuple[MemoryWrite, ...]:
    return tuple(
        MemoryWrite(
            require_bit_vector(
                resolve_memory_reads(write.address, reads),
                "resolved memory write address",
            ),
            require_bit_vector(
                resolve_memory_reads(write.value, reads),
                "resolved memory write value",
            ),
            write.size,
        )
        for write in memory_writes(post)
    )


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
