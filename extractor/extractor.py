"""Extract one AMD64 instruction into symbolic transition outcomes."""

from __future__ import annotations

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
    canonical_flag,
    canonical_declarations,
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


def extract(raw_project: object, source: int) -> InstructionModel:
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
    if memory_writes(post):
        updates[MEMORY_NAME] = resolve_memory_reads(memory_expression(post), reads)
    target, target_value = _extract_target(post, reads)
    updates["rip"] = target
    return step_summary_from_z3(
        canonical_declarations(),
        guard=guard,
        updates=updates,
        target=target if target_value is None else target_value,
        mirrored_pc=target,
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
