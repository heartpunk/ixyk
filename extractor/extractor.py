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
    require_mirrored_rip,
    require_u64,
    resolve_memory_reads,
    source_rip_guard,
)
from extractor.angr_boundary import (
    Project,
    State,
    claripy as _claripy,
    expect_project,
)

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
class RegisterInstructionStep:
    source: int
    target: int
    source_guard: z3.BoolRef
    updates: Mapping[str, z3.ExprRef]


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


def _post_flag_updates(
    post: State,
    source: int,
) -> dict[str, z3.ExprRef]:
    from angr.errors import SimCCallError, SimError

    errors: tuple[type[BaseException], ...] = (SimError, SimCCallError)
    try:
        post_rflags = post.regs.rflags
    except errors as exc:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has unsupported flag state"
        ) from exc

    reads = memory_reads(post)
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


def _single_successor(project: Project, source: int) -> State:
    source = require_u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    instructions = list(block.capstone.insns)
    if block.vex.instructions != 1 or len(instructions) != 1:
        raise Amd64AdapterError(f"expected one decoded instruction at {source:#x}")

    state = fresh_instruction_state(project, source)
    successors = list(project.factory.successors(state, num_inst=1).all_successors)
    if len(successors) != 1:
        raise Amd64AdapterError(
            f"instruction at {source:#x} has {len(successors)} successors"
        )
    return successors[0]


def _post_updates(post: State, source: int) -> dict[str, z3.ExprRef]:
    reads = memory_reads(post)
    updates: dict[str, z3.ExprRef] = {}
    for name in GPR64:
        value = resolve_memory_reads(
            claripy_to_z3(post.regs.__getattr__(name)),
            reads,
        )
        if not _z3.structurally_equal(value, canonical_register(name)):
            updates[name] = value
    updates.update(_post_flag_updates(post, source))
    return updates


def _resolved_writes(post: State) -> tuple[MemoryWrite, ...]:
    reads = memory_reads(post)
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


def _symbolic_target_update(
    post: State,
    updates: dict[str, z3.ExprRef],
) -> tuple[z3.BitVecRef, int | None]:
    target = resolve_memory_reads(
        claripy_to_z3(post.regs.rip),
        memory_reads(post),
    )
    target_bv = require_bit_vector(target, "instruction target")
    if target_bv.size() != 64:
        raise Amd64AdapterError("instruction target is not BV64")
    updates["rip"] = target_bv
    require_mirrored_rip(target_bv, updates["rip"])
    simplified = _z3.simplify(target_bv)
    target_value = (
        simplified.as_long() if isinstance(simplified, z3.BitVecNumRef) else None
    )
    return target_bv, target_value


def _concrete_target_update(
    post: State,
    source: int,
    updates: dict[str, z3.ExprRef],
) -> int:
    post_rip_ast = post.regs.rip
    if post_rip_ast.op != "BVV":
        raise Amd64AdapterError(f"instruction at {source:#x} has symbolic post-rip")
    target = require_u64(post_rip_ast.args[0], "target")
    post_rip = claripy_to_z3(post_rip_ast)
    target_expr = _z3.bit_vec_val(
        target,
        64,
        LTS_EXTRACTION_CONTEXT,
    )
    require_mirrored_rip(target_expr, post_rip)
    updates["rip"] = post_rip
    return target


def step_register_instruction(
    raw_project: object,
    source: int,
) -> RegisterInstructionStep:
    """Execute one exact non-memory-writing instruction."""

    project = expect_project(raw_project)
    source = require_u64(source, "source")
    post = _single_successor(project, source)
    writes = [
        action
        for action in post.history.recent_actions
        if action.type == "mem" and action.action == "write"
    ]
    if writes:
        raise Amd64AdapterError(f"instruction at {source:#x} is not register-only")

    updates = _post_updates(post, source)
    target = _concrete_target_update(post, source, updates)
    return RegisterInstructionStep(
        source=source,
        target=target,
        source_guard=source_rip_guard(source),
        updates=updates,
    )


def step_memory_instruction(
    raw_project: object,
    source: int,
) -> MemoryInstructionStep:
    """Execute one exact memory-reading or memory-writing instruction."""

    project = expect_project(raw_project)
    source = require_u64(source, "source")
    post = _single_successor(project, source)
    reads = memory_reads(post)
    raw_writes = memory_writes(post)
    if not reads and not raw_writes:
        raise Amd64AdapterError(f"instruction at {source:#x} has no memory effect")
    updates = _post_updates(post, source)
    writes = _resolved_writes(post)
    if writes:
        updates[MEMORY_NAME] = resolve_memory_reads(
            memory_expression(post),
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
    raw_project: object,
    source: int,
) -> InstructionOutcomeFamily:
    """Capture every structural VEX exit/default outcome of one instruction."""

    project = expect_project(raw_project)
    source = require_u64(source, "source")
    block = project.factory.block(source, num_inst=1)
    instructions = list(block.capstone.insns)
    if block.vex.instructions != 1 or len(instructions) != 1:
        raise Amd64AdapterError(f"expected one decoded instruction at {source:#x}")
    exit_indices = tuple(
        index
        for index, statement in enumerate(block.vex.statements)
        if statement.__class__.__name__ == "Exit"
    )
    state = fresh_instruction_state(project, source)
    successors = list(project.factory.successors(state, num_inst=1).all_successors)
    if not successors:
        raise Amd64AdapterError(f"instruction at {source:#x} has no outcomes")

    outcomes: list[InstructionOutcome] = []
    exit_guards: list[z3.BoolRef] = []
    saw_default = False
    for post in successors:
        statement_index = int(post.scratch.exit_stmt_idx)
        if statement_index >= 0:
            if statement_index not in exit_indices:
                raise Amd64AdapterError(
                    f"instruction at {source:#x} has unknown VEX exit "
                    + f"statement {statement_index}"
                )
            identity = StaticOutcomeIdentity(
                outcome_id=exit_indices.index(statement_index),
                kind="exit",
                vex_exit_statement_index=statement_index,
            )
            raw_guard = post.history.jump_guard
            if raw_guard is None:
                raise Amd64AdapterError(f"instruction at {source:#x} exit has no guard")
            guard = require_boolean(
                resolve_memory_reads(
                    claripy_to_z3(raw_guard),
                    memory_reads(post),
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
            guard = _z3.bool_val(True, LTS_EXTRACTION_CONTEXT)

        updates = _post_updates(post, source)
        writes = _resolved_writes(post)
        if writes:
            updates[MEMORY_NAME] = resolve_memory_reads(
                memory_expression(post),
                memory_reads(post),
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
        raise Amd64AdapterError(f"instruction at {source:#x} has no default outcome")
    default_guard = require_boolean(
        (
            _z3.conjunction(*(_z3.negate(guard) for guard in exit_guards))
            if exit_guards
            else _z3.bool_val(True, LTS_EXTRACTION_CONTEXT)
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
