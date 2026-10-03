"""Architecture-specific step construction from Z3 state expressions."""
from __future__ import annotations
from collections.abc import Mapping
import z3
from ayxg.expr import BOOL, ArtifactError, Declaration, TypedExpr
from ayxg.z3 import expr_from_z3
from extractor.artifact import Assignment, StepSummary, Target

def _complete_update(
    declarations: tuple[Declaration, ...],
    updates: Mapping[str, z3.ExprRef],
) -> tuple[Assignment, ...]:
    declared = {declaration.name: declaration for declaration in declarations}
    unknown = set(updates) - set(declared)
    if unknown:
        raise ArtifactError(f"update names are not declared: {sorted(unknown)}")
    result: list[Assignment] = []
    for declaration in declarations:
        value = (
            expr_from_z3(updates[declaration.name])
            if declaration.name in updates
            else TypedExpr.var(declaration.name, declaration.sort)
        )
        if value.sort != declaration.sort:
            raise ArtifactError(f"update for {declaration.name!r} has wrong sort")
        result.append(Assignment(declaration.name, value))
    return tuple(result)


def step_summary_from_z3(
    declarations: tuple[Declaration, ...],
    *,
    guard: z3.BoolRef,
    updates: Mapping[str, z3.ExprRef],
    target: int | z3.BitVecRef | str,
    mirrored_pc: z3.BitVecRef,
) -> StepSummary:
    typed_guard = expr_from_z3(guard)
    typed_pc = expr_from_z3(mirrored_pc)
    if type(target) is int:
        typed_target = Target("address", target)
    elif isinstance(target, z3.BitVecRef):
        typed_target = Target("symbolic", expr_from_z3(target))
    elif target in {"halt", "error", "stuck"}:
        typed_target = Target(target)
    else:
        raise ArtifactError("target is neither address, BV64, nor terminal")
    result = StepSummary(
        typed_guard,
        _complete_update(declarations, updates),
        typed_target,
        typed_pc,
    )
    result.validate(declarations)
    return result
