"""Focused checks for typed instruction serialization and Z3 conversion."""

from __future__ import annotations

import pytest

from extractor import z3_boundary as _z3
from extractor.artifact import (
    BOOL,
    BV64,
    ArtifactError,
    Assignment,
    Declaration,
    InstructionModel,
    StepSummary,
    Target,
    TypedExpr,
)
from extractor.typed_z3 import expr_from_z3, step_summary_from_z3
import z3


def _model() -> InstructionModel:
    declarations = (Declaration("rax", BV64), Declaration("rip", BV64))
    rax = TypedExpr.var("rax", BV64)
    target = TypedExpr.bv_lit(64, 0x400003)
    step = StepSummary(
        TypedExpr.binary("eq", rax, TypedExpr.bv_lit(64, 0)),
        (
            Assignment(
                "rax",
                TypedExpr.binary("bv_add", rax, TypedExpr.bv_lit(64, 1)),
            ),
            Assignment("rip", target),
        ),
        Target("address", 0x400003),
        target,
    )
    return InstructionModel(0x400000, declarations, (step,))


def test_json_round_trip_is_canonical() -> None:
    model = _model()
    encoded = model.to_json()
    decoded = InstructionModel.from_json(encoded)
    assert decoded == model
    assert decoded.to_json() == encoded


def test_rejects_unknown_json_fields() -> None:
    data = _model().to_data()
    data["unexpected"] = True
    with pytest.raises(ArtifactError, match="fields differ"):
        _ = InstructionModel.from_data(data)


def test_rejects_missing_or_misordered_updates() -> None:
    model = _model()
    step = model.steps[0]
    with pytest.raises(ArtifactError, match="cover declarations"):
        _ = InstructionModel(
            model.source,
            model.declarations,
            (
                StepSummary(
                    step.guard,
                    tuple(reversed(step.simultaneous_update)),
                    step.target,
                    step.mirrored_pc,
                ),
            ),
        )


def test_rejects_wrong_update_sort() -> None:
    model = _model()
    step = model.steps[0]
    with pytest.raises(ArtifactError, match="wrong sort"):
        _ = InstructionModel(
            model.source,
            model.declarations,
            (
                StepSummary(
                    step.guard,
                    (
                        Assignment("rax", TypedExpr.bool_lit(True)),
                        step.simultaneous_update[1],
                    ),
                    step.target,
                    step.mirrored_pc,
                ),
            ),
        )


def test_rejects_undeclared_variables() -> None:
    model = _model()
    step = model.steps[0]
    alien = TypedExpr.var("alien", BV64)
    with pytest.raises(ArtifactError, match="absent"):
        _ = InstructionModel(
            model.source,
            model.declarations,
            (
                StepSummary(
                    step.guard,
                    (
                        Assignment("rax", alien),
                        step.simultaneous_update[1],
                    ),
                    step.target,
                    step.mirrored_pc,
                ),
            ),
        )


def test_rejects_invalid_json_and_boolean_source() -> None:
    with pytest.raises(ArtifactError, match="valid JSON"):
        _ = InstructionModel.from_json("{")
    model = _model()
    with pytest.raises(ArtifactError, match="BV64 address"):
        _ = InstructionModel(True, model.declarations, model.steps)


def test_z3_bridge_builds_dense_typed_edge() -> None:
    context = z3.Context()
    rax = _z3.bit_vec("rax", 64, context)
    one = _z3.bit_vec_val(1, 64, context)
    target = _z3.bit_vec_val(0x400003, 64, context)
    declarations = (Declaration("rax", BV64), Declaration("rip", BV64))
    step = step_summary_from_z3(
        declarations,
        guard=_z3.bool_val(True, context),
        updates={"rax": rax + one, "rip": target},
        target=0x400003,
        mirrored_pc=target,
    )
    assert step.simultaneous_update[0].value.op == "bv_add"
    assert step.simultaneous_update[1].value == TypedExpr.bv_lit(64, 0x400003)
    assert step.target == Target("address", 0x400003)


def test_z3_bridge_rejects_unsupported_sort() -> None:
    context = z3.Context()
    integer = _z3.integer("integer", context)
    with pytest.raises(ArtifactError, match="unsupported Z3 sort"):
        _ = expr_from_z3(integer)


def test_boolean_expression_requires_boolean_sort() -> None:
    with pytest.raises(ArtifactError, match="operand sorts"):
        _ = TypedExpr(
            "bool_and",
            BOOL,
            (TypedExpr.bool_lit(True), TypedExpr.bv_lit(1, 0)),
        )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
