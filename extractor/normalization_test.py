# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from extractor import z3_runtime as _z3_runtime
from antiunification.many import antiunify_many
from extractor.artifact import (
    Assignment,
    Declaration,
    InstructionModel,
    StepSummary,
    Target,
    TermSort,
    TypedExpr,
)
from extractor.model_syntax import QFAbvSyntax
from extractor.normalization import normalize_expression, normalize_model
from extractor.typed_z3 import expr_to_z3
from hypothesis import given, settings, strategies as st
import pytest
import z3


@st.composite
def expressions(draw):
    width = draw(st.sampled_from([1, 8, 32, 64]))
    sort = TermSort.bv(width)
    leaves = st.one_of(
        st.sampled_from([TypedExpr.var("x", sort), TypedExpr.var("y", sort)]),
        st.sampled_from([0, (1 << width) - 1]).map(
            lambda n: TypedExpr.bv_lit(width, n)
        ),
        st.integers(0, (1 << width) - 1).map(lambda n: TypedExpr.bv_lit(width, n)),
    )
    return draw(
        st.recursive(
            leaves,
            lambda child: st.one_of(
                child.map(lambda x: TypedExpr.unary("bv_not", x)),
                st.builds(lambda a, b: TypedExpr.binary("bv_xor", a, b), child, child),
                st.builds(lambda a, b: TypedExpr.binary("bv_add", a, b), child, child),
            ),
            max_leaves=15,
        )
    )


@settings(max_examples=200, deadline=None)
@given(expressions())
def test_semantics_and_idempotence(expr):
    assert _z3_runtime.LIBSTDCXX.is_file()
    normalized = normalize_expression(expr)
    assert normalize_expression(normalized) == normalized
    assert normalized.sort == expr.sort
    context = z3.Context()
    variables = {
        name: z3.BitVec(name, expr.sort.require_bv_width(), ctx=context)
        for name in ("x", "y")
    }
    solver = z3.Solver(ctx=context)
    solver.set(timeout=5000)
    solver.add(
        expr_to_z3(expr, variables, context)
        != expr_to_z3(normalized, variables, context)
    )
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("width", [1, 8, 32, 64])
def test_complement_forms(width):
    x = TypedExpr.var("x", TermSort.bv(width))
    ones = TypedExpr.bv_lit(width, (1 << width) - 1)
    expected = TypedExpr.unary("bv_not", x)
    assert normalize_expression(TypedExpr.binary("bv_xor", ones, x)) == expected
    assert normalize_expression(TypedExpr.binary("bv_xor", x, ones)) == expected
    assert normalize_expression(expected) == expected


def test_model_fields_and_exact_au_reconstruction():
    sort = TermSort.bv(64)
    x, y = (TypedExpr.var(name, sort) for name in ("x", "y"))
    ones = TypedExpr.bv_lit(64, (1 << 64) - 1)
    raw = TypedExpr.binary("bv_xor", x, ones)
    expected = TypedExpr.unary("bv_not", x)
    model = InstructionModel(
        0,
        (Declaration("x", sort), Declaration("y", sort)),
        (
            StepSummary(
                TypedExpr.binary("eq", raw, y),
                (Assignment("x", raw), Assignment("y", y)),
                Target("symbolic", raw),
                raw,
            ),
        ),
    )
    normalized = normalize_model(model)
    assert normalize_model(normalized) == normalized
    step = normalized.steps[0]
    assert step.guard == TypedExpr.binary("eq", expected, y)
    assert step.simultaneous_update == (Assignment("x", expected), Assignment("y", y))
    assert step.target == Target("symbolic", expected)
    assert step.mirrored_pc == expected
    # Syntax exposure remains lossless for raw and normalized inputs alike.
    for value in (model, normalized):
        result = antiunify_many(QFAbvSyntax(), (value,), correspondences={})
        assert result.instantiate(result.substitutions[0]) == value


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
