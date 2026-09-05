# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from extractor import z3_runtime as _z3_runtime
from dataclasses import replace
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
                st.builds(lambda a, b: TypedExpr.binary("bv_mul", a, b), child, child),
                st.builds(lambda a, b: TypedExpr.binary("bv_sub", a, b), child, child),
                st.builds(
                    lambda x, k: TypedExpr.binary(
                        "bv_shl", x, TypedExpr.bv_lit(width, k)
                    ),
                    child,
                    st.integers(0, min(width + 1, (1 << width) - 1)),
                ),
            ),
            max_leaves=15,
        )
    )


def require_unsat(solver):
    # Unknown is not a counterexample. Retry with a larger bounded budget;
    # if still inconclusive, stop the run as INCOMPLETE instead of letting
    # Hypothesis shrink a timing-dependent assertion or silently passing it.
    for milliseconds in (5000, 30000):
        solver.set(timeout=milliseconds)
        result = solver.check()
        if result == z3.unsat:
            return
        if result == z3.sat:
            raise AssertionError(f"normalization changed semantics: {solver.model()}")
    pytest.exit(
        f"INCOMPLETE normalization proof: {solver.reason_unknown()}", returncode=2
    )


def check_normalization(expr):
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
    solver.add(
        expr_to_z3(expr, variables, context)
        != expr_to_z3(normalized, variables, context)
    )
    require_unsat(solver)


@settings(max_examples=200, deadline=None)
@given(expressions())
def test_semantics_and_idempotence(expr):
    check_normalization(expr)


def test_ci_shift_distributivity_regression():
    x, y = (TypedExpr.var(name, TermSort.bv(64)) for name in ("x", "y"))
    shifted = TypedExpr.binary(
        "bv_shl", TypedExpr.binary("bv_add", x, y), TypedExpr.bv_lit(64, 1)
    )
    check_normalization(
        TypedExpr.unary(
            "bv_not", TypedExpr.binary("bv_mul", TypedExpr.bv_lit(64, 3), shifted)
        )
    )


@pytest.mark.parametrize(
    "results,outcome",
    [
        ([z3.unsat], "pass"),
        ([z3.unknown, z3.unsat], "pass"),
        ([z3.sat], "mismatch"),
        ([z3.unknown, z3.sat], "mismatch"),
        ([z3.unknown, z3.unknown], "incomplete"),
    ],
)
def test_solver_outcomes_are_not_conflated(results, outcome):
    from unittest.mock import Mock

    solver = Mock()
    solver.check.side_effect = results
    solver.reason_unknown.return_value = "timeout"
    if outcome == "pass":
        require_unsat(solver)
    elif outcome == "mismatch":
        with pytest.raises(AssertionError, match="changed semantics"):
            require_unsat(solver)
    else:
        with pytest.raises(
            pytest.exit.Exception, match="INCOMPLETE.*timeout"
        ) as stopped:
            require_unsat(solver)
        assert stopped.value.returncode == 2
    assert solver.check.call_count == len(results)


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


@settings(max_examples=200, deadline=None)
@given(expressions())
def test_normalization_commutes_with_variable_renaming(expr):
    names = {"x": "z", "y": "a"}  # Deliberately reverse lexical ordering.
    labels = {"x": ("left",), "y": ("right",)}

    def rename(node):
        return replace(
            node,
            name=names.get(node.name, node.name),
            args=tuple(rename(arg) for arg in node.args),
        )

    renamed_labels = {names[name]: label for name, label in labels.items()}
    assert normalize_expression(rename(expr), renamed_labels) == rename(
        normalize_expression(expr, labels)
    )


@pytest.mark.parametrize("width", [1, 8, 32, 64, 128])
def test_multiplication_order_uses_correspondence(width):
    x, y = (TypedExpr.var(name, TermSort.bv(width)) for name in ("z", "a"))
    labels = {"z": ("left",), "a": ("right",)}
    expected = TypedExpr.binary("bv_mul", x, y)
    assert normalize_expression(expected, labels) == expected
    assert normalize_expression(TypedExpr.binary("bv_mul", y, x), labels) == expected


@pytest.mark.parametrize("width", [8, 32, 64, 128])
@pytest.mark.parametrize("amount", [0, 1, 2, 3])
def test_scaling_forms_inside_arithmetic(width, amount):
    sort = TermSort.bv(width)
    x, y = (TypedExpr.var(name, sort) for name in ("x", "y"))
    factor = TypedExpr.bv_lit(width, 1 << amount)
    product = TypedExpr.binary("bv_mul", factor, x)
    shift = TypedExpr.binary("bv_shl", x, TypedExpr.bv_lit(width, amount))
    sliced = (
        TypedExpr(
            "concat",
            sort,
            (
                TypedExpr(
                    "extract",
                    TermSort.bv(width - amount),
                    (x,),
                    hi=width - amount - 1,
                    lo=0,
                ),
                TypedExpr.bv_lit(amount, 0),
            ),
        )
        if amount
        else x
    )
    expected = normalize_expression(TypedExpr.binary("bv_add", y, product))
    for term in (shift, sliced, product):
        raw = TypedExpr.binary("bv_add", y, term)
        assert normalize_expression(raw) == expected
        assert normalize_expression(expected) == expected
        context = z3.Context()
        variables = {name: z3.BitVec(name, width, ctx=context) for name in ("x", "y")}
        solver = z3.Solver(ctx=context)
        solver.add(
            expr_to_z3(raw, variables, context)
            != expr_to_z3(expected, variables, context)
        )
        assert solver.check() == z3.unsat


def test_unrecognized_concat_is_not_scaling():
    x = TypedExpr.var("x", TermSort.bv(8))
    for lo, value in ((1, 0), (0, 1)):
        high = TypedExpr("extract", TermSort.bv(6), (x,), hi=lo + 5, lo=lo)
        expr = TypedExpr("concat", TermSort.bv(8), (high, TypedExpr.bv_lit(2, value)))
        assert normalize_expression(expr) == expr


def test_equal_order_labels_do_not_merge_distinct_variables():
    x, y = (TypedExpr.var(name, TermSort.bv(8)) for name in ("x", "y"))
    value = normalize_expression(
        TypedExpr.binary("bv_sub", x, y), {"x": ("same",), "y": ("same",)}
    )
    context = z3.Context()
    variables = {
        "x": z3.BitVecVal(1, 8, ctx=context),
        "y": z3.BitVecVal(2, 8, ctx=context),
    }
    assert z3.simplify(expr_to_z3(value, variables, context)).as_long() == 255


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
