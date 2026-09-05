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
from hypothesis import Phase, given, settings, strategies as st
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


def check_concrete_normalization(expr, x, y):
    assert _z3_runtime.LIBSTDCXX.is_file()
    normalized = normalize_expression(expr)
    assert normalize_expression(normalized) == normalized
    assert normalized.sort == expr.sort
    context = z3.Context()
    width = expr.sort.require_bv_width()
    variables = {
        "x": z3.BitVecVal(x, width, ctx=context),
        "y": z3.BitVecVal(y, width, ctx=context),
    }
    expected = z3.simplify(expr_to_z3(expr, variables, context)).as_long()
    actual = z3.simplify(expr_to_z3(normalized, variables, context)).as_long()
    assert actual == expected, (expr.to_data(), {"x": x, "y": y}, expected, actual)


@settings(max_examples=200, deadline=None, phases=(Phase.generate,))
@given(expressions(), st.data())
def test_semantics_and_idempotence(expr, data):
    mask = (1 << expr.sort.require_bv_width()) - 1
    words = st.one_of(st.sampled_from([0, 1, mask, mask >> 1]), st.integers(0, mask))
    check_concrete_normalization(
        expr, data.draw(words, label="x"), data.draw(words, label="y")
    )


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


@settings(max_examples=200, deadline=None, phases=(Phase.generate,))
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
        mask = (1 << width) - 1
        for x_value, y_value in ((0, 0), (1, mask), (mask, 1), (mask, mask)):
            check_concrete_normalization(raw, x_value, y_value)


def test_shift_distributivity_example():
    x, y = (TypedExpr.var(name, TermSort.bv(64)) for name in ("x", "y"))
    shifted = TypedExpr.binary(
        "bv_shl", TypedExpr.binary("bv_add", x, y), TypedExpr.bv_lit(64, 1)
    )
    expr = TypedExpr.unary(
        "bv_not", TypedExpr.binary("bv_mul", TypedExpr.bv_lit(64, 3), shifted)
    )
    for x_value, y_value in ((0, 0), (1, 2), ((1 << 64) - 1, 1)):
        check_concrete_normalization(expr, x_value, y_value)


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
