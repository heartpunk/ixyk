# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Property laws for the typed QF_ABV syntax and frame normalization."""

from __future__ import annotations

from collections.abc import Mapping

from antiunification import Correspondence, antiunify_values
from extractor.artifact import (
    BOOL,
    BV64,
    MEM64_8,
    Assignment,
    Declaration,
    InstructionModel,
    StepSummary,
    Target,
    TermSort,
    TypedExpr,
)
from extractor.model_syntax import CanonicalVariable, QFAbvSyntax
from hypothesis import given, settings
from hypothesis import strategies as st
import pytest


PARAMETERS = ("p0", "p1", "flag", "memory", "pc")
DECLARATIONS = (
    Declaration("p0", BV64),
    Declaration("p1", BV64),
    Declaration("flag", BOOL),
    Declaration("memory", MEM64_8),
    Declaration("pc", BV64),
)


def bv64_var(name: str) -> TypedExpr:
    return TypedExpr.var(name, BV64)


def bv64_lit(value: int) -> TypedExpr:
    return TypedExpr.bv_lit(64, value)


def zero_extend_32(value: int) -> TypedExpr:
    return TypedExpr(
        "zero_extend",
        BV64,
        (TypedExpr.bv_lit(32, value),),
        amount=32,
    )


def concat_32(values: tuple[int, int]) -> TypedExpr:
    return TypedExpr(
        "concat",
        BV64,
        tuple(TypedExpr.bv_lit(32, value) for value in values),
    )


def binary(op: str, lhs: TypedExpr, rhs: TypedExpr) -> TypedExpr:
    return TypedExpr.binary(op, lhs, rhs)


def bv_not(value: TypedExpr) -> TypedExpr:
    return TypedExpr.unary("bv_not", value)


def ite(
    condition: TypedExpr,
    then_value: TypedExpr,
    else_value: TypedExpr,
) -> TypedExpr:
    return TypedExpr.ite(condition, then_value, else_value)


def bool_not(value: TypedExpr) -> TypedExpr:
    return TypedExpr.unary("bool_not", value)


def bv8_lit(value: int) -> TypedExpr:
    return TypedExpr.bv_lit(8, value)


def extract_low_byte(value: TypedExpr) -> TypedExpr:
    return TypedExpr("extract", TermSort.bv(8), (value,), hi=7, lo=0)


def select_byte(memory: TypedExpr, index: TypedExpr) -> TypedExpr:
    return TypedExpr("select", TermSort.bv(8), (memory, index))


def constant_array(value: TypedExpr) -> TypedExpr:
    return TypedExpr("const_array", MEM64_8, (value,))


def store_byte(index: TypedExpr, value: TypedExpr) -> TypedExpr:
    return TypedExpr(
        "store",
        MEM64_8,
        (TypedExpr.var("memory", MEM64_8), index, value),
    )


BV64_LEAVES = st.one_of(
    st.sampled_from(("p0", "p1", "pc")).map(bv64_var),
    st.integers(min_value=0, max_value=(1 << 64) - 1).map(bv64_lit),
    st.integers(min_value=0, max_value=(1 << 32) - 1).map(zero_extend_32),
    st.tuples(
        st.integers(min_value=0, max_value=(1 << 32) - 1),
        st.integers(min_value=0, max_value=(1 << 32) - 1),
    ).map(concat_32),
)

BV64_EXPRESSIONS = st.recursive(
    BV64_LEAVES,
    lambda children: st.one_of(
        st.builds(
            binary,
            st.sampled_from(
                (
                    "bv_add",
                    "bv_sub",
                    "bv_mul",
                    "bv_and",
                    "bv_or",
                    "bv_xor",
                    "bv_shl",
                    "bv_lshr",
                    "bv_ashr",
                )
            ),
            children,
            children,
        ),
        children.map(bv_not),
        st.builds(
            ite,
            st.booleans().map(TypedExpr.bool_lit),
            children,
            children,
        ),
    ),
    max_leaves=16,
)

BOOL_LEAVES = st.one_of(
    st.just(TypedExpr.var("flag", BOOL)),
    st.booleans().map(TypedExpr.bool_lit),
    st.builds(
        binary,
        st.sampled_from(("eq", "bv_ult", "bv_ule", "bv_slt", "bv_sle")),
        BV64_EXPRESSIONS,
        BV64_EXPRESSIONS,
    ),
)

BOOL_EXPRESSIONS = st.recursive(
    BOOL_LEAVES,
    lambda children: st.one_of(
        children.map(bool_not),
        st.builds(
            binary,
            st.sampled_from(("bool_and", "bool_or")),
            children,
            children,
        ),
    ),
    max_leaves=12,
)

BV8_EXPRESSIONS = st.one_of(
    st.integers(min_value=0, max_value=255).map(bv8_lit),
    BV64_EXPRESSIONS.map(extract_low_byte),
    st.builds(
        select_byte,
        st.just(TypedExpr.var("memory", MEM64_8)),
        BV64_EXPRESSIONS,
    ),
)

ARRAY_EXPRESSIONS = st.one_of(
    st.just(TypedExpr.var("memory", MEM64_8)),
    BV8_EXPRESSIONS.map(constant_array),
    st.builds(
        store_byte,
        BV64_EXPRESSIONS,
        BV8_EXPRESSIONS,
    ),
)


@st.composite
def instruction_models(draw: st.DrawFn) -> InstructionModel:
    first = TypedExpr.binary(
        draw(st.sampled_from(("bv_add", "bv_sub", "bv_xor"))),
        bv64_var("p0"),
        draw(BV64_EXPRESSIONS),
    )
    second = TypedExpr.binary(
        draw(st.sampled_from(("bv_add", "bv_sub", "bv_xor"))),
        bv64_var("p1"),
        draw(BV64_EXPRESSIONS),
    )
    assignments = (
        Assignment("p0", first),
        Assignment("p1", second),
        Assignment("flag", draw(BOOL_EXPRESSIONS)),
        Assignment("memory", draw(ARRAY_EXPRESSIONS)),
        Assignment("pc", draw(BV64_EXPRESSIONS)),
    )
    target = draw(
        st.one_of(
            st.sampled_from(("halt", "error", "stuck")).map(Target),
            st.integers(min_value=0, max_value=(1 << 64) - 1).map(
                lambda address: Target("address", address)
            ),
            BV64_EXPRESSIONS.map(lambda value: Target("symbolic", value)),
        )
    )
    step = StepSummary(
        draw(BOOL_EXPRESSIONS),
        assignments,
        target,
        draw(BV64_EXPRESSIONS),
    )
    return InstructionModel(
        draw(st.integers(min_value=0, max_value=(1 << 64) - 1)),
        DECLARATIONS,
        (step,),
    )


def rename_expression(expression: TypedExpr, names: Mapping[str, str]) -> TypedExpr:
    name = expression.name
    renamed_name = names[name] if name is not None and name in names else name
    return TypedExpr(
        expression.op,
        expression.sort,
        tuple(rename_expression(argument, names) for argument in expression.args),
        name=renamed_name,
        value=expression.value,
        amount=expression.amount,
        hi=expression.hi,
        lo=expression.lo,
    )


def rename_model(model: InstructionModel, prefix: str) -> InstructionModel:
    names = {name: f"{prefix}{index}" for index, name in enumerate(PARAMETERS)}
    return remap_model(model, names)


def remap_model(model: InstructionModel, names: Mapping[str, str]) -> InstructionModel:
    return InstructionModel(
        model.source,
        tuple(Declaration(names[item.name], item.sort) for item in model.declarations),
        tuple(
            StepSummary(
                rename_expression(step.guard, names),
                tuple(
                    Assignment(
                        names[assignment.name],
                        rename_expression(assignment.value, names),
                    )
                    for assignment in step.simultaneous_update
                ),
                Target(
                    step.target.kind,
                    rename_expression(step.target.value, names)
                    if isinstance(step.target.value, TypedExpr)
                    else step.target.value,
                ),
                rename_expression(step.mirrored_pc, names),
            )
            for step in model.steps
        ),
    )


def permute_registers(
    model: InstructionModel, order: tuple[str, ...]
) -> InstructionModel:
    names: dict[str, str] = dict(zip(("p0", "p1", "pc"), order, strict=True))
    names.update({"flag": "flag", "memory": "memory"})
    renamed = remap_model(model, names)
    steps: list[StepSummary] = []
    for step in renamed.steps:
        writes = {
            assignment.name: assignment.value for assignment in step.simultaneous_update
        }
        steps.append(
            StepSummary(
                step.guard,
                tuple(
                    Assignment(item.name, writes[item.name]) for item in DECLARATIONS
                ),
                step.target,
                step.mirrored_pc,
            )
        )
    return InstructionModel(model.source, DECLARATIONS, tuple(steps))


@given(template=instruction_models(), order=st.permutations(("p0", "p1", "pc")))
@settings(max_examples=200, deadline=None)
def test_multiwrite_correspondence_crosses_declaration_positions(
    template: InstructionModel, order: list[str]
) -> None:
    left_names = tuple(order)
    right_names = left_names[1:] + left_names[:1]
    held_names = left_names[2:] + left_names[:2]
    left = permute_registers(template, left_names)
    right = permute_registers(template, right_names)
    held_out = permute_registers(template, held_names)
    result = antiunify_values(
        QFAbvSyntax(),
        left,
        right,
        correspondences=tuple(
            Correspondence(
                f"register_{index}",
                CanonicalVariable(a, BV64),
                CanonicalVariable(b, BV64),
            )
            for index, (a, b) in enumerate(zip(left_names, right_names, strict=True))
        ),
    )
    assert result.instantiate(result.left_substitution) == left
    assert result.instantiate(result.right_substitution) == right
    assert (
        result.instantiate(
            {
                f"register_{index}": CanonicalVariable(name, BV64)
                for index, name in enumerate(held_names)
            }
        )
        == held_out
    )


@given(model=instruction_models())
@settings(max_examples=200, deadline=None)
def test_every_generated_model_round_trips_exactly(model: InstructionModel) -> None:
    result = antiunify_values(QFAbvSyntax(), model, model)

    assert result.left_substitution == {}
    assert result.right_substitution == {}
    assert result.instantiate({}) == model


@given(template=instruction_models())
@settings(max_examples=300, deadline=None)
def test_renamed_multiwrite_model_instantiates_an_exact_third_variant(
    template: InstructionModel,
) -> None:
    left = rename_model(template, "left_")
    right = rename_model(template, "right_")
    held_out = rename_model(template, "held_")
    result = antiunify_values(
        QFAbvSyntax(),
        left,
        right,
        correspondences=tuple(
            Correspondence(
                f"parameter_{index}",
                CanonicalVariable(f"left_{index}", declaration.sort),
                CanonicalVariable(f"right_{index}", declaration.sort),
            )
            for index, declaration in enumerate(DECLARATIONS)
        ),
    )

    assert result.instantiate(result.left_substitution) == left
    assert result.instantiate(result.right_substitution) == right
    assert set(result.left_substitution) == {
        f"parameter_{index}" for index in range(len(PARAMETERS))
    }
    assert (
        result.instantiate(
            {
                f"parameter_{index}": CanonicalVariable(
                    f"held_{index}", declaration.sort
                )
                for index, declaration in enumerate(DECLARATIONS)
            }
        )
        == held_out
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
