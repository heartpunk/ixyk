# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Property laws for the domain-neutral anti-unification algebra."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from antiunification import (
    AlgebraError,
    Application,
    Atom,
    Correspondence,
    FiniteMap,
    Layer,
    antiunify_values,
)
from hypothesis import given, settings
from hypothesis import strategies as st
import pytest


class Sort(Enum):
    EXPR = "expr"
    MAP = "map"


@dataclass(frozen=True)
class Name:
    value: str


@dataclass(frozen=True)
class Call:
    operator: str
    arguments: tuple[Value, ...]


@dataclass(frozen=True)
class Update:
    entries: tuple[tuple[Name, Value], ...]


Value = Name | Call | Update


class GeneratedSyntax:
    def expose(self, value: Value) -> Layer[Value, str, str, Sort]:
        if isinstance(value, Name):
            return Atom(Sort.EXPR, value.value)
        if isinstance(value, Call):
            return Application(Sort.EXPR, value.operator, value.arguments)
        return FiniteMap(Sort.MAP, value.entries)

    def reconstruct(self, layer: Layer[Value, str, str, Sort]) -> Value:
        if isinstance(layer, Atom):
            if layer.sort != Sort.EXPR:
                raise AlgebraError("expression atom has wrong sort")
            return Name(layer.value)
        if isinstance(layer, Application):
            if layer.sort != Sort.EXPR:
                raise AlgebraError("call has wrong sort")
            return Call(layer.constructor, layer.arguments)
        if layer.sort != Sort.MAP:
            raise AlgebraError("update map has wrong sort")
        entries: list[tuple[Name, Value]] = []
        for key, value in layer.entries:
            if not isinstance(key, Name):
                raise AlgebraError("update key is not a name")
            entries.append((key, value))
        return Update(tuple(entries))


PARAMETERS = ("p0", "p1", "p2")
CONSTANTS = ("zero", "one", "carry")

EXPRESSIONS = st.recursive(
    st.sampled_from(PARAMETERS + CONSTANTS).map(Name),
    lambda children: st.builds(
        Call,
        st.sampled_from(("not", "add", "xor", "ite", "pair")),
        st.lists(children, min_size=1, max_size=3).map(tuple),
    ),
    max_leaves=20,
)

UPDATES = st.dictionaries(
    st.sampled_from(PARAMETERS),
    EXPRESSIONS,
    max_size=len(PARAMETERS),
).map(
    lambda entries: Update(tuple((Name(key), value) for key, value in entries.items()))
)

VALUES = st.one_of(EXPRESSIONS, UPDATES)


def rename(value: Value, prefix: str) -> Value:
    if isinstance(value, Name):
        if value.value not in PARAMETERS:
            return value
        return Name(f"{prefix}{PARAMETERS.index(value.value)}")
    if isinstance(value, Call):
        return Call(
            value.operator,
            tuple(rename(argument, prefix) for argument in value.arguments),
        )
    return Update(
        tuple(
            (rename_name(key, prefix), rename(item, prefix))
            for key, item in value.entries
        )
    )


def rename_name(value: Name, prefix: str) -> Name:
    renamed = rename(value, prefix)
    if not isinstance(renamed, Name):
        raise AssertionError("renaming a name changed its constructor")
    return renamed


@given(value=VALUES)
@settings(max_examples=200, deadline=None)
def test_reflexive_generalization_is_exact_and_ground(value: Value) -> None:
    result = antiunify_values(GeneratedSyntax(), value, value)

    assert result.left_substitution == {}
    assert result.right_substitution == {}
    assert result.instantiate({}) == value


@given(left=EXPRESSIONS, right=EXPRESSIONS)
@settings(max_examples=200, deadline=None)
def test_arbitrary_same_sort_pairs_reconstruct_exactly(
    left: Value,
    right: Value,
) -> None:
    result = antiunify_values(GeneratedSyntax(), left, right)

    assert result.instantiate(result.left_substitution) == left
    assert result.instantiate(result.right_substitution) == right


@given(template=VALUES)
@settings(max_examples=300, deadline=None)
def test_bijective_atom_correspondence_instantiates_a_third_variant(
    template: Value,
) -> None:
    left = rename(template, "left_")
    right = rename(template, "right_")
    held_out = rename(template, "held_")
    result = antiunify_values(
        GeneratedSyntax(),
        left,
        right,
        correspondences=tuple(
            Correspondence(
                f"parameter_{index}",
                Name(f"left_{index}"),
                Name(f"right_{index}"),
            )
            for index in range(len(PARAMETERS))
        ),
    )

    assert result.instantiate(result.left_substitution) == left
    assert result.instantiate(result.right_substitution) == right
    assert set(result.left_substitution) <= {
        f"parameter_{index}" for index in range(len(PARAMETERS))
    }
    assert (
        result.instantiate(
            {
                name: Name(f"held_{name.removeprefix('parameter_')}")
                for name in result.left_substitution
            }
        )
        == held_out
    )


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
