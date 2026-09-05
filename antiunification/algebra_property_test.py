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
from antiunification.many import antiunify_many, separating_inputs
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


@settings(max_examples=100, deadline=None)
@given(st.lists(EXPRESSIONS, min_size=2, max_size=5))
def test_many_reconstructs_every_independent_input(values: list[Value]) -> None:
    result = antiunify_many(GeneratedSyntax(), values, correspondences={})
    for value, substitution in zip(values, result.substitutions, strict=True):
        assert result.instantiate(substitution) == value


def test_third_observation_separates_previously_identical_signatures() -> None:
    first = (Name("a"), Name("b"), Name("c"))
    second = (Name("a"), Name("b"), Name("d"))
    values = tuple(Call("pair", (a, b)) for a, b in zip(first, second, strict=True))
    result = antiunify_many(
        GeneratedSyntax(), values, correspondences={"first": first, "second": second}
    )
    assert set(result.substitutions[0]) == {"first", "second"}
    assert result.instantiate({"first": Name("x"), "second": Name("y")}) == Call(
        "pair", (Name("x"), Name("y"))
    )


@settings(max_examples=100, deadline=None)
@given(UPDATES)
def test_many_map_reconstruction_and_held_out_renaming(value: Value) -> None:
    prefixes = ("left_", "middle_", "right_")
    values = tuple(rename(value, prefix) for prefix in prefixes)
    columns = {
        name: tuple(rename(Name(name), prefix) for prefix in prefixes)
        for name in PARAMETERS
    }
    result = antiunify_many(GeneratedSyntax(), values, correspondences=columns)
    for observation, substitution in zip(values, result.substitutions, strict=True):
        assert result.instantiate(substitution) == observation
    assert result.instantiate(
        {name: rename(Name(name), "held_") for name in result.substitutions[0]}
    ) == rename(value, "held_")


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


@given(n=st.integers(min_value=1, max_value=12))
@settings(max_examples=30, deadline=None)
def test_n_plus_one_separates_and_reconstructs(n: int) -> None:
    baseline = {f"p{i}": Name(f"base_{i}") for i in range(n)}
    alternatives = {f"p{i}": Name(f"changed_{i}") for i in range(n)}
    rows = separating_inputs(baseline, alternatives)
    assert len(rows) == n + 1
    for index, row in enumerate(rows[1:]):
        assert {key for key in baseline if row[key] != baseline[key]} == {f"p{index}"}
    columns = {key: tuple(row[key] for row in rows) for key in baseline}
    assert len(set(columns.values())) == n
    values = tuple(Call("f", tuple(row.values())) for row in rows)
    result = antiunify_many(GeneratedSyntax(), values, correspondences=columns)
    assert set(result.substitutions[0]) == baseline.keys()
    for value, substitution in zip(values, result.substitutions, strict=True):
        assert result.instantiate(substitution) == value
    held = {key: Name(f"held_{key}") for key in baseline}
    assert result.instantiate(held) == Call("f", tuple(held.values()))


@pytest.mark.parametrize(
    "baseline,alternatives",
    [({"p": Name("a")}, {}), ({"p": Name("a")}, {"p": Name("a")})],
)
def test_separating_inputs_rejects_invalid_alternatives(baseline, alternatives):
    with pytest.raises(AlgebraError):
        separating_inputs(baseline, alternatives)


@pytest.mark.parametrize(
    "values,columns,message",
    [
        ((), {}, "at least one"),
        ((Name("a"),), {"": (Name("a"),)}, "reserved"),
        ((Name("a"),), {"V0": (Name("a"),)}, "reserved"),
        ((Name("a"),), {"p": ()}, "arity"),
        ((Name("a"), Update(())), {}, "unequal sorts"),
        (
            (Name("a"), Name("b")),
            {"p": (Name("a"), Name("b")), "q": (Name("a"), Name("b"))},
            "multiple names",
        ),
        (
            (Update(((Name("a"), Name("x")), (Name("a"), Name("y")))), Update(())),
            {},
            "duplicate keys",
        ),
        (
            (Update(((Name("a"), Name("x")),)), Update(((Name("b"), Name("y")),))),
            {"p": (Name("a"), Name("b")), "q": (Name("a"), Name("c"))},
            "ambiguous correspondence",
        ),
    ],
)
def test_many_rejects_invalid_observations(values, columns, message):
    with pytest.raises(AlgebraError, match=message):
        antiunify_many(GeneratedSyntax(), values, correspondences=columns)


@pytest.mark.parametrize("right", [Update(()), Update(((Name("b"), Name("y")),))])
def test_many_unalignable_maps_remain_reconstructible_whole_map_holes(right):
    left = Update(((Name("a"), Name("x")),))
    result = antiunify_many(GeneratedSyntax(), (left, right), correspondences={})
    from antiunification.algebra import Hole

    assert isinstance(result.pattern, Hole)
    assert result.instantiate(result.substitutions[0]) == left
    assert result.instantiate(result.substitutions[1]) == right


def test_many_checks_reconstruction_even_for_ground_singletons():
    class BrokenSyntax(GeneratedSyntax):
        def reconstruct(self, layer):
            return Name("wrong")

    with pytest.raises(
        AlgebraError, match="reconstruction law failed for observation 0"
    ):
        antiunify_many(BrokenSyntax(), (Name("a"),), correspondences={})


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
