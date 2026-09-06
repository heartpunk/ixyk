# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Simultaneous anti-unification using complete observation signatures."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Generic

from antiunification.algebra import (
    AlgebraError,
    Application,
    ApplicationPattern,
    Atom,
    AtomPattern,
    AtomValue,
    Constructor,
    FiniteMap,
    FiniteMapPattern,
    Generalization,
    Hole,
    Pattern,
    Sort,
    Syntax,
    Value,
)


class IncompatibleShapes(AlgebraError):
    """These observations do not share a sort-compatible generalization."""


def separating_inputs(
    baseline: Mapping[str, Value], alternatives: Mapping[str, Value]
) -> tuple[dict[str, Value], ...]:
    """Return n+1 assignments: a baseline and one change per parameter.

    Every parameter varies, and its complete input column differs from every
    other parameter's column. This separates names, not arbitrary semantics.
    """
    if baseline.keys() != alternatives.keys():
        raise AlgebraError("need the same parameter set")
    if any(baseline[name] == alternatives[name] for name in baseline):
        raise AlgebraError("each parameter needs a different alternative")
    return (dict(baseline),) + tuple(
        dict(baseline) | {name: alternatives[name]} for name in baseline
    )


@dataclass(frozen=True)
class ManyGeneralization(Generic[Value, Constructor, AtomValue, Sort]):
    syntax: Syntax[Value, Constructor, AtomValue, Sort]
    pattern: Pattern[Constructor, AtomValue, Sort]
    substitutions: tuple[Mapping[str, Value], ...]

    def instantiate(self, substitution: Mapping[str, Value]) -> Value:
        return Generalization(self.syntax, self.pattern, {}, {}).instantiate(
            substitution
        )


def antiunify_many(
    syntax: Syntax[Value, Constructor, AtomValue, Sort],
    values: Sequence[Value],
    *,
    correspondences: Mapping[str, tuple[Value, ...]],
) -> ManyGeneralization[Value, Constructor, AtomValue, Sort]:
    """Align explicit syntax across all inputs and check every reconstruction."""
    count = len(values)
    if count < 1:
        raise AlgebraError("need at least one input")
    if any(not name or name.startswith("V") for name in correspondences):
        raise AlgebraError("correspondence name is empty or reserved")
    if any(len(column) != count for column in correspondences.values()):
        raise AlgebraError("correspondence arity differs from observations")
    substitutions: tuple[dict[str, Value], ...] = tuple({} for _ in values)
    holes: list[tuple[tuple[Value, ...], Hole[Sort]]] = []

    def fresh(column: tuple[Value, ...], sort: Sort) -> Hole[Sort]:
        for previous, hole in holes:
            if previous == column:
                if hole.sort != sort:
                    raise AlgebraError("one signature has conflicting sorts")
                return hole
        names = [
            name for name, signature in correspondences.items() if signature == column
        ]
        if len(names) > 1:
            raise AlgebraError("one disagreement signature has multiple names")
        name = names[0] if names else f"V{len(holes)}"
        hole = Hole(name, sort)
        holes.append((column, hole))
        for substitution, value in zip(substitutions, column, strict=True):
            substitution[name] = value
        return hole

    def ground(value: Value) -> Pattern[Constructor, AtomValue, Sort]:
        layer = syntax.expose(value)
        if isinstance(layer, Atom):
            return AtomPattern(layer)
        if isinstance(layer, Application):
            return ApplicationPattern(
                layer.sort, layer.constructor, tuple(ground(v) for v in layer.arguments)
            )
        return FiniteMapPattern(
            layer.sort, tuple((ground(k), ground(v)) for k, v in layer.entries)
        )

    def visit(column: tuple[Value, ...]) -> Pattern[Constructor, AtomValue, Sort]:
        if all(value == column[0] for value in column):
            return ground(column[0])
        layers = tuple(syntax.expose(value) for value in column)
        first = layers[0]
        if any(layer.sort != first.sort for layer in layers):
            raise IncompatibleShapes("cannot generalize unequal sorts")
        applications = tuple(
            layer for layer in layers if isinstance(layer, Application)
        )
        if len(applications) == count and all(
            layer.constructor == applications[0].constructor
            and len(layer.arguments) == len(applications[0].arguments)
            for layer in applications
        ):
            return ApplicationPattern(
                first.sort,
                applications[0].constructor,
                tuple(
                    visit(tuple(args))
                    for args in zip(
                        *(layer.arguments for layer in applications), strict=True
                    )
                ),
            )
        maps = tuple(layer for layer in layers if isinstance(layer, FiniteMap))
        if len(maps) == count:
            for layer in maps:
                keys = [key for key, _ in layer.entries]
                if any(key in keys[:i] for i, key in enumerate(keys)):
                    raise AlgebraError("finite map contains duplicate keys")
            if all(len(layer.entries) == len(maps[0].entries) for layer in maps):
                remaining = [list(layer.entries) for layer in maps]
                aligned: list[
                    tuple[
                        Pattern[Constructor, AtomValue, Sort],
                        Pattern[Constructor, AtomValue, Sort],
                    ]
                ] = []
                for key, _ in maps[0].entries:
                    signatures = [s for s in correspondences.values() if s[0] == key]
                    if signatures and any(s != signatures[0] for s in signatures):
                        raise AlgebraError("one map key has ambiguous correspondence")
                    expected = signatures[0] if signatures else (key,) * count
                    entries: list[tuple[Value, Value]] = []
                    for items, wanted in zip(remaining, expected, strict=True):
                        matches = [
                            i
                            for i, (candidate, _) in enumerate(items)
                            if candidate == wanted
                        ]
                        if len(matches) != 1:
                            return fresh(column, first.sort)
                        entries.append(items.pop(matches[0]))
                    aligned.append(
                        (
                            visit(tuple(k for k, _ in entries)),
                            visit(tuple(v for _, v in entries)),
                        )
                    )
                return FiniteMapPattern(first.sort, tuple(aligned))
        return fresh(column, first.sort)

    result = ManyGeneralization(syntax, visit(tuple(values)), substitutions)
    for index, (value, substitution) in enumerate(
        zip(values, substitutions, strict=True)
    ):
        if result.instantiate(substitution) != value:
            raise AlgebraError(f"reconstruction law failed for observation {index}")
    return result
