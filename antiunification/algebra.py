# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Many-sorted first-order anti-unification over explicit syntax algebras."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar


Value = TypeVar("Value")
Constructor = TypeVar("Constructor")
AtomValue = TypeVar("AtomValue")
Sort = TypeVar("Sort")
Value_co = TypeVar("Value_co", covariant=True)
Constructor_co = TypeVar("Constructor_co", covariant=True)
AtomValue_co = TypeVar("AtomValue_co", covariant=True)
Sort_co = TypeVar("Sort_co", covariant=True)


class AlgebraError(ValueError):
    """A value or substitution violates a typed syntax contract."""


@dataclass(frozen=True)
class Atom(Generic[AtomValue_co, Sort_co]):
    sort: Sort_co
    value: AtomValue_co


@dataclass(frozen=True)
class Application(Generic[Value_co, Constructor_co, Sort_co]):
    sort: Sort_co
    constructor: Constructor_co
    arguments: tuple[Value_co, ...]


@dataclass(frozen=True)
class FiniteMap(Generic[Value_co, Sort_co]):
    sort: Sort_co
    entries: tuple[tuple[Value_co, Value_co], ...]


type Layer[Value, Constructor, AtomValue, Sort] = (
    Atom[AtomValue, Sort]
    | Application[Value, Constructor, Sort]
    | FiniteMap[Value, Sort]
)


class Syntax(Protocol[Value, Constructor, AtomValue, Sort]):
    def expose(self, value: Value) -> Layer[Value, Constructor, AtomValue, Sort]: ...

    def reconstruct(
        self, layer: Layer[Value, Constructor, AtomValue, Sort]
    ) -> Value: ...


@dataclass(frozen=True)
class Correspondence(Generic[Value]):
    name: str
    left: Value
    right: Value


@dataclass(frozen=True)
class Hole(Generic[Sort_co]):
    name: str
    sort: Sort_co


@dataclass(frozen=True)
class AtomPattern(Generic[AtomValue_co, Sort_co]):
    atom: Atom[AtomValue_co, Sort_co]


@dataclass(frozen=True)
class ApplicationPattern(Generic[Constructor_co, AtomValue_co, Sort_co]):
    sort: Sort_co
    constructor: Constructor_co
    arguments: tuple[Pattern[Constructor_co, AtomValue_co, Sort_co], ...]


@dataclass(frozen=True)
class FiniteMapPattern(Generic[Constructor_co, AtomValue_co, Sort_co]):
    sort: Sort_co
    entries: tuple[
        tuple[
            Pattern[Constructor_co, AtomValue_co, Sort_co],
            Pattern[Constructor_co, AtomValue_co, Sort_co],
        ],
        ...,
    ]


type Pattern[Constructor, AtomValue, Sort] = (
    Hole[Sort]
    | AtomPattern[AtomValue, Sort]
    | ApplicationPattern[Constructor, AtomValue, Sort]
    | FiniteMapPattern[Constructor, AtomValue, Sort]
)


@dataclass(frozen=True)
class Generalization(Generic[Value, Constructor, AtomValue, Sort]):
    syntax: Syntax[Value, Constructor, AtomValue, Sort]
    pattern: Pattern[Constructor, AtomValue, Sort]
    left_substitution: Mapping[str, Value]
    right_substitution: Mapping[str, Value]

    def instantiate(self, substitution: Mapping[str, Value]) -> Value:
        def visit(pattern: Pattern[Constructor, AtomValue, Sort]) -> Value:
            if isinstance(pattern, Hole):
                if pattern.name not in substitution:
                    raise AlgebraError(f"missing substitution for {pattern.name}")
                value = substitution[pattern.name]
                if self.syntax.expose(value).sort != pattern.sort:
                    raise AlgebraError(
                        f"substitution for {pattern.name} has wrong sort"
                    )
                return value
            if isinstance(pattern, AtomPattern):
                return self.syntax.reconstruct(pattern.atom)
            if isinstance(pattern, ApplicationPattern):
                return self.syntax.reconstruct(
                    Application(
                        pattern.sort,
                        pattern.constructor,
                        tuple(visit(argument) for argument in pattern.arguments),
                    )
                )
            return self.syntax.reconstruct(
                FiniteMap(
                    pattern.sort,
                    tuple((visit(key), visit(value)) for key, value in pattern.entries),
                )
            )

        return visit(self.pattern)


def antiunify_values(
    syntax: Syntax[Value, Constructor, AtomValue, Sort],
    left: Value,
    right: Value,
    *,
    correspondences: Iterable[Correspondence[Value]] = (),
) -> Generalization[Value, Constructor, AtomValue, Sort]:
    """Compute a many-sorted LGG and enforce both reconstruction laws."""

    named = tuple(correspondences)
    names = tuple(item.name for item in named)
    if len(names) != len(set(names)):
        raise AlgebraError("correspondence names must be unique")
    if any(not name or name.startswith("V") for name in names):
        raise AlgebraError("correspondence name is empty or reserved")

    holes: list[tuple[Value, Value, Hole[Sort]]] = []
    left_substitution: dict[str, Value] = {}
    right_substitution: dict[str, Value] = {}
    generated = 0

    def ground(value: Value) -> Pattern[Constructor, AtomValue, Sort]:
        layer = syntax.expose(value)
        if isinstance(layer, Atom):
            return AtomPattern(layer)
        if isinstance(layer, Application):
            return ApplicationPattern(
                layer.sort,
                layer.constructor,
                tuple(ground(argument) for argument in layer.arguments),
            )
        return FiniteMapPattern(
            layer.sort,
            tuple((ground(key), ground(item)) for key, item in layer.entries),
        )

    def named_pair(left_value: Value, right_value: Value) -> str | None:
        matches = [
            item.name
            for item in named
            if item.left == left_value and item.right == right_value
        ]
        if len(matches) > 1:
            raise AlgebraError("one disagreement pair has multiple names")
        return matches[0] if matches else None

    def fresh(left_value: Value, right_value: Value, sort: Sort) -> Hole[Sort]:
        nonlocal generated
        for prior_left, prior_right, hole in holes:
            if prior_left == left_value and prior_right == right_value:
                if hole.sort != sort:
                    raise AlgebraError("one disagreement pair has conflicting sorts")
                return hole
        name = named_pair(left_value, right_value)
        if name is None:
            name = f"V{generated}"
            generated += 1
        if name in left_substitution:
            raise AlgebraError(f"correspondence {name!r} names distinct pairs")
        hole = Hole(name, sort)
        holes.append((left_value, right_value, hole))
        left_substitution[name] = left_value
        right_substitution[name] = right_value
        return hole

    def duplicate_keys(entries: tuple[tuple[Value, Value], ...]) -> bool:
        return any(
            left_index != right_index and left_key == right_key
            for left_index, (left_key, _) in enumerate(entries)
            for right_index, (right_key, _) in enumerate(entries)
        )

    def paired_key(left_key: Value) -> Value:
        matches = [item.right for item in named if item.left == left_key]
        if matches and any(candidate != matches[0] for candidate in matches[1:]):
            raise AlgebraError("one map key corresponds to multiple right keys")
        return matches[0] if matches else left_key

    def align(
        left_entries: tuple[tuple[Value, Value], ...],
        right_entries: tuple[tuple[Value, Value], ...],
    ) -> tuple[tuple[Value, Value, Value, Value], ...] | None:
        if len(left_entries) != len(right_entries):
            return None
        if duplicate_keys(left_entries) or duplicate_keys(right_entries):
            raise AlgebraError("finite map contains duplicate keys")
        unused = list(right_entries)
        result: list[tuple[Value, Value, Value, Value]] = []
        for left_key, left_value in left_entries:
            expected = paired_key(left_key)
            matches = [
                index
                for index, (right_key, _) in enumerate(unused)
                if right_key == expected
            ]
            if len(matches) != 1:
                return None
            right_key, right_value = unused.pop(matches[0])
            result.append((left_key, left_value, right_key, right_value))
        return tuple(result)

    def visit(
        left_value: Value, right_value: Value
    ) -> Pattern[Constructor, AtomValue, Sort]:
        if left_value == right_value:
            return ground(left_value)
        left_layer = syntax.expose(left_value)
        right_layer = syntax.expose(right_value)
        if left_layer.sort != right_layer.sort:
            message = f"cannot generalize unequal sorts {left_layer.sort!r} and {right_layer.sort!r}"
            raise AlgebraError(message)
        if (
            isinstance(left_layer, Application)
            and isinstance(right_layer, Application)
            and left_layer.constructor == right_layer.constructor
            and len(left_layer.arguments) == len(right_layer.arguments)
        ):
            return ApplicationPattern(
                left_layer.sort,
                left_layer.constructor,
                tuple(
                    visit(left_argument, right_argument)
                    for left_argument, right_argument in zip(
                        left_layer.arguments, right_layer.arguments, strict=True
                    )
                ),
            )
        if isinstance(left_layer, FiniteMap) and isinstance(right_layer, FiniteMap):
            aligned = align(left_layer.entries, right_layer.entries)
            if aligned is not None:
                return FiniteMapPattern(
                    left_layer.sort,
                    tuple(
                        (visit(left_key, right_key), visit(left_item, right_item))
                        for left_key, left_item, right_key, right_item in aligned
                    ),
                )
        return fresh(left_value, right_value, left_layer.sort)

    result = Generalization(
        syntax,
        visit(left, right),
        left_substitution,
        right_substitution,
    )
    if result.instantiate(result.left_substitution) != left:
        raise AlgebraError("left reconstruction law failed")
    if result.instantiate(result.right_substitution) != right:
        raise AlgebraError("right reconstruction law failed")
    return result
