# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import unittest

from antiunification import (
    AlgebraError,
    Application,
    Atom,
    Correspondence,
    FiniteMap,
    FiniteMapPattern,
    Layer,
    antiunify_values,
)


class Sort(Enum):
    NAME = "name"
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


class ExampleSyntax:
    def expose(self, value: Value) -> Layer[Value, str, str, Sort]:
        if isinstance(value, Name):
            return Atom(Sort.NAME, value.value)
        if isinstance(value, Call):
            return Application(Sort.EXPR, value.operator, value.arguments)
        return FiniteMap(Sort.MAP, value.entries)

    def reconstruct(self, layer: Layer[Value, str, str, Sort]) -> Value:
        if isinstance(layer, Atom):
            if layer.sort != Sort.NAME:
                raise AlgebraError("name atom has wrong sort")
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


class AlgebraTest(unittest.TestCase):
    def test_correspondence_aligns_multiwrite_map_and_reuses_holes(self) -> None:
        syntax = ExampleSyntax()
        left = Update(
            (
                (Name("rcx"), Call("add", (Name("rcx"), Name("rdx")))),
                (Name("rdx"), Call("old", (Name("rdx"),))),
            )
        )
        right = Update(
            (
                (Name("rax"), Call("add", (Name("rax"), Name("rbx")))),
                (Name("rbx"), Call("old", (Name("rbx"),))),
            )
        )
        result = antiunify_values(
            syntax,
            left,
            right,
            correspondences=(
                Correspondence("destination", Name("rcx"), Name("rax")),
                Correspondence("source", Name("rdx"), Name("rbx")),
            ),
        )

        self.assertIsInstance(result.pattern, FiniteMapPattern)
        self.assertEqual(set(result.left_substitution), {"destination", "source"})
        self.assertEqual(result.instantiate(result.left_substitution), left)
        self.assertEqual(result.instantiate(result.right_substitution), right)
        self.assertEqual(
            result.instantiate({"destination": Name("r8"), "source": Name("r9")}),
            Update(
                (
                    (Name("r8"), Call("add", (Name("r8"), Name("r9")))),
                    (Name("r9"), Call("old", (Name("r9"),))),
                )
            ),
        )

    def test_rejects_disagreement_between_sorts(self) -> None:
        with self.assertRaisesRegex(AlgebraError, "unequal sorts"):
            _ = antiunify_values(ExampleSyntax(), Name("rax"), Call("read", ()))


if __name__ == "__main__":
    _ = unittest.main()
