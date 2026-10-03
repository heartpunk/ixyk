# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Strict JSON-serializable QF_ABV instruction models.

Semantics selectively ported from ghot-effectful-extractor-boundary revision
6b652ff3d791a2a46cf1c487854b1c62ae20da18.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import ClassVar, cast

from ayxg.expr import ArtifactError, BOOL, Declaration, TermSort, TypedExpr




def _object(value: object, field: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ArtifactError(f"{field} must be an object")
    raw = cast(dict[object, object], value)
    if not all(isinstance(key, str) for key in raw):
        raise ArtifactError(f"{field} keys must be strings")
    return cast(dict[str, object], value)


def _array(value: object, field: str) -> list[object]:
    if not isinstance(value, list):
        raise ArtifactError(f"{field} must be an array")
    return cast(list[object], value)


def _fields(value: dict[str, object], expected: set[str], field: str) -> None:
    actual = set(value)
    if actual != expected:
        differences = (
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
        raise ArtifactError(f"{field} fields differ: {differences}")


def _integer(value: object, field: str) -> int:
    if type(value) is not int:
        raise ArtifactError(f"{field} must be an integer")
    return value


def _nonnegative(value: object, field: str) -> int:
    result = _integer(value, field)
    if result < 0:
        raise ArtifactError(f"{field} must be nonnegative")
    return result


def _positive(value: object, field: str) -> int:
    result = _integer(value, field)
    if result <= 0:
        raise ArtifactError(f"{field} must be positive")
    return result


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ArtifactError(f"{field} must be a nonempty string")
    return value





BOOL = TermSort.bool()
BV64 = TermSort.bv(64)
MEM64_8 = TermSort.array(64, 8)





@dataclass(frozen=True)
class Assignment:
    name: str
    value: TypedExpr

    def __post_init__(self) -> None:
        _ = _text(self.name, "assignment.name")

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "value": self.value.to_data()}

    @classmethod
    def from_data(cls, value: object, field: str = "assignment") -> Assignment:
        obj = _object(value, field)
        _fields(obj, {"name", "value"}, field)
        return cls(
            _text(obj["name"], f"{field}.name"),
            TypedExpr.from_data(obj["value"], f"{field}.value"),
        )


@dataclass(frozen=True)
class Target:
    kind: str
    value: int | TypedExpr | None = None

    def __post_init__(self) -> None:
        if self.kind == "address":
            address = _nonnegative(self.value, "target.value")
            if address >= 1 << 64:
                raise ArtifactError("target address exceeds BV64")
        elif self.kind == "symbolic":
            if not isinstance(self.value, TypedExpr) or self.value.sort != BV64:
                raise ArtifactError("symbolic target must be BV64")
        elif self.kind in {"halt", "error", "stuck"}:
            if self.value is not None:
                raise ArtifactError(f"{self.kind} target carries a value")
        else:
            raise ArtifactError(f"unknown target kind: {self.kind!r}")

    def to_data(self) -> dict[str, object]:
        result: dict[str, object] = {"kind": self.kind}
        if self.value is not None:
            result["value"] = (
                self.value.to_data()
                if isinstance(self.value, TypedExpr)
                else self.value
            )
        return result

    @classmethod
    def from_data(cls, value: object, field: str = "target") -> Target:
        obj = _object(value, field)
        kind = _text(obj.get("kind"), f"{field}.kind")
        _fields(
            obj,
            {"kind"} if kind in {"halt", "error", "stuck"} else {"kind", "value"},
            field,
        )
        raw = obj.get("value")
        return cls(
            kind,
            TypedExpr.from_data(raw, f"{field}.value")
            if kind == "symbolic"
            else cast(int | None, raw),
        )


@dataclass(frozen=True)
class StepSummary:
    guard: TypedExpr
    simultaneous_update: tuple[Assignment, ...]
    target: Target
    mirrored_pc: TypedExpr

    def __post_init__(self) -> None:
        if self.guard.sort != BOOL:
            raise ArtifactError("step guard must be Boolean")
        if self.mirrored_pc.sort != BV64:
            raise ArtifactError("mirrored PC must be BV64")

    def validate(self, declarations: tuple[Declaration, ...]) -> None:
        declared = {declaration.name: declaration.sort for declaration in declarations}
        names = tuple(assignment.name for assignment in self.simultaneous_update)
        if len(names) != len(set(names)):
            raise ArtifactError("simultaneous update contains duplicate names")
        if names != tuple(declared):
            raise ArtifactError(
                "simultaneous update must cover declarations in declaration order"
            )
        expressions = [
            self.guard,
            *(assignment.value for assignment in self.simultaneous_update),
            self.mirrored_pc,
        ]
        if self.target.kind == "symbolic":
            if not isinstance(self.target.value, TypedExpr):
                raise ArtifactError("symbolic target is malformed")
            expressions.append(self.target.value)
        for assignment in self.simultaneous_update:
            if assignment.value.sort != declared[assignment.name]:
                raise ArtifactError(f"update for {assignment.name!r} has wrong sort")
        for expression in expressions:
            for name, sort in expression.variable_sorts().items():
                if declared.get(name) != sort:
                    raise ArtifactError(
                        f"variable {name!r} is absent or has the wrong sort"
                    )

    def to_data(self) -> dict[str, object]:
        return {
            "guard": self.guard.to_data(),
            "simultaneous_update": [
                assignment.to_data() for assignment in self.simultaneous_update
            ],
            "target": self.target.to_data(),
            "mirrored_pc": self.mirrored_pc.to_data(),
        }

    @classmethod
    def from_data(cls, value: object, field: str = "step") -> StepSummary:
        obj = _object(value, field)
        _fields(
            obj,
            {"guard", "simultaneous_update", "target", "mirrored_pc"},
            field,
        )
        return cls(
            TypedExpr.from_data(obj["guard"], f"{field}.guard"),
            tuple(
                Assignment.from_data(item, f"{field}.simultaneous_update[]")
                for item in _array(
                    obj["simultaneous_update"], f"{field}.simultaneous_update"
                )
            ),
            Target.from_data(obj["target"], f"{field}.target"),
            TypedExpr.from_data(obj["mirrored_pc"], f"{field}.mirrored_pc"),
        )


@dataclass(frozen=True)
class InstructionModel:
    """One source control point and its complete typed outgoing edges."""

    source: int
    declarations: tuple[Declaration, ...]
    steps: tuple[StepSummary, ...]

    schema: ClassVar[str] = "ixyk.qf_abv.instruction.v1"

    def __post_init__(self) -> None:
        if type(self.source) is not int or not 0 <= self.source < 1 << 64:
            raise ArtifactError("instruction source must be a BV64 address")
        names = tuple(declaration.name for declaration in self.declarations)
        if not names or len(names) != len(set(names)):
            raise ArtifactError("declarations must be nonempty and unique")
        if not self.steps:
            raise ArtifactError("instruction model must contain an edge")
        for step in self.steps:
            step.validate(self.declarations)

    def to_data(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "source": self.source,
            "declarations": [
                declaration.to_data() for declaration in self.declarations
            ],
            "steps": [step.to_data() for step in self.steps],
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_data(),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @classmethod
    def from_data(cls, value: object) -> InstructionModel:
        obj = _object(value, "instruction_model")
        _fields(obj, {"schema", "source", "declarations", "steps"}, "instruction_model")
        if obj["schema"] != cls.schema:
            raise ArtifactError("unknown instruction-model schema")
        return cls(
            _nonnegative(obj["source"], "instruction_model.source"),
            tuple(
                Declaration.from_data(item, "instruction_model.declarations[]")
                for item in _array(
                    obj["declarations"], "instruction_model.declarations"
                )
            ),
            tuple(
                StepSummary.from_data(item, "instruction_model.steps[]")
                for item in _array(obj["steps"], "instruction_model.steps")
            ),
        )

    @classmethod
    def from_json(cls, text: str) -> InstructionModel:
        try:
            value = cast(object, json.loads(text))
        except json.JSONDecodeError as exc:
            raise ArtifactError("instruction model is not valid JSON") from exc
        return cls.from_data(value)
