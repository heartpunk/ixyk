"""Strict JSON-serializable QF_ABV instruction models.

Semantics selectively ported from ghot-effectful-extractor-boundary revision
6b652ff3d791a2a46cf1c487854b1c62ae20da18.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import ClassVar, cast


class ArtifactError(ValueError):
    """A typed semantic artifact violated its structural contract."""


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


@dataclass(frozen=True, order=True)
class TermSort:
    kind: str
    width: int | None = None
    index_width: int | None = None
    value_width: int | None = None

    def __post_init__(self) -> None:
        if self.kind == "bool":
            valid = (
                self.width is None
                and self.index_width is None
                and self.value_width is None
            )
        elif self.kind == "bv":
            valid = (
                type(self.width) is int
                and self.width > 0
                and self.index_width is None
                and self.value_width is None
            )
        elif self.kind == "array":
            valid = (
                self.width is None
                and type(self.index_width) is int
                and self.index_width > 0
                and type(self.value_width) is int
                and self.value_width > 0
            )
        else:
            raise ArtifactError(f"unknown term sort: {self.kind!r}")
        if not valid:
            raise ArtifactError(f"malformed {self.kind} sort")

    @classmethod
    def bool(cls) -> TermSort:
        return cls("bool")

    @classmethod
    def bv(cls, width: int) -> TermSort:
        return cls("bv", width=width)

    @classmethod
    def array(cls, index_width: int, value_width: int) -> TermSort:
        return cls("array", index_width=index_width, value_width=value_width)

    def require_bv_width(self) -> int:
        if self.kind != "bv" or self.width is None:
            raise ArtifactError("expected bit-vector sort")
        return self.width

    def require_array_widths(self) -> tuple[int, int]:
        if self.kind != "array" or self.index_width is None or self.value_width is None:
            raise ArtifactError("expected array sort")
        return self.index_width, self.value_width

    def to_data(self) -> dict[str, object]:
        if self.kind == "bool":
            return {"kind": "bool"}
        if self.kind == "bv":
            return {"kind": "bv", "width": self.require_bv_width()}
        index_width, value_width = self.require_array_widths()
        return {
            "kind": "array",
            "index_width": index_width,
            "value_width": value_width,
        }

    @classmethod
    def from_data(cls, value: object, field: str = "sort") -> TermSort:
        obj = _object(value, field)
        kind = _text(obj.get("kind"), f"{field}.kind")
        if kind == "bool":
            _fields(obj, {"kind"}, field)
            return cls.bool()
        if kind == "bv":
            _fields(obj, {"kind", "width"}, field)
            return cls.bv(_positive(obj["width"], f"{field}.width"))
        if kind == "array":
            _fields(obj, {"kind", "index_width", "value_width"}, field)
            return cls.array(
                _positive(obj["index_width"], f"{field}.index_width"),
                _positive(obj["value_width"], f"{field}.value_width"),
            )
        raise ArtifactError(f"{field} has unknown sort kind: {kind!r}")


BOOL = TermSort.bool()
BV64 = TermSort.bv(64)
MEM64_8 = TermSort.array(64, 8)


@dataclass(frozen=True, order=True)
class Declaration:
    name: str
    sort: TermSort

    def __post_init__(self) -> None:
        _ = _text(self.name, "declaration.name")

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "sort": self.sort.to_data()}

    @classmethod
    def from_data(cls, value: object, field: str = "declaration") -> Declaration:
        obj = _object(value, field)
        _fields(obj, {"name", "sort"}, field)
        return cls(
            _text(obj["name"], f"{field}.name"),
            TermSort.from_data(obj["sort"], f"{field}.sort"),
        )


_BOOL_BINARY = {"bool_and", "bool_or"}
_BV_BINARY = {
    "bv_add",
    "bv_sub",
    "bv_mul",
    "bv_udiv",
    "bv_urem",
    "bv_and",
    "bv_or",
    "bv_xor",
    "bv_shl",
    "bv_lshr",
    "bv_ashr",
}
_BV_COMPARE = {"bv_ult", "bv_ule", "bv_slt", "bv_sle"}


@dataclass(frozen=True)
class TypedExpr:
    op: str
    sort: TermSort
    args: tuple[TypedExpr, ...] = ()
    name: str | None = None
    value: bool | int | None = None
    amount: int | None = None
    hi: int | None = None
    lo: int | None = None

    def __post_init__(self) -> None:
        metadata = {
            key
            for key, value in (
                ("name", self.name),
                ("value", self.value),
                ("amount", self.amount),
                ("hi", self.hi),
                ("lo", self.lo),
            )
            if value is not None
        }
        expected: set[str] = set()
        if self.op == "var":
            expected = {"name"}
            _ = _text(self.name, "expression.name")
            self._arity(0)
        elif self.op == "bool_lit":
            expected = {"value"}
            self._arity(0)
            if self.sort != BOOL or type(self.value) is not bool:
                raise ArtifactError("bool_lit requires a Boolean value")
        elif self.op == "bv_lit":
            expected = {"value"}
            self._arity(0)
            width = self.sort.require_bv_width()
            if (
                type(self.value) is not int
                or self.value < 0
                or self.value >= 1 << width
            ):
                raise ArtifactError("bv_lit value is outside its sort")
        elif self.op == "const_array":
            self._arity(1)
            _, value_width = self.sort.require_array_widths()
            if self.args[0].sort != TermSort.bv(value_width):
                raise ArtifactError("const_array value sort disagrees")
        elif self.op in {"bool_not", "bv_not"}:
            self._arity(1)
            required = BOOL if self.op == "bool_not" else self.sort
            if self.sort != required or self.args[0].sort != required:
                raise ArtifactError(f"{self.op} operand sort disagrees")
        elif self.op in _BOOL_BINARY:
            self._arity(2)
            if self.sort != BOOL or any(arg.sort != BOOL for arg in self.args):
                raise ArtifactError(f"{self.op} operand sorts disagree")
        elif self.op in _BV_BINARY:
            self._arity(2)
            _ = self.sort.require_bv_width()
            if any(arg.sort != self.sort for arg in self.args):
                raise ArtifactError(f"{self.op} operand sorts disagree")
        elif self.op in _BV_COMPARE:
            self._arity(2)
            _ = self.args[0].sort.require_bv_width()
            if self.sort != BOOL or self.args[1].sort != self.args[0].sort:
                raise ArtifactError(f"{self.op} operand sorts disagree")
        elif self.op == "eq":
            self._arity(2)
            if (
                self.sort != BOOL
                or self.args[0].sort != self.args[1].sort
                or self.args[0].sort.kind == "array"
            ):
                raise ArtifactError("eq requires equal non-array operands")
        elif self.op == "ite":
            self._arity(3)
            if (
                self.args[0].sort != BOOL
                or self.args[1].sort != self.sort
                or self.args[2].sort != self.sort
            ):
                raise ArtifactError("ite branch sorts disagree")
        elif self.op in {"zero_extend", "sign_extend"}:
            expected = {"amount"}
            self._arity(1)
            amount = _positive(self.amount, "expression.amount")
            if (
                self.sort.require_bv_width()
                != self.args[0].sort.require_bv_width() + amount
            ):
                raise ArtifactError(f"{self.op} widths disagree")
        elif self.op == "extract":
            expected = {"hi", "lo"}
            self._arity(1)
            hi = _nonnegative(self.hi, "expression.hi")
            lo = _nonnegative(self.lo, "expression.lo")
            if (
                lo > hi
                or hi >= self.args[0].sort.require_bv_width()
                or self.sort != TermSort.bv(hi - lo + 1)
            ):
                raise ArtifactError("extract bounds or result width disagree")
        elif self.op == "concat":
            self._arity(2)
            widths = tuple(arg.sort.require_bv_width() for arg in self.args)
            if self.sort != TermSort.bv(sum(widths)):
                raise ArtifactError("concat result width disagrees")
        elif self.op == "select":
            self._arity(2)
            index_width, value_width = self.args[0].sort.require_array_widths()
            if self.args[1].sort != TermSort.bv(
                index_width
            ) or self.sort != TermSort.bv(value_width):
                raise ArtifactError("select operand or result sorts disagree")
        elif self.op == "store":
            self._arity(3)
            index_width, value_width = self.sort.require_array_widths()
            if (
                self.args[0].sort != self.sort
                or self.args[1].sort != TermSort.bv(index_width)
                or self.args[2].sort != TermSort.bv(value_width)
            ):
                raise ArtifactError("store operand or result sorts disagree")
        else:
            raise ArtifactError(f"unknown typed expression operator: {self.op!r}")
        if metadata != expected:
            differences = f"expected={sorted(expected)}, actual={sorted(metadata)}"
            raise ArtifactError(f"{self.op} metadata differs: {differences}")

    def _arity(self, count: int) -> None:
        if len(self.args) != count:
            raise ArtifactError(f"{self.op} requires {count} operands")

    @classmethod
    def var(cls, name: str, sort: TermSort) -> TypedExpr:
        return cls("var", sort, name=name)

    @classmethod
    def bool_lit(cls, value: bool) -> TypedExpr:
        return cls("bool_lit", BOOL, value=value)

    @classmethod
    def bv_lit(cls, width: int, value: int) -> TypedExpr:
        return cls("bv_lit", TermSort.bv(width), value=value)

    @classmethod
    def unary(cls, op: str, arg: TypedExpr) -> TypedExpr:
        return cls(op, BOOL if op == "bool_not" else arg.sort, (arg,))

    @classmethod
    def binary(cls, op: str, lhs: TypedExpr, rhs: TypedExpr) -> TypedExpr:
        result = BOOL if op in _BOOL_BINARY | _BV_COMPARE | {"eq"} else lhs.sort
        return cls(op, result, (lhs, rhs))

    @classmethod
    def ite(
        cls, condition: TypedExpr, then_value: TypedExpr, else_value: TypedExpr
    ) -> TypedExpr:
        return cls("ite", then_value.sort, (condition, then_value, else_value))

    def variable_sorts(self) -> dict[str, TermSort]:
        result: dict[str, TermSort] = {}
        if self.op == "var":
            result[_text(self.name, "expression.name")] = self.sort
        for argument in self.args:
            for name, sort in argument.variable_sorts().items():
                prior = result.setdefault(name, sort)
                if prior != sort:
                    raise ArtifactError(
                        f"variable {name!r} occurs at conflicting sorts"
                    )
        return result

    def to_data(self) -> dict[str, object]:
        result: dict[str, object] = {"op": self.op, "sort": self.sort.to_data()}
        if self.args:
            result["args"] = [argument.to_data() for argument in self.args]
        for name, value in (
            ("name", self.name),
            ("value", self.value),
            ("amount", self.amount),
            ("hi", self.hi),
            ("lo", self.lo),
        ):
            if value is not None:
                result[name] = value
        return result

    @classmethod
    def from_data(cls, value: object, field: str = "expression") -> TypedExpr:
        obj = _object(value, field)
        op = _text(obj.get("op"), f"{field}.op")
        expected = {"op", "sort"}
        if op == "var":
            expected.add("name")
        elif op in {"bool_lit", "bv_lit"}:
            expected.add("value")
        else:
            expected.add("args")
        if op in {"zero_extend", "sign_extend"}:
            expected.add("amount")
        elif op == "extract":
            expected |= {"hi", "lo"}
        _fields(obj, expected, field)
        args = (
            tuple(
                cls.from_data(item, f"{field}.args[]")
                for item in _array(obj["args"], f"{field}.args")
            )
            if "args" in obj
            else ()
        )
        return cls(
            op,
            TermSort.from_data(obj["sort"], f"{field}.sort"),
            args,
            name=_text(obj["name"], f"{field}.name") if "name" in obj else None,
            value=cast(bool | int | None, obj.get("value")),
            amount=(
                _nonnegative(obj["amount"], f"{field}.amount")
                if "amount" in obj
                else None
            ),
            hi=_nonnegative(obj["hi"], f"{field}.hi") if "hi" in obj else None,
            lo=_nonnegative(obj["lo"], f"{field}.lo") if "lo" in obj else None,
        )


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
        if not 0 <= self.source < 1 << 64:
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
