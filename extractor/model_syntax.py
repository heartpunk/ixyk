# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Ordinary typed syntax exposure for canonical QF_ABV instruction models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from antiunification import AlgebraError, Application, Atom, FiniteMap, Layer
from extractor.artifact import (
    Assignment,
    Declaration,
    InstructionModel,
    StepSummary,
    Target,
    TermSort,
    TypedExpr,
)


@dataclass(frozen=True)
class QFSort:
    kind: str
    term: TermSort | None = None


@dataclass(frozen=True)
class CanonicalVariable:
    name: str
    sort: TermSort


@dataclass(frozen=True)
class AddressAtom:
    value: int


@dataclass(frozen=True)
class BooleanAtom:
    value: bool


@dataclass(frozen=True)
class BitVectorAtom:
    value: int
    sort: TermSort


@dataclass(frozen=True)
class NaturalAtom:
    kind: str
    value: int


@dataclass(frozen=True)
class Declarations:
    values: tuple[Declaration, ...]


@dataclass(frozen=True)
class Steps:
    values: tuple[object, ...]


@dataclass(frozen=True)
class ModelStep:
    declarations: tuple[Declaration, ...]
    value: StepSummary


@dataclass(frozen=True)
class StateUpdate:
    declarations: tuple[Declaration, ...]
    writes: tuple[tuple[CanonicalVariable, TypedExpr], ...]


@dataclass(frozen=True)
class SparseWrites:
    entries: tuple[tuple[CanonicalVariable, TypedExpr], ...]


MODEL = QFSort("instruction_model")
DECLARATIONS = QFSort("declarations")
DECLARATION = QFSort("declaration")
STEPS = QFSort("steps")
STEP = QFSort("step")
STATE_UPDATE = QFSort("state_update")
SPARSE_WRITES = QFSort("sparse_writes")
TARGET = QFSort("target")
TERM_SORT = QFSort("term_sort")
ADDRESS = QFSort("address")
NATURAL = QFSort("natural")


def expression_sort(sort: TermSort) -> QFSort:
    return QFSort("expression", sort)


def variable_sort(sort: TermSort) -> QFSort:
    return QFSort("canonical_variable", sort)


def literal_sort(sort: TermSort) -> QFSort:
    return QFSort("literal", sort)


class QFAbvSyntax:
    """Expose and exactly reconstruct the canonical instruction syntax."""

    def expose(self, value: object) -> Layer[object, str, object, QFSort]:
        if isinstance(value, InstructionModel):
            return Application(
                MODEL,
                "instruction_model",
                (
                    AddressAtom(value.source),
                    Declarations(value.declarations),
                    Steps(
                        tuple(
                            ModelStep(value.declarations, step) for step in value.steps
                        )
                    ),
                ),
            )
        if isinstance(value, Declarations):
            return Application(DECLARATIONS, "declarations", value.values)
        if isinstance(value, Declaration):
            return Application(
                DECLARATION,
                "declaration",
                (CanonicalVariable(value.name, value.sort), value.sort),
            )
        if isinstance(value, Steps):
            return Application(STEPS, "steps", value.values)
        if isinstance(value, ModelStep):
            step = value.value
            writes = tuple(
                (
                    CanonicalVariable(assignment.name, declaration.sort),
                    assignment.value,
                )
                for declaration, assignment in zip(
                    value.declarations,
                    step.simultaneous_update,
                    strict=True,
                )
                if assignment.value != TypedExpr.var(declaration.name, declaration.sort)
            )
            return Application(
                STEP,
                "step",
                (
                    step.guard,
                    StateUpdate(value.declarations, writes),
                    step.target,
                    step.mirrored_pc,
                ),
            )
        if isinstance(value, StateUpdate):
            return Application(
                STATE_UPDATE,
                "state_update",
                (Declarations(value.declarations), SparseWrites(value.writes)),
            )
        if isinstance(value, SparseWrites):
            return FiniteMap(SPARSE_WRITES, value.entries)
        if isinstance(value, Target):
            if value.kind == "address":
                return Application(
                    TARGET,
                    "target:address",
                    (AddressAtom(cast(int, value.value)),),
                )
            if value.kind == "symbolic":
                return Application(
                    TARGET,
                    "target:symbolic",
                    (cast(TypedExpr, value.value),),
                )
            return Application(TARGET, f"target:{value.kind}", ())
        if isinstance(value, TypedExpr):
            arguments: list[object]
            if value.op == "var":
                arguments = [CanonicalVariable(cast(str, value.name), value.sort)]
            elif value.op == "bool_lit":
                arguments = [BooleanAtom(cast(bool, value.value))]
            elif value.op == "bv_lit":
                arguments = [BitVectorAtom(cast(int, value.value), value.sort)]
            else:
                arguments = list(value.args)
                for kind, metadata in (
                    ("amount", value.amount),
                    ("hi", value.hi),
                    ("lo", value.lo),
                ):
                    if metadata is not None:
                        arguments.append(NaturalAtom(kind, metadata))
            return Application(
                expression_sort(value.sort),
                f"expression:{value.op}",
                tuple(arguments),
            )
        if isinstance(value, CanonicalVariable):
            return Atom(variable_sort(value.sort), value)
        if isinstance(value, TermSort):
            return Atom(TERM_SORT, value)
        if isinstance(value, AddressAtom):
            return Atom(ADDRESS, value)
        if isinstance(value, BooleanAtom):
            return Atom(literal_sort(TermSort.bool()), value)
        if isinstance(value, BitVectorAtom):
            return Atom(literal_sort(value.sort), value)
        if isinstance(value, NaturalAtom):
            return Atom(NATURAL, value)
        raise AlgebraError(f"unsupported QF_ABV value: {type(value).__name__}")

    def reconstruct(
        self,
        layer: Layer[object, str, object, QFSort],
    ) -> object:
        if isinstance(layer, Atom):
            return layer.value
        if isinstance(layer, FiniteMap):
            return self._reconstruct_map(layer)
        constructor = layer.constructor
        arguments = layer.arguments
        if constructor == "instruction_model":
            source, declarations, steps = arguments
            if not isinstance(source, AddressAtom):
                raise AlgebraError("instruction source is not an address")
            if not isinstance(declarations, Declarations):
                raise AlgebraError("instruction declarations are malformed")
            if not isinstance(steps, Steps):
                raise AlgebraError("instruction steps are malformed")
            if not all(isinstance(step, StepSummary) for step in steps.values):
                raise AlgebraError("instruction step is malformed")
            return InstructionModel(
                source.value,
                declarations.values,
                cast(tuple[StepSummary, ...], steps.values),
            )
        if constructor == "declarations":
            if not all(isinstance(item, Declaration) for item in arguments):
                raise AlgebraError("declaration list is malformed")
            return Declarations(cast(tuple[Declaration, ...], arguments))
        if constructor == "declaration":
            variable, sort = arguments
            if not isinstance(variable, CanonicalVariable):
                raise AlgebraError("declaration variable is malformed")
            if not isinstance(sort, TermSort) or variable.sort != sort:
                raise AlgebraError("declaration sort is malformed")
            return Declaration(variable.name, sort)
        if constructor == "steps":
            return Steps(arguments)
        if constructor == "state_update":
            declarations, writes = arguments
            if not isinstance(declarations, Declarations):
                raise AlgebraError("state-update declarations are malformed")
            if not isinstance(writes, SparseWrites):
                raise AlgebraError("state-update writes are malformed")
            return StateUpdate(declarations.values, writes.entries)
        if constructor == "step":
            return self._reconstruct_step(arguments)
        if constructor.startswith("target:"):
            return self._reconstruct_target(constructor, arguments)
        if constructor.startswith("expression:"):
            return self._reconstruct_expression(layer)
        raise AlgebraError(f"unknown QF_ABV constructor: {constructor!r}")

    def _reconstruct_map(
        self,
        layer: FiniteMap[object, QFSort],
    ) -> SparseWrites:
        if layer.sort != SPARSE_WRITES:
            raise AlgebraError("unexpected finite-map sort")
        entries: list[tuple[CanonicalVariable, TypedExpr]] = []
        for key, value in layer.entries:
            if not isinstance(key, CanonicalVariable):
                raise AlgebraError("state-write key is malformed")
            if not isinstance(value, TypedExpr):
                raise AlgebraError("state-write value is malformed")
            if any(prior == key for prior, _ in entries):
                raise AlgebraError("sparse state update has duplicate keys")
            entries.append((key, value))
        return SparseWrites(tuple(entries))

    def _reconstruct_step(self, arguments: tuple[object, ...]) -> StepSummary:
        guard, update, target, mirrored_pc = arguments
        if not isinstance(guard, TypedExpr):
            raise AlgebraError("step guard is malformed")
        if not isinstance(update, StateUpdate):
            raise AlgebraError("step state update is malformed")
        if not isinstance(target, Target) or not isinstance(mirrored_pc, TypedExpr):
            raise AlgebraError("step control target is malformed")
        declared = {item.name: item.sort for item in update.declarations}
        writes = {key.name: value for key, value in update.writes}
        if len(writes) != len(update.writes):
            raise AlgebraError("state update contains duplicate variables")
        if any(
            key.name not in declared or declared[key.name] != key.sort
            for key, _ in update.writes
        ):
            raise AlgebraError("state update writes an undeclared variable")
        return StepSummary(
            guard,
            tuple(
                Assignment(
                    declaration.name,
                    writes.get(
                        declaration.name,
                        TypedExpr.var(declaration.name, declaration.sort),
                    ),
                )
                for declaration in update.declarations
            ),
            target,
            mirrored_pc,
        )

    def _reconstruct_target(
        self,
        constructor: str,
        arguments: tuple[object, ...],
    ) -> Target:
        kind = constructor.removeprefix("target:")
        if kind == "address":
            if len(arguments) != 1 or not isinstance(arguments[0], AddressAtom):
                raise AlgebraError("address target is malformed")
            return Target(kind, arguments[0].value)
        if kind == "symbolic":
            if len(arguments) != 1 or not isinstance(arguments[0], TypedExpr):
                raise AlgebraError("symbolic target is malformed")
            return Target(kind, arguments[0])
        if arguments:
            raise AlgebraError("terminal target unexpectedly has arguments")
        return Target(kind)

    def _reconstruct_expression(
        self,
        layer: Application[object, str, QFSort],
    ) -> TypedExpr:
        if layer.sort.kind != "expression" or layer.sort.term is None:
            raise AlgebraError("expression sort is malformed")
        op = layer.constructor.removeprefix("expression:")
        sort = layer.sort.term
        arguments = layer.arguments
        if op == "var":
            if len(arguments) != 1 or not isinstance(arguments[0], CanonicalVariable):
                raise AlgebraError("variable expression is malformed")
            variable = arguments[0]
            if variable.sort != sort:
                raise AlgebraError("variable expression sort disagrees")
            return TypedExpr.var(variable.name, variable.sort)
        if op == "bool_lit":
            if len(arguments) != 1 or not isinstance(arguments[0], BooleanAtom):
                raise AlgebraError("Boolean literal is malformed")
            return TypedExpr.bool_lit(arguments[0].value)
        if op == "bv_lit":
            if len(arguments) != 1 or not isinstance(arguments[0], BitVectorAtom):
                raise AlgebraError("bit-vector literal is malformed")
            literal = arguments[0]
            if literal.sort != sort:
                raise AlgebraError("bit-vector literal sort disagrees")
            return TypedExpr.bv_lit(sort.require_bv_width(), literal.value)
        expression_arguments: list[TypedExpr] = []
        metadata: dict[str, int] = {}
        for argument in arguments:
            if isinstance(argument, NaturalAtom):
                if argument.kind in metadata:
                    raise AlgebraError("expression metadata is duplicated")
                metadata[argument.kind] = argument.value
            elif isinstance(argument, TypedExpr):
                expression_arguments.append(argument)
            else:
                raise AlgebraError("expression argument is malformed")
        return TypedExpr(
            op,
            sort,
            tuple(expression_arguments),
            amount=metadata.get("amount"),
            hi=metadata.get("hi"),
            lo=metadata.get("lo"),
        )


def canonical_variable(model: InstructionModel, name: str) -> CanonicalVariable:
    matches = [item.sort for item in model.declarations if item.name == name]
    if len(matches) != 1:
        raise AlgebraError(f"canonical variable {name!r} is not uniquely declared")
    return CanonicalVariable(name, matches[0])
