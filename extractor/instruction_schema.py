# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Operand-variant schemas over canonical typed instruction models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from antiunification import Correspondence, Generalization, antiunify_values
from extractor.artifact import InstructionModel
from extractor.model_syntax import CanonicalVariable, QFAbvSyntax, QFSort
from extractor.operand_slots import DecodedInstruction


class InstructionSchemaError(ValueError):
    """Instruction observations do not determine one operand-slot schema."""


@dataclass(frozen=True)
class InstructionVariant:
    decoded: DecodedInstruction
    model: InstructionModel


@dataclass(frozen=True)
class InstructionSchema:
    decoded_shape: tuple[str, tuple[tuple[int, int, int, int], ...]]
    generalization: Generalization[object, str, object, QFSort]
    parameter_slots: tuple[tuple[str, int], ...]


def _variable_slots(decoded: DecodedInstruction) -> dict[int, CanonicalVariable]:
    return {
        operand.index: operand.variable
        for operand in decoded.operands
        if operand.variable is not None
    }


def generalize_variants(
    left: InstructionVariant,
    right: InstructionVariant,
) -> InstructionSchema:
    """Anti-unify full models using decoder-provided slot correspondence."""

    if left.decoded.shape != right.decoded.shape:
        raise InstructionSchemaError("decoded operand layouts disagree")
    left_slots = _variable_slots(left.decoded)
    right_slots = _variable_slots(right.decoded)
    if left_slots.keys() != right_slots.keys():
        raise InstructionSchemaError("decoded canonical-variable slots disagree")
    correspondences = tuple(
        Correspondence(f"operand_{index}", left_slots[index], right_slots[index])
        for index in left_slots
    )
    result = antiunify_values(
        QFAbvSyntax(),
        cast(object, left.model),
        cast(object, right.model),
        correspondences=cast(tuple[Correspondence[object], ...], correspondences),
    )
    explained = {item.name for item in correspondences}
    unexplained = set(result.left_substitution) - explained
    if unexplained:
        raise InstructionSchemaError(
            f"model disagreements escape decoded operands: {sorted(unexplained)}"
        )
    parameter_slots = tuple(
        (name, int(name.removeprefix("operand_"))) for name in result.left_substitution
    )
    return InstructionSchema(left.decoded.shape, result, parameter_slots)


def instantiate_schema(
    schema: InstructionSchema,
    variant: InstructionVariant,
) -> InstructionModel:
    """Instantiate a model schema from one held-out decoded operand layout."""

    if variant.decoded.shape != schema.decoded_shape:
        raise InstructionSchemaError("held-out decoded operand layout disagrees")
    variables = _variable_slots(variant.decoded)
    missing = {slot for _, slot in schema.parameter_slots} - variables.keys()
    if missing:
        raise InstructionSchemaError(
            f"held-out instruction lacks canonical slots: {sorted(missing)}"
        )
    value = schema.generalization.instantiate(
        {name: variables[slot] for name, slot in schema.parameter_slots}
    )
    if not isinstance(value, InstructionModel):
        raise InstructionSchemaError("schema did not reconstruct an instruction model")
    return value
