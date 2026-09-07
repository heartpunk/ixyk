# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Decoded operand-slot correspondence to canonical model variables."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast

import capstone  # pyright: ignore[reportMissingTypeStubs]

from extractor.angr_boundary import Project, lift_block
from extractor.artifact import Declaration, InstructionModel, TermSort
from extractor.model_syntax import (
    AddressAtom,
    BitVectorAtom,
    CanonicalVariable,
    canonical_variable,
)
from extractor.au_inputs import parameters
from extractor.xed import InstructionInfo, registers, relative_target


def canonical_bindings(
    decoded: InstructionInfo, declarations: tuple[Declaration, ...], source: int
) -> dict[str, object]:
    """Translate XED operand values to atoms of the canonical model syntax."""
    bank = {register["name"]: register for register in registers()}

    def variable(name: str) -> CanonicalVariable:
        register = bank[name]
        matches = [
            declaration
            for declaration in declarations
            if declaration.name.upper() in bank
            and bank[declaration.name.upper()]["parent"] == register["parent"]
            and bank[declaration.name.upper()]["width"] >= register["width"]
        ]
        if len(matches) != 1:
            raise OperandDecodeError(f"no unique canonical register for {name}")
        return CanonicalVariable(matches[0].name, matches[0].sort)

    bindings: dict[str, object] = {}
    operands = {operand["name"]: operand for operand in decoded["operands"]}
    for field, value in parameters(decoded).items():
        if isinstance(value, str):
            bindings[field] = variable(value)
        elif field == "RELBR":
            target = relative_target(decoded, source)
            bindings[field + "_address"] = AddressAtom(target)
            bindings[field + "_bv"] = BitVectorAtom(target, TermSort.bv(64))
        elif field == "IMM0":
            width = operands[field]["width"]
            if decoded["immediate_signed"]:
                encoded_width = decoded["immediate_width"]
                if value & (1 << (encoded_width - 1)):
                    value -= 1 << encoded_width
            bindings[field] = BitVectorAtom(value % (1 << width), TermSort.bv(width))
        else:
            bindings[field] = BitVectorAtom(value % (1 << 64), TermSort.bv(64))
    return bindings


def normalization_labels(bindings: Mapping[str, object]) -> dict[str, tuple[str, ...]]:
    """Give canonical variables stable labels from their supplied correspondence."""
    labels: dict[str, list[str]] = {}
    for label, atom in bindings.items():
        if isinstance(atom, CanonicalVariable):
            labels.setdefault(atom.name, []).append(label)
    return {name: tuple(sorted(roles)) for name, roles in labels.items()}


class OperandDecodeError(ValueError):
    """A decoded instruction cannot provide an unambiguous operand layout."""


class _Operand(Protocol):
    access: int
    reg: int
    size: int
    type: int


class _Instruction(Protocol):
    mnemonic: str
    operands: Sequence[_Operand]
    size: int

    def reg_name(self, register: int) -> str: ...


@dataclass(frozen=True)
class OperandSlot:
    index: int
    kind: int
    access: int
    width: int
    variable: CanonicalVariable | None

    @property
    def shape(self) -> tuple[int, int, int, int]:
        return self.index, self.kind, self.access, self.width


@dataclass(frozen=True)
class DecodedInstruction:
    mnemonic: str
    size: int
    operands: tuple[OperandSlot, ...]

    @property
    def shape(self) -> tuple[str, tuple[tuple[int, int, int, int], ...]]:
        return self.mnemonic, tuple(operand.shape for operand in self.operands)


def decode_operand_slots(
    project: Project,
    address: int,
    model: InstructionModel,
) -> DecodedInstruction:
    """Decode slots and bind explicit register operands to canonical variables."""

    block = lift_block(project, address, num_inst=1)
    if block.vex.instructions != 1 or len(block.capstone.insns) != 1:
        raise OperandDecodeError("expected exactly one decoded instruction")
    wrapped = block.capstone.insns[0]
    instruction = cast(_Instruction, getattr(wrapped, "insn"))
    operands: list[OperandSlot] = []
    for index, operand in enumerate(instruction.operands):
        variable = None
        if operand.type == capstone.x86.X86_OP_REG:
            name = instruction.reg_name(operand.reg)
            try:
                variable = canonical_variable(model, name)
            except ValueError as exc:
                raise OperandDecodeError(
                    f"decoded register {name!r} has no canonical variable"
                ) from exc
        operands.append(
            OperandSlot(
                index=index,
                kind=operand.type,
                access=operand.access,
                width=operand.size * 8,
                variable=variable,
            )
        )
    return DecodedInstruction(instruction.mnemonic, instruction.size, tuple(operands))
