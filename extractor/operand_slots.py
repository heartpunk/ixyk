# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Decoded operand-slot correspondence to canonical model variables."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, cast

import capstone  # pyright: ignore[reportMissingTypeStubs]

from extractor.angr_boundary import Project
from extractor.artifact import InstructionModel
from extractor.model_syntax import CanonicalVariable, canonical_variable


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

    block = project.factory.block(address, num_inst=1)
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
