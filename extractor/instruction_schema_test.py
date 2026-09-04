# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Held-out exact-model and Unicorn checks across register instruction forms."""

from __future__ import annotations

from dataclasses import dataclass

from antiunification import antiunify_values
from extractor import z3_runtime as _z3_runtime
from extractor.angr_boundary import expect_project
from extractor.artifact import InstructionModel
from extractor.extractor import extract
from extractor.fuzzer import fuzz
from extractor.instruction_schema import (
    InstructionVariant,
    generalize_variants,
    instantiate_schema,
)
from extractor.model_syntax import QFAbvSyntax
from extractor.operand_slots import decode_operand_slots
from extractor.runtime import load_shellcode
import pytest


@dataclass(frozen=True)
class RegisterFamily:
    name: str
    left: bytes
    right: bytes
    held_out: bytes


FAMILIES = (
    RegisterFamily(
        "add",
        bytes.fromhex("4801d1"),
        bytes.fromhex("4801d8"),
        bytes.fromhex("4d01c8"),
    ),
    RegisterFamily(
        "adc",
        bytes.fromhex("4811d1"),
        bytes.fromhex("4811d8"),
        bytes.fromhex("4d11c8"),
    ),
    RegisterFamily(
        "sub",
        bytes.fromhex("4829d1"),
        bytes.fromhex("4829d8"),
        bytes.fromhex("4d29c8"),
    ),
    RegisterFamily(
        "xor",
        bytes.fromhex("4831d1"),
        bytes.fromhex("4831d8"),
        bytes.fromhex("4d31c8"),
    ),
    RegisterFamily(
        "cmp",
        bytes.fromhex("4839d1"),
        bytes.fromhex("4839d8"),
        bytes.fromhex("4d39c8"),
    ),
    RegisterFamily(
        "test",
        bytes.fromhex("4885d1"),
        bytes.fromhex("4885d8"),
        bytes.fromhex("4d85c8"),
    ),
    RegisterFamily(
        "mov",
        bytes.fromhex("4889d1"),
        bytes.fromhex("4889d8"),
        bytes.fromhex("4d89c8"),
    ),
    RegisterFamily(
        "imul",
        bytes.fromhex("480fafca"),
        bytes.fromhex("480fafc3"),
        bytes.fromhex("4d0fafc1"),
    ),
    RegisterFamily(
        "xchg",
        bytes.fromhex("4887d1"),
        bytes.fromhex("4887d8"),
        bytes.fromhex("4d87c8"),
    ),
    RegisterFamily(
        "inc",
        bytes.fromhex("48ffc1"),
        bytes.fromhex("48ffc0"),
        bytes.fromhex("49ffc0"),
    ),
)


def acquire_variant(instruction: bytes, address: int = 0x400000) -> InstructionVariant:
    project = expect_project(load_shellcode(instruction, address))
    model: InstructionModel = extract(project, address)
    return InstructionVariant(
        decode_operand_slots(project, address, model),
        model,
    )


@pytest.mark.parametrize("family", FAMILIES, ids=[family.name for family in FAMILIES])
def test_held_out_register_model_is_exact_and_fuzzes(
    family: RegisterFamily,
) -> None:
    assert _z3_runtime.LIBSTDCXX.is_file()
    left = acquire_variant(family.left)
    right = acquire_variant(family.right)
    held_out = acquire_variant(family.held_out)
    syntax = QFAbvSyntax()

    for variant in (left, right, held_out):
        identity = antiunify_values(syntax, variant.model, variant.model)
        assert identity.instantiate(identity.left_substitution) == variant.model
        assert identity.instantiate(identity.right_substitution) == variant.model

    schema = generalize_variants(left, right)
    assert (
        schema.generalization.instantiate(schema.generalization.left_substitution)
        == left.model
    )
    assert (
        schema.generalization.instantiate(schema.generalization.right_substitution)
        == right.model
    )

    instantiated = instantiate_schema(schema, held_out)
    assert instantiated == held_out.model
    assert fuzz(instantiated, family.held_out, examples=100)["status"] == "pass"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
