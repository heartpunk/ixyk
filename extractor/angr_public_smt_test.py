# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Regression checks for Angr's public Claripy-to-Z3 boundary."""

from __future__ import annotations

from extractor import runtime
from extractor.amd64_state import LTS_EXTRACTION_CONTEXT, claripy_to_z3
from extractor.angr_boundary import claripy
import z3


def test_runtime_probe_checks_the_pinned_angr_public_api() -> None:
    result = runtime.run_probe()

    assert result["python"] == "3.12.13"
    assert result["mnemonics"] == ["mov", "ret"]
    assert result["solution"] == 0x1234


def _assert_equivalent(left: z3.ExprRef, right: z3.ExprRef) -> None:
    solver = z3.Solver(ctx=LTS_EXTRACTION_CONTEXT)
    solver.add(left != right)
    assert solver.check() == z3.unsat


def test_public_smt_export_preserves_bit_vector_names_and_widths() -> None:
    value = claripy.BVS("register_rax", 64, explicit_name=True)
    expression = value + claripy.BVV(7, 64)

    converted = claripy_to_z3(expression)
    expected = z3.BitVec("register_rax", 64, ctx=LTS_EXTRACTION_CONTEXT) + z3.BitVecVal(
        7, 64, ctx=LTS_EXTRACTION_CONTEXT
    )

    assert isinstance(converted, z3.BitVecRef)
    assert converted.ctx == LTS_EXTRACTION_CONTEXT
    assert converted.size() == 64
    _assert_equivalent(converted, expected)


def test_public_smt_export_preserves_boolean_symbols() -> None:
    condition = claripy.BoolS("branch_condition", explicit_name=True)
    converted = claripy_to_z3(condition)
    expected = z3.Bool("branch_condition", ctx=LTS_EXTRACTION_CONTEXT)

    assert isinstance(converted, z3.BoolRef)
    assert converted.ctx == LTS_EXTRACTION_CONTEXT
    _assert_equivalent(converted, expected)


def test_boolean_literals_and_result_name_collisions_are_preserved() -> None:
    true_value = claripy_to_z3(claripy.BoolV(True))
    false_value = claripy_to_z3(claripy.BoolV(False))
    assert z3.is_true(true_value)
    assert z3.is_false(false_value)

    source = claripy.BVS("__ixyk_smt_result", 8, explicit_name=True)
    expression = source + claripy.BVV(1, 8)
    converted = claripy_to_z3(expression)
    expected = z3.BitVec(
        "__ixyk_smt_result", 8, ctx=LTS_EXTRACTION_CONTEXT
    ) + z3.BitVecVal(1, 8, ctx=LTS_EXTRACTION_CONTEXT)

    assert claripy_to_z3(expression) is converted
    _assert_equivalent(converted, expected)


if __name__ == "__main__":
    import pytest

    raise SystemExit(pytest.main([__file__]))
