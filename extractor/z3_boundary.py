# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Validated typed access to the untyped parts of z3py used by ixyk."""

from __future__ import annotations

from collections.abc import Callable

import z3


def _function(name: str) -> Callable[..., object]:
    candidate: object = getattr(z3, name, None)
    if not callable(candidate):
        raise TypeError(f"z3.{name} is unavailable")
    return candidate


def _method(receiver: object, name: str) -> Callable[..., object]:
    candidate: object = getattr(receiver, name, None)
    if not callable(candidate):
        raise TypeError(f"{type(receiver).__name__}.{name} is unavailable")
    return candidate


def _expect[Ast: z3.AstRef](value: object, kind: type[Ast], operation: str) -> Ast:
    if not isinstance(value, kind):
        raise TypeError(f"z3.{operation} returned {type(value).__name__}")
    return value


def bit_vec(name: str, width: int, ctx: z3.Context) -> z3.BitVecRef:
    return _expect(_function("BitVec")(name, width, ctx=ctx), z3.BitVecRef, "BitVec")


def boolean(name: str, ctx: z3.Context) -> z3.BoolRef:
    return _expect(_function("Bool")(name, ctx=ctx), z3.BoolRef, "Bool")


def integer(name: str, ctx: z3.Context) -> z3.ArithRef:
    return _expect(_function("Int")(name, ctx=ctx), z3.ArithRef, "Int")


def bit_vec_sort(width: int, ctx: z3.Context) -> z3.BitVecSortRef:
    return _expect(
        _function("BitVecSort")(width, ctx=ctx),
        z3.BitVecSortRef,
        "BitVecSort",
    )


def array(
    name: str,
    domain: z3.SortRef,
    range_: z3.SortRef,
) -> z3.ArrayRef:
    return _expect(_function("Array")(name, domain, range_), z3.ArrayRef, "Array")


def bit_vec_val(value: int, width: int, ctx: z3.Context) -> z3.BitVecNumRef:
    return _expect(
        _function("BitVecVal")(value, width, ctx=ctx),
        z3.BitVecNumRef,
        "BitVecVal",
    )


def bool_val(value: bool, ctx: z3.Context) -> z3.BoolRef:
    return _expect(_function("BoolVal")(value, ctx=ctx), z3.BoolRef, "BoolVal")


def constant_array(
    domain: z3.BitVecSortRef,
    value: z3.BitVecRef,
) -> z3.ArrayRef:
    return _expect(_function("K")(domain, value), z3.ArrayRef, "K")


def select(array_: z3.ArrayRef, index: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("Select")(array_, index), z3.BitVecRef, "Select")


def concat(*pieces: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("Concat")(*pieces), z3.BitVecRef, "Concat")


def store(
    array_: z3.ArrayRef,
    index: z3.BitVecRef,
    value: z3.BitVecRef,
) -> z3.ArrayRef:
    return _expect(_function("Store")(array_, index, value), z3.ArrayRef, "Store")


def extract(high: int, low: int, value: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("Extract")(high, low, value), z3.BitVecRef, "Extract")


def simplify(expression: z3.ExprRef) -> z3.ExprRef:
    return _expect(_function("simplify")(expression), z3.ExprRef, "simplify")


def substitute(
    expression: z3.ExprRef,
    *replacements: tuple[z3.ExprRef, z3.ExprRef],
) -> z3.ExprRef:
    return _expect(
        _function("substitute")(expression, *replacements),
        z3.ExprRef,
        "substitute",
    )


def conjunction(*terms: z3.BoolRef) -> z3.BoolRef:
    return _expect(_function("And")(*terms), z3.BoolRef, "And")


def disjunction(*terms: z3.BoolRef) -> z3.BoolRef:
    return _expect(_function("Or")(*terms), z3.BoolRef, "Or")


def negate(term: z3.BoolRef) -> z3.BoolRef:
    return _expect(_function("Not")(term), z3.BoolRef, "Not")


def equal(left: z3.ExprRef, right: z3.ExprRef) -> z3.BoolRef:
    return _expect(left == right, z3.BoolRef, "equality")


def conditional(
    condition: z3.BoolRef,
    then_value: z3.ExprRef,
    else_value: z3.ExprRef,
) -> z3.ExprRef:
    return _expect(_function("If")(condition, then_value, else_value), z3.ExprRef, "If")


def zero_extend(amount: int, value: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("ZeroExt")(amount, value), z3.BitVecRef, "ZeroExt")


def sign_extend(amount: int, value: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("SignExt")(amount, value), z3.BitVecRef, "SignExt")


def logical_shift_right(left: z3.BitVecRef, right: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("LShR")(left, right), z3.BitVecRef, "LShR")


def unsigned_remainder(left: z3.BitVecRef, right: z3.BitVecRef) -> z3.BitVecRef:
    return _expect(_function("URem")(left, right), z3.BitVecRef, "URem")


def unsigned_less(left: z3.BitVecRef, right: z3.BitVecRef) -> z3.BoolRef:
    return _expect(_function("ULT")(left, right), z3.BoolRef, "ULT")


def unsigned_less_equal(left: z3.BitVecRef, right: z3.BitVecRef) -> z3.BoolRef:
    return _expect(_function("ULE")(left, right), z3.BoolRef, "ULE")


def bit_vector_binary(
    operation: str,
    left: z3.BitVecRef,
    right: z3.BitVecRef,
) -> z3.BitVecRef:
    if operation == "bv_udiv":
        return _expect(_function("UDiv")(left, right), z3.BitVecRef, operation)
    methods = {
        "bv_add": "__add__",
        "bv_sub": "__sub__",
        "bv_mul": "__mul__",
        "bv_and": "__and__",
        "bv_or": "__or__",
        "bv_xor": "__xor__",
        "bv_shl": "__lshift__",
        "bv_ashr": "__rshift__",
    }
    method = methods.get(operation)
    if method is None:
        raise ValueError(f"unknown bit-vector operation {operation!r}")
    return _expect(_method(left, method)(right), z3.BitVecRef, operation)


def signed_compare(
    operation: str,
    left: z3.BitVecRef,
    right: z3.BitVecRef,
) -> z3.BoolRef:
    methods = {"bv_slt": "__lt__", "bv_sle": "__le__"}
    method = methods.get(operation)
    if method is None:
        raise ValueError(f"unknown signed comparison {operation!r}")
    return _expect(_method(left, method)(right), z3.BoolRef, operation)


def solver(context: z3.Context) -> z3.Solver:
    result = _function("Solver")(ctx=context)
    if not isinstance(result, z3.Solver):
        raise TypeError(f"z3.Solver returned {type(result).__name__}")
    return result


def solver_model(solver: z3.Solver) -> z3.ModelRef:
    result = _method(solver, "model")()
    if not isinstance(result, z3.ModelRef):
        raise TypeError(f"Z3 Solver.model returned {type(result).__name__}")
    return result


def model_eval(model: z3.ModelRef, expression: z3.ExprRef) -> z3.ExprRef:
    return _expect(
        _method(model, "eval")(expression, model_completion=True),
        z3.ExprRef,
        "Model.eval",
    )


def require_sat(result: z3.CheckSatResult) -> None:
    if result.r != z3.Z3_L_TRUE:
        raise AssertionError(f"expected satisfiable model, got {result}")


def structurally_equal(left: z3.ExprRef, right: z3.ExprRef) -> bool:
    result = _method(left, "eq")(right)
    if type(result) is not bool:
        raise TypeError(f"Z3 equality returned {type(result).__name__}")
    return result


def solver_add(solver: z3.Solver, constraint: z3.BoolRef) -> None:
    result = _method(solver, "add")(constraint)
    if result is not None:
        raise TypeError(f"Z3 Solver.add returned {type(result).__name__}")


def solver_check(solver: z3.Solver) -> z3.CheckSatResult:
    result = _method(solver, "check")()
    if not isinstance(result, z3.CheckSatResult):
        raise TypeError(f"Z3 Solver.check returned {type(result).__name__}")
    return result


def check_status(result: z3.CheckSatResult) -> int:
    status: object = getattr(result, "r", None)
    if type(status) is not int:
        raise TypeError(f"Z3 check result has invalid status {status!r}")
    return status


def translate(backend: object, ast: object, ctx: z3.Context) -> z3.ExprRef:
    converted = _method(backend, "convert")(ast)
    return _expect(_method(converted, "translate")(ctx), z3.ExprRef, "translate")
