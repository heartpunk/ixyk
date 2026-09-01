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


def negate(term: z3.BoolRef) -> z3.BoolRef:
    return _expect(_function("Not")(term), z3.BoolRef, "Not")


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


def translate(backend: object, ast: object, ctx: z3.Context) -> z3.ExprRef:
    converted = _method(backend, "convert")(ast)
    return _expect(_method(converted, "translate")(ctx), z3.ExprRef, "translate")
