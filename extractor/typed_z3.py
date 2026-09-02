"""One-way Z3 to typed-QF_ABV conversion.

Semantics selectively ported from ghot-effectful-extractor-boundary revision
6b652ff3d791a2a46cf1c487854b1c62ae20da18.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from extractor.artifact import (
    BOOL,
    Assignment,
    ArtifactError,
    Declaration,
    StepSummary,
    Target,
    TermSort,
    TypedExpr,
)
import z3


_BINARY = {
    z3.Z3_OP_BADD: "bv_add",
    z3.Z3_OP_BSUB: "bv_sub",
    z3.Z3_OP_BMUL: "bv_mul",
    z3.Z3_OP_BUDIV: "bv_udiv",
    z3.Z3_OP_BUREM: "bv_urem",
    z3.Z3_OP_BAND: "bv_and",
    z3.Z3_OP_BOR: "bv_or",
    z3.Z3_OP_BXOR: "bv_xor",
    z3.Z3_OP_BSHL: "bv_shl",
    z3.Z3_OP_BLSHR: "bv_lshr",
    z3.Z3_OP_BASHR: "bv_ashr",
    z3.Z3_OP_ULT: "bv_ult",
    z3.Z3_OP_ULEQ: "bv_ule",
    z3.Z3_OP_SLT: "bv_slt",
    z3.Z3_OP_SLEQ: "bv_sle",
    z3.Z3_OP_EQ: "eq",
}
_ASSOCIATIVE_BV = {
    z3.Z3_OP_BADD,
    z3.Z3_OP_BMUL,
    z3.Z3_OP_BAND,
    z3.Z3_OP_BOR,
    z3.Z3_OP_BXOR,
}


def sort_from_z3(sort: z3.SortRef) -> TermSort:
    if isinstance(sort, z3.BoolSortRef):
        return BOOL
    if isinstance(sort, z3.BitVecSortRef):
        return TermSort.bv(sort.size())
    if isinstance(sort, z3.ArraySortRef):
        domain, range_sort = sort.domain(), sort.range()
        if not isinstance(domain, z3.BitVecSortRef) or not isinstance(
            range_sort, z3.BitVecSortRef
        ):
            raise ArtifactError("only BV-indexed BV-valued arrays are admitted")
        return TermSort.array(domain.size(), range_sort.size())
    raise ArtifactError(f"unsupported Z3 sort: {sort}")


def _fold(op: str, arguments: tuple[TypedExpr, ...], identity: bool) -> TypedExpr:
    if not arguments:
        return TypedExpr.bool_lit(identity)
    result = arguments[0]
    for argument in arguments[1:]:
        result = TypedExpr.binary(op, result, argument)
    return result


def expr_from_z3(expression: z3.ExprRef) -> TypedExpr:
    """Translate exactly the admitted ordinary QF_ABV surface."""

    memo: dict[int, TypedExpr] = {}

    def visit(node: z3.ExprRef) -> TypedExpr:
        key = cast(int, node.get_id())
        cached = memo.get(key)
        if cached is not None:
            return cached
        result = convert(node)
        memo[key] = result
        return result

    def convert(node: z3.ExprRef) -> TypedExpr:
        sort = sort_from_z3(node.sort())
        if z3.is_true(node):
            return TypedExpr.bool_lit(True)
        if z3.is_false(node):
            return TypedExpr.bool_lit(False)
        if isinstance(node, z3.BitVecNumRef):
            return TypedExpr.bv_lit(node.size(), node.as_long())

        declaration = node.decl()
        kind = cast(int, declaration.kind())
        raw_children = tuple(cast(list[z3.ExprRef], node.children()))
        if kind in {z3.Z3_OP_AND, z3.Z3_OP_OR}:
            raw_children = tuple(sorted(raw_children, key=lambda child: child.sexpr()))
        children = tuple(visit(child) for child in raw_children)
        if kind == z3.Z3_OP_UNINTERPRETED and not children:
            return TypedExpr.var(str(declaration.name()), sort)
        if kind == z3.Z3_OP_NOT:
            return TypedExpr.unary("bool_not", children[0])
        if kind == z3.Z3_OP_AND:
            return _fold("bool_and", children, True)
        if kind == z3.Z3_OP_OR:
            return _fold("bool_or", children, False)
        if kind == z3.Z3_OP_ITE:
            return TypedExpr.ite(children[0], children[1], children[2])
        if kind == z3.Z3_OP_EQ and len(children) >= 2:
            return _fold(
                "bool_and",
                tuple(
                    TypedExpr.binary("eq", children[0], child) for child in children[1:]
                ),
                True,
            )
        if kind in _ASSOCIATIVE_BV and len(children) >= 2:
            result = children[0]
            for child in children[1:]:
                result = TypedExpr.binary(_BINARY[kind], result, child)
            return result
        if kind in _BINARY:
            if len(children) != 2:
                details = f"arity {len(children)}; expected 2"
                raise ArtifactError(f"Z3 operator {declaration.name()} has {details}")
            return TypedExpr.binary(_BINARY[kind], children[0], children[1])
        if kind == z3.Z3_OP_UGEQ:
            if len(children) != 2:
                raise ArtifactError("unsigned >= must have two operands")
            return TypedExpr.binary("bv_ule", children[1], children[0])
        if kind == z3.Z3_OP_DISTINCT:
            if len(children) != 2:
                raise ArtifactError("only binary distinct is admitted")
            return TypedExpr.unary(
                "bool_not", TypedExpr.binary("eq", children[0], children[1])
            )
        if kind == z3.Z3_OP_BNOT:
            if len(children) != 1:
                raise ArtifactError("bit-vector not must have one operand")
            return TypedExpr.unary("bv_not", children[0])
        if kind in {z3.Z3_OP_ZERO_EXT, z3.Z3_OP_SIGN_EXT}:
            parameters = tuple(cast(list[int], node.params()))
            if len(parameters) != 1:
                raise ArtifactError("Z3 extension has malformed parameters")
            return TypedExpr(
                "zero_extend" if kind == z3.Z3_OP_ZERO_EXT else "sign_extend",
                sort,
                children,
                amount=parameters[0],
            )
        if kind == z3.Z3_OP_EXTRACT:
            parameters = tuple(cast(list[int], node.params()))
            if len(parameters) != 2:
                raise ArtifactError("Z3 extract has malformed parameters")
            return TypedExpr(
                "extract",
                sort,
                children,
                hi=parameters[0],
                lo=parameters[1],
            )
        if kind == z3.Z3_OP_CONCAT:
            if len(children) < 2:
                raise ArtifactError("Z3 concat must have at least two operands")
            result = children[0]
            for child in children[1:]:
                result = TypedExpr(
                    "concat",
                    TermSort.bv(
                        result.sort.require_bv_width() + child.sort.require_bv_width()
                    ),
                    (result, child),
                )
            return result
        if kind == z3.Z3_OP_CONST_ARRAY:
            return TypedExpr("const_array", sort, children)
        if kind == z3.Z3_OP_SELECT:
            return TypedExpr("select", sort, children)
        if kind == z3.Z3_OP_STORE:
            return TypedExpr("store", sort, children)
        raise ArtifactError(f"unsupported Z3 operator {declaration.name()} ({kind})")

    return visit(expression)


def _complete_update(
    declarations: tuple[Declaration, ...],
    updates: Mapping[str, z3.ExprRef],
) -> tuple[Assignment, ...]:
    declared = {declaration.name: declaration for declaration in declarations}
    unknown = set(updates) - set(declared)
    if unknown:
        raise ArtifactError(f"update names are not declared: {sorted(unknown)}")
    result: list[Assignment] = []
    for declaration in declarations:
        value = (
            expr_from_z3(updates[declaration.name])
            if declaration.name in updates
            else TypedExpr.var(declaration.name, declaration.sort)
        )
        if value.sort != declaration.sort:
            raise ArtifactError(f"update for {declaration.name!r} has wrong sort")
        result.append(Assignment(declaration.name, value))
    return tuple(result)


def step_summary_from_z3(
    declarations: tuple[Declaration, ...],
    *,
    guard: z3.BoolRef,
    updates: Mapping[str, z3.ExprRef],
    target: int | z3.BitVecRef | str,
    mirrored_pc: z3.BitVecRef,
) -> StepSummary:
    typed_guard = expr_from_z3(guard)
    typed_pc = expr_from_z3(mirrored_pc)
    if type(target) is int:
        typed_target = Target("address", target)
    elif isinstance(target, z3.BitVecRef):
        typed_target = Target("symbolic", expr_from_z3(target))
    elif target in {"halt", "error", "stuck"}:
        typed_target = Target(target)
    else:
        raise ArtifactError("target is neither address, BV64, nor terminal")
    result = StepSummary(
        typed_guard,
        _complete_update(declarations, updates),
        typed_target,
        typed_pc,
    )
    result.validate(declarations)
    return result
