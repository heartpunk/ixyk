"""Lossless conversion between Z3 and typed QF_ABV artifacts.

Semantics selectively ported from ghot-effectful-extractor-boundary revision
6b652ff3d791a2a46cf1c487854b1c62ae20da18.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from extractor import z3_boundary as _z3
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
_TYPED_BV_BINARY = {
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
_TYPED_BV_COMPARE = {"bv_ult", "bv_ule", "bv_slt", "bv_sle"}


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


def variables_from_declarations(
    declarations: tuple[Declaration, ...], context: z3.Context
) -> dict[str, z3.ExprRef]:
    """Create the exact free variables named by an artifact."""

    variables: dict[str, z3.ExprRef] = {}
    for declaration in declarations:
        sort = declaration.sort
        if sort == BOOL:
            variable: z3.ExprRef = _z3.boolean(declaration.name, context)
        elif sort.kind == "bv":
            variable = _z3.bit_vec(declaration.name, sort.require_bv_width(), context)
        else:
            index_width, value_width = sort.require_array_widths()
            variable = _z3.array(
                declaration.name,
                _z3.bit_vec_sort(index_width, context),
                _z3.bit_vec_sort(value_width, context),
            )
        variables[declaration.name] = variable
    return variables


def _boolean(expression: z3.ExprRef, operation: str) -> z3.BoolRef:
    if not isinstance(expression, z3.BoolRef):
        raise ArtifactError(f"{operation} did not produce a Boolean")
    return expression


def _bit_vector(expression: z3.ExprRef, operation: str) -> z3.BitVecRef:
    if not isinstance(expression, z3.BitVecRef):
        raise ArtifactError(f"{operation} did not produce a bit-vector")
    return expression


def _array(expression: z3.ExprRef, operation: str) -> z3.ArrayRef:
    if not isinstance(expression, z3.ArrayRef):
        raise ArtifactError(f"{operation} did not produce an array")
    return expression


def expr_to_z3(
    expression: TypedExpr,
    variables: Mapping[str, z3.ExprRef],
    context: z3.Context,
) -> z3.ExprRef:
    """Interpret the admitted typed-QF_ABV surface in Z3."""

    memo: dict[TypedExpr, z3.ExprRef] = {}

    def visit(node: TypedExpr) -> z3.ExprRef:
        cached = memo.get(node)
        if cached is not None:
            return cached
        result = convert(node)
        memo[node] = result
        return result

    def convert(node: TypedExpr) -> z3.ExprRef:
        arguments = tuple(visit(argument) for argument in node.args)
        if node.op == "var":
            if node.name is None or node.name not in variables:
                raise ArtifactError(f"missing Z3 variable for {node.name!r}")
            return variables[node.name]
        if node.op == "bool_lit":
            if type(node.value) is not bool:
                raise ArtifactError("malformed Boolean literal")
            return _z3.bool_val(node.value, context)
        if node.op == "bv_lit":
            if type(node.value) is not int:
                raise ArtifactError("malformed bit-vector literal")
            return _z3.bit_vec_val(node.value, node.sort.require_bv_width(), context)
        if node.op == "bool_not":
            return _z3.negate(_boolean(arguments[0], node.op))
        if node.op == "bool_and":
            return _z3.conjunction(*(_boolean(arg, node.op) for arg in arguments))
        if node.op == "bool_or":
            return _z3.disjunction(*(_boolean(arg, node.op) for arg in arguments))
        if node.op == "eq":
            return _z3.equal(arguments[0], arguments[1])
        if node.op == "ite":
            return _z3.conditional(
                _boolean(arguments[0], node.op), arguments[1], arguments[2]
            )
        if node.op == "bv_not":
            return ~_bit_vector(arguments[0], node.op)
        if node.op in _TYPED_BV_BINARY:
            left = _bit_vector(arguments[0], node.op)
            right = _bit_vector(arguments[1], node.op)
            if node.op == "bv_urem":
                return _z3.unsigned_remainder(left, right)
            if node.op == "bv_lshr":
                return _z3.logical_shift_right(left, right)
            return _z3.bit_vector_binary(node.op, left, right)
        if node.op in _TYPED_BV_COMPARE:
            left = _bit_vector(arguments[0], node.op)
            right = _bit_vector(arguments[1], node.op)
            if node.op == "bv_ult":
                return _z3.unsigned_less(left, right)
            if node.op == "bv_ule":
                return _z3.unsigned_less_equal(left, right)
            return _z3.signed_compare(node.op, left, right)
        if node.op == "zero_extend":
            if node.amount is None:
                raise ArtifactError("zero_extend lacks its amount")
            return _z3.zero_extend(node.amount, _bit_vector(arguments[0], node.op))
        if node.op == "sign_extend":
            if node.amount is None:
                raise ArtifactError("sign_extend lacks its amount")
            return _z3.sign_extend(node.amount, _bit_vector(arguments[0], node.op))
        if node.op == "extract":
            if node.hi is None or node.lo is None:
                raise ArtifactError("extract lacks its bounds")
            return _z3.extract(node.hi, node.lo, _bit_vector(arguments[0], node.op))
        if node.op == "concat":
            return _z3.concat(*(_bit_vector(arg, node.op) for arg in arguments))
        if node.op == "const_array":
            index_width, _ = node.sort.require_array_widths()
            return _z3.constant_array(
                _z3.bit_vec_sort(index_width, context),
                _bit_vector(arguments[0], node.op),
            )
        if node.op == "select":
            return _z3.select(
                _array(arguments[0], node.op),
                _bit_vector(arguments[1], node.op),
            )
        if node.op == "store":
            return _z3.store(
                _array(arguments[0], node.op),
                _bit_vector(arguments[1], node.op),
                _bit_vector(arguments[2], node.op),
            )
        raise ArtifactError(f"unsupported typed operator {node.op!r}")

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
