# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Experimental, semantics-preserving normalization of typed QF_ABV syntax."""

from dataclasses import replace
from collections.abc import Mapping
from typing import cast

from extractor.artifact import Assignment, InstructionModel, TypedExpr


def normalize_expression(
    expression: TypedExpr, variable_labels: Mapping[str, tuple[str, ...]] | None = None
) -> TypedExpr:
    memo: dict[int, TypedExpr] = {}
    labels = variable_labels or {}

    def order_key(node: TypedExpr) -> tuple[object, ...]:
        sort = node.sort
        name = cast(str, node.name) if node.op == "var" else ""
        variable = (0, labels[name]) if name in labels else (1, (name,))
        return (
            node.op,
            sort.kind,
            sort.width or 0,
            sort.index_width or 0,
            sort.value_width or 0,
            variable,
            -1 if node.value is None else int(node.value),
            -1 if node.amount is None else node.amount,
            -1 if node.hi is None else node.hi,
            -1 if node.lo is None else node.lo,
            tuple(order_key(arg) for arg in node.args),
        )

    def complement(value: TypedExpr) -> TypedExpr:
        if value.op == "bv_not":
            return value.args[0]
        if value.op == "bv_lit":
            width = value.sort.require_bv_width()
            return TypedExpr.bv_lit(width, ((1 << width) - 1) ^ cast(int, value.value))
        return TypedExpr.unary("bv_not", value)

    def scaling(node: TypedExpr) -> tuple[int, TypedExpr] | None:
        width = node.sort.require_bv_width()
        if node.op == "bv_mul":
            for literal, term in (node.args, node.args[::-1]):
                if literal.op == "bv_lit":
                    return cast(int, literal.value), term
        if node.op == "bv_shl" and node.args[1].op == "bv_lit":
            amount = cast(int, node.args[1].value)
            return (1 << amount if amount < width else 0), node.args[0]
        if node.op == "concat" and len(node.args) == 2:
            high, low = node.args
            if high.op == "extract" and low.op == "bv_lit" and low.value == 0:
                amount = low.sort.require_bv_width()
                original = high.args[0]
                if (
                    original.sort == node.sort
                    and high.lo == 0
                    and high.hi == width - amount - 1
                ):
                    return 1 << amount, original
        return None

    def arithmetic(node: TypedExpr) -> TypedExpr:
        width = node.sort.require_bv_width()
        modulus = 1 << width
        terms: dict[TypedExpr, int] = {}
        constant = 0

        def collect(term: TypedExpr, coefficient: int) -> None:
            nonlocal constant
            if term.op == "bv_lit":
                constant += coefficient * cast(int, term.value)
            elif term.op in {"bv_add", "bv_sub"}:
                collect(term.args[0], coefficient)
                collect(
                    term.args[1], coefficient if term.op == "bv_add" else -coefficient
                )
            elif (scaled := scaling(term)) is not None:
                factor, value = scaled
                collect(value, coefficient * factor)
            else:
                terms[term] = terms.get(term, 0) + coefficient

        collect(node, 1)
        summands = [
            TypedExpr.binary(
                "bv_mul", TypedExpr.bv_lit(width, coefficient % modulus), term
            )
            for term, coefficient in sorted(
                terms.items(), key=lambda item: order_key(item[0])
            )
            if coefficient % modulus
        ]
        if constant % modulus or not summands:
            summands.append(TypedExpr.bv_lit(width, constant % modulus))
        result = summands[0]
        for term in summands[1:]:
            result = TypedExpr.binary("bv_add", result, term)
        return result

    def visit(node: TypedExpr) -> TypedExpr:
        if id(node) in memo:
            return memo[id(node)]
        args = tuple(visit(arg) for arg in node.args)
        value = replace(node, args=args) if args != node.args else node
        if node.op == "bv_not":
            value = complement(args[0])
        elif node.op == "bv_mul":
            # Commutativity, ordered by symbolic labels rather than register names.
            if order_key(args[1]) < order_key(args[0]):
                value = replace(value, args=(args[1], args[0]))
        elif node.op == "bv_xor":
            left, right = args
            width = node.sort.require_bv_width()
            if left == right:
                value = TypedExpr.bv_lit(width, 0)
            elif left.op == right.op == "bv_lit":
                value = TypedExpr.bv_lit(
                    width, cast(int, left.value) ^ cast(int, right.value)
                )
            else:
                for literal, other in ((left, right), (right, left)):
                    if literal.op == "bv_lit" and literal.value == 0:
                        value = other
                    elif literal.op == "bv_lit" and literal.value == (1 << width) - 1:
                        value = complement(other)
        if value.sort.kind == "bv" and (
            value.op in {"bv_add", "bv_sub"} or scaling(value) is not None
        ):
            value = arithmetic(value)
        memo[id(node)] = value
        return value

    return visit(expression)


def normalize_model(
    model: InstructionModel,
    variable_labels: Mapping[str, tuple[str, ...]] | None = None,
) -> InstructionModel:
    def normalize(expression: TypedExpr) -> TypedExpr:
        return normalize_expression(expression, variable_labels)

    return replace(
        model,
        steps=tuple(
            replace(
                step,
                guard=normalize(step.guard),
                simultaneous_update=tuple(
                    Assignment(write.name, normalize(write.value))
                    for write in step.simultaneous_update
                ),
                target=replace(step.target, value=normalize(step.target.value))
                if isinstance(step.target.value, TypedExpr)
                else step.target,
                mirrored_pc=normalize(step.mirrored_pc),
            )
            for step in model.steps
        ),
    )
