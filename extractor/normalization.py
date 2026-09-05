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
