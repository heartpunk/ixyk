# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Experimental, semantics-preserving normalization of typed QF_ABV syntax."""

from dataclasses import replace
from typing import cast

from extractor.artifact import Assignment, InstructionModel, TypedExpr


def normalize_expression(expression: TypedExpr) -> TypedExpr:
    memo: dict[int, TypedExpr] = {}

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


def normalize_model(model: InstructionModel) -> InstructionModel:
    return replace(
        model,
        steps=tuple(
            replace(
                step,
                guard=normalize_expression(step.guard),
                simultaneous_update=tuple(
                    Assignment(write.name, normalize_expression(write.value))
                    for write in step.simultaneous_update
                ),
                target=replace(
                    step.target, value=normalize_expression(step.target.value)
                )
                if isinstance(step.target.value, TypedExpr)
                else step.target,
                mirrored_pc=normalize_expression(step.mirrored_pc),
            )
            for step in model.steps
        ),
    )
