# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""Concrete evaluation of the admitted typed QF_ABV operations."""

from dataclasses import dataclass, replace
from extractor.artifact import TypedExpr, TermSort


@dataclass(eq=False)
class ConcreteArray:
    width: int
    default: int
    values: dict

    def select(self, index):
        return self.values.get(index, self.default)

    def store(self, index, value):
        values = self.values.copy()
        if value == self.default:
            values.pop(index, None)
        else:
            values[index] = value
        return ConcreteArray(self.width, self.default, values)

    def __eq__(self, other):
        if not isinstance(other, ConcreteArray) or self.width != other.width:
            return False
        if self.default == other.default:
            return self.values == other.values
        keys = self.values.keys() | other.values.keys()
        if self.default != other.default and len(keys) < 1 << self.width:
            return False
        return all(self.select(k) == other.select(k) for k in keys)

    @classmethod
    def memory(cls, values):
        result = {}
        for address, value in values.items():
            if not 0 <= address < 1 << 64 or not 0 <= value < 256:
                raise ValueError("concrete memory is not a BV64-to-BV8 map")
            if value:
                result[address] = value
        return cls(64, 0, result)

    def to_expression(self, value_width):
        sort = TermSort.array(self.width, value_width)
        result = TypedExpr(
            "const_array", sort, (TypedExpr.bv_lit(value_width, self.default),)
        )
        for address, value in sorted(self.values.items()):
            result = TypedExpr(
                "store",
                sort,
                (
                    result,
                    TypedExpr.bv_lit(self.width, address),
                    TypedExpr.bv_lit(value_width, value),
                ),
            )
        return result


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def evaluator(environment):
    memo = {}

    def visit(node):
        key = id(node)
        if key not in memo:
            memo[key] = (node, compute(node))
        return memo[key][1]

    def compute(node):
        op = node.op
        if op == "var":
            return environment[node.name]
        if op in ("bool_lit", "bv_lit"):
            return node.value
        if op == "ite":
            return visit(node.args[1] if visit(node.args[0]) else node.args[2])
        a = tuple(visit(child) for child in node.args)
        if op == "bool_not":
            return not a[0]
        if op == "bool_and":
            return a[0] and a[1]
        if op == "bool_or":
            return a[0] or a[1]
        if op == "eq":
            return a[0] == a[1]
        if op == "const_array":
            return ConcreteArray(node.sort.index_width, a[0], {})
        if op == "store":
            return a[0].store(a[1], a[2])
        if op == "select":
            return a[0].select(a[1])
        width = node.args[0].sort.width
        if op == "bv_ult":
            return a[0] < a[1]
        if op == "bv_ule":
            return a[0] <= a[1]
        if op == "bv_slt":
            return signed(a[0], width) < signed(a[1], width)
        if op == "bv_sle":
            return signed(a[0], width) <= signed(a[1], width)
        mask = (1 << node.sort.width) - 1
        if op == "bv_not":
            result = ~a[0]
        elif op == "bv_add":
            result = a[0] + a[1]
        elif op == "bv_sub":
            result = a[0] - a[1]
        elif op == "bv_mul":
            result = a[0] * a[1]
        elif op == "bv_udiv":
            result = a[0] // a[1] if a[1] else mask
        elif op == "bv_urem":
            result = a[0] % a[1] if a[1] else a[0]
        elif op == "bv_and":
            result = a[0] & a[1]
        elif op == "bv_or":
            result = a[0] | a[1]
        elif op == "bv_xor":
            result = a[0] ^ a[1]
        elif op == "bv_shl":
            result = a[0] << a[1] if a[1] < width else 0
        elif op == "bv_lshr":
            result = a[0] >> a[1] if a[1] < width else 0
        elif op == "bv_ashr":
            result = signed(a[0], width) >> min(a[1], width)
        elif op == "zero_extend":
            result = a[0]
        elif op == "sign_extend":
            result = signed(a[0], width)
        elif op == "extract":
            result = a[0] >> node.lo
        elif op == "concat":
            result = (a[0] << node.args[1].sort.width) | a[1]
        else:
            raise ValueError(f"unsupported typed operation: {op}")
        return result & mask

    return visit


def share_expressions(model):
    """Share structurally identical immutable nodes once, outside the sample loop."""
    pool = {}

    def intern(node):
        children = tuple(intern(a) for a in node.args)
        key = (
            node.op,
            node.sort,
            tuple(id(a) for a in children),
            node.name,
            node.value,
            node.amount,
            node.hi,
            node.lo,
        )
        if key not in pool:
            pool[key] = replace(node, args=children)
        return pool[key]

    return replace(
        model,
        steps=tuple(
            replace(
                s,
                guard=intern(s.guard),
                mirrored_pc=intern(s.mirrored_pc),
                simultaneous_update=tuple(
                    replace(a, value=intern(a.value)) for a in s.simultaneous_update
                ),
            )
            for s in model.steps
        ),
    )
