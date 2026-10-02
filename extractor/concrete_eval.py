# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""AMD64 memory input and immutable model expression sharing."""

from dataclasses import replace
from ayxg.qfabv import ArraySort, QFAbvArrayValue


def memory_value(values):
    """Encode concrete AMD64 byte memory in the shared finite-support value."""
    for address, value in values.items():
        if not 0 <= address < 1 << 64 or not 0 <= value < 256:
            raise ValueError("concrete memory is not a BV64-to-BV8 map")
    return QFAbvArrayValue(
        ArraySort(64, 8), 0,
        tuple(sorted((address, value) for address, value in values.items() if value)),
    )


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
