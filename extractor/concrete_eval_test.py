# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
from dataclasses import replace
from unittest.mock import patch

from extractor import z3_runtime as _z3_runtime  # noqa: F401
from extractor.concrete_eval import share_expressions
from ayxg.eval import equal_valuations, eval_expr, eval_exprs
from ayxg.qfabv import ArraySort, QFAbvArrayValue, QFAbvContext, QFAbvValuation, decode_sort
from ayxg.expr import Declaration, TypedExpr as E, TermSort
from extractor.artifact import InstructionModel, Assignment, StepSummary, Target
from extractor.fuzzer import ComparisonUnavailable, CompiledModel, ConcreteState
from ayxg.z3 import expr_to_z3
from tools.lean_differential import OPS, cases
from hypothesis import given, settings, Phase, strategies as st
import pytest
import z3


def test_operators():
    counts = {}
    for op in OPS:
        counts[op] = 0

        @given(cases(op))
        @settings(max_examples=100, deadline=None, phases=[Phase.generate])
        def check(case):
            counts[op] += 1
            expr, bindings = case
            context = z3.Context()
            empty = QFAbvContext(())
            names = tuple(bindings)
            values = eval_exprs(tuple(
                empty.expression(bindings[name], decode_sort(bindings[name].sort))
                for name in names
            ), QFAbvValuation(empty, ()))
            native_context = QFAbvContext(tuple(
                Declaration(name, bindings[name].sort) for name in names
            ))
            z3_env = {k: expr_to_z3(v, {}, context) for k, v in bindings.items()}
            expected = z3.simplify(expr_to_z3(expr, z3_env, context))
            actual = eval_expr(
                native_context.expression(expr, decode_sort(expr.sort)),
                QFAbvValuation(native_context, values),
            )
            reference = (
                z3.is_true(expected) if expr.sort.kind == "bool" else expected.as_long()
            )
            assert type(actual) is type(reference) and actual == reference, (
                op,
                expr,
                bindings,
                actual,
                reference,
            )

        check()
    print(
        f"{sum(counts.values())} generated operation cases passed: {counts}", flush=True
    )
    return counts


@given(
    st.integers(1, 5),
    st.integers(0, 255),
    st.integers(0, 255),
    st.lists(st.tuples(st.integers(0, 31), st.integers(0, 255)), max_size=50),
    st.lists(st.tuples(st.integers(0, 31), st.integers(0, 255)), max_size=50),
)
@settings(max_examples=100, deadline=None, phases=[Phase.generate])
def test_arrays(width, d1, d2, writes1, writes2):
    sort = ArraySort(width, 8)
    left_entries, right_entries = {}, {}
    mask = (1 << width) - 1
    for k, v in writes1:
        left_entries[k & mask] = v
    for k, v in writes2:
        right_entries[k & mask] = v
    left = QFAbvArrayValue(sort, d1, tuple(sorted(
        (k, v) for k, v in left_entries.items() if v != d1
    )))
    right = QFAbvArrayValue(sort, d2, tuple(sorted(
        (k, v) for k, v in right_entries.items() if v != d2
    )))
    context = QFAbvContext((Declaration("memory", sort.encode()),))
    assert equal_valuations(
        QFAbvValuation(context, (left,)), QFAbvValuation(context, (right,))
    ) == all(
        left_entries.get(k, d1) == right_entries.get(k, d2) for k in range(1 << width)
    )
    other_encoding = QFAbvArrayValue(
        sort, d2, tuple(
            (k, left_entries.get(k, d1)) for k in range(1 << width)
            if left_entries.get(k, d1) != d2
        ),
    )
    assert equal_valuations(
        QFAbvValuation(context, (left,)), QFAbvValuation(context, (other_encoding,))
    )


def model_for(guard=True, target="address"):
    word = TermSort.bv(64)
    memory = TermSort.array(64, 8)
    x = E.var("rax", word)
    pc = E.var("rip", word)
    mem = E.var("mem", memory)
    update = E.binary("bv_add", x, E.bv_lit(64, 1))
    step = StepSummary(
        E.bool_lit(guard),
        (Assignment("rax", update), Assignment("rip", pc), Assignment("mem", mem)),
        Target(target, 0) if target == "address" else Target(target),
        pc,
    )
    return InstructionModel(
        0,
        (
            Declaration("rax", word),
            Declaration("rip", word),
            Declaration("mem", memory),
        ),
        (step,),
    )


@given(
    st.integers(0, 2**64 - 1),
    st.dictionaries(st.integers(0, 2**64 - 1), st.integers(0, 255), max_size=50),
)
@settings(max_examples=100, deadline=None, phases=[Phase.generate])
def test_comparison_changes_inputs(x, memory):
    artifact = model_for()
    assert share_expressions(artifact) == artifact
    with (
        patch.object(z3, "Solver", side_effect=AssertionError("solver construction")),
        patch.object(z3, "simplify", side_effect=AssertionError("Z3 evaluation")),
    ):
        compiled = CompiledModel(artifact)
        for value in (x, x ^ 0xFFFF):
            before = ConcreteState({"rax": value, "rip": 0}, memory)
            after = ConcreteState({"rax": (value + 1) & (2**64 - 1), "rip": 0}, memory)
            assert compiled.differences(before, after) == ()
            wrong = ConcreteState(
                after.scalars | {"rax": after.scalars["rax"] ^ 1}, memory
            )
            assert compiled.differences(before, wrong)[0].startswith("rax:")
            wrong_memory = ConcreteState(
                after.scalars, memory | {0: memory.get(0, 0) ^ 1}
            )
            assert compiled.differences(before, wrong_memory) == ("memory differs",)


def test_outcomes_and_missing_inputs():
    state = ConcreteState({"rax": 1, "rip": 0}, {})
    error = CompiledModel(model_for(target="error"))
    assert error.differences(state, "error") == ()
    assert error.differences(state, state) == (
        "target: model=error, emulator=continued",
    )
    regular = CompiledModel(model_for())
    assert regular.differences(state, "error") == (
        "target: model=address, emulator=error",
    )
    for artifact in (
        model_for(False),
        replace(model_for(), steps=model_for().steps * 2),
    ):
        compiled = CompiledModel(artifact)
        assert compiled.differences(state, state)[0].startswith("enabled edges:")
    with pytest.raises(ComparisonUnavailable):
        regular.differences(ConcreteState({"rip": 0}, {}), state)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
