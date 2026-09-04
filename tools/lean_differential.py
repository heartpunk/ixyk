"""Differentially check the real Python/Z3 and Lean QF_ABV interpreters."""

from __future__ import annotations

import argparse
import atexit
from builtins import ExceptionGroup
from functools import cache
import json
from pathlib import Path
import select
import subprocess
import tempfile
import traceback

from hypothesis import given, settings, strategies as st
import z3

from extractor.artifact import BOOL, TermSort, TypedExpr as E
from extractor.typed_z3 import expr_to_z3


BINARY = (
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
)
COMPARE = ("bv_ult", "bv_ule", "bv_slt", "bv_sle", "eq")
OPS = (
    BINARY
    + COMPARE
    + (
        "var",
        "bool_lit",
        "bv_lit",
        "bv_not",
        "bool_not",
        "bool_and",
        "bool_or",
        "ite",
        "zero_extend",
        "sign_extend",
        "extract",
        "concat",
        "const_array",
        "store",
        "select",
    )
)
Z3_CONTEXT = z3.Context()


class LeanProcess:
    def __init__(self, executable):
        self.executable = executable
        self.process = None
        self.errors = tempfile.TemporaryFile(mode="w+")
        atexit.register(self.close)

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
            self.process.stdin.close()
            self.process.stdout.close()
            self.process = None

    def evaluate(self, payload):
        if self.process is None or self.process.poll() is not None:
            self.close()
            self.errors.seek(0)
            self.errors.truncate()
            self.process = subprocess.Popen(
                [str(self.executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self.errors,
                text=True,
            )
        self.process.stdin.write(payload + "\n")
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 10)[0]:
            self.close()
            raise subprocess.TimeoutExpired(str(self.executable), 10)
        line = self.process.stdout.readline()
        if not line:
            self.process.wait(timeout=2)
            self.errors.seek(0)
            error = self.errors.read()
            self.close()
            raise AssertionError((payload, error))
        response = json.loads(line)
        assert "value" in response, (payload, response)
        return response["value"]


def word(width):
    mask = (1 << width) - 1
    return st.one_of(
        st.sampled_from(
            [
                0,
                1,
                mask,
                mask >> 1,
                1 << (width - 1),
                (width - 1) & mask,
                width & mask,
                (width + 1) & mask,
            ]
        ),
        st.integers(0, mask),
    )


def extend_terms(children):
    return st.builds(E.binary, st.sampled_from(BINARY), children, children)


@cache
def terms_for(width):
    sort = TermSort.bv(width)
    leaf = st.one_of(
        st.sampled_from([E.var("x", sort), E.var("y", sort)]),
        word(width).map(lambda n: E.bv_lit(width, n)),
    )
    return st.recursive(leaf, extend_terms, max_leaves=6)


@st.composite
def cases(draw, op):
    width = draw(st.sampled_from([1, 2, 8, 16, 32, 64, 128]))
    sort = TermSort.bv(width)
    x, y = E.var("x", sort), E.var("y", sort)
    bindings = {
        "x": E.bv_lit(width, draw(word(width))),
        "y": E.bv_lit(width, draw(word(width))),
        "flag": E.bool_lit(draw(st.booleans())),
    }
    terms = terms_for(width)
    left, right = draw(terms), draw(terms)
    boolean = E.binary(draw(st.sampled_from(COMPARE)), left, right)
    flag = E.var("flag", BOOL)
    if op in BINARY + COMPARE:
        expr = E.binary(op, left, right)
    elif op == "var":
        expr = draw(st.sampled_from([x, y, flag]))
    elif op == "bool_lit":
        expr = E.bool_lit(draw(st.booleans()))
    elif op == "bv_lit":
        expr = E.bv_lit(width, draw(word(width)))
    elif op in ("bv_not", "bool_not"):
        expr = E.unary(op, left if op == "bv_not" else boolean)
    elif op in ("bool_and", "bool_or"):
        expr = E.binary(op, boolean, flag)
    elif op == "ite":
        expr = E.ite(boolean, left, right)
    elif op in ("zero_extend", "sign_extend"):
        amount = draw(st.integers(1, 64))
        expr = E(op, TermSort.bv(width + amount), (left,), amount=amount)
    elif op == "extract":
        lo = draw(st.integers(0, width - 1))
        hi = draw(st.integers(lo, width - 1))
        expr = E(op, TermSort.bv(hi - lo + 1), (left,), hi=hi, lo=lo)
    elif op == "concat":
        low_width = draw(st.sampled_from([1, 8, 64]))
        low = E.bv_lit(low_width, draw(word(low_width)))
        expr = E(op, TermSort.bv(width + low_width), (left, low))
    else:
        index_width = draw(st.sampled_from([1, 2, 8]))
        array_sort = TermSort.array(index_width, width)
        array = E("const_array", array_sort, (bindings["x"],))
        index = E.bv_lit(index_width, draw(word(index_width)))
        other = draw(
            st.one_of(
                st.just(index),
                word(index_width).map(lambda n: E.bv_lit(index_width, n)),
            )
        )
        bindings["memory"] = array
        if op != "const_array":
            array = E("store", array_sort, (E.var("memory", array_sort), index, left))
            # A second store exercises aliasing and last-write-wins.
            array = E("store", array_sort, (array, other, right))
        expr = E("select", sort, (array, index))
    return expr, bindings


def compare(executable, expr, bindings):
    context = Z3_CONTEXT
    environment = {
        name: expr_to_z3(value, {}, context) for name, value in bindings.items()
    }
    result = z3.simplify(expr_to_z3(expr, environment, context))
    expected = z3.is_true(result) if expr.sort == BOOL else result.as_long()
    request = {
        "expr": expr.to_data(),
        "bindings": [
            {"name": name, "value": value.to_data()} for name, value in bindings.items()
        ],
    }
    payload = json.dumps(request, separators=(",", ":"))
    actual = executable.evaluate(payload)
    assert type(actual) is type(expected) and actual == expected, (
        f"Python/Z3={expected!r}; Lean={actual!r}; replay JSON={payload}"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--executable",
        type=Path,
        default=Path(".lake/build/bin/ixyk-differential-eval"),
    )
    parser.add_argument("--examples", type=int, default=50)
    parser.add_argument(
        "--survey",
        action="store_true",
        help="Finish every family despite mismatches, then fail",
    )
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if args.examples < 1:
        parser.error("--examples must be positive")
    executable = LeanProcess(args.executable.resolve(strict=True))
    failures = {}

    def run_case(family, expr, bindings):
        try:
            compare(executable, expr, bindings)
        except (AssertionError, subprocess.TimeoutExpired) as error:
            if not args.survey:
                raise
            entry = failures.setdefault(
                family, {"count": 0, "first": str(error), "replays": []}
            )
            entry["count"] += 1
            entry["replays"].append(
                {
                    "error": str(error),
                    "expr": expr.to_data(),
                    "bindings": [
                        {"name": name, "value": value.to_data()}
                        for name, value in bindings.items()
                    ],
                }
            )

    # Deterministic divide-by-zero, signed extrema, and oversized-shift cases.
    boundary_count = 0
    for width in (1, 8, 64, 128):
        mask = (1 << width) - 1
        for op in BINARY + COMPARE:
            for left in (0, 1, mask, 1 << (width - 1)):
                for right in (0, 1, width - 1, width, width + 1, mask):
                    expr = E.binary(
                        op, E.bv_lit(width, left), E.bv_lit(width, right & mask)
                    )
                    run_case(op, expr, {})
                    boundary_count += 1
    print(f"Boundary comparisons completed: {boundary_count}", flush=True)
    for op in OPS:

        @settings(
            max_examples=args.examples, deadline=None, derandomize=True, database=None
        )
        @given(cases(op))
        def check(case):
            run_case(op, *case)

        check()
        if op in failures:

            @settings(
                max_examples=args.examples,
                deadline=None,
                derandomize=True,
                database=None,
            )
            @given(cases(op))
            def shrink(case):
                compare(executable, *case)

            try:
                shrink()
            except (AssertionError, subprocess.TimeoutExpired, ExceptionGroup) as error:
                failures[op]["shrunk"] = "".join(traceback.format_exception(error))
        print(f"{'FAIL' if op in failures else 'PASS'} {op}", flush=True)
    report = {
        "boundary_cases": boundary_count,
        "examples_per_family": args.examples,
        "families": list(OPS),
        "failures": failures,
    }
    if args.report:
        args.report.write_text(json.dumps(report, indent=2) + "\n")
    if failures:
        print(json.dumps(report, indent=2))
        raise SystemExit(1)
    print(f"Differential semantics passed for all {len(OPS)} operator families.")


if __name__ == "__main__":
    main()
