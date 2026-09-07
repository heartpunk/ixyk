# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise real XED variability and initial data memory."""

from extractor import z3_runtime as _z3_runtime  # noqa: F401

from unittest.mock import patch
from hypothesis import find, settings, strategies as st
from extractor.fuzz_inputs import instruction_strategy
from extractor.xed import decode
from extractor.extractor import extract
from extractor.runtime import load_shellcode
from extractor.fuzzer import fuzz


def main():
    strategy = instruction_strategy(bytes.fromhex("4801d8"))
    search = settings(max_examples=200, deadline=None, database=None)
    memory = find(
        strategy,
        lambda code: decode(code)["base"]["name"] != "INVALID",
        settings=search,
    )
    assert decode(memory)["iclass"] == "ADD"
    narrow = find(
        strategy,
        lambda code: any(op["width"] == 8 for op in decode(code)["operands"]),
        settings=search,
    )
    assert narrow != bytes.fromhex("4801d8")
    seed = bytes.fromhex("90")
    model = extract(load_shellcode(seed, 0x400000), 0x400000)
    observed = []

    def emulate(code, before):
        observed.append((code, before))
        return before

    def compare(_self, before, after):
        assert before == after == observed[-1][1]
        return ()

    with (
        patch("extractor.fuzz_inputs.instruction_strategy", return_value=st.just(seed)),
        patch("extractor.fuzzer.emulate", emulate),
        patch("extractor.fuzzer.CompiledModel.differences", compare),
    ):
        report = fuzz(model, seed, 10, vary_inputs=True)
    assert report["status"] == "pass", report
    assert {state.scalars["rip"] for _, state in observed} == {model.source}
    assert any(
        any(
            value
            for address, value in state.memory.items()
            if not state.scalars["rip"] <= address < state.scalars["rip"] + len(code)
        )
        for code, state in observed
    )


if __name__ == "__main__":
    main()
