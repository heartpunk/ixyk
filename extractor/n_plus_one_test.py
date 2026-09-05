# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise the public extraction pipeline, not a separate AU implementation."""

from extractor.runtime import load_shellcode
import pytest
import extractor.extractor as implementation
from extractor.fuzz_runner import run_bounded
from extractor.normalization import normalize_model
from extractor.operand_slots import canonical_bindings, normalization_labels
from extractor.xed import decode


CASES = (
    ("add", "4d01c8"),
    ("adc", "4d11c8"),
    ("sub", "4d29c8"),
    ("xor", "4d31c8"),
    ("cmp", "4d39c8"),
    ("mov", "4d89c8"),
    ("imul", "4d0fafc1"),
    ("xchg", "4d87c8"),
    ("xadd", "4d0fc1c8"),
    ("inc", "49ffc0"),
    ("lea", "4f8d444c08"),
)
SOURCE = 0x400000


@pytest.mark.parametrize("name,hexcode", CASES, ids=[c[0] for c in CASES])
def test_public_extraction(name, hexcode, monkeypatch):
    code = bytes.fromhex(hexcode)
    concrete = implementation._extract_concrete
    raw = concrete(load_shellcode(code, SOURCE), SOURCE)
    labels = normalization_labels(
        canonical_bindings(decode(code), raw.declarations, SOURCE)
    )
    expected = normalize_model(raw, labels)
    inputs = []

    def checked(project, source):
        observed = bytes(project.factory.block(source, num_inst=1).bytes)
        assert observed != code, "requested instance was used as an AU input"
        inputs.append(observed)
        return concrete(project, source)

    monkeypatch.setattr(implementation, "_extract_concrete", checked)
    actual = implementation.extract(load_shellcode(code, SOURCE), SOURCE)
    assert inputs
    assert actual == expected, ("normalized held-out mismatch", name)
    report = run_bounded(actual.to_json(), code, 60, examples=10, stage="discover")
    assert report["status"] == "pass", report


@pytest.mark.parametrize(
    "failure,message",
    [
        ("declarations", "input declarations disagree"),
        ("bindings", "input operand bindings disagree"),
        ("constant", "parameter did not vary"),
        ("unexplained", "not explained by operands"),
        ("type", "did not reconstruct an instruction model"),
    ],
)
def test_extraction_rejects_inconsistent_au_inputs(monkeypatch, failure, message):
    from dataclasses import replace
    from types import SimpleNamespace
    import antiunification.many as au
    import extractor.au_inputs as inputs
    import extractor.operand_slots as slots
    from extractor.artifact import TermSort
    from extractor.model_syntax import CanonicalVariable

    code = bytes.fromhex("4801d8")
    project = load_shellcode(code, SOURCE)
    raw = implementation._extract_concrete(project, SOURCE)
    alternate = replace(
        raw,
        declarations=raw.declarations[::-1],
        steps=tuple(
            replace(step, simultaneous_update=step.simultaneous_update[::-1])
            for step in raw.steps
        ),
    )
    models = iter((raw, alternate if failure == "declarations" else raw))
    monkeypatch.setattr(inputs, "instruction_inputs", lambda code: (code, code))
    monkeypatch.setattr(implementation, "_extract_concrete", lambda *args: next(models))
    x = CanonicalVariable("rax", TermSort.bv(64))
    y = CanonicalVariable("rbx", TermSort.bv(64))
    rows = iter(
        (
            {"operand": x},
            {
                "different" if failure == "bindings" else "operand": x
                if failure == "constant"
                else y
            },
            {"operand": x},
        )
    )
    monkeypatch.setattr(slots, "canonical_bindings", lambda *args: next(rows))
    # Inject a faulty AU result only for the two result-boundary checks.
    if failure in {"unexplained", "type"}:
        substitutions = ({"V0": x},) if failure == "unexplained" else ({"operand": x},)
        monkeypatch.setattr(
            au,
            "antiunify_many",
            lambda *args, **kwargs: SimpleNamespace(
                substitutions=substitutions, instantiate=lambda substitution: x
            ),
        )
    with pytest.raises(slots.OperandDecodeError, match=message):
        implementation.extract(project, SOURCE)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
