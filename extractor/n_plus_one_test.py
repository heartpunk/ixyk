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


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
