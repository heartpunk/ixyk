# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
import json
from pathlib import Path
from antiunification.many import separating_inputs, antiunify_many
from extractor.au_inputs import instruction_inputs, parameters
from extractor.model_syntax import BitVectorAtom, QFAbvSyntax
from extractor.artifact import TermSort
from extractor.xed import decode
from extractor.operand_slots import canonical_bindings
from extractor.artifact import Declaration


@pytest.mark.parametrize(
    "hexcode",
    [
        "4801d8",
        "48d3e0",
        "0fb6c3",
        "660fefc1",
        "488d444b08",
        "eb00",
        "e800000000",
        "0f95c0",
        "480fc1d8",
        "c5f358c2",
        "90",
        "c3",
        "4893",
    ],
)
def test_independent_inputs(hexcode):
    code = bytes.fromhex(hexcode)
    requested = parameters(decode(code))
    codes = instruction_inputs(code)
    assert all(decode(item)["form"] == decode(code)["form"] for item in codes)
    assert len(codes) == len(requested) + 1
    if not requested:
        assert codes == (code,)
        return
    assert code not in codes
    baseline = parameters(decode(codes[0]))
    for field, variant in zip(baseline, codes[1:], strict=True):
        row = parameters(decode(variant))
        assert {key for key in baseline if row[key] != baseline[key]} == {field}


def test_singleton_au():
    assert separating_inputs({}, {}) == ({},)
    value = BitVectorAtom(7, TermSort.bv(8))
    result = antiunify_many(QFAbvSyntax(), (value,), correspondences={})
    assert result.substitutions == ({},)
    assert result.instantiate({}) == value


def test_canonical_register_views():
    from extractor.model_syntax import CanonicalVariable

    declarations = (
        Declaration("rax", TermSort.bv(64)),
        Declaration("rbx", TermSort.bv(64)),
    )
    bindings = canonical_bindings(
        decode(bytes.fromhex("0fb6c3")), declarations, 0x400000
    )
    assert bindings["REG0"] == CanonicalVariable("rax", TermSort.bv(64))
    assert bindings["REG1"] == CanonicalVariable("rbx", TermSort.bv(64))


def test_branch_correspondence():
    from extractor.model_syntax import AddressAtom

    bindings = canonical_bindings(decode(bytes.fromhex("eb00")), (), 0x400000)
    assert bindings["RELBR_address"] == AddressAtom(0x400002)
    assert bindings["RELBR_bv"] == BitVectorAtom(0x400002, TermSort.bv(64))


CATALOG = json.loads(
    (Path(__file__).resolve().parents[1] / "catalog/x86_64_probes.json").read_text()
)["probes"]


@pytest.mark.parametrize("probe", CATALOG, ids=[p["name"] for p in CATALOG])
def test_catalog_input_generation(probe):
    test_independent_inputs(probe["bytes"])


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
