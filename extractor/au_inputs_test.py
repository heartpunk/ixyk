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


@pytest.mark.parametrize(
    "hexcode,expected,width",
    [
        ("4883c0ff", 255, 8),
        ("4883c001", 1, 8),
        ("48b88877665544332211", 0x1122334455667788, 64),
    ],
)
def test_immediate_correspondence(hexcode, expected, width):
    decoded = decode(bytes.fromhex(hexcode))
    bindings = canonical_bindings(
        decoded, (Declaration("rax", TermSort.bv(64)),), 0x400000
    )
    assert bindings["IMM0"] == BitVectorAtom(expected, TermSort.bv(width))
    test_independent_inputs(hexcode)


def test_address_component_correspondence():
    decoded = decode(bytes.fromhex("488d444bf8"))
    declarations = tuple(
        Declaration(name, TermSort.bv(64)) for name in ("rax", "rbx", "rcx")
    )
    bindings = canonical_bindings(decoded, declarations, 0x400000)
    assert bindings["SCALE"] == BitVectorAtom(2, TermSort.bv(64))
    assert bindings["DISP"] == BitVectorAtom((1 << 64) - 8, TermSort.bv(64))


@pytest.mark.parametrize(
    "declarations",
    [
        (),
        (Declaration("eax", TermSort.bv(32)),),
        (Declaration("rax", TermSort.bv(64)), Declaration("RAX", TermSort.bv(64))),
    ],
)
def test_register_correspondence_requires_unique_wide_enough_declaration(declarations):
    from extractor.operand_slots import OperandDecodeError

    with pytest.raises(OperandDecodeError, match="no unique canonical register"):
        canonical_bindings(decode(bytes.fromhex("4883c001")), declarations, 0x400000)


@pytest.mark.parametrize(
    "hexcode,expected",
    [
        ("488b03", {"REG0": "RAX", "BASE0": "RBX"}),
        ("488b0500000000", {"REG0": "RAX", "DISP": 0}),
        ("488b044d00000000", {"REG0": "RAX", "INDEX": "RCX", "SCALE": 2, "DISP": 0}),
        ("c8000000", {"IMM0": 0}),
    ],
)
def test_parameter_shapes(hexcode, expected):
    assert parameters(decode(bytes.fromhex(hexcode))) == expected


def test_input_generation_rejects_exhausted_encoder_candidates(monkeypatch):
    from extractor import au_inputs
    from extractor.xed import EncodingError

    attempts = []

    def reject(code, row):
        attempts.append(row)
        raise EncodingError("deliberately unavailable")

    monkeypatch.setattr(au_inputs, "encode", reject)
    with pytest.raises(EncodingError, match="cannot obtain separating value"):
        instruction_inputs(bytes.fromhex("4801d8"))
    assert attempts


def test_input_generation_rejects_encoder_returning_requested_bytes(monkeypatch):
    from extractor import au_inputs
    from extractor.xed import EncodingError

    monkeypatch.setattr(au_inputs, "encode", lambda code, row: code)
    with pytest.raises(EncodingError, match="not distinct"):
        instruction_inputs(bytes.fromhex("4801d8"))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
