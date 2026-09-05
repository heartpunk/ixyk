# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

import pytest
from extractor.xed import EncodingError, decode, encode, registers, relative_target


def test_fixed_operand_metadata():
    operands = decode(bytes.fromhex("48d3e0"))["operands"]
    assert operands[0]["visibility"] == "EXPLICIT"
    assert operands[1]["visibility"] == "IMPLICIT"
    assert operands[1]["register"]["name"] == "CL"


@pytest.mark.parametrize("hexcode", ["4801d8", "0fb6c3", "660fefc1", "488d444b08"])
def test_decode_preserves_bytes(hexcode):
    assert decode(bytes.fromhex(hexcode))["hex"] == hexcode


def test_register_views():
    by_name = {r["name"]: r for r in registers()}
    assert by_name["AL"]["parent"] == "RAX"
    assert by_name["EAX"]["width"] == 32
    assert by_name["XMM0"]["width"] == 128


def test_register_change():
    result = encode(bytes.fromhex("4801d8"), {"REG0": "RCX"})
    assert decode(result)["operands"][0]["register"]["name"] == "RCX"


@pytest.mark.parametrize(
    "hexcode", ["f20f10c1", "f30f10c1", "f30f11c8", "0f10c1", "0f11c8"]
)
def test_preserve_encoding_direction(hexcode):
    original = decode(bytes.fromhex(hexcode))
    for dst in range(16):
        for src in range(16):
            seed = bytes.fromhex(hexcode)
            if dst >= 8 or src >= 8:
                # The seed needs the same length as its requested variants.
                prefix_end = 1 if seed[0] in (0xF2, 0xF3) else 0
                seed = seed[:prefix_end] + b"\x44" + seed[prefix_end:]
            result = decode(encode(seed, {"REG0": f"XMM{dst}", "REG1": f"XMM{src}"}))
            assert result["form"] == original["form"]
            assert [op["register"]["name"] for op in result["operands"]] == [
                f"XMM{dst}",
                f"XMM{src}",
            ]


def test_unrequested_operand_is_preserved():
    result = decode(encode(bytes.fromhex("f30f10c1"), {"REG0": "XMM2"}))
    assert result["operands"][1]["register"]["name"] == "XMM1"


def test_reject_unrequested_operand_change(monkeypatch):
    from extractor import xed

    before = decode(bytes.fromhex("4801d8"))
    wrong = decode(bytes.fromhex("4801d1"))  # RCX destination, RDX source
    monkeypatch.setattr(
        xed, "_invoke", lambda *args: before if len(args) == 1 else wrong
    )
    with pytest.raises(EncodingError, match="operands do not match"):
        encode(bytes.fromhex("4801d8"), {"REG0": "RCX"})


def test_fixed_register_cannot_be_silently_changed():
    with pytest.raises(EncodingError):
        encode(bytes.fromhex("48d3e0"), {"REG1": "DL"})


def test_memory_fields():
    result = encode(
        bytes.fromhex("488d444b08"), {"BASE0": "RDX", "SCALE": 4, "DISP": 16}
    )
    decoded = decode(result)
    assert (decoded["base"]["name"], decoded["scale"], decoded["displacement"]) == (
        "RDX",
        4,
        16,
    )


@pytest.mark.parametrize("source", [0x1000, 0x400000])
def test_relative_branch_at_actual_source(source):
    result = encode(bytes.fromhex("eb00"), {"RELBR": -8})
    assert relative_target(decode(result), source) == source + 2 - 8


def test_immediate():
    result = encode(bytes.fromhex("4883c008"), {"IMM0": 17})
    assert decode(result)["immediate"] == 17


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
