# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
from functools import cache
from hypothesis import given, settings, strategies as st
import pytest
from extractor import z3_runtime as _runtime  # noqa: F401
from extractor.amd64_state import GPR64, YMM256, FLAG_NAMES
from extractor.extractor import _extract_concrete
from extractor.runtime import load_shellcode
from extractor.fuzzer import _input_state, CompiledModel, emulate


@cache
def model(code):
    return _extract_concrete(load_shellcode(code, 0x400000), 0x400000)


@pytest.mark.parametrize(
    "code", [bytes.fromhex(s) for s in ("4801d8", "48ab", "48a7", "fc", "fd")]
)
@given(st.lists(st.booleans(), min_size=9, max_size=9), st.integers(0, 2**64 - 1))
@settings(max_examples=20, deadline=None)
def test_full_flags_match_reference(code, flags, value):
    registers = tuple(
        value if name == "rax" else 0x100000 if name in GPR64 else 0
        for name in GPR64 + YMM256
    )
    before = _input_state(code, 0x400000, {}, bytes(range(32)), registers, flags, True)
    artifact = model(code)
    assert {"rflags_DF", "rflags_AC", "rflags_ID"} <= {
        d.name for d in artifact.declarations
    }
    assert CompiledModel(artifact).differences(before, emulate(code, before)) == ()
    assert set(before.scalars) >= {"rflags_" + name for name in FLAG_NAMES}


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__]))
