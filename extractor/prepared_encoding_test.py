# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
from functools import cache

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from extractor import constructor_inputs
from extractor import z3_runtime as _runtime  # noqa: F401
from extractor.amd64_state import FLAG_NAMES, GPR64, YMM256
from extractor.constructor_inputs import (
    ArgumentCase,
    Domain,
    argument_domain,
    register_domains,
    supported_register_values,
)
from extractor.extractor import _extract_concrete
from extractor.fuzzer import CompiledModel, InputLayout, _input_state, emulate
from extractor.prepared_cases import PreparedCase, _constructor_roles, generalize
from extractor.runtime import load_shellcode
from extractor.xed import EncodingError, _invoke, decode, encode_constructor, registers


@cache
def lea_form(width):
    return next(
        f
        for f in _invoke("forms", "LEA")
        if [a["kind"] for a in f["args"]] == ["gpr64", "gpr64", f"int{width}"]
    )


@given(
    st.integers(-(1 << 31), (1 << 31) - 1),
    st.sampled_from(["RAX", "R9", "R15"]),
    st.sampled_from(["RBX", "RSP", "RIP"]),
)
@settings(max_examples=100, deadline=None)
def test_native_constructor_round_trip(displacement, destination, base):
    bank = {r["name"]: r["value"] for r in registers()}
    actual = encode_constructor(
        lea_form(32)["id"], [bank[destination], bank[base], displacement]
    )
    assert decode(bytes.fromhex(actual["hex"])) == actual
    assert actual["base"]["name"] == base
    assert actual["operands"][0]["register"]["name"] == destination
    assert actual["displacement"] == displacement


@given(st.integers(-128, 127))
@settings(max_examples=20, deadline=None)
def test_native_rejection_preserves_next_request(displacement):
    bank = {r["name"]: r["value"] for r in registers()}
    args = [bank["RAX"], bank["RIP"], displacement]
    with pytest.raises(EncodingError, match="RIP relative"):
        encode_constructor(lea_form(8)["id"], args)
    assert encode_constructor(lea_form(32)["id"], args)["displacement"] == displacement


def test_rejected_constructor_is_preflighted_once(monkeypatch):
    form = next(f for f in _invoke("forms", "ADD") if f["id"] == 946)
    bank = {r["name"]: r["value"] for r in registers()}
    choices = tuple(bank[name] for name in ("RAX", "RCX", "RDX", "RBX"))
    domains = tuple(
        (
            Domain(choices, register=True)
            if arg["ctype"] == "xed_reg_enum_t"
            else argument_domain(arg)
        )
        for arg in form["args"]
    )
    attempts = []

    def reject(_form, values):
        attempts.append(values)
        raise EncodingError("unsupported constructor")

    monkeypatch.setattr("extractor.prepared_cases.encode_constructor", reject)
    with pytest.raises(EncodingError, match="unsupported constructor"):
        _constructor_roles(form, domains)
    assert len(attempts) == 1
    assert attempts[0] == tuple(domain.seed() for domain in domains)


def test_structural_representatives_preserve_alias_partition_directly():
    bank = {r["name"]: r["value"] for r in registers()}
    choices = tuple(bank[name] for name in ("RAX", "RCX", "RDX", "RBX"))
    domains = (Domain(choices, register=True), Domain(choices, register=True))
    form = {"id": 0, "args": ()}

    assert ArgumentCase(form, domains, ((0, 1),)).canonical() == (
        bank["RAX"],
        bank["RAX"],
    )
    assert ArgumentCase(form, domains, ((0,), (1,))).canonical() == (
        bank["RAX"],
        bank["RCX"],
    )


def test_supported_register_domains_are_linear_cached_and_direct(monkeypatch):
    catalog = (
        {"value": 1, "name": "RAX", "class": "GPR", "width": 64, "parent": "RAX"},
        {"value": 2, "name": "EAX", "class": "GPR", "width": 32, "parent": "RAX"},
        {"value": 3, "name": "RSP", "class": "GPR", "width": 64, "parent": "RSP"},
        {"value": 4, "name": "R16", "class": "GPR", "width": 64, "parent": "R16"},
        {"value": 5, "name": "RIP", "class": "IP", "width": 64, "parent": "RIP"},
        {
            "value": 6,
            "name": "INVALID",
            "class": "INVALID",
            "width": 0,
            "parent": "INVALID",
        },
    )
    visits = 0

    class CountingCatalog:
        def __iter__(self):
            nonlocal visits
            for register in catalog:
                visits += 1
                yield register

    monkeypatch.setattr(constructor_inputs, "registers", lambda: CountingCatalog())
    register_domains.cache_clear()
    supported_register_values.cache_clear()
    try:
        supported = supported_register_values(
            frozenset({"rax", "rsp"}), frozenset({"RAX", "RSP"})
        )
        table = register_domains(supported)
        assert visits == 3 * len(catalog)

        before_lookup = visits
        operand = argument_domain(
            {"name": "reg0", "kind": "gpr64", "ctype": "xed_reg_enum_t"},
            table,
        )
        index = argument_domain(
            {"name": "index", "kind": "gpr64_index", "ctype": "xed_reg_enum_t"},
            table,
        )
        base = argument_domain(
            {"name": "base", "kind": "gpr64", "ctype": "xed_reg_enum_t"},
            table,
        )
        assert visits == before_lookup
        assert operand.choices == (1, 3)
        assert index.choices == (1,)
        assert base.choices == (1, 3, 5, 6)

        assert register_domains(supported) is table
        assert visits == before_lookup
        assert (
            supported_register_values(
                frozenset({"rax", "rsp"}), frozenset({"RAX", "RSP"})
            )
            is supported
        )
        assert visits == before_lookup
    finally:
        register_domains.cache_clear()
        supported_register_values.cache_clear()


def test_rejected_form_does_not_prevent_later_preflight(monkeypatch):
    from types import SimpleNamespace

    from extractor import angr_boundary, prepared_cases

    forms = (
        {"id": 1, "args": []},
        {"id": 2, "args": []},
    )
    attempts = []
    loads = []
    lifts = []

    def encode(form, _values):
        attempts.append(form)
        if form == 1:
            raise EncodingError("unsupported constructor")
        return {"hex": "90", "operands": []}

    project = SimpleNamespace(arch=SimpleNamespace(registers={}))
    block = SimpleNamespace(
        vex=SimpleNamespace(instructions=1, jumpkind="Ijk_Boring"), bytes=b"\x90"
    )
    monkeypatch.setattr(prepared_cases, "_invoke", lambda *_args: forms)
    monkeypatch.setattr(prepared_cases, "decode", lambda _code: {"iclass": "TEST"})
    monkeypatch.setattr(prepared_cases, "registers", lambda: ())
    monkeypatch.setattr(prepared_cases, "encode_constructor", encode)
    monkeypatch.setattr(prepared_cases, "structural_cases", lambda *_args: ())
    monkeypatch.setattr(
        prepared_cases,
        "load_shellcode",
        lambda *_args: loads.append(_args) or object(),
    )
    monkeypatch.setattr(angr_boundary, "expect_project", lambda _project: project)
    monkeypatch.setattr(
        angr_boundary,
        "lift_block",
        lambda *_args, **kwargs: lifts.append(kwargs["byte_string"]) or block,
    )
    findings = []

    assert (
        prepared_cases.prepare_catalog(
            b"\x90",
            0x400000,
            on_model=lambda *_args: None,
            on_finding=lambda *finding: findings.append(finding),
        )
        == []
    )
    assert attempts == [1, 2]
    assert len(loads) == 1
    assert lifts == [b"\x90"]
    assert [finding[0] for finding in findings] == ["generation:constructor:1"]
    context = findings[0][3]
    assert context.operation == "constructor-preflight"
    assert context.constructor_id == 1
    assert context.arguments == ()
    assert context.source == 0x400000
    assert context.encoding is None


@cache
def parameterized_add(alias):
    form = next(
        f
        for f in _invoke("forms", "ADD")
        if "_APX" not in f["form"]
        and all(a["name"].startswith("reg") for a in f["args"])
        and [a["kind"] for a in f["args"]] == ["gpr64", "gpr64"]
    )
    domains = tuple(argument_domain(a) for a in form["args"])
    groups = ((0, 1),) if alias else ((0,), (1,))
    arguments = ArgumentCase(form, domains, groups)
    bank = {r["name"]: r["value"] for r in registers()}
    base = (bank["RAX"], bank["RAX"] if alias else bank["RBX"])
    observations = []
    pairs = [(values, 0x400000) for values in arguments.separating(base)]
    pairs.append((base, 0xFFFFFEDCBA987654))
    for values, source in pairs:
        decoded = encode_constructor(form["id"], values)
        code = bytes.fromhex(decoded["hex"])
        observations.append(
            (code, decoded, _extract_concrete(load_shellcode(code, source), source))
        )
    return PreparedCase(
        arguments,
        tuple(observations),
        generalize(observations),
        (True,) * len(observations),
    )


@given(st.booleans(), st.integers(0, (1 << 64) - 16), st.integers(0, (1 << 64) - 1))
@settings(max_examples=20, deadline=None)
def test_alias_and_source_instantiation_matches_direct_model(
    alias, source, register_value
):
    case = parameterized_add(alias)
    bank = {r["name"]: r["value"] for r in registers()}
    values = (bank["R9"], bank["R9"] if alias else bank["R12"])
    code, decoded, model = case.instantiate(values, source)
    direct = _extract_concrete(load_shellcode(code, source), source)
    state = _input_state(
        code,
        source,
        {},
        bytes(32),
        tuple(register_value for _ in GPR64 + YMM256),
        [False] * len(FLAG_NAMES),
        True,
        layout=InputLayout.from_decoded(decoded),
    )
    reference = emulate(code, state)
    assert CompiledModel(model).differences(state, reference) == ()
    assert CompiledModel(direct).differences(state, reference) == ()
    assert model.source == source


@given(st.integers(-(1 << 31), (1 << 31) - 1), st.integers(0, (1 << 64) - 16))
@settings(max_examples=20, deadline=None)
def test_rip_memory_layout_uses_next_pc(displacement, source):
    bank = {r["name"]: r["value"] for r in registers()}
    decoded = encode_constructor(
        lea_form(32)["id"], [bank["RAX"], bank["RIP"], displacement]
    )
    code = bytes.fromhex(decoded["hex"])
    state = _input_state(
        code,
        source,
        {},
        b"\xa5" * 32,
        tuple(0 for _ in GPR64 + YMM256),
        [False] * len(FLAG_NAMES),
        True,
        layout=InputLayout.from_decoded(decoded),
    )
    address = (source + len(code) + displacement) % (1 << 64)
    if not source <= address < source + len(code):
        assert state.memory[address] == 0xA5


@given(st.integers(0, 100))
@settings(max_examples=10, deadline=None)
def test_prepared_case_serialization_reconstructs_template(offset):
    case = parameterized_add(False)
    restored = PreparedCase.from_data(case.to_data())
    bank = {r["name"]: r["value"] for r in registers()}
    args = (bank["RDX"], bank["R8"])
    assert restored.instantiate(args, 0x500000 + offset) == case.instantiate(
        args, 0x500000 + offset
    )


@cache
def source_template(prefix, size):
    observations = []
    for displacement, source in [
        (17, 0x400000),
        (33, 0x400000),
        (17, 0xFFFFFEDCBA987654),
    ]:
        code = bytes.fromhex(prefix) + displacement.to_bytes(
            size, "little", signed=True
        )
        decoded = decode(code)
        observations.append(
            (code, decoded, _extract_concrete(load_shellcode(code, source), source))
        )
    return generalize(observations), observations[0][2].declarations


@pytest.mark.parametrize(
    "prefix,size", [("74", 1), ("e8", 4), ("488d05", 4), ("488b05", 4)]
)
@given(st.integers(-128, 127), st.integers(0, (1 << 64) - 16), st.booleans())
@settings(max_examples=20, deadline=None)
def test_relative_targets_and_memory_parameters(
    prefix, size, displacement, source, zero
):
    from extractor.prepared_cases import bindings

    template, declarations = source_template(prefix, size)
    code = bytes.fromhex(prefix) + displacement.to_bytes(size, "little", signed=True)
    decoded = decode(code)
    row = bindings(decoded, declarations, source)
    model = template.instantiate(
        {name: row[name] for name in template.substitutions[0]}
    )
    state = _input_state(
        code,
        source,
        {},
        bytes(range(32)),
        tuple(0x100000 for _ in GPR64 + YMM256),
        [zero] * len(FLAG_NAMES),
        True,
        layout=InputLayout.from_decoded(decoded),
    )
    assert CompiledModel(model).differences(state, emulate(code, state)) == ()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
