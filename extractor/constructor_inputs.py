# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
"""Constructor argument domains and finite register-alias structural cases."""

import re
from collections import defaultdict
from dataclasses import dataclass
from functools import cache
from itertools import product

from hypothesis import assume
from hypothesis import strategies as st

from extractor.xed import EncodingError, encode_constructor, registers


@cache
def _register_bank():
    return {register["value"]: register for register in registers()}


@cache
def _register_names():
    return {register["name"]: register for register in registers()}


@cache
def _parent_values(choices):
    bank = _register_bank()
    return {bank[value]["parent"]: value for value in choices}


@cache
def _common_parents(choice_sets):
    mappings = tuple(_parent_values(choices) for choices in choice_sets)
    common = set.intersection(*(set(mapping) for mapping in mappings))
    return tuple(parent for parent in mappings[0] if parent in common)


def _register_key(spec):
    kind = spec["kind"]
    match = re.match(r"(?:e?gpr)(8|16|32|64)", kind)
    cls = (
        "GPR"
        if match
        else {
            "kreg": "MASK",
            "kreg!0": "MASK",
            "x87": "X87",
            "mmx": "MMX",
            "xmm": "XMM",
            "ymm": "YMM",
            "zmm": "ZMM",
            "seg": "SR",
            "cr": "CR",
            "dr": "DR",
        }.get(kind.split("_")[0], kind.upper())
    )
    width = int(match[1]) if match else None
    role = (
        "base"
        if spec["name"] == "base"
        else "index" if "index" in spec["name"] else "operand"
    )
    return cls, width, role, kind == "kreg!0"


@cache
def register_domains(available=None):
    """Build immutable role-specific register domains in one linear scan."""
    allowed = None if available is None else set(available)
    domains = defaultdict(list)
    base_sentinels = []
    for register in registers():
        if register["name"] in {"RIP", "INVALID"}:
            base_sentinels.append(register["value"])
        if allowed is not None and register["value"] not in allowed:
            continue
        width = register["width"] if register["class"] == "GPR" else None
        for role in ("operand", "base", "index"):
            if role == "index" and register["name"] in {"RSP", "ESP"}:
                continue
            domains[register["class"], width, role, False].append(register["value"])
            if register["name"] != "K0":
                domains[register["class"], width, role, True].append(register["value"])
    for sentinel in base_sentinels:
        for nonzero in (False, True):
            key = ("GPR", 64, "base", nonzero)
            if sentinel not in domains[key]:
                domains[key].append(sentinel)
    return {key: tuple(values) for key, values in domains.items()}


@cache
def supported_register_values(angr_names, unicorn_names):
    """Return XED views representable through both concrete tool interfaces."""
    maximum_width = {}
    for register in registers():
        if register["name"].lower() in angr_names and register["name"] in unicorn_names:
            parent = register["parent"]
            maximum_width[parent] = max(maximum_width.get(parent, 0), register["width"])
    return tuple(
        register["value"]
        for register in registers()
        if register["width"] <= maximum_width.get(register["parent"], -1)
    )


@dataclass(frozen=True)
class Domain:
    choices: tuple[int, ...] = ()
    low: int = 0
    high: int = 0
    register: bool = False

    def strategy(self):
        return (
            st.sampled_from(self.choices)
            if self.choices
            else st.integers(self.low, self.high)
        )

    def seed(self):
        return self.choices[0] if self.choices else max(self.low, min(1, self.high))

    def alternatives(self, value):
        if self.choices:
            return (v for v in self.choices if v != value)
        return iter(
            v
            for v in (2, 0, -1, self.low, self.high)
            if self.low <= v <= self.high and v != value
        )


def argument_domain(spec, domain_table=None):
    kind, ctype = spec["kind"], spec["ctype"]
    if ctype == "xed_reg_enum_t":
        table = register_domains() if domain_table is None else domain_table
        candidates = table.get(_register_key(spec), ())
        if not candidates:
            raise EncodingError(f"unmapped register domain: {spec}")
        return Domain(candidates, register=True)
    if kind == "scale":
        return Domain((1, 2, 4, 8))
    if kind == "zeroing" or ctype == "xed_bool_t":
        return Domain((0, 1))
    if kind == "rcsae":
        return Domain((0, 1, 2, 3))
    if spec["name"] == "dfv":
        return Domain(tuple(range(16)))
    match = re.fullmatch(r"xed_(u?)int(8|16|32|64)_t", ctype)
    if match:
        bits = int(match[2])
        return Domain(
            low=0 if match[1] else -(1 << (bits - 1)),
            high=(1 << (bits if match[1] else bits - 1)) - 1,
        )
    raise EncodingError(f"unmapped encoder argument: {spec}")


def checked_encode(form, values):
    decoded = encode_constructor(form["id"], values)
    explicit = iter(
        op["register"]["value"]
        for op in decoded["operands"]
        if op["name"].startswith("REG") and op["visibility"] in {"EXPLICIT", "DEFAULT"}
    )
    for arg, value in zip(form["args"], values, strict=True):
        if arg["ctype"] != "xed_reg_enum_t":
            continue
        if arg["name"] == "base":
            actual = decoded["base"]["value"]
        elif arg["name"].startswith("index"):
            actual = decoded["index"]["value"]
        else:
            actual = next(explicit, None)
        if actual != value:
            raise EncodingError(f"constructor changed register argument {arg['name']}")
    return decoded


def _partitions(slots, parents, index=0, groups=()):
    if index == len(slots):
        yield groups
        return
    slot = slots[index]
    for i, group in enumerate(groups):
        if set.intersection(*(parents[j] for j in (*group, slot))):
            yield from _partitions(
                slots,
                parents,
                index + 1,
                groups[:i] + (group + (slot,),) + groups[i + 1 :],
            )
    yield from _partitions(slots, parents, index + 1, groups + ((slot,),))


def structural_cases(form, domains, fixed=()):
    """Separate register views, implicit-register aliases, and control modes.

    Alias partitions range over parents: EAX and RAX can occupy the same group.
    Numeric immediates/displacements remain full-width parameter domains.
    """
    bank = {r["value"]: r for r in registers()}
    choices = []
    for arg, domain in zip(form["args"], domains, strict=True):
        if domain.register:
            categories = {}
            for value in domain.choices:
                r = bank[value]
                special = r["name"] if r["name"] in {"RIP", "INVALID"} else None
                key = (
                    special
                    or (
                        r["name"]
                        if r["class"] not in {"GPR", "XMM", "YMM", "ZMM"}
                        else None
                    ),
                    r["class"],
                    r["width"],
                    r["name"] in {"AH", "BH", "CH", "DH"},
                    r["parent"] if r["parent"] in fixed else None,
                )
                categories.setdefault(key, []).append(value)
            choices.append(
                [Domain(tuple(values), register=True) for values in categories.values()]
            )
        elif domain.choices and arg["kind"] != "scale":
            choices.append([Domain((value,)) for value in domain.choices])
        else:
            choices.append([domain])
    for selected in product(*choices):
        slots = [i for i, d in enumerate(selected) if d.register]
        parents = {i: {bank[v]["parent"] for v in selected[i].choices} for i in slots}
        for groups in _partitions(tuple(slots), parents):
            yield ArgumentCase(form, tuple(selected), groups)


@dataclass(frozen=True)
class ArgumentCase:
    form: dict
    domains: tuple[Domain, ...]
    groups: tuple[tuple[int, ...], ...]

    def parent_choices(self, group):
        return _common_parents(tuple(self.domains[i].choices for i in group))

    def assign(self, values, group, parent):
        for i in group:
            values[i] = _parent_values(self.domains[i].choices)[parent]

    def canonical(self):
        """Construct one representative directly; never retry an encoding."""
        values = [d.seed() for d in self.domains]
        used = set()
        positions = defaultdict(int)
        for group in sorted(self.groups, key=lambda g: len(self.parent_choices(g))):
            parents = self.parent_choices(group)
            if not parents:
                raise EncodingError(
                    "no distinct register assignment for structural case"
                )
            family = _register_names()[parents[0]]["class"]
            position = positions[family]
            if position >= len(parents):
                raise EncodingError(
                    "no fixed representative for structural register case"
                )
            parent = parents[position]
            if parent in used:
                raise EncodingError(
                    "fixed structural representatives do not remain distinct"
                )
            self.assign(values, group, parent)
            used.add(parent)
            positions[family] += 1
        return tuple(values)

    def separating(self, baseline):
        """n+1 witnesses preserving this case's register alias partition."""
        yield baseline
        bank = _register_bank()
        used = {bank[baseline[g[0]]]["parent"] for g in self.groups}
        for group in self.groups:
            parent = next(
                (choice for choice in self.parent_choices(group) if choice not in used),
                None,
            )
            if parent is not None:
                alternative = list(baseline)
                self.assign(alternative, group, parent)
                yield tuple(alternative)
        for i, domain in enumerate(self.domains):
            if domain.register:
                continue
            value = next(domain.alternatives(baseline[i]), None)
            if value is not None:
                alternative = tuple(
                    value if j == i else v for j, v in enumerate(baseline)
                )
                yield alternative

    def strategy(self):
        groups = tuple(
            (group, st.sampled_from(self.parent_choices(group)))
            for group in sorted(self.groups, key=lambda g: len(self.parent_choices(g)))
        )

        @st.composite
        def values(draw):
            result = [d.seed() for d in self.domains]
            used = set()
            for group, parents in groups:
                parent = draw(parents)
                assume(parent not in used)
                self.assign(result, group, parent)
                used.add(parent)
            for i, domain in enumerate(self.domains):
                if not domain.register:
                    result[i] = draw(domain.strategy())
            return tuple(result)

        return values()
