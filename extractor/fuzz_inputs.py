# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Per-ICLASS strategies from XED's actual encoder argument lists."""

import re
from hypothesis import assume, strategies as st
from extractor.xed import EncodingError, _invoke, decode, registers


def instruction_strategy(code: bytes, *, on_unavailable=None):
    iclass = decode(code)["iclass"]
    forms = _invoke("forms", iclass)
    if not forms:
        raise EncodingError(f"XED has no ENC2 constructors for {iclass}")
    bank = registers()

    def argument(spec):
        kind, ctype = spec["kind"], spec["ctype"]
        if ctype == "xed_reg_enum_t":
            match = re.match(r"(?:e?gpr)(8|16|32|64)", kind)
            register_class = (
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
            choices = [
                r["value"]
                for r in bank
                if r["class"] == register_class
                and (not match or r["width"] == int(match[1]))
            ]
            if not choices:
                raise EncodingError(f"unmapped XED register domain: {spec}")
            return st.sampled_from(choices)
        if kind == "scale":
            return st.sampled_from((1, 2, 4, 8))
        if kind == "zeroing" or ctype == "xed_bool_t":
            return st.integers(0, 1)
        if kind == "rcsae":
            return st.integers(0, 3)
        if spec["name"] == "dfv":
            return st.integers(0, 15)
        width = re.fullmatch(r"xed_(u?)int(8|16|32|64)_t", ctype)
        if width:
            bits = int(width[2])
            return (
                st.integers(0, (1 << bits) - 1)
                if width[1]
                else st.integers(-(1 << (bits - 1)), (1 << (bits - 1)) - 1)
            )
        raise EncodingError(f"unmapped XED encoder domain: {spec}")

    choices = []
    for form in forms:
        try:
            choice = (form["id"], st.tuples(*(argument(a) for a in form["args"])))
        except EncodingError as error:
            if on_unavailable is None:
                raise
            on_unavailable(form["id"], error)
        else:
            choices.append(choice)
    if not choices:
        raise EncodingError(f"no usable XED encoder domains for {iclass}")

    @st.composite
    def encoded(draw):
        index, arguments = draw(st.sampled_from(choices))
        values = draw(arguments)
        try:
            result = _invoke("fuzz", str(index), *(str(v) for v in values))
        except EncodingError:
            assume(False)  # XED rejects illegal combinations, not model failures.
        assert result["iclass"] == iclass
        return bytes.fromhex(result["hex"])

    return encoded()


# Sparse random initial bytes; the caller also places generated blocks at data
# addresses so memory operands exercise nonzero data instead of usually missing it.
MEMORY = st.dictionaries(
    st.integers(0, (1 << 64) - 1), st.binary(min_size=1, max_size=32), max_size=8
)
