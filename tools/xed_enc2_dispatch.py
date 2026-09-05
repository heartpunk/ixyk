# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Generate the runtime bridge while XED's ENC2 operand metadata is live."""

from collections import defaultdict
import json
from pathlib import Path


def arguments(record, function):
    """Bind encoder arguments to decoded fields, using XED's operand order."""
    registers = iter(
        op.name
        for op in record.parsed_operands
        if op.name.startswith("REG") and op.visibility in {"EXPLICIT", "DEFAULT"}
    )
    values = []
    checks = []
    for declaration, kind in function.get_args():
        ctype, name = declaration.rsplit(" ", 1)
        if kind == "req":
            value = "&request"
        elif name == "base":
            value = "xed_decoded_inst_get_base_reg(wanted, 0)"
        elif name in {"index", "index_xmm", "index_ymm", "index_zmm"}:
            value = "xed_decoded_inst_get_index_reg(wanted, 0)"
        elif name == "scale":
            value = "xed_decoded_inst_get_scale(wanted, 0)"
        elif name.startswith("relb_disp"):
            value = "xed_decoded_inst_get_branch_displacement(wanted)"
        elif name.startswith("disp"):
            value = "xed_decoded_inst_get_memory_displacement(wanted, 0)"
        elif name.startswith("imm"):
            getter = "second_immediate" if name.endswith("_2") else "unsigned_immediate"
            value = f"xed_decoded_inst_get_{getter}(wanted)"
        elif ctype == "xed_reg_enum_t":
            field = next(registers, None)
            if field is None:
                raise ValueError("encoder register arguments exceed explicit operands")
            value = f"xed_decoded_inst_get_reg(wanted, XED_OPERAND_{field})"
        else:
            raise ValueError(f"unmapped encoder argument {name}: {kind}")
        if ctype == "xed_reg_enum_t":
            widths = {"xmm": 128, "ymm": 256, "zmm": 512, "mmx": 64}
            width = widths.get(kind)
            for prefix in ("gpr", "egpr"):
                if kind.startswith(prefix):
                    digits = kind[len(prefix) :].split("_")[0]
                    if digits.isdigit():
                        width = int(digits)
            if width:
                checks.append(f"xed_get_register_width_bits64({value}) == {width}")
        values.append(f"({ctype})({value})")
    if next(registers, None) is not None:
        raise ValueError("explicit register operands exceed encoder arguments")
    return values, checks


def emit(directory, env, records):
    if (env.mode, env.asz) != (64, 64):
        return
    forms = defaultdict(list)
    unsupported = []
    for record in records:
        for function in record.encoder_functions:
            try:
                values, checks = arguments(record, function)
            except ValueError as error:
                unsupported.append(
                    [record.iform, function.get_function_name(), str(error)]
                )
                continue
            call = f"{function.get_function_name()}({', '.join(values)});"
            forms[record.iform].append((call, checks))
    lines = [
        "/* Generated from pinned XED ENC2 metadata. */",
        '#include "xed-enc2-m64-a64.h"',
        "typedef unsigned (*ixyk_enc2_candidate)(const xed_decoded_inst_t *, unsigned char *);",
    ]
    ranges = []
    index = 0
    for form, candidates in sorted(forms.items()):
        ranges.append((form, index, len(candidates)))
        for call, checks in candidates:
            lines.extend(
                [
                    f"static unsigned ixyk_enc2_{index}(const xed_decoded_inst_t *wanted, unsigned char *bytes) {{",
                    "    xed_enc2_req_t request;",
                    f"    if (!({' && '.join(checks) or '1'})) return 0;",
                    "    xed_enc2_req_t_init(&request, bytes);",
                    f"    {call}",
                    "    return xed_enc2_encoded_length(&request);",
                    "}",
                ]
            )
            index += 1
    lines.append("static const ixyk_enc2_candidate ixyk_enc2_candidates[] = {")
    lines.extend(f"    ixyk_enc2_{i}," for i in range(index))
    lines.append("};")
    lines.append(
        "static const struct { unsigned start, count; } ixyk_enc2_ranges[XED_IFORM_LAST] = {"
    )
    lines.extend(
        f"    [XED_IFORM_{form}] = {{{start}, {count}}},"
        for form, start, count in ranges
    )
    lines.extend(
        [
            "};",
            "static int ixyk_enc2_encode(const xed_decoded_inst_t *wanted,",
            "    unsigned char *bytes, unsigned *length,",
            "    int (*matches)(const xed_decoded_inst_t *, const unsigned char *, unsigned)) {",
            "    unsigned form = xed_decoded_inst_get_iform_enum(wanted);",
            "    if (form >= XED_IFORM_LAST) return 0;",
            "    unsigned start = ixyk_enc2_ranges[form].start;",
            "    unsigned end = start + ixyk_enc2_ranges[form].count;",
            "    for (unsigned i = start; i < end; ++i) {",
            "        *length = ixyk_enc2_candidates[i](wanted, bytes);",
            "        if (*length && matches(wanted, bytes, *length)) return 1;",
            "    }",
            "    return 0;",
            "}",
            "",
        ]
    )
    output = Path(directory)
    (output / "ixyk-enc2-dispatch.h").write_text("\n".join(lines))
    (output / "ixyk-enc2-unmapped.json").write_text(
        json.dumps(unsupported, indent=2) + "\n"
    )
