# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Family-level campaign exclusions with explicit, file-producing skips."""

KNOWN_DIFFICULT = {
    "BSR": "Known differential mismatch; failure processing exceeded 3,000 executions per variant in the 2026-09-04 campaign.",
}

def exclusion_reason(family, profile):
    if profile not in ["fast", "full"]:
        fail("unknown instruction run profile: %s" % profile)
    return KNOWN_DIFFICULT.get(family.upper()) if profile == "fast" else None

def skipped_instruction(name, output, family, instruction_hex, reason):
    report = json.encode({
        "schema": "ixyk.differential_fuzz.v1",
        "status": "skipped",
        "profile": "fast",
        "family": family,
        "instruction_hex": instruction_hex,
        "executions": 0,
        "reason": reason,
    })
    native.genrule(
        name = name,
        outs = [output],
        cmd = "printf '%s\\n' '%s' > $@" % ("%s", report.replace("'", "'\"'\"'")),
    )
