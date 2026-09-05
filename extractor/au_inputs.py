# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Independent operand perturbations using XED's instruction interface."""

from antiunification.many import separating_inputs
from extractor.xed import EncodingError, InstructionInfo, decode, encode, registers


def parameters(decoded: InstructionInfo) -> dict[str, str | int]:
    result: dict[str, str | int] = {}
    for operand in decoded["operands"]:
        if operand["visibility"] != "EXPLICIT":
            continue
        field = operand["name"]
        register = operand["register"]["name"]
        if register != "INVALID":
            result[field] = register
        elif field == "IMM0" and decoded["immediate_width"]:
            result[field] = decoded["immediate"]
        elif field == "RELBR":
            result[field] = decoded["branch"]
        elif field in {"MEM0", "AGEN"}:
            for name, key in (("BASE0", "base"), ("INDEX", "index")):
                if decoded[key]["name"] not in {"INVALID", "RIP", "EIP"}:
                    result[name] = decoded[key]["name"]
            if decoded["index"]["name"] != "INVALID":
                result["SCALE"] = decoded["scale"]
            if decoded["displacement_width"]:
                result["DISP"] = decoded["displacement"]
    return result


def instruction_inputs(code: bytes) -> tuple[bytes, ...]:
    """Produce n+1 independent inputs, excluding the parameterized request."""
    decoded = decode(code)
    requested = parameters(decoded)
    if not requested:
        return (code,)
    bank = {r["name"]: r for r in registers()}
    fixed = {
        op["register"]["parent"]
        for op in decoded["operands"]
        if op["register"]["name"] != "INVALID" and op["name"] not in requested
    }

    def alternative(row: dict[str, str | int], field: str) -> str | int:
        value = requested[field]
        candidates: list[str | int]
        if isinstance(value, str):
            original = bank[value]
            used = (
                fixed
                | {bank[v]["parent"] for v in row.values() if isinstance(v, str)}
                | {original["parent"]}
            )
            candidates = [
                r["name"]
                for r in bank.values()
                if r["class"] == original["class"]
                and r["width"] == original["width"]
                and r["parent"] not in used
            ]
        else:
            candidates = [1, 2, 4, 8] if field == "SCALE" else list(range(1, 33))
        for candidate in candidates:
            if candidate in (value, row[field]):
                continue
            try:
                _ = encode(code, row | {field: candidate})
            except EncodingError:
                continue
            return candidate
        raise EncodingError(f"cannot obtain separating value for {field}")

    baseline = dict(requested)
    for field in requested:
        baseline[field] = alternative(baseline, field)
    alternatives = {field: alternative(baseline, field) for field in baseline}
    rows = separating_inputs(baseline, alternatives)
    inputs = tuple(encode(code, row) for row in rows)
    if code in inputs or len(set(inputs)) != len(inputs):
        raise EncodingError("inputs are not distinct from each other and the request")
    return inputs
