# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Assemble one complete acquisition probe for each catalog family."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory


CATALOG = Path(__file__).with_name("x86_64_top_100.json")
OUTPUT = Path(__file__).with_name("x86_64_probes.json")
STARLARK_OUTPUT = Path(__file__).with_name("x86_64_probes.bzl")
PROBES = {
    "MOV": "mov rax, rbx",
    "ADD": "add rax, rbx",
    "CALL": "call probe_end",
    "LEA": "lea rax, [rbx + rcx*2 + 8]",
    "JE": "je probe_end",
    "TEST": "test rax, rbx",
    "JMP": "jmp probe_end",
    "NOP": "nop",
    "CMP": "cmp rax, rbx",
    "JNE": "jne probe_end",
    "XOR": "xor rax, rbx",
    "RET": "ret",
    "AND": "and rax, rbx",
    "MOVZX": "movzx eax, bl",
    "MOVSD": "movsd xmm0, xmm1",
    "ROL": "rol rax, cl",
    "SUB": "sub rax, rbx",
    "SAR": "sar rax, cl",
    "OR": "or rax, rbx",
    "MOVSXD": "movsxd rax, ebx",
    "JBE": "jbe probe_end",
    "JA": "ja probe_end",
    "SETNE": "setne al",
    "DEC": "dec rax",
    "XCHG": "xchg rax, rbx",
    "JLE": "jle probe_end",
    "JB": "jb probe_end",
    "MULSD": "mulsd xmm0, xmm1",
    "JAE": "jae probe_end",
    "ADDSD": "addsd xmm0, xmm1",
    "MOVAPD": "movapd xmm0, xmm1",
    "IMUL": "imul rax, rbx",
    "JG": "jg probe_end",
    "UCOMISD": "ucomisd xmm0, xmm1",
    "JS": "js probe_end",
    "PXOR": "pxor xmm0, xmm1",
    "ADC": "adc rax, rbx",
    "SHL": "shl rax, cl",
    "MOVSX": "movsx eax, bl",
    "SETE": "sete al",
    "SUBSD": "subsd xmm0, xmm1",
    "CMOVE": "cmove rax, rbx",
    "MOVAPS": "movaps xmm0, xmm1",
    "JL": "jl probe_end",
    "CMOVNE": "cmovne rax, rbx",
    "MOVSS": "movss xmm0, xmm1",
    "JGE": "jge probe_end",
    "CVTSI2SD": "cvtsi2sd xmm0, rax",
    "UD2": "ud2",
    "DIV": "div rbx",
    "CVTTSD2SI": "cvttsd2si rax, xmm0",
    "CDQE": "cdqe",
    "MUL": "mul rbx",
    "SBB": "sbb rax, rbx",
    "JNS": "jns probe_end",
    "BT": "bt rax, rbx",
    "XORPD": "xorpd xmm0, xmm1",
    "INC": "inc rax",
    "NEG": "neg rax",
    "DIVSD": "divsd xmm0, xmm1",
    "JP": "jp probe_end",
    "SHR": "shr rax, cl",
    "MULSS": "mulss xmm0, xmm1",
    "CMPXCHG": "cmpxchg rax, rbx",
    "INT3": "int3",
    "CMOVLE": "cmovle rax, rbx",
    "CMOVB": "cmovb rax, rbx",
    "CMOVGE": "cmovge rax, rbx",
    "CMOVBE": "cmovbe rax, rbx",
    "SETBE": "setbe al",
    "CMOVAE": "cmovae rax, rbx",
    "CLC": "clc",
    "CMOVG": "cmovg rax, rbx",
    "ADDSS": "addss xmm0, xmm1",
    "STOS": "rep stosq",
    "CMOVS": "cmovs rax, rbx",
    "XADD": "xadd rax, rbx",
    "MOVDQA": "movdqa xmm0, xmm1",
    "CMPS": "repe cmpsq",
    "SETG": "setg al",
    "CMOVA": "cmova rax, rbx",
    "VADDSD": "vaddsd xmm0, xmm1, xmm2",
    "MOVDQU": "movdqu xmm0, xmm1",
    "SETAE": "setae al",
    "SETA": "seta al",
    "PCMPEQB": "pcmpeqb xmm0, xmm1",
    "PMOVMSKB": "pmovmskb eax, xmm0",
    "CMOVL": "cmovl rax, rbx",
    "MOVUPS": "movups xmm0, xmm1",
    "BSR": "bsr rax, rbx",
    "MAXSD": "maxsd xmm0, xmm1",
    "CMOVNS": "cmovns rax, rbx",
    "MULPD": "mulpd xmm0, xmm1",
    "SETB": "setb al",
    "UCOMISS": "ucomiss xmm0, xmm1",
    "CDQ": "cdq",
    "SUBSS": "subss xmm0, xmm1",
    "BSWAP": "bswap rax",
    "LEAVE": "leave",
    "CVTSS2SD": "cvtss2sd xmm0, xmm1",
}


def assemble(assembly: str) -> bytes:
    source = f".intel_syntax noprefix\n.text\nprobe:\n  {assembly}\nprobe_end:\n"
    with TemporaryDirectory() as directory:
        root = Path(directory)
        source_path, object_path, binary_path = (
            root / "probe.s",
            root / "probe.o",
            root / "probe.bin",
        )
        _ = source_path.write_text(source, encoding="ascii")
        _ = subprocess.run(
            (
                "llvm-mc",
                "--triple=x86_64-unknown-linux-gnu",
                "--filetype=obj",
                f"--o={object_path}",
                str(source_path),
            ),
            check=True,
        )
        _ = subprocess.run(
            (
                "llvm-objcopy",
                "--only-section=.text",
                "--output-target=binary",
                str(object_path),
                str(binary_path),
            ),
            check=True,
        )
        return binary_path.read_bytes()


def main() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    instructions = catalog["instructions"]
    names = [instruction["name"] for instruction in instructions]
    if set(names) != set(PROBES) or len(names) != len(PROBES):
        raise RuntimeError("probe names do not exactly cover the instruction catalog")
    version_lines = subprocess.run(
        ("llvm-mc", "--version"), check=True, capture_output=True, text=True
    ).stdout.splitlines()
    version = next(line.strip() for line in version_lines if "version" in line.lower())
    probes = [
        {
            "rank": instruction["rank"],
            "name": instruction["name"],
            "assembly": PROBES[instruction["name"]],
            "bytes": assemble(PROBES[instruction["name"]]).hex(),
        }
        for instruction in instructions
    ]
    result = {
        "schema": "ixyk.x86_64.acquisition_probes.v1",
        "catalog_schema": catalog["schema"],
        "assembler": version,
        "probes": probes,
    }
    _ = OUTPUT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    lines = ["X86_64_PROBES = ["]
    lines.extend(
        "    ({rank}, {name}, {assembly}, {bytes}),".format(
            rank=probe["rank"],
            name=json.dumps(probe["name"]),
            assembly=json.dumps(probe["assembly"]),
            bytes=json.dumps(probe["bytes"]),
        )
        for probe in probes
    )
    lines.append("]")
    _ = STARLARK_OUTPUT.write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
