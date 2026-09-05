# Plausible Angr catalog additions beyond the top 100

Date: 2026-09-04

## Scope and conclusion

The strongest next candidates are remaining condition-code instructions, sign extensions, XMM/GPR moves, vector bitwise operations, and integer SIMD. Their implementations largely use the bit-vector operations and architectural state already admitted by ixyk.

This is a source-based investigation, not a new extraction or fuzz campaign. The candidates below have not been validated through ixyk as part of this investigation. One representative encoding per family would establish a catalog probe, not coverage of every operand form, width, or architectural edge case.

The investigation examined Angr's documentation and symbolic operations, PyVEX's AMD64 lifter, and ixyk's extractor at the revisions listed below. Angr and PyVEX were checked out locally at release `v9.2.214`, matching the project's packaged version.

Ranks use the same historical frequency dataset and family aggregation as `catalog/generate_x86_64_top_100.py`. They are occurrence ranks in that corpus, not a modern ISA coverage ranking. PUSH, POP, and NOT are already the subject of [PR #36](https://github.com/heartpunk/ixyk/pull/36); this note considers further additions.

## First batch: 24 families

| Group | Candidates and occurrence ranks | Why they look straightforward |
|---|---|---|
| Remaining SET conditions | SETLE (106), SETNP (115), SETL (116), SETGE (131), SETP (136) | Reuse the same condition-code machinery as existing SET instructions. |
| Conditional branches | JNP (139), JO (168), JNO (177) | Existing modeled flags and branch outcomes suffice. |
| Sign extension | CQO (113), CWDE (166) | VEX uses arithmetic shifts or sign extension; these closely resemble existing CDQ/CDQE probes. |
| Register moves | MOVQ (120), MOVD (133), MOVUPD (134) | Bit-vector transfers. Select XMM/GPR forms, avoiding MMX state. |
| Vector bitwise | ANDPD (108), XORPS (124), ANDPS (127), PAND (152), ORPD (159), ANDNPD (165), POR (169), ANDNPS (174), ORPS (192), PANDN (200) | VEX lowers these to AND/OR/XOR/NOT. PS/PD names do not require floating-point arithmetic for these instructions. |
| Carry flag | STC (214) | Shares VEX's implementation path with the already-cataloged CLC. |

Start with register operands: for example, `setle al`, `movq xmm0, rax`, `movd xmm0, eax`, `movupd xmm0, xmm1`, and `andpd xmm0, xmm1`. Branch probes can follow the existing `probe_end` convention. These choices keep the initial probes within the existing state representation.

## Promising follow-up batch

| Group | Candidates | Assessment |
|---|---|---|
| Integer SIMD comparisons and arithmetic | PMINUB, PMAXUB, PADDD, PADDQ, PADDW, PSUBD, PCMPEQD, PCMPGTD | Angr implements lane-wise arithmetic, comparisons, and min/max. Use XMM forms. |
| Shuffles and unpacking | SHUFPS, PSHUFD, UNPCKLPD, UNPCKLPS, UNPCKHPD, UNPCKHPS, PUNPCKLWD, PUNPCKHWD, PUNPCKLBW, PUNPCKHBW, PUNPCKLDQ | Mostly bit extraction and concatenation. Use fixed shuffle immediates initially. |
| SIMD shifts | PSRLDQ, PSRLD, PSRLQ, PSLLW, PSLLD | Direct bit-vector operations; verify oversized-count behavior. |
| Other small additions | MOVLHPS, MOVHLPS, JRCXZ, CBW, CMC | Fit existing register and flag state without extending the architectural model. |

Angr's tests cover integer SIMD comparisons, interleaving, min operations, and saturation primitives. This supports prioritizing these candidates, but upstream operation tests do not establish end-to-end ixyk extraction or differential agreement.

## Candidates to defer

- **BSF, TZCNT, LZCNT, BLSI, ROR, SHLD/SHRD:** plausible, but zero inputs, undefined flags, shift counts, and CPU-feature decoding need closer attention. VEX explicitly gates TZCNT decoding on BMI support; without it the encoding can have BSF semantics.
- **MOVS, SCAS, CLD, STD, PUSHF/POPF:** direction flags or broader flags state exceed ixyk's current six-flag model. Angr support alone does not resolve this boundary.
- **Floating-point arithmetic and conversions, x87, and system instructions:** these can encounter theory, architectural-state, or execution-environment boundaries. They should not be counted as easy additions merely because the lifter recognizes them.

## Evidence and provenance

- Frequency source: [grouped instruction data](https://x86instructionpop.com/grouped_data.json), SHA-256 `f7531052413093997e0bf995801f4284c95e8b7a0807276b66fde1c949c68bcc`, verified against the catalog generator's pinned digest. Corpus: Ubuntu 16.04 x86-64 ELF binaries from 9,337 packages.
- Angr `v9.2.214`, commit `1648be89efadb6b2591f86b19168bd76d2ed3f09`: [IR documentation](https://github.com/angr/angr/blob/1648be89efadb6b2591f86b19168bd76d2ed3f09/docs/advanced-topics/ir.rst), [symbolic VEX operations](https://github.com/angr/angr/blob/1648be89efadb6b2591f86b19168bd76d2ed3f09/angr/engines/vex/claripy/irop.py), [flag helpers](https://github.com/angr/angr/blob/1648be89efadb6b2591f86b19168bd76d2ed3f09/angr/engines/vex/claripy/ccall.py), and [VEX operation tests](https://github.com/angr/angr/blob/1648be89efadb6b2591f86b19168bd76d2ed3f09/tests/engines/vex/test_vex.py).
- PyVEX `v9.2.214`, commit `fc26f8686b8f8edbca10d007fe9c4bd785cefc3d`, with VEX submodule commit `421bf0d9ec800df09fe4f8d90a8c13a0c63325e3`: [AMD64 lifter](https://github.com/angr/vex/blob/421bf0d9ec800df09fe4f8d90a8c13a0c63325e3/priv/guest_amd64_toIR.c). Relevant sections include vector logic near line 13549, CQO/CWDE near line 20757, CLC/STC/CMC near line 21680, and TZCNT near line 16713.
- ixyk base `8ddb5848fd5ade1b74f68ed31e34349e6a8518bb`: [register-closure check](https://github.com/heartpunk/ixyk/blob/8ddb5848fd5ade1b74f68ed31e34349e6a8518bb/extractor/extractor.py), [modeled registers and flags](https://github.com/heartpunk/ixyk/blob/8ddb5848fd5ade1b74f68ed31e34349e6a8518bb/extractor/amd64_state.py), and [QF_ABV artifact contract](https://github.com/heartpunk/ixyk/blob/8ddb5848fd5ade1b74f68ed31e34349e6a8518bb/extractor/artifact.py).
