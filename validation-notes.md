# 10k differential-validation scratch notes

> Working research notes captured from the preserved 10k validation run. Keep this full evidence ledger for now; later documentation can inline selected summary views without discarding the detailed provenance.

## Provenance

| Item | Value |
|---|---|
| Bazel target | `//catalog:x86_64_top_100_fuzz_10000` |
| Platform | Linux via the repository's configured Bazel/REAPI profile; no local macOS execution |
| Preserved source snapshot | `/tmp/ixyk-fuzz10000-59ab3cad.FGOy7i` on NixOS |
| Original execution window | 2026-09-02 01:40–03:45 PDT (08:40–10:45 UTC), reconstructed from the NativeLink journal |
| Cache audit | 100 exact REAPI action digests recovered from that window; 100/100 ActionCache results were live on 2026-09-03 |
| Report schema | `ixyk.differential_fuzz.v1` |
| Notes authoring | OpenAI Codex using GPT-5.6 Sol, high reasoning, fast mode |
| Authorship boundary | The prose, classifications, calculations, and table presentation are AI-assisted synthesis; the underlying statuses, execution counts, witnesses, artifacts, digests, and catalog data come from the preserved repository and NativeLink cache evidence described here. |
| Requested work | 100 representative instruction-family probes × 10,000 Hypothesis examples = 1,000,000 requested examples |
| Evidence source | Cached ActionResults and CAS output blobs; the audit did not execute fuzz actions |
| Catalog source | Ubuntu 16.04 x86-64 ELF instruction-frequency data covering 9,337 packages, retrieved 2026-09-01 |
| Catalog aggregation | Families normalize `MOVABS` to `MOV` and strip `REP`, `REPZ`, and `REPNZ` prefixes before ranking |

## Headline results

| Status | Families | Requested examples | Actual executions | Top-100 occurrence mass | Share of top-100 mass | Meaning |
|---|---:|---:|---:|---:|---:|---|
| Pass | 78 | 780,000 | 780,000 | 27,656,146,314 | 99.007986% | All requested concrete executions agreed. |
| Mismatch | 3 | 30,000 | 6,621 | 13,510,436 | 0.048367% | Hypothesis found and shrank a concrete disagreement; execution count includes discovery and shrinking. |
| Unsupported | 18 | 180,000 | 0 | 246,836,377 | 0.883665% | The acquired/extracted artifact crossed a deliberately unsupported typed-model or state-closure boundary, so no concrete comparison ran. |
| Acquisition error | 1 | 10,000 | 0 | 16,754,816 | 0.059982% | The instruction could not be acquired into an IR artifact, so no model or concrete comparison ran. |
| **Total** | **100** | **1,000,000** | **786,621** | **27,933,247,943** | **100.000000%** | Actual executions are lower than requested because unsupported/acquisition-error cases run zero examples and mismatches stop after discovery and shrinking. |

| Derived quantity | Value | Exact interpretation |
|---|---:|---|
| Completed passing comparisons | 780,000 | 78 probes completed all 10,000 model-versus-Unicorn executions. |
| Mismatch-path executions | 6,621 | BT 140 + BSR 3,130 + LEAVE 3,351; counts include Hypothesis discovery and shrinking. |
| Zero-execution probes | 19 | 18 unsupported + 1 acquisition error. |
| Passing family rate | 78.000000% | Representative families passing, unweighted. |
| Passing occurrence-weighted share | 99.007986% | Share of occurrence mass **within these top 100 families** whose single representative probe passed. |
| Non-passing occurrence-weighted share | 0.992014% | Unsupported, acquisition-error, and mismatch family mass within the same top-100 denominator. |

The occurrence-weighted percentage is useful prioritization evidence, not an end-to-end coverage claim. It does **not** mean that 99% of every opcode, encoding, operand form, processor mode, or all dynamically executed machine instructions has been validated. Each ranked family currently contributes one representative probe.

## What each fuzz execution validates

| Layer | Inputs / behavior | Success condition | Failure representation |
|---|---|---|---|
| Acquisition | angr/VEX lifts one instruction at RIP `0x400000`. | An acquisition artifact is produced. | Structured `acquisition_error`; UD2 is the sole case in this run. |
| Extraction | The lifted transition is converted to typed declarations and guarded simultaneous updates. | State reads remain inside the declared state; path/outcome identities are complete; artifact is serializable. | Structured `unsupported` when closure or outcome requirements are not met. |
| Typed-model compilation | Serialized expressions are rebuilt in a fresh Z3 context. | Every sort/operator is in the supported typed vocabulary. | Structured `unsupported`, chiefly floating-point and rounding-mode sorts in this run. |
| Concrete generation | Hypothesis uses `seed(0)`, `derandomize=True`, `database=None`, `deadline=None`, and `report_multiple_bugs=False`. | A concrete architectural pre-state is produced. | A mismatch triggers shrinking of the first disagreement. |
| Emulator execution | Unicorn executes exactly one instruction over sparse, zero-default byte memory. Missing pages are mapped on demand. | Execution continues normally, or a CPU exception corresponds to a model error target. | Non-CPU emulator failures are reported as mismatches; CPU-exception/target disagreement is also a mismatch. |
| Path selection | The concrete input is constrained into the symbolic model. | Exactly one guarded model edge is enabled. | `enabled edges: N; expected exactly one`. |
| State comparison | Scalar registers, selected flags, mirrored PC, and full memory are compared. | Every modeled value equals Unicorn's post-state. | Exact differing fields, target disposition, mirrored PC, or `memory differs`. |

## Generated state space

| Component | Generated domain |
|---|---|
| General-purpose registers | 16 x 64-bit GPRs. Every GPR except RSP ranges over all unsigned 64-bit values. |
| RSP | `0x1000` through `2^47 - 0x1000`, inclusive, to keep the initial stack pointer in a mappable low-canonical range. |
| Vector registers | YMM0–YMM15, each over all unsigned 256-bit values. |
| Flags | CF, ZF, SF, OF, PF, and AF, each Boolean. |
| RIP | Fixed at `0x400000`, the extraction source address. |
| Initial memory | Sparse zero-default byte memory seeded with the representative instruction bytes at RIP. |
| Comparison outputs | All 16 GPRs, all 16 YMM registers, RIP, the six selected flags, mirrored PC, and the complete sparse memory function. |

## Results by source category

Categories are inherited from the source frequency catalog. “Weighted pass” uses only that category's top-100 occurrence mass as its denominator.

| Category | Families | Pass | Mismatch | Unsupported | Acquisition error | Occurrence mass | Passing mass | Weighted pass |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| DATA | 22 | 22 | 0 | 0 | 0 | 11,214,012,414 | 11,214,012,414 | 100.000000% |
| CONTROL FLOW | 18 | 17 | 1 | 0 | 0 | 6,183,747,585 | 6,182,054,331 | 99.972618% |
| BINARY ARITHMETIC | 11 | 10 | 0 | 1 | 0 | 4,854,839,885 | 4,838,990,009 | 99.673524% |
| MISC | 3 | 2 | 0 | 0 | 1 | 2,410,955,520 | 2,394,200,704 | 99.305055% |
| BITWISE | 10 | 8 | 2 | 0 | 0 | 1,266,097,951 | 1,254,280,769 | 99.066646% |
| LOGICAL | 3 | 3 | 0 | 0 | 0 | 1,054,473,844 | 1,054,473,844 | 100.000000% |
| SHIFT AND ROTATE | 4 | 4 | 0 | 0 | 0 | 372,124,917 | 372,124,917 | 100.000000% |
| SSE | 22 | 8 | 0 | 14 | 0 | 326,078,322 | 104,337,982 | 31.997828% |
| STRING | 3 | 1 | 0 | 2 | 0 | 211,132,216 | 204,657,284 | 96.933234% |
| MMX | 2 | 2 | 0 | 0 | 0 | 33,579,510 | 33,579,510 | 100.000000% |
| FLAG REGISTER INSN | 1 | 1 | 0 | 0 | 0 | 3,434,550 | 3,434,550 | 100.000000% |
| AVX | 1 | 0 | 0 | 1 | 0 | 2,771,229 | 0 | 0.000000% |

## Unsupported cases by exact boundary

| Boundary | Exact report | Affected representatives | Count | Occurrence mass | Pipeline stage | Current interpretation |
|---|---|---|---:|---:|---|---|
| Binary64 floating-point sort | `unsupported Z3 sort: FPSort(11, 53)` | 28 MULSD; 30 ADDSD; 34 UCOMISD; 41 SUBSD; 60 DIVSD; 82 VADDSD; 91 MAXSD; 93 MULPD; 95 UCOMISS; 100 CVTSS2SD | 10 | 181,008,279 | Typed-model eligibility | The extracted formula contains an IEEE-754 binary64 sort outside the current QF_ABV boundary. |
| Binary32 floating-point sort | `unsupported Z3 sort: FPSort(8, 24)` | 63 MULSS; 74 ADDSS; 97 SUBSS | 3 | 10,603,924 | Typed-model eligibility | The extracted formula contains an IEEE-754 binary32 sort outside the current QF_ABV boundary. |
| Floating-point rounding mode | `unsupported Z3 sort: RoundingMode` | 51 CVTTSD2SI | 1 | 15,667,186 | Typed-model eligibility | The formula depends on a rounding-mode value outside the current typed vocabulary. |
| Declared-state closure | `read [216, 224) escapes declared state` | 48 CVTSI2SD | 1 | 17,232,180 | Model extraction/closure | The lifted semantics read bytes not represented by the declared architectural state. |
| Declared-state closure | `read [176, 184) escapes declared state` | 75 STOS; 79 CMPS | 2 | 6,474,932 | Model extraction/closure | The lifted string semantics read bytes not represented by the declared architectural state. |
| Incomplete outcome identity | `instruction at 0x400000 outcome identities are incomplete` | 50 DIV | 1 | 15,849,876 | Model extraction/outcome classification | Acquisition produced successors whose VEX-exit-derived outcome IDs were not exactly the dense sequence `0..N-1`; extraction stopped before serializing a typed model or running fuzz comparisons. |
| **Total** |  |  | **18** | **246,836,377** |  | Fourteen cases are floating-point/rounding typed-vocabulary boundaries; three are declared-state closure failures; one has incomplete path/outcome identities. |

The floating-point arithmetic/comparison cases do not imply that all SSE-family probes fail. Bit transport and bitwise/vector operations such as MOVSD, MOVSS, MOVAPD, MOVAPS, PXOR, XORPD, MOVDQA, MOVDQU, MOVUPS, PCMPEQB, and PMOVMSKB completed 10,000 comparisons apiece.

## Acquisition error

| Rank | Family | Probe | Bytes | Executions | Exact error | Interpretation |
|---:|---|---|---|---:|---|---|
| 49 | UD2 | `ud2` | `0f0b` | 0 | `SimIRSBNoDecodeError: IR decoding error at 0x400000. You can hook this instruction with a python replacement using project.hook(0x400000, your_function, length=length_of_instruction).` | angr/VEX did not decode/lift the deliberate undefined-instruction opcode, so no model or fuzz comparison was available. |

## Mismatches and minimized witnesses

| Rank | Family | Probe | Executions | Exact disagreement | Minimized nonzero/special input | Current interpretation | Follow-up |
|---:|---|---|---:|---|---|---|---|
| 56 | BT | `bt rax, rbx` | 140 | `rflags_AF: model=0x0, emulator=0x1` | `AF=1`, `RIP=0x400000`, `RSP=0x1000`; all other generated fields zero | Oracle-contract false positive. Intel defines CF, leaves ZF unaffected, and marks OF/SF/AF/PF undefined. The model and Unicorn may legally disagree on AF. | Add per-instruction defined-output masks; compare CF and preserved ZF here, not undefined flags. |
| 90 | BSR | `bsr rax, rbx` | 3,130 | `rflags_PF: model=0x0, emulator=0x1` | `RIP=0x400000`, `RSP=0x1000`; all other generated fields zero, including source `RBX=0` and input `PF=0` | Oracle-contract false positive. Intel marks CF/OF/SF/AF/PF undefined, and with zero source also marks the destination undefined; only ZF is defined. The observed PF disagreement is therefore legal. | Add per-instruction defined-output masks; on the zero-source path compare ZF but mask PF and destination RAX. |
| 99 | LEAVE | `leave` | 3,351 | `emulator UcError: Invalid memory mapping (UC_ERR_MAP)` | `RBP=0xfffffffffffff1e0`, `RSP=0x1000`, `RIP=0x400000`; all other generated fields zero | Harness-domain failure, not a demonstrated model disagreement. The address is canonical high-half, but LEAVE copies unrestricted RBP to RSP and reads from the top 4 KiB page. The symbolic model permits every BV64 memory address; Unicorn rejects the harness's attempt to map that terminal page. | Make the concrete-memory domain match the symbolic contract, or constrain every register that may become a stack/address source; then rerun. |

| Architecture reference | Relevant contract |
|---|---|
| [Intel® 64 and IA-32 Architectures Software Developer’s Manual, Volume 2A](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf) | BT: CF contains the selected bit; ZF is unaffected; OF, SF, AF, and PF are undefined. BSR: ZF reports whether the source is zero; CF, OF, SF, AF, and PF are undefined; destination is undefined for a zero source. |

## Complete representative-family ledger

“Executions” counts calls of the Hypothesis property, including shrinking. A pass therefore has exactly 10,000; a pre-execution boundary has zero.

| Rank | Family | Category | Corpus occurrences | Aggregated source mnemonics | Catalog opcode encodings | Representative probe | Bytes | Status | Executions | Exact result |
|---:|---|---|---:|---|---|---|---|---|---:|---|
| 1 | MOV | DATA | 10,627,770,656 | MOV, MOVABS, REPNZ MOV, REPZ MOV | 88, 89, 8a, 8b, 8c, 8e, a0, a1, a2, a3, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, ba, bb, bc, bd, be, bf, c6, c7, f20, f23 | `mov rax, rbx` | `4889d8` | Pass | 10,000 | All 10,000 executions agreed |
| 2 | ADD | BINARY ARITHMETIC | 3,529,131,973 | ADD, REPNZ ADD, REPZ ADD | 0, 1, 2, 3, 4, 5, 80, 81, 83 | `add rax, rbx` | `4801d8` | Pass | 10,000 | All 10,000 executions agreed |
| 3 | CALL | CONTROL FLOW | 2,235,935,654 | CALL | e8, ff | `call probe_end` | `e800000000` | Pass | 10,000 | All 10,000 executions agreed |
| 4 | LEA | MISC | 1,351,390,642 | LEA | 8d | `lea rax, [rbx + rcx*2 + 8]` | `488d444b08` | Pass | 10,000 | All 10,000 executions agreed |
| 5 | JE | CONTROL FLOW | 1,253,038,862 | JE | 74, f84 | `je probe_end` | `7400` | Pass | 10,000 | All 10,000 executions agreed |
| 6 | TEST | BITWISE | 1,125,117,859 | REPZ TEST, TEST | 84, 85, a8, a9, f6, f7 | `test rax, rbx` | `4885d8` | Pass | 10,000 | All 10,000 executions agreed |
| 7 | JMP | CONTROL FLOW | 1,048,626,646 | JMP, REPZ JMP | e9, eb, ff | `jmp probe_end` | `eb00` | Pass | 10,000 | All 10,000 executions agreed |
| 8 | NOP | MISC | 1,042,810,062 | NOP | 90, f19, f1c, f1f | `nop` | `90` | Pass | 10,000 | All 10,000 executions agreed |
| 9 | CMP | BINARY ARITHMETIC | 934,686,880 | CMP, REPZ CMP | 38, 39, 3a, 3b, 3c, 3d, 80, 81, 83 | `cmp rax, rbx` | `4839d8` | Pass | 10,000 | All 10,000 executions agreed |
| 10 | JNE | CONTROL FLOW | 843,978,385 | JNE, REPZ JNE | 75, f85 | `jne probe_end` | `7500` | Pass | 10,000 | All 10,000 executions agreed |
| 11 | XOR | LOGICAL | 657,996,290 | REPNZ XOR, REPZ XOR, XOR | 30, 31, 32, 33, 34, 35, 81 | `xor rax, rbx` | `4831d8` | Pass | 10,000 | All 10,000 executions agreed |
| 12 | RET | CONTROL FLOW | 296,410,098 | REPZ RET, RET | c2, c3 | `ret` | `c3` | Pass | 10,000 | All 10,000 executions agreed |
| 13 | AND | LOGICAL | 283,871,821 | AND, REPNZ AND, REPZ AND | 20, 21, 22, 23, 24, 25, 80, 81, 83 | `and rax, rbx` | `4821d8` | Pass | 10,000 | All 10,000 executions agreed |
| 14 | MOVZX | DATA | 279,163,464 | MOVZX | fb6, fb7 | `movzx eax, bl` | `0fb6c3` | Pass | 10,000 | All 10,000 executions agreed |
| 15 | MOVSD | STRING | 204,657,284 | MOVSD | f10, f11 | `movsd xmm0, xmm1` | `f20f10c1` | Pass | 10,000 | All 10,000 executions agreed |
| 16 | ROL | SHIFT AND ROTATE | 196,742,072 | ROL | c0, c1, d0, d1, d2, d3 | `rol rax, cl` | `48d3c0` | Pass | 10,000 | All 10,000 executions agreed |
| 17 | SUB | BINARY ARITHMETIC | 183,967,954 | REPNZ SUB, REPZ SUB, SUB | 28, 29, 2a, 2b, 2c, 2d, 80, 81, 83 | `sub rax, rbx` | `4829d8` | Pass | 10,000 | All 10,000 executions agreed |
| 18 | SAR | SHIFT AND ROTATE | 140,511,363 | REPNZ SAR, SAR | c0, c1, d0, d1, d2, d3 | `sar rax, cl` | `48d3f8` | Pass | 10,000 | All 10,000 executions agreed |
| 19 | OR | LOGICAL | 112,605,733 | OR, REPNZ OR, REPZ OR | 8, 80, 81, 83, 9, a, b, c, d | `or rax, rbx` | `4809d8` | Pass | 10,000 | All 10,000 executions agreed |
| 20 | MOVSXD | DATA | 107,204,963 | MOVSXD, REPNZ MOVSXD | 63 | `movsxd rax, ebx` | `4863c3` | Pass | 10,000 | All 10,000 executions agreed |
| 21 | JBE | CONTROL FLOW | 100,743,554 | JBE | 76, f86 | `jbe probe_end` | `7600` | Pass | 10,000 | All 10,000 executions agreed |
| 22 | JA | CONTROL FLOW | 100,701,018 | JA | 77, f87 | `ja probe_end` | `7700` | Pass | 10,000 | All 10,000 executions agreed |
| 23 | SETNE | BITWISE | 87,126,490 | SETNE | f95 | `setne al` | `0f95c0` | Pass | 10,000 | All 10,000 executions agreed |
| 24 | DEC | BINARY ARITHMETIC | 83,671,772 | DEC, REPNZ DEC | fe, ff | `dec rax` | `48ffc8` | Pass | 10,000 | All 10,000 executions agreed |
| 25 | XCHG | DATA | 64,462,611 | REPZ XCHG, XCHG | 86, 87, 90, 91, 92, 93, 94, 95, 96, 97 | `xchg rax, rbx` | `4893` | Pass | 10,000 | All 10,000 executions agreed |
| 26 | JLE | CONTROL FLOW | 59,856,464 | JLE | 7e, f8e | `jle probe_end` | `7e00` | Pass | 10,000 | All 10,000 executions agreed |
| 27 | JB | CONTROL FLOW | 58,498,822 | JB | 72, f82 | `jb probe_end` | `7200` | Pass | 10,000 | All 10,000 executions agreed |
| 28 | MULSD | SSE | 58,224,854 | MULSD | f59 | `mulsd xmm0, xmm1` | `f20f59c1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 29 | JAE | CONTROL FLOW | 54,770,464 | JAE | 73, f83 | `jae probe_end` | `7300` | Pass | 10,000 | All 10,000 executions agreed |
| 30 | ADDSD | SSE | 44,543,198 | ADDSD | f58 | `addsd xmm0, xmm1` | `f20f58c1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 31 | MOVAPD | SSE | 43,244,542 | MOVAPD | f28, f29 | `movapd xmm0, xmm1` | `660f28c1` | Pass | 10,000 | All 10,000 executions agreed |
| 32 | IMUL | BINARY ARITHMETIC | 38,845,870 | IMUL | 69, 6b, f7, faf | `imul rax, rbx` | `480fafc3` | Pass | 10,000 | All 10,000 executions agreed |
| 33 | JG | CONTROL FLOW | 37,072,506 | JG | 7f, f8f | `jg probe_end` | `7f00` | Pass | 10,000 | All 10,000 executions agreed |
| 34 | UCOMISD | SSE | 33,845,132 | UCOMISD | f2e | `ucomisd xmm0, xmm1` | `660f2ec1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 35 | JS | CONTROL FLOW | 31,225,626 | JS | 78, f88 | `js probe_end` | `7800` | Pass | 10,000 | All 10,000 executions agreed |
| 36 | PXOR | MMX | 31,085,484 | PXOR | fef | `pxor xmm0, xmm1` | `660fefc1` | Pass | 10,000 | All 10,000 executions agreed |
| 37 | ADC | BINARY ARITHMETIC | 29,953,466 | ADC, REPNZ ADC, REPZ ADC | 10, 11, 12, 13, 14, 15, 83 | `adc rax, rbx` | `4811d8` | Pass | 10,000 | All 10,000 executions agreed |
| 38 | SHL | SHIFT AND ROTATE | 28,804,734 | SHL | c0, c1, d0, d1, d2, d3 | `shl rax, cl` | `48d3e0` | Pass | 10,000 | All 10,000 executions agreed |
| 39 | MOVSX | DATA | 28,331,958 | MOVSX | fbe, fbf | `movsx eax, bl` | `0fbec3` | Pass | 10,000 | All 10,000 executions agreed |
| 40 | SETE | BITWISE | 28,250,824 | SETE | f94 | `sete al` | `0f94c0` | Pass | 10,000 | All 10,000 executions agreed |
| 41 | SUBSD | SSE | 26,304,452 | SUBSD | f5c | `subsd xmm0, xmm1` | `f20f5cc1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 42 | CMOVE | DATA | 25,266,068 | CMOVE | f44 | `cmove rax, rbx` | `480f44c3` | Pass | 10,000 | All 10,000 executions agreed |
| 43 | MOVAPS | SSE | 22,894,136 | MOVAPS | f28, f29 | `movaps xmm0, xmm1` | `0f28c1` | Pass | 10,000 | All 10,000 executions agreed |
| 44 | JL | CONTROL FLOW | 20,870,366 | JL | 7c, f8c | `jl probe_end` | `7c00` | Pass | 10,000 | All 10,000 executions agreed |
| 45 | CMOVNE | DATA | 20,175,206 | CMOVNE | f45 | `cmovne rax, rbx` | `480f45c3` | Pass | 10,000 | All 10,000 executions agreed |
| 46 | MOVSS | SSE | 19,360,518 | MOVSS | f10, f11 | `movss xmm0, xmm1` | `f30f10c1` | Pass | 10,000 | All 10,000 executions agreed |
| 47 | JGE | CONTROL FLOW | 18,102,372 | JGE | 7d, f8d | `jge probe_end` | `7d00` | Pass | 10,000 | All 10,000 executions agreed |
| 48 | CVTSI2SD | SSE | 17,232,180 | CVTSI2SD | f2a | `cvtsi2sd xmm0, rax` | `f2480f2ac0` | Unsupported | 0 | read [216, 224) escapes declared state |
| 49 | UD2 | MISC | 16,754,816 | UD2 | f0b | `ud2` | `0f0b` | Acquisition error | 0 | SimIRSBNoDecodeError: IR decoding error at 0x400000. You can hook this instruction with a python replacement using project.hook(0x400000, your_function, length=length_of_instruction). |
| 50 | DIV | BINARY ARITHMETIC | 15,849,876 | DIV | f6, f7 | `div rbx` | `48f7f3` | Unsupported | 0 | instruction at 0x400000 outcome identities are incomplete |
| 51 | CVTTSD2SI | SSE | 15,667,186 | CVTTSD2SI | f2c | `cvttsd2si rax, xmm0` | `f2480f2cc0` | Unsupported | 0 | unsupported Z3 sort: RoundingMode |
| 52 | CDQE | DATA | 15,149,112 | CDQE | 98 | `cdqe` | `4898` | Pass | 10,000 | All 10,000 executions agreed |
| 53 | MUL | BINARY ARITHMETIC | 11,857,626 | MUL | f6, f7 | `mul rbx` | `48f7e3` | Pass | 10,000 | All 10,000 executions agreed |
| 54 | SBB | BINARY ARITHMETIC | 11,226,558 | SBB | 18, 19, 1a, 1b, 1c, 1d | `sbb rax, rbx` | `4819d8` | Pass | 10,000 | All 10,000 executions agreed |
| 55 | JNS | CONTROL FLOW | 11,101,268 | JNS | 79, f89 | `jns probe_end` | `7900` | Pass | 10,000 | All 10,000 executions agreed |
| 56 | BT | BITWISE | 9,558,202 | BT | fa3, fba | `bt rax, rbx` | `480fa3d8` | Mismatch | 140 | rflags_AF: model=0x0, emulator=0x1 |
| 57 | XORPD | SSE | 8,198,568 | XORPD | f57 | `xorpd xmm0, xmm1` | `660f57c1` | Pass | 10,000 | All 10,000 executions agreed |
| 58 | INC | BINARY ARITHMETIC | 7,931,076 | INC, REPNZ INC, REPZ INC | fe, ff | `inc rax` | `48ffc0` | Pass | 10,000 | All 10,000 executions agreed |
| 59 | NEG | BINARY ARITHMETIC | 7,716,834 | NEG | f6, f7 | `neg rax` | `48f7d8` | Pass | 10,000 | All 10,000 executions agreed |
| 60 | DIVSD | SSE | 7,317,398 | DIVSD | f5e | `divsd xmm0, xmm1` | `f20f5ec1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 61 | JP | CONTROL FLOW | 6,303,824 | JP | 7a, f8a | `jp probe_end` | `7a00` | Pass | 10,000 | All 10,000 executions agreed |
| 62 | SHR | SHIFT AND ROTATE | 6,066,748 | SHR | c0, c1, d0, d1, d2, d3 | `shr rax, cl` | `48d3e8` | Pass | 10,000 | All 10,000 executions agreed |
| 63 | MULSS | SSE | 5,409,870 | MULSS | f59 | `mulss xmm0, xmm1` | `f30f59c1` | Unsupported | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 64 | CMPXCHG | DATA | 4,942,530 | CMPXCHG | fb0, fb1 | `cmpxchg rax, rbx` | `480fb1d8` | Pass | 10,000 | All 10,000 executions agreed |
| 65 | INT3 | CONTROL FLOW | 4,818,402 | INT3 | cc | `int3` | `cc` | Pass | 10,000 | All 10,000 executions agreed |
| 66 | CMOVLE | DATA | 4,790,260 | CMOVLE | f4e | `cmovle rax, rbx` | `480f4ec3` | Pass | 10,000 | All 10,000 executions agreed |
| 67 | CMOVB | DATA | 4,681,904 | CMOVB | f42 | `cmovb rax, rbx` | `480f42c3` | Pass | 10,000 | All 10,000 executions agreed |
| 68 | CMOVGE | DATA | 3,997,948 | CMOVGE | f4d | `cmovge rax, rbx` | `480f4dc3` | Pass | 10,000 | All 10,000 executions agreed |
| 69 | CMOVBE | DATA | 3,592,482 | CMOVBE | f46 | `cmovbe rax, rbx` | `480f46c3` | Pass | 10,000 | All 10,000 executions agreed |
| 70 | SETBE | BITWISE | 3,578,910 | SETBE | f96 | `setbe al` | `0f96c0` | Pass | 10,000 | All 10,000 executions agreed |
| 71 | CMOVAE | DATA | 3,493,862 | CMOVAE | f43 | `cmovae rax, rbx` | `480f43c3` | Pass | 10,000 | All 10,000 executions agreed |
| 72 | CLC | FLAG REGISTER INSN | 3,434,550 | CLC | f8 | `clc` | `f8` | Pass | 10,000 | All 10,000 executions agreed |
| 73 | CMOVG | DATA | 3,433,332 | CMOVG | f4f | `cmovg rax, rbx` | `480f4fc3` | Pass | 10,000 | All 10,000 executions agreed |
| 74 | ADDSS | SSE | 3,421,454 | ADDSS | f58 | `addss xmm0, xmm1` | `f30f58c1` | Unsupported | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 75 | STOS | STRING | 3,399,614 | REP STOS, STOS | aa, ab | `rep stosq` | `f348ab` | Unsupported | 0 | read [176, 184) escapes declared state |
| 76 | CMOVS | DATA | 3,292,830 | CMOVS | f48 | `cmovs rax, rbx` | `480f48c3` | Pass | 10,000 | All 10,000 executions agreed |
| 77 | XADD | DATA | 3,194,446 | XADD | fc0, fc1 | `xadd rax, rbx` | `480fc1d8` | Pass | 10,000 | All 10,000 executions agreed |
| 78 | MOVDQA | SSE | 3,122,802 | MOVDQA | f6f, f7f | `movdqa xmm0, xmm1` | `660f6fc1` | Pass | 10,000 | All 10,000 executions agreed |
| 79 | CMPS | STRING | 3,075,318 | CMPS, REPZ CMPS | a6, a7 | `repe cmpsq` | `f348a7` | Unsupported | 0 | read [176, 184) escapes declared state |
| 80 | SETG | BITWISE | 2,979,036 | SETG | f9f | `setg al` | `0f9fc0` | Pass | 10,000 | All 10,000 executions agreed |
| 81 | CMOVA | DATA | 2,891,936 | CMOVA | f47 | `cmova rax, rbx` | `480f47c3` | Pass | 10,000 | All 10,000 executions agreed |
| 82 | VADDSD | AVX | 2,771,229 | VADDSD | c4, c5 | `vaddsd xmm0, xmm1, xmm2` | `c5f358c2` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 83 | MOVDQU | SSE | 2,768,088 | MOVDQU | f6f, f7f | `movdqu xmm0, xmm1` | `f30f6fc1` | Pass | 10,000 | All 10,000 executions agreed |
| 84 | SETAE | BITWISE | 2,635,828 | SETAE | f93 | `setae al` | `0f93c0` | Pass | 10,000 | All 10,000 executions agreed |
| 85 | SETA | BITWISE | 2,630,946 | SETA | f97 | `seta al` | `0f97c0` | Pass | 10,000 | All 10,000 executions agreed |
| 86 | PCMPEQB | MMX | 2,494,026 | PCMPEQB | f74 | `pcmpeqb xmm0, xmm1` | `660f74c1` | Pass | 10,000 | All 10,000 executions agreed |
| 87 | PMOVMSKB | SSE | 2,447,296 | PMOVMSKB | fd7 | `pmovmskb eax, xmm0` | `660fd7c0` | Pass | 10,000 | All 10,000 executions agreed |
| 88 | CMOVL | DATA | 2,422,020 | CMOVL | f4c | `cmovl rax, rbx` | `480f4cc3` | Pass | 10,000 | All 10,000 executions agreed |
| 89 | MOVUPS | SSE | 2,302,032 | MOVUPS | f10, f11 | `movups xmm0, xmm1` | `0f10c1` | Pass | 10,000 | All 10,000 executions agreed |
| 90 | BSR | BITWISE | 2,258,980 | BSR | fbd | `bsr rax, rbx` | `480fbdc3` | Mismatch | 3,130 | rflags_PF: model=0x0, emulator=0x1 |
| 91 | MAXSD | SSE | 2,247,994 | MAXSD | f5f | `maxsd xmm0, xmm1` | `f20f5fc1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 92 | CMOVNS | DATA | 2,205,830 | CMOVNS | f49 | `cmovns rax, rbx` | `480f49c3` | Pass | 10,000 | All 10,000 executions agreed |
| 93 | MULPD | SSE | 2,135,924 | MULPD | f59 | `mulpd xmm0, xmm1` | `660f59c1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 94 | SETB | BITWISE | 1,960,876 | SETB | f92 | `setb al` | `0f92c0` | Pass | 10,000 | All 10,000 executions agreed |
| 95 | UCOMISS | SSE | 1,940,968 | UCOMISS | f2e | `ucomiss xmm0, xmm1` | `0f2ec1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 96 | CDQ | DATA | 1,845,960 | CDQ | 99 | `cdq` | `99` | Pass | 10,000 | All 10,000 executions agreed |
| 97 | SUBSS | SSE | 1,772,600 | SUBSS | f5c | `subss xmm0, xmm1` | `f30f5cc1` | Unsupported | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 98 | BSWAP | DATA | 1,703,036 | BSWAP | fc8, fc9, fca, fcb, fcc, fcd, fce, fcf | `bswap rax` | `480fc8` | Pass | 10,000 | All 10,000 executions agreed |
| 99 | LEAVE | CONTROL FLOW | 1,693,254 | LEAVE | c9 | `leave` | `c9` | Mismatch | 3,351 | emulator UcError: Invalid memory mapping (UC_ERR_MAP) |
| 100 | CVTSS2SD | SSE | 1,677,130 | CVTSS2SD | f5a | `cvtss2sd xmm0, xmm1` | `f30f5ac1` | Unsupported | 0 | unsupported Z3 sort: FPSort(11, 53) |

## Cached model-artifact structure

| Structural result | Value | Interpretation |
|---|---:|---|
| Typed QF_ABV instruction models | 81 | Exactly the 78 passes plus the 3 concrete mismatches had executable typed models. |
| Unavailable-model artifacts | 19 | Exactly the 18 unsupported cases plus UD2's acquisition error were represented by structured unavailable-model JSON. |
| Declarations per typed model | 40 | 16 GPRs + 16 YMM registers + RIP + six selected flags + memory. |
| Simultaneous assignments per edge | 40 | Every typed edge assigns the complete declared output state, including identity assignments. |
| Non-identity assignments per edge | 1–9 | The representative instructions actually change between one and nine declared outputs in their serialized edges. |
| One-edge typed models | 68 | Straight-line, merged conditional-move, symbolic-target, or error-target behavior. |
| Two-edge typed models | 13 | The conditional-jump representatives. |
| Constant-address target models | 79 | Includes all two-edge Jcc models. |
| Symbolic-target models | 1 | RET, whose target is loaded from the modeled stack. |
| Error-target models | 1 | INT3, whose modeled error target agreed with Unicorn's CPU exception for 10,000 executions. |
| Distinct typed model CAS blobs | 71 | Some representatives serialize identically and deduplicate by content hash. |
| Distinct unavailable-model CAS blobs | 7 | Equal structured failure reasons deduplicate, notably the floating-point sort boundaries. |
| Logical serialized typed-model bytes | 13,436,234 | Sum across representatives; repeated content-addressed blobs are counted once per representative here. |
| Serialized AST-node occurrences | 18,779 | Count of JSON expression objects containing `op`, including repeated subexpressions; this is not a unique DAG-node count. |

### Passing modes

| Passing mode | Families | Evidence supplied by this run |
|---|---:|---|
| Single-edge, constant-address continuation | 63 | One typed edge was enabled and its complete scalar/vector/flag/memory post-state agreed for 10,000 executions. |
| Two-edge conditional jump | 13 | Exactly one of two guards was enabled and the complete post-state agreed for 10,000 executions, subject to the equal-target caveat below. |
| Symbolic target | 1 | RET's stack-loaded target and complete post-state agreed for 10,000 executions. |
| Error target | 1 | INT3's modeled terminal error agreed with Unicorn's CPU exception for 10,000 executions. |
| **Total** | **78** | **780,000 completed model-versus-Unicorn executions.** |

### Control-flow observability caveat

| Affected probes | Observed model shape | What the 10k run establishes | What it does not strongly establish | Better follow-up probe |
|---|---|---|---|---|
| 5 JE; 10 JNE; 21 JBE; 22 JA; 26 JLE; 27 JB; 29 JAE; 33 JG; 35 JS; 44 JL; 47 JGE; 55 JNS; 61 JP | Two guarded edges apiece; both edges target decimal `4194306` (`0x400002`) because the short relative displacement is zero. | For each generated input, exactly one model guard is satisfiable; the chosen complete post-state agrees with Unicorn. | Taken and fall-through PC are the same, so an incorrect condition that still partitions inputs may remain observationally invisible at RIP. | Put `probe_end` beyond at least one intervening instruction so taken and fall-through destinations differ, then rerun on Linux/REAPI. |

### Largest available models

| Rank | Family | Serialized bytes | Serialized AST-node occurrences | Edges | Non-identity assignments/edge |
|---:|---|---:|---:|---:|---:|
| 32 | IMUL | 6,262,496 | 3,959 | 1 | 8 |
| 18 | SAR | 1,037,443 | 1,901 | 1 | 8 |
| 62 | SHR | 1,037,443 | 1,901 | 1 | 8 |
| 38 | SHL | 1,025,148 | 1,877 | 1 | 8 |
| 16 | ROL | 951,412 | 1,710 | 1 | 8 |
| 90 | BSR | 565,190 | 440 | 1 | 8 |
| 26 | JLE | 105,972 | 249 | 2 | 1 |
| 33 | JG | 105,972 | 249 | 2 | 1 |

### Complete model-artifact ledger

Target entries are grouped as `kind-or-address:edge-count`. “Assignments/edge” counts the complete simultaneous-update vector; “non-identity/edge” removes direct `output = input` assignments. AST nodes count serialized occurrences, not hash-consed unique expressions.

| Rank | Family | Schema | Exact CAS SHA-256 | Bytes | Declarations | Edges | Targets | Assignments/edge | Non-identity/edge | AST nodes | Availability/result |
|---:|---|---|---|---:|---:|---:|---|---:|---:|---:|---|
| 1 | MOV | `ixyk.qf_abv.instruction.v1` | `63e580e4f05d2bba57bf73a017052342c7374e32b6d93919f67f8c354cddc4ea` | 13,631 | 40 | 1 | `address@4194307:1` | 40 | 2 | 42 | Available typed QF_ABV model |
| 2 | ADD | `ixyk.qf_abv.instruction.v1` | `14b80389a6ff2850eb70ba978393fab874ff3686fa920f6a95f65cf1824b6f3c` | 41,787 | 40 | 1 | `address@4194307:1` | 40 | 8 | 128 | Available typed QF_ABV model |
| 3 | CALL | `ixyk.qf_abv.instruction.v1` | `4cd42ad1fca1ffc13d0b36bd26c68967040354912078ad149e8e4456a154fcdc` | 37,865 | 40 | 1 | `address@4194309:1` | 40 | 3 | 108 | Available typed QF_ABV model |
| 4 | LEA | `ixyk.qf_abv.instruction.v1` | `44857fb64781b839e9a366efee84c04d4d80d2b9ee32385742df00ff06f12869` | 15,339 | 40 | 1 | `address@4194309:1` | 40 | 2 | 49 | Available typed QF_ABV model |
| 5 | JE | `ixyk.qf_abv.instruction.v1` | `af6a0c084fa4299f76c014a4039875a3d6ddc59b1a0ffb73d73eafa145d690c0` | 48,004 | 40 | 2 | `address@4194306:2` | 40 | 1 | 141 | Available typed QF_ABV model |
| 6 | TEST | `ixyk.qf_abv.instruction.v1` | `29660033861a04227b2f9cda37d7cd76b8dc186dfb89c2a88b2ecac654f925d6` | 49,115 | 40 | 1 | `address@4194307:1` | 40 | 7 | 131 | Available typed QF_ABV model |
| 7 | JMP | `ixyk.qf_abv.instruction.v1` | `9ed78ee0a75fb4a6cd4f3910260fbf70bfd5525fef0d0f7d1af7f0d50ea39bfc` | 13,631 | 40 | 1 | `address@4194306:1` | 40 | 1 | 42 | Available typed QF_ABV model |
| 8 | NOP | `ixyk.qf_abv.instruction.v1` | `e1c4cd13f4f695a935bcf8172ddeaa84de7e9f08d4e7ce361b28e3b3491ed81e` | 13,631 | 40 | 1 | `address@4194305:1` | 40 | 1 | 42 | Available typed QF_ABV model |
| 9 | CMP | `ixyk.qf_abv.instruction.v1` | `30600466f5ab3677755bfa7b7d056176f4bc7751646d761277ab90f402e4b583` | 47,504 | 40 | 1 | `address@4194307:1` | 40 | 7 | 140 | Available typed QF_ABV model |
| 10 | JNE | `ixyk.qf_abv.instruction.v1` | `af6a0c084fa4299f76c014a4039875a3d6ddc59b1a0ffb73d73eafa145d690c0` | 48,004 | 40 | 2 | `address@4194306:2` | 40 | 1 | 141 | Available typed QF_ABV model |
| 11 | XOR | `ixyk.qf_abv.instruction.v1` | `16d2ef9f9c45525966aefafd6ff2a90c097dd5e6060f731aceec49e020e31599` | 41,344 | 40 | 1 | `address@4194307:1` | 40 | 8 | 103 | Available typed QF_ABV model |
| 12 | RET | `ixyk.qf_abv.instruction.v1` | `6793b78f007c3194406e5ee247c88a160d5b46b516559df8b1234f06ab8676bd` | 61,732 | 40 | 1 | `symbolic:1` | 40 | 2 | 183 | Available typed QF_ABV model |
| 13 | AND | `ixyk.qf_abv.instruction.v1` | `2338f6aa000d39d26c380c7a0c997746a6243ae523c710b066b2fa6620eef145` | 50,369 | 40 | 1 | `address@4194307:1` | 40 | 8 | 136 | Available typed QF_ABV model |
| 14 | MOVZX | `ixyk.qf_abv.instruction.v1` | `b1f219db07f608372d773df32807d93d482e871cca789758e6fa1ddae2c39252` | 14,338 | 40 | 1 | `address@4194307:1` | 40 | 2 | 45 | Available typed QF_ABV model |
| 15 | MOVSD | `ixyk.qf_abv.instruction.v1` | `282bd5584972c1a91269e2ce8231591a48c9ff1548e5f75e802649b0455ba2de` | 14,645 | 40 | 1 | `address@4194308:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 16 | ROL | `ixyk.qf_abv.instruction.v1` | `6a2bdbd281aec8f807c6e94edd346de6d5ef373bc1be690f03808ccf6b51b872` | 951,412 | 40 | 1 | `address@4194307:1` | 40 | 8 | 1,710 | Available typed QF_ABV model |
| 17 | SUB | `ixyk.qf_abv.instruction.v1` | `67cb974ca51e4619341a2b8b839f47902e103b7cdca1da25eb0eecb198e3d995` | 48,411 | 40 | 1 | `address@4194307:1` | 40 | 8 | 144 | Available typed QF_ABV model |
| 18 | SAR | `ixyk.qf_abv.instruction.v1` | `e97fa43dac659a6dab724cd8c6fc6f262d3f76bd981d199a4f66513e87dc5e1b` | 1,037,443 | 40 | 1 | `address@4194307:1` | 40 | 8 | 1,901 | Available typed QF_ABV model |
| 19 | OR | `ixyk.qf_abv.instruction.v1` | `1b6962f2b3723d295caef84705bb72280701fc409ab39321bc3ff900bc3dacb9` | 35,413 | 40 | 1 | `address@4194307:1` | 40 | 8 | 103 | Available typed QF_ABV model |
| 20 | MOVSXD | `ixyk.qf_abv.instruction.v1` | `59b97ca64956de83c32ecdf279bb76f5f4b487ae8ad036a80a893427f9d75fef` | 93,526 | 40 | 1 | `address@4194307:1` | 40 | 2 | 139 | Available typed QF_ABV model |
| 21 | JBE | `ixyk.qf_abv.instruction.v1` | `4ed0a5666c63489117561c52d646db7fa0bd24db81ebca8cc71f6f47ea6a581b` | 50,754 | 40 | 2 | `address@4194306:2` | 40 | 1 | 145 | Available typed QF_ABV model |
| 22 | JA | `ixyk.qf_abv.instruction.v1` | `4ed0a5666c63489117561c52d646db7fa0bd24db81ebca8cc71f6f47ea6a581b` | 50,754 | 40 | 2 | `address@4194306:2` | 40 | 1 | 145 | Available typed QF_ABV model |
| 23 | SETNE | `ixyk.qf_abv.instruction.v1` | `35fd0792f9160de8617664f0b3eb5a238c4afce4b5916196122705f8a2c809d7` | 15,112 | 40 | 1 | `address@4194307:1` | 40 | 2 | 48 | Available typed QF_ABV model |
| 24 | DEC | `ixyk.qf_abv.instruction.v1` | `b441fdae4f17c1b747f2da479077ca93da895f109c8a86aebfae07f86bb7e334` | 33,631 | 40 | 1 | `address@4194307:1` | 40 | 7 | 103 | Available typed QF_ABV model |
| 25 | XCHG | `ixyk.qf_abv.instruction.v1` | `3fe42a652c595fd5ca3677cfb67e67e64222562f312c66f52ea6d9a31be5ecc0` | 13,631 | 40 | 1 | `address@4194306:1` | 40 | 3 | 42 | Available typed QF_ABV model |
| 26 | JLE | `ixyk.qf_abv.instruction.v1` | `7c181915109965c3b39f3e419c6cbc529a9a33b7f17f0c94c967cc0207e6684d` | 105,972 | 40 | 2 | `address@4194306:2` | 40 | 1 | 249 | Available typed QF_ABV model |
| 27 | JB | `ixyk.qf_abv.instruction.v1` | `e7aef8db40ff65444abed215905ea1698d32b79f5dc730637194a1b707dd8511` | 24,420 | 40 | 2 | `address@4194306:2` | 40 | 1 | 91 | Available typed QF_ABV model |
| 28 | MULSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 29 | JAE | `ixyk.qf_abv.instruction.v1` | `e7aef8db40ff65444abed215905ea1698d32b79f5dc730637194a1b707dd8511` | 24,420 | 40 | 2 | `address@4194306:2` | 40 | 1 | 91 | Available typed QF_ABV model |
| 30 | ADDSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 31 | MOVAPD | `ixyk.qf_abv.instruction.v1` | `11626d9ec5a8a728a363bdbb7a6d5aea955e015d2d527bd0fe6506215077b316` | 14,648 | 40 | 1 | `address@4194308:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 32 | IMUL | `ixyk.qf_abv.instruction.v1` | `c7db0b7748affac99ac39845b54e19d44374123bda1ed72ea5280f640ab138ba` | 6,262,496 | 40 | 1 | `address@4194308:1` | 40 | 8 | 3,959 | Available typed QF_ABV model |
| 33 | JG | `ixyk.qf_abv.instruction.v1` | `7c181915109965c3b39f3e419c6cbc529a9a33b7f17f0c94c967cc0207e6684d` | 105,972 | 40 | 2 | `address@4194306:2` | 40 | 1 | 249 | Available typed QF_ABV model |
| 34 | UCOMISD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 35 | JS | `ixyk.qf_abv.instruction.v1` | `c5e2f8669f83b1f37d3acf8770dc24d40afe5272524693d0a67b4e92149b416d` | 48,004 | 40 | 2 | `address@4194306:2` | 40 | 1 | 141 | Available typed QF_ABV model |
| 36 | PXOR | `ixyk.qf_abv.instruction.v1` | `7c3972ac56bd48c6bc36ce021c6cb396a56e0fa437377de648cc1e7be5a6615e` | 15,518 | 40 | 1 | `address@4194308:1` | 40 | 2 | 49 | Available typed QF_ABV model |
| 37 | ADC | `ixyk.qf_abv.instruction.v1` | `6a7001b4b739a9b4a74e3ead5058dbf8f6bc549de52ac32f57f24efb1accb044` | 69,457 | 40 | 1 | `address@4194307:1` | 40 | 8 | 204 | Available typed QF_ABV model |
| 38 | SHL | `ixyk.qf_abv.instruction.v1` | `65db4c742d6c2390aae0036c460e1c822255c99edeff7ad80672026e16f9c5a3` | 1,025,148 | 40 | 1 | `address@4194307:1` | 40 | 8 | 1,877 | Available typed QF_ABV model |
| 39 | MOVSX | `ixyk.qf_abv.instruction.v1` | `4d3fadb426bfdfef408fe13b440c605ba65cb297eefe44a0683cd80eacf31925` | 64,906 | 40 | 1 | `address@4194307:1` | 40 | 2 | 117 | Available typed QF_ABV model |
| 40 | SETE | `ixyk.qf_abv.instruction.v1` | `93aa2b9f7c0ca6a0fd8899cb1ff64b269efb805e96a185ff330b61e6848fd176` | 14,866 | 40 | 1 | `address@4194307:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 41 | SUBSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 42 | CMOVE | `ixyk.qf_abv.instruction.v1` | `6627c4830459bcca762024a1725afc54adebf4d60c28c4f853604c3062b9dc3f` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 43 | MOVAPS | `ixyk.qf_abv.instruction.v1` | `c67945dc0605fb37bd97fe80cf8504f4d0208fa1391984544697481882530b02` | 14,648 | 40 | 1 | `address@4194307:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 44 | JL | `ixyk.qf_abv.instruction.v1` | `bb13683dc716e826c5f2c8e5c9e2c8d96cacea3e776b5bd125d99d7bf8cb8621` | 76,062 | 40 | 2 | `address@4194306:2` | 40 | 1 | 195 | Available typed QF_ABV model |
| 45 | CMOVNE | `ixyk.qf_abv.instruction.v1` | `7dcf1278d5935ace824737fb268c228e4f6db1a55ef5623e3127826541fa0384` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 46 | MOVSS | `ixyk.qf_abv.instruction.v1` | `eddc7e9ed620c507aca9c7dd0b0893886d31798c1552d53a78d534af332ca7ab` | 14,645 | 40 | 1 | `address@4194308:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 47 | JGE | `ixyk.qf_abv.instruction.v1` | `bb13683dc716e826c5f2c8e5c9e2c8d96cacea3e776b5bd125d99d7bf8cb8621` | 76,062 | 40 | 2 | `address@4194306:2` | 40 | 1 | 195 | Available typed QF_ABV model |
| 48 | CVTSI2SD | `ixyk.unavailable_instruction_model.v1` | `8a76840d83b69bbea900e740511c16e0636ec9569e9d5fd6d9b169e12bbce8f2` | 136 | — | — | — | — | — | 0 | read [216, 224) escapes declared state |
| 49 | UD2 | `ixyk.unavailable_instruction_model.v1` | `dcd9c528c7c84e8c3bbea8f88c1a7bc97a6e39f98127deb811a44eb73bd4f5b1` | 287 | — | — | — | — | — | 0 | SimIRSBNoDecodeError: IR decoding error at 0x400000. You can hook this instruction with a python replacement using project.hook(0x400000, your_function, length=length_of_instruction). |
| 50 | DIV | `ixyk.unavailable_instruction_model.v1` | `2396f47e1f6fa710405d9d9f05bdb050735fa45a1f847581dc1b9f4833fd12d8` | 155 | — | — | — | — | — | 0 | instruction at 0x400000 outcome identities are incomplete |
| 51 | CVTTSD2SI | `ixyk.unavailable_instruction_model.v1` | `4ee6524fcf5316f1e4b94c264c17eec6a145fd719f46859bc105a42b07141eeb` | 131 | — | — | — | — | — | 0 | unsupported Z3 sort: RoundingMode |
| 52 | CDQE | `ixyk.qf_abv.instruction.v1` | `d52410b39750ce6c904916f02e3d6f3bc28259f643891f36791f02fb9022dbb0` | 93,526 | 40 | 1 | `address@4194306:1` | 40 | 2 | 139 | Available typed QF_ABV model |
| 53 | MUL | `ixyk.qf_abv.instruction.v1` | `5ca19b3fa479a2e5df483ab27319ca2688b1a7fb06a50a21365586548590a20d` | 40,594 | 40 | 1 | `address@4194307:1` | 40 | 9 | 126 | Available typed QF_ABV model |
| 54 | SBB | `ixyk.qf_abv.instruction.v1` | `a2c97158b9b169f6b7649cc806bdaae3605cde8e21fd10b3cba0bad8acc29739` | 81,235 | 40 | 1 | `address@4194307:1` | 40 | 8 | 230 | Available typed QF_ABV model |
| 55 | JNS | `ixyk.qf_abv.instruction.v1` | `c5e2f8669f83b1f37d3acf8770dc24d40afe5272524693d0a67b4e92149b416d` | 48,004 | 40 | 2 | `address@4194306:2` | 40 | 1 | 141 | Available typed QF_ABV model |
| 56 | BT | `ixyk.qf_abv.instruction.v1` | `3af7f24887d9d059e9ca180a76d6fe8ab6d4b9a43f84fa42af96322ffe54a739` | 53,294 | 40 | 1 | `address@4194308:1` | 40 | 7 | 126 | Available typed QF_ABV model |
| 57 | XORPD | `ixyk.qf_abv.instruction.v1` | `7c3972ac56bd48c6bc36ce021c6cb396a56e0fa437377de648cc1e7be5a6615e` | 15,518 | 40 | 1 | `address@4194308:1` | 40 | 2 | 49 | Available typed QF_ABV model |
| 58 | INC | `ixyk.qf_abv.instruction.v1` | `d76d6af39d4d4a36e8cd98ab1def82080381dc29ee152734818a289a842c425b` | 33,460 | 40 | 1 | `address@4194307:1` | 40 | 7 | 103 | Available typed QF_ABV model |
| 59 | NEG | `ixyk.qf_abv.instruction.v1` | `ac363ee97ee7dad6bbc7fcc7cbe59ee3dbaa40f4cd9c7d7500cc7bf3ded16d84` | 35,337 | 40 | 1 | `address@4194307:1` | 40 | 8 | 110 | Available typed QF_ABV model |
| 60 | DIVSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 61 | JP | `ixyk.qf_abv.instruction.v1` | `a4b9f2cba95553f34e14535e2a42a003bbfc77985e96fef2e4cb7bdf758e32c7` | 48,004 | 40 | 2 | `address@4194306:2` | 40 | 1 | 141 | Available typed QF_ABV model |
| 62 | SHR | `ixyk.qf_abv.instruction.v1` | `38f43cd490fb9f38e7c0a7e630741a06d1324c0964e968df4efd16a4cc74420c` | 1,037,443 | 40 | 1 | `address@4194307:1` | 40 | 8 | 1,901 | Available typed QF_ABV model |
| 63 | MULSS | `ixyk.unavailable_instruction_model.v1` | `675d5d83a4f130adddcc5a5bcecdafe25d6ca385c9a7b8e50bbdd7b9b44ecf9e` | 132 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 64 | CMPXCHG | `ixyk.qf_abv.instruction.v1` | `90c2cff258ddf74397449a1bca303f2421d9b30adeaf60bef06741b4419b210c` | 13,595 | 40 | 1 | `address@4194308:1` | 40 | 8 | 42 | Available typed QF_ABV model |
| 65 | INT3 | `ixyk.qf_abv.instruction.v1` | `13d4ca091322dc7a7410ccd915245fbaf385d86cd5e478f7f6c8f0b04403fdcb` | 13,603 | 40 | 1 | `error:1` | 40 | 1 | 42 | Available typed QF_ABV model |
| 66 | CMOVLE | `ixyk.qf_abv.instruction.v1` | `e676815edf7e23c8c57e09db933c2965dc6edaea7f0055de5b4e7e9f48880b7e` | 17,307 | 40 | 1 | `address@4194308:1` | 40 | 2 | 56 | Available typed QF_ABV model |
| 67 | CMOVB | `ixyk.qf_abv.instruction.v1` | `b5dcc0eadfda3398ca1d6959bc8d4442cecc24e9acc4a223f031d1d0c38de285` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 68 | CMOVGE | `ixyk.qf_abv.instruction.v1` | `b6918d9c1b1354449f685928ef74400e35c33ed33dda8742747ae851e46bcbb5` | 15,708 | 40 | 1 | `address@4194308:1` | 40 | 2 | 51 | Available typed QF_ABV model |
| 69 | CMOVBE | `ixyk.qf_abv.instruction.v1` | `bac953621dda298cc423c14e5d1c872dd0b056a8c64882c4ccb2e923612c4462` | 15,713 | 40 | 1 | `address@4194308:1` | 40 | 2 | 51 | Available typed QF_ABV model |
| 70 | SETBE | `ixyk.qf_abv.instruction.v1` | `402d8d2cb0c138b32f2ea14b694ee4cb3f113a91025bd4e5568c8a6c721fd425` | 15,347 | 40 | 1 | `address@4194307:1` | 40 | 2 | 49 | Available typed QF_ABV model |
| 71 | CMOVAE | `ixyk.qf_abv.instruction.v1` | `6408c0d8b88131f618178e55db4053addb30cdfa7d6e4e287db3cb93a1998050` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 72 | CLC | `ixyk.qf_abv.instruction.v1` | `bb6d13f770ed967b8e717077fda58d819f47b94d2c1a9ff86e4062a82d272a8a` | 13,625 | 40 | 1 | `address@4194305:1` | 40 | 2 | 42 | Available typed QF_ABV model |
| 73 | CMOVG | `ixyk.qf_abv.instruction.v1` | `9c1f8b3ef999d90395ca08b0715df745f4520df0772521092b89b5da39ecfec4` | 17,307 | 40 | 1 | `address@4194308:1` | 40 | 2 | 56 | Available typed QF_ABV model |
| 74 | ADDSS | `ixyk.unavailable_instruction_model.v1` | `675d5d83a4f130adddcc5a5bcecdafe25d6ca385c9a7b8e50bbdd7b9b44ecf9e` | 132 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 75 | STOS | `ixyk.unavailable_instruction_model.v1` | `31b82c2121271df8a4e4752050eaadd98b87c3da06552ea2a72dd46386bd39c0` | 136 | — | — | — | — | — | 0 | read [176, 184) escapes declared state |
| 76 | CMOVS | `ixyk.qf_abv.instruction.v1` | `cb9a6b4bcd217b3dd6b64d35f8acff136833cc692a295893ab6d53216089462d` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 77 | XADD | `ixyk.qf_abv.instruction.v1` | `08e757bada29b4581056858bdb30fdc2146afc8b4c0c8572e9cf4af5d9598fb6` | 41,787 | 40 | 1 | `address@4194308:1` | 40 | 9 | 128 | Available typed QF_ABV model |
| 78 | MOVDQA | `ixyk.qf_abv.instruction.v1` | `11626d9ec5a8a728a363bdbb7a6d5aea955e015d2d527bd0fe6506215077b316` | 14,648 | 40 | 1 | `address@4194308:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 79 | CMPS | `ixyk.unavailable_instruction_model.v1` | `31b82c2121271df8a4e4752050eaadd98b87c3da06552ea2a72dd46386bd39c0` | 136 | — | — | — | — | — | 0 | read [176, 184) escapes declared state |
| 80 | SETG | `ixyk.qf_abv.instruction.v1` | `b6bf169541d5676566cd7fe79a562c1aedad9792b7531262281a63e68638eb3b` | 16,279 | 40 | 1 | `address@4194307:1` | 40 | 2 | 52 | Available typed QF_ABV model |
| 81 | CMOVA | `ixyk.qf_abv.instruction.v1` | `dfdb548b054803e691fd39bdded3a388ae8e4295915a53faffb4ec0ec55f43ec` | 15,713 | 40 | 1 | `address@4194308:1` | 40 | 2 | 51 | Available typed QF_ABV model |
| 82 | VADDSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 83 | MOVDQU | `ixyk.qf_abv.instruction.v1` | `11626d9ec5a8a728a363bdbb7a6d5aea955e015d2d527bd0fe6506215077b316` | 14,648 | 40 | 1 | `address@4194308:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 84 | SETAE | `ixyk.qf_abv.instruction.v1` | `9c7b3792a71814c32144686bd525f32ae39cf7e39ad478d6f4be956ad007c642` | 15,112 | 40 | 1 | `address@4194307:1` | 40 | 2 | 48 | Available typed QF_ABV model |
| 85 | SETA | `ixyk.qf_abv.instruction.v1` | `e16d1e9b58a22b69375e4cfeea1a05dc79f2073e14101b8c33b3cc6f20bd0889` | 15,661 | 40 | 1 | `address@4194307:1` | 40 | 2 | 50 | Available typed QF_ABV model |
| 86 | PCMPEQB | `ixyk.qf_abv.instruction.v1` | `cd1ff757d3187dd384533994b1e3a75b2ca7fd8997396f99af60d5425ac708a0` | 91,450 | 40 | 1 | `address@4194308:1` | 40 | 2 | 187 | Available typed QF_ABV model |
| 87 | PMOVMSKB | `ixyk.qf_abv.instruction.v1` | `aea471bb0df263c75724aaaae812828661cf9aa9f9faac4fc27360c6bd583e1d` | 38,453 | 40 | 1 | `address@4194308:1` | 40 | 2 | 90 | Available typed QF_ABV model |
| 88 | CMOVL | `ixyk.qf_abv.instruction.v1` | `70a2c2963d22abac84a8432ea3d499278208395f8d632679912e1075ba68d11e` | 15,708 | 40 | 1 | `address@4194308:1` | 40 | 2 | 51 | Available typed QF_ABV model |
| 89 | MOVUPS | `ixyk.qf_abv.instruction.v1` | `c67945dc0605fb37bd97fe80cf8504f4d0208fa1391984544697481882530b02` | 14,648 | 40 | 1 | `address@4194307:1` | 40 | 2 | 46 | Available typed QF_ABV model |
| 90 | BSR | `ixyk.qf_abv.instruction.v1` | `96b88269f439b99a54a7b74114993c78baa10892c86023d55b079b40367bc735` | 565,190 | 40 | 1 | `address@4194308:1` | 40 | 8 | 440 | Available typed QF_ABV model |
| 91 | MAXSD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 92 | CMOVNS | `ixyk.qf_abv.instruction.v1` | `5996707dee98febe3ac2601e90a60af0108e533dfb87585cde77d8f68d078652` | 14,686 | 40 | 1 | `address@4194308:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 93 | MULPD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 94 | SETB | `ixyk.qf_abv.instruction.v1` | `d97fc09ae2627ff21c1512f4c630e0b8d83078513b803d3f2692b8e3a0540429` | 14,866 | 40 | 1 | `address@4194307:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 95 | UCOMISS | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |
| 96 | CDQ | `ixyk.qf_abv.instruction.v1` | `c3b2c2aaceca93a2f9e08fce71d04cb7ae80adab07ca9e246c7be06fb573b119` | 14,864 | 40 | 1 | `address@4194305:1` | 40 | 2 | 47 | Available typed QF_ABV model |
| 97 | SUBSS | `ixyk.unavailable_instruction_model.v1` | `675d5d83a4f130adddcc5a5bcecdafe25d6ca385c9a7b8e50bbdd7b9b44ecf9e` | 132 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(8, 24) |
| 98 | BSWAP | `ixyk.qf_abv.instruction.v1` | `3519e067d1023f6412696a873b48d9d39adfba9724871d88f7c57f8cf1a34637` | 21,506 | 40 | 1 | `address@4194307:1` | 40 | 2 | 64 | Available typed QF_ABV model |
| 99 | LEAVE | `ixyk.qf_abv.instruction.v1` | `c1bb223d944a8022b09a14359fa64cdee8859c99a00c59c838fe8e346c6432fe` | 30,695 | 40 | 1 | `address@4194305:1` | 40 | 3 | 90 | Available typed QF_ABV model |
| 100 | CVTSS2SD | `ixyk.unavailable_instruction_model.v1` | `21637add45018ed7bad9c4bd5efe899a601d8ff8c167096b49523385edcde8fb` | 133 | — | — | — | — | — | 0 | unsupported Z3 sort: FPSort(11, 53) |


## Open verification work

| Question | Why it matters | Evidence needed | Destination after resolution |
|---|---|---|---|
| How should defined-output masks be represented for BT, BSR, and other partial contracts? | Intel's instruction reference establishes that both reported scalar differences involve architecturally undefined outputs; BSR's zero-source destination is also undefined. | Design and test an instruction/path-sensitive comparison mask, then rerun the Linux/REAPI probes. | Oracle contract, tests, and README validation limitations. |
| What concrete-memory domain should LEAVE and other derived-address instructions use? | The minimized LEAVE witness is canonical high-half, but the model admits its address while Unicorn cannot map the terminal page; this is a confirmed model/oracle domain mismatch. | Specify the intended address/mapping/exception contract and rerun focused Linux witnesses around both canonical ranges and page boundaries. | Harness contract, generators, tests, and validation docs. |
| Which DIV successor/outcome ID is absent or duplicated? | The source check is now known: successor IDs must be the dense sequence `0..N-1`, and DIV fails it before model serialization. The acquisition artifact preserves only the structured error, not the discarded successor set. | Add focused extraction diagnostics or inspect a Linux acquisition under the preserved source snapshot. | Extractor follow-up and limitations table. |
| What exact hidden state causes the three closure escapes? | Establishes whether the declared AMD64 state should expand or the lifter artifact should be normalized. | Inspect the offsets against VEX's AMD64 guest-state layout and each acquisition artifact. | State-schema design notes. |
| How should model-complexity evidence be summarized durably? | The scratch ledger now records every artifact's schema, digest, byte size, edge/target shape, assignments, and serialized AST-node count. | Decide which aggregate fields belong in the README and whether the complete table deserves a durable report. | README plus a durable validation report if useful. |
