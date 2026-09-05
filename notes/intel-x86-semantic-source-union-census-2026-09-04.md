# Intel x86 semantic-source union census

Date: 2026-09-04

## Question and conclusion

Can ixyk obtain candidate semantics for essentially the whole Intel x86 ISA by using direct Angr acquisition where it works and otherwise transporting executable definitions from open emulators?

Yes, to a degree that changes the engineering problem. Against the current Intel subset of XED, the source-backed estimate is approximately 97.7% of ICLASS families, with a conservative range of 96.2–97.7% depending on whether closely corresponding generic AVX10/FP8 handlers are credited. Against the historical user-level instruction surfaces targeted by Strata (Haswell, 2016) and libLISA (tested CPUs, 2024), the union appears effectively complete at the instruction-family level.

The remaining present-day shortfall is primarily denominator growth: XED now includes very recent ACE, Key Locker, APX, AVX10, FP8/BF8, security, trace, and system-effect instructions that did not belong to those earlier projects' target surfaces. This is not evidence that the core technique covers only an easy historical subset.

This is a semantic-source census, not a proof of model fidelity. An executable implementation can seed extraction, fuzzing, synthesis, and human correction even when it is not yet suitable as a trusted final specification.

## Denominator and measured bounds

The census parsed all XED instruction-definition blocks under `datafiles`, excluding the `amd`, `via`, and test subtrees:

- 8,970 Intel definition blocks;
- 1,846 distinct Intel ICLASS names;
- 1,638 ICLASS names, or 88.73%, mechanically matched by exact mnemonic/name evidence across the initial local source union;
- approximately 164 further ICLASSes accounted for by shared handlers, systematic XED aliases, generic condition dispatch, and separately located executable implementations;
- approximately 1,802/1,846, or 97.62%, established as candidate executable semantics;
- approximately 1,810/1,846, or 98.05%, if the strongest generic AVX10/FP8 handler correspondences are credited;
- working point estimate: 97.7%.

The exact-name figure is deliberately a lower bound. It misses such cases as:

- XED's `_LOCK`, `REP_*`, width-disambiguated, and numbered-NOP ICLASSes sharing ordinary emulator handlers;
- APX's individual condition-code ICLASS names reaching a generic condition dispatcher;
- QEMU's MPX implementation living behind decoder/helper names that do not reproduce every XED ICLASS spelling;
- XED's finely split conversion names reaching generic vector conversion handlers;
- instruction leaves implemented beneath a single dispatcher such as `ENCLS`, `ENCLU`, `GETSEC`, `PCONFIG`, or `SEAMCALL`.

Accordingly, neither the exact lexical count nor the adjusted count measures complete form, mode, exception, concurrency, or effect fidelity.

## Semantic-source union

| ISA area | Located executable sources | Present assessment |
|---|---|---|
| Legacy integer, modes, x87, SSE–AVX2 | Bochs, QEMU TCG, VirtualBox IEM, rax, Remill; K for historical user-level formal semantics | Broadly covered; Bochs supplies extended-precision x87 where other implementations approximate it |
| AVX-512, AMX, AVX10.1/10.2 | Current Bochs and rax | Broad executable coverage; newest FP8/BF8 naming and exact floating-point fidelity require reconciliation |
| AVX512-PF/ER/4VNNIW/4FMAPS | rax | Real executable handlers exist; approximation, exception, and mask fidelity remain validation targets |
| APX | rax; an open 2026 QEMU patch series | Broad REX2, EGPR, NDD, NF, CCMP, CTEST, and related behavior; a narrow tail remains unresolved |
| MPX | QEMU TCG | Real bounds state, checks, loads/stores, and exceptions |
| VMX | Bochs and VirtualBox IEM | Substantive software state-machine semantics, not decoder metadata; guest execution should remain an STS control/effect boundary rather than be unrolled |
| RTM/TSX | Palacios VMM | Substantive transactions, conflict detection, commit, and rollback; newer load-tracking controls remain unresolved |
| ENQCMD/ENQCMDS | Xen x86 emulator | Validation and PASID behavior with queue acceptance represented as an environmental operation |
| SGX | OpenSGX and CCX | Rich executable SGX1/2 behavior; exact current fidelity and several newer or historical leaves remain incomplete |
| PCONFIG/MKTME | OpenTDX | Actual key-program validation and state effects; some error paths remain incomplete |
| TDX/SEAM | OpenTDX plus the open TDX module | Substantial executable behavior; complete platform fidelity is not established |

The transport interpretation matters. Angr need not understand VMX, SGX, TDX, AMX, or another difficult target instruction directly. It need only extract the ordinary host instructions implementing the chosen handler. Interpreter loops and dispatcher re-entry are preserved as STS control structure; device, timing, randomness, queue, trace, or guest-entry behavior becomes an explicit effect boundary where appropriate.

## Current residual ledger

The approximately 42 unresolved or incompletely demonstrated ICLASSes behind the 97.7% estimate are concentrated rather than representative:

- 15 ACE 1.0 matrix/tile classes;
- 11 Key Locker classes;
- 4 APX paired-stack classes;
- 2 instruction-cache prefetch classes;
- 2 TSX load-tracking controls;
- one each for HRESET, IBHF, PREFETCHRST2, PBNDKB, PTWRITE, GETSEC/SMX, and ENCLV;
- PCONFIG was initially in this ledger but OpenTDX supplies a substantive partial implementation;
- ENQCMD and ENQCMDS were initially in this ledger but Xen supplies executable semantics.

In addition, 29 very recent BF8/HF8/AVX10-family ICLASSes account for the difference between the conservative 96.2% floor and the 97.7% point estimate. Closely corresponding generic handlers exist, but the mapping and exact fidelity have not been checked class by class.

“Unresolved” means that this audit has not yet located and validated a suitable executable definition. It does not prove that no implementation exists anywhere. Conversely, source presence does not establish correctness. The correct next use of weak or research implementations is as a scaffold for differential fuzzing, synthesis, and human semantic repair.

## Historical calibration

Strata, published in 2016, synthesized 1,795 variants from the user-level Haswell ISA. The currently unresolved families are overwhelmingly post-Haswell or privileged/system-effect surfaces outside Strata's functional target. The present source union therefore appears to represent 100% of Strata's claimed family surface, although ixyk has not yet transported and validated all 1,795 variants.

The later K x86-64 semantics covered 3,155 non-deprecated sequential user-level Haswell variants across 774 mnemonics. That entire mature user-level region likewise falls within the strongest part of the source union.

libLISA, published in 2024, analyzed five concrete x86-64 CPUs and reported approximately 118,000 CPU-specific instruction groups per machine. It reported 99.99% coverage of in-scope instructions from real binaries and 99.9% on randomized in-scope oracle instructions. Its scope excluded several prefix classes, segmentation, concurrency, memory ordering, timing, undefined-instruction cases, and instructions unsupported by each observed CPU. At the instruction-family level, the present source union appears to cover effectively 100% of that historical tested-machine scope. This does not imply that ixyk already represents every libLISA encoding group or CPU-specific undefined behavior.

These comparisons explain the apparent tension: failing to reach 99% of the 2026 XED ICLASS denominator can coexist with complete coverage of the much narrower 2016 and 2024 research targets. The bar is moving.

## Fidelity and trust boundaries

The useful claim is staged:

1. An executable semantic source exists for nearly every current Intel ICLASS family.
2. Each source can produce a candidate model through direct acquisition or semantic transport.
3. Differential fuzzing and retained witnesses test that candidate against hardware or independent implementations.
4. Counterexamples monotonically refine or replace the candidate.
5. Formal transport proofs establish preservation relative to the source model; they do not silently promote that source into an architectural authority.

Examples of known fidelity cautions:

- OpenSGX is substantial but contains concurrency omissions, disabled checks, and explicit specification deviations.
- OpenTDX is a research implementation of key SMX/MKTME/SEAM behavior, not a demonstrated complete model of every current TDX platform interaction.
- rax implements rare AVX-512 operations, but some approximate floating-point operations use host arithmetic and require accuracy, rounding, exception, and payload validation.
- emulator implementations may intentionally approximate caches, prefetching, traces, devices, randomness, or transactional conflicts; these should remain explicit effects rather than be erased.
- rax is useful as an executable oracle and source for rederivation, but its audited revision describes MIT licensing without a root license file or package license declaration. Do not copy code from it until licensing is resolved.

## Reproducibility and provenance

Locally inspected revisions:

| Source | Revision |
|---|---|
| Intel XED | `0bcb6237345c5066726dcc08b3d87928df3b5b26` |
| Bochs | `22432bc36e1a1c502bf5b181ad832f0710d93ba6` |
| QEMU | `d2843fbf80260e4346c856819e8cea11768c9d0e` |
| VirtualBox | `d29ee06e9971cb4cddcfc0ee37bde6d7b50e21af` |
| Remill | `56918a8c2554088e93389e97d292f4035286506c` |
| rax | `7f162b19aeaa47825c82fb1c77ca042f535124e3` |
| OpenSGX | `8872fc82b2da6158f7bdac6483c5689dc1062ca8` |
| OpenTDX | `211c273b95ed0947b8f74caec0fbe05af85e6035` |
| gem5 | `c8222cc67a399bfc01e8658dd14b30d5bfd634f9` |
| LLVM | `7cbf1a2591520c2491aa35339f227775f4d3adf6` |

Important external sources not yet included in the local clone set:

- Strata: <https://cs.stanford.edu/people/sharmar/pubs/pldi16b.pdf>
- libLISA: <https://liblisa.nl/publications/liblisa-oopsla24/>
- K x86-64 semantics: <https://github.com/kframework/X86-64-semantics>
- Xen x86 emulator: <https://github.com/xen-project/xen/blob/master/xen/arch/x86/x86_emulate/x86_emulate.c>
- Palacios RTM implementation paper: <https://users.eecs.northwestern.edu/~msw978/resources/palacios-htm.pdf>
- CCX SGX implementation: <https://github.com/ma-schulze/ccx>
- QEMU APX series: <https://patchew.org/QEMU/20260825122921.431739-1-pbonzini@redhat.com/>

## Follow-up

- Turn this exploratory census into a reproducible XED-to-source matrix with explicit evidence classes: handler, generic-handler mapping, stub, metadata-only, hardware passthrough, partial research model, and unresolved.
- Audit the 29 tentative AVX10/FP8 correspondences class by class.
- Search focused sources for the 42-item residual, especially ACE and Key Locker.
- Preserve per-source licensing and provenance metadata in the semantic catalog.
- Treat candidate-source coverage, transported-model coverage, fuzz-validation coverage, and proved transport as separate published numbers.
