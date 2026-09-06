# ixyk: symbolic state diffs are all you need

[![DOI](https://zenodo.org/badge/1353984899.svg)](https://doi.org/10.5281/zenodo.22290191)
[![Sponsor heartpunk on GitHub](https://img.shields.io/github/sponsors/heartpunk?label=Sponsor&logo=github)](https://github.com/sponsors/heartpunk) · [Support heartpunk on Patreon](https://www.patreon.com/heartpunk)

## Abstract

a proof of concept of the core of a symbolic-execution and anti-unification oriented technique [[1]](#ref-1) for extracting symbolic state transformers with guards and updates expressed as satisfiability modulo theories (smt) [[3]](#ref-3) using smt-lib [[4]](#ref-4) fragments interpreted with z3 [[6]](#ref-6). 81/100 opcodes get models from angr [[5]](#ref-5), 76/100 pass the full 10k sample hypothesis [[9]](#ref-9) differential fuzz pass [[8]](#ref-8) comparing extracted models to unicorn [[7]](#ref-7) behavior. tl;dr: it subtracts the old state from the new state, and that's the whole thing. just takes the definitions seriously.

## Status

this is v0.0.2. it works. it is described in barely more than minimal form. additional versions will be coming w/clarifications and more explanation as i ascertain what exactly needs to go where. this is the first widely announced release. but it still does presume either specialized background or substantial interest.

also, literally just so i can move on to next steps.

## Citation

v0.0.2 release has the version-specific DOI
[`DOI_TBD`](DOI_TBD). the aggregate DOI is and resolves
[`10.5281/zenodo.22290191`](https://doi.org/10.5281/zenodo.22290191) to
the latest release and all archived versions.

> Sophie Smithburg. (2026). *ixyk: symbolic state diffs are all you need*
> (v0.0.2). Zenodo. DOI_TBD

machine-readable citation metadata is available in [`CITATION.cff`](CITATION.cff).

## Getting Started

the pinned development environment is available through Nix. Docker provides the
Linux/amd64 environment on macOS. run these commands from the repository checkout.

with Nix, the public [`ixyk` development cache](https://ixyk.cachix.org), hosted
by Cachix, lets you download available prebuilt dependencies. no Cachix account
or token is needed for downloads. enable it once, then enter the environment:

```sh
# one-time cache setup; runs Cachix without installing it permanently
nix run nixpkgs#cachix -- use ixyk
nix develop
ixyk-dev-check
```

the flake also declares the cache URL and signing key; accept those settings if
Nix prompts for them.

with Docker, as an alternative:

```sh
export IXYK_UID="$(id -u)" IXYK_GID="$(id -g)"
docker compose pull dev
docker compose run --rm dev
```

then, inside the container:

```sh
ixyk-dev-check
```

## Development

we use a p fuzzing and property based testing heavy approach here. in general, we try to exhaustively test the properties that matter wrt making sure the models we generate will be worth fuzzing, but overall, we rely on the differential fuzzing more than anything else. in some places we've measured coverage and done mutation testing, but not reliably. these are near term v0.0.3 targets. in the end, however, it will be more sensible to use our own models to prove our own correctness. that's probably at least in v0.x.0 territory, for values of x>=1.

most work has been done on osx and all build and test done on linux by way of linux based bazel clients triggering bazel REAPI actions.

## Validation

the abstract and tables below report the completed linux/remote execution api
(reapi) [[18]](#ref-18) campaign from 2026-09-06, using source revision
[`94a99a9`](https://github.com/heartpunk/ixyk/commit/94a99a9dfdc7dec295c3231465d4ae7a6e9626f0)
and invocation `d7f32572-64dd-4474-8475-0fe7f735dac5`. it ran from 09:18 to 10:01 PDT,
starting from one representative encoding for each of the 100 highest-frequency
normalized x86-64 instruction families in the source catalog and requesting
10,000 deterministic hypothesis examples per family. these measurements predate
the final constructor/source-variation and flag-state changes; a fresh campaign
on the current stack is pending.

| Campaign outcome | Families | Actual executions | Share of top-100 occurrence mass | Interpretation |
|---|---:|---:|---:|---|
| pass | 76 | 760,000 | 89.942282% | every requested model-versus-unicorn comparison agreed |
| mismatch | 4 | 40,000 | 1.109504% | completed all 10,000 executions while retaining disagreements |
| incomplete (CALL) | 1 | 4,629 | 8.004567% | the fuzz worker exited without a final result; partial observations were retained |
| unsupported | 18 | 0 | 0.883665% | preparation produced no executable models across a declared theory, state, or outcome boundary |
| no liftable model (UD2) | 1 | 0 | 0.059982% | acquisition failed and no executable fallback was available |
| **total** | **100** | **804,629** | **100.000000%** | **1,000,000 examples were requested across the campaign** |

81 families had executable models. raw acquisition statuses were 80 pass,
18 unsupported, and 2 acquisition errors: CMPXCHG retained four concrete fallback
models and passed 2,500 comparisons per model, while UD2 had no executable model.
the table separates the 20 incomplete fuzz reports into CALL's partial run and
the 19 families with no executable model; it does not count them as passing.

the following are recorded discovery findings, not minimized witnesses or a
claim that each difference is a defect in the extracted instruction semantics:

| Probe | Recorded disagreements | Actual executions | First recorded difference / completion status |
|---|---:|---:|---|
| `ret` | 334 | 10,000 | RIP and mirrored PC differ |
| `bt rax, rbx` | 8,121 | 10,000 | ZF differs |
| `bsr rax, rbx` | 5,792 | 10,000 | PF differs |
| `leave` | 394 | 10,000 | RBP differs |
| `call` | 378 | 4,629 | incomplete; worker exited without a final result, with 412 unusable observations also retained |

this run froze its prepared models before sampling. each concrete execution
initialized all 16 64-bit general-purpose registers, all 16 256-bit YMM registers,
six modeled status flags, RIP, and sparse zero-default byte memory. unicorn
executed exactly one instruction, and the checker compared the modeled outcome
and complete modeled post-state. generation used a fixed seed and an
action-local replay database. discovery continued through findings; separate
shrinking and explanation stages are not included in these counts. the current
implementation additionally models DF, AC, and ID, for nine flags in total;
that expansion is not covered by this earlier measurement.

the 89.942282% figure is occurrence-weighted **within these top 100 families**,
using their combined 27,933,247,943 source-catalog occurrences as the denominator.
it is not a claim that every encoding or operand form—or the same share of all
dynamically executed instructions—has been validated. the existing
[`validation-notes.md`](validation-notes.md) ledger preserves the earlier v0.0.1
campaign and its witness classifications; it is historical evidence, not the
ledger for the 2026-09-06 run summarized here.

## Reference Artifacts

the deliberately versioned examples in [`artifacts/golden/`](artifacts/golden/)
preserve exact acquisition, instruction-models. they are research reference artifacts,
not ordinary `bazel-bin/` or `bazel-out/` contents. the directory documents what
each example demonstrates, how to regenerate the set, and how to verify it against
the pinned linux/reapi toolchain.

## Repository Organization

- `extractor/` — Python instruction-model pipeline.
  - `artifact.py`, `typed_z3.py` — canonical typed QF_ABV models and Z3 conversion.
  - `extractor.py`, `amd64_state.py` — Angr extraction and AMD64 architectural state.
  - `model_syntax.py`, `operand_slots.py`, `instruction_schema.py` — typed syntax exposure, decoded operand correspondence, and instruction-schema generalization.
  - `fuzzer.py` — differential validation against Unicorn.
  - CLI entry points, runtime adapters, and tests live alongside their implementation.
- `antiunification/` — generic typed anti-unification algebra and its unit/property tests; currently housed here.
- `Ixyk/` — Lean embedding.
  - `QfAbv/` — typed syntax, expression semantics, and symbolic transition systems.
  - `Artifact.lean` — imports canonical model artifacts into the typed embedding.
  - `GoldenCheck.lean`, `DifferentialEval.lean` — artifact checking and executable differential evaluation.
- `catalog/` — instruction selections, generated probes, and Bazel validation targets.
- `artifacts/golden/` — checked-in compressed model artifacts and their checksum manifest.
- `notes/` — research notes and exploratory censuses.
- `tools/` — validation and CI tooling, including golden-artifact checks, Lean differential tests, and REAPI execution.
- `third_party/` — vendored Python dependencies with Bazel integration.
- `.github/` — CI workflows and shared actions.
- Root build files — Nix environments (`flake.nix`), Bazel dependencies/configuration, Python tooling (`pyproject.toml`), and Lean package/toolchain configuration.

## Known Limitations

- intentionally linux only, bcz i didn't wanna focus on portability yet. should work on osx in principle p quickly. like. hard hard linux only. can only initiate build from linux client to linux server.
  - we have a docker container if u wanna work from osx! it could still be made portable in principle, but there just hasn't been a reason for it.
- this technique doesn't work really well for recursive opcodes. it could perhaps be generalized, but i just haven't tried yet.

## Future Work

- for this repo
  - fill out the abstract, make easier understand for less specialized reader
  - development section describing processes thus far
  - doesn't yet work where the symex engine doesn't model enough. for example, `VMENTER` may be difficult to directly extract by symbolic state diffs. 
    - the plan there is to read their defs out from emulators when they are defined in terms of instrs we already have, or to try other symex engines that do, or to cowardly admit defeat where we can't be perfectly total. still, i do expect in the end this can achieve higher coverage than prior instruction-semantics approaches [[13]](#ref-13)–[[15]](#ref-15). TBD!
    - check the notes in the [Intel x86 semantic-source union census](notes/intel-x86-semantic-source-union-census-2026-09-04.md).
  - turning the readme into a paper
  - floating point
  - extension to other ISA targets
  - further explanation of the proof story
- for those to come
  - STS stitching for full programs (prototyped)
  - futamura projection [[17]](#ref-17) of programs through implementations that have been assembled as a full STS (prototyped)
  - equivalence checking between hand generated or extracted STSes (prototyped)
  - lean proof of correctness of the technique (underway, quite confident should work out, but not certain yet)
  - eventually, fixed parameter tractable computation time detectors for many common weakness enumeration (CWE) [[19]](#ref-19) classes. this hasn't been done yet to any extent, but we have solid designs ready to prototype as time and priority permits.

## References

1. <a id="ref-1"></a>J. C. King, “Symbolic execution and program testing,” *Communications of the ACM*, vol. 19, no. 7, pp. 385–394, 1976. doi: [10.1145/360248.360252](https://doi.org/10.1145/360248.360252).
2. <a id="ref-2"></a>T. A. Henzinger, R. Majumdar, and J.-F. Raskin, “A classification of symbolic transition systems,” *ACM Transactions on Computational Logic*, vol. 6, no. 1, pp. 1–32, 2005. doi: [10.1145/1042038.1042039](https://doi.org/10.1145/1042038.1042039).
3. <a id="ref-3"></a>C. Barrett, R. Sebastiani, S. A. Seshia, and C. Tinelli, “Satisfiability modulo theories,” in *Handbook of Satisfiability*, vol. 185, IOS Press, 2009, pp. 825–885. doi: [10.3233/978-1-58603-929-5-825](https://doi.org/10.3233/978-1-58603-929-5-825).
4. <a id="ref-4"></a>C. Barrett, P. Fontaine, and C. Tinelli, [*The SMT-LIB Standard: Version 2.7*](https://smt-lib.org/language.shtml). SMT-LIB Initiative, 2025.
5. <a id="ref-5"></a>Y. Shoshitaishvili et al., “SoK: (State of) the art of war: Offensive techniques in binary analysis,” in *Proceedings of the IEEE Symposium on Security and Privacy*, 2016, pp. 138–157. doi: [10.1109/SP.2016.17](https://doi.org/10.1109/SP.2016.17).
6. <a id="ref-6"></a>L. de Moura and N. Bjørner, “Z3: An efficient SMT solver,” in *Proceedings of TACAS*, LNCS 4963, 2008, pp. 337–340. doi: [10.1007/978-3-540-78800-3_24](https://doi.org/10.1007/978-3-540-78800-3_24).
7. <a id="ref-7"></a>A. Q. Nguyen and H. V. Dang, “[Unicorn: Next generation CPU emulator framework](https://www.unicorn-engine.org/docs/),” presented at Black Hat USA, 2015.
8. <a id="ref-8"></a>L. Martignoni, R. Paleari, G. F. Roglia, and D. Bruschi, “Testing CPU emulators,” in *Proceedings of ISSTA*, 2009, pp. 261–272. doi: [10.1145/1572272.1572303](https://doi.org/10.1145/1572272.1572303).
9. <a id="ref-9"></a>D. R. MacIver, Z. Hatfield-Dodds, and contributors, “Hypothesis: A new approach to property-based testing,” *Journal of Open Source Software*, vol. 4, no. 43, art. 1891, 2019. doi: [10.21105/joss.01891](https://doi.org/10.21105/joss.01891).
10. <a id="ref-10"></a>Intel Corporation, [*Intel 64 and IA-32 Architectures Software Developer’s Manual*](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), 2026.
11. <a id="ref-11"></a>G. D. Plotkin, “A note on inductive generalisation,” in *Machine Intelligence 5*, B. Meltzer and D. Michie, Eds. Edinburgh University Press, 1970, pp. 153–163.
12. <a id="ref-12"></a>D. M. Cerna and T. Kutsia, “Anti-unification and generalization: A survey,” in *Proceedings of IJCAI*, 2023, pp. 6563–6573. doi: [10.24963/ijcai.2023/736](https://doi.org/10.24963/ijcai.2023/736).
13. <a id="ref-13"></a>S. Heule, E. Schkufza, R. Sharma, and A. Aiken, “Stratified synthesis: Automatically learning the x86-64 instruction set,” in *Proceedings of PLDI*, 2016, pp. 237–250. doi: [10.1145/2908080.2908121](https://doi.org/10.1145/2908080.2908121).
14. <a id="ref-14"></a>S. Dasgupta, D. Park, T. Kasampalis, V. S. Adve, and G. Roşu, “A complete formal semantics of x86-64 user-level instruction set architecture,” in *Proceedings of PLDI*, 2019, pp. 1133–1148. doi: [10.1145/3314221.3314601](https://doi.org/10.1145/3314221.3314601).
15. <a id="ref-15"></a>J. Craaijo, F. Verbeek, and B. Ravindran, “libLISA: Instruction discovery and analysis on x86-64,” *Proceedings of the ACM on Programming Languages*, vol. 8, no. OOPSLA2, art. 283, 2024. doi: [10.1145/3689723](https://doi.org/10.1145/3689723).
16. <a id="ref-16"></a>L. de Moura and S. Ullrich, “The Lean 4 theorem prover and programming language,” in *Proceedings of CADE-28*, LNCS 12699, 2021, pp. 625–635. doi: [10.1007/978-3-030-79876-5_37](https://doi.org/10.1007/978-3-030-79876-5_37).
17. <a id="ref-17"></a>Y. Futamura, “Partial evaluation of computation process—An approach to a compiler-compiler,” *Higher-Order and Symbolic Computation*, vol. 12, no. 4, pp. 381–391, 1999. doi: [10.1023/A:1010095604496](https://doi.org/10.1023/A:1010095604496).
18. <a id="ref-18"></a>Bazel Project, “[Remote Execution API](https://github.com/bazelbuild/remote-apis/blob/main/build/bazel/remote/execution/v2/remote_execution.proto),” *bazelbuild/remote-apis*.
19. <a id="ref-19"></a>MITRE, “[Common Weakness Enumeration](https://cwe.mitre.org/).”

## License

Copyright (C) 2026 Sophie Smithburg.

Except where otherwise indicated, ixyk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE) for the full license text. Third-party components retain their own copyright and license terms.
