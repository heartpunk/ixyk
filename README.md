# ixyk: symbolic state diffs are all you need

[![DOI](https://zenodo.org/badge/1353984899.svg)](https://doi.org/10.5281/zenodo.22290191)
[![Sponsor heartpunk on GitHub](https://img.shields.io/github/sponsors/heartpunk?label=Sponsor&logo=github)](https://github.com/sponsors/heartpunk) · [Support heartpunk on Patreon](https://www.patreon.com/heartpunk)

## Abstract

a proof of concept of the core of a symbolic-execution technique [[1]](#ref-1) for extracting symbolic state transformers with guards and updates expressed as satisfiability modulo theories (smt) [[3]](#ref-3) using smt-lib [[4]](#ref-4) fragments interpreted with z3 [[6]](#ref-6). 81/100 opcodes get models from angr [[5]](#ref-5), 78/100 pass the full 10k sample hypothesis [[9]](#ref-9) differential fuzz pass [[8]](#ref-8) comparing extracted models to unicorn [[7]](#ref-7) behavior. tl;dr: it subtracts the old state from the new state, and that's the whole thing. just takes the definitions seriously.

## Status

this is v0.0.1. it works. it is described in literally minimal form. additional versions will be coming w/clarifications and more explanation as i ascertain what exactly needs to go where. this release is for those most interested, and/or the agents.

also, literally just so i can move on to next steps.

## Citation

v0.0.1 release has the version-specific DOI
[`10.5281/zenodo.22290192`](https://doi.org/10.5281/zenodo.22290192). the aggregate DOI is and resolves
[`10.5281/zenodo.22290191`](https://doi.org/10.5281/zenodo.22290191) to
the latest release and all archived versions.

> Sophie Smithburg. (2026). *ixyk: symbolic state diffs are all you need*
> (v0.0.1). Zenodo. https://doi.org/10.5281/zenodo.22290192

machine-readable citation metadata is available in [`CITATION.cff`](CITATION.cff).

## Validation

the current linux/remote execution api (reapi) [[18]](#ref-18) campaign takes one representative encoding from each of
the 100 highest-frequency normalized x86-64 instruction families in the source
catalog and requests 10,000 deterministic hypothesis examples per probe.

| Raw result | Families | Actual executions | Share of top-100 occurrence mass | Interpretation |
|---|---:|---:|---:|---|
| pass | 78 | 780,000 | 99.007986% | every requested model-versus-unicorn comparison agreed |
| mismatch | 3 | 6,621 | 0.048367% | hypothesis stopped after finding and shrinking a counterexample |
| unsupported | 18 | 0 | 0.883665% | extraction reached a declared theory, state, or outcome boundary before fuzzing |
| acquisition error | 1 | 0 | 0.059982% | the instruction did not produce a liftable acquisition artifact |
| **total** | **100** | **786,621** | **100.000000%** | **1,000,000 examples were requested across the campaign** |

the three raw mismatches are useful harness findings, but do not presently
demonstrate incorrect instruction semantics:

| Probe | Minimized disagreement | Classification |
|---|---|---|
| `bt rax, rbx` | model and unicorn choose different AF values | oracle false positive: AF is architecturally undefined for BT [[10]](#ref-10) |
| `bsr rax, rbx` | model and unicorn choose different PF values for a zero source | oracle false positive: PF and the zero-source destination are architecturally undefined for BSR [[10]](#ref-10) |
| `leave` | unicorn rejects mapping the canonical high-half address derived from RBP | model/oracle memory-domain mismatch: symbolic memory admits the address but the concrete harness cannot map its terminal page |

each concrete execution initializes all 16 64-bit general-purpose registers,
all 16 256-bit YMM registers, six modeled status flags, RIP, and sparse
zero-default byte memory. unicorn executes exactly one instruction. the checker
then requires exactly one symbolic edge and compares the complete modeled
scalar, vector, flag, program-counter, and memory post-state. generation uses a
fixed seed, disables the hypothesis example database, and shrinks the first
disagreement.

the 99.007986% figure is occurrence-weighted **within these top 100 families**.
it is not a claim that every encoding or operand form—or 99% of all dynamically
executed instructions—has been validated. see the full
[`validation-notes.md`](validation-notes.md) evidence ledger for the complete
100-family results, model shapes, failure taxonomy, witnesses, and additional
control-flow caveats.

## Reference Artifacts

the deliberately versioned examples in [`artifacts/golden/`](artifacts/golden/)
preserve exact acquisition, instruction-model, and 10,000-example validation
outputs for this release. they are research reference artifacts, not ordinary
`bazel-bin/` or `bazel-out/` contents. the directory documents what each example
demonstrates, how to regenerate the set, and how to verify it against the pinned
linux/reapi toolchain.

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
- insists on bazel reapi based execution, because i didn't want to get distracted on other modes or have much possibility of divergence.
- as a result, it may not yet work on your machine without a little tweaking. working on this.
- this technique doesn't work really well for recursive opcodes. it could perhaps be generalized, but i just haven't tried yet.

## Future Work

- for this repo
  - fill out the abstract, make easier understand for less specialized reader
  - build section describe what platforms work and don't rn and what is needed to make it do so
  - shared bazel/reapi environment in a standalone repo: this repo should only invoke its pinned nix flake; publish an equivalent OCI image from the same nix closure for people who don't use nix
  - development section describing processes thus far
  - repo org section explain where what is and why
  - generalize instruction variants using anti-unification [[11]](#ref-11), [[12]](#ref-12). not just one instr variant per opcode. should be exhaustive. was oversight. have technique impled in other repo, porting presently.
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
