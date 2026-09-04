# ixyk: symbolic state diffs are all you need

[![DOI](https://zenodo.org/badge/1353984899.svg)](https://doi.org/10.5281/zenodo.22290191)
[![Sponsor heartpunk on GitHub](https://img.shields.io/github/sponsors/heartpunk?label=Sponsor&logo=github)](https://github.com/sponsors/heartpunk) · [Support heartpunk on Patreon](https://www.patreon.com/heartpunk)

## Abstract

a proof of concept of the core of a technique for extracting symbolic state transformers with guards and updates expressed as smt lib fragments. 81/100 opcodes get models from angr, 78/100 pass the full 10k sample differential fuzz pass comparing extracted models to unicorn behavior. tl;dr: it subtracts the old state from the new state, and that's the whole thing. just takes the definitions seriously.

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

the current linux/reapi campaign takes one representative encoding from each of
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
| `bt rax, rbx` | model and unicorn choose different AF values | oracle false positive: AF is architecturally undefined for BT |
| `bsr rax, rbx` | model and unicorn choose different PF values for a zero source | oracle false positive: PF and the zero-source destination are architecturally undefined for BSR |
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

## Known Limitations

- intentionally linux only, bcz i didn't wanna focus on portability yet. should work on osx in principle p quickly. like. hard hard linux only. can only initiate build from linux client to linux server.
- insists on bazel REAPI based execution, because i didn't want to get distracted on other modes or have much possibility of divergence.
- as a result, it may not yet work on your machine without a little tweaking. working on this.
- this technique doesn't work really well for recursive opcodes. it could perhaps be generalized, but i just haven't tried yet.
- won't work where the symex engine doesn't model enough, tl;dr. like, i have not remotely attempted to consider instructions like `VMENTER`. the plan there is to read their defs out from emulators when they are defined in terms of instrs we already have, or to try other symex engines that do, or to cowardly admit defeat where we can't be perfectly total. still, i do expect in the end this can achieve higher coverage than most approaches. TBD!

## Future Work

- for this repo
  - the lean embedding for the symbolic transition system (STS) fragment language we use, which should in principle enable at least some, but hopefully arbitrary proof for impls using the modeled instruction set (prototyped)
  - fill out the abstract, make easier understand for less specialized reader
  - splain da wordses when use: satisfiability modulo theories (SMT), symbolic transition system (STS), Remote Execution API (REAPI), Common Weakness Enumeration (CWE), Angr, Unicorn, Lean, and Futamura projection
  - cite important techniques and tools. need decide what list is bcz been a bit since thought about this, but, we do have documented what has been considered in impl process.
  - build section describe what platforms work and don't rn and what is needed to make it do so
  - shared bazel/reapi environment in a standalone repo: this repo should only invoke its pinned nix flake; publish an equivalent OCI image from the same nix closure for people who don't use nix
  - development section describing processes thus far
  - repo org section explain where what is and why
  - generalize. not just one instr variant per opcode. should be exhaustive. was oversight. have technique impled in other repo, porting presently.
  - polish/elision pass for AI prose in README (minimal as is FYI!)
  - turning the readme into a paper
  - floating point
  - extension to other ISA targets
  - further explanation of the proof story
- for those to come
  - STS stitching for full programs (prototyped)
  - futamura projecting programs through implementations that have been assembled as a full STS (prototyped)
  - equivalence checking between hand generated or extracted STSes (prototyped)
  - lean proof of correctness of the technique (underway, quite confident should work out, but not certain yet)
  - eventually, fixed parameter tractable computation time detectors for many CWE classes. this hasn't been done yet to any extent, but we have solid designs ready to prototype as time and priority permits.

## License

Copyright (C) 2026 Sophie Smithburg.

Except where otherwise indicated, ixyk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE) for the full license text. Third-party components retain their own copyright and license terms.
