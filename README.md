# ixyk: symbolic state diffs are all you need

[![Sponsor heartpunk on GitHub](https://img.shields.io/github/sponsors/heartpunk?label=Sponsor&logo=github)](https://github.com/sponsors/heartpunk) · [Support heartpunk on Patreon](https://www.patreon.com/heartpunk)

## Abstract

a proof of concept of the core of a technique for extracting symbolic state transformers with guards and updates expressed as smt lib fragments. currently extracts ~60 or so of 100 instrs accurately (stats updating in abstract with the implementation itself). basically, it subtracts the old state from the new state, and that's the whole thing. just takes the definitions seriously.

## Status

this is v0.0.1. it works. it is described in literally minimal form. additional versions will be coming w/clarifications and more explanation as i ascertain what exactly needs to go where. this release is for those most interested, and/or the agents.

also, literally just so i can move on to next steps.

## Known Limitations

- intentionally linux only, bcz i didn't wanna focus on portability yet. should work on osx in principle p quickly.
- insists on bazel REAPI based execution, because i didn't want to get distracted on other modes or have much possibility of divergence.
- as a result, it may not yet work on your machine without a little tweaking. working on this.

## Future Work

- for this repo
  - floating point
  - extension to other ISA targets
  - further explanation of the proof story
- for those to come
  - the lean embedding for the STS fragment language we use, which should in principle enable at least some, but hopefully arbitrary proof for impls using the modeled instruction set (prototyped)
  - STS stitching for full programs (prototyped)
  - futamura projecting programs through implementations that have been assembled as a full STS (prototyped)
  - equivalence checking between hand generated or extracted STSes (prototyped)
  - lean proof of correctness of the technique (underway, quite confident should work out, but not certain yet)
  - eventually, fixed parameter tractable computation time detectors for many CWE classes. this hasn't been done yet to any extent, but we have solid designs ready to prototype as time and priority permits.

## License

Copyright (C) 2026 Sophie Smithburg.

Except where otherwise indicated, ixyk is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version. See [LICENSE](LICENSE) for the full license text. Third-party components retain their own copyright and license terms.
