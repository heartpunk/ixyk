#!/usr/bin/env bash
set -euo pipefail
expected=$(sed -n 's|^leanprover/lean4:v||p' lean-toolchain)
actual=$(lean --version | sed -n 's/^Lean (version \([^,]*\),.*/\1/p')
test -n "$expected" && test "$actual" = "$expected"
lake build Ixyk ixyk-golden-check ixyk-differential-eval
lake env lean -DwarningAsError=true .ci/ProofAudit.lean
revision=$(jq -er '.nodes.nixpkgs.locked.rev' flake.lock)
nix shell "github:NixOS/nixpkgs/$revision#python312" "github:NixOS/nixpkgs/$revision#zstd" --command python tools/ci_lean.py
PYTHONPATH="$PWD" nix shell --impure --file tools/lean_fuzz_env.nix --command python -m tools.lean_differential
