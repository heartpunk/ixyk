#!/usr/bin/env bash
set -euo pipefail
cd /home/heartpunk/workspaces/ixyk-perf/frozen-campaign-20260906
p=/home/heartpunk/workspaces/ixyk-perf/runtime/python-root/bin/python
for t in fuzz_inputs fuzz_stages fuzz_bootstrap; do
 "$p" bootstrap.py "source/extractor/${t}_test.py"
done
for opcode in ADD JE LEA MOVSD; do
 for mode in off reference-json; do
  "$p" bootstrap.py guarded_benchmark.py --opcode "$opcode" --samples 100 --recording "$mode" --commit 1ca1aef6e15025a223a2822fd988137138ca87c0 --invocation-id "final-${opcode}-${mode}" --output-dir "results/final-${opcode}-${mode}"
 done
done
"$p" bootstrap.py forced_fallback.py --opcode ADD --samples 10000 --recording off --commit 1ca1aef6e15025a223a2822fd988137138ca87c0 --invocation-id final-add10k-forced-fallback --output-dir results/final-add10k-fallback
"$p" bootstrap.py audit_evidence.py
