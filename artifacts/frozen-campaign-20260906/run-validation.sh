#!/usr/bin/env bash
set -euo pipefail
cd /home/heartpunk/workspaces/ixyk-perf/frozen-campaign-20260906
python=/home/heartpunk/workspaces/ixyk-perf/runtime/python-root/bin/python
"$python" bootstrap.py guarded_benchmark.py --opcode JE --samples 10000 --recording reference-json --commit 1ca1aef6e15025a223a2822fd988137138ca87c0 --invocation-id frozen-working-copy-je10k-json --output-dir results/je10k-json
"$python" bootstrap.py guarded_benchmark.py --opcode LEA --samples 10000 --recording reference-json --commit 1ca1aef6e15025a223a2822fd988137138ca87c0 --invocation-id frozen-working-copy-lea10k-json --output-dir results/lea10k-json
