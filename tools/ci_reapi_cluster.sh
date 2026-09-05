#!/usr/bin/env bash
set -euo pipefail

cluster=(docker compose -p ixyk-reapi-ci -f compose.reapi.yaml)
cleanup() {
  "${cluster[@]}" logs --no-color --tail 100 || true
  "${cluster[@]}" down --volumes --remove-orphans
}
trap cleanup EXIT

# One action slot per worker makes the two-action barrier require two workers.
export IXYK_WORKER_JOBS=1
"${cluster[@]}" up -d --wait coordinator
"${cluster[@]}" up -d --scale worker=1 worker
timeout --kill-after=10s 180s "${cluster[@]}" run --rm -T client python tools/reapi_smoke.py --launcher ixyk-reapi

# Add capacity to the live coordinator. The client has no namespace exemptions;
# neither workers nor coordinator mount the checkout or another container's store.
"${cluster[@]}" up -d --scale worker=2 worker
timeout --kill-after=10s 180s "${cluster[@]}" run --rm -T --use-aliases client \
  python tools/reapi_smoke.py --launcher ixyk-reapi --callback-host client

# Remove one worker and submit fresh actions, proving the remaining worker works.
first_worker=$("${cluster[@]}" ps -q worker | head -n 1)
docker stop "$first_worker"
timeout --kill-after=10s 180s "${cluster[@]}" run --rm -T client python tools/reapi_smoke.py --launcher ixyk-reapi
