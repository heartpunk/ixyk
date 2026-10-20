#!/usr/bin/env bash
set -euo pipefail
# The transient service contains Bazel and all its descendant process groups.
# Its deadline is shorter than Cosmic Ray's, so cleanup finishes before the
# source is restored or another mutant is attempted.
if [[ "${1:-}" != run ]]; then
  unit="ixyk-mutation-${BASHPID}-${RANDOM}"
  # The unchanged suite takes about four minutes after the native build.
  limit=360
  if [[ "${IFRL_MUTATION_PHASE:-}" == baseline ]]; then limit=1180; fi
  environment=()
  for name in PATH HOME IXYK_NIX_PYTHON_RUNTIME IXYK_NIX_PYTHON_ROOT \
      IXYK_NIX_LIBSTDCXX_ROOT IXYK_NIX_XED_ROOT IFRL_ANGR_ENVIRONMENT \
      PYTHONNOUSERSITE PYTHONSAFEPATH PYTHONDONTWRITEBYTECODE; do
    if [[ -n "${!name-}" ]]; then environment+=("--setenv=$name=${!name}"); fi
  done
  set +e
  sudo systemd-run --quiet --wait --pipe --unit="$unit" \
    --uid="$(id -u)" --gid="$(id -g)" --working-directory="$PWD" \
    --property="RuntimeMaxSec=${limit}s" --property=TimeoutStopSec=5s \
    --property=KillMode=control-group --property=MemoryMax=12G \
    --property=MemorySwapMax=0 --property=CPUQuota=200% \
    "${environment[@]}" "$(command -v bash)" "$PWD/.ci/python-mutation.sh" run
  status=$?
  result=$(sudo systemctl show "$unit" --property=Result --value 2>/dev/null)
  sudo systemctl show "$unit" --property=Result,MemoryPeak,CPUUsageNSec \
    --property=MemoryMax,MemorySwapMax,CPUQuotaPerSecUSec 2>/dev/null
  sudo systemctl reset-failed "$unit" 2>/dev/null
  set -e
  if [[ "$result" == timeout ]]; then
    echo IFRL_MUTATION_TIMEOUT
    exit 124
  elif [[ "$status" -ne 0 && "$result" != exit-code ]]; then
    echo "IFRL_MUTATION_INFRASTRUCTURE: service=$result exit=$status"
    exit 125
  elif [[ "$status" -ne 0 && "$status" -ne 1 && "$status" -ne 3 ]]; then
    echo "IFRL_MUTATION_INFRASTRUCTURE: service=$result exit=$status"
    exit 125
  fi
  exit "$status"
fi
mapfile -t targets < .ci/python-targets.txt
set +e
bazel --batch --host_jvm_args=-Xmx2g test --jobs=2 --local_resources=memory=12000 \
  --spawn_strategy=local --strategy=TestRunner=local \
  --nocache_test_results --test_output=errors "${targets[@]}"
status=$?
set -e
case "$status" in
  0|1|3) ;;
  *) echo "IFRL_MUTATION_INFRASTRUCTURE: bazel exit=$status" ;;
esac
exit "$status"
