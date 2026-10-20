#!/usr/bin/env bash
set -euo pipefail
if [[ "${IFRL_IN_SHELL:-}" != 1 ]]; then
  export IFRL_IN_SHELL=1
  exec nix develop --no-write-lock-file --command bash "$0"
fi
mkdir -p ci-reports/bazel-coverage
mapfile -t targets < .ci/python-targets.txt
excluded_target=//extractor:acquire_cli_test
coverage_targets=()
for target in "${targets[@]}"; do
  if [[ "$target" != "$excluded_target" ]]; then
    coverage_targets+=("$target")
  fi
done
set +e
bash .ifrl-ci/ci/python.sh coverage
tools_status=$?
# This target passes in normal CI but its 60-second fuzz budget is consumed
# before any fuzz executions when Bazel instruments it for coverage.
bazel test --jobs=2 --local_resources=memory=6000 \
  --spawn_strategy=local --strategy=TestRunner=local \
  --nocache_test_results --test_timeout=0,0,2400,0 --test_output=errors \
  "$excluded_target" 2>&1 | tee ci-reports/bazel-coverage/uninstrumented-test.log
uninstrumented_status=${PIPESTATUS[0]}
# rules_python 1.7.0 explicitly enables branch=True in its coverage bootstrap.
bazel coverage --jobs=2 --local_resources=memory=6000 \
  --spawn_strategy=local --strategy=TestRunner=local \
  --extra_toolchains=@ci_coverage_runtime//:toolchain \
  --combined_report=lcov --nocache_test_results \
  --test_timeout=0,0,2400,0 \
  --build_event_json_file=ci-reports/bazel-coverage/build-events.json \
  --instrumentation_filter='^//(antiunification|extractor|tools)' \
  --test_output=errors "${coverage_targets[@]}" 2>&1 | tee ci-reports/bazel-coverage/tests.log
bazel_status=${PIPESTATUS[0]}
set -e
coverage_file=$(bazel info output_path)/_coverage/_coverage_report.dat
if [[ -f "$coverage_file" ]]; then
  cp "$coverage_file" ci-reports/bazel-coverage/coverage.lcov
else
  echo 'Bazel did not produce its branch coverage report' >&2
  exit 1
fi
printf '{"tools_exit_code":%s,"uninstrumented_exit_code":%s,"bazel_exit_code":%s,"coverage_excluded_targets":["%s"]}\n' \
  "$tools_status" "$uninstrumented_status" "$bazel_status" "$excluded_target" > ci-reports/bazel-coverage/status.json
test "$tools_status" -eq 0 && test "$uninstrumented_status" -eq 0 && test "$bazel_status" -eq 0
