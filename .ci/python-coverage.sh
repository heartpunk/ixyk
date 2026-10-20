#!/usr/bin/env bash
set -euo pipefail
if [[ "${IFRL_IN_SHELL:-}" != 1 ]]; then
  export IFRL_IN_SHELL=1
  exec nix develop --no-write-lock-file --command bash "$0"
fi
mkdir -p ci-reports/bazel-coverage
mapfile -t targets < .ci/python-targets.txt
set +e
bash .ifrl-ci/ci/python.sh coverage
tools_status=$?
# rules_python 1.7.0 explicitly enables branch=True in its coverage bootstrap.
bazel coverage --jobs=2 --local_resources=memory=6000 \
  --spawn_strategy=local --strategy=TestRunner=local \
  --extra_toolchains=@ci_coverage_runtime//:toolchain \
  --combined_report=lcov --nocache_test_results \
  --instrumentation_filter='^//(antiunification|extractor|tools)' \
  --test_output=errors "${targets[@]}" 2>&1 | tee ci-reports/bazel-coverage/tests.log
bazel_status=${PIPESTATUS[0]}
set -e
coverage_file=$(bazel info output_path)/_coverage/_coverage_report.dat
if [[ -f "$coverage_file" ]]; then
  cp "$coverage_file" ci-reports/bazel-coverage/coverage.lcov
else
  echo 'Bazel did not produce its branch coverage report' >&2
  exit 1
fi
printf '{"tools_exit_code":%s,"bazel_exit_code":%s}\n' \
  "$tools_status" "$bazel_status" > ci-reports/bazel-coverage/status.json
test "$tools_status" -eq 0 && test "$bazel_status" -eq 0
