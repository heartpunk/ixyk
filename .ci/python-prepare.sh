#!/usr/bin/env bash
set -euo pipefail
# Worker tests exercise the runtime pinned by IXYK, independently of CI's main ref.
ifrl_source=$(nix eval --impure --raw --no-write-lock-file \
  --expr '(builtins.getFlake (toString ./.)).inputs.ifrl.outPath')
printf 'PYTHONPATH=%s/python%s\n' "$ifrl_source" "${PYTHONPATH:+:$PYTHONPATH}" >> "$GITHUB_ENV"
