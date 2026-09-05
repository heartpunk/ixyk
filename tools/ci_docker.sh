#!/usr/bin/env bash
set -euo pipefail

IXYK_UID=$(id -u)
IXYK_GID=$(id -g)
export IXYK_UID IXYK_GID
# Exercise stock Ubuntu's restriction, with an exception for this container.
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=1
sudo apparmor_parser -r tools/docker.apparmor
export IXYK_APPARMOR_PROFILE=ixyk-dev
docker compose config --quiet
nix build .#docker-image --out-link "$RUNNER_TEMP/ixyk-image" --print-build-logs
docker load --input "$RUNNER_TEMP/ixyk-image"
docker image inspect ghcr.io/heartpunk/ixyk-dev:latest --format '{{.Size}} bytes'

# Only the checkout is mounted: no host Nix store, daemon, or Docker socket.
docker compose run --rm -T dev bash -euo pipefail -c '
  if command -v nix; then
    printf "%s\n" "Unexpected Nix executable in the runtime image." >&2
    exit 1
  fi
  test ! -e /nix/var/nix/daemon-socket/socket
  test "$(id -u)" != 0
  (cd /tmp && bazel --version)
  python tools/dev_smoke.py
  python tools/reapi_smoke.py --launcher ixyk-reapi
  touch .ixyk-container-owner-check
'
test "$(stat -c %u .ixyk-container-owner-check)" = "$(id -u)"
rm .ixyk-container-owner-check

bash tools/ci_reapi_cluster.sh

# Preserve the tested image for Docker-only users to download and load.
cp -L "$RUNNER_TEMP/ixyk-image" "$RUNNER_TEMP/ixyk-dev.tar.gz"
