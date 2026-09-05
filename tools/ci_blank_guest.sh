#!/usr/bin/env bash
# Run inside the disposable Ubuntu guest as its unprivileged onboarding user.
set -euo pipefail
cd "$HOME"
cat /etc/os-release
free -b
nproc
# These bootstrap tools are part of the checksum-pinned Ubuntu cloud image.
command -v curl xz tar
test -s /etc/ssl/certs/ca-certificates.crt
test ! -e /nix
for tool in nix bazel lean nativelink; do
  if command -v "$tool"; then
    echo "Unexpected preinstalled tool: $tool" >&2
    exit 1
  fi
done
echo 'Blank guest verified: no Nix store or project tools.'
curl --fail --location --retry 3 --connect-timeout 30 --max-time 300 https://releases.nixos.org/nix/nix-2.31.2/nix-2.31.2-x86_64-linux.tar.xz --output nix.tar.xz
echo 'd1f67c86eed016214864ba08bfb9529c307aea7e8fafb74853f96fcc3bfd8a60  nix.tar.xz' | sha256sum --check
tar -xJf nix.tar.xz
sudo mkdir -m 0755 /nix
sudo chown "$(id -un)" /nix
./nix-2.31.2-x86_64-linux/install --no-daemon --no-channel-add
export PATH="$HOME/.nix-profile/bin:/usr/bin:/bin"
mkdir -p "$HOME/.config/nix"
cat > "$HOME/.config/nix/nix.conf" <<'CONFIG'
experimental-features = nix-command flakes
accept-flake-config = true
max-jobs = 1
cores = 4
CONFIG
mkdir source
tar -xf source.tar -C source
cd source
nix develop --print-build-logs --command python tools/dev_smoke.py
nix build .#dev-environment --out-link "$HOME/materialized"
env -i HOME="$HOME" PATH=/usr/bin:/bin \
  "$HOME/materialized/bin/ixyk-dev" python tools/dev_smoke.py
nix develop --command python tools/reapi_smoke.py
df -h /
echo 'Blank guest onboarding and REAPI validation passed.'
