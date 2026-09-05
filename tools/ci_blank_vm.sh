#!/usr/bin/env bash
# Host-side harness: only the source archive crosses into the fresh guest.
set -euo pipefail
source_root=$PWD
state=$(mktemp -d "${RUNNER_TEMP:-/tmp}/ixyk-blank-vm.XXXXXX")
qemu_pid=
cleanup() {
  if [[ -n "$qemu_pid" ]]; then
    sudo kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  tail -n 80 "$state/serial.log" 2>/dev/null || true
  df -h "$state"
}
trap cleanup EXIT
sudo test -c /dev/kvm
echo 'Installing VM host tools (network timeout: 30 seconds; retries: 3).'
apt_options=(-o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o Acquire::Retries=3)
sudo apt-get "${apt_options[@]}" update -qq
sudo apt-get "${apt_options[@]}" install -y --no-install-recommends qemu-system-x86 qemu-utils cloud-image-utils
cd "$state"
echo 'Downloading the pinned Ubuntu cloud image.'
curl --fail --location --retry 3 --connect-timeout 30 --max-time 300 \
  https://cloud-images.ubuntu.com/jammy/20260829/jammy-server-cloudimg-amd64.img \
  --output base.img
echo '46c966c646ab2e73af6ce8a2bdd20fefbc20f851794bbd46de31d2d1103b72c0  base.img' | sha256sum --check
qemu-img create -f qcow2 -F qcow2 -b "$state/base.img" guest.qcow2 32G
ssh-keygen -q -t ed25519 -N '' -f key
cat > user-data <<CONFIG
#cloud-config
users:
  - name: newcomer
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat key.pub)
ssh_pwauth: false

CONFIG
printf 'instance-id: ixyk-blank-ci\nlocal-hostname: ixyk-blank-ci\n' > meta-data
cloud-localds seed.img user-data meta-data
# No host filesystem/Nix store mount, forwarded agent, or credentials.
echo 'Booting blank Ubuntu guest (4 CPUs, 10 GiB RAM).'
: > serial.log
sudo qemu-system-x86_64 -enable-kvm -cpu host -smp 4 -m 10240 \
  -drive file=guest.qcow2,if=virtio,format=qcow2 \
  -drive file=seed.img,if=virtio,format=raw,readonly=on \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22 \
  -device virtio-net-pci,netdev=net0 -display none -serial file:serial.log \
  -monitor none -no-reboot &
qemu_pid=$!
ssh_options=(-i "$state/key" -p 2222 -o IdentitiesOnly=yes -o IdentityAgent=none
  -o UserKnownHostsFile="$state/known_hosts" -o StrictHostKeyChecking=accept-new
  -o ConnectTimeout=5 -o BatchMode=yes)
ready=false
for ((attempt=0; attempt<120; attempt++)); do
  kill -0 "$qemu_pid"
  if ssh "${ssh_options[@]}" newcomer@127.0.0.1 true 2>/dev/null; then
    ready=true
    break
  fi
  if ((attempt % 15 == 0)); then
    echo "Waiting for guest SSH (attempt $attempt/120)."
    tail -n 3 serial.log || true
  fi
  sleep 2
done
[[ "$ready" == true ]]
echo 'Guest SSH ready; waiting for cloud-init.'
ssh "${ssh_options[@]}" newcomer@127.0.0.1 'sudo timeout --kill-after=5 180 cloud-init status --wait'
git -C "$source_root" archive HEAD > source.tar
ssh "${ssh_options[@]}" newcomer@127.0.0.1 'cat > source.tar' < source.tar
echo 'Starting Nix bootstrap and onboarding tests inside the guest.'
ssh "${ssh_options[@]}" newcomer@127.0.0.1 'bash -s' < "$source_root/tools/ci_blank_guest.sh"
