# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ pkgs, development }:
let
  # NativeLink masks sibling workspaces but retains the host proc mount.
  # Give PID-aware tools a proc mount matching their action's PID namespace.
  entrypoint = pkgs.writeShellScript "ixyk-reapi-action" ''
    exec ${pkgs.util-linux}/bin/unshare --user --map-current-user --mount \
      --pid --fork --mount-proc --kill-child -- "$@"
  '';
  nativelink = pkgs.stdenvNoCC.mkDerivation {
    pname = "nativelink";
    version = "1.6.4";
    src = pkgs.fetchurl {
      url = "https://github.com/TraceMachina/nativelink/releases/download/v1.6.4/nativelink-1.6.4-x86_64-unknown-linux-musl.tar.gz";
      hash = "sha256-gfAUD30vFnyHXi7xzngl2SrIbAmzVUQal3K1d6DD870=";
    };
    sourceRoot = ".";
    installPhase = ''
      install -Dm755 "$(find . -type f -name nativelink -print -quit)" "$out/bin/nativelink"
    '';
    dontFixup = true;
  };
in pkgs.writeShellScriptBin "ixyk-reapi" ''
  exec ${development}/bin/ixyk-dev ${pkgs.python312}/bin/python ${../tools/reapi.py} \
    --nativelink ${nativelink}/bin/nativelink \
    --entrypoint ${entrypoint} "$@"
''
