# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ pkgs, development, reapi }:
let
  entrypoint = pkgs.writeShellScript "ixyk-container" ''
    set -euo pipefail
    uid=$(${pkgs.coreutils}/bin/id -u)
    gid=$(${pkgs.coreutils}/bin/id -g)
    # Materialize NSS records for the host UID, including inside REAPI actions.
    # This container has one user and no login service or privilege helper.
    {
      printf 'root:x:0:0:root:/tmp:/bin/sh\n'
      if [ "$uid" != 0 ]; then
        printf 'ixyk:x:%s:%s:Developer:/tmp:/bin/sh\n' "$uid" "$gid"
      fi
    } > /run/ixyk/passwd
    {
      printf 'root:x:0:\n'
      if [ "$gid" != 0 ]; then
        printf 'ixyk:x:%s:\n' "$gid"
      fi
    } > /run/ixyk/group
    exec ${development}/bin/ixyk-dev "$@"
  '';
in
pkgs.dockerTools.buildLayeredImage {
  name = "ghcr.io/heartpunk/ixyk-dev";
  tag = "latest";
  contents = [
    development
    reapi
    pkgs.cacert
    pkgs.dockerTools.binSh
    pkgs.dockerTools.usrBinEnv
    pkgs.dockerTools.fakeNss
  ];
  extraCommands = ''
    mkdir -p tmp workspace run/ixyk cache
    chmod 1777 tmp run/ixyk cache
    chmod 0777 workspace
    rm etc/passwd etc/group
    ln -s /run/ixyk/passwd etc/passwd
    ln -s /run/ixyk/group etc/group
  '';
  config = {
    Labels."org.opencontainers.image.source" = "https://github.com/heartpunk/ixyk";
    Entrypoint = [ "${entrypoint}" ];
    WorkingDir = "/workspace";
    User = "1000:1000";
    Env = [
      "PATH=/bin"
      "HOME=/tmp"
      "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
      "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
    ];
  };
}
