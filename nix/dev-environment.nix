# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ nixpkgs, ifrl, system }:
let
  pkgs = import nixpkgs { inherit system; };
  shared = import (ifrl.outPath + "/nix/clients/ixyk/nix/dev-environment.nix") {
    inherit nixpkgs ifrl system;
  };
  xedRoot = if pkgs.stdenv.isLinux then
    toString (import ../tools/xed_enc2.nix { inherit pkgs; }) else "";
  shell = shared.shell.overrideAttrs (_: { IXYK_NIX_XED_ROOT = xedRoot; });
  launcher = pkgs.writeShellScriptBin "ixyk-dev" ''
    source ${shared.package}/etc/ixyk-dev-env.sh
    export IXYK_NIX_XED_ROOT=${pkgs.lib.escapeShellArg xedRoot}
    if [ "$#" -eq 0 ]; then
      exec ${pkgs.bashInteractive}/bin/bash --noprofile --norc
    fi
    exec "$@"
  '';
  package = pkgs.symlinkJoin {
    name = "ixyk-dev-environment";
    paths = [ shared.package ];
    postBuild = ''
      rm -f "$out/bin/ixyk-dev"
      ln -s ${launcher}/bin/ixyk-dev "$out/bin/ixyk-dev"
    '';
    meta.mainProgram = "ixyk-dev";
  };
in shared // { inherit shell package; }
