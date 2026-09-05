# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ nixpkgs, angr-nix, system }:
let
  pkgs = import nixpkgs {
    inherit system;
    overlays = [
      angr-nix.overlays.default
      (final: prev: {
        python312 = prev.python312.override (old: {
          packageOverrides = nixpkgs.lib.composeExtensions
            (old.packageOverrides or (_: _: { }))
            (pyFinal: pyPrev: {
              bitstring = pyPrev.bitstring.overridePythonAttrs (attrs: {
                # Keep correctness tests without the benchmark plugin's
                # unrelated Elasticsearch/notebook test dependencies.
                nativeCheckInputs = builtins.filter
                  (dep: nixpkgs.lib.getName dep != "pytest-benchmark")
                  attrs.nativeCheckInputs;
                pytestFlags = builtins.filter
                  (flag: flag != "--benchmark-disable")
                  (attrs.pytestFlags or [ ]);
                disabledTestPaths = (attrs.disabledTestPaths or [ ])
                  ++ [ "tests/test_benchmarks.py" ];
              });
            });
        });
      })
    ];
  };
  python = pkgs.python312.withPackages (ps: [
    ps.angr
    ps.claripy
    ps.coverage
    ps.hypothesis
    ps.ipykernel
    ps.pytest
    ps.unicorn
    ps.z3-solver
  ]);
  bazelVersion = nixpkgs.lib.removeSuffix "\n" (builtins.readFile ../.bazelversion);
  lean = import ./lean.nix { inherit pkgs; };
  leanVersion = nixpkgs.lib.removePrefix "leanprover/lean4:v"
    (nixpkgs.lib.removeSuffix "\n" (builtins.readFile ../lean-toolchain));
  # The pinned nixpkgs Bazel bootstrap fails in the Darwin linker. Materialize
  # the official release that Bazelisk previously fetched at command runtime.
  bazel = if pkgs.stdenv.isDarwin then pkgs.stdenvNoCC.mkDerivation {
    pname = "bazel";
    version = bazelVersion;
    src = pkgs.fetchurl {
      url = "https://github.com/bazelbuild/bazel/releases/download/${bazelVersion}/bazel-${bazelVersion}-darwin-arm64";
      hash = "sha256-LbiDcYRT8EN6e8tAjoidv4U5zcTWHI68OAehqI0C/wg=";
    };
    dontUnpack = true;
    dontFixup = true;
    installPhase = ''
      install -Dm755 "$src" "$out/bin/bazel"
    '';
  } else pkgs.bazel_9;
  environment = {
    ELAN = "";
    # rules_cc detects lld on the client; bind its path for remote link actions.
    BAZEL_LINKOPTS = if pkgs.stdenv.isLinux then
      "-B${pkgs.llvmPackages.lld}/bin" else "";
    IXYK_NIX_PYTHON_ROOT = "${python}";
    IXYK_NIX_XED_ROOT = if pkgs.stdenv.isLinux then
      "${import ../tools/xed_enc2.nix { inherit pkgs; }}" else "";
    IXYK_NIX_PYTHON_RUNTIME = "${pkgs.python312}";
    IXYK_NIX_LIBSTDCXX_ROOT =
      if pkgs.stdenv.isLinux then "${pkgs.stdenv.cc.cc.lib}" else "";
    PYTHONNOUSERSITE = "1";
    PYTHONSAFEPATH = "1";
  };
  devCheck = pkgs.writeShellScriptBin "ixyk-dev-check" ''
    exec ${python}/bin/python ${../tools/dev_check.py} "$@"
  '';
  packages = [
    python
    pkgs.actionlint
    pkgs.basedpyright
    pkgs.bashInteractive
    bazel
    pkgs.buildifier
    pkgs.coreutils
    # Bazel's version-selection launcher runs these before its binary wrapper.
    pkgs.findutils
    pkgs.gnugrep
    pkgs.git
    pkgs.jujutsu
    lean
    pkgs.ruff
    pkgs.stdenv.cc
    pkgs.zstd
    devCheck
  ];
  activation = pkgs.writeText "ixyk-dev-env.sh" (
    nixpkgs.lib.concatStringsSep "\n" (nixpkgs.lib.mapAttrsToList
      (name: value: "export ${name}=${nixpkgs.lib.escapeShellArg value}") environment)
    + "\nexport PATH=${nixpkgs.lib.makeBinPath packages}:\"$PATH\"\n"
  );
  launcher = pkgs.writeShellScriptBin "ixyk-dev" ''
    source ${activation}
    if [ "$#" -eq 0 ]; then
      exec ${pkgs.bashInteractive}/bin/bash --noprofile --norc
    fi
    exec "$@"
  '';
in
assert pkgs.bazel_9.version == bazelVersion;
assert lean.version == leanVersion;
{
  shell = pkgs.mkShell (environment // { inherit packages; });
  package = pkgs.buildEnv {
    name = "ixyk-dev-environment";
    meta.mainProgram = "ixyk-dev";
    paths = packages ++ [ launcher ];
    pathsToLink = [ "/bin" "/share" ];
    postBuild = ''
      mkdir -p "$out/etc"
      ln -s ${activation} "$out/etc/ixyk-dev-env.sh"
    '';
  };
}
