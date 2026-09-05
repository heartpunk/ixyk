# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{
  description = "ixyk AMD64 semantic-model validation spike";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/e7a3ca8092b61ff85b6a45bf863ea2b2d6a661b3";
    angr-nix = {
      url = "github:heartpunk/angr-nix/3a7e87c627acdc1116e90892636b8e8d57d209d4";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    bochs-src = {
      url = "github:bochs-emu/Bochs/22432bc36e1a1c502bf5b181ad832f0710d93ba6";
      flake = false;
    };
    ddisasm-src = {
      url = "github:GrammaTech/ddisasm/4bc2beef7829f6b1cb062813ba5fd3d9081eae55";
      flake = false;
    };
    gtirb-src = {
      url = "github:GrammaTech/gtirb/98fececb52ba36d86fe6798303a1904574dd5bb6";
      flake = false;
    };
    gtirb-pprinter-src = {
      url = "github:GrammaTech/gtirb-pprinter/e479077282e2e1f0be3430e29d9bc8b7d6894579";
      flake = false;
    };
    libehp-src = {
      url = "github:GrammaTech/libehp/5e41e26b88d415f3c7d3eb47f9f0d781cc519459";
      flake = false;
    };
    souffle-src = {
      url = "github:souffle-lang/souffle/2.4";
      flake = false;
    };
    lief-src = {
      url = "github:lief-project/LIEF/0.16.6";
      flake = false;
    };
  };

  outputs =
    inputs@{ nixpkgs, angr-nix, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages.x86_64-linux =
        let
          args = {
            pkgs = import nixpkgs { system = "x86_64-linux"; };
            inherit inputs;
          };
        in
        (import ./nix/toolchain.nix args) // (import ./nix/inventory.nix args);
      checks.x86_64-linux = {
        inventory = inputs.self.packages.x86_64-linux.inventory-tests;
        inventory-smoke = inputs.self.packages.x86_64-linux.inventory-smoke;
      };
      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [
              angr-nix.overlays.default
              (final: prev: {
                python312 = prev.python312.override (old: {
                  packageOverrides = nixpkgs.lib.composeExtensions (old.packageOverrides or (_: _: { })) (
                    pyFinal: pyPrev: {
                      bitstring = pyPrev.bitstring.overridePythonAttrs (attrs: {
                        # Keep correctness tests without the benchmark plugin's
                        # unrelated Elasticsearch/notebook test dependencies.
                        nativeCheckInputs = builtins.filter (
                          dep: nixpkgs.lib.getName dep != "pytest-benchmark"
                        ) attrs.nativeCheckInputs;
                        pytestFlags = builtins.filter (flag: flag != "--benchmark-disable") (attrs.pytestFlags or [ ]);
                        disabledTestPaths = (attrs.disabledTestPaths or [ ]) ++ [ "tests/test_benchmarks.py" ];
                      });
                    }
                  );
                });
              })
            ];
          };
          python = pkgs.python312.withPackages (ps: [
            ps.angr
            ps.coverage
            ps.hypothesis
            ps.ipykernel
            ps.pytest
          ]);
        in
        {
          default = pkgs.mkShell {
            ELAN = "";
            packages = [
              python
              pkgs.basedpyright
              (if pkgs.stdenv.isLinux then pkgs.bazel_9 else pkgs.bazelisk)
              pkgs.buildifier
              pkgs.git
              pkgs.jujutsu
              pkgs.lean4
              pkgs.ruff
              pkgs.zstd
            ];
            IXYK_NIX_PYTHON_ROOT = "${python}";
            IXYK_NIX_ZSTD_ROOT = "${pkgs.zstd.bin}";
            IXYK_NIX_LIBSTDCXX_ROOT = if pkgs.stdenv.isLinux then "${pkgs.stdenv.cc.cc.lib}" else "";
            PYTHONNOUSERSITE = "1";
            PYTHONSAFEPATH = "1";
          };
        }
      );
    };
}
