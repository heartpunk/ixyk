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
  };

  outputs = { nixpkgs, angr-nix, ... }:
    let
      systems = [ "aarch64-darwin" "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forAllSystems (system:
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
            ps.coverage
            ps.hypothesis
            ps.ipykernel
            ps.pytest
          ]);
        in {
          default = pkgs.mkShell {
            packages = [
              python
              pkgs.basedpyright
              (if pkgs.stdenv.isLinux then pkgs.bazel_9 else pkgs.bazelisk)
              pkgs.buildifier
              pkgs.git
              pkgs.jujutsu
              pkgs.ruff
            ];
            IXYK_NIX_PYTHON_ROOT = "${python}";
            IXYK_NIX_LIBSTDCXX_ROOT =
              if pkgs.stdenv.isLinux then "${pkgs.stdenv.cc.cc.lib}" else "";
            PYTHONNOUSERSITE = "1";
            PYTHONSAFEPATH = "1";
          };
        });
    };
}
