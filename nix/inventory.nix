# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
{ pkgs, inputs }:
let
  inherit (pkgs) lib;
  toolchain = import ./toolchain.nix { inherit pkgs inputs; };
  inherit (toolchain) ddisasm gtirb souffle;
  bochs = toolchain.bochs-inventory;
  python = toolchain.inventory-tools.python;
  inventorySource = lib.cleanSourceWith {
    src = ../inventory;
    filter = path: type: type == "directory" || (lib.hasSuffix ".py" path || lib.hasSuffix ".dl" path);
  };
  inventoryCli = pkgs.stdenvNoCC.mkDerivation {
    name = "ixyk-transport-inventory";
    dontUnpack = true;
    nativeBuildInputs = [ pkgs.makeWrapper ];
    installPhase = ''
      mkdir -p "$out/lib/ixyk/extractor" "$out/bin"
      cp -r ${inventorySource} "$out/lib/ixyk/inventory"
      cp ${../extractor/artifact.py} "$out/lib/ixyk/extractor/artifact.py"
      for command in binary golden; do
        makeWrapper ${python}/bin/python3 "$out/bin/ixyk-inventory-$command" \
          --add-flags "-m inventory.$command" \
          --prefix PYTHONPATH : "$out/lib/ixyk:${gtirb}/share/python" \
          --prefix PATH : ${
            lib.makeBinPath [
              pkgs.binutils
              pkgs.zstd
              souffle
            ]
          }
      done
    '';
  };
  facts =
    pkgs.runCommand "ixyk-bochs-ddisasm-facts"
      {
        nativeBuildInputs = [ ddisasm ];
      }
      ''
        mkdir -p "$out"
        ddisasm ${bochs}/bin/bochs --ir "$out/bochs.gtirb" \
          --with-souffle-relations -j "$NIX_BUILD_CORES"
        sha256sum ${bochs}/bin/bochs > "$out/elf.sha256"
        ddisasm --version > "$out/ddisasm-version"
      '';
  inventory =
    pkgs.runCommand "ixyk-bochs-binary-inventory"
      {
        nativeBuildInputs = [ inventoryCli ];
      }
      ''
        mkdir -p "$out"
        ixyk-inventory-binary --gtirb ${facts}/bochs.gtirb \
          --decoder ${bochs}/share/ixyk/decoder --elf ${bochs}/bin/bochs \
          --source-revision ${inputs.bochs-src.rev} --output "$out/inventory.json"
      '';
  availability =
    pkgs.runCommand "ixyk-bochs-golden-availability"
      {
        nativeBuildInputs = [ inventoryCli ];
      }
      ''
        mkdir -p "$out"
        ixyk-inventory-golden --inventory ${inventory}/inventory.json \
          --golden ${../artifacts/golden} --output "$out/availability.json" > "$out/summary.json"
      '';
  tests =
    pkgs.runCommand "ixyk-inventory-tests"
      {
        nativeBuildInputs = [
          python
          pkgs.zstd
          souffle
        ];
      }
      ''
        mkdir -p inventory extractor artifacts
        cp -r ${inventorySource}/. inventory/
        cp ${../extractor/artifact.py} extractor/artifact.py
        ln -s ${../artifacts/golden} artifacts/golden
        python3 -m unittest inventory.inventory_test
        touch "$out"
      '';
  smoke =
    pkgs.runCommand "ixyk-inventory-ddisasm-smoke"
      {
        nativeBuildInputs = [
          pkgs.stdenv.cc
          ddisasm
          inventoryCli
          python
          pkgs.binutils
          pkgs.zstd
          souffle
        ];
      }
      ''
        export PYTHONPATH="${inventoryCli}/lib/ixyk:${gtirb}/share/python"
        python3 -m inventory.compiled_test \
          --source ${../inventory} --golden ${../artifacts/golden} \
          --output "$out" --cores "$NIX_BUILD_CORES"
      '';
in
{
  transport-inventory = inventoryCli;
  bochs-ddisasm-facts = facts;
  bochs-binary-inventory = inventory;
  bochs-availability = availability;
  inventory-tests = tests;
  inventory-smoke = smoke;
}
