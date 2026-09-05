# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ pkgs }:
let
  version = "4.31.0";
  releases = {
    aarch64-darwin = {
      platform = "darwin_aarch64";
      hash = "sha256-JkEFUAyKvfN7aP/gM5Cng+0lmAeAciJpjajdktbOCic=";
    };
    x86_64-linux = {
      platform = "linux";
      hash = "sha256-B6YzzI2RUcvAiCXqTN2lDUsCosnLhSwBMbEwRvScrX8=";
    };
  };
  release = releases.${pkgs.stdenv.hostPlatform.system};
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "lean";
  inherit version;
  src = pkgs.fetchurl {
    url = "https://github.com/leanprover/lean4/releases/download/v${version}/lean-${version}-${release.platform}.tar.zst";
    inherit (release) hash;
  };
  nativeBuildInputs = [ pkgs.zstd ]
    ++ pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.autoPatchelfHook pkgs.makeWrapper ];
  buildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [ pkgs.stdenv.cc.cc.lib ];
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    mkdir -p "$out"
    cp -a . "$out/"
    runHook postInstall
  '';
  postFixup = pkgs.lib.optionalString pkgs.stdenv.isLinux ''
    # The release linker defaults to /lib64/ld-linux-x86-64.so.2, which is
    # absent in the Nix-only container. Bind generated executables to this SDK's
    # packaged runtime as well as patching the SDK executables themselves.
    wrapProgram "$out/bin/ld.lld" --argv0 ld.lld \
      --append-flags "--dynamic-linker=${pkgs.glibc}/lib/ld-linux-x86-64.so.2 -rpath ${pkgs.glibc}/lib"
  '';
  doInstallCheck = pkgs.stdenv.isLinux;
  installCheckPhase = ''
    runHook preInstallCheck
    mkdir native-smoke
    cd native-smoke
    cat > lakefile.toml <<'EOF'
    name = "sdk_smoke"
    [[lean_exe]]
    name = "smoke"
    root = "Main"
    EOF
    echo 'def main : IO Unit := IO.println "sdk-native-ok"' > Main.lean
    ELAN= LEAN_PATH= "$out/bin/lake" build smoke
    test "$(.lake/build/bin/smoke)" = sdk-native-ok
    cd ..
    runHook postInstallCheck
  '';
  meta = {
    description = "Pinned upstream Lean compiler, Lake, and native SDK";
    homepage = "https://lean-lang.org/";
    license = pkgs.lib.licenses.asl20;
    platforms = builtins.attrNames releases;
    mainProgram = "lean";
  };
}
