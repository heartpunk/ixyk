# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

{ pkgs }:
let
  mbuild = pkgs.fetchFromGitHub {
    owner = "intelxed";
    repo = "mbuild";
    rev = "1b437e409221a2b5703b4d8896baa20d43e4ba1a";
    hash = "sha256-neccoffjGqXaund9QVo8CeI3QPn/ZB/EPLVZCN/wWTY=";
  };
in pkgs.stdenv.mkDerivation {
  pname = "ixyk-xed-enc2";
  version = "2026.08.23";
  src = pkgs.fetchFromGitHub {
    owner = "intelxed";
    repo = "xed";
    rev = "0bcb6237345c5066726dcc08b3d87928df3b5b26";
    hash = "sha256-Lhy7q41PM3TXOHJNco/vyTqDtdmE0S+BQJkd7r/vm3c=";
  };
  nativeBuildInputs = [ pkgs.python3 ];
  PYTHONPATH = "${mbuild}";
  postPatch = ''
    cp ${./xed_enc2_dispatch.py} pysrc/ixyk_enc2_dispatch.py
    substituteInPlace pysrc/enc2gen.py \
      --replace-fail '    msge("Writing encoder ' \
        '    __import__("ixyk_enc2_dispatch").emit(args.gendir, env, xeddb.recs); msge("Writing encoder '
    substituteInPlace xed_mbuild.py \
      --replace-fail 'enc2_config_t(32,32),' '# 64-bit bridge only: enc2_config_t(32,32),'
  '';
  buildPhase = ''
    runHook preBuild
    python3 mfile.py --enc2 -j "$NIX_BUILD_CORES" || {
      find obj -name ENC2-ERR.txt -exec cat {} \;
      exit 1
    }
    runHook postBuild
  '';
  installPhase = ''
    runHook preInstall
    mkdir -p "$out/include" "$out/lib" "$out/share"
    cp -r obj/wkit/include/xed "$out/include/"
    cp obj/libxed.a obj/enc2-m64-a64/libxed-enc2-m64-a64.a "$out/lib/"
    cp obj/ixyk-enc2-fuzz.h "$out/include/xed/"
    cp obj/ixyk-enc2-dispatch.h "$out/include/xed/"
    cp obj/ixyk-enc2-unmapped.json "$out/share/"
    runHook postInstall
  '';
}
