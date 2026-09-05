# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later
{ pkgs, inputs }:
let
  inherit (pkgs) lib;
  cmakePackage =
    name: src: extra:
    pkgs.stdenv.mkDerivation (
      {
        pname = name;
        version = builtins.substring 0 12 src.rev;
        inherit src;
        nativeBuildInputs = [
          pkgs.cmake
          pkgs.ninja
          pkgs.pkg-config
        ];
        cmakeFlags = [ "-DCMAKE_POLICY_VERSION_MINIMUM=3.5" ];
        enableParallelBuilding = true;
      }
      // extra
    );
  gtirb = cmakePackage "gtirb" inputs.gtirb-src {
    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
      pkgs.protobuf_21
      pkgs.python3
    ];
    buildInputs = [
      pkgs.boost186
      pkgs.protobuf_21
    ];
    cmakeFlags = [
      "-DCMAKE_POLICY_VERSION_MINIMUM=3.5"
      "-DGTIRB_ENABLE_TESTS=OFF"
      "-DGTIRB_RUN_CLANG_TIDY=OFF"
      "-DGTIRB_DOCUMENTATION=OFF"
      "-DGTIRB_ENABLE_MYPY=OFF"
      "-DGTIRB_JAVA_API=OFF"
      "-DGTIRB_CL_API=OFF"
    ];
    postInstall = ''
      mkdir -p "$out/share/python"
      cp -r python/gtirb "$out/share/python/"
    '';
  };
  pprinter = cmakePackage "gtirb-pprinter" inputs.gtirb-pprinter-src {
    postPatch = ''
      substituteInPlace src/gtirb_pprinter/CMakeLists.txt \
        --replace-fail 'add_subdirectory(test)' 'if(GTIRB_PPRINTER_ENABLE_TESTS)
      add_subdirectory(test)
      endif()'
    '';
    buildInputs = [
      gtirb
      pkgs.boost186
      pkgs.capstone
      pkgs.protobuf_21
    ];
    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
      pkgs.pkg-config
      pkgs.capstone
    ];
    cmakeFlags = [ "-DGTIRB_PPRINTER_ENABLE_TESTS=OFF" ];
  };
  ehp = cmakePackage "libehp" inputs.libehp-src {
    postPatch = ''
      sed -i '1i #include <cstdint>' include/ehp.hpp
    '';
  };
  souffle = pkgs.souffle.overrideAttrs (old: {
    version = "2.4";
    src = inputs.souffle-src;
    patches = [ ];
    cmakeFlags = [
      "-DSOUFFLE_GIT=OFF"
      "-DSOUFFLE_DOMAIN_64BIT=ON"
    ];
    postFixup = "";
  });
  lief = pkgs.lief.overrideAttrs (old: {
    version = "0.16.6";
    src = inputs.lief-src;
    patches = [
      (pkgs.fetchurl {
        url = "https://github.com/lief-project/LIEF/commit/6877ce7aba037074954bc63102c9d45b73d63b0b.patch";
        hash = "sha256-5kCm5Fm4PcAcj3Qk4Vinlkjr9eLeWrjKP+Qpyuc246s=";
      })
    ];
    outputs = [ "out" ];
    cmakeFlags = [
      "-DLIEF_PYTHON_API=OFF"
      "-DLIEF_EXAMPLES=OFF"
      "-DBUILD_SHARED_LIBS=OFF"
      "-DLIEF_MACHO=OFF"
      "-DLIEF_DEX=OFF"
      "-DLIEF_OAT=OFF"
      "-DLIEF_VDEX=OFF"
      "-DLIEF_ART=OFF"
    ];
    postBuild = "";
    postInstall = "";
  });
  ddisasm = cmakePackage "ddisasm" inputs.ddisasm-src {
    postPatch = ''
      sed -i '1i #include <cstdint>' src/gtirb-builder/ArchiveReader.h
      substituteInPlace src/gtirb-builder/PeReader.cpp \
        --replace-fail 'fs::change_extension(Import.name(), "")' 'fs::path(Import.name()).replace_extension("")'
    '';
    nativeBuildInputs = [
      pkgs.cmake
      pkgs.ninja
      pkgs.pkg-config
      souffle
      pkgs.capstone
      pkgs.mcpp
    ];
    buildInputs = [
      gtirb
      pprinter
      ehp
      lief
      pkgs.boost186
      pkgs.capstone
      pkgs.protobuf_21
    ];
    cmakeFlags = [
      "-DDDISASM_ENABLE_TESTS=OFF"
      "-DDDISASM_GENERATE_MANY=ON"
      "-DDDISASM_ARM_32=OFF"
      "-DDDISASM_ARM_64=OFF"
      "-DDDISASM_MIPS_32=OFF"
      "-DDDISASM_X86_32=OFF"
      "-DDDISASM_BUILD_REVISION=${inputs.ddisasm-src.rev}"
    ];
  };
  bochs =
    (pkgs.bochs.override {
      enableSDL2 = false;
      enableTerm = false;
      enableWx = false;
      enableX11 = false;
    }).overrideAttrs
      (old: {
        version = builtins.substring 0 12 inputs.bochs-src.rev;
        src = inputs.bochs-src;
        sourceRoot = "source/bochs";
        patches = [ ];
        # Guest EVEX support is independent of the host compiler target.
        configureFlags = [
          "--with-nogui"
          "--disable-docbook"
          "--disable-readline"
          "--enable-x86-64"
          "--enable-cpu-level=6"
          "--enable-avx"
          "--enable-evex"
          "--enable-amx"
          "--disable-handlers-chaining"
          "--disable-trace-linking"
        ];
        preConfigure = ''
          export CFLAGS="-O2 -g -march=x86-64 -mtune=generic"
          export CXXFLAGS="$CFLAGS"
          export LDFLAGS="-Wl,--emit-relocs"
        '';
        dontStrip = true;
        postInstall = ''
          mkdir -p "$out/share/ixyk"
          cp config.h config.log "$out/share/ixyk/"
          cp -r cpu/decoder "$out/share/ixyk/decoder"
          printf '%s\n' '${inputs.bochs-src.rev}' > "$out/share/ixyk/source-revision"
          $CXX --version > "$out/share/ixyk/compiler-version"
        '';
        passthru = (old.passthru or { }) // {
          source = inputs.bochs-src;
        };
      });
  python = pkgs.python3.withPackages (ps: [
    ps.intervaltree
    ps.protobuf
    ps.sortedcontainers
    ps.networkx
    ps.typing-extensions
  ]);

in
{
  inherit ddisasm gtirb souffle;
  bochs-inventory = bochs;
  inventory-tools = pkgs.symlinkJoin {
    name = "ixyk-inventory-tools";
    paths = [
      ddisasm
      python
      pkgs.zstd
      pkgs.binutils
      pkgs.ast-grep
    ];
    passthru = {
      inherit python;
      gtirbPythonPath = "${gtirb}/share/python";
    };
  };
}
