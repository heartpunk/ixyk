{ pkgs }: {
  leanRuntime = pkgs.runCommand "lean-bazel-glibc-runtime" {} ''
    mkdir -p "$out/lib"
    find ${pkgs.glibc.out}/lib -maxdepth 1 \
      \( -type f -o -type l \) -name '*.so*' \
      -exec cp -L {} "$out/lib/" \;
  '';
  leanCompileTools = pkgs.pkgsStatic.cadical.overrideAttrs (_: {
    version = "2.1.2";
    # Upstream's legacy API test fails under musl.
    doCheck = false;
    src = pkgs.fetchFromGitHub {
      owner = "arminbiere";
      repo = "cadical";
      rev = "rel-2.1.2";
      hash = "sha256-fhvQd/f8eaw7OA2/XoOTVOnQxSSxUvugu6VWo2nmpQ0=";
    };
  });
}
