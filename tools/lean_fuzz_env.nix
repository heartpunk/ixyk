let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  nixpkgs = builtins.getFlake "github:NixOS/nixpkgs/${lock.nodes.nixpkgs.locked.rev}";
  pkgs = import nixpkgs { };
  ayxg = pkgs.python312Packages.buildPythonPackage {
    pname = "ayxg";
    version = "0.1.0";
    src = ../.dependencies/ayxg;
    pyproject = true;
    build-system = [ pkgs.python312Packages.setuptools ];
    doCheck = false;
  };
in pkgs.python312.withPackages (ps: [ ps.hypothesis ps.z3-solver ayxg ])
