let
  lock = builtins.fromJSON (builtins.readFile ../flake.lock);
  nixpkgs = builtins.getFlake "github:NixOS/nixpkgs/${lock.nodes.nixpkgs.locked.rev}";
  pkgs = import nixpkgs { };
in pkgs.python312.withPackages (ps: [ ps.hypothesis ps.z3-solver ])
