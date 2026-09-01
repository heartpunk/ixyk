"""Shared hermetic native-library bootstrap for Bazel Python targets."""

from __future__ import annotations

import ctypes
import os
from pathlib import Path


_LIBSTDCXX_RLOCATION_ENV = "GHOT_LIBSTDCXX_RLOCATION"


def runfiles_root() -> Path:
    raw_root = os.environ.get("RUNFILES_DIR") or os.environ.get("TEST_SRCDIR")
    if raw_root:
        return Path(raw_root).absolute()

    for candidate in Path(__file__).absolute().parents:
        if candidate.name.endswith(".runfiles"):
            return candidate
    raise RuntimeError("Bazel runfiles root is unavailable")


def preload_libstdcxx() -> Path:
    raw_rlocation = os.environ.get(_LIBSTDCXX_RLOCATION_ENV)
    if not raw_rlocation:
        raise RuntimeError(f"{_LIBSTDCXX_RLOCATION_ENV} is required")

    root = runfiles_root()
    relative_runfile = Path(raw_rlocation)
    if relative_runfile.is_absolute() or ".." in relative_runfile.parts:
        raise RuntimeError(f"invalid libstdc++ runfile path: {raw_rlocation}")

    library_runfile = (root / relative_runfile).absolute()
    if not library_runfile.is_relative_to(root):
        raise RuntimeError(f"libstdc++ escaped Bazel runfiles: {library_runfile}")
    if not library_runfile.is_file():
        raise RuntimeError(f"declared libstdc++ runfile is missing: {library_runfile}")

    library_target = library_runfile.resolve()
    # Local Bazel runfiles preserve the repository rule's symlink into the
    # immutable Nix store. REAPI workers instead materialize the same declared
    # file from the CAS as a regular file inside the action's runfiles tree.
    # Accept that standard materialization, but keep rejecting symlinks whose
    # target did not originate in the Nix store.
    if library_target != library_runfile and not library_target.is_relative_to(
        Path("/nix/store")
    ):
        raise RuntimeError(
            f"libstdc++ does not resolve to the immutable Nix store: {library_target}"
        )

    _ = ctypes.CDLL(str(library_runfile), mode=ctypes.RTLD_GLOBAL)
    return library_runfile
