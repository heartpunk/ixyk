"""Reject duplicate pip packages already supplied by the Nix environment."""

import importlib.metadata
import os
import re
from pathlib import Path


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def check() -> None:
    root = Path(__file__).resolve().parents[1]
    environment = Path(os.environ["IFRL_ANGR_ENVIRONMENT"])
    site = environment / "lib/python3.12/site-packages"
    installed = {
        normalized(distribution.metadata["Name"])
        for distribution in importlib.metadata.distributions(path=[str(site)])
    }
    if "angr" not in installed:
        raise ValueError(f"Angr is absent from {site}")
    requirements = {
        normalized(name)
        for name in re.findall(
            r"^([A-Za-z0-9_.-]+)==",
            (root / "extractor/requirements_linux_x86_64.txt").read_text(),
            re.MULTILINE,
        )
    }
    redirected = set(re.findall(
        r'ixyk_pypi_312_(\w+)\s*=\s*"shared_angr"',
        (root / "MODULE.bazel").read_text(),
    ))
    expected = installed & requirements
    if expected != redirected:
        raise ValueError(
            f"Nix/pip overlap drift: missing redirects={sorted(expected - redirected)}, "
            f"obsolete redirects={sorted(redirected - expected)}"
        )
    print(f"All {len(expected)} overlapping packages use the Nix environment.")


if __name__ == "__main__":
    check()
