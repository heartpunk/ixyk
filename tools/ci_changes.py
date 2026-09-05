"""Small, conservative dependency map for CI; unknown paths run every suite."""

import os
from pathlib import Path
import subprocess


SUITES = {"lint", "golden", "lean", "differential", "au"}


def affected(paths):
    selected = set()
    for path in paths:
        name = Path(path).name
        if (
            path.startswith("artifacts/golden/")
            and path != "artifacts/golden/README.md"
        ):
            selected |= {"golden", "lean"}
            continue
        if path.endswith(".md") or path in {
            "LICENSE",
            "CITATION.cff",
            ".github/FUNDING.yml",
        }:
            continue
        if (
            path.startswith(".github/")
            or path
            in {
                "tools/ci_changes.py",
                "tools/ci_changes_test.py",
                "flake.lock",
            }
            or path.endswith(".nix")
        ):
            selected |= SUITES
        elif path.endswith(".lean") or path in {"lean-toolchain", "lake-manifest.json"}:
            selected |= {"lean", "differential"}
        elif path.startswith("catalog/"):
            selected |= {"lint", "golden", "au"}
        elif path.startswith("extractor/"):
            selected |= {"lint", "au", "differential"}
        elif (
            path.startswith(("antiunification/", "third_party/"))
            or path == "tools/ci_reapi.py"
        ):
            selected |= {"lint", "au"}
        elif path in {"tools/ci_golden.py", "tools/ci_golden_test.py"}:
            selected |= {"lint", "golden"}
        elif path == "tools/ci_lean.py":
            selected |= {"lint", "lean"}
        elif path == "tools/lean_differential.py":
            selected |= {"lint", "differential"}
        elif (
            name in {"BUILD", "BUILD.bazel", "MODULE.bazel", "MODULE.bazel.lock"}
            or path.endswith(".bzl")
            or path in {".bazelrc", ".bazelversion"}
        ):
            selected |= {"lint", "au"}
        else:
            selected |= SUITES
    return selected


def changed_paths():
    event = os.environ.get("EVENT_NAME")
    base, head = os.environ.get("BASE_SHA", ""), os.environ.get("HEAD_SHA", "")
    if (
        event not in {"pull_request", "push", "merge_group"}
        or not base
        or not head
        or set(base) == {"0"}
    ):
        return None
    separator = "..." if event == "pull_request" else ".."
    try:
        data = subprocess.check_output(
            [
                "git",
                "diff",
                "--name-only",
                "--no-renames",
                "-z",
                f"{base}{separator}{head}",
                "--",
            ]
        )
    except subprocess.CalledProcessError:
        return None
    return [os.fsdecode(path) for path in data.split(b"\0") if path]


if __name__ == "__main__":
    paths = changed_paths()
    selected = SUITES if paths is None else affected(paths)
    print(
        "Selected suites:", ", ".join(sorted(selected)) or "none (documentation only)"
    )
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        for suite in sorted(SUITES):
            print(f"{suite}={str(suite in selected).lower()}", file=output)
