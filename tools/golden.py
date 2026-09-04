# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Update or verify the deliberately versioned golden artifact corpus."""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path, PurePosixPath
import sys
from typing import Literal, Protocol, cast


class _Options(Protocol):
    artifact: list[str]
    mode: Literal["check", "update"]
    workspace: Path | None


def _workspace(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    raw = os.environ.get("BUILD_WORKSPACE_DIRECTORY")
    if not raw:
        raise ValueError(
            "workspace unavailable; run with `bazel run` or pass --workspace"
        )
    return Path(raw).resolve()


def _runfile(relative: str) -> Path:
    direct = Path(relative)
    if direct.is_absolute():
        if direct.is_file():
            return direct
        raise FileNotFoundError(f"artifact source not found: {relative}")

    candidate = PurePosixPath(relative)
    if ".." in candidate.parts:
        raise ValueError(f"invalid runfile path: {relative!r}")

    root = os.environ.get("RUNFILES_DIR")
    if root:
        result = Path(root, *candidate.parts)
        if result.is_file():
            return result

    manifest = os.environ.get("RUNFILES_MANIFEST_FILE")
    if manifest:
        prefix = relative + " "
        for line in Path(manifest).read_text(encoding="utf-8").splitlines():
            if line.startswith(prefix):
                result = Path(line[len(prefix) :])
                if result.is_file():
                    return result

    raise FileNotFoundError(f"runfile not found: {relative}")


def _artifacts(specifications: list[str]) -> dict[PurePosixPath, Path]:
    result: dict[PurePosixPath, Path] = {}
    for specification in specifications:
        try:
            destination_text, source_text = specification.split("=", 1)
        except ValueError as error:
            raise ValueError(
                f"artifact must have DESTINATION=RUNFILE form: {specification!r}"
            ) from error
        destination = PurePosixPath(destination_text)
        if (
            destination.is_absolute()
            or not destination.parts
            or "." in destination.parts
            or ".." in destination.parts
        ):
            raise ValueError(f"invalid artifact destination: {destination_text!r}")
        if destination in result:
            raise ValueError(f"duplicate artifact destination: {destination}")
        result[destination] = _runfile(source_text)
    if not result:
        raise ValueError("at least one --artifact is required")
    return result


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _manifest(contents: dict[PurePosixPath, bytes]) -> bytes:
    lines = [
        f"{_digest(contents[path])}  {path.as_posix()}\n"
        for path in sorted(contents)
    ]
    return "".join(lines).encode()


def _write_if_changed(path: Path, data: bytes) -> bool:
    if path.is_file() and path.read_bytes() == data:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    temporary.replace(path)
    return True


def _update(directory: Path, contents: dict[PurePosixPath, bytes]) -> int:
    changed = [
        path.as_posix()
        for path in sorted(contents)
        if _write_if_changed(directory.joinpath(*path.parts), contents[path])
    ]
    if _write_if_changed(directory / "MANIFEST.sha256", _manifest(contents)):
        changed.append("MANIFEST.sha256")
    if changed:
        print("updated golden artifacts: " + ", ".join(changed))
    else:
        print("golden artifacts already current")
    return 0


def _check(directory: Path, contents: dict[PurePosixPath, bytes]) -> int:
    differences: list[str] = []
    for path in sorted(contents):
        committed = directory.joinpath(*path.parts)
        if not committed.is_file():
            differences.append(f"missing: {path.as_posix()}")
        elif committed.read_bytes() != contents[path]:
            differences.append(f"different: {path.as_posix()}")
    manifest = directory / "MANIFEST.sha256"
    expected_manifest = _manifest(contents)
    if not manifest.is_file():
        differences.append("missing: MANIFEST.sha256")
    elif manifest.read_bytes() != expected_manifest:
        differences.append("different: MANIFEST.sha256")
    if differences:
        for difference in differences:
            print(difference, file=sys.stderr)
        print(
            "golden artifacts are stale; run `bazel run //tools:update_golden`",
            file=sys.stderr,
        )
        return 1
    print(f"golden artifacts verified: {len(contents)} files")
    return 0


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--mode", choices=("check", "update"), required=True)
    _ = parser.add_argument("--artifact", action="append", default=[])
    _ = parser.add_argument("--workspace", type=Path)
    options = cast(_Options, cast(object, parser.parse_args(arguments)))
    try:
        workspace = _workspace(options.workspace)
        sources = _artifacts(options.artifact)
    except (FileNotFoundError, ValueError) as error:
        parser.error(str(error))
    directory = workspace / "artifacts" / "golden"
    contents = {path: source.read_bytes() for path, source in sources.items()}
    if options.mode == "update":
        return _update(directory, contents)
    return _check(directory, contents)


if __name__ == "__main__":
    raise SystemExit(main())
