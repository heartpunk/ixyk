"""Resolve explicit CLI inputs in ordinary invocations and Bazel runfiles."""

from pathlib import Path


def resolve(value: str | Path) -> Path:
    path = Path(value)
    if path.exists():
        return path.absolute()
    from python.runfiles import runfiles

    resolved = runfiles.Create().Rlocation(str(value))
    if resolved is None or not Path(resolved).is_file():
        raise FileNotFoundError(value)
    # Preserve launcher/runfiles adjacency: resolving the final symlink can
    # turn a Lean executable launcher into its shared trampoline binary.
    return Path(resolved).absolute()
