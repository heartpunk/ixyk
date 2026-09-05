"""Regenerate or verify Ixyk's Lake-authoritative Bazel projection.

Run on Linux in `nix develop`. The exporter and renderer are built by Bazel;
Lake-produced module/native artifacts never become production build inputs.
"""

import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def bazel(*args: str, capture: bool = False) -> str:
    command = [os.environ.get("BAZEL", "bazel"), "--batch"]
    if args[0] in ("build", "run", "test"):
        launcher = os.environ.get("IXYK_REAPI") or shutil.which("ixyk-reapi")
        command = [launcher] if launcher else ["nix", "run", ".#reapi", "--"]
    if args[0] == "info":
        args = (*args, "--config=reapi-local")
    result = subprocess.run(
        [*command, *args],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout or ""


def native_platform() -> str:
    key = (platform.system(), platform.machine())
    if key != ("Linux", "x86_64"):
        raise RuntimeError("Ixyk projection generation requires an x86-64 Linux client")
    return "x86_64-linux"


def stage_sources(destination: Path) -> None:
    destination.mkdir()
    sources = [
        *ROOT.glob("*.lean"),
        *ROOT.glob("Ixyk/**/*.lean"),
        ROOT / "lean-toolchain",
    ]
    for optional in ("lakefile.toml", "lake-manifest.json"):
        if (ROOT / optional).exists():
            sources.append(ROOT / optional)
    for source in sources:
        target = destination / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def regenerate() -> None:
    destination = ROOT / "lean" / native_platform()
    destination.mkdir(parents=True, exist_ok=True)
    installed = [
        ROOT / "BUILD.bazel",
        destination / "lake-authority.json",
        destination / "projection-lock.json",
    ]
    previous = {
        path: path.read_bytes() if path.exists() else None for path in installed
    }
    with tempfile.TemporaryDirectory(prefix="ixyk-lean-projection-") as temporary:
        candidate = Path(temporary)
        stage_sources(candidate / "workspace")
        bazel(
            "run",
            "@lean_bazel//tools:export_lake_bootstrap",
            "--",
            "--workspace",
            str(candidate / "workspace"),
            str(candidate / "lake-authority.json"),
        )
        bazel(
            "run",
            "@lean_bazel//tools:render_bazel_bootstrap",
            "--",
            str(candidate / "lake-authority.json"),
            str(candidate / "BUILD.bazel"),
        )
        subprocess.run(
            ["buildifier", "-mode=check", str(candidate / "BUILD.bazel")], check=True
        )
        try:
            shutil.copyfile(candidate / "BUILD.bazel", installed[0])
            shutil.copyfile(candidate / "lake-authority.json", installed[1])
            if not installed[2].exists():
                installed[2].write_text("{}\n")
            # Regeneration doesn't consume the committed lock. Production
            # targets always require the independently verified freshness stamp.
            bazel(
                "build",
                "//:lake_authority_projection_freshness",
                "--output_groups=regeneration",
            )
            output = Path(bazel("info", "bazel-bin", capture=True).strip())
            generated = (
                output / "projection-freshness/lake_authority_projection_freshness"
            )
            for name in ("BUILD.bazel", "lake-authority.json"):
                if (candidate / name).read_bytes() != (generated / name).read_bytes():
                    raise ValueError(
                        f"independent projection regeneration disagrees: {name}"
                    )
            shutil.copyfile(generated / "candidate-lock.json", installed[2])
            bazel("build", "//:lake_authority_projection_freshness")
        except BaseException:
            for path, content in previous.items():
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.write_bytes(content)
            raise
    print(f"Regenerated and verified {native_platform()} Lake projection")


def emit_candidate(destination: Path) -> None:
    """Emit build outputs for transfer to the source-authoritative workspace."""
    if destination.exists():
        raise FileExistsError(destination)
    bazel(
        "build",
        "//:lake_authority_projection_freshness",
        "--output_groups=regeneration",
    )
    output = Path(bazel("info", "bazel-bin", capture=True).strip())
    generated = output / "projection-freshness/lake_authority_projection_freshness"
    destination.mkdir(parents=True)
    for source, target in (
        ("lake-authority.json", "lake-authority.json"),
        ("BUILD.bazel", "BUILD.bazel"),
        ("candidate-lock.json", "projection-lock.json"),
    ):
        shutil.copyfile(generated / source, destination / target)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--candidate-dir", type=Path)
    args = parser.parse_args()
    native_platform()
    if args.candidate_dir:
        emit_candidate(args.candidate_dir.absolute())
    elif args.check:
        bazel("build", "//:lake_authority_projection_freshness")
    else:
        regenerate()


if __name__ == "__main__":
    main()
