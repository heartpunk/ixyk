"""Verify Linux REAPI execution, cache reuse, and Lean graph freshness.

Run on Linux in `nix develop` against the pinned Ixyk REAPI service. Output and scratch directories must be outside the
source tree. Reports describe the tested source contents, including local edits.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    "//:lake_authority_modules",
    "//tools:ixyk_golden_check",
    "//tools:ixyk_differential_eval",
]
EXCLUDED = {
    ".git",
    ".jj",
    ".lake",
    ".direnv",
    ".hypothesis",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".bazelrc.local",
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_files(root: Path) -> list[Path]:
    result = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(
            d for d in dirs if d not in EXCLUDED and not d.startswith("bazel-")
        )
        for name in sorted(files):
            if name in EXCLUDED or name.startswith("bazel-") or name.endswith(".pyc"):
                continue
            path = Path(directory) / name
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(
                    f"source symlink escapes the archive: {path.relative_to(root)}"
                )
            result.append(path)
    return sorted(result)


def snapshot(source: Path, destination: Path) -> dict[str, str]:
    inventory = {}
    for path in source_files(source):
        relative = path.relative_to(source)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        shutil.copymode(path, target)
        inventory[str(relative)] = digest(target)
    return inventory


def remove_tree(root: Path) -> None:
    """Remove owned Bazel outputs, including read-only remote output directories."""
    if root.is_symlink():
        raise ValueError("refusing to traverse a symlink as an output directory")
    for directory, _, _ in os.walk(root, followlinks=False):
        # Change directories only: files can be hardlinked into caches, and
        # symlinked repositories may refer to immutable Nix store outputs.
        os.chmod(directory, 0o700)
    shutil.rmtree(root)


def run(command: list[str], cwd: Path, log: Path, env=None, expected=0) -> str:
    with log.open("w") as stream:
        result = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
    if result.returncode != expected:
        raise RuntimeError(
            f"expected exit {expected}, got {result.returncode}; inspect {log}"
        )
    return log.read_text()


def actions(path: Path) -> list[dict]:
    raw = path.read_text()
    decoder = json.JSONDecoder()
    records = []
    position = 0
    while position < len(raw):
        if raw[position].isspace():
            position += 1
            continue
        value, position = decoder.raw_decode(raw, position)
        records.append(value)
    return records


def module_actions(path: Path) -> list[dict]:
    return [
        a
        for a in actions(path)
        if a.get("mnemonic") == "LeanCompile"
        and a.get("targetLabel", "").startswith("//:module__ixyk__")
    ]


def artifact_hashes(output: Path) -> dict[str, str]:
    files = [
        *output.glob("olean-root/**/*.olean"),
        output / "bin/ixyk-golden-check",
        output / "bin/ixyk-differential-eval",
    ]
    return {str(p.relative_to(output)): digest(p) for p in sorted(files) if p.is_file()}


def experiment(output: Path, scratch: Path, jobs: int, endpoint: str) -> dict:
    baseline = scratch / "source"
    inventory = snapshot(ROOT, baseline)
    source_hash = hashlib.sha256(
        json.dumps(inventory, sort_keys=True).encode()
    ).hexdigest()
    (output / "source-files.json").write_text(json.dumps(inventory, indent=2) + "\n")
    report = {
        "schema_version": 1,
        "status": "INCOMPLETE",
        "source_tree_sha256": source_hash,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        },
        "lean_toolchain": (baseline / "lean-toolchain").read_text().strip(),
        "jobs": jobs,
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    bazel_bin = os.environ.get("BAZEL", "bazel")
    cache = scratch / "cache"
    cache.mkdir()

    def command(root: Path, *args: str) -> list[str]:
        flags = ["--config=reapi-local"]
        if args[0] in ("build", "test"):
            flags += [f"--remote_executor={endpoint}", f"--remote_cache={endpoint}",
                      "--remote_local_fallback=false", "--spawn_strategy=remote",
                      "--remote_timeout=900", f"--jobs={jobs}"]
        return [bazel_bin, "--batch", f"--output_user_root={root}", args[0],
                *flags, *args[1:]]

    def build(workspace: Path, root: Path, name: str) -> tuple[Path, list[dict]]:
        start = time.monotonic()
        run(
            command(
                root,
                "build",
                *TARGETS,
                f"--jobs={jobs}",
                f"--repository_cache={cache / 'repositories'}",
                "--remote_download_outputs=all",
                "--remote_accept_cached=" + ("false" if name == "cold" else "true"),
                f"--execution_log_json_file={output / (name + '-actions.json')}",
                "--noshow_progress",
            ),
            workspace,
            output / (name + ".log"),
        )
        report[name + "_seconds"] = round(time.monotonic() - start, 3)
        bin_path = subprocess.check_output(
            command(root, "info", "bazel-bin"), cwd=workspace, text=True
        ).strip()
        return Path(bin_path), module_actions(output / (name + "-actions.json"))

    first = scratch / "checkout-a"
    snapshot(baseline, first)
    first_root = scratch / "output-a"
    first_bin, cold = build(first, first_root, "cold")
    expected = {
        "//:module__ixyk__" + name.replace(".", "_d_")
        for name in (
            "Ixyk",
            "Ixyk.Artifact",
            "Ixyk.DifferentialEval",
            "Ixyk.GoldenCheck",
            "Ixyk.QfAbv.Syntax",
            "Ixyk.QfAbv.Semantics",
            "Ixyk.QfAbv.Sts",
        )
    }
    if len(cold) != 7 or {a["targetLabel"] for a in cold} != expected or any(
        a.get("cacheHit") for a in cold
    ):
        raise AssertionError(
            "cold build did not execute exactly the seven Ixyk module actions"
        )
    if any(a.get("runner") != "remote" for a in cold):
        raise AssertionError("consumer Lean compilation did not execute through REAPI")
    report["endpoint"] = endpoint
    report["remote_module_executions"] = len(cold)
    hashes = artifact_hashes(first_bin)
    if len(hashes) != 9:
        raise AssertionError("expected seven .olean artifacts and two linked payloads")
    report["cold_module_executions"] = len(cold)
    remove_tree(first)
    remove_tree(first_root)

    second = scratch / "checkout-b"
    snapshot(baseline, second)
    second_root = scratch / "output-b"
    second_bin, restored = build(second, second_root, "restored")
    if len(restored) != 7 or {a["targetLabel"] for a in restored} != expected or not all(
        a.get("cacheHit") for a in restored
    ):
        raise AssertionError(
            "independent checkout did not restore every Ixyk module from cache"
        )
    if hashes != artifact_hashes(second_bin):
        raise AssertionError(
            "restored compiled artifacts differ from the cold producer"
        )
    report["restored_module_cache_hits"] = len(restored)
    report["restored_artifact_sha256"] = hashes
    run(
        command(second_root, "test", "//tools:lean_golden_test",
                "//tools:lean_differential_test", "--nocache_test_results",
                "--test_output=errors",
                f"--execution_log_json_file={output / 'tests-actions.json'}"),
        second, output / "tests.log",
    )
    test_actions = [a for a in actions(output / "tests-actions.json")
                    if a.get("mnemonic") == "TestRunner"]
    remote_tests = {a.get("targetLabel") for a in test_actions
                    if a.get("runner") == "remote" and not a.get("cacheHit")
                    and a.get("exitCode") == 0}
    expected_tests = {"//tools:lean_golden_test", "//tools:lean_differential_test"}
    # Bazel can emit additional cache-hit records during lost-input retries.
    if remote_tests != expected_tests or any(
        a.get("runner") not in ("remote", "remote cache hit") for a in test_actions
    ):
        raise AssertionError("both semantic tests must execute through REAPI")
    report["remote_semantic_tests"] = 2

    semantics = second / "Ixyk/QfAbv/Semantics.lean"
    semantics.write_text(
        semantics.read_text() + "\ndef ixykBazelCacheWitness : Nat := 1\n"
    )
    _, changed = build(second, second_root, "changed")
    executed = {a["targetLabel"] for a in changed if not a.get("cacheHit")}
    downstream = expected - {"//:module__ixyk__Ixyk_d_QfAbv_d_Syntax"}
    if executed != downstream:
        raise AssertionError(f"unexpected invalidation: {sorted(executed)}")
    report["changed_module_executions"] = sorted(executed)

    # A new effective direct import must fail the mandatory graph check.
    golden_source = second / "Ixyk/GoldenCheck.lean"
    golden_source.write_text("import Ixyk.QfAbv.Syntax\n" + golden_source.read_text())
    failure = run(
        command(
            second_root,
            "build",
            "//:lake_authority_modules",
            f"--jobs={jobs}",
            "--noshow_progress",
        ),
        second,
        output / "stale-graph.log",
        expected=1,
    )
    if "projection-verify-runner:" not in failure or "mismatch" not in failure:
        raise AssertionError("stale graph failed for an unexpected reason")
    report["stale_graph_rejected"] = True
    report["status"] = "PASS"
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--scratch-dir", type=Path)
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--endpoint", required=True, help="pinned Ixyk REAPI coordinator URL")
    args = parser.parse_args()
    if (platform.system(), platform.machine()) != ("Linux", "x86_64"):
        parser.error("requires an x86-64 Linux client")
    if args.jobs < 1:
        parser.error("--jobs must be positive")
    output = args.output_dir.resolve()
    if output.is_relative_to(ROOT):
        parser.error("output directory must be outside the source tree")
    output.mkdir(parents=True, exist_ok=False)
    if args.scratch_dir:
        args.scratch_dir = args.scratch_dir.resolve()
        if args.scratch_dir.is_relative_to(ROOT):
            parser.error("scratch directory must be outside the source tree")
        args.scratch_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="ixyk-lean-proof-", dir=args.scratch_dir
    ) as temporary:
        try:
            report = experiment(output, Path(temporary), args.jobs, args.endpoint)
        except AssertionError as error:
            report_path = output / "report.json"
            report = json.loads(report_path.read_text())
            report.update(status="FAIL", failed_assertion=str(error))
            report_path.write_text(json.dumps(report, indent=2) + "\n")
            raise
    (output / "report.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n"
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
