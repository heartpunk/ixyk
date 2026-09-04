"""Run explicit Bazel tests against a disposable loopback-only NativeLink."""

import argparse
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def configuration(root: Path) -> dict:
    def filesystem(name, limit):
        return {
            "filesystem": {
                "content_path": str(root / name / "content"),
                "temp_path": str(root / name / "tmp"),
                "eviction_policy": {"max_bytes": limit},
            }
        }

    contract = "ghot-e7a3ca80-lean118d8caf-procself-bazel9-v2"
    return {
        "stores": [
            {"name": "CAS", **filesystem("cas", 2_000_000_000)},
            {"name": "AC", **filesystem("ac", 100_000_000)},
            {
                "name": "WORKER",
                "fast_slow": {
                    "fast": filesystem("worker-cas", 2_000_000_000),
                    "slow": {"ref_store": {"name": "CAS"}},
                },
            },
        ],
        "schedulers": [
            {
                "name": "MAIN",
                "simple": {
                    "supported_platform_properties": {
                        "cpu_count": "minimum",
                        "memory_mb": "minimum",
                        "OSFamily": "exact",
                        "ghot-nix-contract": "exact",
                    },
                },
            }
        ],
        "workers": [
            {
                "local": {
                    "worker_api_endpoint": {"uri": "grpc://127.0.0.1:50061"},
                    "cas_fast_slow_store": "WORKER",
                    "upload_action_result": {"ac_store": "AC"},
                    "work_directory": str(root / "work"),
                    "max_action_timeout_s": 900,
                    "max_inflight_tasks": 2,
                    "use_namespaces": True,
                    "use_mount_namespace": True,
                    "platform_properties": {
                        "cpu_count": {"values": ["4"]},
                        "memory_mb": {"values": ["8192"]},
                        "OSFamily": {"values": ["linux"]},
                        "ghot-nix-contract": {"values": [contract]},
                    },
                }
            }
        ],
        "servers": [
            {
                "listener": {"http": {"socket_address": "127.0.0.1:50051"}},
                "services": {
                    "cas": [{"cas_store": "CAS"}],
                    "ac": [{"ac_store": "AC"}],
                    "bytestream": [{"cas_store": "CAS"}],
                    "execution": [{"cas_store": "CAS", "scheduler": "MAIN"}],
                    "capabilities": [{"remote_execution": {"scheduler": "MAIN"}}],
                },
            },
            {
                "listener": {"http": {"socket_address": "127.0.0.1:50061"}},
                "services": {"worker_api": {"scheduler": "MAIN"}, "health": {}},
            },
        ],
        "global": {"max_open_files": 24576},
    }


def run(binary: Path, targets: list[str]) -> int:
    if not targets or any(not target.startswith("//") for target in targets):
        raise ValueError("explicit workspace test targets required")
    with tempfile.TemporaryDirectory(prefix="ixyk-ci-reapi-") as temporary:
        root = Path(temporary)
        config = root / "config.json"
        config.write_text(json.dumps(configuration(root)))
        # Hosted CI grants sudo; no persistent runner or tailnet service is used.
        worker = subprocess.Popen([str(binary.resolve()), str(config)])
        try:
            for _ in range(60):
                if worker.poll() is not None:
                    raise RuntimeError("NativeLink exited during startup")
                try:
                    with socket.create_connection(("127.0.0.1", 50051), timeout=1):
                        break
                except OSError:
                    time.sleep(0.5)
            else:
                raise TimeoutError("NativeLink did not start within 30 seconds")
            return subprocess.call(
                [
                    "bazel",
                    "--output_user_root=" + str(root / "bazel"),
                    "test",
                    "--config=reapi",
                    "--jobs=2",
                    "--remote_executor=grpc://127.0.0.1:50051",
                    "--remote_cache=grpc://127.0.0.1:50051",
                    "--remote_timeout=900",
                    "--test_output=errors",
                    *targets,
                ]
            )
        finally:
            worker.terminate()
            try:
                worker.wait(timeout=10)
            except subprocess.TimeoutExpired:
                worker.kill()
                worker.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("targets", nargs="+")
    args = parser.parse_args()
    raise SystemExit(run(args.binary, args.targets))
