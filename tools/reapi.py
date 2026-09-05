# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run a local, namespace-isolated NativeLink and optional Bazel command."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time


def configuration(root: Path, port: int, worker_port: int, jobs: int, entrypoint: str) -> dict:
    def filesystem(name, limit):
        return {
            "filesystem": {
                "content_path": str(root / name / "content"),
                "temp_path": str(root / name / "tmp"),
                "eviction_policy": {"max_bytes": limit},
            }
        }

    contract = "ixyk-e7a3ca80-python312-lean430-procns-v1"
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
                        "ixyk-nix-contract": "exact",
                    },
                },
            }
        ],
        "workers": [
            {
                "local": {
                    "worker_api_endpoint": {"uri": f"grpc://127.0.0.1:{worker_port}"},
                    "cas_fast_slow_store": "WORKER",
                    "upload_action_result": {"ac_store": "AC"},
                    "work_directory": str(root / "work"),
                    "max_action_timeout_s": 900,
                    "max_inflight_tasks": jobs,
                    "entrypoint": entrypoint,
                    "use_namespaces": True,
                    "use_mount_namespace": True,
                    "platform_properties": {
                        "cpu_count": {"values": ["2"]},
                        "memory_mb": {"values": ["4096"]},
                        "OSFamily": {"values": ["linux"]},
                        "ixyk-nix-contract": {"values": [contract]},
                    },
                }
            }
        ],
        "servers": [
            {
                "listener": {"http": {"socket_address": f"127.0.0.1:{port}"}},
                "services": {
                    "cas": [{"cas_store": "CAS"}],
                    "ac": [{"ac_store": "AC"}],
                    "bytestream": [{"cas_store": "CAS"}],
                    "execution": [{"cas_store": "CAS", "scheduler": "MAIN"}],
                    "capabilities": [{"remote_execution": {"scheduler": "MAIN"}}],
                },
            },
            {
                "listener": {"http": {"socket_address": f"127.0.0.1:{worker_port}"}},
                "services": {"worker_api": {"scheduler": "MAIN"}, "health": {}},
            },
        ],
        "global": {"max_open_files": 24576},
    }


@contextmanager
def state_directory(path):
    if path is None:
        with tempfile.TemporaryDirectory(prefix="ixyk-reapi-") as directory:
            yield Path(directory)
        return
    root = Path(path).resolve()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    marker = root / ".ixyk-reapi-state"
    if not marker.exists() and any(root.iterdir()):
        raise ValueError("state directory must be empty or previously created by ixyk-reapi")
    with marker.open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise ValueError("another ixyk-reapi process owns this state directory") from error
        yield root


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def process(command, **kwargs):
    child = subprocess.Popen(command, start_new_session=True, **kwargs)
    try:
        yield child
    finally:
        try:
            os.killpg(child.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        # A leader can exit while a descendant ignores TERM. Always finish
        # cleanup of this owned process group before unlocking/removing state.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.wait()


def wait_ready(worker, port, worker_port, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if worker.poll() is not None:
            raise RuntimeError(f"NativeLink exited during startup (exit {worker.returncode})")
        try:
            for endpoint in (port, worker_port):
                with socket.create_connection(("127.0.0.1", endpoint), timeout=0.2):
                    pass
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("NativeLink did not become ready within 30 seconds")


def execution_options(port, jobs):
    return ["--config=reapi-local", f"--jobs={jobs}",
            f"--remote_executor=grpc://127.0.0.1:{port}",
            f"--remote_cache=grpc://127.0.0.1:{port}",
            "--remote_local_fallback=false", "--spawn_strategy=remote",
            "--remote_timeout=900"]


def bazel_command(action, arguments, port, jobs):
    if not arguments:
        raise ValueError(f"{action} requires an explicit Bazel target")
    # Keep run's program arguments after '--', and apply the managed execution
    # settings last so workspace/user rc files cannot select a different worker.
    boundary = arguments.index("--") if "--" in arguments else len(arguments)
    return ["bazel", "--batch", action, *arguments[:boundary],
            *execution_options(port, jobs), *arguments[boundary:]]


def positive(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nativelink", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--entrypoint", required=True, help=argparse.SUPPRESS)
    parser.add_argument("--jobs", type=positive, default=2,
                        help="concurrent actions; provision 2 CPUs and 4 GiB per action (default: 2)")
    parser.add_argument("--port", type=positive, help="loopback REAPI port (serve: 50051; otherwise automatic)")
    parser.add_argument("--state-dir", type=Path, help="optional dedicated directory to retain caches")
    parser.add_argument("action", choices=("serve", "build", "test", "run"), nargs="?", default="serve")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.port is not None and args.port > 65535:
        parser.error("port must be at most 65535")
    if args.action == "serve" and args.arguments:
        parser.error("serve does not accept Bazel arguments")
    port = args.port or (50051 if args.action == "serve" else free_port())
    worker_port = free_port()
    while worker_port == port:
        worker_port = free_port()
    command = None if args.action == "serve" else bazel_command(args.action, args.arguments, port, args.jobs)
    preflight = subprocess.run(
        [args.entrypoint, sys.executable, "-c",
         "import os; assert os.readlink('/proc/self/exe') == "
         "os.readlink(f'/proc/{os.getpid()}/exe')"],
        capture_output=True, text=True,
    )
    if preflight.returncode:
        raise RuntimeError(
            "Linux user/mount namespaces are unavailable. Enable them for this user, "
            "or run this launcher with sudo on a trusted disposable machine. "
            + preflight.stderr.strip()
        )
    with state_directory(args.state_dir) as root:
        config = root / "config.json"
        config.write_text(json.dumps(configuration(root, port, worker_port, args.jobs, args.entrypoint)))
        with (root / "server.log").open("w+") as log:
            try:
                with process([args.nativelink, str(config)], stdout=log, stderr=log) as worker:
                    wait_ready(worker, port, worker_port)
                    print(f"REAPI ready at grpc://127.0.0.1:{port} ({args.jobs} concurrent actions)", flush=True)
                    if command is None:
                        flags = " ".join(execution_options(port, args.jobs))
                        print(f"Client (inside nix develop): bazel test {flags} //path:target", flush=True)
                        return worker.wait()
                    with process(command) as client:
                        while client.poll() is None:
                            if worker.poll() is not None:
                                raise RuntimeError("NativeLink exited while Bazel was running")
                            time.sleep(0.1)
                        return client.returncode
            except (RuntimeError, TimeoutError):
                log.flush()
                log.seek(0)
                print(log.read()[-16000:], file=sys.stderr)
                raise


def interrupted(_signum, _frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupted)
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (OSError, ValueError, RuntimeError, TimeoutError) as error:
        print(f"ixyk-reapi: {error}", file=sys.stderr)
        raise SystemExit(1) from error
