# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Run a local, namespace-isolated NativeLink and optional Bazel command."""

import argparse
from contextlib import contextmanager
import fcntl
import json
import ipaddress
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


def configuration(root: Path, port: int, worker_port: int, jobs: int, entrypoint: str) -> dict:
    def filesystem(name, limit):
        return {
            "filesystem": {
                "content_path": str(root / name / "content"),
                "temp_path": str(root / name / "tmp"),
                "eviction_policy": {"max_bytes": limit},
            }
        }

    contract = "ixyk-e7a3ca80-python312-lean431-procns-v2"
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


def coordinator_configuration(root, port, worker_port, listen):
    config = configuration(root, port, worker_port, 1, "")
    config.pop("workers")
    config["stores"] = config["stores"][:2]
    for server, number in zip(config["servers"], (port, worker_port)):
        server["listener"]["http"]["socket_address"] = f"{listen}:{number}"
    return config


def worker_configuration(root, endpoint, worker_endpoint, jobs, entrypoint):
    config = configuration(root, 1, 2, jobs, entrypoint)
    config.pop("schedulers")
    config["servers"] = []
    for index, kind in enumerate(("cas", "ac")):
        config["stores"][index] = {
            "name": kind.upper(),
            "grpc": {"instance_name": "", "store_type": kind,
                     "endpoints": [{"address": endpoint}]},
        }
    config["workers"][0]["local"]["worker_api_endpoint"]["uri"] = worker_endpoint
    return config


def endpoint(value):
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "grpc" or not parsed.hostname or not parsed.port
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):
            raise ValueError
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected grpc://host:port on a trusted network") from error
    return value


def listen_address(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("expected a numeric listen address") from error
    return f"[{address}]" if address.version == 6 else str(address)


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


def wait_ready(worker, port, worker_port, timeout=30, host="127.0.0.1"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if worker.poll() is not None:
            raise RuntimeError(f"NativeLink exited during startup (exit {worker.returncode})")
        try:
            for endpoint in (port, worker_port):
                with socket.create_connection((host, endpoint), timeout=0.2):
                    pass
            return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("NativeLink did not become ready within 30 seconds")


def execution_options(port, jobs):
    remote = f"grpc://127.0.0.1:{port}" if isinstance(port, int) else port
    return ["--config=reapi-local", f"--jobs={jobs}",
            f"--remote_executor={remote}",
            f"--remote_cache={remote}",
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
    parser.add_argument("--jobs", type=positive,
                        help="concurrent actions; default 2 per worker, 48 for a remote client")
    parser.add_argument("--port", type=positive, help="loopback REAPI port (serve: 50051; otherwise automatic)")
    parser.add_argument("--worker-port", type=positive, default=50061, help="coordinator worker API port")
    parser.add_argument("--listen-address", type=listen_address, default="127.0.0.1",
                        help="coordinator bind address; use only trusted networks")
    parser.add_argument("--endpoint", type=endpoint, default=os.environ.get("IXYK_REAPI_ENDPOINT"),
                        help="existing coordinator REAPI URL; client mode starts no local worker")
    parser.add_argument("--worker-endpoint", type=endpoint, help="coordinator worker API URL")
    parser.add_argument("--state-dir", type=Path, help="optional dedicated directory to retain caches")
    parser.add_argument("action", choices=("serve", "coordinator", "worker", "build", "test", "run"), nargs="?", default="serve")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.jobs is None:
        args.jobs = 48 if args.endpoint and args.action in {"build", "test", "run"} else 2
    if (args.port is not None and args.port > 65535) or args.worker_port > 65535:
        parser.error("ports must be at most 65535")
    service = args.action in {"serve", "coordinator", "worker"}
    if service and args.arguments:
        parser.error(f"{args.action} does not accept Bazel arguments")
    if args.action == "worker" and (not args.endpoint or not args.worker_endpoint):
        parser.error("worker requires --endpoint and --worker-endpoint")
    if args.action in {"serve", "coordinator"} and args.endpoint:
        parser.error("--endpoint selects an existing coordinator; use build, test, run, or worker")
    if not service and args.endpoint:
        with process(bazel_command(args.action, args.arguments, args.endpoint, args.jobs)) as client:
            return client.wait()
    port = args.port or (50051 if service else free_port())
    worker_port = args.worker_port if args.action == "coordinator" else free_port()
    if args.action == "coordinator" and worker_port == port:
        parser.error("REAPI and worker API ports must differ")
    while worker_port == port:
        worker_port = free_port()
    command = None if service else bazel_command(args.action, args.arguments, port, args.jobs)
    if args.action != "coordinator":
        check_namespaces(args.entrypoint)
    with state_directory(args.state_dir) as root:
        if args.action == "coordinator":
            settings = coordinator_configuration(root, port, worker_port, args.listen_address)
        elif args.action == "worker":
            settings = worker_configuration(root, args.endpoint, args.worker_endpoint, args.jobs, args.entrypoint)
        else:
            settings = configuration(root, port, worker_port, args.jobs, args.entrypoint)
        config = root / "config.json"
        config.write_text(json.dumps(settings))
        with (root / "server.log").open("w+") as log:
            try:
                with process([args.nativelink, str(config)], stdout=log, stderr=log) as worker:
                    if args.action == "worker":
                        print(f"Worker connecting to {args.worker_endpoint} ({args.jobs} concurrent actions)", flush=True)
                        result = worker.wait()
                        if result:
                            raise RuntimeError(f"NativeLink worker exited with status {result}")
                        return result
                    host = args.listen_address.strip("[]") if args.action == "coordinator" else "127.0.0.1"
                    host = {"0.0.0.0": "127.0.0.1", "::": "::1"}.get(host, host)
                    wait_ready(worker, port, worker_port, host=host)
                    print(f"REAPI ready on port {port}", flush=True)
                    if command is None:
                        print(f"Client: ixyk-reapi --endpoint grpc://HOST:{port} test //path:target", flush=True)
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


def check_namespaces(entrypoint):
    preflight = subprocess.run(
        [entrypoint, sys.executable, "-c",
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
