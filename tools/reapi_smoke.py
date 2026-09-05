"""Exercise actual REAPI actions without depending on project source targets."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def main():
    source = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="ixyk-reapi-smoke-") as temporary:
        root = Path(temporary)
        (root / "MODULE.bazel").write_text(
            'module(name = "reapi_smoke")\n'
            'bazel_dep(name = "platforms", version = "1.1.0")\n'
        )
        shutil.copyfile(source / ".bazelrc", root / ".bazelrc")
        (root / "tools").mkdir()
        shutil.copyfile(source / "tools/reapi_platform.bzl", root / "tools/reapi_platform.bzl")
        (root / "tools/BUILD.bazel").write_text(
            'load(":reapi_platform.bzl", "local_reapi_platform")\nlocal_reapi_platform()\n'
        )
        for name in ("dev_check.py", "dev_smoke.py"):
            shutil.copyfile(source / "tools" / name, root / name)
        for name in ("flake.nix", "lean-toolchain", ".bazelversion"):
            shutil.copyfile(source / name, root / name)
        environment = {
            key: value for key, value in os.environ.items()
            if key in {"PATH", "PYTHONNOUSERSITE", "PYTHONSAFEPATH", "ELAN_TOOLCHAIN"}
            or key.startswith("IXYK_NIX_")
        }
        (root / "run.py").write_text(
            "import subprocess, sys\n"
            "with open(sys.argv[1], 'w') as output:\n"
            "    subprocess.run([sys.executable, 'dev_smoke.py'], stdout=output, check=True)\n"
        )
        # Nixpkgs' Bazel shell wrapper prepends its own Python to PATH.
        # Use an explicit interpreter, as the project's Python toolchain does.
        interpreter = environment["IXYK_NIX_PYTHON_ROOT"] + "/bin/python"
        # Each action checks Python/native dependencies and compiles, links,
        # and executes a Lean program inside the worker's namespaces.
        (root / "smoke.bzl").write_text(
            "def _impl(ctx):\n"
            "    out = ctx.actions.declare_file(ctx.label.name + '.txt')\n"
            "    ctx.actions.run(\n"
            "        inputs = ctx.files.srcs, outputs = [out],\n"
            f"        executable = {json.dumps(interpreter)},\n"
            "        arguments = ['run.py', out.path],\n"
            f"        env = {json.dumps(environment)},\n"
            "    )\n"
            "    return [DefaultInfo(files = depset([out]))]\n"
            "smoke = rule(implementation = _impl, attrs = {\n"
            "    'srcs': attr.label_list(allow_files = True),\n"
            "})\n"
        )
        (root / "BUILD.bazel").write_text(
            'load(":smoke.bzl", "smoke")\n'
            + "\n".join(
                f'smoke(name = "check_{index}", srcs = ["run.py", "dev_check.py", "dev_smoke.py", "flake.nix", "lean-toolchain", ".bazelversion"])'
                for index in range(2)
            )
        )
        subprocess.run([
            "nix", "run", f"{source}#reapi", "--", "--jobs", "2", "build",
            "--lockfile_mode=off", "//:all",
        ], cwd=root, check=True)
        for index in range(2):
            output = (root / f"bazel-bin/check_{index}.txt").read_text()
            if "Standalone Lean compile, link, and execution: OK" not in output:
                raise RuntimeError(f"remote action {index} did not complete: {output}")
        print("Two REAPI actions compiled and ran successfully; local fallback disabled.")


if __name__ == "__main__":
    main()
