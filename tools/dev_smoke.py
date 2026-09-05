# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Exercise the development environment independently of project sources."""

from pathlib import Path
import subprocess
import tempfile


def check() -> None:
    subprocess.run(["ixyk-dev-check"], check=True)
    with tempfile.TemporaryDirectory(prefix="ixyk-dev-smoke-") as temporary:
        root = Path(temporary)
        (root / "lakefile.lean").write_text(
            "import Lake\nopen Lake DSL\npackage newcomer\n"
            "lean_exe smoke where\n  root := `Main\n"
        )
        (root / "Main.lean").write_text(
            'def main : IO Unit := IO.println "ixyk-dev-smoke"\n'
        )
        subprocess.run(["lake", "build", "smoke"], cwd=root, check=True)
        output = subprocess.check_output(
            [str(root / ".lake/build/bin/smoke")], text=True
        )
        if output != "ixyk-dev-smoke\n":
            raise ValueError(f"unexpected Lean executable output: {output!r}")
    print("Standalone Lean compile, link, and execution: OK")


if __name__ == "__main__":
    check()
