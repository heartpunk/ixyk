# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Artifact-to-fact I/O and presentation of Souffle query results."""

from contextlib import contextmanager
import csv
import os
from pathlib import Path
import subprocess
import tempfile


@contextmanager
def query(nodes, root_sets, models, program):
    with tempfile.TemporaryDirectory(prefix="ixyk-souffle-") as directory:
        root = Path(directory)

        def facts(name, rows):
            with (root / f"{name}.facts").open("w") as stream:
                writer = csv.writer(
                    stream, delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_NONE
                )
                writer.writerows(rows)

        facts("Group", ((g,) for g in range(len(root_sets))))
        facts("Root", ((g, b) for g, roots in enumerate(root_sets) for b in roots))
        facts("Block", ((b,) for b in nodes))
        facts(
            "Edge",
            (
                (b, successor)
                for b, node in nodes.items()
                for successor in node["successors"]
            ),
        )
        facts(
            "Unknown",
            (
                (b, p, reason)
                for b, node in nodes.items()
                for p, reason in enumerate(sorted(node["unknown"]))
            ),
        )
        facts(
            "Site",
            (
                (b, p, site["hex"], site["opcode"])
                for b, node in nodes.items()
                for p, site in enumerate(node["instructions"])
            ),
        )
        facts("Model", ((code,) for code in models))
        source = Path(__file__).parent
        (root / "query.dl").write_text(
            (source / "reach.dl").read_text() + "\n" + (source / program).read_text()
        )
        subprocess.run(
            [
                os.environ.get("IXYK_SOUFFLE", "souffle"),
                "--no-preprocessor",
                "-j",
                "1",
                "-F",
                str(root),
                "-D",
                str(root),
                str(root / "query.dl"),
            ],
            check=True,
        )
        yield root


def rows(directory, name):
    with (directory / f"{name}.csv").open() as stream:
        yield from csv.reader(stream, delimiter="\t", quoting=csv.QUOTE_NONE)


def reachable(nodes, roots):
    with query(nodes, [roots], {}, "reachable.dl") as output:
        addresses = sorted(int(b) for _, b in rows(output, "Reach"))
        unknown = sorted(
            (
                {"address": int(b), "reason": reason}
                for _, b, _, reason in rows(output, "Unresolved")
            ),
            key=lambda item: (item["address"], item["reason"]),
        )
    return addresses, unknown


def summaries(nodes, root_sets, models):
    with query(nodes, root_sets, models, "coverage.dl") as output:
        result = {}
        for g, n, e, m, u, t in rows(output, "Summary"):
            result[int(g)] = {
                "host_instruction_sites": int(n),
                "distinct_host_encodings": int(e),
                "cache_miss_sites": int(m),
                "unknown_transfers": int(u),
                "trivial_body": int(n) > 0 and int(t) == 0,
                "first_cache_miss": None,
                "first_unknown_transfer": None,
                "cached_encodings": [],
            }
        for g, b, p in rows(output, "FirstMiss"):
            result[int(g)]["first_cache_miss"] = nodes[b]["instructions"][int(p)]
        for g, b, reason in rows(output, "FirstUnknown"):
            result[int(g)]["first_unknown_transfer"] = {
                "address": int(b),
                "reason": reason,
            }
        for g, code in rows(output, "Covered"):
            result[int(g)]["cached_encodings"].append(code)
        for summary in result.values():
            summary["cached_encodings"].sort()
        return {roots: result[g] for g, roots in enumerate(root_sets)}
