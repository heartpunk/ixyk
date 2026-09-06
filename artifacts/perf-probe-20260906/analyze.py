import pathlib
import json
import sys
import struct
import hashlib
import statistics
import io

root = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(root / "wheels"))
import zstandard  # noqa: E402 -- load the probe-local wheel

results = {
    p.parent.name: json.loads(p.read_text())
    for p in (root / "results").glob("*/result.json")
    if p.parent.name != "baseline-profile-ADD-off"
}


def semantic(d):
    return dict(
        report=d["report"],
        generated_sha256=d["generated_sha256"],
        samples=[
            {k: v for k, v in s.items() if k not in ["select_s", "compare_s"]}
            for s in d["samples"]
        ],
        progress_count=d["progress_count"],
        xed_keys=d["xed_keys"],
    )


def evidence(label):
    with (root / "results" / label / "evidence.json.zst").open("rb") as f:
        data = zstandard.ZstdDecompressor().stream_reader(f).read()
    b = io.BytesIO(data)
    assert b.read(14) == b"IXYK-EVIDENCE\x01"
    n = struct.unpack(">Q", b.read(8))[0]
    manifest = json.loads(b.read(n))
    records = []
    while length := b.read(8):
        n = struct.unpack(">Q", length)[0]
        body = b.read(n)
        assert len(body) == n
        kind, seq, timestamp, ncontext = struct.unpack_from(">IQQI", body)
        context = (
            body[24 : 24 + ncontext].decode().replace(manifest["stream_id"], "STREAM")
        )
        payload = json.loads(
            body[24 + ncontext :].decode().replace(manifest["stream_id"], "STREAM")
        )
        records.append([kind, seq, context, payload])
    canonical = dict(
        manifest={
            k: v for k, v in manifest.items() if k not in ["stream_id", "invocation_id"]
        },
        records=records,
    )
    return hashlib.sha256(
        json.dumps(canonical, sort_keys=True).encode()
    ).hexdigest(), len(records)


checks = []
rows = []
for name in ["ADD", "JE", "LEA", "MOVSD"]:
    for mode in ["off", "json"]:
        labels = [
            f"{variant}-r{repeat}-{name}-{mode}"
            for variant in ["baseline", "cache"]
            for repeat in [1, 2]
        ]
        if any(label not in results for label in labels):
            continue
        values = [results[label] for label in labels]
        assert all(semantic(d) == semantic(values[0]) for d in values), labels
        check = dict(opcode=name, mode=mode, semantic_equal=True)
        if mode == "json":
            ev = [evidence(label) for label in labels]
            assert len(set(ev)) == 1, (labels, ev)
            check.update(evidence_sha256=ev[0][0], records=ev[0][1])
        checks.append(check)
        base = statistics.mean(d["wall_s"] for d in values[:2])
        cache = statistics.mean(d["wall_s"] for d in values[2:])
        rows.append(
            dict(
                opcode=name,
                mode=mode,
                baseline_s=base,
                cache_s=cache,
                speedup=base / cache,
                baseline_xed=values[0]["xed_calls"],
                cached_xed=values[2]["xed_calls"] - values[2]["xed_cache_hits"],
                generated_sha256=values[0]["generated_sha256"],
                routes=[s["route"] for s in values[0]["samples"]],
                executions=values[0]["report"]["executions"],
            )
        )
summary = dict(
    completed=len(results),
    rows=rows,
    checks=checks,
    peak_rss_mib=max(d["peak_rss_kib"] for d in results.values()) / 1024,
)
(root / "summary.json").write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))
