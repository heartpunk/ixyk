# Imports intentionally follow path setup and the import-time timer.
# ruff: noqa: E402
import os
import sys
import pathlib
import time
import json
import cProfile
import pstats
import hashlib
import dataclasses
import resource
import importlib.metadata

root = pathlib.Path(__file__).resolve().parent
rf = pathlib.Path(
    "/tmp/ixyk-pr-xed-speed-20260905/bazel-bin/extractor/au_inputs_test.runfiles"
)
os.environ["RUNFILES_DIR"] = str(root / "runfiles")
sys.path[:0] = (
    [str(root / "source"), str(root / "wheels")]
    + [str(p / "site-packages") for p in sorted(rf.glob("rules_python++pip+*"))]
    + [str(rf / "ixyk_vendored_arpy+"), str(rf / "ixyk_vendored_mulpyplexer+")]
)
t0 = time.perf_counter()
from extractor import z3_runtime  # noqa: F401 -- preload native runtime
from extractor.fuzzer import fuzz
from extractor.fuzz_campaign import Campaign
from extractor.evidence import RunContext
from extractor.evidence_events import EvidenceHooks, evidence_types
from extractor.evidence_recording import BackgroundRecorder
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor import xed
import zstandard

imports = time.perf_counter() - t0
mode, opcode, hexcode, variant, profiled, label = sys.argv[1:]
output = root / "results" / label
output.mkdir(parents=True, exist_ok=True)
print(json.dumps(dict(event="start", label=label, imports_s=imports)), flush=True)
invocations = {}
cache = {}
cache_hits = 0
original_invoke = xed._invoke


def invoke(*args):
    global cache_hits
    key = json.dumps(args)
    invocations[key] = invocations.get(key, 0) + 1
    if variant == "cache" and key in cache:
        cache_hits += 1
        return json.loads(cache[key])
    result = original_invoke(*args)
    if variant == "cache":
        cache[key] = json.dumps(result)
    return result


xed._invoke = invoke
samples = []
original_select = Campaign.select
original_compare = Campaign.compare
pending = {}
generated = hashlib.sha256()


def select(self, code, source, sample, **kw):
    before = kw["before"]
    inp = dict(
        code=code.hex(),
        source=source,
        scalars=dict(before.scalars),
        memory=sorted(before.memory.items()),
    )
    generated.update(json.dumps(inp, sort_keys=True).encode())
    start = time.perf_counter()
    try:
        return original_select(self, code, source, sample, **kw)
    finally:
        pending.update(
            sample=sample,
            select_s=time.perf_counter() - start,
            route=self.route,
            input=inp,
        )


def compare(self, current, code, before, sample):
    start = time.perf_counter()
    result = original_compare(self, current, code, before, sample)
    row = dict(pending, compare_s=time.perf_counter() - start, summary=self.summary())
    samples.append(row)
    print(
        json.dumps(
            dict(
                event="sample",
                label=label,
                sample=sample,
                select_s=row["select_s"],
                compare_s=row["compare_s"],
                route=row["route"],
            )
        ),
        flush=True,
    )
    return result


Campaign.select = select
Campaign.compare = compare
progress_count = 0


def progress(report):
    global progress_count
    progress_count += 1


recorder = None
raw = None
compressed = None
prof = cProfile.Profile()
started = time.perf_counter()
try:
    if mode == "json":
        raw = (output / "evidence.json.zst").open("xb")
        compressed = zstandard.ZstdCompressor(level=3).stream_writer(raw, closefd=False)
        recorder = BackgroundRecorder(
            backend=ReferenceJSONBackend(),
            types=evidence_types(),
            run=RunContext("1ca1aef6e15025a223a2822fd988137138ca87c0", label),
            output=compressed,
        )
    if profiled == "yes":
        prof.enable()
    report = fuzz(
        None,
        bytes.fromhex(hexcode),
        5,
        stage="discover",
        max_executions=5,
        progress=progress,
        vary_inputs=True,
        continue_on_findings=True,
        evidence=EvidenceHooks(recorder) if recorder else None,
    )
finally:
    prof.disable()
    if recorder:
        recorder.close()
    if compressed:
        compressed.close()
    if raw:
        raw.close()
wall = time.perf_counter() - started
stats = pstats.Stats(prof) if profiled == "yes" else None
rows = [
    dict(
        file=k[0],
        line=k[1],
        function=k[2],
        primitive=v[0],
        calls=v[1],
        self_s=v[2],
        cumulative_s=v[3],
    )
    for k, v in (stats.stats.items() if stats else [])
]
result = dict(
    label=label,
    mode=mode,
    opcode=opcode,
    variant=variant,
    profiled=profiled,
    wall_s=wall,
    imports_s=imports,
    report=report,
    generated_sha256=generated.hexdigest(),
    samples=samples,
    progress_count=progress_count,
    xed_calls=sum(invocations.values()),
    xed_unique=len(invocations),
    xed_cache_hits=cache_hits,
    xed_keys=invocations,
    profile=rows,
    recording=dataclasses.asdict(recorder.metrics) if recorder else None,
    peak_rss_kib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
    versions={
        k: importlib.metadata.version(k)
        for k in ["angr", "hypothesis", "unicorn", "zstandard", "z3-solver"]
    },
)
(output / "result.json").write_text(json.dumps(result, indent=2))
if stats:
    prof.dump_stats(str(output / "profile.pstats"))
print(
    json.dumps(
        dict(
            event="done",
            label=label,
            wall_s=wall,
            xed_calls=result["xed_calls"],
            xed_unique=len(invocations),
            peak_rss_kib=result["peak_rss_kib"],
            report=report,
        )
    ),
    flush=True,
)
