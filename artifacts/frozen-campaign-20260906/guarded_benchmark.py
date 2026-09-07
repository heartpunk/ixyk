from contextlib import ExitStack
from unittest.mock import patch
import json
import time
from extractor import z3_runtime  # noqa: F401 -- preload native runtime
from extractor import fuzz_campaign, xed, runtime, evidence_benchmark
from extractor.fuzzer import CompiledModel
import antiunification.many as au

prepare = fuzz_campaign.Campaign.prepare
fuzz = evidence_benchmark._fuzz
counts = {"preparations": 0, "hot_loop_forbidden_calls": 0}
with ExitStack() as guards:

    def forbidden(*a, **kw):
        counts["hot_loop_forbidden_calls"] += 1
        raise AssertionError("acquisition entered frozen execution phase")

    def prepared(self, **kw):
        prepare(self, **kw)
        counts["preparations"] += 1
        for owner, name in [
            (xed, "_invoke"),
            (runtime, "load_shellcode"),
            (fuzz_campaign, "load_shellcode"),
            (fuzz_campaign, "extract"),
            (CompiledModel, "__init__"),
            (au, "antiunify_many"),
        ]:
            guards.enter_context(patch.object(owner, name, forbidden))

    def measured(*a, **kw):
        start = time.monotonic()
        last = [0]

        def progress(r):
            n = r["executions"]
            if n >= last[0] + 1000:
                last[0] = n
                print(
                    json.dumps(
                        dict(samples=n, elapsed_s=round(time.monotonic() - start, 2))
                    ),
                    flush=True,
                )

        return fuzz(*a, progress=progress, **kw)

    guards.enter_context(patch.object(fuzz_campaign.Campaign, "prepare", prepared))
    guards.enter_context(patch.object(evidence_benchmark, "_fuzz", measured))
    result = evidence_benchmark.main()
    assert len(result["cases"]) == 1
    case = result["cases"][0]
    assert case["executions"] == result["samples_per_opcode"]
    assert (
        case["agreements"] + case["disagreements"] + case["unusable"]
        == case["executions"]
    )
    assert case["fallback_allocations"] == case["planned_fallback_allocations"]
    print(
        json.dumps(
            dict(
                guards=counts,
                preparation_s=case["preparation_seconds"],
                execution_s=case["execution_seconds"],
                total_s=case["elapsed_ns"] / 1e9,
                peak_rss_bytes=result["peak_rss_bytes"],
                input_sha256=case["input_sha256"],
            )
        ),
        flush=True,
    )
