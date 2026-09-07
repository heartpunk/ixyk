import hashlib
import json
from collections import Counter
from pathlib import Path
import zstandard
from extractor.evidence import EvidenceReader
from extractor.evidence_reference_json import ReferenceJSONBackend
from extractor.evidence_events import evidence_types, Acquisition, FuzzInput, Comparison
from extractor.artifact import InstructionModel

audits = []
for path in sorted(Path("results").glob("*/*.evidence.zst")):
    report = json.loads((path.parent / "benchmark.json").read_text())["cases"][0]
    counts, outcomes, model_ids, acquisitions = Counter(), Counter(), set(), {}
    digest = hashlib.sha256()
    previous_input = None
    with (
        path.open("rb") as raw,
        zstandard.ZstdDecompressor().stream_reader(raw) as stream,
    ):
        for record in EvidenceReader(
            stream, backend=ReferenceJSONBackend(), types=evidence_types()
        ):
            event = record.value
            counts[type(event).__name__] += 1
            if isinstance(event, InstructionModel):
                assert not counts["FuzzInput"], "model set expanded during sampling"
                model_ids.add(record.id)
            elif isinstance(event, Acquisition):
                assert not counts["FuzzInput"], "acquisition during sampling"
                assert event.model_id in model_ids
                acquisitions[event.model_id, event.instruction] = event.source
            elif isinstance(event, FuzzInput):
                assert event.sample == counts["FuzzInput"]
                assert event.model_id in model_ids
                assert (
                    dict(event.before.scalars)["rip"]
                    == acquisitions[event.model_id, event.instruction]
                )
                assert event.route in {m["route"] for m in report["prepared_models"]}
                previous_input = record.id
                digest.update(
                    len(event.instruction).to_bytes(2, "big") + event.instruction
                )
                for name, value in sorted(event.before.scalars):
                    digest.update(name.encode() + b"\0" + value.to_bytes(32, "big"))
                digest.update(len(event.before.memory).to_bytes(8, "big"))
                for address, byte in sorted(event.before.memory):
                    digest.update(address.to_bytes(8, "big") + bytes((byte,)))
            elif isinstance(event, Comparison):
                assert record.context == previous_input
                previous_input = None
                outcomes[event.outcome] += 1
    assert counts["FuzzInput"] == counts["Comparison"] == report["executions"]
    assert digest.hexdigest() == report["input_sha256"]
    for name in ["agreement", "disagreement", "unusable"]:
        assert outcomes[name] == report[name if name == "unusable" else name + "s"]
    audits.append(
        dict(
            path=str(path),
            records=dict(counts),
            outcomes=dict(outcomes),
            input_sha256=digest.hexdigest(),
        )
    )
Path("evidence-audit.json").write_text(json.dumps(audits, indent=2) + "\n")
print(json.dumps(dict(evidence_streams_validated=len(audits))), flush=True)
