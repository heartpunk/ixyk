# Golden reference artifacts

These files are generated outputs deliberately included as reference artifacts
for the ixyk v0.0.1 research release. They are versioned evidence, not Bazel
implementation directories or disposable compiler output.

Regeneration is not required to inspect or use the archived research artifact.
The commands below exist to reproduce or verify the committed observations.

The committed copies demonstrate five materially different extraction and
validation paths:

| Stem | Representative instruction | What the artifact set demonstrates |
|---|---|---|
| `2_add` | `add rax, rbx` | Scalar arithmetic with modeled register and flag updates. |
| `12_ret` | `ret` | A symbolic control-flow target loaded from modeled stack memory. |
| `28_mulsd` | `mulsd xmm0, xmm1` | A structured, fail-closed unavailable model at the current floating-point theory boundary. |
| `36_pxor` | `pxor xmm0, xmm1` | SIMD/vector state represented inside the QF_ABV model. |
| `65_int3` | `int3` | A modeled terminal error matched against an emulator CPU exception. |

Each stem has three files:

| Suffix | Contents |
|---|---|
| `.acquisition.json` | Whether lifting and typed extraction produced an available model. |
| `.model.json` | The typed instruction transition system, or a structured unavailable-model artifact. |
| `.fuzz-10000.json` | The deterministic 10,000-example differential-validation result, or the corresponding zero-execution boundary report. |

## Regeneration and verification

Run the repository's Linux/REAPI Bazel profile; ixyk intentionally does not
support local macOS execution.

```bash
bazel run --config=reapi //tools:update_golden
bazel run --config=reapi //tools:check_golden
```

`update_golden` regenerates the selected Bazel outputs and updates the committed
copies plus `MANIFEST.sha256`. `check_golden` regenerates into Bazel-managed
output space and compares it with this directory without modifying the source
tree. CI should run the checker, never commit regenerated files automatically.

The JSON writers use sorted keys and stable indentation. Differential fuzzing
uses a fixed Hypothesis seed with the example database disabled, so byte-identical
regeneration is expected when the pinned toolchain and source semantics are
unchanged.

## Provenance and archival meaning

| Item | Source of truth |
|---|---|
| Generating targets | The artifact labels listed by `//tools:update_golden` in `tools/BUILD.bazel`. |
| Bazel version | `.bazelversion`. |
| Python and native dependencies | `MODULE.bazel`, `MODULE.bazel.lock`, and `extractor/requirements_linux_x86_64.txt`. |
| Instruction probes | `catalog/x86_64_probes.json` and `catalog/x86_64_probes.bzl`. |
| Integrity | `MANIFEST.sha256`, covering every generated file in this directory. |
| Source revision/release | The Git commit and release tag containing these files; the DOI archive preserves that repository state. |

Source remains authoritative. These committed generated files are authoritative
reference observations of that source at this release. Ordinary Bazel output
trees such as `bazel-bin/`, `bazel-out/`, and `bazel-testlogs/` remain disposable
and must not be committed.

## Archival references

| Topic | Primary documentation |
|---|---|
| Bazel-managed output directories | [Bazel output directory layout](https://bazel.build/remote/output-directories) |
| Archiving GitHub releases | [Zenodo: Archive a release from GitHub](https://help.zenodo.org/docs/github/archive-software/github-upload/) |
| DOI reservation and published records | [Zenodo: Digital Object Identifier](https://help.zenodo.org/docs/deposit/describe-records/reserve-doi/) |
