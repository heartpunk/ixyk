# Lean build rules included with the Ixyk research artifact

These sources are a publication port of Sophie Smithburg's Lean/Bazel
module-granularity prototype. They are distributed under GPL-3.0-or-later with
Ixyk. `provenance.json` records the original revision and source-file hashes;
the containing Ixyk commit records the publication changes. No separate source
repository, credentials, internal service, or private checkout is required.

The containing software release is cited through [Ixyk's CITATION.cff](../../CITATION.cff).
Its DOI identifies the archived release, not unarchived changes in this directory.

## Build model

Lake supplies module membership, effective imports, options, and native link
plans. The native exporter and renderer generate the committed `BUILD.bazel`
and the Linux `lean/x86_64-linux/lake-authority.json` and `projection-lock.json`.
Bazel builds the exporter and renderer too. Each production module and binary
requires a freshness stamp from independently regenerating and verifying those
inputs. A source import or Lake configuration change cannot silently use an
outdated graph.

Each module has its own elaboration action. Local and SDK semantic import
artifacts are declared individually. A restricted copy of Lean has no ambient
SDK semantic artifacts; its explicit `ModuleSetup.importArts` supplies the
selected closure. Generated C, native objects, links, and test inputs belong to
Bazel. Lake build outputs are excluded from production inputs.

The pinned public Lean 4.31.0 SDK provides compilation and linking tools.
Archive hashes, compiler commit, SDK import metadata, and platform flags are
part of the toolchain. Linux uses an explicit loader/runtime and a statically
linked Cadical. `runtime.nix` prepares them from Ixyk’s pinned public Nix inputs
before Bazel starts. The resulting client environment needs no Nix executable
for SDK repository construction or action execution.

## Scope and adaptations

This port supports Ixyk's ordinary Lean modules and two native executables on
x86-64 Linux, with a Linux Bazel client and Linux REAPI executors. The exporter rejects unsupported plugins,
custom native dependencies, and other unmodeled Lake configuration. It is not
a claim of support for all Lake packages or arbitrary elaborator filesystem IO.
The SDK repository selects the native client platform; cross-compilation from
a macOS client to a Linux executor is not supported.

Publication changes include a self-contained local Bazel module, public-only
runtime inputs, consumer-independent names, SDK-only bootstrap metadata,
a Linux projection lock, a generated build file, and an
Ixyk REAPI reproduction harness. Historical application sources, discussions,
reviewer files, and infrastructure configuration are not part of this port.

## Reproduction

From the Ixyk repository root on x86-64 Linux, with Nix installed:

```sh
nix run .#reapi -- build //:lake_authority_modules //tools:ixyk_golden_check //tools:ixyk_differential_eval
nix run .#reapi -- test //tools:lean_golden_test //tools:lean_differential_test --test_output=errors
```

The repository launcher starts its pinned REAPI executor and disables local
execution fallback. Its existing `--endpoint` option selects a separately
running compatible coordinator. The workers need the pinned development Nix
closure, as required by the repository's REAPI platform contract.

After changing Lake configuration or effective imports, regenerate on Linux:

```sh
nix develop --command python tools/lean_project.py
```

Review the generated build file, manifest, and lock together. To obtain a
candidate without changing a source snapshot, use
`--candidate-dir /tmp/lean-candidate`; install those outputs in the authoritative
source workspace.

To measure remote compilation, independent-checkout remote cache restoration,
artifact identity, semantic tests, downstream invalidation, and stale-graph
rejection, start the pinned service in one terminal:

```sh
nix run .#reapi -- --state-dir /tmp/ixyk-lean-reapi serve
```

Then run the witness from a Linux client:

```sh
nix develop --command python tools/lean_reproduce.py \
  --endpoint grpc://127.0.0.1:50051 --output-dir /tmp/ixyk-lean-evidence
```

The witness uses disposable source copies and output directories. Cold module
compilation and both semantic tests must report remote execution; the second
checkout shares only remote action results and downloaded repository inputs.
Its JSON report records source identities and measured assertions. Detailed logs
are retained beside it and may contain local paths. Historical prototype or
macOS results do not qualify this Linux/REAPI path.
