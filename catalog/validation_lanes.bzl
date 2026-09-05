# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Independent acquire-then-fuzz actions for instruction probes."""

load(":run_profiles.bzl", "exclusion_reason", "skipped_instruction")

def _fuzz_lane(name, model, acquisition, instruction_hex, examples, output):
    native.genrule(
        name = name,
        srcs = [model, acquisition],
        outs = [output],
        cmd = " ".join([
            "$(location //extractor:fuzz_model)",
            "--acquisition $(location %s)" % acquisition,
            "--model $(location %s)" % model,
            "--instruction-hex %s" % instruction_hex,
            "--examples %d" % examples,
            "--output $@",
        ]),
        tools = ["//extractor:fuzz_model"],
    )

def validation_lanes(name, probes, examples):
    fuzz_results = []
    all_artifacts = []
    for rank, family, _assembly, instruction_hex in probes:
        stem = "%d_%s" % (rank, family.lower())
        model = "artifacts/%s.model.json" % stem
        acquisition = "artifacts/%s.acquisition.json" % stem
        fuzz_result = "results/%s.fuzz.json" % stem

        native.genrule(
            name = "%s_acquire" % stem,
            outs = [model, acquisition],
            cmd = " ".join([
                "$(location //extractor:acquire_model)",
                "--instruction-hex %s" % instruction_hex,
                "--model-output $(@D)/%s" % model,
                "--result-output $(@D)/%s" % acquisition,
            ]),
            tools = ["//extractor:acquire_model"],
        )
        _fuzz_lane(
            name = "%s_fuzz" % stem,
            model = model,
            acquisition = acquisition,
            instruction_hex = instruction_hex,
            examples = examples,
            output = fuzz_result,
        )
        fuzz_results.append(fuzz_result)
        all_artifacts.extend([model, acquisition, fuzz_result])

    native.filegroup(name = name, srcs = fuzz_results)
    native.filegroup(name = name + "_artifacts", srcs = all_artifacts)

def validation_tier(name, probes, examples, profile = "full"):
    fuzz_results = []
    all_artifacts = []
    for rank, family, _assembly, instruction_hex in probes:
        stem = "%d_%s" % (rank, family.lower())
        model = "artifacts/%s.model.json" % stem
        acquisition = "artifacts/%s.acquisition.json" % stem
        directory = str(examples) if profile == "full" else "%s/%d" % (profile, examples)
        fuzz_result = "results/%s/%s.fuzz.json" % (directory, stem)

        reason = exclusion_reason(family, profile)
        if reason:
            skipped_instruction(
                name = "%s_%s_fuzz" % (name, stem),
                output = fuzz_result,
                family = family,
                instruction_hex = instruction_hex,
                reason = reason,
            )
            fuzz_results.append(fuzz_result)
            all_artifacts.append(fuzz_result)
            continue

        _fuzz_lane(
            name = "%s_%s_fuzz" % (name, stem),
            model = model,
            acquisition = acquisition,
            instruction_hex = instruction_hex,
            examples = examples,
            output = fuzz_result,
        )
        fuzz_results.append(fuzz_result)
        all_artifacts.extend([model, acquisition, fuzz_result])

    native.filegroup(name = name, srcs = fuzz_results)
    native.filegroup(name = name + "_artifacts", srcs = all_artifacts)
