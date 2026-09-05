# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Independent acquire-then-fuzz actions for instruction probes."""

load(":run_profiles.bzl", "exclusion_reason", "skipped_instruction")

def _fuzz_lane(name, model, acquisition, instruction_hex, examples, output, budgets):
    previous = None
    outputs = []
    discovery_seconds, shrink_executions, shrink_seconds, explain_executions, explain_seconds = budgets
    stages = [
        ("discover", examples + 1, discovery_seconds),
        ("shrink", shrink_executions, shrink_seconds),
        ("explain", explain_executions, explain_seconds),
    ]
    for stage, executions, seconds in stages:
        stage_output = output if stage == "discover" else output.removesuffix(".json") + ".%s.json" % stage
        arguments = [
            "$(location //extractor:fuzz_model)",
            "--acquisition $(location %s)" % acquisition,
            "--model $(location %s)" % model,
            "--instruction-hex %s" % instruction_hex,
            "--examples %d" % examples,
            "--stage %s" % stage,
            "--max-executions %d" % executions,
            "--seconds %d" % seconds,
            "--output $@",
        ]
        if previous:
            arguments.append("--previous $(location %s)" % previous)
        native.genrule(
            name = name if stage == "discover" else name + "_" + stage,
            srcs = [model, acquisition] + ([previous] if previous else []),
            outs = [stage_output],
            cmd = " ".join(arguments),
            tools = ["//extractor:fuzz_model"],
            tags = [] if stage == "discover" else ["manual"],
        )
        outputs.append(stage_output)
        previous = stage_output
    return outputs[1:]

def validation_lanes(name, probes, examples, discovery_seconds = 60, shrink_executions = 500, shrink_seconds = 30, explain_executions = 500, explain_seconds = 30):
    fuzz_results = []
    shrink_results = []
    explain_results = []
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
        processing = _fuzz_lane(
            name = "%s_fuzz" % stem,
            model = model,
            acquisition = acquisition,
            instruction_hex = instruction_hex,
            examples = examples,
            output = fuzz_result,
            budgets = (discovery_seconds, shrink_executions, shrink_seconds, explain_executions, explain_seconds),
        )
        shrink_results.append(processing[0])
        explain_results.append(processing[1])
        fuzz_results.append(fuzz_result)
        all_artifacts.extend([model, acquisition, fuzz_result])

    native.filegroup(name = name, srcs = fuzz_results)
    native.filegroup(name = name + "_shrink", srcs = shrink_results, tags = ["manual"])
    native.filegroup(name = name + "_explain", srcs = explain_results, tags = ["manual"])
    native.filegroup(name = name + "_artifacts", srcs = all_artifacts)

def validation_tier(name, probes, examples, profile = "full", discovery_seconds = 60, shrink_executions = 500, shrink_seconds = 30, explain_executions = 500, explain_seconds = 30):
    fuzz_results = []
    shrink_results = []
    explain_results = []
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

        processing = _fuzz_lane(
            name = "%s_%s_fuzz" % (name, stem),
            model = model,
            acquisition = acquisition,
            instruction_hex = instruction_hex,
            examples = examples,
            output = fuzz_result,
            budgets = (discovery_seconds, shrink_executions, shrink_seconds, explain_executions, explain_seconds),
        )
        shrink_results.append(processing[0])
        explain_results.append(processing[1])
        fuzz_results.append(fuzz_result)
        all_artifacts.extend([model, acquisition, fuzz_result])

    native.filegroup(name = name, srcs = fuzz_results)
    native.filegroup(name = name + "_shrink", srcs = shrink_results, tags = ["manual"])
    native.filegroup(name = name + "_explain", srcs = explain_results, tags = ["manual"])
    native.filegroup(name = name + "_artifacts", srcs = all_artifacts)
