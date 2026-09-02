"""Independent acquire-then-fuzz actions for instruction probes."""

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
        native.genrule(
            name = "%s_fuzz" % stem,
            srcs = [model, acquisition],
            outs = [fuzz_result],
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
        fuzz_results.append(fuzz_result)
        all_artifacts.extend([model, acquisition, fuzz_result])

    native.filegroup(name = name, srcs = fuzz_results)
    native.filegroup(name = name + "_artifacts", srcs = all_artifacts)
