"""Platform for the flake's self-contained local executor."""

def local_reapi_platform():
    native.platform(
        name = "local_reapi_linux_x86_64",
        constraint_values = [
            "@platforms//cpu:x86_64",
            "@platforms//os:linux",
        ],
        exec_properties = {
            "OSFamily": "linux",
            "cpu_count": "2",
            "memory_mb": "4096",
            "ixyk-nix-contract": "ixyk-e7a3ca80-python312-lean431-procns-v2",
        },
        visibility = ["//visibility:public"],
    )
