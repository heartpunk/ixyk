"""Load the declared native runtime before importing the differential oracle."""

from extractor.native_runtime import preload_libstdcxx


def main() -> None:
    preload_libstdcxx()
    from tools.lean_differential import main as differential_main

    differential_main()


if __name__ == "__main__":
    main()
