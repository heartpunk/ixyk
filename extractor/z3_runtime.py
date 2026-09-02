"""Preload the native dependency required before importing Z3."""

from extractor.native_runtime import preload_libstdcxx


LIBSTDCXX = preload_libstdcxx()
