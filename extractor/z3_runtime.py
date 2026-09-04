# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Preload the native dependency required before importing Z3."""

from extractor.native_runtime import preload_libstdcxx


LIBSTDCXX = preload_libstdcxx()
