# SPDX-FileCopyrightText: 2026 Sophie Smithburg
# SPDX-License-Identifier: GPL-3.0-or-later

"""Many-sorted first-order anti-unification over explicit syntax algebras."""

from antiunification.algebra import (
    AlgebraError,
    Application,
    ApplicationPattern,
    Atom,
    AtomPattern,
    Correspondence,
    FiniteMap,
    FiniteMapPattern,
    Generalization,
    Hole,
    Layer,
    Pattern,
    Syntax,
    antiunify_values,
)

__all__ = [
    "AlgebraError",
    "Application",
    "ApplicationPattern",
    "Atom",
    "AtomPattern",
    "Correspondence",
    "FiniteMap",
    "FiniteMapPattern",
    "Generalization",
    "Hole",
    "Layer",
    "Pattern",
    "Syntax",
    "antiunify_values",
]
