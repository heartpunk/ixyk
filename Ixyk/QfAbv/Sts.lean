-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ixyk.QfAbv.Semantics

namespace Ixyk.QfAbv

inductive Control where
  | address (value : BitVec 64)
  | halt | error | stuck

inductive Target (context : Ctx) where
  | address (value : Expr context (.bv 64))
  | halt | error | stuck

def Target.eval : Target context → Env context → Control
  | .address value, state => .address (value.eval state)
  | .halt, _ => .halt
  | .error, _ => .error
  | .stuck, _ => .stuck

structure Edge (context : Ctx) where
  source : Control
  guard : Expr context .bool
  update : StateUpdate context context
  target : Target context

structure STS where
  context : Ctx
  edges : List (Edge context)

def Edge.denotes (edge : Edge context)
    (source : Control × Env context) (target : Control × Env context) : Prop :=
  source.1 = edge.source ∧
  edge.guard.eval source.2 = true ∧
  target.1 = edge.target.eval source.2 ∧
  target.2 = edge.update.eval source.2

def STS.denotes (system : STS)
    (source target : Control × Env system.context) : Prop :=
  ∃ edge ∈ system.edges, edge.denotes source target

end Ixyk.QfAbv
