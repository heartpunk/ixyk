-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ayxg.QfAbv.Update
import Ayxg.STS

namespace Ixyk.QfAbv

open Ayxg.QfAbv

inductive Control where
  | address (value : BitVec 64)
  | halt | error | stuck

inductive Target (context : Ctx) where
  | address (value : Expr context (.bv 64))
  | halt | error | stuck

def Target.eval : Target context → Env context → Control
  | .address value, state => .address (Eval.eval state value)
  | .halt, _ => .halt
  | .error, _ => .error
  | .stuck, _ => .stuck

structure Edge (context : Ctx) where
  source : Control
  guard : Expr context .bool
  update : StateUpdate context context
  target : Target context

def Edge.denotes (edge : Edge context)
    (source : Control × Env context) (target : Control × Env context) : Prop :=
  source.1 = edge.source ∧
  Eval.eval source.2 edge.guard = true ∧
  target.1 = edge.target.eval source.2 ∧
  target.2 = edge.update.eval source.2

end Ixyk.QfAbv
