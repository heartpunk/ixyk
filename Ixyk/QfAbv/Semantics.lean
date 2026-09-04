-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ixyk.QfAbv.Syntax

namespace Ixyk.QfAbv

abbrev Denote : TermSort → Type
  | .bool => Bool
  | .bv width => BitVec width
  | .array indexWidth valueWidth => BitVec indexWidth → BitVec valueWidth

inductive Env : Ctx → Type where
  | nil : Env []
  | cons : Denote declaration.sort → Env context → Env (declaration :: context)

def Env.lookup : Env context → Var context sort → Denote sort
  | .cons value _, .here => value
  | .cons _ rest, .there index => rest.lookup index

def applyBvBin (op : BvBinOp) (left right : BitVec width) : BitVec width :=
  match op with
  | .add => left + right
  | .sub => left - right
  | .mul => left * right
  | .udiv => left / right
  | .urem => left % right
  | .and => left &&& right
  | .or => left ||| right
  | .xor => left ^^^ right
  | .shl => left <<< right
  | .lshr => left >>> right
  | .ashr => BitVec.sshiftRight' left right

def applyBvCmp (op : BvCmpOp) (left right : BitVec width) : Bool :=
  match op with
  | .ult => left.ult right
  | .ule => left.ule right
  | .slt => left.slt right
  | .sle => left.sle right

mutual
  def Expr.eval : Env context → Expr context sort → Denote sort
    | env, .var index => env.lookup index
    | _, .boolLit value => value
    | _, .bvLit width value => BitVec.ofNat width value
    | env, .constArray _ _ value => fun _ => value.eval env
    | env, .boolNot value => !(value.eval env)
    | env, .boolAnd left right => left.eval env && right.eval env
    | env, .boolOr left right => left.eval env || right.eval env
    | env, .ite condition thenValue elseValue =>
        if condition.eval env then thenValue.eval env else elseValue.eval env
    | env, .bvBin op _ left right => applyBvBin op (left.eval env) (right.eval env)
    | env, .bvNot _ value => ~~~(value.eval env)
    | env, .zeroExt width amount value => BitVec.zeroExtend (width + amount) (value.eval env)
    | env, .signExt width amount value => BitVec.signExtend (width + amount) (value.eval env)
    | env, .extract spec value => BitVec.extractLsb spec.hi spec.lo (value.eval env)
    | env, .concat _ _ high low => high.eval env ++ low.eval env
    | env, .select _ _ array index => array.eval env (index.eval env)
    | env, .store _ _ array index value => fun candidate =>
        if candidate = index.eval env then value.eval env else array.eval env candidate
    | env, .bvCmp op _ left right => applyBvCmp op (left.eval env) (right.eval env)
    | env, .eqBool left right => left.eval env == right.eval env
    | env, .eqBv _ left right => left.eval env == right.eval env
    | env, .letPar bindings body => body.eval (bindings.eval env)

  def Bindings.eval : Bindings context extended → Env context → Env extended
    | .nil, env => env
    | .cons _ _ value rest, env => .cons (value.eval env) (rest.eval env)

end

inductive StateUpdate (input : Ctx) : Ctx → Type where
  | nil : StateUpdate input []
  | cons : Expr input declaration.sort → StateUpdate input output →
      StateUpdate input (declaration :: output)

def StateUpdate.eval : StateUpdate input output → Env input → Env output
  | .nil, _ => .nil
  | .cons value rest, env => .cons (value.eval env) (rest.eval env)

end Ixyk.QfAbv
