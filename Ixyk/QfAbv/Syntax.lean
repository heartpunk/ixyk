-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

namespace Ixyk.QfAbv

inductive TermSort where
  | bool
  | bv (width : Nat)
  | array (indexWidth valueWidth : Nat)
  deriving BEq, DecidableEq, Repr

inductive BvBinOp where
  | add | sub | mul | udiv | urem
  | and | or | xor | shl | lshr | ashr
  deriving DecidableEq, Repr

inductive BvCmpOp where
  | ult | ule | slt | sle
  deriving DecidableEq, Repr

structure Decl where
  name : String
  sort : TermSort
  deriving DecidableEq, Repr

abbrev Ctx := List Decl

inductive Var : Ctx → TermSort → Type where
  | here : Var (declaration :: context) declaration.sort
  | there : Var context sort → Var (declaration :: context) sort

structure ExtractSpec (width : Nat) where
  hi : Nat
  lo : Nat
  hiLtWidth : hi < width
  loLeHi : lo ≤ hi

def ExtractSpec.resultWidth {width : Nat} (spec : ExtractSpec width) : Nat :=
  spec.hi - spec.lo + 1

mutual
  inductive Expr : Ctx → TermSort → Type where
    | var : Var context sort → Expr context sort
    | boolLit : Bool → Expr context .bool
    | bvLit : (width value : Nat) → Expr context (.bv width)
    | constArray : (indexWidth valueWidth : Nat) →
        Expr context (.bv valueWidth) → Expr context (.array indexWidth valueWidth)
    | boolNot : Expr context .bool → Expr context .bool
    | boolAnd : Expr context .bool → Expr context .bool → Expr context .bool
    | boolOr : Expr context .bool → Expr context .bool → Expr context .bool
    | ite : Expr context .bool → Expr context sort → Expr context sort → Expr context sort
    | bvBin : BvBinOp → (width : Nat) →
        Expr context (.bv width) → Expr context (.bv width) → Expr context (.bv width)
    | bvNot : (width : Nat) → Expr context (.bv width) → Expr context (.bv width)
    | zeroExt : (width amount : Nat) →
        Expr context (.bv width) → Expr context (.bv (width + amount))
    | signExt : (width amount : Nat) →
        Expr context (.bv width) → Expr context (.bv (width + amount))
    | extract : (spec : ExtractSpec width) →
        Expr context (.bv width) → Expr context (.bv spec.resultWidth)
    | concat : (highWidth lowWidth : Nat) →
        Expr context (.bv highWidth) → Expr context (.bv lowWidth) →
        Expr context (.bv (highWidth + lowWidth))
    | select : (indexWidth valueWidth : Nat) →
        Expr context (.array indexWidth valueWidth) → Expr context (.bv indexWidth) →
        Expr context (.bv valueWidth)
    | store : (indexWidth valueWidth : Nat) →
        Expr context (.array indexWidth valueWidth) → Expr context (.bv indexWidth) →
        Expr context (.bv valueWidth) → Expr context (.array indexWidth valueWidth)
    | bvCmp : BvCmpOp → (width : Nat) →
        Expr context (.bv width) → Expr context (.bv width) → Expr context .bool
    | eqBool : Expr context .bool → Expr context .bool → Expr context .bool
    | eqBv : (width : Nat) →
        Expr context (.bv width) → Expr context (.bv width) → Expr context .bool
    | letPar : Bindings context extended → Expr extended sort → Expr context sort

  inductive Bindings : Ctx → Ctx → Type where
    | nil : Bindings context context
    | cons : (name : String) → (sort : TermSort) → Expr context sort →
        Bindings context extended → Bindings context ({ name, sort } :: extended)

end

end Ixyk.QfAbv
