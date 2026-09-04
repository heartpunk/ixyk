-- SPDX-FileCopyrightText: 2026 Sophie Smithburg
-- SPDX-License-Identifier: GPL-3.0-or-later

import Ixyk.QfAbv.Sts
import Lean.Data.Json

namespace Ixyk.Artifact

open Lean Ixyk.QfAbv

private inductive SomeExpr (context : Ctx) where
  | mk (sort : TermSort) (expr : Expr context sort)

structure RawExpr where
  op : String
  sort : TermSort
  args : Array RawExpr := #[]
  name? : Option String := none
  boolValue? : Option Bool := none
  natValue? : Option Nat := none
  amount? : Option Nat := none
  hi? : Option Nat := none
  lo? : Option Nat := none
  deriving BEq

instance : Inhabited RawExpr where
  default := { op := "", sort := .bool }

structure RawAssignment where
  name : String
  value : RawExpr

inductive RawTarget where
  | address (value : Nat)
  | symbolic (value : RawExpr)
  | halt | error | stuck

structure RawStep where
  guard : RawExpr
  update : Array RawAssignment
  target : RawTarget
  mirroredPc : RawExpr

structure RawModel where
  source : Nat
  declarations : Array Decl
  steps : Array RawStep

inductive Imported where
  | model (system : STS)
  | unavailable (error : String)

private def requireFields (json : Json) (expected : List String)
    (description : String) : Except String Unit := do
  let object ← json.getObj?
  let count := object.foldl (init := 0) fun count _ _ => count + 1
  if count != expected.length || !object.all (fun name _ => expected.contains name) then
    throw s!"{description} fields differ"

private def field (json : Json) (name : String) : Except String Json :=
  json.getObjVal? name

private def stringField (json : Json) (name : String) : Except String String :=
  do (← field json name).getStr?

private def nameField (json : Json) (name : String) : Except String String := do
  let value ← stringField json name
  if value.isEmpty then throw s!"{name} must be nonempty"
  pure value

private def natField (json : Json) (name : String) : Except String Nat :=
  do (← field json name).getNat?

private def parseSort (json : Json) : Except String TermSort := do
  match ← stringField json "kind" with
  | "bool" =>
      requireFields json ["kind"] "sort"
      pure .bool
  | "bv" =>
      requireFields json ["kind", "width"] "sort"
      let width ← natField json "width"
      if width = 0 then throw "bit-vector width must be positive"
      pure (.bv width)
  | "array" =>
      requireFields json ["kind", "index_width", "value_width"] "sort"
      let indexWidth ← natField json "index_width"
      let valueWidth ← natField json "value_width"
      if indexWidth = 0 || valueWidth = 0 then throw "array widths must be positive"
      pure (.array indexWidth valueWidth)
  | kind => throw s!"unknown sort {kind}"

private def plainArgsOp (op : String) : Bool :=
  ["const_array", "bool_not", "bool_and", "bool_or", "ite",
   "bv_add", "bv_sub", "bv_mul", "bv_udiv", "bv_urem", "bv_and", "bv_or",
   "bv_xor", "bv_shl", "bv_lshr", "bv_ashr", "bv_not", "concat", "select",
   "store", "bv_ult", "bv_ule", "bv_slt", "bv_sle", "eq"].contains op

partial def parseExpr (json : Json) : Except String RawExpr := do
  let op ← stringField json "op"
  let sort ← parseSort (← field json "sort")
  let args : Except String (Array RawExpr) := do
    (← (← field json "args").getArr?).mapM parseExpr
  match op with
  | "var" =>
      requireFields json ["op", "sort", "name"] "expression"
      pure { op, sort, name? := some (← nameField json "name") }
  | "bool_lit" =>
      requireFields json ["op", "sort", "value"] "expression"
      pure { op, sort, boolValue? := some (← (← field json "value").getBool?) }
  | "bv_lit" =>
      requireFields json ["op", "sort", "value"] "expression"
      pure { op, sort, natValue? := some (← natField json "value") }
  | "zero_extend" | "sign_extend" =>
      requireFields json ["op", "sort", "args", "amount"] "expression"
      pure { op, sort, args := (← args), amount? := some (← natField json "amount") }
  | "extract" =>
      requireFields json ["op", "sort", "args", "hi", "lo"] "expression"
      let args ← args
      let hi ← natField json "hi"
      let lo ← natField json "lo"
      pure { op, sort, args, hi? := some hi, lo? := some lo }
  | _ =>
      if !plainArgsOp op then throw s!"unknown expression operator {op}"
      requireFields json ["op", "sort", "args"] "expression"
      pure { op, sort, args := (← args) }

private def parseDeclaration (json : Json) : Except String Decl := do
  requireFields json ["name", "sort"] "declaration"
  pure { name := ← nameField json "name", sort := ← parseSort (← field json "sort") }

private def parseAssignment (json : Json) : Except String RawAssignment := do
  requireFields json ["name", "value"] "assignment"
  pure { name := ← nameField json "name", value := ← parseExpr (← field json "value") }

private def parseTarget (json : Json) : Except String RawTarget := do
  match ← stringField json "kind" with
  | "address" =>
      requireFields json ["kind", "value"] "target"
      pure (.address (← natField json "value"))
  | "symbolic" =>
      requireFields json ["kind", "value"] "target"
      pure (.symbolic (← parseExpr (← field json "value")))
  | "halt" => requireFields json ["kind"] "target" *> pure .halt
  | "error" => requireFields json ["kind"] "target" *> pure .error
  | "stuck" => requireFields json ["kind"] "target" *> pure .stuck
  | kind => throw s!"unknown target kind {kind}"

private def parseStep (json : Json) : Except String RawStep := do
  requireFields json ["guard", "simultaneous_update", "target", "mirrored_pc"] "step"
  pure {
    guard := ← parseExpr (← field json "guard")
    update := ← (← (← field json "simultaneous_update").getArr?).mapM parseAssignment
    target := ← parseTarget (← field json "target")
    mirroredPc := ← parseExpr (← field json "mirrored_pc")
  }

private def parseModel (json : Json) : Except String RawModel := do
  requireFields json ["schema", "source", "declarations", "steps"] "instruction model"
  if (← stringField json "schema") != "ixyk.qf_abv.instruction.v1" then
    throw "unknown instruction-model schema"
  pure {
    source := ← natField json "source"
    declarations := ← (← (← field json "declarations").getArr?).mapM parseDeclaration
    steps := ← (← (← field json "steps").getArr?).mapM parseStep
  }

private def parseUnavailable (json : Json) : Except String String := do
  requireFields json ["schema", "status", "error"] "unavailable instruction model"
  if (← stringField json "schema") != "ixyk.unavailable_instruction_model.v1" then
    throw "unknown unavailable-model schema"
  if !["unsupported", "acquisition_error"].contains (← stringField json "status") then
    throw "unknown unavailable-model status"
  nameField json "error"

private def lookupVar : (context : Ctx) → (name : String) → (sort : TermSort) →
    Option (Var context sort)
  | [], _, _ => none
  | declaration :: rest, name, sort =>
      if declaration.name = name then
        if equal : declaration.sort = sort then some (equal ▸ .here) else none
      else
        .there <$> lookupVar rest name sort

private def asSort (expected : TermSort) :
    SomeExpr context → Except String (Expr context expected)
  | .mk actual expression =>
      if equal : actual = expected then pure (equal ▸ expression)
      else throw s!"expression sort mismatch: expected {repr expected}, got {repr actual}"

private def requireArity (raw : RawExpr) (arity : Nat) : Except String Unit :=
  if raw.args.size = arity then pure () else throw s!"{raw.op} has wrong arity"

private def requireSort (raw : RawExpr) (sort : TermSort) : Except String Unit :=
  if raw.sort = sort then pure () else throw s!"declared result sort disagrees for {raw.op}"

private def requireSome (value : Option α) (message : String) : Except String α :=
  match value with
  | some value => pure value
  | none => throw message

mutual
  private partial def elaborateBoolBin (raw : RawExpr)
      (make : Expr context .bool → Expr context .bool → Expr context .bool) :
      Except String (SomeExpr context) := do
    requireArity raw 2
    requireSort raw .bool
    pure (.mk .bool (make
      (← asSort .bool (← elaborateExpr context raw.args[0]!))
      (← asSort .bool (← elaborateExpr context raw.args[1]!))))

  private partial def elaborateBvBin (raw : RawExpr) (op : BvBinOp) :
      Except String (SomeExpr context) := do
    requireArity raw 2
    match ← elaborateExpr context raw.args[0]! with
    | .mk (.bv width) left =>
        requireSort raw (.bv width)
        pure (.mk (.bv width) (.bvBin op width left
          (← asSort (.bv width) (← elaborateExpr context raw.args[1]!))))
    | _ => throw s!"{raw.op} requires bit-vector operands"

  private partial def elaborateBvCmp (raw : RawExpr) (op : BvCmpOp) :
      Except String (SomeExpr context) := do
    requireArity raw 2
    requireSort raw .bool
    match ← elaborateExpr context raw.args[0]! with
    | .mk (.bv width) left =>
        pure (.mk .bool (.bvCmp op width left
          (← asSort (.bv width) (← elaborateExpr context raw.args[1]!))))
    | _ => throw s!"{raw.op} requires bit-vector operands"

  partial def elaborateExpr (context : Ctx) (raw : RawExpr) :
      Except String (SomeExpr context) := do
    match raw.op with
    | "var" =>
        requireArity raw 0
        let name ← requireSome raw.name? "variable has no name"
        match lookupVar context name raw.sort with
        | some index => pure (.mk raw.sort (.var index))
        | none => throw s!"unknown or wrongly sorted variable {name}"
    | "bool_lit" =>
        requireArity raw 0
        requireSort raw .bool
        pure (.mk .bool (.boolLit (← requireSome raw.boolValue? "missing Boolean value")))
    | "bv_lit" =>
        requireArity raw 0
        match raw.sort with
        | .bv width =>
            let value ← requireSome raw.natValue? "missing bit-vector value"
            if value ≥ 2 ^ width then throw "noncanonical bit-vector literal"
            pure (.mk (.bv width) (.bvLit width value))
        | _ => throw "bit-vector literal has non-bit-vector sort"
    | "const_array" =>
        requireArity raw 1
        match raw.sort with
        | .array indexWidth valueWidth =>
            pure (.mk (.array indexWidth valueWidth) (.constArray indexWidth valueWidth
              (← asSort (.bv valueWidth) (← elaborateExpr context raw.args[0]!))))
        | _ => throw "const_array has non-array sort"
    | "bool_not" =>
        requireArity raw 1
        requireSort raw .bool
        pure (.mk .bool (.boolNot (← asSort .bool (← elaborateExpr context raw.args[0]!))))
    | "bool_and" => elaborateBoolBin raw .boolAnd
    | "bool_or" => elaborateBoolBin raw .boolOr
    | "ite" =>
        requireArity raw 3
        let condition ← asSort .bool (← elaborateExpr context raw.args[0]!)
        match ← elaborateExpr context raw.args[1]! with
        | .mk sort thenValue =>
            requireSort raw sort
            pure (.mk sort (.ite condition thenValue
              (← asSort sort (← elaborateExpr context raw.args[2]!))))
    | "bv_add" => elaborateBvBin raw .add
    | "bv_sub" => elaborateBvBin raw .sub
    | "bv_mul" => elaborateBvBin raw .mul
    | "bv_udiv" => elaborateBvBin raw .udiv
    | "bv_urem" => elaborateBvBin raw .urem
    | "bv_and" => elaborateBvBin raw .and
    | "bv_or" => elaborateBvBin raw .or
    | "bv_xor" => elaborateBvBin raw .xor
    | "bv_shl" => elaborateBvBin raw .shl
    | "bv_lshr" => elaborateBvBin raw .lshr
    | "bv_ashr" => elaborateBvBin raw .ashr
    | "bv_not" =>
        requireArity raw 1
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.bv width) value =>
            requireSort raw (.bv width)
            pure (.mk (.bv width) (.bvNot width value))
        | _ => throw "bv_not requires a bit-vector"
    | "zero_extend" | "sign_extend" =>
        requireArity raw 1
        let amount ← requireSome raw.amount? "extension has no amount"
        if amount = 0 then throw "extension amount must be positive"
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.bv width) value =>
            requireSort raw (.bv (width + amount))
            if raw.op = "zero_extend" then
              pure (.mk (.bv (width + amount)) (.zeroExt width amount value))
            else
              pure (.mk (.bv (width + amount)) (.signExt width amount value))
        | _ => throw "extension requires a bit-vector"
    | "extract" =>
        requireArity raw 1
        let hi ← requireSome raw.hi? "extract has no high bound"
        let lo ← requireSome raw.lo? "extract has no low bound"
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.bv width) value =>
            if high : hi < width then
              if low : lo ≤ hi then
                let spec : ExtractSpec width := { hi, lo, hiLtWidth := high, loLeHi := low }
                requireSort raw (.bv spec.resultWidth)
                pure (.mk (.bv spec.resultWidth) (.extract spec value))
              else throw "extract low bound exceeds high bound"
            else throw "extract high bound exceeds operand width"
        | _ => throw "extract requires a bit-vector"
    | "concat" =>
        requireArity raw 2
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.bv highWidth) high =>
            match ← elaborateExpr context raw.args[1]! with
            | .mk (.bv lowWidth) low =>
                requireSort raw (.bv (highWidth + lowWidth))
                pure (.mk (.bv (highWidth + lowWidth)) (.concat highWidth lowWidth high low))
            | _ => throw "concat low operand is not a bit-vector"
        | _ => throw "concat high operand is not a bit-vector"
    | "select" =>
        requireArity raw 2
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.array indexWidth valueWidth) array =>
            requireSort raw (.bv valueWidth)
            pure (.mk (.bv valueWidth) (.select indexWidth valueWidth array
              (← asSort (.bv indexWidth) (← elaborateExpr context raw.args[1]!))))
        | _ => throw "select requires an array"
    | "store" =>
        requireArity raw 3
        match ← elaborateExpr context raw.args[0]! with
        | .mk (.array indexWidth valueWidth) array =>
            requireSort raw (.array indexWidth valueWidth)
            pure (.mk (.array indexWidth valueWidth) (.store indexWidth valueWidth array
              (← asSort (.bv indexWidth) (← elaborateExpr context raw.args[1]!))
              (← asSort (.bv valueWidth) (← elaborateExpr context raw.args[2]!))))
        | _ => throw "store requires an array"
    | "bv_ult" => elaborateBvCmp raw .ult
    | "bv_ule" => elaborateBvCmp raw .ule
    | "bv_slt" => elaborateBvCmp raw .slt
    | "bv_sle" => elaborateBvCmp raw .sle
    | "eq" =>
        requireArity raw 2
        requireSort raw .bool
        match ← elaborateExpr context raw.args[0]! with
        | .mk .bool left =>
            pure (.mk .bool (.eqBool left
              (← asSort .bool (← elaborateExpr context raw.args[1]!))))
        | .mk (.bv width) left =>
            pure (.mk .bool (.eqBv width left
              (← asSort (.bv width) (← elaborateExpr context raw.args[1]!))))
        | _ => throw "array equality is not admitted"
    | op => throw s!"unknown expression operator {op}"

end

private def elaborateUpdate (input : Ctx) :
    (output : Ctx) → List RawAssignment → Except String (StateUpdate input output)
  | [], [] => pure .nil
  | declaration :: rest, assignment :: assignments => do
      if assignment.name != declaration.name then
        throw "simultaneous update does not follow declaration order"
      pure (.cons
        (← asSort declaration.sort (← elaborateExpr input assignment.value))
        (← elaborateUpdate input rest assignments))
  | _, _ => throw "simultaneous update must assign every declaration exactly once"

private def uniqueNames (context : Ctx) : Bool :=
  let names := context.map Decl.name
  names.length = names.eraseDups.length

private def checkMirroredPc (step : RawStep) : Except String Unit :=
  match step.update.find? (·.name = "rip") with
  | some assignment =>
      if assignment.value == step.mirroredPc then pure ()
      else throw "mirrored_pc differs from the simultaneous rip update"
  | none => throw "simultaneous update has no rip assignment"

private def elaborateTarget (context : Ctx) : RawTarget → Except String (Target context)
  | .address value => do
      if value ≥ 2 ^ 64 then throw "address exceeds BV64"
      pure (.address (.bvLit 64 value))
  | .symbolic value => do
      pure (.address (← asSort (.bv 64) (← elaborateExpr context value)))
  | .halt => pure .halt
  | .error => pure .error
  | .stuck => pure .stuck

private def elaborateStep (context : Ctx) (source : Control) (raw : RawStep) :
    Except String (Edge context) := do
  checkMirroredPc raw
  let _ ← asSort (.bv 64) (← elaborateExpr context raw.mirroredPc)
  pure {
    source
    guard := ← asSort .bool (← elaborateExpr context raw.guard)
    update := ← elaborateUpdate context context raw.update.toList
    target := ← elaborateTarget context raw.target
  }

private def elaborateModel (raw : RawModel) : Except String STS := do
  if raw.source ≥ 2 ^ 64 then throw "instruction source exceeds BV64"
  if raw.declarations.isEmpty then throw "declarations must be nonempty"
  if raw.steps.isEmpty then throw "instruction model must contain an edge"
  let context := raw.declarations.toList
  if !uniqueNames context then throw "declaration names must be unique"
  let source := Control.address (BitVec.ofNat 64 raw.source)
  pure { context, edges := ← raw.steps.toList.mapM (elaborateStep context source) }

def parse (text : String) : Except String Imported := do
  let json ← Json.parse text
  match ← stringField json "schema" with
  | "ixyk.qf_abv.instruction.v1" => .model <$> elaborateModel (← parseModel json)
  | "ixyk.unavailable_instruction_model.v1" => .unavailable <$> parseUnavailable json
  | schema => throw s!"unknown instruction-model schema {schema}"

def parseAndElaborate (text : String) : Except String STS := do
  match ← parse text with
  | .model system => pure system
  | .unavailable error => throw s!"instruction model is unavailable: {error}"

end Ixyk.Artifact
