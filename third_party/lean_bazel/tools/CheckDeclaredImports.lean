import Lean.Elab.ParseImportsFast

open Lean

def fail (message : String) : IO α :=
  throw <| IO.userError message

def sortedUnique (values : Array String) : Array String :=
  (values.qsort (· < ·)).foldl (init := #[]) fun result value =>
    if result.contains value then result else result.push value

def parseList (raw : String) : Array String :=
  if raw.isEmpty then #[] else raw.splitOn "," |>.toArray

structure DirectImportWitness where
  ordinal : Nat
  module : String
  importAll : Bool
  isExported : Bool
  isMeta : Bool
  owner : String
  deriving ToJson

def main (args : List String) : IO Unit := do
  let (source, localRaw, sdkRaw, output?) ← match args with
    | [source, localRaw, sdkRaw] => pure (source, localRaw, sdkRaw, none)
    | [source, localRaw, sdkRaw, output] => pure (source, localRaw, sdkRaw, some output)
    | _ =>
        fail "usage: CheckDeclaredImports SOURCE LOCAL_MODULES_CSV SDK_MODULES_CSV [OUTPUT_JSON]"
  let localModules := sortedUnique (parseList localRaw)
  let sdkModules := sortedUnique (parseList sdkRaw)
  for moduleName in localModules do
    if moduleName.isEmpty || sdkModules.contains moduleName then
      fail s!"invalid or multiply owned declared import: {moduleName}"
  for moduleName in sdkModules do
    if moduleName.isEmpty then
      fail "declared SDK import is empty"
  let header ← Lean.parseImports' (← IO.FS.readFile source) source
  let parsedInOrder := header.imports.map fun imported => imported.module.toString
  let parsed := sortedUnique parsedInOrder
  let declared := sortedUnique (localModules ++ sdkModules)
  if parsed != declared then
    fail s!"{source}: parsed direct imports {parsed} differ from declared local-plus-SDK imports {declared}"
  if let some output := output? then
    let imports := header.imports.mapIdx fun ordinal imported =>
      let moduleName := imported.module.toString
      {
        ordinal
        module := moduleName
        importAll := imported.importAll
        isExported := imported.isExported
        isMeta := imported.isMeta
        owner := if localModules.contains moduleName then "local" else "sdk"
      : DirectImportWitness }
    let witness := Json.mkObj [
      ("schemaVersion", "lean-bazel-direct-imports-v1"),
      ("localModules", toJson localModules),
      ("sdkModules", toJson sdkModules),
      ("imports", toJson imports),
    ]
    IO.FS.writeFile output (witness.compress ++ "\n")
  IO.println s!"PASS: {source} direct import declarations match its pinned-Lean parsed header."
