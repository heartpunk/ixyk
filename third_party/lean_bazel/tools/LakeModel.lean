module

public import Lake

public section

open Lean

namespace LeanBazel

def exportSchemaVersion : String := "4"
def authoritySchemaVersion : String := "1"

private def failAt (context message : String) : Except String α :=
  throw s!"{context}: {message}"

private def validateKeys
    (context : String) (allowed required : Array String) (json : Json) : Except String Unit := do
  let object <- json.getObj?
  for key in object.keysArray do
    unless allowed.contains key do
      failAt context s!"unknown field '{key}'"
  for key in required do
    unless object.contains key do
      failAt context s!"missing required field '{key}'"

private def field (context key : String) [FromJson alpha] (json : Json) : Except String alpha := do
  let value <- json.getObjVal? key
  match fromJson? value with
  | .ok result => pure result
  | .error error => failAt s!"{context}.{key}" error

private def optionalField
    (context key : String) [FromJson alpha] (json : Json) : Except String (Option alpha) := do
  let object <- json.getObj?
  match object.get? key with
  | none | some .null => pure none
  | some value =>
      match fromJson? value with
      | .ok result => pure (some result)
      | .error error => failAt s!"{context}.{key}" error

private def validateArrayObjects
    (context fieldName : String) (validate : String -> Json -> Except String Unit)
    (json : Json) : Except String Unit := do
  let values : Array Json <- field context fieldName json
  for h : index in [0:values.size] do
    validate s!"{context}.{fieldName}[{index}]" values[index]

structure EnvMap where
  entries : Array (String × String) := #[]
  deriving Inhabited, Repr

instance : ToJson EnvMap where
  toJson env := Json.mkObj <| env.entries.toList.map fun (key, value) => (key, toJson value)

instance : FromJson EnvMap where
  fromJson? json := do
    let object <- json.getObj?
    let entries <- object.toArray.mapM fun (key, value) => do
      let value <- value.getStr?
      pure (key, value)
    pure {entries}

def EnvMap.normalized (env : EnvMap) : EnvMap :=
  {entries := env.entries.qsort (fun left right => left.1 < right.1)}

inductive AuthorityToolKind
  | process
  | leanExe
  | leanProbe
  deriving Inhabited, Repr, BEq

def AuthorityToolKind.toString : AuthorityToolKind -> String
  | .process => "process"
  | .leanExe => "lean_exe"
  | .leanProbe => "lean_probe"

instance : ToJson AuthorityToolKind where
  toJson kind := toJson kind.toString

instance : FromJson AuthorityToolKind where
  fromJson? json := do
    match <- json.getStr? with
    | "process" => pure .process
    | "lean_exe" => pure .leanExe
    | "lean_probe" => pure .leanProbe
    | value => throw s!"unsupported authority tool kind '{value}'"

inductive AuthorityGeneratorMode
  | check
  | write
  deriving Inhabited, Repr, BEq

def AuthorityGeneratorMode.toString : AuthorityGeneratorMode -> String
  | .check => "check"
  | .write => "write"

instance : ToJson AuthorityGeneratorMode where
  toJson mode := toJson mode.toString

instance : FromJson AuthorityGeneratorMode where
  fromJson? json := do
    match <- json.getStr? with
    | "check" => pure .check
    | "write" => pure .write
    | value => throw s!"unsupported authority generator mode '{value}'"

structure AuthorityResource where
  name : String
  path : String
  digest : Option String := none
  deriving Inhabited, Repr, ToJson, FromJson

structure AuthorityTool where
  name : String
  kind : AuthorityToolKind
  command : String
  target : Option String := none
  deriving Inhabited, Repr, ToJson, FromJson

structure AuthorityGenerator where
  name : String
  tool : String
  args : Array String
  env : EnvMap
  inputs : Array String
  outputs : Array String
  mode : AuthorityGeneratorMode
  deterministic : Bool
  deriving Inhabited, Repr, ToJson, FromJson

structure AuthorityExpected where
  exit : Nat
  stdout : Option String := none
  stderr : Option String := none
  deriving Inhabited, Repr, ToJson, FromJson

structure AuthorityCheck where
  name : String
  kind : AuthorityToolKind
  root : String
  args : Array String
  env : EnvMap
  inputs : Array String
  resources : Array String
  deps : Array String
  expected : AuthorityExpected
  deriving Inhabited, Repr, ToJson, FromJson

structure AuthorityCatalog where
  schemaVersion : String := authoritySchemaVersion
  resources : Array AuthorityResource := #[]
  tools : Array AuthorityTool := #[]
  generators : Array AuthorityGenerator := #[]
  checks : Array AuthorityCheck := #[]
  deriving Inhabited, Repr, ToJson, FromJson

private def validateResourceJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["name", "path", "digest"] #["name", "path"] json

private def validateToolJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["name", "kind", "command", "target"] #["name", "kind", "command"] json

private def validateGeneratorJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context
    #["name", "tool", "args", "env", "inputs", "outputs", "mode", "deterministic"]
    #["name", "tool", "args", "env", "inputs", "outputs", "mode", "deterministic"] json

private def validateExpectedJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["exit", "stdout", "stderr"] #["exit"] json

private def validateCheckJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context
    #["name", "kind", "root", "args", "env", "inputs", "resources", "deps", "expected"]
    #["name", "kind", "root", "args", "env", "inputs", "resources", "deps", "expected"] json
  validateExpectedJson s!"{context}.expected" (← json.getObjVal? "expected")

private def isRelativePath (path : String) : Bool :=
  !path.isEmpty && !path.startsWith "/" &&
    !(path.splitOn "/").contains ".."

private def ensureUnique (context : String) (names : Array String) : Except String Unit := do
  let mut seen : Std.HashSet String := {}
  for name in names do
    if name.isEmpty then
      failAt context "names must be nonempty"
    if seen.contains name then
      failAt context s!"duplicate name '{name}'"
    seen := seen.insert name

def AuthorityCatalog.normalized (catalog : AuthorityCatalog) : AuthorityCatalog :=
  { catalog with
    resources := catalog.resources.qsort (fun left right => left.name < right.name)
    tools := catalog.tools.qsort (fun left right => left.name < right.name)
    generators := catalog.generators.map (fun generator =>
      {generator with env := generator.env.normalized}) |>.qsort (fun left right => left.name < right.name)
    checks := catalog.checks.map (fun check =>
      {check with env := check.env.normalized}) |>.qsort (fun left right => left.name < right.name) }

def AuthorityCatalog.validate (catalog : AuthorityCatalog) : Except String Unit := do
  unless catalog.schemaVersion == authoritySchemaVersion do
    failAt "authorityCatalog.schemaVersion"
      s!"unsupported version '{catalog.schemaVersion}', expected '{authoritySchemaVersion}'"
  ensureUnique "authorityCatalog.resources" (catalog.resources.map (·.name))
  ensureUnique "authorityCatalog.tools" (catalog.tools.map (·.name))
  ensureUnique "authorityCatalog.generators" (catalog.generators.map (·.name))
  ensureUnique "authorityCatalog.checks" (catalog.checks.map (·.name))
  for resource in catalog.resources do
    unless isRelativePath resource.path do
      failAt s!"authorityCatalog.resources.{resource.name}.path"
        s!"expected repository-relative path, got '{resource.path}'"
  for tool in catalog.tools do
    if tool.command.isEmpty then
      failAt s!"authorityCatalog.tools.{tool.name}.command" "command must be nonempty"
    match tool.kind, tool.target with
    | .leanExe, some target =>
        if target.isEmpty then
          failAt s!"authorityCatalog.tools.{tool.name}.target" "target must be nonempty"
    | .leanExe, none =>
        failAt s!"authorityCatalog.tools.{tool.name}.target" "lean_exe tool requires target"
    | _, some _ =>
        failAt s!"authorityCatalog.tools.{tool.name}.target"
          "target is supported only for lean_exe tools"
    | _, none => pure ()
  let toolNames := catalog.tools.map (·.name)
  let resourceNames := catalog.resources.map (·.name)
  let mut allOutputs : Std.HashSet String := {}
  for generator in catalog.generators do
    unless toolNames.contains generator.tool do
      failAt s!"authorityCatalog.generators.{generator.name}.tool"
        s!"unknown tool '{generator.tool}'"
    unless generator.deterministic do
      failAt s!"authorityCatalog.generators.{generator.name}.deterministic"
        "authority generators must be deterministic"
    for input in generator.inputs do
      unless isRelativePath input do
        failAt s!"authorityCatalog.generators.{generator.name}.inputs"
          s!"expected repository-relative path, got '{input}'"
    for output in generator.outputs do
      unless isRelativePath output do
        failAt s!"authorityCatalog.generators.{generator.name}.outputs"
          s!"expected repository-relative path, got '{output}'"
      if generator.inputs.contains output then
        failAt s!"authorityCatalog.generators.{generator.name}.outputs"
          s!"output '{output}' is also an input"
      if allOutputs.contains output then
        failAt "authorityCatalog.generators.outputs" s!"duplicate output '{output}'"
      allOutputs := allOutputs.insert output
  for check in catalog.checks do
    if check.root.isEmpty then
      failAt s!"authorityCatalog.checks.{check.name}.root" "root must be nonempty"
    for input in check.inputs do
      unless isRelativePath input do
        failAt s!"authorityCatalog.checks.{check.name}.inputs"
          s!"expected repository-relative path, got '{input}'"
    for resource in check.resources do
      unless resourceNames.contains resource do
        failAt s!"authorityCatalog.checks.{check.name}.resources"
          s!"unknown resource '{resource}'"

def validateAuthorityCatalogJson (json : Json) : Except String Unit := do
  validateKeys "authorityCatalog"
    #["schemaVersion", "resources", "tools", "generators", "checks"]
    #["schemaVersion", "resources", "tools", "generators", "checks"] json
  validateArrayObjects "authorityCatalog" "resources" validateResourceJson json
  validateArrayObjects "authorityCatalog" "tools" validateToolJson json
  validateArrayObjects "authorityCatalog" "generators" validateGeneratorJson json
  validateArrayObjects "authorityCatalog" "checks" validateCheckJson json

def parseAuthorityCatalog (json : Json) : Except String AuthorityCatalog := do
  validateAuthorityCatalogJson json
  let catalog : AuthorityCatalog <- fromJson? json
  catalog.validate
  pure catalog.normalized

structure ImportModel where
  module : String
  importAll : Bool
  isExported : Bool
  isMeta : Bool
  localPackage : Option String := none
  deriving Inhabited, Repr, ToJson, FromJson

structure HeaderModel where
  isModule : Bool
  imports : Array ImportModel
  deriving Inhabited, Repr, ToJson, FromJson

structure ModuleConfigModel where
  buildType : String
  backend : String
  leanOptions : Json
  leanArgs : Array String
  weakLeanArgs : Array String
  leancArgs : Array String
  weakLeancArgs : Array String
  linkArgs : Array String
  weakLinkArgs : Array String
  platformIndependent : Option Bool := none
  allowImportAll : Bool
  precompileModules : Bool
  nativeFacetsNoExport : Array String
  nativeFacetsExport : Array String
  deriving Inhabited, ToJson, FromJson

structure ModuleModel where
  name : String
  source : String
  owners : Array String
  header : HeaderModel
  config : ModuleConfigModel
  deriving Inhabited, ToJson, FromJson

structure LibraryModel where
  name : String
  srcDir : String
  roots : Array String
  moduleNames : Array String
  defaultFacets : Array String
  nativeFacetsNoExport : Array String
  nativeFacetsExport : Array String
  deriving Inhabited, Repr, ToJson, FromJson

structure NativeLinkInputModel where
  package : String
  module : String
  facet : String
  deriving Inhabited, Repr, ToJson, FromJson

structure ExecutableModel where
  name : String
  root : String
  source : String
  outputName : String
  supportInterpreter : Bool
  sharedLean : Bool
  linkArgs : Array String
  weakLinkArgs : Array String
  nativeFacetsNoExport : Array String
  nativeFacetsExport : Array String
  orderedLinkInputs : Array NativeLinkInputModel
  deriving Inhabited, Repr, ToJson, FromJson

structure TargetModel where
  name : String
  kind : String
  deriving Inhabited, Repr, ToJson, FromJson

structure InputFileModel where
  name : String
  path : String
  text : Bool
  deriving Inhabited, Repr, ToJson, FromJson

structure InputDirModel where
  name : String
  path : String
  text : Bool
  /-- R0 deliberately accepts only Lake's declarative `star` filter. -/
  filter : String
  deriving Inhabited, Repr, ToJson, FromJson

structure PackageModel where
  name : String
  packageId : Option String := none
  directory : String
  configFile : String
  defaultTargets : Array String
  testDriver : Option String := none
  testDriverArgs : Array String
  lintDriver : Option String := none
  lintDriverArgs : Array String
  targets : Array TargetModel
  inputFiles : Array InputFileModel
  inputDirs : Array InputDirModel
  libraries : Array LibraryModel
  executables : Array ExecutableModel
  modules : Array ModuleModel
  deriving Inhabited, ToJson, FromJson

structure WorkspaceModel where
  rootPackage : String
  packages : Array PackageModel
  deriving Inhabited, ToJson, FromJson

structure ToolchainModel where
  target : String
  platform : String
  githash : String
  distributionIdentity : String
  sysroot : String
  lean : String
  leanir : String
  leanc : String
  cc : String
  ar : String
  includeDir : String
  leanLibDir : String
  systemLibDir : String
  ccFlags : Array String
  ccLinkStaticFlags : Array String
  ccLinkSharedFlags : Array String
  deriving Inhabited, Repr, ToJson, FromJson

structure ExportModel where
  schemaVersion : String := exportSchemaVersion
  workspace : WorkspaceModel
  toolchain : ToolchainModel
  authorityCatalog : AuthorityCatalog
  deriving Inhabited, ToJson, FromJson

private def validateImportModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["module", "importAll", "isExported", "isMeta", "localPackage"]
    #["module", "importAll", "isExported", "isMeta"] json

private def validateHeaderModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context #["isModule", "imports"] #["isModule", "imports"] json
  validateArrayObjects context "imports" validateImportModelJson json

private def validateModuleConfigJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context
    #["buildType", "backend", "leanOptions", "leanArgs", "weakLeanArgs", "leancArgs",
      "weakLeancArgs", "linkArgs", "weakLinkArgs", "platformIndependent", "allowImportAll",
      "precompileModules", "nativeFacetsNoExport", "nativeFacetsExport"]
    #["buildType", "backend", "leanOptions", "leanArgs", "weakLeanArgs", "leancArgs",
      "weakLeancArgs", "linkArgs", "weakLinkArgs", "allowImportAll", "precompileModules",
      "nativeFacetsNoExport", "nativeFacetsExport"] json

private def validateModuleModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context #["name", "source", "owners", "header", "config"]
    #["name", "source", "owners", "header", "config"] json
  validateHeaderModelJson s!"{context}.header" (← json.getObjVal? "header")
  validateModuleConfigJson s!"{context}.config" (← json.getObjVal? "config")

private def validateLibraryModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context
    #["name", "srcDir", "roots", "moduleNames", "defaultFacets", "nativeFacetsNoExport",
      "nativeFacetsExport"]
    #["name", "srcDir", "roots", "moduleNames", "defaultFacets", "nativeFacetsNoExport",
      "nativeFacetsExport"] json

private def validateNativeLinkInputModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["package", "module", "facet"] #["package", "module", "facet"] json

private def validateExecutableModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context
    #["name", "root", "source", "outputName", "supportInterpreter", "sharedLean", "linkArgs",
      "weakLinkArgs", "nativeFacetsNoExport", "nativeFacetsExport", "orderedLinkInputs"]
    #["name", "root", "source", "outputName", "supportInterpreter", "sharedLean", "linkArgs",
      "weakLinkArgs", "nativeFacetsNoExport", "nativeFacetsExport", "orderedLinkInputs"] json
  validateArrayObjects context "orderedLinkInputs" validateNativeLinkInputModelJson json

private def validateTargetModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["name", "kind"] #["name", "kind"] json

private def validateInputFileModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context #["name", "path", "text"] #["name", "path", "text"] json

private def validateInputDirModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context #["name", "path", "text", "filter"]
    #["name", "path", "text", "filter"] json
  let filter : String ← field context "filter" json
  unless filter == "star" do
    failAt s!"{context}.filter" s!"unsupported input directory filter '{filter}'"

private def validatePackageModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context
    #["name", "packageId", "directory", "configFile", "defaultTargets", "testDriver", "testDriverArgs",
      "lintDriver", "lintDriverArgs", "targets", "inputFiles", "inputDirs", "libraries",
      "executables", "modules"]
    #["name", "packageId", "directory", "configFile", "defaultTargets", "testDriverArgs", "lintDriverArgs",
      "targets", "inputFiles", "inputDirs", "libraries", "executables", "modules"] json
  validateArrayObjects context "targets" validateTargetModelJson json
  validateArrayObjects context "inputFiles" validateInputFileModelJson json
  validateArrayObjects context "inputDirs" validateInputDirModelJson json
  validateArrayObjects context "libraries" validateLibraryModelJson json
  validateArrayObjects context "executables" validateExecutableModelJson json
  validateArrayObjects context "modules" validateModuleModelJson json

private def validateWorkspaceModelJson (context : String) (json : Json) : Except String Unit := do
  validateKeys context #["rootPackage", "packages"] #["rootPackage", "packages"] json
  validateArrayObjects context "packages" validatePackageModelJson json

private def validateToolchainModelJson (context : String) (json : Json) : Except String Unit :=
  validateKeys context
    #["target", "platform", "githash", "distributionIdentity", "sysroot", "lean", "leanir",
      "leanc", "cc", "ar", "includeDir", "leanLibDir", "systemLibDir", "ccFlags",
      "ccLinkStaticFlags", "ccLinkSharedFlags"]
    #["target", "platform", "githash", "distributionIdentity", "sysroot", "lean", "leanir",
      "leanc", "cc", "ar", "includeDir", "leanLibDir", "systemLibDir", "ccFlags",
      "ccLinkStaticFlags", "ccLinkSharedFlags"] json

def parseExportModel (json : Json) : Except String ExportModel := do
  validateKeys "exportModel" #["schemaVersion", "workspace", "toolchain", "authorityCatalog"]
    #["schemaVersion", "workspace", "toolchain", "authorityCatalog"] json
  let schemaVersion : String ← field "exportModel" "schemaVersion" json
  unless schemaVersion == exportSchemaVersion do
    failAt "exportModel.schemaVersion"
      s!"unsupported version '{schemaVersion}', expected '{exportSchemaVersion}'"
  validateWorkspaceModelJson "exportModel.workspace" (← json.getObjVal? "workspace")
  validateToolchainModelJson "exportModel.toolchain" (← json.getObjVal? "toolchain")
  let catalog ← parseAuthorityCatalog (← json.getObjVal? "authorityCatalog")
  let model : ExportModel ← fromJson? json
  pure {model with authorityCatalog := catalog}

def parseExportModelString (raw : String) : Except String ExportModel := do
  let json ← Json.parse raw
  parseExportModel json

end LeanBazel
