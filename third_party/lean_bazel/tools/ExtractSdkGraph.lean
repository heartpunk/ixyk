import Lean

open Lean

namespace ExtractSdkGraph

structure Entry where
  name : String
  mainPath : String
  mainRelative : String

structure ImportRecord where
  moduleName : String
  importAll : Bool
  isExported : Bool
  isMeta : Bool

structure ModuleRecord where
  name : String
  mainRelative : String
  serverRelative : Option String
  privateRelative : Option String
  irRelative : Option String
  isModule : Bool
  imports : Array ImportRecord

def fail (message : String) : IO α :=
  throw <| IO.userError message

def quote (value : String) : String :=
  let escaped := value.replace "\\" "\\\\" |>.replace "\"" "\\\"" |>.replace "\n" "\\n"
  "\"" ++ escaped ++ "\""

def starlarkBool (value : Bool) : String :=
  if value then "True" else "False"

@[noinline] def ownString (value : String) : String :=
  -- A one-component Name may render by returning its compacted-region String
  -- directly. Round-trip through UTF-8 before freeing that region.
  String.fromUTF8! value.toUTF8

def stripSuffix (value suffix : String) : Option String :=
  if value.endsWith suffix then
    some <| (value.take (value.length - suffix.length)).toString
  else
    none

def parseManifest (contents : String) : IO (Array Entry) := do
  let mut entries : Array Entry := #[]
  let mut names : Std.HashSet String := {}
  let mut relativePaths : Std.HashSet String := {}
  for line in contents.splitOn "\n" do
    if !line.isEmpty then
      match line.splitOn "\t" with
      | [name, mainPath, mainRelative] =>
          if name.isEmpty || mainPath.isEmpty || mainRelative.isEmpty then
            fail s!"manifest contains an empty field: {line}"
          if names.contains name then
            fail s!"duplicate SDK module name: {name}"
          if relativePaths.contains mainRelative then
            fail s!"duplicate SDK module path: {mainRelative}"
          if mainRelative.startsWith "/" || (mainRelative.splitOn "/").contains ".." then
            fail s!"SDK module path is not repository-relative: {mainRelative}"
          if !(mainRelative.endsWith ".olean") then
            fail s!"SDK module path does not end in .olean: {mainRelative}"
          names := names.insert name
          relativePaths := relativePaths.insert mainRelative
          entries := entries.push { name, mainPath, mainRelative }
      | _ => fail s!"malformed manifest line: {line}"
  if entries.isEmpty then
    fail "SDK manifest is empty"
  pure <| entries.qsort fun left right => left.name < right.name

def scanSdk (root relativeRoot : String) : IO (Array Entry) := do
  let rootPath := (System.FilePath.mk root).normalize
  if !(← rootPath.isDir) then
    fail s!"Lean SDK module root is not a directory: {root}"
  let rootString := rootPath.toString
  let rootPrefix := if rootString.endsWith "/" then rootString else rootString ++ "/"
  let mut entries : Array Entry := #[]
  for path in ← rootPath.walkDir do
    if path.extension == some "olean" && !(← path.isDir) then
      let absolute := path.normalize.toString
      if !absolute.startsWith rootPrefix then
        fail s!"walked SDK artifact escaped module root: {absolute}"
      let tail := (absolute.drop rootPrefix.length).toString
      let stem ← match stripSuffix tail ".olean" with
        | some stem => pure stem
        | none => fail s!"walked SDK artifact lacks .olean suffix: {absolute}"
      if stem.isEmpty || (stem.splitOn "/").any (·.isEmpty) then
        fail s!"walked SDK artifact has malformed module path: {absolute}"
      entries := entries.push {
        name := stem.replace "/" "."
        mainPath := absolute
        mainRelative := relativeRoot ++ "/" ++ tail
      }
  parseManifest <| String.intercalate "\n" <| entries.toList.map fun (entry : Entry) =>
    String.intercalate "\t" [entry.name, entry.mainPath, entry.mainRelative]

unsafe def readOwnedMain (path : String) : IO (Bool × Array ImportRecord × CompactedRegion) := do
  let (data, region) ← readModuleData path
  -- Do not use Array.map here: its in-place reuse optimization can retain the
  -- compacted input array. Push into a fresh array before freeing the region.
  let mut imports : Array ImportRecord := #[]
  for imported in data.imports do
    imports := imports.push {
      moduleName := ownString imported.module.toString
      importAll := imported.importAll
      isExported := imported.isExported
      isMeta := imported.isMeta
    }
  pure (data.isModule, imports, region)

unsafe def readPartRegions (paths : Array String) : IO (Array CompactedRegion) := do
  let parts ← readModuleDataParts <| paths.map System.FilePath.mk
  if parts.size != paths.size then
    fail s!"readModuleDataParts returned {parts.size} parts for {paths.size} paths"
  pure <| parts.map (·.2)

unsafe def readRegion (path : String) : IO CompactedRegion := do
  let (_, region) ← readModuleData path
  pure region

unsafe def requireFile (moduleName kind path : String) : IO Unit := do
  if !(← (System.FilePath.mk path).pathExists) then
    fail s!"SDK module {moduleName} is missing {kind} artifact: {path}"

unsafe def readModule (entry : Entry) : IO ModuleRecord := do
  requireFile entry.name "main" entry.mainPath
  let (isModule, imports, mainRegion) ← readOwnedMain entry.mainPath
  mainRegion.free
  let stem ← match stripSuffix entry.mainPath ".olean" with
    | some stem => pure stem
    | none => fail s!"SDK main artifact lacks .olean suffix: {entry.mainPath}"
  let relativeStem ← match stripSuffix entry.mainRelative ".olean" with
    | some stem => pure stem
    | none => fail s!"SDK relative artifact lacks .olean suffix: {entry.mainRelative}"
  let serverPath := entry.mainPath ++ ".server"
  let privatePath := entry.mainPath ++ ".private"
  let irPath := stem ++ ".ir"
  let serverRelative := entry.mainRelative ++ ".server"
  let privateRelative := entry.mainRelative ++ ".private"
  let irRelative := relativeStem ++ ".ir"
  if isModule then
    requireFile entry.name "server" serverPath
    requireFile entry.name "private" privatePath
    requireFile entry.name "IR" irPath
    let regions ← readPartRegions #[entry.mainPath, serverPath, privatePath]
    -- Later compacted parts retain dependencies on earlier parts, so release them
    -- in reverse dependency order after all ModuleData references have left scope.
    for region in regions.reverse do
      region.free
    let irRegion ← readRegion irPath
    irRegion.free
    pure {
      name := entry.name
      mainRelative := entry.mainRelative
      serverRelative := some serverRelative
      privateRelative := some privateRelative
      irRelative := some irRelative
      isModule
      imports
    }
  else
    if entry.name != "Leanc" && entry.name != "LeanChecker" then
      fail s!"unexpected legacy main-only SDK module: {entry.name}"
    for (kind, path) in #[
      ("server", serverPath),
      ("private", privatePath),
      ("IR", irPath),
    ] do
      if ← (System.FilePath.mk path).pathExists then
        fail s!"legacy SDK module {entry.name} unexpectedly has {kind} artifact: {path}"
    pure {
      name := entry.name
      mainRelative := entry.mainRelative
      serverRelative := none
      privateRelative := none
      irRelative := none
      isModule
      imports
    }

def topologicalOrder
    (records : Array ModuleRecord)
    (graph : Std.HashMap String (Array String)) : IO (Array String) := do
  let mut remaining : Std.HashMap String Nat := {}
  let mut dependents : Std.HashMap String (Array String) := {}
  let mut queue : Array String := #[]
  for record in records do
    let dependencies := graph.getD record.name #[]
    remaining := remaining.insert record.name dependencies.size
    if dependencies.isEmpty then
      queue := queue.push record.name
    for dependency in dependencies do
      dependents := dependents.insert dependency <|
        (dependents.getD dependency #[]).push record.name
  queue := queue.qsort (· < ·)
  let mut order := #[]
  while !queue.isEmpty do
    let name := queue.back!
    queue := queue.pop
    order := order.push name
    for dependent in dependents.getD name #[] do
      let count := remaining.getD dependent 0
      if count == 0 then
        fail s!"invalid SDK topology state for {dependent}"
      let count := count - 1
      remaining := remaining.insert dependent count
      if count == 0 then
        queue := (queue.push dependent).qsort (· < ·)
  if order.size != records.size then
    let blocked := records.filterMap fun record =>
      if remaining.getD record.name 0 == 0 then none else some record.name
    fail s!"cycle in SDK module graph involving: {String.intercalate ", " blocked.toList}"
  pure order

def buildGraph (records : Array ModuleRecord) : IO (Std.HashMap String (Array String) × Nat) := do
  let names : Std.HashSet String := records.foldl (init := {}) fun names record => names.insert record.name
  let mut graph : Std.HashMap String (Array String) := {}
  let mut edgeCount := 0
  for record in records do
    let mut dependencies := #[]
    let mut seen : Std.HashSet String := {}
    for imported in record.imports do
      let dependency := imported.moduleName
      edgeCount := edgeCount + 1
      if !names.contains dependency then
        fail s!"SDK module {record.name} imports unresolved module {dependency}"
      if !seen.contains dependency then
        seen := seen.insert dependency
        dependencies := dependencies.push dependency
    graph := graph.insert record.name dependencies
  pure (graph, edgeCount)

def renderStringList (values : Array String) (indent : String := "") : Array String :=
  values.map fun value => indent ++ quote value ++ ","

def renderOptional (value : Option String) : String :=
  value.map quote |>.getD "None"

def renderIndex
    (identity platform archiveSha256 leanGithash runtimeIdentity : String)
    (edgeCount : Nat) (topology : Array String)
    (records : Array ModuleRecord) : String := Id.run do
  let mut lines := #[
    "# Generated by tools/ExtractSdkGraph.lean; do not edit.",
    "SDK_INDEX_SCHEMA = \"lean-sdk-graph-v1\"",
    s!"SDK_IDENTITY = {quote identity}",
    s!"SDK_PLATFORM = {quote platform}",
    s!"SDK_ARCHIVE_SHA256 = {quote archiveSha256}",
    s!"SDK_LEAN_GITHASH = {quote leanGithash}",
    s!"SDK_EXTRACTOR_RUNTIME_IDENTITY = {quote runtimeIdentity}",
    s!"SDK_MODULE_COUNT = {records.size}",
    s!"SDK_DIRECT_EDGE_COUNT = {edgeCount}",
    "SDK_IMPORT_ARTIFACT_LAYOUT = [\"olean\", \"ir\", \"oleanServer\", \"oleanPrivate\"]",
    "SDK_LEGACY_MAIN_ONLY_MODULES = [\"LeanChecker\", \"Leanc\"]",
    "SDK_TOPOLOGICAL_ORDER = [",
  ]
  lines := lines ++ renderStringList topology "    "
  lines := lines.push "]"
  lines := lines.push "SDK_MODULES = {"
  for record in records do
    lines := lines.push s!"    {quote record.name}: \{" 
    lines := lines.push s!"        \"olean\": {quote record.mainRelative},"
    lines := lines.push s!"        \"ir\": {renderOptional record.irRelative},"
    lines := lines.push s!"        \"olean_server\": {renderOptional record.serverRelative},"
    lines := lines.push s!"        \"olean_private\": {renderOptional record.privateRelative},"
    lines := lines.push s!"        \"is_module\": {starlarkBool record.isModule},"
    lines := lines.push "        \"imports\": ["
    for imported in record.imports do
      lines := lines.push <| "            (" ++ String.intercalate ", " [
        quote imported.moduleName,
        starlarkBool imported.importAll,
        starlarkBool imported.isExported,
        starlarkBool imported.isMeta,
      ] ++ "),"
    lines := lines.push "        ],"
    lines := lines.push "    },"
  lines := lines.push "}"
  String.intercalate "\n" lines.toList ++ "\n"

def testRecord (name : String) (imports : Array String) : ModuleRecord := {
  name
  mainRelative := "lib/lean/" ++ name.replace "." "/" ++ ".olean"
  serverRelative := none
  privateRelative := none
  irRelative := none
  isModule := false
  imports := imports.map fun moduleName => {
    moduleName
    importAll := false
    isExported := true
    isMeta := false
  }
}

def expectFailure (description : String) (action : IO α) : IO Unit := do
  let failed ← try
    let _ ← action
    pure false
  catch _ =>
    pure true
  if !failed then
    fail s!"self-test expected failure: {description}"

def selfTest : IO Unit := do
  expectFailure "malformed manifest" <| parseManifest "only-one-field"
  expectFailure "duplicate manifest module" <|
    parseManifest "A\t/tmp/A.olean\tlib/lean/A.olean\nA\t/tmp/B.olean\tlib/lean/B.olean"
  expectFailure "missing import" <| buildGraph #[testRecord "A" #["Missing"]]
  let cyclic := #[testRecord "A" #["B"], testRecord "B" #["A"]]
  let (graph, _) ← buildGraph cyclic
  expectFailure "cycle" <| topologicalOrder cyclic graph
  IO.println "PASS: SDK graph extractor synthetic validation rejects malformed, duplicate, missing, and cyclic inputs."

unsafe def extract
    (root relativeRoot output identity platform archiveSha256 leanGithash runtimeIdentity : String) : IO Unit := do
  let entries ← scanSdk root relativeRoot
  let mut records := #[]
  for entry in entries do
    records := records.push (← readModule entry)
  let (graph, edgeCount) ← buildGraph records
  let topology ← topologicalOrder records graph
  if topology.size != records.size then
    fail s!"SDK topology has {topology.size} modules, expected {records.size}"
  let rendered := renderIndex identity platform archiveSha256 leanGithash runtimeIdentity edgeCount topology records
  IO.FS.writeFile output rendered
  IO.eprintln s!"SDK graph: modules={records.size} directEdges={edgeCount}"

unsafe def main (args : List String) : IO Unit := do
  match args with
  | ["--self-test"] => selfTest
  | [root, relativeRoot, output, identity, platform, archiveSha256, leanGithash, runtimeIdentity] =>
      extract root relativeRoot output identity platform archiveSha256 leanGithash runtimeIdentity
  | _ => fail "usage: ExtractSdkGraph --self-test | LEAN_LIB_ROOT LEAN_LIB_RELATIVE OUTPUT IDENTITY PLATFORM ARCHIVE_SHA256 LEAN_GITHASH RUNTIME_IDENTITY"

end ExtractSdkGraph

unsafe def main (args : List String) : IO Unit :=
  ExtractSdkGraph.main args
