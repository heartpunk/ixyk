module

public import tools.LakeModel
import Lake.Load.Workspace
import Lake.Config.InputFile
import Lean.Elab.ParseImportsFast

open Lean System

namespace LeanBazel

private def ioError (message : String) : IO.Error :=
  .userError message

private def failIO (message : String) : IO α :=
  throw (ioError message)

private def nameString (name : Name) : String :=
  name.toString (escape := false)

private def canonicalPackageName (pkg : Lake.Package) : String :=
  nameString pkg.origName

private def canonicalPackageNameForKey
    (ws : Lake.Workspace) (key : Name) : Option String :=
  ws.packages.find? (fun pkg => pkg.keyName == key) |>.map canonicalPackageName

private def sortedStrings (values : Array String) : Array String :=
  values.qsort (fun left right => left < right)

private def relativePath (root path : FilePath) : IO String := do
  let root := root.normalize.toString
  let path := path.normalize.toString
  if path == root then
    return "."
  let pathPrefix := root ++ FilePath.pathSeparator.toString
  match path.dropPrefix? pathPrefix with
  | some suffix => return suffix.toString
  | none => failIO s!"path '{path}' is outside exported workspace '{root}'"

private def pathWithin (root : FilePath) (path : String) : FilePath :=
  root / FilePath.mk path

private def facetNames (facets : Array (Lake.ModuleFacet FilePath)) : Array String :=
  facets.map (fun facet => nameString facet.name)

private def effectiveBackend : Lake.Backend → String
  | .default | .c => "c"
  | .llvm => "llvm"

private def rejectUnsupportedLib (lib : Lake.LeanLib) : IO Unit := do
  let label := s!"lean_lib {nameString lib.name}"
  unless lib.config.needs.isEmpty do
    failIO s!"{label}: nonempty 'needs' is not supported by R0"
  unless lib.config.extraDepTargets.isEmpty do
    failIO s!"{label}: nonempty 'extraDepTargets' is not supported by R0"
  unless lib.dynlibs.isEmpty do
    failIO s!"{label}: dynamic library inputs are not supported by R0"
  unless lib.plugins.isEmpty do
    failIO s!"{label}: Lean plugin inputs are not supported by R0"
  unless lib.moreLinkObjs.isEmpty do
    failIO s!"{label}: custom link objects are not supported by R0"
  unless lib.moreLinkLibs.isEmpty do
    failIO s!"{label}: custom link libraries are not supported by R0"

private def rejectUnsupportedExe (exe : Lake.LeanExe) : IO Unit := do
  let label := s!"lean_exe {nameString exe.name}"
  unless exe.config.needs.isEmpty do
    failIO s!"{label}: nonempty 'needs' is not supported by R0"
  unless exe.config.extraDepTargets.isEmpty do
    failIO s!"{label}: nonempty 'extraDepTargets' is not supported by R0"
  unless exe.root.dynlibs.isEmpty do
    failIO s!"{label}: dynamic library inputs are not supported by R0"
  unless exe.root.plugins.isEmpty do
    failIO s!"{label}: Lean plugin inputs are not supported by R0"
  unless exe.moreLinkObjs.isEmpty do
    failIO s!"{label}: custom link objects are not supported by R0"
  unless exe.moreLinkLibs.isEmpty do
    failIO s!"{label}: custom link libraries are not supported by R0"

private def readHeader (mod : Lake.Module) : IO ModuleHeader := do
  let input ← IO.FS.readFile mod.leanFile
  Lean.parseImports' input mod.leanFile.toString

private partial def collectTransitiveImports
    (ws : Lake.Workspace) (root : Lake.Module) : IO (Array Lake.Module) := do
  let seen ← IO.mkRef ({} : Std.HashSet String)
  let modules ← IO.mkRef Lake.OrdModuleSet.empty
  let rec visit (mod : Lake.Module) : IO Unit := do
    let key := s!"{mod.pkg.dir}:{nameString mod.name}"
    unless (← seen.get).contains key do
      seen.modify (fun set => set.insert key)
      let header ← readHeader mod
      let imports := header.imports.foldl (init := Lake.OrdModuleSet.empty) fun result imp =>
        match ws.findModule? imp.module with
        | some imported => result.insert imported
        | none => result
      for imported in imports.toArray do
        visit imported
        modules.modify (fun result => result.insert imported)
  visit root
  return (← modules.get).toArray

private def executableLinkInputs
    (ws : Lake.Workspace) (exe : Lake.LeanExe) : IO (Array NativeLinkInputModel) := do
  let modules := #[exe.root] ++ (← collectTransitiveImports ws exe.root)
  let mut inputs : Array NativeLinkInputModel := #[]
  for mod in modules do
    let facets := facetNames (mod.nativeFacets exe.supportInterpreter)
    unless !facets.isEmpty && facets.all (#["module.o", "module.o.export"].contains ·) do
      failIO s!"lean_exe {nameString exe.name}: unsupported native facets for module {nameString mod.name}: {facets}"
    for facet in facets do
      inputs := inputs.push {
        package := canonicalPackageName mod.pkg
        module := nameString mod.name
        facet
      }
  return inputs

private partial def collectLibraryModules
    (ws : Lake.Workspace) (lib : Lake.LeanLib) : IO (Array Lake.Module) := do
  let seen ← IO.mkRef ({} : Std.HashSet String)
  let modules ← IO.mkRef (#[] : Array Lake.Module)
  let rec visit (mod : Lake.Module) : IO Unit := do
    let key := s!"{mod.pkg.dir}:{nameString mod.name}"
    unless (← seen.get).contains key do
      seen.modify (fun set => set.insert key)
      let header ← readHeader mod
      for imp in header.imports do
        if let some imported := ws.findModule? imp.module then
          if imported.pkg.dir == lib.pkg.dir && imported.lib.name == lib.name then
            visit imported
      modules.modify (fun values => values.push mod)
  for mod in (← lib.getModuleArray) do
    visit mod
  return (← modules.get).qsort (fun left right => nameString left.name < nameString right.name)

private def importModel (ws : Lake.Workspace) (imp : Import) : IO ImportModel := do
  let localPackage ←
    match (ws.findModules imp.module).toList with
    | [] => pure none
    | [mod] =>
      match canonicalPackageNameForKey ws mod.pkg.keyName with
      | some packageName => pure (some packageName)
      | none =>
        failIO s!"import '{nameString imp.module}' resolves to unknown workspace package \
          '{nameString mod.pkg.keyName}'"
    | _ =>
      failIO s!"import '{nameString imp.module}' has multiple workspace providers; \
        equivalent-provider disambiguation is not supported"
  return {
    module := nameString imp.module
    importAll := imp.importAll
    isExported := imp.isExported
    isMeta := imp.isMeta
    localPackage
  }

private def moduleModel
    (workspaceRoot : FilePath) (ws : Lake.Workspace) (owners : Array String)
    (mod : Lake.Module) : IO ModuleModel := do
  let header ← readHeader mod
  let imports ← header.imports.mapM (importModel ws)
  return {
    name := nameString mod.name
    source := ← relativePath workspaceRoot mod.leanFile
    owners
    header := {
      isModule := header.isModule
      imports
    }
    config := {
      buildType := mod.buildType.toString
      backend := effectiveBackend mod.backend
      leanOptions := toJson mod.leanOptions
      leanArgs := mod.leanArgs
      weakLeanArgs := mod.weakLeanArgs
      leancArgs := mod.leancArgs
      weakLeancArgs := mod.weakLeancArgs
      linkArgs := mod.linkArgs
      weakLinkArgs := mod.weakLinkArgs
      platformIndependent := mod.platformIndependent
      allowImportAll := mod.allowImportAll
      precompileModules := mod.lib.precompileModules
      nativeFacetsNoExport := facetNames (mod.nativeFacets false)
      nativeFacetsExport := facetNames (mod.nativeFacets true)
    }
  }

private def mergeModule (modules : Array ModuleModel) (newModule : ModuleModel) : IO (Array ModuleModel) := do
  match modules.findIdx? (fun mod => mod.name == newModule.name) with
  | none => return modules.push newModule
  | some index =>
      let existing := modules[index]!
      unless existing.source == newModule.source && toJson existing.config == toJson newModule.config do
        failIO s!"module '{newModule.name}' has incompatible effective configurations across owners"
      let owners := sortedStrings <| (existing.owners ++ newModule.owners).foldl
        (fun result owner => if result.contains owner then result else result.push owner) #[]
      return modules.set! index {existing with owners}

private def libraryModel
    (workspaceRoot : FilePath) (ws : Lake.Workspace) (lib : Lake.LeanLib)
    (modules : Array ModuleModel) : IO (LibraryModel × Array ModuleModel) := do
  rejectUnsupportedLib lib
  let libModules ← collectLibraryModules ws lib
  let owner := s!"lean_lib:{nameString lib.name}"
  let mut models := modules
  for mod in libModules do
    models ← mergeModule models (← moduleModel workspaceRoot ws #[owner] mod)
  return ({
    name := nameString lib.name
    srcDir := ← relativePath workspaceRoot lib.srcDir
    roots := lib.roots.map nameString
    moduleNames := libModules.map (fun mod => nameString mod.name)
    defaultFacets := lib.defaultFacets.map nameString
    nativeFacetsNoExport := facetNames (lib.nativeFacets false)
    nativeFacetsExport := facetNames (lib.nativeFacets true)
  }, models)

private def executableModel
    (workspaceRoot : FilePath) (ws : Lake.Workspace) (exe : Lake.LeanExe)
    (modules : Array ModuleModel) : IO (ExecutableModel × Array ModuleModel) := do
  rejectUnsupportedExe exe
  let root := exe.root
  let owner := s!"lean_exe:{nameString exe.name}"
  let models ← mergeModule modules (← moduleModel workspaceRoot ws #[owner] root)
  let orderedLinkInputs ← executableLinkInputs ws exe
  return ({
    name := nameString exe.name
    root := nameString root.name
    source := ← relativePath workspaceRoot root.leanFile
    outputName := exe.fileName.toString
    supportInterpreter := exe.supportInterpreter
    sharedLean := exe.sharedLean
    linkArgs := exe.linkArgs
    weakLinkArgs := exe.weakLinkArgs
    nativeFacetsNoExport := facetNames (root.nativeFacets false)
    nativeFacetsExport := facetNames (root.nativeFacets true)
    orderedLinkInputs
  }, models)

private def driverOption (driver : String) : Option String :=
  if driver.isEmpty then none else some driver

private structure PackageBuild where
  model : PackageModel
  authorityCatalogPath? : Option FilePath := none

private def moduleKey (mod : Lake.Module) : String :=
  s!"{mod.pkg.dir.normalize}:{nameString mod.name}"

private def pushUniqueModule
    (modules : Array Lake.Module) (mod : Lake.Module) : Array Lake.Module :=
  if modules.any (moduleKey · == moduleKey mod) then modules else modules.push mod

private def rootModules (ws : Lake.Workspace) : IO (Array Lake.Module) := do
  let mut modules : Array Lake.Module := #[]
  for lib in ws.root.leanLibs do
    for mod in (← collectLibraryModules ws lib) do
      modules := pushUniqueModule modules mod
  for exe in ws.root.leanExes do
    modules := pushUniqueModule modules exe.root
  return modules

private def dependencyImportClosure (ws : Lake.Workspace) : IO (Array Lake.Module) := do
  let mut modules : Array Lake.Module := #[]
  for root in (← rootModules ws) do
    for imported in (← collectTransitiveImports ws root) do
      if imported.pkg.keyName != ws.root.keyName then
        modules := pushUniqueModule modules imported
  return modules.qsort fun left right =>
    let leftPackage := canonicalPackageName left.pkg
    let rightPackage := canonicalPackageName right.pkg
    leftPackage < rightPackage ||
      (leftPackage == rightPackage && nameString left.name < nameString right.name)

private def dependencyPackageModel
    (workspaceRoot : FilePath) (ws : Lake.Workspace) (pkg : Lake.Package)
    (importClosure : Array Lake.Module) : IO PackageBuild := do
  -- Dependencies contribute exactly the module-level closure imported by root
  -- targets. Their unrelated package targets are not reinterpreted as Bazel
  -- build intent; selected modules still fail closed when their owning library
  -- requires unsupported target-level effects.
  let selected := importClosure.filter (fun mod => mod.pkg.keyName == pkg.keyName)
  let mut checkedLibraries : Array String := #[]
  let mut modules : Array ModuleModel := #[]
  for mod in selected do
    let libraryName := nameString mod.lib.name
    unless checkedLibraries.contains libraryName do
      rejectUnsupportedLib mod.lib
      checkedLibraries := checkedLibraries.push libraryName
    modules ← mergeModule modules (← moduleModel workspaceRoot ws #[] mod)
  return {
    model := {
      name := canonicalPackageName pkg
      packageId := pkg.id?
      directory := ← relativePath workspaceRoot pkg.dir
      configFile := ← relativePath workspaceRoot pkg.configFile
      defaultTargets := pkg.defaultTargets.map nameString
      testDriver := driverOption pkg.testDriver
      testDriverArgs := pkg.testDriverArgs
      lintDriver := driverOption pkg.lintDriver
      lintDriverArgs := pkg.lintDriverArgs
      targets := #[]
      inputFiles := #[]
      inputDirs := #[]
      libraries := #[]
      executables := #[]
      modules := modules.qsort (fun left right => left.name < right.name)
    }
  }

private def packageModel
    (workspaceRoot : FilePath) (ws : Lake.Workspace) (pkg : Lake.Package) : IO PackageBuild := do
  let mut targets : Array TargetModel := #[]
  let mut inputFiles : Array InputFileModel := #[]
  let mut inputDirs : Array InputDirModel := #[]
  let mut authorityCatalogPath? : Option FilePath := none
  for decl in pkg.targetDecls do
    let kind := decl.kind
    let kindName := nameString kind
    if kind == Lake.LeanLib.configKind then
      targets := targets.push {name := nameString decl.name, kind := "lean_lib"}
    else if kind == Lake.LeanExe.configKind then
      targets := targets.push {name := nameString decl.name, kind := "lean_exe"}
    else if kind == Lake.InputFile.configKind then
      let some config := decl.config? Lake.InputFile.configKind
        | failIO s!"input_file {nameString decl.name}: configuration cast failed"
      let target : Lake.InputFile := .mk pkg decl.name config
      let path ← relativePath workspaceRoot target.path
      targets := targets.push {name := nameString decl.name, kind := "input_file"}
      inputFiles := inputFiles.push {name := nameString decl.name, path, text := target.text}
      if decl.name == `authorityCatalog then
        if authorityCatalogPath?.isSome then
          failIO "multiple input_file targets named 'authorityCatalog'"
        authorityCatalogPath? := some target.path
    else if kind == Lake.InputDir.configKind then
      let some config := decl.config? Lake.InputDir.configKind
        | failIO s!"input_dir {nameString decl.name}: configuration cast failed"
      let target : Lake.InputDir := .mk pkg decl.name config
      match target.config.filter.descr? with
      | some (.all patterns) =>
          unless patterns.isEmpty do
            failIO s!"input_dir {nameString decl.name}: only the declarative star filter is supported by R0"
      | _ =>
          failIO s!"input_dir {nameString decl.name}: only the declarative star filter is supported by R0"
      targets := targets.push {name := nameString decl.name, kind := "input_dir"}
      inputDirs := inputDirs.push {
        name := nameString decl.name
        path := ← relativePath workspaceRoot target.path
        text := target.text
        filter := "star"
      }
    else
      failIO s!"package {nameString pkg.keyName}: unsupported Lake target kind '{kindName}' for '{nameString decl.name}'"

  let mut modules : Array ModuleModel := #[]
  let mut libraries : Array LibraryModel := #[]
  for lib in pkg.leanLibs do
    let (model, nextModules) ← libraryModel workspaceRoot ws lib modules
    libraries := libraries.push model
    modules := nextModules

  let mut executables : Array ExecutableModel := #[]
  for exe in pkg.leanExes do
    let (model, nextModules) ← executableModel workspaceRoot ws exe modules
    executables := executables.push model
    modules := nextModules

  return {
    model := {
      name := canonicalPackageName pkg
      packageId := pkg.id?
      directory := ← relativePath workspaceRoot pkg.dir
      configFile := ← relativePath workspaceRoot pkg.configFile
      defaultTargets := pkg.defaultTargets.map nameString
      testDriver := driverOption pkg.testDriver
      testDriverArgs := pkg.testDriverArgs
      lintDriver := driverOption pkg.lintDriver
      lintDriverArgs := pkg.lintDriverArgs
      targets := targets.qsort (fun left right => left.name < right.name)
      inputFiles := inputFiles.qsort (fun left right => left.name < right.name)
      inputDirs := inputDirs.qsort (fun left right => left.name < right.name)
      libraries := libraries.qsort (fun left right => left.name < right.name)
      executables := executables.qsort (fun left right => left.name < right.name)
      modules := modules.qsort (fun left right => left.name < right.name)
    }
    authorityCatalogPath?
  }

private def readAuthorityCatalog (path : FilePath) : IO AuthorityCatalog := do
  let raw ← IO.FS.readFile path
  let parsed := do
    let json ← Json.parse raw
    parseAuthorityCatalog json
  match parsed with
  | .ok catalog => pure catalog
  | .error error => failIO s!"invalid authority catalog '{path}': {error}"

private def ensureCatalogPathExists (workspaceRoot : FilePath) (context path : String) : IO Unit := do
  unless (← (pathWithin workspaceRoot path).pathExists) do
    failIO s!"{context}: path '{path}' does not exist"

private def validateAuthorityCatalog
    (workspaceRoot : FilePath) (packages : Array PackageModel)
    (catalog : AuthorityCatalog) : IO Unit := do
  let executableNames := packages.flatMap (fun pkg => pkg.executables.map (fun exe => exe.name))
  let moduleNames := packages.flatMap (fun pkg => pkg.modules.map (fun mod => mod.name))
  let targetNames := packages.flatMap (fun pkg => pkg.targets.map (fun target => target.name))
  for resource in catalog.resources do
    ensureCatalogPathExists workspaceRoot s!"authority resource {resource.name}" resource.path
  for tool in catalog.tools do
    match tool.kind, tool.target with
    | .leanExe, some target =>
        unless executableNames.contains target do
          failIO s!"authority tool {tool.name}: unknown lean_exe target '{target}'"
    | _, _ => pure ()
  for generator in catalog.generators do
    for input in generator.inputs do
      ensureCatalogPathExists workspaceRoot s!"authority generator {generator.name} input" input
    for output in generator.outputs do
      ensureCatalogPathExists workspaceRoot s!"authority generator {generator.name} checked-in output" output
  for check in catalog.checks do
    for input in check.inputs do
      ensureCatalogPathExists workspaceRoot s!"authority check {check.name} input" input
    for dep in check.deps do
      unless targetNames.contains dep || moduleNames.contains dep do
        failIO s!"authority check {check.name}: unknown dependency '{dep}'"
    if check.kind == .leanProbe && !moduleNames.contains check.root then
      failIO s!"authority check {check.name}: unknown Lean probe root '{check.root}'"

private def tokenizeToolchainValue (lean : Lake.LeanInstall) (value : String) : String :=
  let sysroot := lean.sysroot.normalize.toString
  value.replace sysroot "$sysroot"

private def tokenizeToolchainPath (lean : Lake.LeanInstall) (path : FilePath) : String :=
  tokenizeToolchainValue lean path.normalize.toString

private def stablePlatformIdentity (target : String) : IO String := do
  if target.startsWith "arm64-apple-darwin" || target.startsWith "aarch64-apple-darwin" then
    pure "aarch64-darwin"
  else if target == "x86_64-unknown-linux-gnu" then
    pure "x86_64-linux"
  else
    failIO s!"unsupported R1 execution platform '{target}'"

private def toolchainModel (lean : Lake.LeanInstall) : IO ToolchainModel := do
  let targetTriple := Platform.target
  let platformName ← stablePlatformIdentity targetTriple
  return {
    target := targetTriple
    platform := platformName
    githash := lean.githash
    distributionIdentity := s!"lean-githash:{lean.githash}"
    sysroot := tokenizeToolchainPath lean lean.sysroot
    lean := tokenizeToolchainPath lean lean.lean
    leanir := tokenizeToolchainPath lean lean.leanir
    leanc := tokenizeToolchainPath lean lean.leanc
    cc := tokenizeToolchainPath lean lean.cc
    ar := tokenizeToolchainPath lean lean.ar
    includeDir := tokenizeToolchainPath lean lean.includeDir
    leanLibDir := tokenizeToolchainPath lean lean.leanLibDir
    systemLibDir := tokenizeToolchainPath lean lean.systemLibDir
    ccFlags := lean.ccFlags.map (tokenizeToolchainValue lean)
    ccLinkStaticFlags := lean.ccLinkStaticFlags.map (tokenizeToolchainValue lean)
    ccLinkSharedFlags := lean.ccLinkSharedFlags.map (tokenizeToolchainValue lean) }

private def validateWorkspaceToolchain (workspaceRoot : FilePath) : IO Unit := do
  let some declared ← Lake.ToolchainVer.ofDir? workspaceRoot
    | failIO s!"workspace '{workspaceRoot}' has no lean-toolchain declaration"
  let expected :=
    Lake.ToolchainVer.ofString s!"leanprover/lean4:v{Lean.versionString}"
  if declared.toString != expected.toString then
    failIO s!"workspace lean-toolchain '{declared}' does not match selected SDK '{expected}'"

private def stagedPackageOverrides
    (workspaceRoot : FilePath) : IO (Array Lake.PackageEntry) := do
  let some manifest ← Lake.Manifest.load? (workspaceRoot / Lake.defaultManifestFile)
    | failIO s!"staged package mode requires '{Lake.defaultManifestFile}'"
  let packagesDir := manifest.packagesDir?.getD Lake.defaultPackagesDir
  manifest.packages.mapM fun entry => do
    match entry.src with
    | .path .. => pure entry
    | .git (subDir? := subDir?) .. =>
      let repositoryDir := packagesDir / entry.prettyName
      let packageDir := subDir?.map (repositoryDir / ·) |>.getD repositoryDir
      unless (← (workspaceRoot / packageDir).isDir) do
        failIO s!"staged Git package '{entry.prettyName}' is missing declared source directory \
          '{packageDir}'"
      pure {entry with src := .path packageDir}

private def loadWorkspace
    (workspaceRoot : FilePath) (leanSysroot? : Option FilePath)
    (useStagedPackages : Bool) :
    IO (Lake.Workspace × Lake.LeanInstall) := do
  let (elan?, lean, lake) ← match leanSysroot? with
    | some sysroot =>
      let sysroot ← IO.FS.realPath sysroot
      let lean ← Lake.LeanInstall.get sysroot (collocated := true)
      pure (none, lean, Lake.LakeInstall.ofLean lean)
    | none =>
      let (elan?, lean?, lake?) ← Lake.findInstall?
      let some lean := lean? | failIO "unable to locate Lean installation"
      pure (elan?, lean, lake?.getD (Lake.LakeInstall.ofLean lean))
  validateWorkspaceToolchain workspaceRoot
  let env ← (Lake.Env.compute lake lean elan?).toIO (fun error => ioError error)
  let packageOverrides ←
    if useStagedPackages then stagedPackageOverrides workspaceRoot else pure #[]
  let some workspace ← (Lake.loadWorkspace {
      lakeEnv := env
      wsDir := workspaceRoot
      packageOverrides
      updateToolchain := false
    }).toBaseIO
    | failIO s!"failed to load Lake workspace at '{workspaceRoot}'"
  pure (workspace, lean)

def exportWorkspace
    (workspaceRoot : FilePath) (leanSysroot? : Option FilePath := none)
    (useStagedPackages : Bool := false) : IO ExportModel := do
  let workspaceRoot ← IO.FS.realPath workspaceRoot
  let (ws, lean) ← loadWorkspace workspaceRoot leanSysroot? useStagedPackages
  let dependencyModules ← dependencyImportClosure ws
  let mut packages : Array PackageModel := #[]
  let mut catalogPath? : Option FilePath := none
  for pkg in ws.packages do
    let built ←
      if pkg.keyName == ws.root.keyName then
        packageModel workspaceRoot ws pkg
      else
        dependencyPackageModel workspaceRoot ws pkg dependencyModules
    packages := packages.push built.model
    if let some path := built.authorityCatalogPath? then
      if pkg.keyName != ws.root.keyName then
        failIO "authorityCatalog input_file must be declared by the root package"
      if catalogPath?.isSome then
        failIO "multiple authorityCatalog input_file declarations"
      catalogPath? := some path
  let sortedPackages := packages.qsort (fun left right => left.name < right.name)
  let catalog ← match catalogPath? with
    | some path => readAuthorityCatalog path
    | none => pure {schemaVersion := authoritySchemaVersion}
  validateAuthorityCatalog workspaceRoot sortedPackages catalog
  pure {
    schemaVersion := exportSchemaVersion
    workspace := {rootPackage := canonicalPackageName ws.root, packages := sortedPackages}
    toolchain := ← toolchainModel lean
    authorityCatalog := catalog
  }

private structure Cli where
  workspace : FilePath := "."
  leanSysroot? : Option FilePath := none
  useStagedPackages : Bool := false
  output? : Option FilePath := none

private def parseCli (args : List String) : Except String Cli := do
  let rec go (args : List String) (cli : Cli) : Except String Cli := do
    match args with
    | [] => pure cli
    | "--workspace" :: path :: rest => go rest {cli with workspace := FilePath.mk path}
    | "--workspace" :: [] => throw "--workspace requires a directory"
    | "--lean-sysroot" :: path :: rest =>
        if cli.leanSysroot?.isSome then
          throw "--lean-sysroot may be specified at most once"
        go rest {cli with leanSysroot? := some (FilePath.mk path)}
    | "--lean-sysroot" :: [] => throw "--lean-sysroot requires a directory"
    | "--use-staged-packages" :: rest =>
        if cli.useStagedPackages then
          throw "--use-staged-packages may be specified at most once"
        go rest {cli with useStagedPackages := true}
    | arg :: rest =>
        if arg.startsWith "-" then
          throw s!"unknown option '{arg}'"
        if cli.output?.isSome then
          throw "expected at most one output path"
        go rest {cli with output? := some (FilePath.mk arg)}
  go args {}

private def absoluteFrom (cwd path : FilePath) : FilePath :=
  if path.isAbsolute then path else cwd / path

def run (args : List String) : IO Unit := do
  let cli ← match parseCli args with
    | .ok cli => pure cli
    | .error error =>
      failIO s!"{error}\nusage: export-lake [--workspace DIR] [--lean-sysroot DIR] \
        [--use-staged-packages] [OUTPUT]"
  let cwd ← IO.currentDir
  let workspace := absoluteFrom cwd cli.workspace
  let leanSysroot? := cli.leanSysroot?.map (absoluteFrom cwd)
  let output? := cli.output?.map (absoluteFrom cwd)
  let oldDir ← IO.Process.getCurrentDir
  let model ← try
    IO.Process.setCurrentDir workspace
    exportWorkspace workspace leanSysroot? cli.useStagedPackages
  finally
    IO.Process.setCurrentDir oldDir
  let json := toJson model
  match parseExportModel json with
  | .error error => failIO s!"internal export model validation failed: {error}"
  | .ok _ => pure ()
  let rendered := json.pretty ++ "\n"
  match output? with
  | none => IO.print rendered
  | some output => IO.FS.writeFile output rendered

end LeanBazel

public def main (args : List String) : IO UInt32 := do
  try
    LeanBazel.run args
    pure 0
  catch error =>
    IO.eprintln s!"export-lake: {error}"
    pure 1
