module

import tools.LakeModel

open Lean

namespace LeanBazel

private def failAt (context message : String) : Except String α :=
  throw s!"{context}: {message}"

private def ensureUnique (context : String) (names : Array String) : Except String Unit := do
  let mut seen : Std.HashSet String := {}
  for name in names do
    if name.isEmpty then
      failAt context "names must be nonempty"
    if seen.contains name then
      failAt context s!"duplicate name '{name}'"
    seen := seen.insert name

private def isRelativePath (path : String) : Bool :=
  !path.isEmpty && !path.startsWith "/" && !(path.splitOn "/").contains ".."

private def validateRelativePath (context path : String) : Except String Unit := do
  unless isRelativePath path do
    failAt context s!"expected repository-relative path, got '{path}'"

private def findPackage? (model : ExportModel) (name : String) : Option PackageModel :=
  model.workspace.packages.find? (fun pkg => pkg.name == name)

private def findTarget? (pkg : PackageModel) (name : String) : Option TargetModel :=
  pkg.targets.find? (fun target => target.name == name)

private def findModule? (pkg : PackageModel) (name : String) : Option ModuleModel :=
  pkg.modules.find? (fun mod => mod.name == name)

private def findModuleAcrossPackages
    (model : ExportModel) (name : String) : Except String (String × ModuleModel) := do
  let foundModules := model.workspace.packages.foldl (init := #[]) fun found pkg =>
    match findModule? pkg name with
    | some mod => found.push (pkg.name, mod)
    | none => found
  if h : foundModules.size = 1 then
    pure foundModules[0]
  else if foundModules.isEmpty then
    failAt "module reference" s!"unknown module '{name}'"
  else
    failAt "module reference" s!"ambiguous module '{name}'"

private def requireTargetKind
    (pkg : PackageModel) (name expected : String) : Except String Unit := do
  let some target := findTarget? pkg name
    | failAt s!"package {pkg.name}" s!"missing target '{name}'"
  unless target.kind == expected do
    failAt s!"package {pkg.name}.target {name}"
      s!"expected kind '{expected}', got '{target.kind}'"

private def validateModel (model : ExportModel) : Except String Unit := do
  ensureUnique "workspace.packages" (model.workspace.packages.map (·.name))
  let some rootPackage := findPackage? model model.workspace.rootPackage
    | failAt "workspace.rootPackage" s!"unknown package '{model.workspace.rootPackage}'"

  for pkg in model.workspace.packages do
    validateRelativePath s!"package {pkg.name}.directory" pkg.directory
    validateRelativePath s!"package {pkg.name}.configFile" pkg.configFile
    ensureUnique s!"package {pkg.name}.targets" (pkg.targets.map (·.name))
    ensureUnique s!"package {pkg.name}.inputFiles" (pkg.inputFiles.map (·.name))
    ensureUnique s!"package {pkg.name}.inputDirs" (pkg.inputDirs.map (·.name))
    ensureUnique s!"package {pkg.name}.libraries" (pkg.libraries.map (·.name))
    ensureUnique s!"package {pkg.name}.executables" (pkg.executables.map (·.name))
    ensureUnique s!"package {pkg.name}.modules" (pkg.modules.map (·.name))

    for exe in pkg.executables do
      let context := s!"package {pkg.name}.executable {exe.name}.orderedLinkInputs"
      let some first := exe.orderedLinkInputs[0]?
        | failAt context "link plan must be nonempty"
      unless first.package == pkg.name && first.module == exe.root do
        failAt context s!"first link input must be executable root '{pkg.name}/{exe.root}'"
      ensureUnique context (exe.orderedLinkInputs.map fun input =>
        s!"{input.package}/{input.module}")
      let expectedFacet := if exe.supportInterpreter then "module.o.export" else "module.o"
      for input in exe.orderedLinkInputs do
        let some inputPackage := findPackage? model input.package
          | failAt context s!"unknown package '{input.package}'"
        let some inputModule := findModule? inputPackage input.module
          | failAt context s!"unknown module '{input.package}/{input.module}'"
        unless input.facet == expectedFacet do
          failAt context <| s!"supportInterpreter={exe.supportInterpreter} requires facet " ++
            s!"'{expectedFacet}', got '{input.facet}' for '{input.package}/{input.module}'"
        let selectedFacets := if exe.supportInterpreter then
          inputModule.config.nativeFacetsExport
        else
          inputModule.config.nativeFacetsNoExport
        unless selectedFacets == #[input.facet] do
          failAt context <| s!"module '{input.package}/{input.module}' does not declare exactly " ++
            s!"the selected facet '{input.facet}'"

    for target in pkg.targets do
      unless #["lean_lib", "lean_exe", "input_file", "input_dir"].contains target.kind do
        failAt s!"package {pkg.name}.target {target.name}"
          s!"unsupported target kind '{target.kind}'"
    for input in pkg.inputFiles do
      requireTargetKind pkg input.name "input_file"
      validateRelativePath s!"package {pkg.name}.inputFile {input.name}" input.path
    for input in pkg.inputDirs do
      requireTargetKind pkg input.name "input_dir"
      validateRelativePath s!"package {pkg.name}.inputDir {input.name}" input.path
      unless input.filter == "star" do
        failAt s!"package {pkg.name}.inputDir {input.name}"
          s!"unsupported input directory filter '{input.filter}'"
    for lib in pkg.libraries do
      requireTargetKind pkg lib.name "lean_lib"
      for moduleName in lib.moduleNames do
        unless (findModule? pkg moduleName).isSome do
          failAt s!"package {pkg.name}.library {lib.name}"
            s!"unknown module '{moduleName}'"
    for exe in pkg.executables do
      requireTargetKind pkg exe.name "lean_exe"
      let some root := findModule? pkg exe.root
        | failAt s!"package {pkg.name}.executable {exe.name}"
            s!"unknown root module '{exe.root}'"
      unless root.source == exe.source do
        failAt s!"package {pkg.name}.executable {exe.name}"
          s!"root source '{root.source}' disagrees with executable source '{exe.source}'"
      if exe.orderedLinkInputs.isEmpty then
        failAt s!"package {pkg.name}.executable {exe.name}" "ordered link plan is empty"
      let first := exe.orderedLinkInputs[0]!
      unless first.package == pkg.name && first.module == exe.root do
        failAt s!"package {pkg.name}.executable {exe.name}"
          "ordered link plan does not begin with the executable root"
      for input in exe.orderedLinkInputs do
        let some inputPackage := findPackage? model input.package
          | failAt s!"package {pkg.name}.executable {exe.name}.orderedLinkInputs"
              s!"unknown package '{input.package}'"
        unless (findModule? inputPackage input.module).isSome do
          failAt s!"package {pkg.name}.executable {exe.name}.orderedLinkInputs"
            s!"unknown module '{input.package}/{input.module}'"
        unless #["module.o", "module.o.export"].contains input.facet do
          failAt s!"package {pkg.name}.executable {exe.name}.orderedLinkInputs"
            s!"unsupported facet '{input.facet}'"
    for mod in pkg.modules do
      validateRelativePath s!"package {pkg.name}.module {mod.name}.source" mod.source
      for owner in mod.owners do
        let context := s!"package {pkg.name}.module {mod.name}.owners"
        match owner.splitOn ":" with
        | [kind, name] =>
            if kind.isEmpty || name.isEmpty then
              failAt context s!"malformed typed target identity '{owner}'"
            unless kind == "lean_lib" || kind == "lean_exe" do
              failAt context s!"unsupported owner target kind '{kind}'"
            requireTargetKind pkg name kind
        | _ =>
            failAt context s!"malformed typed target identity '{owner}'"
      for imp in mod.header.imports do
        if let some localPackage := imp.localPackage then
          let some importedPackage := findPackage? model localPackage
            | failAt s!"package {pkg.name}.module {mod.name}.imports"
                s!"unknown local package '{localPackage}'"
          unless (findModule? importedPackage imp.module).isSome do
            failAt s!"package {pkg.name}.module {mod.name}.imports"
              s!"unknown local module '{localPackage}/{imp.module}'"

  for defaultTarget in rootPackage.defaultTargets do
    unless (findTarget? rootPackage defaultTarget).isSome do
      failAt "workspace.rootPackage.defaultTargets" s!"unknown target '{defaultTarget}'"
  for driver in #[rootPackage.testDriver, rootPackage.lintDriver] do
    if let some name := driver then
      unless (findTarget? rootPackage name).isSome do
        failAt "workspace.rootPackage.driver" s!"unknown target '{name}'"

  let catalog := model.authorityCatalog
  for tool in catalog.tools do
    if tool.kind == .leanExe then
      let some target := tool.target
        | failAt s!"authorityCatalog.tools.{tool.name}" "lean_exe tool has no target"
      requireTargetKind rootPackage target "lean_exe"
  for generator in catalog.generators do
    unless catalog.tools.any (fun tool => tool.name == generator.tool) do
      failAt s!"authorityCatalog.generators.{generator.name}"
        s!"unknown tool '{generator.tool}'"
  for check in catalog.checks do
    for dep in check.deps do
      unless (findTarget? rootPackage dep).isSome do
        failAt s!"authorityCatalog.checks.{check.name}.deps" s!"unknown target '{dep}'"
    match check.kind with
    | .leanExe => requireTargetKind rootPackage check.root "lean_exe"
    | .leanProbe => discard <| findModuleAcrossPackages model check.root
    | .process =>
        unless catalog.tools.any (fun tool => tool.name == check.root) ||
            (findTarget? rootPackage check.root).isSome do
          failAt s!"authorityCatalog.checks.{check.name}.root"
            s!"unknown process tool or target '{check.root}'"

private def quote (value : String) : String :=
  (Json.str value).compress

private def boolText (value : Bool) : String :=
  if value then "true" else "false"

private def starlarkBoolText (value : Bool) : String :=
  if value then "True" else "False"

private def sortedUnique (values : Array String) : Array String :=
  (values.qsort (· < ·)).foldl (init := #[]) fun result value =>
    if result.contains value then result else result.push value

private def sortedBuildifierSrcs (values : Array String) : Array String :=
  let sorted := values.qsort fun left right =>
    let leftIsLabel := left.startsWith ":"
    let rightIsLabel := right.startsWith ":"
    if leftIsLabel == rightIsLabel then left < right else !leftIsLabel
  sorted.foldl (init := #[]) fun result value =>
    if result.contains value then result else result.push value

private def encodeName (value : String) : String :=
  let value := value.replace "_" "_u_"
  let value := value.replace "." "_d_"
  let value := value.replace "-" "_h_"
  let value := value.replace "/" "_s_"
  let value := value.replace ":" "_c_"
  let value := value.replace "@" "_a_"
  value.replace "+" "_p_"

private def moduleRuleName (packageName moduleName : String) : String :=
  s!"module__{encodeName packageName}__{encodeName moduleName}"

private def targetRuleName (packageName targetName : String) : String :=
  s!"target__{encodeName packageName}__{encodeName targetName}"

private def packageRuleName (packageName : String) : String :=
  s!"package__{encodeName packageName}"

private def resourceRuleName (name : String) : String :=
  s!"resource__{encodeName name}"

private def toolRuleName (name : String) : String :=
  s!"tool__{encodeName name}"

private def generatorRuleName (name : String) : String :=
  s!"generator__{encodeName name}"

private def checkRuleName (name : String) : String :=
  s!"check__{encodeName name}"

private def label (name : String) : String := ":" ++ name

private def projectionFreshnessLabel : String :=
  ":lake_authority_projection_freshness"

private def renderStringArray (values : Array String) : String :=
  if values.isEmpty then
    "[]"
  else
    let lines := values.map fun value => "        " ++ quote value ++ ","
    "[\n" ++ String.intercalate "\n" lines.toList ++ "\n    ]"

private def renderStringDict (values : Array (String × String)) : String :=
  if values.isEmpty then
    "{}"
  else
    let lines := values.map fun (key, value) =>
      "        " ++ quote key ++ ": " ++ quote value ++ ","
    "{\n" ++ String.intercalate "\n" lines.toList ++ "\n    }"

private def renderFilegroup (name : String) (srcs tags : Array String) : String :=
  "filegroup(\n" ++
  "    name = " ++ quote name ++ ",\n" ++
  "    srcs = " ++ renderStringArray (sortedBuildifierSrcs srcs) ++ ",\n" ++
  "    tags = " ++ renderStringArray (sortedUnique tags) ++ ",\n" ++
  ")\n"

private def renderProjectionInputs : String :=
  "filegroup(\n" ++
  "    name = \"lake_authority_projection_inputs\",\n" ++
  "    srcs = glob(\n" ++
  "        [\n" ++
  "            \"**/*.lean\",\n" ++
  "            \"lakefile.toml\",\n" ++
  "            \"lean-toolchain\",\n" ++
  "            \"lake-manifest.json\",\n" ++
  "        ],\n" ++
  "        allow_empty = True,\n" ++
  "        exclude = [\n" ++
  "            \".lake/**\",\n" ++
  "            \"bazel-*/**\",\n" ++
  "        ],\n" ++
  "    ),\n" ++
  ")\n"

private def renderProjectionFreshness : String :=
  "lean_projection_freshness(\n" ++
  "    name = \"lake_authority_projection_freshness\",\n" ++
  "    committed_lock = \"lean/x86_64-linux/projection-lock.json\",\n" ++
  "    committed_manifest = \"lean/x86_64-linux/lake-authority.json\",\n" ++
  "    committed_projection = \"BUILD.bazel\",\n" ++
  "    workspace_inputs = [\":lake_authority_projection_inputs\"],\n" ++
  ")\n"

private def renderLeanModule
    (name src moduleName backend leanOptions packageName : String)
    (packageId : Option String)
    (directImportsJson : String)
    (deps sdkImports extraInputs leanArgs weakLeanArgs leancArgs weakLeancArgs tags : Array String)
    (isModule precompileModules : Bool) : String :=
  "lean_module(\n" ++
  "    name = " ++ quote name ++ ",\n" ++
  "    package_name = " ++ quote packageName ++ ",\n" ++
  "    src = " ++ quote src ++ ",\n" ++
  "    backend = " ++ quote backend ++ ",\n" ++
  "    direct_imports_json = " ++ quote directImportsJson ++ ",\n" ++
  "    extra_inputs = " ++ renderStringArray (sortedBuildifierSrcs extraInputs) ++ ",\n" ++
  "    freshness = " ++ quote projectionFreshnessLabel ++ ",\n" ++
  "    is_module = " ++ starlarkBoolText isModule ++ ",\n" ++
  "    lean_args = " ++ renderStringArray leanArgs ++ ",\n" ++
  "    lean_options = " ++ quote leanOptions ++ ",\n" ++
  "    leanc_args = " ++ renderStringArray leancArgs ++ ",\n" ++
  "    module = " ++ quote moduleName ++ ",\n" ++
  (match packageId with
   | some packageId => "    package_id = " ++ quote packageId ++ ",\n"
   | none => "") ++
  "    precompile_modules = " ++ starlarkBoolText precompileModules ++ ",\n" ++
  "    sdk_imports = " ++ renderStringArray (sortedUnique sdkImports) ++ ",\n" ++
  "    tags = " ++ renderStringArray (sortedUnique tags) ++ ",\n" ++
  "    weak_lean_args = " ++ renderStringArray weakLeanArgs ++ ",\n" ++
  "    weak_leanc_args = " ++ renderStringArray weakLeancArgs ++ ",\n" ++
  "    deps = " ++ renderStringArray (sortedBuildifierSrcs (sortedUnique deps)) ++ ",\n" ++
  ")\n"

private def renderLeanBinary
    (name rootModule outputName : String)
    (data linkModules linkFacets weakLinkArgs linkArgs tags : Array String)
    (supportInterpreter sharedLean : Bool) : String :=
  "lean_binary(\n" ++
  "    name = " ++ quote name ++ ",\n" ++
  "    data = " ++ renderStringArray (sortedBuildifierSrcs data) ++ ",\n" ++
  "    freshness = " ++ quote projectionFreshnessLabel ++ ",\n" ++
  "    link_args = " ++ renderStringArray linkArgs ++ ",\n" ++
  "    link_facets = " ++ renderStringArray linkFacets ++ ",\n" ++
  "    link_modules = " ++ renderStringArray linkModules ++ ",\n" ++
  "    output_name = " ++ quote outputName ++ ",\n" ++
  "    root_module = " ++ quote rootModule ++ ",\n" ++
  "    shared_lean = " ++ starlarkBoolText sharedLean ++ ",\n" ++
  "    support_interpreter = " ++ starlarkBoolText supportInterpreter ++ ",\n" ++
  "    tags = " ++ renderStringArray (sortedUnique tags) ++ ",\n" ++
  "    weak_link_args = " ++ renderStringArray weakLinkArgs ++ ",\n" ++
  ")\n"

private def renderLeanCheck
    (name kind root cwd : String)
    (args : Array String) (env : EnvMap)
    (inputs resources deps tags : Array String)
    (expected : AuthorityExpected) : String :=
  "lean_check(\n" ++
  "    name = " ++ quote name ++ ",\n" ++
  "    args = " ++ renderStringArray args ++ ",\n" ++
  "    cwd = " ++ quote cwd ++ ",\n" ++
  "    env = " ++ renderStringDict env.entries ++ ",\n" ++
  "    expect_stderr = " ++ starlarkBoolText expected.stderr.isSome ++ ",\n" ++
  "    expect_stdout = " ++ starlarkBoolText expected.stdout.isSome ++ ",\n" ++
  "    expected_exit = " ++ toString expected.exit ++ ",\n" ++
  "    expected_stderr = " ++ quote (expected.stderr.getD "") ++ ",\n" ++
  "    expected_stdout = " ++ quote (expected.stdout.getD "") ++ ",\n" ++
  "    freshness = " ++ quote projectionFreshnessLabel ++ ",\n" ++
  "    inputs = " ++ renderStringArray (sortedBuildifierSrcs inputs) ++ ",\n" ++
  "    kind = " ++ quote kind ++ ",\n" ++
  "    resources = " ++ renderStringArray (sortedBuildifierSrcs resources) ++ ",\n" ++
  "    root = " ++ quote root ++ ",\n" ++
  "    tags = " ++ renderStringArray (sortedUnique tags) ++ ",\n" ++
  "    deps = " ++ renderStringArray (sortedBuildifierSrcs deps) ++ ",\n" ++
  ")\n"

private def valueTags (tagPrefix : String) (values : Array String) : Array String :=
  values.map fun value => tagPrefix ++ value

private def envTags (tagPrefix : String) (env : EnvMap) : Array String :=
  env.entries.map fun (key, value) => s!"{tagPrefix}{key}={value}"

private def optionTag (tagPrefix : String) : Option String -> Array String
  | some value => #[tagPrefix ++ value]
  | none => #[]

private def generatedByLabels (model : ExportModel) (path : String) : Array String :=
  model.authorityCatalog.generators.foldl (init := #[]) fun labels generator =>
    if generator.outputs.contains path then
      labels.push <| label (generatorRuleName generator.name)
    else
      labels

private def moduleResourceLabels (model : ExportModel) (mod : ModuleModel) : Array String :=
  model.authorityCatalog.checks.foldl (init := #[]) fun labels check =>
    if check.kind == .leanProbe && check.root == mod.name then
      labels ++ check.resources.map fun resource => label (resourceRuleName resource)
    else
      labels

private def renderModuleRule
    (model : ExportModel) (pkg : PackageModel) (mod : ModuleModel) : String :=
  let importLabels := mod.header.imports.foldl (init := #[]) fun labels imp =>
    match imp.localPackage with
    | some localPackage => labels.push <| label (moduleRuleName localPackage imp.module)
    | none => labels
  let sdkImports := mod.header.imports.foldl (init := #[]) fun modules imp =>
    match imp.localPackage with
    | some _ => modules
    | none => modules.push imp.module
  let importTags := mod.header.imports.map fun imp =>
    let localPackage := imp.localPackage.getD "external"
    s!"lake-import={localPackage}/{imp.module};all={boolText imp.importAll};" ++
      s!"exported={boolText imp.isExported};meta={boolText imp.isMeta}"
  let config := mod.config
  let tags :=
    #["lake-kind=lean_module", s!"lake-package={pkg.name}", s!"lake-module={mod.name}",
      s!"lake-is-module={boolText mod.header.isModule}", s!"lake-build-type={config.buildType}",
      s!"lake-backend={config.backend}", s!"lake-lean-options={config.leanOptions.compress}",
      s!"lake-allow-import-all={boolText config.allowImportAll}",
      s!"lake-precompile-modules={boolText config.precompileModules}"] ++
    optionTag "lake-platform-independent=" (config.platformIndependent.map boolText) ++
    valueTags "lake-owner=" mod.owners ++ importTags ++
    valueTags "lake-lean-arg=" config.leanArgs ++
    valueTags "lake-weak-lean-arg=" config.weakLeanArgs ++
    valueTags "lake-leanc-arg=" config.leancArgs ++
    valueTags "lake-weak-leanc-arg=" config.weakLeancArgs ++
    valueTags "lake-link-arg=" config.linkArgs ++
    valueTags "lake-weak-link-arg=" config.weakLinkArgs ++
    valueTags "lake-native-no-export=" config.nativeFacetsNoExport ++
    valueTags "lake-native-export=" config.nativeFacetsExport
  renderLeanModule
    (moduleRuleName pkg.name mod.name)
    mod.source
    mod.name
    config.backend
    config.leanOptions.compress
    pkg.name
    pkg.packageId
    (toJson mod.header.imports).compress
    importLabels
    sdkImports
    (generatedByLabels model mod.source ++ moduleResourceLabels model mod)
    config.leanArgs
    config.weakLeanArgs
    config.leancArgs
    config.weakLeancArgs
    tags
    mod.header.isModule
    config.precompileModules

private def renderLibraryRule (pkg : PackageModel) (lib : LibraryModel) : String :=
  let srcs := lib.moduleNames.map fun moduleName => label (moduleRuleName pkg.name moduleName)
  let tags := #["lake-kind=lean_lib", s!"lake-package={pkg.name}", s!"lake-target={lib.name}",
      s!"lake-src-dir={lib.srcDir}"] ++
    valueTags "lake-root=" lib.roots ++
    valueTags "lake-default-facet=" lib.defaultFacets ++
    valueTags "lake-native-no-export=" lib.nativeFacetsNoExport ++
    valueTags "lake-native-export=" lib.nativeFacetsExport
  renderFilegroup (targetRuleName pkg.name lib.name) srcs tags

private def executableRuntimeData
    (model : ExportModel) (pkg : PackageModel) (exe : ExecutableModel) : Array String :=
  if pkg.name != model.workspace.rootPackage then
    #[]
  else
    let toolNames := model.authorityCatalog.tools.filterMap fun tool =>
      match tool.kind, tool.target with
      | .leanExe, some target => if target == exe.name then some tool.name else none
      | _, _ => none
    let generatorInputs := model.authorityCatalog.generators.foldl (init := #[]) fun data generator =>
      if toolNames.contains generator.tool then data ++ generator.inputs else data
    let checkInputs := model.authorityCatalog.checks.foldl (init := #[]) fun data check =>
      let usesExecutable := check.kind == .leanExe && check.root == exe.name
      let usesExecutableTool := check.kind == .process && toolNames.contains check.root
      if usesExecutable || usesExecutableTool then
        data ++ check.inputs ++ check.resources.map fun resource => label (resourceRuleName resource)
      else
        data
    sortedUnique (generatorInputs ++ checkInputs)

private def renderExecutableRule
    (model : ExportModel) (pkg : PackageModel) (exe : ExecutableModel) : String :=
  let linkModules := exe.orderedLinkInputs.map fun input =>
    label (moduleRuleName input.package input.module)
  let linkFacets := exe.orderedLinkInputs.map (·.facet)
  let tags := #["lake-kind=lean_exe", s!"lake-package={pkg.name}", s!"lake-target={exe.name}",
      s!"lake-root={exe.root}", s!"lake-output-name={exe.outputName}",
      s!"lake-support-interpreter={boolText exe.supportInterpreter}",
      s!"lake-shared-lean={boolText exe.sharedLean}"] ++
    valueTags "lake-link-arg=" exe.linkArgs ++
    valueTags "lake-weak-link-arg=" exe.weakLinkArgs ++
    valueTags "lake-native-no-export=" exe.nativeFacetsNoExport ++
    valueTags "lake-native-export=" exe.nativeFacetsExport ++
    valueTags "lake-link-input=" (exe.orderedLinkInputs.map fun input =>
      s!"{input.package}/{input.module};facet={input.facet}")
  renderLeanBinary
    (targetRuleName pkg.name exe.name)
    exe.root
    exe.outputName
    (executableRuntimeData model pkg exe)
    linkModules
    linkFacets
    exe.weakLinkArgs
    exe.linkArgs
    tags
    exe.supportInterpreter
    exe.sharedLean

private def renderInputFileRule (pkg : PackageModel) (input : InputFileModel) : String :=
  renderFilegroup (targetRuleName pkg.name input.name) #[input.path]
    #["lake-kind=input_file", s!"lake-package={pkg.name}", s!"lake-target={input.name}",
      s!"lake-path={input.path}", s!"lake-text={boolText input.text}"]

private def renderInputDirRule (pkg : PackageModel) (input : InputDirModel) : String :=
  renderFilegroup (targetRuleName pkg.name input.name) #[]
    #["lake-kind=input_dir", s!"lake-package={pkg.name}", s!"lake-target={input.name}",
      s!"lake-path={input.path}", s!"lake-text={boolText input.text}",
      s!"lake-filter={input.filter}"]

private def renderPackageRule (pkg : PackageModel) : String :=
  let srcs := pkg.targets.map fun target => label (targetRuleName pkg.name target.name)
  let tags := #["lake-kind=package", s!"lake-package={pkg.name}",
      s!"lake-directory={pkg.directory}", s!"lake-config-file={pkg.configFile}"] ++
    valueTags "lake-default-target=" pkg.defaultTargets ++
    optionTag "lake-test-driver=" pkg.testDriver ++
    valueTags "lake-test-driver-arg=" pkg.testDriverArgs ++
    optionTag "lake-lint-driver=" pkg.lintDriver ++
    valueTags "lake-lint-driver-arg=" pkg.lintDriverArgs
  renderFilegroup (packageRuleName pkg.name) srcs tags

private def renderToolchainRule (toolchain : ToolchainModel) : String :=
  -- Platform-specific flags remain in the verified manifests and SDK toolchain.
  renderFilegroup "lake_authority_toolchain" #[]
    #["lake-kind=toolchain", s!"lake-githash:{toolchain.githash}"]

private def renderResourceRule (resource : AuthorityResource) : String :=
  let tags := #["lake-kind=resource", s!"lake-resource={resource.name}",
      s!"lake-path={resource.path}"] ++ optionTag "lake-digest=" resource.digest
  renderFilegroup (resourceRuleName resource.name) #[resource.path] tags

private def renderToolRule
    (rootPackage : PackageModel) (tool : AuthorityTool) : String :=
  let srcs := match tool.target with
    | some target => #[label (targetRuleName rootPackage.name target)]
    | none => #[]
  let tags := #["lake-kind=authority_tool", s!"lake-tool={tool.name}",
      s!"lake-tool-kind={tool.kind.toString}", s!"lake-command={tool.command}"] ++
    optionTag "lake-target=" tool.target
  renderFilegroup (toolRuleName tool.name) srcs tags

private def renderGeneratorRule (generator : AuthorityGenerator) : String :=
  let tags := #["lake-kind=generator", s!"lake-generator={generator.name}",
      s!"lake-tool={generator.tool}", s!"lake-mode={generator.mode.toString}",
      s!"lake-deterministic={boolText generator.deterministic}"] ++
    valueTags "lake-arg=" generator.args ++ envTags "lake-env=" generator.env ++
    valueTags "lake-input=" generator.inputs ++ valueTags "lake-output=" generator.outputs
  renderFilegroup (generatorRuleName generator.name)
    (generator.inputs ++ generator.outputs) tags

private def checkRootLabel
    (model : ExportModel) (rootPackage : PackageModel) (check : AuthorityCheck) : Except String String := do
  match check.kind with
  | .leanExe => pure <| label (targetRuleName rootPackage.name check.root)
  | .leanProbe =>
      let (packageName, _) <- findModuleAcrossPackages model check.root
      pure <| label (moduleRuleName packageName check.root)
  | .process =>
      if model.authorityCatalog.tools.any (fun tool => tool.name == check.root) then
        pure <| label (toolRuleName check.root)
      else
        pure <| label (targetRuleName rootPackage.name check.root)

private def renderCheckRule
    (model : ExportModel) (rootPackage : PackageModel) (check : AuthorityCheck) : Except String String := do
  if check.kind == .process then
    failAt s!"authority check {check.name}" "cannot render Bazel check kind 'process'"
  let rootLabel <- checkRootLabel model rootPackage check
  let depLabels := check.deps.map fun dep => label (targetRuleName rootPackage.name dep)
  let resourceLabels := check.resources.map fun resource => label (resourceRuleName resource)
  let expected := check.expected
  let tags := #["lake-kind=check", s!"lake-check={check.name}",
      s!"lake-check-kind={check.kind.toString}", s!"lake-root={check.root}",
      s!"lake-expected-exit={expected.exit}"] ++
    valueTags "lake-arg=" check.args ++ envTags "lake-env=" check.env ++
    valueTags "lake-input=" check.inputs ++ valueTags "lake-resource=" check.resources ++
    valueTags "lake-dep=" check.deps ++
    optionTag "lake-expected-stdout=" expected.stdout ++
    optionTag "lake-expected-stderr=" expected.stderr
  pure <| renderLeanCheck
    (checkRuleName check.name)
    check.kind.toString
    rootLabel
    "."
    check.args
    check.env
    check.inputs
    resourceLabels
    depLabels
    tags
    expected

private def collectExportedFiles (model : ExportModel) : Array String :=
  let packageFiles := model.workspace.packages.foldl (init := #[]) fun files pkg =>
    let files := files.push pkg.configFile
    let files := files ++ pkg.modules.map (·.source)
    let files := files ++ pkg.executables.map (·.source)
    files ++ pkg.inputFiles.map (·.path)
  let catalog := model.authorityCatalog
  let files := packageFiles ++ catalog.resources.map (·.path)
  let files := catalog.generators.foldl (init := files) fun acc generator =>
    acc ++ generator.inputs ++ generator.outputs
  catalog.checks.foldl (init := files) fun acc check => acc ++ check.inputs

private def renderExports (paths : Array String) : String :=
  let paths := sortedUnique paths
  if paths.isEmpty then "" else
  let lines := paths.map fun path => "    " ++ quote path ++ ","
  "exports_files([\n" ++ String.intercalate "\n" lines.toList ++ "\n])\n\n"

def renderBazel (model : ExportModel) : Except String String := do
  validateModel model
  for pkg in model.workspace.packages do
    if let some packageId := pkg.packageId then
      if packageId.isEmpty then
        throw s!"workspace.packages.{pkg.name}.packageId: must be nonempty when present"
  let some rootPackage := findPackage? model model.workspace.rootPackage
    | failAt "workspace.rootPackage" "root package disappeared after validation"
  let mut rules : Array (String × String) := #[]
  for pkg in model.workspace.packages do
    for mod in pkg.modules do
      let name := moduleRuleName pkg.name mod.name
      rules := rules.push (name, renderModuleRule model pkg mod)
    for lib in pkg.libraries do
      let name := targetRuleName pkg.name lib.name
      rules := rules.push (name, renderLibraryRule pkg lib)
    for exe in pkg.executables do
      let name := targetRuleName pkg.name exe.name
      rules := rules.push (name, renderExecutableRule model pkg exe)
    for input in pkg.inputFiles do
      let name := targetRuleName pkg.name input.name
      rules := rules.push (name, renderInputFileRule pkg input)
    for input in pkg.inputDirs do
      let name := targetRuleName pkg.name input.name
      rules := rules.push (name, renderInputDirRule pkg input)
    let name := packageRuleName pkg.name
    rules := rules.push (name, renderPackageRule pkg)
  rules := rules.push ("lake_authority_toolchain", renderToolchainRule model.toolchain)
  for resource in model.authorityCatalog.resources do
    let name := resourceRuleName resource.name
    rules := rules.push (name, renderResourceRule resource)
  for tool in model.authorityCatalog.tools do
    let name := toolRuleName tool.name
    rules := rules.push (name, renderToolRule rootPackage tool)
  for generator in model.authorityCatalog.generators do
    let name := generatorRuleName generator.name
    rules := rules.push (name, renderGeneratorRule generator)
  for check in model.authorityCatalog.checks do
    let name := checkRuleName check.name
    let rendered <- renderCheckRule model rootPackage check
    rules := rules.push (name, rendered)
  ensureUnique "projected Bazel labels" (rules.map (·.1))
  let moduleRuleNames := model.workspace.packages.foldl (init := #[]) fun names pkg =>
    names ++ pkg.modules.map fun mod => label (moduleRuleName pkg.name mod.name)
  let moduleRule := renderFilegroup "lake_authority_modules"
    (moduleRuleNames.push projectionFreshnessLabel)
    #["lake-kind=authority_module_aggregate", s!"lake-schema-version={model.schemaVersion}"]
  let checkRuleNames := model.authorityCatalog.checks.map fun check =>
    label (checkRuleName check.name)
  let checkSuite := renderFilegroup "lake_authority_checks"
    (checkRuleNames.push projectionFreshnessLabel)
    #["lake-kind=authority_check_suite", s!"lake-schema-version={model.schemaVersion}"]
  let ruleNames := (rules.map (fun rule => label rule.1)).push projectionFreshnessLabel
    |>.qsort (· < ·)
  let allRule := renderFilegroup "lake_authority_all" ruleNames
    #["lake-kind=authority_aggregate", s!"lake-schema-version={model.schemaVersion}"]
  let sortedRules := rules.qsort (fun left right => left.1 < right.1)
  let body := String.intercalate "\n" (sortedRules.map (·.2)).toList
  pure <| "# Generated by tools/RenderBazel.lean. Do not edit by hand.\n" ++
    "load(\"@lean_bazel//tools:lean_binary.bzl\", \"lean_binary\")\n" ++
    "load(\"@lean_bazel//tools:lean_check.bzl\", \"lean_check\")\n" ++
    "load(\"@lean_bazel//tools:lean_module.bzl\", \"lean_module\")\n" ++
    "load(\"@lean_bazel//tools:lean_projection_freshness.bzl\", \"lean_projection_freshness\")\n\n" ++
    "package(default_visibility = [\"//visibility:public\"])\n\n" ++
    renderExports (collectExportedFiles model) ++
    renderProjectionInputs ++ "\n" ++ renderProjectionFreshness ++ "\n" ++
    body ++ "\n" ++ moduleRule ++ "\n" ++ checkSuite ++ "\n" ++ allRule

private def loadModel (path : System.FilePath) : IO ExportModel := do
  let raw <- IO.FS.readFile path
  match parseExportModelString raw with
  | .ok model => pure model
  | .error error => throw <| IO.userError s!"invalid Lake authority manifest: {error}"

def main (args : List String) : IO Unit := do
  match args with
  | [manifest, output] =>
      let model <- loadModel manifest
      let content <- match renderBazel model with
        | .ok content => pure content
        | .error error => throw <| IO.userError s!"cannot render Bazel projection: {error}"
      IO.FS.writeFile output content
  | _ =>
      throw <| IO.userError "usage: render-bazel MANIFEST OUTPUT"

end LeanBazel

public def main (args : List String) : IO UInt32 := do
  try
    LeanBazel.main args
    pure 0
  catch error =>
    IO.eprintln s!"render-bazel: {error}"
    pure 1
