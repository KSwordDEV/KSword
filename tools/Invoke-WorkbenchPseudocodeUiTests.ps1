# 独立编译真实 C 页面与共享编辑器；未触发的共享依赖复用主程序链接对象。
# 产物写入已存在的日志目录；不建临时目录，不执行 Java、设备或剪贴板动作。
param(
    [string]$RepositoryRoot = (Split-Path -Parent $PSScriptRoot),
    [string[]]$TestCases = @(),
    [switch]$BuildOnly,
    [switch]$RunOnly,
    [switch]$RelinkOnly
)
$ErrorActionPreference = 'Stop'
if ($RunOnly -and $RelinkOnly) { throw 'RunOnly and RelinkOnly are mutually exclusive.' }
$cPageRepository = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$cPageOutput = Join-Path $cPageRepository '.codex-build-logs'
if (!(Test-Path -LiteralPath $cPageOutput)) { throw 'The established .codex-build-logs directory is required.' }
$cPageQt = Join-Path $cPageRepository '.deps/Qt/6.9.3/msvc2022_64'
if (!(Test-Path -LiteralPath $cPageQt)) { $cPageQt = 'D:/Software/Qt/6.9.3/msvc2022_64' }
$cPageVcBase = 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/VC/Tools/MSVC'
if (!(Test-Path -LiteralPath $cPageVcBase)) { $cPageVcBase = 'D:/Software/VS/VC/Tools/MSVC' }
$cPageVcRoot = Join-Path $cPageVcBase '14.44.35207'
if (!(Test-Path -LiteralPath $cPageVcRoot)) {
    $cPageCandidate = Get-ChildItem -LiteralPath $cPageVcBase -Directory | Sort-Object Name -Descending | Select-Object -First 1
    if (!$cPageCandidate) { throw 'HostX64 MSVC is required.' }
    $cPageVcRoot = $cPageCandidate.FullName
}
$cPageSdk = 'C:/Program Files (x86)/Windows Kits/10'
$cPageSdkVersion = '10.0.26100.0'
$cPageCompiler = Join-Path $cPageVcRoot 'bin/Hostx64/x64/cl.exe'
$cPageLinker = Join-Path $cPageVcRoot 'bin/Hostx64/x64/link.exe'
foreach ($cPageRequired in @($cPageCompiler, $cPageLinker, (Join-Path $cPageQt 'lib/Qt6Widgets.lib'))) {
    if (!(Test-Path -LiteralPath $cPageRequired)) { throw "Required tool or Qt library is missing: $cPageRequired" }
}
# 只使用项目配置中的已知依赖路径；MSVC/SDK 头按外部依赖免报第三方警告。
$cPageIncludes = @(('/I' + $cPageRepository), ('/I' + (Join-Path $cPageRepository 'third_party/zydis')),
    ('/external:I' + (Join-Path $cPageVcRoot 'include')))
foreach ($cPageModule in @('', 'QtCore', 'QtGui', 'QtWidgets', 'QtSvg', 'QtTest')) {
    $cPageIncludes += '/external:I' + (Join-Path $cPageQt ('include/' + $cPageModule))
}
foreach ($cPagePart in @('ucrt', 'shared', 'um')) {
    $cPageIncludes += '/external:I' + (Join-Path $cPageSdk ('Include/' + $cPageSdkVersion + '/' + $cPagePart))
}
$cPageApp = 'Ksword5.1/Ksword5.1'
$cPageContractHeaders = @("$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.h",
    "$cPageApp/UI/Decompiler/GhidraDecompiler.h", "$cPageApp/UI/Decompiler/RawCodePlanner.h")
$cPageSources = @(
    'tools/tests/workbench_pseudocode_ui_tests.cpp', 'tools/workbench_pseudocode_contract_tests.cpp',
    "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.cpp", "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.Ui.cpp", "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.Raw.cpp",
    "$cPageApp/UI/Decompiler/GhidraDecompiler.cpp", "$cPageApp/UI/Decompiler/RawCodePlanner.cpp", 'GhidraRuntimePlugin/RuntimeProfile.cpp',
    "$cPageApp/UI/AsyncOperation.cpp",
    "$cPageApp/UI/CodeEditorWidget.cpp", "$cPageApp/UI/CodeEditorWidget.Export.cpp", "$cPageApp/UI/CodeTextEdit.cpp", "$cPageApp/UI/CodeEditorFileSession.cpp",
    "$cPageApp/UI/StructuredFieldView.cpp", "$cPageApp/UI/FieldTreeModel.cpp", "$cPageApp/UI/FieldDocument.cpp", "$cPageApp/UI/TypedSyntaxDocument.cpp", "$cPageApp/UI/DetailLayoutHost.cpp", "$cPageApp/UI/DetailLayoutHost.Binding.cpp",
    "$cPageApp/UI/DetailLayoutHost.Compatibility.cpp", "$cPageApp/UI/EmbeddedRowDelegate.cpp",
    "$cPageApp/UI/FlowLayout.cpp", "$cPageApp/UI/ThemeStatusRole.cpp", "$cPageApp/UI/ThemeControlGlyphs.cpp",
    "$cPageApp/UI/SmoothScrollSupport.cpp", "$cPageApp/UI/FlatButtonTheme.cpp", "$cPageApp/UI/ThemeBinding.cpp", "$cPageApp/UI/ThemeAccentIcon.cpp",
    "$cPageApp/UI/PrimaryPageStyle.cpp", "$cPageApp/UI/MainSurfaceStyle.cpp", "$cPageApp/UI/PageControlStyle.cpp",
    "$cPageApp/UI/PageTabMotion.cpp", "$cPageApp/UI/PageTabFocusStyle.cpp", "$cPageApp/UI/TabHierarchyTransition.cpp",
    "$cPageApp/Internationalization/LanguageManager.cpp"
)
$cPageOldPath = $env:PATH
$cPageOldPlatform = $env:QT_QPA_PLATFORM
$cPageOldPlugins = $env:QT_PLUGIN_PATH
$cPageExe = Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.exe'
Push-Location $cPageRepository
try {
    $env:PATH = (Join-Path $cPageQt 'bin') + ';' + (Join-Path $cPageSdk ('bin/' + $cPageSdkVersion + '/x64')) + ';' + $cPageOldPath
    if (!$RunOnly) {
        foreach ($cPageHeader in @("$cPageApp/UI/CodeEditorWidget.h", "$cPageApp/UI/StructuredFieldView.h", "$cPageApp/UI/MemoryWorkbench/WorkbenchPseudocodeView.h", "$cPageApp/UI/Decompiler/GhidraDecompiler.h")) {
            $cPageMoc = Join-Path $cPageOutput ('c_progress_moc_' + [IO.Path]::GetFileNameWithoutExtension($cPageHeader) + '.cpp')
            if (!$RelinkOnly) {
                & (Join-Path $cPageQt 'bin/moc.exe') $cPageHeader -o $cPageMoc
                if ($LASTEXITCODE -ne 0) { throw "moc failed: $cPageHeader" }
            }
            $cPageSources += $cPageMoc
        }
        $cPageObjects = @()
        foreach ($cPageSource in $cPageSources) {
            $cPageObject = Join-Path $cPageOutput ('c_progress_' + [IO.Path]::GetFileNameWithoutExtension($cPageSource) + '.obj')
            if ($RelinkOnly) {
                if (!(Test-Path -LiteralPath $cPageObject)) { throw "Compile the current regression sources first: $cPageObject" }
                if ((Get-Item -LiteralPath $cPageSource).LastWriteTimeUtc -gt (Get-Item -LiteralPath $cPageObject).LastWriteTimeUtc) {
                    throw "The regression object is stale; rerun without RelinkOnly: $cPageSource"
                }
                $cPageObjects += $cPageObject
                continue
            }
            $cPageWarnings = @('/W3')
            if ($cPageSource -match '(workbench_pseudocode|WorkbenchPseudocode|GhidraDecompiler|RawCodePlanner|CodeEditorWidget|CodeTextEdit)') {
                $cPageWarnings = @('/W4', '/WX')
            }
            # 原主工程明确排除的旧语法器 data 局部名称警告；不屏蔽本轮新增警告。
            if ($cPageSource -match 'CodeTextEdit\.cpp$') { $cPageWarnings += '/wd4458' }
            & $cPageCompiler /nologo /std:c++20 /Zc:__cplusplus /permissive- /utf-8 /EHsc /MD @cPageWarnings /external:W0 /O1 /Gy /bigobj `
                /DQT_CORE_LIB /DQT_GUI_LIB /DQT_WIDGETS_LIB /DQT_TESTLIB_LIB /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /DZYDIS_STATIC_BUILD /DZYCORE_STATIC_BUILD `
                @cPageIncludes /c $cPageSource ('/Fo' + $cPageObject)
            if ($LASTEXITCODE -ne 0) { throw "Production C page component compilation failed: $cPageSource" }
            $cPageObjects += $cPageObject
        }
        if ($RelinkOnly) {
            $cPageOldestObject = $cPageObjects | ForEach-Object { Get-Item -LiteralPath $_ } | Sort-Object LastWriteTimeUtc | Select-Object -First 1
            foreach ($cPageContractHeader in $cPageContractHeaders) {
                if ((Get-Item -LiteralPath $cPageContractHeader).LastWriteTimeUtc -gt $cPageOldestObject.LastWriteTimeUtc) {
                    throw "Recompile regression objects after the public analysis contract changed: $cPageContractHeader"
                }
            }
        }
        # 沿用 Invoke-MemoryEditorUiTests 的生产依赖链，避免独立维护第二套主题/详情依赖清单。
        # 当前测试、C 页面、RAW planner、后端及以上源码全部使用刚编译对象；同名旧对象必须排除。
        $cPageLinkCandidates = @(
            'Ksword5.1/Ksword5.1/x64/Release/Ksword5.1.tlog/link.command.1.tlog',
            'Ksword5.1/Ksword5.1/Ksword5.1/x64/Release/Ksword5.1.tlog/link.command.1.tlog'
        ) | ForEach-Object { Get-Item -LiteralPath (Join-Path $cPageRepository $_) -ErrorAction SilentlyContinue }
        $cPageLinkLog = $cPageLinkCandidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if (!$cPageLinkLog) { throw 'Build the production application before linking the C page regression.' }
        # 这些公开类型的内联构造也可能来自未触发的宿主对象；不能混用旧布局的 COMDAT。
        foreach ($cPageContractHeader in $cPageContractHeaders) {
            if ((Get-Item -LiteralPath $cPageContractHeader).LastWriteTimeUtc -gt $cPageLinkLog.LastWriteTimeUtc) {
                throw "Rebuild production after its public analysis contract changed: $cPageContractHeader"
            }
        }
        $cPageLinkLines = Get-Content -LiteralPath $cPageLinkLog.FullName
        $cPageProductionInputs = @()
        $cPageProductionFlags = $null
        for ($cPageLineIndex = 1; $cPageLineIndex -lt $cPageLinkLines.Count; ++$cPageLineIndex) {
            if ($cPageLinkLines[$cPageLineIndex] -match '/OUT:"[^"\r\n]*\\KSWORD5\.1\.EXE"') {
                $cPageProductionInputs = @($cPageLinkLines[$cPageLineIndex - 1].TrimStart('^').Split('|'))
                $cPageProductionFlags = $cPageLinkLines[$cPageLineIndex]
            }
        }
        if (!$cPageProductionFlags -or $cPageProductionInputs.Count -lt 2) { throw 'Production link record was not found.' }
        $cPageMainObjects = @($cPageProductionInputs | Where-Object { [IO.Path]::GetFileName($_) -ieq 'main.obj' })
        if ($cPageMainObjects.Count -ne 1) { throw 'Production entry point is ambiguous.' }
        $cPageRecompiledNames = @($cPageSources | ForEach-Object {
            ([IO.Path]::GetFileNameWithoutExtension($_) -replace '^c_progress_', '') + '.obj'
        })
        $cPageProductionInputs = @($cPageProductionInputs | Where-Object {
            $_ -match '\.(OBJ|LIB)$' -and $_ -notin $cPageMainObjects -and
            [IO.Path]::GetFileName($_) -notin $cPageRecompiledNames
        })
        if ($cPageProductionInputs | Where-Object { [IO.Path]::GetFileName($_) -match '^(?:MOC_)?(?:WORKBENCHPSEUDOCODEVIEW|GHIDRADECOMPILER|RAWCODEPLANNER)(?:\..*)?\.OBJ$' }) {
            throw 'An old C page, RAW planner, backend or related moc object escaped replacement.'
        }
        $cPageResponse = [regex]::Replace($cPageProductionFlags, '/(?:OUT|PDB|IMPLIB|LTCGOUT):(?:"[^"]*"|\S+)', '', 'IgnoreCase')
        $cPageResponse = [regex]::Replace($cPageResponse, '/SUBSYSTEM:\S+|\S+\.RES\b', '', 'IgnoreCase')
        $cPageResponse += ' /OUT:"' + $cPageExe + '" /SUBSYSTEM:CONSOLE /INCREMENTAL:NO'
        $cPageResponse += ' /PDB:"' + (Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.pdb') + '"'
        $cPageResponse += ' /LTCG:INCREMENTAL /LTCGOUT:"' + (Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.iobj') + '"'
        foreach ($cPageLibraryRoot in @((Join-Path $cPageVcRoot 'lib/x64'), (Join-Path $cPageVcRoot 'atlmfc/lib/x64'),
            (Join-Path $cPageQt 'lib'), (Join-Path $cPageRepository "$cPageApp/lib"))) {
            $cPageResponse += ' /LIBPATH:"' + $cPageLibraryRoot + '"'
        }
        foreach ($cPagePart in @('ucrt', 'um')) {
            $cPageResponse += ' /LIBPATH:"' + (Join-Path $cPageSdk ('Lib/' + $cPageSdkVersion + '/' + $cPagePart + '/x64')) + '"'
        }
        $cPageZydis = Join-Path $cPageRepository 'third_party/zydis/x64/Release/KswordZydis.lib'
        if (!(Test-Path -LiteralPath $cPageZydis)) { throw "Build the production Zydis library first: $cPageZydis" }
        foreach ($cPageInput in @($cPageObjects) + @($cPageProductionInputs) + @($cPageZydis, (Join-Path $cPageQt 'lib/Qt6Test.lib'))) {
            $cPageResponse += "`r`n`"" + $cPageInput + '"'
        }
        $cPageResponseFile = Join-Path $cPageOutput 'workbench-pseudocode-ui-tests.rsp'
        [IO.File]::WriteAllText($cPageResponseFile, $cPageResponse, [Text.Encoding]::Unicode)
        & $cPageLinker ('@' + $cPageResponseFile)
        if ($LASTEXITCODE -ne 0) { throw 'C page regression link failed.' }
    }
    if ($BuildOnly) { Write-Output 'WORKBENCH_PSEUDOCODE_UI_BUILD=PASS'; return }
    if (!(Test-Path -LiteralPath $cPageExe)) { throw 'Build the C page regression executable before RunOnly.' }
    $env:PATH = (Join-Path $cPageRepository 'Ksword5.1/x64/Release') + ';' + $env:PATH
    $env:QT_QPA_PLATFORM = 'offscreen'
    $env:QT_PLUGIN_PATH = Join-Path $cPageQt 'plugins'
    $cPageLog = Join-Path $cPageOutput 'workbench_pseudocode_ui_tests.log'
    $cPageRunCases = if ($TestCases.Count) { $TestCases } else { @('all') }
    $cPageFailures = 0
    foreach ($cPageCase in $cPageRunCases) {
        $cPageArgs = if ($cPageCase -eq 'all') { @() } else { @('--case', $cPageCase) }
        $ErrorActionPreference = 'Continue'
        & $cPageExe @cPageArgs 2>&1 | Tee-Object -FilePath $cPageLog -Append
        $cPageExit = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($cPageExit -ne 0) {
            ++$cPageFailures
            Write-Output "WORKBENCH_PSEUDOCODE_UI_CASE=$cPageCase EXIT_CODE=$cPageExit"
        }
    }
    if ($cPageFailures) { throw "C page regression cases failed: $cPageFailures" }
}
finally {
    Pop-Location
    $env:PATH = $cPageOldPath
    $env:QT_QPA_PLATFORM = $cPageOldPlatform
    $env:QT_PLUGIN_PATH = $cPageOldPlugins
}
