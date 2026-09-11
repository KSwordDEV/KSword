param([Parameter(Mandatory=$true)][string]$Destination, [switch]$Update)
$ErrorActionPreference='Stop'
$destinationPath=[IO.Path]::GetFullPath($Destination)
$sourcePath=[IO.Path]::GetFullPath($PSScriptRoot)
if ($destinationPath -eq $sourcePath) { throw 'Export destination must differ from the source project.' }
$marker=Join-Path $destinationPath '.standalone-export'
if (Test-Path -LiteralPath $destinationPath) {
    if (!$Update -or !(Test-Path -LiteralPath $marker) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'DwmOrderTool-source-v1') {
        throw 'Destination exists. Use a new directory, or -Update for a previously generated export.'
    }
}
$core=if (Test-Path -LiteralPath (Join-Path $sourcePath 'core/DwmZOrderAgent')) { Join-Path $sourcePath 'core' } else { Split-Path -Parent $sourcePath }
$projectFiles=@('CMakeLists.txt','Main.cpp','Diagnostics.cpp','Diagnostics.h','app.rc','app.manifest','Build.ps1','Export-Source.ps1','Package.ps1','Test-Ui.ps1','README.md','.gitignore')
$coreFiles=@(
    'DwmZOrderAgent/DwmZOrderAgent.cpp','DwmZOrderAgent/NativeQueries.h','DwmZOrderAgent/OrderPlan.h',
    'DwmZOrderAgent/RuntimeResolver.cpp','DwmZOrderAgent/RuntimeResolver.h','DwmZOrderAgent/RuntimeSignatures.h','DwmZOrderAgent/RuntimeWin10Signatures.h','DwmZOrderAgent/RuntimeProfile.h',
    'DwmZOrderAgent/tests/OrderTests.cpp','DwmZOrderAgent/tests/LoaderTests.cpp','DwmZOrderAgent/tests/CfgTests.cpp',
    'DwmZOrderAgent/tests/DeploymentTests.cpp','DwmZOrderAgent/tests/RuntimeTests.cpp','DwmZOrderAgent/tests/LoaderFixture.cpp','DwmZOrderAgent/tests/PrivateQueryFixture.cpp',
    'Ksword5.1/Ksword5.1/OtherDock/DwmZOrderClient.cpp','Ksword5.1/Ksword5.1/OtherDock/DwmZOrderClient.h',
    'Ksword5.1/Ksword5.1/OtherDock/DwmAgentDeployment.cpp','Ksword5.1/Ksword5.1/OtherDock/DwmAgentDeployment.h','Ksword5.1/Ksword5.1/OtherDock/DwmRemoteLoader.asm',
    'shared/window/DwmZOrderProtocol.h','shared/window/DwmProcessIdentity.h','shared/window/DwmRemoteLoader.h',
    'tools/dwm_zorder/generate_signature_model.py','tools/dwm_zorder/generate_win10_signatures.py','tools/dwm_zorder/verify_profile.py'
)
$copies=@()
foreach ($file in $projectFiles) { $copies+=@{ Source=(Join-Path $sourcePath $file); Relative=$file } }
foreach ($file in $coreFiles) { $copies+=@{ Source=(Join-Path $core $file); Relative="core/$file" } }
$license=if (Test-Path -LiteralPath (Join-Path $sourcePath 'LICENSE')) { Join-Path $sourcePath 'LICENSE' } else { Join-Path $core 'LICENSE' }
$support=if (Test-Path -LiteralPath (Join-Path $sourcePath 'SUPPORT.md')) { Join-Path $sourcePath 'SUPPORT.md' } else { Join-Path $core 'docs/DWM窗口序列注入.md' }
$copies+=@{Source=$license;Relative='LICENSE'},@{Source=$support;Relative='SUPPORT.md'}
foreach ($copy in $copies) { if (!(Test-Path -LiteralPath $copy.Source -PathType Leaf)) { throw "Missing source: $($copy.Source)" } }
New-Item -ItemType Directory -Path $destinationPath -Force | Out-Null
$manifest=@()
foreach ($copy in $copies) {
    $target=Join-Path $destinationPath $copy.Relative
    New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
    Copy-Item -LiteralPath $copy.Source -Destination $target -Force
    $hash=(Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash
    if ($hash -ne (Get-FileHash -LiteralPath $copy.Source -Algorithm SHA256).Hash) { throw "Source copy differs: $($copy.Relative)" }
    $manifest+=@{path=$copy.Relative;sha256=$hash}
}
'DwmOrderTool-source-v1' | Set-Content -LiteralPath $marker -Encoding ascii
$manifest | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $destinationPath 'source-manifest.json') -Encoding UTF8
Write-Output "STANDALONE_SOURCE=$destinationPath"
Write-Output "SOURCE_FILES=$($manifest.Count)"
