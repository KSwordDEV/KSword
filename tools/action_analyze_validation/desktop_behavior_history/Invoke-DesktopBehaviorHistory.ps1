<#
.SYNOPSIS
主协调CLI新包增量实测完成后的单端GUI放行入口。本脚本不构建、不启动CLI采集。
.EXAMPLE
./tools/action_analyze_validation/desktop_behavior_history/Invoke-DesktopBehaviorHistory.ps1 -Endpoint Qt -ReleasedAfterCli -CliSha256 <本批CLI哈希> -GuiSha256 <正式Qt哈希>
.EXAMPLE
./tools/action_analyze_validation/desktop_behavior_history/Invoke-DesktopBehaviorHistory.ps1 -Endpoint Light -ReleasedAfterCli -CliSha256 <本批CLI哈希> -GuiSha256 <正式Light哈希>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('Qt', 'Light')]
    [string]$Endpoint,
    [Parameter(Mandatory)]
    [switch]$ReleasedAfterCli,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$CliSha256,
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9A-Fa-f]{64}$')]
    [string]$GuiSha256,
    [string]$Python = 'python'
)

# 所有路径从本脚本位置计算；不依赖个人机器工作区、不复制运行时、不改输入桌面。
$ErrorActionPreference = 'Stop'
if (!$ReleasedAfterCli) {
    throw '本批仅准备脚本，须由主协调在CLI新包实测完成后显式放行。'
}
$validationRoot = Split-Path $PSScriptRoot -Parent
$repositoryRoot = (Resolve-Path (Join-Path $validationRoot '../..')).Path
$desktopLauncher = Join-Path $validationRoot 'isolated_desktop.py'
$guiScript = Join-Path $validationRoot ($Endpoint.ToLowerInvariant() + '/desktop_behavior_history.py')

# Qt与Light由协调者分别串行调用；只传入冻结哈希，不从旧回执推断本轮通过。
Push-Location $repositoryRoot
try {
    & $Python -B $desktopLauncher $guiScript --released-after-cli --cli-sha256 $CliSha256 --gui-sha256 $GuiSha256
    $validationExit = $LASTEXITCODE
} finally {
    Pop-Location
}
exit $validationExit
