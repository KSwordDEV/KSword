[CmdletBinding()]
param()

& (Join-Path $PSScriptRoot 'Invoke-KSwordNativeBuildCheck.ps1') -Product CLI
