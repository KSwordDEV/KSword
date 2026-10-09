# Actual R3 DeviceAudit decoder with a synthetic transport. No driver/device access.
param(
    [string]$Compiler = 'g++',
    [string]$OutputDirectory = '.codex-tmp/device-audit-typed-tests'
)
$ErrorActionPreference = 'Stop'
$auditRepository = Split-Path -Parent $PSScriptRoot
Push-Location $auditRepository
try {
    $auditOutput = if ([IO.Path]::IsPathRooted($OutputDirectory)) {
        [IO.Path]::GetFullPath($OutputDirectory)
    } else { [IO.Path]::GetFullPath((Join-Path $auditRepository $OutputDirectory)) }
    New-Item -ItemType Directory -Path $auditOutput -Force | Out-Null
    $auditFlags = @('-std=c++20', '-O1', '-g0', '-ffunction-sections', '-fdata-sections',
        '-DNOMINMAX', '-DUNICODE', '-D_UNICODE', '-I.')
    $auditObjects = @()
    foreach ($auditSource in @('tools/tests/device_audit_typed_protocol_tests.cpp',
        'Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverAudit.cpp')) {
        $auditObject = Join-Path $auditOutput (([IO.Path]::GetFileNameWithoutExtension($auditSource)) + '.o')
        & $Compiler @auditFlags -c $auditSource -o $auditObject
        if ($LASTEXITCODE -ne 0) { throw "DeviceAudit compilation failed: $auditSource" }
        $auditObjects += $auditObject
    }
    $auditExecutable = Join-Path $auditOutput 'device-audit-typed-tests.exe'
    & $Compiler @auditObjects '-Wl,--gc-sections' -o $auditExecutable
    if ($LASTEXITCODE -ne 0) { throw 'DeviceAudit test linking failed.' }
    & $auditExecutable 2>&1 | Tee-Object -FilePath (Join-Path $auditOutput 'device-audit-typed-tests.log')
    if ($LASTEXITCODE -ne 0) { throw 'DeviceAudit typed protocol regression failed.' }
} finally {
    Pop-Location
}
