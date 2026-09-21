# Run from the staged nested-probe share after a cold guest boot; never touch the host.
[CmdletBinding()]
param([ValidateSet(1,2,4,8)][int]$Vcpu=1,
      [ValidateRange(1,1000)][int]$Cycles=1,
      [switch]$GeneralResident)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Stop-GeneralService([string]$Evidence, [int]$TimeoutMilliseconds=30000) {
    # Reach this only after the runner proved all CPUs stopped and resources released.
    & sc.exe stop KswordARK 2>&1 | Out-File (Join-Path $evidence 'sc-stop.txt') -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'General smoke completed but service stop failed; retain evidence.' }
    $deadline=[DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        $state=& sc.exe query KswordARK
        $queryExit=$LASTEXITCODE
        $state | Out-File (Join-Path $evidence 'sc-final.txt') -Encoding UTF8
        if ($queryExit -ne 0) { throw 'Cannot query service unload completion.' }
        if (($state -join "`n") -match 'STATE\s*:\s*1\s+STOPPED') { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if (($state -join "`n") -notmatch 'STATE\s*:\s*1\s+STOPPED') { throw 'Service unload did not reach STOPPED.' }
}
$machine=Get-CimInstance Win32_ComputerSystem
$os=Get-CimInstance Win32_OperatingSystem
if ($machine.Manufacturer -notmatch 'VMware' -or $os.Caption -notmatch 'Windows 10' -or
    [int]$os.BuildNumber -ge 22000 -or [int]$machine.NumberOfLogicalProcessors -ne $Vcpu) {
    throw 'This entry requires the Windows 10 lab clone with the requested CPU count.'
}
$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Use an elevated guest PowerShell.' }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\KswordARK') {
    $state=& sc.exe query KswordARK
    if ($LASTEXITCODE -ne 0 -or ($state -join "`n") -notmatch 'STATE\s*:\s*1\s+STOPPED') {
        throw 'The existing driver must be STOPPED. This entry does not unload an active driver.'
    }
}
$identity=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'identity.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$suffix=(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N')
$runKind=if ($GeneralResident) {'general-resident'} else {'nested-probe'}
$candidate=Join-Path $env:SystemDrive ('KSwordLab\nested-candidate-'+$suffix)
$evidence=Join-Path $env:SystemDrive ('KSwordLab\'+$runKind+'-'+$suffix)
New-Item -ItemType Directory -Path $candidate | Out-Null
foreach ($name in @('KswordARK.sys','KswordARK.pdb','hvm_ctl.exe')) {
    $source=Join-Path $PSScriptRoot $name
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -ne $identity.candidateSha256.$name) { throw "Source hash mismatch: $name" }
    $target=Join-Path $candidate $name
    Copy-Item -LiteralPath $source -Destination $target
    if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $identity.candidateSha256.$name) { throw "Copy hash mismatch: $name" }
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'identity.json') -Destination $candidate
try {
    & (Join-Path $PSScriptRoot 'Load-GuestCandidate.ps1') -CandidateDirectory $candidate -ControlSourceDirectory $PSScriptRoot | Out-Null
    Write-Host "Candidate loaded. Starting $runKind; evidence: $evidence"
    & (Join-Path $PSScriptRoot 'Invoke-GuestAcceptance.ps1') -Ctl (Join-Path $candidate 'hvm_ctl.exe') `
        -EvidenceDirectory $evidence -Vcpu $Vcpu -Cycles $Cycles -NestedProbe:(-not $GeneralResident) -GeneralResident:$GeneralResident
    if ($GeneralResident) {
        Stop-GeneralService -Evidence $evidence
        @{result='PASS';kind='general-svm-resident-smoke';serviceState='Stopped';innerOperatingSystemTested=$false} |
            ConvertTo-Json | Set-Content (Join-Path $evidence 'complete.json') -Encoding UTF8
    }
} finally {
    # Export completed and failed evidence alike. Never issue a driver control from cleanup.
    if (-not (Test-Path -LiteralPath $evidence)) { New-Item -ItemType Directory -Path $evidence | Out-Null }
    Copy-Item -LiteralPath (Join-Path $candidate 'identity.json') -Destination $evidence
    foreach ($load in @(Get-ChildItem -LiteralPath $candidate -Directory -Filter 'driver-load-*')) {
        Copy-Item -LiteralPath $load.FullName -Destination $evidence -Recurse
    }
    $results=[string]::Concat([char]92,[char]92,'vmware-host',[char]92,'Shared Folders',[char]92,'KSwordResults')
    if (Test-Path -LiteralPath $results) {
        $destination=Join-Path $results ($runKind+'-'+$suffix)
        New-Item -ItemType Directory -Path $destination | Out-Null
        $records=@()
        foreach ($file in @(Get-ChildItem -LiteralPath $evidence -File -Recurse)) {
            $relative=$file.FullName.Substring($evidence.Length+1)
            $target=Join-Path $destination $relative
            New-Item -ItemType Directory -Path (Split-Path -Parent $target) -Force | Out-Null
            $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
            Copy-Item -LiteralPath $file.FullName -Destination $target
            if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $hash) { throw "Evidence export mismatch: $relative" }
            $records+=@{path=$relative;sha256=$hash;bytes=$file.Length}
        }
        @{schema=1;files=$records} | ConvertTo-Json -Depth 6 |
            Set-Content -LiteralPath (Join-Path $destination 'export-manifest.json') -Encoding UTF8
        Write-Host "Evidence exported: $destination"
    } else { Write-Warning "Results share unavailable; evidence retained: $evidence" }
}
