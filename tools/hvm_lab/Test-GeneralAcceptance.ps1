# Validate production evidence gates against synthetic snapshots; never contact a driver.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Invoke-GuestAcceptance.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Runner parse failed.' }
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'CheckGeneral'},$true)
Invoke-Expression $function.Extent.Text
$Vcpu=8
function Snapshot([bool]$Active) {
    $enabled=if ($Active) {1} else {0}
    return [pscustomobject]@{version=6;backend=2;svmProcessors=@(0..7 | ForEach-Object {
        [pscustomobject]@{group=0;number=$_;failureStatus='0x00000000';general=[pscustomobject]@{
            valid=1;sequence='4294967298';preparedEntries='1';hardwareExits=$(if ($Active) {'0'} else {'1'});
            enabled=$enabled;initialized=$enabled;pending=0;nmiCaptured=0;
            leaseToken='0x0000000000000000';armedToken='0';retryToken='0'}}
    })}
}
CheckGeneral (Snapshot $true) $true
CheckGeneral (Snapshot $false) $false
$cases=@(
    {param($s) $s.version=4},
    {param($s) $s.backend=1},
    {param($s) $s.svmProcessors=$s.svmProcessors[0..6]},
    {param($s) $s.svmProcessors[7].number=0},
    {param($s) $s.svmProcessors[7].group=1},
    {param($s) $s.svmProcessors[7].general.valid=0},
    {param($s) $s.svmProcessors[7].general.sequence='4294967299'},
    {param($s) $s.svmProcessors[7].general.preparedEntries='0'},
    {param($s) $s.svmProcessors[7].general.hardwareExits='0'},
    {param($s) $s.svmProcessors[7].failureStatus='0xC0000001'},
    {param($s) $s.svmProcessors[7].general.enabled=1},
    {param($s) $s.svmProcessors[7].general.initialized=1},
    {param($s) $s.svmProcessors[7].general.pending=1},
    {param($s) $s.svmProcessors[7].general.nmiCaptured=1},
    {param($s) $s.svmProcessors[7].general.leaseToken='0x100000000'},
    {param($s) $s.svmProcessors[7].general.armedToken='1'},
    {param($s) $s.svmProcessors[7].general.retryToken='1'}
)
foreach ($case in $cases) {
    $snapshot=Snapshot $false
    & $case $snapshot
    $rejected=$false
    try { CheckGeneral $snapshot $false } catch { $rejected=$true }
    if (-not $rejected) { throw "Accepted invalid snapshot: $case" }
}
# Mutual exclusion must reject before any environment query or driver action.
$rejected=$false
try {
    & (Join-Path $PSScriptRoot 'Invoke-GuestAcceptance.ps1') -Ctl unused -EvidenceDirectory unused -Vcpu 1 -NestedProbe -GeneralResident
} catch {
    if ($_.Exception.Message -notmatch 'mutually exclusive') { throw }
    $rejected=$true
}
if (-not $rejected) { throw 'Conflicting modes accepted.' }
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Start-GuestNestedProbe.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Staging wrapper parse failed.' }
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Stop-GeneralService'},$true)
Invoke-Expression $function.Extent.Text
$evidence=Join-Path $PSScriptRoot ('artifacts/general-script-test-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence | Out-Null
function sc.exe {
    $global:LASTEXITCODE=0
    if ($args[0] -eq 'stop') {
        $global:LASTEXITCODE=$script:stopExit
        return 'STATE : 3 STOP_PENDING'
    }
    if ($args[0] -ne 'query') { throw 'Unexpected SCM command.' }
    $global:LASTEXITCODE=$script:queryExit
    $script:queries++
    if ($script:queries -ge $script:stopAfter) { return 'STATE : 1 STOPPED' }
    return 'STATE : 3 STOP_PENDING'
}
function Start-Sleep { param($Milliseconds) }
$script:queries=0; $script:stopExit=0; $script:queryExit=0; $script:stopAfter=2
Stop-GeneralService -Evidence $evidence
if ($script:queries -ne 2) { throw 'STOP_PENDING was accepted as STOPPED.' }
foreach ($case in @('stop-failed','query-failed','still-pending')) {
    $script:queries=0; $script:stopExit=0; $script:queryExit=0; $script:stopAfter=1
    if ($case -eq 'stop-failed') { $script:stopExit=5 }
    if ($case -eq 'query-failed') { $script:queryExit=5 }
    if ($case -eq 'still-pending') { $script:stopAfter=99 }
    $rejected=$false
    try { Stop-GeneralService -Evidence $evidence -TimeoutMilliseconds 0 } catch { $rejected=$true }
    if (-not $rejected) { throw "SCM failure accepted: $case" }
}
'GENERAL_UNLOAD_TESTS=PASS pending-to-stopped=1 refused=3 SCM=SIMULATED'
'GENERAL_EVIDENCE_TESTS=PASS active/stopped=2 refused=17 conflictingModes=PASS hardware=NOT_RUN'
