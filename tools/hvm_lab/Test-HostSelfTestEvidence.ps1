# Exercise only the production evidence validator; never load a driver or execute SVM.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot 'Test-HostSvmSelfTest.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw ($errors|Out-String) }
$validator=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-HostSvmSelfTestEvidence'},$true)
Invoke-Expression $validator.Extent.Text
$residentValidator=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-HostSvmResidentEvidence'},$true)
Invoke-Expression $residentValidator.Extent.Text
function New-TestEvidence([int]$Count=2) {
    $cpus=@(0..($Count-1)|ForEach-Object {
        [pscustomobject]@{group=0;number=$_;backend=2;executionStage=2;stateFlags=3;
            lastStatus='0x00000000';vmExitCount=1;svmExitCode='0x0000000000000072'}
    })
    $metrics=@(0..($Count-1)|ForEach-Object {
        [pscustomobject]@{group=0;number=$_;valid=1;sequence=2;stage=2;generation=3;
            failureStatus='0x00000000';failureStage=0;exitCode='0x0000000000000072';
            tlbRequests='1';hsavePa='0x0000000000001000';nptRootPa='0x0000000000002000'}
    })
    # JSON round-trip keeps each snapshot independent, as real CLI processes do.
    return ([pscustomobject]@{
        Prepared=@{queryStatus=0;backend=2;stateFlags=3;preparedProcessorCount=$Count;powerGeneration=0;generation=2;processors=$cpus}
        After=@{queryStatus=0;backend=2;stateFlags=19;processorCount=$Count;preparedProcessorCount=$Count;
            selfTestPassedProcessorCount=$Count;residentProcessorCount=0;powerGeneration=0;generation=3;processors=$cpus}
        Metrics=@{backend=2;version=9;svmProcessors=$metrics}
        Control=@{status=0;failedProcessorCount=0;selfTestPassedProcessorCount=$Count;residentProcessorCount=0}
    } | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
}
$checks=0
foreach ($count in @(1,2,8,32)) {
    $t=New-TestEvidence $count
    Assert-HostSvmSelfTestEvidence $t.Prepared $t.After $t.Metrics $t.Control $count
    ++$checks
}
$failures=@(
    {param($t) $t.After.processors[1].number=0},
    {param($t) $t.Metrics.svmProcessors[1].number=3},
    {param($t) $t.After.processors=@($t.After.processors[0])},
    {param($t) $t.After.stateFlags=3},
    {param($t) $t.After.residentProcessorCount=1},
    {param($t) $t.After.powerGeneration=1},
    {param($t) $t.After.generation=2},
    {param($t) $t.Control.failedProcessorCount=1},
    {param($t) $t.Metrics.version=3},
    {param($t) $t.After.processors[0].vmExitCount=0},
    {param($t) $t.After.processors[0].svmExitCode='0xFFFFFFFFFFFFFFFF'},
    {param($t) $t.Metrics.svmProcessors[0].valid=0},
    {param($t) $t.Metrics.svmProcessors[0].sequence=3},
    {param($t) $t.Metrics.svmProcessors[0].failureStatus='0xC00000BB'},
    {param($t) $t.Metrics.svmProcessors[0].generation=2},
    {param($t) $t.Metrics.svmProcessors[0].tlbRequests='0'},
    {param($t) $t.Metrics.svmProcessors[0].hsavePa='0x0000000000000000'}
)
foreach ($change in $failures) {
    $t=New-TestEvidence
    & $change $t
    $rejected=$false
    try { Assert-HostSvmSelfTestEvidence $t.Prepared $t.After $t.Metrics $t.Control 2 }
    catch { $rejected=$true }
    if (-not $rejected) { throw "Invalid evidence accepted: $change" }
    ++$checks
}
$t=New-TestEvidence
$snapshot=($t.After|ConvertTo-Json -Depth 6|ConvertFrom-Json)
$snapshot.generation=4; $snapshot.stateFlags=0x404013; $snapshot.residentProcessorCount=2
# Read the protocol authority, rather than copying a guessed stage from the validator.
$protocol=Get-Content (Join-Path $PSScriptRoot '../../shared/driver/KswordArkHvmIoctl.h') -Raw
if ($protocol -notmatch '#define\s+KSWORD_ARK_HVM_STAGE_ENTERED\s+(\d+)UL') { throw 'Missing ENTERED stage definition.' }
$enteredStage=[int]$Matches[1]
foreach ($cpu in $snapshot.processors) { $cpu.executionStage=$enteredStage; $cpu.stateFlags=0x103 }
Assert-HostSvmResidentEvidence $t.After $snapshot $true 2
++ $checks
foreach ($change in @(
    {param($s) $s.residentProcessorCount=1},
    {param($s) $s.stateFlags=0x4013},
    {param($s) $s.processors[1].number=0},
    {param($s) $s.processors[1].stateFlags=3},
    {param($s) $s.processors[1].executionStage=3},
    {param($s) $s.powerGeneration=1}
)) {
    $bad=$snapshot|ConvertTo-Json -Depth 6|ConvertFrom-Json
    & $change $bad
    $rejected=$false
    try { Assert-HostSvmResidentEvidence $t.After $bad $true 2 } catch { $rejected=$true }
    if (-not $rejected) { throw 'Incomplete residency was accepted.' }
    ++$checks
}
$snapshot.generation=5; $snapshot.stateFlags=19; $snapshot.residentProcessorCount=0
foreach ($cpu in $snapshot.processors) { $cpu.executionStage=6; $cpu.stateFlags=3 }
Assert-HostSvmResidentEvidence $t.After $snapshot $false 2
++ $checks
$snapshot.processors[0].stateFlags=0x103
$rejected=$false
try { Assert-HostSvmResidentEvidence $t.After $snapshot $false 2 } catch { $rejected=$true }
if (-not $rejected) { throw 'An active CPU survived a supposedly complete stop.' }
++ $checks
# Replay the actual 32-CPU snapshots that exposed the ENTERING/ENTERED confusion.
$fixture=Get-Content (Join-Path $PSScriptRoot '../../docs/next/evidence/amd-host-resident-enter-stop.json') -Raw|ConvertFrom-Json
Assert-HostSvmResidentEvidence $fixture.regression.baseline $fixture.regression.active $true 32
Assert-HostSvmResidentEvidence $fixture.regression.baseline $fixture.regression.stopped $false 32
$checks+=2
$waitFunction=$ast.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Wait-HostStopCompletion'},$true)
Invoke-Expression $waitFunction.Extent.Text
function New-FakeService([string]$State,[bool]$Timeout=$false) {
    $fake=[pscustomobject]@{Status=$State;WaitCalls=0;SimulateTimeout=$Timeout}
    $fake|Add-Member ScriptMethod Refresh {}
    $fake|Add-Member ScriptMethod WaitForStatus {
        param($Expected,$Duration)
        ++$this.WaitCalls
        if ([string]$Expected -ne 'Stopped' -or $Duration.TotalSeconds -ne 30) { throw 'Wrong bounded wait contract.' }
        if ($this.SimulateTimeout) { throw [TimeoutException]::new('Simulated SCM timeout') }
        $this.Status='Stopped'
    }
    return $fake
}
$fake=New-FakeService 'Stopped'
Wait-HostStopCompletion $fake ([timespan]::FromSeconds(30))
if ($fake.WaitCalls -ne 0) { throw 'An already stopped service should not wait.' }
++ $checks
$fake=New-FakeService 'StopPending'
Wait-HostStopCompletion $fake ([timespan]::FromSeconds(30))
if ($fake.WaitCalls -ne 1 -or $fake.Status -ne 'Stopped') { throw 'Pending stop was not awaited.' }
++ $checks
foreach ($state in @('Running','StartPending','StopPending')) {
    $fake=New-FakeService $state $true
    $rejected=$false
    try { Wait-HostStopCompletion $fake ([timespan]::FromSeconds(30)) } catch { $rejected=$true }
    if (-not $rejected -or $fake.Status -ne $state) { throw 'Unproven SCM stop was accepted.' }
    if ($state -ne 'StopPending' -and $fake.WaitCalls -ne 0) { throw 'Waited for an unsolicited stop.' }
    ++$checks
}
Write-Output "HOST_SELF_TEST_EVIDENCE_CHECKS=$checks PASS (synthetic and recorded evidence; no driver loaded)"
