# Physical-host SVM self-tests, with an explicit optional short resident/stop cycle.
[CmdletBinding()]
param([ValidateRange(0,30)][int]$ResidentSeconds=0)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Wait-HostStopCompletion($Controller,[timespan]$Timeout) {
    $Controller.Refresh()
    if ([string]$Controller.Status -eq 'StopPending') {
        # A successful sc stop only acknowledges the request; wait for SCM completion.
        $Controller.WaitForStatus('Stopped',$Timeout)
        $Controller.Refresh()
    }
    if ([string]$Controller.Status -ne 'Stopped') {
        throw "Existing KswordARK service must be STOPPED; actual=$($Controller.Status)."
    }
}
function Wait-HostDriverStopped {
    Add-Type -AssemblyName System.ServiceProcess
    $controller=New-Object System.ServiceProcess.ServiceController('KswordARK')
    try { Wait-HostStopCompletion $controller ([timespan]::FromSeconds(30)) }
    finally { $controller.Dispose() }
}

function Assert-HostSvmSelfTestEvidence($Prepared,$After,$Metrics,$Control,[int]$Count) {
    if ($Count -lt 1 -or $Prepared.queryStatus -ne 0 -or $Prepared.backend -ne 2 -or
        $Prepared.stateFlags -ne 3 -or $Prepared.preparedProcessorCount -ne $Count -or
        $After.queryStatus -ne 0 -or $After.backend -ne 2 -or $After.stateFlags -ne 19 -or
        $After.processorCount -ne $Count -or $After.preparedProcessorCount -ne $Count -or
        $After.selfTestPassedProcessorCount -ne $Count -or $After.residentProcessorCount -ne 0 -or
        $After.powerGeneration -ne $Prepared.powerGeneration -or $After.generation -le $Prepared.generation) {
        throw 'Self-test state, topology or generation mismatch.'
    }
    if ($Control.status -ne 0 -or $Control.failedProcessorCount -ne 0 -or
        $Control.selfTestPassedProcessorCount -ne $Count -or $Control.residentProcessorCount -ne 0 -or
        $Metrics.backend -ne 2 -or $Metrics.version -ne 9) { throw 'Self-test control/metrics mismatch.' }
    $sets=@()
    foreach ($rows in @(@($Prepared.processors),@($After.processors),@($Metrics.svmProcessors))) {
        $keys=@($rows | ForEach-Object { '{0}:{1}' -f $_.group,$_.number } | Sort-Object)
        if ($keys.Count -ne $Count -or @($keys|Select-Object -Unique).Count -ne $Count) {
            throw 'Missing or duplicate CPU identity.'
        }
        $sets+=($keys -join ',')
    }
    if ($sets[0] -ne $sets[1] -or $sets[0] -ne $sets[2]) { throw 'CPU sets changed between prepare and completion.' }
    foreach ($cpu in $After.processors) {
        if ($cpu.backend -ne 2 -or $cpu.executionStage -ne 2 -or $cpu.stateFlags -ne 3 -or
            $cpu.lastStatus -ne '0x00000000' -or $cpu.vmExitCount -ne 1 -or
            $cpu.svmExitCode -ne '0x0000000000000072') { throw 'CPU did not complete the expected CPUID round trip.' }
    }
    foreach ($cpu in $Metrics.svmProcessors) {
        if ($cpu.valid -ne 1 -or $cpu.sequence -le 0 -or ($cpu.sequence % 2) -ne 0 -or
            $cpu.stage -ne 2 -or $cpu.generation -ne $After.generation -or
            $cpu.failureStatus -ne '0x00000000' -or $cpu.failureStage -ne 0 -or
            $cpu.exitCode -ne '0x0000000000000072' -or [uint64]$cpu.tlbRequests -ne 1 -or
            $cpu.hsavePa -eq '0x0000000000000000' -or $cpu.nptRootPa -eq '0x0000000000000000') {
            throw 'CPU metrics lack a coherent successful VMRUN return.'
        }
    }
}

function Assert-HostSvmResidentEvidence($Baseline,$Snapshot,[bool]$Active,[int]$Count) {
    $expectedResident=0
    $expectedStage=6
    # Shared protocol: ENTERING=3, ENTERED=4. API return requires ENTERED.
    if ($Active) { $expectedResident=$Count; $expectedStage=4 }
    if ($Snapshot.queryStatus -ne 0 -or $Snapshot.backend -ne 2 -or
        $Snapshot.processorCount -ne $Count -or $Snapshot.preparedProcessorCount -ne $Count -or
        $Snapshot.selfTestPassedProcessorCount -ne $Count -or $Snapshot.residentProcessorCount -ne $expectedResident -or
        $Snapshot.powerGeneration -ne $Baseline.powerGeneration -or $Snapshot.generation -le $Baseline.generation) {
        throw 'Resident CPU count or generation mismatch.'
    }
    if ($Active) {
        # INITIALIZED/RESOURCES/SELF_TEST/ACTIVE/UNLOAD_GUARD, with no fault or pending transition.
        if ($Snapshot.stateFlags -ne 0x00404013) { throw 'Resident state or unload guard not established.' }
    } elseif ($Snapshot.stateFlags -ne 19) { throw 'Native stop was not fully acknowledged.' }
    $expected=@($Baseline.processors|ForEach-Object {'{0}:{1}' -f $_.group,$_.number}|Sort-Object)
    $actual=@($Snapshot.processors|ForEach-Object {'{0}:{1}' -f $_.group,$_.number}|Sort-Object)
    if ($actual.Count -ne $Count -or @($actual|Select-Object -Unique).Count -ne $Count -or
        ($expected -join ',') -ne ($actual -join ',')) { throw 'Resident CPU identity set changed.' }
    foreach ($cpu in $Snapshot.processors) {
        if ($cpu.backend -ne 2 -or $cpu.executionStage -ne $expectedStage -or
            $cpu.lastStatus -ne '0x00000000' -or (($cpu.stateFlags -band 0x100) -ne 0) -ne $Active) {
            throw ('CPU {0}:{1}: expected stage={2}, active={3}; observed stage={4}, flags=0x{5:X}, status={6}.' -f
                $cpu.group,$cpu.number,$expectedStage,$Active,$cpu.executionStage,$cpu.stateFlags,$cpu.lastStatus)
        }
    }
}

$principal=[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run from an elevated host PowerShell.' }
$repository=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$driver=Join-Path $repository 'Ksword5.1\x64\Release\KswordARK.sys'
$ctl=Join-Path $repository 'tools\hvm_ctl\hvm_ctl.exe'
$accepted=Get-Content -LiteralPath (Join-Path $repository 'docs\next\evidence\amd-host-admission-pass.json') -Raw | ConvertFrom-Json
if ((Get-FileHash -LiteralPath $driver).Hash -ne $accepted.driverSha256 -or
    (Get-FileHash -LiteralPath $ctl).Hash -ne $accepted.controlSha256) { throw 'Candidate differs from the accepted host admission evidence.' }
$gui=@(Get-Process -Name 'Ksword5.1' -ErrorAction SilentlyContinue)
if ($gui.Count) { throw ('Exit Ksword5.1 completely, including its tray icon, before this load/unload test. PID: '+(($gui|ForEach-Object Id) -join ',')) }
Wait-HostDriverStopped
$machine=Get-CimInstance Win32_ComputerSystem
if ($machine.HypervisorPresent) { throw 'Physical-host self-test requires the lab boot without an outer hypervisor.' }
$count=[int]$machine.NumberOfLogicalProcessors
$os=Get-CimInstance Win32_OperatingSystem
$evidence=Join-Path $PSScriptRoot ('artifacts\host-self-test-'+(Get-Date -Format yyyyMMdd-HHmmss)+'-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $evidence | Out-Null
$utf8=New-Object Text.UTF8Encoding($false)
@{scope='physical-host-svm-test';residentSeconds=$ResidentSeconds;driverSha256=$accepted.driverSha256;
    controlSha256=$accepted.controlSha256;logicalProcessors=$count;build=$os.BuildNumber;
    bootId=$os.LastBootUpTime.ToUniversalTime().ToString('o');hypervisorPresent=$machine.HypervisorPresent} |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidence 'identity.json') -Encoding UTF8
function Write-HostTestJournal([string]$Command) {
    [IO.File]::AppendAllText((Join-Path $evidence 'commands.log'),([DateTime]::UtcNow.ToString('o')+' '+$Command+[Environment]::NewLine),$utf8)
}
function Invoke-HostSelfTestService([string]$Label,[string[]]$Arguments) {
    Write-HostTestJournal ('sc '+($Arguments -join ' '))
    & sc.exe @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence ($Label+'.txt')) | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Service operation failed: $Label" }
}
function Invoke-HostSelfTestControl([string]$Command,[string]$Label) {
    Write-HostTestJournal ('hvm_ctl --json '+$Command)
    $raw=& $ctl --json $Command 2> (Join-Path $evidence ($Label+'.stderr.txt'))
    $exitCode=$LASTEXITCODE
    [IO.File]::WriteAllText((Join-Path $evidence ($Label+'.json')),($raw -join "`n"),$utf8)
    if ($exitCode -ne 0) { throw "CLI failed: $Command, exit=$exitCode" }
    $value=($raw -join "`n") | ConvertFrom-Json
    if ($value.PSObject.Properties['status'] -and $value.status -ne 0) { throw "Control refused: $Command, status=$($value.status)" }
    return $value
}

$safeToUnload=$false
$started=$false
Write-Host "Evidence: $evidence; sequential self-test on $count logical processors; resident seconds=$ResidentSeconds."
try {
    Invoke-HostSelfTestService 'config' @('config','KswordARK','binPath=',$driver,'start=','demand')
    Invoke-HostSelfTestService 'start' @('start','KswordARK')
    $started=$true
    $safeToUnload=$true
    $initial=Invoke-HostSelfTestControl 'status' 'initial'
    if ($initial.queryStatus -ne 0 -or $initial.backend -ne 2 -or $initial.stateFlags -ne 1 -or
        $initial.svmProbe.rejectReason -ne 0) { throw 'Initial SVM admission is no longer ready.' }
    # From this point, incomplete or failed evidence must retain the driver and its resources.
    $safeToUnload=$false
    $null=Invoke-HostSelfTestControl 'prepare' 'prepare'
    $prepared=Invoke-HostSelfTestControl 'status' 'prepared'
    if ($prepared.stateFlags -ne 3 -or $prepared.preparedProcessorCount -ne $count -or
        $prepared.powerGeneration -ne $initial.powerGeneration) { throw 'Preparation did not establish the complete CPU set.' }
    $control=Invoke-HostSelfTestControl 'self-test' 'self-test'
    $after=Invoke-HostSelfTestControl 'status' 'after-self-test'
    $metrics=Invoke-HostSelfTestControl 'metrics' 'metrics'
    Assert-HostSvmSelfTestEvidence $prepared $after $metrics $control $count
    if ($ResidentSeconds -gt 0) {
        # Always request native stop after attempting residency, even if evidence validation fails.
        # An unproven stop still leaves safeToUnload=false and retains the driver for diagnosis.
        try {
            Write-Host "Starting $count processors concurrently for $ResidentSeconds seconds."
            $null=Invoke-HostSelfTestControl 'resident' 'resident'
            $active=Invoke-HostSelfTestControl 'status' 'active'
            Assert-HostSvmResidentEvidence $after $active $true $count
            Start-Sleep -Seconds $ResidentSeconds
            $stillActive=Invoke-HostSelfTestControl 'status' 'active-after-wait'
            Assert-HostSvmResidentEvidence $after $stillActive $true $count
            if ($stillActive.generation -ne $active.generation) { throw 'Resident lifecycle changed during the observation window.' }
            $null=Invoke-HostSelfTestControl 'metrics' 'resident-metrics'
        } finally {
            $null=Invoke-HostSelfTestControl 'stop' 'resident-stop'
            $stoppedState=Invoke-HostSelfTestControl 'status' 'native-after-stop'
            Assert-HostSvmResidentEvidence $after $stoppedState $false $count
            $null=Invoke-HostSelfTestControl 'metrics' 'stopped-metrics'
        }
    }
    $null=Invoke-HostSelfTestControl 'teardown' 'teardown'
    $final=Invoke-HostSelfTestControl 'status' 'released'
    if ($final.stateFlags -ne 1 -or $final.processorCount -ne 0 -or $final.preparedProcessorCount -ne 0 -or
        $final.residentProcessorCount -ne 0 -or $final.slatReady -ne 0) { throw 'Resource release was not fully acknowledged.' }
    $safeToUnload=$true
} finally {
    if ($started -and $safeToUnload) {
        Invoke-HostSelfTestService 'stop' @('stop','KswordARK')
        Wait-HostDriverStopped
        Invoke-HostSelfTestService 'query-after-stop' @('query','KswordARK')
    } elseif ($started) {
        Write-Warning 'Test incomplete: driver/resources retained for diagnosis. Do not infer rollback from CLI termination.'
    }
    Write-Host "Host self-test evidence: $evidence"
}
Wait-HostDriverStopped
$result=[ordered]@{result='PASS';kind='physical-host-serial-svm-self-test';processors=$count;
    residentTested=($ResidentSeconds -gt 0);residentSeconds=$ResidentSeconds;
    innerOperatingSystemTested=$false;serviceState='Stopped';evidence=$evidence}
if ($ResidentSeconds -gt 0) { $result.kind='physical-host-short-resident-cycle' }
$result|ConvertTo-Json|Tee-Object -FilePath (Join-Path $evidence 'result.json')
