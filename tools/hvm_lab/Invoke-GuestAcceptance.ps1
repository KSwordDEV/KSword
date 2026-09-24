# Run only in the isolated VMware Windows 10 guest, after KD and driver loading were verified.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Ctl,
      [Parameter(Mandatory)][string]$EvidenceDirectory,
      [Parameter(Mandatory)][ValidateSet(1,2,4,8)][int]$Vcpu,
      [ValidateRange(1,1000)][int]$Cycles=20,
      [ValidateRange(1,60)][int]$IdleSeconds=10,
      [ValidateRange(0,86400)][int]$SoakSeconds=0,
      [ValidateRange(10,600)][int]$CommandTimeoutSeconds=60,
      [switch]$NestedProbe,
      [switch]$GeneralResident)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($NestedProbe -and $GeneralResident) { throw 'Probe and general residency are mutually exclusive.' }
if ($NestedProbe -and $SoakSeconds -ne 0) { throw 'The bounded nested probe cannot run a residency soak.' }
$os=Get-CimInstance Win32_OperatingSystem
$machine=Get-CimInstance Win32_ComputerSystem
if ($os.Caption -notmatch 'Windows 10' -or [int]$os.BuildNumber -ge 22000 -or $machine.Manufacturer -notmatch 'VMware') {
    throw 'This acceptance runner is restricted to a VMware Windows 10 guest.'
}
if ([int]$machine.NumberOfLogicalProcessors -ne $Vcpu) { throw 'Unexpected vCPU topology.' }
$guard=Get-CimInstance -Namespace root/Microsoft/Windows/DeviceGuard -ClassName Win32_DeviceGuard
if ($guard.VirtualizationBasedSecurityStatus -eq 2) { throw 'Guest VBS is still running.' }
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a fresh evidence directory for each run.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$Ctl=(Resolve-Path -LiteralPath $Ctl).Path
$script:commandId=0; $script:uncertain=$false
$journal=Join-Path $EvidenceDirectory 'controls.jsonl'
function Record($Value) { $Value | ConvertTo-Json -Depth 12 -Compress | Add-Content -LiteralPath $journal -Encoding UTF8 }
function Hvm([string]$Verb) {
    $script:commandId++
    $stem=Join-Path $EvidenceDirectory ('{0:D5}-{1}' -f $script:commandId,$Verb)
    Record @{id=$script:commandId;phase='before';command=$Verb;utc=[DateTime]::UtcNow.ToString('o')}
    # Own both pipes and await EOF explicitly. Start-Process's file redirection
    # callbacks can still be pending when its returned Process reports exit.
    if ($Verb -notmatch '^[a-z-]+$') { throw 'Invalid internal control verb.' }
    $startInfo=New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName=$Ctl
    $startInfo.Arguments='--json '+$Verb
    $startInfo.UseShellExecute=$false
    $startInfo.CreateNoWindow=$true
    $startInfo.RedirectStandardOutput=$true
    $startInfo.RedirectStandardError=$true
    $startInfo.StandardOutputEncoding=[Text.Encoding]::UTF8
    $startInfo.StandardErrorEncoding=[Text.Encoding]::UTF8
    $process=New-Object System.Diagnostics.Process
    $process.StartInfo=$startInfo
    if (-not $process.Start()) { throw 'Cannot start control process.' }
    $stdout=$process.StandardOutput.ReadToEndAsync()
    $stderr=$process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit($CommandTimeoutSeconds*1000)) {
        $script:uncertain=$true
        Record @{id=$script:commandId;phase='timeout';pid=$process.Id;state='RollbackUnproven'}
        throw 'Control timed out. Process retained; use KD and preserve the VM/logs. No further controls will run.'
    }
    if (-not $stdout.Wait(5000) -or -not $stderr.Wait(5000)) {
        $script:uncertain=$true
        Record @{id=$script:commandId;phase='output-timeout';pid=$process.Id;state='RollbackUnproven'}
        throw 'Control exited but output did not reach EOF. No further controls will run.'
    }
    $exitCode=$process.ExitCode
    $output=$stdout.Result
    [IO.File]::WriteAllText("$stem.json",$output,[Text.Encoding]::UTF8)
    [IO.File]::WriteAllText("$stem.stderr.txt",$stderr.Result,[Text.Encoding]::UTF8)
    $process.Dispose()
    Record @{id=$script:commandId;phase='after';exitCode=$exitCode;utc=[DateTime]::UtcNow.ToString('o')}
    if ($exitCode -ne 0) { throw "Control $Verb failed ($exitCode); raw response retained." }
    if ([string]::IsNullOrWhiteSpace($output)) { throw "Control $Verb returned no JSON; evidence retained." }
    return $output | ConvertFrom-Json
}
function CheckSet($Query,[bool]$Active) {
    if ($Query.backend -ne 2 -or $Query.processorCount -ne $Vcpu -or @($Query.processors).Count -ne $Vcpu) { throw 'Wrong backend or incomplete processor set.' }
    $ids=@($Query.processors | ForEach-Object { "$($_.group):$($_.number)" } | Sort-Object -Unique)
    $expected=@(0..($Vcpu-1) | ForEach-Object { "0:$_" } | Sort-Object)
    if (($ids -join ',') -ne ($expected -join ',')) { throw 'Duplicate, missing or unexpected processor identity.' }
    foreach ($cpu in $Query.processors) {
        if (($cpu.stateNames -contains 'RESIDENT_ACTIVE') -ne $Active) { throw "Unacknowledged CPU $($cpu.group):$($cpu.number)." }
    }
    if ($Query.residentProcessorCount -ne $(if ($Active) {$Vcpu} else {0})) { throw 'Summary does not match per-CPU ownership.' }
    if ($Query.stateNames -contains 'ROLLBACK_REQUIRED' -or $Query.stateNames -contains 'FAULTED') { throw 'Driver retained a fault or rollback requirement.' }
}
function CheckNestedProbe($Metrics, $Previous) {
    if ($Metrics.version -ne 8 -or $Metrics.backend -ne 2 -or @($Metrics.svmProcessors).Count -ne $Vcpu) {
        throw 'Nested probe requires metrics v8 and a complete AMD CPU set.'
    }
    $seen=@{}
    foreach ($cpu in $Metrics.svmProcessors) {
        $id="$($cpu.group):$($cpu.number)"
        if ($cpu.group -ne 0 -or $cpu.number -lt 0 -or $cpu.number -ge $Vcpu -or $seen.ContainsKey($id)) {
            throw 'Duplicate, missing or unexpected nested probe CPU identity.'
        }
        $probe=$cpu.nestedProbe
        if ($probe.valid -ne 1 -or $probe.status -ne '0x00000000' -or
            $probe.sequence -le 0 -or ($probe.sequence % 2) -ne 0 -or
            ($Previous.ContainsKey($id) -and $probe.sequence -le $Previous[$id]) -or
            $probe.entries -ne 1 -or $probe.reflections -ne 1 -or $probe.faults -le 0 -or
            $probe.exit -ne '0x0000000000000072' -or $probe.marker -ne '0x000000004B534E31') {
            throw "CPU $id lacks a fresh, completed nested VMRUN/NPF/reflection/native-return result."
        }
        $seen[$id]=$probe.sequence
    }
    return $seen
}
function CheckGeneral($Metrics, [bool]$Active) {
    if ($Metrics.version -ne 8 -or $Metrics.backend -ne 2 -or @($Metrics.svmProcessors).Count -ne $Vcpu) {
        throw 'General residency requires metrics v8 and the complete AMD CPU set.'
    }
    $seen=@{}
    foreach ($cpu in $Metrics.svmProcessors) {
        $id="$($cpu.group):$($cpu.number)"
        if ($cpu.group -ne 0 -or $cpu.number -lt 0 -or $cpu.number -ge $Vcpu -or $seen.ContainsKey($id)) {
            throw 'Duplicate, missing or unexpected general CPU identity.'
        }
        $seen[$id]=$true
        $g=$cpu.general
        if ($g.valid -ne 1 -or [uint64]$g.sequence -eq 0 -or ([uint64]$g.sequence % 2) -ne 0 -or
            [uint64]$g.preparedEntries -eq 0 -or (-not $Active -and [uint64]$g.hardwareExits -eq 0) -or
            $cpu.failureStatus -ne '0x00000000') {
            throw "CPU $id lacks coherent, executed general-mode evidence."
        }
        $enabled=if ($Active) {1} else {0}
        if ($g.enabled -ne $enabled -or $g.initialized -ne $enabled) { throw "CPU $id general ownership mismatch." }
        if (-not $Active -and ($g.pending -ne 0 -or $g.nmiCaptured -ne 0 -or
            [uint64]$g.leaseToken -ne 0 -or [uint64]$g.armedToken -ne 0 -or [uint64]$g.retryToken -ne 0)) {
            throw "CPU $id retains general event or VMCB ownership."
        }
    }
}
$metadata=@{os=$os.Caption;build=$os.BuildNumber;bootId=$os.LastBootUpTime.ToUniversalTime().ToString('o');
    cpuCount=$Vcpu;cycles=$Cycles;idleSeconds=$IdleSeconds;soakSeconds=$SoakSeconds;ctlHash=(Get-FileHash $Ctl).Hash;hardwareResult='NotRun';
    innerOperatingSystemTested=$false;
    kind=$(if ($NestedProbe) {'bounded-svm-nested-probe'} elseif ($GeneralResident) {'general-svm-resident-smoke'} else {'resident-acceptance'})}
$metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'guest.json') -Encoding UTF8
try {
    $initial=Hvm status
    if ($initial.residentProcessorCount -ne 0 -or $initial.preparedProcessorCount -ne 0) { throw 'Start with a released, inactive driver.' }
    if ($NestedProbe) {
        Hvm prepare-svm-probe | Out-Null
        $prepared=Hvm status
        CheckSet $prepared $false
        $epoch=$prepared.powerGeneration
        $sequences=@{}
        for ($cycle=1; $cycle -le $Cycles; $cycle++) {
            Hvm self-test-svm-nested | Out-Null
            $tested=Hvm status
            CheckSet $tested $false
            if ($tested.selfTestPassedProcessorCount -ne $Vcpu -or $tested.powerGeneration -ne $epoch) {
                throw 'Nested probe did not complete on the prepared CPU/power generation.'
            }
            $sequences=CheckNestedProbe (Hvm metrics) $sequences
            Write-Host ("Nested probe passed: {0}/{1}, vCPU={2}" -f $cycle,$Cycles,$Vcpu)
        }
        Hvm teardown | Out-Null
        $released=Hvm status
        if ($released.preparedProcessorCount -ne 0 -or $released.residentProcessorCount -ne 0) { throw 'Nested probe resources remain owned.' }
        Record @{phase='complete';result='PASS';cycles=$Cycles;kind=$metadata.kind}
        $metadata.hardwareResult='PASS'
        $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'guest.json') -Encoding UTF8
        [pscustomobject]@{result='PASS';kind=$metadata.kind;vcpu=$Vcpu;cycles=$Cycles;
            innerOperatingSystemTested=$false;evidence=$EvidenceDirectory} | ConvertTo-Json
        return
    }
    $prepareVerb=if ($GeneralResident) {'prepare-svm-general'} else {'prepare'}
    $residentVerb=if ($GeneralResident) {'resident-svm-general'} else {'resident'}
    Hvm $prepareVerb | Out-Null
    $prepared=Hvm status
    CheckSet $prepared $false
    Hvm self-test | Out-Null
    $tested=Hvm status
    if ($tested.selfTestPassedProcessorCount -ne $Vcpu) { throw 'Incomplete real SVM self-test.' }
    $epoch=$tested.powerGeneration
    Hvm metrics | Out-Null
    for ($cycle=1; $cycle -le $Cycles; $cycle++) {
        Hvm $residentVerb | Out-Null
        $active=Hvm status
        CheckSet $active $true
        if ($GeneralResident) { CheckGeneral (Hvm metrics) $true }
        if ($active.powerGeneration -ne $epoch) { throw 'Power/topology generation changed.' }
        if ($cycle -eq 1) {
            # A tight CPUID-heavy loop can miss masked timer interrupts. Allow idle,
            # then require timer wakeup and a fresh complete resident CPU snapshot.
            Record @{phase='idle-before';seconds=$IdleSeconds;utc=[DateTime]::UtcNow.ToString('o')}
            Start-Sleep -Seconds $IdleSeconds
            $awake=Hvm status
            CheckSet $awake $true
            if ($awake.powerGeneration -ne $epoch) { throw 'Idle wake crossed a power/topology generation.' }
            Record @{phase='idle-after';utc=[DateTime]::UtcNow.ToString('o');result='PASS'}
        }
        Hvm stop | Out-Null
        CheckSet (Hvm status) $false
        if ($GeneralResident) { CheckGeneral (Hvm metrics) $false }
        # Repeated stop is part of the public idempotency contract.
        Hvm stop | Out-Null
        Hvm metrics | Out-Null
        if ($cycle -eq 1 -or $cycle % 25 -eq 0 -or $cycle -eq $Cycles) {
            Write-Host ("Cycles passed: {0}/{1}, vCPU={2}" -f $cycle,$Cycles,$Vcpu)
        }
    }
    if ($SoakSeconds -gt 0) {
        Hvm $residentVerb | Out-Null
        . (Join-Path $PSScriptRoot 'GuestWorkload.ps1')
        [KswordLabWorkload]::Start($Vcpu,$EvidenceDirectory)
        $lastProgress=New-Object long[] $Vcpu
        $deadline=[DateTime]::UtcNow.AddSeconds($SoakSeconds)
        $nextProgress=[DateTime]::UtcNow.AddMinutes(5)
        Write-Host ("Soak started: {0} seconds, {1} pinned workers. Evidence: {2}" -f $SoakSeconds,$Vcpu,$EvidenceDirectory)
        try {
            while ([DateTime]::UtcNow -lt $deadline) {
                Start-Sleep -Seconds ([Math]::Min(10,[Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalSeconds)))
                $active=Hvm status
                CheckSet $active $true
                if ($GeneralResident) { CheckGeneral (Hvm metrics) $true }
                if ($active.powerGeneration -ne $epoch) { throw 'Soak crossed a power/topology generation.' }
                $progress=@([KswordLabWorkload]::Progress())
                Record @{phase='workload';progress=$progress;errors=@([KswordLabWorkload]::Errors())}
                for ($cpu=0; $cpu -lt $Vcpu; $cpu++) {
                    if ($progress[$cpu] -le $lastProgress[$cpu]) { throw "Worker $cpu made no progress." }
                }
                $lastProgress=$progress
                if ([KswordLabWorkload]::Errors().Length) { throw 'Workload integrity failure.' }
                Hvm metrics | Out-Null
                if ([DateTime]::UtcNow -ge $nextProgress) {
                    Write-Host ("Soak healthy; remaining seconds: {0}; per-CPU progress: {1}" -f
                        [Math]::Max(0,[int]($deadline-[DateTime]::UtcNow).TotalSeconds),($progress -join ','))
                    $nextProgress=[DateTime]::UtcNow.AddMinutes(5)
                }
            }
        } finally { [KswordLabWorkload]::Stop() }
        if ([KswordLabWorkload]::Errors().Length) { throw 'Workload reported a failure while stopping.' }
        Hvm stop | Out-Null
        CheckSet (Hvm status) $false
        if ($GeneralResident) { CheckGeneral (Hvm metrics) $false }
    }
    Hvm teardown | Out-Null
    $released=Hvm status
    if ($released.preparedProcessorCount -ne 0 -or $released.residentProcessorCount -ne 0) { throw 'Resources still owned after teardown.' }
    Record @{phase='complete';result='PASS';cycles=$Cycles;soakSeconds=$SoakSeconds}
    $metadata.hardwareResult='PASS'
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $EvidenceDirectory 'guest.json') -Encoding UTF8
    [pscustomobject]@{result='PASS';kind=$metadata.kind;innerOperatingSystemTested=$false;
        vcpu=$Vcpu;cycles=$Cycles;idleSeconds=$IdleSeconds;soakSeconds=$SoakSeconds;
        preparedProcessorCount=$released.preparedProcessorCount;residentProcessorCount=$released.residentProcessorCount;
        evidence=$EvidenceDirectory} | ConvertTo-Json
} catch {
    # No speculative teardown after timeout/fault: preserve diagnostics and hardware ownership.
    Record @{phase='failed';error=$_.Exception.Message;uncertain=$script:uncertain;result='FAIL'}
    throw
}
