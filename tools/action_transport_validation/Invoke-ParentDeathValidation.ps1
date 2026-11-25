param(
    [string]$MSBuild = 'D:\Software\VS\MSBuild\Current\Bin\amd64\MSBuild.exe',
    [switch]$UseVerifiedBuild
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$logs = Join-Path $repo '.codex-build-logs\behavior-planning'
$runLog = Join-Path $logs 'action-analyze-parent-death-run.log'
$metadataPath = Join-Path $logs 'action-analyze-parent-death-metadata.json'
$exe = Join-Path $repo 'Ksword5.1\x64\Release\ActionTransportValidation.exe'
# 同一改动先增量构建并执行原有正常回归；不覆盖旧用例的通过标准。
if (!$UseVerifiedBuild) {
    & (Join-Path $PSScriptRoot 'Invoke-Validation.ps1') -MSBuild $MSBuild
}
$normalMetadata = Get-Content -LiteralPath (Join-Path $logs 'action-analyze-transport-metadata.json') -Raw | ConvertFrom-Json
if ($normalMetadata.result -ne 'PASS' -or $normalMetadata.buildExit -ne 0 -or $normalMetadata.runExit -ne 0) {
    throw 'Normal transport regression required.'
}
if ((Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash -ne $normalMetadata.sha256) { throw 'Verified artifact changed.' }
foreach ($sourceIdentity in $normalMetadata.sources) {
    if ((Get-FileHash -LiteralPath (Join-Path $repo $sourceIdentity.path) -Algorithm SHA256).Hash -ne $sourceIdentity.sha256) {
        throw "Verified source changed: $($sourceIdentity.path)"
    }
}
$lines = [Collections.Generic.List[string]]::new()
$passed = 0
$failed = 0
$result = 'FAIL'
$faultParent = $null
$faultChild = $null
$parentKilled = $false
$childExitedByJob = $false
$emergencyCleanup = $false
$childCreation = $null
$observedAliveMs = 0
$jobExitMs = $null
function Assert-ParentDeath([bool]$Condition, [string]$Name) {
    if ($Condition) {
        $script:passed++
        $line = "ASSERT PASS $Name"
    } else {
        $script:failed++
        $line = "ASSERT FAIL $Name"
    }
    $script:lines.Add($line)
    Write-Output $line
    if (!$Condition) { throw $Name }
}
try {
    $start = [Diagnostics.ProcessStartInfo]::new($exe)
    $start.Arguments = '--parent-kill-target'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $faultParent = [Diagnostics.Process]::Start($start)
    # 立即固定本次创建的原生句柄；不按进程名枚举和杀死任何其它实例。
    $null = $faultParent.Handle
    $stderr = $faultParent.StandardError.ReadToEndAsync()
    $deadline = [Diagnostics.Stopwatch]::StartNew()
    $readyMatch = $null
    while ($deadline.ElapsedMilliseconds -lt 6000) {
        $lineTask = $faultParent.StandardOutput.ReadLineAsync()
        $remaining = [int][Math]::Max(1, 6000 - $deadline.ElapsedMilliseconds)
        if (!$lineTask.Wait($remaining)) { throw 'Fault target readiness timed out.' }
        $line = $lineTask.GetAwaiter().GetResult()
        if ($null -eq $line) { throw 'Fault target exited before readiness.' }
        $lines.Add($line)
        if ($line -match '^FAULT_READY parent_pid=(\d+) child_pid=(\d+) child_creation=(\d+) declared_held=3$') {
            $readyMatch = @($Matches[1], $Matches[2], $Matches[3])
            break
        }
    }
    Assert-ParentDeath ($null -ne $readyMatch -and [int]$readyMatch[0] -eq $faultParent.Id) 'ready_matches_exact_created_fault_parent'
    $faultChild = [Diagnostics.Process]::GetProcessById([int]$readyMatch[1])
    $null = $faultChild.Handle
    $childCreation = $faultChild.StartTime.ToUniversalTime().ToFileTimeUtc()
    Assert-ParentDeath ($childCreation -eq [long]$readyMatch[2] -and
        [StringComparer]::OrdinalIgnoreCase.Equals($faultChild.MainModule.FileName, $exe)) 'child_handle_creation_and_image_match_reported_self_child'
    Assert-ParentDeath (!$faultParent.HasExited -and !$faultChild.HasExited) 'both_processes_alive_before_negative_control'
    # 子端自有 deadline 为 4500ms。冻结应用线程后，超过该期限仍不能自行清理。
    $aliveWatch = [Diagnostics.Stopwatch]::StartNew()
    $earlyExit = $faultChild.WaitForExit(5000)
    $observedAliveMs = $aliveWatch.ElapsedMilliseconds
    Assert-ParentDeath (!$earlyExit -and !$faultParent.HasExited) 'frozen_child_outlives_own_4500ms_user_mode_deadline_while_parent_alive'
    $killWatch = [Diagnostics.Stopwatch]::StartNew()
    $faultParent.Kill()
    $parentKilled = $true
    Assert-ParentDeath ($faultParent.WaitForExit(2000)) 'exact_fault_parent_terminated_without_graceful_cleanup'
    $childExitedByJob = $faultChild.WaitForExit(3000)
    $jobExitMs = $killWatch.ElapsedMilliseconds
    Assert-ParentDeath $childExitedByJob 'private_job_terminates_frozen_child_after_last_parent_handle_closes'
    # Job 终止的 ExitCode 可能为 0，不能据此反推正常恢复。
    $tail = $faultParent.StandardOutput.ReadToEnd()
    if ($tail) { $lines.Add($tail) }
    Assert-ParentDeath ($tail -notmatch '(?m)^CLEANUP ' -and $tail -notmatch '(?m)^RESULT=PASS') 'killed_parent_did_not_run_normal_release_and_cleanup'
    $result = 'PASS'
} catch {
    $lines.Add('ERROR ' + $_.Exception.Message)
    Write-Output ('ERROR ' + $_.Exception.Message)
} finally {
    # 只使用本次固定的精确句柄。失败时强制清理仍记失败，绝不算故障判据通过。
    foreach ($ownedProcess in @($faultParent, $faultChild)) {
        if ($null -ne $ownedProcess -and !$ownedProcess.HasExited) {
            $emergencyCleanup = $true
            $ownedProcess.Kill()
            $null = $ownedProcess.WaitForExit(3000)
        }
    }
    if ($null -ne $faultParent -and $faultParent.HasExited -and $null -ne $stderr) {
        $errorText = $stderr.GetAwaiter().GetResult()
        if ($errorText) { $lines.Add($errorText) }
    }
    $parentGone = $null -eq $faultParent -or $faultParent.HasExited
    $childGone = $null -eq $faultChild -or $faultChild.HasExited
    if ($emergencyCleanup -or !$parentGone -or !$childGone) { $result = 'FAIL' }
    $lines.Add("RESULT=$result assertionsPassed=$passed assertionsFailed=$failed emergencyCleanup=$emergencyCleanup")
    $lines | Set-Content -LiteralPath $runLog -Encoding utf8
    $metadata = [ordered]@{
        recordedAt = (Get-Date).ToUniversalTime().ToString('o')
        result = $result
        scope = 'Only exact self-created fixture parent and its private-job child; proves Job termination, not target resume or production owner-death recovery.'
        parentKillFaultInjectionTested = $parentKilled
        assertionsPassed = $passed
        assertionsFailed = $failed
        normalRegressionAssertions = $normalMetadata.assertionsPassed
        parentPid = if ($null -ne $faultParent) { $faultParent.Id } else { $null }
        childPid = if ($null -ne $faultChild) { $faultChild.Id } else { $null }
        childCreationFileTime = $childCreation
        childExitCode = if ($null -ne $faultChild -and $faultChild.HasExited) { $faultChild.ExitCode } else { $null }
        observedFrozenChildAliveMs = $observedAliveMs
        parentKillToChildExitMs = $jobExitMs
        childExitedByJobBeforeEmergencyCleanup = $childExitedByJob
        emergencyCleanup = $emergencyCleanup
        exactParentExited = $parentGone
        exactChildExited = $childGone
        executable = $exe
        sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash
        os = $normalMetadata.os
        sources = @('ActionTransportValidation.cpp', 'ActionTransportValidation.h', 'ActionTransportValidation.vcxproj', 'Invoke-Validation.ps1', 'Invoke-ParentDeathValidation.ps1') | ForEach-Object {
            $source = Join-Path $PSScriptRoot $_
            [ordered]@{ path = [IO.Path]::GetRelativePath($repo, $source); sha256 = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash }
        }
        configurationFilesCreated = 0
        runtimeCopiesCreated = 0
    }
    $metadata | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $metadataPath -Encoding utf8
    foreach ($ownedProcess in @($faultParent, $faultChild)) {
        if ($null -ne $ownedProcess) { $ownedProcess.Dispose() }
    }
}
if ($result -ne 'PASS') { throw "Parent-death validation failed; inspect $runLog" }
Write-Output "RESULT=PASS METADATA=$metadataPath"
