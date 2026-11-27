param([ValidateSet('Setup','Capture','ReadArchives','Cleanup')][string]$Phase)
$ErrorActionPreference='Stop'
$root='C:\KSwordValidation\ActionAnalyzeWfp'
Set-Location $root
$cli=Join-Path $root 'KswordCLI.exe'
function Save($name,$value) { $value | ConvertTo-Json -Depth 30 | Set-Content -Encoding UTF8 (Join-Path $root $name) }
function RunCli($name,[string[]]$arguments) {
    $psi=New-Object Diagnostics.ProcessStartInfo
    $psi.FileName=$cli; $psi.Arguments=$arguments -join ' '; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
    $p=[Diagnostics.Process]::Start($psi)
    $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
    if (!$p.WaitForExit(30000)) { throw "$name timed out; PID=$($p.Id)" }
    $rc=$p.ExitCode
    $stdout.Result | Set-Content -Encoding UTF8 "$root\$name.stdout.json"
    $stderr.Result | Set-Content -Encoding UTF8 "$root\$name.stderr.log"
    Save "$name.exit.json" @{exitCode=$rc;arguments=$arguments}
    if ($rc -ne 0) { throw "$name exit=$rc" }
    Get-Content -Raw "$root\$name.stdout.json" | ConvertFrom-Json
}
Start-Transcript "$root\$Phase.transcript.log" -Force
try {
    if ($Phase -eq 'Setup') {
        Save 'baseline.json' @{computer=$env:COMPUTERNAME;user=(whoami);os=(Get-CimInstance Win32_OperatingSystem | Select-Object Caption,BuildNumber);bcd=(& bcdedit /enum '{current}');secureBoot=(Confirm-SecureBootUEFI);existingServices=@(Get-CimInstance Win32_SystemDriver | Where-Object Name -like '*ksword*' | Select-Object Name,State,PathName);files=@(Get-FileHash "$root\KswordARK.sys","$cli","$root\MSVCP140.dll","$root\VCRUNTIME140.dll","$root\VCRUNTIME140_1.dll")}
        if ((Get-FileHash "$root\KswordARK.sys").Hash -ne '56C4FA626360D14F4DB0F4B4AB8DA63A48DE060102D1EF37AF88C7A09BC482DD') { throw 'Driver input hash mismatch' }
        if ((Get-FileHash $cli).Hash -ne '816BDA24663C8E19FB497096B613C807E0B53D51501DCB01FE8E41A8F4788A65') { throw 'CLI input hash mismatch' }
        $cert=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=KSword ActionAnalyze WFP VM Validation' -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256
        Save 'certificate.json' @{thumbprint=$cert.Thumbprint;subject=$cert.Subject}
        Export-Certificate -Cert $cert -FilePath "$root\validation.cer" | Out-Null
        Import-Certificate -FilePath "$root\validation.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        Import-Certificate -FilePath "$root\validation.cer" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
        & "$root\signtool.exe" sign /v /fd SHA256 /sm /s My /sha1 $cert.Thumbprint "$root\KswordARK.sys" 2>&1 | Out-File "$root\sign.log"
        if ($LASTEXITCODE) { throw "signtool exit=$LASTEXITCODE" }
        Save 'signed-driver.json' @{hash=(Get-FileHash "$root\KswordARK.sys").Hash;signature=(Get-AuthenticodeSignature "$root\KswordARK.sys" | Select-Object Status,StatusMessage)}
        & sc.exe create KSwordAAWfp type= kernel start= demand binPath= "$root\KswordARK.sys" 2>&1 | Out-File "$root\service-create.log"
        if ($LASTEXITCODE) { throw "service create exit=$LASTEXITCODE" }
        & sc.exe start KSwordAAWfp 2>&1 | Out-File "$root\service-start.log"
        $start=$LASTEXITCODE
        Save 'driver-loaded.json' @{startExit=$start;service=(Get-CimInstance Win32_SystemDriver -Filter "Name='KSwordAAWfp'" | Select-Object Name,State,Started,PathName)}
        if ($start) { throw "driver load failed exit=$start" }
        RunCli 'traffic-start' @('r0','traffic-start','--confirm','--json') | Out-Null
    } elseif ($Phase -eq 'Capture') {
        $fixture=Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"$root\Loopback.ps1",'-Role','Listener') -WindowStyle Hidden -PassThru -RedirectStandardOutput "$root\fixture.stdout.log" -RedirectStandardError "$root\fixture.stderr.log"
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        while (!(Test-Path "$root\state.json")) { if ($fixture.HasExited -or [DateTime]::UtcNow -gt $deadline) { throw 'Fixture readiness failed' }; Start-Sleep -Milliseconds 50 }
        $state=Get-Content -Raw "$root\state.json" | ConvertFrom-Json
        $psi=New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName=$cli; $psi.Arguments='analyze session'; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardInput=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
        $session=[Diagnostics.Process]::Start($psi)
        $session.StandardInput.WriteLine('project create C:/KSwordValidation/ActionAnalyzeWfp/project WFP-loopback')
        $session.StandardInput.WriteLine('sample create WFP-loopback')
        $session.StandardInput.WriteLine('quit'); $session.StandardInput.Close()
        $session.StandardOutput.ReadToEnd() | Set-Content -Encoding UTF8 "$root\project.stdout.log"
        $session.StandardError.ReadToEnd() | Set-Content -Encoding UTF8 "$root\project.stderr.log"
        $session.WaitForExit(); if ($session.ExitCode) { throw "project exit=$($session.ExitCode)" }
        $sample=(Get-ChildItem "$root\project\samples" -Directory | Select-Object -First 1).Name
        if (!$sample) { throw 'No sample created' }
        # Inbound transport owns the receiving socket: select our listener instance.
        $args=@('analyze','network-traffic','--project',"$root\project",'--sample',$sample,'--pid',"$($state.listenerPid)",'--create-time',"$($state.listenerCreationFileTime)",'--duration-ms','5000','--source','existing-wfp','--json')
        $psi=New-Object Diagnostics.ProcessStartInfo
        $psi.FileName=$cli; $psi.Arguments=$args -join ' '; $psi.UseShellExecute=$false; $psi.CreateNoWindow=$true; $psi.RedirectStandardOutput=$true; $psi.RedirectStandardError=$true
        $capture=[Diagnostics.Process]::Start($psi)
        $captureOut=$capture.StandardOutput.ReadToEndAsync(); $captureErr=$capture.StandardError.ReadToEndAsync()
        Save 'capture-command.json' @{arguments=$args;pid=$capture.Id;sample=$sample;marker=$state.marker}
        Start-Sleep -Milliseconds 1200
        if ($capture.HasExited) { throw 'Capture ended before marker release' }
        Set-Content -Encoding ASCII "$root\release.signal" 'release'
        if (!$capture.WaitForExit(15000)) { throw 'Capture timeout' }
        $captureOut.Result | Set-Content -Encoding UTF8 "$root\capture.stdout.json"
        $captureErr.Result | Set-Content -Encoding UTF8 "$root\capture.stderr.log"
        Save 'capture.exit.json' @{exitCode=$capture.ExitCode}
        $result=Get-Content -Raw "$root\capture.stdout.json" | ConvertFrom-Json
        if ($result.data) { $result=$result.data }
        if (!$result.sourceReady) { throw 'existing-wfp not ready' }
        if (!$result.packetCount) { throw 'existing-wfp packetCount=0' }
        $read=RunCli 'network-read' @('analyze','network-read','--project',"$root\project",'--sample',$sample,'--ordinal',"$($result.ordinal)",'--json')
        if ($read.data) { $read=$read.data }
        foreach ($row in $read.records) {
            RunCli "record-$($row.recordSequence)" @('analyze','network-read','--project',"$root\project",'--sample',$sample,'--ordinal',"$($result.ordinal)",'--record-sequence',"$($row.recordSequence)",'--json') | Out-Null
        }
        Save 'capture-completed.json' @{completed=$true;sample=$sample;ordinal=$result.ordinal;packetCount=$result.packetCount;captureExit=$capture.ExitCode}
    } elseif ($Phase -eq 'ReadArchives') {
        $sample=(Get-Content -Raw "$root\capture-command.json" | ConvertFrom-Json).sample
        foreach ($checkpoint in Get-ChildItem "$root\project\samples\$sample\checkpoints-network\*.json") {
            $ordinal=$checkpoint.BaseName
            $read=RunCli "network-read-$ordinal" @('analyze','network-read','--project',"$root\project",'--sample',$sample,'--ordinal',$ordinal,'--json')
            foreach ($row in $read.data.records) {
                RunCli "record-$ordinal-$($row.recordSequence)" @('analyze','network-read','--project',"$root\project",'--sample',$sample,'--ordinal',$ordinal,'--record-sequence',"$($row.recordSequence)",'--json') | Out-Null
            }
        }
    } else {
        Set-Content -Encoding ASCII "$root\stop.signal" 'stop'
        Start-Sleep -Seconds 2
        $owned=@(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*ActionAnalyzeWfp*' -and $_.Name -in @('powershell.exe','KswordCLI.exe') -and $_.ProcessId -ne $PID })
        foreach ($p in $owned) { Stop-Process -Id $p.ProcessId -ErrorAction SilentlyContinue }
        & $cli r0 traffic-stop --confirm --json 1> "$root\traffic-stop.stdout.json" 2> "$root\traffic-stop.stderr.log"
        $stopRc=$LASTEXITCODE
        & sc.exe stop KSwordAAWfp 2>&1 | Out-File "$root\service-stop.log"
        $serviceStop=$LASTEXITCODE
        & sc.exe delete KSwordAAWfp 2>&1 | Out-File "$root\service-delete.log"
        $serviceDelete=$LASTEXITCODE
        if (Test-Path "$root\certificate.json") {
            $thumb=(Get-Content -Raw "$root\certificate.json" | ConvertFrom-Json).thumbprint
            foreach ($store in @('My','Root','TrustedPublisher')) { $path="Cert:\LocalMachine\$store\$thumb"; if (Test-Path $path) { Remove-Item $path -Force } }
        }
        Save 'cleanup.json' @{trafficStopExit=$stopRc;serviceStopExit=$serviceStop;serviceDeleteExit=$serviceDelete;terminatedOwned=@($owned | Select-Object ProcessId,Name);remainingOwned=@(Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*ActionAnalyzeWfp*' -and $_.Name -in @('powershell.exe','KswordCLI.exe') -and $_.ProcessId -ne $PID } | Select-Object ProcessId,Name);remainingService=@(Get-CimInstance Win32_SystemDriver -Filter "Name='KSwordAAWfp'" | Select-Object Name,State)}
    }
} catch { Save "$Phase.failure.json" @{error=$_.Exception.Message;stack=$_.ScriptStackTrace}; throw } finally { Stop-Transcript }
