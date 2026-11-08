param(
 [Parameter(Mandatory=$true)][string]$Cli,
 [Parameter(Mandatory=$true)][string]$Fixture64,
 [Parameter(Mandatory=$true)][string]$Fixture32,
 [Parameter(Mandatory=$true)][string]$ReportRoot,
 [Parameter(Mandatory=$true)][string]$ExpectedComputerName
)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7' -or $ExpectedComputerName -ne 'DESKTOP-D2161R7'){throw 'Wrong guest'}
foreach($file in @($Cli,$Fixture64,$Fixture32,(Join-Path (Split-Path -Parent $Cli) 'profiles\api_monitor_definitions.json'))){
 if(!(Test-Path -LiteralPath $file -PathType Leaf)){throw "Missing input: $file"}
}
if(Test-Path -LiteralPath $ReportRoot){throw 'Report path exists'}
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
function Check([bool]$value,[string]$message){if(!$value){throw $message};Write-Output "PASS $message"}
function Quote([string]$v){if($v -notmatch '[\s"]'){return $v};$v=[regex]::Replace($v,'(\\*)"','$1$1\"');$v=[regex]::Replace($v,'(\\+)$','$1$1');return '"'+$v+'"'}
$groups=@(
 @{name='window';categories='window,gui'},
 @{name='memory-thread';categories='memory,thread,process'},
 @{name='service-security';categories='service,security,crypto,com'},
 @{name='gui-objects';categories='gui'},
 @{name='gui-drawing';categories='gui'}
)
$failures=[Collections.Generic.List[string]]::new()
foreach($arch in @('x64','x86')){
 $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
 foreach($group in $groups){
  $root=Join-Path $ReportRoot "$arch-$($group.name)";New-Item -ItemType Directory -Path $root | Out-Null
  $target=$null
  try {
   $target=Start-Process -FilePath $fixture -ArgumentList ((Quote $root)+' '+(Quote $group.name)) -WindowStyle Hidden -PassThru
   for($i=0;$i -lt 600 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){
    $target.Refresh();if($target.HasExited){break};Start-Sleep -Milliseconds 100
   }
   $target.Refresh();Check (!$target.HasExited -and (Test-Path -LiteralPath (Join-Path $root 'ready'))) "$arch $($group.name) fixture ready"
   $identity=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
   Check ($identity -and $identity.ExecutablePath -ieq $fixture) "$arch $($group.name) fixture identity"
   $args=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','8000','--categories',$group.categories,
    '--raw','0','--limit','100000','--signatures','1','--confirm','--json')
   $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments=($args | ForEach-Object {Quote $_}) -join ' '
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
   $controller=[Diagnostics.Process]::Start($info);$stdout=$controller.StandardOutput.ReadToEndAsync();$stderr=$controller.StandardError.ReadToEndAsync()
   try {
    [IO.File]::WriteAllText((Join-Path $root 'go'),'go')
    if(!$controller.WaitForExit(120000)){$controller.Kill();$controller.WaitForExit();throw "$arch $($group.name) controller timeout"}
    $raw=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult();$exit=$controller.ExitCode
   } finally {$controller.Dispose()}
   [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$errorText,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText((Join-Path $root 'capture.exit.txt'),[string]$exit)
   Check (@(0,6) -contains $exit) "$arch $($group.name) capture exit=$exit"
   $data=($raw | ConvertFrom-Json).data
   Check ($data -and $data.completedRequestedInterval -and !$data.cancelled) "$arch $($group.name) interval complete"
   Check ($data.cleanupComplete -and $data.stopWritten) "$arch $($group.name) cleanup confirmed"
   Check ([uint64]$data.invalidPacketCount -eq 0 -and [uint64]$data.bufferDroppedCount -eq 0) "$arch $($group.name) no packet or buffer loss"
   $processes=@($data.processes)
   Check ($processes.Count -eq 1 -and $processes[0].pid -eq $target.Id) "$arch $($group.name) owned process capture"
   Check ($processes[0].hooksInstalled -and $processes[0].hooksRemoved -and $processes[0].coverageComplete -and !$processes[0].coverageStale -and [uint64]$processes[0].agentDroppedCount -eq 0 -and [uint32]$processes[0].pipeWin32Error -eq 0) "$arch $($group.name) coverage, removal and no Agent loss"
  } catch {
   $message="$arch $($group.name): $($_.Exception.Message)"
   $failures.Add($message);[IO.File]::WriteAllText((Join-Path $root 'failure.txt'),$message,[Text.UTF8Encoding]::new($false));Write-Warning $message
  } finally {
   if($target){
    [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
    if(!$target.WaitForExit(30000)){
     $message="$arch $($group.name): owned fixture failed to stop";$failures.Add($message);Write-Warning $message
     $target.Kill();$target.WaitForExit()
    } else {
     $target.Refresh();if($target.ExitCode -ne 0){$message="$arch $($group.name): fixture exited $($target.ExitCode)";$failures.Add($message);Write-Warning $message}
    }
    $target.Dispose()
   }
   if(!(Test-Path -LiteralPath (Join-Path $root 'trace.tsv') -PathType Leaf)){$message="$arch $($group.name): trace.tsv missing";$failures.Add($message);Write-Warning $message}
  }
 }
}
if($failures.Count){$failures | Set-Content -LiteralPath (Join-Path $ReportRoot 'failures.txt') -Encoding UTF8;throw "Per-API collection failed in $($failures.Count) checks"}
Write-Output 'PER_API_GUEST_PASS'
