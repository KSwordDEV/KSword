param(
 [Parameter(Mandatory=$true)][string]$Cli,
 [Parameter(Mandatory=$true)][string]$Fixture64,
 [Parameter(Mandatory=$true)][string]$Fixture32,
 [Parameter(Mandatory=$true)][string]$ReportRoot
)
$ErrorActionPreference='Stop'
$Cli=(Resolve-Path -LiteralPath $Cli).Path
$ReportRoot=[IO.Path]::GetFullPath($ReportRoot)
New-Item -ItemType Directory -Path $ReportRoot -Force | Out-Null
$script:checks=0
function Assert($Condition,[string]$Message){if(!$Condition){throw $Message};$script:checks++;Write-Output "PASS $Message"}
function Quote-Argument([string]$Value){
 if($Value.Length -gt 0 -and $Value -notmatch '[\s"]'){return $Value}
 $escaped=[regex]::Replace($Value,'(\\*)"','$1$1\"')
 $escaped=[regex]::Replace($escaped,'(\\+)$','$1$1')
 return '"'+$escaped+'"'
}
function Invoke-Cli([string]$Name,[string[]]$Arguments,[int[]]$Expected=@(0)){
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli
 $info.Arguments=($Arguments|ForEach-Object {Quote-Argument $_}) -join ' '
 $info.UseShellExecute=$false;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
 $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
 $child=[Diagnostics.Process]::Start($info)
 $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
 if(!$child.WaitForExit(90000)){$child.Kill();$child.WaitForExit();throw "Owned CLI timed out: $Name"}
 $output=$stdout.GetAwaiter().GetResult();$errorOutput=$stderr.GetAwaiter().GetResult();$code=$child.ExitCode;$child.Dispose()
 [IO.File]::WriteAllText((Join-Path $ReportRoot ($Name+'.stderr.txt')),$errorOutput,[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText((Join-Path $ReportRoot ($Name+'.json')),$output,[Text.UTF8Encoding]::new($false))
 if($Expected -notcontains $code){throw "$Name exit=$code expected=$Expected output=$output"}
 return $output|ConvertFrom-Json
}
function Assert-Clean($Result){
 Assert ($Result.data.cleanupComplete -and $Result.data.stopWritten) 'Stop acknowledged for every owned participant'
 Assert ($Result.data.invalidPacketCount -eq '0') 'No malformed or foreign-session packet'
 foreach($process in $Result.data.processes){
  Assert ($process.hooksInstalled -and $process.hooksRemoved -and !$process.installFailed -and !$process.targetExited -and $process.pipeWin32Error -eq 0) "PID $($process.pid) installed/removed hooks and remains alive"
  Assert ($process.coverageComplete -and !$process.coverageStale -and @($process.coverage).Count -gt 0) "PID $($process.pid) complete ordered coverage"
 }
}
$help=(& $Cli help monitor api capture|Out-String)
Assert ($LASTEXITCODE -eq 0 -and $help.Contains('--auto-children') -and $help.Contains('--options-file')) 'Leaf help and options'
Assert ((& $Cli monitor api capture --help|Out-String) -eq $help) 'Inline help matches leaf'
foreach($bad in @(
 @('--pid','0','--confirm'),@('--pid','99'),@('--pid','99','--duration-ms','99','--confirm'),
 @('--pid','99','--raw','2','--confirm'),@('--pid','99','--categories','unknown','--confirm'),
 @('--pid','99','--limit','0','--confirm'),@('--pid','99','--stop-timeout-ms','999','--confirm'),
 @('--pid','99','--raw-modules',"bad`npipe_name=foreign",'--confirm')
)){
 $value=Invoke-Cli ('invalid-'+$script:checks) (@('monitor','api','capture')+$bad+@('--json')) @(1)
 Assert ($value.status -eq 'failed') 'Invalid input rejected before injection'
}
$missing=Invoke-Cli 'missing-pid' @('monitor','api','capture','--pid','4294967295','--confirm','--json') @(3)
Assert (!$missing.data.configPublished -and $missing.data.cleanupComplete) 'Missing target fails without publishing configuration'
$targets=@()
try{
 foreach($arch in @('x64','x86')){
  $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
  $root=Join-Path $ReportRoot $arch;New-Item -ItemType Directory -Path $root -Force|Out-Null
  $target=Start-Process -FilePath $fixture -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
  $targets+=@{Process=$target;Root=$root}
  for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
  Assert (!$target.HasExited -and (Test-Path -LiteralPath (Join-Path $root 'ready'))) "$arch fixture ready"
  $base=@('monitor','api','capture','--pid',$target.Id.ToString(),'--duration-ms','1600','--categories','file,registry','--limit','10000','--confirm','--json')
  $result=Invoke-Cli ($arch+'-capture') $base @(0,6);Assert-Clean $result
  Assert ($result.data.completedRequestedInterval -and @($result.data.events|Where-Object {$_.api -eq 'WriteFile' -and $_.pid -eq $target.Id}).Count -gt 0) "$arch real WriteFile event"
  Assert ($result.data.agentPath.EndsWith(('APIMonitor_'+$arch+'.dll'),[StringComparison]::OrdinalIgnoreCase)) "$arch matching Agent chosen"
  $again=Invoke-Cli ($arch+'-repeat') $base @(0,6);Assert-Clean $again
  Assert ($again.data.reusedResident -and $again.data.sessionId -ne $result.data.sessionId) "$arch resident Agent accepts fresh session"
  $limited=Invoke-Cli ($arch+'-limited') @('monitor','api','capture','--pid',$target.Id.ToString(),'--duration-ms','500','--categories','file','--limit','1','--confirm','--json') @(6)
  Assert-Clean $limited
  Assert ($limited.data.returnedCount -eq '1' -and [uint64]$limited.data.bufferDroppedCount -gt 0) "$arch truncation returns partial with loss evidence"
  $ini=Join-Path $root 'options.ini'
  [IO.File]::WriteAllText($ini,"[monitor]`r`nenable_file=1`r`nenable_registry=0`r`nenable_network=0`r`nenable_process=0`r`nenable_loader=0`r`nenable_raw_fallback=1`r`nraw_modules=version.dll`r`npipe_name=foreign`r`nstop_flag_path=foreign`r`nsession_id=foreign`r`n",[Text.Encoding]::Unicode)
  $raw=Invoke-Cli ($arch+'-options') @('monitor','api','capture','--pid',$target.Id.ToString(),'--duration-ms','500','--options-file',$ini,'--confirm','--json') @(0,6);Assert-Clean $raw
  Assert ($raw.data.sessionId -ne 'foreign' -and !$raw.data.options.PSObject.Properties['pipe_name'] -and $raw.data.options.enable_raw_fallback -eq '1') "$arch imports business options without controller override"
  $entry=@($raw.data.events|Where-Object {$_.resultKind -eq 1 -and $_.api -eq 'GetFileVersionInfoSizeW'})
  Assert ($entry.Count -gt 0 -and $null -eq $entry[0].resultCode) "$arch real Raw entry preserves unknown return value"
  if($arch -eq 'x64'){
   $cancelPath=Join-Path $ReportRoot 'cancel.json'
   & $Fixture64 --cancel-controller $Cli $target.Id.ToString() $cancelPath
   Assert ($LASTEXITCODE -eq 0) 'CTRL_BREAK delivered to isolated owned CLI console'
   $cancelled=Get-Content -LiteralPath $cancelPath -Raw -Encoding UTF8|ConvertFrom-Json
   Assert-Clean $cancelled
   Assert ($cancelled.status -eq 'partial' -and $cancelled.data.cancelled -and !$cancelled.data.completedRequestedInterval) 'Cancellation retains partial evidence and confirms hook removal'
  }
 }
 # Root uses the opposite-bitness executable for its child; both must be
 # discovered, drained and stopped through the same authenticated broker.
 $root=Join-Path $ReportRoot 'children';New-Item -ItemType Directory -Path $root -Force|Out-Null
 $target=Start-Process -FilePath $Fixture64 -ArgumentList @(('"'+$root+'"'),('"'+$Fixture32+'"')) -WindowStyle Hidden -PassThru
 $targets+=@{Process=$target;Root=$root}
 $out=Join-Path $ReportRoot 'children.stdout.json';$err=Join-Path $ReportRoot 'children.stderr.txt'
 $args='monitor api capture --pid '+$target.Id+' --duration-ms 6000 --categories file,process --auto-children 1 --limit 20000 --confirm --json'
 $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments=$args;$info.UseShellExecute=$false
 $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true;$info.CreateNoWindow=$true
 $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
 $controller=[Diagnostics.Process]::Start($info)
 $stdout=$controller.StandardOutput.ReadToEndAsync();$stderr=$controller.StandardError.ReadToEndAsync()
 Start-Sleep -Seconds 2
 $busy=Invoke-Cli 'lease-busy' @('monitor','api','capture','--pid',$target.Id.ToString(),'--confirm','--json') @(3)
 Assert (!$busy.data.configPublished -and ($busy.diagnostics -join ' ').Contains('lease unavailable')) 'Concurrent capture refused without replacing active configuration'
 [IO.File]::WriteAllText((Join-Path $root 'spawn'),'spawn')
 if(!$controller.WaitForExit(60000)){throw 'Child capture timed out'}
 $controllerCode=$controller.ExitCode
 [IO.File]::WriteAllText($out,$stdout.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
 [IO.File]::WriteAllText($err,$stderr.GetAwaiter().GetResult(),[Text.UTF8Encoding]::new($false))
 $controller.Dispose();Assert (@(0,6) -contains $controllerCode) 'Child controller exit status'
 $children=Get-Content -LiteralPath $out -Raw -Encoding UTF8|ConvertFrom-Json
 Assert-Clean $children
 Assert (@($children.data.processes).Count -eq 2 -and @($children.data.events|Where-Object {$_.pid -ne $target.Id -and $_.api -eq 'WriteFile'}).Count -gt 0) 'x64 root and x86 child both produced events'
 # A target's normal exit ends the requested interval early. Preserve this as
 # partial and do not invent a stop-marker write after the process has exited.
 $root=Join-Path $ReportRoot 'exit';New-Item -ItemType Directory -Path $root -Force|Out-Null
 $target=Start-Process -FilePath $Fixture64 -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
 $targets+=@{Process=$target;Root=$root};$null=$target.HasExited
 $info.Arguments='monitor api capture --pid '+$target.Id+' --duration-ms 30000 --categories file --limit 20000 --confirm --json'
 $controller=[Diagnostics.Process]::Start($info)
 $stdout=$controller.StandardOutput.ReadToEndAsync();$stderr=$controller.StandardError.ReadToEndAsync()
 Start-Sleep -Seconds 2;[IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
 if(!$controller.WaitForExit(45000)){throw 'Target-exit capture timed out'}
 $controllerCode=$controller.ExitCode;$output=$stdout.GetAwaiter().GetResult()
 [IO.File]::WriteAllText((Join-Path $ReportRoot 'target-exit.json'),$output,[Text.UTF8Encoding]::new($false))
 $errorOutput=$stderr.GetAwaiter().GetResult();$controller.Dispose()
 $exited=$output|ConvertFrom-Json
 Assert ($controllerCode -eq 6 -and $exited.data.processes[0].targetExited -and $exited.data.cleanupComplete -and !$exited.data.completedRequestedInterval -and !$exited.data.stopWritten) 'Target exit returns partial without a fictitious stop-marker write'
}finally{
 foreach($item in $targets){
  [IO.File]::WriteAllText((Join-Path $item.Root 'stop'),'stop')
  if(!$item.Process.WaitForExit(15000)){throw "Owned fixture did not stop: $($item.Process.Id)"}
  $item.Process.Refresh();Assert ($item.Process.ExitCode -eq 0) "Owned fixture $($item.Process.Id) exited normally after hook removal"
 }
}
[pscustomobject]@{success=$true;checks=$script:checks;cliSha256=(Get-FileHash -LiteralPath $Cli).Hash;reportRoot=$ReportRoot}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $ReportRoot 'summary.json') -Encoding UTF8
Write-Output "CLI_API_MONITOR_PASS checks=$script:checks"
