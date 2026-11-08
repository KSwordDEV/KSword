param(
 [Parameter(Mandatory=$true)][string]$Cli,
 [Parameter(Mandatory=$true)][string]$Fixture64,
 [Parameter(Mandatory=$true)][string]$Fixture32,
 [Parameter(Mandatory=$true)][string]$ReportRoot,
 [Parameter(Mandatory=$true)][string]$ExpectedComputerName
)
$ErrorActionPreference='Stop'
if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7' -or $ExpectedComputerName -ne 'DESKTOP-D2161R7'){throw 'Wrong guest'}
if(Test-Path -LiteralPath $ReportRoot){throw 'Report path exists'}
New-Item -ItemType Directory -Path $ReportRoot | Out-Null
$checks=0
function Check([bool]$value,[string]$message){if(!$value){throw $message};$script:checks++;Write-Output "PASS $message"}
function Quote([string]$v){if($v -notmatch '[\s"]'){return $v};$v=[regex]::Replace($v,'(\\*)"','$1$1\"');$v=[regex]::Replace($v,'(\\+)$','$1$1');return '"'+$v+'"'}
$categories=@(
 @{name='memory';id=8;api='VirtualAlloc';returnKind='nonzero';extra='GetProcessWorkingSetSize';extraReturn='one'},
 @{name='thread';id=9;api='OpenThread';returnKind='nonzero';extra='GetThreadPriorityBoost';extraReturn='one'},
 @{name='service';id=10;api='OpenSCManagerW';returnKind='nonzero';extra='QueryServiceStatus';extraReturn='zero'},
 @{name='security';id=11;api='GetTokenInformation';returnKind='one';extra='GetSecurityDescriptorDacl';extraReturn='one'},
 @{name='crypto';id=12;api='CryptAcquireContextW';returnKind='one';extra='BCryptGetProperty';extraReturn='zero'},
 @{name='com';id=13;api='CoInitializeEx';returnKind='zero';extra='CoCreateGuid';extraReturn='zero'},
 @{name='window';id=14;api='GetForegroundWindow';returnKind='any';extra='GetWindowRect';extraReturn='one'}
)
$signaturePath=Join-Path (Split-Path -Parent $Cli) 'profiles\api_monitor_definitions.json'
$sha=(Get-FileHash -LiteralPath $signaturePath -Algorithm SHA256).Hash.ToLowerInvariant()
foreach($arch in @('x64','x86')){
 $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
 foreach($mode in @('memory','thread','service','security','crypto','com','window','inherit')){
  $root=Join-Path $ReportRoot "$arch-$mode";New-Item -ItemType Directory -Path $root | Out-Null
  $target=Start-Process -FilePath $fixture -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
  try {
   for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
   Check (!$target.HasExited -and (Test-Path -LiteralPath (Join-Path $root 'ready'))) "$arch $mode fixture ready"
   $identity=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
   Check ($identity -and $identity.ExecutablePath -ieq $fixture) "$arch $mode fixture identity"
   $chosen=if($mode -eq 'inherit'){@($categories | Where-Object {$_.name -in @('memory','security')})}else{@($categories | Where-Object {$_.name -eq $mode})}
   $list=($chosen | ForEach-Object {$_.name}) -join ','
   $durationMs=if($mode -eq 'inherit'){15000}else{5000}
   $args=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms',[string]$durationMs,'--categories',$list,'--limit','30000','--signatures','1','--timeline','1','--confirm','--json')
   if($mode -eq 'inherit'){$args+=@('--auto-children','1')}
   $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments=($args | ForEach-Object {Quote $_}) -join ' '
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
   $controller=[Diagnostics.Process]::Start($info);$out=$controller.StandardOutput.ReadToEndAsync();$err=$controller.StandardError.ReadToEndAsync()
   try {
    if($mode -eq 'inherit'){Start-Sleep -Seconds 10;[IO.File]::WriteAllText((Join-Path $root 'spawn'),'spawn')}
    if(!$controller.WaitForExit(90000)){$controller.Kill();$controller.WaitForExit();throw "$arch $mode controller timeout"}
    $raw=$out.GetAwaiter().GetResult();$errorText=$err.GetAwaiter().GetResult();$exit=$controller.ExitCode
   } finally {$controller.Dispose()}
   [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$errorText,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText((Join-Path $root 'capture.exit.txt'),[string]$exit)
   Check (@(0,6) -contains $exit) "$arch $mode capture exit=$exit"
   $data=($raw | ConvertFrom-Json).data
   Check ($data.completedRequestedInterval -and !$data.cancelled) "$arch $mode completed interval"
   Check ($data.options.enable_process -eq '0') "$arch $mode process disabled"
   foreach($category in $categories){$expected=if($category.name -in $chosen.name){'1'}else{'0'};Check ($data.options.('enable_'+$category.name) -eq $expected) "$arch $mode option $($category.name)=$expected"}
   Check ($data.cleanupComplete -and $data.stopWritten) "$arch $mode cleanup"
   Check ([uint64]$data.invalidPacketCount -eq 0 -and [uint64]$data.bufferDroppedCount -eq 0) "$arch $mode no packet/buffer loss"
   $processes=@($data.processes);Check ($processes.Count -ge $(if($mode -eq 'inherit'){2}else{1})) "$arch $mode process count"
   Check (@($processes | Where-Object {!$_.hooksInstalled -or !$_.hooksRemoved -or !$_.coverageComplete -or $_.coverageStale -or [uint64]$_.agentDroppedCount -ne 0}).Count -eq 0) "$arch $mode process coverage, removal and loss"
   $events=@($data.events | Where-Object {$_.eventKind -eq 0 -and $_.category -ne 6})
   $ids=@($chosen | ForEach-Object {$_.id})
   Check (@($events | Where-Object {$_.category -notin $ids}).Count -eq 0) "$arch $mode category isolation"
   foreach($p in $processes){
    foreach($category in $chosen){
     $calls=@($events | Where-Object {$_.pid -eq $p.pid -and $_.category -eq $category.id -and $_.api -ceq $category.api})
     Check ($calls.Count -gt 0) "$arch $mode PID $($p.pid) $($category.api) observed"
     Check (@($calls | Where-Object {$_.definitionSha256 -ieq $sha -and $_.declarationCatalogMatchesAgent -eq $true -and $_.returnValueAvailable}).Count -gt 0) "$arch $mode $($category.api) SHA and return marker"
     if($category.returnKind -eq 'one'){Check (@($calls | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 1}).Count -gt 0) "$arch $mode $($category.api) returned TRUE"}
     if($category.returnKind -eq 'zero'){Check (@($calls | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 0}).Count -gt 0) "$arch $mode $($category.api) returned S_OK"}
     if($category.returnKind -eq 'nonzero'){Check (@($calls | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -ne 0}).Count -gt 0) "$arch $mode $($category.api) returned handle"}
     Check (@($p.coverage | Where-Object {$_.api -ceq $category.api -and $_.state -in @(0,1,8) -and $_.definitionSha256 -ieq $sha}).Count -gt 0) "$arch $mode $($category.api) installed coverage SHA"
     $extra=@($events | Where-Object {$_.pid -eq $p.pid -and $_.category -eq $category.id -and $_.api -ceq $category.extra -and $_.returnValueAvailable -and $_.definitionSha256 -ieq $sha -and $_.declarationCatalogMatchesAgent -eq $true})
     Check ($extra.Count -gt 0) "$arch $mode PID $($p.pid) added $($category.extra) observed with return and SHA"
     $expectedReturn=if($category.extraReturn -eq 'one'){1}else{0}
     Check (@($extra | Where-Object {[Convert]::ToUInt64($_.returnValue,16) -eq $expectedReturn}).Count -gt 0) "$arch $mode added $($category.extra) return"
     Check (@($p.coverage | Where-Object {$_.api -ceq $category.extra -and $_.state -in @(0,1,8) -and $_.definitionSha256 -ieq $sha}).Count -gt 0) "$arch $mode added $($category.extra) coverage SHA"
    }
   }
   if($mode -eq 'inherit'){Check (Test-Path -LiteralPath (Join-Path $root 'child-ready')) "$arch child started"}
  } finally {
   [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
   if(!$target.WaitForExit(15000)){throw "$arch $mode fixture did not exit"}
   $target.Refresh();if($target.ExitCode -ne 0){throw "$arch $mode fixture exit $($target.ExitCode)"};$target.Dispose()
  }
 }
}
Write-Output "CATEGORY_GUEST_PASS checks=$checks"
