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
$cases=@(
 @{name='process-raw';category='process';raw='1';gui=$false},
 @{name='window-raw';category='window';raw='1';gui=$false},
 @{name='gui-typed';category='gui';raw='0';gui=$true},
 @{name='gui-raw';category='gui';raw='1';gui=$true}
)
foreach($arch in @('x64','x86')){
 $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
 foreach($case in $cases){
  $root=Join-Path $ReportRoot "$arch-$($case.name)";New-Item -ItemType Directory -Path $root | Out-Null
  $target=Start-Process -FilePath $fixture -ArgumentList (Quote $root) -WindowStyle Hidden -PassThru
  try{
   for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 100}
   Check (Test-Path -LiteralPath (Join-Path $root 'ready')) "$arch $($case.name) fixture ready"
   $identity=Get-CimInstance Win32_Process -Filter "ProcessId=$($target.Id)"
   Check ($identity.ExecutablePath -ieq $fixture) "$arch owned target identity"
   $args=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','3000','--categories',$case.category,
    '--raw',$case.raw,'--raw-modules','gdi32.dll;gdi32full.dll','--limit','100000','--startup-timeout-ms','120000','--confirm','--json')
   $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments=($args | ForEach-Object {Quote $_}) -join ' '
   $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
   $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
   $controller=[Diagnostics.Process]::Start($info);$out=$controller.StandardOutput.ReadToEndAsync();$err=$controller.StandardError.ReadToEndAsync()
   try{
    if(!$controller.WaitForExit(180000)){$controller.Kill();$controller.WaitForExit();throw 'Owned controller timeout'}
    $raw=$out.GetAwaiter().GetResult();$errorText=$err.GetAwaiter().GetResult();$exit=$controller.ExitCode
   }finally{$controller.Dispose()}
   [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
   [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$errorText)
   [IO.File]::WriteAllText((Join-Path $root 'capture.exit.txt'),[string]$exit)
   Check (@(0,6) -contains $exit) "$arch $($case.name) capture exit=$exit"
   $data=($raw | ConvertFrom-Json).data
   Check ($data.completedRequestedInterval -and $data.cleanupComplete -and $data.stopWritten -and !$data.cancelled) "$arch $($case.name) interval and cleanup"
   Check ([uint64]$data.invalidPacketCount -eq 0 -and [uint64]$data.bufferDroppedCount -eq 0) "$arch $($case.name) no packet loss"
   $processes=@($data.processes)
   Check ($processes.Count -eq 1 -and $processes[0].hooksInstalled -and $processes[0].hooksRemoved -and $processes[0].coverageComplete -and !$processes[0].coverageStale -and [uint64]$processes[0].agentDroppedCount -eq 0) "$arch $($case.name) complete coverage and stop"
   $events=@($data.events | Where-Object {$_.eventKind -eq 0})
   $graphics=@($events | Where-Object {$_.module -match '^gdi32(full)?(\.dll)?$' -or $_.category -eq 15})
   $rawQueries=@($graphics | Where-Object {$_.api -in @('GetBkMode','GetMapMode','GetPolyFillMode','GetROP2')})
   if(!$case.gui){
    Check ($graphics.Count -eq 0) "$arch $($case.name) zero GDI/GUI events while GUI disabled"
    $disabled=@($processes[0].coverage | Where-Object {$_.module -ieq 'Gdi32.dll' -and $_.api -eq 'BitBlt' -and $_.state -eq 2})
    $rawDisabled=@($processes[0].coverage | Where-Object {$_.module -ieq 'gdi32.dll' -and $_.api -eq 'GetBkMode' -and $_.hookKind -eq 1 -and $_.state -eq 2})
    Check ($disabled.Count -gt 0 -and $rawDisabled.Count -gt 0) "$arch $($case.name) strong and Raw category-disabled coverage"
   }else{
    Check (@($graphics | Where-Object {$_.api -eq 'BitBlt' -and $_.category -eq 15 -and $_.returnValueAvailable -and $_.durationAvailable}).Count -gt 0) "$arch $($case.name) typed GDI return and duration"
    Check (@($graphics | Where-Object {$_.api -eq 'GetTextMetricsW' -and $_.category -eq 15 -and $_.returnValueAvailable}).Count -gt 0) "$arch $($case.name) newly typed GDI observed"
    if($case.raw -eq '1'){
     Check ($rawQueries.Count -gt 0) "$arch $($case.name) remaining GDI Raw observed"
     Check (@($rawQueries | Where-Object {$_.category -ne 15 -or $_.returnValueAvailable -or $_.durationAvailable}).Count -eq 0) "$arch $($case.name) correct Raw classification and entry semantics"
    }else{Check ($rawQueries.Count -eq 0) "$arch $($case.name) Raw remains off"}
   }
  }finally{
   [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
   if(!$target.WaitForExit(30000)){$target.Kill();$target.WaitForExit();throw 'Owned fixture did not stop'}
   $target.Dispose()
  }
 }
}
[IO.File]::WriteAllText((Join-Path $ReportRoot 'summary.json'),(@{checks=$checks;architectures=@('x64','x86');cases=$cases.name} | ConvertTo-Json -Depth 4))
Write-Output "GUI_CATEGORY_GUEST_PASS checks=$checks"
