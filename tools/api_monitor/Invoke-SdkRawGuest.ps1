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
$results=@()
foreach($arch in @('x64','x86')){
 $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
 $root=Join-Path $ReportRoot $arch;New-Item -ItemType Directory -Path $root | Out-Null
 $target=Start-Process -FilePath $fixture -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
 try {
  for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
  if($target.HasExited -or !(Test-Path -LiteralPath (Join-Path $root 'ready'))){throw "$arch owned fixture not ready"}
  $captureArgs=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','2000',
    '--raw','1','--raw-modules','user32.dll','--limit','20000','--signatures','1','--confirm','--json')
  $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli
  $info.Arguments=($captureArgs -join ' ');$info.UseShellExecute=$false;$info.CreateNoWindow=$true
  $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
  $child=[Diagnostics.Process]::Start($info);$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
  try {if(!$child.WaitForExit(90000)){$child.Kill();$child.WaitForExit();throw "$arch capture timed out"};$raw=$stdout.GetAwaiter().GetResult();$err=$stderr.GetAwaiter().GetResult();$code=$child.ExitCode} finally {$child.Dispose()}
  [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$err,[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $root 'capture.exit.txt'),[string]$code)
  if(@(0,6) -notcontains $code){throw "$arch capture failed: $code"}
  $data=($raw | ConvertFrom-Json).data
  $events=@($data.events | Where-Object {$_.pid -eq $target.Id -and $_.api -ceq 'GetSystemMetrics' -and $_.rawAbi -and $_.declaration})
  $ok=@($events | Where-Object {
    $_.rawAbi.architecture -eq $arch -and $_.declarationCatalogMatchesAgent -and
    $_.declaration.abiEvidence -eq 'Windows SDK x86/x64' -and $_.declaration.returnType -eq 'int' -and
    @($_.declaration.parameters).Count -eq 1 -and $_.declaration.parameters[0].type -eq 'int' -and
    $(if($arch -eq 'x64'){[Convert]::ToUInt64($_.rawAbi.registers.RCX,16) -eq 42}else{@($_.rawAbi.stackSlots).Count -gt 0 -and [Convert]::ToUInt64($_.rawAbi.stackSlots[0],16) -eq 42})
  })
  $process=@($data.processes | Where-Object {$_.pid -eq $target.Id})
  if(!$ok.Count -or $process.Count -ne 1 -or !$process[0].hooksRemoved -or !$process[0].coverageComplete -or $process[0].coverageStale -or !$data.cleanupComplete){throw "$arch SDK declaration / captured raw slot / cleanup check failed"}
  $results+=@([pscustomobject]@{architecture=$arch;exitCode=$code;pid=$target.Id;matchingEvents=$ok.Count;
    agentDropped=$process[0].agentDroppedCount;bufferDropped=$data.bufferDroppedCount;catalogHash=$data.signatureCatalog.sha256})
 } finally {
  [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
  if(!$target.WaitForExit(15000)){throw "$arch fixture did not exit"}
  $target.Refresh();if($target.ExitCode -ne 0){throw "$arch fixture exited $($target.ExitCode)"};$target.Dispose()
 }
}
$summary=[ordered]@{computer=$env:COMPUTERNAME;results=$results;limitations=@('Raw slots are captured ABI locations; no pointer dereference or assumption of other arguments','Exit 6 denotes partial hook coverage')}
[IO.File]::WriteAllText((Join-Path $ReportRoot 'summary.json'),($summary | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output 'SDK_RAW_GUEST_PASS'
