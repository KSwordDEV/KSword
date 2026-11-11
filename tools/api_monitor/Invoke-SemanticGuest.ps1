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
foreach($arch in @('x64','x86')) {
 $fixture=if($arch -eq 'x64'){$Fixture64}else{$Fixture32}
 $root=Join-Path $ReportRoot $arch;New-Item -ItemType Directory -Path $root | Out-Null
 $target=Start-Process -FilePath $fixture -ArgumentList ('"'+$root+'"') -WindowStyle Hidden -PassThru
 try {
  for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath (Join-Path $root 'ready'));$i++){Start-Sleep -Milliseconds 50}
  if($target.HasExited -or !(Test-Path -LiteralPath (Join-Path $root 'ready'))){throw "$arch owned fixture not ready"}
  $args=@('monitor','api','capture','--pid',[string]$target.Id,'--duration-ms','15000',
    '--categories','file,process','--raw','0','--auto-children','0','--limit','20000','--confirm','--json')
  $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$Cli;$info.Arguments=$args -join ' '
  $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
  $info.StandardOutputEncoding=[Text.Encoding]::UTF8;$info.StandardErrorEncoding=[Text.Encoding]::UTF8
  $child=[Diagnostics.Process]::Start($info);$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
  try {
   Start-Sleep -Seconds 6
   [IO.File]::WriteAllText((Join-Path $root 'start'),'start')
   if(!$child.WaitForExit(90000)){$child.Kill();$child.WaitForExit();throw "$arch capture timeout"}
   $raw=$stdout.GetAwaiter().GetResult();$errorText=$stderr.GetAwaiter().GetResult();$code=$child.ExitCode
  } finally {$child.Dispose()}
  [IO.File]::WriteAllText((Join-Path $root 'capture.json'),$raw,[Text.UTF8Encoding]::new($false))
  [IO.File]::WriteAllText((Join-Path $root 'capture.stderr.txt'),$errorText,[Text.UTF8Encoding]::new($false))
  if(@(0,6) -notcontains $code -or !(Test-Path -LiteralPath (Join-Path $root 'done'))){throw "$arch capture or target did not complete"}
  $observed=@{};foreach($line in Get-Content -LiteralPath (Join-Path $root 'observed.txt')){ $parts=$line -split '=',2;if($parts.Count -eq 2){$observed[$parts[0]]=$parts[1]} }
  $data=($raw | ConvertFrom-Json).data
  $process=@($data.processes | Where-Object {$_.pid -eq $target.Id})
  $calls=@($data.events | Where-Object {$_.pid -eq $target.Id -and $_.tid -eq [int]$observed.tid -and $_.eventKind -eq 0})
  $protect=@($calls | Where-Object {$_.api -ceq 'VirtualProtect'})
  $duplicate=@($calls | Where-Object {$_.api -ceq 'DuplicateHandle'})
  $oldHex=('0x{0:X}' -f [uint32]$observed.oldProtect)
  $handleHex=('0x{0:X}' -f [uint64]$observed.duplicateHandle)
  $protectOk=@($protect | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 1 -and $_.detail -match ('out_after\.oldProtectPointer='+[regex]::Escape($oldHex)+'(?:\s|$)')})
  $protectFail=@($protect | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 0 -and $_.resultCode -eq [int]$observed.protectionError -and $_.detail -match 'out_after\.oldProtectPointer=<unavailable>'})
  $duplicateOk=@($duplicate | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 1 -and $_.detail -match ('out_after\.targetHandlePointer='+[regex]::Escape($handleHex)+'(?:\s|$)')})
  $duplicateFail=@($duplicate | Where-Object {$_.returnValueAvailable -and [Convert]::ToUInt64($_.returnValue,16) -eq 0 -and $_.resultCode -eq [int]$observed.duplicateError -and $_.detail -match 'out_after\.targetHandlePointer=<unavailable>'})
  $async=@($data.events | Where-Object {$_.pid -eq $target.Id -and $_.tid -eq [int]$observed.tid -and $_.api -ceq 'ReadFileEx'})
  $submit=@($async | Where-Object {$_.eventKind -eq 1 -and $_.operationId -ne '0'})
  $wait=@();$complete=@()
  if($submit.Count -eq 1){
   $wait=@($async | Where-Object {$_.operationId -eq $submit[0].operationId -and $_.eventKind -eq 2 -and $_.resultKind -eq 2 -and $_.detail -match 'bytes=unknown' -and $_.detail -match 'completion=pending'})
   $complete=@($async | Where-Object {$_.operationId -eq $submit[0].operationId -and $_.eventKind -eq 3 -and $_.resultKind -eq 0 -and $_.resultCode -eq [int]$observed.completionError -and $_.detail -match ('bytes='+[regex]::Escape($observed.completionBytes)+'(?:\s|$)')})
  }
  $row=[ordered]@{architecture=$arch;exitCode=$code;pid=$target.Id;protectionSuccess=$protectOk.Count;protectionFailure=$protectFail.Count;
   duplicateSuccess=$duplicateOk.Count;duplicateFailure=$duplicateFail.Count;asyncPending=$wait.Count;asyncComplete=$complete.Count;
   agentDropped=$process[0].agentDroppedCount;bufferDropped=$data.bufferDroppedCount;cleanup=$data.cleanupComplete}
  $results+=@([pscustomobject]$row)
  if($process.Count -ne 1 -or !$process[0].hooksRemoved -or !$data.cleanupComplete -or !$protectOk.Count -or !$protectFail.Count -or !$duplicateOk.Count -or !$duplicateFail.Count -or !$wait.Count -or !$complete.Count){throw "$arch semantic output mismatch; inspect capture.json and observed.txt"}
 } finally {
  [IO.File]::WriteAllText((Join-Path $root 'stop'),'stop')
  if(!$target.WaitForExit(15000)){throw "$arch fixture did not exit"}
  $target.Refresh();if($target.ExitCode -ne 0){throw "$arch fixture exited $($target.ExitCode)"};$target.Dispose()
 }
}
[IO.File]::WriteAllText((Join-Path $ReportRoot 'summary.json'),([pscustomobject]@{computer=$env:COMPUTERNAME;results=$results} | ConvertTo-Json -Depth 8),[Text.UTF8Encoding]::new($false))
Write-Output 'SEMANTIC_GUEST_PASS'
