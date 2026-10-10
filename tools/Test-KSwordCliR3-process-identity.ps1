$help=Invoke-Cli @('help','process','identity','query')
Assert ($help.Contains('--creation-time') -and (Invoke-Cli @('process','identity','query','--help')) -eq $help) 'Identity leaf help'
Assert (!(Invoke-Cli @('process','identity','help')).Contains('--creation-time')) 'Identity immediate help'
foreach($bad in @(@(),@('--pid','0'),@('--pid','4294967296'),@('--pid',"$PID",'--creation-time','0'),@('--pid',"$PID",'--backend','r0'),@('--pid',"$PID",'--unknown','1'))){Assert (((Invoke-Cli (@('process','identity','query','--json')+$bad) 1)|ConvertFrom-Json).status -eq 'failed') 'Identity validation'}
$sdk=Get-Process -Id $PID;$time=$sdk.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$query=(Invoke-Cli @('process','identity','query','--pid',"$PID",'--creation-time',$time,'--json') 0)|ConvertFrom-Json
Assert ($query.data.identityVerified -and $query.data.aliveBefore -and $query.data.aliveAfter -and $query.data.detailLeaseRetainedDuringQueries -and $query.data.target.creationTime -eq $time -and $query.data.detailIdentity.creationTime -eq $time -and $query.data.navigationIdentity.creationTime -eq $time) 'Independent raw FILETIME with all identity samplers'
Assert ((Get-Item -LiteralPath $query.data.imagePath).FullName -eq (Get-Item -LiteralPath $sdk.Path).FullName -and $query.data.name -eq [IO.Path]::GetFileName($sdk.Path) -and $null -eq $query.data.nameDisplayFallback -and $query.data.pathSamplesConsistent) 'Independent actual image path/name, no PID fallback as executable identity'
foreach($e in @($query.data.navigationIdentity,$query.data.nameEvidence,$query.data.eventPathEvidence)){Assert ($e.identityMatched -and $e.closed) 'Each backend temporary query handle closed'}
$wrong=(Invoke-Cli @('process','identity','query','--pid',"$PID",'--creation-time',([uint64]$time+1).ToString(),'--json') 3)|ConvertFrom-Json
Assert (!$wrong.data.target.identityMatched -and !$wrong.data.identityVerified) 'Creation-time guard prevents stale identity'
Assert ((Invoke-Cli @('process','identity','query','--pid',"$PID")).Contains('source: shared ProcessNavigationIdentity')) 'Identity text'
if($InGuest){
 $target=Start-Process -FilePath 'C:\Windows\System32\cmd.exe' -ArgumentList '/c ping -n 20 127.0.0.1 >nul' -WindowStyle Hidden -PassThru
 try{$target.Refresh();$created=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();$live=(Invoke-Cli @('process','identity','query','--pid',"$($target.Id)",'--creation-time',$created,'--json') 0)|ConvertFrom-Json;Assert ($live.data.identityVerified -and $live.data.name -eq 'cmd.exe' -and $live.data.imagePath -eq 'C:\Windows\System32\cmd.exe') 'Real disposable target identity/path';$target.Kill();$target.WaitForExit();$exited=(Invoke-Cli @('process','identity','query','--pid',"$($target.Id)",'--creation-time',$created,'--json') 3)|ConvertFrom-Json;Assert (!$exited.data.identityVerified) 'Exited target is not a successful stale identity'}finally{if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
