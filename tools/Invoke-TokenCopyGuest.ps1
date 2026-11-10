param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$ServiceName)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7' -or $ServiceName -notmatch '^KswordTokenCopy_[0-9a-f]{12}$' -or $Root -notmatch '^C:\\CodexVm\\TokenCopy-[0-9a-f]{12}$'){throw 'Unsafe guest identity or run scope'}
$fixture=Join-Path $Root 'token_copy_vm_fixture.exe';$cli=Join-Path $Root 'KswordCLI.exe';$driver=Join-Path $Root 'KswordARK.sys'
$journal=[IO.FileStream]::new((Join-Path $Root 'journal.jsonl'),[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read,4096,[IO.FileOptions]::WriteThrough)
function Log([hashtable]$entry){$entry.utc=[DateTime]::UtcNow.ToString('o');$bytes=[Text.Encoding]::UTF8.GetBytes(($entry|ConvertTo-Json -Compress -Depth 12)+"`n");$journal.Write($bytes,0,$bytes.Length);$journal.Flush($true)}
function SaveJson($value,[string]$name){[IO.File]::WriteAllText((Join-Path $Root $name),($value|ConvertTo-Json -Depth 20),[Text.UTF8Encoding]::new($false))}
function Snapshot {
    $os=Get-CimInstance Win32_OperatingSystem;$kernel=Get-Item "$env:windir\System32\ntoskrnl.exe"
    [pscustomobject]@{utc=[DateTime]::UtcNow.ToString('o');computer=$env:COMPUTERNAME;user=(whoami);os=($os|Select-Object Caption,Version,BuildNumber,OSArchitecture,LastBootUpTime);kernel=@{version=$kernel.VersionInfo.FileVersion;sha256=(Get-FileHash $kernel.FullName).Hash};originalService=(Get-CimInstance Win32_SystemDriver -Filter "Name='KswordARK'"|Select-Object Name,State,StartMode,PathName);testSigning=(& bcdedit.exe /enum '{current}'|Select-String 'testsigning').ToString();dumps=@(Get-Item "$env:windir\MEMORY.DMP" -ErrorAction SilentlyContinue | Select-Object FullName,Length,LastWriteTimeUtc;Get-ChildItem "$env:windir\Minidump\*.dmp" -ErrorAction SilentlyContinue|Select-Object FullName,Length,LastWriteTimeUtc);events=@(Get-WinEvent -FilterHashtable @{LogName='System';Id=41,1001,6008;StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue|Select-Object TimeCreated,Id,ProviderName,RecordId,Message);hashes=@(Get-FileHash (Join-Path $Root 'KswordARK.sys'),(Join-Path $Root 'KswordCLI.exe'),(Join-Path $Root 'token_copy_vm_fixture.exe'),(Join-Path $Root 'MSVCP140.dll'),(Join-Path $Root 'VCRUNTIME140.dll'),(Join-Path $Root 'VCRUNTIME140_1.dll')|Select-Object Path,Hash)}
}
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class TokenCopySuspended {
 [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct STARTUPINFO { public int cb; public string reserved,desktop,title; public int x,y,xsize,ysize,xchars,ychars,fill,flags; public short show,reserved2; public IntPtr reservedPtr,stdin,stdout,stderr; }
 [StructLayout(LayoutKind.Sequential)] public struct PI { public IntPtr process,thread; public uint pid,tid; }
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcess(string app,System.Text.StringBuilder cmd,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr env,string dir,ref STARTUPINFO si,out PI pi);
 [DllImport("kernel32.dll",SetLastError=true)] public static extern uint ResumeThread(IntPtr thread);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
 public static PI Create(string exe,string stop) { var si=new STARTUPINFO();si.cb=Marshal.SizeOf(si);PI pi;var cmd=new System.Text.StringBuilder("\""+exe+"\" watch \""+stop+"\" 1");if(!CreateProcess(exe,cmd,IntPtr.Zero,IntPtr.Zero,false,4|0x08000000,IntPtr.Zero,null,ref si,out pi))throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());return pi; }
}
'@
$spawned=@();$created=$false;$suspended=$null;$stop=Join-Path $Root 'stop.signal'
try {
    if((Get-CimInstance Win32_SystemDriver -Filter "Name='KswordARK'").State -ne 'Stopped'){throw 'Original service is not stopped'}
    if(Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'"){throw 'Temporary service already exists'}
    SaveJson (Snapshot) 'baseline.json'
    Log @{action='create-service';service=$ServiceName;driver=$driver}
    & sc.exe create $ServiceName type= kernel start= demand binPath= $driver | Out-File (Join-Path $Root 'service-create.txt');if($LASTEXITCODE -ne 0){throw "sc create failed $LASTEXITCODE"};$created=$true
    Log @{action='start-service';service=$ServiceName}
    & sc.exe start $ServiceName | Out-File (Join-Path $Root 'service-start.txt');if($LASTEXITCODE -ne 0){throw "sc start failed $LASTEXITCODE"}
    SaveJson (Get-CimInstance Win32_SystemDriver -Filter "Name='$ServiceName'"|Select-Object Name,State,PathName) 'service-running.json'
    $source=Start-Process $fixture -ArgumentList @('watch', $stop, '1') -PassThru -RedirectStandardOutput (Join-Path $Root 'source.stdout') -RedirectStandardError (Join-Path $Root 'source.stderr');$null=$source.Handle;$spawned+= $source
    Start-Sleep -Seconds 2
    if($source.HasExited){throw 'Source helper exited early'}
    $sourceInfo=(& $fixture query $source.Id|ConvertFrom-Json);if($LASTEXITCODE -ne 0){throw 'Source token query failed'}
    SaveJson $sourceInfo 'source-query.json'
    foreach($index in 1..5) {
        $threads=if($index -eq 5){4}else{1};$name="running-$index"
        $target=Start-Process $fixture -ArgumentList @('watch',$stop,$threads) -PassThru -RedirectStandardOutput (Join-Path $Root "$name.stdout") -RedirectStandardError (Join-Path $Root "$name.stderr");$null=$target.Handle;$spawned+=$target
        Start-Sleep -Seconds 2;if($target.HasExited){throw "$name exited before test"}
        $before=(& $fixture query $target.Id|ConvertFrom-Json);if($LASTEXITCODE -ne 0){throw "$name before query failed"}
        $args=@('process','token','copy','--source-pid',"$($source.Id)",'--pid',"$($target.Id)",'--source-creation-time',"$($sourceInfo.creationTime)",'--creation-time',"$($before.creationTime)",'--confirm','--backend','r0','--json')
        Log @{action='token-copy';case=$name;source=$sourceInfo;before=$before;threads=$threads;args=$args}
        & $cli @args 1> (Join-Path $Root "$name.cli.stdout") 2> (Join-Path $Root "$name.cli.stderr");$exit=$LASTEXITCODE
        $after=(& $fixture query $target.Id|ConvertFrom-Json);$queryExit=$LASTEXITCODE
        Start-Sleep -Seconds 2;$target.Refresh();$alive=!$target.HasExited
        $out=Get-Content (Join-Path $Root "$name.cli.stdout") -Raw; $receipt=try{$out|ConvertFrom-Json}catch{$null}
        $record=@{name=$name;threads=$threads;source=$sourceInfo;before=$before;after=$after;queryExit=$queryExit;cliExit=$exit;alive=$alive;receipt=$receipt;heartbeatLines=@(Get-Content "$stop.$($target.Id).log"|Where-Object {$_ -like 'heartbeat *'}).Count}
        SaveJson $record "$name.result.json";Log (@{action='token-copy-result'}+$record)
        if(!$alive -or $queryExit -ne 0){throw "$name did not survive or could not be queried"}
    }
    $name='suspended-initial';Log @{action='create-suspended';case=$name};$suspended=[TokenCopySuspended]::Create($fixture,$stop)
    $target=Get-Process -Id $suspended.pid;$null=$target.Handle;$spawned+=$target
    $before=(& $fixture query $suspended.pid|ConvertFrom-Json);if($LASTEXITCODE -ne 0){throw 'Suspended before query failed'}
    $args=@('process','token','copy','--source-pid',"$($source.Id)",'--pid',"$($suspended.pid)",'--source-creation-time',"$($sourceInfo.creationTime)",'--creation-time',"$($before.creationTime)",'--confirm','--backend','r0','--json')
    Log @{action='token-copy';case=$name;source=$sourceInfo;before=$before;creationFlags='CREATE_SUSPENDED';args=$args}
    & $cli @args 1> (Join-Path $Root "$name.cli.stdout") 2> (Join-Path $Root "$name.cli.stderr");$exit=$LASTEXITCODE
    $after=(& $fixture query $suspended.pid|ConvertFrom-Json);$queryExit=$LASTEXITCODE
    Log @{action='resume-initial-thread';case=$name;pid=$suspended.pid}
    $resume=[TokenCopySuspended]::ResumeThread($suspended.thread);if($resume -eq [uint32]::MaxValue){throw 'ResumeThread failed'}
    Start-Sleep -Seconds 3;$target.Refresh();$alive=!$target.HasExited
    $out=Get-Content (Join-Path $Root "$name.cli.stdout") -Raw;$receipt=try{$out|ConvertFrom-Json}catch{$null}
    $record=@{name=$name;creationFlags='CREATE_SUSPENDED';source=$sourceInfo;before=$before;after=$after;queryExit=$queryExit;cliExit=$exit;resumePreviousCount=$resume;alive=$alive;receipt=$receipt}
    SaveJson $record "$name.result.json";Log (@{action='token-copy-result'}+$record)
    if(!$alive -or $queryExit -ne 0){throw 'Suspended target did not survive or could not be queried'}
    Log @{action='normal-helper-exit'};[IO.File]::WriteAllText($stop,'stop')
    foreach($p in $spawned){if(!$p.WaitForExit(10000)){throw "Helper $($p.Id) did not exit normally"};SaveJson @{pid=$p.Id;exitCode=$p.ExitCode} "exit-$($p.Id).json"}
    Log @{action='cases-complete'}
} catch {Log @{action='error';message=$_.ToString()};throw} finally {
    if($null -ne $suspended){[void][TokenCopySuspended]::CloseHandle($suspended.thread);[void][TokenCopySuspended]::CloseHandle($suspended.process)}
    if(!(Test-Path $stop) -and $stop){[IO.File]::WriteAllText($stop,'stop')}
    foreach($p in $spawned){try{if(!$p.HasExited){[void]$p.WaitForExit(3000)}}catch{}}
    if($created){Log @{action='stop-service';service=$ServiceName};& sc.exe stop $ServiceName | Out-File (Join-Path $Root 'service-stop.txt');Log @{action='delete-service';service=$ServiceName};& sc.exe delete $ServiceName | Out-File (Join-Path $Root 'service-delete.txt')}
    try{SaveJson (Snapshot) 'after.json'}catch{Log @{action='after-snapshot-error';message=$_.ToString()}}
    Log @{action='finished'};$journal.Dispose()
}
