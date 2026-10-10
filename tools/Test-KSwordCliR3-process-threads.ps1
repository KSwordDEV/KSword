$paths=@(@('process','thread','enum'),@('process','thread','affinity','query'),@('process','thread','suspend'),@('process','thread','resume'),@('process','thread','terminate'),@('process','thread','set-affinity'))
foreach($path in $paths) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--pid') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Thread leaf help'
    Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Thread missing parameters'
}
Assert (!(Invoke-Cli @('process','thread','help')).Contains('--thread-creation-time')) 'Thread group lists direct children only'
foreach($bad in @(
    @('process','thread','enum','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','thread','enum','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','thread','enum','--pid',$PID.ToString(),'--limit','0','--json'),
    @('process','thread','enum','--pid',$PID.ToString(),'--creation-time','0','--json'),
    @('process','thread','set-affinity','--pid',$PID.ToString(),'--tid','1','--thread-creation-time','1','--processors','0:0,0:0','--confirm','--json'),
    @('process','thread','set-affinity','--pid',$PID.ToString(),'--tid','1','--thread-creation-time','1','--processors','0:64','--confirm','--json'),
    @('process','thread','set-affinity','--pid',$PID.ToString(),'--tid','1','--thread-creation-time','1','--processors','0:0,','--confirm','--json'),
    @('process','thread','suspend','--pid',$PID.ToString(),'--tid','1','--thread-creation-time','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Thread parameter rejection'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$rows=(Invoke-Cli @('process','thread','enum','--pid',$PID.ToString(),'--creation-time',$creation,'--json') @(0,6))|ConvertFrom-Json
Assert ($rows.data.complete -and $rows.data.returnedCount -gt 0 -and $rows.data.target.creationTime -eq $creation) 'Actual thread enumeration'
$oracle=Get-Process -Id $PID;$oracle.Refresh()
foreach($row in $rows.data.threads) {
    Assert ($row.pid -eq $PID) 'No foreign thread rows'
    if($row.creationTime) {
        $actual=@($oracle.Threads|Where-Object {$_.Id -eq $row.tid})
        if($actual.Count) {Assert ($row.creationTime -eq $actual[0].StartTime.ToUniversalTime().ToFileTimeUtc().ToString()) 'Independent thread creation time'}
    }
    if(!$row.startEvidence.available) {Assert ($null -eq $row.startAddress) 'No fake zero start address'}
    if(!$row.suspendEvidence.available) {Assert ($null -eq $row.suspendCount) 'No fake zero suspend count'}
}
$limited=(Invoke-Cli @('process','thread','enum','--pid',$PID.ToString(),'--limit','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Explicit limited enumeration'
Assert (((Invoke-Cli @('process','thread','enum','--pid',$PID.ToString(),'--tid','4294967295','--json'))|ConvertFrom-Json).data.returnedCount -eq 0) 'Valid empty thread filter'
Assert ((Invoke-Cli @('process','thread','enum','--pid',$PID.ToString()) @(0,6)).Contains('threads:')) 'Thread text output'
$self=$rows.data.threads|Where-Object {$_.creationTime}|Sort-Object creationTime|Select-Object -First 1
$base=@('--pid',$PID.ToString(),'--tid',$self.tid.ToString(),'--thread-creation-time',$self.creationTime)
$state=(Invoke-Cli (@('process','thread','affinity','query')+$base+@('--json')))|ConvertFrom-Json
Assert ($state.data.state.known -and $state.data.state.processors.Count -gt 0) 'Read-only thread affinity state'
Assert (((Invoke-Cli @('process','thread','enum','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Process identity mismatch'
Assert (((Invoke-Cli @('process','thread','affinity','query','--pid',$PID.ToString(),'--tid',$self.tid.ToString(),'--thread-creation-time',([uint64]$self.creationTime+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Thread identity mismatch'
if($InGuest) {
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliThreadOracle {
 [DllImport("kernel32.dll")] static extern IntPtr OpenThread(uint a,bool inherit,uint tid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetThreadSelectedCpuSets(IntPtr h,[Out] uint[] ids,uint n,out uint count);
 [DllImport("kernel32.dll")] static extern bool GetThreadGroupAffinity(IntPtr h,out Group a);
 [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h,int c,out uint p,uint n,IntPtr r);
 [StructLayout(LayoutKind.Sequential)] struct Group{public UIntPtr mask;public ushort group,r0,r1,r2;}
 public static uint SuspendCount(uint tid){var h=OpenThread(0x800,false,tid);try{uint result;int status=NtQueryInformationThread(h,35,out result,4,IntPtr.Zero);if(status!=0)throw new Exception("suspend oracle "+status);return result;}finally{CloseHandle(h);}}
 public static uint[] Selected(uint tid){var h=OpenThread(0x800,false,tid);try{uint count;var ids=new uint[512];if(!GetThreadSelectedCpuSets(h,ids,512,out count))throw new Exception("CPU Set query "+Marshal.GetLastWin32Error());Array.Resize(ref ids,(int)count);return ids;}finally{CloseHandle(h);}}
 public static ulong Mask(uint tid){var h=OpenThread(0x800,false,tid);try{Group a;if(!GetThreadGroupAffinity(h,out a))throw new Exception("group affinity");return a.mask.ToUInt64();}finally{CloseHandle(h);}}
}
'@
    $root=Join-Path $env:TEMP ('KswordCliThreads-'+[guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root|Out-Null
    $path=Join-Path $root 'state.json'
    $fixture=Join-Path (Split-Path -Parent $Cli) 'R3Fixture.exe'
    $target=Start-Process -FilePath $fixture -ArgumentList @('--threads',(Quote-CliArgument $path)) -PassThru
    try {
        for($i=0;$i -lt 50 -and !(Test-Path -LiteralPath $path);$i++){Start-Sleep -Milliseconds 100}
        function Read-Workers {for($attempt=0;$attempt -lt 20;$attempt++){try{return (Get-Content -LiteralPath $path -Raw -ErrorAction Stop)|ConvertFrom-Json}catch{Start-Sleep -Milliseconds 20}};throw 'Fixture state unavailable'}
        $workers=Read-Workers;$worker=$workers.workers[0]
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $guard=@('--pid',$target.Id.ToString(),'--creation-time',$born,'--tid',$worker.tid.ToString(),'--thread-creation-time',$worker.creationTime)
        $enum=(Invoke-Cli @('process','thread','enum','--pid',$target.Id.ToString(),'--creation-time',$born,'--json') @(0,6))|ConvertFrom-Json
        foreach($w in $workers.workers){$row=$enum.data.threads|Where-Object {$_.tid -eq $w.tid};Assert ($row.creationTime -eq $w.creationTime -and $row.startAddress -and $row.suspendCount -eq 0) 'Native fixture thread identities and start address'}
        $bad=(Invoke-Cli @('process','thread','suspend','--pid',$target.Id.ToString(),'--tid',$worker.tid.ToString(),'--thread-creation-time',([uint64]$worker.creationTime+1).ToString(),'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($bad.status -eq 'failed' -and [CliThreadOracle]::SuspendCount($worker.tid) -eq 0) 'Thread mismatch performs no action'
        $foreign=(Invoke-Cli @('process','thread','suspend','--pid',$PID.ToString(),'--tid',$worker.tid.ToString(),'--thread-creation-time',$worker.creationTime,'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($foreign.status -eq 'failed' -and [CliThreadOracle]::SuspendCount($worker.tid) -eq 0) 'Owner mismatch performs no action'
        foreach($verb in @('suspend','suspend','resume','resume','resume')) {
            $result=(Invoke-Cli (@('process','thread',$verb)+$guard+@('--confirm','--json')))|ConvertFrom-Json
            $count=[CliThreadOracle]::SuspendCount($worker.tid)
            Assert ($result.data.verified -and $result.data.observed.after.count -eq $count) 'Independent suspend count after each single change'
            Start-Sleep -Milliseconds 250;$a=(Read-Workers).workers[0];Start-Sleep -Milliseconds 500;$b=(Read-Workers).workers[0]
            if($count){Assert ($a.counter -eq $b.counter) 'Suspended worker stopped progressing'}else{Assert ([uint64]$b.counter -gt [uint64]$a.counter) 'Resumed worker progresses'}
        }
        $aff=(Invoke-Cli (@('process','thread','affinity','query')+$guard+@('--json')))|ConvertFrom-Json
        $processor=$aff.data.state.processors|Where-Object {$_.available}|Select-Object -First 1
        $coordinate=$processor.group.ToString()+':'+$processor.logicalIndex.ToString()
        $set=(Invoke-Cli (@('process','thread','set-affinity')+$guard+@('--processors',$coordinate,'--confirm','--json')))|ConvertFrom-Json
        Assert ($set.data.verified) 'Thread affinity verified'
        if($set.data.observed.usesCpuSets){$selected=[CliThreadOracle]::Selected($worker.tid);Assert ($selected.Count -eq 1 -and $selected[0] -eq $processor.cpuSetId) 'Independent CPU Set selection'}
        else{Assert ([CliThreadOracle]::Mask($worker.tid) -eq ([uint64]1 -shl $processor.logicalIndex)) 'Independent group affinity mask'}
        $follow=(Invoke-Cli (@('process','thread','set-affinity')+$guard+@('--processors','follow','--confirm','--json')))|ConvertFrom-Json
        Assert ($follow.data.verified -and $follow.data.observed.followsProcess) 'Thread follows process selection'
        if($follow.data.observed.usesCpuSets){Assert ([CliThreadOracle]::Selected($worker.tid).Count -eq 0) 'Independent cleared CPU Set selection'}
        $invalid=(Invoke-Cli (@('process','thread','set-affinity')+$guard+@('--processors','65535:63','--confirm','--json')) 3)|ConvertFrom-Json
        Assert (!$invalid.data.requestSucceeded -and !$invalid.data.writeAttempted) 'Unavailable coordinate fails before writing'
        $terminate=(Invoke-Cli (@('process','thread','terminate')+$guard+@('--confirm','--json')))|ConvertFrom-Json
        Start-Sleep -Milliseconds 300;$ended=(Read-Workers).workers[0]
        Assert ($terminate.data.verified -and $terminate.data.observed.exitCode -eq 1 -and $ended.exitCode -eq 1) 'Independent native fixture thread exit'
        Assert (((Invoke-Cli (@('process','thread','resume')+$guard+@('--confirm','--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited thread cannot be resumed'
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli (@('process','thread','affinity','query')+$guard+@('--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited process cannot be queried'
    } finally {
        if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()
        $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
        if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe cleanup root'}
        Remove-Item -LiteralPath $absolute -Recurse -Force
    }
}
