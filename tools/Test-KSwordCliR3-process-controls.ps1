$leafs=@(
    @('process','suspend'),@('process','resume'),@('process','terminate'),@('process','terminate','chain'),@('process','terminate-tree'),
    @('process','settings','set-priority'),@('process','settings','efficiency','enable'),@('process','settings','efficiency','disable'),
    @('process','settings','critical','enable'),@('process','settings','critical','disable')
)
$methods=@('win32','nt','wts','winstation','job','nt-job','restart-manager','restart-manager-force','duplicate-handle','threads','nt-threads','debug','ntsd','unmap-ntdll')
foreach($method in $methods) {$leafs+=,@('process','terminate',$method)}
foreach($path in $leafs) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--confirm') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Process control help'
    # Existing R0 leaves require explicit selection to validate R3-only args.
    $args=$path+@('--backend','r3','--json')
    Assert (((Invoke-Cli $args 1)|ConvertFrom-Json).status -eq 'failed') 'Missing control parameters'
}
Assert (!(Invoke-Cli @('help','process','settings')).Contains('--confirm')) 'Settings hierarchy'
foreach($bad in @(
    @('process','settings','set-priority','--pid','4','--level','bad','--confirm','--json'),
    @('process','settings','set-priority','--pid','4','--level','normal','--confirm','--backend','bad','--json'),
    @('process','settings','set-priority','--pid','4','--level','normal','--confirm','--typo','1','--json'),
    @('process','suspend','--pid','4','--backend','r3','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Control parameter rejection'}
$protected=(Invoke-Cli @('process','settings','set-priority','--pid','4','--level','normal','--confirm','--json') 5)|ConvertFrom-Json
Assert ($protected.status -eq 'unsupported') 'Existing backend system PID protection'
if ($InGuest) {
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public static class CliControlOracle {
 [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool inherit,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")] static extern uint GetPriorityClass(IntPtr h);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool IsProcessCritical(IntPtr h,out bool critical);
 [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessInformation(IntPtr h,int c,ref Power p,uint n);
 [DllImport("ntdll.dll")] static extern int NtSetInformationProcess(IntPtr h,int c,ref uint p,uint n);
 [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h,int c,ref Power p,uint n,IntPtr r);
 [DllImport("ntdll.dll",EntryPoint="NtQueryInformationProcess")] static extern int NtQueryLength(IntPtr h,int c,ref Power p,uint n,out uint r);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr h,uint a,out IntPtr t);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string s,string n,out long luid);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t,bool all,ref Privilege p,uint n,IntPtr old,IntPtr r);
 [StructLayout(LayoutKind.Sequential)] struct Power{public uint version,control,state;}
 [StructLayout(LayoutKind.Sequential)] struct Privilege{public uint count;public uint low;public int high;public uint attributes;}
 public static uint Priority(uint pid){var h=OpenProcess(0x1400,false,pid);try{return GetPriorityClass(h);}finally{CloseHandle(h);}}
 public static bool Critical(uint pid){var h=OpenProcess(0x1400,false,pid);try{bool result;if(!IsProcessCritical(h,out result))throw new Exception("critical query "+Marshal.GetLastWin32Error());return result;}finally{CloseHandle(h);}}
 public static bool? Efficiency(uint pid){var h=OpenProcess(0x1400,false,pid);try{var p=new Power{version=1};if(GetProcessInformation(h,4,ref p,12)||NtQueryInformationProcess(h,77,ref p,12,IntPtr.Zero)==0)return (p.control&p.state&1)!=0;return null;}finally{CloseHandle(h);}}
 public static string RawEfficiency(uint pid){string text="";foreach(uint access in new uint[]{0x1000,0x1400}){var h=OpenProcess(access,false,pid);try{var p=new Power{version=1};uint length;int status=NtQueryLength(h,77,ref p,12,out length);text+=" access="+access+" status="+status+" size="+length+" version="+p.version+" control="+p.control+" state="+p.state;}finally{CloseHandle(h);}}return text;}
 public static void ClearCritical(uint pid){IntPtr token;if(!OpenProcessToken(GetCurrentProcess(),0x28,out token))throw new Exception("token");
  try{long luid;LookupPrivilegeValue(null,"SeDebugPrivilege",out luid);var p=new Privilege{count=1,low=(uint)luid,high=(int)(luid>>32),attributes=2};AdjustTokenPrivileges(token,false,ref p,0,IntPtr.Zero,IntPtr.Zero);}finally{CloseHandle(token);}
  var h=OpenProcess(0x1600,false,pid);try{uint zero=0;int s=NtSetInformationProcess(h,29,ref zero,4);if(s!=0)throw new Exception("critical restore "+s);}finally{CloseHandle(h);}}
}
'@
    $target=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru
    $targetText=$target.Id.ToString();$born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
    try {
        $mismatch=(Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--creation-time',([uint64]$born+1).ToString(),'--level','idle','--confirm','--json') 3)|ConvertFrom-Json
        Assert (!$mismatch.data.target.identityMatched -and [CliControlOracle]::Priority($target.Id) -eq 0x20) 'Mismatched identity performs no priority change'
        foreach($pair in @(@('idle',0x40),@('below-normal',0x4000),@('above-normal',0x8000),@('high',0x80),@('normal',0x20))) {
            $changed=(Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--creation-time',$born,'--level',$pair[0],'--confirm','--json'))|ConvertFrom-Json
            Assert ($changed.data.verified -and [CliControlOracle]::Priority($target.Id) -eq $pair[1]) 'Independent priority class'
        }
        $realtime=(Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--creation-time',$born,'--level','realtime','--confirm','--json') @(0,3,6))|ConvertFrom-Json
        if($realtime.data.requestSucceeded) {Assert ([CliControlOracle]::Priority($target.Id) -eq 0x100) 'Realtime actual effect'} else {Assert (!$realtime.data.verified) 'Realtime failure cannot succeed'}
        Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--level','normal','--confirm','--json')|Out-Null
        $suspend=(Invoke-Cli @('process','suspend','--pid',$targetText,'--creation-time',$born,'--confirm','--backend','r3','--json') @(0,6))|ConvertFrom-Json
        $target.Refresh();$suspended=@($target.Threads|Where-Object {$_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended'})
        Assert ($suspend.data.requestSucceeded -and $suspended.Count -gt 0) 'Independent suspended threads'
        $resume=(Invoke-Cli @('process','resume','--pid',$targetText,'--creation-time',$born,'--confirm','--backend','r3','--json') @(0,6))|ConvertFrom-Json
        $target.Refresh();Assert ($resume.data.requestSucceeded -and @($target.Threads|Where-Object {$_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended'}).Count -eq 0) 'Independent resumed threads'
        foreach($verb in @('enable','disable')) {
            $eff=(Invoke-Cli @('process','settings','efficiency',$verb,'--pid',$targetText,'--creation-time',$born,'--confirm','--json') @(0,3,5,6))|ConvertFrom-Json
            if($eff.data.verified) {Assert ([CliControlOracle]::Efficiency($target.Id) -eq ($verb -eq 'enable')) 'Independent efficiency state'}
            elseif($eff.data.requestSucceeded) {
                Assert ($eff.status -eq 'partial' -and !$eff.data.verified) 'Unconfirmed efficiency cannot succeed'
                $native=[CliControlOracle]::Efficiency($target.Id)
                if($null -eq $native) {Assert (!$eff.data.observed.after.known -and $null -eq $eff.data.observed.after.value) 'Unavailable efficiency readback is explicit'}
                else {Assert ($eff.data.observed.after.known -and [bool]$eff.data.observed.after.value -eq $native -and $native -ne ($verb -eq 'enable')) ("Independent mismatch matches partial readback: verb="+$verb+" oracle="+$native+" raw="+[CliControlOracle]::RawEfficiency($target.Id)+" cli="+($eff|ConvertTo-Json -Compress -Depth 12))}
            }
            else {Assert (!$eff.data.verified) 'Unsupported/refused efficiency is explicit'}
        }
        $critical=(Invoke-Cli @('process','settings','critical','enable','--pid',$targetText,'--creation-time',$born,'--confirm','--json') @(0,3,5,6))|ConvertFrom-Json
        if($critical.data.requestSucceeded) {Assert ([CliControlOracle]::Critical($target.Id)) 'Independent critical process flag'}
        $clear=(Invoke-Cli @('process','settings','critical','disable','--pid',$targetText,'--creation-time',$born,'--confirm','--json'))|ConvertFrom-Json
        Assert ($clear.data.verified -and ![CliControlOracle]::Critical($target.Id)) 'Critical flag cleared before termination'
        $text=Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--level','normal','--confirm')
        Assert ($text.Contains('verified: true')) 'Control text'
        $terminated=(Invoke-Cli @('process','terminate','--pid',$targetText,'--creation-time',$born,'--exit-status','0x1234','--confirm','--backend','r3','--json'))|ConvertFrom-Json
        Assert ($target.WaitForExit(5000) -and $target.ExitCode -eq 0x1234 -and $terminated.data.verified -and $terminated.data.exitCode -eq '0x1234') 'Independent native termination exit code'
        $gone=(Invoke-Cli @('process','settings','set-priority','--pid',$targetText,'--creation-time',$born,'--level','normal','--confirm','--json') 3)|ConvertFrom-Json
        Assert ($gone.status -eq 'failed') 'Exited target control fails'
    } finally {
        if(!$target.HasExited) {
            if([CliControlOracle]::Critical($target.Id)) {[CliControlOracle]::ClearCritical($target.Id)}
            Assert (![CliControlOracle]::Critical($target.Id)) 'Cleanup must not terminate a critical process'
            Invoke-Cli @('process','resume','--pid',$targetText,'--confirm','--backend','r3','--json') @(0,3,6)|Out-Null
            $target.Kill();$target.WaitForExit()
        };$target.Dispose()
    }
    foreach($method in (@('chain')+$methods)) {
        $victim=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru
        try {
            $birth=$victim.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            $kill=(Invoke-Cli @('process','terminate',$method,'--pid',$victim.Id.ToString(),'--creation-time',$birth,'--confirm','--json') @(0,3,5,6))|ConvertFrom-Json
            if($kill.data.verified) {Assert ($victim.WaitForExit(5000) -and $kill.data.exited) 'Method actual exit'} else {Assert ($kill.status -ne 'success') 'Unavailable/refused/incomplete method must not succeed'}
        } finally {if(!$victim.HasExited){$victim.Kill();$victim.WaitForExit()};$victim.Dispose()}
    }
    $root=Join-Path $env:TEMP ('KSwordCliTree-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
    $script=Join-Path $root 'parent.ps1';$state=Join-Path $root 'child.txt';$child=$null;$parent=$null
    try {
        @('$child=Start-Process -FilePath "$env:WINDIR\System32\notepad.exe" -PassThru',("$"+'child.Id | Set-Content -LiteralPath '+"'$state'"),'while($true){Start-Sleep -Seconds 1}')|Set-Content -LiteralPath $script -Encoding UTF8
        $parent=Start-Process -FilePath "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "'+$script+'"') -WindowStyle Hidden -PassThru
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        while(!(Test-Path -LiteralPath $state) -and [DateTime]::UtcNow -lt $deadline){Start-Sleep -Milliseconds 30}
        Assert (Test-Path -LiteralPath $state) 'Owned process tree fixture became ready'
        $child=Get-Process -Id ([int](Get-Content -LiteralPath $state))
        $born=$parent.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $expectedChildren=@(Get-CimInstance Win32_Process -Filter ('ParentProcessId='+$parent.Id)|ForEach-Object{[int]$_.ProcessId})
        $tree=(Invoke-Cli @('process','terminate-tree','--pid',$parent.Id.ToString(),'--creation-time',$born,'--confirm','--json'))|ConvertFrom-Json
        Assert ($tree.data.confirmedCount -eq ($expectedChildren.Count+1) -and $tree.data.failedCount -eq 0 -and $parent.WaitForExit(5000) -and $child.WaitForExit(5000)) ("Independent child-first tree termination: "+($tree|ConvertTo-Json -Compress -Depth 12)+" parentExited="+$parent.HasExited+" childExited="+$child.HasExited)
        $actualChildren=@($tree.data.targets|Select-Object -SkipLast 1|ForEach-Object{[int]$_.target.pid})
        Assert ((($actualChildren|Sort-Object)-join ',') -eq (($expectedChildren|Sort-Object)-join ',') -and $tree.data.targets[-1].target.pid -eq $parent.Id) 'Independent tree membership and child-first identity order'
    } finally {
        foreach($p in @($child,$parent)){if($p){if(!$p.HasExited){$p.Kill();$p.WaitForExit()};$p.Dispose()}}
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'Tree fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
