$paths=@(@('process','peb','query'),@('process','peb','environment','query'),@('process','memory','regions','query'),@('process','settings','set-affinity'))
foreach($path in $paths) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--pid') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'PEB/memory/affinity leaf help'
    Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'PEB missing parameters'
}
Assert (!(Invoke-Cli @('process','peb','help')).Contains('--view')) 'PEB help shows direct children only'
Assert (!(Invoke-Cli @('help','process','peb','environment')).Contains('--name')) 'Environment help hierarchy'
Assert (!(Invoke-Cli @('help','process','settings')).Contains('--mask')) 'Settings hierarchy'
foreach($bad in @(
    @('process','peb','query','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','peb','query','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','peb','query','--pid',$PID.ToString(),'--view','bad','--json'),
    @('process','peb','environment','query','--pid',$PID.ToString(),'--limit','0','--json'),
    @('process','memory','regions','query','--pid',$PID.ToString(),'--limit','41','--json'),
    @('process','settings','set-affinity','--pid',$PID.ToString(),'--mask','0','--confirm','--json'),
    @('process','settings','set-affinity','--pid',$PID.ToString(),'--mask','1','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'PEB/memory/affinity parameter rejection'}
Add-Type -TypeDefinition @'
using System;using System.Text;using System.Runtime.InteropServices;
public static class CliPebOracle {
 [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetCurrentDirectory(uint n,StringBuilder p);
 [DllImport("kernel32.dll")] public static extern bool IsDebuggerPresent();
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool i,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("kernel32.dll")] static extern UIntPtr VirtualQueryEx(IntPtr h,IntPtr address,out Info info,UIntPtr n);
 [StructLayout(LayoutKind.Sequential)] struct Info {public IntPtr b,a;public uint allocationProtect;public ushort partitionId,padding;public UIntPtr size;public uint state,protect,type;}
 public static string Directory(){var text=new StringBuilder(32768);if(GetCurrentDirectory(32768,text)==0)throw new Exception("CWD");return text.ToString();}
 public static ulong[] Region(uint pid,ulong address){var h=OpenProcess(0x400,false,pid);try{Info i;var n=VirtualQueryEx(h,new IntPtr(unchecked((long)address)),out i,new UIntPtr((uint)Marshal.SizeOf(typeof(Info))));if(n==UIntPtr.Zero)throw new Exception("VirtualQueryEx");return new ulong[]{unchecked((ulong)i.b.ToInt64()),i.size.ToUInt64(),i.state,i.type,i.protect};}finally{CloseHandle(h);}}
}
'@
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$self=(Invoke-Cli @('process','peb','query','--pid',$PID.ToString(),'--creation-time',$creation,'--json'))|ConvertFrom-Json
$oracle=Get-CimInstance Win32_Process -Filter "ProcessId=$PID"
Assert ($self.data.context.target.creationTime -eq $creation -and $self.data.view -eq 'native' -and $self.data.headerKnown -and $self.data.parametersKnown) 'Native PEB identity/header/parameters'
Assert ($self.data.commandLine.value -eq $oracle.CommandLine -and (Get-Item $self.data.imagePath.value).FullName -eq (Get-Item $oracle.ExecutablePath).FullName) 'Independent PEB command line and image path'
Assert ($self.data.currentDirectory.value.TrimEnd('\') -eq [CliPebOracle]::Directory().TrimEnd('\') -and $self.data.beingDebugged -eq [CliPebOracle]::IsDebuggerPresent()) 'Independent current-directory and debugger state'
Assert ($self.data.pebAddress -match '^0x' -and $self.data.imageBase -match '^0x' -and $self.data.environmentAddress -match '^0x') 'Typed PEB address fields'
$noWow=(Invoke-Cli @('process','peb','query','--pid',$PID.ToString(),'--view','wow64','--json') 5)|ConvertFrom-Json
Assert ($noWow.status -eq 'unsupported') 'Absent WOW64 view is not native fallback'
$savedProbe=[Environment]::GetEnvironmentVariable('AA_KSwordR3PebProbe')
$probe='R3'+[char]0x4e2d+[char]0x6587+'=PEB'
try {
    $env:AA_KSwordR3PebProbe=$probe
    $environment=(Invoke-Cli @('process','peb','environment','query','--pid',$PID.ToString(),'--name','aa_kswordr3pebprobe','--json'))|ConvertFrom-Json
    Assert ($environment.data.complete -and $environment.data.returnedCount -eq 1 -and $environment.data.entries[0].value -eq $probe) 'Actual UTF-16 environment value with case-insensitive filtering'
    $empty=(Invoke-Cli @('process','peb','environment','query','--pid',$PID.ToString(),'--name','KswordEnvironmentMissing-01982','--json'))|ConvertFrom-Json
    Assert ($empty.data.returnedCount -eq 0) 'Valid empty environment filter'
    $limited=(Invoke-Cli @('process','peb','environment','query','--pid',$PID.ToString(),'--limit','1','--json') 6)|ConvertFrom-Json
    Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Environment output limit'
} finally {if($null -eq $savedProbe){Remove-Item Env:AA_KSwordR3PebProbe}else{$env:AA_KSwordR3PebProbe=$savedProbe}}
$memory=(Invoke-Cli @('process','memory','regions','query','--pid',$PID.ToString(),'--json') @(0,6))|ConvertFrom-Json
Assert ($memory.data.regionCount -match '^\d+$' -and [uint64]$memory.data.committedRegionCount -ge [uint64]$memory.data.returnedCount -and $memory.data.returnedCount -le 40) 'Bounded committed preview and safe counter strings'
foreach($r in $memory.data.regions) {
    $address=[Convert]::ToUInt64($r.base.Substring(2),16);$actual=[CliPebOracle]::Region($PID,$address)
    Assert ($r.base -eq ('0x{0:X}' -f $actual[0]) -and $r.size -eq $actual[1].ToString() -and [Convert]::ToUInt32($r.state.Substring(2),16) -eq $actual[2]) 'Independent virtual-region identity and extent'
}
$at=(Invoke-Cli @('process','memory','regions','query','--pid',$PID.ToString(),'--address',$self.data.imageBase,'--json') @(0,6))|ConvertFrom-Json
$actual=[CliPebOracle]::Region($PID,[Convert]::ToUInt64($self.data.imageBase.Substring(2),16))
Assert ($at.data.region.base -eq ('0x{0:X}' -f $actual[0]) -and $at.data.region.size -eq $actual[1].ToString() -and $at.data.region.type -eq '0x1000000') 'Single image-region query through shared backend'
Assert ((Invoke-Cli @('process','peb','query','--pid',$PID.ToString())).Contains('pebAddress:')) 'PEB text output'
Assert (((Invoke-Cli @('process','peb','query','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'PEB creation-time guard'
if($InGuest) {
    $target=Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();$guard=@('--pid',$target.Id.ToString(),'--creation-time',$born)
        $original=$target.ProcessorAffinity.ToInt64();$priority=$target.PriorityClass
        $first=[uint64]($original -band (-$original))
        $bad=(Invoke-Cli @('process','settings','set-affinity','--pid',$target.Id.ToString(),'--creation-time',([uint64]$born+1).ToString(),'--mask',$first.ToString(),'--confirm','--json') 3)|ConvertFrom-Json
        $target.Refresh();Assert ($bad.status -eq 'failed' -and $target.ProcessorAffinity.ToInt64() -eq $original) 'Mismatched affinity target unchanged'
        $set=(Invoke-Cli (@('process','settings','set-affinity')+$guard+@('--mask',$first.ToString(),'--confirm','--json')))|ConvertFrom-Json
        $target.Refresh();Assert ($set.data.verified -and $target.ProcessorAffinity.ToInt64() -eq $first -and $target.PriorityClass -eq $priority) 'Independent process affinity; priority preserved'
        $restore=(Invoke-Cli (@('process','settings','set-affinity')+$guard+@('--mask',$original.ToString(),'--confirm','--json')))|ConvertFrom-Json
        $target.Refresh();Assert ($restore.data.verified -and $target.ProcessorAffinity.ToInt64() -eq $original) 'Process affinity restored'
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli (@('process','peb','query')+$guard+@('--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited PEB target'
    } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
    $x86=Join-Path $env:WINDIR 'SysWOW64\notepad.exe'
    if(Test-Path -LiteralPath $x86) {
        $target=Start-Process $x86 -PassThru
        try {
            $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
            $wow=(Invoke-Cli @('process','peb','query','--pid',$target.Id.ToString(),'--creation-time',$born,'--view','auto','--json'))|ConvertFrom-Json
            Assert ($wow.data.view -eq 'wow64' -and $wow.data.parametersKnown -and $wow.data.imagePath.value -eq $target.Path) 'Actual WOW64 PEB selected and decoded'
            $native=(Invoke-Cli @('process','peb','query','--pid',$target.Id.ToString(),'--view','native','--json') @(0,3,6))|ConvertFrom-Json
            Assert ($native.data.view -eq 'native' -and $native.data.pebAddress -ne $wow.data.pebAddress) 'Explicit native and WOW64 views remain distinct'
        } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
    }
}
