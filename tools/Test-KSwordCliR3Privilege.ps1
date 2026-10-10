$help = Invoke-Cli @('help','privilege','run')
Assert ($help.Contains('--enable') -and $help.Contains('restore')) 'Privilege run help'
Assert ((Invoke-Cli @('privilege','run','--help')) -eq $help) 'Privilege inline help'
Assert (!(Invoke-Cli @('help','privilege')).Contains('--enable')) 'Privilege shallow family help'
foreach ($bad in @(
    @('privilege','query','--backend','r0','--json'),
    @('privilege','query','--unknown','1','--json'),
    @('privilege','query','--limit','-1','--json'),
    @('privilege','run','--json','--','privilege','query'),
    @('privilege','run','--enable','SeDebugPrivilege','--json'),
    @('privilege','run','--enable','SeDebugPrivilege,','--json','--','privilege','query'),
    @('privilege','run','--enable','SeDebugPrivilege','--disable','sedebugprivilege','--json','--','privilege','query')
)) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Privilege parameter JSON' }
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class CliPrivilegeOracle {
 [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,IntPtr b,uint n,out uint r);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool LookupPrivilegeName(string s,IntPtr l,System.Text.StringBuilder b,ref uint n);
 public static Dictionary<string,bool> Read() { IntPtr t; if(!OpenProcessToken(GetCurrentProcess(),8,out t))throw new Exception("token");
 try {uint n; GetTokenInformation(t,3,IntPtr.Zero,0,out n); IntPtr b=Marshal.AllocHGlobal((int)n);
 try {if(!GetTokenInformation(t,3,b,n,out n))throw new Exception("query"); int c=Marshal.ReadInt32(b); var d=new Dictionary<string,bool>();
 for(int i=0;i<c;i++){IntPtr l=IntPtr.Add(b,4+12*i);uint z=256;var text=new System.Text.StringBuilder(256);if(!LookupPrivilegeName(null,l,text,ref z))throw new Exception("name");d.Add(text.ToString(),(Marshal.ReadInt32(l,8)&2)!=0);}return d;
 }finally{Marshal.FreeHGlobal(b);}}finally{CloseHandle(t);}}
}
'@
$oracle=[CliPrivilegeOracle]::Read()
$baseline=(Invoke-Cli @('privilege','query','--json')) | ConvertFrom-Json
Assert ($baseline.data.token.userSid -eq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) 'Independent token identity'
Assert ($baseline.data.privileges.Count -eq $oracle.Count -and $baseline.data.totalCount -eq $oracle.Count) 'Independent privilege count'
foreach ($p in $baseline.data.privileges) {Assert ($oracle.ContainsKey($p.name) -and $oracle[$p.name] -eq $p.enabled) 'Independent privilege attributes'}
Assert ((Invoke-Cli @('privilege','query','--limit','1')).Contains('returnedCount: 1')) 'Privilege text output'
$empty=(Invoke-Cli @('privilege','query','--name','NoSuchPrivilege','--json')) | ConvertFrom-Json
Assert ($empty.data.matchedCount -eq 0) 'Valid empty privilege filter'
if ($InGuest) {
    foreach ($verb in @('--disable','--enable')) {
        $scope=(Invoke-Cli @('privilege','run',$verb,'SeChangeNotifyPrivilege','--json','--','privilege','query','--name','SeChangeNotifyPrivilege','--json')) | ConvertFrom-Json
        $nested=$scope.data.stdout | ConvertFrom-Json
        Assert ($scope.data.executed -and $scope.data.restored -and $scope.data.pid -eq $nested.data.pid -and $scope.data.exitCode -eq 0) 'Same process execution and restoration'
        Assert ($nested.data.privileges[0].enabled -eq ($verb -eq '--enable') -and $scope.data.adjustments[0].verified -and $scope.data.restorations[0].verified) 'Scoped privilege state and readback'
        Assert ($scope.data.restorations[0].observedEnabled -eq $oracle['SeChangeNotifyPrivilege']) 'Original privilege restored'
    }
    $bad=(Invoke-Cli @('privilege','run','--enable','NoSuchPrivilege','--json','--','help') 3) | ConvertFrom-Json
    Assert (!$bad.data.executed -and $bad.data.adjustments[0].win32Error -eq 1313) 'Invalid privilege cannot execute command'
    $absent=(Invoke-Cli @('privilege','run','--enable','SeCreateTokenPrivilege','--json','--','help') 3) | ConvertFrom-Json
    Assert (!$absent.data.executed -and $absent.data.adjustments[0].win32Error -eq 1300) 'Cannot grant unassigned privilege'
    $rollback=(Invoke-Cli @('privilege','run','--disable','SeChangeNotifyPrivilege,NoSuchPrivilege','--json','--','help') 3) | ConvertFrom-Json
    Assert (!$rollback.data.executed -and $rollback.data.restored -and $rollback.data.restorations[0].verified) 'Restore earlier changes after adjustment failure'
    $badChild=(Invoke-Cli @('privilege','run','--disable','SeChangeNotifyPrivilege','--json','--','privilege','query','--bad','1') 1) | ConvertFrom-Json
    Assert ($badChild.data.executed -and $badChild.data.exitCode -eq 1 -and $badChild.data.restored) 'Child failure and restoration'
    $childHelp=(Invoke-Cli @('privilege','run','--disable','SeChangeNotifyPrivilege','--json','--','privilege','query','--help')) | ConvertFrom-Json
    Assert ($childHelp.data.executed -and $childHelp.data.stdout.Contains('Command: privilege query') -and $childHelp.data.restored) 'Tail help belongs to nested command'
    $text=Invoke-Cli @('privilege','run','--disable','SeChangeNotifyPrivilege','--','privilege','query','--name','SeChangeNotifyPrivilege','--json')
    Assert ($text.StartsWith('command=privilege run') -and $text.Contains('restored: true')) 'Nested JSON does not select outer JSON'
    $nestedScope=(Invoke-Cli @('privilege','run','--disable','SeChangeNotifyPrivilege','--json','--','privilege','run','--enable','SeChangeNotifyPrivilege','--json','--','privilege','query','--name','SeChangeNotifyPrivilege','--json')) | ConvertFrom-Json
    $inner=$nestedScope.data.stdout | ConvertFrom-Json; $read=$inner.data.stdout | ConvertFrom-Json
    Assert ($nestedScope.data.restored -and $inner.data.restored -and $read.data.privileges[0].enabled -and !$inner.data.restorations[0].observedEnabled) 'Nested scopes restore their own original states'
    $after=(Invoke-Cli @('privilege','query','--name','SeChangeNotifyPrivilege','--json')) | ConvertFrom-Json
    Assert ($after.data.privileges[0].enabled -eq $oracle['SeChangeNotifyPrivilege']) 'Fresh process privilege state unchanged'
}
