param([Parameter(Mandatory=$true)][string]$Cli, [string]$ReportPath, [switch]$AllowNativeCloseFailure)
$ErrorActionPreference = 'Stop'
$records = [System.Collections.Generic.List[object]]::new()
function Invoke-Cli([string[]]$Arguments, [int[]]$Expected = @(0)) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $Cli
    $info.Arguments = $Arguments -join ' '
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.StandardOutputEncoding = [Text.Encoding]::UTF8
    $info.StandardErrorEncoding = [Text.Encoding]::UTF8
    $p = [Diagnostics.Process]::Start($info)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if (!$p.WaitForExit(30000)) { $p.Kill(); throw 'CLI timeout' }
    $out = $outTask.GetAwaiter().GetResult()
    $err = $errTask.GetAwaiter().GetResult()
    $records.Add([pscustomobject]@{arguments=$Arguments;code=$p.ExitCode;stdout=$out;stderr=$err})
    if ($p.ExitCode -notin $Expected) { throw "Expected $Expected got $($p.ExitCode): $err $out" }
    return $out
}
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
$listener = $null; $client = $null; $server = $null; $udp = $null
try {
    $top = Invoke-Cli @('help')
    Assert ($top.Contains('network') -and !$top.Contains('connections enum')) 'Top help must be shallow'
    $family = Invoke-Cli @('help','network')
    Assert ($family.Contains('connections') -and !$family.Contains('--local-address')) 'Family help must be shallow'
    $group = Invoke-Cli @('help','network','connections')
    Assert ($group.Contains('enum') -and $group.Contains('close')) 'Missing connection leaves'
    $help = Invoke-Cli @('help','network','connections','close')
    Assert ($help.Contains('--local-address') -and $help.Contains('--confirm')) 'Missing close syntax'
    Assert ((Invoke-Cli @('network','connections','close','--help')) -eq $help) 'Inline help differs'
    Assert ((Invoke-Cli @('network','connections','help')) -eq $group) 'Group help differs'
    foreach ($bad in @(
        @('network','connections','enum','--backend','r0','--json'),
        @('network','connections','enum','--protocol','oops','--json'),
        @('network','connections','enum','--limti','1','--json'),
        @('network','connections','enum','--pid','4294967296','--json'),
        @('network','connections','enum','--limit','-1','--json'),
        @('network','connections','close','--json')
    )) {
        $errorResult = (Invoke-Cli $bad 1) | ConvertFrom-Json
        Assert ($errorResult.status -eq 'failed') 'Argument failure JSON'
    }
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
    $listener.Start()
    $client = [Net.Sockets.TcpClient]::new()
    $client.Connect('127.0.0.1', $listener.LocalEndpoint.Port)
    $server = $listener.AcceptTcpClient()
    $udp = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new([Net.IPAddress]::Loopback,0))
    $json = (Invoke-Cli @('network','connections','enum','--pid',"$PID",'--limit','1000','--json')) | ConvertFrom-Json
    Assert ($json.schemaVersion -eq 1 -and $json.backend -eq 'r3' -and $json.status -eq 'success') 'Envelope'
    $local = $client.Client.LocalEndPoint.Port
    $remote = $client.Client.RemoteEndPoint.Port
    $tuple = @($json.data.entries | Where-Object { $_.protocol -eq 'tcp4' -and $_.localPort -eq $local -and $_.remotePort -eq $remote })
    Assert ($tuple.Count -eq 1 -and $tuple[0].state -eq 5 -and $tuple[0].canClose) 'Live TCP tuple not found'
    $independent = @(Get-NetTCPConnection -LocalPort $local -RemotePort $remote -State Established)
    Assert ($independent.Count -eq 1 -and $independent[0].OwningProcess -eq $PID) 'Independent TCP owner disagrees'
    $udpRows = @($json.data.entries | Where-Object { $_.protocol -eq 'udp4' -and $_.localPort -eq $udp.Client.LocalEndPoint.Port })
    Assert ($udpRows.Count -eq 1 -and $null -eq $udpRows[0].state -and !$udpRows[0].canClose) 'UDP row semantics'
    $limited = (Invoke-Cli @('network','connections','enum','--pid',"$PID",'--limit','0','--json')) | ConvertFrom-Json
    Assert ($limited.data.returnedCount -eq 0 -and $limited.data.matchedCount -ge 3 -and $limited.data.truncated) 'Display limit semantics'
    $text = Invoke-Cli @('network','connections','enum','--pid',"$PID",'--limit','1')
    Assert ($text.Contains('backend=r3') -and $text.Contains('localAddress:')) 'Readable text output'
    $closeArgs = @('network','connections','close','--pid',"$PID",'--local-address','127.0.0.1','--local-port',"$local",'--remote-address','127.0.0.1','--remote-port',"$remote",'--confirm','--json')
    $allowed = if ($AllowNativeCloseFailure) { @(0,3) } else { @(0) }
    $closed = (Invoke-Cli $closeArgs $allowed) | ConvertFrom-Json
    $closeSuccessMeasured = $closed.status -eq 'success'
    if (!$closeSuccessMeasured) {
        Assert ($closed.status -eq 'failed' -and $closed.data.win32Error -eq 317 -and !$closed.data.requestSucceeded -and $closed.data.postcheckPresent -and $closed.data.postcheckComplete) 'Native failure must retain actual present tuple evidence'
        Assert (@(Get-NetTCPConnection -LocalPort $local -RemotePort $remote -State Established).Count -eq 1) 'Failed CLI close changed live tuple'
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class KSwordTcpCloseOracle {
    [StructLayout(LayoutKind.Sequential)] public struct Row { public uint State, LocalAddr, LocalPort, RemoteAddr, RemotePort; }
    [DllImport("iphlpapi.dll")] static extern uint GetExtendedTcpTable(IntPtr data, ref uint size, bool sorted, uint family, uint tableClass, uint reserved);
    [DllImport("iphlpapi.dll")] static extern uint SetTcpEntry(ref Row row);
    public static uint Close(int local, int remote, uint owner) {
        uint size=0;
        if(GetExtendedTcpTable(IntPtr.Zero,ref size,false,2,5,0)!=122) throw new Exception("TCP table size failed");
        IntPtr buffer=Marshal.AllocHGlobal(checked((int)size));
        try {
            if(GetExtendedTcpTable(buffer,ref size,false,2,5,0)!=0) throw new Exception("TCP table read failed");
            int count=Marshal.ReadInt32(buffer);
            for(int i=0;i<count;i++) {
                IntPtr p=IntPtr.Add(buffer,checked(4+i*24));
                Row row=Marshal.PtrToStructure<Row>(p);
                uint lp=((row.LocalPort&255)<<8)|((row.LocalPort>>8)&255);
                uint rp=((row.RemotePort&255)<<8)|((row.RemotePort>>8)&255);
                if(lp==local && rp==remote && row.State==5 && unchecked((uint)Marshal.ReadInt32(p,20))==owner) {
                    row.State=12;
                    return SetTcpEntry(ref row);
                }
            }
            throw new Exception("Owned tuple not found");
        } finally { Marshal.FreeHGlobal(buffer); }
    }
}
'@
        $native = [KSwordTcpCloseOracle]::Close($local,$remote,[uint32]$PID)
        Assert ($native -eq 317 -and @(Get-NetTCPConnection -LocalPort $local -RemotePort $remote -State Established).Count -eq 1) 'Independent native API must reproduce 317 without closing the fixture'
        # Dispose our own socket explicitly; stale-tuple test below must still fail.
        $client.Dispose();$client=$null
    } else {
    Assert ($closed.data.requestSucceeded -and !$closed.data.postcheckPresent -and $closed.data.postcheckComplete) 'Close postcheck'
    $server.ReceiveTimeout = 5000
    $disconnected = $false
    try { $buffer = New-Object byte[] 1; $disconnected = ($server.Client.Receive($buffer) -eq 0) }
    catch [Net.Sockets.SocketException] { $disconnected = ($_.Exception.SocketErrorCode -eq [Net.Sockets.SocketError]::ConnectionReset) }
    Assert $disconnected 'Peer socket did not disconnect'
    }
    $missing = (Invoke-Cli $closeArgs 3) | ConvertFrom-Json
    Assert ($missing.status -eq 'failed') 'Stale tuple must fail'
    $listenResult = (Invoke-Cli @('network','connections','close','--pid',"$PID",'--local-address','127.0.0.1','--local-port',"$remote",'--remote-address','0.0.0.0','--remote-port','0','--confirm','--json') 5) | ConvertFrom-Json
    Assert ($listenResult.status -eq 'unsupported') 'Listener must be unsupported'
    $service = Get-Service KswordARK -ErrorAction SilentlyContinue
    $driverState = if ($service) { $service.Status.ToString() } else { 'Absent' }
    $result = [pscustomobject]@{success=$true;closeSuccessMeasured=$closeSuccessMeasured;nativeCloseError=if($closeSuccessMeasured){0}else{$native};os=[Environment]::OSVersion.VersionString;sha256=(Get-FileHash $Cli).Hash;driver=$driverState;cases=$records}
    if ($ReportPath) { $result | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $ReportPath -Encoding UTF8 }
    Write-Output "R3_CONNECTIONS_PASS cases=$($records.Count)"
} finally {
    if ($server) { $server.Dispose() }; if ($client) { $client.Dispose() }; if ($udp) { $udp.Dispose() }; if ($listener) { $listener.Stop() }
}
