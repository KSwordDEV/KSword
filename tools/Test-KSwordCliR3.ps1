param([Parameter(Mandatory=$true)][string]$Cli, [Parameter(Mandatory=$true)][ValidateSet('ping')][string]$Feature, [string]$ReportPath)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\KswordCliR3TestSupport.ps1"
switch ($Feature) {
    'ping' {
        $leaf = Invoke-Cli @('help','network','ping','query')
        Assert ($leaf.Contains('--target') -and $leaf.Contains('--count')) 'Ping help'
        Assert ((Invoke-Cli @('network','ping','query','--help')) -eq $leaf) 'Ping inline help'
        Assert (!(Invoke-Cli @('help','network')).Contains('--count')) 'Family must not expand ping leaves'
        foreach ($bad in @(
            @('network','ping','query','--json'),
            @('network','ping','query','--target','127.0.0.1','--count','0','--json'),
            @('network','ping','query','--target','127.0.0.1','--count','33','--json'),
            @('network','ping','query','--target','127.0.0.1','--timeout-ms','0','--json'),
            @('network','ping','query','--target','127.0.0.1','--backend','r0','--json'),
            @('network','ping','query','--target','127.0.0.1','--unknown','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Ping parameter JSON' }
        $oracle = [Net.NetworkInformation.Ping]::new()
        try { Assert ($oracle.Send('127.0.0.1',1000).Status -eq [Net.NetworkInformation.IPStatus]::Success) 'Independent ping' }
        finally { $oracle.Dispose() }
        $ping = (Invoke-Cli @('network','ping','query','--target','127.0.0.1','--count','2','--timeout-ms','1000','--json')) | ConvertFrom-Json
        Assert ($ping.status -eq 'success' -and $ping.data.sent -eq 2 -and $ping.data.received -eq 2 -and $ping.data.lossPercent -eq 0) 'Ping statistics'
        Assert ($ping.data.probes.Count -eq 2 -and @($ping.data.probes | Where-Object { $_.status -ne 0 -or !$_.replied -or $_.dataBytes -ne 32 }).Count -eq 0) 'Ping probe data'
        Assert ((Invoke-Cli @('network','ping','query','--target','127.0.0.1','--count','1')).Contains('received: 1')) 'Ping text'
        $errorResult = (Invoke-Cli @('network','ping','query','--target','::1','--count','1','--json') 3) | ConvertFrom-Json
        Assert ($errorResult.data.win32Error -ne 0 -and $errorResult.data.sent -eq 0) 'IPv6 cannot pretend an IPv4 ping succeeded'
    }
}
Save-Report
