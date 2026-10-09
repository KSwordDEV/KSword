param([Parameter(Mandatory=$true)][string]$Cli, [Parameter(Mandatory=$true)][ValidateSet('ping','trace-route','dns')][string]$Feature, [string]$ReportPath)
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
    'trace-route' {
        $help = Invoke-Cli @('help','network','trace-route','query')
        Assert ($help.Contains('--max-hops')) 'Trace route help'
        Assert ((Invoke-Cli @('network','trace-route','query','--help')) -eq $help) 'Trace inline help'
        foreach ($bad in @(
            @('network','trace-route','query','--json'),
            @('network','trace-route','query','--target','127.0.0.1','--max-hops','0','--json'),
            @('network','trace-route','query','--target','127.0.0.1','--max-hops','65','--json'),
            @('network','trace-route','query','--target','127.0.0.1','--backend','r0','--json'),
            @('network','trace-route','query','--target','127.0.0.1','--typo','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Trace parameter JSON' }
        $oracle = [Net.NetworkInformation.Ping]::new()
        try {
            $options = [Net.NetworkInformation.PingOptions]::new(1,$false)
            Assert ($oracle.Send('127.0.0.1',1000,(New-Object byte[] 32),$options).Status -eq [Net.NetworkInformation.IPStatus]::Success) 'Independent TTL 1 echo'
        } finally { $oracle.Dispose() }
        $trace = (Invoke-Cli @('network','trace-route','query','--target','127.0.0.1','--max-hops','2','--timeout-ms','1000','--json')) | ConvertFrom-Json
        Assert ($trace.status -eq 'success' -and $trace.data.reached -and $trace.data.attemptedHops -eq 1 -and $trace.data.hops.Count -eq 1) 'Loopback route'
        Assert ($trace.data.hops[0].hop -eq 1 -and $trace.data.hops[0].replied -and $trace.data.hops[0].status -eq 0 -and $trace.data.hops[0].address -eq '127.0.0.1') 'Hop fields'
        Assert ((Invoke-Cli @('network','trace-route','query','--target','127.0.0.1','--max-hops','1')).Contains('reached: true')) 'Trace text'
        $failure = (Invoke-Cli @('network','trace-route','query','--target','::1','--max-hops','1','--json') 3) | ConvertFrom-Json
        Assert (!$failure.data.reached -and $failure.data.win32Error -ne 0 -and $failure.data.attemptedHops -eq 0) 'Trace IPv6 rejection'
    }
    'dns' {
        $help = Invoke-Cli @('help','network','dns','query')
        Assert ($help.Contains('--name') -and $help.Contains('AAAA')) 'DNS help'
        Assert ((Invoke-Cli @('network','dns','query','--help')) -eq $help) 'DNS inline help'
        foreach ($bad in @(
            @('network','dns','query','--json'),
            @('network','dns','query','--name','localhost','--type','BOGUS','--json'),
            @('network','dns','query','--name','localhost','--backend','r0','--json'),
            @('network','dns','query','--name','localhost','--unknown','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'DNS parameter JSON' }
        $oracle = @([Net.Dns]::GetHostAddresses('localhost') | Where-Object AddressFamily -eq InterNetwork | ForEach-Object { $_.ToString() })
        $dns = (Invoke-Cli @('network','dns','query','--name','localhost','--type','A','--json')) | ConvertFrom-Json
        $answers = @($dns.data.records | Where-Object type -eq 1)
        Assert ($dns.status -eq 'success' -and $dns.data.win32Error -eq 0 -and $answers.Count -gt 0) 'Local DNS A record'
        foreach ($record in $answers) { Assert ($record.decoded -and $oracle -contains $record.fields.address) 'Independent DNS disagrees' }
        Assert ((Invoke-Cli @('network','dns','query','--name','localhost')).Contains('records:')) 'DNS text'
        $failure = (Invoke-Cli @('network','dns','query','--name','bad/host','--type','A','--json') 3) | ConvertFrom-Json
        Assert ($failure.data.win32Error -ne 0 -and $failure.data.records.Count -eq 0) 'DNS invalid name failure'
    }
}
Save-Report
