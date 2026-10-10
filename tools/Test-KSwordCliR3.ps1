param([Parameter(Mandatory=$true)][string]$Cli, [Parameter(Mandatory=$true)][ValidateSet('ping','trace-route','dns','firewall','endpoint-audit','service','registry-browse','registry-search')][string]$Feature, [string]$ReportPath, [switch]$InGuest)
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
    'firewall' {
        $help = Invoke-Cli @('help','network','firewall','enum')
        Assert ($help.Contains('--name') -and $help.Contains('Read-only')) 'Firewall help'
        Assert ((Invoke-Cli @('network','firewall','enum','--help')) -eq $help) 'Firewall inline help'
        foreach ($bad in @(
            @('network','firewall','enum','--limit','-1','--json'),
            @('network','firewall','enum','--backend','r0','--json'),
            @('network','firewall','enum','--unknown','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Firewall parameter JSON' }
        $profile = Get-NetFirewallProfile
        $result = (Invoke-Cli @('network','firewall','enum','--limit','2','--json')) | ConvertFrom-Json
        Assert ($result.status -eq 'success' -and $result.data.complete -and $result.data.hresult -eq 0 -and $result.data.returnedCount -le 2) 'Firewall enumeration'
        foreach ($p in $profile) { Assert ($result.data.profiles.($p.Name.ToLower()) -eq ($p.Enabled.ToString() -eq 'True')) 'Independent firewall profile disagrees' }
        $empty = (Invoke-Cli @('network','firewall','enum','--name','KSwordCliDoesNotExist-9572481','--json')) | ConvertFrom-Json
        Assert ($empty.status -eq 'success' -and $empty.data.matchedCount -eq 0) 'Empty firewall result'
        Assert ((Invoke-Cli @('network','firewall','enum','--limit','1')).Contains('profiles:')) 'Firewall text'
        if ($InGuest) {
            $name = 'KSwordCliRule-' + [Guid]::NewGuid().ToString('N')
            try {
                New-NetFirewallRule -Name $name -DisplayName $name -Description 'KSword CLI R3 test' -Direction Inbound -Action Block -Protocol TCP -LocalPort 54321 -Profile Private -Enabled True | Out-Null
                $oracle = Get-NetFirewallRule -Name $name
                $port = $oracle | Get-NetFirewallPortFilter
                $actual = (Invoke-Cli @('network','firewall','enum','--name',$name,'--json')) | ConvertFrom-Json
                Assert ($actual.data.matchedCount -eq 1 -and $actual.data.rules[0].enabled -and $actual.data.rules[0].action -eq 0) 'Temporary firewall rule'
                Assert ($actual.data.rules[0].localPorts -eq $port.LocalPort -and $actual.data.rules[0].protocol -eq 6 -and $actual.data.rules[0].profiles -eq 2) 'Independent firewall tuple disagrees'
            } finally { Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }
        }
    }
    'endpoint-audit' {
        $group = Invoke-Cli @('help','network','endpoint-audit')
        Assert ($group.Contains('afd') -and $group.Contains('nsi') -and !$group.Contains('--limit')) 'Endpoint audit hierarchy'
        foreach ($kind in @('afd','nsi')) {
            $help = Invoke-Cli @('help','network','endpoint-audit',$kind,'query')
            Assert ($help.Contains('--limit')) 'Endpoint leaf help'
            Assert ((Invoke-Cli @('network','endpoint-audit',$kind,'query','--help')) -eq $help) 'Endpoint inline help'
            foreach ($bad in @(
                @('network','endpoint-audit',$kind,'query','--backend','r0','--json'),
                @('network','endpoint-audit',$kind,'query','--unknown','1','--json')
            )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Endpoint parameter JSON' }
            $result = (Invoke-Cli @('network','endpoint-audit',$kind,'query','--limit','1000','--json') @(0,6)) | ConvertFrom-Json
            Assert ($result.status -in @('success','partial') -and $result.data.source.Contains('private AFD/NSI objects are not queried')) 'Endpoint source and status'
            Assert (@($result.data.rows | Where-Object { !$_.available }).Count -eq 0) 'Unexpected unavailable endpoint table'
            if ($kind -eq 'nsi') {
                $active = @(Get-NetIPInterface -AddressFamily IPv4 -IncludeAllCompartments | Where-Object ConnectionState -eq Connected)
                Assert ($active.Count -gt 0) 'Independent interface oracle is empty'
                foreach ($oracle in $active) {
                    $row = @($result.data.rows | Where-Object { $_.fields.interfaceIndex -eq $oracle.InterfaceIndex })
                    Assert ($row.Count -eq 1) "Active interface absent from public projection: $($oracle.InterfaceIndex)"
                    if ($row[0].fields.type -eq 6) { Assert ($row[0].fields.mtu -eq $oracle.NlMtu) 'Independent Ethernet interface MTU disagrees' }
                }
            }
            $limited = (Invoke-Cli @('network','endpoint-audit',$kind,'query','--limit','0','--json') @(0,6)) | ConvertFrom-Json
            Assert ($limited.data.returnedCount -eq 0 -and $limited.data.displayTruncated) 'Endpoint display limit'
        }
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0)
        try {
            $listener.Start()
            $result = (Invoke-Cli @('network','endpoint-audit','afd','query','--limit','1000','--json') @(0,6)) | ConvertFrom-Json
            $row = @($result.data.rows | Where-Object { $_.fields.pid -eq $PID -and $_.fields.localPort -eq $listener.LocalEndpoint.Port })
            if ($InGuest -or !$result.data.backendTruncated) { Assert ($row.Count -eq 1 -and $row[0].fields.state -eq 2 -and $row[0].fields.localAddress -eq '127.0.0.1') 'Raw AFD TCP fields' }
            $oracle = Get-NetTCPConnection -LocalPort $listener.LocalEndpoint.Port -State Listen
            if ($row.Count) { Assert ($oracle.OwningProcess -eq $row[0].fields.pid) 'Independent AFD PID' }
        } finally { $listener.Stop() }
        if ($InGuest) {
            $listeners = [Collections.Generic.List[Net.Sockets.TcpListener]]::new()
            try {
                for ($i=0;$i -lt 140;$i++) { $l=[Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback,0);$l.Start();$listeners.Add($l) }
                $bounded = (Invoke-Cli @('network','endpoint-audit','afd','query','--limit','1000','--json') 6) | ConvertFrom-Json
                Assert ($bounded.status -eq 'partial' -and $bounded.data.backendTruncated -and !$bounded.data.displayTruncated) 'Backend cap must not pretend full evidence'
            } finally { foreach ($l in $listeners) { $l.Stop() } }
        }
    }
    'service' {
        $top=Invoke-Cli @('help')
        Assert ($top.Contains('service') -and !$top.Contains('set-start-type')) 'Service top help'
        $help=Invoke-Cli @('help','service','set-start-type')
        Assert ($help.Contains('--type') -and $help.Contains('--confirm')) 'Service start type help'
        Assert ((Invoke-Cli @('service','set-start-type','--help')) -eq $help) 'Service inline help'
        foreach ($bad in @(
            @('service','query','--json'),
            @('service','query','--name','EventLog','--backend','r0','--json'),
            @('service','enum','--bogus','1','--json'),
            @('service','stop','--name','EventLog','--json'),
            @('service','set-start-type','--name','EventLog','--type','BOGUS','--confirm','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Service invalid arguments' }
        $oracle=Get-Service EventLog
        $query=(Invoke-Cli @('service','query','--name','EventLog','--json')) | ConvertFrom-Json
        Assert ($query.data.hasConfig -and $query.data.hasStatus -and $query.data.state -eq [int]$oracle.Status) 'Independent SCM status'
        $enum=(Invoke-Cli @('service','enum','--name','eventlog','--json')) | ConvertFrom-Json
        Assert ($enum.data.matchedCount -eq 1 -and $enum.data.services[0].name -eq 'EventLog') 'Case-insensitive SCM name'
        $missing=(Invoke-Cli @('service','query','--name','KSwordCliMissing-9283147','--json') 3) | ConvertFrom-Json
        Assert ($missing.data.win32Error -eq 1060) 'Missing service raw error'
        $detail=(Invoke-Cli @('service','detail','query','--name','EventLog','--json') @(0,6)) | ConvertFrom-Json
        Assert ($detail.data.service.name -eq 'EventLog' -and $null -ne $detail.data.failureSettingsStatus.availability) 'Independent detail sections'
        Assert ((Invoke-Cli @('service','query','--name','EventLog')).Contains('binaryPath:')) 'Service text'
        if ($InGuest) {
            $name='KSwordCliService-'+[Guid]::NewGuid().ToString('N')
            $fixture=Join-Path $PSScriptRoot 'R3Fixture.exe'
            try {
                New-Service -Name $name -BinaryPathName ($fixture+' --service') -StartupType Manual -Description 'KSword CLI service fixture' | Out-Null
                foreach ($step in @(@('start',4),@('pause',7),@('continue',4),@('stop',1))) {
                    $arguments=@('service',$step[0],'--name',$name,'--json')
                    if ($step[0] -eq 'stop') { $arguments+='--confirm' }
                    $action=(Invoke-Cli $arguments) | ConvertFrom-Json
                    Assert ($action.data.requestSucceeded -and $action.data.verified -and $action.data.postcheck.state -eq $step[1]) 'Service transition result'
                    Assert ([int](Get-Service $name).Status -eq $step[1]) 'SCM transition oracle'
                }
                foreach ($step in @(@('delayed',2,1),@('automatic',2,0),@('disabled',4,0),@('manual',3,0))) {
                    $action=(Invoke-Cli @('service','set-start-type','--name',$name,'--type',$step[0],'--confirm','--json')) | ConvertFrom-Json
                    Assert ($action.data.verified -and $action.data.postcheck.startType -eq $step[1]) 'Service configuration result'
                    $registry=Get-ItemProperty ('HKLM:\SYSTEM\CurrentControlSet\Services\'+$name)
                    Assert ($registry.Start -eq $step[1]) 'SCM registry startup type'
                    if ($step[1] -eq 2) { Assert ($registry.DelayedAutoStart -eq $step[2]) 'SCM registry delayed flag' }
                }
                $details=(Invoke-Cli @('service','detail','query','--name',$name,'--json')) | ConvertFrom-Json
                Assert ($details.data.service.description -eq 'KSword CLI service fixture' -and $details.data.dependents.Count -eq 0) 'Fixture details'
            } finally {
                Stop-Service -Name $name -Force -ErrorAction SilentlyContinue
                & sc.exe delete $name | Out-Null
            }
        }
    }
    'registry-browse' {
        $help=Invoke-Cli @('help','registry','value','read')
        Assert ($help.Contains('--name') -and $help.Contains('--max-data-bytes')) 'Registry leaf help'
        Assert ((Invoke-Cli @('registry','value','read','--help')) -eq $help) 'Registry inline help'
        $legacy=Invoke-Cli @('help','registry','read-value')
        Assert ($legacy.Contains('Default/R0 syntax') -and $legacy.Contains('--backend r3')) 'Both registry backend forms'
        foreach ($bad in @(
            @('registry','value','read','--json'),
            @('registry','key','enum','--path','HKCU','--kind','BOGUS','--json'),
            @('registry','key','enum','--path','BADROOT','--json'),
            @('registry','key','enum','--path','HKCU','--backend','r0','--json'),
            @('registry','key','enum','--path','HKCU','--unknown','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Registry invalid arguments' }
        $path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $oracle=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion')
        try { $expected=$oracle.GetValue('ProductName') } finally { $oracle.Dispose() }
        $value=(Invoke-Cli @('registry','value','read','--path',$path,'--name','ProductName','--max-data-bytes','4096','--json')) | ConvertFrom-Json
        Assert ($value.data.type -eq 1 -and $value.data.dataText -eq $expected -and !$value.data.dataTruncated) 'Independent registry string disagrees'
        $hex=([BitConverter]::ToString([Text.Encoding]::Unicode.GetBytes($expected+[char]0))).Replace('-','').ToLower()
        Assert ($value.data.dataHex -eq $hex) 'Exact raw registry bytes'
        $alias=(Invoke-Cli @('registry','read-value','--key',$path,'--value','ProductName','--backend','r3','--max-data-bytes','4096','--json')) | ConvertFrom-Json
        Assert ($alias.data.dataHex -eq $hex) 'Explicit R3 legacy alias'
        $limited=(Invoke-Cli @('registry','value','read','--path',$path,'--name','ProductName','--max-data-bytes','0','--json')) | ConvertFrom-Json
        Assert ($limited.data.dataTruncated -and $limited.data.returnedBytes -eq '0' -and $limited.data.dataHex -eq '') 'Registry data preview limit'
        $missing=(Invoke-Cli @('registry','value','read','--path',$path,'--name','KSwordCliMissing-981731','--json') 3) | ConvertFrom-Json
        Assert ($missing.data.win32Error -eq 2) 'Missing value Win32 code'
        Assert ((Invoke-Cli @('registry','value','read','--path',$path,'--name','ProductName')).Contains('typeName: REG_SZ')) 'Registry text'
        if ($InGuest) {
            Invoke-Cli @('registry','read-value','--key',$path) 2 | Out-Null
            Invoke-Cli @('registry','read-value','--key',$path,'--backend','r0') 2 | Out-Null
            $sub='Software\KSwordCliRegistry-'+[Guid]::NewGuid().ToString('N')
            $key=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sub)
            try {
                $key.SetValue('','默认值 测试',[Microsoft.Win32.RegistryValueKind]::String)
                $key.SetValue('DWORD',305419896,[Microsoft.Win32.RegistryValueKind]::DWord)
                $key.SetValue('Binary',[byte[]]@(0,255,34,92),[Microsoft.Win32.RegistryValueKind]::Binary)
                $child=$key.CreateSubKey('Child');$child.Dispose()
                $path='HKCU\'+$sub
                $default=(Invoke-Cli @('registry','value','read','--path',$path,'--name','','--json')) | ConvertFrom-Json
                Assert ($default.data.dataText -eq '默认值 测试') 'Default Unicode value'
                $enum=(Invoke-Cli @('registry','key','enum','--path',$path,'--json')) | ConvertFrom-Json
                Assert ($enum.data.complete -and $enum.data.matchedCount -eq 4) 'Direct key/value enumeration'
                $binary=@($enum.data.entries | Where-Object name -eq Binary)
                Assert ($binary[0].dataHex -eq '00ff225c' -and $binary[0].type -eq 3) 'Raw binary value'
                $keys=(Invoke-Cli @('registry','key','enum','--path',$path,'--kind','keys','--json')) | ConvertFrom-Json
                Assert ($keys.data.matchedCount -eq 1 -and $keys.data.entries[0].kind -eq 'key') 'Key kind filter'
                $empty=(Invoke-Cli @('registry','key','enum','--path',($path+'\Child'),'--json')) | ConvertFrom-Json
                Assert ($empty.data.complete -and $empty.data.matchedCount -eq 0) 'Valid empty key'
                $created=$key.CreateSubKey('Denied');$created.Dispose()
                $denied=$key.OpenSubKey('Denied',[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::FullControl)
                try {
                    $security=$denied.GetAccessControl()
                    $modified=$denied.GetAccessControl()
                    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
                    $rule=[Security.AccessControl.RegistryAccessRule]::new($sid,[Security.AccessControl.RegistryRights]::ReadKey,[Security.AccessControl.InheritanceFlags]::None,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Deny)
                    $modified.AddAccessRule($rule);$denied.SetAccessControl($modified)
                    try {
                        $failure=(Invoke-Cli @('registry','key','enum','--path',($path+'\Denied'),'--json') 3) | ConvertFrom-Json
                        Assert ($failure.data.win32Error -eq 5 -and !$failure.data.complete) 'Registry access denied'
                    } finally { $modified.RemoveAccessRuleSpecific($rule);$denied.SetAccessControl($modified) }
                } finally { $denied.Dispose() }
            } finally { $key.Dispose();[Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sub,$false) }
        }
    }
    'registry-search' {
        $help=Invoke-Cli @('help','registry','search','query')
        Assert ($help.Contains('--max-depth') -and $help.Contains('Ctrl+C')) 'Registry search help'
        Assert ((Invoke-Cli @('registry','search','query','--help')) -eq $help) 'Search inline help'
        foreach ($bad in @(
            @('registry','search','query','--json'),
            @('registry','search','query','--path','HKCU','--query','','--json'),
            @('registry','search','query','--path','BADROOT','--query','a','--json'),
            @('registry','search','query','--path','HKCU','--query','a','--backend','r0','--json'),
            @('registry','search','query','--path','HKCU','--query','a','--unknown','1','--json')
        )) { Assert (((Invoke-Cli $bad 1) | ConvertFrom-Json).status -eq 'failed') 'Search invalid arguments' }
        $path='HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $query=(Invoke-Cli @('registry','search','query','--path',$path,'--query','ProductName','--max-results','1','--json') 6) | ConvertFrom-Json
        Assert ($query.data.stopReason -eq 'result-limit' -and $query.data.hits.Count -eq 1 -and $query.data.hits[0].name -eq 'ProductName') 'System registry search result'
        Assert ((Invoke-Cli @('registry','search','query','--path',$path,'--query','ProductName','--max-results','1') 6).Contains('stopReason: result-limit')) 'Search text'
        $missing=(Invoke-Cli @('registry','search','query','--path','HKCU\Software\KSwordCliMissing-287213','--query','a','--json') 3) | ConvertFrom-Json
        Assert ($missing.data.stopReason -eq 'read-failure' -and $missing.data.firstWin32Error -eq 2) 'Search missing root raw error'
        if ($InGuest) {
            $sub='Software\KSwordCliSearch-'+[Guid]::NewGuid().ToString('N')
            $root=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($sub)
            try {
                $root.SetValue('Needle','root data',[Microsoft.Win32.RegistryValueKind]::String)
                $root.SetValue('Second','unrelated',[Microsoft.Win32.RegistryValueKind]::String)
                $child=$root.CreateSubKey('NeedleChild')
                try {
                    $child.SetValue('Other','NEEDLE 数据',[Microsoft.Win32.RegistryValueKind]::String)
                    $child.SetValue('LongPreview',('x'*100),[Microsoft.Win32.RegistryValueKind]::String)
                    $grandchild=$child.CreateSubKey('GrandNeedle');$grandchild.Dispose()
                } finally {$child.Dispose()}
                $path='HKCU\'+$sub
                $result=(Invoke-Cli @('registry','search','query','--path',$path,'--query','needle','--json')) | ConvertFrom-Json
                Assert ($result.data.complete -and $result.data.hits.Count -eq 5 -and $result.data.counters.visitedKeys -eq '3') 'Case-insensitive keys, value names and data search'
                Assert (@($result.data.hits | Where-Object {$_.name -eq 'Other' -and $_.dataPreview -eq 'NEEDLE 数据'}).Count -eq 1) 'Actual Unicode data preview'
                $empty=(Invoke-Cli @('registry','search','query','--path',$path,'--query','UniqueAbsentKeyword-718431','--json')) | ConvertFrom-Json
                Assert ($empty.data.complete -and $empty.data.hits.Count -eq 0) 'Complete search without hits'
                $bounded=(Invoke-Cli @('registry','search','query','--path',$path,'--query','needle','--max-results','1','--json') 6) | ConvertFrom-Json
                Assert ($bounded.data.stopReason -eq 'result-limit') 'Search result budget'
                $depth=(Invoke-Cli @('registry','search','query','--path',$path,'--query','needle','--max-depth','1','--json') 6) | ConvertFrom-Json
                Assert ($depth.data.stopReason -eq 'depth-limit' -and $depth.data.counters.skippedDepth -eq '1') 'Search depth budget'
                $values=(Invoke-Cli @('registry','search','query','--path',$path,'--query','needle','--max-values','1','--json') 6) | ConvertFrom-Json
                Assert ($values.data.stopReason -eq 'value-limit') 'Search value budget'
                $preview=(Invoke-Cli @('registry','search','query','--path',$path,'--query','LongPreview','--max-preview-bytes','16','--json')) | ConvertFrom-Json
                Assert ($preview.data.hits.Count -eq 1 -and $preview.data.hits[0].previewTruncated -and $preview.data.hits[0].dataBytes -eq '202') 'Unread oversized preview stays marked'
                $defaults=(Invoke-Cli @('registry','search','query','--path',$path,'--query','needle','--max-keys','0','--max-depth','1000','--json')) | ConvertFrom-Json
                Assert ($defaults.data.effectiveBudgets.keys -eq '2000' -and $defaults.data.effectiveBudgets.depth -eq '32') 'Backend budget normalization'
            } finally {$root.Dispose();[Microsoft.Win32.Registry]::CurrentUser.DeleteSubKeyTree($sub,$false)}
        }
    }
}
Save-Report
