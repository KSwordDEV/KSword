param([ValidateSet('Listener','Client')][string]$Role,[int]$Port)
$ErrorActionPreference='Stop'
$root='C:\KSwordValidation\ActionAnalyzeWfp'
$marker='KSWORD_AA_WFP_VM_20261127_'+(Get-Content "$root\marker.txt" -Raw).Trim()
function Save($name,$value) { $value | ConvertTo-Json -Depth 5 | Set-Content -Encoding UTF8 "$root\$name" }
if ($Role -eq 'Client') {
    while (!(Test-Path "$root\release.signal") -and !(Test-Path "$root\stop.signal")) { Start-Sleep -Milliseconds 50 }
    if (Test-Path "$root\stop.signal") { exit 2 }
    $client=New-Object Net.Sockets.TcpClient
    try {
        $client.Connect('127.0.0.1',$Port); $client.NoDelay=$true
        $stream=$client.GetStream(); $payload=[Text.Encoding]::ASCII.GetBytes($marker+"`n")
        $stream.Write($payload,0,$payload.Length)
        Save 'client-result.json' @{sent=$true;marker=$marker;payloadLength=$payload.Length;pid=$PID;localEndpoint=$client.Client.LocalEndPoint.ToString()}
        while (!(Test-Path "$root\stop.signal")) { Start-Sleep -Milliseconds 50 }
    } finally { $client.Close() }
} else {
    $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,0)
    $listener.Start(); $Port=$listener.LocalEndpoint.Port
    $client=Start-Process powershell.exe -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File',"$root\Loopback.ps1",'-Role','Client','-Port',"$Port") -WindowStyle Hidden -PassThru
    $self=Get-Process -Id $PID
    Save 'state.json' @{sourceReady=$true;listenerPid=$PID;listenerCreationFileTime=$self.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();clientPid=$client.Id;clientCreationFileTime=$client.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();endpoint="127.0.0.1:$Port";marker=$marker}
    $connection=$null
    try {
        $deadline=[DateTime]::UtcNow.AddSeconds(60)
        while (!$listener.Pending()) { if ((Test-Path "$root\stop.signal") -or [DateTime]::UtcNow -gt $deadline) { throw 'Listener stopped before connection' }; Start-Sleep -Milliseconds 50 }
        $connection=$listener.AcceptTcpClient(); $stream=$connection.GetStream(); $buffer=New-Object byte[] 4096
        $length=$stream.Read($buffer,0,$buffer.Length); $received=[Text.Encoding]::ASCII.GetString($buffer,0,$length)
        Save 'listener-result.json' @{received=$true;receivedMarker=$received.Contains($marker);receivedHex=([BitConverter]::ToString($buffer,0,$length).Replace('-','').ToLower());bytes=$length}
        while (!(Test-Path "$root\stop.signal") -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 50 }
    } finally {
        if ($connection) { $connection.Close() }; $listener.Stop()
        if (!$client.WaitForExit(3000)) { $client.Kill(); $client.WaitForExit() }
        Save 'fixture-cleanup.json' @{cleanupConfirmed=$client.HasExited;clientExitCode=$client.ExitCode;listenerPid=$PID;clientPid=$client.Id}
    }
}
