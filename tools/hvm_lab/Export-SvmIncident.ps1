# Read-only collection. Never starts/stops a service or a VM, and never resets the recorder.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$Ctl,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string]$Vmx,
    [ValidateRange(1,60)][int]$TimeoutSeconds=15
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Ctl=(Resolve-Path -LiteralPath $Ctl).Path
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a new evidence directory; existing evidence is never overwritten.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory=(Resolve-Path -LiteralPath $EvidenceDirectory).Path
$journal=Join-Path $EvidenceDirectory 'journal.txt'
function Save-Query([string]$Command) {
    if ($Command -notin @('status','metrics')) { throw 'Only read-only queries are permitted.' }
    Add-Content -LiteralPath $journal -Value "$(Get-Date -Format o) before $Command"
    $si=New-Object System.Diagnostics.ProcessStartInfo
    $si.FileName=$Ctl; $si.Arguments="--json $Command"
    $si.UseShellExecute=$false; $si.CreateNoWindow=$true
    $si.RedirectStandardOutput=$true; $si.RedirectStandardError=$true
    $p=New-Object System.Diagnostics.Process
    $p.StartInfo=$si
    if (!$p.Start()) { throw "Could not start $Command" }
    $stdout=$p.StandardOutput.ReadToEndAsync(); $stderr=$p.StandardError.ReadToEndAsync()
    if (!$p.WaitForExit($TimeoutSeconds*1000)) {
        Add-Content -LiteralPath $journal -Value "TIMEOUT $Command pid=$($p.Id); process/driver retained; no rollback inferred"
        throw "Read-only query timed out; process $($p.Id) was not terminated."
    }
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory "$Command.json"),$stdout.GetAwaiter().GetResult())
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory "$Command.stderr.txt"),$stderr.GetAwaiter().GetResult())
    $exit=$p.ExitCode; $p.Dispose()
    Add-Content -LiteralPath $journal -Value "$(Get-Date -Format o) after $Command exit=$exit"
    if ($exit -ne 0) { throw "$Command failed; raw output retained." }
}
function Copy-SharedFile([string]$Source,[string]$Destination) {
    $inputFile=[IO.File]::Open($Source,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    try {
        $outputFile=[IO.File]::Open($Destination,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        try { $inputFile.CopyTo($outputFile) } finally { $outputFile.Dispose() }
    } finally { $inputFile.Dispose() }
}
try {
    Get-FileHash -LiteralPath $Ctl -Algorithm SHA256 | ConvertTo-Json | Set-Content (Join-Path $EvidenceDirectory 'cli-identity.json') -Encoding UTF8
    # These are observed OS/SCM values, not proof of the loaded kernel image's hash.
    try {
        $os=Get-CimInstance Win32_OperatingSystem
        $service=Get-CimInstance Win32_SystemDriver -Filter "Name='KswordARK'"
        [ordered]@{machine=$env:COMPUTERNAME;build=$os.BuildNumber;bootId=$os.LastBootUpTime.ToUniversalTime().ToString('o');
            service=@($service | Select-Object Name,State,PathName);loadedImageIdentityVerified=$false} |
            ConvertTo-Json -Depth 5 | Set-Content (Join-Path $EvidenceDirectory 'environment.json') -Encoding UTF8
    } catch { Add-Content -LiteralPath $journal -Value "Environment metadata unavailable: $($_.Exception.Message)" }
    $identity=Join-Path (Split-Path -Parent $Ctl) 'identity.json'
    if (Test-Path -LiteralPath $identity) { Copy-SharedFile $identity (Join-Path $EvidenceDirectory 'candidate-identity.json') }
    # Preserve VMware logs even if the device query later fails or the driver is older.
    if ($Vmx) {
        $Vmx=(Resolve-Path -LiteralPath $Vmx).Path
        Copy-SharedFile $Vmx (Join-Path $EvidenceDirectory 'machine.vmx')
        $log=Join-Path (Split-Path -Parent $Vmx) 'vmware.log'
        if (Test-Path -LiteralPath $log) { Copy-SharedFile $log (Join-Path $EvidenceDirectory 'vmware.log') }
    }
    Save-Query 'status'
    Save-Query 'metrics'
    $metrics=[IO.File]::ReadAllText((Join-Path $EvidenceDirectory 'metrics.json')) | ConvertFrom-Json
    if ($metrics.version -notin @(6,7,8,9) -or $metrics.backend -ne 2) { throw 'A matching metrics v6/v7/v8/v9 AMD driver and CLI are required.' }
    $latched=0; $incoherent=0; $seen=@{}
    foreach ($cpu in $metrics.svmProcessors) {
        $group=[int]$cpu.group; $number=[int]$cpu.number
        if ($group -lt 0 -or $group -gt 65535 -or $number -lt 0 -or $number -gt 255) { throw 'Invalid CPU identity.' }
        $id="cpu-$group-$number"
        if ($seen.ContainsKey($id)) { throw 'Duplicate CPU in metrics.' }; $seen[$id]=$true
        if ($cpu.flight.coherent -ne 1) { ++$incoherent; continue }
        if ($cpu.flight.latched -ne 1) { continue }
        ++$latched
        foreach ($field in @('vmcb12Hex','currentVmcbHex')) {
            $hex=[string]$cpu.flight.$field
            if ($hex.Length -ne 8192 -or $hex -notmatch '\A[0-9a-fA-F]+\z') { throw "Malformed $id $field" }
            $bytes=New-Object byte[] 4096
            for ($i=0; $i -lt 4096; ++$i) { $bytes[$i]=[Convert]::ToByte($hex.Substring($i*2,2),16) }
            [IO.File]::WriteAllBytes((Join-Path $EvidenceDirectory "$id-$field.bin"),$bytes)
        }
    }
    [ordered]@{kind='svm-incident-export';result='COLLECTED';latchedCpus=$latched;incoherentCpus=$incoherent;
        note='Zero latched CPUs is not a pass; inspect raw logs. No stop/reset/unload was requested.';
        evidence=$EvidenceDirectory} | ConvertTo-Json | Tee-Object -FilePath (Join-Path $EvidenceDirectory 'summary.json')
} finally {
    # Partial collections retain hashes too, including timeout/error journals.
    @(Get-ChildItem -LiteralPath $EvidenceDirectory -File | Where-Object Name -ne 'manifest.json' | ForEach-Object {
        [ordered]@{file=$_.Name;bytes=$_.Length;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
    }) | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $EvidenceDirectory 'manifest.json') -Encoding UTF8
}
