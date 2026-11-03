param(
    [Parameter(Mandatory=$true)][string]$ReleaseDir,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$LocalReportRoot,
    [switch]$MetricsOnly
)
$ErrorActionPreference='Stop'
$expectedGuest='DESKTOP-D2161R7'
$vmx='E:\VMs\Windows10-20H2\Windows 10 x64.vmx'
$vmrun='D:\Software\Vmware\vmrun.exe'
$credentialFile='C:\Users\Administrator\AppData\Local\CodexVm\Windows10-20H2.credential.xml'
$scriptRoot=Split-Path -Parent $PSCommandPath
$files=@(
    (Join-Path $ReleaseDir 'KswordCLI.exe'), (Join-Path $ReleaseDir 'APIMonitor_x64.dll'),
    (Join-Path $ReleaseDir 'APIMonitor_x86.dll'), $Fixture64, $Fixture32,
    (Join-Path $scriptRoot 'Invoke-P0GuestEvidence.ps1'), (Join-Path $scriptRoot 'Invoke-P0GuestSystemEvidence.ps1'),
    (Join-Path $scriptRoot 'Invoke-P0GuestMetrics.ps1')
)
foreach($file in $files) { if(!(Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing deployment input: $file" } }
if ((Split-Path -Leaf $Fixture64) -eq (Split-Path -Leaf $Fixture32)) { throw 'Fixture basenames must differ.' }
if(Test-Path -LiteralPath $LocalReportRoot) { throw 'Local report path already exists.' }
$running=@(& $vmrun -T ws list)
if ($LASTEXITCODE -ne 0 -or $running -notcontains $vmx) { throw 'Target VM is not reported running; no VM state will be changed.' }
$vmIp=(& $vmrun -T ws getGuestIPAddress $vmx).Trim()
if($LASTEXITCODE -ne 0 -or $vmIp -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Guest IP not available.' }
$vmCredential=Import-Clixml -LiteralPath $credentialFile
$options=New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$session=New-PSSession -ComputerName $vmIp -UseSSL -ConfigurationName CodexRemote -Credential $vmCredential -SessionOption $options
try {
    $actual=Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME }
    if($actual -ne $expectedGuest) { throw 'Guest identity mismatch; no files were copied.' }
    $remoteRoot='C:\CodexVm\P0-API-Monitor-'+[guid]::NewGuid().ToString('N')
    Invoke-Command -Session $session -ArgumentList $remoteRoot,$expectedGuest -ScriptBlock {
        param($root,$computer)
        if($env:COMPUTERNAME -ne $computer -or $computer -ne 'DESKTOP-D2161R7') { throw 'Wrong guest.' }
        if(Test-Path -LiteralPath $root) { throw 'Remote staging path exists.' }
        New-Item -ItemType Directory -Path $root | Out-Null
    }
    foreach($file in $files) {
        Copy-Item -LiteralPath $file -Destination $remoteRoot -ToSession $session
        $localHash=(Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash
        $remotePath=Join-Path $remoteRoot (Split-Path -Leaf $file)
        $remoteHash=Invoke-Command -Session $session -ArgumentList $remotePath,$expectedGuest -ScriptBlock {
            param($path,$computer)
            if($env:COMPUTERNAME -ne $computer -or $computer -ne 'DESKTOP-D2161R7') { throw 'Wrong guest.' }
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
        if($localHash -ne $remoteHash) { throw "Deployment hash mismatch: $file" }
    }
    New-Item -ItemType Directory -Path $LocalReportRoot | Out-Null
    try {
        Invoke-Command -Session $session -ArgumentList $remoteRoot,(Split-Path -Leaf $Fixture64),(Split-Path -Leaf $Fixture32),([bool]$MetricsOnly) -ScriptBlock {
            param($root,$fixture64,$fixture32,$metricsOnly)
            if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest.' }
            if($metricsOnly) {
                & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Invoke-P0GuestMetrics.ps1') -Cli (Join-Path $root 'KswordCLI.exe') `
                    -Fixture64 (Join-Path $root $fixture64) -Fixture32 (Join-Path $root $fixture32) -ReportRoot (Join-Path $root 'metrics-results')
                if ($LASTEXITCODE -ne 0) { throw "Metrics test failed: $LASTEXITCODE" }
                return
            }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Invoke-P0GuestEvidence.ps1') -Cli (Join-Path $root 'KswordCLI.exe') `
                -Fixture64 (Join-Path $root $fixture64) -Fixture32 (Join-Path $root $fixture32) `
                -ReportRoot (Join-Path $root 'fixture-results') -ExpectedComputerName 'DESKTOP-D2161R7'
            if ($LASTEXITCODE -ne 0) { throw "Fixture test failed: $LASTEXITCODE" }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Invoke-P0GuestSystemEvidence.ps1') -Cli (Join-Path $root 'KswordCLI.exe') `
                -ReportRoot (Join-Path $root 'system-results')
            if ($LASTEXITCODE -ne 0) { throw "System process test failed: $LASTEXITCODE" }
        }
    } finally {
        foreach($name in @('fixture-results','system-results','metrics-results')) {
            $remotePath=Join-Path $remoteRoot $name
            if (Invoke-Command -Session $session -ArgumentList $remotePath -ScriptBlock { param($p) Test-Path -LiteralPath $p }) {
                Copy-Item -Path $remotePath -Destination $LocalReportRoot -FromSession $session -Recurse -Force
            }
        }
        [IO.File]::WriteAllText((Join-Path $LocalReportRoot 'remote-path.txt'),$remoteRoot)
    }
} finally { Remove-PSSession $session }
