param(
    [Parameter(Mandatory=$true)][string]$ReleaseDir,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$LocalReportRoot
)
$ErrorActionPreference='Stop'
$vmx='E:\VMs\Windows10-20H2\Windows 10 x64.vmx'
$vmrun='D:\Software\Vmware\vmrun.exe'
$credentialFile='C:\Users\Administrator\AppData\Local\CodexVm\Windows10-20H2.credential.xml'
$files=@(
    @{Local=(Join-Path $ReleaseDir 'KswordCLI.exe'); Relative='KswordCLI.exe'},
    @{Local=(Join-Path $ReleaseDir 'APIMonitor_x64.dll'); Relative='APIMonitor_x64.dll'},
    @{Local=(Join-Path $ReleaseDir 'APIMonitor_x86.dll'); Relative='APIMonitor_x86.dll'},
    @{Local=$Fixture64; Relative='ApiFixture64.exe'},
    @{Local=$Fixture32; Relative='ApiFixture32.exe'},
    @{Local=(Join-Path $PSScriptRoot 'Invoke-R0GuestEvidence.ps1'); Relative='Invoke-R0GuestEvidence.ps1'}
)
foreach($file in $files){if(!(Test-Path -LiteralPath $file.Local -PathType Leaf)){throw "Missing input: $($file.Local)"}}
if(Test-Path -LiteralPath $LocalReportRoot){throw 'Local report directory already exists'}
$running=@(& $vmrun -T ws list)
if($LASTEXITCODE -ne 0 -or $running -notcontains $vmx){throw 'Target VM is not reported running; no VM state changed'}
$vmIp=(& $vmrun -T ws getGuestIPAddress $vmx).Trim()
if($LASTEXITCODE -ne 0 -or $vmIp -notmatch '^\d+\.\d+\.\d+\.\d+$'){throw 'Guest IP unavailable'}
$credential=Import-Clixml -LiteralPath $credentialFile
$options=New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$session=New-PSSession -ComputerName $vmIp -UseSSL -ConfigurationName CodexRemote -Credential $credential -SessionOption $options
try {
    Invoke-Command -Session $session -ScriptBlock {
        if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7'){throw 'Wrong guest; no files copied'}
        $driver=Get-CimInstance Win32_SystemDriver -Filter "Name='KswordARK'"
        $p='C:\Users\Administrator\Desktop\Ksword-nice\KswordARK.sys'
        $sha='266EB921B5D3238901145898295C25ABC1F5DF52B8BF6D4FA99E1C5DF512F2AE'
        if(!$driver -or $driver.State -ne 'Stopped' -or $driver.StartMode -ne 'Manual' -or
            $driver.PathName -ne ('\??\'+$p) -or !(Test-Path -LiteralPath $p -PathType Leaf) -or
            (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash -ne $sha){throw 'Unexpected driver baseline; no files copied'}
        $disk=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
        if($disk.FreeSpace -lt 48MB){throw "Insufficient guest space before deployment: $($disk.FreeSpace)"}
    }
    $remoteRoot='C:\CodexVm\R0-ApiMonitor-'+[guid]::NewGuid().ToString('N')
    Invoke-Command -Session $session -ArgumentList $remoteRoot -ScriptBlock {
        param($root)
        if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7'){throw 'Wrong guest'}
        if(Test-Path -LiteralPath $root){throw 'Remote staging directory exists'}
        New-Item -ItemType Directory -Path $root | Out-Null
    }
    New-Item -ItemType Directory -Path $LocalReportRoot | Out-Null
    [IO.File]::WriteAllText((Join-Path $LocalReportRoot 'remote-path.txt'),$remoteRoot)
    foreach($file in $files){
        $remotePath=Join-Path $remoteRoot $file.Relative
        Copy-Item -LiteralPath $file.Local -Destination $remotePath -ToSession $session
        $localHash=(Get-FileHash -LiteralPath $file.Local -Algorithm SHA256).Hash
        $remoteHash=Invoke-Command -Session $session -ArgumentList $remotePath -ScriptBlock {
            param($p);if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7'){throw 'Wrong guest'}
            (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash
        }
        if($localHash -ne $remoteHash){throw "Deployment hash mismatch: $($file.Relative)"}
        Write-Output "DEPLOYED $($file.Relative) SHA256=$localHash"
    }
    try {
        Invoke-Command -Session $session -ArgumentList $remoteRoot -ScriptBlock {
            param($root)
            if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7'){throw 'Wrong guest'}
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root 'Invoke-R0GuestEvidence.ps1') `
                -Cli (Join-Path $root 'KswordCLI.exe') -Fixture64 (Join-Path $root 'ApiFixture64.exe') `
                -Fixture32 (Join-Path $root 'ApiFixture32.exe') -ReportRoot (Join-Path $root 'results')
            if($LASTEXITCODE -ne 0){throw "R0 guest validation failed: $LASTEXITCODE"}
        }
    } finally {
        $remoteResults=Join-Path $remoteRoot 'results'
        if(Invoke-Command -Session $session -ArgumentList $remoteResults -ScriptBlock {param($p);Test-Path -LiteralPath $p}){
            Copy-Item -Path $remoteResults -Destination $LocalReportRoot -FromSession $session -Recurse -Force
        }
    }
} finally { Remove-PSSession $session }
