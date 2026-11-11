param(
    [Parameter(Mandatory=$true)][string]$ReleaseDir,
    [Parameter(Mandatory=$true)][string]$Fixture64,
    [Parameter(Mandatory=$true)][string]$Fixture32,
    [Parameter(Mandatory=$true)][string]$LocalReportRoot,
    [ValidateSet('parity','sdkraw','category','perapi','guicategory')][string]$Mode='parity'
)
$ErrorActionPreference='Stop'
$expectedGuest='DESKTOP-D2161R7'
$vmx='E:\VMs\Windows10-20H2\Windows 10 x64.vmx'
$vmrun='D:\Software\Vmware\vmrun.exe'
$credentialFile='C:\Users\Administrator\AppData\Local\CodexVm\Windows10-20H2.credential.xml'
$guestScriptName=if($Mode -eq 'sdkraw'){'Invoke-SdkRawGuest.ps1'}elseif($Mode -eq 'category'){'Invoke-CategoryGuest.ps1'}elseif($Mode -eq 'perapi'){'Invoke-PerApiGuest.ps1'}elseif($Mode -eq 'guicategory'){'Invoke-GuiCategoryGuest.ps1'}else{'Invoke-CliParityGuest.ps1'}
$guestScript=Join-Path $PSScriptRoot $guestScriptName
$inputs=@(
    @{ Local=(Join-Path $ReleaseDir 'KswordCLI.exe'); Relative='KswordCLI.exe' },
    @{ Local=(Join-Path $ReleaseDir 'APIMonitor_x64.dll'); Relative='APIMonitor_x64.dll' },
    @{ Local=(Join-Path $ReleaseDir 'APIMonitor_x86.dll'); Relative='APIMonitor_x86.dll' },
    @{ Local=(Join-Path $ReleaseDir 'profiles\api_monitor_definitions.json'); Relative='profiles\api_monitor_definitions.json' },
    @{ Local=$Fixture64; Relative='ApiFixture64.exe' },
    @{ Local=$Fixture32; Relative='ApiFixture32.exe' },
    @{ Local=$guestScript; Relative=$guestScriptName }
)
foreach($item in $inputs) { if(!(Test-Path -LiteralPath $item.Local -PathType Leaf)) { throw "Missing input: $($item.Local)" } }
if(Test-Path -LiteralPath $LocalReportRoot) { throw 'Local report directory already exists' }
$running=@(& $vmrun -T ws list)
if($LASTEXITCODE -ne 0 -or $running -notcontains $vmx) { throw 'Target VM is not reported running; no VM state was changed' }
$vmIp=(& $vmrun -T ws getGuestIPAddress $vmx).Trim()
if($LASTEXITCODE -ne 0 -or $vmIp -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Guest IP unavailable' }
$vmCredential=Import-Clixml -LiteralPath $credentialFile
$options=New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$session=New-PSSession -ComputerName $vmIp -UseSSL -ConfigurationName CodexRemote -Credential $vmCredential -SessionOption $options
try {
    $actual=Invoke-Command -Session $session -ScriptBlock { $env:COMPUTERNAME }
    if($actual -ne $expectedGuest) { throw 'Guest identity mismatch; no files copied' }
    $remoteRoot='C:\CodexVm\CLI-Parity-'+[guid]::NewGuid().ToString('N')
    Invoke-Command -Session $session -ArgumentList $remoteRoot -ScriptBlock {
        param($root)
        if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest' }
        if(Test-Path -LiteralPath $root) { throw 'Remote directory exists' }
        New-Item -ItemType Directory -Path (Join-Path $root 'profiles') -Force | Out-Null
    }
    foreach($item in $inputs) {
        $remotePath=Join-Path $remoteRoot $item.Relative
        Copy-Item -LiteralPath $item.Local -Destination $remotePath -ToSession $session
        $localHash=(Get-FileHash -LiteralPath $item.Local -Algorithm SHA256).Hash
        $remoteHash=Invoke-Command -Session $session -ArgumentList $remotePath -ScriptBlock {
            param($path)
            if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest' }
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
        }
        if($localHash -ne $remoteHash) { throw "Deployment hash mismatch: $($item.Relative)" }
        Write-Output "DEPLOYED $($item.Relative) SHA256=$localHash"
    }
    New-Item -ItemType Directory -Path $LocalReportRoot | Out-Null
    try {
        Invoke-Command -Session $session -ArgumentList $remoteRoot,$guestScriptName -ScriptBlock {
            param($root,$scriptName)
            if($env:COMPUTERNAME -ne 'DESKTOP-D2161R7') { throw 'Wrong guest' }
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $root $scriptName) `
                -Cli (Join-Path $root 'KswordCLI.exe') -Fixture64 (Join-Path $root 'ApiFixture64.exe') `
                -Fixture32 (Join-Path $root 'ApiFixture32.exe') -ReportRoot (Join-Path $root 'results') `
                -ExpectedComputerName 'DESKTOP-D2161R7'
            if($LASTEXITCODE -ne 0) { throw "CLI parity test failed: $LASTEXITCODE" }
        }
    } finally {
        $remoteResults=Join-Path $remoteRoot 'results'
        if(Invoke-Command -Session $session -ArgumentList $remoteResults -ScriptBlock { param($path) Test-Path -LiteralPath $path }) {
            Copy-Item -Path $remoteResults -Destination $LocalReportRoot -FromSession $session -Recurse -Force
        }
        [IO.File]::WriteAllText((Join-Path $LocalReportRoot 'remote-path.txt'),$remoteRoot)
    }
} finally { Remove-PSSession $session }
