<#
.SYNOPSIS
    把含 Backend 3 PoC 的 KswordARK.sys 推到 VM 并重启服务，然后原地跑 Test-Backend3Probe.ps1。

.PARAMETER VMName
    目标 Hyper-V VM 名。默认 26H2-11-Pro。

.PARAMETER SysPath
    宿主侧新 .sys 路径。默认 Ksword5.1\x64\Release\KswordARK.sys。

.PARAMETER ProbeMode
    QueryOnly | NoopWrite。默认 QueryOnly。

.PARAMETER Vector
    IDT 向量。默认 1。

.EXAMPLE
    .\Deploy-Backend3Probe.ps1
    .\Deploy-Backend3Probe.ps1 -ProbeMode NoopWrite
#>
[CmdletBinding()]
param(
    [string]$VMName = '26H2-11-Pro',
    [string]$SysPath = 'Ksword5.1\x64\Release\KswordARK.sys',
    [ValidateSet('QueryOnly','NoopWrite')][string]$ProbeMode = 'QueryOnly',
    [ValidateRange(0,255)][int]$Vector = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolved = (Resolve-Path -LiteralPath $SysPath).Path
$hostSize = (Get-Item $resolved).Length
$hostHash = (Get-FileHash $resolved -Algorithm SHA256).Hash
Write-Host ("Host .sys: {0} ({1} bytes) sha256={2}" -f $resolved, $hostSize, $hostHash.Substring(0,16))

$cred = New-Object System.Management.Automation.PSCredential ('felix', (ConvertTo-SecureString 'f' -AsPlainText -Force))

# 启用 Guest Service Interface（Copy-VMFile 的前提）
Enable-VMIntegrationService -VMName $VMName -Name 'Guest Service Interface' -EA SilentlyContinue | Out-Null

# 1. 停服务
Write-Host "Stopping KswordARK service in VM..."
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    try { Stop-Service KswordARK -Force -EA Stop } catch { Write-Host ("Stop-Service: {0}" -f $_.Exception.Message) }
} | Out-Null

# 2. 推 .sys 到 staging
Write-Host "Copying .sys to VM staging via Copy-VMFile..."
Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    if (-not (Test-Path 'C:\ks-stage')) { New-Item -ItemType Directory -Path 'C:\ks-stage' -Force | Out-Null }
} | Out-Null
Copy-VMFile -Name $VMName -SourcePath $resolved -DestinationPath 'C:\ks-stage\KswordARK.sys' -CreateFullPath -FileSource Host -Force

# 3. 等 journal replay，然后移到 ImagePath
Write-Host "Waiting 5s for NTFS journal replay, then moving to ImagePath..."
Start-Sleep -Seconds 5
$copyScript = @'
param($hostHash)
if (-not (Test-Path 'C:\ks-vm')) { New-Item -ItemType Directory -Path 'C:\ks-vm' -Force | Out-Null }
Copy-Item 'C:\ks-stage\KswordARK.sys' 'C:\ks-vm\KswordARK.sys' -Force
Start-Sleep -Seconds 3
$vmHash = (Get-FileHash 'C:\ks-vm\KswordARK.sys' -Algorithm SHA256).Hash
[pscustomobject]@{
    VmHash    = $vmHash
    HashMatch = ($vmHash -eq $hostHash)
    SysSize   = (Get-Item 'C:\ks-vm\KswordARK.sys').Length
}
'@
$copyResult = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock ([ScriptBlock]::Create($copyScript)) -ArgumentList $hostHash
Write-Host ("VM .sys: {0} bytes sha256={1} match={2}" -f $copyResult.SysSize, $copyResult.VmHash.Substring(0,16), $copyResult.HashMatch)
if (-not $copyResult.HashMatch) { throw "VM .sys hash mismatch - abort" }

# 4. 启服务
Write-Host "Starting KswordARK service..."
$startResult = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
    $t0 = [DateTime]::UtcNow
    $out = & sc.exe start KswordARK 2>&1
    $dt = ([DateTime]::UtcNow - $t0).TotalSeconds
    $svc = Get-Service KswordARK -EA SilentlyContinue
    [pscustomobject]@{
        StartOut = ($out -join "`n")
        State    = if ($svc) { $svc.Status } else { 'absent' }
        ElapsedS = [math]::Round($dt, 2)
    }
}
Write-Host ("sc start: state={0} elapsedS={1}" -f $startResult.State, $startResult.ElapsedS)
Write-Host $startResult.StartOut

if ($startResult.State -ne 'Running') {
    throw "Driver did not reach Running state"
}

# 5. 跑 probe
Write-Host ""
Write-Host "Running Backend 3 PoC probe: Mode=$ProbeMode Vector=$Vector"
$probeScript = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'Test-Backend3Probe.ps1') -Raw
$probeResult = Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock ([ScriptBlock]::Create($probeScript)) -ArgumentList $ProbeMode, $Vector
$probeResult | Format-List
return $probeResult
