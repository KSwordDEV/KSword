<#
.SYNOPSIS
    清理 KSword 测试机累积的检查点，回收磁盘空间。

.DESCRIPTION
    必须以**管理员**运行。

    每个检查点都会保存一份完整的内存映像（本机 8 GiB）加上一个差分磁盘，
    分级测试每跑一轮就产生一到两个，很快就把系统盘吃光 —— 表现是
    `Checkpoint operation failed ... 磁盘空间不足 (0x80070070)`。

    **默认只做预演，不删任何东西。** 看过清单确认无误后加 -Confirm 才真删。

    保留规则（两条都生效）：
      * 名字在 -Keep 里的永远保留，默认保留 'clean-install' ——
        那是唯一一个"干净系统 + 已配置好前提"的基线，删了要重装。
      * 其余按创建时间倒序保留最近 -KeepLast 个（默认 2）。

    删除是**异步**的：Hyper-V 在后台把差分磁盘合并回父盘。脚本会等合并结束，
    否则你会看到空间没有立刻回来。

.PARAMETER Confirm
    真正执行删除。不加这个开关只打印将要删除的清单。

.PARAMETER KeepLast
    除保留名单之外，额外保留最近的几个。默认 2。

.PARAMETER Keep
    永不删除的检查点名字。默认 'clean-install'。

.EXAMPLE
    .\Clear-KswordVmCheckpoints.ps1              # 预演，只看清单
    .\Clear-KswordVmCheckpoints.ps1 -Confirm     # 真删
    .\Clear-KswordVmCheckpoints.ps1 -KeepLast 0 -Confirm
#>
[CmdletBinding()]
param(
    [string]   $VMName   = 'KSword-HVM-Target',
    [int]      $KeepLast = 2,
    [string[]] $Keep     = @('clean-install'),
    [switch]   $Confirm
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

function Get-FreeGb {
    param([string] $Path)
    $root = [IO.Path]::GetPathRoot($Path)
    $d = Get-PSDrive -Name $root.TrimEnd(':\') -ErrorAction SilentlyContinue
    if ($d) { return [math]::Round($d.Free / 1GB, 2) }
    return $null
}

$vm = Get-VM -Name $VMName -ErrorAction Stop
$vmPath = $vm.Path
$freeBefore = Get-FreeGb $vmPath
Write-Host ("虚拟机 {0}  状态 {1}  路径 {2}" -f $vm.Name, $vm.State, $vmPath)
Write-Host ("所在卷剩余 {0} GB" -f $freeBefore) -ForegroundColor $(
    if ($freeBefore -lt 5) { 'Red' } elseif ($freeBefore -lt 20) { 'Yellow' } else { 'Green' })

$all = @(Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime)
if ($all.Count -eq 0) { Write-Host "`n没有检查点。" -ForegroundColor Green; return }

Write-Host "`n全部检查点（按时间正序）：" -ForegroundColor Cyan
$all | Format-Table Name, SnapshotType, CreationTime -AutoSize

# 保留：名单内的 + 最近 KeepLast 个
$keepByName = @($all | Where-Object { $Keep -contains $_.Name })
$keepRecent = @($all | Sort-Object CreationTime -Descending | Select-Object -First ([math]::Max($KeepLast, 0)))
$keepNames  = @(($keepByName + $keepRecent) | ForEach-Object { $_.Name } | Sort-Object -Unique)
$doomed     = @($all | Where-Object { $keepNames -notcontains $_.Name })

Write-Host "保留：" -ForegroundColor Green
foreach ($n in $keepNames) {
    $why = if ($Keep -contains $n) { '（保留名单）' } else { '（最近 {0} 个之一）' -f $KeepLast }
    Write-Host ("  {0} {1}" -f $n, $why) -ForegroundColor Green
}

if ($doomed.Count -eq 0) {
    Write-Host "`n没有可删除的检查点。要腾出空间就调小 -KeepLast。" -ForegroundColor Yellow
    return
}

Write-Host "`n将删除 $($doomed.Count) 个：" -ForegroundColor Yellow
foreach ($s in $doomed) { Write-Host ("  {0}   {1}" -f $s.Name, $s.CreationTime) -ForegroundColor Yellow }

if (-not $Confirm) {
    Write-Host "`n【预演】没有删除任何东西。确认清单无误后加 -Confirm 执行：" -ForegroundColor Cyan
    Write-Host "  .\scripts\Clear-KswordVmCheckpoints.ps1 -Confirm"
    return
}

foreach ($s in $doomed) {
    Write-Host ("删除 {0} ..." -f $s.Name) -NoNewline
    Remove-VMSnapshot -VMName $VMName -Name $s.Name -Confirm:$false
    Write-Host " 已提交" -ForegroundColor Green
}

# Hyper-V 的删除是异步的：差分磁盘在后台合并回父盘，合并完空间才真正回来。
# 不等的话会看到"删了但空间没变"，然后误以为删除没生效。
Write-Host "`n等待后台合并完成..." -ForegroundColor Cyan
$deadline = (Get-Date).AddMinutes(30)
while ((Get-Date) -lt $deadline) {
    $merging = @(Get-VM -Name $VMName | Where-Object { $_.Status -match 'Merg|合并' })
    if ($merging.Count -eq 0) { break }
    Write-Host ("  仍在合并：{0}" -f (Get-VM -Name $VMName).Status)
    Start-Sleep -Seconds 15
}

$freeAfter = Get-FreeGb $vmPath
Write-Host ("`n剩余空间 {0} GB -> {1} GB（回收约 {2} GB）" -f
    $freeBefore, $freeAfter, [math]::Round($freeAfter - $freeBefore, 2)) -ForegroundColor Green
Write-Host "`n剩下的检查点：" -ForegroundColor Cyan
Get-VMSnapshot -VMName $VMName | Sort-Object CreationTime | Format-Table Name, CreationTime -AutoSize
