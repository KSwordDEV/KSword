<#
.SYNOPSIS
    一条命令跑完本轮所有该测的东西，跑完给一份合并报告。为无人值守设计。

.DESCRIPTION
    这个脚本本身**不做**任何新的测试逻辑 —— 它按依赖顺序调度已有的 stage，
    在每一段之间把状态查干净，并在出事时自动取证。之所以单独存在，是因为
    无人值守跑最容易出的问题不是"某一项失败"，而是：

      * 前一项把机器留在脏状态里，后面每一项都在测另一台机器；
      * 中途蓝屏 + 自动重启，脚本没看出来，后面全部"通过"；
      * 跑完了才发现 guest 里那份驱动不是刚构建的那份。

    所以顺序、状态核验、哈希核验、崩溃取证都在这里，而不是留给人记。

    **顺序是有依据的，不要随便调**：
      1. 离线断言 + 工具编译     —— 不碰虚拟机，先失败在这里最省
      2. 部署 + SHA256 核验      —— 之后所有读数才可归因
      3. probe-platform          —— 只读，标定 CET / KVA shadow / GS base
      4. probe-flags             —— 只发请求、期望全部被拒，不改状态
      5. self-test               —— 只 VMXON/VMXOFF
      6. launch-guest            —— 一次性受控 guest，爆炸半径一个 4KiB 栈
      7. resident + stop         —— 验常驻活过发起进程（HOST_CR3 与 CR3 恢复）
      8. soak                    —— 长跑，验 StateFlags 全量 interlocked 之后仍稳
      9. view-probe / view-effect —— 分离视图：装得上，且**真的生效**
     10. probe-xonly             —— 会退虚拟化，所以放最后

    3 和 4 在 5 之前，是因为它们只读：万一驱动这一版有问题，先拿到平台读数
    比先把机器打挂有用。9 放最后，是因为它按设计会让常驻退出。

.PARAMETER SoakMs
    浸泡时长。**驱动侧硬上限 30 秒**（KSWORD_ARK_HVM_SOAK_MAX_MILLISECONDS），
    传更大的值会被静默夹到 30000 —— 报告里读 soakElapsedMilliseconds 才是
    真正跑了多久。所以默认就是 30000，不写一个做不到的数字。

.PARAMETER SkipOffline
    跳过第 1 段。只在刚刚已经跑过离线套件时用。

.EXAMPLE
    .\Invoke-KswordUnattendedSuite.ps1
#>
[CmdletBinding()]
param(
    [string] $VMName  = 'KSword-HVM-Target',
    [ValidateRange(1, 30000)]   # 驱动硬上限，超了会被静默夹掉
    [int]    $SoakMs  = 30000,
    [switch] $SkipOffline
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'

$sysPath = Join-Path $repo 'Ksword5.1\x64\Release\KswordARK.sys'
$record  = [ordered]@{
    schema      = 'ksword-unattended-suite/1'
    startedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    vmName      = $VMName
    soakMs      = $SoakMs
    driverSha256 = $null
    stages      = [System.Collections.ArrayList]::new()
    verdict     = 'NOT_RUN'
    notes       = [System.Collections.ArrayList]::new()
}
$resultPath = Join-Path $logDir "unattended-$stamp.json"

function Save-Record {
    $record.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    $record | ConvertTo-Json -Depth 14 | Set-Content -Path $resultPath -Encoding UTF8
}

function Add-Stage {
    param([string] $Name, [string] $Outcome, [string] $Note, $Data)
    $e = [ordered]@{
        name = $Name
        utc  = (Get-Date).ToUniversalTime().ToString('o')
        outcome = $Outcome
    }
    if ($Note) { $e.note = $Note }
    if ($null -ne $Data) { $e.data = $Data }
    [void]$record.stages.Add($e)
    $color = switch ($Outcome) { 'PASS' { 'Green' } 'SKIP' { 'DarkGray' } 'BLOCKED' { 'Yellow' } default { 'Red' } }
    Write-Host ("[{0,-7}] {1}{2}" -f $Outcome, $Name, $(if ($Note) { "  — $Note" })) -ForegroundColor $color
    Save-Record
}

# 崩溃取证：**只在 guest 真崩了时**跑。
#
# 一段失败不等于 guest 崩了。实测过一次：一次性 guest 跑成功了、驱动正常返回，
# 是 hvm_ctl.exe 回用户态时 AV，退出码 0xC0000005 一路传上来 —— 那是工具侧的
# 事故，跟 guest 无关。照样去取转储只会取回一份**几小时前的旧转储**，
# 然后给出一个完全自洽、完全错误的故事。
#
# 判据用控制脚本自己记的 alive 步骤：它比对过开机时刻，OK 就说明没重启过。
function Test-GuestActuallyCrashed {
    param($StageData)
    if ($null -eq $StageData -or $null -eq $StageData.steps) { return $true }
    $alive = @($StageData.steps | Where-Object { $_.name -like 'alive:*' })
    if ($alive.Count -eq 0) { return $true }      # 没测过存活，保守取证
    # 任何一条 alive 判 FAIL 才算 guest 出事
    return [bool](@($alive | Where-Object { $_.outcome -ne 'OK' }).Count -gt 0)
}

function Invoke-CrashForensics {
    param([string] $AfterStage)
    Write-Host "`n出事了，自动取证……" -ForegroundColor Yellow
    try {
        & (Join-Path $PSScriptRoot 'Get-KswordVmBugcheck.ps1') -VMName $VMName 2>&1 |
            Tee-Object -Variable out | Out-Host
        $newest = Get-ChildItem $logDir -Filter 'bugcheck-*.json' |
                  Sort-Object -Property { $_.LastWriteTime } -Descending |
                  Select-Object -First 1
        if ($newest) {
            [void]$record.notes.Add("崩溃取证（$AfterStage 之后）：$($newest.FullName)")
        }
    } catch {
        [void]$record.notes.Add("崩溃取证失败：$($_.Exception.Message)")
    }
}

# 跑一个 stage，返回 $true/$false。失败时把控制脚本写的那份记录挂进报告。
function Invoke-Stage {
    param([string] $Stage, [string] $Why, [int] $Soak = 0)

    Write-Host "`n=== $Stage ===  $Why" -ForegroundColor Cyan
    $before = Get-ChildItem $logDir -Filter 'hvm-autotest-*.json' -ErrorAction SilentlyContinue
    $beforeNames = @($before | ForEach-Object { $_.Name })

    # splat 必须用**哈希表**，不能用数组。
    #
    # 数组 splat 是**按位置**传参：`@('-Stage','resident')` 会把字符串 "-Stage"
    # 本身绑给第一个位置参数（正好就是 $Stage），于是报
    # "The argument '-Stage' does not belong to the set ..." ——
    # 看着像 stage 名字写错了，其实是传参方式错了。实测吃掉过一整轮。
    # 只有哈希表 splat 才是按名字传。
    $stageArgs = @{ Stage = $Stage; VMName = $VMName }
    if ($Soak -gt 0) { $stageArgs['SoakMs'] = $Soak }

    $global:LASTEXITCODE = $null
    & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') @stageArgs | Out-Host
    $code = $LASTEXITCODE
    if ($null -eq $code) {
        # 绑定失败或脚本抛异常时 $LASTEXITCODE 不会被设置。把它当成失败，
        # 而不是让 `$code -eq 0` 的比较悄悄为假、错误信息指向别处。
        Add-Stage $Stage 'FAIL' "调用没有返回退出码（多半是参数绑定失败）—— $Why"
        return $false
    }

    # 把控制脚本刚写的那份在机记录并进来，报告才自足。
    $data = $null
    $after = Get-ChildItem $logDir -Filter 'hvm-autotest-*.json' -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notin $beforeNames } |
             Sort-Object -Property { $_.LastWriteTime } -Descending |
             Select-Object -First 1
    if ($after) {
        try { $data = Get-Content $after.FullName -Raw | ConvertFrom-Json } catch { }
    }

    if ($code -eq 0) {
        Add-Stage $Stage 'PASS' $Why $data
        return $true
    }
    if ($code -eq 3) {
        # 空过：跑完了但没有区分力。**不是通过**，但也不该中断整轮 ——
        # 后面的项和它无关。记 BLOCKED 让总判定降级，然后继续。
        Add-Stage $Stage 'BLOCKED' "空过（跑完但没测到）—— $Why" $data
        [void]$record.notes.Add("$Stage 空过：这一项这次什么都没测到，不算通过。")
        $script:anyBlocked = $true
        return $true
    }
    Add-Stage $Stage 'FAIL' "退出码 $code —— $Why" $data
    return $false
}

$anyBlocked = $false

# ---------------------------------------------------------------------------
Write-Host "=== KSword 无人值守套件 ===" -ForegroundColor Cyan
Write-Host "记录 -> $resultPath`n"

try {
    # --- 0. 驱动哈希：先记下来，之后所有读数才知道属于哪一份二进制 ---
    if (-not (Test-Path $sysPath)) {
        Add-Stage '前置:驱动存在' 'FAIL' "找不到 $sysPath —— 先构建"
        $record.verdict = 'FAIL'
        exit 1
    }
    $record.driverSha256 = (Get-FileHash $sysPath -Algorithm SHA256).Hash
    Add-Stage '前置:驱动哈希' 'PASS' $record.driverSha256

    $sig = Get-AuthenticodeSignature $sysPath
    if ($sig.Status -eq 'NotSigned') {
        Add-Stage '前置:驱动已签名' 'FAIL' '未签名，送进 guest 只会得到 sc start 577'
        $record.verdict = 'FAIL'
        exit 1
    }
    Add-Stage '前置:驱动已签名' 'PASS' "$($sig.Status)"

    # --- 0b. 先腾磁盘 ---
    #
    # 这一轮的 risky stage 会打 5 个检查点，加上部署自己那个，每个约 8 GiB。
    # 无人值守时磁盘满的表现很有迷惑性：检查点失败 → 虚拟机进 Paused-Critical
    # → 看起来像挂死。与其跑到一半撞上，不如开跑前先清。
    # clean-install 永不删除（它是回到干净系统的唯一退路）。
    $freeGb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
    Write-Host "`n=== 磁盘 ===  C: 剩余 $freeGb GB" -ForegroundColor Cyan
    if ($freeGb -lt 80) {
        try {
            & (Join-Path $PSScriptRoot 'Clear-KswordVmCheckpoints.ps1') `
                -VMName $VMName -KeepLast 0 -Confirm | Out-Host
            $freeGb = [math]::Round((Get-PSDrive C).Free / 1GB, 1)
            Add-Stage '前置:清理检查点' 'PASS' "清理后剩余 $freeGb GB（clean-install 保留）"
        } catch {
            Add-Stage '前置:清理检查点' 'BLOCKED' $_.Exception.Message
        }
    } else {
        Add-Stage '前置:清理检查点' 'SKIP' "剩余 $freeGb GB，够用"
    }
    if ($freeGb -lt 50) {
        [void]$record.notes.Add(
            "磁盘只剩 $freeGb GB，5 个检查点很可能放不下 —— 中途失败先看是不是磁盘满。")
    }

    # --- 1. 离线：不碰虚拟机，先失败在这里最省 ---
    if ($SkipOffline) {
        Add-Stage '离线断言+工具' 'SKIP' '按 -SkipOffline 跳过'
    } else {
        Write-Host "`n=== 离线断言 + 工具编译 ===" -ForegroundColor Cyan
        & (Join-Path $PSScriptRoot 'Invoke-KswordAutomatedAcceptance.ps1') -OfflineOnly | Out-Host
        if ($LASTEXITCODE -ne 0) {
            Add-Stage '离线断言+工具' 'FAIL' "退出码 $LASTEXITCODE"
            $record.verdict = 'FAIL'
            exit 1
        }
        Add-Stage '离线断言+工具' 'PASS' '4000 条断言 + 两个 /MT 工具'
    }

    # --- 2. 部署（脚本内部会比对宿主与 guest 的 SHA256）---
    Write-Host "`n=== 部署 ===" -ForegroundColor Cyan
    & (Join-Path $PSScriptRoot 'Deploy-KswordDriverToVm.ps1') -VMName $VMName | Out-Host
    if ($LASTEXITCODE -ne 0) {
        Add-Stage '部署+哈希核验' 'FAIL' "退出码 $LASTEXITCODE —— 前提或哈希不符，后面全部不跑"
        $record.verdict = 'FAIL'
        exit 1
    }
    Add-Stage '部署+哈希核验' 'PASS' 'guest 上就是刚构建的那份'

    # --- 3..9 按依赖顺序 ---
    $plan = @(
        @{ S = 'probe-platform'; W = '只读：CET / KVA shadow / GS base 标定';            Soak = 0 }
        @{ S = 'self-test';      W = 'VMXON/VMXOFF';                                      Soak = 0 }
        # probe-flags 排在 self-test **之后**：驱动的前置检查排在所有能力门之前，
        # 没 prepare+self-test 时能力门根本没被问到，用例会空过。
        @{ S = 'probe-flags';    W = '负向：ENFORCE 与能力 flag 是否在该拒的地方拒';      Soak = 0 }
        @{ S = 'launch-guest';   W = '一次性受控 guest：VMCS 构造 + EPTP + VMLAUNCH';     Soak = 0 }
        @{ S = 'resident';       W = '常驻活过发起进程（HOST_CR3 + 退虚拟化 CR3 恢复）';  Soak = 0 }
        @{ S = 'soak';           W = "长跑 $SoakMs ms（驱动上限 30000）：StateFlags 全量 interlocked 之后仍稳"; Soak = $SoakMs }
        # 视图归因探针只发一次 VIEW_OP_ADD、不进 VMX，所以排在会退虚拟化的两级之前。
        @{ S = 'view-probe';     W = '分离视图安装期归因：拒绝发生在该拒的那道门上';      Soak = 0 }
        # 端到端生效判据。它自己起停常驻，并且是**唯一**会真正走到 EPTP 切换退出
        # 路径的一级，所以排在 probe-xonly 之前 —— probe-xonly 按设计会退虚拟化，
        # 让它先跑就等于让后面这一级在一台刚被打掉常驻的机器上开工。
        @{ S = 'view-effect';    W = 'CLOAK 真的生效：内核读被重定向到影子且常驻未掉';   Soak = 0 }
        @{ S = 'probe-xonly';    W = 'EPT 权限仍被强制（按设计会退虚拟化，故放最后）';    Soak = 0 }
    )

    $anyFail = $false
    foreach ($p in $plan) {
        if (-not (Invoke-Stage $p.S $p.W $p.Soak)) {
            $anyFail = $true
            # 一段失败就停：脏状态下继续跑，后面每一项都在测另一台机器。
            [void]$record.notes.Add("在 $($p.S) 失败后停止 —— 不在脏状态上继续。")
            $lastStage = $record.stages[$record.stages.Count - 1]
            if (Test-GuestActuallyCrashed $lastStage.data) {
                Invoke-CrashForensics $p.S
            } else {
                [void]$record.notes.Add(
                    "guest 全程存活且没有重启 —— 这是**工具或脚本侧**的失败，" +
                    "不是 guest 崩溃。没有去取转储（取回来的会是旧的）。")
                Write-Host "`nguest 没崩（alive 全 OK 且没重启）—— 不取转储。" -ForegroundColor Yellow
            }
            break
        }
        # 每段之后修剪到只留最近一个检查点。
        #
        # 每个 stage 的 plan 自己会垫 self-test，所以一轮下来会打十来个检查点，
        # 每个约 8 GiB —— 按当前剩余空间必然撞满，而磁盘满的表现（虚拟机进
        # Paused-Critical）看起来像挂死。留一个就够回滚到上一段。
        try {
            & (Join-Path $PSScriptRoot 'Clear-KswordVmCheckpoints.ps1') `
                -VMName $VMName -KeepLast 1 -Confirm | Out-Null
        } catch { }
    }

    # 三态总判定。PARTIAL 不是"基本通过"，是"有项目没测到" —— 单列出来，
    # 否则它会被当成绿灯。
    $record.verdict = if ($anyFail) { 'FAIL' }
                      elseif ($anyBlocked) { 'PARTIAL' }
                      else { 'PASS' }
}
catch {
    $record.verdict = 'ERROR'
    [void]$record.notes.Add("套件异常：$($_.Exception.Message)")
    Write-Host "`n套件异常：$($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # 无论怎么退出，都把常驻收干净 —— 留着它会让下一次部署撞上
    # "CPUID 看不到 VMX"那个很有迷惑性的报错。
    try {
        & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') `
            -Stage stop -VMName $VMName -SkipCheckpoint 2>&1 | Out-Null
    } catch { }

    Save-Record
    Write-Host ""
    Write-Host ("================ 无人值守套件总判定: {0} ================" -f $record.verdict) `
        -ForegroundColor $(switch ($record.verdict) {
            'PASS' { 'Green' } 'PARTIAL' { 'Yellow' } default { 'Red' } })
    if ($record.verdict -eq 'PARTIAL') {
        Write-Host "  PARTIAL 不是'基本通过' —— 有项目跑完了但什么都没测到。" -ForegroundColor Yellow
    }
    foreach ($n in $record.notes) { Write-Host "  · $n" -ForegroundColor Yellow }
    Write-Host "  报告 : $resultPath" -ForegroundColor Cyan
    Write-Host "  驱动 : $($record.driverSha256)" -ForegroundColor DarkGray
    exit $(switch ($record.verdict) { 'PASS' { 0 } 'PARTIAL' { 3 } default { 1 } })
}
