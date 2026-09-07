<#
.SYNOPSIS
    在**宿主**上记录 Hyper-V 的嵌套虚拟化计数器，三段标定之后跑 START_RESIDENT，
    用来回答"VM entry 到底有没有把 CPU 送进 L2"。

.DESCRIPTION
    必须以**管理员**运行（PowerShell Direct 需要）。

    为什么必须在宿主侧记录：guest 挂死之后什么都读不到。驱动侧零 DbgPrint、
    零注册表写、每处理器行与事件环都在非分页池，硬复位即灭；而挂死本身连
    NMI 与 Ctrl+C 都打不进调试器。所以**证据必须在挂死发生的同时被送到 guest 之外**。
    Hyper-V 的每虚拟处理器计数器正好在宿主上，guest 怎么死都不影响。

    三段标定，顺序不能省：

      1. 基线      虚拟机空转，记下各计数器的静息值；
      2. 标定      发一次 LAUNCH_TEST_GUEST。它已知恰好产生 1 次 nested entry
                   与 1 次 VM exit —— 如果计数器**不跳**，说明它的含义与我们
                   以为的不同，后面的读数一律不可信，实验作废；
      3. 观测      发 START_RESIDENT，一直采样到虚拟机失联或超时。

    第 2 段是整个实验的地基。跳过它就等于用一个未经检验的判据下结论 ——
    这条排查线上已经三次栽在"未标定的判据"上（GUEST_LAUNCHED 位被上一次实验
    污染、lastVmInstructionError 的 0 有三个来源、RESIDENT_STARTING 在三条出口
    都会被清）。

.PARAMETER SkipResident
    只做基线与标定，不发 START_RESIDENT。用来单独验证计数器语义。

.EXAMPLE
    .\Invoke-KswordHostFlightRecorder.ps1
    .\Invoke-KswordHostFlightRecorder.ps1 -SkipResident
#>
[CmdletBinding()]
param(
    [string] $VMName          = 'KSword-HVM-Target',
    [string] $GuestUser       = 'felix',
    [string] $GuestPassword   = 'password',
    [int]    $BaselineSeconds = 20,
    [int]    $ObserveSeconds  = 90,
    [double] $SampleInterval  = 1,
    [string] $OutDir,
    [switch] $SkipResident
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo = Split-Path $PSScriptRoot -Parent
if (-not $OutDir) { $OutDir = Join-Path $repo 'docs\next\logs' }
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$csv   = Join-Path $OutDir "flight-$stamp.csv"
$json  = Join-Path $OutDir "flight-$stamp.json"

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

# --- 计数器：只用本机实际存在的，缺的静默跳过 --------------------------------
# 写死一张清单再假设它存在，是另一种"未标定的判据"。这里从 -ListSet 实际拿。
$wanted = @(
    # --- 总量与归属 ---
    'Nested VM Entries/sec',
    'Total Intercepts/sec',
    '% Guest Run Time',
    '% Hypervisor Run Time',
    # --- 已实测排除的三类（保留做对照，别删）---
    # 实测：观测段十万次/秒拦截里，这三类合计不到 6 次。
    'MSR Accesses/sec',
    'Hypercalls/sec',
    'Nested Page Fault Intercepts/sec',
    # --- 逐条 VMX 指令的模拟拦截 ---
    # Hyper-V 作为 L0 时会陷入并模拟 L1 执行的每一条 VMX 指令（不做 VMCS
    # shadowing 时 VMREAD/VMWRITE 尤其如此）。上一轮拿不到结论，正是因为
    # 只采了 MSR/hypercall/缺页三类，而真正的风暴不在其中。
    'Total Virtualization Instructions Emulated/sec',
    'VMREAD Emulation Intercepts/sec',
    'VMWRITE Emulation Intercepts/sec',
    'VMPTRLD Emulation Intercepts/sec',
    'VMCLEAR Emulation Intercepts/sec',
    'VMXON Emulation Intercepts/sec',
    'VMXOFF Emulation Intercepts/sec',
    'InvEpt Single Context Emulation Intercepts/sec',
    'InvEpt All Context Emulation Intercepts/sec',
    # --- 兜底：剩下的拦截归到哪一类 ---
    'Emulated Instructions/sec',
    'Page Fault Intercepts/sec',
    'Memory Intercept Messages/sec',
    'IO Intercept Messages/sec',
    'Other Intercepts/sec'
)
$instance = "$VMName" + ':Hv VP 0'
$set = Get-Counter -ListSet 'Hyper-V Hypervisor Virtual Processor' -ErrorAction Stop
$paths = @()
foreach ($w in $wanted) {
    $p = $set.PathsWithInstances | Where-Object { $_ -like "*($instance)\$w" } | Select-Object -First 1
    if ($p) { $paths += $p } else { Write-Host ("  [跳过] 本机没有计数器 '$w'") -ForegroundColor Yellow }
}
if ($paths.Count -eq 0) { throw "找不到 '$instance' 的任何计数器。虚拟机在运行吗？vCPU 数变了会改实例名。" }

Write-Host ("=== 宿主飞行记录仪 ===") -ForegroundColor Cyan
Write-Host ("实例   : {0}" -f $instance)
Write-Host ("计数器 : {0} 个" -f $paths.Count)
Write-Host ("输出   : {0}" -f $csv) -ForegroundColor DarkGray

$samples = New-Object System.Collections.ArrayList
$marks   = New-Object System.Collections.ArrayList

function Add-Sample {
    param([string] $Phase)
    try {
        $s = Get-Counter -Counter $paths -ErrorAction Stop
        $row = [ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); phase = $Phase }
        foreach ($v in $s.CounterSamples) {
            # 计数器名里的空格和百分号在 CSV 里不好用，取末段并规范化
            $name = ($v.Path -split '\\')[-1] -replace '[^A-Za-z0-9]', '_'
            $row[$name] = [math]::Round($v.CookedValue, 2)
        }
        [void]$samples.Add([pscustomobject]$row)
        return $row
    } catch {
        [void]$samples.Add([pscustomobject]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); phase = $Phase; error = "$($_.Exception.Message)" })
        return $null
    }
}

function Invoke-HvmCtl {
    param([string] $Command)
    try {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock {
            param($c)
            $o = 'C:\ksword\fr_out.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            $p = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json', $c) `
                     -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                     -RedirectStandardError 'C:\ksword\fr_err.txt'
            $t = ''
            if (Test-Path $o) { $t = [IO.File]::ReadAllText($o) }
            [ordered]@{ Exit = $p.ExitCode; Out = $t }
        } -ArgumentList $Command
    } catch { return $null }
}

function Get-Field { param($Row, [string] $Like)
    if (-not $Row) { return $null }
    $k = $Row.Keys | Where-Object { $_ -like $Like } | Select-Object -First 1
    if ($k) { return $Row[$k] } else { return $null }
}

function Get-HvmJson {
    param([string] $Command)
    $r = Invoke-HvmCtl $Command
    if (-not $r -or -not $r.Out) { return $null }
    try { return ($r.Out | ConvertFrom-Json) } catch { return $null }
}

# ---------------------------------------------------------------------------
# 前置条件自愈。
#
# 不做这一步的后果实测过一次：驱动带着上一轮残留的 FAULTED、且从未 prepare，
# 于是 launch-test-guest 与 START_RESIDENT 都在前置门被拒（UNSUPPORTED_CPU /
# STATUS_NOT_SUPPORTED），计数器当然不跳、机器当然不挂 —— 整轮实验看起来"跑完了"
# 却什么都没测到，而且很容易被误读成"挂死不复现了"。
#
# 与 Invoke-KswordHvmControl.ps1 用的是同一条链：
#   FAULTED/ROLLBACK_REQUIRED -> reset-fault
#   没有 RESOURCES_READY      -> prepare（有就跳过，重复 prepare 会再打成 FAULTED）
#   没有 SELF_TEST_PASSED     -> self-test
# ---------------------------------------------------------------------------
function Initialize-HvmPrereq {
    Write-Host "`n--- 0. 前置条件自愈 ---" -ForegroundColor Cyan
    $st = Get-HvmJson 'status'
    if (-not $st) {
        throw 'hvm_ctl status 拿不到结果 —— 驱动多半没加载。先跑 Deploy-KswordDriverToVm.ps1。'
    }
    $names = @($st.stateNames)
    Write-Host ("  当前状态: {0}" -f ($names -join ' '))

    if (($names -contains 'FAULTED') -or ($names -contains 'ROLLBACK_REQUIRED')) {
        $r = Get-HvmJson 'reset-fault'
        Write-Host ("  reset-fault -> {0}" -f $(if ($r) { $r.statusName } else { '无响应' }))
        if ($r) { $names = @($r.newStateNames) }
    }
    if ($names -notcontains 'RESOURCES_READY') {
        $r = Get-HvmJson 'prepare'
        Write-Host ("  prepare -> {0}" -f $(if ($r) { $r.statusName } else { '无响应' }))
        if ($r) { $names = @($r.newStateNames) }
    } else {
        Write-Host "  prepare 跳过（RESOURCES_READY 已置位）" -ForegroundColor DarkGray
    }
    if ($names -notcontains 'SELF_TEST_PASSED') {
        $r = Get-HvmJson 'self-test'
        Write-Host ("  self-test -> {0}" -f $(if ($r) { $r.statusName } else { '无响应' }))
        if ($r) { $names = @($r.newStateNames) }
    } else {
        Write-Host "  self-test 跳过（SELF_TEST_PASSED 已置位）" -ForegroundColor DarkGray
    }

    $ok = ($names -contains 'RESOURCES_READY') -and
          ($names -contains 'SELF_TEST_PASSED') -and
          ($names -notcontains 'FAULTED')
    if (-not $ok) {
        throw ("前置条件没满足，实验不会测到任何东西。当前状态: {0}" -f ($names -join ' '))
    }
    Write-Host ("  [OK] 前置条件就绪: {0}" -f ($names -join ' ')) -ForegroundColor Green
}

Initialize-HvmPrereq

# --- 1. 基线 ----------------------------------------------------------------
Write-Host "`n--- 1. 基线（虚拟机空转 $BaselineSeconds 秒）---" -ForegroundColor Cyan
$t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt $BaselineSeconds) {
    $r = Add-Sample 'baseline'
    Start-Sleep -Seconds $SampleInterval
}
$baseNested = ($samples | Where-Object { $_.phase -eq 'baseline' } |
    ForEach-Object { Get-Field $_.PSObject.Properties['nested_vm_entries_sec'].Value '*' } ) 2>$null
$baseAvg = ($samples | Where-Object { $_.phase -eq 'baseline' -and $_.PSObject.Properties['nested_vm_entries_sec'] } |
    Measure-Object -Property nested_vm_entries_sec -Average).Average
Write-Host ("  Nested VM Entries/sec 静息均值 = {0:N2}" -f $baseAvg)

# --- 2. 标定（这一段是地基，不能跳）------------------------------------------
Write-Host "`n--- 2. 标定：发一次 LAUNCH_TEST_GUEST ---" -ForegroundColor Cyan
Write-Host "  它已知恰好产生 1 次 nested entry。计数器不跳 => 判据不可信，实验作废。" -ForegroundColor DarkGray
[void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'launch-test-guest:before' })
$calib = Invoke-HvmCtl 'launch-test-guest'
if ($calib) { Write-Host ("  退出码 {0}" -f $calib.Exit) }
for ($i = 0; $i -lt 8; $i++) { $r = Add-Sample 'calibrate'; Start-Sleep -Seconds $SampleInterval }
$calAvg = ($samples | Where-Object { $_.phase -eq 'calibrate' -and $_.PSObject.Properties['nested_vm_entries_sec'] } |
    Measure-Object -Property nested_vm_entries_sec -Maximum).Maximum
Write-Host ("  Nested VM Entries/sec 标定峰值 = {0:N2}（基线 {1:N2}）" -f $calAvg, $baseAvg)
$calibrated = ($null -ne $calAvg -and $null -ne $baseAvg -and $calAvg -gt $baseAvg)
if ($calibrated) {
    Write-Host "  [OK] 计数器对 nested entry 有反应，判据可用。" -ForegroundColor Green
} else {
    Write-Host "  [警告] 计数器没有明显跳变。后面的读数**不可作为结论**，只能当参考。" -ForegroundColor Yellow
}

if ($SkipResident) {
    Write-Host "`n按 -SkipResident 结束，不发 START_RESIDENT。" -ForegroundColor Yellow
} else {
    # --- 3. 观测 ------------------------------------------------------------
    Write-Host "`n--- 3. 观测：发 START_RESIDENT ---" -ForegroundColor Cyan
    Write-Host "  guest 可能在此挂死。采样在宿主，不受影响。" -ForegroundColor DarkGray
    [void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'resident:before' })

    # 不等它返回 —— 挂死时这个调用永远不会回来。
    $job = Start-Job -ScriptBlock {
        param($n, $u, $p)
        $c = New-Object System.Management.Automation.PSCredential(
            $u, (ConvertTo-SecureString $p -AsPlainText -Force))
        Invoke-Command -VMName $n -Credential $c -ScriptBlock {
            $o = 'C:\ksword\fr_res.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            $pp = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList @('--json','resident') `
                      -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                      -RedirectStandardError 'C:\ksword\fr_res_err.txt'
            $t = ''
            if (Test-Path $o) { $t = [IO.File]::ReadAllText($o) }
            [ordered]@{ Exit = $pp.ExitCode; Out = $t }
        }
    } -ArgumentList $VMName, $GuestUser, $GuestPassword

    $t0 = Get-Date
    while (((Get-Date) - $t0).TotalSeconds -lt $ObserveSeconds) {
        $r = Add-Sample 'observe'
        if ($r -and $r['nested_vm_entries_sec'] -ne $null) {
            Write-Host ("  t+{0,3:N0}s  nestedEntries={1,10:N1}  intercepts={2,10:N1}  guest%={3,6:N1}  hv%={4,6:N1}" -f `
                ((Get-Date) - $t0).TotalSeconds, $r['nested_vm_entries_sec'],
                $r['total_intercepts_sec'], $r['__guest_run_time'], $r['__hypervisor_run_time'])
        }
        Start-Sleep -Seconds $SampleInterval
    }
    if ($job.State -eq 'Completed') {
        $res = Receive-Job $job -ErrorAction SilentlyContinue
        Write-Host ("`n  resident 返回了：退出码 {0}" -f $res.Exit)
        if ($res.Out) { Write-Host "  $($res.Out)" }
    } else {
        Write-Host "`n  resident 调用未返回（guest 多半已挂死）。" -ForegroundColor Yellow
    }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    [void]$marks.Add([ordered]@{ utc = (Get-Date).ToUniversalTime().ToString('o'); mark = 'observe:end' })
}

# --- 落盘与判读 --------------------------------------------------------------
$samples | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
[ordered]@{
    schema     = 'ksword.hostflight/1'
    vmName     = $VMName
    instance   = $instance
    counters   = $paths
    calibrated = $calibrated
    baselineNestedEntriesAvg = $baseAvg
    calibrationNestedEntriesMax = $calAvg
    marks      = $marks
    csv        = $csv
} | ConvertTo-Json -Depth 8 | Set-Content -Path $json -Encoding UTF8

$obs = @($samples | Where-Object { $_.phase -eq 'observe' -and $_.PSObject.Properties['nested_vm_entries_sec'] })
Write-Host "`n=== 判读 ===" -ForegroundColor Cyan
if (-not $calibrated) {
    Write-Host "  标定未通过 —— 下面的判读只能当参考，不能作为结论。" -ForegroundColor Yellow
}
if ($obs.Count -eq 0) {
    Write-Host "  观测段没有有效样本。"
} else {
    $ne = ($obs | Measure-Object -Property nested_vm_entries_sec -Average).Average
    $ti = ($obs | Measure-Object -Property total_intercepts_sec -Average).Average
    $gt = ($obs | Measure-Object -Property __guest_run_time -Average).Average
    $ht = ($obs | Measure-Object -Property __hypervisor_run_time -Average).Average
    Write-Host ("  观测段均值：nestedEntries={0:N1}  intercepts={1:N1}  guest%={2:N1}  hv%={3:N1}" -f $ne, $ti, $gt, $ht)

    # 直接把观测段里涨得最凶的那几个计数器排出来 —— "十万次拦截是哪一类"
    # 这个问题必须由读数回答，不能靠猜。上一轮就是因为只采了三类而全落空。
    $cols = $samples[0].PSObject.Properties.Name | Where-Object { $_ -notin @('utc','phase','error') }
    $rank = foreach ($c in $cols) {
        $b = ($samples | Where-Object { $_.phase -eq 'baseline' -and $null -ne $_.$c } |
              Measure-Object -Property $c -Average).Average
        $o = ($obs | Where-Object { $null -ne $_.$c } | Measure-Object -Property $c -Average).Average
        if ($null -eq $o) { continue }
        [pscustomobject]@{ counter = $c; baseline = [math]::Round(($b), 1); observe = [math]::Round($o, 1); delta = [math]::Round($o - $b, 1) }
    }
    Write-Host "`n  观测段相对基线涨幅排名（前 8）：" -ForegroundColor Cyan
    $rank | Sort-Object delta -Descending | Select-Object -First 8 |
        Format-Table counter, baseline, observe, delta -AutoSize | Out-Host
    if ($ne -gt ($baseAvg + 1)) {
        Write-Host "  => VM entry **一直在成功**，退出一直在被处理，但 guest 零前进。" -ForegroundColor Yellow
        Write-Host "     接着看细分：MSR Accesses/sec 爆表 = 合成 MSR 风暴；" -ForegroundColor DarkGray
        Write-Host "     Hypercalls/sec 爆表 = hypercall 风暴；" -ForegroundColor DarkGray
        Write-Host "     Nested Page Fault Intercepts/sec 爆表 = 影子 EPT 抖动。" -ForegroundColor DarkGray
    } elseif ($ti -lt 1 -and $gt -gt 50) {
        Write-Host "  => CPU 在 L1 的 **VMX root 里空转**（L1 的 root 在 L0 眼里仍算 guest 时间）。" -ForegroundColor Yellow
    } elseif ($ht -gt $gt) {
        Write-Host "  => 卡在 **L0 那一侧**。" -ForegroundColor Yellow
    } else {
        Write-Host "  => 落不进任何一档，把 CSV 贴出来人工判读。" -ForegroundColor Yellow
    }
}
Write-Host ("`nCSV  : {0}" -f $csv)
Write-Host ("JSON : {0}" -f $json)
