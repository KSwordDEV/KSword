<#
.SYNOPSIS
    在 Hyper-V 测试机里自动推进 KSword HVM 生命周期：先读状态、再决定该做什么、
    进 VMX 之前打检查点、之后确认虚拟机还活着，全程输出机器可读的 JSON 记录。

.DESCRIPTION
    必须以**管理员**运行。

    与上一版的关键区别是：**这一版自己看状态再决定动作**，不再无条件按顺序发命令。

      * 重复 PREPARE 会把状态打成 FAULTED。已就绪时驱动返回
        STATUS_ALREADY_REGISTERED，那是 NT_ERROR，会落进 hvm_runtime.c 的
        `StateFlags |= FAULTED` 分支；而 FAULTED 会让后面的 START_RESIDENT 被
        hvm_resident.c 判 STATUS_INVALID_DEVICE_STATE 直接拒掉。也就是说
        「多跑一次 prepare」这种看上去幂等的操作会把后续流程堵死。
        本脚本因此先 status，RESOURCES_READY 已置位就跳过 prepare。

      * 看到 FAULTED / ROLLBACK_REQUIRED 就先 reset-fault 再往下走。

      * 每条命令的标志集合由 hvm_ctl.exe 按 hvm_runtime.c 的 allowedFlags 表给出。
        SELF_TEST / START_RESIDENT / SOAK / RESET_FAULT 都需要 FORCE 位，缺了
        一律是 CONFIRMATION_REQUIRED —— 那个状态码**看上去**像安全策略没开，
        实际与安全策略无关（安全策略这一侧默认就是 0x3fbff，已经放行）。

    分级是刻意的，不要跳步：

      prepare    分配每处理器资源，**不进 VMX**。失败只是资源问题，不会蓝屏。
      self-test  **逐处理器 VMXON 然后 VMXOFF**。第一次真的进 VMX root，但不常驻。
                 嵌套环境下这是关键一步 —— 它证明 L1 里能不能 VMXON。
      resident   全处理器常驻 VMM + EPT 激活。之后系统一直跑在 VMX non-root。
      soak       常驻一段有界时间再停，证明常驻扛得住正常系统活动。

.PARAMETER Stage
    safe      = status + 必要的 reset-fault/prepare + self-test（默认，不常驻）
    prepare   = 只到 prepare
    self-test = 只跑 self-test（前置条件不满足会先补齐）
    resident  = 一路到常驻，跑完 stop
    soak      = 一路到常驻并做有界浸泡
    full      = soak + stop + teardown，跑完把状态清干净
    status / stop / teardown / reset-fault = 单条命令

.PARAMETER ResultPath
    JSON 记录的落地路径。默认写到 docs\next\logs\hvm-autotest-<时间戳>.json。

.PARAMETER SkipCheckpoint
    跳过进 VMX 前的检查点。**不建议**，只在你刚打过检查点时用。

.EXAMPLE
    .\Invoke-KswordHvmControl.ps1
    .\Invoke-KswordHvmControl.ps1 -Stage soak -SoakMs 5000
#>
[CmdletBinding()]
param(
    [ValidateSet('safe', 'status', 'prepare', 'self-test', 'launch-guest',
                 'resident', 'probe-platform', 'probe-flags', 'probe-xonly',
                 'view-probe', 'view-effect',
                 'soak', 'stop', 'teardown', 'reset-fault', 'full')]
    [string] $Stage         = 'safe',
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $SoakMs        = 2000,
    # 本脚本自己造的 before-* 检查点保留几个。每个约占 8 GiB 内存映像 +
    # 一个差分盘，留多了会把系统盘吃光。手工基线（clean-install）不受此限。
    [int]    $KeepCheckpoints = 2,
    [string] $ResultPath,
    [switch] $SkipCheckpoint
)

$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop

$repo = Split-Path $PSScriptRoot -Parent
$tool = Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe'
if (-not (Test-Path $tool)) { throw "缺少 $tool（先跑 scripts\Build-KswordHvmTools.ps1）" }

if (-not $ResultPath) {
    $logDir = Join-Path $repo 'docs\next\logs'
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }
    $ResultPath = Join-Path $logDir ('hvm-autotest-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '.json')
}

$cred = New-Object System.Management.Automation.PSCredential(
    $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

# 整份记录。每一步都往里追加，脚本中途抛异常时也会落盘（见末尾的 finally）。
$record = [ordered]@{
    schema      = 'ksword.hvm.autotest/1'
    startedUtc  = (Get-Date).ToUniversalTime().ToString('o')
    vmName      = $VMName
    stage       = $Stage
    host        = [ordered]@{
        computer = $env:COMPUTERNAME
        os       = (Get-CimInstance Win32_OperatingSystem).Caption
        build    = (Get-CimInstance Win32_OperatingSystem).BuildNumber
    }
    steps       = New-Object System.Collections.ArrayList
    checkpoints = New-Object System.Collections.ArrayList
    verdict     = 'NOT_RUN'
    notes       = New-Object System.Collections.ArrayList
}

function Add-Step {
    param([string] $Name, [string] $Outcome, $Data, [string] $Note)
    $entry = [ordered]@{
        name    = $Name
        utc     = (Get-Date).ToUniversalTime().ToString('o')
        outcome = $Outcome
    }
    if ($null -ne $Data) { $entry.data = $Data }
    if ($Note)           { $entry.note = $Note }
    [void]$record.steps.Add($entry)
    $color = switch ($Outcome) { 'OK' { 'Green' } 'SKIP' { 'DarkGray' } 'BLOCKED' { 'Yellow' } default { 'Red' } }
    Write-Host ("  [{0,-7}] {1}{2}" -f $Outcome, $Name, $(if ($Note) { "  — $Note" })) -ForegroundColor $color
}

function Save-Record {
    $record.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
    # JSON 必须无 BOM，见文件末尾说明。
    [IO.File]::WriteAllText(
        $ResultPath,
        ($record | ConvertTo-Json -Depth 12),
        (New-Object Text.UTF8Encoding($false)))
}

function Invoke-Guest {
    # 参数名不能叫 $Args —— 那是 PowerShell 的自动变量，会让 -ArgumentList 收到空值。
    param([scriptblock] $Script, [object[]] $ScriptArgs)
    if ($null -eq $ScriptArgs -or $ScriptArgs.Count -eq 0) {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script
    } else {
        Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $Script -ArgumentList $ScriptArgs
    }
}

function Test-GuestAlive {
    param([int] $TimeoutSeconds = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $null = Invoke-Command -VMName $VMName -Credential $cred `
                        -ScriptBlock { $env:COMPUTERNAME } -ErrorAction Stop
            return $true
        } catch { Start-Sleep -Seconds 5 }
    }
    return $false
}

# guest 的开机时刻。用来把"活着"和"崩过又自己起来了"分开。
#
# 光看"能不能应答"是不够的：部署脚本把 AutoReboot 设成 1（那是为了拿转储），
# 所以一次蓝屏 + 自动重启只要在 Test-GuestAlive 的 120 秒窗口内起来，
# 就和"从没崩过"一模一样 —— alive:OK。整晚的 PASS 里可能就混着这种。
function Get-GuestBootTime {
    try {
        $t = Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop `
                 -ScriptBlock { (Get-CimInstance Win32_OperatingSystem).LastBootUpTime }
        return [datetime]$t
    } catch { return $null }
}

# 崩没崩过：开机时刻变了就是重启过。再去事件日志里区分蓝屏与静默复位。
function Get-GuestCrashEvidence {
    param($BootBefore)

    $bootAfter = Get-GuestBootTime
    if ($null -eq $BootBefore -or $null -eq $bootAfter) { return $null }
    if ([math]::Abs(($bootAfter - $BootBefore).TotalSeconds) -lt 2) { return $null }

    $code = $null
    try {
        $code = Invoke-Command -VMName $VMName -Credential $cred -ErrorAction Stop -ScriptBlock {
            $e = Get-WinEvent -FilterHashtable @{
                     LogName='System'; ProviderName='Microsoft-Windows-Kernel-Power'; Id=41
                 } -MaxEvents 1 -ErrorAction SilentlyContinue
            if (-not $e) { return $null }
            $x = [xml]$e.ToXml()
            ($x.Event.EventData.Data | Where-Object { $_.Name -eq 'BugcheckCode' }).'#text'
        }
    } catch { }

    if ($null -ne $code -and [int]$code -ne 0) {
        return "本阶段**蓝屏并重启过** bugcheck=0x$('{0:X}' -f [int]$code)（开机时刻 $BootBefore -> $bootAfter）"
    }
    return "本阶段**重启过但没有 bugcheck 码** —— 静默复位（三重故障的典型指纹），开机时刻 $BootBefore -> $bootAfter"
}

function New-Guard {
    param([string] $Label)
    if ($SkipCheckpoint) { Add-Step "checkpoint:$Label" 'SKIP' $null '按 -SkipCheckpoint 跳过'; return $null }

    # 每个检查点要存一份完整内存映像（本机 8 GiB）加一个差分盘，分级测试
    # 每轮产生一到两个。不清理的话很快把系统盘吃光，表现是
    # "Checkpoint operation failed ... 磁盘空间不足 (0x80070070)"，
    # 而那时脚本已经跑到一半，看上去像 HVM 出了问题。
    # 所以每次打检查点之前先修剪本脚本自己造的那些（名字以 before- 开头），
    # 只保留最近 $KeepCheckpoints 个。**从不碰 clean-install 之类的手工基线。**
    try {
        $mine = @(Get-VMSnapshot -VMName $VMName -ErrorAction Stop |
                  Where-Object { $_.Name -like 'before-*' } |
                  Sort-Object CreationTime -Descending)
        if ($mine.Count -gt $KeepCheckpoints) {
            foreach ($old in $mine[$KeepCheckpoints..($mine.Count - 1)]) {
                Remove-VMSnapshot -VMName $VMName -Name $old.Name -Confirm:$false
                Add-Step "prune:$($old.Name)" 'OK' $null '自动修剪旧检查点以回收磁盘'
            }
            # 合并是异步的，不等的话下一次 Checkpoint-VM 仍可能撞上空间不足。
            $deadline = (Get-Date).AddMinutes(15)
            while ((Get-Date) -lt $deadline -and
                   (Get-VM -Name $VMName).Status -match 'Merg|合并') {
                Start-Sleep -Seconds 10
            }
        }
    } catch {
        [void]$record.notes.Add("检查点修剪失败（不影响后续）：$($_.Exception.Message)")
    }

    $name = "before-$Label-" + (Get-Date -Format 'MMdd-HHmmss')
    try {
        Checkpoint-VM -Name $VMName -SnapshotName $name
    } catch {
        # 空间不足是可恢复的操作问题，不是 HVM 的失败。分开报，并给出清理命令。
        Add-Step "checkpoint:$Label" 'FAIL' $null $_.Exception.Message
        if ("$($_.Exception.Message)" -match '0x80070070|磁盘空间不足|not enough space') {
            [void]$record.notes.Add('检查点失败是磁盘空间不足，与 HVM 无关。清理：.\scripts\Clear-KswordVmCheckpoints.ps1 -Confirm')
        }
        throw
    }
    [void]$record.checkpoints.Add($name)
    Add-Step "checkpoint:$Label" 'OK' $name
    return $name
}

# ---------------------------------------------------------------------------
# hvm_ctl.exe 的调用与 JSON 解析
#
# 原生 exe 的 stdout 穿过 PowerShell Direct 会被吞掉，所以在 guest 内重定向到
# 文件再读回。这不是保险起见 —— 直接 `& exe | Out-String` 拿到的是一片空白，
# 看上去像"命令没有输出"。
# ---------------------------------------------------------------------------
function Invoke-HvmCtl {
    param([string] $Command, [int] $Arg = 0)

    $raw = Invoke-Guest {
        param($cmdName, $cmdArg)
        $o = 'C:\ksword\hvm_out.txt'
        $e = 'C:\ksword\hvm_err.txt'
        Remove-Item $o, $e -ErrorAction SilentlyContinue
        $argList = @('--json', $cmdName)
        if ($cmdArg -gt 0) { $argList += "$cmdArg" }
        $p = Start-Process -FilePath 'C:\ksword\hvm_ctl.exe' -ArgumentList $argList `
                 -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o -RedirectStandardError $e
        # 用 ReadAllText 而不是 Get-Content -Raw，理由是它**不可能返回 null**：
        #   * `Get-Content -Raw` 读一个真正的空文件时输出零个对象；
        #   * `[string]$( 零个对象 )` 求值结果仍然是 $null，不是 ''（实测过，
        #     以为加了 [string] 就安全是错的）；
        #   * 那个 $null 穿过 PowerShell Direct 的序列化边界会变成一个**空的
        #     PSCustomObject**，它在 `if ($x)` 里为**真**（任何非 null 对象都为真）
        #     却没有任何字符串方法，下游调 .Trim() 就抛
        #     "does not contain a method named 'Trim'"。
        # 实测踩过两次，第二次正好在 resident 返回非零那条分支上，
        # 把最需要的那份失败响应弄丢了。ReadAllText 空文件返回 ''，链条从源头断掉。
        $outText = ''
        $errText = ''
        if (Test-Path $o) { $outText = [IO.File]::ReadAllText($o) }
        if (Test-Path $e) { $errText = [IO.File]::ReadAllText($e) }
        [ordered]@{
            Exit = $p.ExitCode
            Out  = $outText
            Err  = $errText
        }
    } -ScriptArgs @($Command, $Arg)

    $stdout = ConvertTo-Text $raw.Out
    $stderr = ConvertTo-Text $raw.Err

    $parsed = $null
    if ($stdout) {
        try { $parsed = $stdout | ConvertFrom-Json } catch { $parsed = $null }
    }
    return [ordered]@{
        Exit   = $raw.Exit
        Json   = $parsed
        Stdout = $stdout
        Stderr = $stderr
    }
}

# 把穿过 PowerShell Direct 回来的东西安全地变成字符串。
# 空文件读回来是 $null，序列化后是空 PSCustomObject —— 它非空为真，
# 但没有任何字符串方法。凡是要当文本用的都先过这里。
function ConvertTo-Text {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    $s = "$Value"
    # 空 PSCustomObject 的字符串化结果是空串或类型名，两者都不是内容
    if ($s -eq '' -or $s -eq 'System.Management.Automation.PSCustomObject') { return '' }
    return $s
}

# 状态位名字是否出现在 status/control 的结果里
function Test-StateBit {
    param($StateNames, [string] $Bit)
    if ($null -eq $StateNames) { return $false }
    return [bool]($StateNames -contains $Bit)
}

$exitCode = 0
try {
    $vm = Get-VM -Name $VMName -ErrorAction Stop
    $nested = (Get-VMProcessor -VMName $VMName).ExposeVirtualizationExtensions
    $record.vm = [ordered]@{
        state = "$($vm.State)"; vcpu = $vm.ProcessorCount; nested = [bool]$nested
    }
    Write-Host ("=== KSword HVM 自动化：{0} ===" -f $Stage) -ForegroundColor Cyan
    Write-Host ("虚拟机 {0}  {1}  {2} vCPU  嵌套={3}" -f $vm.Name, $vm.State, $vm.ProcessorCount, $nested)
    Write-Host ("记录 -> {0}`n" -f $ResultPath) -ForegroundColor DarkGray

    if ($vm.State -ne 'Running') { throw "虚拟机不在运行状态（$($vm.State)）。先 Start-VM。" }
    if (-not $nested) { throw '嵌套虚拟化没开 —— 关机后 Set-VMProcessor -ExposeVirtualizationExtensions $true' }

    # ---- 送工具（每次都送，保证跑的是刚编译的那个）------------------------
    Invoke-Guest { New-Item -ItemType Directory -Force -Path 'C:\ksword' | Out-Null } | Out-Null
    try {
        Copy-VMFile -Name $VMName -SourcePath $tool -DestinationPath 'C:\ksword\hvm_ctl.exe' `
                    -CreateFullPath -FileSource Host -Force -ErrorAction Stop
    } catch {
        $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($tool))
        Invoke-Guest {
            param($d, $t)
            [IO.File]::WriteAllBytes($t, [Convert]::FromBase64String($d))
        } -ScriptArgs @($b64, 'C:\ksword\hvm_ctl.exe')
    }
    Add-Step 'deploy:hvm_ctl' 'OK' ((Get-Item $tool).Length)

    # ---- 第一步永远是只读状态 --------------------------------------------
    $st = Invoke-HvmCtl 'status'
    if ($st.Exit -ne 0 -or $null -eq $st.Json) {
        Add-Step 'status' 'FAIL' $st.Stderr '设备查询失败 —— 驱动可能没加载'
        $record.verdict = 'BLOCKED'
        [void]$record.notes.Add('hvm_ctl status 拿不到结果，后续全部未运行。先跑 Deploy-KswordDriverToVm.ps1。')
        $exitCode = 1
        return
    }
    Add-Step 'status' 'OK' $st.Json
    $names = $st.Json.stateNames
    Write-Host ("  状态位: {0}" -f ($names -join ' ')) -ForegroundColor DarkGray

    if ($Stage -eq 'status') { $record.verdict = 'OK'; return }

    # ---- 单条命令模式 ------------------------------------------------------
    if ($Stage -in @('stop', 'teardown', 'reset-fault')) {
        $r = Invoke-HvmCtl $Stage
        Add-Step $Stage $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
        $record.verdict = if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }
        $exitCode = $r.Exit
        return
    }

    # ---- 前置条件自愈：FAULTED 先清，未就绪才 prepare ----------------------
    if ((Test-StateBit $names 'FAULTED') -or (Test-StateBit $names 'ROLLBACK_REQUIRED')) {
        $r = Invoke-HvmCtl 'reset-fault'
        Add-Step 'reset-fault' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                 '状态里带 FAULTED/ROLLBACK_REQUIRED，先清掉否则 resident 必被拒'
        if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
        $names = $r.Json.newStateNames
    }

    # 分离视图那两级要的是 EPTP 切换后端，而后端只能在 PREPARE 里选。
    $needEptpSwitch = $Stage -in @('view-effect')
    $prepareVerb = if ($needEptpSwitch) { 'prepare-eptpsw' } else { 'prepare' }

    if ((Test-StateBit $names 'RESOURCES_READY') -and $needEptpSwitch) {
        # 已经 prepare 过、但可能是**用另一个后端**准备的。
        # 直接跳过 prepare 会让这一级安静地在错误的后端上跑完并报通过 ——
        # 那正是这条线上最贵的一类错误。先拆再按需要的后端重来。
        $armed = Invoke-HvmCtl 'status'
        $isArmed = ($armed.Json.featureNames -contains 'EPTP_SWITCH_ARMED')
        if (-not $isArmed) {
            $r = Invoke-HvmCtl 'teardown'
            Add-Step 'teardown' $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json `
                     '已 prepare 但没有武装 EPTP 切换后端；先拆掉，否则这一级会在错误的后端上测'
            if ($r.Exit -ne 0) { $record.verdict = 'FAIL'; $exitCode = $r.Exit; return }
            $names = @()
        }
    }

    if (Test-StateBit $names 'RESOURCES_READY') {
        Add-Step 'prepare' 'SKIP' $null 'RESOURCES_READY 已置位；重复 prepare 会返回 ALREADY_PREPARED 并把状态打成 FAULTED'
    } else {
        $r = Invoke-HvmCtl $prepareVerb
        Add-Step $prepareVerb $(if ($r.Exit -eq 0) { 'OK' } else { 'FAIL' }) $r.Json
        if ($r.Exit -ne 0) {
            $record.verdict = 'FAIL'
            [void]$record.notes.Add("prepare 返回 $($r.Json.statusName)（lastStatus=$($r.Json.lastStatus)）")
            $exitCode = $r.Exit
            return
        }
        $names = $r.Json.newStateNames
    }
    if ($Stage -eq 'prepare') { $record.verdict = 'OK'; return }

    # ---- 会真的进 VMX 的级别：检查点 -> 执行 -> 存活确认 -------------------
    $plan = switch ($Stage) {
        'safe'      { @('self-test') }
        'self-test' { @('self-test') }
        # launch-test-guest 是 self-test 与 resident 之间缺失的那一级：
        # self-test 只做 VMXON/VMXOFF，不写 VMCS、不装 EPTP、不 VMLAUNCH。
        # 这一级真写 VMCS、真装 EPTP、真 VMLAUNCH 进一个只执行 VMCALL 的
        # guest，爆炸半径是一个 4KiB guest 栈。它回答的是"L0 认不认我们的
        # VMCS 构造"，而那是 self-test 完全没碰过的一块。
        'launch-guest' { @('self-test', 'launch-test-guest') }
        'resident'  { @('self-test', 'resident', 'stop') }
        # 平台探针是纯只读：不进 VMX、不改任何执行路径、不分配、不加锁。
        # 所以它既不进 risky 列表，也不需要 self-test 垫在前面。
        'probe-platform' { @('probe-platform') }
        # 负向探针要垫 self-test。
        #
        # 驱动的前置检查（RESOURCES_READY|EPT_READY|SELF_TEST_PASSED 三个齐）
        # 排在**所有能力门之前**，没齐就先返回 NOT_PREPARED。那时"能力门有没有
        # 放行"这个问题根本没被问到，用例会**空过** —— 报通过而什么都没测。
        # 所以顺序不是可选的，它决定这一组测不测得到东西。
        'probe-flags' { @('self-test', 'probe-flags') }
        # 探针**自己**管常驻的起停，这里不要替它起。
        # 原因是驱动的硬约束：常驻期间规则表不可变（退出路径不加锁扫它），
        # 所以顺序只能是 装规则 → 起常驻 → 读 → 停常驻 → 清规则；
        # 而那一页是工具进程的内存，必须活到常驻起来 —— 只能同进程做完。
        'probe-xonly' { @('self-test', 'probe-xonly') }
        # 视图安装期归因探针：只发一次 VIEW_OP_ADD，装上会立刻卸掉。
        # 它不需要 self-test（不进 VMX），但需要 EPT_READY，而那由前面的
        # prepare 保证；垫 self-test 只为了与其它探针的前置一致。
        'view-probe'  { @('self-test', 'view-probe') }
        # 端到端生效判据。探针**自己**管常驻起停 —— 与 probe-xonly 同一个理由：
        # 视图表常驻期间不可变，所以顺序只能是 装视图 → 起常驻 → 读 → 停 → 卸，
        # 而那一页是工具进程的内存，必须活到常驻起来，只能同进程做完。
        'view-effect' { @('self-test', 'view-effect') }
        'soak'      { @('self-test', 'soak') }
        'full'      { @('self-test', 'soak', 'stop', 'teardown') }
        default     { @() }
    }

    # 只增不减：任何一步空过就置真，末尾据此把这一段判成 PARTIAL 而不是 OK。
    $anyBlocked = $false

    foreach ($step in $plan) {
        # probe-xonly 自己会起一次常驻，所以它和 resident/soak 一样危险，
        # 必须先打检查点。
        # probe-flags 也算 risky：它的用例 2/3 发的是带 FORCE 的 START_RESIDENT，
        # 靶机若真有 #VE 能力，那一条会**把常驻真的起起来**，而工具里没有配对的
        # stop。打个检查点是这条路上最便宜的保险。
        # view-effect 自己会起一次常驻并且**真的让 EPT 强制一次访问**，
        # 是这条路上唯一会走到 EPTP 切换退出路径的一级，所以必须打检查点。
        # view-probe 只发请求、不进 VMX，不算 risky。
        $risky = $step -in @('self-test', 'launch-test-guest', 'resident',
                             'soak', 'probe-flags', 'probe-xonly', 'view-effect')
        $snap = $null
        $bootBefore = $null
        if ($risky) {
            $snap = New-Guard $step
            # 记下开机时刻，回来对一次 —— "能应答"不等于"没崩过"。
            $bootBefore = Get-GuestBootTime
        }

        $arg = if ($step -eq 'soak') { $SoakMs } else { 0 }
        $r = Invoke-HvmCtl $step $arg

        if ($risky) {
            if (Test-GuestAlive) {
                $crash = Get-GuestCrashEvidence $bootBefore
                if ($crash) {
                    Add-Step "alive:$step" 'FAIL' $null $crash
                    $record.verdict = 'FAIL'
                    [void]$record.notes.Add($crash)
                    [void]$record.notes.Add("转储取证：.\scripts\Get-KswordVmBugcheck.ps1")
                    [void]$record.notes.Add("回滚：Restore-VMCheckpoint -VMName '$VMName' -Name '$snap' -Confirm:`$false")
                    $exitCode = 1
                    return
                }
                Add-Step "alive:$step" 'OK' $null '虚拟机仍然响应，且没有重启过'
            } else {
                Add-Step "alive:$step" 'FAIL' "$((Get-VM -Name $VMName).State)" '虚拟机失联，很可能蓝屏'
                $record.verdict = 'FAIL'
                [void]$record.notes.Add("在 $step 阶段失去响应。回滚：Restore-VMCheckpoint -VMName '$VMName' -Name '$snap' -Confirm:`$false")
                [void]$record.notes.Add('转储应在 guest 的 C:\Windows\MEMORY.DMP（部署脚本已提前开启内核转储）')
                $exitCode = 1
                return
            }
        }

        if ($r.Exit -eq 0) {
            Add-Step $step 'OK' $r.Json
        } elseif ($r.Exit -eq 3) {
            # 退出码 3 = 探针"跑完了但没测到" —— 前置没建立、或者标定不全。
            # 它既不是通过也不是失败：记 BLOCKED 并继续，但**不许**被读成通过。
            Add-Step $step 'BLOCKED' $r.Json `
                '探针空过：跑完了但没有区分力（前置未建立或标定不全），不算通过'
            [void]$record.notes.Add("$step 空过 —— 这一项这次什么都没测到。")
            # 记在一个**只增不减**的标志上，不要在这里改 verdict。
            #
            # 上一版写的是 `if ($record.verdict -eq 'OK') { ... = 'PARTIAL' }`，
            # 而这一刻 verdict 还是初值 'NOT_RUN'（第 99 行），**那个条件永远不成立**；
            # 紧接着计划循环末尾又无条件写 'OK'，于是 BLOCKED 被静默升级成通过。
            # 2026-09-07 实测：2 vCPU 上 view-effect 因多核门装不上视图、工具如实
            # 报「测不到生效与否」并退 3，套件却把这一段印成 [PASS]。
            $anyBlocked = $true
        } else {
            # **先把响应记下来再做任何别的事。** 上一版在这里先格式化 note、
            # 后 Add-Step，结果格式化抛异常时把整份失败响应弄丢了 ——
            # 而失败时那份响应恰恰是唯一有价值的东西。
            $sn = if ($r.Json) { "$($r.Json.statusName)" } else { 'NO_JSON' }
            # 能力缺失与代码失败要分开记：前者是 BLOCKED，后者是 FAIL。
            $blockedStatuses = @('UNSUPPORTED_CPU', 'FIRMWARE_DISABLED', 'HYPERVISOR_CONFLICT',
                                 'NESTED_UNSUPPORTED', 'EVMCS_UNSUPPORTED', 'PARTIAL_IMPLEMENTATION')
            $outcome = if ($blockedStatuses -contains $sn) { 'BLOCKED' } else { 'FAIL' }
            $note = (ConvertTo-Text $r.Stderr).Trim()
            Add-Step $step $outcome $r.Json $note
            $record.verdict = $outcome
            $ls = if ($r.Json) { "$($r.Json.lastStatus)" } else { '?' }
            [void]$record.notes.Add("$step 返回 $sn（lastStatus=$ls）；后续级别不再执行。")

            # LIFECYCLE_GUARD_FAILED 是 KswordARKHvmArmUnloadGuard 的失败，
            # 而它三条失败分支里唯一还没被排除的那条比较的是
            # DriverObject->DriverUnload 与注册时捕获的原值。所以这里直接把
            # 驱动自己的 DriverObject 读回来 —— 现值是不是 0 一眼就能定案，
            # 不用再靠推理。
            if ($sn -eq 'LIFECYCLE_GUARD_FAILED') {
                try {
                    $doRaw = Invoke-Guest {
                        $o = 'C:\ksword\drvobj.txt'
                        Remove-Item $o -ErrorAction SilentlyContinue
                        if (-not (Test-Path 'C:\ksword\KswordCLI.exe')) { return '' }
                        $p = Start-Process -FilePath 'C:\ksword\KswordCLI.exe' `
                                 -ArgumentList @('kernel', 'query-driver-object', '--driver', 'KswordARK') `
                                 -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                                 -RedirectStandardError 'C:\ksword\drvobj_err.txt'
                        if (Test-Path $o) { [IO.File]::ReadAllText($o) } else { "（无输出，退出码 $($p.ExitCode)）" }
                    }
                    $doText = ConvertTo-Text $doRaw
                    if ($doText) {
                        $record.driverObject = $doText
                        Write-Host "`n--- KswordARK 的 DriverObject（现值）---" -ForegroundColor Cyan
                        Write-Host $doText
                        $unload = ([regex]::Match($doText, 'driverUnload=(0x[0-9A-Fa-f]+)')).Groups[1].Value
                        if ($unload) {
                            [void]$record.notes.Add("当前 DriverObject->DriverUnload = $unload（注册时捕获的是非 0 值，否则 EnableResidentLifecycle 会提前返回）")
                        }
                    }
                } catch { [void]$record.notes.Add('DriverObject 查询失败') }
            }
            if ($r.Stdout) { [void]$record.notes.Add("原始 stdout: $((ConvertTo-Text $r.Stdout).Trim())") }
            $exitCode = $r.Exit
            return
        }
    }

    # 有任何一步空过，这一段就不是 OK。
    # 「跑完了没崩」与「测到了东西」是两件事，把前者印成后者正是本仓库反复吃亏的形状。
    $record.verdict = if ($anyBlocked) { 'PARTIAL' } else { 'OK' }
}
catch {
    $record.verdict = 'ERROR'
    [void]$record.notes.Add("脚本异常：$($_.Exception.Message)")
    Write-Host "`n脚本异常：$($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}
finally {
    # 无论怎么退出，最终状态都要读一次并落盘 —— 半路抛异常时这份记录尤其重要。
    # 收尾之前先确保常驻不会被留在跑着的状态。
    #
    # 常驻会活过发起它的进程（这是设计，也实测过），所以一个计划中途失败
    # 直接 return 时，常驻就那么留着了。下一次部署会撞上一个很有迷惑性的
    # 报错：CPUID 看不到 VMX —— 因为我们自己的 CPUID 处理按设计抹掉了那一位。
    # 报错指向"嵌套虚拟化没开"，实际却是上一轮没收干净。踩过一次。
    try {
        $pre = Invoke-HvmCtl 'status'
        if ($pre.Json -and $pre.Json.residentProcessorCount -gt 0) {
            Write-Host "`n收尾：常驻仍在跑（residentProcessorCount=$($pre.Json.residentProcessorCount)），停掉它" -ForegroundColor Yellow
            $cleanup = Invoke-HvmCtl 'stop'
            Add-Step 'cleanup:stop' $(if ($cleanup.Exit -eq 0) { 'OK' } else { 'FAIL' }) $cleanup.Json `
                '计划未跑到 stop 就退出，这里补一次'
        }
    } catch { [void]$record.notes.Add('收尾停机检查失败（虚拟机可能已失联）') }

    try {
        $final = Invoke-HvmCtl 'status'
        if ($final.Json) {
            $record.finalStatus = $final.Json
            # 退出遥测直接打在控制台上。这是目前唯一一条不经过串口的退出观测面：
            # 内核调试器的报告通道自己就是端口 I/O，而端口 I/O 正是待查的现象。
            $j = $final.Json
            if ($null -ne $j.vmExitCount) {
                Write-Host ""
                Write-Host "--- 退出遥测 ---" -ForegroundColor Cyan
                Write-Host ("  count={0}  reason={1}  instrLen={2}" -f
                    $j.vmExitCount, $j.lastExitReason, $j.lastExitInstructionLength)
                Write-Host ("  qualification={0}  guestRip={1}  guestRsp={2}" -f
                    $j.lastExitQualification, $j.lastGuestRip, $j.lastGuestRsp)
                if ($j.lastExitReason -eq 30) {
                    # SDM Table 28-5：bits31:16 端口号，bit3 方向（1=IN），bits2:0 宽度
                    $qs = "$($j.lastExitQualification)"
                    if ($qs.StartsWith('0x')) { $qs = $qs.Substring(2) }
                    $q = [Convert]::ToUInt64($qs, 16)
                    $port = [int](($q -shr 16) -band 0xFFFF)
                    $dir  = if ((($q -shr 3) -band 1) -eq 1) { 'IN' } else { 'OUT' }
                    $size = @(1,2,0,4,0,0,0,0)[[int]($q -band 0x7)]
                    Write-Host ("  >>> I/O 退出：{0} 端口 0x{1:X4} ({1})  {2} 字节" -f
                        $dir, $port, $size) -ForegroundColor Green
                }
            }
        }
        # 驱动事件环。
        #
        # 这一段之前引用了一个**从未被赋值**的 $ev，所以 driverEvents 永远不写 ——
        # 一段看着像在取证、实际是死代码的东西。现在真的去取。
        # 注意事件环实测丢包 97%（每次退出都无条件发事件而环只有 1024 槽），
        # 所以它只能当补充线索，不能当判据。
        $ev = Invoke-Guest {
            $o = 'C:\ksword\hvm_events.txt'
            Remove-Item $o -ErrorAction SilentlyContinue
            if (-not (Test-Path 'C:\ksword\KswordCLI.exe')) { return '' }
            $p = Start-Process -FilePath 'C:\ksword\KswordCLI.exe' `
                     -ArgumentList @('r0', 'hvm-events', '--max-rows', '64') `
                     -NoNewWindow -Wait -PassThru -RedirectStandardOutput $o `
                     -RedirectStandardError 'C:\ksword\hvm_events_err.txt'
            if (Test-Path $o) { [IO.File]::ReadAllText($o) }
            else { "（无输出，退出码 $($p.ExitCode)）" }
        }
        $evText = ConvertTo-Text $ev
        if ($evText) {
            $record.driverEvents = $evText
            if ($record.verdict -ne 'OK') {
                Write-Host "`n--- 驱动事件环（丢包率高，仅作线索）---" -ForegroundColor Cyan
                Write-Host $evText
            }
        }
    } catch { [void]$record.notes.Add('事件环查询失败') }

    try { $record.checkpointsNow = @(Get-VMSnapshot -VMName $VMName | ForEach-Object { $_.Name }) } catch { }

    # 空过必须有自己的退出码。
    #
    # 否则调用方（无人值守套件）看到 0 就记 PASS，而那一项其实什么都没测到 ——
    # 那正是这条线上最贵的一类错误：一个看起来全绿的报告。
    if ($record.verdict -eq 'PARTIAL' -and $exitCode -eq 0) { $exitCode = 3 }

    Save-Record
    Write-Host ("`n判定: {0}" -f $record.verdict) -ForegroundColor $(
        switch ($record.verdict) { 'OK' { 'Green' } 'PARTIAL' { 'Yellow' } 'BLOCKED' { 'Yellow' } default { 'Red' } })
    foreach ($n in $record.notes) { Write-Host "  · $n" -ForegroundColor Yellow }
    Write-Host ("记录已写入 {0}" -f $ResultPath) -ForegroundColor Cyan

    # exit 放在 finally 里：try 里的 `return` 会直接结束脚本，写在 finally 之后
    # 的语句根本不会执行，退出码就会永远是 0 —— 那会让 CI 把失败当成通过。
    exit $exitCode
}
