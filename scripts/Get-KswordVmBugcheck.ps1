<#
.SYNOPSIS
    蓝屏取证：把 guest 的 bugcheck 码与 minidump 取回宿主并直接分析。

.DESCRIPTION
    挂死时 guest 里什么都读不到，只能靠宿主计数器；**蓝屏不一样** —— 它留下
    bugcheck 码和转储。这个脚本把那条证据链一次走完：

      1. 虚拟机没在跑就开机，等 PowerShell Direct 恢复；
      2. 读 guest 的崩溃配置（CrashDumpEnabled / AutoReboot / 转储路径）；
      3. 读 System 事件日志里的 BugCheck 记录（WER-SystemErrorReporting 1001
         与 Kernel-Power 41，后者的 XML 里直接带 BugcheckCode）；
      4. 把最新的 minidump 用 PSSession 拷回宿主 docs/next/logs/；
      5. 直接在宿主用 kd -z 跑 !analyze -v，输出落盘。

    只读取证：不改 guest 任何设置、不重启、不动虚拟机配置（除了必要的开机）。

.NOTES
    转储写不出来是常态，不是脚本坏了：CrashDumpEnabled 可能是 0，或者
    页面文件小于最小转储尺寸。脚本会**明确报告是哪一种**，而不是含糊地说
    "没找到转储" —— 那种含糊正是这条线上反复浪费时间的来源。
#>

[CmdletBinding()]
param(
    [string] $VMName        = 'KSword-HVM-Target',
    [string] $GuestUser     = 'felix',
    [string] $GuestPassword = 'password',
    [int]    $WaitSeconds   = 300,
    # 只取证据不跑 kd（比如宿主上没装调试器）
    [switch] $SkipAnalyze
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$NL     = [Environment]::NewLine

function Write-Head { param([string] $T) Write-Host ''; Write-Host "=== $T ===" -ForegroundColor Cyan }

# --- 1. 虚拟机状态 ---------------------------------------------------------
Write-Head '虚拟机状态'
$vm = Get-VM -Name $VMName -ErrorAction Stop
Write-Host ('{0}  state={1}  uptime={2}' -f $vm.Name, $vm.State, $vm.Uptime)

if ($vm.State -ne 'Running') {
    Write-Host "虚拟机不在运行（$($vm.State)），开机……" -ForegroundColor Yellow
    if ($vm.State -eq 'Paused') { Resume-VM -Name $VMName } else { Start-VM -Name $VMName }
}

$cred = New-Object System.Management.Automation.PSCredential(
            $GuestUser, (ConvertTo-SecureString $GuestPassword -AsPlainText -Force))

Write-Host "等待 PowerShell Direct（最多 $WaitSeconds 秒）……"
$deadline = (Get-Date).AddSeconds($WaitSeconds)
$session  = $null
while ((Get-Date) -lt $deadline) {
    try {
        $session = New-PSSession -VMName $VMName -Credential $cred -ErrorAction Stop
        break
    } catch { Start-Sleep -Seconds 5 }
}
if (-not $session) {
    Write-Host 'PowerShell Direct 一直没起来。guest 多半停在蓝屏画面上（AutoReboot 关着）。' -ForegroundColor Red
    Write-Host '打开 vmconnect 看一眼屏幕上的 bugcheck 码，或者拔电源重启：' -ForegroundColor Yellow
    Write-Host "  Stop-VM -Name '$VMName' -TurnOff -Force; Start-VM -Name '$VMName'"
    exit 2
}

$report = [ordered]@{
    vm        = $VMName
    stampUtc  = (Get-Date).ToUniversalTime().ToString('o')
    crashCfg  = $null
    bugchecks = @()
    dumps     = @()
    copied    = $null
    analyzed  = $null
}

# --- 2. 崩溃转储配置 -------------------------------------------------------
Write-Head 'guest 崩溃转储配置'
$report.crashCfg = Invoke-Command -Session $session -ScriptBlock {
    $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
    $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
    $pf = Get-CimInstance Win32_PageFileUsage -ErrorAction SilentlyContinue |
              Select-Object -First 1 -ExpandProperty AllocatedBaseSize
    [ordered]@{
        # 0=不写 1=完整 2=内核 3=小(minidump) 7=自动
        CrashDumpEnabled = $p.CrashDumpEnabled
        AutoReboot       = $p.AutoReboot
        DumpFile         = $p.DumpFile
        MinidumpDir      = $p.MinidumpDir
        PagefileMB       = $pf
    }
}
foreach ($kv in $report.crashCfg.GetEnumerator()) {
    Write-Host ('  {0,-17}: {1}' -f $kv.Key, $kv.Value)
}
if ($report.crashCfg.CrashDumpEnabled -eq 0) {
    Write-Host '  ** CrashDumpEnabled = 0：这台机器根本不写转储。**' -ForegroundColor Red
    Write-Host '     事件日志里仍然有 bugcheck 码，往下看。' -ForegroundColor Yellow
}

# --- 3. 事件日志里的 bugcheck ---------------------------------------------
Write-Head '事件日志：BugCheck'
$report.bugchecks = @(Invoke-Command -Session $session -ScriptBlock {
    $out = @()
    # 1001 / WER-SystemErrorReporting：消息里带完整的 bugcheck 参数串
    try {
        $out += Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
                    Id = 1001
                } -MaxEvents 5 -ErrorAction Stop |
                ForEach-Object {
                    [ordered]@{ time = $_.TimeCreated.ToString('o'); id = 1001; text = $_.Message }
                }
    } catch { }
    # 41 / Kernel-Power：非正常关机，XML 里直接带 BugcheckCode
    try {
        $out += Get-WinEvent -FilterHashtable @{
                    LogName = 'System'
                    ProviderName = 'Microsoft-Windows-Kernel-Power'
                    Id = 41
                } -MaxEvents 5 -ErrorAction Stop |
                ForEach-Object {
                    $x  = [xml]$_.ToXml()
                    $d  = $x.Event.EventData.Data
                    $bc = ($d | Where-Object { $_.Name -eq 'BugcheckCode' }).'#text'
                    $p1 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter1' }).'#text'
                    $p2 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter2' }).'#text'
                    $p3 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter3' }).'#text'
                    $p4 = ($d | Where-Object { $_.Name -eq 'BugcheckParameter4' }).'#text'
                    [ordered]@{
                        time = $_.TimeCreated.ToString('o')
                        id   = 41
                        text = ('BugcheckCode={0} (0x{0:X})  P1={1} P2={2} P3={3} P4={4}' -f
                                    [int]$bc, $p1, $p2, $p3, $p4)
                    }
                }
    } catch { }
    $out
})
if ($report.bugchecks.Count -eq 0) {
    Write-Host '  （没有 bugcheck 事件 —— 要么没崩，要么日志还没落盘）' -ForegroundColor Yellow
} else {
    foreach ($b in $report.bugchecks) {
        Write-Host ('  [{0}] id={1}' -f $b.time, $b.id) -ForegroundColor Green
        foreach ($line in (($b.text -split "`r?`n") | Select-Object -First 5)) {
            if ($line.Trim()) { Write-Host "     $($line.Trim())" }
        }
    }
}

# --- 4. 取转储 -------------------------------------------------------------
Write-Head '转储文件'
$report.dumps = @(Invoke-Command -Session $session -ScriptBlock {
    $r = @()
    foreach ($d in @('C:\Windows\Minidump', 'C:\Windows')) {
        if (Test-Path $d) {
            $r += Get-ChildItem -Path $d -Filter '*.dmp' -File -ErrorAction SilentlyContinue |
                  ForEach-Object {
                      [ordered]@{
                          path = $_.FullName
                          mb   = [math]::Round($_.Length / 1MB, 2)
                          utc  = $_.LastWriteTimeUtc.ToString('o')
                      }
                  }
        }
    }
    $r
})
if ($report.dumps.Count -eq 0) {
    Write-Host '  （guest 里没有 .dmp）' -ForegroundColor Yellow
} else {
    foreach ($d in $report.dumps) { Write-Host ('  {0}  {1} MB  {2}' -f $d.path, $d.mb, $d.utc) }
    # 用脚本块排序，不要 `Sort-Object utc`。
    #
    # 这些记录穿过 PowerShell Direct 回来是**哈希表**，而 Sort-Object 按
    # *属性名* 绑定 —— 哈希表不把键暴露成属性，于是每一项的键都是 $null，
    # 排序退化成稳定排序、原样返回第一个。实测因此取回了几小时前的旧转储，
    # 分析出来是上一次的 bugcheck 码，看着完全像"同一个 bug 又犯了"。
    # `{ $_.utc }` 走的是成员访问，哈希表上是可以的。
    $newest = $report.dumps | Sort-Object -Property { $_.utc } -Descending |
              Select-Object -First 1
    $local  = Join-Path $logDir ("bugcheck-$stamp-" + (Split-Path $newest.path -Leaf))
    Write-Host "  取回最新的一个：$($newest.path)" -ForegroundColor Green
    Copy-Item -FromSession $session -Path $newest.path -Destination $local -Force
    $report.copied = $local
    Write-Host ('  -> {0}  ({1:N2} MB)' -f $local, ((Get-Item $local).Length / 1MB))
}

Remove-PSSession $session

# --- 5. 直接分析 -----------------------------------------------------------
if ($report.copied -and -not $SkipAnalyze) {
    Write-Head 'kd !analyze -v'
    $kd = @(
        'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe',
        'C:\Program Files\Windows Kits\10\Debuggers\x64\kd.exe'
    ) | Where-Object { Test-Path $_ } | Select-Object -First 1

    if (-not $kd) {
        Write-Host '  找不到 kd.exe，跳过分析。转储已经在宿主上了。' -ForegroundColor Yellow
    } else {
        $sym = 'srv*C:\symbols*https://msdl.microsoft.com/download/symbols;' +
               (Join-Path $repo 'Ksword5.1\x64\Release\KswordARKDriver')
        $out = Join-Path $logDir "bugcheck-$stamp-analyze.txt"
        # 命令用分号串起来，最后 q 退出；-logo 把全部输出落盘
        & $kd -z $report.copied -y $sym -logo $out -c '!analyze -v; lm m Ksword*; kb; q' 2>&1 | Out-Null
        $report.analyzed = $out
        if (Test-Path $out) {
            Write-Host "  完整输出：$out" -ForegroundColor Cyan
            $lines = [IO.File]::ReadAllLines($out)
            foreach ($pat in @('Bugcheck code', 'BugCheck ', 'PROCESS_NAME', 'MODULE_NAME',
                               'IMAGE_NAME', 'FAILURE_BUCKET_ID', 'Probably caused by')) {
                $m = $lines | Select-String -SimpleMatch $pat | Select-Object -First 1
                if ($m) { Write-Host ('  {0}' -f $m.Line.Trim()) -ForegroundColor Green }
            }

            # 交叉核验：分析出来的码必须和事件日志里最新那条对得上。
            #
            # 这是防"分析了旧转储"的最后一道。一份陈旧的转储会给出一个
            # **完全自洽、完全错误**的故事 —— 上一次崩溃的码、栈、bucket
            # 一应俱全，看着就像同一个 bug 又犯了，而真正的这次根本没被看过。
            # 实测踩过一次（排序退化取回了几小时前的转储）。
            $analyzedCode = ($lines | Select-String -Pattern '^BUGCHECK_CODE:\s*([0-9a-fA-F]+)' |
                             Select-Object -First 1)
            $eventCode = $null
            foreach ($b in $report.bugchecks) {
                if ($b.text -match 'bugcheck was:\s*0x([0-9a-fA-F]+)') { $eventCode = $Matches[1]; break }
                if ($b.text -match 'BugcheckCode=\d+\s*\(0x([0-9a-fA-F]+)\)') { $eventCode = $Matches[1]; break }
            }
            if ($analyzedCode -and $eventCode) {
                $a = ([int]("0x" + $analyzedCode.Matches[0].Groups[1].Value))
                $e = ([int]("0x" + $eventCode))
                if ($a -ne $e) {
                    Write-Host ''
                    Write-Host ("  ** 分析的是错的转储 ** 事件日志最新一条是 0x{0:X}，" -f $e) -ForegroundColor Red
                    Write-Host ("     但这份转储里是 0x{0:X}。下面的栈和 bucket 属于**上一次**崩溃，" -f $a) -ForegroundColor Red
                    Write-Host '     不要拿它归因本次。手动挑对应时间的 .dmp 重跑。' -ForegroundColor Red
                    [void]($report.GetEnumerator())
                    $report.analyzed = "$out (MISMATCH: event=0x$('{0:X}' -f $e) dump=0x$('{0:X}' -f $a))"
                } else {
                    Write-Host ("  [OK]   与事件日志一致：0x{0:X}" -f $e) -ForegroundColor Green
                }
            }
        }
    }
}

$jsonPath = Join-Path $logDir "bugcheck-$stamp.json"
$report | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8
Write-Host ''
Write-Host "记录已写入 $jsonPath" -ForegroundColor Cyan
