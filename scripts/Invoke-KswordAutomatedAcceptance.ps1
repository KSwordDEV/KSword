<#
.SYNOPSIS
    KSword 一条命令跑完的自动化验收：离线断言套件 + 嵌套虚拟机里的真实驱动验证，
    产出一份机器可读 JSON 和一份可直接贴进验收记录的 Markdown。

.DESCRIPTION
    分三段，每段都能单独失败而不拖垮后面能跑的部分：

      1. 离线（不需要虚拟机、不需要驱动）
         构建并运行 KswordARKLightTests。它调用的是 shared/evidence 与
         shared/driver 里的**生产代码本身**，不是复制一份逻辑到测试里。
         逐套件解析 "N/N checks passed"，任何一条不等就是 FAIL。

      2. 工具
         编译 hvm_probe.exe / hvm_ctl.exe（/MT 静态链接，guest 里不需要 CRT）。

      3. 在机（需要 Hyper-V 测试机 + 已加载的驱动）
         调用 Invoke-KswordHvmControl.ps1 推进 HVM 生命周期并收集它的 JSON。

    **判定语义是刻意分开的**，不要合并：

      PASS     实跑通过，有执行证据
      FAIL     代码/逻辑失败
      BLOCKED  缺硬件能力、缺权限、缺签名环境、缺真实样本 —— 不是代码的问题，
               但也**不能**记成通过
      NOT_RUN  没跑

    脚本**不会**改宿主机的安全配置、不重启、不启用 Verifier、不安装驱动到宿主、
    不上传任何数据。它对虚拟机做的唯一有副作用的事是打检查点和在 guest 内发
    IOCTL，两者都在那台一次性隔离测试机内部。

.PARAMETER OfflineOnly
    只跑第 1、2 段。没有虚拟机时用这个，在机部分记 NOT_RUN 而不是 FAIL。

.PARAMETER Stage
    透传给 Invoke-KswordHvmControl.ps1 的级别。默认 safe（到 self-test 为止，
    不常驻）。要跑常驻/浸泡就显式给 resident / soak / full。

.EXAMPLE
    .\Invoke-KswordAutomatedAcceptance.ps1
    .\Invoke-KswordAutomatedAcceptance.ps1 -OfflineOnly
    .\Invoke-KswordAutomatedAcceptance.ps1 -Stage soak -SoakMs 5000
#>
[CmdletBinding()]
param(
    [switch] $OfflineOnly,
    # 这一组必须与 Invoke-KswordHvmControl.ps1 的 ValidateSet 保持一致 ——
    # 两处枚举是同一个契约的两份表述，改一处忘一处的结果是顶层直接拒参数，
    # 而错误信息指向的是"取值不在集合里"，看不出是哪一侧漏了。实测踩过一次。
    [ValidateSet('safe', 'status', 'prepare', 'self-test', 'launch-guest',
                 'resident', 'probe-platform', 'probe-flags', 'probe-xonly',
                 'view-probe', 'view-effect',
                 'soak', 'full')]
    [string] $Stage   = 'safe',
    [string] $VMName  = 'KSword-HVM-Target',
    [int]    $SoakMs  = 2000,
    [switch] $SkipBuild
)

$ErrorActionPreference = 'Stop'
$repo   = Split-Path $PSScriptRoot -Parent
$stamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
$logDir = Join-Path $repo 'docs\next\logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

$manifestPath = Join-Path $PSScriptRoot 'ksword-expected-suites.json'

$report = [ordered]@{
    schema     = 'ksword.acceptance.autotest/1'
    startedUtc = (Get-Date).ToUniversalTime().ToString('o')
    machine    = [ordered]@{
        computer = $env:COMPUTERNAME
        os       = (Get-CimInstance Win32_OperatingSystem).Caption
        build    = (Get-CimInstance Win32_OperatingSystem).BuildNumber
        cpu      = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
    }
    phases     = [ordered]@{}
}

function Resolve-MSBuild {
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) { throw '找不到 vswhere.exe，无法定位 MSBuild' }
    $p = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
         Select-Object -First 1
    if (-not $p) { throw '找不到 MSBuild.exe' }
    return $p
}

# ---------------------------------------------------------------------------
# 第 1 段：离线断言套件
# ---------------------------------------------------------------------------
Write-Host "=== 1. 离线断言套件（调用生产代码本身）===" -ForegroundColor Cyan
$offline = [ordered]@{ verdict = 'NOT_RUN' }
try {
    $proj = Join-Path $repo 'KswordARKLightTests\KswordARKLightTests.vcxproj'
    $exe  = Join-Path $repo 'KswordARKLightTests\x64\Release\KswordARKLightTests.exe'

    if (-not $SkipBuild) {
        $msb = Resolve-MSBuild
        $buildLog = Join-Path $logDir "autotest-build-$stamp.txt"
        & $msb $proj /t:Build /p:Configuration=Release /p:Platform=x64 /v:minimal /nologo `
            2>&1 | Tee-Object -FilePath $buildLog | Out-Null
        $offline.buildExit = $LASTEXITCODE
        $offline.buildLog  = $buildLog
        if ($LASTEXITCODE -ne 0) { throw "构建失败，退出码 $LASTEXITCODE（见 $buildLog）" }
        Write-Host "  [OK]   构建通过" -ForegroundColor Green
    } else {
        $offline.buildExit = 'skipped'
        Write-Host "  [跳过] 按 -SkipBuild 复用已有产物" -ForegroundColor DarkGray
    }

    if (-not (Test-Path $exe)) { throw "没有测试产物 $exe" }

    $runLog = Join-Path $logDir "autotest-run-$stamp.txt"
    $raw = & $exe 2>&1 | Out-String
    $offline.runExit = $LASTEXITCODE
    $raw | Set-Content -Path $runLog -Encoding UTF8
    $offline.runLog = $runLog

    # 逐套件解析 "<名字>: <通过>/<总数> checks passed"。
    # 只看退出码是不够的：一个套件整个没被链接进来时退出码同样是 0，
    # 那正是这次要堵的洞（HvmEptSwitchTests 曾经就从来没被编译过）。
    $suites = @()
    foreach ($line in ($raw -split "`r?`n")) {
        if ($line -match '^\s*(.+?):\s*(\d+)/(\d+)\s+checks passed\s*$') {
            $suites += [pscustomobject]@{
                suite  = $Matches[1].Trim()
                passed = [int]$Matches[2]
                total  = [int]$Matches[3]
            }
        }
    }
    $offline.suites      = $suites
    $offline.suiteCount  = $suites.Count
    $offline.assertions  = ($suites | Measure-Object -Property total  -Sum).Sum
    $offline.passed      = ($suites | Measure-Object -Property passed -Sum).Sum
    $incomplete = @($suites | Where-Object { $_.passed -ne $_.total })

    # 对清单核验。只看「有没有 FAIL 行」抓不到**整个套件没被链接进来**：
    # 那种情况下测试进程照样退出 0、照样打印「全部通过」，而那些断言一条都没跑。
    # HvmEptSwitchTests 就这样静默缺席过一整轮。
    $missing  = @()
    $shrunk   = @()
    $unlisted = @()
    if (Test-Path $manifestPath) {
        $manifest = Get-Content $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $offline.manifest = $manifestPath
        foreach ($want in $manifest.suites) {
            $got = $suites | Where-Object { $_.suite -eq $want.name } | Select-Object -First 1
            if (-not $got) {
                $missing += $want.name
            } elseif ($got.total -lt $want.minAssertions) {
                $shrunk += [pscustomobject]@{ suite = $want.name; now = $got.total; expected = $want.minAssertions }
            }
        }
        $known = @($manifest.suites | ForEach-Object { $_.name })
        $unlisted = @($suites | Where-Object { $known -notcontains $_.suite } | ForEach-Object { $_.suite })
    } else {
        $offline.manifest = "缺失：$manifestPath（无法核验套件是否齐全）"
    }
    $offline.missingSuites = $missing
    $offline.shrunkSuites  = $shrunk
    $offline.unlistedSuites = $unlisted

    if ($offline.runExit -eq 0 -and $suites.Count -gt 0 -and $incomplete.Count -eq 0 -and
        $missing.Count -eq 0 -and $shrunk.Count -eq 0) {
        $offline.verdict = 'PASS'
        Write-Host ("  [PASS] {0} 个套件，{1} 条断言全过" -f $suites.Count, $offline.assertions) -ForegroundColor Green
    } else {
        $offline.verdict = 'FAIL'
        $offline.failingSuites = $incomplete
        Write-Host ("  [FAIL] 退出码 {0}；未全过的套件 {1} 个" -f $offline.runExit, $incomplete.Count) -ForegroundColor Red
        foreach ($s in $incomplete) { Write-Host ("         {0}: {1}/{2}" -f $s.suite, $s.passed, $s.total) -ForegroundColor Red }
        foreach ($m in $missing)    { Write-Host ("         套件缺席（从未被链接进来？）: {0}" -f $m) -ForegroundColor Red }
        foreach ($s in $shrunk)     { Write-Host ("         断言变少: {0} 现在 {1} 条，登记时 {2} 条" -f $s.suite, $s.now, $s.expected) -ForegroundColor Red }
    }
    foreach ($u in $unlisted) {
        # 新增套件是好事，但清单没更新就意味着它下次消失不会有人发现。
        Write-Host ("         [提醒] 清单里没有的新套件: {0} —— 记得更新 ksword-expected-suites.json" -f $u) -ForegroundColor Yellow
    }
    foreach ($s in $suites) { Write-Host ("         {0,-24} {1,5}/{2}" -f $s.suite, $s.passed, $s.total) -ForegroundColor DarkGray }
}
catch {
    $offline.verdict = 'FAIL'
    $offline.error = "$($_.Exception.Message)"
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
}
$report.phases.offline = $offline

# ---------------------------------------------------------------------------
# 第 2 段：guest 工具
# ---------------------------------------------------------------------------
Write-Host "`n=== 2. guest 工具编译 ===" -ForegroundColor Cyan
$tools = [ordered]@{ verdict = 'NOT_RUN' }
try {
    & (Join-Path $PSScriptRoot 'Build-KswordHvmTools.ps1') | Out-Host
    $tools.verdict = 'PASS'
    $tools.artifacts = @(
        (Join-Path $repo 'tools\hvm_probe\hvm_probe.exe'),
        (Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe')
    ) | Where-Object { Test-Path $_ } | ForEach-Object {
        [pscustomobject]@{ path = $_; bytes = (Get-Item $_).Length }
    }
}
catch {
    $tools.verdict = 'FAIL'
    $tools.error = "$($_.Exception.Message)"
    Write-Host "  [FAIL] $($_.Exception.Message)" -ForegroundColor Red
}
$report.phases.tools = $tools

# ---------------------------------------------------------------------------
# 第 3 段：在机（嵌套虚拟机 + 真实驱动）
# ---------------------------------------------------------------------------
Write-Host "`n=== 3. 在机验证（嵌套 Hyper-V 测试机）===" -ForegroundColor Cyan
$onMachine = [ordered]@{ verdict = 'NOT_RUN' }
if ($OfflineOnly) {
    $onMachine.reason = '按 -OfflineOnly 跳过。在机项记 NOT_RUN，不记 PASS 也不记 FAIL。'
    Write-Host "  [NOT_RUN] $($onMachine.reason)" -ForegroundColor DarkGray
} elseif ($tools.verdict -ne 'PASS') {
    $onMachine.reason = 'hvm_ctl.exe 没编译出来，在机部分无法运行。'
    Write-Host "  [NOT_RUN] $($onMachine.reason)" -ForegroundColor DarkGray
} else {
    try {
        $vm = Get-VM -Name $VMName -ErrorAction Stop
        if ($vm.State -ne 'Running') {
            $onMachine.verdict = 'BLOCKED'
            $onMachine.reason = "虚拟机 $VMName 处于 $($vm.State)，没有启动。"
            Write-Host "  [BLOCKED] $($onMachine.reason)" -ForegroundColor Yellow
        } else {
            $hvmJson = Join-Path $logDir "hvm-autotest-$stamp.json"
            & (Join-Path $PSScriptRoot 'Invoke-KswordHvmControl.ps1') `
                -Stage $Stage -VMName $VMName -SoakMs $SoakMs -ResultPath $hvmJson | Out-Host
            $hvmExit = $LASTEXITCODE
            $onMachine.controlExit = $hvmExit
            $onMachine.resultPath  = $hvmJson
            if (Test-Path $hvmJson) {
                $detail = Get-Content $hvmJson -Raw -Encoding UTF8 | ConvertFrom-Json
                $onMachine.detail  = $detail
                $onMachine.verdict = switch ($detail.verdict) {
                    'OK'      { 'PASS' }
                    'BLOCKED' { 'BLOCKED' }
                    'NOT_RUN' { 'NOT_RUN' }
                    default   { 'FAIL' }
                }
            } else {
                $onMachine.verdict = 'FAIL'
                $onMachine.reason = 'HVM 控制脚本没有产出 JSON 记录。'
            }
        }
    }
    catch {
        # 虚拟机不存在与虚拟机里出错是两回事：前者是环境缺失（BLOCKED），
        # 后者才是失败。这里只有 Get-VM 抛异常会走到，属前者。
        $onMachine.verdict = 'BLOCKED'
        $onMachine.reason = "$($_.Exception.Message)"
        Write-Host "  [BLOCKED] $($onMachine.reason)" -ForegroundColor Yellow
    }
}
$report.phases.onMachine = $onMachine

# ---------------------------------------------------------------------------
# 汇总
# ---------------------------------------------------------------------------
$report.finishedUtc = (Get-Date).ToUniversalTime().ToString('o')
$verdicts = @($offline.verdict, $tools.verdict, $onMachine.verdict)
$report.verdict =
    if ($verdicts -contains 'FAIL')       { 'FAIL' }
    elseif ($verdicts -contains 'BLOCKED') { 'BLOCKED' }
    elseif ($verdicts -contains 'NOT_RUN') { 'PARTIAL' }
    else                                   { 'PASS' }

$jsonPath = Join-Path $logDir "acceptance-autotest-$stamp.json"
# JSON 必须无 BOM，见文件末尾说明。
[IO.File]::WriteAllText(
    $jsonPath,
    ($report | ConvertTo-Json -Depth 14),
    (New-Object Text.UTF8Encoding($false)))

$mdPath = Join-Path $logDir "acceptance-autotest-$stamp.md"
$md = New-Object System.Text.StringBuilder
[void]$md.AppendLine("# KSword 自动化验收记录")
[void]$md.AppendLine()
[void]$md.AppendLine("时间(UTC): $($report.startedUtc) → $($report.finishedUtc)")
[void]$md.AppendLine("机器: $($report.machine.os) build $($report.machine.build)")
[void]$md.AppendLine("CPU: $($report.machine.cpu)")
[void]$md.AppendLine()
[void]$md.AppendLine("**总判定: $($report.verdict)**")
[void]$md.AppendLine()
[void]$md.AppendLine("| 段 | 判定 | 说明 |")
[void]$md.AppendLine("|---|---|---|")
[void]$md.AppendLine("| 离线断言套件 | $($offline.verdict) | $($offline.suiteCount) 个套件 / $($offline.assertions) 条断言 |")
[void]$md.AppendLine("| guest 工具 | $($tools.verdict) | hvm_probe + hvm_ctl，/MT 静态链接 |")
[void]$md.AppendLine("| 在机验证 | $($onMachine.verdict) | $(if ($onMachine.reason) { $onMachine.reason } else { "级别 $Stage" }) |")
[void]$md.AppendLine()
if ($offline.suites) {
    [void]$md.AppendLine("## 离线套件明细")
    [void]$md.AppendLine()
    [void]$md.AppendLine("| 套件 | 通过 | 总数 |")
    [void]$md.AppendLine("|---|---:|---:|")
    foreach ($s in $offline.suites) { [void]$md.AppendLine("| $($s.suite) | $($s.passed) | $($s.total) |") }
    [void]$md.AppendLine()
}
if ($onMachine.detail) {
    [void]$md.AppendLine("## 在机步骤")
    [void]$md.AppendLine()
    [void]$md.AppendLine("| 步骤 | 结果 | 说明 |")
    [void]$md.AppendLine("|---|---|---|")
    foreach ($s in $onMachine.detail.steps) { [void]$md.AppendLine("| $($s.name) | $($s.outcome) | $($s.note) |") }
    [void]$md.AppendLine()
    if ($onMachine.detail.notes) {
        [void]$md.AppendLine("### 备注")
        [void]$md.AppendLine()
        foreach ($n in $onMachine.detail.notes) { [void]$md.AppendLine("- $n") }
        [void]$md.AppendLine()
    }
}
[void]$md.AppendLine("---")
[void]$md.AppendLine()
[void]$md.AppendLine("BLOCKED 表示缺能力/权限/样本，**不等于通过**；NOT_RUN 表示这一段本次没跑。")
[void]$md.AppendLine("原始 JSON: ``$(Split-Path $jsonPath -Leaf)``")
$md.ToString() | Set-Content -Path $mdPath -Encoding UTF8

Write-Host "`n================ 总判定: $($report.verdict) ================" -ForegroundColor $(
    switch ($report.verdict) { 'PASS' { 'Green' } 'BLOCKED' { 'Yellow' } 'PARTIAL' { 'Yellow' } default { 'Red' } })
Write-Host "  JSON     : $jsonPath"
Write-Host "  Markdown : $mdPath"

exit $(if ($report.verdict -eq 'FAIL') { 1 } else { 0 })
