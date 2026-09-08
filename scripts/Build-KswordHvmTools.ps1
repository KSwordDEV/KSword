<#
.SYNOPSIS
    编译测试机上要用的两个无依赖小工具：hvm_probe.exe 与 hvm_ctl.exe。

.DESCRIPTION
    两个都用 /MT 静态链接 CRT。这一条不是风格问题：全新安装的 Windows 没有
    VC++ 可再发行组件，动态链接的 exe 在 guest 里根本起不来，表现是退出码
    0xC0000135 (STATUS_DLL_NOT_FOUND)、stdout/stderr 全空 —— 看上去像"命令没有
    输出"，其实是进程没跑起来。静态链接省掉整套 DLL 投送。

    /W4 /WX：这两个工具直接对内核发 IOCTL，警告在这里没有"以后再说"的余地。

.EXAMPLE
    .\Build-KswordHvmTools.ps1
#>
[CmdletBinding()]
param(
    [string] $VcVars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent

if (-not (Test-Path $VcVars)) {
    # 换个装法就换个路径，用 vswhere 定位而不是猜。
    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $root = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($root) { $VcVars = Join-Path $root 'VC\Auxiliary\Build\vcvars64.bat' }
    }
}
if (-not (Test-Path $VcVars)) { throw "找不到 vcvars64.bat（试过 $VcVars）" }

$targets = @(
    [pscustomobject]@{ Name = 'hvm_probe';    Dir = (Join-Path $repo 'tools\hvm_probe')    ; Libs = '' },
    [pscustomobject]@{ Name = 'hvm_ctl';      Dir = (Join-Path $repo 'tools\hvm_ctl')      ; Libs = '' },
    # hvm_target 是 R-1 进程处置的靶子：自报主循环地址 + 打心跳，让"冻结生效"、
    # "结束生效"与"页选错了什么都没发生"这三种结局在外面可区分。它不碰驱动，
    # 只是个被处置的普通进程。
    [pscustomobject]@{ Name = 'hvm_target';   Dir = (Join-Path $repo 'tools\hvm_target')   ; Libs = '' },
    # attest_probe 跑在**宿主**上，不投进 guest —— 它读的是安全内核签名的运行时
    # 驱动报告，那是 VBS 开着的机器才有的东西，而靶机恰恰要求 VBS 关闭。
    # 一起用 /MT 只是为了和其余两个保持一致，换机器拷过去就能跑。
    # wintrust.lib：算 Authenticode PE image hash（CryptCATAdminCalcHashFromFileHandle2）。
    # 报告里的 ImageHash 就是这个哈希，**不是**文件 flat hash —— 已对 afd.sys 逐字节标定过。
    [pscustomobject]@{ Name = 'attest_probe'; Dir = (Join-Path $repo 'tools\attest_probe') ; Libs = 'psapi.lib wintrust.lib' },
    # hvm_probe_dll 是 R-1 **DLL** 注入的证据：被加载时写一个带 PID 的文件。
    # 只有它是 DLL，所以走 /LD 而不是产出 exe。
    [pscustomobject]@{ Name = 'hvm_probe_dll'; Dir = (Join-Path $repo 'tools\hvm_probe_dll'); Libs = ''; Dll = $true }
)

$failed = 0
foreach ($t in $targets) {
    $src = Join-Path $t.Dir ($t.Name + '.c')
    if (-not (Test-Path $src)) { Write-Host "  [跳过] 没有 $src" -ForegroundColor Yellow; continue }
    # DLL 目标产出 .dll，其余产出 .exe；/LD 同时换掉入口点与链接方式。
    $isDll = [bool]$t.Dll
    $ext = if ($isDll) { '.dll' } else { '.exe' }
    $exe = Join-Path $t.Dir ($t.Name + $ext)
    $obj = Join-Path $t.Dir ($t.Name + '.obj')
    $ldFlag = if ($isDll) { '/LD' } else { '' }

    $cmd = "`"$VcVars`" >nul 2>&1 && cd /d `"$($t.Dir)`" && cl /nologo /W4 /WX /O2 /MT $ldFlag $($t.Name).c /Fe:$($t.Name)$ext /Fo:$($t.Name).obj $($t.Libs)"
    $out = cmd /c $cmd 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $exe)) {
        Write-Host "  [FAIL] $($t.Name)" -ForegroundColor Red
        Write-Host $out
        $failed++
        continue
    }
    Remove-Item $obj -ErrorAction SilentlyContinue
    $size = (Get-Item $exe).Length
    Write-Host ("  [OK]   {0,-10} {1,8:N0} 字节  {2}" -f $t.Name, $size, $exe) -ForegroundColor Green
}

if ($failed -gt 0) { throw "$failed 个工具没编译成功" }
Write-Host "`n两个工具都是 /MT 静态链接，投进 guest 不需要额外的 VC++ 运行库。" -ForegroundColor Cyan
