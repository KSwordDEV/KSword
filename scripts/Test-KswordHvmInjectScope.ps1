# R-1 注入打**共享镜像页**的验证。
#
# 这是 CR3 作用域检查唯一真正吃劲的场景。前几轮的靶页都是进程私有的：probe 页是
# VirtualAlloc 出来的，hvm_target 的 .text 只有它自己映射。而系统 DLL（ntdll、
# kernel32）的代码页被**每一个进程**映射到同一张客户物理页上——视图装在物理页上、
# 全机器可见，不比 CR3 的话，任何执行到那一页的进程都会被拖去跑载荷。
#
# 判据三条：
#   A 目标进程的标记变了 —— 载荷在它身上跑了。
#   B **对照进程**的标记没变 —— 作用域生效了。这一条才是这轮的重点：同时跑两个
#     一模一样的靶子，只对其中一个下注入，另一个必须毫发无伤。
#   C 两个进程的心跳都继续推进 —— 谁都没被打坏。
param([string] $VMName = 'KSword-HVM-Target')
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$cred = New-Object System.Management.Automation.PSCredential(
    'felix', (ConvertTo-SecureString 'password' -AsPlainText -Force))
$repo = 'C:\Users\Felix\CLionProjects\KSword'

function Guest([scriptblock] $s, $a) {
    if ($null -eq $a) { Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $s }
    else { Invoke-Command -VMName $VMName -Credential $cred -ScriptBlock $s -ArgumentList $a }
}
function Ctl([string[]] $a) {
    Guest { param($x)
        $o = & 'C:\ksword\hvm_ctl.exe' @x 2>&1 | Out-String
        [pscustomobject]@{ exit = $LASTEXITCODE; text = $o }
    } (,$a)
}
function Push-Tool([string] $src, [string] $dst) {
    $b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($src))
    Guest { param($d,$t)
        New-Item -ItemType Directory -Force -Path (Split-Path $t) | Out-Null
        [IO.File]::WriteAllBytes($t, [Convert]::FromBase64String($d))
    } @($b64,$dst)
}

Write-Output "=== 0. 投送 ==="
Guest { Get-Process -Name 'hvm_target' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
Push-Tool (Join-Path $repo 'tools\hvm_ctl\hvm_ctl.exe') 'C:\ksword\hvm_ctl.exe'
Push-Tool (Join-Path $repo 'tools\hvm_target\hvm_target.exe') 'C:\ksword\hvm_target.exe'

Write-Output "`n=== 1. 干净起点 ==="
foreach ($v in @('inject-release-all','proc-release-all','stop','teardown','reset-fault')) {
    $null = Ctl @($v)
}
Write-Output "  已复位"

Write-Output "`n=== 2. 启动两个一模一样的靶子 ==="
$pair = Guest {
    $r = @()
    foreach ($tag in @('A','B')) {
        $log = "C:\ksword\target-shared-$tag.log"
        if (Test-Path $log) { Remove-Item $log -Force }
        $p = Start-Process -FilePath 'C:\ksword\hvm_target.exe' `
            -RedirectStandardOutput $log -PassThru -WindowStyle Hidden
        $r += [pscustomobject]@{ tag = $tag; pid = $p.Id; log = $log }
    }
    Start-Sleep -Seconds 2
    foreach ($e in $r) {
        $x = Get-Content $e.log
        $e | Add-Member -NotePropertyName loop -NotePropertyValue `
            ((($x | Where-Object { $_ -like 'loop *' } | Select-Object -First 1) -replace '^loop 0x',''))
        $e | Add-Member -NotePropertyName marker -NotePropertyValue `
            ((($x | Where-Object { $_ -like 'marker *' } | Select-Object -First 1) -replace '^marker 0x',''))
    }
    $r
}
foreach ($e in $pair) {
    Write-Output "  靶子 $($e.tag): pid=$($e.pid) loop=0x$($e.loop) marker=0x$($e.marker)"
}
$targetA = $pair | Where-Object { $_.tag -eq 'A' }
$targetB = $pair | Where-Object { $_.tag -eq 'B' }
# 同一个 exe 的 .text 在两个实例里是**同一张客户物理页**（镜像节共享）。
# 两边的 loop 线性地址若相同，那是 ASLR 每次启动只重定一次的结果，正合我们要的。
Write-Output "  两者 loop 线性地址相同: $($targetA.loop -eq $targetB.loop)"

Write-Output "`n=== 3. 前提 ==="
$null = Ctl @('cr-track-cr3-on')
$r = Ctl @('prepare-eptpsw'); Write-Output "  prepare-eptpsw exit=$($r.exit)"
if ($r.exit -ne 0) { Write-Output $r.text; exit 1 }

Write-Output "`n=== 4. 只对靶子 A 下注入 ==="
$r = Ctl @('inject-test', "$($targetA.pid)", $targetA.loop, $targetA.marker)
Write-Output "  inject-test(A) exit=$($r.exit)`n$($r.text)"
if ($r.exit -ne 0) { Write-Output "装不上，中止"; exit 1 }

Write-Output "`n=== 5. 起常驻，观察 15 秒 ==="
$null = Ctl @('self-test')
$r = Ctl @('resident'); Write-Output "  resident exit=$($r.exit)"
if ($r.exit -ne 0) { Write-Output $r.text; exit 1 }
Start-Sleep -Seconds 15

$obs = Guest { param($pa, $la, $pb, $lb)
    function Snap($p, $l) {
        $lines = @(Get-Content $l -ErrorAction SilentlyContinue)
        $ticks = @($lines | Where-Object { $_ -like 'tick *' })
        [pscustomobject]@{
            alive  = [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
            last   = ($ticks | Select-Object -Last 1)
            marked = @($ticks | Where-Object { $_ -notlike '*marker 00000000*' }).Count
        }
    }
    [pscustomobject]@{ a = (Snap $pa $la); b = (Snap $pb $lb) }
} @($targetA.pid, $targetA.log, $targetB.pid, $targetB.log)

Write-Output "  A(目标)  活着=$($obs.a.alive) 心跳=$($obs.a.last) 标记非零行数=$($obs.a.marked)"
Write-Output "  B(对照)  活着=$($obs.b.alive) 心跳=$($obs.b.last) 标记非零行数=$($obs.b.marked)"
$r = Ctl @('--json','inject-query'); Write-Output "  inject-query: $($r.text)"

Write-Output "`n=== 6. 再等 6 秒确认两边都没被打坏 ==="
Start-Sleep -Seconds 6
$obs2 = Guest { param($pa, $la, $pb, $lb)
    function Snap($p, $l) {
        $lines = @(Get-Content $l -ErrorAction SilentlyContinue)
        $ticks = @($lines | Where-Object { $_ -like 'tick *' })
        [pscustomobject]@{
            alive = [bool](Get-Process -Id $p -ErrorAction SilentlyContinue)
            last  = ($ticks | Select-Object -Last 1)
        }
    }
    [pscustomobject]@{ a = (Snap $pa $la); b = (Snap $pb $lb) }
} @($targetA.pid, $targetA.log, $targetB.pid, $targetB.log)
Write-Output "  A 活着=$($obs2.a.alive) 心跳=$($obs2.a.last)"
Write-Output "  B 活着=$($obs2.b.alive) 心跳=$($obs2.b.last)"

function TickNo($s) { if ($s -match '^tick (\d+)') { [int]$matches[1] } else { -1 } }
$aAdv = (TickNo $obs2.a.last) -gt (TickNo $obs.a.last)
$bAdv = (TickNo $obs2.b.last) -gt (TickNo $obs.b.last)
Write-Output "`n>>> A 载荷执行   : $(if ($obs.a.marked -gt 0) { 'PASS' } else { 'FAIL（目标标记始终为 0）' })"
Write-Output ">>> B 未被波及   : $(if ($obs.b.marked -eq 0) { 'PASS（对照标记始终为 0）' } else { "FAIL（对照也被跑了载荷，$($obs.b.marked) 行非零）" })"
Write-Output ">>> C 两边都完好 : $(if ($obs2.a.alive -and $obs2.b.alive -and $aAdv -and $bAdv) { 'PASS' } else { "FAIL（A活=$($obs2.a.alive) A推进=$aAdv B活=$($obs2.b.alive) B推进=$bAdv）" })"

Write-Output "`n=== 7. 收尾 ==="
$null = Ctl @('stop'); $null = Ctl @('inject-release-all'); $null = Ctl @('teardown')
Guest { Get-Process -Name 'hvm_target' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue }
Write-Output "  完成"
