<#
.SYNOPSIS
    Backend 3 PoC 测试器：发 IOCTL_KSWORD_ARK_KERNEL_NOATTACH_PROBE 到 \\.\KswordARK。

.DESCRIPTION
    两种模式：
    - QueryOnly（默认，non-destructive）：读 IDTR + IDT[vector] 的 16 字节 descriptor。
    - NoopWrite（destructive）：SEH 包装的 RtlCopyMemory no-op 写 IDT[vector]。
      HVCI on 时可能触发 BugCheck 0x139/0x109，必须在授权 VM 内运行。

.PARAMETER Mode
    QueryOnly | NoopWrite | AliasWrite | Trip。默认 QueryOnly。
    Trip：alias 写 IstAndType ^= 0x0100，改 Type 0xE→0xF，等 PG checksum 发现后 0x109。

.PARAMETER Vector
    IDT 向量号 0..255，默认 1 (#DB)。Trip 建议 0x2F。

.EXAMPLE
    .\Test-Backend3Probe.ps1 -Mode QueryOnly
    .\Test-Backend3Probe.ps1 -Mode NoopWrite -Vector 0x2F
    .\Test-Backend3Probe.ps1 -Mode Trip -Vector 0x2F
#>
[CmdletBinding()]
param(
    [ValidateSet('QueryOnly','NoopWrite','AliasWrite','Trip')][string]$Mode = 'QueryOnly',
    [ValidateRange(0,255)][int]$Vector = 1
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Add-Type -Namespace Win32 -Name KSwordB3 -MemberDefinition @'
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true, CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
    public static extern System.IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        System.IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, System.IntPtr hTemplateFile);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool DeviceIoControl(System.IntPtr hDevice, uint dwIoControlCode,
        System.IntPtr lpInBuffer, uint nInBufferSize, System.IntPtr lpOutBuffer, uint nOutBufferSize,
        ref uint lpBytesReturned, System.IntPtr lpOverlapped);
    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(System.IntPtr hObject);
'@

$GENERIC_WRITE  = [uint32]0x40000000
$OPEN_EXISTING  = [uint32]3
$INVALID_HANDLE = [IntPtr]::new(-1)
$IOCTL_PROBE    = [uint32]((0x22 -shl 16) -bor (0x2 -shl 14) -bor (0x940 -shl 2) -bor 0)

Write-Host ("Mode={0} Vector={1} IOCTL=0x{2:X8}" -f $Mode, $Vector, $IOCTL_PROBE)

$op = switch ($Mode) {
    'QueryOnly'  { [uint32]0 }
    'NoopWrite'  { [uint32]1 }
    'AliasWrite' { [uint32]3 }
    'Trip'       { [uint32]4 }
}
$confirm = if ($Mode -in 'NoopWrite','AliasWrite','Trip') { [uint32]1 } else { [uint32]0 }

$h = [Win32.KSwordB3]::CreateFileW('\\.\KswordARKLog', $GENERIC_WRITE, [uint32]3, [IntPtr]::Zero, $OPEN_EXISTING, [uint32]0, [IntPtr]::Zero)
if ($h -eq $INVALID_HANDLE) {
    $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
    throw "CreateFileW \\.\KswordARK failed: Win32=$le"
}
try {
    $req = New-Object byte[] 32
    [BitConverter]::GetBytes([uint32]1).CopyTo($req, 0)
    [BitConverter]::GetBytes($op).CopyTo($req, 4)
    [BitConverter]::GetBytes([uint32]$Vector).CopyTo($req, 8)
    [BitConverter]::GetBytes($confirm).CopyTo($req, 12)
    $inPtr  = [Runtime.InteropServices.Marshal]::AllocHGlobal(32)
    $outPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal(72)
    try {
        [Runtime.InteropServices.Marshal]::Copy($req, 0, $inPtr, 32)
        [Runtime.InteropServices.Marshal]::WriteByte($outPtr, 0, 0)
        $br = [uint32]0
        $t0 = [DateTime]::UtcNow
        $ok = [Win32.KSwordB3]::DeviceIoControl($h, [uint32]$IOCTL_PROBE, $inPtr, [uint32]32, $outPtr, [uint32]72, [ref]$br, [IntPtr]::Zero)
        $le = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        $dt = ([DateTime]::UtcNow - $t0).TotalMilliseconds
        $resp = New-Object byte[] 72
        [Runtime.InteropServices.Marshal]::Copy($outPtr, $resp, 0, 72)
        Write-Host ("DeviceIoControl ok={0} win32={1} bytesReturned={2} elapsedMs={3:F2}" -f $ok, $le, $br, $dt)
        $Version     = [BitConverter]::ToUInt32($resp, 0)
        $StatusFlags = [BitConverter]::ToUInt32($resp, 4)
        $SehCode     = [BitConverter]::ToUInt32($resp, 8)
        $IdtLimit    = [BitConverter]::ToUInt32($resp, 12)
        $IdtBase     = [BitConverter]::ToUInt64($resp, 16)
        $EntryLow    = [BitConverter]::ToUInt64($resp, 24)
        $EntryHigh   = [BitConverter]::ToUInt64($resp, 32)
        $ReadbackLow = [BitConverter]::ToUInt64($resp, 40)
        $ReadbackHigh= [BitConverter]::ToUInt64($resp, 48)
        $QueryTick   = [BitConverter]::ToUInt64($resp, 56)
        $AliasVa     = [BitConverter]::ToUInt64($resp, 64)
        $info = [pscustomobject]@{
            Mode          = $Mode
            Vector        = $Vector
            Ok            = $ok
            Win32         = $le
            BytesReturned = $br
            ElapsedMs     = [math]::Round($dt, 2)
            Version       = $Version
            StatusFlags   = ('0x{0:X8}' -f $StatusFlags)
            SehCode       = ('0x{0:X8}' -f $SehCode)
            IdtLimit      = ('0x{0:X}' -f $IdtLimit)
            IdtBase       = ('0x{0:X16}' -f $IdtBase)
            EntryLow      = ('0x{0:X16}' -f $EntryLow)
            EntryHigh     = ('0x{0:X16}' -f $EntryHigh)
            ReadbackLow   = ('0x{0:X16}' -f $ReadbackLow)
            ReadbackHigh  = ('0x{0:X16}' -f $ReadbackHigh)
            QueryTick     = $QueryTick
            AliasVa       = ('0x{0:X16}' -f $AliasVa)
            Completed     = (($StatusFlags -band 0x1) -ne 0)
            SehFired      = (($StatusFlags -band 0x2) -ne 0)
            ReadbackMatch = (($StatusFlags -band 0x4) -ne 0)
        }
        $info | Format-List
        $info
    } finally {
        [Runtime.InteropServices.Marshal]::FreeHGlobal($inPtr)
        [Runtime.InteropServices.Marshal]::FreeHGlobal($outPtr)
    }
} finally {
    [Win32.KSwordB3]::CloseHandle($h) | Out-Null
}
