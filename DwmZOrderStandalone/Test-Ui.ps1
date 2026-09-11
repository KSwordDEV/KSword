param([Parameter(Mandatory=$true)][string]$Executable, [Parameter(Mandatory=$true)][string]$ScreenshotPath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class DwmOrderUiTest {
  public delegate bool EnumProc(IntPtr h, IntPtr p);
  [StructLayout(LayoutKind.Sequential)] public struct Rect { public int Left,Top,Right,Bottom; }
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc callback, IntPtr p);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder text,int size);
  [DllImport("user32.dll",CharSet=CharSet.Unicode,EntryPoint="SendMessageW")] public static extern IntPtr ReadControlText(IntPtr h,uint message,IntPtr size,StringBuilder text);
  [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h,uint message,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h,uint message,IntPtr w,IntPtr l);
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out Rect r);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h,int show);
  [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint flags);
  public static IntPtr Find(uint pid) {
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,p)=>{uint owner; GetWindowThreadProcessId(h,out owner); var name=new StringBuilder(128); GetClassName(h,name,128);
      if(owner==pid && name.ToString()=="DwmOrderStandalone") {found=h; return false;} return true;},IntPtr.Zero);
    return found;
  }
}
'@
$exe=(Resolve-Path -LiteralPath $Executable).Path
$screenshot=[IO.Path]::GetFullPath($ScreenshotPath)
New-Item -ItemType Directory -Path (Split-Path -Parent $screenshot) -Force | Out-Null
$process=Start-Process -FilePath $exe -PassThru -WindowStyle Hidden
$window=[IntPtr]::Zero
try {
    $deadline=(Get-Date).AddSeconds(15)
    do {
        if ($process.HasExited) { throw "GUI exited early: $($process.ExitCode)" }
        $window=[DwmOrderUiTest]::Find([uint32]$process.Id)
        if ($window -ne [IntPtr]::Zero -and [DwmOrderUiTest]::IsWindowEnabled([DwmOrderUiTest]::GetDlgItem($window,100))) {
            $ready=New-Object Text.StringBuilder 16384
            [DwmOrderUiTest]::ReadControlText([DwmOrderUiTest]::GetDlgItem($window,112),0xD,[IntPtr]16384,$ready) | Out-Null
            if ($ready.ToString().Contains('inspection_complete=')) { break }
        }
        Start-Sleep -Milliseconds 100
    } while ((Get-Date) -lt $deadline)
    if ($window -eq [IntPtr]::Zero -or ![DwmOrderUiTest]::IsWindowEnabled([DwmOrderUiTest]::GetDlgItem($window,100))) { throw 'GUI/diagnostic did not become ready.' }
    [DwmOrderUiTest]::SendMessage($window,0x111,[IntPtr]102,[IntPtr]::Zero) | Out-Null # Test A+B only; no injection.
    $demoDetail=New-Object Text.StringBuilder 4096
    [DwmOrderUiTest]::ReadControlText([DwmOrderUiTest]::GetDlgItem($window,112),0xD,[IntPtr]4096,$demoDetail) | Out-Null
    foreach ($id in @(104,105)) {
        $box=[DwmOrderUiTest]::GetDlgItem($window,$id)
        if ([DwmOrderUiTest]::SendMessage($box,0x146,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -lt 2) { throw 'Test windows missing from selectors.' }
        if ([DwmOrderUiTest]::SendMessage($box,0x147,[IntPtr]::Zero,[IntPtr]::Zero).ToInt64() -lt 0) { throw "Test window was not selected: $demoDetail" }
        $selected=New-Object Text.StringBuilder 512
        [DwmOrderUiTest]::ReadControlText($box,0xD,[IntPtr]512,$selected) | Out-Null
        $expected=if ($id -eq 104) { 'DWM Test A' } else { 'DWM Test B' }
        if (!$selected.ToString().Contains($expected)) {
            $detail=New-Object Text.StringBuilder 4096
            [DwmOrderUiTest]::ReadControlText([DwmOrderUiTest]::GetDlgItem($window,112),0xD,[IntPtr]4096,$detail) | Out-Null
            throw "Wrong selected test window: $selected; $detail"
        }
    }
    $position=[DwmOrderUiTest]::GetDlgItem($window,106)
    [DwmOrderUiTest]::SendMessage($position,0x14e,[IntPtr]2,[IntPtr]::Zero) | Out-Null
    [DwmOrderUiTest]::SendMessage($window,0x111,[IntPtr](106 -bor (1 -shl 16)),$position) | Out-Null
    if (![DwmOrderUiTest]::IsWindowEnabled([DwmOrderUiTest]::GetDlgItem($window,105))) { throw 'Relative order must enable the reference selector.' }
    [DwmOrderUiTest]::SendMessage($position,0x14e,[IntPtr]0,[IntPtr]::Zero) | Out-Null
    [DwmOrderUiTest]::SendMessage($window,0x111,[IntPtr](106 -bor (1 -shl 16)),$position) | Out-Null
    if ([DwmOrderUiTest]::IsWindowEnabled([DwmOrderUiTest]::GetDlgItem($window,105))) { throw 'Absolute order must disable the reference selector.' }
    if (![DwmOrderUiTest]::IsWindowEnabled([DwmOrderUiTest]::GetDlgItem($window,116))) { throw 'Report export must be available after inspection.' }
    [DwmOrderUiTest]::ShowWindow($window,4) | Out-Null
    $rect=New-Object DwmOrderUiTest+Rect
    [DwmOrderUiTest]::GetWindowRect($window,[ref]$rect) | Out-Null
    $bitmap=New-Object Drawing.Bitmap ($rect.Right-$rect.Left),($rect.Bottom-$rect.Top)
    $graphics=[Drawing.Graphics]::FromImage($bitmap)
    $dc=$graphics.GetHdc()
    try { if (![DwmOrderUiTest]::PrintWindow($window,$dc,2)) { throw 'Window capture failed.' } }
    finally { $graphics.ReleaseHdc($dc) }
    try { $bitmap.Save($screenshot,[Drawing.Imaging.ImageFormat]::Png) }
    finally { $graphics.Dispose(); $bitmap.Dispose() }
    Write-Output 'UI_SMOKE=PASS (inspection, selectors, test windows, report availability; no DWM injection)'
    Write-Output "SCREENSHOT=$screenshot"
} finally {
    if ($window -ne [IntPtr]::Zero) { [DwmOrderUiTest]::PostMessage($window,0x10,[IntPtr]::Zero,[IntPtr]::Zero) | Out-Null }
    if (!$process.WaitForExit(10000)) { throw "UI test process did not close: PID $($process.Id)" }
    if ($process.ExitCode -ne 0) { throw "UI process failed: $($process.ExitCode)" }
}
