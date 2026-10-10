$help=Invoke-Cli @('help','process','hotkeys','enum')
Assert ($help.Contains('--source') -and (Invoke-Cli @('process','hotkeys','enum','--help')) -eq $help) 'Process hotkeys leaf help'
Assert (!(Invoke-Cli @('process','hotkeys','help')).Contains('--source')) 'Hotkeys hierarchy'
foreach($bad in @(
    @('process','hotkeys','enum','--json'),
    @('process','hotkeys','enum','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','hotkeys','enum','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','hotkeys','enum','--pid',$PID.ToString(),'--source','registered','--json'),
    @('process','hotkeys','enum','--pid',$PID.ToString(),'--limit','0','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Hotkey parameter rejection'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$self=(Invoke-Cli @('process','hotkeys','enum','--pid',$PID.ToString(),'--creation-time',$creation,'--json') @(0,6))|ConvertFrom-Json
Assert ($self.data.target.creationTime -eq $creation -and !$self.data.globalRegistrationInventory -and $self.data.sources.Count -eq 3) 'Candidate scope and process identity'
foreach($candidate in $self.data.candidates){Assert ($candidate.pid -eq $PID -and $null -eq $candidate.activeRegistration) 'No fabricated global-registration state'}
Assert ((Invoke-Cli @('process','hotkeys','enum','--pid',$PID.ToString(),'--source','accelerators') @(0,6)).Contains('globalRegistrationInventory: false')) 'Hotkey text output'
Assert (((Invoke-Cli @('process','hotkeys','enum','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Hotkey identity guard'
if($InGuest) {
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliHotkeyOracle {
 [DllImport("user32.dll",SetLastError=true)] static extern IntPtr SendMessageTimeout(IntPtr h,uint m,UIntPtr w,IntPtr l,uint flags,uint timeout,out UIntPtr value);
 public static ulong Window(ulong window){UIntPtr result;if(SendMessageTimeout(new IntPtr(unchecked((long)window)),0x33,UIntPtr.Zero,IntPtr.Zero,3,1000,out result)==IntPtr.Zero)throw new Exception("window hotkey oracle "+Marshal.GetLastWin32Error());return result.ToUInt64();}
}
'@
    $root=Join-Path $env:TEMP ('KswordHotkey-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
    $state=Join-Path $root 'state.json';$fixture=Join-Path (Split-Path -Parent $Cli) 'R3Fixture.exe'
    $shortcut=Join-Path ([Environment]::GetFolderPath('Desktop')) ('KswordR3Hotkey-'+[guid]::NewGuid().ToString('N')+'.lnk')
    $shell=New-Object -ComObject WScript.Shell;$link=$shell.CreateShortcut($shortcut);$link.TargetPath=$fixture;$link.Hotkey='CTRL+ALT+F18';$link.Save()
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($link)|Out-Null;[Runtime.InteropServices.Marshal]::FinalReleaseComObject($shell)|Out-Null
    $target=Start-Process $fixture -ArgumentList @('--hotkeys',(Quote-CliArgument $state)) -PassThru
    try {
        for($i=0;$i -lt 50 -and !(Test-Path -LiteralPath $state);$i++){Start-Sleep -Milliseconds 100}
        $data=Get-Content -LiteralPath $state -Raw|ConvertFrom-Json;$born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
        $guard=@('--pid',$target.Id.ToString(),'--creation-time',$born)
        $result=(Invoke-Cli (@('process','hotkeys','enum')+$guard+@('--json')) @(0,6))|ConvertFrom-Json
        $window=$result.data.candidates|Where-Object {$_.source -eq 'window' -and $_.window -eq $data.window}|Select-Object -First 1
        Assert ($window.virtualKey -eq 0x82 -and $window.modifiers -eq '0x6' -and $window.tid -eq $data.tid -and [CliHotkeyOracle]::Window([Convert]::ToUInt64($data.window.Substring(2),16)) -eq $data.hotkeyWord) 'Independent actual WM_GETHOTKEY value and owner thread'
        $menu=$result.data.candidates|Where-Object {$_.source -eq 'menu' -and $_.commandId -eq 2002}|Select-Object -First 1
        Assert ($menu.keyKind -eq 'menu-mnemonic' -and $menu.keyCode -eq 80 -and $null -eq $menu.virtualKey -and $menu.hotkey -eq 'Alt+P') 'Menu mnemonic is not a fabricated virtual-key registration'
        $accelerator=$result.data.candidates|Where-Object {$_.source -eq 'accelerator' -and $_.commandId -eq 1001}|Select-Object -First 1
        Assert ($accelerator.resourceName -eq '#101' -and $accelerator.virtualKey -eq 0x83 -and $accelerator.modifiers -eq '0x3') 'Known compiled PE accelerator fixture'
        $character=$result.data.candidates|Where-Object {$_.source -eq 'accelerator' -and $_.commandId -eq 1002}|Select-Object -First 1
        Assert ($character.keyKind -eq 'character' -and $null -eq $character.virtualKey -and $character.keyCode -eq 106 -and $character.hotkey -eq 'j') 'Character accelerator decoding'
        $lnk=$result.data.candidates|Where-Object {$_.source -eq 'shortcut' -and (Get-Item $_.shortcutPath).FullName -eq (Get-Item $shortcut).FullName}|Select-Object -First 1
        Assert ($lnk.virtualKey -eq 0x81 -and $lnk.modifiers -eq '0x3') 'Actual self-created shortcut hotkey'
        $limited=(Invoke-Cli (@('process','hotkeys','enum')+$guard+@('--limit','1','--json')) 6)|ConvertFrom-Json
        Assert ($limited.data.truncated -and $limited.data.returnedCount -eq 1) 'Limited hotkey output'
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli (@('process','hotkeys','enum')+$guard+@('--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited hotkey target'
    } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose();Remove-Item -LiteralPath $shortcut -Force -ErrorAction SilentlyContinue}
    $target=Start-Process $fixture -ArgumentList @('--hotkeys-hung',(Quote-CliArgument $state)) -PassThru
    try {
        # Ensure the new process, rather than the previous state file, is ready.
        for($i=0;$i -lt 50;$i++){Start-Sleep -Milliseconds 100;try{$data=Get-Content -LiteralPath $state -Raw|ConvertFrom-Json;if($data.pid -eq $target.Id){break}}catch{}}
        $partial=(Invoke-Cli @('process','hotkeys','enum','--pid',$target.Id.ToString(),'--source','windows','--json') 6)|ConvertFrom-Json
        Assert (!$partial.data.sources[0].complete -and $partial.data.sources[0].failures.Count -ge 1 -and $partial.data.returnedCount -ge 1) 'Hung window preserves valid candidates and reports incomplete source'
    } finally {
        if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()
        $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
        if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe hotkey fixture cleanup root'}
        Remove-Item -LiteralPath $absolute -Recurse -Force
    }
}
