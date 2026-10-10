$help=Invoke-Cli @('help','system','context-menu','disable')
Assert ($help.Contains('--confirm') -and (Invoke-Cli @('system','context-menu','disable','--help')) -eq $help) 'Context menu action help'
Assert (!(Invoke-Cli @('system','context-menu','help')).Contains('--registration')) 'Context menu immediate children'
foreach($bad in @(
 @('system','context-menu','enum','--scope','desktop','--json'),
 @('system','context-menu','enum','--kind','com','--json'),
 @('system','context-menu','enum','--state','active','--json'),
 @('system','context-menu','enum','--limit','0','--json'),
 @('system','context-menu','enum','--registration','Software\Outside','--json'),
 @('system','context-menu','disable','--registration','*\shell\Fixture','--json'),
 @('system','context-menu','enable','--registration','*\shell\Fixture\nested','--confirm','--json'),
 @('system','context-menu','enum','--backend','r0','--json'),
 @('system','context-menu','enum','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Context menu validation before mutation'}
$snapshot=(Invoke-Cli @('system','context-menu','enum','--limit','1','--json') @(0,6))|ConvertFrom-Json
Assert ($snapshot.data.sources.Count -eq 6 -and $snapshot.data.returnedCount -eq '1') 'Actual five registration roots plus backup source'
Assert ((Invoke-Cli @('system','context-menu','enum','--limit','1') @(0,6)).Contains('source: HKCR merged')) 'Context menu text output'
if($InGuest){
 $leaf='KswordCli44-'+[guid]::NewGuid().ToString('N');$registration='*\shell\'+$leaf;$physical='Software\Classes\'+$registration
 $backup='Software\KswordARKLight\ShellExtensionBackup\'+$registration.Replace('\','!');$key=$null;$data=$null
 function Create-MenuFixture {
  $key=[Microsoft.Win32.Registry]::LocalMachine.CreateSubKey($physical);try{$key.SetValue('','KSword fixture');$key.SetValue('MUIVerb','KSword probe');$key.SetValue('Marker',321,[Microsoft.Win32.RegistryValueKind]::DWord)
   $command=$key.CreateSubKey('command');try{$command.SetValue('',('"'+$env:WINDIR+'\System32\notepad.exe" "%1"'))}finally{$command.Dispose()}
   $nested=$key.CreateSubKey('fixtureData\nested');try{$nested.SetValue('Blob',[byte[]]@(0,255,10),[Microsoft.Win32.RegistryValueKind]::Binary);$nested.SetValue('Multi',[string[]]@('first','second'),[Microsoft.Win32.RegistryValueKind]::MultiString)}finally{$nested.Dispose()}
  }finally{$key.Dispose()}
 }
 function Assert-MenuSubtree([string]$Path){
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($Path);Assert ($null -ne $key) 'Independent subtree exists'
  try{Assert ($key.GetValue('Marker') -eq 321 -and $key.GetValue('MUIVerb') -eq 'KSword probe') 'Independent copied top-level DWORD/string values'
   $nested=$key.OpenSubKey('fixtureData\nested');try{Assert ($nested.GetValueKind('Blob') -eq [Microsoft.Win32.RegistryValueKind]::Binary -and ([Convert]::ToBase64String($nested.GetValue('Blob'))) -eq 'AP8K' -and ($nested.GetValue('Multi') -join '|') -eq 'first|second') 'Independent exact nested binary/multistring copy'}finally{$nested.Dispose()}
  }finally{$key.Dispose()}
 }
 try{
  Create-MenuFixture
  $row=(Invoke-Cli @('system','context-menu','enum','--registration',$registration,'--json') @(0,6))|ConvertFrom-Json
  Assert ($row.data.matchedCount -eq '1' -and $row.data.entries[0].enabledRegistration -and $row.data.entries[0].candidateFileExists) 'Owned machine verb and module candidate metadata'
  $disabled=(Invoke-Cli @('system','context-menu','disable','--registration',$registration,'--confirm','--json') 0)|ConvertFrom-Json
  Assert ($disabled.data.verified -and $disabled.data.metadataSucceeded -and $disabled.data.sourceDeleted -and $disabled.data.afterBackup.present) 'Real backup/metadata/delete/readback receipt'
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($physical);Assert ($null -eq $key) 'Independent machine source removed'
  Assert-MenuSubtree ($backup+'\Data')
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backup);try{Assert ($key.GetValue('SourcePath') -eq $registration -and $key.GetValue('Kind') -eq 1) 'Independent backup identity/kind metadata'}finally{$key.Dispose()}
  $row=(Invoke-Cli @('system','context-menu','enum','--registration',$registration,'--state','disabled','--json') @(0,6))|ConvertFrom-Json
  Assert ($row.data.matchedCount -eq '1' -and !$row.data.entries[0].enabledRegistration) 'Retained backup discoverable as disabled entry'
  # An existing destination must not be overwritten during restoration.
  Create-MenuFixture
  $conflict=(Invoke-Cli @('system','context-menu','enable','--registration',$registration,'--confirm','--json') 3)|ConvertFrom-Json
  Assert (!$conflict.data.attempted) 'Reappeared destination collision refuses overwrite'
  Assert-MenuSubtree $physical;Assert-MenuSubtree ($backup+'\Data')
  [Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($physical)
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backup,$true);try{$key.DeleteValue('Kind')}finally{$key.Dispose()}
  $invalid=(Invoke-Cli @('system','context-menu','enable','--registration',$registration,'--confirm','--json') 4)|ConvertFrom-Json
  Assert (!$invalid.data.attempted) 'Missing backup kind refuses restoration'
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backup,$true);try{$key.SetValue('Kind',1,[Microsoft.Win32.RegistryValueKind]::DWord)}finally{$key.Dispose()}
  $enabled=(Invoke-Cli @('system','context-menu','enable','--registration',$registration,'--confirm','--json') 0)|ConvertFrom-Json
  Assert ($enabled.data.verified -and $enabled.data.copySucceeded -and $enabled.data.backupDeleted -and !$enabled.data.afterBackup.present) 'Real restore and backup cleanup'
  Assert-MenuSubtree $physical
  $overlay=[Microsoft.Win32.Registry]::CurrentUser.CreateSubKey($physical);try{$overlay.SetValue('MUIVerb','USER overlay')}finally{$overlay.Dispose()}
  $declined=(Invoke-Cli @('system','context-menu','disable','--registration',$registration,'--confirm','--json') 5)|ConvertFrom-Json
  Assert (!$declined.data.attempted -and $declined.data.userRegistration.present) 'Per-user overlay declines before mutation'
  Assert-MenuSubtree $physical
 }finally{
  if(!$leaf.StartsWith('KswordCli44-') -or $registration -ne ('*\shell\'+$leaf)){throw 'Unsafe context-menu fixture cleanup'}
  foreach($hive in @([Microsoft.Win32.Registry]::CurrentUser,[Microsoft.Win32.Registry]::LocalMachine)){$key=$hive.OpenSubKey($physical);if($key){$key.Dispose();$hive.DeleteSubKeyTree($physical)}}
  $key=[Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($backup);if($key){$key.Dispose();[Microsoft.Win32.Registry]::LocalMachine.DeleteSubKeyTree($backup)}
 }
}
