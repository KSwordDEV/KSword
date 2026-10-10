$help=Invoke-Cli @('help','kernel','namespace','enum')
Assert ($help.Contains('--root') -and (Invoke-Cli @('kernel','namespace','enum','--help')) -eq $help) 'Namespace leaf help'
Assert (!(Invoke-Cli @('kernel','namespace','help')).Contains('--duration-ms')) 'Namespace immediate child help'
foreach($bad in @(
 @('kernel','namespace','enum','--root','relative','--json'),
 @('kernel','namespace','enum','--max-entries','0','--json'),
 @('kernel','namespace','enum','--duration-ms','99','--json'),
 @('kernel','namespace','enum','--limit','0','--json'),
 @('kernel','namespace','enum','--backend','r0','--json'),
 @('kernel','namespace','enum','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Namespace parameter validation'}
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;
public static class CliNamespaceOracle {
 [StructLayout(LayoutKind.Sequential)] struct UString{public ushort length,max;public IntPtr buffer;}
 [StructLayout(LayoutKind.Sequential)] struct Attr{public uint length;public IntPtr root,name;public uint flags;public IntPtr security,qos;}
 [StructLayout(LayoutKind.Sequential)] struct Entry{public UString name,type;}
 [DllImport("ntdll.dll")] static extern int NtOpenDirectoryObject(out IntPtr handle,uint access,ref Attr attr);
 [DllImport("ntdll.dll")] static extern int NtQueryDirectoryObject(IntPtr handle,IntPtr buffer,uint size,byte single,byte restart,ref uint context,out uint returned);
 [DllImport("ntdll.dll")] static extern int NtCreateDirectoryObject(out IntPtr handle,uint access,ref Attr attr);
 [DllImport("ntdll.dll")] static extern int NtCreateSymbolicLinkObject(out IntPtr handle,uint access,ref Attr attr,ref UString target);
 [DllImport("ntdll.dll")] static extern int NtCreateEvent(out IntPtr handle,uint access,ref Attr attr,int kind,byte state);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
 static readonly List<IntPtr> owned=new List<IntPtr>();
 static Attr Attributes(string name,out IntPtr chars,out IntPtr unicode){chars=Marshal.StringToHGlobalUni(name);var text=new UString{length=(ushort)(name.Length*2),max=(ushort)((name.Length+1)*2),buffer=chars};unicode=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UString)));Marshal.StructureToPtr(text,unicode,false);return new Attr{length=(uint)Marshal.SizeOf(typeof(Attr)),name=unicode,flags=0x40};}
 static IntPtr Open(string name){IntPtr chars,unicode;var attr=Attributes(name,out chars,out unicode);try{IntPtr h;int status=NtOpenDirectoryObject(out h,1,ref attr);if(status!=0)throw new Exception("oracle open "+status.ToString("X"));return h;}finally{Marshal.FreeHGlobal(unicode);Marshal.FreeHGlobal(chars);}}
 public static Dictionary<string,string> Enum(string name){var h=Open(name);var buffer=Marshal.AllocHGlobal(65536);try{var result=new Dictionary<string,string>();uint context=0,returned;byte restart=1;for(int i=0;i<100000;i++){int status=NtQueryDirectoryObject(h,buffer,65536,1,restart,ref context,out returned);restart=0;if(status==unchecked((int)0x8000001a))return result;if(status!=0)throw new Exception("oracle query "+status.ToString("X"));var entry=(Entry)Marshal.PtrToStructure(buffer,typeof(Entry));if(entry.name.buffer==IntPtr.Zero)return result;result.Add(Marshal.PtrToStringUni(entry.name.buffer,entry.name.length/2),Marshal.PtrToStringUni(entry.type.buffer,entry.type.length/2));}throw new Exception("oracle cap");}finally{Marshal.FreeHGlobal(buffer);if(!CloseHandle(h))throw new Exception("oracle close");}}
 static void Create(string path,string kind){IntPtr chars,unicode;var attr=Attributes(path,out chars,out unicode);try{IntPtr h;int status;if(kind=="dir")status=NtCreateDirectoryObject(out h,0xf,ref attr);else if(kind=="event")status=NtCreateEvent(out h,0x1f0003,ref attr,0,0);else{var targetChars=Marshal.StringToHGlobalUni(@"\KnownDlls");try{var target=new UString{length=20,max=22,buffer=targetChars};status=NtCreateSymbolicLinkObject(out h,0xf0001,ref attr,ref target);}finally{Marshal.FreeHGlobal(targetChars);}}if(status!=0)throw new Exception("fixture create "+status.ToString("X"));owned.Add(h);}finally{Marshal.FreeHGlobal(unicode);Marshal.FreeHGlobal(chars);}}
 public static string Fixture(){var root=@"\BaseNamedObjects\KswordNs-"+Guid.NewGuid().ToString("N");try{Create(root,"dir");Create(root+@"\ChildDir","dir");Create(root+@"\FixtureLink","link");Create(root+@"\FixtureEvent","event");return root;}catch{Stop();throw;}}
 public static void Stop(){for(int i=owned.Count-1;i>=0;i--)if(!CloseHandle(owned[i]))throw new Exception("fixture close");owned.Clear();}
}
'@
$oracle=[CliNamespaceOracle]::Enum('\KnownDlls')
$known=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--limit','100000','--json') @(0,6))|ConvertFrom-Json
Assert ($known.data.sources[0].complete -and $known.data.sources[0].closed -and [uint64]$known.data.enumeratedCount -eq $oracle.Count) 'Independent native KnownDlls enumeration count and root closure'
foreach($row in $known.data.entries){Assert ($oracle.ContainsKey($row.name) -and $oracle[$row.name] -eq $row.type -and $row.parentPath -eq '\KnownDlls') 'Independent native object name/type'}
$empty=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--filter','KswordNoSuchItem-44-47','--json') @(0,6))|ConvertFrom-Json
Assert ($empty.data.matchedCount -eq '0' -and $empty.data.sources[0].complete) 'Complete filtered empty result'
$limited=(Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--max-entries','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.limited -and !$limited.data.sources[0].complete -and $limited.data.enumeratedCount -eq '1') 'Native entry budget and incomplete evidence'
$failed=(Invoke-Cli @('kernel','namespace','enum','--root',('\KswordMissing-'+[guid]::NewGuid().ToString('N')),'--json') 3)|ConvertFrom-Json
Assert (!$failed.data.sources[0].opened -and $failed.data.sources[0].openNtStatus -ne '0x0') 'Selected missing root preserves NTSTATUS'
Assert ((Invoke-Cli @('kernel','namespace','enum','--root','\KnownDlls','--limit','1') 6).Contains('source: shared NtOpenDirectoryObject')) 'Namespace text and output truncation'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture()
 try{
  $oracle=[CliNamespaceOracle]::Enum($root);$result=(Invoke-Cli @('kernel','namespace','enum','--root',$root,'--json') 0)|ConvertFrom-Json
  Assert ($result.data.enumeratedCount -eq '3' -and $oracle.Count -eq 3 -and $result.data.sources[0].complete) 'Self-created namespace directory children'
  foreach($row in $result.data.entries){Assert ($oracle[$row.name] -eq $row.type) 'Independent fixture type';if($row.metadataProbeSupported){Assert ($row.opened -and $row.basic.available -and $row.basic.ntStatus -eq '0x0' -and [uint64]$row.basic.handleCount -ge 1 -and $row.closed) 'Real directory/link basic metadata and closure'}else{Assert ($null -eq $row.opened -and $null -eq $row.basic.handleCount -and !$row.openAttempted) 'Other types not falsely claimed opened'}}
  $link=@($result.data.entries|Where-Object {$_.name -eq 'FixtureLink'})[0];Assert ($link.symlinkTarget.available -and $link.symlinkTarget.value -eq '\KnownDlls') 'Independent created symbolic link target'
 }finally{[CliNamespaceOracle]::Stop()}
 $gone=(Invoke-Cli @('kernel','namespace','enum','--root',$root,'--json') 3)|ConvertFrom-Json
 Assert (!$gone.data.sources[0].opened) 'Last fixture references close and namespace root disappears'
 $overview=(Invoke-Cli @('kernel','namespace','enum','--limit','1','--json') 6)|ConvertFrom-Json
 Assert ($overview.data.currentSessionKnown -and $overview.data.requestedRootCount -gt 15 -and $overview.data.openedRootCount -gt 0 -and $overview.data.truncated) 'Shared default roots and current-session discovery'
}
