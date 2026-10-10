$help=Invoke-Cli @('help','hardware','disk','sample')
Assert ($help.Contains('--instance') -and (Invoke-Cli @('hardware','disk','sample','--help')) -eq $help) 'Disk leaf help'
Assert (!(Invoke-Cli @('hardware','disk','help')).Contains('--instance')) 'Disk intermediate help'
foreach($bad in @(
 @('hardware','disk','sample','--samples','0','--json'),
 @('hardware','disk','sample','--samples','30','--interval-ms','10000','--json'),
 @('hardware','disk','sample','--interval-ms','0','--json'),
 @('hardware','disk','sample','--limit','0','--json'),
 @('hardware','disk','sample','--backend','r0','--json'),
 @('hardware','disk','sample','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Disk argument validation'}
$sample=(Invoke-Cli @('hardware','disk','sample','--json') @(0,5,6))|ConvertFrom-Json
Assert ($sample.data.queryClosed -and $sample.data.returnedSamples -eq 1) 'Disk owner cleanup and JSON envelope'
$fields=@('readBytesPerSecond','writeBytesPerSecond','readsPerSecond','writesPerSecond','currentQueueLength','averageQueueLength','busyPercent','readLatencySeconds','writeLatencySeconds')
foreach($disk in $sample.data.samples[0].disks){foreach($field in $fields){Assert ($null -ne $disk.evidence.$field) 'Per-field disk evidence';if(!$disk.evidence.$field.available){Assert ($null -eq $disk.$field) 'No fabricated missing disk value'}}}
Add-Type -TypeDefinition @'
using System;using System.Collections.Generic;using System.Runtime.InteropServices;using System.Threading;
public static class CliDiskOracle {
 [StructLayout(LayoutKind.Sequential)] struct Value {public uint status;public double number;}
 [StructLayout(LayoutKind.Sequential)] struct Item {public IntPtr name;public Value value;}
 [DllImport("pdh.dll",CharSet=CharSet.Unicode)] static extern uint PdhOpenQuery(string path,UIntPtr context,out IntPtr query);
 [DllImport("pdh.dll",CharSet=CharSet.Unicode)] static extern uint PdhAddEnglishCounter(IntPtr query,string path,UIntPtr context,out IntPtr counter);
 [DllImport("pdh.dll")] static extern uint PdhCollectQueryData(IntPtr query);
 [DllImport("pdh.dll",CharSet=CharSet.Unicode)] static extern uint PdhGetFormattedCounterArray(IntPtr counter,uint format,ref uint size,out uint count,IntPtr data);
 [DllImport("pdh.dll")] static extern uint PdhCloseQuery(IntPtr query);
 public static Dictionary<string,double> Query(){IntPtr query,counter;if(PdhOpenQuery(null,UIntPtr.Zero,out query)!=0)throw new Exception("PDH oracle open");try{if(PdhAddEnglishCounter(query,@"\PhysicalDisk(*)\Current Disk Queue Length",UIntPtr.Zero,out counter)!=0)throw new Exception("PDH oracle add");PdhCollectQueryData(query);Thread.Sleep(120);if(PdhCollectQueryData(query)!=0)throw new Exception("PDH oracle collect");uint size=0,count;PdhGetFormattedCounterArray(counter,0x200,ref size,out count,IntPtr.Zero);var data=Marshal.AllocHGlobal((int)size);try{if(PdhGetFormattedCounterArray(counter,0x200,ref size,out count,data)!=0)throw new Exception("PDH oracle array");var result=new Dictionary<string,double>(StringComparer.OrdinalIgnoreCase);int stride=Marshal.SizeOf(typeof(Item));for(int i=0;i<count;i++){var item=(Item)Marshal.PtrToStructure(IntPtr.Add(data,i*stride),typeof(Item));if(item.value.status<=1)result[Marshal.PtrToStringUni(item.name)]=item.value.number;}return result;}finally{Marshal.FreeHGlobal(data);}}finally{PdhCloseQuery(query);}}
}
'@
if($sample.status -in @('success','partial') -and $sample.data.samples[0].disks.Count -gt 0){
 $oracle=[CliDiskOracle]::Query()
 foreach($disk in $sample.data.samples[0].disks){Assert ($oracle.ContainsKey($disk.instance)) 'Independent PDH instance oracle'}
 Assert ($sample.data.samples[0].sources.Count -eq 9) 'Only nine PhysicalDisk counter sources'
 $first=$sample.data.samples[0].disks[0]
 $selected=(Invoke-Cli @('hardware','disk','sample','--instance',$first.instance,'--json') @(0,6))|ConvertFrom-Json
 Assert ($selected.data.samples[0].returnedCount -eq 1 -and $selected.data.samples[0].disks[0].instance -eq $first.instance) 'Exact disk instance selection'
 $missing=(Invoke-Cli @('hardware','disk','sample','--instance','Ksword-NoSuch-Pdh-Disk','--json') @(0,6))|ConvertFrom-Json
 Assert ($missing.data.samples[0].matchedCount -eq '0') 'Valid disk filter miss'
 if($sample.data.samples[0].disks.Count -gt 1){$limited=(Invoke-Cli @('hardware','disk','sample','--limit','1','--json') 6)|ConvertFrom-Json;Assert ($limited.data.samples[0].truncated) 'Disk output truncation'}
}
Assert ((Invoke-Cli @('hardware','disk','sample') @(0,5,6)).Contains('queryClosed: true')) 'Disk text output'
if($InGuest){
 Assert ($sample.status -eq 'success' -and $sample.data.samples[0].disks.Count -gt 0) 'Successful actual guest disk counters'
 $root=Join-Path $env:TEMP ('KswordDisk-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
 $path=Join-Path $root 'io.bin';$ready=Join-Path $root 'ready'
 $job=Start-Job -ArgumentList $path,$ready -ScriptBlock {
  param($path,$ready);$buffer=New-Object byte[] 65536;[Random]::new().NextBytes($buffer)
  $file=[IO.FileStream]::new($path,[IO.FileMode]::Create,[IO.FileAccess]::ReadWrite,[IO.FileShare]::Read,65536,[IO.FileOptions]::WriteThrough)
  try{for($i=0;$i -lt 128;$i++){$file.Write($buffer,0,$buffer.Length)};$file.Flush();Set-Content -LiteralPath $ready -Value 'ready'
   $until=[DateTime]::UtcNow.AddSeconds(6);while([DateTime]::UtcNow -lt $until){$file.Position=0;for($i=0;$i -lt 128;$i++){$file.Write($buffer,0,$buffer.Length)};$file.Flush();$file.Position=0;for($i=0;$i -lt 128;$i++){[void]$file.Read($buffer,0,$buffer.Length)}}
  }finally{$file.Dispose()}
 }
 try{
  for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath $ready);$i++){Start-Sleep -Milliseconds 100}
  Assert (Test-Path -LiteralPath $ready) 'Disposable disk I/O fixture ready'
  $active=(Invoke-Cli @('hardware','disk','sample','--samples','2','--interval-ms','250','--json') 0)|ConvertFrom-Json
  $writes=@($active.data.samples|ForEach-Object {$_.disks}|Where-Object {$_.writeBytesPerSecond -gt 0})
  Assert ($active.data.returnedSamples -eq 2 -and $writes.Count -gt 0 -and (Get-Item -LiteralPath $path).Length -eq 8388608) 'Actual disk writes independently corroborated by self-owned file and positive sampled throughput'
 }finally{
  Stop-Job $job -ErrorAction SilentlyContinue;Remove-Job $job -Force
  $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe disk cleanup root'}
  Remove-Item -LiteralPath $absolute -Recurse -Force
 }
}
