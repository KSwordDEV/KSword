$help=Invoke-Cli @('help','hardware','performance','sample')
Assert ($help.Contains('--samples') -and (Invoke-Cli @('hardware','performance','sample','--help')) -eq $help) 'Performance leaf help'
Assert (!(Invoke-Cli @('hardware','performance','help')).Contains('--samples')) 'Performance intermediate help'
foreach($bad in @(
 @('hardware','performance','sample','--group','bad','--json'),
 @('hardware','performance','sample','--samples','0','--json'),
 @('hardware','performance','sample','--samples','30','--interval-ms','10000','--json'),
 @('hardware','performance','sample','--interval-ms','1','--json'),
 @('hardware','performance','sample','--limit','0','--json'),
 @('hardware','performance','sample','--backend','r0','--json'),
 @('hardware','performance','sample','--bad','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Performance argument validation'}
$cpu=(Invoke-Cli @('hardware','performance','sample','--group','cpu','--json') @(0,6))|ConvertFrom-Json
Assert ($cpu.data.queryClosed -and $cpu.data.returnedSamples -eq 1 -and !$cpu.data.cancelled) 'PDH cleanup and single JSON sample'
Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliSystemMetricsOracle {
 [StructLayout(LayoutKind.Sequential)] struct Memory {public uint size,load;public ulong total,available,pageTotal,pageAvailable,virtualTotal,virtualAvailable,extended;}
 [DllImport("kernel32.dll")] public static extern uint GetActiveProcessorCount(ushort group);
 [DllImport("kernel32.dll")] public static extern ushort GetActiveProcessorGroupCount();
 [DllImport("kernel32.dll")] static extern bool GlobalMemoryStatusEx(ref Memory m);
 public static ulong TotalMemory(){var m=new Memory();m.size=(uint)Marshal.SizeOf(typeof(Memory));if(!GlobalMemoryStatusEx(ref m))throw new Exception("memory oracle");return m.total;}
}
'@
$cores=$cpu.data.samples[0].metrics|Where-Object {$_.id -eq 'logical-processors'}
$groups=$cpu.data.samples[0].metrics|Where-Object {$_.id -eq 'processor-groups'}
Assert ([uint64]$cores.value -eq [CliSystemMetricsOracle]::GetActiveProcessorCount(0xffff) -and [uint64]$groups.value -eq [CliSystemMetricsOracle]::GetActiveProcessorGroupCount()) 'Independent processor oracle'
foreach($metric in $cpu.data.samples[0].metrics){Assert ($metric.group -eq 'cpu') 'CPU group selection';if(!$metric.valid){Assert ($null -eq $metric.value) 'Unavailable CPU values are null'}}
$memory=(Invoke-Cli @('hardware','performance','sample','--group','memory','--json') @(0,6))|ConvertFrom-Json
$total=$memory.data.samples[0].metrics|Where-Object {$_.id -eq 'physical-memory-total'}
Assert ([uint64]$total.value -eq [CliSystemMetricsOracle]::TotalMemory() -and $total.unit -eq 'bytes') 'Independent physical memory oracle'
$all=(Invoke-Cli @('hardware','performance','sample','--samples','2','--interval-ms','250','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.returnedSamples -eq 2 -and [uint64]$all.data.samples[1].elapsedMilliseconds -ge [uint64]$all.data.samples[0].elapsedMilliseconds+250) 'Bounded repeated sampling interval'
foreach($sample in $all.data.samples){foreach($metric in $sample.metrics){if(!$metric.valid){Assert ($null -eq $metric.value) 'No fabricated unavailable metric'};if($metric.valid -and $metric.evidence.cStatus){Assert ($metric.evidence.cStatus -in @('0x0','0x1')) 'PDH data status accepted only when valid'}}}
$gpu=(Invoke-Cli @('hardware','performance','sample','--group','gpu','--json') @(0,5,6))|ConvertFrom-Json
Assert ($gpu.data.samples[0].metrics[0].id -eq 'gpu-max-engine') 'GPU maximum-engine scope'
if($gpu.status -eq 'unsupported'){Assert ($null -eq $gpu.data.samples[0].metrics[0].value) 'Missing guest GPU accurately unavailable'}
$limited=(Invoke-Cli @('hardware','performance','sample','--limit','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.samples[0].truncated -and $limited.data.samples[0].returnedCount -eq 1) 'Performance output truncation'
Assert ((Invoke-Cli @('hardware','performance','sample','--group','system') @(0,5,6)).Contains('queryClosed: true')) 'Performance text output'
