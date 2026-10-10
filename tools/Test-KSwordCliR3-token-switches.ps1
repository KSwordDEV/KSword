$names=@('sandbox-inert','virtualization-allowed','virtualization-enabled','ui-access','has-restrictions','app-container','restricted','less-privileged-app-container','sandboxed','app-silo','mandatory-no-write-up','mandatory-new-process-min')
$writable=@('virtualization-allowed','virtualization-enabled','ui-access','mandatory-no-write-up','mandatory-new-process-min')
$rootHelp=Invoke-Cli @('help','process','token','switches')
Assert (!$rootHelp.Contains('--confirm') -and $rootHelp.Contains('app-silo')) 'Token switches hierarchy'
foreach($name in $names) {
    $path=@('process','token','switches',$name,'query');$help=Invoke-Cli (@('help')+$path)
    Assert ((Invoke-Cli ($path+@('--help'))) -eq $help -and $help.Contains('--pid')) 'Individual switch query help'
    if($writable -contains $name) {
        foreach($verb in @('enable','disable')) {
            $path=@('process','token','switches',$name,$verb);$help=Invoke-Cli (@('help')+$path)
            Assert ($help.Contains('--confirm') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Switch write help'
            Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Missing switch write parameters'
        }
    } else {Assert (!(Invoke-Cli @('help','process','token','switches',$name)).Contains('enable')) 'Query-only flags have no write leaves'}
}
foreach($bad in @(
    @('process','token','switches','query','--json'),
    @('process','token','switches','query','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','token','switches','query','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','token','switches','query','--pid',$PID.ToString(),'--name','bad','--json'),
    @('process','token','switches','ui-access','enable','--pid',$PID.ToString(),'--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Switch parameter rejection'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$all=(Invoke-Cli @('process','token','switches','query','--pid',$PID.ToString(),'--creation-time',$creation,'--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq 12 -and $all.data.availableCount -ge 7 -and $all.data.target.creationTime -eq $creation) 'All switch states and identity'
foreach($flag in $all.data.switches){if(!$flag.available){Assert ($null -eq $flag.value -and $flag.win32Error -ne 0) 'Missing flag is null rather than disabled'};Assert ($flag.writable -eq ($writable -contains $flag.name)) 'Query and write capability distinction'}
$silo=$all.data.switches|Where-Object {$_.name -eq 'app-silo'}
Assert ($silo.informationClass -eq 48 -and $silo.className -eq 'TokenIsAppSilo') 'Correct native AppSilo identity'
$classes=(Invoke-Cli @('process','token','classes','list','--json'))|ConvertFrom-Json
Assert ($classes.data.classes[47].name -eq 'TokenIsAppSilo' -and $classes.data.classes[50].name -eq 'TokenIsSystemManagedAdmin') 'CLI class labels follow SDK rather than legacy report labels'
$filtered=(Invoke-Cli @('process','token','switches','ui-access','query','--pid',$PID.ToString(),'--json'))|ConvertFrom-Json
Assert ($filtered.data.requestedCount -eq 1 -and $filtered.data.switches[0].name -eq 'ui-access') 'Discoverable individual switch query'
Assert ((Invoke-Cli @('process','token','switches','query','--pid',$PID.ToString()) @(0,6)).Contains('switches:')) 'Switch text output'
Assert (((Invoke-Cli @('process','token','switches','query','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Switch identity mismatch'
if($InGuest) {
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliSwitchOracle {
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool i,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,out uint value,uint n,out uint length);
 public static uint? Scalar(uint pid,int c){IntPtr t;var p=OpenProcess(0x1000,false,pid);try{if(!OpenProcessToken(p,8,out t))return null;try{uint v,n;if(!GetTokenInformation(t,c,out v,4,out n)||(n!=1&&n!=4))return null;return n==1?v&255:v;}finally{CloseHandle(t);}}finally{CloseHandle(p);}}
}
'@
    $target=Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();$guard=@('--pid',$target.Id.ToString(),'--creation-time',$born)
        $query=(Invoke-Cli (@('process','token','switches','query')+$guard+@('--json')) @(0,6))|ConvertFrom-Json
        foreach($flag in $query.data.switches) {
            $actual=[CliSwitchOracle]::Scalar($target.Id,$flag.informationClass)
            if($null -ne $actual){$value=if($flag.mask){([uint32]$actual -band [Convert]::ToUInt32($flag.mask.Substring(2),16)) -ne 0}else{$actual -ne 0};Assert ($flag.available -and $flag.value -eq $value) 'Independent switch scalar or policy bit'}
            else {Assert (!$flag.available) 'Unavailable native scalar is explicit'}
        }
        $mismatch=(Invoke-Cli @('process','token','switches','ui-access','enable','--pid',$target.Id.ToString(),'--creation-time',([uint64]$born+1).ToString(),'--confirm','--json') 3)|ConvertFrom-Json
        Assert ($mismatch.status -eq 'failed' -and [CliSwitchOracle]::Scalar($target.Id,26) -eq 0) 'Switch guard causes no mutation'
        foreach($name in $writable) {
            $flag=$query.data.switches|Where-Object {$_.name -eq $name}
            foreach($verb in @('enable','disable')) {
                $before=[CliSwitchOracle]::Scalar($target.Id,$flag.informationClass)
                $set=(Invoke-Cli (@('process','token','switches',$name,$verb)+$guard+@('--confirm','--json')) @(0,3,5,6))|ConvertFrom-Json
                $actual=[CliSwitchOracle]::Scalar($target.Id,$flag.informationClass)
                if($set.data.requestSucceeded){$value=if($flag.mask){([uint32]$actual -band [Convert]::ToUInt32($flag.mask.Substring(2),16)) -ne 0}else{$actual -ne 0}
                    if($set.data.verified) {
                        Assert ($value -eq ($verb -eq 'enable')) 'Actual switch effect matches verified readback'
                        if($flag.mask){Assert ($set.data.otherPolicyBitPreserved) 'Unselected policy bits preserved'}
                    } else {
                        Assert ($set.status -eq 'partial' -and (!$set.data.after.available -or $value -ne ($verb -eq 'enable') -or ($flag.mask -and !$set.data.otherPolicyBitPreserved))) ('Unconfirmed switch request must explain partial status: '+$name+' '+$verb+' '+($set|ConvertTo-Json -Compress -Depth 10))
                    }
                } else {Assert (!$set.data.verified -and $before -eq $actual) 'Permission/platform refusal preserves flag'}
            }
        }
        # Reuse the tested scoped-privilege command inside an isolated SYSTEM task.
        $root=Join-Path $env:TEMP ('KswordSwitchSystem-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $root|Out-Null
        $taskName='KswordCliSwitch-'+[guid]::NewGuid().ToString('N')
        $script=Join-Path $root 'system.ps1';$config=Join-Path $root 'config.json';$output=Join-Path $root 'result.json'
        @'
param([string]$Configuration)
$ErrorActionPreference='Stop'
$configurationData=Get-Content -LiteralPath $Configuration -Raw|ConvertFrom-Json
$Cli=$configurationData.cli
. $configurationData.support
try{$text=Invoke-Cli $configurationData.arguments;$result=[pscustomobject]@{success=$true;record=$records[0];output=($text|ConvertFrom-Json)}}
catch{$result=[pscustomobject]@{success=$false;error=$_.ToString();records=$records}}
[IO.File]::WriteAllText($configurationData.output,($result|ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
'@ | Set-Content -LiteralPath $script -Encoding UTF8
        try {
            $action=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -ExecutionPolicy Bypass -File '+(Quote-CliArgument $script)+' -Configuration '+(Quote-CliArgument $config))
            $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
            Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Force|Out-Null
            foreach($verb in @('enable','disable')) {
                $arguments=@('privilege','run','--enable','SeTcbPrivilege','--json','--','process','token','switches','ui-access',$verb)+$guard+@('--confirm','--json')
                [pscustomobject]@{cli=$Cli;support=(Join-Path (Split-Path -Parent $Cli) 'KswordCliR3TestSupport.ps1');arguments=$arguments;output=$output}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $config -Encoding UTF8
                if(Test-Path -LiteralPath $output){Remove-Item -LiteralPath $output -Force}
                Start-ScheduledTask -TaskName $taskName
                for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath $output);$i++){Start-Sleep -Milliseconds 100}
                $system=Get-Content -LiteralPath $output -Raw -Encoding UTF8|ConvertFrom-Json
                Assert ($system.success) ('SYSTEM switch fixture failed: '+($system|ConvertTo-Json -Depth 20));$records.Add($system.record)
                $nested=$system.output.data.stdout|ConvertFrom-Json
                Assert ($nested.data.verified -and [bool][CliSwitchOracle]::Scalar($target.Id,26) -eq ($verb -eq 'enable')) 'SYSTEM scoped switch action independently verified'
                for($i=0;$i -lt 50 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Running';$i++){Start-Sleep -Milliseconds 100}
                Assert ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') 'SYSTEM switch fixture completed'
            }
        } finally {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue;Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
            if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe switch fixture cleanup root'}
            Remove-Item -LiteralPath $absolute -Recurse -Force
        }
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli (@('process','token','switches','query')+$guard+@('--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited switch target'
    } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
