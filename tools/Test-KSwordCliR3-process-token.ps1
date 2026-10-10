$paths=@(@('process','token','query'),@('process','token','classes','list'),@('process','token','raw','query'),@('process','token','raw','set'),@('process','token','privilege','enable'),@('process','token','privilege','disable'))
foreach($path in $paths) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--backend r3') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'Token leaf help'
    if($path[-1] -ne 'list'){Assert (((Invoke-Cli ($path+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Token missing parameters'}
}
Assert (!(Invoke-Cli @('process','token','help')).Contains('--class')) 'Token help hierarchy'
Assert (!(Invoke-Cli @('help','process','token','privilege')).Contains('--name')) 'Privilege help hierarchy'
$classes=(Invoke-Cli @('process','token','classes','list','--json'))|ConvertFrom-Json
Assert ($classes.data.classes.Count -eq 80 -and $classes.data.classes[2].name -eq 'TokenPrivileges') 'Token class discovery'
foreach($bad in @(
    @('process','token','query','--pid',$PID.ToString(),'--backend','r0','--json'),
    @('process','token','query','--pid',$PID.ToString(),'--bad','1','--json'),
    @('process','token','query','--pid',$PID.ToString(),'--classes','TokenUser,TokenUser','--json'),
    @('process','token','query','--pid',$PID.ToString(),'--classes','TokenUser,','--json'),
    @('process','token','raw','query','--pid',$PID.ToString(),'--class','81','--json'),
    @('process','token','query','--pid',$PID.ToString(),'--limit','0','--json'),
    @('process','token','privilege','enable','--pid',$PID.ToString(),'--name','SeKswordFakePrivilege','--confirm','--json'),
    @('process','token','raw','set','--pid',$PID.ToString(),'--class','12','--hex','xyz','--confirm','--json'),
    @('process','token','raw','set','--pid',$PID.ToString(),'--class','12','--hex','00','--data-file','bad','--confirm','--json'),
    @('process','token','raw','set','--pid',$PID.ToString(),'--class','12','--hex','00','--json')
)) {Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Token parameter rejection'}
$creation=(Get-Process -Id $PID).StartTime.ToUniversalTime().ToFileTimeUtc().ToString()
$query=(Invoke-Cli @('process','token','query','--pid',$PID.ToString(),'--creation-time',$creation,'--json'))|ConvertFrom-Json
Assert ($query.data.availableCount -eq 7 -and $query.data.target.creationTime -eq $creation) 'Default token queries and identity'
$map=@{};foreach($row in $query.data.classes){$map[$row.name]=$row}
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
Assert ($map.TokenUser.value.sid -eq $identity.User.Value -and $map.TokenUser.value.account -eq $identity.Name) 'Independent token user SID/account'
Assert ($map.TokenSessionId.value -eq (Get-Process -Id $PID).SessionId -and $map.TokenGroups.value.count -gt 0 -and $map.TokenPrivileges.value.count -gt 0) 'Session and group/privilege counts'
$admin=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Assert ($map.TokenElevation.value -eq $admin -and ($map.TokenPrivileges.value.privileges|Where-Object {$_.name -eq 'SeChangeNotifyPrivilege'}).enabled) 'Known elevation and change-notify privilege'
$limited=(Invoke-Cli @('process','token','query','--pid',$PID.ToString(),'--classes','TokenGroups,TokenPrivileges','--limit','1','--json') 6)|ConvertFrom-Json
Assert ($limited.data.classes[0].truncated -and $limited.data.classes[1].truncated) 'Token table limits are partial'
$raw=(Invoke-Cli @('process','token','raw','query','--pid',$PID.ToString(),'--class','TokenSessionId','--json'))|ConvertFrom-Json
Assert ($raw.data.classes[0].byteSize -eq '4' -and $raw.data.classes[0].value.Replace(' ','') -eq (($map.TokenSessionId.value|ForEach-Object {[BitConverter]::GetBytes([uint32]$_)|ForEach-Object {$_.ToString('X2')}}) -join '')) 'Independent raw scalar bytes'
$all=(Invoke-Cli @('process','token','query','--pid',$PID.ToString(),'--classes','all','--json') @(0,6))|ConvertFrom-Json
Assert ($all.data.requestedCount -eq 80 -and $all.data.availableCount -gt 7) 'All queried classes retain per-class status'
foreach($row in $all.data.classes){if(!$row.available){Assert ($null -eq $row.value -and $row.win32Error -ne 0) 'Unsupported class is null with native error'}}
$unknown=(Invoke-Cli @('process','token','raw','query','--pid',$PID.ToString(),'--class','80','--json') @(0,3,5,6))|ConvertFrom-Json
if($unknown.status -ne 'success'){Assert ($unknown.status -ne 'partial' -or $unknown.data.classes[0].truncated) 'Class limitation is explicit'}
Assert (((Invoke-Cli @('process','token','query','--pid',$PID.ToString(),'--creation-time',([uint64]$creation+1).ToString(),'--json') 3)|ConvertFrom-Json).status -eq 'failed') 'Token process identity mismatch'
Assert ((Invoke-Cli @('process','token','query','--pid',$PID.ToString())).Contains('availableCount: 7')) 'Token text output'
if($InGuest) {
    Add-Type -TypeDefinition @'
using System;using System.Runtime.InteropServices;
public static class CliTokenOracle {
 [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint a,bool i,uint pid);
 [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr p,uint a,out IntPtr t);
 [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(IntPtr t,int c,IntPtr p,uint n,out uint required);
 [DllImport("advapi32.dll",CharSet=CharSet.Unicode)] static extern bool LookupPrivilegeValue(string s,string n,out long luid);
 public static uint Scalar(uint pid,int c){IntPtr token;var p=OpenProcess(0x1000,false,pid);try{if(!OpenProcessToken(p,8,out token))throw new Exception("token open");try{var b=Marshal.AllocHGlobal(4);try{uint n;if(!GetTokenInformation(token,c,b,4,out n)||n!=4)throw new Exception("scalar query");return (uint)Marshal.ReadInt32(b);}finally{Marshal.FreeHGlobal(b);}}finally{CloseHandle(token);}}finally{CloseHandle(p);}}
 public static uint Privilege(uint pid,string name){long wanted;if(!LookupPrivilegeValue(null,name,out wanted))throw new Exception("lookup");IntPtr token;var p=OpenProcess(0x1000,false,pid);try{if(!OpenProcessToken(p,8,out token))throw new Exception("token");try{uint n;GetTokenInformation(token,3,IntPtr.Zero,0,out n);var b=Marshal.AllocHGlobal((int)n);try{if(!GetTokenInformation(token,3,b,n,out n))throw new Exception("privileges");int count=Marshal.ReadInt32(b);for(int i=0;i<count;i++){int offset=4+i*12;long luid=Marshal.ReadInt64(b,offset);if(luid==wanted)return (uint)Marshal.ReadInt32(b,offset+8);}throw new Exception("absent privilege");}finally{Marshal.FreeHGlobal(b);}}finally{CloseHandle(token);}}finally{CloseHandle(p);}}
}
'@
    $target=Start-Process "$env:WINDIR\System32\notepad.exe" -PassThru
    try {
        $born=$target.StartTime.ToUniversalTime().ToFileTimeUtc().ToString();$guard=@('--pid',$target.Id.ToString(),'--creation-time',$born)
        $mismatch=(Invoke-Cli @('process','token','privilege','disable','--pid',$target.Id.ToString(),'--creation-time',([uint64]$born+1).ToString(),'--name','SeChangeNotifyPrivilege','--confirm','--json') 3)|ConvertFrom-Json
        Assert ($mismatch.status -eq 'failed' -and ([CliTokenOracle]::Privilege($target.Id,'SeChangeNotifyPrivilege') -band 2)) 'Mismatch does not adjust token'
        foreach($verb in @('disable','enable')) {
            $result=(Invoke-Cli (@('process','token','privilege',$verb)+$guard+@('--name','SeChangeNotifyPrivilege','--confirm','--json')))|ConvertFrom-Json
            $attributes=[CliTokenOracle]::Privilege($target.Id,'SeChangeNotifyPrivilege')
            Assert ($result.data.verified -and ([bool]($attributes -band 2) -eq ($verb -eq 'enable')) -and $result.data.afterAttributes -eq ('0x{0:X}' -f $attributes)) 'Independent target privilege readback'
        }
        $unassigned=(Invoke-Cli (@('process','token','privilege','enable')+$guard+@('--name','SeTcbPrivilege','--confirm','--json')) 3)|ConvertFrom-Json
        Assert (!$unassigned.data.requestSucceeded -and !$unassigned.data.verified -and $unassigned.data.win32Error -eq 1300) 'API true but privilege not assigned is failure'
        $before=[CliTokenOracle]::Scalar($target.Id,27)
        $desired=$before -bxor 2;$hex=([BitConverter]::GetBytes([uint32]$desired)|ForEach-Object {$_.ToString('X2')}) -join ''
        $set=(Invoke-Cli (@('process','token','raw','set')+$guard+@('--class','TokenMandatoryPolicy','--hex',$hex,'--confirm','--json')) @(0,3,5,6))|ConvertFrom-Json
        if($set.data.requestSucceeded) {Assert ($set.data.verified -and [CliTokenOracle]::Scalar($target.Id,27) -eq $desired) 'Independent raw mandatory-policy effect'
            $payloadPath=Join-Path $env:TEMP ('KswordTokenPayload-'+[guid]::NewGuid().ToString('N')+'.bin')
            try {
                [IO.File]::WriteAllBytes($payloadPath,[BitConverter]::GetBytes([uint32]$before))
                $reset=(Invoke-Cli (@('process','token','raw','set')+$guard+@('--class','TokenMandatoryPolicy','--data-file',$payloadPath,'--confirm','--json')))|ConvertFrom-Json
                Assert ($reset.data.verified -and [CliTokenOracle]::Scalar($target.Id,27) -eq $before) 'Binary-file policy payload restored with independent readback'
            } finally {Remove-Item -LiteralPath $payloadPath -Force -ErrorAction SilentlyContinue}
        } else {
            Assert (!$set.data.verified -and [CliTokenOracle]::Scalar($target.Id,27) -eq $before) 'Refused raw write preserves policy'
            # Exercise another implemented scalar write with SeTcbPrivilege
            # under SYSTEM, while retaining the ordinary-context refusal above.
            $uiBefore=[CliTokenOracle]::Scalar($target.Id,26)
            $uiDesired=$uiBefore -bxor 1
            $root=Join-Path $env:TEMP ('KswordTokenSystem-'+[guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $root|Out-Null
            $taskName='KswordCliToken-'+[guid]::NewGuid().ToString('N')
            $systemScript=Join-Path $root 'system.ps1';$configPath=Join-Path $root 'config.json';$outputPath=Join-Path $root 'result.json'
            @'
param([string]$Configuration)
$ErrorActionPreference='Stop'
$configurationData=Get-Content -LiteralPath $Configuration -Raw|ConvertFrom-Json
$Cli=$configurationData.cli
. $configurationData.support
try {
    $output=Invoke-Cli $configurationData.arguments @(0,3,5,6)
    $result=[pscustomobject]@{success=$true;record=$records[0];output=($output|ConvertFrom-Json)}
} catch {$result=[pscustomobject]@{success=$false;error=$_.ToString();records=$records}}
[IO.File]::WriteAllText($configurationData.output,($result|ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))
'@ | Set-Content -LiteralPath $systemScript -Encoding UTF8
            try {
                $scheduledAction=New-ScheduledTaskAction -Execute "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe" -Argument ('-NoProfile -ExecutionPolicy Bypass -File '+(Quote-CliArgument $systemScript)+' -Configuration '+(Quote-CliArgument $configPath))
                $principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
                Register-ScheduledTask -TaskName $taskName -Action $scheduledAction -Principal $principal -Force|Out-Null
                foreach($value in @($uiDesired,$uiBefore)) {
                    $payloadPath=Join-Path $root 'payload.bin';[IO.File]::WriteAllBytes($payloadPath,[BitConverter]::GetBytes([uint32]$value))
                    $arguments=@('privilege','run','--enable','SeTcbPrivilege','--json','--','process','token','raw','set')+$guard+@('--class','TokenUIAccess','--data-file',$payloadPath,'--confirm','--json')
                    [pscustomobject]@{cli=$Cli;support=(Join-Path (Split-Path -Parent $Cli) 'KswordCliR3TestSupport.ps1');arguments=$arguments;output=$outputPath}|ConvertTo-Json -Depth 10|Set-Content -LiteralPath $configPath -Encoding UTF8
                    if(Test-Path -LiteralPath $outputPath){Remove-Item -LiteralPath $outputPath -Force}
                    Start-ScheduledTask -TaskName $taskName
                    for($i=0;$i -lt 100 -and !(Test-Path -LiteralPath $outputPath);$i++){Start-Sleep -Milliseconds 100}
                    $systemResult=Get-Content -LiteralPath $outputPath -Raw -Encoding UTF8|ConvertFrom-Json
                    Assert ($systemResult.success) ('SYSTEM token fixture failed: '+($systemResult|ConvertTo-Json -Depth 15))
                    $records.Add($systemResult.record)
                    $nested=$systemResult.output.data.stdout|ConvertFrom-Json
                    if($nested.data.requestSucceeded) {
                        Assert ($nested.data.verified -and [CliTokenOracle]::Scalar($target.Id,26) -eq $value) 'SYSTEM scoped privilege UIAccess write independently verified'
                    } else {
                        Assert (!$nested.data.verified -and $nested.data.ntStatus -and [CliTokenOracle]::Scalar($target.Id,26) -eq $uiBefore) 'SYSTEM raw write limitation preserves the independently observed flag'
                    }
                    # The next run must start only after this task instance ended.
                    for($i=0;$i -lt 50 -and (Get-ScheduledTask -TaskName $taskName).State -eq 'Running';$i++){Start-Sleep -Milliseconds 100}
                    Assert ((Get-ScheduledTask -TaskName $taskName).State -ne 'Running') 'SYSTEM fixture task completed'
                }
            } finally {
                Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
                $absolute=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
                if(!$absolute.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase)){throw 'Unsafe SYSTEM fixture cleanup root'}
                Remove-Item -LiteralPath $absolute -Recurse -Force
            }
        }
        $readonly=(Invoke-Cli (@('process','token','raw','set')+$guard+@('--class','TokenStatistics','--hex','00000000','--confirm','--json')) @(3,5))|ConvertFrom-Json
        Assert (!$readonly.data.requestSucceeded -and !$readonly.data.verified -and $readonly.data.ntStatus) 'Read-only token class does not claim success'
        $target.Kill();$target.WaitForExit()
        Assert (((Invoke-Cli (@('process','token','query')+$guard+@('--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Exited token target'
    } finally {if(!$target.HasExited){$target.Kill();$target.WaitForExit()};$target.Dispose()}
}
