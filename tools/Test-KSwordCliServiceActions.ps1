param([Parameter(Mandatory=$true)][string]$Cli)
$ErrorActionPreference='Stop'
$exe=(Resolve-Path -LiteralPath $Cli).Path
$suffix=[guid]::NewGuid().ToString('N')
$name='KswordCliSvcTest'+$suffix
$other='KswordCliSvcOther'+$suffix
$ghost='KswordCliSvcGhost'+$suffix
$ghostKey='HKLM:\SYSTEM\CurrentControlSet\Services\'+$ghost
$testDir=Join-Path $env:TEMP ('KswordCliService-'+$suffix)
$resolvedDir=[IO.Path]::GetFullPath($testDir)
$tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\'
if(!$resolvedDir.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or
   [IO.Path]::GetFileName($resolvedDir) -ne ('KswordCliService-'+$suffix)){throw 'Invalid test directory'}
New-Item -ItemType Directory -Path $resolvedDir | Out-Null
$binary=Join-Path $resolvedDir 'service-test.exe'
[IO.File]::WriteAllBytes($binary,[byte[]](1,2,3,4,5))
$created=@()
function Invoke-Cli([string[]]$arguments) {
    $text=(& $exe @arguments | Out-String);$code=$LASTEXITCODE
    try {$json=$text | ConvertFrom-Json} catch {throw "CLI did not return JSON (exit $code): $text"}
    return @{code=$code;json=$json}
}
function Assert-Result($condition,[string]$message) {if(!$condition){throw $message}}
try {
    & sc.exe create $name 'binPath=' $binary 'start=' 'demand' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not create isolated test service; administrator access is required.'}
    $created+= $name
    & sc.exe create $other 'binPath=' $binary 'start=' 'demand' | Out-Null
    if($LASTEXITCODE -ne 0){throw 'Could not create second isolated test service.'}
    $created+= $other
    $config=Invoke-Cli @('service','config','set','--name',$name,'--display-name','KSword CLI fixture','--description','temporary fixture','--error-control','1','--confirm','--json')
    Assert-Result ($config.code -eq 0 -and $config.json.data.verified) 'Service config write/readback did not succeed.'
    $recovery=Invoke-Cli @('service','recovery','set','--name',$name,'--reset-seconds','60','--actions','restart:1000,none:0','--command','fixture','--non-crash','1','--confirm','--json')
    Assert-Result ($recovery.code -eq 0 -and $recovery.json.data.verified) ("Service recovery write/readback did not succeed: exit=$($recovery.code) result=$($recovery.json | ConvertTo-Json -Depth 8 -Compress)")
    $clear=Invoke-Cli @('service','config','set','--name',$name,'--clear-description','1','--clear-dependencies','1','--confirm','--json')
    Assert-Result ($clear.code -eq 0 -and $clear.json.data.verified) ("Service config clear did not succeed: exit=$($clear.code) result=$($clear.json | ConvertTo-Json -Depth 8 -Compress)")
    $clearRecovery=Invoke-Cli @('service','recovery','set','--name',$name,'--clear-actions','1','--clear-command','1','--confirm','--json')
    Assert-Result ($clearRecovery.code -eq 0 -and $clearRecovery.json.data.verified) ("Service recovery clear did not succeed: exit=$($clearRecovery.code) result=$($clearRecovery.json | ConvertTo-Json -Depth 8 -Compress)")
    $blocked=Invoke-Cli @('service','delete','--name',$name,'--delete-file','1','--expected-file',$binary,'--confirm','--json')
    Assert-Result ($blocked.code -eq 3 -and (Test-Path -LiteralPath $binary) -and (Get-Service -Name $name -ErrorAction SilentlyContinue)) 'Shared binary reference was not refused.'
    $delOther=Invoke-Cli @('service','delete','--name',$other,'--confirm','--json')
    Assert-Result ($delOther.code -eq 0 -and $delOther.json.data.registrationDeleteAccepted) 'Second service registration deletion failed.'
    $del=Invoke-Cli @('service','delete','--name',$name,'--delete-file','1','--expected-file',$binary,'--confirm','--json')
    Assert-Result ($del.code -eq 0 -and $del.json.data.registrationDeleteAccepted -and $del.json.data.fileDeleteAccepted) 'Verified service and file deletion failed.'
    Assert-Result (!(Test-Path -LiteralPath $binary)) 'File still exists after CLI exited.'
    $ghostBinary=Join-Path $resolvedDir 'ghost-test.exe'
    [IO.File]::WriteAllBytes($ghostBinary,[byte[]](5,4,3,2,1))
    New-Item -Path $ghostKey -ErrorAction Stop | Out-Null
    New-ItemProperty -Path $ghostKey -Name Type -PropertyType DWord -Value 16 | Out-Null
    New-ItemProperty -Path $ghostKey -Name ImagePath -PropertyType String -Value $ghostBinary | Out-Null
    $ghostDel=Invoke-Cli @('service','delete','--name',$ghost,'--delete-file','1','--expected-file',$ghostBinary,'--confirm','--json')
    Assert-Result ($ghostDel.code -eq 0 -and $ghostDel.json.data.registrationSource -eq 'registry-only' -and $ghostDel.json.data.fileDeleteAccepted) ("Registry-only service deletion failed: $($ghostDel.json | ConvertTo-Json -Depth 8 -Compress)")
    Assert-Result (!(Test-Path -LiteralPath $ghostKey) -and !(Test-Path -LiteralPath $ghostBinary)) 'Registry-only service or its file still exists.'
    Write-Output 'SERVICE_ACTIONS_VM_PASS config recovery clear shared-reference refusal service-delete file-delete registry-only'
} finally {
    foreach($item in $created){& sc.exe delete $item 2>$null | Out-Null}
    if(Test-Path -LiteralPath $ghostKey){Remove-Item -LiteralPath $ghostKey -Recurse -Force}
    if(Test-Path -LiteralPath $resolvedDir){Remove-Item -LiteralPath $resolvedDir -Recurse -Force}
}
