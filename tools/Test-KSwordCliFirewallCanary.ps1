[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Cli)
$ErrorActionPreference = 'Stop'
$Cli = (Resolve-Path -LiteralPath $Cli).Path
$name = 'KSword-CLI-Canary-' + [guid]::NewGuid().ToString('N')
$renamed = $name + '-renamed'
$fingerprint = $null
$owned = $false
Write-Output "FIREWALL_CANARY_NAME=$name"
function Invoke-Rule([string[]]$Command) {
    $text = (& $Cli @Command --json | Out-String)
    $code = $LASTEXITCODE
    try { $payload = $text | ConvertFrom-Json } catch { throw "Invalid CLI JSON for $($Command -join ' '): $text" }
    return @{ Code=$code; Payload=$payload }
}
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
try {
    $before=Invoke-Rule @('network','firewall','rule','query','--name',$name)
    Require ($before.Code -eq 3 -and $before.Payload.data.complete -and $before.Payload.data.nameMatchingCount -eq 0) 'Canary name is not confirmed absent.'
    $before=Invoke-Rule @('network','firewall','rule','query','--name',$renamed)
    Require ($before.Code -eq 3 -and $before.Payload.data.complete -and $before.Payload.data.nameMatchingCount -eq 0) 'Renamed canary name is not confirmed absent.'
    $owned = $true
    $create=Invoke-Rule @('network','firewall','rule','create','--name',$name,'--direction','in','--action','block','--protocol','tcp','--profiles','all','--enabled','off','--local-ports','65534','--application','C:\KSword-Nonexistent-Canary\fixture.exe','--description','initial','--confirm')
    Require ($create.Code -eq 0 -and $create.Payload.data.verified) 'Canary creation did not verify.'
    $query=Invoke-Rule @('network','firewall','rule','query','--name',$name)
    Require ($query.Code -eq 0 -and $query.Payload.data.matchingCount -eq 1) 'Canary query did not return exactly one rule.'
    $fingerprint=$query.Payload.data.fingerprint
    $update=Invoke-Rule @('network','firewall','rule','update','--name',$name,'--fingerprint',$fingerprint,'--description','updated','--confirm')
    Require ($update.Code -eq 0 -and $update.Payload.data.verified) 'Canary update did not verify.'
    $fingerprint=$update.Payload.data.after.fingerprint
    $enable=Invoke-Rule @('network','firewall','rule','enable','--name',$name,'--fingerprint',$fingerprint,'--confirm')
    Require ($enable.Code -eq 0 -and $enable.Payload.data.verified) 'Canary enable did not verify.'
    $fingerprint=$enable.Payload.data.after.fingerprint
    $disable=Invoke-Rule @('network','firewall','rule','disable','--name',$name,'--fingerprint',$fingerprint,'--confirm')
    Require ($disable.Code -eq 0 -and $disable.Payload.data.verified) 'Canary disable did not verify.'
    $fingerprint=$disable.Payload.data.after.fingerprint
    $rename=Invoke-Rule @('network','firewall','rule','update','--name',$name,'--fingerprint',$fingerprint,'--new-name',$renamed,'--confirm')
    Require ($rename.Code -eq 0 -and $rename.Payload.data.verified) 'Canary rename did not verify.'
    Write-Output 'FIREWALL_CANARY_PASS create/query/update/enable/disable/rename with postchecks'
} finally {
    foreach($candidate in $(if($owned){@($name,$renamed)}else{@()})) {
        $remaining=Invoke-Rule @('network','firewall','rule','query','--name',$candidate)
        if ($remaining.Payload.data.complete -and $remaining.Payload.data.nameMatchingCount -eq 1) {
            $delete=Invoke-Rule @('network','firewall','rule','delete','--name',$candidate,'--fingerprint',$remaining.Payload.data.fingerprint,'--confirm')
            if ($delete.Code -ne 0 -or -not $delete.Payload.data.verified) { throw 'Canary cleanup could not be verified.' }
        } elseif (-not $remaining.Payload.data.complete -or $remaining.Payload.data.nameMatchingCount -ne 0) {
            throw 'Canary cleanup could not establish a unique rule or confirmed absence.'
        }
    }
    Write-Output 'FIREWALL_CANARY_CLEANUP_PASS'
}
