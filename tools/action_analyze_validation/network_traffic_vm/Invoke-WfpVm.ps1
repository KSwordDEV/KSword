param([ValidateSet('Deploy','Setup','Capture','ReadArchives','Cleanup','Collect')][string]$Phase)
$ErrorActionPreference='Stop'
$repo=(Resolve-Path "$PSScriptRoot\..\..\..").Path
$logs=Join-Path $repo '.codex-build-logs\action-analyze-wfp-vm'
New-Item -ItemType Directory -Force $logs | Out-Null
$vmx='E:\VMs\Windows10-20H2\Windows 10 x64.vmx'
$vmrun='D:\Software\Vmware\vmrun.exe'
$ip=(& $vmrun -T ws getGuestIPAddress $vmx -wait).Trim()
if ($LASTEXITCODE) { throw 'Guest IP unavailable' }
$credential=Import-Clixml 'C:\Users\Administrator\AppData\Local\CodexVm\Windows10-20H2.credential.xml'
$session=New-PSSession -ComputerName $ip -UseSSL -ConfigurationName CodexRemote -Credential $credential -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck)
$root='C:\KSwordValidation\ActionAnalyzeWfp'
try {
    if ($Phase -eq 'Deploy') {
        Invoke-Command -Session $session -ScriptBlock { param($root) if (Test-Path $root) { throw 'Refusing existing guest validation root' }; New-Item -ItemType Directory $root | Out-Null } -ArgumentList $root
        $release=Join-Path $repo 'Ksword5.1\x64\Release'
        foreach ($name in @('KswordCLI.exe','KswordARK.sys','MSVCP140.dll','VCRUNTIME140.dll','VCRUNTIME140_1.dll')) { Copy-Item -ToSession $session -LiteralPath "$release\$name" -Destination "$root\$name" }
        Copy-Item -ToSession $session -LiteralPath 'C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe' -Destination "$root\signtool.exe"
        foreach ($name in @('Invoke-WfpGuest.ps1','Loopback.ps1')) { Copy-Item -ToSession $session -LiteralPath "$PSScriptRoot\$name" -Destination "$root\$name" }
        Invoke-Command -Session $session -ScriptBlock { param($root) [guid]::NewGuid().ToString('N') | Set-Content -Encoding ASCII "$root\marker.txt" } -ArgumentList $root
    } elseif ($Phase -eq 'Collect') {
        $files=Invoke-Command -Session $session -ScriptBlock { param($root) Get-ChildItem $root -File | Where-Object Extension -in @('.json','.log','.txt') | Select-Object -ExpandProperty Name } -ArgumentList $root
        foreach ($name in $files) { Copy-Item -FromSession $session -LiteralPath "$root\$name" -Destination "$logs\$name" -Force }
        $projectExists=Invoke-Command -Session $session -ScriptBlock { param($root) Test-Path "$root\project" } -ArgumentList $root
        if ($projectExists) {
            New-Item -ItemType Directory -Force "$logs\project" | Out-Null
            Copy-Item -FromSession $session -Path "$root\project\*" -Destination "$logs\project" -Recurse -Force
        }
    } else {
        Invoke-Command -Session $session -ScriptBlock { param($root,$phase) & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$root\Invoke-WfpGuest.ps1" -Phase $phase; if ($LASTEXITCODE) { throw "Guest $phase exit=$LASTEXITCODE" } } -ArgumentList $root,$Phase 2>&1 | Tee-Object "$logs\host-$Phase.log"
    }
} finally { Remove-PSSession $session }
