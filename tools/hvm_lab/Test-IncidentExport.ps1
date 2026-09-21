# Exercises the production exporter with a CLI whose DeviceIoControl is a fake.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$fixture=Join-Path $root 'tools/hvm_ctl/test_query_json.exe'
$testRoot=Join-Path $PSScriptRoot ('artifacts/export-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$vmx=Join-Path $testRoot 'fixture.vmx'
[IO.File]::WriteAllText($vmx,'fixture only')
[IO.File]::WriteAllText((Join-Path $testRoot 'vmware.log'),'fake log')
$evidence=Join-Path $testRoot 'evidence'
& (Join-Path $PSScriptRoot 'Export-SvmIncident.ps1') -Ctl $fixture -EvidenceDirectory $evidence -Vmx $vmx
$summary=Get-Content (Join-Path $evidence 'summary.json') -Raw | ConvertFrom-Json
if ($summary.latchedCpus -ne 1 -or $summary.incoherentCpus -ne 0) { throw 'Missing frozen incident.' }
$vmcb=[IO.File]::ReadAllBytes((Join-Path $evidence 'cpu-0-0-currentVmcbHex.bin'))
if ($vmcb.Length -ne 4096 -or $vmcb[0] -ne 0x5a) { throw 'Current VMCB decoding failed.' }
$vmcb=[IO.File]::ReadAllBytes((Join-Path $evidence 'cpu-0-0-vmcb12Hex.bin'))
if ($vmcb.Length -ne 4096 -or $vmcb[4095] -ne 0xa5) { throw 'Operand VMCB decoding failed.' }
foreach ($file in (Get-Content (Join-Path $evidence 'manifest.json') -Raw | ConvertFrom-Json)) {
    if ((Get-FileHash (Join-Path $evidence $file.file)).Hash -ne $file.sha256) { throw 'Evidence hash mismatch.' }
}
$refused=$false
try { & (Join-Path $PSScriptRoot 'Export-SvmIncident.ps1') -Ctl $fixture -EvidenceDirectory $evidence }
catch { $refused=$true }
if (!$refused) { throw 'Exporter overwrote an existing directory.' }
'INCIDENT_EXPORT=PASS actual PS5 exporter, simulated IOCTL, full page bytes and hashes verified'
