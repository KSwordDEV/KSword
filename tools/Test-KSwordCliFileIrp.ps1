param([Parameter(Mandatory=$true)][string]$Cli)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Cli).Path
$root = Join-Path ([IO.Path]::GetTempPath()) ('ksword-cli-irp-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $target = Join-Path $root 'owned.bin'
    $output = Join-Path $root 'out.json'
    [IO.File]::WriteAllBytes($target, [byte[]](0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48))
    $line = '""{0}" file irp submit --path "{1}" --major 3 --layer 0 --access 0x120089 --share 7 --disposition 1 --offset 0 --output-bytes 8 --confirm --json > "{2}" 2>&1"' -f $exe,$target,$output
    & cmd.exe /d /c $line
    $code = $LASTEXITCODE
    $raw = [IO.File]::ReadAllText($output,[Text.Encoding]::UTF8)
    if ($code -ne 0) { throw "IRP read failed with exit $code`: $raw" }
    $value = $raw | ConvertFrom-Json
    if ($value.backend -ne 'r0' -or $value.data.protocolStatus -ne 0 -or
        $value.data.outputHex -ne '4142434445464748' -or $value.data.shortRead -or
        $value.data.returnedOutputBytes -ne '8') { throw "Unexpected IRP read receipt: $raw" }
    if (([BitConverter]::ToString([IO.File]::ReadAllBytes($target))) -ne '41-42-43-44-45-46-47-48') {
        throw 'The owned target changed during the read.'
    }
    Write-Output 'CLI_FILE_IRP_VM_PASS: owned file read, stage status and bytes'
} finally {
    if ((Split-Path -Leaf $root) -match '^ksword-cli-irp-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
