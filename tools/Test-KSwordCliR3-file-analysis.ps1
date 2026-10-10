foreach ($analysisKind in @('hash','signature','entropy')) {
    $help=Invoke-Cli @('help','file',$analysisKind,'query')
    Assert ($help.Contains('--path') -and (Invoke-Cli @('file',$analysisKind,'query','--help')) -eq $help) 'File analysis help'
    foreach ($bad in @(@('file',$analysisKind,'query','--json'),@('file',$analysisKind,'query','--path','C:\missing','--backend','r0','--json'),@('file',$analysisKind,'query','--path','C:\missing','--bad','1','--json'))) {
        Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'File analysis parameters'
    }
    Assert (!(Invoke-Cli @('help','file',$analysisKind)).Contains('--path')) 'File analysis intermediate help'
}
Assert (((Invoke-Cli @('file','entropy','query','--path','C:\missing','--max-bytes','0','--json') 1)|ConvertFrom-Json).status -eq 'failed') 'Entropy zero budget'
$hash=(Invoke-Cli @('file','hash','query','--path',$Cli,'--json'))|ConvertFrom-Json
Assert ($hash.data.digest -eq (Get-FileHash -LiteralPath $Cli -Algorithm SHA256).Hash -and $hash.data.bytesRead -eq (Get-Item -LiteralPath $Cli).Length.ToString()) 'Independent whole CLI hash'
Assert ((Invoke-Cli @('file','hash','query','--path',$Cli)).Contains('algorithm: SHA256')) 'Hash text'
if ($InGuest) {
    $root=Join-Path $env:TEMP ('KSwordCliAnalysis-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null
    $locked=$null
    try {
        $uniform=Join-Path $root 'uniform.bin';[IO.File]::WriteAllBytes($uniform,[byte[]](0..255))
        $entropy=(Invoke-Cli @('file','entropy','query','--path',$uniform,'--json'))|ConvertFrom-Json
        Assert ($entropy.data.complete -and $entropy.data.sampledBytes -eq '256' -and $entropy.data.bitsPerByte -eq 8) 'Uniform entropy is eight bits'
        $bounded=(Invoke-Cli @('file','entropy','query','--path',$uniform,'--max-bytes','128','--json') 6)|ConvertFrom-Json
        Assert ($bounded.data.limited -and !$bounded.data.complete -and $bounded.data.sampledBytes -eq '128' -and $bounded.data.bitsPerByte -eq 7) 'Bounded entropy is partial and numerically correct'
        Assert ((Invoke-Cli @('file','entropy','query','--path',$uniform)).Contains('bitsPerByte: 8')) 'Entropy text'
        $empty=Join-Path $root 'empty.bin';[IO.File]::WriteAllBytes($empty,[byte[]]@())
        $emptyEntropy=(Invoke-Cli @('file','entropy','query','--path',$empty,'--json'))|ConvertFrom-Json
        Assert ($emptyEntropy.data.complete -and $emptyEntropy.data.bitsPerByte -eq 0 -and $emptyEntropy.data.sampledBytes -eq '0') 'Empty file entropy'
        $emptyHash=(Invoke-Cli @('file','hash','query','--path',$empty,'--json'))|ConvertFrom-Json
        Assert ($emptyHash.data.digest -eq (Get-FileHash -LiteralPath $empty).Hash) 'Empty SHA256 digest'
        $signature=(Invoke-Cli @('file','signature','query','--path',$Cli,'--json'))|ConvertFrom-Json
        Assert ($signature.data.evaluated -and !$signature.data.trusted -and $signature.data.signatureState -eq 'unsigned' -and $signature.data.trustStatus -eq '0x800b0100') 'Unsigned file is explicit evidence'
        $unsupported=(Invoke-Cli @('file','signature','query','--path',$uniform,'--json') 5)|ConvertFrom-Json
        Assert ($unsupported.data.trustStatus -eq '0x800b0003' -and !$unsupported.data.trusted) 'Unsupported binary format preserves trust status'
        Assert ((Get-AuthenticodeSignature -LiteralPath $Cli).Status.ToString() -eq 'NotSigned') 'Independent unsigned signature'
        Assert ((Invoke-Cli @('file','signature','query','--path',$Cli)).Contains('signatureState: unsigned')) 'Signature text'
        foreach ($analysisKind in @('hash','entropy','signature')) {
            $missing=(Invoke-Cli @('file',$analysisKind,'query','--path',(Join-Path $root 'missing'),'--json') 3)|ConvertFrom-Json
            Assert ($missing.status -eq 'failed') 'Missing analysis file cannot succeed'
        }
        $locked=[IO.File]::Open($uniform,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        foreach ($analysisKind in @('hash','entropy')) {
            $failure=(Invoke-Cli @('file',$analysisKind,'query','--path',$uniform,'--json') 3)|ConvertFrom-Json
            Assert ($failure.data.win32Error -eq 32) 'Exclusive file lock preserves read failure'
        }
    } finally {
        if ($locked) {$locked.Dispose()}
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'Analysis fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
