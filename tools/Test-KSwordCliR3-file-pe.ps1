foreach ($path in @(@('file','hex','query'),@('file','pe','query'),@('file','pe','header','query'))) {
    $help=Invoke-Cli (@('help')+$path)
    Assert ($help.Contains('--path') -and (Invoke-Cli ($path+@('--help'))) -eq $help) 'PE leaf help'
    foreach ($bad in @(($path+@('--json')),($path+@('--path','C:\missing','--backend','r0','--json')),($path+@('--path','C:\missing','--bad','1','--json')))) {
        Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'PE parameters'
    }
}
$group=Invoke-Cli @('help','file','pe')
Assert ($group.Contains('file pe header') -and !$group.Contains('optionalMagic')) 'PE help shows legacy leaf and immediate header child'
foreach ($budget in @('0','1048577','-1')) {Assert (((Invoke-Cli @('file','hex','query','--path',$Cli,'--max-bytes',$budget,'--json') 1)|ConvertFrom-Json).status -eq 'failed') 'Hex budget validation'}
$binary=(Invoke-Cli @('file','pe','query','--path',$Cli,'--json') @(0,6))|ConvertFrom-Json
Assert ($binary.data.deepAvailable -and $binary.data.machine -eq '0x8664' -and $binary.data.format -eq 'PE32+' -and $binary.data.sectionCount -gt 0) 'Actual CLI PE analysis'
Assert ($binary.data.imports.Count -gt 0 -and @($binary.data.imports|Where-Object {$_.name -match '^Qt'}).Count -eq 0) 'CLI PE imports contain no Qt'
if ($InGuest) {
    $root=Join-Path $env:TEMP ('KSwordCliPe-'+[Guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($root)|Out-Null;$locked=$null
    try {
        $raw=Join-Path $root 'raw.bin';[IO.File]::WriteAllBytes($raw,[byte[]]@(0,34,92,255,65))
        $hex=(Invoke-Cli @('file','hex','query','--path',$raw,'--json'))|ConvertFrom-Json
        Assert ($hex.data.dataHex -eq '00225cff41' -and $hex.data.returnedBytes -eq 5 -and !$hex.data.limited) 'Exact hex bytes'
        $prefix=(Invoke-Cli @('file','hex','query','--path',$raw,'--max-bytes','2','--json') 6)|ConvertFrom-Json
        Assert ($prefix.data.dataHex -eq '0022' -and $prefix.data.limited -and $prefix.data.returnedBytes -eq 2) 'Bounded prefix status'
        Assert ((Invoke-Cli @('file','hex','query','--path',$raw)).Contains('00000000')) 'Hex text rendering'
        $empty=Join-Path $root 'empty.bin';[IO.File]::WriteAllBytes($empty,[byte[]]@())
        $zero=(Invoke-Cli @('file','hex','query','--path',$empty,'--json'))|ConvertFrom-Json
        Assert ($zero.data.returnedBytes -eq 0 -and $zero.data.dataHex -eq '' -and !$zero.data.limited) 'Empty hex preview succeeds'
        $notPe=(Invoke-Cli @('file','pe','query','--path',$raw,'--json') 4)|ConvertFrom-Json
        Assert (!$notPe.data.deepAvailable -and $notPe.data.fallbackReason -eq 'invalid-pe' -and !$notPe.data.header.available) 'Invalid PE is a format failure'
        $badHeader=(Invoke-Cli @('file','pe','header','query','--path',$raw,'--json') 4)|ConvertFrom-Json
        Assert ($badHeader.data.header.win32Error -eq 193) 'Invalid DOS header has typed status'
        $bytes=New-Object byte[] 1024
        function Write-U16([int]$Offset,[uint16]$Value) {[Array]::Copy([BitConverter]::GetBytes($Value),0,$bytes,$Offset,2)}
        function Write-U32([int]$Offset,[uint32]$Value) {[Array]::Copy([BitConverter]::GetBytes($Value),0,$bytes,$Offset,4)}
        function Write-U64([int]$Offset,[uint64]$Value) {[Array]::Copy([BitConverter]::GetBytes($Value),0,$bytes,$Offset,8)}
        Write-U16 0 0x5a4d;Write-U32 60 128;Write-U32 128 0x4550
        Write-U16 132 0x8664;Write-U16 134 1;Write-U32 136 0x12345678;Write-U16 148 240;Write-U16 150 0x22
        Write-U16 152 0x20b;Write-U32 168 0x1000;Write-U64 176 0x140000000
        Write-U32 184 0x1000;Write-U32 188 512;Write-U32 208 0x2000;Write-U32 212 512;Write-U16 220 3;Write-U32 260 16
        [Array]::Copy([Text.Encoding]::ASCII.GetBytes('.text'),0,$bytes,392,5)
        Write-U32 400 512;Write-U32 404 0x1000;Write-U32 408 512;Write-U32 412 512;Write-U32 428 0x60000020
        $sample=Join-Path $root 'sample.exe';[IO.File]::WriteAllBytes($sample,$bytes)
        $pe=(Invoke-Cli @('file','pe','query','--path',$sample,'--json'))|ConvertFrom-Json
        Assert ($pe.data.deepAvailable -and $pe.data.imageBase -eq '0x140000000' -and $pe.data.subsystem -eq '0x3' -and $pe.data.entryPointRva -eq '0x1000' -and $pe.data.entryPointFileOffset -eq '0x200') 'Independent PE constants'
        Assert ($pe.data.sections.Count -eq 1 -and $pe.data.sections[0].name -eq '.text' -and $pe.data.sections[0].rawSize -eq '512' -and $pe.data.importModuleCount -eq 0) 'Section and empty imports'
        $header=(Invoke-Cli @('file','pe','header','query','--path',$sample,'--json'))|ConvertFrom-Json
        Assert ($header.data.header.available -and $header.data.header.timestamp -eq '0x12345678' -and $header.data.header.characteristics -eq '0x22' -and $header.data.header.optionalMagic -eq '0x20b') 'Independent COFF header constants'
        Assert ((Invoke-Cli @('file','pe','query','--path',$sample)).Contains('machineName: x64')) 'PE text'
        Write-U32 272 0x7ffff000;Write-U32 276 20;[IO.File]::WriteAllBytes($sample,$bytes)
        $partial=(Invoke-Cli @('file','pe','query','--path',$sample,'--json') 6)|ConvertFrom-Json
        Assert ($partial.data.deepAvailable -and $partial.data.imports.Count -eq 1 -and $partial.data.imports[0].diagnostic.Contains('could not be mapped')) 'Partial import evidence retains typed diagnostics'
        Write-U32 272 0;Write-U32 276 0;[IO.File]::WriteAllBytes($sample,$bytes)
        $stream=[IO.File]::Open($sample,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::Read);$stream.SetLength(17*1024*1024);$stream.Dispose()
        $large=(Invoke-Cli @('file','pe','query','--path',$sample,'--json') 6)|ConvertFrom-Json
        Assert (!$large.data.deepAvailable -and $large.data.fallbackReason -eq 'size-limit' -and $large.data.header.available -and $large.data.snapshotSize -eq (17*1024*1024).ToString()) 'Size limit preserves actual readable header'
        foreach ($path in @(@('file','hex','query'),@('file','pe','query'),@('file','pe','header','query'))) {
            Assert (((Invoke-Cli ($path+@('--path',(Join-Path $root 'missing'),'--json')) 3)|ConvertFrom-Json).status -eq 'failed') 'Missing file cannot become a successful fallback'
        }
        $locked=[IO.File]::Open($sample,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        $denied=(Invoke-Cli @('file','pe','query','--path',$sample,'--json') 3)|ConvertFrom-Json
        Assert ($denied.data.win32Error -eq 32 -and !$denied.data.deepAvailable -and !$denied.data.header.available) 'Denied PE read is failure, not successful UI fallback'
    } finally {
        if ($locked) {$locked.Dispose()}
        $resolved=[IO.Path]::GetFullPath($root);Assert ($resolved.StartsWith([IO.Path]::GetFullPath($env:TEMP)+'\')) 'PE fixture cleanup stays within TEMP'
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
