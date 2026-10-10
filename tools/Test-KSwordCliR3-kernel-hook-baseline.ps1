$help=Invoke-Cli @('help','kernel','hook-baseline','query')
Assert ($help.Contains('--rva') -and (Invoke-Cli @('kernel','hook-baseline','query','--help')) -eq $help) 'Baseline leaf help'
Assert (!(Invoke-Cli @('kernel','hook-baseline','help')).Contains('--rva')) 'Baseline immediate help'
foreach($bad in @(@('query'),@('query','--path','dummy'),@('query','--path','dummy','--rva','4294967296'),@('query','--path','dummy','--rva','0','--count','0'),@('query','--path','dummy','--rva','0','--count','17'),@('compare','--path','dummy','--rva','0'),@('compare','--path','dummy','--rva','0','--bytes','00GG'),@('query','--path','dummy','--rva','0','--backend','r0'),@('query','--path','dummy','--rva','0','--unknown','1'))){Assert (((Invoke-Cli (@('kernel','hook-baseline')+$bad+@('--json')) 1)|ConvertFrom-Json).status -eq 'failed') 'Baseline validation'}
$directory=Join-Path $env:TEMP ('KswordBaseline-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($directory)|Out-Null
try{
 $path=Join-Path $directory 'fixture.dll';$image=[byte[]]::new(1024)
 function Put16([int]$offset,[uint16]$value){[BitConverter]::GetBytes($value).CopyTo($image,$offset)}
 function Put32([int]$offset,[uint32]$value){[BitConverter]::GetBytes($value).CopyTo($image,$offset)}
 Put16 0 0x5a4d;Put32 60 128;Put32 128 0x4550;Put16 132 0x8664;Put16 134 1;Put16 148 240;Put16 152 0x20b;Put32 208 0x2000;Put32 212 512
 Put32 400 0x600;Put32 404 0x1000;Put32 408 512;Put32 412 512
 for($i=0;$i -lt 512;$i++){$image[512+$i]=[byte]($i%256)};[IO.File]::WriteAllBytes($path,$image)
 $query=(Invoke-Cli @('kernel','hook-baseline','query','--path',$path,'--rva','0x1010','--json') 0)|ConvertFrom-Json
 $expected=[BitConverter]::ToString($image,528,16).Replace('-','').ToLowerInvariant()
 Assert ($query.data.available -and $query.data.fileOffset -eq '0x210' -and $query.data.bytesHex -eq $expected -and $query.data.file.identityKnown -and $query.data.file.closed -and $query.data.file.sizeBytes -eq '1024') 'Independent section bytes/file offset and file evidence'
 $same=(Invoke-Cli @('kernel','hook-baseline','compare','--path',$path,'--rva','0x1010','--bytes',$expected,'--json') 0)|ConvertFrom-Json
 Assert (!$same.data.differs -and $same.data.comparisonSource -eq 'caller-supplied bytes; origin unverified') 'Comparison provenance/match'
 $different=(Invoke-Cli @('kernel','hook-baseline','compare','--path',$path,'--rva','0x1010','--bytes','00','--json') 0)|ConvertFrom-Json
 Assert ($different.data.differs -and $different.data.byteCount -eq '1') 'Byte difference is successful evidence, not a live hook claim'
 foreach($rva in @('0x1300','0x11fa','0xfffffff8')){
  $unmapped=(Invoke-Cli @('kernel','hook-baseline','query','--path',$path,'--rva',$rva,'--json') 5)|ConvertFrom-Json
  Assert ($unmapped.data.mapping.validPe -and !$unmapped.data.available -and $null -eq $unmapped.data.bytesHex) 'Virtual tail/boundary/wrapping RVA cannot return invented disk bytes'
 }
 Assert ((Invoke-Cli @('kernel','hook-baseline','query','--path',$path,'--rva','0','--count','2')).Contains('bytesHex: 4d5a')) 'Disk header text'
 $bad=Join-Path $directory 'invalid.dll';[IO.File]::WriteAllBytes($bad,[byte[]](1,2,3))
 $invalid=(Invoke-Cli @('kernel','hook-baseline','query','--path',$bad,'--rva','0','--json') 4)|ConvertFrom-Json
 Assert ($invalid.data.mapping.malformed -and !$invalid.data.available) 'Invalid disk PE format'
 $missing=(Invoke-Cli @('kernel','hook-baseline','query','--path',(Join-Path $directory 'missing.dll'),'--rva','0','--json') 3)|ConvertFrom-Json
 Assert (!$missing.data.file.opened -and $missing.data.file.win32Error -eq 2) 'Disk file absence is file I/O failure, not driver-open failure'
 $native=(Invoke-Cli @('kernel','hook-baseline','query','--path','\SystemRoot\System32\ntoskrnl.exe','--rva','0','--count','2','--json') 0)|ConvertFrom-Json
 Assert ($native.data.path -eq (Join-Path $env:windir 'System32\ntoskrnl.exe') -and $native.data.bytesHex -eq '4d5a') 'Actual SystemRoot path normalization/disk header'
}finally{
 $resolved=[IO.Path]::GetFullPath($directory);$tempRoot=[IO.Path]::GetFullPath($env:TEMP).TrimEnd('\')+'\';if(!$resolved.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture cleanup outside TEMP'}
 Remove-Item -LiteralPath $resolved -Recurse -Force
}
