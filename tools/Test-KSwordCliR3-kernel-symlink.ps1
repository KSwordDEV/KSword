$help=Invoke-Cli @('help','kernel','symlink','query')
Assert ($help.Contains('--path') -and (Invoke-Cli @('kernel','symlink','query','--help')) -eq $help) 'Symlink query help'
Assert (!(Invoke-Cli @('kernel','symlink','help')).Contains('--target-filter')) 'Symlink immediate help'
foreach($bad in @(
 @('kernel','symlink','query','--json'),
 @('kernel','symlink','query','--path','relative','--json'),
 @('kernel','symlink','enum','--root','relative','--json'),
 @('kernel','symlink','enum','--max-entries','0','--json'),
 @('kernel','symlink','enum','--duration-ms','99','--json'),
 @('kernel','symlink','enum','--limit','0','--json'),
 @('kernel','symlink','enum','--backend','r0','--json'),
 @('kernel','symlink','query','--path','\KnownDlls\KnownDllPath','--unknown','1','--json')
)){Assert (((Invoke-Cli $bad 1)|ConvertFrom-Json).status -eq 'failed') 'Symlink parameter validation'}
. "$PSScriptRoot\KswordCliR3NamespaceOracle.ps1"
$oracle=[CliNamespaceOracle]::Enum('\KnownDlls')
$links=@($oracle.Keys|Where-Object {$oracle[$_] -eq 'SymbolicLink'})
$enumeration=(Invoke-Cli @('kernel','symlink','enum','--root','\KnownDlls','--json') @(0,6))|ConvertFrom-Json
Assert ($enumeration.data.sources[0].complete -and [uint64]$enumeration.data.symbolicLinkCount -eq $links.Count) 'Independent native symbolic-link type selection'
foreach($row in $enumeration.data.links){Assert ($row.type -eq 'SymbolicLink' -and $row.symlinkTarget.available -and $row.symlinkTarget.value -eq [CliNamespaceOracle]::Resolve($row.fullPath) -and $row.closed) 'Independent native target and closure'}
$missing=(Invoke-Cli @('kernel','symlink','query','--path',('\KnownDlls\Missing-'+[guid]::NewGuid().ToString('N')),'--json') 3)|ConvertFrom-Json
Assert (!$missing.data.link.opened -and $missing.data.link.openNtStatus -ne '0x0') 'Missing link native failure'
Assert ((Invoke-Cli @('kernel','symlink','enum','--root','\KnownDlls') @(0,6)).Contains('source: shared native directory symbolic-link')) 'Symlink text output'
if($InGuest){
 $root=[CliNamespaceOracle]::Fixture()
 try{
  $path=$root+'\FixtureLink';$target=[CliNamespaceOracle]::Resolve($path)
  $query=(Invoke-Cli @('kernel','symlink','query','--path',$path,'--json') 0)|ConvertFrom-Json
  Assert ($query.data.nameDerivedFromRequest -and $query.data.link.symlinkTarget.value -eq $target -and $target -eq '\KnownDlls' -and $query.data.link.closed -and $query.data.link.basic.available) 'Real one-link resolution/basic query/closure'
  $filtered=(Invoke-Cli @('kernel','symlink','enum','--root',$root,'--target-filter','knowndlls','--json') 0)|ConvertFrom-Json
  Assert ($filtered.data.matchedCount -eq '1' -and $filtered.data.links[0].fullPath -eq $path) 'Case-insensitive target filter under private root'
  $empty=(Invoke-Cli @('kernel','symlink','enum','--root',$root,'--target-filter','KswordImpossibleTarget','--json') 0)|ConvertFrom-Json
  Assert ($empty.data.matchedCount -eq '0' -and $empty.data.unknownTargetFilterCount -eq '0') 'Known target filter can produce complete empty result'
  $wrongType=(Invoke-Cli @('kernel','symlink','query','--path',($root+'\ChildDir'),'--json') 3)|ConvertFrom-Json
  Assert (!$wrongType.data.link.opened) 'Wrong native object type refused by opener'
  $limited=(Invoke-Cli @('kernel','symlink','enum','--root',$root,'--max-entries','1','--json') 6)|ConvertFrom-Json
  Assert ($limited.data.limited -and !$limited.data.sources[0].complete) 'Actual directory scan limit'
 }finally{[CliNamespaceOracle]::Stop()}
}
