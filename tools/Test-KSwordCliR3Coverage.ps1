param([Parameter(Mandatory=$true)][string]$Cli,[Parameter(Mandatory=$true)][string]$ReportPath)
$ErrorActionPreference='Stop'
$repo=Split-Path -Parent $PSScriptRoot
$report=[IO.Path]::GetFullPath($ReportPath);if($report.StartsWith(([IO.Path]::GetFullPath($repo).TrimEnd('\')+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'Coverage runtime report must be outside repository'}
$Cli=(Resolve-Path -LiteralPath $Cli).Path
function Help([string]$Path){$args=@('help')+@($Path.Split(' ',[StringSplitOptions]::RemoveEmptyEntries));$text=(& $Cli @args|Out-String);if($LASTEXITCODE -ne 0){throw "Help failed: $Path"};return $text}
$migration=@(Get-Content -LiteralPath (Join-Path $repo 'shared/usermode/backend/MIGRATION.jsonl')|ForEach-Object {$_|ConvertFrom-Json});if($migration.Count -ne 66){throw 'Expected original 66 migration records'}
$coverage=@(Get-Content -LiteralPath (Join-Path $repo 'docs/cli/coverage.json') -Raw|ConvertFrom-Json);if($coverage.Count -ne 66){throw 'Expected 66 CLI coverage entries'}
$top=Help '';if($top -match '--pid|--rva|--creation-time|--mode'){throw 'Top help expands leaf options'}
$families=@([regex]::Matches($top,'(?m)^  (\S+)  ' )|ForEach-Object {$_.Groups[1].Value})
$queue=[Collections.Generic.Queue[string]]::new();foreach($family in $families){$queue.Enqueue($family)}
$seen=[Collections.Generic.HashSet[string]]::new();$leaves=[Collections.Generic.HashSet[string]]::new();$checks=0
while($queue.Count){$path=$queue.Dequeue();if(!$seen.Add($path)){continue};$help=Help $path
 $inline=(& $Cli @($path.Split(' ')) '--help'|Out-String);if($LASTEXITCODE -ne 0 -or $inline -ne $help){throw "Inline help differs: $path"};$checks++
 $children=@([regex]::Matches($help,'(?m)^  KswordCLI\.exe (.+?)  ' )|ForEach-Object {$_.Groups[1].Value})
 foreach($child in $children){if(!$child.StartsWith($path+' ') -or $child.Substring($path.Length+1).Contains(' ')){throw "Intermediate help expands descendants: $path / $child"};$queue.Enqueue($child)}
 if(!$children.Count){if($help -notmatch 'Syntax:|Options:|Notes:'){throw "Leaf lacks complete metadata: $path"};[void]$leaves.Add($path)}
}
for($i=0;$i -lt 66;$i++){$row=$coverage[$i];if($row.item -ne $i+1 -or $row.migrationFeature -ne $migration[$i].feature){throw "Migration ordering differs at $i"};foreach($path in $row.paths){if(!$seen.Contains($path)){throw "Coverage path not in production help: item $($row.item) $path"}};if(!(Test-Path -LiteralPath (Join-Path $repo $row.documentation))){throw "Missing business document: $($row.documentation)"}}
[pscustomobject]@{success=$true;migrationCount=66;familyCount=$families.Count;nodeCount=$seen.Count;leafCount=$leaves.Count;inlineHelpChecks=$checks;cli=$Cli;sha256=(Get-FileHash -LiteralPath $Cli).Hash}|ConvertTo-Json|Set-Content -LiteralPath $report -Encoding UTF8
Write-Output "R3_COVERAGE_PASS migrations=66 nodes=$($seen.Count) leaves=$($leaves.Count) inline=$checks"
