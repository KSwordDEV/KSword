# Test the production acceptance predicate without executing a driver or VM.
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'Invoke-GuestAcceptance.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Runner parse failed.' }
$function=$ast.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'CheckNestedProbe'},$true)
Invoke-Expression $function.Extent.Text
$Vcpu=2
function New-Metrics {
    return [pscustomobject]@{version=6;backend=2;svmProcessors=@(0..1 | ForEach-Object {
        [pscustomobject]@{group=0;number=$_;nestedProbe=[pscustomobject]@{
            valid=1;sequence=2;status='0x00000000';entries=1;reflections=1;faults=7;
            exit='0x0000000000000072';marker='0x000000004B534E31'}}
    })}
}
$previous=CheckNestedProbe (New-Metrics) @{}
if ($previous.Count -ne 2) { throw 'Complete fixture rejected.' }
$mutations=@(
    {param($m) $m.version=3},
    {param($m) $m.backend=1},
    {param($m) $m.svmProcessors=@($m.svmProcessors[0])},
    {param($m) $m.svmProcessors[1].number=0},
    {param($m) $m.svmProcessors[1].group=1},
    {param($m) $m.svmProcessors[1].nestedProbe.valid=0},
    {param($m) $m.svmProcessors[1].nestedProbe.sequence=3},
    {param($m) $m.svmProcessors[1].nestedProbe.status='0xC0000001'},
    {param($m) $m.svmProcessors[1].nestedProbe.entries=0},
    {param($m) $m.svmProcessors[1].nestedProbe.reflections=0},
    {param($m) $m.svmProcessors[1].nestedProbe.faults=0},
    {param($m) $m.svmProcessors[1].nestedProbe.exit='0xFFFFFFFFFFFFFFFF'},
    {param($m) $m.svmProcessors[1].nestedProbe.marker='0x000000004B534E32'}
)
foreach ($mutate in $mutations) {
    $m=New-Metrics
    & $mutate $m
    $rejected=$false
    try { CheckNestedProbe $m @{} | Out-Null } catch { $rejected=$true }
    if (-not $rejected) { throw 'Invalid evidence accepted.' }
}
$rejected=$false
try { CheckNestedProbe (New-Metrics) $previous | Out-Null } catch { $rejected=$true }
if (-not $rejected) { throw 'Stale completion accepted.' }
$fresh=New-Metrics
foreach ($cpu in $fresh.svmProcessors) { $cpu.nestedProbe.sequence=4 }
CheckNestedProbe $fresh $previous | Out-Null
'NESTED_PROBE_EVIDENCE=PASS (16 cases; synthetic data only)'
