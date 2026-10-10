#include "BamAhcache.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
const std::vector<SecurityProbe>& BamAhcacheProbes(){static const std::vector<SecurityProbe> probes{
    {L"bam-summary",L"BAM UserSettings child-key count only; no SIDs/execution history",SecurityProbeKind::Command,
        L"$path='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings';$payload=if(Test-Path -LiteralPath $path -ErrorAction Stop){$keys=@(Get-ChildItem -LiteralPath $path -ErrorAction Stop);[ordered]@{available=$true;path=$path;known=$true;present=$true;userSettingsKeyCount=[string]$keys.Count;summaryOnly=$true}}else{[ordered]@{available=$true;path=$path;known=$true;present=$false;userSettingsKeyCount=$null;summaryOnly=$true}};$payload|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"amcache-file",L"Amcache.hve disk metadata only; no hive/history read",SecurityProbeKind::Command,
        L"$path=Join-Path $env:windir 'AppCompat\\Programs\\Amcache.hve';$payload=if(Test-Path -LiteralPath $path -PathType Leaf -ErrorAction Stop){$file=Get-Item -LiteralPath $path -ErrorAction Stop;[ordered]@{available=$true;path=$path;known=$true;present=$true;lengthBytes=[string]$file.Length;lastWriteUtc=$file.LastWriteTimeUtc.ToString('o');summaryOnly=$true}}else{[ordered]@{available=$true;path=$path;known=$true;present=$false;lengthBytes=$null;lastWriteUtc=$null;summaryOnly=$true}};$payload|ConvertTo-Json -Compress -Depth 8",{},{}},
    {L"appcompat-keys",L"AppCompatCache/AppCompatFlags key availability only",SecurityProbeKind::Command,
        L"$partial=$false;$items=@(foreach($path in @('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache','HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags')){try{[ordered]@{path=$path;known=$true;present=[bool](Test-Path -LiteralPath $path -ErrorAction Stop)}}catch{$partial=$true;[ordered]@{path=$path;known=$false;present=$null;error=$_.Exception.Message}}});[ordered]@{available=$true;keys=$items;summaryOnly=$true}|ConvertTo-Json -Compress -Depth 8;if($partial){exit 6}",{},{}},
    {L"bam-service",L"SCM BAM driver registration/status",SecurityProbeKind::Service,{},{},L"bam"},
    {L"ahcache-service",L"SCM ahcache registration/status",SecurityProbeKind::Service,{},{},L"ahcache"}};return probes;}
void AppendBamAhcacheR3(std::vector<MiscAuditRow>& rows) {




    AddCommandRow(rows, L"BAM / ahcache", L"BAM registry summary", L"PowerShell registry count", RunPowerShellScalar(
        L"$p='HKLM:\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'; if(Test-Path $p){ $users=(Get-ChildItem -LiteralPath $p -ErrorAction SilentlyContinue | Measure-Object).Count; 'UserSettingsKeys=' + $users + '; privacyMode=SummaryOnly' } else { 'BAM UserSettings key missing' }"));
    AddCommandRow(rows, L"BAM / ahcache", L"Amcache availability", L"PowerShell file summary", RunPowerShellScalar(
        L"$p=Join-Path $env:windir 'AppCompat\\Programs\\Amcache.hve'; if(Test-Path $p){ $i=Get-Item -LiteralPath $p; 'AmcachePresent=true; Length=' + $i.Length + '; LastWriteUtc=' + $i.LastWriteTimeUtc.ToString('o') + '; privacyMode=SummaryOnly' } else { 'Amcache.hve missing' }"));
    AddCommandRow(rows, L"BAM / ahcache", L"AppCompat cache service keys", L"PowerShell registry summary", RunPowerShellScalar(
        L"$keys=@('HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache','HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags'); foreach($k in $keys){ if(Test-Path $k){ Write-Output ($k + '=present') } else { Write-Output ($k + '=missing') } }"));
    AddServiceRow(rows, L"BAM / ahcache", L"BAM driver", L"bam");
    AddServiceRow(rows, L"BAM / ahcache", L"Application Compatibility Cache", L"ahcache");
    AppendRow(rows, L"BAM / ahcache", L"Privacy boundary", L"SummaryOnly", L"UI policy", L"Info", L"默认只显示状态、计数和可用性，不枚举用户执行历史明细、不导出路径时间线。");


}
}
