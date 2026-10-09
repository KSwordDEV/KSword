#include "BamAhcache.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <sstream>
#include <utility>
namespace ks::r3::security {
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
