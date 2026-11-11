#include "ApplicationControl.h"
#include <algorithm>
#include <stdexcept>
#include <vector>

namespace ks::r3::security {
namespace {
std::wstring encoded(const std::wstring& value) {
    static constexpr wchar_t alphabet[] = L"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const auto* bytes = reinterpret_cast<const unsigned char*>(value.data());
    const std::size_t length = value.size() * sizeof(wchar_t);
    std::wstring result;
    result.reserve(((length + 2) / 3) * 4);
    for (std::size_t i = 0; i < length; i += 3) {
        const unsigned n = (static_cast<unsigned>(bytes[i]) << 16) |
            (i + 1 < length ? static_cast<unsigned>(bytes[i + 1]) << 8 : 0) |
            (i + 2 < length ? bytes[i + 2] : 0);
        result.push_back(alphabet[(n >> 18) & 63]); result.push_back(alphabet[(n >> 12) & 63]);
        result.push_back(i + 1 < length ? alphabet[(n >> 6) & 63] : L'=');
        result.push_back(i + 2 < length ? alphabet[n & 63] : L'=');
    }
    return result;
}

const std::wstring kHash = LR"PS(
function HashText([string]$text) {
  $h=[Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($h.ComputeHash([Text.Encoding]::UTF8.GetBytes($text)))).Replace('-','').ToLowerInvariant() }
  finally { $h.Dispose() }
}
function Emit($value) { $value | ConvertTo-Json -Compress -Depth 12 }
)PS";

const std::wstring kAppLocker = LR"PS(
$module=Get-Module -ListAvailable -Name AppLocker | Select-Object -First 1
if($null -eq $module) { Emit ([ordered]@{available=$false;reason='AppLocker module unavailable'}); exit 5 }
Import-Module -Name $module.Path -ErrorAction Stop
function PolicyText([string]$scope) {
  if($scope -eq 'effective') { return [string](Get-AppLockerPolicy -Effective -Xml -ErrorAction Stop) }
  $x=[string](Get-AppLockerPolicy -Local -Xml -ErrorAction Stop)
  if([string]::IsNullOrWhiteSpace($x)) { return '<AppLockerPolicy Version="1"></AppLockerPolicy>' }
  return $x
}
function ReadDocument([string]$xml) {
  $settings=New-Object System.Xml.XmlReaderSettings
  $settings.DtdProcessing=[System.Xml.DtdProcessing]::Prohibit
  $settings.XmlResolver=$null
  $doc=New-Object System.Xml.XmlDocument; $doc.XmlResolver=$null
  $reader=[System.Xml.XmlReader]::Create((New-Object System.IO.StringReader($xml)),$settings)
  try { $doc.Load($reader) } finally { $reader.Dispose() }
  if($null -eq $doc.DocumentElement -or $doc.DocumentElement.LocalName -ne 'AppLockerPolicy') { throw 'Expected AppLockerPolicy XML root' }
  return $doc
}
function RuleById($doc,[string]$id) {
  $matches=@($doc.SelectNodes('//*[@Id]') | Where-Object { $_.GetAttribute('Id').Trim('{}') -ieq $id.Trim('{}') })
  if($matches.Count -gt 1) { throw 'Duplicate AppLocker rule identity' }
  if($matches.Count -eq 0) { return $null }; return $matches[0]
}
)PS";

const std::wstring kDefender = LR"PS(
function DefenderSnapshot {
  $p=Get-MpPreference -ErrorAction Stop
  foreach($name in @('EnableControlledFolderAccess','PUAProtection','EnableNetworkProtection','DisableRealtimeMonitoring','AttackSurfaceReductionRules_Ids','AttackSurfaceReductionRules_Actions')) {
    if($null -eq $p.PSObject.Properties[$name]) { throw ('Defender property unavailable: '+$name) }
  }
  $ids=@($p.AttackSurfaceReductionRules_Ids | Where-Object { $null -ne $_ })
  $actions=@($p.AttackSurfaceReductionRules_Actions | Where-Object { $null -ne $_ })
  if($ids.Count -ne $actions.Count) { throw 'ASR id/action arrays differ in length' }
  $rules=@(for($i=0;$i -lt $ids.Count;$i++) { [ordered]@{id=[string]$ids[$i];action=[int]$actions[$i]} })
  $values=[ordered]@{controlledFolderAccess=[int]$p.EnableControlledFolderAccess;puaProtection=[int]$p.PUAProtection;networkProtection=[int]$p.EnableNetworkProtection;realTimeProtection=(-not [bool]$p.DisableRealtimeMonitoring);rules=$rules}
  $canonical=$values | ConvertTo-Json -Compress -Depth 8
  return [pscustomobject]@{hash=(HashText $canonical);values=$values;ids=$ids;actions=$actions}
}
)PS";

std::wstring assignment(const ApplicationControlRequest& request) {
    std::wstring result = L"$v=@{};";
    for (const auto& [key, value] : request.values) {
        if (key.empty() || key.size() > 32 || value.size() > 4096 ||
            !std::all_of(key.begin(),key.end(),[](wchar_t c){return (c >= L'a' && c <= L'z') || c == L'-';}))
            throw std::invalid_argument("invalid application-control input");
        result += L"$v['" + key + L"']=[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('" + encoded(value) + L"'));";
    }
    return result;
}
}

std::wstring BuildApplicationControlScript(const ApplicationControlRequest& request) {
    std::wstring body = assignment(request) + kHash;
    if (request.operation.rfind(L"applocker-",0) == 0) {
        body += kAppLocker;
        if (request.operation == L"applocker-enum") return body + LR"PS(
$xml=PolicyText $v['scope'];$doc=ReadDocument $xml
$rows=@(foreach($collection in @($doc.DocumentElement.SelectNodes('RuleCollection'))) {
  foreach($rule in @($collection.SelectNodes('*[contains(local-name(),"Rule")]'))) {
    if($v.ContainsKey('id') -and $rule.GetAttribute('Id').Trim('{}') -ine $v['id'].Trim('{}')) { continue }
    $path=$rule.SelectSingleNode('Conditions/FilePathCondition')
    [ordered]@{collection=$collection.GetAttribute('Type');enforcement=$collection.GetAttribute('EnforcementMode');id=$rule.GetAttribute('Id');type=$rule.LocalName;name=$rule.GetAttribute('Name');description=$rule.GetAttribute('Description');sid=$rule.GetAttribute('UserOrGroupSid');action=$rule.GetAttribute('Action');path=$(if($null -eq $path){$null}else{$path.GetAttribute('Path')});xml=$rule.OuterXml}
  }
})
$limit=[int]$v['limit'];$selected=@()
foreach($row in $rows) {
  if($selected.Count -ge $limit) { break }
  $candidate=@($selected)+@($row);$size=[Text.Encoding]::UTF8.GetByteCount(($candidate | ConvertTo-Json -Compress -Depth 12))
  if($size -gt 98304) { break };$selected=$candidate
}
Emit ([ordered]@{available=$true;scope=$v['scope'];policyHash=(HashText $xml);totalCount=$rows.Count;returnedCount=$selected.Count;displayTruncated=($rows.Count -gt $selected.Count);rules=$selected})
)PS";
        if (request.operation == L"applocker-export") return body + LR"PS(
$xml=PolicyText $v['scope'];[void](ReadDocument $xml);$path=$v['output']
$bytes=[Text.UTF8Encoding]::new($false).GetBytes($xml)
$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $stream.Write($bytes,0,$bytes.Length);$stream.Flush() } finally { $stream.Dispose() }
$read=[IO.File]::ReadAllText($path,[Text.Encoding]::UTF8);$verified=(HashText $read) -eq (HashText $xml)
Emit ([ordered]@{available=$true;scope=$v['scope'];path=$path;bytes=$bytes.Length;policyHash=(HashText $xml);verified=$verified})
if(-not $verified) { exit 6 }
)PS";
        const bool import = request.operation == L"applocker-import";
        const bool add = request.operation == L"applocker-add";
        const bool update = request.operation == L"applocker-update";
        const bool remove = request.operation == L"applocker-remove";
        if (!(import || add || update || remove)) throw std::invalid_argument("unknown AppLocker operation");
        body += LR"PS(
$before=PolicyText 'local';$beforeHash=HashText $before
if($beforeHash -ine $v['expected']) { Emit ([ordered]@{available=$true;changed=$false;verified=$false;reason='policy changed';beforeHash=$beforeHash});exit 6 }
$doc=ReadDocument $before
)PS";
        if (import) body += LR"PS(
$path=$v['input'];$info=Get-Item -LiteralPath $path -ErrorAction Stop
if($info.PSIsContainer -or $info.Length -gt 2097152) { throw 'Policy input must be a file of at most 2 MiB' }
$desired=[IO.File]::ReadAllText($info.FullName,[Text.Encoding]::UTF8);$next=ReadDocument $desired
$policy=$next.OuterXml;$targetId=''
)PS";
        if (add) body += LR"PS(
$collection=@($doc.DocumentElement.SelectNodes('RuleCollection') | Where-Object { $_.GetAttribute('Type') -ieq $v['collection'] })
if($collection.Count -gt 1) { throw 'Duplicate collection' }
if($collection.Count -eq 0) { $c=$doc.CreateElement('RuleCollection');$c.SetAttribute('Type',$v['collection']);$c.SetAttribute('EnforcementMode','NotConfigured');[void]$doc.DocumentElement.AppendChild($c) } else { $c=$collection[0] }
$targetId=[guid]::NewGuid().ToString('B');$r=$doc.CreateElement('FilePathRule');$r.SetAttribute('Id',$targetId)
$conditions=$doc.CreateElement('Conditions');$condition=$doc.CreateElement('FilePathCondition');[void]$conditions.AppendChild($condition);[void]$r.AppendChild($conditions);[void]$c.AppendChild($r)
)PS";
        if (update || remove) body += LR"PS(
$targetId=$v['id'];$r=RuleById $doc $targetId
if($null -eq $r) { Emit ([ordered]@{available=$true;changed=$false;verified=$false;reason='rule not found in local policy';beforeHash=$beforeHash});exit 3 }
)PS";
        if (remove) body += LR"PS(
$collection=$r.ParentNode;[void]$collection.RemoveChild($r)
if($collection.SelectNodes('*[contains(local-name(),"Rule")]').Count -eq 0) { [void]$collection.ParentNode.RemoveChild($collection) }
)PS";
        if (add || update) body += LR"PS(
if($r.LocalName -ne 'FilePathRule') { throw 'Only local FilePathRule can be edited' }
$r.SetAttribute('Name',$v['name']);$r.SetAttribute('Description',$v['description']);$r.SetAttribute('UserOrGroupSid',$v['sid']);$r.SetAttribute('Action',$v['action'])
$condition=$r.SelectSingleNode('Conditions/FilePathCondition');if($null -eq $condition) { throw 'Missing path condition' };$condition.SetAttribute('Path',$v['path'])
)PS";
        if (!import) body += L"$policy=$doc.OuterXml;\n";
        body += LR"PS(
try { Set-AppLockerPolicy -XmlPolicy $policy -ErrorAction Stop } catch { Emit ([ordered]@{available=$true;attempted=$true;changed=$null;verified=$false;beforeHash=$beforeHash;message=$_.Exception.Message});exit 6 }
try {
  $after=PolicyText 'local';$afterDoc=ReadDocument $after
  )PS";
        if (import) body += L"$verified=$afterDoc.OuterXml -ceq (ReadDocument $policy).OuterXml\n";
        else if (remove) body += L"$verified=$null -eq (RuleById $afterDoc $targetId)\n";
        else body += LR"PS(
$actual=RuleById $afterDoc $targetId
$verified=$null -ne $actual -and $actual.LocalName -eq 'FilePathRule' -and $actual.GetAttribute('Name') -ceq $v['name'] -and $actual.GetAttribute('Description') -ceq $v['description'] -and $actual.GetAttribute('UserOrGroupSid') -ceq $v['sid'] -and $actual.GetAttribute('Action') -ceq $v['action'] -and $null -ne $actual.SelectSingleNode('Conditions/FilePathCondition') -and $actual.SelectSingleNode('Conditions/FilePathCondition').GetAttribute('Path') -ceq $v['path']
)PS";
        body += LR"PS(
  Emit ([ordered]@{available=$true;attempted=$true;changed=$true;verified=[bool]$verified;beforeHash=$beforeHash;afterHash=(HashText $after);id=$targetId})
  if(-not $verified) { exit 6 }
} catch { Emit ([ordered]@{available=$true;attempted=$true;changed=$null;verified=$false;beforeHash=$beforeHash;message=$_.Exception.Message});exit 6 }
)PS";
        return body;
    }
    if (request.operation.rfind(L"defender-",0) == 0) {
        body += kDefender;
        if (request.operation == L"defender-query") return body + LR"PS(
$s=DefenderSnapshot;Emit ([ordered]@{available=$true;snapshotHash=$s.hash;settings=$s.values})
)PS";
        if (request.operation != L"defender-set" && request.operation != L"defender-asr-add" &&
            request.operation != L"defender-asr-set" && request.operation != L"defender-asr-remove")
            throw std::invalid_argument("unknown Defender operation");
        body += LR"PS(
$s=DefenderSnapshot
if($s.hash -ine $v['expected']) { Emit ([ordered]@{available=$true;attempted=$false;verified=$false;reason='settings changed';beforeHash=$s.hash});exit 6 }
)PS";
        if (request.operation == L"defender-set") body += LR"PS(
$number=[int]$v['value'];$setting=$v['setting']
try {
  switch($setting) {
    'controlled-folder' { Set-MpPreference -EnableControlledFolderAccess $number -ErrorAction Stop }
    'pua' { Set-MpPreference -PUAProtection $number -ErrorAction Stop }
    'network' { Set-MpPreference -EnableNetworkProtection $number -ErrorAction Stop }
    'realtime' { Set-MpPreference -DisableRealtimeMonitoring ($number -eq 0) -ErrorAction Stop }
    default { throw 'Unsupported setting' }
  }
} catch { Emit ([ordered]@{available=$true;attempted=$true;verified=$false;beforeHash=$s.hash;message=$_.Exception.Message});exit 6 }
try {
  $after=DefenderSnapshot
  $actual=switch($setting) {'controlled-folder' {$after.values.controlledFolderAccess};'pua' {$after.values.puaProtection};'network' {$after.values.networkProtection};'realtime' {[int]$after.values.realTimeProtection}}
  $verified=$actual -eq $number
  Emit ([ordered]@{available=$true;attempted=$true;verified=$verified;beforeHash=$s.hash;afterHash=$after.hash;setting=$setting;requested=$number;actual=$actual})
  if(-not $verified) { exit 6 }
} catch { Emit ([ordered]@{available=$true;attempted=$true;verified=$false;beforeHash=$s.hash;message=$_.Exception.Message});exit 6 }
)PS";
        else {
            body += LR"PS(
$id=$v['id'];$matches=@(for($i=0;$i -lt $s.ids.Count;$i++) { if(([string]$s.ids[$i]).Trim('{}') -ieq $id.Trim('{}')) {$i} })
if($matches.Count -gt 1) { throw 'Duplicate ASR identity' }
)PS";
            if (request.operation == L"defender-asr-add") body += L"if($matches.Count -ne 0) { throw 'ASR rule already exists' };$ids=@($s.ids)+@($id);$actions=@($s.actions)+@([int]$v['value'])\n";
            else if (request.operation == L"defender-asr-set") body += L"if($matches.Count -ne 1) { throw 'ASR rule not found' };$ids=@($s.ids);$actions=@($s.actions);$actions[$matches[0]]=[int]$v['value']\n";
            else body += L"if($matches.Count -ne 1) { throw 'ASR rule not found' };$ids=@();$actions=@();for($i=0;$i -lt $s.ids.Count;$i++) {if($i -ne $matches[0]) {$ids+=@($s.ids[$i]);$actions+=@($s.actions[$i])}}\n";
            body += LR"PS(
try { Set-MpPreference -AttackSurfaceReductionRules_Ids $ids -AttackSurfaceReductionRules_Actions $actions -ErrorAction Stop }
catch { Emit ([ordered]@{available=$true;attempted=$true;verified=$false;beforeHash=$s.hash;message=$_.Exception.Message});exit 6 }
try {
  $after=DefenderSnapshot;$matches=@(for($i=0;$i -lt $after.ids.Count;$i++) { if(([string]$after.ids[$i]).Trim('{}') -ieq $id.Trim('{}')) {$i} })
)PS";
            if (request.operation == L"defender-asr-remove") body += L"  $verified=$matches.Count -eq 0\n";
            else body += L"  $verified=$matches.Count -eq 1 -and [int]$after.actions[$matches[0]] -eq [int]$v['value']\n";
            body += LR"PS(
  Emit ([ordered]@{available=$true;attempted=$true;verified=[bool]$verified;beforeHash=$s.hash;afterHash=$after.hash;id=$id})
  if(-not $verified) { exit 6 }
} catch { Emit ([ordered]@{available=$true;attempted=$true;verified=$false;beforeHash=$s.hash;message=$_.Exception.Message});exit 6 }
)PS";
        }
        return body;
    }
    throw std::invalid_argument("unknown application-control operation");
}

CommandResult RunApplicationControl(const ApplicationControlRequest& request, DWORD timeoutMs,
                                    const ApplicationControlRunner& runner) {
    const auto script = L"try {\n" + BuildApplicationControlScript(request) + LR"PS(
} catch { [ordered]@{available=$false;exceptionType=$_.Exception.GetType().FullName;exceptionHResult=('0x{0:x8}' -f $_.Exception.HResult);errorId=$_.FullyQualifiedErrorId;message=$_.Exception.Message} | ConvertTo-Json -Compress -Depth 8; exit 3 }
)PS";
    return runner ? runner(script,timeoutMs) : RunPowerShellJson(script,timeoutMs);
}
}
