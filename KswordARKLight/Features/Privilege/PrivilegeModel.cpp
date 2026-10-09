#include "PrivilegeModel.h"

#include <algorithm>

namespace Ksword::Features::Privilege {


void PrivilegeModel::setSnapshot(PrivilegeSnapshot snapshot) {
    snapshot_ = std::move(snapshot);
    // Enabled privileges sort to the top: what the process can do right now is
    // the question this page exists to answer.
    std::stable_sort(snapshot_.privileges.begin(), snapshot_.privileges.end(),
        [](const PrivilegeEntry& left, const PrivilegeEntry& right) {
            if (left.enabled != right.enabled) {
                return left.enabled;
            }
            const bool leftRisky = !left.riskText.empty();
            const bool rightRisky = !right.riskText.empty();
            if (leftRisky != rightRisky) {
                return leftRisky;
            }
            return left.name < right.name;
        });
}

const std::vector<PrivilegeEntry>& PrivilegeModel::privileges() const noexcept {
    return snapshot_.privileges;
}

const TokenSummary& PrivilegeModel::token() const noexcept {
    return snapshot_.token;
}

const PrivilegeEntry* PrivilegeModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= snapshot_.privileges.size()) {
        return nullptr;
    }
    return &snapshot_.privileges[static_cast<std::size_t>(index)];
}

std::wstring PrivilegeModel::textForColumn(const PrivilegeEntry& entry, const int column) const {
    switch (column) {
    case 0:
        return entry.name;
    case 1:
        return entry.displayName;
    case 2:
        return PrivilegeStateText(entry);
    case 3:
        return entry.riskText;
    default:
        return {};
    }
}

std::vector<PrivilegeProperty> PrivilegeModel::propertiesForEntry(const PrivilegeEntry& entry) const {
    std::vector<PrivilegeProperty> properties;
    properties.push_back({ L"常量名", entry.name });
    properties.push_back({ L"显示名", entry.displayName.empty() ? L"-" : entry.displayName });
    properties.push_back({ L"状态", PrivilegeStateText(entry) });
    properties.push_back({ L"默认启用", entry.enabledByDefault ? L"是" : L"否" });
    properties.push_back({ L"已移除", entry.removed ? L"是（本令牌生命周期内不可再启用）" : L"否" });
    properties.push_back({ L"LUID",
        std::to_wstring(entry.luid.HighPart) + L":" + std::to_wstring(entry.luid.LowPart) });
    properties.push_back({ L"作用", entry.description.empty() ? L"（本表未收录该权限的说明）" : entry.description });
    if (!entry.riskText.empty()) {
        properties.push_back({ L"风险", entry.riskText });
    }
    return properties;
}

std::vector<PrivilegeProperty> PrivilegeModel::tokenProperties() const {
    std::vector<PrivilegeProperty> properties;
    properties.push_back({ L"用户", snapshot_.token.userName.empty() ? L"-" : snapshot_.token.userName });
    properties.push_back({ L"SID", snapshot_.token.userSid.empty() ? L"-" : snapshot_.token.userSid });
    properties.push_back({ L"完整性级别", snapshot_.token.integrityLevel.empty() ? L"-" : snapshot_.token.integrityLevel });
    properties.push_back({ L"令牌类型", snapshot_.token.tokenType.empty() ? L"-" : snapshot_.token.tokenType });
    properties.push_back({ L"已提升", snapshot_.token.elevated ? L"是" : L"否" });
    properties.push_back({ L"UIAccess", snapshot_.token.uiAccess ? L"是" : L"否" });
    properties.push_back({ L"权限条目数", std::to_wstring(snapshot_.privileges.size()) });
    for (const std::wstring& group : snapshot_.token.groups) {
        properties.push_back({ L"组", group });
    }
    if (!snapshot_.diagnosticText.empty()) {
        properties.push_back({ L"采集说明", snapshot_.diagnosticText });
    }
    return properties;
}







} // namespace Ksword::Features::Privilege
