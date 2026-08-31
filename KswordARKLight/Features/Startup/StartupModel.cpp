#include "StartupModel.h"

#include <algorithm>
#include <utility>

namespace Ksword::Features::Startup {
namespace {

// AddProperty appends a detail row when the value exists. Inputs are target list,
// label and value; processing filters empty values; no return.
void AddProperty(std::vector<StartupProperty>& properties, const std::wstring& name, const std::wstring& value) {
    if (!value.empty()) {
        properties.push_back({ name, value });
    }
}

} // namespace

StartupModel::StartupModel() = default;

void StartupModel::setEntries(std::vector<StartupEntry> entries) {
    std::sort(entries.begin(), entries.end(), [](const StartupEntry& left, const StartupEntry& right) {
        if (left.kind != right.kind) {
            return static_cast<int>(left.kind) < static_cast<int>(right.kind);
        }
        if (left.scope != right.scope) {
            return static_cast<int>(left.scope) < static_cast<int>(right.scope);
        }
        return left.name < right.name;
    });
    entries_ = std::move(entries);
}

const std::vector<StartupEntry>& StartupModel::entries() const {
    return entries_;
}

const StartupEntry* StartupModel::entryAt(int index) const {
    if (index < 0 || index >= static_cast<int>(entries_.size())) {
        return nullptr;
    }
    return &entries_[index];
}

std::wstring StartupModel::textForColumn(const StartupEntry& entry, int column) const {
    switch (column) {
    case 0:
        return entry.name;
    case 1:
        return StartupKindText(entry.kind);
    case 2:
        return StartupScopeText(entry.scope);
    case 3:
        return StartupStateText(entry.state);
    case 4:
        return entry.command;
    case 5:
        return entry.location;
    default:
        break;
    }
    return {};
}

std::vector<StartupProperty> StartupModel::propertiesForEntry(const StartupEntry& entry) const {
    std::vector<StartupProperty> properties;
    AddProperty(properties, L"Kind", StartupKindText(entry.kind));
    AddProperty(properties, L"Name", entry.name);
    AddProperty(properties, L"Scope", StartupScopeText(entry.scope));
    AddProperty(properties, L"State", StartupStateText(entry.state));
    AddProperty(properties, L"Command", entry.command);
    AddProperty(properties, L"Location", entry.location);
    AddProperty(properties, L"Description", entry.description);
    AddProperty(properties, L"Publisher", entry.publisher);
    for (const StartupProperty& property : entry.properties) {
        AddProperty(properties, property.name, property.value);
    }
    return properties;
}

std::wstring StartupKindText(StartupEntryKind kind) {
    switch (kind) {
    case StartupEntryKind::RegistryRun:
        return L"Registry Run";
    case StartupEntryKind::RegistryRunOnce:
        return L"Registry RunOnce";
    case StartupEntryKind::StartupFolder:
        return L"Startup Folder";
    case StartupEntryKind::Service:
        return L"Service";
    case StartupEntryKind::DriverService:
        return L"Driver Service (read-only)";
    case StartupEntryKind::RegistryOnlyService:
        return L"Registry-observed Service (read-only)";
    case StartupEntryKind::ScheduledTaskFacade:
        return L"Scheduled Task";
    default:
        break;
    }
    return L"Unknown";
}

std::wstring StartupScopeText(StartupEntryScope scope) {
    switch (scope) {
    case StartupEntryScope::CurrentUser:
        return L"Current user";
    case StartupEntryScope::LocalMachine:
        return L"Local machine";
    case StartupEntryScope::AllUsers:
        return L"All users";
    default:
        break;
    }
    return L"Unknown";
}

std::wstring StartupStateText(StartupEntryState state) {
    switch (state) {
    case StartupEntryState::Active:
        return L"Active";
    case StartupEntryState::Disabled:
        return L"Disabled";
    case StartupEntryState::Manual:
        return L"Manual";
    default:
        break;
    }
    return L"Unknown";
}

} // namespace Ksword::Features::Startup
