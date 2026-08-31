#pragma once

#include "../../Core/Win32Lean.h"

#include <string>
#include <vector>

namespace Ksword::Features::Startup {

// StartupEntryKind identifies the startup surface that produced one row. Inputs
// come from StartupEnumerator; consumers use this only for display and for
// routing actions through StartupActions.
enum class StartupEntryKind {
    RegistryRun,
    RegistryRunOnce,
    StartupFolder,
    Service,
    // DriverService represents a kernel or file-system driver reported by SCM.
    // These rows are investigation-only: StartupActions deliberately rejects all
    // mutation and Shell-open requests for this kind.
    DriverService,
    // RegistryOnlyService represents a Services-registry record that this SCM
    // enumeration did not return. It is an observation-only source mismatch,
    // not a hidden-service verdict, and all StartupActions reject it.
    RegistryOnlyService,
    ScheduledTaskFacade
};

// StartupEntryScope describes whether an entry belongs to the current user or
// all users / local machine. Inputs are registry root, known folder, service, or
// scheduled-task location; output text is produced by StartupScopeText.
enum class StartupEntryScope {
    CurrentUser,
    LocalMachine,
    AllUsers,
    Unknown
};

// StartupEntryState describes whether an entry is active startup data, disabled
// data preserved by this module, or an informational facade row.
enum class StartupEntryState {
    Active,
    Disabled,
    Manual,
    Unknown
};

// StartupProperty is one detail-pane name/value pair. Inputs are collected from
// registry, filesystem, service control manager, or scheduled-task facade rows;
// values are formatted for display and are not parsed by the view.
struct StartupProperty {
    std::wstring name;
    std::wstring value;
};

// StartupEntry is the shared model row for all startup surfaces. Inputs are
// produced by StartupEnumerator; processing in StartupActions uses the routing
// fields relevant to the entry kind and ignores unrelated fields.
struct StartupEntry {
    StartupEntryKind kind = StartupEntryKind::RegistryRun;
    StartupEntryScope scope = StartupEntryScope::Unknown;
    StartupEntryState state = StartupEntryState::Unknown;
    std::wstring name;
    std::wstring command;
    std::wstring location;
    std::wstring description;
    std::wstring publisher;
    HKEY registryRoot = nullptr;
    DWORD registryView = 0;
    std::wstring registrySubKey;
    std::wstring registryValueName;
    std::wstring disabledRegistrySubKey;
    std::wstring filePath;
    std::wstring disabledFilePath;
    std::wstring serviceName;
    DWORD serviceStartType = 0;
    std::wstring taskPath;
    std::vector<StartupProperty> properties;
};

// StartupEnumerationResult contains one full startup enumeration pass. success
// remains true when one surface fails and the diagnostic is carried as a row;
// fatal setup failures return success=false.
struct StartupEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<StartupEntry> entries;
};

// StartupModel stores the latest startup rows and prepares display/detail text.
// Inputs are StartupEntry vectors; processing sorts by kind/scope/name; outputs
// remain valid until the next setEntries call.
class StartupModel final {
public:
    StartupModel();

    // setEntries replaces the current startup snapshot. Input rows are copied
    // into the model; processing sorts them for stable UI display; no return.
    void setEntries(std::vector<StartupEntry> entries);

    // entries returns the current startup rows. There is no input; output is a
    // const reference valid until setEntries is called again.
    const std::vector<StartupEntry>& entries() const;

    // entryAt validates a row index. Input is a model index; output is nullptr
    // when the index is outside the current snapshot.
    const StartupEntry* entryAt(int index) const;

    // textForColumn returns list-view text for one entry. Inputs are entry and
    // zero-based column index; output is empty for unsupported columns.
    std::wstring textForColumn(const StartupEntry& entry, int column) const;

    // propertiesForEntry returns complete detail rows for one entry. Input is a
    // startup entry; output combines common fields and enumerator-specific rows.
    std::vector<StartupProperty> propertiesForEntry(const StartupEntry& entry) const;

private:
    // entries_ stores the current startup snapshot after setEntries sorts and
    // replaces it. Inputs are copied StartupEntry rows; readers receive const
    // references or pointers, and there is no direct external mutation path.
    std::vector<StartupEntry> entries_;
};

// StartupKindText formats a startup kind for display. Input is an enum value;
// output is a stable user-facing label.
std::wstring StartupKindText(StartupEntryKind kind);

// StartupScopeText formats a scope for display. Input is an enum value; output is
// a stable user-facing label.
std::wstring StartupScopeText(StartupEntryScope scope);

// StartupStateText formats a state for display. Input is an enum value; output is
// a stable user-facing label.
std::wstring StartupStateText(StartupEntryState state);

} // namespace Ksword::Features::Startup
