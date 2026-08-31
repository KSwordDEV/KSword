#pragma once

#include "../../Core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Service {

// ServiceProperty is one detail-pane name/value pair. Values are already
// formatted for display and are never parsed back by the view.
struct ServiceProperty {
    std::wstring name;
    std::wstring value;
};

// ServiceEntry is the model row for one SCM service. It is filled from
// ks::service::ServiceRecord, the same reusable enumeration layer the Qt build
// uses, so both products report identical facts about a service instead of
// maintaining two SCM readers that can drift apart.
struct ServiceEntry {
    std::wstring serviceName;
    std::wstring displayName;
    std::wstring description;
    std::wstring binaryPath;
    std::wstring accountName;
    std::wstring loadOrderGroup;
    std::wstring dependencies;      // Multi-sz expanded into a readable list.
    std::uint32_t serviceType = 0;
    std::uint32_t currentState = 0;
    std::uint32_t startType = 0;
    std::uint32_t errorControl = 0;
    std::uint32_t processId = 0;
    std::uint32_t controlsAccepted = 0;
    std::uint32_t win32ExitCode = 0;
    std::uint32_t serviceSpecificExitCode = 0;
    std::uint32_t checkPoint = 0;
    std::uint32_t waitHint = 0;
    std::uint32_t serviceFlags = 0;
    std::uint32_t tagId = 0;
    bool delayedAutoStart = false;
    bool hasConfig = false;
    bool hasStatus = false;
    bool hasDescription = false;
    // Direct dependency names and +load-order-group entries stay separate so
    // a detail snapshot can expose the SCM's two dependency forms without
    // asking a view to reverse-parse display text.
    std::vector<std::wstring> dependencyServiceNames;
    std::vector<std::wstring> dependencyLoadOrderGroups;
    std::wstring riskText;          // Empty when nothing stood out.
    std::wstring diagnosticText;    // Why status or config could not be read.
};

// ServiceEnumerationResult carries one full enumeration pass. A service whose
// config could not be read is still returned with its diagnostic text attached:
// dropping it would hide exactly the services an audit cares about, since an
// unreadable config is usually a permission or tampering signal.
struct ServiceEnumerationResult {
    bool success = false;
    std::wstring diagnosticText;
    std::vector<ServiceEntry> entries;
};

// ServiceSortMode orders the table. Name order is the default; the other two
// float the rows an operator usually opens this page to look at.
enum class ServiceSortMode {
    NameAscending,
    RunningFirst,
    AutoStartFirst
};

// ServiceModel stores the latest snapshot and prepares display text. Inputs are
// entry vectors; processing sorts them by the active mode; outputs stay valid
// until the next setEntries call.
class ServiceModel final {
public:
    ServiceModel() = default;

    // setEntries replaces the snapshot and re-sorts it by the active mode.
    void setEntries(std::vector<ServiceEntry> entries);

    // setSortMode changes the order and re-sorts the current snapshot.
    void setSortMode(ServiceSortMode mode);

    ServiceSortMode sortMode() const noexcept;

    const std::vector<ServiceEntry>& entries() const noexcept;

    // entryAt validates a row index; output is nullptr when out of range.
    const ServiceEntry* entryAt(int index) const;

    // textForColumn returns list text for one entry. Columns are service name,
    // display name, state, start type, PID, account and risk.
    std::wstring textForColumn(const ServiceEntry& entry, int column) const;

    // propertiesForEntry expands one entry into the detail pane rows.
    std::vector<ServiceProperty> propertiesForEntry(const ServiceEntry& entry) const;

private:
    void sortEntries();

private:
    std::vector<ServiceEntry> entries_;
    ServiceSortMode sortMode_ = ServiceSortMode::NameAscending;
};

// ServiceStateText formats SERVICE_STATUS::dwCurrentState for display.
std::wstring ServiceStateText(std::uint32_t currentState);

// ServiceStartTypeText formats the start type, folding the delayed-auto flag
// into the "自动" wording because the SCM reports it as a separate bit while
// users think of it as one setting.
std::wstring ServiceStartTypeText(std::uint32_t startType, bool delayedAutoStart);

// ServiceTypeText formats the service type bitmask (own/shared process, kernel
// driver, file system driver, interactive).
std::wstring ServiceTypeText(std::uint32_t serviceType);

// ServicePropertiesForEntry expands a service's base SCM snapshot into stable
// name/value rows. The rows are suitable for a native detail list and TSV
// export; callers never need to parse their display values back into fields.
std::vector<ServiceProperty> ServicePropertiesForEntry(const ServiceEntry& entry);

// ServiceCanStart / ServiceCanStop / ServiceCanPause / ServiceCanContinue report
// whether a transition is legal right now. They read the accepted-controls mask
// rather than guessing from the state alone, because plenty of services simply
// do not implement pause even while running.
bool ServiceCanStart(const ServiceEntry& entry);
bool ServiceCanStop(const ServiceEntry& entry);
bool ServiceCanPause(const ServiceEntry& entry);
bool ServiceCanContinue(const ServiceEntry& entry);

// ServiceIsTransitioning reports a pending state change. Acting on a service
// mid-transition produces confusing SCM errors, so the view blocks it instead.
bool ServiceIsTransitioning(const ServiceEntry& entry);

} // namespace Ksword::Features::Service
