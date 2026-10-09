#pragma once

#include "../../../shared/usermode/backend/service/ServiceTypes.h"

#include "../../Core/Win32Lean.h"

#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Service {
using ks::r3::service::ServiceProperty;
using ks::r3::service::ServiceEntry;
using ks::r3::service::ServiceEnumerationResult;


// ServiceProperty is one detail-pane name/value pair. Values are already
// formatted for display and are never parsed back by the view.


// ServiceEntry is the model row for one SCM service. It is filled from
// ks::service::ServiceRecord, the same reusable enumeration layer the Qt build
// uses, so both products report identical facts about a service instead of
// maintaining two SCM readers that can drift apart.


// ServiceEnumerationResult carries one full enumeration pass. A service whose
// config could not be read is still returned with its diagnostic text attached:
// dropping it would hide exactly the services an audit cares about, since an
// unreadable config is usually a permission or tampering signal.


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
using ks::r3::service::ServiceStateText;

// ServiceStartTypeText formats the start type, folding the delayed-auto flag
// into the "自动" wording because the SCM reports it as a separate bit while
// users think of it as one setting.
using ks::r3::service::ServiceStartTypeText;

// ServiceTypeText formats the service type bitmask (own/shared process, kernel
// driver, file system driver, interactive).
using ks::r3::service::ServiceTypeText;

// ServicePropertiesForEntry expands a service's base SCM snapshot into stable
// name/value rows. The rows are suitable for a native detail list and TSV
// export; callers never need to parse their display values back into fields.
using ks::r3::service::ServicePropertiesForEntry;

// ServiceCanStart / ServiceCanStop / ServiceCanPause / ServiceCanContinue report
// whether a transition is legal right now. They read the accepted-controls mask
// rather than guessing from the state alone, because plenty of services simply
// do not implement pause even while running.
using ks::r3::service::ServiceCanStart;
using ks::r3::service::ServiceCanStop;
using ks::r3::service::ServiceCanPause;
using ks::r3::service::ServiceCanContinue;

// ServiceIsTransitioning reports a pending state change. Acting on a service
// mid-transition produces confusing SCM errors, so the view blocks it instead.
using ks::r3::service::ServiceIsTransitioning;

} // namespace Ksword::Features::Service
