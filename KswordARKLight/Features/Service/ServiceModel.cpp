#include "ServiceModel.h"

#include <algorithm>
#include <cwctype>

namespace Ksword::Features::Service {
namespace {

std::wstring LowerText(std::wstring value) {
    std::transform(value.begin(), value.end(), value.begin(), [](const wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return value;
}

// StatePriority ranks states for the "running first" order. Running services
// come first, then the ones in mid-transition (which are what an operator is
// usually waiting on), then everything stopped.
int StatePriority(const std::uint32_t currentState) {
    switch (currentState) {
    case SERVICE_RUNNING:
        return 0;
    case SERVICE_START_PENDING:
    case SERVICE_STOP_PENDING:
    case SERVICE_CONTINUE_PENDING:
    case SERVICE_PAUSE_PENDING:
        return 1;
    case SERVICE_PAUSED:
        return 2;
    default:
        return 3;
    }
}

// StartTypePriority ranks start types so the ones that run without anyone
// asking sort to the top.
int StartTypePriority(const std::uint32_t startType) {
    switch (startType) {
    case SERVICE_BOOT_START:
        return 0;
    case SERVICE_SYSTEM_START:
        return 1;
    case SERVICE_AUTO_START:
        return 2;
    case SERVICE_DEMAND_START:
        return 3;
    default:
        return 4;
    }
}





} // namespace

void ServiceModel::setEntries(std::vector<ServiceEntry> entries) {
    entries_ = std::move(entries);
    sortEntries();
}

void ServiceModel::setSortMode(const ServiceSortMode mode) {
    sortMode_ = mode;
    sortEntries();
}

ServiceSortMode ServiceModel::sortMode() const noexcept {
    return sortMode_;
}

const std::vector<ServiceEntry>& ServiceModel::entries() const noexcept {
    return entries_;
}

const ServiceEntry* ServiceModel::entryAt(const int index) const {
    if (index < 0 || static_cast<std::size_t>(index) >= entries_.size()) {
        return nullptr;
    }
    return &entries_[static_cast<std::size_t>(index)];
}

void ServiceModel::sortEntries() {
    // Every mode falls back to the service name so the order is total: without
    // that tie-break, two refreshes of the same machine can hand back rows in
    // different positions and the table appears to shuffle on its own.
    const auto byName = [](const ServiceEntry& left, const ServiceEntry& right) {
        return LowerText(left.serviceName) < LowerText(right.serviceName);
    };
    switch (sortMode_) {
    case ServiceSortMode::RunningFirst:
        std::stable_sort(entries_.begin(), entries_.end(), [&byName](const ServiceEntry& left, const ServiceEntry& right) {
            const int leftRank = StatePriority(left.currentState);
            const int rightRank = StatePriority(right.currentState);
            return leftRank != rightRank ? leftRank < rightRank : byName(left, right);
        });
        break;
    case ServiceSortMode::AutoStartFirst:
        std::stable_sort(entries_.begin(), entries_.end(), [&byName](const ServiceEntry& left, const ServiceEntry& right) {
            const int leftRank = StartTypePriority(left.startType);
            const int rightRank = StartTypePriority(right.startType);
            return leftRank != rightRank ? leftRank < rightRank : byName(left, right);
        });
        break;
    case ServiceSortMode::NameAscending:
    default:
        std::stable_sort(entries_.begin(), entries_.end(), byName);
        break;
    }
}

std::wstring ServiceModel::textForColumn(const ServiceEntry& entry, const int column) const {
    switch (column) {
    case 0:
        return entry.serviceName;
    case 1:
        return entry.displayName;
    case 2:
        return entry.hasStatus ? ServiceStateText(entry.currentState) : L"未知";
    case 3:
        return entry.hasConfig ? ServiceStartTypeText(entry.startType, entry.delayedAutoStart) : L"未知";
    case 4:
        // A stopped service has no process, and printing 0 would read as a real
        // PID rather than as "not running".
        return entry.processId != 0 ? std::to_wstring(entry.processId) : L"-";
    case 5:
        return entry.accountName;
    case 6:
        return entry.riskText;
    default:
        return {};
    }
}

std::vector<ServiceProperty> ServiceModel::propertiesForEntry(const ServiceEntry& entry) const {
    return ServicePropertiesForEntry(entry);
}



















} // namespace Ksword::Features::Service
