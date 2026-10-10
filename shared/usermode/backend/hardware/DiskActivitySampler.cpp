#include "PerformanceSamplerSupport.h"
#include <algorithm>
#include <map>
namespace ks::r3::hardware_stats {
using namespace detail;
void PerformanceSampler::collectDiskRows(PerformanceSnapshot& snapshot) {
    static const wchar_t* ids[] = {L"readBytesPerSecond",L"writeBytesPerSecond",L"readsPerSecond",L"writesPerSecond",L"currentQueueLength",L"averageQueueLength",L"busyPercent",L"readLatencySeconds",L"writeLatencySeconds"};
    static_assert(std::size(ids) == static_cast<std::size_t>(DiskCounterId::Count));
    std::map<std::wstring,std::pair<PerformanceEvidence,std::vector<std::pair<std::wstring,double>>>> fields;
    const auto readValues = [this,&snapshot,&fields](const DiskCounterId id, const bool uncapped) {
        const std::size_t index = static_cast<std::size_t>(id);
        PerformanceEvidence e;std::vector<std::pair<std::wstring,double>> values;
        if (index >= impl_->diskCounters.size() || !impl_->diskCounters[index].available) {
            e.statusKnown = index < impl_->diskCounters.size();if (e.statusKnown) e.status = impl_->diskCounters[index].addStatus;
        } else values = ReadArray(impl_->diskCounters[index].handle, uncapped,&e);
        fields[ids[index]] = {e,values};
        const auto path = index < impl_->diskCounters.size() && impl_->diskCounters[index].available ? impl_->diskCounters[index].resolvedPath : DiskCounterPaths()[index];
        snapshot.sources.push_back({ids[index],path,e,L"disk"});return values;
    };

    std::map<std::wstring, DiskActivityRow> rows;
    const auto merge = [&rows](const std::vector<std::pair<std::wstring, double>>& values,
                           double DiskActivityRow::*field) {
        for (const auto& item : values) {
            if (item.first.empty()) {
                continue;
            }
            DiskActivityRow& row = rows[item.first];
            row.instance = item.first;
            row.*field = item.second;
        }
    };

    merge(readValues(DiskCounterId::ReadBytes, false), &DiskActivityRow::readBytesPerSecond);
    merge(readValues(DiskCounterId::WriteBytes, false), &DiskActivityRow::writeBytesPerSecond);
    merge(readValues(DiskCounterId::Reads, false), &DiskActivityRow::readsPerSecond);
    merge(readValues(DiskCounterId::Writes, false), &DiskActivityRow::writesPerSecond);
    merge(readValues(DiskCounterId::CurrentQueue, false), &DiskActivityRow::currentQueueLength);
    merge(readValues(DiskCounterId::AverageQueue, false), &DiskActivityRow::averageQueueLength);
    // A RAID set or a disk with several outstanding requests genuinely exceeds
    // 100 % busy time, and capping it would hide the busiest spindles.
    merge(readValues(DiskCounterId::BusyPercent, true), &DiskActivityRow::busyPercent);
    merge(readValues(DiskCounterId::ReadLatency, false), &DiskActivityRow::readLatencySeconds);
    merge(readValues(DiskCounterId::WriteLatency, false), &DiskActivityRow::writeLatencySeconds);

    snapshot.disks.reserve(rows.size());
    for (auto& entry : rows) {
        for (const auto& [id,field]:fields) {
            auto e = field.first;
            e.available = std::any_of(field.second.begin(),field.second.end(),[&](const auto& value){return value.first == entry.first;});
            if (!e.available) e.complete = false;
            entry.second.evidence[id] = e;
        }
        snapshot.disks.push_back(std::move(entry.second));
    }
    std::sort(snapshot.disks.begin(), snapshot.disks.end(),
        [](const DiskActivityRow& left, const DiskActivityRow& right) {
            // "_Total" is the summary line and belongs at the top rather than
            // sorted in among the physical spindles by name.
            const bool leftTotal = left.instance.find(L"_Total") != std::wstring::npos;
            const bool rightTotal = right.instance.find(L"_Total") != std::wstring::npos;
            if (leftTotal != rightTotal) {
                return leftTotal;
            }
            return CompareInstanceNames(left.instance, right.instance);
        });
}
}
