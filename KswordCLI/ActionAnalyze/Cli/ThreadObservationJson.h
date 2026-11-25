#pragma once

#include "../Memory/PassiveThreadObservation.h"
#include "../../CommandRegistry.h"

namespace ks::cli::action_analyze {

// watch、track 和 stream 使用相同的线程字段、状态词及 FILETIME 编码。
inline Json ThreadObservationJson(const memory::ThreadObservation& observation)
{
    const wchar_t* snapshotStatus = L"unknown";
    switch (observation.status) {
    case memory::ThreadSnapshotStatus::Unknown: break;
    case memory::ThreadSnapshotStatus::TargetExited: snapshotStatus = L"target-exited"; break;
    case memory::ThreadSnapshotStatus::Limited: snapshotStatus = L"limited"; break;
    case memory::ThreadSnapshotStatus::Complete: snapshotStatus = L"complete"; break;
    }

    std::vector<Json> events;
    events.reserve(observation.events.size());
    for (const auto& event : observation.events) {
        const wchar_t* status = L"unknown";
        switch (event.status) {
        case memory::ThreadEventStatus::Unknown: break;
        case memory::ThreadEventStatus::Observed: status = L"observed"; break;
        case memory::ThreadEventStatus::NewlyObserved: status = L"newly-observed"; break;
        case memory::ThreadEventStatus::Exited: status = L"exited"; break;
        }
        events.push_back(Json::object({{L"tid", Json::number(event.tid)},
            {L"creationTime100ns", event.creationTime100ns ? Json::count(event.creationTime100ns) : Json{}},
            {L"status", Json::string(status)}, {L"win32Error", event.win32Error ? Json::number(event.win32Error) : Json{}}}));
    }
    return Json::object({{L"snapshotStatus", Json::string(snapshotStatus)},
        {L"win32Error", Json::number(observation.win32Error)},
        {L"snapshotStartUtc100ns", observation.snapshotStartUtc100ns ? Json::count(observation.snapshotStartUtc100ns) : Json{}},
        {L"snapshotEndUtc100ns", observation.snapshotEndUtc100ns ? Json::count(observation.snapshotEndUtc100ns) : Json{}},
        {L"readbackEndUtc100ns", Json::count(observation.readbackEndUtc100ns)},
        {L"listedThreadCount", observation.listedThreadCount ? Json::count(*observation.listedThreadCount) : Json{}},
        {L"events", Json::array(events)}});
}

} // namespace ks::cli::action_analyze
