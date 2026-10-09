#pragma once

#include "../Win32.h"

#include <cstdint>
#include <string>
#include <vector>

namespace ks::r3::system_tools {

// EventLogChannel is the closed set of channels this page reads. Security is
// deliberately absent: it needs SeSecurityPrivilege and an audit policy to be
// meaningful, and a page that silently returns nothing would look like a bug.
enum class EventLogChannel {
    System,
    Application
};

// EventLogLevelFilter is pushed into the query itself rather than applied after
// reading. The channel holds hundreds of thousands of records, so filtering in
// the reader would mean discarding almost everything it just paid to render.
enum class EventLogLevelFilter {
    All,
    Critical,
    Error,
    Warning,
    Information
};

// EventLogEntry is one rendered record. Text fields are already display-ready.
struct EventLogEntry {
    std::wstring timeText;
    std::uint8_t level = 0;
    std::wstring levelText;
    std::wstring providerName;
    std::uint32_t eventId = 0;
    std::uint64_t recordId = 0;
    std::uint32_t processId = 0;
    std::wstring computer;
    std::wstring message;
};

// EventLogQueryRequest describes one read pass.
struct EventLogQueryRequest {
    EventLogChannel channel = EventLogChannel::System;
    EventLogLevelFilter level = EventLogLevelFilter::All;
    std::uint32_t maxCount = 500;
};

// EventLogQueryResult carries the newest records first.
struct EventLogQueryResult {
    bool success = false;
    std::wstring diagnosticText;
    std::wstring channelPath;
    std::uint32_t elapsedMs = 0;
    std::uint32_t unresolvedMessages = 0;  // Records whose provider had no message table.
    std::vector<EventLogEntry> entries;
};

// QueryEventLog reads one channel through wevtapi. Input is the request;
// processing runs EvtQuery/EvtNext/EvtRender and resolves each message through
// cached publisher metadata; output is newest-first records plus diagnostics.
//
// Message formatting dominates the cost of this call, so it blocks for a
// noticeable time and must only be called from a worker thread.
EventLogQueryResult QueryEventLog(const EventLogQueryRequest& request);

// EventLogChannelPath maps the channel enum onto its wevtapi path.
std::wstring EventLogChannelPath(EventLogChannel channel);

} // namespace ks::r3::system_tools
