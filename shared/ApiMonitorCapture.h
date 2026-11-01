#pragma once
#include "ApiMonitorCoverage.h"
#include <deque>
#include <map>
#include <memory>

namespace ks::winapi_monitor {
// Value-only, Qt-free controller. Injection, leases and wire decoding are the
// same implementations used by WinAPIDock; callers own output and cancellation.
struct CaptureRequest {
    DWORD pid = 0;
    std::wstring agentPath;
    DWORD durationMs = 1000, startupTimeoutMs = 30000, stopTimeoutMs = 15000;
    std::size_t eventLimit = 5000;
    bool autoChildren = false;
    std::map<std::wstring, std::wstring> options;
};
struct CaptureProcess {
    DWORD pid = 0, pipeError = 0;
    std::uint64_t creation = 0, session = 0, revision = 0, agentDropped = 0;
    bool connected = false, installed = false, removed = false, exited = false;
    bool installFailed = false, partialHooks = false, coverageComplete = false, coverageStale = true;
    std::vector<ApiMonitorEventPacket> coverage;
};
struct CaptureResult {
    int code = 3;
    std::wstring sessionId, agentPath, configPath, stopPath;
    std::vector<std::wstring> errors;
    bool configPublished = false, reusedResident = false, cancelled = false;
    bool completedInterval = false, stopWritten = false, cleanupComplete = false;
    std::uint64_t elapsedMs = 0, received = 0, bufferDropped = 0, invalidPackets = 0;
    std::deque<ApiMonitorEventPacket> events;
    std::vector<CaptureProcess> processes;
};
CaptureResult captureApiMonitor(const CaptureRequest& request, const std::atomic_bool& cancel);
}
