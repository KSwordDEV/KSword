#pragma once

// Session ownership is independent of every QWidget. The GUI freezes a request
// and polls values; readers, injection and retained cleanup never enter Qt UI.
#include "WinApiMonitorProtocol.h"
#include "../../../shared/ApiMonitorCoverage.h"
#include "../../../shared/ApiMonitorInjectionBroker.h"
#include "WinAPIFilterRules.h"
#include <QString>
#include <QStringList>
#include <atomic>
#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>
class WinAPIDiskArchive;

struct WinAPIEventRow
{
    QString time100nsText, categoryText, apiText, resultText, pidTidText, detailText, agentStatus;
    std::uint64_t timestamp100ns = 0; // Original FILETIME; zero means absent/legacy.
    std::uint32_t categoryCode = static_cast<std::uint32_t>(ks::winapi_monitor::EventCategory::Unknown);
    std::uint32_t sourcePid = 0;
    std::uint32_t eventKindCode = 0; // ApiCall/IoSubmit/IoWait/IoComplete/IoCancel.
    std::uint64_t sourceCreationTime100ns = 0; // Verified pipe server and process identity; 0 means unknown.
    QString sourceProcessName; // Captured at verified connection, shared across its events.
    QString capturedReturnValue; // Explicit marked return bits; empty means not captured.
    QString capturedCallStack; // Bounded addresses captured on the hook thread; may contain internal frames.
    std::uint64_t duration100ns = 0;
    bool durationCaptured = false; // Zero is a valid measured duration.
    bool resultKnown = true, internalEvent = false;
};
inline QStringList WinAPIEventFields(const WinAPIEventRow& row)
{
    return {row.time100nsText, row.categoryText, row.apiText, row.resultText, row.pidTidText, row.detailText};
}
// The first received non-internal event is the stable session reference.
// This is wall-clock time; later or cross-process events can precede it.
inline std::uint64_t FirstWinAPIEventTime(std::uint64_t first, const WinAPIEventRow& row)
{
    if (first || row.internalEvent) return first;
    if (row.timestamp100ns) return row.timestamp100ns;
    bool valid = false; const auto ticks = row.time100nsText.toULongLong(&valid);
    return valid && ticks ? ticks : 0;
}
struct WinAPIEventRecord
{
    WinAPIEventRow value;
    QString searchText;
    std::uint64_t generation = 0, sequence = 0;
    std::uint64_t sessionBase100ns = 0; // First observed business event; 0 means not established.
};
using WinAPIEventRef = std::shared_ptr<const WinAPIEventRecord>;
struct WinAPICoverageDisplayRow { QStringList columns; QString searchText; };
struct WinAPICoverageViewState
{
    std::uint64_t session = 0, revision = 0;
    bool stale = true, complete = false;
    std::vector<ks::winapi_monitor::ApiMonitorEventPacket> rows;
    std::shared_ptr<const std::vector<WinAPICoverageDisplayRow>> displayRows;
};
struct WinAPISessionConfig
{
    std::uint32_t pid = 0, residentPid = 0;
    std::uint64_t generation = 0, residentCreation = 0;
    QString requestedAgentPath, sessionId, options, archiveDirectory;
    bool autoInjectChildren = false, stopOnly = false, useR0Injection = false;
};

struct WinAPISessionBackend final : std::enable_shared_from_this<WinAPISessionBackend>
{
    using EventRow = WinAPIEventRow;
    using CoverageDisplayRow = WinAPICoverageDisplayRow;
    using CoverageViewState = WinAPICoverageViewState;
    struct Reader
    {
        std::uint32_t pid = 0;
        std::uint64_t creation = 0, session = 0;
        // Set by the reader only after the matching control packet/EOF.
        std::atomic_bool connectedOnce{false}, finished{false}, removed{false}, finalCoverageComplete{false};
        std::atomic_uint64_t requiredFinalRevision{0};
        ks::winapi_monitor::SessionLease lease;
        std::unique_ptr<std::thread> thread;
    };
    explicit WinAPISessionBackend(WinAPISessionConfig value) : config(std::move(value)) {}
    ~WinAPISessionBackend();
    const WinAPISessionConfig config;
    std::shared_ptr<WinAPIDiskArchive> diskArchive;
    // The same gate serializes accepted startup and final cleanup. stop is set
    // before taking the gate, so a close that wins first permanently bars Start.
    std::mutex operationGate;
    std::atomic_bool stop{ false }, connected{ false }, startupTerminal{ false };
    // Stop requests initiate Agent shutdown; forceReadStop is reserved for a
    // bounded drain timeout. Separating them preserves tail packets on Stop.
    std::atomic_bool forceReadStop{ false }, drainIncomplete{ false };
    std::atomic_uint64_t invalidPackets{0}, prefilteredPackets{0}, pausedDropped{0};
    std::atomic_bool eventsPaused{false}, pauseRequested{false}, pauseControlReady{false}, pauseConfirmed{false};
    void setEventsPaused(bool paused) noexcept;
    std::atomic<DWORD> pauseControlError{0};
    std::atomic_bool startupSucceeded{ false }, cleanupComplete{ false }, rootEnded{ false };
    std::atomic_bool reusedResident{ false };
    std::mutex cancelMutex;
    HANDLE cancelEvent = nullptr, targetProcess = nullptr, pauseEvent = nullptr;
    QString pauseEventName;
    std::uint64_t creation = 0;
    bool configPublished = false;
    QString selectedAgentPath, configPath, stopPath, startupError, cleanupError;
    std::unique_ptr<ks::winapi_monitor::InjectionBroker> broker;
    ks::winapi_monitor::SessionLease lease;
    std::mutex readerMutex;
    std::vector<std::shared_ptr<Reader>> readers;
    std::vector<ks::winapi_monitor::InjectionParticipant> participants;
    std::mutex pendingMutex;
    std::shared_ptr<ks::monitor::WinAPIFilterRules> eventRules;
    std::deque<WinAPIEventRef> pendingRows;
    std::uint64_t nextEventSequence = 0, firstEventTime100ns = 0;
    std::unordered_map<std::uint32_t, CoverageViewState> pendingCoverage;
    std::unordered_map<std::uint32_t, std::uint64_t> agentDroppedRows;
    std::size_t pendingDroppedRows = 0;
    std::vector<std::pair<std::uint32_t, DWORD>> pipeErrors;
    static constexpr std::size_t pendingCapacity = 24000;
    bool start();
    void requestStop() noexcept;
    bool cleanup();
    void startReader(std::uint32_t pid, const std::wstring& session, bool root);
    void readPipe(const std::shared_ptr<Reader>& reader, bool root);
    void enqueue(EventRow row);
    void notice(const QString& api, const QString& detail, std::uint32_t pid = 0);
    void queueCoverageSnapshot(std::uint32_t pid, std::uint64_t session, std::uint64_t revision,
        std::vector<ks::winapi_monitor::ApiMonitorEventPacket> rows, bool stale, std::uint64_t generation);
};
