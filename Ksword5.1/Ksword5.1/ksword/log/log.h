#pragma once

// ============================================================
// ksword/log/log.h
// Namespace: ks::log
// Purpose:
// - provide the reusable R3 logging core for ksword consumers;
// - keep the legacy kLogEvent/dbg/info/eol API available for UI code;
// - avoid depending on Framework.h so non-Dock code can reuse logging.
// ============================================================

#include <cstddef> // std::size_t: revision counters and vector indexes.
#include <cstdint> // std::uint32_t: compact log level filter mask.
#include <ctime>   // std::time_t: log timestamps.
#include <mutex>   // std::mutex: thread-safe log storage.
#include <ostream> // std::ostream: stream manipulator overload.
#include <sstream> // std::ostringstream: per-thread pending message buffer.
#include <string>  // std::string: portable UTF-8 text carrier.
#include <vector>  // std::vector: log snapshots and tracking results.

// GUID is the stable event identity used by the existing log tracking UI.
#include <guiddef.h>

// QString support is optional so the ksword logging core can still be reused
// by non-Qt R3 tools that do not expose Qt include directories.
#if defined(__has_include)
#if __has_include(<QString>)
#include <QString>
#define KSWORD_LOG_HAS_QT_STRING 1
#endif
#endif

#ifndef KSWORD_LOG_HAS_QT_STRING
#define KSWORD_LOG_HAS_QT_STRING 0
#endif

namespace ks::log
{
    // Level describes the severity of one archived log record.
    // Input: selected by the caller through a fixed Stream instance.
    // Processing: copied into Event and used for console/UI coloring.
    // Return behavior: enum values are returned by value where needed.
    enum class Level
    {
        Debug = 0,
        Info,
        Warn,
        Error,
        Fatal
    };

    // TraceEvent represents a caller-created logical event id.
    // Input: no constructor input; a GUID is generated automatically.
    // Processing: Stream binds this GUID to records written with <<.
    // Return behavior: no method return value; guid is read directly.
    class TraceEvent
    {
    public:
        TraceEvent();

        const GUID guid; // Immutable event identity for tracking related rows.
    };

    // Event is the archived data model for one log row.
    // Input: fields are filled by Stream::flushPendingState.
    // Processing: LogEntry stores Event values and UI takes snapshots.
    // Return behavior: passive value type, copied by Snapshot/Track.
    struct Event
    {
        // recordSequence：日志管理器归档时分配的单调唯一序号；仅用于 UI 增量更新，不对用户显示。
        std::uint64_t recordSequence = 0;
        GUID guid{};
        Level level{};
        std::string content;
        std::string fileLocation;
        std::string functionName;
        std::time_t timestamp{};
    };

    // LogEntry is the thread-safe in-memory log store.
    // Input: add receives Event values; Save receives an output path.
    // Processing: a mutex protects records and the monotonic revision.
    // Return behavior: Snapshot/Track return copies; Save returns success.
    class LogEntry
    {
    public:
        // add appends one event and bumps the revision counter.
        // Input: eventItem is moved into internal storage.
        // Processing: lock, append, increment revision.
        // Return behavior: no return value.
        void add(Event eventItem);

        // clear removes all archived events and bumps the revision counter.
        // Input: none.
        // Processing: lock and clear the vector.
        // Return behavior: no return value.
        void clear();

        // Save exports the current snapshot as TSV text.
        // Input: outputPath is interpreted as a UTF-8 filesystem path.
        // Processing: copy records under lock, then write outside the lock.
        // Return behavior: true on complete write, false on open/write error.
        bool Save(std::string outputPath);

        // Track filters records by GUID.
        // Input: targetGuid is compared byte-for-byte with Event::guid.
        // Processing: lock and copy matching records.
        // Return behavior: vector of matching Event records.
        std::vector<Event> Track(GUID targetGuid);

        // SnapshotRecent copies only the newest matching records for UI refresh.
        // Input: maxCount caps returned rows; enabledLevelMask uses one bit per Level value;
        //        trackedGuid optionally limits records to one logical event id.
        // Processing: lock, scan records from newest to oldest, copy at most maxCount matches,
        //             then restore chronological order in the returned vector.
        // Return behavior: vector containing the newest matching Event records; internal storage remains full.
        std::vector<Event> SnapshotRecent(
            std::size_t maxCount,
            std::uint32_t enabledLevelMask,
            const GUID* trackedGuid = nullptr) const;

        // Snapshot copies all records for UI refresh/export consumers.
        // Input: none.
        // Processing: lock and copy the vector.
        // Return behavior: full Event vector snapshot.
        std::vector<Event> Snapshot() const;

        // Revision returns the current mutation counter.
        // Input: none.
        // Processing: lock and read the counter.
        // Return behavior: monotonically increasing revision value.
        std::size_t Revision() const;

    private:
        mutable std::mutex m_mutex;   // Protects m_events and m_revision.
        std::vector<Event> m_events;  // Complete archived log stream.
        std::size_t m_revision = 0;   // Incremented after add/clear.
        std::uint64_t m_nextRecordSequence = 1; // 下一条归档日志的唯一序号；clear 后不复位，避免 UI 键重复。
    };

    // EndToken carries source-location metadata collected by the eol macro.
    // Input: macro passes file, line, function name, and signature.
    // Processing: Stream converts the token into an archived Event.
    // Return behavior: passive value type, no direct return behavior.
    struct EndToken
    {
        const char* filePath = "";
        int lineNumber = 0;
        const char* functionName = "";
        const char* functionSignature = "";
    };

    // Stream is a cout-like writer bound to one log Level.
    // Input: caller chains values with << and terminates with EndToken/eol.
    // Processing: data is buffered per thread and per Stream instance.
    // Return behavior: operator<< returns *this for chaining.
    class Stream
    {
    public:
        explicit Stream(Level level);

        // Binds a logical event GUID to the pending message.
        // Input: logEvent provides the GUID.
        // Processing: stores the GUID in thread-local pending state.
        // Return behavior: returns this stream for chaining.
        Stream& operator<<(const TraceEvent& logEvent);

#if KSWORD_LOG_HAS_QT_STRING
        // Appends QString text when Qt headers are available.
        // Input: value is converted through QString::toStdString().
        // Processing: text is appended to the pending message buffer.
        // Return behavior: returns this stream for chaining.
        Stream& operator<<(const QString& value)
        {
            PendingLogState& pendingState = getPendingState();
            pendingState.messageBuffer << value.toStdString();
            return *this;
        }
#endif

        // Appends any ostream-compatible value to the pending message.
        // Input: value must be accepted by std::ostringstream::operator<<.
        // Processing: appends to the current thread-local buffer.
        // Return behavior: returns this stream for chaining.
        template <typename TValue>
        Stream& operator<<(const TValue& value)
        {
            PendingLogState& pendingState = getPendingState();
            pendingState.messageBuffer << value;
            return *this;
        }

        // Appends standard stream manipulators such as std::endl.
        // Input: streamManipulator is an ostream manipulator pointer.
        // Processing: applies it to the pending ostringstream.
        // Return behavior: returns this stream for chaining.
        Stream& operator<<(std::ostream& (*streamManipulator)(std::ostream&));

        // Flushes the pending message into the shared LogEntry.
        // Input: endToken supplies source location metadata.
        // Processing: builds Event, prints console text, clears the buffer.
        // Return behavior: returns this stream for chaining.
        Stream& operator<<(const EndToken& endToken);

    private:
        // PendingLogState keeps one in-progress message per thread/stream.
        // Input: values are appended through operator<<.
        // Processing: hasEvent decides whether to reuse or generate a GUID.
        // Return behavior: used internally by reference.
        struct PendingLogState
        {
            bool hasEvent = false;
            GUID currentGuid{};
            std::ostringstream messageBuffer;
        };

        // getPendingState locates the current thread-local buffer.
        // Input: none; this pointer selects the stream slot.
        // Processing: creates a default state when missing.
        // Return behavior: mutable reference to the pending state.
        PendingLogState& getPendingState();

        // flushPendingState commits one buffered message.
        // Input: endToken supplies file/line/function information.
        // Processing: archives, prints, and resets the pending state.
        // Return behavior: no return value.
        void flushPendingState(const EndToken& endToken);

        const Level m_level; // Severity fixed at stream construction.
    };

    // DefaultEntry returns the process-wide log store.
    // Input: none.
    // Processing: function-local static avoids initialization-order issues.
    // Return behavior: mutable reference to the shared store.
    LogEntry& DefaultEntry();

    // The following accessors expose the five shared severity streams.
    // Input: none.
    // Processing: each uses a function-local static Stream instance.
    // Return behavior: mutable stream reference for chained output.
    Stream& DebugStream();
    Stream& InfoStream();
    Stream& WarnStream();
    Stream& ErrorStream();
    Stream& FatalStream();

    // GuidToString formats a GUID as 8-4-4-4-12 uppercase text.
    // Input: guidValue is the GUID to serialize.
    // Processing: uses snprintf into a fixed local buffer.
    // Return behavior: formatted GUID string.
    std::string GuidToString(const GUID& guidValue);

    // IsSameGuid compares two GUID values byte-for-byte.
    // Input: leftGuid and rightGuid are the compared GUIDs.
    // Processing: uses memcmp over the POD GUID structure.
    // Return behavior: true when all bytes match.
    bool IsSameGuid(const GUID& leftGuid, const GUID& rightGuid);

    // LevelToString converts a Level enum to a stable text token.
    // Input: level is the severity value.
    // Processing: switch over all known enum values.
    // Return behavior: DEBUG/INFO/WARN/ERROR/FATAL/UNKNOWN.
    std::string LevelToString(Level level);

    // FormatTimeToString converts time_t to local wall-clock text.
    // Input: timeValue is a seconds-level timestamp.
    // Processing: localtime_s + put_time formatting.
    // Return behavior: YYYY-MM-DD HH:MM:SS, or epoch fallback on error.
    std::string FormatTimeToString(std::time_t timeValue);
} // namespace ks::log

// ------------------------------------------------------------------------
// Legacy compatibility layer
// ------------------------------------------------------------------------
// Existing Dock/UI code still uses the original global names.  The aliases
// below intentionally keep that source surface stable while the concrete
// implementation now lives under ks::log inside ksword/.
using kLogLevel = ::ks::log::Level;
using kLogEvent = ::ks::log::TraceEvent;
using kEvent = ::ks::log::Event;
using kEventEntry = ::ks::log::LogEntry;
using kLogEntry = ::ks::log::LogEntry;
using LogEndToken = ::ks::log::EndToken;
using LogStream = ::ks::log::Stream;

extern kEventEntry& KswordARKEventEntry;
extern LogStream& dbg;
extern LogStream& info;
extern LogStream& warn;
extern LogStream& err;
extern LogStream& fatal;

inline std::string GuidToString(const GUID& guidValue)
{
    return ::ks::log::GuidToString(guidValue);
}

inline bool IsSameGuid(const GUID& leftGuid, const GUID& rightGuid)
{
    return ::ks::log::IsSameGuid(leftGuid, rightGuid);
}

inline std::string LogLevelToString(const kLogLevel logLevel)
{
    return ::ks::log::LevelToString(logLevel);
}

inline std::string FormatTimeToString(const std::time_t timeValue)
{
    return ::ks::log::FormatTimeToString(timeValue);
}

#if defined(_MSC_VER)
#define KSWORDARK_FUNCTION_SIGNATURE __FUNCSIG__
#else
#define KSWORDARK_FUNCTION_SIGNATURE __PRETTY_FUNCTION__
#endif

#ifndef eol
#define eol LogEndToken{__FILE__, __LINE__, __FUNCTION__, KSWORDARK_FUNCTION_SIGNATURE}
#endif
