#include "log.h"

// Windows console coloring and GUID creation are implemented here so the
// public header remains mostly declarative and cheap to include.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>

#include <algorithm>     // std::replace: TSV field sanitization.
#include <cstdio>        // std::snprintf: GUID formatting.
#include <cstring>       // std::memcmp: GUID comparison.
#include <filesystem>    // std::filesystem::path: UTF-8 output path.
#include <fstream>       // std::ofstream: TSV export writer.
#include <iomanip>       // std::put_time: timestamp formatting.
#include <iostream>      // std::cout: console log output.
#include <unordered_map> // std::unordered_map: thread-local stream states.
#include <utility>       // std::move: efficient Event insertion.

#pragma comment(lib, "Ole32.lib")

namespace
{
    // g_consoleOutputMutex serializes console writes across worker threads.
    // Input: locked by Stream::flushPendingState.
    // Processing: protects color changes and line emission as one unit.
    // Return behavior: no direct return value.
    std::mutex g_consoleOutputMutex;

    constexpr WORD DefaultWhiteColor = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;

    // CreateRandomGuid asks COM for a new GUID and falls back to zero GUID.
    // Input: none.
    // Processing: calls CoCreateGuid; failure is intentionally non-throwing.
    // Return behavior: generated GUID or default GUID{} on failure.
    GUID CreateRandomGuid()
    {
        GUID newGuid{};
        if (::CoCreateGuid(&newGuid) != S_OK)
        {
            return GUID{};
        }
        return newGuid;
    }

    // GetLevelBadge maps a log level to the console badge prefix.
    // Input: level selects the badge.
    // Processing: switch over supported levels.
    // Return behavior: printable badge text.
    std::string GetLevelBadge(const ks::log::Level level)
    {
        switch (level)
        {
        case ks::log::Level::Debug: return "[   ]";
        case ks::log::Level::Info:  return "[ + ]";
        case ks::log::Level::Warn:  return "[ ! ]";
        case ks::log::Level::Error: return "[ x ]";
        case ks::log::Level::Fatal: return "[***]";
        default:                    return "[ ? ]";
        }
    }

    // GetPrefixColor maps a level to Win32 console attributes.
    // Input: level selects the color.
    // Processing: switch over supported levels.
    // Return behavior: SetConsoleTextAttribute-compatible WORD.
    WORD GetPrefixColor(const ks::log::Level level)
    {
        switch (level)
        {
        case ks::log::Level::Debug:
            return FOREGROUND_BLUE | FOREGROUND_INTENSITY;
        case ks::log::Level::Info:
            return FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case ks::log::Level::Warn:
            return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
        case ks::log::Level::Error:
            return FOREGROUND_RED | FOREGROUND_INTENSITY;
        case ks::log::Level::Fatal:
            return BACKGROUND_RED | BACKGROUND_INTENSITY | DefaultWhiteColor;
        default:
            return DefaultWhiteColor;
        }
    }

    // ShouldPrintLocation decides whether console output includes location.
    // Input: level is the archived severity.
    // Processing: only Error and Fatal are considered high-signal enough.
    // Return behavior: true when location should be printed.
    bool ShouldPrintLocation(const ks::log::Level level)
    {
        return level == ks::log::Level::Error || level == ks::log::Level::Fatal;
    }

    // ExtractFileNameOnly shortens a path for console display.
    // Input: fullPath may be a full Windows or POSIX-style path.
    // Processing: searches for the last slash/backslash.
    // Return behavior: file name when found, otherwise original text.
    std::string ExtractFileNameOnly(const std::string& fullPath)
    {
        const std::size_t slashPosition = fullPath.find_last_of("\\/");
        if (slashPosition == std::string::npos)
        {
            return fullPath;
        }
        return fullPath.substr(slashPosition + 1);
    }

    // SanitizeFieldForTsv keeps each log field inside one TSV cell.
    // Input: fieldValue is copied because replacements are in-place.
    // Processing: tabs and line breaks become spaces.
    // Return behavior: sanitized field text.
    std::string SanitizeFieldForTsv(std::string fieldValue)
    {
        std::replace(fieldValue.begin(), fieldValue.end(), '\t', ' ');
        std::replace(fieldValue.begin(), fieldValue.end(), '\r', ' ');
        std::replace(fieldValue.begin(), fieldValue.end(), '\n', ' ');
        return fieldValue;
    }

    // BuildLocationString creates the archived file:line string.
    // Input: filePath may be null; lineNumber is the preprocessor line.
    // Processing: null paths become an empty string.
    // Return behavior: combined location string.
    std::string BuildLocationString(const char* const filePath, const int lineNumber)
    {
        const std::string safeFilePath = (filePath == nullptr) ? "" : std::string(filePath);
        return safeFilePath + ":" + std::to_string(lineNumber);
    }

    // ResolveFunctionDescription chooses the best available function text.
    // Input: functionName is short; functionSignature is compiler-specific.
    // Processing: signature wins because it is richer under MSVC.
    // Return behavior: selected function description text.
    std::string ResolveFunctionDescription(
        const char* const functionName,
        const char* const functionSignature)
    {
        const std::string signatureText =
            (functionSignature == nullptr) ? "" : std::string(functionSignature);
        if (!signatureText.empty())
        {
            return signatureText;
        }
        return (functionName == nullptr) ? "" : std::string(functionName);
    }
} // namespace

namespace ks::log
{
    TraceEvent::TraceEvent()
        : guid(CreateRandomGuid())
    {
    }

    LogEntry& DefaultEntry()
    {
        static LogEntry entry;
        return entry;
    }

    Stream& DebugStream()
    {
        static Stream stream(Level::Debug);
        return stream;
    }

    Stream& InfoStream()
    {
        static Stream stream(Level::Info);
        return stream;
    }

    Stream& WarnStream()
    {
        static Stream stream(Level::Warn);
        return stream;
    }

    Stream& ErrorStream()
    {
        static Stream stream(Level::Error);
        return stream;
    }

    Stream& FatalStream()
    {
        static Stream stream(Level::Fatal);
        return stream;
    }

    std::string GuidToString(const GUID& guidValue)
    {
        char guidBuffer[64] = {};
        std::snprintf(
            guidBuffer,
            sizeof(guidBuffer),
            "%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X",
            static_cast<unsigned long>(guidValue.Data1),
            static_cast<unsigned short>(guidValue.Data2),
            static_cast<unsigned short>(guidValue.Data3),
            static_cast<unsigned int>(guidValue.Data4[0]),
            static_cast<unsigned int>(guidValue.Data4[1]),
            static_cast<unsigned int>(guidValue.Data4[2]),
            static_cast<unsigned int>(guidValue.Data4[3]),
            static_cast<unsigned int>(guidValue.Data4[4]),
            static_cast<unsigned int>(guidValue.Data4[5]),
            static_cast<unsigned int>(guidValue.Data4[6]),
            static_cast<unsigned int>(guidValue.Data4[7]));
        return guidBuffer;
    }

    bool IsSameGuid(const GUID& leftGuid, const GUID& rightGuid)
    {
        return std::memcmp(&leftGuid, &rightGuid, sizeof(GUID)) == 0;
    }

    std::string LevelToString(const Level level)
    {
        switch (level)
        {
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
        case Level::Fatal: return "FATAL";
        default:           return "UNKNOWN";
        }
    }

    std::string FormatTimeToString(const std::time_t timeValue)
    {
        std::tm localTime{};
        if (::localtime_s(&localTime, &timeValue) != 0)
        {
            return "1970-01-01 00:00:00";
        }

        std::ostringstream formattedTime;
        formattedTime << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S");
        return formattedTime.str();
    }

    void LogEntry::add(Event eventItem)
    {
        std::lock_guard<std::mutex> lockGuard(m_mutex);
        // recordSequence 在锁内分配，保证多线程写日志时每个归档记录都有稳定且唯一的 UI 键。
        eventItem.recordSequence = m_nextRecordSequence++;
        m_events.emplace_back(std::move(eventItem));
        ++m_revision;
    }

    void LogEntry::clear()
    {
        std::lock_guard<std::mutex> lockGuard(m_mutex);
        m_events.clear();
        ++m_revision;
    }

    bool LogEntry::Save(std::string outputPath)
    {
        std::vector<Event> eventsSnapshot;
        {
            std::lock_guard<std::mutex> lockGuard(m_mutex);
            eventsSnapshot = m_events;
        }

        // outputPathUtf8 用途：按 C++20/23 推荐形式把 UTF-8 字节串转换为 filesystem::path，避免 u8path 弃用错误。
        const std::u8string outputPathUtf8(outputPath.begin(), outputPath.end());
        const std::filesystem::path outputFilePath(outputPathUtf8);
        std::ofstream outputFile(outputFilePath, std::ios::out | std::ios::trunc);
        if (!outputFile.is_open())
        {
            return false;
        }

        for (const Event& singleEvent : eventsSnapshot)
        {
            outputFile
                << LevelToString(singleEvent.level) << '\t'
                << FormatTimeToString(singleEvent.timestamp) << '\t'
                << ::ks::log::GuidToString(singleEvent.guid) << '\t'
                << SanitizeFieldForTsv(singleEvent.content) << '\t'
                << SanitizeFieldForTsv(singleEvent.fileLocation) << '\t'
                << SanitizeFieldForTsv(singleEvent.functionName) << '\n';
        }

        return outputFile.good();
    }

    std::vector<Event> LogEntry::Track(const GUID targetGuid)
    {
        std::vector<Event> trackedEvents;
        std::lock_guard<std::mutex> lockGuard(m_mutex);
        for (const Event& singleEvent : m_events)
        {
            if (::ks::log::IsSameGuid(singleEvent.guid, targetGuid))
            {
                trackedEvents.push_back(singleEvent);
            }
        }
        return trackedEvents;
    }

    std::vector<Event> LogEntry::SnapshotRecent(
        const std::size_t maxCount,
        const std::uint32_t enabledLevelMask,
        const GUID* const trackedGuid) const
    {
        std::vector<Event> recentEvents;
        if (maxCount == 0 || enabledLevelMask == 0)
        {
            return recentEvents;
        }

        std::lock_guard<std::mutex> lockGuard(m_mutex);
        recentEvents.reserve(std::min(maxCount, m_events.size()));

        // UI 只需要“最近 N 条”，但内部 m_events 必须继续保留全量历史。
        // 因此这里从尾部倒序扫描，命中筛选条件后才复制；达到 maxCount 立即停止。
        // 这样日志量很大时，日志 Dock 刷新不会为了显示 200 行而复制全部历史。
        for (auto reverseIterator = m_events.rbegin(); reverseIterator != m_events.rend(); ++reverseIterator)
        {
            const Event& singleEvent = *reverseIterator;
            const unsigned int levelIndex = static_cast<unsigned int>(singleEvent.level);
            if (levelIndex >= 32U)
            {
                continue;
            }

            const std::uint32_t levelBit = (std::uint32_t{ 1 } << levelIndex);
            if ((enabledLevelMask & levelBit) == 0)
            {
                continue;
            }

            if (trackedGuid != nullptr && !::ks::log::IsSameGuid(singleEvent.guid, *trackedGuid))
            {
                continue;
            }

            recentEvents.push_back(singleEvent);
            if (recentEvents.size() >= maxCount)
            {
                break;
            }
        }

        // 倒序扫描得到的是“新到旧”，表格仍按正常时间顺序“旧到新”显示。
        std::reverse(recentEvents.begin(), recentEvents.end());
        return recentEvents;
    }

    std::vector<Event> LogEntry::Snapshot() const
    {
        std::lock_guard<std::mutex> lockGuard(m_mutex);
        return m_events;
    }

    std::size_t LogEntry::Revision() const
    {
        std::lock_guard<std::mutex> lockGuard(m_mutex);
        return m_revision;
    }

    Stream::Stream(const Level level)
        : m_level(level)
    {
    }

    Stream& Stream::operator<<(const TraceEvent& logEvent)
    {
        PendingLogState& pendingState = getPendingState();
        pendingState.hasEvent = true;
        pendingState.currentGuid = logEvent.guid;
        return *this;
    }

    Stream& Stream::operator<<(std::ostream& (*streamManipulator)(std::ostream&))
    {
        PendingLogState& pendingState = getPendingState();
        pendingState.messageBuffer << streamManipulator;
        return *this;
    }

    Stream& Stream::operator<<(const EndToken& endToken)
    {
        flushPendingState(endToken);
        return *this;
    }

    Stream::PendingLogState& Stream::getPendingState()
    {
        thread_local std::unordered_map<const Stream*, PendingLogState> threadLocalStates;
        return threadLocalStates[this];
    }

    void Stream::flushPendingState(const EndToken& endToken)
    {
        PendingLogState& pendingState = getPendingState();
        const std::string messageText = pendingState.messageBuffer.str();
        const GUID activeGuid = pendingState.hasEvent ? pendingState.currentGuid : CreateRandomGuid();

        const std::time_t nowTime = std::time(nullptr);
        const std::string formattedTime = FormatTimeToString(nowTime);
        const std::string locationString = BuildLocationString(endToken.filePath, endToken.lineNumber);
        const std::string functionString = ResolveFunctionDescription(
            endToken.functionName,
            endToken.functionSignature);

        Event archivedEvent;
        archivedEvent.guid = activeGuid;
        archivedEvent.level = m_level;
        archivedEvent.content = messageText;
        archivedEvent.fileLocation = locationString;
        archivedEvent.functionName = functionString;
        archivedEvent.timestamp = nowTime;
        DefaultEntry().add(std::move(archivedEvent));

        {
            std::lock_guard<std::mutex> lockGuard(g_consoleOutputMutex);
            HANDLE outputHandle = ::GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO originalConsoleInfo{};
            const bool hasConsoleInfo =
                outputHandle != INVALID_HANDLE_VALUE &&
                outputHandle != nullptr &&
                ::GetConsoleScreenBufferInfo(outputHandle, &originalConsoleInfo) != 0;

            const WORD prefixColor = GetPrefixColor(m_level);
            if (hasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, prefixColor);
            }
            std::cout << GetLevelBadge(m_level) << "[" << formattedTime << "]";

            if (hasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, DefaultWhiteColor);
            }
            std::cout << messageText;

            if (ShouldPrintLocation(m_level))
            {
                const std::string shortFileName =
                    ExtractFileNameOnly(endToken.filePath == nullptr ? "" : endToken.filePath);
                std::cout
                    << "(File:" << shortFileName
                    << ", Line " << endToken.lineNumber
                    << ", " << functionString
                    << ")";
            }

            std::cout << std::endl;
            if (hasConsoleInfo)
            {
                ::SetConsoleTextAttribute(outputHandle, originalConsoleInfo.wAttributes);
            }
        }

        pendingState.hasEvent = false;
        pendingState.currentGuid = GUID{};
        pendingState.messageBuffer.str("");
        pendingState.messageBuffer.clear();
    }
} // namespace ks::log

// Legacy global references bind existing source code to the new ks::log core.
kEventEntry& KswordARKEventEntry = ::ks::log::DefaultEntry();
LogStream& dbg = ::ks::log::DebugStream();
LogStream& info = ::ks::log::InfoStream();
LogStream& warn = ::ks::log::WarnStream();
LogStream& err = ::ks::log::ErrorStream();
LogStream& fatal = ::ks::log::FatalStream();
