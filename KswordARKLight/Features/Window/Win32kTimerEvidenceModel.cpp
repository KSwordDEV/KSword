#include "Win32kTimerEvidenceModel.h"

#include "../../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverTypes.h"

#include <algorithm>
#include <cstddef>
#include <iomanip>
#include <sstream>

namespace Ksword::Features::Window {
namespace {

constexpr std::size_t kMaximumSummaryDetailChars = 2048U;
constexpr std::size_t kMaximumDriverDetailChars = 256U;

std::wstring Hex32(const std::uint32_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(8) << value;
    return stream.str();
}

std::wstring Hex64(const std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::uppercase << std::hex << std::setfill(L'0') << std::setw(16) << value;
    return stream.str();
}

std::wstring BoundedDisplayText(const std::wstring& value, const std::size_t maximumChars) {
    std::wstring text;
    const std::size_t copiedChars = std::min(value.size(), maximumChars);
    text.reserve(copiedChars);
    for (std::size_t index = 0U; index < copiedChars; ++index) {
        const wchar_t character = value[index];
        text.push_back(character == L'\r' || character == L'\n' || character == L'\t' ? L' ' : character);
    }
    if (value.size() > maximumChars && maximumChars >= 3U) {
        text.resize(maximumChars - 3U);
        text += L"...";
    }
    return text;
}

std::wstring BoundedPacketText(const wchar_t* value, const std::size_t capacity) {
    if (value == nullptr || capacity == 0U) {
        return {};
    }
    std::size_t length = 0U;
    while (length < capacity && value[length] != L'\0') {
        ++length;
    }
    return BoundedDisplayText(std::wstring(value, length), kMaximumDriverDetailChars);
}

std::wstring BoundedUtf8Diagnostic(const std::string& value) {
    std::wstring text;
    const std::size_t copiedChars = std::min(value.size(), kMaximumDriverDetailChars);
    text.reserve(copiedChars);
    for (std::size_t index = 0U; index < copiedChars; ++index) {
        const wchar_t character = static_cast<unsigned char>(value[index]);
        text.push_back(character == L'\r' || character == L'\n' || character == L'\t' ? L' ' : character);
    }
    if (value.size() > kMaximumDriverDetailChars) {
        text.resize(kMaximumDriverDetailChars - 3U);
        text += L"...";
    }
    return text;
}

std::wstring OptionalHex32(const bool present, const std::uint32_t rawValue) {
    return present ? Hex32(rawValue) : L"<absent; raw=" + Hex32(rawValue) + L">";
}

std::wstring OptionalHex64(const bool present, const std::uint64_t rawValue) {
    return present ? Hex64(rawValue) : L"<absent; raw=" + Hex64(rawValue) + L">";
}

std::wstring OptionalDecimal(const bool present, const std::uint32_t rawValue) {
    return present ? std::to_wstring(rawValue) : L"<absent; raw=" + std::to_wstring(rawValue) + L">";
}

const wchar_t* LayoutSourceText(const std::uint32_t source) {
    switch (source) {
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
        return L"ValidatedDisassembly";
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS:
        return L"NearestPrevious";
    case KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_UNKNOWN:
    default:
        return L"Unknown";
    }
}

std::wstring SnapshotStatusText(const ksword::ark::Win32kTimersResult& result) {
    if (!result.io.ok) {
        return result.unsupported ? L"Unsupported" : L"Unavailable";
    }
    if (result.unsupported || result.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED) {
        return L"Unsupported";
    }
    if (result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND) {
        return L"Win32kMissing";
    }
    return Win32kTimerEvidenceStatusText(result.status);
}

std::wstring BuildSnapshotDetail(const ksword::ark::Win32kTimersResult& result) {
    std::wostringstream detail;
    detail << L"version=" << Hex32(result.version)
           << L"; responseStatus=" << Hex32(result.status)
           << L"; flags=" << Hex32(result.flags)
           << L"; total=" << result.totalCount
           << L"; returned=" << result.returnedCount
           << L"; parsedRows=" << result.entries.size()
           << L"; entrySize=" << result.entrySize
           << L"; lastStatus=" << Hex32(static_cast<std::uint32_t>(result.lastStatus))
           << L"; ioOk=" << (result.io.ok ? L"true" : L"false")
           << L"; win32Error=" << Hex32(static_cast<std::uint32_t>(result.io.win32Error))
           << L"; ioNtStatus=" << Hex32(static_cast<std::uint32_t>(result.io.ntStatus))
           << L"; unsupported=" << (result.unsupported ? L"true" : L"false")
           << L"; capabilityMask=" << Hex64(result.capabilityMask)
           << L"; missingCapabilityMask=" << Hex64(result.missingCapabilityMask)
           << L"; gTimerHashTable=" << Hex64(result.timerHashTable)
           << L"; layoutSource=" << LayoutSourceText(result.layout.source)
           << L" (" << Hex32(result.layout.source) << L")"
           << L"; visited=" << result.visitedNodeCount
           << L"; readFailures=" << result.readFailureCount
           << L"; corruptBuckets=" << result.corruptBucketCount
           << L"; duplicates=" << result.duplicateCount
           << L"; win32kbase=" << Hex32(result.win32kbaseTimeDateStamp)
           << L"/" << Hex32(result.win32kbaseImageSize)
           << L"; win32kfull=" << Hex32(result.win32kfullTimeDateStamp)
           << L"/" << Hex32(result.win32kfullImageSize);
    const std::wstring ioMessage = BoundedUtf8Diagnostic(result.io.message);
    detail << L"; ioMessage=" << (ioMessage.empty() ? L"<empty>" : ioMessage);
    const std::wstring driverDetail = BoundedDisplayText(result.detail, kMaximumDriverDetailChars);
    detail << L"; driverDetail=" << (driverDetail.empty() ? L"<empty>" : driverDetail);
    return BoundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

std::wstring BuildLayoutDetail(const KSWORD_ARK_WIN32K_TIMER_LAYOUT& layout) {
    std::wostringstream detail;
    detail << L"source=" << LayoutSourceText(layout.source) << L" (" << Hex32(layout.source) << L")"
           << L"; objectSize=" << Hex32(layout.objectSize)
           << L"; primaryThreadInfo=" << Hex32(layout.primaryThreadInfo)
           << L"; callback=" << Hex32(layout.callback)
           << L"; countdown=" << Hex32(layout.countdown)
           << L"; tolerance=" << Hex32(layout.tolerance)
           << L"; flags=" << Hex32(layout.flags)
           << L"; interval=" << Hex32(layout.interval)
           << L"; globalListEntry=" << Hex32(layout.globalListEntry)
           << L"; window=" << Hex32(layout.window)
           << L"; timerId=" << Hex32(layout.timerId)
           << L"; alternateThreadInfo=" << Hex32(layout.alternateThreadInfo)
           << L"; hashListEntry=" << Hex32(layout.hashListEntry)
           << L"; timestamp=" << Hex32(layout.timestamp)
           << L"; bucketCount=" << Hex32(layout.bucketCount)
           << L"; bucketStride=" << Hex32(layout.bucketStride)
           << L"; profileTimeDateStamp=" << Hex32(layout.timeDateStamp)
           << L"; profileImageSize=" << Hex32(layout.imageSize);
    return BoundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

std::wstring BuildTimerDetail(const KSWORD_ARK_WIN32K_TIMER_ENTRY& entry) {
    const bool hasObject = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT) != 0U;
    const bool hasThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD) != 0U;
    const bool hasCallback = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_CALLBACK) != 0U;
    const bool hasInterval = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_INTERVAL) != 0U;
    const bool hasFlags = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_FLAGS) != 0U;
    const bool hasWindow = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_WINDOW) != 0U;
    const bool hasId = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_ID) != 0U;
    const bool hasAlternateThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_ALTERNATE_THREAD) != 0U;
    const bool hasHashLink = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_HASH_LINK) != 0U;

    std::wostringstream detail;
    detail << L"fieldFlags=" << Hex32(entry.fieldFlags)
           << L"; statusCode=" << Hex32(entry.status)
           << L"; processId=" << OptionalDecimal(hasThread, entry.processId)
           << L"; threadId=" << OptionalDecimal(hasThread, entry.threadId)
           << L"; sessionId=" << OptionalDecimal(hasThread, entry.sessionId)
           << L"; flags=" << OptionalHex32(hasFlags, entry.flags)
           << L"; intervalMs=" << OptionalDecimal(hasInterval, entry.intervalMs)
           << L"; countdownMs=" << OptionalDecimal(hasInterval, entry.countdownMs)
           << L"; toleranceMs=" << OptionalDecimal(hasInterval, entry.toleranceMs)
           << L"; lastStatus=" << Hex32(static_cast<std::uint32_t>(entry.lastStatus))
           << L"; reserved=" << Hex32(entry.reserved)
           << L"; timerObject=" << OptionalHex64(hasObject, entry.timerObject)
           << L"; callbackAddress=" << OptionalHex64(hasCallback, entry.callbackAddress)
           << L"; primaryThreadInfo=" << OptionalHex64(hasThread, entry.primaryThreadInfo)
           << L"; alternateThreadInfo=" << OptionalHex64(hasAlternateThread, entry.alternateThreadInfo)
           << L"; windowObject=" << OptionalHex64(hasWindow, entry.windowObject)
           << L"; timerId=" << OptionalHex64(hasId, entry.timerId)
           << L"; hashLink=" << OptionalHex64(hasHashLink, entry.hashLink);
    const std::wstring driverDetail = BoundedPacketText(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS);
    detail << L"; driverDetail=" << (driverDetail.empty() ? L"<empty>" : driverDetail);
    return BoundedDisplayText(detail.str(), kMaximumSummaryDetailChars);
}

} // namespace

std::wstring Win32kTimerEvidenceStatusText(const std::uint32_t status) {
    switch (status) {
    case KSWORD_ARK_WIN32K_STATUS_OK: return L"OK";
    case KSWORD_ARK_WIN32K_STATUS_PARTIAL: return L"Partial";
    case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED: return L"Unsupported";
    case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING: return L"ProfileMissing";
    case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND: return L"Win32kMissing";
    case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED: return L"BufferTruncated";
    case KSWORD_ARK_WIN32K_STATUS_READ_FAILED: return L"ReadFailed";
    case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED: return L"EnumFailed";
    case KSWORD_ARK_WIN32K_STATUS_UNKNOWN: return L"Unknown";
    default: return L"Status(" + Hex32(status) + L")";
    }
}

std::vector<Win32kTimerEvidenceRow> BuildWin32kTimerEvidenceRows(
    const ksword::ark::Win32kTimersResult& result) {
    std::vector<Win32kTimerEvidenceRow> rows;
    rows.reserve(result.entries.size() + 2U);
    rows.push_back({
        L"Win32k Timer Snapshot",
        L"ArkDriverClient::queryWin32kTimers",
        L"gTimerHashTable / tagTIMER",
        SnapshotStatusText(result),
        BuildSnapshotDetail(result),
        0U
    });
    const bool projectionUnavailable =
        !result.io.ok ||
        result.unsupported ||
        result.status == KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED ||
        result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND ||
        result.status == KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING;
    if (projectionUnavailable) {
        return rows;
    }
    rows.push_back({
        L"Win32k Timer Layout",
        L"KSWORD_ARK_WIN32K_TIMER_LAYOUT",
        L"tagTIMER layout / " + std::wstring(LayoutSourceText(result.layout.source)),
        result.layout.source == KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY
            ? L"Exact"
            : (result.layout.source == KSWORD_ARK_WIN32K_TIMER_LAYOUT_SOURCE_NEAREST_PREVIOUS
                ? L"NearestPrevious"
                : L"Unknown"),
        BuildLayoutDetail(result.layout),
        0U
    });

    for (std::size_t index = 0U; index < result.entries.size(); ++index) {
        const KSWORD_ARK_WIN32K_TIMER_ENTRY& entry = result.entries[index];
        const bool hasObject = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_OBJECT) != 0U;
        const bool hasThread = (entry.fieldFlags & KSWORD_ARK_WIN32K_TIMER_FIELD_THREAD) != 0U;
        const std::wstring timerObject = hasObject ? Hex64(entry.timerObject) : std::wstring(L"<object absent>");
        rows.push_back({
            L"Win32k Timer",
            L"gTimerHashTable / tagTIMER",
            L"Timer #" + std::to_wstring(index) + L" / " + timerObject,
            Win32kTimerEvidenceStatusText(entry.status),
            BuildTimerDetail(entry),
            hasThread ? entry.processId : 0U
        });
    }
    return rows;
}

} // namespace Ksword::Features::Window
