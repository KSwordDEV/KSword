#include "ArkDriverExtended.h"
#include "CommandRegistry.h"

#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../shared/driver/KswordArkDebuggerIoctl.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace
{
    struct ExtendedArgs
    {
        std::map<std::wstring, std::wstring> options;
    };

    ExtendedArgs parseExtendedArgs(const int argc, wchar_t* const argv[], const int startIndex)
    {
        ExtendedArgs args{};
        for (int index = startIndex; index < argc; ++index)
        {
            if (argv[index] == nullptr || argv[index][0] == L'\0')
            {
                continue;
            }
            if (argv[index][0] != L'-')
            {
                throw std::runtime_error("unexpected positional argument in r0 command");
            }
            const std::wstring key = argv[index];
            std::wstring value;
            if (index + 1 < argc && argv[index + 1] != nullptr && argv[index + 1][0] != L'-')
            {
                value = argv[++index];
            }
            args.options[key] = value;
        }
        return args;
    }

    bool hasOption(const ExtendedArgs& args, const wchar_t* key)
    {
        return args.options.find(key) != args.options.end();
    }

    std::wstring optionValue(const ExtendedArgs& args, const wchar_t* key, const std::wstring& fallback = {})
    {
        const auto it = args.options.find(key);
        return it == args.options.end() ? fallback : it->second;
    }

    std::wstring requireOption(const ExtendedArgs& args, const wchar_t* key)
    {
        const std::wstring value = optionValue(args, key);
        if (value.empty())
        {
            std::string keyText;
            for (const wchar_t* cursor = key; *cursor; ++cursor) keyText.push_back(static_cast<char>(*cursor));
            throw std::invalid_argument("missing required option " + keyText);
        }
        return value;
    }

    std::uint64_t parseUnsigned(const std::wstring& value, const wchar_t* optionName)
    {
        if (value.empty())
        {
            throw std::runtime_error("numeric r0 command option is empty");
        }
        errno = 0;
        wchar_t* end = nullptr;
        const unsigned long long parsed = std::wcstoull(value.c_str(), &end, 0);
        if (errno == ERANGE || end == value.c_str() || *end != L'\0')
        {
            (void)optionName;
            throw std::runtime_error("invalid numeric value for r0 command option");
        }
        return static_cast<std::uint64_t>(parsed);
    }

    std::uint32_t optionU32(const ExtendedArgs& args, const wchar_t* key, const std::uint32_t fallback)
    {
        const std::wstring value = optionValue(args, key);
        if (value.empty())
        {
            return fallback;
        }
        const std::uint64_t parsed = parseUnsigned(value, key);
        if (parsed > (std::numeric_limits<std::uint32_t>::max)())
        {
            throw std::runtime_error("r0 command option exceeds uint32 range");
        }
        return static_cast<std::uint32_t>(parsed);
    }

    std::uint64_t optionU64(const ExtendedArgs& args, const wchar_t* key, const std::uint64_t fallback)
    {
        const std::wstring value = optionValue(args, key);
        return value.empty() ? fallback : parseUnsigned(value, key);
    }

    std::wstring normalizeNtPath(std::wstring path)
    {
        if (path.rfind(L"\\\\?\\", 0U) == 0U)
        {
            return L"\\??\\" + path.substr(4U);
        }
        if (path.rfind(L"\\\\", 0U) == 0U)
        {
            return L"\\??\\UNC\\" + path.substr(2U);
        }
        if (path.size() >= 2U && path[1U] == L':')
        {
            return L"\\??\\" + path;
        }
        return path;
    }

    std::wstring utf8ToWide(const std::string& value)
    {
        if (value.empty())
        {
            return {};
        }
        const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), nullptr, 0);
        if (required <= 0)
        {
            return std::wstring(value.begin(), value.end());
        }
        std::wstring result(static_cast<std::size_t>(required), L'\0');
        (void)::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), static_cast<int>(value.size()), result.data(), required);
        return result;
    }

    template <typename T, typename = void>
    struct HasUnsupported : std::false_type {};

    template <typename T>
    struct HasUnsupported<T, std::void_t<decltype(std::declval<const T&>().unsupported)>> : std::true_type {};

    template <typename T, typename = void>
    struct HasEntries : std::false_type {};

    template <typename T>
    struct HasEntries<T, std::void_t<decltype(std::declval<const T&>().entries)>> : std::true_type {};

    template <typename Result>
    int resultExitCode(const Result& result)
    {
        if (result.io.ok && result.io.ntStatus >= 0)
        {
            if constexpr (HasUnsupported<Result>::value) { if (result.unsupported) return 5; }
            return 0;
        }
        if (result.io.deviceOpenFailed || result.io.message.rfind("CreateFileW", 0U) == 0U) return 2;
        const auto error = result.io.win32Error;
        if (error == ERROR_INVALID_FUNCTION || error == ERROR_NOT_SUPPORTED ||
            error == ERROR_CALL_NOT_IMPLEMENTED || error == ERROR_PROC_NOT_FOUND) return 5;
        if constexpr (HasUnsupported<Result>::value) { if (result.unsupported) return 5; }
        const auto status = static_cast<std::uint32_t>(result.io.ntStatus);
        if (status == 0xC00000BBU || status == 0xC0000002U || status == 0xC000007AU) return 5;
        return 3;
    }

    template <typename Result>
    bool printResultState(const wchar_t* label, const Result& result)
    {
        std::wcout << label << L": io_ok=" << (result.io.ok ? L"true" : L"false")
                   << L" bytes_returned=" << result.io.bytesReturned
                   << L" win32_error=" << result.io.win32Error;
        // A failed Win32 transport with the default zero has no returned
        // NTSTATUS. Preserve nonzero statuses supplied by response parsers.
        if (!result.io.ok && result.io.ntStatus == 0) std::wcout << L" nt_status=n/a";
        else std::wcout << L" nt_status=0x" << std::hex << static_cast<std::uint32_t>(result.io.ntStatus) << std::dec;
        std::wcout << L"\n";
        if constexpr (HasUnsupported<Result>::value)
        {
            std::wcout << L"unsupported=" << (result.unsupported ? L"true" : L"false") << L"\n";
        }
        if constexpr (HasEntries<Result>::value)
        {
            std::wcout << L"returned_rows=" << result.entries.size() << L"\n";
        }
        if (!result.io.message.empty())
        {
            std::wcout << L"detail=" << utf8ToWide(result.io.message) << L"\n";
        }
        if (!result.io.ok && (result.io.deviceOpenFailed || result.io.message.rfind("CreateFileW", 0U) == 0U) &&
            (result.io.win32Error == ERROR_FILE_NOT_FOUND || result.io.win32Error == ERROR_PATH_NOT_FOUND))
            std::wcerr << L"hint: run 'sc start KswordARK' for an installed service, "
                       << L"or run Launcher.exe / Ksword5.1.exe as administrator to load the driver.\n";
        return result.io.ok && result.io.ntStatus >= 0;
    }

    void printBytes(const std::vector<std::uint8_t>& bytes, const std::size_t limit)
    {
        const std::size_t shown = (std::min)(bytes.size(), limit);
        std::wcout << L"data_hex=";
        for (std::size_t index = 0U; index < shown; ++index)
        {
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                       << static_cast<unsigned int>(bytes[index]);
        }
        std::wcout << std::dec << std::setfill(L' ') << L"\n";
        if (shown < bytes.size())
        {
            std::wcout << L"data_hex_truncated=true total_bytes=" << bytes.size() << L"\n";
        }
    }

    void printDirectoryEntries(const std::vector<ksword::ark::DirectoryEntryRecord>& entries, const std::uint32_t limit)
    {
        const std::size_t shown = (std::min)(entries.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < shown; ++index)
        {
            const auto& entry = entries[index];
            std::wcout << L"  [" << index << L"] name=" << entry.name
                       << L" size=" << entry.endOfFile
                       << L" attributes=0x" << std::hex << entry.fileAttributes
                       << L" flags=0x" << entry.flags << std::dec << L"\n";
        }
    }

    void printWorkQueueEntries(const std::vector<ksword::ark::WorkQueueEntry>& entries, const std::uint32_t limit)
    {
        const std::size_t shown = (std::min)(entries.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < shown; ++index)
        {
            const auto& entry = entries[index];
            std::wcout << L"  [" << index << L"] kind=" << entry.rowKind
                       << L" queue_type=" << entry.queueType
                       << L" tid=" << entry.threadId
                       << L" routine=0x" << std::hex << entry.routineAddress
                       << L" module_base=0x" << entry.moduleBase << std::dec
                       << L" module=" << utf8ToWide(entry.moduleName) << L"\n";
        }
    }

    // The protocol strings are fixed-size arrays, and need not contain a NUL.
    template <std::size_t N>
    std::wstring boundedText(const wchar_t (&text)[N])
    {
        return std::wstring(text, std::find(text, text + N, L'\0'));
    }

    void printExtendedRows(const ksword::ark::IoctlRegistryQueryResult& result)
    {
        std::wcout << L"query_status=" << result.status << L" total=" << result.totalCount
                   << L" returned=" << result.returnedCount << L" duplicates=" << result.duplicateCount
                   << L" last_status=0x" << std::hex << static_cast<std::uint32_t>(result.lastStatus) << std::dec << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  ioctl=0x" << std::hex << row.ioControlCode << L" function=0x" << row.functionNumber
                       << L" flags=0x" << row.flags << L" required_capability=0x" << row.requiredCapability
                       << L" handler=0x" << row.handlerAddress << std::dec << L" method=" << row.method
                       << L" access=" << row.access << L" name=" << utf8ToWide(row.name) << L"\n";
    }

    void printExtendedRows(const ksword::ark::UnloadedDriverQueryResult& result)
    {
        std::wcout << L"source=" << result.source << L" query_status=" << result.queryStatus
                   << L" response_flags=0x" << std::hex << result.responseFlags
                   << L" last_status=0x" << static_cast<std::uint32_t>(result.lastStatus) << std::dec
                   << L" total=" << result.totalRows << L" returned=" << result.entries.size()
                   << L" skipped=" << result.skippedRows << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  source=" << row.source << L" flags=0x" << std::hex << row.flags
                       << L" entry=0x" << row.entryAddress << L" base=0x" << row.baseAddress
                       << L" size=0x" << row.imageSize << L" timestamp=0x" << row.timeDateStamp
                       << L" load_status=0x" << static_cast<std::uint32_t>(row.loadStatus) << std::dec
                       << L" unload_time=" << row.unloadTime << L" name=" << row.driverName << L"\n";
    }

    void printExtendedRows(const ksword::ark::PlatformAuditResult& result)
    {
        std::wcout << L"query_status=" << result.status << L" response_flags=0x" << std::hex << result.responseFlags
                   << L" last_status=0x" << static_cast<std::uint32_t>(result.lastStatus) << std::dec
                   << L" total=" << result.totalCount << L" returned=" << result.returnedCount << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  scope=" << row.scope << L" kind=" << row.rowKind << L" index=" << row.entryIndex
                       << L" status=" << row.status << L" hook_status=" << row.hookStatus << L" confidence=" << row.confidence
                       << L" field_flags=0x" << std::hex << row.fieldFlags << L" live=0x" << row.liveAddress
                       << L" original=0x" << row.originalAddress << L" table=0x" << row.tableAddress
                       << L" module_base=0x" << row.moduleBase << L" last_status=0x" << static_cast<std::uint32_t>(row.lastStatus)
                       << std::dec << L" detail_code=" << row.detailCode << L" name=" << boundedText(row.name)
                       << L" module=" << boundedText(row.modulePath) << L"\n";
    }

    void printExtendedRows(const ksword::ark::ObjectTypeTableAuditResult& result)
    {
        std::wcout << L"query_status=" << result.status << L" total=" << result.totalCount
                   << L" returned=" << result.returnedCount << L" next_index=" << result.nextIndex
                   << L" last_status=0x" << std::hex << static_cast<std::uint32_t>(result.lastStatus) << std::dec << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  index=" << row.typeIndex << L" status=" << row.status
                       << L" field_flags=0x" << std::hex << row.fieldFlags << L" object_type=0x" << row.objectTypeAddress
                       << L" identity_hash=0x" << row.identityHash << L" last_status=0x" << static_cast<std::uint32_t>(row.lastStatus)
                       << std::dec << L" name=" << boundedText(row.typeName) << L"\n";
    }

    void printExtendedRows(const ksword::ark::Win32kTimersResult& result)
    {
        std::wcout << L"query_status=" << result.status << L" total=" << result.totalCount << L" returned=" << result.returnedCount
                   << L" capability=0x" << std::hex << result.capabilityMask << L" missing=0x" << result.missingCapabilityMask
                   << L" last_status=0x" << static_cast<std::uint32_t>(result.lastStatus) << std::dec
                   << L" visited=" << result.visitedNodeCount << L" read_failures=" << result.readFailureCount
                   << L" corrupt_buckets=" << result.corruptBucketCount << L" detail=" << result.detail << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  pid=" << row.processId << L" tid=" << row.threadId << L" session=" << row.sessionId
                       << L" status=" << row.status << L" field_flags=0x" << std::hex << row.fieldFlags
                       << L" flags=0x" << row.flags << L" timer=0x" << row.timerObject << L" timer_id=0x" << row.timerId
                       << L" callback=0x" << row.callbackAddress << L" window=0x" << row.windowObject
                       << L" last_status=0x" << static_cast<std::uint32_t>(row.lastStatus) << std::dec
                       << L" interval_ms=" << row.intervalMs << L" countdown_ms=" << row.countdownMs
                       << L" tolerance_ms=" << row.toleranceMs << L" detail=" << boundedText(row.detail) << L"\n";
    }

    void printExtendedRows(const ksword::ark::Win32kEventHooksResult& result)
    {
        std::wcout << L"query_status=" << result.status << L" total=" << result.totalCount << L" returned=" << result.returnedCount
                   << L" capability=0x" << std::hex << result.capabilityMask << L" missing=0x" << result.missingCapabilityMask
                   << L" last_status=0x" << static_cast<std::uint32_t>(result.lastStatus) << std::dec
                   << L" visited=" << result.visitedNodeCount << L" read_failures=" << result.readFailureCount
                   << L" corrupt_links=" << result.corruptLinkCount << L" detail=" << result.detail << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  pid=" << row.processId << L" tid=" << row.threadId << L" session=" << row.sessionId
                       << L" target_pid=" << row.targetProcessId << L" target_tid=" << row.targetThreadId
                       << L" status=" << row.status << L" field_flags=0x" << std::hex << row.fieldFlags
                       << L" flags=0x" << row.flags << L" event_min=0x" << row.eventMin << L" event_max=0x" << row.eventMax
                       << L" hook=0x" << row.hookObject << L" handle=0x" << row.hookHandle << L" callback=0x" << row.callbackAddress
                       << L" last_status=0x" << static_cast<std::uint32_t>(row.lastStatus) << std::dec
                       << L" detail=" << boundedText(row.detail) << L"\n";
    }

    void printExtendedRows(const ksword::ark::KernelTimerDpcEnumResult& result)
    {
        const wchar_t* state = L"unknown";
        switch (result.queryStatus)
        {
        case KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK: state = L"complete"; break;
        case KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL: state = L"partial"; break;
        case KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING: state = L"dyndata-missing"; break;
        case KSWORD_ARK_TIMER_DPC_QUERY_STATUS_INVALID_LAYOUT: state = L"invalid-layout"; break;
        case KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED: state = L"unsupported"; break;
        }
        std::wcout << L"query_state=" << state << L" query_status=" << result.queryStatus
                   << L" status_flags=0x" << std::hex << result.statusFlags
                   << L" last_status=0x" << static_cast<std::uint32_t>(result.lastStatus) << std::dec
                   << L" total=" << result.totalCount << L" returned=" << result.returnedCount
                   << L" processors=" << result.processorCount << L" buckets_visited=" << result.bucketsVisited << L"\n";
        for (const auto& row : result.entries)
            std::wcout << L"  cpu=" << row.processorGroup << L":" << row.processorNumber << L" bucket=" << row.bucketIndex
                       << L" flags=0x" << std::hex << row.flags << L" timer=0x" << row.timerAddress
                       << L" dpc=0x" << row.dpcAddress << L" routine=0x" << row.deferredRoutine
                       << L" context=0x" << row.deferredContext << std::dec << L" type=" << row.timerType
                       << L" period=" << row.period << L" due_time=" << row.dueTime << L"\n";
    }

    std::uint32_t parseUnloadedSource(const std::wstring& source)
    {
        if (source.empty() || source == L"mm") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_MM_UNLOADED_DRIVERS;
        if (source == L"piddb") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_PIDDB_CACHE_TABLE;
        if (source == L"hash") return KSWORD_ARK_UNLOADED_DRIVER_SOURCE_KERNEL_HASH_BUCKET_LIST;
        throw std::runtime_error("invalid --source, expected mm, piddb, or hash");
    }

    // trimWhitespace removes category-list separators' surrounding whitespace
    // without changing the category token itself.
    std::wstring trimWhitespace(std::wstring value)
    {
        std::size_t first = 0U;
        while (first < value.size() && std::iswspace(value[first]) != 0)
        {
            ++first;
        }
        std::size_t last = value.size();
        while (last > first && std::iswspace(value[last - 1U]) != 0)
        {
            --last;
        }
        return value.substr(first, last - first);
    }

    // parseCallbackMonitorCategories maps a readable comma-separated category
    // list to the shared protocol mask and rejects ambiguous empty entries.
    std::uint32_t parseCallbackMonitorCategories(const ExtendedArgs& args)
    {
        if (!hasOption(args, L"--categories"))
        {
            return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE;
        }

        const std::wstring categoryList = optionValue(args, L"--categories");
        if (categoryList.empty())
        {
            throw std::runtime_error("--categories requires a comma-separated category list");
        }

        std::uint32_t categoryMask = 0U;
        std::size_t tokenStart = 0U;
        while (tokenStart <= categoryList.size())
        {
            const std::size_t delimiter = categoryList.find(L',', tokenStart);
            const std::size_t tokenLength = delimiter == std::wstring::npos
                ? categoryList.size() - tokenStart
                : delimiter - tokenStart;
            const std::wstring token = trimWhitespace(categoryList.substr(tokenStart, tokenLength));
            if (token.empty())
            {
                throw std::runtime_error("--categories contains an empty category name");
            }
            if (token == L"process") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
            else if (token == L"thread") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
            else if (token == L"image") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
            else if (token == L"registry") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY;
            else if (token == L"object") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
            else if (token == L"minifilter") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
            else if (token == L"core") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_CORE;
            else if (token == L"all") categoryMask |= KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
            else throw std::runtime_error("--categories contains an unknown category name");

            if (delimiter == std::wstring::npos)
            {
                break;
            }
            tokenStart = delimiter + 1U;
        }
        if (categoryMask == 0U)
        {
            throw std::runtime_error("--categories resolved to an empty category mask");
        }
        return categoryMask;
    }

    // printCallbackMonitorStatus emits the fixed monitor state response in the
    // same key=value shape used by the other ArkDriverClient-backed commands.
    void printCallbackMonitorStatus(const ksword::ark::CallbackMonitorStatusResult& result)
    {
        std::wcout << L"version=" << result.version
                   << L" runtime_flags=0x" << std::hex << result.runtimeFlags
                   << L" category_mask=0x" << result.categoryMask
                   << L" registered_category_mask=0x" << result.registeredCategoryMask
                   << std::dec << L" ring_capacity=" << result.ringCapacity
                   << L" queued_count=" << result.queuedCount
                   << L" latest_sequence=" << result.latestSequence
                   << L" dropped_count=" << result.droppedCount
                   << L" last_status=0x" << std::hex << static_cast<std::uint32_t>(result.lastStatus)
                   << L" minifilter_start_status=0x" << static_cast<std::uint32_t>(result.minifilterStartStatus)
                   << std::dec << L"\n";
    }

    // printCallbackMonitorRead emits cursor metadata and a bounded list of
    // validated callback monitor records; the caller can continue at next_sequence.
    void printCallbackMonitorRead(
        const ksword::ark::CallbackMonitorReadResult& result,
        const std::uint32_t limit)
    {
        std::wcout << L"runtime_flags=0x" << std::hex << result.runtimeFlags
                   << L" category_mask=0x" << result.categoryMask
                   << L" response_flags=0x" << result.responseFlags
                   << std::dec << L" ring_capacity=" << result.ringCapacity
                   << L" first_available_sequence=" << result.firstAvailableSequence
                   << L" latest_sequence=" << result.latestSequence
                   << L" next_sequence=" << result.nextSequence
                   << L" dropped_count=" << result.droppedCount
                   << L" lost_before_first=" << result.lostBeforeFirst
                   << L" returned_records=" << result.records.size() << L"\n";

        const std::size_t shown = (std::min)(result.records.size(), static_cast<std::size_t>(limit));
        for (std::size_t index = 0U; index < shown; ++index)
        {
            const auto& record = result.records[index];
            std::wcout << L"  [" << index << L"] sequence=" << record.sequence
                       << L" time_utc_100ns=" << record.timeUtc100ns
                       << L" category=0x" << std::hex << record.category
                       << L" operation=0x" << record.operation
                       << L" flags=0x" << record.flags
                       << L" result_status=0x" << static_cast<std::uint32_t>(record.resultStatus)
                       << std::dec << L" originating_pid=" << record.originatingProcessId
                       << L" originating_tid=" << record.originatingThreadId
                       << L" target_pid=" << record.targetProcessId
                       << L" target_tid=" << record.targetThreadId
                       << L" parent_pid=" << record.parentProcessId
                       << L" session_id=" << record.sessionId
                       << L" original_access=0x" << std::hex << record.originalAccess
                       << L" desired_access=0x" << record.desiredAccess
                       << L" object_type=0x" << record.objectType
                       << L" detail_code=0x" << record.detailCode
                       << L" address=0x" << record.address
                       << L" region_size=0x" << record.regionSize
                       << std::dec << L" process_name=" << record.processName
                       << L" path=" << record.path << L"\n";
        }
        if (shown < result.records.size())
        {
            std::wcout << L"records_truncated=true total_records=" << result.records.size() << L"\n";
        }
    }

    template <typename Result>
    int finishResult(const wchar_t* label, const Result& result)
    {
        (void)printResultState(label, result);
        return resultExitCode(result);
    }

    template <typename Result>
    int finishRows(const wchar_t* label, const Result& result)
    {
        const int rc = finishResult(label, result);
        // Wrappers validate response bounds before exposing entries. Partial
        // business failures may still carry useful validated rows.
        if (result.io.ok) printExtendedRows(result);
        // STATUS_BUFFER_OVERFLOW reports a bounded partial response, not a
        // failed transport. Keep all other NTSTATUS failures unchanged.
        if (result.io.ok && rc == 3 && static_cast<std::uint32_t>(result.io.ntStatus) == 0x80000005U)
            return 6;
        return rc;
    }

    int timerDpcResultCode(const ksword::ark::KernelTimerDpcEnumResult& result, const int transportRc)
    {
        if (transportRc != 0) return transportRc;
        if (result.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING ||
            result.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_INVALID_LAYOUT ||
            result.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED) return 5;
        if (result.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL ||
            (result.statusFlags & (KSWORD_ARK_TIMER_DPC_STATUS_PARTIAL | KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED)) != 0U) return 6;
        return result.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK ? 0 : 3;
    }

    using ks::cli::Json;
    using JsonFields = std::vector<std::pair<std::wstring, Json>>;

    Json rowJson(const ksword::ark::IoctlRegistryEntry& r)
    {
        return Json::object({{L"ioctl",Json::hex(r.ioControlCode)}, {L"function",Json::hex(r.functionNumber)},
            {L"flags",Json::hex(r.flags)}, {L"requiredCapability",Json::hex(r.requiredCapability)},
            {L"handler",Json::hex(r.handlerAddress)}, {L"method",Json::number(r.method)},
            {L"access",Json::number(r.access)}, {L"name",Json::string(utf8ToWide(r.name))}});
    }
    Json rowJson(const ksword::ark::UnloadedDriverEntry& r)
    {
        return Json::object({{L"source",Json::number(r.source)}, {L"flags",Json::hex(r.flags)},
            {L"entryAddress",Json::hex(r.entryAddress)}, {L"baseAddress",Json::hex(r.baseAddress)},
            {L"imageSize",Json::hex(r.imageSize)}, {L"timestamp",Json::hex(r.timeDateStamp)},
            {L"loadStatus",Json::hex(static_cast<std::uint32_t>(r.loadStatus))},
            {L"unloadTime",Json::count(r.unloadTime)}, {L"name",Json::string(r.driverName)}});
    }
    Json rowJson(const KSWORD_ARK_PLATFORM_AUDIT_ENTRY& r)
    {
        return Json::object({{L"scope",Json::number(r.scope)}, {L"kind",Json::number(r.rowKind)},
            {L"index",Json::number(r.entryIndex)}, {L"status",Json::number(r.status)},
            {L"hookStatus",Json::number(r.hookStatus)}, {L"confidence",Json::number(r.confidence)},
            {L"fieldFlags",Json::hex(r.fieldFlags)}, {L"liveAddress",Json::hex(r.liveAddress)},
            {L"originalAddress",Json::hex(r.originalAddress)}, {L"tableAddress",Json::hex(r.tableAddress)},
            {L"moduleBase",Json::hex(r.moduleBase)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
            {L"detailCode",Json::number(r.detailCode)}, {L"name",Json::string(boundedText(r.name))},
            {L"module",Json::string(boundedText(r.modulePath))}});
    }
    Json rowJson(const KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY& r)
    {
        return Json::object({{L"index",Json::number(r.typeIndex)}, {L"status",Json::number(r.status)},
            {L"fieldFlags",Json::hex(r.fieldFlags)}, {L"objectType",Json::hex(r.objectTypeAddress)},
            {L"identityHash",Json::hex(r.identityHash)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
            {L"name",Json::string(boundedText(r.typeName))}});
    }
    Json rowJson(const KSWORD_ARK_WIN32K_TIMER_ENTRY& r)
    {
        return Json::object({{L"pid",Json::number(r.processId)}, {L"tid",Json::number(r.threadId)},
            {L"session",Json::number(r.sessionId)}, {L"status",Json::number(r.status)},
            {L"fieldFlags",Json::hex(r.fieldFlags)}, {L"flags",Json::hex(r.flags)},
            {L"timer",Json::hex(r.timerObject)}, {L"timerId",Json::hex(r.timerId)},
            {L"callback",Json::hex(r.callbackAddress)}, {L"window",Json::hex(r.windowObject)},
            {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
            {L"intervalMs",Json::number(r.intervalMs)}, {L"countdownMs",Json::number(r.countdownMs)},
            {L"toleranceMs",Json::number(r.toleranceMs)}, {L"detail",Json::string(boundedText(r.detail))}});
    }
    Json rowJson(const KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY& r)
    {
        return Json::object({{L"pid",Json::number(r.processId)}, {L"tid",Json::number(r.threadId)},
            {L"session",Json::number(r.sessionId)}, {L"targetPid",Json::number(r.targetProcessId)},
            {L"targetTid",Json::number(r.targetThreadId)}, {L"status",Json::number(r.status)},
            {L"fieldFlags",Json::hex(r.fieldFlags)}, {L"flags",Json::hex(r.flags)},
            {L"eventMin",Json::hex(r.eventMin)}, {L"eventMax",Json::hex(r.eventMax)},
            {L"hook",Json::hex(r.hookObject)}, {L"handle",Json::hex(r.hookHandle)},
            {L"callback",Json::hex(r.callbackAddress)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))},
            {L"detail",Json::string(boundedText(r.detail))}});
    }
    Json rowJson(const ksword::ark::KernelTimerDpcEntry& r)
    {
        return Json::object({{L"processorGroup",Json::number(r.processorGroup)}, {L"processorNumber",Json::number(r.processorNumber)},
            {L"bucket",Json::number(r.bucketIndex)}, {L"flags",Json::hex(r.flags)}, {L"timer",Json::hex(r.timerAddress)},
            {L"dpc",Json::hex(r.dpcAddress)}, {L"routine",Json::hex(r.deferredRoutine)},
            {L"context",Json::hex(r.deferredContext)}, {L"type",Json::number(r.timerType)},
            {L"period",Json::signedNumber(r.period)}, {L"dueTime",Json::string(std::to_wstring(r.dueTime))}});
    }

    JsonFields rowMetadata(const ksword::ark::IoctlRegistryQueryResult& r) { return {{L"queryStatus",Json::number(r.status)}, {L"totalCount",Json::number(r.totalCount)}, {L"duplicateCount",Json::number(r.duplicateCount)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}; }
    JsonFields rowMetadata(const ksword::ark::UnloadedDriverQueryResult& r) { return {{L"source",Json::number(r.source)}, {L"queryStatus",Json::number(r.queryStatus)}, {L"totalCount",Json::number(r.totalRows)}, {L"skippedRows",Json::number(r.skippedRows)}, {L"responseFlags",Json::hex(r.responseFlags)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}; }
    JsonFields rowMetadata(const ksword::ark::PlatformAuditResult& r) { return {{L"queryStatus",Json::number(r.status)}, {L"totalCount",Json::number(r.totalCount)}, {L"responseFlags",Json::hex(r.responseFlags)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}; }
    JsonFields rowMetadata(const ksword::ark::ObjectTypeTableAuditResult& r) { return {{L"queryStatus",Json::number(r.status)}, {L"totalCount",Json::number(r.totalCount)}, {L"nextIndex",Json::number(r.nextIndex)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}; }
    JsonFields rowMetadata(const ksword::ark::Win32kTimersResult& r) { return {{L"queryStatus",Json::number(r.status)}, {L"totalCount",Json::number(r.totalCount)}, {L"capability",Json::hex(r.capabilityMask)}, {L"missingCapability",Json::hex(r.missingCapabilityMask)}, {L"visited",Json::number(r.visitedNodeCount)}, {L"readFailures",Json::number(r.readFailureCount)}, {L"corruptBuckets",Json::number(r.corruptBucketCount)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}, {L"detail",Json::string(r.detail)}}; }
    JsonFields rowMetadata(const ksword::ark::Win32kEventHooksResult& r) { return {{L"queryStatus",Json::number(r.status)}, {L"totalCount",Json::number(r.totalCount)}, {L"capability",Json::hex(r.capabilityMask)}, {L"missingCapability",Json::hex(r.missingCapabilityMask)}, {L"visited",Json::number(r.visitedNodeCount)}, {L"readFailures",Json::number(r.readFailureCount)}, {L"corruptLinks",Json::number(r.corruptLinkCount)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}, {L"detail",Json::string(r.detail)}}; }
    JsonFields rowMetadata(const ksword::ark::KernelTimerDpcEnumResult& r) { return {{L"queryStatus",Json::number(r.queryStatus)}, {L"totalCount",Json::number(r.totalCount)}, {L"statusFlags",Json::hex(r.statusFlags)}, {L"processors",Json::number(r.processorCount)}, {L"bucketsVisited",Json::number(r.bucketsVisited)}, {L"lastStatus",Json::hex(static_cast<std::uint32_t>(r.lastStatus))}}; }

    template <typename Result>
    bool rowsTruncated(const Result&, std::uint32_t total, std::size_t returned) { return total > returned; }
    bool rowsTruncated(const ksword::ark::ObjectTypeTableAuditResult& r, std::uint32_t, std::size_t) { return r.nextIndex < KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS; }
    bool rowsTruncated(const ksword::ark::KernelTimerDpcEnumResult& r, std::uint32_t total, std::size_t returned) { return total > returned || (r.statusFlags & KSWORD_ARK_TIMER_DPC_STATUS_TRUNCATED) != 0; }

    template <typename Result>
    int finishRowsJson(const wchar_t* label, const Result& result, int rc, std::uint32_t total)
    {
        std::vector<Json> rows;
        if (result.io.ok) for (const auto& entry : result.entries) rows.push_back(rowJson(entry));
        const bool truncated = result.io.ok && rowsTruncated(result, total, rows.size());
        auto fields = result.io.ok ? rowMetadata(result) : JsonFields{{L"totalCount",Json{}}};
        fields.push_back({L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))});
        fields.push_back({L"truncated",result.io.ok ? Json::boolean(truncated) : Json{}});
        // A zero transport exit does not prove every private source was available.
        fields.push_back({L"complete",!result.io.ok || rc != 0 || truncated ? Json::boolean(false) : Json{}});
        fields.push_back({L"transport",Json::object({{L"ok",Json::boolean(result.io.ok)},
            {L"deviceOpenFailed",Json::boolean(result.io.deviceOpenFailed)}, {L"win32Error",Json::number(result.io.win32Error)},
            {L"bytesReturned",Json::number(result.io.bytesReturned)},
            {L"ntStatus",!result.io.ok && result.io.ntStatus == 0 ? Json{} : Json::hex(static_cast<std::uint32_t>(result.io.ntStatus))}})});
        fields.push_back({L"unsupported",Json::boolean(result.unsupported)});
        fields.push_back({L"entries",Json::array(rows)});
        const wchar_t* state = rc == 0 ? (truncated ? L"partial" : L"success") : rc == 6 ? L"partial" : rc == 5 ? L"unsupported" : L"failed";
        std::vector<std::wstring> diagnostics;
        if (!result.io.message.empty()) diagnostics.push_back(utf8ToWide(result.io.message));
        std::wcout << Json::object({{L"schemaVersion",Json::number(1)}, {L"command",Json::string(std::wstring(L"r0 ") + label)},
            {L"backend",Json::string(L"r0")}, {L"status",Json::string(state)}, {L"data",Json::object(fields)},
            {L"diagnostics",Json::strings(diagnostics)}}).text << L"\n";
        return rc;
    }
    template <typename Result>
    int finishRowsSelected(const wchar_t* label, const Result& result, bool json, std::uint32_t total)
    {
        if (!json) return finishRows(label, result);
        int rc = resultExitCode(result);
        if (result.io.ok && rc == 3 && static_cast<std::uint32_t>(result.io.ntStatus) == 0x80000005U) rc = 6;
        return finishRowsJson(label, result, rc, total);
    }

    // Incremental ring responses are pages: a truncated page can be resumed,
    // whereas a cursor gap means that evidence is already irrecoverably lost.
    static_assert(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_TRUNCATED == KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED);
    static_assert(KSWORD_ARK_NETWORK_WFP_EVENT_RESPONSE_FLAG_CURSOR_RESET == KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET);
    std::wstring networkAddress(const unsigned char* address, bool ipv6)
    {
        std::wostringstream out;
        if (!ipv6) {
            out << static_cast<unsigned>(address[0]) << L'.' << static_cast<unsigned>(address[1])
                << L'.' << static_cast<unsigned>(address[2]) << L'.' << static_cast<unsigned>(address[3]);
        } else {
            out << std::hex;
            for (unsigned i = 0; i < 16; i += 2) {
                if (i) out << L':';
                out << ((static_cast<unsigned>(address[i]) << 8) | address[i + 1]);
            }
        }
        return out.str();
    }

    Json eventJson(const KSWORD_ARK_NETWORK_WFP_EVENT_ROW& r)
    {
        return Json::object({{L"sequence",Json::count(r.sequence)}, {L"timestamp100ns",Json::count(r.timestamp100ns)},
            {L"direction",Json::number(r.direction)}, {L"protocol",Json::number(r.protocol)}, {L"processId",Json::number(r.processId)},
            {L"flags",Json::hex(r.flags)}, {L"localAddress",Json::string(networkAddress(r.localAddress,false))},
            {L"localPort",Json::number(r.localPort)}, {L"remoteAddress",Json::string(networkAddress(r.remoteAddress,false))},
            {L"remotePort",Json::number(r.remotePort)}});
    }
    Json eventJson(const KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW& r)
    {
        const bool ipv6 = (r.flags & KSWORD_ARK_NETWORK_TRAFFIC_PACKET_FLAG_IPV6) != 0;
        const auto length = (std::min)(static_cast<std::size_t>(r.capturedLength), sizeof(r.capturedBytes));
        const std::vector<std::uint8_t> bytes(r.capturedBytes, r.capturedBytes + length);
        return Json::object({{L"sequence",Json::count(r.sequence)}, {L"timestamp100ns",Json::count(r.timestamp100ns)},
            {L"addressFamily",Json::number(r.addressFamily)}, {L"direction",Json::number(r.direction)},
            {L"protocol",Json::number(r.protocol)}, {L"processId",Json::number(r.processId)}, {L"flags",Json::hex(r.flags)},
            {L"localAddress",Json::string(networkAddress(r.localAddress,ipv6))}, {L"localPort",Json::number(r.localPort)},
            {L"remoteAddress",Json::string(networkAddress(r.remoteAddress,ipv6))}, {L"remotePort",Json::number(r.remotePort)},
            {L"totalPacketLength",Json::number(r.totalPacketLength)}, {L"capturedLength",Json::number(r.capturedLength)},
            {L"payloadOffset",Json::number(r.payloadOffset)}, {L"payloadLength",Json::number(r.payloadLength)},
            {L"capturedHex",Json::bytes(bytes,bytes.size())}});
    }
    Json eventJson(const ksword::ark::PiDdbEntry& r)
    {
        return Json::object({{L"entryAddress",Json::hex(r.entryAddress)}, {L"timeDateStamp",Json::hex(r.timeDateStamp)},
            {L"loadStatus",Json::hex(static_cast<std::uint32_t>(r.loadStatus))}, {L"driverName",Json::string(r.driverName)}});
    }
    Json eventJson(const KSWORD_ARK_HVM_EVENT_ROW& r)
    {
        return Json::object({{L"sequence",Json::count(r.sequence)}, {L"timestamp",Json::count(r.timestamp)},
            {L"guestPhysicalAddress",Json::hex(r.guestPhysicalAddress)},
            {L"guestLinearAddress",(r.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID) ? Json::hex(r.guestLinearAddress) : Json{}},
            {L"guestRip",Json::hex(r.guestRip)}, {L"qualification",Json::hex(r.qualification)},
            {L"processorGroup",Json::number(r.processorGroup)}, {L"processorNumber",Json::number(r.processorNumber)},
            {L"type",Json::number(r.type)}, {L"exitReason",Json::number(r.exitReason)}, {L"access",Json::hex(r.access)},
            {L"ruleId",Json::number(r.ruleId)}, {L"status",Json::hex(static_cast<std::uint32_t>(r.status))},
            {L"guestRsp",Json::hex(r.guestRsp)}, {L"guestCr3",Json::hex(r.guestCr3)},
            {L"watchState",Json::number(r.watchState)}, {L"eventFlags",Json::hex(r.eventFlags)}});
    }

    template <typename Result>
    int emitEventPage(const wchar_t* label, const Result& result, const std::vector<Json>& rows,
                      JsonFields fields, int code, bool json)
    {
        fields.push_back({L"entries",Json::array(rows)});
        fields.push_back({L"transport",Json::object({{L"ok",Json::boolean(result.io.ok)},
            {L"deviceOpenFailed",Json::boolean(result.io.deviceOpenFailed)}, {L"win32Error",Json::number(result.io.win32Error)},
            {L"bytesReturned",Json::number(result.io.bytesReturned)},
            {L"ntStatus",!result.io.ok && result.io.ntStatus == 0 ? Json{} : Json::hex(static_cast<std::uint32_t>(result.io.ntStatus))}})});
        fields.push_back({L"unsupported",Json::boolean(result.unsupported)});
        if (json) {
            const wchar_t* state = code == 0 ? L"success" : code == 6 ? L"partial" : code == 5 ? L"unsupported" : L"failed";
            std::wcout << Json::object({{L"schemaVersion",Json::number(1)}, {L"command",Json::string(std::wstring(L"r0 ") + label)},
                {L"backend",Json::string(L"r0")}, {L"status",Json::string(state)}, {L"data",Json::object(fields)},
                {L"diagnostics",result.io.message.empty() ? Json::array({}) : Json::strings({utf8ToWide(result.io.message)})}}).text << L"\n";
        } else {
            printResultState(label,result);
            for (const auto& field : fields) if (field.first != L"entries" && field.first != L"transport")
                std::wcout << field.first << L'=' << field.second.text << L' ';
            std::wcout << L"\n";
            for (std::size_t i = 0; i < rows.size(); ++i) std::wcout << L"  [" << i << L"] " << rows[i].text << L"\n";
        }
        return code;
    }

    template <typename Result>
    int networkRingCode(const Result& r)
    {
        int rc = resultExitCode(r);
        if (r.io.ok && rc == 3 && static_cast<std::uint32_t>(r.io.ntStatus) == 0x80000005U) rc = 6;
        if (r.io.ok && r.status == KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE) return 5;
        if (rc != 0) return rc;
        if (r.status == KSWORD_ARK_NETWORK_STATUS_OPERATION_FAILED) return 3;
        if (r.status != KSWORD_ARK_NETWORK_STATUS_APPLIED || r.cursorGapCount != 0 ||
            (r.flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_CURSOR_RESET) != 0) return 6;
        return 0;
    }

    template <typename Result>
    int emitNetworkRing(const wchar_t* label, const Result& result, std::uint64_t dropped, bool json)
    {
        std::vector<Json> rows;
        if (result.io.ok) for (const auto& entry : result.entries) rows.push_back(eventJson(entry));
        const int code = networkRingCode(result);
        return emitEventPage(label, result, rows, {{L"queryStatus",result.io.ok ? Json::number(result.status) : Json{}},
            {L"flags",result.io.ok ? Json::hex(result.flags) : Json{}}, {L"availableCount",result.io.ok ? Json::number(result.totalCount) : Json{}},
            {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"capacity",result.io.ok ? Json::number(result.capacity) : Json{}},
            {L"oldestSequence",result.io.ok ? Json::count(result.oldestSequence) : Json{}}, {L"newestSequence",result.io.ok ? Json::count(result.newestSequence) : Json{}},
            {L"nextSequence",result.io.ok ? Json::count(result.nextSequence) : Json{}}, {L"droppedCount",result.io.ok ? Json::count(dropped) : Json{}},
            {L"cursorGapCount",result.io.ok ? Json::count(result.cursorGapCount) : Json{}},
            {L"pageTruncated",result.io.ok ? Json::boolean((result.flags & KSWORD_ARK_NETWORK_TRAFFIC_RESPONSE_FLAG_TRUNCATED) != 0) : Json{}},
            {L"lastStatus",result.io.ok ? Json::hex(static_cast<std::uint32_t>(result.lastStatus)) : Json{}}}, code, json);
    }

    int emitPiDdb(const ksword::ark::PiDdbQueryResult& result, bool json)
    {
        std::vector<Json> rows;
        if (result.io.ok) for (const auto& entry : result.entries) rows.push_back(eventJson(entry));
        int rc = resultExitCode(result);
        if (result.io.ok && result.queryStatus == KSWORD_ARK_PIDDB_QUERY_STATUS_DYNDATA_MISSING) rc = 5;
        else if (result.io.ok && result.queryStatus == KSWORD_ARK_PIDDB_QUERY_STATUS_PARTIAL) rc = 6;
        else if (result.io.ok && result.queryStatus != KSWORD_ARK_PIDDB_QUERY_STATUS_OK) rc = 3;
        if (rc == 0 && ((result.responseFlags & KSWORD_ARK_PIDDB_RESPONSE_FLAG_TRUNCATED) || result.totalRows > rows.size())) rc = 6;
        return emitEventPage(L"piddb",result,rows,{{L"queryStatus",result.io.ok ? Json::number(result.queryStatus) : Json{}},
            {L"totalCount",result.io.ok ? Json::number(result.totalRows) : Json{}}, {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))},
            {L"responseFlags",result.io.ok ? Json::hex(result.responseFlags) : Json{}},
            {L"lastStatus",result.io.ok ? Json::hex(static_cast<std::uint32_t>(result.lastStatus)) : Json{}}},rc,json);
    }

    int emitHvmEvents(const ksword::ark::HvmEventResult& result, bool json)
    {
        const auto& response = result.response;
        int rc = resultExitCode(result);
        if (rc == 0 && (result.io.bytesReturned != sizeof(response) || response.size != sizeof(response) ||
            response.version != KSWORD_ARK_HVM_PROTOCOL_VERSION || response.returnedRows > KSWORD_ARK_HVM_MAX_EVENT_ROWS ||
            response.returnedRows > response.availableRows)) rc = 4;
        std::vector<Json> rows;
        if (rc == 0) for (unsigned long i = 0; i < response.returnedRows; ++i) rows.push_back(eventJson(response.rows[i]));
        if (rc == 0 && response.droppedRows != 0) rc = 6;
        const bool valid = result.io.ok && (rc == 0 || rc == 6);
        return emitEventPage(L"hvm-events",result,rows,{{L"availableCount",valid ? Json::number(response.availableRows) : Json{}},
            {L"returnedCount",Json::number(static_cast<std::uint32_t>(rows.size()))}, {L"droppedCount",valid ? Json::number(response.droppedRows) : Json{}},
            {L"newestSequence",valid ? Json::count(response.newestSequence) : Json{}},
            {L"nextSequence",valid && response.returnedRows ? Json::count(response.rows[response.returnedRows-1].sequence) : Json{}},
            {L"pageTruncated",valid ? Json::boolean(response.returnedRows < response.availableRows) : Json{}}},rc,json);
    }

    int emitTrafficControl(const wchar_t* label, const ksword::ark::NetworkTrafficCaptureControlResult& result, bool enable, bool json)
    {
        int rc = resultExitCode(result);
        if (result.io.ok && result.response.status == KSWORD_ARK_NETWORK_STATUS_WFP_UNAVAILABLE) rc = 5;
        else if (rc == 0 && (result.response.status != (enable ? KSWORD_ARK_NETWORK_STATUS_APPLIED : KSWORD_ARK_NETWORK_STATUS_DISABLED) ||
            result.response.enabled != (enable ? 1UL : 0UL))) rc = 3;
        return emitEventPage(label,result,{},{{L"queryStatus",result.io.ok ? Json::number(result.response.status) : Json{}},
            {L"enabled",result.io.ok ? Json::boolean(result.response.enabled != 0) : Json{}},
            {L"generation",result.io.ok ? Json::number(result.response.generation) : Json{}},
            {L"lastStatus",result.io.ok ? Json::hex(static_cast<std::uint32_t>(result.response.lastStatus)) : Json{}},
            {L"stopClearsRing",Json::boolean(true)}},rc,json);
    }
}

// commandArkDriverExtended implements the read-only R0 commands backed by
// production ArkDriverClient wrappers that were previously desktop-only.
int commandArkDriverExtended(const int argc, wchar_t* argv[])
{
    if (argc < 3 || argv[2] == nullptr)
    {
        std::wcerr << L"error: r0 requires a subcommand\n";
        return 1;
    }

    const std::wstring subcommand = argv[2];
    const ExtendedArgs args = parseExtendedArgs(argc, argv, 3);
    const ksword::ark::DriverClient client{};
    const std::uint32_t limit = optionU32(args, L"--limit", 64U);

    if (subcommand == L"workqueue")
    {
        const auto result = client.enumerateWorkQueues(
            optionU32(args, L"--flags", KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL),
            optionU32(args, L"--max-entries", 1024U));
        const int rc = finishResult(L"workqueue", result);
        if (rc == 0) printWorkQueueEntries(result.entries, limit);
        return rc;
    }
    if (subcommand == L"directory")
    {
        const auto result = client.enumerateDirectory(
            normalizeNtPath(requireOption(args, L"--path")),
            optionU32(args, L"--max-entries", 4096U));
        const int rc = finishResult(L"directory", result);
        if (rc == 0)
        {
            std::wcout << L"filesystem=" << result.fileSystemName << L" capped=" << (result.capped ? L"true" : L"false") << L"\n";
            printDirectoryEntries(result.entries, limit);
        }
        return rc;
    }
    if (subcommand == L"directory-irp")
    {
        const auto result = client.enumerateDirectoryByIrp(
            normalizeNtPath(requireOption(args, L"--path")),
            optionU32(args, L"--layer", KSWORD_ARK_FILE_IRP_LAYER_BASE_FS),
            optionU32(args, L"--max-entries", 4096U));
        const int rc = finishResult(L"directory-irp", result);
        if (rc == 0)
        {
            std::wcout << L"requested_layer=" << result.requestedLayer
                       << L" resolved_layer=" << result.resolvedLayer
                       << L" receiver=" << result.driverName << L"\n";
            printDirectoryEntries(result.entries, limit);
        }
        return rc;
    }
    if (subcommand == L"image-signature")
    {
        const auto result = client.queryImageSignature(
            normalizeNtPath(requireOption(args, L"--path")),
            optionU64(args, L"--module-base", 0ULL),
            optionU32(args, L"--flags", KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT));
        const int rc = finishResult(L"image-signature", result);
        if (rc == 0) std::wcout << utf8ToWide(ksword::ark::formatImageSignatureEvidence(result)) << L"\n";
        return rc;
    }
    if (subcommand == L"debug-output")
    {
        const auto result = client.drainDebugOutput(
            optionU64(args, L"--after-sequence", 0ULL),
            optionU32(args, L"--max-records", KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS));
        const int rc = finishResult(L"debug-output", result);
        if (rc == 0)
        {
            std::wcout << L"next_sequence=" << result.nextSequence << L" dropped=" << result.droppedCount << L"\n";
            const std::size_t shown = (std::min)(result.records.size(), static_cast<std::size_t>(limit));
            for (std::size_t index = 0U; index < shown; ++index)
            {
                const auto& record = result.records[index];
                std::wcout << L"  [" << index << L"] sequence=" << record.sequence
                           << L" component=" << record.componentId
                           << L" level=" << record.level
                           << L" text=" << utf8ToWide(record.text) << L"\n";
            }
        }
        return rc;
    }
    if (subcommand == L"debugger-status")
    {
        KSWORD_ARK_DEBUGGER_REQUEST request{};
        KSWORD_ARK_DEBUGGER_RESPONSE response{};
        request.version = KSWORD_ARK_DEBUGGER_VERSION; request.size = sizeof(request);
        request.operation = KSWORD_ARK_DEBUGGER_QUERY;
        const auto result = client.deviceIoControl(IOCTL_KSWORD_ARK_DEBUGGER,
            &request, sizeof(request), &response, sizeof(response));
        std::wcout << L"debugger-status transport=" << result.ok << L" win32_error=" << result.win32Error
                   << L" version=" << response.version << L" status=0x" << std::hex << static_cast<unsigned long>(response.status)
                   << L" capabilities=0x" << response.capabilities << std::dec << L"\n";
        return result.ok && result.bytesReturned == sizeof(response) && response.version == KSWORD_ARK_DEBUGGER_VERSION &&
            response.size == sizeof(response) && response.status >= 0 ? 0 : 1;
    }
    if (subcommand == L"hvm-status") return finishResult(L"hvm-status", client.queryHvmStatus());
    if (subcommand == L"hvm-metrics") return finishResult(L"hvm-metrics", client.queryHvmMetrics());
    if (subcommand == L"hvm-platform") return finishResult(L"hvm-platform", client.hvmPlatform());
    if (subcommand == L"hvm-events") return emitHvmEvents(client.queryHvmEvents(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", 128U), false), hasOption(args,L"--json"));
    if (subcommand == L"ioctl-registry") { const auto r=client.queryIoctlRegistry(optionU32(args, L"--flags", KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER), optionU32(args, L"--max-entries", 512U)); return finishRowsSelected(L"ioctl-registry", r, hasOption(args,L"--json"), r.totalCount); }
    if (subcommand == L"timer-dpc")
    {
        const auto result = client.enumerateKernelTimerDpc(optionU32(args, L"--max-entries", KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES), optionU32(args, L"--max-per-bucket", KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET));
        if (hasOption(args,L"--json")) {
            int rc=resultExitCode(result);
            if (result.io.ok && rc==3 && static_cast<std::uint32_t>(result.io.ntStatus)==0x80000005U) rc=6;
            return finishRowsJson(L"timer-dpc", result, timerDpcResultCode(result, rc), result.totalCount);
        }
        return timerDpcResultCode(result, finishRows(L"timer-dpc", result));
    }
    if (subcommand == L"unloaded") { const auto r=client.queryUnloadedDrivers(parseUnloadedSource(optionValue(args, L"--source", L"mm")), optionU32(args, L"--max-rows", KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS)); return finishRowsSelected(L"unloaded", r, hasOption(args,L"--json"), r.totalRows); }
    if (subcommand == L"wfp-events") {
        const auto result = client.queryNetworkWfpEvents(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS));
        return emitNetworkRing(L"wfp-events", result, result.droppedEventCount, hasOption(args,L"--json"));
    }
    if (subcommand == L"traffic") {
        const auto result = client.queryNetworkTrafficPackets(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS));
        return emitNetworkRing(L"traffic", result, result.droppedPacketCount, hasOption(args,L"--json"));
    }
    if (subcommand == L"traffic-start" || subcommand == L"traffic-stop") {
        if (!hasOption(args,L"--confirm")) throw std::invalid_argument("traffic capture control requires --confirm");
        const bool enable = subcommand == L"traffic-start";
        return emitTrafficControl(subcommand.c_str(), client.controlNetworkTrafficCapture(enable), enable, hasOption(args,L"--json"));
    }
    if (subcommand == L"piddb") return emitPiDdb(client.queryPiDdb(optionU32(args, L"--max-rows", KSWORD_ARK_PIDDB_DEFAULT_ROWS)), hasOption(args,L"--json"));
    if (subcommand == L"cpu-power") return finishResult(L"cpu-power", client.queryCpuPowerState());
    if (subcommand == L"process-protect") return finishResult(L"process-protect", client.queryProcessProtectState());
    if (subcommand == L"clipboard-policy") return finishResult(L"clipboard-policy", client.queryClipboardPolicyState());
    if (subcommand == L"raw-disk-backend") return finishResult(L"raw-disk-backend", client.queryRawDiskBackend(optionU32(args, L"--disk", 0U), optionU32(args, L"--backend", KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK), optionU32(args, L"--flags", 0U)));
    if (subcommand == L"raw-disk-read")
    {
        const std::uint64_t lengthValue = parseUnsigned(requireOption(args, L"--length"), L"--length");
        if (lengthValue > (std::numeric_limits<std::uint32_t>::max)())
        {
            throw std::runtime_error("raw disk read length exceeds uint32 range");
        }
        const auto result = client.readRawDisk(
            optionU32(args, L"--disk", 0U),
            optionU32(args, L"--backend", KSWORD_ARK_RAW_DISK_BACKEND_WINDOWS_STACK),
            optionU64(args, L"--offset", 0ULL),
            static_cast<std::uint32_t>(lengthValue),
            optionU32(args, L"--flags", 0U));
        const int rc = finishResult(L"raw-disk-read", result);
        if (rc == 0) printBytes(result.bytes, hasOption(args, L"--hexdump") ? result.bytes.size() : 256U);
        return rc;
    }
    if (subcommand == L"system-time") return finishResult(L"system-time", client.querySystemTime());
    if (subcommand == L"slat-iommu") return finishResult(L"slat-iommu", client.querySlatIommuAudit(hasOption(args, L"--include-mmio")));
    if (subcommand == L"platform") { const auto r=client.queryPlatformAudit(optionU32(args, L"--scope", KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL), optionU32(args, L"--max-rows", KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS)); return finishRowsSelected(L"platform", r, hasOption(args,L"--json"), r.totalCount); }
    if (subcommand == L"i8042") return finishResult(L"i8042", client.queryI8042Audit(optionU32(args, L"--max-rows", KSWORD_ARK_I8042_DEFAULT_MAX_ROWS)));
    if (subcommand == L"object-types") { const auto r=client.enumObjectTypeTable(optionU32(args, L"--flags", KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL), optionU32(args, L"--max-entries", 256U), optionU32(args, L"--start-index", 0U)); return finishRowsSelected(L"object-types", r, hasOption(args,L"--json"), r.totalCount); }
    if (subcommand == L"win32k-timers") { const auto r=client.queryWin32kTimers(optionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(args, L"--session-id", 0U), optionU32(args, L"--pid", 0U), optionU32(args, L"--tid", 0U), optionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)); return finishRowsSelected(L"win32k-timers", r, hasOption(args,L"--json"), r.totalCount); }
    if (subcommand == L"win32k-events") { const auto r=client.queryWin32kEventHooks(optionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(args, L"--session-id", 0U), optionU32(args, L"--pid", 0U), optionU32(args, L"--tid", 0U), optionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)); return finishRowsSelected(L"win32k-events", r, hasOption(args,L"--json"), r.totalCount); }

    std::wcerr << L"error: unknown r0 subcommand '" << subcommand << L"'\n";
    return 1;
}

// commandArkDriverCallbackMonitor implements the read-only callback monitor
// status and cursor-read operations using the shared R3 client wrapper.
int commandArkDriverCallbackMonitor(const int argc, wchar_t* argv[])
{
    if (argc < 3 || argv[2] == nullptr)
    {
        std::wcerr << L"error: callback monitor requires a subcommand\n";
        return 1;
    }

    const std::wstring subcommand = argv[2];
    const ExtendedArgs args = parseExtendedArgs(argc, argv, 3);
    const ksword::ark::DriverClient client{};
    if (subcommand == L"monitor-start")
    {
        const auto result = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_START,
            parseCallbackMonitorCategories(args));
        const int rc = finishResult(L"monitor-start", result);
        if (rc == 0) printCallbackMonitorStatus(result);
        return rc;
    }
    if (subcommand == L"monitor-stop")
    {
        const auto result = client.controlCallbackMonitor(
            KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP,
            0UL);
        const int rc = finishResult(L"monitor-stop", result);
        if (rc == 0) printCallbackMonitorStatus(result);
        return rc;
    }
    if (subcommand == L"monitor-status")
    {
        const auto result = client.queryCallbackMonitorStatus();
        const int rc = finishResult(L"monitor-status", result);
        if (rc == 0) printCallbackMonitorStatus(result);
        return rc;
    }
    if (subcommand == L"monitor-read")
    {
        const auto result = client.readCallbackMonitor(
            optionU64(args, L"--after-sequence", 0ULL),
            optionU32(args, L"--max-records", KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS));
        const int rc = finishResult(L"monitor-read", result);
        if (rc == 0) printCallbackMonitorRead(result, optionU32(args, L"--limit", 64U));
        return rc;
    }

    std::wcerr << L"error: unknown callback monitor subcommand '" << subcommand << L"'\n";
    return 1;
}
