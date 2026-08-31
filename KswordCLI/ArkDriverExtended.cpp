#include "ArkDriverExtended.h"

#include "../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cwctype>
#include <cwchar>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
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
            throw std::runtime_error("missing required r0 command option");
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
    bool printResultState(const wchar_t* label, const Result& result)
    {
        std::wcout << label << L": io_ok=" << (result.io.ok ? L"true" : L"false")
                   << L" bytes_returned=" << result.io.bytesReturned
                   << L" win32_error=" << result.io.win32Error
                   << L" nt_status=0x" << std::hex << static_cast<std::uint32_t>(result.io.ntStatus)
                   << std::dec << L"\n";
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
        return result.io.ok;
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
        return printResultState(label, result) ? 0 : 3;
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
    if (subcommand == L"hvm-status") return finishResult(L"hvm-status", client.queryHvmStatus());
    if (subcommand == L"hvm-events") return finishResult(L"hvm-events", client.queryHvmEvents(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", 128U), false));
    if (subcommand == L"ioctl-registry") return finishResult(L"ioctl-registry", client.queryIoctlRegistry(optionU32(args, L"--flags", KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER), optionU32(args, L"--max-entries", 512U)));
    if (subcommand == L"timer-dpc") return finishResult(L"timer-dpc", client.enumerateKernelTimerDpc(optionU32(args, L"--max-entries", KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES), optionU32(args, L"--max-per-bucket", KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET)));
    if (subcommand == L"unloaded") return finishResult(L"unloaded", client.queryUnloadedDrivers(parseUnloadedSource(optionValue(args, L"--source", L"mm")), optionU32(args, L"--max-rows", KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS)));
    if (subcommand == L"wfp-events") return finishResult(L"wfp-events", client.queryNetworkWfpEvents(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS)));
    if (subcommand == L"traffic") return finishResult(L"traffic", client.queryNetworkTrafficPackets(optionU64(args, L"--after-sequence", 0ULL), optionU32(args, L"--max-rows", KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS)));
    if (subcommand == L"piddb") return finishResult(L"piddb", client.queryPiDdb(optionU32(args, L"--max-rows", KSWORD_ARK_PIDDB_DEFAULT_ROWS)));
    if (subcommand == L"cpu-power") return finishResult(L"cpu-power", client.queryCpuPowerState());
    if (subcommand == L"process-protect") return finishResult(L"process-protect", client.queryProcessProtectState());
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
    if (subcommand == L"platform") return finishResult(L"platform", client.queryPlatformAudit(optionU32(args, L"--scope", KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL), optionU32(args, L"--max-rows", KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS)));
    if (subcommand == L"i8042") return finishResult(L"i8042", client.queryI8042Audit(optionU32(args, L"--max-rows", KSWORD_ARK_I8042_DEFAULT_MAX_ROWS)));
    if (subcommand == L"object-types") return finishResult(L"object-types", client.enumObjectTypeTable(optionU32(args, L"--flags", KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL), optionU32(args, L"--max-entries", 256U), optionU32(args, L"--start-index", 0U)));
    if (subcommand == L"win32k-timers") return finishResult(L"win32k-timers", client.queryWin32kTimers(optionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(args, L"--session-id", 0U), optionU32(args, L"--pid", 0U), optionU32(args, L"--tid", 0U), optionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)));
    if (subcommand == L"win32k-events") return finishResult(L"win32k-events", client.queryWin32kEventHooks(optionU32(args, L"--flags", KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL), optionU32(args, L"--session-id", 0U), optionU32(args, L"--pid", 0U), optionU32(args, L"--tid", 0U), optionU32(args, L"--max-entries", KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES)));

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
