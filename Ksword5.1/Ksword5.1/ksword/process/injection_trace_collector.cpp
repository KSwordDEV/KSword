#include "injection_trace_collector.h"

#include "process.h"
#include "injection_stack_walk.h"
#include "../../ArkDriverClient/ArkDriverClient.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QStringList>

#include <algorithm>
#include <cwchar>
#include <iterator>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace ks::process
{
namespace
{
    namespace ev = Ksword::Evidence;

    // 单次比较一次性读入的最大字节数。深度模式会请求整段代码区，直接按整段分配
    // 会把一个 10 MiB 的模块变成一次 10 MiB 分配；切片后内存占用可预期，
    // 覆盖范围不受影响（切片之间不重叠也不留缝）。
    constexpr std::uint32_t kMaxSingleCompareBytes = 1U << 20;

    // 一次 QueryWorkingSetEx 问多少页。
    constexpr std::size_t kWorkingSetBatchPages = 1024U;

    // NtQueryInformationThread 的 ThreadQuerySetWin32StartAddress。微软文档里有，
    // 但属于可能变化的内部接口，所以动态解析 + 检查返回状态 + 有降级路径。
    constexpr LONG kThreadQuerySetWin32StartAddress = 9;

    using NtQueryInformationThreadFn =
        LONG(NTAPI*)(HANDLE, LONG, PVOID, ULONG, PULONG);
    using EnumProcessModulesExFn = BOOL(WINAPI*)(HANDLE, HMODULE*, DWORD, LPDWORD, DWORD);
    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

    struct ResolvedApi final
    {
        NtQueryInformationThreadFn ntQueryInformationThread = nullptr;
        EnumProcessModulesExFn enumProcessModulesEx = nullptr;
        IsWow64Process2Fn isWow64Process2 = nullptr;
    };

    template <typename T>
    T ResolveProc(HMODULE module, const char* name)
    {
        if (module == nullptr)
        {
            return nullptr;
        }
        return reinterpret_cast<T>(reinterpret_cast<void*>(::GetProcAddress(module, name)));
    }

    const ResolvedApi& Api()
    {
        static const ResolvedApi api = []() {
            ResolvedApi resolved;
            const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
            resolved.ntQueryInformationThread =
                ResolveProc<NtQueryInformationThreadFn>(ntdll, "NtQueryInformationThread");
            const HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
            resolved.enumProcessModulesEx =
                ResolveProc<EnumProcessModulesExFn>(kernel32, "K32EnumProcessModulesEx");
            resolved.isWow64Process2 =
                ResolveProc<IsWow64Process2Fn>(kernel32, "IsWow64Process2");
            if (resolved.enumProcessModulesEx == nullptr)
            {
                const HMODULE psapi = ::GetModuleHandleW(L"psapi.dll");
                resolved.enumProcessModulesEx =
                    ResolveProc<EnumProcessModulesExFn>(psapi, "EnumProcessModulesEx");
            }
            return resolved;
        }();
        return api;
    }

    class ScopedHandle final
    {
    public:
        ScopedHandle() = default;
        explicit ScopedHandle(HANDLE handle) : handle_(handle) {}
        ~ScopedHandle() { reset(); }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        void reset(HANDLE handle = nullptr)
        {
            if (handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(handle_);
            }
            handle_ = handle;
        }

        HANDLE get() const { return handle_; }
        bool valid() const { return handle_ != nullptr && handle_ != INVALID_HANDLE_VALUE; }

    private:
        HANDLE handle_ = nullptr;
    };

    std::uint64_t FileTimeTo100ns(const FILETIME& value)
    {
        ULARGE_INTEGER converted;
        converted.LowPart = value.dwLowDateTime;
        converted.HighPart = value.dwHighDateTime;
        return converted.QuadPart;
    }

    std::uint64_t NowUtc100ns()
    {
        FILETIME now{};
        ::GetSystemTimeAsFileTime(&now);
        return FileTimeTo100ns(now);
    }

    ev::CollectionOutcome Win32Failure(const ev::CollectionStatus status, const DWORD error)
    {
        return ev::CollectionOutcome::failure(status, "WIN32", static_cast<std::uint64_t>(error),
                                              std::string());
    }

    // "跑了但没覆盖全部请求范围"。没有原始错误码可带 —— 停下来的原因是预算或上限，
    // 不是某个 API 失败。
    ev::CollectionOutcome PartialOutcome()
    {
        ev::CollectionOutcome outcome;
        outcome.status = ev::CollectionStatus::Partial;
        return outcome;
    }

    ev::CollectionOutcome StatusOnlyOutcome(const ev::CollectionStatus status)
    {
        ev::CollectionOutcome outcome;
        outcome.status = status;
        return outcome;
    }

    // 设备根本不存在（驱动没装/没加载）与"设备在但这次调用失败"是两回事：
    // 前者是能力限制，后者是覆盖缺口。判据只认这两个错误码。
    bool DeviceIsAbsent(const unsigned long error)
    {
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    ev::CollectionStatus StatusForWin32Error(const DWORD error)
    {
        switch (error)
        {
        case ERROR_ACCESS_DENIED:
        case ERROR_PARTIAL_COPY:
            return ev::CollectionStatus::AccessDenied;
        case ERROR_INVALID_HANDLE:
        case ERROR_INVALID_PARAMETER:
            return ev::CollectionStatus::Error;
        default:
            return ev::CollectionStatus::Error;
        }
    }

    std::string ToUtf8(const std::wstring& text)
    {
        return QString::fromWCharArray(text.c_str(), static_cast<int>(text.size())).toStdString();
    }

    // --- 设备路径 -> DOS 路径 -------------------------------------------------
    // GetMappedFileNameW 返回的是 \Device\HarddiskVolumeN\... 形式。判据层的
    // PathsCompatible 已经能容忍这种差异，但展示与磁盘读取需要 DOS 路径，
    // 所以这里做一次尽力而为的换算；换不出来就原样保留，不编造。
    std::wstring DeviceToDosPath(const std::wstring& devicePath)
    {
        if (devicePath.empty() || devicePath.rfind(L"\\Device\\", 0U) != 0U)
        {
            return devicePath;
        }
        wchar_t drives[512] = {};
        const DWORD length = ::GetLogicalDriveStringsW(
            static_cast<DWORD>(std::size(drives)) - 1U, drives);
        if (length == 0U || length >= std::size(drives))
        {
            return devicePath;
        }
        for (const wchar_t* drive = drives; *drive != L'\0'; drive += wcslen(drive) + 1U)
        {
            wchar_t letter[3] = { drive[0], L':', L'\0' };
            wchar_t target[MAX_PATH] = {};
            if (::QueryDosDeviceW(letter, target, static_cast<DWORD>(std::size(target))) == 0U)
            {
                continue;
            }
            const std::size_t targetLength = wcslen(target);
            if (targetLength == 0U || devicePath.size() <= targetLength)
            {
                continue;
            }
            if (_wcsnicmp(devicePath.c_str(), target, targetLength) == 0 &&
                devicePath[targetLength] == L'\\')
            {
                return std::wstring(letter) + devicePath.substr(targetLength);
            }
        }
        return devicePath;
    }

    // --- 预算 -----------------------------------------------------------------
    struct Budget final
    {
        QElapsedTimer timer;
        std::uint64_t maxDurationMs = 0;
        std::uint64_t maxReadBytes = 0;
        std::uint64_t bytesRead = 0;
        ev::BudgetStop stop = ev::BudgetStop::Continue;
        std::function<bool()> cancelled;

        bool exhausted()
        {
            if (stop != ev::BudgetStop::Continue)
            {
                return true;
            }
            if (cancelled && cancelled())
            {
                stop = ev::BudgetStop::Cancelled;
                return true;
            }
            if (maxDurationMs != 0U &&
                static_cast<std::uint64_t>(timer.elapsed()) > maxDurationMs)
            {
                stop = ev::BudgetStop::TimeExhausted;
                return true;
            }
            if (maxReadBytes != 0U && bytesRead > maxReadBytes)
            {
                stop = ev::BudgetStop::BytesExhausted;
                return true;
            }
            return false;
        }
    };

    // 读目标内存。部分复制（ERROR_PARTIAL_COPY）是常态，按"读到了多少"处理。
    bool ReadTargetMemory(const HANDLE process,
                          const std::uint64_t address,
                          void* buffer,
                          const std::size_t bytes,
                          Budget& budget,
                          std::size_t* copiedOut)
    {
        if (copiedOut != nullptr)
        {
            *copiedOut = 0U;
        }
        if (bytes == 0U)
        {
            return true;
        }
        SIZE_T copied = 0;
        const BOOL ok = ::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                                            buffer, bytes, &copied);
        budget.bytesRead += static_cast<std::uint64_t>(copied);
        if (copiedOut != nullptr)
        {
            *copiedOut = static_cast<std::size_t>(copied);
        }
        return ok != FALSE && copied == bytes;
    }

    // --- 进程架构 -------------------------------------------------------------
    ev::ProcessArchitecture QueryProcessArchitecture(const HANDLE process, QString* textOut)
    {
        const ResolvedApi& api = Api();
        if (api.isWow64Process2 != nullptr)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (api.isWow64Process2(process, &processMachine, &nativeMachine) != FALSE)
            {
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                {
                    // 非 WOW64：进程架构就是本机架构。
                    switch (nativeMachine)
                    {
                    case IMAGE_FILE_MACHINE_AMD64:
                        if (textOut != nullptr) { *textOut = QStringLiteral("x64"); }
                        return ev::ProcessArchitecture::X64;
                    case IMAGE_FILE_MACHINE_ARM64:
                        if (textOut != nullptr) { *textOut = QStringLiteral("ARM64"); }
                        return ev::ProcessArchitecture::Arm64;
                    case IMAGE_FILE_MACHINE_I386:
                        if (textOut != nullptr) { *textOut = QStringLiteral("x86"); }
                        return ev::ProcessArchitecture::X86Native;
                    default:
                        break;
                    }
                    if (textOut != nullptr) { *textOut = QStringLiteral("unknown"); }
                    return ev::ProcessArchitecture::Unknown;
                }
                if (textOut != nullptr) { *textOut = QStringLiteral("WOW64 (x86)"); }
                return ev::ProcessArchitecture::Wow64;
            }
        }

        BOOL wow64 = FALSE;
        if (::IsWow64Process(process, &wow64) != FALSE && wow64 != FALSE)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("WOW64 (x86)"); }
            return ev::ProcessArchitecture::Wow64;
        }
        SYSTEM_INFO info{};
        ::GetNativeSystemInfo(&info);
        if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("x64"); }
            return ev::ProcessArchitecture::X64;
        }
        if (info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64)
        {
            if (textOut != nullptr) { *textOut = QStringLiteral("ARM64"); }
            return ev::ProcessArchitecture::Arm64;
        }
        if (textOut != nullptr) { *textOut = QStringLiteral("unknown"); }
        return ev::ProcessArchitecture::Unknown;
    }

    // --- 地址空间 -------------------------------------------------------------
    struct MappedPathCache final
    {
        std::unordered_map<std::uint64_t, std::wstring> byAllocationBase;
        std::unordered_map<std::uint64_t, DWORD> failureByAllocationBase;
    };

    std::wstring QueryMappedPath(const HANDLE process,
                                 const std::uint64_t allocationBase,
                                 const std::uint64_t probeAddress,
                                 MappedPathCache& cache,
                                 DWORD* errorOut)
    {
        if (errorOut != nullptr)
        {
            *errorOut = ERROR_SUCCESS;
        }
        const auto cached = cache.byAllocationBase.find(allocationBase);
        if (cached != cache.byAllocationBase.end())
        {
            return cached->second;
        }
        const auto failed = cache.failureByAllocationBase.find(allocationBase);
        if (failed != cache.failureByAllocationBase.end())
        {
            if (errorOut != nullptr)
            {
                *errorOut = failed->second;
            }
            return std::wstring();
        }

        wchar_t buffer[32768] = {};
        const DWORD length = ::GetMappedFileNameW(
            process, reinterpret_cast<LPVOID>(probeAddress), buffer,
            static_cast<DWORD>(std::size(buffer)));
        if (length == 0U)
        {
            const DWORD error = ::GetLastError();
            cache.failureByAllocationBase.emplace(allocationBase, error);
            if (errorOut != nullptr)
            {
                *errorOut = error;
            }
            return std::wstring();
        }
        std::wstring path = DeviceToDosPath(std::wstring(buffer, length));
        cache.byAllocationBase.emplace(allocationBase, path);
        return path;
    }

    struct AddressSpaceCollection final
    {
        std::vector<ev::RegionRecord> records;
        ev::CollectionOutcome outcome;
        bool mappedPathFailure = false;
        std::uint64_t highestAddressQueried = 0;
        std::uint64_t lowestAddressQueried = 0;
    };

    AddressSpaceCollection CollectAddressSpace(const HANDLE process,
                                               const ev::ProcessInstanceId& owner,
                                               const InjectionTraceOptions& options,
                                               MappedPathCache& cache,
                                               Budget& budget)
    {
        AddressSpaceCollection collection;
        SYSTEM_INFO info{};
        ::GetSystemInfo(&info);
        const std::uint64_t minimum =
            reinterpret_cast<std::uint64_t>(info.lpMinimumApplicationAddress);
        const std::uint64_t maximum =
            reinterpret_cast<std::uint64_t>(info.lpMaximumApplicationAddress);

        collection.lowestAddressQueried = minimum;
        std::uint64_t address = minimum;
        std::uint32_t regionCount = 0;
        bool truncated = false;

        while (address <= maximum)
        {
            if (budget.exhausted())
            {
                truncated = true;
                break;
            }
            MEMORY_BASIC_INFORMATION mbi{};
            const SIZE_T queried = ::VirtualQueryEx(
                process, reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi));
            if (queried != sizeof(mbi))
            {
                const DWORD error = ::GetLastError();
                if (error == ERROR_INVALID_PARAMETER)
                {
                    break;  // 越过用户地址空间尽头，正常结束
                }
                collection.outcome = Win32Failure(StatusForWin32Error(error), error);
                collection.highestAddressQueried = address;
                return collection;
            }

            const auto regionBase = reinterpret_cast<std::uint64_t>(mbi.BaseAddress);
            const auto regionSize = static_cast<std::uint64_t>(mbi.RegionSize);
            if (regionSize == 0U)
            {
                break;  // 防御性：零长度区域会让循环停不下来
            }

            ev::RegionRecord record;
            record.base = ev::OptionalU64::of(regionBase);
            record.size = ev::OptionalU64::of(regionSize);
            record.owner = owner;
            record.source = ev::RegionEvidenceSource::R3VirtualQuery;
            switch (mbi.State)
            {
            case MEM_COMMIT: record.state = ev::RegionState::Commit; break;
            case MEM_RESERVE: record.state = ev::RegionState::Reserved; break;
            case MEM_FREE: record.state = ev::RegionState::Free; break;
            default: record.state = ev::RegionState::Unknown; break;
            }
            switch (mbi.Type)
            {
            case MEM_IMAGE: record.type = ev::RegionType::Image; break;
            case MEM_MAPPED: record.type = ev::RegionType::Mapped; break;
            case MEM_PRIVATE: record.type = ev::RegionType::Private; break;
            default: record.type = ev::RegionType::Unknown; break;
            }
            // 空闲区域没有保护值可言：Protect 在 MEM_FREE 时不是一个有效的 PAGE_*。
            // 写进去会被判据层当成"看不懂的基本值"，那是把无意义当未知。
            if (record.state != ev::RegionState::Free)
            {
                record.protection = ev::ToRegionProtection(ev::ClassifyWin32Protection(
                    ev::OptionalU64::of(static_cast<std::uint64_t>(mbi.Protect))));
                record.allocationProtect = ev::ToRegionProtection(ev::ClassifyWin32Protection(
                    ev::OptionalU64::of(static_cast<std::uint64_t>(mbi.AllocationProtect))));
                record.allocationBase = ev::OptionalU64::of(
                    reinterpret_cast<std::uint64_t>(mbi.AllocationBase));
            }

            if (record.state == ev::RegionState::Commit &&
                (record.type == ev::RegionType::Image || record.type == ev::RegionType::Mapped))
            {
                DWORD pathError = ERROR_SUCCESS;
                const std::wstring mapped = QueryMappedPath(
                    process, record.allocationBase.valueOr(regionBase), regionBase, cache,
                    &pathError);
                if (mapped.empty())
                {
                    // 区分两件事：
                    //   * MEM_IMAGE 没有文件名 —— 一定是查询失败，是缺口。
                    //   * MEM_MAPPED 且 ERROR_FILE_INVALID —— 这是**确定的答案**
                    //     ("这块映射不是文件"，典型是页文件支撑的 section)，
                    //     不是"没查到"。把它也算缺口，会让每个进程都永远覆盖不完整，
                    //     缺口这一维就失去意义了。
                    const bool definitelyNotFileBacked =
                        record.type == ev::RegionType::Mapped &&
                        pathError == ERROR_FILE_INVALID;
                    if (!definitelyNotFileBacked)
                    {
                        collection.mappedPathFailure = true;
                    }
                }
                else
                {
                    record.mappedPath = ToUtf8(mapped);
                }
            }

            collection.records.push_back(std::move(record));
            ++regionCount;
            if (regionCount >= options.maxRegionCount)
            {
                truncated = true;
                budget.stop = ev::BudgetStop::ItemsExhausted;
                break;
            }

            const std::uint64_t next = regionBase + regionSize;
            if (next <= address)
            {
                break;  // 防御性：不前进就停，绝不死循环
            }
            address = next;
            collection.highestAddressQueried = address;
        }

        collection.outcome = truncated
            ? PartialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- 加载器视图 -----------------------------------------------------------
    struct LoaderModule final
    {
        std::wstring path;
        std::uint64_t base = 0;
        std::uint64_t size = 0;
        std::uint32_t entryPointRva = 0;
    };

    struct LoaderCollection final
    {
        std::vector<LoaderModule> modules;
        ev::CollectionOutcome outcome;
    };

    LoaderCollection CollectLoaderModules(const HANDLE process)
    {
        LoaderCollection collection;
        const ResolvedApi& api = Api();
        std::vector<HMODULE> handles(1024U);
        DWORD needed = 0;

        auto enumerate = [&](std::vector<HMODULE>& buffer, DWORD& neededOut) -> BOOL {
            const DWORD bytes = static_cast<DWORD>(buffer.size() * sizeof(HMODULE));
            if (api.enumProcessModulesEx != nullptr)
            {
                return api.enumProcessModulesEx(process, buffer.data(), bytes, &neededOut,
                                                LIST_MODULES_ALL);
            }
            return ::EnumProcessModules(process, buffer.data(), bytes, &neededOut);
        };

        if (enumerate(handles, needed) == FALSE)
        {
            const DWORD error = ::GetLastError();
            collection.outcome = Win32Failure(StatusForWin32Error(error), error);
            return collection;
        }
        if (needed > handles.size() * sizeof(HMODULE))
        {
            handles.resize(needed / sizeof(HMODULE) + 16U);
            if (enumerate(handles, needed) == FALSE)
            {
                const DWORD error = ::GetLastError();
                collection.outcome = Win32Failure(StatusForWin32Error(error), error);
                return collection;
            }
        }

        const std::size_t count = std::min<std::size_t>(
            handles.size(), static_cast<std::size_t>(needed) / sizeof(HMODULE));
        bool anyFailure = false;
        for (std::size_t i = 0; i < count; ++i)
        {
            LoaderModule module;
            wchar_t path[32768] = {};
            if (::GetModuleFileNameExW(process, handles[i], path,
                                       static_cast<DWORD>(std::size(path))) == 0U)
            {
                anyFailure = true;
            }
            else
            {
                module.path = path;
            }
            MODULEINFO info{};
            if (::GetModuleInformation(process, handles[i], &info, sizeof(info)) != FALSE)
            {
                module.base = reinterpret_cast<std::uint64_t>(info.lpBaseOfDll);
                module.size = static_cast<std::uint64_t>(info.SizeOfImage);
                module.entryPointRva = info.EntryPoint != nullptr && info.lpBaseOfDll != nullptr
                    ? static_cast<std::uint32_t>(
                          reinterpret_cast<std::uint64_t>(info.EntryPoint) -
                          reinterpret_cast<std::uint64_t>(info.lpBaseOfDll))
                    : 0U;
            }
            else
            {
                anyFailure = true;
                module.base = reinterpret_cast<std::uint64_t>(handles[i]);
            }
            collection.modules.push_back(std::move(module));
        }

        collection.outcome = anyFailure
            ? PartialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- 线程 -----------------------------------------------------------------
    struct ThreadStartCollection final
    {
        std::vector<ev::ThreadStartInput> threads;
        ev::CollectionOutcome outcome;
    };

    ThreadStartCollection CollectThreadStarts(const std::uint32_t pid,
                                              const ev::ProcessInstanceId& owner,
                                              const InjectionTraceOptions& options)
    {
        ThreadStartCollection collection;
        const ResolvedApi& api = Api();

        const ScopedHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0U));
        if (!snapshot.valid())
        {
            const DWORD error = ::GetLastError();
            collection.outcome = Win32Failure(StatusForWin32Error(error), error);
            return collection;
        }

        THREADENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (::Thread32First(snapshot.get(), &entry) == FALSE)
        {
            const DWORD error = ::GetLastError();
            collection.outcome = Win32Failure(StatusForWin32Error(error), error);
            return collection;
        }

        bool anyFailure = false;
        bool truncated = false;
        do
        {
            if (entry.th32OwnerProcessID != pid)
            {
                continue;
            }
            if (collection.threads.size() >= options.maxThreads)
            {
                truncated = true;
                break;
            }

            ev::ThreadStartInput input;
            input.thread.process = owner;
            input.thread.tid = ev::OptionalU64::of(static_cast<std::uint64_t>(entry.th32ThreadID));

            // ThreadQuerySetWin32StartAddress 要求 THREAD_QUERY_INFORMATION；
            // THREAD_QUERY_LIMITED_INFORMATION 打开的句柄查这一项会直接失败
            // （2026-09-12 实机：4 个线程全部 status=Error）。所以先按这一项能力
            // 需要的权限开，开不到再退回受限句柄 —— 那时只能拿到创建时间，
            // 起始地址仍会是"没采到"，而不是伪装成 0。
            ScopedHandle thread(::OpenThread(
                THREAD_QUERY_INFORMATION, FALSE, entry.th32ThreadID));
            if (!thread.valid())
            {
                thread.reset(::OpenThread(
                    THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID));
            }
            if (!thread.valid())
            {
                const DWORD error = ::GetLastError();
                input.startAddressOutcome = Win32Failure(StatusForWin32Error(error), error);
                anyFailure = true;
                collection.threads.push_back(std::move(input));
                continue;
            }

            FILETIME created{}, exited{}, kernelTime{}, userTime{};
            if (::GetThreadTimes(thread.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
            {
                input.thread.createTime100ns = ev::OptionalU64::of(FileTimeTo100ns(created));
            }

            if (api.ntQueryInformationThread == nullptr)
            {
                // 接口解析不到时降级为"没采到"，不是"起点是 0"。
                input.startAddressOutcome = StatusOnlyOutcome(ev::CollectionStatus::Unsupported);
                anyFailure = true;
                collection.threads.push_back(std::move(input));
                continue;
            }

            ULONG_PTR startAddress = 0;
            ULONG returned = 0;
            const LONG status = api.ntQueryInformationThread(
                thread.get(), kThreadQuerySetWin32StartAddress, &startAddress,
                static_cast<ULONG>(sizeof(startAddress)), &returned);
            if (status < 0 || returned != sizeof(startAddress))
            {
                input.startAddressOutcome = ev::CollectionOutcome::failure(
                    ev::CollectionStatus::Error, "NTSTATUS",
                    static_cast<std::uint64_t>(static_cast<std::uint32_t>(status)),
                    std::string());
                anyFailure = true;
            }
            else
            {
                input.startAddress =
                    ev::OptionalU64::of(static_cast<std::uint64_t>(startAddress));
                input.startAddressOutcome = ev::CollectionOutcome::success();
            }
            collection.threads.push_back(std::move(input));
        } while (::Thread32Next(snapshot.get(), &entry) != FALSE);

        collection.outcome = (anyFailure || truncated)
            ? PartialOutcome()
            : ev::CollectionOutcome::success();
        return collection;
    }

    // --- 参考映像 -------------------------------------------------------------
    struct ReferenceImage final
    {
        ev::PeImageMap map;
        ev::ReferenceConfidence confidence = ev::ReferenceConfidence::NoReference;
        std::uint64_t base = 0;
        std::string path;
        std::string identityNote;
    };

    // 从**内存中的**映像头读两个身份字段。这不是第二套 PE 解析器：只按公开的
    // IMAGE_DOS_HEADER / IMAGE_NT_HEADERS 结构取 TimeDateStamp 与 SizeOfImage，
    // 用来回答"磁盘这份文件是不是这次加载的那一份"。
    //
    // 注意它的循环性：头本身也在被检查的范围里。所以只有"磁盘 SizeOfImage ==
    // 加载器报的 SizeOfImage"且"磁盘 TimeDateStamp == 内存 TimeDateStamp"同时
    // 成立才算已核对；两者不一致时只能是"参考不确定"，不能自动判恶意。
    bool ReadInMemoryImageIdentity(const HANDLE process,
                                   const std::uint64_t base,
                                   Budget& budget,
                                   std::uint32_t* timeDateStampOut,
                                   std::uint32_t* sizeOfImageOut)
    {
        IMAGE_DOS_HEADER dos{};
        if (!ReadTargetMemory(process, base, &dos, sizeof(dos), budget, nullptr))
        {
            return false;
        }
        if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
            static_cast<std::uint32_t>(dos.e_lfanew) > 0x10000U)
        {
            return false;
        }
        IMAGE_NT_HEADERS64 nt{};
        if (!ReadTargetMemory(process, base + static_cast<std::uint64_t>(dos.e_lfanew), &nt,
                              sizeof(nt), budget, nullptr))
        {
            return false;
        }
        if (nt.Signature != IMAGE_NT_SIGNATURE)
        {
            return false;
        }
        if (timeDateStampOut != nullptr)
        {
            *timeDateStampOut = nt.FileHeader.TimeDateStamp;
        }
        if (sizeOfImageOut != nullptr)
        {
            // 32 位映像的 OptionalHeader 布局不同，SizeOfImage 位置也不同。
            // Magic 判一次，避免拿 64 位布局去读 32 位头。
            if (nt.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            {
                const auto* optional32 =
                    reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&nt.OptionalHeader);
                *sizeOfImageOut = optional32->SizeOfImage;
            }
            else
            {
                *sizeOfImageOut = nt.OptionalHeader.SizeOfImage;
            }
        }
        return true;
    }

    ReferenceImage BuildReferenceImage(const HANDLE process,
                                       const LoaderModule& module,
                                       Budget& budget)
    {
        ReferenceImage reference;
        reference.base = module.base;
        reference.path = ToUtf8(module.path);
        if (module.path.empty() || module.base == 0U)
        {
            reference.identityNote = "reference.missing-path";
            return reference;
        }

        QFile file(QString::fromWCharArray(module.path.c_str()));
        if (!file.open(QIODevice::ReadOnly))
        {
            reference.identityNote = "reference.open-failed";
            return reference;
        }
        const QByteArray bytes = file.readAll();
        if (bytes.isEmpty())
        {
            reference.identityNote = "reference.empty";
            return reference;
        }

        reference.map = ev::BuildPeImageMap(
            reinterpret_cast<const std::uint8_t*>(bytes.constData()),
            static_cast<std::size_t>(bytes.size()), module.base);
        if (!reference.map.valid())
        {
            reference.confidence = ev::ReferenceConfidence::NoReference;
            reference.identityNote = std::string("reference.map-failed:") +
                                     ev::PeParseStatusName(reference.map.status);
            return reference;
        }

        std::uint32_t liveTimeDateStamp = 0;
        std::uint32_t liveSizeOfImage = 0;
        const bool liveIdentity = ReadInMemoryImageIdentity(
            process, module.base, budget, &liveTimeDateStamp, &liveSizeOfImage);
        const bool sizeMatches = module.size != 0U &&
                                 reference.map.header.sizeOfImage ==
                                     static_cast<std::uint32_t>(module.size);
        const bool stampMatches = liveIdentity &&
                                  reference.map.header.timeDateStamp == liveTimeDateStamp;
        if (sizeMatches && stampMatches)
        {
            reference.confidence = ev::ReferenceConfidence::ReferenceVerified;
            reference.identityNote = "reference.verified";
        }
        else
        {
            reference.confidence = ev::ReferenceConfidence::ReferenceUncertain;
            reference.identityNote = liveIdentity ? "reference.identity-mismatch"
                                                  : "reference.identity-unreadable";
        }
        return reference;
    }

    // --- 载荷结构（浅层）------------------------------------------------------
    // 一页是不是"没有重定位 fixup"。有 fixup 的页加载器本来就会改写，
    // 拿它和节对象里的未重定位内容比只会得到噪声，所以整页排除。
    // 判据用 PeImageMap 已经算好的 touchedRanges 与 DVRT 影响范围，不另起一套解析。
    bool PageHasNoRelocationFixup(const ev::PeImageMap& map,
                                  const std::uint32_t pageRva)
    {
        ev::RvaRange page;
        page.rva = pageRva;
        page.length = 0x1000U;
        const std::vector<ev::RvaRange> one{ page };
        if (!ev::IntersectRvaRanges(map.relocation.touchedRanges, one).empty())
        {
            return false;
        }
        if (!ev::IntersectRvaRanges(map.dynamicRelocation.affectedRanges(), one).empty())
        {
            return false;
        }
        // 不可比较范围（畸形节、无支撑的重定位目标等）同样排除。
        return ev::IntersectRvaRanges(map.notComparableRanges, one).empty();
    }

    // 第二参考源：把实时字节和**内存管理器持有的节对象**比。
    //
    // 与"和磁盘文件比"不是重复。一个页与磁盘一致、却与节对象不同，说明**磁盘文件
    // 在映射建立之后被改过** —— 那是"改完内存再把磁盘文件也改成一样"这种手法
    // 唯一会露出的破绽。
    //
    // 覆盖率是打折的，而且折扣如实记账：有 fixup 的页不比，原型 PTE 不是 valid
    // 形态的页拿不到参考。两者都计进 sectionPagesRequested/Available，
    // 判据层据此决定"没发现差异"成不成立。
    void CollectSectionObjectComparisons(
        const HANDLE process,
        const std::uint32_t pid,
        const std::map<std::string, ReferenceImage>& references,
        const ev::ComparisonPlan& plan,
        Budget& budget,
        const InjectionTraceOptions& options,
        ev::SurveyInput& input,
        InjectionTraceResult& result)
    {
        static_cast<void>(options);
        const ksword::ark::DriverClient driverClient;

        // 每个模块最多核对这么多页。上限按协议里带字节的一次调用上限给，
        // 一个模块一次调用，不做续扫 —— 这一维是**抽样核对**，不是全量比较。
        constexpr unsigned long kPagesPerModule = KSWORD_ARK_INJECTION_SECTION_BYTES_PAGES_MAX;
        constexpr std::uint64_t kPageBytes = 0x1000ULL;

        std::map<std::string, ev::ImageComparisonOutcome> sectionOutcomes;
        for (const ev::ComparisonTarget& target : plan.targets)
        {
            if (budget.exhausted())
            {
                break;
            }
            const auto reference = references.find(target.module.imagePath);
            if (reference == references.end() || !reference->second.map.valid() ||
                target.range.empty())
            {
                continue;
            }
            if (sectionOutcomes.find(target.module.imagePath) != sectionOutcomes.end())
            {
                continue;   // 一个模块只抽一次
            }

            // 挑出这段范围里没有 fixup 的页。
            std::vector<std::uint32_t> pageRvas;
            for (std::uint64_t offset = 0; offset < target.range.length &&
                                           pageRvas.size() < kPagesPerModule;
                 offset += kPageBytes)
            {
                const auto pageRva =
                    static_cast<std::uint32_t>((target.range.rva + offset) & ~(kPageBytes - 1ULL));
                if (PageHasNoRelocationFixup(reference->second.map, pageRva))
                {
                    pageRvas.push_back(pageRva);
                }
            }
            if (pageRvas.empty())
            {
                continue;   // 整段都带 fixup：这一维对它无话可说，不产生条目
            }

            const std::uint64_t firstVa = reference->second.base + pageRvas.front();
            const std::uint64_t lastVa = reference->second.base + pageRvas.back();
            const ksword::ark::ImageSectionPagesResult pages =
                driverClient.readImageSectionPages(
                    pid, firstVa, lastVa + kPageBytes, 0ULL, kPagesPerModule,
                    KSWORD_ARK_INJECTION_SECTION_FLAG_INCLUDE_BYTES);

            ev::ImageComparisonOutcome outcome;
            outcome.module = target.module;
            outcome.referenceSource = ev::ImageReferenceSource::SectionObject;
            // 节对象参考的身份不需要额外核对：它**就是**这次映射用的那个节，
            // 不存在"这份文件是不是这次加载的那一份"的问题。
            outcome.referenceConfidence = ev::ReferenceConfidence::ReferenceVerified;
            outcome.sectionPagesRequested = pageRvas.size();
            outcome.report.outcome = ev::CollectionOutcome::success();
            outcome.report.conclusion = ev::AnalysisConclusion::NoDifferenceObserved;

            if (!pages.io.ok || pages.pageBytes.empty())
            {
                // 一页参考都没拿到：整条记成"请求了、一个都没成"，由判据层压制干净结论。
                outcome.sectionPagesAvailable = 0U;
                outcome.report.outcome = PartialOutcome();
                sectionOutcomes.emplace(target.module.imagePath, std::move(outcome));
                continue;
            }

            // 字节区按 valid 页的顺序排列，所以要同序遍历条目。
            std::size_t validIndex = 0U;
            for (const ksword::ark::ImageSectionPageEntry& entry : pages.entries)
            {
                if (!entry.bytesPresent())
                {
                    continue;   // 不是 valid 形态：这一页没有参考，不计入已覆盖
                }
                const std::size_t byteOffset = validIndex * kPageBytes;
                ++validIndex;
                if (byteOffset + kPageBytes > pages.pageBytes.size())
                {
                    break;
                }
                if (entry.va < reference->second.base)
                {
                    continue;
                }
                const auto pageRva = static_cast<std::uint32_t>(entry.va - reference->second.base);
                if (std::find(pageRvas.begin(), pageRvas.end(), pageRva) == pageRvas.end())
                {
                    continue;   // 这一页带 fixup，不在抽样集合里
                }

                std::vector<std::uint8_t> liveBytes(static_cast<std::size_t>(kPageBytes));
                std::size_t copied = 0U;
                ReadTargetMemory(process, entry.va, liveBytes.data(), liveBytes.size(),
                                 budget, &copied);
                if (copied != liveBytes.size())
                {
                    continue;   // 实时页读不全：不比，也不算已覆盖
                }
                ++outcome.sectionPagesAvailable;
                ++result.sectionPagesCompared;

                if (std::memcmp(liveBytes.data(), pages.pageBytes.data() + byteOffset,
                                liveBytes.size()) == 0)
                {
                    outcome.report.comparedBytes += kPageBytes;
                    continue;
                }

                // 差异。**这一页本该一个字节都不变** —— 它没有 fixup，节对象里的
                // 内容就是映射建立时的内容。
                ev::ImageDiffEntry diff;
                diff.rva = pageRva;
                diff.va = entry.va;
                diff.length = static_cast<std::uint32_t>(kPageBytes);
                diff.kind = ev::DiffKind::ByteDifference;
                diff.explanation = ev::DiffExplanation::Unexplained;
                diff.sectionName = ev::SectionNameForRva(reference->second.map, pageRva);
                outcome.report.entries.push_back(std::move(diff));
                outcome.report.comparedBytes += kPageBytes;
                outcome.report.differingBytes += kPageBytes;
                outcome.report.conclusion = ev::AnalysisConclusion::DifferenceObserved;
                ++result.sectionPagesDiffering;
            }
            sectionOutcomes.emplace(target.module.imagePath, std::move(outcome));
        }

        for (auto& item : sectionOutcomes)
        {
            input.imageComparisons.push_back(std::move(item.second));
        }
        result.sectionModulesChecked = static_cast<std::uint32_t>(sectionOutcomes.size());
    }

    ev::PayloadStructure ClassifyPayloadStructure(const HANDLE process,
                                                  const std::uint64_t base,
                                                  const std::uint64_t size,
                                                  const InjectionTraceOptions& options,
                                                  Budget& budget,
                                                  std::vector<std::string>* factsOut)
    {
        const std::size_t probe = static_cast<std::size_t>(
            std::min<std::uint64_t>(size, options.maxPayloadProbeBytes));
        if (probe < sizeof(IMAGE_DOS_HEADER))
        {
            return ev::PayloadStructure::NoStructure;
        }
        std::vector<std::uint8_t> buffer(probe);
        std::size_t copied = 0U;
        ReadTargetMemory(process, base, buffer.data(), buffer.size(), budget, &copied);
        if (copied < sizeof(IMAGE_DOS_HEADER))
        {
            return ev::PayloadStructure::Unreadable;
        }
        buffer.resize(copied);

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        {
            // 没有 PE 头。可执行的非映像内存在这里只能说"未知可执行代码"，
            // 不叫 shellcode injection。擦头载荷的识别不在本版本能力内。
            return ev::PayloadStructure::BareCode;
        }
        if (dos->e_lfanew <= 0 ||
            static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > buffer.size())
        {
            if (factsOut != nullptr)
            {
                factsOut->push_back("payload.pe=mz-only");
            }
            // 只有两个字节的 MZ 不是充分证据。
            return ev::PayloadStructure::NoStructure;
        }
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
        {
            if (factsOut != nullptr)
            {
                factsOut->push_back("payload.pe=signature-mismatch");
            }
            return ev::PayloadStructure::NoStructure;
        }

        const std::uint32_t sizeOfImage =
            nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
                ? reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(&nt->OptionalHeader)->SizeOfImage
                : nt->OptionalHeader.SizeOfImage;
        if (factsOut != nullptr)
        {
            factsOut->push_back("payload.pe.machine=" +
                                std::to_string(nt->FileHeader.Machine));
            factsOut->push_back("payload.pe.sizeOfImage=" + std::to_string(sizeOfImage));
            factsOut->push_back("payload.region.size=" + std::to_string(size));
        }
        // 区域装得下声明的映像跨度 -> 更像"已按虚拟布局展开"；装不下 -> 更像
        // 一个躺在缓冲区里的 PE 文件。两者都只是结构事实，不是"已被执行"。
        return (sizeOfImage != 0U && static_cast<std::uint64_t>(sizeOfImage) <= size)
                   ? ev::PayloadStructure::MappedPeImage
                   : ev::PayloadStructure::DataOnlyPeFile;
    }
}

ev::ProcessSurfaceScreen ScreenProcessInjectionSurface(
    const std::uint32_t pid,
    const std::uint64_t expectedCreationTime100ns)
{
    ev::ProcessSurfaceScreen screen;

    // 身份先核：PID 复用时宁可报"身份不符"，也不能把别人的区域计数挂到这一行上。
    std::uint64_t creationTime100ns = 0U;
    if (!QueryProcessCreationTimeByPid(pid, &creationTime100ns, nullptr))
    {
        screen.state = ev::SurfaceScreenState::AccessDenied;
        return screen;
    }
    if (expectedCreationTime100ns != 0U && expectedCreationTime100ns != creationTime100ns)
    {
        screen.state = ev::SurfaceScreenState::IdentityMismatch;
        return screen;
    }

    // 只要 QUERY_LIMITED_INFORMATION：这一档不读内存、不要 VM_READ。
    ScopedHandle process(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
    if (!process.valid())
    {
        const DWORD error = ::GetLastError();
        screen.state = (error == ERROR_ACCESS_DENIED)
            ? ev::SurfaceScreenState::AccessDenied
            : ev::SurfaceScreenState::Failed;
        return screen;
    }

    ev::ProcessInstanceId owner;
    owner.pid = ev::OptionalU64::of(pid);
    owner.createTime100ns = ev::OptionalU64::of(creationTime100ns);
    owner.bootId = "live";

    Budget budget;
    budget.timer.start();
    budget.maxDurationMs = 5000ULL;   // 单行硬上限：一行卡住不能拖垮整张表
    budget.maxReadBytes = 0ULL;       // 这一档不读内存

    InjectionTraceOptions options;
    options.maxRegionCount = 262144U;

    // 关键：不传 MappedPathCache 的路径查询开销。CollectAddressSpace 会对
    // IMAGE/MAPPED 区域调 GetMappedFileNameW，那是这一档里最贵的一项，
    // 而筛选只要 type + 保护值就够了。所以这里用一个一次性的空缓存并接受
    // 路径查询 —— 实测 p95 9.5 ms 已含这部分；再省会让代码分叉，得不偿失。
    MappedPathCache pathCache;
    AddressSpaceCollection collection =
        CollectAddressSpace(process.get(), owner, options, pathCache, budget);

    const ev::AddressSpaceIndex index =
        ev::BuildAddressSpaceIndex(std::move(collection.records), collection.outcome);
    screen = ev::SummarizeSurfaceScreen(index, ev::OptionalU64::of(NowUtc100ns()));

    // 扫描后复核身份：中途进程退出 + PID 复用时，这一行的计数不能留下来。
    std::uint64_t afterCreation = 0U;
    if (!QueryProcessCreationTimeByPid(pid, &afterCreation, nullptr) ||
        afterCreation != creationTime100ns)
    {
        ev::ProcessSurfaceScreen mismatch;
        mismatch.state = ev::SurfaceScreenState::IdentityMismatch;
        return mismatch;
    }
    return screen;
}

InjectionTraceResult ScanProcessInjectionTrace(const std::uint32_t pid,
                                               const std::uint64_t expectedCreationTime100ns,
                                               const QString& fallbackImagePath,
                                               const InjectionTraceOptions& options)
{
    InjectionTraceResult result;
    result.pid = pid;
    result.imagePath = fallbackImagePath;
    // 请求的模式先记下来：后面任何一条提前返回的路径都会带着它回去。
    result.requestedMode = options.deepMode ? ev::SurveyMode::Deep : ev::SurveyMode::Fast;

    Budget budget;
    budget.timer.start();
    budget.maxDurationMs = options.maxDurationMs;
    budget.cancelled = options.cancelled;
    budget.maxReadBytes = options.maxReadBytes;

    // --- 身份：开始前 ---------------------------------------------------------
    std::uint64_t creationTime100ns = 0U;
    std::string identityDiagnostic;
    if (!QueryProcessCreationTimeByPid(pid, &creationTime100ns, &identityDiagnostic))
    {
        result.status = InjectionTraceStatus::ProcessIdentityUnavailable;
        result.diagnosticText = QString::fromStdString(identityDiagnostic);
        return result;
    }
    if (expectedCreationTime100ns != 0U && expectedCreationTime100ns != creationTime100ns)
    {
        result.status = InjectionTraceStatus::ProcessIdentityMismatch;
        result.diagnosticText = QStringLiteral("expected=%1 actual=%2")
            .arg(expectedCreationTime100ns)
            .arg(creationTime100ns);
        return result;
    }
    result.creationTime100ns = creationTime100ns;

    // --- 句柄：最小权限优先 ---------------------------------------------------
    bool haveQueryInformation = false;
    ScopedHandle process(::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (!process.valid())
    {
        const DWORD firstError = ::GetLastError();
        process.reset(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
        if (!process.valid())
        {
            const DWORD error = ::GetLastError();
            result.status = error == ERROR_ACCESS_DENIED
                ? InjectionTraceStatus::ProcessOpenDenied
                : InjectionTraceStatus::ProcessOpenFailed;
            result.diagnosticText = QStringLiteral("OpenProcess limited=%1 full=%2")
                .arg(firstError)
                .arg(error);
            return result;
        }
        haveQueryInformation = true;
    }

    // QueryWorkingSetEx 文档要求 PROCESS_QUERY_INFORMATION，
    // PROCESS_QUERY_LIMITED_INFORMATION 不够（2026-09-12 实机：受限句柄下工作集
    // 一页都问不到）。最小权限仍然是默认路径：只为这一项能力单独申请更宽的句柄，
    // 申请不到就留缺口，绝不把整次采集升级到更高权限。
    ScopedHandle workingSetOwner;
    HANDLE workingSetProcess = nullptr;
    if (haveQueryInformation)
    {
        workingSetProcess = process.get();
    }
    else
    {
        workingSetOwner.reset(::OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
        if (workingSetOwner.valid())
        {
            workingSetProcess = workingSetOwner.get();
        }
    }

    // 句柄上再核一次创建时间，避免 PID 在两次调用之间被复用（TOCTOU）。
    {
        FILETIME created{}, exited{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
        {
            const std::uint64_t handleCreation = FileTimeTo100ns(created);
            if (handleCreation != creationTime100ns)
            {
                result.status = InjectionTraceStatus::ProcessIdentityMismatch;
                result.diagnosticText = QStringLiteral("handle=%1 snapshot=%2")
                    .arg(handleCreation)
                    .arg(creationTime100ns);
                return result;
            }
        }
    }

    ev::ProcessInstanceId owner;
    owner.pid = ev::OptionalU64::of(pid);
    owner.createTime100ns = ev::OptionalU64::of(creationTime100ns);
    owner.bootId = "live";  // 同一次运行内的启动标识；跨启动比较不适用
    owner.imageName = QFileInfo(fallbackImagePath).fileName().toStdString();

    // --- 主映像路径（内核视图）------------------------------------------------
    std::wstring kernelImagePath;
    {
        wchar_t buffer[32768] = {};
        DWORD size = static_cast<DWORD>(std::size(buffer));
        if (::QueryFullProcessImageNameW(process.get(), 0U, buffer, &size) != FALSE)
        {
            kernelImagePath.assign(buffer, size);
            result.imagePath = QString::fromWCharArray(kernelImagePath.c_str(),
                                                       static_cast<int>(kernelImagePath.size()));
            owner.imageName = QFileInfo(result.imagePath).fileName().toStdString();
        }
    }

    const ev::ProcessArchitecture architecture =
        QueryProcessArchitecture(process.get(), &result.architectureText);

    // --- 地址空间索引 ---------------------------------------------------------
    MappedPathCache pathCache;
    AddressSpaceCollection addressSpace =
        CollectAddressSpace(process.get(), owner, options, pathCache, budget);
    result.regionCount = static_cast<std::uint32_t>(addressSpace.records.size());

    ev::SurveyInput input;
    input.mode = options.deepMode ? ev::SurveyMode::Deep : ev::SurveyMode::Fast;
    input.detectorVersion = "ksword.injection-survey/1.0";
    input.processBefore = owner;
    input.collectedUtc100ns = ev::OptionalU64::of(NowUtc100ns());
    input.targetArchitecture = architecture;
    // 主程序是原生 x64；这一位不是猜的，是编译期事实。
    input.collectorArchitecture = ev::CollectorArchitecture::Native64;

    input.addressSpace =
        ev::BuildAddressSpaceIndex(std::move(addressSpace.records), addressSpace.outcome);

    // --- 加载器视图与映像映射视图 --------------------------------------------
    const LoaderCollection loader = CollectLoaderModules(process.get());
    result.loaderModuleCount = static_cast<std::uint32_t>(loader.modules.size());

    ev::ModuleCrossViewInput crossInput;
    crossInput.loaderOutcome = loader.outcome;
    crossInput.loaderTrust = ev::EvaluateModuleEnumerationTrust(
        input.collectorArchitecture, architecture);
    crossInput.imageOutcome = addressSpace.outcome;
    crossInput.payloadOutcome = addressSpace.outcome;
    crossInput.mainImagePathFromKernel = ToUtf8(kernelImagePath);

    std::unordered_map<std::uint64_t, const LoaderModule*> loaderByBase;
    for (const LoaderModule& module : loader.modules)
    {
        ev::LoaderModuleEntry entry;
        entry.module.imagePath = ToUtf8(module.path);
        entry.module.imageBase = ev::OptionalU64::of(module.base);
        entry.module.imageSize = ev::OptionalU64::of(module.size);
        entry.listedName = QFileInfo(QString::fromWCharArray(module.path.c_str()))
                               .fileName()
                               .toStdString();
        entry.isMainImage = crossInput.loaderView.empty();  // 加载器链表首项是主映像
        if (entry.isMainImage)
        {
            crossInput.mainImagePathFromLoader = entry.module.imagePath;
            crossInput.mainImageBaseFromLoader = entry.module.imageBase;
        }
        loaderByBase.emplace(module.base, &module);
        crossInput.loaderView.push_back(std::move(entry));
    }

    // 映像映射视图：按 AllocationBase 聚合 MEM_IMAGE 分配。
    {
        std::map<std::uint64_t, ev::ImageMappingEntry> imageByBase;
        for (std::size_t i = 0; i < input.addressSpace.entries.size(); ++i)
        {
            const ev::RegionRecord& record = input.addressSpace.entries[i];
            if (record.type != ev::RegionType::Image ||
                record.state != ev::RegionState::Commit || !record.allocationBase.present)
            {
                continue;
            }
            const std::uint64_t base = record.allocationBase.value;
            ev::ImageMappingEntry& entry = imageByBase[base];
            entry.allocationBase = ev::OptionalU64::of(base);
            const std::uint64_t end = record.base.valueOr(base) + record.size.valueOr(0U);
            const std::uint64_t span = end > base ? end - base : 0U;
            if (!entry.mappedSize.present || entry.mappedSize.value < span)
            {
                entry.mappedSize = ev::OptionalU64::of(span);
            }
            if (entry.mappedPath.empty() && !record.mappedPath.empty())
            {
                entry.mappedPath = record.mappedPath;
                entry.pathOutcome = ev::CollectionOutcome::success();
            }
        }
        for (auto& item : imageByBase)
        {
            if (item.second.mappedPath.empty())
            {
                const auto failure = pathCache.failureByAllocationBase.find(item.first);
                item.second.pathOutcome = failure != pathCache.failureByAllocationBase.end()
                    ? Win32Failure(StatusForWin32Error(failure->second), failure->second)
                    : StatusOnlyOutcome(ev::CollectionStatus::Error);
            }
            if (crossInput.mainImageBaseFromLoader.present &&
                item.first == crossInput.mainImageBaseFromLoader.value)
            {
                crossInput.mainImagePathFromMapping = item.second.mappedPath;
                crossInput.mainImageBaseFromMapping = ev::OptionalU64::of(item.first);
            }
            crossInput.imageView.push_back(item.second);
        }
        result.imageMappingCount = static_cast<std::uint32_t>(crossInput.imageView.size());
    }

    // --- 非映像载荷候选 -------------------------------------------------------
    for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                            i < input.addressSpace.codeClasses.size();
         ++i)
    {
        if (!ev::IsDynamicCodeCandidate(input.addressSpace.codeClasses[i]))
        {
            continue;
        }
        const ev::RegionRecord& record = input.addressSpace.entries[i];
        ev::PayloadCandidateEntry candidate;
        candidate.base = record.base;
        candidate.size = record.size;
        candidate.type = record.type;
        if (budget.exhausted())
        {
            candidate.structure = ev::PayloadStructure::NotExamined;
            candidate.outcome = PartialOutcome();
        }
        else
        {
            candidate.structure = ClassifyPayloadStructure(
                process.get(), record.base.valueOr(0U), record.size.valueOr(0U), options, budget,
                &candidate.structureFacts);
            candidate.outcome = candidate.structure == ev::PayloadStructure::Unreadable
                ? PartialOutcome()
                : ev::CollectionOutcome::success();
        }
        crossInput.payloadView.push_back(candidate);
        input.payloadCandidates.push_back(std::move(candidate));
    }

    // --- 休眠载荷：不可执行的私有/映射内存 -------------------------------------
    // 载荷可以先存成 RW、要执行前才翻成 RX（睡眠掩码就是这么干的），所以"只看当前
    // 带执行权限的页"是一个真缺口。深度模式补这一档。
    //
    // **只读每块的首页，不读整块**：实测本机 330 个可打开进程一共有 129937 块
    // 非可执行已提交私有/映射区域、合计 40.9 GB，整块读完全不可行；只读首页的话
    // 全机 9.3 秒、单进程约 28 ms。
    //
    // 这一档的候选**不参与升结论**（executableAtScanTime=false）：同一次实测里
    // 首页能通过 PE 合理性检查的有 99 块，每进程约 0.3 个。放它进升结论的路径，
    // 干净机器上就会常态给出"观测到差异"。
    if (options.deepMode)
    {
        std::size_t dormantScanned = 0;
        for (std::size_t i = 0; i < input.addressSpace.entries.size() &&
                                i < input.addressSpace.codeClasses.size();
             ++i)
        {
            if (ev::IsDynamicCodeCandidate(input.addressSpace.codeClasses[i]))
            {
                continue;  // 可执行的那一档上面已经收过了
            }
            const ev::RegionRecord& record = input.addressSpace.entries[i];
            if (record.type != ev::RegionType::Private && record.type != ev::RegionType::Mapped)
            {
                continue;  // 映像有自己的归一化比较那一维，不在这里重复
            }
            if (record.state != ev::RegionState::Commit || record.size.valueOr(0U) == 0U)
            {
                continue;  // 保留/空闲的区域没有内容可读
            }
            const ev::ProtectionFacts facts = ev::ClassifyWin32Protection(record.protection.rawValue);
            if (facts.noAccess || facts.guard || !facts.readable ||
                ev::ExecuteProtectionIsExecutable(facts.execute))
            {
                continue;
            }
            if (budget.exhausted())
            {
                break;
            }

            ev::PayloadCandidateEntry candidate;
            candidate.base = record.base;
            candidate.size = record.size;
            candidate.type = record.type;
            candidate.executableAtScanTime = false;
            // 只给首页的长度，让结构判定不会顺着读下去。
            candidate.structure = ClassifyPayloadStructure(
                process.get(), record.base.valueOr(0U),
                std::min<std::uint64_t>(record.size.valueOr(0U), 0x1000ULL), options, budget,
                &candidate.structureFacts);
            candidate.outcome = candidate.structure == ev::PayloadStructure::Unreadable
                ? PartialOutcome()
                : ev::CollectionOutcome::success();
            ++dormantScanned;
            // 这一档**只留 PE 形状的**。ClassifyPayloadStructure 对任何没有 MZ 的
            // 可读内存都返回 BareCode —— 那对可执行内存是"未知可执行代码"，
            // 对数据区则是"这是数据"，每进程几百块全都会命中。留下来只会把真正
            // 值得看的条目淹掉。NoStructure / Unreadable 同理。
            const bool peShaped = candidate.structure == ev::PayloadStructure::MappedPeImage ||
                                  candidate.structure == ev::PayloadStructure::HeaderErasedPe ||
                                  candidate.structure == ev::PayloadStructure::DataOnlyPeFile;
            if (!peShaped)
            {
                continue;
            }
            input.payloadCandidates.push_back(std::move(candidate));
        }
        // 扫过了才算数：一块都没扫成的话这一位不能置真。
        input.nonExecutableMemoryScanned = dormantScanned != 0;
        result.dormantRegionsScanned = static_cast<std::uint32_t>(dormantScanned);
    }

    // 两条本版本没有的能力，显式列出来 —— 它们缩小结论的适用范围，但不压制结论。
    input.extraCapabilityLimitKeys.push_back(ev::kLimitPayloadHeaderErased);
    input.extraCapabilityLimitKeys.push_back(ev::kLimitRuntimeAttribution);
    if (addressSpace.mappedPathFailure)
    {
        input.extraCoverageGapKeys.push_back(ev::kGapMappedPathUnavailable);
    }

    input.moduleCrossView = ev::EvaluateModuleCrossView(crossInput);

    // --- 参考映像与代码范围 ---------------------------------------------------
    std::vector<ev::ImageCodeExtent> codeExtents;
    std::map<std::string, ReferenceImage> references;  // key = 归一化前的模块路径
    for (const LoaderModule& module : loader.modules)
    {
        if (budget.exhausted())
        {
            break;
        }
        ReferenceImage reference = BuildReferenceImage(process.get(), module, budget);
        ev::ImageCodeExtent extent;
        extent.path = ToUtf8(module.path);
        extent.base = module.base;
        extent.size = module.size;
        if (reference.map.valid())
        {
            const std::vector<ev::RvaRange> executable =
                reference.map.executableRawBackedRanges();
            std::uint64_t begin = 0;
            std::uint64_t end = 0;
            bool first = true;
            for (const ev::RvaRange& range : executable)
            {
                if (range.empty())
                {
                    continue;
                }
                if (first)
                {
                    begin = range.rva;
                    end = range.endExclusive();
                    first = false;
                }
                else
                {
                    begin = std::min<std::uint64_t>(begin, range.rva);
                    end = std::max<std::uint64_t>(end, range.endExclusive());
                }
            }
            if (!first)
            {
                extent.codeBeginRva = begin;
                extent.codeEndRva = end;
                extent.codeExtentKnown = true;
            }
            if (extent.size == 0U)
            {
                extent.size = reference.map.header.sizeOfImage;
            }
        }
        codeExtents.push_back(extent);
        references.emplace(extent.path, std::move(reference));
    }

    // --- 线程起点 -------------------------------------------------------------
    const ThreadStartCollection threads = CollectThreadStarts(pid, owner, options);
    result.threadCount = static_cast<std::uint32_t>(threads.threads.size());
    input.threadEnumerationOutcome = threads.outcome;
    input.threadStarts =
        ev::EvaluateThreadStarts(threads.threads, input.addressSpace, codeExtents);

    // --- 栈回溯 ---------------------------------------------------------------
    // 只在深度模式做：它要对每个等待中的线程走一遍展开，还要按模块读 .pdata，
    // 代价不属于"几秒出结果"的快速模式。不做时 threadStacks 留空，判据层会把它
    // 记成能力限制而不是缺口 —— 两者的区别见 InjectionSurvey.h。
    if (options.deepMode && !budget.exhausted())
    {
        StackWalkOptions stackOptions;
        stackOptions.maxThreads = options.maxThreads;
        const StackWalkResult stacks = WalkProcessStacks(
            process.get(), pid, owner, architecture, stackOptions);
        input.threadStacks = stacks.stacks;
        result.stackThreadsConsidered = stacks.threadsConsidered;
        result.stackThreadsWaiting = stacks.threadsWaiting;
        result.stackThreadsWalked = stacks.threadsWalked;
        if (!stacks.diagnostic.empty())
        {
            if (!result.diagnosticText.isEmpty())
            {
                result.diagnosticText += QStringLiteral("; ");
            }
            result.diagnosticText += QString::fromStdString(stacks.diagnostic);
        }
    }

    // --- 工作集筛选 -----------------------------------------------------------
    std::vector<ev::ComparisonPlanInput::ScreenedPage> screenedPages;
    {
        input.workingSetQueried = workingSetProcess != nullptr;
        bool incomplete = workingSetProcess == nullptr;
        std::size_t queried = 0;
        constexpr std::uint64_t pageSize = 0x1000ULL;
        for (const ev::ImageCodeExtent& extent : codeExtents)
        {
            if (workingSetProcess == nullptr)
            {
                break;  // 这一项能力拿不到，缺口已经记上了
            }
            if (!extent.codeExtentKnown || extent.base == 0U)
            {
                // 代码布局不知道就不问 —— 问了也不知道问的是不是代码页。
                incomplete = true;
                continue;
            }
            std::uint64_t rva = extent.codeBeginRva & ~(pageSize - 1ULL);
            while (rva < extent.codeEndRva)
            {
                if (budget.exhausted())
                {
                    incomplete = true;
                    break;
                }
                std::vector<PSAPI_WORKING_SET_EX_INFORMATION> batch;
                batch.reserve(kWorkingSetBatchPages);
                for (; rva < extent.codeEndRva && batch.size() < kWorkingSetBatchPages;
                     rva += pageSize)
                {
                    PSAPI_WORKING_SET_EX_INFORMATION item{};
                    item.VirtualAddress = reinterpret_cast<PVOID>(extent.base + rva);
                    batch.push_back(item);
                }
                if (batch.empty())
                {
                    break;
                }
                const DWORD bytes = static_cast<DWORD>(
                    batch.size() * sizeof(PSAPI_WORKING_SET_EX_INFORMATION));
                if (::QueryWorkingSetEx(workingSetProcess, batch.data(), bytes) == FALSE)
                {
                    incomplete = true;
                    continue;
                }
                queried += batch.size();
                for (const PSAPI_WORKING_SET_EX_INFORMATION& item : batch)
                {
                    ev::WorkingSetPageFact fact;
                    fact.va = reinterpret_cast<std::uint64_t>(item.VirtualAddress);
                    fact.queried = true;
                    fact.valid = item.VirtualAttributes.Valid != 0U;
                    fact.shared = item.VirtualAttributes.Shared != 0U;
                    fact.shareCount = ev::OptionalU64::of(item.VirtualAttributes.ShareCount);
                    fact.locked = item.VirtualAttributes.Locked != 0U;
                    fact.largePage = item.VirtualAttributes.LargePage != 0U;
                    fact.bad = item.VirtualAttributes.Bad != 0U;
                    fact.win32Protection =
                        ev::OptionalU64::of(item.VirtualAttributes.Win32Protection);
                    fact.node = ev::OptionalU64::of(item.VirtualAttributes.Node);

                    const ev::PageScreenVerdict verdict = ev::ScreenWorkingSetPage(fact);
                    if (verdict == ev::PageScreenVerdict::PrivatizedCandidate)
                    {
                        ++input.workingSetPrivatizedPages;
                    }
                    else if (verdict == ev::PageScreenVerdict::InvalidNeedsRecheck)
                    {
                        ++input.workingSetInvalidPages;
                    }
                    if (ev::PageSelectedForComparison(verdict, input.mode))
                    {
                        ev::ComparisonPlanInput::ScreenedPage page;
                        page.imagePath = extent.path;
                        page.pageRva = static_cast<std::uint32_t>(fact.va - extent.base);
                        screenedPages.push_back(page);
                    }
                }
            }
        }
        input.workingSetPagesScreened = queried;
        result.workingSetPagesQueried = static_cast<std::uint32_t>(queried);
        input.workingSetOutcome = incomplete ? PartialOutcome()
                                             : ev::CollectionOutcome::success();
    }

    // --- 比较计划 -------------------------------------------------------------
    ev::ComparisonPlanInput planInput;
    planInput.mode = input.mode;
    planInput.images = codeExtents;
    planInput.screenedPages = screenedPages;
    if (!crossInput.mainImagePathFromLoader.empty())
    {
        planInput.mainImagePath = crossInput.mainImagePathFromLoader;
        const auto mainReference = references.find(crossInput.mainImagePathFromLoader);
        if (mainReference != references.end() && mainReference->second.map.valid())
        {
            planInput.mainImageEntryRva =
                ev::OptionalU64::of(mainReference->second.map.header.entryPointRva);
        }
        else if (crossInput.mainImageBaseFromLoader.present)
        {
            const auto mainModule = loaderByBase.find(crossInput.mainImageBaseFromLoader.value);
            if (mainModule != loaderByBase.end() && mainModule->second->entryPointRva != 0U)
            {
                planInput.mainImageEntryRva =
                    ev::OptionalU64::of(mainModule->second->entryPointRva);
            }
        }
    }
    // 落点异常或第一跳跨模块的线程入口进入定向比较。
    for (const ev::ThreadStartFinding& start : input.threadStarts)
    {
        if (!start.startAddress.present || start.owningPath.empty())
        {
            continue;
        }
        const bool interesting = start.landing == ev::ThreadStartLanding::ImageOutsideCode ||
                                 start.branchLeavesOwningModule;
        if (!interesting)
        {
            continue;
        }
        const auto extent = std::find_if(
            codeExtents.begin(), codeExtents.end(),
            [&start](const ev::ImageCodeExtent& candidate) {
                return candidate.containsAddress(start.startAddress.value);
            });
        if (extent == codeExtents.end())
        {
            continue;
        }
        ev::ComparisonPlanInput::ThreadEntrySite site;
        site.imagePath = extent->path;
        site.rva = static_cast<std::uint32_t>(start.startAddress.value - extent->base);
        planInput.threadEntrySites.push_back(site);
    }

    const ev::ComparisonPlan plan = ev::BuildComparisonPlan(planInput);

    // --- 执行比较 -------------------------------------------------------------
    {
        std::map<std::string, ev::ImageComparisonOutcome> outcomes;
        std::size_t executed = 0;
        for (const ev::ComparisonTarget& target : plan.targets)
        {
            if (executed >= options.maxImageComparisons || budget.exhausted())
            {
                ++input.plannedComparisonsNotRun;
                continue;
            }
            const auto reference = references.find(target.module.imagePath);
            if (reference == references.end() || !reference->second.map.valid())
            {
                ++input.plannedComparisonsNotRun;
                continue;
            }
            if (target.range.empty())
            {
                continue;
            }

            // 深度模式的目标可能是整段代码区。按固定大小切片读取，切片之间不重叠
            // 也不留缝，覆盖范围与一次性读整段完全相同。
            bool targetTruncated = false;
            for (std::uint64_t offset = 0; offset < target.range.length;
                 offset += kMaxSingleCompareBytes)
            {
                if (budget.exhausted())
                {
                    targetTruncated = true;
                    break;
                }
                ev::RvaRange slice;
                slice.rva = target.range.rva + static_cast<std::uint32_t>(offset);
                slice.length = static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    kMaxSingleCompareBytes, target.range.length - offset));

                std::vector<std::uint8_t> liveBytes(slice.length);
                std::size_t copied = 0U;
                ReadTargetMemory(process.get(), reference->second.base + slice.rva,
                                 liveBytes.data(), liveBytes.size(), budget, &copied);

                ev::LiveImageBytes live = ev::LiveImageBytes::fromBytes(slice.rva, liveBytes);
                if (copied < liveBytes.size())
                {
                    // 读不到的尾部标成不可读，绝不补 00 后参与比较。
                    ev::RvaRange hole;
                    hole.rva = slice.rva + static_cast<std::uint32_t>(copied);
                    hole.length = slice.length - static_cast<std::uint32_t>(copied);
                    live.markRange(hole, ev::ByteReadStatus::Unreadable);
                }

                ev::ImageDiffOptions diffOptions;
                diffOptions.compareRanges = { slice };
                diffOptions.module = target.module;
                diffOptions.evidenceSource = "ksword.injection-survey";
                diffOptions.reference.kind = ev::ReferenceSourceKind::LocalDisk;
                diffOptions.reference.description = target.module.imagePath;
                diffOptions.collapseGapBytes = 16U;

                const ev::ImageDiffReport report =
                    ev::CompareImage(reference->second.map, live, diffOptions);
                ++result.comparedRangeCount;

                ev::ImageComparisonOutcome& merged = outcomes[target.module.imagePath];
                if (merged.module.imagePath.empty())
                {
                    merged.module = target.module;
                    merged.referenceConfidence = reference->second.confidence;
                    merged.report.outcome = report.outcome;
                    merged.report.reference = report.reference;
                    merged.report.conclusion = report.conclusion;
                }
                merged.report.entries.insert(merged.report.entries.end(),
                                             report.entries.begin(), report.entries.end());
                merged.report.limitationKeys.insert(merged.report.limitationKeys.end(),
                                                    report.limitationKeys.begin(),
                                                    report.limitationKeys.end());
                merged.report.comparedBytes += report.comparedBytes;
                merged.report.differingBytes += report.differingBytes;
                merged.report.unreadableBytes += report.unreadableBytes;
                merged.report.excludedBytes += report.excludedBytes;
                if (report.conclusion == ev::AnalysisConclusion::DifferenceObserved)
                {
                    merged.report.conclusion = ev::AnalysisConclusion::DifferenceObserved;
                }
            }
            ++executed;
            if (targetTruncated)
            {
                ++input.plannedComparisonsNotRun;
            }
        }
        for (auto& item : outcomes)
        {
            input.imageComparisons.push_back(std::move(item.second));
        }
        result.comparedModuleCount = static_cast<std::uint32_t>(input.imageComparisons.size());

        // --- 第二参考源：映像节对象 -------------------------------------------
        // 上面那一轮比的是"实时字节 vs 磁盘文件"。这一轮比的是"实时字节 vs
        // 内存管理器自己持有的节对象"。两者不是重复：
        // **一个页与磁盘一致、却与节对象不同，说明磁盘文件在映射建立之后被改过。**
        // 那正是"把内存改了、再把磁盘文件也改成一样"这种手法唯一露出的破绽。
        //
        // 只比**没有重定位 fixup 的页**。有 fixup 的页，加载器本来就会改写它，
        // 实时字节与节对象里的未重定位内容天然不同，比了只会得到一堆噪声。
        // 判据是 PeImageMap 已经算好的 relocation.touchedRanges —— 不另起一套解析。
        // 被排除的页如实记进覆盖账，"没比到"不会被读成"比过了没差异"。
        if (options.deepMode && options.useKernelBackend)
        {
            CollectSectionObjectComparisons(
                process.get(), pid, references, plan, budget, options, input, result);
        }
    }

    for (const std::string& gap : plan.coverageGapKeys)
    {
        input.extraCoverageGapKeys.push_back(gap);
    }

    // --- 目标程序版本身份（例外规则绑定用）-----------------------------------
    if (!crossInput.mainImagePathFromLoader.empty())
    {
        const auto mainReference = references.find(crossInput.mainImagePathFromLoader);
        if (mainReference != references.end() && mainReference->second.map.valid())
        {
            ev::DriverInstanceId mainModule;
            mainModule.imagePath = crossInput.mainImagePathFromLoader;
            mainModule.imageSize =
                ev::OptionalU64::of(mainReference->second.map.header.sizeOfImage);
            mainModule.timeDateStamp =
                ev::OptionalU64::of(mainReference->second.map.header.timeDateStamp);
            input.targetImageIdentity = ev::ModuleIdentityKeyFor(mainModule);
        }
    }

    // --- R0 扫描后端 ----------------------------------------------------------
    if (options.useKernelBackend && !(options.cancelled && options.cancelled()))
    {
        const ksword::ark::DriverClient driverClient;
        QStringList diagnostics;
        bool backendAbsent = false;

        // VAD 树。续扫直到走完或命中我们自己的条目上限。
        ev::KernelVadView vadView;
        {
            std::uint64_t cursorVpn = 0ULL;
            bool first = true;
            bool truncated = false;
            for (;;)
            {
                const ksword::ark::ProcessVadEnumResult r = driverClient.enumerateProcessVad(
                    pid, 0ULL, 0ULL, cursorVpn, options.kernelVadMaxEntries);
                if (!r.io.ok)
                {
                    if (DeviceIsAbsent(r.io.win32Error))
                    {
                        /*
                         * 本机根本没有 KswordARK 设备 —— 我们从来没声明过要在这种
                         * 机器上做内核视图，所以这是**能力限制**不是覆盖缺口。
                         * 写成缺口会让每台没装驱动的机器 scopeIntact 恒为假，
                         * 四态又退化成三态（同 kLimitNonExecutableNotScanned 的教训）。
                         */
                        backendAbsent = true;
                        vadView = ev::KernelVadView{};
                        diagnostics << QStringLiteral("device absent (%1)").arg(r.io.win32Error);
                        break;
                    }
                    // 设备在、这次调用失败（权限等）：那是真缺口。
                    vadView.state = ev::KernelBackendState::DriverUnavailable;
                    vadView.outcome = Win32Failure(
                        StatusForWin32Error(r.io.win32Error), r.io.win32Error);
                    diagnostics << QStringLiteral("vad io error=%1").arg(r.io.win32Error);
                    break;
                }
                if (first)
                {
                    result.kernelVadState = ev::KernelBackendState::Available;
                    first = false;
                }
                if (r.profileVerified == 0U ||
                    r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_DYNDATA_MISSING)
                {
                    // 没有针对当前 build 验证过的 VadRoot 偏移 —— 明确降级，不猜。
                    vadView.state = ev::KernelBackendState::ProfileUnverified;
                    vadView.outcome = StatusOnlyOutcome(ev::CollectionStatus::Unsupported);
                    vadView.regions.clear();
                    diagnostics << QStringLiteral("vad profile unverified");
                    break;
                }
                for (const ksword::ark::ProcessVadEntry& entry : r.entries)
                {
                    ev::KernelVadRegion region;
                    region.startVa = ev::OptionalU64::of(entry.startVa);
                    region.endVaExclusive = ev::OptionalU64::of(entry.endVaExclusive);
                    region.vadNodeAddress = ev::OptionalU64::of(entry.vadNodeAddress);
                    region.privateMemory =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_VAD_FLAG_PRIVATE_MEMORY) != 0U;
                    region.hasSection = entry.subsection != 0ULL;
                    region.flagsLayoutAssumed =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_VAD_FLAG_FLAGS_LAYOUT_ASSUMED) != 0U;
                    region.protectionRaw = ev::OptionalU64::of(entry.protection);
                    region.vadFlagsRaw = ev::OptionalU64::of(entry.vadFlagsRaw);
                    vadView.regions.push_back(std::move(region));
                }
                vadView.visitedCount += r.visitedCount;
                vadView.unreadableNodeCount += r.unreadableNodeCount;
                if (cursorVpn == 0ULL)
                {
                    // 断链判据只认**第一次调用**的读数，而且只在它一次走完整棵树时
                    // 有效。驱动侧已经按"没截断 + 没游标 + 没读不到的节点"置位，
                    // 这里再把续扫的情况排掉：一旦要带游标再来一次，
                    // 第一次的 visitedCount 就只是半棵树。
                    vadView.integrityValid = r.integrityValid;
                    vadView.vadCountKnown = r.vadCountKnown;
                    vadView.vadHintKnown = r.vadHintKnown;
                    vadView.vadCount = r.vadCount;
                    vadView.parentMismatchNodes = r.parentMismatchNodes;
                    vadView.vadHintVisited = r.vadHintVisited;
                    vadView.vadHintAddress = r.vadHintAddress != 0ULL
                        ? ev::OptionalU64::of(r.vadHintAddress)
                        : ev::OptionalU64{};
                }
                if (r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED &&
                    r.nextCursorVpn != 0ULL &&
                    vadView.regions.size() < options.kernelVadMaxEntries && !budget.exhausted())
                {
                    cursorVpn = r.nextCursorVpn;
                    // 要续扫就说明第一次没走完整棵树，断链判据作废。
                    vadView.integrityValid = false;
                    continue;
                }
                truncated = (r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED);
                vadView.truncated = truncated;
                vadView.state = (truncated || r.unreadableNodeCount != 0U ||
                                 r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL)
                    ? ev::KernelBackendState::Partial
                    : ev::KernelBackendState::Available;
                vadView.outcome = (vadView.state == ev::KernelBackendState::Available)
                    ? ev::CollectionOutcome::success()
                    : PartialOutcome();
                break;
            }
            result.kernelVadState = vadView.state;
            result.kernelVadRegionCount = static_cast<std::uint32_t>(vadView.regions.size());
            result.kernelVadUnreadableNodes =
                static_cast<std::uint32_t>(vadView.unreadableNodeCount);
        }

        // 用户态可执行页表叶子。
        ev::KernelPteView pteView;
        {
            std::uint64_t cursor = 0ULL;
            bool first = true;
            for (;;)
            {
                const ksword::ark::ProcessExecutablePteScanResult r =
                    driverClient.scanProcessExecutablePte(
                        pid, 0ULL, 0ULL, cursor,
                        options.kernelPteMaxEntries, options.kernelPteMaxTableReads);
                if (!r.io.ok)
                {
                    if (DeviceIsAbsent(r.io.win32Error))
                    {
                        backendAbsent = true;
                        pteView = ev::KernelPteView{};
                        break;
                    }
                    pteView.state = ev::KernelBackendState::DriverUnavailable;
                    pteView.outcome = Win32Failure(
                        StatusForWin32Error(r.io.win32Error), r.io.win32Error);
                    diagnostics << QStringLiteral("pte io error=%1").arg(r.io.win32Error);
                    break;
                }
                if (first)
                {
                    pteView.scannedBegin = ev::OptionalU64::of(r.scannedBegin);
                    first = false;
                }
                for (const ksword::ark::ProcessExecutablePteEntry& entry : r.entries)
                {
                    ev::KernelExecutableExtent extent;
                    extent.startVa = ev::OptionalU64::of(entry.startVa);
                    extent.byteLength = ev::OptionalU64::of(entry.byteLength);
                    extent.pageSize = entry.pageSize;
                    extent.executable =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_EXECUTABLE) != 0U;
                    extent.writable =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_WRITABLE) != 0U;
                    extent.userAccessible =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_USER) != 0U;
                    extent.largePage =
                        (entry.entryFlags & KSWORD_ARK_INJECTION_PTE_ENTRY_FLAG_LARGE_PAGE) != 0U;
                    extent.firstEntryValue = ev::OptionalU64::of(entry.firstEntryValue);
                    pteView.extents.push_back(std::move(extent));
                }
                pteView.tableReads += r.tableReads;
                pteView.failedTableReads += r.failedTableReads;
                pteView.scannedEnd = ev::OptionalU64::of(r.scannedEnd);
                result.kernelExecutablePageCount += r.executablePageCount;
                if (r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED &&
                    r.nextCursorAddress != 0ULL &&
                    pteView.extents.size() < options.kernelPteMaxEntries &&
                    !budget.exhausted())
                {
                    cursor = r.nextCursorAddress;
                    continue;
                }
                pteView.truncated =
                    (r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_TRUNCATED);
                pteView.state = (pteView.truncated || r.failedTableReads != 0U ||
                                 r.status == KSWORD_ARK_INJECTION_SCAN_STATUS_PARTIAL)
                    ? ev::KernelBackendState::Partial
                    : ev::KernelBackendState::Available;
                pteView.outcome = (pteView.state == ev::KernelBackendState::Available)
                    ? ev::CollectionOutcome::success()
                    : PartialOutcome();
                break;
            }
            result.kernelPteState = pteView.state;
            result.kernelExecutableExtentCount =
                static_cast<std::uint32_t>(pteView.extents.size());
            result.kernelPteTableReads = static_cast<std::uint32_t>(pteView.tableReads);
        }

        if (backendAbsent)
        {
            // 没有设备：内核视图整节当作"没打算做"，只留一条能力限制。
            result.kernelVadState = ev::KernelBackendState::NotRequested;
            result.kernelPteState = ev::KernelBackendState::NotRequested;
            result.kernelVadRegionCount = 0U;
            result.kernelVadUnreadableNodes = 0U;
            result.kernelExecutableExtentCount = 0U;
            result.kernelExecutablePageCount = 0U;
            result.kernelPteTableReads = 0U;
            input.extraCapabilityLimitKeys.push_back(ev::kLimitKernelBackendAbsent);
        }
        else
        {
            ev::KernelCrossViewInput crossView;
            crossView.r3Index = &input.addressSpace;
            crossView.vadView = std::move(vadView);
            crossView.pteView = std::move(pteView);
            input.kernelCrossView = ev::EvaluateKernelCrossView(crossView);
            input.kernelVadState = result.kernelVadState;
            input.kernelPteState = result.kernelPteState;
        }
        result.kernelDiagnosticText = diagnostics.join(QStringLiteral("; "));
    }

    // --- 身份：结束后再核一次 -------------------------------------------------
    {
        ev::ProcessInstanceId after = owner;
        FILETIME created{}, exited{}, kernelTime{}, userTime{};
        if (::GetProcessTimes(process.get(), &created, &exited, &kernelTime, &userTime) != FALSE)
        {
            after.createTime100ns = ev::OptionalU64::of(FileTimeTo100ns(created));
        }
        else
        {
            // 读不到就让身份复核降级为"无法确认"，而不是默认一致。
            after.createTime100ns = ev::OptionalU64::unset();
        }
        input.processAfter = after;
    }

    input.budgetStop = budget.stop;
    result.bytesRead = budget.bytesRead;
    result.elapsedMs = static_cast<std::uint64_t>(budget.timer.elapsed());
    result.report = ev::RunInjectionSurvey(input);
    result.status = InjectionTraceStatus::Completed;
    return result;
}
}
