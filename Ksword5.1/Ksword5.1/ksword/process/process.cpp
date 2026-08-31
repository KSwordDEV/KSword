#include "process.h"
#include "ProcessCpuUsageModel.h"

#include "../string/string.h"

// Win32 头：进程、线程、令牌、工具快照、Shell、签名等。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <WinTrust.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <Shellapi.h>
#include <winternl.h>
#include <RestartManager.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <ShellScalingApi.h> // PROCESS_DPI_AWARENESS：DPI 感知列在 user32 路径不可用时的回退查询类型。
#include <appmodel.h>        // APPMODEL_ERROR_NO_PACKAGE：区分“进程不属于任何程序包”与真实查询失败。

#include <algorithm>   // std::max/std::clamp：衍生指标计算。
#include <chrono>      // steady_clock：跨刷新轮次计时。
#include <cmath>       // std::isfinite：过滤 PDH 返回的异常浮点值。
#include <cstddef>     // offsetof：校验变长系统句柄表缓冲区。
#include <cstring>     // std::memset：远程结构读取前清零输出缓冲。
#include <cwchar>      // std::swprintf/std::wcstoul：拼接版本信息查询路径与解析 PDH PID。
#include <cwctype>     // std::towlower：解析 GPU Engine 实例名时做大小写归一。
#include <filesystem>  // std::filesystem：路径存在性与目录判断。
#include <fstream>     // std::ifstream：读取 PE 头计算入口 RVA。
#include <iomanip>     // std::hex：格式化十六进制文本。
#include <iterator>    // std::size：静态数组长度。
#include <limits>      // std::numeric_limits：数值边界检查。
#include <mutex>       // std::mutex：保护全局 PDH 查询句柄。
#include <new>         // std::nothrow：远程注入延迟清理上下文分配失败时不抛异常。
#include <sstream>     // std::ostringstream：错误文本拼接。
#include <string>      // std::string/std::wstring：进程文本与 PDH 实例名。
#include <unordered_map> // std::unordered_map：线程枚举时缓存 PID->进程名。
#include <utility>     // std::move：容器写入记录时避免额外拷贝。
#include <vector>      // std::vector：系统信息缓冲与容器。

// 链接依赖库：
// - Psapi：GetProcessMemoryInfo；
// - Wintrust/Crypt32：数字签名校验；
// - Version：读取文件版本信息中的 CompanyName（厂家兜底）。
// - Pdh：读取 Windows GPU Engine 性能计数器，补齐每进程 GPU 利用率。
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pdh.lib")
// - User32：GetGuiResources，用于任务管理器对齐的 GDI / 用户对象计数列。
#pragma comment(lib, "User32.lib")

namespace
{
    // STATUS_INFO_LENGTH_MISMATCH：NtQuerySystemInformation 缓冲不足返回码。
#ifndef STATUS_INFO_LENGTH_MISMATCH
    constexpr NTSTATUS StatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);
#else
    constexpr NTSTATUS StatusInfoLengthMismatch = STATUS_INFO_LENGTH_MISMATCH;
#endif

    // PROCESS_SUSPEND_RESUME：旧头文件可能未定义，手动兜底。
#ifndef PROCESS_SUSPEND_RESUME
    constexpr DWORD ProcessSuspendResumeAccess = 0x0800;
#else
    constexpr DWORD ProcessSuspendResumeAccess = PROCESS_SUSPEND_RESUME;
#endif

    // ProcessBreakOnTermination：NtSetInformationProcess 的关键进程信息类。
    constexpr PROCESSINFOCLASS ProcessBreakOnTerminationInfoClass = static_cast<PROCESSINFOCLASS>(29);

    // ProcessPowerThrottling：Get/SetProcessInformation 的效率模式信息类。
    constexpr ULONG ProcessPowerThrottlingInfoClass = 4UL;
    constexpr ULONG ProcessPowerThrottlingCurrentVersion = 1UL;
    constexpr ULONG ProcessPowerThrottlingExecutionSpeed = 0x1UL;

    // ProcessProtectionLevelInfo：
    // - GetProcessInformation PROCESS_INFORMATION_CLASS 枚举值 7；
    // - 返回 PROCESS_PROTECTION_LEVEL_INFORMATION.ProtectionLevel。
    constexpr ULONG ProcessProtectionLevelInfoClass = 7UL;

    // PROTECTION_LEVEL_*：
    // - 部分构建环境的 processthreadsapi.h 未暴露这些宏；
    // - 本地兜底值仅用于解码 GetProcessInformation 的公开枚举。
    // - 0 同时用于 WINTCB_LIGHT，命名按 WinBase.h 的公开宏保持一致。
    constexpr DWORD ProcessProtectionLevelWinTcbLight = 0x00000000UL;
    constexpr DWORD ProcessProtectionLevelNone = 0xFFFFFFFEUL;
    constexpr DWORD ProcessProtectionLevelWindows = 0x00000001UL;
    constexpr DWORD ProcessProtectionLevelWindowsLight = 0x00000002UL;
    constexpr DWORD ProcessProtectionLevelAntimalwareLight = 0x00000003UL;
    constexpr DWORD ProcessProtectionLevelLsaLight = 0x00000004UL;
    constexpr DWORD ProcessProtectionLevelWinTcb = 0x00000005UL;
    constexpr DWORD ProcessProtectionLevelCodegenLight = 0x00000006UL;
    constexpr DWORD ProcessProtectionLevelAuthenticode = 0x00000007UL;
    constexpr DWORD ProcessProtectionLevelPplApp = 0x00000008UL;
    constexpr DWORD ProcessProtectionLevelSame = 0xFFFFFFFFUL;

    // Restart Manager 关闭标记：
    // - 这里统一使用本地常量，不直接依赖 SDK 是否暴露枚举名字；
    // - 语义等价于 Restart Manager 的强制关闭选项。
    constexpr ULONG RestartManagerForceShutdownFlag = 0x1UL;

    // NT_SUCCESS：判断 NTSTATUS 成功与否。
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

    // Nt 函数指针类型定义。
    using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
    using GetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);
    using SetProcessInformationFn = BOOL(WINAPI*)(HANDLE, ULONG, LPVOID, DWORD);
    using NtSuspendProcessFn = NTSTATUS(NTAPI*)(HANDLE);
    using NtResumeProcessFn = NTSTATUS(NTAPI*)(HANDLE);
    using NtSetInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG);
    using NtTerminateProcessFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtTerminateThreadFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtTerminateJobObjectFn = NTSTATUS(NTAPI*)(HANDLE, NTSTATUS);
    using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE, PVOID);
    using PdhAddEnglishCounterWFn = PDH_STATUS(WINAPI*)(HQUERY, LPCWSTR, DWORD_PTR, HCOUNTER*);

    // ProcessBasicInformation 结果结构（与 NtQueryInformationProcess 对应）。
    struct ProcessBasicInformationLocal
    {
        PVOID reserved1 = nullptr;
        PVOID pebBaseAddress = nullptr;
        PVOID reserved2[2]{};
        ULONG_PTR uniqueProcessId = 0;
        PVOID reserved3 = nullptr;
    };

    // ProcessCommandLineInformation：
    // - NtQueryInformationProcess 信息类 60；
    // - 优先走该路径可避开手工 PEB 偏移差异。
    constexpr PROCESSINFOCLASS ProcessCommandLineInformationClass =
        static_cast<PROCESSINFOCLASS>(60);

    // ProcessWow64Information：
    // - NtQueryInformationProcess 信息类 26；
    // - 64 位工具读取 32 位目标时用它获取 Wow64 PEB 地址。
    constexpr PROCESSINFOCLASS ProcessWow64InformationClass =
        static_cast<PROCESSINFOCLASS>(26);

    // 远程 UNICODE_STRING 最大读取长度：
    // - Length 来自目标进程内存，不能无条件信任；
    // - 256KB 足够覆盖正常命令行，同时避免坏指针导致超大分配。
    constexpr std::size_t RemoteUnicodeStringMaxBytes = 256 * 1024;

    // RemoteUnicodeString32：
    // - 32 位目标进程内 UNICODE_STRING 的真实布局；
    // - Buffer 是 32 位远程地址，读取前需要提升为 64 位整数。
    struct RemoteUnicodeString32
    {
        USHORT length = 0;        // 字符串字节数，不包含终止 NUL。
        USHORT maximumLength = 0; // 缓冲容量字节数。
        std::uint32_t buffer = 0; // 32 位远程 PWSTR 地址。
    };

    // Peb32CommandLineLite / Peb64CommandLineLite：
    // - 只保留 PEB 起始字段到 ProcessParameters；
    // - 避免依赖 SDK 裁剪版 PEB，也避免读取整个 PEB 结构。
    struct Peb32CommandLineLite
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        std::uint32_t mutant = 0;
        std::uint32_t imageBaseAddress = 0;
        std::uint32_t ldr = 0;
        std::uint32_t processParameters = 0;
    };

    struct Peb64CommandLineLite
    {
        BYTE reserved1[2]{};
        BYTE beingDebugged = 0;
        BYTE reserved2[1]{};
        PVOID mutant = nullptr;
        PVOID imageBaseAddress = nullptr;
        PVOID ldr = nullptr;
        PVOID processParameters = nullptr;
    };

    // RtlUserProcessParameters32CommandLine / 64CommandLine：
    // - 按公开稳定偏移直接定位 CommandLine 字段；
    // - 32 位 CommandLine 位于 0x40，64 位 CommandLine 位于 0x70。
    struct RtlUserProcessParameters32CommandLine
    {
        BYTE reservedBeforeCommandLine[0x40]{};
        RemoteUnicodeString32 commandLine{};
    };

    struct RtlUserProcessParameters64CommandLine
    {
        BYTE reservedBeforeCommandLine[0x70]{};
        UNICODE_STRING commandLine{};
    };

    // NtQuerySystemInformation(SystemProcessInformation) 的完整结构体定义。
    // 说明：
    // - 部分 SDK 的 _SYSTEM_PROCESS_INFORMATION 字段被裁剪；
    // - 这里使用兼容版定义以读取创建时间、CPU 时间与 IO 计数器。
    struct SystemProcessInformationRecord
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        LARGE_INTEGER WorkingSetPrivateSize;
        ULONG HardFaultCount;
        ULONG NumberOfThreadsHighWatermark;
        ULONGLONG CycleTime;
        LARGE_INTEGER CreateTime;
        LARGE_INTEGER UserTime;
        LARGE_INTEGER KernelTime;
        UNICODE_STRING ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
        ULONG HandleCount;
        ULONG SessionId;
        ULONG_PTR UniqueProcessKey;
        SIZE_T PeakVirtualSize;
        SIZE_T VirtualSize;
        ULONG PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivatePageCount;
        LARGE_INTEGER ReadOperationCount;
        LARGE_INTEGER WriteOperationCount;
        LARGE_INTEGER OtherOperationCount;
        LARGE_INTEGER ReadTransferCount;
        LARGE_INTEGER WriteTransferCount;
        LARGE_INTEGER OtherTransferCount;
    };

    // NtQuerySystemInformation(SystemProcessInformation) 中的线程子结构。
    // 说明：
    // - 官方 winternl 头在不同 SDK 上字段命名存在差异；
    // - 这里使用兼容布局，保证可读出线程核心字段（TID/优先级/状态等）。
    struct SystemThreadInformationRecord
    {
        LARGE_INTEGER ReservedTime[3];  // [0]=KernelTime, [1]=UserTime, [2]=CreateTime。
        ULONG WaitTime;                 // 线程等待时长计数（原始值）。
        PVOID StartAddress;             // 线程启动地址。
        CLIENT_ID ClientId;             // 线程与所属进程标识。
        KPRIORITY Priority;             // 当前动态优先级。
        LONG BasePriority;              // 基础优先级。
        ULONG ContextSwitches;          // 上下文切换次数。
        ULONG ThreadState;              // 线程状态码（KTHREAD_STATE）。
        ULONG WaitReason;               // 等待原因码（KWAIT_REASON）。
    };

    // SystemExtendedThreadInformationRecord：
    // - SystemExtendedProcessInformation(57) 的线程记录扩展布局；
    // - 在基础 SystemThreadInformation 之后额外提供 StackBase/StackLimit、
    //   Win32StartAddress 和 TebBaseAddress；
    // - 这些字段属于公开 NtQuery 返回，不依赖 R0 驱动。
    struct SystemExtendedThreadInformationRecord
    {
        SystemThreadInformationRecord ThreadInfo{};
        PVOID StackBase = nullptr;
        PVOID StackLimit = nullptr;
        PVOID Win32StartAddress = nullptr;
        PVOID TebBaseAddress = nullptr;
        ULONG_PTR Reserved2 = 0;
        ULONG_PTR Reserved3 = 0;
        ULONG_PTR Reserved4 = 0;
    };

    // SystemHandleTableEntryInfoExLocal：
    // - SystemExtendedHandleInformation(64) 的单条句柄记录；
    // - 用于在 R3 中直接按 PID 聚合句柄数量，避免依赖目标进程可打开。
    struct SystemHandleTableEntryInfoExLocal
    {
        PVOID objectAddress = nullptr;          // objectAddress：内核对象地址，本函数不使用。
        ULONG_PTR uniqueProcessId = 0;          // uniqueProcessId：句柄所属 PID。
        ULONG_PTR handleValue = 0;              // handleValue：句柄值，本函数不使用。
        ULONG grantedAccess = 0;                // grantedAccess：访问掩码，本函数不使用。
        USHORT creatorBackTraceIndex = 0;       // creatorBackTraceIndex：创建栈索引，本函数不使用。
        USHORT objectTypeIndex = 0;             // objectTypeIndex：对象类型编号，本函数不使用。
        ULONG handleAttributes = 0;             // handleAttributes：句柄属性，本函数不使用。
        ULONG reserved = 0;                     // reserved：保留字段。
    };

    // SystemHandleInformationExLocal：
    // - SystemExtendedHandleInformation(64) 的缓冲区头；
    // - handles 是变长数组，访问前必须按缓冲区大小二次校验。
    struct SystemHandleInformationExLocal
    {
        ULONG_PTR numberOfHandles = 0;                    // numberOfHandles：系统句柄总数。
        ULONG_PTR reserved = 0;                           // reserved：保留字段。
        SystemHandleTableEntryInfoExLocal handles[1] = {}; // handles：变长句柄数组首元素。
    };

    // 线程状态与等待原因常量：
    // - KTHREAD_STATE::Waiting = 5；
    // - KWAIT_REASON::Suspended = 5，WrSuspended = 12；
    // - 任务管理器把“全部线程都处于挂起等待”的进程显示为“已挂起”。
    constexpr ULONG SystemThreadStateWaiting = 5UL;
    constexpr ULONG SystemThreadWaitReasonSuspended = 5UL;
    constexpr ULONG SystemThreadWaitReasonWrSuspended = 12UL;

    // ApplyProcessSuspendedStateFromThreadArray 作用：
    // - 输入：SystemProcessInformation 缓冲区内的单条进程记录及其线程数量；
    // - 处理：遍历紧随进程记录之后的线程数组，统计处于挂起等待的线程；
    // - 返回：无返回值，判定结果直接写回 processRecord。
    // 越界保护：线程数组必须完整落在缓冲区内，否则放弃判定并保持 processStateKnown = false。
    void ApplyProcessSuspendedStateFromThreadArray(
        ks::process::ProcessRecord& processRecord,
        const BYTE* const processEntryPointer,
        const BYTE* const bufferBegin,
        const std::size_t bufferSize,
        const std::uint32_t threadCount)
    {
        processRecord.suspendedThreadCount = 0;
        processRecord.processSuspended = false;
        processRecord.processStateKnown = false;

        if (processEntryPointer == nullptr || bufferBegin == nullptr || bufferSize == 0)
        {
            return;
        }
        if (threadCount == 0)
        {
            // 无线程记录（例如 Idle 汇总项）按“运行中”处理，避免误显示为已挂起。
            processRecord.processStateKnown = true;
            return;
        }

        const BYTE* const threadArrayBegin = processEntryPointer + sizeof(SystemProcessInformationRecord);
        if (threadArrayBegin < bufferBegin)
        {
            return;
        }

        const std::size_t consumedBytes = static_cast<std::size_t>(threadArrayBegin - bufferBegin);
        const std::size_t threadArrayBytes =
            static_cast<std::size_t>(threadCount) * sizeof(SystemThreadInformationRecord);
        if (consumedBytes > bufferSize || threadArrayBytes > (bufferSize - consumedBytes))
        {
            return;
        }

        const auto* const threadArray =
            reinterpret_cast<const SystemThreadInformationRecord*>(threadArrayBegin);
        std::uint32_t suspendedCount = 0;
        for (std::uint32_t threadIndex = 0; threadIndex < threadCount; ++threadIndex)
        {
            const SystemThreadInformationRecord& threadInfo = threadArray[threadIndex];
            if (threadInfo.ThreadState != SystemThreadStateWaiting)
            {
                continue;
            }
            if (threadInfo.WaitReason == SystemThreadWaitReasonSuspended ||
                threadInfo.WaitReason == SystemThreadWaitReasonWrSuspended)
            {
                ++suspendedCount;
            }
        }

        processRecord.suspendedThreadCount = suspendedCount;
        processRecord.processSuspended = (suspendedCount == threadCount);
        processRecord.processStateKnown = true;
    }

    // 格式化 Win32 错误码文本，便于 UI 提示详细失败原因。
    std::string FormatLastErrorMessage(const DWORD errorCode)
    {
        wchar_t* wideBuffer = nullptr;
        const DWORD messageLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&wideBuffer),
            0,
            nullptr);

        if (messageLength == 0 || wideBuffer == nullptr)
        {
            std::ostringstream stream;
            stream << "Win32Error=" << errorCode;
            return stream.str();
        }

        std::wstring wideMessage(wideBuffer, messageLength);
        ::LocalFree(wideBuffer);

        std::string utf8Message = ks::str::Utf16ToUtf8(wideMessage);
        utf8Message = ks::str::TrimCopy(utf8Message);

        std::ostringstream stream;
        stream << utf8Message << " (Code=" << errorCode << ")";
        return stream.str();
    }

    // 格式化 NTSTATUS，避免 UI 只看到“失败”而不知道具体码值。
    std::string FormatNtStatusMessage(const NTSTATUS statusCode, const char* prefixText)
    {
        std::ostringstream stream;
        stream << (prefixText == nullptr ? "NTSTATUS failed" : prefixText)
            << " (0x" << std::hex << static_cast<unsigned long>(statusCode) << ")";
        return stream.str();
    }

    // 获取 ntdll 指定导出函数地址（懒加载）。
    FARPROC GetNtdllProcAddress(const char* functionName)
    {
        HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            ntdllModule = ::LoadLibraryW(L"ntdll.dll");
        }
        if (ntdllModule == nullptr)
        {
            return nullptr;
        }
        return ::GetProcAddress(ntdllModule, functionName);
    }

    // ProcessBasicInformationFullLocal：
    // - winternl.h 公开的 PROCESS_BASIC_INFORMATION 把 BasePriority 藏在 Reserved 字段里；
    // - 这里使用完整布局，仅为读取任务管理器“基本优先级”列所需的 KPRIORITY。
    struct ProcessBasicInformationFullLocal
    {
        NTSTATUS exitStatus = 0;                       // 进程退出码。
        PVOID pebBaseAddress = nullptr;                // PEB 基址，本用途不使用。
        ULONG_PTR affinityMask = 0;                    // 亲和性掩码，本用途不使用。
        LONG basePriority = 0;                         // KPRIORITY：0~31 的基础优先级。
        ULONG_PTR uniqueProcessId = 0;                 // PID。
        ULONG_PTR inheritedFromUniqueProcessId = 0;    // 父进程 PID。
    };

    // ApplyProcessBasePriorityAndCycleTimeByHandle 作用：
    // - 输入：已打开的进程句柄（至少具备 PROCESS_QUERY_LIMITED_INFORMATION）；
    // - 处理：读取 KPRIORITY 基础优先级与累计 CPU 周期数；
    // - 返回：无返回值，失败时保持记录内原值并让 cycleTimeKnown 维持 false。
    // 说明：该函数只在非 NtQuery 枚举路径使用；NtQuery 路径已在枚举缓冲区里拿到同样的值。
    void ApplyProcessBasePriorityAndCycleTimeByHandle(
        ks::process::ProcessRecord& processRecord,
        const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return;
        }

        const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            GetNtdllProcAddress("NtQueryInformationProcess"));
        if (ntQueryInformationProcess != nullptr)
        {
            ProcessBasicInformationFullLocal basicInfo{};
            ULONG returnLength = 0;
            const NTSTATUS queryStatus = ntQueryInformationProcess(
                processHandle,
                ProcessBasicInformation,
                &basicInfo,
                static_cast<ULONG>(sizeof(basicInfo)),
                &returnLength);
            if (NT_SUCCESS(queryStatus) && returnLength >= sizeof(basicInfo))
            {
                processRecord.basePriority = static_cast<std::int32_t>(basicInfo.basePriority);
            }
        }

        // QueryProcessCycleTime 声明在 realtimeapiset.h，不同 SDK 的默认包含情况不一致，
        // 因此统一动态解析 kernel32 导出，避免编译期依赖。
        using QueryProcessCycleTimeFn = BOOL(WINAPI*)(HANDLE, PULONG64);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto queryProcessCycleTime = reinterpret_cast<QueryProcessCycleTimeFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "QueryProcessCycleTime") : nullptr);
        if (queryProcessCycleTime != nullptr)
        {
            ULONG64 cycleTimeValue = 0;
            if (queryProcessCycleTime(processHandle, &cycleTimeValue) != FALSE)
            {
                processRecord.cycleTime = static_cast<std::uint64_t>(cycleTimeValue);
                processRecord.cycleTimeKnown = true;
            }
        }
    }

    // 查询是否可提升某特权（SeDebug 等），用于关键进程设置等高权限操作。
    bool EnablePrivilege(const wchar_t* privilegeName)
    {
        if (privilegeName == nullptr)
        {
            return false;
        }

        HANDLE processToken = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &processToken) == FALSE)
        {
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            ::CloseHandle(processToken);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        const BOOL adjustResult = ::AdjustTokenPrivileges(
            processToken,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr);
        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(processToken);

        return adjustResult != FALSE && adjustError == ERROR_SUCCESS;
    }

    // QueryProcessHandleCountsBySystemSnapshot 作用：
    // - 复用句柄模块相同思路，通过 NtQuerySystemInformation(64) 获取全系统句柄快照；
    // - 按 uniqueProcessId 聚合每个 PID 的句柄数量；
    // - 该路径不需要打开目标进程，因此可为 PPL/高权限进程提供 R3 可感知的句柄数。
    std::unordered_map<std::uint32_t, std::uint32_t> QueryProcessHandleCountsBySystemSnapshot()
    {
        std::unordered_map<std::uint32_t, std::uint32_t> handleCountByPid;

        const auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            GetNtdllProcAddress("NtQuerySystemInformation"));
        if (ntQuerySystemInformation == nullptr)
        {
            return handleCountByPid;
        }

        const SYSTEM_INFORMATION_CLASS systemExtendedHandleInformation =
            static_cast<SYSTEM_INFORMATION_CLASS>(64);
        constexpr NTSTATUS statusBufferOverflow = static_cast<NTSTATUS>(0x80000005L);
        constexpr NTSTATUS statusBufferTooSmall = static_cast<NTSTATUS>(0xC0000023L);
        constexpr ULONG maxBufferLength = 256UL * 1024UL * 1024UL;
        ULONG bufferLength = 2UL * 1024UL * 1024UL;
        ULONG returnLength = 0;
        std::vector<BYTE> informationBuffer(bufferLength);

        NTSTATUS queryStatus = ntQuerySystemInformation(
            systemExtendedHandleInformation,
            informationBuffer.data(),
            bufferLength,
            &returnLength);

        while (queryStatus == StatusInfoLengthMismatch ||
            queryStatus == statusBufferOverflow ||
            queryStatus == statusBufferTooSmall)
        {
            ULONG nextLength = (returnLength > bufferLength)
                ? returnLength
                : (bufferLength + bufferLength / 2UL + 64UL * 1024UL);
            if (nextLength <= bufferLength || nextLength > maxBufferLength)
            {
                return handleCountByPid;
            }

            bufferLength = nextLength;
            informationBuffer.assign(bufferLength, 0);
            returnLength = 0;
            queryStatus = ntQuerySystemInformation(
                systemExtendedHandleInformation,
                informationBuffer.data(),
                bufferLength,
                &returnLength);
        }

        if (!NT_SUCCESS(queryStatus) ||
            informationBuffer.size() < sizeof(SystemHandleInformationExLocal))
        {
            return handleCountByPid;
        }

        const auto* handleInfo =
            reinterpret_cast<const SystemHandleInformationExLocal*>(informationBuffer.data());
        const std::size_t headerBytes =
            offsetof(SystemHandleInformationExLocal, handles);
        const std::size_t availableEntryBytes =
            informationBuffer.size() > headerBytes ? informationBuffer.size() - headerBytes : 0;
        const std::size_t safeHandleCount = std::min<std::size_t>(
            static_cast<std::size_t>(handleInfo->numberOfHandles),
            availableEntryBytes / sizeof(SystemHandleTableEntryInfoExLocal));

        handleCountByPid.reserve(std::min<std::size_t>(safeHandleCount, 8192));
        for (std::size_t handleIndex = 0; handleIndex < safeHandleCount; ++handleIndex)
        {
            const auto& handleEntry = handleInfo->handles[handleIndex];
            const std::uint32_t processId = static_cast<std::uint32_t>(handleEntry.uniqueProcessId);
            ++handleCountByPid[processId];
        }

        return handleCountByPid;
    }

    // containsGpuEnginePidPrefixAt 作用：
    // - 判断 GPU Engine 实例名某个位置是否为 "pid_"；
    // - PDH 实例名通常为 pid_1234_luid_..._engtype_3D；
    // - 这里不依赖大小写，避免不同 Windows 构建输出大小写差异。
    bool containsGpuEnginePidPrefixAt(
        const std::wstring& instanceName,
        const std::size_t offset)
    {
        constexpr wchar_t expectedPrefix[] = L"pid_";
        constexpr std::size_t expectedPrefixLength = 4;
        if (offset + expectedPrefixLength > instanceName.size())
        {
            return false;
        }

        for (std::size_t prefixIndex = 0; prefixIndex < expectedPrefixLength; ++prefixIndex)
        {
            const wchar_t actualChar = static_cast<wchar_t>(
                std::towlower(instanceName[offset + prefixIndex]));
            if (actualChar != expectedPrefix[prefixIndex])
            {
                return false;
            }
        }
        return true;
    }

    // ExtractPidFromGpuEngineInstanceName 作用：
    // - 从 PDH GPU Engine 实例名中解析 pid_ 后面的十进制 PID；
    // - 返回 0 表示实例名不含可用 PID，调用方会忽略该条计数器。
    std::uint32_t ExtractPidFromGpuEngineInstanceName(const wchar_t* const rawInstanceName)
    {
        if (rawInstanceName == nullptr || rawInstanceName[0] == L'\0')
        {
            return 0;
        }

        const std::wstring instanceName(rawInstanceName);
        for (std::size_t offset = 0; offset < instanceName.size(); ++offset)
        {
            if (!containsGpuEnginePidPrefixAt(instanceName, offset))
            {
                continue;
            }

            const wchar_t* const digitBegin = instanceName.c_str() + offset + 4;
            if (*digitBegin == L'\0' || std::iswdigit(*digitBegin) == 0)
            {
                continue;
            }

            wchar_t* digitEnd = nullptr;
            const unsigned long parsedPid = std::wcstoul(digitBegin, &digitEnd, 10);
            if (digitEnd == digitBegin || parsedPid == 0UL)
            {
                continue;
            }
            if (parsedPid > static_cast<unsigned long>(std::numeric_limits<std::uint32_t>::max()))
            {
                continue;
            }
            return static_cast<std::uint32_t>(parsedPid);
        }

        return 0;
    }

    // ExtractGpuEngineDisplayText 作用：
    // - 输入：PDH GPU Engine 实例名，形如
    //   "pid_1234_luid_0x00000000_0x0000A1B2_phys_0_eng_3_engtype_3D"；
    // - 处理：解析 phys_N 与 engtype_XXX 两段，拼成任务管理器同款 "GPU N - XXX"；
    // - 返回：展示文本；实例名缺少可解析片段时返回空串，调用方据此跳过。
    std::string ExtractGpuEngineDisplayText(const wchar_t* const rawInstanceName)
    {
        if (rawInstanceName == nullptr || rawInstanceName[0] == L'\0')
        {
            return std::string();
        }

        // 实例名全部由 ASCII 构成，先做一次小写归一，简化后续定位。
        std::wstring instanceName(rawInstanceName);
        std::wstring loweredName;
        loweredName.reserve(instanceName.size());
        for (const wchar_t nameChar : instanceName)
        {
            loweredName.push_back(static_cast<wchar_t>(std::towlower(nameChar)));
        }

        // 引擎类型：engtype_ 之后到字符串结尾（PDH 把它放在实例名末尾）。
        std::string engineTypeText;
        const std::size_t engineTypeOffset = loweredName.rfind(L"engtype_");
        if (engineTypeOffset != std::wstring::npos)
        {
            const std::size_t valueOffset = engineTypeOffset + 8U;
            if (valueOffset < instanceName.size())
            {
                engineTypeText = ks::str::Utf16ToUtf8(instanceName.substr(valueOffset));
            }
        }
        if (engineTypeText.empty())
        {
            return std::string();
        }

        // 适配器序号：phys_ 之后的十进制数字，缺失时只显示引擎类型。
        const std::size_t physicalOffset = loweredName.rfind(L"phys_");
        if (physicalOffset == std::wstring::npos)
        {
            return engineTypeText;
        }

        const wchar_t* const digitBegin = instanceName.c_str() + physicalOffset + 5U;
        if (*digitBegin == L'\0' || std::iswdigit(*digitBegin) == 0)
        {
            return engineTypeText;
        }

        wchar_t* digitEnd = nullptr;
        const unsigned long physicalIndex = std::wcstoul(digitBegin, &digitEnd, 10);
        if (digitEnd == digitBegin)
        {
            return engineTypeText;
        }

        return std::string("GPU ") + std::to_string(physicalIndex) + " - " + engineTypeText;
    }

    // GpuProcessUsageSample：单个进程在一轮 PDH 采样中的 GPU 占用摘要。
    struct GpuProcessUsageSample
    {
        double utilizationPercent = 0.0; // utilizationPercent：该进程全部引擎累加后的 GPU 占用。
        double topEnginePercent = 0.0;   // topEnginePercent：占用最高的单个引擎百分比。
        std::string topEngineText;       // topEngineText：占用最高引擎的展示名，例如 "GPU 0 - 3D"。
    };

    // GpuProcessMemorySample：单个进程在一轮 PDH 采样中的显存占用。
    struct GpuProcessMemorySample
    {
        std::uint64_t dedicatedBytes = 0; // dedicatedBytes：专用 GPU 内存字节数。
        std::uint64_t sharedBytes = 0;    // sharedBytes：共享 GPU 内存字节数。
    };

    // GpuPdhQueryState：保存跨刷新轮次复用的 PDH 查询对象。
    struct GpuPdhQueryState
    {
        HQUERY queryHandle = nullptr;     // queryHandle：PDH 查询句柄，进程退出时由系统回收。
        HCOUNTER counterHandle = nullptr; // counterHandle：GPU Engine 通配计数器句柄。
        bool permanentlyUnavailable = false; // permanentlyUnavailable：当前系统没有可用 GPU Engine 计数器。
        bool hasBaselineSample = false;   // hasBaselineSample：百分比计数器需要至少两轮采样才有有效差值。
    };

    // GpuMemoryPdhQueryState：
    // - 保存 \GPU Process Memory(*) 的专用/共享用量计数器；
    // - 与 GPU Engine 查询相互独立，避免用户只显示显存列时被利用率计数器的基线逻辑拖累。
    struct GpuMemoryPdhQueryState
    {
        HQUERY queryHandle = nullptr;              // queryHandle：PDH 查询句柄。
        HCOUNTER dedicatedCounterHandle = nullptr; // dedicatedCounterHandle：Dedicated Usage 通配计数器。
        HCOUNTER sharedCounterHandle = nullptr;    // sharedCounterHandle：Shared Usage 通配计数器。
        bool permanentlyUnavailable = false;       // permanentlyUnavailable：当前系统没有该计数器集。
    };

    // gpuPdhQueryState 作用：
    // - 返回函数内静态状态，避免暴露全局符号；
    // - 该状态只在 QueryGpuUsagePercentByPid 的互斥锁保护下访问。
    GpuPdhQueryState& gpuPdhQueryState()
    {
        static GpuPdhQueryState state;
        return state;
    }

    // gpuPdhQueryMutex 作用：
    // - 保护 PDH 查询句柄和内部采样状态；
    // - 避免多个 UI/后台线程同时刷新进程列表时破坏 PDH 查询。
    std::mutex& gpuPdhQueryMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // gpuMemoryPdhQueryState 作用：
    // - 返回 GPU 显存计数器的函数内静态状态；
    // - 只在 gpuMemoryPdhQueryMutex 保护下访问。
    GpuMemoryPdhQueryState& gpuMemoryPdhQueryState()
    {
        static GpuMemoryPdhQueryState state;
        return state;
    }

    // gpuMemoryPdhQueryMutex 作用：
    // - 保护 GPU 显存 PDH 查询句柄；
    // - 与 GPU Engine 查询使用各自独立的锁，避免互相阻塞。
    std::mutex& gpuMemoryPdhQueryMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // addGpuEnglishCounter 作用：
    // - 优先动态调用 PdhAddEnglishCounterW，确保中文系统也能使用英文计数器路径；
    // - 若极旧运行环境没有该导出，则回退到 PdhAddCounterW。
    PDH_STATUS addGpuEnglishCounter(
        const HQUERY queryHandle,
        HCOUNTER* const counterHandleOut)
    {
        if (counterHandleOut == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }

        HMODULE pdhModule = ::GetModuleHandleW(L"pdh.dll");
        if (pdhModule == nullptr)
        {
            pdhModule = ::LoadLibraryW(L"pdh.dll");
        }

        const auto addEnglishCounter = reinterpret_cast<PdhAddEnglishCounterWFn>(
            pdhModule != nullptr ? ::GetProcAddress(pdhModule, "PdhAddEnglishCounterW") : nullptr);
        if (addEnglishCounter != nullptr)
        {
            return addEnglishCounter(
                queryHandle,
                L"\\GPU Engine(*)\\Utilization Percentage",
                0,
                counterHandleOut);
        }

        return ::PdhAddCounterW(
            queryHandle,
            L"\\GPU Engine(*)\\Utilization Percentage",
            0,
            counterHandleOut);
    }

    // addPdhEnglishCounterByPath 作用：
    // - 输入：已打开的 PDH 查询句柄与英文计数器路径；
    // - 处理：优先 PdhAddEnglishCounterW，极旧环境回退 PdhAddCounterW；
    // - 返回：PDH_STATUS，调用方据此决定是否放弃该计数器集。
    PDH_STATUS addPdhEnglishCounterByPath(
        const HQUERY queryHandle,
        const wchar_t* const counterPath,
        HCOUNTER* const counterHandleOut)
    {
        if (counterHandleOut == nullptr || counterPath == nullptr)
        {
            return ERROR_INVALID_PARAMETER;
        }

        HMODULE pdhModule = ::GetModuleHandleW(L"pdh.dll");
        if (pdhModule == nullptr)
        {
            pdhModule = ::LoadLibraryW(L"pdh.dll");
        }

        const auto addEnglishCounter = reinterpret_cast<PdhAddEnglishCounterWFn>(
            pdhModule != nullptr ? ::GetProcAddress(pdhModule, "PdhAddEnglishCounterW") : nullptr);
        if (addEnglishCounter != nullptr)
        {
            return addEnglishCounter(queryHandle, counterPath, 0, counterHandleOut);
        }
        return ::PdhAddCounterW(queryHandle, counterPath, 0, counterHandleOut);
    }

    // resetGpuMemoryPdhQueryState 作用：
    // - 关闭 GPU 显存 PDH 查询；
    // - markUnavailable 为 true 时不再重复初始化，避免无该计数器集的机器每轮重试。
    void resetGpuMemoryPdhQueryState(
        GpuMemoryPdhQueryState& state,
        const bool markUnavailable)
    {
        if (state.queryHandle != nullptr)
        {
            ::PdhCloseQuery(state.queryHandle);
        }
        state.queryHandle = nullptr;
        state.dedicatedCounterHandle = nullptr;
        state.sharedCounterHandle = nullptr;
        if (markUnavailable)
        {
            state.permanentlyUnavailable = true;
        }
    }

    // ensureGpuMemoryPdhQueryReadyLocked 作用：
    // - 初始化 \GPU Process Memory(*) 的专用/共享用量通配计数器；
    // - 调用方必须已经持有 gpuMemoryPdhQueryMutex；
    // - 返回 false 表示当前系统/权限下无法读取 GPU 显存计数器。
    bool ensureGpuMemoryPdhQueryReadyLocked(GpuMemoryPdhQueryState& state)
    {
        if (state.permanentlyUnavailable)
        {
            return false;
        }
        if (state.queryHandle != nullptr &&
            state.dedicatedCounterHandle != nullptr &&
            state.sharedCounterHandle != nullptr)
        {
            return true;
        }

        HQUERY queryHandle = nullptr;
        PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (status != ERROR_SUCCESS || queryHandle == nullptr)
        {
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        HCOUNTER dedicatedCounter = nullptr;
        status = addPdhEnglishCounterByPath(
            queryHandle,
            L"\\GPU Process Memory(*)\\Dedicated Usage",
            &dedicatedCounter);
        if (status != ERROR_SUCCESS || dedicatedCounter == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        HCOUNTER sharedCounter = nullptr;
        status = addPdhEnglishCounterByPath(
            queryHandle,
            L"\\GPU Process Memory(*)\\Shared Usage",
            &sharedCounter);
        if (status != ERROR_SUCCESS || sharedCounter == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuMemoryPdhQueryState(state, true);
            return false;
        }

        state.queryHandle = queryHandle;
        state.dedicatedCounterHandle = dedicatedCounter;
        state.sharedCounterHandle = sharedCounter;
        state.permanentlyUnavailable = false;
        return true;
    }

    // resetGpuPdhQueryState 作用：
    // - 关闭当前 PDH 查询；
    // - markUnavailable 为 true 时后续不再重复初始化，避免无 GPU 机器反复开销。
    void resetGpuPdhQueryState(
        GpuPdhQueryState& state,
        const bool markUnavailable)
    {
        if (state.queryHandle != nullptr)
        {
            ::PdhCloseQuery(state.queryHandle);
        }
        state.queryHandle = nullptr;
        state.counterHandle = nullptr;
        state.hasBaselineSample = false;
        if (markUnavailable)
        {
            state.permanentlyUnavailable = true;
        }
    }

    // ensureGpuPdhQueryReadyLocked 作用：
    // - 初始化 Windows GPU Engine PDH 通配计数器；
    // - 调用方必须已经持有 gpuPdhQueryMutex；
    // - 返回 false 表示当前系统/权限下无法读取 GPU Engine。
    bool ensureGpuPdhQueryReadyLocked(GpuPdhQueryState& state)
    {
        if (state.permanentlyUnavailable)
        {
            return false;
        }
        if (state.queryHandle != nullptr && state.counterHandle != nullptr)
        {
            return true;
        }

        HQUERY queryHandle = nullptr;
        PDH_STATUS status = ::PdhOpenQueryW(nullptr, 0, &queryHandle);
        if (status != ERROR_SUCCESS || queryHandle == nullptr)
        {
            resetGpuPdhQueryState(state, true);
            return false;
        }

        HCOUNTER counterHandle = nullptr;
        // 使用 English Counter 路径，避免中文系统上本地化计数器名称导致 AddCounter 失败。
        // addGpuEnglishCounter 内部会在极旧环境中回退 PdhAddCounterW。
        status = addGpuEnglishCounter(queryHandle, &counterHandle);
        if (status != ERROR_SUCCESS || counterHandle == nullptr)
        {
            ::PdhCloseQuery(queryHandle);
            resetGpuPdhQueryState(state, true);
            return false;
        }

        state.queryHandle = queryHandle;
        state.counterHandle = counterHandle;
        state.hasBaselineSample = false;
        state.permanentlyUnavailable = false;
        return true;
    }

    // QueryGpuUsageByPid 作用：
    // - 读取 \GPU Engine(*)\Utilization Percentage；
    // - 按实例名中的 pid_XXXX 聚合同一进程的多个 engine；
    // - 参数 collectEngineText 为 true 时额外记录占用最高的引擎展示名（任务管理器“GPU 引擎”列）；
    // - 返回 PID -> GPU 占用摘要，失败时返回空表。
    std::unordered_map<std::uint32_t, GpuProcessUsageSample> QueryGpuUsageByPid(const bool collectEngineText)
    {
        std::unordered_map<std::uint32_t, GpuProcessUsageSample> gpuUsageByPid;

        std::lock_guard<std::mutex> queryLock(gpuPdhQueryMutex());
        GpuPdhQueryState& state = gpuPdhQueryState();
        if (!ensureGpuPdhQueryReadyLocked(state))
        {
            return gpuUsageByPid;
        }

        const PDH_STATUS collectStatus = ::PdhCollectQueryData(state.queryHandle);
        if (collectStatus != ERROR_SUCCESS)
        {
            // 临时采样失败时允许下一轮重建查询，避免设备重置后长期卡死。
            resetGpuPdhQueryState(state, false);
            return gpuUsageByPid;
        }
        if (!state.hasBaselineSample)
        {
            // GPU Engine Utilization Percentage 和 System Informer 同类 PDH 方案一样需要基线样本。
            // 首次 Collect 只建立内部历史值，下一次刷新再读取格式化数组，避免首轮误报异常。
            state.hasBaselineSample = true;
            return gpuUsageByPid;
        }

        DWORD bufferSize = 0;
        DWORD itemCount = 0;
        PDH_STATUS formatStatus = ::PdhGetFormattedCounterArrayW(
            state.counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            nullptr);
        if (formatStatus == PDH_INVALID_DATA)
        {
            // PDH 许多百分比计数器需要两次 Collect；首轮无历史样本属于正常热身。
            return gpuUsageByPid;
        }
        if (formatStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
        {
            return gpuUsageByPid;
        }

        // PDH 输出缓冲区内既包含结构数组也包含实例名字符串；
        // 用 uint64_t 做底层存储可满足指针/DOUBLE 字段对齐要求。
        std::vector<std::uint64_t> itemStorage(
            (static_cast<std::size_t>(bufferSize) + sizeof(std::uint64_t) - 1U) /
            sizeof(std::uint64_t));
        auto* const itemList = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(itemStorage.data());
        formatStatus = ::PdhGetFormattedCounterArrayW(
            state.counterHandle,
            PDH_FMT_DOUBLE,
            &bufferSize,
            &itemCount,
            itemList);
        if (formatStatus != ERROR_SUCCESS)
        {
            return gpuUsageByPid;
        }

        gpuUsageByPid.reserve(static_cast<std::size_t>(itemCount));
        for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
        {
            const PDH_FMT_COUNTERVALUE_ITEM_W& item = itemList[itemIndex];
            const std::uint32_t processId = ExtractPidFromGpuEngineInstanceName(item.szName);
            if (processId == 0)
            {
                continue;
            }
            if (item.FmtValue.CStatus != ERROR_SUCCESS)
            {
                continue;
            }

            const double enginePercent = item.FmtValue.doubleValue;
            if (!std::isfinite(enginePercent) || enginePercent <= 0.0)
            {
                continue;
            }

            // 同一 PID 可能同时使用 3D/Copy/VideoDecode/Compute 等多个 engine，这里做总和。
            GpuProcessUsageSample& usageSample = gpuUsageByPid[processId];
            usageSample.utilizationPercent += enginePercent;

            // “GPU 引擎”列展示占用最高的那一个引擎，与任务管理器一致。
            if (collectEngineText && enginePercent > usageSample.topEnginePercent)
            {
                std::string engineDisplayText = ExtractGpuEngineDisplayText(item.szName);
                if (!engineDisplayText.empty())
                {
                    usageSample.topEnginePercent = enginePercent;
                    usageSample.topEngineText = std::move(engineDisplayText);
                }
            }
        }

        for (auto& gpuPair : gpuUsageByPid)
        {
            // UI 列按 0~100% 展示，异常累计值统一夹紧，避免多适配器场景破坏排序和高亮。
            gpuPair.second.utilizationPercent =
                std::clamp(gpuPair.second.utilizationPercent, 0.0, 100.0);
        }
        return gpuUsageByPid;
    }

    // QueryGpuProcessMemoryByPid 作用：
    // - 读取 \GPU Process Memory(*)\Dedicated Usage 与 Shared Usage；
    // - 两个计数器都是瞬时原始值，不需要基线样本；
    // - 返回 PID -> 显存占用；计数器不可用时返回空表。
    std::unordered_map<std::uint32_t, GpuProcessMemorySample> QueryGpuProcessMemoryByPid()
    {
        std::unordered_map<std::uint32_t, GpuProcessMemorySample> gpuMemoryByPid;

        std::lock_guard<std::mutex> queryLock(gpuMemoryPdhQueryMutex());
        GpuMemoryPdhQueryState& state = gpuMemoryPdhQueryState();
        if (!ensureGpuMemoryPdhQueryReadyLocked(state))
        {
            return gpuMemoryByPid;
        }

        const PDH_STATUS collectStatus = ::PdhCollectQueryData(state.queryHandle);
        if (collectStatus != ERROR_SUCCESS)
        {
            resetGpuMemoryPdhQueryState(state, false);
            return gpuMemoryByPid;
        }

        // accumulateCounter：把一个通配计数器的全部实例按 PID 聚合到目标字段。
        const auto accumulateCounter =
            [&gpuMemoryByPid](const HCOUNTER counterHandle, const bool writeDedicated) -> void
            {
                if (counterHandle == nullptr)
                {
                    return;
                }

                DWORD bufferSize = 0;
                DWORD itemCount = 0;
                PDH_STATUS formatStatus = ::PdhGetFormattedCounterArrayW(
                    counterHandle,
                    PDH_FMT_LARGE,
                    &bufferSize,
                    &itemCount,
                    nullptr);
                if (formatStatus != PDH_MORE_DATA || bufferSize == 0 || itemCount == 0)
                {
                    return;
                }

                std::vector<std::uint64_t> itemStorage(
                    (static_cast<std::size_t>(bufferSize) + sizeof(std::uint64_t) - 1U) /
                    sizeof(std::uint64_t));
                auto* const itemList = reinterpret_cast<PDH_FMT_COUNTERVALUE_ITEM_W*>(itemStorage.data());
                formatStatus = ::PdhGetFormattedCounterArrayW(
                    counterHandle,
                    PDH_FMT_LARGE,
                    &bufferSize,
                    &itemCount,
                    itemList);
                if (formatStatus != ERROR_SUCCESS)
                {
                    return;
                }

                for (DWORD itemIndex = 0; itemIndex < itemCount; ++itemIndex)
                {
                    const PDH_FMT_COUNTERVALUE_ITEM_W& item = itemList[itemIndex];
                    const std::uint32_t processId = ExtractPidFromGpuEngineInstanceName(item.szName);
                    if (processId == 0 || item.FmtValue.CStatus != ERROR_SUCCESS)
                    {
                        continue;
                    }
                    if (item.FmtValue.largeValue <= 0)
                    {
                        continue;
                    }

                    // 同一进程可能在多个适配器上都有显存实例，按 PID 求和。
                    const std::uint64_t usageBytes = static_cast<std::uint64_t>(item.FmtValue.largeValue);
                    GpuProcessMemorySample& memorySample = gpuMemoryByPid[processId];
                    if (writeDedicated)
                    {
                        memorySample.dedicatedBytes += usageBytes;
                    }
                    else
                    {
                        memorySample.sharedBytes += usageBytes;
                    }
                }
            };

        accumulateCounter(state.dedicatedCounterHandle, true);
        accumulateCounter(state.sharedCounterHandle, false);
        return gpuMemoryByPid;
    }

    // ApplyGpuUsageCountersToProcessList 作用：
    // - 将 PID 聚合后的 GPU 利用率写回进程快照；
    // - 参数 detailDemandFlags 决定是否额外采集引擎名称与显存占用；
    // - PDH 不可用时保持默认 0，不影响进程枚举主流程。
    void ApplyGpuUsageCountersToProcessList(
        std::vector<ks::process::ProcessRecord>& processList,
        const std::uint32_t detailDemandFlags)
    {
        if (processList.empty())
        {
            return;
        }

        const bool collectEngineText =
            (detailDemandFlags & ks::process::ProcessDetailDemand::GpuEngine) != 0U;
        const std::unordered_map<std::uint32_t, GpuProcessUsageSample> gpuUsageByPid =
            QueryGpuUsageByPid(collectEngineText);
        if (!gpuUsageByPid.empty())
        {
            for (ks::process::ProcessRecord& processRecord : processList)
            {
                const auto gpuIt = gpuUsageByPid.find(processRecord.pid);
                if (gpuIt == gpuUsageByPid.end())
                {
                    processRecord.gpuPercent = 0.0;
                    continue;
                }
                processRecord.gpuPercent = gpuIt->second.utilizationPercent;
                if (collectEngineText)
                {
                    processRecord.gpuEngineText = gpuIt->second.topEngineText;
                }
            }
        }

        // 显存列默认隐藏；只有用户显示相关列时才为整表付出一次额外 PDH 采样。
        if ((detailDemandFlags & ks::process::ProcessDetailDemand::GpuMemory) == 0U)
        {
            return;
        }

        const std::unordered_map<std::uint32_t, GpuProcessMemorySample> gpuMemoryByPid =
            QueryGpuProcessMemoryByPid();
        if (gpuMemoryByPid.empty())
        {
            return;
        }

        for (ks::process::ProcessRecord& processRecord : processList)
        {
            const auto memoryIt = gpuMemoryByPid.find(processRecord.pid);
            processRecord.gpuDedicatedMemoryBytes =
                (memoryIt == gpuMemoryByPid.end()) ? 0ULL : memoryIt->second.dedicatedBytes;
            processRecord.gpuSharedMemoryBytes =
                (memoryIt == gpuMemoryByPid.end()) ? 0ULL : memoryIt->second.sharedBytes;
            processRecord.gpuMemoryKnown = true;
        }
    }

    // 读取进程可执行路径（UTF-8），失败返回空串。
    std::string QueryProcessPathByHandle(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return std::string();
        }

        // 路径查询优先使用 QueryFullProcessImageNameW（支持 QUERY_LIMITED_INFORMATION）。
        std::wstring pathBuffer(32768, L'\0');
        DWORD pathLength = static_cast<DWORD>(pathBuffer.size());
        if (::QueryFullProcessImageNameW(processHandle, 0, pathBuffer.data(), &pathLength) != FALSE)
        {
            pathBuffer.resize(pathLength);
            return ks::str::Utf16ToUtf8(pathBuffer);
        }

        // 回退路径：GetModuleFileNameExW（部分进程在前者失败时可读取）。
        std::wstring modulePathBuffer(32768, L'\0');
        const DWORD modulePathLength = ::GetModuleFileNameExW(
            processHandle,
            nullptr,
            modulePathBuffer.data(),
            static_cast<DWORD>(modulePathBuffer.size()));
        if (modulePathLength > 0)
        {
            modulePathBuffer.resize(modulePathLength);
            return ks::str::Utf16ToUtf8(modulePathBuffer);
        }

        return std::string();
    }

    // QueryProcessStartTimeByPid 作用：
    // - 按 PID 读取进程创建时间（FILETIME）；
    // - 供 Restart Manager 的 RM_UNIQUE_PROCESS 结构体填充使用。
    bool QueryProcessStartTimeByPid(const std::uint32_t pid, FILETIME* const creationTimeOut)
    {
        if (creationTimeOut == nullptr || pid == 0)
        {
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
        if (processHandle == nullptr)
        {
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL queryResult = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        ::CloseHandle(processHandle);
        if (queryResult == FALSE)
        {
            return false;
        }

        *creationTimeOut = creationTime;
        return true;
    }

    // QueryModuleBaseAddressBySnapshot 作用：
    // - 通过模块快照定位目标模块基址；
    // - 用于 NtUnmapViewOfSection 定位远程 ntdll.dll 映射地址。
    bool QueryModuleBaseAddressBySnapshot(
        const std::uint32_t pid,
        const wchar_t* const moduleNameText,
        void** const baseAddressOut)
    {
        if (baseAddressOut == nullptr || moduleNameText == nullptr || pid == 0)
        {
            return false;
        }
        *baseAddressOut = nullptr;

        const HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            static_cast<DWORD>(pid));
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        MODULEENTRY32W moduleEntry{};
        moduleEntry.dwSize = sizeof(moduleEntry);
        if (::Module32FirstW(snapshotHandle, &moduleEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            return false;
        }

        do
        {
            if (_wcsicmp(moduleEntry.szModule, moduleNameText) == 0)
            {
                *baseAddressOut = moduleEntry.modBaseAddr;
                ::CloseHandle(snapshotHandle);
                return true;
            }
        } while (::Module32NextW(snapshotHandle, &moduleEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        return false;
    }

    // 通过令牌查询 DOMAIN\\User 形式用户名。
    std::string QueryProcessUserNameByHandle(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return std::string();
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(processToken, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            ::CloseHandle(processToken);
            return std::string();
        }

        std::vector<BYTE> tokenBuffer(requiredLength);
        if (::GetTokenInformation(processToken, TokenUser, tokenBuffer.data(), requiredLength, &requiredLength) == FALSE)
        {
            ::CloseHandle(processToken);
            return std::string();
        }

        const auto* tokenUser = reinterpret_cast<const TOKEN_USER*>(tokenBuffer.data());
        wchar_t accountName[256] = {};
        wchar_t domainName[256] = {};
        DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
        DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
        SID_NAME_USE sidUse = SidTypeUnknown;

        const BOOL lookupResult = ::LookupAccountSidW(
            nullptr,
            tokenUser->User.Sid,
            accountName,
            &accountNameLength,
            domainName,
            &domainNameLength,
            &sidUse);
        ::CloseHandle(processToken);

        if (lookupResult == FALSE)
        {
            return std::string();
        }

        std::wstring fullUserName(domainName);
        if (!fullUserName.empty())
        {
            fullUserName += L"\\";
        }
        fullUserName += accountName;
        return ks::str::Utf16ToUtf8(fullUserName);
    }

    // 查询进程令牌是否提升（管理员）。
    bool QueryProcessIsElevatedByHandle(const HANDLE processHandle)
    {
        HANDLE processToken = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &processToken) == FALSE)
        {
            return false;
        }

        TOKEN_ELEVATION tokenElevation{};
        DWORD returnLength = 0;
        const BOOL queryResult = ::GetTokenInformation(
            processToken,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnLength);
        ::CloseHandle(processToken);

        if (queryResult == FALSE)
        {
            return false;
        }
        return tokenElevation.TokenIsElevated != 0;
    }

    // FileSignatureInfo：单个文件签名信息聚合结构。
    // 该结构用于同时携带：
    // 1) 厂家（Publisher）；
    // 2) 是否被 Windows 信任链接受；
    // 3) UI 直接显示文本。
    struct FileSignatureInfo
    {
        bool hasSignature = false;         // 是否检测到签名。
        bool trustedByWindows = false;     // 是否被 WinVerifyTrust 判定为受信任。
        std::string publisher;             // 证书发布者/厂家名称。
        std::string displayText;           // UI 显示文本（含厂家与可信状态）。
    };

    // QueryCompanyNameByVersion 作用：
    // - 从文件版本信息读取 CompanyName；
    // - 作为“证书发布者为空”时的厂家文本兜底。
    std::string QueryCompanyNameByVersion(const std::wstring& utf16Path)
    {
        if (utf16Path.empty())
        {
            return std::string();
        }

        DWORD versionHandle = 0;
        const DWORD versionInfoSize = ::GetFileVersionInfoSizeW(utf16Path.c_str(), &versionHandle);
        if (versionInfoSize == 0)
        {
            return std::string();
        }

        std::vector<BYTE> versionInfoBuffer(versionInfoSize, 0);
        if (::GetFileVersionInfoW(
            utf16Path.c_str(),
            0,
            versionInfoSize,
            versionInfoBuffer.data()) == FALSE)
        {
            return std::string();
        }

        // 优先读取语言代码页映射，确保拿到正确本地化字符串。
        struct LangAndCodePage
        {
            WORD language = 0;
            WORD codePage = 0;
        };
        LangAndCodePage* translation = nullptr;
        UINT translationSize = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translation),
            &translationSize) != FALSE &&
            translation != nullptr &&
            translationSize >= sizeof(LangAndCodePage))
        {
            wchar_t queryPath[96] = {};
            std::swprintf(
                queryPath,
                std::size(queryPath),
                L"\\StringFileInfo\\%04x%04x\\CompanyName",
                translation[0].language,
                translation[0].codePage);

            LPVOID companyValue = nullptr;
            UINT companyLength = 0;
            if (::VerQueryValueW(
                versionInfoBuffer.data(),
                queryPath,
                &companyValue,
                &companyLength) != FALSE &&
                companyValue != nullptr &&
                companyLength > 0)
            {
                return ks::str::Utf16ToUtf8(static_cast<const wchar_t*>(companyValue));
            }
        }

        // 语言映射缺失时，尝试常见英语代码页兜底。
        LPVOID fallbackValue = nullptr;
        UINT fallbackLength = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\StringFileInfo\\040904B0\\CompanyName",
            &fallbackValue,
            &fallbackLength) != FALSE &&
            fallbackValue != nullptr &&
            fallbackLength > 0)
        {
            return ks::str::Utf16ToUtf8(static_cast<const wchar_t*>(fallbackValue));
        }

        return std::string();
    }

    // QueryVersionStringValue 作用：
    // - 输入：映像完整路径与 StringFileInfo 中的条目名（例如 "FileDescription"）；
    // - 处理：优先按文件自带的语言/代码页读取，缺失时回退英语代码页；
    // - 返回：UTF-8 文本；文件没有版本资源或条目不存在时返回空串。
    std::string QueryVersionStringValue(
        const std::wstring& utf16Path,
        const wchar_t* const valueName)
    {
        if (utf16Path.empty() || valueName == nullptr)
        {
            return std::string();
        }

        DWORD versionHandle = 0;
        const DWORD versionInfoSize = ::GetFileVersionInfoSizeW(utf16Path.c_str(), &versionHandle);
        if (versionInfoSize == 0)
        {
            return std::string();
        }

        std::vector<BYTE> versionInfoBuffer(versionInfoSize, 0);
        if (::GetFileVersionInfoW(
            utf16Path.c_str(),
            0,
            versionInfoSize,
            versionInfoBuffer.data()) == FALSE)
        {
            return std::string();
        }

        struct LangAndCodePage
        {
            WORD language = 0;
            WORD codePage = 0;
        };
        LangAndCodePage* translation = nullptr;
        UINT translationSize = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translation),
            &translationSize) != FALSE &&
            translation != nullptr &&
            translationSize >= sizeof(LangAndCodePage))
        {
            wchar_t queryPath[128] = {};
            std::swprintf(
                queryPath,
                std::size(queryPath),
                L"\\StringFileInfo\\%04x%04x\\%s",
                translation[0].language,
                translation[0].codePage,
                valueName);

            LPVOID stringValue = nullptr;
            UINT stringLength = 0;
            if (::VerQueryValueW(
                versionInfoBuffer.data(),
                queryPath,
                &stringValue,
                &stringLength) != FALSE &&
                stringValue != nullptr &&
                stringLength > 0)
            {
                return ks::str::Utf16ToUtf8(static_cast<const wchar_t*>(stringValue));
            }
        }

        wchar_t fallbackPath[128] = {};
        std::swprintf(
            fallbackPath,
            std::size(fallbackPath),
            L"\\StringFileInfo\\040904B0\\%s",
            valueName);

        LPVOID fallbackValue = nullptr;
        UINT fallbackLength = 0;
        if (::VerQueryValueW(
            versionInfoBuffer.data(),
            fallbackPath,
            &fallbackValue,
            &fallbackLength) != FALSE &&
            fallbackValue != nullptr &&
            fallbackLength > 0)
        {
            return ks::str::Utf16ToUtf8(static_cast<const wchar_t*>(fallbackValue));
        }

        return std::string();
    }

    // ImageOsContextGuidMapping：
    // - 映像清单 <supportedOS Id="{GUID}"/> 到系统名称的映射；
    // - 顺序由新到旧，取匹配到的第一项，与任务管理器“操作系统上下文”显示最高受支持系统一致。
    struct ImageOsContextGuidMapping
    {
        const wchar_t* guidText; // supportedOS Id 属性中的 GUID（小写，含花括号）。
        const char* displayText; // 展示用系统名称。
    };

    const ImageOsContextGuidMapping ImageOsContextGuidMappings[] =
    {
        { L"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}", "Windows 10" },
        { L"{1f676c76-80e1-4239-95bb-83d0f6d0da78}", "Windows 8.1" },
        { L"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}", "Windows 8" },
        { L"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}", "Windows 7" },
        { L"{e2011457-1546-43c5-a5fe-008deee3d3f0}", "Windows Vista" }
    };

    // QueryImageOsContextText 作用：
    // - 输入：映像完整路径；
    // - 处理：以“仅资源”方式映射 PE，读取 RT_MANIFEST 并在其中查找 supportedOS GUID；
    // - 返回：匹配到的系统名称；映像没有兼容性清单时返回空串（任务管理器同样显示空）。
    // 安全性：使用 LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE，不会执行目标映像中的代码。
    std::string QueryImageOsContextText(const std::wstring& utf16Path)
    {
        if (utf16Path.empty())
        {
            return std::string();
        }

        const HMODULE imageModule = ::LoadLibraryExW(
            utf16Path.c_str(),
            nullptr,
            LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
        if (imageModule == nullptr)
        {
            return std::string();
        }

        std::string manifestText;
        // 常见清单资源 ID：1=CREATEPROCESS_MANIFEST_RESOURCE_ID，2/3 为 ISOLATIONAWARE 变体。
        for (WORD manifestId = 1; manifestId <= 3 && manifestText.empty(); ++manifestId)
        {
            const HRSRC resourceHandle = ::FindResourceW(
                imageModule,
                MAKEINTRESOURCEW(manifestId),
                MAKEINTRESOURCEW(24 /* RT_MANIFEST */));
            if (resourceHandle == nullptr)
            {
                continue;
            }

            const DWORD resourceSize = ::SizeofResource(imageModule, resourceHandle);
            if (resourceSize == 0)
            {
                continue;
            }

            const HGLOBAL resourceData = ::LoadResource(imageModule, resourceHandle);
            if (resourceData == nullptr)
            {
                continue;
            }

            const void* const resourceBytes = ::LockResource(resourceData);
            if (resourceBytes == nullptr)
            {
                continue;
            }

            // 清单是 UTF-8 XML 文本；上限保护避免异常资源导致超大分配。
            constexpr DWORD ManifestMaxBytes = 1024U * 1024U;
            manifestText.assign(
                static_cast<const char*>(resourceBytes),
                static_cast<std::size_t>(std::min(resourceSize, ManifestMaxBytes)));
        }

        ::FreeLibrary(imageModule);
        if (manifestText.empty())
        {
            return std::string();
        }

        // GUID 大小写在不同工具链生成的清单里不统一，统一转小写后再比对。
        for (char& manifestChar : manifestText)
        {
            if (manifestChar >= 'A' && manifestChar <= 'Z')
            {
                manifestChar = static_cast<char>(manifestChar - 'A' + 'a');
            }
        }

        for (const ImageOsContextGuidMapping& mapping : ImageOsContextGuidMappings)
        {
            const std::string guidNarrow = ks::str::Utf16ToUtf8(mapping.guidText);
            if (manifestText.find(guidNarrow) != std::string::npos)
            {
                return std::string(mapping.displayText);
            }
        }

        return std::string();
    }

    // ImageDescriptionCacheEntry：按映像路径缓存的“说明 / 操作系统上下文”解析结果。
    struct ImageDescriptionCacheEntry
    {
        std::string fileDescription;    // 版本资源 FileDescription。
        std::string osContextText;      // 清单 supportedOS 映射出的系统名。
        bool descriptionResolved = false; // true 表示已尝试解析 FileDescription（含解析出空串）。
        bool osContextResolved = false;   // true 表示已尝试解析清单。
    };

    // imageDescriptionCache 作用：
    // - 说明与操作系统上下文只取决于磁盘上的映像文件，同名进程可以完全共享结果；
    // - 缓存把“每进程每轮解析 PE”降为“每映像一次”，这是这两列可以常驻显示的前提。
    std::unordered_map<std::string, ImageDescriptionCacheEntry>& imageDescriptionCache()
    {
        static std::unordered_map<std::string, ImageDescriptionCacheEntry> cache;
        return cache;
    }

    // imageDescriptionCacheMutex 作用：保护 imageDescriptionCache，供后台多线程静态补齐并发访问。
    std::mutex& imageDescriptionCacheMutex()
    {
        static std::mutex mutex;
        return mutex;
    }

    // ImageDescriptionCacheMaximumEntryCount：
    // - 缓存条目上限；达到上限后整体清空重建，避免长时间运行后无界增长。
    constexpr std::size_t ImageDescriptionCacheMaximumEntryCount = 4096;

    // ResolveImageDescriptionCached 作用：
    // - 输入：映像路径与本次需要的字段（说明 / 操作系统上下文）；
    // - 处理：命中缓存直接返回，未命中时解析一次并写回缓存；
    // - 返回：无返回值，结果通过输出参数回传。
    void ResolveImageDescriptionCached(
        const std::string& imagePath,
        const bool wantFileDescription,
        const bool wantOsContext,
        std::string* const fileDescriptionOut,
        std::string* const osContextTextOut)
    {
        if (imagePath.empty() || (!wantFileDescription && !wantOsContext))
        {
            return;
        }

        {
            std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
            const auto cacheIt = imageDescriptionCache().find(imagePath);
            if (cacheIt != imageDescriptionCache().end())
            {
                const ImageDescriptionCacheEntry& cachedEntry = cacheIt->second;
                const bool descriptionSatisfied = !wantFileDescription || cachedEntry.descriptionResolved;
                const bool osContextSatisfied = !wantOsContext || cachedEntry.osContextResolved;
                if (descriptionSatisfied && osContextSatisfied)
                {
                    if (wantFileDescription && fileDescriptionOut != nullptr)
                    {
                        *fileDescriptionOut = cachedEntry.fileDescription;
                    }
                    if (wantOsContext && osContextTextOut != nullptr)
                    {
                        *osContextTextOut = cachedEntry.osContextText;
                    }
                    return;
                }
            }
        }

        // 解析阶段不持锁：PE 映射与版本资源读取都可能涉及磁盘 I/O。
        const std::wstring utf16Path = ks::str::Utf8ToUtf16(imagePath);
        std::string resolvedDescription;
        std::string resolvedOsContext;
        if (wantFileDescription)
        {
            resolvedDescription = QueryVersionStringValue(utf16Path, L"FileDescription");
        }
        if (wantOsContext)
        {
            resolvedOsContext = QueryImageOsContextText(utf16Path);
        }

        {
            std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
            if (imageDescriptionCache().size() >= ImageDescriptionCacheMaximumEntryCount)
            {
                imageDescriptionCache().clear();
            }

            ImageDescriptionCacheEntry& cacheEntry = imageDescriptionCache()[imagePath];
            if (wantFileDescription)
            {
                cacheEntry.fileDescription = resolvedDescription;
                cacheEntry.descriptionResolved = true;
            }
            if (wantOsContext)
            {
                cacheEntry.osContextText = resolvedOsContext;
                cacheEntry.osContextResolved = true;
            }
        }

        if (wantFileDescription && fileDescriptionOut != nullptr)
        {
            *fileDescriptionOut = std::move(resolvedDescription);
        }
        if (wantOsContext && osContextTextOut != nullptr)
        {
            *osContextTextOut = std::move(resolvedOsContext);
        }
    }

    // QueryProcessUacVirtualizationStateByHandle 作用：
    // - 输入：具备 PROCESS_QUERY_LIMITED_INFORMATION 的进程句柄；
    // - 处理：读取令牌的 TokenVirtualizationAllowed / TokenVirtualizationEnabled；
    // - 返回：UAC 虚拟化三态；无法打开令牌时返回 Unknown。
    ks::process::ProcessFeatureState QueryProcessUacVirtualizationStateByHandle(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return ks::process::ProcessFeatureState::Unknown;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE || tokenHandle == nullptr)
        {
            return ks::process::ProcessFeatureState::Unknown;
        }

        DWORD virtualizationAllowed = 0;
        DWORD returnLength = 0;
        const BOOL allowedOk = ::GetTokenInformation(
            tokenHandle,
            TokenVirtualizationAllowed,
            &virtualizationAllowed,
            static_cast<DWORD>(sizeof(virtualizationAllowed)),
            &returnLength);
        if (allowedOk == FALSE)
        {
            ::CloseHandle(tokenHandle);
            return ks::process::ProcessFeatureState::Unknown;
        }
        if (virtualizationAllowed == 0)
        {
            // 64 位进程与多数系统组件都不允许虚拟化，任务管理器显示“不允许”。
            ::CloseHandle(tokenHandle);
            return ks::process::ProcessFeatureState::NotAllowed;
        }

        DWORD virtualizationEnabled = 0;
        const BOOL enabledOk = ::GetTokenInformation(
            tokenHandle,
            TokenVirtualizationEnabled,
            &virtualizationEnabled,
            static_cast<DWORD>(sizeof(virtualizationEnabled)),
            &returnLength);
        ::CloseHandle(tokenHandle);
        if (enabledOk == FALSE)
        {
            return ks::process::ProcessFeatureState::Unknown;
        }
        return (virtualizationEnabled != 0)
            ? ks::process::ProcessFeatureState::Enabled
            : ks::process::ProcessFeatureState::Disabled;
    }

    // ApplyProcessMitigationStatesByHandle 作用：
    // - 输入：进程句柄；
    // - 处理：读取数据执行保护与控制流保护缓解策略；
    // - 返回：true 表示至少有一项策略读取成功。
    // 兼容性：GetProcessMitigationPolicy 从 Windows 8 起提供，动态解析后在旧系统上安全跳过。
    bool ApplyProcessMitigationStatesByHandle(
        ks::process::ProcessRecord& processRecord,
        const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }

        using GetProcessMitigationPolicyFn =
            BOOL(WINAPI*)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto getProcessMitigationPolicy = reinterpret_cast<GetProcessMitigationPolicyFn>(
            kernel32Module != nullptr
            ? ::GetProcAddress(kernel32Module, "GetProcessMitigationPolicy")
            : nullptr);
        if (getProcessMitigationPolicy == nullptr)
        {
            return false;
        }

        bool anySucceeded = false;

        PROCESS_MITIGATION_DEP_POLICY depPolicy{};
        if (getProcessMitigationPolicy(
            processHandle,
            ProcessDEPPolicy,
            &depPolicy,
            sizeof(depPolicy)) != FALSE)
        {
            if (depPolicy.Enable == 0)
            {
                processRecord.dataExecutionPreventionState = ks::process::ProcessFeatureState::Disabled;
            }
            else
            {
                processRecord.dataExecutionPreventionState = (depPolicy.Permanent != FALSE)
                    ? ks::process::ProcessFeatureState::EnabledPermanent
                    : ks::process::ProcessFeatureState::Enabled;
            }
            anySucceeded = true;
        }

        PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY controlFlowGuardPolicy{};
        if (getProcessMitigationPolicy(
            processHandle,
            ProcessControlFlowGuardPolicy,
            &controlFlowGuardPolicy,
            sizeof(controlFlowGuardPolicy)) != FALSE)
        {
            processRecord.controlFlowGuardState = (controlFlowGuardPolicy.EnableControlFlowGuard != 0)
                ? ks::process::ProcessFeatureState::Enabled
                : ks::process::ProcessFeatureState::Disabled;
            anySucceeded = true;
        }

        // 硬件强制实施的堆栈保护（Intel CET 用户态影子栈）：
        // - 该策略从 Windows 10 20H1 起提供，旧系统上调用会失败并保持 Unknown。
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY userShadowStackPolicy{};
        if (getProcessMitigationPolicy(
            processHandle,
            ProcessUserShadowStackPolicy,
            &userShadowStackPolicy,
            sizeof(userShadowStackPolicy)) != FALSE)
        {
            processRecord.hardwareStackProtectionState =
                (userShadowStackPolicy.EnableUserShadowStack != 0U)
                ? ks::process::ProcessFeatureState::Enabled
                : ks::process::ProcessFeatureState::Disabled;
            anySucceeded = true;
        }

        return anySucceeded;
    }

    // QueryProcessPackageFullName 作用：
    // - 输入：具备 PROCESS_QUERY_LIMITED_INFORMATION 的进程句柄；
    // - 处理：读取 UWP / MSIX 程序包全名；
    // - 返回：true 表示判定成功（非打包进程也算成功，此时 packageNameOut 为空）。
    // 兼容性：GetPackageFullName 从 Windows 8 起提供，动态解析后在旧系统上安全跳过。
    bool QueryProcessPackageFullName(const HANDLE processHandle, std::string* const packageNameOut)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE || packageNameOut == nullptr)
        {
            return false;
        }
        packageNameOut->clear();

        using GetPackageFullNameFn = LONG(WINAPI*)(HANDLE, UINT32*, PWSTR);
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto getPackageFullName = reinterpret_cast<GetPackageFullNameFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetPackageFullName") : nullptr);
        if (getPackageFullName == nullptr)
        {
            return false;
        }

        // PACKAGE_FULL_NAME_MAX_LENGTH 为 127 个字符，这里多留终止符空间。
        UINT32 nameLength = 128;
        std::wstring nameBuffer(nameLength, L'\0');
        LONG queryResult = getPackageFullName(processHandle, &nameLength, nameBuffer.data());
        if (queryResult == ERROR_INSUFFICIENT_BUFFER)
        {
            nameBuffer.assign(nameLength + 1U, L'\0');
            queryResult = getPackageFullName(processHandle, &nameLength, nameBuffer.data());
        }

        if (queryResult == ERROR_SUCCESS)
        {
            nameBuffer.resize(::wcsnlen(nameBuffer.c_str(), nameBuffer.size()));
            *packageNameOut = ks::str::Utf16ToUtf8(nameBuffer);
            return true;
        }

        // APPMODEL_ERROR_NO_PACKAGE：目标不是打包应用，这是明确结论而不是失败。
        return queryResult == APPMODEL_ERROR_NO_PACKAGE;
    }

    // QueryProcessDpiAwarenessLevel 作用：
    // - 输入：进程句柄；
    // - 处理：优先用 user32 的 DPI 感知上下文接口区分“每监视器 V2 / GDI 缩放”，
    //   否则回退 shcore 的三态查询；
    // - 返回：DPI 感知级别；两条路径都不可用时返回 Unknown。
    ks::process::ProcessDpiAwarenessLevel QueryProcessDpiAwarenessLevel(const HANDLE processHandle)
    {
        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return ks::process::ProcessDpiAwarenessLevel::Unknown;
        }

        using GetDpiAwarenessContextForProcessFn = DPI_AWARENESS_CONTEXT(WINAPI*)(HANDLE);
        using AreDpiAwarenessContextsEqualFn = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT, DPI_AWARENESS_CONTEXT);
        HMODULE user32Module = ::GetModuleHandleW(L"user32.dll");
        const auto getDpiContextForProcess = reinterpret_cast<GetDpiAwarenessContextForProcessFn>(
            user32Module != nullptr
            ? ::GetProcAddress(user32Module, "GetDpiAwarenessContextForProcess")
            : nullptr);
        const auto areDpiContextsEqual = reinterpret_cast<AreDpiAwarenessContextsEqualFn>(
            user32Module != nullptr
            ? ::GetProcAddress(user32Module, "AreDpiAwarenessContextsEqual")
            : nullptr);
        if (getDpiContextForProcess != nullptr && areDpiContextsEqual != nullptr)
        {
            const DPI_AWARENESS_CONTEXT dpiContext = getDpiContextForProcess(processHandle);
            if (dpiContext != nullptr)
            {
                // 比较顺序从具体到宽泛：V2 与 GDI 缩放都属于更细分的上下文，必须先判定。
                if (areDpiContextsEqual(dpiContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::PerMonitorAwareV2;
                }
                if (areDpiContextsEqual(dpiContext, DPI_AWARENESS_CONTEXT_UNAWARE_GDISCALED) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::UnawareGdiScaled;
                }
                if (areDpiContextsEqual(dpiContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::PerMonitorAware;
                }
                if (areDpiContextsEqual(dpiContext, DPI_AWARENESS_CONTEXT_SYSTEM_AWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::SystemAware;
                }
                if (areDpiContextsEqual(dpiContext, DPI_AWARENESS_CONTEXT_UNAWARE) != FALSE)
                {
                    return ks::process::ProcessDpiAwarenessLevel::Unaware;
                }
            }
        }

        // 回退路径：shcore 的 GetProcessDpiAwareness 只区分 Unaware / System / PerMonitor。
        using GetProcessDpiAwarenessFn = HRESULT(WINAPI*)(HANDLE, PROCESS_DPI_AWARENESS*);
        HMODULE shcoreModule = ::GetModuleHandleW(L"shcore.dll");
        if (shcoreModule == nullptr)
        {
            shcoreModule = ::LoadLibraryW(L"shcore.dll");
        }
        const auto getProcessDpiAwareness = reinterpret_cast<GetProcessDpiAwarenessFn>(
            shcoreModule != nullptr ? ::GetProcAddress(shcoreModule, "GetProcessDpiAwareness") : nullptr);
        if (getProcessDpiAwareness == nullptr)
        {
            return ks::process::ProcessDpiAwarenessLevel::Unknown;
        }

        PROCESS_DPI_AWARENESS awarenessValue = PROCESS_DPI_UNAWARE;
        if (FAILED(getProcessDpiAwareness(processHandle, &awarenessValue)))
        {
            return ks::process::ProcessDpiAwarenessLevel::Unknown;
        }
        switch (awarenessValue)
        {
        case PROCESS_SYSTEM_DPI_AWARE:
            return ks::process::ProcessDpiAwarenessLevel::SystemAware;
        case PROCESS_PER_MONITOR_DPI_AWARE:
            return ks::process::ProcessDpiAwarenessLevel::PerMonitorAware;
        case PROCESS_DPI_UNAWARE:
        default:
            return ks::process::ProcessDpiAwarenessLevel::Unaware;
        }
    }

    // QueryFileSignatureInfo 作用：
    // - 用 WinVerifyTrust 判断文件是否“Windows 信任”；
    // - 解析签名链获取发布者（厂家）；
    // - 构建统一显示文本，供表格与详情窗口直接展示。
    FileSignatureInfo QueryFileSignatureInfo(const std::string& utf8Path)
    {
        FileSignatureInfo signatureInfo{};
        signatureInfo.displayText = "Unknown";

        if (utf8Path.empty())
        {
            return signatureInfo;
        }

        const std::wstring utf16Path = ks::str::Utf8ToUtf16(utf8Path);
        if (utf16Path.empty())
        {
            return signatureInfo;
        }

        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        fileInfo.pcwszFilePath = utf16Path.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

        GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG verifyResult = ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        // 尝试通过签名链提取发布者名称（厂家）。
        if (trustData.hWVTStateData != nullptr)
        {
            CRYPT_PROVIDER_DATA* providerData = ::WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (providerData != nullptr)
            {
                CRYPT_PROVIDER_SGNR* signer = ::WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
                if (signer != nullptr && signer->csCertChain > 0 && signer->pasCertChain != nullptr)
                {
                    const CERT_CONTEXT* certificateContext = signer->pasCertChain[0].pCert;
                    if (certificateContext != nullptr)
                    {
                        wchar_t publisherBuffer[512] = {};
                        const DWORD publisherLength = ::CertGetNameStringW(
                            certificateContext,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            nullptr,
                            publisherBuffer,
                            static_cast<DWORD>(std::size(publisherBuffer)));
                        if (publisherLength > 1)
                        {
                            signatureInfo.publisher = ks::str::Utf16ToUtf8(publisherBuffer);
                        }
                    }
                }
            }
        }

        // 无论校验结果如何，都需要关闭 WinVerifyTrust 的状态句柄，避免泄漏。
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        ::WinVerifyTrust(nullptr, &policyGuid, &trustData);

        // 若证书链里拿不到发布者，则回退到文件版本 CompanyName。
        if (signatureInfo.publisher.empty())
        {
            signatureInfo.publisher = QueryCompanyNameByVersion(utf16Path);
        }
        signatureInfo.publisher = ks::str::TrimCopy(signatureInfo.publisher);

        if (verifyResult == ERROR_SUCCESS)
        {
            signatureInfo.hasSignature = true;
            signatureInfo.trustedByWindows = true;
            if (signatureInfo.publisher.empty())
            {
                signatureInfo.publisher = "Unknown Publisher";
            }
            signatureInfo.displayText = signatureInfo.publisher + " (Trusted)";
            return signatureInfo;
        }

        if (verifyResult == TRUST_E_NOSIGNATURE || verifyResult == TRUST_E_SUBJECT_FORM_UNKNOWN)
        {
            signatureInfo.hasSignature = false;
            signatureInfo.trustedByWindows = false;
            signatureInfo.displayText = "Unsigned";
            return signatureInfo;
        }

        // 其他失败码统一视为“有签名但不受信任”。
        signatureInfo.hasSignature = true;
        signatureInfo.trustedByWindows = false;
        if (signatureInfo.publisher.empty())
        {
            signatureInfo.publisher = "Unknown Publisher";
        }
        signatureInfo.displayText = signatureInfo.publisher + " (Untrusted)";
        return signatureInfo;
    }

    // ReadRemoteMemoryExact：
    // - 从目标进程读取固定长度内存；
    // - 输入 processHandle 为目标进程句柄，remoteAddress 为远程地址；
    // - 输入 localBuffer/localSize 为本地缓冲；
    // - 返回 true 表示完整读取 localSize 字节，false 表示失败或部分读取。
    bool ReadRemoteMemoryExact(
        const HANDLE processHandle,
        const std::uint64_t remoteAddress,
        void* localBuffer,
        const SIZE_T localSize)
    {
        if (processHandle == nullptr || remoteAddress == 0 || localBuffer == nullptr || localSize == 0)
        {
            return false;
        }

        SIZE_T bytesRead = 0;
        const BOOL readOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(remoteAddress)),
            localBuffer,
            localSize,
            &bytesRead);
        return readOk != FALSE && bytesRead == localSize;
    }

    // ReadRemoteStructure：
    // - 模板化读取远程结构；
    // - 读取前清空输出结构，失败后调用者不会看到脏数据；
    // - 返回 true 表示读取完整结构成功。
    template<typename T>
    bool ReadRemoteStructure(
        const HANDLE processHandle,
        const std::uint64_t remoteAddress,
        T& valueOut)
    {
        std::memset(&valueOut, 0, sizeof(T));
        return ReadRemoteMemoryExact(
            processHandle,
            remoteAddress,
            &valueOut,
            static_cast<SIZE_T>(sizeof(T)));
    }

    // ReadRemoteUnicodeStringByAddress：
    // - 通过远程 UTF-16 地址和字节长度读取字符串；
    // - 对 Length 做偶数和上限校验，避免目标进程损坏字段拖垮枚举线程；
    // - 返回 UTF-8 文本，失败返回空字符串。
    std::string ReadRemoteUnicodeStringByAddress(
        const HANDLE processHandle,
        const std::uint64_t bufferAddress,
        const USHORT lengthBytes)
    {
        if (processHandle == nullptr || bufferAddress == 0 || lengthBytes == 0)
        {
            return std::string();
        }
        if ((lengthBytes % sizeof(wchar_t)) != 0 ||
            static_cast<std::size_t>(lengthBytes) > RemoteUnicodeStringMaxBytes)
        {
            return std::string();
        }

        std::wstring textBuffer(
            static_cast<std::size_t>(lengthBytes / sizeof(wchar_t)),
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL readOk = ::ReadProcessMemory(
            processHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(bufferAddress)),
            textBuffer.data(),
            static_cast<SIZE_T>(lengthBytes),
            &bytesRead);
        if (readOk == FALSE || bytesRead < sizeof(wchar_t))
        {
            return std::string();
        }

        const std::size_t charCount = static_cast<std::size_t>(
            std::min<SIZE_T>(bytesRead, static_cast<SIZE_T>(lengthBytes)) / sizeof(wchar_t));
        if (charCount < textBuffer.size())
        {
            textBuffer.resize(charCount);
        }
        return ks::str::Utf16ToUtf8(textBuffer);
    }

    // ReadRemoteUnicodeString64：
    // - 读取 64 位目标内的 UNICODE_STRING；
    // - 输入 remoteUnicode 是从远程结构体复制出的快照；
    // - 返回 UTF-8 文本，失败返回空字符串。
    std::string ReadRemoteUnicodeString64(
        const HANDLE processHandle,
        const UNICODE_STRING& remoteUnicode)
    {
        return ReadRemoteUnicodeStringByAddress(
            processHandle,
            reinterpret_cast<std::uint64_t>(remoteUnicode.Buffer),
            remoteUnicode.Length);
    }

    // ReadRemoteUnicodeString32：
    // - 读取 32 位目标内的 UNICODE_STRING；
    // - 输入 remoteUnicode 使用手工 32 位布局，避免指针宽度错位；
    // - 返回 UTF-8 文本，失败返回空字符串。
    std::string ReadRemoteUnicodeString32(
        const HANDLE processHandle,
        const RemoteUnicodeString32& remoteUnicode)
    {
        return ReadRemoteUnicodeStringByAddress(
            processHandle,
            static_cast<std::uint64_t>(remoteUnicode.buffer),
            remoteUnicode.length);
    }

    // QueryProcessCommandLineByNtInfo：
    // - 使用 ProcessCommandLineInformation 查询命令行；
    // - 新系统可直接返回 UNICODE_STRING + 字符串缓冲；
    // - 返回 UTF-8 文本，失败返回空字符串并交给 PEB 回退路径。
    std::string QueryProcessCommandLineByNtInfo(
        const NtQueryInformationProcessFn ntQueryInformationProcess,
        const HANDLE processHandle)
    {
        if (ntQueryInformationProcess == nullptr || processHandle == nullptr)
        {
            return std::string();
        }

        ULONG requiredLength = 0;
        NTSTATUS firstStatus = ntQueryInformationProcess(
            processHandle,
            ProcessCommandLineInformationClass,
            nullptr,
            0,
            &requiredLength);
        if (!NT_SUCCESS(firstStatus) && requiredLength == 0)
        {
            return std::string();
        }
        if (requiredLength < sizeof(UNICODE_STRING))
        {
            requiredLength = static_cast<ULONG>(sizeof(UNICODE_STRING) + 512);
        }

        std::vector<std::uint8_t> queryBuffer(requiredLength + sizeof(wchar_t), 0);
        NTSTATUS secondStatus = ntQueryInformationProcess(
            processHandle,
            ProcessCommandLineInformationClass,
            queryBuffer.data(),
            static_cast<ULONG>(queryBuffer.size()),
            &requiredLength);
        if (!NT_SUCCESS(secondStatus))
        {
            return std::string();
        }

        const auto* commandUnicode = reinterpret_cast<const UNICODE_STRING*>(queryBuffer.data());
        if (commandUnicode == nullptr || commandUnicode->Length == 0 || commandUnicode->Buffer == nullptr)
        {
            return std::string();
        }

        const std::uintptr_t bufferBegin = reinterpret_cast<std::uintptr_t>(queryBuffer.data());
        const std::uintptr_t bufferSize = queryBuffer.size();
        const std::uintptr_t textPtr = reinterpret_cast<std::uintptr_t>(commandUnicode->Buffer);
        const std::size_t textBytes = static_cast<std::size_t>(commandUnicode->Length);
        if ((textBytes % sizeof(wchar_t)) != 0 || textBytes > RemoteUnicodeStringMaxBytes)
        {
            return std::string();
        }

        if (textPtr >= bufferBegin &&
            textPtr - bufferBegin <= bufferSize &&
            textBytes <= bufferSize - (textPtr - bufferBegin))
        {
            const auto* wideText = reinterpret_cast<const wchar_t*>(textPtr);
            return ks::str::Utf16ToUtf8(std::wstring(
                wideText,
                wideText + static_cast<std::size_t>(commandUnicode->Length / sizeof(wchar_t))));
        }

        return ReadRemoteUnicodeString64(processHandle, *commandUnicode);
    }

    // QueryProcessCommandLineByPeb64：
    // - 按 64 位 PEB 布局读取 ProcessParameters.CommandLine；
    // - 用于 ProcessCommandLineInformation 失败后的回退；
    // - 返回 UTF-8 文本，失败返回空字符串。
    std::string QueryProcessCommandLineByPeb64(
        const HANDLE processHandle,
        const std::uint64_t pebAddress)
    {
        Peb64CommandLineLite pebSnapshot{};
        if (!ReadRemoteStructure(processHandle, pebAddress, pebSnapshot) ||
            pebSnapshot.processParameters == nullptr)
        {
            return std::string();
        }

        RtlUserProcessParameters64CommandLine processParameters{};
        if (!ReadRemoteStructure(
            processHandle,
            reinterpret_cast<std::uint64_t>(pebSnapshot.processParameters),
            processParameters))
        {
            return std::string();
        }

        return ReadRemoteUnicodeString64(processHandle, processParameters.commandLine);
    }

    // QueryProcessCommandLineByPeb32：
    // - 按 32 位 Wow64 PEB 布局读取 ProcessParameters.CommandLine；
    // - 修正 x64 控制进程读取 32 位目标时的结构偏移错位；
    // - 返回 UTF-8 文本，失败返回空字符串。
    std::string QueryProcessCommandLineByPeb32(
        const HANDLE processHandle,
        const std::uint64_t pebAddress)
    {
        Peb32CommandLineLite pebSnapshot{};
        if (!ReadRemoteStructure(processHandle, pebAddress, pebSnapshot) ||
            pebSnapshot.processParameters == 0)
        {
            return std::string();
        }

        RtlUserProcessParameters32CommandLine processParameters{};
        if (!ReadRemoteStructure(
            processHandle,
            static_cast<std::uint64_t>(pebSnapshot.processParameters),
            processParameters))
        {
            return std::string();
        }

        return ReadRemoteUnicodeString32(processHandle, processParameters.commandLine);
    }

    // 从远程进程读取命令行（读取 PEB / ProcessParameters）。
    std::string QueryProcessCommandLineByHandle(const HANDLE processHandle)
    {
        // 命令行读取顺序：
        // 1) 优先使用 ProcessCommandLineInformation，让系统处理结构差异；
        // 2) 再读 Native PEB，覆盖旧系统或受限信息类；
        // 3) 最后读 Wow64 PEB，修复 x64 工具读取 32 位目标时的偏移错位。
        const auto ntQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            GetNtdllProcAddress("NtQueryInformationProcess"));
        if (ntQueryInformationProcess == nullptr)
        {
            return std::string();
        }

        const std::string commandLineByInfo = QueryProcessCommandLineByNtInfo(
            ntQueryInformationProcess,
            processHandle);
        if (!commandLineByInfo.empty())
        {
            return commandLineByInfo;
        }

        ProcessBasicInformationLocal basicInfo{};
        NTSTATUS queryStatus = ntQueryInformationProcess(
            processHandle,
            ProcessBasicInformation,
            &basicInfo,
            static_cast<ULONG>(sizeof(basicInfo)),
            nullptr);
        if (!NT_SUCCESS(queryStatus) || basicInfo.pebBaseAddress == nullptr)
        {
            return std::string();
        }

        const std::string commandLineByNativePeb = QueryProcessCommandLineByPeb64(
            processHandle,
            reinterpret_cast<std::uint64_t>(basicInfo.pebBaseAddress));
        if (!commandLineByNativePeb.empty())
        {
            return commandLineByNativePeb;
        }

        ULONG_PTR wow64PebAddress = 0;
        NTSTATUS wow64Status = ntQueryInformationProcess(
            processHandle,
            ProcessWow64InformationClass,
            &wow64PebAddress,
            static_cast<ULONG>(sizeof(wow64PebAddress)),
            nullptr);
        if (NT_SUCCESS(wow64Status) &&
            wow64PebAddress != 0 &&
            wow64PebAddress != reinterpret_cast<ULONG_PTR>(basicInfo.pebBaseAddress))
        {
            return QueryProcessCommandLineByPeb32(
                processHandle,
                static_cast<std::uint64_t>(wow64PebAddress));
        }

        return std::string();
    }

    // 把 PID 转成 DWORD，统一并避免隐式窄化警告。
    DWORD ToDwordPid(const std::uint32_t pid)
    {
        return static_cast<DWORD>(pid);
    }

    // 按路径提取文件名（进程名兜底用）。
    std::string ExtractFileNameFromPath(const std::string& utf8Path)
    {
        if (utf8Path.empty())
        {
            return std::string();
        }
        const std::size_t lastSlash = utf8Path.find_last_of("\\/");
        if (lastSlash == std::string::npos)
        {
            return utf8Path;
        }
        return utf8Path.substr(lastSlash + 1);
    }

    // 把进程优先级常量转换为可读文本。
    std::string PriorityClassToText(const DWORD priorityClass)
    {
        switch (priorityClass)
        {
        case IDLE_PRIORITY_CLASS:
            return "Idle";
        case BELOW_NORMAL_PRIORITY_CLASS:
            return "BelowNormal";
        case NORMAL_PRIORITY_CLASS:
            return "Normal";
        case ABOVE_NORMAL_PRIORITY_CLASS:
            return "AboveNormal";
        case HIGH_PRIORITY_CLASS:
            return "High";
        case REALTIME_PRIORITY_CLASS:
            return "Realtime";
        default:
            return "Unknown";
        }
    }

    // 查询进程当前优先级文本。
    std::string QueryPriorityTextByHandle(const HANDLE processHandle)
    {
        const DWORD priorityClass = ::GetPriorityClass(processHandle);
        if (priorityClass == 0)
        {
            return "Unknown";
        }
        return PriorityClassToText(priorityClass);
    }
    // ProcessPowerThrottlingStateNative：
    // - 兼容旧 SDK 的本地结构声明；
    // - controlMask/stateMask 的 ExecutionSpeed 位代表 Windows 效率模式。
    struct ProcessPowerThrottlingStateNative
    {
        ULONG version = 0;
        ULONG controlMask = 0;
        ULONG stateMask = 0;
    };

    // ProcessProtectionLevelInformationNative：
    // - 兼容旧 SDK 的本地结构声明；
    // - protectionLevel 保存 PROTECTION_LEVEL_* 枚举。
    struct ProcessProtectionLevelInformationNative
    {
        DWORD protectionLevel = 0;
    };

    // ProcessProtectionLevelToText 作用：把公开枚举值翻译成 UI 可读文本。
    std::string ProcessProtectionLevelToText(const DWORD protectionLevel)
    {
        // protectionLevel 用途：GetProcessInformation 返回的原始枚举值。
        // 返回值：包含名称与十六进制值，方便用户与 WinAPI 文档对照。
        switch (protectionLevel)
        {
        case ProcessProtectionLevelNone:
            return "None (PROTECTION_LEVEL_NONE, 0xFFFFFFFE)";
        case ProcessProtectionLevelWinTcbLight:
            return "WinTcbLight (PROTECTION_LEVEL_WINTCB_LIGHT, 0x00000000)";
        case ProcessProtectionLevelWindows:
            return "Windows (PROTECTION_LEVEL_WINDOWS, 0x00000001)";
        case ProcessProtectionLevelWindowsLight:
            return "WindowsLight (PROTECTION_LEVEL_WINDOWS_LIGHT, 0x00000002)";
        case ProcessProtectionLevelAntimalwareLight:
            return "AntimalwareLight (PROTECTION_LEVEL_ANTIMALWARE_LIGHT, 0x00000003)";
        case ProcessProtectionLevelLsaLight:
            return "LsaLight (PROTECTION_LEVEL_LSA_LIGHT, 0x00000004)";
        case ProcessProtectionLevelWinTcb:
            return "WinTcb (PROTECTION_LEVEL_WINTCB, 0x00000005)";
        case ProcessProtectionLevelCodegenLight:
            return "CodegenLight (PROTECTION_LEVEL_CODEGEN_LIGHT, 0x00000006)";
        case ProcessProtectionLevelAuthenticode:
            return "Authenticode (PROTECTION_LEVEL_AUTHENTICODE, 0x00000007)";
        case ProcessProtectionLevelPplApp:
            return "PplApp (PROTECTION_LEVEL_PPL_APP, 0x00000008)";
        case ProcessProtectionLevelSame:
            return "Same (PROTECTION_LEVEL_SAME, 0xFFFFFFFF)";
        default:
            break;
        }

        std::ostringstream textBuilder;
        textBuilder << "Unknown (0x"
            << std::hex
            << std::uppercase
            << std::setw(8)
            << std::setfill('0')
            << static_cast<unsigned long>(protectionLevel)
            << ")";
        return textBuilder.str();
    }

    // QueryProcessEfficiencyModeByHandle 作用：读取目标进程效率模式状态。
    bool QueryProcessEfficiencyModeByHandle(
        const HANDLE processHandle,
        bool* const enabledOut,
        std::string* const errorMessage)
    {
        if (enabledOut != nullptr)
        {
            *enabledOut = false;
        }
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Process handle is null.";
            }
            return false;
        }

        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto getProcessInformation = reinterpret_cast<GetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
        if (getProcessInformation == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcessInformation(ProcessPowerThrottling) is not available.";
            }
            return false;
        }

        ProcessPowerThrottlingStateNative powerState{};
        powerState.version = ProcessPowerThrottlingCurrentVersion;
        const BOOL queryOk = getProcessInformation(
            processHandle,
            ProcessPowerThrottlingInfoClass,
            &powerState,
            static_cast<DWORD>(sizeof(powerState)));
        if (queryOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcessInformation(ProcessPowerThrottling) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        if (enabledOut != nullptr)
        {
            *enabledOut =
                (powerState.controlMask & ProcessPowerThrottlingExecutionSpeed) != 0 &&
                (powerState.stateMask & ProcessPowerThrottlingExecutionSpeed) != 0;
        }
        return true;
    }


    // 按 machine 常量转换为架构文本。
    std::string MachineToArchitectureText(const USHORT machineType)
    {
        switch (machineType)
        {
        case IMAGE_FILE_MACHINE_AMD64:
            return "x64";
        case IMAGE_FILE_MACHINE_I386:
            return "x86";
        case IMAGE_FILE_MACHINE_ARM64:
            return "ARM64";
        case IMAGE_FILE_MACHINE_ARM:
            return "ARM";
        default:
            return "Unknown";
        }
    }

    // 查询目标进程架构（优先 IsWow64Process2）。
    std::string QueryProcessArchitectureByHandle(const HANDLE processHandle)
    {
        using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
        const HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto isWow64Process2Fn = kernel32Module != nullptr
            ? reinterpret_cast<IsWow64Process2Fn>(::GetProcAddress(kernel32Module, "IsWow64Process2"))
            : nullptr;
        if (isWow64Process2Fn != nullptr)
        {
            USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (isWow64Process2Fn(processHandle, &processMachine, &nativeMachine) != FALSE)
            {
                // processMachine=UNKNOWN 表示“与系统原生架构一致”。
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN)
                {
                    return MachineToArchitectureText(nativeMachine);
                }
                return MachineToArchitectureText(processMachine);
            }
        }

        // 回退旧 API：只能区分 WOW64 x86 与“非 WOW64”。
        BOOL isWow64Process = FALSE;
        if (::IsWow64Process(processHandle, &isWow64Process) == FALSE)
        {
            return "Unknown";
        }

#if defined(_WIN64)
        return isWow64Process ? "x86" : "x64";
#else
        return isWow64Process ? "x86" : "x86";
#endif
    }

    // 读取 PE 头并返回 AddressOfEntryPoint（RVA）。
    std::uint32_t QueryImageEntryPointRvaByPath(const std::string& modulePath)
    {
        if (modulePath.empty())
        {
            return 0;
        }

        std::ifstream moduleFile(modulePath, std::ios::binary);
        if (!moduleFile.is_open())
        {
            return 0;
        }

        IMAGE_DOS_HEADER dosHeader{};
        moduleFile.read(reinterpret_cast<char*>(&dosHeader), sizeof(dosHeader));
        if (!moduleFile.good() || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            return 0;
        }

        moduleFile.seekg(static_cast<std::streamoff>(dosHeader.e_lfanew), std::ios::beg);
        DWORD ntSignature = 0;
        moduleFile.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
        if (!moduleFile.good() || ntSignature != IMAGE_NT_SIGNATURE)
        {
            return 0;
        }

        IMAGE_FILE_HEADER fileHeader{};
        moduleFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));
        if (!moduleFile.good())
        {
            return 0;
        }

        WORD optionalMagic = 0;
        moduleFile.read(reinterpret_cast<char*>(&optionalMagic), sizeof(optionalMagic));
        if (!moduleFile.good())
        {
            return 0;
        }
        moduleFile.seekg(-static_cast<std::streamoff>(sizeof(optionalMagic)), std::ios::cur);

        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 optionalHeader{};
            moduleFile.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
            if (!moduleFile.good())
            {
                return 0;
            }
            return optionalHeader.AddressOfEntryPoint;
        }

        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 optionalHeader{};
            moduleFile.read(reinterpret_cast<char*>(&optionalHeader), sizeof(optionalHeader));
            if (!moduleFile.good())
            {
                return 0;
            }
            return optionalHeader.AddressOfEntryPoint;
        }

        return 0;
    }

    // 把线程 ID 列表压缩为字符串，避免单元格过长。
    std::string BuildThreadIdSummaryText(const std::vector<std::uint32_t>& threadIds)
    {
        if (threadIds.empty())
        {
            return "-";
        }

        constexpr std::size_t MaxDisplayCount = 8;
        std::ostringstream stream;
        const std::size_t displayCount = std::min(MaxDisplayCount, threadIds.size());
        for (std::size_t index = 0; index < displayCount; ++index)
        {
            if (index > 0)
            {
                stream << ", ";
            }
            stream << threadIds[index];
        }
        if (threadIds.size() > MaxDisplayCount)
        {
            stream << " ... (+" << (threadIds.size() - MaxDisplayCount) << ")";
        }
        return stream.str();
    }

    // 路径是否指向目录。
    bool IsDirectoryPath(const std::string& utf8Path)
    {
        if (utf8Path.empty())
        {
            return false;
        }

        const std::wstring utf16Path = ks::str::Utf8ToUtf16(utf8Path);
        if (utf16Path.empty())
        {
            return false;
        }

        std::error_code errorCode;
        return std::filesystem::is_directory(std::filesystem::path(utf16Path), errorCode);
    }

    // 在 Explorer 中打开文件夹或定位文件。
    bool OpenInExplorerByPath(const std::string& targetPath, std::string* const errorMessage)
    {
        if (targetPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Target path is empty.";
            }
            return false;
        }

        const std::wstring utf16Path = ks::str::Utf8ToUtf16(targetPath);
        if (utf16Path.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Path UTF-8 -> UTF-16 conversion failed.";
            }
            return false;
        }

        HINSTANCE shellResult = nullptr;
        if (IsDirectoryPath(targetPath))
        {
            shellResult = ::ShellExecuteW(
                nullptr,
                L"open",
                utf16Path.c_str(),
                nullptr,
                nullptr,
                SW_SHOWNORMAL);
        }
        else
        {
            std::wstring parameters = L"/select,\"" + utf16Path + L"\"";
            shellResult = ::ShellExecuteW(
                nullptr,
                L"open",
                L"explorer.exe",
                parameters.c_str(),
                nullptr,
                SW_SHOWNORMAL);
        }

        if (reinterpret_cast<std::intptr_t>(shellResult) > 32)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "ShellExecute(explorer) failed, code=" << reinterpret_cast<std::intptr_t>(shellResult);
            *errorMessage = stream.str();
        }
        return false;
    }

    // 统一默认令牌访问掩码（用于“按 PID 打开并创建新进程”场景）。
    constexpr DWORD DefaultTokenDesiredAccess =
        TOKEN_QUERY |
        TOKEN_DUPLICATE |
        TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_PRIVILEGES |
        TOKEN_ADJUST_DEFAULT |
        TOKEN_ADJUST_SESSIONID;

    // 把 64 位整数和 HANDLE 互转，避免重复 reinterpret_cast。
    HANDLE Uint64ToHandle(const std::uint64_t rawValue)
    {
        return reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(rawValue));
    }

    std::uint64_t HandleToUint64(const HANDLE handleValue)
    {
        return static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(handleValue));
    }

    // 把 UI 传入的多行 KEY=VALUE 转为 Unicode 环境块（双 \0 结尾）。
    // 输入：entries 是 UTF-8 文本，每个元素代表一条环境变量。
    // 处理：跳过空白行和转换失败行，按 Win32 要求拼接为 "A=B\0C=D\0\0"。
    // 返回：有至少一条有效项时返回完整环境块；没有有效项时返回空 vector，让调用层传 nullptr。
    std::vector<wchar_t> BuildUnicodeEnvironmentBlock(const std::vector<std::string>& entries)
    {
        std::vector<wchar_t> environmentBlock;
        bool hasEntry = false;
        for (const std::string& entryText : entries)
        {
            const std::string trimmedEntry = ks::str::TrimCopy(entryText);
            if (trimmedEntry.empty())
            {
                continue;
            }

            const std::wstring wideEntry = ks::str::Utf8ToUtf16(trimmedEntry);
            if (wideEntry.empty())
            {
                continue;
            }

            environmentBlock.insert(environmentBlock.end(), wideEntry.begin(), wideEntry.end());
            environmentBlock.push_back(L'\0');
            hasEntry = true;
        }

        if (!hasEntry)
        {
            return std::vector<wchar_t>();
        }

        // 环境块必须以双 \0 结束；前面每条变量已经追加一个 \0，这里补最后一个。
        environmentBlock.push_back(L'\0');
        return environmentBlock;
    }

    // 把 UI 传入的多行 KEY=VALUE 转为 ANSI 环境块（双 \0 结尾）。
    // 输入：entries 是 UTF-8 文本，每个元素代表一条环境变量。
    // 处理：先转 UTF-16，再按系统 ANSI 代码页转窄字节，匹配未设置 CREATE_UNICODE_ENVIRONMENT 的 Win32 语义。
    // 返回：有至少一条有效项时返回完整环境块；没有有效项或转换失败时返回空 vector，让调用层传 nullptr。
    std::vector<char> BuildAnsiEnvironmentBlock(const std::vector<std::string>& entries)
    {
        std::vector<char> environmentBlock;
        bool hasEntry = false;
        for (const std::string& entryText : entries)
        {
            const std::string trimmedEntry = ks::str::TrimCopy(entryText);
            if (trimmedEntry.empty())
            {
                continue;
            }

            const std::wstring wideEntry = ks::str::Utf8ToUtf16(trimmedEntry);
            if (wideEntry.empty())
            {
                continue;
            }

            const int ansiLengthWithNull = ::WideCharToMultiByte(
                CP_ACP,
                0,
                wideEntry.c_str(),
                -1,
                nullptr,
                0,
                nullptr,
                nullptr);
            if (ansiLengthWithNull <= 1)
            {
                continue;
            }

            std::vector<char> ansiEntry(static_cast<std::size_t>(ansiLengthWithNull), '\0');
            const int convertedLengthWithNull = ::WideCharToMultiByte(
                CP_ACP,
                0,
                wideEntry.c_str(),
                -1,
                ansiEntry.data(),
                ansiLengthWithNull,
                nullptr,
                nullptr);
            if (convertedLengthWithNull <= 1)
            {
                continue;
            }

            environmentBlock.insert(
                environmentBlock.end(),
                ansiEntry.begin(),
                ansiEntry.end() - 1);
            environmentBlock.push_back('\0');
            hasEntry = true;
        }

        if (!hasEntry)
        {
            return std::vector<char>();
        }

        // 环境块必须以双 \0 结束；前面每条变量已经追加一个 \0，这里补最后一个。
        environmentBlock.push_back('\0');
        return environmentBlock;
    }

    // SECURITY_ATTRIBUTES 构建：false 表示调用层应传 nullptr。
    bool BuildSecurityAttributes(
        const ks::process::SecurityAttributesInput& inputValue,
        SECURITY_ATTRIBUTES& outputValue)
    {
        if (!inputValue.useValue)
        {
            return false;
        }

        outputValue = {};
        outputValue.nLength = inputValue.nLength == 0
            ? static_cast<DWORD>(sizeof(SECURITY_ATTRIBUTES))
            : static_cast<DWORD>(inputValue.nLength);
        outputValue.lpSecurityDescriptor = reinterpret_cast<LPVOID>(
            static_cast<std::uintptr_t>(inputValue.securityDescriptor));
        outputValue.bInheritHandle = inputValue.inheritHandle ? TRUE : FALSE;
        return true;
    }

    // STARTUPINFOW 字符串缓存，保证 CreateProcess 调用期间指针有效。
    struct StartupInfoBufferSet
    {
        std::wstring reservedText;
        std::wstring desktopText;
        std::wstring titleText;
    };

    // STARTUPINFOW 构建：CreateProcess* 始终要求有效结构；未自定义时使用默认零初始化值。
    void BuildStartupInfo(
        const ks::process::StartupInfoInput& inputValue,
        STARTUPINFOW& outputValue,
        StartupInfoBufferSet& bufferSet)
    {
        outputValue = {};
        outputValue.cb = (!inputValue.useValue || inputValue.cb == 0)
            ? static_cast<DWORD>(sizeof(STARTUPINFOW))
            : static_cast<DWORD>(inputValue.cb);
        if (!inputValue.useValue)
        {
            return;
        }

        if (!inputValue.lpReserved.empty())
        {
            bufferSet.reservedText = ks::str::Utf8ToUtf16(inputValue.lpReserved);
            if (!bufferSet.reservedText.empty())
            {
                outputValue.lpReserved = bufferSet.reservedText.data();
            }
        }
        if (!inputValue.lpDesktop.empty())
        {
            bufferSet.desktopText = ks::str::Utf8ToUtf16(inputValue.lpDesktop);
            if (!bufferSet.desktopText.empty())
            {
                outputValue.lpDesktop = bufferSet.desktopText.data();
            }
        }
        if (!inputValue.lpTitle.empty())
        {
            bufferSet.titleText = ks::str::Utf8ToUtf16(inputValue.lpTitle);
            if (!bufferSet.titleText.empty())
            {
                outputValue.lpTitle = bufferSet.titleText.data();
            }
        }

        outputValue.dwX = static_cast<DWORD>(inputValue.dwX);
        outputValue.dwY = static_cast<DWORD>(inputValue.dwY);
        outputValue.dwXSize = static_cast<DWORD>(inputValue.dwXSize);
        outputValue.dwYSize = static_cast<DWORD>(inputValue.dwYSize);
        outputValue.dwXCountChars = static_cast<DWORD>(inputValue.dwXCountChars);
        outputValue.dwYCountChars = static_cast<DWORD>(inputValue.dwYCountChars);
        outputValue.dwFillAttribute = static_cast<DWORD>(inputValue.dwFillAttribute);
        outputValue.dwFlags = static_cast<DWORD>(inputValue.dwFlags);
        outputValue.wShowWindow = static_cast<WORD>(inputValue.wShowWindow);
        outputValue.cbReserved2 = static_cast<WORD>(inputValue.cbReserved2);
        outputValue.lpReserved2 = reinterpret_cast<LPBYTE>(
            static_cast<std::uintptr_t>(inputValue.lpReserved2));
        outputValue.hStdInput = Uint64ToHandle(inputValue.hStdInput);
        outputValue.hStdOutput = Uint64ToHandle(inputValue.hStdOutput);
        outputValue.hStdError = Uint64ToHandle(inputValue.hStdError);
    }

    // PROCESS_INFORMATION 是 CreateProcess* 的输出缓冲区，调用前必须提供零初始化的有效地址。
    void InitializeProcessInformationOutput(PROCESS_INFORMATION& outputValue)
    {
        outputValue = {};
    }

    // 打开指定 PID 的进程令牌。
    bool OpenTokenByProcessPid(
        const std::uint32_t pid,
        const DWORD desiredAccess,
        HANDLE& tokenOut,
        std::string* const errorMessage)
    {
        tokenOut = nullptr;
        if (pid == 0)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "tokenSourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL openTokenOk = ::OpenProcessToken(processHandle, desiredAccess, &tokenOut);
        const DWORD openTokenError = ::GetLastError();
        ::CloseHandle(processHandle);
        if (openTokenOk == FALSE || tokenOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken failed: " + FormatLastErrorMessage(openTokenError);
            }
            return false;
        }
        return true;
    }

    // 可选把源令牌复制成 Primary Token（CreateProcessAsUserW 常用）。
    bool DuplicatePrimaryToken(
        const HANDLE sourceToken,
        const DWORD desiredAccess,
        HANDLE& duplicatedTokenOut,
        std::string* const errorMessage)
    {
        duplicatedTokenOut = nullptr;
        const BOOL duplicateOk = ::DuplicateTokenEx(
            sourceToken,
            desiredAccess,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &duplicatedTokenOut);
        if (duplicateOk == FALSE || duplicatedTokenOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DuplicateTokenEx(TokenPrimary) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }
        return true;
    }

    // 对单个特权执行 AdjustTokenPrivileges 调整。
    bool ApplySinglePrivilegeEdit(
        const HANDLE tokenHandle,
        const ks::process::TokenPrivilegeEdit& privilegeEdit,
        std::string* const errorMessage)
    {
        if (privilegeEdit.action == ks::process::TokenPrivilegeAction::Keep)
        {
            return true;
        }

        const std::string privilegeNameUtf8 = ks::str::TrimCopy(privilegeEdit.privilegeName);
        if (privilegeNameUtf8.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Privilege name is empty.";
            }
            return false;
        }

        const std::wstring privilegeNameWide = ks::str::Utf8ToUtf16(privilegeNameUtf8);
        if (privilegeNameWide.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Privilege name UTF-8 -> UTF-16 conversion failed: " + privilegeNameUtf8;
            }
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeNameWide.c_str(), &privilegeLuid) == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LookupPrivilegeValue failed(" + privilegeNameUtf8 + "): " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        switch (privilegeEdit.action)
        {
        case ks::process::TokenPrivilegeAction::Enable:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            break;
        case ks::process::TokenPrivilegeAction::Disable:
            tokenPrivileges.Privileges[0].Attributes = 0;
            break;
        case ks::process::TokenPrivilegeAction::Remove:
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;
            break;
        case ks::process::TokenPrivilegeAction::Keep:
        default:
            tokenPrivileges.Privileges[0].Attributes = 0;
            break;
        }

        ::SetLastError(ERROR_SUCCESS);
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            static_cast<DWORD>(sizeof(tokenPrivileges)),
            nullptr,
            nullptr) == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AdjustTokenPrivileges failed(" + privilegeNameUtf8 + "): " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD adjustError = ::GetLastError();
        if (adjustError != ERROR_SUCCESS)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AdjustTokenPrivileges returned error(" + privilegeNameUtf8 + "): " + FormatLastErrorMessage(adjustError);
            }
            return false;
        }
        return true;
    }

    // 批量应用特权调整。
    bool ApplyPrivilegeEdits(
        const HANDLE tokenHandle,
        const std::vector<ks::process::TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        for (std::size_t editIndex = 0; editIndex < edits.size(); ++editIndex)
        {
            if (!ApplySinglePrivilegeEdit(tokenHandle, edits[editIndex], errorMessage))
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "PrivilegeEdit[" + std::to_string(editIndex) + "] failed: " + *errorMessage;
                }
                return false;
            }
        }
        return true;
    }

    // DeferredRemoteLoadLibraryCleanup 作用：
    // - 输入：保存仍在执行的远程 LoadLibraryW 线程、目标进程句柄和远程 DLL 路径地址；
    // - 处理：把远程地址的释放延后到远程线程确实结束之后，避免超时返回时发生远程 Use-After-Free；
    // - 返回：作为后台清理线程的唯一上下文，由清理线程负责释放；
    // - 原因：LoadLibraryW 超时不代表远程线程已停止，调用方不能同步释放其参数内存。
    struct DeferredRemoteLoadLibraryCleanup
    {
        HANDLE processHandle = nullptr;
        HANDLE remoteThread = nullptr;
        void* remotePathMemory = nullptr;
    };

    // CompleteDeferredRemoteLoadLibraryCleanup 作用：
    // - 输入：parameterValue 指向转移所有权后的 DeferredRemoteLoadLibraryCleanup；
    // - 处理：等待远程 LoadLibraryW 线程结束，再释放它读取过的远程路径内存和全部句柄；
    // - 返回：始终返回 0，后台清理失败不影响调用线程已经返回的注入诊断。
    DWORD WINAPI CompleteDeferredRemoteLoadLibraryCleanup(const LPVOID parameterValue)
    {
        auto* const cleanupContext = static_cast<DeferredRemoteLoadLibraryCleanup*>(parameterValue);
        if (cleanupContext == nullptr)
        {
            return 0;
        }

        const DWORD waitResult = ::WaitForSingleObject(cleanupContext->remoteThread, INFINITE);
        if (waitResult == WAIT_OBJECT_0)
        {
            (void)::VirtualFreeEx(cleanupContext->processHandle, cleanupContext->remotePathMemory, 0, MEM_RELEASE);
        }

        if (cleanupContext->remoteThread != nullptr)
        {
            ::CloseHandle(cleanupContext->remoteThread);
        }
        if (cleanupContext->processHandle != nullptr)
        {
            ::CloseHandle(cleanupContext->processHandle);
        }
        delete cleanupContext;
        return 0;
    }

    // ScheduleDeferredRemoteLoadLibraryCleanup 作用：
    // - 输入：一个未完成的远程 LoadLibraryW 线程及其仍被读取的参数内存；
    // - 处理：创建独立后台线程接管全部资源，避免主线程超时后错误释放远程参数；
    // - 返回：成功转移资源所有权时为 true，失败时调用方仍必须保留远程内存。
    bool ScheduleDeferredRemoteLoadLibraryCleanup(
        const HANDLE processHandle,
        const HANDLE remoteThread,
        void* const remotePathMemory)
    {
        auto* const cleanupContext = new (std::nothrow) DeferredRemoteLoadLibraryCleanup{
            processHandle,
            remoteThread,
            remotePathMemory
        };
        if (cleanupContext == nullptr)
        {
            return false;
        }

        HANDLE cleanupThread = ::CreateThread(
            nullptr,
            0,
            &CompleteDeferredRemoteLoadLibraryCleanup,
            cleanupContext,
            0,
            nullptr);
        if (cleanupThread == nullptr)
        {
            delete cleanupContext;
            return false;
        }

        ::CloseHandle(cleanupThread);
        return true;
    }
}

namespace ks::process
{
    const std::vector<std::string>& KnownTokenPrivilegeNames()
    {
        // Windows SDK winnt.h 中 SE_*_NAME 的完整目录，顺序与 SDK 定义保持一致。
        static const std::vector<std::string> privilegeNames{
            ks::str::Utf16ToUtf8(SE_CREATE_TOKEN_NAME),
            ks::str::Utf16ToUtf8(SE_ASSIGNPRIMARYTOKEN_NAME),
            ks::str::Utf16ToUtf8(SE_LOCK_MEMORY_NAME),
            ks::str::Utf16ToUtf8(SE_INCREASE_QUOTA_NAME),
            ks::str::Utf16ToUtf8(SE_UNSOLICITED_INPUT_NAME),
            ks::str::Utf16ToUtf8(SE_MACHINE_ACCOUNT_NAME),
            ks::str::Utf16ToUtf8(SE_TCB_NAME),
            ks::str::Utf16ToUtf8(SE_SECURITY_NAME),
            ks::str::Utf16ToUtf8(SE_TAKE_OWNERSHIP_NAME),
            ks::str::Utf16ToUtf8(SE_LOAD_DRIVER_NAME),
            ks::str::Utf16ToUtf8(SE_SYSTEM_PROFILE_NAME),
            ks::str::Utf16ToUtf8(SE_SYSTEMTIME_NAME),
            ks::str::Utf16ToUtf8(SE_PROF_SINGLE_PROCESS_NAME),
            ks::str::Utf16ToUtf8(SE_INC_BASE_PRIORITY_NAME),
            ks::str::Utf16ToUtf8(SE_CREATE_PAGEFILE_NAME),
            ks::str::Utf16ToUtf8(SE_CREATE_PERMANENT_NAME),
            ks::str::Utf16ToUtf8(SE_BACKUP_NAME),
            ks::str::Utf16ToUtf8(SE_RESTORE_NAME),
            ks::str::Utf16ToUtf8(SE_SHUTDOWN_NAME),
            ks::str::Utf16ToUtf8(SE_DEBUG_NAME),
            ks::str::Utf16ToUtf8(SE_AUDIT_NAME),
            ks::str::Utf16ToUtf8(SE_SYSTEM_ENVIRONMENT_NAME),
            ks::str::Utf16ToUtf8(SE_CHANGE_NOTIFY_NAME),
            ks::str::Utf16ToUtf8(SE_REMOTE_SHUTDOWN_NAME),
            ks::str::Utf16ToUtf8(SE_UNDOCK_NAME),
            ks::str::Utf16ToUtf8(SE_SYNC_AGENT_NAME),
            ks::str::Utf16ToUtf8(SE_ENABLE_DELEGATION_NAME),
            ks::str::Utf16ToUtf8(SE_MANAGE_VOLUME_NAME),
            ks::str::Utf16ToUtf8(SE_IMPERSONATE_NAME),
            ks::str::Utf16ToUtf8(SE_CREATE_GLOBAL_NAME),
            ks::str::Utf16ToUtf8(SE_TRUSTED_CREDMAN_ACCESS_NAME),
            ks::str::Utf16ToUtf8(SE_RELABEL_NAME),
            ks::str::Utf16ToUtf8(SE_INC_WORKING_SET_NAME),
            ks::str::Utf16ToUtf8(SE_TIME_ZONE_NAME),
            ks::str::Utf16ToUtf8(SE_CREATE_SYMBOLIC_LINK_NAME),
            ks::str::Utf16ToUtf8(SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME)
        };
        return privilegeNames;
    }

    std::string BuildProcessIdentityKey(const std::uint32_t pid, const std::uint64_t creationTime100ns)
    {
        // identity 规则：PID#CreationTime100ns。
        return std::to_string(pid) + "#" + std::to_string(creationTime100ns);
    }

    std::string BuildThreadIdentityKey(
        const std::uint32_t pid,
        const std::uint32_t threadId,
        const std::uint64_t creationTime100ns)
    {
        // 创建时间不可得时仍保留 PID/TID；若发生复用，累计计数器回退会使该轮重新建立基准。
        return std::to_string(pid) + "#" + std::to_string(threadId) + "#" +
            std::to_string(creationTime100ns);
    }

    bool QueryProcessCreationTimeByPid(
        const std::uint32_t pid,
        std::uint64_t* const creationTime100nsOut,
        std::string* const detailTextOut)
    {
        // creationTime100nsOut：调用方必须提供有效输出地址，且失败时保持为 0。
        if (creationTime100nsOut == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process creation time output is null";
            }
            return false;
        }
        *creationTime100nsOut = 0U;

        // processHandle：只申请身份校验所需的受限查询权限，不扩大目标进程访问面。
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "OpenProcess failed(" + std::to_string(::GetLastError()) + ")";
            }
            return false;
        }

        // 四个 FILETIME 输出由 GetProcessTimes 一次填充；这里只消费 creationTime。
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL queryResult = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);

        // queryError：必须在关闭句柄前保存，防止 CloseHandle 覆盖线程错误码。
        const DWORD queryError = queryResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);
        if (queryResult == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "GetProcessTimes failed(" + std::to_string(queryError) + ")";
            }
            return false;
        }

        // creationTimeValue：将 FILETIME 高低位转换为项目统一的 100ns identity 值。
        const std::uint64_t creationTimeValue = ks::str::FileTimeToUint64(
            creationTime.dwHighDateTime,
            creationTime.dwLowDateTime);
        if (creationTimeValue == 0U)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = "process creation time is zero";
            }
            return false;
        }

        *creationTime100nsOut = creationTimeValue;
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }
        return true;
    }

    bool RefreshProcessDynamicCounters(ProcessRecord& processRecord)
    {
        // PID 为 0/4 等系统保留进程时，很多 API 可能无法打开句柄。
        if (processRecord.pid == 0)
        {
            processRecord.dynamicCountersReady = false;
            processRecord.ramMB = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.cpuPercent = 0.0;
            processRecord.gpuPercent = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(processRecord.pid));
        if (processHandle == nullptr)
        {
            // 降级路径：
            // - 某些受保护进程拒绝 PROCESS_VM_READ，但仍可能允许受限查询；
            // - 资源视图的“句柄数”只依赖 PROCESS_QUERY_LIMITED_INFORMATION，单独尝试一次。
            const HANDLE limitedProcessHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                ToDwordPid(processRecord.pid));
            if (limitedProcessHandle != nullptr)
            {
                DWORD processHandleCount = 0;
                if (::GetProcessHandleCount(limitedProcessHandle, &processHandleCount) != FALSE)
                {
                    processRecord.handleCount = static_cast<std::uint32_t>(processHandleCount);
                }
                ::CloseHandle(limitedProcessHandle);
            }
            processRecord.dynamicCountersReady = false;
            return false;
        }

        // 读取创建时间 + CPU 累计时间。
        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
        {
            processRecord.creationTime100ns = ks::str::FileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime);
            processRecord.rawCpuTime100ns =
                ks::str::FileTimeToUint64(kernelTime.dwHighDateTime, kernelTime.dwLowDateTime) +
                ks::str::FileTimeToUint64(userTime.dwHighDateTime, userTime.dwLowDateTime);
            processRecord.startTimeText = ks::str::FileTime100nsToLocalText(processRecord.creationTime100ns);
        }

        // 读取 RAM 工作集。
        PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
        if (::GetProcessMemoryInfo(
            processHandle,
            reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memoryCounters),
            sizeof(memoryCounters)) != FALSE)
        {
            processRecord.rawWorkingSetBytes = static_cast<std::uint64_t>(memoryCounters.WorkingSetSize);
            processRecord.rawPrivateBytes = static_cast<std::uint64_t>(memoryCounters.PrivateUsage);
            if (processRecord.rawPrivateBytes == 0)
            {
                processRecord.rawPrivateBytes = static_cast<std::uint64_t>(memoryCounters.PagefileUsage);
            }
            processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
            processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);

            // 任务管理器内存列对齐：
            // - Toolhelp 等非 NtQuery 路径没有 SYSTEM_PROCESS_INFORMATION，只能靠 Psapi 补齐；
            // - 专用/共享工作集不在 PROCESS_MEMORY_COUNTERS_EX 中，保持 privateWorkingSetKnown=false，
            //   由 UI 显示占位符而不是把“提交大小”伪装成“专用工作集”。
            processRecord.peakWorkingSetBytes = static_cast<std::uint64_t>(memoryCounters.PeakWorkingSetSize);
            processRecord.commitSizeBytes = static_cast<std::uint64_t>(memoryCounters.PagefileUsage);
            processRecord.peakCommitSizeBytes = static_cast<std::uint64_t>(memoryCounters.PeakPagefileUsage);
            processRecord.pagedPoolBytes = static_cast<std::uint64_t>(memoryCounters.QuotaPagedPoolUsage);
            processRecord.nonPagedPoolBytes = static_cast<std::uint64_t>(memoryCounters.QuotaNonPagedPoolUsage);
            processRecord.pageFaultCount = static_cast<std::uint64_t>(memoryCounters.PageFaultCount);
            processRecord.memoryDetailKnown = true;
        }

        // 读取 IO 累计字节。
        IO_COUNTERS ioCounters{};
        if (::GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
        {
            processRecord.rawIoBytes =
                static_cast<std::uint64_t>(ioCounters.ReadTransferCount) +
                static_cast<std::uint64_t>(ioCounters.WriteTransferCount) +
                static_cast<std::uint64_t>(ioCounters.OtherTransferCount);

            // 任务管理器的 6 个 I/O 列直接来自同一次查询，无额外开销。
            processRecord.ioReadOperationCount = static_cast<std::uint64_t>(ioCounters.ReadOperationCount);
            processRecord.ioWriteOperationCount = static_cast<std::uint64_t>(ioCounters.WriteOperationCount);
            processRecord.ioOtherOperationCount = static_cast<std::uint64_t>(ioCounters.OtherOperationCount);
            processRecord.ioReadTransferBytes = static_cast<std::uint64_t>(ioCounters.ReadTransferCount);
            processRecord.ioWriteTransferBytes = static_cast<std::uint64_t>(ioCounters.WriteTransferCount);
            processRecord.ioOtherTransferBytes = static_cast<std::uint64_t>(ioCounters.OtherTransferCount);
            processRecord.ioDetailKnown = true;
        }

        // 基础优先级与累计周期：
        // - 基础优先级取 KPRIORITY（0~31），与任务管理器“基本优先级”列语义一致；
        // - QueryProcessCycleTime 在 Windows 7+ 均可用，失败时保持 cycleTimeKnown=false。
        ApplyProcessBasePriorityAndCycleTimeByHandle(processRecord, processHandle);

        // 若路径未填，顺带补一次路径。
        if (processRecord.imagePath.empty())
        {
            processRecord.imagePath = QueryProcessPathByHandle(processHandle);
        }

        // 动态刷新阶段顺带更新优先级/架构文本，便于详情窗口实时展示。
        processRecord.priorityText = QueryPriorityTextByHandle(processHandle);
        processRecord.efficiencyModeSupported = QueryProcessEfficiencyModeByHandle(
            processHandle,
            &processRecord.efficiencyModeEnabled,
            nullptr);
        if (processRecord.architectureText.empty() || processRecord.architectureText == "Unknown")
        {
            processRecord.architectureText = QueryProcessArchitectureByHandle(processHandle);
        }

        // 句柄数量是资源视图动态列，必须在关闭 processHandle 之前读取。
        DWORD processHandleCount = 0;
        if (::GetProcessHandleCount(processHandle, &processHandleCount) != FALSE)
        {
            processRecord.handleCount = static_cast<std::uint32_t>(processHandleCount);
        }
        ::CloseHandle(processHandle);

        // GPU 由进程列表枚举阶段统一通过 PDH GPU Engine 聚合，避免单进程打开句柄时重复采样。
        // 网络速率需要跨进程页抓包窗口计算；单进程动态刷新无法获得可靠累计值，因此置为 0。
        processRecord.netKBps = 0.0;
        processRecord.netRxKBps = 0.0;
        processRecord.netTxKBps = 0.0;
        processRecord.dynamicCountersReady = true;
        return true;
    }

    bool QueryProcessProtectionLevelByPid(
        const std::uint32_t pid,
        std::uint32_t* const levelOut,
        std::string* const displayTextOut,
        std::string* const errorMessageOut)
    {
        // 输出参数先清零，保证失败路径不会留下上一轮脏值。
        if (levelOut != nullptr)
        {
            *levelOut = 0;
        }
        if (displayTextOut != nullptr)
        {
            displayTextOut->clear();
        }
        if (errorMessageOut != nullptr)
        {
            errorMessageOut->clear();
        }

        // PID 0 没有常规进程句柄，直接返回公开枚举中的 None。
        if (pid == 0)
        {
            if (levelOut != nullptr)
            {
                *levelOut = ProcessProtectionLevelNone;
            }
            if (displayTextOut != nullptr)
            {
                *displayTextOut = ProcessProtectionLevelToText(ProcessProtectionLevelNone);
            }
            return true;
        }

        // GetProcessInformation 从 kernel32 动态解析，兼容较旧 SDK/运行环境。
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto getProcessInformation = reinterpret_cast<GetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "GetProcessInformation") : nullptr);
        if (getProcessInformation == nullptr)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "GetProcessInformation(ProcessProtectionLevelInfo) is not available.";
            }
            return false;
        }

        // 查询 PPL 枚举只需要受限查询权限，避免无谓请求 VM_READ。
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ProcessProtectionLevelInformationNative protectionInfo{};
        const BOOL queryOk = getProcessInformation(
            processHandle,
            ProcessProtectionLevelInfoClass,
            &protectionInfo,
            static_cast<DWORD>(sizeof(protectionInfo)));
        const DWORD queryError = ::GetLastError();
        ::CloseHandle(processHandle);

        if (queryOk == FALSE)
        {
            if (errorMessageOut != nullptr)
            {
                *errorMessageOut = "GetProcessInformation(ProcessProtectionLevelInfo) failed: "
                    + FormatLastErrorMessage(queryError);
            }
            return false;
        }

        if (levelOut != nullptr)
        {
            *levelOut = static_cast<std::uint32_t>(protectionInfo.protectionLevel);
        }
        if (displayTextOut != nullptr)
        {
            *displayTextOut = ProcessProtectionLevelToText(protectionInfo.protectionLevel);
        }
        return true;
    }

    bool FillProcessStaticDetails(ProcessRecord& processRecord, const bool includeSignatureCheck)
    {
        // 静态详情阶段需要更多权限用于读取命令行/令牌信息。
        if (processRecord.pid == 0)
        {
            // PID 0（Idle）没有常规用户态映像，签名逻辑也不适用。
            processRecord.signatureState = includeSignatureCheck ? "Unsigned" : "Pending";
            processRecord.signaturePublisher = "System";
            processRecord.signatureTrusted = false;
            processRecord.architectureText = "N/A";
            processRecord.priorityText = "Idle";
            processRecord.staticDetailsReady = true;
            return true;
        }

        // 先尝试 VM_READ 版本句柄（可读取命令行）；失败后回退到 limited 句柄。
        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(processRecord.pid));
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                ToDwordPid(processRecord.pid));
        }
        if (processHandle == nullptr)
        {
            processRecord.staticDetailsReady = false;
            return false;
        }

        // 可执行路径。
        if (processRecord.imagePath.empty())
        {
            processRecord.imagePath = QueryProcessPathByHandle(processHandle);
        }

        // 进程名兜底：从路径提取文件名。
        if (processRecord.processName.empty())
        {
            processRecord.processName = ExtractFileNameFromPath(processRecord.imagePath);
        }

        // 命令行、用户、管理员状态。
        processRecord.commandLine = QueryProcessCommandLineByHandle(processHandle);
        processRecord.userName = QueryProcessUserNameByHandle(processHandle);
        processRecord.isAdmin = QueryProcessIsElevatedByHandle(processHandle);
        processRecord.architectureText = QueryProcessArchitectureByHandle(processHandle);
        processRecord.priorityText = QueryPriorityTextByHandle(processHandle);
        processRecord.efficiencyModeSupported = QueryProcessEfficiencyModeByHandle(
            processHandle,
            &processRecord.efficiencyModeEnabled,
            nullptr);
        if (processRecord.sessionId == 0)
        {
            DWORD sessionId = 0;
            if (::ProcessIdToSessionId(ToDwordPid(processRecord.pid), &sessionId) != FALSE)
            {
                processRecord.sessionId = static_cast<std::uint32_t>(sessionId);
            }
        }

        // 若创建时间尚未填，尽量补齐。
        if (processRecord.creationTime100ns == 0)
        {
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                processRecord.creationTime100ns = ks::str::FileTimeToUint64(
                    creationTime.dwHighDateTime,
                    creationTime.dwLowDateTime);
            }
        }

        if (!processRecord.startTimeText.empty() || processRecord.creationTime100ns == 0)
        {
            // 无需重复格式化。
        }
        else
        {
            processRecord.startTimeText = ks::str::FileTime100nsToLocalText(processRecord.creationTime100ns);
        }

        ::CloseHandle(processHandle);

        // 数字签名校验通常相对耗时：
        // - 详细模式：执行真实签名校验；
        // - 快速模式：仅标记为 Pending，后续详细模式再补齐。
        if (includeSignatureCheck)
        {
            const FileSignatureInfo signatureInfo = QueryFileSignatureInfo(processRecord.imagePath);
            processRecord.signatureState = signatureInfo.displayText.empty() ? "Unknown" : signatureInfo.displayText;
            processRecord.signaturePublisher = signatureInfo.publisher;
            processRecord.signatureTrusted = signatureInfo.trustedByWindows;
        }
        else if (processRecord.signatureState.empty())
        {
            processRecord.signatureState = "Pending";
            processRecord.signaturePublisher.clear();
            processRecord.signatureTrusted = false;
        }

        // 清理不可见字符，防止表格显示异常。
        ks::str::ReplaceAllInPlace(processRecord.commandLine, "\r", " ");
        ks::str::ReplaceAllInPlace(processRecord.commandLine, "\n", " ");
        processRecord.commandLine = ks::str::TrimCopy(processRecord.commandLine);
        processRecord.userName = ks::str::TrimCopy(processRecord.userName);
        processRecord.signaturePublisher = ks::str::TrimCopy(processRecord.signaturePublisher);

        // staticDetailsReady 在这里表示“基础静态字段可用”，
        // 即便签名处于 Pending 也算可展示，后续可按需补签名。
        processRecord.staticDetailsReady = true;
        return true;
    }

    bool FillProcessOnDemandDetails(
        ProcessRecord& processRecord,
        const std::uint32_t detailDemandFlags,
        std::uint32_t* const resolvedFlagsOut)
    {
        // resolvedFlags：本次真正采集成功的位，供调用方做“只采一次”的记账。
        std::uint32_t resolvedFlags = ProcessDetailDemand::None;
        const auto publishResolvedFlags = [resolvedFlagsOut, &resolvedFlags]() -> void
            {
                if (resolvedFlagsOut != nullptr)
                {
                    *resolvedFlagsOut = resolvedFlags;
                }
            };

        if (detailDemandFlags == ProcessDetailDemand::None)
        {
            publishResolvedFlags();
            return true;
        }

        bool anySucceeded = false;

        // 第一组：只依赖磁盘上的映像文件，可以跨进程按路径共享解析结果。
        const bool wantFileDescription =
            (detailDemandFlags & ProcessDetailDemand::FileDescription) != 0U;
        const bool wantOsContext =
            (detailDemandFlags & ProcessDetailDemand::OsContext) != 0U;
        if ((wantFileDescription || wantOsContext) && !processRecord.imagePath.empty())
        {
            std::string fileDescription;
            std::string osContextText;
            ResolveImageDescriptionCached(
                processRecord.imagePath,
                wantFileDescription,
                wantOsContext,
                &fileDescription,
                &osContextText);
            if (wantFileDescription)
            {
                processRecord.fileDescription = std::move(fileDescription);
            }
            if (wantOsContext)
            {
                processRecord.osContextText = std::move(osContextText);
            }
            resolvedFlags |= (detailDemandFlags & ProcessDetailDemand::ImageFileMask);
            anySucceeded = true;
        }

        // 企业上下文：
        // - Windows 信息保护（WIP/EDP）没有查询“任意进程企业上下文”的公开 API；
        // - 未启用 WIP 的系统上任务管理器同样显示“个人”，这里保持同样语义，不做推断；
        // - 值使用稳定英文标识，由 UI 层按当前语言翻译展示。
        if ((detailDemandFlags & ProcessDetailDemand::EnterpriseContext) != 0U)
        {
            processRecord.enterpriseContextText = "Personal";
            resolvedFlags |= ProcessDetailDemand::EnterpriseContext;
            anySucceeded = true;
        }

        // 第二组：需要目标进程句柄。没有任何一位请求时直接跳过 OpenProcess。
        constexpr std::uint32_t HandleRequiredMask =
            ProcessDetailDemand::GuiResources |
            ProcessDetailDemand::JobObject |
            ProcessDetailDemand::MitigationPolicy |
            ProcessDetailDemand::UacVirtualization |
            ProcessDetailDemand::PackageName |
            ProcessDetailDemand::DpiAwareness;
        if ((detailDemandFlags & HandleRequiredMask) == 0U || processRecord.pid == 0)
        {
            publishResolvedFlags();
            return anySucceeded;
        }

        // GetGuiResources 与 GetProcessMitigationPolicy 需要 PROCESS_QUERY_INFORMATION；
        // 受保护进程只放行 LIMITED 版本，此时降级重试，能拿多少算多少。
        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            ToDwordPid(processRecord.pid));
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                ToDwordPid(processRecord.pid));
        }
        if (processHandle == nullptr)
        {
            publishResolvedFlags();
            return anySucceeded;
        }

        if ((detailDemandFlags & ProcessDetailDemand::GuiResources) != 0U)
        {
            // GetGuiResources 失败时返回 0 且置 LastError；用 LastError 区分“真的是 0 个对象”。
            ::SetLastError(ERROR_SUCCESS);
            const DWORD gdiObjectCount = ::GetGuiResources(processHandle, GR_GDIOBJECTS);
            const DWORD gdiQueryError = ::GetLastError();
            ::SetLastError(ERROR_SUCCESS);
            const DWORD userObjectCount = ::GetGuiResources(processHandle, GR_USEROBJECTS);
            const DWORD userQueryError = ::GetLastError();
            if (gdiQueryError == ERROR_SUCCESS || userQueryError == ERROR_SUCCESS)
            {
                processRecord.gdiObjectCount = static_cast<std::uint32_t>(gdiObjectCount);
                processRecord.userObjectCount = static_cast<std::uint32_t>(userObjectCount);
                processRecord.guiResourceKnown = true;
                resolvedFlags |= ProcessDetailDemand::GuiResources;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & ProcessDetailDemand::JobObject) != 0U)
        {
            BOOL inJobObject = FALSE;
            if (::IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
            {
                processRecord.inJobObject = (inJobObject != FALSE);
                processRecord.jobObjectKnown = true;
                resolvedFlags |= ProcessDetailDemand::JobObject;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & ProcessDetailDemand::MitigationPolicy) != 0U)
        {
            if (ApplyProcessMitigationStatesByHandle(processRecord, processHandle))
            {
                resolvedFlags |= ProcessDetailDemand::MitigationPolicy;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & ProcessDetailDemand::UacVirtualization) != 0U)
        {
            const ProcessFeatureState virtualizationState =
                QueryProcessUacVirtualizationStateByHandle(processHandle);
            processRecord.uacVirtualizationState = virtualizationState;
            if (virtualizationState != ProcessFeatureState::Unknown)
            {
                resolvedFlags |= ProcessDetailDemand::UacVirtualization;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & ProcessDetailDemand::PackageName) != 0U)
        {
            std::string packageFullName;
            if (QueryProcessPackageFullName(processHandle, &packageFullName))
            {
                processRecord.packageFullName = std::move(packageFullName);
                processRecord.packageNameKnown = true;
                resolvedFlags |= ProcessDetailDemand::PackageName;
                anySucceeded = true;
            }
        }

        if ((detailDemandFlags & ProcessDetailDemand::DpiAwareness) != 0U)
        {
            const ProcessDpiAwarenessLevel awarenessLevel = QueryProcessDpiAwarenessLevel(processHandle);
            processRecord.dpiAwarenessLevel = awarenessLevel;
            if (awarenessLevel != ProcessDpiAwarenessLevel::Unknown)
            {
                resolvedFlags |= ProcessDetailDemand::DpiAwareness;
                anySucceeded = true;
            }
        }

        ::CloseHandle(processHandle);
        publishResolvedFlags();
        return anySucceeded;
    }

    void ClearProcessImageDescriptionCache()
    {
        std::lock_guard<std::mutex> cacheLock(imageDescriptionCacheMutex());
        imageDescriptionCache().clear();
    }

    void UpdateDerivedCounters(
        ProcessRecord& processRecord,
        const CounterSample* previousSample,
        CounterSample& nextSampleOut,
        const std::uint32_t logicalCpuCount,
        const std::uint64_t currentTick100ns)
    {
        // 先写入下一轮样本，保证调用方无论成功失败都可更新基准。
        nextSampleOut.cpuTime100ns = processRecord.rawCpuTime100ns;
        nextSampleOut.ioBytes = processRecord.rawIoBytes;
        nextSampleOut.sampleTick100ns = currentTick100ns;
        nextSampleOut.workingSetBytes = processRecord.rawWorkingSetBytes;
        nextSampleOut.pageFaultCount = processRecord.pageFaultCount;
        nextSampleOut.hasMemoryBaseline = processRecord.memoryDetailKnown;

        // RAM 同时保留申请内存与工作集，便于 UI 展示“申请/使用”两组数值。
        processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
        processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);

        // 共享工作集是派生量：只有拿到专用工作集才有意义，否则保持 0 并由 UI 显示占位符。
        processRecord.sharedWorkingSetBytes =
            (processRecord.privateWorkingSetKnown &&
                processRecord.rawWorkingSetBytes > processRecord.privateWorkingSetBytes)
            ? (processRecord.rawWorkingSetBytes - processRecord.privateWorkingSetBytes)
            : 0ULL;

        // 活动的专用工作集：
        // - 语义是“专用工作集中仍在活动的部分”，被挂起/冻结的进程整份工作集都不活动；
        // - 因此挂起进程记 0，其余等于专用工作集，与任务管理器同列的观察结果一致。
        processRecord.activePrivateWorkingSetBytes =
            (processRecord.processStateKnown && processRecord.processSuspended)
            ? 0ULL
            : processRecord.privateWorkingSetBytes;

        // 工作集增量 / 页面错误增量：
        // - 任务管理器的这两列都是“相邻两次刷新之间的变化量”，可以为负；
        // - 首轮或上一轮没有内存基准时保持 0，避免把绝对值误显示成增量。
        if (previousSample != nullptr && previousSample->hasMemoryBaseline && processRecord.memoryDetailKnown)
        {
            processRecord.workingSetDeltaBytes =
                static_cast<std::int64_t>(processRecord.rawWorkingSetBytes) -
                static_cast<std::int64_t>(previousSample->workingSetBytes);
            processRecord.pageFaultDeltaCount =
                static_cast<std::int64_t>(processRecord.pageFaultCount) -
                static_cast<std::int64_t>(previousSample->pageFaultCount);
        }
        else
        {
            processRecord.workingSetDeltaBytes = 0;
            processRecord.pageFaultDeltaCount = 0;
        }

        // 无历史样本时，CPU/Disk 无法计算差值，GPU 保留 PDH 枚举阶段写入值。
        if (previousSample == nullptr)
        {
            processRecord.cpuPercent = 0.0;
            processRecord.cpuCorePercent = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return;
        }

        // 采样间隔过小或时钟回退时，避免除零；GPU 同样保留本轮 PDH 值。
        if (currentTick100ns <= previousSample->sampleTick100ns)
        {
            processRecord.cpuPercent = 0.0;
            processRecord.cpuCorePercent = 0.0;
            processRecord.diskMBps = 0.0;
            processRecord.netKBps = 0.0;
            processRecord.netRxKBps = 0.0;
            processRecord.netTxKBps = 0.0;
            return;
        }

        const std::uint64_t deltaTick100ns = currentTick100ns - previousSample->sampleTick100ns;
        const std::uint64_t deltaCpu100ns =
            (processRecord.rawCpuTime100ns >= previousSample->cpuTime100ns)
            ? (processRecord.rawCpuTime100ns - previousSample->cpuTime100ns)
            : 0;
        const std::uint64_t deltaIoBytes =
            (processRecord.rawIoBytes >= previousSample->ioBytes)
            ? (processRecord.rawIoBytes - previousSample->ioBytes)
            : 0;

        // CPU 百分比同时保留两种语义：
        // - cpuPercent：相对全部逻辑处理器归一化，范围 0~100；
        // - cpuCorePercent：单核等效，100%=占满一个逻辑处理器，多线程进程可超过 100。
        const CpuUsageWindowResult cpuUsage = CalculateCpuUsageWindow(
            processRecord.rawCpuTime100ns,
            previousSample->cpuTime100ns,
            currentTick100ns,
            previousSample->sampleTick100ns,
            logicalCpuCount,
            logicalCpuCount);
        processRecord.cpuPercent = cpuUsage.systemPercent;
        processRecord.cpuCorePercent = cpuUsage.coreEquivalentPercent;

        // 为避免“小于显示精度但非零”的进程看起来恒为 0，
        // 只要 CPU 增量确实大于 0，就给一个最小可见值 0.01%。
        if (deltaCpu100ns > 0 && processRecord.cpuPercent < 0.01)
        {
            processRecord.cpuPercent = 0.01;
        }
        if (deltaCpu100ns > 0 && processRecord.cpuCorePercent < 0.01)
        {
            processRecord.cpuCorePercent = 0.01;
        }

        // Disk 吞吐换算：deltaIoBytes / deltaSeconds -> MB/s。
        const double deltaSeconds = static_cast<double>(deltaTick100ns) / 10000000.0;
        if (deltaSeconds > 0.0)
        {
            processRecord.diskMBps = (static_cast<double>(deltaIoBytes) / deltaSeconds) / (1024.0 * 1024.0);
        }
        else
        {
            processRecord.diskMBps = 0.0;
        }

        // Net 由 ProcessDock 基于抓包累计值在本函数返回后写入；GPU 不在这里清零，避免覆盖 PDH 采样结果。
        processRecord.netKBps = 0.0;
        processRecord.netRxKBps = 0.0;
        processRecord.netTxKBps = 0.0;
    }

    void UpdateThreadCpuUsage(
        SystemThreadRecord& threadRecord,
        const ThreadCounterSample* const previousSample,
        ThreadCounterSample& nextSampleOut,
        const std::uint32_t logicalCpuCount,
        const std::uint64_t currentTick100ns)
    {
        const std::uint64_t currentCpuTime100ns =
            threadRecord.kernelTime100ns + threadRecord.userTime100ns;
        nextSampleOut.cpuTime100ns = currentCpuTime100ns;
        nextSampleOut.sampleTick100ns = currentTick100ns;
        threadRecord.cpuPercent = 0.0;
        threadRecord.cpuUsageReady = false;

        if (previousSample == nullptr)
        {
            return;
        }

        const CpuUsageWindowResult cpuUsage = CalculateCpuUsageWindow(
            currentCpuTime100ns,
            previousSample->cpuTime100ns,
            currentTick100ns,
            previousSample->sampleTick100ns,
            logicalCpuCount,
            1U);
        if (!cpuUsage.valid)
        {
            return;
        }

        threadRecord.cpuPercent = cpuUsage.coreEquivalentPercent;
        if (currentCpuTime100ns > previousSample->cpuTime100ns && threadRecord.cpuPercent < 0.01)
        {
            threadRecord.cpuPercent = 0.01;
        }
        threadRecord.cpuUsageReady = true;
    }

    std::vector<ProcessRecord> EnumerateProcesses(
        const ProcessEnumStrategy strategy,
        ProcessEnumStrategy* const actualStrategyOut,
        const std::uint32_t detailDemandFlags)
    {
        // applyHandleCountFallback 作用：
        // - 最后一遍用系统句柄快照覆盖句柄数量；
        // - 这样即便目标进程因 PPL/权限原因无法 OpenProcess，句柄数仍能由 R3 感知。
        const auto applyHandleCountFallback =
            [](std::vector<ProcessRecord>& processList) -> void
            {
                if (processList.empty())
                {
                    return;
                }

                const std::unordered_map<std::uint32_t, std::uint32_t> handleCountByPid =
                    QueryProcessHandleCountsBySystemSnapshot();
                if (handleCountByPid.empty())
                {
                    return;
                }

                for (ProcessRecord& processRecord : processList)
                {
                    const auto handleCountIt = handleCountByPid.find(processRecord.pid);
                    if (handleCountIt != handleCountByPid.end())
                    {
                        processRecord.handleCount = handleCountIt->second;
                    }
                }
            };

        // applyGpuUsageFallback 作用：
        // - 用 Windows PDH GPU Engine 计数器补齐每进程 GPU 利用率；
        // - 枚举策略本身不提供 GPU 字段，因此必须在返回列表前统一聚合。
        const auto applyGpuUsageFallback =
            [detailDemandFlags](std::vector<ProcessRecord>& processList) -> void
            {
                ApplyGpuUsageCountersToProcessList(processList, detailDemandFlags);
            };

        // 内部 lambda：Toolhelp 路径。
        const auto enumerateBySnapshot = []() -> std::vector<ProcessRecord>
            {
                std::vector<ProcessRecord> processList;

                HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snapshotHandle == INVALID_HANDLE_VALUE)
                {
                    return processList;
                }

                PROCESSENTRY32W processEntry{};
                processEntry.dwSize = sizeof(processEntry);
                if (::Process32FirstW(snapshotHandle, &processEntry) == FALSE)
                {
                    ::CloseHandle(snapshotHandle);
                    return processList;
                }

                // 遍历快照并补动态计数器。
                do
                {
                    ProcessRecord processRecord{};
                    processRecord.pid = static_cast<std::uint32_t>(processEntry.th32ProcessID);
                    processRecord.parentPid = static_cast<std::uint32_t>(processEntry.th32ParentProcessID);
                    processRecord.threadCount = static_cast<std::uint32_t>(processEntry.cntThreads);
                    processRecord.processName = ks::str::Utf16ToUtf8(processEntry.szExeFile);

                    DWORD sessionId = 0;
                    if (::ProcessIdToSessionId(ToDwordPid(processRecord.pid), &sessionId) != FALSE)
                    {
                        processRecord.sessionId = static_cast<std::uint32_t>(sessionId);
                    }

                    // Snapshot 本身不给出 CPU/RAM/IO，需要额外查询。
                    RefreshProcessDynamicCounters(processRecord);
                    processList.push_back(std::move(processRecord));
                } while (::Process32NextW(snapshotHandle, &processEntry) != FALSE);

                ::CloseHandle(snapshotHandle);
                return processList;
            };

        // 内部 lambda：NtQuerySystemInformation 路径。
        const auto enumerateByNtQuery = []() -> std::vector<ProcessRecord>
            {
                std::vector<ProcessRecord> processList;

                const auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
                    GetNtdllProcAddress("NtQuerySystemInformation"));
                if (ntQuerySystemInformation == nullptr)
                {
                    return processList;
                }

                // 缓冲区按返回码动态扩容。
                ULONG bufferLength = 1 * 1024 * 1024;
                std::vector<BYTE> informationBuffer(bufferLength);
                NTSTATUS queryStatus = ntQuerySystemInformation(
                    SystemProcessInformation,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);

                while (queryStatus == StatusInfoLengthMismatch)
                {
                    bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                    informationBuffer.resize(bufferLength);
                    queryStatus = ntQuerySystemInformation(
                        SystemProcessInformation,
                        informationBuffer.data(),
                        bufferLength,
                        &bufferLength);
                }

                if (!NT_SUCCESS(queryStatus))
                {
                    return processList;
                }

                // 按 NextEntryOffset 遍历链式结构。
                BYTE* currentPointer = informationBuffer.data();
                while (currentPointer != nullptr)
                {
                    const auto* processInfo = reinterpret_cast<const SystemProcessInformationRecord*>(currentPointer);
                    ProcessRecord processRecord{};

                    processRecord.pid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(processInfo->UniqueProcessId));
                    processRecord.parentPid = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(processInfo->InheritedFromUniqueProcessId));
                    processRecord.threadCount = static_cast<std::uint32_t>(processInfo->NumberOfThreads);
                    processRecord.handleCount = static_cast<std::uint32_t>(processInfo->HandleCount);
                    processRecord.sessionId = static_cast<std::uint32_t>(processInfo->SessionId);
                    processRecord.creationTime100ns = static_cast<std::uint64_t>(processInfo->CreateTime.QuadPart);
                    processRecord.rawCpuTime100ns = static_cast<std::uint64_t>(processInfo->KernelTime.QuadPart + processInfo->UserTime.QuadPart);
                    processRecord.rawWorkingSetBytes = static_cast<std::uint64_t>(processInfo->WorkingSetSize);
                    processRecord.rawPrivateBytes = static_cast<std::uint64_t>(processInfo->PrivatePageCount);
                    processRecord.rawIoBytes =
                        static_cast<std::uint64_t>(processInfo->ReadTransferCount.QuadPart) +
                        static_cast<std::uint64_t>(processInfo->WriteTransferCount.QuadPart) +
                        static_cast<std::uint64_t>(processInfo->OtherTransferCount.QuadPart);
                    processRecord.workingSetMB = static_cast<double>(processRecord.rawWorkingSetBytes) / (1024.0 * 1024.0);
                    processRecord.ramMB = static_cast<double>(processRecord.rawPrivateBytes) / (1024.0 * 1024.0);
                    processRecord.startTimeText = ks::str::FileTime100nsToLocalText(processRecord.creationTime100ns);
                    processRecord.dynamicCountersReady = true;

                    // 任务管理器对齐字段：
                    // - 这些值都在同一份 NtQuerySystemInformation 缓冲区内，读取不产生额外系统调用；
                    // - 因此无论用户是否显示对应列都直接填充，避免列切换时出现一轮空白。
                    processRecord.basePriority = static_cast<std::int32_t>(processInfo->BasePriority);
                    processRecord.cycleTime = static_cast<std::uint64_t>(processInfo->CycleTime);
                    processRecord.cycleTimeKnown = true;
                    processRecord.peakWorkingSetBytes = static_cast<std::uint64_t>(processInfo->PeakWorkingSetSize);
                    processRecord.privateWorkingSetBytes =
                        (processInfo->WorkingSetPrivateSize.QuadPart > 0)
                        ? static_cast<std::uint64_t>(processInfo->WorkingSetPrivateSize.QuadPart)
                        : 0ULL;
                    processRecord.sharedWorkingSetBytes =
                        (processRecord.rawWorkingSetBytes > processRecord.privateWorkingSetBytes)
                        ? (processRecord.rawWorkingSetBytes - processRecord.privateWorkingSetBytes)
                        : 0ULL;
                    processRecord.privateWorkingSetKnown = true;
                    processRecord.commitSizeBytes = static_cast<std::uint64_t>(processInfo->PagefileUsage);
                    processRecord.peakCommitSizeBytes = static_cast<std::uint64_t>(processInfo->PeakPagefileUsage);
                    processRecord.pagedPoolBytes = static_cast<std::uint64_t>(processInfo->QuotaPagedPoolUsage);
                    processRecord.nonPagedPoolBytes = static_cast<std::uint64_t>(processInfo->QuotaNonPagedPoolUsage);
                    processRecord.pageFaultCount = static_cast<std::uint64_t>(processInfo->PageFaultCount);
                    processRecord.hardFaultCount = static_cast<std::uint64_t>(processInfo->HardFaultCount);
                    processRecord.memoryDetailKnown = true;
                    processRecord.ioReadOperationCount = static_cast<std::uint64_t>(processInfo->ReadOperationCount.QuadPart);
                    processRecord.ioWriteOperationCount = static_cast<std::uint64_t>(processInfo->WriteOperationCount.QuadPart);
                    processRecord.ioOtherOperationCount = static_cast<std::uint64_t>(processInfo->OtherOperationCount.QuadPart);
                    processRecord.ioReadTransferBytes = static_cast<std::uint64_t>(processInfo->ReadTransferCount.QuadPart);
                    processRecord.ioWriteTransferBytes = static_cast<std::uint64_t>(processInfo->WriteTransferCount.QuadPart);
                    processRecord.ioOtherTransferBytes = static_cast<std::uint64_t>(processInfo->OtherTransferCount.QuadPart);
                    processRecord.ioDetailKnown = true;

                    // 运行/挂起状态：
                    // - 线程数组紧跟在进程记录之后，同样已经在缓冲区里，无需再次查询；
                    // - 判定规则与任务管理器一致：全部线程都处于 Waiting 且等待原因为
                    //   Suspended / WrSuspended 时视为“已挂起”。
                    ApplyProcessSuspendedStateFromThreadArray(
                        processRecord,
                        currentPointer,
                        informationBuffer.data(),
                        informationBuffer.size(),
                        static_cast<std::uint32_t>(processInfo->NumberOfThreads));

                    if (processInfo->ImageName.Buffer != nullptr && processInfo->ImageName.Length > 0)
                    {
                        const std::wstring imageName(
                            processInfo->ImageName.Buffer,
                            static_cast<std::size_t>(processInfo->ImageName.Length / sizeof(wchar_t)));
                        processRecord.processName = ks::str::Utf16ToUtf8(imageName);
                    }
                    else
                    {
                        // 系统内核进程常见兜底命名。
                        if (processRecord.pid == 0)
                        {
                            processRecord.processName = "System Idle Process";
                        }
                        else if (processRecord.pid == 4)
                        {
                            processRecord.processName = "System";
                        }
                        else
                        {
                            processRecord.processName = "Unknown";
                        }
                    }

                    processList.push_back(std::move(processRecord));

                    if (processInfo->NextEntryOffset == 0)
                    {
                        break;
                    }
                    currentPointer += processInfo->NextEntryOffset;
                }

                return processList;
            };

        // 按策略执行并处理回退逻辑。
        if (strategy == ProcessEnumStrategy::SnapshotProcess32)
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::SnapshotProcess32;
            }
            std::vector<ProcessRecord> processList = enumerateBySnapshot();
            applyHandleCountFallback(processList);
            applyGpuUsageFallback(processList);
            return processList;
        }
        if (strategy == ProcessEnumStrategy::NtQuerySystemInfo)
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::NtQuerySystemInfo;
            }
            std::vector<ProcessRecord> processList = enumerateByNtQuery();
            applyHandleCountFallback(processList);
            applyGpuUsageFallback(processList);
            return processList;
        }

        // Auto：优先 NtQuery，失败回退 Snapshot。
        std::vector<ProcessRecord> processList = enumerateByNtQuery();
        if (!processList.empty())
        {
            if (actualStrategyOut != nullptr)
            {
                *actualStrategyOut = ProcessEnumStrategy::NtQuerySystemInfo;
            }
            applyHandleCountFallback(processList);
            applyGpuUsageFallback(processList);
            return processList;
        }
        if (actualStrategyOut != nullptr)
        {
            *actualStrategyOut = ProcessEnumStrategy::SnapshotProcess32;
        }
        processList = enumerateBySnapshot();
        applyHandleCountFallback(processList);
        applyGpuUsageFallback(processList);
        return processList;
    }

    std::vector<SystemThreadRecord> EnumerateSystemThreads(
        bool* const usedNtQueryOut,
        std::string* const diagnosticTextOut)
    {
        // usedNtQueryOut 用途：向调用方回报本轮是否走 NtQuery 路径。
        if (usedNtQueryOut != nullptr)
        {
            *usedNtQueryOut = false;
        }

        // diagnosticTextOut 用途：返回本轮路径说明或失败原因。
        if (diagnosticTextOut != nullptr)
        {
            diagnosticTextOut->clear();
        }

        // 第一阶段：优先尝试 NtQuerySystemInformation(SystemExtendedProcessInformation)。
        // 该信息类在基础线程字段外提供 TEB 和用户栈边界；失败时再回退基础类。
        const auto ntQuerySystemInformation = reinterpret_cast<NtQuerySystemInformationFn>(
            GetNtdllProcAddress("NtQuerySystemInformation"));
        if (ntQuerySystemInformation != nullptr)
        {
            const SYSTEM_INFORMATION_CLASS primaryThreadInfoClass =
                static_cast<SYSTEM_INFORMATION_CLASS>(57);
            SYSTEM_INFORMATION_CLASS activeThreadInfoClass = primaryThreadInfoClass;
            bool usedExtendedThreadInfo = true;
            ULONG bufferLength = 2 * 1024 * 1024;
            std::vector<BYTE> informationBuffer(bufferLength);
            NTSTATUS queryStatus = ntQuerySystemInformation(
                activeThreadInfoClass,
                informationBuffer.data(),
                bufferLength,
                &bufferLength);

            while (queryStatus == StatusInfoLengthMismatch)
            {
                bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                informationBuffer.resize(bufferLength);
                queryStatus = ntQuerySystemInformation(
                    activeThreadInfoClass,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);
            }

            if (!NT_SUCCESS(queryStatus))
            {
                // 某些受限环境可能拒绝扩展信息类；回退基础类仍能保证线程页可用。
                activeThreadInfoClass = SystemProcessInformation;
                usedExtendedThreadInfo = false;
                bufferLength = 2 * 1024 * 1024;
                informationBuffer.assign(bufferLength, 0);
                queryStatus = ntQuerySystemInformation(
                    activeThreadInfoClass,
                    informationBuffer.data(),
                    bufferLength,
                    &bufferLength);
                while (queryStatus == StatusInfoLengthMismatch)
                {
                    bufferLength = (bufferLength * 3) / 2 + 64 * 1024;
                    informationBuffer.resize(bufferLength);
                    queryStatus = ntQuerySystemInformation(
                        activeThreadInfoClass,
                        informationBuffer.data(),
                        bufferLength,
                        &bufferLength);
                }
            }

            if (NT_SUCCESS(queryStatus))
            {
                std::vector<SystemThreadRecord> threadList;

                // currentPointer 用途：顺序遍历 NextEntryOffset 链表。
                BYTE* currentPointer = informationBuffer.data();
                while (currentPointer != nullptr)
                {
                    const auto* processInfo = reinterpret_cast<const SystemProcessInformationRecord*>(currentPointer);
                    const std::uint32_t processPid = static_cast<std::uint32_t>(
                        reinterpret_cast<std::uintptr_t>(processInfo->UniqueProcessId));

                    // processNameText 用途：给该进程下所有线程复用同一进程名文本。
                    std::string processNameText;
                    if (processInfo->ImageName.Buffer != nullptr && processInfo->ImageName.Length > 0)
                    {
                        const std::wstring imageName(
                            processInfo->ImageName.Buffer,
                            static_cast<std::size_t>(processInfo->ImageName.Length / sizeof(wchar_t)));
                        processNameText = ks::str::Utf16ToUtf8(imageName);
                    }
                    else if (processPid == 0)
                    {
                        processNameText = "System Idle Process";
                    }
                    else if (processPid == 4)
                    {
                        processNameText = "System";
                    }
                    else
                    {
                        processNameText = "Unknown";
                    }

                    // threadArrayPointer 用途：定位到当前进程条目后紧跟的线程数组。
                    const BYTE* threadArrayPointer = reinterpret_cast<const BYTE*>(processInfo + 1);
                    const std::size_t threadRecordSize = usedExtendedThreadInfo
                        ? sizeof(SystemExtendedThreadInformationRecord)
                        : sizeof(SystemThreadInformationRecord);
                    for (ULONG threadIndex = 0; threadIndex < processInfo->NumberOfThreads; ++threadIndex)
                    {
                        const BYTE* threadRecordPointer =
                            threadArrayPointer + (static_cast<std::size_t>(threadIndex) * threadRecordSize);
                        const auto* threadInfo =
                            reinterpret_cast<const SystemThreadInformationRecord*>(threadRecordPointer);

                        SystemThreadRecord threadRecord{};
                        threadRecord.threadId = static_cast<std::uint32_t>(
                            reinterpret_cast<std::uintptr_t>(threadInfo->ClientId.UniqueThread));
                        threadRecord.ownerPid = static_cast<std::uint32_t>(
                            reinterpret_cast<std::uintptr_t>(threadInfo->ClientId.UniqueProcess));
                        if (threadRecord.ownerPid == 0)
                        {
                            threadRecord.ownerPid = processPid;
                        }
                        threadRecord.ownerProcessName = processNameText;
                        threadRecord.startAddress = reinterpret_cast<std::uint64_t>(threadInfo->StartAddress);
                        threadRecord.priority = static_cast<int>(threadInfo->Priority);
                        threadRecord.basePriority = static_cast<int>(threadInfo->BasePriority);
                        threadRecord.threadState = static_cast<std::uint32_t>(threadInfo->ThreadState);
                        threadRecord.waitReason = static_cast<std::uint32_t>(threadInfo->WaitReason);
                        threadRecord.kernelTime100ns = static_cast<std::uint64_t>(threadInfo->ReservedTime[0].QuadPart);
                        threadRecord.userTime100ns = static_cast<std::uint64_t>(threadInfo->ReservedTime[1].QuadPart);
                        threadRecord.createTime100ns = static_cast<std::uint64_t>(threadInfo->ReservedTime[2].QuadPart);
                        threadRecord.waitTimeTick = static_cast<std::uint32_t>(threadInfo->WaitTime);
                        threadRecord.contextSwitchCount = static_cast<std::uint32_t>(threadInfo->ContextSwitches);

                        if (usedExtendedThreadInfo)
                        {
                            const auto* extendedThreadInfo =
                                reinterpret_cast<const SystemExtendedThreadInformationRecord*>(threadRecordPointer);
                            threadRecord.stackBase = reinterpret_cast<std::uint64_t>(extendedThreadInfo->StackBase);
                            threadRecord.stackLimit = reinterpret_cast<std::uint64_t>(extendedThreadInfo->StackLimit);
                            threadRecord.win32StartAddress = reinterpret_cast<std::uint64_t>(extendedThreadInfo->Win32StartAddress);
                            threadRecord.tebBaseAddress = reinterpret_cast<std::uint64_t>(extendedThreadInfo->TebBaseAddress);
                        }
                        threadList.push_back(std::move(threadRecord));
                    }

                    if (processInfo->NextEntryOffset == 0)
                    {
                        break;
                    }
                    currentPointer += processInfo->NextEntryOffset;
                }

                // 统一排序：先 PID，再 TID，保证 UI 每轮刷新顺序稳定。
                std::sort(
                    threadList.begin(),
                    threadList.end(),
                    [](const SystemThreadRecord& leftRecord, const SystemThreadRecord& rightRecord)
                    {
                        if (leftRecord.ownerPid != rightRecord.ownerPid)
                        {
                            return leftRecord.ownerPid < rightRecord.ownerPid;
                        }
                        return leftRecord.threadId < rightRecord.threadId;
                    });

                if (usedNtQueryOut != nullptr)
                {
                    *usedNtQueryOut = true;
                }
                if (diagnosticTextOut != nullptr)
                {
                    *diagnosticTextOut = usedExtendedThreadInfo
                        ? "NtQuerySystemInformation(SystemExtendedProcessInformation) success"
                        : "NtQuerySystemInformation(SystemProcessInformation) success";
                }
                return threadList;
            }

            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut = FormatNtStatusMessage(
                    queryStatus,
                    "NtQuerySystemInformation(SystemProcessInformation) failed");
            }
        }
        else if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut = "NtQuerySystemInformation not available";
        }

        // 第二阶段：Nt 路径不可用时回退 Toolhelp（保证功能可用性）。
        std::vector<SystemThreadRecord> threadList;
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut += " | Toolhelp fallback failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return threadList;
        }

        // processNameCacheByPid 用途：避免为同 PID 重复调用 GetProcessNameByPID。
        std::unordered_map<std::uint32_t, std::string> processNameCacheByPid;

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            if (diagnosticTextOut != nullptr)
            {
                *diagnosticTextOut += " | Thread32First failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(snapshotHandle);
            return threadList;
        }

        do
        {
            SystemThreadRecord threadRecord{};
            threadRecord.threadId = static_cast<std::uint32_t>(threadEntry.th32ThreadID);
            threadRecord.ownerPid = static_cast<std::uint32_t>(threadEntry.th32OwnerProcessID);
            threadRecord.priority = static_cast<int>(threadEntry.tpBasePri);
            threadRecord.basePriority = static_cast<int>(threadEntry.tpBasePri);
            threadRecord.threadState = std::numeric_limits<std::uint32_t>::max();
            threadRecord.waitReason = std::numeric_limits<std::uint32_t>::max();

            // Toolhelp 本身不返回线程累计时间；尽量用 GetThreadTimes 补齐，
            // 使 NtQuerySystemInformation 不可用时线程 CPU 列仍能在下一轮显示。
            HANDLE threadHandle = ::OpenThread(
                THREAD_QUERY_LIMITED_INFORMATION,
                FALSE,
                threadRecord.threadId);
            if (threadHandle != nullptr)
            {
                FILETIME createTime{};
                FILETIME exitTime{};
                FILETIME kernelTime{};
                FILETIME userTime{};
                if (::GetThreadTimes(
                    threadHandle,
                    &createTime,
                    &exitTime,
                    &kernelTime,
                    &userTime) != FALSE)
                {
                    threadRecord.createTime100ns = ks::str::FileTimeToUint64(
                        createTime.dwHighDateTime,
                        createTime.dwLowDateTime);
                    threadRecord.kernelTime100ns = ks::str::FileTimeToUint64(
                        kernelTime.dwHighDateTime,
                        kernelTime.dwLowDateTime);
                    threadRecord.userTime100ns = ks::str::FileTimeToUint64(
                        userTime.dwHighDateTime,
                        userTime.dwLowDateTime);
                }
                ::CloseHandle(threadHandle);
            }

            auto processNameIt = processNameCacheByPid.find(threadRecord.ownerPid);
            if (processNameIt == processNameCacheByPid.end())
            {
                std::string processNameText = GetProcessNameByPID(threadRecord.ownerPid);
                if (processNameText.empty())
                {
                    processNameText = "Unknown";
                }
                processNameIt = processNameCacheByPid.emplace(
                    threadRecord.ownerPid,
                    std::move(processNameText)).first;
            }
            threadRecord.ownerProcessName = processNameIt->second;
            threadList.push_back(std::move(threadRecord));
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);

        std::sort(
            threadList.begin(),
            threadList.end(),
            [](const SystemThreadRecord& leftRecord, const SystemThreadRecord& rightRecord)
            {
                if (leftRecord.ownerPid != rightRecord.ownerPid)
                {
                    return leftRecord.ownerPid < rightRecord.ownerPid;
                }
                return leftRecord.threadId < rightRecord.threadId;
            });

        if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut += " | Toolhelp fallback success";
        }
        return threadList;
    }

    std::string QueryProcessPathByPid(const std::uint32_t pid)
    {
        if (pid == 0)
        {
            return std::string();
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            return std::string();
        }

        std::string processPath = QueryProcessPathByHandle(processHandle);
        ::CloseHandle(processHandle);
        return processPath;
    }

    std::string GetProcessNameByPID(const std::uint32_t pid)
    {
        // 优先路径提取文件名，失败再回退快照枚举。
        const std::string processPath = QueryProcessPathByPid(pid);
        if (!processPath.empty())
        {
            return ExtractFileNameFromPath(processPath);
        }

        const std::vector<ProcessRecord> processList = EnumerateProcesses(ProcessEnumStrategy::SnapshotProcess32);
        for (const ProcessRecord& processRecord : processList)
        {
            if (processRecord.pid == pid)
            {
                return processRecord.processName;
            }
        }
        return std::string();
    }

    bool ExecuteTaskKill(const std::uint32_t pid, const bool forceKill, std::string* const errorMessage)
    {
        // 通过 cmd /C taskkill 执行，确保行为与用户手工命令一致。
        std::wstring commandLine = L"cmd.exe /C taskkill /PID " + std::to_wstring(pid);
        if (forceKill)
        {
            commandLine += L" /F";
        }

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};

        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        const BOOL createResult = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (createResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateProcess(taskkill) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD waitResult = ::WaitForSingleObject(processInfo.hProcess, 10000);
        if (waitResult != WAIT_OBJECT_0)
        {
            const DWORD waitError = waitResult == WAIT_FAILED ? ::GetLastError() : ERROR_GEN_FAILURE;
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = waitResult == WAIT_TIMEOUT
                    ? "taskkill timed out."
                    : "WaitForSingleObject(taskkill) failed: " + FormatLastErrorMessage(waitError);
            }
            return false;
        }

        DWORD exitCode = 0;
        if (::GetExitCodeProcess(processInfo.hProcess, &exitCode) == FALSE)
        {
            const DWORD exitCodeError = ::GetLastError();
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeProcess(taskkill) failed: " + FormatLastErrorMessage(exitCodeError);
            }
            return false;
        }

        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);

        if (exitCode == 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "taskkill failed, exit code=" << exitCode;
            *errorMessage = stream.str();
        }
        return false;
    }

    bool TerminateProcessByWin32(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE processHandle = ::OpenProcess(PROCESS_TERMINATE, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_TERMINATE) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateProcess(processHandle, 1);
        const DWORD terminateError = ::GetLastError();
        ::CloseHandle(processHandle);

        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    bool TerminateProcessByWin32IfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "process identity is unavailable";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for identity-verified terminate) failed: " +
                    FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL queryOk = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD queryError = queryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t actualCreationTime100ns = queryOk != FALSE
            ? ks::str::FileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime)
            : 0U;
        if (queryOk == FALSE ||
            actualCreationTime100ns == 0U ||
            actualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(processHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = queryOk == FALSE
                    ? "GetProcessTimes failed: " + FormatLastErrorMessage(queryError)
                    : "process identity changed (PID was reused); termination skipped.";
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateProcess(processHandle, 1);
        const DWORD terminateError = terminateResult != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processHandle);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    bool TerminateProcessByNtNative(const std::uint32_t pid, std::string* const errorMessage)
    {
        // NtTerminateProcess 优先，缺失时回退 ZwTerminateProcess。
        auto ntTerminateProcess = reinterpret_cast<NtTerminateProcessFn>(
            GetNtdllProcAddress("NtTerminateProcess"));
        if (ntTerminateProcess == nullptr)
        {
            ntTerminateProcess = reinterpret_cast<NtTerminateProcessFn>(
                GetNtdllProcAddress("ZwTerminateProcess"));
        }
        if (ntTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateProcess / ZwTerminateProcess not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(PROCESS_TERMINATE, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_TERMINATE) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS terminateStatus = ntTerminateProcess(processHandle, static_cast<NTSTATUS>(1));
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(terminateStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(terminateStatus, "NtTerminateProcess failed");
        }
        return false;
    }

    bool TerminateProcessByWtsApi(const std::uint32_t pid, std::string* const errorMessage)
    {
        using WtsTerminateProcessFn = BOOL(WINAPI*)(HANDLE, DWORD, DWORD);

        static HMODULE wtsApiModule = ::LoadLibraryW(L"Wtsapi32.dll");
        if (wtsApiModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(Wtsapi32.dll) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static WtsTerminateProcessFn wtsTerminateProcess = reinterpret_cast<WtsTerminateProcessFn>(
            ::GetProcAddress(wtsApiModule, "WTSTerminateProcess"));
        if (wtsTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(WTSTerminateProcess) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // 传入 nullptr 表示当前服务器（等价 WTS_CURRENT_SERVER_HANDLE）。
        const BOOL terminateResult = wtsTerminateProcess(nullptr, ToDwordPid(pid), 1);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "WTSTerminateProcess failed: " + FormatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool TerminateProcessByWinStationApi(const std::uint32_t pid, std::string* const errorMessage)
    {
        using WinStationTerminateProcessFn = BOOLEAN(WINAPI*)(HANDLE, ULONG, ULONG);

        static HMODULE winstaModule = ::LoadLibraryW(L"winsta.dll");
        if (winstaModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(winsta.dll) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static WinStationTerminateProcessFn winStationTerminateProcess = reinterpret_cast<WinStationTerminateProcessFn>(
            ::GetProcAddress(winstaModule, "WinStationTerminateProcess"));
        if (winStationTerminateProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(WinStationTerminateProcess) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOLEAN terminateResult = winStationTerminateProcess(nullptr, static_cast<ULONG>(pid), 1UL);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "WinStationTerminateProcess failed: " + FormatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool TerminateProcessByJobObject(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for job terminate) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const HANDLE jobHandle = ::CreateJobObjectW(nullptr, nullptr);
        if (jobHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateJobObjectW failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        const BOOL assignResult = ::AssignProcessToJobObject(jobHandle, processHandle);
        const DWORD assignError = ::GetLastError();
        if (assignResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AssignProcessToJobObject failed: " + FormatLastErrorMessage(assignError);
            }
            ::CloseHandle(jobHandle);
            ::CloseHandle(processHandle);
            return false;
        }

        const BOOL terminateResult = ::TerminateJobObject(jobHandle, 1);
        const DWORD terminateError = ::GetLastError();
        ::CloseHandle(jobHandle);
        ::CloseHandle(processHandle);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateJobObject failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    bool TerminateProcessByNtJobObject(const std::uint32_t pid, std::string* const errorMessage)
    {
        // NtTerminateJobObject 优先，缺失时回退 ZwTerminateJobObject。
        auto ntTerminateJobObject = reinterpret_cast<NtTerminateJobObjectFn>(
            GetNtdllProcAddress("NtTerminateJobObject"));
        if (ntTerminateJobObject == nullptr)
        {
            ntTerminateJobObject = reinterpret_cast<NtTerminateJobObjectFn>(
                GetNtdllProcAddress("ZwTerminateJobObject"));
        }
        if (ntTerminateJobObject == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateJobObject / ZwTerminateJobObject not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for nt job terminate) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const HANDLE jobHandle = ::CreateJobObjectW(nullptr, nullptr);
        if (jobHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateJobObjectW failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        const BOOL assignResult = ::AssignProcessToJobObject(jobHandle, processHandle);
        const DWORD assignError = ::GetLastError();
        if (assignResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "AssignProcessToJobObject failed: " + FormatLastErrorMessage(assignError);
            }
            ::CloseHandle(jobHandle);
            ::CloseHandle(processHandle);
            return false;
        }

        const NTSTATUS terminateStatus = ntTerminateJobObject(jobHandle, static_cast<NTSTATUS>(1));
        ::CloseHandle(jobHandle);
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(terminateStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(terminateStatus, "NtTerminateJobObject failed");
        }
        return false;
    }

    bool TerminateProcessByRestartManager(
        const std::uint32_t pid,
        const bool forceShutdown,
        std::string* const errorMessage)
    {
        using RmStartSessionFn = DWORD(WINAPI*)(DWORD*, DWORD, WCHAR*);
        using RmRegisterResourcesFn = DWORD(WINAPI*)(DWORD, UINT, LPCWSTR*, UINT, RM_UNIQUE_PROCESS*, UINT, LPCWSTR*);
        using RmShutdownFn = DWORD(WINAPI*)(DWORD, ULONG, RM_WRITE_STATUS_CALLBACK);
        using RmEndSessionFn = DWORD(WINAPI*)(DWORD);

        static HMODULE restartManagerModule = ::LoadLibraryW(L"Rstrtmgr.dll");
        if (restartManagerModule == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "LoadLibrary(Rstrtmgr.dll) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        static RmStartSessionFn rmStartSession = reinterpret_cast<RmStartSessionFn>(
            ::GetProcAddress(restartManagerModule, "RmStartSession"));
        static RmRegisterResourcesFn rmRegisterResources = reinterpret_cast<RmRegisterResourcesFn>(
            ::GetProcAddress(restartManagerModule, "RmRegisterResources"));
        static RmShutdownFn rmShutdown = reinterpret_cast<RmShutdownFn>(
            ::GetProcAddress(restartManagerModule, "RmShutdown"));
        static RmEndSessionFn rmEndSession = reinterpret_cast<RmEndSessionFn>(
            ::GetProcAddress(restartManagerModule, "RmEndSession"));
        if (rmStartSession == nullptr ||
            rmRegisterResources == nullptr ||
            rmShutdown == nullptr ||
            rmEndSession == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Restart Manager function export missing.";
            }
            return false;
        }

        DWORD sessionHandle = 0;
        WCHAR sessionKey[CCH_RM_SESSION_KEY + 1] = {};
        const DWORD startResult = rmStartSession(&sessionHandle, 0, sessionKey);
        if (startResult != ERROR_SUCCESS)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "RmStartSession failed: code=" + std::to_string(startResult);
            }
            return false;
        }

        FILETIME processStartTime{};
        if (!QueryProcessStartTimeByPid(pid, &processStartTime))
        {
            rmEndSession(sessionHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryProcessStartTimeByPid failed.";
            }
            return false;
        }

        RM_UNIQUE_PROCESS uniqueProcess{};
        uniqueProcess.dwProcessId = ToDwordPid(pid);
        uniqueProcess.ProcessStartTime = processStartTime;

        const DWORD registerResult = rmRegisterResources(
            sessionHandle,
            0,
            nullptr,
            1,
            &uniqueProcess,
            0,
            nullptr);
        if (registerResult != ERROR_SUCCESS)
        {
            rmEndSession(sessionHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "RmRegisterResources failed: code=" + std::to_string(registerResult);
            }
            return false;
        }

        const ULONG shutdownFlags = forceShutdown ? RestartManagerForceShutdownFlag : 0UL;
        const DWORD shutdownResult = rmShutdown(sessionHandle, shutdownFlags, nullptr);
        const DWORD endResult = rmEndSession(sessionHandle);
        if (shutdownResult == ERROR_SUCCESS)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "RmShutdown failed: code=" << shutdownResult
                << ", RmEndSession=" << endResult;
            *errorMessage = stream.str();
        }
        return false;
    }

    bool TerminateProcessByDuplicateHandlePseudo(const std::uint32_t pid, std::string* const errorMessage)
    {
        // 先以“复制句柄权限”打开目标进程。
        const HANDLE targetProcessHandle = ::OpenProcess(PROCESS_DUP_HANDLE, FALSE, ToDwordPid(pid));
        if (targetProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_DUP_HANDLE) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // 复制目标进程中的伪句柄(-1)到当前进程，得到目标进程真实句柄。
        HANDLE duplicatedProcessHandle = nullptr;
        const BOOL duplicateResult = ::DuplicateHandle(
            targetProcessHandle,
            reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)),
            ::GetCurrentProcess(),
            &duplicatedProcessHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);
        const DWORD duplicateError = ::GetLastError();
        ::CloseHandle(targetProcessHandle);
        if (duplicateResult == FALSE || duplicatedProcessHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DuplicateHandle(-1 pseudo handle) failed: " + FormatLastErrorMessage(duplicateError);
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateProcess(duplicatedProcessHandle, 1);
        const DWORD terminateError = ::GetLastError();
        ::CloseHandle(duplicatedProcessHandle);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess(duplicated handle) failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    bool TerminateAllThreadsByPid(const std::uint32_t pid, std::string* const errorMessage)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateToolhelp32Snapshot(THREAD) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "Thread32First failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        std::uint32_t terminatedCount = 0;
        do
        {
            if (threadEntry.th32OwnerProcessID != pid)
            {
                continue;
            }

            const HANDLE threadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadEntry.th32ThreadID);
            if (threadHandle == nullptr)
            {
                continue;
            }

            if (::TerminateThread(threadHandle, 1) != FALSE)
            {
                ++terminatedCount;
            }
            ::CloseHandle(threadHandle);
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        if (terminatedCount > 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "No thread terminated (possible access denied or process has exited).";
        }
        return false;
    }

    bool TerminateAllThreadsByPidNtNative(const std::uint32_t pid, std::string* const errorMessage)
    {
        // NtTerminateThread 优先，缺失时回退 ZwTerminateThread。
        auto ntTerminateThread = reinterpret_cast<NtTerminateThreadFn>(
            GetNtdllProcAddress("NtTerminateThread"));
        if (ntTerminateThread == nullptr)
        {
            ntTerminateThread = reinterpret_cast<NtTerminateThreadFn>(
                GetNtdllProcAddress("ZwTerminateThread"));
        }
        if (ntTerminateThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtTerminateThread / ZwTerminateThread not available.";
            }
            return false;
        }

        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateToolhelp32Snapshot(THREAD) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        if (::Thread32First(snapshotHandle, &threadEntry) == FALSE)
        {
            ::CloseHandle(snapshotHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "Thread32First failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        std::uint32_t terminatedCount = 0;
        do
        {
            if (threadEntry.th32OwnerProcessID != pid)
            {
                continue;
            }

            const HANDLE threadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadEntry.th32ThreadID);
            if (threadHandle == nullptr)
            {
                continue;
            }

            const NTSTATUS terminateStatus = ntTerminateThread(threadHandle, static_cast<NTSTATUS>(1));
            if (NT_SUCCESS(terminateStatus))
            {
                ++terminatedCount;
            }
            ::CloseHandle(threadHandle);
        } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);

        ::CloseHandle(snapshotHandle);
        if (terminatedCount > 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "No thread terminated via NtTerminateThread.";
        }
        return false;
    }

    bool TerminateProcessByDebugAttach(const std::uint32_t pid, std::string* const errorMessage)
    {
        // 调试附加通常需要 SeDebugPrivilege，先尝试启用。
        EnablePrivilege(SE_DEBUG_NAME);

        const BOOL attachResult = ::DebugActiveProcess(ToDwordPid(pid));
        if (attachResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DebugActiveProcess failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // 按示例链路设置 DebugSetProcessKillOnExit(0)。
        const BOOL setKillOnExitResult = ::DebugSetProcessKillOnExit(FALSE);
        const DWORD setKillOnExitError = ::GetLastError();

        // 避免当前进程长期占用调试关系，这里立即尝试解除附加。
        const BOOL stopResult = ::DebugActiveProcessStop(ToDwordPid(pid));
        const DWORD stopError = ::GetLastError();

        if (setKillOnExitResult != FALSE && stopResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            std::ostringstream stream;
            if (setKillOnExitResult == FALSE)
            {
                stream << "DebugSetProcessKillOnExit(FALSE) failed: "
                    << FormatLastErrorMessage(setKillOnExitError);
            }
            if (stopResult == FALSE)
            {
                if (!stream.str().empty())
                {
                    stream << "; ";
                }
                stream << "DebugActiveProcessStop failed: "
                    << FormatLastErrorMessage(stopError);
            }
            *errorMessage = stream.str();
        }
        return false;
    }

    bool TerminateProcessByNtsdCommand(const std::uint32_t pid, std::string* const errorMessage)
    {
        // 命令形态：ntsd -c q -p <pid>，附加后立即执行 q 退出。
        std::wstring commandLine = L"cmd.exe /C ntsd -c q -p " + std::to_wstring(pid);
        std::vector<wchar_t> mutableCommandLine(commandLine.begin(), commandLine.end());
        mutableCommandLine.push_back(L'\0');

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        const BOOL createResult = ::CreateProcessW(
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (createResult == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateProcess(ntsd) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD waitResult = ::WaitForSingleObject(processInfo.hProcess, 15000);
        if (waitResult != WAIT_OBJECT_0)
        {
            ::CloseHandle(processInfo.hThread);
            ::CloseHandle(processInfo.hProcess);
            if (errorMessage != nullptr)
            {
                *errorMessage = "ntsd wait timeout or failed, waitResult=" + std::to_string(waitResult);
            }
            return false;
        }

        DWORD exitCode = 0;
        const BOOL exitCodeOk = ::GetExitCodeProcess(processInfo.hProcess, &exitCode);
        const DWORD exitCodeError = exitCodeOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(processInfo.hThread);
        ::CloseHandle(processInfo.hProcess);
        if (exitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeProcess(ntsd) failed: " + FormatLastErrorMessage(exitCodeError);
            }
            return false;
        }
        if (exitCode == 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "ntsd exit code=" + std::to_string(exitCode);
        }
        return false;
    }

    bool TerminateProcessByNtUnmapNtdll(const std::uint32_t pid, std::string* const errorMessage)
    {
        auto ntUnmapViewOfSection = reinterpret_cast<NtUnmapViewOfSectionFn>(
            GetNtdllProcAddress("NtUnmapViewOfSection"));
        if (ntUnmapViewOfSection == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtUnmapViewOfSection not available.";
            }
            return false;
        }

        void* ntdllBaseAddress = nullptr;
        if (!QueryModuleBaseAddressBySnapshot(pid, L"ntdll.dll", &ntdllBaseAddress) || ntdllBaseAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryModuleBaseAddressBySnapshot(ntdll.dll) failed.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(PROCESS_VM_OPERATION, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_VM_OPERATION) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS unmapStatus = ntUnmapViewOfSection(processHandle, ntdllBaseAddress);
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(unmapStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(unmapStatus, "NtUnmapViewOfSection failed");
        }
        return false;
    }

    bool InjectInvalidShellcode(const std::uint32_t pid, std::string* const errorMessage)
    {
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for injection) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        // 无效 shellcode：UD2 + RET，用于触发非法指令异常。
        const BYTE invalidShellcode[] = { 0x0F, 0x0B, 0xC3 };
        void* remoteMemory = ::VirtualAllocEx(
            processHandle,
            nullptr,
            sizeof(invalidShellcode),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (remoteMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        const BOOL writeResult = ::WriteProcessMemory(
            processHandle,
            remoteMemory,
            invalidShellcode,
            sizeof(invalidShellcode),
            &bytesWritten);
        if (writeResult == FALSE || bytesWritten != sizeof(invalidShellcode))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        // 启动远程线程执行无效代码。
        const HANDLE remoteThread = ::CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory),
            nullptr,
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        ::WaitForSingleObject(remoteThread, 1500);
        ::CloseHandle(remoteThread);
        ::CloseHandle(processHandle);

        // 这里不释放 remoteMemory：目标进程可能已崩溃或退出，释放意义不大。
        return true;
    }

    bool InvokeSuspendResumeProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const bool resume,
        std::string* const errorMessage)
    {
        if (pid == 0U || expectedCreationTime100ns == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "process identity is unavailable";
            }
            return false;
        }

        const auto processRoutine = reinterpret_cast<NtSuspendProcessFn>(
            GetNtdllProcAddress(resume ? "NtResumeProcess" : "NtSuspendProcess"));
        if (processRoutine == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = resume
                    ? "NtResumeProcess not available."
                    : "NtSuspendProcess not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            ProcessSuspendResumeAccess | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for identity-verified suspend/resume) failed: " +
                    FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL queryOk = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD queryError = queryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t actualCreationTime100ns = queryOk != FALSE
            ? ks::str::FileTimeToUint64(
                creationTime.dwHighDateTime,
                creationTime.dwLowDateTime)
            : 0U;
        if (queryOk == FALSE ||
            actualCreationTime100ns == 0U ||
            actualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(processHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = queryOk == FALSE
                    ? "GetProcessTimes failed: " + FormatLastErrorMessage(queryError)
                    : "process identity changed (PID was reused); action skipped.";
            }
            return false;
        }

        const NTSTATUS actionStatus = processRoutine(processHandle);
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(actionStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(
                actionStatus,
                resume ? "NtResumeProcess failed" : "NtSuspendProcess failed");
        }
        return false;
    }

    bool SuspendProcess(const std::uint32_t pid, std::string* const errorMessage)
    {
        const auto ntSuspendProcess = reinterpret_cast<NtSuspendProcessFn>(
            GetNtdllProcAddress("NtSuspendProcess"));
        if (ntSuspendProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtSuspendProcess not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(ProcessSuspendResumeAccess, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SUSPEND_RESUME) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS suspendStatus = ntSuspendProcess(processHandle);
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(suspendStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(suspendStatus, "NtSuspendProcess failed");
        }
        return false;
    }

    bool ResumeProcess(const std::uint32_t pid, std::string* const errorMessage)
    {
        const auto ntResumeProcess = reinterpret_cast<NtResumeProcessFn>(
            GetNtdllProcAddress("NtResumeProcess"));
        if (ntResumeProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtResumeProcess not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(ProcessSuspendResumeAccess, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SUSPEND_RESUME) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const NTSTATUS resumeStatus = ntResumeProcess(processHandle);
        ::CloseHandle(processHandle);
        if (NT_SUCCESS(resumeStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(resumeStatus, "NtResumeProcess failed");
        }
        return false;
    }

    bool SuspendProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return InvokeSuspendResumeProcessIfCreationTimeMatches(
            pid,
            expectedCreationTime100ns,
            false,
            errorMessage);
    }

    bool ResumeProcessIfCreationTimeMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return InvokeSuspendResumeProcessIfCreationTimeMatches(
            pid,
            expectedCreationTime100ns,
            true,
            errorMessage);
    }

    bool SetProcessCriticalFlag(const std::uint32_t pid, const bool enableCritical, std::string* const errorMessage)
    {
        const auto ntSetInformationProcess = reinterpret_cast<NtSetInformationProcessFn>(
            GetNtdllProcAddress("NtSetInformationProcess"));
        if (ntSetInformationProcess == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "NtSetInformationProcess not available.";
            }
            return false;
        }

        // 设置关键进程通常需要 SeDebugPrivilege。
        EnablePrivilege(SE_DEBUG_NAME);

        const HANDLE processHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ULONG criticalFlag = enableCritical ? 1UL : 0UL;
        const NTSTATUS setStatus = ntSetInformationProcess(
            processHandle,
            ProcessBreakOnTerminationInfoClass,
            &criticalFlag,
            static_cast<ULONG>(sizeof(criticalFlag)));
        ::CloseHandle(processHandle);

        if (NT_SUCCESS(setStatus))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = FormatNtStatusMessage(
                setStatus,
                enableCritical ? "Set critical process failed" : "Clear critical process failed");
        }
        return false;
    }

    bool SetProcessPriority(const std::uint32_t pid, const ProcessPriorityLevel priorityLevel, std::string* const errorMessage)
    {
        DWORD priorityClass = NORMAL_PRIORITY_CLASS;
        switch (priorityLevel)
        {
        case ProcessPriorityLevel::Idle:
            priorityClass = IDLE_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::BelowNormal:
            priorityClass = BELOW_NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::Normal:
            priorityClass = NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::AboveNormal:
            priorityClass = ABOVE_NORMAL_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::High:
            priorityClass = HIGH_PRIORITY_CLASS;
            break;
        case ProcessPriorityLevel::Realtime:
            priorityClass = REALTIME_PRIORITY_CLASS;
            break;
        default:
            priorityClass = NORMAL_PRIORITY_CLASS;
            break;
        }

        const HANDLE processHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL setResult = ::SetPriorityClass(processHandle, priorityClass);
        const DWORD setError = ::GetLastError();
        ::CloseHandle(processHandle);
        if (setResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SetPriorityClass failed: " + FormatLastErrorMessage(setError);
        }
        return false;
    }

    bool SetProcessEfficiencyMode(
        const std::uint32_t pid,
        const bool enableEfficiencyMode,
        std::string* const errorMessage)
    {
        HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        const auto setProcessInformation = reinterpret_cast<SetProcessInformationFn>(
            kernel32Module != nullptr ? ::GetProcAddress(kernel32Module, "SetProcessInformation") : nullptr);
        if (setProcessInformation == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "SetProcessInformation(ProcessPowerThrottling) is not available.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(PROCESS_SET_INFORMATION, FALSE, ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(PROCESS_SET_INFORMATION) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        ProcessPowerThrottlingStateNative powerState{};
        powerState.version = ProcessPowerThrottlingCurrentVersion;
        powerState.controlMask = ProcessPowerThrottlingExecutionSpeed;
        powerState.stateMask = enableEfficiencyMode ? ProcessPowerThrottlingExecutionSpeed : 0UL;
        const BOOL setOk = setProcessInformation(
            processHandle,
            ProcessPowerThrottlingInfoClass,
            &powerState,
            static_cast<DWORD>(sizeof(powerState)));
        const DWORD setError = ::GetLastError();
        ::CloseHandle(processHandle);
        if (setOk != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SetProcessInformation(ProcessPowerThrottling) failed: "
                + FormatLastErrorMessage(setError);
        }
        return false;
    }

    bool OpenProcessFolder(const std::uint32_t pid, std::string* const errorMessage)
    {
        const std::string processPath = QueryProcessPathByPid(pid);
        if (processPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Process path is empty or inaccessible.";
            }
            return false;
        }

        return OpenInExplorerByPath(processPath, errorMessage);
    }

    bool QueryProcessStaticDetailByPid(
        const std::uint32_t pid,
        ProcessRecord& outRecord,
        const bool includeSignatureCheck)
    {
        outRecord = ProcessRecord{};
        outRecord.pid = pid;
        outRecord.processName = GetProcessNameByPID(pid);

        // 先刷新动态计数器，保证创建时间/内存等字段尽可能可用。
        RefreshProcessDynamicCounters(outRecord);

        // 再补静态详情：
        // - includeSignatureCheck=false 时跳过 WinVerifyTrust；
        // - 供 UI 快速开窗或后台分阶段刷新使用。
        const bool staticOk = FillProcessStaticDetails(outRecord, includeSignatureCheck);

        // 最后做一次兜底：若进程名仍为空，用 PID 文本占位。
        if (outRecord.processName.empty())
        {
            outRecord.processName = "PID_" + std::to_string(pid);
        }
        return staticOk;
    }

    static ProcessModuleSnapshot EnumerateProcessModulesAndThreadsInternal(
        const std::uint32_t pid,
        const bool includeSignatureCheck,
        const bool requireVerifiedProcessIdentity,
        const std::uint64_t expectedCreationTime100ns)
    {
        ProcessModuleSnapshot snapshot;
        snapshot.modules.clear();
        snapshot.threads.clear();
        snapshot.diagnosticText.clear();

        // appendDiagnostic 作用：
        // - 累积模块刷新诊断文本；
        // - 多段错误通过 " | " 拼接，便于 UI 一次展示完整上下文。
        const auto appendDiagnostic = [&snapshot](const std::string& text)
            {
                if (text.empty())
                {
                    return;
                }
                if (!snapshot.diagnosticText.empty())
                {
                    snapshot.diagnosticText += " | ";
                }
                snapshot.diagnosticText += text;
            };

        struct ScopedProcessIdentityHandle final
        {
            HANDLE handle = nullptr;
            ~ScopedProcessIdentityHandle()
            {
                if (handle != nullptr)
                {
                    ::CloseHandle(handle);
                }
            }
        } processIdentityHold;

        if (requireVerifiedProcessIdentity)
        {
            if (pid == 0U || expectedCreationTime100ns == 0U)
            {
                appendDiagnostic("process identity is unavailable; module snapshot skipped.");
                return snapshot;
            }

            processIdentityHold.handle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                ToDwordPid(pid));
            if (processIdentityHold.handle == nullptr)
            {
                appendDiagnostic(
                    "OpenProcess(for module identity) failed: " +
                    FormatLastErrorMessage(::GetLastError()));
                return snapshot;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL identityQueryOk = ::GetProcessTimes(
                processIdentityHold.handle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD identityQueryError = identityQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t actualCreationTime100ns = identityQueryOk != FALSE
                ? ks::str::FileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
                : 0U;
            if (identityQueryOk == FALSE ||
                actualCreationTime100ns == 0U ||
                actualCreationTime100ns != expectedCreationTime100ns)
            {
                appendDiagnostic(identityQueryOk == FALSE
                    ? "GetProcessTimes(for module identity) failed: " + FormatLastErrorMessage(identityQueryError)
                    : "process identity changed (PID was reused); module snapshot skipped.");
                return snapshot;
            }
        }

        // fillModuleSignature 作用：
        // - 统一填充模块签名显示文本、厂家、可信标记；
        // - includeSignatureCheck=false 时保持 Pending（快速模式）。
        const auto fillModuleSignature = [includeSignatureCheck](ProcessModuleRecord& moduleRecord)
            {
                if (includeSignatureCheck)
                {
                    const FileSignatureInfo signatureInfo = QueryFileSignatureInfo(moduleRecord.modulePath);
                    moduleRecord.signatureState = signatureInfo.displayText.empty() ? "Unknown" : signatureInfo.displayText;
                    moduleRecord.signaturePublisher = signatureInfo.publisher;
                    moduleRecord.signatureTrusted = signatureInfo.trustedByWindows;
                    return;
                }
                moduleRecord.signatureState = "Pending";
                moduleRecord.signaturePublisher.clear();
                moduleRecord.signatureTrusted = false;
            };

        // 先枚举线程，供模块行填充 ThreadID 信息。
        std::vector<std::uint32_t> threadIdList;
        std::uint32_t representativeThreadId = 0U;
        std::uint64_t representativeThreadCreationTime100ns = 0U;
        HANDLE threadSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (threadSnapshotHandle != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 threadEntry{};
            threadEntry.dwSize = sizeof(threadEntry);
            if (::Thread32First(threadSnapshotHandle, &threadEntry) != FALSE)
            {
                do
                {
                    if (threadEntry.th32OwnerProcessID != pid)
                    {
                        continue;
                    }

                    ProcessThreadRecord threadRecord{};
                    threadRecord.threadId = static_cast<std::uint32_t>(threadEntry.th32ThreadID);
                    threadRecord.ownerPid = static_cast<std::uint32_t>(threadEntry.th32OwnerProcessID);
                    threadRecord.basePriority = static_cast<int>(threadEntry.tpBasePri);
                    threadRecord.stateText = "Running";
                    snapshot.threads.push_back(threadRecord);
                    threadIdList.push_back(threadRecord.threadId);

                    // 只将可在同一线程对象上核验 owner + 创建时间的线程用作模块动作入口。
                    if (representativeThreadId == 0U)
                    {
                        const HANDLE representativeThreadHandle = ::OpenThread(
                            THREAD_QUERY_LIMITED_INFORMATION,
                            FALSE,
                            ToDwordPid(threadRecord.threadId));
                        if (representativeThreadHandle != nullptr)
                        {
                            const DWORD actualOwnerPid = ::GetProcessIdOfThread(representativeThreadHandle);
                            FILETIME creationTime{};
                            FILETIME exitTime{};
                            FILETIME kernelTime{};
                            FILETIME userTime{};
                            const BOOL timeQueryOk = ::GetThreadTimes(
                                representativeThreadHandle,
                                &creationTime,
                                &exitTime,
                                &kernelTime,
                                &userTime);
                            const std::uint64_t creationTime100ns = timeQueryOk != FALSE
                                ? ks::str::FileTimeToUint64(
                                    creationTime.dwHighDateTime,
                                    creationTime.dwLowDateTime)
                                : 0U;
                            if (actualOwnerPid == ToDwordPid(pid) && creationTime100ns != 0U)
                            {
                                representativeThreadId = threadRecord.threadId;
                                representativeThreadCreationTime100ns = creationTime100ns;
                            }
                            ::CloseHandle(representativeThreadHandle);
                        }
                    }
                } while (::Thread32Next(threadSnapshotHandle, &threadEntry) != FALSE);
            }
            ::CloseHandle(threadSnapshotHandle);
        }

        // 第一优先：Toolhelp 模块枚举（常规路径）。
        bool moduleEnumerated = false;
        HANDLE moduleSnapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ToDwordPid(pid));
        if (moduleSnapshotHandle == INVALID_HANDLE_VALUE)
        {
            appendDiagnostic("CreateToolhelp32Snapshot(module) failed: " + FormatLastErrorMessage(::GetLastError()));
        }
        else
        {
            MODULEENTRY32W moduleEntry{};
            moduleEntry.dwSize = sizeof(moduleEntry);
            if (::Module32FirstW(moduleSnapshotHandle, &moduleEntry) == FALSE)
            {
                appendDiagnostic("Module32FirstW failed: " + FormatLastErrorMessage(::GetLastError()));
            }
            else
            {
                do
                {
                    ProcessModuleRecord moduleRecord{};
                    moduleRecord.moduleName = ks::str::Utf16ToUtf8(moduleEntry.szModule);
                    moduleRecord.modulePath = ks::str::Utf16ToUtf8(moduleEntry.szExePath);
                    moduleRecord.moduleBaseAddress = reinterpret_cast<std::uint64_t>(moduleEntry.modBaseAddr);
                    moduleRecord.moduleSizeBytes = static_cast<std::uint32_t>(moduleEntry.modBaseSize);
                    moduleRecord.entryPointRva = QueryImageEntryPointRvaByPath(moduleRecord.modulePath);
                    moduleRecord.runningState = "Loaded";
                    fillModuleSignature(moduleRecord);

                    moduleRecord.representativeThreadId = representativeThreadId;
                    moduleRecord.representativeThreadCreationTime100ns = representativeThreadCreationTime100ns;
                    moduleRecord.threadIdText = BuildThreadIdSummaryText(threadIdList);
                    snapshot.modules.push_back(std::move(moduleRecord));
                } while (::Module32NextW(moduleSnapshotHandle, &moduleEntry) != FALSE);
                moduleEnumerated = true;
                appendDiagnostic("Module source: Toolhelp");
            }
            ::CloseHandle(moduleSnapshotHandle);
        }

        // Toolhelp 失败时，回退 PSAPI，解决“模块始终为 0”问题。
        if (!moduleEnumerated)
        {
            const HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE,
                ToDwordPid(pid));
            if (processHandle == nullptr)
            {
                appendDiagnostic("PSAPI fallback open process failed: " + FormatLastErrorMessage(::GetLastError()));
                return snapshot;
            }

            std::vector<HMODULE> moduleHandleBuffer(2048);
            DWORD bytesNeeded = 0;
            if (::EnumProcessModulesEx(
                processHandle,
                moduleHandleBuffer.data(),
                static_cast<DWORD>(moduleHandleBuffer.size() * sizeof(HMODULE)),
                &bytesNeeded,
                LIST_MODULES_ALL) == FALSE)
            {
                appendDiagnostic("EnumProcessModulesEx failed: " + FormatLastErrorMessage(::GetLastError()));
                ::CloseHandle(processHandle);
                return snapshot;
            }

            const std::size_t moduleCount = static_cast<std::size_t>(bytesNeeded / sizeof(HMODULE));
            if (moduleCount > moduleHandleBuffer.size())
            {
                moduleHandleBuffer.resize(moduleCount);
                if (::EnumProcessModulesEx(
                    processHandle,
                    moduleHandleBuffer.data(),
                    static_cast<DWORD>(moduleHandleBuffer.size() * sizeof(HMODULE)),
                    &bytesNeeded,
                    LIST_MODULES_ALL) == FALSE)
                {
                    appendDiagnostic("EnumProcessModulesEx(second pass) failed: " + FormatLastErrorMessage(::GetLastError()));
                    ::CloseHandle(processHandle);
                    return snapshot;
                }
            }

            std::vector<wchar_t> modulePathBuffer(32768U, L'\0');
            for (std::size_t moduleIndex = 0; moduleIndex < moduleCount; ++moduleIndex)
            {
                const HMODULE moduleHandle = moduleHandleBuffer[moduleIndex];
                if (moduleHandle == nullptr)
                {
                    continue;
                }

                const DWORD modulePathLength = ::GetModuleFileNameExW(
                    processHandle,
                    moduleHandle,
                    modulePathBuffer.data(),
                    static_cast<DWORD>(modulePathBuffer.size()));
                if (modulePathLength == 0)
                {
                    continue;
                }

                MODULEINFO moduleInfo{};
                if (::GetModuleInformation(
                    processHandle,
                    moduleHandle,
                    &moduleInfo,
                    static_cast<DWORD>(sizeof(moduleInfo))) == FALSE)
                {
                    continue;
                }

                ProcessModuleRecord moduleRecord{};
                moduleRecord.modulePath = ks::str::Utf16ToUtf8(std::wstring(modulePathBuffer.data(), modulePathLength));
                moduleRecord.moduleName = ExtractFileNameFromPath(moduleRecord.modulePath);
                moduleRecord.moduleBaseAddress = reinterpret_cast<std::uint64_t>(moduleInfo.lpBaseOfDll);
                moduleRecord.moduleSizeBytes = static_cast<std::uint32_t>(moduleInfo.SizeOfImage);

                const std::uint64_t entryPointAddress = reinterpret_cast<std::uint64_t>(moduleInfo.EntryPoint);
                const std::uint64_t baseAddress = moduleRecord.moduleBaseAddress;
                if (entryPointAddress >= baseAddress)
                {
                    moduleRecord.entryPointRva = static_cast<std::uint32_t>(entryPointAddress - baseAddress);
                }
                else
                {
                    moduleRecord.entryPointRva = QueryImageEntryPointRvaByPath(moduleRecord.modulePath);
                }

                moduleRecord.runningState = "Loaded";
                fillModuleSignature(moduleRecord);
                moduleRecord.representativeThreadId = representativeThreadId;
                moduleRecord.representativeThreadCreationTime100ns = representativeThreadCreationTime100ns;
                moduleRecord.threadIdText = BuildThreadIdSummaryText(threadIdList);
                snapshot.modules.push_back(std::move(moduleRecord));
            }

            moduleEnumerated = true;
            appendDiagnostic("Module source: PSAPI fallback");
            ::CloseHandle(processHandle);
        }

        if (!moduleEnumerated)
        {
            appendDiagnostic("No module enumeration path succeeded.");
        }
        else if (snapshot.modules.empty())
        {
            appendDiagnostic("Module enumeration succeeded but module count is 0.");
        }

        return snapshot;
    }

    ProcessModuleSnapshot EnumerateProcessModulesAndThreads(
        const std::uint32_t pid,
        const bool includeSignatureCheck)
    {
        return EnumerateProcessModulesAndThreadsInternal(
            pid,
            includeSignatureCheck,
            false,
            0U);
    }

    ProcessModuleSnapshot EnumerateProcessModulesAndThreadsIfIdentityMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const bool includeSignatureCheck)
    {
        return EnumerateProcessModulesAndThreadsInternal(
            pid,
            includeSignatureCheck,
            true,
            expectedCreationTime100ns);
    }

    bool UnloadModuleByBaseAddressIfIdentityMatches(
        const std::uint32_t pid,
        const std::uint64_t expectedCreationTime100ns,
        const std::uint64_t moduleBaseAddress,
        std::string* const errorMessage)
    {
        const HANDLE processHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for unload module) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        FILETIME creationTime{};
        FILETIME exitTime{};
        FILETIME kernelTime{};
        FILETIME userTime{};
        const BOOL identityQueryOk = ::GetProcessTimes(
            processHandle,
            &creationTime,
            &exitTime,
            &kernelTime,
            &userTime);
        const DWORD identityQueryError = identityQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        const std::uint64_t actualCreationTime100ns = identityQueryOk != FALSE
            ? ks::str::FileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
            : 0U;
        if (expectedCreationTime100ns == 0U ||
            identityQueryOk == FALSE ||
            actualCreationTime100ns == 0U ||
            actualCreationTime100ns != expectedCreationTime100ns)
        {
            ::CloseHandle(processHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = identityQueryOk == FALSE
                    ? "GetProcessTimes(for unload module) failed: " + FormatLastErrorMessage(identityQueryError)
                    : "process identity changed or is unavailable; module unload skipped.";
            }
            return false;
        }

        const HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        FARPROC freeLibraryAddress = kernel32Module != nullptr
            ? ::GetProcAddress(kernel32Module, "FreeLibrary")
            : nullptr;
        if (freeLibraryAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(FreeLibrary) failed.";
            }
            ::CloseHandle(processHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(freeLibraryAddress),
            reinterpret_cast<LPVOID>(moduleBaseAddress),
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(FreeLibrary) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        constexpr DWORD unloadWaitTimeoutMs = 5000;
        const DWORD waitResult = ::WaitForSingleObject(remoteThread, unloadWaitTimeoutMs);
        const DWORD waitError = waitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
        if (waitResult != WAIT_OBJECT_0)
        {
            ::CloseHandle(remoteThread);
            ::CloseHandle(processHandle);
            if (errorMessage != nullptr)
            {
                if (waitResult == WAIT_TIMEOUT)
                {
                    *errorMessage = "FreeLibrary remote thread did not finish within "
                        + std::to_string(unloadWaitTimeoutMs)
                        + " ms; unload state is unknown.";
                }
                else if (waitResult == WAIT_FAILED)
                {
                    *errorMessage = "WaitForSingleObject(FreeLibrary) failed: "
                        + FormatLastErrorMessage(waitError);
                }
                else
                {
                    *errorMessage = "WaitForSingleObject(FreeLibrary) returned unexpected result: "
                        + std::to_string(waitResult);
                }
            }
            return false;
        }

        DWORD threadExitCode = 0;
        const BOOL exitCodeOk = ::GetExitCodeThread(remoteThread, &threadExitCode);
        const DWORD exitCodeError = exitCodeOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        ::CloseHandle(remoteThread);
        ::CloseHandle(processHandle);

        if (exitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeThread(FreeLibrary) failed: "
                    + FormatLastErrorMessage(exitCodeError);
            }
            return false;
        }

        if (threadExitCode != 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "FreeLibrary returned 0, module may not be unloaded.";
        }
        return false;
    }

    bool SuspendThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE threadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (threadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_SUSPEND_RESUME) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD suspendResult = ::SuspendThread(threadHandle);
        ::CloseHandle(threadHandle);
        if (suspendResult != static_cast<DWORD>(-1))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "SuspendThread failed: " + FormatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool ResumeThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE threadHandle = ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (threadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_SUSPEND_RESUME) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const DWORD resumeResult = ::ResumeThread(threadHandle);
        ::CloseHandle(threadHandle);
        if (resumeResult != static_cast<DWORD>(-1))
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "ResumeThread failed: " + FormatLastErrorMessage(::GetLastError());
        }
        return false;
    }

    bool TerminateThreadById(const std::uint32_t threadId, std::string* const errorMessage)
    {
        const HANDLE threadHandle = ::OpenThread(THREAD_TERMINATE, FALSE, threadId);
        if (threadHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenThread(THREAD_TERMINATE) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const BOOL terminateResult = ::TerminateThread(threadHandle, 1);
        const DWORD terminateError = ::GetLastError();
        ::CloseHandle(threadHandle);
        if (terminateResult != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateThread failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    namespace
    {
        enum class ThreadIdentityAction
        {
            Suspend,
            Resume,
            Terminate
        };

        bool applyThreadActionIfIdentityMatches(
            const std::uint32_t threadId,
            const std::uint32_t expectedOwnerPid,
            const std::uint64_t expectedCreationTime100ns,
            const ThreadIdentityAction action,
            std::string* const errorMessage)
        {
            if (threadId == 0U || expectedOwnerPid == 0U || expectedCreationTime100ns == 0U)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "thread identity is unavailable; action skipped.";
                }
                return false;
            }

            const DWORD actionAccess = action == ThreadIdentityAction::Terminate
                ? THREAD_TERMINATE
                : THREAD_SUSPEND_RESUME;
            const HANDLE threadHandle = ::OpenThread(
                actionAccess | THREAD_QUERY_LIMITED_INFORMATION,
                FALSE,
                threadId);
            if (threadHandle == nullptr)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "OpenThread(for identity-verified action) failed: " +
                        FormatLastErrorMessage(::GetLastError());
                }
                return false;
            }

            const DWORD actualOwnerPid = ::GetProcessIdOfThread(threadHandle);
            const DWORD ownerQueryError = actualOwnerPid != 0U ? ERROR_SUCCESS : ::GetLastError();
            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL timeQueryOk = ::GetThreadTimes(
                threadHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD timeQueryError = timeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t actualCreationTime100ns = timeQueryOk != FALSE
                ? ks::str::FileTimeToUint64(
                    creationTime.dwHighDateTime,
                    creationTime.dwLowDateTime)
                : 0U;
            if (actualOwnerPid == 0U || timeQueryOk == FALSE ||
                actualCreationTime100ns == 0U ||
                actualOwnerPid != expectedOwnerPid ||
                actualCreationTime100ns != expectedCreationTime100ns)
            {
                ::CloseHandle(threadHandle);
                if (errorMessage != nullptr)
                {
                    if (actualOwnerPid == 0U)
                    {
                        *errorMessage = "GetProcessIdOfThread failed: " +
                            FormatLastErrorMessage(ownerQueryError);
                    }
                    else if (timeQueryOk == FALSE)
                    {
                        *errorMessage = "GetThreadTimes failed: " +
                            FormatLastErrorMessage(timeQueryError);
                    }
                    else if (actualOwnerPid != expectedOwnerPid)
                    {
                        *errorMessage = "thread owner changed; action skipped.";
                    }
                    else
                    {
                        *errorMessage = "thread identity changed (TID was reused); action skipped.";
                    }
                }
                return false;
            }

            if (action == ThreadIdentityAction::Suspend)
            {
                const DWORD result = ::SuspendThread(threadHandle);
                const DWORD actionError = result == static_cast<DWORD>(-1)
                    ? ::GetLastError()
                    : ERROR_SUCCESS;
                ::CloseHandle(threadHandle);
                if (result != static_cast<DWORD>(-1))
                {
                    return true;
                }
                if (errorMessage != nullptr)
                {
                    *errorMessage = "SuspendThread failed: " + FormatLastErrorMessage(actionError);
                }
                return false;
            }

            if (action == ThreadIdentityAction::Resume)
            {
                const DWORD result = ::ResumeThread(threadHandle);
                const DWORD actionError = result == static_cast<DWORD>(-1)
                    ? ::GetLastError()
                    : ERROR_SUCCESS;
                ::CloseHandle(threadHandle);
                if (result != static_cast<DWORD>(-1))
                {
                    return true;
                }
                if (errorMessage != nullptr)
                {
                    *errorMessage = "ResumeThread failed: " + FormatLastErrorMessage(actionError);
                }
                return false;
            }

            const BOOL result = ::TerminateThread(threadHandle, 1);
            const DWORD actionError = result != FALSE ? ERROR_SUCCESS : ::GetLastError();
            ::CloseHandle(threadHandle);
            if (result != FALSE)
            {
                return true;
            }
            if (errorMessage != nullptr)
            {
                *errorMessage = "TerminateThread failed: " + FormatLastErrorMessage(actionError);
            }
            return false;
        }

        bool applyThreadActionIfProcessAndThreadIdentityMatches(
            const std::uint32_t threadId,
            const std::uint32_t expectedOwnerPid,
            const std::uint64_t expectedProcessCreationTime100ns,
            const std::uint64_t expectedThreadCreationTime100ns,
            const ThreadIdentityAction action,
            std::string* const errorMessage)
        {
            if (expectedOwnerPid == 0U || expectedProcessCreationTime100ns == 0U)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "process identity is unavailable; thread action skipped.";
                }
                return false;
            }

            const HANDLE processHandle = ::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                ToDwordPid(expectedOwnerPid));
            if (processHandle == nullptr)
            {
                if (errorMessage != nullptr)
                {
                    *errorMessage = "OpenProcess(for thread identity) failed: " +
                        FormatLastErrorMessage(::GetLastError());
                }
                return false;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            const BOOL timeQueryOk = ::GetProcessTimes(
                processHandle,
                &creationTime,
                &exitTime,
                &kernelTime,
                &userTime);
            const DWORD timeQueryError = timeQueryOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
            const std::uint64_t actualProcessCreationTime100ns = timeQueryOk != FALSE
                ? ks::str::FileTimeToUint64(creationTime.dwHighDateTime, creationTime.dwLowDateTime)
                : 0U;
            if (timeQueryOk == FALSE ||
                actualProcessCreationTime100ns == 0U ||
                actualProcessCreationTime100ns != expectedProcessCreationTime100ns)
            {
                ::CloseHandle(processHandle);
                if (errorMessage != nullptr)
                {
                    *errorMessage = timeQueryOk == FALSE
                        ? "GetProcessTimes(for thread identity) failed: " + FormatLastErrorMessage(timeQueryError)
                        : "process identity changed (PID was reused); thread action skipped.";
                }
                return false;
            }

            const bool actionOk = applyThreadActionIfIdentityMatches(
                threadId,
                expectedOwnerPid,
                expectedThreadCreationTime100ns,
                action,
                errorMessage);
            ::CloseHandle(processHandle);
            return actionOk;
        }
    }

    bool SuspendThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::Suspend,
            errorMessage);
    }

    bool ResumeThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::Resume,
            errorMessage);
    }

    bool TerminateThreadIfIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedCreationTime100ns,
            ThreadIdentityAction::Terminate,
            errorMessage);
    }

    bool SuspendThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::Suspend,
            errorMessage);
    }

    bool ResumeThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::Resume,
            errorMessage);
    }

    bool TerminateThreadIfProcessAndThreadIdentityMatches(
        const std::uint32_t threadId,
        const std::uint32_t expectedOwnerPid,
        const std::uint64_t expectedProcessCreationTime100ns,
        const std::uint64_t expectedThreadCreationTime100ns,
        std::string* const errorMessage)
    {
        return applyThreadActionIfProcessAndThreadIdentityMatches(
            threadId,
            expectedOwnerPid,
            expectedProcessCreationTime100ns,
            expectedThreadCreationTime100ns,
            ThreadIdentityAction::Terminate,
            errorMessage);
    }

    bool InjectDllByPath(const std::uint32_t pid, const std::string& dllPath, std::string* const errorMessage)
    {
        if (dllPath.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path is empty.";
            }
            return false;
        }

        const std::wstring dllPathWide = ks::str::Utf8ToUtf16(dllPath);
        if (dllPathWide.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path UTF-8 -> UTF-16 conversion failed.";
            }
            return false;
        }

        const DWORD pathAttributes = ::GetFileAttributesW(dllPathWide.c_str());
        if (pathAttributes == INVALID_FILE_ATTRIBUTES || (pathAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "DLL path does not exist or points to a directory.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for DLL inject) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const std::size_t byteCount = (dllPathWide.size() + 1) * sizeof(wchar_t);
        void* remotePathMemory = ::VirtualAllocEx(
            processHandle,
            nullptr,
            byteCount,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE);
        if (remotePathMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx(for DLL path) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        if (::WriteProcessMemory(
            processHandle,
            remotePathMemory,
            dllPathWide.c_str(),
            byteCount,
            &bytesWritten) == FALSE ||
            bytesWritten != byteCount)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory(DLL path) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        const HMODULE kernel32Module = ::GetModuleHandleW(L"kernel32.dll");
        FARPROC loadLibraryAddress = kernel32Module != nullptr
            ? ::GetProcAddress(kernel32Module, "LoadLibraryW")
            : nullptr;
        if (loadLibraryAddress == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetProcAddress(LoadLibraryW) failed.";
            }
            ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibraryAddress),
            remotePathMemory,
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(LoadLibraryW) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        constexpr DWORD loadLibraryWaitTimeoutMs = 10000;
        const DWORD waitResult = ::WaitForSingleObject(remoteThread, loadLibraryWaitTimeoutMs);
        if (waitResult != WAIT_OBJECT_0)
        {
            const DWORD waitError = waitResult == WAIT_FAILED ? ::GetLastError() : ERROR_SUCCESS;
            const bool cleanupScheduled = ScheduleDeferredRemoteLoadLibraryCleanup(
                processHandle,
                remoteThread,
                remotePathMemory);
            if (errorMessage != nullptr)
            {
                if (cleanupScheduled)
                {
                    *errorMessage = "LoadLibraryW remote thread did not finish within "
                        + std::to_string(loadLibraryWaitTimeoutMs)
                        + " ms; deferred cleanup owns the remote path until the thread exits.";
                }
                else
                {
                    *errorMessage = "LoadLibraryW remote thread did not finish within "
                        + std::to_string(loadLibraryWaitTimeoutMs)
                        + " ms and deferred cleanup could not be scheduled; the remote DLL path was intentionally retained until the target process exits.";
                }
                if (waitResult == WAIT_FAILED)
                {
                    *errorMessage += " WaitForSingleObject failed: " + FormatLastErrorMessage(waitError);
                }
            }

            if (!cleanupScheduled)
            {
                // 远程线程仍可能读取 remotePathMemory；清理线程创建失败时宁可保留目标进程中的小块路径内存，
                // 也不能在这里 VirtualFreeEx 触发远程 LoadLibraryW 的悬空指针。
                ::CloseHandle(remoteThread);
                ::CloseHandle(processHandle);
            }
            return false;
        }

        DWORD threadExitCode = 0;
        const BOOL exitCodeOk = ::GetExitCodeThread(remoteThread, &threadExitCode);
        const DWORD exitCodeError = exitCodeOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        ::CloseHandle(remoteThread);
        ::VirtualFreeEx(processHandle, remotePathMemory, 0, MEM_RELEASE);
        ::CloseHandle(processHandle);

        if (exitCodeOk == FALSE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetExitCodeThread(LoadLibraryW) failed: " + FormatLastErrorMessage(exitCodeError);
            }
            return false;
        }

        if (threadExitCode != 0)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "LoadLibraryW returned NULL, DLL may not be loaded.";
        }
        return false;
    }

    bool InjectShellcodeBuffer(
        const std::uint32_t pid,
        const std::vector<std::uint8_t>& shellcodeBuffer,
        std::string* const errorMessage)
    {
        if (shellcodeBuffer.empty())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Shellcode buffer is empty.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            FALSE,
            ToDwordPid(pid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for shellcode inject) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        void* remoteMemory = ::VirtualAllocEx(
            processHandle,
            nullptr,
            shellcodeBuffer.size(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (remoteMemory == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "VirtualAllocEx(for shellcode) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::CloseHandle(processHandle);
            return false;
        }

        SIZE_T bytesWritten = 0;
        if (::WriteProcessMemory(
            processHandle,
            remoteMemory,
            shellcodeBuffer.data(),
            shellcodeBuffer.size(),
            &bytesWritten) == FALSE ||
            bytesWritten != shellcodeBuffer.size())
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "WriteProcessMemory(shellcode) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        HANDLE remoteThread = ::CreateRemoteThread(
            processHandle,
            nullptr,
            0,
            reinterpret_cast<LPTHREAD_START_ROUTINE>(remoteMemory),
            nullptr,
            0,
            nullptr);
        if (remoteThread == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "CreateRemoteThread(shellcode) failed: " + FormatLastErrorMessage(::GetLastError());
            }
            ::VirtualFreeEx(processHandle, remoteMemory, 0, MEM_RELEASE);
            ::CloseHandle(processHandle);
            return false;
        }

        ::WaitForSingleObject(remoteThread, 2000);
        ::CloseHandle(remoteThread);
        ::CloseHandle(processHandle);

        // 为避免 shellcode 仍在执行时释放内存导致异常，此处不主动释放 remoteMemory。
        return true;
    }

    bool OpenFolderByPath(const std::string& targetPath, std::string* const errorMessage)
    {
        return OpenInExplorerByPath(targetPath, errorMessage);
    }

    bool QueryTokenPrivilegesByProcessHandle(
        const HANDLE processHandle,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (privilegesOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByProcessHandle::privilegesOut cannot be null.";
            }
            return false;
        }
        privilegesOut->clear();

        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByProcessHandle::processHandle is invalid.";
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) == FALSE
            || tokenHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken(TOKEN_QUERY) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        DWORD requiredSize = 0;
        ::SetLastError(ERROR_SUCCESS);
        const BOOL sizeQueryOk = ::GetTokenInformation(
            tokenHandle,
            TokenPrivileges,
            nullptr,
            0,
            &requiredSize);
        const DWORD sizeQueryError = ::GetLastError();
        const std::size_t tokenPrivilegesHeaderSize =
            FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges);
        if (sizeQueryOk != FALSE
            || sizeQueryError != ERROR_INSUFFICIENT_BUFFER
            || requiredSize < tokenPrivilegesHeaderSize)
        {
            ::CloseHandle(tokenHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges size failed: "
                    + FormatLastErrorMessage(sizeQueryError);
            }
            return false;
        }

        const DWORD bufferCapacity = requiredSize;
        std::vector<std::uint8_t> tokenBuffer(bufferCapacity, 0);
        TOKEN_PRIVILEGES* const tokenPrivileges = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenBuffer.data());
        DWORD returnedSize = 0;
        if (::GetTokenInformation(
            tokenHandle,
            TokenPrivileges,
            tokenPrivileges,
            bufferCapacity,
            &returnedSize) == FALSE)
        {
            const DWORD queryError = ::GetLastError();
            ::CloseHandle(tokenHandle);
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges failed: "
                    + FormatLastErrorMessage(queryError);
            }
            return false;
        }
        ::CloseHandle(tokenHandle);

        if (returnedSize < tokenPrivilegesHeaderSize
            || returnedSize > bufferCapacity)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges returned an invalid size.";
            }
            return false;
        }
        const std::size_t availablePrivilegeCount =
            (static_cast<std::size_t>(returnedSize) - tokenPrivilegesHeaderSize)
            / sizeof(LUID_AND_ATTRIBUTES);
        if (static_cast<std::size_t>(tokenPrivileges->PrivilegeCount)
            > availablePrivilegeCount)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "GetTokenInformation::TokenPrivileges returned an invalid privilege count.";
            }
            return false;
        }

        std::vector<TokenPrivilegeLuidEntry> privilegeEntries;
        privilegeEntries.reserve(tokenPrivileges->PrivilegeCount);
        for (DWORD privilegeIndex = 0; privilegeIndex < tokenPrivileges->PrivilegeCount; ++privilegeIndex)
        {
            const LUID_AND_ATTRIBUTES& tokenPrivilege = tokenPrivileges->Privileges[privilegeIndex];
            TokenPrivilegeLuidEntry privilegeEntry{};
            privilegeEntry.luidLowPart = tokenPrivilege.Luid.LowPart;
            privilegeEntry.luidHighPart = tokenPrivilege.Luid.HighPart;
            privilegeEntry.attributes = static_cast<std::uint32_t>(tokenPrivilege.Attributes);
            privilegeEntries.push_back(privilegeEntry);
        }

        return BuildKnownTokenPrivilegeSnapshot(
            privilegeEntries,
            privilegesOut,
            errorMessage);
    }

    bool QueryTokenPrivilegesByPid(
        const std::uint32_t sourcePid,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (sourcePid == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByPid::sourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(sourcePid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token query) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const bool queryOk = QueryTokenPrivilegesByProcessHandle(
            processHandle,
            privilegesOut,
            errorMessage);
        ::CloseHandle(processHandle);
        return queryOk;
    }

    bool BuildKnownTokenPrivilegeSnapshot(
        const std::vector<TokenPrivilegeLuidEntry>& entries,
        std::vector<TokenPrivilegeInfo>* const privilegesOut,
        std::string* const errorMessage)
    {
        if (privilegesOut == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "QueryTokenPrivilegesByPid::privilegesOut cannot be null.";
            }
            return false;
        }

        privilegesOut->clear();
        privilegesOut->reserve(KnownTokenPrivilegeNames().size());
        for (const std::string& privilegeName : KnownTokenPrivilegeNames())
        {
            TokenPrivilegeInfo privilegeInfo{};
            privilegeInfo.privilegeName = privilegeName;

            const std::wstring privilegeNameWide = ks::str::Utf8ToUtf16(privilegeName);
            LUID privilegeLuid{};
            if (privilegeNameWide.empty()
                || ::LookupPrivilegeValueW(nullptr, privilegeNameWide.c_str(), &privilegeLuid) == FALSE)
            {
                privilegesOut->push_back(std::move(privilegeInfo));
                continue;
            }

            privilegeInfo.luidLowPart = privilegeLuid.LowPart;
            privilegeInfo.luidHighPart = privilegeLuid.HighPart;
            privilegeInfo.luidKnown = true;
            privilegeInfo.state = TokenPrivilegeState::NotPresent;
            for (const TokenPrivilegeLuidEntry& tokenPrivilege : entries)
            {
                if (tokenPrivilege.luidLowPart != privilegeLuid.LowPart
                    || tokenPrivilege.luidHighPart != privilegeLuid.HighPart)
                {
                    continue;
                }

                privilegeInfo.attributes = tokenPrivilege.attributes;
                privilegeInfo.state = (tokenPrivilege.attributes & SE_PRIVILEGE_ENABLED) != 0
                    ? TokenPrivilegeState::Enabled
                    : TokenPrivilegeState::Disabled;
                break;
            }
            privilegesOut->push_back(std::move(privilegeInfo));
        }

        if (errorMessage != nullptr)
        {
            errorMessage->clear();
        }
        return true;
    }

    bool ApplyTokenPrivilegeEditsByProcessHandle(
        const HANDLE processHandle,
        const std::uint32_t tokenDesiredAccess,
        const bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        const DWORD desiredAccess = tokenDesiredAccess == 0
            ? DefaultTokenDesiredAccess
            : static_cast<DWORD>(tokenDesiredAccess);

        if (processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ApplyTokenPrivilegeEditsByProcessHandle::processHandle is invalid.";
            }
            return false;
        }

        HANDLE sourceToken = nullptr;
        if (::OpenProcessToken(processHandle, desiredAccess, &sourceToken) == FALSE
            || sourceToken == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcessToken(for adjustment) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        HANDLE workingToken = sourceToken;
        HANDLE duplicatedToken = nullptr;
        if (duplicatePrimaryToken)
        {
            if (!DuplicatePrimaryToken(sourceToken, desiredAccess, duplicatedToken, errorMessage))
            {
                ::CloseHandle(sourceToken);
                return false;
            }
            workingToken = duplicatedToken;
        }

        const bool adjustOk = ApplyPrivilegeEdits(workingToken, edits, errorMessage);

        if (duplicatedToken != nullptr)
        {
            ::CloseHandle(duplicatedToken);
        }
        if (sourceToken != nullptr)
        {
            ::CloseHandle(sourceToken);
        }
        if (adjustOk && errorMessage != nullptr)
        {
            std::ostringstream stream;
            stream << "AdjustTokenPrivileges succeeded, edited privileges=" << edits.size();
            *errorMessage = stream.str();
        }
        return adjustOk;
    }

    bool ApplyTokenPrivilegeEditsByPid(
        const std::uint32_t sourcePid,
        const std::uint32_t tokenDesiredAccess,
        const bool duplicatePrimaryToken,
        const std::vector<TokenPrivilegeEdit>& edits,
        std::string* const errorMessage)
    {
        if (sourcePid == 0U)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ApplyTokenPrivilegeEditsByPid::sourcePid cannot be 0.";
            }
            return false;
        }

        const HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            ToDwordPid(sourcePid));
        if (processHandle == nullptr)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "OpenProcess(for token adjustment) failed: "
                    + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }

        const bool adjustOk = ApplyTokenPrivilegeEditsByProcessHandle(
            processHandle,
            tokenDesiredAccess,
            duplicatePrimaryToken,
            edits,
            errorMessage);
        ::CloseHandle(processHandle);
        return adjustOk;
    }

    bool LaunchProcess(
        const CreateProcessRequest& request,
        CreateProcessResult* const resultOut)
    {
        CreateProcessResult localResult{};
        localResult.usedTokenPath = request.tokenModeEnabled;

        std::wstring applicationNameWide;
        LPCWSTR applicationNamePtr = nullptr;
        if (request.useApplicationName)
        {
            applicationNameWide = ks::str::Utf8ToUtf16(request.applicationName);
            applicationNamePtr = applicationNameWide.empty() ? nullptr : applicationNameWide.c_str();
        }

        std::wstring commandLineWide;
        std::vector<wchar_t> commandLineBuffer;
        LPWSTR commandLinePtr = nullptr;
        if (request.useCommandLine)
        {
            commandLineWide = ks::str::Utf8ToUtf16(request.commandLine);
            commandLineBuffer.assign(commandLineWide.begin(), commandLineWide.end());
            commandLineBuffer.push_back(L'\0');
            commandLinePtr = commandLineBuffer.data();
        }

        SECURITY_ATTRIBUTES processSecurityAttributes{};
        SECURITY_ATTRIBUTES threadSecurityAttributes{};
        SECURITY_ATTRIBUTES* processSecurityPtr = BuildSecurityAttributes(
            request.processAttributes,
            processSecurityAttributes) ? &processSecurityAttributes : nullptr;
        SECURITY_ATTRIBUTES* threadSecurityPtr = BuildSecurityAttributes(
            request.threadAttributes,
            threadSecurityAttributes) ? &threadSecurityAttributes : nullptr;

        std::vector<wchar_t> unicodeEnvironmentBlock;
        std::vector<char> ansiEnvironmentBlock;
        LPVOID environmentPtr = nullptr;
        DWORD creationFlags = static_cast<DWORD>(request.creationFlags);
        if (request.useEnvironment)
        {
            const bool useUnicodeEnvironment =
                request.environmentUnicode || ((creationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
            if (useUnicodeEnvironment)
            {
                creationFlags |= CREATE_UNICODE_ENVIRONMENT;
                unicodeEnvironmentBlock = BuildUnicodeEnvironmentBlock(request.environmentEntries);
                environmentPtr = unicodeEnvironmentBlock.empty() ? nullptr : unicodeEnvironmentBlock.data();
            }
            else
            {
                creationFlags &= ~static_cast<DWORD>(CREATE_UNICODE_ENVIRONMENT);
                ansiEnvironmentBlock = BuildAnsiEnvironmentBlock(request.environmentEntries);
                environmentPtr = ansiEnvironmentBlock.empty() ? nullptr : ansiEnvironmentBlock.data();
            }
        }

        std::wstring currentDirectoryWide;
        LPCWSTR currentDirectoryPtr = nullptr;
        if (request.useCurrentDirectory)
        {
            currentDirectoryWide = ks::str::Utf8ToUtf16(request.currentDirectory);
            currentDirectoryPtr = currentDirectoryWide.empty() ? nullptr : currentDirectoryWide.c_str();
        }

        STARTUPINFOW startupInfo{};
        StartupInfoBufferSet startupBufferSet{};
        BuildStartupInfo(
            request.startupInfo,
            startupInfo,
            startupBufferSet);
        STARTUPINFOW* const startupInfoPtr = &startupInfo;

        PROCESS_INFORMATION processInfo{};
        InitializeProcessInformationOutput(processInfo);
        PROCESS_INFORMATION* const processInfoPtr = &processInfo;

        auto finalizeSuccess = [&localResult, processInfoPtr]() {
            localResult.success = true;
            if (processInfoPtr == nullptr)
            {
                return;
            }

            localResult.processInfoAvailable = true;
            localResult.hProcess = HandleToUint64(processInfoPtr->hProcess);
            localResult.hThread = HandleToUint64(processInfoPtr->hThread);
            localResult.dwProcessId = static_cast<std::uint32_t>(processInfoPtr->dwProcessId);
            localResult.dwThreadId = static_cast<std::uint32_t>(processInfoPtr->dwThreadId);

            if (processInfoPtr->hThread != nullptr)
            {
                ::CloseHandle(processInfoPtr->hThread);
                processInfoPtr->hThread = nullptr;
            }
            if (processInfoPtr->hProcess != nullptr)
            {
                ::CloseHandle(processInfoPtr->hProcess);
                processInfoPtr->hProcess = nullptr;
            }
        };

        if (!request.tokenModeEnabled)
        {
            const BOOL createOk = ::CreateProcessW(
                applicationNamePtr,
                commandLinePtr,
                processSecurityPtr,
                threadSecurityPtr,
                request.inheritHandles ? TRUE : FALSE,
                creationFlags,
                environmentPtr,
                currentDirectoryPtr,
                startupInfoPtr,
                processInfoPtr);

            if (createOk == FALSE)
            {
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = "CreateProcessW failed: " + FormatLastErrorMessage(localResult.win32Error);
                if (resultOut != nullptr)
                {
                    *resultOut = localResult;
                }
                return false;
            }

            localResult.detailText = "CreateProcessW succeeded.";
            finalizeSuccess();
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD desiredAccess = request.tokenDesiredAccess == 0
            ? DefaultTokenDesiredAccess
            : static_cast<DWORD>(request.tokenDesiredAccess);
        HANDLE sourceToken = nullptr;
        std::string tokenError;
        if (!OpenTokenByProcessPid(request.tokenSourcePid, desiredAccess, sourceToken, &tokenError))
        {
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = tokenError;
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return false;
        }

        HANDLE workingToken = sourceToken;
        HANDLE duplicatedPrimaryToken = nullptr;
        if (request.duplicatePrimaryToken)
        {
            if (!DuplicatePrimaryToken(sourceToken, desiredAccess, duplicatedPrimaryToken, &tokenError))
            {
                ::CloseHandle(sourceToken);
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = tokenError;
                if (resultOut != nullptr)
                {
                    *resultOut = localResult;
                }
                return false;
            }
            workingToken = duplicatedPrimaryToken;
        }

        if (!ApplyPrivilegeEdits(workingToken, request.tokenPrivilegeEdits, &tokenError))
        {
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = tokenError;
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return false;
        }

        const BOOL createAsUserOk = ::CreateProcessAsUserW(
            workingToken,
            applicationNamePtr,
            commandLinePtr,
            processSecurityPtr,
            threadSecurityPtr,
            request.inheritHandles ? TRUE : FALSE,
            creationFlags,
            environmentPtr,
            currentDirectoryPtr,
            startupInfoPtr,
            processInfoPtr);
        if (createAsUserOk != FALSE)
        {
            localResult.detailText = "CreateProcessAsUserW succeeded.";
            finalizeSuccess();
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD createAsUserError = ::GetLastError();
        // 兼容性回退：部分环境缺少 SeAssignPrimaryTokenPrivilege 时尝试 CreateProcessWithTokenW。
        const BOOL createWithTokenOk = ::CreateProcessWithTokenW(
            workingToken,
            LOGON_WITH_PROFILE,
            applicationNamePtr,
            commandLinePtr,
            creationFlags,
            environmentPtr,
            currentDirectoryPtr,
            startupInfoPtr,
            processInfoPtr);
        if (createWithTokenOk != FALSE)
        {
            localResult.usedCreateProcessWithTokenFallback = true;
            localResult.detailText = "CreateProcessAsUserW failed, fallback CreateProcessWithTokenW succeeded.";
            finalizeSuccess();
            if (duplicatedPrimaryToken != nullptr)
            {
                ::CloseHandle(duplicatedPrimaryToken);
            }
            ::CloseHandle(sourceToken);
            if (resultOut != nullptr)
            {
                *resultOut = localResult;
            }
            return true;
        }

        const DWORD fallbackError = ::GetLastError();
        std::ostringstream detailStream;
        detailStream
            << "CreateProcessAsUserW failed: " << FormatLastErrorMessage(createAsUserError)
            << " | CreateProcessWithTokenW fallback failed: " << FormatLastErrorMessage(fallbackError);
        localResult.win32Error = static_cast<std::uint32_t>(fallbackError);
        localResult.detailText = detailStream.str();

        if (duplicatedPrimaryToken != nullptr)
        {
            ::CloseHandle(duplicatedPrimaryToken);
        }
        ::CloseHandle(sourceToken);
        if (resultOut != nullptr)
        {
            *resultOut = localResult;
        }
        return false;
    }

    bool LaunchSuspendedProcess(
        const SuspendedProcessLaunchRequest& request,
        SuspendedProcessLaunchResult* const resultOut)
    {
        if (resultOut == nullptr)
        {
            return false;
        }

        SuspendedProcessLaunchResult localResult{};
        const auto finish = [&localResult, resultOut](const bool success) {
            localResult.success = success;
            *resultOut = localResult;
            return success;
        };

        const std::wstring imagePathWide = ks::str::Utf8ToUtf16(request.imagePath);
        if (imagePathWide.empty())
        {
            localResult.failure = SuspendedProcessLaunchFailure::InvalidArgument;
            localResult.detailText = "Target image path is empty or cannot be converted to UTF-16.";
            return finish(false);
        }

        // quoteCommandLineArgument：只负责 argv[0] 的 Windows 反斜杠/引号规则。
        // 用户填写的参数文本保持原样追加，避免改变其既有命令行语义。
        const auto quoteCommandLineArgument = [](const std::wstring& argumentText) {
            std::wstring quotedText;
            quotedText.reserve(argumentText.size() + 2);
            quotedText.push_back(L'\"');

            std::size_t slashCount = 0;
            for (const wchar_t characterValue : argumentText)
            {
                if (characterValue == L'\\')
                {
                    ++slashCount;
                    continue;
                }

                if (characterValue == L'\"')
                {
                    quotedText.append(slashCount * 2 + 1, L'\\');
                    quotedText.push_back(L'\"');
                    slashCount = 0;
                    continue;
                }

                if (slashCount > 0)
                {
                    quotedText.append(slashCount, L'\\');
                    slashCount = 0;
                }
                quotedText.push_back(characterValue);
            }

            if (slashCount > 0)
            {
                quotedText.append(slashCount * 2, L'\\');
            }
            quotedText.push_back(L'\"');
            return quotedText;
        };

        std::wstring commandLineWide = quoteCommandLineArgument(imagePathWide);
        if (!request.argumentText.empty())
        {
            commandLineWide.push_back(L' ');
            commandLineWide += ks::str::Utf8ToUtf16(request.argumentText);
        }

        std::wstring workingDirectoryWide;
        LPCWSTR workingDirectoryPointer = nullptr;
        if (!request.workingDirectory.empty())
        {
            workingDirectoryWide = ks::str::Utf8ToUtf16(request.workingDirectory);
            if (!workingDirectoryWide.empty())
            {
                workingDirectoryPointer = workingDirectoryWide.c_str();
            }
        }

        HANDLE currentTokenHandle = nullptr;
        bool currentProcessElevated = false;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &currentTokenHandle) == FALSE)
        {
            localResult.failure = SuspendedProcessLaunchFailure::CreateFailed;
            localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
            localResult.detailText = "OpenProcessToken(current process) failed: "
                + FormatLastErrorMessage(localResult.win32Error);
            return finish(false);
        }

        TOKEN_ELEVATION tokenElevation{};
        DWORD returnedLength = 0;
        const BOOL elevationQueryOk = ::GetTokenInformation(
            currentTokenHandle,
            TokenElevation,
            &tokenElevation,
            sizeof(tokenElevation),
            &returnedLength);
        const DWORD elevationQueryError = elevationQueryOk == FALSE ? ::GetLastError() : ERROR_SUCCESS;
        if (elevationQueryOk == FALSE)
        {
            ::CloseHandle(currentTokenHandle);
            localResult.failure = SuspendedProcessLaunchFailure::CreateFailed;
            localResult.win32Error = static_cast<std::uint32_t>(elevationQueryError);
            localResult.detailText = "GetTokenInformation(TokenElevation) failed: "
                + FormatLastErrorMessage(elevationQueryError);
            return finish(false);
        }
        currentProcessElevated = elevationQueryOk != FALSE && tokenElevation.TokenIsElevated != 0;

        if (request.runAsAdministrator && !currentProcessElevated)
        {
            ::CloseHandle(currentTokenHandle);
            localResult.failure = SuspendedProcessLaunchFailure::AdministratorRequired;
            localResult.win32Error = static_cast<std::uint32_t>(
                elevationQueryOk != FALSE ? ERROR_ELEVATION_REQUIRED : elevationQueryError);
            localResult.detailText = elevationQueryOk != FALSE
                ? "Current KSword process is not elevated."
                : "GetTokenInformation(TokenElevation) failed: " + FormatLastErrorMessage(elevationQueryError);
            return finish(false);
        }

        HANDLE unelevatedPrimaryTokenHandle = nullptr;
        std::string unelevatedTokenError;
        if (currentProcessElevated && !request.runAsAdministrator && !request.allowElevatedFallback)
        {
            TOKEN_LINKED_TOKEN linkedTokenInfo{};
            returnedLength = 0;
            const BOOL linkedTokenQueryOk = ::GetTokenInformation(
                currentTokenHandle,
                TokenLinkedToken,
                &linkedTokenInfo,
                sizeof(linkedTokenInfo),
                &returnedLength);
            if (linkedTokenQueryOk == FALSE || linkedTokenInfo.LinkedToken == nullptr)
            {
                const DWORD linkedTokenError = ::GetLastError();
                unelevatedTokenError = "GetTokenInformation(TokenLinkedToken) failed: "
                    + FormatLastErrorMessage(linkedTokenError);
            }
            else
            {
                const DWORD primaryTokenAccess = TOKEN_ASSIGN_PRIMARY
                    | TOKEN_DUPLICATE
                    | TOKEN_QUERY
                    | TOKEN_ADJUST_DEFAULT
                    | TOKEN_ADJUST_SESSIONID
                    | TOKEN_IMPERSONATE;
                if (::DuplicateTokenEx(
                    linkedTokenInfo.LinkedToken,
                    primaryTokenAccess,
                    nullptr,
                    SecurityImpersonation,
                    TokenPrimary,
                    &unelevatedPrimaryTokenHandle) == FALSE
                    || unelevatedPrimaryTokenHandle == nullptr)
                {
                    const DWORD duplicateError = ::GetLastError();
                    unelevatedTokenError = "DuplicateTokenEx(TokenLinkedToken) failed: "
                        + FormatLastErrorMessage(duplicateError);
                }
                ::CloseHandle(linkedTokenInfo.LinkedToken);
            }

            if (unelevatedPrimaryTokenHandle == nullptr)
            {
                ::CloseHandle(currentTokenHandle);
                localResult.failure = SuspendedProcessLaunchFailure::UnelevatedTokenUnavailable;
                localResult.detailText = unelevatedTokenError.empty()
                    ? "No unelevated linked token is available."
                    : unelevatedTokenError;
                return finish(false);
            }
        }
        ::CloseHandle(currentTokenHandle);

        const auto initializeProcessInformation = []() {
            PROCESS_INFORMATION processInformation{};
            return processInformation;
        };
        const auto finalizeSuccess = [&localResult](PROCESS_INFORMATION& processInformation) {
            localResult.processId = static_cast<std::uint32_t>(processInformation.dwProcessId);
            localResult.threadId = static_cast<std::uint32_t>(processInformation.dwThreadId);
            localResult.processHandle = reinterpret_cast<std::uint64_t>(processInformation.hProcess);
            localResult.initialThreadHandle = reinterpret_cast<std::uint64_t>(processInformation.hThread);
            processInformation.hProcess = nullptr;
            processInformation.hThread = nullptr;
        };
        const auto buildMutableCommandLine = [&commandLineWide]() {
            std::vector<wchar_t> commandLineBuffer(commandLineWide.begin(), commandLineWide.end());
            commandLineBuffer.push_back(L'\0');
            return commandLineBuffer;
        };

        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        const DWORD creationFlags = CREATE_SUSPENDED;

        if (unelevatedPrimaryTokenHandle == nullptr)
        {
            PROCESS_INFORMATION processInformation = initializeProcessInformation();
            std::vector<wchar_t> commandLineBuffer = buildMutableCommandLine();
            const BOOL createOk = ::CreateProcessW(
                imagePathWide.c_str(),
                commandLineBuffer.data(),
                nullptr,
                nullptr,
                FALSE,
                creationFlags,
                nullptr,
                workingDirectoryPointer,
                &startupInfo,
                &processInformation);
            if (createOk == FALSE)
            {
                localResult.failure = SuspendedProcessLaunchFailure::CreateFailed;
                localResult.win32Error = static_cast<std::uint32_t>(::GetLastError());
                localResult.detailText = "CreateProcessW(CREATE_SUSPENDED) failed: "
                    + FormatLastErrorMessage(localResult.win32Error);
                return finish(false);
            }

            localResult.usedElevatedFallback = currentProcessElevated
                && !request.runAsAdministrator
                && request.allowElevatedFallback;
            localResult.detailText = "CreateProcessW(CREATE_SUSPENDED) succeeded.";
            finalizeSuccess(processInformation);
            return finish(true);
        }

        PROCESS_INFORMATION processInformation = initializeProcessInformation();
        std::vector<wchar_t> commandLineBuffer = buildMutableCommandLine();
        BOOL createOk = ::CreateProcessAsUserW(
            unelevatedPrimaryTokenHandle,
            imagePathWide.c_str(),
            commandLineBuffer.data(),
            nullptr,
            nullptr,
            FALSE,
            creationFlags,
            nullptr,
            workingDirectoryPointer,
            &startupInfo,
            &processInformation);
        if (createOk == FALSE)
        {
            const DWORD createAsUserError = ::GetLastError();
            processInformation = initializeProcessInformation();
            commandLineBuffer = buildMutableCommandLine();
            createOk = ::CreateProcessWithTokenW(
                unelevatedPrimaryTokenHandle,
                LOGON_WITH_PROFILE,
                imagePathWide.c_str(),
                commandLineBuffer.data(),
                creationFlags,
                nullptr,
                workingDirectoryPointer,
                &startupInfo,
                &processInformation);
            if (createOk == FALSE)
            {
                const DWORD createWithTokenError = ::GetLastError();
                ::CloseHandle(unelevatedPrimaryTokenHandle);
                localResult.failure = SuspendedProcessLaunchFailure::UnelevatedTokenUnavailable;
                localResult.win32Error = static_cast<std::uint32_t>(createWithTokenError);
                localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken) failed: "
                    + FormatLastErrorMessage(createAsUserError)
                    + " | CreateProcessWithTokenW fallback failed: "
                    + FormatLastErrorMessage(createWithTokenError);
                return finish(false);
            }
            localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken) failed; CreateProcessWithTokenW(CREATE_SUSPENDED) succeeded.";
        }
        else
        {
            localResult.detailText = "CreateProcessAsUserW(TokenLinkedToken, CREATE_SUSPENDED) succeeded.";
        }

        ::CloseHandle(unelevatedPrimaryTokenHandle);
        localResult.usedUnelevatedToken = true;
        finalizeSuccess(processInformation);
        return finish(true);
    }

    bool ResumeSuspendedProcessInitialThread(
        const std::uint64_t initialThreadHandle,
        std::string* const errorMessage)
    {
        const HANDLE threadHandle = reinterpret_cast<HANDLE>(initialThreadHandle);
        if (threadHandle == nullptr || threadHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Initial thread handle is invalid.";
            }
            return false;
        }

        if (::ResumeThread(threadHandle) == static_cast<DWORD>(-1))
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "ResumeThread failed: " + FormatLastErrorMessage(::GetLastError());
            }
            return false;
        }
        return true;
    }

    bool TerminateSuspendedProcessByHandle(
        const std::uint64_t processHandle,
        std::string* const errorMessage)
    {
        const HANDLE nativeProcessHandle = reinterpret_cast<HANDLE>(processHandle);
        if (nativeProcessHandle == nullptr || nativeProcessHandle == INVALID_HANDLE_VALUE)
        {
            if (errorMessage != nullptr)
            {
                *errorMessage = "Suspended process handle is invalid.";
            }
            return false;
        }

        const BOOL terminateOk = ::TerminateProcess(nativeProcessHandle, 1);
        const DWORD terminateError = terminateOk != FALSE ? ERROR_SUCCESS : ::GetLastError();
        if (terminateOk != FALSE)
        {
            return true;
        }

        if (errorMessage != nullptr)
        {
            *errorMessage = "TerminateProcess failed: " + FormatLastErrorMessage(terminateError);
        }
        return false;
    }

    void CloseSuspendedProcessInitialThreadHandle(const std::uint64_t initialThreadHandle)
    {
        const HANDLE threadHandle = reinterpret_cast<HANDLE>(initialThreadHandle);
        if (threadHandle != nullptr && threadHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(threadHandle);
        }
    }

    void CloseSuspendedProcessHandle(const std::uint64_t processHandle)
    {
        const HANDLE nativeProcessHandle = reinterpret_cast<HANDLE>(processHandle);
        if (nativeProcessHandle != nullptr && nativeProcessHandle != INVALID_HANDLE_VALUE)
        {
            ::CloseHandle(nativeProcessHandle);
        }
    }

    std::wstring GetCurrentProcessPath()
    {
        wchar_t szPath[MAX_PATH] = { 0 };
        if (GetModuleFileNameW(NULL, szPath, MAX_PATH) == 0)
        {
            return L"";
        }
        return std::wstring(szPath);
    }
}
