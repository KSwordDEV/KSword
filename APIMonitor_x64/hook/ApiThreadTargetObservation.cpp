#include "pch.h"
#include "ApiThreadTargetObservation.h"
#include <winternl.h>

namespace apimon {
namespace {
// FileTimeValue：合并 value 的 FILETIME 高低位，作为进程/线程创建代次。
std::uint64_t FileTimeValue(const FILETIME& value) noexcept
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}
// Qpc：读取当前单调计数，读取失败时保留未知零值。
std::uint64_t Qpc() noexcept
{
    LARGE_INTEGER value{}; // 系统返回的性能计数。
    return ::QueryPerformanceCounter(&value) && value.QuadPart > 0
        ? static_cast<std::uint64_t>(value.QuadPart) : 0;
}
// ThreadIdentity：原线程句柄的所属进程及线程创建身份。
struct ThreadIdentity {
    DWORD pid = 0; // 线程所属进程 PID。
    DWORD tid = 0; // 线程 TID。
    std::uint64_t creation = 0; // 线程创建 FILETIME。
};
// QueryThread：仅读 thread 句柄已有查询权限，把完整身份写入 identity；失败不补造身份。
bool QueryThread(HANDLE thread, ThreadIdentity& identity) noexcept
{
    FILETIME created{}; // 返回的线程创建时间。
    FILETIME exited{}; // API 必需的退出时间输出，本次不使用。
    FILETIME kernel{}; // API 必需的内核用时输出，本次不使用。
    FILETIME user{}; // API 必需的用户用时输出，本次不使用。
    const DWORD tid = ::GetThreadId(thread); // 输入句柄解析出的线程 ID。
    const DWORD pid = ::GetProcessIdOfThread(thread); // 输入句柄解析出的所属进程 ID。
    if (!pid || !tid || !::GetThreadTimes(thread, &created, &exited, &kernel, &user) ||
        !FileTimeValue(created)) {
        return false;
    }
    identity = {pid, tid, FileTimeValue(created)};
    return true;
}
// ProcessPrefix：SystemProcessInformation 到 PID 的稳定前缀；指针字段遵循当前查询者 ABI。
struct ProcessPrefix {
    ULONG next; // 下条记录相对偏移，零表示最后一条。
    ULONG threadCount; // 布局占位：线程数。
    LARGE_INTEGER workingSetPrivate; // 布局占位：私有工作集。
    ULONG hardFaults; // 布局占位：硬缺页计数。
    ULONG highWatermark; // 布局占位：线程数峰值。
    ULONGLONG cycleTime; // 布局占位：累计周期。
    LARGE_INTEGER creation; // 进程创建 FILETIME。
    LARGE_INTEGER userTime; // 布局占位：用户态用时。
    LARGE_INTEGER kernelTime; // 布局占位：内核态用时。
    UNICODE_STRING imageName; // 布局占位：映像名描述符，不解引用。
    LONG basePriority; // 布局占位：基础优先级。
    HANDLE pid; // 当前记录的进程 ID，按指针宽度存储。
};
static_assert(offsetof(ProcessPrefix, creation) == 32);

// QueryProcessCreation：按 pid 查询创建时间；外部进程只读系统快照，不新开目标句柄。
std::uint64_t QueryProcessCreation(DWORD pid) noexcept
{
    if (pid == ::GetCurrentProcessId()) {
        FILETIME created{}; // 当前进程创建时间。
        FILETIME exited{}; // GetProcessTimes 所需的退出时间输出。
        FILETIME kernel{}; // GetProcessTimes 所需的内核用时输出。
        FILETIME user{}; // GetProcessTimes 所需的用户用时输出。
        return ::GetProcessTimes(::GetCurrentProcess(), &created, &exited, &kernel, &user)
            ? FileTimeValue(created) : 0;
    }
    // 每个调用线程复用有界缓冲；查询失败或超限时保持未知，不读取外部目标内存。
    // Query：动态系统快照查询函数的 ABI，参数依次为类别、缓冲、容量及返回长度。
    using Query = NTSTATUS (NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    static const auto query = reinterpret_cast<Query>(::GetProcAddress( // 已加载 ntdll 的查询入口。
        ::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    if (!query) {
        return 0;
    }
    thread_local std::vector<unsigned char> buffer; // 当前线程复用的系统快照存储。
    constexpr ULONG limit = 8u * 1024 * 1024; // 单线程快照容量硬上限。
    try {
        if (buffer.empty()) {
            buffer.resize(256 * 1024);
        }
        ULONG returned = 0; // 系统报告的有效长度或所需容量。
        NTSTATUS status = query(5, buffer.data(), static_cast<ULONG>(buffer.size()), &returned); // 查询状态。
        if (status == static_cast<NTSTATUS>(0xC0000004u)) {
            if (!returned || returned > limit - 65536) {
                return 0;
            }
            buffer.resize(returned + 65536);
            status = query(5, buffer.data(), static_cast<ULONG>(buffer.size()), &returned);
        }
        if (status < 0 || !returned || returned > buffer.size()) {
            return 0;
        }
        std::size_t offset = 0; // 当前记录相对缓冲起点的位置。
        while (returned - offset >= sizeof(ProcessPrefix)) {
            ProcessPrefix row{}; // 从有界原始缓冲复制的当前进程记录前缀。
            std::memcpy(&row, buffer.data() + offset, sizeof(row));
            if (reinterpret_cast<std::uintptr_t>(row.pid) == pid) {
                return row.creation.QuadPart > 0 ? static_cast<std::uint64_t>(row.creation.QuadPart) : 0;
            }
            if (!row.next || row.next < sizeof(ProcessPrefix) || row.next > returned - offset) {
                break;
            }
            offset += row.next;
        }
    } catch (...) {
        return 0;
    }
    return 0;
}
}

// 冻结 thread 的调用前身份，系统快照前后均复核线程句柄，保留调用方 LastError。
ApiThreadTargetObservation::ApiThreadTargetObservation(HANDLE thread) noexcept : thread_(thread)
{
    const DWORD error = ::GetLastError(); // 额外查询前的调用方错误状态。
    fields_.actorCreationFileTime = QueryProcessCreation(::GetCurrentProcessId());
    if (fields_.actorCreationFileTime) {
        fields_.flags |= ThreadTargetActor;
    }
    fields_.inputThreadHandle = reinterpret_cast<std::uintptr_t>(thread);
    ThreadIdentity before{}; // 读取进程快照之前的线程身份。
    ThreadIdentity after{}; // 读取进程快照之后的线程身份。
    if (QueryThread(thread, before)) {
        const auto creation = QueryProcessCreation(before.pid); // 目标所属进程创建代次。
        if (QueryThread(thread, after) && before.pid == after.pid && before.tid == after.tid &&
            before.creation == after.creation) {
            fields_.targetTid = before.tid;
            fields_.targetThreadCreationFileTime = before.creation;
            fields_.flags |= ThreadTargetThread;
            if (creation && creation <= before.creation) {
                fields_.targetPid = before.pid;
                fields_.targetCreationFileTime = creation;
                fields_.flags |= ThreadTargetProcess;
            }
        }
    }
    ::SetLastError(error);
}
// 在原 API 入口前保存 QPC，不向调用方暴露计时查询的 LastError。
void ApiThreadTargetObservation::MarkEntry() noexcept
{
    const DWORD error = ::GetLastError(); // 原 API 即将接收的 LastError。
    fields_.enterQpc = Qpc();
    ::SetLastError(error);
}
// 在原 API 返回后保存 QPC，不覆盖原 API 的 LastError。
void ApiThreadTargetObservation::MarkReturn() noexcept
{
    const DWORD error = ::GetLastError(); // 原 API 返回时的 LastError。
    fields_.returnQpc = Qpc();
    ::SetLastError(error);
}
// 调用后再次夹取进程快照与线程身份，仅全部代次匹配时声明稳定。
void ApiThreadTargetObservation::Complete() noexcept
{
    const DWORD error = ::GetLastError(); // 复核结束后恢复的原调用错误状态。
    ThreadIdentity after{}; // 调用后、快照前的线程身份。
    ThreadIdentity verified{}; // 调用后、快照后的线程身份。
    if ((fields_.flags & (ThreadTargetProcess | ThreadTargetThread)) ==
        (ThreadTargetProcess | ThreadTargetThread) && QueryThread(thread_, after) &&
        after.pid == fields_.targetPid && after.tid == fields_.targetTid &&
        after.creation == fields_.targetThreadCreationFileTime &&
        QueryProcessCreation(after.pid) == fields_.targetCreationFileTime &&
        QueryThread(thread_, verified) && after.pid == verified.pid && after.tid == verified.tid &&
        after.creation == verified.creation) {
        fields_.flags |= ThreadTargetStable;
    }
    ::SetLastError(error);
}
}
