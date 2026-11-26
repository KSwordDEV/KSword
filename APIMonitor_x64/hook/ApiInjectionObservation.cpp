#include "pch.h"
#include "ApiInjectionObservation.h"

namespace apimon
{
    namespace
    {
        using namespace Ksword::Evidence;

        // FileTimeValue：合并 value 高低位，保留原创建 FILETIME。
        std::uint64_t FileTimeValue(const FILETIME& value) noexcept
        {
            return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        }

        // ProcessIdentity：从原 process 句柄解析 pid/creation，不另开目标句柄。
        bool ProcessIdentity(HANDLE process, DWORD& pid, std::uint64_t& creation) noexcept
        {
            FILETIME created{}; // 进程创建时间输出。
            FILETIME exited{}; // API 所需的退出时间输出。
            FILETIME kernel{}; // API 所需的内核用时输出。
            FILETIME user{}; // API 所需的用户用时输出。
            const DWORD resolvedPid = ::GetProcessId(process); // 原句柄解析出的 PID。
            if (!resolvedPid || !::GetProcessTimes(process, &created, &exited, &kernel, &user)
                || !FileTimeValue(created)) {
                return false;
            }
            pid = resolvedPid;
            creation = FileTimeValue(created);
            return true;
        }

        // ReadOutput：SEH 安全读取 pointer 指向的原输出到 value；调用方负责成功门禁。
        template<typename T>
        bool ReadOutput(const T* pointer, T& value) noexcept
        {
            if (!pointer) {
                return false;
            }
            __try {
                value = *pointer;
                return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                return false;
            }
        }

        // ReadQpc：读取单调计数，失败时保留未知零值。
        std::uint64_t ReadQpc() noexcept
        {
            LARGE_INTEGER value{}; // 系统返回的性能计数。
            return ::QueryPerformanceCounter(&value) && value.QuadPart > 0
                ? static_cast<std::uint64_t>(value.QuadPart) : 0;
        }
    }

    // 构造时冻结原 operation/process/address/requestedBytes 与可查询的进程代次。
    ApiInjectionObservation::ApiInjectionObservation(ApiInjectionOperation operation,
        HANDLE process, std::uint64_t address, std::uint64_t requestedBytes) noexcept
        : process_(process)
    {
        const DWORD lastError = ::GetLastError(); // 原调用前需要保留的错误状态。
        fields_.operation = operation;
        fields_.inputHandle = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(process));
        DWORD pid = 0; // 当前进程身份查询解析出的 PID。
        std::uint64_t created = 0; // 当前进程身份查询解析出的创建代次。
        if (ProcessIdentity(::GetCurrentProcess(), pid, created)) {
            fields_.actorCreationFileTime = created;
            fields_.flags |= ApiInjectionActorIdentity;
        }
        if (ProcessIdentity(process_, pid, created)) {
            fields_.targetPid = pid;
            fields_.targetCreationFileTime = created;
            fields_.flags |= ApiInjectionTargetIdentity;
        }
        if (operation == ApiInjectionOperation::MemoryWrite) {
            fields_.address = address;
            fields_.requestedBytes = requestedBytes;
            fields_.flags |= ApiInjectionAddress;
        } else {
            fields_.startAddress = address;
            fields_.flags |= ApiInjectionStartAddress;
        }
        ::SetLastError(lastError);
    }

    // 原调用前计时，观察操作不影响 LastError。
    void ApiInjectionObservation::MarkEntry() noexcept
    {
        const DWORD lastError = ::GetLastError(); // 原 API 即将接收的错误状态。
        fields_.enterQpc = ReadQpc();
        ::SetLastError(lastError);
    }

    // 原调用返回后立即计时，不把后续身份查询算入原调用区间。
    void ApiInjectionObservation::MarkReturn() noexcept
    {
        const DWORD lastError = ::GetLastError(); // 原 API 返回时的错误状态。
        fields_.returnQpc = ReadQpc();
        ::SetLastError(lastError);
    }

    // 对原进程句柄重新取身份，只有 PID 和创建代次均匹配才标记 Stable。
    void ApiInjectionObservation::RecheckTarget() noexcept
    {
        DWORD pid = 0; // 调用后解析的进程 PID。
        std::uint64_t created = 0; // 调用后解析的创建 FILETIME。
        if ((fields_.flags & ApiInjectionTargetIdentity) && ProcessIdentity(process_, pid, created)
            && pid == fields_.targetPid && created == fields_.targetCreationFileTime) {
            fields_.flags |= ApiInjectionTargetStable;
        }
    }

    // success 为原调用成功结果；仅成功且 completedBytes 可读时保存实际写入长度。
    void ApiInjectionObservation::CompleteWrite(bool success, const SIZE_T* completedBytes) noexcept
    {
        const DWORD lastError = ::GetLastError(); // 观察后需要恢复的原调用错误状态。
        RecheckTarget();
        SIZE_T completed = 0; // 安全读回的实际完成字节数。
        if (success && ReadOutput(completedBytes, completed)) {
            fields_.completedBytes = static_cast<std::uint64_t>(completed);
            fields_.flags |= ApiInjectionCompletedLength;
        }
        ::SetLastError(lastError);
    }

    // success 为原调用成功结果；thread 为原返回句柄，查询创建身份但不声明线程执行。
    void ApiInjectionObservation::CompleteThread(bool success, HANDLE thread) noexcept
    {
        const DWORD lastError = ::GetLastError(); // 观察后需要恢复的原调用错误状态。
        RecheckTarget();
        if (success && thread && thread != INVALID_HANDLE_VALUE) {
            FILETIME created{}; // 返回线程创建时间。
            FILETIME exited{}; // API 所需的线程退出时间输出。
            FILETIME kernel{}; // API 所需的内核用时输出。
            FILETIME user{}; // API 所需的用户用时输出。
            const DWORD tid = ::GetThreadId(thread); // 返回句柄对应的真实 TID。
            const DWORD owner = ::GetProcessIdOfThread(thread); // 返回线程所属 PID。
            if (tid && owner && (!(fields_.flags & ApiInjectionTargetIdentity) || owner == fields_.targetPid)
                && ::GetThreadTimes(thread, &created, &exited, &kernel, &user) && FileTimeValue(created)) {
                fields_.targetTid = tid;
                fields_.targetThreadCreationFileTime = FileTimeValue(created);
                fields_.flags |= ApiInjectionThreadIdentity;
            }
        }
        ::SetLastError(lastError);
    }

    // success 为原 NT 调用成功结果；只在成功时解引用 thread 并交给统一完成路径。
    void ApiInjectionObservation::CompleteThreadOutput(bool success, const HANDLE* thread) noexcept
    {
        HANDLE returnedThread = nullptr; // 安全读回的原返回线程句柄。
        const bool readable = success && ReadOutput(thread, returnedThread); // 原成功及安全读取联合门禁。
        CompleteThread(readable, returnedThread);
    }
}
