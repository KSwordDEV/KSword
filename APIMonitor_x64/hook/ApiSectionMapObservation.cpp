#include "pch.h"
#include "ApiSectionMapObservation.h"

namespace apimon {
namespace {
using namespace Ksword::Evidence;
// FileTimeValue：合并 value 的 FILETIME 位模式，作为进程创建代次。
std::uint64_t FileTimeValue(const FILETIME& value) noexcept
{
    return (static_cast<std::uint64_t>(value.dwHighDateTime) << 32) | value.dwLowDateTime;
}
// ProcessIdentity：从原 process 句柄解析 pid/created，查询失败不伪造身份。
bool ProcessIdentity(HANDLE process, DWORD& pid, std::uint64_t& created) noexcept
{
    FILETIME c{}; // 进程创建时间输出。
    FILETIME exited{}; // API 所需的退出时间输出。
    FILETIME kernel{}; // API 所需的内核用时输出。
    FILETIME user{}; // API 所需的用户用时输出。
    const DWORD resolved = ::GetProcessId(process); // 原句柄对应的进程 PID。
    if (!resolved || !::GetProcessTimes(process, &c, &exited, &kernel, &user) || !FileTimeValue(c)) {
        return false;
    }
    pid = resolved;
    created = FileTimeValue(c);
    return true;
}
// ReadValue：SEH 安全读取 pointer 指向的 T 值到 value，不把不可读地址解释成零值成功。
template<typename T>
bool ReadValue(const T* pointer, T& value) noexcept
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
// Qpc：返回当前性能计数，失败时保留未知零值。
std::uint64_t Qpc() noexcept
{
    LARGE_INTEGER value{}; // 系统查询返回的计数值。
    return ::QueryPerformanceCounter(&value) && value.QuadPart > 0
        ? static_cast<std::uint64_t>(value.QuadPart) : 0;
}
}
// 冻结原 section/process 参数、进程身份及可读输入，不改动原请求缓冲。
ApiSectionMapObservation::ApiSectionMapObservation(HANDLE section, HANDLE process, PVOID const* base,
    const SIZE_T* size, const LARGE_INTEGER* offset, ULONG protection) noexcept : process_(process)
{
    const DWORD error = ::GetLastError(); // 观察查询前的调用方错误状态。
    fields_.inputSectionHandle = reinterpret_cast<std::uintptr_t>(section);
    fields_.inputProcessHandle = reinterpret_cast<std::uintptr_t>(process);
    fields_.requestedProtection = protection;
    DWORD pid = 0; // 当前进程身份查询返回的 PID。
    std::uint64_t created = 0; // 当前进程身份查询返回的创建时间。
    if (ProcessIdentity(::GetCurrentProcess(), pid, created)) {
        fields_.actorCreationFileTime = created;
        fields_.flags |= ApiSectionMapActorIdentity;
    }
    if (ProcessIdentity(process_, pid, created)) {
        fields_.targetPid = pid;
        fields_.targetCreationFileTime = created;
        fields_.flags |= ApiSectionMapTargetIdentity;
    }
    PVOID requestedBase = nullptr; // 原 base 指针安全读出的请求地址。
    SIZE_T requestedSize = 0; // 原 size 指针安全读出的请求长度。
    LARGE_INTEGER requestedOffset{}; // 原 offset 指针安全读出的节内偏移。
    if (ReadValue(base, requestedBase)) {
        fields_.requestedBase = reinterpret_cast<std::uintptr_t>(requestedBase);
        fields_.flags |= ApiSectionMapRequestedBase;
    }
    if (ReadValue(size, requestedSize)) {
        fields_.requestedBytes = requestedSize;
        fields_.flags |= ApiSectionMapRequestedBytes;
    }
    if (ReadValue(offset, requestedOffset)) {
        fields_.sectionOffset = static_cast<std::uint64_t>(requestedOffset.QuadPart);
        fields_.flags |= ApiSectionMapSectionOffset;
    }
    ::SetLastError(error);
}
// 在原调用前记录时点，额外计时查询不影响 LastError。
void ApiSectionMapObservation::MarkEntry() noexcept
{
    const DWORD error = ::GetLastError(); // 原调用即将接收的错误状态。
    fields_.enterQpc = Qpc();
    ::SetLastError(error);
}
// 原调用返回后立即记录时点，后续查询不计入该区间。
void ApiSectionMapObservation::MarkReturn() noexcept
{
    const DWORD error = ::GetLastError(); // 原调用返回时的错误状态。
    fields_.returnQpc = Qpc();
    ::SetLastError(error);
}
// 复核原 process_ 身份，按 success 门禁分别安全读取 base/size，不读失败调用的输出。
void ApiSectionMapObservation::Complete(bool success, PVOID const* base, const SIZE_T* size) noexcept
{
    const DWORD error = ::GetLastError(); // 完成观察后恢复的原调用错误状态。
    DWORD pid = 0; // 调用后查询得到的 PID。
    std::uint64_t created = 0; // 调用后查询得到的进程创建时间。
    if ((fields_.flags & ApiSectionMapTargetIdentity) && ProcessIdentity(process_, pid, created) &&
        pid == fields_.targetPid && created == fields_.targetCreationFileTime) {
        fields_.flags |= ApiSectionMapTargetStable;
    }
    PVOID mappedBase = nullptr; // 成功调用安全读回的映射地址。
    SIZE_T mappedSize = 0; // 成功调用安全读回的映射长度。
    if (success && ReadValue(base, mappedBase)) {
        fields_.mappedBase = reinterpret_cast<std::uintptr_t>(mappedBase);
        fields_.flags |= ApiSectionMapMappedBase;
    }
    if (success && ReadValue(size, mappedSize)) {
        fields_.mappedBytes = mappedSize;
        fields_.flags |= ApiSectionMapMappedBytes;
    }
    ::SetLastError(error);
}
}
