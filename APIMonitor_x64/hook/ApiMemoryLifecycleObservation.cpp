#include "pch.h"
#include "ApiMemoryLifecycleObservation.h"
#include "ApiInjectionObservation.h"

namespace apimon {
namespace {
using namespace Ksword::Evidence;
// SafeRead：SEH读取输入/输出，pointer无效时value保持未知，调用方负责成功门禁。
template<class T>
bool SafeRead(const T* pointer, T& value) noexcept
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
}

// 冻结kind/process/base/size/type/protection原请求；身份复用AAIP1读取链，不编码或修改AAIP1字段。
ApiMemoryLifecycleObservation::ApiMemoryLifecycleObservation(Ksword::Evidence::ApiMemoryOperation kind,
    HANDLE process, PVOID const* base, const SIZE_T* size, ULONG type, ULONG protection) noexcept
    : process_(process)
{
    const DWORD error = ::GetLastError(); // 调用方原错误状态。
    fields_.operation = kind;
    fields_.pointerBits = sizeof(void*) * 8;
    fields_.inputProcessHandle = reinterpret_cast<std::uintptr_t>(process);
    fields_.allocationType = kind == ApiMemoryOperation::Allocate ? type : 0;
    fields_.freeType = kind == ApiMemoryOperation::Free ? type : 0;
    fields_.newProtection = protection;
    // identity仅借用原强身份查询链；写入地址/长度为零且从不发送此临时AAIP1。
    ApiInjectionObservation identity(ApiInjectionOperation::MemoryWrite, process, 0, 0);
    const auto& original = identity.fields(); // 原路径产生的完整进程身份及有效位。
    if (original.flags & ApiInjectionActorIdentity) {
        fields_.actorCreationFileTime = original.actorCreationFileTime;
        fields_.flags |= ApiMemoryActorIdentity;
    }
    if (original.flags & ApiInjectionTargetIdentity) {
        fields_.targetPid = original.targetPid;
        fields_.targetCreationFileTime = original.targetCreationFileTime;
        fields_.flags |= ApiMemoryTargetIdentity;
    }
    PVOID requestedBase = nullptr; // 原输入基址。
    SIZE_T requestedBytes = 0; // 原输入长度，Free允许0。
    if (SafeRead(base, requestedBase)) {
        fields_.requestedBase = reinterpret_cast<std::uintptr_t>(requestedBase);
        fields_.flags |= ApiMemoryRequestedBase;
    }
    if (SafeRead(size, requestedBytes)) {
        fields_.requestedBytes = requestedBytes;
        fields_.flags |= ApiMemoryRequestedBytes;
    }
    ::SetLastError(error);
}

// 进入/返回时点只计原调用；错误状态不被观察查询改变。
void ApiMemoryLifecycleObservation::MarkEntry() noexcept
{
    const DWORD error = ::GetLastError(); // 原LastError。
    LARGE_INTEGER qpc{}; // 本次计数输出。
    if (::QueryPerformanceCounter(&qpc) && qpc.QuadPart > 0) {
        fields_.enterQpc = static_cast<std::uint64_t>(qpc.QuadPart);
    }
    ::SetLastError(error);
}

// MarkReturn：原调用返回后立即记录，后续身份查询不计入耗时。
void ApiMemoryLifecycleObservation::MarkReturn() noexcept
{
    const DWORD error = ::GetLastError(); // 原LastError。
    LARGE_INTEGER qpc{}; // 本次计数输出。
    if (::QueryPerformanceCounter(&qpc) && qpc.QuadPart > 0) {
        fields_.returnQpc = static_cast<std::uint64_t>(qpc.QuadPart);
    }
    ::SetLastError(error);
}

// 按原NTSTATUS采输出；Free/Unmap没有输出范围，不从size=0或输入地址推断全区。
void ApiMemoryLifecycleObservation::Complete(NTSTATUS status, PVOID const* base,
    const SIZE_T* size, const ULONG* oldProtection) noexcept
{
    const DWORD error = ::GetLastError(); // 原调用错误状态。
    fields_.status = status;
    fields_.returnValid = true;
    // 优先快照原调用输出，避免额外的身份查询延后对调用方内存的安全读取。
    PVOID outputBase = nullptr; // 成功后的真实输出基址。
    SIZE_T outputBytes = 0; // 成功后的真实输出长度。
    ULONG previous = 0; // 成功Protect的旧保护。
    if (status >= 0 && (fields_.operation == ApiMemoryOperation::Allocate || fields_.operation == ApiMemoryOperation::Protect)) {
        if (SafeRead(base, outputBase)) {
            fields_.outputBase = reinterpret_cast<std::uintptr_t>(outputBase);
            fields_.flags |= ApiMemoryOutputBase;
        }
        if (SafeRead(size, outputBytes)) {
            fields_.outputBytes = outputBytes;
            fields_.flags |= ApiMemoryOutputBytes;
        }
        if (fields_.operation == ApiMemoryOperation::Protect && SafeRead(oldProtection, previous)) {
            fields_.oldProtection = previous;
            fields_.flags |= ApiMemoryOldProtection;
        }
    }
    // 输出完成后复核原句柄；身份查询失败或不同均不标Stable，不回填PID或范围。
    ApiInjectionObservation identity(ApiInjectionOperation::MemoryWrite, process_, 0, 0); // 复用原强身份链。
    const auto& current = identity.fields(); // 调用后完整身份，查询失败不回填PID。
    if ((fields_.flags & ApiMemoryTargetIdentity) && (current.flags & ApiInjectionTargetIdentity) &&
        fields_.targetPid == current.targetPid && fields_.targetCreationFileTime == current.targetCreationFileTime) {
        fields_.flags |= ApiMemoryTargetStable;
    }
    ::SetLastError(error);
}
} // namespace apimon
