#include "pch.h"
#include "ApiContextObservation.h"

namespace apimon {
namespace {
// ReadRequestedContext：SEH 安全读取 context 中本 ABI 的请求值，仅成功读取后设置 fields 有效位。
void ReadRequestedContext(const CONTEXT* context, Ksword::Evidence::ApiContextFieldsV1& fields) noexcept
{
    if (!context) {
        return;
    }
    __try {
        const DWORD flags = context->ContextFlags; // 调用方声明的寄存器分组及 ABI。
        fields.contextFlags = flags;
        fields.flags |= Ksword::Evidence::ApiContextFlags;
        // 只有包含本 ABI 的 CONTROL 组，IP/SP 才是此次请求的一部分。
        if ((flags & CONTEXT_CONTROL) != CONTEXT_CONTROL) {
            return;
        }
#if defined(_M_X64)
        const auto ip = context->Rip; // x64 请求指令指针，尚未声明读取成功。
        const auto sp = context->Rsp; // x64 请求栈指针，二者读取成功后共同生效。
#else
        const auto ip = context->Eip; // x86 请求指令指针，尚未声明读取成功。
        const auto sp = context->Esp; // x86 请求栈指针，二者读取成功后共同生效。
#endif
        fields.requestedIp = ip;
        fields.requestedSp = sp;
        fields.flags |= Ksword::Evidence::ApiContextControlRegisters;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // 不可读输入不应让观察代码崩溃；保留此前已成功读取的字段。
    }
}
}
// 冻结 context 的调用前请求快照；不修改输入，不获取目标句柄所有权。
ApiContextObservation::ApiContextObservation(HANDLE thread, const CONTEXT* context) noexcept : identity_(thread)
{
    const DWORD error = ::GetLastError(); // 安全读取前的调用方错误状态。
    fields_.contextArchitecture = sizeof(void*) * 8;
    fields_.inputContextAddress = reinterpret_cast<std::uintptr_t>(context);
    ReadRequestedContext(context, fields_);
    ::SetLastError(error);
}
// 把复核后的身份与计时追加到此前冻结的请求字段，保持请求和返回语义分离。
void ApiContextObservation::Complete() noexcept
{
    identity_.Complete();
    const auto& identity = identity_.fields(); // 本次调用的完整身份采集结果。
    using namespace Ksword::Evidence;
    if (identity.flags & ThreadTargetActor) {
        fields_.flags |= ApiContextActorIdentity;
    }
    if (identity.flags & ThreadTargetProcess) {
        fields_.flags |= ApiContextTargetIdentity;
    }
    if (identity.flags & ThreadTargetThread) {
        fields_.flags |= ApiContextThreadIdentity;
    }
    if (identity.flags & ThreadTargetStable) {
        fields_.flags |= ApiContextTargetStable;
    }
    fields_.actorCreationFileTime = identity.actorCreationFileTime;
    fields_.targetPid = identity.targetPid;
    fields_.targetCreationFileTime = identity.targetCreationFileTime;
    fields_.targetTid = identity.targetTid;
    fields_.targetThreadCreationFileTime = identity.targetThreadCreationFileTime;
    fields_.enterQpc = identity.enterQpc;
    fields_.returnQpc = identity.returnQpc;
    fields_.inputThreadHandle = identity.inputThreadHandle;
}
}
