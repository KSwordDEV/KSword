#include "pch.h"
#include "ApiApcObservation.h"

namespace apimon {
// 构造时冻结 thread 的调用前身份及 routine、argument1/2/3 原参数。
ApiApcObservation::ApiApcObservation(HANDLE thread, std::uint64_t routine,
    std::uint64_t argument1, std::uint64_t argument2, std::uint64_t argument3,
    std::uint64_t reserveHandle) noexcept : identity_(thread)
{
    fields_.routineAddress = routine;
    fields_.argument1 = argument1;
    fields_.argument2 = argument2;
    fields_.argument3 = argument3;
    fields_.reserveHandle = reserveHandle;
    // 调用前交接读取同一份冻结身份；Stable 仍只在原 API 返回并完成复核后产生。
    CopyIdentity();
}
// 原调用进入时点由共享采集器记录，避免把额外身份查询计入 QPC 区间。
void ApiApcObservation::MarkEntry() noexcept
{
    identity_.MarkEntry();
}
// 原调用返回时立即记录，后续身份复核不改变该时点。
void ApiApcObservation::MarkReturn() noexcept
{
    identity_.MarkReturn();
}
// 把共享采集结果逐项投影到 AAAP1，不把稳定或入队成功解释成执行。
void ApiApcObservation::Complete() noexcept
{
    identity_.Complete();
    CopyIdentity();
}
// 无输入输出参数；复制当前采集结果，不改写原 APC 参数或自行推定调用成功。
void ApiApcObservation::CopyIdentity() noexcept
{
    const auto& identity = identity_.fields(); // 本次线程句柄的身份、有效位及 QPC。
    using namespace Ksword::Evidence;
    fields_.flags = ApiApcRoutineAddress;
    if (identity.flags & ThreadTargetActor) {
        fields_.flags |= ApiApcActorIdentity;
    }
    if (identity.flags & ThreadTargetProcess) {
        fields_.flags |= ApiApcTargetIdentity;
    }
    if (identity.flags & ThreadTargetThread) {
        fields_.flags |= ApiApcThreadIdentity;
    }
    if (identity.flags & ThreadTargetStable) {
        fields_.flags |= ApiApcTargetStable;
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
