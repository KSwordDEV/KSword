#include "ArkHvmNoAttachClient.h"

namespace ksword::ark
{
// IOCTL 传输成功后传入回执、实际返回字节数和普通驱动标志 kernel。
// 回执格式符合所选后端协议时返回 true，调用方此时才可读取业务状态。
static constexpr bool validNoAttachResponse(const KSWORD_ARK_HVM_NOATTACH_RESPONSE &response,
                                            DWORD bytesReturned, bool kernel)
{
    // version 是所选后端的预期协议版本，maxStopReason 是该后端允许的最大停止原因。
    const auto version = kernel ? KSWORD_ARK_KERNEL_NOATTACH_VERSION : KSWORD_ARK_HVM_NOATTACH_VERSION;
    const auto maxStopReason = kernel ? KSWORD_ARK_HVM_NOATTACH_STOP_MEMORY_WATCH : KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT;
    // 普通后端的四个 DR 槽和四条内存观察记录共享八条回执容量。仅 STOPPED 要求停点令牌。
    return bytesReturned == sizeof(response) && response.version == version && response.size == sizeof(response) &&
           response.state <= KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING &&
           response.breakpointCount <= KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS &&
           (response.state != KSWORD_ARK_HVM_NOATTACH_STOPPED ||
            (response.sessionId != 0 && response.stopId != 0 &&
             response.stopReason >= KSWORD_ARK_HVM_NOATTACH_STOP_FETCH && response.stopReason <= maxStopReason));
}

// 编译期调用实际校验器。测试函数无外部输入，全部样本得到预期结果时返回 true。
static_assert([] {
    KSWORD_ARK_KERNEL_NOATTACH_RESPONSE response{}; // 普通后端回执样本。
    constexpr auto bytes = static_cast<DWORD>(sizeof(response)); // 完整响应长度。
    response.version = KSWORD_ARK_KERNEL_NOATTACH_VERSION;
    response.size = bytes;
    response.state = KSWORD_ARK_HVM_NOATTACH_STOPPED;
    response.sessionId = 1;
    response.stopId = 1;
    response.stopReason = KSWORD_ARK_HVM_NOATTACH_STOP_MEMORY_WATCH;
    response.breakpointCount = KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS;
    // 最大合法响应应通过，截断、超长和后端版本错配均应拒绝。
    if (!validNoAttachResponse(response, bytes, true) || validNoAttachResponse(response, bytes - 1, true) ||
        validNoAttachResponse(response, bytes + 1, true) || validNoAttachResponse(response, bytes, false))
        return false;

    // 每次只破坏一项字段，先检查容量越界，再检查未知停止原因。
    ++response.breakpointCount;
    if (validNoAttachResponse(response, bytes, true))
        return false;
    --response.breakpointCount;
    ++response.stopReason;
    if (validNoAttachResponse(response, bytes, true))
        return false;
    --response.stopReason;
    // 恢复已知停止原因后，验证缺少 stopId 的 STOPPED 仍被拒绝。
    response.stopId = 0;
    if (validNoAttachResponse(response, bytes, true))
        return false;

    // 恢复态可保留会话而无可执行停点。
    response.state = KSWORD_ARK_HVM_NOATTACH_RECOVERY_REQUIRED;
    response.stopReason = 0;
    if (!validNoAttachResponse(response, bytes, true))
        return false;
    // HVM 使用自己的版本和停止原因范围，拒绝普通驱动的内存观察原因。
    response.version = KSWORD_ARK_HVM_NOATTACH_VERSION;
    response.state = KSWORD_ARK_HVM_NOATTACH_STOPPED;
    response.stopId = 1;
    response.stopReason = KSWORD_ARK_HVM_NOATTACH_STOP_MEMORY_WATCH;
    if (validNoAttachResponse(response, bytes, false))
        return false;
    response.stopReason = KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT;
    return validNoAttachResponse(response, bytes, false);
}());

static HvmNoAttachResult controlNoAttach(KSWORD_ARK_HVM_NOATTACH_REQUEST request, DriverHandle *existingHandle, bool kernel)
{
    HvmNoAttachResult result;
    // 执行动作必须由调用方持续持有控制句柄，不能返回 ACK 后立刻触发 Cleanup。
    if (request.operation != KSWORD_ARK_HVM_NOATTACH_QUERY &&
        (existingHandle == nullptr || !existingHandle->isValid()))
    {
        result.io.win32Error = ERROR_INVALID_HANDLE;
        result.io.message = "A retained control handle is required";
        return result;
    }
    const auto version = kernel ? KSWORD_ARK_KERNEL_NOATTACH_VERSION : KSWORD_ARK_HVM_NOATTACH_VERSION;
    request.version = version;
    request.size = sizeof(request);
    DriverClient client;
    result.io = client.deviceIoControl(kernel ? IOCTL_KSWORD_ARK_KERNEL_NOATTACH : IOCTL_KSWORD_ARK_HVM_NOATTACH, &request, sizeof(request),
                                       &result.response, sizeof(result.response), existingHandle);
    // 格式校验失败没有可信回执，不能推断会话已释放。
    if (result.io.ok && !validNoAttachResponse(result.response, result.io.bytesReturned, kernel))
    {
        result.io.ok = false;
        result.io.win32Error = ERROR_INVALID_DATA;
        result.io.message = "Invalid HVM no-attach response";
        result.response = {};
    }
    if (result.io.ok)
        result.io.ntStatus = result.response.status;
    return result;
}
HvmNoAttachResult controlHvmNoAttach(KSWORD_ARK_HVM_NOATTACH_REQUEST request, DriverHandle *existingHandle)
{
    return controlNoAttach(request, existingHandle, false);
}
HvmNoAttachResult controlKernelNoAttach(KSWORD_ARK_KERNEL_NOATTACH_REQUEST request, DriverHandle *existingHandle)
{
    return controlNoAttach(request, existingHandle, true);
}
} // namespace ksword::ark
