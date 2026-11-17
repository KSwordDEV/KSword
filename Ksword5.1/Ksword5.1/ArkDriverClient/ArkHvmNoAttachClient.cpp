#include "ArkHvmNoAttachClient.h"

namespace ksword::ark
{
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
    if (result.io.ok && (result.io.bytesReturned < sizeof(result.response) ||
                         result.response.version != version ||
                         result.response.size != sizeof(result.response) ||
                         result.response.state > KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING ||
                         result.response.breakpointCount > (kernel ? 4UL : KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS) ||
                         (result.response.state == KSWORD_ARK_HVM_NOATTACH_STOPPED &&
                          (result.response.sessionId == 0 || result.response.stopId == 0 ||
                           result.response.stopReason < KSWORD_ARK_HVM_NOATTACH_STOP_FETCH ||
                           result.response.stopReason > KSWORD_ARK_HVM_NOATTACH_STOP_CONTEXT))))
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
