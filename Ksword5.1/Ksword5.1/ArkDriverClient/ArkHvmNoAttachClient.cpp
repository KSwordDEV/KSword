#include "ArkHvmNoAttachClient.h"

namespace ksword::ark
{
HvmNoAttachResult controlHvmNoAttach(KSWORD_ARK_HVM_NOATTACH_REQUEST request, DriverHandle *existingHandle)
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
    request.version = KSWORD_ARK_HVM_NOATTACH_VERSION;
    request.size = sizeof(request);
    DriverClient client;
    result.io = client.deviceIoControl(IOCTL_KSWORD_ARK_HVM_NOATTACH, &request, sizeof(request),
                                       &result.response, sizeof(result.response), existingHandle);
    if (result.io.ok && (result.io.bytesReturned < sizeof(result.response) ||
                         result.response.version != KSWORD_ARK_HVM_NOATTACH_VERSION ||
                         result.response.size != sizeof(result.response) ||
                         result.response.state > KSWORD_ARK_HVM_NOATTACH_CONTEXT_PENDING ||
                         result.response.breakpointCount > KSWORD_ARK_HVM_NOATTACH_MAX_BREAKPOINTS ||
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
} // namespace ksword::ark
