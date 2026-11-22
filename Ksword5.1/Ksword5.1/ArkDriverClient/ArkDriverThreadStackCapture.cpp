#include "ArkDriverClient.h"
#include "../../../shared/usermode/LiveKernelThreadStack.h"

namespace ksword::ark
{
    // 独立端点读取原始保存栈回执，验证未通过时不发布其中任何地址。
    ThreadStackSnapshotResult DriverClient::snapshotThreadStack(const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST& request) const
    {
        ThreadStackSnapshotResult result; // 私有输出只由同次同步 IOCTL 写入。
        auto captured = request; // 传输接口所需的可写副本，不改变冻结输入。
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_SNAPSHOT_THREAD_STACK, &captured,
            static_cast<unsigned long>(sizeof(captured)), &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (!result.io.ok)
        {
            result.unsupported = result.io.win32Error == ERROR_INVALID_FUNCTION ||
                result.io.win32Error == ERROR_NOT_SUPPORTED;
            return result;
        }
        if (!ks::live_kernel_stack::ValidateSavedResponse(request, result.response, result.io.bytesReturned))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "Invalid saved-context stack response";
            return result;
        }
        result.io.ntStatus = result.response.capture.status;
        result.unsupported = result.response.capture.status == -1073741637L; // STATUS_NOT_SUPPORTED，不引入会重定义 Win32 宏的 ntstatus.h。
        result.io.message = result.response.capture.result == KSWORD_ARK_STACK_SNAPSHOT_COMPLETE ?
            "Saved target kernel stack unwound to a verified user machine-frame boundary" :
            result.response.capture.frameCount ? "Partial saved target kernel stack; inspect unwind stop" :
            "No saved target frames; inspect snapshot status and unwind stop";
        return result;
    }

    // 输入冻结的 PID/TID、两个创建时间和预算；返回同次目标采集或明确拒绝，不提供替代来源。
    ThreadStackCaptureResult DriverClient::captureThreadStack(const KSWORD_ARK_THREAD_STACK_REQUEST& request) const
    {
        ThreadStackCaptureResult result; // 私有回执覆盖整个同步请求，回调不能保存用户缓冲。
        auto captured = request; // 现有传输接口接收可写输入；副本不改变调用方冻结身份。
        result.io = deviceIoControl(IOCTL_KSWORD_ARK_CAPTURE_THREAD_STACK, &captured,
            static_cast<unsigned long>(sizeof(captured)), &result.response,
            static_cast<unsigned long>(sizeof(result.response)));
        if (!result.io.ok)
        {
            result.unsupported = result.io.win32Error == ERROR_INVALID_FUNCTION ||
                result.io.win32Error == ERROR_NOT_SUPPORTED;
            return result;
        }

        // 验证完整固定包、目标执行身份、有效帧、未用尾部和退休证明；不只看 NT_SUCCESS。
        if (!ks::live_kernel_stack::ValidateResponse(request, result.response, result.io.bytesReturned))
        {
            result.io.ok = false;
            result.io.win32Error = ERROR_INVALID_DATA;
            result.io.message = "Invalid target-context kernel-stack response";
            return result;
        }
        result.io.ntStatus = result.response.status;
        result.unsupported = result.response.result == KSWORD_ARK_THREAD_STACK_RESULT_LIFETIME_UNAVAILABLE;
        result.io.message = result.response.frameCount ?
            "Target APC-time kernel frames; original-stack completeness is unknown" :
            "No target kernel frames; inspect the explicit capture result and NTSTATUS";
        return result;
    }
}
