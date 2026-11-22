#pragma once

#include <Windows.h>
#include "../driver/KswordArkThreadStackIoctl.h"
#include "../driver/KswordArkThreadStackSnapshotIoctl.h"

namespace ks::live_kernel_stack
{
    // 只验证新协议的运输/身份/帧不变式；不打开设备，不查询离线转储或 ETW，不回退到 R3。
    // 运输只允许由 ArkDriverClient 负责；此文件不接收设备句柄，也不发起设备请求。
    // 第二版请求 flags 必须为零；拒绝旧版延迟退休位和旧版响应。
    // LIFETIME_UNAVAILABLE 表示当前内核取消导出或本驱动尾跳证明不可用，不能显示为抓栈成功。
    // 所有已经入队的回执都必须带退休已验证标志；超时不等于实际取消，取消事实另有标志。
    [[nodiscard]] bool ValidateResponse(
        const KSWORD_ARK_THREAD_STACK_REQUEST& request,
        const KSWORD_ARK_THREAD_STACK_RESPONSE& response,
        DWORD bytesReturned) noexcept;

    // 独立核验保存上下文 wire；不能把请求者 DPC、APC 来源或仅元数据诊断当成目标帧。
    [[nodiscard]] bool ValidateSavedResponse(
        const KSWORD_ARK_THREAD_STACK_SNAPSHOT_REQUEST& request,
        const KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE& response,
        DWORD bytesReturned) noexcept;
}
