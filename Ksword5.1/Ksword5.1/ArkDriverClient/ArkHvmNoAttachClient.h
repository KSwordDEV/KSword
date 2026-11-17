#pragma once

#include "ArkDriverClient.h"

#include "../../../shared/driver/KswordArkHvmNoAttachIoctl.h"
#include "../../../shared/driver/KswordArkKernelNoAttachIoctl.h"

namespace ksword::ark
{
// 通信成功与驱动语义 NTSTATUS 独立保留。
struct HvmNoAttachResult
{
    IoResult io;
    KSWORD_ARK_HVM_NOATTACH_RESPONSE response{};
};

// QUERY 只读；OPEN 才能明确取得独占 HVM 生命周期。
// 非 QUERY 请求必须传持续持有的独立 DriverHandle；临时句柄关闭会撤销会话。
// 同 owner 的 QUERY 恢复也须使用原句柄；STEP/CONTINUE 另消费当前 stopId。
HvmNoAttachResult controlHvmNoAttach(KSWORD_ARK_HVM_NOATTACH_REQUEST request,
                                     DriverHandle *existingHandle = nullptr);
// 普通内核异常通道共享规范停止文档，使用自己的版本与 IOCTL。
HvmNoAttachResult controlKernelNoAttach(KSWORD_ARK_KERNEL_NOATTACH_REQUEST request,
                                        DriverHandle *existingHandle = nullptr);
} // namespace ksword::ark
