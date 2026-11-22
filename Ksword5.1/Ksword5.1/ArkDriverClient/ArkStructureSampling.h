#pragma once

#include "ArkDriverTypes.h"
#include "../../../shared/driver/KswordArkStructureSampleIoctl.h"
#include "../../../shared/usermode/StructureSampleProjection.h"

namespace ksword::ark
{
    // 一次身份限定的只读根对象快照：传输状态、真实回执和逐行投影保持同一归属。
    struct StructureSampleResult
    {
        IoResult io; // 设备访问及协议校验状态，不等同于现场读取全部成功。
        KSWORD_ARK_STRUCTURE_SAMPLE_RESPONSE response{}; // 固定协议，包含每字节有效位和采样区间。
        ks::structure_sample::Projection projection; // 与调用方精确符号布局同序的字段解释。
        bool unsupported = false; // 旧驱动或当前内核没有精确编译布局时明确置位。
        bool identityVerified = false; // 对象创建时间、所有权及运行内核 RSDS 均已核验。
    };
}
