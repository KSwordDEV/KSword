#pragma once

#include "ArkDriverTypes.h"
#include "../../../shared/driver/KswordArkThreadStackIoctl.h"
#include "../../../shared/driver/KswordArkThreadStackSnapshotIoctl.h"

namespace ksword::ark
{
    // Auto 优先读取真实保存上下文；APC 是显式诊断来源，不与新快照拼接。
    enum class ThreadStackCaptureMethod { Auto, Apc, SavedContext };

    struct ThreadStackSnapshotResult
    {
        IoResult io; // 实际独立 IOCTL 和完整 wire 验证结果。
        KSWORD_ARK_THREAD_STACK_SNAPSHOT_RESPONSE response{}; // 保留完整原始快照响应。
        bool unsupported = false; // 旧驱动或精确内核未支持，不表示目标没有栈。
    };

    // 一次同步目标上下文采集的回执；传输成功不代表取得帧，更不代表完整栈。
    struct ThreadStackCaptureResult
    {
        IoResult io; // 打开设备、真实 IOCTL 和固定协议校验结果。
        KSWORD_ARK_THREAD_STACK_RESPONSE response{}; // 唯一共享协议；不附加线索或其他来源的帧。
        bool unsupported = false; // 包括旧驱动、缺少合法取消导出或回调退休能力。
    };

    // 一行真实帧的显示投影；模块快照和本地符号只用于注释，不产生新帧。
    struct ThreadStackFrameSymbol
    {
        std::uint64_t address = 0; // 同一有效回执中的原始指令地址。
        std::uint64_t moduleBase = 0; // 前后模块快照一致时的加载基址。
        std::uint64_t displacement = 0; // 有符号时相对函数，否则相对模块。
        std::wstring moduleName; // 模块列表中的文件名；未知时保持空。
        std::wstring symbolName; // 与本地映像精确匹配的 PDB 符号；不是加载中 PE 的独立证明。
        bool localPdbMatched = false; // 只声明本地 PE/PDB GUID 与 Age 匹配。
    };

    // GUI 与 CLI 共用的持句柄采集；失败时不发布迟到帧或任何替代来源。
    struct VerifiedThreadStackCaptureResult
    {
        ThreadStackCaptureResult capture; // 已通过共享固定协议验证器的传输结果。
        ThreadStackSnapshotResult saved; // 使用保存上下文来源时保留独立原始 wire。
        bool usedSavedContext = false; // 此时 capture.response 是 saved.response.capture 的公共显示投影。
        bool identityVerified = false; // 请求前与冻结身份完全一致且仍存活。
        bool targetAliveAtReadback = false; // IOCTL 返回后原对象仍存活。
        bool deviceAccessAttempted = false; // 身份失败时必须为 false。
        std::vector<ThreadStackFrameSymbol> frames; // 与真实回执逐帧同序，绝不扫描栈寻找地址。
    };
}
