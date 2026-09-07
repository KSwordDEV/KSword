#pragma once

// F-05 采集状态归一层：把 ArkDriverClient 的 IoResult 与各协议自己的
// PARTIAL / TRUNCATED / UNSUPPORTED 状态位，翻译成统一的 CollectionOutcome。
//
// 为什么需要这一层：现在 unsupported 是 bool、denied 只体现在
// win32Error == ERROR_ACCESS_DENIED、timeout 没有独立表达，"未采集"和"正确的
// 空集合"在 UI 上都是一张空表。shared/driver 下 40 多个 *_STATUS_PARTIAL /
// _TRUNCATED / _UNSUPPORTED 宏各自命名，R3 没有归一口径。
//
// 本头文件是 inline-only 的：Qt 主程序、Light、CLI 和插件都直接编译
// ArkDriverClient，加一个 .cpp 会牵动五个工程文件；这里只做纯翻译，没有状态。

#include "ArkDriverTypes.h"

#include "../../../shared/evidence/EvidenceEnvelope.h"

#include <cstdint>
#include <string>
#include <utility>

namespace ksword::ark
{
    // DriverCallShape：调用方已知的、IoResult 表达不了的几件事。
    struct DriverCallShape
    {
        // 该协议返回了"本驱动不提供此能力"（各 Result 的 unsupported 位，
        // 或响应里的 *_STATUS_UNSUPPORTED_* 标志）。
        bool unsupported = false;
        // 响应带 PARTIAL / TRUNCATED 一类标志：调用成功但没覆盖请求范围。
        bool partial = false;
        // 该协议的 lastStatus/queryStatus 是"R0 侧这次操作的结果"（默认，绝大多数
        // IOCTL 都是这样填的）。个别协议把这个字段当纯信息位用（例如回带上一次
        // 无关操作的状态），那种协议必须显式置 false，否则会被判成采集失败。
        bool ntStatusIsAuthoritative = true;
    };

    // toCollectionOutcome：唯一的翻译入口。
    //
    // 判定顺序刻意如此：
    //   1. unsupported 优先于一切 —— 旧驱动把未知 IOCTL 报成 ERROR_INVALID_FUNCTION，
    //      那是"不支持"而不是"出错"，两者在 UI 和报告里语义完全不同。
    //   2. NTSTATUS 分流：DeviceIoControl 往返成功（io.ok = true）而 R0 侧操作失败，
    //      是最常见的一种失败形态 —— 全仓 40+ 处都是
    //      `result.io.ntStatus = response->lastStatus/queryStatus/status`。只看
    //      io.ok 会把 STATUS_ACCESS_DENIED 判成 Success，装进 envelope 后
    //      deriveConclusion(false) 直接给出"未发现差异"（F-05 明令禁止）。
    //   3. 失败按 Win32 错误码分流到 AccessDenied / Timeout / Error，原始码一律保留。
    //   4. 成功时 partial 决定 Success 还是 Partial —— 成功的空集合仍是 Success。
    //
    // 任何分支都不产出"正常"结论：结论由 EvidenceEnvelope::deriveConclusion 另行给出。
    inline Ksword::Evidence::CollectionOutcome toCollectionOutcome(
        const IoResult& io,
        const DriverCallShape& shape = DriverCallShape{})
    {
        using Ksword::Evidence::CollectionOutcome;
        using Ksword::Evidence::CollectionStatus;
        using Ksword::Evidence::OptionalU64;

        CollectionOutcome outcome;
        outcome.message = io.message;

        // NTSTATUS 优先作为原始码：驱动给了它就说明失败发生在 R0 侧。
        if (io.ntStatus != 0)
        {
            outcome.nativeCodeDomain = "NTSTATUS";
            outcome.nativeCode = OptionalU64::of(static_cast<std::uint64_t>(
                static_cast<std::uint32_t>(io.ntStatus)));
        }
        else if (io.win32Error != ERROR_SUCCESS)
        {
            outcome.nativeCodeDomain = "WIN32";
            outcome.nativeCode = OptionalU64::of(static_cast<std::uint64_t>(io.win32Error));
        }

        if (shape.unsupported ||
            io.win32Error == ERROR_INVALID_FUNCTION ||
            io.win32Error == ERROR_NOT_SUPPORTED)
        {
            outcome.status = CollectionStatus::Unsupported;
            return outcome;
        }

        // NTSTATUS 分流。严格按 NTSTATUS 的严重级来分，不写 `ntStatus < 0` ——
        // 那会把 NT_WARNING（0x8xxxxxxx，"有数据但不完整"）一并打成失败。
        //   severity 3 (0xC.......) = NT_ERROR       -> 失败
        //   severity 2 (0x8.......) = NT_WARNING     -> Partial（如 BUFFER_OVERFLOW）
        //   severity 1 (0x4.......) = NT_INFORMATION -> 不改变判定
        //   severity 0 (0x0.......) = NT_SUCCESS     -> 不改变判定（STATUS_TIMEOUT 除外）
        if (shape.ntStatusIsAuthoritative && io.ntStatus != 0)
        {
            const std::uint32_t status = static_cast<std::uint32_t>(io.ntStatus);
            switch (status)
            {
            case 0xC0000022UL:  // STATUS_ACCESS_DENIED
            case 0xC0000061UL:  // STATUS_PRIVILEGE_NOT_HELD
                outcome.status = CollectionStatus::AccessDenied;
                return outcome;
            case 0xC0000034UL:  // STATUS_OBJECT_NAME_NOT_FOUND
            case 0xC00000BBUL:  // STATUS_NOT_SUPPORTED
            case 0xC0000002UL:  // STATUS_NOT_IMPLEMENTED
            case 0xC0000010UL:  // STATUS_INVALID_DEVICE_REQUEST
                outcome.status = CollectionStatus::Unsupported;
                return outcome;
            case 0x00000102UL:  // STATUS_TIMEOUT：severity 是 0，但等待确实没等到
            case 0xC0000102UL:  // STATUS_FILE_CORRUPT_ERROR / 超时族的错误编码
                outcome.status = CollectionStatus::Timeout;
                return outcome;
            default:
                break;
            }

            const std::uint32_t severity = status >> 30U;
            if (severity == 3U)
            {
                outcome.status = CollectionStatus::Error;
                return outcome;
            }
            if (severity == 2U)
            {
                // 例如 STATUS_BUFFER_OVERFLOW (0x80000005)：拿到了数据，但没拿全。
                // 这是 Partial 而不是 Error —— 已取回的部分仍是真实观测。
                outcome.status = CollectionStatus::Partial;
                return outcome;
            }
            // NT_SUCCESS / NT_INFORMATION：继续走下面的常规判定。
        }

        if (!io.ok)
        {
            switch (io.win32Error)
            {
            case ERROR_ACCESS_DENIED:
            case ERROR_PRIVILEGE_NOT_HELD:
                outcome.status = CollectionStatus::AccessDenied;
                break;
            case ERROR_SEM_TIMEOUT:
            case WAIT_TIMEOUT:
            case ERROR_TIMEOUT:
                outcome.status = CollectionStatus::Timeout;
                break;
            default:
                outcome.status = CollectionStatus::Error;
                break;
            }
            return outcome;
        }

        outcome.status = shape.partial ? CollectionStatus::Partial : CollectionStatus::Success;
        return outcome;
    }

    // notCollected：调用根本没发起（无驱动、能力未启用、用户没点刷新）。
    // 它和"发起了但返回空"是两件事，不能共用一个空表格。
    inline Ksword::Evidence::CollectionOutcome driverNotCollected(std::string reason)
    {
        Ksword::Evidence::CollectionOutcome outcome;
        outcome.status = Ksword::Evidence::CollectionStatus::NotCollected;
        outcome.message = std::move(reason);
        return outcome;
    }

    // makeDriverSource：填 SourceRef 的统一入口，保证 sourceGroup 按"底层证据来源"
    // 而不是按 UI 包装取值 —— 否则同一个 collector 的两层包装会被 X-01 当成
    // 两个独立来源，虚增可信度。
    inline Ksword::Evidence::SourceRef makeDriverSource(std::string collectorId,
                                                        std::uint32_t collectorVersion,
                                                        std::string sourceGroup,
                                                        std::string ioctlName)
    {
        Ksword::Evidence::SourceRef source;
        source.collectorId = std::move(collectorId);
        source.collectorVersion = collectorVersion;
        source.sourceGroup = std::move(sourceGroup);
        source.origin = Ksword::Evidence::SourceOrigin::LiveKernel;
        source.dependsOn = "ArkDriverClient/" + ioctlName;
        return source;
    }
}
