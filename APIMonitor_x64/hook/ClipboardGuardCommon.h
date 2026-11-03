#pragma once

// ============================================================
// hook/ClipboardGuardCommon.h
// 作用：
// 1) 提供剪贴板保护功能里 Win32 平导出 hook 和 OLE 虚表 hook 共用的部分；
// 2) 集中策略热更新镜像、事件详情拼接、调用方身份解析、调用栈捕获三块逻辑；
// 3) 不涉及任何 inline hook 安装/卸载，纯粹是"判定+上报"辅助层。
// ============================================================

#include "pch.h"
#include "../core/MonitorConfig.h"

namespace apimon
{
    // ClipboardOperationKind：
    // - 作用：区分一次剪贴板调用属于读/写/枚举三个方向之一；
    // - 调用：用于挑选对应的策略动作，以及事件详情里的 op= 字段。
    enum class ClipboardOperationKind : std::uint32_t
    {
        Read = 0,   // GetClipboardData / IDataObject::GetData。
        Write = 1,  // SetClipboardData / OleSetClipboard。
        Enum = 2    // EnumClipboardFormats/IsClipboardFormatAvailable/GetPriorityClipboardFormat/QueryGetData/EnumFormatEtc。
    };

    // RefreshClipboardPolicyFromConfig 作用：
    // - 输入：configValue 是刚从 INI 重新加载出来的完整会话配置；
    // - 处理：只把剪贴板读/写/枚举三个动作字段镜像进一组独立的原子变量；
    // - 原因：g_activeConfig（ActiveConfig()/ReplaceActiveConfig()）只在会话建立/重建时
    //   整体替换一次，中途从工作线程高频重新赋值会在 hook body 并发读取
    //   std::wstring/std::vector 成员时出现撕裂读，属于真实的用后即崩风险；
    //   剪贴板这三个动作字段是纯值类型，可以安全地用原子变量独立热更新，
    //   不需要、也不应该改动 g_activeConfig 本身的同步方式。
    // - 返回：无返回值，可从任意线程调用。
    void RefreshClipboardPolicyFromConfig(const MonitorConfig& configValue);

    // ResolveClipboardAction 作用：
    // - 输入：kind 指明这次调用的方向；
    // - 处理：读取上面原子镜像里对应方向的当前策略；
    // - 返回：ClipboardPolicyAction，调用方据此决定是否跳过原函数。
    ClipboardPolicyAction ResolveClipboardAction(ClipboardOperationKind kind);

    // NextClipboardEventSequence 作用：
    // - 处理：进程内单调自增的事件序号，用于把事件表里的一行和调用栈持久化文件
    //   里的对应记录关联起来；
    // - 返回：本次调用应使用的序号。
    std::uint64_t NextClipboardEventSequence();

    // ReportClipboardEvent 作用：
    // - 输入：kind 为方向；moduleName/apiName 标识触发事件的 API；formatValue 为 CF_* 常量，
    //   不适用时传 0；dataHandleForSizeHash 仅在"读且已放行"时传入 GetClipboardData
    //   的返回句柄用于取 size/hash，其余场景一律传 nullptr（避免误用 GlobalLock/Size
    //   操作不属于 HGLOBAL 的句柄，比如位图/元文件句柄）；actionTaken 是实际生效的动作。
    // - 处理：解析 Owner 进程、当前会话号、当前进程完整性级别，拼出结构化 detail 文本，
    //   捕获调用方调用栈（仅模块+偏移，不接 DbgHelp/PDB）并持久化，最后通过命名管道
    //   把事件发给 UI。
    // - 返回：无返回值；本函数内部任何一步失败都只降级输出、不抛异常、不影响调用方继续执行。
    void ReportClipboardEvent(
        ClipboardOperationKind kind,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        UINT formatValue,
        HANDLE dataHandleForSizeHash,
        ClipboardPolicyAction actionTaken,
        bool hasReturnValue = false, std::uint64_t returnBits = 0,
        bool hasDuration = false, std::uint64_t duration100ns = 0,
        bool statusKnown = true, std::int32_t statusCode = 0);
}
