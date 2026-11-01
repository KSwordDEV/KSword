#pragma once

// ============================================================
// hook/HookEngine.h
// 作用：
// 1) 提供 x64 Inline Hook 的基础安装与卸载能力；
// 2) 负责为目标函数构造 trampoline 并保存原始字节；
// 3) 供 HookTargets 层批量安装 WinAPI detour 时复用。
// ============================================================

#include "pch.h"

namespace apimon
{
    // The callback is scoped to the installing thread. Removal must remain
    // possible after cancellation; no cancellation callback is used there.
    using HookInstallStopCheck = bool(*)();
    bool HookInstallationCancelled();
    class ScopedHookInstallCancellation {
    public:
        explicit ScopedHookInstallCancellation(HookInstallStopCheck check);
        ~ScopedHookInstallCancellation();
    private:
        HookInstallStopCheck previous;
    };
    class InlineHookInstallBatch {
    public:
        InlineHookInstallBatch();
        ~InlineHookInstallBatch();
        bool commit();
        InlineHookInstallBatch(const InlineHookInstallBatch&) = delete;
        InlineHookInstallBatch& operator=(const InlineHookInstallBatch&) = delete;
    private:
        struct State;
        std::unique_ptr<State> state;
    };
    bool RestoreAllInlineHookEntries();
    bool HasActiveInlineHookEntries();
    // IsInlineHookInternalBypassActive 作用：
    // - 输入：无；
    // - 处理：查询当前线程是否处于 HookEngine 自身安装/卸载 inline hook 的内部区间；
    // - 返回：true 表示 HookedXXX wrapper 应直接调用原始 trampoline，避免安装阶段自触发递归。
    bool IsInlineHookInternalBypassActive();

    // Raw policy follows forwarders and jump stubs so aliases cannot bypass the ntdll exclusion.
    bool IsNativeRuntimeHookTarget(void* exportAddress);

    class ScopedInlineHookInternalBypass final
    {
    public:
        // ScopedInlineHookInternalBypass 构造：
        // - 输入：无；
        // - 处理：递增当前线程 HookEngine 内部 bypass 深度；
        // - 返回：无返回值。
        ScopedInlineHookInternalBypass();

        // ScopedInlineHookInternalBypass 析构：
        // - 输入：无；
        // - 处理：递减当前线程 HookEngine 内部 bypass 深度；
        // - 返回：无返回值。
        ~ScopedInlineHookInternalBypass();

        ScopedInlineHookInternalBypass(const ScopedInlineHookInternalBypass&) = delete;
        ScopedInlineHookInternalBypass& operator=(const ScopedInlineHookInternalBypass&) = delete;

    private:
        bool m_entered = false; // m_entered：记录构造是否成功进入 bypass，防止异常路径下错误递减。
    };

    enum class InlineHookInstallResult
    {
        Installed,
        RetryableFailure,
        PermanentFailure
    };

    struct InlineHookRecord
    {
        void* targetAddress = nullptr;                       // targetAddress：最终被打补丁的目标地址。
        void* detourAddress = nullptr;                       // detourAddress：Detour 函数地址。
        void* trampolineAddress = nullptr;                   // trampolineAddress：原始指令跳板地址。
        std::array<unsigned char, 32> originalBytes = {};   // originalBytes：被覆盖前的原始字节。
        std::size_t patchSize = 0;                          // patchSize：当前覆盖的前导字节数。
        void* sharedPatchContext = nullptr;
        bool sharedEntry = false;
        std::size_t failureOffset = 0;
        std::wstring lastFailure;
        bool installed = false;                             // installed：当前 Hook 是否已生效。
        bool removed = false;                               // Only an actually active entry can be reported removed.
        bool permanentlyDisabled = false;                   // permanentlyDisabled：是否因不可安全安装而永久禁用。
    };

    InlineHookInstallResult InstallInlineHook(
        const wchar_t* moduleName,
        const char* procName,
        void* detourAddress,
        InlineHookRecord* hookOut,
        void** originalOut,
        std::wstring* errorTextOut);

    InlineHookInstallResult InstallInlineHookAtAddress(void* address, void* detour,
        InlineHookRecord* hookOut, void** originalOut, std::wstring* errorTextOut);

    bool UninstallInlineHook(InlineHookRecord* hookValue);
}
