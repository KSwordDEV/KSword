#pragma once

// ============================================================
// ksword/file/file_handle_tools.h
// 命名空间：ks::file
// 作用：
// - 提供 FileDock 与句柄 Dock 共享的路径规范化、系统句柄枚举、
//   NtQueryObject/NtQuerySystemInformation 包装和文件占用扫描能力；
// - 本层只暴露 std 文本类型与 Win32 基础类型，不依赖 Qt 控件或界面字符串类型；
// - UI 层负责把结果转换为表格、颜色、按钮状态和进度条显示。
// ============================================================

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <winternl.h>

namespace ks::file
{
    // ProgressCallback 作用：
    // - 后端扫描过程中上报纯文本阶段与百分比；
    // - UI 可转接到 kPro/状态栏，命令行调用者也可忽略。
    using ProgressCallback = std::function<void(const std::string& stepText, float progressValue)>;

    // CancellationCallback 作用：
    // - 让耗时句柄扫描在 FileDock 关闭或用户取消时尽快结束；
    // - 返回 true 表示调用方不再需要本轮结果，后端只完成必要的资源释放。
    using CancellationCallback = std::function<bool()>;

    // HandleEnumMode 作用：
    // - 描述句柄快照构建使用的枚举路径；
    // - 与句柄 Dock 的 UI 下拉框保持语义一致，但不依赖 UI 枚举。
    enum class HandleEnumMode : int
    {
        UserSnapshot = 0,      // UserSnapshot：只采集 R3 系统句柄快照。
        DuplicateHandle = 1,   // DuplicateHandle：R3 快照后复制句柄并解析计数/对象名。
        KernelHandleTable = 2  // KernelHandleTable：在 R3 快照基础上叠加 R0 HandleTable 差异。
    };

    // HandleDiffStatus 作用：
    // - 描述 R3/R0 双源枚举中的差异状态；
    // - UI 层仅负责将其渲染为本地化文本。
    enum class HandleDiffStatus : int
    {
        NotCompared = 0,
        UserOnly,
        KernelOnly,
        Both
    };

    // NtApiSet 作用：
    // - 保存动态解析到的 ntdll 入口；
    // - 调用方可复用同一份函数指针，避免重复 GetProcAddress。
    struct NtApiSet
    {
        using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        using NtQueryObjectFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

        HMODULE ntdllModule = nullptr;                               // ntdllModule：ntdll 模块句柄，进程生命周期内有效。
        NtQuerySystemInformationFn querySystemInformation = nullptr; // querySystemInformation：NtQuerySystemInformation 地址。
        NtQueryObjectFn queryObject = nullptr;                       // queryObject：NtQueryObject 地址。

        // ready 作用：判断本次 Nt API 动态加载是否满足句柄功能最低要求。
        bool ready() const;
    };

    // RawSystemHandle 作用：
    // - 表示 NtQuerySystemInformation(SystemExtendedHandleInformation) 的安全解码结果；
    // - 只保留 UI 与扫描后端共用字段。
    struct RawSystemHandle
    {
        std::uint32_t processId = 0;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::uint64_t objectAddress = 0;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
    };

    // ObjectBasicInfo 作用：
    // - 封装 ObjectBasicInformation 中句柄/指针计数；
    // - 屏蔽 SDK 头文件里未公开字段布局差异。
    struct ObjectBasicInfo
    {
        std::uint32_t handleCount = 0;
        std::uint32_t pointerCount = 0;
    };

    // ObjectNameQueryResult 作用：
    // - 表示一次对象名解析的完整状态；
    // - 区分“查到了空名称”和“查询失败”。
    struct ObjectNameQueryResult
    {
        bool available = false;
        bool failed = false;
        bool usedFallback = false;
        std::wstring objectName;
    };

    // TargetPathPattern 作用：
    // - 表示文件占用扫描中的一个比较规则；
    // - displayPath 保留用户视角路径，normalizedPath 用于大小写无关匹配。
    struct TargetPathPattern
    {
        std::wstring displayPath;
        std::wstring normalizedPath;
        bool directoryMode = false;
    };

    // ReparsePointQueryResult 作用：
    // - 表示一次 FSCTL_GET_REPARSE_POINT 查询的完整结果；
    // - 既保留结构化字段，也保留降级展示所需的原始信息；
    // - 调用方可以在属性页、列表列文本或右键动作里复用同一份结果。
    struct ReparsePointQueryResult
    {
        bool pathOpened = false;                 // pathOpened：是否成功以“打开重解析点”的方式拿到句柄。
        bool querySucceeded = false;             // querySucceeded：FSCTL_GET_REPARSE_POINT 是否成功返回。
        bool isReparsePoint = false;             // isReparsePoint：目标是否确认为重解析点。
        bool isMicrosoftTag = false;             // isMicrosoftTag：tag 是否为 Microsoft 预定义 tag。
        bool isNameSurrogate = false;            // isNameSurrogate：是否为“命名代理”类重解析点。
        bool isRelative = false;                 // isRelative：仅对符号链接有意义，表示是否为相对链接。
        std::uint32_t tag = 0;                   // tag：重解析点 tag 的原始 32 位值。
        std::wstring tagName;                    // tagName：人类可读的 tag 名称，例如 IO_REPARSE_TAG_SYMLINK。
        std::wstring kindName;                   // kindName：用于 UI 展示的分类名，例如 SYMLINK/JUNCTION/MOUNT_POINT。
        std::wstring substituteName;            // substituteName：重解析缓冲中的 Substitute Name。
        std::wstring printName;                 // printName：重解析缓冲中的 Print Name。
        std::wstring resolvedTargetPath;        // resolvedTargetPath：尽量解析后的最终目标路径。
        std::wstring rawPayloadText;             // rawPayloadText：未能结构化解析时的原始文本或摘要。
        std::wstring rawHexPreview;             // rawHexPreview：原始缓冲的十六进制摘要，便于兜底排障。
        std::wstring errorText;                 // errorText：打开或查询失败原因；不阻塞 UI 展示。
        std::uint32_t win32Error = 0;            // win32Error：原始 GetLastError 结果。
    };

    // HandleSnapshotOptions 作用：
    // - 为句柄 Dock 后台刷新打包输入条件；
    // - 字段均为 std 类型，避免后台层读取 Qt 控件。
    struct HandleSnapshotOptions
    {
        bool hasPidFilter = false;
        std::uint32_t pidFilter = 0;
        std::wstring typeFilterText;
        bool resolveObjectName = true;
        int nameResolveBudget = 300;
        int basicInfoQueryBudget = -1; // < 0 表示不限制；避免只读场景对全系统句柄逐个查询计数。
        HandleEnumMode enumMode = HandleEnumMode::DuplicateHandle;
        std::unordered_map<std::uint16_t, std::string> typeNameCacheByIndex;
        std::unordered_map<std::uint16_t, std::string> typeNameMapFromObjectTab;
    };

    // HandleSnapshotRow 作用：
    // - 句柄 Dock 可直接渲染的一行后端数据；
    // - 不含颜色、表格项、图标等 UI 状态。
    struct HandleSnapshotRow
    {
        std::uint32_t processId = 0;
        std::uint64_t processCreationTime = 0;
        std::wstring processName;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::wstring typeName;
        std::wstring objectName;
        std::uint64_t objectAddress = 0;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::uint32_t handleCount = 0;
        std::uint32_t pointerCount = 0;
        bool basicInfoAvailable = false;
        bool objectNameAvailable = false;
        bool objectNameFailed = false;
        bool objectNameFromFallback = false;
        HandleEnumMode sourceMode = HandleEnumMode::UserSnapshot;
        HandleDiffStatus diffStatus = HandleDiffStatus::NotCompared;
        std::uint32_t decodeStatus = 0;
        std::uint32_t r0FieldFlags = 0;
        std::uint64_t r0DynDataCapabilityMask = 0;
        std::uint32_t epObjectTableOffset = 0xFFFFFFFFUL;
        std::uint32_t htHandleContentionEventOffset = 0xFFFFFFFFUL;
        std::uint32_t obDecodeShift = 0xFFFFFFFFUL;
        std::uint32_t obAttributesShift = 0xFFFFFFFFUL;
        std::uint32_t otNameOffset = 0xFFFFFFFFUL;
        std::uint32_t otIndexOffset = 0xFFFFFFFFUL;
    };

    // HandleSnapshotResult 作用：
    // - 聚合句柄 Dock 一轮后台刷新结果；
    // - 诊断文本保持为宽字符串，UI 可直接转换为界面字符串。
    struct HandleSnapshotResult
    {
        std::vector<HandleSnapshotRow> rows;
        std::vector<std::wstring> availableTypeList;
        std::unordered_map<std::uint16_t, std::string> updatedTypeNameCacheByIndex;
        std::size_t totalHandleCount = 0;
        std::size_t visibleHandleCount = 0;
        std::size_t basicInfoResolvedCount = 0;
        std::size_t resolvedNameCount = 0;
        std::size_t fallbackNameCount = 0;
        std::size_t objectTypeMappedCount = 0;
        std::size_t kernelHandleCount = 0;
        std::size_t userOnlyCount = 0;
        std::size_t kernelOnlyCount = 0;
        std::size_t bothCount = 0;
        std::uint64_t elapsedMs = 0;
        std::wstring diagnosticText;
    };

    // HandleUsageEntry 作用：
    // - 表示文件/目录占用扫描命中的一个来源；
    // - 可来自真实文件句柄、进程映像或模块快照。
    struct HandleUsageEntry
    {
        std::uint32_t processId = 0;
        std::uint64_t processCreationTime = 0; // R0 owner creation time, or GetProcessTimes fallback.
        std::uint64_t objectAddress = 0; // Captured handle object identity; comparison only.
        std::wstring processName;
        std::wstring processImagePath;
        std::uint64_t handleValue = 0;
        std::uint16_t typeIndex = 0;
        std::wstring typeName;
        std::wstring objectName;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::wstring matchedTargetPath;
        bool matchedByDirectoryRule = false;
        std::wstring matchRuleText;
        std::wstring enumerationSource;
    };

    // HandleUsageScanOptions 作用：
    // - 控制文件占用扫描策略；
    // - 默认先尝试 R0 HandleTable，仅当 R0 后端不可用时回退 R3 DuplicateHandle；
    // - R0 成功但没有目标命中属于有效空结果，不能再次全量扫描 R3 句柄表。
    struct HandleUsageScanOptions
    {
        bool tryKernelHandleTable = true;
        ProgressCallback progressCallback;
        CancellationCallback cancellationCallback;
    };

    // HandleUsageScanResult 作用：
    // - 聚合 FileDock 文件占用扫描的结果与统计；
    // - UI 层只负责展示 entries 和 diagnosticText。
    struct HandleUsageScanResult
    {
        std::vector<HandleUsageEntry> entries;
        std::size_t totalHandleCount = 0;
        std::size_t fileLikeHandleCount = 0;
        std::size_t matchedHandleCount = 0;
        std::size_t processImageMatchCount = 0;
        std::size_t loadedModuleMatchCount = 0;
        std::size_t kernelHandleMatchCount = 0;
        bool kernelHandleTableAttempted = false; // kernelHandleTableAttempted：本轮是否先调用了 R0 HandleTable 路径。
        bool kernelHandleTableUsed = false;      // kernelHandleTableUsed：R0 路径是否可用并作为文件句柄结果来源。
        bool r3HandleFallbackUsed = false;       // r3HandleFallbackUsed：R0 不可用后是否回落到 R3 DuplicateHandle。
        bool fileHandleScanIncomplete = false; // Timed out or exhausted bounded R3 query workers.
        std::uint64_t elapsedMs = 0;
        std::wstring diagnosticText;
    };

    // NormalizeNativePath 作用：统一 Windows 路径分隔符和长路径前缀。
    std::wstring NormalizeNativePath(const std::wstring& pathText);

    // NormalizePathForCompare 作用：生成大小写无关、无尾部分隔符的比较键。
    std::wstring NormalizePathForCompare(const std::wstring& pathText);

    // BuildNtPathEquivalent 作用：把 DOS/UNC 路径转换为 NT 设备路径。
    bool BuildNtPathEquivalent(const std::wstring& absolutePath, std::wstring& ntPathOut);

    // BuildTargetPathPatterns 作用：为一组用户路径生成 DOS/NT 双视角匹配规则。
    std::vector<TargetPathPattern> BuildTargetPathPatterns(const std::vector<std::wstring>& absolutePaths);

    // MatchTargetPath 作用：按精确文件或目录前缀规则匹配候选路径。
    bool MatchTargetPath(
        const std::wstring& normalizedCandidatePath,
        const std::vector<TargetPathPattern>& patternList,
        std::wstring& matchedTargetPathOut,
        bool& matchedByDirectoryRuleOut);

    // QueryNtApis 作用：动态加载 NtQuerySystemInformation 和 NtQueryObject。
    NtApiSet QueryNtApis();

    // QuerySystemHandles 作用：安全读取扩展系统句柄快照。
    bool QuerySystemHandles(
        const NtApiSet& apiSet,
        std::vector<RawSystemHandle>& recordsOut,
        std::wstring& diagnosticTextOut,
        const CancellationCallback& cancellationCallback = {});

    // QueryNtObjectText 作用：读取 NtQueryObject 返回的 UNICODE_STRING 文本。
    bool QueryNtObjectText(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        ULONG informationClass,
        std::wstring& textOut);

    // QueryReparsePointInfo 作用：
    // - 以 FILE_FLAG_OPEN_REPARSE_POINT 的方式打开文件或目录；
    // - 通过 FSCTL_GET_REPARSE_POINT 读取重解析缓冲；
    // - 对 SYMLINK / MOUNT_POINT / APPEXECLINK 生成可读结果，并保留原始降级信息。
    // 入参 absolutePath：
    // - 目标文件或目录的 DOS/UNC 绝对路径。
    // 入参 directoryHint：
    // - true 表示目标更可能是目录，可附加 FILE_FLAG_BACKUP_SEMANTICS 打开目录句柄。
    // 返回值：
    // - 结构体本身始终返回，调用方根据 pathOpened/querySucceeded/isReparsePoint 判断展示层级。
    ReparsePointQueryResult QueryReparsePointInfo(
        const std::wstring& absolutePath,
        bool directoryHint);

    // QueryObjectBasicInfo 作用：读取对象 HandleCount/PointerCount。
    bool QueryObjectBasicInfo(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        ObjectBasicInfo& basicInfoOut);

    // ResolveObjectNameText 作用：先走 NtQueryObject，再按对象类型走回退路径。
    ObjectNameQueryResult ResolveObjectNameText(
        const NtApiSet& apiSet,
        HANDLE objectHandle,
        const std::wstring& typeNameText);

    // DuplicateRemoteHandleToLocal 作用：把目标进程句柄复制到当前进程；调用方负责 CloseHandle。
    bool DuplicateRemoteHandleToLocal(
        HANDLE sourceProcessHandle,
        std::uint64_t handleValue,
        HANDLE& localHandleOut);

    // QueryFinalDosPathByHandle 作用：用 GetFinalPathNameByHandleW 读取标准 DOS 路径。
    bool QueryFinalDosPathByHandle(HANDLE objectHandle, std::wstring& pathOut);

    // OpenProcessForVerifiedAction 作用：
    // - 打开目标进程并核对扫描时记录的创建时间；
    // - 成功后调用方必须 CloseHandle，且持有期间 PID 不会被复用到新进程。
    bool OpenProcessForVerifiedAction(
        std::uint32_t processId,
        std::uint64_t expectedCreationTime,
        DWORD desiredAccess,
        HANDLE& processHandleOut,
        std::string& detailTextOut);

    // CloseRemoteHandle 作用：
    // - 校验进程创建时间和当前句柄对应文件路径；
    // - 暂停目标进程后再通过 DuplicateHandle(DUPLICATE_CLOSE_SOURCE) 关闭已验证句柄。
    bool CloseRemoteHandle(
        std::uint32_t processId,
        std::uint64_t handleValue,
        std::uint64_t expectedProcessCreationTime,
        const std::wstring& expectedTargetPath,
        bool expectedDirectoryMatch,
        std::string& detailTextOut);

    // CloseRemoteHandleByObjectIdentity 作用：
    // - 用进程创建时间 + 系统句柄快照中的对象地址复核任意类型句柄；
    // - 供 HandleDock 的单项/批量关闭使用，拒绝陈旧或无法验证的行。
    bool CloseRemoteHandleByObjectIdentity(
        std::uint32_t processId,
        std::uint64_t handleValue,
        std::uint64_t expectedProcessCreationTime,
        std::uint64_t expectedObjectAddress,
        std::string& detailTextOut);

    struct RemoteHandleCloseResult
    {
        bool success = false;
        bool suspendAttempted = false;
        bool closeAttempted = false;
        bool closeSucceeded = false;
        bool resumeAttempted = false;
        long suspendStatus = 0;
        long resumeStatus = 0;
        std::string detail;
    };
    // Preserves the close and resume outcomes separately for automation.
    RemoteHandleCloseResult CloseRemoteHandleByObjectIdentityDetailed(
        std::uint32_t processId,
        std::uint64_t handleValue,
        std::uint64_t expectedProcessCreationTime,
        std::uint64_t expectedObjectAddress);

    // BuildHandleSnapshot 作用：构建句柄 Dock 使用的完整后端快照。
    HandleSnapshotResult BuildHandleSnapshot(const HandleSnapshotOptions& options);

    // ScanHandleUsageByPaths 作用：按文件/目录路径扫描占用来源。
    HandleUsageScanResult ScanHandleUsageByPaths(
        const std::vector<std::wstring>& absolutePaths,
        const HandleUsageScanOptions& options = HandleUsageScanOptions{});
}
