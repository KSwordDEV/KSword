#pragma once

#include "ArkDriverCapabilities.h"
#include "ArkDriverTypes.h"

#include <functional>

namespace ksword::ark
{
    struct BugcheckVerdictBitmap
    {
        std::uint32_t language = 0;
        std::uint32_t classification = 0;
        std::uint32_t width = 0;
        std::uint32_t height = 0;
        std::uint32_t stride = 0;
        std::vector<std::uint8_t> bgraPixels;
    };

    // Format the immutable R0 evidence packet as a stable diagnostic block.
    // UI layers may prepend localized context, but should not reinterpret a
    // present certificate table as a successful trust-chain validation.
    std::string formatImageSignatureEvidence(const ImageSignatureQueryResult& result);

    // DriverClient centralizes all KswordARK control-device access. Docks should
    // call this class instead of opening \\.\KswordARKLog or invoking
    // DeviceIoControl directly.
    class DriverClient
    {
    public:
        // setR0UnavailableHandler：
        // - 为整个 R0 客户端注册一个“控制设备不存在”的 UI 通知入口；
        // - handler 可能从工作线程调用，接收方必须自行切回 UI 线程；
        // - 仅用于驱动未启用，不把旧驱动/业务 IOCTL 失败误报为“请启用 R0”。
        using R0UnavailableHandler = std::function<void(unsigned long win32Error)>;
        static void setR0UnavailableHandler(R0UnavailableHandler handler);

        // setR0PermissionRequiredHandler：
        // - 统一通知“驱动已存在，但当前用户无权执行该 R0 IOCTL”的情况；
        // - handler 可能从工作线程调用，接收方必须自行切回 UI 线程。
        using R0PermissionRequiredHandler = std::function<void(unsigned long win32Error)>;
        static void setR0PermissionRequiredHandler(R0PermissionRequiredHandler handler);

        // clearR0NotificationHandlersAndWait：
        // - 同时停止两类 R0 全局通知，并等待已经复制到工作线程的回调执行完毕；
        // - 主窗口析构必须先调用本函数，保证返回后不再有回调向该窗口投递事件；
        // - 不得从上述 handler 内部调用，否则调用线程会等待自身结束。
        static void clearR0NotificationHandlersAndWait();

        DriverClient() = default;

        // Best-effort branding upload for the VMware-only bugcheck panel.
        // The driver silently discards a valid packet when that feature is inactive.
        IoResult setBugcheckBitmap(
            std::uint32_t width,
            std::uint32_t height,
            std::uint32_t stride,
            std::uint32_t brandColorRgb,
            const std::vector<std::uint8_t>& bgraPixels) const;

        // Install the complete bilingual BGP verdict-card resource set.
        IoResult setBugcheckVerdictResources(
            const std::vector<BugcheckVerdictBitmap>& resources) const;
        // 根据设置文件或用户本次明确操作，按需安装并查询 BGP 蓝屏诊断回调。
        BugcheckDiagnosticsResult configureBugcheckDiagnostics(
            unsigned long action) const;

        // Confirmation-gated control/status path for the one-shot KeBugCheckEx delay guard.
        BugcheckGuardResult configureBugcheckGuard(
            unsigned long action,
            unsigned long delaySeconds = 0UL,
            bool uiConfirmed = false,
            bool tryIgnoreError = false,
            DriverHandle* existingHandle = nullptr) const;
        // Open one synchronous control handle. The returned handle owns CloseHandle.
        DriverHandle open(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Open a synchronous control handle without invoking the global R0 UI
        // notification handlers.  Passive polling paths use this to determine
        // whether the driver is ready before issuing an optional IOCTL.
        DriverHandle openSilently(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Open one overlapped control handle for wait-style callback receivers.
        DriverHandle openOverlapped(unsigned long desiredAccess = GENERIC_READ | GENERIC_WRITE) const;

        // Low-level synchronous IOCTL helper used by narrow advanced UI paths.
        IoResult deviceIoControl(
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            DriverHandle* existingHandle = nullptr) const;

        // Low-level overlapped IOCTL helper for callback event waiting.
        AsyncIoResult deviceIoControlAsync(
            DriverHandle& handle,
            unsigned long ioControlCode,
            void* inputBuffer,
            unsigned long inputBytes,
            void* outputBuffer,
            unsigned long outputBytes,
            OVERLAPPED* overlapped) const;

        IoResult terminateProcess(
            std::uint32_t processId,
            long exitStatus,
            std::uint64_t expectedCreateTime100ns = 0) const;
        IoResult terminateProcess(
            DriverHandle& handle,
            std::uint32_t processId,
            long exitStatus,
            std::uint64_t expectedCreateTime100ns = 0) const;
        IoResult terminateThread(std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult terminateThread(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, long exitStatus) const;
        IoResult setThreadSuspended(std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult setThreadSuspended(DriverHandle& handle, std::uint32_t threadId, std::uint32_t processId, bool suspended) const;
        IoResult controlDriverThread(std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult controlDriverThread(DriverHandle& handle, std::uint32_t threadId, std::uint64_t expectedStartAddress, std::uint64_t expectedCreateTime100ns, unsigned long action, unsigned long terminateMethod, bool uiConfirmed) const;
        IoResult experimentalReturnToFirmware() const;
        IoResult suspendProcess(std::uint32_t processId) const;
        IoResult setProcessProtection(std::uint32_t processId, std::uint8_t protectionLevel) const;
        ProcessVisibilityResult setProcessVisibility(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        // setProcessIntegrity：
        // - 输入：PID 和 S-1-16-* mandatory label RID；
        // - 处理：封装 R0 进程完整性 IOCTL；驱动端先走 Zw* token API，
        //   必要时由 R0 DynData/PDB 私有 Token 字段兜底；
        // - 返回：ProcessIntegrityResult；io.ok 与 status/lastStatus 分别表示通信和语义结果。
        ProcessIntegrityResult setProcessIntegrity(std::uint32_t processId, unsigned long integrityRid) const;
        // queryProcessTokenPrivileges：通过 R0 查询目标主令牌的完整 LUID/属性列表。
        ProcessTokenPrivilegeResult queryProcessTokenPrivileges(
            std::uint32_t processId,
            std::uint64_t expectedCreateTime100ns = 0) const;
        // adjustProcessTokenPrivileges：通过 R0 按顺序批量调整目标主令牌特权。
        ProcessTokenPrivilegeResult adjustProcessTokenPrivileges(
            std::uint32_t processId,
            std::uint64_t expectedCreateTime100ns,
            const std::vector<ProcessTokenPrivilegeEntry>& edits,
            bool allowRemove) const;

        // legacy compatibility entry points for old query/adjust IOCTLs.
        ProcessTokenPrivilegeQueryResult queryProcessTokenPrivileges(
            std::uint32_t processId,
            DriverHandle* existingHandle) const;
        ProcessTokenPrivilegeAdjustResult adjustProcessTokenPrivilege(
            std::uint32_t processId,
            std::uint32_t luidLowPart,
            std::int32_t luidHighPart,
            bool enabled,
            DriverHandle* existingHandle = nullptr) const;
        ProcessSpecialFlagsResult setProcessSpecialFlags(
            std::uint32_t processId,
            unsigned long action,
            unsigned long flags = 0UL,
            std::uint64_t expectedCreateTime100ns = 0) const;
        ProcessDkomResult dkomProcess(std::uint32_t processId, unsigned long action, unsigned long flags = 0UL) const;
        ProcessInjectResult injectProcessDll(
            std::uint32_t processId,
            const std::wstring& dllPath,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED | KSWORD_ARK_PROCESS_INJECT_FLAG_WAIT_THREAD) const;
        ProcessInjectResult injectProcessShellcode(
            std::uint32_t processId,
            const std::vector<std::uint8_t>& shellcode,
            unsigned long flags = KSWORD_ARK_PROCESS_INJECT_FLAG_UI_CONFIRMED) const;

        ProcessEnumResult enumerateProcesses(unsigned long flags) const;
        ProcessEnumResult enumerateProcesses(unsigned long flags, DriverHandle* existingHandle) const;
        ThreadEnumResult enumerateThreads(unsigned long flags, std::uint32_t processId = 0) const;
        WorkQueueEnumResult enumerateWorkQueues(
            unsigned long flags = KSWORD_ARK_WORK_QUEUE_FLAG_INCLUDE_ALL,
            unsigned long maxEntries = KSWORD_ARK_WORK_QUEUE_DEFAULT_MAX_ENTRIES) const;
        HandleEnumResult enumerateProcessHandles(std::uint32_t processId, unsigned long flags = KSWORD_ARK_ENUM_HANDLE_FLAG_INCLUDE_ALL) const;
        HandleObjectQueryResult queryHandleObject(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_QUERY_OBJECT_FLAG_INCLUDE_ALL, unsigned long requestedAccess = 0) const;
        AlpcPortQueryResult queryAlpcPort(std::uint32_t processId, std::uint64_t handleValue, unsigned long flags = KSWORD_ARK_ALPC_QUERY_FLAG_INCLUDE_ALL) const;
        ProcessSectionQueryResult queryProcessSection(std::uint32_t processId, unsigned long flags = KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        FileSectionMappingsQueryResult queryFileSectionMappings(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL, unsigned long maxMappings = KSWORD_ARK_SECTION_MAPPING_LIMIT_DEFAULT) const;
        VirtualMemoryQueryResult queryVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryReadResult readVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            std::uint32_t bytesToRead,
            unsigned long flags = KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE,
            DriverHandle* existingHandle = nullptr) const;
        VirtualMemoryWriteResult writeVirtualMemory(
            std::uint32_t processId,
            std::uint64_t baseAddress,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // readPhysicalMemory：
        // - 输入：physicalAddress 为起始物理地址，上限 0x000FFFFFFFFFFFFF 且区间不得回绕；
        //   bytesToRead 为本次读取长度，上限 KSWORD_ARK_MEMORY_PHYSICAL_READ_MAX_BYTES(64KB)；
        //   flags 必须为 0，驱动对任何非 0 位直接返回 STATUS_INVALID_PARAMETER，
        //   本函数会在发出 IOCTL 之前本地拒绝；existingHandle 可复用已打开的控制句柄。
        // - 处理：按“驱动认定的响应头长度 + bytesToRead”分配输出缓冲，发出
        //   IOCTL_KSWORD_ARK_READ_PHYSICAL_MEMORY，再从 data 成员的真实偏移解析负载。
        //   驱动计算可用空间用的是 sizeof-sizeof(data)，写负载却用 offsetof(data)，
        //   两个数字不相等，因此分配长度和解析偏移必须分别取值，不能互相替代。
        // - 返回：PhysicalMemoryReadResult；io.ok 只表示 IOCTL 通信成功，
        //   数据是否有效要看 readStatus 与 bytesRead。
        PhysicalMemoryReadResult readPhysicalMemory(
            std::uint64_t physicalAddress,
            std::uint32_t bytesToRead,
            unsigned long flags = 0UL,
            DriverHandle* existingHandle = nullptr) const;
        // writePhysicalMemory：
        // - 输入：physicalAddress 为起始物理地址，上限 0x000FFFFFFFFFFFFF 且区间不得回绕；
        //   bytes 为待写入负载，长度必须非 0 且不超过
        //   KSWORD_ARK_MEMORY_PHYSICAL_WRITE_MAX_BYTES(4KB)；flags 只允许
        //   KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED 与 KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE
        //   的组合，其余位由本函数本地拒绝；existingHandle 可复用已打开的控制句柄。
        // - 处理：按“物理写请求头 + bytes.size()”分配输入缓冲，负载通过 request->data
        //   成员拷贝，发出 IOCTL_KSWORD_ARK_WRITE_PHYSICAL_MEMORY；R0 侧先
        //   MmMapIoSpaceEx 映射目标页，再在 __try 内拷贝，映射与拷贝分别有独立状态。
        // - 返回：PhysicalMemoryWriteResult；io.ok 只表示 IOCTL 通信成功。
        //   特别注意：未带 KSWORD_ARK_PHYSICAL_WRITE_FLAG_FORCE 时驱动不会写入任何字节，
        //   而是返回 writeStatus=KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_FORCE_REQUIRED
        //   并且 io.ok 仍为 true，调用方必须检查 writeStatus 才能判断是否真的写成功。
        PhysicalMemoryWriteResult writePhysicalMemory(
            std::uint64_t physicalAddress,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags = KSWORD_ARK_PHYSICAL_WRITE_FLAG_UI_CONFIRMED,
            DriverHandle* existingHandle = nullptr) const;
        // queryKernelMemoryEvidence：
        // - 输入：只读采集 flags、行数/字节预算和可选地址半开区间。
        // - 处理：封装 IOCTL_KSWORD_ARK_SCAN_KERNEL_MEMORY_EVIDENCE，解析变长 evidence rows。
        // - 返回：KernelMemoryEvidenceResult；旧驱动/能力缺失时 unsupported=true，调用方显示 graceful message。
        KernelMemoryEvidenceResult queryKernelMemoryEvidence(
            unsigned long flags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_ALL,
            unsigned long maxRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_ROWS,
            std::uint64_t startAddress = 0,
            std::uint64_t endAddress = 0,
            std::uint64_t maxBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_MAX_BYTES,
            unsigned long maxBigPoolRows = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_BIGPOOL_ROWS,
            unsigned long sampleBytes = KSWORD_ARK_MEMORY_EVIDENCE_DEFAULT_SAMPLE_BYTES) const;
        FileInfoQueryResult queryFileInfo(const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        FileInfoQueryResult queryFileInfo(DriverHandle& handle, const std::wstring& ntPath, unsigned long flags = KSWORD_ARK_QUERY_FILE_INFO_FLAG_INCLUDE_ALL) const;
        // enumerateDirectory：分页调用 R0 ZwQueryDirectoryFile，并合并为有明确总行预算的只读快照。
        DirectoryEnumerationResult enumerateDirectory(
            const std::wstring& ntPath,
            unsigned long maxEntries = 16384UL) const;
        // enumerateDirectoryByIrp：
        // - 输入：驱动可打开的 NT 目录路径、目标栈层与 R3 总行预算；
        // - 处理：R0 自建 IRP_MJ_DIRECTORY_CONTROL 直发指定层，分页合并结果；
        // - 返回：行格式与 enumerateDirectory 一致，另含实际生效层与接收驱动名，
        //   调用方据此判断本次是否真的绕过了过滤层。
        FileIrpDirectoryResult enumerateDirectoryByIrp(
            const std::wstring& ntPath,
            unsigned long targetLayer = KSWORD_ARK_FILE_IRP_LAYER_BASE_FS,
            unsigned long maxEntries = 16384UL) const;
        // submitFileIrp：
        // - 输入：完整的 IRP 构造参数；写语义与危险 major 必须由调用方置
        //   uiConfirmed/allowDangerous，客户端只负责补齐确认令牌；
        // - 处理：一次 IOCTL 完成"打开 → 发送目标 major → 收尾"；
        // - 返回：各阶段 NTSTATUS、目标设备栈信息与输出数据。
        FileIrpSubmitResult submitFileIrp(
            const FileIrpSubmitRequestParams& params) const;
        // Read Authenticode PE certificate-table structure and cached Code
        // Integrity state through the driver. No WinTrust API is used.
        ImageSignatureQueryResult queryImageSignature(
            const std::wstring& ntPath,
            std::uint64_t expectedModuleBase = 0,
            unsigned long flags = KSWORD_ARK_IMAGE_SIGNATURE_QUERY_FLAG_DEFAULT) const;
        // setFileIntegrity：
        // - 输入：驱动可打开的 NT 路径、目录标志和 S-1-16-* mandatory label RID；
        // - 处理：封装 R0 文件 Mandatory Label IOCTL，驱动端只调用 ZwCreateFile/ZwSetSecurityObject；
        // - 返回：FileIntegrityResult；io.ok 与 status/lastStatus 分别表示通信和语义结果。
        FileIntegrityResult setFileIntegrity(const std::wstring& ntPath, bool isDirectory, unsigned long integrityRid) const;
        IoResult controlFileMonitor(unsigned long action, unsigned long operationMask = KSWORD_ARK_FILE_MONITOR_OPERATION_ALL, unsigned long processId = 0UL, unsigned long flags = 0UL) const;
        FileMonitorStatusResult queryFileMonitorStatus() const;
        FileMonitorDrainResult drainFileMonitor(unsigned long maxEvents = 128UL, unsigned long flags = 0UL) const;
        // controlDebugOutput：注册、注销或查询 DbgSetDebugPrintCallback 捕获状态。
        DebugOutputControlResult controlDebugOutput(unsigned long action) const;
        DebugOutputControlResult controlDebugOutput(DriverHandle& handle, unsigned long action) const;
        // drainDebugOutput：使用单调游标增量读取 R0 固定环形缓冲区。
        DebugOutputDrainResult drainDebugOutput(std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        DebugOutputDrainResult drainDebugOutput(DriverHandle& handle, std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_DEBUG_OUTPUT_DEFAULT_DRAIN_RECORDS) const;
        // callback monitor：全局控制状态，读取端使用各自 afterSequence 游标。
        CallbackMonitorStatusResult controlCallbackMonitor(unsigned long action, unsigned long categoryMask) const;
        CallbackMonitorStatusResult controlCallbackMonitor(DriverHandle& handle, unsigned long action, unsigned long categoryMask) const;
        CallbackMonitorStatusResult queryCallbackMonitorStatus() const;
        CallbackMonitorStatusResult queryCallbackMonitorStatus(DriverHandle& handle) const;
        CallbackMonitorReadResult readCallbackMonitor(std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS) const;
        CallbackMonitorReadResult readCallbackMonitor(DriverHandle& handle, std::uint64_t afterSequence, unsigned long maxRecords = KSWORD_ARK_CALLBACK_MONITOR_DEFAULT_READ_RECORDS) const;
        RegistryReadResult readRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, unsigned long maxDataBytes = KSWORD_ARK_REGISTRY_DATA_MAX_BYTES) const;
        RegistryEnumResult enumerateRegistryKey(const std::wstring& kernelKeyPath, unsigned long flags = KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS | KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES) const;
        RegistryOperationResult setRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName, std::uint32_t valueType, const std::vector<std::uint8_t>& data) const;
        RegistryOperationResult deleteRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& valueName) const;
        RegistryOperationResult createRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult deleteRegistryKey(const std::wstring& kernelKeyPath) const;
        RegistryOperationResult renameRegistryValue(const std::wstring& kernelKeyPath, const std::wstring& oldValueName, const std::wstring& newValueName) const;
        RegistryOperationResult renameRegistryKey(const std::wstring& kernelKeyPath, const std::wstring& newKeyName) const;
        IoResult deletePath(const std::wstring& ntPath, bool isDirectory) const;
        IoResult deletePath(DriverHandle& handle, const std::wstring& ntPath, bool isDirectory) const;
        // deletePathEx：
        // - 输入：驱动可打开的 NT 路径、目录标志、是否在 R0 内递归展开、单点失败是否继续，
        //   backend 显式选择底层 Zw*、IRP 或 POSIX 删除；
        // - 处理：封装带响应包的删除 IOCTL；recursive=true 时目录树完全由 R0 后序删除，
        //   不再依赖 R3 枚举，因此目录 DACL 拒绝列举也能删干净；
        // - 返回：DeletePathResult；unsupported=true 表示旧驱动，调用方需回退 R3 展开。
        DeletePathResult deletePathEx(
            const std::wstring& ntPath,
            bool isDirectory,
            bool recursive,
            bool continueOnError = true,
            FileDeleteBackend backend = FileDeleteBackend::Native) const;
        DeletePathResult deletePathEx(
            DriverHandle& handle,
            const std::wstring& ntPath,
            bool isDirectory,
            bool recursive,
            bool continueOnError = true,
            FileDeleteBackend backend = FileDeleteBackend::Native) const;

        SsdtEnumResult enumerateSsdt(unsigned long flags) const;
        SsdtEnumResult enumerateShadowSsdt(unsigned long flags = KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED) const;
        // queryProcessCrossView：
        // - 输入：进程 cross-view 采集 flags、PID 半开/闭合过滤和节点预算。
        // - 处理：只通过 ArkDriverClient 调用 R0，不让 Dock 直接 DeviceIoControl。
        // - existingHandle：可复用已打开的设备句柄，批量只读查询时避免重复打开驱动。
        // - 返回：ProcessCrossViewResult，包含 source matrix、anomaly flags 和 DynData 缺口。
        ProcessCrossViewResult queryProcessCrossView(
            unsigned long flags = KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t startPid = 0,
            std::uint32_t endPid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES,
            DriverHandle* existingHandle = nullptr) const;
        // queryThreadCrossView：
        // - 输入：线程 cross-view 采集 flags、可选 PID/TID 过滤和节点预算。
        // - 处理：解析 ETHREAD/KTHREAD 来源矩阵，只读展示线程 DKOM 证据。
        // - 返回：ThreadCrossViewResult；不返回可用于写操作的对象凭据。
        ThreadCrossViewResult queryThreadCrossView(
            unsigned long flags = KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_ALL,
            std::uint32_t processId = 0,
            std::uint32_t startTid = 0,
            std::uint32_t endTid = 0,
            unsigned long maxNodes = KSWORD_ARK_CROSSVIEW_DEFAULT_MAX_NODES) const;
        // query*RuntimeDetail：
        // - 输入：PID/TID 和只读字段组 flags。
        // - 处理：封装 R0 PDB/DynData detail IOCTL，失败时返回 unsupported/unavailable。
        // - existingHandle：可选共享设备句柄；为空时保持原有按调用打开行为。
        // - 返回：固定响应结构；不把对象地址作为后续写操作凭据。
        ProcessRuntimeDetailResult queryProcessRuntimeDetail(
            std::uint32_t processId,
            unsigned long flags = KSWORD_ARK_PROCESS_DETAIL_FLAG_INCLUDE_ALL,
            DriverHandle* existingHandle = nullptr) const;
        ThreadRuntimeDetailResult queryThreadRuntimeDetail(std::uint32_t threadId, std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_THREAD_DETAIL_FLAG_INCLUDE_ALL) const;
        // query*RuntimeFieldSamples：
        // - 输入：deep PDB catalog 选出的字段 offset/size 列表。
        // - 处理：封装只读小字段采样 IOCTL，R0 不接受对象地址。
        // - 返回：每字段状态、字节样本和 U64 摘要，旧驱动返回 unsupported。
        RuntimeFieldSampleResult queryProcessRuntimeFieldSamples(std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        RuntimeFieldSampleResult queryThreadRuntimeFieldSamples(std::uint32_t threadId, std::uint32_t processId, const std::vector<RuntimeFieldSampleRequestItem>& items, unsigned long flags = 0UL) const;
        KernelInlineHookScanResult scanInlineHooks(unsigned long flags = 0UL, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // scanKernelExecutableMemory：
        // - 作用：调用 Prompt 1 定义的内核可执行页扫描 IOCTL，并解析变长响应为 R3 模型。
        // - 参数 flags：扫描开关位，通常由 UI 传入 INCLUDE_ALL。
        // - 参数 maxEntries：单次最大返回条数，0 表示使用默认值。
        // - 参数 modulePathFilter：R3 预留筛选参数，当前由 UI 在本地完成过滤。
        // - 返回：KernelExecutableMemoryScanResult，io.ok 表示传输和协议解析成功。
        KernelExecutableMemoryScanResult scanKernelExecutableMemory(unsigned long flags = 0UL, unsigned long maxEntries = 4096UL, const std::wstring& modulePathFilter = std::wstring()) const;
        KernelInlinePatchResult patchInlineHook(std::uint64_t functionAddress, unsigned long mode, unsigned long patchBytes, const std::vector<std::uint8_t>& expectedCurrentBytes, const std::vector<std::uint8_t>& restoreBytes = std::vector<std::uint8_t>(), unsigned long flags = 0UL) const;
        KernelIatEatHookScanResult enumerateIatEatHooks(unsigned long flags = KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_IMPORTS | KSWORD_ARK_KERNEL_SCAN_FLAG_INCLUDE_EXPORTS, unsigned long maxEntries = KSWORD_ARK_KERNEL_HOOK_DEFAULT_MAX_ENTRIES, const std::wstring& moduleName = std::wstring()) const;
        // enumerateKernelTimerDpc：只读查询每 CPU TimerTable，返回 KTIMER/KDPC 快照及 partial/corrupt 诊断。
        KernelTimerDpcEnumResult enumerateKernelTimerDpc(
            unsigned long maxEntries = KSWORD_ARK_TIMER_DPC_DEFAULT_MAX_ENTRIES,
            unsigned long maxEntriesPerBucket = KSWORD_ARK_TIMER_DPC_DEFAULT_BUCKET_BUDGET) const;
        DriverObjectQueryResult queryDriverObject(const std::wstring& driverName, unsigned long flags = KSWORD_ARK_DRIVER_OBJECT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxDevices = KSWORD_ARK_DRIVER_DEVICE_LIMIT_DEFAULT, unsigned long maxAttachedDevices = KSWORD_ARK_DRIVER_ATTACHED_LIMIT_DEFAULT) const;
        // controlIoTimer：R0 按名称重新引用 DriverObject，用带引用设备快照
        // 核对 DriverObject/DeviceObject/PIO_TIMER 三重身份后，调用公开 IoStartTimer/IoStopTimer。
        IoTimerControlResult controlIoTimer(
            unsigned long action,
            const std::wstring& driverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint64_t expectedDeviceObjectAddress,
            std::uint64_t expectedTimerAddress,
            bool uiConfirmed) const;
        // queryIoctlRegistry：查询 KswordARK 统一 dispatch 注册表，只读返回元数据。
        IoctlRegistryQueryResult queryIoctlRegistry(unsigned long flags = KSWORD_ARK_IOCTL_REGISTRY_FLAG_INCLUDE_HANDLER, unsigned long maxEntries = KSWORD_ARK_IOCTL_REGISTRY_MAX_ENTRIES) const;

        // queryResearchTopic：查询一个内核知识专题的版本化 R0 现场证据与来源映射。
        ResearchTopicQueryResult queryResearchTopic(
            unsigned long topicId,
            unsigned long maxEntries = KSWORD_ARK_RESEARCH_DEFAULT_MAX_ENTRIES) const;
        // queryDriverIntegrity：
        // - 输入：可选 DriverObject 名称、模块基址和采集预算。
        // - 处理：调用统一驱动完整性 IOCTL，聚合 DriverObject/LDR/FastIo/CPU/IDT 证据。
        // - 返回：DriverIntegrityResult；unsupported=true 表示 R0 尚未集成或驱动过旧。
        DriverIntegrityResult queryDriverIntegrity(
            const std::wstring& driverName = std::wstring(),
            std::uint64_t targetModuleBase = 0,
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DEFAULT,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // queryUnloadedDrivers：
        // - 输入：MmUnloadedDrivers、PiDDBCacheTable 或 g_KernelHashBucketList 来源及行数预算；
        // - 处理：调用统一只读 IOCTL，并按 HAS_* 标志保留各来源真实支持的列；
        // - 返回：UnloadedDriverQueryResult；不会删除、清理或修改任何内核缓存。
        UnloadedDriverQueryResult queryUnloadedDrivers(
            std::uint32_t source,
            unsigned long maxRows = KSWORD_ARK_UNLOADED_DRIVER_DEFAULT_ROWS) const;
        // queryKernelCpuIntegrity：
        // - 输入：CPU/IDT 采集 flags 与预算。
        // - 处理：复用 queryDriverIntegrity 的协议，只请求 CPU entry evidence。
        // - 返回：DriverIntegrityResult；不执行任何 MSR/IDT/GDT 写操作。
        DriverIntegrityResult queryKernelCpuIntegrity(
            unsigned long flags = KSWORD_ARK_DRIVER_INTEGRITY_FLAG_CPU | KSWORD_ARK_DRIVER_INTEGRITY_FLAG_IDT_ENTRIES,
            unsigned long maxRows = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_MAX_ROWS,
            unsigned long maxIdtVectorsPerCpu = KSWORD_ARK_DRIVER_INTEGRITY_DEFAULT_IDT_VECTORS) const;
        // restoreIdtBaseline：对指定 CPU/向量执行不可变启动期基线的只读预检或原子恢复。
        // force=false 只返回 FORCE_REQUIRED/当前状态；force=true 时调用方还必须显式传入 uiConfirmed。
        IdtBaselineRestoreResult restoreIdtBaseline(
            std::uint16_t processorGroup,
            std::uint8_t processorNumber,
            std::uint8_t vector,
            std::uint64_t expectedRawLow,
            std::uint64_t expectedRawHigh,
            bool force,
            bool uiConfirmed) const;
        PiDdbQueryResult queryPiDdb(
            unsigned long maxRows = KSWORD_ARK_PIDDB_DEFAULT_ROWS) const;
        PiDdbDeleteResult deletePiDdbEntry(
            const PiDdbEntry& expectedEntry,
            bool force,
            bool uiConfirmed) const;
        // queryHvmStatus/controlHvm：读取 VT-x/EPT 能力并执行准备、自检、
        // 一次性 VMCALL 来宾、VM-exit 采集或资源释放。
        HvmStatusResult queryHvmStatus() const;
        HvmControlResult controlHvm(
            unsigned long command,
            unsigned long expectedGeneration,
            bool force,
            bool allowNested,
            bool uiConfirmed,
            bool enableEptEvents = false,
            bool enableNestedVmx = false,
            bool enableEvmcs = false) const;
        HvmEptRuleResult controlHvmEptRule(
            unsigned long operation,
            unsigned long expectedGeneration,
            unsigned long ruleId,
            unsigned long deniedAccess,
            std::uint64_t physicalAddress,
            std::uint64_t pageCount,
            bool log,
            bool allowOnce,
            bool uiConfirmed) const;
        // querySlatIommuAudit：只读采集 EPT/NPT 交叉视图、DMAR/IVRS
        // 与公开 IOMMU 接口证据；includeMmio 仅增加只读寄存器采样。
        SlatIommuAuditResult querySlatIommuAudit(bool includeMmio) const;
        // querySystemTime/controlSystemTime：
        // - 查询或控制全系统性能计数器的连续倍率映射；
        // - UI 只传命令、倍率、计时后端、解析模式、期望代次与确认状态，不直接访问设备。
        SystemTimeQueryResult querySystemTime() const;
        SystemTimeControlResult controlSystemTime(
            unsigned long command,
            unsigned long factor,
            unsigned long backend,
            unsigned long resolutionMode,
            unsigned long expectedGeneration,
            bool uiConfirmed) const;
        HvmEventResult queryHvmEvents(
            std::uint64_t afterSequence = 0,
            unsigned long maxRows = KSWORD_ARK_HVM_MAX_EVENT_ROWS,
            bool clear = false) const;
        // queryCpuHardwareSnapshot：
        // - 输入：无；R0 只执行 CPUID 与处理器数量查询。
        // - 处理：封装 IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE，解析 vendor/brand/family/model/feature mask。
        // - 返回：CpuHardwareSnapshotResult；旧驱动未注册 IOCTL 时 unsupported=true。
        CpuHardwareSnapshotResult queryCpuHardwareSnapshot() const;
        // queryPhysicalMemoryLayout：
        // - 输入：无；R0 只读取 MmGetPhysicalMemoryRanges 聚合结果。
        // - 处理：封装 IOCTL_KSWORD_ARK_QUERY_PHYSICAL_MEMORY_LAYOUT，解析物理内存范围统计。
        // - 返回：PhysicalMemoryLayoutResult；不返回任何内存内容。
        PhysicalMemoryLayoutResult queryPhysicalMemoryLayout() const;
        DriverForceUnloadResult forceUnloadDriver(const std::wstring& driverName, unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        DriverForceUnloadResult forceUnloadDriverByModuleBase(std::uint64_t moduleBase, const std::wstring& fallbackDriverName = std::wstring(), unsigned long flags = 0UL, unsigned long timeoutMilliseconds = 3000UL) const;
        // controlDriverCommunication：
        // - 输入：精确模块基址、canonical 名称、证据扫描返回的 DriverObject 地址和 action；
        // - 处理：统一封装独立通信控制 IOCTL，Dock UI 不直接访问 KswordARK 设备；
        // - 返回：状态、MajorFunction 掩码、冲突信息和 canonical DriverObject 名称。
        DriverCommunicationControlResult controlDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        DriverCommunicationControlResult queryDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        DriverCommunicationControlResult blindDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress) const;
        DriverCommunicationControlResult restoreDriverCommunication(
            std::uint64_t moduleBase,
            const std::wstring& displayName = std::wstring()) const;
        // 通用 MajorFunction 编辑只封装身份/CAS 协议，不施加目标或地址策略。
        DriverDispatchControlResult controlDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress = 0U,
            std::uint64_t expectedCurrentDispatchAddress = 0U,
            std::uint64_t desiredDispatchAddress = 0U,
            std::uint32_t expectedGeneration = 0U,
            bool uiConfirmed = false) const;
        DriverDispatchControlResult queryDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        DriverDispatchControlResult applyDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint64_t expectedCurrentDispatchAddress,
            std::uint64_t desiredDispatchAddress,
            std::uint32_t expectedGeneration) const;
        DriverDispatchControlResult restoreDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        DriverDispatchControlResult abandonDriverDispatch(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long majorFunction,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // Driver image 控制只传输显式身份、期望快照和用户确认；不限制驱动类别或地址值。
        DriverImageControlResult controlDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long action,
            unsigned long fieldMask,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            const DriverImageValues& expectedValues,
            const DriverImageValues& desiredValues,
            std::uint64_t expectedLinkFlink = 0U,
            std::uint64_t expectedLinkBlink = 0U,
            bool restoreLink = false,
            bool uiConfirmed = false) const;
        // queryDriverImage：获取五个字段、加载器链、记录归属和冲突的同锁快照。
        DriverImageControlResult queryDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress = 0U) const;
        // applyDriverImageFields：按 fieldMask 对期望值执行原子 CAS 批量修改。
        DriverImageControlResult applyDriverImageFields(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long fieldMask,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            const DriverImageValues& expectedValues,
            const DriverImageValues& desiredValues) const;
        // hideDriverImage：仅在 Flink/Blink 精确匹配时从 PsLoadedModuleList 摘链。
        DriverImageControlResult hideDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration,
            std::uint64_t expectedLinkFlink,
            std::uint64_t expectedLinkBlink) const;
        // restoreDriverImage：恢复所选字段，并可按原邻居或当前尾部重新插入加载链。
        DriverImageControlResult restoreDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            unsigned long fieldMask,
            bool restoreLink,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // abandonDriverImage：保持所有当前危险值/链状态，仅永久丢弃恢复记录。
        DriverImageControlResult abandonDriverImage(
            std::uint64_t moduleBase,
            const std::wstring& canonicalDriverName,
            std::uint64_t expectedDriverObjectAddress,
            std::uint32_t expectedGeneration) const;
        // prepareMutation / commitMutation / rollbackMutation / queryMutationAudit：
        // - 输入：受控 transaction 参数或只读 audit 查询参数。
        // - 处理：仅在 ArkDriverClient 内封装 mutation IOCTL；Dock UI 不直接调用 DeviceIoControl。
        // - 返回：固定响应或 audit rows；UI 只能展示 dry-run/audit/rollback，不暴露任意写按钮。
        MutationResponseResult prepareMutation(const MutationPrepareInput& input) const;
        MutationResponseResult commitMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationResponseResult rollbackMutation(std::uint64_t transactionId, unsigned long flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN) const;
        MutationAuditResult queryMutationAudit(unsigned long flags = 0, unsigned long maxEntries = KSWORD_ARK_MUTATION_AUDIT_RING_CAPACITY, std::uint64_t startSequence = 0) const;
        IoResult setCallbackRules(const void* blobBytes, unsigned long blobSize) const;
        AsyncIoResult waitCallbackEventAsync(
            DriverHandle& handle,
            KSWORD_ARK_CALLBACK_WAIT_REQUEST& request,
            KSWORD_ARK_CALLBACK_EVENT_PACKET& eventPacket,
            OVERLAPPED* overlapped) const;
        CallbackRuntimeResult queryCallbackRuntimeState() const;
        IoResult setMinifilterBypassPids(const std::vector<std::uint32_t>& processIds) const;
        MinifilterBypassPidResult queryMinifilterBypassPids() const;
        // 基于对象管理器句柄回调的进程保护：配置是一次性全量替换，
        // 未出现在 rules 里的进程立即失去保护。
        IoResult setProcessProtectConfig(
            unsigned long globalFlags,
            const std::vector<KSWORD_ARK_PROCESS_PROTECT_RULE>& rules,
            const std::vector<KSWORD_ARK_PROCESS_PROTECT_TRUSTED>& trustedEntries,
            unsigned long scanIntervalMs = KSWORD_ARK_PROCESS_PROTECT_SCAN_INTERVAL_DEFAULT_MS) const;
        ProcessProtectStateResult queryProcessProtectState() const;
        IoResult answerCallbackEvent(const KSWORD_ARK_CALLBACK_ANSWER_REQUEST& request) const;
        IoResult cancelAllPendingCallbackDecisions() const;
        CallbackRemoveResult removeExternalCallback(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_REQUEST& request) const;
        CallbackRemoveExResult removeExternalCallbackEx(const KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_REQUEST& request) const;
        bool supportsExternalCallbackExperimentalUnlink() const;
        CallbackEnumResult enumerateCallbacks(unsigned long flags = KSWORD_ARK_ENUM_CALLBACK_FLAG_INCLUDE_ALL) const;
        KeyboardHotkeyEnumResult enumerateKeyboardHotkeys(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        KeyboardHotkeyMutationResult mutateKeyboardHotkey(
            const KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY& entry,
            unsigned long operation,
            unsigned long newModifiers = 0UL,
            unsigned long newVirtualKey = 0UL) const;

        KeyboardHookEnumResult enumerateKeyboardHooks(std::uint32_t processId = 0, unsigned long flags = KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS | KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS, unsigned long maxEntries = 2048UL) const;
        DriverCapabilitiesQueryResult queryDriverCapabilities() const;
        DynDataStatusResult queryDynDataStatus() const;
        DynDataFieldsResult queryDynDataFields() const;
        DynDataCapabilitiesResult queryDynDataCapabilities() const;
        DynDataProfileApplyResult applyDynDataProfile(const DynDataProfileApplyInput& profile) const;
        DynDataProfileApplyExResult applyDynDataProfileEx(const DynDataProfileApplyExInput& profile) const;
        // applyDynDataProfileV4 / queryDynDataV4*：
        // - 输入：PDB extractor 生成的 v4 profile 或只读查询预算；
        // - 处理：封装 DynData v4 IOCTL，验证固定/变长响应头；
        // - 返回：R3 友好结果；unsupported=true 表示旧驱动未注册 v4 IOCTL。
        DynDataV4ApplyResult applyDynDataProfileV4(const DynDataV4ApplyInput& profile) const;
        DynDataV4ModulesResult queryDynDataV4Modules(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES) const;
        DynDataV4CapabilityGroupsResult queryDynDataV4CapabilityGroups(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_CAPABILITY_GROUPS_PER_MODULE) const;
        DynDataV4MissingItemsResult queryDynDataV4MissingItems(unsigned long maxRows = KSW_DYN_V4_MAX_MISSING_SUMMARY) const;
        DynDataV4ItemsResult queryDynDataV4Items(unsigned long maxRows = KSW_DYN_V4_MAX_MODULES * KSW_DYN_V4_MAX_ITEMS_PER_MODULE) const;
        // queryNetwork*：
        // - 输入：只读网络审计 flags 和最大行数；
        // - 处理：封装 TCP/UDP/WFP/NDIS PDB-backed 审计 IOCTL；
        // - 返回：变长审计行；不执行断连、禁用、detach 或规则修改。
        NetworkEndpointAuditResult queryNetworkTcpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkEndpointAuditResult queryNetworkUdpEndpoints(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpInventoryResult queryNetworkWfpInventory(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        NetworkWfpEventResult queryNetworkWfpEvents(std::uint64_t afterSequence, unsigned long maxRows = KSWORD_ARK_NETWORK_WFP_EVENT_DEFAULT_REQUESTED_ROWS) const;
        NetworkTrafficCaptureControlResult controlNetworkTrafficCapture(bool enabled) const;
        NetworkTrafficPacketResult queryNetworkTrafficPackets(std::uint64_t afterSequence, unsigned long maxRows = KSWORD_ARK_NETWORK_TRAFFIC_DEFAULT_REQUESTED_ROWS) const;
        NetworkNdisChainResult queryNetworkNdisChain(unsigned long flags = KSWORD_ARK_NETWORK_AUDIT_QUERY_FLAG_INCLUDE_ALL, unsigned long maxRows = KSWORD_ARK_NETWORK_AUDIT_MAX_REQUESTED_ROWS) const;
        // File/filter/storage audit wrappers：
        // - 输入：只读 flags、预算和可选卷路径；
        // - 处理：封装 Minifilter/Storage/BitLocker/MountMgr/Filesystem integrity IOCTL；
        // - 返回：协议行数组；BitLocker wrapper 不返回密钥材料。
        MinifilterInventoryResult queryMinifilterInventory(unsigned long flags = KSWORD_ARK_MINIFILTER_INVENTORY_FLAG_INCLUDE_ALL, unsigned long maxRows = 256UL) const;
        StorageVolumeStackAuditResult queryVolumeStackAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageBitlockerFveAuditResult queryBitlockerFveAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageMountMgrMappingAuditResult queryMountMgrMappingAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        StorageFilesystemIntegrityAuditResult queryFilesystemIntegrityAudit(const std::wstring& volumePath = std::wstring(), unsigned long flags = KSWORD_ARK_STORAGE_AUDIT_FLAG_INCLUDE_DEFAULT, unsigned long maxRows = KSWORD_ARK_STORAGE_DEFAULT_MAX_ROWS, unsigned long maxDepth = KSWORD_ARK_STORAGE_DEFAULT_STACK_DEPTH) const;
        // query/read/writeRawDisk：
        // - 输入：物理磁盘号、显式后端、对齐偏移/长度和安全确认标志；
        // - 处理：只在 ArkDriverClient 内封装三层磁盘 IOCTL，不在 Dock 中直接访问控制设备；
        // - 返回：R0 能力、读取字节或安全策略审计后的写入结果。
        RawDiskBackendResult queryRawDiskBackend(
            unsigned long diskNumber,
            unsigned long requestedBackend = 0UL,
            unsigned long flags = 0UL) const;
        RawDiskReadResult readRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            unsigned long length,
            unsigned long flags = 0UL) const;
        RawDiskWriteResult writeRawDisk(
            unsigned long diskNumber,
            unsigned long backend,
            std::uint64_t offset,
            const std::vector<std::uint8_t>& bytes,
            unsigned long flags) const;
        // Security audit wrappers：
        // - 输入：只读 flags 或行预算；
        // - 处理：封装 Security/CI/VBS/Hyper-V/AppControl IOCTL；
        // - 返回：固定或变长结果，不修改任何安全策略。
        SecurityStatusAuditResult querySecurityStatus(unsigned long flags = 0UL) const;
        DriverTrustViewAuditResult queryDriverTrustView(unsigned long flags = KSWORD_ARK_DRIVER_TRUST_QUERY_FLAG_DEFAULT, unsigned long maxEntries = KSWORD_ARK_SECURITY_AUDIT_DEFAULT_DRIVER_ROWS) const;
        HyperVSummaryAuditResult queryHyperVSummary() const;
        AppControlStatusAuditResult queryAppControlStatus() const;
        // Win32K GUI audit wrappers：
        // - 输入：session/pid/tid 过滤和最大行数；
        // - 处理：封装 win32k PDB 只读快照 IOCTL；
        // - 返回：窗口、GUI 线程、hotkey、hook 诊断行；不安装或移除 hook。
        Win32kProfileStatusResult queryWin32kProfileStatus(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowsResult queryWin32kWindows(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kGuiThreadsResult queryWin32kGuiThreads(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHotkeysPdbResult queryWin32kHotkeysPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kHooksPdbResult queryWin32kHooksPdb(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_MESSAGE_HOOK_DEFAULT_MAX_ENTRIES) const;
        Win32kTimersResult queryWin32kTimers(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kEventHooksResult queryWin32kEventHooks(unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_ALL, unsigned long sessionId = 0UL, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long maxEntries = KSWORD_ARK_WIN32K_DEFAULT_MAX_ENTRIES) const;
        Win32kWindowRuntimeDetailResult queryWin32kWindowDetail(std::uint64_t hwnd, unsigned long processId = 0UL, unsigned long threadId = 0UL, unsigned long flags = KSWORD_ARK_WIN32K_QUERY_FLAG_INCLUDE_DIAGNOSTICS) const;
        // Device/kernel-object audit wrappers：
        // - 输入：只读 profile、目标名或 CID/IPC 参数；
        // - 处理：封装 DeviceAudit、CID、KernelObjectSummary、IPCSummary IOCTL；
        // - 返回：诊断行或固定摘要，不执行 DKOM/卸载/解绑。
        DeviceAuditResult queryDeviceStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryInputStackAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryUsbTopologyAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        DeviceAuditResult queryGpuDisplayWatchdogAudit(const std::wstring& targetName = std::wstring(), unsigned long maxRows = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ROWS, unsigned long maxAttachedDepth = KSWORD_ARK_DEVICE_AUDIT_DEFAULT_MAX_ATTACHED_DEPTH) const;
        // queryPlatformAudit：
        // - 输入：HAL/WDF scope 和最大行数；
        // - 处理：只通过受控 IOCTL 获取结构签名与模块边界验证后的证据；
        // - 返回：未知系统布局显式 unsupported/partial，不尝试裸偏移扫描。
        PlatformAuditResult queryPlatformAudit(unsigned long scopeMask = KSWORD_ARK_PLATFORM_AUDIT_SCOPE_ALL, unsigned long maxRows = KSWORD_ARK_PLATFORM_DEFAULT_MAX_ROWS) const;
        // editPlatformAuditEntry：
        // - 输入：查询快照中的 scope/index/table/current 与新的非零函数地址；
        //   scope 只接受四个 HAL 子表与 WDF_FUNCTIONS，WDF_CALLBACKS 无可写槽；
        // - 处理：只通过 FILE_WRITE_ACCESS 控制协议请求 R0 重新定位并原子替换；
        // - 返回：表/槽/前值/当前值证据；不暴露任意内核地址写入。
        PlatformAuditControlResult editPlatformAuditEntry(unsigned long scope, unsigned long entryIndex, std::uint64_t tableAddress, std::uint64_t expectedValue, std::uint64_t newValue, bool uiConfirmed) const;
        // queryI8042Audit：
        // - 输入：最大行预算；
        // - 处理：通过专用只读 IOCTL 获取精确版本描述符验证后的键鼠端点；
        // - 返回：未知 i8042prt 映像显式 unsupported，不回退到 CallbackEnum。
        I8042AuditResult queryI8042Audit(unsigned long maxRows = KSWORD_ARK_I8042_DEFAULT_MAX_ROWS) const;
        // queryHwidDispatchState / controlHwidDispatch：
        // - 输入：无输入查询或完整 HWID Dispatch 控制包；
        // - 处理：只通过 ArkDriverClient 访问新增 IOCTL，Dock 不直接 DeviceIoControl；
        // - 返回：HwidDispatchResult，保留 R0 原始状态和 unsupported 标记。
        HwidDispatchResult queryHwidDispatchState() const;
        HwidDispatchResult controlHwidDispatch(const KSWORD_ARK_HWID_DISPATCH_CONTROL_REQUEST& request) const;
        // queryCpuPowerState / controlCpuPower：
        // - 查询 Intel RAPL/HWP/Turbo 白名单能力，或提交带 expected snapshot 的结构化控制包；
        // - Dock 不直接打开设备，也不暴露任意 MSR 写入入口。
        CpuPowerResult queryCpuPowerState() const;
        CpuPowerResult controlCpuPower(const KSWORD_ARK_CPU_POWER_CONTROL_REQUEST& request) const;
        CidTableAuditResult enumCidTable(unsigned long flags = KSWORD_ARK_CID_ENUM_FLAG_INCLUDE_ALL, unsigned long maxEntries = 4096UL, unsigned long maxVisitCount = 65536UL, unsigned long startCid = 0UL, unsigned long endCid = 0UL) const;
        ObjectTypeTableAuditResult enumObjectTypeTable(unsigned long flags = KSWORD_ARK_OBJECT_TYPE_TABLE_FLAG_INCLUDE_ALL, unsigned long maxEntries = KSWORD_ARK_OBJECT_TYPE_TABLE_MAX_SLOTS, unsigned long startIndex = 0UL) const;
        KernelObjectSummaryAuditResult queryKernelObjectSummary(unsigned long targetKind, unsigned long cidValue = 0UL, std::uint64_t expectedObjectAddress = 0ULL, unsigned long flags = KSWORD_ARK_OBJECT_SUMMARY_FLAG_INCLUDE_ALL) const;
        IpcSummaryAuditResult queryIpcSummary(unsigned long processId = 0UL, std::uint64_t handleValue = 0ULL, unsigned long flags = KSWORD_ARK_IPC_QUERY_FLAG_INCLUDE_ALL, unsigned long maxEntries = 64UL) const;
    };
}
