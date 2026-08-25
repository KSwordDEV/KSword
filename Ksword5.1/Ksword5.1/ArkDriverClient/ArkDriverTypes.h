#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "../../../shared/KswordArkLogProtocol.h"
#include "../../../shared/driver/KswordArkCallbackIoctl.h"
#include "../../../shared/driver/KswordArkCapabilityIoctl.h"
#include "../../../shared/driver/KswordArkDynDataIoctl.h"
#include "../../../shared/driver/KswordArkFileIoctl.h"
#include "../../../shared/driver/KswordArkFileIrpIoctl.h"
#include "../../../shared/driver/KswordArkFileMonitorIoctl.h"
#include "../../../shared/driver/KswordArkHandleIoctl.h"
#include "../../../shared/driver/KswordArkKernelIoctl.h"
#include "../../../shared/driver/KswordArkKeyboardIoctl.h"
#include "../../../shared/driver/KswordArkMemoryIoctl.h"
#include "../../../shared/driver/KswordArkMutationIoctl.h"
#include "../../../shared/driver/KswordArkProcessIoctl.h"
#include "../../../shared/driver/KswordArkProcessProtectIoctl.h"
#include "../../../shared/driver/KswordArkThreadIoctl.h"
#include "../../../shared/driver/KswordArkWorkQueueIoctl.h"
#include "../../../shared/driver/KswordArkAlpcIoctl.h"
#include "../../../shared/driver/KswordArkSectionIoctl.h"
#include "../../../shared/driver/KswordArkRegistryIoctl.h"
#include "../../../shared/driver/KswordArkNetworkIoctl.h"
#include "../../../shared/driver/KswordArkStorageIoctl.h"
#include "../../../shared/driver/KswordArkStorageForensicsIoctl.h"
#include "../../../shared/driver/KswordArkKernelBaselineIoctl.h"
#include "../../../shared/driver/KswordArkPiDdbIoctl.h"
#include "../../../shared/driver/KswordArkHvmIoctl.h"
#include "../../../shared/driver/KswordArkSlatIommuAuditIoctl.h"
#include "../../../shared/driver/KswordArkSecurityAuditIoctl.h"
#include "../../../shared/driver/KswordArkTrustIoctl.h"
#include "../../../shared/driver/KswordArkWin32kIoctl.h"
#include "../../../shared/driver/KswordArkDeviceAuditIoctl.h"
#include "../../../shared/driver/KswordArkPlatformAuditIoctl.h"
#include "../../../shared/driver/KswordArkI8042AuditIoctl.h"
#include "../../../shared/driver/KswordArkDriverBlindIoctl.h"
#include "../../../shared/driver/KswordArkDriverDispatchIoctl.h"
#include "../../../shared/driver/KswordArkDriverImageEditorIoctl.h"
#include "../../../shared/driver/KswordArkFilterIoctl.h"
#include "../../../shared/driver/KswordArkKernelObjectIoctl.h"
#include "../../../shared/driver/KswordArkHwidIoctl.h"
#include "../../../shared/driver/KswordArkCpuPowerIoctl.h"
#include "../../../shared/driver/KswordArkDebugOutputIoctl.h"
#include "../../../shared/driver/KswordArkBugcheckIoctl.h"
#include "../../../shared/driver/KswordArkUnloadedDriverIoctl.h"
#include "../../../shared/driver/KswordArkSystemTimeIoctl.h"
#include "../../../shared/driver/KswordArkResearchIoctl.h"

namespace ksword::ark
{
    // IoResult is the common outcome for every KswordARK driver operation.
    // ok mirrors the Win32 DeviceIoControl success bit, win32Error preserves
    // GetLastError(), ntStatus is filled only when a response packet carries it.
    struct IoResult
    {
        bool ok = false;
        unsigned long win32Error = ERROR_SUCCESS;
        long ntStatus = 0;
        std::string message;
        unsigned long bytesReturned = 0;
    };

    // ResearchTopicQueryResult：保留《第二规划》专题的 R0 现场上下文
    // 和经中央注册表核实的业务 IOCTL 证据行。
    struct ResearchTopicQueryResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_RESEARCH_TOPIC_RESPONSE response{};
        std::vector<KSWORD_ARK_RESEARCH_EVIDENCE_ENTRY> entries;
    };

    // HwidDispatchResult：
    // - 输入：由 DriverClient 的 HWID Dispatch IOCTL wrapper 填充；
    // - 处理：保留 R0 原始响应，UI 负责解释目标驱动状态和风险提示；
    // - 返回行为：结构体无成员函数，io.ok 表示 DeviceIoControl 是否成功。
    struct HwidDispatchResult
    {
        IoResult io;                                  // io：底层 DeviceIoControl 状态。
        bool unsupported = false;                     // unsupported：旧驱动未注册新 IOCTL 时为 true。
        KSWORD_ARK_HWID_DISPATCH_RESPONSE response{}; // response：R0 固定响应包。
    };

    // CpuPowerResult：保留 R0 CPU 电源固定响应及旧驱动兼容状态。
    struct CpuPowerResult
    {
        IoResult io;                                   // io：底层 DeviceIoControl 状态。
        bool unsupported = false;                      // unsupported：加载驱动尚未注册新 IOCTL。
        KSWORD_ARK_CPU_POWER_RESPONSE response{};      // response：能力、原始 MSR 和解码值。
    };

    // DriverHandle owns one KswordARK control-device handle. It is move-only so
    // UI code can cache handles without duplicating close responsibility.
    class DriverHandle
    {
    public:
        DriverHandle() noexcept = default;
        explicit DriverHandle(HANDLE handleValue) noexcept;
        ~DriverHandle();

        DriverHandle(const DriverHandle&) = delete;
        DriverHandle& operator=(const DriverHandle&) = delete;
        DriverHandle(DriverHandle&& other) noexcept;
        DriverHandle& operator=(DriverHandle&& other) noexcept;

        bool isValid() const noexcept;
        HANDLE native() const noexcept;
        HANDLE release() noexcept;
        void reset(HANDLE newHandle = INVALID_HANDLE_VALUE) noexcept;

    private:
        HANDLE m_handle = INVALID_HANDLE_VALUE;
    };

    // ProcessEntry is a normalized, UI-friendly view of one R0 process row.
    struct ProcessEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t sessionId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE;
        std::uint32_t sessionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint8_t protection = 0;
        std::uint8_t signatureLevel = 0;
        std::uint8_t sectionSignatureLevel = 0;
        std::uint32_t protectionSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t signatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t objectTableSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t sectionObjectSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t imagePathSource = KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t protectionOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t signatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionSignatureLevelOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t objectTableOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t sectionObjectOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t objectTableAddress = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t creationTime100ns = 0;
        std::string imageName;
        std::string imagePath;
    };

    // ProcessEnumResult carries both the parsed rows and protocol metadata.
    struct ProcessEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<ProcessEntry> entries;
    };

    // ProcessVisibilityResult 承载 R0 可恢复隐藏标记的更新结果。
    struct ProcessVisibilityResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_VISIBILITY_STATUS_UNKNOWN;
        std::uint32_t hiddenCount = 0;
        long lastStatus = 0;
    };

    // ProcessIntegrityResult 承载 R0 进程完整性写入响应。
    // 输入：由 DriverClient::setProcessIntegrity 填充，processId/integrityRid 回显目标。
    // 处理：io.ok 只代表驱动通信和固定响应解析成功，status/lastStatus 表示 R0 内核 API 执行结果。
    // 返回行为：unsupported=true 表示旧驱动缺少 IOCTL，调用方可以按策略回退到 R3。
    struct ProcessIntegrityResult
    {
        IoResult io;                         // io：底层 DeviceIoControl 状态和响应 NTSTATUS。
        bool unsupported = false;            // unsupported：旧驱动未注册 IOCTL 或返回不支持。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t processId = 0;         // processId：目标 PID。
        std::uint32_t integrityRid = 0;      // integrityRid：S-1-16-* mandatory label RID。
        std::uint32_t status = KSWORD_ARK_PROCESS_INTEGRITY_STATUS_UNKNOWN; // status：R0 聚合状态。
        long lastStatus = 0;                 // lastStatus：Zw* token API 或 R0 DynData Token 兜底路径 NTSTATUS。
    };

    // ProcessTokenPrivilegeEntry is shared by both unified and legacy token privilege flows.
    struct ProcessTokenPrivilegeEntry
    {
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t attributes = 0;
        std::uint32_t action = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_ACTION_KEEP;
    };

    struct ProcessTokenPrivilegeResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t operation = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        std::uint32_t requestedCount = 0;
        std::uint32_t appliedCount = 0;
        std::uint32_t failedIndex = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_FAILED_INDEX_NONE;
        long lastStatus = 0;
        std::uint64_t processCreateTime100ns = 0;
        std::vector<ProcessTokenPrivilegeEntry> entries;
    };

    struct ProcessTokenPrivilegeQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        long lastStatus = 0;
        std::vector<ProcessTokenPrivilegeEntry> entries;
    };

    struct ProcessTokenPrivilegeAdjustResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t luidLowPart = 0;
        std::int32_t luidHighPart = 0;
        std::uint32_t action = 0;
        std::uint32_t status = KSWORD_ARK_PROCESS_TOKEN_PRIVILEGE_STATUS_UNKNOWN;
        long lastStatus = 0;
    };

    // ProcessSpecialFlagsResult 承载 BreakOnTermination/APC 插入控制响应。
    struct ProcessSpecialFlagsResult
    {
        IoResult io;                         // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t processId = 0;         // processId：目标 PID。
        std::uint32_t action = 0;            // action：请求动作。
        std::uint32_t status = KSWORD_ARK_PROCESS_SPECIAL_STATUS_UNKNOWN; // status：R0 聚合状态。
        std::uint32_t appliedFlags = 0;      // appliedFlags：已应用标志。
        std::uint32_t touchedThreadCount = 0;// touchedThreadCount：禁 APC 时改变的线程数。
        long lastStatus = 0;                 // lastStatus：底层 NTSTATUS。
    };

    // ProcessDkomResult 承载 PspCidTable DKOM 删除响应。
    struct ProcessDkomResult
    {
        IoResult io;                         // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t processId = 0;         // processId：目标 PID。
        std::uint32_t action = 0;            // action：请求动作。
        std::uint32_t status = KSWORD_ARK_PROCESS_DKOM_STATUS_UNKNOWN; // status：R0 聚合状态。
        std::uint32_t removedEntries = 0;    // removedEntries：清零的 CID 表项数。
        long lastStatus = 0;                 // lastStatus：底层 NTSTATUS。
        std::uint64_t pspCidTableAddress = 0;// pspCidTableAddress：诊断地址。
        std::uint64_t processObjectAddress = 0; // processObjectAddress：诊断地址。
    };

    // ProcessInjectResult 承载 R0 DLL / Shellcode 注入响应。
    struct ProcessInjectResult
    {
        IoResult io;                         // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t processId = 0;         // processId：目标 PID。
        std::uint32_t injectType = 0;        // injectType：DLL 路径或 shellcode。
        std::uint32_t status = KSWORD_ARK_PROCESS_INJECT_STATUS_UNKNOWN; // status：R0 聚合状态。
        std::uint32_t flags = 0;             // flags：请求标志回显。
        std::uint32_t bytesWritten = 0;      // bytesWritten：写入目标进程的 payload 字节数。
        long lastStatus = 0;                 // lastStatus：底层 NTSTATUS。
        long waitStatus = 0;                 // waitStatus：可选等待远端线程的状态。
        std::uint64_t entryPointAddress = 0; // entryPointAddress：远端线程入口。
        std::uint64_t parameterAddress = 0;  // parameterAddress：远端线程参数。
        std::uint64_t remoteBaseAddress = 0; // remoteBaseAddress：远端 payload 区域。
        std::uint64_t remoteRegionSize = 0;  // remoteRegionSize：远端分配区域大小。
    };

    // ThreadEntry 是 R0 KTHREAD 扩展字段的 R3 侧模型。
    // 输入：ArkDriverProcess.cpp 从 KSWORD_ARK_THREAD_ENTRY 逐字段复制。
    // 处理：flags 保留 KSWORD_ARK_THREAD_FLAG_* cross-view 结果，fieldFlags 保留字段可用性。
    // 返回：纯数据结构，无成员函数返回值。
    struct ThreadEntry
    {
        std::uint32_t threadId = 0;
        std::uint32_t processId = 0;
        std::uint32_t flags = 0;      // KSWORD_ARK_THREAD_FLAG_*：R0 active walk / CID scan 交叉视图标记。
        std::uint32_t fieldFlags = 0;
        std::uint32_t r0Status = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE;
        std::uint32_t stackFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
        std::uint32_t ioFieldSource = KSW_DYN_FIELD_SOURCE_UNAVAILABLE;
        std::uint64_t initialStack = 0;
        std::uint64_t stackLimit = 0;
        std::uint64_t stackBase = 0;
        std::uint64_t kernelStack = 0;
        std::uint64_t readOperationCount = 0;
        std::uint64_t writeOperationCount = 0;
        std::uint64_t otherOperationCount = 0;
        std::uint64_t readTransferCount = 0;
        std::uint64_t writeTransferCount = 0;
        std::uint64_t otherTransferCount = 0;
        std::uint32_t ktInitialStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktStackLimitOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktStackBaseOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktKernelStackOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktReadOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktWriteOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktOtherOperationCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktReadTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktWriteTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktOtherTransferCountOffset = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t dynDataCapabilityMask = 0;
    };

    // ThreadEnumResult 承载 R0 线程扩展枚举响应。
    struct ThreadEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<ThreadEntry> entries;
    };

    // WorkQueueEntry preserves one validated read-only R0 work-item or worker-thread row.
    struct WorkQueueEntry
    {
        std::uint32_t rowKind = 0;
        std::uint32_t queueType = 0;
        std::uint32_t priorityIndex = 0;
        std::uint32_t nodeIndex = 0;
        std::uint32_t flags = 0;
        std::uint32_t status = 0;
        std::uint64_t queueAddress = 0;
        std::uint64_t workItemAddress = 0;
        std::uint64_t routineAddress = 0;
        std::uint64_t parameterAddress = 0;
        std::uint64_t threadObject = 0;
        std::uint32_t threadId = 0;
        std::uint64_t threadCreateTime100ns = 0;
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::string moduleName;
        std::string modulePath;
    };

    // WorkQueueEnumResult separates transport success from explicit fail-closed R0 status.
    struct WorkQueueEnumResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED;
        std::uint32_t statusFlags = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t nodeCount = 0;
        std::uint32_t queuesVisited = 0;
        std::uint32_t corruptListCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t referenceFailureCount = 0;
        long lastStatus = 0;
        std::vector<WorkQueueEntry> entries;
    };

    // HandleEntry 是 R0 HandleTable 直接枚举的 R3 侧模型。
    struct HandleEntry
    {
        std::uint32_t processId = 0;
        std::uint32_t handleValue = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t decodeStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
        std::uint32_t grantedAccess = 0;
        std::uint32_t attributes = 0;
        std::uint32_t objectTypeIndex = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t epObjectTableOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t htHandleContentionEventOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t obDecodeShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t obAttributesShift = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
    };

    // HandleEnumResult 承载 R0 进程 HandleTable 枚举响应。
    struct HandleEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processId = 0;
        std::uint32_t overallStatus = KSWORD_ARK_HANDLE_DECODE_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::vector<HandleEntry> entries;
    };

    // HandleObjectQueryResult 承载 R0 对象类型/对象名查询结果。
    struct HandleObjectQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint64_t handleValue = 0;
        std::uint64_t objectAddress = 0;
        std::uint32_t objectTypeIndex = 0;
        std::uint32_t queryStatus = KSWORD_ARK_OBJECT_QUERY_STATUS_UNAVAILABLE;
        long objectReferenceStatus = 0;
        long typeStatus = 0;
        long nameStatus = 0;
        std::uint32_t proxyStatus = KSWORD_ARK_OBJECT_PROXY_STATUS_NOT_REQUESTED;
        long proxyNtStatus = 0;
        std::uint32_t proxyPolicyFlags = 0;
        std::uint32_t requestedAccess = 0;
        std::uint32_t actualGrantedAccess = 0;
        std::uint64_t proxyHandle = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t otNameOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_HANDLE_OFFSET_UNAVAILABLE;
        std::wstring typeName;
        std::wstring objectName;
    };

    // AlpcPortInfo 是 R0 ALPC Port 查询中单个端口节点的 R3 展示模型。
    struct AlpcPortInfo
    {
        std::uint32_t relation = KSWORD_ARK_ALPC_PORT_RELATION_QUERY;
        std::uint32_t fieldFlags = 0;
        std::uint32_t ownerProcessId = 0;
        std::uint32_t flags = 0;
        std::uint32_t state = 0;
        std::uint32_t sequenceNo = 0;
        long basicStatus = 0;
        long nameStatus = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t portContext = 0;
        std::wstring portName;
    };

    // AlpcPortQueryResult 承载 Phase-6 R0 ALPC 查询响应。
    struct AlpcPortQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint64_t handleValue = 0;
        std::uint32_t queryStatus = KSWORD_ARK_ALPC_QUERY_STATUS_UNAVAILABLE;
        long objectReferenceStatus = 0;
        long typeStatus = 0;
        long basicStatus = 0;
        long communicationStatus = 0;
        long nameStatus = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t alpcCommunicationInfoOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcOwnerProcessOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcConnectionPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcServerCommunicationPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcClientCommunicationPortOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcHandleTableOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcHandleTableLockOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcAttributesOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcAttributesFlagsOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcPortContextOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcPortObjectLockOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcSequenceNoOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::uint32_t alpcStateOffset = KSWORD_ARK_ALPC_OFFSET_UNAVAILABLE;
        std::wstring typeName;
        AlpcPortInfo queryPort;
        AlpcPortInfo connectionPort;
        AlpcPortInfo serverPort;
        AlpcPortInfo clientPort;
    };

    // SectionMappingEntry 是 R0 ControlArea 映射关系的一行 R3 模型。
    struct SectionMappingEntry
    {
        std::uint32_t viewMapType = KSWORD_ARK_SECTION_MAP_TYPE_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint64_t startVa = 0;
        std::uint64_t endVa = 0;
    };

    // ProcessSectionQueryResult 承载 Phase-7 进程 SectionObject / ControlArea 查询响应。
    struct ProcessSectionQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processId = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t queryStatus = KSWORD_ARK_SECTION_QUERY_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint64_t sectionObjectAddress = 0;
        std::uint64_t controlAreaAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t epSectionObjectOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmSectionControlAreaOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaListHeadOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaLockOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::vector<SectionMappingEntry> mappings;
    };

    // FileSectionMappingEntry 是 R0 文件 Data/Image ControlArea 映射关系的一行 R3 模型。
    struct FileSectionMappingEntry
    {
        std::uint32_t sectionKind = KSWORD_ARK_FILE_SECTION_KIND_UNKNOWN; // Data 或 Image。
        std::uint32_t viewMapType = KSWORD_ARK_SECTION_MAP_TYPE_UNKNOWN;  // Process/Session/SystemCache。
        std::uint32_t processId = 0;                                      // 命中映射进程 PID。
        std::uint64_t controlAreaAddress = 0;                             // 仅诊断展示。
        std::uint64_t startVa = 0;                                        // 映射起始 VA。
        std::uint64_t endVa = 0;                                          // 映射结束 VA。
    };

    // FileSectionMappingsQueryResult 承载 Phase-7 文件反查映射进程响应。
    struct FileSectionMappingsQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t queryStatus = KSWORD_ARK_FILE_SECTION_QUERY_STATUS_UNAVAILABLE;
        long lastStatus = 0;
        std::uint64_t fileObjectAddress = 0;
        std::uint64_t sectionObjectPointersAddress = 0;
        std::uint64_t dataControlAreaAddress = 0;
        std::uint64_t imageControlAreaAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t mmControlAreaListHeadOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::uint32_t mmControlAreaLockOffset = KSWORD_ARK_SECTION_OFFSET_UNAVAILABLE;
        std::vector<FileSectionMappingEntry> mappings;
    };

    // FileInfoQueryResult 是 Phase-10 R0 文件基础信息查询的 R3 模型。
    struct FileInfoQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;        // 协议版本。
        std::uint32_t fieldFlags = 0;     // KSWORD_ARK_FILE_INFO_FIELD_*。
        std::uint32_t queryStatus = KSWORD_ARK_FILE_INFO_STATUS_UNAVAILABLE; // 查询聚合状态。
        long openStatus = 0;              // ZwCreateFile 状态。
        long basicStatus = 0;             // FileBasicInformation 查询状态。
        long standardStatus = 0;          // FileStandardInformation 查询状态。
        long objectStatus = 0;            // ObReferenceObjectByHandle/SectionPointer 状态。
        long nameStatus = 0;              // ObQueryNameString 状态。
        std::uint32_t fileAttributes = 0; // FILE_ATTRIBUTE_*。
        std::int64_t allocationSize = 0;  // 分配大小。
        std::int64_t endOfFile = 0;       // 文件逻辑大小。
        std::int64_t creationTime = 0;    // FILETIME 兼容时间戳。
        std::int64_t lastAccessTime = 0;  // FILETIME 兼容时间戳。
        std::int64_t lastWriteTime = 0;   // FILETIME 兼容时间戳。
        std::int64_t changeTime = 0;      // NTFS change time。
        std::uint64_t fileObjectAddress = 0; // 诊断展示，不作为凭据。
        std::uint64_t sectionObjectPointersAddress = 0; // 诊断展示。
        std::uint64_t dataSectionObjectAddress = 0;     // 诊断展示。
        std::uint64_t imageSectionObjectAddress = 0;    // 诊断展示。
        std::wstring ntPath;            // 请求 NT 路径回显。
        std::wstring objectName;        // ObQueryNameString 文件对象名。
    };

    // DirectoryEntryRecord 是 R0 文件系统驱动枚举返回的一条已校验目录记录。
    struct DirectoryEntryRecord
    {
        std::uint32_t flags = 0;          // KSWORD_ARK_DIRECTORY_ENTRY_FLAG_*。
        std::uint32_t fileAttributes = 0; // FILE_ATTRIBUTE_* 原始位。
        std::uint64_t fileId = 0;         // 文件系统提供的 FileId，仅用于展示/关联。
        std::int64_t allocationSize = 0;  // 分配大小，目录或未知值可能为 0。
        std::int64_t endOfFile = 0;       // 文件逻辑长度。
        std::int64_t creationTime = 0;    // NT 100ns 时间戳。
        std::int64_t lastAccessTime = 0;  // NT 100ns 时间戳。
        std::int64_t lastWriteTime = 0;   // NT 100ns 时间戳。
        std::int64_t changeTime = 0;      // NT 100ns 时间戳。
        std::wstring name;                // 已做协议边界校验的文件名。
    };

    // DirectoryEnumerationResult 汇总所有分页响应，并显式保留旧驱动/截断状态。
    struct DirectoryEnumerationResult
    {
        IoResult io;                      // 最后一页的通信结果或本地校验错误。
        bool unsupported = false;         // 旧驱动未注册目录枚举 IOCTL。
        bool capped = false;              // 达到 R3 总行预算，结果不是完整目录。
        std::uint32_t queryStatus =
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE; // 最后一页语义状态。
        std::uint32_t responseFlags = 0;   // 最后一页 KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*。
        long openStatus = 0;               // ZwCreateFile 目录打开状态。
        long lastStatus = 0;               // ZwQueryDirectoryFile 或边界校验状态。
        std::wstring fileSystemName;       // R0 通过 FileFsAttributeInformation 返回的名称。
        std::vector<DirectoryEntryRecord> entries; // 已按驱动顺序合并的目录行。
    };

    // FileIrpDirectoryResult 承载"自建 IRP 直发某一栈层"的目录枚举结果。
    // 行格式与 DirectoryEnumerationResult 完全一致，额外记录 R0 实际生效的栈层
    // 与接收请求的驱动名：请求层与生效层不同就说明发生了回退，调用方不得把回退
    // 结果当作"绕过过滤层后的视图"。
    struct FileIrpDirectoryResult
    {
        IoResult io;                      // 最后一页的通信结果或本地校验错误。
        bool unsupported = false;         // 旧驱动未注册 IRP 目录枚举 IOCTL。
        bool capped = false;              // 达到 R3 总行预算，结果不是完整目录。
        std::uint32_t queryStatus =
            KSWORD_ARK_DIRECTORY_ENUM_STATUS_UNAVAILABLE; // 最后一页语义状态。
        std::uint32_t responseFlags = 0;   // 最后一页 KSWORD_ARK_DIRECTORY_ENUM_RESPONSE_FLAG_*。
        std::uint32_t requestedLayer = 0;  // R3 请求的 KSWORD_ARK_FILE_IRP_LAYER_*。
        std::uint32_t resolvedLayer = 0;   // R0 实际投递的栈层。
        long openStatus = 0;               // CREATE 阶段状态。
        long lastStatus = 0;               // QUERY_DIRECTORY 或边界校验状态。
        std::uint64_t targetDeviceAddress = 0; // 实际接收 IRP 的设备对象。
        std::uint64_t targetDriverAddress = 0; // 该设备所属驱动对象。
        std::wstring driverName;           // 接收请求的驱动名。
        std::wstring fileSystemName;       // 目标卷文件系统名（可能为空）。
        std::vector<DirectoryEntryRecord> entries; // 已按驱动顺序合并的目录行。
    };

    // FileIrpSubmitResult 承载一次通用 IRP 构造提交的完整结果。
    // 各阶段 NTSTATUS 分开保留：UI 必须能区分"打开失败"与"目标 major 被目标驱动
    // 拒绝"，两者在排查过滤层拦截时含义完全不同。
    struct FileIrpSubmitResult
    {
        IoResult io;                       // 底层 DeviceIoControl 状态。
        bool unsupported = false;          // 旧驱动未注册 IRP 提交 IOCTL。
        std::uint32_t status =
            KSWORD_ARK_FILE_IRP_STATUS_INVALID_REQUEST; // 协议级状态。
        std::uint32_t stageFlags = 0;      // KSWORD_ARK_FILE_IRP_STAGE_*。
        std::uint32_t majorFunction = 0;
        std::uint32_t minorFunction = 0;
        std::uint32_t requestedLayer = 0;
        std::uint32_t resolvedLayer = 0;
        long createStatus = 0;
        long operationStatus = 0;
        long cleanupStatus = 0;
        long closeStatus = 0;
        std::uint64_t information = 0;     // 目标 major 的 IoStatus.Information。
        std::uint64_t fileObjectAddress = 0;
        std::uint64_t targetDeviceAddress = 0;
        std::uint64_t targetDriverAddress = 0;
        std::uint64_t relatedDeviceAddress = 0;
        std::uint64_t baseFsDeviceAddress = 0;
        std::uint64_t vpbDeviceAddress = 0;
        std::uint64_t dispatchAddress = 0; // 目标驱动上该 major 的分发入口。
        std::uint32_t targetStackSize = 0;
        std::uint32_t targetDeviceFlags = 0;
        std::wstring driverName;
        std::wstring deviceName;
        std::vector<std::uint8_t> outputData; // 目标驱动写回的数据。
    };

    // FileIrpSubmitRequestParams 是 R3 侧的构造参数集合。
    // 与协议结构分开，让 UI 只填自己关心的字段，长度与令牌由客户端统一补齐。
    struct FileIrpSubmitRequestParams
    {
        std::wstring ntPath;               // 目标 NT 路径。
        std::wstring pattern;              // DIRECTORY_CONTROL 的通配符，可空。
        std::uint32_t majorFunction = 0;
        std::uint32_t minorFunction = 0;
        std::uint32_t targetLayer = KSWORD_ARK_FILE_IRP_LAYER_RELATED;
        std::uint32_t flags = 0;           // KSWORD_ARK_FILE_IRP_FLAG_*（不含令牌位）。
        std::uint32_t timeoutMs = 0;       // 0 表示使用 R0 默认超时。
        std::uint32_t desiredAccess = 0;
        std::uint32_t shareAccess = 0;
        std::uint32_t createDisposition = 0;
        std::uint32_t createOptions = 0;
        std::uint32_t fileAttributes = 0;
        std::uint32_t informationClass = 0;
        std::uint32_t controlCode = 0;
        std::uint32_t securityInformation = 0;
        std::uint32_t lockKey = 0;
        std::uint32_t outputBytes = 0;     // 期望的输出缓冲长度。
        std::uint64_t byteOffset = 0;
        std::uint64_t lockLength = 0;
        std::vector<std::uint8_t> inputData; // 内联输入数据。
        bool uiConfirmed = false;          // 写语义/危险 major 必须为 true。
        bool allowDangerous = false;       // POWER/PNP/SHUTDOWN 等额外闸门。
    };

    // ImageSignatureQueryResult preserves the complete fixed R0 response so
    // callers can distinguish PE certificate-table structure from the
    // independent Code Integrity cached-signing-level result.
    struct ImageSignatureQueryResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_IMAGE_SIGNATURE_RESPONSE response{};
    };

    // FileIntegrityResult 承载 R0 文件 Mandatory Label 写入响应。
    // 输入：由 DriverClient::setFileIntegrity 填充，flags/integrityRid/pathLengthChars 回显请求。
    // 处理：io.ok 只代表驱动通信和响应解析成功，status/lastStatus 表示 ZwCreateFile/ZwSetSecurityObject 结果。
    // 返回行为：unsupported=true 表示旧驱动缺少 IOCTL，调用方可以按策略回退到 R3。
    struct FileIntegrityResult
    {
        IoResult io;                         // io：底层 DeviceIoControl 状态和响应 NTSTATUS。
        bool unsupported = false;            // unsupported：旧驱动未注册 IOCTL 或返回不支持。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t flags = 0;             // flags：KSWORD_ARK_FILE_INTEGRITY_FLAG_* 回显。
        std::uint32_t integrityRid = 0;      // integrityRid：S-1-16-* mandatory label RID。
        std::uint32_t status = KSWORD_ARK_FILE_INTEGRITY_STATUS_UNKNOWN; // status：R0 聚合状态。
        long lastStatus = 0;                 // lastStatus：ZwCreateFile/ZwSetSecurityObject 等 NTSTATUS。
        std::uint32_t pathLengthChars = 0;   // pathLengthChars：驱动接收的 NT 路径字符数。
    };

    // FileDeleteBackend：DELETE_PATH IOCTL 的单节点执行后端。
    // Native 保留原有底层 Zw* 方案；Irp 通过文件系统栈投递 IRP_MJ_SET_INFORMATION；
    // Posix 强制使用 FileDispositionInformationEx 的 POSIX unlink 语义。
    enum class FileDeleteBackend : std::uint32_t
    {
        Native = 0U,
        Irp = 1U,
        Posix = 2U
    };

    // DeletePathResult 承载 R0 删除（单项或递归）的统计回执。
    // 输入：由 DriverClient::deletePathEx 填充。
    // 处理：io.ok 只表示 DeviceIoControl 成功；删除语义看 response.deleteStatus。
    // 返回行为：unsupported=true 表示驱动不认识所选递归/后端标志；仅 Native
    // 可回退到旧版 R3 展开逐项删除，Irp/Posix 必须显式报告后端不可用。
    struct DeletePathResult
    {
        IoResult io;                                // io：底层 DeviceIoControl 状态。
        bool unsupported = false;                   // unsupported：旧驱动拒绝新 flags。
        bool responseValid = false;                 // responseValid：是否解析到完整响应包。
        KSWORD_ARK_DELETE_PATH_RESPONSE response{}; // response：R0 固定统计响应。
    };

    // FileMonitorStatusResult 是 R0 文件系统 minifilter 运行状态的 R3 模型。
    struct FileMonitorStatusResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：文件监控协议版本。
        std::uint32_t size = 0;         // size：R0 返回结构大小。
        std::uint32_t runtimeFlags = 0; // runtimeFlags：REGISTERED/STARTED/DROPPED 等标志。
        std::uint32_t operationMask = 0;// operationMask：当前文件事件操作过滤位。
        std::uint32_t processIdFilter = 0; // processIdFilter：0 表示不过滤 PID。
        std::uint32_t ringCapacity = 0; // ringCapacity：R0 环形队列容量。
        std::uint32_t queuedCount = 0;  // queuedCount：当前待取事件数。
        std::uint32_t droppedCount = 0; // droppedCount：累计覆盖丢弃事件数。
        std::uint64_t sequence = 0;     // sequence：R0 文件事件序列号。
        long registerStatus = 0;        // registerStatus：FltRegisterFilter 状态。
        long startStatus = 0;           // startStatus：FltStartFiltering 状态。
        long lastErrorStatus = 0;       // lastErrorStatus：最近一次文件监控错误。
    };

    // FileMonitorEventRow 是 R0 file-monitor ring buffer 的 R3 展示模型。
    struct FileMonitorEventRow
    {
        std::uint32_t version = 0;       // version：事件协议版本。
        std::uint32_t size = 0;          // size：R0 事件结构大小。
        std::uint32_t operationType = 0; // operationType：KSWORD_ARK_FILE_MONITOR_OPERATION_*。
        std::uint32_t majorFunction = 0; // majorFunction：IRP_MJ_*。
        std::uint32_t minorFunction = 0; // minorFunction：IRP_MN_*。
        std::uint32_t processId = 0;     // processId：请求发起进程 PID。
        std::uint32_t threadId = 0;      // threadId：请求发起线程 ID。
        std::uint32_t fieldFlags = 0;    // fieldFlags：有效字段位图。
        std::uint32_t desiredAccess = 0; // desiredAccess：Create/Open 访问掩码。
        std::uint32_t shareAccess = 0;   // shareAccess：Create/Open 共享掩码。
        std::uint32_t createOptions = 0; // createOptions：Create/Open options。
        std::uint32_t fileInformationClass = 0; // fileInformationClass：SetInformation class。
        long resultStatus = 0;           // resultStatus：post-operation NTSTATUS。
        std::uint32_t pathLengthChars = 0; // pathLengthChars：R0 返回路径字符数。
        std::uint64_t sequence = 0;      // sequence：R0 事件序号。
        std::int64_t timeUtc100ns = 0;   // timeUtc100ns：UTC FILETIME。
        std::uint64_t fileObjectAddress = 0; // fileObjectAddress：FileObject 地址，仅诊断展示。
        std::uint32_t fsControlCode = 0; // fsControlCode：IRP_MJ_FILE_SYSTEM_CONTROL 控制码。
        std::uint32_t fsInputBufferLength = 0; // fsInputBufferLength：输入缓冲区长度。
        std::uint32_t fsOutputBufferLength = 0; // fsOutputBufferLength：输出缓冲区长度。
        std::wstring path;               // path：R0 解析出的 normalized/opened file name。
    };

    // FileMonitorDrainResult 是文件监控 drain IOCTL 的解析结果。
    struct FileMonitorDrainResult
    {
        IoResult io;                     // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;       // version：响应协议版本。
        std::uint32_t totalQueuedBeforeDrain = 0; // totalQueuedBeforeDrain：取出前队列深度。
        std::uint32_t returnedCount = 0; // returnedCount：本次返回事件数。
        std::uint32_t entrySize = 0;     // entrySize：R0 单个事件字节数。
        std::uint32_t droppedCount = 0;  // droppedCount：累计丢弃事件数。
        std::uint32_t runtimeFlags = 0;  // runtimeFlags：REGISTERED/STARTED/DROPPED。
        std::uint32_t ringCapacity = 0;  // ringCapacity：R0 ring 容量。
        std::vector<FileMonitorEventRow> events; // events：已解析事件列表。
    };

    // DebugOutputControlResult 保存 R0 调试输出回调的注册、捕获与丢弃状态。
    struct DebugOutputControlResult
    {
        IoResult io;                         // io：DeviceIoControl 与固定响应解析状态。
        bool unsupported = false;            // unsupported：当前驱动尚未注册调试输出 IOCTL。
        std::uint32_t version = 0;           // version：共享协议版本。
        std::uint32_t runtimeFlags = 0;      // runtimeFlags：REGISTERED/CAPTURING/DROPPED。
        std::uint32_t ringCapacity = 0;      // ringCapacity：R0 固定环形缓冲区容量。
        std::uint32_t queuedCount = 0;       // queuedCount：当前仍可读取的记录数量。
        std::uint64_t latestSequence = 0;    // latestSequence：最近提交的单调序号。
        std::uint64_t droppedCount = 0;      // droppedCount：高 IRQL 并发写入时累计丢弃数。
        long registrationStatus = 0;         // registrationStatus：DbgSetDebugPrintCallback 状态。
        long lastStatus = 0;                 // lastStatus：最近控制动作的 NTSTATUS。
    };

    // DebugOutputRecord 是一条已经稳定复制到 R3 的内核调试消息。
    struct DebugOutputRecord
    {
        std::uint64_t sequence = 0;          // sequence：R0 单调序号。
        std::uint64_t interruptTime100ns = 0;// interruptTime100ns：KeQueryInterruptTime 时间戳。
        std::uint32_t componentId = 0;       // componentId：DbgPrintEx 组件 ID。
        std::uint32_t level = 0;             // level：DbgPrintEx 级别。
        std::uint32_t flags = 0;             // flags：TEXT_TRUNCATED 等记录标志。
        std::string text;                    // text：按协议长度复制的 UTF-8/ANSI 调试文本。
    };

    // DebugOutputDrainResult 是按游标增量读取调试输出环形缓冲区的结果。
    struct DebugOutputDrainResult
    {
        IoResult io;                         // io：DeviceIoControl 与变长响应解析状态。
        bool unsupported = false;            // unsupported：当前驱动不支持该 IOCTL。
        std::uint32_t runtimeFlags = 0;      // runtimeFlags：当前回调运行时标志。
        std::uint32_t responseFlags = 0;     // responseFlags：OVERFLOW/MORE/SNAPSHOT_RACE。
        std::uint32_t ringCapacity = 0;      // ringCapacity：R0 环形容量。
        std::uint64_t firstAvailableSequence = 0; // firstAvailableSequence：最早未覆盖序号。
        std::uint64_t latestSequence = 0;    // latestSequence：读取快照时的最新序号。
        std::uint64_t nextSequence = 0;      // nextSequence：下次请求应携带的游标。
        std::uint64_t droppedCount = 0;      // droppedCount：回调 try-lock 累计丢弃数。
        std::uint64_t lostBeforeFirst = 0;   // lostBeforeFirst：调用方游标落后导致的覆盖数。
        std::vector<DebugOutputRecord> records; // records：本次成功解析的升序记录。
    };

    // RegistryReadResult 是 R0 注册表值读取响应的 R3 模型。
    struct RegistryReadResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t status = KSWORD_ARK_REGISTRY_READ_STATUS_UNKNOWN; // status：R0 聚合状态。
        std::uint32_t valueType = 0;    // valueType：REG_* 类型。
        std::uint32_t dataBytes = 0;    // dataBytes：返回数据长度。
        std::uint32_t requiredBytes = 0; // requiredBytes：完整值数据长度。
        long lastStatus = 0;            // lastStatus：底层 Zw* 状态。
        std::vector<std::uint8_t> data; // data：原始注册表值数据。
    };

    // RegistrySubKeyEntry 是 R0 枚举出的一个子键。
    struct RegistrySubKeyEntry
    {
        std::wstring name;              // name：子键名称，不含父路径。
    };

    // RegistryValueEntry 是 R0 枚举出的一个注册表值。
    struct RegistryValueEntry
    {
        std::wstring name;              // name：值名，空字符串表示默认值。
        std::uint32_t valueType = 0;    // valueType：REG_* 类型。
        std::uint32_t dataBytes = 0;    // dataBytes：返回预览数据长度。
        std::uint32_t requiredBytes = 0; // requiredBytes：完整数据长度。
        std::vector<std::uint8_t> data; // data：预览数据，可能被 R0 截断。
    };

    // RegistryEnumResult 是 R0 枚举键响应的 R3 模型。
    struct RegistryEnumResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t status = KSWORD_ARK_REGISTRY_ENUM_STATUS_UNKNOWN; // status：R0 聚合状态。
        std::uint32_t subKeyCount = 0;  // subKeyCount：R0 观察到的子键数。
        std::uint32_t returnedSubKeyCount = 0; // returnedSubKeyCount：已返回子键数。
        std::uint32_t valueCount = 0;   // valueCount：R0 观察到的值数。
        std::uint32_t returnedValueCount = 0; // returnedValueCount：已返回值数。
        long lastStatus = 0;            // lastStatus：底层 Zw* 状态。
        std::vector<RegistrySubKeyEntry> subKeys; // subKeys：子键列表。
        std::vector<RegistryValueEntry> values;   // values：值列表。
    };

    // RegistryOperationResult 是 R0 注册表写操作通用响应模型。
    struct RegistryOperationResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_UNKNOWN; // status：操作聚合状态。
        long lastStatus = 0;            // lastStatus：底层 Zw* 状态。
    };

    // VirtualMemoryReadResult 是 R0 读目标进程虚拟内存的 R3 模型。
    struct VirtualMemoryQueryResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t processId = 0;    // processId：目标 PID。
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t queryStatus = KSWORD_ARK_MEMORY_QUERY_STATUS_UNAVAILABLE; // queryStatus：R0 查询聚合状态。
        long openStatus = 0;            // openStatus：R0 打开目标进程的 NTSTATUS。
        long basicStatus = 0;           // basicStatus：ZwQueryVirtualMemory 的 NTSTATUS。
        long mappedFileNameStatus = 0;  // mappedFileNameStatus：映射文件名查询状态。
        std::uint32_t source = 0;       // source：数据来源。
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress：请求地址。
        std::uint64_t baseAddress = 0;          // baseAddress：区域起始地址。
        std::uint64_t allocationBase = 0;       // allocationBase：原始分配基址。
        std::uint64_t regionSize = 0;           // regionSize：区域长度。
        std::uint32_t allocationProtect = 0;    // allocationProtect：初始保护属性。
        std::uint32_t state = 0;                // state：MEM_COMMIT/MEM_RESERVE/MEM_FREE。
        std::uint32_t protect = 0;              // protect：当前页面保护属性。
        std::uint32_t type = 0;                 // type：MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE。
        std::wstring mappedFileName;            // mappedFileName：可选映射文件路径。
    };

    struct VirtualMemoryReadResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t headerSize = 0;   // headerSize：R0 固定响应头大小。
        std::uint32_t processId = 0;    // processId：目标 PID。
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t readStatus = KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE; // readStatus：R0 读聚合状态。
        long lookupStatus = 0;          // lookupStatus：PsLookupProcessByProcessId 状态。
        long copyStatus = 0;            // copyStatus：MmCopyVirtualMemory 状态。
        std::uint32_t source = 0;       // source：数据来源。
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress：请求基址。
        std::uint32_t requestedBytes = 0;       // requestedBytes：请求长度。
        std::uint32_t bytesRead = 0;            // bytesRead：R0 返回有效长度。
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest：驱动限制。
        std::vector<std::uint8_t> data;         // data：读回数据，失败区域按 R0 策略可为 00。
    };

    // VirtualMemoryWriteResult 是 R0 写目标进程虚拟内存的 R3 模型。
    struct VirtualMemoryWriteResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t processId = 0;    // processId：目标 PID。
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t writeStatus = KSWORD_ARK_MEMORY_WRITE_STATUS_UNAVAILABLE; // writeStatus：R0 写聚合状态。
        long lookupStatus = 0;          // lookupStatus：PsLookupProcessByProcessId 状态。
        long copyStatus = 0;            // copyStatus：MmCopyVirtualMemory 状态。
        std::uint32_t source = 0;       // source：写入来源。
        std::uint64_t requestedBaseAddress = 0; // requestedBaseAddress：请求基址。
        std::uint32_t requestedBytes = 0;       // requestedBytes：请求写入长度。
        std::uint32_t bytesWritten = 0;         // bytesWritten：实际写入长度。
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest：驱动限制。
    };

    // PhysicalMemoryReadResult 是 R0 读物理内存的 R3 模型。
    // 物理协议不携带 processId，也没有进程查找步骤，因此不含 lookupStatus。
    struct PhysicalMemoryReadResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t headerSize = 0;   // headerSize：R0 自报响应头大小，仅供诊断，不用于定位 data。
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*。
        std::uint32_t readStatus = KSWORD_ARK_MEMORY_PHYSICAL_READ_STATUS_UNAVAILABLE; // readStatus：R0 物理读聚合状态。
        long copyStatus = 0;            // copyStatus：MmCopyMemory 的 NTSTATUS。
        std::uint32_t source = 0;       // source：数据来源，物理读固定为 MM_COPY_PHYSICAL_MEMORY。
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress：请求物理地址。
        std::uint32_t requestedBytes = 0;       // requestedBytes：请求长度。
        std::uint32_t bytesRead = 0;            // bytesRead：R0 返回有效长度。
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest：驱动单次读上限。
        std::vector<std::uint8_t> data;         // data：读回物理字节，部分成功时长度可小于请求。
    };

    // PhysicalMemoryWriteResult 是 R0 受控写物理内存的 R3 模型。
    // 物理写走 MmMapIoSpaceEx 映射再拷贝，因此比虚拟写多一个 mapStatus。
    struct PhysicalMemoryWriteResult
    {
        IoResult io;                    // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;      // version：协议版本。
        std::uint32_t fieldFlags = 0;   // fieldFlags：KSWORD_ARK_MEMORY_FIELD_*，含 FORCE_WRITE_REQUIRED/USED。
        std::uint32_t writeStatus = KSWORD_ARK_MEMORY_PHYSICAL_WRITE_STATUS_UNAVAILABLE; // writeStatus：R0 物理写聚合状态。
        long mapStatus = 0;             // mapStatus：MmMapIoSpaceEx 映射阶段的 NTSTATUS。
        long copyStatus = 0;            // copyStatus：映射后 RtlCopyMemory 阶段的 NTSTATUS。
        std::uint32_t source = 0;       // source：写入来源，物理写固定为 MM_MAP_PHYSICAL_MEMORY。
        std::uint64_t requestedPhysicalAddress = 0; // requestedPhysicalAddress：请求物理地址。
        std::uint32_t requestedBytes = 0;       // requestedBytes：请求写入长度。
        std::uint32_t bytesWritten = 0;         // bytesWritten：实际写入长度。
        std::uint32_t maxBytesPerRequest = 0;   // maxBytesPerRequest：驱动单次写上限。
    };

    // Kernel executable-memory permission bits used by the R3 display model.
    // Input: values parsed from the kernel executable page scan response.
    // Processing: MemoryDock maps these bits to readable R/W/X/NX/Large labels.
    // Return behavior: constants are consumed directly and do not return data.
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionPresent = KSWORD_ARK_PAGE_TABLE_FLAG_PRESENT;
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionWritable = KSWORD_ARK_PAGE_TABLE_FLAG_WRITABLE;
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionUser = KSWORD_ARK_PAGE_TABLE_FLAG_USER;
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionNoExecute = KSWORD_ARK_PAGE_TABLE_FLAG_NX;
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionLargePage = KSWORD_ARK_PAGE_TABLE_FLAG_LARGE_PAGE;
    inline constexpr std::uint32_t KernelExecutableMemoryPermissionGlobal = KSWORD_ARK_PAGE_TABLE_FLAG_GLOBAL;

    // Kernel executable-memory risk bits used by the R3 display model.
    // Input: values parsed from R0 scan entries.
    // Processing: UI uses these stable bits for filtering and risk text.
    // Return behavior: constants are values only; no function return is involved.
    inline constexpr std::uint32_t KernelExecutableMemoryRiskWritableExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_WRITABLE_EXECUTABLE;
    inline constexpr std::uint32_t KernelExecutableMemoryRiskModuleNonTextExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_MODULE_NON_TEXT_EXECUTABLE;
    inline constexpr std::uint32_t KernelExecutableMemoryRiskSectionWritable = KSWORD_ARK_KERNEL_EXEC_RISK_SECTION_WRITABLE;
    inline constexpr std::uint32_t KernelExecutableMemoryRiskLargePage = KSWORD_ARK_KERNEL_EXEC_RISK_LARGE_PAGE;
    inline constexpr std::uint32_t KernelExecutableMemoryRiskCodePageNotExecutable = KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_NOT_EXECUTABLE;
    inline constexpr std::uint32_t KernelExecutableMemoryRiskCodePageWritable = KSWORD_ARK_KERNEL_EXEC_RISK_CODE_PAGE_WRITABLE;

    // KernelExecutableMemoryPageEntry is the R3 model for one executable kernel
    // memory range. Input fields are copied from the Prompt-1 scan response.
    // Processing keeps kernel addresses diagnostic-only and stores owner/path
    // strings for filtering and details. Return behavior: plain data object.
    struct KernelExecutableMemoryPageEntry
    {
        std::uint32_t status = 0;              // status：R0 row status.
        std::uint32_t riskFlags = 0;           // riskFlags：KernelExecutableMemoryRisk* bits.
        std::uint32_t permissionFlags = 0;     // permissionFlags：KernelExecutableMemoryPermission* bits.
        std::uint32_t ownerKind = 0;           // ownerKind：R0 owner classifier, shown diagnostically.
        std::uint32_t pageCount = 0;           // pageCount：contiguous executable pages.
        std::uint32_t pageSize = 0;            // pageSize：4KB/2MB/1GB or R0 effective size.
        long lastStatus = 0;                   // lastStatus：row-level backend status.
        std::uint64_t virtualAddress = 0;      // virtualAddress：range start VA, display only.
        std::uint64_t ownerAddress = 0;        // ownerAddress：diagnostic owner object/address.
        std::uint64_t moduleBase = 0;          // moduleBase：matched module base when available.
        std::uint32_t moduleSize = 0;          // moduleSize：matched module image size when available.
        std::uint64_t regionSize = 0;          // regionSize：pageCount * pageSize or R0 range size.
        std::wstring owner;                    // owner：R0 owner text.
        std::wstring modulePath;               // modulePath：matched module image path.
        std::wstring detail;                   // detail：R0 diagnostic detail for CodeEditorWidget.
    };

    // KernelExecutableMemoryScanResult carries the parsed Prompt-1 response.
    // Input: returned by DriverClient::scanKernelExecutableMemory.
    // Processing: io.ok indicates transport/protocol success; unsupported tells
    // UI to show "not supported / driver too old" instead of crashing.
    // Return behavior: returned by value from DriverClient.
    struct KernelExecutableMemoryScanResult
    {
        IoResult io;                           // io：DeviceIoControl and parse status.
        bool unsupported = false;              // unsupported：true when IOCTL is absent/old.
        std::uint32_t version = 0;             // version：scan protocol version.
        std::uint32_t status = 0;              // status：R0 aggregate status.
        std::uint32_t totalCount = 0;          // totalCount：R0 observed ranges.
        std::uint32_t returnedCount = 0;       // returnedCount：R0 returned ranges.
        std::uint32_t moduleCount = 0;         // moduleCount：R0 module owner set size.
        long lastStatus = 0;                   // lastStatus：R0 aggregate backend status.
        std::vector<KernelExecutableMemoryPageEntry> entries; // entries：parsed scan rows.
    };


    // KernelMemoryEvidenceEntry is the unified R3 model for memory evidence rows.
    // Input: fields are copied from KSWORD_ARK_KERNEL_MEMORY_EVIDENCE_ROW.
    // Processing: keeps addresses and samples diagnostic-only; UI scoring uses
    // riskFlags/permissionFlags without issuing write or repair actions.
    // Return behavior: plain data carrier returned inside KernelMemoryEvidenceResult.
    struct KernelMemoryEvidenceEntry
    {
        std::uint32_t evidenceKind = KSWORD_ARK_MEMORY_EVIDENCE_KIND_UNKNOWN;
        std::uint32_t pageSize = 0;
        std::uint32_t permissionFlags = 0;
        std::uint32_t ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_UNKNOWN;
        std::uint32_t riskFlags = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t confidence = 0;
        std::uint32_t bigPoolTag = 0;
        std::uint32_t bigPoolFlags = 0;
        std::uint32_t sectionRva = 0;
        std::uint32_t sectionSize = 0;
        std::uint32_t hashAlgorithm = KSWORD_ARK_MEMORY_EVIDENCE_HASH_NONE;
        std::uint32_t sampleSize = 0;
        long lastStatus = 0;
        std::uint64_t virtualAddress = 0;
        std::uint64_t regionSize = 0;
        std::uint64_t moduleBase = 0;
        std::uint64_t ownerAddress = 0;
        std::uint64_t contentHash = 0;
        std::string sectionName;
        std::vector<std::uint8_t> sample;
        std::wstring ownerName;
        std::wstring detail;
    };

    // KernelMemoryEvidenceResult carries the variable-length memory evidence response.
    // Input: produced by DriverClient::queryKernelMemoryEvidence.
    // Processing: unsupported distinguishes old drivers from parse failures so UI can
    // render a graceful capability message.
    // Return behavior: returned by value; io.ok reports transport/protocol success.
    struct KernelMemoryEvidenceResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE;
        std::uint32_t responseFlags = 0;
        std::uint32_t sourceFlags = 0;
        std::uint32_t totalRows = 0;
        std::uint32_t returnedRows = 0;
        std::uint32_t maxRows = 0;
        std::uint64_t maxBytes = 0;
        std::uint64_t bytesScanned = 0;
        std::uint32_t moduleCount = 0;
        std::uint32_t bigPoolRowsSeen = 0;
        long lastStatus = 0;
        std::vector<KernelMemoryEvidenceEntry> entries;
    };

    // CrossViewFieldOffsets mirrors the shared R0 offset packet.
    // Input: copied from process/thread cross-view response headers or rows.
    // Processing: UI uses it only for diagnostics and capability explanations.
    // Return behavior: plain data object with no member function return.
    struct CrossViewFieldOffsets
    {
        std::uint32_t epUniqueProcessId = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epActiveProcessLinks = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epThreadListHead = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t epImageFileName = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etCid = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etThreadListEntry = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etStartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t etWin32StartAddress = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t ktProcess = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t htTableCode = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t hteLowValue = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint32_t pspCidTableRva = KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE;
        std::uint64_t pspCidTableAddress = 0;
        std::uint32_t epUniqueProcessIdSource = 0;
        std::uint32_t epActiveProcessLinksSource = 0;
        std::uint32_t epThreadListHeadSource = 0;
        std::uint32_t epImageFileNameSource = 0;
        std::uint32_t etCidSource = 0;
        std::uint32_t etThreadListEntrySource = 0;
        std::uint32_t etStartAddressSource = 0;
        std::uint32_t etWin32StartAddressSource = 0;
        std::uint32_t ktProcessSource = 0;
        std::uint32_t htTableCodeSource = 0;
        std::uint32_t hteLowValueSource = 0;
        std::uint32_t pspCidTableSource = 0;
    };

    // ProcessCrossViewEntry is one EPROCESS cross-view evidence row.
    // Input: copied from KSWORD_ARK_PROCESS_CROSSVIEW_ROW.
    // Processing: sourceMask and anomalyFlags remain raw protocol bits so multiple
    // Dock pages can render consistent DKOM diagnostics.
    // Return behavior: data only; no return value.
    struct ProcessCrossViewEntry
    {
        std::uint64_t objectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t processId = 0;
        std::uint32_t parentProcessId = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        CrossViewFieldOffsets fieldOffsets;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t activeListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        long publicWalkStatus = 0;
        long activeListStatus = 0;
        long cidTableStatus = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::string imageName;
        std::string detail;
    };

    // ProcessCrossViewResult carries a complete process cross-view query.
    // Input: produced by DriverClient::queryProcessCrossView.
    // Processing: missingCapabilityMask explains DynData gaps without hiding rows.
    // Return behavior: returned by value; unsupported flags old drivers.
    struct ProcessCrossViewResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        long lastStatus = 0;
        CrossViewFieldOffsets fieldOffsets;
        std::vector<ProcessCrossViewEntry> entries;
    };

    // ProcessRuntimeDetailResult 承载单进程 PDB/DynData 运行时详情。
    // 输入：queryProcessRuntimeDetail 返回。
    // 处理：response 直接保存 shared\driver 固定响应，避免 UI 重新定义偏移字段。
    // 返回行为：只读展示 EPROCESS 字段，不修改进程对象。
    struct ProcessRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_PROCESS_DETAIL_RESPONSE response{};
    };

    // RuntimeFieldSampleRequestItem 是 deep PDB runtime catalog 到 R0 sampler 的一项请求。
    // 输入：runtimeItemId/offset/size 来自 profiles\pdb_deep_offsets JSON。
    // 处理：R0 会按对象基址 + offset 安全读取最多 16 字节。
    // 返回行为：该结构只作为 R3 请求模型，不保存对象地址。
    struct RuntimeFieldSampleRequestItem
    {
        std::uint32_t runtimeItemId = 0;
        std::uint32_t offset = 0;
        std::uint32_t size = 0;
        std::uint32_t flags = 0;
        std::string name;
        std::string type;
    };

    // RuntimeFieldSampleEntry 是 R0 返回的一项小字段采样结果。
    // 输入：queryProcessRuntimeFieldSamples/queryThreadRuntimeFieldSamples 返回。
    // 处理：sampleBytes 保留原始字节，valueU64 仅用于 <=8 字节字段的摘要展示。
    // 返回行为：只读证据行，不可作为写入或 patch 凭据。
    struct RuntimeFieldSampleEntry
    {
        std::uint32_t runtimeItemId = 0;
        std::uint32_t offset = 0;
        std::uint32_t size = 0;
        std::uint32_t status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_ROW_STATUS_UNKNOWN;
        std::uint32_t bytesRead = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t valueU64 = 0;
        std::vector<std::uint8_t> sampleBytes;
        std::string name;
        std::string type;
    };

    // RuntimeFieldSampleResult 承载 process/thread 通用 deep PDB 字段采样响应。
    // 输入：ArkDriverClient 对 0x83E/0x83F 只读 IOCTL 的解析结果。
    // 处理：objectAddress 只用于显示 R0 实际 lookup 到的对象，不回喂任何写操作。
    // 返回行为：unsupported=true 表示旧驱动缺少 sampler IOCTL。
    struct RuntimeFieldSampleResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_RUNTIME_FIELD_SAMPLE_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t entrySize = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::vector<RuntimeFieldSampleEntry> entries;
    };

    // ThreadCrossViewEntry is one ETHREAD/KTHREAD cross-view evidence row.
    // Input: copied from KSWORD_ARK_THREAD_CROSSVIEW_ROW.
    // Processing: target addresses are diagnostic-only and never used as operation credentials.
    // Return behavior: data-only row.
    struct ThreadCrossViewEntry
    {
        std::uint64_t objectAddress = 0;
        std::uint64_t processObjectAddress = 0;
        std::uint64_t startAddress = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t anomalyFlags = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        CrossViewFieldOffsets fieldOffsets;
        long lastStatus = 0;
        std::uint32_t confidence = 0;
        std::uint32_t publicThreadId = 0;
        std::uint32_t threadListThreadId = 0;
        std::uint32_t cidTableThreadId = 0;
        std::uint32_t publicProcessId = 0;
        std::uint32_t threadListProcessId = 0;
        std::uint32_t cidTableProcessId = 0;
        long publicWalkStatus = 0;
        long threadListStatus = 0;
        long cidTableStatus = 0;
        long startAddressStatus = 0;
        std::uint32_t detailStatus = 0;
        std::uint32_t denoiseFlags = 0;
        std::string imageName;
        std::string detail;
    };

    // ThreadCrossViewResult carries a complete thread cross-view query.
    // Input: produced by DriverClient::queryThreadCrossView.
    // Processing: rows may include orphan/CID-only evidence and remain read-only in UI.
    // Return behavior: returned by value; io.ok indicates parseable response.
    struct ThreadCrossViewResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_CROSSVIEW_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        long lastStatus = 0;
        CrossViewFieldOffsets fieldOffsets;
        std::vector<ThreadCrossViewEntry> entries;
    };

    // ThreadRuntimeDetailResult 承载单线程 PDB/DynData 运行时详情。
    // 输入：queryThreadRuntimeDetail 返回。
    // 处理：response 保存 ETHREAD/KTHREAD Cid、链表、栈和 I/O counter 字段。
    // 返回行为：只读展示线程对象，不挂起、不终止、不改链表。
    struct ThreadRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_THREAD_DETAIL_RESPONSE response{};
    };

    // DriverIntegrityEvidenceEntry is one driver/kernel integrity evidence row.
    // Input: copied from KSWORD_ARK_DRIVER_INTEGRITY_EVIDENCE.
    // Processing: evidenceClass groups DriverObject, LDR, FastIo, MajorFunction, CPU,
    // descriptor-table and MSR rows while riskFlags keeps raw R0 findings.
    // Return behavior: plain data object.
    struct DriverIntegrityEvidenceEntry
    {
        std::uint32_t evidenceClass = 0;
        std::uint32_t riskFlags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t confidence = 0;
        std::uint32_t processorGroup = 0;
        std::uint32_t processorNumber = 0;
        std::uint32_t vector = 0;
        std::uint32_t ownerModuleSize = 0;
        std::uint64_t objectAddress = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t ownerModuleBase = 0;
        std::wstring ownerModule;
        std::wstring detail;
        std::uint32_t entryStatus = 0;              // entryStatus：v2 单行状态，老驱动返回 0。
        std::uint32_t statusFlags = 0;              // statusFlags：partial/unsupported/PDB required 等位。
        std::uint32_t fieldMask = 0;                // fieldMask：本行实际填充的 typed 字段位。
        std::uint32_t riskScore = 0;                // riskScore：R0 汇总风险分，0-100。
        std::uint32_t rangeState = 0;               // rangeState：目标地址相对所属驱动镜像的位置。
        std::uint32_t ordinal = 0;                  // ordinal：IRP major/FastIo/attached depth 等序号。
        std::uint32_t deviceType = 0;               // deviceType：DeviceObject 类型字段。
        std::uint32_t deviceFlags = 0;              // deviceFlags：DeviceObject flags。
        std::uint64_t driverObjectAddress = 0;      // driverObjectAddress：关联 DriverObject。
        std::uint64_t driverStart = 0;              // driverStart：DriverObject.DriverStart。
        std::uint64_t driverSize = 0;               // driverSize：DriverObject.DriverSize。
        std::uint64_t driverSection = 0;            // driverSection：DriverObject.DriverSection。
        std::uint64_t driverUnload = 0;             // driverUnload：DriverObject.DriverUnload。
        std::uint64_t deviceObjectAddress = 0;      // deviceObjectAddress：DeviceObject 地址。
        std::uint64_t nextDeviceObjectAddress = 0;  // nextDeviceObjectAddress：NextDevice。
        std::uint64_t attachedDeviceObjectAddress = 0; // attachedDeviceObjectAddress：AttachedDevice。
        std::uint64_t deviceDriverObjectAddress = 0; // deviceDriverObjectAddress：DeviceObject.DriverObject。
        std::uint64_t kldrEntryAddress = 0;         // kldrEntryAddress：KLDR_DATA_TABLE_ENTRY 地址。
        std::uint64_t kldrListHeadAddress = 0;      // kldrListHeadAddress：PsLoadedModuleList 链表头。
        std::uint64_t kldrDllBase = 0;              // kldrDllBase：KLDR.DllBase。
        std::uint32_t kldrSizeOfImage = 0;          // kldrSizeOfImage：KLDR.SizeOfImage。
        std::uint32_t descriptorSelector = 0;       // descriptorSelector：IDT 代码选择子或 GDT 选择子。
        std::uint32_t descriptorType = 0;           // descriptorType：架构 gate/segment type。
        std::uint32_t descriptorDpl = 0;            // descriptorDpl：描述符特权级。
        std::uint32_t descriptorFlags = 0;          // descriptorFlags：KSWORD_ARK_DESCRIPTOR_FLAG_* 位。
        std::uint32_t descriptorSize = 0;           // descriptorSize：8/16 字节描述符宽度。
        std::uint32_t descriptorTableLimit = 0;     // descriptorTableLimit：IDTR/GDTR limit。
        std::uint64_t descriptorTableBase = 0;      // descriptorTableBase：IDTR/GDTR base。
        std::uint64_t descriptorBase = 0;           // descriptorBase：IDT handler 或 GDT segment/TSS base。
        std::uint64_t descriptorLimit = 0;          // descriptorLimit：GDT 有效 limit。
        std::uint64_t descriptorRawLow = 0;         // descriptorRawLow：前 8 字节原始值。
        std::uint64_t descriptorRawHigh = 0;        // descriptorRawHigh：16 字节描述符后 8 字节。
        std::uint32_t descriptorBaselineFlags = 0;  // descriptorBaselineFlags：启动期基线的存在/一致性状态。
        std::uint32_t descriptorBaselineGeneration = 0; // descriptorBaselineGeneration：本次驱动加载生成的基线代次。
        std::uint64_t descriptorBaselineHandler = 0; // descriptorBaselineHandler：启动期 IDT handler。
        std::uint64_t descriptorBaselineRawLow = 0;  // descriptorBaselineRawLow：启动期表项低 8 字节。
        std::uint64_t descriptorBaselineRawHigh = 0; // descriptorBaselineRawHigh：启动期表项高 8 字节。
    };

    // IdtBaselineRestoreResult carries an IDT restore preflight or mutation response.
    // The caller must first issue a non-force request and may only force after an
    // explicit UI confirmation while preserving the exact-current descriptor pair.
    struct IdtBaselineRestoreResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_IDT_RESTORE_STATUS_INVALID_REQUEST;
        std::uint32_t baselineGeneration = 0;
        long lastStatus = 0;
        std::uint64_t entryAddress = 0;
        std::uint64_t beforeRawLow = 0;
        std::uint64_t beforeRawHigh = 0;
        std::uint64_t baselineRawLow = 0;
        std::uint64_t baselineRawHigh = 0;
        std::uint64_t afterRawLow = 0;
        std::uint64_t afterRawHigh = 0;
    };

    struct PiDdbEntry
    {
        std::uint64_t entryAddress = 0;
        std::uint32_t timeDateStamp = 0;
        long loadStatus = 0;
        std::wstring driverName;
    };

    struct PiDdbQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t queryStatus = KSWORD_ARK_PIDDB_QUERY_STATUS_INVALID_LAYOUT;
        std::uint32_t responseFlags = 0;
        std::uint32_t totalRows = 0;
        long lastStatus = 0;
        std::vector<PiDdbEntry> entries;
    };

    struct PiDdbDeleteResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_PIDDB_DELETE_STATUS_INVALID_REQUEST;
        std::uint32_t remainingRows = 0;
        long lastStatus = 0;
        PiDdbEntry matchedEntry;
    };

    // HvmStatusResult preserves the complete VT-x/EPT capability and lifecycle
    // snapshot. A prepared or self-tested response is not an active hypervisor.
    struct HvmStatusResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_HVM_RESPONSE response{};
    };

    // HvmControlResult carries one generation-bound prepare, self-test, or
    // teardown result. The UI owns all persistent warnings and typed consent.
    struct HvmControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_CONTROL_HVM_RESPONSE response{};
    };

    // Read-only EPT/NPT cross-view and IOMMU firmware/runtime evidence.
    // A clean guest-visible result cannot prove an opaque outer SLAT is clean.
    struct SlatIommuAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_SLAT_IOMMU_AUDIT_RESPONSE response{};
    };

    // SystemTimeQueryResult：
    // - 输入：由 DriverClient::querySystemTime 读取；
    // - 处理：保留 R0 的倍率、接管、冲突和构建解析证据；
    // - 返回行为：unsupported 允许旧驱动在 UI 中平稳降级。
    struct SystemTimeQueryResult
    {
        IoResult io; // io：底层 DeviceIoControl 与固定响应校验状态。
        bool unsupported = false; // unsupported：旧驱动未注册系统变速 IOCTL。
        KSWORD_ARK_QUERY_SYSTEM_TIME_RESPONSE response{}; // response：R0 状态快照。
    };

    // SystemTimeControlResult：
    // - 输入：由 DriverClient::controlSystemTime 填充；
    // - 处理：保存动作前后代次与接管状态；
    // - 返回行为：UI 依据 response.status 判断业务成功或安全拒绝。
    struct SystemTimeControlResult
    {
        IoResult io; // io：底层控制 IOCTL 状态。
        bool unsupported = false; // unsupported：当前驱动不支持该协议。
        KSWORD_ARK_CONTROL_SYSTEM_TIME_RESPONSE response{}; // response：控制结果。
    };


    // BugcheckDiagnosticsResult：保留按需安装蓝屏诊断的传输结果和 R0 准备摘要。
    // UI 仅展示回调/BGP 状态，不重新扫描私有内核函数或推断故障原因。
    struct BugcheckDiagnosticsResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_BUGCHECK_DIAGNOSTICS_RESPONSE response{};
    };

    // BugcheckGuardResult keeps the transport result independent from the R0
    // state snapshot, allowing an older driver to degrade safely in the UI.
    struct BugcheckGuardResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_BUGCHECK_GUARD_RESPONSE response{};
    };
    // HvmEptRuleResult preserves one generation-bound EPT rule mutation or
    // query. The response exposes explicit implementation maturity and never
    // treats a prepared table as an active resident monitor.
    struct HvmEptRuleResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_EPT_RULE_RESPONSE response{};
    };

    // HvmEventResult carries a bounded event-ring page. Clearing the ring is a
    // separate explicit operation and does not alter EPT rules or VMX state.
    struct HvmEventResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_HVM_EVENT_QUERY_RESPONSE response{};
    };

    // DriverIntegrityResult carries DriverObject/LDR/CPU integrity evidence.
    // Input: produced by queryDriverIntegrity or queryKernelCpuIntegrity.
    // Processing: unsupported provides graceful UI fallback for older R0 drivers.
    // Return behavior: returned by value with parsed evidence entries.
    struct DriverIntegrityResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE;
        std::uint32_t flags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t fieldFlags = 0;        // fieldFlags：R0 汇总本次响应实际填充的 evidence 字段位。
        std::uint32_t statusFlags = 0;       // statusFlags：R0 汇总 partial/unsupported/truncated/PDB-required 状态位。
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t cpuCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<DriverIntegrityEvidenceEntry> entries;
    };

    // UnloadedDriverEntry：三个内核来源统一投影后的只读记录。
    // flags 中的 HAS_* 位决定 UI 哪些列显示真实值，缺失字段不会被解释为 0。
    struct UnloadedDriverEntry
    {
        std::uint32_t source = 0;
        std::uint32_t flags = 0;
        std::uint64_t entryAddress = 0;
        std::uint64_t baseAddress = 0;
        std::uint64_t imageSize = 0;
        std::uint64_t unloadTime = 0;
        std::uint32_t timeDateStamp = 0;
        long loadStatus = 0;
        std::wstring driverName;
    };

    // UnloadedDriverQueryResult：一次指定来源查询的传输、业务状态与行集合。
    // unsupported 仅表示旧驱动没有该 IOCTL；DynData/profile 缺失由 queryStatus 表达。
    struct UnloadedDriverQueryResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t source = 0;
        std::uint32_t queryStatus = KSWORD_ARK_UNLOADED_DRIVER_STATUS_INVALID_REQUEST;
        std::uint32_t responseFlags = 0;
        std::uint32_t totalRows = 0;
        std::uint32_t skippedRows = 0;
        long lastStatus = 0;
        std::vector<UnloadedDriverEntry> entries;
    };

    // CpuHardwareSnapshotResult carries the read-only R0 CPUID hardware packet.
    // Input: produced by DriverClient::queryCpuHardwareSnapshot.
    // Processing: featureMask is a stable KSWORD_ARK_CPU_FEATURE_* projection while
    // raw CPUID leaves remain available for diagnostics and future UI expansion.
    // Return behavior: returned by value; unsupported=true means the loaded driver
    // predates IOCTL_KSWORD_ARK_QUERY_CPU_HARDWARE.
    struct CpuHardwareSnapshotResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t logicalProcessorCount = 0;
        std::uint32_t activeProcessorCount = 0;
        std::uint32_t packageCount = 0;
        std::uint32_t family = 0;
        std::uint32_t model = 0;
        std::uint32_t stepping = 0;
        std::uint32_t processorType = 0;
        std::uint32_t brandIndex = 0;
        std::uint32_t clflushLineSize = 0;
        std::uint32_t initialApicId = 0;
        std::uint32_t maxBasicLeaf = 0;
        std::uint32_t maxExtendedLeaf = 0;
        long lastStatus = 0;
        std::uint64_t featureMask = 0;
        std::uint64_t leaf1Ecx = 0;
        std::uint64_t leaf1Edx = 0;
        std::uint64_t leaf7Ebx = 0;
        std::uint64_t leaf7Ecx = 0;
        std::uint64_t leaf7Edx = 0;
        std::uint64_t leaf80000001Ecx = 0;
        std::uint64_t leaf80000001Edx = 0;
        std::string vendor;
        std::string brand;
    };

    // PhysicalMemoryLayoutResult is the R3 view of the R0 physical memory map summary.
    // Input: produced by DriverClient::queryPhysicalMemoryLayout.
    // Processing: stores aggregate ranges only; no physical memory bytes or per-page
    // content are returned to the UI.
    // Return behavior: returned by value; unsupported=true means the loaded driver is old.
    struct PhysicalMemoryLayoutResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t rangeCount = 0;
        std::uint32_t zeroLengthRangeCount = 0;
        std::uint32_t truncated = 0;
        long lastStatus = 0;
        std::uint64_t totalPhysicalBytes = 0;
        std::uint64_t highestPhysicalAddress = 0;
        std::uint64_t largestRangeBytes = 0;
        std::uint64_t smallestRangeBytes = 0;
        std::uint64_t firstBaseAddress = 0;
        std::uint64_t lastEndAddress = 0;
        std::uint64_t estimatedAddressSpaceGapBytes = 0;
    };

    // MutationPrepareInput is the safe R3-side representation of a mutation prepare request.
    // Input: UI/future repair paths populate target kind, address, bytes and expected-before bytes.
    // Processing: DriverClient packs the fields into KSWORD_ARK_MUTATION_PREPARE_REQUEST.
    // Return behavior: used as input to prepareMutation; no member function return.
    struct MutationPrepareInput
    {
        std::uint32_t flags = KSWORD_ARK_MUTATION_FLAG_DRY_RUN;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::vector<std::uint8_t> afterBytes;
        std::vector<std::uint8_t> expectedBeforeBytes;
    };

    // MutationResponseResult carries PREPARE/COMMIT/ROLLBACK response metadata.
    // Input: returned by mutation DriverClient methods.
    // Processing: before/after byte arrays are bounded by the shared protocol max.
    // Return behavior: io.ok reports transport and fixed-response parse success.
    struct MutationResponseResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint32_t riskFlags = 0;
        long lastStatus = 0;
        std::uint64_t transactionId = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::uint64_t beforeHash = 0;
        std::uint64_t afterHash = 0;
        std::uint64_t timestampTick = 0;
        std::vector<std::uint8_t> beforeBytes;
        std::vector<std::uint8_t> afterBytes;
    };

    // MutationAuditEntry is one read-only transaction audit row.
    // Input: copied from KSWORD_ARK_MUTATION_AUDIT_ENTRY.
    // Processing: UI displays audit/dry-run/rollback status only; no arbitrary-write button is exposed.
    // Return behavior: data-only row.
    struct MutationAuditEntry
    {
        std::uint32_t operation = KSWORD_ARK_MUTATION_OPERATION_UNKNOWN;
        std::uint32_t status = KSWORD_ARK_MUTATION_STATUS_UNKNOWN;
        long lastStatus = 0;
        std::uint32_t targetKind = KSWORD_ARK_MUTATION_TARGET_UNKNOWN;
        std::uint32_t riskFlags = 0;
        std::uint32_t flags = 0;
        std::uint32_t processId = 0;
        std::uint32_t bytes = 0;
        std::uint64_t transactionId = 0;
        std::uint64_t sequence = 0;
        std::uint64_t targetAddress = 0;
        std::uint64_t targetContext = 0;
        std::uint64_t beforeHash = 0;
        std::uint64_t afterHash = 0;
        std::uint64_t timestampTick = 0;
        std::vector<std::uint8_t> byteData;
    };

    // MutationAuditResult carries the bounded R0 audit ring snapshot.
    // Input: produced by DriverClient::queryMutationAudit.
    // Processing: unsupported distinguishes missing transaction IOCTL from empty audit rings.
    // Return behavior: returned by value; entries contains parsed audit rows.
    struct MutationAuditResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t lostCount = 0;
        std::uint64_t oldestSequence = 0;
        std::uint64_t nextSequence = 0;
        std::vector<MutationAuditEntry> entries;
    };

    // SsdtEntry is the R3 model of one kernel SSDT response row.
    struct SsdtEntry
    {
        std::uint32_t serviceIndex = 0;
        std::uint32_t flags = 0;
        std::uint64_t zwRoutineAddress = 0;
        std::uint64_t serviceRoutineAddress = 0;
        std::uint64_t tableEntryAddress = 0;
        std::uint64_t currentTableValue = 0;
        std::uint32_t tableEntrySize = 0;
        std::string serviceName;
        std::string moduleName;
    };

    // SsdtEnumResult carries parsed SSDT rows and response header metadata.
    struct SsdtEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint64_t serviceTableBase = 0;
        std::uint32_t serviceCountFromTable = 0;
        std::vector<SsdtEntry> entries;
    };

    // KernelInlineHookEntry 是 R0 Inline Hook 扫描返回的一行 R3 模型。
    struct KernelInlineHookEntry
    {
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN; // 行状态。
        std::uint32_t hookType = KSWORD_ARK_INLINE_HOOK_TYPE_NONE;    // 命中的补丁形态。
        std::uint32_t flags = 0;                                      // R0 诊断标志。
        std::uint32_t originalByteCount = 0;                          // R0 观察基线字节长度；不是磁盘原始字节长度。
        std::uint32_t currentByteCount = 0;                           // 当前字节长度。
        std::uint64_t functionAddress = 0;                            // 函数入口地址。
        std::uint64_t targetAddress = 0;                              // 跳转/补丁目标。
        std::uint64_t moduleBase = 0;                                 // 所属模块基址。
        std::uint64_t targetModuleBase = 0;                           // 目标模块基址。
        std::string functionName;                                     // 导出函数名。
        std::wstring moduleName;                                      // 所属模块名。
        std::wstring targetModuleName;                                // 目标模块名。
        std::vector<std::uint8_t> currentBytes;                       // 当前函数头字节。
        std::vector<std::uint8_t> expectedBytes;                      // 协议兼容字段：R0 观察基线，不代表磁盘原始字节。
    };

    // KernelInlineHookScanResult 承载 R0 Inline Hook 扫描响应。
    struct KernelInlineHookScanResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<KernelInlineHookEntry> entries;
    };

    // KernelInlinePatchResult 承载 R0 Inline Hook 摘除/修复响应。
    struct KernelInlinePatchResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t bytesPatched = 0;
        std::uint32_t fieldFlags = 0;
        long lastStatus = 0;
        std::uint64_t functionAddress = 0;
        std::vector<std::uint8_t> beforeBytes;
        std::vector<std::uint8_t> afterBytes;
    };

    // KernelIatEatHookEntry 是内核模块 IAT/EAT 指针检查的一行 R3 模型。
    struct KernelIatEatHookEntry
    {
        std::uint32_t hookClass = KSWORD_ARK_IAT_EAT_HOOK_CLASS_IAT; // IAT 或 EAT。
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN; // 行状态。
        std::uint32_t flags = 0;                                      // R0 诊断标志。
        std::uint32_t ordinal = 0;                                    // 导出序号或 thunk 序号。
        std::uint64_t moduleBase = 0;                                 // 所属模块基址。
        std::uint64_t thunkAddress = 0;                               // IAT thunk 或 EAT 项地址。
        std::uint64_t currentTarget = 0;                              // 当前目标地址。
        std::uint64_t expectedTarget = 0;                             // 期望目标地址。
        std::uint64_t targetModuleBase = 0;                           // 目标模块基址。
        std::string functionName;                                     // 函数名或占位符。
        std::wstring moduleName;                                      // 所属模块名。
        std::wstring importModuleName;                                // IAT 声明导入模块名。
        std::wstring targetModuleName;                                // 当前目标模块名。
    };

    // KernelIatEatHookScanResult 承载 R0 IAT/EAT 扫描响应。
    struct KernelIatEatHookScanResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KERNEL_HOOK_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t moduleCount = 0;
        long lastStatus = 0;
        std::vector<KernelIatEatHookEntry> entries;
    };

    // KernelTimerDpcEntry 是 R0 从每个 KPRCB TimerTable 返回的一条只读快照。
    struct KernelTimerDpcEntry
    {
        std::uint16_t processorGroup = 0;
        std::uint16_t processorNumber = 0;
        std::uint32_t bucketIndex = 0;
        std::uint32_t flags = 0;
        std::uint32_t timerType = 0;
        std::int32_t period = 0;
        std::int64_t dueTime = 0;
        std::uint64_t timerAddress = 0;
        std::uint64_t dpcAddress = 0;
        std::uint64_t deferredRoutine = 0;
        std::uint64_t deferredContext = 0;
    };

    // KernelTimerDpcEnumResult 保留枚举完整性标记，UI 不把 partial 当成完整快照。
    struct KernelTimerDpcEnumResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED;
        std::uint32_t statusFlags = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t processorCount = 0;
        std::uint32_t bucketCount = 0;
        std::uint32_t bucketsVisited = 0;
        std::uint32_t corruptBucketCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t duplicateCount = 0;
        long lastStatus = 0;
        std::vector<KernelTimerDpcEntry> entries;
    };

    // DriverMajorFunctionEntry 是 Phase-9 DriverObject.MajorFunction 单行模型。
    struct DriverMajorFunctionEntry
    {
        std::uint32_t majorFunction = 0;       // IRP_MJ_* 编号。
        std::uint32_t flags = 0;               // R0 诊断 flags。
        std::uint64_t dispatchAddress = 0;     // dispatch 入口地址，仅展示。
        std::uint64_t moduleBase = 0;          // 所属模块基址，仅展示。
        std::wstring moduleName;               // 所属模块名。
    };

    // DriverDeviceEntry 是 Phase-9 DeviceObject/AttachedDevice 单行模型。
    struct DriverDeviceEntry
    {
        std::uint32_t relationDepth = 0;       // 0=DriverObject->DeviceObject 链，>0=AttachedDevice 深度。
        std::uint32_t deviceType = 0;          // DEVICE_TYPE。
        std::uint32_t flags = 0;               // DO_* flags。
        std::uint32_t characteristics = 0;     // FILE_DEVICE_* characteristics。
        std::uint32_t stackSize = 0;           // DeviceObject.StackSize。
        std::uint32_t alignmentRequirement = 0;// DeviceObject.AlignmentRequirement。
        long nameStatus = 0;                   // ObQueryNameString 状态。
        std::uint64_t rootDeviceObjectAddress = 0; // 根 DeviceObject。
        std::uint64_t deviceObjectAddress = 0;     // 当前 DeviceObject。
        std::uint64_t nextDeviceObjectAddress = 0; // NextDevice。
        std::uint64_t attachedDeviceObjectAddress = 0; // AttachedDevice。
        std::uint64_t driverObjectAddress = 0;    // DeviceObject.DriverObject。
        std::wstring deviceName;              // 设备对象名，可能为空。
        std::uint64_t ioTimerAddress = 0;      // DeviceObject.Timer；只读诊断地址。
    };

    // DriverObjectQueryResult 承载 Phase-9 DriverObject/DeviceObject 查询响应。
    struct DriverObjectQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t queryStatus = KSWORD_ARK_DRIVER_OBJECT_QUERY_STATUS_UNAVAILABLE;
        std::uint32_t fieldFlags = 0;
        std::uint32_t majorFunctionCount = 0;
        std::uint32_t totalDeviceCount = 0;
        std::uint32_t returnedDeviceCount = 0;
        long lastStatus = 0;
        std::uint32_t driverFlags = 0;
        std::uint32_t driverSize = 0;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t driverStart = 0;
        std::uint64_t driverSection = 0;
        std::uint64_t driverUnload = 0;
        std::wstring driverName;
        std::wstring serviceKeyName;
        std::wstring imagePath;
        std::vector<DriverMajorFunctionEntry> majorFunctions;
        std::vector<DriverDeviceEntry> devices;
    };

    // IoTimerControlResult 保留 R0 对 DriverObject/DeviceObject/PIO_TIMER
    // 三重身份的重新观察结果，不把输入地址当作可解引用句柄。
    struct IoTimerControlResult
    {
        IoResult io;                           // io：DeviceIoControl 传输/协议状态。
        bool unsupported = false;              // unsupported：旧驱动未注册控制 IOCTL。
        std::uint32_t version = 0;             // version：响应协议版本。
        std::uint32_t status = KSWORD_ARK_IO_TIMER_CONTROL_STATUS_INVALID_REQUEST; // status：R0 语义结果。
        std::uint32_t action = 0;              // action：启动/停止动作回显。
        long lastStatus = 0;                   // lastStatus：协议、对象或枚举 NTSTATUS。
        std::uint64_t observedDriverObjectAddress = 0; // observedDriverObjectAddress：按名称重新引用结果。
        std::uint64_t observedDeviceObjectAddress = 0; // observedDeviceObjectAddress：带引用设备快照结果。
        std::uint64_t observedTimerAddress = 0;        // observedTimerAddress：公开 DEVICE_OBJECT.Timer 快照。
    };

    // IoctlRegistryEntry 承载 KswordARK dispatch registry 的一条只读诊断行。
    struct IoctlRegistryEntry
    {
        std::uint32_t ioControlCode = 0;       // ioControlCode：完整 CTL_CODE。
        std::uint32_t functionNumber = 0;      // functionNumber：CTL_CODE 的 function 部分。
        std::uint32_t method = 0;              // method：METHOD_BUFFERED 等传输方式。
        std::uint32_t access = 0;              // access：FILE_ANY_ACCESS/READ/WRITE。
        std::uint32_t flags = 0;                // flags：dispatch registry flags。
        std::uint64_t requiredCapability = 0;  // requiredCapability：DynData capability 门槛。
        std::uint64_t handlerAddress = 0;       // handlerAddress：可选 handler 诊断地址。
        std::string name;                       // name：注册表中的固定名称。
    };

    // IoctlRegistryQueryResult 承载 KswordARK 自身 IOCTL registry 查询响应。
    struct IoctlRegistryQueryResult
    {
        IoResult io;                            // io：DeviceIoControl 传输状态。
        bool unsupported = false;               // unsupported：旧驱动未注册查询 IOCTL。
        std::uint32_t version = 0;              // version：协议版本。
        std::uint32_t status = 0;               // status：完整/截断状态。
        std::uint32_t totalCount = 0;           // totalCount：R0 registry 总行数。
        std::uint32_t returnedCount = 0;        // returnedCount：本次返回行数。
        std::uint32_t duplicateCount = 0;       // duplicateCount：重复控制码数量。
        long lastStatus = 0;                    // lastStatus：R0 查询状态。
        std::vector<IoctlRegistryEntry> entries; // entries：按 dispatch 顺序排列的行。
    };

    // DriverForceUnloadResult 承载 R0 DriverObject 强制卸载响应。
    struct DriverForceUnloadResult
    {
        IoResult io;                         // io：DeviceIoControl 调用状态。
        std::uint32_t version = 0;           // version：协议版本。
        std::uint32_t status = KSWORD_ARK_DRIVER_UNLOAD_STATUS_UNKNOWN; // status：卸载聚合状态。
        std::uint32_t flags = 0;             // flags：请求 flags 回显。
        long lastStatus = 0;                 // lastStatus：卸载线程/后端状态。
        long waitStatus = 0;                 // waitStatus：KeWaitForSingleObject 状态。
        std::uint32_t cleanupFlagsApplied = 0; // cleanupFlagsApplied：R0 实际执行的持久清理 flags。
        std::uint32_t deletedDeviceCount = 0;  // deletedDeviceCount：R0 实际删除的 DeviceObject 数量。
        std::uint64_t driverObjectAddress = 0; // driverObjectAddress：诊断地址。
        std::uint64_t driverUnloadAddress = 0; // driverUnloadAddress：DriverUnload 入口。
        std::uint32_t callbackCandidates = 0;  // callbackCandidates：按模块基址命中的回调候选数。
        std::uint32_t callbacksRemoved = 0;    // callbacksRemoved：R0 成功移除的回调数。
        std::uint32_t callbackFailures = 0;    // callbackFailures：R0 移除失败或不支持的回调数。
        long callbackLastStatus = 0;           // callbackLastStatus：最后一个回调移除失败状态。
        std::uint32_t threadCandidates = 0;    // threadCandidates：目标镜像驻留系统线程数。
        std::uint32_t threadsTerminated = 0;   // threadsTerminated：已终止并确认退出的线程数。
        std::uint32_t threadFailures = 0;      // threadFailures：终止或等待失败的线程数。
        long threadLastStatus = 0;             // threadLastStatus：最后一个线程处理失败状态。
        std::uint32_t detachedDeviceCount = 0; // detachedDeviceCount：强拆时解除的上下层设备关联数。
        std::wstring driverName;             // driverName：R0 规范化对象名。
    };

    // DriverCommunicationControlResult：
    // - 作用：承载 Issue #47 的 IRP 通信致盲、查询和恢复响应；
    // - 边界：只展示 R0 返回的地址与掩码，R3 不保存或回传原始 dispatch 指针。
    struct DriverCommunicationControlResult
    {
        IoResult io;                              // io：DeviceIoControl 传输和协议校验状态。
        std::uint32_t version = 0;               // version：响应协议版本。
        std::uint32_t action = 0;                // action：QUERY、BLIND 或 RESTORE。
        std::uint32_t state = KSWORD_ARK_DRIVER_COMMUNICATION_STATE_INACTIVE; // state：当前 R0 记录状态。
        std::uint32_t responseFlags = 0;         // responseFlags：foreign-change 等诊断位。
        long lastStatus = 0;                     // lastStatus：实际控制动作的 NTSTATUS。
        std::uint32_t targetedMask = 0;          // targetedMask：本功能固定管理的 MajorFunction 掩码。
        std::uint32_t changedMask = 0;           // changedMask：本次成功修改或恢复的槽位。
        std::uint32_t activeMask = 0;            // activeMask：当前实际指向系统拒绝入口的槽位。
        std::uint32_t ownedMask = 0;             // ownedMask：当前仍由本功能拥有恢复资格的槽位。
        std::uint32_t conflictMask = 0;          // conflictMask：恢复时检测到第三方改写的槽位。
        std::uint32_t generation = 0;            // generation：目标记录的幂等操作代次。
        std::uint64_t driverObjectAddress = 0;   // driverObjectAddress：只读诊断地址。
        std::uint64_t driverStart = 0;           // driverStart：用于核对模块基址的驱动镜像起点。
        std::uint64_t rejectDispatchAddress = 0; // rejectDispatchAddress：R0 捕获的系统拒绝入口。
        std::wstring driverName;                 // driverName：R0 返回的 canonical DriverObject 名称。
    };

    // DriverDispatchControlResult：任意 DriverObject.MajorFunction 单槽事务结果。
    // 指针字段是显式高级编辑数据；R0 不限制目标类别或地址归属。
    struct DriverDispatchControlResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t version = 0;
        std::uint32_t action = 0;
        std::uint32_t state = KSWORD_ARK_DRIVER_DISPATCH_STATE_INACTIVE;
        std::uint32_t responseFlags = 0;
        long lastStatus = 0;
        std::uint32_t majorFunction = 0;
        std::uint32_t generation = 0;
        std::uint64_t targetModuleBase = 0;
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t currentDispatchAddress = 0;
        std::uint64_t originalDispatchAddress = 0;
        std::uint64_t appliedDispatchAddress = 0;
        std::uint64_t requestedDispatchAddress = 0;
        std::uint64_t selfDriverObjectAddress = 0;
        std::wstring driverName;
    };

    // DriverImageValues：五个可独立选择的 DriverObject/KLDR 镜像元数据值。
    // 所有字段在 R3 使用 64 位承载；R0 仅对两个自然 ULONG 字段执行宽度检查。
    struct DriverImageValues
    {
        std::uint64_t driverStart = 0;       // driverStart：DriverObject->DriverStart。
        std::uint64_t driverSize = 0;        // driverSize：DriverObject->DriverSize。
        std::uint64_t driverSection = 0;     // driverSection：DriverObject->DriverSection。
        std::uint64_t kldrDllBase = 0;       // kldrDllBase：KLDR_DATA_TABLE_ENTRY.DllBase。
        std::uint64_t kldrSizeOfImage = 0;   // kldrSizeOfImage：KLDR SizeOfImage。
    };

    // DriverImageControlResult：任意驱动镜像字段和 PsLoadedModuleList 事务响应。
    // 地址、链和冲突信息全部来自 R0；R3 不按驱动类别或值归属过滤。
    struct DriverImageControlResult
    {
        IoResult io;                         // io：传输、协议校验与 NTSTATUS。
        bool unsupported = false;            // unsupported：旧驱动未注册新 IOCTL。
        std::uint32_t version = 0;            // version：协议版本。
        std::uint32_t action = 0;             // action：查询、应用、隐藏、恢复或放弃。
        std::uint32_t state = KSWORD_ARK_DRIVER_IMAGE_STATE_INACTIVE;
        std::uint32_t responseFlags = 0;      // responseFlags：链、归属、冲突和恢复位置标志。
        long lastStatus = 0;                  // lastStatus：实际事务 NTSTATUS。
        long loaderStatus = 0;                // loaderStatus：加载器布局/资源解析状态。
        std::uint32_t generation = 0;         // generation：CAS 事务代次。
        std::uint32_t managedFieldMask = 0;   // managedFieldMask：仍有恢复记录的字段。
        std::uint32_t ownedFieldMask = 0;     // ownedFieldMask：当前仍等于已应用值。
        std::uint32_t conflictFieldMask = 0;  // conflictFieldMask：第三方已改写字段。
        std::uint32_t changedFieldMask = 0;   // changedFieldMask：本次实际改变字段。
        std::uint32_t layoutFlags = 0;        // layoutFlags：DynData/export 验证来源。
        std::uint64_t targetModuleBase = 0;   // targetModuleBase：首次身份模块基址。
        std::uint64_t driverObjectAddress = 0;
        std::uint64_t selfDriverObjectAddress = 0;
        std::uint64_t loaderEntryAddress = 0;
        std::uint64_t listHeadAddress = 0;
        std::uint64_t listResourceAddress = 0;
        std::uint64_t loaderLinkAddress = 0;
        std::uint64_t currentLinkFlink = 0;
        std::uint64_t currentLinkBlink = 0;
        std::uint64_t originalLinkFlink = 0;
        std::uint64_t originalLinkBlink = 0;
        DriverImageValues currentValues;
        DriverImageValues originalValues;
        DriverImageValues appliedValues;
        DriverImageValues requestedValues;
        std::wstring driverName;              // driverName：R0 canonical 对象名。
    };

    // CallbackRuntimeResult wraps the runtime-state response packet.
    struct CallbackRuntimeResult
    {
        IoResult io;
        KSWORD_ARK_CALLBACK_RUNTIME_STATE state{};
    };

    // MinifilterBypassPidResult wraps the fixed PID whitelist response.
    // Input: none; DriverClient::queryMinifilterBypassPids fills this struct.
    // Processing: io reports transport/protocol success and response carries
    // the full R0 whitelist snapshot.
    // Return behavior: the struct itself has no methods; callers inspect io.ok.
    struct MinifilterBypassPidResult
    {
        IoResult io;
        KSWORD_ARK_MINIFILTER_BYPASS_PID_RESPONSE response{};
    };

    // ProcessProtectStateResult wraps the handle-callback process protection state.
    // 输入：无；DriverClient::queryProcessProtectState 负责填充。
    // 处理：io 记录传输/协议结果，response 是 R0 当前生效的完整保护配置与计数器。
    // 返回：结构本身无方法；调用方先看 io.ok，再看 response.capabilityStatus
    //       区分"没配规则"和"这台机器上句柄回调挂不上"。
    struct ProcessProtectStateResult
    {
        IoResult io;
        KSWORD_ARK_PROCESS_PROTECT_STATE_RESPONSE response{};
    };

    // CallbackRemoveResult wraps the legacy external-callback removal response packet.
    struct CallbackRemoveResult
    {
        IoResult io;
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_RESPONSE response{};
    };

    // CallbackRemoveExResult wraps the extended removal response.
    // Input: none; it is returned by DriverClient::removeExternalCallbackEx.
    // Processing: keeps public-API and experimental-unlink diagnostics together.
    // Return behavior: io.ok reports transport/protocol success; response.ntstatus
    // reports the kernel operation result.
    struct CallbackRemoveExResult
    {
        IoResult io;
        KSWORD_ARK_REMOVE_EXTERNAL_CALLBACK_EX_RESPONSE response{};
    };

    // CallbackEnumEntry 是 R0 回调遍历的一行 R3 模型。
    struct CallbackEnumEntry
    {
        std::uint32_t callbackClass = 0;
        std::uint32_t source = 0;
        std::uint32_t status = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t trustFlags = 0;        // trustFlags：PDB/public/fallback/revalidated 可信位。
        std::uint32_t removeBehavior = 0;    // removeBehavior：R0 推荐的公开 API/实验 unlink 行为。
        std::uint32_t removeFlags = 0;       // removeFlags：兼容旧 UI 命名，始终镜像 removeBehavior。
        std::uint32_t operationMask = 0;
        std::uint32_t objectTypeMask = 0;
        std::uint32_t registrationType = 0; // registrationType：Legacy/Ex/Ex2 等具体注册 API 类型。
        std::uint64_t generation = 0;        // generation：R0 枚举代次，用于 EX 移除前重验证。
        long lastStatus = 0;
        std::uint64_t callbackAddress = 0;
        std::uint64_t contextAddress = 0;
        std::uint64_t registrationAddress = 0;
        std::uint64_t identityHash = 0;      // identityHash：协议 v3 的稳定逐行身份哈希；旧协议保持 0。
        std::uint64_t rawStorageValue = 0;   // rawStorageValue：R0 原始注册槽值；旧协议未提供时为 0。
        std::uint64_t moduleBase = 0;
        std::uint32_t moduleSize = 0;
        std::uint32_t detailCode = KSWORD_ARK_CALLBACK_ENUM_DETAIL_NONE;
        std::uint64_t detailArgs[KSWORD_ARK_CALLBACK_ENUM_DETAIL_ARG_COUNT]{};
        std::wstring name;
        std::wstring altitude;
        std::wstring modulePath;
        std::wstring detail;
    };

    // CallbackEnumResult 承载 R0 回调遍历响应。
    struct CallbackEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t snapshotGeneration = 0; // snapshotGeneration：本次稳定快照令牌。
        std::uint64_t snapshotHash = 0;       // snapshotHash：全量有序回调集合哈希。
        std::uint32_t pageCount = 0;          // pageCount：成功接收的数据页数。
        std::uint32_t snapshotRetryCount = 0; // snapshotRetryCount：检测到并发变化后的重试次数。
        bool snapshotConsistent = false;      // snapshotConsistent：v3 最终校验探针已确认一致。
        std::vector<CallbackEnumEntry> entries;
    };

    // KeyboardHotkeyEntry 是 R0 win32k RegisterHotKey 内部表的一行 R3 模型。
    struct KeyboardHotkeyEntry
    {
        std::uint32_t source = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t flags = 0;
        std::uint32_t bucketIndex = 0;
        std::uint32_t depth = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t modifierFlags2 = 0;
        std::uint32_t virtualKey = 0;
        std::uint32_t hotkeyId = 0;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        long lastStatus = 0;
        std::uint64_t hotkeyObject = 0;
        std::uint64_t nextHotkeyObject = 0;
        std::uint64_t sessionGlobals = 0;
        std::uint64_t threadInfo = 0;
        std::uint64_t threadObject = 0;
        std::uint64_t windowObject = 0;
        std::uint64_t windowHandle = 0;
        std::uint64_t destinationHandle = 0;
        std::uint64_t callbackAddress = 0;
        std::uint64_t childListFlink = 0;
        std::uint64_t childListBlink = 0;
        std::uint64_t snapshotHash = 0;
        std::uint32_t objectSize = 0;
        std::uint32_t entryFlags = 0;
        std::wstring detail;
    };

    // KeyboardHotkeyEnumResult 承载 R0 键盘热键枚举响应。
    struct KeyboardHotkeyEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t win32kBase = 0;
        std::uint64_t sessionGlobals = 0;
        std::uint32_t tableOffset = 0;
        std::uint32_t hotkeyNextOffset = 0;
        std::uint32_t hotkeyModifiersOffset = 0;
        std::uint32_t hotkeyVkOffset = 0;
        std::uint32_t hotkeyIdOffset = 0;
        std::vector<KeyboardHotkeyEntry> entries;
    };


    // KeyboardHotkeyMutationResult 承载一次快照保护的 R0 热键编辑或删除响应。
    struct KeyboardHotkeyMutationResult
    {
        IoResult io;
        KSWORD_ARK_MUTATE_KEYBOARD_HOTKEY_RESPONSE response{};
    };

    // KeyboardHookEntry 是 R0 win32k WH_KEYBOARD/WH_KEYBOARD_LL 链的一行 R3 模型。
    struct KeyboardHookEntry
    {
        std::uint32_t source = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t flags = 0;
        std::uint32_t hookType = 0;
        std::uint32_t hookScope = KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        std::uint32_t moduleId = 0;
        long lastStatus = 0;
        std::uint64_t hookObject = 0;
        std::uint64_t chainHead = 0;
        std::uint64_t nextHookObject = 0;
        std::uint64_t threadInfo = 0;
        std::uint64_t targetThreadInfo = 0;
        std::uint64_t desktopInfo = 0;
        std::uint64_t procedureAddress = 0;
        std::uint64_t procedureOffset = 0;
        std::uint64_t moduleBase = 0;
        std::wstring detail;
    };

    // KeyboardHookEnumResult 承载 R0 键盘钩子枚举响应。
    struct KeyboardHookEnumResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t status = KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNKNOWN;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::uint32_t flags = 0;
        long lastStatus = 0;
        std::uint64_t win32kBase = 0;
        std::uint32_t threadHookArrayOffset = 0;
        std::uint32_t desktopInfoOffset = 0;
        std::uint32_t desktopHookArrayOffset = 0;
        std::uint32_t hookNextOffset = 0;
        std::uint32_t hookTypeOffset = 0;
        std::uint32_t hookProcedureOffset = 0;
        std::uint32_t hookFlagsOffset = 0;
        std::uint32_t hookModuleIdOffset = 0;
        std::uint32_t hookTargetThreadInfoOffset = 0;
        std::vector<KeyboardHookEntry> entries;
    };

    // ArkDynModuleIdentity 是 R3 侧模块身份展示结构。
    struct ArkDynModuleIdentity
    {
        bool present = false;
        std::uint32_t classId = 0;
        std::uint32_t machine = 0;
        std::uint32_t timeDateStamp = 0;
        std::uint32_t sizeOfImage = 0;
        std::uint64_t imageBase = 0;
        std::wstring moduleName;
    };

    // DynDataStatusResult 承载 R0 DynData 状态与匹配诊断。
    struct DynDataStatusResult
    {
        IoResult io;
        std::uint32_t statusFlags = 0;
        std::uint32_t systemInformerDataVersion = 0;
        std::uint32_t systemInformerDataLength = 0;
        long lastStatus = 0;
        std::uint32_t matchedProfileClass = 0;
        std::uint32_t matchedProfileOffset = 0;
        std::uint32_t matchedFieldsId = 0;
        std::uint32_t fieldCount = 0;
        std::uint64_t capabilityMask = 0;
        ArkDynModuleIdentity ntoskrnl;
        ArkDynModuleIdentity lxcore;
        std::wstring unavailableReason;
    };

    // DynDataFieldEntry 是 R3 侧字段行模型。
    struct DynDataFieldEntry
    {
        std::uint32_t fieldId = 0;
        std::uint32_t flags = 0;
        std::uint32_t source = 0;
        std::uint32_t offset = 0;
        std::uint64_t capabilityMask = 0;
        std::string fieldName;
        std::string sourceName;
        std::string featureName;
    };

    // DynDataFieldsResult 承载字段列表响应。
    struct DynDataFieldsResult
    {
        IoResult io;
        std::uint32_t totalCount = 0;
        std::uint32_t returnedCount = 0;
        std::vector<DynDataFieldEntry> entries;
    };

    // DynDataCapabilitiesResult 承载轻量 capability 查询响应。
    struct DynDataCapabilitiesResult
    {
        IoResult io;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
    };

    // DynDataProfileField 是 R3 JSON profile 解析后的单个字段包。
    // 输入：fieldId/offset 来自 profiles/ark_dyndata JSON。
    // 处理：ArkDriverClient 将该数组打包为 KSW_APPLY_DYN_PROFILE_REQUEST。
    // 返回行为：结构本身无返回值，只作为 applyDynDataProfile 的输入。
    struct DynDataProfileField
    {
        std::uint32_t fieldId = 0;
        std::uint32_t offset = 0;
    };

    // DynDataProfileExItem 是 v2 profile pack 展开后的 typed item。
    // 输入：itemId/itemKind/value/flags 来自 R3 JSON pack 校验结果。
    // 处理：ArkDriverClient 只做 packed IOCTL 传输；语义校验由 R3/R0 双层完成。
    // 返回行为：结构本身无返回值，只作为 applyDynDataProfileEx 的输入元素。
    struct DynDataProfileExItem
    {
        std::uint32_t itemId = 0;
        std::uint32_t itemKind = 0;
        std::uint32_t value = 0;
        std::uint32_t flags = 0;
    };

    // DynDataProfileApplyInput 是驱动 apply IOCTL 的 R3 输入模型。
    // 输入：profile 元数据、当前 ntoskrnl identity 和字段列表。
    // 处理：客户端只负责协议打包，不解析 JSON 语义。
    // 返回行为：传入 applyDynDataProfile 后得到 DynDataProfileApplyResult。
    struct DynDataProfileApplyInput
    {
        std::string profileName;
        std::string pdbName;
        std::string pdbGuid;
        std::uint32_t pdbAge = 0;
        ArkDynModuleIdentity ntoskrnl;
        std::vector<DynDataProfileField> fields;
    };

    // DynDataProfileApplyResult 承载 R0 合并 PDB profile 后的固定响应。
    // 输入：无，由 DriverClient::applyDynDataProfile 返回。
    // 处理：保存 R0 校验结果、应用字段数、状态位和消息。
    // 返回行为：io.ok 表示 IOCTL 调用和协议响应可用；status 表示 R0 语义结果。
    struct DynDataProfileApplyResult
    {
        IoResult io;
        long status = 0;
        std::uint32_t appliedFieldCount = 0;
        std::uint32_t rejectedFieldCount = 0;
        std::uint32_t unknownFieldCount = 0;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
        std::wstring message;
    };

    // DynDataProfileApplyExInput 是 v2 typed item apply 的 R3 输入模型。
    // 输入：profile 元数据、当前 ntoskrnl identity 和 v2 items。
    // 处理：客户端打包成 KSW_APPLY_DYN_PROFILE_EX_REQUEST。
    // 返回行为：传入 applyDynDataProfileEx 后得到 DynDataProfileApplyExResult。
    struct DynDataProfileApplyExInput
    {
        std::string profileName;
        std::string pdbName;
        std::string pdbGuid;
        std::uint32_t pdbAge = 0;
        ArkDynModuleIdentity ntoskrnl;
        std::vector<DynDataProfileExItem> items;
    };

    // DynDataProfileApplyExResult 承载 R0 合并 v2 typed item 后的响应。
    // 输入：无，由 DriverClient::applyDynDataProfileEx 返回。
    // 处理：保存 item 级应用/拒绝/未知计数、状态位和 capability。
    // 返回行为：io.ok 表示 IOCTL 调用和协议响应可用；status 表示 R0 语义结果。
    struct DynDataProfileApplyExResult
    {
        IoResult io;
        long status = 0;
        std::uint32_t appliedItemCount = 0;
        std::uint32_t rejectedItemCount = 0;
        std::uint32_t unknownItemCount = 0;
        std::uint32_t statusFlags = 0;
        std::uint64_t capabilityMask = 0;
        std::wstring message;
    };

    // DriverFeatureCapabilityEntry 是统一能力矩阵的一行 R3 模型。
    struct DriverFeatureCapabilityEntry
    {
        std::uint32_t featureId = 0;
        std::uint32_t state = 0;
        std::uint32_t flags = 0;
        std::uint32_t requiredPolicyFlags = 0;
        std::uint32_t deniedPolicyFlags = 0;
        std::uint64_t requiredDynDataMask = 0;
        std::uint64_t presentDynDataMask = 0;
        std::string featureName;
        std::string stateName;
        std::string dependencyText;
        std::string reasonText;
    };

    // DriverCapabilitiesQueryResult 承载 Phase 1 统一能力查询响应。
    struct DriverCapabilitiesQueryResult
    {
        IoResult io;
        std::uint32_t version = 0;
        std::uint32_t driverProtocolVersion = 0;
        std::uint32_t statusFlags = 0;
        std::uint32_t securityPolicyFlags = 0;
        std::uint32_t dynDataStatusFlags = 0;
        long lastErrorStatus = 0;
        std::uint32_t totalFeatureCount = 0;
        std::uint32_t returnedFeatureCount = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::string lastErrorSource;
        std::string lastErrorSummary;
        std::vector<DriverFeatureCapabilityEntry> entries;
    };


    // VariableAuditResultBase 保存所有新增只读审计 wrapper 共用的 IO 状态。
    // 输入：由 ArkDriverAudit.cpp 在解析 METHOD_BUFFERED 响应时填充。
    // 处理：unsupported 用于区分旧驱动未注册 IOCTL 与协议解析失败。
    // 返回行为：结构体本身无函数返回；调用方读取字段展示 R0 审计状态。
    struct VariableAuditResultBase
    {
        IoResult io;                         // io：底层 DeviceIoControl 与协议解析结果。
        bool unsupported = false;            // unsupported：旧驱动缺少该 IOCTL 或明确返回不支持。
        std::uint32_t version = 0;           // version：共享协议版本。
        std::uint32_t status = 0;            // status：协议定义的总体状态。
        std::uint32_t flags = 0;             // flags：响应级标志或查询标志。
        std::uint32_t totalCount = 0;        // totalCount：R0 观察到的总行数。
        std::uint32_t returnedCount = 0;     // returnedCount：R0 写入输出缓冲的行数。
        std::uint32_t entrySize = 0;         // entrySize：单行协议结构大小。
        long lastStatus = 0;                 // lastStatus：R0 最近一次 NTSTATUS。
    };

    // NetworkEndpointAuditResult 承载 TCP/UDP endpoint 的 PDB/R0 只读审计结果。
    // 输入：queryNetworkTcpEndpoints/queryNetworkUdpEndpoints 返回。
    // 处理：entries 直接保存 shared/driver 协议行，避免 UI 重新定义字段。
    // 返回行为：io.ok 表示传输和协议解析成功，unsupported 表示旧驱动缺入口。
    struct NetworkEndpointAuditResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial：APPLIED 但只返回预算内子集。
        bool truncated = false;               // truncated：totalCount 大于 returnedCount。
        std::uint32_t sourceFlags = 0;        // sourceFlags：tcpip/netio/runtime 等证据来源。
        std::uint32_t budgetRows = 0;         // budgetRows：R0 实际接受的行预算。
        std::uint32_t generation = 0;         // generation：R0 快照代数。
        std::vector<KSWORD_ARK_NETWORK_ENDPOINT_ROW> entries;
    };

    // NetworkWfpInventoryResult 承载 WFP provider/sublayer/filter/callout 只读审计结果。
    // 输入：queryNetworkWfpInventory 返回。
    // 处理：每行包含对象类型、GUID、函数地址和 owner module 提示。
    // 返回行为：不包含任何禁用、detach 或删除动作。
    struct NetworkWfpInventoryResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial：collector 部分失败，或 APPLIED 但仅返回子集。
        bool truncated = false;               // truncated：总数/返回数或 BUFFER_OVERFLOW 表示结果不完整。
        std::uint32_t sourceFlags = 0;
        std::uint32_t budgetRows = 0;
        std::uint32_t generation = 0;
        std::vector<KSWORD_ARK_NETWORK_WFP_INVENTORY_ROW> entries;
    };

    // NetworkWfpEventResult 承载真实 WFP ALE IPv4 流授权事件增量响应。
    // 输入：queryNetworkWfpEvents(afterSequence, maxRows) 返回。
    // 处理：严格验证响应/行 ABI、字节边界和 sequence 单调性后复制 entries。
    // 返回行为：事件只含五元组元数据，不含 packet length、bytes 或 payload。
    struct NetworkWfpEventResult : VariableAuditResultBase
    {
        std::uint32_t capacity = 0;           // capacity：驱动固定非分页 ring 容量。
        std::uint64_t oldestSequence = 0;     // oldestSequence：当前仍可读取的最旧序号。
        std::uint64_t newestSequence = 0;     // newestSequence：当前 ring 最新序号。
        std::uint64_t nextSequence = 0;       // nextSequence：本响应最后返回的 cursor。
        std::uint64_t droppedEventCount = 0;  // droppedEventCount：ring 累计覆盖事件数。
        std::uint64_t cursorGapCount = 0;     // cursorGapCount：本次 cursor 已无法恢复的事件数。
        std::vector<KSWORD_ARK_NETWORK_WFP_EVENT_ROW> entries;
    };

    // NetworkTrafficCaptureControlResult 承载 WFP IP packet 逐包数据面的显式启停结果。
    // 旧驱动没有控制 IOCTL 时 unsupported=true，调用方不得继续把 R0 当作已停止。
    struct NetworkTrafficCaptureControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_NETWORK_TRAFFIC_CONTROL_RESPONSE response{};
    };

    // NetworkTrafficPacketResult 承载真实 WFP IPv4/IPv6 IP packet 层逐包增量响应。
    // 输入：queryNetworkTrafficPackets(afterSequence, maxRows) 返回。
    // 处理：严格验证 response/row ABI、cursor、报文边界和有限前缀，再复制 entries。
    // 返回行为：旧驱动未注册新 IOCTL 时 unsupported=true，调用方必须回退 R3 而非降级到 ALE 流事件。
    struct NetworkTrafficPacketResult : VariableAuditResultBase
    {
        std::uint32_t capacity = 0;            // capacity：驱动固定非分页逐包 ring 容量。
        std::uint64_t oldestSequence = 0;      // oldestSequence：当前仍可读取的最旧包序号。
        std::uint64_t newestSequence = 0;      // newestSequence：当前逐包 ring 最新序号。
        std::uint64_t nextSequence = 0;        // nextSequence：本响应最后返回的 cursor。
        std::uint64_t droppedPacketCount = 0;  // droppedPacketCount：ring 累计覆盖报文数。
        std::uint64_t cursorGapCount = 0;      // cursorGapCount：本次 cursor 已无法恢复的报文数。
        std::vector<KSWORD_ARK_NETWORK_TRAFFIC_PACKET_ROW> entries;
    };

    // NetworkNdisChainResult 承载 NDIS miniport/filter/protocol/binding 链只读审计结果。
    // 输入：queryNetworkNdisChain 返回。
    // 处理：每行保留对象地址、父对象、驱动对象和 owner module 诊断字段。
    // 返回行为：不执行 NDIS detach、pause、restart 或 filter 操作。
    struct NetworkNdisChainResult : VariableAuditResultBase
    {
        bool partial = false;                 // partial：collector 部分失败，或 APPLIED 但仅返回子集。
        bool truncated = false;               // truncated：总数/返回数或 BUFFER_OVERFLOW 表示结果不完整。
        std::uint32_t sourceFlags = 0;
        std::uint32_t budgetRows = 0;
        std::uint32_t generation = 0;
        std::vector<KSWORD_ARK_NETWORK_NDIS_CHAIN_ROW> entries;
    };

    // MinifilterInventoryResult 承载 fltMgr 过滤器与实例绑定清单。
    // 输入：queryMinifilterInventory 返回。
    // 处理：entries 保存 filter/altitude/volume/callback-owner 状态。
    // 返回行为：仅用于展示，不卸载、不 detach、不改 callback。
    struct MinifilterInventoryResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::vector<KSWORD_ARK_MINIFILTER_INVENTORY_ENTRY> entries;
    };

    // StorageVolumeStackAuditResult 承载卷设备栈和 fvevol 位置审计结果。
    // 输入：queryVolumeStackAudit 返回。
    // 处理：rows 保存设备对象、驱动对象、栈深度、风险和置信度。
    // 返回行为：不返回 BitLocker 密钥材料，也不改变存储栈。
    struct StorageVolumeStackAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::uint32_t fvevolPresent = 0;
        std::uint32_t fvevolPosition = 0xFFFFFFFFUL;
        std::vector<KSWORD_ARK_VOLUME_STACK_ROW> rows;
    };

    // StorageBitlockerFveAuditResult 承载 BitLocker/FVE 安全状态摘要。
    // 输入：queryBitlockerFveAudit 返回。
    // 处理：rows 只包含保护状态、转换状态、锁定状态和 protector 类型计数。
    // 返回行为：协议不承载密钥、恢复密码或元数据 payload。
    struct StorageBitlockerFveAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_BITLOCKER_FVE_ROW> rows;
    };

    // StorageMountMgrMappingAuditResult 承载 MountMgr 盘符/GUID/NT 路径映射审计结果。
    // 输入：queryMountMgrMappingAudit 返回。
    // 处理：rows 保存符号名和风险标志，不解析卷内数据。
    // 返回行为：仅展示映射关系，不修改挂载点。
    struct StorageMountMgrMappingAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_MOUNTMGR_MAPPING_ROW> rows;
    };

    // StorageFilesystemIntegrityAuditResult 承载文件系统 DriverObject/FastIo/dispatch 完整性行。
    // 输入：queryFilesystemIntegrityAudit 返回。
    // 处理：rows 保存 slot owner、target address 和风险，不写任何函数指针。
    // 返回行为：只读审计结果。
    struct StorageFilesystemIntegrityAuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t fieldFlags = 0;
        std::uint32_t maxRows = 0;
        std::vector<KSWORD_ARK_FILESYSTEM_INTEGRITY_ROW> rows;
    };

    // RawDiskBackendResult 承载一个物理磁盘的三层访问能力与安全边界。
    // 输入：queryRawDiskBackend 返回。
    // 处理：response 保存 R0 探测到的扇区、容量、总线、离线和系统盘信息。
    // 返回行为：unsupported 表示当前驱动未实现协议；不隐式降级到其它后端。
    struct RawDiskBackendResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_RAW_DISK_BACKEND_RESPONSE response{};
    };

    // RawDiskReadResult 承载一个有界、扇区对齐的物理磁盘读取结果。
    // 输入：readRawDisk 返回。
    // 处理：bytes 只保存 R0 明确报告已完成的字节。
    // 返回行为：失败时仍保留 protocol status、backendUsed 与 lastStatus。
    struct RawDiskReadResult
    {
        IoResult io;
        bool unsupported = false;
        std::uint32_t status = KSWORD_ARK_RAW_DISK_STATUS_INVALID_REQUEST;
        std::uint32_t backendUsed = 0;
        std::uint32_t logicalSectorSize = 0;
        std::vector<std::uint8_t> bytes;
    };

    // RawDiskWriteResult 承载显式确认后的物理磁盘写入结果。
    // 输入：writeRawDisk 返回。
    // 处理：response 保留中央安全策略和实际后端的最终状态。
    // 返回行为：bytesTransferred 只表示底层明确报告完成的字节。
    struct RawDiskWriteResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_RAW_DISK_WRITE_RESPONSE response{};
    };

    // SecurityStatusAuditResult 承载 CI/SecureBoot/VBS/SKCI/调试态固定响应。
    // 输入：querySecurityStatus 返回。
    // 处理：response 直接保留共享协议固定结构，便于 UI 展示所有字段。
    // 返回行为：unsupported 表示旧驱动缺安全审计入口。
    struct SecurityStatusAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_SECURITY_STATUS_RESPONSE response{};
    };

    // DriverTrustViewAuditResult 承载已加载驱动签名/模块 cross-view 行。
    // 输入：queryDriverTrustView 返回。
    // 处理：entries 保存模块名、imageBase、signingLevel 和 conflictFlags。
    // 返回行为：不执行签名策略修改或 CI 绕过。
    struct DriverTrustViewAuditResult : VariableAuditResultBase
    {
        std::uint32_t fieldFlags = 0;
        std::uint32_t sourceMask = 0;
        std::uint32_t maxEntriesAccepted = 0;
        std::uint32_t truncated = 0;
        long moduleQueryStatus = 0;
        long signingResolverStatus = 0;
        std::vector<KSWORD_ARK_DRIVER_TRUST_VIEW_ENTRY> entries;
    };

    // HyperVSummaryAuditResult 承载 Hyper-V/VBS 相关模块和 CPUID 固定摘要。
    // 输入：queryHyperVSummary 返回。
    // 处理：response 保留 vendor、module status 和 sourceMask。
    // 返回行为：只读展示，不关闭 Hyper-V 或 VBS。
    struct HyperVSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_HYPERV_SUMMARY_RESPONSE response{};
    };

    // AppControlStatusAuditResult 承载 AppID/AppLocker/mssecflt/BAM 只读状态。
    // 输入：queryAppControlStatus 返回。
    // 处理：response 保留 callback owner module 和模块状态。
    // 返回行为：不改 AppLocker/WDAC/CI 策略。
    struct AppControlStatusAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_APP_CONTROL_STATUS_RESPONSE response{};
    };

    // Win32kProfileStatusResult 承载 win32k/win32kbase/win32kfull profile 和 session 摘要。
    // 输入：queryWin32kProfileStatus 返回。
    // 处理：sessions 保存 per-session readiness；fieldOffsets 保存 PDB offset 状态。
    // 返回行为：只读状态，不安装窗口 hook。
    struct Win32kProfileStatusResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t userGetSiloGlobals = 0;
        KSWORD_ARK_WIN32K_MODULE_STATE win32k{};
        KSWORD_ARK_WIN32K_MODULE_STATE win32kbase{};
        KSWORD_ARK_WIN32K_MODULE_STATE win32kfull{};
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_SESSION_ENTRY> entries;
    };

    // Win32kWindowsResult 承载 HWND/tagWND cross-view 行。
    // 输入：queryWin32kWindows 返回。
    // 处理：entries 保存 HWND、PID/TID、desktop、rect、title/class 状态。
    // 返回行为：不读取消息 payload，不改变窗口状态。
    struct Win32kWindowsResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_WINDOW_ENTRY> entries;
    };

    // Win32kGuiThreadsResult 承载 GUI thread/tagQ/focus/capture/caret 快照。
    // 输入：queryWin32kGuiThreads 返回。
    // 处理：entries 保存队列对象和活跃 HWND 诊断地址。
    // 返回行为：不 hook、不阻断、不重放窗口消息。
    struct Win32kGuiThreadsResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY> entries;
    };

    // Win32kHotkeysPdbResult 承载 PDB-backed hotkey 快照。
    // 输入：queryWin32kHotkeysPdb 返回。
    // 处理：entries 保存 hotkey object、VK/modifiers 和关联 HWND/threadInfo。
    // 返回行为：不删除热键，不修改链表。
    struct Win32kHotkeysPdbResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        std::vector<KSWORD_ARK_WIN32K_HOTKEY_ENTRY> entries;
    };

    // Win32kHooksPdbResult 承载 PDB-backed hook 链快照。
    // 输入：queryWin32kHooksPdb 返回。
    // 处理：entries 保存 hook object、procedure、moduleBase 和 target threadInfo。
    // 返回行为：不 remove/unlink hook 链。
    struct Win32kHooksPdbResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        KSWORD_ARK_WIN32K_FIELD_OFFSETS fieldOffsets{};
        KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT layout{};
        std::uint32_t discoveredChainCount = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptLinkCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_HOOK_ENTRY> entries;
    };

    // Win32kTimersResult 承载 gTimerHashTable/tagTIMER 只读快照。
    // 输入：queryWin32kTimers 返回。
    // 处理：保留 PE 身份、实际布局、遍历完整性计数和 Timer 行。
    // 返回行为：不删除、不修改、不重新调度窗口定时器。
    struct Win32kTimersResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t timerHashTable = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptBucketCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        KSWORD_ARK_WIN32K_TIMER_LAYOUT layout{};
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_TIMER_ENTRY> entries;
    };

    // Win32kEventHooksResult 承载 gpWinEventHooks/tagEVENTHOOK 只读快照。
    // 输入：queryWin32kEventHooks 返回。
    // 处理：保留 PE 身份、实际布局、链完整性计数和 WinEvent Hook 行。
    // 返回行为：不调用 UnhookWinEvent，不修改全局 Hook 链。
    struct Win32kEventHooksResult : VariableAuditResultBase
    {
        std::uint64_t capabilityMask = 0;
        std::uint64_t missingCapabilityMask = 0;
        std::uint64_t hookListPointer = 0;
        std::uint64_t hookListHead = 0;
        std::uint32_t visitedNodeCount = 0;
        std::uint32_t readFailureCount = 0;
        std::uint32_t corruptLinkCount = 0;
        std::uint32_t duplicateCount = 0;
        std::uint32_t win32kbaseTimeDateStamp = 0;
        std::uint32_t win32kbaseImageSize = 0;
        std::uint32_t win32kfullTimeDateStamp = 0;
        std::uint32_t win32kfullImageSize = 0;
        KSWORD_ARK_WIN32K_EVENT_HOOK_LAYOUT layout{};
        std::wstring detail;
        std::vector<KSWORD_ARK_WIN32K_EVENT_HOOK_ENTRY> entries;
    };

    // Win32kWindowRuntimeDetailResult 承载单 HWND 的 win32k readiness/detail。
    // 输入：queryWin32kWindowDetail 返回。
    // 处理：response 保存 module/profile/capability/offset 状态；tagWND reader 未启用时也能解释原因。
    // 返回行为：只读展示，不安装窗口 hook，不读取消息 payload。
    struct Win32kWindowRuntimeDetailResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE response{};
    };

    // DeviceAuditResult 承载 Device/Input/USB/GPU 统一只读设备审计结果。
    // 输入：queryDeviceStackAudit/queryInputStackAudit/queryUsbTopologyAudit/queryGpuDisplayWatchdogAudit 返回。
    // 处理：entries 保存 DriverObject、DeviceObject、attached/next 链和风险标志。
    // 返回行为：不禁用设备、不卸载驱动、不 detach stack。
    struct DeviceAuditResult : VariableAuditResultBase
    {
        std::uint32_t profileFlags = 0;
        std::uint32_t responseFlags = 0;
        std::uint32_t targetCount = 0;
        std::uint32_t driverCount = 0;
        std::uint32_t deviceCount = 0;
        std::vector<KSWORD_ARK_DEVICE_AUDIT_ENTRY> entries;
    };

    // PlatformAuditResult 承载 HAL/WDF 统一审计结果。
    // 输入：queryPlatformAudit 返回，scopeMask 指定 HAL 表或 WDF 表/回调。
    // 处理：entries 保留地址、模块、结构/owner 证据和本地化 detailCode 参数。
    // 返回行为：查询本身只读；HAL 槽与 KMDF 绑定表槽的编辑必须另行调用
    // editPlatformAuditEntry。
    struct PlatformAuditResult : VariableAuditResultBase
    {
        std::uint32_t scopeMask = 0;
        std::uint32_t responseFlags = 0;
        std::uint32_t buildNumber = 0;
        std::uint32_t signaturePolicyFlags = 0;
        std::vector<KSWORD_ARK_PLATFORM_AUDIT_ENTRY> entries;
    };

    // PlatformAuditControlResult 承载一次受控函数槽 CAS 的完整证据。
    // responseFlags 的 ALIAS_WRITE 位表示槽位在只读节，R0 经 MDL 可写别名提交。
    struct PlatformAuditControlResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_CONTROL_PLATFORM_AUDIT_RESPONSE response{};
    };

    // I8042AuditResult 承载专用 i8042prt 描述符与端点证据。
    // 输入：queryI8042Audit 返回；只有精确 PE/RSDS/opcode/DriverObject 匹配时含端点行。
    // 返回行为：只读，不读取输入包，不回放内部 IOCTL，不写设备扩展。
    struct I8042AuditResult : VariableAuditResultBase
    {
        std::uint32_t responseFlags = 0;
        std::uint32_t descriptorId = 0;
        std::uint32_t imageTimeDateStamp = 0;
        std::uint32_t imageSize = 0;
        std::uint32_t imageChecksum = 0;
        std::uint32_t pdbAge = 0;
        std::uint64_t imageBase = 0;
        std::uint8_t pdbGuid[KSWORD_ARK_I8042_PDB_GUID_BYTES]{};
        std::vector<KSWORD_ARK_I8042_AUDIT_ENTRY> entries;
    };

    // CidTableAuditResult 承载 PspCidTable 只读枚举行。
    // 输入：enumCidTable 返回。
    // 处理：entries 保存 CID、对象类型、引用状态和对象地址。
    // 返回行为：不删除 CID，不隐藏进程/线程。
    struct CidTableAuditResult : VariableAuditResultBase
    {
        std::uint32_t visitedCount = 0;
        std::uint32_t maxVisitCount = 0;
        std::uint64_t pspCidTableAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint32_t htTableCodeOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::uint32_t hteLowValueOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::vector<KSWORD_ARK_CID_TABLE_ENTRY> entries;
    };

    // ObjectTypeTableAuditResult 承载 R0 ObTypeIndexTable 只读快照。
    // 输入：enumObjectTypeTable 返回，可按 type index 分页。
    // 处理：保留表地址、DynData 偏移、快照哈希和逐槽交叉验证结果。
    // 返回行为：只读展示，不修改对象类型表或对象头。
    struct ObjectTypeTableAuditResult : VariableAuditResultBase
    {
        std::uint32_t nextIndex = 0;
        std::uint64_t tableAddress = 0;
        std::uint64_t dynDataCapabilityMask = 0;
        std::uint64_t snapshotHash = 0;
        std::uint32_t otNameOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::uint32_t otIndexOffset = KSWORD_ARK_KERNEL_OBJECT_OFFSET_UNAVAILABLE;
        std::vector<KSWORD_ARK_OBJECT_TYPE_TABLE_ENTRY> entries;
    };

    // KernelObjectSummaryAuditResult 承载单对象 header/type/counter 摘要。
    // 输入：queryKernelObjectSummary 返回。
    // 处理：response 直接保存共享固定响应结构。
    // 返回行为：只读展示对象元数据，不改对象头或引用计数。
    struct KernelObjectSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_KERNEL_OBJECT_SUMMARY_RESPONSE response{};
    };

    // IpcSummaryAuditResult 承载 ALPC/Pipe/Mailslot IPC 摘要。
    // 输入：queryIpcSummary 返回。
    // 处理：response 保留句柄、对象地址、typeName 和降级详情。
    // 返回行为：不关闭句柄、不发送消息、不修改 IPC 对象。
    struct IpcSummaryAuditResult
    {
        IoResult io;
        bool unsupported = false;
        KSWORD_ARK_QUERY_IPC_SUMMARY_RESPONSE response{};
    };

    // DynDataV4ApplyInput 是 v4 PDB profile 的 R3 打包输入。
    // 输入：module/capabilityGroups/items 来自 PDB extractor 生成的已校验 profile。
    // 处理：ArkDriverClient 只负责长度校验和协议传输。
    // 返回行为：传入 applyDynDataProfileV4 后得到 DynDataV4ApplyResult。
    struct DynDataV4ApplyInput
    {
        KSW_DYN_V4_MODULE_IDENTITY_PACKET module{};
        std::vector<KSW_DYN_V4_CAPABILITY_GROUP_PACKET> capabilityGroups;
        std::vector<KSW_DYN_V4_ITEM_PACKET> items;
        std::uint32_t flags = 0;
    };

    // DynDataV4ApplyResult 承载 R0 接收 v4 module profile 后的固定响应。
    // 输入：无，由 applyDynDataProfileV4 返回。
    // 处理：response 保留模块身份、statusFlags、capabilityMask 和消息。
    // 返回行为：io.ok 表示传输/协议成功，unsupported 表示旧驱动缺 v4 入口。
    struct DynDataV4ApplyResult
    {
        IoResult io;
        bool unsupported = false;
        KSW_APPLY_DYN_PROFILE_V4_RESPONSE response{};
    };

    // DynDataV4ModulesResult 承载已加载 v4 module profile 状态。
    // 输入：queryDynDataV4Modules 返回。
    // 处理：entries 保存每个模块 class/profile/status/capability 状态。
    // 返回行为：只读查询当前 R0 v4 profile cache。
    struct DynDataV4ModulesResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_MODULE_STATUS_ENTRY> entries;
    };

    // DynDataV4CapabilityGroupsResult 承载 v4 capability group 完整性状态。
    // 输入：queryDynDataV4CapabilityGroups 返回。
    // 处理：entries 保存 required/optional present/missing 计数。
    // 返回行为：只读展示 profile 缺口。
    struct DynDataV4CapabilityGroupsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_CAPABILITY_GROUP_STATUS_ENTRY> entries;
    };

    // DynDataV4MissingItemsResult 承载 v4 required/optional missing 摘要。
    // 输入：queryDynDataV4MissingItems 返回。
    // 处理：entries 保存 itemName/reason，供 UI 展示 profile 缺失项。
    // 返回行为：只读查询，不修改 DynData 状态。
    struct DynDataV4MissingItemsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_MISSING_ITEM_ENTRY> entries;
    };

    // DynDataV4ItemsResult 承载 v4 已接受 item 的只读清单。
    // 输入：queryDynDataV4Items 返回。
    // 处理：entries 保存 moduleClassId、itemIndex 和完整 KSW_DYN_V4_ITEM_PACKET。
    // 返回行为：只读查询，不重新应用 profile，也不把 item 接入业务路径。
    struct DynDataV4ItemsResult : VariableAuditResultBase
    {
        std::vector<KSW_DYN_V4_ITEM_STATUS_ENTRY> entries;
    };

    // AsyncIoResult reports an overlapped DeviceIoControl issue attempt. A false
    // issued value with win32Error==ERROR_IO_PENDING means the request is queued.
    struct AsyncIoResult
    {
        bool issued = false;
        unsigned long win32Error = ERROR_SUCCESS;
        unsigned long bytesReturned = 0;
    };
}
