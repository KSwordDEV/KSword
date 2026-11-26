#pragma once

// ============================================================
// core/MonitorPipe.h
// 作用：
// 1) 负责 Agent 端命名管道服务端创建与关闭；
// 2) 把 Hook 事件组装为固定长度事件包并发送给 UI；
// 3) 提供“当前句柄是否是监控管道”判断，避免 WriteFile Hook 自递归。
// ============================================================

#include "pch.h"
#include "MonitorConfig.h"

namespace Ksword::Evidence {
struct ApiInjectionFieldsV1; // 既有写入/线程创建协议，只在发送时借用。
struct ApiApcFieldsV1; // 独立 APC 入队协议，不表示执行。
struct ApiContextFieldsV1; // 独立上下文请求协议。
struct ApiSectionMapFieldsV1; // 独立映射请求/成功输出协议。
struct ApiMemoryLifecycleFieldsV1; // 独立分配/保护/释放请求协议。
}

namespace apimon
{
    bool StartMonitorPipeServer(const MonitorConfig& configValue, std::wstring* errorTextOut);
    void StopMonitorPipeServer();
    bool DrainMonitorPipeServer(DWORD timeoutMs = 2000);
    // HooksInstalled carries the coverage revision published for the installation.
    bool SendHooksInstalledEvent(const std::wstring& detail);
    // HooksRemoved carries the final coverage revision in snapshotRevision.
    bool SendHooksRemovedEvent(const std::wstring& detail);
    bool SendMonitorEvent(
        ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        std::int32_t resultCode,
        const std::wstring& detailText);
    bool SendMonitorEventRaw(
        ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName,
        const wchar_t* apiName,
        std::int32_t resultCode,
        const wchar_t* detailText,
        ks::winapi_monitor::EventResultKind resultKind = ks::winapi_monitor::EventResultKind::StatusCode,
        ks::winapi_monitor::EventKind eventKind = ks::winapi_monitor::EventKind::ApiCall,
        std::uint64_t operationId = 0, std::uint32_t apiId = 0);
    // An explicitly captured return value, separate from the status/error code.
    bool SendMonitorEventRawWithReturn(
        ks::winapi_monitor::EventCategory categoryValue,
        const wchar_t* moduleName, const wchar_t* apiName,
        std::int32_t resultCode, const wchar_t* detailText,
        std::uint64_t returnBits);
    // SendMonitorEventRawWithMetrics：同步封装一个原队列业务包，调用后不保存字段指针。
    // 普通 Hook 的可选字段均为空；对应 Hook 只传自己的独立协议，不改 AAIP1。
    bool SendMonitorEventRawWithMetrics(
        ks::winapi_monitor::EventCategory categoryValue, // 原事件业务类别。
        const wchar_t* moduleName, // 定义中的模块身份。
        const wchar_t* apiName, // 定义中的精确 API 名。
        std::int32_t resultCode, // 原状态或错误码。
        const wchar_t* detailText, // 普通事件的可截断文本摘要。
        bool hasReturnValue, // 是否保存原返回位。
        std::uint64_t returnBits, // 原返回位模式，与状态码分开。
        bool hasDuration, // 耗时是否有效。
        std::uint64_t duration100ns, // 原调用耗时，单位 100ns。
        std::uint32_t apiId = 0, // 既有 API ID，零表示按模块和名称查找。
        ks::winapi_monitor::EventResultKind resultKind = ks::winapi_monitor::EventResultKind::StatusCode, // 状态语义。
        std::uint64_t operationId = 0, // 既有操作关联标识。
        const Ksword::Evidence::ApiInjectionFieldsV1* injectionFields = nullptr, // 既有 AAIP1 字段。
        const Ksword::Evidence::ApiApcFieldsV1* apcFields = nullptr, // AAAP1 入队请求字段。
        const Ksword::Evidence::ApiContextFieldsV1* contextFields = nullptr, // AACT1 请求上下文字段。
        const Ksword::Evidence::ApiSectionMapFieldsV1* sectionMapFields = nullptr, // AASM1 映射字段。
        const Ksword::Evidence::ApiMemoryLifecycleFieldsV1* memoryFields = nullptr); // AAIM1 生命周期字段。
    std::uint32_t FlushCoverageSnapshot(std::uint32_t budget);
    std::uint32_t FlushPendingMonitorEvents(std::uint32_t maxPacketsToFlush);
    bool IsMonitorPipeHandle(HANDLE handleValue);
}
