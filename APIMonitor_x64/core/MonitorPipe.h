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

namespace apimon
{
    bool StartMonitorPipeServer(const MonitorConfig& configValue, std::wstring* errorTextOut);
    void StopMonitorPipeServer();
    bool DrainMonitorPipeServer(DWORD timeoutMs = 2000);
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
    std::uint32_t FlushCoverageSnapshot(std::uint32_t budget);
    std::uint32_t FlushPendingMonitorEvents(std::uint32_t maxPacketsToFlush);
    bool IsMonitorPipeHandle(HANDLE handleValue);
}
