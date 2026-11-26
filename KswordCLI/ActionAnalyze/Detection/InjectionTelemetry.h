#pragma once

#include "InjectionDiscovery.h"
#include "../../../shared/WinApiMonitorProtocol.h"
#include "../../../shared/driver/KswordArkCallbackMonitorIoctl.h"
#include "../../../shared/usermode/backend/monitor/PassiveEtwSource.h"

namespace Ksword::ActionAnalyze::Detection {

enum class TelemetryDisposition { Unrelated, Projected, ContextOnly, InvalidRecord };

// 包的原字节由上游保存；投影只引用其位置，不复制 ETW 或 Agent 字节进每条告警。
struct TelemetryProjection {
    TelemetryDisposition disposition = TelemetryDisposition::Unrelated;
    std::optional<EvidenceRef> evidence;
    EventProjection event;
};

// 仅接收上游已验真的 Agent 包。裸句柄、摘要中的字节和零占位不生成 A→B。
TelemetryProjection ProjectArchivedApiCall(const SampleScope& scope, const EvidenceRef& evidence,
    const ks::winapi_monitor::ApiMonitorEventPacket& packet);

// 仅读 v1 线程创建通知；保存弱 creator/target 提示。退出通知及对象访问权都不是创建或写入事实。
TelemetryProjection ProjectCallbackThreadCreation(const SampleScope& scope, const EvidenceRef& evidence,
    const KSWORD_ARK_CALLBACK_MONITOR_EVENT& record);

// 调用方须核对同采样已提交的 raw 坐标、来源/代次和正文。只保留通知线索，不要求机器/启动期，
// 也不把归档核验当成原生来源、创建结果或实例身份已证实。
TelemetryProjection ProjectArchivedCallbackThreadCreation(const SampleScope& scope, const EvidenceRef& evidence,
    const KSWORD_ARK_CALLBACK_MONITOR_EVENT& record);

// 仅用于调用方选中的相关 ETW 原始记录。当前通用 ETW 记录没有经过批准的写入/执行语义解析器。
TelemetryProjection ProjectPassiveEtwContext(const SampleScope& scope, const EvidenceRef& evidence,
    const ks::r3::monitor::PassiveEtwRecord& record);

// 从现有回执读取系统/本端丢失、尾部及截断；即使零丢失，也不授予远程写覆盖。
std::vector<Issue> PassiveEtwCoverageGaps(const ks::r3::monitor::PassiveEtwStatus& status);

} // namespace Ksword::ActionAnalyze::Detection
