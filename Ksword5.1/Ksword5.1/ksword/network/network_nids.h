#pragma once

// ============================================================
// ksword/network/network_nids.h
// Namespace: ks::network
// Purpose:
// - Provide a lightweight, UI-independent NIDS rule engine for PacketRecord.
// - Keep rolling flow state in memory and return structured alerts to callers.
// - Cover practical real-time checks: port scan bursts, suspicious DNS/HTTP,
//   risky remote ports, and abnormal outbound transfer bursts.
// ============================================================

#include "network.h"

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ks::network
{
    // NidsAlertSeverity：NIDS 告警等级。
    enum class NidsAlertSeverity : std::uint8_t
    {
        Low = 0,      // 低风险：值得留意但不一定异常。
        Medium = 1,   // 中风险：出现可疑行为或弱信号组合。
        High = 2,     // 高风险：明显攻击/扫描/可疑 C2 特征。
        Critical = 3  // 严重风险：保留给后续阻断联动或强命中规则。
    };

    // NidsAlert：单条 NIDS 告警。
    struct NidsAlert
    {
        std::uint64_t timestampMs = 0;          // 告警时间戳（Unix ms）。
        std::uint64_t sequenceId = 0;           // 关联报文序号。
        NidsAlertSeverity severity = NidsAlertSeverity::Low; // 告警等级。
        std::string category;                   // 分类，例如 Scan/DNS/HTTP/Flow。
        std::string ruleId;                     // 规则编号，便于后续筛选与日志回溯。
        std::string title;                      // 简短标题。
        std::string detail;                     // 详细说明。
        std::uint32_t processId = 0;            // 关联 PID。
        std::string processName;                // 关联进程名。
        // 仅用于把审计证据安全地预填为应用级处置规则。创建时间和镜像路径均在
        // 告警产生时采集；后续处置前必须再次核验，不能把可复用的裸 PID 当身份。
        std::uint64_t processCreationTime100ns = 0;
        std::string processImagePath;
        PacketTransportProtocol protocol = PacketTransportProtocol::Tcp; // 协议。
        PacketDirection direction = PacketDirection::Unknown;             // 方向。
        std::string localAddress;               // 本地地址。
        std::uint16_t localPort = 0;            // 本地端口。
        std::string remoteAddress;              // 远端地址。
        std::uint16_t remotePort = 0;           // 远端端口。
    };

    // NidsEngine：轻量规则型 NIDS 引擎。
    class NidsEngine
    {
    public:
        // AnalyzePacket：
        // - 输入：单条抓包记录；
        // - 输出：本报文触发的告警列表；
        // - 注意：该函数会更新内部滚动窗口状态。
        [[nodiscard]] std::vector<NidsAlert> AnalyzePacket(const PacketRecord& packetRecord);

        // Reset：清空滚动窗口与去重冷却状态。
        void Reset();

    public:
        // 以下结构仅供 network_nids.cpp 的窗口维护辅助函数使用。
        struct PortEvent
        {
            std::uint64_t timestampMs = 0;
            std::uint16_t port = 0;
        };

        struct PortScanWindow
        {
            std::deque<PortEvent> eventList;
            std::uint64_t lastAlertTimestampMs = 0;
        };

        struct ByteEvent
        {
            std::uint64_t timestampMs = 0;
            std::uint64_t byteCount = 0;
        };

        struct ByteWindow
        {
            std::deque<ByteEvent> eventList;
            std::uint64_t totalBytes = 0;
            std::uint64_t lastAlertTimestampMs = 0;
        };

    private:
        // analyzePortScan：检测同一来源对大量端口的短时探测。
        void analyzePortScan(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeDnsPayload：检测 DNS 查询中的高风险域名/异常域名。
        void analyzeDnsPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeHttpPayload：检测明文 HTTP payload 中的攻击特征。
        void analyzeHttpPayload(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeSuspiciousPort：检测高风险远程服务端口访问。
        void analyzeSuspiciousPort(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // analyzeOutboundByteBurst：检测短时大流量出站传输。
        void analyzeOutboundByteBurst(const PacketRecord& packetRecord, std::vector<NidsAlert>& alertList);

        // shouldEmitFlowAlert：按 rule + flow 做冷却去重。
        bool shouldEmitFlowAlert(
            const std::string& dedupeKey,
            std::uint64_t nowMs,
            std::uint64_t cooldownMs);

        std::unordered_map<std::string, PortScanWindow> m_portScanWindowByKey; // 扫描窗口。
        std::unordered_map<std::string, ByteWindow> m_outboundByteWindowByKey; // 出站字节窗口。
        std::unordered_map<std::string, std::uint64_t> m_flowAlertLastTimestampByKey; // 告警冷却。
    };

    // NidsAlertSeverityToString：等级枚举转稳定英文文本。
    [[nodiscard]] std::string NidsAlertSeverityToString(NidsAlertSeverity severity);
} // namespace ks::network
