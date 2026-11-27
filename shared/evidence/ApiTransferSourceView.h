#pragma once

#include "ApiHandoffReceiptView.h"

namespace Ksword::Evidence
{
    // 输入已冻结的网络或ETW回执，输出只读字段分组；不查询现场、不补造来源状态。
    inline std::vector<HandoffReceiptSection> BuildApiTransferSourceView(
        const JsonValue& networkTraffic, const JsonValue& agentEtw)
    {
        using namespace HandoffReceiptView;
        std::vector<HandoffReceiptSection> sections; // 保存两类来源各自的可读摘要。

        // 网络字段只来自网络回执根对象；requestedBackend不替代实际发布来源。
        if (networkTraffic.asObject())
        {
            HandoffReceiptSection network{L"同采样网络摘要"};
            Field(network, networkTraffic, L"请求来源", "requestedBackend");
            Field(network, networkTraffic, L"来源已就绪", "sourceReady");
            Field(network, networkTraffic, L"采集状态", "status");
            Field(network, networkTraffic, L"来源诊断", "detail");
            Field(network, networkTraffic, L"来源错误码", "win32Error");
            Field(network, networkTraffic, L"终态原因", "reason");
            Field(network, networkTraffic, L"流量覆盖", "coverage");
            Field(network, networkTraffic, L"清退已确认", "cleanupConfirmed");
            Field(network, networkTraffic, L"已提交段号", "segmentOrdinal");
            Field(network, networkTraffic, L"已提交包数", "packets");
            Field(network, networkTraffic, L"已提交字节数", "capturedBytes");
            Field(network, networkTraffic, L"来源缺口数", "sourceGap");
            Field(network, networkTraffic, L"不支持包数", "unsupportedPackets");
            Field(network, networkTraffic, L"队列淘汰数", "queueDropped");

            // published为空时仍保留未知字段，不从请求来源或就绪位推导实际网络身份。
            const auto* published = networkTraffic.find("published");
            if (published && published->asObject())
            {
                Field(network, *published, L"发布流", "stream");
                Field(network, *published, L"发布段号", "segmentOrdinal");
                Field(network, *published, L"网络来源 ID", "sourceId");
                Field(network, *published, L"网络时钟 ID", "clockId");
                Field(network, *published, L"最后原始序号", "lastRawSequence");
                Field(network, *published, L"归档结束偏移", "endOffset");
                Field(network, *published, L"归档 SHA-256", "sha256");
            }
            else
            {
                network.fields.push_back({L"发布流", "未知", true});
                network.fields.push_back({L"发布段号", "未知", true});
                network.fields.push_back({L"网络来源 ID", "未知", true});
                network.fields.push_back({L"网络时钟 ID", "未知", true});
                network.fields.push_back({L"最后原始序号", "未知", true});
                network.fields.push_back({L"归档结束偏移", "未知", true});
                network.fields.push_back({L"归档 SHA-256", "未知", true});
            }
            // 与network-read保持同一段损失口径；旧回执缺字段时显示未知，不以零缺口推断无丢失。
            const auto* loss = published ? published->find("loss") : nullptr; // 仅借用最后成功发布段的损失对象。
            const auto unknownLoss = JsonValue::makeNull(); // 兼容历史回执，不为缺失损失补造零或false。
            const auto& segmentLoss = loss && loss->asObject() ? *loss : unknownLoss; // 段增量不同于根级累计。
            Field(network, segmentLoss, L"本段来源损失数", "sourceLost");
            Field(network, segmentLoss, L"本段队列丢弃数", "queueDropped");
            Field(network, segmentLoss, L"来源损失无法量化", "sourceLossUnquantified");
            Field(network, segmentLoss, L"本段来源计数饱和", "sourceCounterSaturated");
            Field(network, segmentLoss, L"本段队列计数饱和", "queueCounterSaturated");
            network.failed = Failed(networkTraffic, "win32Error");
            sections.push_back(std::move(network));
        }

        // ETW字段只读取ETW回执及其自己的published坐标，不借用网络来源坐标。
        if (agentEtw.asObject())
        {
            HandoffReceiptSection etw{L"同采样 ETW 摘要"};
            Field(etw, agentEtw, L"已提交段号", "segmentOrdinal");
            Field(etw, agentEtw, L"已归档观察数", "archivedObservations");
            Field(etw, agentEtw, L"最终段", "finalSegment");
            Field(etw, agentEtw, L"回执不完整", "incomplete");
            etw.failed = Failed(agentEtw, "incomplete");

            // 原生ETW状态位于source子对象；不从网络回执或根级缺失字段补造损失计数。
            const auto* source = agentEtw.find("source");
            if (source && source->asObject())
            {
                Field(etw, *source, L"来源状态", "state");
                Field(etw, *source, L"事件丢失数", "eventsLost");
                Field(etw, *source, L"日志缓冲丢失数", "logBuffersLost");
                Field(etw, *source, L"实时缓冲丢失数", "realTimeBuffersLost");
                Field(etw, *source, L"队列淘汰数", "queueDropped");
                Field(etw, *source, L"负载截断数", "payloadTruncated");
                Field(etw, *source, L"畸形负载数", "malformedPayload");
            }
            else
            {
                etw.fields.push_back({L"来源状态", "未知", true});
                etw.fields.push_back({L"事件丢失数", "未知", true});
                etw.fields.push_back({L"日志缓冲丢失数", "未知", true});
                etw.fields.push_back({L"实时缓冲丢失数", "未知", true});
                etw.fields.push_back({L"队列淘汰数", "未知", true});
                etw.fields.push_back({L"负载截断数", "未知", true});
                etw.fields.push_back({L"畸形负载数", "未知", true});
            }

            // ETW发布对象没有网络sourceId/clockId；保留它自有的原始段坐标。
            const auto* published = agentEtw.find("published");
            if (published && published->asObject())
            {
                Field(etw, *published, L"发布流", "stream");
                Field(etw, *published, L"发布段号", "segmentOrdinal");
                Field(etw, *published, L"首个原始序号", "firstRawSequence");
                Field(etw, *published, L"最后原始序号", "lastRawSequence");
                Field(etw, *published, L"归档结束偏移", "endOffset");
                Field(etw, *published, L"归档 SHA-256", "sha256");
                Field(etw, *published, L"发布对象最终段", "finalSegment");
            }
            else
            {
                etw.fields.push_back({L"发布流", "未知", true});
                etw.fields.push_back({L"发布段号", "未知", true});
                etw.fields.push_back({L"首个原始序号", "未知", true});
                etw.fields.push_back({L"最后原始序号", "未知", true});
                etw.fields.push_back({L"归档结束偏移", "未知", true});
                etw.fields.push_back({L"归档 SHA-256", "未知", true});
                etw.fields.push_back({L"发布对象最终段", "未知", true});
            }
            sections.push_back(std::move(etw));
        }

        return sections;
    }
}
