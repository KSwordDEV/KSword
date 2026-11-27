#pragma once

#include "OfflineSegmentReader.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"

namespace ks::action_analyze
{
    struct PresetReplayCount
    {
        QString label; // 规则库的默认释义，缺省时使用规则 ID。
        QString labelZh; // 规则库的可选简体中文释义。
        quint64 matches = 0; // 当前核验窗口中该规则的命中数。
    };

    struct PresetReplayRequest
    {
        QString path; // 冻结的单段路径或项目清单路径，用于结果归属。
        std::optional<SampleRequest> sample; // 存在时只读该项目指定的已登记采样。
    };

    struct PresetReplayResult
    {
        QString error; // 失败时保存既有稳定诊断码，不提交命中。
        QString projectId; // 归档段头确认的项目身份。
        QString sampleId; // 归档段头确认的采样身份。
        std::optional<quint64> sampleCreatedUtc; // 项目冻结采样的创建 FILETIME。
        quint64 verifiedSegments = 0; // 项目连续核验的段数。
        quint64 firstUnverifiedSegment = 0; // 前缀停止位置，零表示没有未核验段。
        SegmentEnd end = SegmentEnd::Unavailable; // 完整读回与已验证前缀使用不同文案。
        std::optional<Ksword::Evidence::ApiMonitorArchiveSource> archiveSource; // 来自已核验的导入尾记或检查点计划。
        QString presetSet; // 本次回放实际加载的规则集标识。
        QString ruleSourceSha256; // 本次回放实际解析的规则文件字节摘要，不借版本名推断内容。
        QString recordedRulePresetSet; // 已核验采集计划声明的规则集标识，旧档缺失时为空。
        QString recordedRuleSourceSha256; // 采集时计划中的摘要，旧档未知时保持空值。
        QString configError; // 外置规则库加载失败时的诊断。
        Ksword::ActionAnalyze::Rules::ApiPresetReport report; // 细分配置的求值结果。
        std::vector<PresetReplayCount> groupedCounts; // 汇总配置定义顺序及实际命中数。
        std::vector<PresetReplayCount> categoryCounts; // 细分配置定义顺序及实际命中数。
        std::vector<QString> groupRuleIds; // 与细分命中逐条对应的实际汇总规则 ID。
        std::vector<quint64> matchSegments; // 按命中顺序保留归档原段号。
    };

    // 在线程池读取单段或冻结采样，仅将已严格核验的 API 观测提交给当前规则库。
    PresetReplayResult ReadBehaviorPresets(const PresetReplayRequest& request, const CancelCheck& isCanceled);
    // 在 UI 线程格式化完整回执或部分读取状态，语言切换时沿用同一个值结果。
    QString FormatBehaviorPresets(const PresetReplayResult& result);
    QString FormatPresetVerifiedPrefix(const PresetReplayResult& result);
}
