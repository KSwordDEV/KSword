#pragma once

#include "../../../KswordCLI/ActionAnalyze/Rules/AnalysisRun.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/RuleExpression.h"

#include <utility>

namespace ks::action_analyze
{
    inline constexpr std::size_t BehaviorRuleMaxBytes = 256 * 1024; // UTF-8 草稿文件上限。

    // 草稿处理的值回执。区分 JSON 文件字节位置和解码后表达式的字节位置。
    struct BehaviorRuleCheck
    {
        std::string error; // 稳定诊断码，空表示检查成功。
        std::string pointer; // 定位到规则或回放字段，不依赖界面语言。
        std::optional<std::size_t> offset; // JSON 文件中的 0 基 UTF-8 字节位置。
        std::optional<Ksword::ActionAnalyze::Rules::ExpressionLocation> expressionLocation; // 谓词自身的位置。
        std::string ruleId; // 从本次冻结的草稿读到的规则 ID。
        std::size_t eventCount = 0; // 此草稿声明的合成事件数量。
        std::optional<Ksword::ActionAnalyze::Rules::ReplayResult> replay; // 只有回放命令产生判定。
    };

    // 无界面依赖。返回可直接编辑并通过生产规则引擎运行的完整样例。
    std::string_view BehaviorRuleExample();

    // 编辑器说明与准备器共用实际字段目录，类型不是展示文本推断的。
    std::span<const std::pair<std::string_view, Ksword::ActionAnalyze::Rules::FieldType>> BehaviorRuleFields();

    // 校验 UTF-8 JSON 草稿并准备两个选择器。runReplay 为真时只处理草稿中的合成事件。
    BehaviorRuleCheck CheckBehaviorRuleDraft(std::string_view utf8, bool runReplay);
}
