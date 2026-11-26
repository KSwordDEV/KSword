#pragma once

#include "ProjectDocument.h"
#include "../Rules/RuleExpression.h"

namespace Ksword::ActionAnalyze
{
    // 在原采样冻结配置中解析已保存启用RVA定义；模块仅接受同名绝对路径，不加载PDB。
    // 成功输出RVA、原映像散列及条件；未提供对应输出端口时拒绝有约束定义，避免静默弱化。
    ProjectResult ResolveSampleImageDefinition(const ProjectDocument& document, std::string_view sampleId,
        std::string_view definitionId, const std::wstring& modulePath, std::uint32_t& rva,
        std::optional<std::string>* imageSha256 = nullptr,
        std::optional<BreakpointCondition>* condition = nullptr);

    // 输入冻结条件和手填草稿；无条件不改值，冲突/准备失败不改输出，成功同时发布原文及已准备谓词。
    ProjectResult PrepareSampleImageCondition(const std::optional<BreakpointCondition>& condition,
        std::wstring& source, Rules::PreparedPredicate& predicate,
        Rules::Phase phase = Rules::Phase::Observation);
}
