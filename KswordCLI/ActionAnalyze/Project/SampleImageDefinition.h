#pragma once

#include "ProjectDocument.h"

namespace Ksword::ActionAnalyze
{
    // 在原采样冻结配置中解析已保存启用RVA定义；模块仅接受同名绝对路径，不加载PDB。
    // 成功输出RVA及可选原映像散列，调用者必须将散列传给原native准入；未提供输出端口时拒绝带约束定义。
    ProjectResult ResolveSampleImageDefinition(const ProjectDocument& document, std::string_view sampleId,
        std::string_view definitionId, const std::wstring& modulePath, std::uint32_t& rva,
        std::optional<std::string>* imageSha256 = nullptr);
}
