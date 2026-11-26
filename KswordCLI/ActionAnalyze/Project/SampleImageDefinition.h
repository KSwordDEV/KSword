#pragma once

#include "ProjectDocument.h"

namespace Ksword::ActionAnalyze
{
    // 在原采样冻结配置中解析已保存的启用RVA定义，模块仅接受同名绝对路径。
    // 输入原document/sample/定义ID及模块路径，成功返回RVA；不加载PDB，不导入历史停止状态。
    ProjectResult ResolveSampleImageDefinition(const ProjectDocument& document, std::string_view sampleId,
        std::string_view definitionId, const std::wstring& modulePath, std::uint32_t& rva);
}
