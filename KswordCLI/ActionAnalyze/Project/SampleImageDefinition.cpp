#include "SampleImageDefinition.h"
#include "ProjectStorage.h"

#include <algorithm>
#include <filesystem>

namespace Ksword::ActionAnalyze
{
    // 三端在启动实际绑定前调用，只读取本轮sample的冻结定义，不跟随项目后来修订。
    ProjectResult ResolveSampleImageDefinition(const ProjectDocument& document, std::string_view sampleId,
        std::string_view definitionId, const std::wstring& modulePath, std::uint32_t& rva)
    {
        namespace storage = ProjectStorage;
        rva = 0;
        if (!document.Info() || !storage::IsUuid(sampleId) || !storage::IsUuid(definitionId))
        {
            return storage::Failure(ProjectError::InvalidArgument, "sampleBreakpointDefinitionIdentity");
        }
        SampleRecord sample; // 唯一配置来源是本轮已提交采样的冻结修订。
        if (const auto status = document.ReadSample(sampleId, sample); !status)
        {
            return status;
        }
        if (!sample.frozenSettings.breakpointDefinitions)
        {
            return storage::Failure(ProjectError::NotFound, "sampleBreakpointDefinitions");
        }
        const auto& definitions = *sample.frozenSettings.breakpointDefinitions; // 当前读取中的完整定义集合。
        const auto found = std::find_if(definitions.begin(), definitions.end(), [definitionId](const auto& definition) {
            return definition.breakpointDefinitionId == definitionId;
        });
        if (found == definitions.end())
        {
            return storage::Failure(ProjectError::NotFound, "sampleBreakpointDefinition");
        }
        const auto* location = std::get_if<BreakpointRva>(&found->location); // 不将符号名解释为精确PE导出。
        if (!found->enabled || !location || !location->rva || found->module.imageSha256)
        {
            return storage::Failure(ProjectError::InvalidArgument, "sampleBreakpointDefinitionUnsupported");
        }
        const auto& name = found->module.name; // 规范UTF-8模块名，不使用有损系统代码页转换。
        const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()), nullptr, 0);
        std::wstring expected(count > 0 ? static_cast<std::size_t>(count) : 0, L'\0'); // 原定义选择的模块文件名。
        const auto selected = std::filesystem::path(modulePath); // 保留完整路径供原native核验已加载映像。
        const auto basename = selected.filename().wstring();
        if (!selected.is_absolute() || !count || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
            name.data(), static_cast<int>(name.size()), expected.data(), count) ||
            CompareStringOrdinal(basename.c_str(), -1, expected.c_str(), -1, TRUE) != CSTR_EQUAL)
        {
            return storage::Failure(ProjectError::InvalidArgument, "sampleBreakpointModuleMismatch");
        }
        rva = location->rva; // 输出只在全部准入通过后设置，失败不会遗留上一次RVA。
        return {};
    }
}
