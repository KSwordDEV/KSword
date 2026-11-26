#include "SampleImageDefinition.h"
#include "ProjectStorage.h"
#include "../Control/NativeStopCondition.h"

#include <algorithm>
#include <filesystem>

namespace Ksword::ActionAnalyze
{
    // 三端在启动实际绑定前调用，只读取本轮sample的冻结定义，不跟随项目后来修订。
    ProjectResult ResolveSampleImageDefinition(const ProjectDocument& document, std::string_view sampleId,
        std::string_view definitionId, const std::wstring& modulePath, std::uint32_t& rva,
        std::optional<std::string>* imageSha256, std::optional<BreakpointCondition>* condition)
    {
        namespace storage = ProjectStorage;
        rva = 0;
        if (condition)
        {
            condition->reset(); // 输出仅属于本次成功解析的冻结定义。
        }
        if (imageSha256)
        {
            imageSha256->reset(); // 失败不遗留上次定义约束。
        }
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
        if (!found->enabled || !location || !location->rva || (found->module.imageSha256 && !imageSha256) ||
            (found->condition && !condition))
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
        if (imageSha256)
        {
            *imageSha256 = found->module.imageSha256; // 这是冻结约束，实测值由原native装载事件文件提供。
        }
        if (condition)
        {
            *condition = found->condition; // 不从当前项目修订或控件补写冻结原文。
        }
        return {};
    }

    // 同一实现供CLI、Qt与Light的单目标/集合调用，字段目录仍由原生停点层提供。
    ProjectResult PrepareSampleImageCondition(const std::optional<BreakpointCondition>& condition,
        std::wstring& source, Rules::PreparedPredicate& predicate, Rules::Phase phase)
    {
        if (!condition)
        {
            return {}; // 无条件旧定义允许调用方保留自己的显式条件。
        }
        const auto& text = condition->source; // 原UTF-8及固定v3共同属于采样冻结修订。
        const auto count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), nullptr, 0);
        std::wstring frozen(count > 0 ? static_cast<std::size_t>(count) : 0, L'\0'); // 成功前不改调用者草稿。
        if (!count || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(),
            static_cast<int>(text.size()), frozen.data(), count))
        {
            return ProjectStorage::Failure(ProjectError::InvalidArgument, "sampleBreakpointConditionUnicode");
        }
        if (!source.empty() && source != frozen)
        {
            return ProjectStorage::Failure(ProjectError::InvalidArgument, "sampleBreakpointConditionConflict");
        }
        const auto fields = ks::cli::action_analyze::control::NativeStopConditionFields(phase); // 保留调用者原生求值阶段。
        auto prepared = Rules::PreparePredicateExpression(text, phase, fields, "predicate-expr-v3");
        if (prepared.error != Rules::ExpressionError::None)
        {
            return ProjectStorage::Failure(ProjectError::InvalidArgument, Rules::ExpressionErrorId(prepared.error).data());
        }
        source = std::move(frozen);
        predicate = std::move(prepared.predicate);
        return {};
    }
}
