#pragma once

#include "Protocol.h"
#include "../Project/ProjectDocument.h"

#include <span>

namespace ks::cli::action_analyze {

struct Reply;

enum class ProjectMethod { Open, Query, Close, Create, Save, ListSamples, QuerySample, CreateSample, InspectArchive };

struct ProjectCommand {
    ProjectMethod method;
    std::string_view name;
    std::string_view repl;
    std::string_view syntax;
    std::string_view summary;
    bool effect;
};

// CLI 方法与项目文档的适配层。控制器串行持有一个项目快照。
class ProjectCommands {
public:
    static std::span<const ProjectCommand> Catalog() noexcept;
    Reply Dispatch(ProjectMethod method, const JsonValue& params);
    Reply DispatchRepl(ProjectMethod method, const JsonArray& args);
    bool CanClose(const JsonValue& params) const;
    void Close() noexcept { document_.Close(); }
    Ksword::ActionAnalyze::ProjectDocument& Document() noexcept { return document_; }

private:
    Ksword::ActionAnalyze::ProjectDocument document_;
};

} // namespace ks::cli::action_analyze
