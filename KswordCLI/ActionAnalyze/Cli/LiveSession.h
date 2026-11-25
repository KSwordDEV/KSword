#pragma once

#include "Protocol.h"

#include <memory>
#include <span>

namespace Ksword::ActionAnalyze { class ProjectDocument; }

namespace ks::cli::action_analyze {

struct Reply;

enum class LiveMethod { Open, Query, Findings, Stop, Close };

struct LiveCommand {
    LiveMethod method;
    std::string_view name;
    std::string_view repl;
    std::string_view syntax;
    std::string_view summary;
};

// The request thread owns the project lease and services one passive source.
class LiveSession final {
public:
    LiveSession();
    ~LiveSession();
    static std::span<const LiveCommand> Catalog() noexcept;

    bool HasSample() const noexcept;
    // 高频只读来源的状态查询不占用有界请求账本。
    bool UncachedQuery() const noexcept;
    bool NeedsTick() const noexcept;
    bool CleanupPending() const noexcept;
    bool Incomplete() const noexcept;
    bool CanFinalize(LiveMethod method, const Request& request) const;
    void Tick(Ksword::ActionAnalyze::ProjectDocument& project);
    JsonValue Finish(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view reason);
    Reply Dispatch(LiveMethod method, const Request& request, Ksword::ActionAnalyze::ProjectDocument& project);
    Reply DispatchRepl(LiveMethod method, const JsonArray& args, Ksword::ActionAnalyze::ProjectDocument& project);

private:
    // 校验 JSONL 授权与冻结身份，绑定单一只读来源并创建项目采样。
    Reply OpenApiArchive(const Request& request, Ksword::ActionAnalyze::ProjectDocument& project);
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace ks::cli::action_analyze
