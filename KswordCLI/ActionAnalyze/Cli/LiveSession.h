#pragma once

#include "Protocol.h"

#include <memory>
#include <span>

namespace Ksword::ActionAnalyze { class ProjectDocument; }

namespace ks::cli::action_analyze {

struct Reply;

enum class LiveMethod { Open, Query, Stop, Close };

struct LiveCommand {
    LiveMethod method;
    std::string_view name;
    std::string_view repl;
    std::string_view syntax;
    std::string_view summary;
};

// The request thread owns the project lease and finalizes one bounded passive source.
class LiveSession final {
public:
    LiveSession();
    ~LiveSession();
    static std::span<const LiveCommand> Catalog() noexcept;

    bool HasSample() const noexcept;
    bool NeedsTick() const noexcept;
    bool CleanupPending() const noexcept;
    bool Incomplete() const noexcept;
    bool CanFinalize(LiveMethod method, const Request& request) const;
    void Tick(Ksword::ActionAnalyze::ProjectDocument& project);
    JsonValue Finish(Ksword::ActionAnalyze::ProjectDocument& project, std::string_view reason);
    Reply Dispatch(LiveMethod method, const Request& request, Ksword::ActionAnalyze::ProjectDocument& project);
    Reply DispatchRepl(LiveMethod method, const JsonArray& args, Ksword::ActionAnalyze::ProjectDocument& project);

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace ks::cli::action_analyze
