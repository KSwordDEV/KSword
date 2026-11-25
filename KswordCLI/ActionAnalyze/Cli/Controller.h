#pragma once

#include "Protocol.h"
#include "ProjectCommands.h"
#include "LiveSession.h"

#include <map>

namespace ks::cli::action_analyze {

struct Reply {
    JsonValue result;
    std::string text;
    Fault error;
    bool shutdown = false;
    bool observed = false;
};

// 两种输入共用项目和派发器。实时方法仅在明确选择 R3 时登记。
class Controller {
public:
    explicit Controller(bool live = false) : live_(live) {}
    static JsonValue Capabilities(bool live = false);
    static std::string CapabilitiesText(bool live = false);
    static std::string Help(std::string_view command = {}, bool live = false);
    Reply Dispatch(Request request, bool repl);
    bool NeedsTick() const noexcept { return session_.NeedsTick(); }
    void Tick() { session_.Tick(project_.Document()); }
    JsonValue Finish(std::string_view reason);
    bool CleanupPending() const noexcept { return session_.CleanupPending(); }
    bool Incomplete() const noexcept { return session_.Incomplete(); }

private:
    struct Cached {
        std::string method;
        std::string params;
        std::string result;
        Fault error;
        bool observed = false;
    };
    std::map<std::string, Cached> replies_;
    std::size_t replayBytes_ = 0;
    ProjectCommands project_;
    LiveSession session_;
    bool live_;
};

} // namespace ks::cli::action_analyze
