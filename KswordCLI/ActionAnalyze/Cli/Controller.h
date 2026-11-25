#pragma once

#include "Protocol.h"
#include "ProjectCommands.h"

#include <map>

namespace ks::cli::action_analyze {

struct Reply {
    JsonValue result;
    std::string text;
    Fault error;
    bool shutdown = false;
    bool observed = false;
};

// 两种输入共用同一个离线项目和方法派发器。
class Controller {
public:
    static JsonValue Capabilities();
    static std::string CapabilitiesText();
    static std::string Help(std::string_view command = {});
    Reply Dispatch(Request request, bool repl);
    void CloseProject() noexcept { project_.Close(); }

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
};

} // namespace ks::cli::action_analyze
