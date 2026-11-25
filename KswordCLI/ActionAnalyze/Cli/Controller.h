#pragma once

#include "Protocol.h"

#include <map>

namespace ks::cli::action_analyze {

struct Reply {
    JsonValue result;
    std::string text;
    Fault error;
    bool shutdown = false;
};

// 本阶段只有离线控制器。接入项目时，方法目录和控制器仍是两种输入的共同入口。
class Controller {
public:
    static JsonValue Capabilities();
    static std::string CapabilitiesText();
    static std::string Help(std::string_view command = {});
    Reply Dispatch(Request request, bool repl);

private:
    struct Cached {
        std::string method;
        std::string params;
        Reply reply;
    };
    std::map<std::string, Cached> replies_;
};

} // namespace ks::cli::action_analyze
