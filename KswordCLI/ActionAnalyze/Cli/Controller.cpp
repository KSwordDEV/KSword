#include "Controller.h"
#include "Transport.h"

#include <limits>

namespace ks::cli::action_analyze {
namespace {
using Ksword::Evidence::JsonType;
using V = JsonValue;
constexpr std::size_t kReplayEntries = 4096;
constexpr std::size_t kVersionCount = 16;

Reply Reject(const char* id, const char* message, int code = 1) {
    return {{}, {}, {id, message, std::nullopt, code}, false};
}

Reply Hello(const V& params) {
    const auto* versions = params.find("acceptVersions");
    const auto* items = versions ? versions->asArray() : nullptr;
    if (!params.asObject() || params.asObject()->size() != 1 || !items ||
        items->empty() || items->size() > kVersionCount)
        return Reject("invalid-params", "controller.hello expects only acceptVersions with 1 to 16 version integers");
    bool compatible = false;
    for (const auto& item : *items) {
        std::uint64_t version = 0;
        if (item.type() != JsonType::UInt || !item.tryGetU64(version) || !version ||
            version > (std::numeric_limits<std::uint32_t>::max)())
            return Reject("invalid-params", "acceptVersions must contain positive uint32 JSON integers");
        compatible |= version == kSchemaVersion;
    }
    if (!compatible) return Reject("no-common-version", "The only supported schemaVersion is 1", 5);
    return {V::makeObject({{"selectedVersion", V::makeUInt(kSchemaVersion)}}), "Protocol version 1", {}, false};
}

Reply Capabilities(const V&) {
    return {Controller::Capabilities(), Controller::CapabilitiesText(), {}, false};
}

Reply Shutdown(const V&) {
    return {V::makeObject({{"shutdown", V::makeBool(true)}}), "Closing offline controller", {}, true};
}

struct Method {
    std::string_view name;
    std::string_view repl;
    std::string_view help;
    bool acceptsParams;
    Reply (*run)(const V&);
};

constexpr Method kMethods[] = {
    {"controller.hello", "hello", "Negotiate protocol 1. JSONL params requires acceptVersions.", true, Hello},
    {"controller.capabilities", "capabilities", "List the available offline methods and transport limits.", false, Capabilities},
    {"controller.shutdown", "quit", "End this controller and write the final summary.", false, Shutdown},
};

const Method* Find(std::string_view name, bool repl) {
    for (const auto& method : kMethods) if ((repl ? method.repl : method.name) == name) return &method;
    return nullptr;
}
} // namespace

JsonValue Controller::Capabilities() {
    static const auto capabilities = [] {
        JsonArray methods;
        for (const auto& method : kMethods) {
            methods.push_back(V::makeObject({{"method", V::makeString(std::string(method.name))},
                {"repl", V::makeString(std::string(method.repl))}, {"summary", V::makeString(std::string(method.help))}}));
        }
        return V::makeObject({{"backend", V::makeString("offline")}, {"projectStorage", V::makeBool(false)},
            {"archives", V::makeBool(false)}, {"nativeCapture", V::makeBool(false)},
            {"callerProcessMonitoring", V::makeString("not-monitored")},
            {"schemaVersions", V::makeArray({V::makeUInt(kSchemaVersion)})},
            {"methods", V::makeArray(std::move(methods))},
            {"limits", V::makeObject({{"inputLineBytes", V::makeUInt(kInputBytes)},
                {"outputFrameBytes", V::makeUInt(kOutputBytes)}, {"jsonDepth", V::makeUInt(kDepth)},
                {"objectKeys", V::makeUInt(kObjectKeys)}, {"arrayItems", V::makeUInt(kArrayItems)},
                {"requestIdBytes", V::makeUInt(kRequestIdBytes)}, {"replayEntries", V::makeUInt(kReplayEntries)},
                {"pendingOutputFrames", V::makeUInt(kPendingFrames)}, {"outputTimeoutMs", V::makeUInt(kOutputTimeoutMs)}})}});
    }();
    return capabilities;
}

std::string Controller::CapabilitiesText() {
    std::string text = "Offline controller, protocol " + std::to_string(kSchemaVersion) +
        ". Project storage, archives and native capture are unavailable.\n";
    text += "Limits per line and frame: " + std::to_string(kInputBytes) + " input bytes, " +
        std::to_string(kOutputBytes) + " output bytes.\n";
    text += "Replay ledger: " + std::to_string(kReplayEntries) + " entries. Output queue: " +
        std::to_string(kPendingFrames) + " frames, " + std::to_string(kOutputTimeoutMs) + " ms timeout.\n";
    return text + Help();
}

std::string Controller::Help(std::string_view command) {
    std::string text;
    if (command.empty() || command == "help") text = "help [command]  Show available commands or a command's usage.\n";
    if (command.empty()) {
        for (const auto& method : kMethods) {
            text.append(method.repl).append("  ").append(method.help).append("\n");
        }
    } else if (const auto* method = Find(command, true)) {
        text.append(method->repl).append("  ").append(method->help).append("\n");
    }
    return text;
}

Reply Controller::Dispatch(Request request, bool repl) {
    const Method* method = Find(request.method, repl);
    if (repl) {
        const auto* args = request.params.asArray();
        if (!args) return Reject("invalid-repl", "Expected a REPL argument list");
        if (request.method == "help") {
            if (args->size() > 1) return Reject("invalid-repl", "Usage is help [command]");
            std::string command;
            if (!args->empty() && (!args->front().tryGetString(command) || command.empty()))
                return Reject("invalid-repl", "Expected a command name");
            auto text = Help(command);
            if (text.empty()) return Reject("unsupported-method", "Unknown command. Use help.", 5);
            return {{}, std::move(text), {}, false};
        }
        if (!method) return Reject("unsupported-method", "Unknown command. Use help.", 5);
        if (!args->empty()) return Reject("invalid-repl", "This command takes no arguments. Use help.");
        return method->run(method->acceptsParams ? V::makeObject({{"acceptVersions", V::makeArray({V::makeUInt(kSchemaVersion)})}})
                                                 : V::makeObject({}));
    }

    const auto cached = replies_.find(request.id);
    if (cached != replies_.end()) {
        if (request.method != cached->second.method || CanonicalParams(request.params) != cached->second.params)
            return Reject("request-id-conflict", "requestId already identifies a different admitted request");
        return cached->second.reply;
    }
    if (!method) return Reject("unsupported-method", "Method is unavailable in this offline controller", 5);
    const auto* params = request.params.asObject();
    if (!params || (!method->acceptsParams && !params->empty()))
        return Reject("invalid-params", "This method requires an empty params object");
    // 当前除终止外只有查询。账本用满后仍留终止入口，且不会重新使用已登记的 ID。
    if (replies_.size() >= kReplayEntries && method->run != Shutdown)
        return Reject("request-ledger-full", "Request ledger is full. Close this controller and start another.", 6);
    auto reply = method->run(request.params);
    if (!reply.error && !reply.shutdown) {
        // 两种可缓存结果都是静态值，避免每个 ID 持有一份完整能力投影。
        replies_.emplace(std::move(request.id), Cached{std::move(request.method), CanonicalParams(request.params), reply});
    }
    return reply;
}

} // namespace ks::cli::action_analyze
