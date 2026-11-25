#include "Controller.h"
#include "Transport.h"

#include <limits>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
using Ksword::Evidence::JsonType;
using V = JsonValue;
constexpr std::size_t kReplayEntries = 4096;
constexpr std::size_t kReplayBytes = 32u << 20;
constexpr std::size_t kReplayEntryOverhead = 512;
constexpr std::size_t kReservedCloseBytes = 2048;
constexpr std::size_t kReservedLiveReplyBytes = 8192;
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

Reply ReadCapabilities(const V&) {
    return {Controller::Capabilities(), Controller::CapabilitiesText(), {}, false};
}

Reply Shutdown(const V&) {
    return {V::makeObject({{"shutdown", V::makeBool(true)}}), "Closing controller", {}, true};
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
    {"controller.capabilities", "capabilities", "List the available offline methods and transport limits.", false, ReadCapabilities},
    {"controller.shutdown", "quit", "End this controller and write the final summary.", false, Shutdown},
};

const Method* Find(std::string_view name, bool repl) {
    for (const auto& method : kMethods) if ((repl ? method.repl : method.name) == name) return &method;
    return nullptr;
}

const ProjectCommand* FindProject(std::string_view name, bool repl) {
    for (const auto& method : ProjectCommands::Catalog()) if ((repl ? method.repl : method.name) == name) return &method;
    return nullptr;
}

const LiveCommand* FindLive(std::string_view name, bool repl) {
    for (const auto& method : LiveSession::Catalog()) if ((repl ? method.repl : method.name) == name) return &method;
    return nullptr;
}

std::string RequestIdentity(const Request& request) {
    JsonObject identity;
    identity.emplace_back("params", request.params);
    if (request.session) identity.emplace_back("session", V::makeArray({V::makeString(request.session->id),
        V::makeString(request.session->epoch)}));
    if (request.expected) identity.emplace_back("expected", *request.expected);
    return CanonicalParams(V::makeObject(std::move(identity)));
}

void AppendMethod(JsonArray& methods, std::string_view name, std::string_view repl, std::string_view summary) {
    methods.push_back(V::makeObject({{"method", V::makeString(std::string(name))},
        {"repl", V::makeString(std::string(repl))}, {"summary", V::makeString(std::string(summary))}}));
}
} // namespace

JsonValue Controller::Capabilities(bool live) {
    const auto make = [](bool live) {
        JsonArray methods;
        for (const auto& method : kMethods) AppendMethod(methods, method.name, method.repl,
            live && method.run == ReadCapabilities ? "List the available R3 methods and transport limits." : method.help);
        for (const auto& method : ProjectCommands::Catalog()) AppendMethod(methods, method.name, method.repl, method.summary);
        if (live) for (const auto& method : LiveSession::Catalog()) AppendMethod(methods, method.name, method.repl, method.summary);
        return V::makeObject({{"backend", V::makeString(live ? "r3" : "offline")}, {"projectStorage", V::makeBool(true)},
            {"archives", V::makeBool(true)}, {"nativeCapture", V::makeBool(live)},
            {"callerProcessMonitoring", V::makeString("not-monitored")},
            {"schemaVersions", V::makeArray({V::makeUInt(kSchemaVersion)})},
            {"methods", V::makeArray(std::move(methods))},
            {"limits", V::makeObject({{"inputLineBytes", V::makeUInt(kInputBytes)},
                {"outputFrameBytes", V::makeUInt(kOutputBytes)}, {"jsonDepth", V::makeUInt(kDepth)},
                {"objectKeys", V::makeUInt(kObjectKeys)}, {"arrayItems", V::makeUInt(kArrayItems)},
                {"requestIdBytes", V::makeUInt(kRequestIdBytes)}, {"replayEntries", V::makeUInt(kReplayEntries)},
                {"replayBytes", V::makeUInt(kReplayBytes)},
                {"pendingOutputFrames", V::makeUInt(kPendingFrames)}, {"outputTimeoutMs", V::makeUInt(kOutputTimeoutMs)}})}});
    };
    static const auto offline = make(false);
    static const auto passive = make(true);
    return live ? passive : offline;
}

std::string Controller::CapabilitiesText(bool live) {
    std::string text = std::string(live ? "R3 passive ETW controller, protocol " : "Offline controller, protocol ") + std::to_string(kSchemaVersion) +
        ". Project storage, offline sample descriptors and Stored segment framing inspection are available.\n";
    text += "Limits per line and frame: " + std::to_string(kInputBytes) + " input bytes, " +
        std::to_string(kOutputBytes) + " output bytes.\n";
    text += "Replay ledger: " + std::to_string(kReplayEntries) + " entries or " + std::to_string(kReplayBytes) + " bytes. Output queue: " +
        std::to_string(kPendingFrames) + " frames, " + std::to_string(kOutputTimeoutMs) + " ms timeout.\n";
    return text + Help({}, live);
}

std::string Controller::Help(std::string_view command, bool live) {
    std::string text;
    if (command.empty() || command == "help") text = "help [command]  Show available commands or a command's usage.\n";
    if (command.empty()) {
        for (const auto& method : kMethods) {
            text.append(method.repl).append("  ").append(live && method.run == ReadCapabilities ?
                "List the available R3 methods and transport limits." : method.help).append("\n");
        }
    } else if (const auto* method = Find(command, true)) {
        text.append(method->repl).append("  ").append(live && method->run == ReadCapabilities ?
            "List the available R3 methods and transport limits." : method->help).append("\n");
    }
    for (const auto& method : ProjectCommands::Catalog()) {
        if (!command.empty() && method.repl != command &&
            !(method.repl.starts_with(command) && method.repl.size() > command.size() && method.repl[command.size()] == ' ')) continue;
        text.append(method.repl);
        if (!method.syntax.empty()) text.append(" ").append(method.syntax);
        text.append("  ").append(method.summary).append("\n");
    }
    if (live) for (const auto& method : LiveSession::Catalog()) {
        if (!command.empty() && method.repl != command) continue;
        text.append(method.repl);
        if (!method.syntax.empty()) text.append(" ").append(method.syntax);
        text.append("  ").append(method.summary).append("\n");
    }
    return text;
}

JsonValue Controller::Finish(std::string_view reason) {
    auto report = session_.Finish(project_.Document(), reason);
    if (!session_.CleanupPending()) project_.Close();
    return report;
}

Reply Controller::Dispatch(Request request, bool repl) {
    const Method* method = Find(request.method, repl);
    const auto* live = live_ ? FindLive(request.method, repl) : nullptr;
    const auto allowedProject = [this](ProjectMethod method) {
        return !session_.HasSample() || method != ProjectMethod::Close;
    };
    const auto projectBusy = [] { return Reject("project-session-open", "Close the live sample first"); };
    if (repl) {
        const auto* args = request.params.asArray();
        if (!args) return Reject("invalid-repl", "Expected a REPL argument list");
        if (request.method == "help") {
            if (args->size() > 2) return Reject("invalid-repl", "Usage is help [command]");
            std::string command;
            for (const auto& arg : *args) {
                std::string word;
                if (!arg.tryGetString(word) || word.empty()) return Reject("invalid-repl", "Expected a command name");
                if (!command.empty()) command.push_back(' ');
                command += word;
            }
            auto text = Help(command, live_);
            if (text.empty()) return Reject("unsupported-method", "Unknown command. Use help.", 5);
            return {{}, std::move(text), {}, false};
        }
        if (live) return session_.DispatchRepl(live->method, *args, project_.Document());
        if ((request.method == "project" || request.method == "sample" || request.method == "archive") && !args->empty()) {
            std::string verb;
            if (args->front().tryGetString(verb)) {
                if (const auto* project = FindProject(request.method + " " + verb, true)) {
                    if (!allowedProject(project->method)) return projectBusy();
                    return project_.DispatchRepl(project->method, JsonArray(args->begin() + 1, args->end()));
                }
            }
        }
        if (!method) return Reject("unsupported-method", "Unknown command. Use help.", 5);
        if (!args->empty()) return Reject("invalid-repl", "This command takes no arguments. Use help.");
        if (method->run == ReadCapabilities) return {Controller::Capabilities(live_), CapabilitiesText(live_), {}};
        return method->run(method->acceptsParams ? V::makeObject({{"acceptVersions", V::makeArray({V::makeUInt(kSchemaVersion)})}})
                                                 : V::makeObject({}));
    }

    const auto identity = [&] { return live_ ? RequestIdentity(request) : CanonicalParams(request.params); };
    const auto cached = replies_.find(request.id);
    if (cached != replies_.end()) {
        if (request.method != cached->second.method || identity() != cached->second.params)
            return Reject("request-id-conflict", "requestId already identifies a different admitted request");
        auto parsed = Ksword::Evidence::ParseJson(cached->second.result);
        if (!parsed.ok()) throw std::logic_error("Invalid cached ActionAnalyze result");
        return {std::move(parsed.value), {}, cached->second.error, false, cached->second.observed};
    }
    const auto* project = FindProject(request.method, false);
    if (!method && !project && !live) return Reject("unsupported-method", "Method is unavailable in this controller", 5);
    if (!live && (request.session || request.expected)) return Reject("invalid-session", "This method omits session and expected");
    if (project && !allowedProject(project->method)) return projectBusy();
    const auto* params = request.params.asObject();
    if (!params || (method && !method->acceptsParams && !params->empty()))
        return Reject("invalid-params", "This method requires an empty params object");
    if (method && method->run == Shutdown) {
        return method->run(request.params);
    }
    auto requestKey = identity();
    const auto charge = request.id.size() + request.method.size() + requestKey.size() + kReplayEntryOverhead;
    // 先预留整帧空间及 ID 记录再执行，避免变更生效后因账本用满而丢失重放资格。
    const bool validClose = project && project->method == ProjectMethod::Close && project_.CanClose(request.params);
    const bool finishLive = live && session_.CanFinalize(live->method, request);
    // A failed first STOP is itself replayable. Leave a separate slot for a fresh retry before close.
    const std::size_t reserved = validClose ? 0 : !live_ ? 1 : !finishLive ? 4 :
        live->method != LiveMethod::Stop ? 1 : session_.CleanupPending() ? 2 : 3;
    const auto entryLimit = kReplayEntries - reserved;
    const auto byteLimit = kReplayBytes - reserved * (live_ ? kReservedLiveReplyBytes : kReservedCloseBytes);
    const auto responseBudget = validClose ? 256 : finishLive ? kReservedLiveReplyBytes / 2 : kResultBytes;
    if (replies_.size() >= entryLimit || replayBytes_ > byteLimit || charge + responseBudget > byteLimit - replayBytes_)
        return Reject("request-ledger-full", "Request ledger is full. Close the open project or shut down with a fresh ID.", 6);
    auto entry = replies_.emplace(std::move(request.id), Cached{std::move(request.method), std::move(requestKey), {}, {}, false}).first;
    Reply reply;
    if (project) reply = project_.Dispatch(project->method, request.params);
    else if (live) reply = session_.Dispatch(live->method, request, project_.Document());
    else if (method->run == ReadCapabilities) reply = {Controller::Capabilities(live_), CapabilitiesText(live_), {}};
    else reply = method->run(request.params);
    if (reply.error && (!project || !project->effect) && (!live || live->method == LiveMethod::Query)) {
        replies_.erase(entry);
        return reply;
    }
    auto encoded = Ksword::Evidence::WriteJson(reply.result);
    if (encoded.size() > responseBudget) throw std::logic_error("ActionAnalyze result exceeds its reserved capacity");
    replayBytes_ += charge + encoded.size();
    entry->second.result = std::move(encoded);
    entry->second.error = reply.error;
    entry->second.observed = reply.observed;
    return reply;
}

} // namespace ks::cli::action_analyze
