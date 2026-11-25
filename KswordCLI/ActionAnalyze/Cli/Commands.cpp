#include "Commands.h"

#include "../../CommandRegistry.h"
#include "Controller.h"
#include "Transport.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <iostream>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
using V = JsonValue;

std::wstring Wide(std::string_view text) {
    if (text.empty()) return {};
    const auto count = static_cast<int>(text.size());
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), count, nullptr, 0);
    if (!size) throw std::runtime_error("ActionAnalyze produced invalid UTF-8");
    std::wstring wide(size, L'\0');
    (void)MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), count, wide.data(), size);
    return wide;
}

std::string ControllerId() {
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
        throw std::runtime_error("Could not read the controller creation time");
    const auto started = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    return "aa-" + std::to_string(GetCurrentProcessId()) + "-" + std::to_string(started);
}

// 一个会话独占标准输出。只有成功排队的完整记录才会让序号前进。
class Session {
public:
    explicit Session(bool jsonl) : jsonl_(jsonl), id_(ControllerId()) {}

    int Run() {
        if (const auto error = transport_.Start(jsonl_)) {
            std::wcerr << L"error: " << Wide(error.message) << L'\n';
            return error.code;
        }
        try {
            if (!Emit("hello", {{"capabilities", Controller::Capabilities()}}, "ActionAnalyze (offline). Type help for commands."))
                return 3;
            return Loop();
        } catch (const std::exception&) {
            return Complete("internal-error", 3, {"internal-error", "Controller failed", std::nullopt, 3});
        }
    }

private:
    bool Emit(const char* type, JsonObject fields, std::string text) {
        if (jsonl_) {
            JsonObject message{{"schemaVersion", V::makeUInt(kSchemaVersion)}, {"type", V::makeString(type)},
                {"controllerId", V::makeString(id_)}, {"streamSequence", V::makeString(std::to_string(sequence_ + 1))}};
            for (auto& field : fields) message.push_back(std::move(field));
            text = Ksword::Evidence::WriteJson(V::makeObject(std::move(message)));
        }
        if (text.empty() || text.back() != '\n') text.push_back('\n');
        if (!transport_.Send(std::move(text))) return false;
        ++sequence_;
        return true;
    }

    bool Issue(const Fault& error) {
        return Emit("protocolError", {{"requestId", V::makeNull()},
            {"inputSequence", V::makeString(std::to_string(inputSequence_))}, {"error", FaultJson(error)}},
            std::string("error: ") + error.message);
    }

    int Complete(const char* reason, int code, const Fault& error = {}) {
        const bool queued = Emit("summary", {{"reason", V::makeString(reason)}, {"exitCode", V::makeUInt(code)},
            {"clean", V::makeBool(true)}, {"liveSession", V::makeNull()}, {"archive", V::makeNull()},
            {"unresolvedResponsibilities", V::makeArray({})}, {"error", FaultJson(error)}},
            std::string("Session closed: ") + reason);
        return queued && transport_.Finish() ? code : 3;
    }

    int Loop() {
        for (;;) {
            if (!jsonl_ && transport_.Interactive() && !transport_.Send("action> ")) return 3;
            auto input = transport_.Next();
            switch (input.kind) {
            case InputKind::Eof: return Complete("eof", 0);
            case InputKind::Break: return Complete("ctrl-break", 6);
            case InputKind::OutputLost: return 3;
            case InputKind::Fatal:
                ++inputSequence_;
                if (!Issue(input.fault)) return 3;
                return Complete(input.fault.code == 1 ? "protocol-failed" : "input-failed", input.fault.code, input.fault);
            case InputKind::Line: break;
            }
            ++inputSequence_;
            auto decoded = jsonl_ ? DecodeJsonLine(input.line) : DecodeReplLine(input.line);
            if (decoded.error && decoded.request.id.empty()) {
                if (!Issue(decoded.error)) return 3;
                continue;
            }
            if (!jsonl_ && decoded.request.method.empty()) continue;
            const auto requestId = decoded.request.id;
            const auto reply = decoded.error ? Reply{{}, {}, decoded.error, false}
                                             : controller_.Dispatch(std::move(decoded.request), !jsonl_);
            const bool sent = Emit("response", {{"requestId", V::makeString(requestId)},
                {"phase", V::makeString("completed")}, {"effectPhase", V::makeString(reply.shutdown ? "observed" : "not-applicable")},
                {"result", reply.result}, {"error", FaultJson(reply.error)}},
                reply.error ? std::string("error: ") + reply.error.message : reply.text);
            if (!sent) return 3;
            if (reply.shutdown) return Complete("shutdown", 0);
        }
    }

    bool jsonl_;
    std::string id_;
    std::uint64_t sequence_ = 0;
    std::uint64_t inputSequence_ = 0;
    Controller controller_;
    Transport transport_;
};

int RunSession(const Args& args) {
    const auto input = args.get(L"--input", L"repl");
    const auto output = args.get(L"--output", L"text");
    const bool jsonl = input == L"jsonl" && output == L"jsonl";
    if (!jsonl && (input != L"repl" || output != L"text"))
        throw std::invalid_argument("supported combinations are repl/text and jsonl/jsonl");
    return Session(jsonl).Run();
}
} // namespace

void RegisterCommands() {
    addFamily(L"analyze", L"Offline ActionAnalyze controller and session transport.");
    Command capabilities;
    capabilities.path = L"analyze capabilities";
    capabilities.syntax = L"KswordCLI.exe analyze capabilities [--json] [--backend offline]";
    capabilities.summary = L"Report the methods and limits of the offline controller.";
    capabilities.options = L"Optional: --json, --backend offline.";
    capabilities.notes = L"Queries the CLI implementation. Does not open a project or start capture.";
    capabilities.run = [](const Args&) -> Result {
        const auto data = Controller::Capabilities();
        return {0, Json{Wide(Ksword::Evidence::WriteJson(data)),
            Wide(Controller::CapabilitiesText())}, {}};
    };
    capabilities.supportsR3 = false;
    capabilities.defaultBackend = L"offline";
    addCommand(std::move(capabilities));

    Command session;
    session.path = L"analyze session";
    session.syntax = L"KswordCLI.exe analyze session [--input repl|jsonl --output text|jsonl] [--backend offline]";
    session.summary = L"Keep one offline controller alive to receive multiple requests.";
    session.options = L"Default: --input repl --output text. For machine use: --input jsonl --output jsonl with UTF-8 byte streams. Only --backend offline is supported.";
    session.notes = L"JSONL requires LF or CRLF. Use help in the REPL and quit to close. EOF also closes the controller.";
    session.runStreaming = RunSession;
    session.supportsR3 = false;
    session.defaultBackend = L"offline";
    addCommand(std::move(session));
}

} // namespace ks::cli::action_analyze
