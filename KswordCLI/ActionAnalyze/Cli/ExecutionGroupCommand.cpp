#include "ExecutionGroupCommand.h"

#include "ExecutionGroupProtocol.h"
#include "Transport.h"
#include "../Project/ProjectStorage.h"
#include "../../CommandRegistry.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <charconv>
#include <iostream>
#include <map>
#include <stdexcept>

namespace ks::cli::action_analyze {
namespace {
namespace n = control;
namespace p = execution_group;
using V = JsonValue;
V Text(std::string_view text) { return V::makeString(std::string(text)); }
V Count(std::uint64_t number) { return Text(std::to_string(number)); }

// 输入范围参数原文，输出规范正十进制u64；拒绝符号、溢出、前导零和尾随字符。
bool RangeNumber(std::string_view text, std::uint64_t& number)
{
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number); // 直接保留64位精度。
    return number && parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() && text == std::to_string(number);
}

class ExecutionGroupSession final {
public:
    ExecutionGroupSession(bool jsonl, n::OwnerIdentity identity, std::vector<n::ExecutionGroupSite> sites)
        : jsonl_(jsonl), identity_(std::move(identity)), sites_(std::move(sites)) {}

    int Run()
    {
        if (const auto fault = transport_.Start(jsonl_)) { std::cerr << fault.message << '\n'; return fault.code; }
        try {
            const auto started = group_.Start(std::move(sites_), true, n::NativeTargetDisposition::ResumeAndDetach, identity_.sampleId);
            collectionId_ = started.collectionId; // 仅校验包络用，不因校验或请求重放触发条件Query。
            if (!Emit("hello", {}, V::makeObject({{"sampleId", Text(identity_.sampleId)}, {"control", p::Report(started, !jsonl_)},
                {"protocol", V::makeObject({{"maxMembers", V::makeUInt(n::kOwnedExecutionGroupLimit)},
                    {"mutationRequestId", Text("execution/<strictly increasing canonical positive uint64>")},
                     {"replayEntries", V::makeUInt(128)}, {"stopToken", Text("Mixed pause/continue copy complete member.sessionToken entries; legacy lists combine pauseToken for running members and stopToken for Held; step/cancel retain stopToken/stepToken")},
                    {"pauseScope", Text("all/selected validate every explicit session first; exact Held is already-held; Armed bindings call original Pause")},
                    {"continueScope", Text("all/selected validate every explicit session first; exact Held calls Continue; Armed running is already-running")},
                     {"sessionTable", Text("expected:{collectionId,sessions:[complete owner+control sessionToken]}; legacy stops tokens remain accepted")},
                     {"rangeAdd", Text("control.execution.range.add params:{address,bytes} canonical decimal strings; expected:{collectionId,stops:[one complete current NX Held token]}; never Continue")},
                    {"outcomes", Text("Every requested member has actionAttempted and disposition; already-held/already-running never fabricate a release")},
                    {"membersShareOwner", V::makeBool(false)}, {"simultaneousFreeze", V::makeBool(false)}})}}))) return End("output-lost", 3);
            // 部分启动失败仍进入命令循环，保留成功附加者供状态、继续、步进及清退。
            if (started.members.empty()) return End("configuration-rejected", 1);
            return Loop();
        } catch (...) { return End("execution-group-processing-failed", 6); }
    }

private:
    struct Saved { std::string signature; V result; };

    bool Emit(std::string_view type, std::string_view id, V result)
    {
        auto text = Ksword::Evidence::WriteJson(V::makeObject({{"schemaVersion", V::makeUInt(1)}, {"type", Text(type)},
            {"session", V::makeObject({{"id", Text(identity_.sessionId)}, {"epoch", Text(identity_.epoch)}})},
            {"streamSequence", Count(sequence_ + 1)}, {"requestId", id.empty() ? V::makeNull() : Text(id)}, {"result", std::move(result)}}));
        if (text.size() + 1 > kOutputBytes) {
            // 硬输出上限不能静默裁掉控制票据。简短诊断后按正式路径清退全部原 owner。
            text = Ksword::Evidence::WriteJson(V::makeObject({{"schemaVersion", V::makeUInt(1)}, {"type", Text("error")},
                {"errorId", Text("execution-group-output-limit")}, {"message", Text("Full member report exceeds 256 KiB; original owners are closing")}}));
            (void)transport_.Send(text + '\n');
            return false;
        }
        if (!transport_.Send(std::move(text) + '\n')) return false;
        ++sequence_;
        return true;
    }

    bool Invalid(const Request& request, const char* id, const char* message)
    {
        return Emit("error", request.id, FaultJson({id, message, std::nullopt, 1, "cli", 0, "execution-group"}));
    }

    bool Empty(const Request& request) const
    {
        return jsonl_ ? request.params.asObject() && request.params.asObject()->empty() :
            request.params.asArray() && request.params.asArray()->empty();
    }

    // 请求签名含完整 expected。重放只返回本次原回执，永远不重新选择当前成员或重新 Continue。
    template<class Action>
    bool Mutate(const Request& request, std::string id, std::string signature, Action&& action)
    {
        if (!id.starts_with("execution/")) return Invalid(request, "invalid-request-id", "Mutation requires execution/N");
        const auto text = std::string_view(id).substr(10);
        std::uint64_t number = 0;
        const auto parsed = std::from_chars(text.data(), text.data() + text.size(), number);
        if (!number || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() || text != std::to_string(number))
            return Invalid(request, "invalid-request-id", "Mutation requires execution/<canonical positive uint64>");
        if (const auto found = saved_.find(number); found != saved_.end()) {
            if (found->second.signature != signature) return Invalid(request, "request-id-conflict", "Request ID already names different arguments");
            return Emit("response", request.id, found->second.result);
        }
        if (number <= highWater_) return Invalid(request, "replay-expired", "Original receipt is no longer retained; no action attempted");
        // 先占用代次，异常也不能让同 ID 再次触发原生动作。
        highWater_ = number;
        auto [position, inserted] = saved_.emplace(number, Saved{std::move(signature), V::makeObject({
            {"stage", Text("execution-group-request-interrupted")}, {"readbackRequired", V::makeBool(true)}})});
        (void)inserted;
        if (saved_.size() > 128) saved_.erase(saved_.begin());
        position->second.result = action();
        return Emit("response", request.id, position->second.result);
    }

    bool Dispatch(const Request& request, bool& closed)
    {
        if (request.session && (request.session->id != identity_.sessionId || request.session->epoch != identity_.epoch))
            return Invalid(request, "wrong-session", "Use the current hello session and epoch");
        const auto& method = request.method;
        const bool query = method == "status" || method == "control.query";
        const bool close = method == "quit" || method == "close" || method == "controller.shutdown";
        const bool resume = method == "continue" || method == "control.continue";
        const bool pause = method == "pause" || method == "control.pause"; // 同一原执行owner内主动暂停，非新附加。
        const bool scoped = resume || pause;
        const bool step = method == "step" || method == "control.step";
        const bool cancel = method == "step-cancel" || method == "control.step.cancel";
        const bool range = method == "execution-range-add" || method == "control.execution.range.add"; // 原成员显式追加NX页。
        if (!jsonl_ && method == "help" && Empty(request)) return Emit("response", {}, Text(
            "status | pause execution/N all|selected TOKENHEX[,TOKENHEX...] | continue execution/N all|selected TOKENHEX[,TOKENHEX...] | step execution/N into|over-call|out TOKENHEX | step-cancel execution/N TOKENHEX | execution-range-add execution/N ADDRESS BYTES TOKENHEX | quit"));
        if (query && Empty(request) && !request.expected) return Emit("response", request.id, p::Report(group_.Query(), !jsonl_));
        if (jsonl_ && !request.session) return Invalid(request, "session-required", "Control requires the current hello session identity");
        if (close && Empty(request) && !request.expected) {
            const auto result = group_.Close();
            cleanupOnly_ = !result.clean;
            closed = result.clean;
            return Emit("response", request.id, p::Report(result, !jsonl_));
        }
        if (!pause && !resume && !step && !cancel && !range) return Invalid(request, "unsupported-method", "Use status, pause, continue, step, step-cancel, execution-range-add or quit");
        if (cleanupOnly_) return Invalid(request, "cleanup-pending", "Original owners are closing; status and quit remain available");
        std::string id = request.id, scope, mode;
        std::string addressText, bytesText; // 范围原文参与请求签名，不从当前绑定补造。
        std::uint64_t address = 0, bytes = 0; // 解析后按值提交原成员，仍由native核对实际私有页。
        std::vector<n::NativeControlResult> stops;
        std::vector<n::ExecutionGroupSessionEntry> sessions; // 新混合格式显式携带每个原owner。
        JsonArray tokens;
        bool sessionTable = false; // 单个批次不能混入旧裸control与新owner表，避免含糊范围。
        const auto* fields = request.params.asObject();
        const auto* args = request.params.asArray();
        if (jsonl_) {
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* collection = request.expected ? request.expected->find("collectionId") : nullptr;
            const auto* stopValues = request.expected ? request.expected->find("stops") : nullptr;
            const auto* sessionValues = request.expected ? request.expected->find("sessions") : nullptr;
            std::string collectionId;
            if (!expected || expected->size() != 2 || !collection || !collection->tryGetString(collectionId) ||
                collectionId != collectionId_ || (stopValues != nullptr) == (sessionValues != nullptr) ||
                (sessionValues && (!scoped || !sessionValues->asArray())) || (stopValues && !stopValues->asArray()))
                return Invalid(request, "invalid-expected", "Require expected:{collectionId,sessions:[owner+control tokens]} for pause/continue or legacy stops:[complete tokens]");
            sessionTable = sessionValues != nullptr;
            tokens = *(sessionTable ? sessionValues : stopValues)->asArray();
            if (!fields || (scoped ? fields->size() != 1 || !request.params.find("scope") || !request.params.find("scope")->tryGetString(scope) :
                step ? fields->size() != 1 || !request.params.find("mode") || !request.params.find("mode")->tryGetString(mode) :
                range ? fields->size() != 2 || !request.params.find("address") || !request.params.find("address")->tryGetString(addressText) ||
                    !request.params.find("bytes") || !request.params.find("bytes")->tryGetString(bytesText) : !fields->empty()))
                return Invalid(request, "invalid-params", "Pause/continue require scope; step requires mode; range-add requires address and bytes strings; step-cancel requires empty params");
        } else {
            std::string tokenText;
            if (request.expected || !args || args->size() != (range ? 4 : cancel ? 2 : 3) || !(*args)[0].tryGetString(id) ||
                !args->back().tryGetString(tokenText) ||
                (range ? !(*args)[1].tryGetString(addressText) || !(*args)[2].tryGetString(bytesText) :
                    !cancel && !(*args)[1].tryGetString(scoped ? scope : mode)))
                return Invalid(request, "invalid-repl", "Use help; include execution/N and complete TOKENHEX");
            for (;;) {
                const auto at = tokenText.find(',');
                V token;
                if (!p::ParseTokenText(std::string_view(tokenText).substr(0, at), token))
                    return Invalid(request, "invalid-stop-token", "TOKENHEX must contain the complete reported token bytes");
                tokens.push_back(std::move(token));
                if (tokens.size() > n::kOwnedExecutionGroupLimit) return Invalid(request, "too-many-stops", "At most 16 tokens");
                if (at == std::string::npos) break;
                tokenText.erase(0, at + 1);
            }
        }
        // 只接用户明确填写的整页范围；先完成协议校验，再消费execution/N流水。
        if (range && (!RangeNumber(addressText, address) || !RangeNumber(bytesText, bytes) ||
            address % 4096 || bytes % 4096 || bytes > 64ull * 4096 || address > UINT64_MAX - bytes))
        {
            return Invalid(request, "invalid-execution-range", "Require positive aligned address, 1..64 whole pages and no uint64 overflow");
        }
        if (tokens.empty() || tokens.size() > n::kOwnedExecutionGroupLimit || (!scoped && tokens.size() != 1) ||
            (scoped && scope != "all" && scope != "selected") || (step && mode != "into" && mode != "over-call" && mode != "out"))
            return Invalid(request, "invalid-selection", "Provide explicit nonempty stops and valid scope or mode; step/cancel select exactly one");
        // 输入完整批次令牌；输出只含同一种形状的值数组，不借用现场状态补票。
        for (const auto& token : tokens)
        {
            if (scoped && (sessionTable || token.find("owner")))
            {
                n::ExecutionGroupSessionEntry entry; // 原样解析完整owner与control，不补现场数据。
                if (!p::ParseSessionToken(token, entry))
                {
                    return Invalid(request, "invalid-session-token", "Copy complete member.sessionToken");
                }
                sessions.push_back(std::move(entry));
                continue;
            }
            n::NativeControlResult state; // 兼容旧完整control列表，仍严格解析全部停止和绑定字段。
            if (!p::ParseStopToken(token, state))
            {
                return Invalid(request, "invalid-stop-token", "Copy each complete current member token");
            }
            stops.push_back(std::move(state));
        }
        if (!sessions.empty() && !stops.empty())
        {
            return Invalid(request, "mixed-token-shapes", "Use one complete session table or one legacy token list");
        }
        const auto signature = CanonicalParams(V::makeObject({{"action", Text(pause ? "pause" : resume ? "continue" : step ? "step" : range ? "range-add" : "step-cancel")},
            {"scope", Text(scope)}, {"mode", Text(mode)}, {"address", Text(addressText)}, {"bytes", Text(bytesText)}, {"stops", V::makeArray(tokens)}}));
        return Mutate(request, std::move(id), signature, [&] {
            n::ExecutionGroupResult result; // 一次幂等修改仅派发一个原集合动作，并保存其全部成员结果。
            if (pause)
            {
                result = sessions.empty() ? group_.Pause(stops, scope == "all") : group_.Pause(sessions, scope == "all");
            }
            else if (resume)
            {
                result = sessions.empty() ? group_.Continue(stops, scope == "all") : group_.Continue(sessions, scope == "all");
            }
            else if (cancel)
            {
                result = group_.CancelStep(stops.front());
            }
            else if (range)
            {
                result = group_.AddRange(stops.front(), address, bytes); // 不附加、不继续，成员原session分配独立range/N。
            }
            else
            {
                const auto stepMode = mode == "into" ? n::NativeStepMode::Into :
                    mode == "over-call" ? n::NativeStepMode::OverCall : n::NativeStepMode::Out; // 已校验的三种单成员步进。
                result = group_.Step(stops.front(), stepMode);
            }
            return p::Report(result, !jsonl_);
        });
    }

    int End(std::string_view reason, int code)
    {
        cleanupOnly_ = true;
        auto state = group_.Close();
        while (!state.clean) {
            // 原 Close 会中止成员步进并归还停止责任；未 clean 不退出、不销毁其原 owner。
            const auto input = transport_.Next(true);
            if (input.kind == InputKind::Line) {
                try {
                    const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Live) : DecodeReplLine(input.line);
                    bool closed = false;
                    if (decoded.error) (void)Emit("error", decoded.request.id, FaultJson(decoded.error));
                    else if (!decoded.request.method.empty()) (void)Dispatch(decoded.request, closed);
                } catch (...) { std::cerr << "execution-group-cleanup-command-failed: original owners retained\n"; }
            } else if (input.kind != InputKind::Tick) Sleep(100);
            state = group_.Close(); // 在同一串行通道重试原清退，不建立新 owner 或释放票据。
        }
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)}, {"exitCode", V::makeUInt(code)},
            {"control", p::Report(state, !jsonl_)}}));
        return sent && transport_.Finish() ? code : 3;
    }

    int Loop()
    {
        for (;;) {
            const auto input = transport_.Next();
            if (input.kind == InputKind::Tick)
            {
                (void)group_.Query(); // 原串行会话推进条件和主动暂停回读，不创建第二个查询执行者。
                continue;
            }
            if (input.kind != InputKind::Line) return End(input.kind == InputKind::Eof ? "eof" :
                input.kind == InputKind::Break ? "ctrl-break" : input.kind == InputKind::OutputLost ? "output-lost" : "input-failed",
                input.kind == InputKind::Eof ? 0 : 3);
            const auto decoded = jsonl_ ? DecodeJsonLine(input.line, RequestProfile::Live) : DecodeReplLine(input.line);
            if (decoded.error) { if (!Emit("error", decoded.request.id, FaultJson(decoded.error))) return End("output-lost", 3); continue; }
            if (decoded.request.method.empty()) continue;
            bool closed = false;
            if (!Dispatch(decoded.request, closed)) return End("output-lost", 3);
            if (closed) return End("requested", 0);
        }
    }

    bool jsonl_;
    n::OwnerIdentity identity_; // 仅 CLI 包络的身份，成员原身份由各 session 独立创建。
    std::vector<n::ExecutionGroupSite> sites_;
    Transport transport_;
    n::OwnedExecutionGroup group_;
    std::string collectionId_; // 本活集合固定包络身份，不参与成员owner替换。
    bool cleanupOnly_ = false;
    std::uint64_t sequence_ = 0, highWater_ = 0;
    std::map<std::uint64_t, Saved> saved_;
};

int Run(const Args& args)
{
    const auto input = args.get(L"--input", L"repl");
    if (!args.has(L"--confirm") || args.get(L"--disposition") != L"resume-detach" ||
        (input != L"repl" && input != L"jsonl") || (args.has(L"--backend") && args.get(L"--backend") != L"r3"))
        throw std::invalid_argument("Require --confirm --disposition resume-detach --input repl|jsonl (R3 only)");
    auto sites = p::ReadSites(args.require(L"--sites")); // 全部配置及条件先读入，任何错误都在附加前拒绝。
    n::OwnerIdentity identity;
    using Ksword::ActionAnalyze::ProjectStorage::NewId;
    if (!NewId(identity.sampleId) || !NewId(identity.sessionId) || !NewId(identity.epoch) || !NewId(identity.backendInstanceId)) return 3;
    return ExecutionGroupSession(input == L"jsonl", std::move(identity), std::move(sites)).Run();
}
} // namespace

void RegisterExecutionGroupCommand()
{
    Command command;
    command.path = L"analyze execution-group session";
    command.syntax = L"KswordCLI.exe analyze execution-group session --sites PATH --confirm --disposition resume-detach [--input repl|jsonl] [--backend r3]";
    command.summary = L"Attach one frozen execution site per explicit process instance, with independent native owners and conditions.";
    command.options = L"--sites is a UTF-8 JSON disk file without BOM, at most 128 KiB: {schemaVersion:1,sites:[...]}. "
        L"1-16 distinct PIDs; each item requires numeric pid and canonical positive decimal-string creationFileTime. "
        L"Image: absolute DOS module plus exactly one numeric uint32 rva or case-sensitive exactExport. "
        L"Private: decimal-string address and rangeBytes (0 for one DR0 site, otherwise aligned 4 KiB multiples up to 64 pages). "
        L"Optional condition uses the shared typed data-watch expression compiler; configuration is frozen before attach.";
    command.notes = L"REPL: status; pause execution/N all|selected TOKENHEX[,TOKENHEX...]; continue execution/N all|selected TOKENHEX[,TOKENHEX...]; step execution/N into|over-call|out TOKENHEX; "
        L"step-cancel execution/N TOKENHEX; execution-range-add execution/N ADDRESS BYTES TOKENHEX; quit. Copy full replToken bytes, never a member index. "
        L"JSONL: control.query; control.pause params:{scope:all|selected}; control.continue params:{scope:all|selected}; control.step params:{mode:into|over-call|out}; "
        L"control.step.cancel params:{}; control.execution.range.add params:{address,bytes} (canonical positive decimal strings); controller.shutdown params:{}. Mutations require current hello session id/epoch, "
        L"execution/N request IDs, and expected:{collectionId,stops:[complete current member.pauseToken, stopToken or stepToken]}. "
        L"Mixed pause/continue also accept expected:{collectionId,sessions:[complete member.sessionToken owner+control objects]}; REPL accepts replSessionToken lists. "
        L"All/selected validate the entire explicit set first; Pause reports already-held, Continue reports already-running, without native calls for those members. "
        L"Every outcome includes actionAttempted and disposition; unclear/recovery/foreign states reject the batch without clearing responsibility. "
        L"Pause checks all selected live owner/PID/creation/binding request IDs before original session.Pause; no old stop is required. "
        L"ManualPause receipts remain separate; exact Held ManualPause can continue but cannot step in this version. "
        L"Range-add requires exactly one complete current NX Held stopToken, including ManualPause; canAddRange reports eligibility. "
        L"It uses the original member owner, adds only explicit 4 KiB pages within the total 64-page budget, and never continues the target. "
        L"site retains initial configuration; control.breakpoint.executionRanges and control.executionRange show actual ranges and the native range/N receipt. "
        L"128 replay receipts, strictly increasing IDs; replay returns original result and does not repeat actions. "
        L"All stop identities/events/revisions are checked before any selected continue; actual calls remain sequential and may partly fail. "
        L"Partial attach and continue retain successful members and original responsibility. No automatic descendants or system-wide attachment. "
        L"Close/EOF/break/output loss close admission, cancel steps and retain original owners until clean; owner-death recovery is not promised. "
        L"See docs/cli/action-analyze-execution-group.md for schema and protocol examples.";
    command.runStreaming = Run;
    command.supportsR3 = true;
    command.defaultBackend = L"r3";
    addCommand(std::move(command));
}
} // namespace ks::cli::action_analyze
