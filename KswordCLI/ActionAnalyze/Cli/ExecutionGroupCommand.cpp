#include "ExecutionGroupCommand.h"

#include "ExecutionGroupProtocol.h"
#include "NativeSessionApiCapture.h"
#include "Transport.h"
#include "../Project/ProjectStorage.h"
#include "../Project/ExecutionGroupArchive.h"
#include "../../CommandRegistry.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <charconv>
#include <algorithm>
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
    ExecutionGroupSession(bool jsonl, n::OwnerIdentity identity, std::vector<n::ExecutionGroupSite> sites,
        std::wstring projectDirectory, bool openExisting)
        : jsonl_(jsonl), identity_(std::move(identity)), sites_(std::move(sites)),
          projectDirectory_(std::move(projectDirectory)), openExisting_(openExisting) {}

    int Run()
    {
        if (const auto fault = transport_.Start(jsonl_)) { std::cerr << fault.message << '\n'; return fault.code; }
        try {
            if (!archive_.Prepare(projectDirectory_, openExisting_) || !archive_.ResolveSites(sites_))
            {
                // 项目或采样失败在任何附加前报告，原集合仍为空，不创建隐式替代项目。
                (void)Emit("error", {}, Ksword::ActionAnalyze::DescribeExecutionGroupArchive(archive_.View()));
                return End("project-setup-failed", 3);
            }
            if (!archive_.View().sampleId.empty())
            {
                identity_.sampleId = archive_.View().sampleId; // 全体原成员沿用本轮真实新采样。
            }
            const auto started = group_.Start(std::move(sites_), true, n::NativeTargetDisposition::ResumeAndDetach, identity_.sampleId);
            collectionId_ = started.collectionId; // 仅校验包络用，不因校验或请求重放触发条件Query。
            if (!Emit("hello", {}, V::makeObject({{"sampleId", Text(identity_.sampleId)}, {"control", Report(started)},
                {"protocol", V::makeObject({{"maxMembers", V::makeUInt(n::kOwnedExecutionGroupLimit)},
                    {"mutationRequestId", Text("execution/<strictly increasing canonical positive uint64>")},
                     {"replayEntries", V::makeUInt(128)}, {"stopToken", Text("Mixed pause/continue copy complete member.sessionToken entries; legacy lists combine pauseToken for running members and stopToken for Held; step/cancel retain stopToken/stepToken")},
                    {"pauseScope", Text("all/selected validate every explicit session first; exact Held is already-held; Armed bindings call original Pause")},
                    {"continueScope", Text("all/selected validate every explicit session first; exact Held calls Continue; Armed running is already-running")},
                     {"sessionTable", Text("expected:{collectionId,sessions:[complete owner+control sessionToken]}; legacy stops tokens remain accepted")},
                      {"rangeAdd", Text("control.execution.range.add params:{address,bytes} canonical decimal strings; expected:{collectionId,stops:[one complete current NX Held token]}; never Continue")},
                      {"executionSave", Text("control.execution.save params:{}; expected:{collectionId,stops:[one current execution stopToken]}; requires configured project; never Continue")},
                      {"memoryRead", Text("control.memory.read params:{address:decimal-string,bytes:decimal-string}; expected:{collectionId,stops:[one complete stopToken]}; no automatic save or Continue")},
                      {"memorySave", Text("control.memory.save params:{}; expected:{collectionId,trackingEpoch}; save the current original read to raw-memory, independent of member selection")},
                       {"apiCapture", Text("control.api.capture requires one complete sessionToken in expected.sessions and a confirmed explicit source outside all members; shared sample writer, never Continue")},
                       {"membersAppend", Text("control.members.append params:{sites:UTF-8-config-path,confirm:true}; expected:{collectionId}; append explicit new instances to the same sample, at most 16 total")},
                    {"outcomes", Text("Every requested member has actionAttempted and disposition; already-held/already-running never fabricate a release")},
                    {"membersShareOwner", V::makeBool(false)}, {"simultaneousFreeze", V::makeBool(false)}})}}))) return End("output-lost", 3);
            // 部分启动失败仍进入命令循环，保留成功附加者供状态、继续、步进及清退。
            if (started.members.empty()) return End("configuration-rejected", 1);
            return Loop();
        } catch (...) { return End("execution-group-processing-failed", 6); }
    }

private:
    struct Saved { std::string signature; V result; };

    // 原集合投影追加同一writer的归档值；不改变控制令牌形状或成员原owner身份。
    V Report(const n::ExecutionGroupResult& result) const
    {
        const auto report = p::Report(result, !jsonl_); // 控制回执与存储回执各自保留。
        auto fields = *report.asObject(); // JSON对象只提供只读视图，复制值字段后追加归档投影。
        fields.emplace_back("executionArchive", Ksword::ActionAnalyze::DescribeExecutionGroupArchive(archive_.View()));
        fields.emplace_back("memory", Ksword::ActionAnalyze::DescribeExecutionGroupMemory(archive_.View().memory)); // 内存结果独立保留读取与保存身份。
        const auto& view = archive_.View(); // API结果携带采集时冻结的成员身份，不随后来选择漂移。
        fields.emplace_back("apiCapture", view.api ? DescribeNativeSessionApi(*view.api, view.apiBefore, view.apiAfter) : V::makeNull());
        fields.emplace_back("apiOwner", view.api ? V::makeObject({{"sampleId", Text(view.apiOwner.sampleId)},
            {"sessionId", Text(view.apiOwner.sessionId)}, {"epoch", Text(view.apiOwner.epoch)},
            {"backendInstanceId", Text(view.apiOwner.backendInstanceId)}}) : V::makeNull());
        return V::makeObject(std::move(fields));
    }

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

    // 输入单个原成员sessionToken与有限来源草稿，在同一修改流水内采集；不创建第二writer或调试owner。
    bool CaptureApi(const Request& request)
    {
        if (cleanupOnly_)
        {
            return Invalid(request, "cleanup-pending", "Original owners are closing");
        }
        Request parameters = request; // REPL只调整值参数供共用解析器，不修改原请求签名。
        std::string id = request.id; // 所有修改仍使用execution/N递增和原128条回执窗口。
        n::ExecutionGroupSessionEntry member; // 客户端必须复制原成员完整owner+control。
        if (jsonl_)
        {
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* collection = request.expected ? request.expected->find("collectionId") : nullptr;
            const auto* sessions = request.expected ? request.expected->find("sessions") : nullptr;
            std::string collectionId; // 包络集合与成员owner分别核对，不以一个替代另一个。
            if (!request.session || !expected || expected->size() != 2 || !collection ||
                !collection->tryGetString(collectionId) || collectionId != collectionId_ || !sessions ||
                !sessions->asArray() || sessions->asArray()->size() != 1 ||
                !p::ParseSessionToken(sessions->asArray()->front(), member))
            {
                return Invalid(request, "invalid-api-member", "Require current session and expected:{collectionId,sessions:[one complete member.sessionToken]}");
            }
        }
        else
        {
            const auto* args = request.params.asArray(); // 格式：流水 PID FILETIME 时长 confirm TOKENHEX [progress]。
            std::string tokenText;
            V token; // 完整sessionToken只从用户复制的字节解析，不补造现场字段。
            if (request.expected || !args || (args->size() != 6 && args->size() != 7) ||
                !(*args)[0].tryGetString(id) || !(*args)[5].tryGetString(tokenText) ||
                !p::ParseTokenText(tokenText, token) || !p::ParseSessionToken(token, member))
            {
                return Invalid(request, "invalid-api-member", "Use api-capture execution/N PID FILETIME DURATION confirm REPLSESSIONTOKEN [progress]");
            }
            JsonArray values(args->begin() + 1, args->begin() + 5); // 去掉修改流水和目标令牌，复用来源参数语法。
            if (args->size() == 7)
            {
                values.push_back(args->back());
            }
            parameters.params = V::makeArray(std::move(values));
        }
        const auto input = PrepareNativeSessionApi(parameters, jsonl_); // 与单目标入口使用完全相同的来源限制。
        if (!input.capture)
        {
            return Emit("error", request.id, input.error);
        }
        const auto signature = CanonicalParams(V::makeObject({{"action", Text("api-capture")},
            {"params", request.params}, {"expected", request.expected ? *request.expected : V::makeNull()}})); // 令牌和来源均纳入重放冲突判定。
        return Mutate(request, std::move(id), signature, [&] {
            Ksword::ActionAnalyze::NativeBoundApiStartup onStartup; // 显式订阅时仅向stderr输出真实阶段。
            if (input.startupProgress)
            {
                onStartup = [](const Ksword::ActionAnalyze::NativeBoundApiProgress& progress) {
                    const auto value = V::makeObject({{"projectId", Text(progress.projectId)},
                        {"sampleId", Text(progress.sampleId)}, {"sourcePid", V::makeUInt(progress.request.sourcePid)},
                        {"sourceCreationFileTime", Count(progress.request.sourceCreationFileTime)},
                        {"nativePid", V::makeUInt(progress.nativeTarget.pid)},
                        {"nativeCreationFileTime", Count(progress.nativeTarget.creationFileTime)},
                        {"startup", Ksword::ActionAnalyze::ApiCaptureStartupJson(progress.startup)}}); // 不生成stdout控制ACK。
                    std::wcerr << Ksword::ActionAnalyze::ProjectStorage::WideAscii(Ksword::Evidence::WriteJson(value)) << L'\n';
                };
            }
            const std::atomic_bool cancel{false}; // 原CLI串行有限采集；输入在返回后继续处理，不声称在途取消。
            archive_.CaptureApi(group_, member, *input.capture, cancel, onStartup);
            return Report(group_.QueryWithoutCondition()); // 不处理同伴条件，不Continue或自动保存执行观察。
        });
    }

    // 保存已读取的当前快照，不要求仍持有旧停点；trackingEpoch精确指定原字节，不能用当前行号代替。
    bool SaveMemory(const Request& request)
    {
        std::string id = request.id, epoch; // 存储请求仍沿execution/N原重放流水。
        if (cleanupOnly_)
        {
            return Invalid(request, "cleanup-pending", "Original owners are closing");
        }
        if (jsonl_)
        {
            const auto* fields = request.expected ? request.expected->asObject() : nullptr;
            const auto* collection = request.expected ? request.expected->find("collectionId") : nullptr;
            const auto* source = request.expected ? request.expected->find("trackingEpoch") : nullptr;
            std::string collectionId; // 校验本集合及原读取身份，保存不接收stopToken。
            if (!request.session || !Empty(request) || !fields || fields->size() != 2 || !collection ||
                !collection->tryGetString(collectionId) || collectionId != collectionId_ || !source || !source->tryGetString(epoch))
            {
                return Invalid(request, "invalid-memory-source", "Require params:{} and expected:{collectionId,trackingEpoch}");
            }
        }
        else
        {
            const auto* args = request.params.asArray(); // REPL显式复制最新读取的trackingEpoch。
            if (request.expected || !args || args->size() != 2 || !(*args)[0].tryGetString(id) || !(*args)[1].tryGetString(epoch))
            {
                return Invalid(request, "invalid-memory-source", "Use memory-save execution/N TRACKING_EPOCH");
            }
        }
        const auto source = archive_.View().memory.capture; // 完整字节只保留在原worker，不让协议补造内存样本。
        const auto signature = CanonicalParams(V::makeObject({{"action", Text("memory-save")}, {"trackingEpoch", Text(epoch)}}));
        return Mutate(request, std::move(id), signature, [&] {
            if (!source || source->request.plan.trackingEpoch != epoch)
            {
                return FaultJson({"stale-memory-source", "Copy the current memory.read.source.trackingEpoch",
                    std::nullopt, 1, "cli", 0, "execution-group-memory"}); // 重放先命中原回执，新请求才核对当前读取。
            }
            archive_.SaveMemory(source);
            return Report(group_.QueryWithoutCondition()); // 保存原字节不释放任何停止组。
        });
    }

    // 输入已确认的新站点配置文件及原集合身份；重放先命中原回执，不重读变化后的配置或重复附加。
    bool AppendMembers(const Request& request)
    {
        if (cleanupOnly_)
        {
            return Invalid(request, "cleanup-pending", "Original owners are closing");
        }
        std::string id = request.id, path, collectionId; // 配置路径只用于本次显式追加，不改启动参数。
        bool confirmed = false; // 每次追加必须明确确认控制新实例。
        if (jsonl_)
        {
            const auto* fields = request.params.asObject(); // 此动作只接受文件路径与显式授权。
            const auto* sites = request.params.find("sites");
            const auto* confirm = request.params.find("confirm");
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* collection = request.expected ? request.expected->find("collectionId") : nullptr;
            if (!request.session || !fields || fields->size() != 2 || !sites || !sites->tryGetString(path) ||
                !confirm || !confirm->tryGetBool(confirmed) || !confirmed || !expected || expected->size() != 1 ||
                !collection || !collection->tryGetString(collectionId) || collectionId != collectionId_)
            {
                return Invalid(request, "invalid-append-members", "Require params:{sites:PATH,confirm:true}, expected:{collectionId} and current session");
            }
        }
        else
        {
            const auto* args = request.params.asArray(); // REPL显式带集合ID，不能依当前界面索引猜身份。
            std::string confirmation; // 原文必须为confirm，不接受任意非空值。
            if (request.expected || !args || args->size() != 4 || !(*args)[0].tryGetString(id) ||
                !(*args)[1].tryGetString(path) || !(*args)[2].tryGetString(confirmation) || confirmation != "confirm" ||
                !(*args)[3].tryGetString(collectionId) || collectionId != collectionId_)
            {
                return Invalid(request, "invalid-append-members", "Use members-append execution/N SITES_PATH confirm COLLECTION_ID");
            }
            confirmed = true;
        }
        if (path.empty() || path.size() > 32767 || path.find('\0') != std::string::npos)
        {
            return Invalid(request, "invalid-sites-path", "Require a nonempty configuration file path");
        }
        const auto signature = CanonicalParams(V::makeObject({{"action", Text("members-append")},
            {"sites", Text(path)}, {"collectionId", Text(collectionId)}, {"confirm", V::makeBool(confirmed)}}));
        return Mutate(request, std::move(id), signature, [&] {
            std::vector<n::ExecutionGroupSite> sites; // 原ReadSites一次冻结文件字节、字段与条件。
            try
            {
                sites = p::ReadSites(p::Wide(path));
            }
            catch (const std::invalid_argument& error)
            {
                return FaultJson({"invalid-append-sites", error.what(), std::nullopt, 1, "cli", 0, "execution-group"});
            }
            return Report(archive_.AppendMembers(group_, std::move(sites), confirmed, collectionId));
        });
    }

    bool Dispatch(const Request& request, bool& closed)
    {
        if (request.session && (request.session->id != identity_.sessionId || request.session->epoch != identity_.epoch))
            return Invalid(request, "wrong-session", "Use the current hello session and epoch");
        const auto& method = request.method;
        if (method == "members-append" || method == "control.members.append")
        {
            return AppendMembers(request); // 共享execution/N流水，先核对hello身份再读取新配置。
        }
        if (method == "api-capture" || method == "control.api.capture")
        {
            return CaptureApi(request); // 此路径仍受上方hello身份核对及原修改流水约束。
        }
        if (method == "memory-save" || method == "control.memory.save")
        {
            return SaveMemory(request);
        }
        const bool query = method == "status" || method == "control.query";
        const bool close = method == "quit" || method == "close" || method == "controller.shutdown";
        const bool resume = method == "continue" || method == "control.continue";
        const bool pause = method == "pause" || method == "control.pause"; // 同一原执行owner内主动暂停，非新附加。
        const bool scoped = resume || pause;
        const bool step = method == "step" || method == "control.step";
        const bool cancel = method == "step-cancel" || method == "control.step.cancel";
        const bool range = method == "execution-range-add" || method == "control.execution.range.add"; // 原成员显式追加NX页。
        const bool readMemory = method == "memory-read" || method == "control.memory.read"; // 单成员Held范围读取，不自动保存。
        const bool rangeInput = range || readMemory; // 两种动作共用数值输入，但内存读取不要求整页对齐。
        const bool save = method == "execution-save" || method == "control.execution.save"; // 原事件显式归档，不释放成员。
        if (!jsonl_ && method == "help" && Empty(request)) return Emit("response", {}, Text(
            "status | members-append execution/N SITES_PATH confirm COLLECTION_ID | pause execution/N all|selected TOKENHEX[,TOKENHEX...] | continue execution/N all|selected TOKENHEX[,TOKENHEX...] | step execution/N into|over-call|out TOKENHEX | step-cancel execution/N TOKENHEX | execution-range-add execution/N ADDRESS BYTES TOKENHEX | execution-save execution/N TOKENHEX | memory-read execution/N ADDRESS BYTES TOKENHEX | memory-save execution/N TRACKING_EPOCH | api-capture execution/N PID FILETIME DURATION confirm REPLSESSIONTOKEN [progress] | quit"));
        if (query && Empty(request) && !request.expected) return Emit("response", request.id, Report(group_.Query()));
        if (jsonl_ && !request.session) return Invalid(request, "session-required", "Control requires the current hello session identity");
        if (close && Empty(request) && !request.expected) {
            const auto result = group_.Close();
            cleanupOnly_ = !result.clean;
            closed = result.clean;
            if (result.clean) archive_.Close(); // 原native全清退之后才归还writer，保留历史回执。
            return Emit("response", request.id, Report(result));
        }
        if (!pause && !resume && !step && !cancel && !range && !save && !readMemory) return Invalid(request, "unsupported-method", "Use help for execution and memory commands");
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
                rangeInput ? fields->size() != 2 || !request.params.find("address") || !request.params.find("address")->tryGetString(addressText) ||
                    !request.params.find("bytes") || !request.params.find("bytes")->tryGetString(bytesText) : !fields->empty()))
                return Invalid(request, "invalid-params", "Pause/continue require scope; step requires mode; range-add/memory-read require address and bytes strings; step-cancel/save require empty params");
        } else {
            std::string tokenText;
            if (request.expected || !args || args->size() != (rangeInput ? 4 : cancel || save ? 2 : 3) || !(*args)[0].tryGetString(id) ||
                !args->back().tryGetString(tokenText) ||
                (rangeInput ? !(*args)[1].tryGetString(addressText) || !(*args)[2].tryGetString(bytesText) :
                     !cancel && !save && !(*args)[1].tryGetString(scoped ? scope : mode)))
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
        // 范围先完成协议校验再消费execution/N；只有NX追加要求整页，内存读取保留精确字节子范围。
        if (rangeInput && (!RangeNumber(addressText, address) || !RangeNumber(bytesText, bytes) ||
            (range && (address % 4096 || bytes % 4096)) || bytes > 64ull * 4096 || address > UINT64_MAX - bytes))
        {
            return Invalid(request, "invalid-execution-range", range
                ? "Require positive aligned address, 1..64 whole pages and no uint64 overflow"
                : "Require positive decimal address and 1..262144 bytes with no uint64 overflow");
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
        const auto signature = CanonicalParams(V::makeObject({{"action", Text(pause ? "pause" : resume ? "continue" : step ? "step" : range ? "range-add" : readMemory ? "memory-read" : save ? "execution-save" : "step-cancel")},
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
            else if (save || readMemory)
            {
                const auto current = group_.QueryWithoutCondition(); // 无条件回读不自动释放其它成员。
                const auto member = std::find_if(current.members.begin(), current.members.end(), [&](const auto& item) {
                    return item.control.pid == stops.front().pid &&
                        item.control.processCreationTime == stops.front().processCreationTime;
                });
                n::ExecutionGroupSessionEntry entry; // 原owner只能从当前集合取得，客户端不能补造。
                entry.control = stops.front();
                if (member != current.members.end()) entry.owner = member->owner;
                if (readMemory)
                {
                    archive_.CaptureMemory(group_, entry, address, bytes); // 原会话再次核对前后停点，ManualPause可读取。
                }
                else
                {
                    archive_.Save(group_, entry); // 存储层再次核对完整当前事件，拒绝ManualPause和旧停点。
                }
                result = group_.QueryWithoutCondition();
            }
            else
            {
                const auto stepMode = mode == "into" ? n::NativeStepMode::Into :
                    mode == "over-call" ? n::NativeStepMode::OverCall : n::NativeStepMode::Out; // 已校验的三种单成员步进。
                result = group_.Step(stops.front(), stepMode);
            }
            return Report(result);
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
        archive_.Close(); // 所有原owner clean，项目租约可以归还，存储失败回执仍可读。
        const bool sent = Emit("summary", {}, V::makeObject({{"reason", Text(reason)}, {"exitCode", V::makeUInt(code)},
            {"control", Report(state)}}));
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
    Ksword::ActionAnalyze::ExecutionGroupArchive archive_; // 与原集合共用控制线程，clean后关闭。
    std::wstring projectDirectory_; // 启动时冻结的明确项目目录。
    bool openExisting_ = false; // 不从文件是否存在推断项目模式。
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
    if (args.has(L"--open-project") && !args.has(L"--project"))
        throw std::invalid_argument("--open-project requires --project PATH");
    return ExecutionGroupSession(input == L"jsonl", std::move(identity), std::move(sites),
        args.get(L"--project"), args.has(L"--open-project")).Run();
}
} // namespace

void RegisterExecutionGroupCommand()
{
    Command command;
    command.path = L"analyze execution-group session";
    command.syntax = L"KswordCLI.exe analyze execution-group session --sites PATH --confirm --disposition resume-detach [--input repl|jsonl] [--backend r3] [--project PATH [--open-project]]";
    command.summary = L"Attach one frozen execution site per explicit process instance, with independent native owners and conditions.";
    command.options = L"--sites is a UTF-8 JSON disk file without BOM, at most 128 KiB: {schemaVersion:1,sites:[...]}. "
        L"1-16 distinct PIDs; each item requires numeric pid and canonical positive decimal-string creationFileTime. "
        L"Image: absolute DOS module plus exactly one numeric uint32 rva or case-sensitive exactExport. "
        L"Optional imageSha256 is exactly 64 lowercase hex characters; the original member owner verifies the actual debug-load event file before arming DR0. Private sites reject this field. "
        L"Private: decimal-string address and rangeBytes (0 for one DR0 site, otherwise aligned 4 KiB multiples up to 64 pages). "
        L"Optional condition uses the shared typed data-watch expression compiler; configuration is frozen before attach. "
        L"Optional definitionId requires module+rva and --project. Every referenced enabled RVA definition is verified in the new sample's frozen settings before any member attaches, inheriting its image SHA256 constraint. "
        L"--project creates a project and new sample before attach; --open-project opens an existing project but still creates a new sample. Omit both for control without archival.";
    command.notes = L"over-call steps over decoded CALLs at their return boundary and performs one TF step for supported non-CALL instructions, retaining the original requested mode and destination:null. "
        L"REPL: status; pause execution/N all|selected TOKENHEX[,TOKENHEX...]; continue execution/N all|selected TOKENHEX[,TOKENHEX...]; step execution/N into|over-call|out TOKENHEX; "
        L"members-append execution/N SITES_PATH confirm COLLECTION_ID; step-cancel execution/N TOKENHEX; execution-range-add execution/N ADDRESS BYTES TOKENHEX; execution-save execution/N TOKENHEX; "
        L"memory-read execution/N ADDRESS BYTES TOKENHEX; memory-save execution/N TRACKING_EPOCH; "
        L"api-capture execution/N PID FILETIME DURATION confirm REPLSESSIONTOKEN [progress]; quit. Copy full replToken bytes, never a member index. "
        L"JSONL: control.query; control.pause params:{scope:all|selected}; control.continue params:{scope:all|selected}; control.step params:{mode:into|over-call|out}; "
        L"control.step.cancel params:{}; control.execution.range.add params:{address,bytes} (canonical positive decimal strings); control.execution.save params:{} with one complete current execution stop; controller.shutdown params:{}. Mutations require current hello session id/epoch, "
        L"execution/N request IDs, and expected:{collectionId,stops:[complete current member.pauseToken, stopToken or stepToken]}. "
        L"Mixed pause/continue also accept expected:{collectionId,sessions:[complete member.sessionToken owner+control objects]}; REPL accepts replSessionToken lists. "
        L"All/selected validate the entire explicit set first; Pause reports already-held, Continue reports already-running, without native calls for those members. "
        L"Every outcome includes actionAttempted and disposition; unclear/recovery/foreign states reject the batch without clearing responsibility. "
        L"Pause checks all selected live owner/PID/creation/binding request IDs before original session.Pause; no old stop is required. "
        L"ManualPause receipts remain separate; exact Held ManualPause can continue but cannot step in this version. "
        L"Range-add requires exactly one complete current NX Held stopToken, including ManualPause; canAddRange reports eligibility. "
        L"It uses the original member owner, adds only explicit 4 KiB pages within the total 64-page budget, and never continues the target. "
        L"Execution-save writes the current original member event to the configured project's new sample raw-native stream, preserving registers and event-time binding. "
        L"ManualPause is not execution evidence. executionArchive reports saved/firstFailure, written/flushed/verified separately; duplicate events reuse the original ordinal. "
        L"Memory read uses one complete current stopToken, decimal address and byte count (1..262144); ManualPause is allowed. It checks the original owner before and after reading without Continue. "
        L"control.memory.save params:{} expected:{collectionId,trackingEpoch} saves the displayed original snapshot to raw-memory. memory reports source, page states, bounded hex previews and separate write/flush/verification. "
        L"API capture uses control.api.capture params:{sourcePid:UInt,sourceCreationFileTime:decimal-string,durationMs:UInt,confirm:true,startupProgress?:bool}, expected:{collectionId,sessions:[one complete sessionToken]}. "
        L"Source must be outside every execution group member; duration is 1000..10000 ms after Ready, with startup/drain time separate. The original writer/sample is reused. "
        L"CLI handles queued control after the finite capture returns; progress is stderr JSONL, apiCapture reports independent admission/capture/archive/cleanup and before/after member state. "
        L"site retains initial configuration; control.breakpoint.executionRanges and control.executionRange show actual ranges and the native range/N receipt. "
        L"128 replay receipts, strictly increasing IDs; replay returns original result and does not repeat actions. "
        L"All stop identities/events/revisions are checked before any selected continue; actual calls remain sequential and may partly fail. "
        L"control.members.append uses params:{sites:PATH,confirm:true}, expected:{collectionId}, current session and execution/N. "
        L"It reads the same sites schema once, appends new distinct PIDs to the same sample (16 total), and retains all original owners/stops. "
        L"Frozen definitions resolve against the current sample; definition failures preserve the existing writer and memberSetupError. "
        L"Partial attach and continue retain successful members and original responsibility. No automatic descendants or system-wide attachment. "
        L"Close/EOF/break/output loss close admission, cancel steps and retain original owners until clean; owner-death recovery is not promised. "
        L"See docs/cli/action-analyze-execution-group.md for schema and protocol examples.";
    command.runStreaming = Run;
    command.supportsR3 = true;
    command.defaultBackend = L"r3";
    addCommand(std::move(command));
}
} // namespace ks::cli::action_analyze
