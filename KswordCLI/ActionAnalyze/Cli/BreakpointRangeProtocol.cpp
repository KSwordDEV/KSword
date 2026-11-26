#include "BreakpointRangeProtocol.h"

#include <charconv>
#include <limits>

namespace ks::cli::action_analyze
{
    namespace
    {
        using V = JsonValue; // 使用已有传输和规范JSON实现。
        namespace native = control;
        constexpr std::size_t kReceipts = 128; // 与原native范围事务窗口一致。

        // 输入文本，生成JSON字符串；所有64位数值都不经过JSON浮点数。
        V Text(std::string_view value)
        {
            return V::makeString(std::string(value));
        }

        // 输入无符号数，返回规范十进制JSON字符串。
        V Count(std::uint64_t value)
        {
            return Text(std::to_string(value));
        }

        // 输入CLI错误及说明，输出原传输层可消费的稳定fault。
        Fault Error(const char* id, const char* message)
        {
            return {id, message, std::nullopt, 1, "cli", 0, "private-execution-range"};
        }

        // 完整解析规范正十进制字符串，拒绝符号、前导零、溢出和尾随字符。
        std::optional<std::uint64_t> Decimal(std::string_view text)
        {
            std::uint64_t value = 0; // 保留真实64位地址或修订。
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
            if (!value || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
                text != std::to_string(value))
            {
                return {};
            }
            return value;
        }
    }

    // 输入独立range请求，只在当前owner完整Held下提交一次；所有恢复责任仍由owner持有。
    BreakpointStepReply BreakpointRangeProtocol::Dispatch(const Request& request, bool jsonl, bool supported,
        const native::OwnerIdentity& identity, native::NativeDebugOwner& owner)
    {
        if (request.method != "execution-range-add" && request.method != "control.execution.range.add")
        {
            return {};
        }
        const auto fail = [](const char* id, const char* message) {
            return BreakpointStepReply{true, Error(id, message), {}};
        };
        if (!supported)
        {
            return fail("execution-range-unavailable", "Range addition requires a single-target NX execution session");
        }
        if ((jsonl && !request.session) || (request.session &&
            (request.session->id != identity.sessionId || request.session->epoch != identity.epoch)))
        {
            return fail("wrong-session", "Require the current live session identity");
        }

        std::string address, bytes, stop, revision; // 冻结请求原文，不从后续Query补写用户参数。
        if (jsonl)
        {
            const auto* params = request.params.asObject(); // JSONL参数必须恰好为两个范围字段。
            const auto* expected = request.expected ? request.expected->asObject() : nullptr;
            const auto* baseField = request.params.find("address");
            const auto* sizeField = request.params.find("bytes");
            const auto* stopField = request.expected ? request.expected->find("stopId") : nullptr;
            const auto* revisionField = request.expected ? request.expected->find("stateRevision") : nullptr;
            if (!params || params->size() != 2 || !baseField || !baseField->tryGetString(address) ||
                !sizeField || !sizeField->tryGetString(bytes) || !expected || expected->size() != 2 ||
                !stopField || !stopField->tryGetString(stop) || !revisionField || !revisionField->tryGetString(revision))
            {
                return fail("invalid-execution-range", "Require params:{address,bytes} and expected:{stopId,stateRevision}, all strings");
            }
        }
        else
        {
            const auto* args = request.params.asArray(); // REPL使用与JSONL相同的正十进制范围语义。
            if (request.expected || !args || args->size() != 4 || !(*args)[0].tryGetString(address) ||
                !(*args)[1].tryGetString(bytes) || !(*args)[2].tryGetString(stop) || !(*args)[3].tryGetString(revision))
            {
                return fail("invalid-execution-range", "Usage: execution-range-add ADDRESS BYTES STOP_ID STATE_REVISION");
            }
        }
        const auto base = Decimal(address); // 输入地址必须已对齐，不隐式扩大请求范围。
        const auto length = Decimal(bytes);
        const auto stateRevision = Decimal(revision);
        if (!base || !length || !stateRevision || *base % 4096 || *length % 4096 ||
            *length > (std::numeric_limits<std::uint64_t>::max)() - *base || stop.empty() || stop.size() > kRequestIdBytes)
        {
            return fail("invalid-execution-range", "Require aligned positive address and whole pages without uint64 overflow, exact stopId and positive revision");
        }
        if (!jsonl && highWater_ == (std::numeric_limits<std::uint64_t>::max)())
        {
            return fail("range-sequence-exhausted", "Range request IDs are exhausted");
        }
        const auto sequence = jsonl ? (request.id.starts_with("range/")
            ? Decimal(std::string_view(request.id).substr(6)) : std::nullopt)
            : std::optional<std::uint64_t>{highWater_ + 1};
        if (!sequence)
        {
            return fail("invalid-range-request-id", "Require requestId range/<next positive decimal>, starting at range/1");
        }
        const auto signature = CanonicalParams(V::makeArray({Text(address), Text(bytes), Text(stop), Text(revision)}));
        if (const auto found = requests_.find(*sequence); found != requests_.end())
        {
            if (found->second.signature != signature)
            {
                return fail("request-id-conflict", "Range request ID identifies different arguments");
            }
            return {true, found->second.error, found->second.result}; // 重放旧回执，不重读或修改目标。
        }
        if (*sequence <= highWater_ || *sequence - highWater_ != 1)
        {
            return fail("invalid-range-sequence", "Require the next range/N ID; expired receipts cannot be executed again");
        }

        Saved saved{signature, {}, {}}; // 首次处理结果始终入窗口，包括停止代次失配。
        const auto current = owner.Query(); // 原控制线程回读真实owner，不处理条件自动继续。
        if (current.status != native::NativeControlStatus::Held || !current.group || !current.responsibility ||
            !current.pending || !current.breakpoint || !current.breakpoint->rangeBytes ||
            current.group->historical || current.group->state != native::GroupState::HeldComplete ||
            current.group->sampleId != identity.sampleId || current.group->sessionId != identity.sessionId ||
            current.group->epoch != identity.epoch || current.responsibility->state != native::EventState::Held ||
            current.responsibility->event != current.pending->event || !current.pending->ledgerOwned ||
            current.pending->continuationIndeterminate || current.responsibility->stopId != stop ||
            current.group->stateRevision != *stateRevision)
        {
            saved.error = Error("stale-execution-range-stop", "Query the current complete NX execution stop and use its exact revision");
        }
        else
        {
            native::NativeExecutionRangeRequest nativeRequest; // 核心层再次核验所有权、线程及逐页保护。
            nativeRequest.stop = {identity, current.group->groupId, stop, current.responsibility->event,
                "range/" + std::to_string(*sequence), *stateRevision};
            nativeRequest.address = *base;
            nativeRequest.bytes = *length;
            saved.result = owner.AddPrivateExecutionRange(nativeRequest);
        }
        highWater_ = *sequence;
        requests_.emplace(*sequence, saved);
        if (requests_.size() > kReceipts)
        {
            requests_.erase(requests_.begin()); // 与目标无关的旧回执淘汰，不丢失原native恢复责任。
        }
        return {true, saved.error, std::move(saved.result)};
    }

    // 输出范围请求、停止来源、回滚及错误，继续状态恒为false。
    JsonValue BreakpointRangeProtocol::Report(const native::NativeExecutionRangeReceipt& receipt)
    {
        return V::makeObject({{"requestId", Text(receipt.request.stop.requestId)},
            {"address", Count(receipt.request.address)}, {"bytes", Count(receipt.request.bytes)},
            {"sourceStopId", Text(receipt.request.stop.stopId)}, {"stateRevision", Count(receipt.stateRevision)},
            {"added", V::makeBool(receipt.added)}, {"rollbackComplete", V::makeBool(receipt.rollbackComplete)},
            {"stage", Text(receipt.stage)}, {"win32Error", V::makeUInt(receipt.win32Error)},
            {"continued", V::makeBool(false)}});
    }

    // 输出CLI能力，实际NX范围合计和恢复资格仍由native当次执行确定。
    JsonValue BreakpointRangeProtocol::Capabilities()
    {
        return V::makeObject({{"method", Text("control.execution.range.add")}, {"firstRequestId", Text("range/1")},
            {"replayEntries", Count(kReceipts)}, {"maximumTotalPages", V::makeNull()}, {"pageBytes", Count(4096)},
            {"addressEncoding", Text("positive-decimal-string")}, {"continuesTarget", V::makeBool(false)}});
    }
}
