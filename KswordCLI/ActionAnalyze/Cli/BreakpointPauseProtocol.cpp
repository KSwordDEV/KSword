#include "BreakpointPauseProtocol.h"

#include <charconv>
#include <limits>

namespace ks::cli::action_analyze
{
    namespace
    {
        namespace native = control;
        using V = JsonValue; // 沿用现有JSON传输，64位身份以字符串保真。

        // 将稳定字符串投影为现有JSON值，不引入另一种协议编码。
        V Text(std::string_view text)
        {
            return V::makeString(std::string(text));
        }

        // 解析完整正十进制身份，拒绝前导零、符号和溢出。
        std::optional<std::uint64_t> Decimal(std::string_view text)
        {
            std::uint64_t value = 0; // 本次请求冻结的FILETIME或pause序号。
            const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
            if (!value || parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size() ||
                text != std::to_string(value))
            {
                return {};
            }
            return value;
        }

        // 原生请求状态分别编码，Pending不表示目标已经冻结。
        const char* State(native::NativeArmedPauseState state)
        {
            switch (state)
            {
            case native::NativeArmedPauseState::Pending: return "pending";
            case native::NativeArmedPauseState::Held: return "held";
            case native::NativeArmedPauseState::Preempted: return "preempted";
            case native::NativeArmedPauseState::Rejected: return "rejected";
            case native::NativeArmedPauseState::Cancelled: return "cancelled";
            case native::NativeArmedPauseState::Ended: return "ended";
            case native::NativeArmedPauseState::RecoveryRequired: return "recovery-required";
            }
            return "unknown";
        }
    }

    // 请求仅冻结目标实例；真实停止事件由原native线程后续接收及核验。
    BreakpointStepReply BreakpointPauseProtocol::Dispatch(const Request& request, bool jsonl, bool supported,
        const native::OwnerIdentity& identity, native::NativeDebugOwner& owner)
    {
        const bool pause = request.method == "pause" || request.method == "control.pause";
        const bool query = request.method == "pause-status" || request.method == "control.pause.query";
        if (!pause && !query)
        {
            return {};
        }
        const auto fail = [](const char* id, const char* message) {
            return BreakpointStepReply{true, {id, message, std::nullopt, 1, "cli", 0, "armed-pause"}, {}};
        };
        if (!supported)
        {
            return fail("armed-pause-unavailable", "Pause requires the original single-target execution owner");
        }
        if (request.expected || (jsonl && !request.session) || (request.session &&
            (request.session->id != identity.sessionId || request.session->epoch != identity.epoch)))
        {
            return fail("invalid-pause-session", "Require the current live session without expected stop tokens");
        }

        const auto* fields = request.params.asObject(); // JSONL与REPL共享同一冻结目标语义。
        const auto* args = request.params.asArray();
        std::string creationText, pidText, requestedId; // 参数只借用本次请求，不从最新选区补值。
        if (query)
        {
            const auto* id = jsonl ? request.params.find("requestId") : nullptr;
            if (jsonl ? (!fields || fields->size() != 1 || !id || !id->tryGetString(requestedId))
                : (!args || args->size() != 1 || !(*args)[0].tryGetString(requestedId)))
            {
                return fail("invalid-pause-query", "Use pause-status pause/N or params:{requestId}");
            }
            if (!requestedId.starts_with("pause/") || !Decimal(std::string_view(requestedId).substr(6)))
            {
                return fail("invalid-pause-request-id", "Require pause/<positive decimal>");
            }
            return {true, {}, owner.QueryArmedPause(requestedId)};
        }

        std::uint64_t pid = 0; // PID按JSON无符号整数或REPL正十进制读取。
        if (jsonl)
        {
            const auto* pidField = request.params.find("targetPid");
            const auto* creationField = request.params.find("targetCreationFileTime");
            if (!fields || fields->size() != 2 || !pidField || pidField->type() != Ksword::Evidence::JsonType::UInt ||
                !pidField->tryGetU64(pid) || !creationField ||
                !creationField->tryGetString(creationText))
            {
                return fail("invalid-pause-target", "Require params:{targetPid:UInt,targetCreationFileTime:decimal-string}");
            }
            requestedId = request.id;
        }
        else
        {
            if (!args || args->size() != 2 || !(*args)[0].tryGetString(pidText) ||
                !(*args)[1].tryGetString(creationText) || !Decimal(pidText))
            {
                return fail("invalid-pause-target", "Usage: pause PID CREATION_FILETIME");
            }
            pid = *Decimal(pidText);
            if (highWater_ == (std::numeric_limits<std::uint64_t>::max)())
            {
                return fail("pause-id-exhausted", "Pause request IDs are exhausted");
            }
            requestedId = "pause/" + std::to_string(highWater_ + 1);
        }
        const auto creation = Decimal(creationText); // 不允许裸PID在已复用的进程上暂停。
        if (!pid || pid > UINT32_MAX || !creation || !requestedId.starts_with("pause/") ||
            !Decimal(std::string_view(requestedId).substr(6)))
        {
            return fail("invalid-pause-target", "Require a strong target instance and requestId pause/N");
        }
        const auto sequence = *Decimal(std::string_view(requestedId).substr(6)); // 重放交原native判断冲突和过期。
        if (sequence > highWater_ && sequence - highWater_ != 1)
        {
            return fail("invalid-pause-sequence", "Require the next consecutive pause/N ID, starting at pause/1");
        }
        native::NativePauseRequest nativeRequest; // 幂等、抢先命中和清退责任均由原owner处理。
        nativeRequest.requestId = requestedId;
        nativeRequest.pid = static_cast<std::uint32_t>(pid);
        nativeRequest.processCreationTime = *creation;
        nativeRequest.explicitlyAuthorized = true;
        nativeRequest.disposition = native::NativeTargetDisposition::ResumeAndDetach;
        if (sequence > highWater_)
        {
            highWater_ = sequence; // 参数完整的首次请求消费序号，拒绝同一ID日后成为新副作用。
        }
        return {true, {}, owner.PauseArmed(identity, nativeRequest)};
    }

    // 输出暂停自己的事件引用，不用当前breakpointHit代替本请求的完成状态。
    JsonValue BreakpointPauseProtocol::Report(const native::NativeArmedPauseReceipt& receipt)
    {
        return V::makeObject({{"requestId", Text(receipt.request.requestId)}, {"state", Text(State(receipt.state))},
            {"targetPid", V::makeUInt(receipt.request.pid)},
            {"targetCreationFileTime", Text(std::to_string(receipt.request.processCreationTime))},
            {"groupId", receipt.groupId ? Text(*receipt.groupId) : V::makeNull()},
            {"event", receipt.event ? V::makeObject({{"backendInstanceId", Text(receipt.event->backendInstanceId)},
                {"serial", Text(std::to_string(receipt.event->serial))}}) : V::makeNull()},
            {"stage", Text(receipt.stage)}, {"win32Error", V::makeUInt(receipt.win32Error)}});
    }

    // 接受请求后显式Query等真实停止，恢复仍使用原continue/N及精确停止票据。
    JsonValue BreakpointPauseProtocol::Capabilities()
    {
        return V::makeObject({{"method", Text("control.pause")}, {"queryMethod", Text("control.pause.query")},
            {"firstRequestId", Text("pause/1")}, {"replayEntries", V::makeUInt(128)},
            {"usesOriginalOwner", V::makeBool(true)}, {"acceptanceProvesStopped", V::makeBool(false)}});
    }
}
