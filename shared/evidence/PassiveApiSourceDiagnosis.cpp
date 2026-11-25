#include "PassiveApiSourceDiagnosis.h"

namespace Ksword::Evidence {
namespace {

// 仅对明确的设备离线错误给出断开诊断。一般读失败保留原生错误供定位。
bool DeviceDisconnected(DWORD error) noexcept
{
    return error == ERROR_DEVICE_NOT_CONNECTED || error == ERROR_DEV_NOT_EXIST;
}

// 输入为实际文件观察与本端生命周期。输出只描述归档读端可证实的状态。
std::string_view InputState(const PassiveApiTailStatus& tail, bool ended) noexcept
{
    using State = PassiveApiTailState;
    switch (tail.state) {
    case State::Unopened:
        return "unopened";
    case State::Reading:
        if (ended) {
            return "stopped-before-cutoff";
        }
        return tail.visibleBytes ? "reading" : "awaiting-first-read";
    case State::AtTail:
        return ended ? "stopped-before-cutoff" : "idle-at-tail";
    case State::PartialLine:
        return ended ? "stopped-before-cutoff" : "waiting-for-line-end";
    case State::Cutoff:
        return tail.partialLineBytes ? "cutoff-partial-line" : "cutoff";
    // 封存、尾损坏和回执错误各保留自己的原因。
    case State::Sealed:
        return "sealed";
    case State::UnconfirmedEnd:
        return "unconfirmed-end";
    case State::TruncatedTail:
        return "truncated-tail";
    case State::WriterFailed:
        return "writer-failed";
    case State::ReceiptMismatch:
        return "receipt-mismatch";
    case State::SourceChanged:
        return "source-changed";
    // 发生坏行时，后面的数据未核验。此前已验证的前缀仍可使用。
    case State::IdentityMismatch:
        return "identity-mismatch";
    case State::InvalidRecord:
        return "invalid-record";
    case State::ReadFailed:
        return DeviceDisconnected(tail.win32Error) ? "device-disconnected" : "read-failed";
    }
    return "unknown";
}

// 生成稳定 JSON 字符串。输入均为内部诊断常量。
JsonValue Text(std::string_view value)
{
    return JsonValue::makeString(std::string(value));
}

// 统一输出无损源行号，零作为本模块内部的未观察标记。
JsonValue Sequence(std::uint64_t value)
{
    return value ? JsonValue::makeU64Text(value, U64Format::Decimal) : JsonValue::makeNull();
}

} // namespace

std::string_view PassiveApiOpenFailureName(DWORD error) noexcept
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
        return "source-missing";
    case ERROR_ACCESS_DENIED:
        return "source-access-denied";
    default:
        return DeviceDisconnected(error) ? "source-device-disconnected" : "source-unavailable";
    }
}

void PassiveApiSourceDiagnosis::Observe(const ArchivedApiMonitorClue& row) noexcept
{
    using namespace ks::winapi_monitor;
    if (row.sourceSequence <= observedThrough_) {
        return;
    }
    observedThrough_ = row.sourceSequence;
    const auto& packet = row.packet; // 该包已由原调用方审核外层行号与来源身份。
    if (packet.eventKind != static_cast<std::uint32_t>(EventKind::ApiCall) ||
        packet.category != static_cast<std::uint32_t>(EventCategory::Internal) ||
        packet.resultKind != static_cast<std::uint32_t>(EventResultKind::StatusCode) ||
        ApiMonitorPacketText(packet.moduleName) != L"Agent") {
        return;
    }

    // SessionReady 出自生产方发送端握手，早于采集初始化。新的握手让此前的采集声明失效。
    const auto name = ApiMonitorPacketText(packet.apiName); // 从定长包读取的已终止通知名。
    if (name == L"SessionReady" && packet.resultCode == 0) {
        sessionReadySequence_ = row.sourceSequence;
        captureNoticeSequence_ = 0;
        partialNoticeSequence_ = 0;
        captureNotice_ = {};
        return;
    }
    if (name == L"HooksPartial" && packet.resultCode == 0) {
        partialNoticeSequence_ = row.sourceSequence;
        return;
    }

    // 按原协议名报告最后一个生命周期声明。挂起失败和恢复失败同样是可见状态。
    struct Notice {
        std::wstring_view name; // 生产方定长包中的精确名称。
        std::string_view label; // 供机器请求和回放输出的固定 ASCII 名。
        std::int32_t result; // 该通知在当前生产方实现中的固定结果码。
    };
    static constexpr Notice notices[] = {
        {L"HooksInstalled", "HooksInstalled", 0},
        {L"HooksPaused", "HooksPaused", 0},
        {L"HooksResumed", "HooksResumed", 0},
        {L"HooksRemoved", "HooksRemoved", 0},
        {L"HooksPauseFailed", "HooksPauseFailed", 1},
        {L"HooksResumeFailed", "HooksResumeFailed", 1},
        {L"InstallHooksFailed", "InstallHooksFailed", 1},
        {L"InstallHooksCancelled", "InstallHooksCancelled", 1},
    }; // HooksPartial 独立保留，后续成功声明不会擦掉历史部分覆盖提示。
    for (const auto& notice : notices) { // 仅允许精确名称和结果码组合。
        if (name == notice.name && packet.resultCode == notice.result) {
            captureNotice_ = notice.label;
            captureNoticeSequence_ = row.sourceSequence;
            return;
        }
    }
}

JsonValue PassiveApiSourceDiagnosis::Report(const PassiveApiTailStatus& tail, bool ended) const
{
    // 行核验只能证明归档声明一致。源文件不包含原采集端的连接心跳或断开通知。
    std::string_view loss = "unknown"; // 没有统计时，累计丢失量保持未知。
    if (tail.reportedAgentDrops) {
        loss = *tail.reportedAgentDrops != 0 ? "loss-reported" : "zero-reported";
    }
    return JsonValue::makeObject({
        {"input", Text(InputState(tail, ended))},
        {"prefixIdentity", Text(tail.validatedRows ? "prefix-consistent" : "unverified")},
        {"producerConnection", Text("unknown")},
        {"sessionReadySequence", Sequence(sessionReadySequence_)},
        {"captureNotice", captureNotice_.empty() ? JsonValue::makeNull() : Text(captureNotice_)},
        {"captureNoticeSequence", Sequence(captureNoticeSequence_)},
        {"partialNoticeSequence", Sequence(partialNoticeSequence_)},
        {"agentLoss", Text(loss)},
    });
}

} // namespace Ksword::Evidence
