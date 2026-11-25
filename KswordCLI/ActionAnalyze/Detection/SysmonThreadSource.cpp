#include "SysmonThreadSource.h"

#include "../../../shared/usermode/backend/Win32.h"

#include <objbase.h>
#include <winevt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <utility>

#pragma comment(lib, "Wevtapi.lib")

namespace Ksword::ActionAnalyze::Detection {
namespace {

// Windows 清单里的 Event 8 v2。按字段名取得 EventData，不解析或依赖本地化消息。
// schema: microsoft/SysmonCommon manifest.xml, SYSMONEVENT_CREATE_REMOTE_THREAD.
constexpr LPCWSTR kPaths[] = {
    L"Event/EventData/Data[@Name='SourceProcessGuid']",
    L"Event/EventData/Data[@Name='TargetProcessGuid']",
    L"Event/EventData/Data[@Name='SourceProcessId']",
    L"Event/EventData/Data[@Name='TargetProcessId']",
    L"Event/EventData/Data[@Name='NewThreadId']",
    L"Event/EventData/Data[@Name='StartAddress']",
    L"Event/EventData/Data[@Name='SourceImage']",
    L"Event/EventData/Data[@Name='TargetImage']",
    L"Event/EventData/Data[@Name='StartModule']",
    L"Event/EventData/Data[@Name='StartFunction']",
};
enum PayloadIndex : DWORD { SourceGuid, TargetGuid, SourcePid, TargetPid, NewTid, StartVa, SrcImage, DstImage, StartMod, StartFn };
constexpr std::uint32_t kMaxRenderBytes = 65536;
constexpr std::size_t kMaxFieldChars = 1024;
constexpr DWORD kBatchSize = 16;

// 事件、游标及渲染上下文均由 Windows 事件日志自己的关闭接口归还。
struct EventHandle {
    explicit EventHandle(EVT_HANDLE value = nullptr) noexcept : value(value) {}
    ~EventHandle() { if (value) { EvtClose(value); } }
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
    EVT_HANDLE value;
};

struct EventBatch {
    ~EventBatch() { for (auto value : handles) { if (value) { EvtClose(value); } } }
    std::array<EVT_HANDLE, kBatchSize> handles{};
};

int HexDigit(wchar_t digit) noexcept
{
    if (digit >= L'0' && digit <= L'9') { return digit - L'0'; }
    if (digit >= L'a' && digit <= L'f') { return digit - L'a' + 10; }
    if (digit >= L'A' && digit <= L'F') { return digit - L'A' + 10; }
    return -1;
}

// StartAddress 是清单中的十六进制文本。只保留其数值，不把地址当线程已经执行的证明。
std::optional<std::uint64_t> Address(std::wstring_view text)
{
    if (text.size() < 3 || text.size() > 18 || text[0] != L'0' || (text[1] != L'x' && text[1] != L'X')) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    for (const auto ch : text.substr(2)) {
        const auto digit = HexDigit(ch);
        if (digit < 0) { return std::nullopt; }
        value = (value << 4) | static_cast<std::uint64_t>(digit);
    }
    return value;
}

// 双缓冲区分别容纳 System 和 EventData。粒度采用 EVT_VARIANT 自身的对齐。
class RenderedValues {
public:
    bool Render(EVT_HANDLE context, EVT_HANDLE event, std::uint32_t& error)
    {
        used_ = 0;
        count_ = 0;
        if (!EvtRender(context, event, EvtRenderEventValues, Capacity(), buffer_.data(), &used_, &count_)) {
            error = GetLastError();
            if (error != ERROR_INSUFFICIENT_BUFFER || used_ == 0 || used_ > kMaxRenderBytes) { return false; }
            buffer_.resize((used_ + sizeof(EVT_VARIANT) - 1) / sizeof(EVT_VARIANT));
            if (!EvtRender(context, event, EvtRenderEventValues, Capacity(), buffer_.data(), &used_, &count_)) {
                error = GetLastError();
                return false;
            }
        }
        if (used_ > Capacity() || count_ > used_ / sizeof(EVT_VARIANT)) {
            error = ERROR_INVALID_DATA;
            return false;
        }
        error = ERROR_SUCCESS;
        return true;
    }

    const EVT_VARIANT* Get(DWORD index, DWORD type) const noexcept
    {
        return index < count_ && buffer_[index].Type == type ? &buffer_[index] : nullptr;
    }

    std::optional<std::wstring> Text(DWORD index) const
    {
        const auto* value = Get(index, EvtVarTypeString);
        if (!value || !Contains(value->StringVal, sizeof(wchar_t), alignof(wchar_t))) { return std::nullopt; }
        const auto remaining = (used_ - Offset(value->StringVal)) / sizeof(wchar_t);
        const auto* start = value->StringVal;
        const auto* limit = start + (std::min)(remaining, kMaxFieldChars + 1);
        const auto* end = std::find(start, limit, L'\0');
        return end == limit ? std::nullopt : std::optional<std::wstring>(std::wstring(start, end));
    }

    std::wstring Guid(DWORD index) const
    {
        // XML/EVTX 渲染可以提供文本；原生 GUID 单独核对指针边界。
        if (const auto* native = Get(index, EvtVarTypeGuid)) {
            wchar_t text[39]{};
            if (Contains(native->GuidVal, sizeof(GUID), alignof(GUID)) && StringFromGUID2(*native->GuidVal, text, 39)) {
                return text;
            }
            return {};
        }
        return Text(index).value_or(L"");
    }

    std::uint32_t PidOrTid(DWORD index) const
    {
        if (const auto* value = Get(index, EvtVarTypeUInt32)) { return value->UInt32Val; }
        // XPath 选择值也可能按文本返回，仅接受完全匹配的十进制 u32。
        const auto text = Text(index);
        if (!text || text->empty() || text->size() > 10) { return 0; }
        std::uint64_t result = 0;
        for (const auto ch : *text) {
            if (ch < L'0' || ch > L'9') { return 0; }
            result = result * 10 + static_cast<unsigned>(ch - L'0');
        }
        return result <= UINT32_MAX ? static_cast<std::uint32_t>(result) : 0;
    }

private:
    DWORD Capacity() const noexcept { return static_cast<DWORD>(buffer_.size() * sizeof(EVT_VARIANT)); }
    std::uintptr_t Offset(const void* ptr) const noexcept
    {
        return reinterpret_cast<std::uintptr_t>(ptr) - reinterpret_cast<std::uintptr_t>(buffer_.data());
    }
    bool Contains(const void* ptr, std::size_t bytes, std::size_t alignment) const noexcept
    {
        const auto offset = Offset(ptr);
        return ptr && reinterpret_cast<std::uintptr_t>(ptr) % alignment == 0 &&
            offset >= count_ * sizeof(EVT_VARIANT) && offset <= used_ && bytes <= used_ - offset;
    }

    std::vector<EVT_VARIANT> buffer_ = std::vector<EVT_VARIANT>(4096 / sizeof(EVT_VARIANT));
    DWORD used_ = 0, count_ = 0;
};

SysmonThreadFields ReadFields(const RenderedValues& system, const RenderedValues& payload)
{
    SysmonThreadFields fields;
    fields.channel = system.Text(EvtSystemChannel).value_or(L"");
    fields.provider = system.Text(EvtSystemProviderName).value_or(L"");
    fields.providerGuid = system.Guid(EvtSystemProviderGuid);
    fields.computer = system.Text(EvtSystemComputer).value_or(L"");
    if (const auto* item = system.Get(EvtSystemEventID, EvtVarTypeUInt16)) { fields.eventId = item->UInt16Val; }
    if (const auto* item = system.Get(EvtSystemVersion, EvtVarTypeByte)) { fields.version = item->ByteVal; }
    if (const auto* item = system.Get(EvtSystemEventRecordId, EvtVarTypeUInt64)) { fields.recordId = item->UInt64Val; }
    if (const auto* item = system.Get(EvtSystemTimeCreated, EvtVarTypeFileTime)) { fields.timeCreatedFileTime = item->FileTimeVal; }

    fields.sourceGuid = payload.Guid(SourceGuid);
    fields.targetGuid = payload.Guid(TargetGuid);
    fields.sourcePid = payload.PidOrTid(SourcePid);
    fields.targetPid = payload.PidOrTid(TargetPid);
    fields.newThreadId = payload.PidOrTid(NewTid);
    fields.startAddress = payload.Text(StartVa).value_or(L"");
    fields.sourceImage = payload.Text(SrcImage);
    fields.targetImage = payload.Text(DstImage);
    fields.startModule = payload.Text(StartMod);
    fields.startFunction = payload.Text(StartFn);
    return fields;
}

void SetNativeError(SysmonThreadReadResult& result, std::wstring_view stage, std::uint32_t error)
{
    // 首个实际失败保留；后来遇到的解析失败有计数，不能覆盖前一条原生错误。
    if (result.nativeError == 0) {
        result.nativeStage = stage;
        result.nativeError = error;
    }
}

} // namespace

std::optional<std::wstring> NormalizeSysmonGuid(std::wstring_view guid)
{
    if (guid.size() == 38 && guid.front() == L'{' && guid.back() == L'}') { guid = guid.substr(1, 36); }
    if (guid.size() != 36) { return std::nullopt; }
    std::wstring result;
    result.reserve(36);
    bool nonzero = false;
    for (std::size_t i = 0; i < guid.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (guid[i] != L'-') { return std::nullopt; }
            result.push_back(L'-');
        } else {
            const auto value = HexDigit(guid[i]);
            if (value < 0) { return std::nullopt; }
            nonzero |= value != 0;
            result.push_back(L"0123456789abcdef"[value]);
        }
    }
    return nonzero ? std::optional<std::wstring>(std::move(result)) : std::nullopt;
}

SysmonThreadDecoded DecodeSysmonThreadEvent(std::wstring_view targetGuid, SysmonThreadFields fields)
{
    const auto provider = NormalizeSysmonGuid(fields.providerGuid);
    if (fields.channel != kSysmonChannel || fields.provider != kSysmonProvider || !provider ||
        *provider != kSysmonProviderGuid || fields.eventId != kSysmonThreadEventId) {
        return {SysmonThreadDecode::WrongSource, {}};
    }
    if (!fields.version || *fields.version != kSysmonThreadEventVersion) {
        return {SysmonThreadDecode::UnsupportedVersion, {}};
    }
    const auto wanted = NormalizeSysmonGuid(targetGuid);
    const auto target = NormalizeSysmonGuid(fields.targetGuid);
    if (!wanted || !target) { return {}; }
    if (*target != *wanted) { return {SysmonThreadDecode::OtherTarget, {}}; }

    // A 与 B 都必须由同一条 Sysmon 记录独立提供；仅凭 PID 不能补任何一侧。
    const auto source = NormalizeSysmonGuid(fields.sourceGuid);
    const auto address = Address(fields.startAddress);
    if (!source || *source == *target || !fields.sourcePid || !fields.targetPid || fields.sourcePid == fields.targetPid ||
        !fields.newThreadId || !address || fields.computer.empty() || !fields.recordId || !fields.timeCreatedFileTime) {
        return {};
    }
    fields.providerGuid = *provider;
    fields.sourceGuid = *source;
    fields.targetGuid = *target;
    return {SysmonThreadDecode::Observed, SysmonThreadObservation{std::move(fields), *address}};
}

SysmonThreadReadResult ReadLocalSysmonThreadEvents(const SysmonThreadQuery& query)
{
    SysmonThreadReadResult result;
    const auto target = NormalizeSysmonGuid(query.targetGuid);
    if (!target || query.maxMatches == 0 || query.maxMatches > kSysmonMaxMatches ||
        (query.recordId && *query.recordId == 0)) {
        return result;
    }
    result.targetGuid = *target;

    // 只下推明确的原生常量。目标 GUID 从结构化字段读取后规范化比较，避免 XPath 大小写漏报。
    auto xpath = std::wstring(L"*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and EventID=8");
    if (query.recordId) {
        xpath += L" and EventRecordID=" + std::to_wstring(*query.recordId);
    }
    xpath += L"]]";
    const auto started = GetTickCount64();
    const EventHandle events(EvtQuery(nullptr, kSysmonChannel, xpath.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection));
    if (!events.value) {
        const auto error = GetLastError();
        SetNativeError(result, L"query", error);
        result.state = error == ERROR_EVT_CHANNEL_NOT_FOUND ? SysmonReadState::ChannelUnavailable :
            error == ERROR_ACCESS_DENIED ? SysmonReadState::AccessDenied : SysmonReadState::ReadFailed;
        return result;
    }

    const EventHandle systemContext(EvtCreateRenderContext(0, nullptr, EvtRenderContextSystem));
    if (!systemContext.value) {
        SetNativeError(result, L"system-context", GetLastError());
        result.state = SysmonReadState::ReadFailed;
        return result;
    }
    auto paths = std::to_array(kPaths);
    const EventHandle payloadContext(EvtCreateRenderContext(static_cast<DWORD>(paths.size()), paths.data(), EvtRenderContextValues));
    if (!payloadContext.value) {
        SetNativeError(result, L"event-data-context", GetLastError());
        result.state = SysmonReadState::ReadFailed;
        return result;
    }

    RenderedValues system, payload;
    result.observations.reserve(query.maxMatches);
    for (;;) {
        if (GetTickCount64() - started >= kSysmonReadBudgetMs) {
            result.limit = SysmonLimit::Time;
            break;
        }
        if (result.examined >= kSysmonScanLimit) {
            result.limit = SysmonLimit::Scan;
            break;
        }
        if (result.observations.size() >= query.maxMatches) {
            result.limit = SysmonLimit::Matches;
            break;
        }

        // EventBatch 在所有退出路径释放；EvtNext 用短等待，不因通道无后续数据无限阻塞。
        EventBatch batch;
        DWORD returned = 0;
        const auto requested = (std::min)(kBatchSize, static_cast<DWORD>(kSysmonScanLimit - result.examined));
        const auto elapsed = GetTickCount64() - started;
        if (elapsed >= kSysmonReadBudgetMs) {
            result.limit = SysmonLimit::Time;
            break;
        }
        const auto wait = (std::min)(250UL, static_cast<DWORD>(kSysmonReadBudgetMs - elapsed));
        if (!EvtNext(events.value, requested, batch.handles.data(), wait, 0, &returned)) {
            const auto error = GetLastError();
            if (error == ERROR_TIMEOUT) { continue; }
            if (error == ERROR_NO_MORE_ITEMS) {
                result.reachedEnd = true;
            } else {
                SetNativeError(result, L"next", error);
            }
            break;
        }
        if (returned == 0 || returned > requested) {
            SetNativeError(result, L"next-batch", ERROR_INVALID_DATA);
            break;
        }

        for (DWORD i = 0; i < returned; ++i) {
            if (GetTickCount64() - started >= kSysmonReadBudgetMs || result.observations.size() >= query.maxMatches) {
                break;
            }
            ++result.examined;
            const auto event = batch.handles[i];
            std::uint32_t error = 0;
            if (!event) {
                ++result.renderFailed;
                SetNativeError(result, L"next-record", ERROR_INVALID_DATA);
                continue;
            }
            if (!system.Render(systemContext.value, event, error)) {
                ++result.renderFailed;
                SetNativeError(result, L"system-render", error);
                continue;
            }
            if (!payload.Render(payloadContext.value, event, error)) {
                ++result.renderFailed;
                SetNativeError(result, L"event-data-render", error);
                continue;
            }

            auto fields = ReadFields(system, payload);
            if (query.recordId && fields.recordId != *query.recordId) {
                ++result.malformed;
                continue;
            }
            // 非目标的字段不离开读器；未知版本及坏记录影响完整性，不作为空结果处理。
            auto decoded = DecodeSysmonThreadEvent(result.targetGuid, std::move(fields));
            switch (decoded.state) {
            case SysmonThreadDecode::Observed:
                result.observations.push_back(std::move(*decoded.observation));
                break;
            case SysmonThreadDecode::OtherTarget:
                break;
            case SysmonThreadDecode::UnsupportedVersion:
                ++result.unsupportedVersions;
                break;
            case SysmonThreadDecode::WrongSource:
            case SysmonThreadDecode::InvalidFields:
                ++result.malformed;
                break;
            }
        }
    }
    if (result.reachedEnd && !result.unsupportedVersions && !result.malformed && !result.renderFailed) {
        result.state = SysmonReadState::Exhausted;
    } else if (result.examined == 0 && result.nativeError != 0) {
        result.state = SysmonReadState::ReadFailed;
    } else {
        result.state = SysmonReadState::Partial;
    }
    return result;
}

} // namespace Ksword::ActionAnalyze::Detection
