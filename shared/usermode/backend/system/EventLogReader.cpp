#include "EventLogReader.h"

#include <winevt.h>

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Wevtapi.lib is already on the project link line; naming it here keeps this
// translation unit self-describing for anyone reading it in isolation.
#pragma comment(lib, "Wevtapi.lib")

namespace ks::r3::system_tools {
namespace {

// kEvtNextBatch is the number of event handles pulled per EvtNext call. Larger
// batches do not help because message formatting, not the fetch, is the cost.
constexpr DWORD kEvtNextBatch = 32;
constexpr DWORD kEvtNextTimeoutMs = 5000;

// kMaxRequestedCount bounds what the UI may ask for. Every record costs one
// EvtFormatMessage round trip, and an unbounded request would keep the worker
// thread busy long after the user stopped caring about the answer.
constexpr std::uint32_t kMaxRequestedCount = 5000;
void CloseOwned(EVT_HANDLE handle,EventLogQueryResult& result) noexcept {
    if(!handle)return;++result.closeAttempted;
    if(!::EvtClose(handle)){++result.closeFailed;if(result.closeErrors.size()<32)result.closeErrors.push_back(::GetLastError());}
}
struct OwnedEvt {
    EVT_HANDLE handle;EventLogQueryResult& result;
    ~OwnedEvt(){CloseOwned(handle,result);}
};
struct OwnedBatch {
    EVT_HANDLE handles[kEvtNextBatch]{};EventLogQueryResult& result;
    explicit OwnedBatch(EventLogQueryResult& value):result(value){}
    ~OwnedBatch(){for(DWORD i=0;i<kEvtNextBatch;++i){bool duplicate=false;for(DWORD j=0;j<i;++j)duplicate=duplicate||handles[j]==handles[i];if(!duplicate)CloseOwned(handles[i],result);}}
};

std::wstring FormatSystemTime(const SYSTEMTIME& time) {
    std::wostringstream stream;
    stream << std::setfill(L'0')
        << time.wYear << L'-' << std::setw(2) << time.wMonth << L'-' << std::setw(2) << time.wDay
        << L' ' << std::setw(2) << time.wHour << L':' << std::setw(2) << time.wMinute
        << L':' << std::setw(2) << time.wSecond;
    return stream.str();
}

std::wstring FormatFileTimeLocal(const ULONGLONG rawFileTime) {
    if (rawFileTime == 0) {
        return L"—";
    }
    FILETIME utc{};
    utc.dwLowDateTime = static_cast<DWORD>(rawFileTime & 0xFFFFFFFFULL);
    utc.dwHighDateTime = static_cast<DWORD>(rawFileTime >> 32);
    FILETIME local{};
    SYSTEMTIME system{};
    if (!::FileTimeToLocalFileTime(&utc, &local) || !::FileTimeToSystemTime(&local, &system)) {
        return L"—";
    }
    return FormatSystemTime(system);
}

// LevelText maps the standard severity values. Level 0 means the provider did
// not classify the record; the Windows event viewer shows those as information,
// so this page agrees with it rather than inventing a fifth bucket.
std::wstring LevelText(const std::uint8_t level) {
    switch (level) {
    case 0:
        return L"信息";
    case 1:
        return L"关键";
    case 2:
        return L"错误";
    case 3:
        return L"警告";
    case 4:
        return L"信息";
    case 5:
        return L"详细";
    default:
        return L"级别" + std::to_wstring(level);
    }
}

std::wstring LevelQueryFragment(const EventLogLevelFilter filter) {
    switch (filter) {
    case EventLogLevelFilter::Critical:
        return L"*[System[Level=1]]";
    case EventLogLevelFilter::Error:
        return L"*[System[Level=2]]";
    case EventLogLevelFilter::Warning:
        return L"*[System[Level=3]]";
    case EventLogLevelFilter::Information:
        // Level 0 is folded in here for the same reason LevelText does it: an
        // unclassified record is informational, and excluding it would hide
        // most of what several in-box providers write.
        return L"*[System[(Level=4 or Level=0)]]";
    case EventLogLevelFilter::All:
    default:
        return L"*";
    }
}

std::wstring LastErrorText(const DWORD error) {
    LPWSTR buffer = nullptr;
    const DWORD length = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, error, 0, reinterpret_cast<LPWSTR>(&buffer), 0, nullptr);
    std::wstring text = L"错误码 " + std::to_wstring(error);
    if (length > 0 && buffer) {
        std::wstring detail(buffer, length);
        while (!detail.empty() && (detail.back() == L'\r' || detail.back() == L'\n' || detail.back() == L' ')) {
            detail.pop_back();
        }
        text += L"（" + detail + L"）";
    }
    if (buffer) {
        ::LocalFree(buffer);
    }
    return text;
}

// CollapseWhitespace flattens a multi-line event message into one list cell.
// Event descriptions routinely carry embedded newlines and tab-aligned key/value
// blocks, which would break both the single-line ListView cell and the TSV
// export that copies from it.
std::wstring CollapseWhitespace(const std::wstring& text) {
    std::wstring collapsed;
    collapsed.reserve(text.size());
    bool pendingSpace = false;
    for (const wchar_t ch : text) {
        if (ch == L'\r' || ch == L'\n' || ch == L'\t' || ch == L' ') {
            pendingSpace = !collapsed.empty();
            continue;
        }
        if (pendingSpace) {
            collapsed.push_back(L' ');
            pendingSpace = false;
        }
        collapsed.push_back(ch);
    }
    return collapsed;
}

// PublisherMetadataCache keeps one EvtOpenPublisherMetadata handle per provider.
// Opening the metadata is the expensive half of message resolution and a channel
// is dominated by a handful of providers, so the cache turns thousands of opens
// into a few dozen.
class PublisherMetadataCache final {
public:
    explicit PublisherMetadataCache(EventLogQueryResult& result):result_(result){}
    ~PublisherMetadataCache() {
        for (auto& item : handles_) {
            if (item.second) {
                CloseOwned(item.second,result_);
            }
        }
    }

    EVT_HANDLE get(const std::wstring& provider,DWORD& error) {
        const auto found = handles_.find(provider);
        if (found != handles_.end()) {
            error = errors_[provider];
            return found->second;
        }
        EVT_HANDLE metadata = ::EvtOpenPublisherMetadata(nullptr, provider.c_str(), nullptr, 0, 0);
        error = metadata ? ERROR_SUCCESS : ::GetLastError();errors_[provider] = error;
        handles_.emplace(provider, metadata);
        return metadata;
    }

private:
    std::unordered_map<std::wstring, EVT_HANDLE> handles_;
    std::unordered_map<std::wstring, DWORD> errors_;
    EventLogQueryResult& result_;
};

// FormatEventMessage renders the human-readable description. A provider whose
// message table is missing or partially resolvable still yields useful text, so
// the partial-resolution status codes are treated as success rather than as
// failure -- reporting "无法解析" for a message that is 90% rendered would be a
// worse answer than the message itself.
bool FormatEventMessage(EVT_HANDLE metadata, EVT_HANDLE event, std::wstring& messageOut,EventLogEntry& entry) {
    messageOut.clear();
    if (!metadata) {
        return false;
    }
    DWORD used = 0;
    if (::EvtFormatMessage(metadata, event, 0, 0, nullptr, EvtFormatMessageEvent, 0, nullptr, &used)) {
        // A record whose description really is empty succeeds on the sizing
        // call. That is a resolved message, not a missing one.
        return true;
    }
    DWORD error = ::GetLastError();
    entry.messageError = error;
    if (error != ERROR_INSUFFICIENT_BUFFER) {
        return false;
    }
    if(!used){entry.messageMalformed = true;return false;}if(used>65536){entry.messageLimited = true;return false;}
    std::vector<wchar_t> buffer(used, static_cast<wchar_t>(0xffff));
    if (!::EvtFormatMessage(metadata, event, 0, 0, nullptr, EvtFormatMessageEvent,
            static_cast<DWORD>(buffer.size()), buffer.data(), &used)) {
        error = ::GetLastError();
        entry.messageError = error;
        const bool partial = error == ERROR_EVT_UNRESOLVED_VALUE_INSERT ||
            error == ERROR_EVT_UNRESOLVED_PARAMETER_INSERT ||
            error == ERROR_EVT_MAX_INSERTS_REACHED;
        if (!partial) {
            return false;
        }
        entry.messagePartial = true;
    }
    else entry.messageError = ERROR_SUCCESS;
    if(used>buffer.size()){entry.messageMalformed = true;return false;}
    const auto end = std::find(buffer.begin(),buffer.end(),L'\0');if(end==buffer.end()){entry.messageMalformed = true;return false;}
    messageOut.assign(buffer.begin(),end);
    return true;
}

// ReadSystemProperties renders the System section of one record. The values are
// requested through a render context instead of parsing the XML form because
// the variant array is both faster and immune to XML escaping surprises in
// provider names.
bool ReadSystemProperties(EVT_HANDLE context, EVT_HANDLE event, std::vector<BYTE>& scratch, EventLogEntry& entry,EventLogQueryResult& result) {
    DWORD used = 0;
    DWORD propertyCount = 0;
    if (!::EvtRender(context, event, EvtRenderEventValues,
            static_cast<DWORD>(scratch.size()), scratch.data(), &used, &propertyCount)) {
        const auto error = ::GetLastError();if (error != ERROR_INSUFFICIENT_BUFFER) {result.renderError = error;
            return false;
        }
        if(!used){result.malformed = true;return false;}if(used>16u*1024u*1024u){result.limited = true;return false;}scratch.resize(used);
        if (!::EvtRender(context, event, EvtRenderEventValues,
                static_cast<DWORD>(scratch.size()), scratch.data(), &used, &propertyCount)) {
            result.renderError = ::GetLastError();return false;
        }
    }
    if(used>scratch.size()||propertyCount>used/sizeof(EVT_VARIANT)){result.malformed = true;return false;}

    const auto* values = reinterpret_cast<const EVT_VARIANT*>(scratch.data());
    const auto valueAt = [values, propertyCount](const DWORD index) -> const EVT_VARIANT* {
        return index < propertyCount ? &values[index] : nullptr;
    };
    const auto field = [&](const wchar_t* name,DWORD index,DWORD expected) {
        const auto* value = valueAt(index);auto& evidence = entry.fields[name];
        evidence.absent = !value || value->Type == EvtVarTypeNull;evidence.type = value?value->Type:EvtVarTypeNull;
        evidence.available = value && value->Type == expected;evidence.malformed = !evidence.absent && !evidence.available;
        return evidence.available ? value : nullptr;
    };
    const auto string = [&](const wchar_t* name,DWORD index,std::wstring& target) {
        const auto* value = field(name,index,EvtVarTypeString);if(!value)return;
        auto& evidence = entry.fields[name];const auto base = reinterpret_cast<std::uintptr_t>(scratch.data()),address = reinterpret_cast<std::uintptr_t>(value->StringVal);
        if(!value->StringVal||address<base||address-base>used||address%alignof(wchar_t)){evidence.available = false;evidence.malformed = true;return;}
        const auto count = (used-(address-base))/sizeof(wchar_t);const auto* end = std::find(value->StringVal,value->StringVal+count,L'\0');
        if(end==value->StringVal+count){evidence.available = false;evidence.malformed = true;return;}target.assign(value->StringVal,end);
    };
    string(L"providerName",EvtSystemProviderName,entry.providerName);string(L"computer",EvtSystemComputer,entry.computer);
    if(const auto* v=field(L"eventId",EvtSystemEventID,EvtVarTypeUInt16))entry.eventId=v->UInt16Val;
    if(const auto* v=field(L"level",EvtSystemLevel,EvtVarTypeByte))entry.level=v->ByteVal;
    if(const auto* v=field(L"timestampFileTime",EvtSystemTimeCreated,EvtVarTypeFileTime)){entry.timestampFileTime=v->FileTimeVal;entry.timeText=FormatFileTimeLocal(v->FileTimeVal);}
    if(const auto* v=field(L"recordId",EvtSystemEventRecordId,EvtVarTypeUInt64))entry.recordId=v->UInt64Val;
    if(const auto* v=field(L"headerPid",EvtSystemProcessID,EvtVarTypeUInt32))entry.processId=v->UInt32Val;

    entry.levelText = LevelText(entry.level);
    if (entry.timeText.empty()) {
        entry.timeText = L"—";
    }
    return true;
}

} // namespace

std::wstring EventLogChannelPath(const EventLogChannel channel) {
    return channel == EventLogChannel::Application ? L"Application" : L"System";
}

EventLogQueryResult QueryEventLog(const EventLogQueryRequest& request) {
    EventLogQueryResult result{};
    const ULONGLONG startTick = ::GetTickCount64();
    result.channelPath = EventLogChannelPath(request.channel);

    const std::uint32_t wanted = (std::min)(request.maxCount == 0 ? 1u : request.maxCount, kMaxRequestedCount);
    const std::wstring query = LevelQueryFragment(request.level);

    result.closeErrors.reserve(32);
    [&] {
        result.queryAttempted = true;
        OwnedEvt results{::EvtQuery(nullptr,result.channelPath.c_str(),query.c_str(),EvtQueryChannelPath|EvtQueryReverseDirection),result};
        if(!results.handle){result.queryError = ::GetLastError();result.diagnosticText = L"打开事件通道 " + result.channelPath + L" 失败：" + LastErrorText(result.queryError);return;}
        result.contextAttempted = true;OwnedEvt context{::EvtCreateRenderContext(0,nullptr,EvtRenderContextSystem),result};
        if(!context.handle){result.contextError = ::GetLastError();result.diagnosticText = L"创建事件渲染上下文失败：" + LastErrorText(result.contextError);return;}
        PublisherMetadataCache publishers(result);std::vector<BYTE> scratch(4096);result.entries.reserve(wanted);
        while(result.entries.size()<wanted){
            if(request.cancelled&&request.cancelled()){result.cancelled = true;break;}
            if(result.examined>=kMaxRequestedCount||::GetTickCount64()-startTick>=request.maxDurationMs){result.limited = true;break;}
            OwnedBatch events(result);DWORD returned = 0;const auto batch = (std::min)(kEvtNextBatch,static_cast<DWORD>(wanted-result.entries.size()));
            const bool next = ::EvtNext(results.handle,batch,events.handles,kEvtNextTimeoutMs,0,&returned)!=FALSE;
            const auto error = next ? ERROR_SUCCESS : ::GetLastError();
            if(!next){if(error==ERROR_NO_MORE_ITEMS)result.exhausted = true;else {result.nextError = error;result.diagnosticText = L"读取事件记录中断：" + LastErrorText(error);}break;}
            if(!returned||returned>batch){result.malformed = true;break;}
            for(DWORD i=0;i<returned;++i){if(!events.handles[i])result.malformed = true;for(DWORD j=0;j<i;++j)if(events.handles[j]==events.handles[i])result.malformed = true;}
            if(result.malformed)break;
            for(DWORD index=0;index<returned;++index){
                if(request.cancelled&&request.cancelled()){result.cancelled = true;break;}
                if(result.examined>=kMaxRequestedCount||::GetTickCount64()-startTick>=request.maxDurationMs){result.limited = true;break;}
                ++result.examined;EventLogEntry entry{};
                if(ReadSystemProperties(context.handle,events.handles[index],scratch,entry,result)){
                    entry.messageRequested = request.messages;
                    if(request.messages){std::wstring message;const auto metadata = publishers.get(entry.providerName,entry.metadataError);
                        entry.messageAvailable = FormatEventMessage(metadata,events.handles[index],message,entry);
                        if(entry.messageAvailable){entry.messageRaw = message;entry.message = CollapseWhitespace(message);}
                        else {++result.unresolvedMessages;entry.message = L"(无法解析描述，通常是提供程序未注册消息资源)";}}
                    result.entries.push_back(std::move(entry));
                }else ++result.renderFailed;
                if(result.limited||result.malformed)break;
            }
            if(result.limited||result.cancelled||result.malformed)break;
        }
        result.success = true;
        result.pageComplete = !result.limited&&!result.cancelled&&!result.malformed&&!result.nextError&&!result.renderFailed&&(result.exhausted||result.entries.size()==wanted);
    }();
    result.elapsedMs = static_cast<std::uint32_t>(::GetTickCount64() - startTick);

    if (result.entries.empty() && result.diagnosticText.empty()) {
        result.diagnosticText = L"该通道在当前级别筛选下没有记录。";
    }
    return result;
}

} // namespace ks::r3::system_tools
