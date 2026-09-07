#include "TimelineCore.h"

#include <algorithm>
#include <limits>
#include <unordered_map>
#include <utility>

namespace Ksword::Evidence {
namespace {

// FNV-1a 64。只用于批次自校验（识别落盘后被改动的批次），不是密码学校验。
std::uint64_t Fnv1a64(std::string_view text) noexcept {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const char raw : text) {
        hash ^= static_cast<std::uint64_t>(static_cast<unsigned char>(raw));
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::uint64_t SaturatingAddU64(std::uint64_t a, std::uint64_t b) noexcept {
    const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
    return (a > limit - b) ? limit : a + b;
}

// int64 取绝对值时不能写 -v：INT64_MIN 取反是 UB。
std::uint64_t AbsToU64(std::int64_t value) noexcept {
    if (value >= 0) {
        return static_cast<std::uint64_t>(value);
    }
    return static_cast<std::uint64_t>(-(value + 1)) + 1ULL;
}

bool ContainsPid(const std::vector<std::uint64_t>& list, std::uint64_t pid) noexcept {
    return std::find(list.begin(), list.end(), pid) != list.end();
}

const char* BufferingNoticeFor(SessionState state) noexcept {
    switch (state) {
    case SessionState::New:           return "timeline.session.buffering.none";
    case SessionState::Collecting:    return "timeline.session.buffering.recording-and-displaying";
    // T-01：这一条是本模块的核心文案 —— 暂停显示时后台**仍在**记录与落盘。
    case SessionState::DisplayPaused: return "timeline.session.buffering.recording-display-frozen";
    case SessionState::Stopped:       return "timeline.session.buffering.no-new-events-retained";
    case SessionState::Saved:         return "timeline.session.buffering.read-only";
    }
    return "timeline.session.buffering.none";
}

SessionTransition MakeAllowed(SessionState next) {
    SessionTransition t;
    t.allowed = true;
    t.nextState = next;
    t.backgroundRecording = SessionAcceptsNewEvents(next);
    t.displayUpdating = SessionUpdatesDisplay(next);
    t.bufferingNoticeKey = BufferingNoticeFor(next);
    return t;
}

SessionTransition MakeRejected(SessionState current, const char* reasonKey) {
    SessionTransition t;
    t.allowed = false;
    t.nextState = current;
    t.backgroundRecording = SessionAcceptsNewEvents(current);
    t.displayUpdating = SessionUpdatesDisplay(current);
    t.bufferingNoticeKey = BufferingNoticeFor(current);
    t.rejectionKey = reasonKey;
    return t;
}

// ---------------------------------------------------------------------------
// JSON 辅助
// ---------------------------------------------------------------------------

void Put(JsonObject& object, const char* name, JsonValue value) {
    object.emplace_back(std::string(name), std::move(value));
}

void PutText(JsonObject& object, const char* name, const std::string& value) {
    Put(object, name, JsonValue::makeString(value));
}

void PutU32(JsonObject& object, const char* name, std::uint32_t value) {
    Put(object, name, JsonValue::makeUInt(static_cast<std::uint64_t>(value)));
}

void PutU64Text(JsonObject& object, const char* name, std::uint64_t value) {
    Put(object, name, JsonValue::makeU64Text(value, U64Format::Decimal));
}

void PutOptionalU64(JsonObject& object, const char* name, const OptionalU64& value) {
    Put(object, name, JsonValue::makeOptionalU64Text(value, U64Format::Decimal));
}

bool ReadText(const JsonValue& object, const char* name, std::string& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetString(out);
}

bool ReadU32(const JsonValue& object, const char* name, std::uint32_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    std::uint64_t raw = 0;
    if (!field->tryGetU64(raw)) {
        return false;
    }
    if (raw > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
        return false;
    }
    out = static_cast<std::uint32_t>(raw);
    return true;
}

bool ReadU64(const JsonValue& object, const char* name, std::uint64_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetU64(out);
}

bool ReadOptionalU64(const JsonValue& object, const char* name, OptionalU64& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetOptionalU64(out);
}

bool ReadBool(const JsonValue& object, const char* name, bool& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    return field->tryGetBool(out);
}

bool ReadI64(const JsonValue& object, const char* name, std::int64_t& out) {
    const JsonValue* field = object.find(name);
    if (field == nullptr) {
        return false;
    }
    std::string text;
    if (!field->tryGetString(text)) {
        return field->tryGetI64(out);
    }
    return ParseI64(text, out);
}

// 枚举名 <-> 值。解析端只按名字查表；查不到就是坏文件，绝不"猜一个最接近的"。
template <typename Enum, std::size_t N>
bool LookupEnum(const std::pair<const char*, Enum> (&table)[N],
                const std::string& name,
                Enum& out) {
    for (std::size_t i = 0; i < N; ++i) {
        if (name == table[i].first) {
            out = table[i].second;
            return true;
        }
    }
    return false;
}

const std::pair<const char*, TimelineEventCategory> kCategoryTable[] = {
    { "Process", TimelineEventCategory::Process },
    { "Thread", TimelineEventCategory::Thread },
    { "Image", TimelineEventCategory::Image },
    { "File", TimelineEventCategory::File },
    { "Registry", TimelineEventCategory::Registry },
    { "Network", TimelineEventCategory::Network },
    { "Other", TimelineEventCategory::Other },
};

const std::pair<const char*, EventParseOutcome> kParseOutcomeTable[] = {
    { "Parsed", EventParseOutcome::Parsed },
    { "UnparsedUnknownSchema", EventParseOutcome::UnparsedUnknownSchema },
    { "Malformed", EventParseOutcome::Malformed },
};

const std::pair<const char*, TimeResolution> kResolutionTable[] = {
    { "Unknown", TimeResolution::Unknown },
    { "Second", TimeResolution::Second },
    { "Millisecond", TimeResolution::Millisecond },
    { "Microsecond", TimeResolution::Microsecond },
    { "HundredNanosecond", TimeResolution::HundredNanosecond },
};

const std::pair<const char*, AttributionKind> kAttributionTable[] = {
    { "BoundToInstance", AttributionKind::BoundToInstance },
    { "Provisional", AttributionKind::Provisional },
    { "AfterInstanceExit", AttributionKind::AfterInstanceExit },
    { "Ambiguous", AttributionKind::Ambiguous },
    { "UnknownProcess", AttributionKind::UnknownProcess },
};

const std::pair<const char*, SessionState> kSessionStateTable[] = {
    { "New", SessionState::New },
    { "Collecting", SessionState::Collecting },
    { "DisplayPaused", SessionState::DisplayPaused },
    { "Stopped", SessionState::Stopped },
    { "Saved", SessionState::Saved },
};

const std::pair<const char*, RetentionPolicy> kRetentionTable[] = {
    { "StopOnLimit", RetentionPolicy::StopOnLimit },
    { "EvictOldest", RetentionPolicy::EvictOldest },
};

const std::pair<const char*, BoundsState> kBoundsStateTable[] = {
    { "WithinLimits", BoundsState::WithinLimits },
    { "MemoryLimitReached", BoundsState::MemoryLimitReached },
    { "ArchiveLimitReached", BoundsState::ArchiveLimitReached },
};

// T-10：availabilityStatus / origin 以前是"线性找名字，找不到就留一个良性默认值"。
// 那条路会把 *失败* 悄悄改判成 *从未运行*（AccessDenied 拼错 -> NotCollected，而
// nativeCode 还留着 STATUS_ACCESS_DENIED，两个字段互相矛盾），而且和同一个 header 里
// 其它枚举"不认识就判坏文件"的做法自相矛盾。现在一律走 LookupEnum 的硬失败。
const std::pair<const char*, CollectionStatus> kCollectionStatusTable[] = {
    { "NotCollected", CollectionStatus::NotCollected },
    { "Success", CollectionStatus::Success },
    { "Partial", CollectionStatus::Partial },
    { "Unsupported", CollectionStatus::Unsupported },
    { "AccessDenied", CollectionStatus::AccessDenied },
    { "Timeout", CollectionStatus::Timeout },
    { "Error", CollectionStatus::Error },
};

const std::pair<const char*, SourceOrigin> kSourceOriginTable[] = {
    { "Unknown", SourceOrigin::Unknown },
    { "LiveKernel", SourceOrigin::LiveKernel },
    { "LiveUserMode", SourceOrigin::LiveUserMode },
    { "ExternalFile", SourceOrigin::ExternalFile },
    { "OfflineSample", SourceOrigin::OfflineSample },
};

const std::pair<const char*, LossCategory> kLossCategoryTable[] = {
    { "SourceDrop", LossCategory::SourceDrop },
    { "RingOverwrite", LossCategory::RingOverwrite },
    { "QueueDiscard", LossCategory::QueueDiscard },
    { "ParseFailure", LossCategory::ParseFailure },
    { "FilteredOut", LossCategory::FilteredOut },
    { "RetentionEvicted", LossCategory::RetentionEvicted },
};

JsonValue EncodeEvent(const TimelineEvent& event) {
    JsonObject object;
    PutText(object, "recordId", event.recordId);
    PutText(object, "providerId", event.providerId);
    PutText(object, "sourceGroup", event.sourceGroup);
    PutU32(object, "eventId", event.eventId);
    PutU32(object, "eventVersion", event.eventVersion);
    PutU32(object, "opcode", event.opcode);
    PutU32(object, "task", event.task);
    PutText(object, "category", TimelineEventCategoryName(event.category));
    PutText(object, "parseOutcome", EventParseOutcomeName(event.parseOutcome));
    PutText(object, "parserId", event.parserId);
    PutU32(object, "parserVersion", event.parserVersion);
    PutText(object, "parseReasonKey", event.parseReasonKey);

    JsonArray fields;
    fields.reserve(event.rawFields.size());
    for (const auto& pair : event.rawFields) {
        JsonObject one;
        PutText(one, "n", pair.first);
        PutText(one, "v", pair.second);
        fields.push_back(JsonValue::makeObject(std::move(one)));
    }
    Put(object, "rawFields", JsonValue::makeArray(std::move(fields)));
    PutText(object, "rawPayloadHex", event.rawPayloadHex);

    JsonObject time;
    PutOptionalU64(time, "sourceTime100ns", event.time.sourceTime100ns);
    PutOptionalU64(time, "receiveTime100ns", event.time.receiveTime100ns);
    PutText(time, "sourceResolution", TimeResolutionName(event.time.sourceResolution));
    Put(time, "calibrationAvailable", JsonValue::makeBool(event.time.calibrationAvailable));
    PutText(time, "calibrationOffset100ns", FormatI64(event.time.calibrationOffset100ns));
    PutText(time, "calibrationId", event.time.calibrationId);
    PutText(time, "bootId", event.time.bootId);
    PutOptionalU64(time, "sourceMonotonic", event.time.sourceMonotonic);
    Put(time, "lateArrival", JsonValue::makeBool(event.time.lateArrival));
    Put(time, "orderUncertain", JsonValue::makeBool(event.time.orderUncertain));
    Put(object, "time", JsonValue::makeObject(std::move(time)));

    PutText(object, "attribution", AttributionKindName(event.attribution));
    PutText(object, "processInstanceKey", event.processInstanceKey);
    PutText(object, "provisionalProcessId", event.provisionalProcessId);
    PutOptionalU64(object, "pid", event.pid);
    PutOptionalU64(object, "tid", event.tid);
    PutU64Text(object, "arrivalSequence", event.arrivalSequence);
    PutText(object, "sourceLinkId", event.sourceLinkId);
    PutText(object, "sourceLinkField", event.sourceLinkField);
    return JsonValue::makeObject(std::move(object));
}

bool DecodeEvent(const JsonValue& value, TimelineEvent& out) {
    if (value.asObject() == nullptr) {
        return false;
    }
    TimelineEvent event;
    std::string text;
    if (!ReadText(value, "recordId", event.recordId)) { return false; }
    if (!ReadText(value, "providerId", event.providerId)) { return false; }
    if (!ReadText(value, "sourceGroup", event.sourceGroup)) { return false; }
    if (!ReadU32(value, "eventId", event.eventId)) { return false; }
    if (!ReadU32(value, "eventVersion", event.eventVersion)) { return false; }
    if (!ReadU32(value, "opcode", event.opcode)) { return false; }
    if (!ReadU32(value, "task", event.task)) { return false; }
    if (!ReadText(value, "category", text) || !LookupEnum(kCategoryTable, text, event.category)) {
        return false;
    }
    if (!ReadText(value, "parseOutcome", text) ||
        !LookupEnum(kParseOutcomeTable, text, event.parseOutcome)) {
        return false;
    }
    if (!ReadText(value, "parserId", event.parserId)) { return false; }
    if (!ReadU32(value, "parserVersion", event.parserVersion)) { return false; }
    if (!ReadText(value, "parseReasonKey", event.parseReasonKey)) { return false; }

    const JsonValue* fields = value.find("rawFields");
    if (fields == nullptr) { return false; }
    const JsonArray* fieldArray = fields->asArray();
    if (fieldArray == nullptr) { return false; }
    for (const JsonValue& item : *fieldArray) {
        std::string name;
        std::string raw;
        if (!ReadText(item, "n", name) || !ReadText(item, "v", raw)) {
            return false;
        }
        event.rawFields.emplace_back(std::move(name), std::move(raw));
    }
    if (!ReadText(value, "rawPayloadHex", event.rawPayloadHex)) { return false; }

    const JsonValue* time = value.find("time");
    if (time == nullptr || time->asObject() == nullptr) { return false; }
    if (!ReadOptionalU64(*time, "sourceTime100ns", event.time.sourceTime100ns)) { return false; }
    if (!ReadOptionalU64(*time, "receiveTime100ns", event.time.receiveTime100ns)) { return false; }
    if (!ReadText(*time, "sourceResolution", text) ||
        !LookupEnum(kResolutionTable, text, event.time.sourceResolution)) {
        return false;
    }
    if (!ReadBool(*time, "calibrationAvailable", event.time.calibrationAvailable)) { return false; }
    if (!ReadI64(*time, "calibrationOffset100ns", event.time.calibrationOffset100ns)) { return false; }
    if (!ReadText(*time, "calibrationId", event.time.calibrationId)) { return false; }
    if (!ReadText(*time, "bootId", event.time.bootId)) { return false; }
    if (!ReadOptionalU64(*time, "sourceMonotonic", event.time.sourceMonotonic)) { return false; }
    if (!ReadBool(*time, "lateArrival", event.time.lateArrival)) { return false; }
    if (!ReadBool(*time, "orderUncertain", event.time.orderUncertain)) { return false; }

    if (!ReadText(value, "attribution", text) ||
        !LookupEnum(kAttributionTable, text, event.attribution)) {
        return false;
    }
    if (!ReadText(value, "processInstanceKey", event.processInstanceKey)) { return false; }
    if (!ReadText(value, "provisionalProcessId", event.provisionalProcessId)) { return false; }
    if (!ReadOptionalU64(value, "pid", event.pid)) { return false; }
    if (!ReadOptionalU64(value, "tid", event.tid)) { return false; }
    if (!ReadU64(value, "arrivalSequence", event.arrivalSequence)) { return false; }
    if (!ReadText(value, "sourceLinkId", event.sourceLinkId)) { return false; }
    if (!ReadText(value, "sourceLinkField", event.sourceLinkField)) { return false; }

    out = std::move(event);
    return true;
}

JsonValue EncodeEventArray(const std::vector<TimelineEvent>& events) {
    JsonArray array;
    array.reserve(events.size());
    for (const TimelineEvent& event : events) {
        array.push_back(EncodeEvent(event));
    }
    return JsonValue::makeArray(std::move(array));
}

std::uint64_t BatchChecksum(const std::vector<TimelineEvent>& events) {
    return Fnv1a64(WriteJson(EncodeEventArray(events), 0U));
}

// 每行一个 JSON 文档，行尾必须有 '\n'。缺 '\n' 的最后一行即"写到一半被打断"。
std::vector<std::string_view> SplitLines(std::string_view text, bool& lastLineTerminated) {
    std::vector<std::string_view> lines;
    lastLineTerminated = true;
    std::size_t begin = 0;
    while (begin < text.size()) {
        const std::size_t pos = text.find('\n', begin);
        if (pos == std::string_view::npos) {
            lines.push_back(text.substr(begin));
            lastLineTerminated = false;
            break;
        }
        std::string_view line = text.substr(begin, pos - begin);
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        lines.push_back(line);
        begin = pos + 1;
    }
    return lines;
}

} // namespace

// ===========================================================================
// 名字表
// ===========================================================================

const char* SessionStateName(SessionState state) noexcept {
    switch (state) {
    case SessionState::New:           return "New";
    case SessionState::Collecting:    return "Collecting";
    case SessionState::DisplayPaused: return "DisplayPaused";
    case SessionState::Stopped:       return "Stopped";
    case SessionState::Saved:         return "Saved";
    }
    return "New";
}

bool SessionAcceptsNewEvents(SessionState state) noexcept {
    switch (state) {
    case SessionState::Collecting:
    // T-01：暂停的是显示，不是采集。后台仍然记录 —— 既有实现在这里 return 掉事件，
    // 那才是"停止采集且静默丢事件"。
    case SessionState::DisplayPaused:
        return true;
    case SessionState::New:
    case SessionState::Stopped:
    case SessionState::Saved:
        return false;
    }
    return false;
}

bool SessionUpdatesDisplay(SessionState state) noexcept {
    switch (state) {
    case SessionState::Collecting:
        return true;
    case SessionState::New:
    case SessionState::DisplayPaused:
    case SessionState::Stopped:
    case SessionState::Saved:
        return false;
    }
    return false;
}

const char* SessionActionName(SessionAction action) noexcept {
    switch (action) {
    case SessionAction::Start:          return "Start";
    case SessionAction::PauseDisplay:   return "PauseDisplay";
    case SessionAction::ResumeDisplay:  return "ResumeDisplay";
    case SessionAction::StopCollection: return "StopCollection";
    case SessionAction::Save:           return "Save";
    case SessionAction::Reset:          return "Reset";
    }
    return "Start";
}

const char* TimelineEventCategoryName(TimelineEventCategory category) noexcept {
    switch (category) {
    case TimelineEventCategory::Process:  return "Process";
    case TimelineEventCategory::Thread:   return "Thread";
    case TimelineEventCategory::Image:    return "Image";
    case TimelineEventCategory::File:     return "File";
    case TimelineEventCategory::Registry: return "Registry";
    case TimelineEventCategory::Network:  return "Network";
    case TimelineEventCategory::Other:    return "Other";
    }
    return "Other";
}

const char* EventParseOutcomeName(EventParseOutcome outcome) noexcept {
    switch (outcome) {
    case EventParseOutcome::Parsed:                return "Parsed";
    case EventParseOutcome::UnparsedUnknownSchema: return "UnparsedUnknownSchema";
    case EventParseOutcome::Malformed:             return "Malformed";
    }
    return "UnparsedUnknownSchema";
}

const char* TimeResolutionName(TimeResolution resolution) noexcept {
    switch (resolution) {
    case TimeResolution::Unknown:           return "Unknown";
    case TimeResolution::Second:            return "Second";
    case TimeResolution::Millisecond:       return "Millisecond";
    case TimeResolution::Microsecond:       return "Microsecond";
    case TimeResolution::HundredNanosecond: return "HundredNanosecond";
    }
    return "Unknown";
}

std::uint64_t ResolutionSpan100ns(TimeResolution resolution) noexcept {
    switch (resolution) {
    case TimeResolution::Unknown:           return 0ULL;
    case TimeResolution::Second:            return 10000000ULL;
    case TimeResolution::Millisecond:       return 10000ULL;
    case TimeResolution::Microsecond:       return 10ULL;
    case TimeResolution::HundredNanosecond: return 1ULL;
    }
    return 0ULL;
}

const char* TimeComparisonName(TimeComparison comparison) noexcept {
    switch (comparison) {
    case TimeComparison::Comparable:              return "Comparable";
    case TimeComparison::ComparableButUncertain:  return "ComparableButUncertain";
    case TimeComparison::IncomparableCrossBoot:   return "IncomparableCrossBoot";
    case TimeComparison::IncomparableUnknownTime: return "IncomparableUnknownTime";
    case TimeComparison::IncomparableMagnitude:   return "IncomparableMagnitude";
    }
    return "IncomparableUnknownTime";
}

const char* AttributionKindName(AttributionKind kind) noexcept {
    switch (kind) {
    case AttributionKind::BoundToInstance:   return "BoundToInstance";
    case AttributionKind::Provisional:       return "Provisional";
    case AttributionKind::AfterInstanceExit: return "AfterInstanceExit";
    case AttributionKind::Ambiguous:         return "Ambiguous";
    case AttributionKind::UnknownProcess:    return "UnknownProcess";
    }
    return "UnknownProcess";
}

const char* LossCategoryName(LossCategory category) noexcept {
    switch (category) {
    case LossCategory::SourceDrop:       return "SourceDrop";
    case LossCategory::RingOverwrite:    return "RingOverwrite";
    case LossCategory::QueueDiscard:     return "QueueDiscard";
    case LossCategory::ParseFailure:     return "ParseFailure";
    case LossCategory::FilteredOut:      return "FilteredOut";
    case LossCategory::RetentionEvicted: return "RetentionEvicted";
    }
    return "SourceDrop";
}

LossCategory LossCategoryAt(std::size_t index) noexcept {
    switch (index) {
    case 0: return LossCategory::SourceDrop;
    case 1: return LossCategory::RingOverwrite;
    case 2: return LossCategory::QueueDiscard;
    case 3: return LossCategory::ParseFailure;
    case 4: return LossCategory::FilteredOut;
    default: return LossCategory::RetentionEvicted;
    }
}

const char* FilterStageName(FilterStage stage) noexcept {
    switch (stage) {
    case FilterStage::Collection: return "Collection";
    case FilterStage::Display:    return "Display";
    }
    return "Collection";
}

const char* ExportScopeName(ExportScope scope) noexcept {
    switch (scope) {
    case ExportScope::VisibleOnly: return "VisibleOnly";
    case ExportScope::FullSession: return "FullSession";
    }
    return "VisibleOnly";
}

const char* RetentionPolicyName(RetentionPolicy policy) noexcept {
    switch (policy) {
    case RetentionPolicy::StopOnLimit: return "StopOnLimit";
    case RetentionPolicy::EvictOldest: return "EvictOldest";
    }
    return "StopOnLimit";
}

const char* BoundsStateName(BoundsState state) noexcept {
    switch (state) {
    case BoundsState::WithinLimits:        return "WithinLimits";
    case BoundsState::MemoryLimitReached:  return "MemoryLimitReached";
    case BoundsState::ArchiveLimitReached: return "ArchiveLimitReached";
    }
    return "WithinLimits";
}

const char* TimelineEdgeKindName(TimelineEdgeKind kind) noexcept {
    switch (kind) {
    case TimelineEdgeKind::SameProcess:        return "SameProcess";
    case TimelineEdgeKind::ParentChild:        return "ParentChild";
    case TimelineEdgeKind::TemporalNeighbor:   return "TemporalNeighbor";
    case TimelineEdgeKind::SourceProvidedLink: return "SourceProvidedLink";
    }
    return "TemporalNeighbor";
}

bool EdgeKindAllowsCausalWording(TimelineEdgeKind kind) noexcept {
    switch (kind) {
    // T-12：只有来源自己给出的关联才允许因果措辞。
    case TimelineEdgeKind::SourceProvidedLink:
        return true;
    // 同进程只说明"同一个执行体"，父子只说明创建关系，相邻只说明"挨着发生"。
    // 三者都不能推出"A 导致 B"。
    case TimelineEdgeKind::SameProcess:
    case TimelineEdgeKind::ParentChild:
    case TimelineEdgeKind::TemporalNeighbor:
        return false;
    }
    return false;
}

const char* SessionLoadStatusName(SessionLoadStatus status) noexcept {
    switch (status) {
    case SessionLoadStatus::Ok:              return "Ok";
    case SessionLoadStatus::Empty:           return "Empty";
    case SessionLoadStatus::MissingHeader:   return "MissingHeader";
    case SessionLoadStatus::VersionTooNew:   return "VersionTooNew";
    case SessionLoadStatus::IncompleteTail:  return "IncompleteTail";
    case SessionLoadStatus::Corrupt:         return "Corrupt";
    case SessionLoadStatus::TrailerMismatch: return "TrailerMismatch";
    }
    return "Empty";
}

// ===========================================================================
// T-01 转移表
// ===========================================================================

SessionTransition EvaluateSessionTransition(SessionState current, SessionAction action) {
    switch (current) {
    case SessionState::New:
        switch (action) {
        case SessionAction::Start:          return MakeAllowed(SessionState::Collecting);
        case SessionAction::Reset:          return MakeAllowed(SessionState::New);
        case SessionAction::PauseDisplay:
        case SessionAction::ResumeDisplay:
        case SessionAction::StopCollection: return MakeRejected(current, "timeline.session.not-collecting");
        case SessionAction::Save:           return MakeRejected(current, "timeline.session.nothing-to-save");
        }
        break;
    case SessionState::Collecting:
        switch (action) {
        // T-01：暂停显示不改变"后台是否在记录"。
        case SessionAction::PauseDisplay:   return MakeAllowed(SessionState::DisplayPaused);
        // T-01：停止采集是**另一个**动作，且是唯一让后台停记的动作。
        case SessionAction::StopCollection: return MakeAllowed(SessionState::Stopped);
        case SessionAction::Start:          return MakeRejected(current, "timeline.session.already-collecting");
        case SessionAction::ResumeDisplay:  return MakeRejected(current, "timeline.session.display-not-paused");
        // 边界必须确定才能保存：采集中保存会写出一个说不清截止点的会话。
        case SessionAction::Save:           return MakeRejected(current, "timeline.session.stop-before-save");
        case SessionAction::Reset:          return MakeRejected(current, "timeline.session.stop-before-reset");
        }
        break;
    case SessionState::DisplayPaused:
        switch (action) {
        case SessionAction::ResumeDisplay:  return MakeAllowed(SessionState::Collecting);
        // 暂停中直接停止采集是合法的 —— 这正是"两个按钮"的意义。
        case SessionAction::StopCollection: return MakeAllowed(SessionState::Stopped);
        case SessionAction::Start:          return MakeRejected(current, "timeline.session.already-collecting");
        case SessionAction::PauseDisplay:   return MakeRejected(current, "timeline.session.already-paused");
        case SessionAction::Save:           return MakeRejected(current, "timeline.session.stop-before-save");
        case SessionAction::Reset:          return MakeRejected(current, "timeline.session.stop-before-reset");
        }
        break;
    case SessionState::Stopped:
        switch (action) {
        case SessionAction::Save:           return MakeAllowed(SessionState::Saved);
        case SessionAction::Reset:          return MakeAllowed(SessionState::New);
        // 停止后不得续采：续采会让同一个会话里出现两段说不清边界的记录。
        case SessionAction::Start:          return MakeRejected(current, "timeline.session.restart-requires-new-session");
        case SessionAction::PauseDisplay:
        case SessionAction::ResumeDisplay:
        case SessionAction::StopCollection: return MakeRejected(current, "timeline.session.already-stopped");
        }
        break;
    case SessionState::Saved:
        switch (action) {
        case SessionAction::Save:           return MakeAllowed(SessionState::Saved);
        case SessionAction::Reset:          return MakeAllowed(SessionState::New);
        case SessionAction::Start:          return MakeRejected(current, "timeline.session.restart-requires-new-session");
        case SessionAction::PauseDisplay:
        case SessionAction::ResumeDisplay:
        case SessionAction::StopCollection: return MakeRejected(current, "timeline.session.already-stopped");
        }
        break;
    }
    return MakeRejected(current, "timeline.session.unsupported-action");
}

// ===========================================================================
// T-04 时间
// ===========================================================================

OptionalU64 EventTimeStamp::effectiveTime100ns() const noexcept {
    if (!sourceTime100ns.present) {
        // 源时间缺失才退化到接收时间；校准是针对源时钟的，这条路径上不叠加。
        return receiveTime100ns;
    }
    if (!calibrationAvailable || calibrationOffset100ns == 0) {
        return sourceTime100ns;
    }
    const std::uint64_t base = sourceTime100ns.value;
    const std::uint64_t delta = AbsToU64(calibrationOffset100ns);
    if (calibrationOffset100ns > 0) {
        const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max();
        return OptionalU64::of(base > limit - delta ? limit : base + delta);
    }
    return OptionalU64::of(base < delta ? 0ULL : base - delta);
}

bool EventTimeStamp::effectiveFromReceiveTime() const noexcept {
    return !sourceTime100ns.present && receiveTime100ns.present;
}

TimeComparisonResult CompareEventTimes(const EventTimeStamp& earlier,
                                       const EventTimeStamp& later) noexcept {
    TimeComparisonResult result;
    result.calibrationChanged = earlier.calibrationId != later.calibrationId;

    const OptionalU64 a = earlier.effectiveTime100ns();
    const OptionalU64 b = later.effectiveTime100ns();
    if (!a.present || !b.present) {
        result.kind = TimeComparison::IncomparableUnknownTime;
        return result;
    }
    // 启动周期未知同样不可比：没有 bootId 就无法证明两个时间戳出自同一时钟纪元。
    if (earlier.bootId.empty() || later.bootId.empty() || earlier.bootId != later.bootId) {
        result.kind = TimeComparison::IncomparableCrossBoot;
        return result;
    }

    // 有符号路径。无符号相减一旦回绕就会把 1ms 的回拨报成天文数字（X 模块实测过）。
    const bool reversed = b.value < a.value;
    const std::uint64_t magnitude = reversed ? (a.value - b.value) : (b.value - a.value);
    result.regression = reversed;
    if (magnitude > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) {
        result.kind = TimeComparison::IncomparableMagnitude;
        result.delta100ns = 0;
        return result;
    }
    const std::int64_t signedMagnitude = static_cast<std::int64_t>(magnitude);
    result.delta100ns = reversed ? -signedMagnitude : signedMagnitude;

    // 精度未知时不敢宣称顺序可分辨；跨源严格全序本来就不存在。
    if (earlier.sourceResolution == TimeResolution::Unknown ||
        later.sourceResolution == TimeResolution::Unknown) {
        result.kind = TimeComparison::ComparableButUncertain;
        return result;
    }
    const std::uint64_t span = std::max(ResolutionSpan100ns(earlier.sourceResolution),
                                        ResolutionSpan100ns(later.sourceResolution));
    if (magnitude == 0ULL || magnitude < span) {
        result.kind = TimeComparison::ComparableButUncertain;
        return result;
    }
    // 校准换过一次的两个时间落在同一坐标系的证据不足，顺序只能说"不确定"。
    if (result.calibrationChanged) {
        result.kind = TimeComparison::ComparableButUncertain;
        return result;
    }
    result.kind = TimeComparison::Comparable;
    return result;
}

bool SortKeyLess(const TimelineSortKey& a, const TimelineSortKey& b) noexcept {
    if (a.bootEpochRank != b.bootEpochRank) {
        return a.bootEpochRank < b.bootEpochRank;
    }
    if (a.timeKnown != b.timeKnown) {
        // 时间未知的排在时间已知的之后，而不是被当成 0 顶到最前面。
        return a.timeKnown;
    }
    if (a.timeKnown && a.effectiveTime100ns != b.effectiveTime100ns) {
        return a.effectiveTime100ns < b.effectiveTime100ns;
    }
    if (a.arrivalSequence != b.arrivalSequence) {
        return a.arrivalSequence < b.arrivalSequence;
    }
    if (a.sourceGroup != b.sourceGroup) {
        return a.sourceGroup < b.sourceGroup;
    }
    return a.recordId < b.recordId;
}

// ===========================================================================
// T-05 进程归属
// ===========================================================================

bool ProcessInstanceLedger::observeStart(const ProcessInstanceId& identity,
                                         std::uint64_t startTime100ns) {
    if (identity.bootId.empty() || !identity.pid.present) {
        return false;  // 连启动周期和 PID 都没有，登记了也无法用于归属
    }
    for (InstanceRecord& record : instances_) {
        if (record.identity.bootId != identity.bootId || record.identity.pid != identity.pid ||
            record.startTime100ns != startTime100ns) {
            continue;
        }
        // 同 bootId/pid/开始时间但 createTime 不同 —— 是两个实例，不能合并成一个。
        if (identity.createTime100ns.present && record.identity.createTime100ns.present &&
            identity.createTime100ns.value != record.identity.createTime100ns.value) {
            continue;
        }
        record.identity = identity;  // 补齐 createTime/imageName 一类信息
        return true;
    }
    InstanceRecord record;
    record.identity = identity;
    record.startTime100ns = startTime100ns;
    instances_.push_back(std::move(record));
    return true;
}

bool ProcessInstanceLedger::observeExit(const ProcessInstanceId& identity,
                                        std::uint64_t exitTime100ns) {
    if (identity.bootId.empty() || !identity.pid.present) {
        return false;
    }
    // T-05：createTime 在场就必须精确对上。只按 (bootId,pid,"开始时间最晚") 挑候选，
    // A 的迟到退出事件会被记到 B 头上：A 从此没有结束时间（窗口无限延长），B 被判成
    // 已结束。之后 t 落在 B 窗口里的事件因为两个窗口重叠而变成 Ambiguous，t 在 B 之后
    // 的事件又被当成"B 已退出"，两边都错。
    const bool haveCreateTime = identity.createTime100ns.present;
    InstanceRecord* best = nullptr;
    for (InstanceRecord& record : instances_) {
        if (record.identity.bootId != identity.bootId || record.identity.pid != identity.pid) {
            continue;
        }
        if (record.exitKnown || record.startTime100ns > exitTime100ns) {
            continue;
        }
        if (haveCreateTime) {
            if (!record.identity.createTime100ns.present ||
                record.identity.createTime100ns.value != identity.createTime100ns.value) {
                continue;  // 身份对不上就不是这个实例；宁可丢掉这次退出，也不错挂
            }
            best = &record;
            break;
        }
        if (best == nullptr || record.startTime100ns > best->startTime100ns) {
            best = &record;
        }
    }
    if (best == nullptr) {
        return false;  // 不凭空造一个"已结束"实例；调用方据此记一次未匹配退出
    }
    best->exitKnown = true;
    best->exitTime100ns = exitTime100ns;
    if (!haveCreateTime) {
        // 没有 createTime，这次匹配是靠开始时间猜的 —— 单独计数，不假装是确定的。
        ++weakExitMatchCount_;
    }
    return true;
}

std::string MakeProvisionalEntityId(const std::string& bootId,
                                    const OptionalU64& pid,
                                    AttributionKind originKind) {
    // 长度前缀让编码是单射的：空 bootId 与字面量 "boot-unknown" 不再折叠成同一个实体，
    // bootId 里含 ":pid=" 也不会把两个不同的启动周期撞到一起。
    std::string id("prov:b");
    id.append(FormatU64(static_cast<std::uint64_t>(bootId.size()), U64Format::Decimal));
    id.push_back(':');
    id.append(bootId);
    id.append(":pid=");
    id.append(pid.present ? FormatU64(pid.value, U64Format::Decimal) : std::string("unknown"));
    id.push_back(':');
    id.append(AttributionKindName(originKind));
    return id;
}

ProvisionalProcessEntity& ProcessInstanceLedger::touchProvisional(const std::string& bootId,
                                                                  const OptionalU64& pid,
                                                                  const OptionalU64& time,
                                                                  AttributionKind originKind) {
    const std::string id = MakeProvisionalEntityId(bootId, pid, originKind);

    const auto found = provisionalIndex_.find(id);
    if (found != provisionalIndex_.end() && found->second < provisionals_.size()) {
        ProvisionalProcessEntity& entity = provisionals_[found->second];
        ++entity.eventCount;
        if (time.present) {
            if (!entity.firstSeenTime100ns.present || time.value < entity.firstSeenTime100ns.value) {
                entity.firstSeenTime100ns = time;
            }
            if (!entity.lastSeenTime100ns.present || time.value > entity.lastSeenTime100ns.value) {
                entity.lastSeenTime100ns = time;
            }
        }
        return entity;
    }
    ProvisionalProcessEntity entity;
    entity.provisionalId = id;
    entity.bootId = bootId;
    entity.pid = pid;
    entity.firstSeenTime100ns = time;
    entity.lastSeenTime100ns = time;
    entity.eventCount = 1U;
    entity.originKind = originKind;
    entity.identityComplete = false;  // T-05：临时实体永远是"身份不完整"
    provisionalIndex_.emplace(id, provisionals_.size());
    provisionals_.push_back(std::move(entity));
    return provisionals_.back();
}

AttributionDecision ProcessInstanceLedger::attribute(const std::string& bootId,
                                                     const OptionalU64& pid,
                                                     const EventTimeStamp& time) {
    AttributionDecision decision;
    if (!pid.present) {
        decision.kind = AttributionKind::UnknownProcess;
        decision.reasonKey = "timeline.attribution.no-pid";
        return decision;
    }

    const OptionalU64 effective = time.effectiveTime100ns();
    if (bootId.empty()) {
        // 没有启动周期就无法把 PID 定位到某一次启动，绝不猜"当前那个"。
        decision.kind = AttributionKind::Provisional;
        decision.reasonKey = "timeline.attribution.no-boot-id";
        decision.provisionalId =
            touchProvisional(bootId, pid, effective, AttributionKind::Provisional).provisionalId;
        return decision;
    }
    if (!effective.present) {
        decision.kind = AttributionKind::Provisional;
        decision.reasonKey = "timeline.attribution.no-time";
        decision.provisionalId =
            touchProvisional(bootId, pid, effective, AttributionKind::Provisional).provisionalId;
        return decision;
    }

    const std::uint64_t t = effective.value;
    const InstanceRecord* covering = nullptr;
    std::size_t coveringCount = 0;
    bool sawEndedBefore = false;
    for (const InstanceRecord& record : instances_) {
        if (record.identity.bootId != bootId || record.identity.pid != pid) {
            continue;
        }
        if (record.startTime100ns <= t && (!record.exitKnown || t <= record.exitTime100ns)) {
            covering = &record;
            ++coveringCount;
            continue;
        }
        if (record.exitKnown && record.exitTime100ns < t) {
            sawEndedBefore = true;
        }
    }

    if (coveringCount == 1U && covering != nullptr) {
        decision.kind = AttributionKind::BoundToInstance;
        decision.instance = covering->identity;
        decision.identityStrength = covering->identity.strength();
        // F-03 统一门槛：身份不够强只能给 Candidate，不能因为"窗口对上了"就升级。
        decision.identityMatch = decision.identityStrength == IdentityStrength::Strong
                                     ? MatchResult::Confirmed
                                     : MatchResult::Candidate;
        decision.reasonKey = "timeline.attribution.instance-window-match";
        return decision;
    }
    if (coveringCount > 1U) {
        decision.kind = AttributionKind::Ambiguous;
        decision.reasonKey = "timeline.attribution.overlapping-instances";
        decision.provisionalId =
            touchProvisional(bootId, pid, effective, AttributionKind::Ambiguous).provisionalId;
        return decision;
    }
    if (sawEndedBefore) {
        // T-05：目标已结束后的迟到事件。绝不改挂给同 PID 的下一个实例。
        decision.kind = AttributionKind::AfterInstanceExit;
        decision.reasonKey = "timeline.attribution.after-known-exit";
        decision.provisionalId =
            touchProvisional(bootId, pid, effective, AttributionKind::AfterInstanceExit).provisionalId;
        return decision;
    }
    // T-05：缺进程开始事件 —— 建立身份不完整的临时实体，而不是归给当前同 PID 进程。
    decision.kind = AttributionKind::Provisional;
    decision.reasonKey = "timeline.attribution.missing-start-event";
    decision.provisionalId =
        touchProvisional(bootId, pid, effective, AttributionKind::Provisional).provisionalId;
    return decision;
}

bool ProcessInstanceLedger::confirmProvisional(const std::string& provisionalId,
                                               const ProcessInstanceId& identity,
                                               std::string noteKey) {
    for (ProvisionalProcessEntity& entity : provisionals_) {
        if (entity.provisionalId != provisionalId) {
            continue;
        }
        const std::string key = identity.crossSessionKey();
        if (key.empty()) {
            // 补来的证据本身身份不足（缺 createTime/bootId）。记下这次尝试，
            // 但绝不把临时实体标成"已补齐"—— 那是拿弱证据冒充确认。
            entity.resolutionNoteKey = "timeline.provisional.resolve-rejected-weak-identity";
            return false;
        }
        entity.identityComplete = true;
        entity.resolvedInstanceKey = key;
        entity.resolutionNoteKey = std::move(noteKey);
        return true;
    }
    return false;
}

const ProvisionalProcessEntity* ProcessInstanceLedger::findProvisional(
    const std::string& provisionalId) const noexcept {
    for (const ProvisionalProcessEntity& entity : provisionals_) {
        if (entity.provisionalId == provisionalId) {
            return &entity;
        }
    }
    return nullptr;
}

// ===========================================================================
// T-06 丢失账目
// ===========================================================================

bool LossLedger::declareSource(LossCategory category,
                               std::string statisticSource,
                               bool sourceIsAuthoritative,
                               bool intervalSupported) {
    if (statisticSource.empty()) {
        return false;  // T-06："0 也有可解释的统计来源"，来源不许是空串
    }
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (!counter.statisticSource.empty()) {
        // 换来源等于换了一套口径，旧计数不能直接沿用 —— 拒绝，避免两套口径叠加。
        return counter.statisticSource == statisticSource &&
               counter.sourceIsAuthoritative == sourceIsAuthoritative &&
               counter.intervalSupported == intervalSupported;
    }
    counter.statisticSource = std::move(statisticSource);
    counter.sourceIsAuthoritative = sourceIsAuthoritative;
    counter.intervalSupported = intervalSupported;
    if (!sourceIsAuthoritative) {
        // 本地口径从 0 起算，且这个 0 是有来源的。
        counter.count = OptionalU64::of(0ULL);
    }
    // 来源权威的类别在来源真正报数之前保持"未知"，不预设成 0。
    return true;
}

bool LossLedger::setAbsolute(LossCategory category, std::uint64_t count) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || !counter.sourceIsAuthoritative) {
        return false;  // 本地口径不许被绝对值覆盖，否则本地自增会被抹掉或重复
    }
    counter.count = OptionalU64::of(count);
    return true;
}

bool LossLedger::addObserved(LossCategory category, std::uint64_t delta) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || counter.sourceIsAuthoritative) {
        // 来源已经给了绝对值，本地再自增就是把同一批丢失数两遍。
        return false;
    }
    counter.count = OptionalU64::of(SaturatingAddU64(counter.count.valueOr(0ULL), delta));
    return true;
}

bool LossLedger::setInterval(LossCategory category, std::uint64_t begin100ns, std::uint64_t end100ns) {
    LossCounter& counter = counters_[static_cast<std::size_t>(category)];
    if (counter.statisticSource.empty() || !counter.intervalSupported) {
        // T-06：来源只报总计时不得编造精确丢失区间。
        return false;
    }
    if (begin100ns > end100ns) {
        return false;
    }
    counter.intervalBegin100ns = OptionalU64::of(begin100ns);
    counter.intervalEnd100ns = OptionalU64::of(end100ns);
    return true;
}

const LossCounter& LossLedger::counter(LossCategory category) const noexcept {
    return counters_[static_cast<std::size_t>(category)];
}

LossCounter& LossLedger::mutableCounter(LossCategory category) noexcept {
    return counters_[static_cast<std::size_t>(category)];
}

bool LossLedger::anyUnknown() const noexcept {
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        if (counters_[i].statisticSource.empty() || !counters_[i].count.present) {
            return true;
        }
    }
    return false;
}

OptionalU64 LossLedger::totalLost() const noexcept {
    std::uint64_t total = 0;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        if (!counters_[i].count.present) {
            // 把未知当 0 相加会把部分轨迹说成完整轨迹。
            return OptionalU64::unset();
        }
        total = SaturatingAddU64(total, counters_[i].count.value);
    }
    return OptionalU64::of(total);
}

std::vector<std::string> LossLedger::limitationKeys() const {
    std::vector<std::string> keys;
    bool anyPositive = false;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        const LossCategory category = LossCategoryAt(i);
        const LossCounter& counter = counters_[i];
        if (counter.statisticSource.empty()) {
            keys.push_back(std::string("timeline.loss.no-source.") + LossCategoryName(category));
            continue;
        }
        if (!counter.count.present) {
            keys.push_back(std::string("timeline.loss.unknown-count.") + LossCategoryName(category));
            continue;
        }
        if (counter.count.value != 0ULL) {
            anyPositive = true;
            if (!counter.intervalSupported) {
                keys.push_back(std::string("timeline.loss.total-only.") + LossCategoryName(category));
            }
        }
    }
    if (keys.empty() && !anyPositive) {
        // 六类都有具名来源且都是 0 —— 这是正面陈述，不是"默认没事"。
        keys.push_back("timeline.loss.none-all-categories-sourced");
    }
    return keys;
}

// ===========================================================================
// T-03 过滤
// ===========================================================================

bool FilterAdmits(const EventFilter& filter, const TimelineEvent& event) noexcept {
    if (!filter.active) {
        return true;
    }
    if (!filter.allowedPids.empty()) {
        if (!event.pid.present || !ContainsPid(filter.allowedPids, event.pid.value)) {
            return false;
        }
    }
    if (!filter.allowedCategories.empty()) {
        if (std::find(filter.allowedCategories.begin(), filter.allowedCategories.end(),
                      event.category) == filter.allowedCategories.end()) {
            return false;
        }
    }
    if (!filter.allowedProviderIds.empty()) {
        if (std::find(filter.allowedProviderIds.begin(), filter.allowedProviderIds.end(),
                      event.providerId) == filter.allowedProviderIds.end()) {
            return false;
        }
    }
    return true;
}

// ===========================================================================
// T-02 解析
// ===========================================================================

void EventSchemaRegistry::add(EventSchema schema) {
    for (EventSchema& existing : schemas_) {
        if (existing.providerId == schema.providerId && existing.eventId == schema.eventId &&
            existing.version == schema.version) {
            existing = std::move(schema);
            return;
        }
    }
    schemas_.push_back(std::move(schema));
}

const EventSchema* EventSchemaRegistry::findExact(const std::string& providerId,
                                                  std::uint32_t eventId,
                                                  std::uint32_t version) const noexcept {
    for (const EventSchema& schema : schemas_) {
        if (schema.providerId == providerId && schema.eventId == eventId &&
            schema.version == version) {
            return &schema;
        }
    }
    // T-02：没有"退到最近的低版本"这条分支。未知版本就是未知版本。
    return nullptr;
}

bool EventSchemaRegistry::knowsProviderEvent(const std::string& providerId,
                                             std::uint32_t eventId) const noexcept {
    for (const EventSchema& schema : schemas_) {
        if (schema.providerId == providerId && schema.eventId == eventId) {
            return true;
        }
    }
    return false;
}

EventParseReport ParseEventPayload(const EventSchemaRegistry& registry,
                                   const EventParseRequest& request) {
    EventParseReport report;
    if (request.payloadTruncated) {
        report.outcome = EventParseOutcome::Malformed;
        report.reasonKey = "timeline.parse.payload-truncated";
        return report;
    }

    const EventSchema* schema = registry.findExact(request.providerId, request.eventId, request.version);
    if (schema == nullptr) {
        report.outcome = EventParseOutcome::UnparsedUnknownSchema;
        report.reasonKey = registry.knowsProviderEvent(request.providerId, request.eventId)
                               ? "timeline.parse.unknown-event-version"
                               : "timeline.parse.unknown-provider-event";
        // 未解析记录：解析器身份保持空/0，绝不填一个"差不多的"版本号。
        report.parserId.clear();
        report.parserVersion = 0U;
        report.category = TimelineEventCategory::Other;
        return report;
    }

    report.parserId = schema->parserId;
    report.parserVersion = schema->parserVersion;
    report.category = schema->category;
    for (const std::string& required : schema->requiredFields) {
        bool found = false;
        for (const auto& field : request.rawFields) {
            if (field.first == required) {
                found = true;
                break;
            }
        }
        if (!found) {
            report.missingRequiredFields.push_back(required);
        }
    }
    if (!report.missingRequiredFields.empty()) {
        report.outcome = EventParseOutcome::Malformed;
        report.reasonKey = "timeline.parse.missing-required-field";
        return report;
    }
    report.outcome = EventParseOutcome::Parsed;
    report.reasonKey = "timeline.parse.ok";
    return report;
}

void ApplyParseReport(TimelineEvent& event, const EventParseReport& report) {
    event.parseOutcome = report.outcome;
    event.parserId = report.parserId;
    event.parserVersion = report.parserVersion;
    event.parseReasonKey = report.reasonKey;
    // 只有真的选中了解析器才允许改写分类；未知 schema 不许反推类别。
    if (!report.parserId.empty()) {
        event.category = report.category;
    }
    // rawFields / rawPayloadHex 一律保留：未解析记录的价值就在原始数据上。
}

// ===========================================================================
// T-12 关系边
// ===========================================================================

namespace {

TimelineEdge MakeEdge(TimelineEdgeKind kind,
                      const TimelineEvent& from,
                      const TimelineEvent& to,
                      const char* basisKey,
                      std::string basisDetail) {
    TimelineEdge edge;
    edge.kind = kind;
    edge.fromRecordId = from.recordId;
    edge.toRecordId = to.recordId;
    edge.basisKey = basisKey;
    edge.basisDetail = std::move(basisDetail);
    return edge;
}

inline constexpr std::size_t kNoIndex = static_cast<std::size_t>(-1);

// 对每条事件求出"下一条同键事件的下标"。一次 O(n) 的哈希扫描替掉原来的内层线性查找：
// 键互不相同（忙机器上的常态）时，原实现每条事件都要扫到数组末尾，n=16000 就要 400 ms
// 且一条边都产生不了 —— 纯粹白扫。倒着走一遍即可，边的产生顺序与原实现完全一致。
std::vector<std::size_t> NextWithSameKey(const std::vector<TimelineEvent>& events,
                                         std::string TimelineEvent::*member) {
    std::vector<std::size_t> next(events.size(), kNoIndex);
    std::unordered_map<std::string, std::size_t> seen;
    seen.reserve(events.size() * 2U);
    for (std::size_t i = events.size(); i-- > 0;) {
        const std::string& key = events[i].*member;
        if (key.empty()) {
            continue;
        }
        const auto found = seen.find(key);
        if (found != seen.end()) {
            next[i] = found->second;
        }
        seen[key] = i;
    }
    return next;
}

// 首次出现的下标表。ParentChild 原来对每条事实都全表扫描一遍（而且找齐两端后也不退出），
// 是 O(facts x events)；这里换成一次建表。"首次出现"的取值语义与原实现一致。
std::unordered_map<std::string, std::size_t> FirstIndexByKey(
    const std::vector<TimelineEvent>& events,
    std::string TimelineEvent::*member) {
    std::unordered_map<std::string, std::size_t> index;
    index.reserve(events.size() * 2U);
    for (std::size_t i = 0; i < events.size(); ++i) {
        const std::string& key = events[i].*member;
        if (key.empty()) {
            continue;
        }
        index.emplace(key, i);  // emplace 不覆盖已有项 -> 保留第一次出现
    }
    return index;
}

} // namespace

std::vector<TimelineEdge> BuildEdges(const std::vector<TimelineEvent>& events,
                                     const std::vector<ParentChildFact>& parentFacts,
                                     const EdgeBuildOptions& options) {
    std::vector<TimelineEdge> edges;

    // ---- SameProcess：只认已确认的实例主键。仅凭裸 PID 不建边（PID 会复用）。----
    if (options.includeSameProcess) {
        const std::vector<std::size_t> next =
            NextWithSameKey(events, &TimelineEvent::processInstanceKey);
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (next[i] == kNoIndex) {
                continue;  // 只连到下一条同实例事件，避免 O(n^2) 边爆炸
            }
            edges.push_back(MakeEdge(TimelineEdgeKind::SameProcess, events[i], events[next[i]],
                                     "timeline.edge.basis.same-process-instance",
                                     events[i].processInstanceKey));
        }
    }

    // ---- ParentChild：依据必须能点开，因此要求父实例在会话里真有事件 ----
    if (options.includeParentChild) {
        const std::unordered_map<std::string, std::size_t> byInstance =
            FirstIndexByKey(events, &TimelineEvent::processInstanceKey);
        const std::unordered_map<std::string, std::size_t> byRecordId =
            FirstIndexByKey(events, &TimelineEvent::recordId);
        for (const ParentChildFact& fact : parentFacts) {
            if (fact.recordId.empty() || fact.parentInstanceKey.empty() ||
                fact.childInstanceKey.empty()) {
                continue;
            }
            const auto parentIt = byInstance.find(fact.parentInstanceKey);
            const auto childIt = byRecordId.find(fact.recordId);
            if (parentIt == byInstance.end() || childIt == byRecordId.end()) {
                continue;  // 没有可回溯的依据就不建边
            }
            edges.push_back(MakeEdge(TimelineEdgeKind::ParentChild, events[parentIt->second],
                                     events[childIt->second],
                                     "timeline.edge.basis.parent-child-from-create-event",
                                     fact.parentInstanceKey));
        }
    }

    // ---- SourceProvidedLink：唯一允许因果措辞的边 ----
    if (options.includeSourceProvidedLink) {
        const std::vector<std::size_t> next = NextWithSameKey(events, &TimelineEvent::sourceLinkId);
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (next[i] == kNoIndex) {
                continue;
            }
            std::string detail = events[i].sourceLinkField.empty()
                                     ? events[i].sourceLinkId
                                     : events[i].sourceLinkField + "=" + events[i].sourceLinkId;
            edges.push_back(MakeEdge(TimelineEdgeKind::SourceProvidedLink, events[i], events[next[i]],
                                     "timeline.edge.basis.source-provided-link",
                                     std::move(detail)));
        }
    }

    // ---- TemporalNeighbor：只有调用方明确给了窗口才产生 ----
    if (options.temporalNeighborWindow100ns.present) {
        std::vector<std::size_t> order;
        order.reserve(events.size());
        for (std::size_t i = 0; i < events.size(); ++i) {
            if (events[i].time.effectiveTime100ns().present) {
                order.push_back(i);
            }
        }
        std::sort(order.begin(), order.end(), [&events](std::size_t a, std::size_t b) {
            const std::uint64_t ta = events[a].time.effectiveTime100ns().value;
            const std::uint64_t tb = events[b].time.effectiveTime100ns().value;
            if (ta != tb) {
                return ta < tb;
            }
            if (events[a].arrivalSequence != events[b].arrivalSequence) {
                return events[a].arrivalSequence < events[b].arrivalSequence;
            }
            return events[a].recordId < events[b].recordId;
        });
        const std::uint64_t window = options.temporalNeighborWindow100ns.value;
        for (std::size_t k = 1; k < order.size(); ++k) {
            const TimelineEvent& previous = events[order[k - 1]];
            const TimelineEvent& current = events[order[k]];
            const TimeComparisonResult comparison = CompareEventTimes(previous.time, current.time);
            if (!comparison.comparable()) {
                continue;  // 跨启动周期或时间未知：不谈"相邻"
            }
            const std::uint64_t gap = AbsToU64(comparison.delta100ns);
            if (gap > window) {
                continue;
            }
            TimelineEdge edge = MakeEdge(TimelineEdgeKind::TemporalNeighbor, previous, current,
                                         // 措辞刻意写死："只是挨着发生"，不是"导致"。
                                         "timeline.edge.basis.adjacent-in-time-only",
                                         std::string());
            edge.temporalGap100ns = OptionalU64::of(gap);
            edge.orderUncertain = comparison.kind == TimeComparison::ComparableButUncertain;
            edges.push_back(std::move(edge));
        }
    }

    return edges;
}

// ===========================================================================
// 会话
// ===========================================================================

namespace {

// 一个不可用 collector 的说明键：谁、什么状态、本该供给哪几类事件。
// 类别写进键里，UI 才说得出"Registry 这一类根本没采到，不是系统里没有"。
std::string DescribeUnavailableCollector(const CollectorCapability& capability) {
    std::string key("timeline.export.collector-unavailable:");
    key.append(capability.collectorId.empty() ? std::string("unnamed-collector")
                                              : capability.collectorId);
    key.push_back(':');
    key.append(CollectionStatusName(capability.availability.status));
    key.push_back(':');
    if (capability.declaredCategories.empty()) {
        key.append("no-declared-category");
        return key;
    }
    for (std::size_t i = 0; i < capability.declaredCategories.size(); ++i) {
        if (i != 0U) {
            key.push_back('+');
        }
        key.append(TimelineEventCategoryName(capability.declaredCategories[i]));
    }
    return key;
}

} // namespace

TimelineSession::TimelineSession() {
    declareLocalLossSources();
}

TimelineSession::TimelineSession(SessionManifest manifest, BoundsPolicy bounds)
    : manifest_(std::move(manifest)), bounds_(std::move(bounds)) {
    declareLocalLossSources();
}

void TimelineSession::declareLocalLossSources() {
    // T-06："0 也必须有具名统计来源"。这四类丢失是**会话自己**产生的，来源只能是本层，
    // 因此由会话在构造时自己声明。以前要靠调用方先跑一遍 declareSource()，一旦忘记，
    // ingest() 里每一次 addObserved() 都返回 false，被过滤/淘汰/丢弃的条数彻底没有落点
    // ——"0 也有来源"这条判据就只是调用方的口头约定。
    loss_.declareSource(LossCategory::FilteredOut, "local.collectionFilter", false, false);
    loss_.declareSource(LossCategory::QueueDiscard, "local.r3queue", false, false);
    loss_.declareSource(LossCategory::ParseFailure, "local.parser", false, false);
    loss_.declareSource(LossCategory::RetentionEvicted, "local.retention", false, false);
    // SourceDrop / RingOverwrite 由采集器来源报数，会话无权替它们声明。
}

bool TimelineSession::recordLocalLoss(LossCategory category, std::uint64_t delta) {
    if (loss_.addObserved(category, delta)) {
        return true;
    }
    // 记不进去就是硬错误：把这一类打成"未知"，totalLost() 随之 unset。宁可整份账目
    // 判不出总数，也不能静默丢掉这一笔然后继续宣称"共丢失 0 条"。
    loss_.mutableCounter(category).count = OptionalU64::unset();
    lossAccountingFailed_ = true;
    return false;
}

std::uint32_t TimelineSession::registerBoot(const std::string& bootId) {
    for (std::size_t i = 0; i < bootEpochs_.size(); ++i) {
        if (bootEpochs_[i].bootId == bootId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    BootEpoch epoch;
    epoch.bootId = bootId;
    bootEpochs_.push_back(std::move(epoch));
    return static_cast<std::uint32_t>(bootEpochs_.size() - 1U);
}

std::uint32_t TimelineSession::bootRankOf(const std::string& bootId) const noexcept {
    for (std::size_t i = 0; i < bootEpochs_.size(); ++i) {
        if (bootEpochs_[i].bootId == bootId) {
            return static_cast<std::uint32_t>(i);
        }
    }
    return static_cast<std::uint32_t>(bootEpochs_.size());
}

SessionTransition TimelineSession::apply(SessionAction action) {
    SessionTransition transition = EvaluateSessionTransition(state_, action);
    if (transition.allowed && action == SessionAction::Start) {
        // T-08：上限与到限行为必须在采集前呈现过，否则不许开始。
        if (!bounds_.declaredBeforeCollection) {
            return MakeRejected(state_, "timeline.session.bounds-not-declared");
        }
        // 声明了磁盘上限却换算不出条数（缺 approximateBytesPerEvent 或它是 0），
        // 那个上限永远不会生效 —— 用户看到的是一个假的保证。实测：声明 4096 字节、
        // 不给单条估算值，50000 条全部留下，boundsState 还停在 WithinLimits，
        // 落盘 36 MB 是声明上限的 8932 倍。这里必须在采集前就拒掉。
        if (bounds_.maxArchiveBytes.present &&
            (!bounds_.approximateBytesPerEvent.present ||
             bounds_.approximateBytesPerEvent.value == 0ULL)) {
            return MakeRejected(state_, "timeline.session.archive-limit-unenforceable");
        }
        // T-08"内存有上限"：一条能真正换算成条数的上限都没有，就不是有界采集。
        if (!bounds_.maxEventsInMemory.present && !bounds_.maxArchiveBytes.present) {
            return MakeRejected(state_, "timeline.session.no-memory-bound");
        }
    }
    if (!transition.allowed) {
        return transition;
    }
    if (action == SessionAction::Reset) {
        events_.clear();
        recordIds_.clear();
        bootEpochs_.clear();
        loss_ = LossLedger();
        declareLocalLossSources();  // 重置后本地四类仍然必须有具名来源
        processes_ = ProcessInstanceLedger();
        loadIntegrity_ = SessionLoadIntegrity();
        boundsState_ = BoundsState::WithinLimits;
        nextSequence_ = 1U;
        filteredOutCount_ = 0U;
        lossAccountingFailed_ = false;
    }
    state_ = transition.nextState;
    return transition;
}

IngestResult TimelineSession::ingest(TimelineEvent event) {
    IngestResult result;
    result.bounds = boundsState_;

    // T-01：停止/保存后不得再记入新事件。
    if (!SessionAcceptsNewEvents(state_)) {
        result.accepted = false;
        result.reasonKey = "timeline.ingest.session-not-collecting";
        return result;
    }

    // recordId 是排序的最终 tiebreak、关系边的连接键、导出与恢复的主键。空或重复都会
    // 让这三件事各自指向不同的记录（sortedOrder 的不确定性复核就会拿错记录去比时间）。
    // 拒绝并按 R3 侧丢弃入账 —— 拒绝可以，静默吞掉不行。
    if (event.recordId.empty()) {
        result.accepted = false;
        result.lossCategory = LossCategory::QueueDiscard;
        result.reasonKey = "timeline.ingest.missing-record-id";
        result.countedAsLoss = recordLocalLoss(LossCategory::QueueDiscard, 1ULL);
        return result;
    }
    if (recordIds_.find(event.recordId) != recordIds_.end()) {
        result.accepted = false;
        result.lossCategory = LossCategory::QueueDiscard;
        result.reasonKey = "timeline.ingest.duplicate-record-id";
        result.countedAsLoss = recordLocalLoss(LossCategory::QueueDiscard, 1ULL);
        return result;
    }

    // T-03：采集过滤在这里生效；显示过滤在这里**不参与**任何判断。
    if (!FilterAdmits(collectionFilter_, event)) {
        ++filteredOutCount_;
        result.accepted = false;
        result.lossCategory = LossCategory::FilteredOut;
        result.reasonKey = "timeline.ingest.excluded-by-collection-filter";
        result.countedAsLoss = recordLocalLoss(LossCategory::FilteredOut, 1ULL);
        return result;
    }

    // T-08：有界。上限换算成条数；磁盘上限只有给了单条估算字节数才可换算。
    std::uint64_t capacity = std::numeric_limits<std::uint64_t>::max();
    bool archiveBound = false;
    if (bounds_.maxEventsInMemory.present) {
        capacity = bounds_.maxEventsInMemory.value;
    }
    if (bounds_.maxArchiveBytes.present && bounds_.approximateBytesPerEvent.present &&
        bounds_.approximateBytesPerEvent.value != 0ULL) {
        const std::uint64_t diskCapacity =
            bounds_.maxArchiveBytes.value / bounds_.approximateBytesPerEvent.value;
        if (diskCapacity <= capacity) {
            capacity = diskCapacity;
            archiveBound = true;
        }
    }

    if (capacity != std::numeric_limits<std::uint64_t>::max()) {
        const std::uint64_t retained = static_cast<std::uint64_t>(events_.size());
        if (capacity == 0ULL) {
            boundsState_ = archiveBound ? BoundsState::ArchiveLimitReached
                                        : BoundsState::MemoryLimitReached;
            result.bounds = boundsState_;
            result.accepted = false;
            result.lossCategory = LossCategory::QueueDiscard;
            result.reasonKey = "timeline.ingest.capacity-zero";
            result.countedAsLoss = recordLocalLoss(LossCategory::QueueDiscard, 1ULL);
            return result;
        }
        if (retained >= capacity) {
            boundsState_ = archiveBound ? BoundsState::ArchiveLimitReached
                                        : BoundsState::MemoryLimitReached;
            result.bounds = boundsState_;
            switch (bounds_.policy) {
            case RetentionPolicy::StopOnLimit:
                result.accepted = false;
                result.lossCategory = LossCategory::QueueDiscard;
                result.reasonKey = "timeline.ingest.limit-reached-stopped";
                result.countedAsLoss = recordLocalLoss(LossCategory::QueueDiscard, 1ULL);
                return result;
            case RetentionPolicy::EvictOldest:
                while (static_cast<std::uint64_t>(events_.size()) >= capacity && !events_.empty()) {
                    // O(1) 淘汰。原来是 vector::erase(begin())，每淘汰一条都要搬动整个
                    // 保留窗口（sizeof(TimelineEvent)=560B），10 万条上限下只有 ~186 次/秒。
                    recordIds_.erase(events_.front().recordId);
                    events_.pop_front();
                    result.evictedOldest = true;
                    // 淘汰记在 RetentionEvicted，与队列丢弃是两类，绝不合并计数。
                    result.countedAsLoss =
                        recordLocalLoss(LossCategory::RetentionEvicted, 1ULL) || result.countedAsLoss;
                }
                result.lossCategory = LossCategory::RetentionEvicted;
                result.reasonKey = "timeline.ingest.limit-reached-evicted-oldest";
                break;
            }
        }
    }

    // T-04：时间标注。源时间一个字节都不改，只加标记。
    const std::uint32_t rank = registerBoot(event.time.bootId);
    BootEpoch& epoch = bootEpochs_[rank];
    const OptionalU64 effective = event.time.effectiveTime100ns();
    if (effective.present) {
        if (epoch.maxTimeKnown && effective.value < epoch.maxEffectiveTime100ns) {
            event.time.lateArrival = true;  // 接收顺序晚于时间顺序 —— 可补入，但要标出来
        }
        if (!epoch.maxTimeKnown || effective.value > epoch.maxEffectiveTime100ns) {
            epoch.maxEffectiveTime100ns = effective.value;
            epoch.maxTimeKnown = true;
        }
    }
    if (!events_.empty()) {
        // 与上一条到达事件在精度内不可分辨时，两条都标"顺序不确定"。
        // 权威的相邻判定在 sortedOrder() 里做，这里只服务流式 UI。
        const TimeComparisonResult comparison = CompareEventTimes(events_.back().time, event.time);
        if (comparison.kind == TimeComparison::ComparableButUncertain) {
            events_.back().time.orderUncertain = true;
            event.time.orderUncertain = true;
        }
    }

    // T-05：归属。缺开始事件时得到临时实体，绝不落到同 PID 的当前进程上。
    const AttributionDecision decision = processes_.attribute(event.time.bootId, event.pid, event.time);
    event.attribution = decision.kind;
    event.processInstanceKey =
        decision.kind == AttributionKind::BoundToInstance ? decision.instance.crossSessionKey()
                                                          : std::string();
    event.provisionalProcessId = decision.provisionalId;

    // T-06：只有连原始字段都不完整的 Malformed 才算"解析失败丢了信息"。
    // UnparsedUnknownSchema 原始记录完整保留，不计丢失 —— 否则就是重复计数。
    if (event.parseOutcome == EventParseOutcome::Malformed) {
        // 与既有语义一致：解析失败不改变本条事件的 countedAsLoss（它被接纳了）。
        recordLocalLoss(LossCategory::ParseFailure, 1ULL);
    }

    event.arrivalSequence = nextSequence_++;
    result.assignedSequence = event.arrivalSequence;
    result.accepted = true;
    if (result.reasonKey.empty()) {
        result.reasonKey = "timeline.ingest.accepted";
    }
    result.bounds = boundsState_;
    recordIds_.insert(event.recordId);
    events_.push_back(std::move(event));
    return result;
}

bool TimelineSession::appendRestoredEvent(TimelineEvent event) {
    if (event.recordId.empty() || recordIds_.find(event.recordId) != recordIds_.end()) {
        return false;  // 文件里出现空/重复 recordId：结构已经坏了，不能当成正常恢复
    }
    registerBoot(event.time.bootId);
    if (event.arrivalSequence >= nextSequence_) {
        nextSequence_ = event.arrivalSequence + 1U;
    }
    recordIds_.insert(event.recordId);
    events_.push_back(std::move(event));
    return true;
}

void TimelineSession::setStatsForRestore(std::uint64_t filteredOutCount, BoundsState bounds) noexcept {
    filteredOutCount_ = filteredOutCount;
    boundsState_ = bounds;
}

std::vector<const TimelineEvent*> TimelineSession::visibleEvents() const {
    std::vector<const TimelineEvent*> visible;
    visible.reserve(events_.size());
    for (const TimelineEvent& event : events_) {
        if (FilterAdmits(displayFilter_, event)) {
            visible.push_back(&event);
        }
    }
    return visible;
}

std::vector<TimelineSortKey> TimelineSession::sortedOrder() const {
    // 排序键与它来自的事件成对搬运。原来的做法是排完之后按 recordId 回表线性查找，
    // 每一对相邻键都要全表扫一遍 —— 实测 n=32000 要 5.2 秒，规格里 100 万条的负载
    // 按同样的斜率要 84 分钟。而且那次查找保留的是**最后一个**同名 recordId，
    // 一旦有重复 id 就会拿错记录去比时间（重复 id 现在已在 ingest 入口拒掉）。
    struct Entry final {
        TimelineSortKey key;
        const TimelineEvent* event = nullptr;
    };
    std::vector<Entry> entries;
    entries.reserve(events_.size());
    for (const TimelineEvent& event : events_) {
        TimelineSortKey key;
        key.bootEpochRank = bootRankOf(event.time.bootId);
        const OptionalU64 effective = event.time.effectiveTime100ns();
        key.timeKnown = effective.present;
        key.effectiveTime100ns = effective.valueOr(0ULL);
        key.arrivalSequence = event.arrivalSequence;
        key.sourceGroup = event.sourceGroup;
        key.recordId = event.recordId;
        if (!key.timeKnown) {
            key.explanationKey = "timeline.order.time-unknown-ordered-by-arrival";
        } else if (key.bootEpochRank != 0U) {
            // 跨启动周期不比较时间值，只按"启动周期首次出现的次序"分组。
            key.explanationKey = "timeline.order.cross-boot-grouped-by-epoch";
        } else if (event.time.effectiveFromReceiveTime()) {
            key.explanationKey = "timeline.order.by-receive-time-source-time-missing";
        } else {
            key.explanationKey = "timeline.order.by-source-time";
        }
        Entry entry;
        entry.key = std::move(key);
        entry.event = &event;
        entries.push_back(std::move(entry));
    }
    std::sort(entries.begin(), entries.end(), [](const Entry& a, const Entry& b) {
        return SortKeyLess(a.key, b.key);
    });

    // 相邻两条在精度内不可分辨时改写说明：确定的是**排序**，不是真实先后。
    for (std::size_t i = 1; i < entries.size(); ++i) {
        if (entries[i - 1].key.bootEpochRank != entries[i].key.bootEpochRank) {
            continue;
        }
        if (!entries[i - 1].key.timeKnown || !entries[i].key.timeKnown) {
            continue;
        }
        const TimeComparisonResult comparison =
            CompareEventTimes(entries[i - 1].event->time, entries[i].event->time);
        if (comparison.kind == TimeComparison::ComparableButUncertain) {
            entries[i - 1].key.explanationKey = "timeline.order.uncertain-within-resolution";
            entries[i].key.explanationKey = "timeline.order.uncertain-within-resolution";
        }
    }

    std::vector<TimelineSortKey> keys;
    keys.reserve(entries.size());
    for (Entry& entry : entries) {
        keys.push_back(std::move(entry.key));
    }
    return keys;
}

ExportPlan TimelineSession::buildExportPlan(ExportScope scope) const {
    ExportPlan plan;
    plan.scope = scope;
    plan.retainedEventCount = static_cast<std::uint64_t>(events_.size());
    plan.excludedByCollectionFilter = filteredOutCount_;
    const std::uint64_t visible = static_cast<std::uint64_t>(visibleEvents().size());
    plan.hiddenByDisplayFilter = plan.retainedEventCount - visible;

    switch (scope) {
    case ExportScope::VisibleOnly:
        plan.exportedEventCount = visible;
        plan.representsRetainedSession = plan.hiddenByDisplayFilter == 0ULL && !displayFilter_.active;
        plan.noticeKeys.push_back("timeline.export.visible-only");
        if (plan.hiddenByDisplayFilter != 0ULL) {
            // T-03：显示过滤不得让导出看起来"这些事件不存在"。
            plan.noticeKeys.push_back("timeline.export.hidden-events-still-in-session");
        } else if (displayFilter_.active) {
            plan.noticeKeys.push_back("timeline.export.display-filter-active-nothing-hidden");
        }
        break;
    case ExportScope::FullSession:
        plan.exportedEventCount = plan.retainedEventCount;
        plan.representsRetainedSession = true;
        plan.noticeKeys.push_back("timeline.export.full-session");
        if (displayFilter_.active) {
            plan.noticeKeys.push_back("timeline.export.display-filter-not-applied");
        }
        break;
    }

    // T-06：collector 能力不是只写不读的装饰。声明了 File / Registry 采集器却一个都没
    // 跑起来（Error / Unsupported / AccessDenied），会话里当然一条 File / Registry 事件
    // 都没有 —— 那不是"系统没发生过"，把它导出成完整采集就是把采集失败说成了正常。
    std::uint64_t unavailable = 0;
    for (const CollectorCapability& capability : manifest_.capabilities) {
        if (capability.availability.status == CollectionStatus::Success) {
            continue;
        }
        ++unavailable;
        plan.noticeKeys.push_back(DescribeUnavailableCollector(capability));
    }
    plan.unavailableCollectorCount = unavailable;
    const bool capabilitiesDeclared = !manifest_.capabilities.empty();
    if (!capabilitiesDeclared) {
        // 一个 collector 能力都没声明 = 不知道本该采到什么。"完整"需要正面证据。
        plan.noticeKeys.push_back("timeline.export.no-collector-capability-declared");
    }

    plan.unrecoverableFileEventCount = loadIntegrity_.unrecoverableEventCount;
    const bool loadedFileIsComplete =
        !loadIntegrity_.restoredFromFile || loadIntegrity_.representsCompleteFile();
    if (!loadedFileIsComplete) {
        plan.noticeKeys.push_back(std::string("timeline.export.restored-from-incomplete-file.") +
                                  SessionLoadStatusName(loadIntegrity_.status));
    }
    if (plan.unrecoverableFileEventCount != 0ULL) {
        plan.noticeKeys.push_back("timeline.export.unrecoverable-file-events");
    }
    if (lossAccountingFailed_) {
        plan.noticeKeys.push_back("timeline.export.loss-accounting-failed");
    }

    const OptionalU64 total = loss_.totalLost();
    plan.retainedSessionIsCompleteCapture =
        !collectionFilter_.active && total.present && total.value == 0ULL &&
        boundsState_ == BoundsState::WithinLimits && capabilitiesDeclared && unavailable == 0ULL &&
        !lossAccountingFailed_ && plan.unrecoverableFileEventCount == 0ULL && loadedFileIsComplete;
    if (!plan.retainedSessionIsCompleteCapture) {
        plan.noticeKeys.push_back("timeline.export.session-not-complete-capture");
    }
    if (collectionFilter_.active) {
        plan.noticeKeys.push_back("timeline.export.collection-filter-applied");
    }
    if (boundsState_ != BoundsState::WithinLimits) {
        plan.noticeKeys.push_back("timeline.export.bounds-reached");
    }
    return plan;
}

// ===========================================================================
// T-09 / T-10 持久化
// ===========================================================================

std::string SerializeSessionHeaderLine(const TimelineSession& session) {
    const SessionManifest& manifest = session.manifest();
    JsonObject header;
    PutText(header, "kind", kTimelineFormatKind);
    PutU32(header, "formatVersion", kTimelineFormatVersion);
    PutText(header, "sessionId", manifest.sessionId);
    PutText(header, "machineId", manifest.machineId);
    PutText(header, "bootId", manifest.bootId);
    PutText(header, "displayName", manifest.displayName);
    PutText(header, "state", SessionStateName(session.state()));
    PutOptionalU64(header, "queryRangeBegin100ns", manifest.queryRangeBegin100ns);
    PutOptionalU64(header, "queryRangeEnd100ns", manifest.queryRangeEnd100ns);

    JsonObject window;
    PutOptionalU64(window, "startUtc100ns", manifest.window.startUtc100ns);
    PutOptionalU64(window, "endUtc100ns", manifest.window.endUtc100ns);
    PutOptionalU64(window, "startMonotonic", manifest.window.startMonotonic);
    PutOptionalU64(window, "endMonotonic", manifest.window.endMonotonic);
    PutOptionalU64(window, "monotonicFrequency", manifest.window.monotonicFrequency);
    PutText(window, "machineId", manifest.window.machineId);
    PutText(window, "bootId", manifest.window.bootId);
    PutText(window, "sessionId", manifest.window.sessionId);
    PutText(window, "mode", CaptureModeName(manifest.window.mode));
    Put(header, "window", JsonValue::makeObject(std::move(window)));

    const BoundsPolicy& bounds = session.bounds();
    JsonObject boundsObject;
    PutOptionalU64(boundsObject, "maxEventsInMemory", bounds.maxEventsInMemory);
    PutOptionalU64(boundsObject, "maxArchiveBytes", bounds.maxArchiveBytes);
    PutOptionalU64(boundsObject, "approximateBytesPerEvent", bounds.approximateBytesPerEvent);
    PutText(boundsObject, "policy", RetentionPolicyName(bounds.policy));
    Put(boundsObject, "declaredBeforeCollection", JsonValue::makeBool(bounds.declaredBeforeCollection));
    Put(header, "bounds", JsonValue::makeObject(std::move(boundsObject)));

    JsonArray capabilities;
    for (const CollectorCapability& capability : manifest.capabilities) {
        JsonObject one;
        PutText(one, "collectorId", capability.collectorId);
        PutU32(one, "collectorVersion", capability.collectorVersion);
        PutText(one, "sourceGroup", capability.sourceGroup);
        PutText(one, "origin", SourceOriginName(capability.origin));
        JsonArray categories;
        for (const TimelineEventCategory category : capability.declaredCategories) {
            categories.push_back(JsonValue::makeString(TimelineEventCategoryName(category)));
        }
        Put(one, "declaredCategories", JsonValue::makeArray(std::move(categories)));
        PutText(one, "availabilityStatus", CollectionStatusName(capability.availability.status));
        PutText(one, "availabilityDomain", capability.availability.nativeCodeDomain);
        PutOptionalU64(one, "availabilityCode", capability.availability.nativeCode);
        PutText(one, "availabilityMessage", capability.availability.message);
        capabilities.push_back(JsonValue::makeObject(std::move(one)));
    }
    Put(header, "capabilities", JsonValue::makeArray(std::move(capabilities)));

    const EventFilter& filter = session.collectionFilter();
    JsonObject filterObject;
    Put(filterObject, "active", JsonValue::makeBool(filter.active));
    PutText(filterObject, "ruleId", filter.ruleId);
    JsonArray pids;
    for (const std::uint64_t pid : filter.allowedPids) {
        pids.push_back(JsonValue::makeU64Text(pid, U64Format::Decimal));
    }
    Put(filterObject, "allowedPids", JsonValue::makeArray(std::move(pids)));
    JsonArray categories;
    for (const TimelineEventCategory category : filter.allowedCategories) {
        categories.push_back(JsonValue::makeString(TimelineEventCategoryName(category)));
    }
    Put(filterObject, "allowedCategories", JsonValue::makeArray(std::move(categories)));
    JsonArray providers;
    for (const std::string& provider : filter.allowedProviderIds) {
        providers.push_back(JsonValue::makeString(provider));
    }
    Put(filterObject, "allowedProviderIds", JsonValue::makeArray(std::move(providers)));
    Put(header, "collectionFilter", JsonValue::makeObject(std::move(filterObject)));

    std::string line = WriteJson(JsonValue::makeObject(std::move(header)), 0U);
    line.push_back('\n');
    return line;
}

std::string SerializeBatchLine(const SessionBatch& batch) {
    // 事件数组只编码一次：校验和与行内容共用同一份 JsonValue。以前是 EncodeEventArray
    // 跑两遍（一遍算校验和、一遍写出去），大批次上白白翻倍。
    JsonValue eventsValue = EncodeEventArray(batch.events);
    const std::uint64_t checksum = Fnv1a64(WriteJson(eventsValue, 0U));
    JsonObject object;
    PutText(object, "kind", "batch");
    PutU64Text(object, "batchIndex", batch.batchIndex);
    Put(object, "committed", JsonValue::makeBool(batch.committed));
    PutText(object, "checksum", FormatU64(checksum, U64Format::HexAddress));
    Put(object, "events", std::move(eventsValue));
    std::string line = WriteJson(JsonValue::makeObject(std::move(object)), 0U);
    line.push_back('\n');
    return line;
}

std::string SerializeTrailerLine(const TimelineSession& session, std::uint64_t committedBatchCount) {
    JsonObject object;
    PutText(object, "kind", "trailer");
    PutU64Text(object, "batchCount", committedBatchCount);
    PutU64Text(object, "eventCount", static_cast<std::uint64_t>(session.events().size()));
    PutU64Text(object, "collectionFilteredOut", session.collectionFilteredOutCount());
    PutText(object, "boundsState", BoundsStateName(session.boundsState()));

    JsonArray loss;
    for (std::size_t i = 0; i < kLossCategoryCount; ++i) {
        const LossCategory category = LossCategoryAt(i);
        const LossCounter& counter = session.loss().counter(category);
        JsonObject one;
        PutText(one, "category", LossCategoryName(category));
        PutOptionalU64(one, "count", counter.count);
        PutText(one, "statisticSource", counter.statisticSource);
        Put(one, "sourceIsAuthoritative", JsonValue::makeBool(counter.sourceIsAuthoritative));
        Put(one, "intervalSupported", JsonValue::makeBool(counter.intervalSupported));
        PutOptionalU64(one, "intervalBegin100ns", counter.intervalBegin100ns);
        PutOptionalU64(one, "intervalEnd100ns", counter.intervalEnd100ns);
        loss.push_back(JsonValue::makeObject(std::move(one)));
    }
    Put(object, "loss", JsonValue::makeArray(std::move(loss)));

    std::string line = WriteJson(JsonValue::makeObject(std::move(object)), 0U);
    line.push_back('\n');
    return line;
}

void SerializeSessionTo(const TimelineSession& session,
                        std::size_t batchSize,
                        const std::function<void(std::string_view)>& sink) {
    if (!sink) {
        return;
    }
    const std::size_t effectiveBatchSize = batchSize == 0U ? session.events().size() + 1U : batchSize;
    sink(SerializeSessionHeaderLine(session));

    std::uint64_t batchIndex = 0;
    std::size_t offset = 0;
    // 一次只把一个批次搬进内存。以前这里是往一个 std::string 上不停 += —— 20 万条
    // 512B 载荷的会话会先攒出一个 360 MiB 的单串，峰值 = 会话 + 整份文件。
    while (offset < session.events().size()) {
        SessionBatch batch;
        batch.batchIndex = batchIndex;
        batch.committed = true;
        const std::size_t end = std::min(session.events().size(), offset + effectiveBatchSize);
        batch.events.assign(session.events().begin() + static_cast<std::ptrdiff_t>(offset),
                            session.events().begin() + static_cast<std::ptrdiff_t>(end));
        sink(SerializeBatchLine(batch));
        offset = end;
        ++batchIndex;
    }
    sink(SerializeTrailerLine(session, batchIndex));
}

std::string SerializeSession(const TimelineSession& session, std::size_t batchSize) {
    std::string text;
    SerializeSessionTo(session, batchSize, [&text](std::string_view line) { text.append(line); });
    return text;
}

namespace {

bool RestoreLossFromTrailer(const JsonValue& trailer, LossLedger& ledger) {
    const JsonValue* loss = trailer.find("loss");
    if (loss == nullptr) {
        return false;
    }
    const JsonArray* array = loss->asArray();
    if (array == nullptr) {
        return false;
    }
    for (const JsonValue& item : *array) {
        std::string name;
        if (!ReadText(item, "category", name)) {
            return false;
        }
        LossCategory category = LossCategory::SourceDrop;
        if (!LookupEnum(kLossCategoryTable, name, category)) {
            return false;
        }
        LossCounter& counter = ledger.mutableCounter(category);
        if (!ReadOptionalU64(item, "count", counter.count)) { return false; }
        if (!ReadText(item, "statisticSource", counter.statisticSource)) { return false; }
        if (!ReadBool(item, "sourceIsAuthoritative", counter.sourceIsAuthoritative)) { return false; }
        if (!ReadBool(item, "intervalSupported", counter.intervalSupported)) { return false; }
        if (!ReadOptionalU64(item, "intervalBegin100ns", counter.intervalBegin100ns)) { return false; }
        if (!ReadOptionalU64(item, "intervalEnd100ns", counter.intervalEnd100ns)) { return false; }
    }
    return true;
}

bool RestoreHeader(const JsonValue& header, SessionManifest& manifest, BoundsPolicy& bounds,
                   EventFilter& filter, SessionState& state) {
    if (!ReadText(header, "sessionId", manifest.sessionId)) { return false; }
    if (!ReadText(header, "machineId", manifest.machineId)) { return false; }
    if (!ReadText(header, "bootId", manifest.bootId)) { return false; }
    if (!ReadText(header, "displayName", manifest.displayName)) { return false; }
    std::string text;
    if (!ReadText(header, "state", text) || !LookupEnum(kSessionStateTable, text, state)) {
        return false;
    }
    if (!ReadOptionalU64(header, "queryRangeBegin100ns", manifest.queryRangeBegin100ns)) { return false; }
    if (!ReadOptionalU64(header, "queryRangeEnd100ns", manifest.queryRangeEnd100ns)) { return false; }

    const JsonValue* window = header.find("window");
    if (window == nullptr || window->asObject() == nullptr) { return false; }
    if (!ReadOptionalU64(*window, "startUtc100ns", manifest.window.startUtc100ns)) { return false; }
    if (!ReadOptionalU64(*window, "endUtc100ns", manifest.window.endUtc100ns)) { return false; }
    if (!ReadOptionalU64(*window, "startMonotonic", manifest.window.startMonotonic)) { return false; }
    if (!ReadOptionalU64(*window, "endMonotonic", manifest.window.endMonotonic)) { return false; }
    if (!ReadOptionalU64(*window, "monotonicFrequency", manifest.window.monotonicFrequency)) { return false; }
    if (!ReadText(*window, "machineId", manifest.window.machineId)) { return false; }
    if (!ReadText(*window, "bootId", manifest.window.bootId)) { return false; }
    if (!ReadText(*window, "sessionId", manifest.window.sessionId)) { return false; }
    if (!ReadText(*window, "mode", text)) { return false; }
    // 采集模式：读回的会话一律是重放；这里只校验字段存在且是已知取值。
    if (text != "Unknown" && text != "Snapshot" && text != "Streaming" && text != "Replay") {
        return false;
    }
    manifest.window.mode = CaptureMode::Replay;

    const JsonValue* boundsObject = header.find("bounds");
    if (boundsObject == nullptr || boundsObject->asObject() == nullptr) { return false; }
    if (!ReadOptionalU64(*boundsObject, "maxEventsInMemory", bounds.maxEventsInMemory)) { return false; }
    if (!ReadOptionalU64(*boundsObject, "maxArchiveBytes", bounds.maxArchiveBytes)) { return false; }
    if (!ReadOptionalU64(*boundsObject, "approximateBytesPerEvent", bounds.approximateBytesPerEvent)) {
        return false;
    }
    if (!ReadText(*boundsObject, "policy", text) || !LookupEnum(kRetentionTable, text, bounds.policy)) {
        return false;
    }
    if (!ReadBool(*boundsObject, "declaredBeforeCollection", bounds.declaredBeforeCollection)) {
        return false;
    }

    const JsonValue* capabilities = header.find("capabilities");
    if (capabilities == nullptr) { return false; }
    const JsonArray* capabilityArray = capabilities->asArray();
    if (capabilityArray == nullptr) { return false; }
    for (const JsonValue& item : *capabilityArray) {
        CollectorCapability capability;
        if (!ReadText(item, "collectorId", capability.collectorId)) { return false; }
        if (!ReadU32(item, "collectorVersion", capability.collectorVersion)) { return false; }
        if (!ReadText(item, "sourceGroup", capability.sourceGroup)) { return false; }
        // 认不出的 origin 不再默默退成 Unknown：同一个 header 里 declaredCategories /
        // policy / state 都是"认不出就判坏文件"，这里没有理由更宽松。
        if (!ReadText(item, "origin", text) ||
            !LookupEnum(kSourceOriginTable, text, capability.origin)) {
            return false;
        }
        const JsonValue* categories = item.find("declaredCategories");
        if (categories == nullptr) { return false; }
        const JsonArray* categoryArray = categories->asArray();
        if (categoryArray == nullptr) { return false; }
        for (const JsonValue& category : *categoryArray) {
            std::string categoryName;
            if (!category.tryGetString(categoryName)) { return false; }
            TimelineEventCategory decoded = TimelineEventCategory::Other;
            if (!LookupEnum(kCategoryTable, categoryName, decoded)) { return false; }
            capability.declaredCategories.push_back(decoded);
        }
        // 认不出的 availabilityStatus 以前会静默退成 NotCollected —— 那是把一次
        // **失败**改判成**从未运行**，而 nativeCode 里还留着 STATUS_ACCESS_DENIED，
        // 两个字段自相矛盾。坏名字就是坏文件。
        if (!ReadText(item, "availabilityStatus", text) ||
            !LookupEnum(kCollectionStatusTable, text, capability.availability.status)) {
            return false;
        }
        if (!ReadText(item, "availabilityDomain", capability.availability.nativeCodeDomain)) { return false; }
        if (!ReadOptionalU64(item, "availabilityCode", capability.availability.nativeCode)) { return false; }
        if (!ReadText(item, "availabilityMessage", capability.availability.message)) { return false; }
        manifest.capabilities.push_back(std::move(capability));
    }

    const JsonValue* filterObject = header.find("collectionFilter");
    if (filterObject == nullptr || filterObject->asObject() == nullptr) { return false; }
    if (!ReadBool(*filterObject, "active", filter.active)) { return false; }
    if (!ReadText(*filterObject, "ruleId", filter.ruleId)) { return false; }
    const JsonValue* pids = filterObject->find("allowedPids");
    if (pids == nullptr || pids->asArray() == nullptr) { return false; }
    for (const JsonValue& pid : *pids->asArray()) {
        std::uint64_t value = 0;
        if (!pid.tryGetU64(value)) { return false; }
        filter.allowedPids.push_back(value);
    }
    const JsonValue* filterCategories = filterObject->find("allowedCategories");
    if (filterCategories == nullptr || filterCategories->asArray() == nullptr) { return false; }
    for (const JsonValue& category : *filterCategories->asArray()) {
        std::string categoryName;
        if (!category.tryGetString(categoryName)) { return false; }
        TimelineEventCategory decoded = TimelineEventCategory::Other;
        if (!LookupEnum(kCategoryTable, categoryName, decoded)) { return false; }
        filter.allowedCategories.push_back(decoded);
    }
    const JsonValue* filterProviders = filterObject->find("allowedProviderIds");
    if (filterProviders == nullptr || filterProviders->asArray() == nullptr) { return false; }
    for (const JsonValue& provider : *filterProviders->asArray()) {
        std::string providerName;
        if (!provider.tryGetString(providerName)) { return false; }
        filter.allowedProviderIds.push_back(providerName);
    }
    return true;
}

} // namespace

SessionLoadResult LoadSession(std::string_view text) {
    SessionLoadResult result;
    if (text.empty()) {
        result.status = SessionLoadStatus::Empty;
        result.diagnosticKey = "timeline.load.empty";
        return result;
    }

    bool lastLineTerminated = true;
    const std::vector<std::string_view> lines = SplitLines(text, lastLineTerminated);
    if (lines.empty()) {
        result.status = SessionLoadStatus::Empty;
        result.diagnosticKey = "timeline.load.empty";
        return result;
    }

    // ---- header ----
    const JsonParseResult headerParse = ParseJson(lines[0]);
    result.jsonStatus = headerParse.status;
    if (!headerParse.ok() || headerParse.value.asObject() == nullptr) {
        result.status = SessionLoadStatus::MissingHeader;
        result.diagnosticKey = "timeline.load.header-unparsable";
        result.failedLineIndex = 0;
        return result;
    }
    std::string kind;
    if (!ReadText(headerParse.value, "kind", kind) || kind != kTimelineFormatKind) {
        result.status = SessionLoadStatus::MissingHeader;
        result.diagnosticKey = "timeline.load.header-kind-mismatch";
        return result;
    }
    if (!ReadU32(headerParse.value, "formatVersion", result.fileFormatVersion)) {
        result.status = SessionLoadStatus::MissingHeader;
        result.diagnosticKey = "timeline.load.header-version-missing";
        return result;
    }
    if (result.fileFormatVersion > kTimelineFormatVersion) {
        // T-10：版本过新是独立状态。既不当成"格式无效"，也绝不猜着读。
        result.status = SessionLoadStatus::VersionTooNew;
        result.diagnosticKey = "timeline.load.format-version-too-new";
        return result;
    }

    SessionManifest manifest;
    BoundsPolicy bounds;
    EventFilter collectionFilter;
    SessionState state = SessionState::Saved;
    if (!RestoreHeader(headerParse.value, manifest, bounds, collectionFilter, state)) {
        result.status = SessionLoadStatus::MissingHeader;
        result.diagnosticKey = "timeline.load.header-fields-invalid";
        return result;
    }

    TimelineSession session(std::move(manifest), bounds);
    session.setCollectionFilter(std::move(collectionFilter));

    bool sawTrailer = false;
    bool sawUncommitted = false;
    std::uint64_t trailerEventCount = 0;
    std::uint64_t trailerBatchCount = 0;
    std::uint64_t trailerFilteredOut = 0;
    BoundsState trailerBounds = BoundsState::WithinLimits;
    SessionLoadStatus status = SessionLoadStatus::Ok;
    std::string diagnostic = "timeline.load.ok";

    for (std::size_t index = 1; index < lines.size(); ++index) {
        const bool isLastLine = (index + 1U == lines.size());
        if (lines[index].empty()) {
            continue;
        }
        if (sawTrailer) {
            // T-10：trailer 必须是最后一行。之后还有内容 —— 第二个 trailer、被中断的
            // 重写留在中间的旧 trailer、事后追加上去的批次 —— 都说明文件结构已经坏了。
            // 以前这里只是 continue，于是 "header+batch+trailer+batch" 读回来是
            // status=Ok / representsCompleteFile()=true 的"干净完整会话"。
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.content-after-trailer";
            break;
        }
        if (isLastLine && !lastLineTerminated) {
            // 写到一半被打断：这一行不完整，之前已提交的批次照常保留。
            status = SessionLoadStatus::IncompleteTail;
            diagnostic = "timeline.load.unterminated-final-line";
            result.failedLineIndex = index;
            break;
        }
        const JsonParseResult lineParse = ParseJson(lines[index]);
        if (!lineParse.ok() || lineParse.value.asObject() == nullptr) {
            result.jsonStatus = lineParse.status;
            result.failedLineIndex = index;
            status = isLastLine ? SessionLoadStatus::IncompleteTail : SessionLoadStatus::Corrupt;
            diagnostic = isLastLine ? "timeline.load.tail-line-unparsable"
                                    : "timeline.load.line-unparsable";
            break;
        }
        std::string lineKind;
        if (!ReadText(lineParse.value, "kind", lineKind)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.line-kind-missing";
            break;
        }
        if (lineKind == "trailer") {
            if (!ReadU64(lineParse.value, "batchCount", trailerBatchCount) ||
                !ReadU64(lineParse.value, "eventCount", trailerEventCount) ||
                !ReadU64(lineParse.value, "collectionFilteredOut", trailerFilteredOut)) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::Corrupt;
                diagnostic = "timeline.load.trailer-fields-invalid";
                break;
            }
            std::string boundsName;
            if (!ReadText(lineParse.value, "boundsState", boundsName) ||
                !LookupEnum(kBoundsStateTable, boundsName, trailerBounds)) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::Corrupt;
                diagnostic = "timeline.load.trailer-fields-invalid";
                break;
            }
            if (!RestoreLossFromTrailer(lineParse.value, session.loss())) {
                result.failedLineIndex = index;
                status = SessionLoadStatus::Corrupt;
                diagnostic = "timeline.load.trailer-loss-invalid";
                break;
            }
            sawTrailer = true;
            continue;
        }
        if (lineKind != "batch") {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.unknown-line-kind";
            break;
        }

        bool committed = false;
        std::uint64_t batchIndex = 0;
        std::string checksumText;
        if (!ReadBool(lineParse.value, "committed", committed) ||
            !ReadU64(lineParse.value, "batchIndex", batchIndex) ||
            !ReadText(lineParse.value, "checksum", checksumText)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.batch-fields-invalid";
            break;
        }
        const JsonValue* eventsValue = lineParse.value.find("events");
        if (eventsValue == nullptr || eventsValue->asArray() == nullptr) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.batch-events-invalid";
            break;
        }
        std::vector<TimelineEvent> decoded;
        bool decodeOk = true;
        for (const JsonValue& item : *eventsValue->asArray()) {
            TimelineEvent event;
            if (!DecodeEvent(item, event)) {
                decodeOk = false;
                break;
            }
            decoded.push_back(std::move(event));
        }
        if (!decodeOk) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.event-decode-failed";
            break;
        }
        if (!committed) {
            // T-10：只承诺已提交批次。未提交的条数单独报出来，标记为缺失。
            sawUncommitted = true;
            result.uncommittedEventCount =
                SaturatingAddU64(result.uncommittedEventCount,
                                 static_cast<std::uint64_t>(decoded.size()));
            continue;
        }
        std::uint64_t storedChecksum = 0;
        if (!ParseU64(checksumText, storedChecksum)) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.batch-checksum-invalid";
            break;
        }
        if (BatchChecksum(decoded) != storedChecksum) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.batch-checksum-mismatch";
            break;
        }
        bool appendOk = true;
        for (TimelineEvent& event : decoded) {
            if (!session.appendRestoredEvent(std::move(event))) {
                appendOk = false;
                break;
            }
        }
        if (!appendOk) {
            result.failedLineIndex = index;
            status = SessionLoadStatus::Corrupt;
            diagnostic = "timeline.load.duplicate-record-id";
            break;
        }
        ++result.committedBatchCount;
    }

    result.recoveredEventCount = static_cast<std::uint64_t>(session.events().size());
    result.trailerPresent = sawTrailer;
    if (sawTrailer) {
        session.setStatsForRestore(trailerFilteredOut, trailerBounds);
        result.declaredEventCount = trailerEventCount;
    }
    if (status == SessionLoadStatus::Ok) {
        if (!sawTrailer) {
            status = SessionLoadStatus::IncompleteTail;
            diagnostic = "timeline.load.missing-trailer";
        } else if (sawUncommitted) {
            status = SessionLoadStatus::IncompleteTail;
            diagnostic = "timeline.load.uncommitted-batch-present";
        } else if (trailerEventCount != result.recoveredEventCount ||
                   trailerBatchCount != result.committedBatchCount) {
            status = SessionLoadStatus::TrailerMismatch;
            diagnostic = "timeline.load.trailer-count-mismatch";
        }
    }

    // T-10："未提交部分标记缺失"。两个来源：未提交批次里的条数，以及 trailer 声明得比
    // 实际恢复出来的更多的那一部分。这不是 T-06 的六类采集丢失（那六类说的是采集期），
    // 所以单独记账、单独给统计来源，绝不并进 totalLost()。
    std::uint64_t unrecoverable = result.uncommittedEventCount;
    if (sawTrailer && trailerEventCount > result.recoveredEventCount) {
        const std::uint64_t missing = trailerEventCount - result.recoveredEventCount;
        if (missing > unrecoverable) {
            // 未提交的那些本来就算在 trailer 声明里，取较大值即可，不重复计数。
            unrecoverable = missing;
        }
    }
    result.unrecoverableEventCount = unrecoverable;

    // T-10：载入结论必须长在会话上。以前它只写在 result 上，session 一交出去，
    // "尾部截断 / trailer 对不上"就彻底消失 —— 实测截断文件的 session 会给出
    // retainedSessionIsCompleteCapture=1 和 envelope Success。
    SessionLoadIntegrity integrity;
    integrity.restoredFromFile = true;
    integrity.status = status;
    integrity.diagnosticKey = diagnostic;
    integrity.unrecoverableEventCount = unrecoverable;
    integrity.unrecoverableStatisticSource = "local.session-file.uncommitted";
    session.setLoadIntegrityForRestore(std::move(integrity));

    // 离线重开的会话一律只读；恢复出来的状态不允许是"正在采集"。
    session.setStateForRestore(state == SessionState::New ? SessionState::New : SessionState::Saved);
    result.status = status;
    result.diagnosticKey = std::move(diagnostic);
    result.session = std::move(session);
    return result;
}

// ===========================================================================
// 会话 envelope
// ===========================================================================

EvidenceEnvelope BuildSessionEnvelope(const TimelineSession& session) {
    EvidenceEnvelope envelope;
    envelope.source.collectorId = "timeline.session";
    envelope.source.sourceGroup = "timeline.session";
    envelope.source.collectorVersion = kTimelineFormatVersion;
    envelope.source.dependsOn = "ETW / CallbackMonitor / FileMonitor";
    envelope.source.origin = session.state() == SessionState::Saved ? SourceOrigin::OfflineSample
                                                                   : SourceOrigin::LiveUserMode;
    envelope.window = session.manifest().window;
    envelope.evidenceId = session.manifest().sessionId;

    const LossLedger& loss = session.loss();
    const OptionalU64 total = loss.totalLost();
    const SessionManifest& manifest = session.manifest();
    const SessionLoadIntegrity& integrity = session.loadIntegrity();

    const CollectorCapability* unavailable = nullptr;
    for (const CollectorCapability& capability : manifest.capabilities) {
        if (capability.availability.status != CollectionStatus::Success) {
            unavailable = &capability;
            break;
        }
    }

    if (session.state() == SessionState::New) {
        envelope.outcome.status = CollectionStatus::NotCollected;
    } else if (manifest.capabilities.empty()) {
        // 一个 collector 能力都没声明：不知道本该采到什么，就没有资格说"采全了"。
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.message = "no collector capability declared";
    } else if (unavailable != nullptr) {
        // F-05：失败必须保留原始错误码及说明，不得用默认 0/空串/"正常"补齐。
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.nativeCodeDomain = unavailable->availability.nativeCodeDomain;
        envelope.outcome.nativeCode = unavailable->availability.nativeCode;
        envelope.outcome.message = unavailable->collectorId + ": " +
                                   CollectionStatusName(unavailable->availability.status) +
                                   (unavailable->availability.message.empty()
                                        ? std::string()
                                        : (": " + unavailable->availability.message));
    } else if (integrity.restoredFromFile && !integrity.representsCompleteFile()) {
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.message = std::string("session file ") +
                                   SessionLoadStatusName(integrity.status) + ": " +
                                   integrity.diagnosticKey;
    } else if (integrity.unrecoverableEventCount != 0ULL) {
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.message = "session file has unrecoverable events";
    } else if (session.lossAccountingFailed()) {
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.message = "loss accounting failed";
    } else if (!total.present) {
        envelope.outcome.status = CollectionStatus::Partial;
        envelope.outcome.message = "loss accounting incomplete";
    } else if (total.value != 0ULL || session.boundsState() != BoundsState::WithinLimits ||
               session.collectionFilteredOutCount() != 0ULL) {
        envelope.outcome.status = CollectionStatus::Partial;
    } else {
        envelope.outcome.status = CollectionStatus::Success;
    }

    CoverageAccount& coverage = envelope.coverage;
    coverage.requestedBegin = manifest.queryRangeBegin100ns;
    coverage.requestedEnd = manifest.queryRangeEnd100ns;
    coverage.succeeded = static_cast<std::uint64_t>(session.events().size());
    // 采集过滤排除的条数由会话权威地记着；账目里的 FilteredOut 只是它的副本。
    // 以前这里用 loss.counter(FilteredOut).count.valueOr(0)，账目没有来源时就把
    // "排除了 7 条"写成 0 —— 那正是本模块自己在 1041 行禁止的替换。
    coverage.skipped = session.collectionFilteredOutCount();
    // CoverageAccount 的这三个计数是 F 层的 std::uint64_t，没有"未知"状态可用，
    // 因此只把**已知**的计数相加，并且任何一类未知都会在上面把 outcome 打成 Partial
    // 并写明原因。绝不把未知当 0 合进来假装账目是齐的。
    const LossCategory kFailedCategories[] = { LossCategory::SourceDrop,
                                               LossCategory::RingOverwrite,
                                               LossCategory::QueueDiscard,
                                               LossCategory::ParseFailure };
    std::uint64_t failed = 0;
    bool anyUnknownCount = false;
    for (const LossCategory category : kFailedCategories) {
        const LossCounter& counter = loss.counter(category);
        if (!counter.count.present) {
            // T-06：来源没给这一类的计数。跳过它是对的（不能把未知按 0 汇总进
            // 总数），但"跳过"本身必须留痕 —— 否则 coverage.failed 里的数字看着
            // 精确，实际上只是一个下界，UI 会把"不知道丢了多少"读成"没丢"。
            anyUnknownCount = true;
            continue;
        }
        failed = SaturatingAddU64(failed, counter.count.value);
    }
    coverage.failed = failed;
    coverage.countsIncomplete = anyUnknownCount;
    // 保留策略淘汰 + 会话文件里恢复不出来的条数，都是"这一段轨迹被截掉了"。
    coverage.truncated =
        SaturatingAddU64(loss.counter(LossCategory::RetentionEvicted).count.valueOr(0ULL),
                         integrity.unrecoverableEventCount);
    coverage.limitHit = session.boundsState() != BoundsState::WithinLimits;
    coverage.limit = session.bounds().maxEventsInMemory;

    // F-06 / T-06：时间线**永远不知道**系统总共发生过多少事件，因此 totalKnown
    // 恒不设置。只有账目六类全部有具名来源时，才敢给出"处理范围"这条正面证据；
    // 有任何一类未知就把端点留空，fullyCovered() 因而判不完整 —— 这正是我们要的。
    if (!loss.anyUnknown()) {
        std::uint64_t begin = 0;
        std::uint64_t end = 0;
        bool any = false;
        for (const TimelineEvent& event : session.events()) {
            const OptionalU64 effective = event.time.effectiveTime100ns();
            if (!effective.present) {
                continue;
            }
            if (!any || effective.value < begin) {
                begin = effective.value;
            }
            if (!any || effective.value > end) {
                end = effective.value;
            }
            any = true;
        }
        if (any) {
            coverage.processedBegin = OptionalU64::of(begin);
            coverage.processedEnd = OptionalU64::of(end);
        }
    }
    return envelope;
}

} // namespace Ksword::Evidence
