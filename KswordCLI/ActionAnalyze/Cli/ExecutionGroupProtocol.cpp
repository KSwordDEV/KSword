#include "ExecutionGroupProtocol.h"
#include "../Project/ProjectStorage.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <charconv>
#include <climits>
#include <limits>
#include <stdexcept>

namespace ks::cli::action_analyze::execution_group {
namespace {
using V = JsonValue;
namespace n = control;
V Text(std::string_view s) { return V::makeString(std::string(s)); }
V Count(std::uint64_t v) { return Text(std::to_string(v)); }
bool Shape(const V& v, std::size_t count) { return v.asObject() && v.asObject()->size() == count; }
bool String(const V* v, std::string& out, std::size_t limit = 4096)
{
    return v && v->tryGetString(out) && !out.empty() && out.size() <= limit && out.find('\0') == std::string::npos;
}
bool Number(const V* v, std::uint64_t& out, bool zero = false)
{
    std::string text;
    if (!String(v, text, 20)) return false;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), out);
    return parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
        (zero || out) && text == std::to_string(out);
}
bool UInt(const V* v, std::uint32_t& out, std::uint32_t maximum = UINT32_MAX)
{
    std::uint64_t value = 0;
    if (!v || v->type() != Ksword::Evidence::JsonType::UInt || !v->tryGetU64(value) || value > maximum) return false;
    out = static_cast<std::uint32_t>(value);
    return true;
}
bool Boolean(const V* v, bool& out) { return v && v->tryGetBool(out); }
template<class E> bool Enum(const V* v, E& out, std::uint32_t maximum)
{
    std::uint32_t value = 0;
    if (!UInt(v, value, maximum)) return false;
    out = static_cast<E>(value);
    return true;
}
V Thread(const n::ThreadIdentity& t)
{
    return V::makeObject({{"threadId", Text(t.threadId)}, {"processInstanceId", Text(t.processInstanceId)}});
}
bool ThreadValue(const V* v, n::ThreadIdentity& t)
{
    return v && Shape(*v, 2) && String(v->find("threadId"), t.threadId) && String(v->find("processInstanceId"), t.processInstanceId);
}
V Owner(const n::OwnerIdentity& o)
{
    return V::makeObject({{"sampleId", Text(o.sampleId)}, {"sessionId", Text(o.sessionId)},
        {"epoch", Text(o.epoch)}, {"backendInstanceId", Text(o.backendInstanceId)}});
}
bool OwnerValue(const V* v, n::OwnerIdentity& o)
{
    return v && Shape(*v, 4) && String(v->find("sampleId"), o.sampleId) && String(v->find("sessionId"), o.sessionId) &&
        String(v->find("epoch"), o.epoch) && String(v->find("backendInstanceId"), o.backendInstanceId);
}
V Event(const n::NativeEventKey& e)
{
    return V::makeObject({{"backendInstanceId", Text(e.backendInstanceId)}, {"serial", Count(e.serial)}});
}
bool EventValue(const V* v, n::NativeEventKey& e)
{
    return v && Shape(*v, 2) && String(v->find("backendInstanceId"), e.backendInstanceId) && Number(v->find("serial"), e.serial);
}
V StepRequest(const n::NativeStepRequest& s)
{
    const auto& r = s.release;
    return V::makeObject({{"owner", Owner(r.owner)}, {"groupId", Text(r.groupId)}, {"stopId", Text(r.stopId)},
        {"event", Event(r.event)}, {"requestId", Text(r.requestId)}, {"stateRevision", Count(r.expectedStateRevision)},
        {"thread", Thread(s.thread)}, {"tid", V::makeUInt(s.tid)}, {"threadCreationFileTime", Count(s.threadCreationTime)},
        {"mode", V::makeUInt(static_cast<unsigned>(s.mode))}});
}
bool StepValue(const V* v, n::NativeStepRequest& s)
{
    auto& r = s.release;
    return v && Shape(*v, 10) && OwnerValue(v->find("owner"), r.owner) && String(v->find("groupId"), r.groupId) &&
        String(v->find("stopId"), r.stopId) && EventValue(v->find("event"), r.event) &&
        String(v->find("requestId"), r.requestId) && Number(v->find("stateRevision"), r.expectedStateRevision) &&
        ThreadValue(v->find("thread"), s.thread) && UInt(v->find("tid"), s.tid) && s.tid &&
        Number(v->find("threadCreationFileTime"), s.threadCreationTime) && Enum(v->find("mode"), s.mode, 2);
}
template<class T, class Reader> bool Optional(const V* v, std::optional<T>& out, Reader reader)
{
    if (!v) return false;
    if (v->isNull()) { out.reset(); return true; }
    T value{};
    if (!reader(v, value)) return false;
    out = std::move(value);
    return true;
}
Ksword::Evidence::JsonLimits Limits(std::size_t bytes)
{
    Ksword::Evidence::JsonLimits limits;
    limits.maxTotalBytes = bytes;
    limits.maxStringBytes = 32768;
    limits.maxDepth = 16;
    limits.maxTotalNodes = 32768;
    limits.maxContainerItems = 4096;
    return limits;
}
} // namespace

std::wstring Wide(std::string_view text)
{
    if (text.empty()) return {};
    if (text.size() > INT_MAX) throw std::invalid_argument("UTF-8 text too large");
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (!size) throw std::invalid_argument("Invalid UTF-8");
    std::wstring out(size, L'\0');
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), size) != size)
        throw std::invalid_argument("Invalid UTF-8");
    return out;
}
std::string Utf8(std::wstring_view text)
{
    if (text.empty()) return {};
    if (text.size() > INT_MAX) throw std::invalid_argument("Unicode text too large");
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), nullptr, 0, nullptr, nullptr);
    if (!size) throw std::invalid_argument("Invalid Unicode");
    std::string out(size, '\0');
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, text.data(), static_cast<int>(text.size()), out.data(), size, nullptr, nullptr) != size)
        throw std::invalid_argument("Invalid Unicode");
    return out;
}

std::vector<n::ExecutionGroupSite> ReadSites(const std::wstring& path)
{
    // 单句柄固定读入，不读管道/设备，不允许配置在读入期间被写入或替换。
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) throw std::invalid_argument("Could not open --sites file");
    std::string text;
    try {
        LARGE_INTEGER size{};
        if (GetFileType(file) != FILE_TYPE_DISK || !GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 128 * 1024)
            throw std::invalid_argument("--sites must be a disk file of 1..131072 bytes");
        text.resize(static_cast<std::size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file, text.data(), static_cast<DWORD>(text.size()), &read, nullptr) || read != text.size())
            throw std::invalid_argument("Could not read complete --sites file");
    } catch (...) { CloseHandle(file); throw; }
    CloseHandle(file);
    if (text.starts_with("\xef\xbb\xbf")) throw std::invalid_argument("--sites UTF-8 BOM is forbidden");
    (void)Wide(text); // 严格核对整个文件 UTF-8，不只核对选中的字符串字段。
    const auto parsed = Ksword::Evidence::ParseJson(text, Limits(128 * 1024));
    std::uint32_t version = 0;
    const auto* listValue = parsed.value.find("sites");
    const auto* list = listValue ? listValue->asArray() : nullptr;
    if (!parsed.ok() || !Shape(parsed.value, 2) || !UInt(parsed.value.find("schemaVersion"), version) || version != 1 ||
        !list || list->empty() || list->size() > n::kOwnedExecutionGroupLimit)
        throw std::invalid_argument("--sites requires {schemaVersion:1,sites:[1..16 explicit site objects]}");
    std::vector<n::ExecutionGroupSite> result;
    for (const auto& value : *list) {
        n::ExecutionGroupSite site;
        const auto* object = value.asObject();
        const auto* expression = value.find("condition");
        if (!object || !UInt(value.find("pid"), site.pid) || !site.pid ||
            !Number(value.find("creationFileTime"), site.creationFileTime))
            throw std::invalid_argument("Each site requires numeric pid and canonical decimal-string creationFileTime");
        const auto* address = value.find("address");
        const auto* rva = value.find("rva");
        const auto* name = value.find("exactExport");
        const auto* imageHash = value.find("imageSha256"); // 可选输入约束独立于模块定位和条件。
        const auto* definition = value.find("definitionId"); // 只标识冻结RVA定义；实际配置由本轮sample提供。
        const std::size_t expected = 4 + (expression ? 1 : 0) + (imageHash ? 1 : 0) + (definition ? 1 : 0);
        if (object->size() != expected) throw std::invalid_argument("Site has unknown or missing fields");
        if (address) {
            if (rva || name || imageHash || definition || value.find("module") || !Number(address, site.address) || !Number(value.find("rangeBytes"), site.rangeBytes, true))
                throw std::invalid_argument("Private site requires decimal-string address and rangeBytes only");
        } else {
            std::string module;
            std::uint32_t offset = 0;
            if (!String(value.find("module"), module, 32768) || (rva != nullptr) == (name != nullptr) ||
                (rva && (!UInt(rva, offset) || !offset)) || (name && !String(name, site.exactExport)))
                throw std::invalid_argument("Image site requires absolute module and exactly one numeric rva or exactExport");
            site.modulePath = Wide(module);
            if (rva) site.rva = offset;
            if (definition && (!rva || !String(definition, site.definitionId, 36) ||
                !Ksword::ActionAnalyze::ProjectStorage::IsUuid(site.definitionId)))
            {
                throw std::invalid_argument("definitionId requires a canonical UUID and module+rva site");
            }
            if (imageHash)
            {
                std::string hash; // 请求中的规范小写SHA256，不读取本地同名路径补值。
                if (!String(imageHash, hash, 64) || hash.size() != 64 ||
                    hash.find_first_not_of("0123456789abcdef") != std::string::npos)
                {
                    throw std::invalid_argument("imageSha256 requires 64 lowercase hexadecimal characters for an image site");
                }
                site.imageSha256 = std::move(hash);
            }
        }
        if (expression) {
            std::string source;
            if (!String(expression, source, Ksword::ActionAnalyze::Rules::MaxPredicateExpressionBytes))
                throw std::invalid_argument("condition must be a nonempty expression of at most 8192 UTF-8 bytes");
            site.conditionSource = Wide(source);
            auto prepared = n::PrepareDataWatchCondition(site.conditionSource);
            if (prepared.diagnostic) throw std::invalid_argument(std::string("condition: ") + prepared.diagnostic +
                (prepared.location ? " at UTF-8 byte " + std::to_string(prepared.location->offset) : ""));
            site.condition = std::move(prepared.predicate);
        }
        result.push_back(std::move(site));
    }
    return result;
}

JsonValue StopToken(const n::NativeControlResult& state)
{
    JsonArray threads;
    for (const auto& t : state.frozenThreads) threads.push_back(V::makeObject({{"identity", Thread(t.identity)},
        {"tid", V::makeUInt(t.tid)}, {"creationFileTime", Count(t.creationTime)}}));
    V group = V::makeNull(), responsibility = V::makeNull(), pending = V::makeNull();
    if (state.group) {
        const auto& g = *state.group;
        JsonArray members, incidental;
        for (const auto& m : g.members) members.push_back(V::makeObject({{"threadId", Text(m.threadId)},
            {"state", V::makeUInt(static_cast<unsigned>(m.state))}, {"stopId", m.stopId ? Text(*m.stopId) : V::makeNull()},
            {"evidence", V::makeUInt(static_cast<unsigned>(m.evidence))}}));
        for (const auto& id : g.incidentalThreadIds) incidental.push_back(Text(id));
        group = V::makeObject({{"sampleId", Text(g.sampleId)}, {"sessionId", Text(g.sessionId)}, {"epoch", Text(g.epoch)},
            {"groupId", Text(g.groupId)}, {"stateRevision", Count(g.stateRevision)}, {"membershipRevision", Count(g.membershipRevision)},
            {"membershipSha256", Text(g.membershipSha256)}, {"state", V::makeUInt(static_cast<unsigned>(g.state))},
            {"origin", g.origin ? V::makeObject({{"threadId", Text(g.origin->threadId)},
                {"phase", V::makeUInt(static_cast<unsigned>(g.origin->phase))}, {"hold", V::makeUInt(static_cast<unsigned>(g.origin->hold))}}) : V::makeNull()},
            {"members", V::makeArray(std::move(members))}, {"incidentalQuality", V::makeUInt(static_cast<unsigned>(g.incidentalQuality))},
            {"incidentalThreadIds", V::makeArray(std::move(incidental))}, {"historical", V::makeBool(g.historical)},
            {"nativeEventState", g.nativeEventState ? V::makeUInt(static_cast<unsigned>(*g.nativeEventState)) : V::makeNull()}});
    }
    if (state.responsibility) {
        const auto& r = *state.responsibility;
        responsibility = V::makeObject({{"groupId", Text(r.groupId)}, {"event", Event(r.event)},
            {"actualEventThread", Thread(r.actualEventThread)}, {"stopId", Text(r.stopId)},
            {"state", V::makeUInt(static_cast<unsigned>(r.state))}, {"lastRequestId", r.lastRequestId ? Text(*r.lastRequestId) : V::makeNull()}});
    }
    if (state.pending) {
        const auto& p = *state.pending;
        pending = V::makeObject({{"event", Event(p.event)}, {"pid", V::makeUInt(p.pid)}, {"tid", V::makeUInt(p.tid)},
            {"eventCode", V::makeUInt(p.eventCode)}, {"exceptionCode", p.exceptionCode ? V::makeUInt(*p.exceptionCode) : V::makeNull()},
            {"exceptionFirstChance", p.exceptionFirstChance ? V::makeBool(*p.exceptionFirstChance) : V::makeNull()},
            {"ledgerOwned", V::makeBool(p.ledgerOwned)}, {"continuationIndeterminate", V::makeBool(p.continuationIndeterminate)}});
    }
    V binding = V::makeNull();
    if (state.breakpoint) {
        JsonArray ranges;
        for (const auto& range : state.breakpoint->executionRanges) ranges.push_back(V::makeObject({
            {"base", Count(range.base)}, {"bytes", Count(range.bytes)}, {"allocationBase", Count(range.allocationBase)}}));
        binding = V::makeObject({{"requestId", Text(state.breakpoint->requestId)}, {"state", V::makeUInt(static_cast<unsigned>(state.breakpoint->state))},
            {"address", Count(state.breakpoint->address)}, {"rangeBytes", Count(state.breakpoint->rangeBytes)},
            {"imageSha256", state.breakpoint->imageSha256 ? Text(*state.breakpoint->imageSha256) : V::makeNull()},
            {"waitingForModule", V::makeBool(state.breakpoint->waitingForModule)}, // 原owner真实等待状态，不能从零地址推断。
            {"executionRanges", V::makeArray(std::move(ranges))}});
    }
    V pause = V::makeNull(); // 主动暂停回执保留原owner和pause/N，ManualPause继续仍须完整事件与停止组。
    if (state.armedPause)
    {
        const auto& p = *state.armedPause; // 不是按旧stop补齐身份，全部取自原owner显示回执。
        pause = V::makeObject({{"owner", Owner(p.owner)}, {"requestId", Text(p.request.requestId)},
            {"pid", V::makeUInt(p.request.pid)}, {"creationFileTime", Count(p.request.processCreationTime)},
            {"authorized", V::makeBool(p.request.explicitlyAuthorized)},
            {"disposition", V::makeUInt(static_cast<unsigned>(p.request.disposition))},
            {"state", V::makeUInt(static_cast<unsigned>(p.state))},
            {"groupId", p.groupId ? Text(*p.groupId) : V::makeNull()},
            {"event", p.event ? Event(*p.event) : V::makeNull()}});
    }
    return V::makeObject({{"pid", V::makeUInt(state.pid)}, {"creationFileTime", Count(state.processCreationTime)},
        {"processInstanceId", Text(state.processInstanceId)}, {"status", V::makeUInt(static_cast<unsigned>(state.status))},
        {"group", std::move(group)}, {"responsibility", std::move(responsibility)}, {"pending", std::move(pending)},
        {"frozenThreads", V::makeArray(std::move(threads))}, {"stepRequest", state.step ? StepRequest(state.step->request) : V::makeNull()},
        {"stepState", state.step ? V::makeUInt(static_cast<unsigned>(state.step->state)) : V::makeNull()},
        {"attached", V::makeBool(state.attached)}, {"clean", V::makeBool(state.clean)},
        {"stopReason", V::makeUInt(static_cast<unsigned>(state.stopReason))}, {"armedPause", std::move(pause)}, {"breakpoint", std::move(binding)},
        {"hit", state.breakpointHit ? V::makeObject({{"address", Count(state.breakpointHit->address)}}) : V::makeNull()},
        {"stepObservedEvent", state.step && state.step->observedEvent ? Event(*state.step->observedEvent) : V::makeNull()},
        {"stepStopGroupId", state.step && state.step->stopGroupId ? Text(*state.step->stopGroupId) : V::makeNull()}});
}

bool ParseStopToken(const V& token, n::NativeControlResult& state)
{
    state = {};
    if (!Shape(token, 18) || !UInt(token.find("pid"), state.pid) || !state.pid ||
        !Number(token.find("creationFileTime"), state.processCreationTime) || !String(token.find("processInstanceId"), state.processInstanceId) ||
        !Enum(token.find("status"), state.status, 9) || !Boolean(token.find("attached"), state.attached) ||
        !Boolean(token.find("clean"), state.clean) || !Enum(token.find("stopReason"), state.stopReason, 3)) return false;
    if (!Optional(token.find("armedPause"), state.armedPause, [](const V* v, n::NativeArmedPauseReceipt& p)
    {
        // 精确校验原暂停请求及事件；拒绝缺字段、外来owner和越界枚举，不从当前现场补值。
        return Shape(*v, 9) && OwnerValue(v->find("owner"), p.owner) && String(v->find("requestId"), p.request.requestId) &&
            UInt(v->find("pid"), p.request.pid) && p.request.pid && Number(v->find("creationFileTime"), p.request.processCreationTime) &&
            Boolean(v->find("authorized"), p.request.explicitlyAuthorized) && Enum(v->find("disposition"), p.request.disposition, 1) &&
            Enum(v->find("state"), p.state, 6) && Optional(v->find("groupId"), p.groupId, [](const V* x, std::string& s) { return String(x, s); }) &&
            Optional(v->find("event"), p.event, EventValue);
    })) return false;
    if (!Optional(token.find("group"), state.group, [](const V* v, n::StopGroupSnapshot& g) {
        if (!Shape(*v, 14) || !String(v->find("sampleId"), g.sampleId) || !String(v->find("sessionId"), g.sessionId) ||
            !String(v->find("epoch"), g.epoch) || !String(v->find("groupId"), g.groupId) || !Number(v->find("stateRevision"), g.stateRevision) ||
            !Number(v->find("membershipRevision"), g.membershipRevision) || !String(v->find("membershipSha256"), g.membershipSha256) ||
            !Enum(v->find("state"), g.state, 9) || !Enum(v->find("incidentalQuality"), g.incidentalQuality, 2) ||
            !Boolean(v->find("historical"), g.historical)) return false;
        if (!Optional(v->find("origin"), g.origin, [](const V* x, n::OriginSnapshot& o) {
            return Shape(*x, 3) && String(x->find("threadId"), o.threadId) && Enum(x->find("phase"), o.phase, 3) && Enum(x->find("hold"), o.hold, 4);
        }) || !Optional(v->find("nativeEventState"), g.nativeEventState, [](const V* x, n::EventState& e) { return Enum(x, e, 5); })) return false;
        const auto* members = v->find("members");
        const auto* incidental = v->find("incidentalThreadIds");
        if (!members || !members->asArray() || !incidental || !incidental->asArray()) return false;
        for (const auto& x : *members->asArray()) {
            n::MemberSnapshot m{};
            if (!Shape(x, 4) || !String(x.find("threadId"), m.threadId) || !Enum(x.find("state"), m.state, 7) ||
                !Enum(x.find("evidence"), m.evidence, 4) || !Optional(x.find("stopId"), m.stopId,
                    [](const V* y, std::string& s) { return String(y, s); })) return false;
            g.members.push_back(std::move(m));
        }
        for (const auto& x : *incidental->asArray()) { std::string id; if (!String(&x, id)) return false; g.incidentalThreadIds.push_back(std::move(id)); }
        return true;
    })) return false;
    if (!Optional(token.find("responsibility"), state.responsibility, [](const V* v, n::EventResponsibility& r) {
        return Shape(*v, 6) && String(v->find("groupId"), r.groupId) && EventValue(v->find("event"), r.event) &&
            ThreadValue(v->find("actualEventThread"), r.actualEventThread) && String(v->find("stopId"), r.stopId) &&
            Enum(v->find("state"), r.state, 5) && Optional(v->find("lastRequestId"), r.lastRequestId,
                [](const V* x, std::string& s) { return String(x, s); });
    })) return false;
    if (!Optional(token.find("pending"), state.pending, [](const V* v, n::NativePendingEvent& p) {
        return Shape(*v, 8) && EventValue(v->find("event"), p.event) && UInt(v->find("pid"), p.pid) && UInt(v->find("tid"), p.tid) &&
            UInt(v->find("eventCode"), p.eventCode) && Boolean(v->find("ledgerOwned"), p.ledgerOwned) &&
            Boolean(v->find("continuationIndeterminate"), p.continuationIndeterminate) &&
            Optional(v->find("exceptionCode"), p.exceptionCode, [](const V* x, std::uint32_t& out) { return UInt(x, out); }) &&
            Optional(v->find("exceptionFirstChance"), p.exceptionFirstChance, [](const V* x, bool& out) { return Boolean(x, out); });
    })) return false;
    const auto* threads = token.find("frozenThreads");
    if (!threads || !threads->asArray()) return false;
    for (const auto& x : *threads->asArray()) {
        n::NativeFrozenThread t;
        if (!Shape(x, 3) || !ThreadValue(x.find("identity"), t.identity) || !UInt(x.find("tid"), t.tid) ||
            !Number(x.find("creationFileTime"), t.creationTime)) return false;
        state.frozenThreads.push_back(std::move(t));
    }
    const auto* step = token.find("stepRequest");
    if (!step) return false;
    if (!step->isNull()) {
        n::NativeStepReceipt receipt;
        if (!StepValue(step, receipt.request) || !Enum(token.find("stepState"), receipt.state, 5) ||
            !Optional(token.find("stepObservedEvent"), receipt.observedEvent, EventValue) ||
            !Optional(token.find("stepStopGroupId"), receipt.stopGroupId, [](const V* x, std::string& s) { return String(x, s); })) return false;
        state.step = std::move(receipt);
    } else if (!token.find("stepState") || !token.find("stepState")->isNull() ||
        !token.find("stepObservedEvent") || !token.find("stepObservedEvent")->isNull() ||
        !token.find("stepStopGroupId") || !token.find("stepStopGroupId")->isNull()) return false;
    if (!Optional(token.find("breakpoint"), state.breakpoint, [](const V* v, n::NativeBreakpointBinding& b) {
        // 新票据回传等待位；旧五/六字段票据仍可读，不从当前会话补造历史字段。
        const auto* hash = v->find("imageSha256"); // 可选的既有实测映像摘要字段。
        const auto* waiting = v->find("waitingForModule"); // 新增独立报告位，不授予控制资格。
        const auto fields = std::size_t{5} + (hash ? 1 : 0) + (waiting ? 1 : 0); // 精确形状仍拒绝未知字段。
        if (!Shape(*v, fields) || (waiting && !Boolean(waiting, b.waitingForModule)) ||
            !String(v->find("requestId"), b.requestId) || !Enum(v->find("state"), b.state, 6) || !Number(v->find("address"), b.address, true) ||
            !Number(v->find("rangeBytes"), b.rangeBytes, true)) return false;
        if (hash && !hash->isNull())
        {
            std::string observed; // 票据携带实测值；不从当前owner补造历史显示字段。
            if (!String(hash, observed, 64) || observed.size() != 64 ||
                observed.find_first_not_of("0123456789abcdef") != std::string::npos)
            {
                return false;
            }
            b.imageSha256 = std::move(observed);
        }
        const auto* ranges = v->find("executionRanges");
        if (!ranges || !ranges->asArray() || ranges->asArray()->size() > 64) return false;
        for (const auto& x : *ranges->asArray()) {
            n::NativeExecutionRange r;
            if (!Shape(x, 3) || !Number(x.find("base"), r.base) || !Number(x.find("bytes"), r.bytes) ||
                !Number(x.find("allocationBase"), r.allocationBase, true)) return false;
            b.executionRanges.push_back(r);
        }
        return true;
    }) || !Optional(token.find("hit"), state.breakpointHit, [](const V* v, n::NativeBreakpointHit& h) {
        return Shape(*v, 1) && Number(v->find("address"), h.address);
    })) return false;
    return true;
}

// 新表只包装原owner与完整控制值；不按PID从当前集合补充任何控制字段。
JsonValue SessionToken(const n::ExecutionGroupMember& member)
{
    return V::makeObject({{"owner", Owner(member.owner)}, {"control", StopToken(member.control)}});
}

bool ParseSessionToken(const V& token, n::ExecutionGroupSessionEntry& entry)
{
    entry = {}; // 原owner四字段与control完整形状都必须存在，失败不留下半份票据。
    const auto* state = token.find("control");
    return Shape(token, 2) && OwnerValue(token.find("owner"), entry.owner) && state && ParseStopToken(*state, entry.control);
}

std::string TokenText(const V& token)
{
    const auto json = Ksword::Evidence::WriteJson(token);
    constexpr char digits[] = "0123456789abcdef";
    std::string result;
    result.reserve(json.size() * 2);
    for (const unsigned char c : json) { result.push_back(digits[c >> 4]); result.push_back(digits[c & 15]); }
    return result;
}
bool ParseTokenText(std::string_view text, V& token)
{
    if (text.empty() || text.size() > 2 * kInputBytes || text.size() % 2) return false;
    std::string json;
    json.reserve(text.size() / 2);
    const auto digit = [](char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1; };
    for (std::size_t i = 0; i < text.size(); i += 2) {
        const int high = digit(text[i]), low = digit(text[i + 1]);
        if (high < 0 || low < 0) return false;
        json.push_back(static_cast<char>((high << 4) | low));
    }
    try { (void)Wide(json); } catch (...) { return false; }
    const auto parsed = Ksword::Evidence::ParseJson(json, Limits(kInputBytes));
    if (!parsed.ok()) return false;
    token = parsed.value;
    return true;
}

} // namespace ks::cli::action_analyze::execution_group
