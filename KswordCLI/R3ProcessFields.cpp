#include "R3ProcessShared.h"
#include "../shared/usermode/backend/process/ProcessEnrichment.h"
#include "../Ksword5.1/Ksword5.1/ksword/string/string.h"
#include <algorithm>
#include <set>
#include <sstream>
#include <wintrust.h>
#include <softpub.h>
namespace ks::cli {
namespace {
namespace backend = ks::r3::process;
using Id = backend::ProcessFieldId;
struct Field { const wchar_t* name; Id id; };
const Field fields[] = {
    {L"name",Id::Name},{L"path",Id::Path},{L"command-line",Id::CommandLine},{L"user",Id::User},{L"architecture",Id::ProcessType},
    {L"description",Id::Description},{L"elevated",Id::IsAdmin},{L"efficiency",Id::PowerThrottling},{L"status",Id::Status},
    {L"signature",Id::Signature},{L"ppl",Id::PplLevel},{L"package",Id::PackageName},{L"job",Id::JobObject},
    {L"uac-virtualization",Id::UacVirtualization},{L"dep",Id::DataExecutionPrevention},{L"cfg",Id::ControlFlowGuard},
    {L"stack-protection",Id::HardwareStackProtection},{L"dpi",Id::DpiAwareness},{L"enterprise",Id::EnterpriseContext},
    {L"gpu",Id::Gpu},{L"gpu-engine",Id::GpuEngine},{L"gpu-dedicated-memory",Id::GpuDedicatedMemory},{L"gpu-shared-memory",Id::GpuSharedMemory},
    {L"cpu-time",Id::CpuTime},{L"cycle-time",Id::CycleTime},{L"working-set",Id::WorkingSet},{L"peak-working-set",Id::PeakWorkingSet},
    {L"private-working-set",Id::PrivateWorkingSet},{L"commit-size",Id::CommitSize},{L"paged-pool",Id::PagedPool},{L"nonpaged-pool",Id::NonPagedPool},
    {L"page-faults",Id::PageFaults},{L"io-reads",Id::IoReads},{L"io-writes",Id::IoWrites},{L"io-other",Id::IoOther},
    {L"io-read-bytes",Id::IoReadBytes},{L"io-write-bytes",Id::IoWriteBytes},{L"io-other-bytes",Id::IoOtherBytes}
};
struct Value { bool available = false; Json data; Json nativeStatus; };
Json text(const std::string& value) { return Json::string(ks::str::Utf8ToUtf16(value)); }
Value feature(ks::process::ProcessFeatureState state) {
    using S = ks::process::ProcessFeatureState;
    const wchar_t* name = state == S::NotAllowed ? L"not-applicable" : state == S::Disabled ? L"disabled" :
        state == S::Enabled ? L"enabled" : state == S::EnabledPermanent ? L"enabled-permanent" : L"unknown";
    return {state != S::Unknown, Json::string(name)};
}
Value value(const backend::ProcessDetailEvidence& evidence, Id id) {
    const auto& r = evidence.record;
    switch (id) {
    case Id::Name: return {!r.processName.empty(), text(r.processName)};
    case Id::Path: return {!r.imagePath.empty(), text(r.imagePath)};
    case Id::CommandLine: return {!r.commandLine.empty(), text(r.commandLine)};
    case Id::User: return {!r.userName.empty(), text(r.userName)};
    case Id::ProcessType: return {r.architectureKnown, text(r.architectureText)};
    case Id::Description: return {!r.fileDescription.empty(), text(r.fileDescription)};
    case Id::IsAdmin: return {r.isAdminKnown, Json::boolean(r.isAdmin)};
    case Id::PowerThrottling: return {r.efficiencyModeSupported, Json::boolean(r.efficiencyModeEnabled)};
    case Id::Status: return {r.processStateKnown, Json::string(r.processSuspended ? L"suspended" : L"running")};
    case Id::Signature: {
        const auto s = r.signatureTrustStatus;
        const bool known = r.signatureEvaluated && (s == ERROR_SUCCESS || s == TRUST_E_NOSIGNATURE || s == CERT_E_EXPIRED ||
            s == TRUST_E_BAD_DIGEST || s == CERT_E_UNTRUSTEDROOT || s == CERT_E_CHAINING || s == TRUST_E_EXPLICIT_DISTRUST || s == TRUST_E_SUBJECT_NOT_TRUSTED);
        return {known, Json::object({{L"trusted", Json::boolean(r.signatureTrusted)}, {L"publisher", text(r.signaturePublisher)},
            {L"display", text(r.signatureState)}}), r.signatureEvaluated ? Json::hex(static_cast<DWORD>(s)) : Json{}};
    }
    case Id::PplLevel: return {r.protectionLevelKnown, Json::hex(r.protectionLevel)};
    case Id::PackageName: return {r.packageNameKnown, text(r.packageFullName)};
    case Id::JobObject: return {r.jobObjectKnown, Json::boolean(r.inJobObject)};
    case Id::UacVirtualization: return feature(r.uacVirtualizationState);
    case Id::DataExecutionPrevention: return feature(r.dataExecutionPreventionState);
    case Id::ControlFlowGuard: return feature(r.controlFlowGuardState);
    case Id::HardwareStackProtection: return feature(r.hardwareStackProtectionState);
    case Id::DpiAwareness: {
        using D = ks::process::ProcessDpiAwarenessLevel;
        const auto state = r.dpiAwarenessLevel;
        const wchar_t* name = state == D::Unaware ? L"unaware" : state == D::SystemAware ? L"system" : state == D::PerMonitorAware ? L"per-monitor" :
            state == D::PerMonitorAwareV2 ? L"per-monitor-v2" : state == D::UnawareGdiScaled ? L"unaware-gdi-scaled" : L"unknown";
        return {state != D::Unknown, Json::string(name)};
    }
    case Id::EnterpriseContext: return {evidence.extra.enterpriseKnown, Json::object({{L"states", Json::hex(evidence.extra.enterpriseStates)},
        {L"identity", Json::string(evidence.extra.enterpriseIdentity)}}), Json::hex(static_cast<DWORD>(evidence.extra.enterpriseStatus))};
    case Id::Gpu: return {r.gpuUsageKnown, Json::real(r.gpuPercent)};
    case Id::GpuEngine: return {r.gpuUsageKnown, text(r.gpuEngineText)};
    case Id::GpuDedicatedMemory: return {r.gpuMemoryKnown, Json::count(r.gpuDedicatedMemoryBytes)};
    case Id::GpuSharedMemory: return {r.gpuMemoryKnown, Json::count(r.gpuSharedMemoryBytes)};
    case Id::CpuTime: return {r.dynamicCountersReady, Json::count(r.rawCpuTime100ns)};
    case Id::CycleTime: return {r.cycleTimeKnown, Json::count(r.cycleTime)};
    case Id::WorkingSet: return {r.dynamicCountersReady, Json::count(r.rawWorkingSetBytes)};
    case Id::PeakWorkingSet: return {r.memoryDetailKnown, Json::count(r.peakWorkingSetBytes)};
    case Id::PrivateWorkingSet: return {r.privateWorkingSetKnown, Json::count(r.privateWorkingSetBytes)};
    case Id::CommitSize: return {r.memoryDetailKnown, Json::count(r.commitSizeBytes)};
    case Id::PagedPool: return {r.memoryDetailKnown, Json::count(r.pagedPoolBytes)};
    case Id::NonPagedPool: return {r.memoryDetailKnown, Json::count(r.nonPagedPoolBytes)};
    case Id::PageFaults: return {r.memoryDetailKnown, Json::count(r.pageFaultCount)};
    case Id::IoReads: return {r.ioDetailKnown, Json::count(r.ioReadOperationCount)};
    case Id::IoWrites: return {r.ioDetailKnown, Json::count(r.ioWriteOperationCount)};
    case Id::IoOther: return {r.ioDetailKnown, Json::count(r.ioOtherOperationCount)};
    case Id::IoReadBytes: return {r.ioDetailKnown, Json::count(r.ioReadTransferBytes)};
    case Id::IoWriteBytes: return {r.ioDetailKnown, Json::count(r.ioWriteTransferBytes)};
    case Id::IoOtherBytes: return {r.ioDetailKnown, Json::count(r.ioOtherTransferBytes)};
    default: return {};
    }
}
std::vector<const Field*> selected(const Args& args) {
    const auto names = args.get(L"--fields", L"command-line,user,architecture,elevated");
    std::vector<const Field*> result; std::set<std::wstring> seen;
    if (names == L"all") { for (const auto& f : fields) result.push_back(&f); return result; }
    std::wistringstream stream(names); std::wstring name;
    while (std::getline(stream, name, L',')) {
        const auto it = std::find_if(std::begin(fields), std::end(fields), [&name](const Field& f) { return name == f.name; });
        if (it == std::end(fields) || !seen.insert(name).second) throw std::invalid_argument("unknown or duplicate --fields name; use process detail fields list");
        result.push_back(it);
    }
    if (result.empty() || names.back() == L',') throw std::invalid_argument("empty --fields name");
    return result;
}
Result query(const Args& args) {
    const auto selection = selected(args); process::Lease lease(args);
    if (!lease.handle.valid() || !lease.matches || !lease.alive()) return {3, Json::object({{L"target", lease.json()}}), {L"Target identity could not be acquired, changed, or has exited."}};
    auto snapshot = backend::EnumerateProcessesByNtQuerySystemInformation();
    if (!snapshot.success || snapshot.malformed) return {snapshot.malformed ? 4 : 3, Json::object({{L"target", lease.json()}, {L"ntStatus", Json::hex(static_cast<DWORD>(snapshot.ntStatus))}}), {snapshot.diagnosticText}};
    std::erase_if(snapshot.rows, [&lease](const auto& row) { return row.processId != lease.pid || row.creationTime100ns != lease.creationTime; });
    if (snapshot.rows.empty()) return {3, Json::object({{L"target", lease.json()}}), {L"Target identity is absent from the native snapshot."}};
    std::vector<Id> columns; for (const auto* f : selection) columns.push_back(f->id);
    std::unordered_map<std::wstring, std::string> cache; std::optional<backend::ProcessDetailEvidence> evidence;
    backend::ApplyMainProcessDetails(snapshot.rows, columns, cache, true, [&evidence](const auto& observed) { evidence = observed; });
    if (!lease.alive()) return {3, Json::object({{L"target", lease.json()}}), {L"Target exited during field collection."}};
    std::vector<Json> rows; std::uint32_t available = 0;
    for (const auto* f : selection) {
        const auto observed = evidence ? value(*evidence, f->id) : Value{};
        if (observed.available) ++available;
        const auto displayed = snapshot.rows.front().detailTexts.find(static_cast<std::uint8_t>(f->id));
        rows.push_back(Json::object({{L"name", Json::string(f->name)}, {L"available", Json::boolean(observed.available)},
            {L"value", observed.available ? observed.data : Json{}}, {L"nativeStatus", observed.nativeStatus},
            {L"display", displayed == snapshot.rows.front().detailTexts.end() ? Json{} : Json::string(displayed->second)}}));
    }
    return {available == selection.size() ? 0 : available ? 6 : 5, Json::object({{L"target", lease.json()},
        {L"source", Json::string(L"shared R3 process enrichment")}, {L"requestedCount", Json::number(static_cast<std::uint32_t>(selection.size()))},
        {L"availableCount", Json::number(available)}, {L"fields", Json::array(rows)}}), available == selection.size() ?
            std::vector<std::wstring>{} : std::vector<std::wstring>{L"Some requested fields lack reliable evidence; display text is retained only as backend presentation."}};
}
}
void registerProcessFields() {
    addCommand({L"process detail fields list", L"KswordCLI.exe process detail fields list [--backend r3] [--json]",
        L"List selectable R3 process field names.", L"Optional: --backend r3, --json.",
        L"Field names select existing backend queries. R0-only EPROCESS fields and unsampled rates are not published here.", [](const Args&) {
            std::vector<Json> rows; for (const auto& f : fields) rows.push_back(Json::string(f.name));
            return Result{0, Json::object({{L"fields", Json::array(rows)}, {L"defaultFields", Json::string(L"command-line,user,architecture,elevated")}})};
        }});
    addCommand({L"process detail fields query", L"KswordCLI.exe process detail fields query --pid PID [--creation-time FILETIME] [--fields NAME[,NAME...]|all] [--backend r3] [--json]",
        L"Read selected extended fields with independent availability and typed values.", L"Required: --pid. Optional: --creation-time expected identity, --fields (use fields list), --backend r3, --json.",
        L"Fields: target PID/creationTime, availableCount, fields with available/value/nativeStatus/display. Retains an identity handle until completion. Unknown fields are null; partial availability returns 6, none returns 5. A single PDH query can be warming up; display text never determines success.", query});
}
}
