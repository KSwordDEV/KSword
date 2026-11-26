// WriteProcessGroupMemorySnapshot 的最小自有目标原生验收。
// 只验证该 wrapper 的归档格式、令牌/计划一致性、旧 live 格式兼容和明确拒绝；
// 不重复 ProcessGroupMemorySnapshot 的 1313 项组矩阵，也不覆盖 SelectedMemorySnapshot/PassiveDirtyMemory 核心。
#include "../../../KswordCLI/ActionAnalyze/Control/OwnedProcessGroup.h"
#include "../../../KswordCLI/ActionAnalyze/Control/ProcessGroupMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Memory/SelectedMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectMemorySnapshot.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

namespace aa = Ksword::ActionAnalyze;
namespace memory = ks::cli::action_analyze::memory;
namespace native = ks::cli::action_analyze::control;
namespace archive = ks::cli::action_analyze::archive;
namespace ev = Ksword::Evidence;
namespace fs = std::filesystem;

std::size_t checks = 0;

void Check(bool passed, const char* description)
{
    if (!passed) {
        std::fprintf(stderr, "FAIL %s win32=%lu\n", description, GetLastError());
        std::exit(1);
    }
    ++checks;
}

class Handle {
public:
    explicit Handle(HANDLE value = nullptr) : value_(value) {}
    ~Handle() { if (value_) CloseHandle(value_); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    HANDLE Get() const { return value_; }
    void Reset(HANDLE value)
    {
        if (value_) CloseHandle(value_);
        value_ = value;
    }
private:
    HANDLE value_ = nullptr;
};

std::uint64_t FileTimeValue(const FILETIME& time) noexcept
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::string Sha256Hex(const std::uint8_t* data, std::size_t length)
{
    BCRYPT_ALG_HANDLE provider = nullptr;
    Check(BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0,
        "test opens sha256 provider");
    unsigned char digest[32]{};
    const NTSTATUS status = BCryptHash(provider, nullptr, 0, const_cast<PUCHAR>(data),
        static_cast<ULONG>(length), digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(provider, 0);
    Check(status >= 0, "test hashes bytes");
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    for (const auto byte : digest) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}

// 自有良性子进程：在继承的共享节写入自身视图基址和 64 字节已知模式，等待父进程释放。
int MemoryChild(const wchar_t* mappingArg, const wchar_t* readyArg, const wchar_t* stopArg)
{
    const Handle mapping(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(mappingArg, nullptr, 10))));
    const Handle ready(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(readyArg, nullptr, 10))));
    const Handle stopHandle(reinterpret_cast<HANDLE>(static_cast<std::uintptr_t>(std::wcstoull(stopArg, nullptr, 10))));
    void* view = MapViewOfFile(mapping.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!view) return 2;
    auto* bytes = static_cast<unsigned char*>(view);
    const std::uint64_t base = reinterpret_cast<std::uintptr_t>(view);
    std::memcpy(bytes, &base, sizeof(base));
    for (unsigned i = 0; i < 64; ++i) bytes[8 + i] = static_cast<unsigned char>(0x5A + (i % 7));
    if (!SetEvent(ready.Get())) {
        UnmapViewOfFile(view);
        return 2;
    }
    WaitForSingleObject(stopHandle.Get(), INFINITE);
    UnmapViewOfFile(view);
    return 0;
}

class MemoryFixture {
public:
    explicit MemoryFixture(wchar_t* executable)
    {
        job_.Reset(CreateJobObjectW(nullptr, nullptr));
        Check(job_.Get() != nullptr, "fixture-private-job");
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        Check(SetInformationJobObject(job_.Get(), JobObjectExtendedLimitInformation, &limits, sizeof(limits)) != FALSE,
            "fixture-job-kill-on-close");
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), nullptr, TRUE};
        mapping_.Reset(CreateFileMappingW(INVALID_HANDLE_VALUE, &attributes, PAGE_READWRITE, 0, 4096, nullptr));
        Check(mapping_.Get() != nullptr, "fixture-mapping");
        view_ = MapViewOfFile(mapping_.Get(), FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        Check(view_ != nullptr, "fixture-parent-view");
        ready_.Reset(CreateEventW(&attributes, FALSE, FALSE, nullptr));
        stop_.Reset(CreateEventW(&attributes, TRUE, FALSE, nullptr));
        Check(ready_.Get() && stop_.Get(), "fixture-events");

        HANDLE inherited[]{mapping_.Get(), ready_.Get(), stop_.Get()};
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --memory";
        for (auto handle : inherited) command += L" " + std::to_wstring(reinterpret_cast<std::uintptr_t>(handle));
        SIZE_T bytes = 0;
        InitializeProcThreadAttributeList(nullptr, 2, 0, &bytes);
        Check(bytes != 0, "fixture-attribute-size");
        std::vector<std::uintptr_t> storage((bytes + sizeof(std::uintptr_t) - 1) / sizeof(std::uintptr_t));
        STARTUPINFOEXW startup{};
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        Check(InitializeProcThreadAttributeList(startup.lpAttributeList, 2, 0, &bytes) != FALSE,
            "fixture-attribute-list");
        auto job = job_.Get();
        Check(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            inherited, sizeof(inherited), nullptr, nullptr) != FALSE, "fixture-handle-list");
        Check(UpdateProcThreadAttribute(startup.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_JOB_LIST,
            &job, sizeof(job), nullptr, nullptr) != FALSE, "fixture-job");
        PROCESS_INFORMATION process{};
        const auto created = CreateProcessW(executable, command.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
            &startup.StartupInfo, &process);
        DeleteProcThreadAttributeList(startup.lpAttributeList);
        Check(created != FALSE, "fixture-created");
        const Handle initialThread(process.hThread);
        process_.Reset(process.hProcess);
        pid = process.dwProcessId;
        Check(ResumeThread(initialThread.Get()) == 1, "fixture-started");
        Check(WaitForSingleObject(ready_.Get(), 5000) == WAIT_OBJECT_0, "fixture-known-bytes-ready");
        std::memcpy(&childBase_, view_, sizeof(childBase_));
        Check(childBase_ != 0, "fixture-child-view-base");
        const auto* probe = static_cast<const unsigned char*>(view_) + 8;
        for (unsigned i = 0; i < 64; ++i) Check(probe[i] == static_cast<unsigned char>(0x5A + (i % 7)),
            "fixture-known-byte-pattern");
        FILETIME creation{}, exitTime{}, kernel{}, user{};
        Check(GetProcessTimes(process_.Get(), &creation, &exitTime, &kernel, &user) != FALSE,
            "fixture-creation-time");
        creationTime = FileTimeValue(creation);
    }

    ~MemoryFixture() { if (view_) UnmapViewOfFile(view_); }
    MemoryFixture(const MemoryFixture&) = delete;
    MemoryFixture& operator=(const MemoryFixture&) = delete;

    native::ProcessGroupTarget Target() const { return native::ProcessGroupTarget{pid, creationTime}; }
    memory::Range Range() const { return memory::Range{childBase_ + 8, 64}; }
    unsigned char Byte(unsigned index) const { return static_cast<const unsigned char*>(view_)[8 + index]; }

    void CheckAttached(bool expected) const
    {
        BOOL debugging = FALSE;
        Check(CheckRemoteDebuggerPresent(process_.Get(), &debugging) && (debugging != FALSE) == expected,
            "fixture-independent-attachment-readback");
    }

    void Exit() const
    {
        Check(SetEvent(stop_.Get()) != FALSE, "fixture-signal-stop");
        Check(WaitForSingleObject(process_.Get(), 5000) == WAIT_OBJECT_0, "fixture-exited");
        DWORD code = 0;
        Check(GetExitCodeProcess(process_.Get(), &code) && code == 0, "fixture-exit-code");
    }

    DWORD pid = 0;
    std::uint64_t creationTime = 0;

private:
    Handle job_{CreateJobObjectW(nullptr, nullptr)};
    Handle process_;
    Handle mapping_;
    Handle ready_;
    Handle stop_;
    void* view_ = nullptr;
    std::uint64_t childBase_ = 0;
};

native::OwnerIdentity Identity(const std::string& sampleId, unsigned last)
{
    const std::string tail = std::to_string(last);
    return native::OwnerIdentity{sampleId,
        "20000000-0000-0000-0000-00000000000" + tail,
        "30000000-0000-0000-0000-00000000000" + tail,
        "40000000-0000-0000-0000-00000000000" + tail};
}

memory::Plan MakePlan(const MemoryFixture& fixture, const std::string& sampleId)
{
    memory::Plan plan;
    plan.sampleId = sampleId;
    plan.trackingEpoch = "archive-epoch-1";
    plan.target.machineId = "machine-archive";
    plan.target.bootId = "boot-archive";
    plan.target.processInstanceId = "instance-archive";
    plan.target.pid = fixture.pid;
    plan.target.creationFileTime100ns = fixture.creationTime;
    plan.range = fixture.Range();
    plan.rounds = 2;
    plan.intervalMs = 100;
    plan.authorizedOwnedProcess = true;
    return plan;
}

native::ProcessGroupStop StopOf(const native::ProcessGroupResult& group, const char* check)
{
    Check(group.members.size() == 1 && group.members[0].stop.has_value(), check);
    return *group.members[0].stop;
}

native::ProcessGroupResult HeldGroup(native::OwnedProcessGroup& group, const char* check)
{
    const auto deadline = GetTickCount64() + 5000;
    native::ProcessGroupResult result;
    do {
        result = group.Query();
        if (result.state == native::ProcessGroupState::HeldComplete && result.members.size() == 1 &&
            result.members[0].stop.has_value()) {
            Check(true, check);
            return result;
        }
        Sleep(1);
    } while (GetTickCount64() < deadline);
    Check(false, check);
    return result;
}

struct Record {
    std::string metadata;
    std::string bytes;
};

std::optional<ev::JsonValue> Parse(const std::string& text)
{
    auto parsed = ev::ParseJson(text);
    if (!parsed.ok()) return std::nullopt;
    return std::move(parsed.value);
}

bool Str(const ev::JsonValue& value, std::string_view key, std::string_view expected)
{
    const auto* field = value.find(key);
    std::string actual;
    return field && field->tryGetString(actual) && actual == expected;
}

bool U64(const ev::JsonValue& value, std::string_view key, std::uint64_t expected)
{
    const auto* field = value.find(key);
    std::uint64_t actual = 0;
    return field && field->tryGetU64(actual) && actual == expected;
}

bool BoolField(const ev::JsonValue& value, std::string_view key, bool expected)
{
    const auto* field = value.find(key);
    bool actual = !expected;
    return field && field->tryGetBool(actual) && actual == expected;
}

bool StopMatches(const ev::JsonValue& value, const native::ProcessGroupStop& stop)
{
    return Str(value, "groupId", stop.groupId) && Str(value, "stopId", stop.stopId) &&
        Str(value, "backendInstanceId", stop.event.backendInstanceId) &&
        U64(value, "pid", stop.target.pid) && U64(value, "creationFileTime", stop.target.creationFileTime) &&
        U64(value, "eventSerial", stop.event.serial) && U64(value, "stateRevision", stop.stateRevision);
}

bool ReadSegment(aa::ProjectDocument& project, const std::string& projectId, const std::string& sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    std::vector<Record>& records, archive::RawEvidenceScanResult& scan, std::string* prefixHash)
{
    records.clear();
    const auto visitor = [&](const auto&, const auto&, const std::vector<archive::DecodedRecord>& decoded) {
        for (const auto& record : decoded) {
            const auto* raw = std::get_if<archive::RawRecordV1>(&record.body);
            if (!raw) return false;
            records.push_back({std::string(raw->metadataJson), std::string(raw->inlineRawData)});
        }
        return true;
    };
    aa::ProjectRawEvidenceRead read{projectId, sampleId, ordinal, std::nullopt, previousSequence,
        visitor, std::nullopt, aa::ProjectEvidenceLane::MemorySnapshots};
    if (!project.ReadRawEvidenceSegment(read, scan, prefixHash)) return false;
    return true;
}

void CheckBytesAndSha(const std::vector<Record>& records, const MemoryFixture& fixture,
    const std::string& expectedSha, const char* tag)
{
    Check(records.size() == 3, tag);
    auto page = Parse(records[1].metadata);
    Check(page.has_value(), tag);
    Check(Str(*page, "kind", "selected-memory-page-v1") && Str(*page, "state", "sampled"), tag);
    std::string sha;
    const auto* shaField = page->find("sha256");
    Check(shaField && shaField->tryGetString(sha), tag);
    Check(records[1].bytes.size() == 64, tag);
    auto bytes = reinterpret_cast<const std::uint8_t*>(records[1].bytes.data());
    Check(sha == Sha256Hex(bytes, 64), tag);
    for (unsigned i = 0; i < 64; ++i) Check(records[1].bytes[i] == static_cast<char>(fixture.Byte(i)), tag);
    Check(!expectedSha.empty() && expectedSha == sha, tag);
}

void Run(const fs::path& scratch, wchar_t* executable)
{
    const auto projectPath = scratch / L"held-archive-project";
    aa::ProjectDocument project;
    Check(!!project.Create(projectPath.wstring(), {"Held memory archive fixture", ""}), "create project");
    const std::string projectId = project.Info()->projectId;

    aa::SampleInfo heldSample, partialSample, liveSample;
    Check(!!project.CreateSample("held-evidence", heldSample), "create held sample");
    Check(!!project.CreateSample("partial-evidence", partialSample), "create partial sample");
    Check(!!project.CreateSample("live-evidence", liveSample), "create live sample");

    // 先创建 sample，再用该 sample 配置 group：归档请求身份与冻结采样同源。
    MemoryFixture fixture(executable);
    native::OwnedProcessGroup group(Identity(heldSample.sampleId, 7));
    Check(group.Configure({fixture.Target()}, true, native::NativeTargetDisposition::ResumeAndDetach).state ==
        native::ProcessGroupState::Ready, "group-configured-after-sample-created");
    const auto plan = MakePlan(fixture, heldSample.sampleId);

    // 真实 live 采样（新 wrapper）：仅源与读前/读后证据不同，字节与旧 live 完全同形。
    native::ProcessMemorySnapshotRequest liveRequest{plan, native::ProcessMemorySource::LiveRead, std::nullopt};
    const auto live = native::CaptureProcessGroupMemory(group, liveRequest);
    Check(std::string(live.stage) == "process-memory-read-observed" && live.snapshot && live.snapshot->completeRange,
        "live-capture-succeeds");
    fixture.CheckAttached(false);

    // 真实持有停点：精确令牌读，归档写入前后不得 Continue 目标。
    const auto targets = std::vector<native::ProcessGroupTarget>{fixture.Target()};
    Check(group.Pause("group/1", std::span<const native::ProcessGroupTarget>(targets)).ledgerResult ==
        native::LedgerResult::Applied, "pause-applied");
    const auto held = HeldGroup(group, "held-complete");
    const auto stop = StopOf(held, "exact-stop");
    fixture.CheckAttached(true);

    native::ProcessMemorySnapshotRequest heldRequest{plan, native::ProcessMemorySource::HeldEvent, stop};
    const auto capture = native::CaptureProcessGroupMemory(group, heldRequest);
    Check(std::string(capture.stage) == "process-memory-read-observed" && capture.snapshot &&
        capture.snapshot->completeRange, "held-capture-succeeds");
    Check(capture.before && *capture.before == stop && capture.after && *capture.after == stop &&
        capture.heldAtBothChecks, "held-token-identical-both-checks");
    Check(group.Query().state == native::ProcessGroupState::HeldComplete && group.Query().members[0].stop &&
        *group.Query().members[0].stop == stop, "read-does-not-continue-target-before-archive");
    fixture.CheckAttached(true);

    // 新 wrapper 写独立 raw-memory/1：held 完整证据。
    aa::ProjectMemorySnapshotReceipt receipt;
    Check(!!aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, capture, receipt),
        "held-wrapper-writes-raw-memory-1");
    Check(receipt.verified && receipt.ordinal == 1 && receipt.completeRange && receipt.raw.flushed.has_value() &&
        aa::ProjectStorage::IsHash(receipt.sha256), "held-receipt-verified");
    Check(receipt.capturedBytes == 64 && receipt.unavailablePages == 0, "held-receipt-byte-counts");
    Check(group.Query().state == native::ProcessGroupState::HeldComplete && group.Query().members[0].stop &&
        *group.Query().members[0].stop == stop, "archive-write-does-not-continue-target");
    fixture.CheckAttached(true);

    // 同一 ProjectDocument 读句柄回读原 readContext / before / after / 真实字节 / SHA。
    std::vector<Record> records;
    archive::RawEvidenceScanResult scan;
    std::string prefixHash;
    Check(ReadSegment(project, projectId, heldSample.sampleId, 1, std::nullopt, records, scan, &prefixHash),
        "readback-held-segment");
    Check(scan.VerifiedBoundary(*receipt.raw.flushed) && prefixHash == receipt.sha256, "held-boundary-and-prefix-hash");
    auto planJson = Parse(records[0].metadata);
    Check(planJson.has_value(), "parse-held-plan");
    Check(Str(*planJson, "kind", "selected-memory-plan-v1") && Str(*planJson, "sampleId", heldSample.sampleId),
        "held-plan-identity");
    const auto* context = planJson->find("readContext");
    Check(context != nullptr, "held-plan-has-read-context");
    Check(Str(*context, "source", "held-event") && Str(*context, "stage", capture.stage), "held-context-source-stage");
    Check(U64(*context, "win32Error", capture.win32Error) && BoolField(*context, "heldAtBothChecks", true),
        "held-context-error-and-flag");
    const auto* before = context->find("before");
    const auto* after = context->find("after");
    Check(before && after && !before->isNull() && !after->isNull(), "held-context-has-both-tokens");
    Check(StopMatches(*before, stop) && StopMatches(*after, stop), "held-context-tokens-equal-exact-stop");
    auto page = Parse(records[1].metadata);
    Check(page.has_value(), "parse-held-page");
    std::string pageSha;
    const auto* shaField = page->find("sha256");
    Check(shaField && shaField->tryGetString(pageSha), "held-page-has-sha");
    CheckBytesAndSha(records, fixture, pageSha, "held-bytes-and-sha");

    // heldAtBothChecks=false 且 after 变化：保留前后令牌/部分证据，不伪称 held。
    auto partialCapture = capture;
    auto changed = stop;
    ++changed.stateRevision;
    partialCapture.after = changed;
    partialCapture.heldAtBothChecks = false;
    partialCapture.stage = "process-memory-stop-changed-during-read";
    partialCapture.win32Error = ERROR_RETRY;
    const auto partialPlan = MakePlan(fixture, partialSample.sampleId);
    partialCapture.request.plan = partialPlan;
    partialCapture.snapshot->plan = partialPlan;
    partialCapture.snapshot->round->effectivePlan = partialPlan;
    aa::ProjectMemorySnapshotReceipt partialReceipt;
    Check(!!aa::WriteProcessGroupMemorySnapshot(project, partialSample.sampleId, 1, std::nullopt, partialCapture,
        partialReceipt), "partial-wrapper-writes-raw-memory-1");
    std::vector<Record> partialRecords;
    archive::RawEvidenceScanResult partialScan;
    Check(ReadSegment(project, projectId, partialSample.sampleId, 1, std::nullopt, partialRecords, partialScan, nullptr),
        "readback-partial-segment");
    auto partialPlanJson = Parse(partialRecords[0].metadata);
    Check(partialPlanJson.has_value(), "parse-partial-plan");
    const auto* partialContext = partialPlanJson->find("readContext");
    Check(partialContext != nullptr && Str(*partialContext, "source", "held-event") &&
        BoolField(*partialContext, "heldAtBothChecks", false), "partial-keeps-held-source-without-held-claim");
    const auto* partialBefore = partialContext->find("before");
    const auto* partialAfter = partialContext->find("after");
    Check(partialBefore && StopMatches(*partialBefore, stop), "partial-before-keeps-original-token");
    Check(partialAfter && StopMatches(*partialAfter, changed), "partial-after-keeps-changed-token");
    {
        auto partialPage = Parse(partialRecords[1].metadata);
        std::string partialSha;
        const auto* partialShaField = partialPage->find("sha256");
        Check(partialShaField && partialShaField->tryGetString(partialSha), "partial-page-has-sha");
        CheckBytesAndSha(partialRecords, fixture, partialSha, "partial-bytes-intact");
    }

    // Live 新 wrapper 与旧 live writer 共享同一 raw-memory 链，旧格式无 readContext。
    const auto livePlan = MakePlan(fixture, liveSample.sampleId);
    auto liveCapture = live;
    liveCapture.request.plan = livePlan;
    liveCapture.snapshot->plan = livePlan;
    liveCapture.snapshot->round->effectivePlan = livePlan;
    aa::ProjectMemorySnapshotReceipt liveReceipt;
    Check(!!aa::WriteProcessGroupMemorySnapshot(project, liveSample.sampleId, 1, std::nullopt, liveCapture,
        liveReceipt), "live-wrapper-writes-raw-memory-1");
    std::vector<Record> liveRecords;
    archive::RawEvidenceScanResult liveScan;
    Check(ReadSegment(project, projectId, liveSample.sampleId, 1, std::nullopt, liveRecords, liveScan, nullptr),
        "readback-live-wrapper-segment");
    auto livePlanJson = Parse(liveRecords[0].metadata);
    Check(livePlanJson.has_value(), "parse-live-wrapper-plan");
    const auto* liveContext = livePlanJson->find("readContext");
    Check(liveContext && Str(*liveContext, "source", "live-read") &&
        BoolField(*liveContext, "heldAtBothChecks", false) && liveContext->find("before") &&
        liveContext->find("before")->isNull() && liveContext->find("after") &&
        liveContext->find("after")->isNull(), "live-wrapper-context-has-no-token");

    aa::ProjectMemorySnapshotReceipt legacyReceipt;
    Check(!!aa::WriteSelectedMemorySnapshot(project, liveSample.sampleId, 2,
        liveReceipt.raw.flushed->lastSequence, *liveCapture.snapshot, legacyReceipt),
        "legacy-live-writer-writes-raw-memory-2");
    std::vector<Record> legacyRecords;
    archive::RawEvidenceScanResult legacyScan;
    Check(ReadSegment(project, projectId, liveSample.sampleId, 2,
        liveReceipt.raw.flushed->lastSequence, legacyRecords, legacyScan, nullptr), "readback-legacy-live-segment");
    auto legacyPlanJson = Parse(legacyRecords[0].metadata);
    Check(legacyPlanJson.has_value() && legacyPlanJson->find("readContext") == nullptr,
        "legacy-live-format-has-no-read-context");
    {
        auto legacyPage = Parse(legacyRecords[1].metadata);
        std::string legacySha;
        const auto* legacyShaField = legacyPage->find("sha256");
        Check(legacyShaField && legacyShaField->tryGetString(legacySha), "legacy-page-has-sha");
        CheckBytesAndSha(legacyRecords, fixture, legacySha, "legacy-bytes-intact");
    }

    // 伪 plan / sample / token 不一致必须拒绝，且不得改变原生停点。
    aa::ProjectMemorySnapshotReceipt rejected;
    auto sampleMismatch = capture;
    Check(aa::WriteProcessGroupMemorySnapshot(project, "wrong-sample-id", 1, std::nullopt, sampleMismatch,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-wrong-sample-argument");
    auto snapshotSample = capture;
    snapshotSample.snapshot->plan.sampleId = "fake-snapshot-sample";
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, snapshotSample,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-snapshot-plan-sample");
    auto snapshotEpoch = capture;
    snapshotEpoch.snapshot->plan.trackingEpoch = "fake-epoch";
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, snapshotEpoch,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-snapshot-plan-epoch");
    auto snapshotTarget = capture;
    snapshotTarget.snapshot->plan.target.pid += 1;
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, snapshotTarget,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-snapshot-plan-target");
    auto snapshotRange = capture;
    snapshotRange.snapshot->plan.range.base += 1;
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, snapshotRange,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-snapshot-plan-range");
    auto fakeStop = capture;
    ++fakeStop.before->stateRevision;
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, fakeStop,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-fake-before-token");
    auto fakeAfter = capture;
    ++fakeAfter.after->stateRevision;
    Check(aa::WriteProcessGroupMemorySnapshot(project, heldSample.sampleId, 1, std::nullopt, fakeAfter,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-held-true-after-mismatch");
    auto liveWithStop = liveCapture;
    liveWithStop.request.stop = stop;
    Check(aa::WriteProcessGroupMemorySnapshot(project, liveSample.sampleId, 3, std::nullopt, liveWithStop,
        rejected).error == aa::ProjectError::InvalidArgument, "reject-live-with-stop");

    // 字节完整性由 CheckBytesAndSha 对 held=true 与 held=false 分别核对，与 held 标记独立。
    Check(group.Query().state == native::ProcessGroupState::HeldComplete && group.Query().members[0].stop &&
        *group.Query().members[0].stop == stop, "rejections-preserve-original-stop");
    fixture.CheckAttached(true);

    // 所有归档写完后才显式释放，证明写入过程没有 Continue 目标。
    const auto stops = std::vector<native::ProcessGroupStop>{stop};
    Check(group.Continue("group/2", std::span<const native::ProcessGroupStop>(stops)).ledgerResult ==
        native::LedgerResult::Applied, "continue-after-all-archives");
    Check(group.Close().clean, "group-closes-cleanly");
    fixture.CheckAttached(false);
    fixture.Exit();
    project.Close();
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc == 5 && std::wstring_view(argv[1]) == L"--memory")
        return MemoryChild(argv[2], argv[3], argv[4]);
    if (argc != 2) {
        std::fprintf(stderr, "usage: GroupMemoryArchiveTests.exe <scratch-dir>\n");
        return 2;
    }
    const fs::path scratch(argv[1]);
    Run(scratch, argv[0]);
    std::printf("RESULT=PASS checks=%zu failures=0\n", checks);
    return 0;
}
