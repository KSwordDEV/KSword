#include "../SelectedMemorySnapshot.h"
#include "../../Project/ProjectMemorySnapshot.h"
#include "../../Project/ProjectDocument.h"
#include "../../Project/ProjectRawEvidence.h"
#include "../../Project/ProjectStorage.h"

#include <bcrypt.h>

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace {

namespace aa = Ksword::ActionAnalyze;
namespace archive = ks::cli::action_analyze::archive;
namespace memory = ks::cli::action_analyze::memory;
namespace ev = Ksword::Evidence;
namespace fs = std::filesystem;
using Ksword::ActionAnalyze::ProjectStorage::IsHash;

std::size_t checks = 0; // 通过的本机断言数。
std::size_t scenarios = 0; // 已完成的场景数。

// 每项在实际执行后计数，失败时报告对应检查并停止测试。
void Check(bool passed, const char* description)
{
    if (!passed) {
        std::cerr << "FAIL " << description << '\n';
        std::exit(1);
    }
    ++checks;
}

void Scenario(const char* name)
{
    ++scenarios;
    std::cout << "SCENARIO " << scenarios << ' ' << name << '\n';
}

// ---- 夹具工具 ----------------------------------------------------------

constexpr std::uint64_t kSyntheticPage = 0x1000; // 合成归档快照使用的页大小。

std::uint8_t PatternAt(std::uint64_t address)
{
    std::uint64_t mixed = address + 0x9E3779B97F4A7C15ull;
    mixed ^= mixed >> 31;
    mixed *= 0xBF58476D1CE4E5B9ull;
    mixed ^= mixed >> 28;
    return static_cast<std::uint8_t>(mixed >> 40);
}

void FillPattern(std::uint64_t base, std::size_t length)
{
    auto* bytes = reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(base));
    for (std::size_t index = 0; index < length; ++index) bytes[index] = PatternAt(base + index);
}

std::vector<std::uint8_t> ExpectedPattern(std::uint64_t base, std::size_t length)
{
    std::vector<std::uint8_t> bytes(length);
    for (std::size_t index = 0; index < length; ++index) bytes[index] = PatternAt(base + index);
    return bytes;
}

memory::Sha256 HashBytes(const std::uint8_t* data, std::size_t length)
{
    memory::Sha256 digest{};
    BCRYPT_ALG_HANDLE provider = nullptr;
    Check(BCryptOpenAlgorithmProvider(&provider, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0, "test opens sha256 provider");
    const NTSTATUS status = BCryptHash(provider, nullptr, 0, const_cast<PUCHAR>(data),
        static_cast<ULONG>(length), digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(provider, 0);
    Check(status >= 0, "test hashes bytes");
    return digest;
}

std::string Hex(const memory::Sha256& digest)
{
    static constexpr char digits[] = "0123456789abcdef";
    std::string text;
    text.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        text.push_back(digits[byte >> 4]);
        text.push_back(digits[byte & 15]);
    }
    return text;
}

std::uint64_t FileTimeValue(const FILETIME& time) noexcept
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::uint64_t SelfCreationTime()
{
    FILETIME creation{}, exit{}, kernel{}, user{};
    Check(GetProcessTimes(GetCurrentProcess(), &creation, &exit, &kernel, &user), "query self creation time");
    return FileTimeValue(creation);
}

memory::Plan SelfPlan(const char* sampleId, std::uint64_t base, std::uint64_t length)
{
    memory::Plan plan;
    plan.sampleId = sampleId;
    plan.trackingEpoch = "epoch-self";
    plan.target.machineId = "machine-local";
    plan.target.bootId = "boot-local";
    plan.target.processInstanceId = "proc-self";
    plan.target.pid = GetProcessId(GetCurrentProcess());
    plan.target.creationFileTime100ns = SelfCreationTime();
    plan.range = {base, length};
    plan.rounds = std::nullopt;
    plan.intervalMs = 10;
    plan.authorizedOwnedProcess = true;
    return plan;
}

memory::Plan SyntheticPlan(const std::string& sampleId, std::uint64_t base, std::uint64_t length)
{
    memory::Plan plan;
    plan.sampleId = sampleId;
    plan.trackingEpoch = "epoch-1";
    plan.target.machineId = "machine-a";
    plan.target.bootId = "boot-a";
    plan.target.processInstanceId = "proc-a";
    plan.target.pid = 4242;
    plan.target.creationFileTime100ns = 13300000000000000ull;
    plan.range = {base, length};
    plan.rounds = std::nullopt;
    plan.intervalMs = 10;
    plan.authorizedOwnedProcess = true;
    return plan;
}

memory::Mapping SyntheticMapping(std::uint64_t pageBase)
{
    memory::Mapping mapping;
    mapping.region = {pageBase, kSyntheticPage};
    mapping.allocationBase = pageBase;
    mapping.state = MEM_COMMIT;
    mapping.type = MEM_PRIVATE;
    mapping.protection = PAGE_READWRITE;
    mapping.allocationProtection = PAGE_READWRITE;
    return mapping;
}

struct SpecPage {
    memory::PageStatus status = memory::PageStatus::Sampled;
    std::uint64_t base = 0;
    std::uint32_t length = kSyntheticPage;
    std::vector<std::uint8_t> bytes; // 仅 Sampled 页提供完整字节。
};

// 合成一次显式单轮快照；content 摘要按原字节重算，保证自身一致。
memory::SelectedMemorySnapshot SyntheticSnapshot(const memory::Plan& plan, const std::vector<SpecPage>& pages)
{
    memory::SelectedMemorySnapshot snapshot;
    snapshot.plan = plan;
    snapshot.status.state = memory::State::Stopped;
    snapshot.status.pointerWidth = 64;
    snapshot.status.pageSize = kSyntheticPage;
    snapshot.status.qpcFrequency = 10000000;
    snapshot.status.attemptedRounds = 1;
    snapshot.status.fullRounds = 1;
    snapshot.status.plannedPages = static_cast<std::uint32_t>(pages.size());
    memory::Round round;
    round.effectivePlan = plan;
    round.ordinal = 1;
    round.beginQpc = 1000;
    round.endQpc = 2000;
    round.allPagesVisited = true;
    for (const auto& spec : pages) {
        memory::PageObservation page;
        page.pageBase = spec.base;
        page.sampledRange = {spec.base, spec.length};
        page.status = spec.status;
        if (spec.status == memory::PageStatus::Sampled) {
            const auto mapping = SyntheticMapping(spec.base);
            page.before = mapping;
            page.after = mapping;
            page.mappingGeneration = 1;
            page.readQpc = memory::QpcWindow{300, 400};
            page.returnedBytes = spec.bytes.size();
            memory::ContentSample content;
            content.roundOrdinal = 1;
            content.version = 1;
            content.readQpc = *page.readQpc;
            content.sha256 = HashBytes(spec.bytes.data(), spec.bytes.size());
            content.origin = memory::ContentOrigin::Baseline;
            page.content = content;
            ++snapshot.status.sampledPages;
        } else {
            ++snapshot.status.unavailablePages;
        }
        memory::        CapturedMemoryPage captured;
        captured.observation = page;
        captured.bytes = spec.bytes;
        round.pages.push_back(std::move(page));
        if (spec.status == memory::PageStatus::Sampled) snapshot.captured.push_back(std::move(captured));
    }
    snapshot.round = std::move(round);
    return snapshot;
}

void RestorePage(std::uint64_t base)
{
    VirtualAlloc(reinterpret_cast<void*>(static_cast<std::uintptr_t>(base)), kSyntheticPage,
        MEM_COMMIT, PAGE_READWRITE);
    DWORD oldProtect = 0;
    VirtualProtect(reinterpret_cast<void*>(static_cast<std::uintptr_t>(base)), kSyntheticPage,
        PAGE_READWRITE, &oldProtect);
}

std::vector<std::uint8_t> ReadFileBytes(const fs::path& path)
{
    std::ifstream file(path, std::ios::binary);
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

void WriteFileBytes(const fs::path& path, const std::vector<std::uint8_t>& bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Check(!!file, "rewrite fixture segment bytes");
}

void CheckU64(const ev::JsonValue& object, std::string_view key, std::uint64_t expected, const char* what)
{
    const auto* field = object.find(key);
    std::uint64_t value = 0;
    Check(field && field->tryGetU64(value) && value == expected, what);
}

void CheckText(const ev::JsonValue& object, std::string_view key, std::string_view expected, const char* what)
{
    const auto* field = object.find(key);
    std::string value;
    Check(field && field->tryGetString(value) && value == expected, what);
}

// ---- 场景 1：本机自采样，多页已知字节精确比对与采样 SHA ----------------

void ScenarioSelfCapture()
{
    Scenario("self multi-page unaligned capture with known bytes");
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    const auto pageSize = static_cast<std::uint64_t>(info.dwPageSize);
    Check(pageSize && (pageSize & (pageSize - 1)) == 0, "page size is a power of two");

    constexpr std::uint64_t kPages = 5;
    void* region = VirtualAlloc(nullptr, static_cast<SIZE_T>(kPages * pageSize),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(region != nullptr, "allocate fixture region");
    const auto base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region));
    FillPattern(base, static_cast<std::size_t>(kPages * pageSize));

    const auto plan = SelfPlan("fixture-sample", base + 0x40, kPages * pageSize - 0x40 - 0x100);
    const auto snapshot = CaptureSelectedMemory(GetCurrentProcess(), plan);

    Check(snapshot.status.state == memory::State::Stopped, "capture finishes Stopped");
    Check(snapshot.completeRange, "unaligned full range completes");
    Check(snapshot.status.pointerWidth == 64, "self pointer width is 64");
    Check(snapshot.status.pageSize == pageSize, "status reports native page size");
    Check(snapshot.status.plannedPages == kPages, "planned pages span unaligned edges");
    Check(snapshot.status.unavailablePages == 0 && snapshot.status.sampledPages == kPages, "all pages sampled");
    Check(snapshot.round.has_value(), "round recorded");
    Check(snapshot.round->allPagesVisited && snapshot.round->endQpc.has_value(), "round visited all pages and closed");
    Check(snapshot.round->effectivePlan.target == plan.target &&
        snapshot.round->effectivePlan.sampleId == plan.sampleId &&
        snapshot.round->effectivePlan.trackingEpoch == plan.trackingEpoch &&
        snapshot.round->effectivePlan.range == plan.range, "round binds frozen plan");
    Check(snapshot.captured.size() == kPages, "captured pairs with every sampled page");

    const auto firstPage = base / pageSize;
    for (std::uint64_t index = 0; index < kPages; ++index) {
        const auto pageBase = (firstPage + index) * pageSize;
        const auto start = (std::max)(pageBase, plan.range.base);
        const auto end = (std::min)(pageBase + pageSize, plan.range.base + plan.range.length);
        const auto& page = snapshot.round->pages[static_cast<std::size_t>(index)];
        const auto& captured = snapshot.captured[static_cast<std::size_t>(index)];
        Check(page.pageBase == pageBase, "page base matches real allocation address");
        Check(page.status == memory::PageStatus::Sampled && page.content.has_value(), "page sampled");
        Check(page.sampledRange == memory::Range{start, end - start}, "sampled subrange identity");
        Check(page.before.has_value() && page.before == page.after, "stable mapping before and after read");
        Check(page.before->protection == static_cast<std::uint32_t>(PAGE_READWRITE), "mapping protection recorded");
        Check(page.readQpc.has_value() && page.readQpc->begin <= page.readQpc->end, "read qpc window recorded");
        Check(page.returnedBytes == end - start, "returned bytes equal subrange");
        Check(captured.observation.pageBase == pageBase, "captured observation identity");
        Check(captured.bytes == ExpectedPattern(start, static_cast<std::size_t>(end - start)),
            "captured bytes exactly match known pattern");
        Check(captured.observation.content.has_value() &&
            captured.observation.content->sha256 == HashBytes(captured.bytes.data(), captured.bytes.size()),
            "captured bytes hash equals sampled sha");
        Check(page.content->sha256 == captured.observation.content->sha256, "row sha matches captured sha");
        Check(page.content->version == 1 && page.content->origin == memory::ContentOrigin::Baseline,
            "first sample records baseline version");
    }
    Check(VirtualFree(region, 0, MEM_RELEASE), "release capture fixture region");
}

// ---- 场景 2：NOACCESS / 未提交 / Guard 失败页的部分结果 ---------------

void ScenarioPartialFailures()
{
    Scenario("failed pages keep partial results without consuming guard");
    SYSTEM_INFO info{};
    GetNativeSystemInfo(&info);
    const auto pageSize = static_cast<std::uint64_t>(info.dwPageSize);
    constexpr std::uint64_t kPages = 4;
    void* region = VirtualAlloc(nullptr, static_cast<SIZE_T>(kPages * pageSize),
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(region != nullptr, "allocate mixed-protection region");
    const auto base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region));
    FillPattern(base, static_cast<std::size_t>(kPages * pageSize));

    auto* page1 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(base + pageSize));
    auto* page2 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(base + 2 * pageSize));
    auto* page3 = reinterpret_cast<void*>(static_cast<std::uintptr_t>(base + 3 * pageSize));
    DWORD oldProtect = 0;
    Check(VirtualProtect(page1, static_cast<SIZE_T>(pageSize), PAGE_NOACCESS, &oldProtect), "make page inaccessible");
    Check(VirtualFree(page2, static_cast<SIZE_T>(pageSize), MEM_DECOMMIT), "decommit second page");
    Check(VirtualProtect(page3, static_cast<SIZE_T>(pageSize), PAGE_READWRITE | PAGE_GUARD, &oldProtect),
        "arm guard page");

    const auto plan = SelfPlan("fixture-partial", base, kPages * pageSize);
    const auto snapshot = CaptureSelectedMemory(GetCurrentProcess(), plan);

    Check(snapshot.status.state == memory::State::Stopped, "capture finishes Stopped");
    Check(!snapshot.completeRange, "range with failed pages is not complete");
    Check(snapshot.round.has_value() && snapshot.round->pages.size() == kPages && snapshot.round->allPagesVisited,
        "all four pages visited");
    Check(snapshot.captured.size() == 1, "only the readable page produced bytes");
    Check(snapshot.status.unavailablePages == 3 && snapshot.status.sampledPages == 1, "status counts partial results");
    const auto& page0 = snapshot.round->pages[0];
    const auto& page1Row = snapshot.round->pages[1];
    const auto& page2Row = snapshot.round->pages[2];
    const auto& page3Row = snapshot.round->pages[3];
    Check(page0.status == memory::PageStatus::Sampled && page0.content.has_value(), "committed page sampled");
    Check(page0.pageBase == base, "committed page identity");
    Check(snapshot.captured[0].bytes == ExpectedPattern(base, static_cast<std::size_t>(pageSize)),
        "committed page bytes exact");
    Check(page1Row.status == memory::PageStatus::NotReadable, "noaccess page reports not readable");
    Check(page2Row.status == memory::PageStatus::NotCommitted, "decommitted page reports not committed");
    Check(page3Row.status == memory::PageStatus::Guarded, "guard page reports guarded");
    Check(!page1Row.returnedBytes && !page2Row.returnedBytes && !page3Row.returnedBytes,
        "failed pages never attempt a read");
    Check(page1Row.issue.stage == memory::Stage::None && page2Row.issue.stage == memory::Stage::None &&
        page3Row.issue.stage == memory::Stage::None, "skipped pages carry no fabricated error");

    MEMORY_BASIC_INFORMATION mbi{};
    Check(VirtualQueryEx(GetCurrentProcess(), page3, &mbi, sizeof(mbi)) == sizeof(mbi), "query guard page after capture");
    Check((mbi.Protect & PAGE_GUARD) != 0 && mbi.State == MEM_COMMIT, "guard flag survives sampling");
    Check(VirtualQueryEx(GetCurrentProcess(), page1, &mbi, sizeof(mbi)) == sizeof(mbi), "query noaccess page after capture");
    Check(mbi.Protect == PAGE_NOACCESS, "noaccess protection unchanged");

    Check(VirtualProtect(page1, static_cast<SIZE_T>(pageSize), PAGE_READWRITE, &oldProtect), "restore noaccess page");
    Check(VirtualProtect(page3, static_cast<SIZE_T>(pageSize), PAGE_READWRITE, &oldProtect), "restore guard page");
    Check(VirtualAlloc(page2, static_cast<SIZE_T>(pageSize), MEM_COMMIT, PAGE_READWRITE), "recommit page");
    Check(VirtualFree(region, 0, MEM_RELEASE), "release mixed-protection region");

    // 纯 reserve 区域同样返回未提交，不产生捕获字节。
    void* reserved = VirtualAlloc(nullptr, pageSize, MEM_RESERVE, PAGE_NOACCESS);
    Check(reserved != nullptr, "reserve fixture region");
    const auto reservedBase = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(reserved));
    const auto reservedPlan = SelfPlan("fixture-reserved", reservedBase, pageSize);
    const auto reservedSnapshot = CaptureSelectedMemory(GetCurrentProcess(), reservedPlan);
    Check(reservedSnapshot.round.has_value() &&
        reservedSnapshot.round->pages[0].status == memory::PageStatus::NotCommitted, "reserved page not committed");
    Check(reservedSnapshot.captured.empty() && !reservedSnapshot.completeRange, "reserved page yields no bytes");
    Check(VirtualFree(reserved, 0, MEM_RELEASE), "release reserved region");
}

// ---- 场景 3：错 creation / 退出目标 / 取消 / 零范围 / 溢出 -------------

void ScenarioRejections()
{
    Scenario("identity, exit, cancel and plan boundaaries");
    // 错误 creation 时间判定为实例不匹配。
    auto mismatchPlan = SelfPlan("fixture-mismatch", 0x10000, 0x1000);
    mismatchPlan.target.creationFileTime100ns += 1;
    const auto mismatch = CaptureSelectedMemory(GetCurrentProcess(), mismatchPlan);
    Check(mismatch.status.state == memory::State::Rejected &&
        mismatch.status.issue.stage == memory::Stage::ProcessMismatch, "wrong creation time rejected");
    Check(mismatch.round == std::nullopt && mismatch.captured.empty(), "rejected capture has no rows or bytes");

    // 已退出目标：挂起自有副本后终止，句柄与实例身份仍真实。
    wchar_t exePath[MAX_PATH]{};
    Check(GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0, "query self image path");
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    PROCESS_INFORMATION child{};
    std::wstring command = L"\"" + std::wstring(exePath) + L"\" --dead-fixture";
    Check(CreateProcessW(exePath, command.data(), nullptr, nullptr, FALSE, CREATE_SUSPENDED,
        nullptr, nullptr, &startup, &child), "spawn suspended fixture child");
    Check(TerminateProcess(child.hProcess, 0), "terminate fixture child");
    Check(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0, "fixture child exited");
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    Check(GetProcessTimes(child.hProcess, &creation, &exitTime, &kernel, &user), "query dead child creation");
    memory::Plan exitedPlan = SelfPlan("fixture-exited", 0x10000, 0x1000);
    exitedPlan.target.pid = GetProcessId(child.hProcess);
    exitedPlan.target.creationFileTime100ns = FileTimeValue(creation);
    const auto exited = CaptureSelectedMemory(child.hProcess, exitedPlan);
    Check(exited.status.state == memory::State::TargetExited &&
        exited.status.issue.stage == memory::Stage::ProcessLifetime, "exited target reports lifetime state");
    CloseHandle(child.hThread);
    CloseHandle(child.hProcess);

    // 取消在采样前生效，不产生轮次。
    void* region = VirtualAlloc(nullptr, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(region != nullptr, "allocate cancel fixture");
    const auto cancelBase = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region));
    std::atomic_bool cancel{true};
    const auto canceled = CaptureSelectedMemory(GetCurrentProcess(),
        SelfPlan("fixture-cancel", cancelBase, 0x1000), &cancel);
    Check(canceled.status.state == memory::State::Canceled && canceled.round == std::nullopt &&
        canceled.captured.empty() && !canceled.completeRange, "canceled capture stops before sampling");
    Check(VirtualFree(region, 0, MEM_RELEASE), "release cancel fixture");

    struct BoundPlan { const char* what; std::uint64_t base; std::uint64_t length; std::optional<std::uint32_t> rounds; };
    const BoundPlan bad[] = {
        {"zero length rejected", 0x10000, 0, std::nullopt},
        {"range overflow rejected", 0xFFFFFFFFFFFFFFF0ull, 0x100, std::nullopt},
        {"null base rejected", 0, 0x1000, std::nullopt},
        {"single round rejected", 0x10000, 0x1000, std::uint32_t{1}},
        {"page count beyond registry rejected", 0x10000, 65 * 0x1000, std::nullopt},
    };
    for (const auto& bound : bad) {
        auto plan = SelfPlan("fixture-bounds", bound.base, bound.length);
        plan.rounds = bound.rounds;
        const auto snapshot = CaptureSelectedMemory(GetCurrentProcess(), plan);
        Check(snapshot.status.state == memory::State::Rejected &&
            snapshot.status.issue.stage == memory::Stage::ValidatePlan, bound.what);
    }

    auto unauthorized = SelfPlan("fixture-authz", 0x10000, 0x1000);
    unauthorized.authorizedOwnedProcess = false;
    const auto denied = CaptureSelectedMemory(GetCurrentProcess(), unauthorized);
    Check(denied.status.state == memory::State::Rejected &&
        denied.status.issue.stage == memory::Stage::ValidatePlan, "unauthorized selection rejected");
}

// ---- 场景 4：旧 Poll 行为保持，PollCapture 借用视图不跨回调 ------------

void ScenarioPollAndCapture()
{
    Scenario("old poll behavior and capture visitor ownership");
    void* region = VirtualAlloc(nullptr, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(region != nullptr, "allocate poll fixture");
    const auto base = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(region));
    FillPattern(base, 0x2000);

    memory::Plan plan = SelfPlan("fixture-poll", base, 0x2000);
    plan.rounds = 2;
    plan.intervalMs = 10;
    memory::PassiveDirtyMemory poller;
    Check(poller.Begin(GetCurrentProcess(), plan).state == memory::State::Active, "begin old poll");

    const auto first = poller.Poll();
    Check(first.round.has_value() && first.status.state == memory::State::Active, "first round executes when due");
    Check(first.round->pages.size() == 2 && first.status.attemptedRounds == 1, "first round visits both pages");
    Check(first.round->pages[0].content && first.round->pages[0].content->origin == memory::ContentOrigin::Baseline &&
        first.round->pages[0].content->version == 1, "first round is baseline");
    Check(first.round->pages[1].content && first.round->pages[1].content->version == 1, "second page baseline");

    const auto immediate = poller.Poll();
    Check(!immediate.round.has_value(), "poll before interval is not due");
    const auto statusOnly = poller.Poll(nullptr, memory::PollMode::StatusOnly);
    Check(!statusOnly.round.has_value() && statusOnly.status.attemptedRounds == 1, "status only consumes no round");

    Sleep(30); // 超过 10ms 间隔，下一轮必然到期。
    auto* bytes = reinterpret_cast<std::uint8_t*>(static_cast<std::uintptr_t>(base));
    for (std::size_t index = 0; index < 64; ++index) bytes[index] ^= 0xFF; // 每字节都确定不同。
    const auto second = poller.Poll();
    Check(second.round.has_value() && second.status.state == memory::State::Completed, "planned rounds finish completed");
    Check(second.round->pages[0].content && second.round->pages[0].content->version == 2 &&
        second.round->pages[0].content->origin == memory::ContentOrigin::Changed, "mutation produces changed version");
    Check(second.round->pages[0].difference.has_value() && second.round->pages[0].difference->changedBytes == 64 &&
        second.round->pages[0].difference->ranges.size() == 1 &&
        second.round->pages[0].difference->ranges[0] == memory::Range{base, 64}, "difference reports exact range");
    Check(second.round->pages[1].content && second.round->pages[1].content->version == 1 &&
        second.round->pages[1].content->origin == memory::ContentOrigin::Unchanged, "untouched page stays unchanged");
    const auto after = poller.Poll();
    Check(!after.round.has_value() && after.status.state == memory::State::Completed, "completed poller stays idle");
    Check(VirtualFree(region, 0, MEM_RELEASE), "release poll fixture");

    // PollCapture：借用视图只在回调内有效；快照必须复制原字节。
    void* regionCapture = VirtualAlloc(nullptr, 0x3000, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    Check(regionCapture != nullptr, "allocate capture fixture");
    const auto captureBase = static_cast<std::uint64_t>(reinterpret_cast<std::uintptr_t>(regionCapture));
    FillPattern(captureBase, 0x3000);
    auto* guardPage = reinterpret_cast<void*>(static_cast<std::uintptr_t>(captureBase + 0x1000));
    DWORD oldProtect = 0;
    Check(VirtualProtect(guardPage, 0x1000, PAGE_READWRITE | PAGE_GUARD, &oldProtect), "arm middle guard page");

    memory::Plan capturePlan = SelfPlan("fixture-capture", captureBase, 0x3000);
    capturePlan.intervalMs = 200;
    memory::PassiveDirtyMemory capturer;
    Check(capturer.Begin(GetCurrentProcess(), capturePlan).state == memory::State::Active, "begin capture poller");

    std::vector<const std::uint8_t*> borrowed; // 回调期间记录的借用指针。
    std::vector<std::vector<std::uint8_t>> copies; // 回调内的自持复制。
    std::vector<std::uint64_t> visitedBases;
    int calls = 0;
    const memory::CapturedPageVisitor visitor = [&](const memory::PageObservation& page,
        std::span<const std::uint8_t> bytes) {
        ++calls;
        visitedBases.push_back(page.pageBase);
        borrowed.push_back(bytes.data());
        copies.emplace_back(bytes.begin(), bytes.end());
    };
    const auto captured = capturer.PollCapture(visitor);
    Check(captured.round.has_value() && captured.round->pages.size() == 3, "capture round visits all pages");
    Check(captured.round->pages[1].status == memory::PageStatus::Guarded, "guard page skipped by capture");
    Check(calls == 2, "visitor invoked only for sampled pages");
    Check(visitedBases.size() == 2 && visitedBases[0] == captureBase && visitedBases[1] == captureBase + 0x2000,
        "visitor pages ascend by address");
    Check(copies.size() == 2 && copies[0] == ExpectedPattern(captureBase, 0x1000) &&
        copies[1] == ExpectedPattern(captureBase + 0x2000, 0x1000), "visitor receives exact original bytes");
    Check(borrowed[0] != copies[0].data() && borrowed[1] != copies[1].data(),
        "snapshot copy owns storage separate from borrowed view");
    Check(captured.status.state == memory::State::Active && captured.status.attemptedRounds == 1,
        "explicit capture stays active for caller stop");

    int lateCalls = 0;
    const memory::CapturedPageVisitor lateVisitor = [&](const memory::PageObservation&, std::span<const std::uint8_t>) {
        ++lateCalls;
    };
    const auto notDue = capturer.PollCapture(lateVisitor);
    Check(!notDue.round.has_value() && lateCalls == 0 && notDue.status.attemptedRounds == 1,
        "capture does not re-sample before interval");
    Check(capturer.Stop().state == memory::State::Stopped, "caller stops capture poller");
    MEMORY_BASIC_INFORMATION mbi{};
    Check(VirtualQueryEx(GetCurrentProcess(), guardPage, &mbi, sizeof(mbi)) == sizeof(mbi), "query capture guard page");
    Check((mbi.Protect & PAGE_GUARD) != 0, "capture path leaves guard armed");
    Check(VirtualProtect(guardPage, 0x1000, PAGE_READWRITE, &oldProtect), "restore capture guard page");
    Check(VirtualFree(regionCapture, 0, MEM_RELEASE), "release capture fixture");
}

// ---- 归档读回工具 ------------------------------------------------------

struct RecordCopy {
    std::string metadata;
    std::string bytes;
};

void ScenarioArchiveCorruption(const fs::path& scratch, const aa::SampleInfo& sampleA,
    const aa::SampleInfo& sampleB, const archive::RawEvidenceBoundary& firstFlush,
    const aa::ProjectMemorySnapshotReceipt& partialReceipt, const std::string& projectId);

std::vector<RecordCopy> records; // 最近一次读回收集的记录副本。

bool CollectRecords(const archive::SegmentIdentity&, const archive::BlockInfo&,
    const std::vector<archive::DecodedRecord>& block)
{
    for (const auto& record : block) {
        const auto* body = std::get_if<archive::RawRecordV1>(&record.body);
        if (!body) return false;
        records.push_back({std::string(body->metadataJson), std::string(body->inlineRawData)});
    }
    return true;
}

const ev::JsonValue& ParsedPlanMetadata()
{
    static ev::JsonValue parsed; // 最近一次场景解析的计划元数据。
    const auto result = ev::ParseJson(records[0].metadata);
    Check(result.ok(), "plan metadata parses");
    parsed = result.value;
    return parsed;
}

const ev::JsonValue& ParsedPageMetadata(std::size_t index)
{
    static ev::JsonValue parsed; // 最近一次场景解析的页元数据。
    const auto result = ev::ParseJson(records[index].metadata);
    Check(result.ok(), "page metadata parses");
    parsed = result.value;
    return parsed;
}

// 期望成功的写入：失败时打印项目层错误细节，便于定位。
bool WriteSnapshotOk(aa::ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    std::optional<std::uint64_t> previousSequence, const memory::SelectedMemorySnapshot& snapshot,
    aa::ProjectMemorySnapshotReceipt& receipt)
{
    const auto result = aa::WriteSelectedMemorySnapshot(project, sampleId, ordinal, previousSequence, snapshot, receipt);
    if (!result) {
        std::cerr << "WRITE-ERROR detail=" << result.detail << " error=" << static_cast<int>(result.error)
            << " native=" << result.nativeError << '\n';
        return false;
    }
    return true;
}

// 期望失败的写入：错误码不符时打印项目层细节。
void ExpectWriteError(aa::ProjectDocument& project, std::string_view sampleId, std::uint64_t ordinal,
    std::optional<std::uint64_t> previousSequence, const memory::SelectedMemorySnapshot& snapshot,
    aa::ProjectMemorySnapshotReceipt& receipt, aa::ProjectError expected, const char* what)
{
    const auto result = aa::WriteSelectedMemorySnapshot(project, sampleId, ordinal, previousSequence, snapshot, receipt);
    if (result.error != expected) {
        std::cerr << "EXPECT-ERROR detail=" << result.detail << " error=" << static_cast<int>(result.error)
            << " expected=" << static_cast<int>(expected) << " native=" << result.nativeError << " what=" << what << '\n';
    }
    Check(result.error == expected, what);
}

// ---- 场景 5：正式 ProjectDocument 同 sample 写 raw-memory/1 与 2 -------

void ScenarioArchiveRoundTrip(const fs::path& scratch)
{
    Scenario("archive raw-memory chain with verified readback");
    const auto path = scratch / L"mem-snapshot-project";
    aa::ProjectDocument project;
    aa::SampleInfo sampleA;
    aa::SampleInfo sampleB;
    Check(!!project.Create(path.wstring(), {"Memory snapshot fixture", ""}), "create project");
    const auto projectId = project.Info()->projectId;
    Check(!!project.CreateSample("sample-a", sampleA), "create sample a");
    Check(!!project.CreateSample("sample-b", sampleB), "create sample b");

    const auto plan = SyntheticPlan(sampleA.sampleId, 0x7ff600000000ull, 2 * kSyntheticPage);
    auto complete = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, ExpectedPattern(plan.range.base, kSyntheticPage)},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage,
            ExpectedPattern(plan.range.base + kSyntheticPage, kSyntheticPage)},
    });
    complete.completeRange = true;

    aa::ProjectMemorySnapshotReceipt receipt;
    Check(WriteSnapshotOk(project, sampleA.sampleId, 1, std::nullopt, complete, receipt),
        "write complete snapshot to raw-memory/1");
    Check(receipt.verified && receipt.ordinal == 1 && receipt.completeRange, "receipt verifies first snapshot");
    Check(receipt.capturedBytes == 2 * kSyntheticPage && receipt.unavailablePages == 0, "receipt counts complete bytes");
    Check(receipt.raw.flushed.has_value() && IsHash(receipt.sha256), "receipt carries flush boundary and hash");
    const auto firstFlush = *receipt.raw.flushed;

    const auto raw1 = path / L"samples" / fs::path(sampleA.sampleId) / L"raw-memory" / L"00000000000000000001.ksaseg";
    Check(fs::exists(raw1), "raw-memory/1 exists under sample");
    const auto raw1Bytes = ReadFileBytes(raw1);
    Check(raw1Bytes.size() == firstFlush.byteOffset, "flush boundary matches file size");
    const auto raw1Digest = HashBytes(raw1Bytes.data(), raw1Bytes.size());

    records.clear();
    aa::ProjectRawEvidenceRead read{projectId, sampleA.sampleId, 1, firstFlush.byteOffset, std::nullopt,
        &CollectRecords, std::nullopt, aa::ProjectEvidenceLane::MemorySnapshots};
    archive::RawEvidenceScanResult scan;
    std::string prefixHash;
    Check(!!project.ReadRawEvidenceSegment(read, scan, &prefixHash), "read raw-memory/1");
    Check(scan.VerifiedBoundary(firstFlush) && records.size() == 4, "raw-memory/1 verifies with four rows");
    Check(prefixHash == receipt.sha256, "receipt sha equals readback prefix hash");

    const auto& planJson = ParsedPlanMetadata();
    CheckText(planJson, "kind", "selected-memory-plan-v1", "plan record kind");
    CheckText(planJson, "projectId", projectId, "plan binds project");
    CheckText(planJson, "sampleId", sampleA.sampleId, "plan binds sample");
    CheckText(planJson, "source", "read-only-memory-sample", "plan declares read-only source");
    bool atomicFlag = true;
    Check(planJson.find("atomicProcessSnapshot") && planJson.find("atomicProcessSnapshot")->tryGetBool(atomicFlag) &&
        !atomicFlag, "atomic process snapshot explicitly false");
    bool generationFlag = true;
    Check(planJson.find("allocationGenerationVerified") &&
        planJson.find("allocationGenerationVerified")->tryGetBool(generationFlag) && !generationFlag,
        "allocation generation explicitly unknown");
    CheckU64(planJson, "qpcFrequency", complete.status.qpcFrequency, "plan preserves qpc frequency");
    const auto* rangeJson = planJson.find("range");
    Check(rangeJson != nullptr, "plan has range");
    CheckU64(*rangeJson, "base", plan.range.base, "plan range base preserved");
    CheckU64(*rangeJson, "bytes", plan.range.length, "plan range length preserved");
    const auto* targetJson = planJson.find("target");
    Check(targetJson != nullptr, "plan has target");
    CheckU64(*targetJson, "pid", 4242, "plan target pid preserved");
    CheckU64(*targetJson, "creationFileTime", 13300000000000000ull, "plan target creation preserved");

    for (std::size_t index = 1; index <= 2; ++index) {
        const auto& pageJson = ParsedPageMetadata(index);
        CheckText(pageJson, "kind", "selected-memory-page-v1", "page record kind");
        CheckText(pageJson, "state", "sampled", "page state sampled");
        const auto pageBase = plan.range.base + (index - 1) * kSyntheticPage;
        CheckU64(pageJson, "pageBase", pageBase, "page base preserved");
        CheckU64(pageJson, "returnedBytes", kSyntheticPage, "page returned bytes preserved");
        const auto* sha = pageJson.find("sha256");
        std::string shaText;
        Check(sha && sha->tryGetString(shaText) && shaText == Hex(HashBytes(
            reinterpret_cast<const std::uint8_t*>(records[index].bytes.data()), records[index].bytes.size())),
            "page sha matches archived bytes");
        Check(records[index].bytes == std::string(
                reinterpret_cast<const char*>(ExpectedPattern(pageBase, kSyntheticPage).data()), kSyntheticPage),
            "page bytes archived exactly");
    }

    const auto& endJson = ParsedPageMetadata(3);
    CheckText(endJson, "kind", "selected-memory-end-v1", "end record kind");
    bool endComplete = false;
    Check(endJson.find("completeRange") && endJson.find("completeRange")->tryGetBool(endComplete) && endComplete,
        "end record marks complete range");
    CheckU64(endJson, "capturedBytes", 2 * kSyntheticPage, "end record byte count");
    CheckU64(endJson, "unavailablePages", 0, "end record has no unavailable pages");
    CheckU64(endJson, "visitedPages", 2, "end record visited pages");
    bool allVisited = false;
    Check(endJson.find("allPagesVisited") && endJson.find("allPagesVisited")->tryGetBool(allVisited) && allVisited,
        "end record marks all pages visited");

    // 部分失败页写入 raw-memory/2；completeRange 与完整采样不可混淆。
    auto partial = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, ExpectedPattern(plan.range.base, kSyntheticPage)},
        {memory::PageStatus::NotCommitted, plan.range.base + kSyntheticPage, kSyntheticPage, {}},
    });
    aa::ProjectMemorySnapshotReceipt partialReceipt;
    Check(WriteSnapshotOk(project, sampleA.sampleId, 2, firstFlush.lastSequence, partial, partialReceipt),
        "write partial snapshot to raw-memory/2");
    Check(partialReceipt.verified && partialReceipt.ordinal == 2 && !partialReceipt.completeRange,
        "partial receipt stays incomplete");
    Check(partialReceipt.unavailablePages == 1 && partialReceipt.capturedBytes == kSyntheticPage,
        "partial receipt counts one failed page");
    Check(HashBytes(raw1Bytes.data(), raw1Bytes.size()) == raw1Digest,
        "raw-memory/1 bytes unchanged after second segment");

    const auto raw2 = path / L"samples" / fs::path(sampleA.sampleId) / L"raw-memory" / L"00000000000000000002.ksaseg";
    Check(fs::exists(raw2), "raw-memory/2 exists under sample");
    records.clear();
    aa::ProjectRawEvidenceRead read2{projectId, sampleA.sampleId, 2, partialReceipt.raw.flushed->byteOffset,
        firstFlush.lastSequence, &CollectRecords, std::nullopt, aa::ProjectEvidenceLane::MemorySnapshots};
    archive::RawEvidenceScanResult scan2;
    Check(!!project.ReadRawEvidenceSegment(read2, scan2) && scan2.VerifiedBoundary(*partialReceipt.raw.flushed) &&
        records.size() == 4, "raw-memory/2 verifies with chained predecessor");
    const auto& failedPage = ParsedPageMetadata(2);
    CheckText(failedPage, "state", "not-committed", "failed page state archived");
    Check(failedPage.find("sha256") && failedPage.find("sha256")->isNull(), "failed page carries no sha");
    Check(records[2].bytes.empty(), "failed page archives no fabricated bytes");
    const auto& partialEnd = ParsedPageMetadata(3);
    bool endPartial = true;
    Check(partialEnd.find("completeRange") && partialEnd.find("completeRange")->tryGetBool(endPartial) && !endPartial,
        "partial end record stays incomplete");
    CheckU64(partialEnd, "unavailablePages", 1, "partial end record counts failed page");

    aa::ProjectRawEvidenceRead wrongChain{projectId, sampleA.sampleId, 2, partialReceipt.raw.flushed->byteOffset,
        firstFlush.lastSequence + 1, &CollectRecords, std::nullopt, aa::ProjectEvidenceLane::MemorySnapshots};
    archive::RawEvidenceScanResult chainScan;
    Check(!!project.ReadRawEvidenceSegment(wrongChain, chainScan) &&
        chainScan.issue == archive::RawEvidenceScanIssue::UnexpectedSequence, "wrong predecessor rejected on read");

    // 第二个采样写入自己的 raw-memory/1，供坏段测试使用。
    const auto singlePlan = SyntheticPlan(sampleB.sampleId, 0x7ff700000000ull, kSyntheticPage);
    auto single = SyntheticSnapshot(singlePlan, {
        {memory::PageStatus::Sampled, singlePlan.range.base, kSyntheticPage,
            ExpectedPattern(singlePlan.range.base, kSyntheticPage)},
    });
    single.completeRange = true;
    aa::ProjectMemorySnapshotReceipt singleReceipt;
    Check(WriteSnapshotOk(project, sampleB.sampleId, 1, std::nullopt, single, singleReceipt),
        "write single snapshot to sample b raw-memory/1");
    Check(singleReceipt.completeRange && singleReceipt.capturedBytes == kSyntheticPage, "single receipt complete");

    project.Close();
    ScenarioArchiveCorruption(scratch, sampleA, sampleB, firstFlush, partialReceipt, projectId);
}

// ---- 场景 6：错误前序 / 只读项目 / 缺 sample / 坏段 ---------------------

void ScenarioArchiveCorruption(const fs::path& scratch, const aa::SampleInfo& sampleA,
    const aa::SampleInfo& sampleB, const archive::RawEvidenceBoundary& firstFlush,
    const aa::ProjectMemorySnapshotReceipt& partialReceipt, const std::string& projectId)
{
    Scenario("archive rejects wrong identities and damaged segments");
    const auto path = scratch / L"mem-snapshot-project";
    aa::ProjectDocument project;
    Check(!!project.Open(path.wstring(), aa::ProjectAccess::ReadWrite), "reopen project for failure paths");
    const auto plan = SyntheticPlan(sampleA.sampleId, 0x7ff600000000ull, 2 * kSyntheticPage);
    const auto sampleBytes = ExpectedPattern(plan.range.base, kSyntheticPage);

    // 已有 raw-memory/1 不被覆盖。
    const auto raw1 = path / L"samples" / fs::path(sampleA.sampleId) / L"raw-memory" / L"00000000000000000001.ksaseg";
    const auto raw1Before = ReadFileBytes(raw1);
    const auto raw1Digest = HashBytes(raw1Before.data(), raw1Before.size());
    auto duplicate = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    duplicate.completeRange = true;
    aa::ProjectMemorySnapshotReceipt receipt;
    const auto duplicateResult = aa::WriteSelectedMemorySnapshot(project, sampleA.sampleId, 1, std::nullopt,
        duplicate, receipt);
    if (duplicateResult.error != aa::ProjectError::AlreadyExists) {
        std::cerr << "DUP-ERROR detail=" << duplicateResult.detail << " error="
            << static_cast<int>(duplicateResult.error) << " native=" << duplicateResult.nativeError << '\n';
    }
    Check(duplicateResult.error == aa::ProjectError::AlreadyExists, "duplicate ordinal rejected");
    const auto raw1After = ReadFileBytes(raw1);
    Check(HashBytes(raw1After.data(), raw1After.size()) == raw1Digest, "raw-memory/1 not overwritten");

    // 错误前序与身份不匹配。
    const auto lastSequence = partialReceipt.raw.flushed->lastSequence;
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence + 1, duplicate, receipt,
        aa::ProjectError::RecoveryRequired, "wrong previous sequence rejected");
    ExpectWriteError(project, sampleB.sampleId, 3, lastSequence, duplicate, receipt,
        aa::ProjectError::InvalidArgument, "sample mismatch rejected");
    auto foreign = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    foreign.completeRange = true;
    foreign.round->effectivePlan.target.pid += 1;
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, foreign, receipt,
        aa::ProjectError::InvalidArgument, "effective plan identity mismatch rejected");

    // 页序、字节配对与完整性口径。
    auto gap = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base + 0x10, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage + 0x10, kSyntheticPage, sampleBytes},
    });
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, gap, receipt,
        aa::ProjectError::InvalidArgument, "page order gap rejected");
    auto missingBytes = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    missingBytes.captured.clear();
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, missingBytes, receipt,
        aa::ProjectError::InvalidArgument, "missing captured bytes rejected");
    auto extraBytes = SyntheticSnapshot(plan, {
        {memory::PageStatus::NotCommitted, plan.range.base, kSyntheticPage, {}},
    });
    extraBytes.captured.push_back({extraBytes.round->pages[0], {}});
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, extraBytes, receipt,
        aa::ProjectError::InvalidArgument, "extra captured bytes rejected");
    auto tampered = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    auto tamperedBytes = sampleBytes;
    ++tamperedBytes[3]; // 摘要与原字节不再一致。
    tampered.captured[0].bytes = tamperedBytes;
    tampered.captured[0].observation.content = std::nullopt;
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, tampered, receipt,
        aa::ProjectError::InvalidArgument, "captured bytes without matching sha rejected");
    auto digestMismatch = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    auto lyingBytes = sampleBytes;
    ++lyingBytes[7];
    digestMismatch.captured[1].bytes = lyingBytes; // sha 仍是原字节摘要，字节已被替换。
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, digestMismatch, receipt,
        aa::ProjectError::InvalidArgument, "captured bytes contradicting sampled sha rejected");
    auto overstated = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::NotCommitted, plan.range.base + kSyntheticPage, kSyntheticPage, {}},
    });
    overstated.completeRange = true;
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, overstated, receipt,
        aa::ProjectError::InvalidArgument, "partial result cannot claim complete range");
    auto understated = SyntheticSnapshot(plan, {
        {memory::PageStatus::Sampled, plan.range.base, kSyntheticPage, sampleBytes},
        {memory::PageStatus::Sampled, plan.range.base + kSyntheticPage, kSyntheticPage, sampleBytes},
    });
    understated.completeRange = false;
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, understated, receipt,
        aa::ProjectError::InvalidArgument, "complete result cannot deny completeness");

    // 缺失采样：项目没有该 UUID 采样。
    constexpr auto kMissingSampleId = "123e4567-e89b-42d3-a456-426614174000";
    auto missingSample = SyntheticSnapshot(SyntheticPlan(kMissingSampleId, 0x7ff800000000ull, kSyntheticPage), {
        {memory::PageStatus::Sampled, 0x7ff800000000ull, kSyntheticPage, sampleBytes},
    });
    missingSample.completeRange = true;
    ExpectWriteError(project, kMissingSampleId, 1, std::nullopt, missingSample, receipt,
        aa::ProjectError::NotFound, "unknown sample rejected");

    // 只读项目拒绝写入。
    project.Close();
    Check(!!project.Open(path.wstring(), aa::ProjectAccess::ReadOnly), "reopen read-only");
    ExpectWriteError(project, sampleA.sampleId, 3, lastSequence, duplicate, receipt,
        aa::ProjectError::ReadOnly, "read-only project rejects snapshot write");
    project.Close();

    // 坏段：真实短尾与位翻转。先保留完整原字节，再依次截断与翻转。
    Check(!!project.Open(path.wstring()), "reopen project for corruption reads");
    const auto raw2 = path / L"samples" / fs::path(sampleA.sampleId) / L"raw-memory" / L"00000000000000000002.ksaseg";
    const auto raw2Original = ReadFileBytes(raw2);
    Check(raw2Original.size() == partialReceipt.raw.flushed->byteOffset, "raw-memory/2 holds full original bytes");
    fs::resize_file(raw2, partialReceipt.raw.flushed->byteOffset - 1);
    records.clear();
    aa::ProjectRawEvidenceRead read2{projectId, sampleA.sampleId, 2, partialReceipt.raw.flushed->byteOffset,
        firstFlush.lastSequence, &CollectRecords, std::nullopt, aa::ProjectEvidenceLane::MemorySnapshots};
    archive::RawEvidenceScanResult scan2;
    Check(!!project.ReadRawEvidenceSegment(read2, scan2) && !scan2.VerifiedBoundary(*partialReceipt.raw.flushed) &&
        scan2.segment.framing.status == archive::SegmentScanStatus::Truncated && records.size() == 3,
        "truncated segment keeps prior whole rows only");
    Check(fs::file_size(raw2) == partialReceipt.raw.flushed->byteOffset - 1, "truncation leaves file untouched");

    WriteFileBytes(raw2, raw2Original); // 还原完整原字节后做位翻转。
    auto flipped = raw2Original;
    flipped[flipped.size() / 2] = static_cast<std::uint8_t>(flipped[flipped.size() / 2] ^ 0x40);
    WriteFileBytes(raw2, flipped);
    records.clear();
    archive::RawEvidenceScanResult flipScan;
    Check(!!project.ReadRawEvidenceSegment(read2, flipScan) && !flipScan.VerifiedBoundary(*partialReceipt.raw.flushed),
        "flipped payload byte fails verification");
    project.Close();
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring_view(argv[1]) == L"--dead-fixture") {
        return 0; // 挂起夹具子进程的良性出口；正常流程不会执行到这里。
    }
    if (argc != 2) {
        return 2;
    }
    const fs::path scratch(argv[1]); // 验证脚本独占创建的固定输出目录。
    ScenarioSelfCapture();
    ScenarioPartialFailures();
    ScenarioRejections();
    ScenarioPollAndCapture();
    ScenarioArchiveRoundTrip(scratch);
    std::cout << "RESULT=PASS scenarios=" << scenarios << " checks=" << checks << '\n';
    return 0;
}
