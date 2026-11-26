#include "PassiveDirtyMemory.h"

#include "../../../shared/usermode/backend/Common.h"

#include <bcrypt.h>

#include <algorithm>
#include <limits>
#include <string_view>
#include <utility>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "bcrypt.lib")

namespace ks::cli::action_analyze::memory {
namespace {

using r3::common::UniqueHandle;
constexpr auto kAddressMax = (std::numeric_limits<std::uint64_t>::max)();
constexpr DWORD kProcessAccess = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE;

Issue Error(Stage stage, DWORD code) noexcept
{
    return {stage, code, std::nullopt};
}

Issue LastError(Stage stage) noexcept
{
    const DWORD error = GetLastError();
    return Error(stage, error ? error : ERROR_GEN_FAILURE);
}

Issue CryptoError(Stage stage, NTSTATUS status) noexcept
{
    return {stage, ERROR_SUCCESS, static_cast<std::int32_t>(status)};
}

std::uint64_t FileTimeValue(const FILETIME& time) noexcept
{
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::optional<std::uint64_t> NowQpc() noexcept
{
    LARGE_INTEGER count{};
    if (!QueryPerformanceCounter(&count) || count.QuadPart < 0) return std::nullopt;
    return static_cast<std::uint64_t>(count.QuadPart);
}

bool ValidLabel(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= 128 && std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
            ch == '-' || ch == '_' || ch == '.' || ch == ':' || ch == '/';
    });
}

bool Contains(const Range& range, std::uint64_t address) noexcept
{
    return address >= range.base && address - range.base < range.length;
}

bool ValidPlan(const Plan& plan) noexcept
{
    return ValidLabel(plan.sampleId) && ValidLabel(plan.trackingEpoch) && ValidLabel(plan.target.machineId) &&
        ValidLabel(plan.target.bootId) && ValidLabel(plan.target.processInstanceId) && plan.target.pid &&
        plan.target.creationFileTime100ns && plan.range.base && plan.range.length &&
        plan.range.length <= kAddressMax - plan.range.base &&
        (!plan.rounds || (*plan.rounds >= 2 && *plan.rounds <= kMaxSampleRounds)) &&
        plan.intervalMs >= 10 && plan.intervalMs <= 1000;
}

Issue ConfirmLive(HANDLE process) noexcept
{
    switch (WaitForSingleObject(process, 0)) {
    case WAIT_TIMEOUT: return {};
    case WAIT_OBJECT_0: return Error(Stage::ProcessLifetime, ERROR_PROCESS_ABORTED);
    case WAIT_FAILED: return LastError(Stage::ProcessLifetime);
    default: return Error(Stage::ProcessLifetime, ERROR_GEN_FAILURE);
    }
}

Issue ConfirmIdentity(HANDLE process, const ProcessInstance& target) noexcept
{
    const DWORD pid = GetProcessId(process);
    if (!pid) return LastError(Stage::ProcessId);
    FILETIME creation{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return LastError(Stage::ProcessCreation);
    if (pid != target.pid || FileTimeValue(creation) != target.creationFileTime100ns) {
        return Error(Stage::ProcessMismatch, ERROR_INVALID_PARAMETER);
    }
    return ConfirmLive(process);
}

Issue ConfirmOwner(HANDLE process) noexcept
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return LastError(Stage::OpenOwnerToken);
    const UniqueHandle ownerToken(token);
    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) return LastError(Stage::OpenTargetToken);
    const UniqueHandle targetToken(token);
    struct TokenUserBuffer {
        TOKEN_USER user;
        std::array<std::uint8_t, SECURITY_MAX_SID_SIZE> sidBuffer;
    } owner{}, target{};
    DWORD ownerSession = 0, targetSession = 0, returned = 0;
    if (!GetTokenInformation(ownerToken.get(), TokenUser, &owner, sizeof(owner), &returned) ||
        !GetTokenInformation(targetToken.get(), TokenUser, &target, sizeof(target), &returned) ||
        !GetTokenInformation(ownerToken.get(), TokenSessionId, &ownerSession, sizeof(ownerSession), &returned) ||
        !GetTokenInformation(targetToken.get(), TokenSessionId, &targetSession, sizeof(targetSession), &returned)) {
        return LastError(Stage::ReadTokenIdentity);
    }
    if (ownerSession != targetSession || !EqualSid(owner.user.User.Sid, target.user.User.Sid)) {
        return Error(Stage::TokenOwnerMismatch, ERROR_ACCESS_DENIED);
    }
    BOOL critical = FALSE;
    if (!IsProcessCritical(process, &critical)) return LastError(Stage::CriticalProcess);
    return critical ? Error(Stage::CriticalProcess, ERROR_ACCESS_DENIED) : Issue{};
}

Issue ReadPointerWidth(HANDLE process, std::uint32_t& width) noexcept
{
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(process, &processMachine, &nativeMachine)) return LastError(Stage::TargetMachine);
    switch (processMachine == IMAGE_FILE_MACHINE_UNKNOWN ? nativeMachine : processMachine) {
    case IMAGE_FILE_MACHINE_I386: width = 32; break;
    case IMAGE_FILE_MACHINE_AMD64:
    case IMAGE_FILE_MACHINE_ARM64: width = 64; break;
    default: return Error(Stage::TargetMachine, ERROR_NOT_SUPPORTED);
    }
    return width <= sizeof(std::uintptr_t) * 8 ? Issue{} : Error(Stage::TargetMachine, ERROR_NOT_SUPPORTED);
}

// 复用 Memory Watch 的可读权限与读前、读后比对口径；这里只按所选页内区间读。
bool Readable(DWORD protect) noexcept
{
    switch (protect & 0xffu) {
    case PAGE_READONLY: case PAGE_READWRITE: case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ: case PAGE_EXECUTE_READWRITE: case PAGE_EXECUTE_WRITECOPY:
        return true;
    default: return false;
    }
}

Issue ReadMapping(HANDLE process, const Range& sampled, Stage stage, Mapping& result) noexcept
{
    MEMORY_BASIC_INFORMATION raw{};
    const SIZE_T returned = VirtualQueryEx(process, reinterpret_cast<const void*>(
        static_cast<std::uintptr_t>(sampled.base)), &raw, sizeof(raw));
    if (!returned) return LastError(stage);
    if (returned != sizeof(raw)) return Error(stage, ERROR_INVALID_DATA);

    result.region = {reinterpret_cast<std::uintptr_t>(raw.BaseAddress), raw.RegionSize};
    result.state = raw.State;
    if (result.region.length > kAddressMax - result.region.base || !Contains(result.region, sampled.base) ||
        !Contains(result.region, sampled.base + sampled.length - 1)) return Error(stage, ERROR_INVALID_DATA);

    switch (raw.State) {
    case MEM_FREE: break; // 空闲区的 AllocationBase、Protect 等字段未定义。
    case MEM_RESERVE:
    case MEM_COMMIT:
        result.allocationBase = reinterpret_cast<std::uintptr_t>(raw.AllocationBase);
        result.allocationProtection = raw.AllocationProtect;
        result.type = raw.Type;
        if (raw.State == MEM_COMMIT) result.protection = raw.Protect;
        break;
    default: return Error(stage, ERROR_INVALID_DATA);
    }
    return {};
}

bool SameObservedMapping(const Mapping& a, const Mapping& b) noexcept
{
    return a.state == b.state && a.allocationBase == b.allocationBase && a.type == b.type &&
        a.allocationProtection == b.allocationProtection;
}

Difference Compare(const std::vector<std::uint8_t>& previous, const std::vector<std::uint8_t>& current,
    const Range& range)
{
    Difference result;
    const auto length = static_cast<std::uint32_t>(range.length);
    for (std::uint32_t index = 0; index < length;) {
        if (previous[index] == current[index]) { ++index; continue; }
        const auto start = index++;
        while (index < length && previous[index] != current[index]) ++index;
        const auto count = index - start;
        result.changedBytes += count;
        if (++result.rangeCount <= kMaxReportedDiffRanges) result.ranges.push_back({range.base + start, count});
    }
    return result;
}

struct PageHistory {
    std::uint64_t base = 0;
    Range sampled;
    std::optional<Mapping> mapping;
    std::uint64_t mappingSequence = 0;
    std::uint64_t contentSequence = 0;
    bool sawMapping = false;
    std::vector<std::uint8_t> bytes;
    std::optional<ContentSample> before;
    std::optional<ContentSample> latest;

    void BreakContent() noexcept
    {
        before.reset();
        latest.reset();
    }

    void ObserveMapping(const Mapping& observed, PageObservation& row) noexcept
    {
        bool newGeneration = !mapping;
        if (mapping) {
            const bool changed = !SameObservedMapping(*mapping, observed);
            row.changes.mappingChanged |= changed;
            row.changes.regionLayoutChanged |= mapping->region != observed.region;
            row.changes.protectionChanged |= mapping->state == MEM_COMMIT && observed.state == MEM_COMMIT &&
                mapping->protection != observed.protection;
            row.changes.newlyCommitted |= mapping->state != MEM_COMMIT && observed.state == MEM_COMMIT;
            row.changes.noLongerCommitted |= mapping->state == MEM_COMMIT && observed.state != MEM_COMMIT;
            newGeneration = changed;
        } else {
            row.changes.firstMappingObservation = !sawMapping;
            row.changes.mappingContinuityReset = sawMapping;
        }
        if (newGeneration) {
            BreakContent();
            if (observed.state != MEM_FREE) ++mappingSequence;
        }
        mapping = observed;
        sawMapping = true;
        row.mappingGeneration = observed.state != MEM_FREE ? std::optional{mappingSequence} : std::nullopt;
    }

    void BreakMapping(PageObservation& row) noexcept
    {
        mapping.reset();
        row.mappingGeneration.reset();
        BreakContent();
    }

    void AcceptContent(PageObservation& row, const std::vector<std::uint8_t>& current, const Sha256& hash,
        std::uint64_t ordinal)
    {
        ContentOrigin origin = ContentOrigin::Baseline;
        row.previousContent = latest;
        if (latest) {
            row.difference = Compare(bytes, current, sampled);
            origin = row.difference->changedBytes ? ContentOrigin::Changed : ContentOrigin::Unchanged;
        }
        if (origin != ContentOrigin::Unchanged) ++contentSequence;
        before = latest;
        latest = ContentSample{ordinal, contentSequence, *row.readQpc, hash, origin};
        row.content = latest;
        std::copy_n(current.begin(), static_cast<std::size_t>(sampled.length), bytes.begin());
    }
};

void FreeBytes(std::vector<std::uint8_t>& bytes) noexcept
{
    if (!bytes.empty()) SecureZeroMemory(bytes.data(), bytes.size());
    std::vector<std::uint8_t>().swap(bytes);
}

} // namespace

class PassiveDirtyMemory::Impl {
public:
    ~Impl() { ReleaseNative(); }

    Status Begin(HANDLE selectedProcess, const Plan& plan);
    PollResult Poll(const std::atomic_bool* cancel, PollMode mode, const CapturedPageVisitor* visitor = nullptr);
    ExecutionLink CorrelateExecution(const ExecutionObservation& observation) const;
    void Finish(State state, Issue issue = {}) noexcept;

    Status status;

private:
    PageObservation SamplePage(PageHistory& page, std::uint64_t ordinal);
    bool CheckProcess() noexcept;
    void ReleaseNative() noexcept;

    Plan plan_;
    UniqueHandle process_;
    BCRYPT_ALG_HANDLE hashProvider_ = nullptr;
    std::vector<PageHistory> pages_;
    std::vector<std::uint8_t> scratch_;
    std::uint64_t intervalTicks_ = 0;
};

Status PassiveDirtyMemory::Impl::Begin(HANDLE selectedProcess, const Plan& plan)
{
    if (status.state != State::Idle) {
        return {State::Rejected, Error(Stage::ValidatePlan, ERROR_ALREADY_INITIALIZED)};
    }
    const auto reject = [this](Issue issue) {
        Finish(issue.win32Error == ERROR_PROCESS_ABORTED && issue.stage == Stage::ProcessLifetime
            ? State::TargetExited : State::Rejected, issue);
        return status;
    };
    if (!selectedProcess || !ValidPlan(plan)) return reject(Error(Stage::ValidatePlan, ERROR_INVALID_PARAMETER));
    if (!plan.authorizedOwnedProcess) return reject(Error(Stage::ValidatePlan, ERROR_ACCESS_DENIED));

    // 先验证借用句柄，再验证实际用于后续所有读取的最小权限副本。不从 PID 重开。
    if (const auto issue = ConfirmIdentity(selectedProcess, plan.target); issue.stage != Stage::None) return reject(issue);
    HANDLE copy = nullptr;
    if (!DuplicateHandle(GetCurrentProcess(), selectedProcess, GetCurrentProcess(), &copy, kProcessAccess, FALSE, 0)) {
        return reject(LastError(Stage::DuplicateProcess));
    }
    process_.reset(copy);
    if (const auto issue = ConfirmIdentity(copy, plan.target); issue.stage != Stage::None) return reject(issue);
    if (const auto issue = ConfirmOwner(copy); issue.stage != Stage::None) return reject(issue);
    if (const auto issue = ReadPointerWidth(copy, status.pointerWidth); issue.stage != Stage::None) return reject(issue);

    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    status.pageSize = system.dwPageSize;
    const auto last = plan.range.base + plan.range.length - 1;
    const auto upperAddress = status.pointerWidth == 32 ? static_cast<std::uint64_t>(UINT32_MAX)
        : reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    if (!status.pageSize || status.pageSize > 65536 || last > upperAddress) {
        return reject(Error(Stage::ValidatePlan, ERROR_INVALID_ADDRESS));
    }
    const auto firstPage = plan.range.base / status.pageSize;
    const auto lastPage = last / status.pageSize;
    if (lastPage - firstPage >= kMaxTrackedPages) return reject(Error(Stage::ValidatePlan, ERROR_INVALID_PARAMETER));
    status.plannedPages = static_cast<std::uint32_t>(lastPage - firstPage + 1);

    LARGE_INTEGER frequency{};
    const auto now = NowQpc();
    if (!now || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 ||
        static_cast<std::uint64_t>(frequency.QuadPart) > (kAddressMax - 999) / plan.intervalMs) {
        return reject(Error(Stage::Clock, ERROR_GEN_FAILURE));
    }
    const NTSTATUS crypto = BCryptOpenAlgorithmProvider(&hashProvider_, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (crypto < 0) return reject(CryptoError(Stage::OpenHashProvider, crypto));

    plan_ = plan;
    pages_.reserve(status.plannedPages);
    for (auto index = firstPage; index <= lastPage; ++index) {
        auto& page = pages_.emplace_back();
        page.base = index * status.pageSize;
        const auto start = (std::max)(page.base, plan.range.base);
        const auto end = (std::min)(page.base + status.pageSize, last + 1);
        page.sampled = {start, end - start};
        page.bytes.resize(static_cast<std::size_t>(page.sampled.length));
    }
    scratch_.resize(status.pageSize);
    status.qpcFrequency = static_cast<std::uint64_t>(frequency.QuadPart);
    intervalTicks_ = (status.qpcFrequency * plan.intervalMs + 999) / 1000;
    status.nextDueQpc = *now;
    if (!CheckProcess()) return status;
    status.state = State::Active;
    return status;
}

PageObservation PassiveDirtyMemory::Impl::SamplePage(PageHistory& page, std::uint64_t ordinal)
{
    PageObservation row;
    row.pageBase = page.base;
    row.sampledRange = page.sampled;
    Mapping before;
    row.issue = ReadMapping(process_.get(), page.sampled, Stage::QueryBeforeRead, before);
    if (row.issue.stage != Stage::None) {
        page.BreakMapping(row);
        return row;
    }
    row.before = before;
    page.ObserveMapping(before, row);
    if (before.state != MEM_COMMIT) row.status = PageStatus::NotCommitted;
    else if (before.protection & PAGE_GUARD) row.status = PageStatus::Guarded;
    else if (before.protection & (PAGE_NOCACHE | PAGE_WRITECOMBINE)) row.status = PageStatus::UnsafeReadAttributes;
    else if (!Readable(before.protection)) row.status = PageStatus::NotReadable;
    else row.status = PageStatus::ReadFailed; // 进入读取路径，尚未获得完整字节。
    if (row.status != PageStatus::ReadFailed) {
        page.BreakContent();
        return row;
    }

    const auto begin = NowQpc();
    if (!begin) {
        row.status = PageStatus::ReadFailed;
        row.issue = Error(Stage::Clock, ERROR_GEN_FAILURE);
        page.BreakContent();
        return row;
    }
    SIZE_T returned = 0;
    const auto length = static_cast<SIZE_T>(page.sampled.length);
    const auto didRead = ReadProcessMemory(process_.get(), reinterpret_cast<const void*>(
        static_cast<std::uintptr_t>(page.sampled.base)), scratch_.data(), length, &returned);
    const auto readIssue = !didRead ? LastError(Stage::ReadMemory) :
        returned != length ? Error(Stage::ReadMemory, ERROR_PARTIAL_COPY) : Issue{};
    const auto end = NowQpc();
    if (end && *end >= *begin) row.readQpc = QpcWindow{*begin, *end};
    row.returnedBytes = returned;

    // 部分读取也回查映射；任一字节或映射证据不完整时，不推进内容版本。
    Mapping after;
    const auto afterIssue = ReadMapping(process_.get(), page.sampled, Stage::QueryAfterRead, after);
    if (afterIssue.stage != Stage::None) {
        row.issue = afterIssue;
        if (readIssue.stage != Stage::None) row.additionalIssue = readIssue;
        page.BreakMapping(row);
        return row;
    }
    row.after = after;
    if (before != after) {
        page.ObserveMapping(after, row);
        row.status = PageStatus::MappingUnstable;
        row.issue = Error(Stage::CompareMappings, ERROR_RETRY);
        if (readIssue.stage != Stage::None) row.additionalIssue = readIssue;
    } else if (readIssue.stage != Stage::None || !row.readQpc) {
        row.status = PageStatus::ReadFailed;
        row.issue = readIssue.stage != Stage::None ? readIssue : Error(Stage::Clock, ERROR_GEN_FAILURE);
    } else {
        Sha256 digest{};
        const NTSTATUS hash = BCryptHash(hashProvider_, nullptr, 0, scratch_.data(), static_cast<ULONG>(length),
            digest.data(), static_cast<ULONG>(digest.size()));
        if (hash >= 0) {
            row.status = PageStatus::Sampled;
            page.AcceptContent(row, scratch_, digest, ordinal);
            return row;
        }
        row.status = PageStatus::HashFailed;
        row.issue = CryptoError(Stage::HashContent, hash);
    }
    page.BreakContent();
    return row;
}

PollResult PassiveDirtyMemory::Impl::Poll(const std::atomic_bool* cancel, PollMode mode, const CapturedPageVisitor* visitor)
{
    if (status.state != State::Active) return {status, std::nullopt};
    const auto isCanceled = [cancel] { return cancel && cancel->load(std::memory_order_relaxed); };
    if (isCanceled()) Finish(State::Canceled);
    if (status.state != State::Active || !CheckProcess()) return {status, std::nullopt};
    if (mode == PollMode::StatusOnly) return {status, std::nullopt};
    const auto begin = NowQpc();
    if (!begin) {
        Finish(State::Failed, Error(Stage::Clock, ERROR_GEN_FAILURE));
        return {status, std::nullopt};
    }
    if (*begin < *status.nextDueQpc) return {status, std::nullopt};

    Round round;
    round.effectivePlan = plan_;
    round.pages.reserve(pages_.size());
    round.ordinal = ++status.attemptedRounds;
    round.beginQpc = *begin;
    for (auto& page : pages_) {
        if (isCanceled()) { Finish(State::Canceled); break; }
        if (!CheckProcess()) break;
        round.pages.push_back(SamplePage(page, round.ordinal));
        if (round.pages.back().content) {
            ++status.sampledPages;
            if (visitor && *visitor) (*visitor)(round.pages.back(), page.bytes);
        } else {
            ++status.unavailablePages;
        }
    }
    round.allPagesVisited = round.pages.size() == pages_.size();
    if (round.allPagesVisited) ++status.fullRounds;

    const auto end = NowQpc();
    if (end && *end >= *begin) round.endQpc = *end;
    if (!round.endQpc || intervalTicks_ > kAddressMax - *round.endQpc) {
        if (status.state == State::Active) Finish(State::Failed, Error(Stage::Clock, ERROR_GEN_FAILURE));
    } else {
        if (status.state == State::Active && CheckProcess()) {
            if (isCanceled()) Finish(State::Canceled);
            else if (plan_.rounds && status.attemptedRounds == *plan_.rounds) Finish(State::Completed);
            else status.nextDueQpc = *round.endQpc + intervalTicks_;
        }
    }
    return {status, std::move(round)};
}

bool PassiveDirtyMemory::Impl::CheckProcess() noexcept
{
    const auto issue = ConfirmLive(process_.get());
    if (issue.stage == Stage::None) return true;
    Finish(issue.win32Error == ERROR_PROCESS_ABORTED ? State::TargetExited : State::Failed, issue);
    return false;
}

void PassiveDirtyMemory::Impl::ReleaseNative() noexcept
{
    process_.reset();
    if (hashProvider_) BCryptCloseAlgorithmProvider(std::exchange(hashProvider_, nullptr), 0);
    FreeBytes(scratch_);
    for (auto& page : pages_) FreeBytes(page.bytes);
}

void PassiveDirtyMemory::Impl::Finish(State state, Issue issue) noexcept
{
    status.state = state;
    status.issue = issue;
    status.nextDueQpc.reset();
    ReleaseNative();
}

ExecutionLink PassiveDirtyMemory::Impl::CorrelateExecution(const ExecutionObservation& observation) const
{
    ExecutionLink result;
    if (observation.fact != ExecutionFact::Executed) return result;
    result.relation = ExecutionRelation::InvalidEvidence;
    if (!ValidLabel(observation.sampleId) || !ValidLabel(observation.sourceId) ||
        !ValidLabel(observation.sourceEpoch) || !ValidLabel(observation.threadInstanceId) || !observation.tid ||
        !observation.threadCreationFileTime100ns || !observation.actualIp) return result;
    result.relation = ExecutionRelation::WrongInstance;
    if (observation.sampleId != plan_.sampleId || observation.target != plan_.target) return result;
    result.relation = ExecutionRelation::InvalidEvidence;
    if (observation.threadCreationFileTime100ns < plan_.target.creationFileTime100ns) return result;
    result.relation = ExecutionRelation::ClockMismatch;
    if (!status.qpcFrequency || observation.qpcFrequency != status.qpcFrequency) return result;
    result.relation = ExecutionRelation::OutsideSelectedRange;
    if (!Contains(plan_.range, observation.actualIp)) return result;

    result.relation = ExecutionRelation::NoObservationWindow;
    const auto page = std::find_if(pages_.begin(), pages_.end(), [&](const PageHistory& entry) {
        return Contains(entry.sampled, observation.actualIp);
    });
    if (page == pages_.end() || !page->before || !page->latest ||
        page->before->roundOrdinal + 1 != page->latest->roundOrdinal) return result;

    result.relation = ExecutionRelation::OutsideObservationWindow;
    if (observation.qpc < page->before->readQpc.end || observation.qpc > page->latest->readQpc.begin) return result;

    // 真实执行属于外部事实；采样的空间/时间夹定不是执行时字节证明。
    result.relation = page->before->version == page->latest->version
        ? ExecutionRelation::SameSampledVersionCandidate : ExecutionRelation::VersionAmbiguous;
    result.trackingEpoch = plan_.trackingEpoch;
    result.pageBase = page->base;
    result.sampledRange = page->sampled;
    result.mappingGeneration = page->mappingSequence;
    result.before = page->before;
    result.after = page->latest;
    result.evidence = observation;
    return result;
}

PassiveDirtyMemory::PassiveDirtyMemory() : impl_(std::make_unique<Impl>()) {}
PassiveDirtyMemory::~PassiveDirtyMemory() = default;

Status PassiveDirtyMemory::Begin(HANDLE process, const Plan& plan)
{
    return impl_->Begin(process, plan);
}

Status PassiveDirtyMemory::Query() const noexcept
{
    return impl_->status;
}

PollResult PassiveDirtyMemory::Poll(const std::atomic_bool* cancel, PollMode mode)
{
    return impl_->Poll(cancel, mode);
}

PollResult PassiveDirtyMemory::PollCapture(const CapturedPageVisitor& visitor, const std::atomic_bool* cancel)
{
    return impl_->Poll(cancel, PollMode::SampleWhenDue, &visitor);
}

Status PassiveDirtyMemory::Stop() noexcept
{
    if (impl_->status.state == State::Active || impl_->status.state == State::Idle) impl_->Finish(State::Stopped);
    return impl_->status;
}

ExecutionLink PassiveDirtyMemory::CorrelateExecution(const ExecutionObservation& observation) const
{
    return impl_->CorrelateExecution(observation);
}

} // namespace ks::cli::action_analyze::memory
