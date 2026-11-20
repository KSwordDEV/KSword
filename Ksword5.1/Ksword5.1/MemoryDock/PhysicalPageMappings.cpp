#include "PhysicalPageMappings.h"
#include "PhysicalPageConsumers.h"
#include "../ArkDriverClient/ArkDriverPfn.h"
#include <QDateTime>
#include <QUuid>
#include <Psapi.h>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <limits>
#include <map>
#include <set>
#include <tuple>
#include <utility>

namespace ksword::pfn {
namespace {
constexpr std::size_t maxReferences = 2 * 1024 * 1024;
constexpr std::uint64_t maxProbedPages = 16 * 1024 * 1024;
constexpr std::size_t probeBatchPages = 4096;
constexpr std::uint64_t pageBytes = 4096;
// Public MemoryRegionInfo ABI (Win10 1607+); a local named-field mirror keeps
// older SDK headers usable without importing the new API on older Windows.
struct RegionInfo {
    PVOID AllocationBase;
    ULONG AllocationProtect;
    ULONG Private : 1;
    ULONG MappedDataFile : 1;
    ULONG MappedImage : 1;
    ULONG MappedPageFile : 1;
    ULONG MappedPhysical : 1;
    ULONG DirectMapped : 1;
    ULONG Reserved : 26;
    SIZE_T RegionSize, CommitSize;
};
static_assert(sizeof(RegionInfo) == 32 && offsetof(RegionInfo, RegionSize) == 16);
using QueryRegion = BOOL(WINAPI*)(HANDLE, const VOID*, int, PVOID, SIZE_T, PSIZE_T);

bool allocationInfo(HANDLE process, std::uint64_t address, RegionInfo& info)
{
    static const QueryRegion query = [] {
        auto function = reinterpret_cast<QueryRegion>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "QueryVirtualMemoryInformation"));
        if (!function) {
            // Retain the API-set module for the static function's lifetime.
            const auto module = LoadLibraryExW(L"api-ms-win-core-memory-l1-1-4.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
            if (module) { function = reinterpret_cast<QueryRegion>(GetProcAddress(module, "QueryVirtualMemoryInformation")); }
        }
        return function;
    }();
    SIZE_T returned = 0;
    info = {};
    if (!query || !query(process, reinterpret_cast<const VOID*>(address), 0, &info, sizeof(info), &returned)
        || returned != sizeof(info)) { return false; }
    const auto base = reinterpret_cast<std::uint64_t>(info.AllocationBase);
    return info.RegionSize && address >= base && address - base < info.RegionSize && info.CommitSize <= info.RegionSize
        && info.RegionSize <= std::numeric_limits<std::uint64_t>::max() - base
        && !(info.MappedPageFile && (info.MappedDataFile || info.MappedImage || info.MappedPhysical))
        && !(info.Private && (info.MappedDataFile || info.MappedImage || info.MappedPageFile || info.MappedPhysical));
}
struct Handle {
    HANDLE value = nullptr;
    explicit Handle(HANDLE input = nullptr) : value(input) {}
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
    ~Handle() { if (value) { CloseHandle(value); } }
};
struct Process {
    std::uint32_t pid;
    std::uint64_t creation;
    Handle query, read;
    QString name;
    // Only retained ordinary WS observations need deduplicating in pass two.
    // They are sorted VA values, avoiding a second tree per mapping reference.
    std::vector<std::uint64_t> baselineAddresses;
    std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t, DWORD, QString>, std::uint32_t> backings;
    bool readIdentityMismatch = false;
    DWORD readError = 0;
};

// Stage 0 = before, 1 = sampled phase endpoint, 2 = final after.
// These maxima are endpoint samples, not a continuous or lifetime high-water mark.
void sampleMappingObserver(Mappings& result, unsigned stage)
{
    if (stage == 2) { result.observerAfterKnown = false; }
    PROCESS_MEMORY_COUNTERS_EX memory{};
    memory.cb = sizeof(memory);
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory))) {
        ++result.observerMemorySamples;
        result.observerWorkingSetMax = std::max<std::uint64_t>(result.observerWorkingSetMax, memory.WorkingSetSize);
        result.observerPrivateMax = std::max<std::uint64_t>(result.observerPrivateMax, memory.PrivateUsage);
        if (stage == 0) {
            result.observerBeforeKnown = true;
            result.observerWorkingSetBefore = memory.WorkingSetSize;
            result.observerPrivateBefore = memory.PrivateUsage;
        } else if (stage == 2) {
            result.observerAfterKnown = true;
            result.observerWorkingSetAfter = memory.WorkingSetSize;
            result.observerPrivateAfter = memory.PrivateUsage;
        }
    }
    result.observerMemoryKnown = result.observerBeforeKnown && result.observerAfterKnown;
}

bool regionContains(const MEMORY_BASIC_INFORMATION& region, std::uint64_t address)
{
    const auto base = reinterpret_cast<std::uint64_t>(region.BaseAddress);
    return address >= base && address - base < region.RegionSize;
}

std::uint64_t fileKey(const KSWORD_ARK_PFN_IDENTITY& identity)
{
    const auto use = identity.frame & 15;
    return identity.frame != ~0ULL && (use == 1 || use == 8)
        && ((identity.frame >> 4) & 7) == 6 ? identity.backing & ~3ULL : 0;
}

// A path observation must surround a stable file-key and VA->PFN observation.
// Conflicting names suppress the join rather than guessing which observation won.
void observeFile(Mappings& result, std::set<std::uint64_t>& conflicts,
    std::uint64_t key, const QString& path)
{
    if (!key || path.isEmpty() || conflicts.count(key)) { return; }
    const auto previous = result.observedFileNames.find(key);
    if (previous != result.observedFileNames.end()) {
        if (previous->second.compare(path, Qt::CaseInsensitive) != 0) {
            result.observedFileNames.erase(previous);
            conflicts.insert(key);
            ++result.conflictingFileKeys;
        }
    } else if (result.observedFileNames.size() < 65536) {
        result.observedFileNames.emplace(key, path);
    }
}

std::shared_ptr<Mappings> collect(const std::shared_ptr<MappingJob>& job, unsigned seconds)
{
    auto result = std::make_shared<Mappings>();
    sampleMappingObserver(*result, 0);
    result->sampledAt = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
    result->domain = QStringLiteral("windows-user-va-pfn-observation");
    result->epoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
    result->ledgerContextEpoch = job->ledgerContextEpoch;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    ark::PfnQueryClient client;
    result->driverAvailable = client.mappingAvailable();
    if (!result->driverAvailable) { return result; }
    std::vector<DWORD> pids(65536);
    DWORD pidBytes = 0;
    if (!EnumProcesses(pids.data(), static_cast<DWORD>(pids.size() * sizeof(DWORD)), &pidBytes)) {
        result->status = static_cast<long>(0xC0000001UL);
        return result;
    }
    if (pidBytes == pids.size() * sizeof(DWORD)) { result->budgetReached = true; }
    if (pidBytes > pids.size() * sizeof(DWORD) || pidBytes % sizeof(DWORD)) {
        result->status = static_cast<long>(0xC000003EUL);
        return result;
    }
    pids.resize(pidBytes / sizeof(DWORD));
    result->processes = static_cast<std::uint32_t>(pids.size());
    bool unsupported = false;
    auto stopped = [&](bool checkProbeBudget = false) {
        if (job->stopping()) { result->cancelled = true; return true; }
        if (unsupported) { return true; }
        if (std::chrono::steady_clock::now() >= deadline || result->rows.size() >= maxReferences
            || (checkProbeBudget && result->virtualPagesProbed >= maxProbedPages)) {
            result->budgetReached = true;
            return true;
        }
        return false;
    };
    std::set<std::uint64_t> conflicts;
    std::vector<std::size_t> representatives;
    // Both discovery passes use the same row validation. Baseline VAs are sorted
    // and unique; each supplemental VA is visited once by the monotonic sweep.
    auto retain = [&](Process& process, const std::vector<std::uint64_t>& addresses, bool baseline) {
        for (std::size_t offset = 0; offset < addresses.size() && !stopped(); ) {
            MEMORY_BASIC_INFORMATION region{};
            if (VirtualQueryEx(process.query.value, reinterpret_cast<void*>(addresses[offset]), &region, sizeof(region)) != sizeof(region)
                || !regionContains(region, addresses[offset])) {
                ++result->regionQueryFailures;
                ++result->failed;
                ++offset;
                continue;
            }
            std::size_t batchCount = 1;
            while (batchCount < KSWORD_ARK_PFN_MAX_MAPPINGS && offset + batchCount < addresses.size()
                && regionContains(region, addresses[offset + batchCount])) { ++batchCount; }
            std::vector<std::uint64_t> batch(addresses.begin() + offset, addresses.begin() + offset + batchCount);
            std::vector<KSWORD_ARK_PFN_MAPPING> translated;
            result->status = client.mappings(process.pid, process.creation, batch, translated);
            if (result->status < 0 || translated.empty() || translated.size() > batch.size()) {
                result->failed += addresses.size() - offset;
                unsupported = result->status == static_cast<long>(0xC00000BBUL);
                return false;
            }
            batch.resize(translated.size());
            std::vector<std::uint64_t> pfns;
            std::vector<std::size_t> positions;
            for (std::size_t i = 0; i < translated.size(); ++i) {
                if (translated[i].status >= 0 && translated[i].pfn != ~0ULL) { pfns.push_back(translated[i].pfn); positions.push_back(i); }
            }
            std::vector<KSWORD_ARK_PFN_IDENTITY> identities;
            std::vector<std::uint64_t> fileKeys(translated.size());
            long nativeBeforeStatus = static_cast<long>(0xC00000BBUL);
            const bool mapped = region.Type == MEM_MAPPED || region.Type == MEM_IMAGE;
            if (!pfns.empty() && (nativeBeforeStatus = client.identities(pfns, identities)) >= 0 && identities.size() == pfns.size()) {
                for (std::size_t i = 0; i < identities.size(); ++i) { fileKeys[positions[i]] = fileKey(identities[i]); }
            }
            QString path;
            auto pathStatus = mapped ? MappingPathStatus::Unavailable : MappingPathStatus::NotApplicable;
            DWORD pathError = 0;
            if (mapped && process.read.value) {
                wchar_t name[32768]{};
                const DWORD length = GetMappedFileNameW(process.read.value, reinterpret_cast<void*>(batch.front()), name, static_cast<DWORD>(std::size(name)));
                // A full buffer can be a truncated path, not an owner identity.
                if (length && length < std::size(name)) { path = QString::fromWCharArray(name, static_cast<int>(length)); pathStatus = MappingPathStatus::Resolved; }
                else if (length) { pathStatus = MappingPathStatus::Truncated; }
                else { pathError = GetLastError(); }
            } else if (mapped) {
                pathStatus = process.readIdentityMismatch ? MappingPathStatus::IdentityChanged
                    : (process.readError == ERROR_ACCESS_DENIED ? MappingPathStatus::AccessDenied : MappingPathStatus::Unavailable);
                pathError = process.readError;
            }
            RegionInfo allocationBefore{}, allocationAfter{};
            const bool beforeKnown = allocationInfo(process.query.value, batch.front(), allocationBefore);
            MEMORY_BASIC_INFORMATION afterRegion{};
            const bool regionStable = VirtualQueryEx(process.query.value, reinterpret_cast<void*>(batch.front()), &afterRegion, sizeof(afterRegion)) == sizeof(afterRegion)
                && afterRegion.AllocationBase == region.AllocationBase && afterRegion.Type == region.Type
                && regionContains(afterRegion, batch.back());
            const bool afterKnown = allocationInfo(process.query.value, batch.front(), allocationAfter);
            const bool allocationKnown = beforeKnown && afterKnown && allocationBefore.AllocationBase == region.AllocationBase
                && allocationAfter.AllocationBase == region.AllocationBase && allocationBefore.RegionSize == allocationAfter.RegionSize
                && allocationBefore.AllocationProtect == region.AllocationProtect && allocationAfter.AllocationProtect == region.AllocationProtect
                && allocationBefore.Private == allocationAfter.Private && allocationBefore.MappedDataFile == allocationAfter.MappedDataFile
                && allocationBefore.MappedImage == allocationAfter.MappedImage && allocationBefore.MappedPageFile == allocationAfter.MappedPageFile
                && allocationBefore.MappedPhysical == allocationAfter.MappedPhysical;
            std::vector<PSAPI_WORKING_SET_EX_INFORMATION> extended(batch.size());
            for (std::size_t i = 0; i < extended.size(); ++i) { extended[i].VirtualAddress = reinterpret_cast<void*>(batch[i]); }
            const bool extendedOk = QueryWorkingSetEx(process.query.value, extended.data(), static_cast<DWORD>(extended.size() * sizeof(extended[0]))) != FALSE;
            if (!extendedOk) { ++result->workingSetQueryFailures; }
            std::vector<KSWORD_ARK_PFN_MAPPING> confirmed;
            result->status = client.mappings(process.pid, process.creation, batch, confirmed);
            if (result->status < 0 || confirmed.empty() || confirmed.size() > batch.size()) {
                result->failed += addresses.size() - offset;
                unsupported = result->status == static_cast<long>(0xC00000BBUL);
                return false;
            }
            std::vector<KSWORD_ARK_PFN_IDENTITY> afterIdentities;
            long nativeAfterStatus = static_cast<long>(0xC00000BBUL);
            const bool identityStable = !pfns.empty() && identities.size() == pfns.size()
                && (nativeAfterStatus = client.identities(pfns, afterIdentities)) >= 0 && afterIdentities.size() == identities.size();
            std::vector<std::uint64_t> afterKeys(translated.size());
            std::vector<KSWORD_ARK_PFN_IDENTITY> initialIdentities(translated.size());
            std::vector<KSWORD_ARK_PFN_IDENTITY> retainedIdentities(translated.size());
            std::vector<bool> identityKnown(translated.size());
            if (identities.size() == pfns.size()) {
                for (std::size_t i = 0; i < identities.size(); ++i) { initialIdentities[positions[i]] = identities[i]; }
            }
            if (identityStable) {
                for (std::size_t i = 0; i < afterIdentities.size(); ++i) {
                    afterKeys[positions[i]] = fileKey(afterIdentities[i]);
                    identityKnown[positions[i]] = identities[i].frame == afterIdentities[i].frame
                        && identities[i].backing == afterIdentities[i].backing && afterIdentities[i].frame != ~0ULL;
                    retainedIdentities[positions[i]] = afterIdentities[i];
                }
            }
            for (std::size_t i = 0; i < confirmed.size(); ++i) {
                ++result->tested;
                if (translated[i].status < 0 || translated[i].pfn == ~0ULL
                    || confirmed[i].status < 0 || confirmed[i].pfn == ~0ULL || !extendedOk) { ++result->failed; continue; }
                if (translated[i].pfn != confirmed[i].pfn || translated[i].pageSize != confirmed[i].pageSize
                    || !extended[i].VirtualAttributes.Valid || !regionStable) {
                    ++result->changedMappings;
                    continue;
                }
                const auto allocation = reinterpret_cast<std::uint64_t>(region.AllocationBase);
                const bool stableFile = fileKeys[i] && fileKeys[i] == afterKeys[i];
                const auto rowPath = (fileKeys[i] || afterKeys[i]) && !stableFile ? QString{} : path;
                const auto indexKey = std::make_tuple(allocation, reinterpret_cast<std::uint64_t>(region.BaseAddress),
                    static_cast<std::uint64_t>(region.RegionSize), region.Type, rowPath);
                auto backing = process.backings.find(indexKey);
                if (backing == process.backings.end()) {
                    backing = process.backings.emplace(indexKey, static_cast<std::uint32_t>(result->backing.size())).first;
                    Backing detail{process.name, rowPath, region.Type};
                    detail.pid = process.pid;
                    detail.processCreateTime = process.creation;
                    detail.allocationBase = allocation;
                    detail.regionBase = reinterpret_cast<std::uint64_t>(region.BaseAddress);
                    detail.regionSize = region.RegionSize;
                    detail.pathStatus = (fileKeys[i] || afterKeys[i]) && !stableFile ? MappingPathStatus::IdentityChanged : pathStatus;
                    detail.pathError = pathError;
                    detail.regionInformationKnown = allocationKnown;
                    if (allocationKnown) {
                        detail.mappedPageFile = allocationAfter.MappedPageFile != 0;
                        detail.mappedDataFile = allocationAfter.MappedDataFile != 0;
                        detail.mappedImage = allocationAfter.MappedImage != 0;
                        detail.mappedPhysical = allocationAfter.MappedPhysical != 0;
                    }
                    representatives.push_back(result->rows.size());
                    result->backing.push_back(std::move(detail));
                }
                Mapping row;
                row.pfn = confirmed[i].pfn;
                row.address = batch[i];
                row.pid = process.pid;
                row.processCreateTime = process.creation;
                row.pfnRevalidated = true;
                row.nativeIdentityKnown = identityKnown[i];
                row.nativeBeforeStatus = nativeBeforeStatus;
                row.nativeAfterStatus = nativeAfterStatus;
                row.mappingBeforeStatus = translated[i].status;
                row.mappingAfterStatus = confirmed[i].status;
                row.nativeFrameBefore = initialIdentities[i].frame;
                row.nativeBackingBefore = initialIdentities[i].backing;
                row.nativeFrame = retainedIdentities[i].frame;
                row.nativeBacking = retainedIdentities[i].backing;
                if (row.nativeIdentityKnown) {
                    row.nativeFileKey = fileKey(retainedIdentities[i]);
                }
                row.pageSize = confirmed[i].pageSize;
                row.backingIndex = backing->second;
                if (stableFile) { observeFile(*result, conflicts, fileKeys[i], path); }
                row.attributesKnown = true;
                row.locked = extended[i].VirtualAttributes.Locked != 0;
                row.shared = extended[i].VirtualAttributes.Shared != 0;
                row.shareCount = static_cast<std::uint32_t>(extended[i].VirtualAttributes.ShareCount);
                result->rows.push_back(row);
                if (baseline) { process.baselineAddresses.push_back(row.address); }
                if (result->rows.size() >= maxReferences) { result->budgetReached = true; break; }
            }
            offset += confirmed.size(); // Resume either driver's bounded, partially processed batch.
            job->tested.store(result->tested);
        }
        return !stopped();
    };

    std::vector<Process> processes;
    // Ordinary residents in every accessible process have priority over large,
    // sparse reserved arenas in the supplemental VA sweep. Hold process objects
    // through both passes, so PID reuse cannot alter the second pass or its dedup.
    for (DWORD pid : pids) {
        if (stopped()) { break; }
        Handle query{OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid)};
        if (!query.value) { ++result->inaccessible; continue; }
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(query.value, &created, &exited, &kernel, &user)) { ++result->inaccessible; continue; }
        const auto creation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        wchar_t processPath[32768]{};
        DWORD chars = static_cast<DWORD>(std::size(processPath));
        const QString name = QueryFullProcessImageNameW(query.value, 0, processPath, &chars)
            ? QString::fromWCharArray(processPath, static_cast<int>(chars)) : QString{};
        // WS enumeration / mapped filenames need VM_READ; QueryWorkingSetEx and
        // VirtualQueryEx still work with query access when this handle is denied.
        Handle read{OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)};
        const DWORD readError = read.value ? 0 : GetLastError();
        bool readIdentityMismatch = false;
        if (read.value) {
            FILETIME readCreated{};
            if (!GetProcessTimes(read.value, &readCreated, &exited, &kernel, &user)
                || readCreated.dwHighDateTime != created.dwHighDateTime
                || readCreated.dwLowDateTime != created.dwLowDateTime) {
                CloseHandle(read.value);
                read.value = nullptr;
                readIdentityMismatch = true;
            }
        }
        processes.push_back(Process{pid, creation, std::move(query), std::move(read), name, {}, {}});
        auto& process = processes.back();
        process.readIdentityMismatch = readIdentityMismatch;
        process.readError = readIdentityMismatch ? ERROR_INVALID_PARAMETER : readError;
        if (!process.read.value) { continue; }
        std::vector<std::uint64_t> wsStorage(8192);
        bool haveWs = false;
        while (!stopped() && wsStorage.size() * sizeof(std::uint64_t) <= 64ULL * 1024 * 1024) {
            if (QueryWorkingSet(process.read.value, wsStorage.data(), static_cast<DWORD>(wsStorage.size() * sizeof(std::uint64_t)))) { haveWs = true; break; }
            if (GetLastError() != ERROR_BAD_LENGTH || wsStorage.size() * sizeof(std::uint64_t) >= 64ULL * 1024 * 1024) { break; }
            wsStorage.resize(wsStorage.size() * 2);
        }
        if (!haveWs) { if (!stopped()) { ++result->workingSetQueryFailures; } continue; }
        const auto* ws = reinterpret_cast<const PSAPI_WORKING_SET_INFORMATION*>(wsStorage.data());
        if (ws->NumberOfEntries > wsStorage.size() - 1) { ++result->workingSetQueryFailures; continue; }
        std::vector<std::uint64_t> addresses;
        addresses.reserve(ws->NumberOfEntries);
        for (ULONG_PTR i = 0; i < ws->NumberOfEntries; ++i) { addresses.push_back(ws->WorkingSetInfo[i].VirtualPage << 12); }
        std::sort(addresses.begin(), addresses.end());
        addresses.erase(std::unique(addresses.begin(), addresses.end()), addresses.end());
        std::vector<std::uint64_t>().swap(wsStorage);
        if (retain(process, addresses, true)) { ++result->workingSetProcesses; }
    }

    // Concrete kernel consumer observations get a bounded share after ordinary
    // resident discovery; sparse supplemental reservations cannot starve them.
    sampleMappingObserver(*result, 1);
    const auto consumerSeconds = std::min<unsigned>(15, std::max<unsigned>(1, seconds / 4));
    collectPhysicalConsumers(*result, job->cancel, std::min(deadline,
        std::chrono::steady_clock::now() + std::chrono::seconds(consumerSeconds)));
    sampleMappingObserver(*result, 1);
    for (auto& process : processes) {
        if (stopped(true)) { break; }
        std::uint64_t cursor = 0;
        bool completed = false, processFailed = false;
        while (!stopped(true) && !processFailed) {
            MEMORY_BASIC_INFORMATION region{};
            if (VirtualQueryEx(process.query.value, reinterpret_cast<void*>(cursor), &region, sizeof(region)) != sizeof(region)) {
                if (GetLastError() == ERROR_INVALID_PARAMETER) { completed = true; }
                else { ++result->regionQueryFailures; }
                break;
            }
            const auto base = reinterpret_cast<std::uint64_t>(region.BaseAddress);
            if (!regionContains(region, cursor) || region.RegionSize > std::numeric_limits<std::uint64_t>::max() - base) {
                ++result->regionQueryFailures;
                break;
            }
            const auto regionEnd = base + region.RegionSize;
            // QueryWorkingSet excludes AWE and large-page allocations. Probe
            // committed regions and reserved AWE windows with QueryWorkingSetEx
            // instead; ordinary PAGE_NOACCESS reservations need no page walk.
            const bool probe = region.State == MEM_COMMIT
                || (region.State == MEM_RESERVE && region.Type == MEM_PRIVATE
                    && (region.AllocationProtect & 0xff) != PAGE_NOACCESS
                    && (region.AllocationProtect & 0xff) != 0);
            if (probe) {
                for (auto address = cursor; address < regionEnd && !stopped(true) && !processFailed; ) {
                    const auto count = static_cast<std::size_t>(std::min<std::uint64_t>(
                        probeBatchPages, std::min((regionEnd - address) / pageBytes, maxProbedPages - result->virtualPagesProbed)));
                    if (!count) { ++result->regionQueryFailures; processFailed = true; break; }
                    std::vector<PSAPI_WORKING_SET_EX_INFORMATION> probed(count);
                    for (std::size_t i = 0; i < count; ++i) { probed[i].VirtualAddress = reinterpret_cast<void*>(address + i * pageBytes); }
                    result->virtualPagesProbed += count;
                    if (!QueryWorkingSetEx(process.query.value, probed.data(), static_cast<DWORD>(probed.size() * sizeof(probed[0])))) {
                        ++result->workingSetQueryFailures;
                        address += count * pageBytes;
                        continue;
                    }
                    std::vector<std::uint64_t> addresses;
                    for (const auto& page : probed) {
                        const auto va = reinterpret_cast<std::uint64_t>(page.VirtualAddress);
                        if (page.VirtualAttributes.Valid
                            && !std::binary_search(process.baselineAddresses.begin(), process.baselineAddresses.end(), va)) { addresses.push_back(va); }
                    }
                    // Process residents found by the final allowed probe too;
                    // its discovery work already fits the supplemental cap.
                    if (!retain(process, addresses, false)) { processFailed = true; }
                    address += count * pageBytes;
                }
            }
            cursor = regionEnd;
        }
        if (completed) { ++result->scannedProcesses; }
    }
    // This narrower object provider never turns an allocation VA, a handle, or
    // the native shareable-page backing union into a Section object identity.
    // Existing R0 APIs expose the main image Section and file ControlAreas only.
    ark::DriverClient objects;
    auto current = [&](const Process& process, const Mapping& row, const Backing& backing, MappingWitnessProof& proof) {
        std::vector<KSWORD_ARK_PFN_MAPPING> maps;
        proof = {};
        proof.mappingStatus = client.mappings(process.pid, process.creation, {row.address}, maps);
        if (maps.size() == 1) {
            proof.pfn = maps[0].pfn; proof.pageSize = maps[0].pageSize; proof.entryStatus = maps[0].status;
        }
        if (proof.mappingStatus < 0 || maps.size() != 1 || maps[0].status < 0
            || maps[0].pfn != row.pfn || maps[0].pageSize != row.pageSize) { return false; }
        MEMORY_BASIC_INFORMATION region{};
        proof.regionQueried = VirtualQueryEx(process.query.value, reinterpret_cast<void*>(row.address), &region, sizeof(region)) == sizeof(region);
        if (proof.regionQueried) {
            proof.allocationBase = reinterpret_cast<std::uint64_t>(region.AllocationBase);
            proof.regionBase = reinterpret_cast<std::uint64_t>(region.BaseAddress);
            proof.regionSize = region.RegionSize; proof.regionKind = region.Type;
        }
        if (!proof.regionQueried || !regionContains(region, row.address)
            || reinterpret_cast<std::uint64_t>(region.AllocationBase) != backing.allocationBase || region.Type != backing.kind) { return false; }
        if (row.nativeIdentityKnown) {
            std::vector<KSWORD_ARK_PFN_IDENTITY> identities;
            proof.nativeQueried = true;
            proof.nativeStatus = client.identities({row.pfn}, identities);
            if (identities.size() == 1) { proof.nativeFrame = identities[0].frame; proof.nativeBacking = identities[0].backing; }
            if (proof.nativeStatus < 0 || identities.size() != 1
                || identities[0].frame != row.nativeFrame || identities[0].backing != row.nativeBacking) { return false; }
        }
        return true;
    };
    for (std::size_t index = 0; index < result->backing.size(); ++index) {
        auto& backing = result->backing[index];
        if (backing.kind != MEM_IMAGE && backing.kind != MEM_MAPPED) { continue; }
        if (job->stopping() || std::chrono::steady_clock::now() >= deadline || result->objectQueries > 508) {
            result->objectBudgetReached = true;
            break;
        }
        const auto process = std::find_if(processes.begin(), processes.end(), [&](const Process& context) {
            return context.pid == backing.pid && context.creation == backing.processCreateTime;
        });
        if (process == processes.end() || representatives[index] >= result->rows.size()) { continue; }
        const auto& row = result->rows[representatives[index]];
        if (backing.kind != MEM_IMAGE && (backing.pathStatus != MappingPathStatus::Resolved
            || backing.path.isEmpty() || backing.mappedPageFile)) { continue; }
        MappingWitnessProof initialWitness;
        if (!current(*process, row, backing, initialWitness)) {
            backing.objectStatus = initialWitness.mappingStatus < 0 ? initialWitness.mappingStatus : static_cast<long>(0xC000022DUL);
            continue;
        }
        auto proof = std::make_shared<ObjectEvidence>();
        proof->witnessBefore = initialWitness;
        backing.objectEvidence = proof;
        if (backing.kind == MEM_IMAGE) {
            auto before = objects.queryProcessSection(process->pid);
            ++result->objectQueries;
            backing.objectStatus = before.io.ok ? before.lastStatus : before.io.ntStatus;
            backing.objectQueryStatus = before.queryStatus;
            backing.objectFieldFlags = before.fieldFlags;
            backing.objectCapabilityMask = before.dynDataCapabilityMask;
            auto captureMain = [&](const auto& packet) {
                ObjectQueryProof proof;
                proof.provider = ObjectQueryProvider::ProcessImageSection;
                proof.transportOk = packet.io.ok; proof.ioStatus = packet.io.ntStatus; proof.lastStatus = packet.lastStatus;
                proof.version = packet.version; proof.queryFlags = KSWORD_ARK_SECTION_QUERY_FLAG_INCLUDE_ALL;
                proof.queryStatus = packet.queryStatus; proof.fieldFlags = packet.fieldFlags; proof.queryPid = packet.processId;
                proof.capabilityMask = packet.dynDataCapabilityMask;
                proof.sectionObject = packet.sectionObjectAddress; proof.controlArea = packet.controlAreaAddress;
                proof.offsets = {packet.epSectionObjectOffset, packet.mmSectionControlAreaOffset,
                    packet.mmControlAreaListHeadOffset, packet.mmControlAreaLockOffset};
                const auto view = std::find_if(packet.mappings.begin(), packet.mappings.end(), [&](const auto& value) {
                    return value.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS && value.processId == process->pid
                        && row.address >= value.startVa && row.address < value.endVa;
                });
                if (view != packet.mappings.end()) {
                    proof.matchingView = true; proof.viewPid = view->processId; proof.viewType = view->viewMapType;
                    proof.viewStart = view->startVa; proof.viewEnd = view->endVa;
                    // Process-section entries expose no independent section-kind or ControlArea field.
                }
                return proof;
            };
            proof->before = captureMain(before);
            const auto required = KSWORD_ARK_SECTION_FIELD_SECTION_OBJECT_PRESENT | KSWORD_ARK_SECTION_FIELD_CONTROL_AREA_PRESENT
                | KSWORD_ARK_SECTION_FIELD_MAPPING_LIST_PRESENT;
            auto contains = [&](const auto& evidence) {
                return evidence.io.ok && evidence.processId == process->pid && evidence.lastStatus >= 0
                    && (evidence.fieldFlags & required) == required
                    && !(evidence.fieldFlags & KSWORD_ARK_SECTION_FIELD_REMOTE_MAPPING_UNSUPPORTED)
                    && evidence.sectionObjectAddress && evidence.controlAreaAddress
                    && std::any_of(evidence.mappings.begin(), evidence.mappings.end(), [&](const auto& view) {
                        return view.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS && view.processId == process->pid
                            && row.address >= view.startVa && row.address < view.endVa;
                    });
            };
            if (contains(before)) {
                auto after = objects.queryProcessSection(process->pid);
                ++result->objectQueries;
                proof->after = captureMain(after);
                if (contains(after) && before.sectionObjectAddress == after.sectionObjectAddress
                    && before.controlAreaAddress == after.controlAreaAddress && current(*process, row, backing, proof->witnessAfter)) {
                    backing.sectionObject = after.sectionObjectAddress;
                    backing.controlArea = after.controlAreaAddress;
                    backing.objectSource = MappingObjectSource::VerifiedMainImageSection;
                    backing.objectWitnessPfn = row.pfn;
                    backing.objectWitnessVa = row.address;
                    backing.objectStatus = 0;
                    ++result->verifiedObjectRelations;
                    continue;
                }
            }
        }
        if (backing.pathStatus != MappingPathStatus::Resolved || backing.path.isEmpty() || backing.mappedPageFile) { continue; }
        // A path-opened FileObject need not equal a PFN's FileObject instance.
        // Join only a returned ControlArea view that names this exact PID/VA,
        // and revalidate both that relation and the pinned VA/PFN observation.
        auto before = objects.queryFileSectionMappings(backing.path.toStdWString());
        ++result->objectQueries;
        backing.objectStatus = before.io.ok ? before.lastStatus : before.io.ntStatus;
        backing.objectQueryStatus = before.queryStatus;
        backing.objectFieldFlags = before.fieldFlags;
        backing.objectCapabilityMask = before.dynDataCapabilityMask;
        auto area = [&](const auto& evidence) -> std::uint64_t {
            if (!evidence.io.ok || evidence.lastStatus < 0
                || !(evidence.fieldFlags & KSWORD_ARK_FILE_SECTION_FIELD_MAPPING_LIST_PRESENT)) { return 0; }
            const bool image = backing.kind == MEM_IMAGE;
            const auto flag = image ? KSWORD_ARK_FILE_SECTION_FIELD_IMAGE_CONTROL_AREA_PRESENT : KSWORD_ARK_FILE_SECTION_FIELD_DATA_CONTROL_AREA_PRESENT;
            const auto key = image ? evidence.imageControlAreaAddress : evidence.dataControlAreaAddress;
            if (!(evidence.fieldFlags & flag) || !key) { return 0; }
            return std::any_of(evidence.mappings.begin(), evidence.mappings.end(), [&](const auto& view) {
                return view.sectionKind == (image ? KSWORD_ARK_FILE_SECTION_KIND_IMAGE : KSWORD_ARK_FILE_SECTION_KIND_DATA)
                    && view.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS && view.processId == process->pid
                    && view.controlAreaAddress == key && row.address >= view.startVa && row.address < view.endVa;
            }) ? key : 0;
        };
        auto captureFile = [&](const auto& packet) {
            ObjectQueryProof proof;
            proof.provider = ObjectQueryProvider::FileControlArea;
            proof.transportOk = packet.io.ok; proof.ioStatus = packet.io.ntStatus; proof.lastStatus = packet.lastStatus;
            proof.version = packet.version; proof.queryFlags = KSWORD_ARK_FILE_SECTION_QUERY_FLAG_INCLUDE_ALL;
            proof.queryStatus = packet.queryStatus; proof.fieldFlags = packet.fieldFlags;
            proof.capabilityMask = packet.dynDataCapabilityMask;
            proof.controlArea = backing.kind == MEM_IMAGE ? packet.imageControlAreaAddress : packet.dataControlAreaAddress;
            proof.offsets = {0, 0, packet.mmControlAreaListHeadOffset, packet.mmControlAreaLockOffset};
            const auto kind = backing.kind == MEM_IMAGE ? KSWORD_ARK_FILE_SECTION_KIND_IMAGE : KSWORD_ARK_FILE_SECTION_KIND_DATA;
            const auto view = std::find_if(packet.mappings.begin(), packet.mappings.end(), [&](const auto& value) {
                return value.sectionKind == kind && value.viewMapType == KSWORD_ARK_SECTION_MAP_TYPE_PROCESS
                    && value.processId == process->pid && value.controlAreaAddress == proof.controlArea
                    && row.address >= value.startVa && row.address < value.endVa;
            });
            if (view != packet.mappings.end()) {
                proof.matchingView = true; proof.viewPid = view->processId; proof.viewType = view->viewMapType;
                proof.viewKind = view->sectionKind; proof.viewStart = view->startVa; proof.viewEnd = view->endVa;
                proof.viewControlArea = view->controlAreaAddress;
            }
            return proof;
        };
        proof->before = captureFile(before);
        proof->after = {};
        proof->witnessAfter = {};
        const auto beforeArea = area(before);
        if (beforeArea) {
            auto after = objects.queryFileSectionMappings(backing.path.toStdWString());
            ++result->objectQueries;
            proof->after = captureFile(after);
            if (area(after) == beforeArea && current(*process, row, backing, proof->witnessAfter)) {
                backing.controlArea = beforeArea;
                backing.objectSource = MappingObjectSource::VerifiedFileControlArea;
                backing.objectWitnessPfn = row.pfn;
                backing.objectWitnessVa = row.address;
                backing.objectStatus = 0;
                ++result->verifiedObjectRelations;
            }
        }
    }
    sampleMappingObserver(*result, 1);
    std::sort(result->rows.begin(), result->rows.end(), [](const Mapping& a, const Mapping& b) {
        if (a.pfn != b.pfn) { return a.pfn < b.pfn; }
        if (a.pid != b.pid) { return a.pid < b.pid; }
        return a.address < b.address;
    });
    for (std::size_t i = 0; i < result->rows.size(); ) {
        std::size_t end = i + 1;
        while (end < result->rows.size() && result->rows[end].pfn == result->rows[i].pfn) { ++end; }
        bool large = false, locked = false;
        for (std::size_t j = i; j < end; ++j) { large |= result->rows[j].pageSize > pageBytes; locked |= result->rows[j].locked; }
        ++result->distinct;
        result->large += large ? 1 : 0;
        result->locked += locked ? 1 : 0;
        bool conflict = false, allKnown = true;
        const Mapping* identity = nullptr;
        for (std::size_t j = i; j < end; ++j) {
            const auto& row = result->rows[j];
            allKnown &= row.nativeIdentityKnown;
            if (!row.nativeIdentityKnown) { continue; }
            if (identity && (identity->nativeFrame != row.nativeFrame || identity->nativeBacking != row.nativeBacking)) { conflict = true; }
            identity = &row;
        }
        result->identityConflicted += conflict ? 1 : 0;
        // Sequential observations do not establish simultaneous sharing.
        // Incompatible or unavailable native identities cannot establish aliases.
        result->multiplyMapped += end - i > 1 && allKnown && !conflict ? 1 : 0;
        i = end;
    }
    return result;
}
}
void collectPhysicalMappings(const std::shared_ptr<MappingJob>& job, unsigned seconds)
{
    std::shared_ptr<Mappings> result;
    try { result = collect(job, seconds); }
    catch (...) {
        try { result = std::make_shared<Mappings>(); result->failedAllocation = true; }
        catch (...) { /* Null also denotes resource failure. */ }
    }
    if (result) { sampleMappingObserver(*result, 2); result->finished = QDateTime::currentDateTime().toString(Qt::ISODateWithMs); }
    {
        std::lock_guard<std::mutex> lock(job->mutex);
        job->result = std::move(result);
    }
    job->done.store(true);
}
}
