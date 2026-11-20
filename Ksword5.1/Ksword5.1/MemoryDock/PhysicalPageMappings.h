#pragma once
#include <QString>
#include <atomic>
#include <array>
#include <cstdint>
#include <functional>
#include <memory>
#include <map>
#include <mutex>
#include <vector>

namespace ksword::pfn {
struct ConsumerEvidence;
enum class MappingPathStatus : std::uint32_t {
    NotApplicable, Resolved, Unavailable, AccessDenied, Truncated, IdentityChanged
};
enum class MappingObjectSource : std::uint32_t {
    ObservedAllocation, VerifiedMainImageSection, VerifiedFileControlArea
};
struct MappingWitnessProof {
    long mappingStatus = static_cast<long>(0xC00000BBUL), nativeStatus = static_cast<long>(0xC00000BBUL);
    long entryStatus = static_cast<long>(0xC00000BBUL);
    std::uint64_t pfn = ~0ULL, nativeFrame = 0, nativeBacking = 0;
    std::uint32_t pageSize = 0, regionKind = 0;
    std::uint64_t allocationBase = 0, regionBase = 0, regionSize = 0;
    bool nativeQueried = false, regionQueried = false;
};
enum class ObjectQueryProvider : std::uint32_t { None, ProcessImageSection, FileControlArea };
struct ObjectQueryProof {
    ObjectQueryProvider provider = ObjectQueryProvider::None;
    bool transportOk = false, matchingView = false;
    long ioStatus = static_cast<long>(0xC00000BBUL), lastStatus = static_cast<long>(0xC00000BBUL);
    std::uint32_t version = 0, queryFlags = 0, queryStatus = 0, fieldFlags = 0, queryPid = 0;
    std::uint64_t capabilityMask = 0, sectionObject = 0, controlArea = 0;
    std::uint32_t viewPid = 0, viewType = 0, viewKind = 0;
    std::uint64_t viewStart = 0, viewEnd = 0, viewControlArea = 0;
    std::array<std::uint32_t, 4> offsets{};
};
struct ObjectEvidence {
    ObjectQueryProof before, after;
    MappingWitnessProof witnessBefore, witnessAfter;
};
struct Mapping {
    std::uint64_t pfn = 0, address = 0;
    std::uint64_t processCreateTime = 0, nativeFrame = 0, nativeBacking = 0, nativeFileKey = 0;
    std::uint64_t nativeFrameBefore = 0, nativeBackingBefore = 0;
    std::uint32_t pid = 0, backingIndex = 0, pageSize = 0, shareCount = 0;
    bool locked = false, shared = false, attributesKnown = false;
    bool nativeIdentityKnown = false, pfnRevalidated = false;
    long nativeBeforeStatus = static_cast<long>(0xC00000BBUL), nativeAfterStatus = static_cast<long>(0xC00000BBUL);
    long mappingBeforeStatus = 0, mappingAfterStatus = 0;
};
struct Backing {
    QString process, path;
    std::uint32_t kind = 0, pid = 0;
    std::uint64_t processCreateTime = 0, allocationBase = 0, regionBase = 0, regionSize = 0;
    MappingPathStatus pathStatus = MappingPathStatus::NotApplicable;
    std::uint32_t pathError = 0;
    bool regionInformationKnown = false, mappedPageFile = false, mappedDataFile = false;
    bool mappedImage = false, mappedPhysical = false;
    MappingObjectSource objectSource = MappingObjectSource::ObservedAllocation;
    std::uint64_t sectionObject = 0, controlArea = 0;
    long objectStatus = static_cast<long>(0xC00000BBUL);
    std::uint32_t objectQueryStatus = 0, objectFieldFlags = 0;
    std::uint64_t objectCapabilityMask = 0;
    std::uint64_t objectWitnessPfn = 0, objectWitnessVa = 0;
    std::shared_ptr<const ObjectEvidence> objectEvidence{};
    // An observed consumer/view is not proof of a Section creator or allocation caller.
    bool creatorKnown = false;
};
struct Mappings {
    QString sampledAt, finished, domain, epoch, ledgerContextEpoch;
    std::vector<Mapping> rows;
    std::vector<Backing> backing;
    std::map<std::uint64_t, QString> observedFileNames;
    std::shared_ptr<ConsumerEvidence> consumers;
    std::uint64_t tested = 0, failed = 0, distinct = 0, large = 0, locked = 0, multiplyMapped = 0, identityConflicted = 0;
    std::uint64_t virtualPagesProbed = 0, changedMappings = 0, conflictingFileKeys = 0;
    std::uint32_t regionQueryFailures = 0, workingSetQueryFailures = 0;
    std::uint32_t processes = 0, inaccessible = 0, scannedProcesses = 0, workingSetProcesses = 0;
    std::uint32_t objectQueries = 0, verifiedObjectRelations = 0;
    std::uint64_t observerWorkingSetBefore = 0, observerWorkingSetAfter = 0, observerWorkingSetMax = 0;
    std::uint64_t observerPrivateBefore = 0, observerPrivateAfter = 0, observerPrivateMax = 0;
    std::uint32_t observerMemorySamples = 0;
    bool observerBeforeKnown = false, observerAfterKnown = false, observerMemoryKnown = false;
    bool observerMemoryPeakIsSampled = true;
    bool objectBudgetReached = false;
    // Existing path-input file APIs cannot reverse an arbitrary native PFN file key.
    long cacheFileNameProviderStatus = static_cast<long>(0xC00000BBUL);
    long anonymousSectionProviderStatus = static_cast<long>(0xC00000BBUL);
    long status = 0;
    bool cancelled = false, budgetReached = false, driverAvailable = false, failedAllocation = false;
};
struct MappingJob {
    // Immutable UI-supplied context only; this independent observation has its own epoch.
    QString ledgerContextEpoch;
    std::atomic_bool cancel{false}, done{false};
    std::function<bool()> externalCancel;
    bool stopping() { if (externalCancel && externalCancel()) cancel.store(true); return cancel.load(); }
    std::atomic<std::uint64_t> tested{0};
    std::mutex mutex;
    std::shared_ptr<Mappings> result;
};
void collectPhysicalMappings(const std::shared_ptr<MappingJob>& job, unsigned seconds);
}
