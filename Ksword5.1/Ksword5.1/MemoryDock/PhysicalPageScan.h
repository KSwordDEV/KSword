#pragma once
#include "../../../shared/evidence/PfnAccounting.h"
#include "../ArkDriverClient/ArkDriverPfn.h"
#include <QString>
#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>

namespace ksword::pfn {
struct QueryBatch {
    std::uint64_t ordinal = 0, firstPfn = 0, startUs = 0, endUs = 0;
    std::uint32_t pageCount = 0;
    unsigned nativeAccepted = 0, driverAccepted = 0;
    QString operation, started, finished, selectedPath;
    long status = 0;
    ark::PfnQueryTrace trace;
};
struct Owner {
    std::uint32_t pid = 0;
    QString name;
    bool seenBefore = false, seenAfter = false;
    bool leaseHeld = false, lifetimeVerified = false;
    std::uint64_t createTimeBefore = 0, createTimeAfter = 0;
};
struct Group {
    Use use = Use::Unknown;
    // pages is the disjoint in-use total (states 3, 4, 6, 7);
    // activePages is only its state-6 subset.
    std::uint64_t key = 0, pages = 0, activePages = 0, firstPfn = 0;
    QString name;
    std::uint32_t pid = 0;
    std::array<std::uint64_t, 8> pagesByState{};
    Identity firstIdentity;
    bool ownerSeenBefore = false, ownerSeenAfter = false, ownerLifetimeVerified = false;
    std::uint64_t ownerCreateTime = 0;
};
struct Scan {
    Accounting accounting;
    OwnerCoverage ownerCoverage;
    AuditCriterionSample auditSample;
    std::vector<Range> ranges;
    std::vector<Group> groups;
    std::map<std::uint64_t, Owner> owners;
    // Bounded sample of PFN identities for drill-down, never the accounting input.
    std::array<std::vector<std::pair<std::uint64_t, Identity>>, useCount> examples;
    QString started, finished;
    QString domain, epoch, nativeAbi, processArchitecture, nativeArchitecture, semanticValidation;
    std::uint32_t windowsMajor = 0, windowsMinor = 0, windowsBuild = 0;
    bool windowsVersionKnown = false, nativeAbiObserved = false, semanticsValidated = false;
    std::vector<QueryBatch> batches;
    std::uint64_t batchTimingOverflow = 0;
    QString rawEvidencePath, rawEvidenceError;
    bool rawEvidenceRequested = false, rawEvidenceFailed = false, rawEvidenceFinalized = false, rawEvidenceComplete = false;
    std::uint64_t rawEvidenceBytes = 0, rawEvidenceLedgerPages = 0, rawEvidenceAttemptPages = 0;
    std::uint64_t rawEvidenceChunks = 0, rawBufferPeakBytes = 0;
    std::uint64_t observerWorkingSetBefore = 0, observerWorkingSetAfter = 0, observerWorkingSetMax = 0;
    std::uint64_t observerPrivateBefore = 0, observerPrivateAfter = 0, observerPrivateMax = 0;
    bool observerMemoryKnown = false;
    bool observerMemoryBeforeKnown = false, observerMemoryAfterKnown = false;
    std::uint64_t observerMemorySamples = 0;
    std::uint64_t totalBefore = 0, availableBefore = 0, totalAfter = 0, availableAfter = 0, installed = 0;
    std::uint64_t nativeBatches = 0, driverBatches = 0, failedBatches = 0, groupedOverflowPages = 0;
    std::uint64_t recoveryQueries = 0, recoveredPages = 0;
    std::uint64_t unresolvedPrivatePages = 0, resolvedPrivatePages = 0, ownerConflicts = 0;
    std::uint64_t elapsedMs = 0;
    long rangesStatus = 0, ownersStatus = 0, lastPageStatus = 0;
    long ownersRecheckStatus = 0;
    bool cancelled = false, complete = false, hypervisor = false, secureKernel = false, secureKnown = false;
    bool resourceFailure = false, rangesChanged = false;
    bool ownersRechecked = false;
};
struct ScanJob {
    // Set on the UI thread before starting the worker. Empty disables spooling.
    QString rawEvidencePath;
    std::atomic_bool cancel{false}, done{false};
    std::function<bool()> externalCancel;
    bool stopping() const { return cancel.load() || (externalCancel && externalCancel()); }
    std::atomic<std::uint64_t> visited{0}, total{0};
    std::mutex mutex;
    std::shared_ptr<Scan> result;
};
void collectPhysicalPages(const std::shared_ptr<ScanJob>& job);
}
