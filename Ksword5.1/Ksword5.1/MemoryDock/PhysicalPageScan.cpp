#include "PhysicalPageScan.h"
#include "../ArkDriverClient/ArkDriverPfn.h"
#include <QDateTime>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUuid>
#include <Psapi.h>
#include <chrono>
#include <cstring>
#include <intrin.h>
#include <iterator>
#include <new>
#include <set>
#include <tuple>

namespace ksword::pfn {
namespace {
void memoryTotals(std::uint64_t& total, std::uint64_t& availableBytes)
{
    MEMORYSTATUSEX memory{};
    memory.dwLength = sizeof(memory);
    if (GlobalMemoryStatusEx(&memory)) { total = memory.ullTotalPhys; availableBytes = memory.ullAvailPhys; }
}

QString hex(std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 0, 16); }
QString statusHex(long value) { return hex(static_cast<std::uint32_t>(value)); }
QString utcNow() { return QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs); }
QJsonArray matrix(const OwnerCoverage::Matrix& values)
{
    QJsonArray result;
    for (const auto& row : values) {
        QJsonArray states;
        for (const auto value : row) { states.append(QString::number(value)); }
        result.append(states);
    }
    return result;
}
void observerMemory(Scan& scan, bool before = false, bool after = false)
{
    PROCESS_MEMORY_COUNTERS_EX memory{};
    if (!GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory))) { return; }
    ++scan.observerMemorySamples;
    scan.observerWorkingSetMax = std::max(scan.observerWorkingSetMax, static_cast<std::uint64_t>(memory.WorkingSetSize));
    scan.observerPrivateMax = std::max(scan.observerPrivateMax, static_cast<std::uint64_t>(memory.PrivateUsage));
    if (before) { scan.observerMemoryBeforeKnown = true; scan.observerWorkingSetBefore = memory.WorkingSetSize; scan.observerPrivateBefore = memory.PrivateUsage; }
    if (after) { scan.observerMemoryAfterKnown = true; scan.observerWorkingSetAfter = memory.WorkingSetSize; scan.observerPrivateAfter = memory.PrivateUsage; }
    scan.observerMemoryKnown = scan.observerMemoryBeforeKnown && scan.observerMemoryAfterKnown;
}
void provenance(Scan& scan)
{
    scan.epoch = QUuid::createUuid().toString(QUuid::WithoutBraces);
    wchar_t host[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD chars = static_cast<DWORD>(std::size(host));
    scan.domain = QStringLiteral("windows.nt-physical/vtl0/%1")
        .arg(GetComputerNameW(host, &chars) ? QString::fromWCharArray(host) : QStringLiteral("host-unavailable"));
    scan.processArchitecture = QStringLiteral("x64"); // This collector uses the explicit x64 native ABI.
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    switch (system.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64: scan.nativeArchitecture = QStringLiteral("x64"); break;
    case PROCESSOR_ARCHITECTURE_ARM64: scan.nativeArchitecture = QStringLiteral("arm64"); break;
    case PROCESSOR_ARCHITECTURE_INTEL: scan.nativeArchitecture = QStringLiteral("x86"); break;
    default: scan.nativeArchitecture = QStringLiteral("unknown"); break;
    }
    using Version = LONG(WINAPI*)(OSVERSIONINFOW*);
    const auto version = reinterpret_cast<Version>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion"));
    OSVERSIONINFOW os{};
    os.dwOSVersionInfoSize = sizeof(os);
    if (version && version(&os) >= 0) {
        scan.windowsVersionKnown = true;
        scan.windowsMajor = os.dwMajorVersion;
        scan.windowsMinor = os.dwMinorVersion;
        scan.windowsBuild = os.dwBuildNumber;
    }
    scan.nativeAbi = QStringLiteral("x64 Superfetch=45 PFN=1 PrivateSource=8 identityBytes=24");
    scan.semanticValidation = QStringLiteral("Observed query/layout status only; Windows build classification semantics are not validated by a support matrix");
    // Query success is not a semantic compatibility test. No supported-build
    // matrix is present, so the proposed acceptance criterion must stay pending.
    scan.semanticsValidated = false;
}

class RawEvidence {
public:
    explicit RawEvidence(Scan& scan) : m_scan(scan), m_file(scan.rawEvidencePath) {
        if (!scan.rawEvidenceRequested) { return; }
        if (!m_file.open(QIODevice::WriteOnly | QIODevice::Truncate)) { fail(m_file.errorString()); }
    }
    bool active() const { return m_scan.rawEvidenceRequested && !m_progress.failed && m_file.isOpen(); }
    QJsonObject record(const char* kind) const {
        return {{QStringLiteral("schema"), QStringLiteral("ksword.pfn.raw")}, {QStringLiteral("version"), 2},
            {QStringLiteral("kind"), QString::fromLatin1(kind)}, {QStringLiteral("domain"), m_scan.domain},
            {QStringLiteral("epoch"), m_scan.epoch}};
    }
    bool write(QJsonObject value) {
        if (!active()) { return false; }
        QByteArray data = QJsonDocument(value).toJson(QJsonDocument::Compact);
        data.append('\n');
        if (data.size() > 8 * 1024 * 1024) { fail(QStringLiteral("Encoded evidence record exceeded the 8 MiB bound")); return false; }
        observerMemory(m_scan);
        const bool ok = appendRawEvidence(m_progress, std::string_view(data.constData(), static_cast<std::size_t>(data.size())),
            [&](const char* bytes, std::size_t count) { return m_file.write(bytes, static_cast<qint64>(count)); });
        if (!ok) { fail(m_file.errorString()); }
        sync();
        return ok;
    }
    void header() {
        if (!active()) { return; }
        auto value = record("header");
        value.insert(QStringLiteral("started"), m_scan.started);
        value.insert(QStringLiteral("pageBytes"), static_cast<int>(pageBytes));
        value.insert(QStringLiteral("nativeAbi"), m_scan.nativeAbi);
        value.insert(QStringLiteral("semanticsValidated"), m_scan.semanticsValidated);
        value.insert(QStringLiteral("semanticValidation"), m_scan.semanticValidation);
        value.insert(QStringLiteral("build"), QJsonObject{{QStringLiteral("major"), static_cast<int>(m_scan.windowsMajor)},
            {QStringLiteral("minor"), static_cast<int>(m_scan.windowsMinor)}, {QStringLiteral("build"), static_cast<int>(m_scan.windowsBuild)},
            {QStringLiteral("known"), m_scan.windowsVersionKnown}});
        value.insert(QStringLiteral("architecture"), QJsonObject{{QStringLiteral("process"), m_scan.processArchitecture},
            {QStringLiteral("native"), m_scan.nativeArchitecture}});
        QJsonArray ranges;
        for (const auto& range : m_scan.ranges) {
            ranges.append(QJsonObject{{QStringLiteral("firstPfn"), hex(range.first)}, {QStringLiteral("pageCount"), QString::number(range.count)}});
        }
        value.insert(QStringLiteral("ranges"), ranges);
        value.insert(QStringLiteral("limits"), QJsonObject{{QStringLiteral("identityBatchPages"), 4096},
            {QStringLiteral("recoveryQueriesPerBatch"), 64}, {QStringLiteral("groups"), 65536},
            {QStringLiteral("samplesPerUse"), 256}, {QStringLiteral("timingRecords"), 4096},
            {QStringLiteral("rawEncodedRecordBytes"), 8 * 1024 * 1024}});
        value.insert(QStringLiteral("observerMemoryScope"), QStringLiteral("Entire KSword process; maxima are sampled values, not scan-only allocations or a guaranteed peak"));
        value.insert(QStringLiteral("observer"), QJsonObject{{QStringLiteral("workingSetBefore"), QString::number(m_scan.observerWorkingSetBefore)},
            {QStringLiteral("privateBefore"), QString::number(m_scan.observerPrivateBefore)}, {QStringLiteral("known"), m_scan.observerMemoryBeforeKnown}});
        value.insert(QStringLiteral("ownerRecordsScope"), QStringLiteral("Normalized process private-source records; not kernel/session private-source records"));
        value.insert(QStringLiteral("queryRecordsScope"), QStringLiteral("One normalized public PFN operation; per-path R3/R0 attempts and statuses are retained in query provenance"));
        value.insert(QStringLiteral("addressDomainSemantics"), QStringLiteral("NT-visible physical PFNs; guest GPA is not proven equal to host HPA and VTL0 does not expose every isolated domain"));
        if (write(std::move(value))) { m_progress.headerWritten = true; }
    }
    void query(const QueryBatch& batch) {
        if (!active()) { return; }
        auto value = record("query");
        value.insert(QStringLiteral("ordinal"), QString::number(batch.ordinal));
        value.insert(QStringLiteral("operation"), batch.operation);
        value.insert(QStringLiteral("firstPfn"), hex(batch.firstPfn));
        value.insert(QStringLiteral("pageCount"), QString::number(batch.pageCount));
        value.insert(QStringLiteral("startUs"), QString::number(batch.startUs));
        value.insert(QStringLiteral("endUs"), QString::number(batch.endUs));
        value.insert(QStringLiteral("started"), batch.started);
        value.insert(QStringLiteral("finished"), batch.finished);
        value.insert(QStringLiteral("status"), statusHex(batch.status));
        value.insert(QStringLiteral("selectedPath"), batch.selectedPath);
        value.insert(QStringLiteral("nativeAccepted"), static_cast<int>(batch.nativeAccepted));
        value.insert(QStringLiteral("driverAccepted"), static_cast<int>(batch.driverAccepted));
        QJsonArray attempts;
        for (unsigned i = 0; i < batch.trace.nativeAttemptCount; ++i) {
            const auto& attempt = batch.trace.nativeAttempts[i];
            attempts.append(QJsonObject{{QStringLiteral("informationClass"), static_cast<int>(attempt.informationClass)},
                {QStringLiteral("abiVersion"), static_cast<int>(attempt.abiVersion)}, {QStringLiteral("status"), statusHex(attempt.status)},
                {QStringLiteral("invoked"), attempt.invoked}});
        }
        value.insert(QStringLiteral("nativeAttempts"), attempts);
        value.insert(QStringLiteral("driver"), QJsonObject{{QStringLiteral("operation"), static_cast<int>(batch.trace.driverOperation)},
            {QStringLiteral("status"), statusHex(batch.trace.driverStatus)}, {QStringLiteral("transportStatus"), statusHex(batch.trace.driverTransportStatus)},
            {QStringLiteral("available"), batch.trace.driverAvailable}, {QStringLiteral("invoked"), batch.trace.driverInvoked}});
        value.insert(QStringLiteral("providerRelation"), QStringLiteral("R3 NtQuerySystemInformation and R0 ZwQuerySystemInformation use the same Memory Manager Superfetch ABI"));
        write(std::move(value));
    }
    void identities(const QueryBatch& queryBatch, std::uint64_t first, std::size_t count,
        const std::vector<Identity>& pages, const std::vector<std::uint64_t>* pfns = nullptr, bool ledger = false) {
        if (!active()) { return; }
        auto value = record(ledger ? "ledger_chunk" : "identities");
        const bool synthesized = !ledger && (queryBatch.status < 0 || pages.size() != count);
        value.insert(QStringLiteral("queryOrdinal"), QString::number(queryBatch.ordinal));
        value.insert(QStringLiteral("firstPfn"), hex(first));
        value.insert(QStringLiteral("pageCount"), QString::number(count));
        value.insert(QStringLiteral("requestCount"), QString::number(count));
        value.insert(QStringLiteral("startUs"), QString::number(queryBatch.startUs));
        value.insert(QStringLiteral("endUs"), QString::number(queryBatch.endUs));
        value.insert(QStringLiteral("status"), statusHex(queryBatch.status));
        if (ledger) {
            value.insert(QStringLiteral("chunkOrdinal"), QString::number(m_progress.chunks));
            value.insert(QStringLiteral("chunkComplete"), pages.size() == count);
            value.insert(QStringLiteral("classificationPhase"), QStringLiteral("Native identity; process lifetime witnesses are listed in final owner records"));
        } else {
            value.insert(QStringLiteral("role"), QStringLiteral("query_attempt"));
            value.insert(QStringLiteral("synthesized"), synthesized);
        }
        QJsonArray rows;
        for (std::size_t i = 0; i < count; ++i) {
            const Identity page = synthesized || i >= pages.size() ? Identity{} : pages[i];
            rows.append(QJsonArray{hex(pfns ? (*pfns)[i] : first + i), hex(page.frame), hex(page.backing)});
        }
        value.insert(QStringLiteral("identities"), rows);
        if (write(std::move(value))) {
            if (ledger) { m_progress.ledgerPages += count; ++m_progress.chunks; }
            else { m_progress.attemptPages += count; }
            sync();
        }
    }
    void owners(const char* phase, const QueryBatch& batch, const std::vector<KSWORD_ARK_PFN_OWNER>& owners) {
        if (!active()) { return; }
        for (std::size_t offset = 0; offset < owners.size() || offset == 0; offset += 512) {
            auto value = record("owners");
            value.insert(QStringLiteral("phase"), QString::fromLatin1(phase));
            value.insert(QStringLiteral("queryOrdinal"), QString::number(batch.ordinal));
            value.insert(QStringLiteral("queryStatus"), statusHex(batch.status));
            QJsonArray rows;
            const auto end = std::min(owners.size(), offset + 512);
            for (std::size_t i = offset; i < end; ++i) {
                const auto& owner = owners[i];
                rows.append(QJsonObject{{QStringLiteral("key"), hex(owner.processKey)}, {QStringLiteral("pid"), static_cast<qint64>(owner.processId)},
                    {QStringLiteral("sessionId"), static_cast<qint64>(owner.sessionId)},
                    {QStringLiteral("name"), QString::fromLatin1(owner.imageName, static_cast<qsizetype>(strnlen_s(owner.imageName, 16)))}});
            }
            value.insert(QStringLiteral("owners"), rows);
            write(std::move(value));
        }
    }
    void ranges(const char* phase, const QueryBatch& batch, const std::vector<KSWORD_ARK_PFN_RANGE>& ranges) {
        if (!active()) { return; }
        auto value = record("ranges");
        value.insert(QStringLiteral("phase"), QString::fromLatin1(phase));
        value.insert(QStringLiteral("queryOrdinal"), QString::number(batch.ordinal));
        value.insert(QStringLiteral("queryStatus"), statusHex(batch.status));
        QJsonArray rows;
        for (const auto& range : ranges) {
            rows.append(QJsonObject{{QStringLiteral("firstPfn"), hex(range.firstPfn)}, {QStringLiteral("pageCount"), QString::number(range.pageCount)}});
        }
        value.insert(QStringLiteral("ranges"), rows);
        write(std::move(value));
    }
    void finish() {
        if (!active()) { sync(); return; }
        QJsonArray ownerRows;
        auto emitOwners = [&] {
            auto value = record("owners");
            value.insert(QStringLiteral("phase"), QStringLiteral("final"));
            value.insert(QStringLiteral("owners"), ownerRows);
            write(std::move(value));
            ownerRows = {};
        };
        for (const auto& entry : m_scan.owners) {
            const auto& owner = entry.second;
            ownerRows.append(QJsonObject{{QStringLiteral("key"), hex(entry.first)}, {QStringLiteral("pid"), static_cast<qint64>(owner.pid)},
                {QStringLiteral("name"), owner.name}, {QStringLiteral("seenBefore"), owner.seenBefore}, {QStringLiteral("seenAfter"), owner.seenAfter},
                {QStringLiteral("leaseHeld"), owner.leaseHeld}, {QStringLiteral("lifetimeVerified"), owner.lifetimeVerified},
                {QStringLiteral("createTimeBefore"), QString::number(owner.createTimeBefore)},
                {QStringLiteral("createTimeAfter"), QString::number(owner.createTimeAfter)}});
            if (ownerRows.size() == 512) { emitOwners(); }
        }
        emitOwners();
        auto value = record("footer");
        value.insert(QStringLiteral("complete"), m_scan.complete);
        value.insert(QStringLiteral("cancelled"), m_scan.cancelled);
        value.insert(QStringLiteral("rangesChanged"), m_scan.rangesChanged);
        value.insert(QStringLiteral("reconciles"), m_scan.accounting.reconciles());
        value.insert(QStringLiteral("finished"), m_scan.finished);
        value.insert(QStringLiteral("expectedPages"), QString::number(m_scan.accounting.expected));
        value.insert(QStringLiteral("visitedPages"), QString::number(m_scan.accounting.visited));
        value.insert(QStringLiteral("unreadablePages"), QString::number(m_scan.accounting.unreadable));
        value.insert(QStringLiteral("unscannedPages"), QString::number(m_scan.accounting.notScanned()));
        value.insert(QStringLiteral("categories"), matrix(m_scan.accounting.byUseAndState));
        value.insert(QStringLiteral("unknownByNativeUse"), matrix(m_scan.accounting.unknownByNativeUse));
        value.insert(QStringLiteral("ownerCoverage"), QJsonObject{{QStringLiteral("resolved"), matrix(m_scan.ownerCoverage.resolved)},
            {QStringLiteral("unresolved"), matrix(m_scan.ownerCoverage.unresolved)}, {QStringLiteral("notApplicable"), matrix(m_scan.ownerCoverage.notApplicable)},
            {QStringLiteral("objectKeyKnown"), matrix(m_scan.ownerCoverage.objectKeyKnown)}});
        QJsonArray compressionKeys, resolvedKeys;
        for (const auto& group : m_scan.groups) {
            // No authoritative compression-store identity provider is available.
            if (group.use == Use::Private && group.ownerLifetimeVerified) { resolvedKeys.append(hex(group.key)); }
        }
        value.insert(QStringLiteral("compressionKeys"), compressionKeys);
        value.insert(QStringLiteral("ownerResolvedKeys"), resolvedKeys);
        value.insert(QStringLiteral("ledgerPages"), QString::number(m_progress.ledgerPages));
        value.insert(QStringLiteral("attemptPages"), QString::number(m_progress.attemptPages));
        value.insert(QStringLiteral("chunks"), QString::number(m_progress.chunks));
        value.insert(QStringLiteral("rawBytesBeforeFooter"), QString::number(m_progress.bytes));
        value.insert(QStringLiteral("groupedOverflowPages"), QString::number(m_scan.groupedOverflowPages));
        value.insert(QStringLiteral("batchTimingOverflow"), QString::number(m_scan.batchTimingOverflow));
        value.insert(QStringLiteral("nativeAbiObserved"), m_scan.nativeAbiObserved);
        value.insert(QStringLiteral("semanticsValidated"), m_scan.semanticsValidated);
        value.insert(QStringLiteral("statuses"), QJsonObject{{QStringLiteral("ranges"), statusHex(m_scan.rangesStatus)},
            {QStringLiteral("ownersBefore"), statusHex(m_scan.ownersStatus)}, {QStringLiteral("ownersAfter"), statusHex(m_scan.ownersRecheckStatus)},
            {QStringLiteral("lastPage"), statusHex(m_scan.lastPageStatus)}});
        value.insert(QStringLiteral("successfulNativeBatches"), QString::number(m_scan.nativeBatches));
        value.insert(QStringLiteral("successfulDriverBatches"), QString::number(m_scan.driverBatches));
        value.insert(QStringLiteral("recoveredPages"), QString::number(m_scan.recoveredPages));
        value.insert(QStringLiteral("recoveryQueries"), QString::number(m_scan.recoveryQueries));
        value.insert(QStringLiteral("ownerConflicts"), QString::number(m_scan.ownerConflicts));
        value.insert(QStringLiteral("hypervisorPresent"), m_scan.hypervisor);
        value.insert(QStringLiteral("secureKernelKnown"), m_scan.secureKnown);
        value.insert(QStringLiteral("secureKernelRunning"), m_scan.secureKernel);
        value.insert(QStringLiteral("ledgerRawComplete"), m_progress.headerWritten && m_progress.ledgerPages == m_scan.accounting.visited);
        value.insert(QStringLiteral("observer"), QJsonObject{{QStringLiteral("workingSetBefore"), QString::number(m_scan.observerWorkingSetBefore)},
            {QStringLiteral("workingSetAfter"), QString::number(m_scan.observerWorkingSetAfter)}, {QStringLiteral("workingSetMax"), QString::number(m_scan.observerWorkingSetMax)},
            {QStringLiteral("privateBefore"), QString::number(m_scan.observerPrivateBefore)}, {QStringLiteral("privateAfter"), QString::number(m_scan.observerPrivateAfter)},
            {QStringLiteral("privateMax"), QString::number(m_scan.observerPrivateMax)}, {QStringLiteral("known"), m_scan.observerMemoryKnown},
            {QStringLiteral("beforeKnown"), m_scan.observerMemoryBeforeKnown}, {QStringLiteral("afterKnown"), m_scan.observerMemoryAfterKnown},
            {QStringLiteral("samples"), QString::number(m_scan.observerMemorySamples)}});
        if (write(std::move(value))) {
            if (!m_file.flush()) { fail(m_file.errorString()); }
            else { m_progress.finalized = true; }
        }
        sync();
        m_file.close();
    }
private:
    void fail(const QString& error) { m_progress.failed = true; m_scan.rawEvidenceError = error.isEmpty() ? QStringLiteral("Raw evidence write failed") : error; sync(); }
    void sync() {
        m_scan.rawEvidenceFailed = m_progress.failed;
        m_scan.rawEvidenceFinalized = m_progress.finalized;
        m_scan.rawEvidenceBytes = m_progress.bytes;
        m_scan.rawEvidenceLedgerPages = m_progress.ledgerPages;
        m_scan.rawEvidenceAttemptPages = m_progress.attemptPages;
        m_scan.rawEvidenceChunks = m_progress.chunks;
        m_scan.rawBufferPeakBytes = m_progress.peakEncodedBytes;
        m_scan.rawEvidenceComplete = m_progress.finalized && !m_progress.failed && m_progress.headerWritten
            && m_scan.complete && m_progress.ledgerPages == m_scan.accounting.visited;
    }
    Scan& m_scan;
    QFile m_file;
    RawEvidenceProgress m_progress;
};

std::shared_ptr<Scan> collect(const std::shared_ptr<ScanJob>& job, std::shared_ptr<Scan>& retained)
{
    auto scan = std::make_shared<Scan>();
    retained = scan; // Keep denominator and progress even if a later allocation throws.
    const auto start = std::chrono::steady_clock::now();
    scan->started = utcNow();
    provenance(*scan);
    observerMemory(*scan, true);
    scan->rawEvidencePath = job->rawEvidencePath;
    scan->rawEvidenceRequested = !scan->rawEvidencePath.isEmpty();
    RawEvidence raw(*scan);
    memoryTotals(scan->totalBefore, scan->availableBefore);
    ULONGLONG installedKb = 0;
    if (GetPhysicallyInstalledSystemMemory(&installedKb)) { scan->installed = installedKb * 1024; }
    int cpu[4]{};
    __cpuid(cpu, 1);
    scan->hypervisor = (static_cast<unsigned>(cpu[2]) & (1U << 31)) != 0;
    using Query = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    // SYSTEM_ISOLATED_USER_MODE_INFORMATION starts with SecureKernelRunning.
    std::array<unsigned char, 16> isolated{};
    if (query && query(165, isolated.data(), static_cast<ULONG>(isolated.size()), nullptr) >= 0) {
        scan->secureKnown = true;
        scan->secureKernel = (isolated[0] & 1) != 0;
    }
    ark::PfnQueryClient client;
    std::uint64_t queryOrdinal = 0;
    bool rawHeaderWritten = false;
    auto observedQuery = [&](const char* operation, std::uint64_t first, std::uint32_t count, auto&& call) {
        QueryBatch batch;
        batch.ordinal = ++queryOrdinal;
        batch.operation = QString::fromLatin1(operation);
        batch.firstPfn = first;
        batch.pageCount = count;
        batch.started = utcNow();
        batch.startUs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        const auto nativeBefore = client.nativeBatches, driverBefore = client.driverBatches;
        batch.status = call();
        batch.trace = client.lastTrace();
        batch.nativeAccepted = static_cast<unsigned>(client.nativeBatches - nativeBefore);
        batch.driverAccepted = static_cast<unsigned>(client.driverBatches - driverBefore);
        scan->nativeBatches = client.nativeBatches;
        scan->driverBatches = client.driverBatches;
        batch.endUs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
        batch.finished = utcNow();
        batch.selectedPath = batch.status < 0 ? QStringLiteral("Unavailable")
            : (client.nativeBatches != nativeBefore ? QStringLiteral("R3 Native")
                : (client.driverBatches != driverBefore ? QStringLiteral("R0 fallback") : QStringLiteral("Unavailable")));
        if (batch.status >= 0 && (batch.operation == QStringLiteral("pages") || batch.operation == QStringLiteral("identities"))) {
            scan->nativeAbiObserved = true;
        }
        if (scan->batches.size() < 4096) { scan->batches.push_back(batch); }
        else { ++scan->batchTimingOverflow; }
        if (rawHeaderWritten) { raw.query(batch); }
        observerMemory(*scan);
        return batch;
    };
    std::vector<KSWORD_ARK_PFN_RANGE> ranges;
    const auto rangesBefore = observedQuery("ranges_before", 0, 0, [&] { return client.ranges(ranges); });
    scan->rangesStatus = rangesBefore.status;
    if (scan->rangesStatus >= 0) {
        for (const auto& range : ranges) { scan->ranges.push_back({range.firstPfn, range.pageCount}); }
        if (!normalizeRanges(scan->ranges) || scan->ranges.empty()) {
            scan->rangesStatus = static_cast<long>(0xC000003EUL);
            scan->ranges.clear();
        }
    }
    for (const auto& range : scan->ranges) { scan->accounting.expected += range.count; }
    job->total.store(scan->accounting.expected);
    raw.header();
    rawHeaderWritten = true;
    raw.query(rangesBefore);
    raw.ranges("before", rangesBefore, ranges);
    if (!scan->ranges.empty()) {
        std::vector<KSWORD_ARK_PFN_OWNER> owners;
        const auto ownersBefore = observedQuery("owners_before", 0, KSWORD_ARK_PFN_MAX_OWNERS, [&] { return client.owners(owners); });
        scan->ownersStatus = ownersBefore.status;
        raw.owners("before", ownersBefore, owners);
        std::set<std::uint64_t> conflictingKeys;
        auto mergeOwners = [&](const std::vector<KSWORD_ARK_PFN_OWNER>& sources, bool after) {
            for (const auto& owner : sources) {
                // EPROCESS low-48 is the native key, not a PID inferred from a
                // page table or an address. Null/redacted keys never own pages.
                const QString name = QString::fromLatin1(owner.imageName,
                    static_cast<qsizetype>(strnlen_s(owner.imageName, 16)));
                mergeOwnerSnapshot(scan->owners, conflictingKeys, owner.processKey,
                    Owner{owner.processId, name}, after, [](const Owner& a, const Owner& b) {
                        return a.pid == b.pid && a.name.compare(b.name, Qt::CaseInsensitive) == 0;
                    });
            }
        };
        if (ownersBefore.status >= 0) { mergeOwners(owners, false); }
        struct OwnerLease {
            HANDLE handle = nullptr;
            std::uint64_t created = 0;
            ~OwnerLease() { if (handle) { CloseHandle(handle); } }
        };
        std::map<std::uint32_t, OwnerLease> leases;
        const auto liveCreation = [](HANDLE handle, std::uint32_t pid) -> std::uint64_t {
            FILETIME created{}, exited{}, kernel{}, user{};
            if (!handle || GetProcessId(handle) != pid || WaitForSingleObject(handle, 0) != WAIT_TIMEOUT
                || !GetProcessTimes(handle, &created, &exited, &kernel, &user)) { return 0; }
            return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        };
        // Acquire before any PFN call and retain through the after source query.
        for (const auto& entry : scan->owners) {
            if (job->stopping()) { break; }
            const auto pid = entry.second.pid;
            if (!pid || leases.count(pid)) { continue; }
            auto& lease = leases[pid];
            lease.handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
            lease.created = liveCreation(lease.handle, pid);
        }
        // A group is a backing identity, never another physical accounting total.
        std::map<std::pair<Use, std::uint64_t>, std::size_t> groupIndex;
        std::vector<Identity> batch;
        unsigned consecutiveFailures = 0;
        bool terminalFailure = false;
        IdentityRetryPolicy sentinelRetry;
        OwnerCoverage::Matrix objectKeys{};
        for (const auto& range : scan->ranges) {
            for (std::uint64_t offset = 0; offset < range.count && !job->stopping(); ) {
                const auto count = static_cast<std::uint32_t>(std::min<std::uint64_t>(KSWORD_ARK_PFN_MAX_PAGES, range.count - offset));
                const auto first = range.first + offset;
                const auto chunkStartUs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                QueryBatch chunkQuery;
                const auto recovery = recoverRange(first, count, batch,
                    [&](std::uint64_t firstPfn, std::uint32_t amount, std::vector<Identity>& pages) {
                        std::vector<KSWORD_ARK_PFN_IDENTITY> records;
                        chunkQuery = observedQuery("pages", firstPfn, amount, [&] { return client.pages(firstPfn, amount, records); });
                        for (const auto& record : records) { pages.push_back({record.frame, record.backing}); }
                        raw.identities(chunkQuery, firstPfn, amount, pages);
                        return static_cast<std::int32_t>(chunkQuery.status);
                    }, [&] { return job->stopping(); });
                if (!recovery.queried) { break; }
                terminalFailure = recovery.terminal;
                scan->failedBatches += recovery.initialFailed ? 1 : 0;
                scan->recoveryQueries += recovery.queries;
                scan->recoveredPages += recovery.recoveredPages;
                // A successful query can still return unavailable identities.
                // Retry their exact PFNs once as an arbitrary-identity batch,
                // accepting only validated final identities for those slots.
                const auto retry = retryUnavailable(first, batch,
                    [&](const std::vector<std::uint64_t>& pfns, std::vector<Identity>& pages) {
                        std::vector<KSWORD_ARK_PFN_IDENTITY> records;
                        chunkQuery = observedQuery("identities", pfns.front(), static_cast<std::uint32_t>(pfns.size()), [&] { return client.identities(pfns, records); });
                        for (const auto& record : records) { pages.push_back({record.frame, record.backing}); }
                        raw.identities(chunkQuery, pfns.front(), pfns.size(), pages, &pfns);
                        return static_cast<std::int32_t>(chunkQuery.status);
                    }, [&] { return !sentinelRetry.enabled || recovery.terminal || job->stopping(); });
                sentinelRetry.record(retry);
                // Arbitrary-identity queries can be denied while ranged queries
                // still work. Stop only those retries and retain their failure
                // after later successful range queries so unreadables have a
                // diagnostic status rather than an apparent success code.
                scan->lastPageStatus = recovery.lastStatus < 0 ? recovery.lastStatus
                    : (sentinelRetry.lastFailure < 0 ? sentinelRetry.lastFailure : recovery.lastStatus);
                scan->recoveryQueries += retry.queries;
                scan->recoveredPages += retry.recoveredPages;
                bool anyValid = false;
                for (std::size_t i = 0; i < batch.size(); ++i) {
                    const auto& page = batch[i];
                    const auto pfn = first + i;
                    // Native Private remains Private; a short name cannot prove compression.
                    const Use use = classify(page);
                    scan->accounting.add(page, use);
                    if (page.frame == ~0ULL) { continue; }
                    if ((use == Use::MappedFile || use == Use::Image || use == Use::Metafile) && (page.backing & ~3ULL)) {
                        ++objectKeys[static_cast<std::size_t>(use)][state(page)];
                    }
                    anyValid = true;
                    auto& examples = scan->examples[static_cast<std::size_t>(use)];
                    if (!available(state(page)) && examples.size() < 256) { examples.emplace_back(pfn, page); }
                    if (available(state(page)) || state(page) == 5) { continue; }
                    const bool process = nativeUse(page) == 0;
                    const bool file = nativeUse(page) == 1 || nativeUse(page) == 8;
                    const auto key = process ? processKey(page) : (file ? page.backing & ~3ULL : 0ULL);
                    const auto indexKey = std::make_pair(use, key);
                    auto entry = groupIndex.find(indexKey);
                    if (entry == groupIndex.end()) {
                        if (scan->groups.size() >= 65536) { ++scan->groupedOverflowPages; continue; }
                        Group group;
                        group.use = use;
                        group.key = key;
                        group.firstPfn = pfn;
                        group.firstIdentity = page;
                        entry = groupIndex.emplace(indexKey, scan->groups.size()).first;
                        scan->groups.push_back(std::move(group));
                    }
                    auto& group = scan->groups[entry->second];
                    ++group.pages;
                    ++group.pagesByState[state(page)];
                    group.activePages += state(page) == 6 ? 1 : 0;
                }
                offset += count;
                job->visited.store(scan->accounting.visited);
                chunkQuery.startUs = chunkStartUs;
                chunkQuery.endUs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count());
                raw.identities(chunkQuery, first, count, batch, nullptr, true);
                // Redacted sentinel identities in an otherwise successful
                // batch do not prove that later RAM extents are unavailable.
                consecutiveFailures = recovery.initialFailed && !anyValid ? consecutiveFailures + 1 : 0;
                if (terminalFailure || consecutiveFailures >= 3) { break; }
            }
            if (job->stopping() || terminalFailure || consecutiveFailures >= 3) { break; }
        }
        std::vector<KSWORD_ARK_PFN_OWNER> afterOwners;
        const auto ownersAfter = observedQuery("owners_after", 0, KSWORD_ARK_PFN_MAX_OWNERS, [&] { return client.owners(afterOwners); });
        scan->ownersRecheckStatus = ownersAfter.status;
        raw.owners("after", ownersAfter, afterOwners);
        scan->ownersRechecked = scan->ownersRecheckStatus >= 0;
        if (scan->ownersRechecked) { mergeOwners(afterOwners, true); }
        scan->ownerConflicts = conflictingKeys.size();
        for (auto& entry : scan->owners) {
            auto& owner = entry.second;
            const auto lease = leases.find(owner.pid);
            if (lease == leases.end()) { continue; }
            owner.leaseHeld = lease->second.handle != nullptr;
            owner.createTimeBefore = lease->second.created;
            owner.createTimeAfter = liveCreation(lease->second.handle, owner.pid);
            owner.lifetimeVerified = owner.pid && !owner.name.isEmpty() && ownerLifetimeVerified(
                owner.seenBefore, owner.seenAfter, owner.leaseHeld, owner.createTimeBefore, owner.createTimeAfter);
        }
        for (auto& group : scan->groups) {
            if (group.use != Use::Private) { continue; }
            const auto ownerIt = scan->owners.find(group.key);
            if (!group.key || ownerIt == scan->owners.end()) { continue; }
            const auto& owner = ownerIt->second;
            group.pid = owner.pid;
            group.name = owner.name;
            group.ownerSeenBefore = owner.seenBefore;
            group.ownerSeenAfter = owner.seenAfter;
            group.ownerLifetimeVerified = owner.lifetimeVerified;
            group.ownerCreateTime = owner.createTimeBefore;
            if (owner.lifetimeVerified) { scan->resolvedPrivatePages += group.pages; }
        }
        scan->unresolvedPrivatePages = scan->accounting.inUse(Use::Private)
            + scan->accounting.inUse(Use::Compression) - scan->resolvedPrivatePages;
        scan->ownerCoverage.initialize(scan->accounting);
        scan->ownerCoverage.objectKeyKnown = objectKeys;
        for (const auto& group : scan->groups) {
            if (group.use == Use::Private && group.ownerLifetimeVerified) {
                scan->ownerCoverage.resolve(group.use, group.pagesByState);
            }
        }
        // A hot-add/remove changes the denominator; don't label it a complete snapshot.
        std::vector<KSWORD_ARK_PFN_RANGE> afterRanges;
        const auto rangesAfter = observedQuery("ranges_after", 0, 0, [&] { return client.ranges(afterRanges); });
        raw.ranges("after", rangesAfter, afterRanges);
        if (rangesAfter.status >= 0) {
            std::vector<Range> normalized;
            for (const auto& range : afterRanges) { normalized.push_back({range.firstPfn, range.pageCount}); }
            scan->rangesChanged = !normalizeRanges(normalized) || normalized.size() != scan->ranges.size();
            for (std::size_t i = 0; !scan->rangesChanged && i < normalized.size(); ++i) {
                scan->rangesChanged = normalized[i].first != scan->ranges[i].first || normalized[i].count != scan->ranges[i].count;
            }
        } else { scan->rangesChanged = true; }
    }
    scan->cancelled = job->stopping();
    scan->complete = scan->accounting.expected != 0 && !scan->cancelled && !scan->rangesChanged
        && scan->accounting.visited == scan->accounting.expected && scan->accounting.unreadable == 0;
    scan->nativeBatches = client.nativeBatches;
    scan->driverBatches = client.driverBatches;
    memoryTotals(scan->totalAfter, scan->availableAfter);
    scan->finished = utcNow();
    scan->elapsedMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
    observerMemory(*scan, false, true);
    scan->auditSample = {scan->domain.toStdString(), scan->epoch.toStdString(), scan->nativeArchitecture.toStdString(),
        scan->windowsMajor, scan->windowsMinor, scan->windowsBuild, scan->accounting.inUse(Use::Unknown),
        scan->accounting.unreadable, scan->accounting.notScanned(), scan->complete, scan->accounting.reconciles(), scan->semanticsValidated};
    raw.finish();
    std::sort(scan->groups.begin(), scan->groups.end(), [](const Group& a, const Group& b) { return a.pages > b.pages; });
    return scan;
}
}

void collectPhysicalPages(const std::shared_ptr<ScanJob>& job)
{
    std::shared_ptr<Scan> result;
    try { result = collect(job, result); }
    catch (...) {
        // No detached worker may terminate the GUI process on resource exhaustion.
        try {
            if (!result) { result = std::make_shared<Scan>(); }
            result->resourceFailure = true;
            result->complete = false;
            result->auditSample.complete = false;
            if (!result->accounting.expected) { result->accounting.expected = job->total.load(); }
            if (!result->ownerCoverage.reconciles(result->accounting)) {
                result->ownerCoverage.initialize(result->accounting);
                result->resolvedPrivatePages = 0;
                result->unresolvedPrivatePages = result->accounting.inUse(Use::Private) + result->accounting.inUse(Use::Compression);
            }
            result->auditSample.unknownInUsePages = result->accounting.inUse(Use::Unknown);
            result->auditSample.unreadablePages = result->accounting.unreadable;
            result->auditSample.unscannedPages = result->accounting.notScanned();
            result->lastPageStatus = static_cast<long>(0xC000009AUL);
            result->rawEvidenceFinalized = false;
            result->rawEvidenceComplete = false;
            result->rawEvidencePath = job->rawEvidencePath;
            result->rawEvidenceRequested = !job->rawEvidencePath.isEmpty();
            result->rawEvidenceFailed = result->rawEvidenceRequested;
            if (result->rawEvidenceRequested) { result->rawEvidenceError = QStringLiteral("Resource failure; raw evidence has no completed footer"); }
        }
        catch (...) { /* A null result is also an explicit failure at the UI boundary. */ }
    }
    {
        std::lock_guard<std::mutex> lock(job->mutex);
        job->result = std::move(result);
    }
    job->done.store(true);
}
}
