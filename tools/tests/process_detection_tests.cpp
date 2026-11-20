#include <WinSock2.h>
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessDetectionForensics.h"
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessResearchCatalog.h"
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessDetectionProfile.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"
#include "../../Ksword5.1/Ksword5.1/ksword/process/process.h"
#include "../../Ksword5.1/Ksword5.1/ksword/process/injection_trace_collector.h"
#include "../../Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageScan.h"
#include "../../Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageMappings.h"
#include <QCoreApplication>
#include <QRegularExpression>
#include <QDir>
#include <QFileInfo>
#include <QFile>
#include <QScopeGuard>
#include <QtEndian>
#include <algorithm>
#include <iostream>
#include <stdexcept>

namespace
{
    unsigned checks = 0;
    unsigned driverQueries = 0;
    bool exercisingUnavailableProviders = false;
    bool emptyHvmRing = false;
    unsigned long processFlags = 0;
    unsigned long threadFlags = 0;
    void check(bool condition, const char* reason)
    {
        ++checks;
        if (!condition) throw std::runtime_error(reason);
    }
    template<class T> T unavailable()
    {
        ++driverQueries;
        T response{};
        response.io.deviceOpenFailed = true;
        response.io.win32Error = ERROR_FILE_NOT_FOUND;
        response.io.message = "Device unavailable (test transport)";
        return response;
    }
}

// Keep driver availability deterministic without loading or changing a host driver.
namespace ksword::detection
{
    QString PrepareDetectionLayout(const ResearchSet&, const QString&) { return {}; }
}

namespace ksword::ark
{
    CallbackEnumResult DriverClient::enumerateCallbacks(unsigned long) const { return unavailable<CallbackEnumResult>(); }
    SsdtEnumResult DriverClient::enumerateSsdt(unsigned long) const { return unavailable<SsdtEnumResult>(); }
    KernelInlineHookScanResult DriverClient::scanInlineHooks(unsigned long, unsigned long, const std::wstring&) const
    { return unavailable<KernelInlineHookScanResult>(); }
    ProcessCrossViewResult DriverClient::queryProcessCrossView(unsigned long flags, std::uint32_t,
        std::uint32_t, unsigned long, DriverHandle*) const
    { processFlags = flags; return unavailable<ProcessCrossViewResult>(); }
    ThreadCrossViewResult DriverClient::queryThreadCrossView(unsigned long flags, std::uint32_t,
        std::uint32_t, std::uint32_t, unsigned long) const
    { threadFlags = flags; return unavailable<ThreadCrossViewResult>(); }
    CallbackMonitorStatusResult DriverClient::queryCallbackMonitorStatus() const { return unavailable<CallbackMonitorStatusResult>(); }
    CallbackMonitorReadResult DriverClient::readCallbackMonitor(std::uint64_t, unsigned long) const { return unavailable<CallbackMonitorReadResult>(); }
    HvmEventResult DriverClient::queryHvmEvents(std::uint64_t, unsigned long, bool) const
    {
        if (!emptyHvmRing) return unavailable<HvmEventResult>();
        HvmEventResult result{};
        result.io.ok = true;
        return result;
    }
    HvmProcessResult DriverClient::resolveHvmDirectoryBase(std::uint64_t) const { return unavailable<HvmProcessResult>(); }
    DriverIntegrityResult DriverClient::queryKernelCpuIntegrity(unsigned long, unsigned long, unsigned long) const { return unavailable<DriverIntegrityResult>(); }
    DriverIntegrityResult DriverClient::queryDriverIntegrity(const std::wstring&, std::uint64_t,
        unsigned long, unsigned long, unsigned long) const { return unavailable<DriverIntegrityResult>(); }
    KernelMemoryEvidenceResult DriverClient::queryKernelMemoryEvidence(unsigned long, unsigned long,
        std::uint64_t, std::uint64_t, std::uint64_t, unsigned long, unsigned long) const { return unavailable<KernelMemoryEvidenceResult>(); }
    WorkQueueEnumResult DriverClient::enumerateWorkQueues(unsigned long, unsigned long) const { return unavailable<WorkQueueEnumResult>(); }
    KernelTimerDpcEnumResult DriverClient::enumerateKernelTimerDpc(unsigned long, unsigned long) const { return unavailable<KernelTimerDpcEnumResult>(); }
    DriverObjectModuleSnapshot DriverClient::captureDriverObjectModules() const { return {}; }
    ProcessEnumResult DriverClient::enumerateProcesses(unsigned long) const { return unavailable<ProcessEnumResult>(); }
    HandleEnumResult DriverClient::enumerateProcessHandles(std::uint32_t, unsigned long) const { return unavailable<HandleEnumResult>(); }
    HandleObjectQueryResult DriverClient::queryHandleObject(std::uint32_t, std::uint64_t, unsigned long, unsigned long) const
    { return unavailable<HandleObjectQueryResult>(); }
}

// These methods are excluded from this fixture's selected masks. A call means that
// a disabled provider actually ran and must make the test fail.
namespace ksword::pfn
{
    void collectPhysicalPages(const std::shared_ptr<ScanJob>& job)
    {
        if (!exercisingUnavailableProviders) throw std::runtime_error("disabled live PFN provider executed");
        job->result = std::make_shared<Scan>();
        job->result->rangesStatus = static_cast<LONG>(0xc00000bb);
    }
    void collectPhysicalMappings(const std::shared_ptr<MappingJob>&, unsigned)
    {
        if (!exercisingUnavailableProviders) throw std::runtime_error("disabled mappings provider executed");
    }
}
namespace ks::process
{
    std::string GetProcessNameByPID(std::uint32_t) { throw std::runtime_error("unused network process name lookup"); }
    std::string QueryProcessPathByPid(std::uint32_t) { throw std::runtime_error("file occupancy search executed"); }
    std::vector<ProcessRecord> EnumerateProcesses(ProcessEnumStrategy, ProcessEnumStrategy*, std::uint32_t)
    {
        if (!exercisingUnavailableProviders) throw std::runtime_error("disabled per-process memory survey executed");
        return {};
    }
    InjectionTraceResult ScanProcessInjectionTrace(std::uint32_t, std::uint64_t, const QString&, const InjectionTraceOptions&)
    { throw std::runtime_error("disabled per-process memory survey executed"); }
}

int main(int argc, char** argv)
{
    using namespace ksword::detection;
    QCoreApplication app(argc, argv);
    // Child fixture exercises the real argument list, CSV parser and subprocess
    // diagnostics without requiring a Volatility installation or a memory dump.
    const auto args = app.arguments();
    if (args.value(1) == QStringLiteral("--vmrs-crosscheck"))
    {
        if (args.size() != 5) return 2;
        ScanInputs input;
        input.hypervSavedState = args[2];
        input.memProcFsLibrary = args[3];
        input.guestProcessFile = args[4];
        input.memProcFsRoot = QStringLiteral("unrelated-generic-mount");
        DetectionSelection selection;
        selection.research.set(44-1); selection.research.set(49-1);
        const auto result = RunSelected(selection, {}, input);
        bool system = false, staticView = false, comparison = false;
        for (const auto& row : result.evidence)
            if (row.researchPoints.test(44-1) && row.pid == 4 && row.image == QStringLiteral("System"))
                system |= row.historical && row.scope.contains(QStringLiteral("Hyper-V HvSavedState"));
        for (const auto& r : result.reports)
        {
            std::cout << "id=" << r.researchId << " status=" << int(r.status) << " rows=" << r.count
                << " ms=" << r.elapsedMs << " " << r.detail.toStdString() << '\n';
            if (r.researchId == 44) staticView = (r.status == Status::Complete || r.status == Status::Partial) &&
                r.count > 0 && r.detail.contains(QStringLiteral("Read-only, Static"));
            if (r.researchId == 49) comparison = r.status == Status::Partial &&
                QRegularExpression(QStringLiteral("candidate_matches=[1-9][0-9]*")).match(r.detail).hasMatch();
        }
        return system && staticView && comparison ? 0 : 1;
    }
    const bool orphanTrace = args.value(1) == QStringLiteral("--etl-orphan-check");
    if (orphanTrace || args.value(1) == QStringLiteral("--etl-check"))
    {
        if (args.size() != 5) return 2;
        const auto markerPid = args[3].toUInt(), markerTid = args[4].toUInt();
        if (!markerPid || !markerTid) return 2;
        ScanInputs input;
        input.eventTraceFile = args[2];
        bool valid = true;
        for (int id : {17, 36, 37})
        {
            if (orphanTrace && id == 36) continue;
            DetectionSelection selection;
            selection.research.set(id - 1);
            const auto result = RunSelected(selection, {}, input);
            if (result.reports.size() != 1) return 1;
            const auto& receipt = result.reports.front();
            unsigned starts = 0, ends = 0, switches = 0, ready = 0, unknown = 0, unownedMarker = 0;
            for (const auto& row : result.evidence) {
                if (!row.researchPoints.test(id - 1) || !row.historical || row.scope != input.eventTraceFile)
                    valid = false;
                const bool switchEvent = row.detail.startsWith(QStringLiteral("CSwitch |"));
                const bool readyEvent = row.detail.startsWith(QStringLiteral("ReadyThread |"));
                if (id == 17 && !switchEvent) valid = false;
                if ((switchEvent || readyEvent) && !row.pid) ++unknown;
                const bool markerThread = row.detail.contains(QStringLiteral(" | TID=%1 |").arg(markerTid));
                if (orphanTrace && (switchEvent || readyEvent)) {
                    if (row.pid != 0) valid = false;
                    if (markerThread && !row.pid) ++unownedMarker;
                }
                if (row.pid != markerPid || (id != 36 && !markerThread)) continue;
                if (switchEvent) ++switches;
                else if (readyEvent) ++ready;
                else if (row.detail.contains(QStringLiteral(" | opcode=1 |"))) ++starts;
                else if (row.detail.contains(QStringLiteral(" | opcode=2 |"))) ++ends;
            }
            std::cout << "ID=" << id << " rows=" << receipt.count << " status=" << int(receipt.status)
                << " marker_start=" << starts << " marker_end=" << ends << " marker_switch=" << switches
                << " marker_ready=" << ready << " unknown_schedule_pid=" << unknown << " unowned_marker=" << unownedMarker
                << " " << receipt.detail.toStdString() << '\n';
            valid &= receipt.status == Status::Complete || receipt.status == Status::Partial;
            valid &= orphanTrace ? unownedMarker > 0 : id == 17 ? switches > 0 : id == 36 ? starts && ends : starts && ends && switches && ready;
        }
        return valid ? 0 : 1;
    }
    if (args.value(1) == QStringLiteral("--image-check"))
    {
        if (args.size() != 5) return 2;
        DetectionSelection selected;
        for (const auto& field : args[4].split(QLatin1Char(',')))
        {
            bool ok = false;
            const int id = field.toInt(&ok);
            if (!ok || id < 1 || id > ResearchCount) return 2;
            selected.research.set(id-1);
        }
        ScanInputs inputs;
        inputs.memoryImage = args[2];
        inputs.volatilityProgram = args[3];
        // Some numbered checks pair an image view with a live view. In this
        // fixture the live transport is deliberately unavailable.
        exercisingUnavailableProviders = true;
        ScanResult result;
        try { result = RunSelected(selected, {}, inputs); }
        catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
        bool allRead = true;
        for (const auto& report : result.reports)
        {
            std::cout << "id=" << report.researchId << " status=" << static_cast<int>(report.status)
                << " count=" << report.count << " elapsed_ms=" << report.elapsedMs << '\n';
            if (report.status == Status::Failed || report.status == Status::Unavailable)
                std::cerr << report.detail.toUtf8().constData() << '\n';
            allRead &= (report.status == Status::Complete || report.status == Status::Partial);
        }
        return allRead && size_t(result.reports.size()) == selected.research.count() ? 0 : 1;
    }
    if (args.value(1) == QStringLiteral("--exit-fixture")) return 0;
    if (args.value(1) == QStringLiteral("--offline"))
    {
        const int renderer = args.indexOf(QStringLiteral("-r"));
        if ((renderer != 3 && renderer != 5) || args[2] != QStringLiteral("-q") ||
            args.value(renderer + 1) != QStringLiteral("csv") || args.value(renderer + 2) != QStringLiteral("-f")
            || !QFileInfo(args.value(renderer + 3)).isFile()) return 2;
        if (args.value(renderer+4) == QStringLiteral("kswordobjects.KswordObjects"))
        {
            std::cout << "TreeDepth,Status,PID,Name,Address,Detail\n0,,99,test,0xffff800000000001,observed\n";
            if (args.last() == QStringLiteral("3")) std::cout << "0,partial,,,,sparse capture\n";
            return 0;
        }
        if (args.value(renderer+4) == QStringLiteral("windows.pslist.PsList"))
        {
            std::cout << "TreeDepth,PID,ImageFileName,Note,Offset\n0,77,\"image,name\",\"line one\nline two\",18446744073709486081\n";
            return 0;
        }
        if (args.value(renderer+4) == QStringLiteral("windows.malware.psxview.PsXView"))
        {
            std::cout << "TreeDepth,PID,Name,csrss,pslist\n0,77,one,True,False\n0,78,two,False,True\n";
            return 0;
        }
        std::cerr << "fixture plugin unavailable\n";
        return 3;
    }
    try
    {
        check(args.size() <= 2, "optional argument is the tracked MemProcFS fixture root");
        const auto blank = Run(0);
        check(blank.reports.isEmpty() && blank.evidence.isEmpty(), "empty selection must leave no evidence");
        MethodMask all = 0;
        for (const auto& method : Methods())
        {
            check(method.bit && !(method.bit & (method.bit - 1)) && !(method.bit & all), "method bits must be unique");
            all |= method.bit;
            if (Defaults(false) & method.bit) check(method.cost == Cost::Fast, "list defaults must be quick");
        }
        check(Defaults(false) && (Defaults(true) & ~Defaults(false)), "independent defaults");
        check(!((Defaults(false) | Defaults(true)) & ~all), "defaults contain unknown bits");
        const auto listPreset = DetectionDefaults(false);
        const auto deepPreset = DetectionDefaults(true);
        check(listPreset.research.any() && deepPreset.research != listPreset.research, "numbered presets differ");
        DetectionSelection every;
        every.research.set();
        const auto canceled = RunSelected(every, [] { return true; });
        check(canceled.cancelled && canceled.reports.size() == ResearchCount, "a receipt for all 66 research points");
        for (int i = 0; i < ResearchCount; ++i)
        {
            const auto& point = ResearchCatalog().at(i);
            check(point.id == i+1 && !point.name.isEmpty(), "number and name must match the original index");
            check(!listPreset.research.test(i) || point.cost == Cost::Fast, "list preset cost");
            check(canceled.reports[i].researchId == point.id && canceled.reports[i].status == Status::Cancelled, "no alias above bit 63");
        }
        check(RunSelected({}).reports.isEmpty() && !driverQueries, "empty or cancelled selection cannot run providers");
        emptyHvmRing = true;
        DetectionSelection cr3;
        cr3.research.set(22-1);
        const auto noSample = RunSelected(cr3);
        check(noSample.reports.size() == 1 && noSample.reports[0].status == Status::Unavailable &&
            noSample.evidence.isEmpty(), "a readable but empty event ring has no processor CR3 sample");
        emptyHvmRing = false;
        {
            exercisingUnavailableProviders = true;
            const auto matrix = RunSelected(every);
            check(matrix.reports.size() == ResearchCount, "every selected research point must execute or report its missing input");
            for (int i = 0; i < ResearchCount; ++i)
            {
                const auto& receipt = matrix.reports[i];
                check(receipt.researchId == i+1 && receipt.status != Status::Cancelled &&
                    receipt.detail != QStringLiteral("No collector registered"), "unrouted research point");
            }
            check(std::all_of(matrix.evidence.begin(), matrix.evidence.end(), [](const Evidence& row) {
                return row.researchPoints.any();
            }), "a finding must retain its numbered source");
            for (int i = 0; i < ResearchCount; ++i)
            {
                DetectionSelection only;
                only.research.set(i);
                const auto sample = RunSelected(only);
                check(sample.reports.size() == 1 && sample.reports.front().researchId == i+1, "single selection ran the wrong method");
                check(std::all_of(sample.evidence.begin(), sample.evidence.end(), [&](const Evidence& e) {
                    return e.researchPoints == only.research;
                }), "single selection returned evidence attributed to another research point");
            }
            exercisingUnavailableProviders = false;
            driverQueries = 0;
        }
        DetectionSelection callbackSelection;
        for (const int id : {31,32,33,34,35,42}) callbackSelection.research.set(id-1);
        const auto callbacks = RunSelected(callbackSelection);
        check(callbacks.reports.size() == 6 && driverQueries == 1, "six receipts from a single callback query");
        for (const auto& receipt : callbacks.reports)
            check(receipt.status == Status::Unavailable, "missing callback monitor");
        driverQueries = 0;
        const auto live = Run(ProcessBaseline | ThreadOwners);
        check(live.reports.size() == 2 && live.startedUtc.isValid(), "live snapshot identity");
        for (const auto& report : live.reports)
            check(report.status == Status::Complete && report.elapsedMs >= 0 && report.count, "real Toolhelp snapshot");
        FILETIME created{}, exited{}, kernel{}, user{};
        check(GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user) != FALSE, "query actual process creation time");
        const quint64 selfCreation = (quint64(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        for (const auto bit : {ProcessBaseline, ThreadOwners})
            check(std::any_of(live.evidence.cbegin(), live.evidence.cend(), [&](const auto& row) {
                return row.methods == bit && row.pid == GetCurrentProcessId() && !row.absentFromBaseline
                    && row.creationTime100ns == selfCreation && !row.historical && !row.lifetimeUnknown;
            }), "both fast views must carry the actual live self identity");
        check(!driverQueries, "driver queried despite disabled mask");
        const HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, GetCurrentProcessId());
        check(self != nullptr, "open a live process object");
        const auto closeSelf = qScopeGuard([self] { CloseHandle(self); });
        const auto executable = QDir::toNativeSeparators(app.applicationFilePath()).toStdWString();
        auto command = L"\"" + executable + L"\" --exit-fixture";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION child{};
        check(CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &startup, &child), "launch controlled short-lived process");
        const auto closeChild = qScopeGuard([&] { CloseHandle(child.hThread); CloseHandle(child.hProcess); });
        check(WaitForSingleObject(child.hProcess, 10000) == WAIT_OBJECT_0, "wait for child object to be signaled");
        const auto supplemental = Run(DesktopWindows | NetworkEndpoints | CsrssHandles | ProcessHandles);
        check(supplemental.reports.size() == 4 && !driverQueries, "supplemental R3 selection");
        const auto printReports = [](const ScanResult& result) {
            for (const auto& report : result.reports)
                std::cout << "live method_bit=" << report.method << " status=" << static_cast<int>(report.status)
                    << " elapsed_ms=" << report.elapsedMs << " count=" << report.count
                    << " detail=" << report.detail.toStdString() << '\n';
        };
        printReports(live);
        printReports(supplemental);
        const auto handleObserved = [&](quint32 pid, bool historical) {
            return std::any_of(supplemental.evidence.cbegin(), supplemental.evidence.cend(), [&](const auto& row) {
                return row.methods == ProcessHandles && row.pid == pid && row.creationTime100ns &&
                    row.historical == historical && !row.lifetimeUnknown && !row.absentFromBaseline;
            });
        };
        check(handleObserved(GetCurrentProcessId(), false), "held self handle must produce live evidence");
        check(handleObserved(child.dwProcessId, true), "retained exited process object must produce historical evidence");
        const auto off = Run(CidProcesses | CidThreads);
        check(off.reports.size() == 2 && driverQueries == 2, "only selected driver sources queried");
        check(processFlags == KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE, "wrong process request mask");
        check(threadFlags == (KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE | KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START), "wrong thread request mask");
        for (const auto& report : off.reports)
            check(report.status == Status::Unavailable && !report.count, "missing driver is not a successful empty scan");
        ScanResult comparison;
        auto& response = comparison.processCrossView.emplace();
        response.io.ok = true;
        response.status = KSWORD_ARK_CROSSVIEW_STATUS_OK;
        response.totalCount = response.returnedCount = 1;
        ksword::ark::ProcessCrossViewEntry native{};
        native.sourceMask = KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE;
        native.anomalyFlags = KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST | KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
        comparison.selected = ProcessCrossView | CidProcesses;
        check(!(ComparableAnomalies(comparison, native) & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST),
            "unselected active list must not count as negative evidence");
        comparison.selected = ActiveProcesses | CidProcesses;
        check(ComparableAnomalies(comparison, native) == native.anomalyFlags, "complete CID and active-list comparison");
        response.totalCount++;
        check(!ComparableAnomalies(comparison, native), "truncated views cannot support absence evidence");
        const auto cancelled = Run(all, [] { return true; });
        check(cancelled.cancelled && cancelled.evidence.isEmpty() && driverQueries == 2, "cancelled providers ran");
        for (const auto& report : cancelled.reports) check(report.status == Status::Cancelled, "cancellation receipt");
        const auto noInputs = Run(MountedDtb | MountedPfn | VolatilityMethods().front().bit);
        for (const auto& report : noInputs.reports) check(report.status == Status::Unavailable, "missing offline input");
        check(noInputs.reports.size() == 3 && noInputs.evidence.isEmpty(), "missing input receipts");
        ScanInputs inputs;
        inputs.memProcFsRoot = args.size() == 2 ? QDir(args[1]).absolutePath() :
            QDir::cleanPath(app.applicationDirPath() + QStringLiteral("/../../fixtures/process_detection"));
        inputs.eventTraceFile = QDir(inputs.memProcFsRoot).absoluteFilePath(QStringLiteral("absent.etl"));
        const auto noTrace = Run(EtlProcesses | EtlThreads, {}, inputs);
        check(noTrace.reports.size() == 2 && noTrace.evidence.isEmpty(), "missing ETL should return two receipts");
        for (const auto& receipt : noTrace.reports)
            check(receipt.status == Status::Unavailable && !receipt.count, "missing ETL is unavailable");
        const auto eventHistory = Run(SecurityHistory | SysmonHistory);
        check(eventHistory.reports.size() == 2, "Security and Sysmon queries must each return a receipt");
        quint64 historyCount = 0;
        for (const auto& receipt : eventHistory.reports)
        {
            check(receipt.status != Status::Cancelled && receipt.elapsedMs >= 0 && receipt.count <= 512, "event query bounds");
            historyCount += receipt.count;
            std::cout << "history method_bit=" << receipt.method << " status=" << static_cast<int>(receipt.status)
                << " count=" << receipt.count << '\n';
        }
        check(historyCount == static_cast<quint64>(eventHistory.evidence.size()) &&
            std::all_of(eventHistory.evidence.cbegin(), eventHistory.evidence.cend(), [](const auto& row) {
                return row.historical && !row.scope.isEmpty() && !row.absentFromBaseline;
            }), "history must be scoped to its channel and excluded from live absence checks");
        const auto memory = Run(MountedDtb | MountedPfn, {}, inputs);
        check(memory.reports.size() == 2 && memory.evidence.size() == 3, "mount evidence counts");
        check(memory.reports[0].status == Status::Partial && memory.reports[0].count == 2,
            "malformed page root must be rejected");
        check(memory.reports[1].status == Status::Complete && memory.reports[1].count == 1, "PFN owner grouping");
        bool hasOwner = false, hasOrphan = false, hasPfn = false;
        for (const auto& row : memory.evidence)
        {
            check(!row.scope.isEmpty() && !row.absentFromBaseline && !row.creationTime100ns, "offline scope crossed live process identity");
            if (row.methods == MountedDtb && row.pid == 4 && row.objectAddress) hasOwner = true;
            if (row.methods == MountedDtb && !row.pid && !row.objectAddress) hasOrphan = true;
            if (row.methods == MountedPfn && row.pid == 4 && row.detail.contains(QStringLiteral("ProcPriv=2"))) hasPfn = true;
        }
        check(hasOwner && hasOrphan && hasPfn, "known root, unassigned root, PFN owner");
        inputs.flatPhysicalImage = QDir(app.applicationDirPath()).absoluteFilePath(QStringLiteral("process_detection_fixture.raw"));
        QFile image(inputs.flatPhysicalImage);
        check(image.open(QIODevice::NewOnly | QIODevice::WriteOnly), "test image path already occupied");
        const auto cleanImage = qScopeGuard([&] { image.close(); image.remove(); });
        QByteArray bytes(6 * 4096, '\0');
        const auto setEntry = [&](int offset, quint64 value) { qToLittleEndian(value, bytes.data() + offset); };
        setEntry(0x1000 + 510 * 8, 0x1003);
        setEntry(0x1000, 0x2007);
        setEntry(0x2000, 0x3007);
        setEntry(0x3000, 0x4007);
        setEntry(0x4000, 0x5007);
        const auto writeImage = [&] {
            check(image.write(bytes) == bytes.size() && image.flush(), "test image write failed");
            image.close();
        };
        writeImage();
        const auto roots = Run(RawPageRoots, {}, inputs);
        DetectionSelection sharedRoots;
        sharedRoots.research.set(18);
        sharedRoots.research.set(19);
        auto flatInputs = inputs;
        flatInputs.memProcFsRoot.clear();
        const auto shared = RunSelected(sharedRoots, {}, flatInputs);
        check(shared.evidence.size() == 1 && shared.reports.size() == 2 &&
            shared.evidence.front().researchPoints == sharedRoots.research, "shared scan records both independent selection IDs");
        check(roots.reports.size() == 1 && roots.reports.front().status == Status::Complete &&
            roots.evidence.size() == 1 && roots.evidence.front().detail.contains(QStringLiteral("PML4=0x1000"))
            && roots.evidence.front().scope == inputs.flatPhysicalImage, "known flat page root");
        inputs.volatilityProgram = app.applicationFilePath();
        inputs.memoryImage = inputs.flatPhysicalImage;
        DetectionSelection csrssImage;
        csrssImage.research.set(10-1);
        const auto csrssView = RunSelected(csrssImage, {}, inputs);
        check(csrssView.reports.size() == 1 && csrssView.reports[0].count == 1 &&
            csrssView.evidence.size() == 1 && csrssView.evidence[0].pid == 77 &&
            csrssView.evidence[0].scope == inputs.memoryImage, "independent CSRSS selection must exclude unsupported image rows");
        MethodReport special;
        ScanResult specialResult;
        RunVolatilityPlugin(specialResult, special, inputs, [] { return false; }, QStringLiteral("kswordobjects.KswordObjects"),
            {QStringLiteral("--method"), QStringLiteral("3")}, app.applicationDirPath());
        check(special.status == Status::Partial && special.count == 1 && specialResult.evidence.size() == 1 &&
            specialResult.evidence.front().objectAddress == 0xffff800000000001ULL, "plugin receipt and exact address");
        special = {};
        RunVolatilityPlugin(specialResult, special, inputs, [] { return false; }, QStringLiteral("kswordobjects.KswordObjects"),
            {QStringLiteral("--method"), QStringLiteral("5")}, app.applicationDirPath());
        check(special.status == Status::Partial, "missing plugin coverage receipt");
        const auto plugins = VolatilityMethods();
        const auto vol = Run(plugins[0].bit | plugins[1].bit, {}, inputs);
        check(vol.reports.size() == 2 && vol.reports[0].status == Status::Complete &&
            vol.reports[1].status == Status::Failed, "external provider success and failure receipts");
        check(vol.evidence.size() == 1 && vol.evidence.front().pid == 77 &&
            vol.evidence.front().image == QStringLiteral("image,name") &&
            vol.evidence.front().detail.contains(QStringLiteral("line two")) &&
            vol.evidence.front().detail.contains(QStringLiteral("18446744073709486081")) &&
            vol.evidence.front().scope == inputs.memoryImage, "quoted CSV fields and offline identity");
        setEntry(0x4000, 0);
        check(image.open(QIODevice::WriteOnly | QIODevice::Truncate), "test image reopen");
        writeImage();
        const auto broken = Run(RawPageRoots, {}, inputs);
        check(broken.reports.size() == 1 && broken.reports.front().status == Status::Complete &&
            broken.evidence.isEmpty(), "self-reference without a mapped user page must be excluded");
        bytes.replace(0, 8, "PAGEDU64");
        check(image.open(QIODevice::WriteOnly | QIODevice::Truncate), "test image reopen");
        writeImage();
        const auto dump = Run(RawPageRoots, {}, inputs);
        check(dump.reports.size() == 1 && dump.reports.front().status == Status::Failed &&
            dump.evidence.isEmpty(), "crash dump header must be rejected");
        std::cout << "PASS checks=" << checks << " methods=" << Methods().size()
            << " live_processes=" << live.reports[0].count << " live_threads=" << live.reports[1].count << '\n';
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL check=" << checks << ' ' << error.what() << '\n';
        return 1;
    }
}
