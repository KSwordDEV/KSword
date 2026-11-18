#include <WinSock2.h>
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessDetectionForensics.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include "../../Ksword5.1/Ksword5.1/ksword/file/file_handle_tools.h"
#include "../../Ksword5.1/Ksword5.1/ksword/process/process.h"
#include "../../Ksword5.1/Ksword5.1/ksword/process/injection_trace_collector.h"
#include "../../Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageScan.h"
#include "../../Ksword5.1/Ksword5.1/MemoryDock/PhysicalPageMappings.h"
#include <QCoreApplication>
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
namespace ksword::ark
{
    ProcessCrossViewResult DriverClient::queryProcessCrossView(unsigned long flags, std::uint32_t,
        std::uint32_t, unsigned long, DriverHandle*) const
    { processFlags = flags; return unavailable<ProcessCrossViewResult>(); }
    ThreadCrossViewResult DriverClient::queryThreadCrossView(unsigned long flags, std::uint32_t,
        std::uint32_t, std::uint32_t, unsigned long) const
    { threadFlags = flags; return unavailable<ThreadCrossViewResult>(); }
    CallbackMonitorStatusResult DriverClient::queryCallbackMonitorStatus() const { return unavailable<CallbackMonitorStatusResult>(); }
    CallbackMonitorReadResult DriverClient::readCallbackMonitor(std::uint64_t, unsigned long) const { return unavailable<CallbackMonitorReadResult>(); }
    HvmEventResult DriverClient::queryHvmEvents(std::uint64_t, unsigned long, bool) const { return unavailable<HvmEventResult>(); }
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
    void collectPhysicalPages(const std::shared_ptr<ScanJob>&) { throw std::runtime_error("disabled live PFN provider executed"); }
    void collectPhysicalMappings(const std::shared_ptr<MappingJob>&, unsigned) { throw std::runtime_error("disabled mappings provider executed"); }
}
namespace ks::process
{
    std::string GetProcessNameByPID(std::uint32_t) { throw std::runtime_error("unused network process name lookup"); }
    std::string QueryProcessPathByPid(std::uint32_t) { throw std::runtime_error("file occupancy search executed"); }
    std::vector<ProcessRecord> EnumerateProcesses(ProcessEnumStrategy, ProcessEnumStrategy*, std::uint32_t)
    { throw std::runtime_error("disabled per-process memory survey executed"); }
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
    if (args.value(1) == QStringLiteral("--exit-fixture")) return 0;
    if (args.value(1) == QStringLiteral("--offline"))
    {
        if (args.size() != 8 || args[2] != QStringLiteral("-q") || args[3] != QStringLiteral("-r")
            || args[4] != QStringLiteral("csv") || args[5] != QStringLiteral("-f")
            || !QFileInfo(args[6]).isFile()) return 2;
        if (args[7] == QStringLiteral("windows.pslist.PsList"))
        {
            std::cout << "TreeDepth,PID,ImageFileName,Note,Offset\n0,77,\"image,name\",\"line one\nline two\",18446744073709486081\n";
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
        check(roots.reports.size() == 1 && roots.reports.front().status == Status::Complete &&
            roots.evidence.size() == 1 && roots.evidence.front().detail.contains(QStringLiteral("PML4=0x1000"))
            && roots.evidence.front().scope == inputs.flatPhysicalImage, "known flat page root");
        inputs.volatilityProgram = app.applicationFilePath();
        inputs.memoryImage = inputs.flatPhysicalImage;
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
