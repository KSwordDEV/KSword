#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessResearchActivity.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <QCoreApplication>
#include <QProcess>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace ksword::detection;

namespace
{
    unsigned checks = 0;
    ksword::ark::KernelMemoryEvidenceResult pool;
    unsigned long requestedPoolFlags = 0;
    void check(bool condition, const char* message)
    {
        if (!condition) throw std::runtime_error(message);
        ++checks;
    }
    const auto keepGoing = [] { return false; };
}

namespace ksword::ark
{
    KernelMemoryEvidenceResult DriverClient::queryKernelMemoryEvidence(unsigned long flags, unsigned long,
        std::uint64_t, std::uint64_t, std::uint64_t, unsigned long, unsigned long) const
    {
        requestedPoolFlags = flags;
        return pool;
    }
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().contains(QStringLiteral("--trace-marker"))) return 0;
    try
    {
        check(app.arguments().size() >= 2, "fixture root or --live-only required");
        const bool liveOnly = app.arguments().contains(QStringLiteral("--live-only"));
        ScanInputs inputs;
        inputs.memProcFsRoot = app.arguments().at(1);
        const struct { int id; quint32 pid; quint64 address; } cases[] {
            {58, 145, 0x12345000}, {60, 442, 0x42}, {61, 879, 0x1000}
        };
        for (const auto& c : cases)
        {
            if (liveOnly) break;
            ScanResult scan;
            MethodReport report;
            check(CollectResearchActivity(c.id, inputs, scan, report, keepGoing), "missing research dispatch");
            check(report.status == Status::Complete && report.count == 1 && scan.evidence.size() == 1, "typed FindEvil count");
            const auto& row = scan.evidence.front();
            check(row.researchId == c.id && row.pid == c.pid && row.objectAddress == c.address, "typed process identity");
            check(row.creationTime100ns == 0 && !row.scope.isEmpty(), "image evidence stayed offline");
            if (c.id == 58) check(row.image == QStringLiteral("sample name.exe"), "full-width image name with spaces");
        }
        {
            MethodReport report; ScanResult result;
            check(CollectResearchActivity(58, {}, result, report, keepGoing) && report.status == Status::Unavailable, "missing input");
            check(!CollectResearchActivity(32, {}, result, report, keepGoing), "callback has another owner");
            check(CollectResearchActivity(40, {}, result, report, [] { return true; }) && report.status == Status::Cancelled, "WMI cancellation");
        }
        for (const auto eventId : {8,10})
        {
            const auto xml = QStringLiteral("<Event><System><EventID>%1</EventID><EventRecordID>42</EventRecordID>"
                "<TimeCreated SystemTime='2026-01-02T12:10:54Z'/></System><EventData>"
                "<Data Name='SourceProcessID'>200</Data><Data Name='TargetProcessId'>300</Data>"
                "<Data Name='SourceProcessGUID'>{a}</Data><Data Name='TargetProcessGuid'>{b}</Data>"
                "<Data Name='TargetImage'>target.exe</Data></EventData></Event>").arg(eventId);
            Evidence row;
            check(DecodeProcessHistoryEvent(xml, row) && row.pid == 300 && row.image == QStringLiteral("target.exe"), "directed Sysmon target");
            check(row.historical && row.creationTime100ns == 0 && row.detail.contains(QStringLiteral("SourceProcessId=200")) &&
                row.detail.contains(QStringLiteral("TargetProcessGuid={b}")), "direction and lifetime semantics");
            QString missing = xml;
            missing.replace(QStringLiteral("TargetProcessId"), QStringLiteral("OtherField"));
            check(!DecodeProcessHistoryEvent(missing, row), "no target PID fallback to source or provider PID");
        }
        {
            const QString service = QStringLiteral("<Event><System><EventID>7045</EventID><EventRecordID>53</EventRecordID>"
                "<TimeCreated SystemTime='2026-01-02T12:10:55Z'/></System><EventData>"
                "<Data Name='ServiceName'>example</Data><Data Name='ImagePath'>example.exe</Data></EventData></Event>");
            Evidence row;
            check(DecodeProcessHistoryEvent(service, row) && row.pid == 0 && row.historical &&
                row.image == QStringLiteral("example.exe") && row.detail.contains(QStringLiteral("ServiceName=example")), "service install has no execution identity");
        }
        {
            ScanResult scan; MethodReport report;
            check(CollectResearchActivity(62, {}, scan, report, keepGoing) && scan.evidence.empty(), "missing transport produces no candidates");
            pool.io.ok = true;
            pool.sourceFlags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES | KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
            check(requestedPoolFlags == pool.sourceFlags, "big pool budget is independent of module scans");
            pool.status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK;
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Unavailable, "missing module coverage is not a clean scan");
            pool.moduleCount = 12;
            pool.status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL;
            pool.lastStatus = static_cast<long>(0xc0000004U);
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Failed && report.detail.contains(QStringLiteral("c0000004")),
                "old driver length mismatch must not look like a successful empty enumeration");
            pool.sourceFlags |= KSWORD_ARK_MEMORY_EVIDENCE_SOURCE_BIGPOOL_QUERIED;
            pool.bigPoolQueryStatus = static_cast<long>(0xc0000022U);
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Unavailable && report.detail.contains(QStringLiteral("c0000022")),
                "raw big pool status must survive an unrelated aggregate status");
            pool.bigPoolQueryStatus = 0;
            pool.lastStatus = static_cast<long>(0xc000003eU);
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Failed && report.detail.contains(QStringLiteral("c000003e")),
                "native success with an invalid directory is a failed observation");
            pool.sourceFlags |= KSWORD_ARK_MEMORY_EVIDENCE_SOURCE_BIGPOOL_VALIDATED;
            pool.lastStatus = 0;
            pool.status = KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK;
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Partial && report.count == 0 &&
                report.detail.contains(QStringLiteral("SystemBigPoolInformation NTSTATUS=0x00000000")),
                "only a validated empty directory gets a successful source receipt");
            pool.bigPoolRowsSeen = 4;
            pool.bytesScanned = 4 * 4096;
            ksword::ark::KernelMemoryEvidenceEntry entry;
            entry.evidenceKind = KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL;
            entry.ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL;
            entry.permissionFlags = KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT | KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE;
            entry.riskFlags = KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE;
            entry.virtualAddress = 0xffff800000000000ULL;
            pool.entries.push_back(entry);
            entry.ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE; pool.entries.push_back(entry);
            entry.ownerKind = KSWORD_ARK_MEMORY_EVIDENCE_OWNER_BIGPOOL;
            entry.riskFlags = KSWORD_ARK_MEMORY_EVIDENCE_RISK_EXECUTABLE_POOL; pool.entries.push_back(entry);
            entry.riskFlags = KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE;
            entry.permissionFlags = KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX; pool.entries.push_back(entry);
            CollectResearchActivity(62, {}, scan, report, keepGoing);
            check(report.status == Status::Partial && scan.evidence.size() == 1 && scan.evidence.first().researchId == 62,
                "only a present executable nonmodule page is attached to 62");
        }
        if (liveOnly || app.arguments().contains(QStringLiteral("--live")))
        {
            for (int id : {40,43})
            {
                ScanResult scan; MethodReport report;
                std::vector<quint32> markerPids;
                std::jthread markers;
                if (id == 40 && app.arguments().contains(QStringLiteral("--probe-wmi")))
                {
                    const auto executable = QCoreApplication::applicationFilePath();
                    markers = std::jthread([&, executable](std::stop_token stop) {
                        for (int i = 0; i < 10 && !stop.stop_requested(); ++i) {
                            std::this_thread::sleep_for(std::chrono::milliseconds(700));
                            if (stop.stop_requested()) return;
                            QProcess marker;
                            marker.start(executable, {QStringLiteral("--trace-marker")});
                            if (marker.waitForStarted(1500)) {
                                markerPids.push_back(static_cast<quint32>(marker.processId()));
                                marker.waitForFinished(2000);
                            }
                        }
                    });
                }
                check(CollectResearchActivity(id, {}, scan, report, keepGoing), "native activity collection");
                std::cout << "id=" << id << " status=" << int(report.status) << " count=" << report.count
                    << " detail=" << report.detail.toStdString() << '\n';
                if (markers.joinable()) {
                    markers.request_stop(); markers.join();
                    unsigned pairs = 0;
                    for (const auto pid : markerPids) {
                        bool start = false, end = false;
                        for (const auto& row : scan.evidence) {
                            if (row.pid != pid) continue;
                            start |= row.detail.startsWith(QStringLiteral("Win32_ProcessStartTrace"));
                            end |= row.detail.startsWith(QStringLiteral("Win32_ProcessStopTrace"));
                        }
                        if (start && end) ++pairs;
                    }
                    std::cout << "controlled_children=" << markerPids.size() << " start_stop_pairs=" << pairs << '\n';
                    check(pairs > 0, "WMI did not observe a controlled child lifecycle");
                }
                for (const auto& row : scan.evidence)
                    if (row.researchId != id || !row.historical || row.creationTime100ns != 0 || (id == 43 && row.pid))
                        throw std::runtime_error("historical artifact promoted to live process");
            }
        }
        std::cout << "PASS checks=" << checks << '\n';
        return 0;
    }
    catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
