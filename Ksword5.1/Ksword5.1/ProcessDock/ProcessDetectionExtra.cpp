#include "ProcessDetectionExtra.h"
#include "ProcessDetectionForensics.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include <QElapsedTimer>
#include <QHash>

namespace ksword::detection
{
    namespace
    {
        void readWatchHistory(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            ark::DriverClient client;
            const auto page = client.queryHvmEvents(0, KSWORD_ARK_HVM_MAX_EVENT_ROWS, false);
            if (!page.io.ok)
            {
                report.status = Status::Unavailable;
                report.detail = QString::fromStdString(page.io.message);
                return;
            }
            const auto& response = page.response;
            const auto size = (std::min)(response.returnedRows, static_cast<unsigned long>(KSWORD_ARK_HVM_MAX_EVENT_ROWS));
            if (response.droppedRows || response.availableRows > size || size != response.returnedRows)
                report.status = Status::Partial;
            QHash<quint64, QPair<quint32, quint32>> owners;
            for (unsigned long i = 0; i < size; ++i)
            {
                if (stop()) { report.status = Status::Cancelled; break; }
                const auto& row = response.rows[i];
                if (!(row.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_WATCH_HIT) || !row.guestCr3) continue;
                if (!owners.contains(row.guestCr3))
                {
                    const auto lookup = client.resolveHvmDirectoryBase(row.guestCr3);
                    owners.insert(row.guestCr3, lookup.io.ok
                        ? qMakePair(quint32(lookup.response.resolvedProcessId), quint32(lookup.response.resolvedScannedProcesses))
                        : QPair<quint32, quint32>{});
                    if (!lookup.io.ok || !lookup.response.resolvedScannedProcesses) report.status = Status::Partial;
                }
                const auto attribution = owners.value(row.guestCr3);
                Evidence evidence;
                evidence.methods = report.method;
                evidence.historical = true;
                evidence.pid = attribution.first;
                evidence.scope = QStringLiteral("HVM / EPT");
                evidence.detail = QStringLiteral("#%1 | CPU=%2:%3 | CR3=0x%4 | GPA=0x%5 | RIP=0x%6 | access=0x%7 | PID candidates checked=%8")
                    .arg(row.sequence).arg(row.processorGroup).arg(row.processorNumber).arg(row.guestCr3, 0, 16)
                    .arg(row.guestPhysicalAddress, 0, 16).arg(row.guestRip, 0, 16).arg(row.access, 0, 16).arg(attribution.second);
                scan.evidence.append(std::move(evidence));
                ++report.count;
            }
            report.detail = QStringLiteral("读取既有监视事件 %1 条，丢失 %2 条。PID 归属来自本次查询。").arg(size).arg(response.droppedRows);
        }

        void readIntegrity(ScanResult& scan, MethodReport& report)
        {
            ark::DriverClient client;
            const auto data = report.method == CpuIntegrity ? client.queryKernelCpuIntegrity()
                : client.queryDriverIntegrity({}, 0, KSWORD_ARK_DRIVER_INTEGRITY_FLAG_DRIVER_OBJECT |
                    KSWORD_ARK_DRIVER_INTEGRITY_FLAG_OPTIONAL_GLOBALS);
            if (!data.io.ok || data.queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_UNAVAILABLE)
                report.status = Status::Unavailable;
            else if (data.queryStatus == KSWORD_ARK_DRIVER_INTEGRITY_STATUS_QUERY_FAILED)
                report.status = Status::Failed;
            else if (data.queryStatus != KSWORD_ARK_DRIVER_INTEGRITY_STATUS_OK || data.statusFlags || data.totalCount > data.returnedCount)
                report.status = Status::Partial;
            report.detail = QStringLiteral("status=%1 | flags=0x%2 | %3/%4 | %5")
                .arg(data.queryStatus).arg(data.statusFlags, 0, 16).arg(data.returnedCount).arg(data.totalCount)
                .arg(QString::fromStdString(data.io.message));
            for (const auto& row : data.entries)
            {
                Evidence evidence;
                evidence.methods = report.method;
                evidence.category = QStringLiteral("内核完整性证据");
                evidence.image = QString::fromStdWString(row.ownerModule);
                evidence.objectAddress = row.objectAddress;
                evidence.detail = QStringLiteral("%1 | target=0x%2 | class=%3 | risk=0x%4 | CPU=%5:%6 | vector=%7 | status=%8")
                    .arg(QString::fromStdWString(row.detail)).arg(row.targetAddress, 0, 16).arg(row.evidenceClass)
                    .arg(row.riskFlags, 0, 16).arg(row.processorGroup).arg(row.processorNumber).arg(row.vector).arg(row.entryStatus);
                scan.evidence.append(std::move(evidence));
                ++report.count;
            }
        }
    }

    QVector<Method> ExtraMethods()
    {
        QVector<Method> catalog{
            {SecurityHistory, QStringLiteral("安全审计进程历史（24 小时）"), Cost::Moderate},
            {SysmonHistory, QStringLiteral("Sysmon 进程历史（24 小时）"), Cost::Moderate},
            {MountedDtb, QStringLiteral("MemProcFS 页表根与进程归属"), Cost::Slow},
            {MountedPfn, QStringLiteral("MemProcFS 私有物理页归属"), Cost::Slow},
            {HvmWatchHistory, QStringLiteral("HVM 监视命中的 CR3 归属"), Cost::Slow},
            {KernelIntegrity, QStringLiteral("R0 驱动对象与模块完整性"), Cost::Slow},
            {CpuIntegrity, QStringLiteral("R0 CPU 与 IDT 完整性"), Cost::Slow},
            {EtlProcesses, QStringLiteral("ETL 进程生命周期"), Cost::Slow},
            {EtlThreads, QStringLiteral("ETL 线程与上下文切换"), Cost::Slow},
            {RawPageRoots, QStringLiteral("平坦物理镜像自引用 PML4 扫描"), Cost::Slow}
        };
        catalog += VolatilityMethods();
        return catalog;
    }

    void CollectExtraMethods(ScanResult& scan, const ScanInputs& inputs, const std::function<bool()>& cancelled)
    {
        const CancelCheck stop = [&] { return cancelled && cancelled(); };
        for (const auto& method : ExtraMethods())
        {
            if (!(method.bit & scan.selected)) continue;
            MethodReport report;
            report.method = method.bit;
            QElapsedTimer time;
            time.start();
            if (stop()) report.status = Status::Cancelled;
            else if (method.bit == SecurityHistory || method.bit == SysmonHistory) ReadEventHistory(scan, report, stop);
            else if (method.bit == MountedDtb || method.bit == MountedPfn) ReadMountedMemory(scan, report, inputs.memProcFsRoot, stop);
            else if (method.bit == HvmWatchHistory) readWatchHistory(scan, report, stop);
            else if (method.bit == RawPageRoots) ScanRawPageRoots(scan, report, inputs.flatPhysicalImage, stop);
            else if (method.bit == EtlProcesses || method.bit == EtlThreads) ReadEtl(scan, report, inputs.eventTraceFile, stop);
            else if (method.bit == CpuIntegrity || method.bit == KernelIntegrity) readIntegrity(scan, report);
            else ReadVolatility(scan, report, inputs, stop);
            report.elapsedMs = time.elapsed();
            if (report.status == Status::Cancelled) scan.cancelled = true;
            scan.reports.append(std::move(report));
        }
    }
}
