#include "ProcessResearchCatalog.h"
#include "ProcessDetectionForensics.h"
#include "ProcessDetectionNativeMemory.h"
#include "ProcessDetectionProfile.h"
#include "ProcessResearchActivity.h"
#include "ProcessResearchExternal.h"
#include "ProcessResearchObjects.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include <QElapsedTimer>

namespace ksword::detection
{
    namespace
    {
        MethodMask sourcesFor(const ResearchPoint& point, const ScanInputs& inputs)
        {
            const bool image = !inputs.volatilityProgram.isEmpty() && !inputs.memoryImage.isEmpty();
            if (point.id == 10 && image) return 1ULL << 43; // PsXView's CSRSS handle view.
            if (point.id == 64 && !image) return 0;
            if (point.id == 63 && image) return point.sources | (1ULL << 50); // Volatility drivermodule.
            if (point.id == 65 && image) return point.sources | (1ULL << 52); // Volatility SSDT.
            if (point.id == 19 && !inputs.memProcFsRoot.isEmpty()) return MountedDtb;
            if (point.id == 26 && !inputs.memProcFsRoot.isEmpty()) return MountedPfn;
            return point.sources;
        }

        void callbackInventory(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto data = ark::DriverClient().enumerateCallbacks();
            if (!data.io.ok)
            {
                report.status = data.io.deviceOpenFailed ? Status::Unavailable : Status::Failed;
                report.detail = QString::fromStdString(data.io.message);
                return;
            }
            bool partial = !data.snapshotConsistent || data.lastStatus < 0 || data.returnedCount < data.totalCount;
            bool observed = false;
            for (const auto& entry : data.entries)
            {
                if (stop()) { report.status = Status::Cancelled; return; }
                if (entry.status == KSWORD_ARK_CALLBACK_ENUM_STATUS_NOT_REGISTERED) { observed = true; continue; }
                if (!(entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_CALLBACK_ADDRESS) || !entry.callbackAddress)
                { partial = true; continue; }
                observed = true;
                Evidence row;
                row.researchPoints.set(64-1);
                row.objectAddress = entry.callbackAddress;
                row.image = QString::fromStdWString(entry.modulePath);
                row.category = QStringLiteral("内核回调归属");
                row.detail = QStringLiteral("%1 | class=%2 | source=%3 | status=%4 | flags=0x%5 | NTSTATUS=0x%6")
                    .arg(QString::fromStdWString(entry.name)).arg(entry.callbackClass).arg(entry.source).arg(entry.status)
                    .arg(entry.fieldFlags,0,16).arg(quint32(entry.lastStatus),0,16);
                partial |= !(entry.fieldFlags & KSWORD_ARK_CALLBACK_ENUM_FIELD_MODULE) ||
                    (entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_OK && entry.status != KSWORD_ARK_CALLBACK_ENUM_STATUS_SUSPICIOUS);
                scan.evidence.append(std::move(row));
                ++report.count;
            }
            report.status = !partial ? Status::Complete : observed ? Status::Partial : Status::Unavailable;
            report.detail = QStringLiteral("R0 | %1/%2 | NTSTATUS=0x%3").arg(data.returnedCount).arg(data.totalCount).arg(quint32(data.lastStatus),0,16);
        }

        void addKernelImageView(int id, const ScanInputs& inputs, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            if (inputs.volatilityProgram.isEmpty() || inputs.memoryImage.isEmpty() || stop()) return;
            MethodReport offline;
            offline.researchId = id;
            const auto start = scan.evidence.size();
            if (!CollectResearchObjects(id, inputs, scan, offline, stop)) return;
            for (auto i = start; i < scan.evidence.size(); ++i)
            {
                scan.evidence[i].researchPoints.set(id-1);
                scan.evidence[i].category = id == 62 ? QStringLiteral("镜像模块外可执行映射线索") : QStringLiteral("镜像共享映射归属");
            }
            report.detail += QStringLiteral("\nVolatility 3 | %1").arg(offline.detail);
            report.count += offline.count;
            if (offline.status == Status::Cancelled) report.status = Status::Cancelled;
            else if (offline.status == Status::Complete && report.status == Status::Complete) return;
            else if (offline.status == Status::Complete || offline.status == Status::Partial ||
                report.status == Status::Complete || report.status == Status::Partial) report.status = Status::Partial;
            else if (offline.status == Status::Failed) report.status = Status::Failed;
        }

        quint32 callbackBits(int id)
        {
            switch (id)
            {
            case 31: return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS;
            case 32: return SubsystemCreationCapture;
            case 33: return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
            case 34: return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
            case 35: return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT;
            case 42: return KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY | KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
            default: return 0;
            }
        }

        bool relevant(const Evidence& row, int id)
        {
            if (id == 10 && (row.methods & (1ULL << 43))) return row.researchPoints.test(10-1);
            if (callbackBits(id) || id == 17 || id == 27)
                return row.researchId == id;
            if (id == 28 || id == 29) return row.researchPoints.test(id-1);
            return true;
        }

        void appendKernelRows(ScanResult& scan, const DetectionSelection& selection)
        {
            const auto append = [&](const auto& row, int id, ULONG flag, MethodMask bit, quint32 tid) {
                if (!selection.research.test(id-1) || !(row.sourceMask & flag)) return;
                auto& evidence = scan.evidence.emplaceBack();
                evidence.methods = bit;
                evidence.pid = row.processId;
                evidence.objectAddress = row.objectAddress;
                evidence.image = QString::fromStdString(row.imageName);
                evidence.detail = QStringLiteral("source=0x%1 | anomalies=0x%2 | NTSTATUS=0x%3")
                    .arg(row.sourceMask, 0, 16).arg(ComparableAnomalies(scan, row), 0, 16)
                    .arg(static_cast<quint32>(row.lastStatus), 0, 16);
                if (tid) evidence.detail += QStringLiteral(" | TID=%1").arg(tid);
                if (!row.detail.empty()) evidence.detail += QStringLiteral(" | ") + QString::fromStdString(row.detail);
            };
            if (scan.processCrossView)
                for (const auto& row : scan.processCrossView->entries)
                {
                    append(row, 1, KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST, ActiveProcesses, 0);
                    append(row, 4, KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE, CidProcesses, 0);
                }
            if (scan.threadCrossView)
                for (const auto& row : scan.threadCrossView->entries)
                    append(row, 7, KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST, LinkedThreads, row.threadId);
        }

        // A combined receipt preserves each source's actual completion state. Equal
        // timings from an R0 batch are not interpreted as independent measurements.
        MethodReport receipt(const ResearchPoint& point, MethodMask sources,
            const QVector<MethodReport>& base, quint64 matching)
        {
            MethodReport report;
            report.researchId = point.id;
            report.count = matching;
            const quint32 required = callbackBits(point.id);
            int total = 0, complete = 0, available = 0, failed = 0, cancelled = 0;
            for (const auto& source : base)
            {
                if (!(source.method & sources)) continue;
                auto state = source.status;
                if (required && (state == Status::Complete || state == Status::Partial))
                {
                    if (!(source.capturedCategories & required) && !matching) state = Status::Unavailable;
                    else if ((source.capturedCategories & required) != required) state = Status::Partial;
                    else if (source.completeForCapturedCategories) state = Status::Complete;
                }
                if (point.id == 27 && !matching && state == Status::Partial) state = Status::Unavailable;
                if (point.id == 22 && !matching && (state == Status::Complete || state == Status::Partial))
                    state = Status::Unavailable;
                ++total;
                complete += state == Status::Complete;
                available += state == Status::Complete || state == Status::Partial;
                failed += state == Status::Failed;
                cancelled += state == Status::Cancelled;
                report.elapsedMs += source.elapsedMs;
                if (!source.detail.isEmpty()) {
                    if (!report.detail.isEmpty()) report.detail += QChar::LineFeed;
                    report.detail += source.detail;
                }
            }
            if (cancelled) report.status = Status::Cancelled;
            else if (complete && complete == total) report.status = Status::Complete;
            else if (available) report.status = Status::Partial;
            else if (failed) report.status = Status::Failed;
            else report.status = Status::Unavailable;
            if (point.id == 22 && !matching && report.status == Status::Unavailable)
                report.detail += QStringLiteral(" | No captured CR3 sample");
            return report;
        }
    }

    ScanResult RunSelected(const DetectionSelection& selection, const std::function<bool()>& cancelled,
        const ScanInputs& inputs)
    {
        const CancelCheck stop = [&] { return cancelled && cancelled(); };
        const auto& catalog = ResearchCatalog();
        const auto started = QDateTime::currentDateTimeUtc();
        QString layoutReceipt;
        if (!stop() && (selection.research.test(0) || selection.research.test(6) || selection.research.test(26)))
        {
            QElapsedTimer timer;
            timer.start();
            const auto detail = PrepareDetectionLayout(selection.research);
            if (!detail.isEmpty()) layoutReceipt = QStringLiteral("DynData (%1 ms) | %2").arg(timer.elapsed()).arg(detail);
        }
        MethodMask sources = selection.sources;
        for (const auto& point : catalog)
            if (selection.research.test(point.id-1)) sources |= sourcesFor(point, inputs);
        auto scan = Run(sources, stop, inputs);
        scan.startedUtc = started;
        auto base = std::move(scan.reports);
        scan.reports.clear();
        appendKernelRows(scan, selection);
        std::array<quint64, ResearchCount> counts{};
        for (auto& row : scan.evidence)
        {
            ResearchSet matching;
            for (const auto& point : catalog)
            {
                if (!selection.research.test(point.id-1) || !(row.methods & sourcesFor(point, inputs))) continue;
                if (relevant(row, point.id))
                {
                    matching.set(point.id-1);
                    ++counts[point.id-1];
                }
            }
            row.researchPoints = matching;
        }
        scan.evidence.removeIf([&](const Evidence& row) {
            return row.researchPoints.none() && !(selection.sources & row.methods);
        });
        for (const auto& point : catalog)
        {
            if (!selection.research.test(point.id-1)) continue;
            if (point.backend == ResearchBackend::Shared)
            {
                auto report = receipt(point, sourcesFor(point, inputs), base, counts[point.id-1]);
                if (point.id == 29 || (point.id == 64 && !sourcesFor(point, inputs)))
                {
                    QElapsedTimer timer;
                    timer.start();
                    if (stop()) report.status = Status::Cancelled;
                    else if (point.id == 64) callbackInventory(scan, report, stop);
                    else addKernelImageView(point.id, inputs, scan, report, stop);
                    report.elapsedMs += timer.elapsed();
                }
                if (!layoutReceipt.isEmpty() && (point.id == 1 || point.id == 7 || point.id == 27))
                    report.detail += QChar::LineFeed + layoutReceipt;
                if (point.id == 65 && !stop())
                {
                    const auto start = scan.evidence.size();
                    QElapsedTimer timer;
                    timer.start();
                    ReadResearchKernelPaths(scan, report, stop);
                    report.elapsedMs += timer.elapsed();
                    for (auto i = start; i < scan.evidence.size(); ++i) scan.evidence[i].researchPoints.set(point.id-1);
                }
                scan.reports.append(std::move(report));
                continue;
            }
            MethodReport report;
            report.researchId = point.id;
            const auto start = scan.evidence.size();
            QElapsedTimer clock;
            clock.start();
            if (stop()) report.status = Status::Cancelled;
            else
            {
                bool handled = false;
                switch (point.backend)
                {
                case ResearchBackend::Objects: handled = CollectResearchObjects(point.id, inputs, scan, report, stop); break;
                case ResearchBackend::Activity: handled = CollectResearchActivity(point.id, inputs, scan, report, stop); break;
                case ResearchBackend::External: handled = CollectResearchExternal(point.id, inputs, scan, report, stop); break;
                default: break;
                }
                if (!handled) { report.status = Status::Failed; report.detail = QStringLiteral("No collector registered"); }
                if (point.id == 62) addKernelImageView(point.id, inputs, scan, report, stop);
            }
            report.elapsedMs = clock.elapsed();
            for (auto i = start; i < scan.evidence.size(); ++i) scan.evidence[i].researchPoints.set(point.id-1);
            if (stop()) report.status = Status::Cancelled;
            scan.reports.append(std::move(report));
        }
        for (const auto& source : base)
            if (selection.sources & source.method) scan.reports.append(source);
        scan.cancelled = stop();
        scan.researchVmrsProcessFiles.reset(); // Acquisition-only cache shared by 44/49 in this run.
        return scan;
    }
}
