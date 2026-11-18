#include "ProcessDetectionNativeMemory.h"
#include "../MemoryDock/PhysicalPageScan.h"
#include "../MemoryDock/PhysicalPageConsumers.h"
#include "../ksword/process/injection_trace_collector.h"
#include "../ksword/process/process.h"
#include "../../../shared/usermode/backend/driver/DriverQueries.h"
#include <QElapsedTimer>
#include <QMap>
#include <QStringList>

namespace ksword::detection
{
    namespace
    {
        using Stop = std::function<bool()>;
        bool stopped(const Stop& stop) { return stop && stop(); }
        void residentMappings(ScanResult& out, MethodReport& report, const Stop& stop)
        {
            auto job = std::make_shared<pfn::MappingJob>();
            job->externalCancel = stop;
            pfn::collectPhysicalMappings(job, 30);
            const auto& scan = job->result;
            if (!scan || !scan->driverAvailable)
            {
                report.status = scan ? Status::Unavailable : Status::Failed;
                report.detail = QStringLiteral("工作集 PFN 映射核验需要可用的 R0 页表查询。");
                return;
            }
            report.count = scan->rows.size();
            if (scan->cancelled) report.status = Status::Cancelled;
            else if (scan->status < 0 && scan->rows.empty()) report.status = Status::Failed;
            else if (scan->failedAllocation || scan->status < 0 || scan->failed || scan->budgetReached ||
                scan->inaccessible || scan->regionQueryFailures || scan->workingSetQueryFailures ||
                scan->objectBudgetReached || scan->identityConflicted || scan->changedMappings)
                report.status = Status::Partial;
            report.detail = QStringLiteral("30 秒采样，已核实映射 %1，探测 %2，访问受限进程 %3，映射变化 %4，对象关系 %5，NTSTATUS 0x%6")
                .arg(scan->rows.size()).arg(scan->tested).arg(scan->inaccessible).arg(scan->changedMappings)
                .arg(scan->verifiedObjectRelations).arg(static_cast<quint32>(scan->status), 0, 16);
            // Collapse resident mappings by allocation and preserve one directly revalidated VA/PFN.
            struct Sample { quint64 count = 0, pfn = 0, va = 0; };
            QMap<quint32, Sample> samples;
            for (const auto& mapping : scan->rows)
            {
                if (!mapping.pfnRevalidated || mapping.backingIndex >= scan->backing.size()) continue;
                auto& sample = samples[mapping.backingIndex];
                if (!sample.count) { sample.pfn = mapping.pfn; sample.va = mapping.address; }
                ++sample.count;
            }
            for (auto it = samples.cbegin(); it != samples.cend(); ++it)
            {
                const auto& backing = scan->backing[it.key()];
                auto& row = out.evidence.emplaceBack();
                row.methods = report.method;
                row.pid = backing.pid;
                row.creationTime100ns = backing.processCreateTime;
                row.image = backing.process;
                row.objectAddress = it->va;
                row.detail = QStringLiteral("映射 %1 页，示例 PFN 0x%2，分配基址 0x%3，Section 0x%4，ControlArea 0x%5，%6")
                    .arg(it->count).arg(it->pfn, 0, 16).arg(backing.allocationBase, 0, 16)
                    .arg(backing.sectionObject, 0, 16).arg(backing.controlArea, 0, 16).arg(backing.path);
            }
            if (scan->consumers)
            {
                if ((scan->consumers->budgetReached || scan->consumers->failed) && report.status == Status::Complete)
                    report.status = Status::Partial;
                for (const auto& witness : scan->consumers->relations)
                {
                    auto& row = out.evidence.emplaceBack();
                    row.methods = report.method;
                    if (witness.processIdentityRevalidated)
                    {
                        row.pid = witness.pid;
                        row.creationTime100ns = witness.processCreateTime;
                    }
                    row.category = QStringLiteral("物理页使用关系");
                    row.objectAddress = witness.virtualAddress;
                    row.detail = QStringLiteral("kind=%1 | PFN=0x%2 | TID=%3 | CR3=0x%4")
                        .arg(static_cast<int>(witness.kind)).arg(witness.pfn, 0, 16)
                        .arg(witness.tid).arg(witness.translationFinal.cr3, 0, 16);
                }
            }
        }
        void physicalOwners(ScanResult& out, MethodReport& report, const Stop& stop)
        {
            auto job = std::make_shared<pfn::ScanJob>();
            job->externalCancel = stop;
            pfn::collectPhysicalPages(job);
            const auto& scan = job->result;
            if (!scan)
            {
                report.status = Status::Failed;
                report.detail = QStringLiteral("物理页扫描未返回结果。");
                return;
            }
            report.count = scan->accounting.visited;
            if (scan->cancelled) report.status = Status::Cancelled;
            else if (scan->rangesStatus < 0) report.status = Status::Unavailable;
            else if (scan->resourceFailure || !scan->complete || !scan->ownersRechecked ||
                scan->unresolvedPrivatePages || scan->groupedOverflowPages) report.status = Status::Partial;
            report.detail = QStringLiteral("物理页 %1/%2，无法读取 %3，私有页已归属 %4，未核实归属 %5，所有者冲突 %6，NTSTATUS 0x%7")
                .arg(scan->accounting.visited).arg(scan->accounting.expected).arg(scan->accounting.unreadable)
                .arg(scan->resolvedPrivatePages).arg(scan->unresolvedPrivatePages).arg(scan->ownerConflicts)
                .arg(static_cast<quint32>(scan->rangesStatus < 0 ? scan->rangesStatus : scan->lastPageStatus), 0, 16);
            for (const auto& group : scan->groups)
            {
                if (group.use != pfn::Use::Private || !group.pages) continue;
                auto& row = out.evidence.emplaceBack();
                row.methods = report.method;
                if (group.ownerLifetimeVerified)
                {
                    row.pid = group.pid;
                    row.creationTime100ns = group.ownerCreateTime;
                    row.image = group.name;
                }
                else row.category = QStringLiteral("未核实所属进程的物理页");
                row.detail = QStringLiteral("私有物理页 %1，首次 PFN 0x%2，所有者键 0x%3，端点记录 PID %4")
                    .arg(group.pages).arg(group.firstPfn, 0, 16).arg(group.key, 0, 16).arg(group.pid);
            }
        }

        void processMemory(ScanResult& out, MethodReport& report, const Stop& stop)
        {
            namespace ev = Ksword::Evidence;
            const auto processes = ks::process::EnumerateProcesses(ks::process::ProcessEnumStrategy::Auto);
            if (processes.empty())
            {
                report.status = Status::Failed;
                report.detail = QStringLiteral("无法取得本次用户态进程清单。");
                return;
            }
            quint64 verified = 0, denied = 0, incomplete = 0, kernelChecked = 0;
            QString firstFailure;
            // Use the existing read-only survey and its identity/coverage verdicts. Fast mode
            // includes executable PTEs, VADs, memory images and thread starts, without stack capture.
            ks::process::InjectionTraceOptions options;
            options.cancelled = stop;
            for (const auto& process : processes)
            {
                if (stopped(stop)) break;
                if (!process.pid) continue;
                if (!process.creationTime100ns) { ++denied; continue; }
                const auto scan = ks::process::ScanProcessInjectionTrace(process.pid, process.creationTime100ns,
                    QString::fromStdString(process.imagePath), options);
                if (stopped(stop)) break;
                if (!scan.completed() || scan.report.identity != ev::IdentityRecheckVerdict::Same)
                {
                    ++denied;
                    if (firstFailure.isEmpty()) firstFailure = QStringLiteral("PID %1 | %2")
                        .arg(process.pid).arg(scan.diagnosticText);
                    continue;
                }
                ++verified;
                const bool kernelComplete = scan.kernelPteState == ev::KernelBackendState::Available &&
                    scan.kernelVadState == ev::KernelBackendState::Available;
                if (kernelComplete) ++kernelChecked;
                if (!scan.report.scopeIntact || !kernelComplete) ++incomplete;
                struct RuleGroup { quint64 count = 0; const ev::InjectionFinding* first = nullptr; };
                QMap<QString, RuleGroup> rules;
                for (const auto& finding : scan.report.findings)
                {
                    auto& group = rules[QString::fromStdString(finding.ruleId)];
                    if (!group.first) group.first = &finding;
                    ++group.count;
                }
                for (auto it = rules.cbegin(); it != rules.cend(); ++it)
                {
                    const auto& sample = *it->first;
                    auto& row = out.evidence.emplaceBack();
                    row.methods = report.method;
                    row.category = QStringLiteral("进程内存与执行线索");
                    row.pid = process.pid;
                    row.creationTime100ns = scan.creationTime100ns;
                    row.image = scan.imagePath;
                    row.objectAddress = sample.address.present ? sample.address.value : 0;
                    QStringList facts;
                    for (const auto& fact : sample.facts) facts << QString::fromStdString(fact);
                    row.detail = QStringLiteral("规则 %1，观测 %2 处，首条记录 %3")
                        .arg(it.key()).arg(it->count).arg(facts.join(QChar::LineFeed));
                }
            }
            report.count = verified;
            if (!verified) report.status = Status::Unavailable;
            else if (denied || incomplete) report.status = Status::Partial;
            report.detail = QStringLiteral("核实进程 %1，拒绝访问或身份失效 %2，覆盖不完整 %3，完整 VAD/PTE 对照 %4")
                .arg(verified).arg(denied).arg(incomplete).arg(kernelChecked);
            if (!firstFailure.isEmpty()) report.detail += QChar::LineFeed + firstFailure;
        }

        bool failedIo(const ark::IoResult& io, MethodReport& report)
        {
            if (io.ok) return false;
            report.status = io.deviceOpenFailed || io.win32Error == ERROR_NOT_SUPPORTED ||
                io.win32Error == ERROR_INVALID_FUNCTION ? Status::Unavailable : Status::Failed;
            report.detail = QString::fromStdString(io.message);
            return true;
        }

        void kernelPages(ScanResult& out, MethodReport& report)
        {
            const ark::DriverClient client;
            constexpr ULONG flags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_LOADED_MODULE_EXECUTABLE |
                KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_BIGPOOL | KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
            const auto response = client.queryKernelMemoryEvidence(flags);
            if (failedIo(response.io, report)) return;
            if (response.status == KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE) report.status = Status::Unavailable;
            else if (response.status == KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL || response.responseFlags ||
                response.totalRows > response.returnedRows) report.status = Status::Partial;
            else if (response.status != KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK) report.status = Status::Failed;
            report.count = response.returnedRows;
            report.detail = QStringLiteral("扫描字节 %1，内核模块 %2，大池条目 %3，返回 %4/%5，状态 %6，标志 0x%7")
                .arg(response.bytesScanned).arg(response.moduleCount).arg(response.bigPoolRowsSeen)
                .arg(response.returnedRows).arg(response.totalRows).arg(response.status).arg(response.responseFlags, 0, 16);
            for (const auto& entry : response.entries)
            {
                if (!entry.riskFlags) continue;
                auto& row = out.evidence.emplaceBack();
                row.methods = report.method;
                row.category = QStringLiteral("内核内存执行线索");
                row.image = QString::fromStdWString(entry.ownerName);
                row.objectAddress = entry.virtualAddress;
                row.detail = QStringLiteral("%1 | kind=%2 | owner=%3 | permissions=0x%4 | flags=0x%5 | size=%6")
                    .arg(QString::fromStdWString(entry.detail)).arg(entry.evidenceKind).arg(entry.ownerKind)
                    .arg(entry.permissionFlags, 0, 16).arg(entry.riskFlags, 0, 16).arg(entry.regionSize);
            }
        }

        void workItems(ScanResult& out, MethodReport& report)
        {
            const auto response = ark::DriverClient().enumerateWorkQueues();
            if (failedIo(response.io, report)) return;
            if (response.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_UNSUPPORTED) report.status = Status::Unavailable;
            else if (response.queryStatus == KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_PARTIAL ||
                response.totalCount > response.returnedCount) report.status = Status::Partial;
            else if (response.queryStatus != KSWORD_ARK_WORK_QUEUE_QUERY_STATUS_OK) report.status = Status::Failed;
            report.count = response.returnedCount;
            report.detail = QStringLiteral("工作队列 %1，返回 %2/%3，损坏链 %4，读取失败 %5，对象引用失败 %6，状态 %7")
                .arg(response.queuesVisited).arg(response.returnedCount).arg(response.totalCount)
                .arg(response.corruptListCount).arg(response.readFailureCount).arg(response.referenceFailureCount).arg(response.queryStatus);
            for (const auto& entry : response.entries)
            {
                auto& row = out.evidence.emplaceBack();
                row.methods = report.method;
                row.category = entry.rowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD ?
                    QStringLiteral("内核工作线程") : QStringLiteral("内核工作项");
                row.image = QString::fromStdString(entry.modulePath);
                row.objectAddress = entry.rowKind == KSWORD_ARK_WORK_QUEUE_ROW_WORKER_THREAD ?
                    entry.threadObject : entry.workItemAddress;
                row.detail = QStringLiteral("TID %1，队列 0x%2，例程 0x%3，标志 0x%4，状态 %5")
                    .arg(entry.threadId).arg(entry.queueAddress, 0, 16).arg(entry.routineAddress, 0, 16)
                    .arg(entry.flags, 0, 16).arg(entry.status);
            }
        }

        void timerRoutines(ScanResult& out, MethodReport& report)
        {
            const ark::DriverClient client;
            const auto response = client.enumerateKernelTimerDpc();
            if (failedIo(response.io, report)) return;
            if (response.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_NOT_SUPPORTED ||
                response.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_DYNDATA_MISSING) report.status = Status::Unavailable;
            else if (response.queryStatus == KSWORD_ARK_TIMER_DPC_QUERY_STATUS_PARTIAL ||
                response.totalCount > response.returnedCount) report.status = Status::Partial;
            else if (response.queryStatus != KSWORD_ARK_TIMER_DPC_QUERY_STATUS_OK) report.status = Status::Failed;
            report.count = response.returnedCount;
            report.detail = QStringLiteral("处理器 %1，定时器桶 %2，损坏 %3，读取失败 %4，状态 %5")
                .arg(response.processorCount).arg(response.bucketsVisited).arg(response.corruptBucketCount)
                .arg(response.readFailureCount).arg(response.queryStatus);
            if (response.entries.empty()) return;
            const auto snapshot = client.captureDriverObjectModules();
            if (snapshot.systemInformation.empty() && report.status == Status::Complete) report.status = Status::Partial;
            // captureDriverObjectModules validates every extent and bounded path before publication.
            const auto modules = snapshot.systemInformation.empty() ? nullptr :
                reinterpret_cast<const ks::r3::driver::KRTL_PROCESS_MODULES*>(snapshot.systemInformation.data());
            QMap<quint64, QString> routines;
            for (const auto& entry : response.entries)
            {
                if (!(entry.flags & KSWORD_ARK_TIMER_DPC_ENTRY_DPC_FIELDS_PRESENT) || !entry.deferredRoutine) continue;
                auto match = routines.find(entry.deferredRoutine);
                if (match == routines.end())
                {
                    QString path;
                    for (ULONG i = 0; modules && i < modules->NumberOfModules; ++i)
                    {
                        const auto& module = modules->Modules[i];
                        const auto base = reinterpret_cast<quintptr>(module.ImageBase);
                        if (entry.deferredRoutine >= base && entry.deferredRoutine - base < module.ImageSize)
                        {
                            path = QString::fromLocal8Bit(reinterpret_cast<const char*>(module.FullPathName),
                                strnlen(reinterpret_cast<const char*>(module.FullPathName), sizeof(module.FullPathName)));
                            break;
                        }
                    }
                    match = routines.insert(entry.deferredRoutine, path);
                }
                auto& row = out.evidence.emplaceBack();
                row.methods = report.method;
                row.category = QStringLiteral("内核定时器 DPC");
                row.image = match.value();
                row.objectAddress = entry.dpcAddress;
                row.detail = QStringLiteral("CPU %1:%2，定时器 0x%3，例程 0x%4，标志 0x%5")
                    .arg(entry.processorGroup).arg(entry.processorNumber).arg(entry.timerAddress, 0, 16)
                    .arg(entry.deferredRoutine, 0, 16).arg(entry.flags, 0, 16);
            }
        }
    }

    QVector<Method> NativeMemoryMethods()
    {
        return {
            {PhysicalPageOwners, QStringLiteral("全内存 PFN 私有页归属"), Cost::Slow},
            {ResidentMappings, QStringLiteral("工作集、PTE 与 PFN 映射复核（30 秒）"), Cost::Slow},
            {ProcessMemorySurvey, QStringLiteral("逐进程映像、线程入口与 VAD/PTE 交叉检查"), Cost::Slow},
            {KernelCodePages, QStringLiteral("内核映像可执行页与大池"), Cost::Slow},
            {KernelWorkItems, QStringLiteral("内核工作项与工作线程"), Cost::Moderate},
            {TimerRoutines, QStringLiteral("内核定时器 DPC 与模块归属"), Cost::Moderate},
        };
    }
    void CollectNativeMemory(ScanResult& result, const Stop& stop)
    {
        for (const auto& method : NativeMemoryMethods())
        {
            if (!(method.bit & result.selected)) continue;
            MethodReport report;
            report.method = method.bit;
            QElapsedTimer timer;
            timer.start();
            if (!stopped(stop))
            {
                if (method.bit == PhysicalPageOwners) physicalOwners(result, report, stop);
                else if (method.bit == ResidentMappings) residentMappings(result, report, stop);
                else if (method.bit == ProcessMemorySurvey) processMemory(result, report, stop);
                else if (method.bit == KernelCodePages) kernelPages(result, report);
                else if (method.bit == KernelWorkItems) workItems(result, report);
                else if (method.bit == TimerRoutines) timerRoutines(result, report);
            }
            if (stopped(stop)) report.status = Status::Cancelled;
            report.elapsedMs = timer.elapsed();
            result.reports.push_back(std::move(report));
        }
    }
}
