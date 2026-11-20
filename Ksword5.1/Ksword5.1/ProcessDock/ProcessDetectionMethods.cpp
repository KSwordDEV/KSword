#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include "ProcessDetectionMethods.h"
#include "ProcessResearchActivity.h"
#include "ProcessDetectionExtra.h"
#include "ProcessDetectionNativeMemory.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../ksword/file/file_handle_tools.h"
#include "../ksword/network/network_connection_tools.h"

#include <TlHelp32.h>
#include <QElapsedTimer>
#include <QFileInfo>
#include <QHash>
#include <QSet>
#include <QStringList>
#include <algorithm>
#include <memory>

namespace ksword::detection
{
    namespace
    {
        using Stop = std::function<bool()>;
        struct HandleCloser
        {
            void operator()(HANDLE handle) const
            {
                if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
            }
        };
        using Handle = std::unique_ptr<void, HandleCloser>;

        bool stopped(const Stop& stop) { return stop && stop(); }
        QString errorCode(DWORD error)
        {
            return QStringLiteral("Win32 %1").arg(error);
        }

        Evidence& append(ScanResult& result, MethodMask method, quint32 pid)
        {
            auto& row = result.evidence.emplaceBack();
            row.methods = method;
            row.pid = pid;
            return row;
        }

        struct ProcessNames
        {
            QHash<quint32, QString> names;
            DWORD error = ERROR_SUCCESS;
        };
        ProcessNames processSnapshot(const Stop& stop)
        {
            ProcessNames data;
            Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
            PROCESSENTRY32W entry{sizeof(entry)};
            if (snapshot.get() == INVALID_HANDLE_VALUE || !Process32FirstW(snapshot.get(), &entry))
            {
                data.error = GetLastError();
                return data;
            }
            do
            {
                if (stopped(stop)) { data.error = ERROR_CANCELLED; return data; }
                data.names.insert(entry.th32ProcessID, QString::fromWCharArray(entry.szExeFile));
            } while (Process32NextW(snapshot.get(), &entry));
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_FILES) data.error = error;
            return data;
        }

        void enumerateThreads(ScanResult& result, MethodReport& report, const Stop& stop)
        {
            Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0));
            THREADENTRY32 entry{sizeof(entry)};
            if (snapshot.get() == INVALID_HANDLE_VALUE || !Thread32First(snapshot.get(), &entry))
            {
                report.status = Status::Failed;
                report.detail = errorCode(GetLastError());
                return;
            }
            QHash<quint32, QPair<quint32, quint32>> owners;
            do
            {
                if (stopped(stop)) return;
                auto& owner = owners[entry.th32OwnerProcessID];
                if (owner.first == 0) owner.second = entry.th32ThreadID;
                ++owner.first;
                ++report.count;
            } while (Thread32Next(snapshot.get(), &entry));
            const DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_FILES)
            {
                report.status = Status::Partial;
                report.detail = errorCode(error);
            }
            for (auto it = owners.cbegin(); it != owners.cend(); ++it)
            {
                auto& row = append(result, report.method, it.key());
                row.detail = QStringLiteral("线程数 %1，示例 TID %2").arg(it->first).arg(it->second);
            }
        }

        struct WindowScan
        {
            const Stop& stop;
            QHash<quint32, QPair<quint32, quintptr>> owners;
            quint64 readFailures = 0;
        };
        BOOL CALLBACK collectWindow(HWND window, LPARAM param)
        {
            auto& scan = *reinterpret_cast<WindowScan*>(param);
            if (stopped(scan.stop)) return FALSE;
            DWORD pid = 0;
            if (!GetWindowThreadProcessId(window, &pid) || !pid) ++scan.readFailures;
            else
            {
                auto& owner = scan.owners[pid];
                if (owner.first == 0) owner.second = reinterpret_cast<quintptr>(window);
                ++owner.first;
            }
            return TRUE;
        }
        void enumerateWindows(ScanResult& result, MethodReport& report, const Stop& stop)
        {
            WindowScan scan{stop, {}, 0};
            if (!EnumWindows(collectWindow, reinterpret_cast<LPARAM>(&scan)))
            {
                report.status = scan.owners.isEmpty() ? Status::Failed : Status::Partial;
                report.detail = errorCode(GetLastError());
            }
            else if (scan.readFailures)
            {
                report.status = Status::Partial;
                report.detail = QStringLiteral("未取得所属 PID 的窗口数 %1").arg(scan.readFailures);
            }
            for (auto it = scan.owners.cbegin(); it != scan.owners.cend(); ++it)
            {
                auto& row = append(result, report.method, it.key());
                report.count += it->first;
                row.detail = QStringLiteral("桌面顶层窗口数 %1，示例 HWND 0x%2")
                    .arg(it->first).arg(it->second, 0, 16);
            }
        }

        void enumerateNetwork(ScanResult& result, MethodReport& report, const Stop& stop)
        {
            std::vector<ks::network::TcpConnectionRecord> tcp;
            std::vector<ks::network::UdpEndpointRecord> udp;
            std::string tcpError, udpError;
            const bool tcpOk = ks::network::EnumerateTcpConnectionRecords(tcp, &tcpError, false);
            if (stopped(stop)) return;
            const bool udpOk = ks::network::EnumerateUdpEndpointRecords(udp, &udpError, false);
            QHash<quint32, QPair<quint32, quint32>> counts;
            for (const auto& item : tcp) if (item.processId) ++counts[item.processId].first;
            for (const auto& item : udp) if (item.processId) ++counts[item.processId].second;
            for (auto it = counts.cbegin(); it != counts.cend(); ++it)
            {
                auto& row = append(result, report.method, it.key());
                row.detail = QStringLiteral("TCP %1 / UDP %2").arg(it->first).arg(it->second);
                report.count += it->first + it->second;
            }
            if (!tcpOk && !udpOk) report.status = Status::Failed;
            else if (!tcpError.empty() || !udpError.empty()) report.status = Status::Partial;
            QStringList diagnostics;
            if (!tcpError.empty()) diagnostics << QString::fromStdString(tcpError);
            if (!udpError.empty()) diagnostics << QString::fromStdString(udpError);
            report.detail = diagnostics.join(QChar::LineFeed);
        }

        QString processPath(HANDLE handle)
        {
            wchar_t buffer[32768];
            DWORD size = static_cast<DWORD>(std::size(buffer));
            return QueryFullProcessImageNameW(handle, 0, buffer, &size)
                ? QString::fromWCharArray(buffer, static_cast<int>(size)) : QString();
        }
        quint64 filetime(const FILETIME& value)
        {
            return (quint64(value.dwHighDateTime) << 32) | value.dwLowDateTime;
        }

        void corroborateLiveIdentities(ScanResult& result, quint64 started, const Stop& stop)
        {
            constexpr MethodMask pidSources = ProcessBaseline | ThreadOwners | DesktopWindows | NetworkEndpoints;
            if (!(result.selected & pidSources)) return;
            QElapsedTimer timer;
            timer.start();
            QHash<quint32, quint64> times;
            quint64 verified = 0;
            for (auto& row : result.evidence)
            {
                if (stopped(stop)) return;
                if (!row.pid || !(row.methods & pidSources) || row.historical || !row.scope.isEmpty()) continue;
                auto known = times.constFind(row.pid);
                if (known != times.cend()) { row.creationTime100ns = known.value(); continue; }
                // This process must have existed during the complete PID observation window.
                // An object created after the first snapshot cannot corroborate a reused PID.
                Handle owner(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, row.pid));
                FILETIME create{}, exit{}, kernel{}, user{};
                if (owner && GetProcessId(owner.get()) == row.pid &&
                    GetProcessTimes(owner.get(), &create, &exit, &kernel, &user) &&
                    filetime(create) && filetime(create) <= started &&
                    WaitForSingleObject(owner.get(), 0) == WAIT_TIMEOUT)
                {
                    row.creationTime100ns = filetime(create);
                    ++verified;
                }
                times.insert(row.pid, row.creationTime100ns);
            }
            const auto detail = QStringLiteral("共享 PID 身份核验 %1 ms，已核实 %2/%3")
                .arg(timer.elapsed()).arg(verified).arg(times.size());
            for (auto& report : result.reports)
            {
                if (!(report.method & pidSources) || report.status == Status::Failed ||
                    report.status == Status::Cancelled || report.status == Status::Unavailable) continue;
                if (!report.detail.isEmpty()) report.detail += QChar::LineFeed;
                report.detail += detail;
            }
        }

        struct HandleSnapshot
        {
            std::vector<ks::file::RawSystemHandle> rows;
            quint16 processType = 0;
            QString diagnostic;
        };
        HandleSnapshot systemHandles(const Stop& stop)
        {
            HandleSnapshot snapshot;
            // Discover the process type on this boot through our own known handle.
            Handle marker(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId()));
            if (!marker)
            {
                snapshot.diagnostic = errorCode(GetLastError());
                return snapshot;
            }
            std::wstring diagnostic;
            const bool ok = ks::file::QuerySystemHandles(ks::file::QueryNtApis(), snapshot.rows, diagnostic, stop);
            snapshot.diagnostic = QString::fromStdWString(diagnostic);
            if (!ok) return snapshot;
            for (const auto& entry : snapshot.rows)
            {
                if (entry.processId == GetCurrentProcessId() &&
                    entry.handleValue == reinterpret_cast<quintptr>(marker.get()))
                {
                    snapshot.processType = entry.typeIndex;
                    break;
                }
            }
            if (!snapshot.processType)
                snapshot.diagnostic = QStringLiteral("系统句柄快照未包含用于确认 Process 类型的本进程句柄。");
            else
            {
                // The marker is an implementation detail, never process-handle evidence.
                std::erase_if(snapshot.rows, [&](const auto& entry) {
                    return entry.typeIndex != snapshot.processType ||
                        (entry.processId == GetCurrentProcessId() &&
                         entry.handleValue == reinterpret_cast<quintptr>(marker.get()));
                });
            }
            return snapshot;
        }

        void enumerateHandles(ScanResult& result, MethodReport& report, const Stop& stop,
            const HandleSnapshot& snapshot, const QSet<quint32>& csrss)
        {
            if (!snapshot.processType)
            {
                report.status = Status::Failed;
                report.detail = snapshot.diagnostic;
                return;
            }
            const bool csrssOnly = report.method == CsrssHandles;
            if (csrssOnly && csrss.isEmpty())
            {
                report.status = Status::Unavailable;
                report.detail = QStringLiteral("未能识别可供查询的 CSRSS 进程。");
                return;
            }
            std::unordered_map<DWORD, Handle> ownerHandles;
            QHash<QPair<quint32, quint64>, qsizetype> evidenceRows;
            quint64 unreadable = 0, candidates = 0, lifetimeUnknown = 0;
            for (const auto& source : snapshot.rows)
            {
                if (stopped(stop)) return;
                if (csrssOnly && !csrss.contains(source.processId)) continue;
                ++candidates;
                const auto [it, inserted] = ownerHandles.try_emplace(source.processId);
                if (inserted)
                {
                    DWORD access = PROCESS_DUP_HANDLE;
                    if (csrssOnly) access |= PROCESS_QUERY_LIMITED_INFORMATION;
                    it->second.reset(OpenProcess(access, FALSE, source.processId));
                    if (csrssOnly && it->second)
                    {
                        wchar_t systemDir[MAX_PATH] = {};
                        const UINT length = GetSystemDirectoryW(systemDir, MAX_PATH);
                        const auto expected = QString::fromWCharArray(systemDir) + QStringLiteral("\\csrss.exe");
                        if (!length || length >= MAX_PATH ||
                            processPath(it->second.get()).compare(expected, Qt::CaseInsensitive) != 0)
                            it->second.reset();
                    }
                }
                HANDLE raw = nullptr;
                const HANDLE value = reinterpret_cast<HANDLE>(static_cast<quintptr>(source.handleValue));
                const bool waitable = it->second && DuplicateHandle(it->second.get(), value, GetCurrentProcess(),
                    &raw, PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, 0);
                if (!waitable && (!it->second || !DuplicateHandle(it->second.get(), value, GetCurrentProcess(),
                    &raw, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)))
                {
                    ++unreadable;
                    continue;
                }
                Handle target(raw);
                const DWORD pid = GetProcessId(target.get());
                FILETIME create{}, exit{}, kernel{}, user{};
                if (!pid || !GetProcessTimes(target.get(), &create, &exit, &kernel, &user))
                {
                    ++unreadable;
                    continue;
                }
                ++report.count;
                // GetProcessTimes does not define its exit output on a live process.
                const DWORD wait = waitable ? WaitForSingleObject(target.get(), 0) : WAIT_FAILED;
                if (wait != WAIT_OBJECT_0 && wait != WAIT_TIMEOUT) ++lifetimeUnknown;
                const QPair<quint32, quint64> identity(pid, filetime(create));
                auto seen = evidenceRows.constFind(identity);
                const bool first = seen == evidenceRows.cend();
                if (first)
                {
                    evidenceRows.insert(identity, result.evidence.size());
                    auto& row = append(result, report.method, pid);
                    row.creationTime100ns = identity.second;
                    row.lifetimeUnknown = true;
                    row.image = processPath(target.get());
                    row.detail = QStringLiteral("持有者 PID %1，句柄 0x%2")
                        .arg(source.processId).arg(source.handleValue, 0, 16);
                    // A source handle value may have been recycled since the snapshot.
                    // Identity above is from the duplicate; do not attribute a stale kernel address.
                }
                auto& observed = first ? result.evidence.back() : result.evidence[seen.value()];
                if (wait == WAIT_OBJECT_0) { observed.historical = true; observed.lifetimeUnknown = false; }
                else if (wait == WAIT_TIMEOUT) observed.lifetimeUnknown = false;
                if (observed.lifetimeUnknown) observed.category = QStringLiteral("存续状态未核实的进程句柄");
                else observed.category.clear();
            }
            if (!snapshot.diagnostic.isEmpty() || unreadable || lifetimeUnknown)
            {
                report.status = candidates && unreadable == candidates ? Status::Unavailable : Status::Partial;
                report.detail = QStringLiteral("候选句柄 %1，可读 %2，无法核实目标 %3，未取得存续状态 %4")
                    .arg(candidates).arg(report.count).arg(unreadable).arg(lifetimeUnknown);
                if (!snapshot.diagnostic.isEmpty()) report.detail += QChar::LineFeed + snapshot.diagnostic;
            }
        }

        void callbackHistory(ScanResult& result, MethodReport& report, const Stop& stop)
        {
            const ark::DriverClient client;
            const auto state = client.queryCallbackMonitorStatus();
            report.capturedCategories = state.registeredCategoryMask & state.categoryMask;
            if (!(state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING) ||
                (state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_STOPPING))
                report.capturedCategories = 0;
            if ((report.capturedCategories & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS) &&
                (state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_SUBSYSTEM_NOTIFY))
                report.capturedCategories |= SubsystemCreationCapture;
            constexpr ULONG relevant = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_ALL;
            if (!state.io.ok || (!(state.categoryMask & relevant) && !state.queuedCount))
            {
                report.status = Status::Unavailable;
                report.detail = state.io.ok ? QStringLiteral("内核回调监控未提供进程相关记录。")
                    : QString::fromStdString(state.io.message);
                return;
            }
            const auto end = state.latestSequence;
            std::uint64_t cursor = end > state.queuedCount ? end - state.queuedCount : 0;
            bool incomplete = state.droppedCount != 0 ||
                cursor != 0 || !(state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING);
            while (cursor < end)
            {
                if (stopped(stop)) return;
                const auto batch = client.readCallbackMonitor(cursor, KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
                if (!batch.io.ok)
                {
                    report.status = report.count ? Status::Partial : Status::Failed;
                    report.detail = QString::fromStdString(batch.io.message);
                    return;
                }
                incomplete |= batch.lostBeforeFirst || batch.droppedCount ||
                    (batch.responseFlags & KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE) != 0;
                for (const auto& entry : batch.records)
                {
                    if (entry.sequence > end) break;
                    const bool ioActivity = entry.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY ||
                        entry.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
                    const quint32 pid = ioActivity ? entry.originatingProcessId : entry.targetProcessId;
                    if (!(entry.category & relevant) || !pid) continue;
                    auto& row = append(result, report.method, pid);
                    row.historical = true;
                    switch (entry.category)
                    {
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS:
                        row.researchId = (entry.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_SUBSYSTEM_CREATE) ? 32 : 31;
                        break;
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD: row.researchId = 33; break;
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE: row.researchId = 34; break;
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT: row.researchId = 35; break;
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY:
                    case KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER: row.researchId = 42; break;
                    }
                    if (ioActivity) row.image = QString::fromStdWString(entry.processName);
                    else if (entry.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS)
                        row.image = QString::fromStdWString(entry.path);
                    row.detail = QStringLiteral("序号 %1，FILETIME %2，类别 0x%3，操作 0x%4，发起 PID %5，目标 TID %6")
                        .arg(entry.sequence).arg(entry.timeUtc100ns).arg(entry.category, 0, 16)
                        .arg(entry.operation, 0, 16).arg(entry.originatingProcessId).arg(entry.targetThreadId);
                    if (!entry.path.empty()) row.detail += QChar::LineFeed + QString::fromStdWString(entry.path);
                    ++report.count;
                }
                if (batch.nextSequence <= cursor) { incomplete = true; break; }
                cursor = batch.nextSequence;
            }
            report.completeForCapturedCategories = !incomplete;
            if (incomplete || (report.capturedCategories & relevant) != relevant) report.status = Status::Partial;
            report.detail = QStringLiteral("回调类别 0x%1，保留记录 %2，最后序号 %3，累计丢弃 %4")
                .arg(state.categoryMask, 0, 16).arg(state.queuedCount).arg(end).arg(state.droppedCount);
        }

        struct KernelSource
        {
            MethodMask method;
            ULONG requestFlag;
            ULONG rowSource;
            quint64 capability;
        };
        constexpr KernelSource processSources[] {
            {ProcessCrossView, KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK,
                KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK, 0},
            {ActiveProcesses, KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_ACTIVE_LIST,
                KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST, KSW_CAP_PROCESS_LIST_FIELDS},
            {CidProcesses, KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_CID_TABLE,
                KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE, KSW_CAP_CID_TABLE_WALK},
        };
        constexpr KernelSource threadSources[] {
            {ThreadCrossView, KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK,
                KSWORD_ARK_CROSSVIEW_SOURCE_PUBLIC_WALK, 0},
            {LinkedThreads, KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_THREAD_LIST,
                KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST, KSW_CAP_THREAD_LIST_FIELDS},
            {CidThreads, KSWORD_ARK_THREAD_CROSSVIEW_FLAG_INCLUDE_CID_TABLE,
                KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE, KSW_CAP_CID_TABLE_WALK},
        };

        template<class Sources, class Query, class OptionalResult>
        void kernelScan(ScanResult& result, const Sources& sources, const Stop& stop,
            Query query, OptionalResult& output)
        {
            ULONG flags = 0;
            for (const auto& source : sources)
                if (result.selected & source.method) flags |= source.requestFlag;
            if (!flags) return;
            QElapsedTimer timer;
            timer.start();
            if (!stopped(stop)) output.emplace(query(flags));
            const qint64 duration = timer.elapsed();
            for (const auto& source : sources)
            {
                if (!(result.selected & source.method)) continue;
                MethodReport report;
                report.method = source.method;
                report.elapsedMs = duration;
                if (!output || stopped(stop)) report.status = Status::Cancelled;
                else
                {
                    const auto& response = *output;
                    report.count = std::count_if(response.entries.cbegin(), response.entries.cend(),
                        [&](const auto& row) { return (row.sourceMask & source.rowSource) != 0; });
                    if (!response.io.ok)
                    {
                        report.status = response.io.deviceOpenFailed || response.unsupported ?
                            Status::Unavailable : Status::Failed;
                        report.detail = QString::fromStdString(response.io.message);
                    }
                    else
                    {
                        if ((response.missingCapabilityMask & source.capability) ||
                            response.status == KSWORD_ARK_CROSSVIEW_STATUS_CAPABILITY_MISSING)
                            report.status = report.count ? Status::Partial : Status::Unavailable;
                        else if (response.status == KSWORD_ARK_CROSSVIEW_STATUS_PARTIAL ||
                            response.returnedCount < response.totalCount)
                            report.status = Status::Partial;
                        else if (response.status != KSWORD_ARK_CROSSVIEW_STATUS_OK)
                            report.status = report.count ? Status::Partial : Status::Failed;
                        report.detail = QStringLiteral("同组联合采集 %1 ms，返回 %2/%3，状态 %4，NTSTATUS 0x%5，缺失能力 0x%6")
                            .arg(duration).arg(response.returnedCount).arg(response.totalCount)
                            .arg(response.status).arg(static_cast<quint32>(response.lastStatus), 0, 16)
                            .arg(response.missingCapabilityMask, 0, 16);
                    }
                }
                result.reports.push_back(std::move(report));
            }
        }

        constexpr quint32 absenceFlags = KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY |
            KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY | KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST |
            KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE | KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST;
        template<class Result, class Row, class Sources>
        quint32 comparable(MethodMask selected, const Result& response, const Row& row,
            const Sources& sources, ULONG listSource, ULONG missingListFlag)
        {
            // Raw flags remain available in the protocol record. A missing side is only
            // interpretable when both that side and an observed peer were actually queried.
            quint32 flags = row.anomalyFlags & ~absenceFlags;
            if (!response || !response->io.ok || response->status != KSWORD_ARK_CROSSVIEW_STATUS_OK ||
                response->returnedCount != response->totalCount || row.denoiseFlags) return flags;
            ULONG expected = 0;
            for (const auto& source : sources)
                if ((selected & source.method) && !(response->missingCapabilityMask & source.capability))
                    expected |= source.rowSource;
            if ((expected & (expected - 1)) == 0) return flags;
            const ULONG observed = row.sourceMask & expected;
            if (!observed) return flags;
            constexpr ULONG cid = KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE;
            if ((expected & listSource) && !(observed & listSource))
                flags |= row.anomalyFlags & missingListFlag;
            if ((expected & cid) && !(observed & cid))
                flags |= row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_CID_TABLE;
            if (observed == cid)
                flags |= row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_CID_ONLY;
            if (observed == listSource)
                flags |= row.anomalyFlags & KSWORD_ARK_CROSSVIEW_ANOMALY_ACTIVE_ONLY;
            return flags;
        }
    }

    QVector<Method> Methods()
    {
        QVector<Method> methods {
            {ProcessBaseline, QStringLiteral("Toolhelp 进程快照"), Cost::Fast},
            {ThreadOwners, QStringLiteral("Toolhelp 线程所属进程"), Cost::Fast},
            {DesktopWindows, QStringLiteral("当前桌面窗口所属进程"), Cost::Fast},
            {NetworkEndpoints, QStringLiteral("TCP / UDP 端点所属进程"), Cost::Moderate},
            {ProcessCrossView, QStringLiteral("R0 公开进程枚举"), Cost::Moderate},
            {ActiveProcesses, QStringLiteral("R0 活动进程链表"), Cost::Moderate},
            {CidProcesses, QStringLiteral("R0 进程 CID 表"), Cost::Slow},
            {ThreadCrossView, QStringLiteral("R0 公开线程枚举与入口验证"), Cost::Slow},
            {LinkedThreads, QStringLiteral("R0 进程线程链表与入口验证"), Cost::Slow},
            {CidThreads, QStringLiteral("R0 线程 CID 表与入口验证"), Cost::Slow},
            {ProcessHandles, QStringLiteral("系统进程句柄反查"), Cost::Slow},
            {CsrssHandles, QStringLiteral("CSRSS 进程句柄反查"), Cost::Slow},
            {CallbackHistory, QStringLiteral("内核回调历史记录"), Cost::Moderate},
        };
        methods.append(NativeMemoryMethods());
        methods.append(ExtraMethods());
        return methods;
    }

    MethodMask Defaults(bool deep)
    {
        const MethodMask fast = ProcessBaseline | ThreadOwners | DesktopWindows;
        return deep ? fast | NetworkEndpoints | ProcessKernelMethods | ThreadKernelMethods |
            ProcessHandles | CallbackHistory : fast;
    }

    quint32 ComparableAnomalies(const ScanResult& result, const ark::ProcessCrossViewEntry& row)
    {
        return comparable(result.selected, result.processCrossView, row, processSources,
            KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST, KSWORD_ARK_CROSSVIEW_ANOMALY_MISSING_FROM_ACTIVE_LIST);
    }
    quint32 ComparableAnomalies(const ScanResult& result, const ark::ThreadCrossViewEntry& row)
    {
        return comparable(result.selected, result.threadCrossView, row, threadSources,
            KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST, KSWORD_ARK_CROSSVIEW_ANOMALY_THREAD_NOT_IN_PROCESS_LIST);
    }

    ScanResult Run(MethodMask selected, const Stop& stop, const ScanInputs& inputs)
    {
        ScanResult result;
        result.startedUtc = QDateTime::currentDateTimeUtc();
        FILETIME started{};
        GetSystemTimePreciseAsFileTime(&started);
        result.selected = selected;
        std::optional<ProcessNames> baseline;
        std::optional<HandleSnapshot> handleSnapshot;
        const auto collect = [&](MethodMask bit, auto operation)
        {
            if (!(selected & bit)) return;
            MethodReport report;
            report.method = bit;
            QElapsedTimer timer;
            timer.start();
            if (!stopped(stop)) operation(report);
            if (stopped(stop)) report.status = Status::Cancelled;
            report.elapsedMs = timer.elapsed();
            result.reports.push_back(std::move(report));
        };
        collect(ProcessBaseline, [&](MethodReport& report) {
            baseline = processSnapshot(stop);
            for (auto it = baseline->names.cbegin(); it != baseline->names.cend(); ++it)
                append(result, ProcessBaseline, it.key()).image = it.value();
            report.count = baseline->names.size();
            if (baseline->error)
            {
                report.status = report.count ? Status::Partial : Status::Failed;
                report.detail = errorCode(baseline->error);
            }
        });
        collect(ThreadOwners, [&](MethodReport& report) { enumerateThreads(result, report, stop); });
        collect(DesktopWindows, [&](MethodReport& report) { enumerateWindows(result, report, stop); });
        collect(NetworkEndpoints, [&](MethodReport& report) { enumerateNetwork(result, report, stop); });
        corroborateLiveIdentities(result, filetime(started), stop);
        const ark::DriverClient client;
        kernelScan(result, processSources, stop,
            [&](ULONG flags) { return client.queryProcessCrossView(flags); }, result.processCrossView);
        kernelScan(result, threadSources, stop, [&](ULONG flags) {
            return client.queryThreadCrossView(flags | KSWORD_ARK_THREAD_CROSSVIEW_FLAG_VALIDATE_START);
        }, result.threadCrossView);
        for (const MethodMask bit : {CsrssHandles, ProcessHandles})
        {
            collect(bit, [&](MethodReport& report) {
                QSet<quint32> csrss;
                if (bit == CsrssHandles)
                {
                    const auto names = baseline ? *baseline : processSnapshot(stop);
                    if (names.error)
                    {
                        report.status = Status::Failed;
                        report.detail = errorCode(names.error);
                        return;
                    }
                    for (auto it = names.names.cbegin(); it != names.names.cend(); ++it)
                        if (it.value().compare(QStringLiteral("csrss.exe"), Qt::CaseInsensitive) == 0)
                            csrss.insert(it.key());
                }
                if (!handleSnapshot) handleSnapshot = systemHandles(stop);
                enumerateHandles(result, report, stop, *handleSnapshot, csrss);
            });
        }
        collect(CallbackHistory, [&](MethodReport& report) { callbackHistory(result, report, stop); });
        CollectNativeMemory(result, stop);
        if (baseline && !baseline->error && !stopped(stop))
        {
            // Bracket local comparisons with a second snapshot. A PID that appeared during
            // collection is ordinary process churn; history and exited handles stay historical.
            const auto finished = processSnapshot(stop);
            if (!finished.error)
            {
                for (auto& row : result.evidence)
                {
                    row.absentFromBaseline = row.pid && !row.historical && !row.lifetimeUnknown && !baseline->names.contains(row.pid) &&
                        !finished.names.contains(row.pid);
                }
                QHash<QPair<quint32, quint64>, qsizetype> kernelOnly;
                const auto compareKernel = [&](const auto& entries, const auto& sources, auto processObject) {
                    for (const auto& entry : entries)
                    {
                        if (!entry.processId || baseline->names.contains(entry.processId) ||
                            finished.names.contains(entry.processId)) continue;
                        MethodMask methods = 0;
                        for (const auto& source : sources)
                            if ((selected & source.method) && (entry.sourceMask & source.rowSource))
                                methods |= source.method;
                        if (!methods) continue;
                        const quint64 object = processObject(entry);
                        const QPair<quint32, quint64> key(entry.processId, object);
                        const auto found = kernelOnly.constFind(key);
                        if (found != kernelOnly.cend())
                        {
                            result.evidence[found.value()].methods |= methods;
                            continue;
                        }
                        kernelOnly.insert(key, result.evidence.size());
                        auto& row = append(result, methods, entry.processId);
                        row.absentFromBaseline = true;
                        row.objectAddress = object;
                        row.image = QString::fromStdString(entry.imageName);
                        row.detail = QStringLiteral("两次 Toolhelp 进程快照均未列出此 PID。");
                    }
                };
                if (result.processCrossView) compareKernel(result.processCrossView->entries, processSources,
                    [](const auto& entry) { return entry.objectAddress; });
                if (result.threadCrossView) compareKernel(result.threadCrossView->entries, threadSources,
                    [](const auto& entry) { return entry.processObjectAddress; });
            }
            else
            {
                auto& report = result.reports.front(); // The selected baseline always runs first.
                report.status = Status::Partial;
                report.detail = QStringLiteral("结束快照失败，未计算实时来源差异。%1").arg(errorCode(finished.error));
            }
        }
        result.cancelled = stopped(stop);
        CollectExtraMethods(result, inputs, stop);
        result.cancelled |= stopped(stop);
        return result;
    }
}
