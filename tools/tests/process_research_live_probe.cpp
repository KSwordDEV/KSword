#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessResearchCatalog.h"
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessDetectionProfile.h"
#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QStringList>
#include <QScopeGuard>

#include <iostream>

namespace
{
    using namespace ksword::detection;

    QString statusName(Status status)
    {
        switch (status)
        {
        case Status::Complete: return QStringLiteral("complete");
        case Status::Partial: return QStringLiteral("partial");
        case Status::Unavailable: return QStringLiteral("unavailable");
        case Status::Failed: return QStringLiteral("failed");
        case Status::Cancelled: return QStringLiteral("cancelled");
        }
        return QStringLiteral("unknown");
    }

    void emitJson(const QJsonObject& object)
    {
        std::cout << QJsonDocument(object).toJson(QJsonDocument::Compact).constData() << '\n' << std::flush;
    }

    struct CallbackActions
    {
        QString marker;
        DWORD object = ERROR_NOT_SUPPORTED, registry = ERROR_NOT_SUPPORTED, file = ERROR_NOT_SUPPORTED;
        DWORD registryCleanup = ERROR_SUCCESS, fileCleanup = ERROR_SUCCESS;
    };

    CallbackActions captureTestOperations(ULONG enabled, quint64 sequence)
    {
        CallbackActions result;
        result.marker = QStringLiteral("KSwordCallbackProbe-%1-%2").arg(GetCurrentProcessId()).arg(sequence);
        if (enabled & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)
        {
            HANDLE self = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
            result.object = self ? ERROR_SUCCESS : GetLastError();
            if (self) CloseHandle(self);
        }
        if (enabled & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY)
        {
            const auto path = (QStringLiteral("Software\\") + result.marker).toStdWString();
            HKEY key = nullptr; DWORD disposition = 0;
            result.registry = RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, REG_OPTION_VOLATILE,
                KEY_SET_VALUE | KEY_QUERY_VALUE, nullptr, &key, &disposition);
            if (result.registry == ERROR_SUCCESS)
            {
                if (disposition != REG_CREATED_NEW_KEY) { result.registry = ERROR_ALREADY_EXISTS; RegCloseKey(key); }
                else
                {
                    const DWORD value = GetCurrentProcessId();
                    result.registry = RegSetValueExW(key, L"ProbePid", 0, REG_DWORD,
                        reinterpret_cast<const BYTE*>(&value), sizeof(value));
                    RegCloseKey(key);
                    result.registryCleanup = RegDeleteKeyW(HKEY_CURRENT_USER, path.c_str());
                }
            }
        }
        if (enabled & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
        {
            const auto path = QDir::toNativeSeparators(QDir(QCoreApplication::applicationDirPath())
                .filePath(result.marker + QStringLiteral(".tmp"))).toStdWString();
            HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr);
            if (file == INVALID_HANDLE_VALUE) result.file = GetLastError();
            else
            {
                const DWORD payload = GetCurrentProcessId();
                DWORD written = 0;
                result.file = WriteFile(file, &payload, sizeof(payload), &written, nullptr) ?
                    (written == sizeof(payload) ? ERROR_SUCCESS : ERROR_WRITE_FAULT) : GetLastError();
                if (!CloseHandle(file)) result.fileCleanup = GetLastError();
                else if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
                    result.fileCleanup = ERROR_FILE_EXISTS;
                else if (GetLastError() != ERROR_FILE_NOT_FOUND) result.fileCleanup = GetLastError();
            }
        }
        return result;
    }

    int callbackWindow()
    {
        using namespace ksword::ark;
        constexpr ULONG ordinary = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS | KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD |
            KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE;
        constexpr ULONG supplemental = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT | KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY |
            KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER;
        const DriverClient client;
        auto state = client.queryCallbackMonitorStatus();
        const auto describe = [&](const char* step, const CallbackMonitorStatusResult& value) {
            emitJson({{"event", step}, {"ok", value.io.ok}, {"win32", static_cast<qint64>(value.io.win32Error)},
                {"last_status", static_cast<qint64>(value.lastStatus)}, {"flags", static_cast<qint64>(value.runtimeFlags)},
                {"mask", static_cast<qint64>(value.categoryMask)}, {"registered", static_cast<qint64>(value.registeredCategoryMask)},
                {"queued", static_cast<qint64>(value.queuedCount)},
                {"ex2", bool(value.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_SUBSYSTEM_NOTIFY)}});
        };
        describe("callback_before", state);
        if (!state.io.ok || (state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_STOPPING)) return 4;
        const ULONG mask = ordinary | (state.registeredCategoryMask & supplemental);
        bool owned = false;
        const auto stopOwned = [&] {
            if (!owned) return true;
            const auto current = client.queryCallbackMonitorStatus();
            if (!current.io.ok) { describe("callback_stop_check_failed", current); return false; }
            if (current.categoryMask != mask || !(current.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING))
            {
                owned = false;
                describe("callback_ownership_changed", current);
                return current.categoryMask == 0;
            }
            const auto stopped = client.controlCallbackMonitor(KSWORD_ARK_CALLBACK_MONITOR_ACTION_STOP, 0);
            describe("callback_stop", stopped);
            owned = !stopped.io.ok || stopped.lastStatus < 0 || stopped.categoryMask != 0;
            return !owned;
        };
        const auto cleanup = qScopeGuard([&] { if (owned) stopOwned(); });
        if (!state.categoryMask && !(state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING))
        {
            // START on an idle driver resets the ring. Preserve any previous session's retained evidence.
            if (state.queuedCount || state.latestSequence)
            {
                emitJson({{"event","callback_retained_history"}, {"queued",static_cast<qint64>(state.queuedCount)}});
                return 4;
            }
            state = client.controlCallbackMonitor(KSWORD_ARK_CALLBACK_MONITOR_ACTION_START, mask);
            owned = state.io.ok && state.lastStatus >= 0 && state.categoryMask == mask &&
                (state.runtimeFlags & KSWORD_ARK_CALLBACK_MONITOR_RUNTIME_CAPTURING);
            describe("callback_start", state);
            if (!owned) return 4;
        }
        const auto begin = state.latestSequence;
        const auto executable = QDir::toNativeSeparators(QCoreApplication::applicationFilePath()).toStdWString();
        auto command = L"\"" + executable + L"\" --probe-child-exit";
        STARTUPINFOW start{}; start.cb = sizeof(start);
        PROCESS_INFORMATION child{};
        if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
            nullptr, nullptr, &start, &child))
        { emitJson({{"event","child_start_failed"},{"win32",static_cast<qint64>(GetLastError())}}); return 5; }
        const auto closeChild = qScopeGuard([&] { CloseHandle(child.hThread); CloseHandle(child.hProcess); });
        DWORD exitCode = STILL_ACTIVE;
        if (WaitForSingleObject(child.hProcess, 15000) != WAIT_OBJECT_0 || !GetExitCodeProcess(child.hProcess, &exitCode) || exitCode)
        { emitJson({{"event","child_exit_failed"},{"child",static_cast<qint64>(child.dwProcessId)},{"exit",static_cast<qint64>(exitCode)}}); return 5; }
        // Keep the signaled process handle until the end to protect the child PID against reuse.
        const auto enabled = state.categoryMask & state.registeredCategoryMask;
        const auto actions = captureTestOperations(enabled, begin);
        emitJson({{"event","callback_test_operations"},{"marker",actions.marker},
            {"object_registered",bool(state.registeredCategoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT)},
            {"registry_registered",bool(state.registeredCategoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY)},
            {"file_registered",bool(state.registeredCategoryMask & KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)},
            {"enabled_mask",qint64(enabled)},{"self_open_win32",qint64(actions.object)},{"registry_win32",qint64(actions.registry)},
            {"file_win32",qint64(actions.file)},{"registry_cleanup",qint64(actions.registryCleanup)},{"file_cleanup",qint64(actions.fileCleanup)}});
        DetectionSelection selection;
        for (int id : {31,32,33,34,35,42}) selection.research.set(id-1);
        const auto scan = RunSelected(selection);
        ResearchSet received;
        for (const auto& report : scan.reports)
        {
            if (report.researchId < 1 || report.researchId > ResearchCount || !selection.research.test(report.researchId-1)) continue;
            received.set(report.researchId-1);
            int childRows = 0, selfRows = 0, markerRows = 0;
            for (const auto& row : scan.evidence)
            {
                if (!row.researchPoints.test(report.researchId-1)) continue;
                if (row.pid == child.dwProcessId) ++childRows;
                if (row.pid == GetCurrentProcessId())
                { ++selfRows; if (row.detail.contains(actions.marker, Qt::CaseInsensitive)) ++markerRows; }
            }
            emitJson({{"event","callback_method"},{"id",report.researchId},{"status",statusName(report.status)},
                {"count",static_cast<qint64>(report.count)},{"child_rows",childRows},{"self_rows",selfRows},
                {"marker_rows",markerRows},{"elapsed_ms",report.elapsedMs},{"detail",report.detail}});
        }
        const auto after = client.queryCallbackMonitorStatus();
        describe("callback_after",after);
        quint64 cursor = begin, creates = 0, threadRows = 0, imageRows = 0, subsystem = 0, childSubsystem = 0;
        quint64 selfObject = 0, markedRegistry = 0, markedFile = 0;
        bool intact = after.io.ok && after.latestSequence >= begin && after.droppedCount == state.droppedCount;
        while (after.io.ok && cursor < after.latestSequence)
        {
            const auto batch = client.readCallbackMonitor(cursor, KSWORD_ARK_CALLBACK_MONITOR_MAX_READ_RECORDS);
            if (!batch.io.ok || batch.nextSequence <= cursor) { intact = false; break; }
            if (batch.lostBeforeFirst || (batch.responseFlags & KSWORD_ARK_CALLBACK_MONITOR_READ_FLAG_SNAPSHOT_RACE)) intact = false;
            for (const auto& row : batch.records)
            {
                if (row.sequence <= begin || row.sequence > after.latestSequence) continue;
                const bool isChild = row.targetProcessId == child.dwProcessId;
                if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_PROCESS && row.operation == KSWORD_ARK_PROCESS_OP_CREATE)
                {
                    creates += isChild;
                    if (row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_SUBSYSTEM_CREATE)
                    { ++subsystem; childSubsystem += isChild; }
                }
                else if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD) threadRows += isChild;
                else if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_IMAGE) imageRows += isChild;
                else if (row.originatingProcessId == GetCurrentProcessId())
                {
                    if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_OBJECT && row.targetProcessId == GetCurrentProcessId() &&
                        !(row.flags & KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_OBJECT_THREAD)) ++selfObject;
                    else if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY ||
                        row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_MINIFILTER)
                    {
                        if (!QString::fromStdWString(row.path).contains(actions.marker, Qt::CaseInsensitive)) continue;
                        if (row.category == KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_REGISTRY) ++markedRegistry;
                        else ++markedFile;
                    }
                }
            }
            cursor = batch.nextSequence;
        }
        emitJson({{"event","callback_window"},{"started_by_probe",owned},{"child",static_cast<qint64>(child.dwProcessId)},
            {"from",static_cast<qint64>(begin)},{"to",static_cast<qint64>(after.latestSequence)},{"intact",intact},
            {"child_creates",static_cast<qint64>(creates)},{"child_threads",static_cast<qint64>(threadRows)},
            {"child_images",static_cast<qint64>(imageRows)},{"subsystem_creates",static_cast<qint64>(subsystem)},
            {"child_subsystem_creates",static_cast<qint64>(childSubsystem)},{"self_object",qint64(selfObject)},
            {"marked_registry",qint64(markedRegistry)},{"marked_file",qint64(markedFile)}});
        return stopOwned() && received == selection.research && !actions.registryCleanup && !actions.fileCleanup ? 0 : 6;
    }

    bool readInputs(const QString& path, ScanInputs& inputs)
    {
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly) || file.size() > 128 * 1024) return false;
        const auto json = QJsonDocument::fromJson(file.readAll());
        if (!json.isObject()) return false;
        struct Key { const char* name; QString ScanInputs::*field; };
        static const Key keys[] = {
            {"memoryImage", &ScanInputs::memoryImage}, {"volatilityProgram", &ScanInputs::volatilityProgram},
            {"memProcFsRoot", &ScanInputs::memProcFsRoot}, {"eventTraceFile", &ScanInputs::eventTraceFile},
            {"flatPhysicalImage", &ScanInputs::flatPhysicalImage}, {"guestProcessFile", &ScanInputs::guestProcessFile},
            {"processorTraceFile", &ScanInputs::processorTraceFile}, {"processorTraceTool", &ScanInputs::processorTraceTool},
            {"xenTraceFile", &ScanInputs::xenTraceFile}, {"debuggerProgram", &ScanInputs::debuggerProgram},
            {"debuggerTarget", &ScanInputs::debuggerTarget}, {"memProcFsLibrary", &ScanInputs::memProcFsLibrary},
            {"vmiMountRoot", &ScanInputs::vmiMountRoot}, {"dmaMountRoot", &ScanInputs::dmaMountRoot},
            {"hypervSavedState", &ScanInputs::hypervSavedState}, {"vmwareProcessId", &ScanInputs::vmwareProcessId}
        };
        auto pending = json.object();
        for (const auto& key : keys)
        {
            const auto value = pending.take(QString::fromLatin1(key.name));
            if (value.isUndefined()) continue;
            if (!value.isString()) return false;
            inputs.*key.field = value.toString();
        }
        return pending.isEmpty();
    }

    bool run(const DetectionSelection& selection, const ScanInputs& inputs, qint64 timeout)
    {
        QElapsedTimer clock; clock.start();
        QJsonObject started{{"event", "start"}, {"selection_count", static_cast<int>(selection.research.count())}};
        if (selection.research.count() == 1)
            for (const auto& point : ResearchCatalog())
                if (selection.research.test(point.id - 1)) { started.insert("id", point.id); break; }
        emitJson(started);
        const auto result = RunSelected(selection, [&] { return timeout && clock.elapsed() >= timeout; }, inputs);
        ResearchSet received;
        bool valid = true;
        for (const auto& report : result.reports)
        {
            const int id = report.researchId;
            if (id < 1 || id > ResearchCount || !selection.research.test(id-1) || received.test(id-1))
            { valid = false; continue; }
            received.set(id-1);
            emitJson({{"event", "method"}, {"id", id}, {"name", ResearchCatalog()[id-1].name},
                {"status", statusName(report.status)}, {"count", static_cast<qint64>(report.count)},
                {"elapsed_ms", report.elapsedMs}, {"detail", report.detail}});
        }
        valid &= received == selection.research;
        emitJson({{"event", "finish"}, {"valid", valid}, {"elapsed_ms", clock.elapsed()},
            {"started_utc", result.startedUtc.toString(Qt::ISODateWithMs)}, {"cancelled", result.cancelled},
            {"evidence_rows", result.evidence.size()}, {"reports", static_cast<int>(received.count())}});
        return valid;
    }

    int knownObject()
    {
        const auto pid = GetCurrentProcessId(), tid = GetCurrentThreadId();
        DetectionSelection selection;
        for (const int id : {1,4,7}) selection.research.set(id - 1);
        const auto result = RunSelected(selection);
        bool valid = true;
        for (const auto& receipt : result.reports)
        {
            const int id = receipt.researchId;
            const bool thread = id == 7;
            const ULONG source = id == 1 ? KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST :
                thread ? KSWORD_ARK_CROSSVIEW_SOURCE_THREAD_LIST : KSWORD_ARK_CROSSVIEW_SOURCE_CID_TABLE;
            auto emitRows = [&](const auto& response, auto matches) {
                quint64 sourceRows = 0, identityRows = 0;
                quint32 sourceMask = 0;
                if (response && response->io.ok)
                    for (const auto& row : response->entries)
                    {
                        if (!(row.sourceMask & source)) continue;
                        ++sourceRows;
                        if (!row.objectAddress || !matches(row)) continue;
                        ++identityRows;
                        sourceMask |= row.sourceMask;
                    }
                emitJson({{"event","known_object"},{"id",id},{"status",statusName(receipt.status)},
                    {"pid",static_cast<qint64>(pid)},{"tid",static_cast<qint64>(tid)},
                    {"expected_source",static_cast<qint64>(source)},{"matched_mask",static_cast<qint64>(sourceMask)},
                    {"source_rows",static_cast<qint64>(sourceRows)},{"identity_rows",static_cast<qint64>(identityRows)},
                    {"found",identityRows > 0},{"returned",response ? qint64(response->returnedCount) : 0},
                    {"total",response ? qint64(response->totalCount) : 0},{"detail",receipt.detail}});
                valid &= identityRows != 0;
            };
            if (thread) emitRows(result.threadCrossView, [&](const auto& r) {
                return r.processId == pid && r.threadId == tid && r.threadListProcessId == pid && r.threadListThreadId == tid;
            });
            else emitRows(result.processCrossView, [&](const auto& r) {
                return r.processId == pid && (id == 1 ? r.activeListProcessId : r.cidTableProcessId) == pid;
            });
        }
        if (result.processCrossView && result.processCrossView->io.ok)
        {
            int shown = 0;
            for (const auto& row : result.processCrossView->entries)
            {
                if (row.sourceMask != KSWORD_ARK_CROSSVIEW_SOURCE_ACTIVE_LIST ||
                    (row.processId && row.activeListProcessId && row.activeListStatus >= 0 && row.lastStatus >= 0 &&
                     !(row.denoiseFlags & KSWORD_ARK_CROSSVIEW_DENOISE_REFERENCE_FAILURE))) continue;
                emitJson({{"event","active_reference_gap"},{"source",qint64(row.sourceMask)},{"pid",qint64(row.processId)},
                    {"active_pid",qint64(row.activeListProcessId)},{"object",QString::number(row.objectAddress,16)},
                    {"active_status",qint64(row.activeListStatus)},{"last_status",qint64(row.lastStatus)},
                    {"detail_status",qint64(row.detailStatus)},{"anomalies",qint64(row.anomalyFlags)},
                    {"denoise_flags",qint64(row.denoiseFlags)},{"detail",QString::fromStdString(row.detail).left(512)}});
                if (++shown == 4) break;
            }
        }
        return valid && result.reports.size() == 3 ? 0 : 7;
    }
}

int main(int argc, char** argv)
{
    using namespace ksword::detection;
    QCoreApplication app(argc, argv);
    const auto args = app.arguments();
    if (args.size() == 2 && args[1] == QStringLiteral("--probe-child-exit")) return 0;
    if (args.size() == 2 && args[1] == QStringLiteral("--callback-window")) return callbackWindow();
    if (args.size() == 2 && args[1] == QStringLiteral("--known-object")) return knownObject();
    if ((args.size() == 2 || args.size() == 3) && args[1] == QStringLiteral("--prepare-readonly-layout"))
    {
        ResearchSet selected;
        for (const int id : {1,7,27}) selected.set(id-1);
        const auto detail = PrepareDetectionLayout(selected, args.value(2));
        const bool verified = VerifyPreparedDetectionLayout(selected);
        emitJson({{"event","readonly_layout"},{"verified",verified},{"detail",detail}});
        return verified ? 0 : 4;
    }
    DetectionSelection selection;
    ScanInputs inputs;
    bool each = false;
    qint64 timeout = 0;
    for (qsizetype i = 1; i < args.size(); ++i)
    {
        const auto arg = args.at(i);
        if ((arg == QStringLiteral("--all") || arg == QStringLiteral("--each")) && selection.empty())
        {
            each = arg == QStringLiteral("--each");
            selection.research.set();
        }
        else if (arg == QStringLiteral("--method") && i + 1 < args.size() && selection.empty())
        {
            bool ok = false;
            const int id = args.at(++i).toInt(&ok);
            if (!ok || id < 1 || id > ResearchCount) return 2;
            selection.research.set(id - 1);
        }
        else if (arg == QStringLiteral("--inputs") && i + 1 < args.size())
        {
            if (!readInputs(args.at(++i), inputs)) { std::cerr << "Invalid input file.\n"; return 2; }
        }
        else if (arg == QStringLiteral("--timeout-ms") && i + 1 < args.size())
        {
            bool ok = false; timeout = args.at(++i).toLongLong(&ok);
            if (!ok || timeout < 0) return 2;
        }
        else { std::cerr << "Unknown or repeated option.\n"; return 2; }
    }
    if (selection.empty())
    {
        std::cerr << "process_research_live_probe (--method 1..66 | --all | --each) [--inputs inputs.json] [--timeout-ms n]\n";
        return 2;
    }
    if (!each) return run(selection, inputs, timeout) ? 0 : 3;
    bool valid = true;
    for (int id = 1; id <= ResearchCount; ++id)
    {
        DetectionSelection single;
        single.research.set(id-1);
        valid &= run(single, inputs, timeout);
    }
    return valid ? 0 : 3;
}
