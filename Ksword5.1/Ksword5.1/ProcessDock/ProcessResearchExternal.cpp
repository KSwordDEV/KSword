#include "ProcessResearchExternal.h"
#include "ProcessResearchSavedState.h"
#include <QSet>
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../../../shared/usermode/backend/driver/DriverQueries.h"
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QProcess>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QSet>
#include <QStringDecoder>
#include <QTimeZone>
#include <QtEndian>
#include <TlHelp32.h>
#include <shellapi.h>
#include <winternl.h>
#include <vmsavedstatedump.h>
#include <DbgEng.h>
#include <wrl/client.h>
#include <algorithm>
#include <bit>
#include <memory>
#include <vector>

namespace ksword::detection
{
    namespace
    {
        constexpr qsizetype limit = 16384;
        using Microsoft::WRL::ComPtr;
        bool cancelled(const CancelCheck& stop) { return stop && stop(); }
        void unavailable(MethodReport& r, const QString& reason) { r.status = Status::Unavailable; r.detail = reason; }
        QString hex(quint64 n) { return QStringLiteral("0x%1").arg(n, 0, 16); }
        QString code(HRESULT status) { return hex(static_cast<quint32>(status)); }
        QString localFile(const QString& path)
        {
            const QFileInfo file(path);
            if (!file.isAbsolute() || !file.isFile()) return {};
            return file.canonicalFilePath();
        }
        struct Library
        {
            HMODULE handle = nullptr;
            DWORD loadError = ERROR_INVALID_NAME;
            explicit Library(const QString& path)
            {
                const auto canonical = localFile(path);
                if (canonical.isEmpty() || canonical.startsWith(QStringLiteral("//"))) return;
                const auto native = QDir::toNativeSeparators(canonical);
                handle = LoadLibraryExW(reinterpret_cast<LPCWSTR>(native.utf16()), nullptr,
                    LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
                loadError = handle ? ERROR_SUCCESS : GetLastError();
            }
            ~Library() { if (handle) FreeLibrary(handle); }
            Library(const Library&) = delete;
            template<class T> T get(const char* name) const
            {
                return handle ? std::bit_cast<T>(GetProcAddress(handle, name)) : nullptr;
            }
        };

        Evidence& observation(ScanResult& scan, MethodReport& report, const QString& scope, const QString& kind)
        {
            ++report.count;
            auto& row = scan.evidence.emplaceBack();
            row.scope = scope;
            row.category = kind;
            return row;
        }

        void hvm(int id, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const ark::DriverClient client;
            if (!scan.researchHvmEvents)
                scan.researchHvmEvents = std::make_shared<ark::HvmEventResult>(client.queryHvmEvents(0, KSWORD_ARK_HVM_MAX_EVENT_ROWS, false));
            const auto& batch = *scan.researchHvmEvents;
            if (!batch.io.ok) { unavailable(report, QString::fromStdString(batch.io.message)); return; }
            const auto& events = batch.response;
            const auto size = (std::min)(events.returnedRows, ULONG(KSWORD_ARK_HVM_MAX_EVENT_ROWS));
            report.detail = QStringLiteral("HVM ring: %1/%2, lost=%3").arg(size).arg(events.availableRows).arg(events.droppedRows);
            if (!size) { unavailable(report, QStringLiteral("HVM 环中没有可读事件。")); return; }
            // A retained ring cannot establish continuous instruction or write coverage.
            report.status = Status::Partial;
            QHash<quint64, quint32> objectFields;
            if (id == 47)
            {
                std::optional<ark::ProcessCrossViewResult> acquired;
                if (!scan.processCrossView) acquired = client.queryProcessCrossView(KSWORD_ARK_PROCESS_CROSSVIEW_FLAG_INCLUDE_PUBLIC_WALK);
                const auto& processes = scan.processCrossView ? *scan.processCrossView : *acquired;
                if (!processes.io.ok) { unavailable(report, QString::fromStdString(processes.io.message)); return; }
                for (const auto& p : processes.entries)
                {
                    if (!p.objectAddress || !p.fieldOffsets.epActiveProcessLinks) continue;
                    if (p.objectAddress > UINT64_MAX - p.fieldOffsets.epActiveProcessLinks - 8) continue;
                    const auto addr = p.objectAddress + p.fieldOffsets.epActiveProcessLinks;
                    objectFields.insert(addr, p.processId);
                    objectFields.insert(addr + 8, p.processId);
                }
                if (objectFields.isEmpty()) { unavailable(report, QStringLiteral("缺少可核对的活动进程链字段地址。")); return; }
            }
            for (ULONG i = 0; i < size; ++i)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                const auto& hit = events.rows[i];
                const bool watch = hit.type == KSWORD_ARK_HVM_EVENT_TYPE_EPT_VIOLATION &&
                    (hit.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_WATCH_HIT) && hit.status >= 0;
                quint32 pid = 0;
                QString kind;
                if (id == 45)
                {
                    // Intel VM-exit reason 28; qualification identifies MOV to CR3. The
                    // generic ring has no source GPR value, so do not invent the new DTB.
                    if (hit.type != KSWORD_ARK_HVM_EVENT_TYPE_VMEXIT || hit.exitReason != 28 ||
                        (hit.qualification & 0x3f) != 3) continue;
                    kind = QStringLiteral("MOV-to-CR3 退出");
                }
                else if (id == 46)
                {
                    const auto root = hit.guestCr3 & 0x000ffffffffff000ULL;
                    if (!watch || !(hit.access & 2) || !root || (hit.guestPhysicalAddress & ~0xfffULL) != root) continue;
                    kind = QStringLiteral("活动页表根写入命中");
                }
                else if (id == 47)
                {
                    if (!watch || !(hit.access & 2) || !(hit.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID) ||
                        !(hit.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_RANGE_MATCH)) continue;
                    const auto field = objectFields.constFind(hit.guestLinearAddress & ~7ULL);
                    if (field == objectFields.cend()) continue;
                    pid = field.value();
                    kind = QStringLiteral("进程链字段写入（事后地址关联）");
                }
                else
                {
                    if (!watch || !(hit.access & 4)) continue;
                    kind = QStringLiteral("EPT 执行命中");
                }
                auto& row = observation(scan, report, QStringLiteral("KSword HVM"), kind);
                row.historical = true;
                row.pid = pid;
                row.detail = QStringLiteral("#%1 CPU=%2:%3 RIP=%4 GLA=%5 GPA=%6 CR3=%7 qualification=%8 status=%9")
                    .arg(hit.sequence).arg(hit.processorGroup).arg(hit.processorNumber).arg(hex(hit.guestRip),
                        hit.eventFlags & KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID ? hex(hit.guestLinearAddress) : QStringLiteral("?"),
                        hex(hit.guestPhysicalAddress), hit.guestCr3 ? hex(hit.guestCr3) : QStringLiteral("?"),
                        hex(hit.qualification), hex(static_cast<quint32>(hit.status)));
            }
        }

        QString sdkProvider()
        {
            const QDir bin(qEnvironmentVariable("ProgramFiles(x86)") + QStringLiteral("/Windows Kits/10/bin"));
            for (const auto& version : bin.entryList({QStringLiteral("10.0.*")}, QDir::Dirs, QDir::Name | QDir::Reversed))
            {
                const auto file = localFile(bin.filePath(version + QStringLiteral("/x64/VmSavedStateDumpProvider.dll")));
                if (!file.isEmpty()) return file;
            }
            return {};
        }

        void savedVm(const ScanInputs& input, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const QFileInfo vmrs(input.hypervSavedState.isEmpty() ? input.memoryImage : input.hypervSavedState);
            const auto file = vmrs.absoluteFilePath();
            if (!vmrs.isAbsolute() || !file.endsWith(QStringLiteral(".vmrs"), Qt::CaseInsensitive))
            { unavailable(report, QStringLiteral("请选择 Hyper-V 保存状态文件（.vmrs）。")); return; }
            const Library provider(sdkProvider());
            const auto load = provider.get<decltype(&LoadSavedStateFile)>("LoadSavedStateFile");
            const auto release = provider.get<decltype(&ReleaseSavedStateFiles)>("ReleaseSavedStateFiles");
            const auto count = provider.get<decltype(&GetVpCount)>("GetVpCount");
            const auto architecture = provider.get<decltype(&GetArchitecture)>("GetArchitecture");
            const auto reg = provider.get<decltype(&GetRegisterValue)>("GetRegisterValue");
            if (!load || !release || !count || !architecture || !reg)
            { unavailable(report, QStringLiteral("缺少 Windows SDK x64 保存状态读取组件。")); return; }
            VM_SAVED_STATE_DUMP_HANDLE handle{};
            HRESULT hr = load(reinterpret_cast<LPCWSTR>(file.utf16()), &handle);
            if (FAILED(hr))
            {
                report.status = hr == E_ACCESSDENIED || hr == HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION) ||
                    hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) ?
                    Status::Unavailable : Status::Failed;
                report.detail = file + QLatin1Char(' ') + code(hr); return;
            }
            const auto cleanup = qScopeGuard([&] { release(handle); });
            UINT32 vcpus = 0;
            hr = count(handle, &vcpus);
            if (FAILED(hr) || !vcpus || vcpus > 4096)
            { report.status = Status::Failed; report.detail = QStringLiteral("GetVpCount %1, VP=%2").arg(code(hr)).arg(vcpus); return; }
            for (UINT32 vp = 0; vp < vcpus; ++vp)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                VIRTUAL_PROCESSOR_ARCH arch{};
                VIRTUAL_PROCESSOR_REGISTER cr3{}, ip{};
                if (FAILED(architecture(handle, vp, &arch)) || arch != Arch_x64 ||
                    FAILED(reg(handle, vp, X64_RegisterCr3, &cr3)) || FAILED(reg(handle, vp, X64_RegisterRip, &ip)))
                { report.status = Status::Partial; continue; }
                auto& row = observation(scan, report, file, QStringLiteral("宿主保存的虚拟 CPU 现场"));
                row.historical = true;
                row.detail = QStringLiteral("VP=%1 CR3=%2 RIP=%3").arg(vp).arg(hex(cr3.Reg64), hex(ip.Reg64));
            }
            if (!report.count) report.status = Status::Unavailable;
            report.detail = QStringLiteral("VMRS: VP=%1, x64=%2").arg(vcpus).arg(report.count);
        }

        // Xen public trace.h t_rec format; xentrace emits an explicit CPU and
        // byte-count prefix for each window. CR_WRITE64 stores an unaligned
        // packed u32 register number followed by the full u64 operand.
        void xenCr3(const QString& path, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            QFile file(localFile(path));
            if (!file.open(QIODevice::ReadOnly)) { unavailable(report, file.errorString()); return; }
            constexpr quint32 cpuChange = 0x2001f003, lost = 0x1f001, switchVcpu = 0x2800a;
            constexpr quint32 write32 = 0x82009, write64 = 0x82109;
            QHash<quint32, QPair<quint32, quint32>> scheduled;
            quint64 windows = 0, records = 0, missing = 0;
            bool damaged = false, limited = false;
            while (!file.atEnd() && !damaged && !limited)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                char prefix[12];
                if (file.read(prefix, sizeof(prefix)) != sizeof(prefix) || qFromLittleEndian<quint32>(prefix) != cpuChange)
                { damaged = true; break; }
                const auto cpu = qFromLittleEndian<quint32>(prefix + 4);
                auto remaining = qFromLittleEndian<quint32>(prefix + 8);
                if (cpu > 65535 || remaining % 4 || quint64(remaining) > quint64(file.size() - file.pos()))
                { damaged = true; break; }
                ++windows;
                while (remaining)
                {
                    if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                    if (records >= 16'000'000 || report.count >= limit) { limited = true; break; }
                    const auto offset = file.pos();
                    char header[4];
                    if (remaining < sizeof(header) || file.read(header, sizeof(header)) != sizeof(header))
                    { damaged = true; break; }
                    const auto raw = qFromLittleEndian<quint32>(header);
                    const auto event = raw & 0x0fffffffU;
                    const auto words = (raw >> 28) & 7;
                    const auto tsBytes = (raw >> 31) ? 8U : 0U;
                    const auto bytes = tsBytes + words * 4;
                    char tail[36]{};
                    if (bytes + 4 > remaining || file.read(tail, bytes) != bytes)
                    { damaged = true; break; }
                    remaining -= bytes + 4;
                    ++records;
                    const auto* data = tail + tsBytes;
                    if (event == lost) { ++missing; scheduled.remove(cpu); }
                    else if (event == switchVcpu && words == 4)
                        scheduled.insert(cpu, {qFromLittleEndian<quint32>(data+8), qFromLittleEndian<quint32>(data+12)});
                    else if (event == write32 || event == write64)
                    {
                        if (words != (event == write32 ? 2U : 3U)) { damaged = true; break; }
                        if (qFromLittleEndian<quint32>(data) != 3) continue;
                        const auto operand = event == write32 ? quint64(qFromLittleEndian<quint32>(data + 4)) :
                            qFromLittleEndian<quint64>(data + 4);
                        const auto owner = scheduled.constFind(cpu);
                        const auto scope = owner == scheduled.cend() ? QStringLiteral("?") :
                            QStringLiteral("d%1/v%2").arg(owner.value().first).arg(owner.value().second);
                        auto& row = observation(scan, report, file.fileName(), QStringLiteral("Xen CR3 写入记录"));
                        row.historical = true;
                        row.detail = QStringLiteral("pCPU=%1 %2 CR3=%3 TSC=%4 offset=%5").arg(cpu).arg(scope, hex(operand),
                            tsBytes ? hex(qFromLittleEndian<quint64>(tail)) : QStringLiteral("?"), hex(offset));
                    }
                }
            }
            if (!windows || damaged) report.status = records ? Status::Partial : Status::Failed;
            else if (limited || missing) report.status = Status::Partial;
            report.detail = QStringLiteral("xentrace: windows=%1, records=%2, loss_records=%3, malformed=%4, limited=%5")
                .arg(windows).arg(records).arg(missing).arg(damaged).arg(limited);
        }

        void processorTrace(const ScanInputs& input, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto trace = localFile(input.processorTraceFile);
            const auto decoder = localFile(input.processorTraceTool);
            if (trace.isEmpty() || QFileInfo(decoder).fileName().compare(QStringLiteral("ptdump.exe"), Qt::CaseInsensitive))
            { unavailable(report, QStringLiteral("请选择 Intel libipt 的 ptdump.exe 和原始 PT 文件。")); return; }
            QProcess tool;
            tool.setWorkingDirectory(QFileInfo(decoder).absolutePath());
            tool.start(decoder, {QStringLiteral("--no-pad"), QStringLiteral("--no-timing"), QStringLiteral("--no-cyc"), trace}, QIODevice::ReadOnly);
            if (!tool.waitForStarted(5000)) { unavailable(report, tool.errorString()); return; }
            const QRegularExpression packet(QStringLiteral("^([0-9a-fA-F]{1,16})\\s+(psb|pip|ovf)\\b(.*)$"));
            // ptdump may append the decoded "cr3" column to the short PIP operand.
            const QRegularExpression paging(QStringLiteral("^([0-9a-fA-F]{1,16})(?:,\\s*nr)?(?:\\s+cr3\\s+([0-9a-fA-F]{1,16}))?$"));
            bool limited = false;
            quint64 syncPackets = 0, overflowPackets = 0, malformed = 0;
            QByteArray pending, err;
            QElapsedTimer timer; timer.start();
            while (true)
            {
                tool.waitForFinished(80);
                err = (err + tool.readAllStandardError()).right(2048);
                pending += tool.readAllStandardOutput();
                qsizetype begin = 0;
                while (begin < pending.size())
                {
                    const auto end = pending.indexOf('\n', begin);
                    if (end < 0) break;
                    const auto match = packet.match(QString::fromLatin1(pending.constData() + begin, end - begin).trimmed());
                    begin = end + 1;
                    if (!match.hasMatch()) continue;
                    const auto op = match.captured(2);
                    if (op == QStringLiteral("psb")) { ++syncPackets; continue; }
                    if (op == QStringLiteral("ovf")) { ++overflowPackets; continue; }
                    if (!syncPackets) continue;
                    const auto pip = paging.match(match.captured(3).trimmed());
                    if (!pip.hasMatch() || (!pip.captured(2).isEmpty() &&
                        pip.captured(1).toULongLong(nullptr, 16) != pip.captured(2).toULongLong(nullptr, 16)))
                    { ++malformed; continue; }
                    auto& row = observation(scan, report, trace, QStringLiteral("Intel PT 页表上下文"));
                    row.historical = true;
                    row.detail = QStringLiteral("PIP @0x%1 CR3=0x%2").arg(match.captured(1), pip.captured(1));
                    if (report.count == limit) { limited = true; break; }
                }
                pending.remove(0, begin);
                if (pending.size() > 64 * 1024 || timer.elapsed() > 180000) limited = true;
                if (limited || cancelled(stop)) { tool.kill(); tool.waitForFinished(5000); break; }
                if (tool.state() == QProcess::NotRunning) break;
            }
            if (cancelled(stop)) report.status = Status::Cancelled;
            else if (!syncPackets || tool.exitStatus() != QProcess::NormalExit || tool.exitCode() != 0)
                report.status = report.count ? Status::Partial : Status::Failed;
            else if (overflowPackets || limited || malformed || !err.trimmed().isEmpty()) report.status = Status::Partial;
            report.detail = QStringLiteral("libipt: PSB=%1, PIP=%2, OVF=%3, exit=%4 %5")
                .arg(syncPackets).arg(report.count).arg(overflowPackets).arg(tool.exitCode()).arg(QString::fromLocal8Bit(err).trimmed());
            if (malformed) report.detail += QStringLiteral(" | malformed PIP=%1").arg(malformed);
        }

        void kernelDebugger(const ScanInputs& input, ScanResult& scan, MethodReport& report)
        {
            static const QRegularExpression pipeName(QStringLiteral("^[A-Za-z0-9_.-]{1,128}$"));
            if (!pipeName.match(input.debuggerTarget).hasMatch())
            { unavailable(report, QStringLiteral("请输入已运行的本机 DbgEng 调试服务器管道名。")); return; }
            const auto program = QFileInfo(localFile(input.debuggerProgram));
            if (program.fileName().compare(QStringLiteral("kd.exe"), Qt::CaseInsensitive) &&
                program.fileName().compare(QStringLiteral("windbg.exe"), Qt::CaseInsensitive))
            { unavailable(report, QStringLiteral("请选择 Windows Debugging Tools 的 kd.exe 或 windbg.exe。")); return; }
            const Library engine(program.dir().filePath(QStringLiteral("dbgeng.dll")));
            const auto connect = engine.get<decltype(&DebugConnectWide)>("DebugConnectWide");
            if (!connect) { unavailable(report, QStringLiteral("缺少同目录的 x64 dbgeng.dll。")); return; }
            const auto endpoint = QStringLiteral("npipe:server=localhost,pipe=%1").arg(input.debuggerTarget);
            const auto pipePath = QStringLiteral("\\\\.\\pipe\\") + input.debuggerTarget;
            if (!WaitNamedPipeW(reinterpret_cast<LPCWSTR>(pipePath.utf16()), 100))
            { unavailable(report, QStringLiteral("调试服务管道不可用（Win32 %1）。").arg(GetLastError())); return; }
            ComPtr<IDebugClient> client;
            HRESULT hr = connect(reinterpret_cast<LPCWSTR>(endpoint.utf16()), __uuidof(IDebugClient),
                reinterpret_cast<void**>(client.GetAddressOf()));
            if (FAILED(hr)) { unavailable(report, endpoint + QLatin1Char(' ') + code(hr)); return; }
            hr = client->ConnectSession(DEBUG_CONNECT_SESSION_NO_VERSION | DEBUG_CONNECT_SESSION_NO_ANNOUNCE, 0);
            if (FAILED(hr)) { unavailable(report, endpoint + QLatin1Char(' ') + code(hr)); return; }
            ComPtr<IDebugControl> control;
            ComPtr<IDebugSystemObjects> objects;
            ComPtr<IDebugRegisters> registers;
            ULONG type{}, qualifier{}, execution{}, processor{};
            if (FAILED(client.As(&control)) || FAILED(client.As(&objects)) || FAILED(client.As(&registers)) ||
                FAILED(control->GetDebuggeeType(&type, &qualifier)) || type != DEBUG_CLASS_KERNEL ||
                (qualifier != DEBUG_KERNEL_CONNECTION && qualifier != DEBUG_KERNEL_EXDI_DRIVER) ||
                FAILED(control->GetExecutionStatus(&execution)) || execution != DEBUG_STATUS_BREAK ||
                FAILED(control->GetActualProcessorType(&processor)) || processor != IMAGE_FILE_MACHINE_AMD64)
            { unavailable(report, QStringLiteral("服务器未提供已暂停的 x64 内核 KD/EXDI 目标。")); return; }
            ULONG pid{}, cr3Index{};
            ULONG64 processObject{}, rip{};
            DEBUG_VALUE cr3{};
            if (FAILED(objects->GetCurrentProcessDataOffset(&processObject)) || !processObject ||
                FAILED(registers->GetInstructionOffset(&rip)) || FAILED(registers->GetIndexByName("cr3", &cr3Index)) ||
                FAILED(registers->GetValue(cr3Index, &cr3)) || cr3.Type != DEBUG_VALUE_INT64 ||
                FAILED(control->GetExecutionStatus(&execution)) || execution != DEBUG_STATUS_BREAK)
            { report.status = Status::Failed; report.detail = QStringLiteral("无法读回稳定的内核调试现场。"); return; }
            auto& row = observation(scan, report, endpoint, QStringLiteral("带外调试现场"));
            row.objectAddress = processObject;
            if (SUCCEEDED(objects->GetCurrentProcessSystemId(&pid))) row.pid = pid;
            row.detail = QStringLiteral("%1 CR3=%2 RIP=%3 EPROCESS=%4")
                .arg(qualifier == DEBUG_KERNEL_EXDI_DRIVER ? QStringLiteral("EXDI") : QStringLiteral("KD"),
                    hex(cr3.I64), hex(rip), hex(processObject));
            report.detail = QStringLiteral("读取当前已暂停调试上下文。");
        }

        QByteArray readBounded(const QString& path, qsizetype bytes, bool& ok)
        {
            if (path.isEmpty()) { ok = false; return {}; }
            QFile file(path);
            ok = file.open(QIODevice::ReadOnly);
            if (!ok) return {};
            const auto data = file.read(bytes + 1);
            ok = data.size() <= bytes && file.error() == QFileDevice::NoError;
            return ok ? data : QByteArray{};
        }

        struct MountedProcess
        {
            quint32 pid{};
            QString image, created;
            bool unlinked = false, terminated = false;
            QString fullImage;
        };
        struct MountedView
        {
            QString name, tag, source, savedFile;
            QVector<MountedProcess> rows;
        };
        bool parseProcessView(const QByteArray& info, const QByteArray& bytes, MountedView& view,
            MethodReport& report, const CancelCheck& stop)
        {
            const auto field = [&](const char* prefix) {
                for (auto line : info.split('\n'))
                    if (line.trimmed().startsWith(prefix))
                        return QString::fromUtf8(line.trimmed().mid(qstrlen(prefix)).trimmed());
                return QString();
            };
            view.name = field("Computer Name:");
            view.tag = field("Unique Tag:");
            view.source = field("Memory Source:");
            if (view.name.isEmpty() || view.tag.isEmpty() || view.source.isEmpty())
            { unavailable(report, QStringLiteral("缺少 MemProcFS 系统与采集来源信息。")); return false; }
            for (const auto& line : bytes.split('\n'))
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return false; }
                if (line.trimmed().isEmpty() || line.startsWith("Process ") || line.startsWith("----")) continue;
                bool pidOk = false, parentOk = false;
                const auto pid = line.mid(16, 6).trimmed().toUInt(&pidOk);
                line.mid(23, 6).trimmed().toUInt(&parentOk);
                if (line.size() < 77 || !pidOk || !parentOk) { report.status = Status::Partial; continue; }
                view.rows.append({pid, QString::fromUtf8(line.left(16)).trimmed(),
                    QString::fromLatin1(line.mid(54, 23)).trimmed(), line[32] == 'E', line[33] == 'T',
                    QString::fromUtf8(line.mid(104)).trimmed()});
                if (view.rows.size() == limit) { report.status = Status::Partial; break; }
            }
            if (!view.rows.isEmpty()) return true;
            report.status = Status::Failed; report.detail = QStringLiteral("进程生命周期表没有可解析的数据行。"); return false;
        }

        bool readMount(const QString& root, MountedView& view, MethodReport& report, const CancelCheck& stop)
        {
            if (!QDir::isAbsolutePath(root))
            { unavailable(report, QStringLiteral("请选择 MemProcFS 挂载根目录。")); return false; }
            const QDir mount(root);
            bool ok = false;
            const auto info = readBounded(mount.filePath(QStringLiteral("sys/sysinfo/sysinfo.txt")), 1024 * 1024, ok);
            if (!ok) { unavailable(report, QStringLiteral("缺少 MemProcFS 系统与采集来源信息。")); return false; }
            const auto bytes = readBounded(mount.filePath(QStringLiteral("sys/proc/proc-time.txt")), 8 * 1024 * 1024, ok);
            if (!ok) { unavailable(report, QStringLiteral("无法读取 MemProcFS 进程生命周期表。")); return false; }
            return parseProcessView(info, bytes, view, report, stop);
        }

        bool useSavedState(const ScanInputs& input)
        {
            return input.vmiMountRoot.isEmpty() && !input.hypervSavedState.isEmpty();
        }

        bool readSavedProcesses(const ScanInputs& input, ScanResult& scan, MountedView& view, MethodReport& report, const CancelCheck& stop)
        {
            const auto library = localFile(input.memProcFsLibrary);
            if (QFileInfo(library).fileName().compare(QStringLiteral("vmm.dll"), Qt::CaseInsensitive))
            { unavailable(report, QStringLiteral("请选择本地离线 VMRS 文件和 MemProcFS x64 的 vmm.dll。")); return false; }
            view.savedFile = localFile(input.hypervSavedState);
            auto files = scan.researchVmrsProcessFiles;
            if (!files || files->sourceFile != view.savedFile || files->library != library) {
                const Library vmm(library);
                if (!vmm.handle) {
                    unavailable(report, QStringLiteral("vmm.dll | Win32=%1").arg(vmm.loadError));
                    return false;
                }
                auto acquired = std::make_shared<VmrsProcessFiles>();
                acquired->sourceFile = view.savedFile;
                acquired->library = library;
                if (!ReadVmrsProcessFiles(vmm.handle, view.savedFile, acquired->systemInfo, acquired->processes, report, stop)) return false;
                files = std::move(acquired);
            }
            if (!parseProcessView(files->systemInfo, files->processes, view, report, stop)) return false;
            if (view.source.compare(QStringLiteral("Read-only, Static"), Qt::CaseInsensitive))
            { unavailable(report, QStringLiteral("保存态提供方没有确认只读静态内存来源。")); return false; }
            scan.researchVmrsProcessFiles = std::move(files);
            return true;
        }

        QStringList processArguments(HANDLE process)
        {
            using Query = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
            const auto query = std::bit_cast<Query>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
            if (!query) return {};
            ULONG size = 0;
            constexpr auto commandLineInfo = static_cast<PROCESSINFOCLASS>(60);
            query(process, commandLineInfo, nullptr, 0, &size);
            if (size < sizeof(UNICODE_STRING) || size > 256 * 1024) return {};
            std::vector<BYTE> buffer(size);
            if (query(process, commandLineInfo, buffer.data(), size, &size) < 0) return {};
            const auto* raw = reinterpret_cast<const UNICODE_STRING*>(buffer.data());
            const auto addr = reinterpret_cast<quintptr>(raw->Buffer);
            const auto base = reinterpret_cast<quintptr>(buffer.data());
            if (addr < base || addr - base > buffer.size() || raw->Length % sizeof(wchar_t) ||
                raw->Length > buffer.size() - (addr - base)) return {};
            const std::wstring command(raw->Buffer, raw->Length / sizeof(wchar_t));
            int argc = 0;
            auto argv = CommandLineToArgvW(command.c_str(), &argc);
            if (!argv) return {};
            const auto free = qScopeGuard([&] { LocalFree(argv); });
            QStringList args;
            for (int i = 0; i < argc; ++i) args.append(QString::fromWCharArray(argv[i]));
            return args;
        }

        // Require a live MemProcFS process belonging to the selected installation
        // and naming this drive and backend. A copied VFS tree is insufficient.
        QString activeMount(const ScanInputs& input, const QString& root, bool dma)
        {
            const auto library = QFileInfo(localFile(input.memProcFsLibrary));
            if (library.fileName().compare(QStringLiteral("vmm.dll"), Qt::CaseInsensitive)) return {};
            const auto exe = library.dir().filePath(QStringLiteral("MemProcFS.exe"));
            const auto mount = QDir::cleanPath(QDir::fromNativeSeparators(root)).toUpper();
            static const QRegularExpression drive(QStringLiteral("^[A-Z]:/$"));
            if (!drive.match(mount).hasMatch()) return {};
            const QString driveName = mount.left(2);
            wchar_t target[1024]{};
            if (!QueryDosDeviceW(reinterpret_cast<LPCWSTR>(driveName.utf16()), target, DWORD(std::size(target)))) return {};
            const auto devicePath = QString::fromWCharArray(target);
            if (devicePath.startsWith(QStringLiteral("\\Device\\Harddisk"), Qt::CaseInsensitive) ||
                devicePath.startsWith(QStringLiteral("\\??\\"), Qt::CaseInsensitive)) return {};
            bool requestedPidOk = false;
            const auto requestedPid = input.vmwareProcessId.toUInt(&requestedPidOk);
            if (!dma && input.vmwareProcessId.trimmed().isEmpty()) return {};
            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return {};
            const auto releaseSnapshot = qScopeGuard([&] { CloseHandle(snapshot); });
            PROCESSENTRY32W entry{}; entry.dwSize = sizeof(entry);
            if (!Process32FirstW(snapshot, &entry)) return {};
            do
            {
                if (_wcsicmp(entry.szExeFile, L"MemProcFS.exe")) continue;
                HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ProcessID);
                if (!process) continue;
                const auto close = qScopeGuard([&] { CloseHandle(process); });
                wchar_t path[32768]; DWORD n = DWORD(std::size(path));
                if (!QueryFullProcessImageNameW(process, 0, path, &n) ||
                    QDir::fromNativeSeparators(QString::fromWCharArray(path, n)).compare(exe, Qt::CaseInsensitive)) continue;
                const auto args = processArguments(process);
                QString device, driveArg = QStringLiteral("M");
                for (int i = 1; i + 1 < args.size(); ++i)
                {
                    if (!args[i].compare(QStringLiteral("-device"), Qt::CaseInsensitive)) device = args[i + 1].toLower();
                    if (!args[i].compare(QStringLiteral("-mount"), Qt::CaseInsensitive)) driveArg = args[i + 1].toUpper();
                }
                if (driveArg != mount && driveArg != driveName && driveArg != mount.left(1)) continue;
                if (WaitForSingleObject(process, 0) != WAIT_TIMEOUT) continue;
                if (dma && (device == QStringLiteral("fpga") || device.startsWith(QStringLiteral("fpga://"))))
                    return QStringLiteral("FPGA / MemProcFS PID %1").arg(entry.th32ProcessID);
                if (!dma && requestedPidOk && requestedPid && device.startsWith(QStringLiteral("vmware://")))
                {
                    const auto params = device.mid(9).split(',');
                    if (params.contains(QStringLiteral("id=%1").arg(requestedPid)) && params.contains(QStringLiteral("ro=1")))
                        return QStringLiteral("VMware PID %1 / MemProcFS PID %2").arg(requestedPid).arg(entry.th32ProcessID);
                }
                if (!dma && (device == QStringLiteral("livekd") || device.isEmpty()))
                {
                    // Sysinternals LiveKd starts the debugger/VFS as a child.
                    // Bind the active parent, command line and process lifetimes
                    // to the named Hyper-V VM. Never start LiveKd from this reader.
                    HANDLE parent = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, entry.th32ParentProcessID);
                    if (!parent) continue;
                    const auto releaseParent = qScopeGuard([&] { CloseHandle(parent); });
                    n = DWORD(std::size(path));
                    if (!QueryFullProcessImageNameW(parent, 0, path, &n)) continue;
                    const auto name = QFileInfo(QString::fromWCharArray(path, n)).fileName().toLower();
                    if (name != QStringLiteral("livekd.exe") && name != QStringLiteral("livekd64.exe")) continue;
                    FILETIME parentTime{}, childTime{}, e{}, k{}, u{};
                    if (!GetProcessTimes(parent, &parentTime, &e, &k, &u) ||
                        !GetProcessTimes(process, &childTime, &e, &k, &u) || CompareFileTime(&parentTime, &childTime) > 0) continue;
                    const auto command = processArguments(parent);
                    for (int a = 1; a + 1 < command.size(); ++a)
                        if (!command[a].compare(QStringLiteral("-hv"), Qt::CaseInsensitive) &&
                            !command[a+1].compare(input.vmwareProcessId, Qt::CaseInsensitive) &&
                            WaitForSingleObject(parent, 0) == WAIT_TIMEOUT)
                            return QStringLiteral("Hyper-V %1 / LiveKd PID %2 / MemProcFS PID %3")
                                .arg(input.vmwareProcessId).arg(entry.th32ParentProcessID).arg(entry.th32ProcessID);
                }
            } while (Process32NextW(snapshot, &entry));
            return {};
        }

        void mountedProvider(bool dma, const ScanInputs& input, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto specific = dma ? input.dmaMountRoot : input.vmiMountRoot;
            const auto root = specific.isEmpty() ? input.memProcFsRoot : specific;
            const bool saved = !dma && useSavedState(input);
            QString provider;
            MountedView view;
            if (saved) {
                if (!readSavedProcesses(input, scan, view, report, stop)) return;
                provider = QStringLiteral("Hyper-V HvSavedState | ") + view.savedFile;
            } else {
                provider = activeMount(input, root, dma);
                if (provider.isEmpty())
                { unavailable(report, QStringLiteral("没有与所选驱动器、安装位置及采集设备相符的运行中 MemProcFS。")); return; }
                if (!readMount(root, view, report, stop)) return;
                if (!view.source.endsWith(QStringLiteral(", Volatile"), Qt::CaseInsensitive) ||
                    (!dma && !view.source.startsWith(QStringLiteral("Read-only,"), Qt::CaseInsensitive)))
                { unavailable(report, QStringLiteral("挂载源没有报告匹配的实时采集属性。")); return; }
                if (activeMount(input, root, dma) != provider) { unavailable(report, QStringLiteral("采集期间挂载提供方已更替。")); return; }
            }
            const auto scope = provider + QStringLiteral(" | ") + view.tag;
            for (const auto& p : view.rows)
            {
                auto& row = observation(scan, report, scope, p.unlinked ? QStringLiteral("外部视图进程链缺项") : QStringLiteral("外部进程对象"));
                row.pid = p.pid; row.image = p.fullImage.isEmpty() ? p.image : p.fullImage; row.historical = saved || p.terminated;
                row.detail = QStringLiteral("created=%1 unlinked=%2 terminated=%3").arg(p.created).arg(p.unlinked).arg(p.terminated);
                if (!p.fullImage.isEmpty() && p.fullImage != p.image) row.detail += QStringLiteral(" | short image=%1").arg(p.image);
            }
            if (!saved) report.status = Status::Partial; // A volatile capture cannot certify a consistent physical snapshot.
            report.detail = QStringLiteral("%1 | %2 | %3 | %4").arg(provider, view.name, view.tag, view.source);
        }

        QStringList csvLine(const QString& line)
        {
            QStringList fields;
            QString field;
            bool quoted = false;
            for (qsizetype i = 0; i < line.size(); ++i)
            {
                const auto c = line.at(i);
                if (c == QLatin1Char('"'))
                {
                    if (quoted && i + 1 < line.size() && line.at(i + 1) == c) { field += c; ++i; }
                    else quoted = !quoted;
                }
                else if (c == QLatin1Char(',') && !quoted) { fields.append(field.trimmed()); field.clear(); }
                else field += c;
            }
            if (quoted) return {};
            fields.append(field.trimmed());
            return fields;
        }
        QDateTime guestCreation(const QString& value)
        {
            // WMI's DMTF datetime carries a signed UTC offset in minutes.
            static const QRegularExpression cim(QStringLiteral("^(\\d{14})\\.(\\d{6})([+-])(\\d{3})$"));
            const auto match = cim.match(value);
            if (match.hasMatch())
            {
                auto date = QDateTime::fromString(match.captured(1), QStringLiteral("yyyyMMddHHmmss"));
                date.setTimeZone(QTimeZone::UTC);
                const int minutes = match.captured(4).toInt() * (match.captured(3) == QStringLiteral("+") ? 1 : -1);
                return date.addSecs(-60 * minutes);
            }
            static const QRegularExpression zone(QStringLiteral("(?:Z|[+-]\\d\\d:\\d\\d)$"));
            return zone.match(value).hasMatch() ? QDateTime::fromString(value, Qt::ISODateWithMs).toUTC() : QDateTime();
        }
        void crossGuest(const ScanInputs& input, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto source = localFile(input.guestProcessFile);
            bool ok = false;
            const auto raw = readBounded(source, 4 * 1024 * 1024, ok);
            if (!ok) { unavailable(report, QStringLiteral("请选择含 CSName、ProcessId、Name、CreationDate 的来宾 WMI CSV。")); return; }
            QStringDecoder decoder(QStringConverter::encodingForData(raw).value_or(QStringConverter::Utf8));
            const QString content = decoder(raw);
            if (decoder.hasError()) { report.status = Status::Failed; report.detail = QStringLiteral("来宾 CSV 文本编码无效。"); return; }
            MountedView view;
            const bool saved = useSavedState(input);
            QString root = input.vmiMountRoot.isEmpty() ? input.memProcFsRoot : input.vmiMountRoot;
            if (saved) {
                if (!readSavedProcesses(input, scan, view, report, stop)) return;
                root = QStringLiteral("Hyper-V HvSavedState | ") + view.savedFile;
            } else if (!readMount(root, view, report, stop)) return;
            const auto lines = content.split(QLatin1Char('\n'));
            QStringList header;
            qsizetype first = 0;
            while (first < lines.size() && header.isEmpty())
            {
                const auto line = lines[first++].trimmed();
                if (!line.isEmpty() && !line.startsWith(QStringLiteral("#TYPE "))) header = csvLine(line);
            }
            const auto machine = header.indexOf(QStringLiteral("CSName"), 0);
            const auto pid = header.indexOf(QStringLiteral("ProcessId"), 0);
            const auto name = header.indexOf(QStringLiteral("Name"), 0);
            const auto created = header.indexOf(QStringLiteral("CreationDate"), 0);
            if (machine < 0 || pid < 0 || name < 0 || created < 0)
            { report.status = Status::Failed; report.detail = QStringLiteral("来宾 CSV 的 WMI 身份列不完整。"); return; }
            QHash<quint32, QPair<QString, qint64>> guest;
            quint64 malformed = 0;
            for (auto i = first; i < lines.size(); ++i)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                if (lines[i].trimmed().isEmpty()) continue;
                const auto fields = csvLine(lines[i]);
                if (fields.size() != header.size()) { ++malformed; continue; }
                if (fields[machine].compare(view.name, Qt::CaseInsensitive))
                { report.status = Status::Failed; report.detail = QStringLiteral("来宾计算机名与宿主内存视图不匹配。"); return; }
                const auto processId = fields[pid].toUInt(&ok);
                const auto time = guestCreation(fields[created]);
                if (!ok || !time.isValid() || guest.contains(processId)) { ++malformed; continue; }
                guest.insert(processId, {fields[name], time.toSecsSinceEpoch()});
            }
            if (guest.isEmpty()) { report.status = Status::Failed; report.detail = QStringLiteral("来宾 CSV 没有有效的进程创建时间。"); return; }
            quint64 matched = 0, uncertain = 0, guestOnly = 0, hostOnly = 0;
            QSet<quint32> hostPids;
            const auto scope = source + QStringLiteral(" | ") + root + QStringLiteral(" | ") + view.tag;
            for (const auto& p : view.rows)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                if (p.terminated) continue;
                hostPids.insert(p.pid);
                auto time = QDateTime::fromString(p.created, QStringLiteral("yyyy-MM-dd HH:mm:ss 'UTC'"));
                time.setTimeZone(QTimeZone::UTC);
                const auto it = guest.constFind(p.pid);
                if (!time.isValid()) { ++uncertain; continue; }
                const QString& image = p.fullImage.isEmpty() ? p.image : p.fullImage;
                const bool same = it != guest.cend() && it.value().second == time.toSecsSinceEpoch() &&
                    (p.fullImage.isEmpty() ? it->first.left(15).compare(p.image.left(15), Qt::CaseInsensitive) :
                        it->first.compare(p.fullImage, Qt::CaseInsensitive)) == 0;
                if (same) { ++matched; continue; }
                if (it == guest.cend()) ++hostOnly;
                auto& row = observation(scan, report, scope, QStringLiteral("来宾与宿主进程身份待核实"));
                row.pid = p.pid; row.image = image;
                row.historical = true;
                row.detail = QStringLiteral("Host=%1 | Guest=%2 | snapshot time unverified").arg(p.created,
                    it == guest.cend() ? QStringLiteral("?") : QDateTime::fromSecsSinceEpoch(it.value().second, QTimeZone::UTC).toString(Qt::ISODate));
                if (it != guest.cend()) row.detail += QStringLiteral(" | guest image=%1").arg(it->first);
            }
            for (auto it = guest.cbegin(); it != guest.cend(); ++it)
            {
                if (cancelled(stop)) { report.status = Status::Cancelled; return; }
                if (hostPids.contains(it.key())) continue;
                ++guestOnly;
                auto& row = observation(scan, report, scope, QStringLiteral("仅来宾快照记录"));
                row.pid = it.key(); row.image = it->first; row.historical = true;
                row.detail = QStringLiteral("Guest=%1 | snapshot time unverified")
                    .arg(QDateTime::fromSecsSinceEpoch(it->second, QTimeZone::UTC).toString(Qt::ISODate));
            }
            report.status = Status::Partial;
            report.detail = QStringLiteral("%1 / %2 | guest=%3, candidate_matches=%4, unresolved=%5, skipped=%6")
                .arg(view.name, view.tag).arg(guest.size()).arg(matched).arg(uncertain).arg(malformed);
            report.detail += QStringLiteral(" | host=%1 guest-only=%2 host-only=%3 | %4")
                .arg(hostPids.size()).arg(guestOnly).arg(hostOnly).arg(root);
            report.detail += QChar::LineFeed + QStringLiteral("候选匹配使用 PID、映像名称与 UTC 整秒创建时间。优先使用完整映像名，两次采样时间未对齐。");
        }
    }

    bool CollectResearchExternal(int id, const ScanInputs& input, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
    {
        if (id < 44 || id > 53) return false;
        if (cancelled(stop)) { report.status = Status::Cancelled; return true; }
        if (id == 44 || id == 51) mountedProvider(id == 51, input, scan, report, stop);
        else if (id == 45 && !input.xenTraceFile.isEmpty()) xenCr3(input.xenTraceFile, scan, report, stop);
        else if (id >= 45 && id <= 48) hvm(id, scan, report, stop);
        else if (id == 49) crossGuest(input, scan, report, stop);
        else if (id == 50) processorTrace(input, scan, report, stop);
        else if (id == 52) savedVm(input, scan, report, stop);
        else kernelDebugger(input, scan, report);
        return true;
    }

    namespace
    {
        Status ioFailure(const ark::IoResult& io)
        {
            return io.deviceOpenFailed || io.win32Error == ERROR_ACCESS_DENIED || io.win32Error == ERROR_NOT_SUPPORTED ||
                io.win32Error == ERROR_INVALID_FUNCTION || static_cast<quint32>(io.ntStatus) == 0xc0000022U ?
                Status::Unavailable : Status::Failed;
        }
        QString transport(const ark::IoResult& io)
        {
            return QStringLiteral("Win32=%1 NTSTATUS=%2 %3").arg(io.win32Error)
                .arg(hex(static_cast<quint32>(io.ntStatus)), QString::fromStdString(io.message));
        }
        struct ImageRange
        {
            quint64 base;
            quint32 size;
            QString path;
            bool contains(quint64 va) const { return va >= base && va - base < size; }
        };
        std::vector<ImageRange> imageRanges(const ark::DriverObjectModuleSnapshot& snapshot)
        {
            using namespace ks::r3::driver;
            constexpr size_t start = offsetof(KRTL_PROCESS_MODULES, Modules);
            const auto& bytes = snapshot.systemInformation;
            if (bytes.size() < start) return {};
            const auto* modules = reinterpret_cast<const KRTL_PROCESS_MODULES*>(bytes.data());
            if (modules->NumberOfModules > (bytes.size() - start) / sizeof(KRTL_PROCESS_MODULE_INFORMATION)) return {};
            std::vector<ImageRange> image;
            for (ULONG n = 0; n < modules->NumberOfModules; ++n)
            {
                const auto& module = modules->Modules[n];
                const auto* path = reinterpret_cast<const char*>(module.FullPathName);
                if (module.ImageBase && module.ImageSize)
                    image.push_back({reinterpret_cast<quintptr>(module.ImageBase), module.ImageSize,
                        QString::fromLocal8Bit(path, strnlen(path, sizeof(module.FullPathName)))});
            }
            return image;
        }

        Status inspectSsdt(const ark::DriverClient& client, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto table = client.enumerateSsdt(KSWORD_ARK_ENUM_SSDT_FLAG_INCLUDE_UNRESOLVED);
            if (!table.io.ok)
            {
                report.detail += QStringLiteral("\nSSDT: ") + transport(table.io);
                return ioFailure(table.io);
            }
            const auto images = imageRanges(client.captureDriverObjectModules());
            const auto kernel = std::find_if(images.cbegin(), images.cend(), [&](const ImageRange& range) {
                const auto name = QFileInfo(QDir::fromNativeSeparators(range.path)).fileName().toLower();
                return (name == QStringLiteral("ntoskrnl.exe") || name == QStringLiteral("ntkrnlmp.exe")) &&
                    range.contains(table.serviceTableBase);
            });
            QSet<quint32> indices;
            quint64 unresolved = 0, outsideKernel = 0;
            constexpr ULONG observed = KSWORD_ARK_SSDT_ENTRY_FLAG_INDEX_RESOLVED |
                KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_ADDRESS_VALID | KSWORD_ARK_SSDT_ENTRY_FLAG_TABLE_VALUE_CAPTURED;
            for (const auto& service : table.entries)
            {
                if (cancelled(stop)) return Status::Cancelled;
                if ((service.flags & observed) != observed || !table.serviceTableBase ||
                    service.serviceIndex >= table.serviceCountFromTable || service.tableEntrySize != sizeof(quint32) ||
                    !service.serviceRoutineAddress || service.tableEntryAddress < table.serviceTableBase ||
                    service.tableEntryAddress - table.serviceTableBase != quint64(service.serviceIndex) * sizeof(quint32))
                { ++unresolved; continue; }
                indices.insert(service.serviceIndex);
                if (kernel == images.cend() || kernel->contains(service.serviceRoutineAddress)) continue;
                const auto owner = std::find_if(images.cbegin(), images.cend(), [&](const ImageRange& range) {
                    return range.contains(service.serviceRoutineAddress);
                });
                auto& row = observation(scan, report, QStringLiteral("R0 / SSDT"), QStringLiteral("系统服务目标位于内核映像之外"));
                row.researchId = 65;
                row.objectAddress = service.tableEntryAddress;
                if (owner != images.cend()) row.image = owner->path;
                row.detail = QStringLiteral("%1 [%2] slot=%3 value=%4 target=%5")
                    .arg(QString::fromStdString(service.serviceName)).arg(service.serviceIndex)
                    .arg(hex(service.tableEntryAddress), hex(service.currentTableValue), hex(service.serviceRoutineAddress));
                ++outsideKernel;
            }
            report.detail += QStringLiteral("\nSSDT (Zw): %1/%2, slots=%3/%4, unresolved=%5, target_outside=%6, kernel=%7")
                .arg(table.returnedCount).arg(table.totalCount).arg(indices.size()).arg(table.serviceCountFromTable)
                .arg(unresolved).arg(outsideKernel).arg(kernel == images.cend() ? QStringLiteral("?") : kernel->path);
            if (indices.isEmpty()) return table.entries.empty() ? Status::Unavailable : Status::Partial;
            return kernel == images.cend() || unresolved || indices.size() < table.serviceCountFromTable ||
                table.totalCount != table.returnedCount || table.entries.size() != table.returnedCount ? Status::Partial : Status::Complete;
        }

        Status inspectInline(const ark::DriverClient& client, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            const auto hooks = client.scanInlineHooks();
            if (!hooks.io.ok)
            {
                report.detail += QStringLiteral("\nInline: ") + transport(hooks.io);
                return ioFailure(hooks.io);
            }
            quint64 unread = 0, unusual = 0;
            for (const auto& entry : hooks.entries)
            {
                if (cancelled(stop)) return Status::Cancelled;
                if (entry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_INTERNAL_BRANCH ||
                    entry.status == KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN) continue;
                if (entry.status != KSWORD_ARK_KERNEL_HOOK_STATUS_SUSPICIOUS)
                { ++unread; continue; }
                auto& row = observation(scan, report, QStringLiteral("R0 / Inline"), QStringLiteral("导出入口分支线索"));
                row.researchId = 65;
                row.objectAddress = entry.functionAddress;
                row.image = QString::fromStdWString(entry.moduleName);
                row.detail = QStringLiteral("%1 type=%2 entry=%3 target=%4 owner=%5 sampled=%6")
                    .arg(QString::fromStdString(entry.functionName)).arg(entry.hookType)
                    .arg(hex(entry.functionAddress), hex(entry.targetAddress), QString::fromStdWString(entry.targetModuleName))
                    .arg(entry.currentByteCount);
                ++unusual;
            }
            report.detail += QStringLiteral("\nInline (exports): modules=%1, rows=%2/%3, unusual=%4, unread=%5, status=%6, NTSTATUS=%7")
                .arg(hooks.moduleCount).arg(hooks.returnedCount).arg(hooks.totalCount).arg(unusual)
                .arg(unread).arg(hooks.status).arg(hex(static_cast<quint32>(hooks.lastStatus)));
            if (!hooks.moduleCount && hooks.entries.empty()) return Status::Unavailable;
            return unread || hooks.status != KSWORD_ARK_KERNEL_HOOK_STATUS_CLEAN || hooks.lastStatus < 0 ||
                hooks.totalCount != hooks.returnedCount || hooks.entries.size() != hooks.returnedCount ?
                Status::Partial : Status::Complete;
        }
    }

    void ReadResearchKernelPaths(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
    {
        if (cancelled(stop) || report.status == Status::Cancelled) { report.status = Status::Cancelled; return; }
        const ark::DriverClient client;
        const auto ssdt = inspectSsdt(client, scan, report, stop);
        if (cancelled(stop) || ssdt == Status::Cancelled) { report.status = Status::Cancelled; return; }
        const auto hooks = inspectInline(client, scan, report, stop);
        const std::array parts{report.status, ssdt, hooks};
        if (cancelled(stop) || hooks == Status::Cancelled) report.status = Status::Cancelled;
        else if (std::all_of(parts.begin(), parts.end(), [](Status s) { return s == Status::Complete; })) report.status = Status::Complete;
        else if (std::any_of(parts.begin(), parts.end(), [](Status s) { return s == Status::Complete || s == Status::Partial; })) report.status = Status::Partial;
        else if (std::find(parts.begin(), parts.end(), Status::Failed) != parts.end()) report.status = Status::Failed;
        else report.status = Status::Unavailable;
    }
}
