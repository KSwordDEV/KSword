#include "ProcessResearchActivity.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QStringList>
#include <Windows.h>
#include <Wbemidl.h>
#include <atlbase.h>
#include <array>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "advapi32.lib")

namespace ksword::detection
{
    namespace
    {
        bool canceled(const CancelCheck& stop) { return stop && stop(); }

        Evidence& append(ScanResult& scan, MethodReport& report, int id, const QString& scope)
        {
            ++report.count;
            auto& row = scan.evidence.emplaceBack();
            row.researchId = id;
            row.methods = report.method;
            row.scope = scope;
            return row;
        }

        void readFindEvil(int id, const QString& mount, ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            if (mount.isEmpty())
            {
                report.status = Status::Unavailable;
                report.detail = QStringLiteral("请在检测方法中选择 MemProcFS 挂载目录。");
                return;
            }
            const QDir root(mount);
            QFile progress(root.filePath(QStringLiteral("forensic/progress_percent.txt")));
            const bool complete = progress.open(QIODevice::ReadOnly) && progress.read(16).trimmed() == "100";
            const auto path = root.absoluteFilePath(QStringLiteral("forensic/findevil/findevil.txt"));
            QFile file(path);
            if (!file.open(QIODevice::ReadOnly))
            {
                report.status = Status::Unavailable;
                report.detail = path + QChar::LineFeed + file.errorString();
                return;
            }
            const QByteArray type = id == 58 ? "PE_INJECT" : id == 60 ? "UM_APC" : "PE_PATCHED";
            bool headerSeen = false;
            qsizetype processColumn = -1, typeColumn = -1, addressColumn = -1;
            quint64 malformed = 0;
            while (!file.atEnd())
            {
                if (canceled(stop)) { report.status = Status::Cancelled; return; }
                if (file.pos() > 16 * 1024 * 1024 || report.count >= 4096) { report.status = Status::Partial; break; }
                const auto line = file.readLine(65536);
                if (line.size() == 65535 && !line.endsWith('\n')) { ++malformed; break; }
                const auto clean = line.trimmed();
                if (clean.startsWith('#'))
                {
                    processColumn = line.indexOf("Process");
                    typeColumn = line.indexOf("Type", processColumn + 1);
                    addressColumn = line.indexOf("VirtualAddress", typeColumn + 1);
                    if (addressColumn < 0) addressColumn = line.indexOf("Address", typeColumn + 1);
                    headerSeen = line.contains("PID") && processColumn > 0 && typeColumn > processColumn && addressColumn > typeColumn;
                    if (!headerSeen) { ++malformed; break; }
                    continue;
                }
                if (clean.isEmpty() || clean.startsWith("---") || clean.startsWith("===")) continue;
                if (!headerSeen) { ++malformed; break; }
                const auto indexPid = line.left(processColumn).simplified().split(' ');
                if (indexPid.size() != 2) { ++malformed; continue; }
                bool pidOk = false, addressOk = false;
                const auto pid = indexPid[1].toUInt(&pidOk);
                const auto address = line.mid(addressColumn, 16).trimmed().toULongLong(&addressOk, 16);
                if (!pidOk || !addressOk) { ++malformed; continue; }
                if (line.mid(typeColumn, addressColumn - typeColumn).trimmed() != type) continue;
                auto& row = append(scan, report, id, path);
                row.pid = pid;
                row.image = QString::fromUtf8(line.mid(processColumn, typeColumn - processColumn).trimmed());
                row.objectAddress = address;
                row.category = QString::fromLatin1(type);
                row.detail = QString::fromUtf8(clean);
            }
            if (!headerSeen || file.error() != QFileDevice::NoError)
                report.status = report.count ? Status::Partial : Status::Failed;
            else if (!complete || malformed) report.status = Status::Partial;
            report.detail = QStringLiteral("%1 | %2 | malformed=%3 | forensic progress complete=%4")
                .arg(path, QString::fromLatin1(type)).arg(malformed).arg(complete);
        }

        QString property(IWbemClassObject* object, const wchar_t* name)
        {
            CComVariant value;
            if (FAILED(object->Get(name, 0, &value, nullptr, nullptr)) || value.vt == VT_NULL ||
                value.vt == VT_EMPTY || FAILED(value.ChangeType(VT_BSTR)) || !value.bstrVal) return {};
            return QString::fromWCharArray(value.bstrVal);
        }

        void watchProcessTrace(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            struct Apartment {
                HRESULT status = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
                ~Apartment() { if (SUCCEEDED(status)) CoUninitialize(); }
            } apartment;
            HRESULT hr = apartment.status == RPC_E_CHANGED_MODE ? S_OK : apartment.status;
            CComPtr<IWbemLocator> locator;
            CComPtr<IWbemServices> service;
            CComPtr<IEnumWbemClassObject> events;
            if (SUCCEEDED(hr)) hr = locator.CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER);
            if (SUCCEEDED(hr)) hr = locator->ConnectServer(CComBSTR(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                WBEM_FLAG_CONNECT_USE_MAX_WAIT, nullptr, nullptr, &service);
            if (SUCCEEDED(hr)) hr = CoSetProxyBlanket(service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
            if (SUCCEEDED(hr)) hr = service->ExecNotificationQuery(CComBSTR(L"WQL"),
                CComBSTR(L"SELECT * FROM Win32_ProcessTrace"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &events);
            if (FAILED(hr))
            {
                report.status = Status::Unavailable;
                report.detail = QStringLiteral("Win32_ProcessTrace | HRESULT=0x%1").arg(quint32(hr), 8, 16, QChar('0'));
                return;
            }
            QElapsedTimer clock;
            clock.start();
            quint64 malformed = 0;
            const QString scope = QStringLiteral("WMI ROOT\\CIMV2");
            while (clock.elapsed() < 5000 && report.count < 1024)
            {
                if (canceled(stop)) { report.status = Status::Cancelled; return; }
                ULONG returned = 0;
                CComPtr<IWbemClassObject> event;
                hr = events->Next(100, 1, &event, &returned);
                if (FAILED(hr) || hr == WBEM_S_FALSE) { report.status = Status::Partial; break; }
                if (!returned || !event) continue;
                const auto kind = property(event, L"__CLASS");
                if (kind != QStringLiteral("Win32_ProcessStartTrace") && kind != QStringLiteral("Win32_ProcessStopTrace")) continue;
                bool ok = false;
                const auto pid = property(event, L"ProcessID").toUInt(&ok);
                const auto time = property(event, L"TIME_CREATED");
                if (!ok || time.isEmpty()) { ++malformed; continue; }
                auto& row = append(scan, report, 40, scope);
                row.historical = true;
                row.pid = pid;
                row.image = property(event, L"ProcessName");
                row.detail = QStringLiteral("%1 | event FILETIME=%2 | PPID=%3 | session=%4")
                    .arg(kind, time, property(event, L"ParentProcessID"), property(event, L"SessionID"));
            }
            if (malformed || report.count >= 1024) report.status = Status::Partial;
            report.detail = QStringLiteral("Win32_ProcessTrace | %1 ms | malformed=%2 | HRESULT=0x%3")
                .arg(clock.elapsed()).arg(malformed).arg(quint32(hr), 0, 16);
        }

        void readExecutablePool(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            constexpr auto flags = KSWORD_ARK_MEMORY_EVIDENCE_FLAG_COMPARE_BIGPOOL_MODULES |
                KSWORD_ARK_MEMORY_EVIDENCE_FLAG_INCLUDE_SUSPECTED_BIGPOOL;
            const auto snapshot = ark::DriverClient().queryKernelMemoryEvidence(flags,
                KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_ROWS, 0, 0, KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BYTES,
                KSWORD_ARK_MEMORY_EVIDENCE_HARD_MAX_BIGPOOL_ROWS, 0);
            const bool queried = (snapshot.sourceFlags & KSWORD_ARK_MEMORY_EVIDENCE_SOURCE_BIGPOOL_QUERIED) != 0;
            const bool validated = (snapshot.sourceFlags & KSWORD_ARK_MEMORY_EVIDENCE_SOURCE_BIGPOOL_VALIDATED) != 0;
            const QString queryReceipt = queried
                ? QStringLiteral("SystemBigPoolInformation NTSTATUS=0x%1").arg(quint32(snapshot.bigPoolQueryStatus), 8, 16, QChar('0'))
                : QStringLiteral("无大池系统查询回执");
            report.detail = QStringLiteral("%1 | scan NTSTATUS=0x%2").arg(queryReceipt)
                .arg(quint32(snapshot.lastStatus), 8, 16, QChar('0'));
            if (!snapshot.io.ok || snapshot.unsupported)
            {
                report.status = snapshot.unsupported || snapshot.io.deviceOpenFailed ||
                    snapshot.io.win32Error == ERROR_INVALID_PARAMETER || snapshot.io.win32Error == ERROR_NOT_SUPPORTED ||
                    snapshot.io.win32Error == ERROR_INVALID_FUNCTION ? Status::Unavailable : Status::Failed;
                report.detail = queried ? report.detail + QChar::LineFeed + QString::fromStdString(snapshot.io.message)
                    : QStringLiteral("Win32=%1 NTSTATUS=0x%2 %3").arg(snapshot.io.win32Error)
                        .arg(quint32(snapshot.io.ntStatus), 8, 16, QChar('0')).arg(QString::fromStdString(snapshot.io.message));
                return;
            }
            if ((snapshot.sourceFlags & flags) != flags || !snapshot.moduleCount ||
                snapshot.status == KSWORD_ARK_MEMORY_EVIDENCE_STATUS_UNAVAILABLE)
            {
                report.status = Status::Unavailable;
                report.detail += QChar::LineFeed + QStringLiteral("未取得可用于大池执行页归属比较的内核模块清单。");
                return;
            }
            if (snapshot.status != KSWORD_ARK_MEMORY_EVIDENCE_STATUS_OK && snapshot.status != KSWORD_ARK_MEMORY_EVIDENCE_STATUS_PARTIAL)
            {
                report.status = Status::Failed;
                return;
            }
            if ((queried && (!validated || snapshot.bigPoolQueryStatus < 0)) || (!queried && !snapshot.bigPoolRowsSeen))
            {
                const auto cause = quint32(queried && snapshot.bigPoolQueryStatus < 0 ? snapshot.bigPoolQueryStatus : snapshot.lastStatus);
                report.status = cause == 0xc0000022U || cause == 0xc0000003U || cause == 0xc00000bbU ||
                    (!queried && !cause) ? Status::Unavailable : Status::Failed;
                report.detail += QChar::LineFeed + QStringLiteral("未取得通过校验的大池目录。");
                return;
            }
            report.status = Status::Partial; // Sampling the first page of large allocations cannot cover all kernel VA.
            constexpr auto required = KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_PRESENT | KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_EXECUTE;
            for (const auto& entry : snapshot.entries)
            {
                if (canceled(stop)) { report.status = Status::Cancelled; return; }
                if (entry.evidenceKind != KSWORD_ARK_MEMORY_EVIDENCE_KIND_BIGPOOL ||
                    entry.ownerKind == KSWORD_ARK_MEMORY_EVIDENCE_OWNER_LOADED_MODULE || !entry.virtualAddress ||
                    (entry.permissionFlags & required) != required ||
                    (entry.permissionFlags & KSWORD_ARK_MEMORY_EVIDENCE_PERMISSION_NX) ||
                    !(entry.riskFlags & KSWORD_ARK_MEMORY_EVIDENCE_RISK_NONMODULE_EXECUTABLE)) continue;
                auto& row = append(scan, report, 62, {});
                row.category = QStringLiteral("模块外内核可执行内存");
                row.objectAddress = entry.virtualAddress;
                row.detail = QStringLiteral("BigPool | tag=0x%1 | size=%2 | PTE=0x%3 | risk=0x%4")
                    .arg(entry.bigPoolTag, 0, 16).arg(entry.regionSize)
                    .arg(entry.permissionFlags, 0, 16).arg(entry.riskFlags, 0, 16);
            }
            report.detail += QChar::LineFeed + QStringLiteral("大池目录已访问 %1 项，尝试检查 %2 个首页，模块清单 %3 项，返回 %4/%5，扫描标志 0x%6。")
                .arg(snapshot.bigPoolRowsSeen).arg(snapshot.bytesScanned / 4096).arg(snapshot.moduleCount)
                .arg(snapshot.returnedRows).arg(snapshot.totalRows).arg(snapshot.responseFlags, 0, 16);
        }

        DWORD readPrefetch(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            wchar_t windows[MAX_PATH]{};
            const auto length = GetWindowsDirectoryW(windows, MAX_PATH);
            if (!length || length >= MAX_PATH) return ERROR_BAD_PATHNAME;
            const QDir directory(QString::fromWCharArray(windows) + QStringLiteral("/Prefetch"));
            WIN32_FIND_DATAW data{};
            const auto pattern = QDir::toNativeSeparators(directory.filePath(QStringLiteral("*.pf"))).toStdWString();
            struct Find { HANDLE h; ~Find() { if (h != INVALID_HANDLE_VALUE) FindClose(h); } } find{FindFirstFileW(pattern.c_str(), &data)};
            if (find.h == INVALID_HANDLE_VALUE) {
                const auto error = GetLastError();
                return error == ERROR_FILE_NOT_FOUND ? ERROR_SUCCESS : error;
            }
            DWORD skipped = 0, visited = 0;
            do {
                if (canceled(stop)) return ERROR_CANCELLED;
                if (++visited > 512) return ERROR_MORE_DATA;
                if (data.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) continue;
                const auto name = QString::fromWCharArray(data.cFileName);
                const auto path = directory.filePath(name);
                QFile file(path);
                if (!file.open(QIODevice::ReadOnly)) { ++skipped; continue; }
                const auto header = file.read(8);
                if (header.size() != 8 || !(header.mid(4, 4) == "SCCA" ||
                    (header.startsWith("MAM") && (uchar(header[3]) & 0x7f) == 4))) { ++skipped; continue; }
                auto& row = append(scan, report, 43, directory.absolutePath());
                row.historical = true;
                row.category = QStringLiteral("Prefetch");
                const auto base = QFileInfo(name).completeBaseName();
                const auto dash = base.lastIndexOf(QChar('-'));
                row.image = dash > 0 ? base.left(dash) : base;
                const auto write = (quint64(data.ftLastWriteTime.dwHighDateTime) << 32) | data.ftLastWriteTime.dwLowDateTime;
                row.detail = QStringLiteral("%1 | file last-write FILETIME=%2").arg(path).arg(write);
            } while (FindNextFileW(find.h, &data));
            const auto err = GetLastError();
            return err != ERROR_NO_MORE_FILES ? err : skipped ? ERROR_PARTIAL_COPY : ERROR_SUCCESS;
        }

        DWORD readAmcache(ScanResult& scan, MethodReport& report, const CancelCheck& stop)
        {
            constexpr wchar_t subkey[] = L"AMCACHE\\Root\\InventoryApplicationFile";
            struct Key { HKEY h = nullptr; ~Key() { if (h) RegCloseKey(h); } } key;
            const auto error = RegOpenKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key.h);
            if (error != ERROR_SUCCESS) return error;
            unsigned skipped = 0;
            for (DWORD index = 0; ; ++index)
            {
                if (canceled(stop)) return ERROR_CANCELLED;
                wchar_t child[256]{};
                DWORD length = static_cast<DWORD>(std::size(child));
                FILETIME write{};
                const auto status = RegEnumKeyExW(key.h, index, child, &length, nullptr, nullptr, nullptr, &write);
                if (status == ERROR_NO_MORE_ITEMS) return skipped ? ERROR_PARTIAL_COPY : ERROR_SUCCESS;
                if (status != ERROR_SUCCESS) return status;
                if (index == 1024) return ERROR_MORE_DATA;
                std::array<wchar_t, 32768> path{};
                DWORD bytes = sizeof(path);
                if (RegGetValueW(key.h, child, L"LowerCaseLongPath", RRF_RT_REG_SZ, nullptr, path.data(), &bytes) != ERROR_SUCCESS)
                { ++skipped; continue; }
                const auto source = QStringLiteral("HKLM\\AMCACHE\\Root\\InventoryApplicationFile");
                auto& row = append(scan, report, 43, source);
                row.historical = true;
                row.category = QStringLiteral("Amcache inventory");
                row.image = QString::fromWCharArray(path.data());
                row.detail = QStringLiteral("%1\\%2 | inventory key last-write FILETIME=%3")
                    .arg(source, QString::fromWCharArray(child)).arg((quint64(write.dwHighDateTime) << 32) | write.dwLowDateTime);
            }
        }
    }

    bool CollectResearchActivity(const int id, const ScanInputs& inputs, ScanResult& scan,
        MethodReport& report, const CancelCheck& stop)
    {
        if (id != 40 && id != 43 && id != 58 && id != 60 && id != 61 && id != 62) return false;
        if (canceled(stop)) { report.status = Status::Cancelled; return true; }
        if (id == 40) watchProcessTrace(scan, report, stop);
        else if (id == 43)
        {
            const auto prefetch = readPrefetch(scan, report, stop);
            const auto amcache = canceled(stop) ? ERROR_CANCELLED : readAmcache(scan, report, stop);
            MethodReport services;
            services.method = report.method;
            services.researchId = 43;
            if (!canceled(stop)) ReadServiceInstallHistory(scan, services, stop);
            report.count += services.count;
            if (canceled(stop) || prefetch == ERROR_CANCELLED || amcache == ERROR_CANCELLED || services.status == Status::Cancelled)
                report.status = Status::Cancelled;
            else if (prefetch != ERROR_SUCCESS || amcache != ERROR_SUCCESS || services.status != Status::Complete)
                report.status = report.count || !prefetch || !amcache || services.status == Status::Complete ? Status::Partial : Status::Unavailable;
            report.detail = QStringLiteral("Prefetch Win32=%1 | Amcache Win32=%2 | SCM 7045: %3")
                .arg(prefetch).arg(amcache).arg(services.detail);
        }
        else if (id == 62) readExecutablePool(scan, report, stop);
        else readFindEvil(id, inputs.memProcFsRoot, scan, report, stop);
        return true;
    }
}
