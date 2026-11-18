#include "ProcessDetectionForensics.h"
#include <QFileInfo>
#include <QHash>
#include <evntrace.h>
#include <evntcons.h>
#include <tdh.h>
#include <exception>

#pragma comment(lib, "tdh.lib")

namespace ksword::detection
{
    namespace
    {
        // Classic kernel Process/Thread and the manifest Microsoft-Windows-Kernel-Process provider.
        constexpr GUID processGuid{0x3d6fa8d0,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
        constexpr GUID threadGuid{0x3d6fa8d1,0xfe05,0x11d0,{0x9d,0xda,0x00,0xc0,0x4f,0xd7,0xba,0x7c}};
        constexpr GUID kernelProcess{0x22fb2cd6,0x0e7b,0x422b,{0xa0,0xc7,0x2f,0xad,0x1f,0xd0,0xe7,0x16}};
        constexpr quint64 limit = 4096;

        bool readId(EVENT_RECORD* event, const wchar_t* name, quint32& value)
        {
            PROPERTY_DATA_DESCRIPTOR prop{};
            prop.PropertyName = reinterpret_cast<ULONG_PTR>(name);
            prop.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            return TdhGetPropertySize(event, 0, nullptr, 1, &prop, &size) == ERROR_SUCCESS &&
                size == sizeof(value) && TdhGetProperty(event, 0, nullptr, 1, &prop, size,
                    reinterpret_cast<PBYTE>(&value)) == ERROR_SUCCESS;
        }

        struct Reader
        {
            ScanResult& scan;
            MethodReport& report;
            const QString& path;
            const CancelCheck& stop;
            bool traceLostEvents = false;
            QHash<quint32, quint32> owners;
            quint64 omitted = 0;
            std::exception_ptr failure;

            bool finished() const { return failure || stop() || (report.count >= limit && omitted); }
            void record(EVENT_RECORD* event)
            {
                if (finished()) return;
                const auto& header = event->EventHeader;
                const bool manifest = IsEqualGUID(header.ProviderId, kernelProcess);
                const bool process = IsEqualGUID(header.ProviderId, processGuid);
                const bool thread = IsEqualGUID(header.ProviderId, threadGuid);
                const auto id = header.EventDescriptor.Id;
                const auto op = header.EventDescriptor.Opcode;
                const bool life = op >= 1 && op <= 4;
                const bool cswitch = thread && op == 36;
                if (report.method == EtlProcesses)
                {
                    if (!((process && (life || op == 39)) || (manifest && (id == 1 || id == 2)))) return;
                }
                else if (!((thread && (life || cswitch)) || (manifest && (id == 3 || id == 4)))) return;
                if (report.count >= limit) { ++omitted; return; }
                Evidence evidence;
                quint32 tid = 0;
                if (cswitch)
                {
                    if (!readId(event, L"NewThreadId", tid)) { ++omitted; return; }
                    // Dropped lifetime events can make a recycled TID point at the wrong PID.
                    if (!traceLostEvents) evidence.pid = owners.value(tid);
                }
                else
                {
                    if (!(readId(event, L"ProcessId", evidence.pid) || readId(event, L"ProcessID", evidence.pid)))
                    { ++omitted; return; }
                    if (report.method == EtlThreads)
                    {
                        if (!(readId(event, L"TThreadId", tid) || readId(event, L"ThreadID", tid)))
                        { ++omitted; return; }
                        if ((thread && op == 2) || (manifest && id == 4)) owners.remove(tid);
                        else owners.insert(tid, evidence.pid);
                    }
                }
                evidence.methods = report.method;
                evidence.historical = true;
                evidence.scope = path;
                evidence.detail = QStringLiteral("%1 | id=%2 | opcode=%3 | TID=%4 | FILETIME=%5")
                    .arg(cswitch ? QStringLiteral("CSwitch") : manifest ? QStringLiteral("Kernel-Process")
                        : process ? QStringLiteral("Process") : QStringLiteral("Thread"))
                    .arg(id).arg(op).arg(tid).arg(header.TimeStamp.QuadPart);
                scan.evidence.append(std::move(evidence));
                ++report.count;
            }
        };

        void WINAPI eventCallback(EVENT_RECORD* event)
        {
            auto& reader = *static_cast<Reader*>(event->UserContext);
            try { reader.record(event); }
            catch (...) { reader.failure = std::current_exception(); }
        }

        ULONG WINAPI bufferCallback(EVENT_TRACE_LOGFILEW* buffer)
        {
            auto& reader = *static_cast<Reader*>(buffer->Context);
            return !reader.finished();
        }
    }

    void ReadEtl(ScanResult& result, MethodReport& report, const QString& path, const CancelCheck& stop)
    {
        const QFileInfo file(path);
        if (!file.isAbsolute() || !file.isFile())
        {
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("请在检测方法中选择 ETL 文件。");
            return;
        }
        auto nativePath = file.absoluteFilePath().toStdWString();
        Reader reader{result, report, path, stop, false, {}, 0, {}};
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName = nativePath.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD;
        log.EventRecordCallback = eventCallback;
        log.BufferCallback = bufferCallback;
        log.Context = &reader;
        auto handle = OpenTraceW(&log);
        if (handle == INVALID_PROCESSTRACE_HANDLE)
        {
            const auto error = GetLastError();
            report.status = Status::Failed;
            report.detail = QStringLiteral("OpenTraceW: %1").arg(error);
            return;
        }
        reader.traceLostEvents = log.LogfileHeader.EventsLost != 0;
        const auto code = ProcessTrace(&handle, 1, nullptr, nullptr);
        CloseTrace(handle);
        if (reader.failure) std::rethrow_exception(reader.failure);
        if (stop()) report.status = Status::Cancelled;
        else if (code != ERROR_SUCCESS && code != ERROR_CANCELLED)
            report.status = report.count ? Status::Partial : Status::Failed;
        else if (code == ERROR_CANCELLED || reader.omitted || log.LogfileHeader.EventsLost)
            report.status = Status::Partial;
        report.detail = QStringLiteral("%1 | Win32=%2 | EventsLost=%3 | skipped=%4 | limit=%5")
            .arg(path).arg(code).arg(log.LogfileHeader.EventsLost).arg(reader.omitted).arg(limit);
    }
}
