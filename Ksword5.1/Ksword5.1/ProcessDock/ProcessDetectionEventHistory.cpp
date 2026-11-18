#include "ProcessDetectionForensics.h"
#include <QHash>
#include <QXmlStreamReader>
#include <array>
#include <vector>
#include <windows.h>
#include <winevt.h>

#pragma comment(lib, "wevtapi.lib")

namespace ksword::detection
{
    namespace
    {
        struct EventHandle
        {
            EVT_HANDLE handle;
            ~EventHandle() { if (handle) EvtClose(handle); }
        };

        bool readEvent(EVT_HANDLE event, Evidence& evidence)
        {
            DWORD used = 0, count = 0;
            EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &count);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used > 1024 * 1024) return false;
            std::vector<wchar_t> buffer(used / sizeof(wchar_t) + 1);
            if (!EvtRender(nullptr, event, EvtRenderEventXml, used, buffer.data(), &used, &count)) return false;
            QXmlStreamReader xml(QString::fromWCharArray(buffer.data()));
            QString id, record, timestamp;
            QHash<QString, QString> fields;
            while (!xml.atEnd())
            {
                xml.readNext();
                if (!xml.isStartElement()) continue;
                const auto name = xml.name();
                if (name == u"TimeCreated") timestamp = xml.attributes().value(u"SystemTime").toString();
                else if (name == u"EventID") id = xml.readElementText();
                else if (name == u"EventRecordID") record = xml.readElementText();
                else if (name == u"Data")
                {
                    const auto key = xml.attributes().value(u"Name").toString();
                    fields.insert(key, xml.readElementText());
                }
            }
            bool ok = false;
            const QString pidText = fields.value(id == u"4688" ? QStringLiteral("NewProcessId") : QStringLiteral("ProcessId"));
            evidence.pid = pidText.toUInt(&ok, pidText.startsWith(QLatin1String("0x"), Qt::CaseInsensitive) ? 16 : 10);
            if (xml.hasError() || !ok || id.isEmpty() || timestamp.isEmpty() || record.isEmpty()) return false;
            evidence.image = fields.value(id == u"4688" ? QStringLiteral("NewProcessName")
                : id == u"4689" ? QStringLiteral("ProcessName") : QStringLiteral("Image"));
            evidence.historical = true;
            evidence.detail = QStringLiteral("EventID=%1 | RecordID=%2 | UTC=%3").arg(id, record, timestamp);
            const auto guid = fields.value(QStringLiteral("ProcessGuid"));
            if (!guid.isEmpty()) evidence.detail += QStringLiteral(" | ProcessGuid=%1").arg(guid);
            return true;
        }
    }

    void ReadEventHistory(ScanResult& result, MethodReport& report, const CancelCheck& stop)
    {
        const bool sysmon = report.method == SysmonHistory;
        const wchar_t* channel = sysmon ? L"Microsoft-Windows-Sysmon/Operational" : L"Security";
        const wchar_t* filter = sysmon
            ? L"*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1 or EventID=5 or EventID=25) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"
            : L"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4688 or EventID=4689) and TimeCreated[timediff(@SystemTime) <= 86400000]]]";
        EventHandle query{EvtQuery(nullptr, channel, filter, EvtQueryChannelPath | EvtQueryReverseDirection)};
        if (!query.handle)
        {
            const DWORD error = GetLastError();
            report.status = Status::Unavailable;
            report.detail = QStringLiteral("%1 | Win32=%2").arg(QString::fromWCharArray(channel)).arg(error);
            return;
        }
        report.detail = QStringLiteral("最近 24 小时，最多读取 512 条匹配事件。");
        quint64 seen = 0;
        for (;;)
        {
            if (stop()) { report.status = Status::Cancelled; return; }
            std::array<EVT_HANDLE, 16> batch{};
            DWORD n = 0;
            if (!EvtNext(query.handle, DWORD(batch.size()), batch.data(), 1000, 0, &n))
            {
                const DWORD error = GetLastError();
                if (error != ERROR_NO_MORE_ITEMS)
                {
                    report.status = seen ? Status::Partial : Status::Failed;
                    report.detail += QStringLiteral(" Win32=%1").arg(error);
                }
                return;
            }
            for (DWORD i = 0; i < n; ++i)
            {
                EventHandle item{batch[i]};
                if (++seen > 512) { report.status = Status::Partial; continue; }
                Evidence evidence;
                evidence.methods = report.method;
                evidence.scope = QString::fromWCharArray(channel);
                if (!readEvent(item.handle, evidence)) { report.status = Status::Partial; continue; }
                result.evidence.append(std::move(evidence));
                ++report.count;
            }
            if (!n || seen > 512) return;
        }
    }
}
