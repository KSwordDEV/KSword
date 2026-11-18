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

    }

    bool DecodeProcessHistoryEvent(const QString& document, Evidence& evidence)
    {
        QXmlStreamReader xml(document);
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
                fields.insert(key.toCaseFolded(), xml.readElementText());
            }
        }
        if (xml.hasError() || id.isEmpty() || timestamp.isEmpty() || record.isEmpty()) return false;
        evidence.historical = true;
        evidence.detail = QStringLiteral("EventID=%1 | RecordID=%2 | UTC=%3").arg(id, record, timestamp);
        if (id == u"7045")
        {
            evidence.pid = 0; // The SCM registration event carries no process identity.
            const auto service = fields.value(QStringLiteral("servicename"));
            evidence.image = fields.value(QStringLiteral("imagepath"));
            if (service.isEmpty() || evidence.image.isEmpty()) return false;
            evidence.category = QStringLiteral("Service installation");
            evidence.detail += QStringLiteral(" | ServiceName=%1 | ServiceType=%2 | StartType=%3")
                .arg(service, fields.value(QStringLiteral("servicetype")), fields.value(QStringLiteral("starttype")));
            return true;
        }
        bool ok = false;
        const bool directed = id == u"8" || id == u"10";
        const QString pidText = fields.value(directed ? QStringLiteral("targetprocessid") :
            id == u"4688" ? QStringLiteral("newprocessid") : QStringLiteral("processid"));
        evidence.pid = pidText.toUInt(&ok, pidText.startsWith(QLatin1String("0x"), Qt::CaseInsensitive) ? 16 : 10);
        if (!ok) return false;
        evidence.image = fields.value(directed ? QStringLiteral("targetimage") :
            id == u"4688" ? QStringLiteral("newprocessname") :
            id == u"4689" ? QStringLiteral("processname") : QStringLiteral("image"));
        const auto guid = fields.value(directed ? QStringLiteral("targetprocessguid") : QStringLiteral("processguid"));
        if (!guid.isEmpty()) evidence.detail += QStringLiteral(" | ProcessGuid=%1").arg(guid);
        if (directed)
        {
            for (const auto key : {"SourceProcessId", "SourceProcessGuid", "SourceImage", "TargetProcessId",
                "TargetProcessGuid", "TargetImage", "NewThreadId", "StartAddress", "GrantedAccess", "CallTrace"})
            {
                const auto name = QString::fromLatin1(key);
                const auto value = fields.value(name.toCaseFolded());
                if (!value.isEmpty()) evidence.detail += QStringLiteral(" | %1=%2").arg(name, value);
            }
        }
        return true;
    }
    namespace
    {
        bool readEvent(EVT_HANDLE event, Evidence& evidence)
        {
            DWORD used = 0, count = 0;
            EvtRender(nullptr, event, EvtRenderEventXml, 0, nullptr, &used, &count);
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || used > 1024 * 1024) return false;
            std::vector<wchar_t> buffer(used / sizeof(wchar_t) + 1);
            if (!EvtRender(nullptr, event, EvtRenderEventXml, used, buffer.data(), &used, &count)) return false;
            return DecodeProcessHistoryEvent(QString::fromWCharArray(buffer.data()), evidence);
        }
    }

    static void readChannel(ScanResult& result, MethodReport& report, const CancelCheck& stop,
        const wchar_t* channel, const wchar_t* filter)
    {
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
            if (stop && stop()) { report.status = Status::Cancelled; return; }
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
                evidence.researchId = report.researchId;
                evidence.scope = QString::fromWCharArray(channel);
                if (!readEvent(item.handle, evidence)) { report.status = Status::Partial; continue; }
                result.evidence.append(std::move(evidence));
                ++report.count;
            }
            if (!n || seen > 512) return;
        }
    }
    void ReadEventHistory(ScanResult& result, MethodReport& report, const CancelCheck& stop)
    {
        if (report.method == SysmonHistory)
            readChannel(result, report, stop, L"Microsoft-Windows-Sysmon/Operational",
                L"*[System[Provider[@Name='Microsoft-Windows-Sysmon'] and (EventID=1 or EventID=5 or EventID=8 or EventID=10 or EventID=25) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
        else readChannel(result, report, stop, L"Security",
            L"*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4688 or EventID=4689) and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
    }
    void ReadServiceInstallHistory(ScanResult& result, MethodReport& report, const CancelCheck& stop)
    {
        readChannel(result, report, stop, L"System",
            L"*[System[Provider[@Name='Service Control Manager'] and EventID=7045 and TimeCreated[timediff(@SystemTime) <= 86400000]]]");
    }
}
