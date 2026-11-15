#include <Windows.h>
#include "UacDesk.h"
#include "UacScanWorker.h"
#include "../Ksword5.1/Ksword5.1/theme.h"

#include <QApplication>
#include <QBoxLayout>
#include <QEvent>
#include <QDir>
#include <QFileInfo>
#include <QGuiApplication>
#include <QLabel>
#include <QMessageBox>
#include <QFileIconProvider>
#include <QImage>
#include <QPainter>
#include <QPixmap>
#include <QPushButton>
#include <QRegularExpression>
#include <QScreen>
#include <QStyle>
#include <QStyleHints>
#include <QWindow>
#include <QMouseEvent>

#include <Psapi.h>
#include <TlHelp32.h>
#include <Sddl.h>
#include <Tdh.h>
#include <Objbase.h>
#include <oleacc.h>
#include <UIAutomation.h>
#include <WtsApi32.h>
#include <shellapi.h>
#include <strsafe.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

#include <algorithm>
#include <cwctype>
#include <cstring>
#include <functional>
#include <limits>
#include <numeric>
#include <utility>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "OleAut32.lib")
#pragma comment(lib, "Oleacc.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Tdh.lib")
#pragma comment(lib, "Uiautomationcore.lib")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Wtsapi32.lib")
#pragma comment(lib, "Wintrust.lib")

namespace
{
    constexpr wchar_t kWinlogonDesktop[] = L"winsta0\\Winlogon";
    constexpr wchar_t kWinlogonDesktopName[] = L"Winlogon";
    constexpr wchar_t kOwnerMutexPrefix[] = L"Global\\KswordUacDesk.Owner.";
    constexpr wchar_t kReadyEventPrefix[] = L"Global\\KswordUacDesk.Ready.";
    constexpr ULONGLONG kLuaDiagnosticKeyword = 0x8000000000000000ULL;
    constexpr ULONGLONG kSystemAlpcKeyword = 0x0000000000000001ULL;
    constexpr GUID kUacAlpcEtwSessionGuid =
        {0x7a2d2d2c, 0x8ca4, 0x4a95, {0x9c, 0x84, 0x4f, 0x65, 0x6e, 0x9c, 0x7b, 0x1e}};
    constexpr wchar_t kEtwSessionPrefix[] = L"KswordUacDesk.";
    constexpr DWORD kDesktopSwitchEvent = EVENT_SYSTEM_DESKTOPSWITCH;
    constexpr ULONG kAlpcSendEvent = 33;
    constexpr ULONG kAlpcReceiveEvent = 34;
    constexpr quint64 kAlpcSendRetentionMs = 10000;
    constexpr quint64 kUacCorrelationWindowMs = 5000;
    // AppInfo's consent request is private implementation detail, not a
    // supported ABI.  The currently tested layouts differ between the
    // Windows 10 and Windows 11 build families.
    constexpr size_t kAppInfoWin10OriginPidOffset = 0x68;
    constexpr size_t kAppInfoWin10TargetPathOffset = 0x70;
    constexpr size_t kAppInfoWin11OriginPidOffset = 0xF0;
    constexpr size_t kAppInfoWin11TargetPathOffset = 0xFC;
    constexpr DWORD kWindows11BuildNumber = 22000;
    const GUID kLuaProvider = {0x93c05d69, 0x51a3, 0x485e, {0x87, 0x7f, 0x18, 0x06, 0xa8, 0x73, 0x13, 0x46}};
    const GUID kSystemAlpcProvider = {0xfcb9baaf, 0xe529, 0x4980, {0x92, 0xe9, 0xce, 0xd1, 0xa6, 0xaa, 0xdf, 0xdf}};
    // The legacy ALPCGuid is what the classic SystemTraceProvider emits in the
    // event header. Microsoft documents that system-provider enablement does not
    // rewrite those records to the individual SystemAlpcProvider GUID.
    const GUID kLegacyAlpcProvider = {0x45d8cccd, 0x539f, 0x4b72, {0xa8, 0xb7, 0x5c, 0x68, 0x31, 0x42, 0x60, 0x9a}};
    UacEventMonitor* g_eventMonitor = nullptr;

    bool scanCanceled(const UacScanCancellation* cancel)
    {
        return cancel && cancel->canceled();
    }

    struct WindowScanContext
    {
        QVector<HWND> windows;
        QStringList text;
        const UacScanCancellation* budget = nullptr;
    };

    QString winError(DWORD error = GetLastError())
    {
        wchar_t buffer[512] = {};
        FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0,
                       buffer, static_cast<DWORD>(std::size(buffer)), nullptr);
        return QString::fromWCharArray(buffer).trimmed() + QStringLiteral(" (0x") + QString::number(error, 16) + QLatin1Char(')');
    }

    DWORD windowsBuildNumber()
    {
        using RtlGetVersionFn = LONG (WINAPI*)(PRTL_OSVERSIONINFOW);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto rtlGetVersion = ntdll
            ? reinterpret_cast<RtlGetVersionFn>(GetProcAddress(ntdll, "RtlGetVersion"))
            : nullptr;
        if (!rtlGetVersion)
            return 0;

        RTL_OSVERSIONINFOEXW version{};
        version.dwOSVersionInfoSize = sizeof(version);
        return rtlGetVersion(reinterpret_cast<PRTL_OSVERSIONINFOW>(&version)) == 0
            ? version.dwBuildNumber
            : 0;
    }

    ULONG stopTraceSession(TRACEHANDLE session, const QString& traceName)
    {
        const std::wstring name = traceName.toStdWString();
        std::vector<BYTE> buffer(sizeof(EVENT_TRACE_PROPERTIES) +
                                 (name.size() + 1) * sizeof(wchar_t), 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(buffer.data());
        properties->Wnode.BufferSize = static_cast<ULONG>(buffer.size());
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        return ControlTraceW(session, name.c_str(), properties, EVENT_TRACE_CONTROL_STOP);
    }

    void closeTraceConsumer(std::atomic<TRACEHANDLE>& consumer)
    {
        const TRACEHANDLE handle = consumer.exchange(0);
        if (handle != 0 && handle != INVALID_PROCESSTRACE_HANDLE)
            CloseTrace(handle);
    }

    QString timestampedEtwSessionName(const QString& component = {})
    {
        const QString timestamp = QDateTime::currentDateTime().toString(QStringLiteral("yyyyMMddHHmmsszzz"));
        const QString stem = component.isEmpty()
            ? QStringLiteral("KswordUacDesk")
            : QStringLiteral("KswordUacDesk.") + component;
        return QStringLiteral("%1.%2.%3").arg(stem, timestamp).arg(GetCurrentProcessId());
    }

    void cleanupStaleEtwSessions()
    {
        constexpr ULONG kEtwQueryCapacity = 128;
        constexpr ULONG kEtwPropertyBytes = sizeof(EVENT_TRACE_PROPERTIES) + 2048;
        std::vector<std::vector<BYTE>> buffers;
        buffers.resize(kEtwQueryCapacity);
        std::vector<PEVENT_TRACE_PROPERTIES> properties;
        properties.reserve(kEtwQueryCapacity);
        for (auto& buffer : buffers)
        {
            buffer.resize(kEtwPropertyBytes, 0);
            auto* value = reinterpret_cast<PEVENT_TRACE_PROPERTIES>(buffer.data());
            value->Wnode.BufferSize = kEtwPropertyBytes;
            properties.push_back(value);
        }

        ULONG loggerCount = 0;
        const ULONG queryStatus = QueryAllTracesW(properties.data(), kEtwQueryCapacity, &loggerCount);
        if (queryStatus != ERROR_SUCCESS && queryStatus != ERROR_MORE_DATA)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "etw-cleanup: QueryAllTracesW failed status=0x%1 (%2)")
                .arg(queryStatus, 0, 16).arg(winError(queryStatus)));
            return;
        }

        const ULONG inspected = std::min(loggerCount, kEtwQueryCapacity);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "etw-cleanup: enumerated sessions=%1 queryStatus=0x%2")
            .arg(inspected).arg(queryStatus, 0, 16));
        for (ULONG i = 0; i < inspected; ++i)
        {
            auto* value = properties[i];
            if (!value || value->LoggerNameOffset < sizeof(EVENT_TRACE_PROPERTIES) ||
                value->LoggerNameOffset >= kEtwPropertyBytes)
                continue;
            const auto* name = reinterpret_cast<const wchar_t*>(
                buffers[i].data() + value->LoggerNameOffset);
            const QString sessionName = QString::fromWCharArray(name).trimmed();
            if (!sessionName.startsWith(QString::fromWCharArray(kEtwSessionPrefix), Qt::CaseSensitive))
                continue;

            const ULONG stopStatus = ControlTraceW(0, name, value, EVENT_TRACE_CONTROL_STOP);
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "etw-cleanup: stop name=%1 status=0x%2")
                .arg(sessionName).arg(stopStatus, 0, 16));
        }
    }

    QString lowerFileName(const QString& path)
    {
        return QFileInfo(path).fileName().toLower();
    }

    QString versionStringValue(const QString& path, const wchar_t* valueName)
    {
        if (path.isEmpty() || !valueName) return {};
        const std::wstring widePath = path.toStdWString();
        DWORD ignored = 0;
        const DWORD size = GetFileVersionInfoSizeW(widePath.c_str(), &ignored);
        if (size == 0) return {};
        std::vector<BYTE> buffer(size);
        if (!GetFileVersionInfoW(widePath.c_str(), 0, size, buffer.data())) return {};

        struct Translation { WORD language; WORD codePage; };
        Translation* translations = nullptr;
        UINT translationBytes = 0;
        if (VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
                           reinterpret_cast<LPVOID*>(&translations), &translationBytes) &&
            translations && translationBytes >= sizeof(Translation))
        {
            const UINT count = translationBytes / sizeof(Translation);
            for (UINT i = 0; i < count; ++i)
            {
                const QString query = QStringLiteral("\\StringFileInfo\\%1%2\\%3")
                    .arg(translations[i].language, 4, 16, QLatin1Char('0'))
                    .arg(translations[i].codePage, 4, 16, QLatin1Char('0'))
                    .arg(QString::fromWCharArray(valueName));
                LPVOID value = nullptr;
                UINT valueChars = 0;
                if (VerQueryValueW(buffer.data(), query.toStdWString().c_str(), &value, &valueChars) &&
                    value && valueChars > 0)
                    return QString::fromWCharArray(static_cast<const wchar_t*>(value), static_cast<int>(valueChars)).trimmed();
            }
        }
        return {};
    }

    bool isSamePath(const QString& left, const QString& right)
    {
        return QString::compare(QDir::cleanPath(left), QDir::cleanPath(right), Qt::CaseInsensitive) == 0;
    }

    QString windowText(HWND hwnd)
    {
        const int length = GetWindowTextLengthW(hwnd);
        if (length <= 0)
            return {};
        std::wstring value(static_cast<size_t>(length) + 1, L'\0');
        GetWindowTextW(hwnd, value.data(), length + 1);
        return QString::fromStdWString(value.c_str());
    }

    QString windowClassName(HWND hwnd)
    {
        wchar_t buffer[256] = {};
        const int length = GetClassNameW(hwnd, buffer, static_cast<int>(std::size(buffer)));
        return length > 0 ? QString::fromWCharArray(buffer, length) : QStringLiteral("<unknown>");
    }

    bool containsAny(const QString& value, const QStringList& needles)
    {
        for (const QString& needle : needles)
        {
            if (value.contains(needle, Qt::CaseInsensitive))
                return true;
        }
        return false;
    }

    void appendUniqueText(QStringList& values, const QString& value)
    {
        const QString trimmed = value.trimmed();
        if (trimmed.isEmpty() || trimmed.size() > 512)
            return;
        for (const QString& existing : values)
        {
            if (existing.compare(trimmed, Qt::CaseSensitive) == 0)
                return;
        }
        values.push_back(trimmed);
    }

    QString etwPropertyValue(UCHAR inType, const BYTE* data, ULONG size)
    {
        if (!data || size == 0)
            return {};

        switch (inType)
        {
        case TDH_INTYPE_UNICODESTRING:
        case TDH_INTYPE_COUNTEDSTRING:
        case TDH_INTYPE_NONNULLTERMINATEDSTRING:
        {
            const size_t chars = size / sizeof(wchar_t);
            return QString::fromWCharArray(reinterpret_cast<const wchar_t*>(data), static_cast<int>(chars)).trimmed();
        }
        case TDH_INTYPE_ANSISTRING:
            return QString::fromUtf8(reinterpret_cast<const char*>(data), static_cast<int>(size)).trimmed();
        case TDH_INTYPE_UINT8:
            return size >= 1 ? QString::number(*data) : QString();
        case TDH_INTYPE_UINT16:
        {
            WORD value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_UINT32:
        case TDH_INTYPE_HEXINT32:
        {
            DWORD value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return inType == TDH_INTYPE_HEXINT32
                ? QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0'))
                : QString::number(value);
        }
        case TDH_INTYPE_UINT64:
        case TDH_INTYPE_HEXINT64:
        {
            ULONGLONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return inType == TDH_INTYPE_HEXINT64
                ? QStringLiteral("0x%1").arg(value, 16, 16, QLatin1Char('0'))
                : QString::number(value);
        }
        case TDH_INTYPE_INT32:
        {
            LONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_INT64:
        {
            LONGLONG value = 0;
            if (size < sizeof(value)) return {};
            std::memcpy(&value, data, sizeof(value));
            return QString::number(value);
        }
        case TDH_INTYPE_BOOLEAN:
            return size >= sizeof(BOOL) && *reinterpret_cast<const BOOL*>(data) ? QStringLiteral("true") : QStringLiteral("false");
        default:
            return QByteArray(reinterpret_cast<const char*>(data), static_cast<int>(std::min<ULONG>(size, 32))).toHex(' ').toUpper();
        }
    }

    quint64 currentTraceTimeMs()
    {
        FILETIME fileTime{};
        GetSystemTimePreciseAsFileTime(&fileTime);
        return (static_cast<quint64>(fileTime.dwHighDateTime) << 32 | fileTime.dwLowDateTime) / 10000ULL;
    }

    quint64 eventTraceTimeMs(PEVENT_RECORD record)
    {
        if (!record)
            return currentTraceTimeMs();
        const quint64 raw = static_cast<quint64>(record->EventHeader.TimeStamp.QuadPart);
        return raw > 100000000000ULL ? raw / 10000ULL : currentTraceTimeMs();
    }

    bool tdhNumericProperty(PEVENT_RECORD record, const QStringList& names, ULONGLONG& value)
    {
        value = 0;
        if (!record) return false;
        ULONG infoSize = 0;
        if (TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize) != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return false;
        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS)
            return false;
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0) continue;
            const QString propertyName = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset));
            bool wanted = false;
            for (const QString& name : names)
                if (propertyName.compare(name, Qt::CaseInsensitive) == 0) { wanted = true; break; }
            if (!wanted) continue;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(infoBuffer.data() + property.NameOffset);
            descriptor.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0 || size > sizeof(ULONGLONG))
                return false;
            std::vector<BYTE> data(size);
            if (TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
                return false;
            std::memcpy(&value, data.data(), size);
            return true;
        }
        return false;
    }

    QString tdhStringProperty(PEVENT_RECORD record, const QStringList& names)
    {
        if (!record) return {};
        ULONG infoSize = 0;
        if (TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize) != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return {};
        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        if (TdhGetEventInformation(record, 0, nullptr, info, &infoSize) != ERROR_SUCCESS)
            return {};
        for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0) continue;
            const QString propertyName = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset));
            bool wanted = false;
            for (const QString& name : names)
                if (propertyName.compare(name, Qt::CaseInsensitive) == 0) { wanted = true; break; }
            if (!wanted) continue;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(infoBuffer.data() + property.NameOffset);
            descriptor.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            if (TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &size) != ERROR_SUCCESS || size == 0 || size > 65536)
                return {};
            std::vector<BYTE> data(size);
            if (TdhGetProperty(record, 0, nullptr, 1, &descriptor, size, data.data()) != ERROR_SUCCESS)
                return {};
            return etwPropertyValue(property.nonStructType.InType, data.data(), size);
        }
        return {};
    }

    QString decodeEtwPayload(PEVENT_RECORD record)
    {
        if (!record)
            return {};

        ULONG infoSize = 0;
        TDHSTATUS status = TdhGetEventInformation(record, 0, nullptr, nullptr, &infoSize);
        if (status != ERROR_INSUFFICIENT_BUFFER || infoSize == 0)
            return QStringLiteral("schema-error=0x%1").arg(status, 0, 16);

        std::vector<BYTE> infoBuffer(infoSize);
        auto* info = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
        status = TdhGetEventInformation(record, 0, nullptr, info, &infoSize);
        if (status != ERROR_SUCCESS)
            return QStringLiteral("schema-error=0x%1").arg(status, 0, 16);

        QStringList properties;
        const ULONG propertyCount = std::min<ULONG>(info->TopLevelPropertyCount, 32);
        for (ULONG i = 0; i < propertyCount; ++i)
        {
            const EVENT_PROPERTY_INFO& property = info->EventPropertyInfoArray[i];
            if ((property.Flags & PropertyStruct) != 0 || property.NameOffset == 0)
                continue;

            const wchar_t* propertyName = reinterpret_cast<const wchar_t*>(infoBuffer.data() + property.NameOffset);
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyName);
            descriptor.ArrayIndex = ULONG_MAX;

            ULONG propertySize = 0;
            status = TdhGetPropertySize(record, 0, nullptr, 1, &descriptor, &propertySize);
            if (status != ERROR_SUCCESS || propertySize == 0 || propertySize > 64 * 1024)
            {
                properties.push_back(QStringLiteral("%1=<unreadable:0x%2>")
                                         .arg(QString::fromWCharArray(propertyName))
                                         .arg(status, 0, 16));
                continue;
            }

            std::vector<BYTE> value(propertySize);
            status = TdhGetProperty(record, 0, nullptr, 1, &descriptor, propertySize, value.data());
            if (status != ERROR_SUCCESS)
            {
                properties.push_back(QStringLiteral("%1=<read-failed:0x%2>")
                                         .arg(QString::fromWCharArray(propertyName))
                                         .arg(status, 0, 16));
                continue;
            }

            const QString formatted = etwPropertyValue(property.nonStructType.InType, value.data(), propertySize);
            properties.push_back(QStringLiteral("%1=%2").arg(QString::fromWCharArray(propertyName), formatted.left(512)));
        }
        return properties.join(QStringLiteral(", "));
    }

    ULONG alpcMessageId(PEVENT_RECORD record)
    {
        ULONGLONG value = 0;
        if (!tdhNumericProperty(record, {QStringLiteral("MessageId"), QStringLiteral("MessageID")}, value))
            return 0;
        return static_cast<ULONG>(value);
    }

    QStringList uacTextValues(const QString& automationText)
    {
        QStringList values;
        for (const QString& part : automationText.split(QStringLiteral(" | "), Qt::SkipEmptyParts))
        {
            const int marker = part.indexOf(QStringLiteral("Text="));
            if (marker < 0)
                continue;
            appendUniqueText(values, part.mid(marker + 5));
        }
        return values;
    }

    QString uacApplicationNameFromText(const QString& automationText)
    {
        const QStringList values = uacTextValues(automationText);
        for (const QString& value : values)
        {
            if (value.compare(QStringLiteral("用户帐户控制"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("User Account Control"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("是"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("否"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("Yes"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("No"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("关闭"), Qt::CaseInsensitive) == 0 ||
                value.compare(QStringLiteral("Close"), Qt::CaseInsensitive) == 0 ||
                value.contains(QStringLiteral("允许此应用"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("allow this app"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("已验证的发布者"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("verified publisher"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("显示更多详细信息"), Qt::CaseInsensitive) ||
                value.contains(QStringLiteral("show more details"), Qt::CaseInsensitive))
                continue;
            return value;
        }
        return {};
    }

    QString uacPublisherFromText(const QString& automationText)
    {
        for (const QString& value : uacTextValues(automationText))
        {
            const QStringList separators = {QStringLiteral(":"), QStringLiteral("：")};
            for (const QString& separator : separators)
            {
                const int index = value.indexOf(separator);
                if (index >= 0 && (value.contains(QStringLiteral("发布者"), Qt::CaseInsensitive) ||
                                   value.contains(QStringLiteral("publisher"), Qt::CaseInsensitive)))
                    return value.mid(index + 1).trimmed();
            }
        }
        return {};
    }

    QString uacPathFromText(const QString& automationText)
    {
        static const QRegularExpression pathExpression(
            QStringLiteral(R"(([A-Za-z]:\\[^|\r\n"]+?\.exe))"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch match = pathExpression.match(automationText);
        return match.hasMatch() ? match.captured(1).trimmed() : QString();
    }

    QString desktopProcessName(HWND hwnd)
    {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        ProcessIdentity identity;
        if (pid != 0 && ProcessInspector::query(pid, identity))
            return lowerFileName(identity.imagePath);
        return {};
    }

    QString collectChildText(HWND hwnd, const UacScanCancellation* cancel)
    {
        WindowScanContext context;
        context.budget = cancel;
        EnumChildWindows(hwnd, &UacWindowScanner::enumChildProc, reinterpret_cast<LPARAM>(&context));
        return context.text.join(QStringLiteral(" | "));
    }

    bool getTokenElevation(HANDLE token)
    {
        TOKEN_ELEVATION elevation{};
        DWORD length = 0;
        return GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &length) && elevation.TokenIsElevated != 0;
    }

    bool tokenIsSystem(HANDLE token)
    {
        DWORD length = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &length);
        if (length == 0)
            return false;
        std::vector<BYTE> data(length);
        if (!GetTokenInformation(token, TokenUser, data.data(), length, &length))
            return false;
        const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data());
        PSID systemSid = nullptr;
        SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (!AllocateAndInitializeSid(&ntAuthority, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &systemSid))
            return false;
        const bool result = EqualSid(user->User.Sid, systemSid) != FALSE;
        FreeSid(systemSid);
        return result;
    }

    bool enableTokenPrivilege(HANDLE token, LPCWSTR privilegeName)
    {
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, privilegeName, &luid)) return false;
        TOKEN_PRIVILEGES privileges{};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, sizeof(privileges), nullptr, nullptr)) return false;
        return GetLastError() == ERROR_SUCCESS;
    }

    bool enableCurrentProcessPrivilege(LPCWSTR privilegeName)
    {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
        const bool result = enableTokenPrivilege(token, privilegeName);
        CloseHandle(token);
        return result;
    }

    bool tokenBelongsToLocalSystem(HANDLE token)
    {
        DWORD length = 0;
        GetTokenInformation(token, TokenUser, nullptr, 0, &length);
        if (length == 0) return false;
        std::vector<BYTE> buffer(length);
        if (!GetTokenInformation(token, TokenUser, buffer.data(), length, &length)) return false;
        BYTE sidBuffer[SECURITY_MAX_SID_SIZE]{};
        DWORD sidLength = sizeof(sidBuffer);
        if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sidBuffer, &sidLength)) return false;
        const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
        return EqualSid(user->User.Sid, sidBuffer) != FALSE;
    }

    class ScopedImpersonation final
    {
    public:
        ~ScopedImpersonation() { reset(); }
        bool begin(HANDLE token) { reset(); m_active = ImpersonateLoggedOnUser(token) != FALSE; return m_active; }
        void reset() { if (m_active) RevertToSelf(); m_active = false; }
    private:
        bool m_active = false;
    };

    bool queryTokenSessionId(HANDLE token, DWORD& sessionId, QString& error)
    {
        sessionId = 0;
        DWORD length = 0;
        if (!GetTokenInformation(token, TokenSessionId, nullptr, 0, &length) &&
            GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            error = QStringLiteral("GetTokenInformation(TokenSessionId) 查询大小失败：") + winError();
            return false;
        }
        if (length < sizeof(DWORD) || !GetTokenInformation(token, TokenSessionId, &sessionId, sizeof(sessionId), &length))
        {
            error = QStringLiteral("GetTokenInformation(TokenSessionId) 读取失败：") + winError();
            return false;
        }
        return true;
    }

    bool duplicateSystemTokenForSession(DWORD sessionId, HANDLE& result, QString& error)
    {
        result = nullptr;
        error.clear();
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("token: begin, targetSession=%1").arg(sessionId));
        if (!PrivilegeStage::isProcessElevated())
        {
            error = QStringLiteral("当前阶段不是提升管理员，不能打开 SYSTEM 进程令牌。");
            return false;
        }
        enableCurrentProcessPrivilege(SE_DEBUG_NAME);
        enableCurrentProcessPrivilege(SE_ASSIGNPRIMARYTOKEN_NAME);
        enableCurrentProcessPrivilege(SE_INCREASE_QUOTA_NAME);
        enableCurrentProcessPrivilege(SE_TCB_NAME);
        enableCurrentProcessPrivilege(SE_IMPERSONATE_NAME);

        DWORD sourcePid = 0;
        int bestRank = 0;

        PROCESSENTRY32W entry{sizeof(entry)};
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
        {
            error = QStringLiteral("CreateToolhelp32Snapshot：") + winError();
            return false;
        }
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        {
            DWORD candidateSession = 0;
            ProcessIdToSessionId(entry.th32ProcessID, &candidateSession);
            const bool sameSession = candidateSession == sessionId;
            int rank = 0;
            if (_wcsicmp(entry.szExeFile, L"winlogon.exe") == 0) rank = sameSession ? 40 : 30;
            else if (_wcsicmp(entry.szExeFile, L"services.exe") == 0) rank = sameSession ? 20 : 10;
            if (rank > bestRank) { bestRank = rank; sourcePid = entry.th32ProcessID; }
        }
        CloseHandle(snapshot);
        if (sourcePid == 0)
        {
            error = QStringLiteral("没有找到当前 Session 的 winlogon.exe 或 services.exe SYSTEM 令牌源。");
            return false;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("token: selected source pid=%1 rank=%2").arg(sourcePid).arg(bestRank));

        HANDLE sourceProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, sourcePid);
        if (!sourceProcess)
        {
            error = QStringLiteral("OpenProcess(SYSTEM 令牌源 PID=%1) 失败：").arg(sourcePid) + winError();
            return false;
        }
        HANDLE sourceToken = nullptr;
        if (!OpenProcessToken(sourceProcess, TOKEN_DUPLICATE | TOKEN_QUERY, &sourceToken))
        {
            error = QStringLiteral("OpenProcessToken(SYSTEM 令牌源 PID=%1) 失败：").arg(sourcePid) + winError();
            CloseHandle(sourceProcess);
            return false;
        }
        const bool sourceIsSystem = tokenBelongsToLocalSystem(sourceToken);
        if (!sourceIsSystem)
        {
            error = QStringLiteral("选中的令牌源 PID=%1 不是 LocalSystem。").arg(sourcePid);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("token: source pid=%1 verified LocalSystem").arg(sourcePid));

        DWORD sourceTokenSession = 0;
        if (!queryTokenSessionId(sourceToken, sourceTokenSession, error))
        {
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("token: source token session=%1").arg(sourceTokenSession));

        SECURITY_ATTRIBUTES security{sizeof(security)};
        HANDLE impersonationToken = nullptr;
        if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &security, SecurityImpersonation, TokenImpersonation, &impersonationToken))
        {
            error = QStringLiteral("DuplicateTokenEx(TokenImpersonation) 失败：") + winError();
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        ScopedImpersonation impersonation;
        if (!impersonation.begin(impersonationToken))
        {
            error = QStringLiteral("ImpersonateLoggedOnUser(SYSTEM) 失败：") + winError();
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        enableTokenPrivilege(impersonationToken, SE_ASSIGNPRIMARYTOKEN_NAME);
        enableTokenPrivilege(impersonationToken, SE_INCREASE_QUOTA_NAME);
        enableTokenPrivilege(impersonationToken, SE_TCB_NAME);

        HANDLE primaryToken = nullptr;
        if (!DuplicateTokenEx(sourceToken, MAXIMUM_ALLOWED, &security, SecurityImpersonation, TokenPrimary, &primaryToken))
        {
            error = QStringLiteral("DuplicateTokenEx(TokenPrimary) 失败：") + winError();
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        enableTokenPrivilege(primaryToken, SE_ASSIGNPRIMARYTOKEN_NAME);
        enableTokenPrivilege(primaryToken, SE_INCREASE_QUOTA_NAME);
        enableTokenPrivilege(primaryToken, SE_TCB_NAME);
        if (sourceTokenSession != sessionId && !SetTokenInformation(primaryToken, TokenSessionId, &sessionId, sizeof(sessionId)))
        {
            error = QStringLiteral("SetTokenInformation(TokenSessionId=%1) 失败：").arg(sessionId) + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        DWORD uiAccess = 1;
        if (!SetTokenInformation(primaryToken, TokenUIAccess, &uiAccess, sizeof(uiAccess)))
        {
            error = QStringLiteral("SetTokenInformation(TokenUIAccess=1) 失败：") + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        DWORD verifiedUiAccess = 0;
        DWORD verifiedLength = 0;
        if (!GetTokenInformation(primaryToken, TokenUIAccess, &verifiedUiAccess, sizeof(verifiedUiAccess), &verifiedLength) || verifiedUiAccess == 0)
        {
            error = QStringLiteral("TokenUIAccess 设置后校验失败：") + winError();
            CloseHandle(primaryToken);
            CloseHandle(impersonationToken);
            CloseHandle(sourceToken);
            CloseHandle(sourceProcess);
            return false;
        }
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("token: primary token UIAccess verified=1, targetSession=%1").arg(sessionId));

        CloseHandle(impersonationToken);
        CloseHandle(sourceToken);
        CloseHandle(sourceProcess);
        result = primaryToken;
        return true;
    }

    QString ownerMutexName(DWORD sessionId)
    {
        return QString::fromWCharArray(kOwnerMutexPrefix) + QString::number(sessionId);
    }

    QString readyEventName(DWORD pid)
    {
        return QString::fromWCharArray(kReadyEventPrefix) + QString::number(pid);
    }

    bool isWinlogonDesktop()
    {
        return PrivilegeStage::currentDesktopName().compare(QStringLiteral("Winlogon"), Qt::CaseInsensitive) == 0;
    }

    QPixmap removeFlatBackground(const QPixmap& source)
    {
        if (source.isNull()) return source;
        QImage image = source.toImage().convertToFormat(QImage::Format_ARGB32);
        if (image.isNull()) return source;
        const QColor corner = image.pixelColor(0, 0);
        // Some icon sizes are already transparent at the corner while still
        // carrying an opaque white matte around the artwork.
        const QColor key = corner.alpha() == 0 ? QColor(Qt::white) : corner;
        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QColor pixel = image.pixelColor(x, y);
                if (pixel.alpha() != 0 &&
                    std::abs(pixel.red() - key.red()) <= 24 &&
                    std::abs(pixel.green() - key.green()) <= 24 &&
                    std::abs(pixel.blue() - key.blue()) <= 24)
                {
                    image.setPixelColor(x, y, QColor(pixel.red(), pixel.green(), pixel.blue(), 0));
                }
            }
        }
        return QPixmap::fromImage(image);
    }

    class UacBrandHeaderWidget final : public QWidget
    {
    public:
        explicit UacBrandHeaderWidget(const QIcon& icon, QWidget* parent = nullptr)
            : QWidget(parent),
              m_iconPixmap(removeFlatBackground(icon.pixmap(QSize(32, 32))))
        {
            // Keep the branding bar compact.  The companion window height is
            // determined by its complete content, not by the UAC window.
            setFixedHeight(31);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        }

    protected:
        void paintEvent(QPaintEvent*) override
        {
            QPainter painter(this);
            const QRect bounds = rect();
            const QColor surface = palette().color(QPalette::Window);
            painter.fillRect(bounds, surface);

            const QRect iconRect(10, 3, 26, 25);
            if (!m_iconPixmap.isNull())
            {
                const QPixmap iconPixmap = m_iconPixmap.scaled(QSize(22, 22),
                                                                Qt::KeepAspectRatio,
                                                                Qt::SmoothTransformation);
                painter.drawPixmap(iconRect.center() - QPoint(iconPixmap.width() / 2, iconPixmap.height() / 2), iconPixmap);
            }

            painter.setPen(palette().color(QPalette::WindowText));
            painter.setFont(font());
            painter.drawText(QRect(42, 0, width() - 42, height()),
                             Qt::AlignVCenter | Qt::AlignLeft, QStringLiteral("UAC诊断"));

            painter.setPen(palette().color(QPalette::Mid));
            painter.drawLine(0, height() - 1, width() - 1, height() - 1);
        }

    private:
        QPixmap m_iconPixmap;
    };

    void applySystemPalette()
    {
        QPalette palette = qApp->palette();
        const QStyleHints* hints = QGuiApplication::styleHints();
        const Qt::ColorScheme scheme = hints ? hints->colorScheme() : Qt::ColorScheme::Unknown;
        const bool dark = scheme == Qt::ColorScheme::Dark ||
                          (scheme == Qt::ColorScheme::Unknown &&
                           palette.color(QPalette::Window).lightness() < 128);
        const QColor window = dark
            ? QColor(29, 31, 34)
            : QColor(250, 250, 250);
        const QColor surface = dark
            ? QColor(39, 42, 46)
            : QColor(255, 255, 255);
        const QColor text = dark
            ? QColor(241, 243, 245)
            : QColor(24, 26, 28);
        const QColor secondary = dark
            ? QColor(170, 176, 183)
            : QColor(92, 98, 105);
        const QColor accent = KswordTheme::DefaultPrimaryAccentColor();
        palette.setColor(QPalette::Window, window);
        palette.setColor(QPalette::Base, surface);
        palette.setColor(QPalette::AlternateBase, window);
        palette.setColor(QPalette::Button, surface);
        palette.setColor(QPalette::WindowText, text);
        palette.setColor(QPalette::Text, text);
        palette.setColor(QPalette::ButtonText, text);
        palette.setColor(QPalette::PlaceholderText, secondary);
        palette.setColor(QPalette::Mid, dark ? QColor(100, 108, 117) : QColor(151, 158, 166));
        palette.setColor(QPalette::Highlight, accent);
        palette.setColor(QPalette::HighlightedText, Qt::white);
        qApp->setPalette(palette);
    }

    QString uacDeskSystemStyle()
    {
        return QStringLiteral(
            "QMainWindow{background:palette(window);color:palette(window-text);border:none;}"
            "QWidget#kswordUacDeskRoot{background:palette(window);color:palette(window-text);}"
            "QLabel{background:transparent;color:palette(window-text);}"
            "QLabel#uacIdentityLabel{color:palette(window-text);}"
            // 详情正文继承系统主题文字角色，避免深色安全桌面出现黑字深底。
            "QLabel#uacProcessDetailsLabel{color:palette(window-text);}"
            "QPushButton{min-height:24px;max-height:24px;padding:1px 7px;background:palette(button);color:palette(button-text);"
            "border:1px solid palette(highlight);border-radius:0;}"
            "QPushButton#uacTerminateButton{background:palette(highlight);color:palette(highlighted-text);}"
            "QPushButton:hover{background:palette(highlight);color:palette(highlighted-text);}"
            "QPushButton:pressed{background:palette(dark);color:palette(button-text);}"
            "QPushButton:disabled{background:palette(window);color:palette(mid);border:1px solid palette(mid);}"
            "QPushButton:focus{border:1px solid palette(highlight);outline:none;}");
    }
}



QString formatFileTime(quint64 fileTime)
{
    if (fileTime == 0)
        return QStringLiteral("未知");
    FILETIME ft{};
    ft.dwLowDateTime = static_cast<DWORD>(fileTime & 0xffffffffULL);
    ft.dwHighDateTime = static_cast<DWORD>(fileTime >> 32);
    SYSTEMTIME systemTime{};
    if (!FileTimeToSystemTime(&ft, &systemTime))
        return QStringLiteral("未知");
    return QStringLiteral("%1-%2-%3 %4:%5:%6")
        .arg(systemTime.wYear, 4, 10, QLatin1Char('0'))
        .arg(systemTime.wMonth, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wDay, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wHour, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wMinute, 2, 10, QLatin1Char('0'))
        .arg(systemTime.wSecond, 2, 10, QLatin1Char('0'));
}

quint64 processCreationTime(HANDLE process)
{
    FILETIME creation{}, exitTime{}, kernel{}, user{};
    if (!GetProcessTimes(process, &creation, &exitTime, &kernel, &user))
        return 0;
    return (static_cast<quint64>(creation.dwHighDateTime) << 32) | creation.dwLowDateTime;
}

QString quoteArgument(const QString& value)
{
    QString result = QStringLiteral("\"");
    int backslashes = 0;
    for (const QChar ch : value)
    {
        if (ch == QLatin1Char('\\'))
        {
            ++backslashes;
        }
        else if (ch == QLatin1Char('"'))
        {
            result += QString(backslashes * 2 + 1, QLatin1Char('\\'));
            result += QLatin1Char('"');
            backslashes = 0;
        }
        else
        {
            result += QString(backslashes, QLatin1Char('\\'));
            result += ch;
            backslashes = 0;
        }
    }
    result += QString(backslashes * 2, QLatin1Char('\\'));
    result += QLatin1Char('"');
    return result;
}

QString ProcessInspector::fileName(const QString& path)
{
    return QFileInfo(path).fileName();
}

bool ProcessInspector::query(DWORD pid, ProcessIdentity& identity, DWORD desiredAccess)
{
    identity = {};
    HANDLE process = OpenProcess(desiredAccess | SYNCHRONIZE, FALSE, pid);
    if (!process)
        return false;
    identity.pid = pid;
    identity.creationTime = processCreationTime(process);
    DWORD session = 0;
    ProcessIdToSessionId(pid, &session);
    identity.sessionId = session;
    wchar_t path[32768] = {};
    DWORD pathLength = static_cast<DWORD>(std::size(path));
    QueryFullProcessImageNameW(process, 0, path, &pathLength);
    identity.imagePath = QString::fromWCharArray(path, static_cast<int>(pathLength));
    identity.commandLine.clear();
    queryCommandLine(process, identity.commandLine);
    identity.fileDescription = versionStringValue(identity.imagePath, L"FileDescription");
    CloseHandle(process);

    PROCESSENTRY32W entry{sizeof(entry)};
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok; ok = Process32NextW(snapshot, &entry))
        {
            if (entry.th32ProcessID == pid)
            {
                identity.parentPid = entry.th32ParentProcessID;
                break;
            }
        }
        CloseHandle(snapshot);
    }
    return identity.isValid();
}

bool ProcessInspector::queryCommandLine(HANDLE process, QString& commandLine)
{
    using NtQueryInformationProcessFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    struct BasicInfo { PVOID reserved1; PVOID peb; PVOID reserved2[2]; ULONG_PTR pid; PVOID reserved3; };
    struct UnicodeString { USHORT length; USHORT maximumLength; PWSTR buffer; };
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto query = ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(GetProcAddress(ntdll, "NtQueryInformationProcess")) : nullptr;
    if (!query)
        return false;
    BasicInfo basic{};
    if (query(process, 0, &basic, sizeof(basic), nullptr) != 0 || !basic.peb)
        return false;
    PVOID params = nullptr;
    if (!ReadProcessMemory(process, reinterpret_cast<BYTE*>(basic.peb) + 0x20, &params, sizeof(params), nullptr) || !params)
        return false;
    UnicodeString value{};
    if (!ReadProcessMemory(process, reinterpret_cast<BYTE*>(params) + 0x70, &value, sizeof(value), nullptr) || !value.buffer || value.length == 0)
        return false;
    std::vector<wchar_t> buffer(value.length / sizeof(wchar_t) + 1, L'\0');
    if (!ReadProcessMemory(process, value.buffer, buffer.data(), value.length, nullptr))
        return false;
    commandLine = QString::fromWCharArray(buffer.data(), value.length / sizeof(wchar_t));
    return !commandLine.isEmpty();
}

bool ProcessInspector::queryCommandLine(DWORD pid, QString& commandLine)
{
    commandLine.clear();
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process)
        return false;
    const bool ok = queryCommandLine(process, commandLine);
    CloseHandle(process);
    return ok;
}

bool ProcessInspector::identityStillMatches(const ProcessIdentity& expected)
{
    ProcessIdentity current;
    if (!query(expected.pid, current))
        return false;
    return current.creationTime == expected.creationTime && current.sessionId == expected.sessionId && isSamePath(current.imagePath, expected.imagePath);
}

bool ProcessInspector::isProtectedName(const QString& imagePath)
{
    static const QStringList names = {QStringLiteral("system"), QStringLiteral("system idle process"), QStringLiteral("smss.exe"),
                                      QStringLiteral("csrss.exe"), QStringLiteral("wininit.exe"), QStringLiteral("services.exe"),
                                      QStringLiteral("lsass.exe"), QStringLiteral("winlogon.exe"), QStringLiteral("dwm.exe"),
                                      QStringLiteral("consent.exe"), QStringLiteral("credentialuibroker.exe"), QStringLiteral("logonui.exe"),
                                      QStringLiteral("ksworduacdesk.exe")};
    return names.contains(lowerFileName(imagePath), Qt::CaseInsensitive);
}

namespace
{
    DWORD appInfoServicePid(DWORD& serviceState)
    {
        serviceState = SERVICE_STOPPED;
        SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (!manager)
            return 0;
        SC_HANDLE service = OpenServiceW(manager, L"Appinfo", SERVICE_QUERY_STATUS);
        if (!service)
        {
            CloseServiceHandle(manager);
            return 0;
        }

        SERVICE_STATUS_PROCESS status{};
        DWORD bytes = 0;
        const bool ok = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                                             reinterpret_cast<LPBYTE>(&status), sizeof(status), &bytes) != FALSE;
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        if (!ok)
            return 0;
        serviceState = status.dwCurrentState;
        return status.dwProcessId;
    }

    QString processImagePathForWindow(HWND hwnd, DWORD& pid)
    {
        pid = 0;
        if (!hwnd || !GetWindowThreadProcessId(hwnd, &pid) || pid == 0)
            return {};
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process)
            return {};
        wchar_t path[32768] = {};
        DWORD length = static_cast<DWORD>(std::size(path));
        const bool ok = QueryFullProcessImageNameW(process, 0, path, &length) != FALSE;
        CloseHandle(process);
        return ok ? QString::fromWCharArray(path, static_cast<int>(length)) : QString();
    }

    QString utf16BufferString(const std::vector<BYTE>& buffer, size_t offset)
    {
        if (offset >= buffer.size() || (buffer.size() - offset) < sizeof(char16_t))
            return {};
        const size_t maxChars = (buffer.size() - offset) / sizeof(char16_t);
        size_t chars = 0;
        const auto* value = reinterpret_cast<const char16_t*>(buffer.data() + offset);
        while (chars < maxChars && value[chars] != u'\0')
            ++chars;
        return chars == 0 ? QString() : QString::fromUtf16(value, static_cast<qsizetype>(chars));
    }

    DWORD discoverConsentPid(DWORD sessionId, const UacScanCancellation* cancel)
    {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;
        DWORD result = 0;
        PROCESSENTRY32W entry{sizeof(entry)};
        for (BOOL ok = Process32FirstW(snapshot, &entry); ok && !scanCanceled(cancel); ok = Process32NextW(snapshot, &entry))
        {
            if (_wcsicmp(entry.szExeFile, L"consent.exe") == 0)
            {
                DWORD candidateSession = 0;
                if (ProcessIdToSessionId(entry.th32ProcessID, &candidateSession) &&
                    candidateSession == sessionId)
                {
                    result = entry.th32ProcessID;
                    break;
                }
            }
        }
        CloseHandle(snapshot);
        return result;
    }

    QString tokenIntegrityLevel(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) return QStringLiteral("不可用");
        HANDLE token = nullptr;
        const bool opened = OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
        CloseHandle(process);
        if (!opened) return QStringLiteral("不可用");

        DWORD length = 0;
        GetTokenInformation(token, TokenIntegrityLevel, nullptr, 0, &length);
        std::vector<BYTE> buffer(length);
        QString result = QStringLiteral("不可用");
        if (length != 0 && GetTokenInformation(token, TokenIntegrityLevel, buffer.data(), length, &length))
        {
            const auto* label = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(buffer.data());
            const DWORD rid = *GetSidSubAuthority(label->Label.Sid,
                                                   static_cast<DWORD>(*GetSidSubAuthorityCount(label->Label.Sid) - 1));
            if (rid >= SECURITY_MANDATORY_SYSTEM_RID) result = QStringLiteral("System");
            else if (rid >= SECURITY_MANDATORY_HIGH_RID) result = QStringLiteral("High");
            else if (rid >= SECURITY_MANDATORY_MEDIUM_RID) result = QStringLiteral("Medium");
            else if (rid >= SECURITY_MANDATORY_LOW_RID) result = QStringLiteral("Low");
            else result = QStringLiteral("Untrusted");
        }
        CloseHandle(token);
        return result;
    }

    QString tokenElevationType(DWORD pid)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!process) return QStringLiteral("不可用");
        HANDLE token = nullptr;
        const bool opened = OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
        CloseHandle(process);
        if (!opened) return QStringLiteral("不可用");
        TOKEN_ELEVATION_TYPE type = TokenElevationTypeDefault;
        DWORD length = 0;
        const bool ok = GetTokenInformation(token, TokenElevationType, &type, sizeof(type), &length) != FALSE;
        CloseHandle(token);
        if (!ok) return QStringLiteral("不可用");
        switch (type)
        {
        case TokenElevationTypeFull: return QStringLiteral("Full");
        case TokenElevationTypeLimited: return QStringLiteral("Limited");
        default: return QStringLiteral("Default");
        }
    }

    QString verifyFileSignature(const QString& imagePath, const UacScanCancellation* cancel)
    {
        if (scanCanceled(cancel)) return {};
        if (imagePath.isEmpty()) return QStringLiteral("未取得");
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct = sizeof(fileInfo);
        const std::wstring path = imagePath.toStdWString();
        fileInfo.pcwszFilePath = path.c_str();
        WINTRUST_DATA trustData{};
        trustData.cbStruct = sizeof(trustData);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_IGNORE;
        GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        const LONG status = WinVerifyTrust(nullptr, &action, &trustData);
        if (scanCanceled(cancel)) return {};
        const QString trustText = status == ERROR_SUCCESS
            ? QStringLiteral("Trusted")
            : QStringLiteral("Untrusted (0x%1)").arg(static_cast<unsigned long>(status), 0, 16);

        // WinVerifyTrust reports trust only. Read the embedded signer
        // certificate as well so the UI shows the concrete signer text.
        HCERTSTORE store = nullptr;
        HCRYPTMSG message = nullptr;
        DWORD encoding = 0;
        DWORD contentType = 0;
        DWORD format = 0;
        QString signerText;
        if (!scanCanceled(cancel) && CryptQueryObject(CERT_QUERY_OBJECT_FILE,
                             path.c_str(),
                             CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                             CERT_QUERY_FORMAT_FLAG_BINARY,
                             0,
                             &encoding,
                             &contentType,
                             &format,
                             &store,
                             &message,
                             nullptr))
        {
            DWORD signerSize = 0;
            if (!scanCanceled(cancel) && CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerSize) && signerSize != 0)
            {
                std::vector<BYTE> signerBuffer(signerSize);
                if (!scanCanceled(cancel) && CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, signerBuffer.data(), &signerSize))
                {
                    const auto* signerInfo = reinterpret_cast<const CMSG_SIGNER_INFO*>(signerBuffer.data());
                    CERT_INFO certInfo{};
                    certInfo.Issuer = signerInfo->Issuer;
                    certInfo.SerialNumber = signerInfo->SerialNumber;
                    PCCERT_CONTEXT certificate = scanCanceled(cancel) ? nullptr : CertFindCertificateInStore(
                        store,
                        encoding,
                        0,
                        CERT_FIND_SUBJECT_CERT,
                        &certInfo,
                        nullptr);
                    if (certificate)
                    {
                        wchar_t signerName[512] = {};
                        if (!scanCanceled(cancel) && CertGetNameStringW(certificate,
                                               CERT_NAME_SIMPLE_DISPLAY_TYPE,
                                               0,
                                               nullptr,
                                               signerName,
                                               static_cast<DWORD>(std::size(signerName))) > 1)
                        {
                            signerText = QString::fromWCharArray(signerName);
                        }
                        CertFreeCertificateContext(certificate);
                    }
                }
            }
            if (message) CryptMsgClose(message);
            if (store) CertCloseStore(store, 0);
        }
        return signerText.isEmpty()
            ? trustText
            : QStringLiteral("%1 · %2").arg(trustText, signerText);
    }

    QString processRunDuration(quint64 creationTime)
    {
        if (creationTime == 0) return QStringLiteral("不可用");
        FILETIME nowFileTime{};
        GetSystemTimeAsFileTime(&nowFileTime);
        const quint64 now = (static_cast<quint64>(nowFileTime.dwHighDateTime) << 32) | nowFileTime.dwLowDateTime;
        if (now <= creationTime) return QStringLiteral("00:00:00");
        const quint64 totalSeconds = (now - creationTime) / 10000000ULL;
        const quint64 hours = totalSeconds / 3600;
        const quint64 minutes = (totalSeconds / 60) % 60;
        const quint64 seconds = totalSeconds % 60;
        return QStringLiteral("%1:%2:%3")
            .arg(hours, 2, 10, QLatin1Char('0'))
            .arg(minutes, 2, 10, QLatin1Char('0'))
            .arg(seconds, 2, 10, QLatin1Char('0'));
    }

    QString processLaunchChain(const ProcessIdentity& origin, const UacScanCancellation* cancel)
    {
        QStringList names;
        QVector<DWORD> visited;
        ProcessIdentity current = origin;
        for (int depth = 0; depth < 16 && current.isValid(); ++depth)
        {
            if (scanCanceled(cancel)) return {};
            if (std::find(visited.cbegin(), visited.cend(), current.pid) != visited.cend())
                break;
            visited.push_back(current.pid);
            const QString name = ProcessInspector::fileName(current.imagePath);
            // The secure desktop can expose a fallback font without some
            // application-specific glyphs. Keep the chain readable and
            // deterministic: normal Windows executable names are ASCII;
            // otherwise show the PID instead of rendering tofu boxes.
            bool asciiName = !name.isEmpty();
            for (const QChar character : name)
            {
                if (character.unicode() < 0x20 || character.unicode() > 0x7e)
                {
                    asciiName = false;
                    break;
                }
            }
            names.push_back(asciiName ? name : QStringLiteral("PID %1").arg(current.pid));
            if (current.parentPid == 0 || current.parentPid == current.pid)
                break;
            ProcessIdentity parent;
            if (!ProcessInspector::query(current.parentPid, parent))
                break;
            if (parent.sessionId != current.sessionId || parent.creationTime > current.creationTime)
                break;
            current = parent;
        }
        std::reverse(names.begin(), names.end());
        return names.join(QStringLiteral(" -> "));
    }

    QIcon processIcon(const QString& imagePath)
    {
        if (imagePath.isEmpty()) return {};
        QFileIconProvider provider;
        return provider.icon(QFileInfo(imagePath));
    }

    UINT dpiForWindow(HWND hwnd)
    {
        UINT dpi = 96;
        HMODULE user32 = GetModuleHandleW(L"user32.dll");
        using GetDpiForWindowFn = UINT(WINAPI*)(HWND);
        const auto getDpiForWindow = user32
            ? reinterpret_cast<GetDpiForWindowFn>(GetProcAddress(user32, "GetDpiForWindow"))
            : nullptr;
        if (getDpiForWindow && hwnd)
        {
            const UINT reported = getDpiForWindow(hwnd);
            if (reported >= 96) dpi = reported;
        }
        return dpi;
    }
}

bool ProcessInspector::suspend(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = winError(); return false; }
    THREADENTRY32 entry{sizeof(entry)};
    bool touched = false;
    for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
    {
        if (entry.th32OwnerProcessID != expected.pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) continue;
        if (SuspendThread(thread) != static_cast<DWORD>(-1)) touched = true;
        CloseHandle(thread);
    }
    CloseHandle(snapshot);
    if (!touched) { error = winError(); return false; }
    return true;
}

bool ProcessInspector::resume(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) { error = winError(); return false; }
    THREADENTRY32 entry{sizeof(entry)};
    bool touched = false;
    for (BOOL ok = Thread32First(snapshot, &entry); ok; ok = Thread32Next(snapshot, &entry))
    {
        if (entry.th32OwnerProcessID != expected.pid) continue;
        HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
        if (!thread) continue;
        while (ResumeThread(thread) > 0) touched = true;
        CloseHandle(thread);
    }
    CloseHandle(snapshot);
    if (!touched) { error = winError(); return false; }
    return true;
}

bool ProcessInspector::terminate(const ProcessIdentity& expected, QString& error)
{
    if (!identityStillMatches(expected) || isProtectedName(expected.imagePath)) { error = QStringLiteral("目标身份已变化或属于受保护进程"); return false; }
    HANDLE process = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, expected.pid);
    if (!process) { error = winError(); return false; }
    const bool ok = TerminateProcess(process, 1) != FALSE;
    if (!ok) error = winError();
    CloseHandle(process);
    return ok;
}

bool PrivilegeStage::isProcessElevated()
{
    HANDLE token = nullptr;
    const bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && getTokenElevation(token);
    if (token) CloseHandle(token);
    return ok;
}

bool PrivilegeStage::isSystem()
{
    HANDLE token = nullptr;
    const bool ok = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) && tokenIsSystem(token);
    if (token) CloseHandle(token);
    return ok;
}

bool PrivilegeStage::hasUiAccess()
{
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    DWORD value = 0, length = 0;
    const bool ok = GetTokenInformation(token, TokenUIAccess, &value, sizeof(value), &length) && value != 0;
    CloseHandle(token);
    return ok;
}

bool PrivilegeStage::launchAdminStage(const QString& executable, const QStringList& args, QString& error)
{
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("admin-launch: begin executable=%1 args=%2")
                           .arg(executable, args.join(QLatin1Char(' '))));
    SHELLEXECUTEINFOW info{sizeof(info)};
    const QString parameters = std::accumulate(args.cbegin(), args.cend(), QString(), [](const QString& a, const QString& b) { return a.isEmpty() ? b : a + QLatin1Char(' ') + b; });
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpVerb = L"runas";
    const std::wstring file = executable.toStdWString();
    const std::wstring params = parameters.toStdWString();
    info.lpFile = file.c_str();
    info.lpParameters = params.c_str();
    info.nShow = SW_HIDE;
    const bool ok = ShellExecuteExW(&info) != FALSE;
    if (!ok)
        error = QStringLiteral("ShellExecuteExW(runas) 失败：") + winError();
    KSWORD_UAC_DIAGNOSTIC_LOG(ok
        ? QStringLiteral("admin-launch: ShellExecuteExW succeeded")
        : QStringLiteral("admin-launch: %1").arg(error));
    if (info.hProcess) CloseHandle(info.hProcess);
    return ok;
}

bool PrivilegeStage::launchSystemStage(const QString& executable, const QStringList& args, const QString& desktop,
                                       DWORD targetSession, QString& error)
{
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system-launch: begin executable=%1 targetSession=%2 desktop=%3 args=%4")
                           .arg(executable).arg(targetSession).arg(desktop, args.join(QLatin1Char(' '))));
    HANDLE token = nullptr;
    if (!duplicateSystemTokenForSession(targetSession, token, error))
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system-launch: token preparation failed: %1").arg(error));
        return false;
    }
    const QString parameters = std::accumulate(args.cbegin(), args.cend(), QString(), [](const QString& a, const QString& b) { return a.isEmpty() ? b : a + QLatin1Char(' ') + b; });
    const std::wstring executablePath = executable.toStdWString();
    std::wstring command = quoteArgument(executable).toStdWString();
    if (!parameters.isEmpty()) { command += L" "; command += parameters.toStdWString(); }
    std::vector<wchar_t> mutableCommand(command.begin(), command.end());
    mutableCommand.push_back(L'\0');
    STARTUPINFOW startup{sizeof(startup)};
    std::wstring desktopName = desktop.toStdWString();
    startup.lpDesktop = desktopName.data();
    PROCESS_INFORMATION processInfo{};
    // 这里使用 Ksword5.1 现有 System 链路的正常创建方式：
    // 源令牌来自 winlogon/services 的 LocalSystem 令牌，复制后的主令牌直接交给
    // CreateProcessWithTokenW；AdjustTokenPrivileges 只负责准备调用条件，绝不替代令牌来源。
    const bool ok = CreateProcessWithTokenW(token, LOGON_NETCREDENTIALS_ONLY, executablePath.c_str(),
                                            mutableCommand.data(), NORMAL_PRIORITY_CLASS, nullptr, nullptr,
                                            &startup, &processInfo) != FALSE;
    if (!ok)
        error = QStringLiteral("CreateProcessWithTokenW(SYSTEM/UIAccess, desktop=%1) 失败：").arg(desktop) + winError();
    KSWORD_UAC_DIAGNOSTIC_LOG(ok
        ? QStringLiteral("system-launch: CreateProcessWithTokenW succeeded childPid=%1").arg(processInfo.dwProcessId)
        : QStringLiteral("system-launch: %1").arg(error));
    if (processInfo.hThread) CloseHandle(processInfo.hThread);
    if (processInfo.hProcess) CloseHandle(processInfo.hProcess);
    CloseHandle(token);
    return ok;
}

QString PrivilegeStage::currentDesktopName()
{
    HDESK desktop = GetThreadDesktop(GetCurrentThreadId());
    if (!desktop) return {};
    DWORD length = 0;
    GetUserObjectInformationW(desktop, UOI_NAME, nullptr, 0, &length);
    if (length == 0) return {};
    std::vector<wchar_t> buffer(length + 1, L'\0');
    if (!GetUserObjectInformationW(desktop, UOI_NAME, buffer.data(), static_cast<DWORD>(buffer.size() * sizeof(wchar_t)), &length)) return {};
    return QString::fromWCharArray(buffer.data());
}

namespace
{
    void logEtwCallbackException(DWORD code)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw-callback: SEH exception code=0x%1, event dropped")
                                               .arg(code, 0, 16));
    }
}

DWORD PrivilegeStage::currentSessionId()
{
    DWORD session = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &session);
    return session;
}

UacEventMonitor::UacEventMonitor(QObject* parent) : QObject(parent)
{
    m_consumeTimer.setInterval(80);
    QObject::connect(&m_consumeTimer, &QTimer::timeout, this, [this] { consumeEvents(); });
}

UacEventMonitor::~UacEventMonitor() { stop(); }

void UacEventMonitor::start()
{
    if (m_running.exchange(true)) return;
    g_eventMonitor = this;
    cleanupStaleEtwSessions();
    // WinEvent is only a wake-up/indexing signal.  It never becomes evidence
    // for a process action: the origin is accepted only after reading the
    // consent -> AppInfo request buffer below.
    m_winEventHook = SetWinEventHook(EVENT_SYSTEM_DESKTOPSWITCH, EVENT_SYSTEM_DESKTOPSWITCH,
                                     nullptr, &UacEventMonitor::winEventCallback,
                                     0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    m_objectEventHook = SetWinEventHook(EVENT_OBJECT_CREATE, EVENT_OBJECT_SHOW,
                                        nullptr, &UacEventMonitor::winEventCallback,
                                        0, 0, WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
        "winevent: desktopHook=0x%1 objectHook=0x%2; hooks are wake-up only")
                                           .arg(reinterpret_cast<quintptr>(m_winEventHook), 0, 16)
                                           .arg(reinterpret_cast<quintptr>(m_objectEventHook), 0, 16));
    DWORD serviceState = SERVICE_STOPPED;
    m_appInfoPid = appInfoServicePid(serviceState);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: Appinfo pid=%1 state=%2")
                                           .arg(m_appInfoPid.load()).arg(serviceState));
    startEtw();
    startAlpcEtw();
    m_consumeTimer.start();
}

void UacEventMonitor::stop()
{
    if (!m_running.exchange(false)) return;
    m_consumeTimer.stop();
    if (m_winEventHook) { UnhookWinEvent(m_winEventHook); m_winEventHook = nullptr; }
    if (m_objectEventHook) { UnhookWinEvent(m_objectEventHook); m_objectEventHook = nullptr; }
    stopAlpcEtw();
    stopEtw();
    if (g_eventMonitor == this) g_eventMonitor = nullptr;
}

namespace
{
// Collector-local indexing only. ETW remains owned by the companion; scanning
// discovers consent directly and never borrows its monitor or g_eventMonitor.
std::optional<UacOriginEvidence> readConsentOrigin(DWORD sessionId, DWORD companionPid,
    const UacScanOriginHint& originHint, const UacScanCancellation* cancel)
{
    if (!originHint.monitorRunning || scanCanceled(cancel))
        return std::nullopt;

    static DWORD cachedConsentPid = 0;
    static quint64 lastConsentDiscoveryMs = 0;
    // Preserve the monitor's latest consent identity as values. The collector
    // never dereferences the host monitor or joins its lifetime.
    if (originHint.consentPid != 0 && originHint.discoveredAtMs >= lastConsentDiscoveryMs)
    {
        cachedConsentPid = originHint.consentPid;
        lastConsentDiscoveryMs = originHint.discoveredAtMs;
    }
    const quint64 now = GetTickCount64();
    DWORD consentPid = cachedConsentPid;
    if (consentPid == 0 || now - lastConsentDiscoveryMs >= 500)
    {
        const DWORD discovered = discoverConsentPid(sessionId, cancel);
        if (scanCanceled(cancel)) return std::nullopt;
        lastConsentDiscoveryMs = now;
        if (discovered != 0)
            cachedConsentPid = discovered;
        else if (consentPid != 0)
        {
            QString ignored;
            if (!ProcessInspector::queryCommandLine(consentPid, ignored))
                cachedConsentPid = 0;
        }
        consentPid = cachedConsentPid;
    }
    if (consentPid == 0 || scanCanceled(cancel))
        return std::nullopt;

    QString consentCommandLine;
    if (!ProcessInspector::queryCommandLine(consentPid, consentCommandLine))
    {
        cachedConsentPid = 0;
        return std::nullopt;
    }
    if (scanCanceled(cancel)) return std::nullopt;

    // Current Win10/Win11 consent.exe receives: AppInfo PID, declared byte
    // length, and a pointer into the AppInfo request buffer.  This is private
    // implementation detail, so every field is range-checked and failure is
    // reported as "unresolved" instead of becoming an action candidate.
    static const QRegularExpression consentArguments(
        QStringLiteral("consent\\.exe\\s+(\\d+)\\s+(\\d+)\\s+([0-9A-Fa-f]+)"),
        QRegularExpression::CaseInsensitiveOption);
    const QRegularExpressionMatch match = consentArguments.match(consentCommandLine);
    if (!match.hasMatch())
        return std::nullopt;

    bool okPid = false;
    bool okLength = false;
    bool okAddress = false;
    const DWORD appInfoPid = match.captured(1).toUInt(&okPid);
    const DWORD bufferLength = match.captured(2).toUInt(&okLength);
    const quintptr requestAddress = static_cast<quintptr>(match.captured(3).toULongLong(&okAddress, 16));
    const DWORD osBuild = windowsBuildNumber();
    const bool useWin11Layout = osBuild >= kWindows11BuildNumber;
    const size_t originPidOffset = useWin11Layout
        ? kAppInfoWin11OriginPidOffset
        : kAppInfoWin10OriginPidOffset;
    const size_t targetPathOffset = useWin11Layout
        ? kAppInfoWin11TargetPathOffset
        : kAppInfoWin10TargetPathOffset;
    if (!okPid || !okLength || !okAddress || appInfoPid == 0 || requestAddress == 0 ||
        bufferLength < targetPathOffset || bufferLength > 0x10000)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "appinfo-origin: reject consentPid=%1 cmd=%2 parsed appInfo=%3 length=%4 address=0x%5")
                                               .arg(consentPid).arg(consentCommandLine.left(600))
                                               .arg(appInfoPid).arg(bufferLength).arg(requestAddress, 0, 16));
        return std::nullopt;
    }

    if (scanCanceled(cancel)) return std::nullopt;
    HANDLE appInfo = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, appInfoPid);
    if (!appInfo)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("appinfo-origin: OpenProcess failed pid=%1 error=%2")
                                               .arg(appInfoPid).arg(winError()));
        return std::nullopt;
    }

    std::vector<BYTE> request(bufferLength);
    SIZE_T bytesRead = 0;
    const bool readOk = ReadProcessMemory(appInfo, reinterpret_cast<LPCVOID>(requestAddress),
                                          request.data(), request.size(), &bytesRead) != FALSE;
    CloseHandle(appInfo);
    if (scanCanceled(cancel)) return std::nullopt;
    if (!readOk || bytesRead != request.size())
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "appinfo-origin: ReadProcessMemory failed appInfoPid=%1 address=0x%2 requested=%3 read=%4 error=%5")
                                               .arg(appInfoPid).arg(requestAddress, 0, 16)
                                               .arg(bufferLength).arg(static_cast<qulonglong>(bytesRead)).arg(winError()));
        return std::nullopt;
    }

    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
        "appinfo-origin: layout osBuild=%1 family=%2 originPidOffset=0x%3 targetPathOffset=0x%4")
                                           .arg(osBuild)
                                           .arg(useWin11Layout ? QStringLiteral("Win11") : QStringLiteral("Win10/fallback"))
                                           .arg(originPidOffset, 0, 16)
                                           .arg(targetPathOffset, 0, 16));

    DWORD originPid = 0;
    std::memcpy(&originPid, request.data() + originPidOffset, sizeof(originPid));
    const QString targetPath = utf16BufferString(request, targetPathOffset);
    if (originPid == 0 || originPid == appInfoPid || originPid == consentPid ||
        originPid == companionPid || originPid == GetCurrentProcessId())
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "appinfo-origin: invalid origin pid=%1 consent=%2 appInfo=%3 target=%4")
                                               .arg(originPid).arg(consentPid).arg(appInfoPid).arg(targetPath));
        return std::nullopt;
    }

    ProcessIdentity origin;
    if (!ProcessInspector::query(originPid, origin) || !origin.isValid())
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("appinfo-origin: origin process unavailable pid=%1")
                                               .arg(originPid));
        return std::nullopt;
    }
    if (scanCanceled(cancel)) return std::nullopt;
    if (origin.sessionId != sessionId || ProcessInspector::isProtectedName(origin.imagePath))
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "appinfo-origin: origin rejected pid=%1 originSession=%2 expectedSession=%3 path=%4")
                                               .arg(origin.pid).arg(origin.sessionId).arg(sessionId).arg(origin.imagePath));
        return std::nullopt;
    }

    UacOriginEvidence evidence;
    evidence.origin = origin;
    evidence.targetPath = targetPath;
    evidence.consentPid = consentPid;
    evidence.appInfoPid = appInfoPid;
    evidence.bufferLength = bufferLength;
    evidence.requestAddress = requestAddress;
    evidence.originPidOffset = static_cast<DWORD>(originPidOffset);
    evidence.targetPathOffset = static_cast<DWORD>(targetPathOffset);
    evidence.observedAtMs = now;

    return evidence;
}
}

void WINAPI UacEventMonitor::winEventCallback(HWINEVENTHOOK, DWORD event, HWND hwnd, LONG objectId, LONG, DWORD, DWORD)
{
    if (!g_eventMonitor)
        return;

    if (event == kDesktopSwitchEvent)
    {
        UacEventMonitor::EventItem item{};
        item.eventId = event;
        g_eventMonitor->pushEvent(item);
        return;
    }

    if ((event == EVENT_OBJECT_CREATE || event == EVENT_OBJECT_SHOW) &&
        objectId == OBJID_WINDOW && hwnd)
    {
        DWORD pid = 0;
        const QString path = processImagePathForWindow(hwnd, pid);
        const QString name = ProcessInspector::fileName(path);
        if (name.compare(QStringLiteral("consent.exe"), Qt::CaseInsensitive) != 0 &&
            name.compare(QStringLiteral("credentialuibroker.exe"), Qt::CaseInsensitive) != 0)
            return;

        if (name.compare(QStringLiteral("consent.exe"), Qt::CaseInsensitive) == 0 && pid != 0)
        {
            g_eventMonitor->m_consentPid.store(pid);
            g_eventMonitor->m_lastConsentDiscoveryMs.store(GetTickCount64());
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("winevent: %1 hwnd=0x%2 consentPid=%3 path=%4")
                                                   .arg(event == EVENT_OBJECT_CREATE ? QStringLiteral("CREATE") : QStringLiteral("SHOW"))
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(pid).arg(path));
        }

        UacEventMonitor::EventItem item{};
        item.eventId = event;
        item.hwnd = hwnd;
        g_eventMonitor->pushEvent(item);
    }
}

void WINAPI UacEventMonitor::etwEventCallback(PEVENT_RECORD record)
{
    __try
    {
        etwEventCallbackImpl(record);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        logEtwCallbackException(GetExceptionCode());
    }
}

void UacEventMonitor::etwEventCallbackImpl(PEVENT_RECORD record)
{
    if (!g_eventMonitor || !record || !g_eventMonitor->m_running.load()) return;
    EventItem item{};
    item.provider = record->EventHeader.ProviderId;
    item.eventId = record->EventHeader.EventDescriptor.Id;
    item.task = record->EventHeader.EventDescriptor.Task;
    item.opcode = record->EventHeader.EventDescriptor.Opcode;
    item.pid = record->EventHeader.ProcessId;
    item.eventTimeMs = eventTraceTimeMs(record);
    const bool isAlpcRecord = IsEqualGUID(item.provider, kSystemAlpcProvider) ||
                              IsEqualGUID(item.provider, kLegacyAlpcProvider);
    if (isAlpcRecord)
    {
        const ULONG eventId = record->EventHeader.EventDescriptor.Id;
        const ULONG task = record->EventHeader.EventDescriptor.Task;
        const ULONG opcode = record->EventHeader.EventDescriptor.Opcode;
        const bool send = eventId == kAlpcSendEvent;
        const bool receive = eventId == kAlpcReceiveEvent;
        if (send || receive)
        {
            const ULONG messageId = alpcMessageId(record);
            if (messageId != 0)
                g_eventMonitor->observeAlpc(receive, record->EventHeader.ProcessId,
                                            record->EventHeader.ThreadId, messageId, item.eventTimeMs);
        }
    }
    g_eventMonitor->pushEvent(item);
}

void UacEventMonitor::pushEvent(const EventItem& item)
{
    QMutexLocker locker(&m_queueMutex);
    if (m_events.size() > 1024) m_events.dequeue();
    m_events.enqueue(item);
}

void UacEventMonitor::observeAlpc(bool receive, DWORD pid, DWORD tid, ULONG messageId, quint64 eventTimeMs)
{
    if (pid == 0 || tid == 0 || messageId == 0)
        return;

    const quint64 now = GetTickCount64();
    const DWORD appInfoPid = m_appInfoPid.load();
    QMutexLocker locker(&m_alpcMutex);
    while (!m_alpcSends.isEmpty() && now - m_alpcSends.front().observedAtMs > kAlpcSendRetentionMs)
        m_alpcSends.dequeue();
    while (!m_uacOrigins.isEmpty() && now - m_uacOrigins.front().observedAtMs > kAlpcSendRetentionMs)
        m_uacOrigins.dequeue();

    if (!receive)
    {
        m_alpcSends.enqueue({messageId, pid, tid, eventTimeMs, now});
        while (m_alpcSends.size() > 512)
            m_alpcSends.dequeue();
        return;
    }

    if (appInfoPid == 0 || pid != appInfoPid)
        return;

    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: Appinfo receive pid=%1 tid=%2 message=%3")
                                           .arg(pid).arg(tid).arg(messageId));
    for (auto it = m_alpcSends.crbegin(); it != m_alpcSends.crend(); ++it)
    {
        if (it->messageId != messageId || it->pid == appInfoPid)
            continue;
        if (eventTimeMs < it->eventTimeMs || eventTimeMs - it->eventTimeMs > kUacCorrelationWindowMs)
            continue;

        bool duplicate = false;
        for (const UacOriginItem& existing : m_uacOrigins)
        {
            if (existing.messageId == messageId && existing.clientPid == it->pid && existing.clientTid == it->tid)
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            m_uacOrigins.enqueue({messageId, it->pid, it->tid, appInfoPid, eventTimeMs, now});
            while (m_uacOrigins.size() > 128)
                m_uacOrigins.dequeue();
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: candidate pid=%1 tid=%2 message=%3 ageMs=%4 appinfoPid=%5")
                                                   .arg(it->pid).arg(it->tid).arg(messageId)
                                                   .arg(now - it->observedAtMs).arg(appInfoPid));
        }
        return;
    }
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: Appinfo receive has no matching send message=%1")
                                           .arg(messageId));
}

std::optional<ProcessIdentity> UacEventMonitor::takeUacOrigin(DWORD sessionId, quint64 uacObservedAtMs,
                                                              const QString& targetPath)
{
    if (uacObservedAtMs == 0)
        return std::nullopt;

    const quint64 now = GetTickCount64();
    QVector<UacOriginItem> recent;
    {
        QMutexLocker locker(&m_alpcMutex);
        QQueue<UacOriginItem> retained;
        while (!m_uacOrigins.isEmpty())
        {
            const UacOriginItem item = m_uacOrigins.dequeue();
            if (now >= item.observedAtMs && now - item.observedAtMs <= kAlpcSendRetentionMs)
                retained.enqueue(item);
            if (item.eventTimeMs <= uacObservedAtMs + 1500 &&
                uacObservedAtMs <= item.eventTimeMs + kUacCorrelationWindowMs)
                recent.push_back(item);
        }
        m_uacOrigins.swap(retained);
    }

    QVector<ProcessIdentity> matches;
    QVector<ULONG> matchMessages;
    for (const UacOriginItem& item : recent)
    {
        ProcessIdentity identity;
        if (!ProcessInspector::query(item.clientPid, identity))
            continue;
        if (identity.sessionId != sessionId || ProcessInspector::isProtectedName(identity.imagePath))
            continue;
        if (!targetPath.isEmpty() && isSamePath(identity.imagePath, targetPath))
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: requester path equals UAC target path pid=%1 path=%2")
                                                   .arg(identity.pid).arg(identity.imagePath));
        }

        bool duplicate = false;
        for (const ProcessIdentity& existing : matches)
        {
            if (existing.pid == identity.pid && existing.creationTime == identity.creationTime)
            {
                duplicate = true;
                break;
            }
        }
        if (!duplicate)
        {
            matches.push_back(identity);
            matchMessages.push_back(item.messageId);
        }
    }

    if (matches.size() != 1)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: resolve target=%1 recent=%2 valid=%3 result=%4")
                                               .arg(targetPath).arg(recent.size()).arg(matches.size())
                                               .arg(matches.size() == 1 ? QStringLiteral("unique") : QStringLiteral("ambiguous-or-none")));
        return std::nullopt;
    }

    {
        QMutexLocker locker(&m_alpcMutex);
        for (auto it = m_uacOrigins.begin(); it != m_uacOrigins.end();)
        {
            if (it->messageId == matchMessages.front() && it->clientPid == matches.front().pid)
                it = m_uacOrigins.erase(it);
            else
                ++it;
        }
    }
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: resolved pid=%1 tidMessage=%2 path=%3")
                                           .arg(matches.front().pid).arg(matchMessages.front()).arg(matches.front().imagePath));
    return matches.front();
}

void UacEventMonitor::consumeEvents()
{
    const quint64 now = GetTickCount64();
    if (m_lastAppInfoPidRefreshMs == 0 || now - m_lastAppInfoPidRefreshMs >= 1000)
    {
        m_lastAppInfoPidRefreshMs = now;
        DWORD serviceState = SERVICE_STOPPED;
        const DWORD pid = appInfoServicePid(serviceState);
        const DWORD previous = m_appInfoPid.exchange(pid);
        if (previous != pid)
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-queue: Appinfo pid changed %1 -> %2 state=%3")
                                                   .arg(previous).arg(pid).arg(serviceState));
    }
    QQueue<EventItem> events;
    {
        QMutexLocker locker(&m_queueMutex);
        events.swap(m_events);
    }
    while (!events.isEmpty())
    {
        const EventItem item = events.dequeue();
        const bool desktopEvent = IsEqualGUID(item.provider, GUID{}) ||
                                  (IsEqualGUID(item.provider, kLuaProvider) &&
                                   (item.task == 15002 || item.task == 15003 || item.task == 15004 || item.task == 15005));
        if (desktopEvent && onDesktopChanged) onDesktopChanged();
    }
}

void UacEventMonitor::startEtw()
{
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw: start requested"));
    m_traceName = timestampedEtwSessionName();
    const size_t size = sizeof(EVENT_TRACE_PROPERTIES) + 2 * 1024;
    auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(calloc(1, size));
    if (!properties) return;
    properties->Wnode.BufferSize = static_cast<ULONG>(size);
    properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties->Wnode.ClientContext = 2;
    properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
    wchar_t* name = reinterpret_cast<wchar_t*>(reinterpret_cast<BYTE*>(properties) + properties->LoggerNameOffset);
    StringCchCopyW(name, 1024, m_traceName.toStdWString().c_str());
    ULONG status = StartTraceW(&m_traceSession, name, properties);
    free(properties);
    if (status != ERROR_SUCCESS)
    {
        m_traceSession = 0;
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw: StartTraceW failed status=0x%1").arg(status, 0, 16));
        return;
    }
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw: StartTraceW succeeded session=0x%1").arg(m_traceSession, 0, 16));
    const ULONG luaStatus = EnableTraceEx2(m_traceSession, &kLuaProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                                           TRACE_LEVEL_VERBOSE, kLuaDiagnosticKeyword, 0, 0, nullptr);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw: EnableTraceEx2(Microsoft-Windows-LUA) status=0x%1")
                                           .arg(luaStatus, 0, 16));
    if (luaStatus != ERROR_SUCCESS)
    {
        stopTraceSession(m_traceSession, m_traceName);
        m_traceSession = 0;
        return;
    }
    m_etwStop = false;
    m_etwAvailable = false;
    m_etwThread = std::thread([this]
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw-thread: entered"));
        EVENT_TRACE_LOGFILEW logfile{};
        std::wstring name = m_traceName.toStdWString();
        // EVENT_TRACE_LOGFILEW::LoggerName 是 LPWSTR，不是内嵌字符数组。
        // 之前对零初始化的空指针执行 StringCchCopyW 会在 ETW 线程中立即触发 0xC0000005。
        logfile.LoggerName = name.data();
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &UacEventMonitor::etwEventCallback;
        TRACEHANDLE traceHandle = OpenTraceW(&logfile);
        m_traceHandle.store(traceHandle);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw-thread: OpenTrace handle=0x%1").arg(m_traceHandle, 0, 16));
        if (traceHandle != INVALID_PROCESSTRACE_HANDLE)
        {
            if (!m_etwStop.load())
            {
                const ULONG traceStatus = ProcessTrace(&traceHandle, 1, nullptr, nullptr);
                m_etwAvailable = traceStatus == ERROR_SUCCESS || traceStatus == ERROR_CANCELLED;
            }
        }
        // The worker or stopper closes the consumer, never both. Checking the
        // stop flag after publication also covers shutdown racing OpenTrace.
        closeTraceConsumer(m_traceHandle);
    });
}

void UacEventMonitor::stopEtw()
{
    m_etwStop = true;
    if (m_traceSession != 0)
    {
        stopTraceSession(m_traceSession, m_traceName);
        m_traceSession = 0;
    }
    // CloseTrace cancels real-time ProcessTrace even if stopping the controller
    // failed, so join cannot depend solely on ControlTrace succeeding.
    closeTraceConsumer(m_traceHandle);
    if (m_etwThread.joinable()) m_etwThread.join();
}

void UacEventMonitor::startAlpcEtw()
{
    if (m_alpcThread.joinable())
        return;

    m_alpcStop.store(false);
    m_alpcLastStatus.store(ERROR_SUCCESS);
    m_alpcTraceName = timestampedEtwSessionName(QStringLiteral("Alpc"));
    const QString traceName = m_alpcTraceName;

    // Match the main program's ETW ownership model: the worker owns the
    // controller and consumer handles from StartTrace through ProcessTrace.
    // This keeps the Qt thread out of potentially blocking ETW APIs.
    m_alpcThread = std::thread([this, traceName]
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw-alpc-thread: entered"));
        const std::wstring sessionNameWide = traceName.toStdWString();
        const ULONG traceNameBytes = static_cast<ULONG>((sessionNameWide.size() + 1) * sizeof(wchar_t));
        const ULONG propertyBufferSize = static_cast<ULONG>(sizeof(EVENT_TRACE_PROPERTIES) + traceNameBytes);
        std::vector<unsigned char> propertyBuffer(propertyBufferSize, 0);
        auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertyBuffer.data());
        properties->Wnode.BufferSize = propertyBufferSize;
        properties->Wnode.ClientContext = 2;
        properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        properties->Wnode.Guid = kUacAlpcEtwSessionGuid;
        // System providers require a system logger. EnableFlags is also set so
        // the classic ALPCGuid path is active on builds where the newer mapped
        // provider is accepted but its records retain the legacy provider GUID.
        properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        properties->EnableFlags = EVENT_TRACE_FLAG_ALPC;
        properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        properties->FlushTimer = 1;
        properties->BufferSize = 256;
        properties->MinimumBuffers = 16;
        properties->MaximumBuffers = 64;
        wchar_t* loggerNamePointer = reinterpret_cast<wchar_t*>(
            propertyBuffer.data() + properties->LoggerNameOffset);
        wcscpy_s(loggerNamePointer, sessionNameWide.size() + 1, sessionNameWide.c_str());

        TRACEHANDLE sessionHandle = 0;
        ULONG startStatus = StartTraceW(&sessionHandle, loggerNamePointer, properties);
        if (startStatus == ERROR_ALREADY_EXISTS)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "etw-alpc-thread: stale/existing session found; stopping by name and retrying"));
            ControlTraceW(0, loggerNamePointer, properties, EVENT_TRACE_CONTROL_STOP);
            startStatus = StartTraceW(&sessionHandle, loggerNamePointer, properties);
        }
        m_alpcLastStatus.store(startStatus);
        if (startStatus != ERROR_SUCCESS)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("etw-alpc-thread: StartTraceW failed status=0x%1 (%2)")
                                                   .arg(startStatus, 0, 16).arg(winError(startStatus)));
            return;
        }
        m_alpcSession.store(static_cast<ULONG64>(sessionHandle));
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "etw-alpc-thread: StartTraceW succeeded session=0x%1 name=%2 enableFlags=ALPC")
            .arg(static_cast<qulonglong>(sessionHandle), 0, 16).arg(traceName));

        if (m_alpcStop.load())
        {
            const ULONG64 ownedSession = m_alpcSession.exchange(0);
            if (ownedSession != 0)
                ControlTraceW(static_cast<TRACEHANDLE>(ownedSession), loggerNamePointer,
                              properties, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        const ULONG providerStatus = EnableTraceEx2(
            sessionHandle, &kSystemAlpcProvider, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
            TRACE_LEVEL_VERBOSE, kSystemAlpcKeyword, 0, 0, nullptr);
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "etw-alpc-thread: EnableTraceEx2(SystemAlpcProvider) status=0x%1")
            .arg(providerStatus, 0, 16));
        if (providerStatus != ERROR_SUCCESS)
        {
            m_alpcLastStatus.store(providerStatus);
            const ULONG64 ownedSession = m_alpcSession.exchange(0);
            if (ownedSession != 0)
                ControlTraceW(static_cast<TRACEHANDLE>(ownedSession), loggerNamePointer,
                              properties, EVENT_TRACE_CONTROL_STOP);
            return;
        }

        EVENT_TRACE_LOGFILEW logfile{};
        logfile.LoggerName = loggerNamePointer;
        logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.EventRecordCallback = &UacEventMonitor::etwEventCallback;
        const TRACEHANDLE traceHandle = OpenTraceW(&logfile);
        m_alpcTraceHandle.store(static_cast<TRACEHANDLE>(traceHandle));
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
            "etw-alpc-thread: OpenTrace handle=0x%1")
            .arg(static_cast<qulonglong>(traceHandle), 0, 16));
        if (traceHandle == INVALID_PROCESSTRACE_HANDLE)
        {
            const ULONG error = GetLastError();
            m_alpcLastStatus.store(error);
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "etw-alpc-thread: OpenTrace failed status=0x%1 (%2)")
                .arg(error, 0, 16).arg(winError(error)));
        }
        else
        {
            if (!m_alpcStop.load())
            {
                TRACEHANDLE processTraceHandle = traceHandle;
                const ULONG traceStatus = ProcessTrace(&processTraceHandle, 1, nullptr, nullptr);
                m_alpcLastStatus.store(m_alpcStop.load() ? ERROR_SUCCESS : traceStatus);
                KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                    "etw-alpc-thread: ProcessTrace returned status=0x%1 stop=%2")
                    .arg(traceStatus, 0, 16).arg(m_alpcStop.load() ? 1 : 0));
            }
        }
        closeTraceConsumer(m_alpcTraceHandle);

        const ULONG64 ownedSession = m_alpcSession.exchange(0);
        if (ownedSession != 0)
            ControlTraceW(static_cast<TRACEHANDLE>(ownedSession), loggerNamePointer,
                          properties, EVENT_TRACE_CONTROL_STOP);
    });
}

void UacEventMonitor::stopAlpcEtw()
{
    m_alpcStop.store(true);
    const ULONG64 ownedSession = m_alpcSession.exchange(0);
    if (ownedSession != 0)
    {
        stopTraceSession(static_cast<TRACEHANDLE>(ownedSession), m_alpcTraceName);
    }
    closeTraceConsumer(m_alpcTraceHandle);
    if (m_alpcThread.joinable())
        m_alpcThread.join();
    m_alpcTraceHandle.store(0);
}

UacApplicationIdentity UacWindowScanner::scan(const UacScanCancellation* cancel)
{
    UacApplicationIdentity result;
    if (scanCanceled(cancel)) return result;
    HDESK desktop = OpenDesktopW(kWinlogonDesktopName, 0, FALSE, DESKTOP_READOBJECTS | DESKTOP_ENUMERATE);
    bool closeDesktop = true;
    if (!desktop)
    {
        // 在当前线程已经位于 Winlogon 时，优先复用当前桌面句柄作为 OpenDesktop 的回退。
        desktop = GetThreadDesktop(GetCurrentThreadId());
        closeDesktop = false;
    }
    if (!desktop)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-scan: cannot open Winlogon desktop: %1").arg(winError()));
        return result;
    }
    WindowScanContext context;
    context.budget = cancel;
    EnumDesktopWindows(desktop, &enumWindowProc, reinterpret_cast<LPARAM>(&context));
    if (closeDesktop) CloseDesktop(desktop);
    if (scanCanceled(cancel)) return result;
    struct Candidate
    {
        HWND hwnd = nullptr;
        QRect rect;
        QString process;
        QString className;
        QString title;
        QString children;
        QString automation;
        QString allText;
        QString applicationName;
        QString publisher;
        QString imagePath;
        int score = 0;
    };

    bool sawConsentProcess = false;
    QStringList windowSummary;
    QVector<Candidate> candidates;
    const qint64 virtualArea = static_cast<qint64>(std::max(1, GetSystemMetrics(SM_CXVIRTUALSCREEN))) *
                               static_cast<qint64>(std::max(1, GetSystemMetrics(SM_CYVIRTUALSCREEN)));
    for (HWND hwnd : context.windows)
    {
        if (scanCanceled(cancel)) return {};
        const QString process = desktopProcessName(hwnd);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        RECT nativeRect{};
        GetWindowRect(hwnd, &nativeRect);
        const QRect rect(nativeRect.left, nativeRect.top,
                         nativeRect.right - nativeRect.left, nativeRect.bottom - nativeRect.top);
        const QString className = windowClassName(hwnd);
        const QString title = windowText(hwnd);
        windowSummary.push_back(QStringLiteral("hwnd=0x%1 pid=%2 process=%3 visible=%4 rect=%5,%6,%7,%8 class=%9 title=%10")
                                    .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                    .arg(pid)
                                    .arg(process.isEmpty() ? QStringLiteral("<unresolved>") : process)
                                    .arg(IsWindowVisible(hwnd) ? 1 : 0)
                                    .arg(rect.left()).arg(rect.top()).arg(rect.width()).arg(rect.height())
                                    .arg(className)
                                    .arg(title.left(120)));
        if (process != QStringLiteral("consent.exe") && process != QStringLiteral("credentialuibroker.exe")) continue;
        sawConsentProcess = true;

        if (!IsWindowVisible(hwnd) || rect.width() < 120 || rect.height() < 80) continue;
        if (className.contains(QStringLiteral("tooltip"), Qt::CaseInsensitive) ||
            title.compare(QStringLiteral("Tooltip"), Qt::CaseInsensitive) == 0) continue;

        Candidate candidate;
        candidate.hwnd = hwnd;
        candidate.rect = rect;
        candidate.process = process;
        candidate.className = className;
        candidate.title = title;
        candidate.children = collectChildText(hwnd, cancel);
        if (scanCanceled(cancel)) return {};
        candidate.automation = readUiAutomationName(hwnd, cancel);
        if (scanCanceled(cancel)) return {};
        candidate.applicationName = uacApplicationNameFromText(candidate.automation);
        candidate.publisher = uacPublisherFromText(candidate.automation);
        candidate.imagePath = uacPathFromText(candidate.automation);
        QStringList textParts;
        for (const QString& part : {candidate.title, candidate.children, candidate.automation})
            if (!part.trimmed().isEmpty()) textParts.push_back(part.trimmed());
        candidate.allText = textParts.join(QStringLiteral(" | "));
        candidate.score = process == QStringLiteral("consent.exe") ? 30 : 20;
        if (containsAny(candidate.allText,
                        {QStringLiteral("用户帐户控制"), QStringLiteral("User Account Control"),
                         QStringLiteral("Windows 安全性"), QStringLiteral("Windows Security")}))
            candidate.score += 120;
        if (!candidate.children.isEmpty()) candidate.score += 35;
        if (!candidate.automation.isEmpty()) candidate.score += 35;
        if (rect.width() >= 300 && rect.width() <= 1600 && rect.height() >= 180 && rect.height() <= 1100)
            candidate.score += 25;

        const qint64 area = static_cast<qint64>(rect.width()) * rect.height();
        const bool nearlyFullScreen = area * 100 >= virtualArea * 70;
        if (nearlyFullScreen && candidate.allText.isEmpty()) continue;
        if (nearlyFullScreen) candidate.score -= 100;
        candidates.push_back(std::move(candidate));
    }

    const auto best = std::max_element(candidates.cbegin(), candidates.cend(),
                                       [](const Candidate& left, const Candidate& right)
                                       {
                                           return left.score < right.score;
                                       });
    if (best != candidates.cend() && best->score >= 50)
    {
        result.consentWindow = best->hwnd;
        result.windowRect = best->rect;
        result.displayName = !best->applicationName.isEmpty()
            ? best->applicationName
            : (!best->title.isEmpty() ? best->title : best->automation);
        result.publisher = best->publisher;
        result.imagePath = best->imagePath;
        if (result.displayName.isEmpty() && !best->children.isEmpty())
            result.displayName = best->children.section(QLatin1Char('|'), 0, 0).trimmed();
        if (result.displayName.isEmpty()) result.displayName = QStringLiteral("UAC 安全桌面应用");
        result.matchText = best->allText;
        result.evidence = QStringLiteral("Winlogon 窗口：%1；类：%2；发布者：%3；路径：%4；控件文本：%5")
            .arg(best->process, best->className, best->publisher,
                 best->imagePath.isEmpty() ? QStringLiteral("未知") : best->imagePath,
                 best->allText.left(420));
        result.isUac = true;
        result.observedAtMs = currentTraceTimeMs();
        result.exact = false;
    }
    static QString previousWindowSummary;
    const QString currentWindowSummary = windowSummary.join(QStringLiteral(" || "));
    if (currentWindowSummary != previousWindowSummary)
    {
        previousWindowSummary = currentWindowSummary;
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-scan: enumerated=%1 consent=%2 %3")
                                                .arg(context.windows.size())
                                                .arg(sawConsentProcess ? 1 : 0)
                                                .arg(currentWindowSummary));
    }
    return result;
}

namespace
{
    ProcessActionState resolveTargetInWorker(UacApplicationIdentity& identity, DWORD sessionId,
        DWORD companionPid, const UacScanOriginHint& originHint, const UacScanCancellation* cancel)
    {
        ProcessActionState state;
        if (scanCanceled(cancel)) return state;
        const auto appInfoEvidence = readConsentOrigin(sessionId, companionPid, originHint, cancel);
        if (scanCanceled(cancel)) return state;

        // AppInfo evidence can arrive a little before the native window scan.
        // Keep it visible in that case, but do not pretend the target path is
        // the originating process and never enable process actions from it.
        if (appInfoEvidence.has_value())
        {
            identity.isUac = true;
            identity.observedAtMs = appInfoEvidence->observedAtMs;
            if (identity.displayName.isEmpty())
                identity.displayName = QStringLiteral("UAC 请求");
            if (!appInfoEvidence->targetPath.isEmpty())
                identity.imagePath = appInfoEvidence->targetPath;
            identity.exact = true;
            identity.evidence = QStringLiteral(
                "AppInfo 缓冲区：%1 字节；origin PID 位于 +0x%2；目标路径位于 +0x%3；consent PID=%4；目标=%5")
                .arg(appInfoEvidence->bufferLength)
                .arg(appInfoEvidence->originPidOffset, 0, 16)
                .arg(appInfoEvidence->targetPathOffset, 0, 16)
                .arg(appInfoEvidence->consentPid)
                .arg(appInfoEvidence->targetPath.isEmpty() ? QStringLiteral("未知") : appInfoEvidence->targetPath);
            state.origin = appInfoEvidence->origin;
            state.originResolved = true;
            state.unique = true;
            state.protectedProcess = ProcessInspector::isProtectedName(state.origin.imagePath) ||
                                     state.origin.pid == companionPid || state.origin.pid == GetCurrentProcessId();
            state.reason = state.protectedProcess
                ? QStringLiteral("发起者属于受保护进程，动作已拒绝")
                : QStringLiteral("已读取 UAC 发起者");
            const QString detailKey = QStringLiteral("%1/%2/%3/%4/%5")
                .arg(appInfoEvidence->consentPid)
                .arg(appInfoEvidence->appInfoPid)
                .arg(state.origin.pid)
                .arg(state.origin.creationTime)
                .arg(appInfoEvidence->targetPath);
            static QMutex detailCacheMutex;
            static QString cachedDetailKey;
            static ProcessActionState cachedDetails;
            bool cacheHit = false;
            {
                QMutexLocker locker(&detailCacheMutex);
                if (detailKey == cachedDetailKey)
                {
                    state.originIcon = cachedDetails.originIcon;
                    state.launchChain = cachedDetails.launchChain;
                    state.integrityLevel = cachedDetails.integrityLevel;
                    state.elevationType = cachedDetails.elevationType;
                    state.startTime = cachedDetails.startTime;
                    state.runDuration = processRunDuration(state.origin.creationTime);
                    state.originSignature = cachedDetails.originSignature;
                    state.targetSignature = cachedDetails.targetSignature;
                    cacheHit = true;
                }
            }
            if (!cacheHit)
            {
                if (scanCanceled(cancel)) return state;
                state.originIcon = processIcon(state.origin.imagePath);
                if (scanCanceled(cancel)) return state;
                state.launchChain = processLaunchChain(state.origin, cancel);
                if (scanCanceled(cancel)) return state;
                state.integrityLevel = tokenIntegrityLevel(state.origin.pid);
                if (scanCanceled(cancel)) return state;
                state.elevationType = tokenElevationType(state.origin.pid);
                state.startTime = formatFileTime(state.origin.creationTime);
                state.runDuration = processRunDuration(state.origin.creationTime);
                if (scanCanceled(cancel)) return state;
                state.originSignature = verifyFileSignature(state.origin.imagePath, cancel);
                if (scanCanceled(cancel)) return state;
                state.targetSignature = verifyFileSignature(appInfoEvidence->targetPath, cancel);
                if (scanCanceled(cancel)) return state; // Never publish incomplete canceled details.
                QMutexLocker locker(&detailCacheMutex);
                cachedDetailKey = detailKey;
                cachedDetails = state;
                KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                    "uac-match: AppInfo origin pid=%1 name=%2 target=%3 protected=%4 details=refreshed")
                                                       .arg(state.origin.pid)
                                                       .arg(ProcessInspector::fileName(state.origin.imagePath))
                                                       .arg(appInfoEvidence->targetPath)
                                                       .arg(state.protectedProcess ? 1 : 0));
            }
            else
            {
                state.runDuration = processRunDuration(state.origin.creationTime);
            }
        }

        if (!identity.isUac)
        {
            state.reason = QStringLiteral("当前未发现 UAC 窗口或有效 AppInfo 请求");
            return state;
        }

        // The old ALPC queue remains available for diagnostics, but it is not
        // used as an origin candidate: it observes transport participants and
        // cannot prove the request's original caller.
        if (!state.originResolved)
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "uac-match: UAC window seen but AppInfo origin is unresolved; actions disabled"));
            state.reason = QStringLiteral("已发现 UAC 窗口，尚未读取有效 AppInfo 发起者");
            return state;
        }
        // The request layout is selected coarsely by the Windows build family;
        // the action identity is the caller itself and every action still
        // revalidates its process identity.
        return state;
    }
}

BOOL CALLBACK UacWindowScanner::enumWindowProc(HWND hwnd, LPARAM lParam)
{
    auto* context = reinterpret_cast<WindowScanContext*>(lParam);
    if (scanCanceled(context->budget)) return FALSE;
    context->windows.push_back(hwnd);
    return TRUE;
}

BOOL CALLBACK UacWindowScanner::enumChildProc(HWND hwnd, LPARAM lParam)
{
    auto* context = reinterpret_cast<WindowScanContext*>(lParam);
    if (scanCanceled(context->budget)) return FALSE;
    const QString text = windowText(hwnd).trimmed();
    if (!text.isEmpty()) context->text.push_back(text);
    return TRUE;
}

QString UacWindowScanner::readUiAutomationName(HWND hwnd, const UacScanCancellation* cancel)
{
    if (!hwnd || scanCanceled(cancel))
        return {};

    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: probe begin hwnd=0x%1")
                                           .arg(reinterpret_cast<quintptr>(hwnd), 0, 16));
    const HRESULT initResult = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    const bool shouldUninitialize = SUCCEEDED(initResult);
    if (FAILED(initResult) && initResult != RPC_E_CHANGED_MODE)
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: CoInitializeEx(MTA) failed hr=0x%1")
                                               .arg(static_cast<unsigned long>(initResult), 0, 16));
        return {};
    }

    QStringList uiAutomationValues;
    IUIAutomation* automation = nullptr;
    HRESULT hr = scanCanceled(cancel) ? E_ABORT : CoCreateInstance(CLSID_CUIAutomation, nullptr, CLSCTX_INPROC_SERVER,
                                  IID_PPV_ARGS(&automation));
    if (SUCCEEDED(hr) && automation)
    {
        IUIAutomationElement* root = nullptr;
        hr = scanCanceled(cancel) ? E_ABORT : automation->ElementFromHandle(hwnd, &root);
        if (SUCCEEDED(hr) && root)
        {
            auto readRootBstr = [&](const wchar_t* label, HRESULT (STDMETHODCALLTYPE IUIAutomationElement::*getter)(BSTR*))
            {
                if (scanCanceled(cancel)) return;
                BSTR value = nullptr;
                const HRESULT valueResult = (root->*getter)(&value);
                if (SUCCEEDED(valueResult) && value)
                {
                    const QString text = QString::fromWCharArray(value).trimmed();
                    if (!text.isEmpty())
                        appendUniqueText(uiAutomationValues, QStringLiteral("%1=%2").arg(QString::fromWCharArray(label), text));
                    SysFreeString(value);
                }
            };
            readRootBstr(L"Name", &IUIAutomationElement::get_CurrentName);
            readRootBstr(L"Class", &IUIAutomationElement::get_CurrentClassName);
            readRootBstr(L"AutomationId", &IUIAutomationElement::get_CurrentAutomationId);
            readRootBstr(L"Provider", &IUIAutomationElement::get_CurrentProviderDescription);

            IUIAutomationCondition* condition = nullptr;
            IUIAutomationElementArray* elements = nullptr;
            hr = scanCanceled(cancel) ? E_ABORT : automation->CreateTrueCondition(&condition);
            if (!scanCanceled(cancel) && SUCCEEDED(hr) && condition)
                hr = root->FindAll(TreeScope_Descendants, condition, &elements);

            int elementCount = 0;
            if (SUCCEEDED(hr) && elements)
            {
                int length = 0;
                if (!scanCanceled(cancel) && SUCCEEDED(elements->get_Length(&length)))
                    elementCount = std::min(length, 256);
                for (int i = 0; i < elementCount && !scanCanceled(cancel); ++i)
                {
                    IUIAutomationElement* element = nullptr;
                    if (FAILED(elements->GetElement(i, &element)) || !element)
                        continue;

                    BSTR name = nullptr;
                    if (!scanCanceled(cancel) && SUCCEEDED(element->get_CurrentName(&name)) && name)
                    {
                        const QString elementName = QString::fromWCharArray(name).trimmed();
                        appendUniqueText(uiAutomationValues, QStringLiteral("Text=%1").arg(elementName));
                        SysFreeString(name);
                    }
                    element->Release();
                }
            }
            else
            {
                KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: FindAll failed hwnd=0x%1 hr=0x%2")
                                                       .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                       .arg(static_cast<unsigned long>(hr), 0, 16));
            }
            if (elements) elements->Release();
            if (condition) condition->Release();
            root->Release();
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: UIA success hwnd=0x%1 elements=%2 values=%3")
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(elementCount)
                                                   .arg(uiAutomationValues.join(QStringLiteral(" | ")).left(1000)));
        }
        else
        {
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: ElementFromHandle failed hwnd=0x%1 hr=0x%2")
                                                   .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                                   .arg(static_cast<unsigned long>(hr), 0, 16));
        }
        automation->Release();
    }
    else
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: CoCreateInstance(CUIAutomation) failed hr=0x%1")
                                               .arg(static_cast<unsigned long>(hr), 0, 16));
    }

    QStringList msaaValues;
    IAccessible* accessible = nullptr;
    hr = scanCanceled(cancel) ? E_ABORT : AccessibleObjectFromWindow(hwnd, OBJID_CLIENT, IID_IAccessible,
                                    reinterpret_cast<void**>(&accessible));
    if (SUCCEEDED(hr) && accessible)
    {
        LONG childCount = 0;
        if (!scanCanceled(cancel)) accessible->get_accChildCount(&childCount);
        childCount = std::clamp<LONG>(childCount, 0, 256);
        for (LONG child = 0; child <= childCount && !scanCanceled(cancel); ++child)
        {
            VARIANT childId{};
            VariantInit(&childId);
            childId.vt = VT_I4;
            childId.lVal = child == 0 ? CHILDID_SELF : child;
            BSTR name = nullptr;
            if (SUCCEEDED(accessible->get_accName(childId, &name)) && name)
            {
                appendUniqueText(msaaValues, QString::fromWCharArray(name));
                SysFreeString(name);
            }
            VariantClear(&childId);
        }
        accessible->Release();
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: MSAA success hwnd=0x%1 children=%2 values=%3")
                                               .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                               .arg(childCount)
                                               .arg(msaaValues.join(QStringLiteral(" | ")).left(1000)));
    }
    else
    {
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-ui: AccessibleObjectFromWindow failed hwnd=0x%1 hr=0x%2")
                                               .arg(reinterpret_cast<quintptr>(hwnd), 0, 16)
                                               .arg(static_cast<unsigned long>(hr), 0, 16));
    }

    if (shouldUninitialize)
        CoUninitialize();

    QStringList result;
    if (!uiAutomationValues.isEmpty())
        result.push_back(QStringLiteral("UIA: ") + uiAutomationValues.join(QStringLiteral(" | ")));
    if (!msaaValues.isEmpty())
        result.push_back(QStringLiteral("MSAA: ") + msaaValues.join(QStringLiteral(" | ")));
    return result.join(QStringLiteral(" | "));
}

UacScanResult collectUacScan(DWORD companionPid, const UacScanOriginHint& originHint,
    const UacScanCancellation& budget)
{
    UacScanResult result;
    if (budget.canceled()) return result;
    result.identity = UacWindowScanner::scan(&budget);
    if (!budget.canceled())
        result.actionState = resolveTargetInWorker(result.identity, PrivilegeStage::currentSessionId(), companionPid, originHint, &budget);
    return budget.canceled() ? UacScanResult{} : result;
}

UacDeskWindow::UacDeskWindow(QWidget* parent)
    : QMainWindow(parent)
{
    m_scanWorker = std::make_unique<UacScanWorker>();
    setWindowTitle(QStringLiteral("Ksword UAC 诊断"));
    const QIcon applicationIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico"));
    setWindowIcon(applicationIcon);
    setAttribute(Qt::WA_ShowWithoutActivating, true);
    // Winlogon 桌面没有普通 Shell 窗口管理链路。Tool + TopMost 是保证该独立
    // 辅助窗口进入可见 Z 序所必需的；ShowWithoutActivating/NOACTIVATE
    // 确保显示伴随窗口不会改变 UAC 的键盘焦点。
    setWindowFlags(Qt::Tool | Qt::FramelessWindowHint | Qt::WindowStaysOnTopHint);
    resize(430, 460);
    setMinimumWidth(320);
    setMinimumHeight(0);
    setMaximumWidth(460);
    setMaximumHeight(QWIDGETSIZE_MAX);
    auto* root = new QWidget(this);
    root->setObjectName(QStringLiteral("kswordUacDeskRoot"));
    auto* layout = new QVBoxLayout(root);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_brandHeader = new UacBrandHeaderWidget(applicationIcon, root);
    m_dragHandle = m_brandHeader;
    m_dragHandle->setCursor(Qt::OpenHandCursor);
    m_dragHandle->installEventFilter(this);
    layout->addWidget(m_brandHeader);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
        "ui: brand resources horizontalLogo=0 icon=%1 accent=%2")
                                           .arg(applicationIcon.isNull() ? 0 : 1)
                                           .arg(KswordTheme::ThemeColorName(KswordTheme::DefaultPrimaryAccentColor())));

    auto* content = new QWidget(root);
    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(18, 2, 18, 10);
    contentLayout->setSpacing(5);

    auto* originRow = new QWidget(content);
    auto* originLayout = new QHBoxLayout(originRow);
    originLayout->setContentsMargins(0, 0, 0, 0);
    originLayout->setSpacing(9);
    m_originIconLabel = new QLabel(originRow);
    m_originIconLabel->setFixedSize(20, 20);
    m_originIconLabel->setAlignment(Qt::AlignCenter);
    m_originIconLabel->setPixmap(removeFlatBackground(applicationIcon.pixmap(20, 20)));
    originLayout->addWidget(m_originIconLabel);
    m_identityLabel = new QLabel(QStringLiteral("等待 UAC 发起者..."), originRow);
    m_identityLabel->setObjectName(QStringLiteral("uacIdentityLabel"));
    m_identityLabel->setWordWrap(false);
    originLayout->addWidget(m_identityLabel, 1);
    contentLayout->addWidget(originRow);

    m_processLabel = new QLabel(QStringLiteral(
        "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"), content);
    m_processLabel->setObjectName(QStringLiteral("uacProcessDetailsLabel"));
    m_processLabel->setWordWrap(true);
    m_processLabel->setTextFormat(Qt::PlainText);
    contentLayout->addWidget(m_processLabel);
    contentLayout->addStretch(1);
    auto* actions = new QGridLayout();
    actions->setHorizontalSpacing(14);
    actions->setVerticalSpacing(5);
    m_terminateButton = new QPushButton(QStringLiteral("结束发起者"), content);
    m_terminateButton->setObjectName(QStringLiteral("uacTerminateButton"));
    m_suspendButton = new QPushButton(QStringLiteral("挂起发起者"), content);
    m_powerShellButton = new QPushButton(QStringLiteral("启动 PowerShell"), content);
    m_launchMainButton = new QPushButton(QStringLiteral("启动 Ksword"), content);
    const QSizePolicy buttonPolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_terminateButton->setSizePolicy(buttonPolicy);
    m_suspendButton->setSizePolicy(buttonPolicy);
    m_powerShellButton->setSizePolicy(buttonPolicy);
    m_launchMainButton->setSizePolicy(buttonPolicy);
    m_terminateButton->setFixedHeight(24);
    m_suspendButton->setFixedHeight(24);
    m_powerShellButton->setFixedHeight(24);
    m_launchMainButton->setFixedHeight(24);
    actions->setContentsMargins(0, 0, 0, 0);
    actions->setColumnStretch(0, 1);
    actions->setColumnStretch(1, 1);
    actions->addWidget(m_terminateButton, 0, 0);
    actions->addWidget(m_suspendButton, 0, 1);
    actions->addWidget(m_powerShellButton, 1, 0);
    actions->addWidget(m_launchMainButton, 1, 1);
    contentLayout->addLayout(actions);
    layout->addWidget(content, 1);
    setCentralWidget(root);
    refreshAppearance();

    QObject::connect(m_suspendButton, &QPushButton::clicked, this, [this] { runProcessAction(0); });
    QObject::connect(m_terminateButton, &QPushButton::clicked, this, [this] { runProcessAction(2); });
    QObject::connect(m_powerShellButton, &QPushButton::clicked, this, [this] { launchPowerShellOnSecureDesktop(); });
    QObject::connect(m_launchMainButton, &QPushButton::clicked, this, [this] { launchMainOnSecureDesktop(); });
    // Window presence is cheap to poll on the Winlogon desktop. Keep this
    // independent from the slower UIA/process-evidence work in the scan worker.
    m_refreshTimer.setInterval(500);
    m_refreshTimer.setTimerType(Qt::CoarseTimer);
    QObject::connect(&m_refreshTimer, &QTimer::timeout, this, [this] { refreshUacState(); });
    m_refreshTimer.start();
    if (QScreen* screen = QGuiApplication::primaryScreen())
    {
        const QRect work = screen->availableGeometry();
        setMaximumWidth(std::min(maximumWidth(), std::max(320, work.width() - 40)));
        adjustToContent();
        const int x = std::max(work.left(), work.right() - width() - 24);
        const int y = std::max(work.top(), std::min(work.top() + 72, work.bottom() - height() + 1));
        move(x, y);
    }
    updateButtons();
    // The companion is event-driven UI for an actual UAC prompt.  It must not
    // leave a visible window on the shared Winlogon desktop while the machine
    // is merely locked (or while no prompt is present).
    hide();
}

UacDeskWindow::~UacDeskWindow()
{
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("window: UacDeskWindow destructor"));
    m_refreshTimer.stop();
    m_scanStop = true;
    m_scanGeneration.fetch_add(1);
    m_scanWorker->close();
    if (m_parentWatchStop) SetEvent(m_parentWatchStop);
    if (m_parentWatchThread.joinable()) m_parentWatchThread.join();
    if (m_parentWatchStop) CloseHandle(m_parentWatchStop);
    if (m_actionThread.joinable()) m_actionThread.join();
    if (m_launchThread.joinable()) m_launchThread.join();
    if (m_parentProcess) CloseHandle(m_parentProcess);
}

bool UacDeskWindow::setParentWatch(HANDLE processHandle, quint64 creationTime)
{
    m_parentProcess = processHandle;
    if (!m_parentProcess) return true;
    // Validate once, then wait on this exact process object. PID reuse cannot
    // change the identity of an already-open process handle.
    if (creationTime == 0 || processCreationTime(m_parentProcess) != creationTime)
        return false;
    m_parentWatchStop = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!m_parentWatchStop) return false;
    m_parentWatchThread = std::thread([this]
    {
        // Cancellation comes first so destruction never queues another quit.
        const HANDLE waits[] = {m_parentWatchStop, m_parentProcess};
        const DWORD result = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
        if (result == WAIT_OBJECT_0 || m_scanStop.load()) return;
        // Close admission immediately on this value-only boundary. A ready
        // result already queued on Qt must not show a panel while quit waits.
        m_scanStop = true;
        m_scanGeneration.fetch_add(1);
        // A failed wait must not leave an unmonitored companion running.
        QMetaObject::invokeMethod(this, [this]
        {
            m_refreshTimer.stop();
            m_scanStop = true;
            m_scanGeneration.fetch_add(1);
            m_scanWorker->close();
            close();
            qApp->quit();
        }, Qt::QueuedConnection);
    });
    return true;
}

void UacDeskWindow::setInitialStatus(const QString& status) { showStatus(status); }

void UacDeskWindow::refreshNow()
{
    refreshUacState();
}

void UacDeskWindow::notifyUacActivity()
{
    m_fastPollUntilMs = GetTickCount64() + 5000;
    if (m_refreshTimer.interval() != 75)
    {
        m_refreshTimer.setInterval(75);
        m_refreshTimer.setTimerType(Qt::PreciseTimer);
        m_refreshTimer.start();
    }
}

void UacDeskWindow::refreshAppearance()
{
    applySystemPalette();
    setStyleSheet(uacDeskSystemStyle());
    adjustToContent();
    if (m_brandHeader)
        m_brandHeader->update();
}

void UacDeskWindow::adjustToContent()
{
    if (!centralWidget()) return;
    centralWidget()->layout()->activate();
    const int desiredHeight = qMax(1, sizeHint().height());
    if (height() != desiredHeight)
        resize(width(), desiredHeight);
}

bool UacDeskWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (watched != m_dragHandle)
        return QMainWindow::eventFilter(watched, event);

    if (event->type() == QEvent::MouseButtonPress)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            m_dragging = true;
            m_dragOffset = mouseEvent->globalPosition().toPoint() - frameGeometry().topLeft();
            if (m_dragHandle) m_dragHandle->setCursor(Qt::ClosedHandCursor);
            return true;
        }
    }
    else if (event->type() == QEvent::MouseMove && m_dragging)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        move(mouseEvent->globalPosition().toPoint() - m_dragOffset);
        return true;
    }
    else if (event->type() == QEvent::MouseButtonRelease)
    {
        auto* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton)
        {
            m_dragging = false;
            if (m_dragHandle) m_dragHandle->setCursor(Qt::OpenHandCursor);
            return true;
        }
    }
    return QMainWindow::eventFilter(watched, event);
}

void UacDeskWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);
    if (event && event->type() == QEvent::ApplicationPaletteChange)
        refreshAppearance();
}

void UacDeskWindow::refreshUacState()
{
    const quint64 now = GetTickCount64();
    if (m_fastPollUntilMs != 0 && now >= m_fastPollUntilMs)
    {
        m_fastPollUntilMs = 0;
        m_refreshTimer.setInterval(500);
        m_refreshTimer.setTimerType(Qt::CoarseTimer);
        m_refreshTimer.start();
    }
    if (m_scanStop.load() || m_scanWorker->busy()) return;
    const quint64 generation = m_scanGeneration.fetch_add(1) + 1;
    const UacScanOriginHint originHint = g_eventMonitor ? g_eventMonitor->scanOriginHint() : UacScanOriginHint{};
    const bool admitted = m_scanWorker->request(originHint, [this, generation](UacScanResult result)
    {
        if (!m_scanStop.load() && generation == m_scanGeneration.load())
            applyScanResult(result.identity, result.actionState);
    });
    if (!admitted && m_identity.isUac) applyScanResult({}, {});
}

void UacDeskWindow::applyScanResult(const UacApplicationIdentity& identity, const ProcessActionState& actionState)
{
    // AppInfo evidence may arrive before the native window scan.  It is useful
    // for correlating the request, but it is not enough to make a visible panel
    // with no anchor rectangle: otherwise a lock-screen/transition state could
    // expose a stale panel at its previous position.
    const bool hasVisibleUac = identity.isUac && identity.consentWindow != nullptr &&
                               !identity.windowRect.isEmpty();
    if (!hasVisibleUac)
    {
        // Winlogon is shared by UAC and the lock screen.  Visibility is gated
        // by positive UAC detection, not by the fact that this process can
        // access the Winlogon desktop.  Hide immediately on a negative scan so
        // a stale panel cannot remain visible on the lock screen.
        if (isVisible())
        {
            hide();
            KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
                "uac-visibility: hidden because no valid UAC window was detected"));
        }
        m_positionedUacWindow = nullptr;
        m_identity = {};
        m_actionState = {};
        m_originIconLabel->setPixmap(removeFlatBackground(QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico")).pixmap(20, 20)));
        m_identityLabel->setText(QStringLiteral("等待 UAC 发起者..."));
        m_processLabel->setText(QStringLiteral(
            "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"));
        adjustToContent();
        updateButtons();
        return;
    }
    const bool shouldPosition = m_positionedUacWindow == nullptr || m_positionedUacWindow != identity.consentWindow;
    m_identity = identity;
    m_actionState = actionState;
    if (m_actionState.originResolved)
    {
        const QString processName = ProcessInspector::fileName(m_actionState.origin.imagePath);
        const QIcon icon = m_actionState.originIcon.isNull()
            ? QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico"))
            : m_actionState.originIcon;
        m_originIconLabel->setPixmap(removeFlatBackground(icon.pixmap(20, 20)));
        m_identityLabel->setText(QStringLiteral("%1 · PID %2")
                                     .arg(processName.isEmpty() ? QStringLiteral("未知") : processName)
                                     .arg(m_actionState.origin.pid));
        m_processLabel->setText(QStringLiteral(
            "启动参数：%1\n进程位置：%2\n启动链：%3\n完整性级别：%4\n提升类型：%5\n启动时间：%6\n运行时长：%7\n数字签名（发起者）：%8\n数字签名（目标）：%9")
                                    .arg(m_actionState.origin.commandLine.isEmpty() ? QStringLiteral("不可用") : m_actionState.origin.commandLine)
                                    .arg(m_actionState.origin.imagePath)
                                    .arg(m_actionState.launchChain.isEmpty() ? QStringLiteral("不可用") : m_actionState.launchChain)
                                    .arg(m_actionState.integrityLevel)
                                    .arg(m_actionState.elevationType)
                                    .arg(m_actionState.startTime)
                                    .arg(m_actionState.runDuration)
                                    .arg(m_actionState.originSignature)
                                    .arg(m_actionState.targetSignature));
    }
    else
    {
        m_originIconLabel->setPixmap(removeFlatBackground(QIcon(QStringLiteral(":/KswordUacDesk/KswordLogo.ico")).pixmap(20, 20)));
        m_identityLabel->setText(QStringLiteral("UAC 已出现，正在读取发起者..."));
        m_processLabel->setText(QStringLiteral(
            "启动参数：不可用\n进程位置：不可用\n启动链：不可用\n完整性级别：不可用\n提升类型：不可用\n启动时间：不可用\n运行时长：不可用\n数字签名（发起者）：不可用\n数字签名（目标）：不可用"));
    }
    adjustToContent();
    updateButtons();
    if (shouldPosition)
    {
        // Keep the panel attached only by its top-left relationship to the
        // newly observed consent window.  Its height is content-driven and is
        // intentionally not forced to match the native UAC window.
        show();
        repositionBesideUac(identity);
        m_positionedUacWindow = identity.consentWindow;
        KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("uac-layout: positioned once hwnd=0x%1 rect=%2,%3,%4,%5")
                                               .arg(reinterpret_cast<quintptr>(identity.consentWindow), 0, 16)
                                               .arg(identity.windowRect.left()).arg(identity.windowRect.top())
                                               .arg(identity.windowRect.width()).arg(identity.windowRect.height()));
    }
    else if (!isVisible())
    {
        // A prompt can briefly disappear during its native transition.  If it
        // is still positively identified when the next result arrives, make
        // the companion visible again without activating it.
        show();
        SetWindowPos(reinterpret_cast<HWND>(winId()), HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW);
    }
}

void UacDeskWindow::repositionBesideUac(const UacApplicationIdentity& identity)
{
    if (!identity.consentWindow || identity.windowRect.isEmpty()) return;
    RECT nativeUac{};
    if (!GetWindowRect(identity.consentWindow, &nativeUac)) return;

    HWND ownWindow = reinterpret_cast<HWND>(winId());
    RECT nativePanel{};
    if (!ownWindow || !GetWindowRect(ownWindow, &nativePanel)) return;

    const UINT dpi = dpiForWindow(identity.consentWindow);
    const double scale = std::max(1.0, static_cast<double>(dpi) / 96.0);
    const int minimumNativeWidth = qRound(minimumWidth() * scale);
    const int preferredNativeWidth = qRound(430 * scale);
    int panelWidth = nativePanel.right - nativePanel.left;
    const int panelHeight = nativePanel.bottom - nativePanel.top;

    // The panel is attached in the same native coordinate space as consent:
    // zero gap, identical top, and content-driven height. If the monitor edge
    // leaves a narrower strip, shrink the Qt window before placing it.
    HMONITOR monitor = MonitorFromWindow(identity.consentWindow, MONITOR_DEFAULTTONEAREST);
    MONITORINFO monitorInfo{sizeof(monitorInfo)};
    if (monitor && GetMonitorInfoW(monitor, &monitorInfo))
    {
        const int availableRight = monitorInfo.rcWork.right - nativeUac.right;
        const int targetWidth = availableRight >= minimumNativeWidth
            ? std::min(preferredNativeWidth, availableRight)
            : preferredNativeWidth;
        if (targetWidth > 0 && targetWidth < panelWidth)
        {
            const int targetLogicalWidth = qMax(minimumWidth(), qRound(targetWidth / scale));
            resize(targetLogicalWidth, height());
            if (GetWindowRect(ownWindow, &nativePanel))
                panelWidth = nativePanel.right - nativePanel.left;
        }
    }

    const int x = nativeUac.right;
    const int y = nativeUac.top;
    const BOOL positioned = SetWindowPos(ownWindow,
                                         HWND_TOPMOST,
                                         x,
                                         y,
                                         panelWidth,
                                         panelHeight,
                                         SWP_NOACTIVATE | SWP_SHOWWINDOW);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral(
        "uac-layout: native adjacent right result=%1 x=%2 y=%3 w=%4 h=%5 uacRight=%6 uacTop=%7")
                                           .arg(positioned ? 1 : 0)
                                           .arg(x).arg(y).arg(panelWidth).arg(panelHeight)
                                           .arg(nativeUac.right).arg(nativeUac.top));
}

void UacDeskWindow::updateButtons()
{
    const bool allowed = m_actionState.unique && !m_actionState.protectedProcess && !m_actionRunning.load() && isWinlogonDesktop();
    m_suspendButton->setEnabled(allowed);
    m_terminateButton->setEnabled(allowed);
    m_powerShellButton->setEnabled(!m_launchRunning.load() && isWinlogonDesktop());
    m_launchMainButton->setEnabled(!m_launchRunning.load() && isWinlogonDesktop());
}

void UacDeskWindow::showStatus(const QString& status, bool error)
{
    Q_UNUSED(status);
    Q_UNUSED(error);
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("ui-status: %1").arg(status));
}

void UacDeskWindow::launchMainOnSecureDesktop()
{
    if (m_launchRunning.exchange(true)) return;
    if (m_launchThread.joinable()) m_launchThread.join();
    const QString executable = QDir(QCoreApplication::applicationDirPath()).filePath(QStringLiteral("Ksword5.1.exe"));
    KSWORD_UAC_DIAGNOSTIC_LOG(QStringLiteral("system-launch: Ksword target resolved from application directory: %1")
                                           .arg(executable));
    QStringList args;
    const DWORD sessionId = PrivilegeStage::currentSessionId();
    updateButtons();
    m_launchThread = std::thread([this, executable, args, sessionId]
    {
        QString error;
        const bool ok = PrivilegeStage::launchSystemStage(executable, args,
                                                          QString::fromWCharArray(kWinlogonDesktop),
                                                          sessionId, error);
        if (!m_scanStop.load())
        {
            QMetaObject::invokeMethod(this, [this, ok, error]
            {
                m_launchRunning = false;
                if (!ok)
                    showStatus(QStringLiteral("打开 Ksword5.1 失败：%1").arg(error), true);
                else
                    showStatus(QStringLiteral("已在当前 Winlogon 安全桌面启动 Ksword5.1"));
                updateButtons();
            }, Qt::QueuedConnection);
        }
        else
        {
            m_launchRunning = false;
        }
    });
}

void UacDeskWindow::launchPowerShellOnSecureDesktop()
{
    if (m_launchRunning.exchange(true)) return;
    if (m_launchThread.joinable()) m_launchThread.join();
    const QString windowsDirectory = QString::fromWCharArray([] {
        static wchar_t buffer[MAX_PATH] = {};
        static DWORD length = GetWindowsDirectoryW(buffer, static_cast<UINT>(std::size(buffer)));
        return buffer;
    }());
    const QString executable = QDir(windowsDirectory).filePath(QStringLiteral("System32/WindowsPowerShell/v1.0/powershell.exe"));
    const QStringList args{QStringLiteral("-NoLogo")};
    const DWORD sessionId = PrivilegeStage::currentSessionId();
    updateButtons();
    m_launchThread = std::thread([this, executable, args, sessionId]
    {
        QString error;
        const bool ok = PrivilegeStage::launchSystemStage(executable, args,
                                                          QString::fromWCharArray(kWinlogonDesktop),
                                                          sessionId, error);
        if (!m_scanStop.load())
        {
            QMetaObject::invokeMethod(this, [this, ok, error]
            {
                m_launchRunning = false;
                if (!ok)
                    showStatus(QStringLiteral("启动 PowerShell 失败：%1").arg(error), true);
                else
                    showStatus(QStringLiteral("已在当前 Winlogon 安全桌面启动 PowerShell"));
                updateButtons();
            }, Qt::QueuedConnection);
        }
        else
        {
            m_launchRunning = false;
        }
    });
}

void UacDeskWindow::runProcessAction(int action)
{
    if (!m_actionState.unique || m_actionState.protectedProcess)
    {
        showStatus(QStringLiteral("发起者身份未唯一确认或属于受保护进程，动作已拒绝"), true);
        refreshUacState();
        return;
    }
    if (m_actionRunning.exchange(true)) return;
    if (m_actionThread.joinable()) m_actionThread.join();
    const ProcessIdentity target = m_actionState.origin;
    updateButtons();
    m_actionThread = std::thread([this, action, target]
    {
        QString error;
        bool ok = ProcessInspector::identityStillMatches(target);
        if (ok)
        {
            if (action == 0) ok = ProcessInspector::suspend(target, error);
            else ok = ProcessInspector::terminate(target, error);
        }
        if (!m_scanStop.load())
        {
            QMetaObject::invokeMethod(this, [this, ok, error]
            {
                m_actionRunning = false;
                if (!ok && error.isEmpty())
                    showStatus(QStringLiteral("发起者身份在执行前校验失败，动作已拒绝"), true);
                else
                    showStatus(ok ? QStringLiteral("进程动作已完成") : QStringLiteral("进程动作失败：%1").arg(error), !ok);
                updateButtons();
                if (ok) QTimer::singleShot(250, this, [this] { refreshUacState(); });
            }, Qt::QueuedConnection);
        }
        else
        {
            m_actionRunning = false;
        }
    });
}
