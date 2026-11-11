#pragma once

#include "WinAPISessionBackend.h"
#include <QDateTime>
#include <QStringList>
#include <QVariant>
#include <limits>
#include <unordered_map>

// Display columns are a projection of the immutable record. The six original
// WinAPIEventFields remain the disk archive/search format for compatibility.
namespace ks::monitor {
enum EventColumn {
    Time, Category, Api, Status, PidTid, Sequence, Module, Pid, Tid,
    Summary, ReturnValue, Duration, CallerModule, CallerAddress,
    MemoryKind, Phase, OperationId, CaptureKind, RawTime, ProcessName,
    RelativeTime, Detail, ColumnCount
};
struct EventTimeRange { bool enabled = false; std::uint64_t first = 0, last = 0; };
// This UI-side cache is a projection of a later process query, never a claim
// about the address mapping at event time. Keys identify immutable records.
struct CallerColumnValues { QString module, memoryKind; std::uint64_t observedTime100ns = 0; };
using CallerColumnMap = std::unordered_map<const WinAPIEventRecord*, CallerColumnValues>;
inline std::uint64_t EventTimestamp(const WinAPIEventRow& row, bool* valid)
{
    if (row.timestamp100ns) { if (valid) *valid = true; return row.timestamp100ns; }
    bool ok = false; const auto ticks = row.time100nsText.toULongLong(&ok);
    if (valid) *valid = ok && ticks != 0;
    return ticks;
}
inline bool EventInTimeRange(const WinAPIEventRef& record, const EventTimeRange& range)
{
    if (!range.enabled) return true;
    if (!record) return false;
    bool valid = false; const auto ticks = EventTimestamp(record->value, &valid);
    return valid && ticks && ticks >= range.first && ticks <= range.last;
}
inline QString EventColumnText(const WinAPIEventRef& record, int column, const CallerColumnMap* callerColumns = nullptr)
{
    if (!record) return {};
    const auto& row = record->value;
    const QString unavailable = QStringLiteral("-");
    const int bang = row.apiText.indexOf(QChar('!'));
    switch (column) {
    case Time: {
        bool ok = false; const auto ticks = EventTimestamp(row, &ok);
        constexpr quint64 epoch = 116444736000000000ULL;
        if (!ok || ticks < epoch) return row.time100nsText;
        const auto ms = (ticks - epoch) / 10000;
        if (ms > quint64(std::numeric_limits<qint64>::max())) return row.time100nsText;
        return QDateTime::fromMSecsSinceEpoch(static_cast<qint64>(ms)).toLocalTime().toString(QStringLiteral("HH:mm:ss.zzz"));
    }
    case Category: return row.categoryText;
    case Api: return bang >= 0 ? row.apiText.mid(bang + 1) : row.apiText;
    case Status: return row.resultText == QStringLiteral("未采集") || row.resultText.isEmpty() ? unavailable : row.resultText;
    case PidTid: return row.pidTidText;
    case Sequence: return record->sequence ? QString::number(record->sequence) : unavailable;
    case Module: return bang > 0 ? row.apiText.left(bang) : unavailable;
    case Pid: return row.pidTidText.section(QChar('/'), 0, 0).trimmed();
    case Tid: { const auto tid = row.pidTidText.section(QChar('/'), 1, 1).trimmed(); return tid.isEmpty() ? unavailable : tid; }
    case Summary:
        if (row.internalEvent) return row.detailText.left(180);
        if (row.detailText.contains(QStringLiteral("strongTyped=0"))) return unavailable;
        return row.detailText.isEmpty() ? unavailable : row.detailText.left(180);
    case CallerAddress: {
        const int marker = row.detailText.indexOf(QStringLiteral(" caller=0x"));
        const int rawMarker = row.detailText.indexOf(QStringLiteral(" strongTyped=0"));
        if (marker < 0 || rawMarker < marker) return unavailable;
        const int first = marker + 8;
        int end = first + 2;
        while (end < row.detailText.size()) {
            const QChar ch = row.detailText.at(end);
            if (!((ch >= QLatin1Char('0') && ch <= QLatin1Char('9')) ||
                  (ch >= QLatin1Char('a') && ch <= QLatin1Char('f')) ||
                  (ch >= QLatin1Char('A') && ch <= QLatin1Char('F')))) break;
            ++end;
        }
        return end > first + 2 ? row.detailText.mid(first, end - first) : unavailable;
    }
    case Phase: {
        if (!row.detailText.startsWith(QChar('['))) return unavailable;
        const int marker = row.detailText.indexOf(QStringLiteral(" #"));
        const int close = row.detailText.indexOf(QChar(']'));
        return marker > 1 && close > marker ? row.detailText.mid(1, marker - 1) : unavailable;
    }
    case OperationId: {
        if (!row.detailText.startsWith(QChar('['))) return unavailable;
        const int marker = row.detailText.indexOf(QStringLiteral(" #"));
        const int close = row.detailText.indexOf(QChar(']'));
        if (marker < 0 || close <= marker + 2) return unavailable;
        const auto id = row.detailText.mid(marker + 2, close - marker - 2);
        bool ok = false; id.toULongLong(&ok); return ok ? id : unavailable;
    }
    case CaptureKind: return row.internalEvent ? QStringLiteral("内部")
        : (row.detailText.contains(QStringLiteral("strongTyped=0")) ? QStringLiteral("Raw")
            : (row.durationCaptured || !row.capturedReturnValue.isEmpty() ? QStringLiteral("Strong") : unavailable));
    case RawTime: return row.timestamp100ns ? QString::number(row.timestamp100ns) : row.time100nsText;
    case ProcessName: return row.sourceProcessName.isEmpty() ? unavailable : row.sourceProcessName;
    case RelativeTime: {
        bool ok = false; const auto ticks = EventTimestamp(row, &ok);
        if (!ok || !record->sessionBase100ns) return unavailable;
        const bool negative = ticks < record->sessionBase100ns;
        const quint64 difference = negative ? record->sessionBase100ns - ticks : ticks - record->sessionBase100ns;
        if (difference > quint64(std::numeric_limits<qint64>::max())) return unavailable;
        return QStringLiteral("%1%2.%3 ms").arg(negative ? QLatin1Char('-') : QLatin1Char('+'))
            .arg(difference / 10000).arg(difference % 10000, 4, 10, QLatin1Char('0'));
    }
    case Detail: return row.detailText;
    case ReturnValue: return row.capturedReturnValue.isEmpty() ? unavailable : row.capturedReturnValue;
    case CallerModule: case MemoryKind: {
        if (!callerColumns) return unavailable;
        const auto found = callerColumns->find(record.get());
        if (found == callerColumns->end()) return unavailable;
        const auto& value = column == CallerModule ? found->second.module : found->second.memoryKind;
        return value.isEmpty() ? unavailable : value + QStringLiteral(" [snapshot]");
    }
    case Duration: return row.durationCaptured
        ? QStringLiteral("%1.%2 ms").arg(row.duration100ns / 10000).arg(row.duration100ns % 10000, 4, 10, QLatin1Char('0'))
        : unavailable;
    default: return {};
    }
}
inline QStringList EventColumnTexts(const WinAPIEventRef& record, const CallerColumnMap* callerColumns = nullptr)
{
    QStringList cells; cells.reserve(ColumnCount);
    for (int i = 0; i < ColumnCount; ++i) cells.push_back(EventColumnText(record, i, callerColumns));
    return cells;
}
inline QVariant EventSortValue(const WinAPIEventRef& record, int column, const CallerColumnMap* callerColumns = nullptr)
{
    if (!record) return {};
    bool ok = false; qulonglong value = 0;
    switch (column) {
    case Time: case RawTime: value = EventTimestamp(record->value, &ok); break;
    case Sequence: value = record->sequence; ok = value != 0; break;
    case Duration: value = record->value.duration100ns; ok = record->value.durationCaptured; break;
    case Pid: case Tid: case OperationId: value = EventColumnText(record, column).toULongLong(&ok); break;
    case CallerAddress: case ReturnValue: value = EventColumnText(record, column).toULongLong(&ok, 16); break;
    case RelativeTime: {
        const auto ticks = EventTimestamp(record->value, &ok);
        if (!ok || !record->sessionBase100ns) return {};
        const bool negative = ticks < record->sessionBase100ns;
        const quint64 diff = negative ? record->sessionBase100ns - ticks : ticks - record->sessionBase100ns;
        if (diff > quint64(std::numeric_limits<qint64>::max())) return {};
        return QVariant::fromValue(negative ? -qint64(diff) : qint64(diff));
    }
    default: return EventColumnText(record, column, callerColumns);
    }
    return ok ? QVariant::fromValue(value) : QVariant();
}
}
