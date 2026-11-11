#pragma once

#include "WinAPIFilterRules.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>
#include <utility>
#include <vector>

namespace ks::monitor {
struct WinAPIFilterCatalogEntry { QString module, function, category; };
using WinAPIFilterCatalog = std::vector<WinAPIFilterCatalogEntry>;

// Parse the shipped definition file off the GUI thread; retain exact export case.
inline bool ParseWinAPIFilterCatalog(const QByteArray& data, WinAPIFilterCatalog* result)
{
    if (!result || data.size() > 16 * 1024 * 1024) return false;
    QJsonParseError error{};
    const auto document = QJsonDocument::fromJson(data, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    const auto root = document.object();
    if (root.value(QStringLiteral("schema_version")).toInt() != 1 || !root.value(QStringLiteral("apis")).isArray()) return false;
    const auto entries = root.value(QStringLiteral("apis")).toArray();
    if (entries.size() > 100000) return false;
    WinAPIFilterCatalog parsed; parsed.reserve(static_cast<std::size_t>(entries.size())); QSet<QString> seen;
    for (const auto& entry : entries) {
        if (!entry.isObject()) return false;
        const auto item = entry.toObject();
        if (!item.value(QStringLiteral("module")).isString() || !item.value(QStringLiteral("export")).isString()) return false;
        const auto module = item.value(QStringLiteral("module")).toString().trimmed();
        const auto function = item.value(QStringLiteral("export")).toString().trimmed();
        if (module.isEmpty() || function.isEmpty() || module.contains(QChar(0x1f)) || function.contains(QChar(0x1f))) return false;
        const auto key = WinAPIFilterSnapshot::functionKey(module, function);
        if (!seen.contains(key)) { seen.insert(key); parsed.push_back({module, function, item.value(QStringLiteral("category")).toString()}); }
    }
    const auto refValue = root.value(QStringLiteral("reference_signatures"));
    if (!refValue.isUndefined()) {
        if (!refValue.isObject()) return false;
        const auto refs = refValue.toObject();
        if (refs.value(QStringLiteral("schema_version")).toInt(-1) != 1
            || refs.value(QStringLiteral("status")).toString() != QStringLiteral("unverified")
            || !refs.value(QStringLiteral("entries")).isArray()) return false;
        const auto rows = refs.value(QStringLiteral("entries")).toArray();
        if (rows.size() > 65536 || rows.size() + entries.size() > 100000) return false;
        parsed.reserve(static_cast<std::size_t>(entries.size() + rows.size()));
        for (const auto& row : rows) {
            if (!row.isArray()) return false;
            const auto fields = row.toArray();
            if (fields.size() != 6 || !fields[0].isString() || !fields[1].isString()) return false;
            const auto module = fields[0].toString().trimmed();
            const auto function = fields[1].toString().trimmed();
            if (module.isEmpty() || function.isEmpty() || module.contains(QChar(0x1f)) || function.contains(QChar(0x1f))) return false;
            const auto key = WinAPIFilterSnapshot::functionKey(module, function);
            if (!seen.contains(key)) { seen.insert(key); parsed.push_back({module, function, {}}); }
        }
    }
    *result = std::move(parsed); return true;
}
}
