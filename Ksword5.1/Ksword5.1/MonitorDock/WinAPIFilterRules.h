#pragma once

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QSet>
#include <QString>
#include <algorithm>
#include <atomic>
#include <memory>

namespace ks::monitor {
// Immutable snapshots are shared with pipe readers and asynchronous list filtering.
struct WinAPIFilterSnapshot {
    QSet<QString> preModules, preFunctions, postModules, postFunctions;
    QSet<QString> preAllowed, postAllowed;
    static QString moduleKey(const QString& module) { return module.trimmed().toCaseFolded(); }
    static QString functionKey(const QString& module, const QString& function) {
        return moduleKey(module) + QChar(0x1f) + function.trimmed();
    }
    bool rejects(const QString& module, const QString& function, bool pre) const {
        const auto& modules = pre ? preModules : postModules;
        const auto& functions = pre ? preFunctions : postFunctions;
        const auto& allowed = pre ? preAllowed : postAllowed;
        const auto key = functionKey(module, function);
        return functions.contains(key) || (modules.contains(moduleKey(module)) && !allowed.contains(key));
    }
    bool rejectsApi(const QString& api, bool pre) const {
        const auto split = api.indexOf(QChar('!'));
        return split > 0 && split + 1 < api.size() && rejects(api.left(split), api.mid(split + 1), pre);
    }
};

class WinAPIFilterRules {
public:
    explicit WinAPIFilterRules(QString path) : m_path(std::move(path)), m_snapshot(std::make_shared<const WinAPIFilterSnapshot>()) {}
    std::shared_ptr<const WinAPIFilterSnapshot> snapshot() const { return m_snapshot.load(); }
    bool load() { if (!QFileInfo::exists(m_path)) return true; return importFile(m_path); }
    bool importFile(const QString& path) {
        QFile file(path); if (!file.open(QIODevice::ReadOnly) || file.size() > 4 * 1024 * 1024) return false;
        QJsonParseError error{}; const auto document = QJsonDocument::fromJson(file.readAll(), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
        const auto object = document.object();
        const int version = object.value(QStringLiteral("version")).toInt();
        if ((version != 1 && version != 2) || !object.value(QStringLiteral("rules")).isArray()) return false;
        auto next = std::make_shared<WinAPIFilterSnapshot>();
        const auto rules = object.value(QStringLiteral("rules")).toArray(); if (rules.size() > 20000) return false;
        for (const auto& item : rules) {
            if (!item.isObject()) return false;
            const auto row = item.toObject();
            if (!row.value(QStringLiteral("module")).isString() || !row.value(QStringLiteral("function")).isString()
                || !row.value(QStringLiteral("pre")).isBool() || !row.value(QStringLiteral("post")).isBool()) return false;
            const auto module = row.value(QStringLiteral("module")).toString().trimmed();
            const auto function = row.value(QStringLiteral("function")).toString().trimmed();
            if (module.isEmpty() || module.contains(QChar(0x1f)) || function.contains(QChar(0x1f))
                || module.size() > 260 || function.size() > 1024) return false;
            const auto key = function.isEmpty() ? WinAPIFilterSnapshot::moduleKey(module) : WinAPIFilterSnapshot::functionKey(module, function);
            if (row.value(QStringLiteral("pre")).toBool()) (function.isEmpty() ? next->preModules : next->preFunctions).insert(key);
            if (row.value(QStringLiteral("post")).toBool()) (function.isEmpty() ? next->postModules : next->postFunctions).insert(key);
            if (version == 2) {
                if (!row.value(QStringLiteral("preAllow")).isBool() || !row.value(QStringLiteral("postAllow")).isBool()) return false;
                if (function.isEmpty() && (row.value(QStringLiteral("preAllow")).toBool() || row.value(QStringLiteral("postAllow")).toBool())) return false;
                if (row.value(QStringLiteral("preAllow")).toBool()) next->preAllowed.insert(key);
                if (row.value(QStringLiteral("postAllow")).toBool()) next->postAllowed.insert(key);
            }
        }
        m_snapshot.store(std::shared_ptr<const WinAPIFilterSnapshot>(next)); return true;
    }
    bool save(const WinAPIFilterSnapshot& value) {
        if (!writeFile(m_path, value)) return false;
        m_snapshot.store(std::make_shared<const WinAPIFilterSnapshot>(value)); return true;
    }
    bool exportFile(const QString& path) const { return writeFile(path, *snapshot()); }
private:
    static bool writeFile(const QString& path, const WinAPIFilterSnapshot& value) {
        QSet<QString> keys = value.preModules; keys.unite(value.postModules); keys.unite(value.preFunctions); keys.unite(value.postFunctions);
        keys.unite(value.preAllowed); keys.unite(value.postAllowed);
        if (keys.size() > 20000) return false;
        auto sorted = keys.values(); std::sort(sorted.begin(), sorted.end()); QJsonArray rows;
        for (const auto& key : sorted) {
            const auto split = key.indexOf(QChar(0x1f)); const bool function = split >= 0;
            rows.append(QJsonObject{{QStringLiteral("module"), function ? key.left(split) : key},
                {QStringLiteral("function"), function ? key.mid(split + 1) : QString()},
                {QStringLiteral("pre"), function ? value.preFunctions.contains(key) : value.preModules.contains(key)},
                {QStringLiteral("post"), function ? value.postFunctions.contains(key) : value.postModules.contains(key)},
                {QStringLiteral("preAllow"), function && value.preAllowed.contains(key)},
                {QStringLiteral("postAllow"), function && value.postAllowed.contains(key)}});
        }
        if (!QDir().mkpath(QFileInfo(path).absolutePath())) return false;
        QSaveFile file(path); if (!file.open(QIODevice::WriteOnly)) return false;
        const auto data = QJsonDocument(QJsonObject{{QStringLiteral("version"), 2}, {QStringLiteral("rules"), rows}}).toJson();
        return data.size() <= 4 * 1024 * 1024 && file.write(data) == data.size() && file.commit();
    }
    QString m_path;
    std::atomic<std::shared_ptr<const WinAPIFilterSnapshot>> m_snapshot;
};
}
