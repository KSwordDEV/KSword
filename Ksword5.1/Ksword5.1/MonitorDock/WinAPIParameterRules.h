#pragma once
#include "WinAPIParameterDecode.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QHash>

namespace ks::monitor
{
    struct RawParameterRule { RawDecodeMode mode = RawDecodeMode::Parameters; QVector<RawParameterAllocation> allocations; };
    class WinAPIParameterRules final
    {
    public:
        explicit WinAPIParameterRules(QString file) : m_file(std::move(file)) {}
        static QString key(QString module, const QString& api)
        { return module.trimmed().toCaseFolded() + QChar(0x1f) + api.trimmed(); }
        RawParameterRule rule(const QString& identity) const { return m_rules.value(identity); }
        bool load()
        {
            QFile file(m_file); if (!file.exists()) return true;
            if (!file.open(QIODevice::ReadOnly) || file.size() > 4 * 1024 * 1024) return false;
            QJsonParseError error{}; const auto document = QJsonDocument::fromJson(file.readAll(), &error);
            if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
            const auto root = document.object();
            if (root.value(QStringLiteral("version")).toInt(-1) != 1 || !root.value(QStringLiteral("rules")).isArray()) return false;
            QHash<QString, RawParameterRule> loaded;
            for (const auto& value : root.value(QStringLiteral("rules")).toArray()) {
                if (!value.isObject()) return false;
                const auto object = value.toObject();
                const QString module = object.value(QStringLiteral("module")).toString().trimmed();
                const QString api = object.value(QStringLiteral("api")).toString().trimmed();
                const QString mode = object.value(QStringLiteral("mode")).toString();
                const auto arrayValue = object.value(QStringLiteral("allocations"));
                if (module.isEmpty() || api.isEmpty() || module.contains(QChar(0x1f)) || api.contains(QChar(0x1f))
                    || (mode != QStringLiteral("parameters") && mode != QStringLiteral("bytes")) || !arrayValue.isArray()) return false;
                const auto array = arrayValue.toArray(); if (array.size() > 128) return false;
                RawParameterRule rule; rule.mode = mode == QStringLiteral("bytes") ? RawDecodeMode::Bytes : RawDecodeMode::Parameters;
                for (const auto& entry : array) {
                    if (!entry.isObject()) return false;
                    const auto item = entry.toObject(); const QString type = item.value(QStringLiteral("type")).toString();
                    RawParameterAllocation allocation{};
                    if (type == QStringLiteral("int")) allocation.type = RawParameterType::Int;
                    else if (type == QStringLiteral("char")) allocation.type = RawParameterType::Char;
                    else if (type == QStringLiteral("bool")) allocation.type = RawParameterType::Bool;
                    else if (type == QStringLiteral("longlong")) allocation.type = RawParameterType::LongLong;
                    else if (type == QStringLiteral("uchar")) allocation.type = RawParameterType::UChar;
                    else if (type == QStringLiteral("short")) allocation.type = RawParameterType::Short;
                    else if (type == QStringLiteral("ushort")) allocation.type = RawParameterType::UShort;
                    else if (type == QStringLiteral("uint")) allocation.type = RawParameterType::UInt;
                    else if (type == QStringLiteral("ulonglong")) allocation.type = RawParameterType::ULongLong;
                    else if (type == QStringLiteral("float")) allocation.type = RawParameterType::Float;
                    else if (type == QStringLiteral("double")) allocation.type = RawParameterType::Double;
                    else if (type == QStringLiteral("pointer")) allocation.type = RawParameterType::Pointer;
                    else if (type == QStringLiteral("wchar")) allocation.type = RawParameterType::WChar;
                    else if (type == QStringLiteral("winbool")) allocation.type = RawParameterType::WinBool;
                    else if (type == QStringLiteral("long")) allocation.type = RawParameterType::Long;
                    else if (type == QStringLiteral("ulong")) allocation.type = RawParameterType::ULong;
                    else if (type == QStringLiteral("winbyte")) allocation.type = RawParameterType::WinByte;
                    else if (type == QStringLiteral("winword")) allocation.type = RawParameterType::WinWord;
                    else if (type == QStringLiteral("windword")) allocation.type = RawParameterType::WinDword;
                    else if (type == QStringLiteral("handle")) allocation.type = RawParameterType::Handle;
                    else if (type == QStringLiteral("sizet")) allocation.type = RawParameterType::SizeT;
                    else if (type == QStringLiteral("bytes")) { allocation.type = RawParameterType::Bytes; allocation.length = item.value(QStringLiteral("length")).toInt(); }
                    else return false;
                    if (allocation.type != RawParameterType::Bytes && item.contains(QStringLiteral("length")))
                        allocation.length = item.value(QStringLiteral("length")).toInt(-1);
                    if (!RawParameterWidth(allocation)) return false;
                    rule.allocations.push_back(allocation);
                }
                const auto identity = key(module, api); if (loaded.contains(identity)) return false;
                loaded.insert(identity, std::move(rule));
            }
            m_rules = std::move(loaded); return true;
        }
        bool saveRule(const QString& identity, const RawParameterRule& rule)
        {
            const int separator = identity.indexOf(QChar(0x1f));
            if (separator <= 0 || separator == identity.size() - 1 || rule.allocations.size() > 128) return false;
            for (const auto& allocation : rule.allocations) if (!RawParameterWidth(allocation)) return false;
            auto updated = m_rules; updated.insert(identity, rule);
            QJsonArray values; auto keys = updated.keys(); std::sort(keys.begin(), keys.end());
            for (const auto& k : keys) {
                const auto& item = updated[k]; const int split = k.indexOf(QChar(0x1f));
                QJsonArray allocations;
                for (const auto& allocation : item.allocations) {
                    QString type;
                    switch (allocation.type) {
                    case RawParameterType::Int: type = QStringLiteral("int"); break;
                    case RawParameterType::Char: type = QStringLiteral("char"); break;
                    case RawParameterType::Bool: type = QStringLiteral("bool"); break;
                    case RawParameterType::LongLong: type = QStringLiteral("longlong"); break;
                    case RawParameterType::UChar: type = QStringLiteral("uchar"); break;
                    case RawParameterType::Short: type = QStringLiteral("short"); break;
                    case RawParameterType::UShort: type = QStringLiteral("ushort"); break;
                    case RawParameterType::UInt: type = QStringLiteral("uint"); break;
                    case RawParameterType::ULongLong: type = QStringLiteral("ulonglong"); break;
                    case RawParameterType::Float: type = QStringLiteral("float"); break;
                    case RawParameterType::Double: type = QStringLiteral("double"); break;
                    case RawParameterType::Pointer: type = QStringLiteral("pointer"); break;
                    case RawParameterType::WChar: type = QStringLiteral("wchar"); break;
                    case RawParameterType::WinBool: type = QStringLiteral("winbool"); break;
                    case RawParameterType::Long: type = QStringLiteral("long"); break;
                    case RawParameterType::ULong: type = QStringLiteral("ulong"); break;
                    case RawParameterType::WinByte: type = QStringLiteral("winbyte"); break;
                    case RawParameterType::WinWord: type = QStringLiteral("winword"); break;
                    case RawParameterType::WinDword: type = QStringLiteral("windword"); break;
                    case RawParameterType::Handle: type = QStringLiteral("handle"); break;
                    case RawParameterType::SizeT: type = QStringLiteral("sizet"); break;
                    case RawParameterType::Bytes: type = QStringLiteral("bytes"); break;
                    }
                    QJsonObject a{{QStringLiteral("type"), type}};
                    if (allocation.type == RawParameterType::Bytes || allocation.length > 1) a.insert(QStringLiteral("length"), allocation.length);
                    allocations.append(a);
                }
                values.append(QJsonObject{{QStringLiteral("module"), k.left(split)}, {QStringLiteral("api"), k.mid(split + 1)},
                    {QStringLiteral("mode"), item.mode == RawDecodeMode::Bytes ? QStringLiteral("bytes") : QStringLiteral("parameters")},
                    {QStringLiteral("allocations"), allocations}});
            }
            if (!QDir().mkpath(QFileInfo(m_file).absolutePath())) return false;
            QSaveFile file(m_file); if (!file.open(QIODevice::WriteOnly)) return false;
            const auto data = QJsonDocument(QJsonObject{{QStringLiteral("version"), 1}, {QStringLiteral("rules"), values}}).toJson();
            if (file.write(data) != data.size() || !file.commit()) return false;
            m_rules = std::move(updated); return true;
        }
    private:
        QString m_file;
        QHash<QString, RawParameterRule> m_rules;
    };
}
