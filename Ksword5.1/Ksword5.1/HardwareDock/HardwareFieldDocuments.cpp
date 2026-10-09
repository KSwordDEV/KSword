#include "HardwareFieldDocuments.h"
#include "../UI/TypedSyntaxDocument.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

#include <utility>

namespace hardware_field_documents
{
    DeviceAuditColumns FromDeviceAuditEntry(const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry)
    {
        DeviceAuditColumns columns;
        const QString unavailable = QStringLiteral("<不可用>");
        columns.ownerDriver = (entry.fieldFlags & KSWORD_ARK_DEVICE_AUDIT_FIELD_OWNER_DRIVER_PRESENT) != 0U
            ? QStringLiteral("0x%1").arg(static_cast<qulonglong>(entry.ownerDriverObjectAddress), 16, 16, QChar('0')).toUpper()
            : unavailable;
        const bool summary = (entry.fieldFlags & KSWORD_ARK_DEVICE_AUDIT_FIELD_INTEGRITY_SUMMARY_PRESENT) != 0U;
        columns.integrityStatus = summary ? QString::number(entry.integrityStatus) : unavailable;
        columns.integrityRows = summary ? QStringLiteral("%1/%2").arg(entry.integrityReturnedCount).arg(entry.integrityTotalCount) : unavailable;
        columns.modules = summary ? QString::number(entry.integrityModuleCount) : unavailable;
        columns.integrityFlags = summary
            ? QStringLiteral("0x%1").arg(static_cast<qulonglong>(entry.integrityStatusFlags), 8, 16, QChar('0')).toUpper() : unavailable;
        return columns;
    }

    std::optional<ks::ui::FieldDocument> FromCimJson(const QString& payload)
    {
        // Preserve the collector's existing multi-page CIM scopes (thousands of records),
        // while byte-window JSON/XML keeps its smaller default presentation budget.
        ks::ui::TypedSyntaxLimits limits;
        limits.maximumCharacters = 16 * 1024 * 1024;
        limits.maximumNodes = 64 * 1024;
        auto syntax = ks::ui::ParseTypedSyntaxDocument(payload, limits);
        if (!syntax || syntax->kind != ks::ui::TypedSyntaxDocument::Kind::Json
            || syntax->fields.nodes.size() != 1)
            return std::nullopt;
        QString json = payload.trimmed();
        if (json.startsWith(QChar(0xFEFF))) json = json.mid(1).trimmed();
        const QJsonDocument parsed = QJsonDocument::fromJson(json.toUtf8());
        if (!parsed.isObject()) return std::nullopt;
        const QJsonObject object = parsed.object();
        ks::ui::FieldDocument document;
        for (auto& group : syntax->fields.nodes.front().children)
        {
            const QJsonValue records = object.value(group.name);
            if (!records.isArray()) return std::nullopt;
            for (const auto& record : records.toArray()) if (!record.isObject()) return std::nullopt;
            group.kind = ks::ui::FieldNode::Kind::Section;
            group.translateName = true; // The collector owns section labels; CIM data stays literal.
            for (auto& record : group.children)
            {
                QString recordName;
                for (const QString& candidate : {QStringLiteral("Name"), QStringLiteral("Model"),
                    QStringLiteral("Product"), QStringLiteral("BankLabel"), QStringLiteral("DeviceID"),
                    QStringLiteral("Manufacturer"), QStringLiteral("Antecedent")})
                {
                    for (const auto& field : record.children)
                        if (field.name == candidate && !field.value.isEmpty() && field.value != QStringLiteral("null"))
                        { recordName = field.value; break; }
                    if (!recordName.isEmpty()) break;
                }
                if (!recordName.isEmpty()) record.name = recordName;
                record.kind = ks::ui::FieldNode::Kind::Section;
                record.value.clear();
                record.translateName = false;
            }
            if (group.children.isEmpty())
            {
                ks::ui::FieldNode note;
                note.kind = ks::ui::FieldNode::Kind::Note;
                note.value = QStringLiteral("<未检测到>");
                group.children.append(std::move(note));
            }
            group.value.clear();
            document.nodes.append(std::move(group));
        }
        return document;
    }
}
