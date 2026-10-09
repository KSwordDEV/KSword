#pragma once

#include "../UI/StructuredFieldView.h"
#include "../../../shared/driver/KswordArkDeviceAuditIoctl.h"
#include <optional>

namespace hardware_field_documents
{
    // PowerShell/CIM returns an ordered object of named record arrays, not formatted reports.
    // The adapter consumes its actual JSON schema and never splits labels/lines/columns.
    std::optional<ks::ui::FieldDocument> FromCimJson(const QString& payload);

    struct DeviceAuditColumns
    {
        QString ownerDriver;
        QString integrityStatus;
        QString integrityRows;
        QString modules;
        QString integrityFlags;
    };

    // Validity comes exclusively from v2 flags. Diagnostic text is never consulted.
    DeviceAuditColumns FromDeviceAuditEntry(const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry);
}
