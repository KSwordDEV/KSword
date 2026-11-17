#include "ArkProcessLifetimeProfile.h"
#include "ArkLocalDynDataProfile.h"
#include <QStringList>
#include <algorithm>
#include <array>
#include <mutex>

namespace
{
    bool lifetimeLayoutReady(const ksword::ark::DynDataFieldsResult& fields, QStringList& missing)
    {
        constexpr std::array required{
            KSW_DYN_FIELD_ID_EP_EXIT_TIME, KSW_DYN_FIELD_ID_EP_ACTIVE_THREADS,
            KSW_DYN_FIELD_ID_EP_OBJECT_TABLE, KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD,
            KSW_DYN_FIELD_ID_ET_CID, KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY,
            KSW_DYN_FIELD_ID_HT_TABLE_CODE, KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT
        };
        if (!fields.io.ok || fields.returnedCount != fields.totalCount)
            return false;
        for (const auto id : required)
        {
            const bool present = std::any_of(fields.entries.begin(), fields.entries.end(),
                [id](const ksword::ark::DynDataFieldEntry& row) {
                    return row.fieldId == id && (row.flags & KSW_DYN_FIELD_FLAG_PRESENT) != 0U &&
                        row.offset != 0xFFFFFFFFU;
                });
            if (!present) missing.push_back(QString::number(id));
        }
        return missing.isEmpty();
    }
}

ksword::ark::ProcessLifetimeProfileResult ksword::ark::prepareProcessLifetimeProfile(
    const DriverClient& client, const DynDataProfileText& texts)
{
    // Concurrent process workers must observe the completed apply, not race it.
    static std::mutex preparationMutex;
    const std::lock_guard lock(preparationMutex);
    ProcessLifetimeProfileResult result;
    QStringList missing;
    const auto fields = client.queryDynDataFields();
    if (lifetimeLayoutReady(fields, missing))
    {
        result.ready = true;
        return result;
    }
    const auto status = client.queryDynDataStatus();
    if (!status.io.ok || !status.ntoskrnl.present)
    {
        result.detail = QString::fromStdString(status.io.message);
        return result;
    }
    QString diagnostics;
    const auto profile = findMatchingPdbProfile(status.ntoskrnl, diagnostics, texts);
    result.detail = diagnostics;
    if (!profile.valid || profile.applyExInput.items.empty())
        return result;
    const auto applied = client.applyDynDataProfileEx(profile.applyExInput);
    result.applied = applied.io.ok && applied.status == 0 && applied.rejectedItemCount == 0;
    if (!result.applied)
    {
        result.detail += QString::fromStdString(applied.io.message);
        return result;
    }
    missing.clear();
    result.ready = lifetimeLayoutReady(client.queryDynDataFields(), missing);
    result.detail += QStringLiteral(" | layout=%1; missing=%2")
        .arg(result.ready ? 1 : 0).arg(missing.join(QLatin1Char(',')));
    return result;
}
