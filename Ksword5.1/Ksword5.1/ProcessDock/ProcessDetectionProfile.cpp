#include "ProcessDetectionProfile.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>

namespace ksword::detection
{
    namespace
    {
        using namespace ksword::ark;
        constexpr char guid[] = "CE884F70F5A9025D53DB35D8BE8BFF79";
        constexpr char groupName[] = "process.enumeration.readonly";
        constexpr char profileName[] = "process-detection-CE884F70F5A9025D53DB35D8BE8BFF79-1";
        constexpr char imageHash[] = "F6F275F67C7EF44FC2DF2D828658FB31EAFFD41018AC5A0FD9440E08D9912C30";
        constexpr char fieldsHash[] = "2E74B0FB951D002A613112963273B8963210931A7F7A5B88D690D37A6AA5A637";
        constexpr ULONG imageTimestamp = 0x6674bb5e, imageSize = 0x01450000;
        constexpr std::array<ULONG, 10> fields{
            KSW_DYN_FIELD_ID_EP_UNIQUE_PROCESS_ID, KSW_DYN_FIELD_ID_EP_ACTIVE_PROCESS_LINKS, KSW_DYN_FIELD_ID_EP_THREAD_LIST_HEAD,
            KSW_DYN_FIELD_ID_ET_CID, KSW_DYN_FIELD_ID_ET_THREAD_LIST_ENTRY, KSW_DYN_FIELD_ID_ET_START_ADDRESS, KSW_DYN_FIELD_ID_KT_PROCESS,
            KSW_DYN_FIELD_ID_EP_VAD_ROOT, KSW_DYN_FIELD_ID_EP_VAD_HINT, KSW_DYN_FIELD_ID_EP_VAD_COUNT
        };

        QByteArray digest(const QByteArray& data)
        { return QCryptographicHash::hash(data, QCryptographicHash::Sha256).toHex().toUpper(); }

        bool trustedItems(const std::vector<KSW_DYN_V4_ITEM_PACKET>& items)
        {
            if (items.size() != fields.size()) return false;
            QByteArray values;
            for (size_t i = 0; i < fields.size(); ++i)
            {
                const auto& v = items[i];
                if (v.itemId != fields[i] || v.itemKind != KSW_DYN_V4_ITEM_KIND_STRUCT_OFFSET ||
                    v.capabilityGroupId != KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY ||
                    v.flags != KSW_DYN_V4_ITEM_FLAG_REQUIRED || !v.valueLow || v.valueLow >= 0x10000 || v.valueLow % 8 ||
                    v.valueHigh || v.aux0 || v.aux1 || v.aux2 || v.aux3) return false;
                values += QByteArray::number(static_cast<quint32>(v.itemId)) + ':' +
                    QByteArray::number(static_cast<quint32>(v.valueLow)) + '\n';
            }
            return digest(values) == fieldsHash;
        }

        bool exactImage(const KSW_DYN_MODULE_IDENTITY_PACKET& id)
        {
            return id.present && id.classId == KSW_DYN_PROFILE_CLASS_NTOSKRNL && id.machine == IMAGE_FILE_MACHINE_AMD64 &&
                id.timeDateStamp == imageTimestamp && id.sizeOfImage == imageSize;
        }
        bool exactDiskKernel()
        {
            wchar_t system[MAX_PATH]{};
            const auto n = GetSystemDirectoryW(system, DWORD(std::size(system)));
            if (!n || n >= std::size(system)) return false;
            QFile image(QDir(QString::fromWCharArray(system)).filePath(QStringLiteral("ntoskrnl.exe")));
            if (!image.open(QIODevice::ReadOnly) || image.size() != 13172176) return false;
            QCryptographicHash hash(QCryptographicHash::Sha256);
            return hash.addData(&image) && hash.result().toHex().toUpper() == imageHash;
        }
        bool legacyReady(const DriverClient& client, const ResearchSet& selected)
        {
            const auto caps = client.queryDynDataCapabilities();
            if (!caps.io.ok || (selected.test(0) && !(caps.capabilityMask & KSW_CAP_PROCESS_LIST_FIELDS)) ||
                (selected.test(6) && !(caps.capabilityMask & KSW_CAP_THREAD_LIST_FIELDS))) return false;
            if (!selected.test(26)) return true;
            const auto present = client.queryDynDataFields();
            if (!present.io.ok || present.totalCount != present.returnedCount) return false;
            for (const auto field : {KSW_DYN_FIELD_ID_EP_VAD_ROOT, KSW_DYN_FIELD_ID_EP_VAD_HINT, KSW_DYN_FIELD_ID_EP_VAD_COUNT})
                if (std::none_of(present.entries.cbegin(), present.entries.cend(), [field](const auto& v) {
                    return v.fieldId == field && (v.flags & KSW_DYN_FIELD_FLAG_PRESENT) && v.offset && v.offset < 0x10000;
                })) return false;
            return true;
        }
        bool readResource(const QString& fileName, const KSW_DYN_MODULE_IDENTITY_PACKET& id, DynDataV4ApplyInput& packet)
        {
            QFile file(fileName);
            if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) return false;
            const auto doc = QJsonDocument::fromJson(file.readAll()).object();
            const auto profiles = doc.value("profiles").toArray();
            if (doc.value("packVersion").toInt() != 4 || doc.value("imageSha256").toString() != QLatin1String(imageHash) ||
                profiles.size() != 1 || !exactImage(id)) return false;
            const auto p = profiles[0].toObject();
            const auto groups = p.value("capabilityGroups").toArray();
            if (p.value("profileName").toString() != QLatin1String(profileName) || p.value("pdbGuid").toString() != QLatin1String(guid) ||
                p.value("pdbName").toString() != QStringLiteral("ntkrnlmp.pdb") || p.value("pdbAge").toInt() != 1 ||
                p.value("moduleClassId").toInt(-1) != 0 || p.value("machine").toInteger(-1) != id.machine ||
                p.value("sizeOfImage").toInteger(-1) != id.sizeOfImage || p.value("timeDateStamp").toInteger(-1) != id.timeDateStamp ||
                groups.size() != 1) return false;
            const auto group = groups[0].toObject();
            if (group.value("groupId").toInt() != KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY ||
                group.value("groupName").toString() != QLatin1String(groupName) || group.value("requiredItemCount").toInt() != int(fields.size()) ||
                group.value("optionalItemCount").toInt(-1) || group.value("flags").toInt(-1)) return false;
            packet.module.image = id;
            strcpy_s(packet.module.pdb.pdbName, "ntkrnlmp.pdb");
            strcpy_s(packet.module.pdb.pdbGuid, guid);
            strcpy_s(packet.module.profileName, profileName);
            packet.module.pdb.pdbAge = 1;
            auto& out = packet.capabilityGroups.emplace_back();
            out.groupId = KSW_DYN_V4_CAPABILITY_GROUP_PROCESS_ENUM_READONLY;
            out.requiredItemCount = static_cast<ULONG>(fields.size());
            strcpy_s(out.groupName, groupName);
            for (const auto& value : p.value("items").toArray())
            {
                const auto item = value.toObject();
                const auto u = [&](const char* key) { return static_cast<ULONG>(item.value(key).toInt(-1)); };
                packet.items.push_back({u("itemId"), u("itemKind"), u("flags"), u("capabilityGroupId"),
                    u("valueLow"), u("valueHigh"), u("aux0"), u("aux1"), u("aux2"), u("aux3")});
            }
            return trustedItems(packet.items);
        }
        std::optional<KSW_DYN_V4_MODULE_STATUS_ENTRY> kernelSlot(const DriverClient& client)
        {
            const auto modules = client.queryDynDataV4Modules();
            if (!modules.io.ok || modules.totalCount != modules.returnedCount) return {};
            for (const auto& entry : modules.entries)
                if (entry.module.image.present && entry.module.image.classId == KSW_DYN_PROFILE_CLASS_NTOSKRNL) return entry;
            return {};
        }
        bool confirmed(const DriverClient& client, const KSW_DYN_V4_MODULE_STATUS_ENTRY& slot)
        {
            constexpr auto published = KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED | KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE |
                KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED | KSW_DYN_V4_STATUS_FLAG_PROCESS_ENUM_PROTECTED_APPLY;
            if (!exactImage(slot.module.image) || (slot.statusFlags & published) != published ||
                slot.itemCount != fields.size() || slot.capabilityGroupCount != 1 || slot.activeCapabilityGroupCount != 1 ||
                slot.module.pdb.pdbAge != 1 || strncmp(slot.module.profileName, profileName, sizeof(slot.module.profileName)) ||
                strncmp(slot.module.pdb.pdbGuid, guid, sizeof(slot.module.pdb.pdbGuid))) return false;
            const auto result = client.queryDynDataV4Items();
            if (!result.io.ok || result.totalCount != result.returnedCount) return false;
            std::vector<KSW_DYN_V4_ITEM_PACKET> items;
            for (const auto& row : result.entries)
                if (row.moduleClassId == KSW_DYN_PROFILE_CLASS_NTOSKRNL) items.push_back(row.item);
            std::sort(items.begin(), items.end(), [](const auto& a, const auto& b) { return a.itemId < b.itemId; });
            return trustedItems(items);
        }
    }

    QString PrepareDetectionLayout(const ResearchSet& selected, const QString& profileDirectory)
    {
        if (!selected.test(0) && !selected.test(6) && !selected.test(26)) return {};
        static std::mutex lock;
        const std::lock_guard serialize(lock);
        const ark::DriverClient client;
        if (legacyReady(client, selected)) return {};
        const auto slot = kernelSlot(client);
        if (!slot) return QStringLiteral("未取得驱动的 NTOS 只读布局状态。");
        if (!(slot->statusFlags & KSW_DYN_V4_STATUS_FLAG_PROCESS_ENUM_PROTECTED_APPLY))
            return QStringLiteral("驱动未提供只读枚举布局的防覆盖安装。");
        if (!exactImage(slot->module.image)) return QStringLiteral("没有与当前内核身份匹配的只读枚举布局。");
        if (slot->itemCount || slot->capabilityGroupCount || (slot->statusFlags & KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED))
            return confirmed(client, *slot) ? QStringLiteral("已核对驱动中的 10 项专用只读布局。") :
                QStringLiteral("保留现有 NTOS 配置，专用只读布局未装入。");
        // The pinned PE digest binds its file RSDS to the exact public PDB. The
        // protected v4 receiver also checks the mapped kernel identity under its lock.
        if (!exactDiskKernel()) return QStringLiteral("磁盘内核与专用只读布局的 SHA-256 不匹配。");
        const QDir dir(profileDirectory.isEmpty() ? QCoreApplication::applicationDirPath() +
            QStringLiteral("/profiles/process-detection") : profileDirectory);
        ark::DynDataV4ApplyInput input;
        if (!readResource(dir.filePath(QLatin1String(guid) + QStringLiteral("-1.json")), slot->module.image, input))
            return QStringLiteral("专用只读布局文件缺失或字段摘要校验失败。");
        const auto applied = client.applyDynDataProfileV4(input);
        const auto after = kernelSlot(client);
        if (after && confirmed(client, *after)) return QStringLiteral("专用只读布局已装入，10 项字段回读一致。");
        return QStringLiteral("专用只读布局未通过回读，Win32=%1，NTSTATUS=0x%2。")
            .arg(applied.io.win32Error).arg(static_cast<quint32>(applied.response.status), 0, 16);
    }

    bool VerifyPreparedDetectionLayout(const ResearchSet& selected)
    {
        if (!selected.test(0) && !selected.test(6) && !selected.test(26)) return true;
        const ark::DriverClient client;
        if (legacyReady(client, selected)) return true;
        const auto current = kernelSlot(client);
        return current && confirmed(client, *current);
    }
}
