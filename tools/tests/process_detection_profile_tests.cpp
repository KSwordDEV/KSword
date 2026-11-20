#include "../../Ksword5.1/Ksword5.1/ArkDriverClient/ArkDriverClient.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QScopeGuard>
#include <iostream>
#include <stdexcept>

namespace
{
    // Substitute the guest system directory and driver transport only. Resource
    // and PE hashes, the production packet builder and readback checks are real.
    std::wstring kernelDirectory;
    UINT WINAPI testSystemDirectory(LPWSTR out, UINT size)
    {
        if (kernelDirectory.size() + 1 > size) return 0;
        wcscpy_s(out, size, kernelDirectory.c_str());
        return static_cast<UINT>(kernelDirectory.size());
    }
}
#define GetSystemDirectoryW testSystemDirectory
#include "../../Ksword5.1/Ksword5.1/ProcessDock/ProcessDetectionProfile.cpp"
#undef GetSystemDirectoryW

namespace
{
    ksword::ark::DynDataV4ModulesResult modules;
    ksword::ark::DynDataV4ItemsResult items;
    unsigned checks = 0, applications = 0;
    bool legacy = false, corruptReadback = false, collision = false;
    void check(bool value, const char* what)
    {
        ++checks;
        if (!value) throw std::runtime_error(what);
    }
    void clearSlot()
    {
        modules = {}; items = {}; modules.io.ok = items.io.ok = true;
        modules.totalCount = modules.returnedCount = 1;
        auto& slot = modules.entries.emplace_back();
        slot.module.image.present = 1;
        slot.module.image.classId = KSW_DYN_PROFILE_CLASS_NTOSKRNL;
        slot.module.image.machine = IMAGE_FILE_MACHINE_AMD64;
        slot.module.image.timeDateStamp = 0x6674bb5e; slot.module.image.sizeOfImage = 0x1450000;
        wcscpy_s(slot.module.image.moduleName, L"ntoskrnl.exe");
        slot.statusFlags = KSW_DYN_V4_STATUS_FLAG_PROCESS_ENUM_PROTECTED_APPLY;
    }
}
namespace ksword::ark
{
    DynDataCapabilitiesResult DriverClient::queryDynDataCapabilities() const
    {
        DynDataCapabilitiesResult r; r.io.ok = true;
        if (legacy) r.capabilityMask = KSW_CAP_PROCESS_LIST_FIELDS | KSW_CAP_THREAD_LIST_FIELDS;
        return r;
    }
    DynDataFieldsResult DriverClient::queryDynDataFields() const
    {
        DynDataFieldsResult r; r.io.ok = true;
        if (legacy) for (auto field : {KSW_DYN_FIELD_ID_EP_VAD_ROOT, KSW_DYN_FIELD_ID_EP_VAD_HINT, KSW_DYN_FIELD_ID_EP_VAD_COUNT})
        { auto& v = r.entries.emplace_back(); v.fieldId = field; v.flags = KSW_DYN_FIELD_FLAG_PRESENT; v.offset = 8; }
        r.totalCount = r.returnedCount = static_cast<uint32_t>(r.entries.size());
        return r;
    }
    DynDataV4ModulesResult DriverClient::queryDynDataV4Modules(unsigned long) const { return modules; }
    DynDataV4ItemsResult DriverClient::queryDynDataV4Items(unsigned long) const { return items; }
    DynDataV4ApplyResult DriverClient::applyDynDataProfileV4(const DynDataV4ApplyInput& input) const
    {
        ++applications;
        check(input.items.size() == 10 && input.capabilityGroups.size() == 1, "wrong read-only packet shape");
        auto& slot = modules.entries.front();
        if (collision)
        {
            slot.capabilityGroupCount = 1; slot.itemCount = 19;
            DynDataV4ApplyResult r; r.response.status = static_cast<long>(0xc0000035U); return r;
        }
        slot.module = input.module; slot.itemCount = 10; slot.capabilityGroupCount = slot.activeCapabilityGroupCount = 1;
        slot.statusFlags |= KSW_DYN_V4_STATUS_FLAG_PROFILE_APPLIED | KSW_DYN_V4_STATUS_FLAG_REQUIRED_COMPLETE |
            KSW_DYN_V4_STATUS_FLAG_IDENTITY_MATCHED;
        for (const auto& v : input.items) { auto& stored = items.entries.emplace_back(); stored.item = v; }
        items.totalCount = items.returnedCount = static_cast<uint32_t>(items.entries.size());
        if (corruptReadback) ++items.entries.front().item.valueLow;
        DynDataV4ApplyResult result; result.io.ok = true;
        return result;
    }
}
int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    using namespace ksword::detection;
    try
    {
        if (app.arguments().size() != 3) throw std::runtime_error("expected guest kernel directory and profile directory");
        kernelDirectory = QDir(app.arguments()[1]).absolutePath().toStdWString();
        const auto profileDir = QDir(app.arguments()[2]).absolutePath();
        ResearchSet selected; for (int id : {1,7,27}) selected.set(id-1);
        clearSlot();
        check(PrepareDetectionLayout({}, profileDir).isEmpty() && !applications, "unrelated methods applied offsets");
        modules.entries.front().statusFlags = 0;
        check(!PrepareDetectionLayout(selected, profileDir).isEmpty() && !applications, "old driver accepted a sparse replacement");
        clearSlot();
        modules.entries.front().itemCount = 1;
        check(!PrepareDetectionLayout(selected, profileDir).isEmpty() && !applications, "existing NTOS cache overwritten");
        clearSlot(); ++modules.entries.front().module.image.timeDateStamp;
        PrepareDetectionLayout(selected, profileDir);
        check(!applications, "nearby build applied");
        clearSlot(); legacy = true;
        check(PrepareDetectionLayout(selected, profileDir).isEmpty() && !applications, "existing native layout unnecessarily replaced");
        legacy = false;
        const auto expectedDir = kernelDirectory; kernelDirectory = L".";
        PrepareDetectionLayout(selected, profileDir);
        check(!applications, "missing or incorrect on-disk kernel was accepted");
        kernelDirectory = expectedDir;
        PrepareDetectionLayout(selected, app.applicationDirPath() + QStringLiteral("/absent"));
        check(!applications, "missing resource accepted");
        const auto filename = QStringLiteral("CE884F70F5A9025D53DB35D8BE8BFF79-1.json");
        QFile original(QDir(profileDir).filePath(filename));
        check(original.open(QIODevice::ReadOnly), "source profile unavailable");
        auto doc = QJsonDocument::fromJson(original.readAll()).object();
        auto profiles = doc["profiles"].toArray(); auto p = profiles.first().toObject();
        auto editedItems = p["items"].toArray(); auto f = editedItems.first().toObject();
        f["valueLow"] = f["valueLow"].toInt() + 8; editedItems[0] = f; p["items"] = editedItems; profiles[0] = p; doc["profiles"] = profiles;
        const QDir obj(app.applicationDirPath() + QStringLiteral("/ProcessProfile/obj"));
        check(obj.mkdir(QStringLiteral("altered")), "altered test directory already exists");
        const QDir altered(obj.filePath(QStringLiteral("altered")));
        QFile changed(altered.filePath(filename));
        const auto remove = qScopeGuard([&] { changed.close(); changed.remove(); obj.rmdir(QStringLiteral("altered")); });
        check(changed.open(QIODevice::NewOnly | QIODevice::WriteOnly), "altered test input unavailable");
        const auto content = QJsonDocument(doc).toJson(); check(changed.write(content) == content.size(), "test input write");
        changed.close(); PrepareDetectionLayout(selected, altered.absolutePath());
        check(!applications, "field digest accepted tampered data");
        PrepareDetectionLayout(selected, profileDir);
        check(applications == 1 && VerifyPreparedDetectionLayout(selected), "exact official kernel/resource/readback failed");
        PrepareDetectionLayout(selected, profileDir);
        check(applications == 1, "verified current group was reapplied");
        clearSlot(); corruptReadback = true;
        PrepareDetectionLayout(selected, profileDir);
        check(applications == 2 && !VerifyPreparedDetectionLayout(selected), "changed field readback accepted");
        clearSlot(); corruptReadback = false; collision = true;
        PrepareDetectionLayout(selected, profileDir); PrepareDetectionLayout(selected, profileDir);
        check(applications == 3 && modules.entries.front().itemCount == 19 && !VerifyPreparedDetectionLayout(selected),
            "concurrent unrelated group overwritten or mistaken for successful installation");
        std::cout << "PASS profile checks=" << checks << " allowed_items=10\n";
        return 0;
    }
    catch (const std::exception& e) { std::cerr << "FAIL " << checks << " " << e.what() << '\n'; return 1; }
}
