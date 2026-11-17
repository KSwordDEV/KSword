// QtCore-only fixture: real production profile parser/preparer and IOCTL codecs.
#include "Ksword5.1/Ksword5.1/ArkDriverClient/ArkProcessLifetimeProfile.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonArray>
#include <QJsonObject>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <thread>

static bool live = false, rejectApply = false, loseReadback = false;
static unsigned appliedCount = 0, cases = 0;
static std::array<ULONG, 8> ids{106, 121, 1, 59, 62, 63, 67, 3};
static std::array<bool, 8> present{};
static KSW_DYN_MODULE_IDENTITY_PACKET identity{};
static void check(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

ksword::ark::IoResult ksword::ark::DriverClient::deviceIoControl(
    ULONG code, void* input, ULONG inputBytes, void* output, ULONG outputBytes, DriverHandle*) const
{
    IoResult result{};
    if (live) {
        HANDLE device = CreateFileW(L"\\\\.\\KswordARKLog", GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (device == INVALID_HANDLE_VALUE) { result.win32Error = GetLastError(); return result; }
        DWORD bytes = 0;
        result.ok = DeviceIoControl(device, code, input, inputBytes, output, outputBytes, &bytes, nullptr) != FALSE;
        result.win32Error = result.ok ? 0 : GetLastError(); result.bytesReturned = bytes;
        CloseHandle(device); return result;
    }
    result.ok = true;
    if (code == IOCTL_KSWORD_ARK_QUERY_DYN_FIELDS) {
        auto* reply = static_cast<KSW_QUERY_DYN_FIELDS_RESPONSE*>(output);
        reply->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION;
        reply->entrySize = sizeof(KSW_DYN_FIELD_ENTRY); reply->totalCount = reply->returnedCount = ULONG(ids.size());
        result.bytesReturned = ULONG(offsetof(KSW_QUERY_DYN_FIELDS_RESPONSE, entries) + ids.size() * sizeof(KSW_DYN_FIELD_ENTRY));
        check(result.bytesReturned <= outputBytes, "field output buffer");
        for (size_t i = 0; i < ids.size(); ++i) {
            reply->entries[i].fieldId = ids[i]; reply->entries[i].flags = present[i] ? KSW_DYN_FIELD_FLAG_PRESENT : 0;
            reply->entries[i].offset = present[i] ? 16 : 0xffffffffUL;
        }
    } else if (code == IOCTL_KSWORD_ARK_QUERY_DYN_STATUS) {
        auto* reply = static_cast<KSW_QUERY_DYN_STATUS_RESPONSE*>(output);
        reply->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION; reply->ntoskrnl = identity;
        result.bytesReturned = sizeof(*reply);
    } else if (code == IOCTL_KSWORD_ARK_APPLY_DYN_PROFILE_EX) {
        const auto* request = static_cast<const KSW_APPLY_DYN_PROFILE_EX_REQUEST*>(input);
        check(request->itemCount > 0 && request->ntoskrnl.timeDateStamp == identity.timeDateStamp &&
            request->ntoskrnl.sizeOfImage == identity.sizeOfImage, "exact identity in production EX request");
        check(inputBytes == KSW_APPLY_DYN_PROFILE_EX_REQUEST_HEADER_SIZE + request->itemCount * sizeof(KSW_DYN_PROFILE_EX_ITEM_PACKET), "production EX request length");
        ++appliedCount;
        auto* reply = static_cast<KSW_APPLY_DYN_PROFILE_EX_RESPONSE*>(output);
        reply->version = KSWORD_ARK_DYNDATA_PROTOCOL_VERSION; reply->status = rejectApply ? LONG(0xc000000dUL) : 0;
        reply->rejectedItemCount = rejectApply ? request->itemCount : 0;
        reply->appliedItemCount = rejectApply ? 0 : request->itemCount;
        result.bytesReturned = sizeof(*reply);
        if (!rejectApply && !loseReadback) for (ULONG item = 0; item < request->itemCount; ++item)
            for (size_t field = 0; field < ids.size(); ++field)
                if (request->items[item].itemId == ids[field]) present[field] = true;
    } else throw std::runtime_error("unexpected IOCTL in profile preparation");
    return result;
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    try {
        if (argc > 1 && std::string(argv[1]) == "--prepare-live") {
            wchar_t manufacturer[256]{}; DWORD size = sizeof(manufacturer);
            check(GetEnvironmentVariableW(L"KSWORD_CID_VM_LAB", nullptr, 0) != 0 &&
                RegGetValueW(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemManufacturer",
                RRF_RT_REG_SZ, nullptr, manufacturer, &size) == ERROR_SUCCESS &&
                std::wstring(manufacturer).find(L"VMware") != std::wstring::npos, "VM-only opt-in required");
            live = true;
            const auto result = ksword::ark::prepareProcessLifetimeProfile(ksword::ark::DriverClient{});
            std::printf("ready=%d applied=%d\n%s\n", result.ready, result.applied, qPrintable(result.detail));
            return result.ready ? 0 : 2;
        }
        check(argc == 2, "supply profile pack path");
        qputenv("KSWORD_ARK_PROFILE_PACK", argv[1]);
        identity.present = 1; identity.machine = 0x8664; identity.classId = KSW_DYN_PROFILE_CLASS_NTOSKRNL;
        identity.timeDateStamp = 0xed9dc31e; identity.sizeOfImage = 0x1046000;
        const auto prepare = [] { return ksword::ark::prepareProcessLifetimeProfile(ksword::ark::DriverClient{}); };
        for (size_t missing = 0; missing < ids.size(); ++missing) {
            present.fill(true); present[missing] = false; appliedCount = 0;
            const bool expectedReady = ids[missing] != KSW_DYN_FIELD_ID_HT_HANDLE_CONTENTION_EVENT;
            check(prepare().ready == expectedReady && appliedCount == 1, "prepare available fields; unsupported layout stays unknown"); ++cases;
            if (expectedReady) { check(prepare().ready && appliedCount == 1, "ready layout must not reapply"); ++cases; }
        }
        present.fill(false); rejectApply = true;
        check(!prepare().ready, "rejected apply must remain unknown"); ++cases; rejectApply = false;
        loseReadback = true;
        check(!prepare().ready, "apply receipt does not replace field readback"); ++cases; loseReadback = false;
        ++identity.timeDateStamp; appliedCount = 0;
        check(!prepare().ready && appliedCount == 0, "unmatched identity must not apply"); ++cases; --identity.timeDateStamp;
        present.fill(false); present.back() = true; appliedCount = 0;
        bool first = false, second = false;
        std::thread a([&] { first = prepare().ready; }), b([&] { second = prepare().ready; });
        a.join(); b.join(); check(first && second && appliedCount == 1, "concurrent cold workers wait for one completed apply"); ++cases;
        std::printf("PROCESS_LIFETIME_PROFILE_PASS cases=%u\n", cases);
        return 0;
    } catch (const std::exception& error) { std::fprintf(stderr, "%s\n", error.what()); return 1; }
}
