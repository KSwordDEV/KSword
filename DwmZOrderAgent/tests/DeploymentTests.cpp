#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Aclapi.h>
#include <Sddl.h>
#include <cstring>
#include <iostream>
#include "../../Ksword5.1/Ksword5.1/OtherDock/DwmAgentDeployment.h"

namespace
{
    std::wstring Dacl(const std::wstring& path)
    {
        PSECURITY_DESCRIPTOR security = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, nullptr, nullptr, &security)) return {};
        LPWSTR text = nullptr;
        std::wstring value;
        if (ConvertSecurityDescriptorToStringSecurityDescriptorW(security, SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION, &text, nullptr)) { value = text; LocalFree(text); }
        LocalFree(security);
        return value;
    }

    bool ReaderAccess(const std::wstring& path, PSID sid)
    {
        PACL acl = nullptr;
        PSECURITY_DESCRIPTOR security = nullptr;
        if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &acl, nullptr, &security)) return false;
        DWORD granted = 0;
        bool valid = acl != nullptr;
        for (DWORD i = 0; acl && i < acl->AceCount; ++i)
        {
            void* entry = nullptr;
            if (!GetAce(acl, i, &entry)) { valid = false; break; }
            const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(entry);
            if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE && !(ace->Header.AceFlags & INHERITED_ACE)
                && EqualSid(const_cast<DWORD*>(&ace->SidStart), sid)) granted |= ace->Mask;
        }
        LocalFree(security);
        return valid && granted == (FILE_GENERIC_READ | FILE_GENERIC_EXECUTE);
    }

    std::vector<unsigned char> Contents(const std::wstring& path)
    {
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) return {};
        const DWORD size = GetFileSize(file, nullptr);
        std::vector<unsigned char> data;
        if (size && size <= 64 * 1024 * 1024)
        {
            data.resize(size);
            DWORD read = 0;
            if (!ReadFile(file, data.data(), size, &read, nullptr) || read != size) data.clear();
        }
        CloseHandle(file);
        return data;
    }
}

ks::dwm_order::transport::PreparedAgent RunDeploymentTests(void (*check)(bool, const char*), const wchar_t* agentPath)
{
    using namespace ks::dwm_order::transport;
    PreparedAgent prepared;
    std::vector<unsigned char> currentUser;
    check(ReadProcessUserSid(GetCurrentProcess(), currentUser) == ERROR_SUCCESS && !currentUser.empty(),
        "read the target process primary user SID without impersonation");
    PSID reader = nullptr;
    check(ConvertStringSidToSidW(L"S-1-5-90-0", &reader) != FALSE, "construct a separate Window Manager reader SID");
    if (!reader) return prepared;
    std::vector<unsigned char> readerSid(GetLengthSid(reader));
    std::memcpy(readerSid.data(), reader, readerSid.size());
    const auto originalDacl = Dacl(agentPath);
    const DWORD error = PrepareAgentCopy(agentPath, readerSid, prepared);
    std::cout << "DEPLOYMENT_WIN32=" << error << '\n';
    check(!originalDacl.empty() && !error && prepared.lease && prepared.path != agentPath,
        "prepare a verified sidecar copy of the agent");
    check(Dacl(agentPath) == originalDacl, "deployment does not change the source DLL permissions");
    if (!error)
    {
        const auto version = prepared.path.substr(0, prepared.path.find_last_of(L'\\'));
        const auto root = version.substr(0, version.find_last_of(L'\\'));
        check(ReaderAccess(root, reader) && ReaderAccess(version, reader) && ReaderAccess(prepared.path, reader),
            "only read and execute rights are explicitly granted to the reader on the managed copy and directories");
        const auto original = Contents(agentPath);
        check(!original.empty() && Contents(prepared.path) == original, "deployed agent bytes exactly match the source");
        HANDLE replace = CreateFileW(prepared.path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        const DWORD replaceError = GetLastError();
        check(replace == INVALID_HANDLE_VALUE && replaceError == ERROR_SHARING_VIOLATION,
            "deployment lease prevents replacing the DLL during loading");
        if (replace != INVALID_HANDLE_VALUE) CloseHandle(replace);
        PreparedAgent repeated;
        check(PrepareAgentCopy(agentPath, readerSid, repeated) == ERROR_SUCCESS && repeated.path == prepared.path,
            "unchanged agent content reuses the existing verified copy");
        PreparedAgent invalid;
        check(PrepareAgentCopy(agentPath, {}, invalid) == ERROR_INVALID_SID && invalid.path.empty(),
            "missing target SID is rejected without preparing another copy");
    }
    LocalFree(reader);
    return prepared;
}
