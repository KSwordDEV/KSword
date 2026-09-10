#include "DwmAgentDeployment.h"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <Windows.h>
#include <Aclapi.h>
#include <Wincrypt.h>
#include <array>
#include <mutex>

namespace ks::dwm_order::transport
{
    namespace
    {
        struct File
        {
            HANDLE value = INVALID_HANDLE_VALUE;
            File() = default;
            File(const File&) = delete;
            File& operator=(const File&) = delete;
            ~File() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
        };
        struct Lease
        {
            File root, version, image;
        };
        std::mutex g_deployMutex;

        DWORD ReadImage(HANDLE file, std::vector<unsigned char>& bytes)
        {
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(file, &info)) return GetLastError();
            if ((info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))
                || info.nNumberOfLinks != 1 || info.nFileSizeHigh || !info.nFileSizeLow
                || info.nFileSizeLow > 64 * 1024 * 1024) return ERROR_BAD_EXE_FORMAT;
            LARGE_INTEGER beginning{};
            if (!SetFilePointerEx(file, beginning, nullptr, FILE_BEGIN)) return GetLastError();
            bytes.resize(info.nFileSizeLow);
            DWORD read = 0;
            if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr)) return GetLastError();
            return read == bytes.size() ? ERROR_SUCCESS : ERROR_READ_FAULT;
        }

        DWORD Digest(const std::vector<unsigned char>& bytes, std::wstring& text)
        {
            HCRYPTPROV provider = 0;
            HCRYPTHASH hash = 0;
            if (!CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return GetLastError();
            DWORD error = ERROR_SUCCESS;
            std::array<unsigned char, 32> digest{};
            DWORD size = static_cast<DWORD>(digest.size());
            if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)
                || !CryptHashData(hash, bytes.data(), static_cast<DWORD>(bytes.size()), 0)
                || !CryptGetHashParam(hash, HP_HASHVAL, digest.data(), &size, 0)) error = GetLastError();
            if (hash) CryptDestroyHash(hash);
            CryptReleaseContext(provider, 0);
            if (error) return error;
            if (size != digest.size()) return ERROR_INVALID_DATA;
            const wchar_t digits[] = L"0123456789abcdef";
            text.clear();
            for (const auto value : digest) { text += digits[value >> 4]; text += digits[value & 15]; }
            return ERROR_SUCCESS;
        }

        DWORD GrantReadExecute(HANDLE object, PSID reader)
        {
            PACL previous = nullptr, updated = nullptr;
            PSECURITY_DESCRIPTOR security = nullptr;
            DWORD error = GetSecurityInfo(object, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, &previous, nullptr, &security);
            if (error) return error;
            if (!previous) { LocalFree(security); return ERROR_INVALID_ACL; }
            EXPLICIT_ACCESSW access{};
            access.grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
            access.grfAccessMode = GRANT_ACCESS;
            access.grfInheritance = NO_INHERITANCE;
            access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
            access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
            access.Trustee.ptstrName = static_cast<LPWSTR>(reader);
            error = SetEntriesInAclW(1, &access, previous, &updated);
            if (!error) error = SetSecurityInfo(object, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                nullptr, nullptr, updated, nullptr);
            if (updated) LocalFree(updated);
            LocalFree(security);
            return error;
        }

        DWORD OpenDirectory(const std::wstring& path, PSID reader, File& file)
        {
            if (!CreateDirectoryW(path.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) return GetLastError();
            file.value = CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (file.value == INVALID_HANDLE_VALUE) return GetLastError();
            BY_HANDLE_FILE_INFORMATION info{};
            if (!GetFileInformationByHandle(file.value, &info)) return GetLastError();
            if (!(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                || (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) return ERROR_REPARSE_TAG_INVALID;
            return GrantReadExecute(file.value, reader);
        }

        DWORD CreateCopy(const std::wstring& path, const std::vector<unsigned char>& bytes)
        {
            File file;
            file.value = CreateFileW(path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr,
                CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (file.value == INVALID_HANDLE_VALUE)
            {
                const DWORD error = GetLastError();
                return error == ERROR_FILE_EXISTS ? ERROR_SUCCESS : error;
            }
            DWORD written = 0, error = ERROR_SUCCESS;
            if (!WriteFile(file.value, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr)
                || written != bytes.size() || !FlushFileBuffers(file.value))
                error = GetLastError() ? GetLastError() : ERROR_WRITE_FAULT;
            if (error)
            {
                // Only remove the new file represented by this still-open handle.
                FILE_DISPOSITION_INFO remove{TRUE};
                SetFileInformationByHandle(file.value, FileDispositionInfo, &remove, sizeof(remove));
            }
            return error;
        }
    }

    std::uint32_t ReadProcessUserSid(void* process, std::vector<unsigned char>& sid)
    {
        File token;
        if (!OpenProcessToken(process, TOKEN_QUERY, &token.value)) return GetLastError();
        DWORD size = 0;
        GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
        std::vector<unsigned char> data(size);
        DWORD error = ERROR_SUCCESS;
        if (!size || !GetTokenInformation(token.value, TokenUser, data.data(), size, &size)) error = GetLastError();
        else
        {
            auto* user = reinterpret_cast<TOKEN_USER*>(data.data());
            if (!IsValidSid(user->User.Sid)) error = ERROR_INVALID_SID;
            else
            {
                sid.resize(GetLengthSid(user->User.Sid));
                if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user->User.Sid)) error = GetLastError();
            }
        }
        return error;
    }

    std::uint32_t PrepareAgentCopy(const std::wstring& sourcePath,
        const std::vector<unsigned char>& readerSid, PreparedAgent& prepared)
    {
        prepared = {};
        if (readerSid.empty() || !IsValidSid(const_cast<unsigned char*>(readerSid.data()))
            || GetLengthSid(const_cast<unsigned char*>(readerSid.data())) != readerSid.size()) return ERROR_INVALID_SID;
        const auto separator = sourcePath.find_last_of(L'\\');
        if (separator == std::wstring::npos) return ERROR_BAD_PATHNAME;
        std::lock_guard guard(g_deployMutex);
        File source;
        source.value = CreateFileW(sourcePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (source.value == INVALID_HANDLE_VALUE) return GetLastError();
        std::vector<unsigned char> bytes;
        DWORD error = ReadImage(source.value, bytes);
        if (error) return error;
        std::wstring digest;
        error = Digest(bytes, digest);
        if (error) return error;
        const std::wstring root = sourcePath.substr(0, separator) + L"\\dwm-agent";
        const std::wstring version = root + L"\\" + digest;
        const std::wstring copy = version + L"\\" + sourcePath.substr(separator + 1);
        if (copy.size() >= MAX_PATH) return ERROR_FILENAME_EXCED_RANGE;
        auto lease = std::make_shared<Lease>();
        auto* reader = const_cast<unsigned char*>(readerSid.data());
        error = OpenDirectory(root, reader, lease->root);
        if (!error) error = OpenDirectory(version, reader, lease->version);
        if (!error) error = CreateCopy(copy, bytes);
        if (error) return error;
        lease->image.value = CreateFileW(copy.c_str(), GENERIC_READ | READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (lease->image.value == INVALID_HANDLE_VALUE) return GetLastError();
        std::vector<unsigned char> copied;
        error = ReadImage(lease->image.value, copied);
        if (error) return error;
        if (copied != bytes) return ERROR_FILE_CORRUPT;
        error = GrantReadExecute(lease->image.value, reader);
        if (error) return error;
        prepared.path = copy;
        prepared.lease = std::move(lease);
        return ERROR_SUCCESS;
    }
}
