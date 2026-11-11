#include "FileAnalysis.h"
#include "PathNavigator.h"
#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <vector>
#include <softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <mscat.h>
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wintrust.lib")
namespace ks::r3::file {
std::wstring HexText(std::uint64_t value) {
    std::wostringstream stream;
    stream << L"0x" << std::hex << std::uppercase << value;
    return stream.str();
}
std::wstring BytesToHex(const BYTE* data, DWORD bytes) {
    std::wostringstream stream;
    stream << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD index = 0; index < bytes; ++index) {
        stream << std::setw(2) << static_cast<unsigned int>(data[index]);
    }
    return stream.str();
}
std::wstring ComputeSha256(const std::wstring& path, std::wstring* errorOut) {
    const auto result = ReadSha256(path);
    if (errorOut) *errorOut = result.errorText;
    return result.digest;
}
HashResult ReadSha256(const std::wstring& path) {
    HashResult result;
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        result.errorCode = ::GetLastError();
        result.errorText = L"CreateFileW error " + std::to_wstring(result.errorCode);
        return result;
    }
    HCRYPTPROV provider = 0; HCRYPTHASH hash = 0;
    if (!::CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !::CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        result.errorCode = ::GetLastError();
        if (hash) ::CryptDestroyHash(hash);
        if (provider) ::CryptReleaseContext(provider, 0);
        ::CloseHandle(file);
        result.errorText = L"CryptoAPI error " + std::to_wstring(result.errorCode);
        return result;
    }
    BYTE buffer[64 * 1024]{}; DWORD read = 0; bool ok = true;
    while (true) {
        if (!::ReadFile(file, buffer, sizeof(buffer), &read, nullptr)) {
            result.errorCode = ::GetLastError(); ok = false; break;
        }
        if (!read) break;
        result.bytesRead += read;
        if (!::CryptHashData(hash, buffer, read, 0)) {
            result.errorCode = ::GetLastError(); ok = false; break;
        }
    }
    DWORD hashBytes = 32; BYTE hashValue[32]{};
    if (ok) {
        ok = ::CryptGetHashParam(hash, HP_HASHVAL, hashValue, &hashBytes, 0) != FALSE;
        if (!ok) result.errorCode = ::GetLastError();
    }
    ::CryptDestroyHash(hash); ::CryptReleaseContext(provider, 0); ::CloseHandle(file);
    if (!ok) {
        result.errorText = L"Hash read error " + std::to_wstring(result.errorCode);
        return result;
    }
    result.digest = BytesToHex(hashValue, hashBytes); result.success = true;
    return result;
}

double ComputeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut) {
    const auto result = ReadFileEntropy(path, maxBytes);
    if (sampledOut) *sampledOut = result.sampled;
    return !result.success && result.sampled == 0 ? -1.0 : result.bitsPerByte;
}
EntropyResult ReadFileEntropy(const std::wstring& path, std::uint64_t maxBytes) {
    EntropyResult result;
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) { result.errorCode = ::GetLastError(); return result; }
    LARGE_INTEGER size{};
    if (::GetFileSizeEx(file, &size) && size.QuadPart >= 0) {
        result.sizeKnown = true; result.size = static_cast<std::uint64_t>(size.QuadPart);
    }
    std::uint64_t counts[256]{}; BYTE buffer[64 * 1024]{}; DWORD read = 0; bool eof = false;
    while (result.sampled < maxBytes) {
        if (!::ReadFile(file, buffer, static_cast<DWORD>(std::min<std::uint64_t>(sizeof(buffer), maxBytes - result.sampled)), &read, nullptr)) {
            result.errorCode = ::GetLastError(); break;
        }
        if (!read) { eof = true; break; }
        for (DWORD i = 0; i < read; ++i) ++counts[buffer[i]];
        result.sampled += read;
    }
    ::CloseHandle(file);
    result.success = result.errorCode == ERROR_SUCCESS;
    result.limited = !eof && result.sampled == maxBytes && (!result.sizeKnown || result.size > result.sampled);
    result.complete = result.success && !result.limited;
    if (result.sampled) for (const auto count : counts) {
        if (!count) continue;
        const double probability = static_cast<double>(count) / static_cast<double>(result.sampled);
        result.bitsPerByte -= probability * (std::log(probability) / std::log(2.0));
    }
    return result;
}
std::wstring VerifyEmbeddedSignature(const std::wstring& path) {
    return ReadEmbeddedSignature(path).message;
}
SignatureResult ReadEmbeddedSignature(const std::wstring& path) {
    SignatureResult result;
    if (path.empty()) {
        result.message = L"路径为空，无法检查签名。";
        return result;
    }

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = path.c_str();

    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    const LONG status = ::WinVerifyTrust(nullptr, &policy, &trustData);
    result.evaluated = true; result.trustStatus = status;
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(nullptr, &policy, &trustData);

    if (status == ERROR_SUCCESS) {
        result.message = L"数字签名验证通过。";
        return result;
    }
    if (status == TRUST_E_NOSIGNATURE) {
        result.message = L"文件没有嵌入式 Authenticode 签名。";
        return result;
    }
    if (status == CERT_E_EXPIRED) {
        result.message = L"数字签名证书已过期。";
        return result;
    }
    if (status == TRUST_E_BAD_DIGEST) {
        result.message = L"数字签名摘要不匹配，文件可能已被修改。";
        return result;
    }
    result.message = L"数字签名验证失败，状态 0x" + HexText(static_cast<std::uint32_t>(status));
    return result;
}

CatalogSignatureResult ReadCatalogSignature(const std::wstring& path) {
    CatalogSignatureResult result;
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) { result.errorCode = ::GetLastError(); return result; }
    bool complete = true;
    for (const auto* algorithm : {L"SHA256", L"SHA1"}) {
        HCATADMIN admin = nullptr;
        GUID subsystem = DRIVER_ACTION_VERIFY;
        if (!::CryptCATAdminAcquireContext2(&admin, &subsystem, algorithm, nullptr, 0)) {
            if (!result.errorCode) result.errorCode = ::GetLastError();
            complete = false;
            continue;
        }
        DWORD bytes = 0;
        LARGE_INTEGER start{};
        const bool positioned = ::SetFilePointerEx(file, start, nullptr, FILE_BEGIN) != FALSE;
        const bool sized = positioned && ::CryptCATAdminCalcHashFromFileHandle2(admin, file, &bytes, nullptr, 0) != FALSE;
        if (!sized || bytes == 0 || bytes > 1024) {
            if (!result.errorCode) result.errorCode = sized ? ERROR_INVALID_DATA : ::GetLastError();
            complete = false;
            ::CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        std::vector<BYTE> hash(bytes);
        if (!::SetFilePointerEx(file, start, nullptr, FILE_BEGIN) ||
            !::CryptCATAdminCalcHashFromFileHandle2(admin, file, &bytes, hash.data(), 0) || !bytes || bytes > hash.size()) {
            if (!result.errorCode) result.errorCode = ::GetLastError();
            complete = false;
            ::CryptCATAdminReleaseContext(admin, 0);
            continue;
        }
        hash.resize(bytes);
        std::wstring tag;
        static constexpr wchar_t digits[] = L"0123456789ABCDEF";
        for (BYTE value : hash) { tag.push_back(digits[value >> 4]); tag.push_back(digits[value & 15]); }
        HCATINFO previous = nullptr;
        for (;;) {
            ::SetLastError(ERROR_SUCCESS);
            HCATINFO current = ::CryptCATAdminEnumCatalogFromHash(admin, hash.data(), bytes, 0, &previous);
            if (!current) {
                const DWORD error = ::GetLastError();
                if (error != ERROR_SUCCESS && error != ERROR_NOT_FOUND && error != static_cast<DWORD>(CRYPT_E_NOT_FOUND)) {
                    if (!result.errorCode) result.errorCode = error;
                    complete = false;
                }
                break;
            }
            previous = current;
            if (++result.catalogsExamined > 64) {
                ::CryptCATAdminReleaseCatalogContext(admin, current, 0);
                if (!result.errorCode) result.errorCode = ERROR_MORE_DATA;
                complete = false;
                break;
            }
            CATALOG_INFO info{}; info.cbStruct = sizeof(info);
            if (!::CryptCATCatalogInfoFromContext(current, &info, 0)) {
                if (!result.errorCode) result.errorCode = ::GetLastError();
                complete = false;
                continue;
            }
            WINTRUST_CATALOG_INFO catalog{};
            catalog.cbStruct = sizeof(catalog); catalog.pcwszCatalogFilePath = info.wszCatalogFile;
            catalog.pcwszMemberTag = tag.c_str(); catalog.pcwszMemberFilePath = path.c_str();
            catalog.hMemberFile = file; catalog.pbCalculatedFileHash = hash.data();
            catalog.cbCalculatedFileHash = bytes; catalog.hCatAdmin = admin;
            WINTRUST_DATA trust{};
            trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE; trust.fdwRevocationChecks = WTD_REVOKE_NONE;
            trust.dwUnionChoice = WTD_CHOICE_CATALOG; trust.pCatalog = &catalog;
            trust.dwStateAction = WTD_STATEACTION_VERIFY; trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
            GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            const LONG status = ::WinVerifyTrust(nullptr, &policy, &trust);
            trust.dwStateAction = WTD_STATEACTION_CLOSE;
            (void)::WinVerifyTrust(nullptr, &policy, &trust);
            result.evaluated = true; result.trustStatus = status;
            result.catalogPath = info.wszCatalogFile; result.hashAlgorithm = algorithm;
            result.candidates.push_back({status, info.wszCatalogFile, algorithm});
            if (status == ERROR_SUCCESS) {
                result.trusted = true;
                ::CryptCATAdminReleaseCatalogContext(admin, current, 0);
                break;
            }
        }
        ::CryptCATAdminReleaseContext(admin, 0);
        if (result.trusted) break;
    }
    ::CloseHandle(file);
    result.complete = complete && !result.trusted;
    return result;
}
}
