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
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        if (errorOut) {
            *errorOut = L"CreateFileW error " + std::to_wstring(::GetLastError());
        }
        return {};
    }
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    if (!::CryptAcquireContextW(&provider, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !::CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        const DWORD error = ::GetLastError();
        if (hash) {
            ::CryptDestroyHash(hash);
        }
        if (provider) {
            ::CryptReleaseContext(provider, 0);
        }
        ::CloseHandle(file);
        if (errorOut) {
            *errorOut = L"CryptoAPI error " + std::to_wstring(error);
        }
        return {};
    }
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    bool ok = true;
    while (::ReadFile(file, buffer, sizeof(buffer), &read, nullptr) && read > 0) {
        if (!::CryptHashData(hash, buffer, read, 0)) {
            ok = false;
            break;
        }
    }
    DWORD hashBytes = 32;
    BYTE hashValue[32]{};
    if (ok) {
        ok = ::CryptGetHashParam(hash, HP_HASHVAL, hashValue, &hashBytes, 0) != FALSE;
    }
    const DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
    ::CryptDestroyHash(hash);
    ::CryptReleaseContext(provider, 0);
    ::CloseHandle(file);
    if (!ok) {
        if (errorOut) {
            *errorOut = L"Hash read error " + std::to_wstring(error);
        }
        return {};
    }
    return BytesToHex(hashValue, hashBytes);
}
double ComputeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return -1.0;
    }
    std::uint64_t counts[256]{};
    BYTE buffer[64 * 1024]{};
    DWORD read = 0;
    std::uint64_t total = 0;
    while (total < maxBytes && ::ReadFile(file, buffer, static_cast<DWORD>(std::min<std::uint64_t>(sizeof(buffer), maxBytes - total)), &read, nullptr) && read > 0) {
        for (DWORD index = 0; index < read; ++index) {
            ++counts[buffer[index]];
        }
        total += read;
    }
    ::CloseHandle(file);
    if (sampledOut) {
        *sampledOut = total;
    }
    if (total == 0) {
        return 0.0;
    }
    double entropy = 0.0;
    for (std::uint64_t count : counts) {
        if (count == 0) {
            continue;
        }
        const double p = static_cast<double>(count) / static_cast<double>(total);
        entropy -= p * (std::log(p) / std::log(2.0));
    }
    return entropy;
}
std::wstring VerifyEmbeddedSignature(const std::wstring& path) {
    if (path.empty()) {
        return L"路径为空，无法检查签名。";
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
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    (void)::WinVerifyTrust(nullptr, &policy, &trustData);

    if (status == ERROR_SUCCESS) {
        return L"数字签名验证通过。";
    }
    if (status == TRUST_E_NOSIGNATURE) {
        return L"文件没有嵌入式 Authenticode 签名。";
    }
    if (status == CERT_E_EXPIRED) {
        return L"数字签名证书已过期。";
    }
    if (status == TRUST_E_BAD_DIGEST) {
        return L"数字签名摘要不匹配，文件可能已被修改。";
    }
    return L"数字签名验证失败，状态 0x" + HexText(static_cast<std::uint32_t>(status));
}
}
