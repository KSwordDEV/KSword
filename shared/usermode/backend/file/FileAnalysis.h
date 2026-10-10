#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

struct HashResult {
    bool success = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::uint64_t bytesRead = 0;
    std::wstring digest, errorText;
};
struct EntropyResult {
    bool success = false, complete = false, limited = false, sizeKnown = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::uint64_t sampled = 0, size = 0;
    double bitsPerByte = 0.0;
};
struct SignatureResult {
    bool evaluated = false;
    LONG trustStatus = E_INVALIDARG;
    std::wstring message;
};
HashResult ReadSha256(const std::wstring& path);
EntropyResult ReadFileEntropy(const std::wstring& path, std::uint64_t maxBytes);
SignatureResult ReadEmbeddedSignature(const std::wstring& path);

std::wstring BytesToHex(const BYTE* data, DWORD bytes);
std::wstring ComputeSha256(const std::wstring& path, std::wstring* errorOut);
double ComputeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut);
std::wstring VerifyEmbeddedSignature(const std::wstring& path);
std::wstring HexText(std::uint64_t value);
}
