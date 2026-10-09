#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {

std::wstring BytesToHex(const BYTE* data, DWORD bytes);
std::wstring ComputeSha256(const std::wstring& path, std::wstring* errorOut);
double ComputeFileEntropy(const std::wstring& path, std::uint64_t maxBytes, std::uint64_t* sampledOut);
std::wstring VerifyEmbeddedSignature(const std::wstring& path);
std::wstring HexText(std::uint64_t value);
}
