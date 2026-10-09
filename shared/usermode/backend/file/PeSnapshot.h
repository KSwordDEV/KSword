#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
namespace ks::r3::file {
struct PeStaticSummaryResult {
    bool success = false;
    bool partial = true;
    std::wstring text;
};
std::wstring HexPreview(const std::wstring& path, DWORD maxBytes);
std::wstring BuildPeHeaderSummary(const std::wstring& path);
bool IsLiteralDosOrUncFilePath(const std::wstring& path);
bool ReadLitePeSnapshot(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytesOut,
    std::uint64_t& sizeOut,
    std::wstring& errorOut);
std::wstring SingleLinePreview(std::wstring text, const std::size_t maxChars);
PeStaticSummaryResult BuildPeHeaderFallback(const std::wstring& path, const std::wstring& reason);
std::wstring PeMachineText(const std::uint16_t machine);
std::wstring PeSubsystemText(const std::uint16_t subsystem);
PeStaticSummaryResult BuildPeStaticSummary(const std::wstring& path);
std::wstring Utf8ToWide(const std::string& text);
}
