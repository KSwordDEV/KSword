#pragma once
#include "../Win32.h"
#include <cstdint>
#include <string>
#include <vector>
#include "../../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"
namespace ks::r3::file {
struct HexPreviewResult {
    bool success = false, limited = false, sizeKnown = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::uint64_t size = 0;
    std::vector<std::uint8_t> bytes;
    std::wstring text;
};
struct PeHeaderResult {
    bool success = false;
    DWORD errorCode = ERROR_SUCCESS;
    std::uint16_t machine = 0, sections = 0, characteristics = 0, optionalMagic = 0;
    std::uint32_t timestamp = 0;
    std::wstring text;
};
struct PeReadEvidence {
    DWORD errorCode = ERROR_SUCCESS;
    bool limitExceeded = false;
    std::uint64_t size = 0, bytesRead = 0;
};
enum class PeFallbackReason { None, UnsupportedPath, ReadFailure, SizeLimit, InvalidPe };
struct PeStaticSummaryResult {
    bool success = false;
    bool partial = true;
    std::wstring text;
    bool deepAvailable = false, sectionsTruncated = false, importsTruncated = false;
    PeFallbackReason fallbackReason = PeFallbackReason::None;
    PeReadEvidence read;
    PeHeaderResult header;
    ks::file::PeAnalysisResult analysis;
};
HexPreviewResult ReadHexPreview(const std::wstring& path, DWORD maxBytes);
PeHeaderResult ReadPeHeader(const std::wstring& path);
std::wstring HexPreview(const std::wstring& path, DWORD maxBytes);
std::wstring BuildPeHeaderSummary(const std::wstring& path);
bool IsLiteralDosOrUncFilePath(const std::wstring& path);
bool ReadLitePeSnapshot(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytesOut,
    std::uint64_t& sizeOut,
    std::wstring& errorOut,
    PeReadEvidence* evidence = nullptr);
std::wstring SingleLinePreview(std::wstring text, const std::size_t maxChars);
PeStaticSummaryResult BuildPeHeaderFallback(const std::wstring& path, const std::wstring& reason);
std::wstring PeMachineText(const std::uint16_t machine);
std::wstring PeSubsystemText(const std::uint16_t subsystem);
PeStaticSummaryResult BuildPeStaticSummary(const std::wstring& path);
std::wstring Utf8ToWide(const std::string& text);
}
