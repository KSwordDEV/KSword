#include "PeSnapshot.h"
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
#include "../../../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"
#include <new>
namespace ks::r3::file {
constexpr std::uint64_t kLitePeStaticMaxFileBytes = 16ULL * 1024ULL * 1024ULL;
constexpr std::size_t kLitePeStaticMaxSectionRows = 32;
constexpr std::size_t kLitePeStaticMaxImportModuleRows = 64;
constexpr std::size_t kLitePeStaticMaxDisplayChars = 240;
std::wstring Utf8ToWide(const std::string& text) {
    if (text.empty()) {
        return {};
    }

    const int required = ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required > 0) {
        std::wstring wide(static_cast<std::size_t>(required), L'\0');
        ::MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, text.c_str(), static_cast<int>(text.size()), wide.data(), required);
        return wide;
    }

    std::wstring fallback;
    fallback.reserve(text.size());
    for (const unsigned char ch : text) {
        fallback.push_back(static_cast<wchar_t>(ch));
    }
    return fallback;
}
std::wstring HexPreview(const std::wstring& path, DWORD maxBytes) {
    HANDLE file = ::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return {};
    }
    std::vector<BYTE> buffer(maxBytes);
    DWORD read = 0;
    const BOOL ok = ::ReadFile(file, buffer.data(), maxBytes, &read, nullptr);
    ::CloseHandle(file);
    if (!ok) {
        return {};
    }
    std::wostringstream dump;
    dump << std::uppercase << std::hex << std::setfill(L'0');
    for (DWORD offset = 0; offset < read; offset += 16) {
        dump << std::setw(8) << offset << L"  ";
        for (DWORD index = 0; index < 16; ++index) {
            if (offset + index < read) {
                dump << std::setw(2) << static_cast<unsigned int>(buffer[offset + index]) << L' ';
            } else {
                dump << L"   ";
            }
        }
        dump << L" ";
        for (DWORD index = 0; index < 16 && offset + index < read; ++index) {
            const BYTE ch = buffer[offset + index];
            dump << (ch >= 32 && ch < 127 ? static_cast<wchar_t>(ch) : L'.');
        }
        dump << L"\r\n";
    }
    return dump.str();
}
std::wstring BuildPeHeaderSummary(const std::wstring& path) {
    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return L"打开文件失败，错误 " + std::to_wstring(::GetLastError());
    }

    IMAGE_DOS_HEADER dos{};
    DWORD read = 0;
    if (!::ReadFile(file, &dos, sizeof(dos), &read, nullptr) ||
        read != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：DOS 头无效。";
    }
    if (::SetFilePointer(file, dos.e_lfanew, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER &&
        ::GetLastError() != ERROR_SUCCESS) {
        ::CloseHandle(file);
        return L"定位 NT 头失败，错误 " + std::to_wstring(::GetLastError());
    }

    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (!::ReadFile(file, &signature, sizeof(signature), &read, nullptr) ||
        read != sizeof(signature) || signature != IMAGE_NT_SIGNATURE ||
        !::ReadFile(file, &fileHeader, sizeof(fileHeader), &read, nullptr) ||
        read != sizeof(fileHeader)) {
        ::CloseHandle(file);
        return L"不是有效的 PE 文件：NT 头无效。";
    }

    WORD optionalMagic = 0;
    if (!::ReadFile(file, &optionalMagic, sizeof(optionalMagic), &read, nullptr) ||
        read != sizeof(optionalMagic)) {
        ::CloseHandle(file);
        return L"读取 OptionalHeader 失败。";
    }
    ::CloseHandle(file);

    std::wostringstream text;
    text << L"PE 头部摘要\r\n\r\n"
         << L"Machine: 0x" << std::hex << std::uppercase << fileHeader.Machine << L"\r\n"
         << L"Sections: " << std::dec << fileHeader.NumberOfSections << L"\r\n"
         << L"TimeDateStamp: 0x" << std::hex << std::uppercase << fileHeader.TimeDateStamp << L"\r\n"
         << L"Characteristics: 0x" << std::hex << std::uppercase << fileHeader.Characteristics << L"\r\n"
         << L"OptionalHeader.Magic: 0x" << std::hex << std::uppercase << optionalMagic
         << (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? L" (PE32+)" :
             optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC ? L" (PE32)" : L"") << L"\r\n\r\n"
         << L"KswordARKLight 仅显示轻量 PE 摘要；完整属性页已按要求移除。";
    return text.str();
}
bool IsLiteralDosOrUncFilePath(const std::wstring& path) {
    const auto isAsciiLetter = [](const wchar_t value) {
        return (value >= L'A' && value <= L'Z') || (value >= L'a' && value <= L'z');
    };
    if (path.size() >= 3 && isAsciiLetter(path[0]) && path[1] == L':' &&
        (path[2] == L'\\' || path[2] == L'/')) {
        return true;
    }

    if (path.size() < 5 || path[0] != L'\\' || path[1] != L'\\' ||
        path[2] == L'?' || path[2] == L'.') {
        return false;
    }

    const std::size_t serverEnd = path.find_first_of(L"\\/", 2);
    if (serverEnd == std::wstring::npos || serverEnd == 2) {
        return false;
    }
    const std::size_t shareStart = serverEnd + 1;
    if (shareStart >= path.size()) {
        return false;
    }
    const std::size_t shareEnd = path.find_first_of(L"\\/", shareStart);
    return shareEnd == std::wstring::npos || shareEnd > shareStart;
}
bool ReadLitePeSnapshot(
    const std::wstring& path,
    std::vector<std::uint8_t>& bytesOut,
    std::uint64_t& sizeOut,
    std::wstring& errorOut) {
    bytesOut.clear();
    sizeOut = 0;
    errorOut.clear();

    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        errorOut = L"打开文件失败，错误 " + std::to_wstring(::GetLastError()) + L"。";
        return false;
    }

    LARGE_INTEGER fileSize{};
    if (::GetFileSizeEx(file, &fileSize) == FALSE || fileSize.QuadPart < 0) {
        const DWORD error = ::GetLastError();
        ::CloseHandle(file);
        errorOut = L"获取文件大小失败，错误 " + std::to_wstring(error) + L"。";
        return false;
    }
    if (static_cast<std::uint64_t>(fileSize.QuadPart) > kLitePeStaticMaxFileBytes) {
        ::CloseHandle(file);
        errorOut = L"文件大小为 " + std::to_wstring(fileSize.QuadPart) +
            L" bytes，超过 Lite PE 静态摘要的 16 MiB 上限。";
        return false;
    }

    try {
        bytesOut.resize(static_cast<std::size_t>(fileSize.QuadPart));
    } catch (const std::bad_alloc&) {
        ::CloseHandle(file);
        bytesOut.clear();
        errorOut = L"无法为受限 PE 快照分配内存。";
        return false;
    }

    std::size_t totalRead = 0;
    while (totalRead < bytesOut.size()) {
        const std::size_t remaining = bytesOut.size() - totalRead;
        const DWORD requestSize = static_cast<DWORD>(std::min<std::size_t>(remaining, 1024U * 1024U));
        DWORD read = 0;
        if (::ReadFile(file, bytesOut.data() + totalRead, requestSize, &read, nullptr) == FALSE) {
            const DWORD error = ::GetLastError();
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"读取文件失败，错误 " + std::to_wstring(error) + L"。";
            return false;
        }
        if (read == 0) {
            ::CloseHandle(file);
            bytesOut.clear();
            errorOut = L"文件在读取期间提前结束或发生变化。";
            return false;
        }
        totalRead += read;
    }

    ::CloseHandle(file);
    sizeOut = static_cast<std::uint64_t>(fileSize.QuadPart);
    return true;
}
std::wstring SingleLinePreview(std::wstring text, const std::size_t maxChars) {
    for (wchar_t& character : text) {
        if (character == L'\r' || character == L'\n' || character == L'\t' ||
            character < L' ' || character == 0x7F) {
            character = L' ';
        }
    }
    if (text.size() > maxChars) {
        text.resize(maxChars);
        text += L"...";
    }
    return text;
}
PeStaticSummaryResult BuildPeHeaderFallback(const std::wstring& path, const std::wstring& reason) {
    PeStaticSummaryResult result;
    result.success = true;
    result.partial = true;
    result.text = L"PE 静态摘要（Partial）\r\n\r\n"
        L"深度解析未完成：" + SingleLinePreview(reason, kLitePeStaticMaxDisplayChars) +
        L"\r\n\r\n已保留兼容的轻量 PE 头部摘要：\r\n\r\n" + BuildPeHeaderSummary(path);
    return result;
}
std::wstring PeMachineText(const std::uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386: return L"x86";
    case IMAGE_FILE_MACHINE_AMD64: return L"x64";
    case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
    case IMAGE_FILE_MACHINE_ARM: return L"ARM";
    case IMAGE_FILE_MACHINE_ARMNT: return L"ARMNT";
    case IMAGE_FILE_MACHINE_IA64: return L"IA64";
    default: return L"Unknown";
    }
}
std::wstring PeSubsystemText(const std::uint16_t subsystem) {
    switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE: return L"Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Windows CUI";
    case IMAGE_SUBSYSTEM_POSIX_CUI: return L"POSIX CUI";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return L"EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return L"EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return L"Windows Boot Application";
    default: return L"Unknown";
    }
}
PeStaticSummaryResult BuildPeStaticSummary(const std::wstring& path) {
    PeStaticSummaryResult result;
    if (!IsLiteralDosOrUncFilePath(path)) {
        return BuildPeHeaderFallback(
            path,
            L"深度解析仅支持普通 DOS 盘符或 UNC 路径；当前路径继续使用原有轻量读取器。");
    }

    std::vector<std::uint8_t> fileBytes;
    std::uint64_t fileSize = 0;
    std::wstring readError;
    if (!ReadLitePeSnapshot(path, fileBytes, fileSize, readError)) {
        return BuildPeHeaderFallback(path, readError);
    }

    const ks::file::PeAnalysisResult analysis = ks::file::AnalyzePeBytes(fileBytes);
    if (!analysis.success) {
        const std::wstring diagnostic = analysis.errorText.empty()
            ? L"共享 PE 解析器未返回可用结果。"
            : SingleLinePreview(analysis.errorText, kLitePeStaticMaxDisplayChars);
        return BuildPeHeaderFallback(path, L"深度解析失败：" + diagnostic);
    }

    std::wostringstream text;
    text << L"PE 静态摘要（只读）\r\n\r\n"
         << L"路径: " << SingleLinePreview(path, 512) << L"\r\n"
         << L"快照大小: " << fileSize << L" bytes（上限 16 MiB）\r\n"
         << L"格式: " << (analysis.isPe64 ? L"PE32+" : L"PE32") << L"\r\n"
         << L"Machine: " << HexText(analysis.machine) << L" (" << PeMachineText(analysis.machine) << L")\r\n"
         << L"Subsystem: " << HexText(analysis.subsystem) << L" (" << PeSubsystemText(analysis.subsystem) << L")\r\n"
         << L"ImageBase: " << HexText(analysis.imageBase) << L"\r\n"
         << L"EntryPoint RVA: " << HexText(analysis.entryPointRva) << L"\r\n"
         << L"EntryPoint File Offset: "
         << (analysis.entryPointFileOffsetValid ? HexText(analysis.entryPointFileOffset) : L"<unmapped>") << L"\r\n"
         << L"解析到的区段: " << analysis.sections.size() << L"\r\n"
         << L"解析到的导入模块: " << analysis.importModules.size() << L"\r\n";

    const std::size_t sectionDisplayCount = std::min(analysis.sections.size(), kLitePeStaticMaxSectionRows);
    text << L"\r\n区段（最多显示 " << kLitePeStaticMaxSectionRows << L" 个）\r\n";
    if (sectionDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < sectionDisplayCount; ++index) {
            const ks::file::PeSectionSummary& section = analysis.sections[index];
            text << L"[" << index << L"] "
                 << SingleLinePreview(Utf8ToWide(section.name), 80)
                 << L" | VA=" << HexText(section.virtualAddress)
                 << L" | VSz=" << HexText(section.virtualSize)
                 << L" | Raw=" << HexText(section.rawOffset) << L"+" << HexText(section.rawSize)
                 << L" | Chars=" << HexText(section.characteristics)
                 << L" | Entropy=" << std::fixed << std::setprecision(2) << section.entropy
                 << L"\r\n";
        }
        if (analysis.sections.size() > sectionDisplayCount) {
            text << L"...仅显示前 " << sectionDisplayCount << L" 个区段。\r\n";
        }
    }

    bool partial = false;
    const std::size_t importDisplayCount = std::min(analysis.importModules.size(), kLitePeStaticMaxImportModuleRows);
    text << L"\r\n导入模块摘要（最多显示 " << kLitePeStaticMaxImportModuleRows
         << L" 个；不显示导入函数）\r\n";
    if (importDisplayCount == 0) {
        text << L"<none>\r\n";
    } else {
        for (std::size_t index = 0; index < importDisplayCount; ++index) {
            const ks::file::PeImportModuleSummary& module = analysis.importModules[index];
            std::wstring moduleName = SingleLinePreview(Utf8ToWide(module.dllName), kLitePeStaticMaxDisplayChars);
            if (moduleName.empty()) {
                moduleName = L"<unnamed module>";
            }
            text << L"[" << module.descriptorIndex << L"] " << moduleName
                 << L" | parsed entries=" << module.imports.size();
            if (!module.diagnosticText.empty()) {
                partial = true;
                text << L" | Partial: "
                     << SingleLinePreview(Utf8ToWide(module.diagnosticText), kLitePeStaticMaxDisplayChars);
            }
            text << L"\r\n";
        }
        if (analysis.importModules.size() > importDisplayCount) {
            text << L"...仅显示前 " << importDisplayCount << L" 个导入模块。\r\n";
        }
    }

    result.success = true;
    result.partial = partial;
    result.text = text.str();
    return result;
}
}
