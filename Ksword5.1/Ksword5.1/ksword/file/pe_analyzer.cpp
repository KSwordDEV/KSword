#include "pe_analyzer.h"

#include "../string/string.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <cstring>
#include <cwchar>
#include <iomanip>
#include <iterator>
#include <limits>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ks::file
{
    namespace
    {
        // These limits keep malformed files from causing unbounded loops or huge reports.
        // They are intentionally conservative because this backend feeds an interactive UI.
        constexpr std::uint16_t kMaxSectionCount = 128;
        constexpr std::uint32_t kMaxImportDescriptors = 1024;
        constexpr std::uint32_t kMaxImportPerModule = 2048;
        constexpr std::uint32_t kMaxExportNames = 4096;
        constexpr std::uint64_t kMaxPeFileBytes = 512ULL * 1024ULL * 1024ULL;

        // Collect semantic fields at the point where structures are decoded.
        // No report text is read back or split to manufacture the property tree.
        class ReportCollector
        {
        public:
            explicit ReportCollector(PeAnalysisResult& result) : result_(result) {}
            void Section(std::wstring name)
            {
                result_.entries.push_back({ PeReportEntry::Kind::Section, std::move(name), {}, 0 });
            }
            void Field(std::wstring name, std::wstring value, std::uint32_t depth = 0)
            {
                result_.entries.push_back({ PeReportEntry::Kind::Field, std::move(name), std::move(value), depth });
            }
            void Note(std::wstring value, std::uint32_t depth = 0)
            {
                result_.entries.push_back({ PeReportEntry::Kind::Note, {}, std::move(value), depth });
            }
        private:
            PeAnalysisResult& result_;
        };

        void SetAnalysisError(PeAnalysisResult& result, std::wstring message)
        {
            result.errorText = message;
            result.reportText = message;
            result.entries.clear();
            ReportCollector(result).Note(std::move(message));
        }

        // Hex formats unsigned integer values as uppercase 0x-prefixed report text.
        // The return value is a standalone string so stream state is not leaked.
        template <typename TValue>
        std::wstring Hex(TValue value)
        {
            std::wostringstream stream;
            stream << L"0x" << std::uppercase << std::hex << static_cast<std::uint64_t>(value);
            return stream.str();
        }

        // UnixTimeToLocalText converts PE TimeDateStamp seconds to local display text.
        // On CRT conversion failure it returns an explicit placeholder.
        std::wstring UnixTimeToLocalText(const std::uint32_t timeStamp)
        {
            std::time_t rawTime = static_cast<std::time_t>(timeStamp);
            std::tm localTime{};
            if (localtime_s(&localTime, &rawTime) != 0)
            {
                return L"<time conversion failed>";
            }
            wchar_t buffer[64] = {};
            if (std::wcsftime(buffer, std::size(buffer), L"%Y-%m-%d %H:%M:%S", &localTime) == 0)
            {
                return L"<time format failed>";
            }
            return buffer;
        }

        // MachineToText maps IMAGE_FILE_HEADER.Machine into common architecture names.
        // Unknown values remain visible through the raw numeric field printed by callers.
        std::wstring MachineToText(const std::uint16_t machineValue)
        {
            switch (machineValue)
            {
            case IMAGE_FILE_MACHINE_I386: return L"x86";
            case IMAGE_FILE_MACHINE_AMD64: return L"x64";
            case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
            case IMAGE_FILE_MACHINE_ARM: return L"ARM";
            case IMAGE_FILE_MACHINE_ARMNT: return L"ARMNT";
            case IMAGE_FILE_MACHINE_IA64: return L"IA64";
            default: return L"Unknown";
            }
        }

        // SubsystemToText maps the OptionalHeader subsystem value into readable text.
        // The report still includes the raw subsystem code for exact diagnostics.
        std::wstring SubsystemToText(const std::uint16_t subsystemValue)
        {
            switch (subsystemValue)
            {
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

        // JoinItems builds a pipe-separated flag summary for report output.
        // If no flags are known, emptyText explains that the summary is empty.
        std::wstring JoinItems(const std::vector<std::wstring>& itemList, const std::wstring& emptyText)
        {
            if (itemList.empty())
            {
                return emptyText;
            }
            std::wstring output;
            for (const std::wstring& itemText : itemList)
            {
                if (!output.empty())
                {
                    output += L" | ";
                }
                output += itemText;
            }
            return output;
        }

        // FileCharacteristicsToText summarizes common COFF file flags.
        // Inputs are raw IMAGE_FILE_HEADER.Characteristics bits.
        std::wstring FileCharacteristicsToText(const std::uint16_t characteristicsValue)
        {
            std::vector<std::wstring> itemList;
            if ((characteristicsValue & IMAGE_FILE_EXECUTABLE_IMAGE) != 0) { itemList.push_back(L"Executable"); }
            if ((characteristicsValue & IMAGE_FILE_DLL) != 0) { itemList.push_back(L"DLL"); }
            if ((characteristicsValue & IMAGE_FILE_LARGE_ADDRESS_AWARE) != 0) { itemList.push_back(L"LargeAddressAware"); }
            if ((characteristicsValue & IMAGE_FILE_32BIT_MACHINE) != 0) { itemList.push_back(L"Machine32Bit"); }
            if ((characteristicsValue & IMAGE_FILE_SYSTEM) != 0) { itemList.push_back(L"System"); }
            if ((characteristicsValue & IMAGE_FILE_RELOCS_STRIPPED) != 0) { itemList.push_back(L"RelocsStripped"); }
            return JoinItems(itemList, L"<no common flags>");
        }

        // SectionCharacteristicsToText summarizes common section flags.
        // The caller prints the raw bitmask next to this derived text.
        std::wstring SectionCharacteristicsToText(const std::uint32_t characteristicsValue)
        {
            std::vector<std::wstring> itemList;
            if ((characteristicsValue & IMAGE_SCN_CNT_CODE) != 0) { itemList.push_back(L"CODE"); }
            if ((characteristicsValue & IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) { itemList.push_back(L"INIT_DATA"); }
            if ((characteristicsValue & IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0) { itemList.push_back(L"BSS"); }
            if ((characteristicsValue & IMAGE_SCN_MEM_EXECUTE) != 0) { itemList.push_back(L"EXECUTE"); }
            if ((characteristicsValue & IMAGE_SCN_MEM_READ) != 0) { itemList.push_back(L"READ"); }
            if ((characteristicsValue & IMAGE_SCN_MEM_WRITE) != 0) { itemList.push_back(L"WRITE"); }
            if ((characteristicsValue & IMAGE_SCN_MEM_DISCARDABLE) != 0) { itemList.push_back(L"DISCARDABLE"); }
            return JoinItems(itemList, L"<no common attributes>");
        }

        // DataDirectoryName maps the fixed PE directory index to its standard label.
        // It returns UNKNOWN only for caller bugs because valid PE files expose 16 entries.
        std::wstring DataDirectoryName(const int directoryIndex)
        {
            static const std::array<const wchar_t*, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> kNames{ {
                L"EXPORT", L"IMPORT", L"RESOURCE", L"EXCEPTION",
                L"SECURITY", L"BASERELOC", L"DEBUG", L"ARCHITECTURE",
                L"GLOBALPTR", L"TLS", L"LOAD_CONFIG", L"BOUND_IMPORT",
                L"IAT", L"DELAY_IMPORT", L"COM_DESCRIPTOR", L"RESERVED"
            } };
            if (directoryIndex < 0 || directoryIndex >= static_cast<int>(kNames.size()))
            {
                return L"UNKNOWN";
            }
            return kNames[static_cast<std::size_t>(directoryIndex)];
        }

        // ReadPodAtOffset copies a fixed-size POD value from a bounded byte buffer.
        // It returns false instead of throwing when the requested range is invalid.
        template <typename TPod>
        bool ReadPodAtOffset(const std::vector<std::uint8_t>& fileBytes, std::uint64_t offsetValue, TPod& valueOut)
        {
            if (offsetValue > static_cast<std::uint64_t>(fileBytes.size()))
            {
                return false;
            }
            if (sizeof(TPod) > fileBytes.size() - static_cast<std::size_t>(offsetValue))
            {
                return false;
            }
            std::memcpy(&valueOut, fileBytes.data() + static_cast<std::size_t>(offsetValue), sizeof(TPod));
            return true;
        }

        // ReadAsciiAtOffset reads a NUL-terminated ANSI/UTF-8-ish PE string.
        // Inputs are the mapped file byte array and a validated file offset. The
        // loop is capped so malformed PE files cannot turn a missing NUL byte into
        // a whole-file string allocation. The return value is empty when the offset
        // is outside the file, otherwise it contains at most kMaxPeStringBytes bytes.
        std::wstring ReadAsciiAtOffset(const std::vector<std::uint8_t>& fileBytes, std::uint64_t offsetValue)
        {
            if (offsetValue >= static_cast<std::uint64_t>(fileBytes.size()))
            {
                return std::wstring();
            }
            constexpr std::size_t kMaxPeStringBytes = 4096;
            const std::size_t beginOffset = static_cast<std::size_t>(offsetValue);
            std::size_t endOffset = beginOffset;
            const std::size_t cappedEndOffset = std::min(fileBytes.size(), beginOffset + kMaxPeStringBytes);
            while (endOffset < cappedEndOffset && fileBytes[endOffset] != 0)
            {
                ++endOffset;
            }
            return ks::str::Utf8ToUtf16(std::string(
                reinterpret_cast<const char*>(fileBytes.data() + beginOffset),
                endOffset - beginOffset));
        }

        // SafeSectionName extracts an IMAGE_SECTION_HEADER.Name without assuming NUL termination.
        // The return value remains narrow because PeSectionSummary stores section names as std::string.
        std::string SafeSectionName(const IMAGE_SECTION_HEADER& sectionHeader)
        {
            const char* nameBytes = reinterpret_cast<const char*>(sectionHeader.Name);
            int length = 0;
            while (length < IMAGE_SIZEOF_SHORT_NAME && nameBytes[length] != '\0')
            {
                ++length;
            }
            return std::string(nameBytes, nameBytes + length);
        }

        // RvaToFileOffset maps only bytes that physically exist in a section's
        // raw-data range. A VirtualSize-only tail is zero-filled by the loader and
        // has no file offset, so treating it as raw evidence would be incorrect.
        bool RvaToFileOffset(
            std::uint32_t rvaValue,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            std::uint32_t& fileOffsetOut)
        {
            for (const IMAGE_SECTION_HEADER& sectionHeader : sectionList)
            {
                const std::uint32_t sectionRva = sectionHeader.VirtualAddress;
                if (rvaValue < sectionRva)
                {
                    continue;
                }
                const std::uint32_t delta = rvaValue - sectionRva;
                if (delta >= sectionHeader.SizeOfRawData
                    || sectionHeader.PointerToRawData
                        > std::numeric_limits<std::uint32_t>::max()
                            - delta)
                {
                    continue;
                }
                fileOffsetOut =
                    sectionHeader.PointerToRawData + delta;
                return true;
            }
            if (rvaValue < sizeOfHeadersValue)
            {
                fileOffsetOut = rvaValue;
                return true;
            }
            return false;
        }

        // CalculateSectionEntropy computes Shannon entropy over the raw section bytes.
        // Raw size is truncated to the file length so damaged headers remain safe.
        double CalculateSectionEntropy(
            const std::vector<std::uint8_t>& fileBytes,
            std::uint32_t rawOffsetValue,
            std::uint32_t rawSizeValue)
        {
            if (rawSizeValue == 0 || rawOffsetValue >= fileBytes.size())
            {
                return 0.0;
            }
            const std::uint32_t readableSize = std::min<std::uint32_t>(
                rawSizeValue,
                static_cast<std::uint32_t>(fileBytes.size() - rawOffsetValue));
            std::array<std::uint32_t, 256> countList{};
            for (std::uint32_t index = 0; index < readableSize; ++index)
            {
                ++countList[fileBytes[static_cast<std::size_t>(rawOffsetValue) + index]];
            }
            double entropyValue = 0.0;
            for (std::uint32_t countValue : countList)
            {
                if (countValue == 0) { continue; }
                const double probability = static_cast<double>(countValue) / static_cast<double>(readableSize);
                entropyValue -= probability * std::log2(probability);
            }
            return entropyValue;
        }

        // ReadWholeFile reads a Unicode path through Win32 sharing-friendly flags.
        // The output buffer receives exactly the bytes that were read.
        bool ReadWholeFile(const std::wstring& filePath, std::vector<std::uint8_t>& fileBytesOut, std::wstring& errorTextOut)
        {
            fileBytesOut.clear();
            errorTextOut.clear();
            HANDLE fileHandle = ::CreateFileW(
                filePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                errorTextOut = L"CreateFileW failed, error=" + std::to_wstring(::GetLastError());
                return false;
            }

            LARGE_INTEGER fileSize{};
            if (::GetFileSizeEx(fileHandle, &fileSize) == FALSE || fileSize.QuadPart < 0)
            {
                const DWORD errorCode = ::GetLastError();
                ::CloseHandle(fileHandle);
                errorTextOut = L"GetFileSizeEx failed, error=" + std::to_wstring(errorCode);
                return false;
            }
            if (static_cast<std::uint64_t>(fileSize.QuadPart) > kMaxPeFileBytes)
            {
                ::CloseHandle(fileHandle);
                errorTextOut = L"file is too large for interactive PE analysis";
                return false;
            }

            fileBytesOut.assign(static_cast<std::size_t>(fileSize.QuadPart), 0);
            std::size_t totalRead = 0;
            while (totalRead < fileBytesOut.size())
            {
                const DWORD chunkSize = static_cast<DWORD>(std::min<std::size_t>(fileBytesOut.size() - totalRead, 1024U * 1024U));
                DWORD bytesRead = 0;
                if (::ReadFile(fileHandle, fileBytesOut.data() + totalRead, chunkSize, &bytesRead, nullptr) == FALSE)
                {
                    const DWORD errorCode = ::GetLastError();
                    ::CloseHandle(fileHandle);
                    errorTextOut = L"ReadFile failed, error=" + std::to_wstring(errorCode);
                    return false;
                }
                if (bytesRead == 0)
                {
                    break;
                }
                totalRead += bytesRead;
            }
            ::CloseHandle(fileHandle);
            fileBytesOut.resize(totalRead);
            return true;
        }

        // AppendDataDirectories prints all standard PE data directories.
        // No directory is dereferenced here; this is the safe overview stage.
        void AppendDataDirectories(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::array<IMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES>& directoryList)
        {
            report.Section(L"数据目录");
            outputStream << L"\n[数据目录]\n";
            for (int directoryIndex = 0; directoryIndex < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++directoryIndex)
            {
                const IMAGE_DATA_DIRECTORY& directoryEntry = directoryList[static_cast<std::size_t>(directoryIndex)];
                report.Field(L"[" + std::to_wstring(directoryIndex) + L"] " + DataDirectoryName(directoryIndex), L"");
                report.Field(L"RVA", Hex(directoryEntry.VirtualAddress), 1);
                report.Field(L"Size", Hex(directoryEntry.Size), 1);
                outputStream << L"[" << directoryIndex << L"] " << DataDirectoryName(directoryIndex)
                    << L" RVA=" << Hex(directoryEntry.VirtualAddress)
                    << L" Size=" << Hex(directoryEntry.Size) << L"\n";
            }
        }

        // AppendImportTable walks IMAGE_IMPORT_DESCRIPTOR and each module thunk list.
        // It handles both name imports and ordinal imports for PE32 and PE32+ files.
        void AppendImportTable(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            bool isPe64,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& importDirectory)
        {
            report.Section(L"导入表");
            outputStream << L"\n[导入表]\n";
            if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
            {
                report.Note(L"无导入表。");
                outputStream << L"无导入表。\n";
                return;
            }
            std::uint32_t descriptorOffset = 0;
            if (!RvaToFileOffset(importDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, descriptorOffset))
            {
                report.Note(L"导入表 RVA 无法映射到文件偏移。");
                outputStream << L"导入表 RVA 无法映射到文件偏移。\n";
                return;
            }

            for (std::uint32_t moduleIndex = 0; moduleIndex < kMaxImportDescriptors; ++moduleIndex)
            {
                IMAGE_IMPORT_DESCRIPTOR descriptor{};
                const std::uint64_t currentOffset = static_cast<std::uint64_t>(descriptorOffset) + moduleIndex * sizeof(descriptor);
                if (!ReadPodAtOffset(fileBytes, currentOffset, descriptor))
                {
                    report.Note(L"导入描述符读取失败，索引=" + std::to_wstring(moduleIndex));
                    outputStream << L"导入描述符读取失败，索引=" << moduleIndex << L"\n";
                    return;
                }
                if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0)
                {
                    break;
                }

                std::uint32_t moduleNameOffset = 0;
                const std::wstring moduleName = RvaToFileOffset(descriptor.Name, sizeOfHeadersValue, sectionList, moduleNameOffset)
                    ? ReadAsciiAtOffset(fileBytes, moduleNameOffset)
                    : L"<名称RVA无法映射>";
                report.Field(L"模块", moduleName);
                report.Field(L"OriginalFirstThunk", Hex(descriptor.OriginalFirstThunk), 1);
                report.Field(L"FirstThunk", Hex(descriptor.FirstThunk), 1);
                outputStream << L"模块: " << moduleName << L"\n";

                const std::uint32_t thunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
                std::uint32_t thunkOffset = 0;
                if (!RvaToFileOffset(thunkRva, sizeOfHeadersValue, sectionList, thunkOffset))
                {
                    report.Note(L"  Thunk RVA 无法映射。");
                    outputStream << L"  Thunk RVA 无法映射。\n";
                    continue;
                }
                for (std::uint32_t importIndex = 0; importIndex < kMaxImportPerModule; ++importIndex)
                {
                    if (isPe64)
                    {
                        std::uint64_t thunkValue = 0;
                        if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(thunkOffset) + importIndex * sizeof(thunkValue), thunkValue) || thunkValue == 0)
                        {
                            break;
                        }
                        if ((thunkValue & IMAGE_ORDINAL_FLAG64) != 0)
                        {
                            report.Field(L"#" + std::to_wstring(importIndex), L"", 1);
                            report.Field(L"Ordinal", std::to_wstring(thunkValue & 0xFFFFULL), 2);
                            outputStream << L"  #" << importIndex << L" Ordinal=" << (thunkValue & 0xFFFFULL) << L"\n";
                            continue;
                        }
                        std::uint32_t importNameOffset = 0;
                        if (thunkValue > std::numeric_limits<std::uint32_t>::max() || !RvaToFileOffset(static_cast<std::uint32_t>(thunkValue), sizeOfHeadersValue, sectionList, importNameOffset))
                        {
                            report.Field(L"#" + std::to_wstring(importIndex), L"", 1);
                            report.Field(L"NameRVA", Hex(thunkValue), 2);
                            report.Note(L"无法映射", 2);
                            outputStream << L"  #" << importIndex << L" NameRVA=" << Hex(thunkValue) << L" <无法映射>\n";
                            continue;
                        }
                        std::uint16_t hintValue = 0;
                        ReadPodAtOffset(fileBytes, importNameOffset, hintValue);
                        report.Field(L"#" + std::to_wstring(importIndex), ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)), 1);
                        report.Field(L"Hint", std::to_wstring(hintValue), 2);
                        report.Field(L"NameRVA", Hex(thunkValue), 2);
                        outputStream << L"  #" << importIndex << L" Hint=" << hintValue
                            << L" Name=" << ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)) << L"\n";
                    }
                    else
                    {
                        std::uint32_t thunkValue = 0;
                        if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(thunkOffset) + importIndex * sizeof(thunkValue), thunkValue) || thunkValue == 0)
                        {
                            break;
                        }
                        if ((thunkValue & IMAGE_ORDINAL_FLAG32) != 0)
                        {
                            report.Field(L"#" + std::to_wstring(importIndex), L"", 1);
                            report.Field(L"Ordinal", std::to_wstring(thunkValue & 0xFFFFU), 2);
                            outputStream << L"  #" << importIndex << L" Ordinal=" << (thunkValue & 0xFFFFU) << L"\n";
                            continue;
                        }
                        std::uint32_t importNameOffset = 0;
                        if (!RvaToFileOffset(thunkValue, sizeOfHeadersValue, sectionList, importNameOffset))
                        {
                            report.Field(L"#" + std::to_wstring(importIndex), L"", 1);
                            report.Field(L"NameRVA", Hex(thunkValue), 2);
                            report.Note(L"无法映射", 2);
                            outputStream << L"  #" << importIndex << L" NameRVA=" << Hex(thunkValue) << L" <无法映射>\n";
                            continue;
                        }
                        std::uint16_t hintValue = 0;
                        ReadPodAtOffset(fileBytes, importNameOffset, hintValue);
                        report.Field(L"#" + std::to_wstring(importIndex), ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)), 1);
                        report.Field(L"Hint", std::to_wstring(hintValue), 2);
                        report.Field(L"NameRVA", Hex(thunkValue), 2);
                        outputStream << L"  #" << importIndex << L" Hint=" << hintValue
                            << L" Name=" << ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)) << L"\n";
                    }
                }
            }
        }

        // CollectImportTable walks IMAGE_IMPORT_DESCRIPTOR and thunk arrays into
        // structured rows. Inputs are the already-read file bytes, PE bitness, header
        // size, section table and import directory entry. Processing mirrors
        // AppendImportTable but stores bounded module/function records for UI tables.
        // Return value is a vector; malformed ranges are reported per-module through
        // diagnosticText and never throw or access outside fileBytes.
        std::vector<PeImportModuleSummary> CollectImportTable(
            const std::vector<std::uint8_t>& fileBytes,
            const bool isPe64,
            const std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& importDirectory)
        {
            std::vector<PeImportModuleSummary> moduleList;
            if (importDirectory.VirtualAddress == 0 || importDirectory.Size == 0)
            {
                return moduleList;
            }

            std::uint32_t descriptorOffset = 0;
            if (!RvaToFileOffset(importDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, descriptorOffset))
            {
                PeImportModuleSummary errorModule{};
                errorModule.dllName = "<Import Directory RVA mapping failed>";
                errorModule.diagnosticText = "Import Directory RVA could not be mapped to a file offset.";
                moduleList.push_back(std::move(errorModule));
                return moduleList;
            }

            for (std::uint32_t moduleIndex = 0; moduleIndex < kMaxImportDescriptors; ++moduleIndex)
            {
                IMAGE_IMPORT_DESCRIPTOR descriptor{};
                const std::uint64_t currentOffset =
                    static_cast<std::uint64_t>(descriptorOffset) +
                    static_cast<std::uint64_t>(moduleIndex) * sizeof(descriptor);
                if (!ReadPodAtOffset(fileBytes, currentOffset, descriptor))
                {
                    PeImportModuleSummary errorModule{};
                    errorModule.descriptorIndex = moduleIndex;
                    errorModule.dllName = "<Import Descriptor read failed>";
                    errorModule.diagnosticText = "Import descriptor could not be read safely.";
                    moduleList.push_back(std::move(errorModule));
                    return moduleList;
                }
                if (descriptor.OriginalFirstThunk == 0 && descriptor.FirstThunk == 0 && descriptor.Name == 0)
                {
                    break;
                }

                PeImportModuleSummary module{};
                module.descriptorIndex = moduleIndex;

                std::uint32_t moduleNameOffset = 0;
                if (RvaToFileOffset(descriptor.Name, sizeOfHeadersValue, sectionList, moduleNameOffset))
                {
                    module.dllName = ks::str::Utf16ToUtf8(ReadAsciiAtOffset(fileBytes, moduleNameOffset));
                }
                else
                {
                    module.dllName = "<Name RVA mapping failed>";
                    module.diagnosticText = "DLL name RVA could not be mapped.";
                }

                const std::uint32_t thunkRva =
                    descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
                const std::uint32_t displayThunkRva =
                    descriptor.FirstThunk != 0 ? descriptor.FirstThunk : thunkRva;
                std::uint32_t thunkOffset = 0;
                if (!RvaToFileOffset(thunkRva, sizeOfHeadersValue, sectionList, thunkOffset))
                {
                    if (!module.diagnosticText.empty())
                    {
                        module.diagnosticText += " ";
                    }
                    module.diagnosticText += "Thunk RVA could not be mapped.";
                    moduleList.push_back(std::move(module));
                    continue;
                }

                const std::uint32_t thunkWidth = isPe64
                    ? static_cast<std::uint32_t>(sizeof(std::uint64_t))
                    : static_cast<std::uint32_t>(sizeof(std::uint32_t));
                for (std::uint32_t importIndex = 0; importIndex < kMaxImportPerModule; ++importIndex)
                {
                    PeImportFunctionSummary function{};
                    function.dllName = module.dllName;
                    function.thunkRva = displayThunkRva + (importIndex * thunkWidth);

                    if (isPe64)
                    {
                        std::uint64_t thunkValue = 0;
                        if (!ReadPodAtOffset(
                            fileBytes,
                            static_cast<std::uint64_t>(thunkOffset) + importIndex * sizeof(thunkValue),
                            thunkValue) ||
                            thunkValue == 0)
                        {
                            break;
                        }
                        if ((thunkValue & IMAGE_ORDINAL_FLAG64) != 0)
                        {
                            function.importByOrdinal = true;
                            function.ordinal = static_cast<std::uint16_t>(thunkValue & 0xFFFFULL);
                            module.imports.push_back(std::move(function));
                            continue;
                        }

                        std::uint32_t importNameOffset = 0;
                        if (thunkValue > std::numeric_limits<std::uint32_t>::max() || !RvaToFileOffset(
                            static_cast<std::uint32_t>(thunkValue),
                            sizeOfHeadersValue,
                            sectionList,
                            importNameOffset))
                        {
                            function.functionName = "<Name RVA mapping failed>";
                            module.imports.push_back(std::move(function));
                            continue;
                        }
                        ReadPodAtOffset(fileBytes, importNameOffset, function.hint);
                        function.functionName = ks::str::Utf16ToUtf8(
                            ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)));
                        module.imports.push_back(std::move(function));
                    }
                    else
                    {
                        std::uint32_t thunkValue = 0;
                        if (!ReadPodAtOffset(
                            fileBytes,
                            static_cast<std::uint64_t>(thunkOffset) + importIndex * sizeof(thunkValue),
                            thunkValue) ||
                            thunkValue == 0)
                        {
                            break;
                        }
                        if ((thunkValue & IMAGE_ORDINAL_FLAG32) != 0)
                        {
                            function.importByOrdinal = true;
                            function.ordinal = static_cast<std::uint16_t>(thunkValue & 0xFFFFU);
                            module.imports.push_back(std::move(function));
                            continue;
                        }

                        std::uint32_t importNameOffset = 0;
                        if (!RvaToFileOffset(thunkValue, sizeOfHeadersValue, sectionList, importNameOffset))
                        {
                            function.functionName = "<Name RVA mapping failed>";
                            module.imports.push_back(std::move(function));
                            continue;
                        }
                        ReadPodAtOffset(fileBytes, importNameOffset, function.hint);
                        function.functionName = ks::str::Utf16ToUtf8(
                            ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(importNameOffset) + sizeof(std::uint16_t)));
                        module.imports.push_back(std::move(function));
                    }
                }

                if (module.imports.size() >= kMaxImportPerModule)
                {
                    if (!module.diagnosticText.empty())
                    {
                        module.diagnosticText += " ";
                    }
                    module.diagnosticText += "Import function list was truncated by safety limit.";
                }
                moduleList.push_back(std::move(module));
            }

            return moduleList;
        }

        // AppendExportTable reports export directory metadata and named exports.
        // Forwarder strings are detected when function RVAs point into the export directory.
        void AppendExportTable(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& exportDirectory)
        {
            report.Section(L"导出表");
            outputStream << L"\n[导出表]\n";
            if (exportDirectory.VirtualAddress == 0 || exportDirectory.Size == 0)
            {
                report.Note(L"无导出表。");
                outputStream << L"无导出表。\n";
                return;
            }
            std::uint32_t exportOffset = 0;
            if (!RvaToFileOffset(exportDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, exportOffset))
            {
                report.Note(L"导出表 RVA 无法映射到文件偏移。");
                outputStream << L"导出表 RVA 无法映射到文件偏移。\n";
                return;
            }

            IMAGE_EXPORT_DIRECTORY exportInfo{};
            if (!ReadPodAtOffset(fileBytes, exportOffset, exportInfo))
            {
                report.Note(L"导出目录读取失败。");
                outputStream << L"导出目录读取失败。\n";
                return;
            }
            std::uint32_t dllNameOffset = 0;
            const std::wstring dllName = RvaToFileOffset(exportInfo.Name, sizeOfHeadersValue, sectionList, dllNameOffset)
                ? ReadAsciiAtOffset(fileBytes, dllNameOffset)
                : L"<名称RVA无法映射>";
            report.Field(L"DLL名称", dllName);
            report.Field(L"Base", std::to_wstring(exportInfo.Base));
            report.Field(L"FunctionCount", std::to_wstring(exportInfo.NumberOfFunctions));
            report.Field(L"NameCount", std::to_wstring(exportInfo.NumberOfNames));
            outputStream << L"DLL名称: " << dllName << L"\n";
            outputStream << L"Base: " << exportInfo.Base
                << L" FunctionCount: " << exportInfo.NumberOfFunctions
                << L" NameCount: " << exportInfo.NumberOfNames << L"\n";

            std::uint32_t functionArrayOffset = 0;
            std::uint32_t nameArrayOffset = 0;
            std::uint32_t ordinalArrayOffset = 0;
            if (!RvaToFileOffset(exportInfo.AddressOfFunctions, sizeOfHeadersValue, sectionList, functionArrayOffset) ||
                !RvaToFileOffset(exportInfo.AddressOfNames, sizeOfHeadersValue, sectionList, nameArrayOffset) ||
                !RvaToFileOffset(exportInfo.AddressOfNameOrdinals, sizeOfHeadersValue, sectionList, ordinalArrayOffset))
            {
                report.Note(L"导出数组 RVA 无法映射。");
                outputStream << L"导出数组 RVA 无法映射。\n";
                return;
            }

            const std::uint32_t displayCount = std::min<std::uint32_t>(
                static_cast<std::uint32_t>(exportInfo.NumberOfNames),
                kMaxExportNames);
            for (std::uint32_t nameIndex = 0; nameIndex < displayCount; ++nameIndex)
            {
                std::uint32_t nameRva = 0;
                std::uint16_t ordinalIndex = 0;
                if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(nameArrayOffset) + nameIndex * sizeof(nameRva), nameRva) ||
                    !ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(ordinalArrayOffset) + nameIndex * sizeof(ordinalIndex), ordinalIndex))
                {
                    report.Note(L"导出数组读取失败，索引=" + std::to_wstring(nameIndex));
                    outputStream << L"导出数组读取失败，索引=" << nameIndex << L"\n";
                    break;
                }

                std::uint32_t functionRva = 0;
                if (ordinalIndex < exportInfo.NumberOfFunctions)
                {
                    ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(functionArrayOffset) + ordinalIndex * sizeof(functionRva), functionRva);
                }
                std::uint32_t nameOffset = 0;
                const std::wstring functionName = RvaToFileOffset(nameRva, sizeOfHeadersValue, sectionList, nameOffset)
                    ? ReadAsciiAtOffset(fileBytes, nameOffset)
                    : L"<名称RVA无法映射>";

                report.Field(L"[" + std::to_wstring(nameIndex) + L"]", functionName);
                report.Field(L"Ordinal", std::to_wstring(static_cast<std::uint64_t>(exportInfo.Base) + ordinalIndex), 1);
                report.Field(L"RVA", Hex(functionRva), 1);
                outputStream << L"  Ordinal=" << (exportInfo.Base + ordinalIndex)
                    << L" RVA=" << Hex(functionRva)
                    << L" Name=" << functionName;
                if (functionRva >= exportDirectory.VirtualAddress &&
                    static_cast<std::uint64_t>(functionRva) < static_cast<std::uint64_t>(exportDirectory.VirtualAddress) + exportDirectory.Size)
                {
                    std::uint32_t forwarderOffset = 0;
                    if (RvaToFileOffset(functionRva, sizeOfHeadersValue, sectionList, forwarderOffset))
                    {
                        report.Field(L"Forwarder", ReadAsciiAtOffset(fileBytes, forwarderOffset), 1);
                        outputStream << L" Forwarder=" << ReadAsciiAtOffset(fileBytes, forwarderOffset);
                    }
                }
                outputStream << L"\n";
            }
            if (exportInfo.NumberOfNames > displayCount)
            {
                report.Note(L"<导出名称已截断，剩余 " + std::to_wstring(exportInfo.NumberOfNames - displayCount) + L" 项>");
                outputStream << L"<导出名称已截断，剩余 " << (exportInfo.NumberOfNames - displayCount) << L" 项>\n";
            }
        }

        // ResourceTypeIdToText maps common resource type IDs found in root entries.
        // Named resources are reported separately because their text requires UTF-16 decoding.
        std::wstring ResourceTypeIdToText(const std::uint32_t typeIdValue)
        {
            switch (typeIdValue)
            {
            case 1: return L"CURSOR";
            case 2: return L"BITMAP";
            case 3: return L"ICON";
            case 4: return L"MENU";
            case 5: return L"DIALOG";
            case 6: return L"STRING";
            case 9: return L"ACCELERATOR";
            case 10: return L"RCDATA";
            case 14: return L"GROUP_ICON";
            case 16: return L"VERSION";
            case 24: return L"MANIFEST";
            default: return L"TYPE_" + std::to_wstring(typeIdValue);
            }
        }

        // AppendResourceDirectory provides a shallow first-level resource summary.
        // It avoids recursive tree expansion to keep backend output bounded.
        void AppendResourceDirectory(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& resourceDirectory)
        {
            report.Section(L"资源目录");
            outputStream << L"\n[资源目录]\n";
            if (resourceDirectory.VirtualAddress == 0 || resourceDirectory.Size == 0)
            {
                report.Note(L"无资源目录。");
                outputStream << L"无资源目录。\n";
                return;
            }
            std::uint32_t resourceBaseOffset = 0;
            if (!RvaToFileOffset(resourceDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, resourceBaseOffset))
            {
                report.Note(L"资源目录 RVA 无法映射到文件偏移。");
                outputStream << L"资源目录 RVA 无法映射到文件偏移。\n";
                return;
            }
            IMAGE_RESOURCE_DIRECTORY rootDirectory{};
            if (!ReadPodAtOffset(fileBytes, resourceBaseOffset, rootDirectory))
            {
                report.Note(L"资源目录头读取失败。");
                outputStream << L"资源目录头读取失败。\n";
                return;
            }

            const std::uint32_t entryCount = rootDirectory.NumberOfNamedEntries + rootDirectory.NumberOfIdEntries;
            report.Field(L"一级资源节点数", std::to_wstring(entryCount));
            outputStream << L"一级资源节点数: " << entryCount << L"\n";
            const std::uint32_t displayCount = std::min<std::uint32_t>(entryCount, 64U);
            for (std::uint32_t index = 0; index < displayCount; ++index)
            {
                IMAGE_RESOURCE_DIRECTORY_ENTRY entry{};
                const std::uint64_t entryOffset = static_cast<std::uint64_t>(resourceBaseOffset) +
                    sizeof(IMAGE_RESOURCE_DIRECTORY) + static_cast<std::uint64_t>(index) * sizeof(entry);
                if (!ReadPodAtOffset(fileBytes, entryOffset, entry))
                {
                    report.Note(L"资源目录项读取失败，索引=" + std::to_wstring(index));
                    outputStream << L"资源目录项读取失败，索引=" << index << L"\n";
                    break;
                }
                report.Field(L"[" + std::to_wstring(index) + L"]", entry.NameIsString ? L"NamedResource" : ResourceTypeIdToText(entry.Id));
                report.Field(L"OffsetToData", Hex(entry.OffsetToData), 1);
                outputStream << L"  [" << index << L"] "
                    << (entry.NameIsString ? L"NamedResource" : ResourceTypeIdToText(entry.Id))
                    << L" OffsetToData=" << Hex(entry.OffsetToData) << L"\n";
            }
        }

        // AppendBaseRelocDirectory summarizes relocation block and entry counts.
        // The loop validates each block size before advancing to avoid infinite loops.
        void AppendBaseRelocDirectory(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& relocDirectory)
        {
            report.Section(L"重定位表");
            outputStream << L"\n[重定位表]\n";
            if (relocDirectory.VirtualAddress == 0 || relocDirectory.Size == 0)
            {
                report.Note(L"无重定位表。");
                outputStream << L"无重定位表。\n";
                return;
            }
            std::uint32_t relocOffset = 0;
            if (!RvaToFileOffset(relocDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, relocOffset))
            {
                report.Note(L"重定位表 RVA 无法映射到文件偏移。");
                outputStream << L"重定位表 RVA 无法映射到文件偏移。\n";
                return;
            }

            std::uint32_t consumedBytes = 0;
            std::uint32_t blockCount = 0;
            std::uint32_t entryCount = 0;
            while (consumedBytes <= relocDirectory.Size
                && sizeof(IMAGE_BASE_RELOCATION) <= relocDirectory.Size - consumedBytes)
            {
                IMAGE_BASE_RELOCATION block{};
                if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(relocOffset) + consumedBytes, block))
                {
                    break;
                }
                if (block.VirtualAddress == 0 || block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
                {
                    break;
                }
                if (block.SizeOfBlock > relocDirectory.Size - consumedBytes
                    || static_cast<std::uint64_t>(relocOffset) + consumedBytes > fileBytes.size()
                    || block.SizeOfBlock > fileBytes.size()
                        - (static_cast<std::uint64_t>(relocOffset) + consumedBytes))
                {
                    report.Note(L"重定位块范围超出目录或文件边界。");
                    outputStream << L"重定位块范围超出目录或文件边界。\n";
                    break;
                }
                ++blockCount;
                entryCount += (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
                consumedBytes += block.SizeOfBlock;
            }
            report.Field(L"重定位块", std::to_wstring(blockCount));
            report.Field(L"条目估算", std::to_wstring(entryCount));
            outputStream << L"重定位块: " << blockCount << L"，条目估算: " << entryCount << L"\n";
        }

        // AppendDebugDirectory prints debug directory rows and CodeView PDB paths when present.
        // It keeps parsing shallow because this backend is for quick PE triage.
        void AppendDebugDirectory(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& debugDirectory)
        {
            report.Section(L"调试目录");
            outputStream << L"\n[调试目录]\n";
            if (debugDirectory.VirtualAddress == 0 || debugDirectory.Size == 0)
            {
                report.Note(L"无调试目录。");
                outputStream << L"无调试目录。\n";
                return;
            }
            std::uint32_t debugOffset = 0;
            if (!RvaToFileOffset(debugDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, debugOffset))
            {
                report.Note(L"调试目录 RVA 无法映射到文件偏移。");
                outputStream << L"调试目录 RVA 无法映射到文件偏移。\n";
                return;
            }
            const std::uint32_t entryCount = debugDirectory.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
            report.Field(L"调试项数量", std::to_wstring(entryCount));
            outputStream << L"调试项数量: " << entryCount << L"\n";
            for (std::uint32_t index = 0; index < std::min<std::uint32_t>(entryCount, 32U); ++index)
            {
                IMAGE_DEBUG_DIRECTORY entry{};
                if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(debugOffset) + index * sizeof(entry), entry))
                {
                    report.Note(L"调试项读取失败，索引=" + std::to_wstring(index));
                    outputStream << L"调试项读取失败，索引=" << index << L"\n";
                    break;
                }
                report.Field(L"[" + std::to_wstring(index) + L"]", L"");
                report.Field(L"Type", std::to_wstring(entry.Type), 1);
                report.Field(L"Size", std::to_wstring(entry.SizeOfData), 1);
                report.Field(L"Raw", Hex(entry.PointerToRawData), 1);
                outputStream << L"  [" << index << L"] Type=" << entry.Type
                    << L" Size=" << entry.SizeOfData
                    << L" Raw=" << Hex(entry.PointerToRawData) << L"\n";
                if (entry.Type == IMAGE_DEBUG_TYPE_CODEVIEW && static_cast<std::uint64_t>(entry.PointerToRawData) + 24U < fileBytes.size())
                {
                    const std::wstring pdbPath = ReadAsciiAtOffset(fileBytes, static_cast<std::uint64_t>(entry.PointerToRawData) + 24U);
                    if (!pdbPath.empty())
                    {
                        report.Field(L"PDB", pdbPath, 1);
                        outputStream << L"      PDB=" << pdbPath << L"\n";
                    }
                }
            }
        }

        // AppendTlsDirectory prints TLS callback addresses for PE32 and PE32+ images.
        // Callback VA values are converted through imageBase back to file offsets.
        void AppendTlsDirectory(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const std::vector<std::uint8_t>& fileBytes,
            bool isPe64,
            std::uint64_t imageBaseValue,
            std::uint32_t sizeOfHeadersValue,
            const std::vector<IMAGE_SECTION_HEADER>& sectionList,
            const IMAGE_DATA_DIRECTORY& tlsDirectory)
        {
            report.Section(L"TLS目录");
            outputStream << L"\n[TLS目录]\n";
            if (tlsDirectory.VirtualAddress == 0 || tlsDirectory.Size == 0)
            {
                report.Note(L"无 TLS 目录。");
                outputStream << L"无 TLS 目录。\n";
                return;
            }
            std::uint32_t tlsOffset = 0;
            if (!RvaToFileOffset(tlsDirectory.VirtualAddress, sizeOfHeadersValue, sectionList, tlsOffset))
            {
                report.Note(L"TLS RVA 无法映射到文件偏移。");
                outputStream << L"TLS RVA 无法映射到文件偏移。\n";
                return;
            }

            std::uint64_t callbacksVa = 0;
            if (isPe64)
            {
                IMAGE_TLS_DIRECTORY64 tlsInfo{};
                if (!ReadPodAtOffset(fileBytes, tlsOffset, tlsInfo))
                {
                    report.Note(L"TLS64 目录读取失败。");
                    outputStream << L"TLS64 目录读取失败。\n";
                    return;
                }
                callbacksVa = tlsInfo.AddressOfCallBacks;
            }
            else
            {
                IMAGE_TLS_DIRECTORY32 tlsInfo{};
                if (!ReadPodAtOffset(fileBytes, tlsOffset, tlsInfo))
                {
                    report.Note(L"TLS32 目录读取失败。");
                    outputStream << L"TLS32 目录读取失败。\n";
                    return;
                }
                callbacksVa = tlsInfo.AddressOfCallBacks;
            }
            report.Field(L"AddressOfCallBacks", Hex(callbacksVa));
            outputStream << L"AddressOfCallBacks: " << Hex(callbacksVa) << L"\n";
            if (callbacksVa <= imageBaseValue || callbacksVa - imageBaseValue > std::numeric_limits<std::uint32_t>::max())
            {
                return;
            }

            std::uint32_t callbackOffset = 0;
            const std::uint32_t callbackRva = static_cast<std::uint32_t>(callbacksVa - imageBaseValue);
            if (!RvaToFileOffset(callbackRva, sizeOfHeadersValue, sectionList, callbackOffset))
            {
                report.Note(L"TLS 回调数组 RVA 无法映射。");
                outputStream << L"TLS 回调数组 RVA 无法映射。\n";
                return;
            }
            for (std::uint32_t index = 0; index < 64U; ++index)
            {
                if (isPe64)
                {
                    std::uint64_t callbackVa = 0;
                    if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(callbackOffset) + index * sizeof(callbackVa), callbackVa) || callbackVa == 0)
                    {
                        break;
                    }
                    report.Field(L"Callback[" + std::to_wstring(index) + L"] VA", Hex(callbackVa));
                    outputStream << L"  Callback[" << index << L"] VA=" << Hex(callbackVa) << L"\n";
                }
                else
                {
                    std::uint32_t callbackVa = 0;
                    if (!ReadPodAtOffset(fileBytes, static_cast<std::uint64_t>(callbackOffset) + index * sizeof(callbackVa), callbackVa) || callbackVa == 0)
                    {
                        break;
                    }
                    report.Field(L"Callback[" + std::to_wstring(index) + L"] VA", Hex(callbackVa));
                    outputStream << L"  Callback[" << index << L"] VA=" << Hex(callbackVa) << L"\n";
                }
            }
        }

        // AppendSimpleDirectory prints a presence/location summary for directories that
        // do not need deeper parsing in this shared backend.
        void AppendSimpleDirectory(
            std::wostringstream& outputStream,
            ReportCollector& report,
            const wchar_t* titleText,
            const wchar_t* emptyText,
            const IMAGE_DATA_DIRECTORY& directoryEntry)
        {
            report.Section(titleText);
            outputStream << L"\n[" << titleText << L"]\n";
            if (directoryEntry.VirtualAddress == 0 || directoryEntry.Size == 0)
            {
                report.Note(emptyText);
                outputStream << emptyText << L"\n";
                return;
            }
            report.Field(L"RVA", Hex(directoryEntry.VirtualAddress));
            report.Field(L"Size", Hex(directoryEntry.Size));
            outputStream << L"RVA=" << Hex(directoryEntry.VirtualAddress)
                << L" Size=" << Hex(directoryEntry.Size) << L"\n";
        }
    }

    PeAnalysisResult AnalyzePeBytes(
        const std::vector<std::uint8_t>& fileBytes)
    {
        PeAnalysisResult result{};
        if (fileBytes.size() < sizeof(IMAGE_DOS_HEADER))
        {
            SetAnalysisError(result, L"PE解析失败：文件过小，无法读取 DOS 头。");
            return result;
        }

        IMAGE_DOS_HEADER dosHeader{};
        if (!ReadPodAtOffset(fileBytes, 0, dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
        {
            SetAnalysisError(result, L"PE解析失败：不是有效的 MZ 文件。");
            return result;
        }
        if (dosHeader.e_lfanew < 0)
        {
            SetAnalysisError(result, L"PE解析失败：e_lfanew 为负数。");
            return result;
        }

        const std::uint64_t ntHeaderOffset = static_cast<std::uint64_t>(dosHeader.e_lfanew);
        std::uint32_t peSignature = 0;
        if (!ReadPodAtOffset(fileBytes, ntHeaderOffset, peSignature) || peSignature != IMAGE_NT_SIGNATURE)
        {
            SetAnalysisError(result, L"PE解析失败：PE 签名无效。");
            return result;
        }

        IMAGE_FILE_HEADER fileHeader{};
        const std::uint64_t fileHeaderOffset = ntHeaderOffset + sizeof(std::uint32_t);
        if (!ReadPodAtOffset(fileBytes, fileHeaderOffset, fileHeader))
        {
            SetAnalysisError(result, L"PE解析失败：COFF 文件头读取失败。");
            return result;
        }
        if (fileHeader.NumberOfSections > kMaxSectionCount)
        {
            SetAnalysisError(result, L"PE解析失败：区段数量异常：" + std::to_wstring(fileHeader.NumberOfSections));
            return result;
        }

        const std::uint64_t optionalHeaderOffset = fileHeaderOffset + sizeof(IMAGE_FILE_HEADER);
        if (fileHeader.SizeOfOptionalHeader < sizeof(std::uint16_t)
            || optionalHeaderOffset
                > static_cast<std::uint64_t>(
                    fileBytes.size())
            || static_cast<std::uint64_t>(
                   fileHeader.SizeOfOptionalHeader)
                > static_cast<std::uint64_t>(
                    fileBytes.size())
                    - optionalHeaderOffset)
        {
            SetAnalysisError(result, L"PE解析失败：Optional Header 声明范围超出文件边界。");
            return result;
        }
        std::uint16_t optionalMagic = 0;
        if (!ReadPodAtOffset(fileBytes, optionalHeaderOffset, optionalMagic))
        {
            SetAnalysisError(result, L"PE解析失败：Optional Header 魔数读取失败。");
            return result;
        }

        bool isPe64 = false;
        std::uint64_t imageBaseValue = 0;
        std::uint32_t entryPointRva = 0;
        std::uint16_t subsystemValue = 0;
        std::uint32_t sizeOfImageValue = 0;
        std::uint32_t sizeOfHeadersValue = 0;
        std::uint32_t sectionAlignmentValue = 0;
        std::uint32_t fileAlignmentValue = 0;
        std::uint32_t checksumValue = 0;
        std::array<IMAGE_DATA_DIRECTORY, IMAGE_NUMBEROF_DIRECTORY_ENTRIES> dataDirectoryList{};

        if (optionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER64 optionalHeader{};
            const std::size_t fixedHeaderBytes =
                FIELD_OFFSET(
                    IMAGE_OPTIONAL_HEADER64,
                    DataDirectory);
            if (fileHeader.SizeOfOptionalHeader
                < fixedHeaderBytes)
            {
                SetAnalysisError(result, L"PE解析失败：PE32+ Optional Header 不足以覆盖固定字段和 NumberOfRvaAndSizes。");
                return result;
            }
            std::memcpy(
                &optionalHeader,
                fileBytes.data()
                    + static_cast<std::size_t>(
                        optionalHeaderOffset),
                std::min<std::size_t>(
                    sizeof(optionalHeader),
                    fileHeader.SizeOfOptionalHeader));
            isPe64 = true;
            imageBaseValue = optionalHeader.ImageBase;
            entryPointRva = optionalHeader.AddressOfEntryPoint;
            subsystemValue = optionalHeader.Subsystem;
            sizeOfImageValue = optionalHeader.SizeOfImage;
            sizeOfHeadersValue = optionalHeader.SizeOfHeaders;
            sectionAlignmentValue = optionalHeader.SectionAlignment;
            fileAlignmentValue = optionalHeader.FileAlignment;
            checksumValue = optionalHeader.CheckSum;
            const std::size_t directoryCapacity =
                (fileHeader.SizeOfOptionalHeader
                 - fixedHeaderBytes)
                / sizeof(IMAGE_DATA_DIRECTORY);
            const std::uint32_t count =
                std::min<std::uint32_t>(
                    std::min<std::uint32_t>(
                        optionalHeader.NumberOfRvaAndSizes,
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
                    static_cast<std::uint32_t>(
                        directoryCapacity));
            for (std::uint32_t index = 0; index < count; ++index)
            {
                dataDirectoryList[static_cast<std::size_t>(index)] = optionalHeader.DataDirectory[index];
            }
        }
        else if (optionalMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            IMAGE_OPTIONAL_HEADER32 optionalHeader{};
            const std::size_t fixedHeaderBytes =
                FIELD_OFFSET(
                    IMAGE_OPTIONAL_HEADER32,
                    DataDirectory);
            if (fileHeader.SizeOfOptionalHeader
                < fixedHeaderBytes)
            {
                SetAnalysisError(result, L"PE解析失败：PE32 Optional Header 不足以覆盖固定字段和 NumberOfRvaAndSizes。");
                return result;
            }
            std::memcpy(
                &optionalHeader,
                fileBytes.data()
                    + static_cast<std::size_t>(
                        optionalHeaderOffset),
                std::min<std::size_t>(
                    sizeof(optionalHeader),
                    fileHeader.SizeOfOptionalHeader));
            isPe64 = false;
            imageBaseValue = optionalHeader.ImageBase;
            entryPointRva = optionalHeader.AddressOfEntryPoint;
            subsystemValue = optionalHeader.Subsystem;
            sizeOfImageValue = optionalHeader.SizeOfImage;
            sizeOfHeadersValue = optionalHeader.SizeOfHeaders;
            sectionAlignmentValue = optionalHeader.SectionAlignment;
            fileAlignmentValue = optionalHeader.FileAlignment;
            checksumValue = optionalHeader.CheckSum;
            const std::size_t directoryCapacity =
                (fileHeader.SizeOfOptionalHeader
                 - fixedHeaderBytes)
                / sizeof(IMAGE_DATA_DIRECTORY);
            const std::uint32_t count =
                std::min<std::uint32_t>(
                    std::min<std::uint32_t>(
                        optionalHeader.NumberOfRvaAndSizes,
                        IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
                    static_cast<std::uint32_t>(
                        directoryCapacity));
            for (std::uint32_t index = 0; index < count; ++index)
            {
                dataDirectoryList[static_cast<std::size_t>(index)] = optionalHeader.DataDirectory[index];
            }
        }
        else
        {
            SetAnalysisError(result, L"PE解析失败：未知 Optional Header 魔数：" + Hex(optionalMagic));
            return result;
        }

        // Read and summarize the section table before any directory parsing uses RVA mapping.
        // The structured summaries are returned alongside the human-readable report.
        const std::uint64_t optionalHeaderEnd =
            optionalHeaderOffset
            + static_cast<std::uint64_t>(
                fileHeader.SizeOfOptionalHeader);
        const std::uint64_t sectionTableOffset =
            optionalHeaderEnd;
        const std::uint64_t sectionTableBytes =
            static_cast<std::uint64_t>(
                fileHeader.NumberOfSections)
            * sizeof(IMAGE_SECTION_HEADER);
        /*
         * The PE section table begins exactly at the end declared by
         * SizeOfOptionalHeader, so construction prevents overlap. Recheck the
         * addition for wraparound and the complete table for file containment.
         */
        if (optionalHeaderEnd < optionalHeaderOffset
            || sectionTableOffset
                > static_cast<std::uint64_t>(
                    fileBytes.size())
            || sectionTableBytes
                > static_cast<std::uint64_t>(
                    fileBytes.size())
                    - sectionTableOffset)
        {
            SetAnalysisError(result, L"PE解析失败：区段表与 Optional Header 重叠或超出文件边界。");
            return result;
        }
        std::vector<IMAGE_SECTION_HEADER> sectionList;
        sectionList.reserve(fileHeader.NumberOfSections);
        for (std::uint16_t sectionIndex = 0; sectionIndex < fileHeader.NumberOfSections; ++sectionIndex)
        {
            IMAGE_SECTION_HEADER sectionHeader{};
            const std::uint64_t currentOffset = sectionTableOffset +
                static_cast<std::uint64_t>(sectionIndex) * sizeof(IMAGE_SECTION_HEADER);
            if (!ReadPodAtOffset(fileBytes, currentOffset, sectionHeader))
            {
                SetAnalysisError(result, L"PE解析失败：区段表读取失败，索引=" + std::to_wstring(sectionIndex));
                return result;
            }
            const std::uint64_t rawOffset =
                sectionHeader.PointerToRawData;
            const std::uint64_t rawSize =
                sectionHeader.SizeOfRawData;
            if (rawSize != 0U
                && (rawOffset
                        > static_cast<std::uint64_t>(
                            fileBytes.size())
                    || rawSize
                        > static_cast<std::uint64_t>(
                            fileBytes.size())
                            - rawOffset))
            {
                SetAnalysisError(result, L"PE解析失败：区段原始数据范围超出文件边界，索引="
                    + std::to_wstring(sectionIndex));
                return result;
            }
            sectionList.push_back(sectionHeader);

            PeSectionSummary summary{};
            summary.name = SafeSectionName(sectionHeader);
            summary.virtualAddress = sectionHeader.VirtualAddress;
            summary.virtualSize = sectionHeader.Misc.VirtualSize;
            summary.rawOffset = sectionHeader.PointerToRawData;
            summary.rawSize = sectionHeader.SizeOfRawData;
            summary.characteristics = sectionHeader.Characteristics;
            summary.entropy = CalculateSectionEntropy(fileBytes, sectionHeader.PointerToRawData, sectionHeader.SizeOfRawData);
            result.sections.push_back(summary);
        }

        // Fill the structured result fields before building text so non-UI callers can
        // inspect basic metadata without parsing the report string.
        result.success = true;
        result.isPe64 = isPe64;
        result.machine = fileHeader.Machine;
        result.subsystem = subsystemValue;
        result.entryPointRva = entryPointRva;
        result.imageBase = imageBaseValue;
        result.entryPointFileOffsetValid =
            entryPointRva != 0U
            && RvaToFileOffset(
                entryPointRva,
                sizeOfHeadersValue,
                sectionList,
                result.entryPointFileOffset)
            && result.entryPointFileOffset
                < static_cast<std::uint64_t>(fileBytes.size());
        result.importModules = CollectImportTable(
            fileBytes,
            isPe64,
            sizeOfHeadersValue,
            sectionList,
            dataDirectoryList[IMAGE_DIRECTORY_ENTRY_IMPORT]);

        ReportCollector report(result);
        report.Section(L"PE头");
        report.Field(L"文件格式", isPe64 ? L"PE32+" : L"PE32");
        report.Field(L"e_lfanew", Hex(static_cast<std::uint32_t>(dosHeader.e_lfanew)));
        report.Field(L"Machine", Hex(fileHeader.Machine) + L" (" + MachineToText(fileHeader.Machine) + L")");
        report.Field(L"Section数量", std::to_wstring(fileHeader.NumberOfSections));
        report.Field(L"TimeDateStamp", Hex(fileHeader.TimeDateStamp) + L" (" + UnixTimeToLocalText(fileHeader.TimeDateStamp) + L")");
        report.Field(L"Characteristics", Hex(fileHeader.Characteristics) + L" (" + FileCharacteristicsToText(fileHeader.Characteristics) + L")");
        report.Field(L"EntryPoint RVA", Hex(entryPointRva));
        report.Field(L"ImageBase", Hex(imageBaseValue));
        report.Field(L"Subsystem", Hex(subsystemValue) + L" (" + SubsystemToText(subsystemValue) + L")");
        report.Field(L"SectionAlignment", Hex(sectionAlignmentValue));
        report.Field(L"FileAlignment", Hex(fileAlignmentValue));
        report.Field(L"SizeOfImage", Hex(sizeOfImageValue));
        report.Field(L"SizeOfHeaders", Hex(sizeOfHeadersValue));
        report.Field(L"CheckSum", Hex(checksumValue));
        std::wostringstream outputStream;
        outputStream << L"[PE头]\n";
        outputStream << L"文件格式: " << (isPe64 ? L"PE32+" : L"PE32") << L"\n";
        outputStream << L"e_lfanew: " << Hex(static_cast<std::uint32_t>(dosHeader.e_lfanew)) << L"\n";
        outputStream << L"Machine: " << Hex(fileHeader.Machine) << L" (" << MachineToText(fileHeader.Machine) << L")\n";
        outputStream << L"Section数量: " << fileHeader.NumberOfSections << L"\n";
        outputStream << L"TimeDateStamp: " << Hex(fileHeader.TimeDateStamp) << L" (" << UnixTimeToLocalText(fileHeader.TimeDateStamp) << L")\n";
        outputStream << L"Characteristics: " << Hex(fileHeader.Characteristics) << L" (" << FileCharacteristicsToText(fileHeader.Characteristics) << L")\n";
        outputStream << L"EntryPoint RVA: " << Hex(entryPointRva) << L"\n";
        outputStream << L"ImageBase: " << Hex(imageBaseValue) << L"\n";
        outputStream << L"Subsystem: " << Hex(subsystemValue) << L" (" << SubsystemToText(subsystemValue) << L")\n";
        outputStream << L"SectionAlignment: " << Hex(sectionAlignmentValue) << L"\n";
        outputStream << L"FileAlignment: " << Hex(fileAlignmentValue) << L"\n";
        outputStream << L"SizeOfImage: " << Hex(sizeOfImageValue) << L"\n";
        outputStream << L"SizeOfHeaders: " << Hex(sizeOfHeadersValue) << L"\n";
        outputStream << L"CheckSum: " << Hex(checksumValue) << L"\n";

        report.Section(L"区段表");
        outputStream << L"\n[区段表]\n";
        for (std::size_t sectionIndex = 0; sectionIndex < sectionList.size(); ++sectionIndex)
        {
            const IMAGE_SECTION_HEADER& sectionHeader = sectionList[sectionIndex];
            const PeSectionSummary& summary = result.sections[sectionIndex];
            report.Field(L"[" + std::to_wstring(sectionIndex) + L"]", ks::str::Utf8ToUtf16(summary.name));
            report.Field(L"VirtualAddress", Hex(sectionHeader.VirtualAddress), 1);
            report.Field(L"VirtualSize", Hex(sectionHeader.Misc.VirtualSize), 1);
            report.Field(L"PointerToRawData", Hex(sectionHeader.PointerToRawData), 1);
            report.Field(L"SizeOfRawData", Hex(sectionHeader.SizeOfRawData), 1);
            std::wostringstream entropyText;
            entropyText << std::fixed << std::setprecision(4) << summary.entropy;
            report.Field(L"Entropy", entropyText.str(), 1);
            report.Field(L"Characteristics", Hex(sectionHeader.Characteristics) + L" (" + SectionCharacteristicsToText(sectionHeader.Characteristics) + L")", 1);
            outputStream
                << L"[" << sectionIndex << L"] " << ks::str::Utf8ToUtf16(summary.name) << L"\n"
                << L"  VirtualAddress: " << Hex(sectionHeader.VirtualAddress) << L"\n"
                << L"  VirtualSize: " << Hex(sectionHeader.Misc.VirtualSize) << L"\n"
                << L"  PointerToRawData: " << Hex(sectionHeader.PointerToRawData) << L"\n"
                << L"  SizeOfRawData: " << Hex(sectionHeader.SizeOfRawData) << L"\n"
                << L"  Entropy: " << std::fixed << std::setprecision(4) << summary.entropy << L"\n"
                << L"  Characteristics: " << Hex(sectionHeader.Characteristics)
                << L" (" << SectionCharacteristicsToText(sectionHeader.Characteristics) << L")\n";
        }

        // Directory-specific appenders stay independent so new consumers can move toward
        // structured directory objects later without changing the UI wrapper contract.
        AppendDataDirectories(outputStream, report, dataDirectoryList);
        AppendImportTable(outputStream, report, fileBytes, isPe64, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_IMPORT]);
        AppendExportTable(outputStream, report, fileBytes, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_EXPORT]);
        AppendTlsDirectory(outputStream, report, fileBytes, isPe64, imageBaseValue, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_TLS]);
        AppendResourceDirectory(outputStream, report, fileBytes, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
        AppendBaseRelocDirectory(outputStream, report, fileBytes, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
        AppendDebugDirectory(outputStream, report, fileBytes, sizeOfHeadersValue, sectionList, dataDirectoryList[IMAGE_DIRECTORY_ENTRY_DEBUG]);
        AppendSimpleDirectory(outputStream, report, L"延迟导入表", L"无延迟导入表。", dataDirectoryList[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
        AppendSimpleDirectory(outputStream, report, L"绑定导入表", L"无绑定导入表。", dataDirectoryList[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]);
        AppendSimpleDirectory(outputStream, report, L"Load Config目录", L"无 Load Config 目录。", dataDirectoryList[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG]);
        AppendSimpleDirectory(outputStream, report, L"CLR/.NET目录", L"无 CLR 目录。", dataDirectoryList[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]);
        AppendSimpleDirectory(outputStream, report, L"安全目录/证书", L"无安全目录。", dataDirectoryList[IMAGE_DIRECTORY_ENTRY_SECURITY]);

        result.reportText = outputStream.str();
        return result;
    }

    PeAnalysisResult AnalyzePeFile(const std::wstring& filePath)
    {
        std::vector<std::uint8_t> fileBytes;
        std::wstring readErrorText;
        if (!ReadWholeFile(filePath, fileBytes, readErrorText))
        {
            PeAnalysisResult result;
            SetAnalysisError(result, L"PE解析失败：" + readErrorText);
            return result;
        }
        return AnalyzePeBytes(fileBytes);
    }

    std::wstring BuildPeAnalysisText(const std::wstring& filePath)
    {
        // BuildPeAnalysisText is the text-only facade used by the FileDock property page.
        // It returns the report regardless of success so failures remain displayable.
        return AnalyzePeFile(filePath).reportText;
    }

    std::wstring BuildPeAnalysisText(
        const std::vector<std::uint8_t>& fileBytes)
    {
        return AnalyzePeBytes(fileBytes).reportText;
    }

    std::string BuildPeAnalysisTextUtf8(const std::string& filePathUtf8)
    {
        // UTF-8 callers receive both path conversion and report conversion in one helper.
        // Empty conversion results naturally flow through to AnalyzePeFile failure text.
        return ks::str::Utf16ToUtf8(BuildPeAnalysisText(ks::str::Utf8ToUtf16(filePathUtf8)));
    }
}
