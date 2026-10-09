#include "binary_scanner.h"
#include "binary_layout.h"

#include "scanner_internal.h"
#include "../file/pe_analyzer.h"

// ============================================================
// ksword/scanner/binary_scanner.cpp
// Purpose:
// - Bound and load one file, dispatch by magic, and adapt parser results.
// - Reuse ks::file::AnalyzePeBytes as the canonical PE implementation.
// - Add only the structured PE export information absent from that API.
// ============================================================

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <limits>
#include <new>
#include <span>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace ks::scanner
{
    namespace
    {
        using detail::AddDiagnostic;
        using detail::AddDiagnosticAt;
        using detail::AddField;
        using detail::AppendRow;
        using detail::Decimal;
        using detail::EndianReader;
        using detail::Hex;

        struct PeSectionMap
        {
            std::uint32_t virtualAddress = 0;
            std::uint32_t virtualSize = 0;
            std::uint32_t rawOffset = 0;
            std::uint32_t rawSize = 0;
        };

        std::string WideToUtf8(const std::wstring& text)
        {
            if (text.empty())
            {
                return {};
            }
            const int requiredBytes = ::WideCharToMultiByte(
                CP_UTF8,
                WC_ERR_INVALID_CHARS,
                text.data(),
                static_cast<int>(std::min<std::size_t>(
                    text.size(),
                    static_cast<std::size_t>(std::numeric_limits<int>::max()))),
                nullptr,
                0,
                nullptr,
                nullptr);
            if (requiredBytes <= 0)
            {
                return "PE analyzer rejected the file.";
            }
            std::string output(static_cast<std::size_t>(requiredBytes), '\0');
            if (::WideCharToMultiByte(
                    CP_UTF8,
                    WC_ERR_INVALID_CHARS,
                    text.data(),
                    static_cast<int>(text.size()),
                    output.data(),
                    requiredBytes,
                    nullptr,
                    nullptr) <= 0)
            {
                return "PE analyzer rejected the file.";
            }
            return output;
        }

        const char* PeMachineName(const std::uint16_t machine)
        {
            switch (machine)
            {
            case 0x014CU: return "x86";
            case 0x8664U: return "x86-64";
            case 0x01C0U: return "ARM";
            case 0x01C4U: return "ARM Thumb-2";
            case 0xAA64U: return "ARM64";
            case 0x0200U: return "IA-64";
            default: return "Unknown";
            }
        }

        const char* PeSubsystemName(const std::uint16_t subsystem)
        {
            switch (subsystem)
            {
            case 1: return "Native";
            case 2: return "Windows GUI";
            case 3: return "Windows Console";
            case 7: return "POSIX Console";
            case 9: return "Windows CE GUI";
            case 10: return "EFI Application";
            case 11: return "EFI Boot Driver";
            case 12: return "EFI Runtime Driver";
            case 13: return "EFI ROM";
            case 14: return "Xbox";
            case 16: return "Windows Boot Application";
            default: return "Unknown";
            }
        }

        std::string FormatEntropy(const double value)
        {
            std::ostringstream stream;
            stream << std::fixed << std::setprecision(4) << value;
            return stream.str();
        }

        bool ReadWholeFile(
            const std::wstring& filePath,
            const ScanOptions& options,
            std::vector<std::uint8_t>& bytesOut,
            BinaryScanResult& result)
        {
            bytesOut.clear();
            HANDLE fileHandle = ::CreateFileW(
                filePath.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                const DWORD error = ::GetLastError();
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.open_failed",
                    "CreateFileW failed with error " + Decimal(error) + ".");
                return false;
            }

            BY_HANDLE_FILE_INFORMATION information{};
            if (::GetFileInformationByHandle(fileHandle, &information) == FALSE)
            {
                const DWORD error = ::GetLastError();
                ::CloseHandle(fileHandle);
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.info_failed",
                    "GetFileInformationByHandle failed with error " + Decimal(error) + ".");
                return false;
            }
            if ((information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                ::CloseHandle(fileHandle);
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.not_ordinary",
                    "The selected path is a directory, not an ordinary file.");
                return false;
            }

            LARGE_INTEGER fileSize{};
            if (::GetFileSizeEx(fileHandle, &fileSize) == FALSE ||
                fileSize.QuadPart < 0)
            {
                const DWORD error = ::GetLastError();
                ::CloseHandle(fileHandle);
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.size_failed",
                    "GetFileSizeEx failed with error " + Decimal(error) + ".");
                return false;
            }
            result.fileSize = static_cast<std::uint64_t>(fileSize.QuadPart);
            if (result.fileSize > options.maxFileBytes ||
                result.fileSize > static_cast<std::uint64_t>(
                    std::numeric_limits<std::size_t>::max()))
            {
                ::CloseHandle(fileHandle);
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.too_large",
                    "The file exceeds ScanOptions.maxFileBytes.");
                return false;
            }

            try
            {
                bytesOut.assign(static_cast<std::size_t>(result.fileSize), 0);
            }
            catch (const std::bad_alloc&)
            {
                ::CloseHandle(fileHandle);
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.allocation_failed",
                    "Memory allocation for the input file failed.");
                return false;
            }

            std::size_t totalRead = 0;
            while (totalRead < bytesOut.size())
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                    bytesOut.size() - totalRead,
                    1024U * 1024U));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        fileHandle,
                        bytesOut.data() + totalRead,
                        requested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    const DWORD error = ::GetLastError();
                    ::CloseHandle(fileHandle);
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Error,
                        "file.read_failed",
                        "ReadFile failed with error " + Decimal(error) + ".");
                    return false;
                }
                if (bytesRead == 0)
                {
                    ::CloseHandle(fileHandle);
                    bytesOut.clear();
                    AddDiagnostic(
                        result,
                        DiagnosticSeverity::Error,
                        "file.short_read",
                        "The file changed or became shorter while it was being read.");
                    return false;
                }
                totalRead += bytesRead;
            }

            // A second complete pass rejects mixed snapshots, including most
            // changes made through a writable mapping that predates our
            // non-write-shared handle. A tiny final verification-to-close race is
            // an unavoidable Win32 boundary and is documented by this API.
            LARGE_INTEGER verifiedSize{};
            DWORD verificationError = ERROR_SUCCESS;
            if (::GetFileSizeEx(fileHandle, &verifiedSize) == FALSE)
            {
                verificationError = ::GetLastError();
            }
            else if (verifiedSize.QuadPart != fileSize.QuadPart)
            {
                verificationError = ERROR_REVISION_MISMATCH;
            }
            else
            {
                LARGE_INTEGER beginning{};
                if (::SetFilePointerEx(
                        fileHandle,
                        beginning,
                        nullptr,
                        FILE_BEGIN) == FALSE)
                {
                    verificationError = ::GetLastError();
                }
            }

            std::vector<std::uint8_t> verificationBuffer(1024U * 1024U);
            std::size_t verifiedBytes = 0;
            while (verificationError == ERROR_SUCCESS &&
                verifiedBytes < bytesOut.size())
            {
                const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(
                    bytesOut.size() - verifiedBytes,
                    verificationBuffer.size()));
                DWORD bytesRead = 0;
                if (::ReadFile(
                        fileHandle,
                        verificationBuffer.data(),
                        requested,
                        &bytesRead,
                        nullptr) == FALSE)
                {
                    verificationError = ::GetLastError();
                    break;
                }
                if (bytesRead != requested ||
                    !std::equal(
                        verificationBuffer.begin(),
                        verificationBuffer.begin() + bytesRead,
                        bytesOut.begin() + verifiedBytes))
                {
                    verificationError = ERROR_REVISION_MISMATCH;
                    break;
                }
                verifiedBytes += bytesRead;
            }
            ::CloseHandle(fileHandle);
            if (verificationError != ERROR_SUCCESS)
            {
                bytesOut.clear();
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "file.changed_during_read",
                    "The file changed while the scanner was building a stable snapshot.");
                return false;
            }
            return true;
        }

        bool ReadPeSupplementLayout(
            const EndianReader& reader,
            std::uint32_t& exportRvaOut,
            std::uint32_t& exportSizeOut,
            std::uint32_t& sizeOfHeadersOut,
            std::vector<PeSectionMap>& sectionsOut)
        {
            std::uint32_t ntOffset = 0;
            if (!reader.readU32(0x3C, ntOffset))
            {
                return false;
            }
            std::uint32_t signature = 0;
            std::uint16_t sectionCount = 0;
            std::uint16_t optionalSize = 0;
            const std::uint64_t fileHeaderOffset =
                static_cast<std::uint64_t>(ntOffset) + 4U;
            if (!reader.readU32(ntOffset, signature) ||
                signature != 0x00004550U ||
                !reader.readU16(fileHeaderOffset + 2, sectionCount) ||
                !reader.readU16(fileHeaderOffset + 16, optionalSize))
            {
                return false;
            }
            const std::uint64_t optionalOffset = fileHeaderOffset + 20U;
            std::uint16_t optionalMagic = 0;
            if (!reader.readU16(optionalOffset, optionalMagic) ||
                !reader.readU32(optionalOffset + 60, sizeOfHeadersOut))
            {
                return false;
            }

            std::uint64_t directoryCountOffset = 0;
            std::uint64_t directoryOffset = 0;
            if (optionalMagic == 0x10BU)
            {
                directoryCountOffset = optionalOffset + 92U;
                directoryOffset = optionalOffset + 96U;
            }
            else if (optionalMagic == 0x20BU)
            {
                directoryCountOffset = optionalOffset + 108U;
                directoryOffset = optionalOffset + 112U;
            }
            else
            {
                return false;
            }

            std::uint32_t directoryCount = 0;
            if (!reader.readU32(directoryCountOffset, directoryCount))
            {
                return false;
            }
            exportRvaOut = 0;
            exportSizeOut = 0;
            if (directoryCount > 0 &&
                !reader.readU32(directoryOffset, exportRvaOut))
            {
                return false;
            }
            if (directoryCount > 0 &&
                !reader.readU32(directoryOffset + 4, exportSizeOut))
            {
                return false;
            }

            const std::uint64_t sectionTableOffset = optionalOffset + optionalSize;
            sectionsOut.clear();
            sectionsOut.reserve(sectionCount);
            for (std::uint16_t index = 0; index < sectionCount; ++index)
            {
                const std::uint64_t offset =
                    sectionTableOffset + static_cast<std::uint64_t>(index) * 40U;
                PeSectionMap section{};
                if (!reader.readU32(offset + 8, section.virtualSize) ||
                    !reader.readU32(offset + 12, section.virtualAddress) ||
                    !reader.readU32(offset + 16, section.rawSize) ||
                    !reader.readU32(offset + 20, section.rawOffset))
                {
                    return false;
                }
                sectionsOut.push_back(section);
            }
            return true;
        }

        bool PeRvaToOffset(
            const EndianReader& reader,
            const std::uint32_t rva,
            const std::uint32_t sizeOfHeaders,
            const std::vector<PeSectionMap>& sections,
            std::uint64_t& offsetOut)
        {
            for (const PeSectionMap& section : sections)
            {
                const std::uint64_t start = section.virtualAddress;
                const std::uint64_t span = std::max(
                    section.virtualSize,
                    section.rawSize);
                const std::uint64_t end = start + span;
                if (span != 0 &&
                    static_cast<std::uint64_t>(rva) >= start &&
                    static_cast<std::uint64_t>(rva) < end)
                {
                    const std::uint64_t delta =
                        static_cast<std::uint64_t>(rva) - start;
                    if (delta >= section.rawSize)
                    {
                        // VirtualSize may include zero-fill bytes that have no
                        // file representation; never map them into later data.
                        return false;
                    }
                    const std::uint64_t candidate =
                        static_cast<std::uint64_t>(section.rawOffset) + delta;
                    const std::uint64_t rawEnd =
                        static_cast<std::uint64_t>(section.rawOffset) +
                        section.rawSize;
                    if (candidate >= rawEnd || !reader.contains(candidate, 1))
                    {
                        return false;
                    }
                    offsetOut = candidate;
                    return true;
                }
            }
            if (rva < sizeOfHeaders && reader.contains(rva, 1))
            {
                offsetOut = rva;
                return true;
            }
            return false;
        }

        std::string ReadPeString(
            const EndianReader& reader,
            const std::uint32_t rva,
            const std::uint32_t sizeOfHeaders,
            const std::vector<PeSectionMap>& sections,
            const ScanOptions& options)
        {
            std::uint64_t offset = 0;
            if (!PeRvaToOffset(reader, rva, sizeOfHeaders, sections, offset))
            {
                return {};
            }
            return reader.cString(
                offset,
                reader.size(),
                options.maxStringBytes);
        }

        void AppendPeExports(
            const std::span<const std::uint8_t> bytes,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            BinaryTable exports{
                "exports",
                "Exports",
                { "Ordinal", "Name", "RVA", "Forwarder" },
                {},
                false
            };
            const EndianReader reader(bytes, ByteOrder::LittleEndian);
            std::uint32_t exportRva = 0;
            std::uint32_t exportSize = 0;
            std::uint32_t sizeOfHeaders = 0;
            std::vector<PeSectionMap> sections;
            if (!ReadPeSupplementLayout(
                    reader,
                    exportRva,
                    exportSize,
                    sizeOfHeaders,
                    sections))
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Warning,
                    "pe.export_layout_unavailable",
                    "PE export supplement could not read the validated header layout.");
                result.tables.push_back(std::move(exports));
                return;
            }
            if (exportRva == 0 || exportSize == 0)
            {
                result.tables.push_back(std::move(exports));
                return;
            }

            std::uint64_t exportOffset = 0;
            if (!PeRvaToOffset(
                    reader,
                    exportRva,
                    sizeOfHeaders,
                    sections,
                    exportOffset) ||
                !reader.contains(exportOffset, 40))
            {
                AddDiagnosticAt(
                    result,
                    DiagnosticSeverity::Warning,
                    "pe.export_directory_invalid",
                    "PE export directory is outside the file.",
                    exportOffset);
                result.tables.push_back(std::move(exports));
                return;
            }

            std::uint32_t dllNameRva = 0;
            std::uint32_t ordinalBase = 0;
            std::uint32_t functionCount = 0;
            std::uint32_t nameCount = 0;
            std::uint32_t functionsRva = 0;
            std::uint32_t namesRva = 0;
            std::uint32_t ordinalsRva = 0;
            if (!reader.readU32(exportOffset + 12, dllNameRva) ||
                !reader.readU32(exportOffset + 16, ordinalBase) ||
                !reader.readU32(exportOffset + 20, functionCount) ||
                !reader.readU32(exportOffset + 24, nameCount) ||
                !reader.readU32(exportOffset + 28, functionsRva) ||
                !reader.readU32(exportOffset + 32, namesRva) ||
                !reader.readU32(exportOffset + 36, ordinalsRva))
            {
                result.tables.push_back(std::move(exports));
                return;
            }

            const std::string moduleName = ReadPeString(
                reader,
                dllNameRva,
                sizeOfHeaders,
                sections,
                options);
            if (!moduleName.empty())
            {
                AddField(result.summary, "Export Module", moduleName);
            }

            const std::uint32_t boundedFunctionCount =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    functionCount,
                    options.maxContainerEntries));
            const std::uint32_t boundedNameCount =
                static_cast<std::uint32_t>(std::min<std::uint64_t>(
                    nameCount,
                    options.maxContainerEntries));
            if (boundedFunctionCount != functionCount ||
                boundedNameCount != nameCount)
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Warning,
                    "pe.export_count_limited",
                    "PE export counts exceeded maxContainerEntries.");
            }

            std::uint64_t functionsOffset = 0;
            std::uint64_t namesOffset = 0;
            std::uint64_t ordinalsOffset = 0;
            if ((boundedFunctionCount != 0 &&
                    (!PeRvaToOffset(reader, functionsRva, sizeOfHeaders, sections, functionsOffset) ||
                     !reader.contains(functionsOffset, static_cast<std::uint64_t>(boundedFunctionCount) * 4U))) ||
                (boundedNameCount != 0 &&
                    (!PeRvaToOffset(reader, namesRva, sizeOfHeaders, sections, namesOffset) ||
                     !PeRvaToOffset(reader, ordinalsRva, sizeOfHeaders, sections, ordinalsOffset) ||
                     !reader.contains(namesOffset, static_cast<std::uint64_t>(boundedNameCount) * 4U) ||
                     !reader.contains(ordinalsOffset, static_cast<std::uint64_t>(boundedNameCount) * 2U))))
            {
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Warning,
                    "pe.export_arrays_invalid",
                    "One or more PE export arrays are outside the file.");
                result.tables.push_back(std::move(exports));
                return;
            }

            std::vector<std::string> namesByFunction(boundedFunctionCount);
            for (std::uint32_t index = 0; index < boundedNameCount; ++index)
            {
                std::uint32_t nameRva = 0;
                std::uint16_t ordinalIndex = 0;
                if (!reader.readU32(namesOffset + static_cast<std::uint64_t>(index) * 4U, nameRva) ||
                    !reader.readU16(ordinalsOffset + static_cast<std::uint64_t>(index) * 2U, ordinalIndex))
                {
                    break;
                }
                if (ordinalIndex < namesByFunction.size())
                {
                    namesByFunction[ordinalIndex] = ReadPeString(
                        reader,
                        nameRva,
                        sizeOfHeaders,
                        sections,
                        options);
                }
            }

            const std::uint64_t exportEnd =
                static_cast<std::uint64_t>(exportRva) + exportSize;
            for (std::uint32_t index = 0; index < boundedFunctionCount; ++index)
            {
                std::uint32_t functionRva = 0;
                if (!reader.readU32(
                        functionsOffset + static_cast<std::uint64_t>(index) * 4U,
                        functionRva))
                {
                    break;
                }
                if (functionRva == 0)
                {
                    continue;
                }
                std::string forwarder;
                if (functionRva >= exportRva &&
                    static_cast<std::uint64_t>(functionRva) < exportEnd)
                {
                    forwarder = ReadPeString(
                        reader,
                        functionRva,
                        sizeOfHeaders,
                        sections,
                        options);
                }
                AppendRow(
                    exports,
                    {
                        Decimal(static_cast<std::uint64_t>(ordinalBase) + index),
                        namesByFunction[index],
                        Hex(functionRva),
                        forwarder
                    },
                    options);
            }
            result.tables.push_back(std::move(exports));
        }

        bool ParsePe(
            const std::vector<std::uint8_t>& bytes,
            const ScanOptions& options,
            BinaryScanResult& result)
        {
            result.recognized = true;
            result.byteOrder = ByteOrder::LittleEndian;
            // Analyze the exact already-bounded snapshot instead of reopening the
            // path, so detection, PE adaptation, and export supplement cannot see
            // different file revisions.
            const ks::file::PeAnalysisResult pe = ks::file::AnalyzePeBytes(bytes);
            if (!pe.success)
            {
                result.format = BinaryFormat::Unknown;
                AddDiagnostic(
                    result,
                    DiagnosticSeverity::Error,
                    "pe.analysis_failed",
                    WideToUtf8(pe.reportText));
                return false;
            }

            result.format = pe.isPe64
                ? BinaryFormat::Pe32Plus
                : BinaryFormat::Pe32;
            AddField(result.summary, "Format", pe.isPe64 ? "PE32+" : "PE32");
            AddField(result.summary, "Byte Order", "Little-endian");
            AddField(result.summary, "Architecture", PeMachineName(pe.machine));
            AddField(result.summary, "Entry Point RVA", Hex(pe.entryPointRva));
            if (pe.entryPointFileOffsetValid)
            {
                AddField(result.summary, "Entry Point File Offset", Hex(pe.entryPointFileOffset));
            }
            AddField(result.summary, "Image Base", Hex(pe.imageBase));
            AddField(result.summary, "Sections", Decimal(pe.sections.size()));
            AddField(result.summary, "Import Modules", Decimal(pe.importModules.size()));

            AddField(result.headers, "Machine", std::string(PeMachineName(pe.machine)) + " (" + Hex(pe.machine) + ")");
            AddField(result.headers, "Subsystem", std::string(PeSubsystemName(pe.subsystem)) + " (" + Hex(pe.subsystem) + ")");
            AddField(result.headers, "Entry Point RVA", Hex(pe.entryPointRva));
            if (pe.entryPointFileOffsetValid)
            {
                AddField(result.headers, "Entry Point File Offset", Hex(pe.entryPointFileOffset));
            }
            AddField(result.headers, "Image Base", Hex(pe.imageBase));

            result.imageBase = pe.imageBase;
            result.entryPointRva = pe.entryPointRva;
            result.entryPointFileOffset = pe.entryPointFileOffset;
            result.entryPointFileOffsetValid = pe.entryPointFileOffsetValid;
            result.x86Compatible = pe.machine == 0x014CU || pe.machine == 0x8664U;
            result.is64Bit = pe.isPe64;
            const EndianReader layoutReader(std::span<const std::uint8_t>(bytes), ByteOrder::LittleEndian);
            std::uint32_t ntOffset = 0;
            std::uint32_t headerBytes = 0;
            std::uint32_t resourceRva = 0;
            if (layoutReader.readU32(0x3C, ntOffset))
            {
                const auto optionalOffset = static_cast<std::uint64_t>(ntOffset) + 24U;
                if (!layoutReader.readU32(optionalOffset + 60U, headerBytes)) headerBytes = 0;
                std::uint32_t directoryCount = 0;
                if (layoutReader.readU32(optionalOffset + (pe.isPe64 ? 108U : 92U), directoryCount) && directoryCount > 2)
                    if (!layoutReader.readU32(optionalOffset + (pe.isPe64 ? 112U : 96U) + 16U, resourceRva)) resourceRva = 0;
            }
            const auto physicalHeaderBytes = std::min<std::uint64_t>(headerBytes, bytes.size());
            result.mappedRegions.push_back(BinaryMappedRegion{
                "Headers", 0, physicalHeaderBytes, 0, headerBytes, 0, 0.0,
                true, BinaryRegionKind::Headers });
            std::uint64_t lastPhysicalByte = physicalHeaderBytes;
            for (const auto& section : pe.sections)
            {
                const auto physicalSize = section.rawOffset <= bytes.size()
                    ? std::min<std::uint64_t>(section.rawSize, bytes.size() - section.rawOffset)
                    : 0;
                const bool containsResources = resourceRva != 0 && resourceRva >= section.virtualAddress &&
                    static_cast<std::uint64_t>(resourceRva) - section.virtualAddress <
                        std::max(section.virtualSize, section.rawSize);
                const auto kind = containsResources || section.name == ".rsrc"
                    ? BinaryRegionKind::Resources
                    : (section.characteristics & 0x20000000U) != 0
                        ? BinaryRegionKind::Code : BinaryRegionKind::Data;
                result.mappedRegions.push_back(BinaryMappedRegion{
                    section.name, section.rawOffset, physicalSize, section.virtualAddress,
                    section.virtualSize, section.characteristics, section.entropy, true, kind });
                if (physicalSize != 0) lastPhysicalByte = std::max(lastPhysicalByte,
                    static_cast<std::uint64_t>(section.rawOffset) + physicalSize);
            }
            if (lastPhysicalByte < bytes.size())
            {
                result.mappedRegions.push_back(BinaryMappedRegion{
                    "Overlay", lastPhysicalByte, bytes.size() - lastPhysicalByte,
                    0, 0, 0, 0.0, false, BinaryRegionKind::Overlay });
            }
            const auto mappedEntry = RvaToFileOffset(result, result.entryPointRva);
            result.entryPointFileOffsetValid = mappedEntry.has_value();
            if (mappedEntry) result.entryPointFileOffset = *mappedEntry;

            BinaryTable sections{
                "sections",
                "Sections",
                { "Name", "Virtual Address", "Virtual Size", "Raw Offset",
                  "Raw Size", "Characteristics", "Entropy" },
                {},
                false
            };
            for (const ks::file::PeSectionSummary& section : pe.sections)
            {
                AppendRow(
                    sections,
                    {
                        section.name,
                        Hex(section.virtualAddress),
                        Hex(section.virtualSize),
                        Hex(section.rawOffset),
                        Hex(section.rawSize),
                        Hex(section.characteristics),
                        FormatEntropy(section.entropy)
                    },
                    options);
            }
            result.tables.push_back(std::move(sections));

            BinaryTable imports{
                "imports",
                "Imports",
                { "Module", "Function", "Hint", "Ordinal", "Import Kind",
                  "Thunk RVA", "Diagnostic" },
                {},
                false
            };
            for (const ks::file::PeImportModuleSummary& module : pe.importModules)
            {
                if (module.imports.empty())
                {
                    AppendRow(
                        imports,
                        {
                            module.dllName,
                            {},
                            {},
                            {},
                            {},
                            {},
                            module.diagnosticText
                        },
                        options);
                    continue;
                }
                for (const ks::file::PeImportFunctionSummary& function : module.imports)
                {
                    if (!AppendRow(
                            imports,
                            {
                                module.dllName,
                                function.functionName,
                                Decimal(function.hint),
                                Decimal(function.ordinal),
                                function.importByOrdinal ? "Ordinal" : "Name",
                                Hex(function.thunkRva),
                                module.diagnosticText
                            },
                            options))
                    {
                        break;
                    }
                }
            }
            result.tables.push_back(std::move(imports));
            AppendPeExports(std::span<const std::uint8_t>(bytes), options, result);
            // 攻击路径检测复用同一稳定快照，不重新打开文件，也不会调用 PE 入口点。
            detail::DetectAttackPathInPe(
                std::span<const std::uint8_t>(bytes),
                "<selected-file>",
                0,
                options,
                result);
            result.success = true;
            return true;
        }

        bool LooksLikeMachO(const std::span<const std::uint8_t> bytes)
        {
            if (bytes.size() < 4)
            {
                return false;
            }
            const std::uint32_t prefix =
                (static_cast<std::uint32_t>(bytes[0]) << 24U) |
                (static_cast<std::uint32_t>(bytes[1]) << 16U) |
                (static_cast<std::uint32_t>(bytes[2]) << 8U) |
                static_cast<std::uint32_t>(bytes[3]);
            switch (prefix)
            {
            case 0xCEFAEDFEU:
            case 0xFEEDFACEU:
            case 0xCFFAEDFEU:
            case 0xFEEDFACFU:
            case 0xCAFEBABEU:
            case 0xBEBAFECAU:
            case 0xCAFEBABFU:
            case 0xBFBAFECAU:
                return true;
            default:
                return false;
            }
        }

        // ISO9660 卷描述符固定从 2048 字节扇区 16 开始；这里只做分派魔数检查。
        bool LooksLikeIso9660(const std::span<const std::uint8_t> bytes)
        {
            constexpr std::size_t descriptorOffset = 16U * 2048U;
            constexpr std::size_t signatureOffset = descriptorOffset + 1U;
            return bytes.size() >= descriptorOffset + 7U &&
                bytes[signatureOffset] == 'C' &&
                bytes[signatureOffset + 1U] == 'D' &&
                bytes[signatureOffset + 2U] == '0' &&
                bytes[signatureOffset + 3U] == '0' &&
                bytes[signatureOffset + 4U] == '1' &&
                bytes[descriptorOffset + 6U] == 1U;
        }
    }

    BinaryScanResult ScanBinaryFile(
        const std::wstring& filePath,
        const ScanOptions& options)
    {
        BinaryScanResult result{};
        if (filePath.empty())
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "file.path_empty",
                "The file path is empty.");
            return result;
        }
        if (options.maxFileBytes == 0 ||
            options.maxRowsPerTable == 0 ||
            options.maxStringBytes == 0 ||
            options.maxContainerEntries == 0)
        {
            AddDiagnostic(
                result,
                DiagnosticSeverity::Error,
                "options.invalid",
                "All ScanOptions limits must be greater than zero.");
            return result;
        }

        // The retained UI snapshot and every parser share the same verified
        // allocation. Large files are not copied into a second GUI buffer.
        auto bytesOwner = std::make_shared<std::vector<std::uint8_t>>();
        auto& bytes = *bytesOwner;
        if (!ReadWholeFile(filePath, options, bytes, result))
        {
            return result;
        }
        AddField(result.summary, "File Size", Decimal(result.fileSize));
        if (options.retainInputSnapshot) result.inputSnapshot = bytesOwner;

        const std::span<const std::uint8_t> view(bytes);
        if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z')
        {
            ParsePe(bytes, options, result);
            return result;
        }
        if (bytes.size() >= 4 &&
            bytes[0] == 0x7FU &&
            bytes[1] == 'E' &&
            bytes[2] == 'L' &&
            bytes[3] == 'F')
        {
            detail::ParseElf(view, options, result);
            return result;
        }
        if (LooksLikeMachO(view))
        {
            detail::ParseMachO(view, options, result);
            return result;
        }
        if (LooksLikeIso9660(view))
        {
            detail::ParseIso9660(view, options, result);
            return result;
        }

        AddDiagnostic(
            result,
            DiagnosticSeverity::Information,
            "format.unsupported",
            "The file is not PE, ELF, Mach-O, or ISO9660.");
        return result;
    }

    const char* FormatName(const BinaryFormat format)
    {
        switch (format)
        {
        case BinaryFormat::Pe32: return "PE32";
        case BinaryFormat::Pe32Plus: return "PE32+";
        case BinaryFormat::Elf32: return "ELF32";
        case BinaryFormat::Elf64: return "ELF64";
        case BinaryFormat::MachO32: return "Mach-O 32";
        case BinaryFormat::MachO64: return "Mach-O 64";
        case BinaryFormat::MachOUniversal: return "Universal Mach-O";
        case BinaryFormat::Iso9660: return "ISO9660";
        case BinaryFormat::Unknown:
        default:
            return "Unknown";
        }
    }

    const char* ByteOrderName(const ByteOrder byteOrder)
    {
        switch (byteOrder)
        {
        case ByteOrder::LittleEndian: return "Little-endian";
        case ByteOrder::BigEndian: return "Big-endian";
        case ByteOrder::BothEndian: return "Both-endian";
        case ByteOrder::Unknown:
        default:
            return "Unknown";
        }
    }
}
