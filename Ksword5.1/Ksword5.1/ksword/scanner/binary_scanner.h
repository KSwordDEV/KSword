#pragma once

// ============================================================
// ksword/scanner/binary_scanner.h
// Namespace: ks::scanner
// Purpose:
// - Define a Qt-free, format-neutral model for binary inspection.
// - Scan PE32/PE32+, ELF32/ELF64, Mach-O, and ISO9660/Joliet images.
// - Return bounded key/value and tabular data that UI, CLI, or tests can render.
//
// Security boundary:
// - Callers provide limits through ScanOptions.
// - Parsers never return borrowed pointers into the input file.
// - File loading denies new writers/deletes and verifies a second full read before
//   parsing, rejecting mixed snapshots instead of silently accepting a short read.
// - A writable mapping created before the scanner opens the file remains an OS
//   boundary; callers should rescan files that are actively mapped by another tool.
// - A recognized but malformed file returns recognized=true, success=false.
// ============================================================

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ks::scanner
{
    // BinaryFormat identifies the exact container/class combination discovered
    // from the on-disk magic and format header.
    enum class BinaryFormat
    {
        Unknown = 0,
        Pe32,
        Pe32Plus,
        Elf32,
        Elf64,
        MachO32,
        MachO64,
        MachOUniversal,
        Iso9660
    };

    // ByteOrder describes how multi-byte fields in the selected object are stored.
    // BothEndian is used for ISO9660 fields that carry paired LE/BE copies.
    enum class ByteOrder
    {
        Unknown = 0,
        LittleEndian,
        BigEndian,
        BothEndian
    };

    // DiagnosticSeverity lets frontends distinguish recoverable truncation from a
    // fatal parse rejection without interpreting localized text.
    enum class DiagnosticSeverity
    {
        Information = 0,
        Warning,
        Error
    };

    // BinaryField is used for summary and header key/value collections.
    struct BinaryField
    {
        std::string name;
        std::string value;
    };

    // BinaryTable is a format-neutral rectangular result set.
    // Every row is normalized to columns.size() cells by the parser.
    struct BinaryTable
    {
        std::string id;                         // Stable ASCII identifier for callers.
        std::string title;                      // Human-readable English title.
        std::vector<std::string> columns;
        std::vector<std::vector<std::string>> rows;
        bool truncated = false;                // True when ScanOptions.maxRowsPerTable was reached.
    };

    // BinaryDiagnostic records parser observations with an optional byte offset.
    // hasOffset=false is used for whole-file or adapter errors.
    struct BinaryDiagnostic
    {
        DiagnosticSeverity severity = DiagnosticSeverity::Information;
        std::string code;                       // Stable machine-readable identifier.
        std::string message;
        bool hasOffset = false;
        std::uint64_t offset = 0;
    };

    // AttackPathSeverity 作用：表达攻击链证据对最终判定的影响等级。
    // 该枚举与解析错误级别分离，避免把“文件损坏”误当成“恶意行为”。
    enum class AttackPathSeverity
    {
        Information = 0,
        Suspicious,
        High,
        Critical
    };

    // AttackPathEvidence 作用：保存一条可独立复核的静态证据。
    // code/stage 使用稳定 ASCII 标识，UI 根据标识本地化说明文本。
    struct AttackPathEvidence
    {
        std::string code;
        std::string stage;
        std::string artifact;
        std::string mitreTechnique;
        AttackPathSeverity severity = AttackPathSeverity::Information;
        std::uint32_t score = 0;
        bool hasOffset = false;
        std::uint64_t offset = 0;
    };

    // AttackPathDetection 作用：聚合多阶段证据并给出有上限的规则评分。
    // matched 只在满足规则阈值与关键行为组合时置位，不以单一哈希定性。
    struct AttackPathDetection
    {
        bool matched = false;
        std::uint32_t score = 0;
        std::string ruleId;
        std::string family;
        std::vector<AttackPathEvidence> evidence;
    };

    // ScanOptions bounds memory usage, entry walks, and strings from hostile files.
    // Values are intentionally conservative for an interactive desktop application.
    struct ScanOptions
    {
        std::uint64_t maxFileBytes = 512ULL * 1024ULL * 1024ULL;
        std::size_t maxRowsPerTable = 10000;
        std::size_t maxStringBytes = 4096;
        std::size_t maxContainerEntries = 65536;
        // Interactive viewers retain the exact verified input, without a second
        // file read or a second whole-file allocation. Other callers opt out.
        bool retainInputSnapshot = false;
    };

    enum class BinaryRegionKind { Headers, Code, Data, Resources, Unmapped, Overlay };

    // All file intervals are half-open and clipped to captured physical bytes.
    // virtualSize also describes zero-fill, which never supplies file bytes.
    struct BinaryMappedRegion
    {
        std::string name;
        std::uint64_t fileOffset = 0;
        std::uint64_t fileSize = 0;
        std::uint64_t rva = 0;
        std::uint64_t virtualSize = 0;
        std::uint32_t characteristics = 0;
        double entropy = 0.0;
        bool mapped = false;
        BinaryRegionKind kind = BinaryRegionKind::Unmapped;
    };

    // BinaryScanResult is the complete scanner response.
    // recognized says the magic is supported; success says its required header and
    // primary table layout passed validation. Warnings can coexist with success.
    struct BinaryScanResult
    {
        bool recognized = false;
        bool success = false;
        BinaryFormat format = BinaryFormat::Unknown;
        ByteOrder byteOrder = ByteOrder::Unknown;
        std::uint64_t fileSize = 0;
        std::vector<BinaryField> summary;
        std::vector<BinaryField> headers;
        std::vector<BinaryTable> tables;
        std::vector<BinaryDiagnostic> diagnostics;
        AttackPathDetection attackPath;
        std::shared_ptr<const std::vector<std::uint8_t>> inputSnapshot;
        std::vector<BinaryMappedRegion> mappedRegions;
        std::uint64_t imageBase = 0;
        std::uint64_t entryPointRva = 0;
        std::uint64_t entryPointFileOffset = 0;
        bool entryPointFileOffsetValid = false;
        bool x86Compatible = false;
        bool is64Bit = true;
    };

    // ScanBinaryFile loads and scans one ordinary file.
    // PE files reuse ks::file::AnalyzePeBytes over the same bounded snapshot for
    // canonical validation, sections, and imports; the scanner adds only
    // format-neutral adaptation and structured exports.
    BinaryScanResult ScanBinaryFile(
        const std::wstring& filePath,
        const ScanOptions& options = ScanOptions{});

    // FormatName and ByteOrderName provide stable ASCII labels for UI/CLI output.
    const char* FormatName(BinaryFormat format);
    const char* ByteOrderName(ByteOrder byteOrder);
}
