#pragma once

// ============================================================
// ksword/file/pe_analyzer.h
// 命名空间：ks::file
// 作用：
// - 提供不依赖 Qt 的 PE 基础解析能力；
// - 解析 PE 头、节表、导入/导出、数据目录和常用目录摘要；
// - 返回不依赖报告文本的原生字段模型，同时保留可读报告导出。
// ============================================================

#include <cstdint>
#include <string>
#include <vector>

namespace ks::file
{
    // Native analysis entries are emitted while reading PE structures. They are
    // the source for both the property model and the optional text export.
    struct PeReportEntry
    {
        enum class Kind { Section, Field, Note };
        Kind kind = Kind::Field;
        std::wstring name;
        std::wstring value;
        std::uint32_t depth = 0;
    };

    // PeSectionSummary 作用：
    // - 保存区段表中 UI/日志常用字段；
    // - analyzePeFile 可用于后续非文本化展示。
    struct PeSectionSummary
    {
        std::string name;
        std::uint32_t virtualAddress = 0;
        std::uint32_t virtualSize = 0;
        std::uint32_t rawOffset = 0;
        std::uint32_t rawSize = 0;
        std::uint32_t characteristics = 0;
        double entropy = 0.0;
    };

    // PeImportFunctionSummary 作用：
    // - 保存单个导入函数的结构化信息；
    // - UI 可直接使用该结构填充“依赖 DLL”表格，不需要从文本报告反向解析。
    struct PeImportFunctionSummary
    {
        std::string dllName;             // dllName：所属导入 DLL 名称。
        std::string functionName;        // functionName：按名称导入时的函数名；按序号导入时为空。
        std::uint16_t hint = 0;          // hint：IMAGE_IMPORT_BY_NAME.Hint；按序号导入时为 0。
        std::uint16_t ordinal = 0;       // ordinal：按序号导入时的 ordinal；按名称导入时为 0。
        std::uint32_t thunkRva = 0;      // thunkRva：当前 thunk/IAT 项的 RVA，便于定位。
        bool importByOrdinal = false;    // importByOrdinal：true=Ordinal 导入；false=名称导入。
    };

    // PeImportModuleSummary 作用：
    // - 保存一个 IMAGE_IMPORT_DESCRIPTOR 对应的 DLL 及其函数列表；
    // - descriptorIndex 用于展示与损坏导入表诊断。
    struct PeImportModuleSummary
    {
        std::string dllName;                         // dllName：导入描述符指向的 DLL 名称。
        std::uint32_t descriptorIndex = 0;           // descriptorIndex：导入描述符序号。
        std::vector<PeImportFunctionSummary> imports; // imports：该 DLL 下解析出的导入函数。
        std::string diagnosticText;                  // diagnosticText：局部解析失败或截断说明。
    };

    // PeAnalysisResult 作用：
    // - 聚合原生字段、节表与导入摘要，并保留兼容报告导出；
    // - success=false 时 errorText 与 Note 保存可读失败原因。
    struct PeAnalysisResult
    {
        bool success = false;
        bool isPe64 = false;
        std::uint16_t machine = 0;
        std::uint16_t subsystem = 0;
        std::uint32_t entryPointRva = 0;
        std::uint32_t entryPointFileOffset = 0;
        bool entryPointFileOffsetValid = false;
        std::uint64_t imageBase = 0;
        std::vector<PeSectionSummary> sections;
        std::vector<PeImportModuleSummary> importModules;
        std::vector<PeReportEntry> entries;
        std::wstring errorText;
        std::wstring reportText;
    };

    // AnalyzePeFile 作用：读取文件并解析 PE 结构，返回结构化结果与报告文本。
    PeAnalysisResult AnalyzePeFile(const std::wstring& filePath);

    // AnalyzePeBytes 作用：直接解析来自原始磁盘、内存快照或其它证据源的 PE 字节。
    PeAnalysisResult AnalyzePeBytes(
        const std::vector<std::uint8_t>& fileBytes);

    // BuildPeAnalysisText 作用：兼容属性窗口现有“直接拿文本显示”的调用方式。
    std::wstring BuildPeAnalysisText(const std::wstring& filePath);

    // BuildPeAnalysisText 作用：返回内存 PE 字节的可读分析报告。
    std::wstring BuildPeAnalysisText(
        const std::vector<std::uint8_t>& fileBytes);

    // BuildPeAnalysisTextUtf8 作用：便于非 Qt 调用者传入 UTF-8 文件路径并获得 UTF-8 报告。
    std::string BuildPeAnalysisTextUtf8(const std::string& filePathUtf8);
}
