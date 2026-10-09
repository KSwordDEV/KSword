#include "../../Ksword5.1/Ksword5.1/ksword/file/pe_analyzer.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace
{
    int checks = 0;
    int failures = 0;
    void Check(bool condition, const char* reason)
    {
        ++checks;
        if (!condition) { ++failures; std::cerr << reason << '\n'; }
    }
    template<class T>
    void Write(std::vector<std::uint8_t>& bytes, std::size_t offset, const T& value)
    {
        std::memcpy(bytes.data() + offset, &value, sizeof(value));
    }
    void WriteString(std::vector<std::uint8_t>& bytes, std::size_t offset, const char* value)
    {
        std::memcpy(bytes.data() + offset, value, std::strlen(value) + 1);
    }
    std::size_t Raw(std::uint32_t rva) { return rva - 0x1000U + 0x200U; }

    std::vector<std::uint8_t> Fixture(bool pe64, bool directories = true)
    {
        std::vector<std::uint8_t> bytes(0x2000, 0);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE;
        dos.e_lfanew = 0x80;
        Write(bytes, 0, dos);
        const std::uint32_t signature = IMAGE_NT_SIGNATURE;
        Write(bytes, 0x80, signature);
        IMAGE_FILE_HEADER coff{};
        coff.Machine = pe64 ? IMAGE_FILE_MACHINE_AMD64 : IMAGE_FILE_MACHINE_I386;
        coff.NumberOfSections = 1;
        coff.SizeOfOptionalHeader = pe64 ? sizeof(IMAGE_OPTIONAL_HEADER64) : sizeof(IMAGE_OPTIONAL_HEADER32);
        coff.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
        coff.TimeDateStamp = 100;
        Write(bytes, 0x84, coff);
        IMAGE_OPTIONAL_HEADER64 optional{};
        optional.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        optional.ImageBase = 0x140000000ULL;
        optional.AddressOfEntryPoint = 0x1000;
        optional.SizeOfHeaders = 0x200;
        optional.SectionAlignment = 0x1000;
        optional.FileAlignment = 0x200;
        optional.SizeOfImage = 0x3000;
        optional.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
        optional.CheckSum = 0xABCDEFU;
        optional.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        if (directories)
        {
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT] = { 0x1100, 40 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT] = { 0x1200, 0x100 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS] = { 0x1400, 40 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE] = { 0x1500, 24 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC] = { 0x1600, 12 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] = { 0x1700, sizeof(IMAGE_DEBUG_DIRECTORY) };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = { 0x1800, 32 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT] = { 0x1850, 16 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG] = { 0x1900, 64 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR] = { 0x1A00, 72 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY] = { 0x1F00, 16 };
            optional.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION] = { 0x1B00, 12 };
        }
        if (pe64) { Write(bytes, 0x98, optional); }
        else
        {
            IMAGE_OPTIONAL_HEADER32 optional32{};
            optional32.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
            optional32.ImageBase = 0x400000;
            optional32.AddressOfEntryPoint = optional.AddressOfEntryPoint;
            optional32.SizeOfHeaders = optional.SizeOfHeaders;
            optional32.SectionAlignment = optional.SectionAlignment;
            optional32.FileAlignment = optional.FileAlignment;
            optional32.SizeOfImage = optional.SizeOfImage;
            optional32.Subsystem = optional.Subsystem;
            optional32.CheckSum = optional.CheckSum;
            optional32.NumberOfRvaAndSizes = optional.NumberOfRvaAndSizes;
            std::memcpy(optional32.DataDirectory, optional.DataDirectory, sizeof(optional.DataDirectory));
            Write(bytes, 0x98, optional32);
        }
        IMAGE_SECTION_HEADER section{};
        std::memcpy(section.Name, ".test", 5);
        section.VirtualAddress = 0x1000;
        section.Misc.VirtualSize = 0x1E00;
        section.PointerToRawData = 0x200;
        section.SizeOfRawData = 0x1E00;
        section.Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE;
        Write(bytes, 0x98 + coff.SizeOfOptionalHeader, section);
        if (!directories) { return bytes; }

        IMAGE_IMPORT_DESCRIPTOR import{};
        import.Name = 0x1160;
        import.OriginalFirstThunk = import.FirstThunk = 0x1180;
        Write(bytes, Raw(0x1100), import);
        WriteString(bytes, Raw(0x1160), "native.dll");
        if (pe64)
        {
            const std::uint64_t name = 0x11C0;
            const std::uint64_t ordinal = IMAGE_ORDINAL_FLAG64 | 42;
            Write(bytes, Raw(0x1180), name);
            Write(bytes, Raw(0x1180) + 8, ordinal);
        }
        else
        {
            const std::uint32_t name = 0x11C0;
            const std::uint32_t ordinal = IMAGE_ORDINAL_FLAG32 | 42;
            Write(bytes, Raw(0x1180), name);
            Write(bytes, Raw(0x1180) + 4, ordinal);
        }
        const std::uint16_t hint = 7;
        Write(bytes, Raw(0x11C0), hint);
        WriteString(bytes, Raw(0x11C0) + 2, "NativeImport");

        IMAGE_EXPORT_DIRECTORY exports{};
        exports.Base = 5;
        exports.NumberOfFunctions = exports.NumberOfNames = 1;
        exports.Name = 0x12C0;
        exports.AddressOfNames = 0x1260;
        exports.AddressOfFunctions = 0x1280;
        exports.AddressOfNameOrdinals = 0x1290;
        Write(bytes, Raw(0x1200), exports);
        const std::uint32_t exportName = 0x12A0;
        const std::uint32_t forwarder = 0x12E0;
        Write(bytes, Raw(0x1260), exportName);
        Write(bytes, Raw(0x1280), forwarder);
        WriteString(bytes, Raw(0x12A0), "NativeExport");
        WriteString(bytes, Raw(0x12C0), "export.dll");
        WriteString(bytes, Raw(0x12E0), "forward.Target");

        if (pe64)
        {
            IMAGE_TLS_DIRECTORY64 tls{};
            tls.AddressOfCallBacks = optional.ImageBase + 0x1450;
            Write(bytes, Raw(0x1400), tls);
            const std::uint64_t callback = optional.ImageBase + 0x17F0;
            Write(bytes, Raw(0x1450), callback);
        }
        else
        {
            IMAGE_TLS_DIRECTORY32 tls{};
            tls.AddressOfCallBacks = 0x401450;
            Write(bytes, Raw(0x1400), tls);
            const std::uint32_t callback = 0x4017F0;
            Write(bytes, Raw(0x1450), callback);
        }
        IMAGE_RESOURCE_DIRECTORY resource{};
        resource.NumberOfIdEntries = 1;
        Write(bytes, Raw(0x1500), resource);
        IMAGE_RESOURCE_DIRECTORY_ENTRY entry{};
        entry.Id = 16;
        entry.OffsetToData = 0x40;
        Write(bytes, Raw(0x1500) + sizeof(resource), entry);
        IMAGE_BASE_RELOCATION relocation{};
        relocation.VirtualAddress = 0x1000;
        relocation.SizeOfBlock = 12;
        Write(bytes, Raw(0x1600), relocation);
        IMAGE_DEBUG_DIRECTORY debug{};
        debug.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
        debug.SizeOfData = 48;
        debug.PointerToRawData = static_cast<DWORD>(Raw(0x1750));
        Write(bytes, Raw(0x1700), debug);
        WriteString(bytes, Raw(0x1750) + 24, "native.pdb");
        return bytes;
    }

    bool Has(const ks::file::PeAnalysisResult& result, ks::file::PeReportEntry::Kind kind,
        const std::wstring& name, const std::wstring& value = L"", std::uint32_t depth = 0)
    {
        for (const auto& entry : result.entries)
        {
            if (entry.kind == kind && entry.name == name && entry.depth == depth
                && (value.empty() || entry.value == value)) { return true; }
        }
        return false;
    }
}

int main()
{
    using Kind = ks::file::PeReportEntry::Kind;
    for (const bool pe64 : { false, true })
    {
        const auto result = ks::file::AnalyzePeBytes(Fixture(pe64));
        Check(result.success && result.isPe64 == pe64, "PE format");
        Check(result.errorText.empty(), "success has no error");
        for (const auto* section : { L"PE头", L"区段表", L"数据目录", L"导入表", L"导出表",
            L"TLS目录", L"资源目录", L"重定位表", L"调试目录", L"延迟导入表", L"绑定导入表",
            L"Load Config目录", L"CLR/.NET目录", L"安全目录/证书" })
        { Check(Has(result, Kind::Section, section), "directory section retained"); }
        Check(Has(result, Kind::Field, L"CheckSum", L"0xABCDEF"), "optional header field");
        Check(Has(result, Kind::Field, L"PointerToRawData", L"0x200", 1), "section raw offset");
        Check(Has(result, Kind::Field, L"模块", L"native.dll"), "import module");
        Check(Has(result, Kind::Field, L"#0", L"NativeImport", 1), "name import");
        Check(Has(result, Kind::Field, L"Hint", L"7", 2), "name hint nested");
        Check(Has(result, Kind::Field, L"Ordinal", L"42", 2), "ordinal import nested");
        Check(Has(result, Kind::Field, L"[0]", L"NativeExport"), "export name");
        Check(Has(result, Kind::Field, L"Forwarder", L"forward.Target", 1), "export forwarder");
        Check(Has(result, Kind::Field, L"Callback[0] VA"), "TLS callback");
        Check(Has(result, Kind::Field, L"[0]", L"VERSION"), "resource type");
        Check(Has(result, Kind::Field, L"OffsetToData", L"0x40", 1), "resource data offset");
        Check(Has(result, Kind::Field, L"重定位块", L"1"), "relocation block count");
        Check(Has(result, Kind::Field, L"条目估算", L"2"), "relocation entry count");
        Check(Has(result, Kind::Field, L"PDB", L"native.pdb", 1), "debug PDB path");
        Check(Has(result, Kind::Field, L"[3] EXCEPTION"), "exception directory overview");
        const auto exported = ks::file::ExportPeAnalysisText(result);
        Check(exported.find(L"NativeImport") != std::wstring::npos, "export includes model fields");
        auto changed = result;
        changed.entries.clear();
        changed.entries.push_back({ Kind::Field, L"Synthetic", L"model-only", 0 });
        Check(ks::file::ExportPeAnalysisText(changed) == L"Synthetic: model-only\n", "export derives solely from model");
    }
    const auto absent = ks::file::AnalyzePeBytes(Fixture(true, false));
    Check(absent.success, "empty directories remain valid");
    Check(Has(absent, Kind::Note, L"", L"无导入表。"), "empty import explanation");
    Check(Has(absent, Kind::Note, L"", L"无安全目录。"), "empty security explanation");
    const auto invalid = ks::file::AnalyzePeBytes({ 0x00 });
    Check(!invalid.success && invalid.error == ks::file::PeAnalysisError::NotPe && !invalid.errorText.empty(), "invalid file has native error");
    Check(invalid.entries.size() == 1 && invalid.entries[0].kind == Kind::Note,
        "invalid file has typed diagnostic");
    auto bytes = Fixture(true);
    IMAGE_BASE_RELOCATION oversized{};
    oversized.VirtualAddress = 0x1000;
    oversized.SizeOfBlock = UINT32_MAX;
    Write(bytes, Raw(0x1600), oversized);
    const auto malformed = ks::file::AnalyzePeBytes(bytes);
    Check(malformed.success && Has(malformed, Kind::Note, L"", L"重定位块范围超出目录或文件边界。"),
        "oversized relocation terminates with diagnostic");
    bytes = Fixture(true);
    IMAGE_TLS_DIRECTORY64 tls{};
    tls.AddressOfCallBacks = 0x140000000ULL + 0x100001450ULL;
    Write(bytes, Raw(0x1400), tls);
    const auto truncatedTls = ks::file::AnalyzePeBytes(bytes);
    Check(!Has(truncatedTls, Kind::Field, L"Callback[0] VA"), "TLS VA does not wrap into valid RVA");
    bytes = Fixture(true);
    IMAGE_DEBUG_DIRECTORY debug{};
    debug.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
    debug.PointerToRawData = UINT32_MAX - 10;
    Write(bytes, Raw(0x1700), debug);
    WriteString(bytes, 13, "wrapped.pdb");
    const auto truncatedDebug = ks::file::AnalyzePeBytes(bytes);
    Check(!Has(truncatedDebug, Kind::Field, L"PDB", L"", 1), "debug raw offset does not wrap into file");
    bytes = Fixture(true);
    const std::uint64_t oversizedNameRva = 0x1000011C0ULL;
    Write(bytes, Raw(0x1180), oversizedNameRva);
    const auto truncatedImport = ks::file::AnalyzePeBytes(bytes);
    Check(!Has(truncatedImport, Kind::Field, L"#0", L"NativeImport", 1),
        "64 bit import name RVA does not wrap into valid name");
    Check(truncatedImport.importModules.size() == 1
        && !truncatedImport.importModules[0].imports.empty()
        && truncatedImport.importModules[0].imports[0].functionName == "<Name RVA mapping failed>",
        "dependency rows share the 64 bit name RVA check");
    std::cout << "PE native property checks: " << checks << ", failures: " << failures << '\n';
    return failures == 0 ? 0 : 1;
}
