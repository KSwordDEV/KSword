#include "R3FileShared.h"
#include "../shared/usermode/backend/file/PeSnapshot.h"
#include <algorithm>
namespace ks::cli {
namespace {
namespace backend = ks::r3::file;
Json header(const backend::PeHeaderResult& value) {
    return Json::object({{L"available", Json::boolean(value.success)}, {L"win32Error", Json::number(value.errorCode)},
        {L"machine", value.success ? Json::hex(value.machine) : Json{}}, {L"machineName", value.success ? Json::string(backend::PeMachineText(value.machine)) : Json{}},
        {L"sectionCount", value.success ? Json::number(value.sections) : Json{}}, {L"timestamp", value.success ? Json::hex(value.timestamp) : Json{}},
        {L"characteristics", value.success ? Json::hex(value.characteristics) : Json{}}, {L"optionalMagic", value.success ? Json::hex(value.optionalMagic) : Json{}}});
}
Result headerQuery(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto result = backend::ReadPeHeader(path);
    return {result.success ? 0 : result.errorCode == ERROR_BAD_EXE_FORMAT ? 4 : 3,
        Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"disk PE headers")}, {L"header", header(result)}}),
        result.success ? std::vector<std::wstring>{} : std::vector<std::wstring>{result.text}};
}
Result hex(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto max = args.u32(L"--max-bytes", 256);
    if (!max || max > 1024 * 1024) throw std::invalid_argument("--max-bytes must be 1..1048576");
    const auto result = backend::ReadHexPreview(path, max);
    return {!result.success ? 3 : result.limited ? 6 : 0, Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"disk prefix")},
        {L"maxBytes", Json::number(max)}, {L"returnedBytes", Json::number(static_cast<std::uint32_t>(result.bytes.size()))},
        {L"sizeBytes", result.sizeKnown ? Json::count(result.size) : Json{}}, {L"limited", Json::boolean(result.limited)},
        {L"win32Error", Json::number(result.errorCode)}, {L"dataHex", result.success ? Json::bytes(result.bytes, result.bytes.size()) : Json{}},
        {L"preview", Json::string(result.text)}})};
}
Result query(const Args& args) {
    const auto path = file::path(args, L"--path"); const auto result = backend::BuildPeStaticSummary(path); const auto& analysis = result.analysis;
    std::vector<Json> sections, imports, notes; bool partial = result.partial || result.sectionsTruncated || result.importsTruncated;
    for (std::size_t i = 0; i < std::min<std::size_t>(analysis.sections.size(), 32); ++i) {
        const auto& s = analysis.sections[i]; sections.push_back(Json::object({{L"name", Json::string(backend::Utf8ToWide(s.name))},
            {L"virtualAddress", Json::hex(s.virtualAddress)}, {L"virtualSize", Json::count(s.virtualSize)}, {L"rawOffset", Json::hex(s.rawOffset)},
            {L"rawSize", Json::count(s.rawSize)}, {L"characteristics", Json::hex(s.characteristics)}, {L"entropy", Json::real(s.entropy)}}));
    }
    for (const auto& m : analysis.importModules) if (!m.diagnosticText.empty()) partial = true;
    for (std::size_t i = 0; i < std::min<std::size_t>(analysis.importModules.size(), 64); ++i) {
        const auto& m = analysis.importModules[i]; imports.push_back(Json::object({{L"name", Json::string(backend::Utf8ToWide(m.dllName))},
            {L"descriptorIndex", Json::number(m.descriptorIndex)}, {L"descriptorValid", Json::boolean(m.descriptorValid)},
            {L"originalFirstThunk", Json::hex(m.originalFirstThunk)}, {L"firstThunk", Json::hex(m.firstThunk)},
            {L"parsedEntryCount", Json::number(static_cast<std::uint32_t>(m.imports.size()))}, {L"diagnostic", Json::string(backend::Utf8ToWide(m.diagnosticText))}}));
    }
    for (const auto& entry : analysis.entries) if (entry.kind == ks::file::PeReportEntry::Kind::Note) notes.push_back(Json::string(entry.value));
    int code = result.deepAvailable ? partial ? 6 : 0 : result.fallbackReason == backend::PeFallbackReason::InvalidPe ? 4 :
        result.fallbackReason == backend::PeFallbackReason::ReadFailure ? 3 : result.header.success ? 6 : 5;
    const wchar_t* reason = result.fallbackReason == backend::PeFallbackReason::None ? L"none" : result.fallbackReason == backend::PeFallbackReason::InvalidPe ? L"invalid-pe" :
        result.fallbackReason == backend::PeFallbackReason::SizeLimit ? L"size-limit" : result.fallbackReason == backend::PeFallbackReason::ReadFailure ? L"read-failure" : L"unsupported-path";
    Result output{code};
    output.data = Json::object({{L"path", Json::string(path)}, {L"source", Json::string(L"bounded disk PE snapshot")},
        {L"deepAvailable", Json::boolean(result.deepAvailable)}, {L"fallbackReason", Json::string(reason)}, {L"win32Error", Json::number(result.read.errorCode)},
        {L"snapshotSize", Json::count(result.read.size)}, {L"bytesRead", Json::count(result.read.bytesRead)}, {L"header", header(result.header)},
        {L"format", result.deepAvailable ? Json::string(analysis.isPe64 ? L"PE32+" : L"PE32") : Json{}},
        {L"machine", result.deepAvailable ? Json::hex(analysis.machine) : Json{}}, {L"machineName", result.deepAvailable ? Json::string(backend::PeMachineText(analysis.machine)) : Json{}},
        {L"subsystem", result.deepAvailable ? Json::hex(analysis.subsystem) : Json{}}, {L"subsystemName", result.deepAvailable ? Json::string(backend::PeSubsystemText(analysis.subsystem)) : Json{}},
        {L"imageBase", result.deepAvailable ? Json::hex(analysis.imageBase) : Json{}}, {L"entryPointRva", result.deepAvailable ? Json::hex(analysis.entryPointRva) : Json{}},
        {L"entryPointFileOffset", analysis.entryPointFileOffsetValid ? Json::hex(analysis.entryPointFileOffset) : Json{}},
        {L"sectionCount", Json::number(static_cast<std::uint32_t>(analysis.sections.size()))}, {L"importModuleCount", Json::number(static_cast<std::uint32_t>(analysis.importModules.size()))},
        {L"sectionsTruncated", Json::boolean(result.sectionsTruncated)}, {L"importsTruncated", Json::boolean(result.importsTruncated)},
        {L"sections", Json::array(sections)}, {L"imports", Json::array(imports)}, {L"notes", Json::array(notes)}});
    if (!result.deepAvailable) output.diagnostics.push_back(result.text);
    return output;
}
}
void registerFilePe() {
    addCommand({L"file hex query", L"KswordCLI.exe file hex query --path PATH [--max-bytes N] [--backend r3] [--json]",
        L"Read a bounded prefix as bytes and a hex/ASCII preview.", L"Required: --path. Optional: --max-bytes 1..1048576 (default 256), --backend r3, --json.",
        L"Fields: dataHex, preview, returnedBytes, sizeBytes, limited, win32Error. A limited preview returns 6; valid empty files return 0.", hex});
    addCommand({L"file pe query", L"KswordCLI.exe file pe query --path PATH [--backend r3] [--json]",
        L"Analyze a bounded PE snapshot with section and import module summaries.", L"Required: --path. Optional: --backend r3, --json.",
        L"Fields: format, machine, subsystem, imageBase, entryPointRva, sections, imports, fallbackReason, header. Backend limits: 16 MiB, 32 displayed sections, 64 import modules. Partial results return 6; invalid PE returns 4; read failure returns 3. No import function/export table publication.", query});
    addCommand({L"file pe header query", L"KswordCLI.exe file pe header query --path PATH [--backend r3] [--json]",
        L"Read the lightweight DOS/NT/COFF header without loading the entire file.", L"Required: --path. Optional: --backend r3, --json.",
        L"Fields: machine, sectionCount, timestamp, characteristics, optionalMagic. Does not validate all directories or section contents.", headerQuery});
}
}
