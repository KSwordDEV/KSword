#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentInspection.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentWriter.h"

#include <Windows.h>
#include <objbase.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

namespace {

namespace fs = std::filesystem;
namespace aa = Ksword::ActionAnalyze;
namespace archive = ks::cli::action_analyze::archive;
unsigned checks = 0;

void Check(bool passed, const char* description) {
    if (!passed) throw std::runtime_error(description);
    ++checks;
}

void Expect(aa::ProjectResult result, aa::ProjectError error, std::string_view detail = {}) {
    if (result.error != error || (!detail.empty() && detail != result.detail)) {
        std::cerr << "expected " << aa::ProjectErrorName(error) << ' ' << detail << ", got "
                  << aa::ProjectErrorName(result.error) << ' ' << result.detail << '/' << result.nativeError << '\n';
        throw std::runtime_error("unexpected ProjectResult");
    }
    ++checks;
}

archive::ArchiveUuid Uuid(const std::string& text) {
    auto wide = L"{" + std::wstring(text.begin(), text.end()) + L"}";
    GUID guid{};
    Check(SUCCEEDED(CLSIDFromString(wide.c_str(), &guid)), "fixture UUID");
    // 独立地从 Windows GUID 字段构造 RFC 顺序字节。
    archive::ArchiveUuid result{};
    for (unsigned i = 0; i < 4; ++i) result[i] = static_cast<std::uint8_t>(guid.Data1 >> ((3 - i) * 8));
    for (unsigned i = 0; i < 2; ++i) {
        result[4 + i] = static_cast<std::uint8_t>(guid.Data2 >> ((1 - i) * 8));
        result[6 + i] = static_cast<std::uint8_t>(guid.Data3 >> ((1 - i) * 8));
    }
    std::copy_n(guid.Data4, 8, result.begin() + 8);
    return result;
}

auto Tree(const fs::path& project) {
    std::map<fs::path, std::pair<fs::file_time_type, std::string>> result;
    for (const auto& entry : fs::recursive_directory_iterator(project)) {
        std::string bytes;
        fs::file_time_type writeTime{};
        if (entry.is_regular_file()) {
            std::ifstream stream(entry.path(), std::ios::binary);
            if (!stream) throw std::runtime_error("fixture file read");
            bytes.assign(std::istreambuf_iterator<char>(stream), {});
            writeTime = entry.last_write_time();
        }
        result.emplace(entry.path(), std::make_pair(writeTime, std::move(bytes)));
    }
    return result;
}

void Run(const fs::path& project) {
    aa::ProjectDocument writer;
    Expect(writer.Create(project.wstring(), {"Project Archive Validation", ""}), aa::ProjectError::None);
    aa::SampleInfo first, second;
    Expect(writer.CreateSample("first", first), aa::ProjectError::None);
    Expect(writer.CreateSample("second", second), aa::ProjectError::None);
    const auto projectId = writer.Info()->projectId;
    writer.Close();

    aa::ProjectDocument reader;
    archive::SegmentInspection inspection;
    using enum aa::ProjectError;
    using enum archive::StreamKind;
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, {}, inspection), NotOpen);
    Expect(reader.Open(project.wstring()), None);
    const auto firstDir = project / "samples" / first.sampleId;
    const auto segment = firstDir / "records" / "00000000000000000001.ksaseg";
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, {}, inspection), NotFound,
           "archiveStreamUnavailable");
    Check(!fs::exists(segment.parent_path()), "lookup leaves missing stream directory untouched");
    fs::create_directory(segment.parent_path());
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, {}, inspection), NotFound,
           "archiveSegmentUnavailable");
    Check(!fs::exists(segment), "lookup leaves missing segment untouched");

    const archive::SegmentIdentity identity{Records, 1, Uuid(projectId), Uuid(first.sampleId)};
    {
        archive::SegmentWriter fixture(segment, {identity, 1});
        Check(fixture.AppendBlock({{4, 1, 1, 15, {1, 2, 3}}}).status == archive::SegmentWriteStatus::Ok,
              "one stored block");
        Check(fixture.Close().status == archive::SegmentWriteStatus::Ok, "close fixture");
    }
    const auto secondStream = project / "samples" / second.sampleId / "records";
    fs::create_directory(secondStream);
    fs::copy_file(segment, secondStream / segment.filename());
    const auto orphanId = "11111111-1111-4111-8111-111111111111";
    const auto orphanStream = project / "samples" / orphanId / "records";
    fs::create_directories(orphanStream);
    fs::copy_file(segment, orphanStream / segment.filename());

    const auto before = Tree(project);
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, {}, inspection), None);
    Check(inspection.framingStatus == archive::SegmentScanStatus::FramingComplete &&
          inspection.framingCoverage.blockCount == 1 && inspection.framingCoverage.lastSequence == 15,
          "matched same-handle segment");
    Check(!inspection.interpretedBytes && !inspection.durableBytes, "evidence endpoints unknown");
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, archive::kSegmentHeaderBytes, inspection), None);
    Check(inspection.framingStatus == archive::SegmentScanStatus::FramingComplete &&
          inspection.framingCoverage.framedBytes == archive::kSegmentHeaderBytes &&
          inspection.framingCoverage.blockCount == 0, "explicit scan boundary");
    Expect(reader.InspectSegment(projectId, second.sampleId, Records, 1, {}, inspection), None);
    Check(inspection.framingStatus == archive::SegmentScanStatus::Corrupt &&
          inspection.error.issue == archive::SegmentIssue::Identity && inspection.framingCoverage.framedBytes == 0,
          "filename cannot replace on-disk sample identity");
    Expect(reader.InspectSegment(projectId, orphanId, Records, 1, {}, inspection), NotFound, "sampleId");
    Expect(reader.InspectSegment(projectId, "../records", Records, 1, {}, inspection), InvalidArgument, "sampleId");
    Expect(reader.InspectSegment(orphanId, first.sampleId, Records, 1, {}, inspection), InvalidArgument,
           "archiveProjectIdMismatch");
    Expect(reader.InspectSegment(projectId, first.sampleId, Analysis, 1, {}, inspection), Unsupported, "archiveStream");
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 0, {}, inspection), InvalidArgument, "archiveOrdinal");
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 1, archive::kMaxSegmentBytes + 1, inspection),
           LimitExceeded, "archiveEndOffset");
    const auto after = Tree(project);
    if (before != after) {
        for (const auto& [file, previous] : before) {
            const auto now = after.find(file);
            if (now == after.end() || now->second != previous) std::wcerr << L"changed " << file.c_str() << L'\n';
        }
    }
    Check(before == after, "scan leaves project contents and file mtimes intact");

    const auto link = segment.parent_path() / "00000000000000000002.ksaseg";
    fs::create_hard_link(segment, link);
    Expect(reader.InspectSegment(projectId, first.sampleId, Records, 2, {}, inspection), UnsafePath, "fileIdentity");
    fs::remove(link);
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 2) return 2;
    try {
        Run(fs::absolute(argv[1]));
        std::cout << "PROJECT_ARCHIVE_ASSERTIONS=" << checks << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
