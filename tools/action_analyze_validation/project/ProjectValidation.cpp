#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include "../../../KswordCLI/ActionAnalyze/Project/ProjectDocument.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>

void RunCallbackValidation(const std::filesystem::path& project);

namespace {
using namespace Ksword::ActionAnalyze;
namespace fs = std::filesystem;

unsigned checks = 0;

void Check(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
    ++checks;
}

void CheckResult(ProjectResult result, ProjectError expected, const char* reason) {
    if (result.error != expected) {
        std::cerr << reason << " expected=" << ProjectErrorName(expected) << " actual="
                  << ProjectErrorName(result.error) << " stage=" << result.detail << " native=" << result.nativeError << '\n';
        throw std::runtime_error(reason);
    }
    ++checks;
}

void Ok(ProjectResult result, const char* reason) { CheckResult(result, ProjectError::None, reason); }

std::string Bytes(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("fixtureRead");
    return {std::istreambuf_iterator<char>(file), {}};
}

void Put(const fs::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    if (!file) throw std::runtime_error("fixtureWrite");
}

std::string Replace(std::string bytes, std::string_view before, std::string_view after) {
    const auto position = bytes.find(before);
    if (position == bytes.npos) throw std::runtime_error("fixtureReplace");
    bytes.replace(position, before.size(), after);
    return bytes;
}

auto Tree(const fs::path& root) {
    std::map<fs::path, std::pair<std::string, fs::file_time_type>> files;
    for (const auto& entry : fs::recursive_directory_iterator(root)) {
        files.emplace(entry.path().lexically_relative(root),
                      std::make_pair(entry.is_regular_file() ? Bytes(entry.path()) : std::string{}, entry.last_write_time()));
    }
    return files;
}

unsigned TryWriterChild(const fs::path& project) {
    std::wstring command = L"\"" + fs::absolute(fs::path(__wargv[0])).wstring() + L"\" --try-writer \"" +
        project.wstring() + L"\"";
    STARTUPINFOW start{};
    start.cb = sizeof(start);
    PROCESS_INFORMATION process{};
    if (!CreateProcessW(nullptr, command.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &start, &process)) {
        throw std::runtime_error("fixtureChildCreate");
    }
    CloseHandle(process.hThread);
    const DWORD wait = WaitForSingleObject(process.hProcess, 10000);
    DWORD status = 255;
    const bool read = GetExitCodeProcess(process.hProcess, &status) != FALSE;
    CloseHandle(process.hProcess);
    if (wait != WAIT_OBJECT_0 || !read) throw std::runtime_error("fixtureChildWait");
    return status;
}

void Run(const fs::path& project) {
    const auto manifest = project / "project.ksaproj";
    ProjectDocument writer, reader, competitor;
    const RevisionSettings a{"离线调查", "line 1\n\tline 2 \"😀\" / \\"};
    const RevisionSettings b{"调查更新", "第二份配置"};
    const RevisionSettings c{"保存失败的标题", "未发布"};
    Ok(writer.Create(project.wstring(), a), "create");
    Check(writer.Info()->generation == 1 && writer.Info()->sampleCount == 0, "initialGeneration");
    const auto firstRevision = writer.Info()->revisionId;
    CheckResult(competitor.Create(project.wstring(), a), ProjectError::AlreadyExists, "exclusiveCreate");
    Check(TryWriterChild(project) == 10, "crossProcessWriterBusy");

    SampleInfo first, second;
    Ok(writer.CreateSample("同名采样", first), "firstSample");
    Ok(reader.Open(manifest.wstring()), "manifestReadOnly");
    Ok(writer.Save(b, firstRevision), "saveDifferentRevision");
    const auto secondRevision = writer.Info()->revisionId;
    Check(firstRevision != secondRevision, "distinctRevisions");
    CheckResult(writer.Save(c, firstRevision), ProjectError::StaleRevision, "staleSave");
    Check(writer.Info()->revisionId == secondRevision, "staleSaveKeepsRevision");
    const auto beforeNoOp = writer.Info()->generation;
    Ok(writer.Save(b, secondRevision), "unchangedSave");
    Check(writer.Info()->generation == beforeNoOp, "unchangedDoesNotCommit");
    Ok(writer.CreateSample("同名采样", second), "secondSample");
    Check(first.sampleId != second.sampleId && first.snapshotId != second.snapshotId, "distinctSamples");
    Check(reader.Info()->sampleCount == 1 && reader.Info()->revisionId == firstRevision, "stableReaderGeneration");
    SampleRecord record;
    CheckResult(reader.ReadSample(second.sampleId, record), ProjectError::NotFound, "olderSnapshotExcludesSecond");
    CheckResult(reader.Save(b), ProjectError::ReadOnly, "readOnlyRejectsSave");
    CheckResult(reader.CreateSample("拒绝", second), ProjectError::ReadOnly, "readOnlyRejectsSample");
    reader.Close();

    CheckResult(competitor.Open(project.wstring(), ProjectAccess::ReadWrite), ProjectError::WriterBusy, "secondWriterInProcess");
    const auto beforeRead = Tree(project);
    Ok(reader.Open(project.wstring()), "latestReadOnly");
    std::vector<SampleInfo> rows;
    Ok(reader.ListSamples(0, 1, rows), "firstListPage");
    Check(rows.size() == 1 && rows[0].sampleId == first.sampleId, "firstListPageIdentity");
    Ok(reader.ListSamples(1, 1, rows), "secondListPage");
    Check(rows.size() == 1 && rows[0].sampleId == second.sampleId, "secondListPageIdentity");
    Ok(reader.ListSamples(2, 1, rows), "emptyPage");
    Check(rows.empty(), "emptyPageResult");
    CheckResult(reader.ListSamples(3, 1, rows), ProjectError::InvalidArgument, "invalidPage");
    CheckResult(reader.ReadSample("../project.ksaproj", record), ProjectError::InvalidArgument, "unsafeSampleId");
    Ok(reader.ReadSample(first.sampleId, record), "firstSampleRead");
    Check(record.info.revisionId == firstRevision && record.frozenSettings.title == a.title &&
          record.frozenSettings.notes == a.notes, "firstFrozenRevision");
    Ok(reader.ReadSample(second.sampleId, record), "secondSampleRead");
    Check(record.info.revisionId == secondRevision && record.frozenSettings.title == b.title &&
          record.frozenSettings.notes == b.notes, "secondFrozenRevision");
    reader.Close();
    Check(beforeRead == Tree(project), "readOnlyNoFilesOrMtimeChanged");

    const auto stable = Bytes(manifest);
    const auto generation = writer.Info()->generation;
    const auto latestJournal = project / "journal" / (std::to_string(generation) + ".json");
    const auto journalBytes = Bytes(latestJournal);
    Put(latestJournal, journalBytes + "\n");
    CheckResult(writer.Save(c, secondRevision), ProjectError::Corrupt, "writeChecksCurrentJournalHash");
    Check(writer.Info()->generation == generation && Bytes(manifest) == stable, "badJournalLeavesManifestUntouched");
    Put(latestJournal, journalBytes);
    const HANDLE pinned = CreateFileW(manifest.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                                      FILE_ATTRIBUTE_NORMAL, nullptr);
    Check(pinned != INVALID_HANDLE_VALUE, "pinManifest");
    SampleInfo interrupted;
    const auto interruptedResult = writer.CreateSample("half-published", interrupted);
    CloseHandle(pinned);
    CheckResult(interruptedResult, ProjectError::IoError, "renameBlocked");
    Check(writer.Info()->generation == generation && Bytes(manifest) == stable && interrupted.sampleId.empty(),
          "interruptedCommitDoesNotPublishOrReturnId");
    std::vector<std::string> orphans;
    Ok(writer.ListOrphans(orphans), "orphansRead");
    Check(orphans.size() == 1, "newOrphanReported");
    writer.Close();
    Check(TryWriterChild(project) == 0, "crossProcessWriterReacquiresStaleLockFile");

    Ok(reader.Open(project.wstring()), "openAfterInterruptedCommit");
    Check(reader.Info()->generation == generation && reader.Info()->sampleCount == 2 && !reader.Info()->recoveredPrevious,
          "unpublishedHigherGenerationIgnored");
    CheckResult(reader.ReadSample(orphans[0], record), ProjectError::NotFound, "orphanIsNotAdopted");
    reader.Close();

    // 上次正常提交引用采样 1。失败写入保留的 previous 则引用上一次已发布的双采样清单。
    const auto previous = project / "journal" / "previous.ksaproj";
    const auto failedPrevious = Bytes(previous);
    Check(failedPrevious == stable, "failedPublishBackupPointsAtGenuineCurrentCommit");
    Put(manifest, Replace(stable, "\"journalGeneration\":\"4\"", "\"journalGeneration\":\"5\""));
    Ok(reader.Open(project.wstring()), "recoverMismatchedGeneration");
    Check(reader.Info()->recoveredPrevious && reader.Info()->generation == generation && reader.Info()->sampleCount == 2,
          "recoveredGenuineCommittedGeneration");
    reader.Close();
    CheckResult(competitor.Open(project.wstring(), ProjectAccess::ReadWrite), ProjectError::RecoveryRequired, "recoveredProjectCannotWrite");
    Put(manifest, stable);

    Ok(writer.Open(project.wstring(), ProjectAccess::ReadWrite), "reopenWriterForRetry");
    Ok(writer.Save({"最终修订", "合法下一代"}, secondRevision), "retrySkipsUnpublishedGeneration");
    Check(writer.Info()->generation == generation + 2 && writer.Info()->sampleCount == 2, "retryGenerationSkipsOrphan");
    writer.Close();
    const auto newest = Bytes(manifest);
    const auto latest = project / "journal" / "6.json";
    const auto latestBytes = Bytes(latest);
    Put(latest, latestBytes + "\n");
    Ok(reader.Open(project.wstring()), "recoverJournalHashFault");
    Check(reader.Info()->recoveredPrevious && reader.Info()->generation == generation && reader.Info()->sampleCount == 2 &&
          std::string_view(reader.Info()->primaryFailure.detail) == "documentHash", "verifyRecoveryAfterJournalHashFault");
    reader.Close();
    Put(latest, latestBytes);
    Check(Bytes(latestJournal) == journalBytes, "olderJournalImmutable");

    for (const auto& invalid : {std::string("\xef\xbb\xbf") + newest,
                                Replace(newest, "\"version\":1", "\"version\":01"),
                                Replace(newest, "\"version\":1", "\"version\":1,\"version\":1"),
                                Replace(newest, "最终修订", "\\ud800"),
                                Replace(newest, "最终修订", "\xc0\xaf")}) {
        Put(manifest, invalid);
        Ok(reader.Open(project.wstring()), "recoverInvalidDocument");
        Check(reader.Info()->recoveredPrevious && reader.Info()->primaryFailure.error == ProjectError::Corrupt,
              "badDocumentDetected");
        reader.Close();
    }
    Put(manifest, Replace(newest, kOfflineProjectFeature, "future-feature-v2"));
    CheckResult(reader.Open(project.wstring()), ProjectError::Unsupported, "unknownFeatureNoFallback");
    Put(manifest, Replace(newest, "\"version\":1", "\"version\":2"));
    CheckResult(reader.Open(project.wstring()), ProjectError::Unsupported, "futureVersionNoFallback");
    Put(manifest, newest);

    const auto tailPage = project / "catalog" / "4" / "1.json";
    const auto pageBytes = Bytes(tailPage);
    Put(tailPage, pageBytes + "\n");
    CheckResult(reader.Open(project.wstring()), ProjectError::Corrupt, "bothHeadsRejectDamagedSharedCatalogPage");
    Put(tailPage, pageBytes);

    const auto sample = project / "samples" / second.sampleId / "sample.json";
    const auto originalSample = Bytes(sample);
    Put(sample, originalSample + "\n");
    Ok(reader.Open(project.wstring()), "projectCanOpenWithDamagedSample");
    CheckResult(reader.ReadSample(second.sampleId, record), ProjectError::Corrupt, "damagedDescriptionReported");
    reader.Close();
    Put(sample, originalSample);

    const auto firstFile = project / "samples" / first.sampleId / "sample.json";
    const auto alias = project / ".staging" / "test-hardlink";
    fs::create_hard_link(firstFile, alias);
    Ok(reader.Open(project.wstring()), "projectOpensWithoutTraversingSample");
    CheckResult(reader.ReadSample(first.sampleId, record), ProjectError::UnsafePath, "rejectHardLinkedSample");
    reader.Close();
    fs::remove(alias);
    std::cout << "PROJECT_ASSERTIONS=" << checks << '\n';
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"--callback") {
            RunCallbackValidation(fs::absolute(argv[2]));
            return 0;
        }
        if (argc == 3 && std::wstring_view(argv[1]) == L"--try-writer") {
            ProjectDocument test;
            const auto result = test.Open(argv[2], ProjectAccess::ReadWrite);
            if (result) return 0;
            if (result.error == ProjectError::WriterBusy) return 10;
            std::cerr << ProjectErrorName(result.error) << ' ' << result.detail << ' ' << result.nativeError << '\n';
            return 11;
        }
        if (argc != 2) return 2;
        Run(fs::absolute(argv[1]));
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL " << error.what() << '\n';
        return 1;
    }
}
