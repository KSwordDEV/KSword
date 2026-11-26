#include "../../../KswordCLI/ActionAnalyze/Project/ProjectCallbackEvidence.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentWire.h"
#include "../../../shared/driver/KswordArkCallbackIoctl.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using namespace Ksword::ActionAnalyze;
namespace Archive = ks::cli::action_analyze::archive;
namespace fs = std::filesystem;

constexpr std::string_view kObservation = R"({"kind":"kswordark-callback-thread-create-observation-v1"})";

void Check(bool condition, const char* reason) {
    if (!condition) throw std::runtime_error(reason);
}

void Expect(ProjectResult result, ProjectError expected, const char* reason) {
    if (result.error != expected) {
        std::cerr << reason << " expected=" << ProjectErrorName(expected) << " actual="
                  << ProjectErrorName(result.error) << " stage=" << result.detail << " native=" << result.nativeError << '\n';
        throw std::runtime_error(reason);
    }
}

void Ok(ProjectResult result, const char* reason) { Expect(result, ProjectError::None, reason); }

fs::path RawOne(const fs::path& project, const SampleInfo& sample) {
    return project / "samples" / sample.sampleId / "raw" / "00000000000000000001.ksaseg";
}

std::string Bytes(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    Check(static_cast<bool>(file), "callbackFixtureRead");
    return {std::istreambuf_iterator<char>(file), {}};
}

void Put(const fs::path& path, std::string_view bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    Check(static_cast<bool>(file), "callbackFixtureWrite");
}

std::string_view EventBytes(const KSWORD_ARK_CALLBACK_MONITOR_EVENT& event) {
    return {reinterpret_cast<const char*>(&event), sizeof(event)};
}

void CheckUnpublished(const ProjectCallbackEvidenceReceipt& out, const char* reason) {
    Check(out.projectId.empty() && out.sampleId.empty() && out.descriptionHash.empty() &&
          out.plan.sourceEpoch.empty() && out.end.state == CallbackBatchState::NotRead && out.records.empty() &&
          out.segmentOrdinal == 0 && out.boundary.blockOrdinal == 0 && out.boundary.lastSequence == 0 &&
          out.boundary.byteOffset == 0 && out.prefixSha256.empty(), reason);
}

void CheckCoordinates(std::string_view bytes, const ProjectCallbackEvidenceRecord& row, std::string_view eventBytes) {
    // Locate the second Stored record from the on-disk length of the first, without using receipt offsets.
    const auto* data = reinterpret_cast<const std::uint8_t*>(bytes.data());
    constexpr auto first = Archive::kSegmentHeaderBytes + Archive::kBlockHeaderBytes;
    Check(bytes.size() >= first + Archive::kRecordHeaderBytes, "callbackPlanHeaderOnDisk");
    const auto record = first + Archive::wire::Get<std::uint32_t>(data, first);
    const auto metadata = record + Archive::kRecordHeaderBytes + Archive::kRawRecordV1PrefixBytes;
    const auto inlineData = metadata + kObservation.size();
    Check(bytes.size() >= inlineData + eventBytes.size(), "callbackObservationOnDisk");
    Check(row.rawOffset == record && row.inlineOffset == inlineData && row.rawSequence == 2 &&
          Archive::wire::Get<std::uint64_t>(data, record + 16) == row.rawSequence &&
          Archive::wire::Get<std::uint32_t>(data, record + Archive::kRecordHeaderBytes) == kObservation.size() &&
          bytes.substr(metadata, kObservation.size()) == kObservation, "callbackRealCoordinates");
    Check(bytes.substr(static_cast<std::size_t>(row.inlineOffset), eventBytes.size()) == eventBytes &&
          EventBytes(row.event) == eventBytes, "callbackExactEventBytes");
}

} // namespace

void RunCallbackValidation(const std::filesystem::path& project) {
    // Populate only an in-memory ABI record; never open an event source or a device.
    std::array<KSWORD_ARK_CALLBACK_MONITOR_EVENT, 1> events{};
    auto& event = events.front();
    event.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    event.size = static_cast<unsigned long>(sizeof(event));
    event.sequence = 107;
    event.timeUtc100ns = 133000000000000123LL;
    event.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    event.operation = KSWORD_ARK_THREAD_OP_CREATE;
    event.flags = KSWORD_ARK_CALLBACK_MONITOR_EVENT_FLAG_PROCESS_NAME_PRESENT;
    event.originatingProcessId = 4101;
    event.originatingThreadId = 4102;
    event.targetProcessId = 4201;
    event.targetThreadId = 4202;
    event.processName[0] = L'X';
    event.processName[1] = L'\u4e2d';
    const ProjectCallbackEvidencePlan plan{"11111111-1111-4111-8111-111111111111", 101, 8};
    const ProjectCallbackEvidenceEnd end{CallbackBatchState::CaughtUp, 108, 108, 3, 4ULL, 17ULL};
    const ProjectCallbackEvidenceEnd emptyEnd{CallbackBatchState::CaughtUp, 101, 101, 0, 0ULL, std::nullopt};

    ProjectDocument writer, reader;
    Ok(writer.Create(project.wstring(), {"Synthetic callback archive", "In-memory records only"}), "callbackProjectCreate");
    const auto projectId = writer.Info()->projectId;
    SampleInfo positive, empty, conflict;
    Ok(writer.CreateSample("Synthetic thread creation", positive), "callbackPositiveSample");
    Ok(writer.CreateSample("Complete empty callback batch", empty), "callbackEmptySample");
    Ok(writer.CreateSample("Conflicting callback counts", conflict), "callbackConflictSample");

    ProjectCallbackEvidenceReceipt written, emptyWritten;
    Ok(WriteInitialCallbackEvidence(writer, positive.sampleId, plan, end, events, written), "callbackPositiveWrite");
    Ok(WriteInitialCallbackEvidence(writer, empty.sampleId, plan, emptyEnd, {}, emptyWritten), "callbackEmptyWrite");
    const auto raw = RawOne(project, positive);
    const auto original = Bytes(raw);
    auto changedEvents = events;
    ++changedEvents.front().targetThreadId;
    auto replay = written; // Each failure must clear a previously populated receipt.
    Expect(WriteInitialCallbackEvidence(writer, positive.sampleId, plan, end, changedEvents, replay),
           ProjectError::AlreadyExists, "callbackExistingRawOneRejected");
    CheckUnpublished(replay, "callbackExistingRawOneUnpublished");
    Check(Bytes(raw) == original, "callbackExistingRawOneUnchanged");

    auto conflictingEnd = end;
    conflictingEnd.returnedCount = 4; // 108 - 101 cannot account for both four returned and four lost.
    replay = written;
    Expect(WriteInitialCallbackEvidence(writer, conflict.sampleId, plan, conflictingEnd, events, replay),
           ProjectError::InvalidArgument, "callbackConflictingCursorRejectedOnWrite");
    CheckUnpublished(replay, "callbackConflictingWriteUnpublished");
    Check(!fs::exists(RawOne(project, conflict)), "callbackConflictingWriteCreatesNoSegment");

    // Write the same conflict via the generic Stored writer. Valid framing/CRC must not bypass semantic validation.
    const auto conflictPlan = std::string(R"({"kind":"kswordark-callback-thread-create-plan-v1","sourceId":"kswordark.callback","descriptionHash":")") +
        conflict.descriptionHash + R"(","sourceEpoch":"11111111-1111-4111-8111-111111111111","afterSequence":"101","maxRecords":"8"})";
    constexpr std::string_view conflictEnd = R"({"kind":"kswordark-callback-thread-create-end-v1","state":"caught-up","nextSequence":"108","latestSequence":"108","returnedCount":"4","observationCount":"1","lostBeforeFirst":"4","droppedCount":"17","coverage":"unknown"})";
    const std::array<Archive::RawEvidenceInput, 3> conflictRows{{
        {conflictPlan, {}}, {kObservation, EventBytes(event)}, {conflictEnd, {}}
    }};
    Archive::RawEvidenceReceipt conflictStored;
    Ok(writer.WriteRawEvidenceSegment({projectId, conflict.sampleId, 1, std::nullopt,
        [&](Archive::RawEvidenceArchive& archive) {
            Check(archive.Append(conflictRows).result.status == Archive::SegmentWriteStatus::Ok, "callbackConflictStoredAppend");
            return ProjectResult{};
        }}, conflictStored), "callbackConflictStoredWrite");
    Check(conflictStored.flushed && conflictStored.flushed->lastSequence == 3, "callbackConflictStoredFlushed");
    writer.Close();

    Ok(reader.Open(project.wstring()), "callbackProjectReopen");
    Ok(ReadInitialCallbackEvidence(reader, positive.sampleId, replay), "callbackPositiveReplay");
    Check(replay.projectId == projectId && replay.sampleId == positive.sampleId &&
          replay.descriptionHash == positive.descriptionHash && replay.plan.sourceEpoch == plan.sourceEpoch &&
          replay.plan.afterSequence == 101 && replay.plan.maxRecords == 8 && replay.end.state == CallbackBatchState::CaughtUp &&
          replay.end.nextSequence == 108 && replay.end.latestSequence == 108 && replay.end.returnedCount == 3 &&
          replay.end.lostBeforeFirst == 4ULL && replay.end.droppedCount == 17ULL && replay.records.size() == 1,
          "callbackPositiveIdentityAndSourceBatch");
    Check(replay.segmentOrdinal == 1 && replay.boundary.blockOrdinal == 1 && replay.boundary.lastSequence == 3 &&
          replay.boundary.byteOffset == original.size() && replay.boundary.byteOffset == written.boundary.byteOffset &&
          replay.prefixSha256.size() == 64 && replay.prefixSha256 == written.prefixSha256 && written.records.size() == 1,
          "callbackPositiveBoundaryAndHash");
    CheckCoordinates(original, written.records.front(), EventBytes(event));
    CheckCoordinates(original, replay.records.front(), EventBytes(event));

    ProjectCallbackEvidenceReceipt emptyReplay;
    Ok(ReadInitialCallbackEvidence(reader, empty.sampleId, emptyReplay), "callbackEmptyReplay");
    Check(emptyReplay.projectId == projectId && emptyReplay.sampleId == empty.sampleId &&
          emptyReplay.descriptionHash == empty.descriptionHash && emptyReplay.plan.sourceEpoch == plan.sourceEpoch &&
          emptyReplay.plan.afterSequence == 101 && emptyReplay.plan.maxRecords == 8 && emptyReplay.records.empty() &&
          emptyReplay.end.state == CallbackBatchState::CaughtUp && emptyReplay.end.nextSequence == 101 &&
          emptyReplay.end.latestSequence == 101 && emptyReplay.end.returnedCount == 0 && emptyReplay.end.lostBeforeFirst == 0ULL &&
          !emptyReplay.end.droppedCount && emptyReplay.segmentOrdinal == 1 && emptyReplay.boundary.blockOrdinal == 1 &&
          emptyReplay.boundary.lastSequence == 2 && emptyReplay.boundary.byteOffset == fs::file_size(RawOne(project, empty)) &&
          emptyReplay.boundary.byteOffset == emptyWritten.boundary.byteOffset && emptyReplay.prefixSha256.size() == 64 &&
          emptyReplay.prefixSha256 == emptyWritten.prefixSha256, "callbackVerifiedEmpty");

    Expect(ReadInitialCallbackEvidence(reader, conflict.sampleId, replay), ProjectError::Corrupt, "callbackConflictingCursorRejectedOnRead");
    CheckUnpublished(replay, "callbackConflictingReadUnpublished");
    const auto rejectDamaged = [&](std::string_view damaged, const char* reason) {
        Put(raw, damaged);
        replay = written;
        Expect(ReadInitialCallbackEvidence(reader, positive.sampleId, replay), ProjectError::Corrupt, reason);
        CheckUnpublished(replay, "callbackDamageUnpublished");
        Check(Bytes(raw) == damaged, "callbackFailedReadDoesNotRepairSource");
    };
    rejectDamaged(original + std::string(Archive::kBlockHeaderBytes, '\0'), "callbackBadTailAfterCompleteBlock");
    rejectDamaged(std::string_view(original).substr(0, original.size() - 1), "callbackTruncatedBlock");
    Put(raw, original);
    Ok(ReadInitialCallbackEvidence(reader, positive.sampleId, replay), "callbackRestoredReplay");
    Check(replay.records.size() == 1 && replay.prefixSha256 == written.prefixSha256, "callbackRestoredEvidence");
    const auto& row = replay.records.front();
    std::cout << "PROJECT_CALLBACK_VALIDATION=PASS INPUT=synthetic-memory"
              << " POSITIVE_SAMPLE=" << positive.sampleId << " EMPTY_SAMPLE=" << empty.sampleId
              << " RAW_SEQUENCE=" << row.rawSequence << " SOURCE_SEQUENCE=" << row.event.sequence
              << " RECORD_OFFSET=" << row.rawOffset << " INLINE_OFFSET=" << row.inlineOffset
              << " PREFIX_SHA256=" << replay.prefixSha256 << '\n';
}
