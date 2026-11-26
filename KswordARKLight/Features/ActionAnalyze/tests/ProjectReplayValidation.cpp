#include "../ProjectReplay.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectCallbackEvidence.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"
#include "../../../../shared/driver/KswordArkCallbackIoctl.h"
#include "../../../../shared/evidence/ApiMonitorClue.h"

#include <array>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <utility>

namespace {

namespace fs = std::filesystem;
namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
namespace Archive = ks::cli::action_analyze::archive;
namespace Light = Ksword::Features::ActionAnalyze;
using namespace Storage;
constexpr char kProvider[] = "d4a71ada-81b0-4b15-a173-417f33bc8107"; // 合成提供程序身份。
constexpr char kSourceEpoch[] = "12345678-9abc-4def-8123-456789abcdef"; // 合成来源代次。
constexpr wchar_t kSegment[] = L"00000000000000000001.ksaseg"; // 两流各自的首段名。

// 汇总本次原生回归断言，失败立即输出用例名称并交由外层清理。
void Check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

// 读取测试自有文件的原始字节，用于最小变异和确认只读复测不修改资料。
std::string ReadBytes(const fs::path& path) {
    std::ifstream file(path, std::ios::binary); // 测试项目中的固定证据文件。
    Check(static_cast<bool>(file), "read fixture file");
    return {std::istreambuf_iterator<char>(file), {}};
}

// 仅覆写测试程序已创建的文件，调用方保留原字节用于后续用例。
void WriteBytes(const fs::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc); // 测试故障文件。
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    Check(static_cast<bool>(file), "write fixture file");
}

// 用生产写入器生成三条 raw 记录与一条 Coverage，不采集真实进程。
Project::ProjectEtwCheckpoint WriteCapture(Project::ProjectDocument& project, const Project::SampleInfo& sample,
    bool rotated = false) {
    using V = Ksword::Evidence::JsonValue;
    const auto projectId = project.Info()->projectId; // 当前测试项目 UUID。
    Project::SampleRecord checked; // 从生产目录回读的冻结配置。
    Check(static_cast<bool>(project.ReadSample(sample.sampleId, checked)), "read fixture frozen sample");
    const auto plan = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-capture-plan-v1")},
        {"backend", Text("r3")}, {"session", Object({{"id", Text(sample.sampleId)}, {"epoch", Text(kSourceEpoch)}})},
        {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
        {"revisionHash", Text(checked.revisionHash)}, {"configSemanticHash", Text(checked.configSemanticHash)},
        {"providerId", Text(kProvider)}, {"sourceEpoch", Text(kSourceEpoch)}, {"headerPid", V::makeUInt(100)},
        {"processCreationFileTime", Number(101)}, {"durationMs", V::makeUInt(rotated ? 0U : 100U)}}));
    const auto observation = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-observation-v1")},
        {"providerId", Text(kProvider)}, {"sourceEpoch", Text(kSourceEpoch)}, {"headerPid", V::makeUInt(100)},
        {"headerTid", V::makeUInt(200)}, {"descriptor", Object({{"id", V::makeUInt(1)},
            {"version", V::makeUInt(0)}, {"opcode", V::makeUInt(0)}})},
        {"sourceFileTime100ns", Number(102)}, {"originalPayloadBytes", V::makeUInt(4)},
        {"storedPayloadBytes", Number(4)}, {"malformedPayload", V::makeBool(false)},
        {"receiveQpc", Number(30)}, {"qpcFrequencyHz", Number(10)}})); // 序号 2，已知内联原字节。
    const auto end = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-capture-end-v1")},
        {"stopReason", Text(rotated ? "segment-rotated" : "fixture")}, {"finalSegment", V::makeBool(!rotated)},
        {"segmentObservations", Number(1)}, {"source", Object({{"sourceEpoch", Text(kSourceEpoch)},
            {"enqueued", Number(1)}, {"queued", Number(0)}, {"nativeSessionStopped", V::makeBool(true)},
            {"eventsLost", V::makeUInt(0)}, {"logBuffersLost", V::makeUInt(0)},
            {"realTimeBuffersLost", V::makeUInt(0)}, {"queueDropped", Number(0)},
            {"payloadTruncated", Number(0)}, {"malformedPayload", Number(0)}})}})); // 序号 3，结束回执。

    // 生产 writer 按输入分配段内序号。二进制串包含 NUL 和两个非 ASCII 值。
    const std::string_view bytes("\x00\xff\x80\x4b", 4); // 固定 ETW UserData。
    const std::array inputs{Archive::RawEvidenceInput{plan, {}}, Archive::RawEvidenceInput{observation, bytes},
        Archive::RawEvidenceInput{end, {}}}; // 一块内的三条 raw 记录。
    Archive::RawEvidenceReceipt raw; // 生产写入并刷盘后的端点。
    const auto written = project.WriteRawEvidenceSegment({projectId, sample.sampleId, 1, {}, [&](auto& writer) {
        return writer.Append(inputs).result.status == Archive::SegmentWriteStatus::Ok ? Project::ProjectResult{} :
            Failure(Project::ProjectError::IoError, "fixtureRawAppend");
    }}, raw);
    Check(written && raw.flushed.has_value(), "write fixture raw");

    const Archive::EtwCoverageV1 coverage{kProvider, kSourceEpoch, 1, 1, 3, 1, 0, 0, 0, 0, 0, 0}; // 与 raw 逐字段匹配。
    Project::ProjectEtwCheckpoint checkpoint; // 两条已刷流的生产终态标记。
    Check(static_cast<bool>(project.PublishEtwCheckpoint(sample.sampleId, *raw.flushed, coverage, checkpoint)),
        "publish fixture checkpoint");
    return checkpoint;
}

// 写入单段导入的历史格式，可显式声明当时的合作输入。
void WriteApiClue(Project::ProjectDocument& project, const Project::SampleInfo& sample, bool cooperative = false) {
    namespace Evidence = Ksword::Evidence;
    namespace Monitor = ks::winapi_monitor;
    Monitor::ApiMonitorEventPacket packet{};
    packet.size = sizeof(packet);
    packet.version = Monitor::kProtocolVersion;
    packet.eventKind = static_cast<std::uint32_t>(Monitor::EventKind::ApiCall);
    packet.category = static_cast<std::uint32_t>(Monitor::EventCategory::Memory);
    packet.pid = 100;
    packet.tid = 200;
    packet.sessionIdentity = 1;
    wcscpy_s(packet.moduleName, L"kernelbase.dll");
    wcscpy_s(packet.apiName, L"WriteProcessMemory");
    const auto clue = Evidence::WriteJson(Object({{"kind", Text(Evidence::kApiMonitorClueRecord)},
        {"sourceSequence", Number(3)}}));
    Evidence::JsonObject terminal{{"kind", Text(Evidence::kApiMonitorClueEnd)},
        {"sourceRows", Number(4)}, {"clueRows", Number(1)}}; // 旧单段从尾记确定输入语义。
    if (cooperative) terminal.emplace_back("archiveSource", Text("cooperative-pipe"));
    const auto end = Evidence::WriteJson(Object(std::move(terminal)));
    const std::array inputs{Archive::RawEvidenceInput{clue, {reinterpret_cast<const char*>(&packet), sizeof(packet)}},
        Archive::RawEvidenceInput{end, {}}};
    Archive::RawEvidenceReceipt raw;
    const auto written = project.WriteRawEvidenceSegment({project.Info()->projectId, sample.sampleId, 1, {}, [&](auto& writer) {
        return writer.Append(inputs).result.status == Archive::SegmentWriteStatus::Ok ? Project::ProjectResult{} :
            Failure(Project::ProjectError::IoError, "fixtureApiAppend");
    }}, raw);
    Check(written && raw.flushed.has_value(), "write fixture API import");
}

// 使用生产写入器和检查点发布器生成固定的离线原包，无实际 API 操作。
void WriteFollowSegment(Project::ProjectDocument& project, const Project::SampleInfo& sample,
    std::uint64_t ordinal, const Project::ProjectApiCheckpoint* previous, bool terminal, bool legacy,
    Project::ProjectApiCheckpoint* published, bool cooperative = false) {
    using namespace Ksword::Evidence;
    namespace Monitor = ks::winapi_monitor;
    Project::SampleRecord checked;
    Check(static_cast<bool>(project.ReadSample(sample.sampleId, checked)), "read frozen API follow sample");
    JsonObject planFields{{"kind", Text(Project::kApiFollowPlanKind)},
        {"projectId", Text(project.Info()->projectId)}, {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
        {"revisionHash", Text(checked.revisionHash)}, {"configSemanticHash", Text(checked.configSemanticHash)},
        {"sourceEpoch", Text(kSourceEpoch)}, {"session", Object({{"id", Text(sample.sampleId)}, {"epoch", Text(kSourceEpoch)}})},
        {"durationMs", JsonValue::makeUInt(0)}, {"readerPid", JsonValue::makeUInt(100)},
        {"readerCreation100ns", Number(101)}, {"sessionIdentity", Number(1)}};
    if (cooperative) {
        planFields.emplace_back("archiveSource", Text("cooperative-pipe"));
    } else {
        planFields.emplace_back("identity", Text("archive-consistency-only"));
        planFields.emplace_back("file", Object({{"fileId", Text("123456789abc4def8123456789abcdef")},
            {"volumeSerial", Number(9)}, {"initialVisibleBytes", Number(0)}}));
    }
    if (!legacy) planFields.emplace_back("checkpointRequired", JsonValue::makeBool(true));
    const auto plan = WriteJson(Object(std::move(planFields)));

    Monitor::ApiMonitorEventPacket packet{};
    packet.size = sizeof(packet);
    packet.version = Monitor::kProtocolVersion;
    packet.eventKind = static_cast<std::uint32_t>(Monitor::EventKind::ApiCall);
    packet.category = static_cast<std::uint32_t>(Monitor::EventCategory::Memory);
    packet.pid = 100;
    packet.tid = 200;
    packet.sessionIdentity = 1;
    wcscpy_s(packet.moduleName, L"kernelbase.dll");
    wcscpy_s(packet.apiName, L"WriteProcessMemory");
    const std::string_view bytes(reinterpret_cast<const char*>(&packet), sizeof(packet));
    auto unclassified = packet;
    wcscpy_s(unclassified.apiName, L"ReadProcessMemory");
    const std::string_view unclassifiedBytes(reinterpret_cast<const char*>(&unclassified), sizeof(unclassified));
    const auto previousSource = previous ? previous->lastSourceSequence : 0;
    // 合作终段只放尾记。上一段同时包含分类和未分类普通包。
    const std::size_t count = terminal ? (cooperative ? 0 : 2) : 256;
    std::vector<std::string> packetMetadata;
    packetMetadata.reserve(count);
    std::vector<Archive::RawEvidenceInput> input{{plan, {}}};
    for (std::size_t index = 0; index < count; ++index) {
        packetMetadata.push_back(WriteJson(Object({{"kind", Text(Project::kApiFollowPacketKind)},
            {"sourceSequence", Number(previousSource + index + 1)}, {"readerCreation100ns", Number(101)}})));
        const bool rawOnly = cooperative ? index != 0 : terminal && index == 1; // 未分类包也计入水位。
        input.push_back({packetMetadata.back(), rawOnly ? unclassifiedBytes : bytes});
    }
    const auto sourceKind = cooperative ? "cooperative-pipe" : "passive-api-archive"; // 两类计划对应各自的终段来源回执。
    JsonObject source{{"kind", Text(sourceKind)}, {"readerPid", JsonValue::makeUInt(100)},
        {"readerCreation100ns", Number(101)}, {"sessionIdentity", Number(1)}, {"validatedRows", Number(previousSource + count)}};
    if (cooperative) {
        source.emplace_back("state", Text("pipe-eof"));
        source.emplace_back("agentReportedDrops", Number(0));
        source.emplace_back("invalidPackets", Number(0));
    } else {
        source.emplace_back("identity", Text("archive-consistency-only"));
        source.emplace_back("coverage", Text("unknown"));
        source.emplace_back("writerReceipt", JsonValue::makeNull());
        source.emplace_back("state", Text("cutoff"));
        source.emplace_back("cutoffReached", JsonValue::makeBool(true));
        source.emplace_back("partialLineBytes", Number(0));
    }
    const auto end = WriteJson(Object({{"kind", Text(Project::kApiFollowEndKind)}, {"stopReason", Text("fixture")},
        {"source", Object(std::move(source))}}));
    if (terminal) input.push_back({end, {}});

    Archive::RawEvidenceReceipt raw;
    const auto written = project.WriteRawEvidenceSegment({project.Info()->projectId, sample.sampleId, ordinal,
        previous ? previous->rawEnd.lastSequence : 0, [&](auto& writer) {
            return writer.Append(input).result.status == Archive::SegmentWriteStatus::Ok ? Project::ProjectResult{} :
                Failure(Project::ProjectError::IoError, "fixtureFollowAppend");
        }}, raw);
    Check(written && raw.flushed.has_value(), "write fixture API follow segment");
    if (published) {
        Check(static_cast<bool>(Project::PublishApiCheckpoint(project, sample.sampleId, ordinal, raw, input, previous, *published)),
            "publish fixture API follow checkpoint");
    }
}

void VerifyApiFollowReplay(Project::ProjectDocument& writer, const fs::path& root, const std::wstring& manifest) {
    Project::SampleInfo sample, legacy, pending;
    Check(writer.Open(manifest, Project::ProjectAccess::ReadWrite) && writer.CreateSample("API follow", sample) &&
        writer.CreateSample("old API follow", legacy) && writer.CreateSample("pending API follow", pending), "register API follow fixtures");
    const auto projectId = writer.Info()->projectId;
    WriteFollowSegment(writer, legacy, 1, nullptr, true, true, nullptr);
    WriteFollowSegment(writer, pending, 1, nullptr, true, false, nullptr);
    Project::ProjectApiCheckpoint committed;
    for (std::uint64_t ordinal = 1; ordinal <= 17; ++ordinal) {
        WriteFollowSegment(writer, sample, ordinal, committed.ordinal ? &committed : nullptr, ordinal == 17, false, &committed);
    }
    writer.Close();

    const Light::ProjectReplayRequest request{manifest, projectId, sample.sampleId, sample.descriptionHash};
    const Light::ProjectReplayRequest legacyRequest{manifest, projectId, legacy.sampleId, legacy.descriptionHash};
    const Light::ProjectReplayRequest pendingRequest{manifest, projectId, pending.sampleId, pending.descriptionHash};
    for (const auto mode : {Light::ProjectReplayMode::Explicit, Light::ProjectReplayMode::SelectionPreview}) {
        const auto legacyResult = Light::ReadProjectReplay(legacyRequest, mode);
        Check(legacyResult.checkpoint.kind == Light::ReplayCheckpointKind::PassiveApi &&
            legacyResult.checkpoint.state == Light::CheckpointState::NotPublished && !legacyResult.raw.identity &&
            legacyResult.raw.rows.empty(), "legacy API follow has no published records");
        const auto pendingResult = Light::ReadProjectReplay(pendingRequest, mode);
        Check(pendingResult.checkpoint.kind == Light::ReplayCheckpointKind::PassiveApi &&
            pendingResult.checkpoint.state == Light::CheckpointState::Pending && pendingResult.checkpoint.pendingOrdinal == 1 &&
            !pendingResult.raw.identity && pendingResult.raw.rows.empty(), "unpublished API first segment stays hidden");
    }

    const auto preview = Light::ReadProjectReplay(request, Light::ProjectReplayMode::SelectionPreview);
    Check(preview.checkpoint.kind == Light::ReplayCheckpointKind::PassiveApi && preview.checkpoint.state == Light::CheckpointState::PreviewLimited &&
        preview.checkpoint.lastVerifiedOrdinal == 1 && preview.raw.rows.size() == 257 && preview.raw.apiClues == 256,
        "API selection preview stops at the first checkpoint");
    const auto& clue = preview.raw.rows[1];
    Check(clue.segmentOrdinal == 1 && clue.blockOrdinal == 1 && clue.sequence == 2 && clue.offset > Archive::kSegmentHeaderBytes &&
        clue.apiFamily == L"memory-write" && clue.headerPid == std::uint32_t{100} && clue.headerTid == std::uint32_t{200} &&
        !clue.eventOrdinal && !clue.targetObjectId && clue.preview.find(L"源归档行号：1\r\n") != std::wstring::npos,
        "API packet uses verified segment coordinates and source line");

    const auto base = root / L"samples" / WideAscii(sample.sampleId);
    const auto checkLegacyGate = [&](const Project::SampleInfo& fixture, bool requiresCheckpoint) {
        const auto path = root / L"samples" / WideAscii(fixture.sampleId) / L"raw" / kSegment;
        Storage::Handle file(::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
        Check(file.get() != INVALID_HANDLE_VALUE, "open fixture at the legacy project fallback boundary");
        const Light::SegmentIdentity expected{projectId, fixture.sampleId, static_cast<std::uint32_t>(Archive::StreamKind::Raw), 1};
        const auto gated = Light::ReadOpenStoredEvidence(file.get(), std::nullopt, &expected, Light::StoredReadMode::LegacyProject);
        Check(gated.apiFollowRequiresCheckpoint == requiresCheckpoint && gated.rows.empty() && gated.blocks == 0 &&
            gated.framedBytes == Archive::kSegmentHeaderBytes, "legacy fallback stops at an API follow plan before projecting its block");
    };
    checkLegacyGate(legacy, false);
    checkLegacyGate(pending, true);
    const auto first = ReadBytes(base / L"raw" / kSegment);
    constexpr auto sequenceOffset = 16; // Stored v1 记录头内的归档序号字段。
    Check(clue.offset + sequenceOffset + 8 <= first.size() &&
        first.compare(static_cast<std::size_t>(clue.offset) + sequenceOffset, 8, "\x02\0\0\0\0\0\0\0", 8) == 0,
        "API record offset resolves directly to the archived sequence");
    const auto terminalPath = base / L"raw" / L"00000000000000000017.ksaseg";
    const auto terminal = ReadBytes(terminalPath);
    WriteBytes(terminalPath, terminal + "unpublished tail");
    const auto full = Light::ReadProjectReplay(request);
    Check(full.checkpoint.state == Light::CheckpointState::Verified && full.checkpoint.lastVerifiedOrdinal == 17 &&
        full.checkpoint.recordsEnd == 0 && full.checkpoint.rawEnd == committed.rawEnd.byteOffset &&
        full.raw.decodedPrefixBytes == committed.rawEnd.byteOffset && full.raw.fileBytes > full.raw.decodedPrefixBytes &&
        full.raw.apiClues == 4097 && full.raw.rows.size() == Light::kEvidenceRows &&
        full.raw.rows.front().sequence == committed.rawEnd.lastSequence - Light::kEvidenceRows + 1 &&
        full.raw.rows.back().segmentOrdinal == 17 && full.raw.rows.back().sequence == committed.rawEnd.lastSequence,
        "API explicit replay keeps recent window and excludes appended tail");
    const auto& unclassified = full.raw.rows[full.raw.rows.size() - 2];
    Check(unclassified.segmentOrdinal == 17 && unclassified.sequence == committed.rawEnd.lastSequence - 1 &&
        unclassified.apiFamily.empty() && unclassified.apiClue.empty() &&
        unclassified.preview.find(L"内联原始字节（1000 字节）") != std::wstring::npos,
        "verified unclassified packet stays in the raw replay");
    Check(ReadBytes(terminalPath) == terminal + "unpublished tail", "API replay leaves authorized raw bytes untouched");

    const auto markerPath = base / L"checkpoints" / L"00000000000000000017.json";
    const auto marker = ReadBytes(markerPath);
    auto changed = marker;
    const auto hash = changed.find(committed.rawSha256);
    Check(hash != std::string::npos, "terminal marker has raw hash");
    changed.replace(hash, 64, std::string(64, '0'));
    WriteBytes(markerPath, changed);
    const auto rejected = Light::ReadProjectReplay(request);
    Check(rejected.checkpoint.state == Light::CheckpointState::Partial && rejected.checkpoint.lastVerifiedOrdinal == 16 &&
        rejected.checkpoint.pendingOrdinal == 17 && rejected.raw.rows.size() == Light::kEvidenceRows &&
        rejected.raw.rows.back().segmentOrdinal == 16 && rejected.raw.apiClues == 4096,
        "changed digest discards rows staged by the visitor before digest verification");
    Check(fs::remove(markerPath), "remove fixture terminal API marker");
    const auto wait = Light::ReadProjectReplay(request);
    Check(wait.checkpoint.state == Light::CheckpointState::Pending && wait.checkpoint.pendingOrdinal == 17 &&
        wait.raw.rows.size() == Light::kEvidenceRows && wait.raw.rows.back().segmentOrdinal == 16,
        "missing marker keeps only preceding API segments");
    WriteBytes(markerPath, marker);
    WriteBytes(terminalPath, terminal.substr(0, terminal.size() - 1));
    Check(Light::ReadProjectReplay(request).checkpoint.lastVerifiedOrdinal == 16, "truncated API raw keeps previous checkpoint");
    WriteBytes(terminalPath, terminal);
    Check(Light::ReadProjectReplay(request).checkpoint.state == Light::CheckpointState::Verified, "restored API terminal replays");
}

// 通过正式读回入口测试合作多段、缺末标记和零包终段，全部输入为本地合成封装。
void VerifyCooperativeApiReplay(Project::ProjectDocument& writer, const fs::path& root, const std::wstring& manifest) {
    using Ksword::Evidence::ApiMonitorArchiveSource;
    Project::SampleInfo sample, empty, legacy; // 分别覆盖多段采样、零普通包终段和旧单段导入。
    Check(writer.Open(manifest, Project::ProjectAccess::ReadWrite) && writer.CreateSample("cooperative API", sample) &&
        writer.CreateSample("empty cooperative API", empty) && writer.CreateSample("legacy cooperative API", legacy),
        "register cooperative API fixtures");
    const auto projectId = writer.Info()->projectId; // 正常读回使用已登记项目的实际 ID。
    Project::ProjectApiCheckpoint first, terminal, emptyTerminal; // 写端实际发布的基准端点。
    WriteFollowSegment(writer, sample, 1, nullptr, false, false, &first, true);
    WriteFollowSegment(writer, sample, 2, &first, true, false, &terminal, true);
    WriteFollowSegment(writer, empty, 1, nullptr, true, false, &emptyTerminal, true);
    WriteApiClue(writer, legacy, true);
    writer.Close();

    const auto result = Light::ReadProjectReplay({manifest, projectId, sample.sampleId, sample.descriptionHash});
    Check(result.checkpoint.state == Light::CheckpointState::Verified && result.checkpoint.lastVerifiedOrdinal == 2 &&
        result.checkpoint.apiArchiveSource == ApiMonitorArchiveSource::CooperativePipe &&
        result.apiSourcePackets == 256 && result.raw.apiClues == 1 && result.raw.rows.size() == 259 &&
        result.raw.lastSequence == terminal.rawEnd.lastSequence && result.raw.decodedPrefixBytes == terminal.rawEnd.byteOffset,
        "cooperative API replay uses terminal segment and cumulative packet count");
    const auto& clue = result.raw.rows[1]; // 首个普通包是唯一分类线索，下一包仍可作为原始记录回放。
    Check(clue.segmentOrdinal == 1 && clue.apiSourceSequence == 1 && clue.apiArchiveSource == ApiMonitorArchiveSource::CooperativePipe &&
        clue.preview.find(L"合作流水号（非 JSONL 行号）：1\r\n") != std::wstring::npos && result.raw.rows[2].apiClue.empty(),
        "cooperative clue uses its actual segment and call sequence");

    const auto emptyResult = Light::ReadProjectReplay({manifest, projectId, empty.sampleId, empty.descriptionHash});
    Check(emptyResult.raw.identity && emptyResult.checkpoint.state == Light::CheckpointState::Verified &&
        emptyResult.checkpoint.lastVerifiedOrdinal == 1 && emptyResult.checkpoint.apiArchiveSource == ApiMonitorArchiveSource::CooperativePipe &&
        emptyResult.apiSourcePackets == 0 && emptyResult.raw.apiClues == 0 &&
        emptyResult.raw.decodedPrefixBytes == emptyTerminal.rawEnd.byteOffset, "cooperative empty terminal identifies its source");

    const auto legacyResult = Light::ReadProjectReplay({manifest, projectId, legacy.sampleId, legacy.descriptionHash});
    Check(legacyResult.checkpoint.state == Light::CheckpointState::NotPublished && legacyResult.raw.rows.size() == 1 &&
        legacyResult.raw.apiClues == 1 && legacyResult.raw.rows[0].apiArchiveSource == ApiMonitorArchiveSource::CooperativePipe &&
        legacyResult.raw.rows[0].preview.find(L"合作流水号（非 JSONL 行号）：3\r\n") != std::wstring::npos,
        "legacy single-segment cooperative clues keep the validated source and call sequence");

    const auto marker = root / L"samples" / WideAscii(sample.sampleId) / L"checkpoints" / L"00000000000000000002.json";
    Check(fs::remove(marker), "remove cooperative fixture terminal marker");
    const auto prefix = Light::ReadProjectReplay({manifest, projectId, sample.sampleId, sample.descriptionHash});
    Check(prefix.checkpoint.state == Light::CheckpointState::Pending && prefix.checkpoint.pendingOrdinal == 2 &&
        prefix.checkpoint.lastVerifiedOrdinal == 1 && prefix.checkpoint.apiArchiveSource == ApiMonitorArchiveSource::CooperativePipe &&
        prefix.apiSourcePackets == 256 && prefix.raw.apiClues == 1 && prefix.raw.rows.size() == 257 &&
        prefix.raw.decodedPrefixBytes == first.rawEnd.byteOffset, "cooperative prefix retains count and coordinates without a terminal marker");
}

void VerifyCallbackReplay(Project::ProjectDocument& writer, const fs::path& root, const std::wstring& manifest) {
    Check(static_cast<bool>(writer.Open(manifest, Project::ProjectAccess::ReadWrite)), "open callback fixture project");
    Project::SampleInfo positive, empty, missing;
    Check(writer.CreateSample("callback observation", positive) && writer.CreateSample("empty callback batch", empty) &&
        writer.CreateSample("unpublished callback batch", missing), "register callback samples");
    const auto projectId = writer.Info()->projectId;
    const Project::ProjectCallbackEvidencePlan plan{kSourceEpoch, 100, 4};
    const Project::ProjectCallbackEvidenceEnd end{Project::CallbackBatchState::CaughtUp, 102, 102, 2, 0, std::nullopt};
    KSWORD_ARK_CALLBACK_MONITOR_EVENT event{};
    event.version = KSWORD_ARK_CALLBACK_MONITOR_PROTOCOL_VERSION;
    event.size = static_cast<unsigned long>(sizeof(event));
    event.category = KSWORD_ARK_CALLBACK_MONITOR_CATEGORY_THREAD;
    event.operation = KSWORD_ARK_THREAD_OP_CREATE;
    event.sequence = 102;
    event.originatingProcessId = 100;
    event.originatingThreadId = 101;
    event.targetProcessId = 200;
    event.targetThreadId = 201;
    event.timeUtc100ns = 132903391110000000LL;
    Project::ProjectCallbackEvidenceReceipt written, emptyWritten;
    Check(static_cast<bool>(Project::WriteInitialCallbackEvidence(writer, positive.sampleId, plan, end, {&event, 1}, written)),
        "write callback observation without opening the driver");
    const Project::ProjectCallbackEvidenceEnd emptyEnd{Project::CallbackBatchState::CaughtUp, 101, 101, 1, std::nullopt, 0};
    Check(static_cast<bool>(Project::WriteInitialCallbackEvidence(writer, empty.sampleId, plan, emptyEnd, {}, emptyWritten)),
        "write complete empty callback batch with a non-thread raw return");
    writer.Close();

    const auto request = [&](const Project::SampleInfo& sample) {
        return Light::ProjectReplayRequest{manifest, projectId, sample.sampleId, sample.descriptionHash};
    };
    const auto path = root / L"samples" / WideAscii(positive.sampleId) / L"raw" / kSegment;
    const auto bytes = ReadBytes(path);
    const auto& receipt = written.records.front();
    const auto verifyFailure = [](const Light::ProjectReplayEvidence& result) {
        Check(!result.raw.diagnostic.empty() && result.raw.rows.empty() && !result.callback,
            "callback failure must not publish a partial batch or a complete empty batch");
    };
    for (const auto mode : {Light::ProjectReplayMode::Explicit, Light::ProjectReplayMode::SelectionPreview}) {
        const auto result = Light::ReadProjectReplay(request(positive), mode);
        Check(result.callback && result.raw.identity && result.raw.identity->sampleId == positive.sampleId &&
            result.raw.identity->streamKind == 1 && result.raw.identity->ordinal == 1 && result.raw.rows.size() == 1 &&
            result.raw.records == 3 && result.raw.diagnostic.empty() && result.raw.fileBytes == bytes.size() &&
            result.raw.decodedPrefixBytes == written.boundary.byteOffset && result.checkpoint.kind == Light::ReplayCheckpointKind::None,
            "verified callback batch projects observations without a checkpoint");
        const auto& row = result.raw.rows.front();
        Check(row.callback && row.callback->sourceSequence == event.sequence && row.sequence == receipt.rawSequence &&
            row.sequence == 2 && row.segmentOrdinal == written.segmentOrdinal && row.blockOrdinal == written.boundary.blockOrdinal &&
            row.offset == receipt.rawOffset && row.callback->inlineOffset == receipt.inlineOffset && row.callback->inlineBytes == sizeof(event) &&
            bytes.substr(static_cast<std::size_t>(row.callback->inlineOffset), row.callback->inlineBytes) ==
                std::string_view(reinterpret_cast<const char*>(&event), sizeof(event)), "callback row uses exact file coordinates and bytes");
        Check(row.callback->contextPid == 100 && row.callback->contextTid == 101 && row.callback->targetPid == 200 &&
            row.callback->targetTid == 201 && row.callback->sourceUtc100ns == event.timeUtc100ns &&
            !row.headerPid && !row.headerTid && !row.eventOrdinal && !row.actorObjectId && !row.targetObjectId && !row.threadObjectId &&
            !row.receiveQpc && row.apiClue.empty() && !row.etw && !row.network, "callback IDs stay hints and FILETIME is not QPC");
        Check(result.callback->prefixSha256 == written.prefixSha256 && result.callback->plan.sourceEpoch == kSourceEpoch &&
            result.callback->end.lostBeforeFirst == 0 && !result.callback->end.droppedCount &&
            Light::CallbackReplayDetails(*result.callback).find(L"采集覆盖：未知") != std::wstring::npos,
            "known zero loss and absent cumulative count do not establish coverage");

        const auto verifiedEmpty = Light::ReadProjectReplay(request(empty), mode);
        Check(verifiedEmpty.callback && verifiedEmpty.raw.identity && verifiedEmpty.raw.diagnostic.empty() &&
            verifiedEmpty.raw.rows.empty() && verifiedEmpty.raw.records == 2 && verifiedEmpty.callback->end.returnedCount == 1 &&
            !verifiedEmpty.callback->end.lostBeforeFirst && verifiedEmpty.callback->end.droppedCount == 0 &&
            verifiedEmpty.callback->prefixSha256 == emptyWritten.prefixSha256, "complete empty callback batch retains its receipt");
        verifyFailure(Light::ReadProjectReplay(request(missing), mode));
    }
    const auto standalone = Light::OpenStoredEvidence(path.wstring());
    Check(!standalone.identity && standalone.rows.empty() && !standalone.diagnostic.empty(), "standalone opening cannot bypass sample binding");
    Check(ReadBytes(path) == bytes, "callback replay leaves bytes untouched");
    for (const auto& damaged : {bytes + "torn", bytes.substr(0, bytes.size() - 1), bytes.substr(0, Archive::kSegmentHeaderBytes)}) {
        WriteBytes(path, damaged);
        for (const auto mode : {Light::ProjectReplayMode::Explicit, Light::ProjectReplayMode::SelectionPreview}) {
            verifyFailure(Light::ReadProjectReplay(request(positive), mode));
        }
        Check(ReadBytes(path) == damaged, "failed callback replay does not repair bytes");
    }
    WriteBytes(path, bytes);
    Check(Light::ReadProjectReplay(request(positive)).callback.has_value(), "restored callback archive replays");
}

// 在不会覆盖已有输出的固定项目目录，验证 Light 同一生产入口的成功与失败情形。
void Run(const fs::path& folder) {
    const auto root = folder / L"项目"; // 有界 Unicode 项目路径。
    const auto manifest = (root / L"project.ksaproj").wstring(); // 用户选择的文件身份。
    const auto created = Light::CreateProjectReplayCatalog(root.wstring());
    Check(created.diagnostic.empty() && !created.projectId.empty() && created.manifestPath == manifest && created.choices.empty(),
        "create empty Unicode project through the Light adapter");
    Check(!Light::CreateProjectReplayCatalog(root.wstring()).diagnostic.empty(), "create refuses an existing project directory");
    Project::ProjectDocument writer; // 仅用于准备这次自有测试数据。
    Check(static_cast<bool>(writer.Open(manifest, Project::ProjectAccess::ReadWrite)), "open fixture project for collection");
    const auto emptyCatalog = Light::ReadProjectReplayCatalog(manifest);
    Check(emptyCatalog.diagnostic.empty() && emptyCatalog.choices.empty() && emptyCatalog.projectId == created.projectId &&
        emptyCatalog.manifestPath == manifest, "empty catalog carries project identity before the first sample");
    Project::SampleInfo sample; // 采样身份用于生成独立的 raw 和 records 路径。
    Project::SampleInfo other; // 名称相同的已登记采样，验证选择不能仅依赖标题。
    Check(writer.CreateSample("同名采样", sample) && writer.CreateSample("同名采样", other), "register two samples");
    const auto checkpoint = WriteCapture(writer, sample); // 预期验证端点。
    writer.Close();

    const auto catalog = Light::ReadProjectReplayCatalog(manifest); // 生产只读目录适配器。
    Check(catalog.diagnostic.empty() && catalog.choices.size() == 2, "catalog has both committed samples");
    const auto& request = catalog.choices.front().request; // 模拟用户确认后冻结的完整请求。
    Check(request.sampleId == sample.sampleId && request.descriptionHash == sample.descriptionHash &&
        catalog.choices[1].request.sampleId == other.sampleId, "exact sample identities");
    const auto archive = root / L"samples" / WideAscii(sample.sampleId); // 首个采样内两流路径。
    const auto rawPath = archive / L"raw" / kSegment;
    const auto recordsPath = archive / L"records" / kSegment;
    const auto markerPath = archive / L"checkpoints" / L"00000000000000000001.json";
    const auto raw = ReadBytes(rawPath); // 记住原件，验证全部读回不写入测试项目。
    const auto records = ReadBytes(recordsPath);
    const auto marker = ReadBytes(markerPath);

    const auto initial = Light::ReadProjectReplay(request); // 同一文件散列后重新定位投影。
    Check(initial.checkpoint.state == Light::CheckpointState::Verified && initial.raw.diagnostic.empty() &&
        initial.raw.rows.size() == 3 && initial.raw.decodedPrefixBytes == checkpoint.raw.end.byteOffset &&
        initial.checkpoint.recordsEnd == checkpoint.records.end.byteOffset, "verified extent and row count");
    Check(initial.raw.rows[1].etw && initial.raw.rows[1].etw->sourceEpoch == kSourceEpoch &&
        initial.raw.rows[1].preview.find(L"00 ff 80 4b") != std::wstring::npos, "exact archived ETW bytes");
    const auto previewMode = Light::ProjectReplayMode::SelectionPreview;
    const auto initialPreview = Light::ReadProjectReplay(request, previewMode);
    Check(initialPreview.checkpoint.state == Light::CheckpointState::Verified && initialPreview.raw.rows.size() == 3 &&
        initialPreview.raw.rows[1].etw && initialPreview.raw.decodedPrefixBytes == checkpoint.raw.end.byteOffset,
        "selection preview verifies a single terminal checkpoint");
    Check(ReadBytes(rawPath) == raw && ReadBytes(recordsPath) == records && ReadBytes(markerPath) == marker,
        "verified read leaves original files untouched");

    // raw 追加一个重复块，records 模拟断尾。已提交范围保持不变。
    WriteBytes(rawPath, raw + raw.substr(Archive::kSegmentHeaderBytes));
    WriteBytes(recordsPath, records + "torn");
    const auto tailed = Light::ReadProjectReplay(request); // 坏尾不影响已提交范围。
    Check(tailed.checkpoint.state == Light::CheckpointState::Verified && tailed.raw.rows.size() == 3 &&
        tailed.raw.fileBytes > tailed.raw.decodedPrefixBytes, "both appended tails excluded");
    const auto standalone = Light::OpenStoredEvidence(rawPath.wstring()); // 旧单段入口仍按物理 EOF 判定坏尾。
    Check(standalone.rows.size() == 3 && !standalone.diagnostic.empty(), "single segment retains its diagnostic prefix");
    WriteBytes(rawPath, raw);
    WriteBytes(recordsPath, records);

    // 有标记但依赖失败时结果不携带可发布行。
    const auto reject = [&] (std::string_view label) {
        const auto checked = Light::ReadProjectReplay(request); // 生产项目回放拒绝失败的提交。
        Check(checked.checkpoint.lastVerifiedOrdinal == 0 && !checked.raw.identity &&
            checked.raw.rows.empty() && !checked.raw.diagnostic.empty(), label);
    };
    WriteBytes(recordsPath, records.substr(0, records.size() - 1));
    reject("truncated committed records must not publish");
    Check(fs::remove(recordsPath), "remove fixture records");
    reject("missing records must not fall back");
    WriteBytes(recordsPath, records);
    WriteBytes(rawPath, raw.substr(0, raw.size() - 1));
    reject("truncated committed raw must not publish");
    auto corruptRaw = raw;
    corruptRaw.back() ^= 1;
    WriteBytes(rawPath, corruptRaw);
    reject("bad CRC in committed raw must not publish");
    Check(fs::remove(rawPath), "remove fixture raw");
    reject("missing raw must not fall back");
    WriteBytes(rawPath, raw);
    WriteBytes(markerPath, "{");
    reject("malformed present marker must not fall back");
    auto changedMarker = marker; // 仅篡改 raw 哈希文本，保留可读元数据。
    const auto hashLocation = changedMarker.find(checkpoint.raw.sha256);
    Check(hashLocation != std::string::npos, "find fixture marker raw hash");
    changedMarker.replace(hashLocation, checkpoint.raw.sha256.size(), 64, '0');
    WriteBytes(markerPath, changedMarker);
    reject("changed checkpoint raw hash must not publish");
    WriteBytes(markerPath, marker);
    auto changedRequest = request; // 同一已登记行但冻结描述与重开不符。
    changedRequest.descriptionHash = std::string(64, '0');
    Check(Light::ReadProjectReplay(changedRequest).raw.diagnostic == "corrupt/replayDescriptionHash", "stale description rejected");
    changedRequest = request;
    changedRequest.projectId = other.sampleId;
    Check(Light::ReadProjectReplay(changedRequest).raw.diagnostic == "corrupt/replayProjectId", "wrong project rejected");

    // 只有真正缺少提交标记的自有项目才显示独立的旧 raw 预览状态。
    Check(fs::remove(markerPath), "remove fixture marker");
    const auto legacy = Light::ReadProjectReplay(request); // 原 raw 无改动，按旧档读取。
    Check(legacy.checkpoint.state == Light::CheckpointState::NotPublished && legacy.raw.rows.size() == 3 &&
        legacy.checkpoint.recordsEnd == 0, "legacy raw is visible without a durability claim");
    WriteBytes(rawPath, raw + "broken");
    const auto legacyTail = Light::ReadProjectReplay(request); // 旧档只显示真实可用的诊断前缀。
    Check(legacyTail.checkpoint.state == Light::CheckpointState::NotPublished && legacyTail.raw.rows.size() == 3 &&
        !legacyTail.raw.diagnostic.empty(), "legacy bad tail retains its verified prefix");
    fs::resize_file(rawPath, 16ULL * 1024 * 1024 + 1);
    const auto largePreview = Light::ReadProjectReplay(request, previewMode);
    Check(!largePreview.raw.identity && largePreview.raw.rows.empty() && largePreview.raw.diagnostic == "replaySelectionLimit",
        "selection preview bounds an uncheckpointed raw file before decoding");
    Check(Light::ReadProjectReplay(request).raw.rows.size() == 3, "explicit replay still reads the available legacy prefix");

    // 旧档不能接收另一个采样的段，即使路径和文件名相同。
    const auto otherArchive = root / L"samples" / WideAscii(other.sampleId) / L"raw"; // 自有第二个采样。
    Check(fs::create_directory(otherArchive), "create second fixture raw folder");
    WriteBytes(otherArchive / kSegment, raw);
    const auto wrong = Light::ReadProjectReplay(catalog.choices[1].request);
    Check(!wrong.raw.identity && wrong.raw.rows.empty() && wrong.raw.diagnostic == "segment.identity", "cross-sample legacy raw rejected");
    WriteBytes(rawPath, raw);
    WriteBytes(markerPath, marker);
    Check(Light::ReadProjectReplay(request).checkpoint.state == Light::CheckpointState::Verified,
        "retry succeeds after fixture restoration");

    Check(static_cast<bool>(writer.Open(manifest, Project::ProjectAccess::ReadWrite)), "reopen for continuous fixture");
    Project::SampleInfo rotating;
    Check(static_cast<bool>(writer.CreateSample("continuous preview", rotating)), "register continuous fixture sample");
    const auto rotated = WriteCapture(writer, rotating, true);
    Check(!rotated.finalSegment, "fixture publishes a nonterminal checkpoint");
    Project::SampleInfo imported;
    Check(static_cast<bool>(writer.CreateSample("API preview", imported)), "register API fixture sample");
    WriteApiClue(writer, imported);
    writer.Close();

    const Light::ProjectReplayRequest rotatingRequest{manifest, request.projectId, rotating.sampleId, rotating.descriptionHash};
    const auto quick = Light::ReadProjectReplay(rotatingRequest, previewMode);
    Check(quick.checkpoint.state == Light::CheckpointState::PreviewLimited && quick.checkpoint.lastVerifiedOrdinal == 1 &&
        quick.checkpoint.pendingOrdinal == 0 && quick.raw.rows.size() == 3,
        "selection preview stops at the first verified segment without investigating later markers");
    const auto explicitReplay = Light::ReadProjectReplay(rotatingRequest);
    Check(explicitReplay.checkpoint.state == Light::CheckpointState::Pending && explicitReplay.checkpoint.pendingOrdinal == 2 &&
        explicitReplay.raw.rows.size() == 3, "explicit replay reads beyond the first segment and reports the pending marker");

    const Light::ProjectReplayRequest apiRequest{manifest, request.projectId, imported.sampleId, imported.descriptionHash};
    const auto api = Light::ReadProjectReplay(apiRequest, previewMode);
    Check(api.checkpoint.state == Light::CheckpointState::NotPublished && api.raw.apiClues == 1 && api.raw.rows.size() == 1 &&
        api.raw.rows[0].apiClue == L"WriteProcessMemory" && api.raw.rows[0].apiFamily == L"memory-write" &&
        !api.raw.rows[0].targetObjectId && !api.raw.rows[0].eventOrdinal, "verified API family without inferred relations");
    const auto apiPath = root / L"samples" / WideAscii(imported.sampleId) / L"raw" / kSegment;
    fs::resize_file(apiPath, fs::file_size(apiPath) - 1);
    const auto brokenApi = Light::ReadProjectReplay(apiRequest, previewMode);
    Check(brokenApi.raw.rows.empty() && brokenApi.raw.apiClues == 0 && !brokenApi.raw.diagnostic.empty(),
        "incomplete API import does not publish classifications");
    VerifyApiFollowReplay(writer, root, manifest);
    VerifyCooperativeApiReplay(writer, root, manifest);
    VerifyCallbackReplay(writer, root, manifest);
}

} // namespace

void VerifyProjectReplay(const std::filesystem::path& testOutput) {
    const auto parent = std::filesystem::canonical(testOutput); // 只接受测试工程的固定输出目录。
    Check(parent.filename() == L"ActionAnalyzeTests" && parent.parent_path().filename() == L"Release" &&
        parent.parent_path().parent_path().filename() == L"x64" &&
        parent.parent_path().parent_path().parent_path().filename() == L"KswordARKLight", "fixed test output");
    const auto folder = parent / L"ProjectReplayFixture"; // 本次独占、可清理的夹具根。
    Check(fs::create_directory(folder), "fixture location must be vacant");
    try {
        Run(folder);
    } catch (...) {
        fs::remove_all(folder);
        throw;
    }
    Check(fs::remove_all(folder) > 0 && !fs::exists(folder), "clean fixture output");
    std::cout << "PASS Light project replay: creation, preview bounds, passive and cooperative API, callback batches, checked streams, identity and retry\n";
}
