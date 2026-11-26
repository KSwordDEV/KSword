#include "ProjectNativeExecution.h"

#include "ProjectStorage.h"

namespace Ksword::ActionAnalyze {
namespace {
namespace native = ks::cli::action_analyze::control;
namespace archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using V = Evidence::JsonValue;

V Document(const ProjectInfo& project, const native::OwnerIdentity& owner,
    const native::NativeExecutionEvidence& observed)
{
    return Object({{"kind", Text("native-execution-v1")}, {"projectId", Text(project.projectId)},
        {"sampleId", Text(owner.sampleId)}, {"sessionId", Text(owner.sessionId)}, {"epoch", Text(owner.epoch)},
        {"source", Text("native-debug-owner")}, {"historical", V::makeBool(true)},
        {"observation", Text(observed.kind == native::NativeExecutionKind::InstructionCompleted ?
            "instruction-completed" : "execution-enter-attempt")},
        {"target", Object({{"processInstanceId", Text(observed.thread.identity.processInstanceId)},
            {"pid", V::makeUInt(observed.pid)}, {"creationFileTime", Number(observed.processCreationFileTime)}})},
        {"thread", Object({{"threadId", Text(observed.thread.identity.threadId)}, {"tid", V::makeUInt(observed.thread.tid)},
            {"creationFileTime", Number(observed.thread.creationTime)}})},
        {"event", Object({{"backendInstanceId", Text(observed.event.backendInstanceId)}, {"serial", Number(observed.event.serial)}})},
        {"groupId", Text(observed.groupId)}, {"stopId", Text(observed.stopId)}, {"stateRevision", Number(observed.stateRevision)},
        {"instructionAddress", Number(observed.instructionAddress)},
        {"nextInstructionAddress", observed.nextInstructionAddress ? Number(*observed.nextInstructionAddress) : V::makeNull()},
        {"observedQpc", observed.observedQpc ? Number(*observed.observedQpc) : V::makeNull()},
        {"qpcFrequency", Number(observed.qpcFrequency)}});
}

bool Positive(const V& object, std::string_view key, std::uint64_t* output = nullptr)
{
    std::uint64_t number = 0;
    if (!GetNumber(object, key, number) || !number) return false;
    if (output) *output = number;
    return true;
}

bool Identifier(const V& object, std::string_view key)
{
    std::string value;
    return GetString(object, key, value) && IsText(value, 1024) && !value.empty();
}

bool ValidDocument(const V& doc, std::string_view projectId, std::string_view sampleId)
{
    if (!Fields(doc, {"kind", "projectId", "sampleId", "sessionId", "epoch", "source", "historical", "observation",
            "target", "thread", "event", "groupId", "stopId", "stateRevision", "instructionAddress",
            "nextInstructionAddress", "observedQpc", "qpcFrequency"}) ||
        !IsString(doc, "kind", "native-execution-v1") || !IsString(doc, "projectId", projectId) ||
        !IsString(doc, "sampleId", sampleId) || !IsString(doc, "source", "native-debug-owner")) return false;
    std::string session, epoch, backend;
    const auto* historical = doc.find("historical");
    bool isHistorical = false;
    if (!GetUuid(doc, "sessionId", session) || !GetUuid(doc, "epoch", epoch) ||
        !historical || !historical->tryGetBool(isHistorical) || !isHistorical ||
        !Identifier(doc, "groupId") || !Identifier(doc, "stopId") ||
        !Positive(doc, "stateRevision") || !Positive(doc, "instructionAddress")) return false;
    const auto* target = doc.find("target");
    const auto* thread = doc.find("thread");
    const auto* event = doc.find("event");
    if (!target || !thread || !event ||
        !Fields(*target, {"processInstanceId", "pid", "creationFileTime"}) ||
        !Fields(*thread, {"threadId", "tid", "creationFileTime"}) ||
        !Fields(*event, {"backendInstanceId", "serial"}) ||
        !Identifier(*target, "processInstanceId") || !Identifier(*thread, "threadId") ||
        !GetUuid(*event, "backendInstanceId", backend) || !Positive(*event, "serial")) return false;
    const auto* pid = target->find("pid");
    const auto* tid = thread->find("tid");
    std::uint64_t processId = 0, threadId = 0;
    std::uint64_t processTime = 0, threadTime = 0;
    if (!pid || pid->type() != Evidence::JsonType::UInt || !pid->tryGetU64(processId) || !processId || processId > MAXDWORD ||
        !tid || tid->type() != Evidence::JsonType::UInt || !tid->tryGetU64(threadId) || !threadId || threadId > MAXDWORD ||
        !Positive(*target, "creationFileTime", &processTime) || !Positive(*thread, "creationFileTime", &threadTime) ||
        threadTime < processTime) return false;
    std::uint64_t frequency = 0;
    if (!GetNumber(doc, "qpcFrequency", frequency) ||
        (!IsNull(doc, "observedQpc") && (!frequency || !Positive(doc, "observedQpc")))) return false;
    if (IsString(doc, "observation", "instruction-completed")) return Positive(doc, "nextInstructionAddress");
    return IsString(doc, "observation", "execution-enter-attempt") && IsNull(doc, "nextInstructionAddress");
}
} // namespace

ProjectResult ReadNativeExecution(const ProjectDocument& project, std::string_view sampleId,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence, ArchivedNativeExecution& out)
{
    out = {};
    const auto* info = project.Info();
    if (!info) return Failure(ProjectError::NotOpen, "project");
    ArchivedNativeExecution staged;
    std::size_t count = 0;
    bool valid = true;
    const auto visit = [&](const auto&, const auto& block, const std::vector<archive::DecodedRecord>& records) {
        for (const auto& record : records) {
            const auto* body = std::get_if<archive::RawRecordV1>(&record.body);
            if (++count != 1 || !body || !body->inlineRawData.empty()) { valid = false; return false; }
            const auto parsed = Evidence::ParseJson(body->metadataJson);
            if (!parsed.ok() || !ValidDocument(parsed.value, info->projectId, sampleId)) { valid = false; return false; }
            staged.document = parsed.value;
            staged.recordOffset = record.recordOffset; // 只随整段身份、正文及散列核验成功发布。
            staged.blockOrdinal = block.ordinal;
        }
        return true;
    };
    const ProjectRawEvidenceRead request{info->projectId, sampleId, ordinal, std::nullopt, previousSequence,
        visit, 64 * 1024, ProjectEvidenceLane::NativeExecution};
    archive::RawEvidenceScanResult scanned;
    if (const auto read = project.ReadRawEvidenceSegment(request, scanned, &staged.sha256); !read) return read;
    if (!valid || count != 1 || !scanned.checked || !scanned.VerifiedBoundary(*scanned.checked) || !IsHash(staged.sha256))
        return Failure(ProjectError::Corrupt, "nativeExecutionReadback");
    staged.end = *scanned.checked;
    out = std::move(staged);
    return {};
}

ProjectResult WriteNativeExecution(ProjectDocument& project, const native::OwnerIdentity& owner,
    std::uint64_t ordinal, std::optional<std::uint64_t> previousSequence,
    const native::NativeControlResult& state, ProjectNativeExecutionReceipt& out)
{
    out = {};
    out.ordinal = ordinal;
    const auto* info = project.Info();
    if (!info) return Failure(ProjectError::NotOpen, "project");
    const auto observed = native::NativeExecutionFromOwnedStop(state);
    if (!observed || !state.group || state.group->sampleId != owner.sampleId ||
        state.group->sessionId != owner.sessionId || state.group->epoch != owner.epoch ||
        observed->event.backendInstanceId != owner.backendInstanceId)
        return Failure(ProjectError::InvalidArgument, "nativeExecutionActiveOwner");
    const auto document = Document(*info, owner, *observed);
    if (!ValidDocument(document, info->projectId, owner.sampleId))
        return Failure(ProjectError::InvalidArgument, "nativeExecutionMetadata");
    const auto text = Evidence::WriteJson(document);
    const auto append = [&](archive::RawEvidenceArchive& writer) -> ProjectResult {
        const archive::RawEvidenceInput row{text, {}};
        const auto written = writer.Append(std::span(&row, 1));
        return written.result.status == archive::SegmentWriteStatus::Ok ? ProjectResult{} :
            Failure(ProjectError::IoError, "nativeExecutionWrite", written.result.error.win32Error);
    };
    const ProjectRawEvidenceWrite request{info->projectId, owner.sampleId, ordinal, previousSequence,
        append, ProjectEvidenceLane::NativeExecution};
    if (const auto written = project.WriteRawEvidenceSegment(request, out.raw); !written) return written;
    if (!out.raw.flushed) return Failure(ProjectError::IoError, "nativeExecutionFlush");
    ArchivedNativeExecution checked;
    if (const auto read = ReadNativeExecution(project, owner.sampleId, ordinal, previousSequence, checked); !read) return read;
    if (Evidence::WriteJson(checked.document) != text || checked.end.byteOffset != out.raw.flushed->byteOffset ||
        checked.end.blockOrdinal != out.raw.flushed->blockOrdinal || checked.end.lastSequence != out.raw.flushed->lastSequence)
        return Failure(ProjectError::Corrupt, "nativeExecutionWrittenBytes");
    out.sha256 = std::move(checked.sha256);
    out.verified = true;
    return {};
}

} // namespace Ksword::ActionAnalyze
