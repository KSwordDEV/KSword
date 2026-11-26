#include "ProjectNativeExecution.h"

#include "ProjectStorage.h"

namespace Ksword::ActionAnalyze {
namespace {
namespace native = ks::cli::action_analyze::control;
namespace archive = ks::cli::action_analyze::archive;
using namespace ProjectStorage;
using V = Evidence::JsonValue;

// 将实际事件的完整寄存器按稳定目录写入当前版本；失败保持null，不使用全零对象替代。
V Registers(const native::NativeExecutionEvidence& observed)
{
    if (!observed.registers)
    {
        return V::makeNull();
    }
    JsonObject values; // 所有u64值保留无损十进制编码。
    for (const auto& field : native::NativeStopRegisterFields)
    {
        values.emplace_back(field.name, Number((*observed.registers).*(field.value)));
    }
    return Object({{"threadId", Text(observed.registers->thread.threadId)}, {"values", Object(std::move(values))}});
}

// 输入执行事件的原绑定副本，输出纯历史定位字段；不序列化停止票据或恢复责任。
V Binding(const native::NativeExecutionEvidence& observed)
{
    if (!observed.binding)
    {
        return V::makeNull();
    }
    const auto& binding = *observed.binding; // 同一事件被冻结的原owner绑定，不是下轮草稿。
    JsonArray ranges; // 按原接纳顺序保存初始范围和后续追加范围。
    for (const auto& range : binding.executionRanges)
    {
        ranges.push_back(Object({{"base", Number(range.base)}, {"bytes", Number(range.bytes)},
            {"allocationBase", Number(range.allocationBase)}}));
    }
    return Object({{"requestId", Text(binding.requestId)}, {"address", Number(binding.address)},
        {"rangeBytes", Number(binding.rangeBytes)}, {"moduleBase", Number(binding.moduleBase)},
        {"rva", Number(binding.rva)}, {"writeWatchBytes", V::makeUInt(binding.writeWatchBytes)},
        {"imageSha256", binding.imageSha256 ? Text(*binding.imageSha256) : V::makeNull()},
        {"executionRanges", V::makeArray(std::move(ranges))}});
}

// 输入项目身份、原owner身份和已提取的执行事件，输出v3历史文档，不产生新控制能力。
V Document(const ProjectInfo& project, const native::OwnerIdentity& owner,
    const native::NativeExecutionEvidence& observed)
{
    return Object({{"kind", Text("native-execution-v3")}, {"projectId", Text(project.projectId)},
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
        {"qpcFrequency", Number(observed.qpcFrequency)}, {"registers", Registers(observed)},
        {"binding", Binding(observed)}});
}

// v2寄存器必须全部存在且来自文档的实际线程；v1没有该字段，不补造未知寄存器。
bool ValidRegisters(const V& doc, const V& thread)
{
    const auto* registers = doc.find("registers"); // 当前版本已经核对顶层字段集合。
    if (!registers || registers->isNull())
    {
        return true;
    }
    std::string expectedThread, actualThread; // 与原生执行观察的实际强线程ID比较。
    if (!Fields(*registers, {"threadId", "values"}) || !GetString(thread, "threadId", expectedThread) ||
        !GetString(*registers, "threadId", actualThread) || actualThread != expectedThread)
    {
        return false;
    }
    const auto* values = registers->find("values"); // 固定18项，不忽略拼写错误或额外寄存器。
    const auto* object = values ? values->asObject() : nullptr;
    if (!object || object->size() != native::NativeStopRegisterFields.size())
    {
        return false;
    }
    for (const auto& field : native::NativeStopRegisterFields)
    {
        std::uint64_t value = 0; // 已校验的无符号寄存器值，零合法。
        if (!GetNumber(*values, field.name, value))
        {
            return false;
        }
    }
    std::uint64_t flags = 0, rip = 0, stoppedIp = 0; // RIP指向事件时现场，Into保存的是完成后的下一地址。
    return GetNumber(*values, "eflags", flags) && flags <= MAXDWORD && GetNumber(*values, "rip", rip) &&
        GetNumber(doc, IsString(doc, "observation", "instruction-completed") ? "nextInstructionAddress" : "instructionAddress", stoppedIp) &&
        rip == stoppedIp;
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

// 输入v3归档绑定，核对字段及可表示的真实范围；只验证历史自洽，不授予现场控制资格。
bool ValidBinding(const V& doc)
{
    const auto* binding = doc.find("binding"); // v3固定具有该字段，未知原绑定显式为null。
    if (!binding)
    {
        return false;
    }
    if (binding->isNull())
    {
        return !IsString(doc, "observation", "execution-enter-attempt");
    }
    std::uint64_t address = 0, bytes = 0, module = 0, rva = 0, width = 0; // 原绑定的定位与模式。
    const auto* widthField = binding->find("writeWatchBytes"); // 宽度沿原数值字段类型读取。
    if (!Fields(*binding, {"requestId", "address", "rangeBytes", "moduleBase", "rva", "writeWatchBytes", "imageSha256", "executionRanges"}) ||
        !Identifier(*binding, "requestId") || !Positive(*binding, "address", &address) ||
        !GetNumber(*binding, "rangeBytes", bytes) || !GetNumber(*binding, "moduleBase", module) ||
        !GetNumber(*binding, "rva", rva) || rva > MAXDWORD || !widthField ||
        widthField->type() != Evidence::JsonType::UInt || !widthField->tryGetU64(width) ||
        (width != 0 && width != 1 && width != 2 && width != 4 && width != 8))
    {
        return false;
    }
    const auto* hash = binding->find("imageSha256"); // 仅实测成功值，不把配置中的期望值当作测量。
    std::string measured; // 规范小写SHA256；无约束或未取得时为null。
    if (!hash || (!hash->isNull() && (!module || !GetString(*binding, "imageSha256", measured) || !IsHash(measured))))
    {
        return false;
    }

    const auto* ranges = binding->find("executionRanges"); // 原接纳成功的完整NX范围目录。
    const auto* list = ranges ? ranges->asArray() : nullptr;
    if (!list || (!bytes && !list->empty()) ||
        (bytes && width))
    {
        return false;
    }
    std::uint64_t instruction = 0; // 被保存的实际执行地址；不再累计人为页数额度。
    if (!Positive(doc, "instructionAddress", &instruction))
    {
        return false;
    }
    bool includesInstruction = !bytes && instruction == address; // DR0进入只接受精确原地址。
    for (std::size_t i = 0; i < list->size(); ++i)
    {
        const auto& range = (*list)[i]; // 每个范围保持原分配基址，不能用句柄替代区域身份。
        std::uint64_t base = 0, length = 0, allocation = 0; // 无损半开区间与原分配定位。
        if (!Fields(range, {"base", "bytes", "allocationBase"}) || !Positive(range, "base", &base) ||
            !Positive(range, "bytes", &length) || !Positive(range, "allocationBase", &allocation) ||
            base % 4096 || length % 4096 || allocation > base || length > UINT64_MAX - base ||
            (i == 0 && (base != address || length != bytes)))
        {
            return false;
        }
        includesInstruction = includesInstruction || (instruction >= base && instruction - base < length);
    }
    // Into的指令可已离开原绑定；进入尝试必须落在保存的当时已纳入范围。
    return (!bytes || !list->empty()) &&
        (!IsString(doc, "observation", "execution-enter-attempt") || (!width && includesInstruction));
}

bool ValidDocument(const V& doc, std::string_view projectId, std::string_view sampleId)
{
    const bool version3 = IsString(doc, "kind", "native-execution-v3"); // v3保存事件时绑定，旧v1/v2不补字段。
    const bool version2 = IsString(doc, "kind", "native-execution-v2"); // 版本严格分开，旧v1仍按原字段集合读取。
    const bool fieldsValid = version3 ? Fields(doc, {"kind", "projectId", "sampleId", "sessionId", "epoch", "source", "historical", "observation",
            "target", "thread", "event", "groupId", "stopId", "stateRevision", "instructionAddress",
            "nextInstructionAddress", "observedQpc", "qpcFrequency", "registers", "binding"}) :
        version2 ? Fields(doc, {"kind", "projectId", "sampleId", "sessionId", "epoch", "source", "historical", "observation",
            "target", "thread", "event", "groupId", "stopId", "stateRevision", "instructionAddress",
            "nextInstructionAddress", "observedQpc", "qpcFrequency", "registers"}) :
        Fields(doc, {"kind", "projectId", "sampleId", "sessionId", "epoch", "source", "historical", "observation",
            "target", "thread", "event", "groupId", "stopId", "stateRevision", "instructionAddress",
            "nextInstructionAddress", "observedQpc", "qpcFrequency"});
    if (!fieldsValid || !IsNativeExecutionDocument(doc) || !IsString(doc, "projectId", projectId) ||
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
        threadTime < processTime || ((version2 || version3) && !ValidRegisters(doc, *thread)) ||
        (version3 && !ValidBinding(doc))) return false;
    std::uint64_t frequency = 0;
    if (!GetNumber(doc, "qpcFrequency", frequency) ||
        (!IsNull(doc, "observedQpc") && (!frequency || !Positive(doc, "observedQpc")))) return false;
    if (IsString(doc, "observation", "instruction-completed")) return Positive(doc, "nextInstructionAddress");
    return IsString(doc, "observation", "execution-enter-attempt") && IsNull(doc, "nextInstructionAddress");
}
} // namespace

bool IsNativeExecutionDocument(const Evidence::JsonValue& document)
{
    return IsString(document, "kind", "native-execution-v1") || IsString(document, "kind", "native-execution-v2") ||
        IsString(document, "kind", "native-execution-v3");
}

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
