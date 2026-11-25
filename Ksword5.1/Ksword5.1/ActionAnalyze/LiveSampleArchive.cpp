#include "LiveSampleArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <QUuid>
#include <charconv>
#include <utility>

namespace ks::action_analyze
{
namespace
{
    namespace project = Ksword::ActionAnalyze;
    namespace archive = ks::cli::action_analyze::archive;
    namespace evidence = Ksword::Evidence;
    using Value = evidence::JsonValue;

    // u64 用十进制字符串保存，避免经过可视编辑器或其它读取器时丢失精度。
    Value Number(std::optional<quint64> number)
    {
        return number ? Value::makeString(std::to_string(*number)) : Value::makeNull();
    }

    // 从已校验的正文读取无损十进制字段，未知和无效值不投影为零。
    std::optional<quint64> Decimal(const Value& object, std::string_view key)
    {
        const auto* field = object.find(key); // 指定记录字段。
        std::string digits; // 原始十进制表示。
        if (!field || !field->tryGetString(digits) || digits.empty() || (digits.size() > 1 && digits.front() == '0'))
        {
            return {};
        }
        quint64 value = 0; // 只有完整消费字段时才返回解析值。
        const auto* end = digits.data() + digits.size();
        const auto [next, error] = std::from_chars(digits.data(), end, value);
        return error == std::errc{} && next == end ? std::optional{value} : std::nullopt;
    }

    // 可选计数由生产端明确写为 null；缺失或其它类型都不算有效。
    bool NullableDecimal(const Value& object, std::string_view key, std::optional<quint64>& out)
    {
        const auto* field = object.find(key); // 保存字段的真实存在性与类型。
        out = Decimal(object, key);
        return field && (field->type() == evidence::JsonType::Null || out.has_value());
    }

    // 只在语义版本、结束原因、范围和完整统计字段匹配时输出收尾计数。
    bool DecodeTerminal(const Value& object, QtLiveTerminal& terminal)
    {
        const auto* reasonField = object.find("reason"); // 本端停止原因。
        const auto* provider = object.find("provider"); // 未选择 ETW 来源时写 null。
        const auto* tailField = object.find("nativeTailUnconfirmed"); // 独立于落盘状态的原生收尾事实。
        std::string reason; // 只识别当前版本支持的三个停止原因。
        std::string providerId; // 声明的来源 GUID。
        bool tailUnconfirmed = false; // 用于核验字段类型，不推断来源覆盖。
        std::optional<quint64> eventsLost; // 原生统计可能未知。
        const auto created = Decimal(object, "creationFileTime"); // 实际进程实例的创建时间。
        const auto observed = Decimal(object, "observed"); // 实时序号最终水位。
        const auto dropped = Decimal(object, "archiveQueueDropped"); // 写入队列丢弃数。
        if (!reasonField || !reasonField->tryGetString(reason) ||
            (reason != "requested" && reason != "target-exited" && reason != "process-error") ||
            !provider || (provider->type() != evidence::JsonType::Null &&
                (!provider->tryGetString(providerId) || QUuid(QString::fromStdString(providerId)).isNull())) ||
            !tailField || !tailField->tryGetBool(tailUnconfirmed) || !NullableDecimal(object, "eventsLost", eventsLost) ||
            !created || !*created || !observed || !dropped || *dropped > *observed)
        {
            return false;
        }
        terminal = {*observed, *dropped};
        return true;
    }

    // 正式项目接口返回阶段和原始 Win32 码；不以通用成功文案掩盖原因。
    QString Describe(const project::ProjectResult& result)
    {
        return QStringLiteral("%1: %2 (%3)").arg(QString::fromLatin1(project::ProjectErrorName(result.error)),
            QString::fromLatin1(result.detail), QString::number(result.nativeError));
    }

    // 保存本端实际取得的 CPU/I/O 区间或直接 ETW 报头，不声称存在未采集的 ETW 载荷。
    std::string EncodeRow(const SegmentRow& row)
    {
        evidence::JsonObject fields{{"liveSequence", Number(row.sequence)}, {"receiveQpc", Number(row.receiveQpc)},
            {"headerPid", Number(row.pid.value_or(0))}}; // 所有观测共用的冻结范围。
        if (row.liveProcess)
        {
            const auto& item = *row.liveProcess; // 已比较过的实际活动区间。
            fields.emplace_back("kind", Value::makeString("qt-process-activity-v1"));
            fields.emplace_back("creationFileTime", Number(item.creationTime));
            fields.emplace_back("elapsedMs", Number(item.elapsedMs));
            fields.emplace_back("cpu100ns", Number(item.cpu100ns));
            fields.emplace_back("readBytes", Number(item.readBytes));
            fields.emplace_back("writeBytes", Number(item.writeBytes));
        }
        else if (row.liveEtw)
        {
            const auto& item = *row.liveEtw; // 此采集后端只回传事件头。
            fields.emplace_back("kind", Value::makeString("qt-etw-header-v1"));
            fields.emplace_back("provider", Value::makeString(item.provider.toStdString()));
            fields.emplace_back("fileTime", Number(item.fileTime));
            fields.emplace_back("eventId", Number(item.eventId));
            fields.emplace_back("version", Number(item.version));
            fields.emplace_back("opcode", Number(item.opcode));
            fields.emplace_back("headerTid", Number(row.tid.value_or(0)));
        }
        return evidence::WriteJson(Value::makeObject(std::move(fields)));
    }
}

// 取得写租约后核实冻结项目和修订。返回真实目录行及其描述散列，供同一采样重开。
std::optional<SampleRequest> LiveSampleArchive::open(const LiveArchiveProject& frozen, quint32 pid)
{
    auto result = m_project.Open(frozen.manifest.toStdWString(), project::ProjectAccess::ReadWrite); // 只在采集线程打开。
    if (result && (m_project.Info()->projectId != frozen.projectId.toStdString() ||
        m_project.Info()->revisionId != frozen.revisionId.toStdString()))
    {
        result = {project::ProjectError::StaleRevision, 0, "liveProjectContext"};
    }
    project::SampleInfo sample; // 正式项目目录返回的新采样身份。
    if (result)
    {
        const auto title = std::string("PID ") + std::to_string(pid); // 稳定短标题，不储存界面语言。
        result = m_project.CreateSample(title, sample, frozen.revisionId.toStdString());
    }
    if (!result)
    {
        m_status.error = Describe(result);
        m_project.Close();
        return {};
    }
    m_sample = std::move(sample.sampleId);
    // 保留实际提交的数据，回读沿用和项目目录相同的身份校验。
    return SampleRequest{frozen.manifest, frozen.projectId, {
        QString::fromStdString(m_sample), QString::fromStdString(sample.title), sample.createdUtc,
        QString::fromStdString(sample.revisionId), QString::fromStdString(sample.snapshotId),
        QString::fromStdString(sample.descriptionHash)}};
}

// 写一个不可变 Stored raw 段，再按正式项目身份重开并核验同一刷盘边界。
bool LiveSampleArchive::write(const QList<SegmentRow>& rows, const std::string& terminal)
{
    if (m_sample.empty() || m_status.finished || !m_status.error.isEmpty())
    {
        return false;
    }
    if (rows.isEmpty() && terminal.empty())
    {
        return true;
    }
    std::vector<std::string> metadata; // 拥有整批 JSON，写入视图借用至回调返回。
    metadata.reserve(static_cast<std::size_t>(rows.size()) + (terminal.empty() ? 0u : 1u));
    for (const auto& row : rows)
    {
        metadata.push_back(EncodeRow(row));
    }
    if (!terminal.empty())
    {
        metadata.push_back(terminal);
    }

    std::vector<archive::RawEvidenceInput> inputs; // 本源只有真实活动数值或 ETW 报头，无内联字节。
    inputs.reserve(metadata.size());
    for (const auto& record : metadata)
    {
        inputs.push_back({record, {}});
    }
    const auto& id = m_project.Info()->projectId; // 持有租约的真实项目 UUID。
    const auto ordinal = m_status.verifiedSegments + 1; // 已核验前缀之后的唯一段号。
    archive::RawEvidenceReceipt receipt; // 文件写入器的实际刷盘端点。
    auto result = m_project.WriteRawEvidenceSegment({id, m_sample, ordinal, m_previous,
        [&inputs](archive::RawEvidenceArchive& writer) -> project::ProjectResult {
            const auto appended = writer.Append(inputs); // 每批对应一个有限块。
            if (appended.result.status == archive::SegmentWriteStatus::Ok)
            {
                return {};
            }
            return {project::ProjectError::IoError, appended.result.error.win32Error, "qtRawAppend"};
        }}, receipt);

    // 只有同一文件实际完整回读才推进进度。失败保留已经核验过的前序段。
    if (result && receipt.flushed)
    {
        archive::RawEvidenceScanResult checked; // 重新扫描并核对真实端点和序号。
        result = m_project.ReadRawEvidenceSegment({id, m_sample, ordinal, receipt.flushed->byteOffset,
            m_previous.value_or(0), {}}, checked);
        if (result && checked.VerifiedBoundary(*receipt.flushed))
        {
            m_previous = receipt.flushed->lastSequence;
            ++m_status.verifiedSegments;
            m_status.finished = !terminal.empty();
            return true;
        }
    }
    m_status.error = Describe(result ? project::ProjectResult{project::ProjectError::Corrupt, 0, "qtRawReadback"} : result);
    return false;
}

// 对已通过外层 CRC 的 Qt raw 正文作值化投影，返回语义版本的识别与验证结果。
QtLiveRecordKind ProjectQtLiveMetadata(const archive::RawRecordV1& raw, SegmentRow& row, QtLiveTerminal& terminal)
{
    const auto parsed = evidence::ParseJson(raw.metadataJson); // 正式 JSON 解析器保留字段类型。
    std::string kind; // 本端已知的语义版本。
    const auto* kindField = parsed.ok() ? parsed.value.find("kind") : nullptr; // 用精确类型标记识别格式。
    if (!kindField || !kindField->tryGetString(kind) ||
        (kind != "qt-process-activity-v1" && kind != "qt-etw-header-v1" && kind != "qt-live-end-v1"))
    {
        return QtLiveRecordKind::Other;
    }
    const auto& object = parsed.value; // 字段仅在本函数内借用。
    const auto pid = Decimal(object, "headerPid"); // 记录头上下文，不等于当前系统实例。
    if (!raw.inlineRawData.empty() || !pid || *pid == 0 || *pid > UINT32_MAX)
    {
        return QtLiveRecordKind::Invalid;
    }
    if (kind == "qt-live-end-v1")
    {
        return DecodeTerminal(object, terminal) ? QtLiveRecordKind::Terminal : QtLiveRecordKind::Invalid;
    }

    // 原观测序号和接收时钟独立于跨段封装序号，时钟允许明确未知。
    const auto sourceSequence = Decimal(object, "liveSequence"); // 原采集行的顺序锚点。
    std::optional<quint64> qpc; // 由生产端读取的 QPC 或明确未知。
    if (!sourceSequence || !*sourceSequence || !NullableDecimal(object, "receiveQpc", qpc))
    {
        return QtLiveRecordKind::Invalid;
    }
    if (kind == "qt-process-activity-v1")
    {
        const auto created = Decimal(object, "creationFileTime"); // 原目标创建时间。
        const auto elapsed = Decimal(object, "elapsedMs"); // 单调计时区间。
        const auto cpu = Decimal(object, "cpu100ns"); // 实际 CPU 差值，允许为零。
        std::optional<quint64> reads; // 区间读 I/O 字节差。
        std::optional<quint64> writes; // 区间写 I/O 字节差。
        if (!created || !*created || !elapsed || !*elapsed || !cpu ||
            !NullableDecimal(object, "readBytes", reads) || !NullableDecimal(object, "writeBytes", writes))
        {
            return QtLiveRecordKind::Invalid;
        }
        row.liveProcess = LiveProcessObservation{*created, *elapsed, *cpu, reads, writes};
    }
    else
    {
        const auto* providerField = object.find("provider"); // 该记录自己的来源 GUID。
        std::string provider; // 保留原记录的 GUID 字符串。
        const auto fileTime = Decimal(object, "fileTime"); // 原 ETW 报头时间。
        const auto eventId = Decimal(object, "eventId"); // 描述符编号。
        const auto version = Decimal(object, "version"); // 描述符版本。
        const auto opcode = Decimal(object, "opcode"); // 描述符操作码。
        const auto tid = Decimal(object, "headerTid"); // 报头线程上下文。
        if (!providerField || !providerField->tryGetString(provider) || QUuid(QString::fromStdString(provider)).isNull() ||
            !fileTime || !eventId || *eventId > UINT16_MAX || !version || *version > UINT8_MAX ||
            !opcode || *opcode > UINT8_MAX || !tid || *tid > UINT32_MAX)
        {
            return QtLiveRecordKind::Invalid;
        }
        row.liveEtw = LiveEtwHeader{QString::fromStdString(provider), *fileTime, static_cast<quint16>(*eventId),
            static_cast<quint8>(*version), static_cast<quint8>(*opcode)};
        row.tid = static_cast<quint32>(*tid);
    }
    row.pid = static_cast<quint32>(*pid);
    row.receiveQpc = qpc;
    row.liveSourceSequence = sourceSequence;
    return QtLiveRecordKind::Observation;
}
}
