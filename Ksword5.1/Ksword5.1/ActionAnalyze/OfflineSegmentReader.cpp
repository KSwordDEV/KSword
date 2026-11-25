#include "OfflineSegmentReader.h"
#include "LiveSampleArchive.h"

#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentBodies.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/NetworkEvidenceArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectApiCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../shared/evidence/ApiMonitorClue.h"
#include "../../../shared/evidence/ArchivedEtwObservation.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <QUuid>
#include <QDir>
#include <QFileInfo>
#include <algorithm>
#include <deque>
#include <iterator>
#include <windows.h>

namespace ks::action_analyze
{
namespace
{
    namespace archive = ks::cli::action_analyze::archive;
    namespace project = Ksword::ActionAnalyze;
    constexpr std::uint64_t kPreviewBytes = 64ull * 1024 * 1024; // 独立段扫描的文件前缀上限。
    constexpr std::size_t kPreviewRows = 4096; // 一次提交到 UI 的记录上限。
    constexpr std::size_t kNetworkPreviewBytes = 256; // 每条已验证网络记录保留此前缀。
    constexpr std::size_t kEtwPreviewBytes = 128; // 详情显示的实际 UserData 前缀。
    constexpr std::size_t kApiPreviewBytes = 64; // API 详情只复制报头前缀。

    // 只读且独占文件位置的句柄，离开工作线程函数前释放。
    struct SegmentFile
    {
        HANDLE handle = INVALID_HANDLE_VALUE; // 扫描器借用的 Win32 同步读句柄。
        ~SegmentFile()
        {
            if (handle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(handle);
            }
        }
    };

    // 从已打开的句柄核对最终路径，拒绝目录重定向到项目之外的文件。
    bool MatchesProjectPath(HANDLE file, const QString& path)
    {
        constexpr DWORD capacity = 32768; // Win32 支持的完整本地路径上限。
        wchar_t finalPath[capacity]; // 只读工作线程持有的路径缓冲。
        const DWORD length = GetFinalPathNameByHandleW(file, finalPath, capacity, FILE_NAME_NORMALIZED);
        if (!length || length >= capacity)
        {
            return false;
        }
        const auto actual = QString::fromWCharArray(finalPath, length); // Win32 返回扩展长度路径。
        const auto expected = QStringLiteral("\\\\?\\") + QDir::toNativeSeparators(QDir::cleanPath(path));
        return actual.compare(expected, Qt::CaseInsensitive) == 0;
    }

    // 将段头 RFC 字节身份按规范小写文本呈现。
    QString UuidText(const archive::ArchiveUuid& uuid)
    {
        const auto* bytes = reinterpret_cast<const char*>(uuid.data()); // 原始字节按 RFC 顺序。
        return QUuid::fromRfc4122(QByteArrayView(bytes, static_cast<qsizetype>(uuid.size()))).toString(QUuid::WithoutBraces);
    }

    // 对已校验的 RawRecord 做 ETW 识别。复制预览后，界面无需持有文件缓冲区。
    void ProjectRawEtw(const archive::RecordBody& body, SegmentRow& row)
    {
        const auto* raw = std::get_if<archive::RawRecordV1>(&body); // 类型化原始记录封装。
        if (!raw)
        {
            return;
        }
        Ksword::Evidence::JsonLimits limits; // Stored 正文已检查，此处只解释字段。
        limits.maxTotalBytes = 4 * 1024 * 1024;
        limits.maxDepth = 32;
        limits.maxStringBytes = 65536;
        const auto parsed = Ksword::Evidence::ParseJson(raw->metadataJson, limits);
        const auto etw = parsed.ok() ? Ksword::Evidence::ReadArchivedEtwObservation(parsed.value, raw->inlineRawData.size()) : std::nullopt;
        if (!etw)
        {
            return;
        }

        // 来源 PID/TID 进入记录列，进程及线程对象字段仍保持缺失。
        row.liveEtw = LiveEtwHeader{QString::fromStdString(etw->providerId), etw->fileTime,
            etw->eventId, etw->version, etw->opcode};
        row.pid = etw->headerPid;
        row.tid = etw->headerTid;
        if (etw->receiveQpc)
        {
            row.receiveQpc = *etw->receiveQpc;
        }
        const auto length = (std::min)(raw->inlineRawData.size(), kEtwPreviewBytes); // 预览配额内的字节数。
        row.archivedEtw = SegmentEtwPayload{QString::fromStdString(etw->sourceEpoch), etw->qpcFrequencyHz,
            etw->originalPayloadBytes, raw->inlineRawBytes, etw->malformedPayload,
            QByteArray(raw->inlineRawData.data(), static_cast<qsizetype>(length))};
    }

    // 只投影明确已知的来源头 u32，缺少字段或任何其它状态都保留为空。
    std::optional<quint32> HeaderId(const Ksword::Evidence::JsonValue& fields, std::string_view key)
    {
        const auto* field = fields.find(key); // 来源头字段，非进程实例解析结果。
        if (!field)
        {
            return {};
        }
        const auto* type = field->find("type"); // 精确要求 A0 u32。
        const auto* state = field->find("state"); // 精确要求 known。
        const auto* value = field->find("value"); // 保留合法零，不接受字符串形式。
        std::string typeName; // 字段字面量类型名。
        std::string stateName; // 字段字面量状态名。
        std::uint64_t number = 0; // 公共解析器的无符号输出。
        if (!type || !state || !value || !type->tryGetString(typeName) || typeName != "u32"
            || !state->tryGetString(stateName) || stateName != "known"
            || value->type() != Ksword::Evidence::JsonType::UInt || !value->tryGetU64(number) || number > UINT32_MAX)
        {
            return {};
        }
        return static_cast<quint32>(number);
    }

    // 将共享正文值复制成独立 Qt 投影，回调后不留块缓冲区引用。
    void ProjectBody(const archive::RecordBody& body, SegmentRow& row)
    {
        row.decoded = !std::holds_alternative<std::monostate>(body);
        const auto* event = std::get_if<archive::CanonicalEventV1>(&body); // 固定正文字段所在记录。
        if (!event)
        {
            return;
        }
        row.ordinal = event->eventOrdinal;
        row.receiveQpc = event->receiveQpc;
        row.category = event->category;
        row.eventKind = event->eventKind;
        row.sourceId = event->sourceInstanceDictionaryId;
        row.actorId = event->actorProcessObjectId;
        row.targetId = event->targetProcessObjectId;
        row.threadId = event->observedThreadObjectId;

        // A0 字段集只用于读取两个已知头字段，保留共享解码器的正文校验边界。
        Ksword::Evidence::JsonLimits limits;
        limits.maxTotalBytes = 4 * 1024 * 1024;
        limits.maxDepth = 32;
        limits.maxStringBytes = 65536;
        const auto parsed = Ksword::Evidence::ParseJson(event->fieldJson, limits); // 临时值，不随模型保留。
        if (parsed.ok())
        {
            row.pid = HeaderId(parsed.value, "source.headerPid");
            row.tid = HeaderId(parsed.value, "source.headerTid");
        }
    }

    // 根据低层扫描回执生成 Qt 状态，不把中止或字节上限当文件完成。
    SegmentEnd ScanEnd(const archive::SegmentScanResult& scan, std::uint64_t boundary)
    {
        switch (scan.status)
        {
        case archive::SegmentScanStatus::FramingComplete:
            return scan.fileBytes > boundary ? SegmentEnd::PreviewLimit : SegmentEnd::Complete;
        case archive::SegmentScanStatus::Truncated:
            return scan.fileBytes > boundary && scan.error.offset == boundary ? SegmentEnd::PreviewLimit : SegmentEnd::Truncated;
        case archive::SegmentScanStatus::Corrupt:
            return SegmentEnd::Invalid;
        case archive::SegmentScanStatus::Unsupported:
            return SegmentEnd::Unsupported;
        case archive::SegmentScanStatus::Stopped:
            return SegmentEnd::Canceled;
        case archive::SegmentScanStatus::IoError:
            return SegmentEnd::Unavailable;
        }
        return SegmentEnd::Unavailable;
    }

    // 把共享扫描器借出的单条记录投影为 Qt 值。偏移只在该源段中有效。
    SegmentRow ProjectRecord(const archive::SegmentIdentity& identity, const archive::DecodedRecord& record,
        std::uint64_t end)
    {
        SegmentRow row; // 不借用共享解码块内存的结果。
        row.sequence = record.recordSequence;
        row.offset = record.recordOffset;
        row.segmentOrdinal = identity.ordinal;
        row.type = record.recordType;
        row.version = record.recordSchemaVersion;
        row.payloadBytes = static_cast<quint32>(end - record.recordOffset - archive::kRecordHeaderBytes);
        ProjectBody(record.body, row);
        if (identity.stream == archive::StreamKind::Raw)
        {
            ProjectRawEtw(record.body, row);
        }
        // 借用已校验载荷，只复制结果需要的前缀及本段内的起点。
        if (const auto network = archive::ProjectNetworkFlowRecord(identity, record))
        {
            const auto length = (std::min)(network->inlineBytes.size(), kNetworkPreviewBytes); // 字节预览长度。
        const auto offset = record.recordOffset + archive::kRecordHeaderBytes + network->inlineOffsetInPayload; // 字节起点。
            row.network = SegmentNetworkEvidence{network->flow, network->source, network->sourceTrust, offset,
                QByteArray(network->inlineBytes.data(), static_cast<qsizetype>(length))};
            row.receiveQpc = network->flow.observation.receiveQpc;
            row.actorId = network->flow.observation.processObjectId;
        }
        return row;
    }

    // 复制通过校验的 API 线索与有界报头预览。输入记录来自同一 Stored 原始段。
    SegmentRow ProjectApiClue(const Ksword::Evidence::ArchivedApiMonitorClue& clue,
        const archive::SegmentIdentity& identity, const archive::DecodedRecord& record, std::uint64_t end)
    {
        SegmentRow row; // 不借用扫描块或原包的 UI 行。
        row.sequence = record.recordSequence;
        row.offset = record.recordOffset;
        row.segmentOrdinal = identity.ordinal;
        row.type = record.recordType;
        row.version = record.recordSchemaVersion;
        row.payloadBytes = static_cast<quint32>(end - record.recordOffset - archive::kRecordHeaderBytes);
        row.decoded = true;

        // 头部 PID/TID 只作来源提示，操作菜单所需的对象字段继续为空。
        row.pid = clue.packet.pid;
        row.tid = clue.packet.tid;
        row.archivedApi = SegmentApiClue{QString::fromWCharArray(clue.clue->api.data(), clue.clue->api.size()),
            QString::fromLatin1(clue.clue->family.data(), clue.clue->family.size()), clue.packet.timestamp100ns,
            clue.sourceSequence, clue.readerCreation ? std::optional<quint64>(clue.readerCreation) : std::nullopt,
            QByteArray(reinterpret_cast<const char*>(&clue.packet), kApiPreviewBytes)};
        return row;
    }

    // 仅对首条原始记录识别未发布的连续采样；旧独立段与旧计划仍按旧档诊断预览。
    bool IsContinuousPlan(const archive::DecodedRecord& record)
    {
        const auto* raw = std::get_if<archive::RawRecordV1>(&record.body); // 计划属于 RawRecord v1。
        if (!raw || record.recordSequence != 1)
        {
            return false;
        }
        const auto parsed = Ksword::Evidence::ParseJson(raw->metadataJson); // 与检查点共用的元数据语义。
        const auto* kind = parsed.ok() ? parsed.value.find("kind") : nullptr; // 报文类型字段。
        const auto* duration = parsed.ok() ? parsed.value.find("durationMs") : nullptr; // 零表示连续模式。
        std::string name; // 解码后的类型。
        std::uint64_t ms = 0; // 以毫秒保存的计划时长。
        return kind && kind->tryGetString(name) && name == "etw-capture-plan-v1" && duration &&
            duration->type() == Ksword::Evidence::JsonType::UInt && duration->tryGetU64(ms) && ms == 0;
    }
}

// 只接受项目目录生成的绝对本地清单路径和规范采样 ID。
QString SampleRawSegmentPath(const SampleRequest& sample)
{
    const QFileInfo manifest(sample.manifestPath); // 已打开目录的冻结清单。
    const auto root = manifest.absolutePath(); // 与项目读取器相同的本地盘符路径。
    const QUuid id(sample.sample.id); // 校验目录分量，拒绝全零或非规范标识。
    if (!manifest.isAbsolute() || manifest.fileName().compare(QLatin1String("project.ksaproj"), Qt::CaseInsensitive) != 0 ||
        root.size() < 3 || root.at(1) != u':' || root.at(2) != u'/' ||
        id.isNull() || id.toString(QUuid::WithoutBraces) != sample.sample.id)
    {
        return {};
    }
    return QDir(root).filePath(QStringLiteral("samples/%1/raw/00000000000000000001.ksaseg").arg(sample.sample.id));
}

namespace
{
// 读取独立文件或无检查点的旧段。项目回退识别 Qt 首条记录后改走严格整段回放。
SegmentSnapshot ReadStandalone(const QString& path, const CancelCheck& isCanceled, const SampleRequest* expected,
    bool* qtLive = nullptr)
{
    SegmentSnapshot snapshot; // 只有通过实际检查的数据才发布。
    snapshot.path = path;
    snapshot.checkpoint = expected ? SegmentCheckpoint::Unpublished : SegmentCheckpoint::NotRequested;
    if (isCanceled())
    {
        snapshot.end = SegmentEnd::Canceled;
        return snapshot;
    }
    const auto nativePath = QDir::toNativeSeparators(path).toStdWString(); // Win32 打开路径。
    const SegmentFile file{CreateFileW(nativePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (file.handle == INVALID_HANDLE_VALUE || GetFileType(file.handle) != FILE_TYPE_DISK)
    {
        return snapshot;
    }
    if (expected && !MatchesProjectPath(file.handle, path))
    {
        snapshot.end = SegmentEnd::WrongSample;
        return snapshot;
    }

    // 首次只验证段头，冻结同一文件、大小和真实段身份。
    archive::SegmentScanOptions headerOptions; // 扫描边界阻止此轮读取正文。
    headerOptions.endOffset = archive::kSegmentHeaderBytes;
    const auto header = archive::ScanOpenSegment(file.handle, headerOptions);
    snapshot.fileBytes = header.fileBytes;
    if (!header.header)
    {
        snapshot.end = ScanEnd(header, archive::kSegmentHeaderBytes);
        snapshot.failureOffset = header.error.offset;
        return snapshot;
    }
    const auto& identity = header.header->identity; // 由已通过 CRC 的段头提供。
    snapshot.projectId = UuidText(identity.project);
    snapshot.sampleId = UuidText(identity.sample);
    if (expected && (snapshot.projectId != expected->projectId || snapshot.sampleId != expected->sample.id ||
        identity.ordinal != 1 || identity.stream != archive::StreamKind::Raw))
    {
        snapshot.end = SegmentEnd::WrongSample;
        return snapshot; // 不发布错误段的记录、段号或前缀。
    }
    snapshot.ordinal = identity.ordinal;
    snapshot.stream = static_cast<quint32>(identity.stream);
    snapshot.prefixBytes = archive::kSegmentHeaderBytes;

    // 记录回调只接受经过共享扫描器验证的块和已理解的必需正文。
    const auto boundary = (std::min)(header.fileBytes, kPreviewBytes); // 实际字节读取上限。
    std::optional<SegmentEnd> stop; // Qt 预览提前停止的原因。
    Ksword::Evidence::ApiMonitorClueReadback api; // 导入段读到合法尾记前不发布行。
    bool apiImport = false; // 由首条记录声明的专用导入格式。
    std::deque<SegmentRow> apiRows; // 有界最近窗口，扫描会继续验证窗口外记录。
    const auto body = archive::ScanOpenSegmentBodies(file.handle, identity, boundary,
        [&](const archive::SegmentIdentity& checkedIdentity, const archive::BlockInfo& block,
            const std::vector<archive::DecodedRecord>& records) {
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                const auto& record = records.at(index); // 块内已校验的记录及正文。
                if (isCanceled())
                {
                    stop = SegmentEnd::Canceled;
                }
                else if (qtLive && checkedIdentity.stream == archive::StreamKind::Raw &&
                    snapshot.rows.isEmpty() && !apiImport && apiRows.empty())
                {
                    const auto* raw = std::get_if<archive::RawRecordV1>(&record.body); // 已验证封装的首条记录。
                    SegmentRow first; // 仅作格式探测，严格扫描会重新构造可发布的行。
                    QtLiveTerminal terminal; // 首段允许是零观测的单独终止段。
                    if (raw && ProjectQtLiveMetadata(*raw, first, terminal) != QtLiveRecordKind::Other)
                    {
                        *qtLive = true;
                        return false;
                    }
                }
                if (!stop && checkedIdentity.stream == archive::StreamKind::Raw && (apiImport || record.recordSequence == 1))
                {
                    const auto* raw = std::get_if<archive::RawRecordV1>(&record.body); // 已解封的 raw 元数据。
                    const auto metadata = raw ? Ksword::Evidence::ParseJson(raw->metadataJson) : Ksword::Evidence::JsonParseResult{}; // 首条记录的归档格式声明。
                    // 只读探测与回退打开之间可能出现首段。跟随档必须通过检查点入口发布。
                    const auto* kind = metadata.ok() ? metadata.value.find("kind") : nullptr; // 首记录的格式类别。
                    std::string format; // 仅用于核对跟随计划类型。
                    if (expected && record.recordSequence == 1 && kind && kind->tryGetString(format) &&
                        format == project::kApiFollowPlanKind)
                    {
                        stop = SegmentEnd::IncompleteSample;
                        snapshot.checkpoint = metadata.value.find(project::kApiFollowCheckpointField) ? SegmentCheckpoint::Pending
                            : SegmentCheckpoint::ApiLegacyUnpublished;
                        return false;
                    }
                    apiImport = apiImport || (raw && metadata.ok() && Ksword::Evidence::IsApiMonitorClueImport(metadata.value));
                    if (apiImport)
                    {
                        std::optional<Ksword::Evidence::ArchivedApiMonitorClue> clue; // 尾记不会产生表格行。
                        if (!raw || !metadata.ok() || record.recordSequence != api.clues + 1 ||
                            !api.Accept(metadata.value, raw->inlineRawData, clue))
                        {
                            stop = SegmentEnd::Invalid;
                        }
                        else
                        {
                            // 整段的校验水位与最近窗口容量独立推进。
                            const auto end = index + 1 < records.size() ? records.at(index + 1).recordOffset : block.endOffset;
                            if (clue)
                            {
                                if (apiRows.size() == kPreviewRows)
                                {
                                    apiRows.pop_front();
                                }
                                apiRows.push_back(ProjectApiClue(*clue, checkedIdentity, record, end));
                            }
                            snapshot.prefixBytes = end;
                            continue;
                        }
                    }
                }
                if (!stop && expected && snapshot.rows.isEmpty() && IsContinuousPlan(record))
                {
                    stop = SegmentEnd::IncompleteSample;
                    snapshot.checkpoint = SegmentCheckpoint::Pending;
                }
                else if (!stop && static_cast<std::size_t>(snapshot.rows.size()) >= kPreviewRows)
                {
                    stop = SegmentEnd::PreviewLimit;
                }
                else if (!stop && (record.flags & archive::kRequiredRecord) && std::holds_alternative<std::monostate>(record.body))
                {
                    stop = SegmentEnd::Unsupported;
                }
                if (stop)
                {
                    snapshot.failureOffset = record.recordOffset;
                    return false;
                }

                // Stored 记录无填充，下一记录或块尾即为当前记录的精确边界。
                const auto end = index + 1 < records.size() ? records.at(index + 1).recordOffset : block.endOffset;
                auto row = ProjectRecord(checkedIdentity, record, end); // 不借用扫描内存。
                snapshot.hasArchivedEtw |= row.archivedEtw.has_value();
                snapshot.rows.append(std::move(row));
                snapshot.prefixBytes = end;
            }
            return true;
        });
    // 把工作线程取消、解码失败及封装回执分开报告。
    if (stop)
    {
        snapshot.end = *stop;
    }
    else if (isCanceled())
    {
        snapshot.end = SegmentEnd::Canceled;
    }
    else if (body.bodyFailure.issue != archive::BodyIssue::None)
    {
        snapshot.end = body.bodyFailure.issue == archive::BodyIssue::JsonBudget ? SegmentEnd::PreviewLimit : SegmentEnd::Invalid;
        snapshot.failureOffset = body.bodyFailure.recordOffset;
    }
    else
    {
        snapshot.end = ScanEnd(body.framing, boundary);
        snapshot.failureOffset = body.framing.error.offset;
        if (snapshot.end == SegmentEnd::PreviewLimit && !snapshot.failureOffset)
        {
            snapshot.failureOffset = snapshot.prefixBytes;
        }
    }
    // API 导入只有在校验完整文件和尾记后才交出行，失败重读保留页面旧结果。
    if (apiImport && snapshot.end == SegmentEnd::Complete)
    {
        if (api.ended)
        {
            snapshot.hasArchivedApi = true;
            snapshot.verifiedRows = api.clues;
            snapshot.rows.assign(std::make_move_iterator(apiRows.begin()), std::make_move_iterator(apiRows.end()));
        }
        else
        {
            snapshot.end = SegmentEnd::Invalid;
        }
    }
    // 旧档诊断也不能把已识别的连续首段或取消的结果提交到页面。
    if (snapshot.end == SegmentEnd::IncompleteSample || snapshot.end == SegmentEnd::Canceled)
    {
        SegmentSnapshot pending; // 仅返回稳定的请求锚点和状态，不发布未提交数据。
        pending.path = path;
        pending.end = snapshot.end;
        pending.checkpoint = snapshot.checkpoint;
        return pending;
    }
    return snapshot;
}

// 只在整段通过验证后推进共享窗口，坏段没有机会移出已核验的旧行。
void MergePage(std::deque<SegmentRow>& rows, std::deque<SegmentRow>& page)
{
    for (auto& row : page)
    {
        if (rows.size() == kPreviewRows)
        {
            rows.pop_front();
        }
        rows.push_back(std::move(row));
    }
}

// 统一项目首段锚点和采样身份。保留可筛选的 ETW 头，包括纯 raw 头。
void FinishProjectReplay(const SampleRequest& expected, std::deque<SegmentRow>& rows, SegmentSnapshot& snapshot)
{
    snapshot.projectId = expected.projectId;
    snapshot.sampleId = expected.sample.id;
    snapshot.ordinal = 1;
    snapshot.stream = static_cast<quint32>(archive::StreamKind::Raw);
    snapshot.hasArchivedEtw = std::any_of(rows.cbegin(), rows.cend(),
        [](const auto& row) { return row.liveEtw.has_value(); });
    snapshot.rows.assign(std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
}

// 同一采样的连续 Qt raw 文件逐段整体验证，找不到下一段时只报告已验证的中间前缀。
SegmentSnapshot ReadQtRawReplay(const QString& path, const CancelCheck& isCanceled, const SampleRequest& expected,
    const project::ProjectDocument& document, const std::string& sampleId, quint64 maxSegments)
{
    SegmentSnapshot snapshot; // 返回页只拥有已验证的文件信息及观测行。
    snapshot.path = path;
    std::deque<SegmentRow> rows; // 跨段保留最近窗口。
    quint64 previousSource = 0; // 已通过整段验证的原观测水位，允许队列丢弃导致的跳号。
    for (quint64 ordinal = 1; !isCanceled(); ++ordinal)
    {
        // 预算只在已提交段边界检查，已验证窗口仍可用于自动预览。
        if (maxSegments && ordinal > maxSegments)
        {
            snapshot.end = SegmentEnd::PreviewLimit;
            break;
        }
        std::deque<SegmentRow> page; // 暂存当前候选段的观测行。
        std::optional<QtLiveTerminal> terminal; // 同段终止记录，必须是最后一条。
        auto source = previousSource; // 候选段的原观测水位。
        quint64 invalidOffset = 0; // 语义错误位置优先于共享扫描器的停止位置。
        // raw 写入器分配连续封装序号。共有项目读取器核对固定路径、身份和整个文件。
        const project::ProjectRawEvidenceRead request{document.Info()->projectId, sampleId, ordinal,
            std::nullopt, snapshot.verifiedRows,
            [&](const archive::SegmentIdentity& identity, const archive::BlockInfo& block,
                const std::vector<archive::DecodedRecord>& records) {
                for (std::size_t index = 0; index < records.size(); ++index)
                {
                    if (isCanceled())
                    {
                        return false;
                    }
                    // Stored 块内无填充，下一记录或块端点即当前记录的边界。
                    const auto& record = records.at(index); // 共享读取器已验证封装类型与序号。
                    const auto end = index + 1 < records.size() ? records.at(index + 1).recordOffset : block.endOffset; // 本记录端点。
                    SegmentRow row; // 先验证 Qt 语义，再填入不可变归档坐标。
                    QtLiveTerminal candidate; // 只有终止类型会提供统计。
                    const auto kind = ProjectQtLiveMetadata(std::get<archive::RawRecordV1>(record.body), row, candidate);
                    if (!terminal && kind == QtLiveRecordKind::Terminal && candidate.observed >= source &&
                        candidate.observed - candidate.dropped == record.recordSequence - 1)
                    {
                        terminal = candidate;
                        continue;
                    }
                    if (terminal || kind != QtLiveRecordKind::Observation || !row.liveSourceSequence ||
                        *row.liveSourceSequence <= source)
                    {
                        invalidOffset = record.recordOffset;
                        return false;
                    }

                    // 只保留声明的进程活动或 ETW 头，不生成任何载荷或跨流引用。
                    source = *row.liveSourceSequence;
                    row.sequence = record.recordSequence;
                    row.offset = record.recordOffset;
                    row.segmentOrdinal = identity.ordinal;
                    row.type = record.recordType;
                    row.version = record.recordSchemaVersion;
                    row.decoded = true;
                    row.payloadBytes = static_cast<quint32>(end - record.recordOffset - archive::kRecordHeaderBytes);
                    if (page.size() == kPreviewRows)
                    {
                        page.pop_front();
                    }
                    page.push_back(std::move(row));
                }
                return true;
            }, kPreviewBytes};
        archive::RawEvidenceScanResult raw; // 只有完整文件的实际端点可提交。
        const auto result = document.ReadRawEvidenceSegment(request, raw);
        if (isCanceled())
        {
            break;
        }
        if (result.error == project::ProjectError::NotFound)
        {
            snapshot.end = SegmentEnd::IncompleteSample;
            break;
        }

        const auto& framing = raw.segment.framing; // 段文件自身的包络回执。
        if (!result || !raw.checked || !raw.VerifiedBoundary(*raw.checked) || raw.checked->byteOffset != framing.fileBytes)
        {
            snapshot.end = !result ? (result.error == project::ProjectError::LimitExceeded ? SegmentEnd::PreviewLimit
                : SegmentEnd::Unavailable) : SegmentEnd::Invalid;
            snapshot.failedOrdinal = ordinal;
            snapshot.failureOffset = invalidOffset ? invalidOffset : raw.invalidRecordOffset;
            if (!snapshot.failureOffset)
            {
                snapshot.failureOffset = raw.segment.bodyFailure.recordOffset ? raw.segment.bodyFailure.recordOffset
                    : framing.error.offset;
            }
            break;
        }

        MergePage(rows, page);
        previousSource = source;
        snapshot.checkpoint = SegmentCheckpoint::QtRawVerified;
        snapshot.lastVerifiedOrdinal = ordinal;
        snapshot.verifiedRows = raw.checked->lastSequence;
        snapshot.fileBytes = framing.fileBytes;
        snapshot.prefixBytes = raw.checked->byteOffset;
        if (terminal)
        {
            snapshot.qtArchiveDropped = terminal->dropped;
            snapshot.end = SegmentEnd::Complete;
            break;
        }
    }

    if (isCanceled())
    {
        snapshot = {};
        snapshot.path = path;
        snapshot.end = SegmentEnd::Canceled;
    }
    else if (snapshot.lastVerifiedOrdinal)
    {
        FinishProjectReplay(expected, rows, snapshot);
    }
    return snapshot;
}

// 复用安全项目句柄按检查点水位扫描。先暂存末页，只有字节和散列都一致才交给调用方。
bool ReadCommittedSegment(const project::ProjectDocument& document, const std::string& sampleId,
    quint64 ordinal, const project::ProjectEtwCheckpoint& checkpoint, const CancelCheck& isCanceled,
    std::deque<SegmentRow>& page, SegmentSnapshot& snapshot)
{
    const project::ProjectRawEvidenceRead request{document.Info()->projectId, sampleId, ordinal, // 冻结读取身份与水位。
        checkpoint.raw.end.byteOffset, checkpoint.planRawSequence - 1,
        [&](const archive::SegmentIdentity& identity, const archive::BlockInfo& block,
            const std::vector<archive::DecodedRecord>& records) {
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                if (isCanceled())
                {
                    return false;
                }
                // 段内也可能超过整页配额。暂存最近行，坏段不得淘汰已验证的旧行。
                if (page.size() == kPreviewRows)
                {
                    page.pop_front();
                }
                const auto end = index + 1 < records.size() ? records.at(index + 1).recordOffset : block.endOffset; // 记录端点。
                page.push_back(ProjectRecord(identity, records.at(index), end));
            }
            return true;
        }};
    archive::RawEvidenceScanResult raw; // 同一个禁止写入的句柄验证正文、端点及 SHA-256。
    std::string hash; // 本次实际投影文件的已提交前缀散列。
    if (!document.ReadRawEvidenceSegment(request, raw, &hash) || !raw.VerifiedBoundary(checkpoint.raw.end) ||
        hash != checkpoint.raw.sha256)
    {
        snapshot.failureOffset = raw.invalidRecordOffset ? raw.invalidRecordOffset : raw.segment.bodyFailure.recordOffset;
        if (!snapshot.failureOffset)
        {
            snapshot.failureOffset = raw.segment.framing.error.offset;
        }
        return false;
    }
    snapshot.fileBytes = raw.segment.framing.fileBytes;
    snapshot.prefixBytes = checkpoint.raw.end.byteOffset;
    return true;
}

// 从首段开始核对被动 API 标记。同一文件句柄上的投影只在整段和散列均通过后才发布。
SegmentSnapshot ReadApiFollowReplay(const QString& path, const CancelCheck& isCanceled, const SampleRequest& expected,
    const project::ProjectDocument& document, const std::string& sampleId, quint64 maxSegments)
{
    SegmentSnapshot snapshot; // 采样身份和已核验水位随首个成功的段一起发布。
    snapshot.path = path;
    snapshot.checkpoint = SegmentCheckpoint::Pending;
    std::deque<SegmentRow> rows; // 跨段保留近期原始行，保持正常总览的窗口上限。
    project::ProjectApiCheckpoint checkpoint; // 上一次连续验证的检查点。
    for (quint64 ordinal = 1; ordinal && !isCanceled(); ++ordinal)
    {
        if (maxSegments && ordinal > maxSegments)
        {
            snapshot.end = SegmentEnd::PreviewLimit;
            break;
        }
        std::deque<SegmentRow> page; // 本段尚未通过水位核验的临时投影。
        const auto read = project::ReadApiCheckpoint(document, sampleId, ordinal, ordinal > 1 ? &checkpoint : nullptr,
            checkpoint, [&](const archive::SegmentIdentity& identity, const archive::BlockInfo& block,
                const std::vector<archive::DecodedRecord>& records) {
                for (std::size_t index = 0; index < records.size(); ++index)
                {
                    if (isCanceled())
                    {
                        return false;
                    }
                    const auto& record = records.at(index); // 共享验证器保证本记录是有效 RawRecord。
                    const auto end = index + 1 < records.size() ? records.at(index + 1).recordOffset : block.endOffset;
                    const auto& raw = std::get<archive::RawRecordV1>(record.body); // 仅在回调期间借用。
                    const auto clue = project::ReadCommittedApiClue(raw); // 只把已知线索投影为 API 行。
                    page.push_back(clue ? ProjectApiClue(*clue, identity, record, end) : ProjectRecord(identity, record, end));
                }
                return true;
            });
        if (!read)
        {
            snapshot.end = read.error == project::ProjectError::NotFound ? SegmentEnd::IncompleteSample : SegmentEnd::InvalidCheckpoint;
            snapshot.failedOrdinal = read.error == project::ProjectError::NotFound ? 0 : ordinal;
            break;
        }

        // 累计水位包含未分类包与计划，API 筛选只作用于当前窗口里的已知线索。
        MergePage(rows, page);
        snapshot.checkpoint = SegmentCheckpoint::ApiRawVerified;
        snapshot.lastVerifiedOrdinal = ordinal;
        snapshot.verifiedRows = checkpoint.rawEnd.lastSequence;
        snapshot.apiFollowSourceRows = checkpoint.lastSourceSequence;
        snapshot.fileBytes = checkpoint.rawFileBytes;
        snapshot.prefixBytes = checkpoint.rawEnd.byteOffset;
        if (checkpoint.finalSegment)
        {
            snapshot.end = SegmentEnd::Complete;
            break;
        }
    }
    if (isCanceled())
    {
        snapshot = {};
        snapshot.path = path;
        snapshot.end = SegmentEnd::Canceled;
    }
    else if (snapshot.lastVerifiedOrdinal)
    {
        FinishProjectReplay(expected, rows, snapshot);
        snapshot.hasArchivedApi = std::any_of(snapshot.rows.cbegin(), snapshot.rows.cend(),
            [](const SegmentRow& row) { return row.archivedApi.has_value(); });
    }
    return snapshot;
}

// 绑定同一个已登记采样，按序验证发布的双流。缺标记不等于终止，不扫描未提交的后续 raw 文件。
SegmentSnapshot ReadProjectReplay(const QString& path, const CancelCheck& isCanceled, const SampleRequest& expected,
    quint64 maxSegments)
{
    SegmentSnapshot snapshot; // 仅发布连续通过验证的归档前缀或失败回执。
    snapshot.path = path;
    const auto boundPath = SampleRawSegmentPath(expected); // 请求的唯一入口路径。
    if (boundPath.isEmpty() || QDir::fromNativeSeparators(path).compare(boundPath, Qt::CaseInsensitive) != 0)
    {
        snapshot.end = SegmentEnd::WrongSample;
        return snapshot;
    }
    project::ProjectDocument document; // 本次读取专用的项目目录句柄。
    if (!document.Open(expected.manifestPath.toStdWString(), project::ProjectAccess::ReadOnly))
    {
        return snapshot;
    }
    const auto sampleId = expected.sample.id.toStdString(); // 目录请求中的规范 UUID。
    project::SampleRecord sample; // 重新核对已登记的冻结采样描述。
    if (document.Info()->projectId != expected.projectId.toStdString() || !document.ReadSample(sampleId, sample) ||
        sample.info.descriptionHash != expected.sample.descriptionHash.toStdString())
    {
        snapshot.end = SegmentEnd::WrongSample;
        return snapshot;
    }

    // 先确认被动 API 格式，阻止旧跟随档进入普通首段回退。
    project::ApiFollowArchiveKind apiKind; // 只用于分派读取器，探测不授予水位。
    const auto apiProbe = project::ProbeApiFollowArchive(document, sampleId, apiKind);
    if (!apiProbe)
    {
        snapshot.end = SegmentEnd::InvalidCheckpoint;
        snapshot.failedOrdinal = 1;
        return snapshot;
    }
    if (apiKind == project::ApiFollowArchiveKind::Checkpointed)
    {
        return ReadApiFollowReplay(path, isCanceled, expected, document, sampleId, maxSegments);
    }
    if (apiKind == project::ApiFollowArchiveKind::Legacy)
    {
        snapshot.end = SegmentEnd::IncompleteSample;
        snapshot.checkpoint = SegmentCheckpoint::ApiLegacyUnpublished;
        return snapshot;
    }

    // 全采样只保留最近窗口。单段验证失败或取消时，绝不提交该段的行。
    std::deque<SegmentRow> rows; // 各已验证段合并后的最近行。
    std::uint64_t previousSequence = 0; // 上一个已验证检查点的原始水位。
    for (quint64 ordinal = 1; !isCanceled(); ++ordinal) // 按连续发布序号逐段核验。
    {
        // 达到自动预算后不读取下一段，显式回放使用原有完整范围。
        if (maxSegments && ordinal > maxSegments)
        {
            snapshot.end = SegmentEnd::PreviewLimit;
            break;
        }
        project::ProjectEtwCheckpoint checkpoint; // 本次段的双流水位及终段标记。
        const auto result = document.ReadEtwCheckpoint(sampleId, checkpoint, ordinal); // 先验覆盖结果和 raw。
        if (isCanceled())
        {
            break;
        }
        if (result.error == project::ProjectError::NotFound)
        {
            if (ordinal == 1)
            {
                bool qtLive = false; // 首条记录确认 Qt 格式后才进入纯 raw 项目路径。
                auto legacy = ReadStandalone(path, isCanceled, &expected, &qtLive);
                return qtLive ? ReadQtRawReplay(path, isCanceled, expected, document, sampleId, maxSegments) : std::move(legacy);
            }
            snapshot.end = SegmentEnd::IncompleteSample;
            break;
        }

        // 原始序号为全采样连续序列，不接受段间重叠或断号。
        std::deque<SegmentRow> page; // 仅当前候选段，可整体丢弃。
        if (!result || previousSequence == UINT64_MAX || checkpoint.planRawSequence != previousSequence + 1 ||
            !ReadCommittedSegment(document, sampleId, ordinal, checkpoint, isCanceled, page, snapshot))
        {
            snapshot.end = SegmentEnd::InvalidCheckpoint;
            snapshot.failedOrdinal = ordinal;
            break;
        }

        // 当前段已完整回读，旧页只淘汰被最近窗口替换的行。
        MergePage(rows, page);
        snapshot.checkpoint = SegmentCheckpoint::Verified;
        snapshot.lastVerifiedOrdinal = ordinal;
        previousSequence = checkpoint.raw.end.lastSequence;
        if (checkpoint.finalSegment)
        {
            snapshot.end = SegmentEnd::Complete;
            break;
        }
    }

    // 取消回执不能替换先前页面状态，也不能泄漏途中暂存的行。
    if (isCanceled())
    {
        SegmentSnapshot canceled; // 只有可归属的取消回执。
        canceled.path = path;
        canceled.end = SegmentEnd::Canceled;
        return canceled;
    }
    if (snapshot.lastVerifiedOrdinal)
    {
        snapshot.verifiedRows = previousSequence; // 已从 1 连续读到此序号，含首尾元数据。
        FinishProjectReplay(expected, rows, snapshot);
    }
    return snapshot;
}
} // namespace

// 项目请求进入多段只读回放；独立文件继续使用诊断式前缀预览。
SegmentSnapshot ReadOfflineSegment(const QString& path, const CancelCheck& isCanceled, const SampleRequest* expected,
    quint64 maxProjectSegments)
{
    if (expected && !isCanceled())
    {
        return ReadProjectReplay(path, isCanceled, *expected, maxProjectSegments);
    }
    return ReadStandalone(path, isCanceled, expected);
}
}
