#include "OfflineSegmentReader.h"

#include "../../../KswordCLI/ActionAnalyze/Archive/SegmentBodies.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <QUuid>
#include <algorithm>
#include <windows.h>

namespace ks::action_analyze
{
namespace
{
    namespace archive = ks::cli::action_analyze::archive;
    constexpr std::uint64_t kPreviewBytes = 64ull * 1024 * 1024; // 扫描的文件前缀上限。
    constexpr qsizetype kPreviewRows = 4096; // 一次提交到 UI 的记录上限。

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

    // 将段头 RFC 字节身份按规范小写文本呈现。
    QString UuidText(const archive::ArchiveUuid& uuid)
    {
        const auto* bytes = reinterpret_cast<const char*>(uuid.data()); // 原始字节按 RFC 顺序。
        return QUuid::fromRfc4122(QByteArrayView(bytes, static_cast<qsizetype>(uuid.size()))).toString(QUuid::WithoutBraces);
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
}

// 从同一只读文件句柄先获得段身份，再按此身份读取公共语义前缀。
SegmentSnapshot ReadOfflineSegment(const QString& path, const CancelCheck& isCanceled)
{
    SegmentSnapshot snapshot; // 只有通过实际检查的数据才发布。
    snapshot.path = path;
    if (isCanceled())
    {
        snapshot.end = SegmentEnd::Canceled;
        return snapshot;
    }
    const auto nativePath = path.toStdWString(); // 原生绝对路径用于打开指定文件。
    const SegmentFile file{CreateFileW(nativePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (file.handle == INVALID_HANDLE_VALUE || GetFileType(file.handle) != FILE_TYPE_DISK)
    {
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
    snapshot.ordinal = identity.ordinal;
    snapshot.stream = static_cast<quint32>(identity.stream);
    snapshot.prefixBytes = archive::kSegmentHeaderBytes;

    // 记录回调只接受经过共享扫描器验证的块和已理解的必需正文。
    const auto boundary = (std::min)(header.fileBytes, kPreviewBytes); // 实际字节读取上限。
    std::optional<SegmentEnd> stop; // Qt 预览提前停止的原因。
    const auto body = archive::ScanOpenSegmentBodies(file.handle, identity, boundary,
        [&](const archive::SegmentIdentity&, const archive::BlockInfo& block,
            const std::vector<archive::DecodedRecord>& records) {
            for (std::size_t index = 0; index < records.size(); ++index)
            {
                const auto& record = records.at(index); // 块内已校验的记录及正文。
                if (isCanceled())
                {
                    stop = SegmentEnd::Canceled;
                }
                else if (snapshot.rows.size() >= kPreviewRows)
                {
                    stop = SegmentEnd::PreviewLimit;
                }
                else if ((record.flags & archive::kRequiredRecord) && std::holds_alternative<std::monostate>(record.body))
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
                SegmentRow row; // 值投影不借用共享解码器缓冲区。
                row.sequence = record.recordSequence;
                row.offset = record.recordOffset;
                row.type = record.recordType;
                row.version = record.recordSchemaVersion;
                row.payloadBytes = static_cast<quint32>(end - record.recordOffset - archive::kRecordHeaderBytes);
                ProjectBody(record.body, row);
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
    return snapshot;
}
}
