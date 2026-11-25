#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentReader.h"

#include <QDir>
#include <QFileInfo>
#include <QString>
#include <cstdio>
#include <string_view>

namespace
{
    namespace archive = ks::cli::action_analyze::archive;
    using ks::action_analyze::ReadOfflineSegment;
    using ks::action_analyze::SegmentEnd;

    // 检查一个读取断言；失败时输出夹具名和值的用途。
    bool Check(bool passed, const char* context)
    {
        if (!passed)
        {
            std::fprintf(stderr, "FAIL %s\n", context);
        }
        return passed;
    }

    // 写入三条合成流量记录，调用 Qt 读回入口检查来源、完整载荷与截断载荷。
    bool CheckNetworkReadback(const QString& root)
    {
        const archive::NetworkEvidenceBinding binding{{0x11}, {0x22}, "fixture-source", {0x33},
            "fixture-qpc", "fixture-boot", archive::NetworkTimeDomain::Qpc, 10'000'000}; // 固定采样和来源。
        archive::NetworkEvidenceArchive writer(std::filesystem::path(root.toStdWString()), binding, 1, 12345);
        archive::NetworkFlowMetadata flow; // 仅供本次读回的合成进程及端点。
        flow.processId = 40;
        flow.processCreatedUtc100ns = 12344;
        flow.processObjectId = 1;
        flow.sourceField = {{192, 0, 2, 1}, 52000};
        flow.destinationField = {{198, 51, 100, 2}, 443};
        flow.etw = archive::NetworkFlowMetadata::EtwDescriptor{10, 0, 10};
        flow.observedBytes = 20;
        const auto first = writer.Submit(binding, flow); // 第一条只含 ETW 流量元数据。

        // 第二条保留合成通信字节。记录不声明 ETW 描述符。
        flow.etw.reset();
        flow.observedBytes.reset();
        constexpr std::array<std::uint8_t, 4> captured{0x00, 0xff, 0x80, 0x4b};
        const auto second = writer.Submit(binding, flow,
            {archive::NetworkCaptureLayer::TransportPayload, captured.size(), captured});
        flow.receiveQpc = 25; // 部分载荷的接收时钟应原样回读。
        const std::array<std::uint8_t, 300> truncated{0xab, 0xcd}; // 超过界面单行预览限制。
        const auto third = writer.Submit(binding, flow,
            {archive::NetworkCaptureLayer::TransportPayload, 350, truncated, true});
        const auto finished = writer.Finish(archive::NetworkArchiveEnd::Stopped); // 刷盘并关闭本段。
        const auto path = root + QStringLiteral("/00000000000000000001.ksaseg"); // 新生成段的固定路径。
        const auto snapshot = ReadOfflineSegment(path, [] { return false; }); // 走产品独立段读取入口。
        if (!Check(first == archive::NetworkSubmitStatus::Queued && second == archive::NetworkSubmitStatus::Queued &&
                third == archive::NetworkSubmitStatus::Queued && finished.eofFlushed &&
                snapshot.end == SegmentEnd::Complete && snapshot.rows.size() == 4 &&
                snapshot.rows.at(0).network && snapshot.rows.at(1).network && snapshot.rows.at(2).network,
                "network Stored readback"))
        {
            return false;
        }

        // 独立段只能提供来源声明，字节回读仍须准确保留 NUL 和非 UTF-8 值。
        const auto& declaredEtw = *snapshot.rows.at(0).network;
        const auto& communication = *snapshot.rows.at(1).network;
        bool passed = Check(declaredEtw.sourceTrust == archive::NetworkSourceTrust::RecordedDeclaration &&
            declaredEtw.flow.observation.etw.has_value() && declaredEtw.preview.isEmpty() &&
            declaredEtw.flow.capture.state == archive::NetworkPayloadState::MetadataOnly &&
            snapshot.rows.at(0).actorId == 1 && !snapshot.rows.at(0).pid && !snapshot.rows.at(0).tid,
            "unverified ETW declaration and sample-local object reference");
        passed &= Check(communication.flow.capture.state == archive::NetworkPayloadState::Complete &&
            communication.flow.capture.capturedLength == captured.size() &&
            communication.preview == QByteArray("\x00\xff\x80\x4b", captured.size()) &&
            communication.inlineFileOffset == snapshot.rows.at(1).offset + archive::kRecordHeaderBytes +
                snapshot.rows.at(1).payloadBytes - captured.size(), "exact communication byte preview and file offset");
        const auto& partialRow = snapshot.rows.at(2); // 归档截断与本页预览截断使用各自口径。
        const auto& partial = *partialRow.network;
        passed &= Check(partial.flow.capture.state == archive::NetworkPayloadState::Truncated &&
            partial.flow.capture.originalLength == 350 && partial.flow.capture.capturedLength == 300 &&
            partial.preview.size() == 256 && partial.preview.startsWith(QByteArray("\xab\xcd", 2)) &&
            partialRow.receiveQpc == 25 && !snapshot.rows.at(3).network, "partial archive bytes, bounded preview and generic EOF");
        return passed;
    }
    // 按正式 CLI 写出的原始段读取记录，核对同一自有生产者的顺序、字节和来源语义。
    bool CheckLiveCliReadback(const QString& path)
    {
        const auto canceled = [] { return false; }; // 本夹具由父进程的期限管理。
        const auto standalone = ReadOfflineSegment(path, canceled); // 从真实段得出独立身份。
        ks::action_analyze::SampleRequest selected; // 冻结已选目录的项目和采样 UUID。
        QDir projectRoot = QFileInfo(path).absoluteDir(); // 从 raw 目录回到测试项目根。
        if (!Check(projectRoot.cdUp() && projectRoot.cdUp() && projectRoot.cdUp(), "CLI project root"))
        {
            return false;
        }
        selected.manifestPath = projectRoot.filePath(QStringLiteral("project.ksaproj"));
        selected.projectId = standalone.projectId;
        selected.sample.id = standalone.sampleId;
        const auto snapshot = ReadOfflineSegment(path, canceled, &selected); // 以目录约束再次读取。
        if (!Check(snapshot.end == SegmentEnd::Complete && snapshot.hasArchivedEtw && snapshot.rows.size() == 14,
            "complete CLI segment with plan, twelve events and terminal coverage"))
        {
            return false;
        }
        bool passed = Check(!snapshot.rows.front().liveEtw && !snapshot.rows.back().liveEtw,
            "plan and terminal coverage are separate from observations");
        // 同一路径而段头项目不符时，不能向目录页提交结果。
        auto wrongProject = selected; // 负控仅改变冻结请求中的项目 UUID。
        wrongProject.projectId = QStringLiteral("00000000-0000-0000-0000-000000000001");
        const auto mismatch = ReadOfflineSegment(path, canceled, &wrongProject);
        passed &= Check(mismatch.end == SegmentEnd::WrongSample && mismatch.rows.isEmpty() && !mismatch.ordinal,
            "mismatched segment identity does not publish archive rows");
        auto wrongRoot = selected; // 同一个文件不得用于另一目录的同 ID 请求。
        wrongRoot.manifestPath = projectRoot.filePath(QStringLiteral("other/project.ksaproj"));
        const auto misplaced = ReadOfflineSegment(path, canceled, &wrongRoot);
        passed &= Check(misplaced.end == SegmentEnd::WrongSample && misplaced.rows.isEmpty(),
            "matching segment UUIDs cannot override a different project path");
        for (qsizetype index = 0; index < 12; ++index)
        {
            const auto& row = snapshot.rows.at(index + 1); // 记录 1 为计划。
            QByteArray bytes(8, '\0'); // 自有样本的两个小端 u32 字段。
            bytes[0] = static_cast<char>(index / 2);
            bytes[4] = 28;
            passed &= Check(row.liveEtw && row.archivedEtw && row.liveEtw->eventId == 1 + index % 2 &&
                row.liveEtw->provider == QStringLiteral("d4a71ada-81b0-4b15-a173-417f33bc8107") &&
                row.receiveQpc && row.pid && row.tid && row.archivedEtw->originalBytes == 8 &&
                row.archivedEtw->storedBytes == 8 && row.archivedEtw->preview == bytes &&
                !row.actorId && !row.targetId && !row.threadId && !row.ordinal, "ETW source and original bytes");
        }
        if (passed)
        {
            std::puts("PASS QtCore CLI ETW readback: 12 events and exact bytes");
        }
        return passed;
    }
}

// 以固定夹具目录为输入，直接运行产品的 QtCore 读取路径。
int main(int argc, char** argv)
{
    if (argc == 3 && std::string_view(argv[1]) == "--etw-file")
    {
        return CheckLiveCliReadback(QString::fromLocal8Bit(argv[2])) ? 0 : 1;
    }
    if (argc != 2)
    {
        return 2;
    }
    const auto root = QString::fromLocal8Bit(argv[1]); // 存放可信格式向量的夹具目录。
    const auto read = [&root](const char* name) {
        return ReadOfflineSegment(root + u'/' + QString::fromLatin1(name) + QStringLiteral(".ksaseg"), [] { return false; });
    };
    const auto empty = read("valid-header-alone"); // 完整空文件仍含成对身份。
    bool passed = Check(empty.end == SegmentEnd::Complete && empty.rows.isEmpty() && empty.prefixBytes == 96,
        "valid empty segment");
    passed &= Check(empty.projectId == QStringLiteral("12345678-9abc-4def-8123-456789abcdef") &&
        empty.sampleId == QStringLiteral("fedcba98-7654-4321-a234-56789abcdef0"), "paired RFC UUIDs");

    const auto events = read("event-segment-with-known-zeroes"); // A0 向量的零值及固定字段。
    passed &= Check(events.end == SegmentEnd::Complete && events.rows.size() == 1 &&
        events.prefixBytes == events.fileBytes, "canonical segment");
    if (events.rows.size() == 1)
    {
        const auto& row = events.rows.front(); // 已验证的真实记录。
        passed &= Check(row.ordinal == 0 && row.receiveQpc == 2387509390608836392ull && row.decoded &&
            row.type == 4 && row.sequence == 29 && row.offset == 176,
            "known zero values, record type and offset");
        passed &= Check(row.category == 21862 && row.eventKind == 287454020 && row.sourceId == 72623859790382856ull &&
            !row.pid && !row.tid, "category and unresolved source, absent header IDs");
    }

    const auto partial = read("truncated-second-block-payload"); // 已通过校验的首块保留。
    passed &= Check(partial.end == SegmentEnd::Truncated && partial.rows.size() == 1 && partial.prefixBytes == 218 &&
        partial.prefixBytes < partial.fileBytes, "verified prefix after truncated block");
    const auto damaged = read("bad-second-stored-crc"); // 后续 CRC 失败不得提供行。
    passed &= Check(damaged.end == SegmentEnd::Invalid && damaged.rows.size() == 1 && damaged.prefixBytes == 218,
        "verified prefix after bad block CRC");
    const auto badBody = read("event-json-length-disagrees-with-payload"); // 封装可读不代表正文有效。
    passed &= Check(badBody.end == SegmentEnd::Invalid && badBody.rows.isEmpty() && badBody.prefixBytes == 96,
        "malformed canonical body");

    const auto optional = read("optional-unknown-record"); // 可选未知记录只保留封装字段。
    passed &= Check(optional.end == SegmentEnd::Complete && optional.rows.size() == 1 &&
        !optional.rows.front().decoded && !optional.rows.front().category, "opaque optional row");
    const auto required = read("required-unknown-record"); // 必需未知记录终止语义预览。
    passed &= Check(required.end == SegmentEnd::Unsupported && required.rows.isEmpty() && required.prefixBytes == 96,
        "unsupported required record");
    passed &= Check(read("unavailable-zstd").end == SegmentEnd::Unsupported, "unsupported codec");
    passed &= Check(read("missing").end == SegmentEnd::Unavailable, "missing file");

    // 在首条记录回调取消，确认已读取头部也不会产出正文行。
    int checks = 0; // 取消令牌读取次数，初次放行，下一次取消。
    const auto canceled = ReadOfflineSegment(events.path, [&checks]() { return ++checks > 1; });
    passed &= Check(canceled.end == SegmentEnd::Canceled && canceled.rows.isEmpty(), "canceled during preview");
    passed &= CheckNetworkReadback(root);
    if (passed)
    {
        std::puts("PASS 17 QtCore Stored reader assertions");
    }
    return passed ? 0 : 1;
}
