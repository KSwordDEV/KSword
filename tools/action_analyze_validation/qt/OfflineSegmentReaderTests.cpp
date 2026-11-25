#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentReader.h"
#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/LiveSampleArchive.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QString>
#include <QUuid>
#include <algorithm>
#include <cstdio>
#include <string_view>

namespace
{
    namespace archive = ks::cli::action_analyze::archive;
    namespace project = Ksword::ActionAnalyze;
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
        // 与项目页一样，从项目目录取得已登记采样的冻结描述散列。
        const auto catalog = ks::action_analyze::ReadProjectCatalog(
            projectRoot.filePath(QStringLiteral("project.ksaproj")), canceled);
        const auto sample = std::find_if(catalog.samples.cbegin(), catalog.samples.cend(),
            [&standalone](const auto& entry) { return entry.id == standalone.sampleId; }); // 同一采样的目录行。
        if (!Check(catalog.problem.status == ks::action_analyze::ReadStatus::Ready && sample != catalog.samples.cend(),
            "CLI sample registered in project catalog"))
        {
            return false;
        }
        selected = {catalog.manifestPath, catalog.id, *sample};
        const auto snapshot = ReadOfflineSegment(path, canceled, &selected); // 以目录约束再次读取。
        if (!Check(snapshot.end == SegmentEnd::Complete && snapshot.hasArchivedEtw && snapshot.rows.size() == 14 &&
            snapshot.checkpoint == ks::action_analyze::SegmentCheckpoint::Verified,
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
        auto staleSample = selected; // 保持项目、路径和 UUID 相同，只修改冻结散列。
        staleSample.sample.descriptionHash = QString(64, u'0');
        const auto stale = ReadOfflineSegment(path, canceled, &staleSample); // 目录行已与真实描述不符。
        passed &= Check(stale.end == SegmentEnd::WrongSample && stale.rows.isEmpty(), "stale sample description hash");
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

    // 使用正式项目及段写入器构造已知序号、字节和覆盖的 ETW 测试段。
    bool WriteEtwSegment(project::ProjectDocument& document, const project::SampleRecord& sample,
        std::uint64_t ordinal, std::uint64_t previous, std::size_t count, bool final,
        bool publish, bool continuous = true)
    {
        constexpr char provider[] = "d4a71ada-81b0-4b15-a173-417f33bc8107"; // 合成提供程序身份。
        constexpr char epoch[] = "fedcba98-7654-4321-a234-56789abcdef0"; // 固定来源代次。
        const auto& id = sample.info.sampleId; // 真实登记的采样 UUID。
        const auto plan = std::string(R"({"kind":"etw-capture-plan-v1","backend":"r3","session":{"id":")") + id +
            R"("},"revisionId":")" + sample.info.revisionId + R"(","snapshotId":")" + sample.info.snapshotId +
            R"(","revisionHash":")" + sample.revisionHash + R"(","configSemanticHash":")" + sample.configSemanticHash +
            R"(","providerId":")" + provider + R"(","sourceEpoch":")" + epoch + R"(","headerPid":40,"durationMs":)" +
            (continuous ? "0}" : "500}");
        // 每个段的 ETW 接收时钟和原始字节对应到本段，便于校验来源没有错置。
        const auto observation = std::string(R"({"kind":"etw-observation-v1","providerId":")") + provider +
            R"(","sourceEpoch":")" + epoch + R"(","headerPid":40,"headerTid":41,"descriptor":{"id":1,"version":0,"opcode":0},)"
            R"("sourceFileTime100ns":"100","receiveQpc":")" + std::to_string(ordinal) +
            R"(","qpcFrequencyHz":"1000","originalPayloadBytes":2,"storedPayloadBytes":"2","malformedPayload":false})";
        const std::array bytes{static_cast<char>(ordinal), '\0'}; // 保留尾 NUL 的实际载荷。
        const auto tail = std::string(R"({"kind":"etw-capture-end-v1","stopReason":")") +
            (final ? "stopped" : "segment-rotated") + R"(","finalSegment":)" + (final ? "true" : "false") +
            R"(,"segmentObservations":")" + std::to_string(count) + R"(","source":{"sourceEpoch":")" + epoch +
            R"(","enqueued":")" + std::to_string(count) +
            R"(","queued":"0","eventsLost":null,"logBuffersLost":null,"realTimeBuffersLost":null,)"
            R"("queueDropped":"0","payloadTruncated":"0","malformedPayload":"0"}})";
        archive::RawEvidenceReceipt raw; // 写入器的实际已刷盘端点。
        const auto written = document.WriteRawEvidenceSegment({document.Info()->projectId, id, ordinal, previous,
            [&](archive::RawEvidenceArchive& writer) -> project::ProjectResult {
                const archive::RawEvidenceInput first{plan, {}}; // 计划使用自己的块。
                const archive::RawEvidenceInput last{tail, {}}; // 尾记录使用自己的块。
                if (writer.Append(std::span(&first, 1)).result.status != archive::SegmentWriteStatus::Ok)
                {
                    return {project::ProjectError::IoError, 0, "fixturePlan"};
                }
                // 每批固定上限，和生产写入一样形成多个完整块。
                const std::vector<archive::RawEvidenceInput> batch(128,
                    {observation, std::string_view(bytes.data(), bytes.size())});
                for (std::size_t index = 0; index < count; index += batch.size())
                {
                    if (writer.Append(std::span(batch).first((std::min)(batch.size(), count - index)))
                        .result.status != archive::SegmentWriteStatus::Ok)
                    {
                        return {project::ProjectError::IoError, 0, "fixtureObservation"};
                    }
                }
                if (writer.Append(std::span(&last, 1)).result.status != archive::SegmentWriteStatus::Ok)
                {
                    return {project::ProjectError::IoError, 0, "fixtureTail"};
                }
                return {};
            }}, raw);
        if (!written || !raw.flushed)
        {
            std::fprintf(stderr, "fixture write %llu: %s (%u)\n", static_cast<unsigned long long>(ordinal),
                written.detail, written.nativeError);
            return false;
        }
        const archive::EtwCoverageV1 coverage{provider, epoch, ordinal, previous + 1, previous + count + 2, count,
            std::nullopt, std::nullopt, std::nullopt, 0, 0, 0}; // 同段实际计划与尾序号。
        project::ProjectEtwCheckpoint checkpoint; // 发表前由公共代码复验。
        if (!publish)
        {
            return true;
        }
        const auto result = document.PublishEtwCheckpoint(id, *raw.flushed, coverage, checkpoint); // 记录共享层失败原因。
        if (!result)
        {
            std::fprintf(stderr, "fixture publish %llu: %s (%u)\n", static_cast<unsigned long long>(ordinal),
                result.detail, result.nativeError);
        }
        return static_cast<bool>(result);
    }

    // 将测试项目目录里已冻结的三项身份传给产品项目回放入口。
    ks::action_analyze::SampleRequest ReplayRequest(const QString& path, const project::ProjectDocument& document,
        const project::SampleRecord& sample)
    {
        const auto& info = sample.info; // 正式项目目录给出的冻结身份。
        return {path, QString::fromStdString(document.Info()->projectId),
            {QString::fromStdString(info.sampleId), QString::fromStdString(info.title), info.createdUtc,
                QString::fromStdString(info.revisionId), QString::fromStdString(info.snapshotId),
                QString::fromStdString(info.descriptionHash)}};
    }

    // 基于合成段核对旧档、活前缀、正常结束、裁剪、取消和坏尾回退。
    bool CheckProjectReplay(const QString& root)
    {
        using ks::action_analyze::SegmentCheckpoint;
        const auto folder = QDir(root).filePath(QStringLiteral("replay-project")); // 脚本为本夹具保留的固定目录。
        const auto manifest = QDir(folder).filePath(QStringLiteral("project.ksaproj")); // 传给项目回放入口。
        project::ProjectDocument document; // 本夹具持有的唯一写者。
        project::SampleInfo catalogEntry; // 第一份冻结目录行。
        project::SampleRecord sample; // 包含正式归档要求的冻结散列。
        if (!Check(document.Create(folder.toStdWString(), {"Replay", "ETW fixture"}) &&
            document.CreateSample("Continuous", catalogEntry) && document.ReadSample(catalogEntry.sampleId, sample),
            "create registered replay fixture"))
        {
            return false;
        }

        const auto request = ReplayRequest(manifest, document, sample); // 冻结选中的项目和采样。
        const auto path = ks::action_analyze::SampleRawSegmentPath(request); // 入口始终对应 raw/1。
        const auto read = [&] { return ReadOfflineSegment(path, [] { return false; }, &request); };
        if (!Check(WriteEtwSegment(document, sample, 1, 0, 2, false, true), "publish first continuous segment"))
        {
            return false;
        }
        const auto first = read(); // 存在首段但尚无整次采样的结束记录。
        bool passed = Check(first.end == SegmentEnd::IncompleteSample && first.lastVerifiedOrdinal == 1 &&
            first.checkpoint == SegmentCheckpoint::Verified && first.verifiedRows == 4 && first.rows.size() == 4,
            "verified segment without final checkpoint is incomplete");

        // 中段超出单页，检查最终回放跨段保留最近序号，并仍使用同个采样入口。
        if (!Check(WriteEtwSegment(document, sample, 2, 4, 4100, false, true) &&
            WriteEtwSegment(document, sample, 3, 4106, 1, true, true), "publish middle and final segments"))
        {
            return false;
        }
        QFile finalSegment(QFileInfo(path).absoluteDir().filePath(QStringLiteral("00000000000000000003.ksaseg"))); // 终段文件。
        if (!Check(finalSegment.open(QIODevice::WriteOnly | QIODevice::Append) && finalSegment.write("tail", 4) == 4,
            "append bytes after final committed boundary"))
        {
            return false;
        }
        finalSegment.close();
        const auto full = read(); // 三个检查点连续有效，终段证明采样结束。
        passed &= Check(full.end == SegmentEnd::Complete && full.checkpoint == SegmentCheckpoint::Verified &&
            full.lastVerifiedOrdinal == 3 && full.ordinal == 1 && full.failedOrdinal == 0 &&
            full.sampleId == request.sample.id && full.verifiedRows == 4109 && full.rows.size() == 4096 &&
            full.fileBytes == full.prefixBytes + 4,
            "complete project replay presents latest bounded window");
        if (full.rows.size() == 4096)
        {
            const auto& observation = full.rows.at(full.rows.size() - 2); // 终段的唯一实际观察。
            passed &= Check(full.rows.front().sequence == 14 && full.rows.front().segmentOrdinal == 2 &&
                full.rows.back().sequence == 4109 && full.rows.back().segmentOrdinal == 3 &&
                observation.sequence == 4108 && observation.segmentOrdinal == 3 && observation.archivedEtw &&
                observation.archivedEtw->preview == QByteArray("\x03\0", 2) && observation.receiveQpc == 3,
                "latest page retains absolute sequence, raw segment identity and exact bytes");
        }

        int checks = 0; // 首段两次验证中的投影阶段触发取消。
        const auto canceled = ReadOfflineSegment(path, [&checks] { return ++checks >= 5; }, &request);
        passed &= Check(canceled.end == SegmentEnd::Canceled && canceled.rows.isEmpty() && !canceled.lastVerifiedOrdinal,
            "cancellation discards staged project rows");

        // 破坏已发布终段的 raw 头，投影只能保留前两个独立核验过的段。
        if (!Check(finalSegment.open(QIODevice::WriteOnly) && finalSegment.write("broken", 6) == 6,
            "damage final segment of isolated fixture"))
        {
            return false;
        }
        finalSegment.close();
        const auto partial = read(); // 终段的失败与前一水位有独立身份。
        passed &= Check(partial.end == SegmentEnd::InvalidCheckpoint && partial.failedOrdinal == 3 &&
            partial.lastVerifiedOrdinal == 2 && partial.verifiedRows == 4106 && partial.rows.size() == 4096 &&
            partial.rows.back().sequence == 4106 && partial.rows.back().segmentOrdinal == 2,
            "damaged final segment keeps previously verified prefix");

        // 同一个项目的两个额外采样，检查无标记场景与旧档兼容。
        for (const bool continuous : {true, false})
        {
            if (!Check(document.CreateSample(continuous ? "Pending" : "Legacy", catalogEntry) &&
                document.ReadSample(catalogEntry.sampleId, sample) &&
                WriteEtwSegment(document, sample, 1, 0, 1, !continuous, false, continuous),
                "write unmarked project sample"))
            {
                return false;
            }
            const auto unmarked = ReplayRequest(manifest, document, sample); // 对应本轮冻结的采样。
            const auto preview = ReadOfflineSegment(ks::action_analyze::SampleRawSegmentPath(unmarked),
                [] { return false; }, &unmarked);
            if (continuous)
            {
                passed &= Check(preview.end == SegmentEnd::IncompleteSample && preview.checkpoint == SegmentCheckpoint::Pending &&
                    !preview.ordinal && preview.rows.isEmpty(), "unmarked continuous first segment stays unpublished");
            }
            else
            {
                passed &= Check(preview.end == SegmentEnd::Complete && preview.checkpoint == SegmentCheckpoint::Unpublished &&
                    preview.rows.size() == 3 && preview.hasArchivedEtw, "legacy unmarked single segment fallback");
            }
        }
        if (passed)
        {
            std::puts("PASS QtCore project ETW replay: intermediate, final, bounded page, damaged tail, pending and legacy");
        }
        return passed;
    }

    // 复用生产 Qt writer 写入活动、ETW 报头和终止段，再通过项目入口核对原观测与封装序号。
    bool CheckQtRawReplay(const QString& root)
    {
        using namespace ks::action_analyze;
        const auto manifest = QDir(root).filePath(QStringLiteral("replay-project/project.ksaproj")); // 固定测试项目。
        project::ProjectDocument document; // 仅从目录读取本次 writer 所需的冻结身份。
        if (!Check(static_cast<bool>(document.Open(manifest.toStdWString(), project::ProjectAccess::ReadOnly)),
            "open shared fixture project"))
        {
            return false;
        }
        const LiveArchiveProject context{manifest, QString::fromStdString(document.Info()->projectId),
            QString::fromStdString(document.Info()->revisionId)}; // 与真实总览交给工作线程的内容一致。
        document.Close(); // 新采样提交后重新打开，旧只读目录不会看到新代次。
        LiveSampleArchive writer; // 直接调用生产 Qt 保存路径。
        const auto registered = writer.open(context, 40); // 采集工具条可直接回读的冻结目录行。
        project::SampleRecord sample; // 项目页冻结的采样描述。
        SegmentRow activity; // 合成进程区间，I/O 读计数明确未知，写计数为零。
        activity.sequence = 1;
        activity.pid = 40;
        activity.liveProcess = LiveProcessObservation{50, 1050, 20000, std::nullopt, 0};
        if (!Check(registered && writer.write({activity}),
            "Qt raw first segment via production writer"))
        {
            std::fprintf(stderr, "%s\n", writer.status().error.toUtf8().constData());
            return false;
        }
        if (!Check(document.Open(manifest.toStdWString(), project::ProjectAccess::ReadOnly) &&
            document.ReadSample(registered->sample.id.toStdString(), sample), "reopen catalog after Qt writer registers sample"))
        {
            return false;
        }
        const auto& request = *registered; // 直接使用采集写入器返回的真实目录行。
        const auto path = SampleRawSegmentPath(request); // 固定项目回放的首段位置。
        const auto read = [&] { return ReadOfflineSegment(path, [] { return false; }, &request); };
        const auto midway = read(); // 第一个完整段已刷盘，尚无终止记录。
        bool passed = Check(midway.end == SegmentEnd::IncompleteSample && midway.lastVerifiedOrdinal == 1 &&
            midway.checkpoint == SegmentCheckpoint::QtRawVerified && midway.rows.size() == 1 &&
            !midway.hasArchivedEtw && !midway.qtArchiveDropped, "Qt ongoing prefix without ETW payload or terminal");

        // 制造一个原观测序号缺口，封装序号仍由生产 writer 连续分配。
        SegmentRow header;
        header.sequence = 3;
        header.pid = 40;
        header.tid = 41;
        header.receiveQpc = 100;
        header.liveEtw = LiveEtwHeader{QStringLiteral("{d4a71ada-81b0-4b15-a173-417f33bc8107}"), 51, 2, 1, 3};
        const std::string terminal = R"({"kind":"qt-live-end-v1","reason":"requested","observed":"3",)"
            R"("headerPid":"40","creationFileTime":"50","provider":"{d4a71ada-81b0-4b15-a173-417f33bc8107}",)"
            R"("archiveQueueDropped":"1","nativeTailUnconfirmed":false,"eventsLost":null})"; // 生产终止记录的实际字段。
        if (!Check(writer.write({header}) && writer.write({}, terminal) && writer.status().finished &&
            writer.status().verifiedSegments == 3, "Qt raw three verified segments written"))
        {
            return false;
        }
        passed &= Check(!writer.write({header}), "Qt writer rejects rows after terminal");
        writer.close();
        const auto full = read(); // 第三段是独立终止记录，只计入水位。
        if (!Check(full.end == SegmentEnd::Complete && full.checkpoint == SegmentCheckpoint::QtRawVerified &&
            full.lastVerifiedOrdinal == 3 && full.verifiedRows == 3 && full.rows.size() == 2 &&
            full.hasArchivedEtw && full.qtArchiveDropped == 1 && full.fileBytes == full.prefixBytes,
            "Qt raw reopening completes at terminal without rendering it as an observation"))
        {
            return false;
        }
        const auto& process = full.rows.front(); // 进程活动字段保持未知和零的语义。
        const auto& event = full.rows.back(); // 此 ETW 只有头字段与原观测坐标。
        passed &= Check(process.liveProcess && process.liveProcess->creationTime == 50 &&
            !process.liveProcess->readBytes && process.liveProcess->writeBytes == 0 && !process.receiveQpc &&
            process.sequence == 1 && process.liveSourceSequence == 1 && process.segmentOrdinal == 1,
            "Qt raw process readback preserves values and unknowns");
        passed &= Check(event.liveEtw && !event.archivedEtw && event.liveEtw->eventId == 2 && event.tid == 41 &&
            event.sequence == 2 && event.liveSourceSequence == 3 && event.segmentOrdinal == 2 && event.receiveQpc == 100,
            "Qt raw ETW headers with separate source and Stored sequences");

        // 保留有效第二段的块并添加坏尾，核对暂存观测没有从坏段逸出。
        QFile middle(QFileInfo(path).absoluteDir().filePath(QStringLiteral("00000000000000000002.ksaseg")));
        if (!Check(middle.open(QIODevice::WriteOnly | QIODevice::Append) && middle.write("tail", 4) == 4,
            "append invalid bytes after a valid Qt raw block"))
        {
            return false;
        }
        middle.close();
        const auto partial = read(); // 第一段依然可用，终止第三段不越过失败段。
        passed &= Check(partial.end == SegmentEnd::Invalid && partial.failedOrdinal == 2 &&
            partial.lastVerifiedOrdinal == 1 && partial.rows.size() == 1 && partial.verifiedRows == 1 &&
            !partial.hasArchivedEtw && !partial.qtArchiveDropped, "Qt raw bad middle segment does not publish any rows");
        if (!Check(middle.remove(), "remove only fixture middle segment to verify ordinal gap"))
        {
            return false;
        }
        const auto gap = read(); // 缺第二段时无法把第三段确认为这个前缀的终点。
        passed &= Check(gap.end == SegmentEnd::IncompleteSample && gap.lastVerifiedOrdinal == 1 && gap.rows.size() == 1,
            "Qt raw replay does not cross missing raw file");

        // 写入封装和同一采样身份都正确、但起始记录有断号的第二段。
        const auto uuid = [](const QString& text) {
            const auto bytes = QUuid(text).toRfc4122(); // 归档段头以 RFC 字节顺序保存 UUID。
            archive::ArchiveUuid id{}; // 共享写入器需要的定长数组。
            std::copy_n(bytes.cbegin(), id.size(), id.begin());
            return id;
        };
        archive::RawEvidenceArchive jumped(std::filesystem::path(middle.fileName().toStdWString()),
            {{archive::StreamKind::Raw, 2, uuid(request.projectId), uuid(request.sample.id)}, 50}, 8);
        const archive::RawEvidenceInput skipped{
            R"({"kind":"qt-process-activity-v1","liveSequence":"3","receiveQpc":null,"headerPid":"40",)"
            R"("creationFileTime":"50","elapsedMs":"1000","cpu100ns":"1","readBytes":null,"writeBytes":null})", {}};
        if (!Check(jumped.Append(std::span(&skipped, 1)).result.status == archive::SegmentWriteStatus::Ok &&
            jumped.Finish().flushed.has_value(), "write a framing-valid Qt raw segment with discontinuous Stored sequence"))
        {
            return false;
        }
        const auto discontinuous = read(); // 从第一段末序号接续，不能单独认可第二段的 CRC。
        passed &= Check(discontinuous.end == SegmentEnd::Invalid && discontinuous.failedOrdinal == 2 &&
            discontinuous.lastVerifiedOrdinal == 1 && discontinuous.rows.size() == 1,
            "Qt raw project rejects a framing-valid cross-segment Stored sequence gap");
        if (passed)
        {
            std::puts("PASS QtCore Qt-written raw replay: intermediate, terminal, header-only, bad middle and sequence gaps");
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
    passed &= CheckProjectReplay(root);
    passed &= CheckQtRawReplay(root);
    if (passed)
    {
        std::puts("PASS 17 QtCore Stored reader assertions");
    }
    return passed ? 0 : 1;
}
