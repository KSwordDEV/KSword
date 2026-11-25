#include "../RawEvidenceArchive.h"
#include "../SegmentInspection.h"
#include "../../Project/ProjectRawEvidence.h"

#include <array>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <limits>

namespace {

namespace aa = Ksword::ActionAnalyze;
namespace archive = ks::cli::action_analyze::archive;
namespace fs = std::filesystem;

std::size_t checks = 0; // 通过的本机断言数。

// 每项在实际执行后计数，失败时报告对应检查并停止测试。
void Check(bool passed, const char* description)
{
    if (!passed) {
        std::cerr << "FAIL " << description << '\n';
        std::exit(1);
    }
    ++checks;
}

// 测试使用非契约元数据作为调用方输入。未声明这些字段为产品记录语义。
constexpr archive::RawEvidenceInput kSource{"{\"fixture\":\"source\"}", {}};
constexpr archive::RawEvidenceInput kObservation{"{\"fixture\":\"observation\",\"headerPid\":42}",
    std::string_view("\x00\x25\xff", 3)};
constexpr archive::RawEvidenceInput kEnd{"{\"fixture\":\"incomplete\",\"lost\":\"18446744073709551615\"}", {}};

// 建项目并提交两个样本。仅在指定采样的 raw 流追加、刷盘和重开。
void CheckProjectRoundTrip(const fs::path& scratch)
{
    const auto path = scratch / L"fixture-project";
    aa::ProjectDocument project;
    aa::SampleInfo sample;
    aa::SampleInfo other;
    Check(!!project.Create(path.wstring(), {"Archive bridge fixture", ""}), "create project");
    const auto projectId = project.Info()->projectId;
    Check(!!project.CreateSample("sample", sample), "create capture fixture sample");
    Check(!!project.CreateSample("other", other), "create second sample");

    // 两个块分别推进文件写入和刷盘端点。坏批次不占用归档序号。
    archive::RawEvidenceReceipt output;
    archive::RawEvidenceBoundary first;
    const aa::ProjectRawEvidenceWrite write{projectId, sample.sampleId, 1, std::nullopt,
        [&](archive::RawEvidenceArchive& writer) {
            const std::array bad{kSource, archive::RawEvidenceInput{"{\"x\":0,\"x\":1}", {}}};
            auto receipt = writer.Append(bad);
            Check(receipt.result.status == archive::SegmentWriteStatus::InvalidInput &&
                receipt.inputIssue == archive::BodyIssue::Json && receipt.rejectedInput == 1 &&
                !receipt.written && !receipt.flushed, "reject complete batch containing duplicate keys");

            const std::array start{kSource, kObservation};
            receipt = writer.Append(start, archive::QpcRange{0, 23});
            Check(receipt.result.status == archive::SegmentWriteStatus::Ok && !receipt.flushed &&
                receipt.written && receipt.written->lastSequence == 2 && receipt.written->blockOrdinal == 1,
                "written endpoint reflects first entire block");
            receipt = writer.Flush();
            Check(receipt.flushed && receipt.flushed->lastSequence == 2, "flush yields first boundary");
            first = *receipt.flushed;

            receipt = writer.Append(std::span(&kEnd, 1));
            Check(receipt.written && receipt.written->lastSequence == 3 && receipt.flushed &&
                receipt.flushed->byteOffset == first.byteOffset, "unflushed end leaves prior flush receipt");
            return aa::ProjectResult{};
        }};
    Check(!!project.WriteRawEvidenceSegment(write, output), "finish project raw segment");
    Check(output.flushed && output.flushed->blockOrdinal == 2 && output.flushed->lastSequence == 3,
        "finish yields final file flush endpoint");
    const auto expectedFinal = *output.flushed;

    // 不允许覆盖已有段。另一个采样的目录也不会被该写入修改。
    const aa::ProjectRawEvidenceWrite duplicate{projectId, sample.sampleId, 1, std::nullopt,
        [](archive::RawEvidenceArchive& writer) {
            const auto receipt = writer.Append(std::span(&kEnd, 1));
            Check(receipt.result.status == archive::SegmentWriteStatus::IoError && !receipt.written,
                "existing segment rejects CREATE_NEW");
            return aa::ProjectResult{};
        }};
    Check(project.WriteRawEvidenceSegment(duplicate, output).error == aa::ProjectError::AlreadyExists &&
        output.result.status == archive::SegmentWriteStatus::IoError, "return original create error at finish");

    // 第二段绑定目录记录与前一段的实际末序号，错误前序不能创建新段。
    bool resumed = false;
    aa::ProjectRawEvidenceWrite next{projectId, sample.sampleId, 2, 2,
        [&](archive::RawEvidenceArchive& writer) {
            resumed = true;
            const auto receipt = writer.Append(std::span(&kObservation, 1));
            Check(receipt.written && receipt.written->lastSequence == 4 &&
                receipt.written->blockOrdinal == 1, "new segment starts at verified next sequence");
            return aa::ProjectResult{};
        }};
    Check(project.WriteRawEvidenceSegment(next, output).error == aa::ProjectError::RecoveryRequired && !resumed,
        "project rejects incorrect prior segment receipt");
    next.previousSequence = expectedFinal.lastSequence;
    Check(!!project.WriteRawEvidenceSegment(next, output) && resumed && output.flushed,
        "write and flush following segment");
    const auto second = *output.flushed;

    project.Close();
    Check(!!project.Open(path.wstring()), "reopen project read-only");
    Check(project.WriteRawEvidenceSegment(write, output).error == aa::ProjectError::ReadOnly,
        "reject writing through read-only catalog");
    archive::SegmentInspection inspection;
    Check(!!project.InspectSegment(projectId, sample.sampleId, archive::StreamKind::Raw, 1,
        first.byteOffset, inspection) && inspection.framingStatus == archive::SegmentScanStatus::FramingComplete &&
        inspection.framingCoverage.framedBytes == first.byteOffset && !inspection.durableBytes,
        "existing framing inspection reopens the same prefix without checkpoint claims");

    // 历史读按已验证的文件端点扫描。比较元数据和原始字节的精确内容和顺序。
    const std::array expected{kSource, kObservation, kEnd};
    archive::RawEvidenceScanResult scan;
    std::size_t seen = 0;
    aa::ProjectRawEvidenceRead read{projectId, sample.sampleId, 1, expectedFinal.byteOffset, 0,
        [&](const archive::SegmentIdentity&, const archive::BlockInfo& block,
            const std::vector<archive::DecodedRecord>& records) {
            if (block.ordinal == 1) {
                Check(block.receiveQpc && block.receiveQpc->minimum == 0 && block.receiveQpc->maximum == 23,
                    "read explicit receive range including known zero");
            }
            for (const auto& record : records) {
                const auto& raw = std::get<archive::RawRecordV1>(record.body);
                Check(seen < expected.size() && record.recordSequence == seen + 1 &&
                    raw.metadataJson == expected[seen].metadataJson && raw.inlineRawData == expected[seen].inlineRawData,
                    "read exact caller metadata and original bytes in archived order");
                ++seen;
            }
            return true;
        }};
    Check(!!project.ReadRawEvidenceSegment(read, scan) && scan.VerifiedBoundary(expectedFinal) && seen == 3,
        "verify complete segment on catalog reopen");
    const aa::ProjectRawEvidenceRead readNext{projectId, sample.sampleId, 2, second.byteOffset,
        expectedFinal.lastSequence, {}};
    Check(!!project.ReadRawEvidenceSegment(readNext, scan) && scan.VerifiedBoundary(second),
        "verify second segment with previous sequence after catalog reopen");
    read.endOffset = first.byteOffset;
    seen = 0;
    Check(!!project.ReadRawEvidenceSegment(read, scan) && scan.VerifiedBoundary(first) && seen == 2,
        "honor first flush receipt despite later complete block");
    read.endOffset = first.byteOffset + 1;
    seen = 0;
    Check(!!project.ReadRawEvidenceSegment(read, scan) && !scan.VerifiedBoundary(first) && seen == 2 &&
        scan.segment.framing.status == archive::SegmentScanStatus::Truncated,
        "interior offset cannot be verified as an exact block endpoint");

    read.sampleId = other.sampleId;
    Check(project.ReadRawEvidenceSegment(read, scan).error == aa::ProjectError::NotFound,
        "no raw stream appears under other committed sample");
    read.sampleId = sample.sampleId;
    read.previousSequence = 1;
    Check(!!project.ReadRawEvidenceSegment(read, scan) && !scan.checked &&
        scan.issue == archive::RawEvidenceScanIssue::UnexpectedSequence, "reject unbound predecessor");

    // 制造真实短尾。读者保留首块可读端点，且不截断原件或生成检查点。
    project.Close();
    const auto samplePath = path / L"samples" / fs::path(sample.sampleId);
    const auto rawPath = samplePath / L"raw" / L"00000000000000000001.ksaseg";
    fs::resize_file(rawPath, expectedFinal.byteOffset - 1);
    Check(!!project.Open(path.wstring()), "open after fixture disk truncation");
    read.endOffset = expectedFinal.byteOffset;
    read.previousSequence = 0;
    seen = 0;
    Check(!!project.ReadRawEvidenceSegment(read, scan) && !scan.VerifiedBoundary(expectedFinal) && seen == 2 &&
        scan.checked && scan.checked->byteOffset == first.byteOffset &&
        scan.segment.framing.status == archive::SegmentScanStatus::Truncated, "recover only prior whole block");
    Check(fs::file_size(rawPath) == expectedFinal.byteOffset - 1, "recovery leaves source bytes unchanged");
    Check(!fs::exists(samplePath / L"checkpoints") && !fs::exists(samplePath / L"sealed.json"),
        "archive leaves checkpoint and seal absent");
}

// 验证输入边界以及收尾没有内容时的行为。期望向量手写以避免循环验证。
void CheckWriterLimits(const fs::path& scratch)
{
    std::vector<std::uint8_t> encoded{0xf1};
    Check(archive::EncodeRawRecordV1("\xef\xbb\xbf{}", {}, encoded) == archive::BodyIssue::Json &&
        encoded == std::vector<std::uint8_t>{0xf1}, "BOM failure preserves supplied output");
    Check(archive::EncodeRawRecordV1("{}", std::string_view("\x00\xff", 2), encoded) == archive::BodyIssue::None &&
        encoded == std::vector<std::uint8_t>{2, 0, 0, 0, 0x7b, 0x7d, 0x00, 0xff}, "literal RawRecord v1 bytes");

    const auto path = scratch / L"sequence-limit.ksaseg";
    archive::SegmentHeader header;
    header.identity.stream = archive::StreamKind::Raw;
    constexpr auto limit = (std::numeric_limits<std::uint64_t>::max)();
    archive::RawEvidenceArchive writer(path, header, limit);
    auto receipt = writer.Append(std::span(&kObservation, 1));
    Check(receipt.result.error.issue == archive::SegmentIssue::Sequence && !receipt.written,
        "u64 sequence does not wrap");
    receipt = writer.Finish();
    Check(receipt.result.status == archive::SegmentWriteStatus::Ok && !receipt.flushed && !fs::exists(path),
        "finish without records creates no segment");
    Check(writer.Append(std::span(&kObservation, 1)).result.status == archive::SegmentWriteStatus::Closed,
        "closed segment rejects late producer");
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) {
        return 2;
    }
    const fs::path scratch(argv[1]); // 验证脚本独占创建的固定输出目录。
    CheckProjectRoundTrip(scratch);
    CheckWriterLimits(scratch);
    std::cout << "PASS " << checks << " raw evidence archive checks\n";
    return 0;
}
