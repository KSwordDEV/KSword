#include "../NetworkEvidenceArchive.h"
#include "../SegmentBodies.h"
#include "../SegmentInspection.h"

#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <utility>
#include <windows.h>

namespace {

namespace a = ks::cli::action_analyze::archive;
using a::NetworkSubmitStatus;
using a::SegmentScanStatus;
using a::SegmentWriteStatus;
constexpr std::array<std::uint8_t, 7> kKnownBytes{0, 255, 128, 14, 0, 0x4b, 0x53};
std::size_t assertions = 0;

void Check(bool condition, const char* what)
{
    if (!condition) throw std::runtime_error(what);
    ++assertions;
}

a::NetworkEvidenceBinding Binding()
{
    return {{0x11}, {0x22}, "fixture/source.1", {0x33}, "fixture-clock", "fixture:boot",
        a::NetworkTimeDomain::Qpc, 10000000};
}

a::NetworkFlowMetadata Flow(std::uint64_t tick = 5)
{
    a::NetworkFlowMetadata flow;
    flow.sourceField = {{192, 0, 2, 8}, std::uint16_t{0}};
    flow.destinationField = {{198, 51, 100, 12}, std::uint16_t{443}};
    flow.processId = 175;
    flow.processCreatedUtc100ns = 0x1000020000400;
    flow.processObjectId = 27;
    flow.sourceTimestamp = tick;
    flow.producerSequence = 0;
    flow.receiveQpc = tick + 30;
    flow.observedBytes = 0;
    flow.etw = a::NetworkFlowMetadata::EtwDescriptor{10, 0, 0};
    return flow;
}

struct File {
    explicit File(const std::filesystem::path& path, DWORD access = GENERIC_READ)
        : handle(CreateFileW(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL, nullptr))
    {
        Check(handle != INVALID_HANDLE_VALUE, "open fixture file");
    }
    ~File() { CloseHandle(handle); }
    File(const File&) = delete;
    File& operator=(const File&) = delete;
    HANDLE handle;
};

std::filesystem::path Segment(const std::filesystem::path& scratch, std::uint64_t ordinal)
{
    const auto scope = Binding();
    return scratch / a::NameInspectionSegment({a::StreamKind::Raw, ordinal, scope.project, scope.sample})->fileName;
}

void CutPhysicalTail(const std::filesystem::path& path, std::uint64_t bytes)
{
    const File file(path, GENERIC_WRITE);
    LARGE_INTEGER physicalTail{};
    physicalTail.QuadPart = static_cast<LONGLONG>(bytes);
    Check(SetFilePointerEx(file.handle, physicalTail, nullptr, FILE_BEGIN) != 0 && SetEndOfFile(file.handle) != 0,
        "truncate the owned fixture segment");
}

void RoundTrip(const std::filesystem::path& scratch)
{
    const auto scope = Binding();
    a::NetworkEvidenceArchive writer(scratch, scope, 1, 12345, 91);
    auto wrong = scope;
    wrong.sample[1] = 8;
    auto flow = Flow();
    Check(writer.Submit(wrong, flow) == NetworkSubmitStatus::WrongBinding && !writer.ReportSourceLoss(wrong, 1),
          "another sample cannot submit records or loss");
    wrong = scope;
    wrong.sourceEpoch[1] = 9;
    Check(writer.Submit(wrong, flow) == NetworkSubmitStatus::WrongBinding, "wrong source epoch cannot submit");
    flow.processCreatedUtc100ns = 0;
    Check(writer.Submit(scope, flow) == NetworkSubmitStatus::InvalidObservation, "reject unresolved process instance");
    flow = Flow();
    Check(writer.Submit(scope, flow) == NetworkSubmitStatus::Queued, "queue metadata-only observation");
    auto suppliedBytes = kKnownBytes;
    Check(writer.Submit(scope, Flow(8), {a::NetworkCaptureLayer::TransportPayload, 7, suppliedBytes}) ==
        NetworkSubmitStatus::Queued, "queue verified communication bytes");
    suppliedBytes.fill(17);
    flow.transport = a::NetworkTransport::Udp;
    flow.direction = a::NetworkDirection::Inbound;
    flow.family = a::NetworkFamily::IPv6;
    flow.destinationField.address.back() = 1;
    flow.sourceField.port.reset();
    flow.etw.reset();
    Check(writer.Submit(scope, flow, {a::NetworkCaptureLayer::IpPacket, 10, kKnownBytes, true}) ==
        NetworkSubmitStatus::Queued, "queue already truncated IPv6 observation");
    Check(writer.Submit(scope, flow, {a::NetworkCaptureLayer::TransportPayload, 0, {}}) ==
        NetworkSubmitStatus::Queued, "queue verified empty payload");
    Check(writer.Submit(scope, flow, {a::NetworkCaptureLayer::LinkFrame, std::nullopt, kKnownBytes}) ==
        NetworkSubmitStatus::Queued, "queue bytes with unknown original extent");
    Check(writer.Submit(scope, flow, {a::NetworkCaptureLayer::FlowMetadata, 7, kKnownBytes}) ==
        NetworkSubmitStatus::InvalidObservation, "metadata-only source cannot carry communication bytes");
    Check(writer.Submit(scope, flow, {a::NetworkCaptureLayer::IpPacket, 6, kKnownBytes}) ==
        NetworkSubmitStatus::InvalidObservation, "producer capture cannot exceed original length");
    std::vector<std::uint8_t> large(a::kNetworkMaxInlineBytes + 1, 0x5d);
    large[0] = 0x4b;
    const a::NetworkCapturedBytes oversized{a::NetworkCaptureLayer::IpPacket, large.size(), large};
    Check(writer.Submit(scope, flow, oversized) == NetworkSubmitStatus::NeedsBlob, "oversized default routes to blob owner");
    Check(writer.Submit(scope, flow, oversized, a::NetworkInlinePolicy::RetainPrefix) ==
        NetworkSubmitStatus::Queued, "explicit inline prefix policy");
    Check(writer.Receipt().writtenBytes == 0 && writer.Receipt().queuedObservations == 6, "queue creates no file write");
    const auto drain = writer.Drain();
    Check(drain.result.status == SegmentWriteStatus::Ok && drain.writtenBytes > 0 && drain.flushedBytes == 0 &&
        drain.lastWrittenSequence == 97 && !drain.lastFlushedSequence, "complete append and file flush are distinct receipts");
    const auto flush = writer.Flush();
    Check(flush.flushedBytes == drain.writtenBytes && flush.lastFlushedSequence == 97 && !flush.eofFlushed,
          "actual file flush covers only written data");
    const auto finish = writer.Finish(a::NetworkArchiveEnd::Stopped);
    Check(finish.result.status == SegmentWriteStatus::Ok && finish.eofWritten && finish.eofFlushed &&
        finish.writtenBytes == finish.flushedBytes && finish.lastFlushedSequence == 98, "flushed EOF receipt");
    Check(writer.Submit(scope, flow) == NetworkSubmitStatus::Closed, "EOF closes the writer lane");

    const File file(Segment(scratch, 1));
    std::vector<a::NetworkArchivedFlow> rows;
    const auto read = a::ScanOpenNetworkEvidence(file.handle, scope, 1, std::nullopt,
        [&](const auto& block, const auto& items) {
            Check(block.receiveQpc && block.receiveQpc->minimum == 35 && block.receiveQpc->maximum == 38,
                  "readback only includes the real receive QPC range");
            rows.insert(rows.end(), items.begin(), items.end());
        });
    Check(read.framing.status == SegmentScanStatus::FramingComplete && read.checkedBytes == finish.writtenBytes &&
        !read.framing.interpretedBytes && !read.invalidMetadataOffset && read.eof == a::NetworkArchiveEnd::Stopped,
        "semantic readback through explicit EOF without publishing a project endpoint");
    Check(rows.size() == 6 && rows.front().recordSequence == 92 && rows.back().recordSequence == 97 &&
        rows.front().recordOffset > a::kSegmentHeaderBytes, "archive anchors are stable Stored record positions");
    const auto& first = rows[0].observation;
    Check(first.OutboundDestination() && first.OutboundDestination()->port == 443 && first.sourceField.port == 0 &&
        first.observedBytes == 0 && first.producerSequence == 0 && first.etw && first.etw->eventId == 10 &&
        !rows[2].observation.OutboundDestination() && !rows[2].observation.sourceField.port,
        "outbound linkage, observed zeros, missing fields and event descriptor");
    auto incomplete = first;
    incomplete.destinationField.port = std::uint16_t{0};
    Check(!incomplete.OutboundDestination(), "a reported zero destination port is evidence without confirmed linkage");
    incomplete = first;
    incomplete.destinationField.address = {};
    Check(!incomplete.OutboundDestination(), "a reported wildcard address is evidence without confirmed linkage");
    incomplete = first;
    incomplete.processObjectId.reset();
    Check(!incomplete.OutboundDestination(), "confirmed outbound linkage requires a sample process object");
    Check(rows[0].capture.state == a::NetworkPayloadState::MetadataOnly && rows[0].capture.capturedLength == 0 &&
        rows[1].capture.state == a::NetworkPayloadState::Complete && rows[1].capture.originalLength == 7 &&
        rows[2].capture.state == a::NetworkPayloadState::Truncated && rows[2].capture.sourceTruncated &&
        rows[2].capture.originalLength == 10 && rows[3].capture.state == a::NetworkPayloadState::NoPayload &&
        rows[4].capture.state == a::NetworkPayloadState::Captured && !rows[4].capture.originalLength &&
        rows[5].capture.state == a::NetworkPayloadState::Truncated && !rows[5].capture.sourceTruncated &&
        rows[5].capture.producerCapturedLength == large.size() && rows[5].capture.capturedLength == a::kNetworkMaxInlineBytes,
        "capture extent and state survive replay");

    const auto identity = finish.segment;
    std::size_t seen = 0;
    const auto bodies = a::ScanOpenSegmentBodies(file.handle, identity, std::nullopt,
        [&](const auto& checkedIdentity, const auto&, const auto& records) {
            for (const auto& record : records) {
                const auto* raw = std::get_if<a::RawRecordV1>(&record.body);
                Check(raw && record.recordType == 3 && record.recordSchemaVersion == 1 && record.flags == 0,
                      "existing decoder accepts the network wire envelope");
                // 独立段可给出类型化端点及声明来源，项目核对通过后才提升来源可信度。
                const auto projected = a::ProjectNetworkFlowRecord(checkedIdentity, record);
                if (seen < rows.size()) {
                    Check(projected && projected->flow.recordSequence == rows[seen].recordSequence &&
                        projected->flow.capture.capturedLength == rows[seen].capture.capturedLength &&
                        projected->source.sourceId == scope.sourceId && projected->source.sourceEpoch == scope.sourceEpoch &&
                        projected->sourceTrust == a::NetworkSourceTrust::RecordedDeclaration &&
                        projected->inlineOffsetInPayload == raw->inlineRawOffsetInPayload &&
                        projected->inlineBytes == raw->inlineRawData, "standalone typed projection preserves range and declaration trust");
                } else {
                    Check(!projected, "terminal record is not a network flow");
                }
                if (seen == 1) {
                    const auto matched = a::ProjectNetworkFlowRecord(checkedIdentity, record, &scope);
                    Check(matched && matched->sourceTrust == a::NetworkSourceTrust::MatchedVerifiedBinding &&
                        matched->flow.observation.etw && matched->flow.observation.etw->eventId == 10,
                        "project binding is matched independently of the archived ETW descriptor");
                    auto wrongClock = scope;
                    wrongClock.clockId = "wrong-clock";
                    Check(!a::ProjectNetworkFlowRecord(checkedIdentity, record, &wrongClock), "a conflicting source binding rejects projection");
                }
                const auto* bytes = reinterpret_cast<const std::uint8_t*>(raw->inlineRawData.data());
                Check(raw->inlineRawData.size() == raw->inlineRawBytes, "exact inline extent");
                if (seen == 1 || seen == 2 || seen == 4) {
                    Check(raw->inlineRawBytes == kKnownBytes.size() && std::equal(kKnownBytes.begin(), kKnownBytes.end(), bytes),
                          "captured byte-for-byte match after caller mutated the input buffer");
                } else if (seen == 5) {
                    Check(raw->inlineRawBytes == a::kNetworkMaxInlineBytes &&
                        std::equal(bytes, bytes + raw->inlineRawBytes, large.begin()), "exact retained prefix");
                } else {
                    Check(raw->inlineRawData.empty(), "metadata-only, empty, and EOF have zero inline bytes");
                }
                ++seen;
            }
            return true;
        });
    Check(bodies.bodyFailure.issue == a::BodyIssue::None && seen == 7 &&
        bodies.bodyCheckedBytes == finish.writtenBytes, "existing decoder reports all RawRecord byte extents");
    const auto bounded = a::ScanOpenNetworkEvidence(file.handle, scope, 1, flush.flushedBytes);
    Check(bounded.framing.status == SegmentScanStatus::FramingComplete && !bounded.eof &&
          bounded.checkedBytes == flush.flushedBytes, "exact readable boundary is distinct from EOF");
    wrong = scope;
    wrong.clockId = "foreign-clock";
    const auto badSource = a::ScanOpenNetworkEvidence(file.handle, wrong, 1);
    Check(badSource.invalidMetadataOffset && badSource.checkedBytes == a::kSegmentHeaderBytes && !badSource.eof,
          "wrong clock cannot resolve archived records");
}

void Recovery(const std::filesystem::path& scratch)
{
    const auto scope = Binding();
    constexpr std::uint64_t previous = 100;
    a::NetworkEvidenceArchive writer(scratch, scope, 2, 12346, previous);
    for (std::size_t i = 0; i < a::kNetworkQueueCapacity; ++i) {
        Check(writer.Submit(scope, Flow(i)) == NetworkSubmitStatus::Queued, "fill only bounded queue");
    }
    Check(writer.Submit(scope, Flow(999)) == NetworkSubmitStatus::QueueFull &&
        writer.Submit(scope, Flow(1000)) == NetworkSubmitStatus::QueueFull, "surplus arrivals rejected with accounting");
    Check(writer.ReportSourceLoss(scope, 9) && writer.ReportSourceLoss(scope, std::nullopt), "known and unquantified provider loss");
    const auto first = writer.Drain();
    Check(first.lastWrittenSequence == previous + a::kNetworkBatchRecords &&
        first.queuedObservations == a::kNetworkQueueCapacity - a::kNetworkBatchRecords + 1 &&
        first.pendingLoss.queueDropped == 0, "one bounded flow and loss block appended");
    Check(writer.Flush().flushedBytes == first.writtenBytes, "flush prefix before damaged tail");
    Check(writer.Submit(scope, Flow(12345), {a::NetworkCaptureLayer::IpPacket, 7, kKnownBytes}) ==
        NetworkSubmitStatus::Queued, "freed ring capacity accepts another retained record");
    const auto second = writer.Drain();
    Check(second.writtenBytes > first.writtenBytes && second.flushedBytes == first.writtenBytes,
        "second append leaves previous flush receipt intact");
    const auto final = writer.Finish(a::NetworkArchiveEnd::SourceFailed);
    Check(final.eofFlushed && final.lastWrittenSequence == previous + a::kNetworkQueueCapacity + 3,
        "bounded final drain with loss record and EOF");
    const auto path = Segment(scratch, 2);
    {
        const File file(path);
        const auto full = a::ScanOpenNetworkEvidence(file.handle, scope, 2);
        Check(full.eof == a::NetworkArchiveEnd::SourceFailed && full.loss.queueDropped == 2 &&
            full.loss.sourceLost == 9 && full.loss.sourceLossUnquantified, "clean framing retains unavailable source quality");
        for (const auto cut : {first.writtenBytes + 1, first.writtenBytes + a::kBlockHeaderBytes - 1, second.writtenBytes - 1}) {
            const auto bounded = a::ScanOpenNetworkEvidence(file.handle, scope, 2, cut);
            Check(bounded.framing.status == SegmentScanStatus::Truncated && bounded.checkedBytes == first.writtenBytes &&
                !bounded.eof && bounded.loss.queueDropped == 2, "recover prefix at partial block header or body");
        }
    }
    CutPhysicalTail(path, final.writtenBytes - 1);
    std::uint64_t dataEnd = 0;
    {
        const File file(path);
        std::size_t read = 0;
        const auto recovered = a::ScanOpenNetworkEvidence(file.handle, scope, 2, std::nullopt,
            [&](const auto&, const auto& rows) { read += rows.size(); });
        Check(recovered.framing.status == SegmentScanStatus::Truncated && !recovered.eof &&
            recovered.loss.queueDropped == 2 && recovered.loss.sourceLost == 9 &&
            read == a::kNetworkQueueCapacity + 1, "damaged EOF retains validated flows and known loss");
        dataEnd = recovered.checkedBytes;
    }
    CutPhysicalTail(path, dataEnd - 1);
    const File cutPayload(path);
    std::size_t readableFlows = 0;
    const auto tail = a::ScanOpenNetworkEvidence(cutPayload.handle, scope, 2, std::nullopt,
        [&](const auto&, const auto& rows) { readableFlows += rows.size(); });
    Check(tail.framing.status == SegmentScanStatus::Truncated && tail.checkedBytes < dataEnd && !tail.eof &&
        tail.loss.queueDropped == 2 && readableFlows == a::kNetworkQueueCapacity - 1,
        "a cut inside real inline bytes withholds the whole affected block");
}

void Failure(const std::filesystem::path& scratch)
{
    const auto scope = Binding();
    a::NetworkEvidenceArchive duplicate(scratch, scope, 1, 0);
    Check(duplicate.Submit(scope, Flow()) == NetworkSubmitStatus::Queued && duplicate.ReportSourceLoss(scope, 2),
          "memory admission is distinct from opening the path");
    const auto collision = duplicate.Drain();
    Check(collision.result.status == SegmentWriteStatus::IoError && collision.result.error.issue == a::SegmentIssue::FileOpen &&
        collision.queuedObservations == 1 && collision.pendingLoss.sourceLost == 2 && collision.flushedBytes == 0 &&
        !duplicate.Finish(a::NetworkArchiveEnd::Stopped).eofWritten, "existing segment untouched and failure remains visible");

    a::NetworkEvidenceArchive exhausted(scratch, scope, 3, 0, (std::numeric_limits<std::uint64_t>::max)());
    Check(exhausted.Submit(scope, Flow()) == NetworkSubmitStatus::Queued, "queue separately from exhausted sequence");
    const auto unavailable = exhausted.Drain();
    Check(unavailable.result.error.issue == a::SegmentIssue::Sequence && unavailable.writtenBytes == 0 &&
        !std::filesystem::exists(Segment(scratch, 3)), "exhausted sequence does not wrap or create a file");
    a::NetworkEvidenceArchive empty(scratch, scope, 4, 0);
    Check(empty.Finish(a::NetworkArchiveEnd::SourceUnavailable).eofFlushed, "source unavailable still records terminal evidence");
    const File file(Segment(scratch, 4));
    const auto sealed = a::ScanOpenNetworkEvidence(file.handle, scope, 4);
    Check(sealed.eof == a::NetworkArchiveEnd::SourceUnavailable && sealed.framing.blockCount == 1,
        "source unavailable EOF is distinct from clean empty data");
}

void PayloadBudget(const std::filesystem::path& scratch)
{
    const auto scope = Binding();
    a::NetworkEvidenceArchive writer(scratch, scope, 5, 12347);
    std::vector<std::uint8_t> bytes(a::kNetworkMaxInlineBytes);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::uint8_t>(i % 251u);
    const auto shortSize = bytes.size() - 1;
    Check(writer.Submit(scope, Flow(), {a::NetworkCaptureLayer::TransportPayload, shortSize,
        std::span<const std::uint8_t>(bytes).first(shortSize)}) == NetworkSubmitStatus::Queued, "accept short leading extent");
    const auto payloads = a::kNetworkQueuedPayloadBudget / a::kNetworkMaxInlineBytes;
    for (std::size_t i = 1; i < payloads; ++i) {
        Check(writer.Submit(scope, Flow(i), {a::NetworkCaptureLayer::TransportPayload, bytes.size(), bytes}) ==
            NetworkSubmitStatus::Queued, "accept full 65536-byte observation at the default limit");
    }
    Check(writer.Receipt().queuedPayloadBytes == a::kNetworkQueuedPayloadBudget - 1 &&
        writer.Receipt().queuedObservations == payloads, "queued bytes have their own aggregate budget");
    const a::NetworkCapturedBytes extra{a::NetworkCaptureLayer::TransportPayload, kKnownBytes.size(), kKnownBytes};
    Check(writer.Submit(scope, Flow(), extra) == NetworkSubmitStatus::QueueFull &&
        writer.Receipt().pendingLoss.queueDropped == 1, "over-budget submission counts as a queue drop");
    Check(writer.Submit(scope, Flow()) == NetworkSubmitStatus::Queued, "metadata-only row consumes no payload budget");
    const auto drained = writer.Drain();
    Check(drained.result.status == SegmentWriteStatus::Ok && drained.queuedPayloadBytes == a::kNetworkMaxInlineBytes &&
        drained.writtenBytes <= a::kMaxDecodedBlockBytes + a::kBlockHeaderBytes + a::kSegmentHeaderBytes,
        "near-full batch satisfies Stored limits and releases only written payload bytes");
    Check(writer.Submit(scope, Flow(), extra) == NetworkSubmitStatus::Queued &&
        writer.Receipt().queuedPayloadBytes == a::kNetworkMaxInlineBytes + kKnownBytes.size(),
        "new extent wraps around the payload ring after the drain");
    const auto finished = writer.Finish(a::NetworkArchiveEnd::Stopped);
    Check(finished.eofFlushed && finished.queuedPayloadBytes == 0, "final flushing drains the byte budget");
    const File file(Segment(scratch, 5));
    std::size_t verified = 0;
    const auto result = a::ScanOpenSegmentBodies(file.handle, finished.segment, std::nullopt,
        [&](const auto&, const auto&, const auto& records) {
            for (const auto& record : records) {
                const auto* raw = std::get_if<a::RawRecordV1>(&record.body);
                Check(raw != nullptr, "decode payload budget RawRecord");
                if (raw->inlineRawData.empty()) continue;
                const auto expected = verified == 0 ? shortSize :
                    verified < payloads ? bytes.size() : kKnownBytes.size();
                const auto* begin = verified < payloads ? bytes.data() : kKnownBytes.data();
                const auto* actual = reinterpret_cast<const std::uint8_t*>(raw->inlineRawData.data());
                Check(raw->inlineRawData.size() == expected && std::equal(begin, begin + expected, actual),
                      "preserve every byte through the full cap and the ring wrap");
                ++verified;
            }
            return true;
        });
    Check(result.bodyFailure.issue == a::BodyIssue::None && verified == payloads + 1,
        "read back all accepted communication bytes through the common decoder");
    const auto recovered = a::ScanOpenNetworkEvidence(file.handle, scope, 5);
    Check(recovered.eof == a::NetworkArchiveEnd::Stopped && recovered.loss.queueDropped == 1 &&
         recovered.checkedBytes == finished.writtenBytes, "readback preserves byte-budget loss and EOF");
}

// 使用现有写入器生成独立 Stored 段，直接测试 Light 将使用的 RecordView 入口。
void StoredPreview(const std::filesystem::path& scratch)
{
    using Layer = a::NetworkCaptureLayer;
    using Material = a::NetworkCommunicationEvidence;
    constexpr std::uint64_t ordinal = 6; // 夹具专属的段号。
    const auto scope = Binding(); // 测试所有者独立掌握的来源绑定。
    a::NetworkEvidenceArchive writer(scratch, scope, ordinal, 12348);
    auto flow = Flow(); // 合成文档地址，已报告的流量计数不代表保留字节。
    flow.observedBytes = 400;
    Check(writer.Submit(scope, flow) == NetworkSubmitStatus::Queued, "queue flow metadata with positive count");

    // 覆盖三种没有内联字节的不同观测，另保留一个明示来源截断的反例。
    Check(writer.Submit(scope, flow, {Layer::TransportPayload, 0, {}}) == NetworkSubmitStatus::Queued,
        "queue confirmed empty communication");
    Check(writer.Submit(scope, flow, {Layer::TransportPayload, std::nullopt, {}}) == NetworkSubmitStatus::Queued,
        "queue zero retained bytes with unknown original length");
    Check(writer.Submit(scope, flow, {Layer::IpPacket, 100, {}}) == NetworkSubmitStatus::Queued,
        "queue no retained bytes with known original length");
    Check(writer.Submit(scope, flow, {Layer::IpPacket, std::nullopt, {}, true}) == NetworkSubmitStatus::Queued,
        "queue no retained bytes with explicit truncation");

    // 用真实二进制覆盖 NUL、高位和界面预览截断，保留原始长度供回读核对。
    std::array<std::uint8_t, a::kNetworkStoredPreviewBytes + 1> original{}; // 人工构造的通信字节。
    std::copy(kKnownBytes.begin(), kKnownBytes.end(), original.begin());
    original.back() = 0xbc;
    flow.family = a::NetworkFamily::IPv6;
    flow.sourceField.address = {};
    flow.sourceField.address.back() = 1;
    flow.destinationField.address = {0x20, 0x01, 0x0d, 0xb8};
    flow.etw.reset();
    Check(writer.Submit(scope, flow, {Layer::TransportPayload, original.size(), original}) == NetworkSubmitStatus::Queued,
        "queue a binary capture larger than the visual preview");
    Check(writer.ReportSourceLoss(scope, 3), "record source loss separately from flow evidence");
    const auto finished = writer.Finish(a::NetworkArchiveEnd::Stopped); // 完整刷新后的夹具段。
    Check(finished.eofFlushed, "flush Stored preview fixture");

    const File file(Segment(scratch, ordinal)); // 整个夹具只读；不启动任何采集源。
    std::vector<a::NetworkStoredFlowPreview> rows; // 模拟跨块回调保留的 Light 可见行。
    std::string_view expectedTail(reinterpret_cast<const char*>(original.data()), original.size()); // 逐字节比对。
    const auto scanned = a::ScanOpenSegment(file.handle, {finished.segment, std::nullopt, std::nullopt},
        [&](const auto&, const auto& records) {
            for (const auto& record : records) {
                auto row = a::PreviewStoredNetworkFlow(finished.segment, record); // 借用当前块，返回拥有内存的值。
                if (record.sequence > 6) {
                    Check(!row, "loss and terminal records are not mislabeled as flows");
                    continue;
                }
                Check(row && row->segmentOrdinal == ordinal && row->flow.recordSequence == record.sequence &&
                    row->flow.recordOffset == record.offset && row->source.sourceEpoch == scope.sourceEpoch &&
                    row->sourceTrust == a::NetworkSourceTrust::RecordedDeclaration,
                    "owning preview preserves record anchor and declaration trust");
                if (record.sequence == 6) {
                    // 有效前缀和文件内偏移来自同一已校验记录。
                    const auto raw = a::ProjectNetworkFlowRecord(finished.segment, record, &scope);
                    Check(raw && raw->inlineBytes == expectedTail &&
                        raw->sourceTrust == a::NetworkSourceTrust::MatchedVerifiedBinding &&
                        row->inlineFileOffset == record.offset + a::kRecordHeaderBytes + raw->inlineOffsetInPayload,
                        "shared RecordView projection preserves exact content and independent binding");

                    // 不可信的调用声明和错误的正文范围均不得产生网络证据行。
                    auto badBinding = scope; // 独立来源代次不匹配。
                    ++badBinding.sourceEpoch[0];
                    Check(!a::PreviewStoredNetworkFlow(finished.segment, record, &badBinding), "reject wrong source epoch");
                    auto badRecord = record; // 模拟调用者交付缺少最后一个实际字节的正文。
                    --badRecord.payloadBytes;
                    Check(!a::PreviewStoredNetworkFlow(finished.segment, badRecord), "reject false retained extent");
                    badRecord = record;
                    badRecord.offset = (std::numeric_limits<std::uint64_t>::max)();
                    Check(!a::PreviewStoredNetworkFlow(finished.segment, badRecord), "reject impossible physical anchor");
                }
                rows.push_back(std::move(*row));
            }
            return true;
        });
    Check(scanned.status == SegmentScanStatus::FramingComplete && rows.size() == 6, "scan only valid flow projections");

    // 无内联字节时，文件锚点仅定位记录，不返回不存在的字节起点。
    const std::array states{Material::MetadataOnly, Material::ConfirmedEmpty, Material::UnknownPresence,
        Material::MissingBytes, Material::MissingBytes}; // 与写入序号逐项对应。
    for (std::size_t index = 0; index < states.size(); ++index) {
        const auto& row = rows[index]; // 已脱离块内存的回读行。
        Check(row.flow.capture.CommunicationEvidence() == states[index] && row.bytes.empty() && !row.inlineFileOffset,
            "zero retained extent preserves the reason bytes are absent");
    }
    const auto& captured = rows.back(); // 有实际字节，界面上限不改变归档完整性。
    Check(captured.flow.capture.CommunicationEvidence() == Material::RetainedBytes &&
        captured.flow.capture.state == a::NetworkPayloadState::Complete &&
        captured.flow.capture.capturedLength == original.size() && captured.bytes.size() == a::kNetworkStoredPreviewBytes &&
        std::equal(captured.bytes.begin(), captured.bytes.end(), original.begin()),
        "owned preview retains exact binary prefix after scan returns");
    Check(captured.flow.observation.family == a::NetworkFamily::IPv6 && !captured.flow.observation.etw &&
        captured.flow.observation.sourceField.port == 0 && captured.flow.observation.OutboundDestination() &&
        captured.flow.observation.OutboundDestination()->address == flow.destinationField.address,
        "IPv6 endpoint, known-zero port, and absent ETW declaration survive projection");

    // 独立从文件绝对锚点读取全部字节，核对界面收敛前缀与归档中的完整正文。
    std::array<std::uint8_t, original.size()> archived{}; // 从文件读取的实际保留字节。
    LARGE_INTEGER byteStart{}; // 文件内偏移已受 Stored 段上限约束。
    byteStart.QuadPart = static_cast<LONGLONG>(captured.inlineFileOffset.value_or(0));
    DWORD bytesRead = 0; // 原生读取的已交付字节数。
    Check(captured.inlineFileOffset && SetFilePointerEx(file.handle, byteStart, nullptr, FILE_BEGIN) &&
        ReadFile(file.handle, archived.data(), static_cast<DWORD>(archived.size()), &bytesRead, nullptr) &&
        bytesRead == archived.size() && archived == original,
        "physical byte anchor reopens the complete archived payload");
}

} // namespace

int wmain(int argc, wchar_t** argv)
{
    try {
        if (argc != 2) throw std::runtime_error("expected fixed scratch directory");
        const std::filesystem::path scratch(argv[1]);
        RoundTrip(scratch);
        Recovery(scratch);
        Failure(scratch);
        PayloadBudget(scratch);
        StoredPreview(scratch);
        std::cout << "PASS " << assertions << " network archive checks\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL after " << assertions << " checks: " << error.what() << '\n';
        return 1;
    }
}
