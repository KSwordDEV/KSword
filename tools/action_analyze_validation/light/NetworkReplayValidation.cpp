#include "../../../KswordARKLight/Features/ActionAnalyze/NetworkReplayPresentation.h"
#include "../../../KswordARKLight/Features/ActionAnalyze/StoredEvidence.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace {

namespace Archive = ks::cli::action_analyze::archive;
namespace Light = Ksword::Features::ActionAnalyze;
namespace fs = std::filesystem;
using Archive::NetworkCaptureLayer;
using Archive::NetworkCommunicationEvidence;
using Archive::NetworkSubmitStatus;
using Archive::SegmentWriteStatus;

constexpr std::array<std::uint8_t, 7> kBytes{0, 255, 128, 14, 0, 0x4b, 0x53}; // 任意合成字节。
constexpr wchar_t kSegmentName[] = L"00000000000000000001.ksaseg"; // 自有生产写入器的文件名。

// 回执仅汇总本次实际通过的断言，失败立即抛出用例名称。
void Check(bool ok, const char* label, std::size_t& checks) {
    if (!ok) {
        throw std::runtime_error(label);
    }
    ++checks;
}

struct Fixture {
    fs::path folder; // 只有成功独占创建后才由本轮测试加以清理。

    ~Fixture() {
        std::error_code error; // 各文件使用固定名称，已存在的测试目录不会被复用。
        if (!folder.empty()) {
            fs::remove(folder / kSegmentName, error);
            fs::remove(folder, error);
        }
    }
};

// 使用明确的文档用途地址和纯合成数据生成两块，不启动采集源。
std::uint64_t WriteFixture(const fs::path& folder, std::size_t& checks) {
    const Archive::NetworkEvidenceBinding binding{{0x11}, {0x22}, "fixture/network", {0x33}, "fixture-qpc",
        "fixture-boot", Archive::NetworkTimeDomain::Qpc, 10000000}; // 合成项目、采样和源实例。
    Archive::NetworkEvidenceArchive writer(folder, binding, 1, 321); // 仅写固定目录的自有段。
    Archive::NetworkFlowMetadata flow; // 初始观测为 TCP IPv4 出站。
    flow.sourceField = {{192, 0, 2, 8}, std::uint16_t{0}};
    flow.destinationField = {{198, 51, 100, 12}, std::uint16_t{443}};
    flow.processId = 175;
    flow.processCreatedUtc100ns = 0x1000020000400;
    flow.processObjectId = 27;
    flow.sourceTimestamp = 5;
    flow.producerSequence = 0;
    flow.receiveQpc = 0;
    flow.observedBytes = 992;
    flow.etw = Archive::NetworkFlowMetadata::EtwDescriptor{10, 0, 0};
    Check(writer.Submit(binding, flow) == NetworkSubmitStatus::Queued, "synthetic metadata", checks);
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::TransportPayload, 7, kBytes}) == NetworkSubmitStatus::Queued,
        "synthetic complete bytes", checks);

    // 特意让接收时钟、进程对象、端口、ETW 描述符和观测计数均缺失。
    flow.family = Archive::NetworkFamily::IPv6;
    flow.transport = Archive::NetworkTransport::Udp;
    flow.direction = Archive::NetworkDirection::Inbound;
    flow.sourceField = {{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12}, std::nullopt};
    flow.destinationField = {{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, std::uint16_t{53}};
    flow.processObjectId.reset();
    flow.receiveQpc.reset();
    flow.observedBytes.reset();
    flow.etw.reset();
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::TransportPayload, 0, {}}) == NetworkSubmitStatus::Queued,
        "synthetic confirmed zero", checks);
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::IpPacket, 10, kBytes, true}) == NetworkSubmitStatus::Queued,
        "synthetic truncated retained bytes", checks);
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::IpPacket, 10, {}, true}) == NetworkSubmitStatus::Queued,
        "synthetic missing bytes", checks);
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::LinkFrame, std::nullopt, {}}) == NetworkSubmitStatus::Queued,
        "synthetic unknown presence", checks);
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::LinkFrame, std::nullopt, kBytes}) == NetworkSubmitStatus::Queued,
        "synthetic captured with unknown completeness", checks);
    const auto first = writer.Drain(); // 第一块独立可用于坏尾恢复。
    Check(first.result.status == SegmentWriteStatus::Ok && first.lastWrittenSequence == 7, "first block written", checks);

    std::vector<std::uint8_t> large(300, 0x5d); // 比产品预览更长，完整保留至文件。
    std::copy(kBytes.begin(), kBytes.end(), large.begin());
    Check(writer.Submit(binding, flow, {NetworkCaptureLayer::IpPacket, large.size(), large}) == NetworkSubmitStatus::Queued,
        "synthetic bytes above display limit", checks);
    const auto end = writer.Finish(Archive::NetworkArchiveEnd::Stopped); // 尾记不是网络流。
    Check(end.result.status == SegmentWriteStatus::Ok && end.eofFlushed, "fixture written and closed", checks);
    return first.writtenBytes;
}

// 取出固定测试文件内容，检查只读字节身份和文件内偏移。
std::vector<std::uint8_t> ReadBytes(const fs::path& path, std::size_t& checks) {
    std::ifstream file(path, std::ios::binary); // 本轮唯一的自有归档文件。
    Check(static_cast<bool>(file), "open owned archive", checks);
    return {std::istreambuf_iterator<char>(file), {}};
}

// 文件逻辑投影及详情都使用正式 Light 实现，坏尾用例从内存提供受控副本。
void Verify(const fs::path& path, std::uint64_t firstEnd, std::size_t& checks) {
    const auto before = ReadBytes(path, checks); // 重读前的原归档。
    const auto result = Light::OpenStoredEvidence(path.wstring()); // 正常生产只读入口。
    Check(result.diagnostic.empty() && result.rows.size() == 9 && result.decodedPrefixBytes == before.size() &&
        result.identity && result.identity->streamKind == 1, "complete network archive framing", checks);
    Check(std::all_of(result.rows.begin(), result.rows.end() - 1, [](const auto& row) { return row.network.has_value(); }),
        "all eight flows carry typed network evidence", checks);
    Check(ReadBytes(path, checks) == before, "replay leaves segment bytes unchanged", checks);

    const auto& metadata = *result.rows.at(0).network; // 已知出站地址、零端口与归档来源声明。
    const auto& flow = metadata.flow.observation; // 原始传输观察，计数和归档字节独立。
    Check(flow.sourceField.port == 0 && flow.destinationField.port == 443 && flow.observedBytes == 992 &&
        flow.processId == 175 && flow.processObjectId == 27 && flow.receiveQpc == 0 && flow.etw && flow.etw->eventId == 10 &&
        result.rows[0].receiveQpc == 0 && !result.rows[0].headerTid &&
        metadata.sourceTrust == Archive::NetworkSourceTrust::RecordedDeclaration, "exact metadata and zero-valued QPC", checks);
    Check(Light::NetworkReplaySummary(metadata) == L"TCP/IPv4 出站 · 198.51.100.12:443", "visible outbound endpoint", checks);
    const auto text = Light::NetworkReplayDetails(metadata); // 展示文本由同一份结构生成。
    Check(text.find(L"192.0.2.8:0") != text.npos && text.find(L"来源观测计数（字节）：992") != text.npos &&
        text.find(L"通信字节：仅元数据") != text.npos && text.find(L"通信字节预览") == text.npos,
        "metadata distinct from bytes", checks);

    const auto& captured = *result.rows.at(1).network; // 归档中的实际内联字节。
    Check(captured.segmentOrdinal == 1 && captured.flow.recordSequence == 2 && captured.flow.recordOffset == result.rows[1].offset &&
        captured.bytes.size() == kBytes.size() && std::equal(kBytes.begin(), kBytes.end(), captured.bytes.begin()) &&
        captured.inlineFileOffset && *captured.inlineFileOffset + kBytes.size() <= before.size() &&
        std::equal(kBytes.begin(), kBytes.end(), before.begin() + static_cast<std::ptrdiff_t>(*captured.inlineFileOffset)),
        "encoded payload and presentation anchors are exact", checks);
    Check(Light::NetworkReplayDetails(captured).find(L"00 ff 80 0e 00 4b 53") != text.npos, "hex preview exact", checks);

    // 文本投影保留双栈、入站方向和每种未知及空状态。
    const auto& empty = *result.rows.at(2).network;
    const auto emptyText = Light::NetworkReplayDetails(empty);
    Check(Light::NetworkReplaySummary(empty) == L"UDP/IPv6 入站 · [2001:db8::12]:端口未知" &&
        emptyText.find(L"目的端点：[2001:db8::1]:53") != text.npos && emptyText.find(L"已确认原始长度为 0") != text.npos &&
        emptyText.find(L"接收 QPC：未知") != text.npos && emptyText.find(L"ETW 描述符：未知") != text.npos &&
        emptyText.find(L"进程对象 ID：未知") != text.npos, "IPv6, known empty and unknowns are distinct", checks);
    Check(Light::NetworkReplayDetails(*result.rows.at(3).network).find(L"已归档字节（截断）") != text.npos,
        "retained source-truncated bytes", checks);
    Check(result.rows.at(4).network->flow.capture.CommunicationEvidence() == NetworkCommunicationEvidence::MissingBytes &&
        Light::NetworkReplayDetails(*result.rows.at(4).network).find(L"已截断，归档未保留字节") != text.npos &&
        !result.rows.at(4).network->inlineFileOffset, "missing bytes are not an empty capture", checks);
    Check(result.rows.at(5).network->flow.capture.CommunicationEvidence() == NetworkCommunicationEvidence::UnknownPresence &&
        Light::NetworkReplayDetails(*result.rows.at(5).network).find(L"原始内容存在性未知") != text.npos,
        "unobserved bytes stay unknown", checks);
    Check(Light::NetworkReplayDetails(*result.rows.at(6).network).find(L"完整性未知") != text.npos,
        "actual bytes with unknown completeness", checks);

    const auto& limited = *result.rows.at(7).network; // 预览限制与归档本身的完整状态独立。
    const auto limitedText = Light::NetworkReplayDetails(limited);
    Check(limited.bytes.size() == Archive::kNetworkStoredPreviewBytes && limited.flow.capture.capturedLength == 300 &&
        limited.flow.capture.state == Archive::NetworkPayloadState::Complete && limited.inlineFileOffset &&
        limitedText.find(L"256 / 300 B") != text.npos && limitedText.find(L"[字节预览截断]") != text.npos &&
        !result.rows.at(8).network, "preview limit and terminal record remain distinct", checks);

    auto corrupted = before; // 只损坏内存副本中第二块的真实字节。
    corrupted.at(static_cast<std::size_t>(*limited.inlineFileOffset)) ^= 1;
    std::size_t offset = 0; // 读取器的单向不可变输入位置。
    const auto partial = Light::ReadStoredEvidence(corrupted.size(), [&](std::span<std::uint8_t> buffer) {
        std::copy_n(corrupted.begin() + static_cast<std::ptrdiff_t>(offset), buffer.size(), buffer.begin());
        offset += buffer.size();
        return std::uint32_t{0};
    });
    Check(partial.diagnostic == "block.storedCrc" && partial.decodedPrefixBytes == firstEnd &&
        partial.rows.size() == 7 && partial.rows.at(1).network && partial.rows.at(1).network->bytes == captured.bytes,
        "bad body CRC leaves only the prior whole block", checks);
}

} // namespace

// 在既有 Build IntDir 父目录的固定子目录运行网络专用原生夹具。
void VerifyNetworkReplay(const fs::path& testOutput) {
    std::size_t checks = 0; // 成功断言的实际计数。
    const auto parent = fs::canonical(testOutput); // 只接受 Light 本身的固定原生夹具输出位置。
    Check(parent.filename() == L"ActionAnalyzeTests" && parent.parent_path().filename() == L"Release" &&
        parent.parent_path().parent_path().filename() == L"x64" &&
        parent.parent_path().parent_path().parent_path().filename() == L"KswordARKLight", "fixed test output", checks);
    const auto folder = parent / L"network-replay-fixture"; // 专用并可清理的固定路径。
    {
        Check(fs::create_directory(folder), "create clean fixed network fixture directory", checks);
        const Fixture fixture{folder}; // 持有本次新目录的清理责任。
        const auto firstEnd = WriteFixture(folder, checks); // 已刷流的首完整块端点。
        Verify(folder / kSegmentName, firstEnd, checks);
    }
    Check(!fs::exists(folder), "owned fixture files removed", checks);
    std::cout << "Light network replay: " << checks << " checks PASS\n";
}
