#include "../ProjectReplay.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectEtwCheckpoint.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectRawEvidence.h"
#include "../../../../KswordCLI/ActionAnalyze/Project/ProjectStorage.h"

#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>

namespace {

namespace fs = std::filesystem;
namespace Project = Ksword::ActionAnalyze;
namespace Storage = Project::ProjectStorage;
namespace Archive = ks::cli::action_analyze::archive;
namespace Light = Ksword::Features::ActionAnalyze;
using namespace Storage;
constexpr char kProvider[] = "d4a71ada-81b0-4b15-a173-417f33bc8107"; // 合成提供程序身份。
constexpr char kSourceEpoch[] = "12345678-9abc-4def-8123-456789abcdef"; // 合成来源代次。
constexpr wchar_t kSegment[] = L"00000000000000000001.ksaseg"; // 两流各自的首段名。

// 汇总本次原生回归断言，失败立即输出用例名称并交由外层清理。
void Check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

// 读取测试自有文件的原始字节，用于最小变异和确认只读复测不修改资料。
std::string ReadBytes(const fs::path& path) {
    std::ifstream file(path, std::ios::binary); // 测试项目中的固定证据文件。
    Check(static_cast<bool>(file), "read fixture file");
    return {std::istreambuf_iterator<char>(file), {}};
}

// 仅覆写测试程序已创建的文件，调用方保留原字节用于后续用例。
void WriteBytes(const fs::path& path, const std::string& bytes) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc); // 测试故障文件。
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    Check(static_cast<bool>(file), "write fixture file");
}

// 用生产写入器生成三条 raw 记录与一条 Coverage，不采集真实进程。
Project::ProjectEtwCheckpoint WriteCapture(Project::ProjectDocument& project, const Project::SampleInfo& sample) {
    using V = Ksword::Evidence::JsonValue;
    const auto projectId = project.Info()->projectId; // 当前测试项目 UUID。
    Project::SampleRecord checked; // 从生产目录回读的冻结配置。
    Check(static_cast<bool>(project.ReadSample(sample.sampleId, checked)), "read fixture frozen sample");
    const auto plan = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-capture-plan-v1")},
        {"backend", Text("r3")}, {"session", Object({{"id", Text(sample.sampleId)}, {"epoch", Text(kSourceEpoch)}})},
        {"revisionId", Text(sample.revisionId)}, {"snapshotId", Text(sample.snapshotId)},
        {"revisionHash", Text(checked.revisionHash)}, {"configSemanticHash", Text(checked.configSemanticHash)},
        {"providerId", Text(kProvider)}, {"sourceEpoch", Text(kSourceEpoch)}, {"headerPid", V::makeUInt(100)},
        {"processCreationFileTime", Number(101)}})); // 序号 1，冻结目标和配置。
    const auto observation = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-observation-v1")},
        {"providerId", Text(kProvider)}, {"sourceEpoch", Text(kSourceEpoch)}, {"headerPid", V::makeUInt(100)},
        {"headerTid", V::makeUInt(200)}, {"descriptor", Object({{"id", V::makeUInt(1)},
            {"version", V::makeUInt(0)}, {"opcode", V::makeUInt(0)}})},
        {"sourceFileTime100ns", Number(102)}, {"originalPayloadBytes", V::makeUInt(4)},
        {"storedPayloadBytes", Number(4)}, {"malformedPayload", V::makeBool(false)},
        {"receiveQpc", Number(30)}, {"qpcFrequencyHz", Number(10)}})); // 序号 2，已知内联原字节。
    const auto end = Ksword::Evidence::WriteJson(Object({{"kind", Text("etw-capture-end-v1")},
        {"stopReason", Text("fixture")}, {"source", Object({{"sourceEpoch", Text(kSourceEpoch)},
            {"enqueued", Number(1)}, {"queued", Number(0)}, {"nativeSessionStopped", V::makeBool(true)},
            {"eventsLost", V::makeUInt(0)}, {"logBuffersLost", V::makeUInt(0)},
            {"realTimeBuffersLost", V::makeUInt(0)}, {"queueDropped", Number(0)},
            {"payloadTruncated", Number(0)}, {"malformedPayload", Number(0)}})}})); // 序号 3，结束回执。

    // 生产 writer 按输入分配段内序号。二进制串包含 NUL 和两个非 ASCII 值。
    const std::string_view bytes("\x00\xff\x80\x4b", 4); // 固定 ETW UserData。
    const std::array inputs{Archive::RawEvidenceInput{plan, {}}, Archive::RawEvidenceInput{observation, bytes},
        Archive::RawEvidenceInput{end, {}}}; // 一块内的三条 raw 记录。
    Archive::RawEvidenceReceipt raw; // 生产写入并刷盘后的端点。
    const auto written = project.WriteRawEvidenceSegment({projectId, sample.sampleId, 1, {}, [&](auto& writer) {
        return writer.Append(inputs).result.status == Archive::SegmentWriteStatus::Ok ? Project::ProjectResult{} :
            Failure(Project::ProjectError::IoError, "fixtureRawAppend");
    }}, raw);
    Check(written && raw.flushed.has_value(), "write fixture raw");

    const Archive::EtwCoverageV1 coverage{kProvider, kSourceEpoch, 1, 1, 3, 1, 0, 0, 0, 0, 0, 0}; // 与 raw 逐字段匹配。
    Project::ProjectEtwCheckpoint checkpoint; // 两条已刷流的生产终态标记。
    Check(static_cast<bool>(project.PublishEtwCheckpoint(sample.sampleId, *raw.flushed, coverage, checkpoint)),
        "publish fixture checkpoint");
    return checkpoint;
}

// 在不会覆盖已有输出的固定项目目录，验证 Light 同一生产入口的成功与失败情形。
void Run(const fs::path& folder) {
    const auto root = folder / L"项目"; // 有界 Unicode 项目路径。
    const auto manifest = (root / L"project.ksaproj").wstring(); // 用户选择的文件身份。
    Project::ProjectDocument writer; // 仅用于准备这次自有测试数据。
    Check(static_cast<bool>(writer.Create(root.wstring(), {"ETW fixture", ""})), "create fixture project");
    const auto emptyCatalog = Light::ReadProjectReplayCatalog(manifest);
    Check(emptyCatalog.diagnostic.empty() && emptyCatalog.choices.empty(), "initial catalog empty");
    Project::SampleInfo sample; // 采样身份用于生成独立的 raw 和 records 路径。
    Project::SampleInfo other; // 名称相同的已登记采样，验证选择不能仅依赖标题。
    Check(writer.CreateSample("同名采样", sample) && writer.CreateSample("同名采样", other), "register two samples");
    const auto checkpoint = WriteCapture(writer, sample); // 预期验证端点。
    writer.Close();

    const auto catalog = Light::ReadProjectReplayCatalog(manifest); // 生产只读目录适配器。
    Check(catalog.diagnostic.empty() && catalog.choices.size() == 2, "catalog has both committed samples");
    const auto& request = catalog.choices.front().request; // 模拟用户确认后冻结的完整请求。
    Check(request.sampleId == sample.sampleId && request.descriptionHash == sample.descriptionHash &&
        catalog.choices[1].request.sampleId == other.sampleId, "exact sample identities");
    const auto archive = root / L"samples" / WideAscii(sample.sampleId); // 首个采样内两流路径。
    const auto rawPath = archive / L"raw" / kSegment;
    const auto recordsPath = archive / L"records" / kSegment;
    const auto markerPath = archive / L"checkpoints" / L"00000000000000000001.json";
    const auto raw = ReadBytes(rawPath); // 记住原件，验证全部读回不写入测试项目。
    const auto records = ReadBytes(recordsPath);
    const auto marker = ReadBytes(markerPath);

    const auto initial = Light::ReadProjectReplay(request); // 同一文件散列后重新定位投影。
    Check(initial.checkpoint == Light::CheckpointState::Verified && initial.raw.diagnostic.empty() &&
        initial.raw.rows.size() == 3 && initial.raw.decodedPrefixBytes == checkpoint.raw.end.byteOffset &&
        initial.recordsEnd == checkpoint.records.end.byteOffset, "verified extent and row count");
    Check(initial.raw.rows[1].etw && initial.raw.rows[1].etw->sourceEpoch == kSourceEpoch &&
        initial.raw.rows[1].preview.find(L"00 ff 80 4b") != std::wstring::npos, "exact archived ETW bytes");
    Check(ReadBytes(rawPath) == raw && ReadBytes(recordsPath) == records && ReadBytes(markerPath) == marker,
        "verified read leaves original files untouched");

    // raw 追加一个重复块，records 模拟断尾。已提交范围保持不变。
    WriteBytes(rawPath, raw + raw.substr(Archive::kSegmentHeaderBytes));
    WriteBytes(recordsPath, records + "torn");
    const auto tailed = Light::ReadProjectReplay(request); // 坏尾不影响已提交范围。
    Check(tailed.checkpoint == Light::CheckpointState::Verified && tailed.raw.rows.size() == 3 &&
        tailed.raw.fileBytes > tailed.raw.decodedPrefixBytes, "both appended tails excluded");
    const auto standalone = Light::OpenStoredEvidence(rawPath.wstring()); // 旧单段入口仍按物理 EOF 判定坏尾。
    Check(standalone.rows.size() == 3 && !standalone.diagnostic.empty(), "single segment retains its diagnostic prefix");
    WriteBytes(rawPath, raw);
    WriteBytes(recordsPath, records);

    // 有标记但依赖失败时结果不携带可发布行。
    const auto reject = [&] (std::string_view label) {
        const auto checked = Light::ReadProjectReplay(request); // 生产项目回放拒绝失败的提交。
        Check(checked.checkpoint == Light::CheckpointState::NotChecked && !checked.raw.identity &&
            checked.raw.rows.empty() && !checked.raw.diagnostic.empty(), label);
    };
    WriteBytes(recordsPath, records.substr(0, records.size() - 1));
    reject("truncated committed records must not publish");
    Check(fs::remove(recordsPath), "remove fixture records");
    reject("missing records must not fall back");
    WriteBytes(recordsPath, records);
    WriteBytes(rawPath, raw.substr(0, raw.size() - 1));
    reject("truncated committed raw must not publish");
    auto corruptRaw = raw;
    corruptRaw.back() ^= 1;
    WriteBytes(rawPath, corruptRaw);
    reject("bad CRC in committed raw must not publish");
    Check(fs::remove(rawPath), "remove fixture raw");
    reject("missing raw must not fall back");
    WriteBytes(rawPath, raw);
    WriteBytes(markerPath, "{");
    reject("malformed present marker must not fall back");
    auto changedMarker = marker; // 仅篡改 raw 哈希文本，保留可读元数据。
    const auto hashLocation = changedMarker.find(checkpoint.raw.sha256);
    Check(hashLocation != std::string::npos, "find fixture marker raw hash");
    changedMarker.replace(hashLocation, checkpoint.raw.sha256.size(), 64, '0');
    WriteBytes(markerPath, changedMarker);
    reject("changed checkpoint raw hash must not publish");
    WriteBytes(markerPath, marker);
    auto changedRequest = request; // 同一已登记行但冻结描述与重开不符。
    changedRequest.descriptionHash = std::string(64, '0');
    Check(Light::ReadProjectReplay(changedRequest).raw.diagnostic == "corrupt/replayDescriptionHash", "stale description rejected");
    changedRequest = request;
    changedRequest.projectId = other.sampleId;
    Check(Light::ReadProjectReplay(changedRequest).raw.diagnostic == "corrupt/replayProjectId", "wrong project rejected");

    // 只有真正缺少提交标记的自有项目才显示独立的旧 raw 预览状态。
    Check(fs::remove(markerPath), "remove fixture marker");
    const auto legacy = Light::ReadProjectReplay(request); // 原 raw 无改动，按旧档读取。
    Check(legacy.checkpoint == Light::CheckpointState::NotPublished && legacy.raw.rows.size() == 3 &&
        legacy.recordsEnd == 0, "legacy raw is visible without a durability claim");
    WriteBytes(rawPath, raw + "broken");
    const auto legacyTail = Light::ReadProjectReplay(request); // 旧档只显示真实可用的诊断前缀。
    Check(legacyTail.checkpoint == Light::CheckpointState::NotPublished && legacyTail.raw.rows.size() == 3 &&
        !legacyTail.raw.diagnostic.empty(), "legacy bad tail retains its verified prefix");

    // 旧档不能接收另一个采样的段，即使路径和文件名相同。
    const auto otherArchive = root / L"samples" / WideAscii(other.sampleId) / L"raw"; // 自有第二个采样。
    Check(fs::create_directory(otherArchive), "create second fixture raw folder");
    WriteBytes(otherArchive / kSegment, raw);
    const auto wrong = Light::ReadProjectReplay(catalog.choices[1].request);
    Check(!wrong.raw.identity && wrong.raw.rows.empty() && wrong.raw.diagnostic == "segment.identity", "cross-sample legacy raw rejected");
    WriteBytes(rawPath, raw);
    WriteBytes(markerPath, marker);
    Check(Light::ReadProjectReplay(request).checkpoint == Light::CheckpointState::Verified, "retry succeeds after fixture restoration");
}

} // namespace

void VerifyProjectReplay(const std::filesystem::path& testOutput) {
    const auto parent = std::filesystem::canonical(testOutput); // 只接受测试工程的固定输出目录。
    Check(parent.filename() == L"ActionAnalyzeTests" && parent.parent_path().filename() == L"Release" &&
        parent.parent_path().parent_path().filename() == L"x64" &&
        parent.parent_path().parent_path().parent_path().filename() == L"KswordARKLight", "fixed test output");
    const auto folder = parent / L"ProjectReplayFixture"; // 本次独占、可清理的夹具根。
    Check(fs::create_directory(folder), "fixture location must be vacant");
    try {
        Run(folder);
    } catch (...) {
        fs::remove_all(folder);
        throw;
    }
    Check(fs::remove_all(folder) > 0 && !fs::exists(folder), "clean fixture output");
    std::cout << "PASS Light project replay: verified two-stream bounds, tail isolation, legacy raw, identity and retry\n";
}
