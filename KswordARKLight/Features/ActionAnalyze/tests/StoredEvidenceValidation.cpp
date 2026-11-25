#include "../StoredEvidence.h"
#include "../ProjectReplay.h"
#include "../../../../shared/evidence/EvidenceJson.h"

#include <algorithm>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string_view>

// 使用工程固定测试目录创建、验证并清理只含合成被动 ETW 记录的项目。
void VerifyProjectReplay(const std::filesystem::path& testOutput);

namespace {

using Ksword::Evidence::JsonValue;
using namespace Ksword::Features::ActionAnalyze;
using Bytes = std::vector<std::uint8_t>;

void Check(bool condition, std::string_view message) {
    if (!condition) throw std::runtime_error(std::string(message));
}

std::uint64_t Number(const JsonValue* value) {
    std::uint64_t result = 0;
    Check(value && value->tryGetU64(result), "invalid vector integer");
    return result;
}

std::string Text(const JsonValue* value) {
    std::string text;
    Check(value && value->tryGetString(text), "invalid vector text");
    return text;
}

void AppendHex(Bytes& bytes, std::string_view hex) {
    Check(hex.size() % 2 == 0, "vector hex length");
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        unsigned byte = 0;
        const auto parsed = std::from_chars(hex.data() + i, hex.data() + i + 2, byte, 16);
        Check(parsed.ec == std::errc{} && parsed.ptr == hex.data() + i + 2, "invalid vector hex");
        bytes.push_back(static_cast<std::uint8_t>(byte));
    }
}

void AppendFixture(Bytes& result, const JsonValue& fixtures, const std::string& name) {
    const auto* fixture = fixtures.find(name);
    Check(fixture && fixture->find("hex") && fixture->find("hex")->asArray(), "missing fixture");
    for (const auto& line : *fixture->find("hex")->asArray()) AppendHex(result, Text(&line));
}

SegmentEvidence Decode(const Bytes& bytes, const SegmentIdentity* expected) {
    std::size_t offset = 0;
    return ReadStoredEvidence(bytes.size(), [&](std::span<std::uint8_t> target) -> std::uint32_t {
        Check(offset <= bytes.size() && target.size() <= bytes.size() - offset, "read exceeds immutable byte extent");
        std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(offset), target.size(), target.begin());
        offset += target.size();
        return 0;
    }, expected);
}

void Verify(const std::filesystem::path& vectorFile) {
    std::ifstream stream(vectorFile, std::ios::binary);
    Check(static_cast<bool>(stream), "unable to open literal vectors");
    const std::string text{ std::istreambuf_iterator<char>(stream), {} };
    const auto contract = Ksword::Evidence::ParseJson(text);
    Check(contract.ok(), "unable to parse literal vectors");
    const auto* fixtures = contract.value.find("fixtures");
    const auto* identity = contract.value.find("expectedIdentity");
    const auto* cases = contract.value.find("cases");
    Check(fixtures && identity && cases && cases->asArray(), "incomplete vector file");
    std::size_t verified = 0;
    for (const auto& test : *cases->asArray()) {
        const auto name = Text(test.find("id"));
        try {
            const auto base = Text(test.find("base"));
            const auto* baseFixture = fixtures->find(base);
            Check(baseFixture != nullptr, "missing base fixture");
            const SegmentIdentity expected{ Text(identity->find("projectUUID")), Text(identity->find("sampleUUID")),
                static_cast<std::uint32_t>(Number(baseFixture->find("streamKind"))), Number(identity->find("segmentOrdinal")) };
            Bytes bytes;
            AppendFixture(bytes, *fixtures, base);
            if (const auto* take = test.find("take")) bytes.resize(static_cast<std::size_t>(Number(take)));
            if (const auto* append = test.find("append")) AppendFixture(bytes, *fixtures, Text(append));
            if (const auto* appendHex = test.find("appendHex")) AppendHex(bytes, Text(appendHex));
            if (const auto* patches = test.find("patch")) {
                Check(patches->asArray() != nullptr, "invalid patches");
                for (const auto& patch : *patches->asArray()) {
                    const auto* fields = patch.asArray();
                    Check(fields && fields->size() == 2, "invalid patch");
                    const auto offset = static_cast<std::size_t>(Number(&fields->front()));
                    Bytes replacement;
                    AppendHex(replacement, Text(&fields->back()));
                    Check(offset <= bytes.size() && replacement.size() <= bytes.size() - offset, "patch out of bounds");
                    std::copy(replacement.begin(), replacement.end(), bytes.begin() + static_cast<std::ptrdiff_t>(offset));
                }
            }
            if (const auto* truncate = test.find("truncate")) bytes.resize(static_cast<std::size_t>(Number(truncate)));
            const auto result = Decode(bytes, &expected);
            const auto status = Text(test.find("status"));
            const auto shownStatus = !result.diagnostic.empty() ? result.diagnostic : result.opaqueRequiredRecords ? "raw-only" : "complete";
            const auto decoded = Number(test.find("prefixBytes"));
            const auto* framed = test.find("framedBytes");
            Check(status == shownStatus, "expected " + status + ", got " + shownStatus);
            Check(result.framedBytes == (framed ? Number(framed) : decoded), "framed prefix");
            Check(result.decodedPrefixBytes == decoded, "decoded prefix");
            if (const auto* optional = test.find("opaqueOptional")) {
                Check(result.opaqueOptionalRecords == Number(optional), "optional opaque count");
            }
            if (status == "complete" || status == "raw-only") {
                Check(result.identity == expected, "exact archive identity");
                Check(result.createdUtc100ns == Number(contract.value.find("expectedCreatedUtc100ns")), "archive creation time");
                Check(result.blocks == Number(test.find("blocks")), "block count");
            }
            if (name == "event-segment-with-known-zeroes") {
                const auto& row = result.rows.at(0);
                Check(row.sequence == 29 && row.eventOrdinal == 0 && row.rawSequence == 0, "event and raw IDs with valid zero");
                Check(row.sourceDictionaryId == 72623859790382856ULL && row.epochDictionaryId == 18364758544493064720ULL,
                    "source IDs remain lossless");
                Check(row.receiveQpc == 2387509390608836392ULL && row.category == 21862, "waterfall input identity");
                Check(row.actorObjectId == 3544952156018063160ULL && !row.targetObjectId && !row.headerPid && !row.headerTid,
                    "object IDs are not native PID/TID");
            }
            if (name == "raw-segment") Check(result.rows.at(0).preview.find(L"00 ff 80 4b") != std::wstring::npos, "raw byte preview");
            ++verified;
        } catch (const std::exception& error) {
            throw std::runtime_error(name + ": " + error.what());
        }
    }
    const auto absent = OpenStoredEvidence((vectorFile / L"missing.ksaseg").wstring());
    Check(absent.diagnostic == "file.open" && absent.systemError != 0 && !absent.identity, "Win32 open failure identity");
    const auto wrongContainer = OpenStoredEvidence(vectorFile.wstring());
    Check(wrongContainer.diagnostic == "segment.magic" && !wrongContainer.identity && !wrongContainer.fileIdentity.empty(),
        "a real non-segment file stays identified as a failure");
    std::cout << "StoredEvidence: " << verified << " literal vectors + 2 Win32 file cases PASS\n";
}

// 打开正式 CLI 产生的文件，核对自有样本中的观察行及关联边界。
void VerifyLiveCliReadback(const std::wstring& path) {
    const auto result = OpenStoredEvidence(path); // Light 正式读取器。
    Check(result.identity && result.diagnostic.empty() && result.rows.size() == 14, "complete CLI ETW segment");
    Check(!result.rows.front().etw && !result.rows.back().etw, "capture plan and terminal coverage are separate");
    for (std::size_t i = 0; i < 12; ++i) {
        const auto& row = result.rows.at(i + 1); // 带原始载荷的观察行。
        Check(row.etw && row.etw->eventId == 1 + i % 2 && row.etw->originalPayloadBytes == 8 &&
            row.etw->providerId == "d4a71ada-81b0-4b15-a173-417f33bc8107" && row.headerPid && row.headerTid &&
            row.receiveQpc && !row.eventOrdinal && !row.actorObjectId && !row.threadObjectId, "ETW record context");
        const auto expected = std::wstring(L"0") + static_cast<wchar_t>(L'0' + i / 2) + L" 00 00 00 1c 00 00 00";
        Check(row.preview.find(expected) != std::wstring::npos, "ETW byte preview matches owned payload");
    }
    std::cout << "PASS Light CLI ETW readback: 12 events and exact bytes\n";

    // 从同一正式项目的目录进入，核对 Light 项目回放提交的端点和每行投影。
    const std::filesystem::path segment(path); // raw/1 在正式项目中的路径。
    const auto manifest = segment.parent_path().parent_path().parent_path().parent_path() / L"project.ksaproj";
    const auto catalog = ReadProjectReplayCatalog(manifest.wstring()); // 从已提交目录选择采样。
    Check(catalog.diagnostic.empty(), "CLI project catalog opened");
    const auto selected = std::find_if(catalog.choices.begin(), catalog.choices.end(),
        [&](const auto& choice) { return choice.request.sampleId == result.identity->sampleId; }); // 同一采样的冻结请求。
    Check(selected != catalog.choices.end(), "CLI sample present in Light project catalog");
    const auto replay = ReadProjectReplay(selected->request); // 使用生产项目回放入口。
    Check(replay.checkpoint == CheckpointState::Verified && replay.recordsEnd > 0 && replay.raw.diagnostic.empty() &&
        replay.raw.identity == result.identity && replay.raw.decodedPrefixBytes == result.decodedPrefixBytes &&
        replay.raw.rows.size() == result.rows.size(), "verified CLI checkpoint in Light");
    for (std::size_t index = 0; index < result.rows.size(); ++index) {
        const auto& row = replay.raw.rows.at(index); // 项目回放的记录和字节预览。
        const auto& standalone = result.rows.at(index); // 同一记录的独立段投影。
        Check(row.sequence == standalone.sequence && row.preview == standalone.preview &&
            row.etw.has_value() == standalone.etw.has_value(), "Light project projection matches standalone ETW row");
    }
    std::cout << "PASS Light CLI project checkpoint: matching identity, boundary and 14 rows\n";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    try {
        if (argc == 3 && std::wstring_view(argv[1]) == L"--etw-file") {
            VerifyLiveCliReadback(argv[2]);
            return 0;
        }
        if (argc == 3 && std::wstring_view(argv[1]) == L"--project-fixture") {
            VerifyProjectReplay(argv[2]);
            return 0;
        }
        Check(argc == 2, "pass schemas/action_analyze/vectors/stored-v1.json");
        Verify(argv[1]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
