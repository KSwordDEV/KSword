#include "ApiMonitorEvidenceCommand.h"

#include "../../CommandRegistry.h"
#include "../Project/ProjectRawEvidence.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

#include <array>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace evidence = Ksword::Evidence;
namespace monitor = ks::winapi_monitor;
using Packet = monitor::ApiMonitorEventPacket;
using V = evidence::JsonValue;

constexpr DWORD kInputBytes = 32u << 20; // 单次离线导入的输入配额。
constexpr std::size_t kReadBytes = 64u << 10; // 顺序读的固定块大小。
constexpr std::size_t kLineBytes = 8192; // 覆盖当前 1000 字节包及 JSON 转义字段。
constexpr std::size_t kBatchRows = 128; // 共享 Stored 写入器单块的线索数量。
constexpr std::uint64_t kPageRows = 100; // 单份 CLI 回执最多包含的线索数。

// 用只读且排斥写入者的磁盘句柄冻结归档。按行调用 visitor，返回 Win32 状态或首个损坏行号。
struct ArchiveScan {
    DWORD error = ERROR_SUCCESS; // 文件系统错误，或超出输入配额。
    std::uint64_t rows = 0; // 输入已完整处理的行数。
    bool invalid = false; // 数据错误发生在下一个行号，即 rows + 1。
};

template<class Visitor>
ArchiveScan ScanClosedArchive(const std::wstring& path, Visitor&& visit)
{
    struct File {
        HANDLE value; // 函数独占的原归档句柄。
        ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    } file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, nullptr)};
    if (file.value == INVALID_HANDLE_VALUE) {
        return {GetLastError()};
    }
    if (GetFileType(file.value) != FILE_TYPE_DISK) {
        return {ERROR_INVALID_DATA};
    }

    // 先检查配额。此后写入者无法在读取中追加或替换源文件。
    LARGE_INTEGER size{}; // 从持有句柄读取的文件长度。
    if (!GetFileSizeEx(file.value, &size)) {
        return {GetLastError()};
    }
    if (size.QuadPart < 0 || size.QuadPart > kInputBytes) {
        return {ERROR_FILE_TOO_LARGE};
    }
    ArchiveScan result; // 行验证与读取故障各自保留。
    std::array<char, kReadBytes> block; // 复用 I/O 缓冲，不复制当前块中已完整的行。
    std::string pending; // 仅保存跨读块的行前缀。
    auto remaining = static_cast<DWORD>(size.QuadPart); // 冻结文件的剩余字节。
    while (remaining) {
        DWORD read = 0; // 本次读到的实际字节数。
        if (!ReadFile(file.value, block.data(), (std::min)(remaining, static_cast<DWORD>(block.size())), &read, nullptr)) {
            result.error = GetLastError();
            return result;
        }
        if (!read) {
            result.error = ERROR_HANDLE_EOF;
            return result;
        }
        remaining -= read;
        std::string_view chunk(block.data(), read); // 只借用本次成功读取的内容。

        // 每次从当前块找下一换行。只有跨块数据进入 pending，且总长受行上限约束。
        while (!chunk.empty()) {
            const auto end = chunk.find('\n'); // 当前块中下一个行边界。
            auto line = chunk.substr(0, end); // 当前块中的行或后半部分。
            if (pending.size() + line.size() > kLineBytes) {
                result.invalid = true;
                return result;
            }
            if (end == chunk.npos) {
                pending.append(line);
                break;
            }
            if (!pending.empty()) {
                pending.append(line);
                line = pending;
            }
            if (!visit(line, result.rows + 1)) {
                result.invalid = true;
                return result;
            }
            ++result.rows;
            pending.clear();
            chunk.remove_prefix(end + 1);
        }
    }
    result.invalid = !pending.empty(); // EOF 只能出现在完整 JSON 行之后。
    return result;
}

// 从注册表命令参数接收 UTF-16 标题。输出 UTF-8，非法字符或空标题由项目参数校验拒绝。
std::string Utf8Title(const std::wstring& title)
{
    if (title.empty() || title.size() > 4096) {
        return {};
    }
    const auto length = static_cast<int>(title.size()); // 传给 Win32 转换的 UTF-16 单元数。
    const int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, title.data(), length, nullptr, 0, nullptr, nullptr);
    if (!bytes) {
        return {};
    }
    std::string output(bytes, '\0'); // 接收准确长度的 UTF-8。
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, title.data(), length, output.data(), bytes, nullptr, nullptr);
    return output;
}

// 不信任 JSON 摘要中的 API 名称。校验源序号、读者 PID、协议版本及原包，再返回解码结果。
bool DecodeArchiveLine(std::string_view line, std::uint64_t expectedSequence, evidence::ArchivedApiMonitorClue& row)
{
    if (line.size() > kLineBytes) {
        return false;
    }
    const auto parsed = evidence::ParseJson(line); // 严格解析，拒绝重复键与非法 UTF-8。
    if (!parsed.ok()) {
        return false;
    }
    const auto* sequence = parsed.value.find("sequence"); // 写入器生成的连续归档行号。
    const auto* reader = parsed.value.find("readerPid"); // 管道读取者绑定的数字 PID。
    const auto* field = parsed.value.find("packetBase64"); // 完整、未经解释的原始包。
    auto& packet = row.packet; // 只写入本地副本。
    std::uint64_t readerPid = 0; // 校验后必须与包头 PID 一致。
    std::string base64; // 文本只在当前行解码期间使用。
    if (!sequence || !sequence->tryGetU64(row.sourceSequence) || row.sourceSequence != expectedSequence ||
        !reader || !reader->tryGetU64(readerPid) || !readerPid || !field || !field->tryGetString(base64) ||
        base64.size() != ((sizeof(packet) + 2) / 3) * 4) {
        return false;
    }

    DWORD bytes = sizeof(packet); // 解码缓冲区上限，解码后再次检查精确大小。
    if (!CryptStringToBinaryA(base64.data(), static_cast<DWORD>(base64.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_STRICT,
            reinterpret_cast<BYTE*>(&packet), &bytes, nullptr, nullptr) || bytes != sizeof(packet) ||
        packet.size != sizeof(packet) || packet.version != monitor::kProtocolVersion ||
        !packet.sessionIdentity || readerPid != packet.pid) {
        return false;
    }
    if (const auto* creation = parsed.value.find("processCreation100ns")) { // 可缺失的调用方创建时间声明。
        if (!creation->tryGetU64(row.readerCreation) || !row.readerCreation) {
            return false;
        }
    }
    row.clue = evidence::ClassifyApiMonitorClue(packet);
    return true;
}

// 统一输出失败阶段、原始行号或存储错误。样本若已登记，始终将其 ID 随失败一起返回。
Result Failure(int code, const wchar_t* status, std::uint64_t sequence = 0,
    DWORD native = 0, const std::string& sample = {}, const char* detail = "")
{
    return {code, Json::object({{L"status", Json::string(status)},
        {L"sourceSequence", sequence ? Json::count(sequence) : Json{}},
        {L"win32Error", native ? Json::number(native) : Json{}},
        {L"sampleId", sample.empty() ? Json{} : Json::string({sample.begin(), sample.end()})},
        {L"detail", Json::string(std::wstring(detail, detail + std::char_traits<char>::length(detail)))}}), {status}};
}

// 将验证好的线索按原始顺序写入单段。尾部计数用于识别仅写了前缀的失败导入。
project::ProjectResult Store(project::ProjectDocument& document, const project::SampleInfo& sample,
    const std::vector<evidence::ArchivedApiMonitorClue>& rows, std::uint64_t sourceRows, archive::RawEvidenceReceipt& receipt)
{
    const auto append = [&](archive::RawEvidenceArchive& writer) -> project::ProjectResult {
        for (std::size_t first = 0; first < rows.size(); first += kBatchRows) { // 每批独立封装为完整块。
            const auto count = (std::min)(kBatchRows, rows.size() - first); // 本批线索总数。
            std::vector<std::string> metadata; // 生存期覆盖 Append 的所有 JSON 视图。
            std::vector<archive::RawEvidenceInput> inputs; // 从行中借用原包，不重新序列化原字段。
            metadata.reserve(count);
            inputs.reserve(count);
            for (std::size_t index = first; index < first + count; ++index) {
                const auto& row = rows[index]; // 本批对应原始归档中的一条线索。
                evidence::JsonObject fields{{"kind", V::makeString(std::string(evidence::kApiMonitorClueRecord))},
                    {"sourceSequence", V::makeString(std::to_string(row.sourceSequence))}};
                if (row.readerCreation) {
                    fields.emplace_back("readerCreation100ns", V::makeString(std::to_string(row.readerCreation)));
                }
                metadata.push_back(evidence::WriteJson(V::makeObject(std::move(fields))));
                inputs.push_back({metadata.back(), {reinterpret_cast<const char*>(&row.packet), sizeof(row.packet)}});
            }
            const auto written = writer.Append(inputs); // 同步提交本块并回读底层状态。
            if (written.result.status != archive::SegmentWriteStatus::Ok) {
                return {project::ProjectError::IoError, written.result.error.win32Error, "writeClueBlock"};
            }
        }

        // 尾记只声明文件解析与导入范围。源端覆盖范围与丢失仍独立保留为未知。
        const auto metadata = evidence::WriteJson(V::makeObject({
            {"kind", V::makeString(std::string(evidence::kApiMonitorClueEnd))},
            {"sourceRows", V::makeString(std::to_string(sourceRows))}, {"clueRows", V::makeString(std::to_string(rows.size()))}}));
        const archive::RawEvidenceInput end{metadata, {}}; // 原始字节为空的导入回执记录。
        const auto written = writer.Append(std::span(&end, 1)); // 尾部为单独的块。
        if (written.result.status != archive::SegmentWriteStatus::Ok) {
            return {project::ProjectError::IoError, written.result.error.win32Error, "writeClueEnd"};
        }
        return {};
    };
    return document.WriteRawEvidenceSegment({document.Info()->projectId, sample.sampleId, 1, {}, append}, receipt);
}

// 将原包事实和未知项投影成 CLI 值。原包序号与 Stored 序号分别引用。
Json ClueJson(const evidence::ArchivedApiMonitorClue& row, std::uint64_t rawSequence, bool includePacket)
{
    const auto& packet = row.packet; // 原始调用来源头与回包字段。
    const auto family = row.clue->family; // 稳定线索类别。
    const bool hasReturn = packet.snapshotIndex == monitor::kApiCallReturnValueMarker &&
        (packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode) ||
         packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusUnknown));
    const wchar_t* phase = hasReturn ? L"return" : packet.resultKind ==
        static_cast<std::uint32_t>(monitor::EventResultKind::EntryOnly) ? L"entry" : L"observation";
    std::vector<std::pair<std::wstring, Json>> fields{
        {L"rawSequence", Json::count(rawSequence)}, {L"sourceSequence", Json::count(row.sourceSequence)},
        {L"family", Json::string({family.begin(), family.end()})}, {L"api", Json::string(std::wstring(row.clue->api))},
        {L"pid", Json::number(packet.pid)}, {L"tid", Json::number(packet.tid)},
        {L"sourceSessionIdentity", Json::count(packet.sessionIdentity)}, {L"time100ns", Json::count(packet.timestamp100ns)},
        {L"archivedCallerCreation100ns", row.readerCreation ? Json::count(row.readerCreation) : Json{}},
        {L"phase", Json::string(phase)}, {L"reportedReturnBits", hasReturn ? Json::hex(packet.hookAddress) : Json{}},
        {L"reportedStatusCode", packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)
            ? Json::signedNumber(packet.resultCode) : Json{}},
        {L"targetIdentity", Json{}}, {L"completedWriteBytes", Json{}}, {L"executed", Json{}}, {L"attribution", Json{}},
    }; // 未知字段显式为空，旧摘要不会升级成跨进程事实。
    if (includePacket) {
        const auto* begin = reinterpret_cast<const std::uint8_t*>(&packet); // 已核对的原包字节范围。
        fields.emplace_back(L"packet", Json::bytes({begin, begin + sizeof(packet)}, sizeof(packet)));
    }
    return Json::object(fields);
}

// 重开项目中指定样本的 raw/1。先扫完整段和导入尾记，再发布本次页或明确失败。
Result Replay(const project::ProjectDocument& document, const std::string& sample, std::uint64_t after,
    std::uint64_t limit, bool includePacket, const archive::RawEvidenceBoundary* expected = nullptr)
{
    std::vector<Json> page; // 流扫描时只保存本页范围。
    evidence::ApiMonitorClueReadback readback; // 线索与尾记语义由三端共用的读状态校验。
    std::uint64_t lastShown = after; // 上一个已显示的原始序号。
    const auto visitor = [&](const archive::SegmentIdentity&, const archive::BlockInfo&,
                             const std::vector<archive::DecodedRecord>& records) {
        for (const auto& record : records) {
            const auto* raw = std::get_if<archive::RawRecordV1>(&record.body); // 只读已校验 raw 正文。
            if (!raw) {
                return false;
            }
            const auto parsed = evidence::ParseJson(raw->metadataJson); // 单条来源元数据。
            std::optional<evidence::ArchivedApiMonitorClue> row; // 合法尾记无行可显示。
            if (!parsed.ok() || !readback.Accept(parsed.value, raw->inlineRawData, row)) {
                return false;
            }
            if (row && record.recordSequence > after && page.size() < limit) {
                page.push_back(ClueJson(*row, record.recordSequence, includePacket));
                lastShown = record.recordSequence;
            }
        }
        return true;
    };

    archive::RawEvidenceScanResult scan; // Stored 封装、CRC、序列和段端点。
    const auto io = document.ReadRawEvidenceSegment({document.Info()->projectId, sample, 1, {}, 0,
        visitor, kInputBytes}, scan);
    if (!io) {
        return Failure(io.error == project::ProjectError::NotFound ? 5 : 3, L"archive-unavailable", 0,
            io.nativeError, sample, io.detail);
    }
    if (!readback.ended || !scan.checked || !scan.VerifiedBoundary(expected ? *expected : *scan.checked)) {
        return Failure(4, L"archive-invalid-or-incomplete", 0, 0, sample);
    }
    return {0, Json::object({{L"status", Json::string(L"readback-verified")},
        {L"sampleId", Json::string({sample.begin(), sample.end()})}, {L"rawSegment", Json::count(1)},
        {L"sourceRows", Json::count(readback.sourceRows)}, {L"clueRows", Json::count(readback.clues)},
        {L"coverage", Json::string(L"unknown")},
        {L"nextAfter", !page.empty() && lastShown < readback.clues ? Json::count(lastShown) : Json{}},
        {L"rows", Json::array(page)}}), {}};
}

// 先完整验证已关闭的事件文件，成功后按项目修订创建新样本并进行刷盘回读。
Result Import(const Args& args)
{
    const auto title = Utf8Title(args.require(L"--title")); // 冻结到新样本的标题。
    const auto path = args.require(L"--project"); // 用户现有项目目录或清单。
    std::vector<evidence::ArchivedApiMonitorClue> rows; // 仅选中且已核对的原始调用包。
    const auto source = ScanClosedArchive(args.require(L"--archive"), [&](std::string_view line, std::uint64_t sequence) {
        evidence::ArchivedApiMonitorClue row; // 当前候选原包，不匹配的行随回调返回丢弃。
        if (!DecodeArchiveLine(line, sequence, row)) {
            return false;
        }
        if (row.clue) {
            rows.push_back(std::move(row));
        }
        return true;
    });
    if (source.error != ERROR_SUCCESS) {
        return Failure(3, L"source-unavailable", 0, source.error);
    }
    if (source.invalid) {
        return Failure(4, L"source-invalid-or-truncated", source.rows + 1);
    }
    if (rows.empty()) {
        return {0, Json::object({{L"status", Json::string(L"no-clues")}, {L"sourceRows", Json::count(source.rows)},
            {L"clueRows", Json::count(0)}, {L"coverage", Json::string(L"unknown")}}), {}};
    }

    // 只打开已存在项目，写锁串行登记样本和写入 raw 段。
    project::ProjectDocument document; // 本次导入期间独占项目写入租约。
    if (const auto open = document.Open(path, project::ProjectAccess::ReadWrite); !open) {
        return Failure(3, L"project-unavailable", 0, open.nativeError, {}, open.detail);
    }
    const auto revision = document.Info()->revisionId; // 冻结本次明确打开并核验的写入项目修订。
    project::SampleInfo sample; // 项目服务分配的新采样身份。
    if (const auto create = document.CreateSample(title, sample, revision); !create) {
        return Failure(3, L"sample-create-failed", 0, create.nativeError, {}, create.detail);
    }
    archive::RawEvidenceReceipt receipt; // 同一写入器确认的刷盘边界。
    const auto written = Store(document, sample, rows, source.rows, receipt);
    if (!written || !receipt.flushed) {
        return Failure(3, L"archive-write-failed", 0, written.nativeError, sample.sampleId, written.detail);
    }
    return Replay(document, sample.sampleId, 0, 0, false, &*receipt.flushed);
}

// 从只读项目回放指定样本，按 Stored raw 序号翻页，或回读某条线索的原始包。
Result RunReplay(const Args& args)
{
    const auto sample = args.require(L"--sample"); // 项目层将验证规范 UUID，路径不能由其自由构造。
    if (sample.size() != 36 || sample.find_first_not_of(L"0123456789abcdef-") != sample.npos) {
        return Failure(1, L"invalid-sample-id");
    }
    const auto after = args.integer(L"--after", 0); // 上一页最后一个原始序号。
    const auto limit = args.integer(L"--limit", 25); // 调用者指定的页大小。
    if (!limit || limit > kPageRows || (args.has(L"--packet") && args.integer(L"--packet") != 1)) {
        return Failure(1, L"invalid-page-options");
    }
    project::ProjectDocument document; // 按冻结的项目目录只读回放。
    if (const auto open = document.Open(args.require(L"--project")); !open) {
        return Failure(3, L"project-unavailable", 0, open.nativeError, {}, open.detail);
    }
    // 上方已经限定 ASCII UUID 字符，按单字节编码转给项目层。
    std::string id; // 项目接口消费的 UUID 字符串。
    id.reserve(sample.size());
    for (const auto ch : sample) {
        id.push_back(static_cast<char>(ch));
    }
    return Replay(document, id, after, limit, args.has(L"--packet"));
}

} // namespace

void RegisterApiMonitorEvidenceCommands()
{
    Command ingest; // 导入已结束的 API Monitor 原文件，创建独立项目采样。
    ingest.path = L"analyze api-evidence import";
    ingest.syntax = L"KswordCLI.exe analyze api-evidence import --archive EVENTS_JSONL --project PATH --title TITLE [--json]";
    ingest.options = L"Required: --archive, --project and --title.";
    ingest.summary = L"Import injection-related clues from a closed WinAPI events.jsonl into a new sample.";
    ingest.notes = L"The source retains its original bytes. Coverage and target identity are unknown.";
    ingest.run = Import;
    addCommand(std::move(ingest));

    Command replay; // 只读重开相同采样，可按序号翻页并选读原包。
    replay.path = L"analyze api-evidence replay";
    replay.syntax = L"KswordCLI.exe analyze api-evidence replay --project PATH --sample UUID [--after SEQUENCE] [--limit N] [--packet 1] [--json]";
    replay.options = L"Required: --project and --sample. Optional: --after, --limit (1-100) and --packet 1.";
    replay.summary = L"Read a verified page of archived WinAPI clues.";
    replay.notes = L"Use the returned nextAfter as the next page's --after value.";
    replay.run = RunReplay;
    addCommand(std::move(replay));
}

} // namespace ks::cli::action_analyze
