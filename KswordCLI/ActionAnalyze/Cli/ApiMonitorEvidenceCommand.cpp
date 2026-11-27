#include "ApiMonitorEvidenceCommand.h"
#include "ApiMemoryLifecycleProjection.h"
#include "ApiCaptureProgress.h"

#include "../../CommandRegistry.h"
#include "../Project/CooperativeApiCapture.h"
#include "../Project/AttachedApiCapture.h"
#include "../Project/LaunchedApiCapture.h"
#include "../Project/ProjectEtwEvidence.h"
#include "../Project/ProjectApiClueArchive.h"
#include "../Project/ProjectApiCheckpoint.h"
#include "../Project/ProjectStorage.h"
#include "../../../Ksword5.1/Ksword5.1/ksword/string/string.h"

#include <array>
#include <iterator>
#include <iostream>
#include <wincrypt.h>

#pragma comment(lib, "Crypt32.lib")

namespace ks::cli::action_analyze {
namespace {
namespace project = Ksword::ActionAnalyze;
namespace evidence = Ksword::Evidence;
namespace monitor = ks::winapi_monitor;
using Packet = monitor::ApiMonitorEventPacket;

constexpr DWORD kInputBytes = 32u << 20; // 单次离线导入的输入配额。
constexpr std::size_t kReadBytes = 64u << 10; // 顺序读的固定块大小。
constexpr std::size_t kLineBytes = 8192; // 覆盖当前 1000 字节包及 JSON 转义字段。
constexpr std::uint64_t kPageRows = 100; // 单份 CLI 回执最多包含的线索数。

// 输入共享JSON纯值和原文字摘要，返回CLI外壳JSON；先解码UTF-8，保留中文路径与诊断。
Json CaptureReceiptJson(const evidence::JsonValue& value, const wchar_t* display = L"unavailable")
{
    const auto serialized = evidence::WriteJson(value); // 共享序列化器输出UTF-8，不能逐字节扩宽。
    return Json{ks::str::Utf8ToUtf16(serialized), display}; // 保留非JSON模式原有的简短摘要。
}

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
    DWORD native = 0, const std::string& sample = {}, const char* detail = "", const Json& progress = {})
{
    std::vector<std::pair<std::wstring, Json>> fields{{L"status", Json::string(status)},
        {L"sourceSequence", sequence ? Json::count(sequence) : Json{}},
        {L"win32Error", native ? Json::number(native) : Json{}},
        {L"sampleId", sample.empty() ? Json{} : Json::string({sample.begin(), sample.end()})},
        {L"detail", Json::string(std::wstring(detail, detail + std::char_traits<char>::length(detail)))}};
    if (progress.text != L"null")
    {
        fields.emplace_back(L"captureProgress", progress); // 只对已订阅且已创建输出通道的调用附加交付事实。
    }
    return {code, Json::object(fields), {status}};
}

// 输入当前原包的同一份规则字段投影，输出带类型的已采事实，缺字段不补零或空字符串。
Json ReplayObservedFields(const project::Rules::ArchivedApiObservation& observation,
    const std::optional<evidence::ApiMonitorMemoryWriteReturn>& returned)
{
    const auto fields = project::Rules::ProjectApiPresetFields(observation.api, observation.family,
        returned, observation.evidence); // 与生产谓词求值使用相同目录和缺值语义。
    std::vector<Json> values; // 本行拥有的 JSON 值，不保留投影器借用的字符串视图。
    values.reserve(fields.size());
    for (const auto& field : fields)
    {
        Json value; // 仅由真实已采类型分支赋值，未知值不作为已知事实发布。
        const wchar_t* type = nullptr; // 字段实际类型，数值序列化为十进制字符串以保全 u64。
        if (const auto* boolean = std::get_if<bool>(&field.value))
        {
            value = Json::boolean(*boolean);
            type = L"bool";
        }
        else if (const auto* number = std::get_if<std::uint64_t>(&field.value))
        {
            value = Json::count(*number);
            type = L"u64";
        }
        else if (const auto* text = std::get_if<std::string_view>(&field.value))
        {
            value = Json::string(ks::str::Utf8ToUtf16(std::string(*text)));
            type = L"text";
        }
        // 当前生产投影只添加 Known；不让未来新增的缺值质量意外落入已知值分支。
        if (field.quality != project::Rules::Quality::Known || !type)
        {
            continue;
        }
        values.push_back(Json::object({
            {L"id", Json::string(ks::str::Utf8ToUtf16(std::string(field.id)))},
            {L"type", Json::string(type)}, {L"value", value}}));
    }
    return Json::array(values);
}

// 输入本页冻结规则库和已核验原包坐标，返回本条分类、行为及同一原包的已采规则输入。
Json ReplayRuleJson(const project::Rules::ApiPresetDatabase& database,
    const evidence::ArchivedApiMonitorClue& row, std::uint64_t rawSequence)
{
    // 单条沿生产页投影器求值，不从API名称、预览文本或活采latest推导历史行为。
    const auto api = ks::str::Utf16ToUtf8(std::wstring(row.clue->api)); // 同步求值期间持有精确API名。
    const auto returned = evidence::ReadApiMonitorMemoryWriteReturn(row.packet); // 独立的真实返回证据。
    const project::Rules::ArchivedApiObservation observation{
        rawSequence, row.sourceSequence, api, row.clue->family,
        returned ? std::optional{project::Rules::ArchivedApiMemoryWriteReturn{
            returned->returned, returned->statusCode}} : std::nullopt,
        project::Rules::ReadApiPresetEvidence(row.packet)}; // 不套用活采计划序号，兼容首条导入记录#1。
    const auto observed = ReplayObservedFields(observation, returned); // 规则坏配置也保留原包可解释的已采值。
    if (!database.error.empty())
    {
        return Json::object({{L"status", Json::string(L"configuration-failed")},
            {L"error", Json::string(ks::str::Utf8ToUtf16(database.error))},
            {L"observedFields", observed}});
    }
    const auto report = project::Rules::AnalyzeVerifiedApiPresetPage(database,
        std::span<const project::Rules::ArchivedApiObservation>(&observation, 1), 1,
        project::Rules::ApiPresetProfile::ByCategory);
    if (report.error != project::Rules::ApiPresetError::None || report.matches.size() != 1)
    {
        return Json::object({{L"status", Json::string(L"evaluation-failed")},
            {L"error", Json::number(static_cast<std::uint32_t>(report.error))},
            {L"observedFields", observed}});
    }
    const auto& match = report.matches.front(); // 同一原包的拥有型分类及可选行为释义。
    Json behavior; // 普通分类未附行为时保持null，不冒充无意义的空释义。
    if (match.behavior)
    {
        const auto& hit = *match.behavior; // 规则文件实际提供的双语文本与证据强度。
        behavior = Json::object({
            {L"ruleId", Json::string(ks::str::Utf8ToUtf16(hit.ruleId))},
            {L"evidence", Json::string(ks::str::Utf8ToUtf16(hit.evidence))},
            {L"summary", Json::string(ks::str::Utf8ToUtf16(hit.summary))},
            {L"summaryZh", Json::string(ks::str::Utf8ToUtf16(hit.summaryZh))}});
    }
    return Json::object({{L"status", Json::string(L"evaluated")},
        {L"ruleId", Json::string(ks::str::Utf8ToUtf16(match.ruleId))},
        {L"observedFields", observed},
        {L"behavior", behavior}});
}

// 输入本页规则库及可选的已核验采集计划，输出回放与采集两份身份及内容比较结果。
Json ReplayRuleProfile(const project::Rules::ApiPresetDatabase& database,
    const project::ProjectApiCheckpoint* checkpoint = nullptr)
{
    const bool recorded = checkpoint && !checkpoint->ruleSourceSha256.empty(); // 旧导入档没有规则内容身份。
    const bool replayKnown = database.error.empty() && !database.sourceSha256.empty(); // 配置失败不能当作已知不匹配。
    return Json::object({
        {L"presetSet", Json::string(ks::str::Utf8ToUtf16(database.presetSet))},
        {L"sourceSha256", database.sourceSha256.empty() ? Json{} :
            Json::string(ks::str::Utf8ToUtf16(database.sourceSha256))},
        {L"recordedPresetSet", checkpoint && !checkpoint->rulePresetSet.empty() ?
            Json::string(ks::str::Utf8ToUtf16(checkpoint->rulePresetSet)) : Json{}},
        {L"recordedSourceSha256", recorded ?
            Json::string(ks::str::Utf8ToUtf16(checkpoint->ruleSourceSha256)) : Json{}},
        {L"matchesRecordedRules", recorded && replayKnown ?
            Json::boolean(checkpoint->ruleSourceSha256 == database.sourceSha256) : Json{}},
        {L"configError", database.error.empty() ? Json{} :
            Json::string(ks::str::Utf8ToUtf16(database.error))}});
}

// 将原包事实和未知项投影成 CLI 值。原包序号与 Stored 序号分别引用。
Json ClueJson(const evidence::ArchivedApiMonitorClue& row, std::uint64_t rawSequence, bool includePacket,
    std::uint64_t rawSegment = 1, const project::Rules::ApiPresetDatabase* database = nullptr)
{
    const auto& packet = row.packet; // 原始调用来源头与回包字段。
    const auto family = row.clue->family; // 稳定线索类别。
    const bool hasReturn = packet.snapshotIndex == monitor::kApiCallReturnValueMarker &&
        (packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode) ||
         packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusUnknown));
    const wchar_t* phase = hasReturn ? L"return" : packet.resultKind ==
        static_cast<std::uint32_t>(monitor::EventResultKind::EntryOnly) ? L"entry" : L"observation";
    std::vector<std::pair<std::wstring, Json>> fields{
        {L"rawSegment", Json::count(rawSegment)}, {L"rawSequence", Json::count(rawSequence)},
        {L"sourceSequence", Json::count(row.sourceSequence)},
        {L"family", Json::string({family.begin(), family.end()})}, {L"api", Json::string(std::wstring(row.clue->api))},
        {L"pid", Json::number(packet.pid)}, {L"tid", Json::number(packet.tid)},
        {L"sourceSessionIdentity", Json::count(packet.sessionIdentity)}, {L"time100ns", Json::count(packet.timestamp100ns)},
        {L"archivedCallerCreation100ns", row.readerCreation ? Json::count(row.readerCreation) : Json{}},
        {L"phase", Json::string(phase)}, {L"reportedReturnBits", hasReturn ? Json::hex(packet.hookAddress) : Json{}},
        {L"reportedStatusCode", packet.resultKind == static_cast<std::uint32_t>(monitor::EventResultKind::StatusCode)
            ? Json::signedNumber(packet.resultCode) : Json{}},
        {L"targetIdentity", Json{}}, {L"completedWriteBytes", Json{}}, {L"executed", Json{}}, {L"attribution", Json{}},
        {L"apiMemoryLifecycle", ks::cli::action_analyze::ApiMemoryLifecycleCliJson(packet)}, // 生命周期原请求和成功输出。
    }; // 未知字段显式为空，旧摘要不会升级成跨进程事实。
    if (database)
    {
        fields.emplace_back(L"rule", ReplayRuleJson(*database, row, rawSequence)); // 行为与原行共用坐标，不另读档。
    }
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
    const auto database = project::Rules::LoadApiPresetDatabase(); // 一页内固定同一规则内容身份。
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
                page.push_back(ClueJson(*row, record.recordSequence, includePacket, 1, &database));
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
    const auto source = evidence::ApiMonitorArchiveSourceName(readback.source); // 完整核验后才公布尾记声明。
    return {0, Json::object({{L"status", Json::string(L"readback-verified")},
        {L"sampleId", Json::string({sample.begin(), sample.end()})}, {L"rawSegment", Json::count(1)},
        {L"archiveSource", Json::string({source.begin(), source.end()})},
        {L"mixedEtw", Json::boolean(readback.mixedEtw)},
        {L"sourceRows", Json::count(readback.sourceRows)}, {L"clueRows", Json::count(readback.clues)},
        {L"coverage", Json::string(L"unknown")},
        {L"ruleProfile", ReplayRuleProfile(database)},
        {L"nextAfter", !page.empty() && lastShown < readback.clues ? Json::count(lastShown) : Json{}},
        {L"rows", Json::array(page)}}), {}};
}

// 逐段回查合作管道检查点。只在本段完全核验后发布记录，坏段保留此前有效前缀。
std::optional<Result> ReplayCooperative(const project::ProjectDocument& document, const std::string& sample,
    std::uint64_t after, std::uint64_t limit, bool includePacket, std::uint64_t through = 0)
{
    const auto database = project::Rules::LoadApiPresetDatabase(); // 各段沿本次回放冻结库，不读取采集时latest。
    project::ProjectApiCheckpoint checkpoint; // 上一次完整核验的有效水位。
    std::vector<Json> page; // 本页只保留有限条分类线索。
    std::uint64_t clues = 0; // 连续前缀中的线索数。
    std::uint64_t lastShown = after; // 当前页可用于翻页的最后一条原始序号。
    bool more = false; // 还有本页以后的已核验线索。
    project::ProjectResult status; // 首个未通过的检查点或待读终段。
    for (std::uint64_t ordinal = 1; ordinal; ++ordinal) {
        std::vector<Json> rows; // 暂存单段候选，直到标记、原包和散列通过。
        std::uint64_t segmentClues = 0; // 当前段中的线索计数。
        auto segmentLast = lastShown; // 当前段候选翻页位置。
        bool segmentMore = false; // 当前段内有窗口之外的分类线索。
        status = project::ReadApiCheckpoint(document, sample, ordinal, checkpoint.ordinal ? &checkpoint : nullptr,
            checkpoint, [&](const auto&, const auto&, const auto& records) {
                for (const auto& record : records) {
                    const auto& raw = std::get<archive::RawRecordV1>(record.body); // 共用验证器确认正文格式。
                    const auto clue = project::ReadCommittedApiClue(raw); // 未分类包仍属于已提交的原始流。
                    if (!clue) {
                        continue;
                    }
                    ++segmentClues;
                    if (record.recordSequence > after) {
                        if (page.size() + rows.size() < limit) {
                            rows.push_back(ClueJson(*clue, record.recordSequence, includePacket, ordinal, &database));
                            segmentLast = record.recordSequence;
                        } else {
                            segmentMore = true;
                        }
                    }
                }
                return true;
            });
        if (!status) {
            break;
        }
        if (checkpoint.source != evidence::ApiMonitorArchiveSource::CooperativePipe) {
            return std::nullopt;
        }
        // 只有已发布段的结果进入累计计数和调用者可见的页。
        clues += segmentClues;
        more |= segmentMore;
        lastShown = segmentLast;
        page.insert(page.end(), std::make_move_iterator(rows.begin()), std::make_move_iterator(rows.end()));
        if (checkpoint.finalSegment || ordinal == through) {
            break;
        }
    }
    // 结束回执有写端已确认的水位；在这个范围内缺检查点同样是回读故障。
    const bool invalid = !status && (status.error != project::ProjectError::NotFound || checkpoint.ordinal < through);
    if (!checkpoint.ordinal) {
        return Failure(invalid ? 4 : 5,
            L"archive-invalid-or-incomplete", 0, status.nativeError, sample, status.detail);
    }
    return Result{invalid ? 4 : 0, Json::object({{L"status", Json::string(checkpoint.finalSegment ? L"readback-verified" : L"readback-prefix")},
        {L"sampleId", Json::string({sample.begin(), sample.end()})}, {L"rawSegment", Json::count(1)},
        {L"committedSegments", Json::count(checkpoint.ordinal)}, {L"finalSegment", Json::boolean(checkpoint.finalSegment)},
        {L"archiveSource", Json::string(L"cooperative-pipe")}, {L"mixedEtw", Json::boolean(checkpoint.mixedEtw)},
        {L"sourceRows", Json::count(checkpoint.lastSourceSequence)}, {L"clueRows", Json::count(clues)},
        {L"coverage", Json::string(L"unknown")}, {L"sourceState", checkpoint.sourceState.empty() ? Json{} :
            Json::string(project::ProjectStorage::WideAscii(checkpoint.sourceState))},
        {L"ruleProfile", ReplayRuleProfile(database, &checkpoint)},
        {L"failedSegment", invalid ? Json::count(checkpoint.ordinal + 1) : Json{}},
        {L"nextAfter", !page.empty() && more ? Json::count(lastShown) : Json{}}, {L"rows", Json::array(page)}}), {}};
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
    const auto written = project::WriteApiClueArchive(document, sample, rows, source.rows,
        evidence::ApiMonitorArchiveSource::ClosedJsonl, receipt);
    if (!written || !receipt.flushed) {
        return Failure(3, L"archive-write-failed", 0, written.nativeError, sample.sampleId, written.detail);
    }
    return Replay(document, sample.sampleId, 0, 0, false, &*receipt.flushed);
}

// 将已提交段的累计规则结果投影至 CLI；空结果明确返回 null，失败时保留此前命中。
Json CooperativeRulesReport(const project::CooperativeApiRuleReceipt& rules)
{
    using project::ProjectStorage::WideAscii;
    const auto shared = ApiCaptureRulesJson(rules); // 行为窗口沿实时及原生同一投影，不再维护第四份坐标/双语转换。
    Json latest; // 最近命中及原始坐标；没有命中时为空。
    if (rules.latest) {
        const auto& match = *rules.latest; // 已提交原包中的末条匹配结果。
        std::vector<std::pair<std::wstring, Json>> fields{{L"ruleId", Json::string(ks::str::Utf8ToUtf16(match.ruleId))},
            {L"segmentOrdinal", Json::count(rules.latestSegment)}, {L"rawSequence", Json::count(match.rawSequence)},
            {L"sourceSequence", Json::count(match.sourceSequence)}};
        if (match.behavior) {
            fields.emplace_back(L"behavior", Json::object({{L"ruleId", Json::string(ks::str::Utf8ToUtf16(match.behavior->ruleId))},
                {L"evidence", Json::string(WideAscii(match.behavior->evidence))},
                {L"summary", Json::string(ks::str::Utf8ToUtf16(match.behavior->summary))},
                {L"summaryZh", match.behavior->summaryZh.empty() ? Json{} :
                    Json::string(ks::str::Utf8ToUtf16(match.behavior->summaryZh))}}));
        }
        latest = Json::object(fields);
    }
    return Json::object({{L"presetSet", rules.presetSet.empty() ? Json{} : Json::string(WideAscii(rules.presetSet))},
        {L"sourceSha256", rules.sourceSha256.empty() ? Json{} : Json::string(WideAscii(rules.sourceSha256))},
        // 外置规则错误可含用户规则ID及路径；与双语释义相同按UTF-8解码，不逐字节扩宽。
        {L"configError", rules.configError.empty() ? Json{} : Json::string(ks::str::Utf8ToUtf16(rules.configError))},
        {L"profile", Json::string(L"by-category")}, {L"coverage", Json::string(L"unknown")},
        {L"state", Json::string(rules.failed ? L"evaluation-failed" : L"ready")},
        {L"matchedRows", Json::count(rules.matchedRows)}, {L"latest", std::move(latest)},
        {L"behaviorMatches", CaptureReceiptJson(*shared.find("behaviorMatches"))},
        {L"behaviorWindowTruncated", CaptureReceiptJson(*shared.find("behaviorWindowTruncated"))},
        {L"recentBehaviors", CaptureReceiptJson(*shared.find("recentBehaviors"))}});
}

// 输入共享候选文档与种类，输出原命令的兼容外壳；原坐标、身份和请求值只有一处投影所有者。
Json CooperativeTransfersReport(const evidence::JsonValue& candidates, unsigned kind)
{
    // 固定三类窗口分别对应原有apiTransfers/apiApcTransfers/apiContextTransfers，不改变顶层接口。
    constexpr const char* counts[] = {"candidateCount", "apcCandidateCount", "contextCandidateCount"};
    constexpr const char* truncated[] = {"windowTruncated", "apcWindowTruncated", "contextWindowTruncated"};
    constexpr const char* windows[] = {"recent", "recentApc", "recentContext"};
    constexpr const wchar_t* sources[] = {L"reported-api-write-to-thread-create",
        L"reported-api-write-to-apc-queue", L"reported-api-write-to-context-request"};
    // 输入只由ApiCaptureTransferCandidatesJson生成，固定成员包含64位十进制字符串，不再逐字段扩宽重建。
    std::vector<std::pair<std::wstring, Json>> fields{
        {L"evidence", Json::string(sources[kind])},
        {L"candidateCount", CaptureReceiptJson(*candidates.find(counts[kind]))},
        {L"evictedWrites", CaptureReceiptJson(*candidates.find("evictedWrites"))},
        {L"windowTruncated", CaptureReceiptJson(*candidates.find(truncated[kind]))},
        {L"recent", CaptureReceiptJson(*candidates.find(windows[kind]))}};
    if (kind == 0)
    {
        fields.emplace_back(L"execution", Json::string(L"unknown")); // 保留线程创建候选原有的外层未知表示。
    }
    else
    {
        fields.emplace_back(kind == 1 ? L"delivery" : L"contextApplied", Json{}); // 接受请求不等于投递或上下文采用。
        fields.emplace_back(L"execution", Json{});
    }
    return Json::object(fields);
}

Result CaptureEvidence(const Args& args, bool attached, bool launch = false)
{
    const auto title = Utf8Title(args.require(L"--title")); // 冻结到项目的新采样标题。
    const auto duration = args.u32(L"--duration-ms", 3000); // 安装回执及对应覆盖经核验后开始计时。
    auto pid = launch ? DWORD{0} : args.u32(L"--pid"); // 启动模式仅从创建回执取得实际PID。
    auto creation = launch ? std::uint64_t{0} : args.integer(L"--creation-filetime"); // 已有实例必须冻结创建时间。
    if (!args.has(L"--confirm") || (!launch && (pid <= 4 || pid == GetCurrentProcessId() || !creation)) ||
         title.empty() || (duration != 0 && (duration < 1000 || duration > 120000)) ||
        (args.has(L"--startup-progress") && args.get(L"--startup-progress") != L"1") ||
        (args.has(L"--capture-progress") && args.get(L"--capture-progress") != L"1") ||
        (args.has(L"--agent-etw") && args.get(L"--agent-etw") != L"1")) {
        return Failure(1, attached ? L"invalid-attachment-scope" : L"invalid-resident-capture-scope");
    }
    std::optional<std::uint32_t> entryRva; // 启动时省略使用PE入口；显式零值不能偷偷退回默认。
    if (launch && args.has(L"--rva"))
    {
        entryRva = args.u32(L"--rva");
        if (!*entryRva)
        {
            return Failure(1, L"invalid-launch-rva");
        }
    }

    project::ProjectDocument document; // 本轮独占项目写入租约，避免同一采样混用修订。
    if (const auto opened = document.Open(args.require(L"--project"), project::ProjectAccess::ReadWrite); !opened) {
        return Failure(3, L"project-unavailable", 0, opened.nativeError, {}, opened.detail);
    }
    std::optional<project::NetworkTrafficBackend> networkTraffic; // 省略时不抓包，显式来源不静默回退。
    if (args.has(L"--network-traffic"))
    {
        const auto source = args.require(L"--network-traffic"); // 原网络页提供的两种实际来源。
        if (source == L"raw-socket")
        {
            networkTraffic = project::NetworkTrafficBackend::RawSocket;
        }
        else if (source == L"existing-wfp")
        {
            networkTraffic = project::NetworkTrafficBackend::ExistingWfp;
        }
        else
        {
            return Failure(1, L"invalid-network-traffic-source");
        }
    }
    const auto revision = document.Info()->revisionId; // 采集启动之前冻住当前保存的修订。
    Cancellation cancel; // 控制台停止由本次采样执行，不终止目标。
    const bool captureEtw = args.has(L"--agent-etw"); // 同一采样增开配套的自有 ETW 流。
    ApiCaptureProgress progressOutput(args.has(L"--startup-progress") || args.has(L"--capture-progress"),
        document.Info()->projectId); // 原有有界writer统一发送stderr通知，不在目标恢复线程同步写终端。
    project::CooperativeApiCommitted onCommitted; // 仅用户选择运行进度时订阅已核验检查点。
    project::CooperativeApiTransferCommitted onTransfers; // 直接使用原控制器的活动快照，不增设轮询。
    if (args.has(L"--capture-progress"))
    {
        onCommitted = [&](const project::SampleInfo& sample, const project::ProjectApiCheckpoint& checkpoint,
            const project::CooperativeApiRuleReceipt& rules)
        {
            progressOutput.Committed(sample, checkpoint, rules);
        };
        onTransfers = [&](const project::CooperativeApiTransferReceipt& transfers)
        {
            progressOutput.Transfers(transfers);
        };
    }
    project::CooperativeApiStartup onStartup; // 显式选择才向stderr输出，不改变stdout最终单JSON文档。
    if (args.has(L"--startup-progress"))
    {
        onStartup = [&](const monitor::CaptureStartupProgress& progress) {
            // 一阶段一行，输出原快照；用户可在采样未结束时分辨装载与真正Ready。
            const auto value = project::ApiCaptureStartupJson(progress); // 使用归档与原生响应相同字段。
            progressOutput.Publish(value);
        };
    }
    const bool autoTransfer = args.has(L"--auto-transfer"); // 本轮显式开启API调用前目标自动设防。
    project::CooperativeApiReceipt run; // 三种准入最终共用同一归档、规则和退出状态投影。
    std::optional<project::LaunchedApiReceipt> launched; // 自有启动的入口交接责任独立于Agent采集。
    if (launch)
    {
        project::LaunchedApiLaunchProgress onLaunch; // 只有明确选择进度时才写stderr阶段回执。
        if (args.has(L"--startup-progress"))
        {
            onLaunch = [&](const project::LaunchedApiProgress& progress)
            {
                progressOutput.Publish(project::LaunchedApiProgressJson(progress));
            };
        }
        launched = project::CaptureLaunchedApi(document,
            {args.require(L"--exe"), entryRva, duration, title, revision, autoTransfer, networkTraffic, captureEtw},
            *cancel.token, {}, onCommitted, onTransfers, onStartup, onLaunch);
        if (launched->launch)
        {
            pid = launched->launch->pid;
            creation = launched->launch->creationFileTime;
        }
        run = std::move(launched->api);
        if (!launched->agentReadyBeforeMainResume && run.sample.sampleId.empty())
        {
            // 尚未登记采样的入口故障仍保留启动阶段，不能仅报成项目创建失败。
            std::vector<std::pair<std::wstring, Json>> failureFields{
                {L"status", Json::string(L"launch-bootstrap-incomplete")},
                {L"launch", CaptureReceiptJson(project::LaunchedApiProgressJson(*launched))}};
            const auto delivery = progressOutput.Finish(); // 恢复返回后排空；无订阅时不改变旧响应字段。
            if (!delivery.isNull())
            {
                failureFields.emplace_back(L"captureProgress", CaptureReceiptJson(delivery));
            }
            return {cancel.token->load() ? 6 : 3, Json::object(failureFields), {}};
        }
    }
    else if (attached)
    {
        run = project::CaptureAttachedApi(document,
            {pid, creation, true, false, duration, title, revision, {}, autoTransfer, networkTraffic, captureEtw},
            *cancel.token, {}, onCommitted, onTransfers, onStartup);
    }
    else
    {
        run = project::CaptureCooperativeApi(document, {pid, creation, duration, title, revision, captureEtw,
            project::ApiCaptureMode::CooperativeResident, {}, autoTransfer, networkTraffic},
            *cancel.token, {}, onCommitted, onTransfers, onStartup);
    }
    const auto progressDelivery = progressOutput.Finish(); // 原采集及恢复已返回后才有限排空旁路通知。
    const auto deliveryJson = progressDelivery.isNull() ? Json{} :
        CaptureReceiptJson(progressDelivery);
    if (!run.sampleStatus) {
        return Failure(3, L"sample-create-failed", 0, run.sampleStatus.nativeError, {}, run.sampleStatus.detail, deliveryJson);
    }
    if (!run.agentPathAvailable) {
        return Failure(3, L"agent-path-unavailable", 0, 0, run.sample.sampleId, "", deliveryJson);
    }
    const auto& sample = run.sample; // 成功登记的实际采样，而不是当前 UI 选择。
    const auto& captured = run.capture; // 从冻结目标的真实管道回执投影。
    const auto root = std::find_if(captured.processes.begin(), captured.processes.end(), [&](const auto& process) {
        return process.pid == pid && process.creation == creation;
    }); // 只有被冻结身份的实际安装回执可作为就绪证据。
    const bool ready = captured.started; // 同一会话的安装与有效覆盖均在启动阶段确认。
    Result archiveResult; // 保存独立的已提交回执或最早的存储故障。
    const bool apiArchived = run.committedSegments != 0; // 零线索时仍可回读原包或合法终段。
    if (apiArchived) {
        archiveResult = ReplayCooperative(document, sample.sampleId, 0, 1, false, run.committedSegments).value_or(
            Failure(4, L"archive-invalid-or-incomplete", 0, 0, sample.sampleId));
    }
    if (!run.archiveStatus) {
        archiveResult.diagnostics.emplace_back(L"archive-write-failed");
    }

    const auto* etw = run.etw ? &*run.etw : nullptr; // 仅请求时公开独立的 ETW 活采回执。
    const bool etwWriteFailed = etw && (!etw->archiveStatus || !etw->checkpointStatus); // 区分存储故障和来源缺口。
    const bool incomplete = run.omittedClues || run.rules.failed || (etw && etw->Incomplete()) ||
        (launched && (!launched->bootstrapClean || !launched->agentReadyBeforeMainResume ||
            !launched->initialMainSuspendReleased || launched->error)); // 启动交接不完整同样保留部分结果。
    const int captureCode = captured.code == 0 && incomplete ? 6 : captured.code; // 保留原 API 错误码。
    const int code = archiveResult.code ? archiveResult.code : !run.archiveStatus || etwWriteFailed ? 3 : captureCode;
    const auto* target = root == captured.processes.end() ? nullptr : &*root; // 只投影已绑定的目标实例回执。
    const bool connected = target && target->connected; // 没有连接证据时不发布生产方的会话或丢失值。
    // 目标退出也能完成清退，但不能代替生产方的停钩及完整排空回执。
    const bool hooksRemoved = connected && target->removed;
    const bool cleanPipeEof = connected && target->cleanPipeEof;
    const auto candidates = ApiCaptureTransferCandidatesJson(run.transfers); // 三类旧响应和实时/原生响应共用同一原坐标文档。
    std::vector<std::pair<std::wstring, Json>> fields{
        {L"status", Json::string(code == 0 ? L"capture-complete" : code == 6 ? L"capture-partial" : L"capture-failed")},
        {L"sampleId", Json::string({sample.sampleId.begin(), sample.sampleId.end()})},
        {L"revisionId", Json::string({revision.begin(), revision.end()})},
        {L"pid", Json::number(pid)}, {L"creationFileTime", Json::count(creation)},
        {L"transferHandoff", CaptureReceiptJson(run.transferHandoff)},
        {L"networkTraffic", CaptureReceiptJson(project::ApiCaptureNetworkJson(run.networkTraffic))},
        {L"residentVerified", Json::boolean(captured.reusedResident)},
        {L"captureMode", Json::string(launch ? L"launched-r3-attachment" : attached ? L"explicit-r3-attachment" : L"cooperative-resident")},
        {L"launch", launched ? CaptureReceiptJson(project::LaunchedApiProgressJson(*launched)) : Json{}},
        {L"attachmentIdentityVerified", attached ? Json::boolean(captured.attachmentIdentityVerified) : Json{}},
        {L"agentLoadAttempted", attached ? Json::boolean(captured.agentLoadAttempted) : Json{}},
        {L"agentModuleVerified", attached ? Json::boolean(captured.agentModuleVerified) : Json{}},
        {L"agentPath", attached && !captured.agentPath.empty() ? Json::string(captured.agentPath) : Json{}},
        {L"configPublished", Json::boolean(captured.configPublished)},
        {L"startup", CaptureReceiptJson(project::ApiCaptureStartupJson(captured.startup), L"startup")},
        {L"connected", Json::boolean(connected)}, {L"agentReady", Json::boolean(ready)},
        {L"sessionReady", connected ? Json::boolean(target->sessionReady) : Json{}},
        {L"hooksInstalled", connected ? Json::boolean(target->installed) : Json{}},
        {L"sourceSessionIdentity", connected ? Json::count(target->session) : Json{}},
        {L"completedInterval", Json::boolean(captured.completedInterval)},
        {L"cancelled", Json::boolean(captured.cancelled)}, {L"targetExited", Json::boolean(target && target->exited)},
        {L"cleanupComplete", Json::boolean(captured.cleanupComplete)},
        {L"stopMarkerWritten", Json::boolean(captured.stopWritten)},
        {L"hooksRemoved", connected ? Json::boolean(hooksRemoved) : Json{}},
        {L"cleanPipeEof", connected ? Json::boolean(cleanPipeEof) : Json{}},
        {L"coverageRevision", connected && target->coverageComplete ? Json::count(target->revision) : Json{}},
        {L"requiredFinalCoverageRevision", hooksRemoved && target->finalRevision ? Json::count(target->finalRevision) : Json{}},
        {L"elapsedMs", Json::count(captured.elapsedMs)},
        {L"readyAfterMs", captured.readyAfterMs ? Json::count(*captured.readyAfterMs) : Json{}},
        {L"readyCoverageRevision", captured.readyCoverageRevision ? Json::count(*captured.readyCoverageRevision) : Json{}},
        {L"intervalElapsedMs", captured.intervalElapsedMs ? Json::count(*captured.intervalElapsedMs) : Json{}},
        {L"invalidPackets", Json::count(captured.invalidPackets)},
        {L"ordinaryPackets", Json::count(run.ordinaryPackets)}, {L"archivedPackets", Json::count(run.archivedPackets)},
        {L"omittedClues", Json::count(run.omittedClues)},
        {L"archiveError", run.archiveStatus ? Json{} : Json::object({
            {L"stage", Json::string(project::ProjectStorage::WideAscii(run.archiveStatus.detail))},
            {L"win32Error", Json::number(run.archiveStatus.nativeError)}})},
        {L"agentReportedDrops", connected ? Json::count(target->agentDropped) : Json{}},
        {L"partialHooks", target ? Json::boolean(target->partialHooks) : Json{}},
        {L"coverageSnapshotCurrent", target ? Json::boolean(target->coverageComplete && !target->coverageStale) : Json{}},
        {L"pipeError", target && target->pipeError ? Json::number(target->pipeError) : Json{}},
        {L"archive", apiArchived ? archiveResult.data : Json{}},
        {L"rules", apiArchived ? CooperativeRulesReport(run.rules) : Json{}},
        {L"apiTransfers", apiArchived ? CooperativeTransfersReport(candidates, 0) : Json{}},
        {L"apiApcTransfers", apiArchived ? CooperativeTransfersReport(candidates, 1) : Json{}},
        {L"apiContextTransfers", apiArchived ? CooperativeTransfersReport(candidates, 2) : Json{}},
        {L"errors", Json::strings(captured.errors)}
    };
    if (!progressDelivery.isNull())
    {
        fields.emplace_back(L"captureProgress", deliveryJson);
    }
    if (etw) {
        // 原生来源回执只含 ASCII 字段和值。封段与检查点错误各自保留本地阶段。
        const auto status = evidence::WriteJson(project::EtwSourceReceipt(etw->source)); // 活采的原生来源快照。
        const auto error = [](const project::ProjectResult& result) {
            return result ? Json{} : Json::object({
                {L"stage", Json::string(project::ProjectStorage::WideAscii(result.detail))},
                {L"win32Error", Json::number(result.nativeError)}});
        };
        fields.emplace_back(L"etw", Json::object({{L"rawStream", Json::string(L"raw-etw")},
            {L"started", Json::boolean(etw->started)}, {L"stopped", Json::boolean(etw->stopped)},
            {L"source", Json{project::ProjectStorage::WideAscii(status), L"ETW"}},
            {L"setupError", error(etw->setup)}, {L"archiveError", error(etw->archiveStatus)},
             {L"checkpointError", error(etw->checkpointStatus)},
             {L"segmentOrdinal", Json::count(etw->segmentOrdinal)},
             {L"archivedObservations", Json::count(etw->archivedObservations)},
             {L"finalSegment", Json::boolean(etw->finalSegment)},
            {L"verified", Json::boolean(etw->archiveStatus && etw->checkpointStatus && etw->raw.flushed)}}));
    }
    return {code, Json::object(fields), std::move(archiveResult.diagnostics)};
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
    project::ApiFollowArchiveKind kind; // 首探测只分派格式，实际读取仍需逐段校验。
    const auto probe = project::ProbeApiFollowArchive(document, id, kind);
    if (probe && kind == project::ApiFollowArchiveKind::Checkpointed) {
        if (auto result = ReplayCooperative(document, id, after, limit, args.has(L"--packet"))) {
            return std::move(*result);
        }
    }
    return Replay(document, id, after, limit, args.has(L"--packet"));
}

} // namespace

Result RunAttachedApiEvidence(const Args& args)
{
    return CaptureEvidence(args, true);
}

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

    Command capture; // 合作目标的真实管道和项目归档入口。
    capture.path = L"analyze api-evidence capture";
    capture.syntax = L"KswordCLI.exe analyze api-evidence capture --project PATH --title TITLE --pid PID --creation-filetime VALUE --confirm [--auto-transfer] [--network-traffic raw-socket|existing-wfp] [--agent-etw 1] [--duration-ms MS] [--startup-progress 1] [--capture-progress 1] [--json]";
    capture.options = L"Requires an existing project, an explicitly selected cooperative target with the resident product Agent, "
                      L"and its private KSWORD_APIMON_COOPERATIVE_SESSION_V1 directory.";
    capture.summary = L"Collect WinAPI evidence from a cooperative target's resident Agent into a new project sample.";
    capture.notes = L"--duration-ms accepts 1,000–120,000 ms (default 3,000), or 0 to capture until console cancellation or target exit. "
                      L"Startup and cleanup timeouts still apply. Continuous capture never reports completedInterval=true; cancellation or target exit returns partial (6). "
                      L"All verified ordinary calls are committed in bounded segments. "
                     L"API rules from profiles/action_analyze_api_rules.json run on committed segments; "
                     L"the result includes their cumulative count and latest source location. "
                        L"--agent-etw 1 saves lifecycle events to the same sample in raw-etw with an independent checkpoint. With --auto-transfer, target header PIDs join the same ETW source before the handoff ACK; header PIDs remain hints. "
                       L"--network-traffic selects the existing packet source and archives PID hints and retained bytes to raw-network in the same sample. With --auto-transfer, admitted target instances join this source before the handoff ACK and remain in scope after the root exits; packet attribution stays a PID hint. It uses the original writer and does not decrypt HTTPS. "
                      L"--startup-progress 1 writes one JSON line per verified startup stage to stderr; stdout retains the final result. "
                      L"The final startup snapshot retains the last reached stage and its elapsedMs, including failed starts.";
    capture.run = [](const Args& args) { return CaptureEvidence(args, false); };
    capture.notes += L" --capture-progress 1 emits committed API checkpoints, rule explanations, candidate coordinates and live handoff/network/Agent-ETW snapshots to stderr as UTF-8 JSONL, without changing final stdout. Source snapshots are change-only at most every 500 ms, including silent API intervals. Progress uses a bounded non-blocking queue; droppedFrames and outputDrained report delivery separately from capture and recovery. Progress and final rules retain up to 32 recentBehaviors with original coordinates, behaviorMatches and behaviorWindowTruncated; the bounded window is not the complete archive.";
    addCommand(std::move(capture));

    Command launch; // 普通EXE自动创建、入口交接和附加，复用现有采集结果及回放入口。
    launch.path = L"analyze api-evidence launch";
    launch.syntax = L"KswordCLI.exe analyze api-evidence launch --project PATH --title TITLE --exe PATH --confirm [--rva RVA] [--auto-transfer] [--network-traffic raw-socket|existing-wfp] [--agent-etw 1] [--duration-ms MS] [--startup-progress 1] [--capture-progress 1] [--json]";
    launch.summary = L"Launch an AMD64 EXE suspended, hand its entry stop to the product Agent, then archive API calls.";
    launch.options = L"Select an existing project and a plain EXE. Optional nonzero --rva overrides PE AddressOfEntryPoint. No cooperative exports or manually supplied PID are required. Duration: 1,000-120,000 ms (default 3,000), or 0 until cancellation or exit.";
    launch.notes = L"The native owner arms entry DR0 before releasing the creation suspension. At the actual main-thread entry stop, the bootstrap takes one explicit main-thread suspension and detaches the debugger. It releases that suspension only after the real Agent Ready and coverage barrier. TLS and earlier loader execution remain outside this entry-based path. --auto-transfer enables automatic private-range discovery and recursive Agent handoff for the same sample. --network-traffic starts the selected existing packet source before Agent Ready releases the main thread. With --auto-transfer, admitted target instances join the same source before the handoff ACK and remain in scope after the root exits; packet attribution stays a PID hint, without HTTPS decryption. Startup failure terminates only this exact newly created process. --startup-progress 1 emits completed bootstrap and Agent stages to stderr. Replay uses analyze api-evidence replay; saved packet bytes use analyze network-read.";
    launch.notes += L" --agent-etw 1 starts the own Agent lifecycle provider before main-thread release and saves it in raw-etw; automatic handoff adds target header PIDs to that same source before ACK. Header PIDs remain hints.";
    launch.notes += L" --capture-progress 1 emits committed checkpoints, rule explanations, candidate coordinates and live handoff/network/Agent-ETW snapshots through the same bounded stderr queue. Source snapshots are change-only at most every 500 ms, including silent API intervals. Output loss does not block target recovery; final captureProgress reports delivery separately. Progress and final rules retain up to 32 recentBehaviors with original coordinates, behaviorMatches and behaviorWindowTruncated; the bounded window is not the complete archive.";
    launch.run = [](const Args& args) { return CaptureEvidence(args, true, true); };
    addCommand(std::move(launch));

    Command replay; // 只读重开相同采样，可按序号翻页并选读原包。
    replay.path = L"analyze api-evidence replay";
    replay.syntax = L"KswordCLI.exe analyze api-evidence replay --project PATH --sample UUID [--after SEQUENCE] [--limit N] [--packet 1] [--json]";
    replay.options = L"Required: --project and --sample. Optional: --after, --limit (1-100) and --packet 1.";
    replay.summary = L"Read a verified page of archived WinAPI clues.";
    replay.notes = L"Use the returned nextAfter as the next page's --after value. Each row.rule contains classification, optional bilingual behavior and typed observedFields from the verified packet; omitted fields remain uncollected. ruleProfile identifies current and recorded rules; matchesRecordedRules is null when either identity is unavailable. Rule errors do not prevent reading archived packets or observed fields.";
    replay.run = RunReplay;
    addCommand(std::move(replay));
}

} // namespace ks::cli::action_analyze
