#include "../../../KswordCLI/ActionAnalyze/Rules/RuleExpression.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"
#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/BehaviorRuleDraft.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/RawEvidenceArchive.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

#include <iostream>
#include <limits>

namespace {
namespace rule = Ksword::ActionAnalyze::Rules;
namespace archive = ks::cli::action_analyze::archive;
namespace evidence = Ksword::Evidence;
namespace apiMonitor = ks::winapi_monitor;
using namespace std::literals;

constexpr auto Entry = rule::Phase::Entry; // 入口字段只来自已冻结的入参。
constexpr auto Return = rule::Phase::Return; // 返回字段在入口阶段不可用。
constexpr rule::FieldBinding Catalog[] = {
    {"arg.flag", rule::FieldType::Bool, Entry},
    {"arg.n", rule::FieldType::U64, Entry},
    {"arg.text", rule::FieldType::Text, Entry},
    {"result.ok", rule::FieldType::Bool, Return}
};
std::size_t checks = 0; // 总断言数。
std::size_t failures = 0; // 失败后继续报告剩余断言。

// 出现失败时打印稳定断言名称，计数供调用方检查。
void Check(bool ok, std::string_view name)
{
    ++checks;
    if (!ok) {
        ++failures;
        std::cerr << "FAIL " << name << '\n';
    }
}

// 用真实生产解释器运行已准备的谓词。返回值包含真假未知以及独立故障。
void Truth(std::string_view source, rule::Truth expected,
    std::span<const rule::FieldSample> fields = {}, rule::Phase phase = Entry)
{
    const auto prepared = rule::PreparePredicateExpression(source, phase, Catalog); // 此断言的类型化谓词。
    Check(prepared.error == rule::ExpressionError::None && prepared.predicate.valid(), source);
    const auto evaluated = rule::EvaluatePredicate(prepared.predicate, phase, fields); // 实际解释器回执。
    Check(evaluated.truth == expected && evaluated.fault == rule::EvaluationFault::None, source);
}

// 不可用表达式必须留下诊断，并且不暴露可执行的部分树。
void Reject(std::string_view source, rule::ExpressionError error,
    rule::PrepareError preparation = rule::PrepareError::None)
{
    const auto rejected = rule::PreparePredicateExpression(source, Entry, Catalog); // 拒绝回执。
    Check(rejected.error == error && rejected.preparationError == preparation &&
        !rejected.predicate.valid() && !rule::ExpressionErrorId(rejected.error).empty() &&
        rejected.location.offset + rejected.location.length <= source.size(), source);
}

// 覆盖比较、结合、短路和真实类型绑定。
void TestEvaluation()
{
    using enum rule::Truth;
    constexpr rule::FieldSample fields[] = { // 解释器按 ID 顺序读取输入。
        {"arg.flag", rule::Quality::Known, false},
        {"arg.n", rule::Quality::Known, (std::numeric_limits<std::uint64_t>::max)()},
        {"arg.text", rule::Quality::Known, "文件\0🐱"sv}
    };
    Truth("true || false && false", True);
    Truth("(true || false) && false", False);
    Truth("!!true && !false && !(false || false)", True);
    Truth("!arg.flag && arg.flag == false && arg.flag != true", True, fields);
    Truth("arg.n == 18446744073709551615u64 && arg.n >= 0xFFFFFFFFFFFFFFFFu64", True, fields);
    Truth("arg.n > 1u64 && arg.n < 0xFFFFFFFFFFFFFFFFu64", False, fields);
    Truth("arg.n <= 0xffffffffffffffffu64 && arg.n != 0u64", True, fields);
    Truth(R"(arg.text == "\u6587件\0\uD83D\uDC31")", True, fields);
    Truth(R"(Text.Contains(arg.text, "\U0001F431") && Text.StartsWith(arg.text, "文件"))", True, fields);
    Truth(R"(Text.EndsWith(arg.text, "\u0000🐱"))", True, fields);
    Truth("arg.flag == null || isNull(arg.flag)", False, fields);
    Truth("!arg.flag", Unknown);
    Truth("arg.flag || true", True);
    Truth("arg.flag && false", False);
    Truth("arg.flag || false", Unknown);
    Truth("arg.flag && true", Unknown);
    Truth("!isNull(arg.text) && !isComplete(arg.text)", True);
    Truth("arg.text == null", Unknown);
    Truth("result.ok", Unknown, {}, Return);

    constexpr rule::FieldSample nullText[] = {{"arg.text", rule::Quality::Null, {}}};
    Truth("arg.text == null && isNull(arg.text) && isComplete(arg.text)", True, nullText);
    constexpr rule::FieldSample partial[] = {{"arg.text", rule::Quality::Truncated, "prefix"sv}};
    Truth(R"(!Text.Contains(arg.text, "absent"))", Unknown, partial);
    Truth(R"(Text.StartsWith(arg.text, "pre") && !isComplete(arg.text))", True, partial);
    Truth(R"(Text.EndsWith(arg.text, "fix"))", Unknown, partial);
    Truth(R"(Text.Equals(arg.text, "prefix"))", Unknown, partial);

    constexpr rule::FieldSample escaped[] = { // 路径和双引号按原始字符保存。
        {"arg.text", rule::Quality::Known, R"(C:\data""file)"sv}
    };
    Truth(R"(arg.text == @"C:\data""""file")", True, escaped);
    Truth(R"(arg.text == "C:\\data\"\"file")", True, escaped);
}

// 覆盖未知阶段、类型错误、标记边界和不可执行构造。
void TestRejection()
{
    using enum rule::ExpressionError;
    Reject("", ExpectedPredicate);
    Reject("(true", ExpectedCloseParen);
    Reject("true &&", ExpectedPredicate);
    Reject("true false", UnexpectedToken);
    Reject("true; false", UnexpectedToken);
    Reject("arg.flag = false", UnexpectedToken);
    Reject("arg.flag & true", UnexpectedToken);
    Reject("!arg.n == 1u64", UnexpectedToken);
    Reject("arg.n == arg.n", ExpectedLiteral);
    Reject("arg.n == -1", ExpectedLiteral);
    Reject("arg.n == 1", InvalidNumber);
    Reject("arg.n == 0xu64", InvalidNumber);
    Reject("arg.n == 1u64extra", InvalidNumber);
    Reject("arg.n == 18446744073709551616u64", NumericOverflow);
    Reject("arg.n == 0x10000000000000000u64", NumericOverflow);
    Reject("Text.Contains(arg.text \"foo\")", ExpectedComma);
    Reject("File.ReadAllText(arg.text)", UnsupportedCall);
    Reject("Text.Contains(arg.text, $\"{arg.text}\")", ExpectedLiteral);
    Reject("isNull(false)", InvalidFieldPath);
    Reject("arg..flag", InvalidFieldPath);
    Reject(R"(arg.text == "\q")", UnsupportedEscape);
    Reject(R"(arg.text == "\uD83D")", InvalidString);
    Reject(R"(arg.text == "\U00110000")", InvalidString);
    Reject("arg.text == \"\xed\xa0\x80\"", PreparationFailed, rule::PrepareError::InvalidUtf8);
    Reject("true || missing", PreparationFailed, rule::PrepareError::UnknownField);
    Reject("false && result.ok", PreparationFailed, rule::PrepareError::FieldNotInPhase);
    Reject("arg.n", PreparationFailed, rule::PrepareError::TypeMismatch);
    Reject("arg.n == true", PreparationFailed, rule::PrepareError::TypeMismatch);
    Reject("Text.Equals(arg.flag, \"a\")", PreparationFailed, rule::PrepareError::TypeMismatch);
    Reject(std::string(rule::MaxPredicateExpressionBytes + 1, ' '), TextLimit);
    Reject(std::string(33, '(') + "true" + std::string(33, ')'), NestingLimit);

    std::string conjunction = "true"; // 左结合树超过类型化 AST 的深度上限。
    for (std::size_t i = 0; i < 32; ++i) {
        conjunction += " && true";
    }
    Reject(conjunction, PreparationFailed, rule::PrepareError::DepthLimit);
    for (std::size_t i = 0; i < 224; ++i) {
        conjunction += " && true";
    }
    Reject(conjunction, NodeLimit);

    constexpr auto source = "Text.Equals(arg.text, \"汉\") ||\r\n result.ok"sv; // UTF-8 位置与 CRLF 检查。
    const auto invalid = rule::PreparePredicateExpression(source, Entry, Catalog); // 阶段错误应定位字段本身。
    Check(invalid.location.offset == source.find("result.ok") && invalid.location.length == 9 &&
        invalid.location.line == 2 && invalid.location.byteColumn == 2, "phase diagnostic location");
}

// 走真实 Qt 页使用的纯 C++ 草稿检查入口，并比较旧版草稿与新版表达式的结果。
void TestDraft()
{
    using namespace ks::action_analyze;
    const auto expression = BehaviorRuleExample(); // 内置页面的数据源，包含三个合成事件。
    const auto validated = CheckBehaviorRuleDraft(expression, false); // 与「校验规则」相同。
    Check(validated.error.empty() && validated.eventCount == 3 && !validated.replay, "draft validate");
    const auto replayed = CheckBehaviorRuleDraft(expression, true); // 与「回放合成事件」相同。
    Check(replayed.error.empty() && replayed.replay && replayed.replay->windows.size() == 3, "draft replay");
    if (replayed.replay && replayed.replay->windows.size() == 3) {
        const auto& hit = replayed.replay->windows[1]; // 观察到同窗口的两条确定证据。
        Check(hit.truth == rule::Truth::True && hit.anchorOrdinal == 1 &&
            hit.stepOrdinals == std::vector<std::uint64_t>{0, 1}, "draft replay hit evidence");
    }
    constexpr auto exprValue = R"QV("(source.headerPid == 42u64 && !isNull(source.headerPid)) || source.headerPid == 0x2au64")QV"sv;
    const auto offset = expression.find(exprValue); // 此处只替换一个谓词值，保留相同输入事件。
    Check(offset != std::string_view::npos, "draft default expression retained");
    if (offset == std::string_view::npos) {
        return;
    }
    auto oldDraft = std::string(expression); // 旧版本对象谓词。
    oldDraft.replace(offset, exprValue.size(), R"({"field":"source.headerPid","operator":"eq","value":"42"})");
    const auto oldReport = CheckBehaviorRuleDraft(oldDraft, true); // 旧草稿实际执行结果。
    Check(oldReport.error.empty() && oldReport.replay && replayed.replay &&
        oldReport.replay->windows.size() == replayed.replay->windows.size(), "old JSON draft replay");
    if (oldReport.replay && replayed.replay && oldReport.replay->windows.size() == replayed.replay->windows.size()) {
        for (std::size_t i = 0; i < oldReport.replay->windows.size(); ++i) {
            const auto& before = oldReport.replay->windows[i]; // 旧结构的逐窗口结果。
            const auto& after = replayed.replay->windows[i]; // 表达式的同一窗口结果。
            Check(before.truth == after.truth && before.stepOrdinals == after.stepOrdinals &&
                before.issues == after.issues, "draft compatibility, including missing field");
        }
    }
    auto invalidDraft = std::string(expression); // 含 JSON 转义换行与未知字段的草稿。
    invalidDraft.replace(offset, exprValue.size(), R"("true ||\n missing.field")");
    const auto invalid = CheckBehaviorRuleDraft(invalidDraft, true); // JSON Pointer 加上内部谓词位置。
    Check(invalid.error == "unknown-field" && invalid.pointer == "/step/predicate" && !invalid.offset &&
        invalid.expressionLocation && invalid.expressionLocation->line == 2 &&
        invalid.expressionLocation->byteColumn == 2 && !invalid.replay, "draft expression offset and no replay");
}

// 预置覆盖五类归档线索。队列顺序和两套证据编号必须保持原值。
void TestPresets()
{
    constexpr rule::ArchivedApiObservation rows[] = { // 模拟已验证的最近五条 Stored 记录。
        {10, 31, "WriteProcessMemory", "memory-write"},
        {11, 35, "NtMapViewOfSection", "section-map"},
        {12, 36, "CreateRemoteThreadEx", "thread-create"},
        {13, 41, "SetThreadContext", "thread-context"},
        {14, 43, "QueueUserAPC", "apc-queue"},
    };
    const auto report = rule::AnalyzeArchivedApiPresets(rows, 14); // 尾记总量大于分析窗口。
    Check(report.error == rule::ApiPresetError::None && report.importedRows == 14 &&
        report.analyzedRows == 5 && report.matches.size() == 5, "preset suffix and hit count");
    for (std::size_t index = 0; index < report.matches.size() && index < std::size(rows); ++index) {
        const auto& hit = report.matches[index]; // 由编译后的预置判定产生。
        const auto& row = rows[index]; // 用于核对来源字段的输入记录。
        const auto id = index < 2 ? "ksword.api.memory-operation-observed.v1"
            : "ksword.api.thread-control-observed.v1"; // 不同类别的预置 ID。
        Check(hit.ruleId == id && hit.rawSequence == row.rawSequence && hit.sourceSequence == row.sourceSequence &&
            hit.api == row.api, "preset evidence identity");
    }

    const auto empty = rule::AnalyzeArchivedApiPresets({}, 0); // 已验证尾记的有效空采样。
    Check(empty.error == rule::ApiPresetError::None && empty.matches.empty(), "preset empty import");
    const auto missing = rule::AnalyzeArchivedApiPresets({}, 1); // 尾记和实际投影矛盾。
    Check(missing.error == rule::ApiPresetError::InvalidInput, "preset missing projection");
    const auto wrongTail = rule::AnalyzeArchivedApiPresets(rows, 15); // 输入并非实际最近窗口。
    Check(wrongTail.error == rule::ApiPresetError::InvalidInput && wrongTail.matches.empty(), "preset wrong raw cutoff");
    rule::ArchivedApiObservation broken[] = {rows[0], rows[1]}; // 构建一批已命中后才失败的输入。
    broken[1].sourceSequence = broken[0].sourceSequence;
    const auto ambiguous = rule::AnalyzeArchivedApiPresets(broken, 11); // 旧命中不得进入失败回执。
    Check(ambiguous.error == rule::ApiPresetError::InvalidInput && ambiguous.matches.empty(), "preset duplicate source identity");
    broken[1] = rows[1];
    broken[1].family = "unknown-family";
    const auto unknown = rule::AnalyzeArchivedApiPresets(broken, 11); // 未登记分类显示为输入失败。
    Check(unknown.error == rule::ApiPresetError::InvalidInput && unknown.matches.empty(), "preset unknown family");
}

// 用生产 Stored 读写器和原包校验器重开实际文件，再把已验证观测交给预置规则。
void TestStoredPreset(const std::filesystem::path& scratch, bool withEnd)
{
    const auto path = scratch / (withEnd ? L"preset-complete.ksaseg" : L"preset-no-end.ksaseg"); // 固定夹具文件。
    archive::SegmentHeader header{{archive::StreamKind::Raw, 1, {0x11}, {0x22}}, 1}; // 隔离的合成身份。
    apiMonitor::ApiMonitorEventPacket packet; // 构造固定原包数据，不执行归档记录中的 API。
    packet.pid = 41;
    packet.tid = 42;
    packet.sessionIdentity = 43;
    packet.category = static_cast<std::uint32_t>(apiMonitor::EventCategory::Memory);
    wcscpy_s(packet.moduleName, L"kernelbase.dll");
    wcscpy_s(packet.apiName, L"WriteProcessMemory");
    const archive::RawEvidenceInput inputs[] = {
        {R"({"kind":"api-monitor-clue-v1","sourceSequence":"7"})", {reinterpret_cast<const char*>(&packet), sizeof(packet)}},
        {R"({"kind":"api-monitor-clue-import-end-v1","sourceRows":"9","clueRows":"1"})", {}},
    };
    archive::RawEvidenceArchive writer(path, header); // CREATE_NEW 避免覆盖任何已有文件。
    const auto added = writer.Append(std::span(inputs, withEnd ? 2u : 1u)); // 分别生成有和无有效尾记的合法 Stored 段。
    const auto finished = writer.Finish(); // 真实刷盘回执。
    Check(added.result.status == archive::SegmentWriteStatus::Ok && finished.flushed.has_value(), "write Stored preset input");
    if (!finished.flushed) {
        return;
    }

    struct File {
        HANDLE value; // 测试读取期间独占原句柄的生命周期。
        ~File() { if (value != INVALID_HANDLE_VALUE) CloseHandle(value); }
    } file{CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr)};
    Check(file.value != INVALID_HANDLE_VALUE, "open Stored preset input read-only");
    if (file.value == INVALID_HANDLE_VALUE) {
        return;
    }

    evidence::ApiMonitorClueReadback readback; // 产品使用的原始归档线索与尾记校验。
    std::string api; // 持有本夹具唯一观测的 UTF-8 导出名。
    std::vector<rule::ArchivedApiObservation> observed; // 原包字段及两套身份坐标。
    const auto visitor = [&](const archive::SegmentIdentity&, const archive::BlockInfo&,
        const std::vector<archive::DecodedRecord>& records) {
        for (const auto& record : records) {
            const auto* raw = std::get_if<archive::RawRecordV1>(&record.body); // 共享 Stored 解封的记录正文。
            if (!raw) {
                return false;
            }
            const auto metadata = evidence::ParseJson(raw->metadataJson); // 真实的严格 JSON 解码。
            std::optional<evidence::ArchivedApiMonitorClue> clue; // 合法尾记没有线索。
            if (!metadata.ok() || !readback.Accept(metadata.value, raw->inlineRawData, clue)) {
                return false;
            }
            if (clue) {
                for (const auto ch : clue->clue->api) { // 生产分类表仅含 ASCII 导出名。
                    api.push_back(static_cast<char>(ch));
                }
                observed.push_back({record.recordSequence, clue->sourceSequence, api, clue->clue->family});
            }
        }
        return true;
    };
    const auto checked = archive::ScanOpenRawEvidence(file.value, header.identity, std::nullopt, 0, visitor);
    Check(checked.VerifiedBoundary(*finished.flushed) && readback.ended == withEnd && observed.size() == 1,
        "validate Stored framing and independent API import tail");
    if (readback.ended && checked.VerifiedBoundary(*finished.flushed)) {
        const auto result = rule::AnalyzeArchivedApiPresets(observed, readback.clues); // 同一个类型化预置入口。
        Check(result.error == rule::ApiPresetError::None && result.matches.size() == 1 &&
            result.matches.front().rawSequence == 1 && result.matches.front().sourceSequence == 7 &&
            result.matches.front().api == "WriteProcessMemory", "Stored preset evidence receipt");
    }
}
} // namespace

// 运行无窗口夹具。失败向命令行返回非零。
int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) {
        std::cerr << "Expected the dedicated fixture IntDir.\n";
        return 2;
    }
    TestEvaluation();
    TestRejection();
    TestDraft();
    TestPresets();
    TestStoredPreset(argv[1], true);
    TestStoredPreset(argv[1], false);
    std::cout << "ActionAnalyze rule expression: " << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
