#include "../../../KswordCLI/ActionAnalyze/Rules/RuleExpression.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"
#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/BehaviorRuleDraft.h"
#include "../../../KswordCLI/ActionAnalyze/Archive/RawEvidenceArchive.h"
#include "../../../shared/evidence/ApiMonitorClue.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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
bool focusedEightOutput = false; // 定向模式逐项回执，不改变旧套件的输出。

// 出现失败时打印稳定断言名称，计数供调用方检查。
void Check(bool ok, std::string_view name)
{
    ++checks;
    if (!ok) {
        ++failures;
    }
    if (focusedEightOutput) {
        std::cout << (ok ? "PASS " : "FAIL ") << name << '\n';
    } else if (!ok) {
        std::cerr << "FAIL " << name << '\n';
    }
}

// 用 Windows CNG 的一次性 BCryptHash 对实际字节求 SHA-256，输出小写十六进制。失败时返回空串。
std::string Sha256Hex(std::string_view bytes)
{
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0) {
        return {};
    }
    std::array<UCHAR, 32> digest{}; // SHA-256 固定 32 字节，不依赖 SDK 宏。
    const auto status = BCryptHash(algorithm, nullptr, 0,
        reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data())), static_cast<ULONG>(bytes.size()),
        digest.data(), static_cast<ULONG>(digest.size()));
    BCryptCloseAlgorithmProvider(algorithm, 0);
    if (status < 0) {
        return {};
    }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(digest.size() * 2);
    for (const auto byte : digest) {
        result.push_back(hex[byte >> 4]);
        result.push_back(hex[byte & 0x0F]);
    }
    return result;
}

// 以二进制方式写出确切字节，不追加换行或编码标记。
bool WriteAllBytes(const std::filesystem::path& path, std::string_view bytes)
{
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    if (!file) {
        return false;
    }
    file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    file.close();
    return file.good();
}

// 读回落盘字节，用于核对实际写出的内容。
std::string ReadAllBytes(const std::filesystem::path& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        return {};
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// 小写十六进制 SHA-256 文本的形状检查。
bool IsLowerHex64(std::string_view text)
{
    if (text.size() != 64) {
        return false;
    }
    for (const auto character : text) {
        const bool digit = character >= '0' && character <= '9';
        const bool lower = character >= 'a' && character <= 'f';
        if (!digit && !lower) {
            return false;
        }
    }
    return true;
}

// 产品库已正式提供 sourceSha256：身份断言直接访问该字段，不再兼容探测或跳过。
void CheckPresetIdentity(const rule::ApiPresetDatabase& database, std::string_view expected, std::string_view name)
{
    Check(std::string_view(database.sourceSha256) == expected, name);
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
    Truth("arg.flag & true", rule::Truth::Unknown);
    Reject("!arg.n == 1u64", PreparationFailed, rule::PrepareError::TypeMismatch);
    Truth("arg.n == arg.n", rule::Truth::Unknown);
    Reject("arg.n == -1", ExpectedPredicate);
    Reject("arg.n == 1x", InvalidNumber);
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
    Reject("arg.n", ExpectedPredicate, rule::PrepareError::TypeMismatch);
    Reject("arg.n == true", ExpectedU64Operands, rule::PrepareError::TypeMismatch);
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

// 通过生产表达式入口覆盖二进制字面量的准入、求值、非法字符和全宽溢出。
void TestBinaryNumericLiterals()
{
    using enum rule::ExpressionError;
    constexpr rule::FieldSample fields[] = {
        {"arg.n", rule::Quality::Known, std::uint64_t{14}}
    }; // 14 与二进制掩码共同验证数值字段和位运算。
    const auto normal = rule::PreparePredicateExpression(
        "(arg.n & 0b1110u64) == 0b1110u64", Entry, Catalog); // v3 二进制掩码。
    const auto evaluated = normal.error == None ?
        rule::EvaluatePredicate(normal.predicate, Entry, fields) : rule::Evaluation{};
    Check(normal.error == None && normal.predicate.valid() && evaluated.truth == rule::Truth::True &&
        evaluated.fault == rule::EvaluationFault::None, "binary mask parsing and evaluation");
    const auto invalid = rule::PreparePredicateExpression(
        "arg.n == 0b102u64", Entry, Catalog); // 二进制数字出现非法数字时必须拒绝。
    Check(invalid.error == InvalidNumber && !invalid.predicate.valid(), "binary mask invalid digit");
    const auto overflow = rule::PreparePredicateExpression(
        "arg.n == 0b11111111111111111111111111111111111111111111111111111111111111111u64",
        Entry, Catalog); // 65 个 1 超出 u64，不允许截断高位。
    Check(overflow.error == NumericOverflow && !overflow.predicate.valid(), "binary mask u64 overflow");
    const auto legacy = rule::PreparePredicateExpression(
        "arg.n == 0b101u64", Entry, Catalog, "predicate-expr-v2"); // legacy-v2 不开放二进制前缀。
    Check(legacy.error != None && !legacy.predicate.valid(), "legacy-v2 rejects binary mask");
}

// 创建满足生产分类器要求的 WriteFile 返回包；本函数不调用包中声明的目标 API。
apiMonitor::ApiMonitorEventPacket MakeWriteFilePacket(bool succeeded, std::uint32_t status,
    std::wstring_view detail, apiMonitor::EventResultKind resultKind = apiMonitor::EventResultKind::StatusCode)
{
    apiMonitor::ApiMonitorEventPacket packet; // 当前一次 API Monitor 返回观察。
    packet.pid = 41; // 非零进程身份满足协议有效包要求。
    packet.tid = 42; // 非零线程身份保持夹具包完整。
    packet.category = static_cast<std::uint32_t>(apiMonitor::EventCategory::File);
    packet.resultCode = static_cast<std::int32_t>(status); // 与返回值配套的 Win32 状态。
    packet.resultKind = static_cast<std::uint32_t>(resultKind);
    packet.hookKind = static_cast<std::uint32_t>(apiMonitor::HookKind::Strong);
    packet.snapshotIndex = apiMonitor::kApiCallReturnValueMarker;
    packet.sessionIdentity = 43; // 生产读侧要求同一包带稳定采集会话身份。
    packet.hookAddress = succeeded ? 1 : 0; // WriteFile 的 BOOL 返回槽，仅使用低 32 位。
    wcscpy_s(packet.moduleName, L"KernelBase"); // 由生产分类表识别 Win32 包装器模块族。
    wcscpy_s(packet.apiName, L"WriteFile"); // 由生产分类表识别文件写入导出。
    const auto detailLength = std::min(detail.size(), std::size(packet.detailText) - 1); // 保留终止符空间。
    std::copy_n(detail.begin(), detailLength, packet.detailText); // 复制确切详情，不假定视图自带终止符。
    packet.detailText[detailLength] = L'\0'; // 生产读侧按定长包中的首个终止符读取详情。
    return packet;
}

// 直接用部署 profile 的行为谓词评估生产投影，返回本次规则是否确定命中。
bool EvaluateWriteFileRule(const rule::ApiPresetDatabase& database,
    const apiMonitor::ApiMonitorEventPacket& packet, std::string_view ruleId,
    std::optional<std::uint64_t> requested, std::optional<std::uint64_t> transferred)
{
    const auto observed = rule::ReadApiBehaviorObservation(packet); // 生产返回值及详情解析。
    const auto evidence = rule::ReadApiPresetEvidence(packet); // 生产协议证据读取入口。
    if (!observed || !evidence.behavior || observed->succeeded != evidence.behavior->succeeded) {
        return false;
    }
    const auto fields = rule::ProjectApiPresetFields("WriteFile", "file-write", std::nullopt, evidence);
    const rule::ApiPresetDefinition* definition = nullptr; // 部署 profile 中的目标行为规则。
    for (const auto& candidate : database.behaviorRules) {
        if (candidate.description.ruleId == ruleId) {
            definition = &candidate;
            break;
        }
    }
    if (!definition) {
        return false;
    }
    const auto evaluation = rule::EvaluatePredicate(definition->prepared, rule::Phase::Observation, fields);
    bool hasRequested = false; // 投影是否发布请求计数。
    bool hasTransferred = false; // 投影是否发布完成计数。
    std::uint64_t requestedValue = 0; // 生产投影中的请求计数。
    std::uint64_t transferredValue = 0; // 生产投影中的完成计数。
    for (const auto& field : fields) {
        if (field.id == "file.requestedBytes") {
            hasRequested = std::holds_alternative<std::uint64_t>(field.value);
            if (hasRequested) requestedValue = std::get<std::uint64_t>(field.value);
        } else if (field.id == "file.transferredBytes") {
            hasTransferred = std::holds_alternative<std::uint64_t>(field.value);
            if (hasTransferred) transferredValue = std::get<std::uint64_t>(field.value);
        }
    }
    return evaluation.truth == rule::Truth::True && evaluation.fault == rule::EvaluationFault::None &&
        hasRequested == requested.has_value() && hasTransferred == transferred.has_value() &&
        (!requested || requestedValue == *requested) && (!transferred || transferredValue == *transferred);
}

// 覆盖 WriteFile 同步零字节、部分完成、完整完成，以及异步 pending 的未知计数。
void TestWriteFileBehavior(const rule::ApiPresetDatabase& database)
{
    const auto zero = MakeWriteFilePacket(true, ERROR_SUCCESS,
        L"handle=0x123 request=0 transferred=0"); // 同步成功且实际完成零字节。
    Check(EvaluateWriteFileRule(database, zero, "ksword.behavior.file-write-zero-completed.v1", 0, 0),
        "WriteFile synchronous zero transferred");
    const auto partial = MakeWriteFilePacket(true, ERROR_SUCCESS,
        L"handle=0x123 request=16 transferred=7"); // 同步成功但只完成请求的一部分。
    Check(EvaluateWriteFileRule(database, partial, "ksword.behavior.file-write-partial.v1", 16, 7),
        "WriteFile synchronous partial transferred");
    const auto full = MakeWriteFilePacket(true, ERROR_SUCCESS,
        L"handle=0x123 request=16 transferred=16"); // 同步成功且完成计数等于请求计数。
    Check(EvaluateWriteFileRule(database, full, "ksword.behavior.file-write-full.v1", 16, 16),
        "WriteFile synchronous full transferred");
    const auto pending = MakeWriteFilePacket(false, ERROR_IO_PENDING,
        L"handle=0x123 request=16 transferred=unknown"); // ERROR_IO_PENDING 表示异步未知完成计数。
    Check(EvaluateWriteFileRule(database, pending, "ksword.behavior.file-write-pending.v1", std::nullopt, std::nullopt),
        "WriteFile asynchronous ERROR_IO_PENDING unknown count");
}

// 验证质量标记条件、普通比较的 Unknown 和受限解释器的诊断。
void TestQualityConditions()
{
    using enum rule::Truth;
    const auto states = R"(quality(arg.text) == "truncated" || quality(arg.text) == "redacted")"sv;
    constexpr rule::FieldSample truncated[] = {{"arg.text", rule::Quality::Truncated, "prefix"sv}};
    constexpr rule::FieldSample redacted[] = {{"arg.text", rule::Quality::Redacted, {}}};
    constexpr rule::FieldSample nullText[] = {{"arg.text", rule::Quality::Null, {}}};
    constexpr rule::FieldSample emptyText[] = {{"arg.text", rule::Quality::Known, ""sv}};
    Truth(states, True, truncated);
    Truth(states, True, redacted);
    Truth(states, False);
    Truth(R"(quality(arg.text) == "notCollected" && !isKnown(arg.text))", True);
    Truth(R"(quality(arg.text) != "known" && isNull(arg.text) && isComplete(arg.text))", True, nullText);
    Truth("isKnown(arg.text)", False, nullText);
    Truth(R"(isKnown(arg.text) && arg.text == "")", True, emptyText);
    Truth(R"(quality(arg.text) == "redacted" && !(arg.text == "anything"))", Unknown, redacted);
    Truth(R"(quality(arg.text) == "truncated" && !Text.Contains(arg.text, "absent"))", Unknown, truncated);

    using enum rule::ExpressionError;
    Reject("quality(arg.text)", ExpectedQualityComparison);
    Reject(R"(quality(arg.text) < "known")", ExpectedQualityComparison);
    Reject(R"(!quality(arg.text) == "known")", ExpectedQualityComparison);
    Reject(R"(quality(arg.text) == "NotCollected")", InvalidQuality);
    Reject(R"(quality(arg.text) == arg.text)", ExpectedLiteral);
    Reject(R"(true || quality(result.ok) == "known")", PreparationFailed, rule::PrepareError::FieldNotInPhase);
    Reject(R"(true || quality(newField) == "known")", PreparationFailed, rule::PrepareError::UnknownField);
    Reject(R"(System.IO.File.ReadAllText(arg.text))", UnsupportedCall);

    // 非法状态的位置按 UTF-8 字节计算，并覆盖该状态的整个字面量。
    const auto source = "Text.Equals(arg.text, \"汉\") || quality(arg.text) == \"坏值\""sv;
    const auto invalid = rule::PreparePredicateExpression(source, Entry, Catalog);
    const auto invalidState = "\"坏值\""sv;
    Check(invalid.error == InvalidQuality && invalid.location.offset == source.find(invalidState) &&
        invalid.location.length == invalidState.size() && invalid.location.line == 1 &&
        invalid.location.byteColumn == invalid.location.offset + 1, "invalid quality UTF-8 location");

    // 质量条件仍使用统一字段检查和计费。耗尽不能产生确定命中。
    const auto prepared = rule::PreparePredicateExpression(states, Entry, Catalog);
    const auto limited = rule::EvaluatePredicate(prepared.predicate, Entry, truncated, 1);
    Check(limited.truth == Unknown && limited.fault == rule::EvaluationFault::Budget && limited.workUsed <= 1,
        "quality evaluation budget");
    constexpr rule::FieldSample malformed[] = {{"arg.text", rule::Quality::Redacted, "unexpected bytes"sv}};
    const auto shape = rule::EvaluatePredicate(prepared.predicate, Entry, malformed);
    Check(shape.truth == Unknown && shape.fault == rule::EvaluationFault::InvalidInput, "quality field shape validation");
}

// 走生产离线 Replay。使用已获前缀作为正证据，缺值标记只作为明确选择的锚点。
void TestQualityReplay()
{
    const auto step = rule::PreparePredicateExpression(
        R"(quality(arg.text) == "truncated" && Text.StartsWith(arg.text, "prefix"))", Entry, Catalog);
    const auto anchor = rule::PreparePredicateExpression(R"(quality(arg.text) == "notCollected")", Entry, Catalog);
    Check(step.error == rule::ExpressionError::None && anchor.error == rule::ExpressionError::None,
        "quality replay predicates prepared");
    constexpr rule::FieldSample truncated[] = {{"arg.text", rule::Quality::Truncated, "prefix partial"sv}};
    constexpr rule::FieldSample complete[] = {{"arg.text", rule::Quality::Known, "prefix complete"sv}};
    const rule::ReplayEvent events[] = {
        {"sample", 1, "source", "epoch", 11, "thread", rule::EventTime{"clock", 10}, "test", Entry, truncated},
        {"sample", 2, "source", "epoch", 12, "thread", rule::EventTime{"clock", 20}, "test", Entry, complete},
        {"sample", 3, "source", "epoch", 13, "thread", rule::EventTime{"clock", 30}, "test", Entry, {}},
    }; // 第一条可进入证据列表，第二条只满足前缀条件，第三条是锚点。
    const rule::ReplaySnapshot snapshot{"run", {"sample", "source", "epoch", "thread", "clock"}, 3, {}, true};
    const rule::ReplayRule request{rule::ReplayKind::CountAtLeast, {"test", &step.predicate},
        {"test", &anchor.predicate}, 30, 1}; // 无覆盖凭证，确定证据只可支持下界。
    const auto replay = rule::Replay(snapshot, request, events);
    Check(replay.error == rule::ReplayError::None && replay.windows.size() == 1, "quality replay anchor selection");
    if (replay.windows.size() == 1) {
        const auto& window = replay.windows.front(); // 保留可核对的原事件坐标与覆盖缺口。
        Check(window.truth == rule::Truth::True && window.anchorOrdinal == 3 &&
            window.stepOrdinals == std::vector<std::uint64_t>{1} &&
            rule::HasIssue(window.issues, rule::ReplayIssue::Coverage), "quality replay evidence and incomplete coverage");
    }
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

// 规则身份契约由下面的独立用例覆盖，共用同一个固定夹具文件。
void TestPresetIdentity(const std::filesystem::path& path);

// 预置覆盖五类归档线索。队列顺序和两套证据编号必须保持原值。
void TestPresetFile(const std::filesystem::path& scratch)
{
    const auto path = scratch / "test-api-presets.json";
    if (std::filesystem::exists(path)) {
        Check(false, "preset fixture file already exists");
        return;
    }
    const auto missing = rule::LoadApiPresetDatabase(path);
    Check(missing.error == "rules-profile-unavailable" && missing.presetSet.empty(), "missing preset file");

    {
        std::ofstream file(path, std::ios::binary);
        file << '{';
        file.close();
        Check(file.good(), "write malformed preset file");
    }
    const auto malformed = rule::LoadApiPresetDatabase(path);
    Check(malformed.error.starts_with("rules-profile-json/") && malformed.profiles[0].empty(), "malformed preset file");

    const auto writePreset = [&path](std::string_view version, std::string_view summaryZh) {
        std::ofstream file(path, std::ios::binary | std::ios::trunc);
        file << R"({"schemaVersion":1,"presetSet":")" << version << R"(","profiles":{
            "grouped":[{"ruleId":"test.group","predicate":"true","summary":"Group"}],
            "by-category":[{"ruleId":"test.category","predicate":"true","summary":"Category"}]},
            "behaviorRules":[{"ruleId":"test.behavior","predicate":"!result.returned",
              "summary":"Fixture result","summaryZh":")" << summaryZh << R"("}]})";
        file.close();
        Check(file.good(), "write valid preset file");
    };
    writePreset("test.v1", "旧释义");
    const auto first = rule::LoadApiPresetDatabase(path);
    writePreset("test.v2", "新释义");
    const auto second = rule::LoadApiPresetDatabase(path);
    Check(std::filesystem::remove(path), "remove preset fixture file");
    Check(first.error.empty() && first.presetSet == "test.v1" && second.error.empty() && second.presetSet == "test.v2",
        "new profile load reads replacement version");

    const rule::ArchivedApiObservation row{17, 23, "WriteProcessMemory", "memory-write",
        rule::ArchivedApiMemoryWriteReturn{false, ERROR_ACCESS_DENIED}};
    const auto checkMatch = [&row](const rule::ApiPresetDatabase& database, std::string_view summaryZh) {
        const auto report = rule::AnalyzeVerifiedApiPresetPage(database, std::span(&row, 1), 1);
        Check(report.error == rule::ApiPresetError::None && report.matches.size() == 1 &&
            report.matches.front().behavior && report.matches.front().behavior->summaryZh == summaryZh &&
            report.matches.front().rawSequence == 17 && report.matches.front().sourceSequence == 23,
            "preset snapshot keeps its own summary and evidence coordinate");
    };
    checkMatch(first, "旧释义");
    checkMatch(second, "新释义");
    TestPresetIdentity(path); // 身份契约复用同一固定夹具文件。
}

// 规则身份契约：同一 presetSet 的不同释义、同一字节重载、仅外部空白、失败为空与旧对象冻结。
// 三个测试向量的摘要常量由 PowerShell 的 .NET SHA256 独立预先计算，夹具不复用产品实现。
void TestPresetIdentity(const std::filesystem::path& path)
{
    constexpr std::string_view base = R"JSON({"schemaVersion":1,"presetSet":"test.v1","profiles":{"grouped":[{"ruleId":"test.group","predicate":"true","summary":"Group"}],"by-category":[{"ruleId":"test.category","predicate":"true","summary":"Category"}]},"behaviorRules":[{"ruleId":"test.behavior","predicate":"!result.returned","summary":"Fixture result","summaryZh":"old-summary"}]})JSON";
    constexpr std::string_view revised = R"JSON({"schemaVersion":1,"presetSet":"test.v1","profiles":{"grouped":[{"ruleId":"test.group","predicate":"true","summary":"Group"}],"by-category":[{"ruleId":"test.category","predicate":"true","summary":"Category"}]},"behaviorRules":[{"ruleId":"test.behavior","predicate":"!result.returned","summary":"Fixture result","summaryZh":"new-summary"}]})JSON";
    constexpr std::string_view badHeader = R"JSON({"schemaVersion":2,"presetSet":"test.v1","profiles":{"grouped":[{"ruleId":"test.group","predicate":"true","summary":"Group"}],"by-category":[{"ruleId":"test.category","predicate":"true","summary":"Category"}]},"behaviorRules":[{"ruleId":"test.behavior","predicate":"!result.returned","summary":"Fixture result","summaryZh":"old-summary"}]})JSON";
    constexpr std::string_view badPredicate = R"JSON({"schemaVersion":1,"presetSet":"test.v1","profiles":{"grouped":[{"ruleId":"test.group","predicate":"true","summary":"Group"}],"by-category":[{"ruleId":"test.category","predicate":"true","summary":"Category"}]},"behaviorRules":[{"ruleId":"test.behavior","predicate":"true &&","summary":"Fixture result","summaryZh":"old-summary"}]})JSON";
    constexpr std::string_view baseDigest = "c554271721e6882e242951cd02e543517cfd44feff2b4f30574927569a24c8cf"sv;
    constexpr std::string_view revisedDigest = "3fcdaed50e333d84bc1b26f3d4ec502963fcd5a0e44a53fe8fd9dfd9780240b2"sv;
    constexpr std::string_view spacedDigest = "26ddee915e7cb21ef95f64a64c958f3f07ffa2f66f0e66a1f4870823b0b25657"sv;
    const std::string spaced = "\n" + std::string(base) + "\n"; // 只在 JSON 文档外部增加空白。

    Check(base.size() == 339 && revised.size() == 339 && spaced.size() == 341, "identity vector sizes");
    Check(Sha256Hex(base) == baseDigest, "identity vector base digest");
    Check(Sha256Hex(revised) == revisedDigest, "identity vector revised digest");
    Check(Sha256Hex(spaced) == spacedDigest, "identity vector spaced digest");
    Check(baseDigest != revisedDigest && baseDigest != spacedDigest, "identity vectors differ by bytes");

    Check(WriteAllBytes(path, base), "write identity base file");
    Check(ReadAllBytes(path) == base, "identity base file keeps the exact bytes");
    Check(Sha256Hex(ReadAllBytes(path)) == baseDigest, "identity digest of the written bytes");
    const auto first = rule::LoadApiPresetDatabase(path);
    Check(first.error.empty() && first.presetSet == "test.v1", "identity base load");
    CheckPresetIdentity(first, baseDigest, "identity base matches the independent digest");
    Check(IsLowerHex64(first.sourceSha256), "identity base is lower-case hex");

    const auto firstAgain = rule::LoadApiPresetDatabase(path); // 同一字节再次加载。
    Check(firstAgain.error.empty() && firstAgain.presetSet == "test.v1", "identity reload of identical bytes");
    CheckPresetIdentity(firstAgain, baseDigest, "identity is stable for identical bytes");
    CheckPresetIdentity(first, baseDigest, "identity of the first object stays frozen");

    Check(WriteAllBytes(path, revised), "write identity revised file");
    const auto second = rule::LoadApiPresetDatabase(path); // 同一 presetSet 只改释义。
    Check(second.error.empty() && second.presetSet == "test.v1", "identity revised load keeps the preset set");
    CheckPresetIdentity(second, revisedDigest, "identity revised matches the independent digest");
    CheckPresetIdentity(first, baseDigest, "identity of the first object survives the overwrite");

    const rule::ArchivedApiObservation row{17, 23, "WriteProcessMemory", "memory-write",
        rule::ArchivedApiMemoryWriteReturn{false, ERROR_ACCESS_DENIED}};
    const auto summaryOf = [&row](const rule::ApiPresetDatabase& database) {
        const auto report = rule::AnalyzeVerifiedApiPresetPage(database, std::span(&row, 1), 1);
        if (report.error != rule::ApiPresetError::None || report.matches.size() != 1 ||
            !report.matches.front().behavior) {
            return std::string{};
        }
        return report.matches.front().behavior->summaryZh;
    };
    Check(summaryOf(first) == "old-summary", "frozen object keeps its own summary");
    Check(summaryOf(second) == "new-summary", "revised object exposes the new summary");

    Check(WriteAllBytes(path, spaced), "write identity spaced file");
    const auto third = rule::LoadApiPresetDatabase(path); // 仅外部空白变化。
    Check(third.error.empty() && third.presetSet == "test.v1", "identity spaced load still parses");
    CheckPresetIdentity(third, spacedDigest, "identity spaced matches the independent digest");
    Check(summaryOf(third) == "old-summary", "spaced object keeps the same rules");

    Check(std::filesystem::remove(path), "remove identity fixture file");
    CheckPresetIdentity(first, baseDigest, "identity survives the file removal");
    Check(summaryOf(first) == "old-summary", "frozen rules survive the file removal");

    const auto missing = rule::LoadApiPresetDatabase(path); // 文件已删除。
    Check(missing.error == "rules-profile-unavailable" && missing.presetSet.empty(), "identity missing file error");
    CheckPresetIdentity(missing, ""sv, "identity missing file stays empty");
    Check(missing.profiles[0].empty() && missing.profiles[1].empty() && missing.behaviorRules.empty(),
        "identity missing file has no partial rules");

    Check(WriteAllBytes(path, "{"), "write malformed identity file");
    const auto malformed = rule::LoadApiPresetDatabase(path);
    Check(malformed.error.starts_with("rules-profile-json/") && malformed.presetSet.empty(), "identity malformed json error");
    CheckPresetIdentity(malformed, ""sv, "identity malformed json stays empty");
    Check(malformed.profiles[0].empty() && malformed.profiles[1].empty() && malformed.behaviorRules.empty(),
        "identity malformed json has no partial rules");

    Check(WriteAllBytes(path, badHeader), "write invalid header identity file");
    const auto invalidHeader = rule::LoadApiPresetDatabase(path);
    Check(invalidHeader.error == "rules-profile-invalid-header" && invalidHeader.presetSet.empty(),
        "identity invalid header error");
    CheckPresetIdentity(invalidHeader, ""sv, "identity invalid header stays empty");
    Check(invalidHeader.profiles[0].empty() && invalidHeader.profiles[1].empty() &&
        invalidHeader.behaviorRules.empty(), "identity invalid header has no partial rules");

    Check(WriteAllBytes(path, badPredicate), "write invalid predicate identity file");
    const auto invalidPredicate = rule::LoadApiPresetDatabase(path);
    Check(invalidPredicate.error == "rules-profile-invalid-predicate/test.behavior/expression-expected-predicate",
        "identity invalid predicate error");
    CheckPresetIdentity(invalidPredicate, ""sv, "identity invalid predicate stays empty");
    Check(invalidPredicate.profiles[0].empty() && invalidPredicate.profiles[1].empty() &&
        invalidPredicate.behaviorRules.empty(), "identity invalid predicate has no partial rules");
    Check(std::filesystem::remove(path), "remove identity fixture file after failures");
}

void TestPresets(const rule::ApiPresetDatabase& database)
{
    constexpr rule::ArchivedApiObservation rows[] = { // 模拟已验证的最近五条 Stored 记录。
        {10, 31, "WriteProcessMemory", "memory-write"},
        {11, 35, "NtMapViewOfSection", "section-map"},
        {12, 36, "CreateRemoteThreadEx", "thread-create"},
        {13, 41, "SetThreadContext", "thread-context"},
        {14, 43, "QueueUserAPC", "apc-queue"},
    };
    const auto report = rule::AnalyzeArchivedApiPresets(database, rows, 14); // 尾记总量大于分析窗口。
    Check(report.error == rule::ApiPresetError::None && report.importedRows == 14 &&
        report.analyzedRows == 5 && report.matches.size() == 5, "preset suffix and hit count");
    for (std::size_t index = 0; index < report.matches.size() && index < std::size(rows); ++index) {
        const auto& hit = report.matches[index]; // 由编译后的预置判定产生。
        const auto& row = rows[index]; // 用于核对来源字段的输入记录。
        const auto id = index < 2 ? "ksword.api.memory-operation-observed.v1"
            : "ksword.api.thread-control-observed.v1"; // 不同类别的预置 ID。
        Check(hit.ruleId == id && hit.rawSequence == row.rawSequence && hit.sourceSequence == row.sourceSequence &&
            hit.api == row.api && !hit.behavior, "preset evidence identity without return evidence");
    }

    const auto empty = rule::AnalyzeArchivedApiPresets(database, {}, 0); // 已验证尾记的有效空采样。
    Check(empty.error == rule::ApiPresetError::None && empty.matches.empty(), "preset empty import");
    const auto missing = rule::AnalyzeArchivedApiPresets(database, {}, 1); // 尾记和实际投影矛盾。
    Check(missing.error == rule::ApiPresetError::InvalidInput, "preset missing projection");
    const auto wrongTail = rule::AnalyzeArchivedApiPresets(database, rows, 15); // 输入并非实际最近窗口。
    Check(wrongTail.error == rule::ApiPresetError::InvalidInput && wrongTail.matches.empty(), "preset wrong raw cutoff");
    rule::ArchivedApiObservation broken[] = {rows[0], rows[1]}; // 构建一批已命中后才失败的输入。
    broken[1].sourceSequence = broken[0].sourceSequence;
    const auto ambiguous = rule::AnalyzeArchivedApiPresets(database, broken, 11); // 旧命中不得进入失败回执。
    Check(ambiguous.error == rule::ApiPresetError::InvalidInput && ambiguous.matches.empty(), "preset duplicate source identity");
    broken[1] = rows[1];
    broken[1].family = "unknown-family";
    const auto unknown = rule::AnalyzeArchivedApiPresets(database, broken, 11); // 未登记分类显示为输入失败。
    Check(unknown.error == rule::ApiPresetError::InvalidInput && unknown.matches.empty(), "preset unknown family");

    // 新的细分预置保留相同顺序和证据坐标，每条记录仍只匹配一次。
    const auto detailed = rule::AnalyzeArchivedApiPresets(database, rows, 14, rule::ApiPresetProfile::ByCategory);
    constexpr std::string_view ids[] = {
        "ksword.api.memory-write-observed.v1", "ksword.api.section-map-observed.v1",
        "ksword.api.thread-create-observed.v1", "ksword.api.thread-context-observed.v1",
        "ksword.api.apc-queue-observed.v1",
    };
    Check(detailed.error == rule::ApiPresetError::None && detailed.importedRows == 14 &&
        detailed.analyzedRows == 5 && detailed.matches.size() == std::size(rows), "category preset bounded window");
    for (std::size_t i = 0; i < detailed.matches.size() && i < std::size(rows); ++i) {
        const auto& hit = detailed.matches[i]; // 细分类别回执的同一条原始观测。
        Check(hit.ruleId == ids[i] && hit.rawSequence == rows[i].rawSequence &&
            hit.sourceSequence == rows[i].sourceSequence && hit.api == rows[i].api, "category preset evidence identity");
    }
    const auto detailedInvalid = rule::AnalyzeArchivedApiPresets(database, broken, 11, rule::ApiPresetProfile::ByCategory);
    Check(detailedInvalid.error == rule::ApiPresetError::InvalidInput && detailedInvalid.matches.empty(),
        "category preset invalid projection discards prior hits");
}

// 仅构造离线协议包，不执行包中的 API，也不访问注册表或其它进程。
void TestBehaviorPreset(const rule::ApiPresetDatabase& database)
{
    apiMonitor::ApiMonitorEventPacket denied;
    denied.category = static_cast<std::uint32_t>(apiMonitor::EventCategory::Memory);
    denied.snapshotIndex = apiMonitor::kApiCallReturnValueMarker;
    denied.resultCode = static_cast<std::int32_t>(ERROR_ACCESS_DENIED);
    wcscpy_s(denied.moduleName, L"KernelBase");
    wcscpy_s(denied.apiName, L"WriteProcessMemory");

    const auto verify = [&database](const apiMonitor::ApiMonitorEventPacket& packet, bool hasReturn, bool hasBehavior,
        std::string_view name) {
        const auto returned = evidence::ReadApiMonitorMemoryWriteReturn(packet);
        Check(returned.has_value() == hasReturn, name);
        rule::ArchivedApiObservation row{17, 23, "WriteProcessMemory", "memory-write"};
        if (returned) {
            row.memoryWriteReturn = rule::ArchivedApiMemoryWriteReturn{returned->returned, returned->statusCode};
        }
        for (const auto profile : {rule::ApiPresetProfile::Grouped, rule::ApiPresetProfile::ByCategory}) {
            const auto report = rule::AnalyzeVerifiedApiPresetPage(database, std::span(&row, 1), 31, profile);
            Check(report.error == rule::ApiPresetError::None && report.matches.size() == 1, name);
            if (report.matches.size() == 1) {
                const auto& hit = report.matches.front();
                Check(hit.rawSequence == 17 && hit.sourceSequence == 23 && hit.behavior.has_value() == hasBehavior, name);
                if (hit.behavior) {
                    Check(hit.behavior->ruleId == "ksword.behavior.memory-write-access-denied-return.v1" &&
                        hit.behavior->evidence == "reported-api-return", name);
                }
            }
        }
    };
    verify(denied, true, true, "behavior: explicit FALSE and access denied");
    auto other = denied;
    other.resultCode = static_cast<std::int32_t>(ERROR_INVALID_HANDLE);
    verify(other, true, false, "behavior: other failure is not access denied");
    other = denied;
    other.hookAddress = TRUE;
    verify(other, true, false, "behavior: nonzero BOOL cannot be an access denial");
    other = denied;
    other.snapshotIndex = 0;
    wcscpy_s(other.detailText, L"return=FALSE status=ERROR_ACCESS_DENIED");
    verify(other, false, false, "behavior: summary text and status do not replace return marker");
    other = denied;
    other.resultKind = static_cast<std::uint32_t>(apiMonitor::EventResultKind::EntryOnly);
    verify(other, false, false, "behavior: entry observation has no return");
    other.resultKind = static_cast<std::uint32_t>(apiMonitor::EventResultKind::StatusUnknown);
    verify(other, false, false, "behavior: unknown status cannot establish access denial");
    other = denied;
    other.hookKind = static_cast<std::uint32_t>(apiMonitor::HookKind::Fake);
    verify(other, false, false, "behavior: simulated return is not an original call result");
    other = denied;
    other.hookAddress = 1ULL << 32;
    verify(other, false, false, "behavior: malformed BOOL return bits");
    other = denied;
    wcscpy_s(other.moduleName, L"fixture.dll");
    verify(other, false, false, "behavior: wrong module cannot supply return evidence");

    const rule::ArchivedApiObservation native{17, 23, "NtWriteVirtualMemory", "memory-write",
        rule::ArchivedApiMemoryWriteReturn{false, ERROR_ACCESS_DENIED}};
    const auto mismatched = rule::AnalyzeVerifiedApiPresetPage(database, std::span(&native, 1), 31);
    Check(mismatched.error == rule::ApiPresetError::None && mismatched.matches.size() == 1 &&
        !mismatched.matches.front().behavior, "behavior: Win32 return evidence cannot label a native memory write");

    other = denied;
    other.category = static_cast<std::uint32_t>(apiMonitor::EventCategory::Registry);
    wcscpy_s(other.moduleName, L"Advapi32");
    wcscpy_s(other.apiName, L"RegQueryValueExW");
    wcscpy_s(other.detailText, L"value=KSwordFixtureMarker");
    Check(!evidence::ClassifyApiMonitorClue(other), "behavior: registry summary is not structured environment evidence");
    Check(!evidence::ReadApiMonitorMemoryWriteReturn(other), "behavior: registry summary supplies no write return evidence");
}

// 用生产 Stored 读写器和原包校验器重开实际文件，再把已验证观测交给预置规则。
void TestStoredPreset(const rule::ApiPresetDatabase& database, const std::filesystem::path& scratch, bool withEnd)
{
    const auto path = scratch / (withEnd ? L"preset-complete.ksaseg" : L"preset-no-end.ksaseg"); // 固定夹具文件。
    archive::SegmentHeader header{{archive::StreamKind::Raw, 1, {0x11}, {0x22}}, 1}; // 隔离的合成身份。
    apiMonitor::ApiMonitorEventPacket packet; // 构造固定原包数据，不执行归档记录中的 API。
    packet.pid = 41;
    packet.tid = 42;
    packet.sessionIdentity = 43;
    packet.category = static_cast<std::uint32_t>(apiMonitor::EventCategory::Memory);
    packet.snapshotIndex = apiMonitor::kApiCallReturnValueMarker;
    packet.resultCode = static_cast<std::int32_t>(ERROR_ACCESS_DENIED);
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

    struct ScanOutcome {
        bool boundaryVerified = false; // Stored 封装边界是否与写端回执一致。
        bool ended = false; // 是否见到合法导入尾记。
        std::uint64_t clues = 0; // 已核对的线索总数。
        std::vector<rule::ArchivedApiObservation> observed; // 原包字段及两套身份坐标。
    };
    const auto scan = [&]() {
        evidence::ApiMonitorClueReadback readback; // 产品使用的原始归档线索与尾记校验。
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
                    // 本夹具只有一个固定包；名字必须是静态存储，不能用离开作用域即销毁的局部 string。
                    constexpr std::string_view api = "WriteProcessMemory";
                    rule::ArchivedApiObservation row{record.recordSequence, clue->sourceSequence, api, clue->clue->family};
                    if (const auto returned = evidence::ReadApiMonitorMemoryWriteReturn(clue->packet)) {
                        row.memoryWriteReturn = rule::ArchivedApiMemoryWriteReturn{returned->returned, returned->statusCode};
                    }
                    observed.push_back(row);
                }
            }
            return true;
        };
        const auto checked = archive::ScanOpenRawEvidence(file.value, header.identity, std::nullopt, 0, visitor);
        ScanOutcome outcome;
        outcome.boundaryVerified = checked.VerifiedBoundary(*finished.flushed);
        outcome.ended = readback.ended;
        outcome.clues = readback.clues;
        outcome.observed = std::move(observed);
        return outcome;
    };

    const auto first = scan();
    Check(first.boundaryVerified && first.ended == withEnd && first.observed.size() == 1,
        "validate Stored framing and independent API import tail");
    if (first.ended && first.boundaryVerified) {
        const auto result = rule::AnalyzeArchivedApiPresets(database, first.observed, first.clues); // 同一个类型化预置入口。
        Check(result.error == rule::ApiPresetError::None && result.matches.size() == 1 &&
            result.matches.front().rawSequence == 1 && result.matches.front().sourceSequence == 7 &&
            result.matches.front().api == "WriteProcessMemory", "Stored preset evidence receipt");
        const auto detailed = rule::AnalyzeArchivedApiPresets(database, first.observed, first.clues, rule::ApiPresetProfile::ByCategory);
        Check(detailed.error == rule::ApiPresetError::None && detailed.matches.size() == 1 &&
            detailed.matches.front().ruleId == "ksword.api.memory-write-observed.v1" &&
            detailed.matches.front().rawSequence == 1 && detailed.matches.front().sourceSequence == 7 &&
            detailed.matches.front().behavior &&
            detailed.matches.front().behavior->ruleId == "ksword.behavior.memory-write-access-denied-return.v1" &&
            detailed.matches.front().behavior->evidence == "reported-api-return",
            "Stored category and behavior share the original evidence coordinate");

        // 错误规则数据库必须拒绝同一原包，且不改变已归档字节与边界。
        const auto broken = rule::LoadApiPresetDatabase(scratch / L"absent-rule-profile.json");
        Check(broken.error == "rules-profile-unavailable" && broken.profiles[0].empty() &&
            broken.profiles[1].empty() && broken.behaviorRules.empty(), "Stored preset error database");
        CheckPresetIdentity(broken, ""sv, "error database keeps an empty identity");
        const auto rejected = rule::AnalyzeArchivedApiPresets(broken, first.observed, first.clues);
        Check(rejected.error == rule::ApiPresetError::InvalidPreset && rejected.matches.empty(),
            "Stored preset rejects an error rule database");

        const auto again = scan(); // 归档必须仍可读，边界与原始字节不变。
        Check(again.boundaryVerified && again.ended == withEnd && again.clues == first.clues &&
            again.observed.size() == 1 && again.observed.front().rawSequence == 1 &&
            again.observed.front().sourceSequence == 7 && again.observed.front().api == "WriteProcessMemory",
            "Stored boundary and raw bytes stay readable after the rejected analysis");
    }
}

// 产品已部署规则配置的身份：产品报告值必须等于该文件原始字节的摘要。
void TestDeployedProfileIdentity(const rule::ApiPresetDatabase& database)
{
    std::wstring image(32768, L'\0'); // 当前进程映像绝对路径。
    const auto length = GetModuleFileNameW(nullptr, image.data(), static_cast<DWORD>(image.size()));
    if (!length || length >= image.size()) {
        Check(false, "deployed profile image path");
        return;
    }
    image.resize(length);
    const auto profile = std::filesystem::path(image).parent_path() / L"profiles" / L"action_analyze_api_rules.json";
    const auto bytes = ReadAllBytes(profile);
    Check(!bytes.empty(), "deployed profile bytes are readable");
    Check(Sha256Hex(bytes) == database.sourceSha256, "deployed profile identity matches the file digest");
}
} // namespace

// 运行无窗口夹具。失败向命令行返回非零。
int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring_view(argv[2]) == L"--focused-eight") {
        focusedEightOutput = true;
        TestBinaryNumericLiterals();
        const auto database = rule::LoadApiPresetDatabase();
        if (!database.error.empty()) {
            std::cerr << "API preset load failed: " << database.error << '\n';
        }
        std::cout << "FocusedEightProfileSha256=" << database.sourceSha256 << '\n';
        TestWriteFileBehavior(database);
        const int exitCode = failures == 0 && database.error.empty() && checks == 8 ? 0 : 1;
        std::cout << "ActionAnalyze focused eight: " << checks << " checks, " << failures << " failures\n";
        std::cout << "FocusedEightFixtureExitCode=" << exitCode << '\n';
        return exitCode;
    }
    const bool evidenceOnly = argc == 3 && std::wstring_view(argv[2]) == L"--offline-evidence-only";
    if (argc != 2 && !evidenceOnly) {
        std::cerr << "Expected the dedicated fixture IntDir and optional --offline-evidence-only.\n";
        return 2;
    }
    if (!evidenceOnly) {
        TestEvaluation();
        TestRejection();
        TestBinaryNumericLiterals();
        TestDraft();
    }
    TestQualityConditions();
    TestQualityReplay();
    const auto database = rule::LoadApiPresetDatabase(); // 本次离线断言共用同一份已装载的规则。
    if (!database.error.empty()) {
        std::cerr << "API preset load failed: " << database.error << '\n';
        return 1;
    }
    TestPresets(database);
    TestBehaviorPreset(database);
    TestWriteFileBehavior(database);
    TestPresetFile(argv[1]);
    TestDeployedProfileIdentity(database);
    TestStoredPreset(database, argv[1], true);
    TestStoredPreset(database, argv[1], false);
    std::cout << "ActionAnalyze preset identity contract: active\n";
    std::cout << "ActionAnalyze rule expression: " << checks << " checks, " << failures << " failures\n";
    return failures == 0 ? 0 : 1;
}
