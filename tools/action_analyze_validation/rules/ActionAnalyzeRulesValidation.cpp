#include "../../../KswordCLI/ActionAnalyze/Rules/AnalysisRun.h"

#include <algorithm>
#include <array>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <source_location>
#include <stdexcept>
#include <utility>

using namespace Ksword::ActionAnalyze::Rules;

namespace {

// 固定夹具只使用本地声明字段和自己构造的投影记录。
constexpr auto Obs = Phase::Observation;
const std::array catalog{FieldBinding{"flag", FieldType::Bool, Obs},
                         FieldBinding{"length", FieldType::U64, Obs},
                         FieldBinding{"note", FieldType::Text, Obs},
                         FieldBinding{"result", FieldType::U64, Phase::Return}};
std::size_t checks = 0;

// 失败输出用例、源位置并终止，Release 也不关闭断言。
void Check(bool condition, const char* name, std::source_location loc = std::source_location::current())
{
    ++checks;
    if (!condition) {
        std::cerr << loc.line() << ": " << name << '\n';
        throw std::runtime_error("ActionAnalyze rule check failed");
    }
}

PreparedPredicate Prepare(std::initializer_list<AstNode> nodes)
{
    auto result = PreparePredicate(Obs, catalog, {nodes.begin(), nodes.size()});
    Check(result.error == PrepareError::None && result.predicate.valid(), "fixture preparation");
    return result.predicate;
}

// 用缺字段构造 U，对所有 AND／OR 组合和 NOT 使用独立期望表。
void TruthTables()
{
    constexpr Truth F = Truth::False;
    constexpr Truth T = Truth::True;
    constexpr Truth U = Truth::Unknown;
    const std::array<AstNode, 3> atoms{false, true, FieldTest{FieldOp::Equal, "flag", true}};
    constexpr Truth andTable[3][3] = {{F, F, F}, {F, T, U}, {F, U, U}};
    constexpr Truth orTable[3][3] = {{F, T, U}, {T, T, T}, {U, T, U}};
    constexpr Truth notTable[3] = {T, F, U};
    for (std::size_t i = 0; i < atoms.size(); ++i) {
        Check(EvaluatePredicate(Prepare({atoms[i], Not{0}}), Obs, {}).truth == notTable[i], "NOT table");
        for (std::size_t j = 0; j < atoms.size(); ++j) {
            Check(EvaluatePredicate(Prepare({atoms[i], atoms[j], Logical{Logic::And, 0, 1}}), Obs, {}).truth
                  == andTable[i][j], "AND table");
            Check(EvaluatePredicate(Prepare({atoms[i], atoms[j], Logical{Logic::Or, 0, 1}}), Obs, {}).truth
                  == orTable[i][j], "OR table");
        }
    }
    const std::array wrongType{FieldSample{"flag", Quality::Known, std::uint64_t{0}}};
    const auto shortCircuit = Prepare({true, atoms[2], Logical{Logic::Or, 0, 1}});
    Check(EvaluatePredicate(shortCircuit, Obs, wrongType).fault == EvaluationFault::None, "left short circuit");
    const auto faultRead = Prepare({atoms[2], true, Logical{Logic::Or, 0, 1}});
    const auto invalid = EvaluatePredicate(faultRead, Obs, wrongType);
    Check(invalid.truth == U && invalid.fault == EvaluationFault::InvalidInput, "input errors stay distinguishable");
}

// 验证看似无害但语义未定义的 AST 不会产生可执行谓词。
void BadPreparation()
{
    const auto reject = [](std::initializer_list<AstNode> nodes, PrepareError expected) {
        const auto result = PreparePredicate(Obs, catalog, {nodes.begin(), nodes.size()});
        Check(result.error == expected && !result.predicate.valid(), "invalid AST rejected");
    };
    reject({false, FieldTest{FieldOp::Equal, "unknown", true}, Logical{Logic::And, 0, 1}}, PrepareError::UnknownField);
    reject({FieldTest{FieldOp::Equal, "result", std::uint64_t{0}}}, PrepareError::FieldNotInPhase);
    reject({FieldTest{FieldOp::Equal, "length", false}}, PrepareError::TypeMismatch);
    reject({FieldTest{FieldOp::Contains, "length", std::string("0")}}, PrepareError::TypeMismatch);
    reject({FieldTest{static_cast<FieldOp>(255), "length", std::uint64_t{0}}}, PrepareError::UnsupportedOperator);
    reject({FieldTest{FieldOp::Equal, "note", std::string("\xed\xa0\x80")}}, PrepareError::InvalidUtf8);
    reject({FieldTest{FieldOp::Equal, "note", std::string(8193, 'a')}}, PrepareError::LiteralLimit);
    reject({true, true}, PrepareError::InvalidTree);
    reject({true, Logical{Logic::And, 0, 0}}, PrepareError::InvalidTree);
    reject({Not{0}}, PrepareError::InvalidTree);
    std::vector<AstNode> deep{false};
    for (std::size_t i = 0; i < 32; ++i) {
        deep.emplace_back(Not{i});
    }
    Check(PreparePredicate(Obs, catalog, deep).error == PrepareError::DepthLimit, "tree depth");
    const std::vector<AstNode> wide(513, true);
    Check(PreparePredicate(Obs, catalog, wide).error == PrepareError::NodeLimit, "node bound");
    const std::array entry{AstNode{FieldTest{FieldOp::Equal, "result", std::uint64_t{0}}}};
    Check(PreparePredicate(Phase::Entry, catalog, entry).error == PrepareError::FieldNotInPhase, "entry blocks return value");
}

// 比较测试保留空值、u64 边界、NUL 及截断文本的可证明结论。
void Values()
{
    const auto checkText = [](FieldOp op, std::string pattern, Quality quality, std::string_view text, Truth expected) {
        const auto predicate = Prepare({FieldTest{op, "note", std::move(pattern)}});
        const std::array row{FieldSample{"note", quality, text}};
        Check(EvaluatePredicate(predicate, Obs, row).truth == expected, "text truth");
    };
    checkText(FieldOp::Contains, "c", Quality::Truncated, "abc", Truth::True);
    checkText(FieldOp::Contains, "z", Quality::Truncated, "abc", Truth::Unknown);
    checkText(FieldOp::StartsWith, "abc", Quality::Truncated, "ab", Truth::Unknown);
    checkText(FieldOp::StartsWith, "ab", Quality::Truncated, "abc", Truth::True);
    checkText(FieldOp::StartsWith, "ax", Quality::Truncated, "abc", Truth::False);
    checkText(FieldOp::EndsWith, "c", Quality::Truncated, "abc", Truth::Unknown);
    checkText(FieldOp::Equal, "abc", Quality::Truncated, "abc", Truth::Unknown);
    checkText(FieldOp::Equal, "abc", Quality::Truncated, "abd", Truth::False);
    checkText(FieldOp::Equal, "ab", Quality::Truncated, "abc", Truth::False);
    checkText(FieldOp::Equal, "", Quality::Known, "", Truth::True);
    checkText(FieldOp::Equal, "ABC", Quality::Known, "abc", Truth::False);
    checkText(FieldOp::Contains, std::string("\0b", 2), Quality::Known, std::string_view("a\0bc", 4), Truth::True);
    checkText(FieldOp::Equal, "\xe4\xb8\xad", Quality::Known, "\xe4\xb8\xad", Truth::True);

    const auto negated = Prepare({FieldTest{FieldOp::Contains, "note", std::string("z")}, Not{0}});
    const std::array prefix{FieldSample{"note", Quality::Truncated, std::string_view("abc")}};
    Check(EvaluatePredicate(negated, Obs, prefix).truth == Truth::Unknown, "negated truncated non-match");
    const std::array malformed{FieldSample{"note", Quality::Known, std::string_view("\xff")}};
    const auto decoded = EvaluatePredicate(negated, Obs, malformed);
    Check(decoded.truth == Truth::Unknown && decoded.fault == EvaluationFault::InvalidInput, "bad UTF-8 stays unknown");
    const auto expensive = Prepare({FieldTest{FieldOp::Contains, "note", std::string(71, 'z')}});
    const std::string longText(2000, 'a');
    const std::array longRow{FieldSample{"note", Quality::Known, std::string_view(longText)}};
    const auto exhausted = EvaluatePredicate(expensive, Obs, longRow);
    Check(exhausted.truth == Truth::Unknown && exhausted.fault == EvaluationFault::Budget, "text work budget");

    const auto isNull = Prepare({FieldTest{FieldOp::IsNull, "length", {}}});
    const auto isComplete = Prepare({FieldTest{FieldOp::IsComplete, "length", {}}});
    const auto eqNull = Prepare({FieldTest{FieldOp::Equal, "length", {}}});
    const auto eqZero = Prepare({FieldTest{FieldOp::Equal, "length", std::uint64_t{0}}});
    const std::array nullRow{FieldSample{"length", Quality::Null, {}}};
    const std::array zeroRow{FieldSample{"length", Quality::Known, std::uint64_t{0}}};
    Check(EvaluatePredicate(isNull, Obs, {}).truth == Truth::False, "missing is not null");
    Check(EvaluatePredicate(isComplete, Obs, nullRow).truth == Truth::True, "complete null");
    Check(EvaluatePredicate(eqNull, Obs, {}).truth == Truth::Unknown, "unknown null equality");
    Check(EvaluatePredicate(eqNull, Obs, nullRow).truth == Truth::True, "known null equality");
    Check(EvaluatePredicate(eqNull, Obs, zeroRow).truth == Truth::False, "zero differs from null");
    Check(EvaluatePredicate(eqZero, Obs, zeroRow).truth == Truth::True, "known zero");
    const auto eqFalse = Prepare({FieldTest{FieldOp::Equal, "flag", false}});
    const std::array falseRow{FieldSample{"flag", Quality::Known, false}};
    Check(EvaluatePredicate(eqFalse, Obs, falseRow).truth == Truth::True, "known false is a normal value");
    const std::array duplicatedField{falseRow[0], falseRow[0]};
    Check(EvaluatePredicate(eqFalse, Obs, duplicatedField).fault == EvaluationFault::InvalidInput, "duplicate field rejected");
    const auto geMax = Prepare({FieldTest{FieldOp::GreaterEqual, "length", (std::numeric_limits<std::uint64_t>::max)()}});
    const std::array maximum{FieldSample{"length", Quality::Known, (std::numeric_limits<std::uint64_t>::max)()}};
    Check(EvaluatePredicate(geMax, Obs, maximum).truth == Truth::True, "u64 maximum stays exact");
    Check(EvaluatePredicate(eqZero, Phase::Entry, zeroRow).fault == EvaluationFault::InvalidInput, "evaluation phase mismatch");

    for (auto quality : {Quality::NotCollected, Quality::AccessDenied, Quality::Unsupported, Quality::ReadFailed,
                         Quality::Truncated, Quality::DecodeFailed, Quality::Redacted}) {
        const std::array missing{FieldSample{"length", quality, {}}};
        Check(EvaluatePredicate(eqZero, Obs, missing).truth == Truth::Unknown, "unavailable is distinct from zero");
        Check(EvaluatePredicate(isComplete, Obs, missing).truth == Truth::False, "unavailable is incomplete");
    }
}

// 测试 ID 故意可读。适配器负责真实强实例与覆盖凭证的来源。
constexpr ReplayScope scope{"sample", "adapter", "epoch", "thread-generation-1", "source-clock"};

ReplayEvent Event(std::uint64_t ordinal, std::optional<std::uint64_t> sequence, std::uint64_t time,
                  std::string_view type, std::span<const FieldSample> fields = {})
{
    return {scope.sampleId, ordinal, scope.sourceId, scope.sourceEpoch, sequence,
            scope.strongActorThreadId, EventTime{scope.clockId, time}, type, Obs, fields};
}

// 检查迟到只影响固定 cutoff 以后的新运行，原运行的证据引用保留。
void CountAndWatermarks()
{
    const auto detector = Prepare({FieldTest{FieldOp::GreaterEqual, "length", std::uint64_t{1}}});
    const auto all = Prepare({true});
    const std::array positive{FieldSample{"length", Quality::Known, std::uint64_t{1}}};
    const auto anchor = Event(5, 3, 130, "anchor");
    const auto late = Event(6, 1, 100, "step", positive);
    const auto old = Event(2, 0, 99, "step", positive);
    ReplaySnapshot snapshot{"run-1", scope, 5, std::nullopt, true};
    const ReplayRule absence{ReplayKind::CountEqual, {"step", &detector}, {"anchor", &all}, 30, 0};
    const std::array rows{late, anchor, old};
    const auto unproven = Replay(snapshot, absence, rows);
    Check(unproven.windows.size() == 1 && unproven.windows[0].truth == Truth::Unknown &&
          HasIssue(unproven.windows[0].issues, ReplayIssue::Coverage), "archive cutoff does not prove absence");
    Check(HasIssue(Replay(snapshot, absence, {}).issues, ReplayIssue::Coverage), "empty unproven run");
    snapshot.coverage = VerifiedCoverage{scope, 5, 100, 129};
    Check(Replay(snapshot, absence, rows).windows.at(0).truth == Truth::Unknown, "event-time watermark must reach anchor");
    snapshot.coverage->through100ns = 130;
    snapshot.coverage->from100ns = 101;
    Check(Replay(snapshot, absence, rows).windows.at(0).truth == Truth::Unknown, "window start requires coverage");
    snapshot.coverage->from100ns = 100;
    const auto first = Replay(snapshot, absence, rows);
    Check(first.windows.at(0).truth == Truth::True && first.windows[0].stepOrdinals.empty(), "proved absence at old cutoff");
    Check(first.windows[0].range && first.windows[0].range->start100ns == 100 && first.windows[0].range->end100ns == 130,
          "explicit closed replay window");
    snapshot.analysisRunId = "run-2";
    snapshot.archiveThroughOrdinal = 6;
    Check(Replay(snapshot, absence, rows).error == ReplayError::InvalidRequest, "coverage cannot move cutoff");
    snapshot.coverage->archiveThroughOrdinal = 6;
    const auto revised = Replay(snapshot, absence, rows);
    Check(revised.analysisRunId != first.analysisRunId && revised.windows.at(0).truth == Truth::False &&
          revised.windows[0].stepOrdinals == std::vector<std::uint64_t>{6}, "late evidence in distinct run at inclusive boundary");
    Check(first.archiveThroughOrdinal == 5 && first.windows[0].truth == Truth::True, "old result remains intact");

    const ReplayRule lowerBound{ReplayKind::CountAtLeast, {"step", &detector}, {"step", &detector}, 0, 1};
    snapshot.coverage.reset();
    const std::array duplicate{late, late};
    const auto lower = Replay(snapshot, lowerBound, duplicate);
    Check(lower.duplicateEvents == 1 && lower.windows.size() == 1 && lower.windows[0].truth == Truth::True &&
          lower.windows[0].stepOrdinals == std::vector<std::uint64_t>{6} && HasIssue(lower.issues, ReplayIssue::Coverage),
          "known lower bound includes anchor once and retains incomplete coverage");
    auto conflict = late;
    conflict.time->ticks100ns = 101;
    const auto invalid = Replay(snapshot, absence, std::array{late, conflict});
    Check(invalid.error == ReplayError::ConflictingEventId && invalid.windows.empty(), "same ID different facts fails run");
    auto foreign = late;
    foreign.sampleId = "other-sample";
    Check(Replay(snapshot, absence, std::array{foreign}).error == ReplayError::InvalidEvent, "foreign sample rejected");
    const std::array zeroTime{Event(0, 0, 0, "step", positive)};
    const ReplayRule zeroWindow{ReplayKind::CountEqual, lowerBound.step, lowerBound.anchor, 30, 1};
    snapshot.coverage = VerifiedCoverage{scope, 6, 0, 0};
    Check(Replay(snapshot, zeroWindow, zeroTime).windows.at(0).truth == Truth::True, "zero clock and ordinal are valid");
}

// 只允许一个强线程、一个源 epoch。排序用源序号，展示仍按归档 ordinal。
void SequencesAndLimits()
{
    const auto all = Prepare({true});
    const ReplayRule sequence{ReplayKind::Sequence, {"first", &all}, {"last", &all}, 30};
    ReplaySnapshot snapshot{"run-s", scope, 9, VerifiedCoverage{scope, 9, 100, 130}, true};
    const auto last = Event(1, 9, 130, "last");
    const auto first = Event(4, 0, 100, "first");
    const auto second = Event(5, 1, 130, "first");
    auto reused = Event(6, 2, 100, "first");
    reused.strongActorThreadId = "thread-generation-2";
    auto otherEpoch = Event(7, 3, 100, "first");
    otherEpoch.sourceEpoch = "other-epoch";
    auto wrongPhase = Event(8, 4, 100, "first");
    wrongPhase.phase = Phase::Entry;
    auto rows = std::array{second, reused, last, otherEpoch, first, second};
    const auto result = Replay(snapshot, sequence, rows);
    Check(result.duplicateEvents == 1 && result.windows.at(0).truth == Truth::True &&
          result.windows[0].stepOrdinals == std::vector<std::uint64_t>{4, 5}, "all ordered same-thread matches");
    std::reverse(rows.begin(), rows.end());
    const auto reordered = Replay(snapshot, sequence, rows);
    Check(reordered.windows.at(0).stepOrdinals == result.windows[0].stepOrdinals, "immutable replay independent of input delivery order");
    Check(Replay(snapshot, sequence, std::array{last, reused, otherEpoch, wrongPhase}).windows.at(0).truth == Truth::False,
          "TID reuse, epoch mismatch and phase mismatch do not match");
    const auto secondAnchor = Event(2, 10, 130, "last");
    const auto shared = Replay(snapshot, sequence, std::array{last, secondAnchor, first});
    Check(shared.windows.size() == 2 && shared.windows[0].stepOrdinals == std::vector<std::uint64_t>{4} &&
          shared.windows[1].stepOrdinals == shared.windows[0].stepOrdinals, "step can match multiple anchors");

    auto weak = first;
    weak.strongActorThreadId = {};
    auto wrongClock = second;
    wrongClock.time->clockId = "unrelated";
    auto noOrder = Event(8, std::nullopt, 102, "first");
    auto equalOrder = Event(9, 9, 102, "first");
    const auto unknown = Replay(snapshot, sequence, std::array{last, weak, wrongClock, noOrder, equalOrder});
    Check(unknown.windows.at(0).truth == Truth::Unknown && unknown.windows[0].stepOrdinals.empty() &&
          HasIssue(unknown.issues, ReplayIssue::ActorThread) && HasIssue(unknown.issues, ReplayIssue::Clock) &&
          HasIssue(unknown.issues, ReplayIssue::Order), "weak identity, clock and unstated order remain unknown");
    Check(Replay(snapshot, sequence, std::array{last, equalOrder}).windows.at(0).truth == Truth::Unknown,
          "shared publication cannot prove order");
    Check(Replay(snapshot, sequence, std::array{last, Event(2, 10, 129, "first")}).windows.at(0).truth == Truth::False,
          "source order rules out reverse sequence");
    snapshot.orderedSourceSequence = false;
    Check(Replay(snapshot, sequence, rows).windows.at(0).truth == Truth::Unknown, "order needs recorded source guarantee");
    snapshot.orderedSourceSequence = true;

    ReplayBudget budget;
    budget.maxWindowCandidates = 1;
    const auto truncated = Replay(snapshot, sequence, rows, budget);
    Check(truncated.windows.at(0).truth == Truth::True && truncated.windows[0].stepOrdinals.size() == 1 &&
          HasIssue(truncated.issues, ReplayIssue::WindowLimit), "known sequence survives window state limit");
    const auto exact = ReplayRule{ReplayKind::CountEqual, sequence.step, sequence.anchor, 30, 1};
    Check(Replay(snapshot, exact, rows, budget).windows.at(0).truth == Truth::Unknown, "limited count cannot claim exactness");
    budget.maxWorkUnits = 1;
    const auto exhausted = Replay(snapshot, exact, rows, budget);
    Check(exhausted.windows.at(0).truth == Truth::Unknown && HasIssue(exhausted.issues, ReplayIssue::Budget),
          "replay work budget never produces absence");
    budget.maxInputEvents = 1;
    Check(Replay(snapshot, sequence, rows, budget).error == ReplayError::InputLimit, "input size hard bound");

    const auto needsField = Prepare({FieldTest{FieldOp::Equal, "length", std::uint64_t{0}}});
    const ReplayRule predicateUnknown{ReplayKind::CountEqual, {"first", &needsField}, {"last", &all}, 30, 0};
    const auto missing = Replay(snapshot, predicateUnknown, std::array{last, first});
    Check(missing.windows.at(0).truth == Truth::Unknown && HasIssue(missing.issues, ReplayIssue::PredicateUnknown),
          "covered source with unavailable field cannot prove absence");
    const auto anchorMissing = Replay(snapshot, ReplayRule{ReplayKind::CountEqual, sequence.step, {"last", &needsField}, 30, 0},
                                     std::array{last});
    Check(anchorMissing.windows.at(0).truth == Truth::Unknown && !anchorMissing.windows[0].range,
          "unknown anchor selection remains visible without claiming a window");
    const auto sharedPublication = Event(3, 0, 100, "first");
    const auto count = Replay(snapshot, ReplayRule{ReplayKind::CountEqual, sequence.step, sequence.anchor, 30, 2},
                              std::array{last, first, sharedPublication});
    Check(count.windows.at(0).truth == Truth::True && count.windows[0].stepOrdinals.size() == 2,
          "distinct normalized event IDs in one packet still count as distinct events");
}

} // namespace

int main()
{
    try {
        TruthTables();
        BadPreparation();
        Values();
        CountAndWatermarks();
        SequencesAndLimits();
    } catch (const std::runtime_error&) {
        return 1;
    }
    std::cout << "ActionAnalyze rules checks passed: " << checks << '\n';
    return 0;
}
