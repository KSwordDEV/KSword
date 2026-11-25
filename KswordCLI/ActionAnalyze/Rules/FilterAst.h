#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace Ksword::ActionAnalyze::Rules {

// 谓词真值、字段阶段、类型和采集质量分别建模。
enum class Truth { False, True, Unknown };
enum class Phase { Entry, Return, Submit, Complete, Observation };
enum class FieldType { Bool, U64, Text };
enum class Quality {
    Known, Null, NotCollected, Unsupported, AccessDenied,
    ReadFailed, Truncated, DecodeFailed, Redacted
};

inline constexpr std::size_t MaxKeyBytes = 128;
inline constexpr std::size_t MaxEventFields = 128;
inline constexpr std::size_t MaxValueBytes = 64 * 1024;
inline constexpr std::size_t MaxPredicateWork = 65536;

// CLI 内部投影。调用方从适用来源、事件种类和阶段的 A0 目录绑定字段。
struct FieldBinding {
    std::string_view id;
    FieldType type;
    Phase phase;
};

struct FieldSample {
    std::string_view id;
    Quality quality;
    std::variant<std::monostate, bool, std::uint64_t, std::string_view> value;

    friend bool operator==(const FieldSample&, const FieldSample&) = default;
};

// 字段比较只允许显式常量。null 单独表示，保留布尔和 u64 的位宽。
enum class FieldOp {
    Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual,
    Contains, StartsWith, EndsWith, IsNull, IsComplete
};

using Literal = std::variant<std::monostate, bool, std::uint64_t, std::string>;
struct FieldTest { FieldOp op; std::string field; Literal literal; };
struct Not { std::size_t child; };
enum class Logic { And, Or };
struct Logical { Logic op; std::size_t left; std::size_t right; };
using AstNode = std::variant<bool, Not, Logical, FieldTest>;

// 准备错误定位到节点，运行错误另外附在 Unknown 上。
enum class PrepareError {
    None, InvalidPhase, InvalidCatalog, NodeLimit, InvalidTree, DepthLimit,
    UnknownField, FieldNotInPhase, UnsupportedOperator, TypeMismatch,
    LiteralLimit, InvalidUtf8
};

enum class EvaluationFault { None, InvalidInput, Budget };
struct Evaluation {
    Truth truth = Truth::Unknown;
    EvaluationFault fault = EvaluationFault::None;
    std::size_t workUsed = 0;
};

struct Preparation;
class PreparedPredicate {
public:
    bool valid() const noexcept { return !nodes_.empty() && nodes_.size() == types_.size(); }
    Phase phase() const noexcept { return phase_; }

private:
    // 每个测试节点保留经目录核对的字段类型。其他位置只是占位。
    Phase phase_ = Phase::Observation;
    std::vector<AstNode> nodes_;
    std::vector<FieldType> types_;

    friend Preparation PreparePredicate(Phase, std::span<const FieldBinding>, std::span<const AstNode>);
    friend Evaluation EvaluatePredicate(const PreparedPredicate&, Phase, std::span<const FieldSample>, std::size_t);
};

struct Preparation {
    PreparedPredicate predicate;
    PrepareError error = PrepareError::None;
    std::size_t node = 0;
};

// 只接受已结构化的后序树，根为最后一项。每个节点只属一个父节点。
// 支持布尔常量、!、&&、||，以及字段与有类型字面量的比较／质量检查。
Preparation PreparePredicate(Phase phase, std::span<const FieldBinding> catalog,
                             std::span<const AstNode> nodes);

// 字段视图在调用期间有效，按 ID 递增且唯一。未投影字段的质量为 NotCollected。
// 短路保留左到右语义。实际读到的坏字段或耗尽预算独立报告，结果为 Unknown。
Evaluation EvaluatePredicate(const PreparedPredicate& predicate, Phase phase,
                             std::span<const FieldSample> fields,
                             std::size_t workLimit = MaxPredicateWork);

} // namespace Ksword::ActionAnalyze::Rules
