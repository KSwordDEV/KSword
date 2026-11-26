#pragma once

#include "NumericOperations.h"

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

// 原有字段谓词继续支持显式常量；数值表达式使用独立类型化节点。
enum class FieldOp {
    Equal, NotEqual, Less, LessEqual, Greater, GreaterEqual,
    Contains, StartsWith, EndsWith, IsNull, IsComplete, IsKnown, QualityEqual, QualityNotEqual
};

using Literal = std::variant<std::monostate, bool, std::uint64_t, std::string, Quality>;
struct FieldTest { FieldOp op; std::string field; Literal literal; };
struct Not { std::size_t child; };
enum class Logic { And, Or };
struct Logical { Logic op; std::size_t left; std::size_t right; };
struct NumericComparison {
    FieldOp op; // 仅允许六种数值比较。
    std::size_t left; // 左侧 u64 子树的后序索引。
    std::size_t right; // 右侧 u64 子树的后序索引。
};
// 条件必须为布尔谓词，两个分支必须同为 bool 或同为 u64。
// 未知条件不会求值任何分支，也不会通过比较两个分支推断结果。
struct Conditional {
    std::size_t condition; // 先求值的布尔条件。
    std::size_t whenTrue; // 条件已知为真时唯一求值的分支。
    std::size_t whenFalse; // 条件已知为假时唯一求值的分支。
};
using AstNode = std::variant<bool, Not, Logical, FieldTest, NumericLiteral,
    NumericField, NumericUnary, NumericBinary, NumericComparison, Conditional>;

// 准备错误定位到节点，运行错误另外附在 Unknown 上。
enum class PrepareError {
    None, InvalidPhase, InvalidCatalog, NodeLimit, InvalidTree, DepthLimit,
    UnknownField, FieldNotInPhase, UnsupportedOperator, TypeMismatch,
    LiteralLimit, InvalidUtf8
};

enum class EvaluationFault { None, InvalidInput, Budget, DivisionByZero };
// 返回稳定诊断 ID；None 对应空串，除零和余零统一为 division-by-zero。
std::string_view EvaluationFaultId(EvaluationFault fault) noexcept;
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
// 根必须为布尔谓词；数值及条件子树同样计入节点、深度和唯一父节点限制。
Preparation PreparePredicate(Phase phase, std::span<const FieldBinding> catalog,
                             std::span<const AstNode> nodes);

// 字段视图在调用期间有效，按 ID 递增且唯一。未投影字段的质量为 NotCollected。
// 短路保留左到右语义；条件节点只读取已选分支，未知条件不读取分支字段。
// 实际读到的坏字段或耗尽预算独立报告，结果为 Unknown。
Evaluation EvaluatePredicate(const PreparedPredicate& predicate, Phase phase,
                             std::span<const FieldSample> fields,
                             std::size_t workLimit = MaxPredicateWork);

} // namespace Ksword::ActionAnalyze::Rules
