#pragma once

#include "FilterAst.h"

namespace Ksword::ActionAnalyze::Rules {

// v3 增补有限数值运算和条件运算符，旧表达式与 JSON 字段谓词保持兼容。
inline constexpr std::string_view PredicateExpressionProfile = "predicate-expr-v3";
inline constexpr bool IsSupportedPredicateExpressionProfile(std::string_view profile) noexcept
{
    return profile == PredicateExpressionProfile || profile == "predicate-expr-v2" ||
        profile == "predicate-expr-v1";
}
inline constexpr std::size_t MaxPredicateExpressionBytes = 8192;

// 表达式原文使用 UTF-8。偏移从 0 开始，行与字节列从 1 开始。
struct ExpressionLocation {
    std::size_t offset = 0;
    std::size_t length = 0;
    std::size_t line = 1;
    std::size_t byteColumn = 1;
};

enum class ExpressionError {
    None, TextLimit, ExpectedPredicate, ExpectedLiteral, ExpectedCloseParen,
    ExpectedComma, UnexpectedToken, InvalidFieldPath, UnsupportedCall,
    InvalidNumber, NumericOverflow, InvalidString, UnsupportedEscape,
    NestingLimit, NodeLimit, PreparationFailed, ExpectedQualityComparison, InvalidQuality,
    ExpectedU64Operands, BitwiseComparisonPrecedence, UnsupportedProfile,
    ExpectedConditionalColon, ExpectedBooleanCondition, ConditionalBranchTypeMismatch
};

struct ExpressionPreparation {
    PreparedPredicate predicate; // 仅成功时生成可供现有解释器执行的类型化谓词。
    ExpressionError error = ExpressionError::None; // 稳定的语法或绑定失败类别。
    PrepareError preparationError = PrepareError::None; // 保留目录、类型和阶段的原诊断。
    ExpressionLocation location; // 表达式自身的字节范围，不是 JSON 文件位置。
};

// 解析纯表达式并按调用方明确提供的字段目录及阶段验证。完整消耗输入后才返回谓词。
// 优先级从高到低为 !、~、一元+；*/%；+/-；<< >>；关系；相等；&；^；|；&&；||；?:。
// ?: 右结合，条件必须为 bool，两分支必须同为 bool 或同为 u64；根仍须为 bool。
// 已知条件只求值所选分支；未知条件直接返回 Unknown，不求值或合并分支。
// u64 加减乘环绕；无符号右移，位移计数取低六位；除零返回 Unknown 和故障码。
// 不支持一元负号（与 C# ulong 一致）、隐式类型转换、赋值或用户函数。
// 数值叶子为目录中 U64 字段或十进制／0x 十六进制 u64 常量；括号可包任意子表达式。
// &、^、| 接受同为 u64 或同为 bool 的两侧，bool 路径非短路；混合类型拒绝。
// 数值位运算参与比较时加括号：mask & 1u64 != 0u64 必须写为 (mask & 1u64) != 0u64。
// isKnown 仅匹配 known，quality(field) 可与规范状态名做 == 或 != 比较。
ExpressionPreparation PreparePredicateExpression(std::string_view source, Phase phase,
    std::span<const FieldBinding> catalog);

// 读取归档中的显式语义版本；v1/v2 按原句法准入，不开放 v3 数值运算或 ?:。
// v1 也不开放 v2 才引入的 isKnown/quality；未知版本拒绝而不猜测。
ExpressionPreparation PreparePredicateExpression(std::string_view source, Phase phase,
    std::span<const FieldBinding> catalog, std::string_view profile);

// 返回稳定英文诊断 ID，供外层 JSON 或界面回执引用。
std::string_view ExpressionErrorId(ExpressionError error) noexcept;

} // namespace Ksword::ActionAnalyze::Rules
