#pragma once

#include "FilterAst.h"

namespace Ksword::ActionAnalyze::Rules {

// 本地草稿选择器使用的受限表达式语义版本。JSON 兼容的旧谓词仍走原入口。
inline constexpr std::string_view PredicateExpressionProfile = "predicate-expr-v1";
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
    NestingLimit, NodeLimit, PreparationFailed
};

struct ExpressionPreparation {
    PreparedPredicate predicate; // 仅成功时生成可供现有解释器执行的类型化谓词。
    ExpressionError error = ExpressionError::None; // 稳定的语法或绑定失败类别。
    PrepareError preparationError = PrepareError::None; // 保留目录、类型和阶段的原诊断。
    ExpressionLocation location; // 表达式自身的字节范围，不是 JSON 文件位置。
};

// 解析纯表达式并按调用方明确提供的字段目录及阶段验证。完整消耗输入后才返回谓词。
// 语法包含 !、&&、||、括号、字段与字面量比较，以及少量白名单文本与质量函数。
ExpressionPreparation PreparePredicateExpression(std::string_view source, Phase phase,
    std::span<const FieldBinding> catalog);

// 返回稳定英文诊断 ID，供外层 JSON 或界面回执引用。
std::string_view ExpressionErrorId(ExpressionError error) noexcept;

} // namespace Ksword::ActionAnalyze::Rules
