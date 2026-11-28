#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace Ksword::ActionAnalyze::Rules {

// 数值节点只使用 u64，不读取目标内存，也不包含调用或赋值。
struct NumericLiteral {
    std::uint64_t value; // 已验证范围的常量。
};
struct NumericField {
    std::string field; // 准备阶段绑定的证据字段 ID。
};
enum class NumericUnaryOp { Plus, Complement, ToByte, ToUInt16, ToUInt32, ToUInt64 };
struct NumericUnary {
    NumericUnaryOp op; // 白名单一元运算。
    std::size_t child; // 后序树中的操作数。
};
enum class NumericBinaryOp {
    Multiply, Divide, Remainder, Add, Subtract,
    ShiftLeft, ShiftRight, BitAnd, BitXor, BitOr
};
struct NumericBinary {
    NumericBinaryOp op; // 白名单二元运算。
    std::size_t left; // 左操作数的后序索引。
    std::size_t right; // 右操作数的后序索引。
};

// 检查结构化 AST 提供的枚举是否属于闭集，不执行任何运算。
bool IsValidNumericOperator(NumericUnaryOp op) noexcept;
bool IsValidNumericOperator(NumericBinaryOp op) noexcept;
// 输入已验证的一元运算和值；显式无符号转换保留目标低位，但结果容器仍为 u64。
std::uint64_t ApplyNumericOperator(NumericUnaryOp op, std::uint64_t value) noexcept;

// 加减乘采用 unchecked u64 环绕；移位计数只取低六位。
// 除零或余零返回 false，由解释器保留 Unknown 和稳定故障码。
bool ApplyNumericOperator(NumericBinaryOp op, std::uint64_t left,
    std::uint64_t right, std::uint64_t& result) noexcept;

} // namespace Ksword::ActionAnalyze::Rules
