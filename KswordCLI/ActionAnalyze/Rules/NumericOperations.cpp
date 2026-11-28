#include "NumericOperations.h"

namespace Ksword::ActionAnalyze::Rules {

// 准备阶段验证一元操作，拒绝伪造的枚举值。
bool IsValidNumericOperator(NumericUnaryOp op) noexcept
{
    switch (op) {
    case NumericUnaryOp::Plus: case NumericUnaryOp::Complement:
    case NumericUnaryOp::ToByte: case NumericUnaryOp::ToUInt16:
    case NumericUnaryOp::ToUInt32: case NumericUnaryOp::ToUInt64:
        return true;
    }
    return false;
}

// 准备阶段验证二元操作；调用方据此发布可执行的类型化树。
bool IsValidNumericOperator(NumericBinaryOp op) noexcept
{
    switch (op) {
    case NumericBinaryOp::Multiply: case NumericBinaryOp::Divide: case NumericBinaryOp::Remainder:
    case NumericBinaryOp::Add: case NumericBinaryOp::Subtract:
    case NumericBinaryOp::ShiftLeft: case NumericBinaryOp::ShiftRight:
    case NumericBinaryOp::BitAnd: case NumericBinaryOp::BitXor: case NumericBinaryOp::BitOr:
        return true;
    }
    return false;
}

// 正号保留原值；显式转换只截取低位，不引入 CLR 整数提升或 checked 溢出语义。
std::uint64_t ApplyNumericOperator(NumericUnaryOp op, std::uint64_t value) noexcept
{
    switch (op) {
    case NumericUnaryOp::Complement:
        return ~value;
    case NumericUnaryOp::ToByte:
        return value & 0xffULL;
    case NumericUnaryOp::ToUInt16:
        return value & 0xffffULL;
    case NumericUnaryOp::ToUInt32:
        return value & 0xffffffffULL;
    case NumericUnaryOp::Plus: case NumericUnaryOp::ToUInt64:
        return value;
    }
    return value; // 无效枚举在准备阶段拒绝，不会进入已准备树。
}

// 输入均为已知 u64；成功写入 result，除零或无效操作返回 false。
bool ApplyNumericOperator(NumericBinaryOp op, std::uint64_t left,
    std::uint64_t right, std::uint64_t& result) noexcept
{
    switch (op) {
    case NumericBinaryOp::Multiply:
        result = left * right;
        break;
    case NumericBinaryOp::Add:
        result = left + right;
        break;
    case NumericBinaryOp::Subtract:
        result = left - right;
        break;
    // C# ulong 移位只使用计数的低六位，避免 C++ 的超宽移位未定义行为。
    case NumericBinaryOp::ShiftLeft:
        result = left << (right & 63u);
        break;
    case NumericBinaryOp::ShiftRight:
        result = left >> (right & 63u);
        break;
    case NumericBinaryOp::BitAnd:
        result = left & right;
        break;
    case NumericBinaryOp::BitXor:
        result = left ^ right;
        break;
    case NumericBinaryOp::BitOr:
        result = left | right;
        break;
    // 不使用异常或硬件故障处理；除法前显式拒绝零除数。
    case NumericBinaryOp::Divide:
    case NumericBinaryOp::Remainder:
        if (right == 0) {
            return false;
        }
        result = op == NumericBinaryOp::Divide ? left / right : left % right;
        break;
    default:
        return false;
    }
    return true;
}

} // namespace Ksword::ActionAnalyze::Rules
