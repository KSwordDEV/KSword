#pragma once

// F-08: 64 位数据不丢失。
//
// 地址、64 位 ID、计数和高精度时间戳在本层永远不经过 double。持久化时 64 位
// 值写成带格式说明的字符串（十进制 "12345" 或地址 "0x00007FFE12340000"），
// 读回时逐位还原。空值是独立状态，绝不退化成 0。

#include <cstdint>
#include <string>
#include <string_view>

namespace Ksword::Evidence {

// OptionalU64 把"未知"和"零"分成两个状态。默认构造是未知。
struct OptionalU64 final {
    bool present = false;
    std::uint64_t value = 0;

    constexpr OptionalU64() noexcept = default;

    static constexpr OptionalU64 unset() noexcept { return OptionalU64{}; }

    static constexpr OptionalU64 of(std::uint64_t v) noexcept {
        OptionalU64 result;
        result.present = true;
        result.value = v;
        return result;
    }

    // valueOr 只用于展示回退；它不改变底层状态，调用点必须自己先看 present。
    constexpr std::uint64_t valueOr(std::uint64_t fallback) const noexcept {
        return present ? value : fallback;
    }

    friend constexpr bool operator==(const OptionalU64& a, const OptionalU64& b) noexcept {
        return a.present == b.present && (!a.present || a.value == b.value);
    }

    friend constexpr bool operator!=(const OptionalU64& a, const OptionalU64& b) noexcept {
        return !(a == b);
    }
};

// U64 的持久化格式标记。读写两侧共用，导出里必须显式带上，读取方不猜。
enum class U64Format {
    Decimal,     // "18446744073709551615"
    HexAddress,  // "0x00007FFE12340000" —— 固定 16 位十六进制，便于按地址排序与复制
};

std::string FormatU64(std::uint64_t value, U64Format format);

// FormatOptionalU64 对未知值返回空串，调用点据此写 JSON null，而不是 "0"。
std::string FormatOptionalU64(const OptionalU64& value, U64Format format);

// ParseU64 接受十进制与 0x 前缀十六进制两种写法，溢出、空串、尾随垃圾一律失败。
bool ParseU64(std::string_view text, std::uint64_t& out) noexcept;

// ParseOptionalU64：空串解析为"未知"并返回 true；非法文本返回 false 且不改 out。
bool ParseOptionalU64(std::string_view text, OptionalU64& out) noexcept;

// 有符号 64 位（例如时钟校准偏移）同样避免浮点。
std::string FormatI64(std::int64_t value);
bool ParseI64(std::string_view text, std::int64_t& out) noexcept;

} // namespace Ksword::Evidence
