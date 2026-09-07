#pragma once

// 无损 JSON 编解码 —— F-08，并被 T-09 / D-06 / Q-12 的会话持久化复用。
//
// 关键约束：
//   * 本读写器**没有浮点数类型**。JSON number 只解析为 int64/uint64；带小数点或
//     指数的 number 直接判为解析失败，避免 2^53 以上的值悄悄丢精度。
//   * 64 位地址/ID/计数一律以带格式说明的字符串写出（见 LosslessValue.h）。
//   * null 与 0、空串是三个不同的值，读回后不合并。
//   * 解析器对深度、长度、成员数量有硬上限（Q-12：不可信输入）。

#include "LosslessValue.h"

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace Ksword::Evidence {

enum class JsonType {
    Null,
    Bool,
    UInt,
    Int,
    String,
    Array,
    Object,
};

class JsonValue;

using JsonArray = std::vector<JsonValue>;
using JsonObject = std::vector<std::pair<std::string, JsonValue>>;  // 保序，导出可复核

class JsonValue final {
public:
    JsonValue() = default;

    static JsonValue makeNull();
    static JsonValue makeBool(bool value);
    static JsonValue makeUInt(std::uint64_t value);
    static JsonValue makeInt(std::int64_t value);
    static JsonValue makeString(std::string value);
    static JsonValue makeArray(JsonArray value);
    static JsonValue makeObject(JsonObject value);

    // 无损地址/计数字段的标准写法：写成字符串，读回用 tryGetU64。
    static JsonValue makeU64Text(std::uint64_t value, U64Format format);
    static JsonValue makeOptionalU64Text(const OptionalU64& value, U64Format format);

    JsonType type() const noexcept { return type_; }
    bool isNull() const noexcept { return type_ == JsonType::Null; }

    bool tryGetBool(bool& out) const noexcept;
    bool tryGetU64(std::uint64_t& out) const noexcept;      // 接受 UInt 或可解析的 String
    bool tryGetI64(std::int64_t& out) const noexcept;
    bool tryGetString(std::string& out) const;
    // null -> unset 且返回 true；非法内容返回 false。
    bool tryGetOptionalU64(OptionalU64& out) const noexcept;

    const JsonArray* asArray() const noexcept;
    const JsonObject* asObject() const noexcept;

    // 只在 Object 上查找；找不到返回 nullptr（不是插入）。
    const JsonValue* find(std::string_view name) const noexcept;

private:
    JsonType type_ = JsonType::Null;
    bool bool_ = false;
    std::uint64_t uint_ = 0;
    std::int64_t int_ = 0;
    std::string string_;
    std::shared_ptr<JsonArray> array_;
    std::shared_ptr<JsonObject> object_;
};

// 序列化。indent=0 输出紧凑单行。
std::string WriteJson(const JsonValue& value, unsigned indent = 0);

struct JsonLimits final {
    std::size_t maxDepth = 64;
    std::size_t maxStringBytes = 1u << 20;      // 1 MiB
    std::size_t maxContainerItems = 1u << 20;   // 单个数组/对象成员上限
    // Q-12：节点上限按"个数"给管不住内存 —— 每个 JsonValue 有几十字节固定开销，
    // 几 MB 输入就能撑出几百 MB 常驻。三条上限一起卡：输入字节、节点个数、节点字节。
    std::size_t maxTotalNodes = 1u << 19;             // 524,288 个节点
    std::size_t maxTotalBytes = 32u * 1024u * 1024u;  // 32 MiB 输入；0 表示不限
    // nodes * sizeof(JsonValue) 的预算；0 表示不限。需要更大的调用方显式抬高。
    std::size_t maxEstimatedNodeBytes = 64u * 1024u * 1024u;
};

enum class JsonParseStatus {
    Ok,
    Empty,
    Syntax,
    DepthLimit,
    SizeLimit,
    NodeLimit,
    FloatingPointRejected,   // 明确拒绝浮点，而不是悄悄降精度
    IntegerOverflow,
    TrailingData,
    DuplicateKey,
};

const char* JsonParseStatusName(JsonParseStatus status) noexcept;

struct JsonParseResult final {
    JsonParseStatus status = JsonParseStatus::Empty;
    JsonValue value;
    std::size_t errorOffset = 0;

    bool ok() const noexcept { return status == JsonParseStatus::Ok; }
};

JsonParseResult ParseJson(std::string_view text, const JsonLimits& limits = JsonLimits{});

} // namespace Ksword::Evidence
