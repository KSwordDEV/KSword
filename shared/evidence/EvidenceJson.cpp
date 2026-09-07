#include "EvidenceJson.h"

#include <limits>
#include <unordered_set>

namespace Ksword::Evidence {
namespace {

constexpr char kHexDigitsLower[] = "0123456789abcdef";

void AppendEscapedString(std::string& out, const std::string& text) {
    out.push_back('"');
    for (const char raw : text) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
        case '"':  out.append("\\\""); break;
        case '\\': out.append("\\\\"); break;
        case '\b': out.append("\\b"); break;
        case '\f': out.append("\\f"); break;
        case '\n': out.append("\\n"); break;
        case '\r': out.append("\\r"); break;
        case '\t': out.append("\\t"); break;
        default:
            if (c < 0x20U) {
                // Q-12：控制字符一律转义，报告里不残留裸控制码。
                out.append("\\u00");
                out.push_back(kHexDigitsLower[(c >> 4U) & 0xFU]);
                out.push_back(kHexDigitsLower[c & 0xFU]);
            } else {
                out.push_back(raw);
            }
            break;
        }
    }
    out.push_back('"');
}

void AppendIndent(std::string& out, unsigned indent, unsigned depth) {
    if (indent == 0U) {
        return;
    }
    out.push_back('\n');
    out.append(static_cast<std::size_t>(indent) * depth, ' ');
}

void WriteValue(std::string& out, const JsonValue& value, unsigned indent, unsigned depth);

void WriteContainer(std::string& out,
                    const JsonValue& value,
                    unsigned indent,
                    unsigned depth) {
    if (const JsonArray* array = value.asArray()) {
        if (array->empty()) {
            out.append("[]");
            return;
        }
        out.push_back('[');
        bool first = true;
        for (const JsonValue& item : *array) {
            if (!first) {
                out.push_back(',');
            }
            first = false;
            AppendIndent(out, indent, depth + 1U);
            WriteValue(out, item, indent, depth + 1U);
        }
        AppendIndent(out, indent, depth);
        out.push_back(']');
        return;
    }

    const JsonObject* object = value.asObject();
    if (object == nullptr || object->empty()) {
        out.append("{}");
        return;
    }
    out.push_back('{');
    bool first = true;
    for (const auto& member : *object) {
        if (!first) {
            out.push_back(',');
        }
        first = false;
        AppendIndent(out, indent, depth + 1U);
        AppendEscapedString(out, member.first);
        out.push_back(':');
        if (indent != 0U) {
            out.push_back(' ');
        }
        WriteValue(out, member.second, indent, depth + 1U);
    }
    AppendIndent(out, indent, depth);
    out.push_back('}');
}

void WriteValue(std::string& out, const JsonValue& value, unsigned indent, unsigned depth) {
    switch (value.type()) {
    case JsonType::Null:
        out.append("null");
        break;
    case JsonType::Bool: {
        bool flag = false;
        (void)value.tryGetBool(flag);
        out.append(flag ? "true" : "false");
        break;
    }
    case JsonType::UInt: {
        std::uint64_t number = 0U;
        (void)value.tryGetU64(number);
        out.append(FormatU64(number, U64Format::Decimal));
        break;
    }
    case JsonType::Int: {
        std::int64_t number = 0;
        (void)value.tryGetI64(number);
        out.append(FormatI64(number));
        break;
    }
    case JsonType::String: {
        std::string text;
        (void)value.tryGetString(text);
        AppendEscapedString(out, text);
        break;
    }
    case JsonType::Array:
    case JsonType::Object:
        WriteContainer(out, value, indent, depth);
        break;
    }
}

// ---------------------------------------------------------------------------
// 解析器
// ---------------------------------------------------------------------------
class Parser final {
public:
    Parser(std::string_view text, const JsonLimits& limits) noexcept
        : text_(text), limits_(limits) {}

    JsonParseResult run() {
        skipWhitespace();
        if (pos_ >= text_.size()) {
            return fail(JsonParseStatus::Empty);
        }
        JsonValue value;
        if (!parseValue(value, 0U)) {
            return fail(status_);
        }
        skipWhitespace();
        if (pos_ != text_.size()) {
            return fail(JsonParseStatus::TrailingData);
        }
        JsonParseResult result;
        result.status = JsonParseStatus::Ok;
        result.value = std::move(value);
        return result;
    }

private:
    JsonParseResult fail(JsonParseStatus status) const {
        JsonParseResult result;
        result.status = status == JsonParseStatus::Ok ? JsonParseStatus::Syntax : status;
        result.errorOffset = pos_;
        return result;
    }

    void skipWhitespace() noexcept {
        while (pos_ < text_.size()) {
            const char c = text_[pos_];
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                ++pos_;
            } else {
                break;
            }
        }
    }

    bool consume(char expected) noexcept {
        if (pos_ < text_.size() && text_[pos_] == expected) {
            ++pos_;
            return true;
        }
        status_ = JsonParseStatus::Syntax;
        return false;
    }

    bool literal(std::string_view word) noexcept {
        if (text_.size() - pos_ < word.size() || text_.compare(pos_, word.size(), word) != 0) {
            status_ = JsonParseStatus::Syntax;
            return false;
        }
        pos_ += word.size();
        return true;
    }

    bool countNode() noexcept {
        if (++nodes_ > limits_.maxTotalNodes) {
            status_ = JsonParseStatus::NodeLimit;
            return false;
        }
        // F-07 / Q-12：节点个数管不住内存放大 —— 4 个各 100 万元素的数组只有 7.6 MB
        // 输入，却按 sizeof(JsonValue) 撑出几百 MB。这里按估算字节数再卡一道。
        // 用除法而不是乘法，避免 nodes_ * sizeof 自己先溢出。
        if (limits_.maxEstimatedNodeBytes != 0U &&
            nodes_ > limits_.maxEstimatedNodeBytes / sizeof(JsonValue)) {
            status_ = JsonParseStatus::SizeLimit;
            return false;
        }
        return true;
    }

    bool parseValue(JsonValue& out, std::size_t depth) {
        if (depth > limits_.maxDepth) {
            status_ = JsonParseStatus::DepthLimit;
            return false;
        }
        if (!countNode()) {
            return false;
        }
        skipWhitespace();
        if (pos_ >= text_.size()) {
            status_ = JsonParseStatus::Syntax;
            return false;
        }
        switch (text_[pos_]) {
        case 'n':
            if (!literal("null")) {
                return false;
            }
            out = JsonValue::makeNull();
            return true;
        case 't':
            if (!literal("true")) {
                return false;
            }
            out = JsonValue::makeBool(true);
            return true;
        case 'f':
            if (!literal("false")) {
                return false;
            }
            out = JsonValue::makeBool(false);
            return true;
        case '"': {
            std::string text;
            if (!parseString(text)) {
                return false;
            }
            out = JsonValue::makeString(std::move(text));
            return true;
        }
        case '[':
            return parseArray(out, depth);
        case '{':
            return parseObject(out, depth);
        default:
            return parseNumber(out);
        }
    }

    bool parseArray(JsonValue& out, std::size_t depth) {
        if (!consume('[')) {
            return false;
        }
        JsonArray items;
        skipWhitespace();
        if (pos_ < text_.size() && text_[pos_] == ']') {
            ++pos_;
            out = JsonValue::makeArray(std::move(items));
            return true;
        }
        for (;;) {
            if (items.size() >= limits_.maxContainerItems) {
                status_ = JsonParseStatus::SizeLimit;
                return false;
            }
            JsonValue item;
            if (!parseValue(item, depth + 1U)) {
                return false;
            }
            items.push_back(std::move(item));
            skipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            break;
        }
        if (!consume(']')) {
            return false;
        }
        out = JsonValue::makeArray(std::move(items));
        return true;
    }

    bool parseObject(JsonValue& out, std::size_t depth) {
        if (!consume('{')) {
            return false;
        }
        JsonObject members;
        // Q-12：重复键检测必须是均摊 O(1)。早先用 any_of 线性扫已收成员，导入侧
        // 就多了一条 O(n²) 的 DoS 通道：128,000 个成员（1.4 MB）实测要 15 秒，按
        // 默认成员上限外推约 17 分钟，而全程 status=Ok，UI 只会看起来挂死。
        std::unordered_set<std::string> seenNames;
        skipWhitespace();
        if (pos_ < text_.size() && text_[pos_] == '}') {
            ++pos_;
            out = JsonValue::makeObject(std::move(members));
            return true;
        }
        for (;;) {
            if (members.size() >= limits_.maxContainerItems) {
                status_ = JsonParseStatus::SizeLimit;
                return false;
            }
            skipWhitespace();
            std::string name;
            if (!parseString(name)) {
                return false;
            }
            // Q-12：重复 id / 重复键必须拒绝，不能让后写的悄悄覆盖前一个。
            if (!seenNames.insert(name).second) {
                status_ = JsonParseStatus::DuplicateKey;
                return false;
            }
            skipWhitespace();
            if (!consume(':')) {
                return false;
            }
            JsonValue value;
            if (!parseValue(value, depth + 1U)) {
                return false;
            }
            members.emplace_back(std::move(name), std::move(value));
            skipWhitespace();
            if (pos_ < text_.size() && text_[pos_] == ',') {
                ++pos_;
                continue;
            }
            break;
        }
        if (!consume('}')) {
            return false;
        }
        out = JsonValue::makeObject(std::move(members));
        return true;
    }

    bool appendUtf8(std::string& out, std::uint32_t codepoint) {
        if (codepoint < 0x80U) {
            out.push_back(static_cast<char>(codepoint));
        } else if (codepoint < 0x800U) {
            out.push_back(static_cast<char>(0xC0U | (codepoint >> 6U)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else if (codepoint < 0x10000U) {
            out.push_back(static_cast<char>(0xE0U | (codepoint >> 12U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else if (codepoint <= 0x10FFFFU) {
            out.push_back(static_cast<char>(0xF0U | (codepoint >> 18U)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3FU)));
            out.push_back(static_cast<char>(0x80U | (codepoint & 0x3FU)));
        } else {
            status_ = JsonParseStatus::Syntax;
            return false;
        }
        return true;
    }

    bool parseHex4(std::uint32_t& out) noexcept {
        if (text_.size() - pos_ < 4U) {
            status_ = JsonParseStatus::Syntax;
            return false;
        }
        std::uint32_t value = 0U;
        for (std::size_t i = 0U; i < 4U; ++i) {
            const char c = text_[pos_ + i];
            std::uint32_t digit = 0U;
            if (c >= '0' && c <= '9') {
                digit = static_cast<std::uint32_t>(c - '0');
            } else if (c >= 'a' && c <= 'f') {
                digit = static_cast<std::uint32_t>(c - 'a') + 10U;
            } else if (c >= 'A' && c <= 'F') {
                digit = static_cast<std::uint32_t>(c - 'A') + 10U;
            } else {
                status_ = JsonParseStatus::Syntax;
                return false;
            }
            value = (value << 4U) | digit;
        }
        pos_ += 4U;
        out = value;
        return true;
    }

    bool parseString(std::string& out) {
        if (!consume('"')) {
            return false;
        }
        out.clear();
        for (;;) {
            if (pos_ >= text_.size()) {
                status_ = JsonParseStatus::Syntax;
                return false;
            }
            if (out.size() > limits_.maxStringBytes) {
                status_ = JsonParseStatus::SizeLimit;
                return false;
            }
            const char c = text_[pos_];
            if (c == '"') {
                ++pos_;
                return true;
            }
            if (c == '\\') {
                ++pos_;
                if (pos_ >= text_.size()) {
                    status_ = JsonParseStatus::Syntax;
                    return false;
                }
                const char esc = text_[pos_++];
                switch (esc) {
                case '"':  out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/':  out.push_back('/'); break;
                case 'b':  out.push_back('\b'); break;
                case 'f':  out.push_back('\f'); break;
                case 'n':  out.push_back('\n'); break;
                case 'r':  out.push_back('\r'); break;
                case 't':  out.push_back('\t'); break;
                case 'u': {
                    std::uint32_t code = 0U;
                    if (!parseHex4(code)) {
                        return false;
                    }
                    if (code >= 0xD800U && code <= 0xDBFFU) {
                        // 高代理必须紧跟低代理，否则是坏数据。
                        if (text_.size() - pos_ < 6U || text_[pos_] != '\\' || text_[pos_ + 1U] != 'u') {
                            status_ = JsonParseStatus::Syntax;
                            return false;
                        }
                        pos_ += 2U;
                        std::uint32_t low = 0U;
                        if (!parseHex4(low)) {
                            return false;
                        }
                        if (low < 0xDC00U || low > 0xDFFFU) {
                            status_ = JsonParseStatus::Syntax;
                            return false;
                        }
                        code = 0x10000U + ((code - 0xD800U) << 10U) + (low - 0xDC00U);
                    } else if (code >= 0xDC00U && code <= 0xDFFFU) {
                        status_ = JsonParseStatus::Syntax;
                        return false;
                    }
                    if (!appendUtf8(out, code)) {
                        return false;
                    }
                    break;
                }
                default:
                    status_ = JsonParseStatus::Syntax;
                    return false;
                }
                continue;
            }
            if (static_cast<unsigned char>(c) < 0x20U) {
                status_ = JsonParseStatus::Syntax;  // 裸控制字符不合法
                return false;
            }
            out.push_back(c);
            ++pos_;
        }
    }

    bool parseNumber(JsonValue& out) {
        const std::size_t start = pos_;
        const bool negative = pos_ < text_.size() && text_[pos_] == '-';
        if (negative) {
            ++pos_;
        }
        const std::size_t digitStart = pos_;
        while (pos_ < text_.size() && text_[pos_] >= '0' && text_[pos_] <= '9') {
            ++pos_;
        }
        if (pos_ == digitStart) {
            status_ = JsonParseStatus::Syntax;
            pos_ = start;
            return false;
        }
        // F-08：本读写器不接受浮点。小数点/指数一律判失败，而不是降精度。
        if (pos_ < text_.size() && (text_[pos_] == '.' || text_[pos_] == 'e' || text_[pos_] == 'E')) {
            status_ = JsonParseStatus::FloatingPointRejected;
            return false;
        }
        const std::string_view digits = text_.substr(digitStart, pos_ - digitStart);
        std::uint64_t magnitude = 0U;
        if (!ParseU64(digits, magnitude)) {
            status_ = JsonParseStatus::IntegerOverflow;
            return false;
        }
        if (!negative) {
            out = JsonValue::makeUInt(magnitude);
            return true;
        }
        constexpr std::uint64_t kPositiveMax =
            static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        if (magnitude > kPositiveMax + 1ULL) {
            status_ = JsonParseStatus::IntegerOverflow;
            return false;
        }
        if (magnitude == kPositiveMax + 1ULL) {
            out = JsonValue::makeInt((std::numeric_limits<std::int64_t>::min)());
            return true;
        }
        out = JsonValue::makeInt(-static_cast<std::int64_t>(magnitude));
        return true;
    }

    std::string_view text_;
    JsonLimits limits_;
    std::size_t pos_ = 0;
    std::size_t nodes_ = 0;
    JsonParseStatus status_ = JsonParseStatus::Syntax;
};

} // namespace

// ---------------------------------------------------------------------------
// JsonValue
// ---------------------------------------------------------------------------
JsonValue JsonValue::makeNull() {
    JsonValue value;
    value.type_ = JsonType::Null;
    return value;
}

JsonValue JsonValue::makeBool(bool flag) {
    JsonValue value;
    value.type_ = JsonType::Bool;
    value.bool_ = flag;
    return value;
}

JsonValue JsonValue::makeUInt(std::uint64_t number) {
    JsonValue value;
    value.type_ = JsonType::UInt;
    value.uint_ = number;
    return value;
}

JsonValue JsonValue::makeInt(std::int64_t number) {
    JsonValue value;
    value.type_ = JsonType::Int;
    value.int_ = number;
    return value;
}

JsonValue JsonValue::makeString(std::string text) {
    JsonValue value;
    value.type_ = JsonType::String;
    value.string_ = std::move(text);
    return value;
}

JsonValue JsonValue::makeArray(JsonArray items) {
    JsonValue value;
    value.type_ = JsonType::Array;
    value.array_ = std::make_shared<JsonArray>(std::move(items));
    return value;
}

JsonValue JsonValue::makeObject(JsonObject members) {
    JsonValue value;
    value.type_ = JsonType::Object;
    value.object_ = std::make_shared<JsonObject>(std::move(members));
    return value;
}

JsonValue JsonValue::makeU64Text(std::uint64_t number, U64Format format) {
    return makeString(FormatU64(number, format));
}

JsonValue JsonValue::makeOptionalU64Text(const OptionalU64& number, U64Format format) {
    if (!number.present) {
        return makeNull();  // F-08：空值写 null，读回仍是空值，不变成 0
    }
    return makeString(FormatU64(number.value, format));
}

bool JsonValue::tryGetBool(bool& out) const noexcept {
    if (type_ != JsonType::Bool) {
        return false;
    }
    out = bool_;
    return true;
}

bool JsonValue::tryGetU64(std::uint64_t& out) const noexcept {
    if (type_ == JsonType::UInt) {
        out = uint_;
        return true;
    }
    if (type_ == JsonType::Int) {
        if (int_ < 0) {
            return false;
        }
        out = static_cast<std::uint64_t>(int_);
        return true;
    }
    if (type_ == JsonType::String) {
        return ParseU64(string_, out);
    }
    return false;
}

bool JsonValue::tryGetI64(std::int64_t& out) const noexcept {
    if (type_ == JsonType::Int) {
        out = int_;
        return true;
    }
    if (type_ == JsonType::UInt) {
        constexpr std::uint64_t kMax =
            static_cast<std::uint64_t>((std::numeric_limits<std::int64_t>::max)());
        if (uint_ > kMax) {
            return false;
        }
        out = static_cast<std::int64_t>(uint_);
        return true;
    }
    if (type_ == JsonType::String) {
        return ParseI64(string_, out);
    }
    return false;
}

bool JsonValue::tryGetString(std::string& out) const {
    if (type_ != JsonType::String) {
        return false;
    }
    out = string_;
    return true;
}

bool JsonValue::tryGetOptionalU64(OptionalU64& out) const noexcept {
    if (type_ == JsonType::Null) {
        out = OptionalU64::unset();
        return true;
    }
    std::uint64_t number = 0U;
    if (!tryGetU64(number)) {
        return false;
    }
    out = OptionalU64::of(number);
    return true;
}

const JsonArray* JsonValue::asArray() const noexcept {
    return (type_ == JsonType::Array && array_) ? array_.get() : nullptr;
}

const JsonObject* JsonValue::asObject() const noexcept {
    return (type_ == JsonType::Object && object_) ? object_.get() : nullptr;
}

const JsonValue* JsonValue::find(std::string_view name) const noexcept {
    const JsonObject* members = asObject();
    if (members == nullptr) {
        return nullptr;
    }
    for (const auto& member : *members) {
        if (member.first == name) {
            return &member.second;
        }
    }
    return nullptr;
}

std::string WriteJson(const JsonValue& value, unsigned indent) {
    std::string out;
    WriteValue(out, value, indent, 0U);
    return out;
}

const char* JsonParseStatusName(JsonParseStatus status) noexcept {
    switch (status) {
    case JsonParseStatus::Ok:                    return "Ok";
    case JsonParseStatus::Empty:                 return "Empty";
    case JsonParseStatus::Syntax:                return "Syntax";
    case JsonParseStatus::DepthLimit:            return "DepthLimit";
    case JsonParseStatus::SizeLimit:             return "SizeLimit";
    case JsonParseStatus::NodeLimit:             return "NodeLimit";
    case JsonParseStatus::FloatingPointRejected: return "FloatingPointRejected";
    case JsonParseStatus::IntegerOverflow:       return "IntegerOverflow";
    case JsonParseStatus::TrailingData:          return "TrailingData";
    case JsonParseStatus::DuplicateKey:          return "DuplicateKey";
    }
    return "Syntax";
}

JsonParseResult ParseJson(std::string_view text, const JsonLimits& limits) {
    // Q-12：会话/报告导入是不可信输入。先卡总字节，再谈解析 —— 否则一个 11 MB 的
    // 文件就能把导入线程占死。
    if (limits.maxTotalBytes != 0U && text.size() > limits.maxTotalBytes) {
        JsonParseResult result;
        result.status = JsonParseStatus::SizeLimit;
        result.errorOffset = limits.maxTotalBytes;
        return result;
    }
    Parser parser(text, limits);
    return parser.run();
}

} // namespace Ksword::Evidence
