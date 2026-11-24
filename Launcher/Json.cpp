#include "Json.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <algorithm>

namespace launcher {

JsonValue::JsonValue() = default;
JsonValue::JsonValue(bool value) : type_(Type::Boolean), boolean_(value) {}
JsonValue::JsonValue(double value) : type_(Type::Number), number_(value) {}
JsonValue::JsonValue(std::string value) : type_(Type::String), string_(std::move(value)) {}
JsonValue::JsonValue(Array value) : type_(Type::Array), array_(std::move(value)) {}
JsonValue::JsonValue(Object value) : type_(Type::Object), object_(std::move(value)) {}

const JsonValue* JsonValue::get(const char* name) const {
    if (!name || type_ != Type::Object) return nullptr;
    auto it = object_.find(name);
    return it == object_.end() ? nullptr : &it->second;
}

std::string JsonValue::stringOr(const char* name, const std::string& fallback) const {
    const JsonValue* child = get(name);
    return child && child->isString() ? child->string() : fallback;
}

double JsonValue::numberOr(const char* name, double fallback) const {
    const JsonValue* child = get(name);
    return child && child->isNumber() ? child->number() : fallback;
}

bool JsonValue::booleanOr(const char* name, bool fallback) const {
    const JsonValue* child = get(name);
    return child && child->isBoolean() ? child->boolean() : fallback;
}

class Parser {
public:
    Parser(const std::string& text, std::string* error, const std::vector<std::string>* members = nullptr)
        : text_(text), error_(error), members_(members)
    {
        // members_：可选的根成员保留名单；不拥有调用方数据。
    }

    bool parse(JsonValue* output) {
        skipWhitespace();
        if (!parseValue(output)) return false;
        skipWhitespace();
        if (position_ != text_.size()) return fail("trailing characters");
        return true;
    }

private:
    bool fail(const char* message) {
        if (error_) {
            std::ostringstream stream;
            stream << message << " at byte " << position_;
            *error_ = stream.str();
        }
        return false;
    }

    void skipWhitespace() {
        while (position_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[position_]))) ++position_;
    }

    bool consume(char expected) {
        skipWhitespace();
        if (position_ >= text_.size() || text_[position_] != expected) return fail("unexpected character");
        ++position_;
        return true;
    }

    bool parseValue(JsonValue* output, size_t depth = 0) {
        skipWhitespace();
        if (position_ >= text_.size()) return fail("unexpected end of input");
        const char ch = text_[position_];
        // Bound both parser recursion and the depth of the resulting DOM destruction.
        if (ch == '{' || ch == '[') {
            if (depth >= 64) return fail("JSON nesting limit exceeded");
            return ch == '{' ? parseObject(output, depth + 1) : parseArray(output, depth + 1);
        }
        if (ch == '"') {
            std::string value;
            if (!parseString(&value)) return false;
            if (output)
            {
                *output = JsonValue(std::move(value));
            }
            return true;
        }
        // 跳过的标量仍消费和校验原始 JSON，但不构造常驻 DOM 值。
        if (ch == 't' && consumeLiteral("true"))
        {
            if (output)
            {
                *output = JsonValue(true);
            }
            return true;
        }
        if (ch == 'f' && consumeLiteral("false"))
        {
            if (output)
            {
                *output = JsonValue(false);
            }
            return true;
        }
        if (ch == 'n' && consumeLiteral("null"))
        {
            if (output)
            {
                *output = JsonValue();
            }
            return true;
        }
        return parseNumber(output);
    }

    bool consumeLiteral(const char* literal) {
        const size_t length = std::strlen(literal);
        if (text_.compare(position_, length, literal) != 0) return false;
        position_ += length;
        return true;
    }

    bool parseString(std::string* output) {
        if (position_ >= text_.size() || text_[position_] != '"') return fail("expected string");
        ++position_;
        output->clear();
        while (position_ < text_.size()) {
            const unsigned char ch = static_cast<unsigned char>(text_[position_++]);
            if (ch == '"') return true;
            if (ch < 0x20) return fail("control character in string");
            if (ch != '\\') { output->push_back(static_cast<char>(ch)); continue; }
            if (position_ >= text_.size()) return fail("unfinished escape");
            const char escaped = text_[position_++];
            switch (escaped) {
            case '"': output->push_back('"'); break;
            case '\\': output->push_back('\\'); break;
            case '/': output->push_back('/'); break;
            case 'b': output->push_back('\b'); break;
            case 'f': output->push_back('\f'); break;
            case 'n': output->push_back('\n'); break;
            case 'r': output->push_back('\r'); break;
            case 't': output->push_back('\t'); break;
            case 'u': {
                // 清单只使用 ASCII 字段；仍然接受 BMP 转义，便于报告解析。
                if (position_ + 4 > text_.size()) return fail("short unicode escape");
                unsigned value = 0;
                for (int index = 0; index < 4; ++index) {
                    const char digit = text_[position_++];
                    const int nibble = std::isdigit(static_cast<unsigned char>(digit)) ? digit - '0' :
                        (digit >= 'a' && digit <= 'f') ? digit - 'a' + 10 :
                        (digit >= 'A' && digit <= 'F') ? digit - 'A' + 10 : -1;
                    if (nibble < 0) return fail("invalid unicode escape");
                    value = (value << 4) | static_cast<unsigned>(nibble);
                }
                if (value < 0x80) output->push_back(static_cast<char>(value));
                else if (value < 0x800) {
                    output->push_back(static_cast<char>(0xC0 | (value >> 6)));
                    output->push_back(static_cast<char>(0x80 | (value & 0x3F)));
                } else {
                    output->push_back(static_cast<char>(0xE0 | (value >> 12)));
                    output->push_back(static_cast<char>(0x80 | ((value >> 6) & 0x3F)));
                    output->push_back(static_cast<char>(0x80 | (value & 0x3F)));
                }
                break;
            }
            default: return fail("invalid escape");
            }
        }
        return fail("unterminated string");
    }

    bool parseNumber(JsonValue* output) {
        const size_t start = position_;
        if (position_ < text_.size() && text_[position_] == '-') ++position_;
        while (position_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[position_]))) ++position_;
        if (position_ < text_.size() && text_[position_] == '.') {
            ++position_;
            while (position_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[position_]))) ++position_;
        }
        if (position_ < text_.size() && (text_[position_] == 'e' || text_[position_] == 'E')) {
            ++position_;
            if (position_ < text_.size() && (text_[position_] == '+' || text_[position_] == '-')) ++position_;
            while (position_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[position_]))) ++position_;
        }
        if (start == position_) return fail("expected value");
        char* end = nullptr;
        const double value = std::strtod(text_.c_str() + start, &end);
        if (end != text_.c_str() + position_) return fail("invalid number");
        if (output)
        {
            *output = JsonValue(value);
        }
        return true;
    }

    bool parseArray(JsonValue* output, size_t depth) {
        if (!consume('[')) return false;
        JsonValue::Array values;
        skipWhitespace();
        if (position_ < text_.size() && text_[position_] == ']')
        {
            ++position_;
            if (output)
            {
                *output = JsonValue(std::move(values));
            }
            return true;
        }
        while (true) {
            JsonValue value;
            if (!parseValue(output ? &value : nullptr, depth)) return false; // 跳过的数组不积累 DOM。
            if (output)
            {
                values.push_back(std::move(value));
            }
            skipWhitespace();
            if (position_ < text_.size() && text_[position_] == ']') { ++position_; break; }
            if (!consume(',')) return false;
        }
        if (output)
        {
            *output = JsonValue(std::move(values));
        }
        return true;
    }

    bool parseObject(JsonValue* output, size_t depth) {
        if (!consume('{')) return false;
        JsonValue::Object values;
        skipWhitespace();
        if (position_ < text_.size() && text_[position_] == '}')
        {
            ++position_;
            if (output)
            {
                *output = JsonValue(std::move(values));
            }
            return true;
        }
        while (true) {
            std::string key;
            skipWhitespace();
            if (!parseString(&key)) return false;
            if (!consume(':')) return false;
            JsonValue value;
            const bool retain = output && (!members_ || depth != 1 ||
                std::find(members_->begin(), members_->end(), key) != members_->end()); // 只筛选根成员，不裁剪布局内容。
            if (!parseValue(retain ? &value : nullptr, depth)) return false;
            if (retain && !values.emplace(std::move(key), std::move(value)).second)
            {
                return fail("duplicate object key");
            }
            skipWhitespace();
            if (position_ < text_.size() && text_[position_] == '}') { ++position_; break; }
            if (!consume(',')) return false;
        }
        if (output)
        {
            *output = JsonValue(std::move(values));
        }
        return true;
    }

    const std::string& text_;
    std::string* error_ = nullptr;
    size_t position_ = 0;
    const std::vector<std::string>* members_ = nullptr; // 不拥有调用方名单，仅在同步解析期间使用。
};

bool ParseJson(const std::string& text, JsonValue* value, std::string* error) {
    if (!value) return false;
    Parser parser(text, error);
    return parser.parse(value);
}

bool ParseJsonRootMembers(const std::string& text, const std::vector<std::string>& members,
    JsonValue* value, std::string* error) {
    // 输入整份 v4 文本与根键名单；输出仍是根对象，不把部分文档伪装成完整驱动配置。
    if (!value) return false;
    Parser parser(text, error, &members);
    return parser.parse(value) && value->isObject();
}

std::string JsonEscape(const std::string& text) {
    std::string output;
    output.reserve(text.size() + 8);
    for (unsigned char ch : text) {
        switch (ch) {
        case '"': output += "\\\""; break;
        case '\\': output += "\\\\"; break;
        case '\n': output += "\\n"; break;
        case '\r': output += "\\r"; break;
        case '\t': output += "\\t"; break;
        default:
            if (ch < 0x20) { char buffer[7] = {}; std::snprintf(buffer, sizeof(buffer), "\\u%04x", ch); output += buffer; }
            else output.push_back(static_cast<char>(ch));
        }
    }
    return output;
}

}
