#pragma once

#include <map>
#include <string>
#include <vector>

namespace launcher {

// JsonValue 是 Launcher 使用的最小 JSON DOM，避免引入 Qt 或其它运行时依赖。
class JsonValue {
public:
    enum class Type { Null, Boolean, Number, String, Array, Object };

    using Array = std::vector<JsonValue>;
    using Object = std::map<std::string, JsonValue>;

    JsonValue();
    explicit JsonValue(bool value);
    explicit JsonValue(double value);
    explicit JsonValue(std::string value);
    explicit JsonValue(Array value);
    explicit JsonValue(Object value);

    Type type() const { return type_; }
    bool isObject() const { return type_ == Type::Object; }
    bool isArray() const { return type_ == Type::Array; }
    bool isString() const { return type_ == Type::String; }
    bool isNumber() const { return type_ == Type::Number; }
    bool isBoolean() const { return type_ == Type::Boolean; }
    const Object& object() const { return object_; }
    const Array& array() const { return array_; }
    const std::string& string() const { return string_; }
    double number() const { return number_; }
    bool boolean() const { return boolean_; }

    const JsonValue* get(const char* name) const;
    std::string stringOr(const char* name, const std::string& fallback) const;
    double numberOr(const char* name, double fallback) const;
    bool booleanOr(const char* name, bool fallback) const;

private:
    Type type_ = Type::Null;
    bool boolean_ = false;
    double number_ = 0.0;
    std::string string_;
    Array array_;
    Object object_;
};

// ParseJson 将 UTF-8 JSON 文本解析为 DOM；失败时返回 false 并填写错误描述。
bool ParseJson(const std::string& text, JsonValue* value, std::string* error);
// 仍校验整份 JSON，只保留指定根成员；用于 v4 元数据，避免复制几十万个驱动 item。
bool ParseJsonRootMembers(const std::string& text, const std::vector<std::string>& members,
    JsonValue* value, std::string* error);

// JsonEscape 将 UTF-8 字符串转为可嵌入 JSON 的字符串字面量内容。
std::string JsonEscape(const std::string& text);

}
