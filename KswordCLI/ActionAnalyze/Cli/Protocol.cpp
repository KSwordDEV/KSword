#include "Protocol.h"

#include <algorithm>

namespace ks::cli::action_analyze {
namespace {
using namespace Ksword::Evidence;

std::optional<std::size_t> BadUtf8(std::string_view line) {
    for (std::size_t i = 0; i < line.size();) {
        const auto lead = static_cast<unsigned char>(line[i]);
        if (lead < 0x80) { ++i; continue; }
        if (lead < 0xc2 || lead > 0xf4) return i;
        const unsigned width = lead < 0xe0 ? 2 : lead < 0xf0 ? 3 : 4;
        if (line.size() - i < width) return i;
        for (unsigned j = 1; j < width; ++j) {
            const auto tail = static_cast<unsigned char>(line[i + j]);
            if (tail < 0x80 || tail > 0xbf) return i + j;
            if (j == 1 && ((lead == 0xe0 && tail < 0xa0) || (lead == 0xed && tail > 0x9f) ||
                           (lead == 0xf0 && tail < 0x90) || (lead == 0xf4 && tail > 0x8f))) return i;
        }
        i += width;
    }
    return std::nullopt;
}

Fault TextFault(std::string_view line) {
    if (line.starts_with("\xef\xbb\xbf")) return {"bom-rejected", "A UTF-8 BOM is forbidden", 0};
    if (const auto offset = BadUtf8(line)) return {"invalid-utf8", "Invalid UTF-8 sequence", offset};
    return {};
}

bool ValidId(std::string_view text) {
    return !text.empty() && text.size() <= kRequestIdBytes &&
        std::none_of(text.begin(), text.end(), [](unsigned char ch) { return ch < 0x20 || ch == 0x7f; });
}

Fault ShapeFault(const JsonValue& value, std::size_t depth = 1) {
    // 深度按容器计数，根对象为第 1 层。数组项数在底层解析时已经限制。
    if ((value.asObject() || value.asArray()) && depth > kDepth)
        return {"depth-limit", "JSON depth exceeds 32 containers"};
    if (const auto* object = value.asObject()) {
        if (object->size() > kObjectKeys) return {"size-limit", "JSON objects may have at most 128 keys"};
        for (const auto& entry : *object) if (const auto fault = ShapeFault(entry.second, depth + 1)) return fault;
    }
    if (const auto* array = value.asArray()) {
        for (const auto& item : *array) if (const auto fault = ShapeFault(item, depth + 1)) return fault;
    }
    return {};
}

bool Digit(char ch) { return ch >= '0' && ch <= '9'; }

Fault LexicalFault(std::string_view line) {
    // 底层读入十进制证据值时允许前导零。JSON 数字 token 不允许保留这种拼写。
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char ch = line[i];
        if (ch == '\r') return {"invalid-json", "Unexpected carriage return", i};
        if (quoted && ch == '\\' && i + 1 < line.size()) { ++i; continue; }
        if (ch == '"') { quoted = !quoted; continue; }
        if (!quoted && Digit(ch)) {
            if (ch == '0' && i + 1 < line.size() && Digit(line[i + 1]))
                return {"invalid-json", "A JSON number cannot contain a leading zero", i};
            while (i + 1 < line.size() && Digit(line[i + 1])) ++i;
        }
    }
    return {};
}

const char* ParseErrorId(JsonParseStatus status) {
    switch (status) {
    case JsonParseStatus::DuplicateKey: return "duplicate-key";
    case JsonParseStatus::FloatingPointRejected: return "floating-point-rejected";
    case JsonParseStatus::IntegerOverflow: return "integer-overflow";
    case JsonParseStatus::DepthLimit: return "depth-limit";
    case JsonParseStatus::NodeLimit:
    case JsonParseStatus::SizeLimit: return "size-limit";
    default: return "invalid-json";
    }
}

// 只识别空白、成对引号和引号内的双写引号。反斜杠保持原样，便于输入 Windows 路径。
bool ReplSpace(char ch) { return ch == ' ' || ch == '\t'; }

JsonValue Sorted(const JsonValue& value) {
    if (const auto* object = value.asObject()) {
        JsonObject sorted;
        for (const auto& [key, item] : *object) sorted.emplace_back(key, Sorted(item));
        std::sort(sorted.begin(), sorted.end(), [](const auto& a, const auto& b) { return a.first < b.first; });
        return JsonValue::makeObject(std::move(sorted));
    }
    if (const auto* array = value.asArray()) {
        JsonArray sorted;
        for (const auto& item : *array) sorted.push_back(Sorted(item));
        return JsonValue::makeArray(std::move(sorted));
    }
    return value;
}
} // namespace

Decoded DecodeJsonLine(std::string_view line, RequestProfile profile) {
    if (const auto fault = TextFault(line)) return {{}, fault};
    if (const auto fault = LexicalFault(line)) return {{}, fault};
    JsonLimits limits;
    limits.maxDepth = kDepth;
    limits.maxStringBytes = kInputBytes;
    limits.maxTotalBytes = kInputBytes;
    limits.maxContainerItems = kArrayItems;
    limits.maxTotalNodes = 65536;
    const auto parsed = ParseJson(line, limits);
    if (!parsed.ok()) return {{}, {ParseErrorId(parsed.status), JsonParseStatusName(parsed.status), parsed.errorOffset}};
    const auto* fields = parsed.value.asObject();
    if (!fields) return {{}, {"invalid-request", "Request must be an object"}};
    Decoded decoded;
    const auto* id = parsed.value.find("requestId");
    if (!id || !id->tryGetString(decoded.request.id) || !ValidId(decoded.request.id))
        return {{}, {"invalid-request-id", "requestId must be a nonempty string of at most 128 UTF-8 bytes without control characters"}};
    const auto fail = [&](const char* code, const char* message) {
        decoded.error = {code, message};
        return std::move(decoded);
    };
    if (const auto fault = ShapeFault(parsed.value)) { decoded.error = fault; return decoded; }
    for (const auto& [key, unused] : *fields) {
        if (key == "schemaVersion" || key == "requestId" || key == "method" || key == "params") continue;
        if (profile == RequestProfile::Live && (key == "session" || key == "expected")) continue;
        return fail("unknown-field", profile == RequestProfile::Offline
            ? "Unexpected request field for this offline controller" : "Unexpected request field for this live controller");
    }
    const auto* version = parsed.value.find("schemaVersion");
    std::uint64_t number = 0;
    if (!version || version->type() != JsonType::UInt || !version->tryGetU64(number))
        return fail("invalid-schema-version", "schemaVersion must be an unsigned JSON integer");
    if (number != kSchemaVersion) return fail("unsupported-schema-version", "Expected schemaVersion 1");
    const auto* method = parsed.value.find("method");
    if (!method || !method->tryGetString(decoded.request.method) || !ValidId(decoded.request.method))
        return fail("invalid-method", "method must be a nonempty string of at most 128 UTF-8 bytes without control characters");
    const auto* params = parsed.value.find("params");
    if (!params || !params->asObject()) return fail("invalid-params", "params must be an object");
    decoded.request.params = *params;
    if (const auto* session = parsed.value.find("session")) {
        RequestSession identity;
        const auto* sessionId = session->find("id");
        const auto* epoch = session->find("epoch");
        if (!session->asObject() || session->asObject()->size() != 2 ||
            !sessionId || !sessionId->tryGetString(identity.id) || !ValidId(identity.id) ||
            !epoch || !epoch->tryGetString(identity.epoch) || !ValidId(identity.epoch)) {
            return fail("invalid-session", "session requires exactly id and epoch as bounded strings");
        }
        decoded.request.session = std::move(identity);
    }
    if (const auto* expected = parsed.value.find("expected")) {
        if (!expected->asObject()) return fail("invalid-expected", "expected must be an object when present");
        decoded.request.expected = *expected;
    }
    return decoded;
}

Decoded DecodeReplLine(std::string_view line) {
    if (const auto fault = TextFault(line)) return {{}, fault};
    constexpr std::size_t kMaxReplWords = 9; // 两段命令名加上归档图续页所需的七个参数。
    std::vector<std::string> words;
    for (std::size_t i = 0; i < line.size();) {
        if (ReplSpace(line[i])) { ++i; continue; }
        if (words.size() == kMaxReplWords) {
            return {{}, {"invalid-repl", "Too many command arguments", i}};
        }
        std::string word;
        if (line[i] == '"') {
            const std::size_t start = i++;
            bool closed = false;
            while (i < line.size()) {
                if (line[i] != '"') { word += line[i++]; continue; }
                ++i;
                if (i == line.size() || line[i] != '"') { closed = true; break; }
                word += line[i++];
            }
            if (!closed) return {{}, {"invalid-repl", "Unterminated quote", start}};
            if (i < line.size() && !ReplSpace(line[i])) return {{}, {"invalid-repl", "Expected whitespace after quote", i}};
        } else {
            while (i < line.size() && !ReplSpace(line[i])) {
                if (line[i] == '"') return {{}, {"invalid-repl", "A quoted argument must start with a quote", i}};
                word += line[i++];
            }
        }
        if (word.find_first_of("\r\n\0", 0, 3) != std::string::npos)
            return {{}, {"invalid-repl", "Unexpected control character"}};
        words.push_back(std::move(word));
    }
    if (words.empty()) return {};
    // 人类子命令的映射与参数验证由真实方法目录处理。
    JsonArray args;
    for (std::size_t i = 1; i < words.size(); ++i) args.push_back(JsonValue::makeString(std::move(words[i])));
    return {{{}, std::move(words[0]), JsonValue::makeArray(std::move(args))}, {}};
}

JsonValue FaultJson(const Fault& error) {
    using V = JsonValue;
    if (!error) return V::makeNull();
    return V::makeObject({{"errorId", V::makeString(error.id)}, {"message", V::makeString(error.message)},
        {"source", V::makeString(error.source)}, {"code", V::makeUInt(error.nativeCode ? error.nativeCode : error.code)},
        {"retryability", V::makeString("none")}, {"stage", V::makeString(error.stage)},
        {"byteOffset", error.offset ? V::makeUInt(*error.offset) : V::makeNull()}});
}

std::string CanonicalParams(const JsonValue& value) {
    return WriteJson(Sorted(value));
}

} // namespace ks::cli::action_analyze
