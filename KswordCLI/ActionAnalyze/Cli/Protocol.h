#pragma once

#include "../../../shared/evidence/EvidenceJson.h"

#include <optional>
#include <string_view>

namespace ks::cli::action_analyze {

using Ksword::Evidence::JsonArray;
using Ksword::Evidence::JsonObject;
using Ksword::Evidence::JsonValue;

inline constexpr unsigned kSchemaVersion = 1;
inline constexpr std::size_t kInputBytes = 1u << 20;
inline constexpr std::size_t kOutputBytes = 256u << 10;
inline constexpr std::size_t kResultBytes = kOutputBytes - 2048; // 保留回执包络和转义后的 ID。
inline constexpr std::size_t kRequestIdBytes = 128;
inline constexpr std::size_t kDepth = 32;
inline constexpr std::size_t kObjectKeys = 128;
inline constexpr std::size_t kArrayItems = 4096;

struct Fault {
    const char* id = nullptr;
    const char* message = nullptr;
    std::optional<std::size_t> offset = std::nullopt;
    int code = 1;
    const char* source = "cli";
    unsigned nativeCode = 0;
    const char* stage = "offline";
    explicit operator bool() const { return id != nullptr; }
};

enum class RequestProfile { Offline, Live };

struct RequestSession {
    std::string id;
    std::string epoch;
};

struct Request {
    std::string id;
    std::string method;
    JsonValue params;
    std::optional<RequestSession> session = std::nullopt;
    std::optional<JsonValue> expected = std::nullopt;
};

struct Decoded {
    Request request;
    Fault error;
};

// offsets 均为零基 UTF-8 字节偏移。framing 不属于 JSON 解码器。
Decoded DecodeJsonLine(std::string_view line, RequestProfile profile = RequestProfile::Offline);
Decoded DecodeReplLine(std::string_view line);
JsonValue FaultJson(const Fault& error);
std::string CanonicalParams(const JsonValue& value);

} // namespace ks::cli::action_analyze
