#pragma once

#include "ProjectDocument.h"
#include "../../../shared/evidence/EvidenceJson.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <initializer_list>
#include <array>

namespace Ksword::ActionAnalyze::ProjectStorage {

using Evidence::JsonArray;
using Evidence::JsonObject;
using Evidence::JsonType;
using Evidence::JsonValue;
using Parts = std::initializer_list<std::wstring_view>;

inline constexpr DWORD kMaxDocumentBytes = 4 * 1024 * 1024;
inline constexpr std::size_t kMaxTitleBytes = 1024;
inline constexpr std::size_t kMaxNotesBytes = 64 * 1024;

class Handle final {
public:
    Handle() = default;
    explicit Handle(HANDLE value) noexcept : value_(value) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept;
    Handle& operator=(Handle&& other) noexcept;
    explicit operator bool() const noexcept { return value_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return value_; }
    void reset() noexcept;

private:
    HANDLE value_ = INVALID_HANDLE_VALUE;
};

struct Directory {
    std::wstring path;
    std::vector<Handle> pins;
};

ProjectResult Failure(ProjectError error, const char* detail, DWORD native = 0);
ProjectResult WinFailure(const char* detail, DWORD native);
ProjectResult OpenRoot(std::wstring path, bool create, bool write, Directory& out);
ProjectResult OpenDirectory(const Directory& root, Parts parts, Directory& out, bool createLast = false);
ProjectResult OpenFile(const Directory& dir, std::wstring_view name, DWORD access, DWORD share,
                       DWORD disposition, Handle& out);
ProjectResult Read(const Directory& root, Parts dirs, std::wstring_view file,
                   std::string_view expectedHash, JsonValue& out, std::string* checkedHash = nullptr);
ProjectResult Publish(const Directory& root, Parts dirs, std::wstring_view file,
                      const JsonValue& doc, bool replace, std::string* hash = nullptr);
// 在只读固定句柄上核对有限前缀，调用者仍负责检查封装与身份。
// 借用同步读句柄，从文件头计算 byteCount 字节的散列。失败时清空 hash。
ProjectResult HashArchivePrefix(HANDLE file, std::uint64_t byteCount, std::string& hash);

bool IsUuid(std::string_view str);
// 仅接收已通过 IsUuid 校验的文本，按 A0 定义的顺序返回段头 UUID 字节。
std::array<std::uint8_t, 16> UuidBytes(std::string_view checkedUuid);
bool IsHash(std::string_view str);
bool IsText(std::string_view str, std::size_t maxBytes, bool multiline = false);
std::wstring WideAscii(std::string_view str);
ProjectResult NewId(std::string& out);
std::uint64_t UtcNow();
std::wstring NumberFile(std::uint64_t number);

JsonValue Object(JsonObject values);
JsonValue Text(std::string_view value);
JsonValue Number(std::uint64_t value);
bool Fields(const JsonValue& value, std::initializer_list<std::string_view> keys);
bool GetString(const JsonValue& object, std::string_view key, std::string& out);
bool GetUuid(const JsonValue& object, std::string_view key, std::string& out);
bool GetHash(const JsonValue& object, std::string_view key, std::string& out);
bool GetNumber(const JsonValue& object, std::string_view key, std::uint64_t& out);
bool IsString(const JsonValue& object, std::string_view key, std::string_view expected);
bool IsNull(const JsonValue& object, std::string_view key);
JsonValue Settings(const RevisionSettings& settings);
bool ParseSettings(const JsonValue& config, RevisionSettings& out);
ProjectResult ConfigHash(const RevisionSettings& settings, std::string& out);

} // namespace Ksword::ActionAnalyze::ProjectStorage
