#include "ProjectStorage.h"

#include <bcrypt.h>
#include <objbase.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <limits>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ole32.lib")

namespace Ksword::ActionAnalyze::ProjectStorage {
namespace {

constexpr std::wstring_view kLongPathPrefix = L"\\\\?\\";

bool SafeName(std::wstring_view name) {
    if (name.empty() || name == L"." || name == L".." || name.back() == L'.' || name.back() == L' ' ||
        name.find_first_of(L"/\\:<>\"|?*") != name.npos) return false;
    if (std::any_of(name.begin(), name.end(), [](wchar_t c) { return c < 32; })) return false;
    const auto base = name.substr(0, name.find(L'.'));
    const auto same = [](std::wstring_view a, std::wstring_view b) {
        return CompareStringOrdinal(a.data(), static_cast<int>(a.size()), b.data(),
                                    static_cast<int>(b.size()), TRUE) == CSTR_EQUAL;
    };
    if (!base.empty() && (same(base, L"CON") || same(base, L"PRN") || same(base, L"AUX") ||
                          same(base, L"NUL") || same(base, L"CONIN$") || same(base, L"CONOUT$"))) return false;
    return base.size() != 4 ||
           (!(same(base.substr(0, 3), L"COM") || same(base.substr(0, 3), L"LPT"))) ||
           std::wstring_view(L"123456789¹²³").find(base.back()) == base.npos;
}

std::wstring Join(const std::wstring& path, std::wstring_view name) {
    auto result = path;
    if (result.back() != L'\\') result += L'\\';
    result += name;
    return result;
}

ProjectResult VerifyHandle(const Handle& handle, const std::wstring& path, bool directory) {
    BY_HANDLE_FILE_INFORMATION info{};
    if (!GetFileInformationByHandle(handle.get(), &info)) return WinFailure("fileIdentity", GetLastError());
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
        ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) != directory ||
        (!directory && (info.nNumberOfLinks != 1 || GetFileType(handle.get()) != FILE_TYPE_DISK))) {
        return Failure(ProjectError::UnsafePath, "fileIdentity");
    }

    // 校验实际句柄路径。父目录句柄不共享删除，后续操作不穿过可替换的祖先。
    std::wstring finalPath(path.size() + 2, L'\0');
    const auto capacity = static_cast<DWORD>(finalPath.size());
    const DWORD size = GetFinalPathNameByHandleW(handle.get(), finalPath.data(), capacity,
                                               FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
    if (size == 0) return WinFailure("finalPath", GetLastError());
    if (size >= capacity || CompareStringOrdinal(path.data(), static_cast<int>(path.size()),
            finalPath.data(), static_cast<int>(size), TRUE) != CSTR_EQUAL) {
        return Failure(ProjectError::UnsafePath, "finalPath");
    }
    return {};
}

ProjectResult PinDirectory(const std::wstring& path, bool create, Directory& out) {
    if (create && !CreateDirectoryW(path.c_str(), nullptr)) return WinFailure("createDirectory", GetLastError());
    Handle handle(CreateFileW(path.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                              nullptr));
    if (!handle) return WinFailure("openDirectory", GetLastError());
    if (auto result = VerifyHandle(handle, path, true); !result) return result;
    out.path = path;
    out.pins.emplace_back(std::move(handle));
    return {};
}

ProjectResult CheckWriteVolume(const Directory& drive) {
    wchar_t filesystem[32]{};
    if (!GetVolumeInformationByHandleW(drive.pins.back().get(), nullptr, 0, nullptr, nullptr,
                                       nullptr, filesystem, ARRAYSIZE(filesystem))) {
        return WinFailure("volumeInfo", GetLastError());
    }
    return std::wstring_view(filesystem) == L"NTFS" ? ProjectResult{}
        : Failure(ProjectError::Unsupported, "writeRequiresNtfs");
}

bool IsUtf8(std::string_view value) {
    return value.empty() || MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(),
                                                static_cast<int>(value.size()), nullptr, 0) != 0;
}

bool HasStrictNumbers(std::string_view bytes) {
    // EvidenceJson 允许宽松整数。仅在字符串外检查数字词素，其余语法交给原解析器。
    bool inString = false;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const char c = bytes[i];
        if (c == '"') inString = !inString;
        else if (inString && c == '\\') ++i;
        else if (!inString && c >= '0' && c <= '9') {
            const std::size_t start = i;
            while (i + 1 < bytes.size() && bytes[i + 1] >= '0' && bytes[i + 1] <= '9') ++i;
            if (i != start && c == '0') return false;
        }
    }
    return true;
}

constexpr char kHex[] = "0123456789abcdef";

ProjectResult Sha256(std::string_view bytes, std::string& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if (status < 0) return Failure(ProjectError::IoError, "sha256Provider", static_cast<DWORD>(status));
    unsigned char digest[32]{};
    auto* input = reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data()));
    status = BCryptHash(alg, nullptr, 0, input, static_cast<ULONG>(bytes.size()), digest, sizeof(digest));
    BCryptCloseAlgorithmProvider(alg, 0);
    if (status < 0) return Failure(ProjectError::IoError, "sha256", static_cast<DWORD>(status));
    out.clear();
    out.reserve(sizeof(digest) * 2);
    for (auto byte : digest) {
        out.push_back(kHex[byte >> 4]);
        out.push_back(kHex[byte & 15]);
    }
    return {};
}

void CanonicalString(std::string_view text, std::string& out) {
    out += '"';
    for (char c : text) {
        if (c == '"' || c == '\\') out += '\\';
        if (const auto byte = static_cast<unsigned char>(c); byte < 32) {
            out += "\\u00";
            out += kHex[byte >> 4];
            out += kHex[byte & 15];
        } else {
            out += c;
        }
    }
    out += '"';
}

ProjectResult ReadBytes(const Handle& file, std::string& out) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file.get(), &size)) return WinFailure("documentSize", GetLastError());
    if (size.QuadPart <= 0) return Failure(ProjectError::Corrupt, "documentEmpty");
    if (size.QuadPart > kMaxDocumentBytes) return Failure(ProjectError::LimitExceeded, "documentSize");
    const auto bytes = static_cast<DWORD>(size.QuadPart);
    out.resize(bytes);
    DWORD got = 0;
    if (!ReadFile(file.get(), out.data(), bytes, &got, nullptr)) return WinFailure("documentRead", GetLastError());
    if (got != bytes) return Failure(ProjectError::Corrupt, "shortDocumentRead");
    return {};
}

ProjectResult RenameDocument(const Handle& source, const std::wstring& target, bool replace) {
    const auto nameBytes = target.size() * sizeof(wchar_t);
    const auto size = offsetof(FILE_RENAME_INFO, FileName) + nameBytes + sizeof(wchar_t);
    std::vector<std::uint64_t> buffer((size + sizeof(std::uint64_t) - 1) / sizeof(std::uint64_t));
    auto* info = reinterpret_cast<FILE_RENAME_INFO*>(buffer.data());
    info->ReplaceIfExists = replace ? TRUE : FALSE;
    info->FileNameLength = static_cast<DWORD>(nameBytes);
    std::memcpy(info->FileName, target.data(), nameBytes);
    for (unsigned attempt = 0; ; ++attempt) {
        if (SetFileInformationByHandle(source.get(), FileRenameInfo, info, static_cast<DWORD>(size))) return {};
        const DWORD error = GetLastError();
        if (error != ERROR_SHARING_VIOLATION || attempt == 2) return WinFailure("documentRename", error);
        Sleep(10);
    }
}

} // namespace

// 调用方保留同步读句柄的所有权，并在散列期间禁止修改该文件。
ProjectResult HashArchivePrefix(HANDLE file, std::uint64_t byteCount, std::string& hash) {
    hash.clear();
    if (!byteCount || byteCount > kMaxDocumentBytes) {
        return Failure(ProjectError::LimitExceeded, "archivePrefixSize");
    }
    LARGE_INTEGER begin{}; // 从固定前缀的起点读取。
    if (!SetFilePointerEx(file, begin, nullptr, FILE_BEGIN)) {
        return WinFailure("archivePrefixSeek", GetLastError());
    }
    std::string bytes(static_cast<std::size_t>(byteCount), '\0'); // 配额内的待读字节。
    DWORD got = 0; // 本次实际读取的字节数。
    if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &got, nullptr)) {
        return WinFailure("archivePrefixRead", GetLastError());
    }
    if (got != byteCount) return Failure(ProjectError::Corrupt, "shortArchivePrefix");
    return Sha256(bytes, hash);
}

std::array<std::uint8_t, 16> UuidBytes(std::string_view checkedUuid) {
    const auto digit = [](char c) { return c <= '9' ? c - '0' : c - 'a' + 10; };
    std::array<std::uint8_t, 16> bytes{};
    std::size_t offset = 0;
    // 输入已由项目文档校验。按文本顺序取字节，保持与段头的 UUID 一致。
    for (auto& byte : bytes) {
        if (checkedUuid[offset] == '-') ++offset;
        byte = static_cast<std::uint8_t>((digit(checkedUuid[offset]) << 4) | digit(checkedUuid[offset + 1]));
        offset += 2;
    }
    return bytes;
}

Handle::Handle(Handle&& other) noexcept : value_(other.value_) { other.value_ = INVALID_HANDLE_VALUE; }

Handle& Handle::operator=(Handle&& other) noexcept {
    if (&other != this) {
        reset();
        value_ = other.value_;
        other.value_ = INVALID_HANDLE_VALUE;
    }
    return *this;
}

void Handle::reset() noexcept {
    if (*this) {
        CloseHandle(value_);
        value_ = INVALID_HANDLE_VALUE;
    }
}

ProjectResult Failure(ProjectError error, const char* detail, DWORD native) { return {error, native, detail}; }

ProjectResult WinFailure(const char* detail, DWORD native) {
    auto error = ProjectError::IoError;
    if (native == ERROR_FILE_NOT_FOUND || native == ERROR_PATH_NOT_FOUND) error = ProjectError::NotFound;
    if (native == ERROR_FILE_EXISTS || native == ERROR_ALREADY_EXISTS) error = ProjectError::AlreadyExists;
    return Failure(error, detail, native);
}

ProjectResult OpenRoot(std::wstring path, bool create, bool write, Directory& out) {
    if (path.empty() || path.find(L'\0') != path.npos) return Failure(ProjectError::InvalidArgument, "projectPath");
    std::replace(path.begin(), path.end(), L'/', L'\\');
    if (path.starts_with(L"\\\\")) return Failure(ProjectError::Unsupported, "localDriveOnly");

    std::wstring absolute(32768, L'\0');
    const auto capacity = static_cast<DWORD>(absolute.size());
    const DWORD size = GetFullPathNameW(path.c_str(), capacity, absolute.data(), nullptr);
    if (!size) return WinFailure("absolutePath", GetLastError());
    if (size >= capacity - 100) return Failure(ProjectError::LimitExceeded, "projectPath");
    absolute.resize(size);
    if (size < 4 || absolute[1] != L':' || absolute[2] != L'\\') {
        return Failure(ProjectError::InvalidArgument, "projectPath");
    }
    const auto drive = absolute.substr(0, 3);
    const auto driveType = GetDriveTypeW(drive.c_str());
    if (driveType != DRIVE_FIXED && driveType != DRIVE_REMOVABLE) {
        return Failure(ProjectError::Unsupported, "localDriveOnly");
    }
    if (absolute.back() == L'\\') absolute.pop_back();

    Directory pinned;
    if (auto result = PinDirectory(std::wstring(kLongPathPrefix) + drive, false, pinned); !result) return result;
    if (write) {
        if (auto result = CheckWriteVolume(pinned); !result) return result;
    }
    for (std::size_t start = 3; start < absolute.size();) {
        const auto end = absolute.find(L'\\', start);
        const auto part = std::wstring_view(absolute).substr(start, end - start);
        if (!SafeName(part)) return Failure(ProjectError::UnsafePath, "pathComponent");
        if (auto result = PinDirectory(Join(pinned.path, part), create && end == absolute.npos, pinned);
            !result) return result;
        if (end == absolute.npos) break;
        start = end + 1;
    }
    if (pinned.pins.size() == 1) return Failure(ProjectError::InvalidArgument, "projectPath");
    out = std::move(pinned);
    return {};
}

ProjectResult OpenDirectory(const Directory& root, Parts parts, Directory& out, bool createLast) {
    Directory pinned;
    pinned.path = root.path;
    for (auto it = parts.begin(); it != parts.end(); ++it) {
        if (!SafeName(*it)) return Failure(ProjectError::UnsafePath, "pathComponent");
        if (auto result = PinDirectory(Join(pinned.path, *it), createLast && it + 1 == parts.end(), pinned);
            !result) return result;
    }
    out = std::move(pinned);
    return {};
}

ProjectResult OpenFile(const Directory& dir, std::wstring_view name, DWORD access, DWORD share,
                       DWORD disposition, Handle& out) {
    if (!SafeName(name)) return Failure(ProjectError::UnsafePath, "fileName");
    const auto path = Join(dir.path, name);
    Handle file(CreateFileW(path.c_str(), access, share, nullptr, disposition, FILE_FLAG_OPEN_REPARSE_POINT,
                            nullptr));
    if (!file) return WinFailure("openFile", GetLastError());
    if (auto result = VerifyHandle(file, path, false); !result) return result;
    out = std::move(file);
    return {};
}

ProjectResult Read(const Directory& root, Parts dirs, std::wstring_view name,
                   std::string_view expectedHash, JsonValue& out, std::string* checkedHash) {
    Directory directory;
    if (auto result = OpenDirectory(root, dirs, directory); !result) return result;
    Handle file;
    for (unsigned attempt = 0; ; ++attempt) {
        auto result = OpenFile(directory, name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                               OPEN_EXISTING, file);
        if (result) break;
        if (result.nativeError != ERROR_SHARING_VIOLATION || attempt == 2) return result;
        Sleep(10);
    }
    std::string bytes;
    if (auto result = ReadBytes(file, bytes); !result) return result;
    if (checkedHash || !expectedHash.empty()) {
        std::string actual;
        if (auto result = Sha256(bytes, actual); !result) return result;
        if (!expectedHash.empty() && actual != expectedHash) return Failure(ProjectError::Corrupt, "documentHash");
        if (checkedHash) *checkedHash = std::move(actual);
    }
    if (bytes.starts_with("\xef\xbb\xbf") || bytes.find('\r') != bytes.npos ||
        !IsUtf8(bytes) || !HasStrictNumbers(bytes)) return Failure(ProjectError::Corrupt, "documentEncoding");
    Evidence::JsonLimits limits;
    limits.maxDepth = 32;
    limits.maxStringBytes = 64 * 1024;
    limits.maxTotalBytes = kMaxDocumentBytes;
    limits.maxContainerItems = kProjectCatalogPageSize;
    limits.maxTotalNodes = 4096;
    auto parsed = Evidence::ParseJson(bytes, limits);
    if (!parsed.ok()) return Failure(ProjectError::Corrupt, Evidence::JsonParseStatusName(parsed.status));
    out = std::move(parsed.value);
    return {};
}

ProjectResult Publish(const Directory& root, Parts dirs, std::wstring_view name,
                      const JsonValue& doc, bool replace, std::string* hash) {
    Directory target;
    if (auto result = OpenDirectory(root, dirs, target); !result) return result;
    if (!SafeName(name)) return Failure(ProjectError::UnsafePath, "fileName");
    if (replace) {
        Handle old;
        const auto result = OpenFile(target, name, FILE_READ_ATTRIBUTES,
                                     FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, OPEN_EXISTING, old);
        if (!result && result.error != ProjectError::NotFound) return result;
    }

    auto bytes = Evidence::WriteJson(doc);
    bytes += '\n';
    if (bytes.size() > kMaxDocumentBytes) return Failure(ProjectError::LimitExceeded, "documentSize");
    std::string expected;
    if (auto result = Sha256(bytes, expected); !result) return result;

    Directory staging;
    if (auto result = OpenDirectory(root, {L".staging"}, staging); !result) return result;
    std::string id;
    if (auto result = NewId(id); !result) return result;
    Handle staged;
    if (auto result = OpenFile(staging, WideAscii(id) + L".partial", GENERIC_READ | GENERIC_WRITE | DELETE,
                               FILE_SHARE_READ, CREATE_NEW, staged); !result) return result;
    const auto toWrite = static_cast<DWORD>(bytes.size());
    DWORD written = 0;
    if (!WriteFile(staged.get(), bytes.data(), toWrite, &written, nullptr)) {
        return WinFailure("documentWrite", GetLastError());
    }
    if (written != toWrite) return Failure(ProjectError::IoError, "shortDocumentWrite");
    if (!FlushFileBuffers(staged.get())) return WinFailure("documentFlush", GetLastError());
    LARGE_INTEGER start{};
    if (!SetFilePointerEx(staged.get(), start, nullptr, FILE_BEGIN)) return WinFailure("documentSeek", GetLastError());
    std::string verified;
    if (auto result = ReadBytes(staged, verified); !result) return result;
    if (verified != bytes) return Failure(ProjectError::Corrupt, "documentVerify");

    // 用已验过的 staging 句柄发布，同 ID 文件采用不覆盖的重命名。
    if (auto result = RenameDocument(staged, Join(target.path, name), replace); !result) return result;
    if (hash) *hash = std::move(expected);
    return {};
}

bool IsHash(std::string_view value) {
    return value.size() == 64 && value.find_first_not_of("0123456789abcdef") == value.npos;
}

bool IsUuid(std::string_view value) {
    if (value.size() != 36 || value == "00000000-0000-0000-0000-000000000000") return false;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (value[i] != '-') return false;
        } else if (std::string_view(kHex).find(value[i]) == std::string_view::npos) {
            return false;
        }
    }
    return true;
}

bool IsText(std::string_view value, std::size_t maxBytes, bool multiline) {
    if (value.size() > maxBytes || (!multiline && value.empty()) || !IsUtf8(value)) return false;
    for (unsigned char byte : value) {
        if (byte < 32 && !(multiline && (byte == '\n' || byte == '\t'))) return false;
    }
    return true;
}

std::wstring WideAscii(std::string_view text) { return {text.begin(), text.end()}; }

ProjectResult NewId(std::string& out) {
    GUID id{};
    const HRESULT result = CoCreateGuid(&id);
    if (FAILED(result)) return Failure(ProjectError::IoError, "createUuid", static_cast<DWORD>(result));
    wchar_t string[39]{};
    if (StringFromGUID2(id, string, ARRAYSIZE(string)) != ARRAYSIZE(string)) {
        return Failure(ProjectError::IoError, "formatUuid");
    }
    out.clear();
    out.reserve(36);
    for (std::size_t i = 1; i <= 36; ++i) {
        const wchar_t c = string[i];
        out.push_back(static_cast<char>(c >= L'A' && c <= L'F' ? c + (L'a' - L'A') : c));
    }
    return {};
}

std::uint64_t UtcNow() {
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return (static_cast<std::uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

std::wstring NumberFile(std::uint64_t number) { return std::to_wstring(number) + L".json"; }

JsonValue Object(JsonObject values) { return JsonValue::makeObject(std::move(values)); }
JsonValue Text(std::string_view value) { return JsonValue::makeString(std::string(value)); }
JsonValue Number(std::uint64_t value) { return JsonValue::makeString(std::to_string(value)); }

bool Fields(const JsonValue& value, std::initializer_list<std::string_view> keys) {
    const auto* object = value.asObject();
    if (!object || object->size() != keys.size()) return false;
    for (auto key : keys) if (!value.find(key)) return false;
    return true;
}

bool GetString(const JsonValue& object, std::string_view key, std::string& out) {
    const auto* field = object.find(key);
    return field && field->tryGetString(out);
}

bool GetUuid(const JsonValue& object, std::string_view key, std::string& out) {
    return GetString(object, key, out) && IsUuid(out);
}

bool GetHash(const JsonValue& object, std::string_view key, std::string& out) {
    return GetString(object, key, out) && IsHash(out);
}

bool GetNumber(const JsonValue& object, std::string_view key, std::uint64_t& out) {
    std::string value;
    if (!GetString(object, key, value) || value.empty() || (value[0] == '0' && value.size() != 1) ||
        value.find_first_not_of("0123456789") != value.npos) return false;
    const auto end = value.data() + value.size();
    const auto parsed = std::from_chars(value.data(), end, out);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

bool IsString(const JsonValue& object, std::string_view key, std::string_view expected) {
    std::string actual;
    return GetString(object, key, actual) && actual == expected;
}

bool IsNull(const JsonValue& object, std::string_view key) {
    const auto* field = object.find(key);
    return field && field->isNull();
}

namespace {

// 定义文本先按 UTF-8 校验，再检查单行展示不应包含的控制和分隔字符。
bool IsDefinitionText(std::string_view text, std::size_t limit) {
    if (!IsText(text, limit) || text.front() == ' ' || text.back() == ' ') return false;
    for (std::size_t index = 0; index < text.size(); ++index) {
        const auto byte = static_cast<unsigned char>(text[index]);
        if (byte == 0x7f) return false;
        if (byte == 0xc2 && index + 1 < text.size()) {
            const auto next = static_cast<unsigned char>(text[index + 1]);
            if (next >= 0x80 && next <= 0x9f) return false;
        }
    }
    return text.find("\xe2\x80\xa8") == text.npos && text.find("\xe2\x80\xa9") == text.npos;
}

// 校验离线位置和模块标识，适用于草稿和存盘值。
bool IsDefinitionBody(const BreakpointDefinition& row) {
    const auto& module = row.module;
    if (row.condition && (row.condition->source.empty() || !IsText(row.condition->source, 8192)))
    {
        return false; // 不在存储层绑定原生字段；正式激活前仍须完成类型化条件准备。
    }
    if (!IsDefinitionText(module.name, 255) || module.name.back() == '.' ||
        module.name.find_first_of("/\\:*?\"<>|") != module.name.npos ||
        (module.imageSha256 && !IsHash(*module.imageSha256))) return false;
    if (std::holds_alternative<BreakpointRva>(row.location)) return true;
    const auto* symbol = std::get_if<BreakpointSymbol>(&row.location);
    return symbol && IsDefinitionText(symbol->symbol, 512) &&
        (!symbol->pdb || (IsUuid(symbol->pdb->guid) && symbol->pdb->age != 0));
}

// 稳定比较模块标签的 ASCII 大小写，避免依赖宿主界面语言或 Unicode 映射。
char FoldModuleAscii(char value) {
    return value >= 'A' && value <= 'Z' ? static_cast<char>(value + ('a' - 'A')) : value;
}

bool SameLocation(const BreakpointDefinition& left, const BreakpointDefinition& right) {
    const auto& a = left.module.name;
    const auto& b = right.module.name;
    return left.location == right.location && left.module.imageSha256 == right.module.imageSha256 &&
        std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char x, char y) {
            return FoldModuleAscii(x) == FoldModuleAscii(y);
        });
}

// 定义集合很小，逐项比较以避免再建一份规范定位键编码。
bool HasLocation(const std::vector<BreakpointDefinition>& rows, const BreakpointDefinition& row) {
    return std::any_of(rows.begin(), rows.end(), [&](const BreakpointDefinition& existing) {
        return SameLocation(existing, row);
    });
}

// 写入定义集合。所有对象键以字节顺序构造，字段校验排除了需特殊规范转义的 C0。
JsonValue DefinitionLocationJson(const BreakpointDefinition& row) {
    if (const auto* rva = std::get_if<BreakpointRva>(&row.location)) {
        return Object({{"kind", Text("module-rva")}, {"rva", Number(rva->rva)}});
    }
    const auto& symbol = std::get<BreakpointSymbol>(row.location);
    auto pdb = symbol.pdb ? Object({{"age", Number(symbol.pdb->age)}, {"guid", Text(symbol.pdb->guid)}})
                          : JsonValue::makeNull();
    return Object({{"kind", Text("module-symbol")}, {"pdb", std::move(pdb)}, {"symbol", Text(symbol.symbol)}});
}

JsonValue DefinitionsJson(const std::vector<BreakpointDefinition>& rows) {
    JsonArray result;
    result.reserve(rows.size());
    for (const auto& row : rows) {
        auto module = Object({{"imageSha256", row.module.imageSha256 ? Text(*row.module.imageSha256) : JsonValue::makeNull()},
                              {"name", Text(row.module.name)}});
        JsonObject fields{{"breakpointDefinitionId", Text(row.breakpointDefinitionId)},
            {"definitionRevision", Number(row.definitionRevision)}, {"enabled", JsonValue::makeBool(row.enabled)},
            {"location", DefinitionLocationJson(row)}, {"module", std::move(module)}}; // 旧无条件形状保持原键顺序。
        if (row.condition)
        {
            fields.insert(fields.begin() + 1, {"condition", Object({{"expressionProfile", Text("predicate-expr-v3")},
                {"source", Text(row.condition->source)}})}); // 原文及版本按键序进入修订散列。
        }
        result.push_back(Object(std::move(fields)));
    }
    return JsonValue::makeArray(std::move(result));
}

// 用现有十进制解析器读取后检查目标字段宽度。
bool ReadU32(const JsonValue& doc, std::string_view key, std::uint32_t& out) {
    std::uint64_t value = 0;
    if (!GetNumber(doc, key, value) || value > std::numeric_limits<std::uint32_t>::max()) return false;
    out = static_cast<std::uint32_t>(value);
    return true;
}

// 读取唯一的定位分支，拒绝其它分支的字段和未知种类。
bool ReadLocation(const JsonValue& doc, BreakpointDefinition& row) {
    if (IsString(doc, "kind", "module-rva")) {
        BreakpointRva rva;
        if (!Fields(doc, {"kind", "rva"}) || !ReadU32(doc, "rva", rva.rva)) return false;
        row.location = rva;
        return true;
    }
    BreakpointSymbol symbol;
    if (!IsString(doc, "kind", "module-symbol") || !Fields(doc, {"kind", "symbol", "pdb"}) ||
        !GetString(doc, "symbol", symbol.symbol)) return false;
    const auto& pdb = *doc.find("pdb");
    if (!pdb.isNull()) {
        BreakpointPdb identity;
        if (!Fields(pdb, {"guid", "age"}) || !GetUuid(pdb, "guid", identity.guid) ||
            !ReadU32(pdb, "age", identity.age) || identity.age == 0) return false;
        symbol.pdb = std::move(identity);
    }
    row.location = std::move(symbol);
    return true;
}

// 读取单条定义。草稿允许显式的新项标记，已存文件要求已分配的身份。
bool ReadDefinition(const JsonValue& doc, BreakpointDefinition& row, bool draft) {
    const auto* condition = doc.find("condition"); // 缺字段是旧无条件定义；null不等于显式清空原规则。
    const bool shape = condition
        ? Fields(doc, {"breakpointDefinitionId", "definitionRevision", "enabled", "module", "location", "condition"})
        : Fields(doc, {"breakpointDefinitionId", "definitionRevision", "enabled", "module", "location"});
    if (!shape ||
        !GetString(doc, "breakpointDefinitionId", row.breakpointDefinitionId) ||
        !GetNumber(doc, "definitionRevision", row.definitionRevision) ||
        !doc.find("enabled")->tryGetBool(row.enabled)) return false;
    const bool newDraft = draft && row.breakpointDefinitionId.empty() && row.definitionRevision == 0; // 新项由写入器分配身份。
    if (!newDraft && (!IsUuid(row.breakpointDefinitionId) || row.definitionRevision == 0)) {
        return false;
    }
    row.condition.reset(); // 复用输出对象时不能把旧条件带入没有该字段的定义。
    if (condition)
    {
        BreakpointCondition predicate; // 只读明确v3来源，未知profile拒绝而不重标版本。
        if (!Fields(*condition, {"expressionProfile", "source"}) ||
            !IsString(*condition, "expressionProfile", "predicate-expr-v3") ||
            !GetString(*condition, "source", predicate.source))
        {
            return false;
        }
        row.condition = std::move(predicate);
    }
    const auto& module = *doc.find("module"); // 模块字段在两种配置形状中一致。
    if (!Fields(module, {"name", "imageSha256"}) || !GetString(module, "name", row.module.name)) return false;
    if (!IsNull(module, "imageSha256")) {
        std::string hash; // 输入提供的可选映像散列。
        if (!GetHash(module, "imageSha256", hash)) return false;
        row.module.imageSha256 = std::move(hash);
    }
    return ReadLocation(*doc.find("location"), row) && IsDefinitionBody(row);
}

// 分配草稿行身份或比较其基准，已删除和来自别的修订的 ID 不可重新提交。
ProjectResult PrepareDefinition(BreakpointDefinition& row, const std::vector<BreakpointDefinition>& base,
                                const std::vector<BreakpointDefinition>& prepared) {
    const auto hasId = [&](const std::vector<BreakpointDefinition>& rows) {
        return std::find_if(rows.begin(), rows.end(), [&](const BreakpointDefinition& existing) {
            return row.breakpointDefinitionId == existing.breakpointDefinitionId;
        });
    };
    if (row.breakpointDefinitionId.empty()) {
        if (row.definitionRevision) return Failure(ProjectError::InvalidArgument, "newBreakpointRevision");
        if (auto result = NewId(row.breakpointDefinitionId); !result) return result;
        if (!IsUuid(row.breakpointDefinitionId) || hasId(base) != base.end() || hasId(prepared) != prepared.end()) {
            return Failure(ProjectError::IoError, "createBreakpointId");
        }
        row.definitionRevision = 1;
        return {};
    }

    // 当前定义版本标记作为逐项基准，变化才递增持久修订。
    const auto previous = hasId(base);
    if (!IsUuid(row.breakpointDefinitionId) || previous == base.end() || hasId(prepared) != prepared.end()) {
        return Failure(ProjectError::InvalidArgument, "breakpointDefinitionId");
    }
    if (row.definitionRevision != previous->definitionRevision) {
        return Failure(ProjectError::StaleRevision, "breakpointDefinitionRevision");
    }
    if (row != *previous) {
        if (row.definitionRevision == std::numeric_limits<std::uint64_t>::max()) {
            return Failure(ProjectError::LimitExceeded, "breakpointDefinitionRevision");
        }
        ++row.definitionRevision;
    }
    return {};
}

} // namespace

JsonValue Settings(const RevisionSettings& settings) {
    JsonObject fields{{"title", Text(settings.title)}, {"notes", Text(settings.notes)}};
    if (settings.breakpointDefinitions) {
        fields.emplace_back(kBreakpointDefinitionsKey, DefinitionsJson(*settings.breakpointDefinitions));
    }
    return Object(std::move(fields));
}

bool ParseSettings(const JsonValue& config, RevisionSettings& out) {
    return Fields(config, {"title", "notes"}) && ReadStoredSettings(config, out);
}

// 两种读取路径共用字段校验。磁盘读取额外要求有序、唯一的已提交集合。
static bool ReadSettings(const JsonValue& config, RevisionSettings& out, bool draft) {
    RevisionSettings settings; // 成功完成全部校验后才发布到 out。
    const auto* field = config.find(kBreakpointDefinitionsKey); // 缺省字段表示旧配置。
    const bool knownFields = field ? Fields(config, {"title", "notes", kBreakpointDefinitionsKey}) :
                                     Fields(config, {"title", "notes"});
    if (!knownFields || !GetString(config, "title", settings.title) || !GetString(config, "notes", settings.notes) ||
        !IsText(settings.title, kMaxTitleBytes) || !IsText(settings.notes, kMaxNotesBytes, true)) return false;

    // 空数组仍保留扩展格式。草稿的排序与基准校验由写入器在持锁期间完成。
    if (field) {
        const auto* array = field->asArray(); // 唯一允许的定义集合形状。
        if (!array || array->size() > kProjectBreakpointLimit) return false;
        auto& rows = settings.breakpointDefinitions.emplace(); // 已解码的定义集合。
        rows.reserve(array->size());
        for (const auto& value : *array) {
            BreakpointDefinition row; // 当前输入项的离线字段。
            if (!ReadDefinition(value, row, draft)) {
                return false;
            }
            if (!draft && ((!rows.empty() && rows.back().breakpointDefinitionId >= row.breakpointDefinitionId) ||
                HasLocation(rows, row))) {
                return false;
            }
            rows.push_back(std::move(row));
        }
    }
    out = std::move(settings);
    return true;
}

bool ParseSettingsDraft(const JsonValue& config, RevisionSettings& out) {
    return ReadSettings(config, out, true);
}

bool ReadStoredSettings(const JsonValue& config, RevisionSettings& out) {
    return ReadSettings(config, out, false);
}

ProjectResult PrepareSettings(const RevisionSettings& draft, const RevisionSettings* base, RevisionSettings& out) {
    if (!IsText(draft.title, kMaxTitleBytes) || !IsText(draft.notes, kMaxNotesBytes, true)) {
        return Failure(ProjectError::InvalidArgument, "revisionSettings");
    }
    if (!draft.breakpointDefinitions) {
        if (base && base->breakpointDefinitions) return Failure(ProjectError::InvalidArgument, "missingBreakpointDefinitions");
        out = draft;
        return {};
    }
    if (draft.breakpointDefinitions->size() > kProjectBreakpointLimit) {
        return Failure(ProjectError::LimitExceeded, "breakpointDefinitionCount");
    }

    // 整批草稿规范化成功后才交给发布方，返回值总是按稳定 ID 排序。
    const std::vector<BreakpointDefinition> empty;
    const auto& previous = base && base->breakpointDefinitions ? *base->breakpointDefinitions : empty;
    RevisionSettings settings{draft.title, draft.notes};
    auto& rows = settings.breakpointDefinitions.emplace();
    rows.reserve(draft.breakpointDefinitions->size());
    for (const auto& proposed : *draft.breakpointDefinitions) {
        if (!IsDefinitionBody(proposed) || HasLocation(rows, proposed)) {
            return Failure(ProjectError::InvalidArgument, "breakpointLocation");
        }
        auto row = proposed;
        if (auto result = PrepareDefinition(row, previous, rows); !result) return result;
        rows.push_back(std::move(row));
    }
    std::sort(rows.begin(), rows.end(), [](const auto& left, const auto& right) {
        return left.breakpointDefinitionId < right.breakpointDefinitionId;
    });
    out = std::move(settings);
    return {};
}

ProjectResult ConfigHash(const RevisionSettings& settings, std::string& out) {
    // aa-cjson-v1。按已知键序写入。旧双字段对象保持原字节与原散列域。
    using namespace std::string_literals;
    auto input = "KSAA\0cli-offline-config-v1\0{"s;
    if (settings.breakpointDefinitions) {
        input = "KSAA\0project-breakpoint-config-v1\0{\"breakpointDefinitions\":"s;
        input += Evidence::WriteJson(DefinitionsJson(*settings.breakpointDefinitions));
        input += ',';
    }
    input += "\"notes\":";
    CanonicalString(settings.notes, input);
    input += ",\"title\":";
    CanonicalString(settings.title, input);
    input += '}';
    return Sha256(input, out);
}

} // namespace Ksword::ActionAnalyze::ProjectStorage
