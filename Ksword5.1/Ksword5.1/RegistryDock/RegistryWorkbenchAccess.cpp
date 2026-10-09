#ifndef NOMINMAX
#define NOMINMAX
#endif

#include "RegistryWorkbenchAccess.h"
#include "../ArkDriverClient/ArkDriverClient.h"

#include <algorithm>
#include <array>
#include <limits>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <sddl.h>

namespace
{
constexpr DWORD kValueLimit = 16U * 1024U * 1024U;
constexpr qint64 kTotalBytesLimit = 128LL * 1024LL * 1024LL;
constexpr DWORD kNameCapacity = 16384U;
constexpr qsizetype kItemLimit = 100000;
constexpr int kRetryLimit = 16;
constexpr int kDepthLimit = 256;

// 路径解析结果：根句柄、规范根名及保留原文的子路径，供全部通道共用。
struct ParsedPath
{
    HKEY root = nullptr; // 已确认的预定义根句柄。
    QString rootName; // 统一完整根名，保持根映射一致。
    QString subKey; // 合法子路径，保留空格和原大小写。
};

// 预定义根的完整名、缩写及 Win32 句柄映射，禁止猜测未支持的根。
struct RootEntry
{
    const char* name; // Win32 完整根名。
    const char* alias; // 支持的短根名。
    HKEY root; // 此根唯一的预定义句柄。
};

const std::array<RootEntry, 5> kRoots{{
    {"HKEY_CLASSES_ROOT", "HKCR", HKEY_CLASSES_ROOT},
    {"HKEY_CURRENT_USER", "HKCU", HKEY_CURRENT_USER},
    {"HKEY_LOCAL_MACHINE", "HKLM", HKEY_LOCAL_MACHINE},
    {"HKEY_USERS", "HKU", HKEY_USERS},
    {"HKEY_CURRENT_CONFIG", "HKCC", HKEY_CURRENT_CONFIG}
}};

class RegistryHandle final
{
public:
    HKEY value = nullptr; // 此对象独占的实际打开句柄。
    // 独占 Win32 键句柄；退出作用域时释放，不把句柄泄漏到 UI。
    ~RegistryHandle()
    {
        if (value)
            ::RegCloseKey(value);
    }
    RegistryHandle() = default;
    RegistryHandle(const RegistryHandle&) = delete;
    RegistryHandle& operator=(const RegistryHandle&) = delete;
};

// 输入 QString，借用其 UTF-16 缓冲区供同步 Win32 调用；不转码或裁剪。
const wchar_t* wide(const QString& value)
{
    return reinterpret_cast<const wchar_t*>(value.utf16());
}

// 可选 error 接收完整原因，返回 false 让调用方停止本次访问。
bool fail(QString* error, const QString& text)
{
    if (error) *error = text;
    return false;
}

// 输入 Win32 状态，输出保留精确错误码的诊断文本。
QString systemError(const LONG status)
{
    return QStringLiteral("Registry access failed (Win32=%1).").arg(status);
}

// 输入传输与协议状态，输出 Win32/NTSTATUS 和原客户端消息，避免吞掉失败来源。
QString r0Error(const ksword::ark::IoResult& io, const quint32 status)
{
    return QStringLiteral("R0 registry access failed (status=%1, Win32=%2, NTSTATUS=0x%3): %4")
        .arg(status).arg(io.win32Error)
        .arg(static_cast<quint32>(io.ntStatus), 8, 16, QLatin1Char('0'))
        .arg(QString::fromStdString(io.message));
}

// 输入原始路径，校验根和组件预算，parsed 输出精确目标，失败写入 error。
bool parsePath(const QString& path, ParsedPath* parsed, QString* error)
{
    // Paths and raw value names are never trimmed: whitespace is legal registry data.
    if (path.isEmpty() || path.size() > 32767 || path.contains(QChar(0)))
        return fail(error, QStringLiteral("Invalid registry key path."));
    const qsizetype separator = path.indexOf(QLatin1Char('\\'));
    const QString rootName = separator < 0 ? path : path.left(separator);
    for (const auto& root : kRoots)
    {
        if (rootName.compare(QLatin1String(root.name), Qt::CaseInsensitive) == 0 ||
            rootName.compare(QLatin1String(root.alias), Qt::CaseInsensitive) == 0)
        {
            parsed->root = root.root;
            parsed->rootName = QLatin1String(root.name);
            parsed->subKey = separator < 0 ? QString() : path.mid(separator + 1);
            if (separator >= 0)
            {
                const QStringList components = parsed->subKey.split(QLatin1Char('\\'));
                if (components.size() > kDepthLimit)
                    return fail(error, QStringLiteral("Registry key depth exceeds the access limit."));
                for (const auto& component : components)
                {
                    if (component.isEmpty() || component.size() > 255)
                        return fail(error, QStringLiteral("Invalid registry key component."));
                }
            }
            return true;
        }
    }
    return fail(error, QStringLiteral("Unsupported registry root."));
}

// 同时验证路径和所选通道；显式视图及 HKCR 不允许映射到 R0 v1 协议。
bool validate(const QString& path, const RegistryAccessContext& context,
    ParsedPath* parsed, QString* error)
{
    if (error) error->clear();
    if (context.viewBits != 0 && context.viewBits != 32 && context.viewBits != 64)
        return fail(error, QStringLiteral("Invalid registry view."));
    if (context.useR0 && context.viewBits != 0)
        return fail(error, QStringLiteral("The R0 registry protocol does not support an explicit 32-bit or 64-bit view."));
    if (!parsePath(path, parsed, error)) return false;
    if (context.useR0 && parsed->root == HKEY_CLASSES_ROOT)
        return fail(error, QStringLiteral("HKEY_CLASSES_ROOT is a merged Win32 view; R0 access cannot represent it."));
    return true;
}

// 输入原值名，返回是否满足长度和 NUL 约束；不裁剪合法空格。
bool validateName(const QString& name, QString* error)
{
    return name.size() <= 16383 && !name.contains(QChar(0))
        ? true : fail(error, QStringLiteral("Invalid registry value name."));
}

// 把用户视图转换为 WOW64 访问标志，所有同一请求的句柄共用。
REGSAM viewFlag(const RegistryAccessContext& context)
{
    return context.viewBits == 32 ? KEY_WOW64_32KEY : context.viewBits == 64 ? KEY_WOW64_64KEY : 0;
}

// 检查 R0 传输和聚合状态均成功；失败时保留客户端的结构化诊断。
bool operationSucceeded(const ksword::ark::RegistryOperationResult& result, QString* error)
{
    return result.io.ok && result.status == KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS
        ? true : fail(error, r0Error(result.io, result.status));
}

QByteArray rawBytes(const std::vector<std::uint8_t>& data)
{
    return data.empty() ? QByteArray() : QByteArray(reinterpret_cast<const char*>(data.data()), static_cast<qsizetype>(data.size()));
}

// 使用已有键句柄完整读取值，state 输出存在/类型/原字节；有界重试增长竞争。
bool readWin32(HKEY key, const QString& name, RegistryValueState* state, QString* error)
{
    for (int attempt = 0; attempt < kRetryLimit; ++attempt)
    {
        DWORD type = 0, required = 0;
        LONG result = ::RegQueryValueExW(key, wide(name), nullptr, &type, nullptr, &required);
        if (result == ERROR_FILE_NOT_FOUND) return true;
        if (result != ERROR_SUCCESS && result != ERROR_MORE_DATA) return fail(error, systemError(result));
        if (required > kValueLimit) return fail(error, QStringLiteral("Registry value exceeds the 16 MiB access limit."));
        QByteArray bytes(static_cast<qsizetype>(required), '\0');
        DWORD returned = required;
        result = ::RegQueryValueExW(key, wide(name), nullptr, &type,
            required ? reinterpret_cast<BYTE*>(bytes.data()) : nullptr, &returned);
        if (result == ERROR_FILE_NOT_FOUND) return true;
        if (result == ERROR_MORE_DATA || (result == ERROR_SUCCESS && returned > required)) continue;
        if (result != ERROR_SUCCESS) return fail(error, systemError(result));
        bytes.resize(static_cast<qsizetype>(returned));
        state->exists = true;
        state->type = type;
        state->data = std::move(bytes);
        state->requiredBytes = returned;
        state->complete = true;
        return true;
    }
    return fail(error, QStringLiteral("Registry value changed repeatedly while reading; retry the operation."));
}

// 将枚举结果标为不完整，只保留首个原因供 UI 明确展示。
void incomplete(RegistryKeyListing* listing, const QString& warning)
{
    listing->complete = false;
    if (listing->warning.isEmpty()) listing->warning = warning;
}

// 从当前进程令牌读取 HKCU 所属 SID；失败返回空，不能把整个 HKU 当作 HKCU。
QString userSid()
{
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD bytes = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0)
    {
        ::CloseHandle(token);
        return {};
    }
    std::vector<BYTE> data(bytes);
    const BOOL queried = ::GetTokenInformation(token, TokenUser, data.data(), bytes, &bytes);
    ::CloseHandle(token);
    if (!queried) return {};
    const auto* user = reinterpret_cast<const TOKEN_USER*>(data.data());
    LPWSTR sid = nullptr;
    if (!::ConvertSidToStringSidW(user->User.Sid, &sid)) return {};
    const QString result = QString::fromWCharArray(sid);
    ::LocalFree(sid);
    return result;
}

// 只读逐层检查精确键，任何中间 REG_LINK 都拒绝，防止递归删除跳出授权树。
bool proveNoRegistryLinks(const ParsedPath& parsed, const RegistryAccessContext& context, QString* error)
{
    // REG_OPTION_OPEN_LINK opens the final component itself. Walk every ancestor
    // so an intermediate link cannot redirect destructive recursion either.
    QString partial;
    const QStringList components = parsed.subKey.split(QLatin1Char('\\'));
    for (const auto& component : components)
    {
        partial = partial.isEmpty() ? component : partial + QLatin1Char('\\') + component;
        RegistryHandle key;
        const LONG opened = ::RegOpenKeyExW(parsed.root, wide(partial), REG_OPTION_OPEN_LINK,
            KEY_QUERY_VALUE | viewFlag(context), &key.value);
        if (opened != ERROR_SUCCESS) return fail(error, systemError(opened));
        DWORD type = 0, bytes = 0;
        const LONG queried = ::RegQueryValueExW(key.value, L"SymbolicLinkValue", nullptr, &type, nullptr, &bytes);
        if (queried == ERROR_SUCCESS && type == REG_LINK)
            return fail(error, QStringLiteral("Registry tree deletion cannot traverse symbolic links."));
        if (queried != ERROR_SUCCESS && queried != ERROR_FILE_NOT_FOUND)
            return fail(error, systemError(queried));
    }
    return true;
}
}

// 输入 Win32 根路径，输出可证明的内核路径；HKCR 合并视图无法表示，返回空。
QString RegistryWorkbenchAccess::kernelPath(const QString& path)
{
    ParsedPath parsed;
    if (!parsePath(path, &parsed, nullptr)) return {};
    QString root;
    if (parsed.root == HKEY_LOCAL_MACHINE) root = QStringLiteral("\\REGISTRY\\MACHINE");
    else if (parsed.root == HKEY_USERS) root = QStringLiteral("\\REGISTRY\\USER");
    else if (parsed.root == HKEY_CURRENT_CONFIG)
        root = QStringLiteral("\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Hardware Profiles\\Current");
    else if (parsed.root == HKEY_CURRENT_USER)
    {
        const QString sid = userSid();
        if (sid.isEmpty()) return {}; // Never approximate HKCU with all of HKEY_USERS.
        root = QStringLiteral("\\REGISTRY\\USER\\%1").arg(sid);
    }
    else return {};
    return parsed.subKey.isEmpty() ? root : root + QLatin1Char('\\') + parsed.subKey;
}

// 输入路径、名称和通道快照，state 输出完整性；失败不会换通道重试。
bool RegistryWorkbenchAccess::read(const QString& path, const QString& name,
    const RegistryAccessContext& context, RegistryValueState* state, QString* error)
{
    if (!state) return fail(error, QStringLiteral("Missing registry value output."));
    *state = RegistryValueState{};
    state->name = name;
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error) || !validateName(name, error)) return false;
    if (context.useR0)
    {
        const QString kernel = kernelPath(path);
        if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
        const auto result = ksword::ark::DriverClient{}.readRegistryValue(kernel.toStdWString(), name.toStdWString());
        if (!result.io.ok) return fail(error, r0Error(result.io, result.status));
        if (result.status == KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND) return true;
        if (result.status != KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS &&
            result.status != KSWORD_ARK_REGISTRY_READ_STATUS_BUFFER_TOO_SMALL)
            return fail(error, r0Error(result.io, result.status));
        state->exists = true;
        state->type = result.valueType;
        state->data = rawBytes(result.data);
        state->requiredBytes = result.requiredBytes;
        state->complete = result.status == KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS &&
            result.dataBytes == result.data.size() && result.requiredBytes == result.data.size();
        return true;
    }
    RegistryHandle key;
    const LONG result = ::RegOpenKeyExW(parsed.root, wide(parsed.subKey), 0, KEY_QUERY_VALUE | viewFlag(context), &key.value);
    if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return true;
    if (result != ERROR_SUCCESS) return fail(error, systemError(result));
    return readWin32(key.value, name, state, error);
}

// 输入同一通道/视图上下文，输出有界键和值列表；缺项或增长竞争明确标为不完整。
bool RegistryWorkbenchAccess::enumerate(const QString& path, const RegistryAccessContext& context,
    RegistryKeyListing* listing, QString* error, const bool includeSubKeys)
{
    if (!listing) return fail(error, QStringLiteral("Missing registry key output."));
    *listing = RegistryKeyListing{};
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error)) return false;
    if (context.useR0)
    {
        const QString kernel = kernelPath(path);
        if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
        const auto flags = KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_VALUES |
            (includeSubKeys ? KSWORD_ARK_REGISTRY_ENUM_FLAG_INCLUDE_SUBKEYS : 0UL);
        const auto result = ksword::ark::DriverClient{}.enumerateRegistryKey(kernel.toStdWString(), flags);
        if (!result.io.ok || (result.status != KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS &&
            result.status != KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL)) return fail(error, r0Error(result.io, result.status));
        listing->complete = result.status == KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS;
        for (const auto& subKey : result.subKeys) listing->subKeys.push_back(QString::fromStdWString(subKey.name));
        for (const auto& entry : result.values)
        {
            RegistryValueState state;
            state.name = QString::fromStdWString(entry.name);
            state.exists = true;
            state.type = entry.valueType;
            state.data = rawBytes(entry.data);
            state.requiredBytes = entry.requiredBytes;
            state.complete = entry.dataBytes == entry.data.size() && entry.requiredBytes == entry.data.size();
            listing->values.push_back(std::move(state));
            if (!listing->values.back().complete) listing->complete = false;
        }
        if (!listing->complete) listing->warning = QStringLiteral("R0 enumeration is incomplete; some names, entries or value bytes could not be returned.");
        return true;
    }

    RegistryHandle key;
    const REGSAM access = KEY_QUERY_VALUE | (includeSubKeys ? KEY_ENUMERATE_SUB_KEYS : 0UL) | viewFlag(context);
    const LONG opened = ::RegOpenKeyExW(parsed.root, wide(parsed.subKey), 0, access, &key.value);
    if (opened != ERROR_SUCCESS) return fail(error, systemError(opened));
    FILETIME before{};
    const LONG beforeResult = ::RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &before);
    if (beforeResult != ERROR_SUCCESS) return fail(error, systemError(beforeResult));
    qint64 totalBytes = 0;
    for (DWORD index = 0; ; ++index)
    {
        if (listing->values.size() >= kItemLimit)
        {
            incomplete(listing, QStringLiteral("Registry enumeration reached the item limit."));
            break;
        }
        std::vector<wchar_t> name(256);
        QByteArray data(1024, '\0');
        bool completed = false;
        for (int attempt = 0; attempt < kRetryLimit; ++attempt)
        {
            DWORD nameChars = static_cast<DWORD>(name.size()), dataBytes = static_cast<DWORD>(data.size()), type = 0;
            const LONG result = ::RegEnumValueW(key.value, index, name.data(), &nameChars, nullptr, &type,
                reinterpret_cast<BYTE*>(data.data()), &dataBytes);
            if (result == ERROR_NO_MORE_ITEMS)
            {
                completed = true;
                break;
            }
            if (result == ERROR_MORE_DATA)
            {
                const std::size_t requiredName = std::max<std::size_t>(name.size() * 2U, static_cast<std::size_t>(nameChars) + 1U);
                if (dataBytes > kValueLimit || (name.size() >= kNameCapacity && nameChars >= name.size()))
                {
                    incomplete(listing, QStringLiteral("Registry enumeration exceeded a name or value size limit."));
                    break;
                }
                name.resize(std::min<std::size_t>(requiredName, kNameCapacity));
                if (dataBytes > static_cast<DWORD>(data.size())) data.resize(static_cast<qsizetype>(dataBytes));
                continue;
            }
            if (result != ERROR_SUCCESS)
            {
                incomplete(listing, systemError(result));
                break;
            }
            if (nameChars >= name.size() || dataBytes > static_cast<DWORD>(data.size()))
            {
                incomplete(listing, QStringLiteral("Registry enumeration returned an invalid length."));
                break;
            }
            totalBytes += static_cast<qint64>(dataBytes);
            if (totalBytes > kTotalBytesLimit)
            {
                incomplete(listing, QStringLiteral("Registry enumeration reached the total data limit."));
                break;
            }
            RegistryValueState state;
            state.name = QString::fromWCharArray(name.data(), static_cast<qsizetype>(nameChars));
            state.type = type;
            data.resize(static_cast<qsizetype>(dataBytes));
            state.data = std::move(data);
            state.requiredBytes = dataBytes;
            state.exists = true;
            listing->values.push_back(std::move(state));
            completed = true;
            break;
        }
        if (!completed)
        {
            incomplete(listing, QStringLiteral("Registry enumeration changed repeatedly; retry the operation."));
            break;
        }
        if (listing->values.size() <= index) break; // ERROR_NO_MORE_ITEMS.
    }
    if (includeSubKeys)
    {
        for (DWORD index = 0; ; ++index)
        {
            if (listing->values.size() + listing->subKeys.size() >= kItemLimit)
            {
                incomplete(listing, QStringLiteral("Registry enumeration reached the item limit."));
                break;
            }
            std::array<wchar_t, 256> name{};
            DWORD nameChars = static_cast<DWORD>(name.size());
            const LONG result = ::RegEnumKeyExW(key.value, index, name.data(), &nameChars, nullptr, nullptr, nullptr, nullptr);
            if (result == ERROR_NO_MORE_ITEMS) break;
            if (result != ERROR_SUCCESS || nameChars >= name.size())
            {
                incomplete(listing, systemError(result == ERROR_SUCCESS ? ERROR_INVALID_DATA : result));
                break;
            }
            listing->subKeys.push_back(QString::fromWCharArray(name.data(), static_cast<qsizetype>(nameChars)));
        }
    }
    FILETIME after{};
    const LONG afterResult = ::RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr,
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &after);
    if (afterResult != ERROR_SUCCESS)
        incomplete(listing, systemError(afterResult));
    else if (::CompareFileTime(&before, &after) != 0)
        incomplete(listing, QStringLiteral("Registry key changed during enumeration; refresh before using a complete snapshot."));
    return true;
}

// 仅提交完整且在容量范围内的原始值；参数和通道均校验后才执行写入。
bool RegistryWorkbenchAccess::write(const QString& path, const RegistryValueState& state,
    const RegistryAccessContext& context, QString* error)
{
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error) || !validateName(state.name, error)) return false;
    if (!state.complete || state.requiredBytes != state.data.size() || state.data.size() > kValueLimit)
        return fail(error, QStringLiteral("An incomplete or oversized registry value cannot be written."));
    if (context.useR0)
    {
        const QString kernel = kernelPath(path);
        if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
        const auto* begin = reinterpret_cast<const std::uint8_t*>(state.data.constData());
        const std::vector<std::uint8_t> data(begin, begin + state.data.size());
        return operationSucceeded(ksword::ark::DriverClient{}.setRegistryValue(kernel.toStdWString(),
            state.name.toStdWString(), state.type, data), error);
    }
    RegistryHandle key;
    const LONG opened = ::RegOpenKeyExW(parsed.root, wide(parsed.subKey), 0, KEY_SET_VALUE | viewFlag(context), &key.value);
    if (opened != ERROR_SUCCESS) return fail(error, systemError(opened));
    const LONG result = ::RegSetValueExW(key.value, wide(state.name), 0, state.type,
        reinterpret_cast<const BYTE*>(state.data.constData()), static_cast<DWORD>(state.data.size()));
    return result == ERROR_SUCCESS ? true : fail(error, systemError(result));
}

// 输入精确路径和值名，从指定通道删除单值；失败不进行另一通道的隐式补写。
bool RegistryWorkbenchAccess::removeValue(const QString& path, const QString& name,
    const RegistryAccessContext& context, QString* error)
{
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error) || !validateName(name, error)) return false;
    if (context.useR0)
    {
        const QString kernel = kernelPath(path);
        if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
        return operationSucceeded(ksword::ark::DriverClient{}.deleteRegistryValue(kernel.toStdWString(), name.toStdWString()), error);
    }
    RegistryHandle key;
    const LONG opened = ::RegOpenKeyExW(parsed.root, wide(parsed.subKey), 0, KEY_SET_VALUE | viewFlag(context), &key.value);
    if (opened != ERROR_SUCCESS) return fail(error, systemError(opened));
    const LONG result = ::RegDeleteValueW(key.value, wide(name));
    return result == ERROR_SUCCESS ? true : fail(error, systemError(result));
}

// 输入非根目标路径与通道，在选定视图创建键，返回原 API 状态。
bool RegistryWorkbenchAccess::createKey(const QString& path, const RegistryAccessContext& context, QString* error)
{
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error)) return false;
    if (parsed.subKey.isEmpty()) return fail(error, QStringLiteral("Registry root keys cannot be created or deleted."));
    if (context.useR0)
    {
        const QString kernel = kernelPath(path);
        if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
        return operationSucceeded(ksword::ark::DriverClient{}.createRegistryKey(kernel.toStdWString()), error);
    }
    RegistryHandle key;
    const LONG result = ::RegCreateKeyExW(parsed.root, wide(parsed.subKey), 0, nullptr, 0,
        KEY_SET_VALUE | KEY_QUERY_VALUE | viewFlag(context), nullptr, &key.value, nullptr);
    return result == ERROR_SUCCESS ? true : fail(error, systemError(result));
}

// 先完整预检授权树，再按固定叶到根顺序删除；任何缺项或链接都拒绝开始。
bool RegistryWorkbenchAccess::removeTree(const QString& path, const RegistryAccessContext& context, QString* error)
{
    ParsedPath parsed;
    if (!validate(path, context, &parsed, error)) return false;
    if (parsed.subKey.isEmpty()) return fail(error, QStringLiteral("Registry root keys cannot be created or deleted."));

    // Collect the whole tree before the first deletion. The selected backend
    // handles enumeration and deletion; Win32 OPEN_LINK is a read-only guard for
    // R0 because protocol v1 cannot prove whether ZwOpenKey followed a link.
    // 待检查项携带原路径与深度，限定完整预检的遍历预算。
    struct PendingKey
    {
        QString path; // 原始目标键路径。
        int depth;    // 相对授权根的层数。
    };
    QVector<PendingKey> pending{{path, 0}};
    QStringList deletionOrder;
    while (!pending.isEmpty())
    {
        const PendingKey item = pending.takeLast();
        if (item.depth > kDepthLimit || deletionOrder.size() + pending.size() >= kItemLimit)
            return fail(error, QStringLiteral("Registry tree deletion exceeds the traversal limit."));
        ParsedPath current;
        if (!parsePath(item.path, &current, error) || !proveNoRegistryLinks(current, context, error)) return false;
        RegistryKeyListing listing;
        if (!enumerate(item.path, context, &listing, error, true)) return false;
        if (!listing.complete)
            return fail(error, listing.warning.isEmpty() ? QStringLiteral("Registry tree enumeration is incomplete; deletion was not started.") : listing.warning);
        deletionOrder.push_back(item.path);
        for (const auto& child : listing.subKeys)
            pending.push_back({item.path + QLatin1Char('\\') + child, item.depth + 1});
    }

    for (auto iterator = deletionOrder.crbegin(); iterator != deletionOrder.crend(); ++iterator)
    {
        ParsedPath current;
        if (!parsePath(*iterator, &current, error) || !proveNoRegistryLinks(current, context, error)) return false;
        if (context.useR0)
        {
            const QString kernel = kernelPath(*iterator);
            if (kernel.isEmpty()) return fail(error, QStringLiteral("Unable to resolve the registry kernel path."));
            if (!operationSucceeded(ksword::ark::DriverClient{}.deleteRegistryKey(kernel.toStdWString()), error)) return false;
        }
        else
        {
            // Delete only this now-leaf key. RegDeleteTree on a path can recurse
            // into new children created after the preflight and is not used.
            const LONG result = ::RegDeleteKeyExW(current.root, wide(current.subKey), viewFlag(context), 0);
            if (result != ERROR_SUCCESS) return fail(error, systemError(result));
        }
    }
    return true;
}
