// Offline recording mocks run the actual access service and R0 client bodies.
// No real registry query or mutation is issued by any access-service method.
#define NOMINMAX
#include <Windows.h>
#include <QCoreApplication>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include "ArkDriverClient/ArkDriverClient.h"

namespace fixture
{
struct Value { DWORD type = REG_BINARY; QByteArray data; };
struct Key { std::map<std::wstring, Value> values; std::vector<std::wstring> children; unsigned identity = 0; std::wstring linkTarget; };
struct Handle { std::wstring path; REGSAM view; unsigned identity = 0; };
std::map<std::wstring, Key> keys;
std::vector<REGSAM> masks;
std::vector<std::wstring> deleted;
unsigned cases, opens, writes, r0Calls, r0Writes;
bool denied, growing, changed, r0Denied;
unsigned nextIdentity = 0; // 内存键实例身份，路径移动或替换不会改变旧句柄所属实例。
bool replaceAfterParentQuery = false, replaceBeforeRename = false, replacementApplied = false;
DWORD enumFailure = ERROR_SUCCESS;
DWORD r0Status = KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS;
std::wstring writtenName;
QByteArray writtenData;
DWORD writtenType;

void reset()
{
    keys.clear(); masks.clear(); deleted.clear(); opens = writes = r0Calls = r0Writes = 0;
    denied = growing = changed = r0Denied = false; enumFailure = ERROR_SUCCESS;
    r0Status = KSWORD_ARK_REGISTRY_ENUM_STATUS_SUCCESS;
    nextIdentity = 0;
    replaceAfterParentQuery = replaceBeforeRename = replacementApplied = false;
    keys[L"Software\\Test"].values[L"v"] = {REG_BINARY, QByteArray("abcd", 4)};
}

// 根据实例身份求当前实际路径；持有的旧句柄不会因路径被 REG_LINK 替换而跳到 B。
std::wstring currentPath(HKEY raw)
{
    if (raw == HKEY_LOCAL_MACHINE) return {};
    const auto* handle = reinterpret_cast<Handle*>(raw);
    for (const auto& entry : keys)
        if (entry.second.identity == handle->identity) return entry.first;
    return handle->path;
}

// 将 A 的父键移走后，在旧路径放置指向 B 的链接，模拟真正的命名空间竞争。
void replaceParentWithLink()
{
    assert(!replacementApplied && keys.count(L"Software") && keys.count(L"Software\\Test"));
    auto parent = keys.extract(L"Software");
    parent.key() = L"CapturedA";
    keys.insert(std::move(parent));
    auto child = keys.extract(L"Software\\Test");
    child.key() = L"CapturedA\\Test";
    keys.insert(std::move(child));
    keys[L"Software"].values[L"SymbolicLinkValue"] = {REG_LINK, QByteArray("BParent")};
    keys[L"Software"].linkTarget = L"BParent";
    replacementApplied = true;
}

LONG open(HKEY raw, LPCWSTR path, DWORD options, REGSAM access, PHKEY result)
{
    ++opens; masks.push_back(access);
    assert(options == 0 || options == REG_OPTION_OPEN_LINK);
    if (denied) return ERROR_ACCESS_DENIED;
    std::wstring name = currentPath(raw);
    if (path && *path) name += (name.empty() ? L"" : L"\\") + std::wstring(path);
    // OPEN_LINK 仅保护最终组件；普通完整路径访问仍会跟随已替换的中间父链接。
    const auto slash = name.find(L'\\');
    if (slash != std::wstring::npos)
    {
        const auto parent = keys.find(name.substr(0, slash));
        if (parent != keys.end() && !parent->second.linkTarget.empty())
            name = parent->second.linkTarget + name.substr(slash);
    }
    if (!keys.count(name)) return ERROR_FILE_NOT_FOUND;
    auto& key = keys.at(name);
    if (!key.identity) key.identity = ++nextIdentity;
    *result = reinterpret_cast<HKEY>(new Handle{name, access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY), key.identity});
    return ERROR_SUCCESS;
}

LONG close(HKEY key) { delete reinterpret_cast<Handle*>(key); return ERROR_SUCCESS; }

LONG query(HKEY raw, LPCWSTR name, LPDWORD, LPDWORD type, LPBYTE output, LPDWORD bytes)
{
    auto& key = keys.at(currentPath(raw));
    const auto iterator = key.values.find(name ? name : L"");
    if (iterator == key.values.end())
    {
        if (replaceAfterParentQuery && !replacementApplied && currentPath(raw) == L"Software"
            && name && std::wstring(name) == L"SymbolicLinkValue") replaceParentWithLink();
        return ERROR_FILE_NOT_FOUND;
    }
    const Value& value = iterator->second;
    *type = value.type;
    if (!output)
    {
        *bytes = growing ? 1 : static_cast<DWORD>(value.data.size());
        growing = false;
        return ERROR_SUCCESS;
    }
    if (*bytes < static_cast<DWORD>(value.data.size()))
    {
        *bytes = static_cast<DWORD>(value.data.size());
        return ERROR_MORE_DATA;
    }
    *bytes = static_cast<DWORD>(value.data.size());
    std::memcpy(output, value.data.constData(), *bytes);
    return ERROR_SUCCESS;
}

LONG enumValue(HKEY raw, DWORD index, LPWSTR name, LPDWORD nameChars, LPDWORD,
    LPDWORD type, LPBYTE output, LPDWORD bytes)
{
    const auto& values = keys.at(reinterpret_cast<Handle*>(raw)->path).values;
    if (enumFailure) return static_cast<LONG>(enumFailure);
    if (index >= values.size()) return ERROR_NO_MORE_ITEMS;
    auto iterator = values.begin(); std::advance(iterator, index);
    const auto& rawName = iterator->first;
    const auto& value = iterator->second;
    *type = value.type;
    if (*nameChars <= rawName.size() || *bytes < static_cast<DWORD>(value.data.size()))
    {
        *nameChars = static_cast<DWORD>(rawName.size());
        *bytes = static_cast<DWORD>(value.data.size());
        return ERROR_MORE_DATA;
    }
    std::copy(rawName.begin(), rawName.end(), name);
    name[rawName.size()] = L'\0';
    *nameChars = static_cast<DWORD>(rawName.size());
    *bytes = static_cast<DWORD>(value.data.size());
    std::memcpy(output, value.data.constData(), *bytes);
    return ERROR_SUCCESS;
}

LONG enumKey(HKEY raw, DWORD index, LPWSTR name, LPDWORD nameChars, LPDWORD, LPWSTR, LPDWORD, PFILETIME)
{
    const auto& children = keys.at(reinterpret_cast<Handle*>(raw)->path).children;
    if (index >= children.size()) return ERROR_NO_MORE_ITEMS;
    if (*nameChars <= children[index].size()) return ERROR_MORE_DATA;
    std::copy(children[index].begin(), children[index].end(), name);
    *nameChars = static_cast<DWORD>(children[index].size()); name[*nameChars] = L'\0'; return ERROR_SUCCESS;
}

unsigned infoCalls;
LONG info(HKEY, LPWSTR, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, LPDWORD, PFILETIME time)
{
    time->dwHighDateTime = 0; time->dwLowDateTime = changed ? ++infoCalls : 1; return ERROR_SUCCESS;
}

LONG set(HKEY raw, LPCWSTR name, DWORD, DWORD type, const BYTE* data, DWORD bytes)
{
    ++writes; writtenName = name; writtenType = type;
    writtenData = QByteArray(reinterpret_cast<const char*>(data), bytes);
    keys.at(reinterpret_cast<Handle*>(raw)->path).values[writtenName] = {type, writtenData};
    return ERROR_SUCCESS;
}

LONG removeValue(HKEY raw, LPCWSTR name)
{
    ++writes; writtenName = name ? name : L"";
    keys.at(reinterpret_cast<Handle*>(raw)->path).values.erase(writtenName);
    return ERROR_SUCCESS;
}
LONG create(HKEY, LPCWSTR path, DWORD, LPWSTR, DWORD, REGSAM access, const SECURITY_ATTRIBUTES*, PHKEY result, LPDWORD disposition)
{
    ++writes; masks.push_back(access);
    const bool present = keys.count(path) != 0;
    if (disposition) *disposition = present ? REG_OPENED_EXISTING_KEY : REG_CREATED_NEW_KEY;
    if (!present) keys[path] = Key{};
    *result = reinterpret_cast<HKEY>(new Handle{path, access & (KEY_WOW64_32KEY | KEY_WOW64_64KEY)});
    return ERROR_SUCCESS;
}
LONG removeKey(HKEY, LPCWSTR path, REGSAM view, DWORD)
{
    ++writes; masks.push_back(view); deleted.push_back(path); return ERROR_SUCCESS;
}

// 实际共享键重命名 API 的内存传输，包含原数据保存和目的冲突。
LONG rename(HKEY raw, LPCWSTR oldName, LPCWSTR newName)
{
    assert(oldName == nullptr); // 实际生产入口必须改精确句柄自身，禁止再次按子名选择对象。
    if (replaceBeforeRename && !replacementApplied) replaceParentWithLink();
    const auto oldPath = currentPath(raw);
    const auto slash = oldPath.rfind(L'\\');
    const auto parent = slash == std::wstring::npos ? std::wstring() : oldPath.substr(0, slash);
    const auto newPath = parent.empty() ? std::wstring(newName) : parent + L"\\" + newName;
    if (!keys.count(oldPath)) return ERROR_FILE_NOT_FOUND;
    if (keys.count(newPath)) return ERROR_ALREADY_EXISTS;
    ++writes;
    keys[newPath] = std::move(keys[oldPath]);
    keys.erase(oldPath);
    return ERROR_SUCCESS;
}

void checkView(REGSAM expected)
{
    assert(!masks.empty());
    for (const auto mask : masks) assert((mask & (KEY_WOW64_32KEY | KEY_WOW64_64KEY)) == expected);
}
}

#define RegOpenKeyExW fixture::open
#define RegCloseKey fixture::close
#define RegQueryValueExW fixture::query
#define RegEnumValueW fixture::enumValue
#define RegEnumKeyExW fixture::enumKey
#define RegQueryInfoKeyW fixture::info
#define RegSetValueExW fixture::set
#define RegDeleteValueW fixture::removeValue
#define RegCreateKeyExW fixture::create
#define RegDeleteKeyExW fixture::removeKey
#define RegRenameKey fixture::rename
#include "RegistryDock/RegistryWorkbenchAccess.cpp"
#include "ArkDriverClient/ArkDriverRegistry.cpp"

namespace ksword::ark
{
IoResult DriverClient::deviceIoControl(unsigned long code, void* input, unsigned long,
    void* output, unsigned long bytes, DriverHandle*) const
{
    ++fixture::r0Calls;
    if (fixture::r0Denied)
    {
        IoResult result; result.ok = false; result.win32Error = ERROR_ACCESS_DENIED;
        return result;
    }
    std::memset(output, 0, bytes);
    // 每个协议请求都绑定内存中的准确机器路径，不接触真实驱动。
    const auto* keyRequest = static_cast<KSWORD_ARK_REGISTRY_KEY_PATH_REQUEST*>(input);
    std::wstring keyPath(code == IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY
        ? static_cast<KSWORD_ARK_ENUM_REGISTRY_KEY_REQUEST*>(input)->keyPath : keyRequest->keyPath);
    const std::wstring machinePrefix = L"\\REGISTRY\\MACHINE\\";
    if (keyPath.rfind(machinePrefix, 0) == 0) keyPath = keyPath.substr(machinePrefix.size());
    if (code == IOCTL_KSWORD_ARK_READ_REGISTRY_VALUE)
    {
        auto* response = static_cast<KSWORD_ARK_READ_REGISTRY_VALUE_RESPONSE*>(output);
        const auto* request = static_cast<KSWORD_ARK_READ_REGISTRY_VALUE_REQUEST*>(input);
        const auto key = fixture::keys.find(keyPath);
        const auto name = std::wstring(request->valueName);
        response->version = 1;
        if (key == fixture::keys.end() || !key->second.values.count(name))
            response->status = KSWORD_ARK_REGISTRY_READ_STATUS_NOT_FOUND;
        else
        {
            const auto& value = key->second.values.at(name);
            response->status = KSWORD_ARK_REGISTRY_READ_STATUS_SUCCESS;
            response->valueType = value.type;
            response->dataBytes = static_cast<unsigned long>(value.data.size());
            response->requiredBytes = fixture::r0Status == KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL ? 8192 : response->dataBytes;
            std::memcpy(response->data, value.data.constData(), response->dataBytes);
        }
    }
    else if (code == IOCTL_KSWORD_ARK_ENUM_REGISTRY_KEY)
    {
        auto* response = static_cast<KSWORD_ARK_ENUM_REGISTRY_KEY_RESPONSE*>(output);
        response->version = 1;
        response->status = fixture::keys.count(keyPath) ? fixture::r0Status : KSWORD_ARK_REGISTRY_ENUM_STATUS_NOT_FOUND;
    }
    else
    {
        ++fixture::r0Writes;
        auto* response = static_cast<KSWORD_ARK_REGISTRY_OPERATION_RESPONSE*>(output);
        response->version = 1;
        response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_SUCCESS;
        if (code == IOCTL_KSWORD_ARK_SET_REGISTRY_VALUE)
        {
            const auto* request = static_cast<KSWORD_ARK_SET_REGISTRY_VALUE_REQUEST*>(input);
            fixture::keys[keyPath].values[request->valueName] = {request->valueType,
                QByteArray(reinterpret_cast<const char*>(request->data), request->dataBytes)};
        }
        else if (code == IOCTL_KSWORD_ARK_DELETE_REGISTRY_VALUE)
        {
            const auto* request = static_cast<KSWORD_ARK_REGISTRY_VALUE_NAME_REQUEST*>(input);
            fixture::keys[keyPath].values.erase(request->valueName);
        }
        else if (code == IOCTL_KSWORD_ARK_CREATE_REGISTRY_KEY)
            fixture::keys[keyPath];
        else if (code == IOCTL_KSWORD_ARK_RENAME_REGISTRY_KEY)
        {
            const auto* request = static_cast<KSWORD_ARK_RENAME_REGISTRY_KEY_REQUEST*>(input);
            const auto separator = keyPath.find_last_of(L'\\');
            const auto target = keyPath.substr(0, separator + 1) + request->newKeyName;
            if (fixture::keys.count(target)) response->status = KSWORD_ARK_REGISTRY_OPERATION_STATUS_ALREADY_EXISTS;
            else { fixture::keys[target] = std::move(fixture::keys[keyPath]); fixture::keys.erase(keyPath); }
        }
    }
    IoResult result; result.ok = true; result.bytesReturned = bytes; return result;
}
}

int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv);
    using namespace fixture;
    const QString path = QStringLiteral("HKLM\\Software\\Test");
    QString error;
    RegistryValueState state;
    RegistryKeyListing listing;
    for (const int bits : {0, 32, 64})
    {
        const RegistryAccessContext context{bits, false};
        const REGSAM expected = bits == 32 ? KEY_WOW64_32KEY : bits == 64 ? KEY_WOW64_64KEY : 0;
        reset(); growing = true;
        assert(RegistryWorkbenchAccess::read(path, QStringLiteral("v"), context, &state, &error));
        assert(state.exists && state.complete && state.data == "abcd" && state.requiredBytes == 4);
        assert(r0Calls == 0 && opens == 1 && error.isEmpty()); checkView(expected); ++cases;
        reset(); keys[L"Software\\Test"].values[std::wstring(512, L'V')] = {REG_BINARY, QByteArray(5000, 'X')};
        assert(RegistryWorkbenchAccess::enumerate(path, context, &listing, &error));
        assert(listing.complete && listing.values.size() == 2 && listing.values[0].data.size() == 5000); checkView(expected); ++cases;
        reset(); keys[L"Software\\Test"].values[L"  (默认)  "] = {REG_SZ, QByteArray("X\0\0\0", 4)};
        assert(RegistryWorkbenchAccess::read(path, QStringLiteral("  (默认)  "), context, &state, &error));
        assert(state.exists && state.name == QStringLiteral("  (默认)  "));
        assert(RegistryWorkbenchAccess::write(path, state, context, &error));
        assert(writtenName == L"  (默认)  " && writtenData == state.data && writtenType == REG_SZ); checkView(expected); ++cases;
        reset(); assert(RegistryWorkbenchAccess::removeValue(path, QStringLiteral(" (默认) "), context, &error));
        assert(writtenName == L" (默认) " && writes == 1); checkView(expected); ++cases;
        reset(); assert(RegistryWorkbenchAccess::createKey(QStringLiteral("HKLM\\NewKey"), context, &error));
        assert(writes == 1 && opens == 0); ++cases;
        checkView(expected);
    }
    reset(); assert(RegistryWorkbenchAccess::read(path, QStringLiteral("missing"), {}, &state, &error));
    assert(!state.exists && state.complete); ++cases;
    reset(); assert(RegistryWorkbenchAccess::read(QStringLiteral("HKLM\\missing"), QStringLiteral("v"), {}, &state, &error));
    assert(!state.exists); ++cases;
    reset(); denied = true;
    assert(!RegistryWorkbenchAccess::read(path, QStringLiteral("v"), {}, &state, &error));
    assert(r0Calls == 0 && !error.isEmpty()); ++cases;
    for (const QString& invalid : {QStringLiteral("HKLMoops\\Test"), QStringLiteral("HKLM\\"), QStringLiteral(" HKLM\\Test"), QStringLiteral("HKLM\\a\\\\b")})
    {
        reset(); assert(!RegistryWorkbenchAccess::read(invalid, QStringLiteral("v"), {}, &state, &error));
        assert(opens == 0 && r0Calls == 0); ++cases;
    }
    for (const int bits : {32, 64, 99})
    {
        reset(); assert(!RegistryWorkbenchAccess::read(path, QStringLiteral("v"), {bits, true}, &state, &error));
        assert(opens == 0 && r0Calls == 0); ++cases;
    }
    reset(); assert(!RegistryWorkbenchAccess::read(QStringLiteral("HKCR\\Test"), QStringLiteral("v"), {0, true}, &state, &error));
    assert(r0Calls == 0 && opens == 0 && RegistryWorkbenchAccess::kernelPath(QStringLiteral("HKCR\\Test")).isEmpty()); ++cases;
    reset(); assert(RegistryWorkbenchAccess::read(path, QStringLiteral("v"), {0, true}, &state, &error));
    assert(r0Calls == 1 && opens == 0 && state.complete && state.data == "abcd"); ++cases;
    reset(); r0Denied = true;
    assert(!RegistryWorkbenchAccess::read(path, QStringLiteral("v"), {0, true}, &state, &error));
    assert(r0Calls == 1 && opens == 0 && !error.isEmpty()); ++cases;
    reset(); r0Status = KSWORD_ARK_REGISTRY_ENUM_STATUS_PARTIAL;
    assert(RegistryWorkbenchAccess::read(path, QStringLiteral("v"), {0, true}, &state, &error));
    assert(!state.complete && state.requiredBytes == 8192 && state.data.size() == 4); ++cases;
    assert(!RegistryWorkbenchAccess::write(path, state, {0, true}, &error));
    assert(r0Writes == 0 && writes == 0); ++cases;
    reset(); state.complete = true; state.data = "abcd"; state.requiredBytes = 3;
    assert(!RegistryWorkbenchAccess::write(path, state, {}, &error)); assert(writes == 0 && opens == 0); ++cases;
    reset(); state.complete = true; state.data = QByteArray(4097, 'X'); state.requiredBytes = 4097;
    assert(!RegistryWorkbenchAccess::write(path, state, {0, true}, &error));
    assert(r0Calls == 0 && writes == 0 && opens == 0); ++cases;
    reset(); state.data = QByteArray(16 * 1024 * 1024 + 1, 'X'); state.requiredBytes = static_cast<quint32>(state.data.size());
    assert(!RegistryWorkbenchAccess::write(path, state, {}, &error));
    assert(writes == 0 && opens == 0); ++cases;
    reset(); keys[L"Software\\Test"].values[L"large"] = {REG_BINARY, QByteArray(16 * 1024 * 1024 + 1, 'X')};
    assert(RegistryWorkbenchAccess::enumerate(path, {}, &listing, &error));
    assert(!listing.complete && !listing.warning.isEmpty()); ++cases;
    reset(); changed = true;
    assert(RegistryWorkbenchAccess::enumerate(path, {}, &listing, &error));
    assert(!listing.complete && !listing.warning.isEmpty()); ++cases;
    reset(); enumFailure = ERROR_ACCESS_DENIED;
    assert(RegistryWorkbenchAccess::enumerate(path, {}, &listing, &error));
    assert(!listing.complete && !listing.warning.isEmpty() && r0Calls == 0); ++cases;
    // 旧逐次删树 API 已退役；事务树删除由正式 KTM 夹具验证，R0 混合计划由 Mutation 夹具验证零写。
    for (const auto context : {RegistryAccessContext{0, false}, RegistryAccessContext{32, false},
        RegistryAccessContext{64, false}, RegistryAccessContext{0, true}})
    {
        reset(); keys[L"Software"] = Key{};
        bool exists = false;
        assert(RegistryWorkbenchAccess::keyExists(path, context, &exists, &error) && exists); ++cases;
        assert(RegistryWorkbenchAccess::keyExists(QStringLiteral("HKLM\\Software\\Absent"), context, &exists, &error) && !exists); ++cases;
        QString destination;
        if (context.useR0)
        {
            reset(); keys[L"Software"] = Key{}; // 单独验证 R0 改名首个调用前拒绝，不借前面的读取伪装能力。
            assert(!RegistryWorkbenchAccess::renameKey(path, QStringLiteral("Renamed"), context, &destination, &error));
            assert(r0Calls == 0 && r0Writes == 0 && writes == 0 && opens == 0 && destination.isEmpty());
            assert(keys[L"Software\\Test"].values[L"v"].data == "abcd" && error.contains(QStringLiteral("Win32")));
            ++cases;
            continue;
        }
        assert(RegistryWorkbenchAccess::renameKey(path, QStringLiteral("Renamed"), context, &destination, &error));
        assert(destination == QStringLiteral("HKLM\\Software\\Renamed"));
        assert(keys.count(L"Software\\Renamed") && !keys.count(L"Software\\Test"));
        assert(keys[L"Software\\Renamed"].values[L"v"].data == "abcd");
        assert(r0Calls == 0); checkView(context.viewBits == 32 ? KEY_WOW64_32KEY : context.viewBits == 64 ? KEY_WOW64_64KEY : 0);
        ++cases;
        reset(); keys[L"Software"] = Key{}; keys[L"Software\\Destination"].values[L"B"] = {REG_BINARY, QByteArray("retained")};
        assert(!RegistryWorkbenchAccess::renameKey(path, QStringLiteral("Destination"), context, &destination, &error));
        assert(writes == 0 && r0Writes == 0 && keys[L"Software\\Destination"].values[L"B"].data == "retained"); ++cases;
    }
    // 真实生产 renameKey + Win32 fake：静态链接和路径替换不能让持有 A 的句柄改到 B。
    for (const int bits : {0, 32, 64})
    {
        const RegistryAccessContext context{bits, false}; // 三种准确视图都验证相同来源绑定约束。
        QString destination;
        for (const bool linkAtParent : {true, false})
        {
            reset(); keys[L"Software"] = Key{};
            const std::wstring linkPath = linkAtParent ? L"Software" : L"Software\\Test";
            keys[linkPath].values[L"SymbolicLinkValue"] = {REG_LINK, QByteArray("outside")};
            assert(!RegistryWorkbenchAccess::renameKey(path, QStringLiteral("Renamed"), context, &destination, &error));
            assert(writes == 0 && r0Calls == 0 && destination.isEmpty());
            assert(keys[L"Software\\Test"].values[L"v"].data == "abcd");
            ++cases;
        }
        for (const bool raceAtParentQuery : {true, false})
        {
            reset(); keys[L"Software"] = Key{};
            keys[L"BParent"] = Key{};
            keys[L"BParent\\Test"].values[L"v"] = {REG_BINARY, QByteArray("B-must-remain")};
            replaceAfterParentQuery = raceAtParentQuery;
            replaceBeforeRename = !raceAtParentQuery;
            // 命名空间已换成 B，最终路径回读必须报告未验证；真正改名只允许作用于持有的 A。
            assert(!RegistryWorkbenchAccess::renameKey(path, QStringLiteral("Renamed"), context, &destination, &error));
            assert(replacementApplied && writes == 1 && r0Calls == 0 && destination.isEmpty());
            assert(keys.count(L"CapturedA\\Renamed") && !keys.count(L"CapturedA\\Test"));
            assert(keys[L"CapturedA\\Renamed"].values[L"v"].data == "abcd");
            assert(keys[L"BParent\\Test"].values[L"v"].data == "B-must-remain"
                && !keys.count(L"BParent\\Renamed"));
            assert(error.contains(QStringLiteral("final state")));
            checkView(bits == 32 ? KEY_WOW64_32KEY : bits == 64 ? KEY_WOW64_64KEY : 0);
            ++cases;
        }
    }
    std::printf("registry-workbench-access regression: %u cases passed; all registry APIs mocked\n", cases);
}
