// Execute the production Win32 deletion backend with an in-memory registry and
// transactional resource manager. No real registry APIs are linked or called.
#include <Windows.h>
#include <QCoreApplication>
#include <QMap>
#include <QString>
#include <atomic>
#include <cstring>
#include <iostream>
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocument.h"

namespace mock {
struct Value { DWORD type = REG_BINARY; QByteArray bytes; };
using Tree = QMap<QString, QMap<QString, Value>>;
Tree live;
int version = 0, deletes = 0, ordinaryDeletes = 0, rollbacks = 0, commits = 0;
int injectAt = 0, failAt = 0, invalidBindings = 0, transactionReads = 0;
LSTATUS absentStatus = ERROR_FILE_NOT_FOUND;
bool lateChild = false, unavailable = false, unsupported = false, rejectCommit = false, redirectCandidate = false;
bool changeAclOnBind = false;
QByteArray acl;
std::atomic_bool* cancel = nullptr;
const QString root = QStringLiteral("HKEY_CURRENT_USER\\Fixture");
struct Transaction { Tree staged; int originalVersion; bool committed = false; };
struct Key { QString path; Transaction* transaction; };
QString path(HKEY handle) { return handle == HKEY_CURRENT_USER ? QStringLiteral("HKEY_CURRENT_USER") : reinterpret_cast<Key*>(handle)->path; }
const Tree& tree(HKEY handle) {
    if (handle != HKEY_CURRENT_USER && reinterpret_cast<Key*>(handle)->transaction)
        return reinterpret_cast<Key*>(handle)->transaction->staged;
    return live;
}
void reset()
{
    live.clear(); live[QStringLiteral("HKEY_CURRENT_USER")]; live[root];
    live[root + QStringLiteral("\\Branch")]; live[root + QStringLiteral("\\Branch\\Leaf")];
    live[root][QStringLiteral("Old")] = {REG_BINARY, QByteArray(1, '\x42')};
    version = deletes = ordinaryDeletes = rollbacks = commits = 0;
    injectAt = failAt = invalidBindings = transactionReads = 0;
    absentStatus = ERROR_FILE_NOT_FOUND;
    lateChild = unavailable = unsupported = rejectCommit = redirectCandidate = false; cancel = nullptr;
    changeAclOnBind = false; acl = QByteArray::fromHex("0100008000000000000000000000000000000000");
}
HANDLE WINAPI create(LPSECURITY_ATTRIBUTES, LPGUID, DWORD options, DWORD isolation, DWORD flags, DWORD timeout, LPWSTR)
{
    if (options || isolation || flags || timeout == 0) ++invalidBindings;
    return reinterpret_cast<HANDLE>(new Transaction {live, version, false});
}
BOOL WINAPI commit(HANDLE handle)
{
    auto* transaction = reinterpret_cast<Transaction*>(handle);
    if (rejectCommit || transaction->originalVersion != version) {
        SetLastError(ERROR_TRANSACTIONAL_CONFLICT); return FALSE;
    }
    live = transaction->staged; ++version; ++commits; transaction->committed = true;
    return TRUE;
}
template<class T> FARPROC address(T function) {
    FARPROC result = nullptr; static_assert(sizeof(result) == sizeof(function));
    std::memcpy(&result, &function, sizeof(result)); return result;
}
LONG NTAPI queryKey(HANDLE handle, ULONG kind, PVOID buffer, ULONG size, PULONG returned)
{
    const auto* key = reinterpret_cast<Key*>(handle);
    if (!key->transaction || kind != 3) ++invalidBindings;
    const QString name = QStringLiteral("\\REGISTRY\\USER\\MOCK\\") + key->path;
    const ULONG bytes = static_cast<ULONG>(name.size() * 2);
    *returned = sizeof(ULONG) + bytes;
    if (!buffer || size < *returned) return static_cast<LONG>(0xc0000023);
    std::memcpy(buffer, &bytes, sizeof(bytes));
    std::memcpy(static_cast<char*>(buffer) + sizeof(bytes), name.utf16(), bytes);
    return 0;
}
}
HMODULE WINAPI mockLoadLibraryExW(LPCWSTR, HANDLE, DWORD flags)
{
    if (flags != LOAD_LIBRARY_SEARCH_SYSTEM32) ++mock::invalidBindings;
    if (mock::unavailable) { SetLastError(ERROR_MOD_NOT_FOUND); return nullptr; }
    return reinterpret_cast<HMODULE>(1);
}
FARPROC WINAPI mockGetProcAddress(HMODULE, LPCSTR name)
{
    if (std::strcmp(name, "CreateTransaction") == 0) return mock::address(&mock::create);
    if (std::strcmp(name, "CommitTransaction") == 0) return mock::address(&mock::commit);
    if (std::strcmp(name, "NtQueryKey") == 0) return mock::address(&mock::queryKey);
    return nullptr;
}
BOOL WINAPI mockFreeLibrary(HMODULE) { return TRUE; }
BOOL WINAPI mockCloseHandle(HANDLE handle)
{
    auto* transaction = reinterpret_cast<mock::Transaction*>(handle);
    if (!transaction->committed) ++mock::rollbacks;
    delete transaction; return TRUE;
}
LSTATUS WINAPI mockRegCloseKey(HKEY handle)
{
    if (handle != HKEY_CURRENT_USER) delete reinterpret_cast<mock::Key*>(handle);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegOpenKeyExW(HKEY parent, LPCWSTR name, DWORD options, REGSAM, PHKEY result)
{
    if (options != REG_OPTION_OPEN_LINK) ++mock::invalidBindings;
    QString path = mock::path(parent);
    if (name && *name) path += QLatin1Char('\\') + QString::fromWCharArray(name);
    if (!mock::live.contains(path)) return mock::absentStatus;
    *result = reinterpret_cast<HKEY>(new mock::Key {path, nullptr}); return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegOpenKeyTransactedW(HKEY parent, LPCWSTR name, DWORD options,
    REGSAM, PHKEY result, HANDLE handle, PVOID extra)
{
    if (options || extra) ++mock::invalidBindings;
    if (mock::unsupported) return ERROR_RM_NOT_ACTIVE;
    if (mock::changeAclOnBind) {
        mock::changeAclOnBind = false;
        mock::acl = QByteArray::fromHex("0100048000000000000000000000000000000000"); ++mock::version;
    }
    auto* transaction = reinterpret_cast<mock::Transaction*>(handle);
    QString path = mock::path(parent);
    if (name && *name) {
        if (reinterpret_cast<mock::Key*>(parent)->transaction != transaction) ++mock::invalidBindings;
        if (mock::redirectCandidate) path = QStringLiteral("HKEY_CURRENT_USER\\Outside");
        else path += QLatin1Char('\\') + QString::fromWCharArray(name);
    }
    if (!transaction->staged.contains(path)) return ERROR_FILE_NOT_FOUND;
    *result = reinterpret_cast<HKEY>(new mock::Key {path, transaction}); return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegQueryValueExW(HKEY key, LPCWSTR name, LPDWORD, LPDWORD type, LPBYTE bytes, LPDWORD size)
{
    const auto& tree = mock::tree(key);
    const auto keyIt = tree.constFind(mock::path(key));
    if (keyIt == tree.cend()) return ERROR_FILE_NOT_FOUND;
    const auto value = keyIt->constFind(QString::fromWCharArray(name));
    if (value == keyIt->cend()) return ERROR_FILE_NOT_FOUND;
    if (key != HKEY_CURRENT_USER && reinterpret_cast<mock::Key*>(key)->transaction) ++mock::transactionReads;
    if (type) *type = value->type;
    if (!size) return ERROR_SUCCESS;
    const DWORD required = static_cast<DWORD>(value->bytes.size());
    const DWORD capacity = *size; *size = required;
    if (bytes) {
        if (capacity < required) return ERROR_MORE_DATA;
        std::memcpy(bytes, value->bytes.constData(), required);
    }
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegQueryInfoKeyW(HKEY key, LPWSTR, LPDWORD, LPDWORD, LPDWORD children,
    LPDWORD, LPDWORD, LPDWORD values, LPDWORD, LPDWORD, LPDWORD, PFILETIME)
{
    const auto& tree = mock::tree(key); const QString path = mock::path(key);
    if (!tree.contains(path)) return ERROR_FILE_NOT_FOUND;
    DWORD count = 0;
    for (auto it = tree.cbegin(); it != tree.cend(); ++it)
        if (it.key().startsWith(path + QLatin1Char('\\'))) ++count;
    if (children) *children = count;
    if (values) *values = static_cast<DWORD>(tree.value(path).size());
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegGetKeySecurity(HKEY handle, SECURITY_INFORMATION, PSECURITY_DESCRIPTOR buffer, LPDWORD size)
{
    if (!reinterpret_cast<mock::Key*>(handle)->transaction) ++mock::invalidBindings;
    const DWORD required = static_cast<DWORD>(mock::acl.size());
    const DWORD capacity = *size; *size = required;
    if (!buffer || capacity < required) return ERROR_INSUFFICIENT_BUFFER;
    std::memcpy(buffer, mock::acl.constData(), required); return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegDeleteKeyTransactedW(HKEY parent, LPCWSTR name, REGSAM, DWORD reserved, HANDLE handle, PVOID extra)
{
    if (reserved || extra) ++mock::invalidBindings;
    auto* transaction = reinterpret_cast<mock::Transaction*>(handle);
    ++mock::deletes;
    if (mock::deletes == mock::injectAt) {
        if (mock::lateChild) mock::live[mock::root + QStringLiteral("\\LateChild")];
        else mock::live[mock::root][QStringLiteral("Late")] = {REG_BINARY, QByteArray(1, '\x43')};
        ++mock::version;
    }
    if (mock::deletes == mock::failAt) return ERROR_ACCESS_DENIED;
    const QString path = mock::path(parent) + QLatin1Char('\\') + QString::fromWCharArray(name);
    for (auto it = transaction->staged.cbegin(); it != transaction->staged.cend(); ++it)
        if (it.key().startsWith(path + QLatin1Char('\\'))) return ERROR_ACCESS_DENIED;
    if (!transaction->staged.remove(path)) return ERROR_FILE_NOT_FOUND;
    if (mock::cancel) mock::cancel->store(true);
    return ERROR_SUCCESS;
}
LSTATUS WINAPI mockRegCreateKeyExW(HKEY, LPCWSTR, DWORD, LPWSTR, DWORD, REGSAM,
    const LPSECURITY_ATTRIBUTES, PHKEY, LPDWORD) { return ERROR_ACCESS_DENIED; }
LSTATUS WINAPI mockRegSetValueExW(HKEY, LPCWSTR, DWORD, DWORD, const BYTE*, DWORD) { return ERROR_ACCESS_DENIED; }
LSTATUS WINAPI mockRegDeleteValueW(HKEY, LPCWSTR) { return ERROR_ACCESS_DENIED; }
LSTATUS WINAPI mockRegDeleteKeyExW(HKEY, LPCWSTR, REGSAM, DWORD) { ++mock::ordinaryDeletes; return ERROR_ACCESS_DENIED; }
#define LoadLibraryExW mockLoadLibraryExW
#define GetProcAddress mockGetProcAddress
#define FreeLibrary mockFreeLibrary
#define CloseHandle mockCloseHandle
#define RegCloseKey mockRegCloseKey
#define RegOpenKeyExW mockRegOpenKeyExW
#define RegOpenKeyTransactedW mockRegOpenKeyTransactedW
#define RegQueryValueExW mockRegQueryValueExW
#define RegQueryInfoKeyW mockRegQueryInfoKeyW
#define RegGetKeySecurity mockRegGetKeySecurity
#define RegDeleteKeyTransactedW mockRegDeleteKeyTransactedW
#define RegDeleteKeyExW mockRegDeleteKeyExW
#define RegCreateKeyExW mockRegCreateKeyExW
#define RegSetValueExW mockRegSetValueExW
#define RegDeleteValueW mockRegDeleteValueW
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocumentApply.cpp"
#include "../Ksword5.1/Ksword5.1/RegistryDock/RegistryDocumentApply.Win32.cpp"
bool RegistryDocumentService::encodeBackup(const RegistryDocument&, QByteArray&, QString&) { return false; }
bool RegistryDocumentService::decodeBackup(const QByteArray&, RegistryDocument&, QString&) { return false; }
bool RegistryDocumentService::captureWin32(const QString& path, int view, RegistryDocument& result, QString&, qint64)
{
    result = {}; result.rootPath = path; result.viewBits = view;
    for (auto it = mock::live.cbegin(); it != mock::live.cend(); ++it) {
        if (it.key() != path && !it.key().startsWith(path + QLatin1Char('\\'))) continue;
        result.keys.append({it.key(), false, mock::acl});
        for (auto value = it->cbegin(); value != it->cend(); ++value)
            result.values.append({it.key(), value.key(), value->type, value->bytes, false});
    }
    return !result.keys.isEmpty();
}
namespace {
int checks = 0, failures = 0;
void check(bool ok, const char* label) { ++checks; if (!ok) { ++failures; std::cerr << "FAIL " << label << '\n'; } }
RegistryApplyPlan plan() {
    RegistryApplyPlan result; RegistryApplyOperation op;
    op.kind = RegistryApplyOperation::Kind::DeleteTree; op.keyPath = mock::root; op.keyExistedBefore = true;
    QString error; RegistryDocumentService::captureWin32(mock::root, 0, op.beforeTree, error);
    result.operations.append(op); return result;
}
bool original() {
    return mock::live.contains(mock::root + QStringLiteral("\\Branch\\Leaf"))
        && mock::live.value(mock::root).value(QStringLiteral("Old")).bytes == QByteArray(1, '\x42');
}
}
int main(int argc, char** argv)
{
    QCoreApplication application(argc, argv); RegistryApplyResult result;
    mock::reset();
    check(RegistryDocumentApplyService::applyWin32(plan(), result) && result.completed
        && !mock::live.contains(mock::root) && mock::commits == 1 && mock::rollbacks == 0, "normal deletion commits once");
    check(mock::transactionReads == 2 && mock::invalidBindings == 0 && mock::ordinaryDeletes == 0,
        "all final value checks and deletes use the same transaction and no-follow handle binding");
    mock::reset(); mock::absentStatus = ERROR_KEY_DELETED;
    check(RegistryDocumentApplyService::applyWin32(plan(), result) && result.completed,
        "pending key removal with an external handle still verifies logical deletion");
    for (int inject : {1, 3}) {
        for (bool child : {false, true}) {
            mock::reset(); mock::injectAt = inject; mock::lateChild = child;
            check(!RegistryDocumentApplyService::applyWin32(plan(), result) && !result.completed
                && mock::commits == 0 && mock::rollbacks == 1 && original(), "late writer rolls back the whole deletion");
            check(child ? mock::live.contains(mock::root + QStringLiteral("\\LateChild"))
                : mock::live.value(mock::root).contains(QStringLiteral("Late")), "late unbacked value or child is retained");
            check(mock::ordinaryDeletes == 0 && mock::invalidBindings == 0, "conflict never falls back to ordinary deletion");
        }
    }
    mock::reset(); mock::failAt = 2;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::rollbacks == 1 && original(), "API failure restores earlier staged children");
    mock::reset(); mock::rejectCommit = true;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::deletes == 3 && mock::rollbacks == 1 && original(), "commit failure leaves the whole subtree");
    mock::reset(); std::atomic_bool cancel {false}; mock::cancel = &cancel;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result, &cancel) && result.canceled
        && mock::rollbacks == 1 && original(), "cancellation rolls back staged writes");
    mock::reset(); mock::unavailable = true;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::deletes == 0 && original(), "missing transaction API refuses deletion");
    mock::reset(); mock::unsupported = true;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::deletes == 0
        && mock::rollbacks == 1 && original(), "inactive resource manager refuses deletion");
    mock::reset(); mock::live[QStringLiteral("HKEY_CURRENT_USER\\Outside")]; mock::redirectCandidate = true;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::deletes == 0
        && mock::rollbacks == 1 && original() && mock::live.contains(QStringLiteral("HKEY_CURRENT_USER\\Outside")),
        "parent-relative replacement or link redirection cannot change the checked deletion target");
    mock::reset(); mock::changeAclOnBind = true;
    check(!RegistryDocumentApplyService::applyWin32(plan(), result) && mock::deletes == 0
        && mock::rollbacks == 1 && original(), "changed original security metadata is retained without deletion");
    std::cout << "REGISTRY_TRANSACTION_MOCK_CHECKS=" << checks << " FAILURES=" << failures << '\n';
    return failures ? 1 : 0;
}
