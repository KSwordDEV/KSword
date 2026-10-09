#include "RegistryDocumentApplyInternal.h"
#include "RegistryValueTransactions.h"

// Win32 适配层；纯文档状态机保留在 RegistryDocumentApply.cpp。
#include <QHash>
#include <algorithm>
#include <cstring>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

using namespace ks::registry::apply_detail;

#ifdef Q_OS_WIN
namespace
{
class ApplyKey final
{
public:
    // 析构释放所属 HKEY。
    ~ApplyKey()
    {
        close();
    }
    // 关闭句柄并置空，允许显式提前释放或析构再次调用。
    void close()
    {
        if (handle)
        {
            RegCloseKey(handle);
            handle = nullptr;
        }
    }
    HKEY handle = nullptr; // 当前对象独占的键句柄。
};

// 输入 Win32 状态和目标路径，输出诊断到 error 并返回失败。
bool apiError(QString& error, const QString& path, LSTATUS status)
{
    return failure(error, QStringLiteral("Registry operation failed at %1 (Win32 %2).").arg(path).arg(status));
}

// KTM 动态 API 与事务句柄的生命周期；未提交即关闭时由系统回滚。
class ApplyTransaction final
{
public:
    ~ApplyTransaction()
    {
        // 关闭最后一个尚未提交的 KTM 句柄，由系统回滚整个事务的暂存变更。
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        if (m_module) FreeLibrary(m_module);
    }
    // 加载系统 KTM 并创建有超时的事务；输入路径用于诊断，失败输出 error。
    bool begin(const QString& path, QString& error)
    {
        m_module = LoadLibraryExW(L"KtmW32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (!m_module) return apiError(error, path, GetLastError());
        using Create = HANDLE (WINAPI*)(LPSECURITY_ATTRIBUTES, LPGUID, DWORD, DWORD, DWORD, DWORD, LPWSTR);
        Create create = nullptr;
        const FARPROC createAddress = GetProcAddress(m_module, "CreateTransaction");
        const FARPROC commitAddress = GetProcAddress(m_module, "CommitTransaction");
        static_assert(sizeof(create) == sizeof(createAddress));
        static_assert(sizeof(m_commit) == sizeof(commitAddress));
        std::memcpy(&create, &createAddress, sizeof(create));
        std::memcpy(&m_commit, &commitAddress, sizeof(m_commit));
        if (!create || !m_commit) return apiError(error, path, ERROR_PROC_NOT_FOUND);
        handle = create(nullptr, nullptr, 0, 0, 0, 30000, nullptr);
        return handle != INVALID_HANDLE_VALUE || apiError(error, path, GetLastError());
    }
    // 提交当前事务，失败时析构回滚所有已暂存删除。
    bool commit(const QString& path, QString& error)
    {
        return m_commit(handle) || apiError(error, path, GetLastError());
    }
    HANDLE handle = INVALID_HANDLE_VALUE; // 当前事务的唯一所有权句柄，未提交时关闭会回滚。
private:
    HMODULE m_module = nullptr; // 仅从系统目录加载的 KTM 模块，析构时释放。
    BOOL (WINAPI* m_commit)(HANDLE) = nullptr; // 已验证的提交入口，失败不能转入普通写入。
};

// 输入规范化根名，返回 Win32 预定义句柄；未知根返回空。
HKEY rootHandle(const QString& root)
{
    if (root == QStringLiteral("HKEY_CLASSES_ROOT")) return HKEY_CLASSES_ROOT;
    if (root == QStringLiteral("HKEY_CURRENT_USER")) return HKEY_CURRENT_USER;
    if (root == QStringLiteral("HKEY_LOCAL_MACHINE")) return HKEY_LOCAL_MACHINE;
    if (root == QStringLiteral("HKEY_USERS")) return HKEY_USERS;
    if (root == QStringLiteral("HKEY_CURRENT_CONFIG")) return HKEY_CURRENT_CONFIG;
    return nullptr;
}

// 检查精确句柄上的 REG_LINK 值，发现符号链接时拒绝操作。
bool inspectLink(HKEY handle, const QString& path, QString& error)
{
    DWORD type = 0;
    const LSTATUS status = RegQueryValueExW(handle, L"SymbolicLinkValue", nullptr, &type, nullptr, nullptr);
    if (status == ERROR_SUCCESS && type == REG_LINK)
        return failure(error, QStringLiteral("Registry operations refuse symbolic links: %1").arg(path));
    if (status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND)
        return apiError(error, path, status);
    return true;
}

// 输入精确句柄，输出其内核全名 identity，用于绑定相对删除名称。
bool keyIdentity(HKEY handle, const QString& path, QString& identity, QString& error)
{
    using QueryKey = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    QueryKey query = nullptr;
    const FARPROC address = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryKey");
    static_assert(sizeof(query) == sizeof(address));
    std::memcpy(&query, &address, sizeof(query));
    if (!query) return apiError(error, path, ERROR_PROC_NOT_FOUND);
    ULONG required = 0;
    // KeyNameInformation 由名字字节数及原生 UTF-16 名字组成；先验证长度再解码。
    query(handle, 3, nullptr, 0, &required);
    if (required < sizeof(ULONG) || required > 128 * 1024)
        return apiError(error, path, ERROR_INVALID_DATA);
    QByteArray buffer(static_cast<qsizetype>(required), Qt::Uninitialized);
    ULONG returned = required;
    if (query(handle, 3, buffer.data(), required, &returned) < 0)
        return apiError(error, path, ERROR_INVALID_HANDLE);
    ULONG bytes = 0;
    std::memcpy(&bytes, buffer.constData(), sizeof(bytes));
    if (returned < sizeof(bytes) || returned > required || !bytes || bytes > returned - sizeof(bytes) || bytes % 2)
        return apiError(error, path, ERROR_INVALID_DATA);
    identity = QString::fromWCharArray(reinterpret_cast<const wchar_t*>(buffer.constData() + sizeof(bytes)), bytes / 2);
    return true;
}

// Win32 执行后端：使用共用路径校验，输出保持原类型与完整原始字节。
class Win32ApplyBackend final : public RegistryApplyBackend
{
public:
    explicit Win32ApplyBackend(int viewBits, const std::atomic_bool* canceled = nullptr) : m_bits(viewBits),
        m_view(viewBits == 32 ? KEY_WOW64_32KEY : viewBits == 64 ? KEY_WOW64_64KEY : 0), m_canceled(canceled) {}

    bool supportsAtomicValueMove() const override { return true; }

    // 下方 deleteTree 在同一 KTM 事务内复核原树并提交，明确提供安全树删除能力。
    bool supportsAtomicTreeDeletion() const override { return true; }

    // 原值、目的缺失、写新值、删原值全部绑定同一个事务；不调用普通后端逐步提交。
    bool moveValueAtomic(const QString& sourcePath, const QString& oldName,
        const QString& destinationPath, const QString& newName, const RegistryApplyValueState& expected,
        RegistryValueRenameResult& result, QString& error) override
    {
        result = {};
        QString source;
        QString destination;
        if ((m_bits != 0 && m_bits != 32 && m_bits != 64)
            || !pathCanonical(sourcePath, source, error)
            || !pathCanonical(destinationPath, destination, error)) return false;
        bool committed = false; // 只有 CommitTransaction 成功才表示永久变更。
        bool stagedWrite = false; // 失败时区分尚未开始与已由 KTM 回滚的变更。
        {
            ApplyTransaction transaction; // 比键先构造，使键先析构，最后关闭未提交事务回滚。
            ApplyKey sourceKey;
            ApplyKey destinationKey;
            auto execute = [&]() {
                if (!transaction.begin(source, error)) return false;
                LSTATUS status = ERROR_SUCCESS;
                if (!openTransacted(source, KEY_QUERY_VALUE | KEY_SET_VALUE,
                    transaction.handle, sourceKey, status, error)) return false;
                RegistryApplyValueState original; // 原始值在事务内与模态前基线比较。
                if (!readValueHandle(sourceKey.handle, source, oldName, original, error)) return false;
                if (!sameValue(original, expected))
                    return failure(error, QStringLiteral("Original registry value changed; rename was not started."));
                if (source.compare(destination, Qt::CaseInsensitive) == 0)
                {
                    // 同键改名直接复用已核验的事务对象，不再次通过普通句柄访问该键。
                    status = RegOpenKeyTransactedW(sourceKey.handle, L"", 0,
                        KEY_QUERY_VALUE | KEY_SET_VALUE | m_view, &destinationKey.handle, transaction.handle, nullptr);
                    if (status != ERROR_SUCCESS) return apiError(error, destination, status);
                }
                else if (!openMoveDestination(destination, transaction.handle, destinationKey, error)) return false;
                RegistryApplyValueState target; // 目的存在检查在同一事务内，不留 read->set 竞争窗口。
                if (!readValueHandle(destinationKey.handle, destination, newName, target, error)) return false;
                if (target.exists)
                    return failure(error, QStringLiteral("Registry destination value already exists; it was not replaced."));
                stagedWrite = true;
                status = RegSetValueExW(destinationKey.handle, reinterpret_cast<LPCWSTR>(newName.utf16()), 0,
                    expected.type, reinterpret_cast<const BYTE*>(expected.data.constData()),
                    static_cast<DWORD>(expected.data.size()));
                if (status != ERROR_SUCCESS) return apiError(error, destination, status);
                status = RegDeleteValueW(sourceKey.handle, reinterpret_cast<LPCWSTR>(oldName.utf16()));
                if (status != ERROR_SUCCESS) return apiError(error, source, status);
                // 事务内先确认逻辑结果；提交若遇外部写者会冲突并回滚所有暂存。
                if (!readValueHandle(sourceKey.handle, source, oldName, original, error)
                    || !readValueHandle(destinationKey.handle, destination, newName, target, error)) return false;
                if (original.exists || !sameValue(target, expected))
                    return failure(error, QStringLiteral("Registry transaction staging did not match the requested value move."));
                return transaction.commit(source, error);
            };
            committed = execute();
        }
        result.committed = committed;
        // 事务句柄已关闭，失败已回滚；两端实际回读不能拿事务内缓存冒充永久状态。
        QString originalError;
        QString destinationError;
        result.originalVerified = readValue(source, oldName, result.actualOriginal, originalError);
        bool destinationExists = false;
        result.destinationVerified = keyExists(destination, destinationExists, destinationError);
        if (result.destinationVerified && destinationExists)
            result.destinationVerified = readValue(destination, newName, result.actualDestination, destinationError);
        if (committed && result.originalVerified && result.destinationVerified
            && !result.actualOriginal.exists && sameValue(result.actualDestination, expected))
        {
            result.state = RegistryValueRenameResult::State::Renamed;
            error.clear();
            return true;
        }
        result.state = !result.originalVerified || !result.destinationVerified || committed
            ? RegistryValueRenameResult::State::Unverified
            : stagedWrite && sameValue(result.actualOriginal, expected) && !result.actualDestination.exists
            ? RegistryValueRenameResult::State::Restored
            : stagedWrite || !sameValue(result.actualOriginal, expected)
            ? RegistryValueRenameResult::State::Conflict : RegistryValueRenameResult::State::Rejected;
        if (committed)
            error = QStringLiteral("Registry value move committed but its permanent state could not be verified; inspect both names.");
        else if (result.state == RegistryValueRenameResult::State::Restored)
            error += QLatin1Char('\n') + QStringLiteral("Registry value move failed; the transaction rolled back and the original value was preserved.");
        else if (error.isEmpty()) error = QStringLiteral("Registry rename was not verified; inspect both names before retrying.");
        if (!originalError.isEmpty()) error += QLatin1Char('\n') + originalError;
        if (!destinationError.isEmpty()) error += QLatin1Char('\n') + destinationError;
        return false;
    }

    // 输入键路径，输出存在状态；已删除或缺失作为不存在，其它错误仍失败。
    bool keyExists(const QString& path, bool& exists, QString& error) override
    {
        ApplyKey key;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(path, KEY_QUERY_VALUE, key, status, error)) {
            if (status == ERROR_FILE_NOT_FOUND || status == ERROR_PATH_NOT_FOUND || status == ERROR_KEY_DELETED) {
                exists = false;
                error.clear();
                return true;
            }
            return false;
        }
        exists = true;
        return true;
    }

    // 无链接打开目标键，value 输出存在状态、类型和完整字节。
    bool readValue(const QString& path, const QString& name, RegistryApplyValueState& value, QString& error) override
    {
        value = {};
        ApplyKey key;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(path, KEY_QUERY_VALUE, key, status, error))
            return false;
        return readValueHandle(key.handle, path, name, value, error);
    }

    // 从已绑定句柄读取，用于事务内比较，避免重新按名称打开目标。
    bool readValueHandle(HKEY handle, const QString& path, const QString& name,
        RegistryApplyValueState& value, QString& error)
    {
        value = {};
        DWORD type = 0, size = 0;
        LSTATUS status = RegQueryValueExW(handle, reinterpret_cast<LPCWSTR>(name.utf16()), nullptr, &type, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND)
            return true;
        if (status != ERROR_SUCCESS)
            return apiError(error, path, status);
        for (int attempt = 0; attempt < 5; ++attempt) {
            if (size > 16 * 1024 * 1024)
                return failure(error, QStringLiteral("Registry value exceeds the apply read budget."));
            QByteArray data(static_cast<qsizetype>(size), Qt::Uninitialized);
            DWORD actual = size;
            status = RegQueryValueExW(handle, reinterpret_cast<LPCWSTR>(name.utf16()), nullptr,
                &type, reinterpret_cast<BYTE*>(data.data()), &actual);
            if (status == ERROR_MORE_DATA)
            {
                size = actual;
                continue;
            }
            if (status == ERROR_FILE_NOT_FOUND)
                return true;
            if (status != ERROR_SUCCESS)
                return apiError(error, path, status);
            if (actual > static_cast<DWORD>(data.size()))
                return failure(error, QStringLiteral("Registry apply read returned an invalid data length."));
            data.resize(actual);
            value = {true, type, std::move(data)};
            return true;
        }
        return failure(error, QStringLiteral("Registry value kept growing during apply verification."));
    }

    // 用统一预算捕获完整树，输出可逐项比较的原始文档。
    bool captureTree(const QString& path, RegistryDocument& tree, QString& error) override
    {
        return captureTreeBounded(path, kPlanDataLimit, tree, error);
    }

    // 输入剩余预算，拒绝链接后捕获同一视图中的完整子树。
    bool captureTreeBounded(const QString& path, qint64 maximumDataBytes,
        RegistryDocument& tree, QString& error) override
    {
        ApplyKey key;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(path, KEY_QUERY_VALUE, key, status, error))
            return false;
        return RegistryDocumentService::captureWin32(path, m_bits, tree, error, maximumDataBytes);
    }

    // 在已核验父键下创建新键；竞争者已创建时拒绝作为本次成功。
    bool createKey(const QString& path, QString& error) override
    {
        const QString parent = parentPath(path);
        if (parent.isEmpty())
            return failure(error, QStringLiteral("A predefined registry root cannot be created."));
        ApplyKey parentKey, created;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(parent, KEY_CREATE_SUB_KEY | KEY_QUERY_VALUE, parentKey, status, error))
            return false;
        const QString name = path.mid(parent.size() + 1);
        DWORD disposition = 0;
        if (canceled(error))
            return false;
        status = RegCreateKeyExW(parentKey.handle, reinterpret_cast<LPCWSTR>(name.utf16()), 0, nullptr,
            REG_OPTION_NON_VOLATILE, KEY_QUERY_VALUE | m_view, nullptr, &created.handle, &disposition);
        if (status != ERROR_SUCCESS)
            return apiError(error, path, status);
        if (disposition != REG_CREATED_NEW_KEY)
            return failure(error, QStringLiteral("Registry key appeared after its creation preview."));
        return true;
    }

    // 写入同一视图中的完整原始值；取消后不写，上层负责最终回读。
    bool setValue(const QString& path, const QString& name, quint32 type, const QByteArray& data, QString& error) override
    {
        ApplyKey key;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(path, KEY_QUERY_VALUE | KEY_SET_VALUE, key, status, error))
            return false;
        if (canceled(error))
            return false;
        status = RegSetValueExW(key.handle, reinterpret_cast<LPCWSTR>(name.utf16()), 0, type,
            reinterpret_cast<const BYTE*>(data.constData()), static_cast<DWORD>(data.size()));
        return status == ERROR_SUCCESS || apiError(error, path, status);
    }

    // 删除已比较值；此时缺失属于竞争冲突，向上层返回错误。
    bool deleteValue(const QString& path, const QString& name, QString& error) override
    {
        ApplyKey key;
        LSTATUS status = ERROR_SUCCESS;
        if (!open(path, KEY_QUERY_VALUE | KEY_SET_VALUE, key, status, error))
            return false;
        if (canceled(error))
            return false;
        status = RegDeleteValueW(key.handle, reinterpret_cast<LPCWSTR>(name.utf16()));
        // 写前刚确认存在、实际删除时却缺失，属于外部竞争冲突而不是本次成功。
        return status == ERROR_SUCCESS || apiError(error, path, status);
    }

    // 输入授权子树与预览快照，在一个事务内比较和删除，全部成功才提交。
    bool deleteTree(const QString& path, const RegistryDocument& expectedTree, QString& error) override
    {
        if (parentPath(path).isEmpty() || expectedTree.rootPath.compare(path, Qt::CaseInsensitive) != 0
            || expectedTree.keys.isEmpty() || hasLink(expectedTree))
            return failure(error, QStringLiteral("Deleting a predefined registry root is forbidden."));
        QStringList paths;
        for (const auto& key : expectedTree.keys) {
            if (!inside(key.path, path))
                return failure(error, QStringLiteral("Registry deletion plan contains a key outside its authorized subtree."));
            paths.append(key.path);
        }
        std::sort(paths.begin(), paths.end(), [](const QString& a, const QString& b) {
            return a.size() > b.size();
        });
        QHash<QString, QVector<RegistryDocumentValue>> values;
        QHash<QString, QByteArray> security;
        for (const auto& key : expectedTree.keys)
            security.insert(folded(key.path), key.securityDescriptor);
        for (const auto& value : expectedTree.values)
            values[folded(value.keyPath)].append(value);
        ApplyTransaction transaction;
        if (!transaction.begin(path, error)) return false;
        // 写入前冻结删除清单，禁止把外部新出现的子键扩入授权范围。
        // 原值核验与所有删除共用一个事务；外部写者导致冲突/回滚，保留其数据。
        for (const auto& target : paths) {
            if (canceled(error))
                return false;
            ApplyKey key, parent;
            LSTATUS status = ERROR_SUCCESS;
            const auto expectedSecurity = security.value(folded(target));
            if (!openTransacted(target, KEY_QUERY_VALUE | DELETE | (expectedSecurity.isEmpty() ? 0 : READ_CONTROL),
                transaction.handle, key, status, error))
                return false;
            if (!expectedSecurity.isEmpty()) {
                constexpr SECURITY_INFORMATION parts = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
                DWORD bytes = 0;
                status = RegGetKeySecurity(key.handle, parts, nullptr, &bytes);
                if (status != ERROR_INSUFFICIENT_BUFFER || bytes > 1024 * 1024 || bytes == 0)
                    return apiError(error, target, status == ERROR_INSUFFICIENT_BUFFER || status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status);
                QByteArray currentSecurity(static_cast<qsizetype>(bytes), Qt::Uninitialized);
                status = RegGetKeySecurity(key.handle, parts,
                    reinterpret_cast<PSECURITY_DESCRIPTOR>(currentSecurity.data()), &bytes);
                if (status != ERROR_SUCCESS) return apiError(error, target, status);
                if (bytes > static_cast<DWORD>(currentSecurity.size())) return apiError(error, target, ERROR_INVALID_DATA);
                currentSecurity.resize(bytes);
                if (currentSecurity != expectedSecurity) return apiError(error, target, ERROR_TRANSACTIONAL_CONFLICT);
            }
            DWORD childCount = 0, valueCount = 0;
            status = RegQueryInfoKeyW(key.handle, nullptr, nullptr, nullptr, &childCount, nullptr,
                nullptr, &valueCount, nullptr, nullptr, nullptr, nullptr);
            if (status != ERROR_SUCCESS)
                return apiError(error, target, status);
            const auto expectedValues = values.value(folded(target));
            if (childCount != 0 || valueCount != static_cast<DWORD>(expectedValues.size()))
                return failure(error, QStringLiteral("Registry deletion stopped because the key acquired a child or changed its values."));
            for (const auto& value : expectedValues) {
                RegistryApplyValueState actual;
                if (!readValueHandle(key.handle, target, value.name, actual, error))
                    return false;
                if (!sameValue({true, value.type, value.data}, actual))
                    return failure(error, QStringLiteral("Registry value changed immediately before tree deletion."));
            }
            const QString parentName = parentPath(target);
            if (!openTransacted(parentName, KEY_QUERY_VALUE, transaction.handle, parent, status, error))
                return false;
            const QString leaf = target.mid(parentName.size() + 1);
            ApplyKey candidate;
            status = RegOpenKeyTransactedW(parent.handle, reinterpret_cast<LPCWSTR>(leaf.utf16()), 0,
                KEY_QUERY_VALUE | DELETE | m_view, &candidate.handle, transaction.handle, nullptr);
            if (status != ERROR_SUCCESS) return apiError(error, target, status);
            // 同时绑定实际删除名字与无链接核验过的对象，比较原生身份。
            // 重命名、替换或链接竞争不得把相对父键删除重定向到未备份的键。
            QString expectedIdentity, candidateIdentity;
            if (!keyIdentity(key.handle, target, expectedIdentity, error)
                || !keyIdentity(candidate.handle, target, candidateIdentity, error)) return false;
            if (expectedIdentity.compare(candidateIdentity, Qt::CaseInsensitive) != 0)
                return apiError(error, target, ERROR_TRANSACTIONAL_CONFLICT);
            key.close();
            if (canceled(error))
                return false;
            status = RegDeleteKeyTransactedW(parent.handle, reinterpret_cast<LPCWSTR>(leaf.utf16()),
                m_view, 0, transaction.handle, nullptr);
            if (status != ERROR_SUCCESS)
                return apiError(error, target, status);
        }
        if (canceled(error)) return false;
        return transaction.commit(path, error);
    }

private:
    // 固定同一事务创建缺失目的键及父链；预存在键仍按无链接句柄绑定。
    bool openMoveDestination(const QString& path, HANDLE transaction, ApplyKey& key, QString& error,
        const REGSAM access = KEY_QUERY_VALUE | KEY_SET_VALUE)
    {
        LSTATUS status = ERROR_SUCCESS;
        if (openTransacted(path, access,
            transaction, key, status, error)) return true;
        if (status != ERROR_FILE_NOT_FOUND && status != ERROR_PATH_NOT_FOUND) return false;
        error.clear();
        const QString parent = parentPath(path); // 缺失的预定义根不能自行创造。
        if (parent.isEmpty()) return apiError(error, path, status);
        ApplyKey parentKey;
        if (!openMoveDestination(parent, transaction, parentKey, error,
            KEY_QUERY_VALUE | KEY_CREATE_SUB_KEY)) return false;
        DWORD disposition = 0; // 若外部写者已经创建此键，不将它收养为本次新对象。
        const QString leaf = path.mid(parent.size() + 1);
        status = RegCreateKeyTransactedW(parentKey.handle, reinterpret_cast<LPCWSTR>(leaf.utf16()),
            0, nullptr, REG_OPTION_NON_VOLATILE,
            access | KEY_QUERY_VALUE | m_view,
            nullptr, &key.handle, &disposition, transaction, nullptr);
        if (status != ERROR_SUCCESS) return apiError(error, path, status);
        return disposition == REG_CREATED_NEW_KEY
            || apiError(error, path, ERROR_TRANSACTIONAL_CONFLICT);
    }

    // 输入精确路径与事务，key 输出绑定同一对象的新事务句柄。
    bool openTransacted(const QString& path, REGSAM access, HANDLE transaction,
        ApplyKey& key, LSTATUS& status, QString& error)
    {
        // 先逐组件无链接打开并检查；事务 API 的 options 是保留参数，不能传 OPEN_LINK。
        // 通过精确句柄的空子键绑定事务，避免重新按路径遍历而跟随外部替换的链接。
        ApplyKey exact;
        if (!open(path, access, exact, status, error)) return false;
        status = RegOpenKeyTransactedW(exact.handle, L"", 0,
            access | KEY_QUERY_VALUE | m_view, &key.handle, transaction, nullptr);
        return status == ERROR_SUCCESS || apiError(error, path, status);
    }

    // 读取借用的取消令牌；取消时返回 true 并说明写入尚未开始。
    bool canceled(QString& error) const
    {
        if (!m_canceled || !m_canceled->load(std::memory_order_relaxed))
            return false;
        error = QStringLiteral("Registry operation canceled before writing.");
        return true;
    }
    // 逐组件无链接打开；输出独占句柄、Win32 状态及诊断，不跟随中间链接。
    bool open(const QString& input, REGSAM access, ApplyKey& key, LSTATUS& status, QString& error)
    {
        QString path;
        if (!pathCanonical(input, path, error))
        {
            status = ERROR_INVALID_PARAMETER;
            return false;
        }
        const auto parts = path.split(QLatin1Char('\\'));
        HKEY current = rootHandle(parts.first());
        ApplyKey owned;
        QString currentPath = parts.first();
        if (parts.size() == 1) {
            status = RegOpenKeyExW(current, L"", REG_OPTION_OPEN_LINK, access | KEY_QUERY_VALUE | m_view, &key.handle);
            return status == ERROR_SUCCESS || apiError(error, path, status);
        }
        for (qsizetype i = 1; i < parts.size(); ++i) {
            HKEY child = nullptr;
            status = RegOpenKeyExW(current, reinterpret_cast<LPCWSTR>(parts.at(i).utf16()), REG_OPTION_OPEN_LINK,
                (i + 1 == parts.size() ? access : KEY_QUERY_VALUE) | KEY_QUERY_VALUE | m_view, &child);
            if (status != ERROR_SUCCESS)
                return apiError(error, path, status);
            owned.close();
            owned.handle = child;
            current = child;
            currentPath += QLatin1Char('\\') + parts.at(i);
            if (!inspectLink(current, currentPath, error))
            {
                status = ERROR_INVALID_PARAMETER;
                return false;
            }
        }
        key.handle = owned.handle;
        owned.handle = nullptr;
        return true;
    }

    int m_bits = 0; // 原视图位数，传给完整捕获服务。
    REGSAM m_view = 0; // 所有句柄共用的 WOW64 访问标志。
    const std::atomic_bool* m_canceled = nullptr; // 借用的取消令牌，生命周期覆盖调用。
};
} // namespace
#endif

// Windows 只读入口：绑定视图后端，再由纯状态机生成计划。
bool RegistryDocumentApplyService::prepareWin32(const RegistryDocument& document, RegistryApplyPlan& plan, QString& error)
{
#ifdef Q_OS_WIN
    Win32ApplyBackend backend(document.viewBits);
    return prepareWithBackend(document, backend, plan, error);
#else
    Q_UNUSED(document);
    plan = {};
    return failure(error, QStringLiteral("Registry apply preparation requires Windows."));
#endif
}

// Windows 执行入口：绑定计划和取消令牌，由纯状态机记录回执。
bool RegistryDocumentApplyService::applyWin32(const RegistryApplyPlan& plan, RegistryApplyResult& result,
    const std::atomic_bool* canceledToken)
{
#ifdef Q_OS_WIN
    Win32ApplyBackend backend(plan.viewBits, canceledToken);
    return applyWithBackend(plan, backend, result, canceledToken);
#else
    Q_UNUSED(plan);
    Q_UNUSED(canceledToken);
    result = {};
    return failure(result.error, QStringLiteral("Registry application requires Windows."));
#endif
}

// Windows 撤销入口：保留原提交身份和剩余回执，不反转部分撤销结果。
bool RegistryDocumentApplyService::undoWin32(const RegistryApplyResult& previous, RegistryApplyResult& result,
    const std::atomic_bool* canceledToken)
{
#ifdef Q_OS_WIN
    Win32ApplyBackend backend(previous.viewBits, canceledToken);
    return undoWithBackend(previous, backend, result, canceledToken);
#else
    Q_UNUSED(previous);
    Q_UNUSED(canceledToken);
    result = {};
    return failure(result.error, QStringLiteral("Registry committed undo requires Windows."));
#endif
}

// 原子值移动唯一 Win32 入口；上下文只来自调用者捕获的视图，任何 KTM 失败都拒绝普通写入。
bool RegistryDocumentApplyService::moveValueWin32(const QString& sourcePath, const QString& oldName,
    const QString& destinationPath, const QString& newName, const RegistryApplyValueState& expected,
    const int viewBits, RegistryValueRenameResult& result)
{
    result = {};
#ifdef Q_OS_WIN
    if ((viewBits != 0 && viewBits != 32 && viewBits != 64) || !expected.exists
        || expected.data.size() > 16 * 1024 * 1024 || oldName.size() > 16383 || newName.size() > 16383
        || oldName.contains(QChar(0)) || newName.contains(QChar(0))
        || !oldName.isValidUtf16() || !newName.isValidUtf16())
    {
        result.error = QStringLiteral("Invalid registry value rename request.");
        return false;
    }
    Win32ApplyBackend backend(viewBits);
    QString error;
    const bool ok = backend.moveValueAtomic(sourcePath, oldName, destinationPath, newName, expected, result, error);
    result.error = error;
    return ok;
#else
    Q_UNUSED(sourcePath);
    Q_UNUSED(oldName);
    Q_UNUSED(destinationPath);
    Q_UNUSED(newName);
    Q_UNUSED(expected);
    Q_UNUSED(viewBits);
    result.error = QStringLiteral("Atomic registry value moves require Windows KTM.");
    return false;
#endif
}
