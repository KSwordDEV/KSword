#include "../Framework.h"
#include "PrivilegeAccountPages.h"
#include "PrivilegeAccountSupport.h"
#include "../UI/TableContextMenu.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ImmutableValueTable.h"
#include "../UI/ThemeStatusRole.h"
#include "../theme.h"

#include <QApplication>
#include <QAction>
#include <QClipboard>
#include <QComboBox>
#include <QFutureWatcher>
#include <QPointer>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPromise>
#include <QPushButton>
#include <QRunnable>
#include <QShowEvent>
#include <QSet>
#include <QSplitter>
#include <QThreadPool>
#include <QVBoxLayout>
#include <QVariant>

#include <algorithm>
#include <exception>
#include <memory>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Lm.h>
// Framework 已经提供 winternl 类型；仅在 LSA 头范围内复用它们，防止 SDK 重定义字符串。
#pragma push_macro("_NTDEF_")
#ifndef _NTDEF_
#define _NTDEF_
#endif
#include <NTSecAPI.h>
#pragma pop_macro("_NTDEF_")
#include <Sddl.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace ks::privilege
{
namespace account_detail
{
    QString privilegeText(const char* key, const QString& source)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), source);
    }

    // Every runRows job owns a frozen context. Unscoped exported collectors retain
    // source text instead of consulting the mutable LanguageManager from a worker.
    thread_local const ks::i18n::SourceTextSnapshot* workerTranslation = nullptr;
    struct WorkerTranslationScope
    {
        const ks::i18n::SourceTextSnapshot* previous;
        explicit WorkerTranslationScope(const ks::i18n::SourceTextSnapshot& value)
            : previous(std::exchange(workerTranslation, &value)) {}
        ~WorkerTranslationScope() { workerTranslation = previous; }
    };
    QString privilegeWorkerText(const char* key, const QString& source)
    {
        return workerTranslation ? workerTranslation->contextText(QString::fromLatin1(key), source) : source;
    }

    QString winError(DWORD code)
    {
        wchar_t* text = nullptr;
        ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
            reinterpret_cast<LPWSTR>(&text), 0, nullptr);
        const QString message = text ? QString::fromWCharArray(text).trimmed() : QString();
        if (text) ::LocalFree(text);
        return QStringLiteral("%1 (code=%2)").arg(message).arg(code);
    }

    QString sidText(PSID sid)
    {
        if (!sid || !::IsValidSid(sid)) return {};
        LPWSTR text = nullptr;
        if (!::ConvertSidToStringSidW(sid, &text)) return {};
        const QString result = QString::fromWCharArray(text);
        ::LocalFree(text);
        return result;
    }

    struct SidResult
    {
        std::vector<unsigned char> bytes;
        QString error;
        PSID sid() const { return bytes.empty() ? nullptr : const_cast<unsigned char*>(bytes.data()); }
    };

    SidResult resolveSid(const QString& input)
    {
        SidResult result;
        const QString value = input.trimmed();
        if (value.isEmpty())
        {
            result.error = privilegeWorkerText("privilege.workbench.groups.error.account_empty", QStringLiteral("请输入账户名或 SID。"));
            return result;
        }
        if (value.startsWith(QStringLiteral("S-1-"), Qt::CaseInsensitive))
        {
            PSID sid = nullptr;
            if (!::ConvertStringSidToSidW(reinterpret_cast<LPCWSTR>(value.utf16()), &sid))
            {
                result.error = winError(::GetLastError());
                return result;
            }
            const DWORD length = ::GetLengthSid(sid);
            result.bytes.resize(length);
            ::CopySid(length, result.bytes.data(), sid);
            ::LocalFree(sid);
            return result;
        }
        DWORD bytes = 0, domainChars = 0;
        SID_NAME_USE use = SidTypeUnknown;
        ::LookupAccountNameW(nullptr, reinterpret_cast<LPCWSTR>(value.utf16()), nullptr,
            &bytes, nullptr, &domainChars, &use);
        const DWORD firstError = ::GetLastError();
        if (firstError != ERROR_INSUFFICIENT_BUFFER || bytes == 0 || bytes > 65536 || domainChars > 32768)
        {
            result.error = winError(firstError);
            return result;
        }
        result.bytes.resize(bytes);
        std::vector<wchar_t> domain(domainChars + 1);
        if (!::LookupAccountNameW(nullptr, reinterpret_cast<LPCWSTR>(value.utf16()),
            result.bytes.data(), &bytes, domain.data(), &domainChars, &use))
        {
            result.error = winError(::GetLastError());
            result.bytes.clear();
        }
        return result;
    }

    QString accountName(PSID sid)
    {
        DWORD nameChars = 0, domainChars = 0;
        SID_NAME_USE use = SidTypeUnknown;
        ::LookupAccountSidW(nullptr, sid, nullptr, &nameChars, nullptr, &domainChars, &use);
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || nameChars > 32768 || domainChars > 32768)
            return sidText(sid);
        std::vector<wchar_t> name(nameChars + 1), domain(domainChars + 1);
        if (!::LookupAccountSidW(nullptr, sid, name.data(), &nameChars, domain.data(), &domainChars, &use))
            return sidText(sid);
        const QString nameText = QString::fromWCharArray(name.data());
        const QString domainText = QString::fromWCharArray(domain.data());
        return domainText.isEmpty() ? nameText : domainText + QLatin1Char('\\') + nameText;
    }

    void appendError(QString& target, const QString& error)
    {
        if (!target.isEmpty()) target += QLatin1Char('\n');
        target += error;
    }

    template<class Value> void retireAccountValue(Value value) noexcept
    {
        try
        {
            auto task = std::unique_ptr<QRunnable>(QRunnable::create([value = std::move(value)] {}));
            QThreadPool::globalInstance()->start(task.get());
            task.release();
        }
        catch (...) {}
    }

    // QtCore-only asynchronous jobs: the future owns the result. Destroying a page destroys its
    // watcher and disconnects the completion; workers never dereference or invoke a UI pointer.
    template<class Work, class Done>
    void runRows(QObject* page, Work work, Done done)
    {
        const auto translator = ks::i18n::LanguageManager::instance().sourceTextSnapshot();
        using Result = std::shared_ptr<const RowsResult>;
        auto promise = std::make_shared<QPromise<Result>>();
        promise->start();
        auto* watcher = new QFutureWatcher<Result>(page);
        QObject::connect(watcher, &QFutureWatcher<Result>::finished, page, [watcher, done, owner = QPointer<QObject>(page)]()
        {
            // Detaching a finished future posts another finished notification.
            // Disconnect before reset so this completion can only consume one result.
            QObject::disconnect(watcher, nullptr, owner.data(), nullptr);
            auto result = watcher->result();
            const QPointer<QObject> alive(watcher);
            watcher->setFuture({});
            if (alive) watcher->deleteLater();
            if (owner) done(*result);
            retireAccountValue(std::move(result));
        });
        watcher->setFuture(promise->future());
        QThreadPool::globalInstance()->start(QRunnable::create([promise, work, translator]()
        {
            const WorkerTranslationScope scope(translator);
            RowsResult result;
            try { result = work(); }
            catch (const std::exception& exception) { result.error = QString::fromUtf8(exception.what()); }
            catch (...) { result.error = privilegeWorkerText("privilege.workbench.groups.worker_exception", QStringLiteral("后台任务发生异常。")); }
            promise->addResult(std::make_shared<const RowsResult>(std::move(result)));
            promise->finish();
        }));
    }

    // 替换性只读查询每个语义通道至多一个在途、一个最新待执行意图。
    // 变更预览与已接受写事务仍走 runRows，绝不覆盖或丢弃事务。
    class LatestRowsLane final : public QObject
    {
    public:
        explicit LatestRowsLane(QObject* parent) : QObject(parent) {}
        void invalidate()
        {
            ++m_revision;
            m_pending = {};
        }
        template<class Work, class Done>
        void submit(Work work, Done done)
        {
            const auto revision = ++m_revision;
            m_pending = [this, revision, work, done]()
            {
                runRows(this, work, [this, revision, done](const RowsResult& result)
                {
                    m_running = false;
                    const QPointer<LatestRowsLane> guard(this);
                    if (revision == m_revision) done(result);
                    if (guard) startPending();
                });
            };
            startPending();
        }
    private:
        void startPending()
        {
            if (m_running || !m_pending) return;
            m_running = true;
            auto next = std::move(m_pending);
            m_pending = {};
            next();
        }
        bool m_running = false;
        quint64 m_revision = 0;
        std::function<void()> m_pending;
    };

    LatestRowsLane* rowsLane(QObject* page, const char* key)
    {
        const QByteArray property = QByteArrayLiteral("ksword_latest_rows_") + key;
        auto* lane = static_cast<LatestRowsLane*>(page->property(property.constData()).value<QObject*>());
        if (lane == nullptr)
        {
            lane = new LatestRowsLane(page);
            page->setProperty(property.constData(), QVariant::fromValue(static_cast<QObject*>(lane)));
        }
        return lane;
    }

    template<class Work, class Done>
    void runLatestRows(QObject* page, const char* key, Work work, Done done)
    {
        rowsLane(page, key)->submit(std::move(work), std::move(done));
    }

    void invalidateLatestRows(QObject* page, const char* key)
    {
        rowsLane(page, key)->invalidate();
    }

    // 页面复用现有任务所有权与冻结翻译；输入后台任务和 UI 回调，无同步返回值。
    void runAccountRows(QObject* page, RowsWork work, RowsDone done)
    {
        runRows(page, std::move(work), std::move(done));
    }

    // 同类只读请求共用同一通道；过期结果不会覆盖后来输入。
    void runLatestAccountRows(QObject* page, const char* key, RowsWork work, RowsDone done)
    {
        runLatestRows(page, key, std::move(work), std::move(done));
    }

    QString machineName()
    {
        wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
        return ::GetComputerNameW(name, &length) ? QString::fromWCharArray(name, static_cast<int>(length)) : QString();
    }

    QString localName(const QString& value)
    {
        const QString input = value.trimmed();
        const qsizetype slash = input.indexOf(QLatin1Char('\\'));
        if (slash < 0) return input;
        const QString domain = input.left(slash);
        return (domain == QStringLiteral(".") || domain.compare(machineName(), Qt::CaseInsensitive) == 0)
            ? input.mid(slash + 1) : QString();
    }

    RowsResult enumerateUsers(DWORD preferredLength = 65536)
    {
        RowsResult result;
        QSet<QString> seen;
        DWORD resume = 0;
        NET_API_STATUS status = NERR_Success;
        do
        {
            LPUSER_INFO_1 data = nullptr;
            DWORD count = 0, total = 0;
            int newRows = 0;
            status = ::NetUserEnum(nullptr, 1, FILTER_NORMAL_ACCOUNT,
                reinterpret_cast<LPBYTE*>(&data), preferredLength, &count, &total, &resume);
            if (status != NERR_Success && status != ERROR_MORE_DATA)
                appendError(result.error, QStringLiteral("NetUserEnum: %1").arg(winError(status)));
            else
                for (DWORD index = 0; index < count; ++index)
                {
                    const USER_INFO_1& user = data[index];
                    Row row;
                    row.name = QString::fromWCharArray(user.usri1_name);
                    const QString identity = row.name.toCaseFolded();
                    if (seen.contains(identity)) continue;
                    seen.insert(identity); ++newRows;
                    row.detail = user.usri1_comment ? QString::fromWCharArray(user.usri1_comment) : QString();
                    row.extra = QString::number(user.usri1_flags);
                    row.disabled = (user.usri1_flags & UF_ACCOUNTDISABLE) != 0;
                    const SidResult sid = resolveSid(machineName() + QLatin1Char('\\') + row.name);
                    row.sid = sidText(sid.sid());
                    if (!sid.error.isEmpty()) appendError(result.error, row.name + QStringLiteral(": ") + sid.error);
                    result.rows.push_back(row);
                }
            if (data) ::NetApiBufferFree(data);
            if (status == ERROR_MORE_DATA && newRows == 0)
            {
                appendError(result.error, QStringLiteral("NetUserEnum: pagination did not advance"));
                break;
            }
        } while (status == ERROR_MORE_DATA);
        return result;
    }

    RowsResult enumerateGroups(DWORD preferredLength)
    {
        RowsResult result;
        QSet<QString> seen;
        DWORD_PTR resume = 0;
        NET_API_STATUS status = NERR_Success;
        do
        {
            LPLOCALGROUP_INFO_1 data = nullptr;
            DWORD count = 0, total = 0;
            int newRows = 0;
            status = ::NetLocalGroupEnum(nullptr, 1, reinterpret_cast<LPBYTE*>(&data),
                preferredLength, &count, &total, &resume);
            if (status != NERR_Success && status != ERROR_MORE_DATA)
                appendError(result.error, QStringLiteral("NetLocalGroupEnum: %1").arg(winError(status)));
            else
                for (DWORD index = 0; index < count; ++index)
                {
                    Row row;
                    row.name = QString::fromWCharArray(data[index].lgrpi1_name);
                    const QString identity = row.name.toCaseFolded();
                    if (seen.contains(identity)) continue;
                    seen.insert(identity); ++newRows;
                    row.detail = data[index].lgrpi1_comment ? QString::fromWCharArray(data[index].lgrpi1_comment) : QString();
                    const SidResult sid = resolveSid(row.name);
                    row.sid = sidText(sid.sid());
                    if (!sid.error.isEmpty()) appendError(result.error, row.name + QStringLiteral(": ") + sid.error);
                    result.rows.push_back(row);
                }
            if (data) ::NetApiBufferFree(data);
            if (status == ERROR_MORE_DATA && newRows == 0)
            {
                appendError(result.error, QStringLiteral("NetLocalGroupEnum: pagination did not advance"));
                break;
            }
        } while (status == ERROR_MORE_DATA);
        return result;
    }

    RowsResult enumerateMembers(const QString& group, DWORD preferredLength)
    {
        RowsResult result;
        QSet<QString> seen;
        DWORD_PTR resume = 0;
        NET_API_STATUS status = NERR_Success;
        do
        {
            LPLOCALGROUP_MEMBERS_INFO_2 data = nullptr;
            DWORD count = 0, total = 0;
            int newRows = 0;
            status = ::NetLocalGroupGetMembers(nullptr, reinterpret_cast<LPCWSTR>(group.utf16()),
                2, reinterpret_cast<LPBYTE*>(&data), preferredLength, &count, &total, &resume);
            if (status != NERR_Success && status != ERROR_MORE_DATA)
                appendError(result.error, QStringLiteral("NetLocalGroupGetMembers: %1").arg(winError(status)));
            else
                for (DWORD index = 0; index < count; ++index)
                {
                    Row row;
                    row.sid = sidText(data[index].lgrmi2_sid);
                    row.name = data[index].lgrmi2_domainandname
                        ? QString::fromWCharArray(data[index].lgrmi2_domainandname) : row.sid;
                    const QString identity = row.sid.isEmpty() ? row.name.toCaseFolded() : row.sid;
                    if (seen.contains(identity)) continue;
                    seen.insert(identity); ++newRows;
                    row.detail = QString::number(data[index].lgrmi2_sidusage);
                    result.rows.push_back(row);
                }
            if (data) ::NetApiBufferFree(data);
            if (status == ERROR_MORE_DATA && newRows == 0)
            {
                appendError(result.error, QStringLiteral("NetLocalGroupGetMembers: pagination did not advance"));
                break;
            }
        } while (status == ERROR_MORE_DATA);
        return result;
    }

    RowsResult accountGroups(const QString& input)
    {
        RowsResult result;
        const SidResult sid = resolveSid(input);
        if (!sid.error.isEmpty()) { result.error = sid.error; return result; }
        const QString account = accountName(sid.sid());
        QStringList directNames;
        bool directComplete = false;
        for (int pass = 0; pass < 2; ++pass)
        {
            LPLOCALGROUP_USERS_INFO_0 data = nullptr;
            DWORD count = 0, total = 0;
            const NET_API_STATUS status = ::NetUserGetLocalGroups(nullptr,
                reinterpret_cast<LPCWSTR>(account.utf16()), 0, pass == 0 ? 0 : LG_INCLUDE_INDIRECT,
                reinterpret_cast<LPBYTE*>(&data), MAX_PREFERRED_LENGTH, &count, &total);
            if (status != NERR_Success)
                appendError(result.error, QStringLiteral("NetUserGetLocalGroups (%1): %2").arg(pass).arg(winError(status)));
            if (pass == 0) directComplete = status == NERR_Success;
            if (status == NERR_Success || status == ERROR_MORE_DATA)
                for (DWORD index = 0; index < count; ++index)
                {
                    const QString group = QString::fromWCharArray(data[index].lgrui0_name);
                    if (pass == 0) directNames.push_back(group);
                    // Keep directly queried rows even if the inclusive query later fails.
                    if (pass == 0 || !directNames.contains(group, Qt::CaseInsensitive))
                    {
                        Row row;
                        row.name = group;
                        const SidResult groupSid = resolveSid(group);
                        row.sid = sidText(groupSid.sid());
                        if (!groupSid.error.isEmpty()) appendError(result.error, group + QStringLiteral(": ") + groupSid.error);
                        row.extra = pass == 0 ? QStringLiteral("direct")
                            : directComplete ? QStringLiteral("indirect") : QStringLiteral("unknown");
                        result.rows.push_back(row);
                    }
                }
            if (data) ::NetApiBufferFree(data);
        }
        return result;
    }

    struct Policy
    {
        LSA_HANDLE handle = nullptr;
        QString error;
        explicit Policy(ACCESS_MASK access)
        {
            LSA_OBJECT_ATTRIBUTES attributes = {};
            attributes.Length = sizeof(attributes);
            const NTSTATUS status = ::LsaOpenPolicy(nullptr, &attributes, access, &handle);
            if (status != 0) error = QStringLiteral("LsaOpenPolicy: %1").arg(winError(::LsaNtStatusToWinError(status)));
        }
        ~Policy() { if (handle) ::LsaClose(handle); }
        Policy(const Policy&) = delete;
        Policy& operator=(const Policy&) = delete;
    };

    LSA_UNICODE_STRING lsaString(const QString& text)
    {
        LSA_UNICODE_STRING value = {};
        value.Buffer = const_cast<PWSTR>(reinterpret_cast<LPCWSTR>(text.utf16()));
        value.Length = static_cast<USHORT>(text.size() * sizeof(wchar_t));
        value.MaximumLength = value.Length;
        return value;
    }

    QString knownRightDescription(const QString& right)
    {
        if (right == QStringLiteral("SeInteractiveLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.interactive", QStringLiteral("允许本地交互登录"));
        if (right == QStringLiteral("SeNetworkLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.network", QStringLiteral("允许从网络访问此计算机"));
        if (right == QStringLiteral("SeBatchLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.batch", QStringLiteral("允许作为批处理作业登录"));
        if (right == QStringLiteral("SeServiceLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.service", QStringLiteral("允许作为服务登录"));
        if (right == QStringLiteral("SeRemoteInteractiveLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.remote", QStringLiteral("允许通过远程桌面登录"));
        if (right == QStringLiteral("SeDenyInteractiveLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.deny_interactive", QStringLiteral("拒绝本地交互登录"));
        if (right == QStringLiteral("SeDenyNetworkLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.deny_network", QStringLiteral("拒绝从网络访问此计算机"));
        if (right == QStringLiteral("SeDenyBatchLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.deny_batch", QStringLiteral("拒绝作为批处理作业登录"));
        if (right == QStringLiteral("SeDenyServiceLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.deny_service", QStringLiteral("拒绝作为服务登录"));
        if (right == QStringLiteral("SeDenyRemoteInteractiveLogonRight")) return privilegeWorkerText("privilege.workbench.rights.logon.deny_remote", QStringLiteral("拒绝通过远程桌面登录"));
        return {};
    }

    QString rightDescription(const QString& right)
    {
        const QString known = knownRightDescription(right);
        if (!known.isEmpty()) return known;
        DWORD count = 0, language = 0;
        ::LookupPrivilegeDisplayNameW(nullptr, reinterpret_cast<LPCWSTR>(right.utf16()), nullptr, &count, &language);
        if (::GetLastError() != ERROR_INSUFFICIENT_BUFFER || count > 32768) return right;
        std::vector<wchar_t> buffer(count + 1);
        if (!::LookupPrivilegeDisplayNameW(nullptr, reinterpret_cast<LPCWSTR>(right.utf16()), buffer.data(), &count, &language)) return right;
        return QString::fromWCharArray(buffer.data(), static_cast<int>(count));
    }

    RowsResult directRights(LSA_HANDLE policy, PSID sid)
    {
        RowsResult result;
        PLSA_UNICODE_STRING data = nullptr;
        ULONG count = 0;
        const NTSTATUS status = ::LsaEnumerateAccountRights(policy, sid, &data, &count);
        const DWORD error = ::LsaNtStatusToWinError(status);
        // No policy record means no direct rights, not an enumeration failure.
        if (status != 0 && error != ERROR_FILE_NOT_FOUND)
            result.error = QStringLiteral("LsaEnumerateAccountRights: %1").arg(winError(error));
        if (status == 0)
            for (ULONG index = 0; index < count; ++index)
            {
                Row row;
                row.name = QString::fromWCharArray(data[index].Buffer, data[index].Length / sizeof(wchar_t));
                row.sid = sidText(sid);
                row.detail = rightDescription(row.name);
                row.detailRight = row.name;
                result.rows.push_back(row);
            }
        if (data) ::LsaFreeMemory(data);
        return result;
    }

    RowsResult queryRights(const QString& account)
    {
        const SidResult sid = resolveSid(account);
        if (!sid.error.isEmpty()) return {{}, sid.error};
        Policy policy(POLICY_LOOKUP_NAMES);
        if (!policy.error.isEmpty()) return {{}, policy.error};
        return directRights(policy.handle, sid.sid());
    }

    // 输入账户名/SID，返回经系统解析的身份；不把无法解析的 SID 当成现存账户。
    RowsResult resolveAccountIdentity(const QString& input)
    {
        const SidResult sid = resolveSid(input); // 保留经过格式检查的二进制 SID。
        RowsResult result; // 返回身份或明确的解析错误。
        result.error = sid.error;
        if (!result.error.isEmpty()) return result;
        DWORD nameChars = 0; // 账户名称缓冲区字符数。
        DWORD domainChars = 0; // 账户域缓冲区字符数。
        SID_NAME_USE use = SidTypeUnknown; // 区分用户、组与特殊身份。
        ::LookupAccountSidW(nullptr, sid.sid(), nullptr, &nameChars, nullptr, &domainChars, &use);
        const DWORD error = ::GetLastError(); // 只接受标准的两阶段缓冲区查询。
        if (error != ERROR_INSUFFICIENT_BUFFER)
        {
            result.error = winError(error);
            return result;
        }
        // 实际读取身份类型，来源名称仍复用统一的账户显示转换。
        std::vector<wchar_t> name(nameChars + 1); // 系统账户名。
        std::vector<wchar_t> domain(domainChars + 1); // 系统域名。
        if (!::LookupAccountSidW(nullptr, sid.sid(), name.data(), &nameChars,
            domain.data(), &domainChars, &use))
        {
            result.error = winError(::GetLastError());
            return result;
        }
        Row row; // 规范 SID 是后续去重身份，extra 携带身份类型。
        row.name = accountName(sid.sid());
        row.sid = sidText(sid.sid());
        row.extra = QString::number(use);
        result.rows.push_back(std::move(row));
        return result;
    }

    // 输入账户及权限，返回真实 SID、显示名和当前直接分配状态，供写前确认使用。
    RowsResult previewDirectRight(const QString& account, const QString& right)
    {
        const SidResult sid = resolveSid(account); // 写操作必须锁定已解析的 SID。
        RowsResult result; // 预览失败时保留原错误，不发起策略变更。
        result.error = sid.error;
        if (!result.error.isEmpty()) return result;
        result = queryRights(sidText(sid.sid()));
        if (!result.error.isEmpty()) return result;
        const bool assigned = std::any_of(result.rows.cbegin(), result.rows.cend(),
            [&right](const Row& row) { return row.name == right; }); // 只检查账户自身分配。
        result.rows = {{accountName(sid.sid()), sidText(sid.sid()), {},
            assigned ? QStringLiteral("assigned") : QStringLiteral("unassigned")}};
        return result;
    }

    // 输入确认后的 SID/权限/增删方向；仅改目标直接分配并同步回读验证。
    RowsResult writeDirectRight(const QString& sidString, const QString& right, bool add)
    {
        RowsResult result; // 返回回读后的直接权限或错误。
        const SidResult sid = resolveSid(sidString); // 固定身份，不按可变账户名写入。
        if (!sid.error.isEmpty())
        {
            result.error = sid.error;
            return result;
        }
        Policy policy(POLICY_LOOKUP_NAMES | (add ? POLICY_CREATE_ACCOUNT : 0)); // 最小策略访问权。
        if (!policy.error.isEmpty())
        {
            result.error = policy.error;
            return result;
        }
        // 不接受“移除所有权限”；一次只提交确认框中的一个权限。
        LSA_UNICODE_STRING value = lsaString(right); // LSA 需要的计数字符串。
        const NTSTATUS status = add
            ? ::LsaAddAccountRights(policy.handle, sid.sid(), &value, 1)
            : ::LsaRemoveAccountRights(policy.handle, sid.sid(), FALSE, &value, 1); // 系统回执。
        if (status != 0)
        {
            result.error = winError(::LsaNtStatusToWinError(status));
            return result;
        }
        result = directRights(policy.handle, sid.sid());
        if (!result.error.isEmpty())
        {
            result.error = privilegeWorkerText("privilege.workbench.groups.readback_failed",
                QStringLiteral("变更已提交，但回读失败：%1")).arg(result.error);
        }
        else
        {
            const bool assigned = std::any_of(result.rows.cbegin(), result.rows.cend(),
                [&right](const Row& row) { return row.name == right; }); // 验证请求状态。
            if (assigned != add)
                result.error = privilegeWorkerText("privilege.workbench.groups.readback_mismatch",
                    QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
        }
        return result;
    }

    RowsResult assignedAccounts(const QString& right)
    {
        RowsResult result;
        Policy policy(POLICY_LOOKUP_NAMES | POLICY_VIEW_LOCAL_INFORMATION);
        if (!policy.error.isEmpty()) { result.error = policy.error; return result; }
        LSA_UNICODE_STRING value = lsaString(right);
        PLSA_ENUMERATION_INFORMATION data = nullptr;
        ULONG count = 0;
        const NTSTATUS status = ::LsaEnumerateAccountsWithUserRight(policy.handle, &value,
            reinterpret_cast<PVOID*>(&data), &count);
        const DWORD error = ::LsaNtStatusToWinError(status);
        if (status != 0 && error != ERROR_NO_MORE_ITEMS)
            result.error = QStringLiteral("LsaEnumerateAccountsWithUserRight: %1").arg(winError(error));
        if (status == 0)
            for (ULONG index = 0; index < count; ++index)
                result.rows.push_back({accountName(data[index].Sid), sidText(data[index].Sid), right, {}, false});
        if (data) ::LsaFreeMemory(data);
        return result;
    }

    QStringList rightsCatalog()
    {
        return {
            QStringLiteral("SeInteractiveLogonRight"), QStringLiteral("SeNetworkLogonRight"),
            QStringLiteral("SeBatchLogonRight"), QStringLiteral("SeServiceLogonRight"),
            QStringLiteral("SeRemoteInteractiveLogonRight"), QStringLiteral("SeDenyInteractiveLogonRight"),
            QStringLiteral("SeDenyNetworkLogonRight"), QStringLiteral("SeDenyBatchLogonRight"),
            QStringLiteral("SeDenyServiceLogonRight"), QStringLiteral("SeDenyRemoteInteractiveLogonRight"),
            QStringLiteral("SeAssignPrimaryTokenPrivilege"), QStringLiteral("SeAuditPrivilege"),
            QStringLiteral("SeBackupPrivilege"), QStringLiteral("SeChangeNotifyPrivilege"),
            QStringLiteral("SeCreateGlobalPrivilege"), QStringLiteral("SeCreatePagefilePrivilege"),
            QStringLiteral("SeCreatePermanentPrivilege"), QStringLiteral("SeCreateSymbolicLinkPrivilege"),
            QStringLiteral("SeCreateTokenPrivilege"), QStringLiteral("SeDebugPrivilege"),
            QStringLiteral("SeDelegateSessionUserImpersonatePrivilege"), QStringLiteral("SeEnableDelegationPrivilege"),
            QStringLiteral("SeImpersonatePrivilege"), QStringLiteral("SeIncreaseBasePriorityPrivilege"),
            QStringLiteral("SeIncreaseQuotaPrivilege"), QStringLiteral("SeIncreaseWorkingSetPrivilege"),
            QStringLiteral("SeLoadDriverPrivilege"), QStringLiteral("SeLockMemoryPrivilege"),
            QStringLiteral("SeMachineAccountPrivilege"), QStringLiteral("SeManageVolumePrivilege"),
            QStringLiteral("SeProfileSingleProcessPrivilege"), QStringLiteral("SeRelabelPrivilege"),
            QStringLiteral("SeRemoteShutdownPrivilege"), QStringLiteral("SeRestorePrivilege"),
            QStringLiteral("SeSecurityPrivilege"), QStringLiteral("SeShutdownPrivilege"),
            QStringLiteral("SeSyncAgentPrivilege"), QStringLiteral("SeSystemEnvironmentPrivilege"),
            QStringLiteral("SeSystemProfilePrivilege"), QStringLiteral("SeSystemtimePrivilege"),
            QStringLiteral("SeTakeOwnershipPrivilege"), QStringLiteral("SeTcbPrivilege"),
            QStringLiteral("SeTimeZonePrivilege"), QStringLiteral("SeTrustedCredManAccessPrivilege"),
            QStringLiteral("SeUndockPrivilege")
        };
    }

    QString accountRowKey(const QString& name, const QString& sid)
    {
        // SID is the object identity even when its display name changes.
        return sid.isEmpty() ? QString::number(name.size()) + QLatin1Char(':') + name : sid;
    }

    ks::ui::ImmutableTableSource prepareAccountRows(const QVector<Row>& rows, bool account,
        bool membership, int columns, const ks::i18n::SourceTextSnapshot& translator)
    {
        const WorkerTranslationScope scope(translator);
        QVector<ks::ui::ImmutableTableRow> prepared;
        prepared.reserve(rows.size());
        for (const auto& row : rows)
        {
            QString detail = row.detailRight.isEmpty() ? QString() : knownRightDescription(row.detailRight);
            if (detail.isEmpty()) detail = row.detail;
            if (membership) detail = row.extra == QStringLiteral("unknown")
                ? privilegeWorkerText("privilege.workbench.groups.source_unknown", QStringLiteral("来源未知（直接查询不完整）"))
                : row.extra == QStringLiteral("direct")
                ? privilegeWorkerText("privilege.workbench.groups.direct", QStringLiteral("直接成员"))
                : privilegeWorkerText("privilege.workbench.groups.indirect", QStringLiteral("间接成员（全局组）"));
            QStringList cells{row.name, row.sid, detail, row.extra};
            if (account) cells = {row.name, row.sid, row.disabled
                ? privilegeWorkerText("privilege.workbench.groups.disabled", QStringLiteral("已禁用"))
                : privilegeWorkerText("privilege.workbench.groups.enabled", QStringLiteral("已启用")), detail};
            while (cells.size() > columns) cells.removeLast();
            ks::ui::ImmutableTableRow value;
            value.key = row.detailRight.isEmpty() ? accountRowKey(row.name, row.sid)
                : QString::number(row.name.size()) + QLatin1Char(':') + row.name + row.sid;
            value.cells = std::move(cells);
            value.roles.insert(Qt::UserRole, row.sid);
            value.roles.insert(Qt::UserRole + 1, row.disabled);
            prepared.push_back(std::move(value));
        }
        return ks::ui::MakeImmutableTableSource(std::move(prepared));
    }

    ValueTable* makeTable(QWidget* parent, QVector<TableHeader> headers)
    {
        auto* table = new ValueTable(parent, std::move(headers));
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        // Preserve QTableWidget's initial section-0 descending order; later user
        // header choices are retained by the immutable view across source refreshes.
        table->sortByColumn(0, Qt::DescendingOrder);
        table->setMinimumSize(0, 0);
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QWidget::customContextMenuRequested, table, [table](const QPoint& point)
        {
            const QModelIndex index = table->indexAt(point);
            if (!index.isValid()) return;
            const QString sid = table->cell(index.row(), 0, Qt::UserRole).toString();
            QStringList values;
            for (int column = 0; column < table->columnCount(); ++column)
                values.push_back(table->cell(index.row(), column).toString());
            const QPointer<ValueTable> alive(table);
            table->setCurrentIndex(index);
            if (!alive) return;
            auto* menu = new QMenu(table);
            menu->setAttribute(Qt::WA_DeleteOnClose);
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copySid = menu->addAction(privilegeText("privilege.workbench.groups.copy_sid", QStringLiteral("复制 SID")));
            copySid->setEnabled(!sid.isEmpty());
            QObject::connect(copySid, &QAction::triggered, menu, [sid]() { QApplication::clipboard()->setText(sid); });
            QAction* copyRow = menu->addAction(privilegeText("privilege.workbench.groups.copy_row", QStringLiteral("复制行")));
            ks::ui::SetTableContextActionRole(copyRow, ks::ui::TableContextActionRole::CopyRows);
            QObject::connect(copyRow, &QAction::triggered, menu, [values]() { QApplication::clipboard()->setText(values.join(QLatin1Char('\t'))); });
            menu->popup(table->viewport()->mapToGlobal(point));
        });
        return table;
    }

    bool fillTable(ValueTable* table, const QVector<Row>& rows, bool account, bool membership)
    {
        const QPointer<ValueTable> alive(table);
        const int columns = table->columnCount();
        table->setSourceFactory([rows, account, membership, columns](const auto& translator) {
            return prepareAccountRows(rows, account, membership, columns, translator);
        });
        return !alive.isNull();
    }

    bool filterTable(ValueTable* table, const QString& query)
    { const QPointer<ValueTable> alive(table); table->setQuery(query); return !alive.isNull(); }
    bool clearRows(ValueTable* table)
    { const QPointer<ValueTable> alive(table); table->clearRows(); return !alive.isNull(); }

    QPushButton* button(QWidget* page, const char* key, const QString& text)
    {
        auto* result = new QPushButton(privilegeText(key, text), page);
        result->setStyleSheet(KswordTheme::ThemedButtonStyle());
        return result;
    }

    void showResult(QLabel* status, const RowsResult& result)
    {
        const QPointer<QLabel> alive(status);
        status->setText(result.error.isEmpty()
            ? privilegeText("privilege.workbench.groups.completed", QStringLiteral("查询完成，共 %1 项。")).arg(result.rows.size())
            : result.error);
        if (!alive) return;
        ks::ui::ApplyStatusRole(status, result.error.isEmpty() ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
    }

    class AccountPage final : public QWidget
    {
    public:
        explicit AccountPage(QWidget* parent,
            std::function<void(const QString&, const QString&)> navigate) : QWidget(parent), m_navigate(std::move(navigate))
        {
            auto* layout = new QVBoxLayout(this);
            auto* toolbar = new QHBoxLayout;
            m_search = new QLineEdit(this);
            m_search->setPlaceholderText(privilegeText("privilege.workbench.groups.search_accounts", QStringLiteral("搜索账户、SID、状态或说明")));
            ks::ui::StyleSearchField(m_search);
            auto* refresh = button(this, "privilege.workbench.groups.refresh_accounts", QStringLiteral("刷新账户"));
            auto* enable = button(this, "privilege.workbench.groups.enable_account", QStringLiteral("启用账户"));
            auto* disable = button(this, "privilege.workbench.groups.disable_account", QStringLiteral("禁用账户"));
            toolbar->addWidget(m_search, 1); toolbar->addWidget(refresh); toolbar->addWidget(enable); toolbar->addWidget(disable);
            ks::ui::NormalizeToolbarRow(toolbar);
            layout->addLayout(toolbar);
            auto* navigation = new QHBoxLayout;
            auto* viewGroups = button(this, "privilege.workbench.groups.view_groups", QStringLiteral("查看用户组"));
            auto* viewRights = button(this, "privilege.workbench.groups.view_rights", QStringLiteral("查看权限分配"));
            auto* viewSessions = button(this, "privilege.workbench.groups.view_sessions", QStringLiteral("查看登录会话"));
            viewGroups->setObjectName(QStringLiteral("privilege_groups_navigation"));
            viewRights->setObjectName(QStringLiteral("privilege_rights_navigation"));
            viewSessions->setObjectName(QStringLiteral("privilege_sessions_navigation"));
            navigation->addWidget(viewGroups); navigation->addWidget(viewRights); navigation->addWidget(viewSessions); navigation->addStretch();
            ks::ui::NormalizeToolbarRow(navigation);
            layout->addLayout(navigation);
            viewGroups->setEnabled(static_cast<bool>(m_navigate));
            viewRights->setEnabled(static_cast<bool>(m_navigate));
            viewSessions->setEnabled(static_cast<bool>(m_navigate));
            QObject::connect(viewGroups, &QPushButton::clicked, this, [this]() { navigateTo(QStringLiteral("groups")); });
            QObject::connect(viewRights, &QPushButton::clicked, this, [this]() { navigateTo(QStringLiteral("rights")); });
            QObject::connect(viewSessions, &QPushButton::clicked, this, [this]() { navigateTo(QStringLiteral("sessions")); });
            m_table = makeTable(this, {TableHeader(QStringLiteral("privilege.workbench.groups.account"), QStringLiteral("账户")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.groups.state"), QStringLiteral("状态")), TableHeader(QStringLiteral("privilege.workbench.groups.description"), QStringLiteral("说明"))});
            m_table->setObjectName(QStringLiteral("privilege_accounts_table"));
            // 账户清单保留快照；所属组仅是当前账户的关联详情。
            ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Full);
            m_groups = makeTable(this, {TableHeader(QStringLiteral("privilege.workbench.groups.group"), QStringLiteral("用户组")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.groups.membership"), QStringLiteral("成员来源"))});
            ks::ui::SetTableActionBarMode(m_groups, ks::ui::TableActionBarMode::Compact);
            auto* splitter = new QSplitter(Qt::Vertical, this);
            splitter->addWidget(m_table); splitter->addWidget(m_groups);
            splitter->setStretchFactor(0, 3); splitter->setStretchFactor(1, 1);
            layout->addWidget(splitter, 1);
            m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
            QObject::connect(refresh, &QPushButton::clicked, this, [this]() { refreshUsers(); });
            QObject::connect(m_search, &QLineEdit::textChanged, this, [this](const QString& query) { if (!filterTable(m_table, query)) return; });
            m_table->currentRowChanged = [this]() {
                const QString key = m_table->rowKey(m_table->currentRow());
                if (key.isEmpty() && !m_lastAccountKey.isEmpty())
                {
                    const auto source = m_table->canonicalSource();
                    if (source && source->byKey.contains(m_lastAccountKey)) return; // Filtering keeps the related result.
                }
                if (m_lastAccountKey != key) refreshGroups();
            };
            m_table->sourceReady = [this]() { refreshGroups(); };
            QObject::connect(enable, &QPushButton::clicked, this, [this]() { setEnabledState(true); });
            QObject::connect(disable, &QPushButton::clicked, this, [this]() { setEnabledState(false); });
        }
    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_loaded) { m_loaded = true; refreshUsers(); }
        }
    private:
        void navigateTo(const QString& target)
        {
            const int row = m_table->currentRow();
            if (!m_navigate || row < 0) return;
            const QString sid = m_table->cell(row, 0, Qt::UserRole).toString();
            if (!sid.isEmpty()) m_navigate(target, sid);
        }
        void refreshUsers()
        {
            const quint64 generation = ++m_userGeneration;
            ++m_groupGeneration;
            invalidateLatestRows(this, "account_groups");
            if (!clearRows(m_groups)) return;
            runLatestRows(this, "users", []() { return enumerateUsers(); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_userGeneration) return;
                if (!fillTable(m_table, result.rows, true)) return; if (!filterTable(m_table, m_search->text())) return; showResult(m_status, result);
            });
        }
        void refreshGroups()
        {
            m_lastAccountKey = m_table->rowKey(m_table->currentRow());
            const quint64 generation = ++m_groupGeneration;
            const int row = m_table->currentRow();
            if (!clearRows(m_groups)) return;
            if (row < 0) { invalidateLatestRows(this, "account_groups"); return; }
            const QString account = m_table->cell(row, 0).toString();
            runLatestRows(this, "account_groups", [account]() { return accountGroups(account); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_groupGeneration) return;
                if (!fillTable(m_groups, result.rows, false, true)) return; showResult(m_status, result);
            });
        }
        void setEnabledState(bool enabled)
        {
            const int row = m_table->currentRow();
            if (row < 0) return;
            const QString account = m_table->cell(row, 0).toString();
            const QString sid = m_table->cell(row, 0, Qt::UserRole).toString();
            if (sid.isEmpty()) return;
            const QString before = m_table->cell(row, 2).toString();
            const QString after = enabled ? privilegeText("privilege.workbench.groups.enabled", QStringLiteral("已启用"))
                : privilegeText("privilege.workbench.groups.disabled", QStringLiteral("已禁用"));
            const QPointer<QWidget> pageGuard(this);
            if (QMessageBox::question(this, privilegeText("privilege.workbench.groups.preview", QStringLiteral("变更预览")),
                privilegeText("privilege.workbench.groups.account_preview", QStringLiteral("账户：%1\nSID：%2\n状态：%3 → %4\n\n应用后将回读确认。"))
                    .arg(account, sid, before, after), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
            if (!pageGuard) return;
            ++m_userGeneration; ++m_groupGeneration;
            invalidateLatestRows(this, "users");
            invalidateLatestRows(this, "account_groups");
            setEnabled(false);
            runRows(this, [account, sid, enabled]()
            {
                RowsResult result;
                const SidResult current = resolveSid(machineName() + QLatin1Char('\\') + account);
                if (!current.error.isEmpty()) { result.error = current.error; return result; }
                if (sidText(current.sid()) != sid)
                {
                    result.error = privilegeWorkerText("privilege.workbench.groups.identity_changed", QStringLiteral("账户身份已变化，请刷新后重试。"));
                    return result;
                }
                if (!setLocalAccountEnabled(account, enabled, &result.error)) return result;
                result = enumerateUsers();
                return result;
            }, [this](const RowsResult& result)
            {
                const QPointer<QWidget> enabledOwner(this);
                setEnabled(true);
                if (!enabledOwner) return;
                if (result.error.isEmpty()) { if (!fillTable(m_table, result.rows, true)) return; if (!filterTable(m_table, m_search->text())) return; }
                showResult(m_status, result);
            });
        }
        QLineEdit* m_search = nullptr;
        ValueTable* m_table = nullptr;
        ValueTable* m_groups = nullptr;
        QLabel* m_status = nullptr;
        QString m_lastAccountKey;
        quint64 m_userGeneration = 0, m_groupGeneration = 0;
        bool m_loaded = false;
        std::function<void(const QString&, const QString&)> m_navigate;
    };

    class GroupsPage final : public QWidget
    {
    public:
        explicit GroupsPage(QWidget* parent) : QWidget(parent)
        {
            auto* layout = new QVBoxLayout(this);
            auto* toolbar = new QHBoxLayout;
            m_search = new QLineEdit(this);
            m_search->setPlaceholderText(privilegeText("privilege.workbench.groups.search", QStringLiteral("搜索用户组、成员或 SID")));
            ks::ui::StyleSearchField(m_search);
            auto* refresh = button(this, "privilege.workbench.groups.refresh", QStringLiteral("刷新用户组"));
            toolbar->addWidget(m_search, 1); toolbar->addWidget(refresh); layout->addLayout(toolbar);
            ks::ui::NormalizeToolbarRow(toolbar);
            m_groups = makeTable(this, {TableHeader(QStringLiteral("privilege.workbench.groups.group"), QStringLiteral("用户组")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.groups.description"), QStringLiteral("说明"))});
            m_members = makeTable(this, {TableHeader(QStringLiteral("privilege.workbench.groups.member"), QStringLiteral("成员")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.groups.sid_type"), QStringLiteral("SID 类型值"))});
            // 本地组是主清单；成员及查询所属组是依附当前选择的辅助结果。
            ks::ui::SetTableActionBarMode(m_groups, ks::ui::TableActionBarMode::Full);
            ks::ui::SetTableActionBarMode(m_members, ks::ui::TableActionBarMode::Compact);
            auto* split = new QSplitter(Qt::Horizontal, this);
            split->addWidget(m_groups); split->addWidget(m_members); layout->addWidget(split, 3);
            auto* actions = new QHBoxLayout;
            m_member = new QLineEdit(this);
            ks::ui::StyleStandaloneInput(m_member); // 成员操作参数与搜索框分开登记。
            m_member->setPlaceholderText(privilegeText("privilege.workbench.groups.member_input", QStringLiteral("待加入的账户名或 SID")));
            auto* add = button(this, "privilege.workbench.groups.add", QStringLiteral("加入所选组"));
            auto* remove = button(this, "privilege.workbench.groups.remove", QStringLiteral("移除所选成员"));
            actions->addWidget(m_member, 1); actions->addWidget(add); actions->addWidget(remove); layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);
            auto* lookup = new QHBoxLayout;
            m_account = new QLineEdit(this);
            m_account->setPlaceholderText(privilegeText("privilege.workbench.groups.lookup_input", QStringLiteral("查询账户所属的本地组（含间接成员）")));
            ks::ui::StyleStandaloneInput(m_account);
            auto* query = button(this, "privilege.workbench.groups.lookup", QStringLiteral("查询所属组"));
            lookup->addWidget(m_account, 1); lookup->addWidget(query); layout->addLayout(lookup);
            ks::ui::NormalizeToolbarRow(lookup);
            m_memberships = makeTable(this, {TableHeader(QStringLiteral("privilege.workbench.groups.group"), QStringLiteral("用户组")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.groups.membership"), QStringLiteral("成员来源"))});
            layout->addWidget(m_memberships, 1);
            ks::ui::SetTableActionBarMode(m_memberships, ks::ui::TableActionBarMode::Compact);
            m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
            QObject::connect(refresh, &QPushButton::clicked, this, [this]() { refreshGroups(); });
            m_groups->currentRowChanged = [this]() {
                const QString key = m_groups->rowKey(m_groups->currentRow());
                if (key.isEmpty() && !m_lastGroupKey.isEmpty())
                {
                    const auto source = m_groups->canonicalSource();
                    if (source && source->byKey.contains(m_lastGroupKey)) return; // Filtering keeps the related result.
                }
                if (m_lastGroupKey != key) refreshMembers();
            };
            m_groups->sourceReady = [this]() { refreshMembers(); };
            QObject::connect(m_search, &QLineEdit::textChanged, this, [this](const QString& value) { if (!filterTable(m_groups, value)) return; if (!filterTable(m_members, value)) return; });
            QObject::connect(add, &QPushButton::clicked, this, [this]() { changeMember(true); });
            QObject::connect(remove, &QPushButton::clicked, this, [this]() { changeMember(false); });
            QObject::connect(query, &QPushButton::clicked, this, [this]() { lookupAccount(); });
            QObject::connect(m_account, &QLineEdit::returnPressed, this, [this]() { lookupAccount(); });
            m_memberships->rowDoubleClicked = [this](int row)
            {
                const QString name = m_memberships->cell(row, 0).toString();
                const QString sid = m_memberships->cell(row, 0, Qt::UserRole).toString();
                const QPointer<QWidget> alive(this);
                m_search->clear();
                if (!alive) return;
                m_groups->selectKey(accountRowKey(name, sid));
            };
        }
        void selectAccount(const QString& account) { m_account->setText(account); lookupAccount(); }
    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_loaded) { m_loaded = true; refreshGroups(); }
        }
    private:
        void refreshGroups()
        {
            const quint64 generation = ++m_groupsGeneration;
            ++m_membersGeneration;
            invalidateLatestRows(this, "members");
            if (!clearRows(m_members)) return;
            runLatestRows(this, "groups", []() { return enumerateGroups(); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_groupsGeneration) return;
                if (!fillTable(m_groups, result.rows)) return; if (!filterTable(m_groups, m_search->text())) return; showResult(m_status, result);
            });
        }
        void refreshMembers()
        {
            m_lastGroupKey = m_groups->rowKey(m_groups->currentRow());
            const quint64 generation = ++m_membersGeneration;
            if (!clearRows(m_members)) return;
            const int row = m_groups->currentRow();
            if (row < 0) { invalidateLatestRows(this, "members"); return; }
            const QString group = m_groups->cell(row, 0).toString();
            runLatestRows(this, "members", [group]() { return enumerateMembers(group); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_membersGeneration) return;
                if (!fillTable(m_members, result.rows)) return; if (!filterTable(m_members, m_search->text())) return; showResult(m_status, result);
            });
        }
        void lookupAccount()
        {
            const quint64 generation = ++m_lookupGeneration;
            const QString account = m_account->text().trimmed();
            if (!clearRows(m_memberships)) return;
            runLatestRows(this, "account_groups", [account]() { return accountGroups(account); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_lookupGeneration) return;
                if (!fillTable(m_memberships, result.rows, false, true)) return; showResult(m_status, result);
            });
        }
        void changeMember(bool add)
        {
            const int groupRow = m_groups->currentRow();
            if (groupRow < 0) return;
            const QString group = m_groups->cell(groupRow, 0).toString();
            const QString groupSid = m_groups->cell(groupRow, 0, Qt::UserRole).toString();
            if (groupSid.isEmpty()) return;
            QString member = m_member->text().trimmed();
            if (!add)
            {
                const int row = m_members->currentRow();
                if (row < 0) return;
                member = m_members->cell(row, 0, Qt::UserRole).toString();
            }
            if (member.isEmpty()) return;
            // Resolve and show a concrete SID before approval; never resolve names on the UI thread.
            ++m_membersGeneration; ++m_groupsGeneration;
            invalidateLatestRows(this, "members");
            invalidateLatestRows(this, "groups");
            setEnabled(false);
            runRows(this, [member]()
            {
                const SidResult sid = resolveSid(member);
                RowsResult result;
                result.error = sid.error;
                if (result.error.isEmpty()) result.rows.push_back({accountName(sid.sid()), sidText(sid.sid()), {}, {}, false});
                return result;
            }, [this, group, groupSid, add](const RowsResult& resolved)
            {
                const QPointer<QWidget> enabledOwner(this);
                setEnabled(true);
                if (!enabledOwner) return;
                if (!resolved.error.isEmpty() || resolved.rows.isEmpty()) { showResult(m_status, resolved); return; }
                const Row memberRow = resolved.rows.first();
                const QString action = add ? privilegeText("privilege.workbench.groups.action_add", QStringLiteral("加入"))
                    : privilegeText("privilege.workbench.groups.action_remove", QStringLiteral("移除"));
                const QPointer<QWidget> pageGuard(this);
                if (QMessageBox::question(this, privilegeText("privilege.workbench.groups.preview", QStringLiteral("变更预览")),
                    privilegeText("privilege.workbench.groups.member_preview", QStringLiteral("操作：%1\n用户组：%2\n组 SID：%3\n成员：%4\n成员 SID：%5\n\n应用后将回读确认成员关系。"))
                        .arg(action, group, groupSid, memberRow.name, memberRow.sid), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
                if (!pageGuard) return;
                const QString sidString = memberRow.sid;
                setEnabled(false);
                runRows(this, [group, groupSid, sidString, add]()
                {
                    RowsResult result;
                    const SidResult identity = resolveSid(group), memberSid = resolveSid(sidString);
                    if (!identity.error.isEmpty() || !memberSid.error.isEmpty())
                    { result.error = identity.error + memberSid.error; return result; }
                    if (sidText(identity.sid()) != groupSid)
                    { result.error = privilegeWorkerText("privilege.workbench.groups.identity_changed", QStringLiteral("账户身份已变化，请刷新后重试。")); return result; }
                    LOCALGROUP_MEMBERS_INFO_0 value = {}; value.lgrmi0_sid = memberSid.sid();
                    const NET_API_STATUS status = add
                        ? ::NetLocalGroupAddMembers(nullptr, reinterpret_cast<LPCWSTR>(group.utf16()), 0, reinterpret_cast<LPBYTE>(&value), 1)
                        : ::NetLocalGroupDelMembers(nullptr, reinterpret_cast<LPCWSTR>(group.utf16()), 0, reinterpret_cast<LPBYTE>(&value), 1);
                    if (status != NERR_Success) { result.error = winError(status); return result; }
                    result = enumerateMembers(group);
                    if (!result.error.isEmpty())
                        result.error = privilegeWorkerText("privilege.workbench.groups.readback_failed", QStringLiteral("变更已提交，但回读失败：%1")).arg(result.error);
                    else
                    {
                        const bool present = std::any_of(result.rows.cbegin(), result.rows.cend(), [&sidString](const Row& row) { return row.sid == sidString; });
                        if (present != add)
                            result.error = privilegeWorkerText("privilege.workbench.groups.readback_mismatch", QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
                    }
                    return result;
                }, [this, group](const RowsResult& result)
                {
                    const QPointer<QWidget> enabledOwner(this);
                setEnabled(true);
                if (!enabledOwner) return;
                    const int selected = m_groups->currentRow();
                    if (selected >= 0 && m_groups->cell(selected, 0).toString() == group)
                    { if (!fillTable(m_members, result.rows)) return; if (!filterTable(m_members, m_search->text())) return; }
                    showResult(m_status, result);
                    if (!clearRows(m_memberships)) return; ++m_lookupGeneration;
                });
            });
        }
        QLineEdit *m_search = nullptr, *m_member = nullptr, *m_account = nullptr;
        ValueTable *m_groups = nullptr, *m_members = nullptr, *m_memberships = nullptr;
        QLabel* m_status = nullptr;
        QString m_lastGroupKey;
        quint64 m_groupsGeneration = 0, m_membersGeneration = 0, m_lookupGeneration = 0;
        bool m_loaded = false;
    };

}

using namespace account_detail;

QWidget* createAccountManagementPage(QWidget* parent,
    std::function<void(const QString&, const QString&)> navigate)
{ return new AccountPage(parent, std::move(navigate)); }
QWidget* createGroupsPage(QWidget* parent) { return new GroupsPage(parent); }
void selectGroupAccount(QWidget* page, const QString& account)
{ if (auto* groups = dynamic_cast<GroupsPage*>(page)) groups->selectAccount(account); }

bool setLocalAccountEnabled(const QString& account, bool enabled, QString* error)
{
    if (error) error->clear();
    const QString name = localName(account);
    if (name.isEmpty())
    {
        if (error) *error = privilegeWorkerText("privilege.workbench.groups.local_only", QStringLiteral("只能修改本机本地账户。"));
        return false;
    }
    LPUSER_INFO_1 current = nullptr;
    NET_API_STATUS status = ::NetUserGetInfo(nullptr, reinterpret_cast<LPCWSTR>(name.utf16()), 1,
        reinterpret_cast<LPBYTE*>(&current));
    if (status != NERR_Success) { if (error) *error = winError(status); return false; }
    USER_INFO_1008 flags = {};
    flags.usri1008_flags = enabled ? current->usri1_flags & ~UF_ACCOUNTDISABLE : current->usri1_flags | UF_ACCOUNTDISABLE;
    ::NetApiBufferFree(current); current = nullptr;
    DWORD parameter = 0;
    status = ::NetUserSetInfo(nullptr, reinterpret_cast<LPCWSTR>(name.utf16()), 1008, reinterpret_cast<LPBYTE>(&flags), &parameter);
    if (status != NERR_Success) { if (error) *error = winError(status); return false; }
    status = ::NetUserGetInfo(nullptr, reinterpret_cast<LPCWSTR>(name.utf16()), 1, reinterpret_cast<LPBYTE*>(&current));
    if (status != NERR_Success)
    {
        if (error) *error = privilegeWorkerText("privilege.workbench.groups.readback_failed", QStringLiteral("变更已提交，但回读失败：%1")).arg(winError(status));
        return false;
    }
    const bool readbackEnabled = (current->usri1_flags & UF_ACCOUNTDISABLE) == 0;
    ::NetApiBufferFree(current);
    if (readbackEnabled != enabled)
    {
        if (error) *error = privilegeWorkerText("privilege.workbench.groups.readback_mismatch", QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
        return false;
    }
    return true;
}

QJsonObject captureAccountPolicySnapshot(const ks::i18n::SourceTextSnapshot* translator)
{
    // The caller captures the value before dispatch. Preserve an existing nested
    // worker context; a legacy no-context entry keeps source text without GUI access.
    const ks::i18n::SourceTextSnapshot sourceOnly;
    const WorkerTranslationScope scope(translator ? *translator : workerTranslation ? *workerTranslation : sourceOnly);
    QJsonArray entries, errors;
    const auto addError = [&errors](const QString& message) { if (!message.isEmpty()) errors.push_back(message); };
    const auto entry = [&entries](const QString& key, const QJsonValue& value)
    { entries.push_back(QJsonObject{{QStringLiteral("key"), key}, {QStringLiteral("value"), value}}); };
    const RowsResult users = enumerateUsers(); addError(users.error);
    for (const Row& user : users.rows)
        if (!user.sid.isEmpty())
        {
            entry(QStringLiteral("account/%1/name").arg(user.sid), user.name);
            entry(QStringLiteral("account/%1/enabled").arg(user.sid), !user.disabled);
            entry(QStringLiteral("account/%1/flags").arg(user.sid), user.extra);
        }
    const RowsResult groups = enumerateGroups(); addError(groups.error);
    for (const Row& group : groups.rows)
    {
        if (group.sid.isEmpty()) continue;
        entry(QStringLiteral("group/%1/name").arg(group.sid), group.name);
        const RowsResult members = enumerateMembers(group.name); addError(members.error);
        for (const Row& member : members.rows)
            if (!member.sid.isEmpty()) entry(QStringLiteral("group/%1/member/%2").arg(group.sid, member.sid), true);
            else addError(QStringLiteral("Invalid member SID: %1/%2").arg(group.name, member.name));
    }
    Policy policy(POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES); addError(policy.error);
    if (policy.handle)
    {
        PLSA_ENUMERATION_INFORMATION data = nullptr;
        ULONG count = 0;
        // Documented null-right enumeration returns every LSA principal without a resume cursor.
        const NTSTATUS status = ::LsaEnumerateAccountsWithUserRight(policy.handle, nullptr,
            reinterpret_cast<PVOID*>(&data), &count);
        if (status != 0 && ::LsaNtStatusToWinError(status) != ERROR_NO_MORE_ITEMS)
            addError(QStringLiteral("LsaEnumerateAccountsWithUserRight: %1").arg(winError(::LsaNtStatusToWinError(status))));
        if (status == 0)
            for (ULONG index = 0; index < count; ++index)
            {
                const QString sid = sidText(data[index].Sid);
                if (sid.isEmpty()) { addError(QStringLiteral("Invalid LSA principal SID")); continue; }
                const RowsResult rights = directRights(policy.handle, data[index].Sid); addError(rights.error);
                for (const Row& right : rights.rows)
                    entry(QStringLiteral("right/%1/account/%2").arg(right.name, sid), true);
            }
        if (data) ::LsaFreeMemory(data);
    }
    // Sort independently of Windows enumeration order, keeping comparison and export reproducible.
    QVector<QJsonObject> sorted;
    for (const QJsonValue& value : entries) sorted.push_back(value.toObject());
    std::sort(sorted.begin(), sorted.end(), [](const QJsonObject& left, const QJsonObject& right)
    { return left.value(QStringLiteral("key")).toString() < right.value(QStringLiteral("key")).toString(); });
    entries = QJsonArray(); for (const QJsonObject& value : sorted) entries.push_back(value);
    return {{QStringLiteral("entries"), entries}, {QStringLiteral("errors"), errors}};
}
}
