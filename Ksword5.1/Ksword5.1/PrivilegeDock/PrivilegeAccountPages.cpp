#include "PrivilegeAccountPages.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
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

#include <algorithm>
#include <exception>
#include <memory>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Lm.h>
#include <NTSecAPI.h>
#include <Sddl.h>

#pragma comment(lib, "Netapi32.lib")
#pragma comment(lib, "Advapi32.lib")

namespace ks::privilege
{
namespace
{
    QString privilegeText(const char* key, const QString& source)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), source);
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
            result.error = privilegeText("privilege.workbench.groups.error.account_empty", QStringLiteral("请输入账户名或 SID。"));
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

    struct Row
    {
        QString name;
        QString sid;
        QString detail;
        QString extra;
        bool disabled = false;
    };
    struct RowsResult
    {
        QVector<Row> rows;
        QString error;
    };

    void appendError(QString& target, const QString& error)
    {
        if (!target.isEmpty()) target += QLatin1Char('\n');
        target += error;
    }

    // QtCore-only asynchronous jobs: the future owns the result. Destroying a page destroys its
    // watcher and disconnects the completion; workers never dereference or invoke a UI pointer.
    template<class Work, class Done>
    void runRows(QWidget* page, Work work, Done done)
    {
        auto promise = std::make_shared<QPromise<RowsResult>>();
        promise->start();
        auto* watcher = new QFutureWatcher<RowsResult>(page);
        QObject::connect(watcher, &QFutureWatcher<RowsResult>::finished, page, [watcher, done]()
        {
            const RowsResult result = watcher->result();
            watcher->deleteLater();
            done(result);
        });
        watcher->setFuture(promise->future());
        QThreadPool::globalInstance()->start(QRunnable::create([promise, work]()
        {
            RowsResult result;
            try { result = work(); }
            catch (const std::exception& exception) { result.error = QString::fromUtf8(exception.what()); }
            catch (...) { result.error = privilegeText("privilege.workbench.groups.worker_exception", QStringLiteral("后台任务发生异常。")); }
            promise->addResult(result);
            promise->finish();
        }));
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

    RowsResult enumerateGroups(DWORD preferredLength = 65536)
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

    RowsResult enumerateMembers(const QString& group, DWORD preferredLength = 65536)
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

    QString rightDescription(const QString& right)
    {
        if (right == QStringLiteral("SeInteractiveLogonRight")) return privilegeText("privilege.workbench.rights.logon.interactive", QStringLiteral("允许本地交互登录"));
        if (right == QStringLiteral("SeNetworkLogonRight")) return privilegeText("privilege.workbench.rights.logon.network", QStringLiteral("允许从网络访问此计算机"));
        if (right == QStringLiteral("SeBatchLogonRight")) return privilegeText("privilege.workbench.rights.logon.batch", QStringLiteral("允许作为批处理作业登录"));
        if (right == QStringLiteral("SeServiceLogonRight")) return privilegeText("privilege.workbench.rights.logon.service", QStringLiteral("允许作为服务登录"));
        if (right == QStringLiteral("SeRemoteInteractiveLogonRight")) return privilegeText("privilege.workbench.rights.logon.remote", QStringLiteral("允许通过远程桌面登录"));
        if (right == QStringLiteral("SeDenyInteractiveLogonRight")) return privilegeText("privilege.workbench.rights.logon.deny_interactive", QStringLiteral("拒绝本地交互登录"));
        if (right == QStringLiteral("SeDenyNetworkLogonRight")) return privilegeText("privilege.workbench.rights.logon.deny_network", QStringLiteral("拒绝从网络访问此计算机"));
        if (right == QStringLiteral("SeDenyBatchLogonRight")) return privilegeText("privilege.workbench.rights.logon.deny_batch", QStringLiteral("拒绝作为批处理作业登录"));
        if (right == QStringLiteral("SeDenyServiceLogonRight")) return privilegeText("privilege.workbench.rights.logon.deny_service", QStringLiteral("拒绝作为服务登录"));
        if (right == QStringLiteral("SeDenyRemoteInteractiveLogonRight")) return privilegeText("privilege.workbench.rights.logon.deny_remote", QStringLiteral("拒绝通过远程桌面登录"));
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

    QTableWidget* makeTable(QWidget* parent, const QStringList& headers)
    {
        auto* table = new ks::ui::VisibleTableWidget(parent);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setAlternatingRowColors(true);
        table->verticalHeader()->hide();
        table->horizontalHeader()->setStretchLastSection(true);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        table->setMinimumSize(0, 0);
        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QWidget::customContextMenuRequested, table, [table](const QPoint& point)
        {
            const QModelIndex index = table->indexAt(point);
            if (!index.isValid()) return;
            table->setCurrentCell(index.row(), index.column());
            const QString sid = table->item(index.row(), 0)->data(Qt::UserRole).toString();
            QStringList values;
            for (int column = 0; column < table->columnCount(); ++column)
                values.push_back(table->item(index.row(), column) ? table->item(index.row(), column)->text() : QString());
            // A non-blocking popup keeps worker commits outside an exec() nested event loop.
            auto* menu = new QMenu(table);
            menu->setAttribute(Qt::WA_DeleteOnClose);
            QAction* copySid = menu->addAction(privilegeText("privilege.workbench.groups.copy_sid", QStringLiteral("复制 SID")));
            copySid->setEnabled(!sid.isEmpty());
            QObject::connect(copySid, &QAction::triggered, menu, [sid]() { QApplication::clipboard()->setText(sid); });
            QAction* copyRow = menu->addAction(privilegeText("privilege.workbench.groups.copy_row", QStringLiteral("复制行")));
            QObject::connect(copyRow, &QAction::triggered, menu, [values]() { QApplication::clipboard()->setText(values.join(QLatin1Char('\t'))); });
            menu->popup(table->viewport()->mapToGlobal(point));
        });
        return table;
    }

    void fillTable(QTableWidget* table, const QVector<Row>& rows, bool account = false)
    {
        table->setSortingEnabled(false);
        table->setRowCount(rows.size());
        for (qsizetype index = 0; index < rows.size(); ++index)
        {
            const Row& row = rows[index];
            QStringList values{row.name, row.sid, row.detail, row.extra};
            if (account) values = {row.name, row.sid, row.disabled
                ? privilegeText("privilege.workbench.groups.disabled", QStringLiteral("已禁用"))
                : privilegeText("privilege.workbench.groups.enabled", QStringLiteral("已启用")), row.detail};
            for (int column = 0; column < table->columnCount(); ++column)
            {
                auto* item = new QTableWidgetItem(values.value(column));
                item->setToolTip(values.value(column));
                if (column == 0)
                {
                    item->setData(Qt::UserRole, row.sid);
                    item->setData(Qt::UserRole + 1, row.disabled);
                }
                table->setItem(static_cast<int>(index), column, item);
            }
        }
        table->setSortingEnabled(true);
    }

    void filterTable(QTableWidget* table, const QString& query)
    {
        for (int row = 0; row < table->rowCount(); ++row)
        {
            bool match = query.isEmpty();
            for (int column = 0; !match && column < table->columnCount(); ++column)
                match = table->item(row, column) && table->item(row, column)->text().contains(query, Qt::CaseInsensitive);
            table->setRowHidden(row, !match);
        }
    }

    QPushButton* button(QWidget* page, const char* key, const QString& text)
    {
        auto* result = new QPushButton(privilegeText(key, text), page);
        result->setStyleSheet(KswordTheme::ThemedButtonStyle());
        return result;
    }

    void showResult(QLabel* status, const RowsResult& result)
    {
        status->setText(result.error.isEmpty()
            ? privilegeText("privilege.workbench.groups.completed", QStringLiteral("查询完成，共 %1 项。")).arg(result.rows.size())
            : result.error);
        ks::ui::ApplyStatusRole(status, result.error.isEmpty() ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
    }

    QVector<Row> membershipRows(QVector<Row> rows)
    {
        for (Row& row : rows)
            row.detail = row.extra == QStringLiteral("unknown")
                ? privilegeText("privilege.workbench.groups.source_unknown", QStringLiteral("来源未知（直接查询不完整）"))
                : row.extra == QStringLiteral("direct")
                ? privilegeText("privilege.workbench.groups.direct", QStringLiteral("直接成员"))
                : privilegeText("privilege.workbench.groups.indirect", QStringLiteral("间接成员（全局组）"));
        return rows;
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
            m_table = makeTable(this, {privilegeText("privilege.workbench.groups.account", QStringLiteral("账户")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.state", QStringLiteral("状态")), privilegeText("privilege.workbench.groups.description", QStringLiteral("说明"))});
            m_table->setObjectName(QStringLiteral("privilege_accounts_table"));
            // 账户清单保留快照；所属组仅是当前账户的关联详情。
            ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Full);
            m_groups = makeTable(this, {privilegeText("privilege.workbench.groups.group", QStringLiteral("用户组")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.membership", QStringLiteral("成员来源"))});
            ks::ui::SetTableActionBarMode(m_groups, ks::ui::TableActionBarMode::Compact);
            auto* splitter = new QSplitter(Qt::Vertical, this);
            splitter->addWidget(m_table); splitter->addWidget(m_groups);
            splitter->setStretchFactor(0, 3); splitter->setStretchFactor(1, 1);
            layout->addWidget(splitter, 1);
            m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
            QObject::connect(refresh, &QPushButton::clicked, this, [this]() { refreshUsers(); });
            QObject::connect(m_search, &QLineEdit::textChanged, this, [this](const QString& query) { filterTable(m_table, query); });
            QObject::connect(m_table, &QTableWidget::itemSelectionChanged, this, [this]() { refreshGroups(); });
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
            if (!m_navigate || row < 0 || m_table->isRowHidden(row)) return;
            const QString sid = m_table->item(row, 0)->data(Qt::UserRole).toString();
            if (!sid.isEmpty()) m_navigate(target, sid);
        }
        void refreshUsers()
        {
            const quint64 generation = ++m_userGeneration;
            ++m_groupGeneration;
            m_groups->setRowCount(0);
            runRows(this, []() { return enumerateUsers(); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_userGeneration) return;
                fillTable(m_table, result.rows, true); filterTable(m_table, m_search->text()); showResult(m_status, result);
            });
        }
        void refreshGroups()
        {
            const quint64 generation = ++m_groupGeneration;
            const int row = m_table->currentRow();
            m_groups->setRowCount(0);
            if (row < 0 || m_table->isRowHidden(row)) return;
            const QString account = m_table->item(row, 0)->text();
            runRows(this, [account]() { return accountGroups(account); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_groupGeneration) return;
                fillTable(m_groups, membershipRows(result.rows)); showResult(m_status, result);
            });
        }
        void setEnabledState(bool enabled)
        {
            const int row = m_table->currentRow();
            if (row < 0 || m_table->isRowHidden(row)) return;
            const QString account = m_table->item(row, 0)->text();
            const QString sid = m_table->item(row, 0)->data(Qt::UserRole).toString();
            if (sid.isEmpty()) return;
            const QString before = m_table->item(row, 2)->text();
            const QString after = enabled ? privilegeText("privilege.workbench.groups.enabled", QStringLiteral("已启用"))
                : privilegeText("privilege.workbench.groups.disabled", QStringLiteral("已禁用"));
            const QPointer<QWidget> pageGuard(this);
            if (QMessageBox::question(this, privilegeText("privilege.workbench.groups.preview", QStringLiteral("变更预览")),
                privilegeText("privilege.workbench.groups.account_preview", QStringLiteral("账户：%1\nSID：%2\n状态：%3 → %4\n\n应用后将回读确认。"))
                    .arg(account, sid, before, after), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
            if (!pageGuard) return;
            ++m_userGeneration; ++m_groupGeneration;
            setEnabled(false);
            runRows(this, [account, sid, enabled]()
            {
                RowsResult result;
                const SidResult current = resolveSid(machineName() + QLatin1Char('\\') + account);
                if (!current.error.isEmpty()) { result.error = current.error; return result; }
                if (sidText(current.sid()) != sid)
                {
                    result.error = privilegeText("privilege.workbench.groups.identity_changed", QStringLiteral("账户身份已变化，请刷新后重试。"));
                    return result;
                }
                if (!setLocalAccountEnabled(account, enabled, &result.error)) return result;
                result = enumerateUsers();
                return result;
            }, [this](const RowsResult& result)
            {
                setEnabled(true);
                if (result.error.isEmpty()) { fillTable(m_table, result.rows, true); filterTable(m_table, m_search->text()); }
                showResult(m_status, result);
            });
        }
        QLineEdit* m_search = nullptr;
        QTableWidget* m_table = nullptr;
        QTableWidget* m_groups = nullptr;
        QLabel* m_status = nullptr;
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
            m_groups = makeTable(this, {privilegeText("privilege.workbench.groups.group", QStringLiteral("用户组")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.description", QStringLiteral("说明"))});
            m_members = makeTable(this, {privilegeText("privilege.workbench.groups.member", QStringLiteral("成员")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.sid_type", QStringLiteral("SID 类型值"))});
            // 本地组是主清单；成员及查询所属组是依附当前选择的辅助结果。
            ks::ui::SetTableActionBarMode(m_groups, ks::ui::TableActionBarMode::Full);
            ks::ui::SetTableActionBarMode(m_members, ks::ui::TableActionBarMode::Compact);
            auto* split = new QSplitter(Qt::Horizontal, this);
            split->addWidget(m_groups); split->addWidget(m_members); layout->addWidget(split, 3);
            auto* actions = new QHBoxLayout;
            m_member = new QLineEdit(this);
            m_member->setPlaceholderText(privilegeText("privilege.workbench.groups.member_input", QStringLiteral("待加入的账户名或 SID")));
            auto* add = button(this, "privilege.workbench.groups.add", QStringLiteral("加入所选组"));
            auto* remove = button(this, "privilege.workbench.groups.remove", QStringLiteral("移除所选成员"));
            actions->addWidget(m_member, 1); actions->addWidget(add); actions->addWidget(remove); layout->addLayout(actions);
            ks::ui::NormalizeToolbarRow(actions);
            auto* lookup = new QHBoxLayout;
            m_account = new QLineEdit(this);
            m_account->setPlaceholderText(privilegeText("privilege.workbench.groups.lookup_input", QStringLiteral("查询账户所属的本地组（含间接成员）")));
            auto* query = button(this, "privilege.workbench.groups.lookup", QStringLiteral("查询所属组"));
            lookup->addWidget(m_account, 1); lookup->addWidget(query); layout->addLayout(lookup);
            ks::ui::NormalizeToolbarRow(lookup);
            m_memberships = makeTable(this, {privilegeText("privilege.workbench.groups.group", QStringLiteral("用户组")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.membership", QStringLiteral("成员来源"))});
            layout->addWidget(m_memberships, 1);
            ks::ui::SetTableActionBarMode(m_memberships, ks::ui::TableActionBarMode::Compact);
            m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
            QObject::connect(refresh, &QPushButton::clicked, this, [this]() { refreshGroups(); });
            QObject::connect(m_groups, &QTableWidget::itemSelectionChanged, this, [this]() { refreshMembers(); });
            QObject::connect(m_search, &QLineEdit::textChanged, this, [this](const QString& value) { filterTable(m_groups, value); filterTable(m_members, value); });
            QObject::connect(add, &QPushButton::clicked, this, [this]() { changeMember(true); });
            QObject::connect(remove, &QPushButton::clicked, this, [this]() { changeMember(false); });
            QObject::connect(query, &QPushButton::clicked, this, [this]() { lookupAccount(); });
            QObject::connect(m_account, &QLineEdit::returnPressed, this, [this]() { lookupAccount(); });
            QObject::connect(m_memberships, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item)
            {
                const QString sid = m_memberships->item(item->row(), 0)->data(Qt::UserRole).toString();
                for (int row = 0; row < m_groups->rowCount(); ++row)
                    if (m_groups->item(row, 0)->data(Qt::UserRole).toString() == sid)
                    {
                        m_search->clear(); m_groups->setCurrentCell(row, 0); m_groups->selectRow(row); break;
                    }
            });
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
            m_members->setRowCount(0);
            runRows(this, []() { return enumerateGroups(); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_groupsGeneration) return;
                fillTable(m_groups, result.rows); filterTable(m_groups, m_search->text()); showResult(m_status, result);
            });
        }
        void refreshMembers()
        {
            const quint64 generation = ++m_membersGeneration;
            m_members->setRowCount(0);
            const int row = m_groups->currentRow();
            if (row < 0 || m_groups->isRowHidden(row)) return;
            const QString group = m_groups->item(row, 0)->text();
            runRows(this, [group]() { return enumerateMembers(group); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_membersGeneration) return;
                fillTable(m_members, result.rows); filterTable(m_members, m_search->text()); showResult(m_status, result);
            });
        }
        void lookupAccount()
        {
            const quint64 generation = ++m_lookupGeneration;
            const QString account = m_account->text().trimmed();
            m_memberships->setRowCount(0);
            runRows(this, [account]() { return accountGroups(account); }, [this, generation](const RowsResult& result)
            {
                if (generation != m_lookupGeneration) return;
                fillTable(m_memberships, membershipRows(result.rows)); showResult(m_status, result);
            });
        }
        void changeMember(bool add)
        {
            const int groupRow = m_groups->currentRow();
            if (groupRow < 0 || m_groups->isRowHidden(groupRow)) return;
            const QString group = m_groups->item(groupRow, 0)->text();
            const QString groupSid = m_groups->item(groupRow, 0)->data(Qt::UserRole).toString();
            if (groupSid.isEmpty()) return;
            QString member = m_member->text().trimmed();
            if (!add)
            {
                const int row = m_members->currentRow();
                if (row < 0 || m_members->isRowHidden(row)) return;
                member = m_members->item(row, 0)->data(Qt::UserRole).toString();
            }
            if (member.isEmpty()) return;
            // Resolve and show a concrete SID before approval; never resolve names on the UI thread.
            ++m_membersGeneration; ++m_groupsGeneration;
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
                setEnabled(true);
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
                    { result.error = privilegeText("privilege.workbench.groups.identity_changed", QStringLiteral("账户身份已变化，请刷新后重试。")); return result; }
                    LOCALGROUP_MEMBERS_INFO_0 value = {}; value.lgrmi0_sid = memberSid.sid();
                    const NET_API_STATUS status = add
                        ? ::NetLocalGroupAddMembers(nullptr, reinterpret_cast<LPCWSTR>(group.utf16()), 0, reinterpret_cast<LPBYTE>(&value), 1)
                        : ::NetLocalGroupDelMembers(nullptr, reinterpret_cast<LPCWSTR>(group.utf16()), 0, reinterpret_cast<LPBYTE>(&value), 1);
                    if (status != NERR_Success) { result.error = winError(status); return result; }
                    result = enumerateMembers(group);
                    if (!result.error.isEmpty())
                        result.error = privilegeText("privilege.workbench.groups.readback_failed", QStringLiteral("变更已提交，但回读失败：%1")).arg(result.error);
                    else
                    {
                        const bool present = std::any_of(result.rows.cbegin(), result.rows.cend(), [&sidString](const Row& row) { return row.sid == sidString; });
                        if (present != add)
                            result.error = privilegeText("privilege.workbench.groups.readback_mismatch", QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
                    }
                    return result;
                }, [this, group](const RowsResult& result)
                {
                    setEnabled(true);
                    const int selected = m_groups->currentRow();
                    if (selected >= 0 && m_groups->item(selected, 0)->text() == group)
                    { fillTable(m_members, result.rows); filterTable(m_members, m_search->text()); }
                    showResult(m_status, result);
                    m_memberships->setRowCount(0); ++m_lookupGeneration;
                });
            });
        }
        QLineEdit *m_search = nullptr, *m_member = nullptr, *m_account = nullptr;
        QTableWidget *m_groups = nullptr, *m_members = nullptr, *m_memberships = nullptr;
        QLabel* m_status = nullptr;
        quint64 m_groupsGeneration = 0, m_membersGeneration = 0, m_lookupGeneration = 0;
        bool m_loaded = false;
    };

    class RightsPage final : public QWidget
    {
    public:
        explicit RightsPage(QWidget* parent) : QWidget(parent)
        {
            auto* layout = new QVBoxLayout(this);
            auto* explanation = new QLabel(privilegeText("privilege.workbench.rights.explanation", QStringLiteral("此页展示本机 LSA 策略中的直接权限分配。组继承、登录类型、拒绝登录策略及 UAC 会影响实际令牌；已有进程令牌不会因修改策略立即更新。请在令牌对比页检查实际进程。")), this);
            explanation->setWordWrap(true); layout->addWidget(explanation);
            auto* accountBar = new QHBoxLayout;
            m_account = new QLineEdit(this);
            m_account->setPlaceholderText(privilegeText("privilege.workbench.rights.account_input", QStringLiteral("账户名或 SID（用户、组、服务身份）")));
            auto* queryAccount = button(this, "privilege.workbench.rights.query_account", QStringLiteral("账户 → 直接权限"));
            accountBar->addWidget(m_account, 1); accountBar->addWidget(queryAccount); layout->addLayout(accountBar);
            ks::ui::NormalizeToolbarRow(accountBar);
            auto* rightBar = new QHBoxLayout;
            // 可编辑权限选择器保留原目录和输入功能，只统一完整控件底面。
            m_right = new QComboBox(this);
            m_right->setEditable(true);
            m_right->addItems(rightsCatalog());
            ks::ui::StylePrimaryCombo(m_right);
            auto* queryRight = button(this, "privilege.workbench.rights.query_right", QStringLiteral("权限 → 已分配账户"));
            auto* add = button(this, "privilege.workbench.rights.add", QStringLiteral("分配此权限"));
            auto* remove = button(this, "privilege.workbench.rights.remove", QStringLiteral("移除此权限"));
            rightBar->addWidget(m_right, 1); rightBar->addWidget(queryRight); rightBar->addWidget(add); rightBar->addWidget(remove); layout->addLayout(rightBar);
            ks::ui::NormalizeToolbarRow(rightBar);
            m_description = new QLabel(this); m_description->setWordWrap(true); layout->addWidget(m_description);
            m_search = new QLineEdit(this);
            m_search->setPlaceholderText(privilegeText("privilege.workbench.rights.search", QStringLiteral("搜索权限、账户或 SID"))); layout->addWidget(m_search);
            ks::ui::StyleSearchField(m_search);
            auto* splitter = new QSplitter(Qt::Horizontal, this);
            auto* accountPane = new QWidget(splitter); auto* accountLayout = new QVBoxLayout(accountPane); accountLayout->setContentsMargins(0, 0, 0, 0);
            accountLayout->addWidget(new QLabel(privilegeText("privilege.workbench.rights.direct_caption", QStringLiteral("账户的直接策略分配")), accountPane));
            m_rights = makeTable(accountPane, {privilegeText("privilege.workbench.rights.right", QStringLiteral("权限名称")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.groups.description", QStringLiteral("说明"))});
            accountLayout->addWidget(m_rights);
            auto* rightPane = new QWidget(splitter); auto* rightLayout = new QVBoxLayout(rightPane); rightLayout->setContentsMargins(0, 0, 0, 0);
            rightLayout->addWidget(new QLabel(privilegeText("privilege.workbench.rights.assigned_caption", QStringLiteral("此权限的直接分配账户")), rightPane));
            m_accounts = makeTable(rightPane, {privilegeText("privilege.workbench.groups.account", QStringLiteral("账户")), QStringLiteral("SID"),
                privilegeText("privilege.workbench.rights.right", QStringLiteral("权限名称"))});
            rightLayout->addWidget(m_accounts); splitter->addWidget(accountPane); splitter->addWidget(rightPane); layout->addWidget(splitter, 1);
            // 双向权限查询已有业务操作，两个辅助结果仅保留紧凑导出入口。
            ks::ui::SetTableActionBarMode(m_rights, ks::ui::TableActionBarMode::Compact);
            ks::ui::SetTableActionBarMode(m_accounts, ks::ui::TableActionBarMode::Compact);
            m_status = new QLabel(this); m_status->setWordWrap(true); layout->addWidget(m_status);
            QObject::connect(queryAccount, &QPushButton::clicked, this, [this]() { refreshRights(); });
            QObject::connect(queryRight, &QPushButton::clicked, this, [this]() { refreshAccounts(); });
            QObject::connect(m_account, &QLineEdit::returnPressed, this, [this]() { refreshRights(); });
            QObject::connect(m_rights, &QTableWidget::itemSelectionChanged, this, [this]()
            { const int row = m_rights->currentRow(); if (row >= 0) m_right->setCurrentText(m_rights->item(row, 0)->text()); });
            QObject::connect(m_accounts, &QTableWidget::itemDoubleClicked, this, [this](QTableWidgetItem* item)
            { m_account->setText(m_accounts->item(item->row(), 0)->data(Qt::UserRole).toString()); refreshRights(); });
            QObject::connect(m_search, &QLineEdit::textChanged, this, [this](const QString& value) { filterTable(m_rights, value); filterTable(m_accounts, value); });
            QObject::connect(add, &QPushButton::clicked, this, [this]() { changeRight(true); });
            QObject::connect(remove, &QPushButton::clicked, this, [this]() { changeRight(false); });
            QObject::connect(m_right, &QComboBox::currentTextChanged, this, [this]()
            { m_description->setText(m_right->currentData(Qt::ToolTipRole).toString()); });
            runRows(this, []()
            {
                RowsResult result;
                for (const QString& right : rightsCatalog()) result.rows.push_back({right, {}, rightDescription(right), {}, false});
                return result;
            }, [this](const RowsResult& result)
            {
                for (const Row& row : result.rows)
                { const int index = m_right->findText(row.name); if (index >= 0) m_right->setItemData(index, row.detail, Qt::ToolTipRole); }
                m_description->setText(m_right->currentData(Qt::ToolTipRole).toString());
            });
        }
        void selectAccount(const QString& account) { m_account->setText(account); refreshRights(); }
    private:
        void refreshRights()
        {
            const QString account = m_account->text().trimmed(); const quint64 generation = ++m_rightsGeneration;
            m_rights->setRowCount(0);
            runRows(this, [account]() { return queryRights(account); }, [this, generation](const RowsResult& result)
            { if (generation != m_rightsGeneration) return; fillTable(m_rights, result.rows); filterTable(m_rights, m_search->text()); showResult(m_status, result); });
        }
        void refreshAccounts()
        {
            const QString right = m_right->currentText().trimmed(); const quint64 generation = ++m_accountsGeneration;
            m_accounts->setRowCount(0);
            if (right.isEmpty()) return;
            runRows(this, [right]() { return assignedAccounts(right); }, [this, generation](const RowsResult& result)
            { if (generation != m_accountsGeneration) return; fillTable(m_accounts, result.rows); filterTable(m_accounts, m_search->text()); showResult(m_status, result); });
        }
        void changeRight(bool add)
        {
            const QString account = m_account->text().trimmed(), right = m_right->currentText().trimmed();
            if (!rightsCatalog().contains(right))
            {
                m_status->setText(privilegeText("privilege.workbench.rights.invalid_right", QStringLiteral("请选择目录中的有效权限名称。"))); return;
            }
            ++m_rightsGeneration; ++m_accountsGeneration;
            setEnabled(false);
            runRows(this, [account, right]()
            {
                const SidResult sid = resolveSid(account); RowsResult result; result.error = sid.error;
                if (!result.error.isEmpty()) return result;
                result = queryRights(sidText(sid.sid()));
                if (!result.error.isEmpty()) return result;
                const bool assigned = std::any_of(result.rows.cbegin(), result.rows.cend(), [&right](const Row& row) { return row.name == right; });
                result.rows = {{accountName(sid.sid()), sidText(sid.sid()), {}, assigned ? QStringLiteral("assigned") : QStringLiteral("unassigned")}};
                return result;
            }, [this, right, add](const RowsResult& resolved)
            {
                setEnabled(true);
                if (!resolved.error.isEmpty() || resolved.rows.isEmpty()) { showResult(m_status, resolved); return; }
                const Row accountRow = resolved.rows.first();
                const bool before = accountRow.extra == QStringLiteral("assigned");
                if (before == add)
                { m_status->setText(privilegeText("privilege.workbench.rights.no_change", QStringLiteral("该直接权限已处于请求状态，无需修改。"))); return; }
                const QString action = add ? privilegeText("privilege.workbench.rights.action_add", QStringLiteral("分配"))
                    : privilegeText("privilege.workbench.rights.action_remove", QStringLiteral("移除"));
                const QPointer<QWidget> pageGuard(this);
                if (QMessageBox::question(this, privilegeText("privilege.workbench.groups.preview", QStringLiteral("变更预览")),
                    privilegeText("privilege.workbench.rights.preview", QStringLiteral("操作：%1\n账户：%2\nSID：%3\n直接策略权限：%4\n\n应用后将回读策略；需要新登录才能反映在新令牌中。"))
                        .arg(action, accountRow.name, accountRow.sid, right), QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
                if (!pageGuard) return;
                const QString sidString = accountRow.sid;
                setEnabled(false);
                runRows(this, [sidString, right, add]()
                {
                    RowsResult result;
                    const SidResult sid = resolveSid(sidString);
                    if (!sid.error.isEmpty()) { result.error = sid.error; return result; }
                    Policy policy(POLICY_LOOKUP_NAMES | (add ? POLICY_CREATE_ACCOUNT : 0));
                    if (!policy.error.isEmpty()) { result.error = policy.error; return result; }
                    LSA_UNICODE_STRING value = lsaString(right);
                    const NTSTATUS status = add ? ::LsaAddAccountRights(policy.handle, sid.sid(), &value, 1)
                        : ::LsaRemoveAccountRights(policy.handle, sid.sid(), FALSE, &value, 1);
                    if (status != 0) { result.error = winError(::LsaNtStatusToWinError(status)); return result; }
                    result = directRights(policy.handle, sid.sid());
                    if (!result.error.isEmpty()) result.error = privilegeText("privilege.workbench.groups.readback_failed", QStringLiteral("变更已提交，但回读失败：%1")).arg(result.error);
                    else
                    {
                        const bool assigned = std::any_of(result.rows.cbegin(), result.rows.cend(), [&right](const Row& row) { return row.name == right; });
                        if (assigned != add) result.error = privilegeText("privilege.workbench.groups.readback_mismatch", QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
                    }
                    return result;
                }, [this, sidString, right](const RowsResult& result)
                {
                    setEnabled(true); m_account->setText(sidString); m_right->setCurrentText(right);
                    fillTable(m_rights, result.rows); filterTable(m_rights, m_search->text());
                    m_accounts->setRowCount(0); showResult(m_status, result);
                    if (result.error.isEmpty()) refreshAccounts();
                });
            });
        }
        QLineEdit *m_account = nullptr, *m_search = nullptr;
        QComboBox* m_right = nullptr;
        QTableWidget *m_rights = nullptr, *m_accounts = nullptr;
        QLabel* m_status = nullptr;
        QLabel* m_description = nullptr;
        quint64 m_rightsGeneration = 0, m_accountsGeneration = 0;
    };
}

QWidget* createAccountManagementPage(QWidget* parent,
    std::function<void(const QString&, const QString&)> navigate)
{ return new AccountPage(parent, std::move(navigate)); }
QWidget* createGroupsPage(QWidget* parent) { return new GroupsPage(parent); }
QWidget* createRightsPage(QWidget* parent) { return new RightsPage(parent); }
void selectGroupAccount(QWidget* page, const QString& account)
{ if (auto* groups = dynamic_cast<GroupsPage*>(page)) groups->selectAccount(account); }
void selectRightsAccount(QWidget* page, const QString& account)
{ if (auto* rights = dynamic_cast<RightsPage*>(page)) rights->selectAccount(account); }

bool setLocalAccountEnabled(const QString& account, bool enabled, QString* error)
{
    if (error) error->clear();
    const QString name = localName(account);
    if (name.isEmpty())
    {
        if (error) *error = privilegeText("privilege.workbench.groups.local_only", QStringLiteral("只能修改本机本地账户。"));
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
        if (error) *error = privilegeText("privilege.workbench.groups.readback_failed", QStringLiteral("变更已提交，但回读失败：%1")).arg(winError(status));
        return false;
    }
    const bool readbackEnabled = (current->usri1_flags & UF_ACCOUNTDISABLE) == 0;
    ::NetApiBufferFree(current);
    if (readbackEnabled != enabled)
    {
        if (error) *error = privilegeText("privilege.workbench.groups.readback_mismatch", QStringLiteral("变更已提交，但回读状态与请求不一致，请刷新检查。"));
        return false;
    }
    return true;
}

QJsonObject captureAccountPolicySnapshot()
{
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
