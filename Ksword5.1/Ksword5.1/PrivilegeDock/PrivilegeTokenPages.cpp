#include "PrivilegeTokenPages.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ThemeStatusRole.h"
#include "../ksword/process/process_run_as.h"

#include <TlHelp32.h>
#include <NTSecAPI.h>
#include <sddl.h>
#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QPromise>
#include <QRunnable>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QMessageBox>
#include <QPushButton>
#include <QPointer>
#include <QSet>
#include <QShowEvent>
#include <QSplitter>
#include <QStandardItemModel>
#include <QTableWidgetItem>
#include <QTimer>
#include <QThreadPool>
#include <QVBoxLayout>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Secur32.lib")

namespace
{
    QString text(const char* key, const QString& source)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), source);
    }

    struct Handle final
    {
        HANDLE value = nullptr;
        ~Handle() { if (value && value != INVALID_HANDLE_VALUE) ::CloseHandle(value); }
        Handle() = default;
        Handle(const Handle&) = delete;
        Handle& operator=(const Handle&) = delete;
    };

    quint64 creationTime(HANDLE process)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!::GetProcessTimes(process, &created, &exited, &kernel, &user)) return 0;
        return (static_cast<quint64>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }

    struct ProcessLife
    {
        DWORD wait = WAIT_FAILED;
        DWORD error = ERROR_SUCCESS;
        bool known() const { return wait == WAIT_TIMEOUT || wait == WAIT_OBJECT_0; }
        bool alive() const { return wait == WAIT_TIMEOUT; }
    };

    ProcessLife processLife(HANDLE process)
    {
        ProcessLife result;
        result.wait = ::WaitForSingleObject(process, 0);
        result.error = result.wait == WAIT_FAILED ? ::GetLastError()
            : result.known() ? ERROR_SUCCESS : ERROR_INVALID_DATA;
        return result;
    }

    QString imagePath(HANDLE process)
    {
        std::vector<wchar_t> buffer(32768);
        DWORD length = static_cast<DWORD>(buffer.size());
        return ::QueryFullProcessImageNameW(process, 0, buffer.data(), &length)
            ? QString::fromWCharArray(buffer.data(), static_cast<int>(length)) : QString();
    }

    QString winError(DWORD code)
    {
        wchar_t* buffer = nullptr;
        ::FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, code, 0,
            reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
        const QString message = buffer ? QString::fromWCharArray(buffer).trimmed() : QString();
        if (buffer) ::LocalFree(buffer);
        return QStringLiteral("Win32 %1: %2").arg(code).arg(message);
    }

    QString luidText(const LUID& luid)
    {
        return QStringLiteral("%1:%2").arg(static_cast<quint32>(luid.HighPart), 8, 16, QChar('0'))
            .arg(luid.LowPart, 8, 16, QChar('0'));
    }

    QString sidText(PSID sid)
    {
        if (!sid || !::IsValidSid(sid)) return {};
        wchar_t* result = nullptr;
        if (!::ConvertSidToStringSidW(sid, &result)) return {};
        const QString value = QString::fromWCharArray(result);
        ::LocalFree(result);
        return value;
    }

    QString sidAccount(PSID sid)
    {
        if (!sid || !::IsValidSid(sid)) return {};
        DWORD nameLength = 0, domainLength = 0;
        SID_NAME_USE use{};
        ::LookupAccountSidW(nullptr, sid, nullptr, &nameLength, nullptr, &domainLength, &use);
        if (!nameLength || nameLength > 32768 || domainLength > 32768) return {};
        std::vector<wchar_t> name(nameLength), domain(std::max<DWORD>(1, domainLength));
        if (!::LookupAccountSidW(nullptr, sid, name.data(), &nameLength, domain.data(), &domainLength, &use)) return {};
        const QString domainText = QString::fromWCharArray(domain.data());
        return (domainText.isEmpty() ? QString() : domainText + QChar('\\'))
            + QString::fromWCharArray(name.data());
    }

    QString hex(DWORD value) { return QStringLiteral("0x%1").arg(value, 8, 16, QChar('0')); }

    struct TokenCollector final
    {
        QJsonArray entries;
        QJsonArray errors;
        QJsonObject categories;
        HANDLE token = nullptr;

        void add(const QString& key, const QString& value, const QString& state = QStringLiteral("read"),
            const QString& sid = {})
        {
            QJsonObject entry{ { QStringLiteral("key"), key }, { QStringLiteral("value"), value },
                { QStringLiteral("state"), state } };
            if (!sid.isEmpty()) entry.insert(QStringLiteral("sid"), sid);
            entries.append(entry);
        }

        void failure(const QString& key, DWORD error)
        {
            const QString detail = winError(error);
            add(key, detail, QStringLiteral("unreadable"));
            errors.append(key + QStringLiteral(": ") + detail);
            categories.insert(key, QStringLiteral("unreadable"));
        }

        bool query(TOKEN_INFORMATION_CLASS information, const QString& key, std::vector<BYTE>& buffer)
        {
            DWORD length = 0;
            ::GetTokenInformation(token, information, nullptr, 0, &length);
            DWORD error = ::GetLastError();
            if (!length || length > 16 * 1024 * 1024)
            {
                failure(key, length ? ERROR_INVALID_DATA : error);
                return false;
            }
            for (int attempt = 0; attempt < 3; ++attempt)
            {
                buffer.resize(length);
                DWORD actual = 0;
                if (::GetTokenInformation(token, information, buffer.data(), length, &actual))
                {
                    if (!actual || actual > length) { failure(key, ERROR_INVALID_DATA); return false; }
                    buffer.resize(actual);
                    categories.insert(key, QStringLiteral("read"));
                    return true;
                }
                error = ::GetLastError();
                if (error != ERROR_INSUFFICIENT_BUFFER || actual <= length || actual > 16 * 1024 * 1024) break;
                length = actual;
            }
            failure(key, error);
            return false;
        }

        template<typename T> bool fixed(TOKEN_INFORMATION_CLASS information, const QString& key, T& value)
        {
            DWORD actual = 0;
            if (::GetTokenInformation(token, information, &value, sizeof(value), &actual) && actual == sizeof(value))
            {
                categories.insert(key, QStringLiteral("read"));
                return true;
            }
            failure(key, actual > sizeof(value) ? ERROR_INVALID_DATA : ::GetLastError());
            return false;
        }

        void sid(TOKEN_INFORMATION_CLASS information, const QString& key)
        {
            std::vector<BYTE> buffer;
            if (!query(information, key, buffer)) return;
            if (buffer.size() < sizeof(PSID)) { failure(key, ERROR_INVALID_DATA); return; }
            PSID value = *reinterpret_cast<PSID*>(buffer.data());
            if (!value) { add(key, {}, QStringLiteral("absent")); return; }
            const QString raw = sidText(value);
            if (raw.isEmpty()) { failure(key, ERROR_INVALID_SID); return; }
            add(key, raw, QStringLiteral("read"), raw);
            add(key + QStringLiteral("/account"), sidAccount(value));
        }

        void groups(TOKEN_INFORMATION_CLASS information, const QString& key)
        {
            std::vector<BYTE> buffer;
            if (!query(information, key, buffer)) return;
            if (buffer.size() < offsetof(TOKEN_GROUPS, Groups)) { failure(key, ERROR_INVALID_DATA); return; }
            const auto* groups = reinterpret_cast<const TOKEN_GROUPS*>(buffer.data());
            const size_t maximum = (buffer.size() - offsetof(TOKEN_GROUPS, Groups)) / sizeof(SID_AND_ATTRIBUTES);
            if (groups->GroupCount > maximum) { failure(key, ERROR_INVALID_DATA); return; }
            add(key + QStringLiteral("/count"), QString::number(groups->GroupCount));
            for (DWORD index = 0; index < groups->GroupCount; ++index)
            {
                const auto& group = groups->Groups[index];
                const QString raw = sidText(group.Sid);
                if (raw.isEmpty()) { failure(key + QChar('/') + QString::number(index), ERROR_INVALID_SID); continue; }
                const QString groupKey = key + QChar('/') + raw;
                // Attribute bits are compared independently; display names never establish identity.
                add(groupKey + QStringLiteral("/attributes"), hex(group.Attributes), QStringLiteral("read"), raw);
                add(groupKey + QStringLiteral("/enabled"), QString::number((group.Attributes & SE_GROUP_ENABLED) != 0), QStringLiteral("read"), raw);
                add(groupKey + QStringLiteral("/deny_only"), QString::number((group.Attributes & SE_GROUP_USE_FOR_DENY_ONLY) != 0), QStringLiteral("read"), raw);
                add(groupKey + QStringLiteral("/account"), sidAccount(group.Sid), QStringLiteral("read"), raw);
            }
        }

        void privileges(const QString& key)
        {
            std::vector<BYTE> buffer;
            if (!query(TokenPrivileges, key, buffer)) return;
            if (buffer.size() < offsetof(TOKEN_PRIVILEGES, Privileges)) { failure(key, ERROR_INVALID_DATA); return; }
            const auto* privileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
            const size_t maximum = (buffer.size() - offsetof(TOKEN_PRIVILEGES, Privileges)) / sizeof(LUID_AND_ATTRIBUTES);
            if (privileges->PrivilegeCount > maximum) { failure(key, ERROR_INVALID_DATA); return; }
            add(key + QStringLiteral("/count"), QString::number(privileges->PrivilegeCount));
            for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
            {
                const auto& privilege = privileges->Privileges[index];
                wchar_t name[256]{};
                DWORD nameLength = 256;
                const QString identity = ::LookupPrivilegeNameW(nullptr, const_cast<LUID*>(&privilege.Luid), name, &nameLength)
                    ? QString::fromWCharArray(name, static_cast<int>(nameLength)) : luidText(privilege.Luid);
                const QString prefix = key + QChar('/') + identity;
                add(prefix + QStringLiteral("/attributes"), hex(privilege.Attributes));
                add(prefix + QStringLiteral("/enabled"), QString::number((privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0));
                add(prefix + QStringLiteral("/default_enabled"), QString::number((privilege.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0));
                add(prefix + QStringLiteral("/removed"), QString::number((privilege.Attributes & SE_PRIVILEGE_REMOVED) != 0));
            }
        }

        void scalar(TOKEN_INFORMATION_CLASS information, const QString& key)
        {
            DWORD value = 0;
            if (fixed(information, key, value)) add(key, QString::number(value));
        }

        void collect(const QString& prefix = {})
        {
            sid(TokenUser, prefix + QStringLiteral("user"));
            sid(TokenOwner, prefix + QStringLiteral("owner"));
            sid(TokenPrimaryGroup, prefix + QStringLiteral("primary_group"));
            groups(TokenGroups, prefix + QStringLiteral("groups"));
            groups(TokenRestrictedSids, prefix + QStringLiteral("restricted_sids"));
            groups(TokenCapabilities, prefix + QStringLiteral("capabilities"));
            groups(TokenLogonSid, prefix + QStringLiteral("logon_sids"));
            privileges(prefix + QStringLiteral("privileges"));
            scalar(TokenElevation, prefix + QStringLiteral("elevated"));
            scalar(TokenElevationType, prefix + QStringLiteral("elevation_type"));
            scalar(TokenUIAccess, prefix + QStringLiteral("ui_access"));
            scalar(TokenIsAppContainer, prefix + QStringLiteral("app_container"));
            scalar(TokenHasRestrictions, prefix + QStringLiteral("has_restrictions"));
            scalar(TokenVirtualizationAllowed, prefix + QStringLiteral("virtualization_allowed"));
            scalar(TokenVirtualizationEnabled, prefix + QStringLiteral("virtualization_enabled"));
            scalar(TokenSessionId, prefix + QStringLiteral("wts_session_id"));
            scalar(TokenType, prefix + QStringLiteral("token_type"));
            sid(TokenAppContainerSid, prefix + QStringLiteral("app_container_sid"));
            std::vector<BYTE> label;
            const QString integrityKey = prefix + QStringLiteral("integrity");
            if (query(TokenIntegrityLevel, integrityKey, label))
            {
                if (label.size() < sizeof(TOKEN_MANDATORY_LABEL)) failure(integrityKey, ERROR_INVALID_DATA);
                else
                {
                    const auto* integrity = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(label.data());
                    const QString raw = sidText(integrity->Label.Sid);
                    if (raw.isEmpty()) failure(integrityKey, ERROR_INVALID_SID);
                    else
                    {
                        add(integrityKey + QStringLiteral("/sid"), raw, QStringLiteral("read"), raw);
                        add(integrityKey + QStringLiteral("/attributes"), hex(integrity->Label.Attributes));
                        const BYTE count = *::GetSidSubAuthorityCount(integrity->Label.Sid);
                        if (count) add(integrityKey + QStringLiteral("/rid"), QString::number(*::GetSidSubAuthority(integrity->Label.Sid, count - 1)));
                    }
                }
            }
            TOKEN_STATISTICS statistics{};
            if (fixed(TokenStatistics, prefix + QStringLiteral("statistics"), statistics))
            {
                add(prefix + QStringLiteral("authentication_id"), luidText(statistics.AuthenticationId));
                add(prefix + QStringLiteral("token_id"), luidText(statistics.TokenId));
                add(prefix + QStringLiteral("modified_id"), luidText(statistics.ModifiedId));
            }
            TOKEN_MANDATORY_POLICY policy{};
            if (fixed(TokenMandatoryPolicy, prefix + QStringLiteral("mandatory_policy"), policy))
                add(prefix + QStringLiteral("mandatory_policy"), hex(policy.Policy));
        }
    };

    QJsonObject tokenOnProcess(HANDLE process, DWORD pid)
    {
        const quint64 created = creationTime(process);
        const auto initialLife = processLife(process);
        QJsonObject metadata{ { QStringLiteral("pid"), static_cast<double>(pid) },
            { QStringLiteral("creationTime100ns"), QString::number(created) },
            { QStringLiteral("imagePath"), imagePath(process) },
            { QStringLiteral("capturedAtUtc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs) } };
        if (initialLife.known()) metadata.insert(QStringLiteral("aliveAfterCapture"), initialLife.alive());
        else return { { QStringLiteral("entries"), QJsonArray{} },
            { QStringLiteral("errors"), QJsonArray{winError(initialLife.error)} },
            { QStringLiteral("metadata"), metadata }, { QStringLiteral("readable"), false } };
        Handle token;
        if (!created || !::OpenProcessToken(process, TOKEN_QUERY, &token.value))
        {
            const QString error = winError(::GetLastError());
            return { { QStringLiteral("entries"), QJsonArray{} }, { QStringLiteral("errors"), QJsonArray{error} },
                { QStringLiteral("metadata"), metadata }, { QStringLiteral("readable"), false } };
        }
        TokenCollector collector;
        collector.token = token.value;
        collector.collect();
        TOKEN_ELEVATION_TYPE elevation{};
        DWORD length = 0;
        if (::GetTokenInformation(token.value, TokenElevationType, &elevation, sizeof(elevation), &length)
            && elevation == TokenElevationTypeDefault)
        {
            collector.add(QStringLiteral("linked"), {}, QStringLiteral("absent"));
            collector.categories.insert(QStringLiteral("linked"), QStringLiteral("absent"));
        }
        else
        {
            TOKEN_LINKED_TOKEN linked{};
            if (collector.fixed(TokenLinkedToken, QStringLiteral("linked"), linked))
            {
                Handle linkedHandle;
                linkedHandle.value = linked.LinkedToken;
                collector.add(QStringLiteral("linked"), QStringLiteral("1"));
                collector.token = linkedHandle.value;
                collector.collect(QStringLiteral("linked/"));
            }
        }
        const auto finalLife = processLife(process);
        if (!finalLife.known())
        {
            collector.errors.append(winError(finalLife.error));
            metadata.remove(QStringLiteral("aliveAfterCapture"));
        }
        else
        {
            if (!finalLife.alive()) collector.errors.append(QStringLiteral("Process exited during token capture"));
            metadata.insert(QStringLiteral("aliveAfterCapture"), finalLife.alive());
        }
        return { { QStringLiteral("entries"), collector.entries }, { QStringLiteral("errors"), collector.errors },
            { QStringLiteral("categories"), collector.categories }, { QStringLiteral("metadata"), metadata },
            { QStringLiteral("readable"), true } };
    }

    QJsonObject processList(bool authentication)
    {
        QJsonArray processes, errors;
        Handle snapshot;
        snapshot.value = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        PROCESSENTRY32W item{};
        item.dwSize = sizeof(item);
        if (snapshot.value == INVALID_HANDLE_VALUE || !::Process32FirstW(snapshot.value, &item))
            return { { QStringLiteral("processes"), processes }, { QStringLiteral("errors"), QJsonArray{winError(::GetLastError())} } };
        do
        {
            QJsonObject record{ { QStringLiteral("pid"), static_cast<double>(item.th32ProcessID) },
                { QStringLiteral("name"), QString::fromWCharArray(item.szExeFile) } };
            Handle process;
            process.value = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, item.th32ProcessID);
            if (process.value)
            {
                record.insert(QStringLiteral("creationTime100ns"), QString::number(creationTime(process.value)));
                record.insert(QStringLiteral("imagePath"), imagePath(process.value));
                if (authentication)
                {
                    Handle token;
                    TOKEN_STATISTICS statistics{};
                    DWORD length = 0;
                    if (::OpenProcessToken(process.value, TOKEN_QUERY, &token.value)
                        && ::GetTokenInformation(token.value, TokenStatistics, &statistics, sizeof(statistics), &length))
                        record.insert(QStringLiteral("authentication_id"), luidText(statistics.AuthenticationId));
                    else record.insert(QStringLiteral("error"), winError(::GetLastError()));
                }
                const auto life = processLife(process.value);
                if (!life.known() || !life.alive())
                {
                    record.remove(QStringLiteral("authentication_id"));
                    record.insert(QStringLiteral("error"), life.known()
                        ? QStringLiteral("Process exited during token capture") : winError(life.error));
                }
            }
            else record.insert(QStringLiteral("error"), winError(::GetLastError()));
            processes.append(record);
        } while (::Process32NextW(snapshot.value, &item));
        const DWORD finalError = ::GetLastError();
        if (finalError != ERROR_NO_MORE_FILES) errors.append(winError(finalError));
        return { { QStringLiteral("processes"), processes }, { QStringLiteral("errors"), errors } };
    }

    QString lsaString(const LSA_UNICODE_STRING& value)
    {
        return value.Buffer && value.Length && value.Length % sizeof(wchar_t) == 0
            ? QString::fromWCharArray(value.Buffer, value.Length / sizeof(wchar_t)) : QString();
    }

    QJsonObject sessionsSnapshot()
    {
        QJsonArray sessions, errors;
        ULONG count = 0;
        PLUID identifiers = nullptr;
        const NTSTATUS status = ::LsaEnumerateLogonSessions(&count, &identifiers);
        if (status != 0)
            errors.append(winError(::LsaNtStatusToWinError(status)));
        else
        {
            struct LsaBuffer { void* value; ~LsaBuffer() { if (value) ::LsaFreeReturnBuffer(value); } } guard{identifiers};
            for (ULONG index = 0; index < count; ++index)
            {
                QJsonObject row{ { QStringLiteral("luid"), luidText(identifiers[index]) } };
                PSECURITY_LOGON_SESSION_DATA data = nullptr;
                const NTSTATUS itemStatus = ::LsaGetLogonSessionData(&identifiers[index], &data);
                LsaBuffer itemGuard{data};
                if (itemStatus != 0 || !data || data->Size < offsetof(SECURITY_LOGON_SESSION_DATA, LogonTime) + sizeof(LARGE_INTEGER))
                    row.insert(QStringLiteral("error"), winError(itemStatus ? ::LsaNtStatusToWinError(itemStatus) : ERROR_INVALID_DATA));
                else
                {
                    const QString domain = lsaString(data->LogonDomain);
                    row.insert(QStringLiteral("account"), (domain.isEmpty() ? QString() : domain + QChar('\\')) + lsaString(data->UserName));
                    row.insert(QStringLiteral("sid"), sidText(data->Sid));
                    row.insert(QStringLiteral("type"), static_cast<double>(data->LogonType));
                    row.insert(QStringLiteral("wts_session_id"), static_cast<double>(data->Session));
                    row.insert(QStringLiteral("package"), lsaString(data->AuthenticationPackage));
                    row.insert(QStringLiteral("logonTime100ns"), QString::number(data->LogonTime.QuadPart));
                }
                sessions.append(row);
            }
        }
        QJsonObject processes = processList(true);
        for (const QJsonValue& error : processes.value(QStringLiteral("errors")).toArray()) errors.append(error);
        return { { QStringLiteral("sessions"), sessions },
            { QStringLiteral("processes"), processes.value(QStringLiteral("processes")) },
            { QStringLiteral("errors"), errors } };
    }

    template<typename Work, typename Done> void async(QWidget* owner, Work work, Done done)
    {
        using Result = decltype(work());
        auto* watcher = new QFutureWatcher<Result>(owner);
        QObject::connect(watcher, &QFutureWatcher<Result>::finished, owner, [watcher, done]()
        {
            const Result result = watcher->result();
            watcher->deleteLater();
            done(result);
        });
        // A destroyed page disconnects delivery; worker captures contain values and never a UI pointer.
        auto promise = std::make_shared<QPromise<Result>>();
        promise->start();
        watcher->setFuture(promise->future());
        QThreadPool::globalInstance()->start(QRunnable::create([promise, work = std::move(work)]()
        {
            promise->addResult(work());
            promise->finish();
        }));
    }

    using Rows = QList<QStringList>;

    ks::ui::VisibleTableWidget* table(QWidget* owner, const QStringList& headers)
    {
        auto* result = new ks::ui::VisibleTableWidget(owner);
        result->setColumnCount(static_cast<int>(headers.size()));
        result->setHorizontalHeaderLabels(headers);
        result->setEditTriggers(QAbstractItemView::NoEditTriggers);
        result->setSelectionBehavior(QAbstractItemView::SelectRows);
        result->setSelectionMode(QAbstractItemView::SingleSelection);
        result->setWordWrap(false);
        result->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        result->horizontalHeader()->setStretchLastSection(true);
        result->verticalHeader()->hide();
        ks::ui::SetTableActionBarMode(result, ks::ui::TableActionBarMode::Compact);
        return result;
    }

    void fill(QTableWidget* target, const Rows& rows, const QList<QVariant>& identities = {}, std::function<void()> done = {})
    {
        const quint64 generation = target->property("privilege_fill_generation").toULongLong() + 1;
        target->setProperty("privilege_fill_generation", generation);
        target->setEnabled(false);
        target->setRowCount(0);
        target->setRowCount(static_cast<int>(rows.size()));
        auto position = std::make_shared<int>(0);
        auto step = std::make_shared<std::function<void()>>();
        const std::weak_ptr<std::function<void()>> weakStep = step;
        *step = [target, rows, identities, position, generation, weakStep, done]()
        {
            if (target->property("privilege_fill_generation").toULongLong() != generation) return;
            const int end = std::min(*position + 32, static_cast<int>(rows.size()));
            for (; *position < end; ++*position)
            {
                const int row = *position;
                for (int column = 0; column < target->columnCount(); ++column)
                {
                    auto* item = new QTableWidgetItem(rows[row].value(column));
                    if (row < identities.size()) item->setData(Qt::UserRole, identities[row]);
                    target->setItem(row, column, item);
                }
            }
            if (*position == rows.size()) { target->setEnabled(true); if (done) done(); return; }
            if (auto continuation = weakStep.lock())
                QTimer::singleShot(0, target, [continuation]() { (*continuation)(); });
        };
        QTimer::singleShot(0, target, [step]() { (*step)(); });
    }

    QString errorText(const QJsonObject& snapshot)
    {
        QStringList errors;
        for (const QJsonValue& value : snapshot.value(QStringLiteral("errors")).toArray()) errors.append(ks::i18n::sourceText(value.toString()));
        return errors.join(QChar('\n'));
    }

    bool sameIdentity(const QJsonObject& snapshot, DWORD pid, quint64 expected)
    {
        const auto metadata = snapshot.value(QStringLiteral("metadata")).toObject();
        return metadata.value(QStringLiteral("pid")).toDouble() == pid
            && expected != 0 && metadata.value(QStringLiteral("creationTime100ns")).toString().toULongLong() == expected;
    }

    QString unavailableText()
    {
        return text("privilege.workbench.tokens.unreadable", QStringLiteral("不可读（不能推断为不存在）"));
    }

    QString absentText()
    {
        return text("privilege.workbench.tokens.absent", QStringLiteral("不存在"));
    }

    QString identityChangedText()
    {
        return text("privilege.workbench.tokens.identity_changed", QStringLiteral("进程已退出或 PID 已复用，请重新选择进程。"));
    }

    QString missingValue(const QJsonObject& snapshot, const QString& key)
    {
        if (!snapshot.value(QStringLiteral("readable")).toBool()) return unavailableText();
        const auto categories = snapshot.value(QStringLiteral("categories")).toObject();
        QString category = key;
        while (!category.isEmpty())
        {
            const QString state = categories.value(category).toString();
            if (state == QStringLiteral("unreadable")) return unavailableText();
            if (state == QStringLiteral("absent") || state == QStringLiteral("read")) return absentText();
            const int slash = category.lastIndexOf(QChar('/'));
            if (slash < 0) break;
            category = category.left(slash);
        }
        return unavailableText();
    }

    QString displayValue(const QJsonObject& entry)
    {
        const QString state = entry.value(QStringLiteral("state")).toString();
        if (state == QStringLiteral("unreadable")) return unavailableText() + QStringLiteral(": ") + entry.value(QStringLiteral("value")).toString();
        if (state == QStringLiteral("absent")) return absentText();
        return entry.value(QStringLiteral("value")).toString();
    }

    Rows comparisonRows(const QJsonObject& left, const QJsonObject& right, bool differences, const QString& query,
        QList<QVariant>& sids)
    {
        QMap<QString, QJsonObject> a, b;
        for (const auto& value : left.value(QStringLiteral("entries")).toArray())
            a.insert(value.toObject().value(QStringLiteral("key")).toString(), value.toObject());
        for (const auto& value : right.value(QStringLiteral("entries")).toArray())
            b.insert(value.toObject().value(QStringLiteral("key")).toString(), value.toObject());
        QSet<QString> keySet;
        for (auto it = a.cbegin(); it != a.cend(); ++it) keySet.insert(it.key());
        for (auto it = b.cbegin(); it != b.cend(); ++it) keySet.insert(it.key());
        QStringList keys = keySet.values();
        std::sort(keys.begin(), keys.end());
        Rows rows;
        for (const auto& key : keys)
        {
            const QString av = a.contains(key) ? displayValue(a.value(key)) : missingValue(left, key);
            const QString bv = b.contains(key) ? displayValue(b.value(key)) : missingValue(right, key);
            const bool known = a.value(key).value(QStringLiteral("state")).toString() != QStringLiteral("unreadable")
                && b.value(key).value(QStringLiteral("state")).toString() != QStringLiteral("unreadable")
                && !av.startsWith(unavailableText()) && !bv.startsWith(unavailableText());
            const bool equal = known && av == bv;
            if (differences && equal) continue;
            const QString sid = a.value(key).value(QStringLiteral("sid")).toString().isEmpty()
                ? b.value(key).value(QStringLiteral("sid")).toString() : a.value(key).value(QStringLiteral("sid")).toString();
            const QString state = !known ? text("privilege.workbench.tokens.unknown", QStringLiteral("无法确定"))
                : equal ? text("privilege.workbench.tokens.equal", QStringLiteral("相同"))
                : text("privilege.workbench.tokens.different", QStringLiteral("不同"));
            const QStringList row{key, av, bv, state};
            if (!query.isEmpty() && !row.join(QChar(' ')).contains(query, Qt::CaseInsensitive)) continue;
            rows.append(row);
            sids.append(sid);
        }
        return rows;
    }

    void copySid(QTableWidget* source, int column)
    {
        const int row = source->currentRow();
        if (row < 0 || !source->item(row, column)) return;
        const QString sid = source->item(row, column)->data(Qt::UserRole).toString();
        if (sid.startsWith(QStringLiteral("S-"))) QApplication::clipboard()->setText(sid);
    }

    void openProcessDetail(QWidget* owner, const QJsonObject& record, QLabel* status,
        const std::function<void(DWORD, quint64)>& openProcess)
    {
        const DWORD pid = static_cast<DWORD>(record.value(QStringLiteral("pid")).toDouble());
        const quint64 expected = record.value(QStringLiteral("creationTime100ns")).toString().toULongLong();
        if (!pid || !expected) { status->setText(identityChangedText()); return; }
        async(owner, [pid]()
        {
            Handle process;
            process.value = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
            const DWORD openError = process.value ? ERROR_SUCCESS : ::GetLastError();
            const auto life = process.value ? processLife(process.value) : ProcessLife{};
            const DWORD error = openError ? openError : life.error;
            QJsonObject metadata{
                { QStringLiteral("pid"), static_cast<double>(pid) },
                { QStringLiteral("creationTime100ns"), QString::number(process.value ? creationTime(process.value) : 0) } };
            if (process.value && life.known()) metadata.insert(QStringLiteral("aliveAfterCapture"), life.alive());
            return QJsonObject{ { QStringLiteral("errors"), error ? QJsonArray{winError(error)} : QJsonArray{} },
                { QStringLiteral("metadata"), metadata } };
        },
            [status, pid, expected, openProcess](const QJsonObject& snapshot)
            {
                if (!snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("creationTime100ns")).toString().toULongLong()
                    || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).isBool())
                { status->setText(errorText(snapshot).isEmpty() ? unavailableText() : errorText(snapshot)); return; }
                if (!sameIdentity(snapshot, pid, expected)
                    || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).toBool())
                { status->setText(identityChangedText()); return; }
                if (openProcess) openProcess(pid, expected);
                else status->setText(text("privilege.workbench.sessions.no_navigation", QStringLiteral("进程详情导航尚未连接。")));
            });
    }

    class TokenComparePage final : public QWidget
    {
    public:
        explicit TokenComparePage(QWidget* parent) : QWidget(parent)
        {
            auto* layout = new QVBoxLayout(this);
            auto* selectors = new QHBoxLayout;
            for (int side = 0; side < 2; ++side)
            {
                auto* form = new QVBoxLayout;
                form->addWidget(new QLabel(side == 0 ? text("privilege.workbench.tokens.process_a", QStringLiteral("进程 A"))
                    : text("privilege.workbench.tokens.process_b", QStringLiteral("进程 B")), this));
                m_process[side] = new QComboBox(this);
                m_process[side]->setObjectName(side == 0 ? QStringLiteral("privilege_token_pid_a") : QStringLiteral("privilege_token_pid_b"));
                m_process[side]->setEditable(true);
                m_process[side]->setInsertPolicy(QComboBox::NoInsert);
                m_process[side]->setMinimumContentsLength(12);
                m_process[side]->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
                ks::ui::NormalizeToolbarControl(m_process[side]);
                m_process[side]->lineEdit()->setPlaceholderText(text("privilege.workbench.tokens.pid_hint", QStringLiteral("选择进程或输入 PID")));
                form->addWidget(m_process[side]);
                m_identity[side] = new QLabel(this);
                m_identity[side]->setWordWrap(true);
                form->addWidget(m_identity[side]);
                selectors->addLayout(form, 1);
                connect(m_process[side], &QComboBox::currentIndexChanged, this, [this, side](int)
                {
                    m_anchor[side] = 0;
                    m_snapshots[side] = {};
                });
                connect(m_process[side]->lineEdit(), &QLineEdit::textEdited, this, [this, side](const QString&)
                {
                    m_anchor[side] = 0;
                    m_snapshots[side] = {};
                });
            }
            layout->addLayout(selectors);
            auto* bar = new QHBoxLayout;
            m_refresh = new QPushButton(text("privilege.workbench.tokens.compare", QStringLiteral("刷新并对比")), this);
            m_refresh->setObjectName(QStringLiteral("privilege_token_compare"));
            m_processRefresh = new QPushButton(text("privilege.workbench.tokens.process_refresh", QStringLiteral("更新进程选择")), this);
            m_differences = new QCheckBox(text("privilege.workbench.tokens.differences", QStringLiteral("只显示差异")), this);
            m_differences->setObjectName(QStringLiteral("privilege_token_differences"));
            m_search = new QLineEdit(this);
            m_search->setObjectName(QStringLiteral("privilege_token_search"));
            ks::ui::StyleSearchField(m_search);
            m_search->setPlaceholderText(text("privilege.workbench.tokens.search", QStringLiteral("搜索字段、SID 或权限")));
            auto* copy = new QPushButton(text("privilege.workbench.tokens.copy_sid", QStringLiteral("复制选中 SID")), this);
            copy->setObjectName(QStringLiteral("privilege_token_copy_sid"));
            bar->addWidget(m_refresh); bar->addWidget(m_processRefresh); bar->addWidget(m_differences);
            bar->addWidget(m_search, 1); bar->addWidget(copy);
            ks::ui::NormalizeToolbarRow(bar);
            layout->addLayout(bar);
            auto* legend = new QLabel(text("privilege.workbench.tokens.legend", QStringLiteral("SID 和权限属性按原始值对比；布尔值 1=是、0=否。完整性 RID：4096=低、8192=中、12288=高、16384=SYSTEM。不可读字段保留为未知。")), this);
            legend->setWordWrap(true); layout->addWidget(legend);
            m_table = table(this, { text("privilege.workbench.tokens.field", QStringLiteral("字段")),
                text("privilege.workbench.tokens.value_a", QStringLiteral("A 值")), text("privilege.workbench.tokens.value_b", QStringLiteral("B 值")),
                text("privilege.workbench.tokens.result", QStringLiteral("结果")) });
            m_table->setObjectName(QStringLiteral("privilege_token_comparison_table"));
            // 页面已经有令牌 A/B 比较，通用快照栏不应再重复一套比较动作。
            ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Compact);
            layout->addWidget(m_table, 1);
            m_status = new QLabel(text("privilege.workbench.tokens.idle", QStringLiteral("选择两个进程后刷新；查询不调整目标令牌。")), this);
            m_status->setWordWrap(true); m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(m_status);
            connect(m_refresh, &QPushButton::clicked, this, [this]() { compare(); });
            connect(m_processRefresh, &QPushButton::clicked, this, [this]() { refreshProcesses(); });
            connect(m_differences, &QCheckBox::toggled, this, [this]() { render(); });
            connect(m_search, &QLineEdit::textChanged, this, [this]() { render(); });
            connect(copy, &QPushButton::clicked, this, [this]() { copySid(m_table, 0); });
        }

    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_loaded) { m_loaded = true; QTimer::singleShot(0, this, [this]() { refreshProcesses(); }); }
        }

    private:
        DWORD selectedPid(int side) const
        {
            const QJsonObject selected = m_process[side]->currentData().toJsonObject();
            const QString selectedLabel = m_process[side]->itemText(m_process[side]->currentIndex());
            if (m_process[side]->currentText() == selectedLabel && !selected.isEmpty())
                return static_cast<DWORD>(selected.value(QStringLiteral("pid")).toDouble());
            bool okay = false;
            const quint64 value = m_process[side]->currentText().trimmed().toULongLong(&okay);
            return okay && value > 0 && value <= MAXDWORD ? static_cast<DWORD>(value) : 0;
        }

        void refreshProcesses()
        {
            if (m_busy || m_listBusy) return;
            m_listBusy = true;
            m_processRefresh->setEnabled(false);
            m_refresh->setEnabled(false);
            for (auto* process : m_process) process->setEnabled(false);
            const DWORD left = selectedPid(0), right = selectedPid(1);
            async(this, []() { return processList(false); }, [this, left, right](const QJsonObject& result)
            {
                for (int side = 0; side < 2; ++side)
                {
                    const DWORD wanted = side == 0 ? left : right;
                    bool found = false;
                    m_process[side]->clear();
                    for (const auto& value : result.value(QStringLiteral("processes")).toArray())
                    {
                        const auto record = value.toObject();
                        const DWORD pid = static_cast<DWORD>(record.value(QStringLiteral("pid")).toDouble());
                        m_process[side]->addItem(QStringLiteral("%1 | PID %2").arg(record.value(QStringLiteral("name")).toString()).arg(pid), record);
                        if (pid == wanted || (!wanted && pid == ::GetCurrentProcessId()))
                        { m_process[side]->setCurrentIndex(m_process[side]->count() - 1); found = true; }
                    }
                    if (wanted && !found) m_process[side]->setEditText(QString::number(wanted));
                    m_process[side]->setEnabled(true);
                }
                m_listBusy = false;
                m_processRefresh->setEnabled(true);
                m_refresh->setEnabled(true);
                if (!errorText(result).isEmpty()) m_status->setText(errorText(result));
            });
        }

        void compare()
        {
            if (m_busy || m_listBusy) return;
            const DWORD a = selectedPid(0), b = selectedPid(1);
            if (!a || !b) { m_status->setText(text("privilege.workbench.tokens.invalid_pid", QStringLiteral("请输入有效的非零 PID。"))); return; }
            quint64 expected[2]{};
            for (int side = 0; side < 2; ++side)
            {
                expected[side] = m_anchor[side];
                if (!expected[side])
                {
                    const auto record = m_process[side]->currentData().toJsonObject();
                    if (m_process[side]->currentText() == m_process[side]->itemText(m_process[side]->currentIndex()))
                        expected[side] = record.value(QStringLiteral("creationTime100ns")).toString().toULongLong();
                }
                m_process[side]->setEnabled(false);
            }
            m_busy = true; m_refresh->setEnabled(false); m_processRefresh->setEnabled(false);
            m_status->setText(text("privilege.workbench.tokens.loading", QStringLiteral("正在查询两个进程的令牌...")));
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Info);
            async(this, [a, b]()
            {
                return QJsonObject{ { QStringLiteral("a"), ks::privilege::captureTokenSnapshot(a) },
                    { QStringLiteral("b"), ks::privilege::captureTokenSnapshot(b) } };
            }, [this, a, b, ea = expected[0], eb = expected[1]](const QJsonObject& result)
            {
                const DWORD pids[2]{a, b};
                const quint64 expectedValues[2]{ea, eb};
                QStringList errors;
                for (int side = 0; side < 2; ++side)
                {
                    auto snapshot = result.value(side == 0 ? QStringLiteral("a") : QStringLiteral("b")).toObject();
                    const auto metadata = snapshot.value(QStringLiteral("metadata")).toObject();
                    const quint64 actual = metadata.value(QStringLiteral("creationTime100ns")).toString().toULongLong();
                    if (expectedValues[side] && actual && !sameIdentity(snapshot, pids[side], expectedValues[side]))
                    {
                        snapshot.insert(QStringLiteral("entries"), QJsonArray{});
                        snapshot.insert(QStringLiteral("readable"), false);
                        snapshot.insert(QStringLiteral("errors"), QJsonArray{identityChangedText()});
                    }
                    else if (actual) m_anchor[side] = actual;
                    m_snapshots[side] = snapshot;
                    m_identity[side]->setText(QStringLiteral("PID %1 | %2\n%3").arg(pids[side]).arg(actual)
                        .arg(metadata.value(QStringLiteral("imagePath")).toString()));
                    const QString detail = errorText(snapshot);
                    if (!detail.isEmpty()) errors.append(QStringLiteral("%1: %2").arg(side == 0 ? QStringLiteral("A") : QStringLiteral("B")).arg(detail));
                    m_process[side]->setEnabled(true);
                }
                m_busy = false; m_refresh->setEnabled(true); m_processRefresh->setEnabled(!m_listBusy);
                m_status->setText(errors.isEmpty() ? text("privilege.workbench.tokens.loaded", QStringLiteral("令牌已刷新；进程身份以 PID 和创建时间锁定。")) : errors.join(QChar('\n')));
                ks::ui::ApplyStatusRole(m_status, errors.isEmpty() ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
                render();
            });
        }

        void render()
        {
            QList<QVariant> sids;
            const Rows rows = comparisonRows(m_snapshots[0], m_snapshots[1], m_differences->isChecked(), m_search->text().trimmed(), sids);
            fill(m_table, rows, sids);
        }
        QComboBox* m_process[2]{};
        QLabel* m_identity[2]{};
        quint64 m_anchor[2]{};
        QJsonObject m_snapshots[2];
        QPushButton *m_refresh = nullptr, *m_processRefresh = nullptr;
        QCheckBox* m_differences = nullptr;
        QLineEdit* m_search = nullptr;
        QTableWidget* m_table = nullptr;
        QLabel* m_status = nullptr;
        bool m_loaded = false, m_busy = false, m_listBusy = false;
    };

    QString logonType(DWORD type)
    {
        switch (type)
        {
        case 2: return text("privilege.workbench.sessions.type_interactive", QStringLiteral("交互式"));
        case 3: return text("privilege.workbench.sessions.type_network", QStringLiteral("网络"));
        case 4: return text("privilege.workbench.sessions.type_batch", QStringLiteral("批处理"));
        case 5: return text("privilege.workbench.sessions.type_service", QStringLiteral("服务"));
        case 7: return text("privilege.workbench.sessions.type_unlock", QStringLiteral("解锁"));
        case 8: return text("privilege.workbench.sessions.type_network_cleartext", QStringLiteral("网络明文"));
        case 9: return text("privilege.workbench.sessions.type_new_credentials", QStringLiteral("新凭据"));
        case 10: return text("privilege.workbench.sessions.type_remote", QStringLiteral("远程交互（RDP）"));
        case 11: return text("privilege.workbench.sessions.type_cached", QStringLiteral("缓存交互"));
        case 12: return text("privilege.workbench.sessions.type_cached_remote", QStringLiteral("缓存远程交互"));
        case 13: return text("privilege.workbench.sessions.type_cached_unlock", QStringLiteral("缓存解锁"));
        default: return QString::number(type);
        }
    }

    QString fileTimeText(const QString& raw)
    {
        bool okay = false;
        const qint64 value = raw.toLongLong(&okay);
        constexpr qint64 unixEpoch100ns = 116444736000000000LL;
        return okay && value >= unixEpoch100ns
            ? QDateTime::fromMSecsSinceEpoch((value - unixEpoch100ns) / 10000).toLocalTime().toString(Qt::ISODate)
            : QString();
    }

    class SessionsPage final : public QWidget
    {
    public:
        SessionsPage(QWidget* parent, std::function<void(DWORD, quint64)> openProcess)
            : QWidget(parent), m_openProcess(std::move(openProcess))
        {
            auto* layout = new QVBoxLayout(this);
            auto* bar = new QHBoxLayout;
            m_refresh = new QPushButton(text("privilege.workbench.sessions.refresh", QStringLiteral("刷新登录会话")), this);
            m_search = new QLineEdit(this);
            m_search->setPlaceholderText(text("privilege.workbench.sessions.search", QStringLiteral("搜索账号、SID 或登录 LUID")));
            m_search->setObjectName(QStringLiteral("privilege_logon_account_search"));
            ks::ui::StyleSearchField(m_search);
            auto* all = new QPushButton(text("privilege.workbench.sessions.show_all", QStringLiteral("显示所有关联进程")), this);
            auto* sidCopy = new QPushButton(text("privilege.workbench.sessions.copy_sid", QStringLiteral("复制会话 SID")), this);
            bar->addWidget(m_refresh); bar->addWidget(m_search, 1); bar->addWidget(all); bar->addWidget(sidCopy);
            ks::ui::NormalizeToolbarRow(bar);
            layout->addLayout(bar);
            auto* note = new QLabel(text("privilege.workbench.sessions.note", QStringLiteral("进程按令牌 AuthenticationId 关联登录 LUID。终端会话编号仅用于显示；无法读取令牌的进程单独标明。选中登录会话筛选进程，双击进程打开详情。")), this);
            note->setWordWrap(true); layout->addWidget(note);
            auto* split = new QSplitter(Qt::Vertical, this);
            m_sessions = table(split, { text("privilege.workbench.sessions.account", QStringLiteral("账号")),
                text("privilege.workbench.sessions.luid", QStringLiteral("登录 LUID")),
                text("privilege.workbench.sessions.type", QStringLiteral("登录类型")),
                text("privilege.workbench.sessions.terminal_id", QStringLiteral("终端会话编号")),
                text("privilege.workbench.sessions.time", QStringLiteral("登录时间")),
                text("privilege.workbench.sessions.package", QStringLiteral("认证包")),
                QStringLiteral("SID"), text("privilege.workbench.sessions.process_count", QStringLiteral("关联进程数")),
                text("privilege.workbench.sessions.state", QStringLiteral("查询状态")) });
            m_sessions->setObjectName(QStringLiteral("privilege_logon_sessions_table"));
            ks::ui::SetTableActionBarMode(m_sessions, ks::ui::TableActionBarMode::Full);
            auto* processPanel = new QWidget(split);
            auto* processLayout = new QVBoxLayout(processPanel);
            processLayout->setContentsMargins(0, 0, 0, 0);
            auto* processBar = new QHBoxLayout;
            m_selectedLabel = new QLabel(this);
            m_processSearch = new QLineEdit(this);
            m_processSearch->setPlaceholderText(text("privilege.workbench.sessions.process_search", QStringLiteral("搜索进程名、PID 或查询错误")));
            ks::ui::StyleSearchField(m_processSearch);
            m_open = new QPushButton(text("privilege.workbench.sessions.open_process", QStringLiteral("打开进程详情")), this);
            m_open->setObjectName(QStringLiteral("privilege_logon_open_process"));
            m_open->setEnabled(static_cast<bool>(m_openProcess));
            processBar->addWidget(m_selectedLabel); processBar->addWidget(m_processSearch, 1); processBar->addWidget(m_open);
            ks::ui::NormalizeToolbarRow(processBar);
            processLayout->addLayout(processBar);
            m_processes = table(processPanel, { QStringLiteral("PID"), text("privilege.workbench.sessions.process", QStringLiteral("进程")),
                text("privilege.workbench.sessions.account", QStringLiteral("账号")),
                text("privilege.workbench.sessions.auth_id", QStringLiteral("令牌 AuthenticationId")),
                text("privilege.workbench.sessions.creation", QStringLiteral("进程创建时间")),
                text("privilege.workbench.sessions.path", QStringLiteral("映像路径")),
                text("privilege.workbench.sessions.state", QStringLiteral("查询状态")) });
            m_processes->setObjectName(QStringLiteral("privilege_logon_processes_table"));
            // 会话关联进程是嵌入式结果，与上方会话主表区分。
            ks::ui::SetTableActionBarMode(m_processes, ks::ui::TableActionBarMode::Compact);
            processLayout->addWidget(m_processes, 1);
            split->addWidget(m_sessions); split->addWidget(processPanel);
            split->setStretchFactor(0, 1); split->setStretchFactor(1, 1);
            layout->addWidget(split, 1);
            m_status = new QLabel(text("privilege.workbench.sessions.idle", QStringLiteral("尚未加载登录会话。")), this);
            m_status->setWordWrap(true); m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(m_status);
            connect(m_refresh, &QPushButton::clicked, this, [this]() { refresh(); });
            connect(m_search, &QLineEdit::textChanged, this, [this]() { renderSessions(); });
            connect(m_processSearch, &QLineEdit::textChanged, this, [this]() { renderProcesses(); });
            connect(all, &QPushButton::clicked, this, [this]() { m_selected.clear(); m_sessions->clearSelection(); renderProcesses(); });
            connect(sidCopy, &QPushButton::clicked, this, [this]()
            {
                const auto* item = m_sessions->item(m_sessions->currentRow(), 0);
                if (!item) return;
                const QString sid = item->data(Qt::UserRole).toJsonObject().value(QStringLiteral("sid")).toString();
                if (!sid.isEmpty()) QApplication::clipboard()->setText(sid);
            });
            connect(m_sessions, &QTableWidget::itemSelectionChanged, this, [this]()
            {
                const auto* item = m_sessions->item(m_sessions->currentRow(), 0);
                if (!item) return;
                m_selected = item->data(Qt::UserRole).toJsonObject().value(QStringLiteral("luid")).toString();
                renderProcesses();
            });
            connect(m_open, &QPushButton::clicked, this, [this]() { openSelected(); });
            connect(m_processes, &QTableWidget::cellDoubleClicked, this, [this](int, int) { openSelected(); });
        }

        void focusAccount(const QString& accountOrSid)
        {
            m_pendingAccount = accountOrSid.trimmed();
            m_selected = m_pendingAccount.isEmpty() ? QString() : QStringLiteral("account_filter_no_match");
            m_search->setText(m_pendingAccount);
            renderSessions(); renderProcesses();
            m_search->setFocus();
        }

    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_loaded) { m_loaded = true; QTimer::singleShot(0, this, [this]() { refresh(); }); }
        }

    private:
        void refresh()
        {
            if (m_busy) return;
            m_busy = true; m_refresh->setEnabled(false);
            m_status->setText(text("privilege.workbench.sessions.loading", QStringLiteral("正在查询 LSA 登录会话和进程令牌...")));
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Info);
            async(this, []() { return sessionsSnapshot(); }, [this](const QJsonObject& result)
            {
                m_snapshot = result;
                m_hasSnapshot = true;
                m_sessionMap.clear(); m_counts.clear();
                for (const auto& value : result.value(QStringLiteral("sessions")).toArray())
                {
                    const auto record = value.toObject();
                    m_sessionMap.insert(record.value(QStringLiteral("luid")).toString(), record);
                }
                int unreadable = 0, unmatched = 0;
                for (const auto& value : result.value(QStringLiteral("processes")).toArray())
                {
                    const auto record = value.toObject();
                    const QString authentication = record.value(QStringLiteral("authentication_id")).toString();
                    if (!record.value(QStringLiteral("error")).toString().isEmpty()) ++unreadable;
                    else if (!m_sessionMap.contains(authentication)) ++unmatched;
                    if (!authentication.isEmpty()) ++m_counts[authentication];
                }
                if (!m_selected.isEmpty() && !m_sessionMap.contains(m_selected))
                    m_selected = m_pendingAccount.isEmpty() ? QString() : QStringLiteral("account_filter_no_match");
                renderSessions(); renderProcesses();
                m_busy = false; m_refresh->setEnabled(true);
                QString summary = text("privilege.workbench.sessions.summary", QStringLiteral("登录会话 %1；进程 %2；令牌不可读 %3；LSA 未枚举的登录 LUID %4。"))
                    .arg(m_sessionMap.size()).arg(result.value(QStringLiteral("processes")).toArray().size()).arg(unreadable).arg(unmatched);
                const QString errors = errorText(result);
                if (!errors.isEmpty()) summary += QChar('\n') + errors;
                m_status->setText(summary);
                ks::ui::ApplyStatusRole(m_status, errors.isEmpty() && unreadable == 0 && unmatched == 0
                    ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
            });
        }

        void renderSessions()
        {
            Rows rows;
            QList<QVariant> identities;
            const QString requested = m_pendingAccount;
            if (!requested.isEmpty() && m_search->text().trimmed() != requested)
            {
                m_pendingAccount.clear();
                if (m_selected == QStringLiteral("account_filter_no_match")) { m_selected.clear(); renderProcesses(); }
            }
            int selectedRow = -1;
            for (const auto& value : m_snapshot.value(QStringLiteral("sessions")).toArray())
            {
                const auto record = value.toObject();
                const QString error = ks::i18n::sourceText(record.value(QStringLiteral("error")).toString());
                const QString luid = record.value(QStringLiteral("luid")).toString();
                const QStringList row{record.value(QStringLiteral("account")).toString(), luid,
                    error.isEmpty() ? logonType(static_cast<DWORD>(record.value(QStringLiteral("type")).toDouble())) : unavailableText(),
                    error.isEmpty() ? QString::number(record.value(QStringLiteral("wts_session_id")).toInt()) : unavailableText(),
                    fileTimeText(record.value(QStringLiteral("logonTime100ns")).toString()),
                    record.value(QStringLiteral("package")).toString(), record.value(QStringLiteral("sid")).toString(),
                    QString::number(m_counts.value(luid)),
                    error.isEmpty() ? text("privilege.workbench.sessions.read", QStringLiteral("已读取")) : error};
                if (!m_search->text().trimmed().isEmpty()
                    && !row.join(QChar(' ')).contains(m_search->text().trimmed(), Qt::CaseInsensitive)) continue;
                if (!m_pendingAccount.isEmpty())
                {
                    const bool exact = record.value(QStringLiteral("sid")).toString().compare(m_pendingAccount, Qt::CaseInsensitive) == 0
                        || record.value(QStringLiteral("account")).toString().compare(m_pendingAccount, Qt::CaseInsensitive) == 0;
                    if (!exact) continue;
                    if (selectedRow < 0) selectedRow = static_cast<int>(rows.size());
                }
                rows.append(row); identities.append(record);
            }
            fill(m_sessions, rows, identities, [this, selectedRow, requested]()
            {
                if (requested.isEmpty() || requested != m_pendingAccount) return;
                if (selectedRow >= 0) m_sessions->setCurrentCell(selectedRow, 0);
                else if (m_hasSnapshot)
                {
                    m_selected = QStringLiteral("account_filter_no_match"); renderProcesses();
                    m_status->setText(text("privilege.workbench.sessions.no_account_match", QStringLiteral("没有可读取且与此账号 SID 完全匹配的登录会话：%1")).arg(requested));
                    ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Warning);
                }
            });
        }

        void renderProcesses()
        {
            Rows rows;
            QList<QVariant> identities;
            for (const auto& value : m_snapshot.value(QStringLiteral("processes")).toArray())
            {
                const auto record = value.toObject();
                const QString auth = record.value(QStringLiteral("authentication_id")).toString();
                if (!m_selected.isEmpty() && auth != m_selected) continue;
                const QString error = ks::i18n::sourceText(record.value(QStringLiteral("error")).toString());
                const QString state = !error.isEmpty() ? error : m_sessionMap.contains(auth)
                    ? text("privilege.workbench.sessions.linked", QStringLiteral("已按登录 LUID 关联"))
                    : text("privilege.workbench.sessions.unmatched", QStringLiteral("LSA 未枚举此登录 LUID"));
                const QStringList row{QString::number(record.value(QStringLiteral("pid")).toInt()),
                    record.value(QStringLiteral("name")).toString(), m_sessionMap.value(auth).value(QStringLiteral("account")).toString(),
                    auth.isEmpty() ? unavailableText() : auth,
                    fileTimeText(record.value(QStringLiteral("creationTime100ns")).toString()),
                    record.value(QStringLiteral("imagePath")).toString(), state};
                if (!m_processSearch->text().trimmed().isEmpty()
                    && !row.join(QChar(' ')).contains(m_processSearch->text().trimmed(), Qt::CaseInsensitive)) continue;
                rows.append(row); identities.append(record);
            }
            fill(m_processes, rows, identities);
            m_selectedLabel->setText(m_selected == QStringLiteral("account_filter_no_match")
                ? text("privilege.workbench.sessions.account_filter", QStringLiteral("账号筛选：%1")).arg(m_pendingAccount)
                : m_selected.isEmpty() ? text("privilege.workbench.sessions.all", QStringLiteral("所有进程（含不可读项）"))
                : text("privilege.workbench.sessions.selected", QStringLiteral("登录 LUID：%1")).arg(m_selected));
        }

        void openSelected()
        {
            const auto* item = m_processes->item(m_processes->currentRow(), 0);
            if (item) openProcessDetail(this, item->data(Qt::UserRole).toJsonObject(), m_status, m_openProcess);
        }

        QPushButton *m_refresh = nullptr, *m_open = nullptr;
        QLineEdit *m_search = nullptr, *m_processSearch = nullptr;
        QTableWidget *m_sessions = nullptr, *m_processes = nullptr;
        QLabel *m_status = nullptr, *m_selectedLabel = nullptr;
        QJsonObject m_snapshot;
        QMap<QString, QJsonObject> m_sessionMap;
        QMap<QString, int> m_counts;
        QString m_selected, m_pendingAccount;
        std::function<void(DWORD, quint64)> m_openProcess;
        bool m_loaded = false, m_busy = false, m_hasSnapshot = false;
    };

    QJsonObject launchAndCapture(const QString& image, const QString& arguments, ks::process::RunAsIdentity identity)
    {
        const auto launched = ks::process::RunExecutableAs(image.toStdWString(), identity, arguments.toStdWString());
        QJsonObject result{ { QStringLiteral("success"), launched.success },
            { QStringLiteral("error"), static_cast<double>(launched.error) },
            { QStringLiteral("pid"), static_cast<double>(launched.processId) },
            { QStringLiteral("detail"), QString::fromStdWString(launched.detail) },
            { QStringLiteral("creationTime100ns"), QString::number(launched.creationTime100ns) } };
        if (!launched.success) return result;
        if (!launched.processId || !launched.creationTime100ns)
        {
            result.insert(QStringLiteral("capture_error"), QStringLiteral("Child process identity was not returned"));
            return result;
        }
        QJsonObject snapshot = ks::privilege::captureTokenSnapshot(launched.processId);
        const quint64 capturedCreation = snapshot.value(QStringLiteral("metadata")).toObject()
            .value(QStringLiteral("creationTime100ns")).toString().toULongLong();
        if (!capturedCreation || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).isBool())
        {
            auto errors = snapshot.value(QStringLiteral("errors")).toArray();
            errors.append(QStringLiteral("Child process identity could not be verified"));
            snapshot.insert(QStringLiteral("errors"), errors);
        }
        else if (!sameIdentity(snapshot, launched.processId, launched.creationTime100ns)
            || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).toBool())
        {
            snapshot.insert(QStringLiteral("entries"), QJsonArray{});
            snapshot.insert(QStringLiteral("readable"), false);
            snapshot.insert(QStringLiteral("errors"), QJsonArray{QStringLiteral("Child exited or PID was reused before token capture")});
        }
        result.insert(QStringLiteral("snapshot"), snapshot);
        return result;
    }

    class IdentityLaunchPage final : public QWidget
    {
    public:
        explicit IdentityLaunchPage(QWidget* parent) : QWidget(parent)
        {
            auto* layout = new QVBoxLayout(this);
            auto* form = new QFormLayout;
            auto* pathRow = new QHBoxLayout;
            m_image = new QLineEdit(this);
            m_image->setPlaceholderText(text("privilege.workbench.launch.image_hint", QStringLiteral("可执行文件的完整路径（.exe）")));
            auto* browse = new QPushButton(text("privilege.workbench.launch.browse", QStringLiteral("浏览")), this);
            pathRow->addWidget(m_image, 1); pathRow->addWidget(browse);
            ks::ui::NormalizeToolbarRow(pathRow);
            form->addRow(text("privilege.workbench.launch.image", QStringLiteral("程序")), pathRow);
            m_arguments = new QLineEdit(this);
            form->addRow(text("privilege.workbench.launch.arguments", QStringLiteral("参数")), m_arguments);
            m_directory = new QLineEdit(this); m_directory->setReadOnly(true);
            form->addRow(text("privilege.workbench.launch.directory", QStringLiteral("工作目录（程序所在目录）")), m_directory);
            m_mode = new QComboBox(this);
            m_mode->addItem(text("privilege.workbench.launch.standard", QStringLiteral("普通用户（未提升）")), static_cast<int>(ks::process::RunAsIdentity::StandardUser));
            m_mode->addItem(text("privilege.workbench.launch.admin", QStringLiteral("管理员（Windows UAC）")), static_cast<int>(ks::process::RunAsIdentity::Administrator));
            m_mode->addItem(QStringLiteral("SYSTEM"), static_cast<int>(ks::process::RunAsIdentity::System));
            m_mode->addItem(QStringLiteral("TrustedInstaller"), static_cast<int>(ks::process::RunAsIdentity::TrustedInstaller));
            form->addRow(text("privilege.workbench.launch.identity", QStringLiteral("请求身份")), m_mode);
            layout->addLayout(form);
            auto* note = new QLabel(text("privilege.workbench.launch.note", QStringLiteral("复用现有身份启动后端，目标用户环境和交互式会话由后端设置。SYSTEM / TrustedInstaller 需要当前 KSword 已提升；TrustedInstaller 可能启动服务。工作目录固定为程序目录。实际身份以启动后的令牌为准。")), this);
            note->setWordWrap(true); layout->addWidget(note);
            auto* bar = new QHBoxLayout;
            m_launch = new QPushButton(text("privilege.workbench.launch.start", QStringLiteral("以所选身份启动")), this);
            m_launch->setObjectName(QStringLiteral("privilege_identity_launch"));
            m_launch->setEnabled(false);
            m_availability = new QPushButton(text("privilege.workbench.launch.availability", QStringLiteral("重新检查身份可用性")), this);
            m_baseline = new QPushButton(text("privilege.workbench.launch.baseline", QStringLiteral("再启动普通用户实例并对比")), this);
            m_baseline->setEnabled(false);
            m_refresh = new QPushButton(text("privilege.workbench.launch.refresh", QStringLiteral("刷新已启动进程令牌")), this);
            m_refresh->setEnabled(false);
            bar->addWidget(m_launch); bar->addWidget(m_availability); bar->addWidget(m_baseline); bar->addWidget(m_refresh);
            ks::ui::NormalizeToolbarRow(bar);
            layout->addLayout(bar);
            auto* searchBar = new QHBoxLayout;
            m_differences = new QCheckBox(text("privilege.workbench.tokens.differences", QStringLiteral("只显示差异")), this);
            m_search = new QLineEdit(this);
            m_search->setPlaceholderText(text("privilege.workbench.tokens.search", QStringLiteral("搜索字段、SID 或权限")));
            auto* copy = new QPushButton(text("privilege.workbench.tokens.copy_sid", QStringLiteral("复制选中 SID")), this);
            searchBar->addWidget(m_differences); searchBar->addWidget(m_search, 1); searchBar->addWidget(copy);
            layout->addLayout(searchBar);
            m_identity = new QLabel(this); m_identity->setWordWrap(true);
            m_identity->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(m_identity);
            m_table = table(this, { text("privilege.workbench.tokens.field", QStringLiteral("字段")),
                text("privilege.workbench.launch.actual", QStringLiteral("所选身份实例的实际令牌")),
                text("privilege.workbench.launch.ordinary_actual", QStringLiteral("普通用户实例的实际令牌")),
                text("privilege.workbench.tokens.result", QStringLiteral("结果")) });
            m_table->setObjectName(QStringLiteral("privilege_launch_token_table"));
            // 启动后的令牌对比已由页面处理，通用操作栏只需紧凑导出。
            ks::ui::StyleSearchField(m_search);
            ks::ui::NormalizeToolbarRow(searchBar);
            ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Compact);
            layout->addWidget(m_table, 1);
            m_status = new QLabel(text("privilege.workbench.launch.idle", QStringLiteral("尚未启动程序；身份可用性检查不会请求 UAC 或启动服务。")), this);
            m_status->setWordWrap(true); m_status->setTextInteractionFlags(Qt::TextSelectableByMouse); layout->addWidget(m_status);
            connect(browse, &QPushButton::clicked, this, [this]()
            {
                const QPointer<QWidget> pageGuard(this);
                const QString path = QFileDialog::getOpenFileName(this, text("privilege.workbench.launch.choose", QStringLiteral("选择可执行程序")),
                    m_image->text(), text("privilege.workbench.launch.filter", QStringLiteral("可执行程序 (*.exe)")));
                if (pageGuard && !path.isEmpty()) m_image->setText(path);
            });
            connect(m_image, &QLineEdit::textChanged, this, [this](const QString& image)
            {
                m_directory->setText(image.trimmed().isEmpty() ? QString() : QFileInfo(image.trimmed()).absolutePath());
            });
            connect(m_launch, &QPushButton::clicked, this, [this]() { launch(false); });
            connect(m_baseline, &QPushButton::clicked, this, [this]() { launch(true); });
            connect(m_availability, &QPushButton::clicked, this, [this]() { checkAvailability(); });
            connect(m_refresh, &QPushButton::clicked, this, [this]() { refreshTokens(); });
            connect(m_search, &QLineEdit::textChanged, this, [this]() { render(); });
            connect(m_differences, &QCheckBox::toggled, this, [this]() { render(); });
            connect(copy, &QPushButton::clicked, this, [this]() { copySid(m_table, 0); });
        }

    protected:
        void showEvent(QShowEvent* event) override
        {
            QWidget::showEvent(event);
            if (!m_loaded) { m_loaded = true; QTimer::singleShot(0, this, [this]() { checkAvailability(); }); }
        }

    private:
        void busy(bool value)
        {
            m_busy = value;
            m_launch->setEnabled(!value && m_available);
            m_availability->setEnabled(!value);
            m_baseline->setEnabled(!value && m_standardAvailable && m_results[0].value(QStringLiteral("success")).toBool());
            m_refresh->setEnabled(!value && m_results[0].value(QStringLiteral("success")).toBool()
                && m_results[0].value(QStringLiteral("creationTime100ns")).toString().toULongLong() != 0);
            m_mode->setEnabled(!value); m_image->setEnabled(!value); m_arguments->setEnabled(!value);
        }

        void checkAvailability()
        {
            if (m_busy) return;
            busy(true);
            async(this, []()
            {
                const auto available = ks::process::QueryRunAsAvailability();
                return QJsonObject{ { QStringLiteral("standard"), available.standardUser },
                    { QStringLiteral("admin"), available.administrator }, { QStringLiteral("system"), available.system },
                    { QStringLiteral("ti"), available.trustedInstaller } };
            }, [this](const QJsonObject& available)
            {
                const bool states[4]{available.value(QStringLiteral("standard")).toBool(), available.value(QStringLiteral("admin")).toBool(),
                    available.value(QStringLiteral("system")).toBool(), available.value(QStringLiteral("ti")).toBool()};
                auto* model = qobject_cast<QStandardItemModel*>(m_mode->model());
                int first = -1;
                for (int index = 0; index < 4; ++index)
                {
                    if (model && model->item(index)) model->item(index)->setEnabled(states[index]);
                    if (states[index] && first < 0) first = index;
                }
                if (m_mode->currentIndex() < 0 || !states[m_mode->currentIndex()]) m_mode->setCurrentIndex(first);
                m_available = first >= 0; m_standardAvailable = states[0];
                busy(false);
                m_status->setText(text("privilege.workbench.launch.availability_summary", QStringLiteral("身份检查：普通用户 %1；管理员 %2；SYSTEM %3；TrustedInstaller %4。不可用身份已禁用。"))
                    .arg(states[0] ? QStringLiteral("1") : QStringLiteral("0"))
                    .arg(states[1] ? QStringLiteral("1") : QStringLiteral("0"))
                    .arg(states[2] ? QStringLiteral("1") : QStringLiteral("0"))
                    .arg(states[3] ? QStringLiteral("1") : QStringLiteral("0")));
            });
        }

        void launch(bool baseline)
        {
            if (m_busy) return;
            const QString image = baseline ? m_lastImage : QFileInfo(m_image->text().trimmed()).absoluteFilePath();
            const QString arguments = baseline ? m_lastArguments : m_arguments->text();
            const auto identity = baseline ? ks::process::RunAsIdentity::StandardUser
                : static_cast<ks::process::RunAsIdentity>(m_mode->currentData().toInt());
            if ((!baseline && m_image->text().trimmed().isEmpty()) || !QFileInfo(image).isFile()
                || QFileInfo(image).suffix().compare(QStringLiteral("exe"), Qt::CaseInsensitive) != 0)
            { m_status->setText(text("privilege.workbench.launch.invalid_image", QStringLiteral("请选择存在的 .exe 可执行程序。"))); return; }
            const bool elevated = identity != ks::process::RunAsIdentity::StandardUser;
            if (baseline || elevated)
            {
                const QString prompt = baseline
                    ? text("privilege.workbench.launch.confirm_baseline", QStringLiteral("将以普通用户再次启动下面的程序，并保留两个实例用于令牌对比。程序及参数：\n%1\n%2")).arg(image, arguments)
                    : text("privilege.workbench.launch.confirm_elevated", QStringLiteral("将以 %1 启动下面的程序。程序会立即运行；TrustedInstaller 模式可能启动服务。\n%2\n%3"))
                        .arg(m_mode->currentText(), image, arguments);
                const QPointer<QWidget> pageGuard(this);
                if (QMessageBox::question(this, text("privilege.workbench.launch.confirm_title", QStringLiteral("确认身份启动")), prompt,
                    QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
                if (!pageGuard) return;
            }
            if (!baseline) { m_lastImage = image; m_lastArguments = arguments; m_results[1] = {}; }
            busy(true);
            m_status->setText(text("privilege.workbench.launch.starting", QStringLiteral("正在启动程序并读取实际子进程令牌...")));
            ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Info);
            async(this, [image, arguments, identity]() { return launchAndCapture(image, arguments, identity); },
                [this, baseline](const QJsonObject& result)
                {
                    m_results[baseline ? 1 : 0] = result;
                    busy(false);
                    if (!result.value(QStringLiteral("success")).toBool())
                    {
                        m_status->setText(text("privilege.workbench.launch.failed", QStringLiteral("启动失败：%1；%2"))
                            .arg(result.value(QStringLiteral("detail")).toString(), winError(static_cast<DWORD>(result.value(QStringLiteral("error")).toDouble()))));
                        ks::ui::ApplyStatusRole(m_status, ks::ui::StatusRole::Error);
                    }
                    else
                    {
                        const auto snapshot = result.value(QStringLiteral("snapshot")).toObject();
                        QString detail = errorText(snapshot);
                        if (!result.value(QStringLiteral("capture_error")).toString().isEmpty())
                            detail += ks::i18n::sourceText(result.value(QStringLiteral("capture_error")).toString());
                        m_status->setText(text("privilege.workbench.launch.started", QStringLiteral("已启动 PID %1。%2"))
                            .arg(result.value(QStringLiteral("pid")).toInt()).arg(detail.isEmpty()
                                ? text("privilege.workbench.launch.captured", QStringLiteral("下表显示实际读取的令牌。"))
                                : text("privilege.workbench.launch.capture_failed", QStringLiteral("实际身份未完整验证：%1")).arg(detail)));
                        ks::ui::ApplyStatusRole(m_status, detail.isEmpty() ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
                    }
                    render();
                });
        }

        void refreshTokens()
        {
            if (m_busy || !m_results[0].value(QStringLiteral("success")).toBool()) return;
            const QJsonObject a = m_results[0], b = m_results[1];
            busy(true);
            async(this, [a, b]()
            {
                QJsonArray updated;
                for (const auto& previous : {a, b})
                {
                    if (!previous.value(QStringLiteral("success")).toBool()) { updated.append(previous); continue; }
                    QJsonObject result = previous;
                    const DWORD pid = static_cast<DWORD>(previous.value(QStringLiteral("pid")).toDouble());
                    const quint64 expected = previous.value(QStringLiteral("creationTime100ns")).toString().toULongLong();
                    if (!expected)
                    {
                        result.insert(QStringLiteral("snapshot"), QJsonObject{ { QStringLiteral("entries"), QJsonArray{} },
                            { QStringLiteral("errors"), QJsonArray{QStringLiteral("Child process identity was not returned")} },
                            { QStringLiteral("readable"), false } });
                        updated.append(result); continue;
                    }
                    auto snapshot = ks::privilege::captureTokenSnapshot(pid);
                    const quint64 capturedCreation = snapshot.value(QStringLiteral("metadata")).toObject()
                        .value(QStringLiteral("creationTime100ns")).toString().toULongLong();
                    if (!capturedCreation || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).isBool())
                    {
                        auto errors = snapshot.value(QStringLiteral("errors")).toArray();
                        errors.append(QStringLiteral("Child process identity could not be verified"));
                        snapshot.insert(QStringLiteral("errors"), errors);
                    }
                    else if (!sameIdentity(snapshot, pid, expected)
                        || !snapshot.value(QStringLiteral("metadata")).toObject().value(QStringLiteral("aliveAfterCapture")).toBool())
                    {
                        snapshot.insert(QStringLiteral("entries"), QJsonArray{});
                        snapshot.insert(QStringLiteral("readable"), false);
                        snapshot.insert(QStringLiteral("errors"), QJsonArray{QStringLiteral("Child exited or PID was reused before token capture")});
                    }
                    result.insert(QStringLiteral("snapshot"), snapshot); updated.append(result);
                }
                return QJsonObject{ { QStringLiteral("updated"), updated } };
            }, [this](const QJsonObject& result)
            {
                const auto updated = result.value(QStringLiteral("updated")).toArray();
                m_results[0] = updated.at(0).toObject(); m_results[1] = updated.at(1).toObject();
                busy(false); render();
                QStringList errors;
                for (const auto& item : m_results) { const QString error = errorText(item.value(QStringLiteral("snapshot")).toObject()); if (!error.isEmpty()) errors.append(error); }
                m_status->setText(errors.isEmpty() ? text("privilege.workbench.launch.refreshed", QStringLiteral("已按启动时的 PID 和创建时间刷新令牌。")) : errors.join(QChar('\n')));
                ks::ui::ApplyStatusRole(m_status, errors.isEmpty() ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
            });
        }

        void render()
        {
            QList<QVariant> sids;
            const auto left = m_results[0].value(QStringLiteral("snapshot")).toObject();
            const auto right = m_results[1].value(QStringLiteral("snapshot")).toObject();
            fill(m_table, comparisonRows(left, right, m_differences->isChecked(), m_search->text().trimmed(), sids), sids);
            QStringList identities;
            for (int side = 0; side < 2; ++side)
            {
                if (!m_results[side].value(QStringLiteral("success")).toBool()) continue;
                const auto snapshot = m_results[side].value(QStringLiteral("snapshot")).toObject();
                QString sid, account, elevated, integrity;
                for (const auto& value : snapshot.value(QStringLiteral("entries")).toArray())
                {
                    const auto entry = value.toObject(); const QString key = entry.value(QStringLiteral("key")).toString();
                    if (key == QStringLiteral("user")) sid = displayValue(entry);
                    else if (key == QStringLiteral("user/account")) account = displayValue(entry);
                    else if (key == QStringLiteral("elevated")) elevated = displayValue(entry);
                    else if (key == QStringLiteral("integrity/rid")) integrity = displayValue(entry);
                }
                identities.append(text("privilege.workbench.launch.actual_identity", QStringLiteral("%1：PID %2；账号 %3；SID %4；提升 %5；完整性 RID %6"))
                    .arg(side == 0 ? text("privilege.workbench.launch.selected_instance", QStringLiteral("所选身份实例"))
                        : text("privilege.workbench.launch.standard_instance", QStringLiteral("普通用户实例")))
                    .arg(m_results[side].value(QStringLiteral("pid")).toInt())
                    .arg(account.isEmpty() ? unavailableText() : account, sid.isEmpty() ? unavailableText() : sid,
                        elevated.isEmpty() ? unavailableText() : elevated, integrity.isEmpty() ? unavailableText() : integrity));
            }
            m_identity->setText(identities.join(QChar('\n')));
        }
        QLineEdit *m_image = nullptr, *m_arguments = nullptr, *m_directory = nullptr, *m_search = nullptr;
        QComboBox* m_mode = nullptr;
        QPushButton *m_launch = nullptr, *m_availability = nullptr, *m_baseline = nullptr, *m_refresh = nullptr;
        QCheckBox* m_differences = nullptr;
        QTableWidget* m_table = nullptr;
        QLabel *m_status = nullptr, *m_identity = nullptr;
        QJsonObject m_results[2];
        QString m_lastImage, m_lastArguments;
        bool m_loaded = false, m_busy = false, m_available = false, m_standardAvailable = false;
    };
}

QJsonObject ks::privilege::captureTokenSnapshot(DWORD pid)
{
    Handle process;
    process.value = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, pid);
    if (!process.value)
        return { { QStringLiteral("entries"), QJsonArray{} }, { QStringLiteral("errors"), QJsonArray{winError(::GetLastError())} },
            { QStringLiteral("metadata"), QJsonObject{ { QStringLiteral("pid"), static_cast<double>(pid) } } },
            { QStringLiteral("readable"), false } };
    return tokenOnProcess(process.value, pid);
}

QWidget* ks::privilege::createTokenComparePage(QWidget* parent) { return new TokenComparePage(parent); }
QWidget* ks::privilege::createSessionsPage(QWidget* parent, std::function<void(DWORD, quint64)> openProcess)
{ return new SessionsPage(parent, std::move(openProcess)); }
void ks::privilege::focusSessionsAccount(QWidget* page, const QString& accountOrSid)
{
    if (auto* sessions = dynamic_cast<SessionsPage*>(page)) sessions->focusAccount(accountOrSid);
}
QWidget* ks::privilege::createIdentityLaunchPage(QWidget* parent) { return new IdentityLaunchPage(parent); }
