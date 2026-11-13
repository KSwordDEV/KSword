#include "../UI/KeyboardItemActivation.h"
#include "RegistryAdvancedDialogs.h"
#include "./OfflineHiveSession.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/PrimaryPageStyle.h"
#include "RegistryValueCodec.h"
#include "RegistryValueEditorWidget.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/AsyncOperation.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/UI_All.h"

#include <QCloseEvent>
#include <QElapsedTimer>
#include <QPersistentModelIndex>
#include <QTimer>
#include <deque>
#include <functional>
#include <QDialog>
#include <QDialogButtonBox>
#include "../UI/SecondaryPageLayout.h"
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QPointer>
#include <QSaveFile>
#include <QSplitter>
#include <QStringList>
#include <QTableWidget>
#include <QTemporaryDir>
#include <QTreeWidget>
#include <QVBoxLayout>
#include <QVector>

#include <Windows.h>
#include <Sddl.h>

#include <array>
#include <utility>

namespace
{
    namespace hive = ks::registry::offline;
    constexpr int kKeyPathRole = Qt::UserRole;
    constexpr int kNextKeyRole = Qt::UserRole + 1;
    constexpr int kLoadedRole = Qt::UserRole + 2;
    constexpr int kMoreRole = Qt::UserRole + 3;

    QString trText(const QString& text) { return ks::i18n::sourceText(text); }
    LPCWSTR wide(const QString& text) { return reinterpret_cast<LPCWSTR>(text.utf16()); }

    QString winError(LSTATUS status)
    {
        LPWSTR message = nullptr;
        const DWORD size = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM
            | FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, static_cast<DWORD>(status), 0,
            reinterpret_cast<LPWSTR>(&message), 0, nullptr);
        const QString detail = size ? QString::fromWCharArray(message, size).trimmed() : QString();
        if (message) LocalFree(message);
        return trText(QStringLiteral("Win32 错误 %1：%2")).arg(status).arg(detail);
    }

    struct Key
    {
        HKEY value = nullptr;
        Key() = default;
        ~Key() { if (value) RegCloseKey(value); }
        Key(const Key&) = delete;
        Key& operator=(const Key&) = delete;
        Key(Key&& other) noexcept : value(std::exchange(other.value, nullptr)) {}
        Key& operator=(Key&& other) noexcept
        {
            if (this != &other)
            {
                if (value) RegCloseKey(value);
                value = std::exchange(other.value, nullptr);
            }
            return *this;
        }
    };

    bool parsePath(const QString& path, HKEY* root, QString* subkey)
    {
        if (path.contains(QChar(0))) return false;
        const qsizetype slash = path.indexOf(QLatin1Char('\\'));
        const QString name = slash < 0 ? path : path.left(slash);
        *subkey = slash < 0 ? QString() : path.mid(slash + 1);
        if (name.compare(QStringLiteral("HKEY_CLASSES_ROOT"), Qt::CaseInsensitive) == 0
            || name.compare(QStringLiteral("HKCR"), Qt::CaseInsensitive) == 0) *root = HKEY_CLASSES_ROOT;
        else if (name.compare(QStringLiteral("HKEY_CURRENT_USER"), Qt::CaseInsensitive) == 0
            || name.compare(QStringLiteral("HKCU"), Qt::CaseInsensitive) == 0) *root = HKEY_CURRENT_USER;
        else if (name.compare(QStringLiteral("HKEY_LOCAL_MACHINE"), Qt::CaseInsensitive) == 0
            || name.compare(QStringLiteral("HKLM"), Qt::CaseInsensitive) == 0) *root = HKEY_LOCAL_MACHINE;
        else if (name.compare(QStringLiteral("HKEY_USERS"), Qt::CaseInsensitive) == 0
            || name.compare(QStringLiteral("HKU"), Qt::CaseInsensitive) == 0) *root = HKEY_USERS;
        else if (name.compare(QStringLiteral("HKEY_CURRENT_CONFIG"), Qt::CaseInsensitive) == 0
            || name.compare(QStringLiteral("HKCC"), Qt::CaseInsensitive) == 0) *root = HKEY_CURRENT_CONFIG;
        else return false;
        return true;
    }

    QString sddl(PSECURITY_DESCRIPTOR descriptor, SECURITY_INFORMATION part)
    {
        LPWSTR text = nullptr;
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, part, &text, nullptr))
            return {};
        const QString result = QString::fromWCharArray(text);
        LocalFree(text);
        return result;
    }

    LSTATUS readSecurity(HKEY key, QByteArray* bytes)
    {
        constexpr SECURITY_INFORMATION parts = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
        DWORD size = 0;
        LSTATUS status = RegGetKeySecurity(key, parts, nullptr, &size);
        if (status != ERROR_INSUFFICIENT_BUFFER && status != ERROR_SUCCESS) return status;
        if (size == 0 || size > 1024 * 1024) return ERROR_INVALID_DATA;
        QByteArray raw(size, '\0');
        status = RegGetKeySecurity(key, parts, reinterpret_cast<PSECURITY_DESCRIPTOR>(raw.data()), &size);
        if (status != ERROR_SUCCESS) return status;
        raw.resize(size);
        if (!IsValidSecurityDescriptor(reinterpret_cast<PSECURITY_DESCRIPTOR>(raw.data()))) return ERROR_INVALID_SECURITY_DESCR;
        *bytes = raw;
        return ERROR_SUCCESS;
    }

    void setStatus(QLabel* label, const QString& text, ks::ui::StatusRole role)
    {
        label->setText(text);
        ks::ui::ApplyStatusRole(label, role);
    }

    LSTATUS linkTraversalStatus(HKEY key);


    // Permission workers retain only this immutable target and raw security values.
    struct PermissionTarget
    {
        QString path;
        REGSAM view = 0;
    };

    LSTATUS openPermissionKey(const PermissionTarget& target, REGSAM access, Key* key)
    {
        HKEY root = nullptr;
        QString subkey;
        if (!parsePath(target.path, &root, &subkey)) return ERROR_INVALID_PARAMETER;
        Key current;
        LSTATUS status = RegOpenKeyExW(root, L"", REG_OPTION_OPEN_LINK,
            KEY_QUERY_VALUE | target.view | (subkey.isEmpty() ? access : 0), &current.value);
        if (status != ERROR_SUCCESS) return status;
        const QStringList parts = subkey.isEmpty() ? QStringList() : subkey.split(QLatin1Char('\\'), Qt::KeepEmptyParts);
        for (qsizetype i = 0; i < parts.size(); ++i)
        {
            if (parts[i].isEmpty()) return ERROR_INVALID_PARAMETER;
            status = linkTraversalStatus(current.value);
            if (status != ERROR_SUCCESS) return status;
            Key next;
            const REGSAM requested = KEY_QUERY_VALUE | target.view | (i + 1 == parts.size() ? access : 0);
            status = RegOpenKeyExW(current.value, wide(parts[i]), REG_OPTION_OPEN_LINK, requested, &next.value);
            if (status != ERROR_SUCCESS) return status;
            current = std::move(next);
        }
        status = linkTraversalStatus(current.value);
        if (status != ERROR_SUCCESS) return status;
        *key = std::move(current);
        return ERROR_SUCCESS;
    }

    struct PermissionSnapshot
    {
        QByteArray baseline;
        QString owner;
        QString group;
        QString dacl;
        LSTATUS status = ERROR_SUCCESS;
        LSTATUS writeStatus = ERROR_ACCESS_DENIED;
    };

    PermissionSnapshot permissionSnapshot(HKEY key)
    {
        PermissionSnapshot result;
        result.status = readSecurity(key, &result.baseline);
        if (result.status == ERROR_SUCCESS)
        {
            auto* descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(result.baseline.data());
            result.owner = sddl(descriptor, OWNER_SECURITY_INFORMATION);
            result.group = sddl(descriptor, GROUP_SECURITY_INFORMATION);
            result.dacl = sddl(descriptor, DACL_SECURITY_INFORMATION);
        }
        return result;
    }

    PermissionSnapshot readPermissionSnapshot(const PermissionTarget& target)
    {
        Key key;
        PermissionSnapshot result;
        result.status = openPermissionKey(target, READ_CONTROL, &key);
        if (result.status != ERROR_SUCCESS) return result;
        result = permissionSnapshot(key.value);
        if (result.status != ERROR_SUCCESS) return result;
        Key writable;
        result.writeStatus = openPermissionKey(target, READ_CONTROL | WRITE_DAC, &writable);
        return result;
    }

    struct PermissionApplyRequest
    {
        PermissionTarget target;
        QByteArray baseline;
        QString original;
        QString input;
    };

    struct PermissionApplyResult
    {
        enum class Kind { Nul, InvalidSddl, DaclOnly, Unchanged, Access, Conflict, ReadBack, Applied };
        Kind kind = Kind::Access;
        LSTATUS status = ERROR_SUCCESS;
        bool submitted = false;
        QString requested;
        PermissionSnapshot actual;
    };

    PermissionApplyResult applyPermissionRequest(const PermissionApplyRequest& request)
    {
        PermissionApplyResult result;
        if (request.input.contains(QChar(0))) { result.kind = PermissionApplyResult::Kind::Nul; return result; }
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(request.input), SDDL_REVISION_1, &descriptor, nullptr))
        {
            result.kind = PermissionApplyResult::Kind::InvalidSddl;
            result.status = GetLastError();
            return result;
        }
        struct LocalDescriptor { PSECURITY_DESCRIPTOR value; ~LocalDescriptor() { LocalFree(value); } } release{descriptor};
        BOOL present = FALSE, defaulted = FALSE, saclPresent = FALSE;
        PACL acl = nullptr, sacl = nullptr;
        PSID owner = nullptr, group = nullptr;
        const bool daclOnly = GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted)
            && GetSecurityDescriptorSacl(descriptor, &saclPresent, &sacl, &defaulted)
            && GetSecurityDescriptorOwner(descriptor, &owner, &defaulted)
            && GetSecurityDescriptorGroup(descriptor, &group, &defaulted)
            && present && !saclPresent && !owner && !group;
        if (!daclOnly) { result.kind = PermissionApplyResult::Kind::DaclOnly; return result; }
        result.requested = sddl(descriptor, DACL_SECURITY_INFORMATION);
        if (result.requested == request.original) { result.kind = PermissionApplyResult::Kind::Unchanged; return result; }
        Key key;
        result.status = openPermissionKey(request.target, READ_CONTROL | WRITE_DAC, &key);
        QByteArray current;
        if (result.status == ERROR_SUCCESS) result.status = readSecurity(key.value, &current);
        if (result.status != ERROR_SUCCESS) return result;
        if (current != request.baseline) { result.kind = PermissionApplyResult::Kind::Conflict; return result; }
        SECURITY_DESCRIPTOR_CONTROL control = 0;
        DWORD revision = 0;
        if (!GetSecurityDescriptorControl(descriptor, &control, &revision))
        {
            result.status = GetLastError();
            return result;
        }
        const SECURITY_INFORMATION parts = DACL_SECURITY_INFORMATION | ((control & SE_DACL_PROTECTED)
            ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
        result.status = RegSetKeySecurity(key.value, parts, descriptor);
        if (result.status != ERROR_SUCCESS) return result;
        result.submitted = true;
        result.actual = permissionSnapshot(key.value);
        result.status = result.actual.status;
        if (result.status != ERROR_SUCCESS) { result.kind = PermissionApplyResult::Kind::ReadBack; return result; }
        result.actual.writeStatus = ERROR_SUCCESS;
        result.kind = PermissionApplyResult::Kind::Applied;
        return result;
    }

    class PermissionsDialog final : public QDialog
    {
    public:
        PermissionsDialog(QWidget* parent, const QString& path, int viewBits)
            : QDialog(parent), m_path(path), m_view(viewBits == 32 ? KEY_WOW64_32KEY : viewBits == 64 ? KEY_WOW64_64KEY : 0)
        {
            setObjectName(QStringLiteral("registry_key_permissions"));
            setWindowTitle(trText(QStringLiteral("注册表键权限")));
            auto* rootLayout = new QVBoxLayout(this);
            // 注册表对象标识与业务页分开，两个 DACL 编辑器仅滚动各自正文。
            rootLayout->addWidget(ks::ui::CreateDetailSummaryHeader(this, windowTitle(), path));
            auto* content = new QWidget(this);
            auto* layout = new QVBoxLayout(content);
            layout->setContentsMargins(16, 16, 16, 16);
            layout->setSpacing(12);
            rootLayout->addWidget(content, 1);
            auto* scope = new QLabel(trText(QStringLiteral("Win32 权限 · %1 位视图 · Owner / Group 只读；仅编辑 DACL，不请求 SACL。"))
                .arg(viewBits == 32 ? 32 : viewBits == 64 ? 64 : static_cast<int>(sizeof(void*) * 8)), this);
            scope->setWordWrap(true);
            layout->addWidget(scope);
            auto* form = new QFormLayout;
            ks::ui::ConfigureDetailForm(form);
            m_owner = new QLineEdit(this);
            m_group = new QLineEdit(this);
            m_owner->setReadOnly(true);
            m_group->setReadOnly(true);
            ks::ui::StyleStandaloneInput(m_owner);
            ks::ui::StyleStandaloneInput(m_group);
            form->addRow(QStringLiteral("Owner SDDL"), m_owner);
            form->addRow(QStringLiteral("Group SDDL"), m_group);
            auto* identityCard = ks::ui::CreateDetailCard(QString(), content);
            qobject_cast<QVBoxLayout*>(identityCard->layout())->addLayout(form);
            layout->addWidget(identityCard);
            auto* originalCard = ks::ui::CreateDetailCard(trText(QStringLiteral("原始 DACL SDDL")), content);
            originalCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            // 原始 DACL 是系统返回的原始数据，禁止翻译或自动切换结构视图。
            m_original = new CodeEditorWidget(this);
            m_original->setObjectName(QStringLiteral("registry_original_dacl"));
            m_original->setReadOnly(true);
            m_original->setMinimumSize(0, 0);
            m_original->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
            qobject_cast<QVBoxLayout*>(originalCard->layout())->addWidget(m_original, 1);
            layout->addWidget(originalCard, 1);
            auto* requestedCard = ks::ui::CreateDetailCard(trText(QStringLiteral("新 DACL SDDL（只允许 D: 部分）")), content);
            requestedCard->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            // 新 DACL 使用相同内置编辑器；是否允许修改仍由 WRITE_DAC 校验决定。
            m_edit = new CodeEditorWidget(this);
            m_edit->setObjectName(QStringLiteral("registry_requested_dacl"));
            m_edit->setMinimumSize(0, 0);
            m_edit->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
            qobject_cast<QVBoxLayout*>(requestedCard->layout())->addWidget(m_edit, 1);
            layout->addWidget(requestedCard, 1);
            m_status = new QLabel(this);
            m_status->setTextFormat(Qt::PlainText);
            m_status->setWordWrap(true);
            layout->addWidget(m_status);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
            m_refresh = buttons->addButton(trText(QStringLiteral("重新读取")), QDialogButtonBox::ActionRole);
            m_apply = buttons->addButton(trText(QStringLiteral("应用 DACL")), QDialogButtonBox::ActionRole);
            ks::ui::NormalizeToolbarControl(m_refresh);
            ks::ui::NormalizeToolbarControl(m_apply);
            ks::ui::NormalizeToolbarControl(buttons->button(QDialogButtonBox::Close));
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
            connect(m_refresh, &QPushButton::clicked, this, [this] { reload(); });
            connect(m_apply, &QPushButton::clicked, this, [this] { apply(); });
            rootLayout->addWidget(buttons);
            ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(880, 680), QSize(460, 380));
            ks::ui::ApplyDetailDialogChrome(this);
            m_operation = std::make_unique<ks::ui::AsyncOperation>(this);
            m_operation->setStateChangedCallback([this] {
                if (m_busy && !m_operation->isBusy())
                {
                    m_baseline.clear();
                    m_writable = false;
                    setBusy(false);
                    setStatus(m_status, trText(QStringLiteral("权限操作未取得完整回执；请重新读取。")), ks::ui::StatusRole::Warning);
                }
            });
            reload();
        }
        ~PermissionsDialog() override { m_operation->close(); }

    private:

        void setBusy(const bool busy)
        {
            m_busy = busy;
            m_refresh->setEnabled(!busy);
            m_apply->setEnabled(!busy && m_writable && !m_baseline.isEmpty());
            m_edit->setReadOnly(busy || !m_writable);
        }
        void installSnapshot(const PermissionSnapshot& snapshot)
        {
            m_baseline = snapshot.baseline;
            m_owner->setText(snapshot.owner);
            m_group->setText(snapshot.group);
            m_original->setRawText(snapshot.dacl);
            m_edit->setRawText(snapshot.dacl);
            m_writable = snapshot.writeStatus == ERROR_SUCCESS && !snapshot.dacl.isEmpty();
        }
        void reload()
        {
            if (m_operation->isBusy()) return;
            setBusy(true);
            setStatus(m_status, trText(QStringLiteral("正在读取权限…")), ks::ui::StatusRole::Info);
            m_operation->submit<PermissionTarget, PermissionSnapshot>({m_path, m_view},
                [](const PermissionTarget& target, const ks::ui::AsyncOperationToken&) { return readPermissionSnapshot(target); },
                [this](const PermissionSnapshot& snapshot, std::uint64_t) {
                    if (snapshot.status != ERROR_SUCCESS)
                    {
                        m_baseline.clear();
                        m_writable = false;
                        m_owner->clear();
                        m_group->clear();
                        m_original->setRawText({});
                        setStatus(m_status, winError(snapshot.status), ks::ui::StatusRole::Error);
                    }
                    else
                    {
                        installSnapshot(snapshot);
                        setStatus(m_status, m_writable
                            ? trText(QStringLiteral("具备 WRITE_DAC；应用前重新读取原值，完成后回读 DACL。权限修改不支持草稿撤销。"))
                            : trText(QStringLiteral("仅可读取权限；WRITE_DAC 不可用：%1")).arg(winError(snapshot.writeStatus)),
                            m_writable ? ks::ui::StatusRole::Info : ks::ui::StatusRole::Warning);
                    }
                    setBusy(false);
                    return true;
                }, [this](std::exception_ptr) {
                    m_baseline.clear();
                    m_writable = false;
                    setBusy(false);
                    setStatus(m_status, winError(ERROR_UNHANDLED_EXCEPTION), ks::ui::StatusRole::Error);
                });
        }
        void apply()
        {
            if (m_operation->isBusy() || !m_writable || m_baseline.isEmpty()) return;
            const PermissionApplyRequest request{{m_path, m_view}, m_baseline, m_original->text(), m_edit->text().trimmed()};
            setBusy(true);
            setStatus(m_status, trText(QStringLiteral("正在应用 DACL…")), ks::ui::StatusRole::Info);
            const auto accepted = m_operation->submitTransaction<PermissionApplyRequest, PermissionApplyResult>(request,
                [](const PermissionApplyRequest& value) { return applyPermissionRequest(value); },
                [this](const PermissionApplyResult& result, std::uint64_t) {
                    using Kind = PermissionApplyResult::Kind;
                    QString message;
                    auto role = ks::ui::StatusRole::Error;
                    switch (result.kind)
                    {
                    case Kind::Nul: message = trText(QStringLiteral("DACL SDDL 不能包含 NUL。")); break;
                    case Kind::InvalidSddl: message = trText(QStringLiteral("DACL SDDL 无效：%1")).arg(winError(result.status)); break;
                    case Kind::DaclOnly: message = trText(QStringLiteral("只能提交 DACL；不能包含 Owner、Group 或 SACL。")); break;
                    case Kind::Unchanged: message = trText(QStringLiteral("DACL 与原值一致。")); role = ks::ui::StatusRole::Info; break;
                    case Kind::Conflict: message = trText(QStringLiteral("权限已被其他操作修改；请重新读取后再编辑。")); break;
                    case Kind::ReadBack:
                        m_baseline.clear();
                        m_writable = false;
                        message = trText(QStringLiteral("DACL 已提交，但回读失败：%1")).arg(winError(result.status));
                        role = ks::ui::StatusRole::Warning;
                        break;
                    case Kind::Applied:
                        installSnapshot(result.actual);
                        message = result.actual.dacl == result.requested ? trText(QStringLiteral("DACL 已应用并回读一致。"))
                            : trText(QStringLiteral("DACL 已提交，但回读内容与请求不同；已显示实际结果。"));
                        role = result.actual.dacl == result.requested ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning;
                        break;
                    case Kind::Access: message = winError(result.status); break;
                    }
                    setBusy(false);
                    setStatus(m_status, message, role);
                    return true;
                }, [this](std::exception_ptr) {
                    // A worker exception is not proof that an accepted write did not commit.
                    m_baseline.clear();
                    m_writable = false;
                    setBusy(false);
                    setStatus(m_status, trText(QStringLiteral("权限操作未取得完整回执；请重新读取。")), ks::ui::StatusRole::Warning);
                });
            if (!accepted)
            {
                setBusy(false);
                setStatus(m_status, winError(ERROR_OPERATION_ABORTED), ks::ui::StatusRole::Warning);
            }
        }
        QString m_path;
        REGSAM m_view = 0;
        QByteArray m_baseline;
        QLineEdit* m_owner = nullptr;
        QLineEdit* m_group = nullptr;
        CodeEditorWidget* m_original = nullptr; // 系统读取的原始 DACL，只读。
        CodeEditorWidget* m_edit = nullptr;     // 用户待提交 DACL，受 WRITE_DAC 控制。
        QLabel* m_status = nullptr;
        QPushButton* m_apply = nullptr;
        QPushButton* m_refresh = nullptr;
        bool m_writable = false;
        bool m_busy = false;
        std::unique_ptr<ks::ui::AsyncOperation> m_operation;
    };

    LSTATUS linkTraversalStatus(HKEY key)
    {
        DWORD type = 0, size = 0;
        const LSTATUS status = RegQueryValueExW(key, L"SymbolicLinkValue", nullptr, &type, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
        if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) return status;
        return type == REG_LINK ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    }

    using HiveValue = hive::Value;

    QString typeName(DWORD type)
    {
        switch (type)
        {
        case REG_SZ: return QStringLiteral("REG_SZ");
        case REG_EXPAND_SZ: return QStringLiteral("REG_EXPAND_SZ");
        case REG_MULTI_SZ: return QStringLiteral("REG_MULTI_SZ");
        case REG_DWORD: return QStringLiteral("REG_DWORD");
        case REG_DWORD_BIG_ENDIAN: return QStringLiteral("REG_DWORD_BIG_ENDIAN");
        case REG_QWORD: return QStringLiteral("REG_QWORD");
        case REG_BINARY: return QStringLiteral("REG_BINARY");
        case REG_NONE: return QStringLiteral("REG_NONE");
        default: return QString::number(type);
        }
    }

    QString preview(const HiveValue& value)
    {
        if (value.status != ERROR_SUCCESS) return winError(value.status);
        if (value.raw.isEmpty() && value.length > 0)
            return trText(QStringLiteral("按需读取（完整 %1 字节）")).arg(value.length);
        // Presentation only: edits always receive HiveValue::raw in full.
        const QByteArray sample = value.raw.left(64);
        return QString::fromLatin1(sample.toHex(' ')) + (sample.size() < value.length
            ? trText(QStringLiteral(" …（完整 %1 字节）")).arg(value.length) : QString());
    }

    class OfflineHiveDialog final : public QDialog
    {
    public:
        explicit OfflineHiveDialog(QWidget* parent) : QDialog(parent)
        {
            setObjectName(QStringLiteral("registry_offline_hive"));
            setWindowTitle(trText(QStringLiteral("离线 Hive 工作副本")));
            ks::ui::StyleSecondaryWindow(this);
            auto* layout = new QVBoxLayout(this);
            ks::ui::StyleSecondaryContentLayout(layout);
            layout->addWidget(ks::ui::CreateDetailSummaryHeader(this, windowTitle()));
            auto* notice = new QLabel(trText(QStringLiteral("选择现有 Hive 文件后复制到临时工作副本。编辑仅改变工作副本；使用“另存副本”导出，原文件不直接加载或修改。")), this);
            notice->setWordWrap(true);
            layout->addWidget(notice);
            auto* tools = new QHBoxLayout;
            m_open = new QPushButton(trText(QStringLiteral("打开 Hive")), this);
            m_save = new QPushButton(trText(QStringLiteral("另存副本")), this);
            m_newKey = new QPushButton(trText(QStringLiteral("新建子键")), this);
            m_deleteKey = new QPushButton(trText(QStringLiteral("删除空键")), this);
            tools->addWidget(m_open);
            tools->addWidget(m_newKey);
            tools->addWidget(m_deleteKey);
            tools->addStretch();
            ks::ui::NormalizeToolbarRow(tools);
            layout->addLayout(tools);
            m_source = new QLabel(this);
            m_source->setTextFormat(Qt::PlainText);
            m_source->setWordWrap(true);
            m_source->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(m_source);
            auto* split = new QSplitter(this);
            split->setChildrenCollapsible(false);
            m_tree = new QTreeWidget(split);
            m_tree->setMinimumWidth(0);
            m_tree->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
            m_tree->setProperty("ks_i18n_preserve_model_data", true);
            m_tree->setHeaderLabel(trText(QStringLiteral("离线键")));
            auto* right = new QWidget(split);
            m_valuePanel = right;
            auto* rightLayout = new QVBoxLayout(right);
            rightLayout->setContentsMargins(0, 0, 0, 0);
            m_values = new QTableWidget(right);
            m_values->setMinimumWidth(0);
            m_values->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
            // 离线 Hive 值表为工作副本编辑，不提供无意义的现场比较栏。
            ks::ui::SetTableActionBarMode(m_values, ks::ui::TableActionBarMode::Compact);
            m_values->setProperty("ks_i18n_preserve_model_data", true);
            m_values->setColumnCount(4);
            m_values->setHorizontalHeaderLabels({trText(QStringLiteral("名称")), trText(QStringLiteral("类型")),
                trText(QStringLiteral("字节数")), trText(QStringLiteral("数据预览"))});
            m_values->setSelectionBehavior(QAbstractItemView::SelectRows);
            m_values->setSelectionMode(QAbstractItemView::SingleSelection);
            m_values->setEditTriggers(QAbstractItemView::NoEditTriggers);
            m_values->horizontalHeader()->setStretchLastSection(true);
            rightLayout->addWidget(m_values, 1);
            auto* valueTools = new QHBoxLayout;
            m_newValue = new QPushButton(trText(QStringLiteral("新建值")), right);
            m_editValue = new QPushButton(trText(QStringLiteral("编辑值")), right);
            m_deleteValue = new QPushButton(trText(QStringLiteral("删除值")), right);
            m_moreValues = new QPushButton(trText(QStringLiteral("继续加载值")), right);
            valueTools->addWidget(m_newValue);
            valueTools->addWidget(m_editValue);
            valueTools->addWidget(m_deleteValue);
            valueTools->addWidget(m_moreValues);
            ks::ui::NormalizeToolbarRow(valueTools);
            rightLayout->addLayout(valueTools);
            split->setStretchFactor(0, 1);
            split->setStretchFactor(1, 3);
            layout->addWidget(split, 1);
            m_status = new QLabel(this);
            m_status->setTextFormat(Qt::PlainText);
            m_status->setWordWrap(true);
            layout->addWidget(m_status);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
            // 保存工作副本属于窗口级动作，和关闭一起固定在底部。
            buttons->addButton(m_save, QDialogButtonBox::ActionRole);
            ks::ui::StyleSecondaryButtonBox(buttons);
            ks::ui::StyleSecondaryFooter(buttons);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
            layout->addWidget(buttons);
            connect(m_open, &QPushButton::clicked, this, [this] { openFile(); });
            connect(m_save, &QPushButton::clicked, this, [this] { saveCopy(false); });
            connect(m_tree, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { loadChildren(item); });
            connect(m_tree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem* item) {
                if (item->data(0, kMoreRole).toBool()) loadChildren(item->parent(), true);
            });
            connect(m_tree, &QTreeWidget::currentItemChanged, this, [this] {
                refreshValues();
            });
            connect(m_moreValues, &QPushButton::clicked, this, [this] { loadValues(); });
            connect(m_newKey, &QPushButton::clicked, this, [this] { createKey(); });
            connect(m_deleteKey, &QPushButton::clicked, this, [this] { deleteKey(); });
            connect(m_newValue, &QPushButton::clicked, this, [this] { editValue(true); });
            connect(m_editValue, &QPushButton::clicked, this, [this] { editValue(false); });
            connect(m_deleteValue, &QPushButton::clicked, this, [this] { deleteValue(); });
            ks::ui::InstallKeyboardItemActivation(m_values);
            connect(m_values, &QTableWidget::cellDoubleClicked, this, [this] { editValue(false); });
            m_operation = std::make_unique<ks::ui::AsyncOperation>(this);
            m_operation->setStateChangedCallback([this] {
                if (m_busy && !m_receipt && !m_operation->isBusy()) finishWithoutReceipt();
            });
            m_lifecycle = new QTimer(this);
            m_lifecycle->setInterval(100);
            connect(m_lifecycle, &QTimer::timeout, this, [this] { pollCleanup(); });
            updateControls();
            setStatus(m_status, trText(QStringLiteral("尚未加载 Hive；RegLoadAppKey 的 ACL 限制会原样报告，不接管权限。")), ks::ui::StatusRole::Info);
            ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(1080, 740), QSize(560, 420));
        }
        ~OfflineHiveDialog() override
        {
            m_operation->close();
            m_session.reset();
        }
    protected:
        void reject() override { requestClose(); }
        void closeEvent(QCloseEvent* event) override
        {
            if (m_closeApproved) { QDialog::closeEvent(event); return; }
            event->ignore();
            requestClose();
        }
    private:
        struct Command
        {
            std::shared_ptr<hive::State> native;
            std::shared_ptr<hive::Session::Reservation> reservation;
            hive::Request request;
        };
        struct Projection
        {
            QPersistentModelIndex parent;
            std::shared_ptr<const hive::Result> result;
            QVector<QTreeWidgetItem*> detached;
            qsizetype cursor = 0;
            bool clearing = false;
            ~Projection() { qDeleteAll(detached); }
        };
        static QMessageBox::StandardButton question(QWidget* parent,const QString& title,const QString& text,
            QMessageBox::StandardButtons buttons=QMessageBox::Yes|QMessageBox::No,QMessageBox::StandardButton fallback=QMessageBox::No)
        {
            const QPointer<QMessageBox> box=new QMessageBox(QMessageBox::Question,title,text,buttons,parent);
            box->setDefaultButton(fallback);const auto answer=box->exec();if(box)delete box.data();
            return static_cast<QMessageBox::StandardButton>(answer);
        }
        static void warning(QWidget* parent,const QString& title,const QString& text)
        {
            const QPointer<QMessageBox> box=new QMessageBox(QMessageBox::Warning,title,text,QMessageBox::Ok,parent);
            box->exec();if(box)delete box.data();
        }
        static QString inputName(QWidget* parent,bool* accepted)
        {
            const QPointer<QInputDialog> dialog=new QInputDialog(parent);
            dialog->setWindowTitle(trText(QStringLiteral("新建离线子键")));
            dialog->setLabelText(trText(QStringLiteral("子键名称（保留空格）")));
            dialog->setInputMode(QInputDialog::TextInput);dialog->setTextEchoMode(QLineEdit::Normal);
            const auto answer=dialog->exec();const auto text=dialog?dialog->textValue():QString();
            *accepted=dialog && answer==QDialog::Accepted;if(dialog)delete dialog.data();return text;
        }
        bool busy() const { return m_busy || m_projecting; }
        bool ready() const { return m_session && !busy() && !m_closing && !m_recoveryNeeded; }
        QString currentPath() const
        {
            const auto* item = m_tree->currentItem();
            return !item || item->data(0, kMoreRole).toBool() ? QString() : item->data(0, kKeyPathRole).toString();
        }
        void updateControls()
        {
            const bool idle = !busy() && !m_closing && !m_recoveryNeeded;
            m_open->setEnabled(idle && !m_session);
            m_save->setEnabled(idle && m_session && !m_snapshot.copyPath.isEmpty());
            m_tree->setEnabled(idle && m_snapshot.loaded);
            m_values->setEnabled(idle && m_snapshot.loaded);
            m_valuePanel->setEnabled(idle && m_snapshot.loaded);
            for (auto* button : {m_newKey,m_deleteKey,m_newValue,m_editValue,m_deleteValue}) button->setEnabled(idle && m_snapshot.loaded);
            m_moreValues->setEnabled(idle && m_snapshot.loaded && m_moreAvailable);
        }
        hive::Request request(hive::Action action) const
        {
            hive::Request result;
            result.action = action;
            result.generation = m_snapshot.generation;
            result.path = currentPath();
            return result;
        }
        void finishIdle()
        {
            updateControls();
            if (busy()) return;
            if (m_closing) { pollCleanup(); return; }
            if (m_closeRequested) { continueClose(); return; }
            if (m_afterIdle.empty()) return;
            auto action = std::move(m_afterIdle.front());
            m_afterIdle.pop_front();
            QTimer::singleShot(0, this, [this, action = std::move(action)]() mutable {
                const QPointer<OfflineHiveDialog> guard(this);
                if (!busy() && !m_closing && !m_closeRequested) action();
                if (guard) finishIdle();
            });
        }
        void finishWithoutReceipt()
        {
            m_busy = false;
            m_recoveryNeeded = true;
            m_afterIdle.clear();
            setStatus(m_status, trText(QStringLiteral("离线 Hive 未取得完整回执；请关闭工作副本后重新打开。")), ks::ui::StatusRole::Warning);
            finishIdle();
        }
        bool submit(hive::Request value, bool transaction, std::function<void(const hive::Result&)> apply)
        {
            if (!ready()) return false;
            auto reservation = m_session->reserve();
            if (!reservation) { pollCleanup(); return false; }
            const Command command{m_session->native(),std::move(reservation),std::move(value)};
            m_busy = true;
            m_receipt = false;
            updateControls();
            setStatus(m_status, trText(QStringLiteral("正在处理离线 Hive…")), ks::ui::StatusRole::Info);
            auto accepted = [this, apply = std::move(apply)](const hive::Result& result, std::uint64_t) {
                m_receipt = true;
                auto receipt = std::make_shared<const hive::Result>(result);
                QTimer::singleShot(0, this, [this, receipt = std::move(receipt), apply]() {
                    m_snapshot = receipt->snapshot;
                    m_busy = false;
                    const QPointer<OfflineHiveDialog> guard(this);
                    if (!m_closing) apply(*receipt);
                    if (guard) finishIdle();
                });
                return true;
            };
            auto failed = [this](std::exception_ptr) {
                m_receipt = true;
                QTimer::singleShot(0, this, [this] { finishWithoutReceipt(); });
            };
            const auto ticket = transaction
                ? m_operation->submitTransaction<Command,hive::Result>(command,
                    [](const Command& frozen) { return hive::execute(*frozen.native,frozen.request); },std::move(accepted),std::move(failed))
                : m_operation->submit<Command,hive::Result>(command,
                    [](const Command& frozen,const ks::ui::AsyncOperationToken&) { return hive::execute(*frozen.native,frozen.request); },std::move(accepted),std::move(failed));
            if (!ticket) { m_busy = false; m_receipt = true; setStatus(m_status,winError(ERROR_OPERATION_ABORTED),ks::ui::StatusRole::Warning);pollCleanup();updateControls(); }
            return ticket != 0;
        }
        bool nativeOk(const hive::Result& result)
        {
            if (result.outcome == hive::Outcome::Ok) return true;
            QString message;
            switch(result.outcome)
            {
            case hive::Outcome::InvalidSource: message=trText(QStringLiteral("请选择现有文件；临时工作目录必须可用。"));break;
            case hive::Outcome::CopyFailed: message=trText(QStringLiteral("无法创建 Hive 工作副本。"));break;
            case hive::Outcome::LoadFailed: message=trText(QStringLiteral("工作副本加载失败（未绕过 ACL）：%1")).arg(winError(result.status));break;
            case hive::Outcome::InvalidTarget: message=trText(QStringLiteral("另存必须使用源文件和临时工作副本之外的路径。"));break;
            case hive::Outcome::FlushFailed: message=trText(QStringLiteral("工作副本刷新失败，未另存：%1")).arg(winError(result.status));break;
            case hive::Outcome::CloseFailed: message=trText(QStringLiteral("工作副本关闭失败，未另存：%1")).arg(winError(result.status));break;
            case hive::Outcome::SaveFailed: message=trText(QStringLiteral("另存失败；临时工作副本仍在：%1")).arg(result.snapshot.copyPath);break;
            case hive::Outcome::Conflict: message=trText(QStringLiteral("值已存在、已变化或无法复核；工作副本未写入。"));break;
            case hive::Outcome::AlreadyExists: message=trText(QStringLiteral("子键已存在；未替换现有键。"));break;
            case hive::Outcome::NotEmpty: message=trText(QStringLiteral("仅允许删除无子键、无值的空键；不执行递归删除。"));break;
            case hive::Outcome::InvalidName: message=trText(QStringLiteral("子键名称必须为 1 ～ 255 字符，不能包含反斜杠或 NUL。"));break;
            default: message=winError(result.status);break;
            }
            setStatus(m_status,message,ks::ui::StatusRole::Warning);
            return false;
        }
        void openFile()
        {
            if (m_session || busy()) return;
            const QPointer<OfflineHiveDialog> guard(this);
            const QString path=QFileDialog::getOpenFileName(this,trText(QStringLiteral("打开现有离线 Hive 文件")));
            if (!guard || path.isEmpty()) return;
            m_session=hive::Session::create();
            if (!m_session) { setStatus(m_status,winError(ERROR_OPERATION_ABORTED),ks::ui::StatusRole::Warning);return; }
            m_lifecycle->start();
            m_snapshot={};m_snapshot.generation=++m_generation;
            auto command=request(hive::Action::Open);command.source=path;
            submit(std::move(command),true,[this](const hive::Result& result) {
                if (!nativeOk(result)) { m_failedOpen=true;beginCleanup(false);return; }
                m_source->setText(trText(QStringLiteral("源文件：%1\n临时工作副本：%2")).arg(m_snapshot.originalPath,m_snapshot.copyPath));
                m_tree->clear();
                auto* root=new QTreeWidgetItem(m_tree,{trText(QStringLiteral("Hive 根"))});
                root->setData(0,kKeyPathRole,QString());root->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
                m_tree->setCurrentItem(root);root->setExpanded(true);
                setStatus(m_status,trText(QStringLiteral("工作副本已加载；符号链接不下探，树和值按每批 300 项加载。")),ks::ui::StatusRole::Success);
            });
        }
        void loadChildren(QTreeWidgetItem* item,bool more=false)
        {
            if (!item || !m_snapshot.loaded || item->data(0,kMoreRole).toBool() || (!more && item->data(0,kLoadedRole).toBool())) return;
            const QPersistentModelIndex identity(m_tree->indexFromItem(item));
            if (busy()) { m_afterIdle.emplace_back([this,identity,more] { if(identity.isValid())loadChildren(m_tree->itemFromIndex(identity),more); });return; }
            if (!ready()) return;
            auto command=request(hive::Action::Keys);command.path=item->data(0,kKeyPathRole).toString();command.next=more?item->data(0,kNextKeyRole).toUInt():0;
            submit(std::move(command),false,[this,identity,more](const hive::Result& result) {
                if (!identity.isValid()) return;
                if (result.outcome!=hive::Outcome::Ok && result.keys.isEmpty()) { nativeOk(result);return; }
                auto state=std::make_shared<Projection>();state->parent=identity;state->result=std::make_shared<const hive::Result>(result);state->clearing=!more;
                auto* parent=m_tree->itemFromIndex(identity);
                if(more && parent->childCount() && parent->child(parent->childCount()-1)->data(0,kMoreRole).toBool()) delete parent->takeChild(parent->childCount()-1);
                m_projecting=true;updateControls();projectChildren(std::move(state));
            });
        }
        void projectChildren(std::shared_ptr<Projection> state)
        {
            auto* parent=state->parent.isValid()?m_tree->itemFromIndex(state->parent):nullptr;
            QElapsedTimer budget;budget.start();int operations=0;
            while(operations<16 && budget.elapsed()<4)
            {
                if(!state->detached.isEmpty())
                {
                    auto* node=state->detached.last();
                    if(node->childCount())state->detached.push_back(node->takeChild(node->childCount()-1));
                    else {state->detached.removeLast();delete node;}
                }
                else if(state->clearing && parent && parent->childCount())state->detached.push_back(parent->takeChild(parent->childCount()-1));
                else if(state->clearing)state->clearing=false;
                else if(parent && !m_closing && state->cursor<state->result->keys.size())
                {
                    const auto& name=state->result->keys[state->cursor++];
                    auto* child=new QTreeWidgetItem(parent,{name});
                    child->setData(0,kKeyPathRole,state->result->path.isEmpty()?name:state->result->path+QLatin1Char('\\')+name);
                    child->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
                }
                else break;
                ++operations;
            }
            if(!state->detached.isEmpty() || state->clearing || (parent && !m_closing && state->cursor<state->result->keys.size()))
            {QTimer::singleShot(0,this,[this,state=std::move(state)]{projectChildren(state);});return;}
            if(parent && !m_closing)
            {
                parent->setData(0,kLoadedRole,true);parent->setData(0,kNextKeyRole,static_cast<quint32>(state->result->next));
                if(state->result->more){auto* more=new QTreeWidgetItem(parent,{trText(QStringLiteral("继续加载子键…"))});more->setData(0,kMoreRole,true);}
                if(parent->childCount()==0)parent->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
                nativeOk(*state->result);
            }
            m_projecting=false;finishIdle();
        }
        void refreshValues()
        {
            if (busy()) { const auto path=currentPath();m_afterIdle.emplace_back([this,path]{if(currentPath()==path)refreshValues();});return; }
            if (m_closing) return;
            m_projecting=true;m_moreAvailable=false;updateControls();clearValueRows();
        }
        void clearValueRows()
        {
            QElapsedTimer budget;budget.start();int rows=0;
            while(m_values->rowCount() && rows<16 && budget.elapsed()<4){m_values->removeRow(m_values->rowCount()-1);++rows;}
            if(m_values->rowCount()){QTimer::singleShot(0,this,[this]{clearValueRows();});return;}
            auto retired=std::make_shared<QVector<HiveValue>>();retired->swap(m_valueRows);
            QThreadPool::globalInstance()->start(QRunnable::create([retired=std::move(retired)]{}));
            m_valueNext=0;m_projecting=false;
            if(!m_closing && !m_closeRequested)loadValues();
            finishIdle();
        }
        void loadValues()
        {
            auto* item=m_tree->currentItem();
            if(!item || !m_snapshot.loaded || item->data(0,kMoreRole).toBool())return;
            if(busy()){const auto path=currentPath();m_afterIdle.emplace_back([this,path]{if(currentPath()==path)loadValues();});return;}
            if(!ready())return;
            auto command=request(hive::Action::Values);command.next=m_valueNext;
            const auto path=command.path;
            submit(std::move(command),false,[this,path](const hive::Result& result){
                if(currentPath()!=path)return;
                if(result.outcome!=hive::Outcome::Ok && result.values.isEmpty()){m_moreAvailable=false;nativeOk(result);return;}
                auto state=std::make_shared<Projection>();state->result=std::make_shared<const hive::Result>(result);
                m_projecting=true;updateControls();projectValues(std::move(state));
            });
        }
        void projectValues(std::shared_ptr<Projection> state)
        {
            QElapsedTimer budget;budget.start();int rows=0;
            while(!m_closing && state->cursor<state->result->values.size() && rows<16 && budget.elapsed()<4)
            {
                auto value=state->result->values[state->cursor++];const int row=m_values->rowCount();m_values->insertRow(row);
                auto* name=new QTableWidgetItem(value.name.isEmpty()?trText(QStringLiteral("（默认）")):value.name);
                name->setData(Qt::UserRole,static_cast<int>(m_valueRows.size()));m_values->setItem(row,0,name);
                m_values->setItem(row,1,new QTableWidgetItem(typeName(value.type)));m_values->setItem(row,2,new QTableWidgetItem(QString::number(value.length)));
                m_values->setItem(row,3,new QTableWidgetItem(preview(value)));value.raw.clear();m_valueRows.push_back(std::move(value));++rows;
            }
            if(!m_closing && state->cursor<state->result->values.size()){QTimer::singleShot(0,this,[this,state=std::move(state)]{projectValues(state);});return;}
            m_valueNext=state->result->next;m_moreAvailable=state->result->more;
            if(!m_closing)nativeOk(*state->result);
            m_projecting=false;finishIdle();
        }
        const HiveValue* selectedValue()const
        {
            const int row=m_values->currentRow();const auto* item=row>=0?m_values->item(row,0):nullptr;
            if(!item)return nullptr;const int index=item->data(Qt::UserRole).toInt();
            return index>=0 && index<m_valueRows.size()?&m_valueRows[index]:nullptr;
        }
        void editValue(bool create)
        {
            if(!ready() || !m_snapshot.loaded || !m_tree->currentItem() || m_tree->currentItem()->data(0,kMoreRole).toBool())return;
            const auto* selected=selectedValue();
            if(!create && (!selected || selected->status!=ERROR_SUCCESS))
            {setStatus(m_status,trText(QStringLiteral("请选择已完整读取的值；超过 32 MiB 或读取失败的值不能编辑。")),ks::ui::StatusRole::Warning);return;}
            const QString path=currentPath();
            if(create){auto probe=request(hive::Action::ProbeWrite);submit(std::move(probe),false,[this,path](const hive::Result& result){if(nativeOk(result) && currentPath()==path)showEditor(path,HiveValue{},true);});return;}
            auto command=request(hive::Action::ReadValue);command.name=selected->name;
            submit(std::move(command),false,[this,path](const hive::Result& result){if(nativeOk(result) && currentPath()==path)showEditor(path,result.value,false);});
        }
        void showEditor(const QString& path,const HiveValue& original,bool create)
        {
            if(!ready() || currentPath()!=path)return;
            const QPointer<OfflineHiveDialog> guard(this);const QPointer<QDialog> dialog=new QDialog(this);
            dialog->setWindowTitle(trText(create?QStringLiteral("新建离线 Hive 值"):QStringLiteral("编辑离线 Hive 值")));
            ks::ui::StyleSecondaryWindow(dialog);auto* layout=new QVBoxLayout(dialog);ks::ui::StyleSecondaryContentLayout(layout);
            auto* editor=new RegistryValueEditorWidget(dialog);editor->setValue(trText(QStringLiteral("离线 Hive"))+QLatin1Char('\\')+path,original.name,
                create?REG_SZ:original.type,create?QByteArray(2,'\0'):original.raw,create);layout->addWidget(editor,1);
            auto* buttons=new QDialogButtonBox(QDialogButtonBox::Save|QDialogButtonBox::Cancel,dialog);RegistryValueDraft draft;
            connect(buttons,&QDialogButtonBox::accepted,dialog,[&]{QString error;if(editor->value(&draft,&error))dialog->accept();else warning(dialog,trText(QStringLiteral("草稿无效")),error);});
            connect(buttons,&QDialogButtonBox::rejected,dialog,&QDialog::reject);ks::ui::StyleSecondaryButtonBox(buttons);ks::ui::StyleSecondaryFooter(buttons);layout->addWidget(buttons);
            ks::ui::applyResponsiveWindowGeometry(dialog,this,QSize(880,680),QSize(460,380));const auto answer=dialog->exec();if(dialog)delete dialog.data();
            if(!guard || answer!=QDialog::Accepted || !ready() || currentPath()!=path)return;
            auto command=request(create?hive::Action::CreateValue:hive::Action::UpdateValue);command.path=path;command.name=draft.name;command.original=original;command.type=draft.type;command.data=draft.data;
            submit(std::move(command),true,[this](const hive::Result& result){
                if(!nativeOk(result))return;refreshValues();
                setStatus(m_status,result.verified?trText(QStringLiteral("工作副本值已写入并回读一致；尚未另存。")):trText(QStringLiteral("工作副本写入已提交，但回读未一致；尚未另存。")),result.verified?ks::ui::StatusRole::Success:ks::ui::StatusRole::Warning);
            });
        }
        void deleteValue()
        {
            const auto* selected=selectedValue();if(!ready() || !selected || selected->status!=ERROR_SUCCESS)return;
            auto command=request(hive::Action::ReadValue);command.name=selected->name;const auto path=command.path;
            submit(std::move(command),false,[this,path](const hive::Result& result){
                if(!nativeOk(result) || currentPath()!=path)return;
                const auto original=result.value;const QPointer<OfflineHiveDialog> guard(this);
                const auto answer=question(this,trText(QStringLiteral("删除工作副本值")),trText(QStringLiteral("从工作副本删除值“%1”？原 Hive 文件不受影响。"))
                    .arg(original.name.isEmpty()?trText(QStringLiteral("（默认）")):original.name));
                if(!guard || answer!=QMessageBox::Yes || !ready() || currentPath()!=path)return;
                auto value=request(hive::Action::DeleteValue);value.path=path;value.name=original.name;value.original=original;
                submit(std::move(value),true,[this](const hive::Result& receipt){
                    if(!nativeOk(receipt))return;refreshValues();
                    setStatus(m_status,receipt.verified?trText(QStringLiteral("工作副本值已删除并复核；尚未另存。")):trText(QStringLiteral("工作副本删除已提交，但复核未确认；尚未另存。")),receipt.verified?ks::ui::StatusRole::Success:ks::ui::StatusRole::Warning);
                });
            });
        }
        void createKey()
        {
            if(!ready() || !m_snapshot.loaded || !m_tree->currentItem() || m_tree->currentItem()->data(0,kMoreRole).toBool())return;
            const auto path=currentPath();const QPersistentModelIndex identity(m_tree->indexFromItem(m_tree->currentItem()));const QPointer<OfflineHiveDialog> guard(this);bool accepted=false;
            const auto name=inputName(this,&accepted);
            if(!guard || !accepted || !ready() || currentPath()!=path)return;
            if(name.isEmpty() || name.size()>255 || name.contains(QLatin1Char('\\')) || name.contains(QChar(0)))
            {setStatus(m_status,trText(QStringLiteral("子键名称必须为 1 ～ 255 字符，不能包含反斜杠或 NUL。")),ks::ui::StatusRole::Error);return;}
            auto command=request(hive::Action::CreateKey);command.path=path;command.name=name;
            submit(std::move(command),true,[this,identity](const hive::Result& result){if(!nativeOk(result))return;if(identity.isValid()){auto* item=m_tree->itemFromIndex(identity);item->setData(0,kLoadedRole,false);loadChildren(item);}setStatus(m_status,trText(QStringLiteral("工作副本子键已创建；尚未另存。")),ks::ui::StatusRole::Success);});
        }
        void deleteKey()
        {
            if(!ready() || !m_snapshot.loaded || !m_tree->currentItem() || m_tree->currentItem()->data(0,kMoreRole).toBool() || currentPath().isEmpty())return;
            const QPersistentModelIndex identity(m_tree->indexFromItem(m_tree->currentItem()));auto command=request(hive::Action::DeleteKey);
            submit(std::move(command),true,[this,identity](const hive::Result& result){if(!nativeOk(result))return;if(identity.isValid()){auto* item=m_tree->itemFromIndex(identity);m_tree->setCurrentItem(item->parent());delete item;}setStatus(m_status,trText(QStringLiteral("工作副本空键已删除；尚未另存。")),ks::ui::StatusRole::Success);});
        }
        void saveCopy(bool closeAfter)
        {
            if(!ready() || m_snapshot.copyPath.isEmpty())return;
            const QPointer<OfflineHiveDialog> guard(this);const auto target=QFileDialog::getSaveFileName(this,trText(QStringLiteral("另存 Hive 副本")));
            if(!guard)return;
            if(target.isEmpty()){if(closeAfter)m_closeRequested=false;return;}
            if(!ready())return;
            auto command=request(hive::Action::SaveCopy);command.target=target;
            submit(std::move(command),true,[this,closeAfter](const hive::Result& result){
                if(!nativeOk(result)){if(closeAfter)m_closeRequested=false;return;}
                setStatus(m_status,result.reloadStatus==ERROR_SUCCESS?trText(QStringLiteral("Hive 副本已另存：%1")).arg(result.target)
                    :trText(QStringLiteral("副本已另存，但重新加载工作副本失败：%1")).arg(winError(result.reloadStatus)),result.reloadStatus==ERROR_SUCCESS?ks::ui::StatusRole::Success:ks::ui::StatusRole::Warning);
                if(closeAfter && result.published)beginCleanup(false);
            });
        }
        void requestClose()
        {
            if(m_closeApproved){QDialog::reject();return;}
            m_closeRequested=true;
            if(busy()){setStatus(m_status,trText(QStringLiteral("正在关闭离线 Hive；等待当前操作和资源清理完成。")),ks::ui::StatusRole::Info);return;}
            continueClose();
        }
        void continueClose()
        {
            if(!m_session){m_closeApproved=true;QDialog::reject();return;}
            if(m_closing){if(m_session->job()->hasFailed())m_session->stop(m_discardApproved);pollCleanup();return;}
            if(m_snapshot.dirty && !m_recoveryNeeded)
            {
                const QPointer<OfflineHiveDialog> guard(this);
                const auto answer=question(this,trText(QStringLiteral("未另存的 Hive 修改")),trText(QStringLiteral("工作副本有未另存修改。保存副本后关闭，或放弃这些修改？")),QMessageBox::Save|QMessageBox::Discard|QMessageBox::Cancel,QMessageBox::Cancel);
                if(!guard)return;
                if(answer==QMessageBox::Cancel){m_closeRequested=false;return;}
                if(answer==QMessageBox::Save){saveCopy(true);return;}
                beginCleanup(true);return;
            }
            beginCleanup(false);
        }
        void beginCleanup(bool discard)
        {
            if(!m_session)return;
            m_discardApproved=m_discardApproved||discard;m_closing=true;m_afterIdle.clear();updateControls();
            setStatus(m_status,trText(QStringLiteral("正在关闭离线 Hive；等待当前操作和资源清理完成。")),ks::ui::StatusRole::Info);
            m_session->stop(m_discardApproved);m_lifecycle->start();
        }
        void pollCleanup()
        {
            if(!m_session)return;
            const auto job=m_session->job();
            if(job->isCleanupRequested() && !m_closing){m_closing=true;m_closeRequested=true;m_afterIdle.clear();updateControls();}
            if(job->hasFailed() && m_reportedAttempt!=job->attemptCount())
            {
                m_reportedAttempt=job->attemptCount();const auto receipt=hive::cleanupReceipt(*m_session->native());
                setStatus(m_status,trText(QStringLiteral("离线 Hive 清理失败：%1；再次关闭或在退出提示中重试。")).arg(winError(receipt.status)),ks::ui::StatusRole::Warning);
            }
            if(!job->isComplete() || busy())return;
            const auto receipt=hive::cleanupReceipt(*m_session->native());m_lifecycle->stop();m_session.reset();m_snapshot.loaded=false;m_closing=false;
            if(receipt.retained)setStatus(m_status,trText(QStringLiteral("未另存的 Hive 工作副本已保留：%1")).arg(receipt.retainedPath),ks::ui::StatusRole::Warning);
            if(m_failedOpen){m_failedOpen=false;m_snapshot={};m_recoveryNeeded=false;updateControls();if(!m_closeRequested)return;}
            if(m_closeRequested){m_closeApproved=true;QDialog::reject();}
        }
        std::unique_ptr<ks::ui::AsyncOperation> m_operation;
        std::shared_ptr<hive::Session> m_session;
        hive::Snapshot m_snapshot;
        std::deque<std::function<void()>> m_afterIdle;
        bool m_busy=false,m_receipt=false,m_projecting=false,m_closing=false,m_recoveryNeeded=false;
        bool m_closeRequested=false,m_closeApproved=false,m_discardApproved=false,m_failedOpen=false,m_moreAvailable=false;
        quint64 m_generation=0,m_reportedAttempt=0;
        DWORD m_valueNext=0;
        QVector<HiveValue> m_valueRows;
        QWidget* m_valuePanel=nullptr;
        QTreeWidget* m_tree=nullptr;
        QTableWidget* m_values=nullptr;
        QLabel* m_source=nullptr;
        QLabel* m_status=nullptr;
        QPushButton* m_open=nullptr;
        QPushButton* m_save=nullptr;
        QPushButton* m_newKey=nullptr;
        QPushButton* m_deleteKey=nullptr;
        QPushButton* m_newValue=nullptr;
        QPushButton* m_editValue=nullptr;
        QPushButton* m_deleteValue=nullptr;
        QPushButton* m_moreValues=nullptr;
        QTimer* m_lifecycle=nullptr;
    };
}

void ShowRegistryKeyPermissions(QWidget* parent,const QString& path,int viewBits)
{
    const QPointer<PermissionsDialog> dialog=new PermissionsDialog(parent,path,viewBits);
    dialog->exec();if(dialog)delete dialog.data();
}
void ShowRegistryOfflineHive(QWidget* parent)
{
    const QPointer<OfflineHiveDialog> dialog=new OfflineHiveDialog(parent);
    dialog->exec();if(dialog)delete dialog.data();
}
