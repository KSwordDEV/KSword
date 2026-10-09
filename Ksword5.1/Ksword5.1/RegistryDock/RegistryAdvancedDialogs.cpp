#include "RegistryAdvancedDialogs.h"
#include "../UI/DetailDialogChrome.h"
#include "RegistryValueCodec.h"
#include "RegistryValueEditorWidget.h"
#include "../UI/CodeEditorWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/UI_All.h"

#include <QCloseEvent>
#include <QDialog>
#include <QDialogButtonBox>
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
    constexpr DWORD kMaximumValueBytes = 32 * 1024 * 1024;
    constexpr int kBatchRows = 300;
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

    class PermissionsDialog final : public QDialog
    {
    public:
        PermissionsDialog(QWidget* parent, const QString& path, int viewBits)
            : QDialog(parent), m_path(path), m_view(viewBits == 32 ? KEY_WOW64_32KEY : viewBits == 64 ? KEY_WOW64_64KEY : 0)
        {
            setObjectName(QStringLiteral("registry_key_permissions"));
            setWindowTitle(trText(QStringLiteral("注册表键权限")));
            auto* rootLayout = new QVBoxLayout(this);
            auto* content = new QWidget(this);
            auto* layout = new QVBoxLayout(content);
            layout->setContentsMargins(8, 8, 8, 8);
            layout->setSpacing(6);
            rootLayout->addWidget(content, 1);
            auto* address = new QLabel(path, this);
            address->setProperty("ks_i18n_preserve_data_text", true);
            address->setTextFormat(Qt::PlainText);
            address->setWordWrap(true);
            address->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(address);
            auto* scope = new QLabel(trText(QStringLiteral("Win32 权限 · %1 位视图 · Owner / Group 只读；仅编辑 DACL，不请求 SACL。"))
                .arg(viewBits == 32 ? 32 : viewBits == 64 ? 64 : static_cast<int>(sizeof(void*) * 8)), this);
            scope->setWordWrap(true);
            layout->addWidget(scope);
            auto* form = new QFormLayout;
            form->setRowWrapPolicy(QFormLayout::WrapLongRows);
            m_owner = new QLineEdit(this);
            m_group = new QLineEdit(this);
            m_owner->setReadOnly(true);
            m_group->setReadOnly(true);
            form->addRow(QStringLiteral("Owner SDDL"), m_owner);
            form->addRow(QStringLiteral("Group SDDL"), m_group);
            layout->addLayout(form);
            layout->addWidget(new QLabel(trText(QStringLiteral("原始 DACL SDDL")), this));
            // 原始 DACL 是系统返回的原始数据，禁止翻译或自动切换结构视图。
            m_original = new CodeEditorWidget(this);
            m_original->setObjectName(QStringLiteral("registry_original_dacl"));
            m_original->setReadOnly(true);
            layout->addWidget(m_original, 1);
            layout->addWidget(new QLabel(trText(QStringLiteral("新 DACL SDDL（只允许 D: 部分）")), this));
            // 新 DACL 使用相同内置编辑器；是否允许修改仍由 WRITE_DAC 校验决定。
            m_edit = new CodeEditorWidget(this);
            m_edit->setObjectName(QStringLiteral("registry_requested_dacl"));
            layout->addWidget(m_edit, 1);
            m_status = new QLabel(this);
            m_status->setTextFormat(Qt::PlainText);
            m_status->setWordWrap(true);
            layout->addWidget(m_status);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
            auto* refresh = buttons->addButton(trText(QStringLiteral("重新读取")), QDialogButtonBox::ActionRole);
            m_apply = buttons->addButton(trText(QStringLiteral("应用 DACL")), QDialogButtonBox::ActionRole);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
            connect(refresh, &QPushButton::clicked, this, [this] { reload(); });
            connect(m_apply, &QPushButton::clicked, this, [this] { apply(); });
            rootLayout->addWidget(buttons);
            ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(880, 680), QSize(460, 380));
            ks::ui::ApplyDetailDialogChrome(this);
            reload();
        }

    private:
        LSTATUS open(REGSAM access, Key* key)
        {
            HKEY root = nullptr;
            QString subkey;
            if (!parsePath(m_path, &root, &subkey)) return ERROR_INVALID_PARAMETER;
            Key current;
            LSTATUS status = RegOpenKeyExW(root, L"", REG_OPTION_OPEN_LINK,
                KEY_QUERY_VALUE | m_view | (subkey.isEmpty() ? access : 0), &current.value);
            if (status != ERROR_SUCCESS) return status;
            const QStringList parts = subkey.isEmpty() ? QStringList() : subkey.split(QLatin1Char('\\'), Qt::KeepEmptyParts);
            for (qsizetype i = 0; i < parts.size(); ++i)
            {
                if (parts[i].isEmpty()) return ERROR_INVALID_PARAMETER;
                status = linkTraversalStatus(current.value);
                if (status != ERROR_SUCCESS) return status;
                Key next;
                const REGSAM requested = KEY_QUERY_VALUE | m_view | (i + 1 == parts.size() ? access : 0);
                status = RegOpenKeyExW(current.value, wide(parts[i]), REG_OPTION_OPEN_LINK, requested, &next.value);
                if (status != ERROR_SUCCESS) return status;
                current = std::move(next);
            }
            status = linkTraversalStatus(current.value);
            if (status != ERROR_SUCCESS) return status;
            *key = std::move(current);
            return ERROR_SUCCESS;
        }
        void reload()
        {
            Key key;
            LSTATUS status = open(READ_CONTROL, &key);
            if (status == ERROR_SUCCESS) status = readSecurity(key.value, &m_baseline);
            if (status != ERROR_SUCCESS)
            {
                m_baseline.clear();
                m_apply->setEnabled(false);
                m_edit->setReadOnly(true);
                setStatus(m_status, winError(status), ks::ui::StatusRole::Error);
                return;
            }
            auto* descriptor = reinterpret_cast<PSECURITY_DESCRIPTOR>(m_baseline.data());
            m_owner->setText(sddl(descriptor, OWNER_SECURITY_INFORMATION));
            m_group->setText(sddl(descriptor, GROUP_SECURITY_INFORMATION));
            const QString original = sddl(descriptor, DACL_SECURITY_INFORMATION);
            m_original->setRawText(original);
            m_edit->setRawText(original);
            Key writable;
            const LSTATUS writeStatus = open(READ_CONTROL | WRITE_DAC, &writable);
            m_apply->setEnabled(writeStatus == ERROR_SUCCESS && !original.isEmpty());
            m_edit->setReadOnly(writeStatus != ERROR_SUCCESS);
            setStatus(m_status, writeStatus == ERROR_SUCCESS
                ? trText(QStringLiteral("具备 WRITE_DAC；应用前重新读取原值，完成后回读 DACL。权限修改不支持草稿撤销。"))
                : trText(QStringLiteral("仅可读取权限；WRITE_DAC 不可用：%1")).arg(winError(writeStatus)),
                writeStatus == ERROR_SUCCESS ? ks::ui::StatusRole::Info : ks::ui::StatusRole::Warning);
        }
        void apply()
        {
            const QString input = m_edit->text().trimmed();
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            if (input.contains(QChar(0)))
            {
                setStatus(m_status, trText(QStringLiteral("DACL SDDL 不能包含 NUL。")), ks::ui::StatusRole::Error);
                return;
            }
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(wide(input), SDDL_REVISION_1, &descriptor, nullptr))
            {
                setStatus(m_status, trText(QStringLiteral("DACL SDDL 无效：%1")).arg(winError(GetLastError())), ks::ui::StatusRole::Error);
                return;
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
            if (!daclOnly)
            {
                setStatus(m_status, trText(QStringLiteral("只能提交 DACL；不能包含 Owner、Group 或 SACL。")), ks::ui::StatusRole::Error);
                return;
            }
            const QString requested = sddl(descriptor, DACL_SECURITY_INFORMATION);
            if (requested == m_original->text())
            {
                setStatus(m_status, trText(QStringLiteral("DACL 与原值一致。")), ks::ui::StatusRole::Info);
                return;
            }
            Key key;
            LSTATUS status = open(READ_CONTROL | WRITE_DAC, &key);
            QByteArray current;
            if (status == ERROR_SUCCESS) status = readSecurity(key.value, &current);
            if (status != ERROR_SUCCESS || current != m_baseline)
            {
                setStatus(m_status, status != ERROR_SUCCESS ? winError(status)
                    : trText(QStringLiteral("权限已被其他操作修改；请重新读取后再编辑。")), ks::ui::StatusRole::Error);
                return;
            }
            SECURITY_DESCRIPTOR_CONTROL control = 0;
            DWORD revision = 0;
            if (!GetSecurityDescriptorControl(descriptor, &control, &revision))
            {
                setStatus(m_status, winError(GetLastError()), ks::ui::StatusRole::Error);
                return;
            }
            const SECURITY_INFORMATION parts = DACL_SECURITY_INFORMATION | ((control & SE_DACL_PROTECTED)
                ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION);
            status = RegSetKeySecurity(key.value, parts, descriptor);
            if (status != ERROR_SUCCESS)
            {
                setStatus(m_status, winError(status), ks::ui::StatusRole::Error);
                return;
            }
            QByteArray observed;
            status = readSecurity(key.value, &observed);
            if (status != ERROR_SUCCESS)
            {
                m_apply->setEnabled(false);
                setStatus(m_status, trText(QStringLiteral("DACL 已提交，但回读失败：%1")).arg(winError(status)), ks::ui::StatusRole::Warning);
                return;
            }
            m_baseline = observed;
            m_owner->setText(sddl(reinterpret_cast<PSECURITY_DESCRIPTOR>(observed.data()), OWNER_SECURITY_INFORMATION));
            m_group->setText(sddl(reinterpret_cast<PSECURITY_DESCRIPTOR>(observed.data()), GROUP_SECURITY_INFORMATION));
            const QString actual = sddl(reinterpret_cast<PSECURITY_DESCRIPTOR>(observed.data()), DACL_SECURITY_INFORMATION);
            m_original->setRawText(actual);
            m_edit->setRawText(actual);
            setStatus(m_status, actual == requested ? trText(QStringLiteral("DACL 已应用并回读一致。"))
                : trText(QStringLiteral("DACL 已提交，但回读内容与请求不同；已显示实际结果。")),
                actual == requested ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
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
    };

    LSTATUS linkTraversalStatus(HKEY key)
    {
        DWORD type = 0, size = 0;
        const LSTATUS status = RegQueryValueExW(key, L"SymbolicLinkValue", nullptr, &type, nullptr, &size);
        if (status == ERROR_FILE_NOT_FOUND) return ERROR_SUCCESS;
        if (status != ERROR_SUCCESS && status != ERROR_MORE_DATA) return status;
        return type == REG_LINK ? ERROR_ACCESS_DENIED : ERROR_SUCCESS;
    }

    // Each path component is opened as a link object, never followed. No child
    // HKEY escapes this stack. The application-hive root is the only anchor.
    LSTATUS openHiveKey(HKEY hive, const QString& path, REGSAM access, Key* result)
    {
        if (!hive || path.contains(QChar(0))) return ERROR_INVALID_PARAMETER;
        Key current;
        LSTATUS status = RegOpenKeyExW(hive, L"", REG_OPTION_OPEN_LINK,
            access | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &current.value);
        if (status != ERROR_SUCCESS) return status;
        if (!path.isEmpty())
        {
            for (const QString& part : path.split(QLatin1Char('\\'), Qt::KeepEmptyParts))
            {
                if (part.isEmpty()) return ERROR_INVALID_PARAMETER;
                status = linkTraversalStatus(current.value);
                if (status != ERROR_SUCCESS) return status;
                Key next;
                status = RegOpenKeyExW(current.value, wide(part), REG_OPTION_OPEN_LINK,
                    access | KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &next.value);
                if (status != ERROR_SUCCESS) return status;
                current = std::move(next);
            }
        }
        status = linkTraversalStatus(current.value);
        if (status != ERROR_SUCCESS) return status;
        *result = std::move(current);
        return ERROR_SUCCESS;
    }

    struct HiveValue
    {
        QString name;
        DWORD type = 0;
        QByteArray raw;
        qsizetype length = 0;
        LSTATUS status = ERROR_SUCCESS;
    };

    LSTATUS readHiveValue(HKEY key, const QString& name, DWORD* type, QByteArray* raw)
    {
        for (int attempt = 0; attempt < 3; ++attempt)
        {
            DWORD size = 0;
            LSTATUS status = RegQueryValueExW(key, wide(name), nullptr, type, nullptr, &size);
            if (status != ERROR_SUCCESS) return status;
            if (size > kMaximumValueBytes) return ERROR_FILE_TOO_LARGE;
            QByteArray bytes(size, '\0');
            status = RegQueryValueExW(key, wide(name), nullptr, type, reinterpret_cast<LPBYTE>(bytes.data()), &size);
            if (status == ERROR_MORE_DATA) continue;
            if (status != ERROR_SUCCESS) return status;
            if (size > static_cast<DWORD>(bytes.size())) return ERROR_MORE_DATA;
            bytes.resize(size);
            *raw = bytes;
            return ERROR_SUCCESS;
        }
        return ERROR_RETRY;
    }

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
        return QString::fromLatin1(sample.toHex(' ')) + (sample.size() < value.raw.size()
            ? trText(QStringLiteral(" …（完整 %1 字节）")).arg(value.raw.size()) : QString());
    }

    class OfflineHiveDialog final : public QDialog
    {
    public:
        explicit OfflineHiveDialog(QWidget* parent) : QDialog(parent)
        {
            setObjectName(QStringLiteral("registry_offline_hive"));
            setWindowTitle(trText(QStringLiteral("离线 Hive 工作副本")));
            auto* layout = new QVBoxLayout(this);
            auto* notice = new QLabel(trText(QStringLiteral("选择现有 Hive 文件后复制到临时工作副本。编辑仅改变工作副本；使用“另存副本”导出，原文件不直接加载或修改。")), this);
            notice->setWordWrap(true);
            layout->addWidget(notice);
            auto* tools = new QHBoxLayout;
            m_open = new QPushButton(trText(QStringLiteral("打开 Hive")), this);
            m_save = new QPushButton(trText(QStringLiteral("另存副本")), this);
            m_newKey = new QPushButton(trText(QStringLiteral("新建子键")), this);
            m_deleteKey = new QPushButton(trText(QStringLiteral("删除空键")), this);
            tools->addWidget(m_open);
            tools->addWidget(m_save);
            tools->addWidget(m_newKey);
            tools->addWidget(m_deleteKey);
            tools->addStretch();
            layout->addLayout(tools);
            m_source = new QLabel(this);
            m_source->setTextFormat(Qt::PlainText);
            m_source->setWordWrap(true);
            m_source->setTextInteractionFlags(Qt::TextSelectableByMouse);
            layout->addWidget(m_source);
            auto* split = new QSplitter(this);
            m_tree = new QTreeWidget(split);
            m_tree->setProperty("ks_i18n_preserve_model_data", true);
            m_tree->setHeaderLabel(trText(QStringLiteral("离线键")));
            auto* right = new QWidget(split);
            auto* rightLayout = new QVBoxLayout(right);
            rightLayout->setContentsMargins(0, 0, 0, 0);
            m_values = new QTableWidget(right);
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
            rightLayout->addLayout(valueTools);
            split->setStretchFactor(0, 1);
            split->setStretchFactor(1, 3);
            layout->addWidget(split, 1);
            m_status = new QLabel(this);
            m_status->setTextFormat(Qt::PlainText);
            m_status->setWordWrap(true);
            layout->addWidget(m_status);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, this);
            connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::close);
            layout->addWidget(buttons);
            connect(m_open, &QPushButton::clicked, this, [this] { openFile(); });
            connect(m_save, &QPushButton::clicked, this, [this] { saveCopy(); });
            connect(m_tree, &QTreeWidget::itemExpanded, this, [this](QTreeWidgetItem* item) { loadChildren(item); });
            connect(m_tree, &QTreeWidget::itemClicked, this, [this](QTreeWidgetItem* item) {
                if (item->data(0, kMoreRole).toBool()) loadChildren(item->parent(), true);
            });
            connect(m_tree, &QTreeWidget::currentItemChanged, this, [this] {
                m_valueNext = 0;
                m_valueRows.clear();
                m_values->setRowCount(0);
                loadValues();
            });
            connect(m_moreValues, &QPushButton::clicked, this, [this] { loadValues(); });
            connect(m_newKey, &QPushButton::clicked, this, [this] { createKey(); });
            connect(m_deleteKey, &QPushButton::clicked, this, [this] { deleteKey(); });
            connect(m_newValue, &QPushButton::clicked, this, [this] { editValue(true); });
            connect(m_editValue, &QPushButton::clicked, this, [this] { editValue(false); });
            connect(m_deleteValue, &QPushButton::clicked, this, [this] { deleteValue(); });
            connect(m_values, &QTableWidget::cellDoubleClicked, this, [this] { editValue(false); });
            enableLoaded(false);
            setStatus(m_status, trText(QStringLiteral("尚未加载 Hive；RegLoadAppKey 的 ACL 限制会原样报告，不接管权限。")), ks::ui::StatusRole::Info);
            ks::ui::applyResponsiveWindowGeometry(this, parent, QSize(1080, 740), QSize(560, 420));
        }
        ~OfflineHiveDialog() override { if (m_hive) RegCloseKey(m_hive); }

    protected:
        void reject() override
        {
            if (m_closeApproved || confirmClose()) QDialog::reject();
        }
        void closeEvent(QCloseEvent* event) override
        {
            if (!confirmClose()) { event->ignore(); return; }
            m_closeApproved = true;
            QDialog::closeEvent(event);
            m_closeApproved = false;
        }

    private:
        bool confirmClose()
        {
            if (!m_dirty) return true;
            const auto result = QMessageBox::question(this, trText(QStringLiteral("未另存的 Hive 修改")),
                trText(QStringLiteral("工作副本有未另存修改。保存副本后关闭，或放弃这些修改？")),
                QMessageBox::Save | QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
            return result == QMessageBox::Discard || (result == QMessageBox::Save && saveCopy());
        }
        QString currentPath() const
        {
            auto* item = m_tree->currentItem();
            if (!item || item->data(0, kMoreRole).toBool()) return {};
            return item->data(0, kKeyPathRole).toString();
        }
        void enableLoaded(bool loaded)
        {
            m_open->setEnabled(!loaded && !m_dirty);
            m_save->setEnabled(loaded || (m_dirty && !m_copyPath.isEmpty()));
            m_tree->setEnabled(loaded);
            m_values->setEnabled(loaded);
            for (auto* button : {m_newKey, m_deleteKey, m_newValue, m_editValue, m_deleteValue}) button->setEnabled(loaded);
            m_moreValues->setEnabled(false);
        }
        void openFile()
        {
            if (m_hive) return;
            const QString path = QFileDialog::getOpenFileName(this, trText(QStringLiteral("打开现有离线 Hive 文件")));
            if (path.isEmpty()) return;
            const QFileInfo source(path);
            if (!source.isFile() || !m_temp.isValid())
            {
                setStatus(m_status, trText(QStringLiteral("请选择现有文件；临时工作目录必须可用。")), ks::ui::StatusRole::Error);
                return;
            }
            m_originalPath = source.canonicalFilePath();
            // Unique per chosen source; never pass the source filename to the
            // registry API. A failed load leaves the user's original untouched.
            m_copyPath = m_temp.filePath(QStringLiteral("working-%1.hive").arg(++m_generation));
            if (!QFile::copy(m_originalPath, m_copyPath))
            {
                setStatus(m_status, trText(QStringLiteral("无法创建 Hive 工作副本。")), ks::ui::StatusRole::Error);
                return;
            }
            const LSTATUS status = RegLoadAppKeyW(wide(m_copyPath), &m_hive, KEY_READ | KEY_WRITE, REG_PROCESS_APPKEY, 0);
            if (status != ERROR_SUCCESS)
            {
                m_hive = nullptr;
                setStatus(m_status, trText(QStringLiteral("工作副本加载失败（未绕过 ACL）：%1")).arg(winError(status)), ks::ui::StatusRole::Error);
                return;
            }
            m_dirty = false;
            m_source->setText(trText(QStringLiteral("源文件：%1\n临时工作副本：%2")).arg(m_originalPath, m_copyPath));
            m_tree->clear();
            auto* root = new QTreeWidgetItem(m_tree, {trText(QStringLiteral("Hive 根"))});
            root->setData(0, kKeyPathRole, QString());
            root->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
            enableLoaded(true);
            m_tree->setCurrentItem(root);
            root->setExpanded(true);
            setStatus(m_status, trText(QStringLiteral("工作副本已加载；符号链接不下探，树和值按每批 300 项加载。")), ks::ui::StatusRole::Success);
        }
        void loadChildren(QTreeWidgetItem* item, bool more = false)
        {
            if (!item || !m_hive || item->data(0, kMoreRole).toBool() || (!more && item->data(0, kLoadedRole).toBool())) return;
            if (more && item->childCount() && item->child(item->childCount() - 1)->data(0, kMoreRole).toBool())
                delete item->takeChild(item->childCount() - 1);
            const QString path = item->data(0, kKeyPathRole).toString();
            Key key;
            const LSTATUS opened = openHiveKey(m_hive, path, KEY_READ, &key);
            if (opened != ERROR_SUCCESS)
            {
                item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
                setStatus(m_status, trText(QStringLiteral("键无法打开或已阻止符号链接：%1")).arg(winError(opened)), ks::ui::StatusRole::Warning);
                return;
            }
            DWORD index = more ? item->data(0, kNextKeyRole).toUInt() : 0;
            if (!more) qDeleteAll(item->takeChildren());
            for (int count = 0; count < kBatchRows; ++count, ++index)
            {
                std::array<wchar_t, 256> name{};
                DWORD length = static_cast<DWORD>(name.size());
                const LSTATUS status = RegEnumKeyExW(key.value, index, name.data(), &length, nullptr, nullptr, nullptr, nullptr);
                if (status != ERROR_SUCCESS)
                {
                    item->setData(0, kLoadedRole, true);
                    if (status != ERROR_NO_MORE_ITEMS) setStatus(m_status, winError(status), ks::ui::StatusRole::Warning);
                    if (item->childCount() == 0) item->setChildIndicatorPolicy(QTreeWidgetItem::DontShowIndicator);
                    return;
                }
                const QString childName = QString::fromWCharArray(name.data(), length);
                auto* child = new QTreeWidgetItem(item, {childName});
                child->setData(0, kKeyPathRole, path.isEmpty() ? childName : path + QLatin1Char('\\') + childName);
                child->setChildIndicatorPolicy(QTreeWidgetItem::ShowIndicator);
            }
            item->setData(0, kLoadedRole, true);
            item->setData(0, kNextKeyRole, static_cast<quint32>(index));
            auto* next = new QTreeWidgetItem(item, {trText(QStringLiteral("继续加载子键…"))});
            next->setData(0, kMoreRole, true);
        }
        void loadValues()
        {
            if (!m_hive || !m_tree->currentItem() || m_tree->currentItem()->data(0, kMoreRole).toBool()) return;
            Key key;
            const LSTATUS opened = openHiveKey(m_hive, currentPath(), KEY_READ, &key);
            if (opened != ERROR_SUCCESS)
            {
                setStatus(m_status, trText(QStringLiteral("键无法打开或已阻止符号链接：%1")).arg(winError(opened)), ks::ui::StatusRole::Warning);
                m_moreValues->setEnabled(false);
                return;
            }
            for (int count = 0; count < kBatchRows; ++count, ++m_valueNext)
            {
                std::array<wchar_t, 16384> name{};
                DWORD length = static_cast<DWORD>(name.size()), type = 0, dataLength = 0;
                const LSTATUS status = RegEnumValueW(key.value, m_valueNext, name.data(), &length, nullptr, &type, nullptr, &dataLength);
                if (status != ERROR_SUCCESS)
                {
                    m_moreValues->setEnabled(false);
                    if (status != ERROR_NO_MORE_ITEMS) setStatus(m_status, winError(status), ks::ui::StatusRole::Warning);
                    return;
                }
                HiveValue value;
                value.name = QString::fromWCharArray(name.data(), length);
                value.type = type;
                value.length = dataLength;
                if (dataLength > kMaximumValueBytes) value.status = ERROR_FILE_TOO_LARGE;
                else if (dataLength <= 64 * 1024)
                {
                    value.status = readHiveValue(key.value, value.name, &value.type, &value.raw);
                    if (value.status == ERROR_SUCCESS) value.length = value.raw.size();
                }
                const int row = m_values->rowCount();
                m_values->insertRow(row);
                auto* nameItem = new QTableWidgetItem(value.name.isEmpty() ? trText(QStringLiteral("（默认）")) : value.name);
                nameItem->setData(Qt::UserRole, static_cast<int>(m_valueRows.size()));
                m_values->setItem(row, 0, nameItem);
                m_values->setItem(row, 1, new QTableWidgetItem(typeName(value.type)));
                m_values->setItem(row, 2, new QTableWidgetItem(QString::number(value.length)));
                m_values->setItem(row, 3, new QTableWidgetItem(preview(value)));
                // Keep bounded metadata in the list. The editor obtains its
                // immutable full baseline on demand, never this preview.
                value.raw.clear();
                m_valueRows.push_back(std::move(value));
            }
            m_moreValues->setEnabled(true);
        }
        void refreshValues()
        {
            m_valueNext = 0;
            m_valueRows.clear();
            m_values->setRowCount(0);
            loadValues();
        }
        const HiveValue* selectedValue() const
        {
            const int row = m_values->currentRow();
            const auto* item = row >= 0 ? m_values->item(row, 0) : nullptr;
            if (!item) return nullptr;
            const int index = item->data(Qt::UserRole).toInt();
            return index >= 0 && index < m_valueRows.size() ? &m_valueRows[index] : nullptr;
        }
        void editValue(bool create)
        {
            if (!m_hive || !m_tree->currentItem() || m_tree->currentItem()->data(0, kMoreRole).toBool()) return;
            const HiveValue* selected = selectedValue();
            if (!create && (!selected || selected->status != ERROR_SUCCESS))
            {
                setStatus(m_status, trText(QStringLiteral("请选择已完整读取的值；超过 32 MiB 或读取失败的值不能编辑。")), ks::ui::StatusRole::Warning);
                return;
            }
            HiveValue original = create ? HiveValue{} : *selected;
            const QString path = currentPath();
            Key key;
            LSTATUS status = openHiveKey(m_hive, path, KEY_READ | KEY_SET_VALUE, &key);
            if (status == ERROR_SUCCESS && !create)
                status = readHiveValue(key.value, original.name, &original.type, &original.raw);
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            QDialog dialog(this);
            dialog.setWindowTitle(trText(create ? QStringLiteral("新建离线 Hive 值") : QStringLiteral("编辑离线 Hive 值")));
            auto* layout = new QVBoxLayout(&dialog);
            auto* editor = new RegistryValueEditorWidget(&dialog);
            editor->setValue(trText(QStringLiteral("离线 Hive")) + QLatin1Char('\\') + path, original.name,
                create ? REG_SZ : original.type, create ? QByteArray(2, '\0') : original.raw, create);
            layout->addWidget(editor, 1);
            auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel, &dialog);
            RegistryValueDraft draft;
            connect(buttons, &QDialogButtonBox::accepted, &dialog, [&] {
                QString error;
                if (editor->value(&draft, &error)) dialog.accept();
                else QMessageBox::warning(&dialog, trText(QStringLiteral("草稿无效")), error);
            });
            connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
            layout->addWidget(buttons);
            ks::ui::applyResponsiveWindowGeometry(&dialog, this, QSize(880, 680), QSize(460, 380));
            if (dialog.exec() != QDialog::Accepted) return;
            DWORD currentType = 0;
            QByteArray current;
            status = readHiveValue(key.value, draft.name, &currentType, &current);
            if ((create && status != ERROR_FILE_NOT_FOUND) || (!create
                && (status != ERROR_SUCCESS || currentType != original.type || current != original.raw)))
            {
                setStatus(m_status, trText(QStringLiteral("值已存在、已变化或无法复核；工作副本未写入。")), ks::ui::StatusRole::Error);
                return;
            }
            status = RegSetValueExW(key.value, wide(draft.name), 0, draft.type,
                reinterpret_cast<const BYTE*>(draft.data.constData()), static_cast<DWORD>(draft.data.size()));
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            m_dirty = true;
            status = readHiveValue(key.value, draft.name, &currentType, &current);
            const bool verified = status == ERROR_SUCCESS && currentType == draft.type && current == draft.data;
            refreshValues();
            setStatus(m_status, verified ? trText(QStringLiteral("工作副本值已写入并回读一致；尚未另存。"))
                : trText(QStringLiteral("工作副本写入已提交，但回读未一致；尚未另存。")),
                verified ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
        }
        void deleteValue()
        {
            const HiveValue* selected = selectedValue();
            if (!m_hive || !selected || selected->status != ERROR_SUCCESS) return;
            HiveValue original = *selected;
            const QString path = currentPath();
            Key key;
            LSTATUS status = openHiveKey(m_hive, path, KEY_READ | KEY_SET_VALUE, &key);
            if (status == ERROR_SUCCESS) status = readHiveValue(key.value, original.name, &original.type, &original.raw);
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            if (QMessageBox::question(this, trText(QStringLiteral("删除工作副本值")),
                trText(QStringLiteral("从工作副本删除值“%1”？原 Hive 文件不受影响。"))
                    .arg(original.name.isEmpty() ? trText(QStringLiteral("（默认）")) : original.name)) != QMessageBox::Yes) return;
            DWORD type = 0;
            QByteArray raw;
            if (status == ERROR_SUCCESS) status = readHiveValue(key.value, original.name, &type, &raw);
            if (status != ERROR_SUCCESS || type != original.type || raw != original.raw)
            {
                setStatus(m_status, trText(QStringLiteral("值已变化或无法复核；工作副本未删除。")), ks::ui::StatusRole::Error);
                return;
            }
            status = RegDeleteValueW(key.value, wide(original.name));
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            m_dirty = true;
            status = readHiveValue(key.value, original.name, &type, &raw);
            refreshValues();
            setStatus(m_status, status == ERROR_FILE_NOT_FOUND ? trText(QStringLiteral("工作副本值已删除并复核；尚未另存。"))
                : trText(QStringLiteral("工作副本删除已提交，但复核未确认；尚未另存。")),
                status == ERROR_FILE_NOT_FOUND ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
        }
        void createKey()
        {
            if (!m_hive || !m_tree->currentItem() || m_tree->currentItem()->data(0, kMoreRole).toBool()) return;
            const QString path = currentPath();
            bool accepted = false;
            const QString name = QInputDialog::getText(this, trText(QStringLiteral("新建离线子键")),
                trText(QStringLiteral("子键名称（保留空格）")), QLineEdit::Normal, QString(), &accepted);
            if (!accepted) return;
            if (name.isEmpty() || name.size() > 255 || name.contains(QLatin1Char('\\')) || name.contains(QChar(0)))
            {
                setStatus(m_status, trText(QStringLiteral("子键名称必须为 1 ～ 255 字符，不能包含反斜杠或 NUL。")), ks::ui::StatusRole::Error);
                return;
            }
            Key parent, created;
            LSTATUS status = openHiveKey(m_hive, path, KEY_READ | KEY_CREATE_SUB_KEY, &parent);
            DWORD disposition = 0;
            if (status == ERROR_SUCCESS) status = RegCreateKeyExW(parent.value, wide(name), 0, nullptr,
                REG_OPTION_NON_VOLATILE, KEY_READ | KEY_WRITE, nullptr, &created.value, &disposition);
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            if (disposition != REG_CREATED_NEW_KEY)
            {
                setStatus(m_status, trText(QStringLiteral("子键已存在；未替换现有键。")), ks::ui::StatusRole::Warning);
                return;
            }
            m_dirty = true;
            auto* item = m_tree->currentItem();
            item->setData(0, kLoadedRole, false);
            loadChildren(item);
            setStatus(m_status, trText(QStringLiteral("工作副本子键已创建；尚未另存。")), ks::ui::StatusRole::Success);
        }
        void deleteKey()
        {
            if (!m_hive || !m_tree->currentItem() || m_tree->currentItem()->data(0, kMoreRole).toBool()) return;
            const QString path = currentPath();
            if (path.isEmpty()) return;
            const qsizetype slash = path.lastIndexOf(QLatin1Char('\\'));
            const QString parentPath = slash < 0 ? QString() : path.left(slash);
            const QString name = slash < 0 ? path : path.mid(slash + 1);
            Key parent;
            LSTATUS status = openHiveKey(m_hive, parentPath, KEY_READ | KEY_WRITE, &parent);
            DWORD children = 0, values = 0;
            {
                Key key;
                if (status == ERROR_SUCCESS) status = openHiveKey(m_hive, path, KEY_READ | DELETE, &key);
                if (status == ERROR_SUCCESS) status = RegQueryInfoKeyW(key.value, nullptr, nullptr, nullptr,
                    &children, nullptr, nullptr, &values, nullptr, nullptr, nullptr, nullptr);
            }
            if (status != ERROR_SUCCESS || children || values)
            {
                setStatus(m_status, status != ERROR_SUCCESS ? winError(status)
                    : trText(QStringLiteral("仅允许删除无子键、无值的空键；不执行递归删除。")), ks::ui::StatusRole::Warning);
                return;
            }
            status = RegDeleteKeyExW(parent.value, wide(name), 0, 0);
            if (status != ERROR_SUCCESS) { setStatus(m_status, winError(status), ks::ui::StatusRole::Error); return; }
            m_dirty = true;
            auto* item = m_tree->currentItem();
            auto* parentItem = item->parent();
            m_tree->setCurrentItem(parentItem);
            delete item;
            setStatus(m_status, trText(QStringLiteral("工作副本空键已删除；尚未另存。")), ks::ui::StatusRole::Success);
        }
        bool saveCopy()
        {
            if (m_copyPath.isEmpty() || (!m_hive && !QFile::exists(m_copyPath))) return false;
            const QString target = QFileDialog::getSaveFileName(this, trText(QStringLiteral("另存 Hive 副本")));
            if (target.isEmpty()) return false;
            const QFileInfo destination(target);
            const QString resolved = destination.exists() ? destination.canonicalFilePath() : destination.absoluteFilePath();
            if (resolved.compare(m_originalPath, Qt::CaseInsensitive) == 0
                || resolved.compare(QFileInfo(m_copyPath).canonicalFilePath(), Qt::CaseInsensitive) == 0)
            {
                setStatus(m_status, trText(QStringLiteral("另存必须使用源文件和临时工作副本之外的路径。")), ks::ui::StatusRole::Error);
                return false;
            }
            LSTATUS status = m_hive ? RegFlushKey(m_hive) : ERROR_SUCCESS;
            if (status != ERROR_SUCCESS)
            {
                setStatus(m_status, trText(QStringLiteral("工作副本刷新失败，未另存：%1")).arg(winError(status)), ks::ui::StatusRole::Error);
                return false;
            }
            // No subordinate HKEY is retained between user actions. Closing
            // this final handle unloads the application hive before file I/O.
            status = m_hive ? RegCloseKey(m_hive) : ERROR_SUCCESS;
            if (status != ERROR_SUCCESS)
            {
                setStatus(m_status, trText(QStringLiteral("工作副本关闭失败，未另存：%1")).arg(winError(status)), ks::ui::StatusRole::Error);
                return false;
            }
            m_hive = nullptr;
            enableLoaded(false);
            bool copied = false;
            QFile input(m_copyPath);
            QSaveFile output(target);
            if (input.open(QIODevice::ReadOnly) && output.open(QIODevice::WriteOnly))
            {
                copied = true;
                while (!input.atEnd())
                {
                    const QByteArray block = input.read(1024 * 1024);
                    if (input.error() != QFileDevice::NoError || block.isEmpty() || output.write(block) != block.size())
                    {
                        copied = false;
                        break;
                    }
                }
                if (copied) copied = output.commit();
            }
            input.close();
            status = RegLoadAppKeyW(wide(m_copyPath), &m_hive, KEY_READ | KEY_WRITE, REG_PROCESS_APPKEY, 0);
            if (status != ERROR_SUCCESS) m_hive = nullptr;
            if (copied) m_dirty = false;
            enableLoaded(status == ERROR_SUCCESS);
            setStatus(m_status, !copied ? trText(QStringLiteral("另存失败；临时工作副本仍在：%1")).arg(m_copyPath)
                : status == ERROR_SUCCESS ? trText(QStringLiteral("Hive 副本已另存：%1")).arg(target)
                : trText(QStringLiteral("副本已另存，但重新加载工作副本失败：%1")).arg(winError(status)),
                copied && status == ERROR_SUCCESS ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
            return copied;
        }
        QTemporaryDir m_temp;
        HKEY m_hive = nullptr;
        QString m_originalPath;
        QString m_copyPath;
        bool m_dirty = false;
        bool m_closeApproved = false;
        quint64 m_generation = 0;
        DWORD m_valueNext = 0;
        QVector<HiveValue> m_valueRows;
        QTreeWidget* m_tree = nullptr;
        QTableWidget* m_values = nullptr;
        QLabel* m_source = nullptr;
        QLabel* m_status = nullptr;
        QPushButton* m_open = nullptr;
        QPushButton* m_save = nullptr;
        QPushButton* m_newKey = nullptr;
        QPushButton* m_deleteKey = nullptr;
        QPushButton* m_newValue = nullptr;
        QPushButton* m_editValue = nullptr;
        QPushButton* m_deleteValue = nullptr;
        QPushButton* m_moreValues = nullptr;
    };
}

void ShowRegistryKeyPermissions(QWidget* parent, const QString& path, int viewBits)
{
    PermissionsDialog dialog(parent, path, viewBits);
    dialog.exec();
}

void ShowRegistryOfflineHive(QWidget* parent)
{
    OfflineHiveDialog dialog(parent);
    dialog.exec();
}
