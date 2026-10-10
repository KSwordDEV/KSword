#include "PrivilegeDock.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "PrivilegeAccountPages.h"
#include "PrivilegeTokenPages.h"
#include "PrivilegeAccessPage.h"
#include "PrivilegeSnapshotPage.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"
#include "../Internationalization/LanguageManager.h"
#include "../Framework/PrivilegeElevationPrompt.h"

// ============================================================
// PrivilegeDock.cpp
// 作用：
// 1) 实现本地账号管理（创建用户、重置密码）；
// 2) 枚举用户/组/当前进程权限，用于权限审计；
// 3) 所有敏感操作均要求二次确认并写入日志。
// ============================================================

#include "../theme.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QDateTime>
#include <QEvent>
#include <QFormLayout>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPushButton>
#include <QPointer>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <string>
#include <vector>
#include <functional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Lm.h>

#pragma comment(lib, "Netapi32.lib")

namespace
{
    QString privilegeText(const char* const key, const QString& sourceText)
    {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    }

    std::string privilegeLogText(const char* const key, const QString& sourceText)
    {
        return privilegeText(key, sourceText).toStdString();
    }

    // blueButtonStyle 作用：
    // - 统一按钮风格，保证权限页视觉与其他 Dock 一致。
    QString blueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    // blueInputStyle 作用：
    // - 账号表单使用可辨认的中性实底，边界只在焦点时强调。
    QString blueInputStyle()
    {
        return QStringLiteral(
            "QLineEdit{border:1px solid %2;border-radius:5px;background:%3;color:%4;padding:2px 8px;}"
            "QLineEdit:focus{border:1px solid %1;}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::TextPrimaryHex());
    }

    // tableHeaderStyle 作用：
    // - 统一账号表头样式，保证深浅色模式可读性。
    QString tableHeaderStyle()
    {
        return QStringLiteral("QHeaderView::section{color:%1;background:%2;border:0;border-bottom:1px solid %3;font-weight:500;padding:4px 8px;}")
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::BorderHex());
    }

    // boolText 作用：
    // - 把布尔状态统一转换成“是/否”中文文本。
    QString boolText(const bool value)
    {
        return value
            ? privilegeText("privilege.bool.yes", QStringLiteral("是"))
            : privilegeText("privilege.bool.no", QStringLiteral("否"));
    }

    QString privilegeTableMenuStyle()
    {
        // 输入：无。
        // 处理：生成不透明菜单样式，保持账号/权限表右键菜单在深浅色主题下可读。
        // 返回：QMenu 样式表文本。
        return QStringLiteral(
            "QMenu{background:%1;color:%2;border:1px solid %3;}"
            "QMenu::item{padding:5px 24px 5px 24px;background:transparent;}"
            "QMenu::item:selected{background:%4;color:%6;}"
            "QMenu::item:disabled{color:%5;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::TextSecondaryHex())
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    void copyPrivilegeTableCurrentRow(QTableWidget* table)
    {
        // 输入：账号表或权限表。
        // 处理：读取当前显示行的所有列，按 TSV 复制到剪贴板。
        // 返回：无返回值；表格/剪贴板不可用或无当前行时不做动作。
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join(QChar('\t')));
    }

    void installPrivilegeTableCopyMenu(QTableWidget* table)
    {
        // 输入：需要复制当前行能力的账号/权限表。
        // 处理：安装只读右键菜单；右键某行时先选中对应单元格。
        // 返回：无返回值；不会触发账号创建、密码重置或权限调整。
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition) {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
            }

            QMenu menu(table);
            menu.setStyleSheet(privilegeTableMenuStyle());
            QAction* copyRowAction = menu.addAction(privilegeText(
                "privilege.menu.copy_row", QStringLiteral("复制当前行")));
            copyRowAction->setEnabled(table->currentRow() >= 0);
            if (menu.exec(table->viewport()->mapToGlobal(localPosition)) == copyRowAction)
            {
                copyPrivilegeTableCurrentRow(table);
            }
        });
    }

    // A factory runs only when its page is first selected. The placeholder owns its content.
    QWidget* addWorkbenchPage(QTabWidget* tabs, const char* key, const QString& title,
        std::function<QWidget*(QWidget*)> factory)
    {
        auto* holder = new QWidget(tabs);
        holder->setObjectName(QString::fromLatin1(key));
        auto* layout = new QVBoxLayout(holder);
        layout->setContentsMargins(0, 0, 0, 0);
        holder->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        tabs->addTab(holder, title);
        ks::i18n::LanguageManager::instance().bindTab(tabs, holder, QString::fromLatin1(key), title);
        QObject::connect(tabs, &QTabWidget::currentChanged, holder, [tabs, holder, layout, factory](int index) {
            if (tabs->widget(index) != holder || holder->property("ks_privilege_loaded").toBool()) return;
            holder->setProperty("ks_privilege_loaded", true);
            QWidget* content = factory(holder);
            holder->setProperty("ks_privilege_content", QVariant::fromValue(static_cast<QObject*>(content)));
            layout->addWidget(content);
        });
        return holder;
    }
}

PrivilegeDock::PrivilegeDock(QWidget* parent)
    : QWidget(parent)
{
    kLogEvent event;
    info << event
        << privilegeLogText("privilege.log.construct.start", QStringLiteral("[PrivilegeDock] 构造开始。"))
        << eol;

    initializeUi();
    initializeConnections();

    info << event
        << privilegeLogText("privilege.log.construct.completed", QStringLiteral("[PrivilegeDock] 构造完成。"))
        << eol;
}

void PrivilegeDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);

    if (m_initialRefreshDone)
    {
        return;
    }

    m_initialRefreshDone = true;
    if (m_accountStatusLabel != nullptr)
    {
        m_accountStatusLabel->setText(privilegeText(
            "privilege.account.status.first_load",
            QStringLiteral("状态：首次打开，正在加载账号列表...")));
    }
    if (m_permissionStatusLabel != nullptr)
    {
        m_permissionStatusLabel->setText(privilegeText(
            "privilege.permission.status.first_load",
            QStringLiteral("状态：首次打开，正在加载权限快照...")));
    }

    QTimer::singleShot(0, this, [this]()
        {
            refreshLocalUserList();
            refreshPermissionSnapshot();
        });
}

void PrivilegeDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr || event->type() != QEvent::LanguageChange)
    {
        return;
    }

    applyTranslatedHeaders();
    refreshLocalUserTable();
    refreshPermissionSnapshot();
}

void PrivilegeDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setTabPosition(QTabWidget::West);
    ks::ui::StylePageTabs(m_tabWidget);
    m_rootLayout->addWidget(m_tabWidget, 1);

    initializeAccountTab();
    // Keep existing create/reset tools together with the full account manager.
    m_tabWidget->removeTab(0);
    auto* accounts = new QWidget(m_tabWidget);
    auto* accountLayout = new QVBoxLayout(accounts);
    accountLayout->setContentsMargins(0, 0, 0, 0);
    auto* accountTabs = new QTabWidget(accounts);
    ks::ui::StylePageTabs(accountTabs);
    accountLayout->addWidget(accountTabs);
    auto* manager = ks::privilege::createAccountManagementPage(accountTabs,
        [this](const QString& target, const QString& account) {
            const QString name = QStringLiteral("privilege.workbench.tab.") + target;
            QWidget* holder = m_tabWidget->findChild<QWidget*>(name, Qt::FindDirectChildrenOnly);
            // QTabWidget reparents pages to its stacked widget; select by stable object name.
            if (!holder)
                for (int index = 0; index < m_tabWidget->count(); ++index)
                    if (m_tabWidget->widget(index)->objectName() == name) { holder = m_tabWidget->widget(index); break; }
            if (!holder) return;
            m_tabWidget->setCurrentWidget(holder);
            QWidget* content = qobject_cast<QWidget*>(holder->property("ks_privilege_content").value<QObject*>());
            if (target == QLatin1String("groups")) ks::privilege::selectGroupAccount(content, account);
            else if (target == QLatin1String("rights")) ks::privilege::selectRightsAccount(content, account);
            else if (target == QLatin1String("sessions")) ks::privilege::focusSessionsAccount(content, account);
        });
    accountTabs->addTab(manager, QStringLiteral("账号管理"));
    accountTabs->addTab(m_accountPage, QStringLiteral("创建与重置"));
    auto& language = ks::i18n::LanguageManager::instance();
    language.bindTab(accountTabs, manager, QStringLiteral("privilege.workbench.tab.account_manager"), QStringLiteral("账号管理"));
    language.bindTab(accountTabs, m_accountPage, QStringLiteral("privilege.workbench.tab.account_tools"), QStringLiteral("创建与重置"));
    m_tabWidget->addTab(accounts, QStringLiteral("账号"));
    language.bindTab(m_tabWidget, accounts, QStringLiteral("privilege.tab.accounts"), QStringLiteral("账号"));
    initializePermissionTab();
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.groups", QStringLiteral("用户组"), ks::privilege::createGroupsPage);
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.rights", QStringLiteral("权限分配"), ks::privilege::createRightsPage);
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.tokens", QStringLiteral("令牌对比"), ks::privilege::createTokenComparePage);
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.access", QStringLiteral("访问诊断"), ks::privilege::createAccessDiagnosticPage);
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.sessions", QStringLiteral("登录会话"), [](QWidget* parent) {
        return ks::privilege::createSessionsPage(parent, [](DWORD pid, quint64 creationTime) {
            ks::ui::OpenProcessDetailByIdentity(pid, creationTime);
        });
    });
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.launch", QStringLiteral("指定身份启动"), ks::privilege::createIdentityLaunchPage);
    addWorkbenchPage(m_tabWidget, "privilege.workbench.tab.snapshots", QStringLiteral("权限快照"), ks::privilege::createPermissionSnapshotPage);
}

void PrivilegeDock::initializeAccountTab()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    m_accountPage = new QWidget(m_tabWidget);
    m_accountLayout = new QVBoxLayout(m_accountPage);
    m_accountLayout->setContentsMargins(4, 4, 4, 4);
    m_accountLayout->setSpacing(6);

    m_accountToolbarLayout = new QHBoxLayout();
    m_accountToolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_accountToolbarLayout->setSpacing(6);

    m_accountRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_accountPage);
    languageManager.bindToolTip(
        m_accountRefreshButton,
        QStringLiteral("privilege.account.refresh.tooltip"),
        QStringLiteral("刷新本地账号列表"));
    m_accountRefreshButton->setStyleSheet(blueButtonStyle());
    m_accountRefreshButton->setFixedWidth(34);

    m_accountStatusLabel = new QLabel(privilegeText(
        "privilege.account.status.pending", QStringLiteral("状态：待刷新")), m_accountPage);
    m_accountToolbarLayout->addWidget(m_accountRefreshButton, 0);
    m_accountToolbarLayout->addWidget(m_accountStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(m_accountToolbarLayout);
    m_accountLayout->addLayout(m_accountToolbarLayout, 0);

    m_accountTable = new ks::ui::VisibleTableWidget(m_accountPage);
    // 创建/重置页的账户表是表单选取辅助，避免占用两组表单高度。
    ks::ui::SetTableActionBarMode(m_accountTable, ks::ui::TableActionBarMode::Compact);
    m_accountTable->setColumnCount(4);
    applyTranslatedHeaders();
    m_accountTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_accountTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_accountTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_accountTable->horizontalHeader()->setStyleSheet(tableHeaderStyle());
    m_accountTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_accountTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_accountTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_accountTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    installPrivilegeTableCopyMenu(m_accountTable);
    m_accountLayout->addWidget(m_accountTable, 1);

    // 新建用户输入区：包含用户名、密码、确认密码。
    QFormLayout* createLayout = new QFormLayout();
    // 组内保持紧凑，两个不同账号动作之间额外留白，避免误读为连续步骤。
    createLayout->setVerticalSpacing(8);
    createLayout->setHorizontalSpacing(12);
    m_createUserNameEdit = new QLineEdit(m_accountPage);
    m_createPasswordEdit = new QLineEdit(m_accountPage);
    m_createPasswordConfirmEdit = new QLineEdit(m_accountPage);
    m_createPasswordEdit->setEchoMode(QLineEdit::Password);
    m_createPasswordConfirmEdit->setEchoMode(QLineEdit::Password);
    languageManager.bindPlaceholder(
        m_createUserNameEdit,
        QStringLiteral("privilege.account.create.username.placeholder"),
        QStringLiteral("输入新用户名"));
    languageManager.bindPlaceholder(
        m_createPasswordEdit,
        QStringLiteral("privilege.account.create.password.placeholder"),
        QStringLiteral("输入密码"));
    languageManager.bindPlaceholder(
        m_createPasswordConfirmEdit,
        QStringLiteral("privilege.account.create.confirm_password.placeholder"),
        QStringLiteral("再次输入密码"));
    m_createUserNameEdit->setStyleSheet(blueInputStyle());
    m_createPasswordEdit->setStyleSheet(blueInputStyle());
    m_createPasswordConfirmEdit->setStyleSheet(blueInputStyle());
    QLabel* createUserLabel = new QLabel(QStringLiteral("新用户"), m_accountPage);
    QLabel* createPasswordLabel = new QLabel(QStringLiteral("密码"), m_accountPage);
    QLabel* createConfirmPasswordLabel = new QLabel(QStringLiteral("确认密码"), m_accountPage);
    languageManager.bindText(createUserLabel, QStringLiteral("privilege.account.create.username.label"), QStringLiteral("新用户"));
    languageManager.bindText(createPasswordLabel, QStringLiteral("privilege.account.create.password.label"), QStringLiteral("密码"));
    languageManager.bindText(createConfirmPasswordLabel, QStringLiteral("privilege.account.create.confirm_password.label"), QStringLiteral("确认密码"));
    createLayout->addRow(createUserLabel, m_createUserNameEdit);
    createLayout->addRow(createPasswordLabel, m_createPasswordEdit);
    createLayout->addRow(createConfirmPasswordLabel, m_createPasswordConfirmEdit);
    m_accountLayout->addLayout(createLayout, 0);

    m_createUserButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), m_accountPage);
    languageManager.bindToolTip(
        m_createUserButton,
        QStringLiteral("privilege.account.create.tooltip"),
        QStringLiteral("创建本地用户（会弹出二次确认）"));
    m_createUserButton->setStyleSheet(blueButtonStyle());
    m_createUserButton->setFixedWidth(34);
    ks::ui::NormalizeToolbarControl(m_createUserButton);
    m_accountLayout->addWidget(m_createUserButton, 0, Qt::AlignLeft);
    m_accountLayout->addSpacing(12);

    // 重置密码输入区：支持指定账号并确认密码。
    QFormLayout* resetLayout = new QFormLayout();
    resetLayout->setVerticalSpacing(8);
    resetLayout->setHorizontalSpacing(12);
    m_resetUserNameEdit = new QLineEdit(m_accountPage);
    m_resetPasswordEdit = new QLineEdit(m_accountPage);
    m_resetPasswordConfirmEdit = new QLineEdit(m_accountPage);
    m_resetPasswordEdit->setEchoMode(QLineEdit::Password);
    m_resetPasswordConfirmEdit->setEchoMode(QLineEdit::Password);
    languageManager.bindPlaceholder(
        m_resetUserNameEdit,
        QStringLiteral("privilege.account.reset.username.placeholder"),
        QStringLiteral("输入要重置密码的用户名"));
    languageManager.bindPlaceholder(
        m_resetPasswordEdit,
        QStringLiteral("privilege.account.reset.password.placeholder"),
        QStringLiteral("输入新密码"));
    languageManager.bindPlaceholder(
        m_resetPasswordConfirmEdit,
        QStringLiteral("privilege.account.reset.confirm_password.placeholder"),
        QStringLiteral("再次输入新密码"));
    m_resetUserNameEdit->setStyleSheet(blueInputStyle());
    m_resetPasswordEdit->setStyleSheet(blueInputStyle());
    m_resetPasswordConfirmEdit->setStyleSheet(blueInputStyle());
    QLabel* resetUserLabel = new QLabel(QStringLiteral("目标用户"), m_accountPage);
    QLabel* resetPasswordLabel = new QLabel(QStringLiteral("新密码"), m_accountPage);
    QLabel* resetConfirmPasswordLabel = new QLabel(QStringLiteral("确认新密码"), m_accountPage);
    languageManager.bindText(resetUserLabel, QStringLiteral("privilege.account.reset.username.label"), QStringLiteral("目标用户"));
    languageManager.bindText(resetPasswordLabel, QStringLiteral("privilege.account.reset.password.label"), QStringLiteral("新密码"));
    languageManager.bindText(resetConfirmPasswordLabel, QStringLiteral("privilege.account.reset.confirm_password.label"), QStringLiteral("确认新密码"));
    resetLayout->addRow(resetUserLabel, m_resetUserNameEdit);
    resetLayout->addRow(resetPasswordLabel, m_resetPasswordEdit);
    resetLayout->addRow(resetConfirmPasswordLabel, m_resetPasswordConfirmEdit);
    m_accountLayout->addLayout(resetLayout, 0);

    m_resetPasswordButton = new QPushButton(QIcon(":/Icon/process_priority.svg"), QString(), m_accountPage);
    languageManager.bindToolTip(
        m_resetPasswordButton,
        QStringLiteral("privilege.account.reset.tooltip"),
        QStringLiteral("重置用户密码（会弹出二次确认）"));
    m_resetPasswordButton->setStyleSheet(blueButtonStyle());
    m_resetPasswordButton->setFixedWidth(34);
    ks::ui::NormalizeToolbarControl(m_resetPasswordButton);
    m_accountLayout->addWidget(m_resetPasswordButton, 0, Qt::AlignLeft);
    // 账号和密码输入均为单行表单，采用与查询工具一致的触达高度。
    for (QLineEdit* edit : {m_createUserNameEdit, m_createPasswordEdit,
        m_createPasswordConfirmEdit, m_resetUserNameEdit, m_resetPasswordEdit,
        m_resetPasswordConfirmEdit})
    {
        ks::ui::NormalizeToolbarControl(edit);
    }

    m_tabWidget->addTab(m_accountPage, QStringLiteral("账号"));
    languageManager.bindTab(
        m_tabWidget,
        m_accountPage,
        QStringLiteral("privilege.tab.accounts"),
        QStringLiteral("账号"));
}

void PrivilegeDock::initializePermissionTab()
{
    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    m_permissionPage = new QWidget(m_tabWidget);
    m_permissionLayout = new QVBoxLayout(m_permissionPage);
    m_permissionLayout->setContentsMargins(4, 4, 4, 4);
    m_permissionLayout->setSpacing(6);

    m_permissionToolbarLayout = new QHBoxLayout();
    m_permissionToolbarLayout->setContentsMargins(0, 0, 0, 0);
    m_permissionToolbarLayout->setSpacing(6);

    m_permissionRefreshButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_permissionPage);
    languageManager.bindToolTip(
        m_permissionRefreshButton,
        QStringLiteral("privilege.permission.refresh.tooltip"),
        QStringLiteral("刷新用户/组/权限快照"));
    m_permissionRefreshButton->setStyleSheet(blueButtonStyle());
    m_permissionRefreshButton->setFixedWidth(34);

    m_permissionStatusLabel = new QLabel(privilegeText(
        "privilege.permission.status.pending", QStringLiteral("状态：待刷新")), m_permissionPage);
    m_permissionToolbarLayout->addWidget(m_permissionRefreshButton, 0);
    m_permissionToolbarLayout->addWidget(m_permissionStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(m_permissionToolbarLayout);
    m_permissionLayout->addLayout(m_permissionToolbarLayout, 0);

    m_permissionTable = new ks::ui::VisibleTableWidget(m_permissionPage);
    // 权限页为可刷新清单，保留现场前后对比。
    ks::ui::SetTableActionBarMode(m_permissionTable, ks::ui::TableActionBarMode::Full);
    m_permissionTable->setColumnCount(4);
    applyTranslatedHeaders();
    m_permissionTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_permissionTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_permissionTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_permissionTable->setWordWrap(false);
    m_permissionTable->horizontalHeader()->setStyleSheet(tableHeaderStyle());
    m_permissionTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_permissionTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_permissionTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_permissionTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::Stretch);
    installPrivilegeTableCopyMenu(m_permissionTable);
    m_permissionLayout->addWidget(m_permissionTable, 1);

    m_tabWidget->addTab(m_permissionPage, QStringLiteral("权限"));
    languageManager.bindTab(
        m_tabWidget,
        m_permissionPage,
        QStringLiteral("privilege.tab.permissions"),
        QStringLiteral("权限"));
}

void PrivilegeDock::applyTranslatedHeaders()
{
    if (m_accountTable != nullptr)
    {
        m_accountTable->setHorizontalHeaderLabels({
            privilegeText("privilege.account.header.username", QStringLiteral("用户名")),
            privilegeText("privilege.account.header.full_name", QStringLiteral("全名")),
            privilegeText("privilege.account.header.disabled", QStringLiteral("已禁用")),
            privilegeText("privilege.account.header.last_logon", QStringLiteral("最后登录"))
            });
    }
    if (m_permissionTable != nullptr)
    {
        m_permissionTable->setHorizontalHeaderLabels({
            privilegeText("privilege.permission.header.type", QStringLiteral("类型")),
            privilegeText("privilege.permission.header.name", QStringLiteral("名称")),
            privilegeText("privilege.permission.header.status", QStringLiteral("状态")),
            privilegeText("privilege.permission.header.detail", QStringLiteral("详情"))
            });
    }
}

void PrivilegeDock::initializeConnections()
{
    connect(m_accountRefreshButton, &QPushButton::clicked, this, [this]() {
        refreshLocalUserList();
    });
    connect(m_permissionRefreshButton, &QPushButton::clicked, this, [this]() {
        refreshPermissionSnapshot();
    });
    connect(m_createUserButton, &QPushButton::clicked, this, [this]() {
        createUserByInputs();
    });
    connect(m_resetPasswordButton, &QPushButton::clicked, this, [this]() {
        resetPasswordByInputs();
    });
    connect(m_accountTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        const int row = m_accountTable->currentRow();
        if (row < 0 || m_accountTable->item(row, 0) == nullptr)
        {
            return;
        }
        m_resetUserNameEdit->setText(m_accountTable->item(row, 0)->text());
    });
}

void PrivilegeDock::refreshLocalUserList()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-local-user-refresh"),
            {m_accountTable, m_permissionTable},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshLocalUserList();
                }
            }))
    {
        return;
    }

    // accountEvent 复用整条刷新日志链路。
    kLogEvent accountEvent;
    info << accountEvent
        << privilegeLogText(
            "privilege.log.refresh_users.start",
            QStringLiteral("[PrivilegeDock] 开始刷新本地用户列表。"))
        << eol;

    m_localUserList.clear();

    DWORD level = 2;
    DWORD preferedLength = MAX_PREFERRED_LENGTH;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0;
    DWORD resumeHandle = 0;
    LPUSER_INFO_2 userInfo = nullptr;

    const NET_API_STATUS enumStatus = ::NetUserEnum(
        nullptr,
        level,
        FILTER_NORMAL_ACCOUNT,
        reinterpret_cast<LPBYTE*>(&userInfo),
        preferedLength,
        &entriesRead,
        &totalEntries,
        &resumeHandle);
    if (enumStatus != NERR_Success && enumStatus != ERROR_MORE_DATA)
    {
        const QString errorText = winErrorText(enumStatus);
        err << accountEvent
            << privilegeLogText(
                "privilege.log.refresh_users.failed",
                QStringLiteral("[PrivilegeDock] 刷新用户失败, status="))
            << enumStatus
            << ", error="
            << errorText.toStdString()
            << eol;
        m_accountStatusLabel->setText(privilegeText(
            "privilege.account.status.refresh_failed",
            QStringLiteral("状态：刷新失败 - %1")).arg(errorText));
        if (userInfo != nullptr)
        {
            ::NetApiBufferFree(userInfo);
        }
        refreshLocalUserTable();
        return;
    }

    for (DWORD index = 0; index < entriesRead; ++index)
    {
        const USER_INFO_2& infoData = userInfo[index];
        LocalUserEntry entry;
        entry.name = infoData.usri2_name != nullptr
            ? QString::fromWCharArray(infoData.usri2_name)
            : QStringLiteral("<null>");
        entry.fullName = infoData.usri2_full_name != nullptr
            ? QString::fromWCharArray(infoData.usri2_full_name)
            : QString();
        entry.disabled = (infoData.usri2_flags & UF_ACCOUNTDISABLE) != 0;
        entry.lastLogonText = fileTimeToDateTimeText(infoData.usri2_last_logon);
        m_localUserList.push_back(entry);
    }

    if (userInfo != nullptr)
    {
        ::NetApiBufferFree(userInfo);
    }

    refreshLocalUserTable();
    m_accountStatusLabel->setText(privilegeText(
        "privilege.account.status.loaded",
        QStringLiteral("状态：已加载 %1 / %2 个账号"))
        .arg(entriesRead)
        .arg(totalEntries));

    info << accountEvent
        << privilegeLogText(
            "privilege.log.refresh_users.completed",
            QStringLiteral("[PrivilegeDock] 用户列表刷新完成, entriesRead="))
        << entriesRead
        << ", totalEntries="
        << totalEntries
        << eol;
}

void PrivilegeDock::refreshLocalUserTable()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-local-user-table-rebuild"),
            {m_accountTable},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshLocalUserTable();
                }
            }))
    {
        return;
    }

    m_accountTable->setRowCount(static_cast<int>(m_localUserList.size()));
    for (int row = 0; row < static_cast<int>(m_localUserList.size()); ++row)
    {
        const LocalUserEntry& entry = m_localUserList[static_cast<std::size_t>(row)];
        m_accountTable->setItem(row, 0, new QTableWidgetItem(entry.name));
        m_accountTable->setItem(row, 1, new QTableWidgetItem(entry.fullName));
        m_accountTable->setItem(row, 2, new QTableWidgetItem(boolText(entry.disabled)));
        m_accountTable->setItem(row, 3, new QTableWidgetItem(entry.lastLogonText));
    }
}

bool PrivilegeDock::createLocalUser(
    const QString& userName,
    const QString& passwordText,
    QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::wstring userNameW = userName.toStdWString();
    std::wstring passwordW = passwordText.toStdWString();

    USER_INFO_1 userInfo{};
    userInfo.usri1_name = const_cast<wchar_t*>(userNameW.c_str());
    userInfo.usri1_password = const_cast<wchar_t*>(passwordW.c_str());
    userInfo.usri1_priv = USER_PRIV_USER;
    userInfo.usri1_flags = UF_SCRIPT;

    DWORD paramError = 0;
    const NET_API_STATUS status = ::NetUserAdd(
        nullptr,
        1,
        reinterpret_cast<LPBYTE>(&userInfo),
        &paramError);
    if (status != NERR_Success)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = privilegeText(
                "privilege.error.net_user_add",
                QStringLiteral("NetUserAdd失败: %1, 参数索引=%2"))
                .arg(winErrorText(status))
                .arg(paramError);
        }
        return false;
    }
    return true;
}

bool PrivilegeDock::resetLocalUserPassword(
    const QString& userName,
    const QString& newPassword,
    QString* errorTextOut)
{
    if (errorTextOut != nullptr)
    {
        errorTextOut->clear();
    }

    std::wstring passwordW = newPassword.toStdWString();
    USER_INFO_1003 userInfo{};
    userInfo.usri1003_password = const_cast<wchar_t*>(passwordW.c_str());

    const NET_API_STATUS status = ::NetUserSetInfo(
        nullptr,
        reinterpret_cast<LPCWSTR>(userName.utf16()),
        1003,
        reinterpret_cast<LPBYTE>(&userInfo),
        nullptr);
    if (status != NERR_Success)
    {
        if (errorTextOut != nullptr)
        {
            *errorTextOut = privilegeText(
                "privilege.error.net_user_set_info",
                QStringLiteral("NetUserSetInfo失败: %1")).arg(winErrorText(status));
        }
        return false;
    }
    return true;
}

void PrivilegeDock::createUserByInputs()
{
    const QString userName = m_createUserNameEdit->text().trimmed();
    const QString password = m_createPasswordEdit->text();
    const QString confirmPassword = m_createPasswordConfirmEdit->text();

    if (userName.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.username_empty", QStringLiteral("用户名不能为空。")));
        return;
    }
    if (password.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.password_empty", QStringLiteral("密码不能为空。")));
        return;
    }
    if (password != confirmPassword)
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
            privilegeText("privilege.dialog.create.password_mismatch", QStringLiteral("两次密码输入不一致。")));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("创建本地用户"));
        return;
    }

    // 二次确认：避免误触导致系统新增账号。
    const int confirm = QMessageBox::question(
        this,
        privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
        privilegeText(
            "privilege.dialog.create.confirm",
            QStringLiteral("确定创建本地用户“%1”吗？")).arg(userName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirm != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    info << actionEvent
        << privilegeLogText(
            "privilege.log.create_user.request",
            QStringLiteral("[PrivilegeDock] 创建用户请求, user="))
        << userName.toStdString()
        << eol;

    QString errorText;
    if (!createLocalUser(userName, password, &errorText))
    {
        err << actionEvent
            << privilegeLogText(
                "privilege.log.create_user.failed",
                QStringLiteral("[PrivilegeDock] 创建用户失败, user="))
            << userName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        // privilegePromptHandled：提权恢复提示已展示时跳过旧的创建失败弹窗。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("创建本地用户"),
            errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
                errorText);
        }
        return;
    }

    info << actionEvent
        << privilegeLogText(
            "privilege.log.create_user.succeeded",
            QStringLiteral("[PrivilegeDock] 创建用户成功, user="))
        << userName.toStdString()
        << eol;
    QMessageBox::information(
        this,
        privilegeText("privilege.dialog.create.title", QStringLiteral("创建用户")),
        privilegeText("privilege.dialog.create.succeeded", QStringLiteral("创建成功。")));
    refreshLocalUserList();
    refreshPermissionSnapshot();
}

void PrivilegeDock::resetPasswordByInputs()
{
    const QString userName = m_resetUserNameEdit->text().trimmed();
    const QString password = m_resetPasswordEdit->text();
    const QString confirmPassword = m_resetPasswordConfirmEdit->text();

    if (userName.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.username_empty", QStringLiteral("目标用户名不能为空。")));
        return;
    }
    if (password.isEmpty())
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.password_empty", QStringLiteral("新密码不能为空。")));
        return;
    }
    if (password != confirmPassword)
    {
        QMessageBox::warning(
            this,
            privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
            privilegeText("privilege.dialog.reset.password_mismatch", QStringLiteral("两次密码输入不一致。")));
        return;
    }

    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("重置本地用户密码"));
        return;
    }

    const int confirm = QMessageBox::question(
        this,
        privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
        privilegeText(
            "privilege.dialog.reset.confirm",
            QStringLiteral("确定为“%1”重置密码吗？")).arg(userName),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);
    if (confirm != QMessageBox::Yes)
    {
        return;
    }

    kLogEvent actionEvent;
    info << actionEvent
        << privilegeLogText(
            "privilege.log.reset_password.request",
            QStringLiteral("[PrivilegeDock] 重置密码请求, user="))
        << userName.toStdString()
        << eol;

    QString errorText;
    if (!resetLocalUserPassword(userName, password, &errorText))
    {
        err << actionEvent
            << privilegeLogText(
                "privilege.log.reset_password.failed",
                QStringLiteral("[PrivilegeDock] 重置密码失败, user="))
            << userName.toStdString()
            << ", error="
            << errorText.toStdString()
            << eol;
        // privilegePromptHandled：提权恢复提示已展示时跳过旧的重置失败弹窗。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("重置本地用户密码"),
            errorText);
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
                errorText);
        }
        return;
    }

    info << actionEvent
        << privilegeLogText(
            "privilege.log.reset_password.succeeded",
            QStringLiteral("[PrivilegeDock] 重置密码成功, user="))
        << userName.toStdString()
        << eol;
    QMessageBox::information(
        this,
        privilegeText("privilege.dialog.reset.title", QStringLiteral("重置密码")),
        privilegeText("privilege.dialog.reset.succeeded", QStringLiteral("重置成功。")));
}

void PrivilegeDock::refreshPermissionSnapshot()
{
    QPointer<PrivilegeDock> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("privilege-permission-snapshot-refresh"),
            {m_accountTable, m_permissionTable},
            [guardThis]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->refreshPermissionSnapshot();
                }
            }))
    {
        return;
    }

    kLogEvent event;
    info << event
        << privilegeLogText(
            "privilege.log.refresh_privileges.start",
            QStringLiteral("[PrivilegeDock] 开始刷新权限快照。"))
        << eol;

    std::vector<PermissionSnapshotRow> rowList;
    appendLocalUserAndGroupRows(&rowList);
    appendCurrentProcessPrivilegeRows(&rowList);
    refreshPermissionTable(rowList);

    m_permissionStatusLabel->setText(privilegeText(
        "privilege.permission.status.completed",
        QStringLiteral("状态：%1 刷新完成，共 %2 项"))
        .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
        .arg(static_cast<int>(rowList.size())));

    info << event
        << privilegeLogText(
            "privilege.log.refresh_privileges.completed",
            QStringLiteral("[PrivilegeDock] 权限快照刷新完成, rows="))
        << rowList.size()
        << eol;
}

void PrivilegeDock::appendLocalUserAndGroupRows(std::vector<PermissionSnapshotRow>* rowsOut) const
{
    if (rowsOut == nullptr)
    {
        return;
    }

    // 先写入本地用户缓存。
    for (const LocalUserEntry& entry : m_localUserList)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.user", QStringLiteral("用户"));
        row.name = entry.name;
        row.status = privilegeText(
            "privilege.row.user.status",
            QStringLiteral("禁用:%1  最后登录:%2"))
            .arg(boolText(entry.disabled))
            .arg(entry.lastLogonText);
        row.detail = entry.fullName.isEmpty()
            ? privilegeText("privilege.row.no_full_name", QStringLiteral("<无全名>"))
            : privilegeText("privilege.row.full_name", QStringLiteral("全名:%1")).arg(entry.fullName);
        rowsOut->push_back(row);
    }

    // 再枚举本地组。
    LPLOCALGROUP_INFO_1 groupInfo = nullptr;
    DWORD entriesRead = 0;
    DWORD totalEntries = 0; // totalEntries：保留用于后续扩展分页。
    DWORD_PTR resumeHandle = 0;
    const NET_API_STATUS status = ::NetLocalGroupEnum(
        nullptr,
        1,
        reinterpret_cast<LPBYTE*>(&groupInfo),
        MAX_PREFERRED_LENGTH,
        &entriesRead,
        &totalEntries,
        &resumeHandle);
    if (status == NERR_Success || status == ERROR_MORE_DATA)
    {
        for (DWORD index = 0; index < entriesRead; ++index)
        {
            const LOCALGROUP_INFO_1& group = groupInfo[index];
            const QString groupName = group.lgrpi1_name != nullptr
                ? QString::fromWCharArray(group.lgrpi1_name)
                : QStringLiteral("<null>");
            const QString groupComment = group.lgrpi1_comment != nullptr
                ? QString::fromWCharArray(group.lgrpi1_comment)
                : QString();
            PermissionSnapshotRow row;
            row.type = privilegeText("privilege.row.type.group", QStringLiteral("组"));
            row.name = groupName;
            row.status = privilegeText("privilege.row.group.local", QStringLiteral("本地组"));
            row.detail = groupComment.isEmpty()
                ? privilegeText("privilege.row.no_description", QStringLiteral("<无说明>"))
                : groupComment;
            rowsOut->push_back(row);
        }
    }
    else
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.group", QStringLiteral("组"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = winErrorText(status);
        rowsOut->push_back(row);
    }

    if (groupInfo != nullptr)
    {
        ::NetApiBufferFree(groupInfo);
    }
}

void PrivilegeDock::appendCurrentProcessPrivilegeRows(std::vector<PermissionSnapshotRow>* rowsOut) const
{
    if (rowsOut == nullptr)
    {
        return;
    }

    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.open_process_token",
            QStringLiteral("OpenProcessToken失败: %1")).arg(winErrorText(::GetLastError()));
        rowsOut->push_back(row);
        return;
    }

    DWORD bytesNeeded = 0;
    ::GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &bytesNeeded);
    if (bytesNeeded == 0)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.get_token_information",
            QStringLiteral("GetTokenInformation失败: %1")).arg(winErrorText(::GetLastError()));
        rowsOut->push_back(row);
        ::CloseHandle(tokenHandle);
        return;
    }

    std::vector<unsigned char> tokenBuffer(bytesNeeded, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenPrivileges,
        tokenBuffer.data(),
        bytesNeeded,
        &bytesNeeded) == FALSE)
    {
        const QString errorText = winErrorText(::GetLastError());
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.read_failed", QStringLiteral("<读取失败>"));
        row.status = privilegeText("privilege.row.error", QStringLiteral("错误"));
        row.detail = privilegeText(
            "privilege.error.get_token_information",
            QStringLiteral("GetTokenInformation失败: %1")).arg(errorText);
        rowsOut->push_back(row);
        ::CloseHandle(tokenHandle);
        return;
    }

    TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(tokenBuffer.data());
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index)
    {
        const LUID_AND_ATTRIBUTES& privilege = privileges->Privileges[index];
        wchar_t nameBuffer[256] = {};
        DWORD nameLength = static_cast<DWORD>(std::size(nameBuffer));
        QString privilegeName = privilegeText(
            "privilege.row.lookup_privilege_name_failed",
            QStringLiteral("<LookupPrivilegeName失败>"));
        if (::LookupPrivilegeNameW(nullptr, const_cast<PLUID>(&privilege.Luid), nameBuffer, &nameLength) != FALSE)
        {
            privilegeName = QString::fromWCharArray(nameBuffer, static_cast<int>(nameLength));
        }

        wchar_t displayNameBuffer[512] = {};
        DWORD displayNameLength = static_cast<DWORD>(std::size(displayNameBuffer));
        DWORD languageId = 0;
        QString displayName = privilegeText("privilege.row.no_display_name", QStringLiteral("<无显示名>"));
        if (::LookupPrivilegeDisplayNameW(
            nullptr,
            reinterpret_cast<LPCWSTR>(privilegeName.utf16()),
            displayNameBuffer,
            &displayNameLength,
            &languageId) != FALSE)
        {
            Q_UNUSED(languageId);
            displayName = QString::fromWCharArray(displayNameBuffer, static_cast<int>(displayNameLength));
        }

        const bool enabled = (privilege.Attributes & SE_PRIVILEGE_ENABLED) != 0;
        const bool enabledByDefault = (privilege.Attributes & SE_PRIVILEGE_ENABLED_BY_DEFAULT) != 0;
        const bool removed = (privilege.Attributes & SE_PRIVILEGE_REMOVED) != 0;

        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeName;
        row.status = privilegeText(
            "privilege.row.process_privilege.status",
            QStringLiteral("启用:%1 默认:%2 移除:%3"))
            .arg(boolText(enabled))
            .arg(boolText(enabledByDefault))
            .arg(boolText(removed));
        row.detail = QStringLiteral("%1, Attributes=0x%2")
            .arg(displayName)
            .arg(QString::number(privilege.Attributes, 16).toUpper());
        rowsOut->push_back(row);
    }

    if (privileges->PrivilegeCount == 0)
    {
        PermissionSnapshotRow row;
        row.type = privilegeText("privilege.row.type.process_privilege", QStringLiteral("进程权限"));
        row.name = privilegeText("privilege.row.empty", QStringLiteral("<空>"));
        row.status = privilegeText("privilege.row.no_privileges", QStringLiteral("无权限项"));
        row.detail = privilegeText(
            "privilege.row.no_privileges.detail",
            QStringLiteral("当前进程令牌未返回任何权限条目。"));
        rowsOut->push_back(row);
    }

    ::CloseHandle(tokenHandle);
}

void PrivilegeDock::refreshPermissionTable(const std::vector<PermissionSnapshotRow>& rowList)
{
    if (m_permissionTable == nullptr)
    {
        return;
    }

    m_permissionTable->setRowCount(static_cast<int>(rowList.size()));
    for (int rowIndex = 0; rowIndex < static_cast<int>(rowList.size()); ++rowIndex)
    {
        const PermissionSnapshotRow& rowData = rowList[static_cast<std::size_t>(rowIndex)];
        m_permissionTable->setItem(rowIndex, 0, new QTableWidgetItem(rowData.type));
        m_permissionTable->setItem(rowIndex, 1, new QTableWidgetItem(rowData.name));
        m_permissionTable->setItem(rowIndex, 2, new QTableWidgetItem(rowData.status));
        m_permissionTable->setItem(rowIndex, 3, new QTableWidgetItem(rowData.detail));
    }
}

QString PrivilegeDock::fileTimeToDateTimeText(const std::uint32_t secondsSince1970) const
{
    if (secondsSince1970 == 0)
    {
        return privilegeText("privilege.time.never", QStringLiteral("从未"));
    }
    return QDateTime::fromSecsSinceEpoch(secondsSince1970).toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"));
}

QString PrivilegeDock::winErrorText(const DWORD code) const
{
    wchar_t* messageBuffer = nullptr;
    const DWORD messageLength = ::FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        0,
        reinterpret_cast<LPWSTR>(&messageBuffer),
        0,
        nullptr);
    QString messageText;
    if (messageLength > 0 && messageBuffer != nullptr)
    {
        messageText = QString::fromWCharArray(messageBuffer).trimmed();
        ::LocalFree(messageBuffer);
    }
    if (messageText.isEmpty())
    {
        return privilegeText("privilege.error.code", QStringLiteral("错误码 %1")).arg(code);
    }
    return QStringLiteral("%1 (code=%2)").arg(messageText).arg(code);
}
