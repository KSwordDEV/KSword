#include "../Framework.h"
#include "PrivilegeAccountPages.h"
#include "PrivilegeAccountSupport.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/SegmentedControl.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"
#include <QAction>
#include <QComboBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QResizeEvent>
#include <QSet>
#include <QSplitter>
#include <QVBoxLayout>

namespace ks::privilege
{
namespace
{
    using namespace account_detail;

    // 输入翻译键、原文和父级，返回可换行的自然高度说明，不另建文本编辑器。
    QLabel* label(QWidget* parent, const char* key, const QString& source)
    {
        auto* text = new QLabel(privilegeText(key, source), parent); // 显示简短状态/用途说明。
        text->setWordWrap(true);
        text->setMinimumWidth(0);
        return text;
    }

    // 输入原按钮与用途提示；沿用 button() 的原有中性样式，只补悬停释义。
    void describeButton(QPushButton* action, const char* key, const QString& description)
    {
        action->setToolTip(privilegeText(key, description));
    }

    // 输入权限表及两颗原按钮；A 看权限/说明/来源，B 看权限/来源 SID/路径。
    class RightsColumns final : public QObject
    {
    public:
        RightsColumns(ValueTable* table, QPushButton* a, QPushButton* b)
            : QObject(table), m_table(table), m_a(a), m_b(b)
        {
            connect(a, &QPushButton::clicked, this, [this]() { apply(false); });
            connect(b, &QPushButton::clicked, this, [this]() { apply(true); });
            table->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
            connect(table->horizontalHeader(), &QWidget::customContextMenuRequested,
                this, [this](const QPoint& point) { showColumns(point); });
            apply(false);
        }
    private:
        // 只改变可见列；完整模型、搜索与导出仍使用同一份权限来源数据。
        void apply(bool provenance)
        {
            for (int column = 0; column < m_table->columnCount(); ++column)
            {
                const bool visible = column == 0 || (provenance
                    ? column == 1 || column == 4 : column == 2 || column == 3); // 互补精简列组。
                m_table->setColumnHidden(column, !visible);
            }
            m_a->setChecked(!provenance);
            m_b->setChecked(provenance);
        }

        // 表头右键保留逐列选择；手动设置后清除 A/B 选中，明确表示自定义布局。
        void showColumns(const QPoint& point)
        {
            auto* menu = new QMenu(m_table); // 异步菜单随表格销毁，不持有嵌套事件循环。
            menu->setAttribute(Qt::WA_DeleteOnClose);
            menu->setStyleSheet(KswordTheme::ContextMenuStyle());
            for (int column = 0; column < m_table->columnCount(); ++column)
            {
                auto* action = menu->addAction(m_table->model()->headerData(
                    column, Qt::Horizontal).toString()); // 当前语言的列标题。
                action->setCheckable(true);
                action->setChecked(!m_table->isColumnHidden(column));
                connect(action, &QAction::toggled, this, [this, column](bool visible)
                {
                    m_table->setColumnHidden(column, !visible);
                    m_a->setChecked(false);
                    m_b->setChecked(false);
                });
            }
            menu->popup(m_table->horizontalHeader()->mapToGlobal(point));
        }
        ValueTable* m_table; // 唯一结果表。
        QPushButton* m_a; // 概览列组按钮。
        QPushButton* m_b; // 来源列组按钮。
    };

    // 权限→权限分配：两个独立参数/执行/结果面板，权限选择附近保留原有增删动作。
    class RightsPage final : public QWidget
    {
    public:
        explicit RightsPage(QWidget* parent) : QWidget(parent)
        {
            auto* root = new QVBoxLayout(this); // 页根仅拥有一次等边留白。
            root->setContentsMargins(6, 6, 6, 6);
            root->setSpacing(6);
            root->addWidget(label(this, "privilege.workbench.rights.summary_scope",
                QStringLiteral("查询本机 LSA 策略分配；自身及其组模式递归解析本地组并保留来源。域组与动态登录组不保证完整，结果不等于进程令牌。")));
            m_panels = new QSplitter(Qt::Horizontal, this);
            m_panels->setChildrenCollapsible(false);
            m_panels->setHandleWidth(6);
            root->addWidget(m_panels, 1);

            // 两个工作流各自使用共享参数正文滚动、固定执行栏和结果容器。
            createAccountPanel();
            createRightPanel();
            m_panels->setStretchFactor(0, 1);
            m_panels->setStretchFactor(1, 1);
            connectQueries();
            m_leftWorkspace->finish();
            m_rightWorkspace->finish();
            loadDescriptions();
        }

        // 账户管理页导航调用：填入稳定 SID，沿用“只查自身”的原有跳转语义。
        void selectAccount(const QString& account)
        {
            m_account->setText(account);
            refreshRights(false);
        }
    protected:
        // 宽窗左右一一对应，窄窗整组上下排列，不让输入与另一个方向的结果交叉。
        void resizeEvent(QResizeEvent* event) override
        {
            QWidget::resizeEvent(event);
            const Qt::Orientation direction = width() < 900 ? Qt::Vertical : Qt::Horizontal;
            if (m_panels->orientation() != direction || !m_positioned)
            {
                m_panels->setOrientation(direction);
                m_panels->setSizes({1, 1});
                m_positioned = true;
            }
        }
    private:
        // 左侧：账户输入、两种查询、独立筛选及权限来源表。
        void createAccountPanel()
        {
            m_leftWorkspace = new ks::ui::ParameterWorkspace(m_panels);
            m_leftWorkspace->setObjectName(QStringLiteral("privilege_rights_account_panel"));
            m_leftWorkspace->useStackedLayout();
            auto* heading = label(this, "privilege.workbench.rights.account_panel", QStringLiteral("账户权限查询"));
            ks::ui::StylePrimarySectionTitle(heading);
            m_leftWorkspace->parameters()->addWidget(heading);
            m_account = new QLineEdit(this);
            m_account->setObjectName(QStringLiteral("privilege_rights_account_input"));
            m_account->setPlaceholderText(privilegeText("privilege.workbench.rights.account_input",
                QStringLiteral("账户名或 SID（用户、组、服务身份）")));
            m_leftWorkspace->parameters()->addWidget(m_account);

            // 两种查询保留文字和释义，在同一固定操作行并排显示。
            auto* actions = new QWidget(this); // 固定执行区，独立于参数滚动正文。
            auto* actionLayout = new QHBoxLayout(actions); // 按文字自然宽度排列两种账户查询。
            actionLayout->setContentsMargins(0, 0, 0, 0);
            actionLayout->setSpacing(8);
            m_queryDirect = button(this, "privilege.workbench.rights.query_account", QStringLiteral("账户 → 直接权限"));
            m_queryGroups = button(this, "privilege.workbench.rights.query_groups", QStringLiteral("账户 → 自身及其组权限"));
            m_queryDirect->setObjectName(QStringLiteral("privilege_rights_query_direct"));
            m_queryGroups->setObjectName(QStringLiteral("privilege_rights_query_groups"));
            describeButton(m_queryDirect, "privilege.workbench.rights.direct_tip", QStringLiteral("仅查询输入账户 SID 的直接策略分配。"));
            describeButton(m_queryGroups, "privilege.workbench.rights.groups_tip",
                QStringLiteral("汇总账户自身及可解析本地组的策略权限；同一权限按不同来源分别保留。"));
            actionLayout->addWidget(m_queryDirect);
            actionLayout->addWidget(m_queryGroups);
            actionLayout->addStretch(1);
            ks::ui::NormalizeToolbarRow(actionLayout);
            m_leftWorkspace->actions()->addWidget(actions, 1);

            // 来源行保留规范 SID，两个互补视图只改变展示，不复制结果数据。
            auto* views = new QHBoxLayout; // 固定结果工具行。
            auto* a = new QPushButton(QStringLiteral("A"), this); // 权限/说明/来源。
            auto* b = new QPushButton(QStringLiteral("B"), this); // 权限/SID/关系路径。
            a->setCheckable(true);
            b->setCheckable(true);
            a->setToolTip(privilegeText("privilege.workbench.rights.view_a", QStringLiteral("概览：权限、说明和来源账户/组。")));
            b->setToolTip(privilegeText("privilege.workbench.rights.view_b", QStringLiteral("来源：权限、来源 SID 和一条已确认的成员关系路径。")));
            views->addWidget(a);
            views->addWidget(b);
            ks::ui::InstallSegmentedButtons(views, {a, b});
            m_leftSearch = new QLineEdit(this);
            m_leftSearch->setPlaceholderText(privilegeText("privilege.workbench.rights.search", QStringLiteral("搜索权限、账户或 SID")));
            ks::ui::StyleSearchField(m_leftSearch);
            views->addWidget(m_leftSearch, 1);
            ks::ui::NormalizeToolbarRow(views);
            m_leftWorkspace->results()->addLayout(views);
            m_rights = makeTable(this, {
                TableHeader(QStringLiteral("privilege.workbench.rights.right"), QStringLiteral("权限名称")),
                TableHeader(QStringLiteral("privilege.workbench.rights.source_sid"), QStringLiteral("来源 SID")),
                TableHeader(QStringLiteral("privilege.workbench.groups.description"), QStringLiteral("说明")),
                TableHeader(QStringLiteral("privilege.workbench.rights.source"), QStringLiteral("来源账户/组")),
                TableHeader(QStringLiteral("privilege.workbench.rights.path"), QStringLiteral("成员关系路径"))});
            m_rights->setObjectName(QStringLiteral("privilege_rights_sources_table"));
            new RightsColumns(m_rights, a, b);
            ks::ui::SetTableActionBarMode(m_rights, ks::ui::TableActionBarMode::Compact);
            m_leftWorkspace->results()->addWidget(m_rights, 1);
            m_leftStatus = label(this, "privilege.workbench.rights.await_account", QStringLiteral("输入账户后选择查询范围。"));
            m_leftStatus->setObjectName(QStringLiteral("privilege_rights_account_status"));
            m_leftWorkspace->results()->addWidget(m_leftStatus);
        }

        // 右侧：权限选择与说明、反查动作、独立筛选和直接分配账户表。
        void createRightPanel()
        {
            m_rightWorkspace = new ks::ui::ParameterWorkspace(m_panels);
            m_rightWorkspace->setObjectName(QStringLiteral("privilege_rights_right_panel"));
            m_rightWorkspace->useStackedLayout();
            auto* heading = label(this, "privilege.workbench.rights.right_panel", QStringLiteral("权限分配反查"));
            ks::ui::StylePrimarySectionTitle(heading);
            m_rightWorkspace->parameters()->addWidget(heading);
            m_right = new QComboBox(this);
            m_right->setObjectName(QStringLiteral("privilege_rights_right_input"));
            m_right->setEditable(true);
            m_right->addItems(rightsCatalog());
            ks::ui::StylePrimaryCombo(m_right);
            m_rightWorkspace->parameters()->addWidget(m_right);
            m_description = label(this, "privilege.workbench.rights.await_right", QStringLiteral("选择权限后查询直接分配账户。"));
            m_rightWorkspace->parameters()->addWidget(m_description);
            m_queryRight = button(this, "privilege.workbench.rights.query_right", QStringLiteral("权限 → 已分配账户"));
            m_queryRight->setObjectName(QStringLiteral("privilege_rights_query_assigned"));
            describeButton(m_queryRight, "privilege.workbench.rights.right_tip", QStringLiteral("只反查右侧当前权限的直接分配账户和组。"));
            // 查询和原有增删动作固定在权限选择下方，不随参数正文滚动或落到整页底部。
            auto* actions = new QWidget(this); // 右侧权限选择对应的固定动作区。
            auto* actionLayout = new QVBoxLayout(actions); // 目标说明在上，三个动作在下方同一行。
            actionLayout->setContentsMargins(0, 0, 0, 0);
            actionLayout->setSpacing(8);
            createMutationBar(actionLayout);
            m_rightWorkspace->actions()->addWidget(actions, 1);
            m_rightSearch = new QLineEdit(this);
            m_rightSearch->setPlaceholderText(privilegeText("privilege.workbench.rights.search", QStringLiteral("搜索权限、账户或 SID")));
            ks::ui::StyleSearchField(m_rightSearch);
            m_rightWorkspace->results()->addWidget(m_rightSearch);
            m_accounts = makeTable(this, {
                TableHeader(QStringLiteral("privilege.workbench.groups.account"), QStringLiteral("账户")), QStringLiteral("SID"),
                TableHeader(QStringLiteral("privilege.workbench.rights.right"), QStringLiteral("权限名称"))});
            m_accounts->setObjectName(QStringLiteral("privilege_rights_assigned_table"));
            ks::ui::SetTableActionBarMode(m_accounts, ks::ui::TableActionBarMode::Compact);
            m_rightWorkspace->results()->addWidget(m_accounts, 1);
            m_rightStatus = label(this, "privilege.workbench.rights.await_right", QStringLiteral("选择权限后查询直接分配账户。"));
            m_rightStatus->setObjectName(QStringLiteral("privilege_rights_assigned_status"));
            m_rightWorkspace->results()->addWidget(m_rightStatus);
        }

        // 输入权限侧固定动作布局，返回无；目标说明下并排放置反查、分配和移除。
        void createMutationBar(QVBoxLayout* actions)
        {
            m_target = label(this, "privilege.workbench.rights.mutation_scope",
                QStringLiteral("变更目标为左侧账户与右侧权限，仅修改该账户自身的直接分配。"));
            m_target->setObjectName(QStringLiteral("privilege_rights_mutation_target"));
            actions->addWidget(m_target);
            auto* row = new QHBoxLayout; // 三个权限动作共用一行，保留原按钮样式与信号。
            m_add = button(this, "privilege.workbench.rights.add", QStringLiteral("分配此权限"));
            m_remove = button(this, "privilege.workbench.rights.remove", QStringLiteral("移除此权限"));
            m_add->setObjectName(QStringLiteral("privilege_rights_add"));
            m_remove->setObjectName(QStringLiteral("privilege_rights_remove"));
            describeButton(m_add, "privilege.workbench.rights.add_tip", QStringLiteral("向左侧账户直接分配右侧选中的权限，确认后生效。"));
            describeButton(m_remove, "privilege.workbench.rights.remove_tip",
                QStringLiteral("仅移除左侧账户自身的直接分配，不修改来源组。"));
            row->addWidget(m_queryRight);
            row->addWidget(m_add);
            row->addWidget(m_remove);
            row->addStretch();
            ks::ui::NormalizeToolbarRow(row);
            actions->addLayout(row);
        }

        // 连接原控件；编辑输入立即清除旧结果并使在途结果失效，不自动触发额外枚举。
        void connectQueries()
        {
            connect(m_queryDirect, &QPushButton::clicked, this, [this]() { refreshRights(false); });
            connect(m_queryGroups, &QPushButton::clicked, this, [this]() { refreshRights(true); });
            connect(m_queryRight, &QPushButton::clicked, this, [this]() { refreshAccounts(); });
            connect(m_account, &QLineEdit::returnPressed, this, [this]() { refreshRights(m_includeGroups); });
            connect(m_account, &QLineEdit::textChanged, this, [this]() { invalidateAccount(); updateTarget(); });
            connect(m_right, &QComboBox::currentTextChanged, this, [this]() { invalidateRight(); updateTarget(); });
            connect(m_leftSearch, &QLineEdit::textChanged, m_rights, &ValueTable::setQuery);
            connect(m_rightSearch, &QLineEdit::textChanged, m_accounts, &ValueTable::setQuery);
            connect(m_add, &QPushButton::clicked, this, [this]() { changeRight(true); });
            connect(m_remove, &QPushButton::clicked, this, [this]() { changeRight(false); });
            m_rights->currentRowChanged = [this]()
            {
                const QString right = m_rights->currentCell(0).toString(); // 只填权限，不改变左侧账户。
                if (!right.isEmpty()) m_right->setCurrentText(right);
            };
            m_accounts->rowDoubleClicked = [this](int row)
            {
                m_account->setText(m_accounts->cell(row, 0, Qt::UserRole).toString());
                refreshRights(m_includeGroups);
            };
            updateTarget();
        }

        // 后台读取权限说明，UI 仅应用值；沿用冻结的翻译快照。
        void loadDescriptions()
        {
            runAccountRows(this, []()
            {
                RowsResult result; // 目录中每项权限的本地化说明。
                for (const QString& right : rightsCatalog())
                    result.rows.push_back({right, {}, rightDescription(right)});
                return result;
            }, [this](const RowsResult& result)
            {
                for (const Row& row : result.rows)
                    m_right->setItemData(m_right->findText(row.name), row.detail, Qt::ToolTipRole);
                m_description->setText(m_right->currentData(Qt::ToolTipRole).toString());
            });
        }

        void refreshRights(bool includeGroups);
        void refreshAccounts();
        void publishRights(const RowsResult& result, const QString& account, bool includeGroups);
        void invalidateAccount();
        void invalidateRight();
        void updateTarget();
        void changeRight(bool add);

        QSplitter* m_panels = nullptr; // 两个完整查询工作流的分栏。
        ks::ui::ParameterWorkspace* m_leftWorkspace = nullptr; // 账户查询骨架。
        ks::ui::ParameterWorkspace* m_rightWorkspace = nullptr; // 权限反查骨架。
        QLineEdit* m_account = nullptr; // 输入账户名/SID，唯一写目标。
        QComboBox* m_right = nullptr; // 输入权限常量，唯一写目标权限。
        QLineEdit* m_leftSearch = nullptr; // 只筛选左表。
        QLineEdit* m_rightSearch = nullptr; // 只筛选右表。
        ValueTable* m_rights = nullptr; // 权限及来源的规范数据。
        ValueTable* m_accounts = nullptr; // 当前权限的直接分配对象。
        QLabel* m_leftStatus = nullptr; // 账户侧独立状态。
        QLabel* m_rightStatus = nullptr; // 权限侧独立状态。
        QLabel* m_description = nullptr; // 所选权限说明。
        QLabel* m_target = nullptr; // 变更目标预览。
        QPushButton* m_queryDirect = nullptr; // 查询账户自身。
        QPushButton* m_queryGroups = nullptr; // 查询自身及组。
        QPushButton* m_queryRight = nullptr; // 反查权限。
        QPushButton* m_add = nullptr; // 分配直接权限。
        QPushButton* m_remove = nullptr; // 移除直接权限。
        bool m_includeGroups = false; // Enter 和写后刷新沿用最近查询范围。
        bool m_positioned = false; // 不在普通 resize 时重置用户分栏比例。
    };

    // 输入改变后旧结果失效；与实际查询共用同一通道，防止慢查询覆盖新账户。
    void RightsPage::invalidateAccount()
    {
        invalidateLatestRows(this, "rights");
        if (!clearRows(m_rights)) return;
        m_leftStatus->setText(privilegeText("privilege.workbench.rights.await_account",
            QStringLiteral("输入账户后选择查询范围。")));
        ks::ui::ApplyStatusRole(m_leftStatus, ks::ui::StatusRole::Idle);
    }

    // 切换权限立即清除右侧旧表，并保留左侧账户结果不受影响。
    void RightsPage::invalidateRight()
    {
        invalidateLatestRows(this, "assigned_accounts");
        if (!clearRows(m_accounts)) return;
        m_description->setText(m_right->currentData(Qt::ToolTipRole).toString());
        m_rightStatus->setText(privilegeText("privilege.workbench.rights.await_right",
            QStringLiteral("选择权限后查询直接分配账户。")));
        ks::ui::ApplyStatusRole(m_rightStatus, ks::ui::StatusRole::Idle);
    }

    // 显示写操作的两个输入快照，未填写时禁用；查询按钮保持可用。
    void RightsPage::updateTarget()
    {
        const QString account = m_account->text().trimmed(); // 当前账户输入。
        const QString right = m_right->currentText().trimmed(); // 当前权限输入。
        m_target->setText(privilegeText("privilege.workbench.rights.mutation_target",
            QStringLiteral("直接分配变更：账户 %1；权限 %2。不会修改来源组。"))
            .arg(account.isEmpty() ? QStringLiteral("—") : account, right));
        const bool valid = !account.isEmpty() && rightsCatalog().contains(right); // 写入目录校验。
        m_add->setEnabled(valid);
        m_remove->setEnabled(valid);
    }

    // 输入查询范围，后台采集；两个按钮及 Enter 共享 latest-only 语义通道。
    void RightsPage::refreshRights(bool includeGroups)
    {
        m_includeGroups = includeGroups;
        const QString account = m_account->text().trimmed(); // 捕获后不从后台读取控件。
        if (!clearRows(m_rights)) return;
        m_leftStatus->setText(privilegeText("privilege.workbench.rights.querying_account",
            QStringLiteral("正在查询账户：%1")).arg(account));
        ks::ui::ApplyStatusRole(m_leftStatus, ks::ui::StatusRole::Info);
        runLatestAccountRows(this, "rights", [account, includeGroups]()
        {
            return includeGroups ? queryAccountAndGroupRights(account) : queryRights(account);
        }, [this, account, includeGroups](const RowsResult& result)
        {
            publishRights(result, account, includeGroups);
        });
    }

    // 输入完整采集结果，保持权限/SID 唯一行键，并把来源字段纳入搜索、复制和导出。
    void RightsPage::publishRights(const RowsResult& result, const QString& account, bool includeGroups)
    {
        const QPointer<RightsPage> alive(this); // 模型提交可能触发外部关闭页面。
        m_rights->setSourceFactory([rows = result.rows, account](const auto& translator)
        {
            QVector<ks::ui::ImmutableTableRow> values; // 唯一规范数据源，含隐藏列。
            for (const Row& row : rows)
            {
                ks::ui::ImmutableTableRow value; // 一个权限与一个实际分配来源。
                value.key = row.name + QLatin1Char('|') + row.sid;
                const QString source = row.extra.isEmpty() ? account : row.extra; // 自身查询补足显示来源。
                value.cells = {row.name, row.sid, translator.sourceText(row.detail), source,
                    row.path.isEmpty() ? account : row.path};
                value.roles.insert(Qt::UserRole, row.sid);
                const QString provenance = value.cells.join(QLatin1Char('\n')); // 完整可读提示，不拼 HTML。
                for (int column = 0; column < value.cells.size(); ++column)
                    value.columnRoles[column].insert(Qt::ToolTipRole, provenance);
                values.push_back(std::move(value));
            }
            return ks::ui::MakeImmutableTableSource(std::move(values));
        });
        if (!alive) return;
        m_rights->setQuery(m_leftSearch->text());
        if (!alive) return;
        QSet<QString> uniqueRights; // 与来源记录数区分，避免把重复来源当成更多种权限。
        for (const Row& row : result.rows) uniqueRights.insert(row.name);
        const QString scope = includeGroups
            ? privilegeText("privilege.workbench.rights.scope_groups", QStringLiteral("自身及其组"))
            : privilegeText("privilege.workbench.rights.scope_direct", QStringLiteral("仅自身")); // 查询模式。
        QString status = privilegeText("privilege.workbench.rights.account_complete",
            QStringLiteral("%1（%2）：%3 种权限，%4 条来源分配。"))
            .arg(account, scope).arg(uniqueRights.size()).arg(result.rows.size()); // 无结果时明确显示零。
        if (!result.error.isEmpty())
            status += QLatin1Char('\n') + privilegeText("privilege.workbench.rights.partial",
                QStringLiteral("结果不完整或查询失败：%1")).arg(result.error);
        m_leftStatus->setText(status);
        ks::ui::ApplyStatusRole(m_leftStatus, result.error.isEmpty()
            ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
    }

    // 右侧只按当前权限查询，结果与状态始终携带权限常量。
    void RightsPage::refreshAccounts()
    {
        const QString right = m_right->currentText().trimmed(); // 查询时固定权限。
        if (!clearRows(m_accounts)) return;
        if (!rightsCatalog().contains(right))
        {
            invalidateLatestRows(this, "assigned_accounts");
            showResult(m_rightStatus, {{}, privilegeText("privilege.workbench.rights.invalid_right",
                QStringLiteral("请选择目录中的有效权限名称。"))});
            return;
        }
        m_rightStatus->setText(privilegeText("privilege.workbench.rights.querying_right",
            QStringLiteral("正在反查权限：%1")).arg(right));
        ks::ui::ApplyStatusRole(m_rightStatus, ks::ui::StatusRole::Info);
        runLatestAccountRows(this, "assigned_accounts", [right]() { return assignedAccounts(right); },
            [this, right](const RowsResult& result)
        {
            if (!fillTable(m_accounts, result.rows)) return;
            if (!filterTable(m_accounts, m_rightSearch->text())) return;
            m_rightStatus->setText(privilegeText("privilege.workbench.rights.right_complete",
                QStringLiteral("%1：%2 个直接分配账户/组。"))
                .arg(right).arg(result.rows.size())
                + (result.error.isEmpty() ? QString() : QLatin1Char('\n') + result.error));
            ks::ui::ApplyStatusRole(m_rightStatus, result.error.isEmpty()
                ? ks::ui::StatusRole::Success : ks::ui::StatusRole::Warning);
        });
    }

    // 只修改左侧输入账户的直接权限；组汇总不影响写目标，写前预览与写后回读保持原行为。
    void RightsPage::changeRight(bool add)
    {
        const QString account = m_account->text().trimmed(); // 固定确认前的输入账户。
        const QString right = m_right->currentText().trimmed(); // 固定确认前的权限常量。
        if (account.isEmpty() || !rightsCatalog().contains(right)) return;
        invalidateLatestRows(this, "rights");
        invalidateLatestRows(this, "assigned_accounts");
        setEnabled(false);
        runAccountRows(this, [account, right]() { return previewDirectRight(account, right); },
            [this, right, add](const RowsResult& preview)
        {
            const QPointer<RightsPage> alive(this); // 弹窗和 enabled 回调可能关闭页面。
            setEnabled(true);
            if (!alive) return;
            if (!preview.error.isEmpty() || preview.rows.isEmpty())
            {
                showResult(m_leftStatus, preview);
                return;
            }
            const Row identity = preview.rows.first(); // 用已解析的 SID 确认，避免重名和输入漂移。
            if ((identity.extra == QStringLiteral("assigned")) == add)
            {
                m_leftStatus->setText(privilegeText("privilege.workbench.rights.no_change",
                    QStringLiteral("该直接权限已处于请求状态，无需修改。")));
                return;
            }
            const QString action = add
                ? privilegeText("privilege.workbench.rights.action_add", QStringLiteral("分配"))
                : privilegeText("privilege.workbench.rights.action_remove", QStringLiteral("移除")); // 确认动作。
            if (QMessageBox::question(this, privilegeText("privilege.workbench.groups.preview", QStringLiteral("变更预览")),
                privilegeText("privilege.workbench.rights.preview",
                    QStringLiteral("操作：%1\n账户：%2\nSID：%3\n直接策略权限：%4\n\n应用后将回读策略；需要新登录才能反映在新令牌中。"))
                    .arg(action, identity.name, identity.sid, right),
                QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes) return;
            if (!alive) return;
            const QString sid = identity.sid; // 后台仅使用已确认的稳定 SID。
            setEnabled(false);
            runAccountRows(this, [sid, right, add]() { return writeDirectRight(sid, right, add); },
                [this, sid, right](const RowsResult& result)
            {
                const QPointer<RightsPage> owner(this); // 写后回读先确认宿主。
                setEnabled(true);
                if (!owner) return;
                m_account->setText(sid);
                m_right->setCurrentText(right);
                if (!owner) return;
                if (!result.error.isEmpty())
                {
                    showResult(m_leftStatus, result);
                    return;
                }
                refreshRights(m_includeGroups);
                refreshAccounts();
            });
        });
    }
}

// 惰性工厂创建完整查询页；账户管理导航沿用外部已有接口。
QWidget* createRightsPage(QWidget* parent)
{
    return new RightsPage(parent);
}

// 输入页面和账户/SID，只有真实权限页才接收导航，返回无。
void selectRightsAccount(QWidget* page, const QString& account)
{
    if (auto* rights = dynamic_cast<RightsPage*>(page)) rights->selectAccount(account);
}
}
