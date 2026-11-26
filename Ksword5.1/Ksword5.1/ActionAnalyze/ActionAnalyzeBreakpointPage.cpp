#include "ActionAnalyzeBreakpointPage.h"
#include "../../../KswordCLI/ActionAnalyze/Control/NativeStopCondition.h"

#include "OfflineProjectReader.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemedMessageBox.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QSignalBlocker>
#include <QStringList>
#include <QVBoxLayout>
#include <algorithm>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;
    using namespace Ksword::ActionAnalyze;

    constexpr qsizetype kModuleLength = 255; // 模块文件名允许的最大 UTF-8 字节数。
    constexpr qsizetype kSymbolLength = 512; // 精确符号允许的最大 UTF-8 字节数。

    // 定位方式只用于草稿描述，不使用本地进程、内核或调试器。
    enum class LocationKind { Rva, Symbol };

    struct SaveRequest
    {
        QString manifestPath; // 按下保存时实际显示的项目清单。
        std::string projectId; // 用于辨认同路径被替换的项目。
        std::string expectedRevisionId; // 草稿基于的已提交修订。
        std::vector<BreakpointDefinition> definitions; // 全量离线定义，含保留行的 ID 和修订。
    };

    struct SaveResult
    {
        ProjectResult result; // 共享存储层的写入回执。
        ProjectInfo info; // 成功后由存储层回读的身份、修订和规范定义。
    };

    // 后台线程持租约保存冻结的定义。读取同租约下最新配置，保留其标题与说明。
    SaveResult SaveDefinitions(const SaveRequest& request)
    {
        ProjectDocument document; // 析构释放读写租约，UI 回调无需持有该对象。
        if (const auto opened = document.Open(request.manifestPath.toStdWString(), ProjectAccess::ReadWrite); !opened)
        {
            return {opened, {}};
        }
        const auto* current = document.Info(); // 读写打开后，存储层已在持锁状态重新核验头。
        if (!current || current->projectId != request.projectId)
        {
            return {{ProjectError::StaleRevision, 0, "projectId"}, {}};
        }
        auto settings = current->settings; // 只替换断点完整集合，其它设置采用当前值。
        settings.breakpointDefinitions = request.definitions;
        if (const auto saved = document.Save(settings, request.expectedRevisionId); !saved)
        {
            return {saved, {}};
        }
        return {{}, *document.Info()};
    }

    // 按存储契约裁去首尾 ASCII 空格，保留合法的其它 Unicode 空白和内部空格。
    QStringView TrimDefinition(QStringView text)
    {
        while (!text.isEmpty() && text.front() == QLatin1Char(' '))
        {
            text = text.sliced(1);
        }
        while (!text.isEmpty() && text.back() == QLatin1Char(' '))
        {
            text.chop(1);
        }
        return text;
    }

    // 检查单行文本是否能无损写为规范 UTF-8，并受存储字节配额约束。
    bool IsDefinitionText(QStringView value, qsizetype maxBytes)
    {
        if (value.isEmpty() || !value.isValidUtf16() || value.toUtf8().size() > maxBytes)
        {
            return false;
        }
        for (const QChar ch : value) // 逐字符检查，不限制一般 Unicode 名称。
        {
            const auto category = ch.category(); // 判断不可见控制和行边界。
            if (category == QChar::Other_Control || category == QChar::Separator_Line
                || category == QChar::Separator_Paragraph)
            {
                return false;
            }
        }
        return true;
    }

    // 输入已去掉外围空白的模块名，返回是否为有效的 Windows 基础文件名语法。
    bool IsModuleName(QStringView module)
    {
        static const QRegularExpression invalid(QStringLiteral(R"([/\\:*?"<>|])")); // 文件名禁用字符。
        return IsDefinitionText(module, kModuleLength) && !module.endsWith(QLatin1Char('.'))
            && !invalid.matchView(module).hasMatch();
    }

    // 输入已去掉外围空白的 RVA，返回真实数值，非法或超过 32 位时返回空值。
    std::optional<std::uint32_t> ParseRva(QStringView input)
    {
        static const QRegularExpression syntax(QStringLiteral("\\A(?:0[xX])?([0-9a-fA-F]{1,8})\\z"));
        const auto match = syntax.matchView(input); // 捕获不含可选 0x 前缀的数值部分。
        if (!match.hasMatch())
        {
            return {};
        }
        return match.captured(1).toUInt(nullptr, 16); // 语法已限制为无符号 32 位。
    }

    // 按存储层的 ASCII 大小写规则比较模块标签，非 ASCII 字节按原值比较。
    bool SameModule(std::string_view left, std::string_view right)
    {
        const auto fold = [](char ch) { return ch >= 'A' && ch <= 'Z' ? static_cast<char>(ch + ('a' - 'A')) : ch; };
        return std::equal(left.begin(), left.end(), right.begin(), right.end(),
            [&](char a, char b) { return fold(a) == fold(b); });
    }

    // 返回已有定义的表单定位类型和输入文字，RVA 使用人可读的十六进制。
    LocationKind DefinitionKind(const BreakpointDefinition& definition)
    {
        return std::holds_alternative<BreakpointRva>(definition.location) ? LocationKind::Rva : LocationKind::Symbol;
    }

    QString LocationText(const BreakpointDefinition& definition)
    {
        if (const auto* rva = std::get_if<BreakpointRva>(&definition.location))
        {
            return QStringLiteral("0x%1").arg(QString::number(rva->rva, 16).toUpper());
        }
        return QString::fromStdString(std::get<BreakpointSymbol>(definition.location).symbol);
    }

    // 精确身份来自已保存的资料；在表单和单元格提示里原样展示。
    QString IdentityText(const BreakpointDefinition& definition)
    {
        QStringList details; // 按需包含映像散列和 PDB 身份。
        if (definition.module.imageSha256)
        {
            details.append(sourceText(QStringLiteral("映像 SHA-256：%1"))
                .arg(QString::fromStdString(*definition.module.imageSha256)));
        }
        const auto* symbol = std::get_if<BreakpointSymbol>(&definition.location); // RVA 不含 PDB 标识。
        if (symbol && symbol->pdb)
        {
            details.append(sourceText(QStringLiteral("PDB：%1 · %2"))
                .arg(QString::fromStdString(symbol->pdb->guid), QString::number(symbol->pdb->age)));
        }
        if (definition.condition)
        {
            details.append(sourceText(QStringLiteral("断点条件：%1"))
                .arg(QString::fromStdString(definition.condition->source))); // 完整规则同源用于表格tooltip与编辑身份。
        }
        return details.join(QLatin1Char('\n'));
    }

    // 初始化状态标签；数据采用纯文本以保留符号中的尖括号等字符。
    QLabel* StatusLabel(QWidget* parent)
    {
        auto* label = new QLabel(parent); // 由承载本标签的工作区接管。
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        return label;
    }

    // 创建共享主题的标准图标按钮，文案在语言刷新时设置。
    QPushButton* IconButton(QWidget* parent, const QString& resource,
        ks::ui::FlatButtonTone tone = ks::ui::FlatButtonTone::Neutral)
    {
        auto* button = new QPushButton(parent); // 所有者为相应动作区或列表工具带。
        KswordTheme::ApplyStandardIconButtonMetrics(button);
        ks::ui::ApplyFlatButtonTheme(button, tone, ks::ui::FlatButtonAppearance::Solid);
        ks::ui::SetThemeButtonIcon(button, QIcon(resource));
        return button;
    }
}

// 草稿模型保留完整文本。增删改单行，表单用持久索引识别编辑对象。
class BreakpointDraftModel final : public QAbstractTableModel
{
public:
    using QAbstractTableModel::QAbstractTableModel;

    // 接收 Qt 父索引，返回根层行数或零，模型没有子行。
    int rowCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_rows.size());
    }

    // 接收 Qt 父索引，返回三个互补的草稿字段列或零。
    int columnCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : 3;
    }

    // 从指定行列返回显示、可访问或悬停文本，用于保留完整的模块名与符号。
    QVariant data(const QModelIndex& index, int role) const override
    {
        const auto* draft = draftAt(index.row()); // 当前单元格的草稿定义。
        if (!index.isValid() || !draft || (role != Qt::DisplayRole && role != Qt::ToolTipRole
            && role != Qt::AccessibleTextRole))
        {
            return {};
        }
        if (role == Qt::ToolTipRole && index.column() <= 1)
        {
            const auto identity = IdentityText(*draft); // 同名候选项可借精确身份区分。
            const auto value = index.column() == 0 ? QString::fromStdString(draft->module.name) : displayLocation(*draft);
            return identity.isEmpty() ? value : value + QLatin1Char('\n') + identity;
        }
        switch (index.column())
        {
        case 0:
            return QString::fromStdString(draft->module.name);
        case 1:
            return displayLocation(*draft);
        case 2:
            return draft->enabled ? sourceText(QStringLiteral("已启用")) : sourceText(QStringLiteral("已禁用"));
        default:
            return {};
        }
    }

    // 返回指定水平栏的本地化标签。垂直表头和其它角色沿用 Qt 默认实现。
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            switch (section)
            {
            case 0:
                return sourceText(QStringLiteral("模块文件名"));
            case 1:
                return sourceText(QStringLiteral("断点位置"));
            case 2:
                return sourceText(QStringLiteral("草稿状态"));
            }
        }
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    // 返回给定行的只读草稿或 nullptr，调用方在修改模型前消费返回值。
    const BreakpointDefinition* draftAt(int row) const
    {
        return row >= 0 && row < rowCount() ? &m_rows.at(row) : nullptr;
    }

    // 为列表和当前编辑对象生成同一定位文字，保持位置类型与数值一致。
    static QString displayLocation(const BreakpointDefinition& draft)
    {
        return DefinitionKind(draft) == LocationKind::Rva
            ? sourceText(QStringLiteral("RVA %1")).arg(LocationText(draft))
            : sourceText(QStringLiteral("符号 %1")).arg(LocationText(draft));
    }

    // 忽略正编辑的行，检查是否存在同模块、同类型且同定位值的另一草稿。
    bool contains(const BreakpointDefinition& candidate, int excludedRow) const
    {
        for (int row = 0; row < rowCount(); ++row) // 单选表未接代理，源行可直接比较。
        {
            const auto& draft = m_rows.at(row); // 只读对比现有定义。
            if (row != excludedRow && draft.location == candidate.location
                && draft.module.imageSha256 == candidate.module.imageSha256
                && SameModule(draft.module.name, candidate.module.name))
            {
                return true;
            }
        }
        return false;
    }

    // 接收经校验的草稿以及已确认的编辑行，空行号 -1 表示新增；返回提交行索引。
    QModelIndex put(int row, const BreakpointDefinition& draft)
    {
        if (row >= 0)
        {
            m_rows[row] = draft;
            emit dataChanged(index(row, 0), index(row, 2));
            return index(row, 0);
        }
        row = rowCount();
        beginInsertRows({}, row, row);
        m_rows.push_back(draft);
        endInsertRows();
        return index(row, 0);
    }

    // 接收由页面确认的模型行号，删除该行并更新持久索引。
    void erase(int row)
    {
        beginRemoveRows({}, row, row);
        m_rows.erase(m_rows.begin() + row);
        endRemoveRows();
    }

    // 按项目读回或写回的权威定义更新整表，调用前先清除编辑对象。
    void replaceRows(const std::vector<BreakpointDefinition>& rows)
    {
        beginResetModel();
        m_rows = rows;
        endResetModel();
    }

    // 返回当前完整草稿，调用方保存时据此拷贝为异步值请求。
    const std::vector<BreakpointDefinition>& rows() const
    {
        return m_rows;
    }

    // 语言变化只刷新已投影的表头和单元格文字。
    void retranslate()
    {
        emit headerDataChanged(Qt::Horizontal, 0, 2);
        if (rowCount() > 0)
        {
            emit dataChanged(index(0, 0), index(rowCount() - 1, 2));
        }
    }

private:
    std::vector<BreakpointDefinition> m_rows; // 只包含用户已提交到列表的断点定义草稿。
};

ActionAnalyzeBreakpointPage::ActionAnalyzeBreakpointPage(QWidget* parent)
    : QWidget(parent)
{
    auto* root = new QVBoxLayout(this); // 工作台已有页框，子页只接共享参数工作区。
    root->setContentsMargins(0, 0, 0, 0);
    m_workspace = new ks::ui::ParameterWorkspace(this, 370);
    m_saveOperation = new ks::ui::AsyncOperation(this);
    root->addWidget(m_workspace);
    createForm();
    createList();
    retranslate();
    m_workspace->finish();
}

// 关闭共享回调门禁。后台已受理的项目写入仍按存储层的提交规则完成。
ActionAnalyzeBreakpointPage::~ActionAnalyzeBreakpointPage()
{
    m_saveOperation->close();
}

void ActionAnalyzeBreakpointPage::createForm()
{
    m_form = new QGroupBox(m_workspace);
    auto* form = new QFormLayout(m_form); // 窄栏下标签换行，参数正文仅向下滚动。
    form->setFieldGrowthPolicy(QFormLayout::AllNonFixedFieldsGrow);
    form->setRowWrapPolicy(QFormLayout::WrapLongRows);
    form->setLabelAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    m_module = new QLineEdit(m_form);
    m_kind = new QComboBox(m_form);
    m_location = new QLineEdit(m_form);
    m_condition = new QLineEdit(m_form); // 复用原参数表单和独立输入主题。
    m_condition->setMaxLength(8192); // 真正上限仍按准备器的UTF-8字节数计算。
    m_enabled = new QCheckBox(m_form);
    m_enabled->setChecked(true);

    // 标签保留原生伙伴关联，支持键盘和辅助技术理解字段含义。
    m_moduleLabel = new QLabel(m_form);
    m_kindLabel = new QLabel(m_form);
    m_locationLabel = new QLabel(m_form);
    m_conditionLabel = new QLabel(m_form);
    m_conditionLabel->setBuddy(m_condition);
    m_moduleLabel->setBuddy(m_module);
    m_kindLabel->setBuddy(m_kind);
    m_locationLabel->setBuddy(m_location);
    m_editTarget = StatusLabel(m_form);
    form->addRow(m_editTarget);
    m_editIdentity = StatusLabel(m_form);
    form->addRow(m_editIdentity);
    form->addRow(m_moduleLabel, m_module);
    form->addRow(m_kindLabel, m_kind);
    form->addRow(m_locationLabel, m_location);
    form->addRow(m_conditionLabel, m_condition);
    form->addRow(m_enabled);
    m_workspace->parameters()->addWidget(m_form);
    ks::ui::StyleParameterSection(m_form);

    // 提交和放弃输入固定在表单下面，随参数滚动仍可访问。
    m_commit = new QPushButton(m_workspace);
    ks::ui::ApplyFlatButtonTheme(m_commit, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    m_clear = IconButton(m_workspace, QStringLiteral(":/Icon/log_cancel_track.svg"));
    m_workspace->actions()->addWidget(m_commit);
    m_workspace->actions()->addWidget(m_clear);
    m_workspace->actions()->addStretch();
    ks::ui::NormalizeToolbarRow(m_workspace->actions());
    connect(m_commit, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::commitForm);
    connect(m_clear, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::clearForm);

    // 普通文本不触发应用。Enter 单独提交当前表单，Tab 保留 Qt 原生遍历。
    connect(m_module, &QLineEdit::returnPressed, this, &ActionAnalyzeBreakpointPage::commitForm);
    connect(m_location, &QLineEdit::returnPressed, this, &ActionAnalyzeBreakpointPage::commitForm);
    connect(m_condition, &QLineEdit::returnPressed, this, &ActionAnalyzeBreakpointPage::commitForm);
    connect(m_module, &QLineEdit::textChanged, this, &ActionAnalyzeBreakpointPage::formChanged);
    connect(m_location, &QLineEdit::textChanged, this, &ActionAnalyzeBreakpointPage::formChanged);
    connect(m_condition, &QLineEdit::textChanged, this, &ActionAnalyzeBreakpointPage::formChanged);
    connect(m_kind, &QComboBox::currentIndexChanged, this, &ActionAnalyzeBreakpointPage::formChanged);
    connect(m_enabled, &QCheckBox::toggled, this, &ActionAnalyzeBreakpointPage::formChanged);
}

void ActionAnalyzeBreakpointPage::createList()
{
    auto* toolbar = new QWidget(m_workspace); // 草稿列表管理动作，与表单提交分开。
    auto* tools = new QHBoxLayout(toolbar); // 列表操作与项目保存等高排列。
    ks::ui::StylePrimaryToolbar(toolbar);
    m_edit = IconButton(toolbar, QStringLiteral(":/Icon/rxpf_write.svg"));
    m_remove = IconButton(toolbar, QStringLiteral(":/Icon/log_clear.svg"), ks::ui::FlatButtonTone::Danger);
    m_prepareLive = IconButton(toolbar, QStringLiteral(":/Icon/process_start.svg"));
    tools->addWidget(m_edit);
    tools->addWidget(m_remove);
    tools->addWidget(m_prepareLive);
    tools->addStretch();
    m_openPending = IconButton(toolbar, QStringLiteral(":/Icon/process_refresh.svg"));
    m_save = IconButton(toolbar, QStringLiteral(":/Icon/disk_save.svg"), ks::ui::FlatButtonTone::Accent);
    tools->addWidget(m_openPending);
    tools->addWidget(m_save);
    ks::ui::NormalizeToolbarRow(tools);
    m_workspace->results()->addWidget(toolbar);

    // 明确区分本页实际能验证的状态和草稿列表中的启用意图。
    m_activation = StatusLabel(m_workspace);
    m_projectLabel = StatusLabel(m_workspace);
    m_projectStatus = StatusLabel(m_workspace);
    m_summary = StatusLabel(m_workspace);
    m_feedbackLabel = StatusLabel(m_workspace);
    m_workspace->results()->addWidget(m_projectLabel);
    m_workspace->results()->addWidget(m_projectStatus);
    m_workspace->results()->addWidget(m_activation);
    m_workspace->results()->addWidget(m_summary);
    m_workspace->results()->addWidget(m_feedbackLabel);

    // 草稿列表操作由本页工具带承载，关闭重复的快照表格操作条。
    m_table = new ks::ui::TableActionTableView(m_workspace);
    m_drafts = new BreakpointDraftModel(m_table);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_table->setAlternatingRowColors(true);
    m_table->verticalHeader()->hide();
    ks::ui::ResultTableCapabilities capabilities; // 本表各共享能力的明确选择。
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::None;
    ks::ui::ResultTableHost::ensure(m_table)->bindModel(m_drafts,
        {{0, QStringLiteral("module")}, {1, QStringLiteral("location")}, {2, QStringLiteral("draft_state")}},
        capabilities);
    m_workspace->results()->addWidget(m_table, 1);

    // 移动列表选区只影响按钮资格。双击或编辑按钮才载入表单。
    connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged,
        this, &ActionAnalyzeBreakpointPage::updateControls);
    connect(m_table, &QTableView::doubleClicked, this, &ActionAnalyzeBreakpointPage::editSelection);
    connect(m_edit, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::editSelection);
    connect(m_remove, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::removeSelection);
    connect(m_prepareLive, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::prepareLiveSelection);
    connect(m_openPending, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::openPendingProject);
    connect(m_save, &QPushButton::clicked, this, &ActionAnalyzeBreakpointPage::saveProject);
}

// 输入原控制页的草稿端口；刷新按钮资格，不启动查询、调试器或第二份常驻会话。
void ActionAnalyzeBreakpointPage::setLivePreparation(
    std::function<bool(const QString&, std::uint32_t, const QString&, const QString&)> prepare)
{
    m_livePreparation = std::move(prepare);
    updateControls();
}

// 输入当前列表单选，冻结定义再打开选择器；成功后控制页继续收集真实PID与创建时间。
void ActionAnalyzeBreakpointPage::prepareLiveSelection()
{
    const auto rows = m_table->selectionModel()->selectedRows(); // 不使用仍未提交的表单输入。
    const auto* selected = rows.size() == 1 ? m_drafts->draftAt(rows.front().row()) : nullptr;
    if (!selected || m_saving || !m_livePreparation || !selected->enabled ||
        selected->breakpointDefinitionId.empty() ||
        std::find(m_project.definitions.begin(), m_project.definitions.end(), *selected) == m_project.definitions.end())
    {
        return;
    }
    const auto definition = *selected; // 文件选择器会进入事件循环，不能跨越它持有模型行指针。
    const auto project = m_project; // 冻结已保存定义的真正项目，不采用选择器返回后的新上下文。
    const auto* location = std::get_if<BreakpointRva>(&definition.location); // 调试符号不冒充PE导出。
    if (!location || !location->rva)
    {
        return;
    }
    const QPointer<ActionAnalyzeBreakpointPage> alive(this); // 文件选择器期间工作台可被关闭。
    const auto path = QFileDialog::getOpenFileName(this, sourceText(QStringLiteral("选择已加载模块")),
        QString::fromStdString(definition.module.name), sourceText(QStringLiteral("Windows 模块 (*.exe *.dll)")));
    if (!alive || path.isEmpty())
    {
        return;
    }
    if (!m_project.matches(project) || m_project.revisionId != project.revisionId || m_saving ||
        std::find(m_project.definitions.begin(), m_project.definitions.end(), definition) == m_project.definitions.end())
    {
        return; // 选择模块期间项目或定义已变化，不能将旧位置标为新项目的定义。
    }
    // 文件名是定义的模块选择条件；实际是否装载及RVA是否可执行由原native准入判断。
    if (QFileInfo(path).fileName().compare(QString::fromStdString(definition.module.name), Qt::CaseInsensitive) != 0)
    {
        ks::ui::OpenThemedTextMessage(this, QMessageBox::Warning, sourceText(QStringLiteral("模块选择不匹配")),
            sourceText(QStringLiteral("所选文件名与断点定义的模块名不同，请重新选择。")));
        return;
    }
    if (m_livePreparation)
    {
        m_livePreparation(path, location->rva, QString::fromStdString(definition.breakpointDefinitionId), project.manifestPath);
    }
}

void ActionAnalyzeBreakpointPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_drafts)
    {
        retranslate();
    }
}

// 工作台只把核验成功的项目交给该页；读取失败时仍可查看原项目和草稿。
void ActionAnalyzeBreakpointPage::setProjectContext(const ProjectSnapshot& snapshot)
{
    if (snapshot.problem.status != ReadStatus::Ready || snapshot.manifestPath.isEmpty()
        || snapshot.id.isEmpty() || snapshot.revisionId.isEmpty())
    {
        return;
    }
    acceptProject({snapshot.manifestPath, snapshot.id, snapshot.title, snapshot.revisionId,
        snapshot.generation, snapshot.breakpointDefinitions});
}

bool ActionAnalyzeBreakpointPage::ProjectContext::matches(const ProjectContext& other) const
{
    return manifestPath == other.manifestPath && id == other.id;
}

bool ActionAnalyzeBreakpointPage::hasDraftChanges() const
{
    return m_drafts->rows() != m_project.definitions;
}

// 获得已核验的目录回读。仅标题、说明或采样更新时，可以保留原定义草稿。
void ActionAnalyzeBreakpointPage::acceptProject(ProjectContext project)
{
    const bool sameProject = m_project.matches(project); // 路径与真实项目 UUID 都须匹配。
    if (sameProject && project.generation < m_project.generation)
    {
        return;
    }
    if (!m_saving && sameProject && project.definitions == m_project.definitions)
    {
        m_project = std::move(project);
        m_pendingProject.reset();
        if (m_revisionStale)
        {
            m_revisionStale = false;
            m_saveError = ProjectError::None;
        }
        updateControls();
        return;
    }
    if (!m_saving && !hasDraftChanges() && !hasFormChanges())
    {
        loadProject(std::move(project));
        return;
    }
    // 换项目、定义冲突或写入途中仍保留列表与未提交表单，等待用户处理。
    m_pendingProject = std::move(project);
    updateControls();
}

// 已确认允许更换基准。以稳定 ID 恢复同项目的单选，写回新行则按定义内容认领。
void ActionAnalyzeBreakpointPage::loadProject(ProjectContext project)
{
    std::optional<BreakpointDefinition> selected; // 模型重置前保留当前单选的值。
    const auto* old = m_drafts->draftAt(m_table->currentIndex().row()); // 同步取值，不能跨模型重置使用。
    if (old && m_project.matches(project))
    {
        selected = *old;
    }
    clearForm();
    m_project = std::move(project);
    m_pendingProject.reset();
    m_revisionStale = false;
    m_saveError = ProjectError::None;
    m_saved = false;
    m_drafts->replaceRows(m_project.definitions);
    // 回读可能按稳定 ID 重排列表，因此不能恢复上一次的行号。
    for (int row = 0; selected && row < m_drafts->rowCount(); ++row)
    {
        const auto& next = *m_drafts->draftAt(row); // 新基准中的候选选择。
        const bool match = selected->breakpointDefinitionId.empty()
            ? selected->module == next.module && selected->location == next.location
            : selected->breakpointDefinitionId == next.breakpointDefinitionId;
        if (match)
        {
            m_table->selectionModel()->setCurrentIndex(m_drafts->index(row, 0),
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
            break;
        }
    }
    updateControls();
}

// 有修改时需用户明确确认丢弃，确认期间若换了候选项目或修订则保留原草稿。
void ActionAnalyzeBreakpointPage::openPendingProject()
{
    if (m_saving || !m_pendingProject)
    {
        return;
    }
    const auto pending = *m_pendingProject; // 冻结确认框关联的项目和修订。
    if (hasDraftChanges() || hasFormChanges())
    {
        const QPointer<ActionAnalyzeBreakpointPage> guard(this); // 确认框期间页面可能关闭。
        // 主程序统一安装 ThemedMessageBox 事件过滤器，接管标准确认框的首帧样式。
        const auto answer = QMessageBox::question(this, sourceText(QStringLiteral("载入项目断点")),
            sourceText(QStringLiteral("放弃当前断点草稿和表单改动，载入已保存的定义？")),
            QMessageBox::Discard | QMessageBox::Cancel, QMessageBox::Cancel);
        if (!guard || answer != QMessageBox::Discard || m_saving || !m_pendingProject
            || !m_pendingProject->matches(pending) || m_pendingProject->revisionId != pending.revisionId)
        {
            return;
        }
    }
    loadProject(*m_pendingProject);
}

// 仅在明确按下保存时写入。冻结完整草稿，成功采用 ProjectDocument 的实际修订和定义。
void ActionAnalyzeBreakpointPage::saveProject()
{
    if (m_saving || m_project.id.isEmpty() || m_revisionStale || !hasDraftChanges()
        || (m_pendingProject && m_project.matches(*m_pendingProject)))
    {
        return;
    }
    if (hasFormChanges())
    {
        reportError(Feedback::PendingEdit);
        return;
    }
    SaveRequest request{m_project.manifestPath, m_project.id.toStdString(),
        m_project.revisionId.toStdString(), m_drafts->rows()}; // 固定原项目，后续切换不改变目标。
    m_saving = true;
    m_saved = false;
    m_saveError = ProjectError::None;
    const auto ticket = m_saveOperation->submitTransaction<SaveRequest, SaveResult>(std::move(request), SaveDefinitions,
        [this](const SaveResult& saved, quint64) {
            m_saving = false;
            if (!saved.result)
            {
                reportSaveFailure(saved.result.error);
                return true;
            }
            // UI 此时仍绑定写入目标。写入中到达的另一项目保留为待载入项。
            const auto manifest = m_project.manifestPath; // 回执和工作台刷新使用同一清单身份。
            auto pending = std::move(m_pendingProject); // 不让模型重置吞掉先前的项目切换。
            const auto& info = saved.info; // 从持租约的文档返回的权威头。
            loadProject({manifest, QString::fromStdString(info.projectId), QString::fromStdString(info.settings.title),
                QString::fromStdString(info.revisionId), info.generation, info.settings.breakpointDefinitions.value_or(
                    std::vector<BreakpointDefinition>{})});
            m_pendingProject = std::move(pending);
            if (m_pendingProject && m_project.matches(*m_pendingProject))
            {
                auto latest = std::move(*m_pendingProject); // 可能早于保存提交，交给代次校验。
                m_pendingProject.reset();
                acceptProject(std::move(latest));
            }
            m_saved = true;
            updateControls();
            if (projectDefinitionsSaved)
            {
                projectDefinitionsSaved(manifest, QString::fromStdString(info.projectId));
            }
            return true;
        }, [this](std::exception_ptr) {
            m_saving = false;
            reportSaveFailure(ProjectError::IoError);
        });
    if (!ticket)
    {
        m_saving = false;
        reportSaveFailure(ProjectError::WriterBusy);
        return;
    }
    updateControls();
}

// 完成失败回执。写入期间若已回读同一未修改的定义，可以保留草稿并更新基准。
void ActionAnalyzeBreakpointPage::reportSaveFailure(ProjectError error)
{
    m_saveError = error;
    m_revisionStale = error == ProjectError::StaleRevision;
    if (m_pendingProject && m_project.matches(*m_pendingProject)
        && m_pendingProject->definitions == m_project.definitions)
    {
        auto latest = std::move(*m_pendingProject); // 只有更晚读取才能解释刚发生的修订冲突。
        m_pendingProject.reset();
        if (!m_revisionStale || latest.generation > m_project.generation)
        {
            acceptProject(std::move(latest));
        }
    }
    updateControls();
}

void ActionAnalyzeBreakpointPage::retranslate()
{
    const QSignalBlocker blocker(m_kind); // 切换语言时不改变录入值或草稿身份。
    if (m_kind->count() == 0)
    {
        m_kind->addItem(sourceText(QStringLiteral("模块内 RVA")), static_cast<int>(LocationKind::Rva));
        m_kind->addItem(sourceText(QStringLiteral("调试符号")), static_cast<int>(LocationKind::Symbol));
    }
    else
    {
        m_kind->setItemText(0, sourceText(QStringLiteral("模块内 RVA")));
        m_kind->setItemText(1, sourceText(QStringLiteral("调试符号")));
    }

    // 标签、按钮及定位选项保留原对象和选项索引，避免语言切换打断编辑。
    m_moduleLabel->setText(sourceText(QStringLiteral("模块文件名")));
    m_conditionLabel->setText(sourceText(QStringLiteral("断点条件（可选）")));
    m_condition->setPlaceholderText(QStringLiteral("stop.tid != 0u64"));
    m_condition->setToolTip(sourceText(QStringLiteral("条件随采样冻结，激活时使用原生停点字段；留空为无条件，手填冲突会拒绝附加。")));
    m_module->setPlaceholderText(sourceText(QStringLiteral("输入文件名，例如示例.exe")));
    m_kindLabel->setText(sourceText(QStringLiteral("定位方式")));
    m_enabled->setText(sourceText(QStringLiteral("在草稿中启用")));
    m_enabled->setToolTip(sourceText(QStringLiteral("只记录定义的启用状态。")));
    m_edit->setAccessibleName(sourceText(QStringLiteral("编辑所选断点")));
    m_remove->setAccessibleName(sourceText(QStringLiteral("删除所选断点")));
    m_prepareLive->setAccessibleName(sourceText(QStringLiteral("在实时控制页准备所选RVA断点")));
    m_clear->setAccessibleName(sourceText(QStringLiteral("放弃表单编辑")));
    m_save->setAccessibleName(sourceText(QStringLiteral("保存项目断点")));
    m_openPending->setAccessibleName(sourceText(QStringLiteral("载入项目断点")));
    m_openPending->setToolTip(m_openPending->accessibleName());
    m_activation->setText(sourceText(QStringLiteral("原生断点状态：未绑定。")));
    ks::ui::ApplyStatusRole(m_activation, ks::ui::StatusRole::Idle);
    m_drafts->retranslate();
    updateControls();
}

void ActionAnalyzeBreakpointPage::updateControls()
{
    using ks::ui::StatusRole;
    const auto* original = m_drafts->draftAt(m_editing.row()); // 所编定义提交前的原始位置。
    const bool editing = original != nullptr; // 没有编辑对象时，提交将新增定义。
    const bool symbol = m_kind->currentData().toInt() == static_cast<int>(LocationKind::Symbol); // 值输入模式。
    const auto selection = m_table->selectionModel()->selectedRows(); // 独立于编辑对象的单选。
    const bool selected = !selection.isEmpty(); // 当前列表动作是否有明确对象。
    const bool editable = !m_saving && !m_project.id.isEmpty(); // 必须先有可定位的项目，写入时冻结输入。
    m_form->setTitle(editing ? sourceText(QStringLiteral("编辑断点")) : sourceText(QStringLiteral("新增断点")));
    m_editTarget->setText(editing ? sourceText(QStringLiteral("正在编辑：%1 · %2"))
        .arg(QString::fromStdString(original->module.name), BreakpointDraftModel::displayLocation(*original)) : QString());
    m_editTarget->setVisible(editing);
    const auto identity = original ? IdentityText(*original) : QString(); // 显示所载入定义的精确定位附加资料。
    m_editIdentity->setText(identity);
    m_editIdentity->setVisible(!identity.isEmpty());
    m_locationLabel->setText(symbol ? sourceText(QStringLiteral("精确符号")) : sourceText(QStringLiteral("十六进制 RVA")));
    m_location->setPlaceholderText(symbol
        ? sourceText(QStringLiteral("输入符号名称")) : sourceText(QStringLiteral("例如 0x1234")));

    // 主动作说明如何提交定义。工具按钮可由辅助技术及 tooltip 读出具体动作。
    m_commit->setText(editing ? sourceText(QStringLiteral("更新草稿")) : sourceText(QStringLiteral("加入草稿")));
    m_commit->setToolTip(sourceText(QStringLiteral("校验当前表单并写入断点草稿列表。")));
    m_clear->setToolTip(sourceText(QStringLiteral("清除表单，保留已加入列表的草稿。")));
    m_form->setEnabled(editable);
    m_commit->setEnabled(editable);
    m_clear->setEnabled(editable && (editing || hasFormChanges()));
    m_edit->setEnabled(editable && selected);
    m_remove->setEnabled(editable && selected);
    const auto* liveDefinition = selected ? m_drafts->draftAt(selection.front().row()) : nullptr;
    const auto* liveRva = liveDefinition ? std::get_if<BreakpointRva>(&liveDefinition->location) : nullptr;
    m_prepareLive->setEnabled(!m_saving && m_livePreparation && liveRva && liveRva->rva &&
        liveDefinition->enabled && !liveDefinition->breakpointDefinitionId.empty() &&
        std::find(m_project.definitions.begin(), m_project.definitions.end(), *liveDefinition) != m_project.definitions.end());
    m_prepareLive->setToolTip(m_prepareLive->isEnabled()
        ? sourceText(QStringLiteral("选择同名模块后带入实时控制页；固定映像散列由原生附加核对实际装载文件，再武装断点。"))
        : sourceText(QStringLiteral("请选择已保存并启用的非零RVA定义。调试符号尚不支持此入口。")));
    m_edit->setToolTip(selected ? m_edit->accessibleName() : sourceText(QStringLiteral("请先选择一条草稿。")));
    m_remove->setToolTip(selected ? m_remove->accessibleName() : sourceText(QStringLiteral("请先选择一条草稿。")));

    // 空列表及行数独立于校验回执。失败时不隐藏现有有效草稿。
    const int count = m_drafts->rowCount(); // 草稿实际数量。
    m_summary->setVisible(!m_project.id.isEmpty());
    m_summary->setText(count == 0 ? sourceText(QStringLiteral("暂无断点草稿。填写位置后加入草稿。"))
        : sourceText(QStringLiteral("%1 条断点草稿")).arg(count));
    QString message; // 根据当前语言生成最近动作的文字回执。
    StatusRole role = StatusRole::Error; // 校验类回执默认显示失败色。
    switch (m_feedback)
    {
    case Feedback::InvalidModule:
        message = sourceText(QStringLiteral("请输入有效的模块文件名，无需目录路径。"));
        break;
    case Feedback::InvalidRva:
        message = sourceText(QStringLiteral("请输入 1 至 8 位十六进制 RVA，可带 0x 前缀。"));
        break;
    case Feedback::InvalidSymbol:
        message = sourceText(QStringLiteral("请输入单行调试符号，最多 512 个 UTF-8 字节。"));
        break;
    case Feedback::Duplicate:
        message = sourceText(QStringLiteral("相同模块和位置的断点草稿已存在。"));
        break;
    case Feedback::InvalidCondition:
        message = sourceText(QStringLiteral("断点条件无效：%1")).arg(m_conditionDiagnostic);
        break;
    case Feedback::Limit:
        message = sourceText(QStringLiteral("每个项目最多保存 %1 条断点定义。"))
            .arg(static_cast<int>(kProjectBreakpointLimit));
        break;
    case Feedback::PendingEdit:
        message = sourceText(QStringLiteral("请先提交或放弃表单中的修改。"));
        role = StatusRole::Warning;
        break;
    // 以下三个结果来自模型修改成功，页首的原生状态仍保持独立。
    case Feedback::Added:
        message = sourceText(QStringLiteral("已加入断点草稿。"));
        role = StatusRole::Success;
        break;
    case Feedback::Updated:
        message = sourceText(QStringLiteral("已更新断点草稿。"));
        role = StatusRole::Success;
        break;
    case Feedback::Removed:
        message = sourceText(QStringLiteral("已删除断点草稿。"));
        role = StatusRole::Success;
        break;
    case Feedback::None:
        break;
    }
    m_feedbackLabel->setText(message);
    m_feedbackLabel->setVisible(!message.isEmpty());
    ks::ui::ApplyStatusRole(m_feedbackLabel, role);
    updateProjectControls();
}

// 用户能在同一区域看到实际保存对象、未提交状态和失败恢复动作。
void ActionAnalyzeBreakpointPage::updateProjectControls()
{
    using ks::ui::StatusRole;
    const bool ready = !m_project.id.isEmpty(); // 只有经核验的项目可写。
    const bool conflicted = m_pendingProject && m_project.matches(*m_pendingProject); // 同项目定义已变。
    const bool draftChanged = hasDraftChanges(); // 已加入列表但未保存的改动。
    const bool formChanged = hasFormChanges(); // 尚未提交到列表的表单值。
    m_projectLabel->setText(ready ? sourceText(QStringLiteral("断点所属项目：%1\n%2"))
        .arg(m_project.title, m_project.manifestPath) : sourceText(QStringLiteral("请在“项目与采样”中打开项目。")));
    m_projectLabel->setToolTip(ready ? m_projectLabel->text() + QLatin1Char('\n') + m_project.revisionId : QString());
    m_save->setEnabled(ready && !m_saving && draftChanged && !formChanged && !m_revisionStale && !conflicted);
    m_openPending->setVisible(m_pendingProject.has_value());
    m_openPending->setEnabled(!m_saving);

    QString status; // 当前项目存储状态文本，优先显示需要处理的条件。
    StatusRole role = StatusRole::Idle; // 用共享语义色显示运行与冲突。
    if (m_saving)
    {
        status = sourceText(QStringLiteral("正在保存项目断点…"));
        role = StatusRole::Info;
    }
    else if (conflicted)
    {
        status = sourceText(QStringLiteral("项目中的断点已更新。当前草稿已保留，请确认后载入新定义。"));
        role = StatusRole::Warning;
    }
    else if (m_revisionStale)
    {
        status = sourceText(QStringLiteral("项目修订已变更。请在“项目与采样”中重新读取项目，草稿已保留。"));
        role = StatusRole::Warning;
    }
    else if (m_saveError != ProjectError::None)
    {
        status = m_saveError == ProjectError::WriterBusy
            ? sourceText(QStringLiteral("项目正在写入。草稿已保留，请稍后重试。"))
            : sourceText(QStringLiteral("无法保存项目断点（%1）。草稿已保留。"))
                .arg(QString::fromLatin1(ProjectErrorName(m_saveError)));
        role = StatusRole::Error;
    }
    else if (formChanged)
    {
        status = sourceText(QStringLiteral("请先提交或放弃表单中的修改。"));
        role = StatusRole::Warning;
    }
    else if (draftChanged)
    {
        status = sourceText(QStringLiteral("断点草稿尚未保存到项目。"));
        role = StatusRole::Warning;
    }
    else if (m_saved)
    {
        status = sourceText(QStringLiteral("已保存项目断点。"));
        role = StatusRole::Success;
    }

    // 与工作台所选项目不一致时，说明当前仍保留旧项目，并为待载入项提供目标提示。
    if (m_pendingProject && !conflicted)
    {
        if (!status.isEmpty())
        {
            status += QLatin1Char('\n');
        }
        status += sourceText(QStringLiteral("待载入项目：%1")).arg(m_pendingProject->title);
    }
    m_openPending->setToolTip(m_pendingProject
        ? sourceText(QStringLiteral("载入项目断点：%1")).arg(m_pendingProject->manifestPath) : m_openPending->accessibleName());
    m_projectStatus->setText(status);
    m_projectStatus->setVisible(!status.isEmpty());
    ks::ui::ApplyStatusRole(m_projectStatus, role);
    m_save->setToolTip(m_save->isEnabled() ? sourceText(QStringLiteral("保存到项目：%1")).arg(m_project.manifestPath)
        : (status.isEmpty() ? m_projectLabel->text() : status));
}

bool ActionAnalyzeBreakpointPage::hasFormChanges() const
{
    const auto* draft = m_drafts->draftAt(m_editing.row()); // 仅在已载入某行时可用。
    const int kind = m_kind->currentData().toInt(); // 当前草稿的定位方式。
    if (!draft)
    {
        return !m_module->text().isEmpty() || !m_location->text().isEmpty() || !m_condition->text().isEmpty()
            || kind != static_cast<int>(LocationKind::Rva) || !m_enabled->isChecked();
    }
    return m_module->text() != QString::fromStdString(draft->module.name) || m_location->text() != LocationText(*draft)
        || m_condition->text() != (draft->condition ? QString::fromStdString(draft->condition->source) : QString())
        || kind != static_cast<int>(DefinitionKind(*draft)) || m_enabled->isChecked() != draft->enabled;
}

void ActionAnalyzeBreakpointPage::formChanged()
{
    m_conditionDiagnostic.clear(); // 编辑只清除旧诊断，不改列表中已提交的规则。
    m_feedback = Feedback::None;
    updateControls();
}

void ActionAnalyzeBreakpointPage::clearForm()
{
    // 四个控件共同构成一次草稿重置，阻止中间状态触发 UI 刷新。
    const QSignalBlocker moduleBlock(m_module);
    const QSignalBlocker locationBlock(m_location);
    const QSignalBlocker conditionBlock(m_condition);
    const QSignalBlocker kindBlock(m_kind);
    const QSignalBlocker enabledBlock(m_enabled);
    m_editing = QPersistentModelIndex();
    m_module->clear();
    m_location->clear();
    m_condition->clear();
    m_kind->setCurrentIndex(0);
    m_enabled->setChecked(true);
    formChanged();
}

void ActionAnalyzeBreakpointPage::editSelection()
{
    if (m_saving)
    {
        return;
    }
    const auto selected = m_table->selectionModel()->selectedRows(); // 明确读取本次所选。
    if (selected.isEmpty() || selected.first() == QModelIndex(m_editing))
    {
        return;
    }
    if (hasFormChanges())
    {
        reportError(Feedback::PendingEdit);
        return;
    }

    // 装载所选行后记住该定义。切换选区不改变后续更新的对象。
    const QModelIndex index = selected.first(); // 取出所属模型的源行。
    const auto* draft = m_drafts->draftAt(index.row()); // 同步填入的草稿值。
    if (!draft)
    {
        return;
    }
    const QSignalBlocker moduleBlock(m_module);
    const QSignalBlocker locationBlock(m_location);
    const QSignalBlocker conditionBlock(m_condition);
    const QSignalBlocker kindBlock(m_kind);
    const QSignalBlocker enabledBlock(m_enabled);
    m_editing = index;
    m_module->setText(QString::fromStdString(draft->module.name));
    m_location->setText(LocationText(*draft));
    m_condition->setText(draft->condition ? QString::fromStdString(draft->condition->source) : QString());
    m_kind->setCurrentIndex(m_kind->findData(static_cast<int>(DefinitionKind(*draft))));
    m_enabled->setChecked(draft->enabled);
    formChanged();
    m_module->setFocus();
    m_workspace->revealParameter(m_module);
}

void ActionAnalyzeBreakpointPage::removeSelection()
{
    if (m_saving)
    {
        return;
    }
    const auto selected = m_table->selectionModel()->selectedRows(); // 只移除明确所选的一条。
    if (selected.isEmpty())
    {
        return;
    }
    const QModelIndex index = selected.first(); // 此次删除使用按下按钮时的选区。
    if (index == QModelIndex(m_editing))
    {
        if (hasFormChanges())
        {
            reportError(Feedback::PendingEdit);
            return;
        }
        clearForm();
    }
    m_drafts->erase(index.row());
    m_saved = false;
    m_feedback = Feedback::Removed;
    updateControls();
}

void ActionAnalyzeBreakpointPage::commitForm()
{
    if (m_saving || m_project.id.isEmpty())
    {
        return;
    }
    const auto moduleText = m_module->text(); // 保持字符串存活直到验证及转换完成。
    const auto module = TrimDefinition(moduleText); // 模块基础名保留合法的 Unicode。
    if (!IsModuleName(module))
    {
        reportError(Feedback::InvalidModule, m_module);
        return;
    }
    const auto kind = static_cast<LocationKind>(m_kind->currentData().toInt()); // 表单选择的定位方式。
    const auto locationText = m_location->text(); // 原始定位值，供下方只读视图引用。
    const auto location = TrimDefinition(locationText); // 按项目格式规范化首尾 ASCII 空格。
    const auto* original = m_drafts->draftAt(m_editing.row()); // 无需重建已经保存的定义身份。
    BreakpointDefinition draft = original ? *original : BreakpointDefinition{}; // 新项由存储层分配 ID。
    const auto moduleName = module.toUtf8().toStdString(); // 同存储层使用 UTF-8 标签。
    const bool sameModule = original && SameModule(original->module.name, moduleName);
    draft.module.name = moduleName;
    if (!sameModule)
    {
        draft.module.imageSha256.reset(); // 改用另一模块时，原映像标识不再适用。
    }
    // RVA 使用整数以识别等价输入，符号保留原大小写与同模块 PDB 资料。
    if (kind == LocationKind::Rva)
    {
        const auto rva = ParseRva(location); // 模块内 32 位偏移，零也合法。
        if (!rva)
        {
            reportError(Feedback::InvalidRva, m_location);
            return;
        }
        draft.location = BreakpointRva{*rva};
    }
    else
    {
        if (!IsDefinitionText(location, kSymbolLength))
        {
            reportError(Feedback::InvalidSymbol, m_location);
            return;
        }
        const auto* oldSymbol = sameModule ? std::get_if<BreakpointSymbol>(&original->location) : nullptr;
        draft.location = BreakpointSymbol{location.toUtf8().toStdString(), oldSymbol ? oldSymbol->pdb : std::nullopt};
    }

    // 明确提交到冻结的表单对象。排序或选区变化不能改写另一个草稿。
    const int editingRow = m_editing.row(); // -1 代表新增，其他值来自持续有效的模型索引。
    if (editingRow < 0 && m_drafts->rows().size() >= kProjectBreakpointLimit)
    {
        reportError(Feedback::Limit);
        return;
    }
    if (m_drafts->contains(draft, editingRow))
    {
        reportError(Feedback::Duplicate, m_location);
        return;
    }
    draft.enabled = m_enabled->isChecked();
    draft.condition.reset(); // 显式清空表示删除旧条件，不隐式继承。
    if (!m_condition->text().isEmpty())
    {
        const auto source = m_condition->text().toUtf8(); // 保存原UTF-8，不修剪或重写谓词。
        const auto prepared = ks::cli::action_analyze::control::PrepareNativeStopCondition(
            std::string_view(source.constData(), static_cast<std::size_t>(source.size())),
            Ksword::ActionAnalyze::Rules::Phase::Observation, "predicate-expr-v3");
        if (prepared.error != Ksword::ActionAnalyze::Rules::ExpressionError::None)
        {
            const auto diagnostic = Ksword::ActionAnalyze::Rules::ExpressionErrorId(prepared.error); // 静态ID来自原准备器。
            m_conditionDiagnostic = QString::fromLatin1(diagnostic.data(), static_cast<qsizetype>(diagnostic.size()));
            reportError(Feedback::InvalidCondition, m_condition);
            return;
        }
        draft.condition = Ksword::ActionAnalyze::BreakpointCondition{source.toStdString()};
    }
    m_saved = false;
    const QModelIndex submitted = m_drafts->put(editingRow, draft); // 成功后的实际列表行。
    clearForm();
    m_table->selectionModel()->setCurrentIndex(submitted, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
    m_table->scrollTo(submitted);
    m_feedback = editingRow < 0 ? Feedback::Added : Feedback::Updated;
    updateControls();
}

void ActionAnalyzeBreakpointPage::reportError(Feedback feedback, QWidget* field)
{
    m_feedback = feedback;
    updateControls();
    if (field)
    {
        field->setFocus();
        m_workspace->revealParameter(field);
    }
}
}
