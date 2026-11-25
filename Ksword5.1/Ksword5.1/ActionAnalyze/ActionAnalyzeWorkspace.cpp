#include "ActionAnalyzeWorkspace.h"
#include "../Internationalization/LanguageManager.h"
#include "../MonitorDock/MonitorDock.h"
#include "../MonitorDock/MonitorNavigationSchema.h"
#include "../UI/AsyncOperation.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/FlowLayout.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeBinding.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QDateTime>
#include <QEvent>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
#include <QStandardItemModel>
#include <QTimeZone>
#include <QVBoxLayout>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;

    // 将已保存的 UTC 时间呈现到毫秒，详情另行保留原始 100ns 数值。
    QString DisplayTime(quint64 ticks)
    {
        constexpr qint64 kEpochOffsetMillis = 11644473600000;
        const auto utc = QDateTime::fromMSecsSinceEpoch(
            static_cast<qint64>(ticks / 10000) - kEpochOffsetMillis, QTimeZone::utc());
        return utc.toString(Qt::ISODateWithMs);
    }

    // 创建纯文本状态标签，避免将项目标题或路径解释成富文本。
    QLabel* StatusLabel(QWidget* parent)
    {
        auto* label = new QLabel(parent);
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        return label;
    }

    // 把后台的文件级问题映射到当前语言，可用同一入口重试。
    QString DescribeProblem(const ReadProblem& problem)
    {
        switch (problem.status)
        {
        case ReadStatus::Unavailable:
            return sourceText(QStringLiteral("无法读取文件：%1")).arg(problem.relativeFile);
        case ReadStatus::Invalid:
            return sourceText(QStringLiteral("文件内容或校验值无效：%1")).arg(problem.relativeFile);
        case ReadStatus::Unsupported:
            return sourceText(QStringLiteral("不支持此文件版本或类型：%1")).arg(problem.relativeFile);
        default:
            return {};
        }
    }
}

// 目录表按需读取冻结行；后台完成后一次换代，不逐格创建 QTableWidgetItem。
class SampleCatalogModel final : public QAbstractTableModel
{
public:
    using QAbstractTableModel::QAbstractTableModel;

    // Qt 传入父索引；目录是平面表，返回根层样本数。
    int rowCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_rows.size());
    }

    // Qt 传入父索引；根层返回目录的三列，其它索引没有子列。
    int columnCount(const QModelIndex& parent = {}) const override
    {
        return parent.isValid() ? 0 : 3;
    }

    // 返回指定单元格文本和 tooltip，同一稳定行可用于详情查询。
    QVariant data(const QModelIndex& index, int role) const override
    {
        const auto* row = sampleAt(index.row()); // 该单元格所属的冻结采样。
        if (!index.isValid() || !row || (role != Qt::DisplayRole && role != Qt::ToolTipRole))
        {
            return {};
        }
        switch (index.column())
        {
        case 0:
            return row->title;
        case 1:
            return DisplayTime(row->createdUtc);
        case 2:
            return row->id;
        default:
            return {};
        }
    }

    // 水平表头随应用语言更新，垂直索引使用 Qt 默认实现。
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override
    {
        if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
        {
            switch (section)
            {
            case 0:
                return sourceText(QStringLiteral("采样名称"));
            case 1:
                return sourceText(QStringLiteral("创建时间 (UTC)"));
            case 2:
                return sourceText(QStringLiteral("采样 ID"));
            }
        }
        return QAbstractTableModel::headerData(section, orientation, role);
    }

    // 提交新目录，读取相同项目时由页面按稳定 ID 恢复当前行。
    void replaceRows(const QList<SampleSummary>& rows)
    {
        beginResetModel();
        m_rows = rows;
        endResetModel();
    }

    // 更新本地化表头，无须重建行或重发文件请求。
    void retranslate()
    {
        emit headerDataChanged(Qt::Horizontal, 0, 2);
    }

    // 返回指定源行或 nullptr，调用者立即复制到后台值请求。
    const SampleSummary* sampleAt(int index) const
    {
        return index >= 0 && index < m_rows.size() ? &m_rows.at(index) : nullptr;
    }

private:
    QList<SampleSummary> m_rows; // 只读目录快照的共享副本。
};

// 构建页根、项目工具带及真实子页，首次打开保持空闲。
ActionAnalyzeWorkspace::ActionAnalyzeWorkspace(QWidget* parent)
    : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this); // 共享页框内的纵向工作区。
    layout->setSpacing(6);
    ks::ui::StyleWorkspaceContentFrame(this);
    m_projectRead = new ks::ui::AsyncOperation(this);
    m_sampleRead = new ks::ui::AsyncOperation(this);

    // 项目操作与当前会话状态共用顶部工具带，窄窗按控件自然宽度换行。
    auto* toolbar = new QWidget(this); // 项目操作工具带。
    ks::ui::StylePrimaryToolbar(toolbar);
    auto* tools = new ks::ui::FlowLayout(toolbar, 8, 8, 6); // 按可用宽度换行的动作布局。
    m_open = new QPushButton(toolbar);
    ks::ui::ApplyFlatButtonTheme(m_open, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_open, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
    // 重读和取消使用项目主题的方形图标按钮，保留可访问名称及释义。
    m_retry = new QPushButton(toolbar);
    KswordTheme::ApplyStandardIconButtonMetrics(m_retry);
    ks::ui::SetThemeButtonIcon(m_retry, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_cancel = new QPushButton(toolbar);
    KswordTheme::ApplyStandardIconButtonMetrics(m_cancel);
    ks::ui::SetThemeButtonIcon(m_cancel, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    for (auto* button : {m_open, m_retry, m_cancel}) // 按自然操作顺序加入工具带。
    {
        tools->addWidget(button);
    }
    ks::ui::NormalizeToolbarLayout(tools);
    layout->addWidget(toolbar);

    // 单独保留已提交数据路径和当前读进度，失败仍可见原项目身份。
    m_source = StatusLabel(this);
    m_manifestPath = StatusLabel(this);
    m_status = StatusLabel(this);
    layout->addWidget(m_source);
    layout->addWidget(m_manifestPath);
    layout->addWidget(m_status);

    // 概览与项目目录各自保持子页选择。未接通的规则和断点留待真实编辑器。
    m_tabs = new QTabWidget(this);
    ks::monitor::AddMonitorNavigationTab(m_tabs, createOverview(), QString::fromLatin1(ks::monitor::ActionAnalyzeOverviewId));
    ks::monitor::AddMonitorNavigationTab(m_tabs, createProjectBrowser(), QString::fromLatin1(ks::monitor::ActionAnalyzeSamplesId));
    ks::ui::StyleChildPageTabs(m_tabs);
    layout->addWidget(m_tabs, 1);
    m_sessionStatus = StatusLabel(this);
    layout->addWidget(m_sessionStatus);
    retranslateOverview();

    // 所有工作由用户发起，导航及主题切换不执行文件 I/O。
    connect(m_open, &QPushButton::clicked, this, [this]() {
        chooseProject();
    });
    connect(m_retry, &QPushButton::clicked, this, [this]() {
        openProject(m_requestedPath);
    });
    connect(m_cancel, &QPushButton::clicked, this, [this]() {
        m_projectRead->cancel();
        m_readingProject = false;
        m_projectCanceled = true;
        updateStatus();
    });
    updateStatus();
    updateSampleDocument();
}

// 先阻断回投，再让 QWidget 销毁控件，后台不借用本页任何对象。
ActionAnalyzeWorkspace::~ActionAnalyzeWorkspace()
{
    m_projectRead->close();
    m_sampleRead->close();
}

// 统一处理语言变化，保持已选采样及当前项目快照。
void ActionAnalyzeWorkspace::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_catalog)
    {
        m_catalog->retranslate();
        retranslateOverview();
        updateStatus();
        updateSampleDocument();
    }
}

// 概览按设计放置左瀑布、中部事件、右上操作状态和底部传播资料。
QWidget* ActionAnalyzeWorkspace::createOverview()
{
    auto* page = new QWidget(m_tabs);
    auto* layout = new QVBoxLayout(page);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* vertical = new QSplitter(Qt::Vertical, page);
    auto* middle = new QSplitter(Qt::Horizontal, vertical);
    middle->setChildrenCollapsible(false);
    layout->addWidget(vertical);

    // 还没有事件时间戳时不绘制轴或泳道标记。
    auto* waterfall = new QWidget(middle);
    ks::ui::StylePrimaryContentPanel(waterfall, false);
    auto* waterfallLayout = new QVBoxLayout(waterfall);
    waterfallLayout->setContentsMargins(8, 8, 8, 8);
    m_waterfallTitle = new QLabel(waterfall);
    ks::ui::StylePrimarySectionTitle(m_waterfallTitle);
    m_waterfallStatus = StatusLabel(waterfall);
    waterfallLayout->addWidget(m_waterfallTitle);
    waterfallLayout->addWidget(m_waterfallStatus);
    waterfallLayout->addStretch(1);

    // 两路显示开关独立，当前未取得任何来源时皆不可用。
    auto* eventPane = new QWidget(middle);
    auto* eventLayout = new QVBoxLayout(eventPane);
    eventLayout->setContentsMargins(0, 0, 0, 0);
    eventLayout->setSpacing(6);
    auto* toolbar = new QWidget(eventPane);
    ks::ui::StylePrimaryToolbar(toolbar);
    auto* sources = new ks::ui::FlowLayout(toolbar, 8, 8, 6);
    m_apiSource = new QCheckBox(toolbar);
    m_etwSource = new QCheckBox(toolbar);
    m_apiSource->setEnabled(false);
    m_etwSource->setEnabled(false);
    sources->addWidget(m_apiSource);
    sources->addWidget(m_etwSource);
    m_liveStatus = StatusLabel(toolbar);
    m_liveStatus->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    sources->addExpandingWidget(m_liveStatus, 195);
    ks::ui::NormalizeToolbarLayout(sources);
    eventLayout->addWidget(toolbar);

    // 仍展示规定的五列。没有真实项目事件时共享操作条由模型计数禁用。
    m_eventStatus = StatusLabel(eventPane);
    eventLayout->addWidget(m_eventStatus);
    auto* eventTable = new ks::ui::TableActionTableView(eventPane);
    eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    eventTable->verticalHeader()->hide();
    m_events = new QStandardItemModel(0, 5, eventTable);
    ks::ui::ResultTableCapabilities capabilities;
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    ks::ui::ResultTableHost::ensure(eventTable)->bindModel(m_events, {{0, QStringLiteral("time")},
        {1, QStringLiteral("pid")}, {2, QStringLiteral("tid")}, {3, QStringLiteral("process")},
        {4, QStringLiteral("event")}}, capabilities);
    eventLayout->addWidget(eventTable, 1);
    middle->setStretchFactor(0, 0);
    middle->setStretchFactor(1, 1);
    middle->setSizes({185, 720});
    vertical->addWidget(middle);

    // 缺少实例及关系证据时保持自然高度，空间留给中央视图。
    auto* propagation = new QWidget(vertical);
    ks::ui::StylePrimaryContentPanel(propagation, false);
    auto* graphLayout = new QVBoxLayout(propagation);
    graphLayout->setContentsMargins(8, 8, 8, 8);
    m_propagationTitle = new QLabel(propagation);
    ks::ui::StylePrimarySectionTitle(m_propagationTitle);
    m_propagationStatus = StatusLabel(propagation);
    graphLayout->addWidget(m_propagationTitle);
    graphLayout->addWidget(m_propagationStatus);
    vertical->addWidget(propagation);
    vertical->setStretchFactor(0, 1);
    return page;
}

// 更新可见列名和无来源时的指引，状态由 updateStatus 更新。
void ActionAnalyzeWorkspace::retranslateOverview()
{
    m_waterfallTitle->setText(sourceText(QStringLiteral("时间瀑布")));
    m_propagationTitle->setText(sourceText(QStringLiteral("证据传播")));
    m_apiSource->setText(QStringLiteral("API"));
    m_etwSource->setText(QStringLiteral("ETW"));
    const auto reason = sourceText(QStringLiteral("当前项目格式不包含事件来源。"));
    m_apiSource->setToolTip(reason);
    m_etwSource->setToolTip(reason);
    m_liveStatus->setText(sourceText(QStringLiteral("实时操作需要活动会话")));
    m_events->setHorizontalHeaderLabels({sourceText(QStringLiteral("时间")), QStringLiteral("PID"),
        QStringLiteral("TID"), sourceText(QStringLiteral("进程")), sourceText(QStringLiteral("事件"))});
}

// 目录与详情沿用 Monitor 风险中心的共享模型宿主及详情布局。
QWidget* ActionAnalyzeWorkspace::createProjectBrowser()
{
    auto* page = new QWidget(m_tabs); // 项目目录与详情的实际页签。
    auto* layout = new QVBoxLayout(page); // 放置局部工具带和目录分栏。
    layout->setContentsMargins(0, 0, 0, 0);
    // 重读选中采样独立于项目工具带，原生按钮支持键盘直接操作。
    auto* toolbar = new QWidget(page); // 当前采样的恢复入口。
    auto* tools = new QHBoxLayout(toolbar); // 单项恢复动作保持自然高度。
    ks::ui::StylePrimaryToolbar(toolbar);
    m_sampleRetry = new QPushButton(toolbar);
    ks::ui::SetThemeButtonIcon(m_sampleRetry, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    tools->addWidget(m_sampleRetry);
    tools->addStretch();
    ks::ui::NormalizeToolbarRow(tools);
    layout->addWidget(toolbar);

    auto* splitter = new QSplitter(Qt::Vertical, page); // 可调整目录和字段详情的高度。
    layout->addWidget(splitter);

    // 单选目录表支持共享的紧凑复制与导出，不允许改写目录。
    m_samples = new ks::ui::TableActionTableView(splitter);
    m_catalog = new SampleCatalogModel(m_samples);
    m_samples->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_samples->setSelectionMode(QAbstractItemView::SingleSelection);
    m_samples->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_samples->setAlternatingRowColors(true);
    m_samples->verticalHeader()->hide();
    m_catalogHost = ks::ui::ResultTableHost::ensure(m_samples);
    ks::ui::ResultTableCapabilities capabilities;
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    m_catalogHost->bindModel(m_catalog, {{0, QStringLiteral("title")},
        {1, QStringLiteral("createdUtc")}, {2, QStringLiteral("sampleId")}}, capabilities);
    splitter->addWidget(m_samples);

    // 详情搜索与复制/导出始终使用同一冻结字段文档。
    m_fields = new ks::ui::StructuredFieldView(splitter);
    m_fields->setValueModelProjection();
    m_fields->setHiddenProjectionDeferred();
    splitter->addWidget(m_fields);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    ks::ui::DetailLayoutRegistry::registerStructuredHost(m_samples, m_fields, page, splitter, m_samples, m_fields);
    connect(m_samples->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex&, const QModelIndex&) { readSelectedSample(); });
    connect(m_sampleRetry, &QPushButton::clicked, this, [this]() {
        if (!m_readingSample)
        {
            readSelectedSample();
        }
    });
    return page;
}

// 打开原生只读文件选择器；取消选择不会替换当前项目。
void ActionAnalyzeWorkspace::chooseProject()
{
    const QString path = QFileDialog::getOpenFileName(this,
        sourceText(QStringLiteral("打开行为分析项目")), m_requestedPath,
        sourceText(QStringLiteral("行为分析项目 (project.ksaproj)")), nullptr, QFileDialog::ReadOnly);
    if (!path.isEmpty())
    {
        openProject(path);
    }
}

// 按明确选定的路径读取；失败只更新操作回执，原目录保持可查看。
void ActionAnalyzeWorkspace::openProject(const QString& path)
{
    if (path.isEmpty())
    {
        return;
    }
    m_requestedPath = path;
    m_readingProject = true;
    m_projectCanceled = false;
    m_projectProblem = {};
    updateStatus();
    m_projectRead->submit<QString, ProjectSnapshot>(path,
        [](const QString& selected, const ks::ui::AsyncOperationToken& token) {
            return ReadProjectCatalog(selected, [&token]() { return token.isCanceled(); });
        },
        [this](const ProjectSnapshot& snapshot, quint64 generation) {
            const auto commit = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("action_analyze_catalog"),
                {m_catalogHost}, [this, snapshot, generation]() {
                    if (m_projectRead->isCurrent(generation))
                    {
                        applyProject(snapshot);
                    }
                    m_projectRead->completeDeferred(generation);
                });
            // 拒绝提交时保留已显示的目录，并结束本次读取的可见状态。
            if (commit == ks::ui::UiCommitSubmission::Rejected)
            {
                m_readingProject = false;
                m_projectProblem = {ReadStatus::Unavailable, QStringLiteral("project.ksaproj")};
                updateStatus();
            }
            return commit != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            m_readingProject = false;
            m_projectProblem = {ReadStatus::Unavailable, m_requestedPath};
            updateStatus();
        });
}

// 仅在读取成功后替换目录。同项目刷新使用稳定 UUID 恢复选择。
void ActionAnalyzeWorkspace::applyProject(const ProjectSnapshot& snapshot)
{
    m_readingProject = false;
    m_projectProblem = snapshot.problem;
    if (snapshot.problem.status != ReadStatus::Ready)
    {
        updateStatus();
        return;
    }
    // 同一项目以项目与清单路径共同识别；目录重建后只读一次所选采样。
    const bool sameProject = snapshot.id == m_project.id && snapshot.manifestPath == m_project.manifestPath;
    const auto oldId = sameProject ? m_selected.id : QString(); // 尝试恢复的目录 UUID。
    if (!sameProject)
    {
        m_selected = {};
        m_hasVerifiedSample = false;
        m_sampleDetails = {};
    }
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_fields);
    m_project = snapshot;
    m_catalog->replaceRows(snapshot.samples);

    // 恢复精确行；换项目后由用户进入目录并选择。读取完成不动当前页签。
    for (qsizetype row = 0; !oldId.isEmpty() && row < snapshot.samples.size(); ++row)
    {
        if (snapshot.samples.at(row).id == oldId)
        {
            m_samples->selectionModel()->setCurrentIndex(m_catalog->index(static_cast<int>(row), 0),
                QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
            break;
        }
    }
    if (!m_samples->currentIndex().isValid())
    {
        readSelectedSample();
    }
    updateStatus();
}

// 任何新选择使已排队旧详情失效；后台只使用冻结的项目及采样身份。
void ActionAnalyzeWorkspace::readSelectedSample()
{
    m_sampleRead->cancel();
    const auto* row = m_catalog->sampleAt(m_samples->currentIndex().row()); // 新请求绑定的目录行。
    // 同项目、同采样及同描述散列才可沿用旧配置；不同结果不进入当前文档。
    if (!row || row->id != m_selected.id || row->descriptionHash != m_selected.descriptionHash)
    {
        m_sampleDetails = {};
        m_hasVerifiedSample = false;
    }
    m_selected = row ? *row : SampleSummary{};
    m_sampleProblem = {};
    m_readingSample = row != nullptr;
    updateStatus();
    updateSampleDocument();
    if (!row)
    {
        return;
    }

    const SampleRequest request{m_project.manifestPath, m_project.id, m_selected};
    m_sampleRead->submit<SampleRequest, SampleDetails>(request,
        [](const SampleRequest& selected, const ks::ui::AsyncOperationToken& token) {
            return ReadSampleDetails(selected, [&token]() { return token.isCanceled(); });
        },
        [this](const SampleDetails& details, quint64) {
            m_readingSample = false;
            m_sampleProblem = details.problem;
            // 本次失败单独显示，最后验证成功的同一采样配置仍可查看。
            if (details.problem.status == ReadStatus::Ready)
            {
                m_sampleDetails = details;
                m_hasVerifiedSample = true;
            }
            updateStatus();
            updateSampleDocument();
            return true;
        },
        [this](std::exception_ptr) {
            m_readingSample = false;
            m_sampleProblem = {ReadStatus::Unavailable, QStringLiteral("sample.json")};
            updateStatus();
            updateSampleDocument();
        });
}

// 从一个字段文档向详情栏、复制与导出提供一致的当前采样内容。
void ActionAnalyzeWorkspace::updateSampleDocument()
{
    ks::ui::FieldDocument document;
    document.title = QStringLiteral("采样详情");
    if (m_selected.id.isEmpty())
    {
        document.note(QStringLiteral("从目录选择一项采样以查看冻结的配置。"));
    }
    else
    {
        // 目录身份与读回的样本内容分开，读失败仍可核对用户选择了哪一项。
        document.section(QStringLiteral("采样身份"))
            .field(QStringLiteral("采样名称"), m_selected.title)
            .field(QStringLiteral("采样 ID"), m_selected.id)
            .field(QStringLiteral("创建时间 (UTC)"), DisplayTime(m_selected.createdUtc))
            .field(QStringLiteral("FILETIME (100 ns)"), QString::number(m_selected.createdUtc))
            .field(QStringLiteral("项目修订 ID"), m_selected.revisionId)
            .field(QStringLiteral("配置快照 ID"), m_selected.snapshotId);
        if (m_readingSample)
        {
            document.note(QStringLiteral("正在读取采样详情…"));
        }
        else if (m_sampleProblem.status != ReadStatus::Ready)
        {
            document.note(DescribeProblem(m_sampleProblem));
        }

        // 跨读取保留的配置明确标成上次验证结果，避免被当成这一次读回。
        if (m_hasVerifiedSample)
        {
            const auto title = m_readingSample || m_sampleProblem.status != ReadStatus::Ready
                ? QStringLiteral("上次验证的冻结配置") : QStringLiteral("冻结配置");
            document.section(title)
                .field(QStringLiteral("采集状态"), QStringLiteral("未采集"), true)
                .field(QStringLiteral("项目标题"), m_sampleDetails.configurationTitle)
                .field(QStringLiteral("说明"), m_sampleDetails.configurationNotes)
                .field(QStringLiteral("配置语义散列"), m_sampleDetails.configurationHash);
        }
    }
    m_fields->setDocument(document);
}

// 并列更新操作进度、真实发布身份和采样的可用性。
void ActionAnalyzeWorkspace::updateStatus()
{
    using ks::ui::StatusRole;
    const bool hasProject = !m_project.id.isEmpty();
    m_open->setText(sourceText(QStringLiteral("打开行为分析项目")));
    m_open->setToolTip(sourceText(QStringLiteral("选择项目清单，以只读方式载入。")));
    m_retry->setAccessibleName(sourceText(QStringLiteral("重新读取")));
    m_retry->setToolTip(m_requestedPath.isEmpty()
        ? sourceText(QStringLiteral("请先选择项目清单。"))
        : sourceText(QStringLiteral("重新读取所选项目：%1")).arg(m_requestedPath));
    m_cancel->setAccessibleName(sourceText(QStringLiteral("取消读取")));
    m_cancel->setToolTip(sourceText(QStringLiteral("取消本次读取并保留已显示的项目。")));
    m_cancel->setVisible(m_readingProject);
    m_retry->setEnabled(!m_requestedPath.isEmpty() && !m_readingProject);
    m_sampleRetry->setText(sourceText(QStringLiteral("重新读取采样")));
    m_sampleRetry->setToolTip(sourceText(QStringLiteral("重读选中采样的冻结配置。")));
    // 在途读保持按钮可获焦；再次触发时由 Click 处理器忽略。
    m_sampleRetry->setEnabled(!m_selected.id.isEmpty());
    m_source->setVisible(hasProject);
    m_manifestPath->setVisible(hasProject);
    m_manifestPath->setText(m_project.manifestPath);
    m_source->setText(hasProject ? sourceText(QStringLiteral("%1 · 项目 %2 · 代次 %3 · 修订 %4"))
        .arg(m_project.title, m_project.id, QString::number(m_project.generation), m_project.revisionId) : QString());

    // 加载、取消、加载失败、有效空目录与成功目录使用独立提示。
    StatusRole role = StatusRole::Idle;
    QString message;
    if (m_readingProject)
    {
        message = sourceText(QStringLiteral("正在读取项目：%1")).arg(m_requestedPath);
        role = StatusRole::Info;
    }
    else if (m_projectCanceled)
    {
        message = sourceText(QStringLiteral("已取消读取。"));
    }
    else if (m_projectProblem.status != ReadStatus::Ready)
    {
        message = sourceText(QStringLiteral("未能打开 %1。%2"))
            .arg(m_requestedPath, DescribeProblem(m_projectProblem));
        role = StatusRole::Error;
    }
    else if (!hasProject)
    {
        message = sourceText(QStringLiteral("选择项目清单以查看离线采样。"));
    }
    else if (m_project.samples.isEmpty())
    {
        message = sourceText(QStringLiteral("项目目录已读取，尚无采样。"));
        role = StatusRole::Success;
    }
    else
    {
        message = sourceText(QStringLiteral("已读取 %1 项采样。"))
            .arg(static_cast<qlonglong>(m_project.samples.size()));
        role = StatusRole::Success;
    }
    m_status->setText(message);
    ks::ui::ApplyStatusRole(m_status, role);

    // 只有读回的采样描述明确标成 not-collected 时才显示未采集。
    QString eventState = sourceText(QStringLiteral("在项目与采样中选择采样。"));
    if (m_readingSample)
    {
        eventState = sourceText(QStringLiteral("正在读取采样详情…"));
    }
    else if (m_sampleProblem.status != ReadStatus::Ready)
    {
        eventState = DescribeProblem(m_sampleProblem);
    }
    else if (!m_selected.id.isEmpty())
    {
        eventState = sourceText(QStringLiteral("此采样未采集事件。API 和 ETW 显示筛选不可用。"));
    }
    m_eventStatus->setText(eventState);
    m_waterfallStatus->setText(sourceText(QStringLiteral("未取得可用于时间范围的事件时间。")));
    m_propagationStatus->setText(sourceText(QStringLiteral("未取得可用于证据图的实例与关系。")));
    m_sessionStatus->setText(m_selected.id.isEmpty()
        ? sourceText(QStringLiteral("离线只读 · 未选择采样 · 无活动会话"))
        : sourceText(QStringLiteral("离线只读 · 采样 %1 · 无活动会话")).arg(m_selected.id));
}
}

// 由监控的真实导航激活一次；共享首帧准备延后至子控件全部挂载。
void MonitorDock::ensureActionAnalyzeTabInitialized()
{
    if (!m_actionAnalyzePage || m_actionAnalyzeWidget)
    {
        return;
    }
    const ks::ui::ScopedWidgetThemePreparation preparation(m_actionAnalyzePage);
    auto* layout = new QVBoxLayout(m_actionAnalyzePage);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    m_actionAnalyzeWidget = new ks::action_analyze::ActionAnalyzeWorkspace(m_actionAnalyzePage);
    layout->addWidget(m_actionAnalyzeWidget);
}
