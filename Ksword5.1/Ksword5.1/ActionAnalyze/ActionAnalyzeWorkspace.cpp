#include "ActionAnalyzeWorkspace.h"
#include "ActionAnalyzeBreakpointPage.h"
#include "BehaviorRulesPage.h"
#include "ToolbarCapabilities.h"
#include "OfflineSegmentOverview.h"
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
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QLabel>
#include <QPushButton>
#include <QSplitter>
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
    m_create = new QPushButton(toolbar);
    m_create->setObjectName(QStringLiteral("action_analyze_create_project"));
    ks::ui::SetThemeButtonIcon(m_create, QIcon(QStringLiteral(":/Icon/codeeditor_new.svg")));
    m_open = new QPushButton(toolbar);
    ks::ui::SetThemeButtonIcon(m_open, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
    m_newScan = new QPushButton(toolbar);
    m_newScan->setObjectName(QStringLiteral("action_analyze_new_scan"));
    ks::ui::ApplyFlatButtonTheme(m_newScan, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
    ks::ui::SetThemeButtonIcon(m_newScan, QIcon(QStringLiteral(":/Icon/process_resume.svg")));
    // 重读和取消使用项目主题的方形图标按钮，保留可访问名称及释义。
    m_retry = new QPushButton(toolbar);
    KswordTheme::ApplyStandardIconButtonMetrics(m_retry);
    ks::ui::SetThemeButtonIcon(m_retry, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    m_cancel = new QPushButton(toolbar);
    KswordTheme::ApplyStandardIconButtonMetrics(m_cancel);
    ks::ui::SetThemeButtonIcon(m_cancel, QIcon(QStringLiteral(":/Icon/process_stop.svg")));
    for (auto* button : {m_create, m_open, m_newScan, m_retry, m_cancel}) // 按自然操作顺序加入工具带。
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

    // 总览与编辑器共用正式导航。各页保留自己的选择和草稿。
    m_tabs = new QTabWidget(this);
    m_tabs->setObjectName(QStringLiteral("action_analyze_tabs"));
    m_overview = new OfflineSegmentOverview(m_tabs);
    m_overview->setObjectName(QStringLiteral("action_analyze_overview"));
    ks::monitor::AddMonitorNavigationTab(m_tabs, createProjectBrowser(), QString::fromLatin1(ks::monitor::ActionAnalyzeSamplesId));
    ks::monitor::AddMonitorNavigationTab(m_tabs, m_overview, QString::fromLatin1(ks::monitor::ActionAnalyzeOverviewId));
    ks::monitor::AddMonitorNavigationTab(m_tabs, CreateBehaviorRulesPage(m_tabs), QString::fromLatin1(ks::monitor::ActionAnalyzeRulesId));
    m_breakpoints = new ActionAnalyzeBreakpointPage(m_tabs);
    ks::monitor::AddMonitorNavigationTab(m_tabs, m_breakpoints, QString::fromLatin1(ks::monitor::ActionAnalyzeBreakpointsId));
    m_overview->openBreakpointPage = [this]() {
        m_tabs->setCurrentWidget(m_breakpoints);
    };
    m_overview->activateOverview = [this]() {
        // 浮窗请求受理后切回共用结果页，保留其它页的草稿与选择。
        m_tabs->setCurrentWidget(m_overview);
    };
    ks::ui::StyleChildPageTabs(m_tabs);
    layout->addWidget(m_tabs, 1);
    m_sessionStatus = StatusLabel(this);
    m_sessionStatus->setObjectName(QStringLiteral("action_analyze_session_status"));
    layout->addWidget(m_sessionStatus);
    m_overview->sessionStatusChanged = [this](const QString& receipt) {
        // 底栏显示会话的真实回执，切到规则和断点页也可读。
        m_sessionStatus->setText(receipt.isEmpty() ? sourceText(QStringLiteral("尚未开始监控。")) : receipt);
    };
    const auto refreshProject = [this](const QString& manifest, const QString& projectId) {
        // 只刷新仍在查看的项目。采样登记和保存断点共用现有读取入口。
        if (!m_readingProject && !m_projectCanceled && m_projectProblem.status == ReadStatus::Ready &&
            m_project.id == projectId && m_project.manifestPath == manifest && m_requestedPath == manifest)
        {
            openProject(manifest);
        }
    };
    m_overview->liveSampleRegistered = refreshProject;
    m_breakpoints->projectDefinitionsSaved = refreshProject;

    // 项目与扫描入口始终可见。打开扫描参数只切页，实际采集仍须显式启动。
    connect(m_create, &QPushButton::clicked, this, &ActionAnalyzeWorkspace::chooseNewProject);
    connect(m_newScan, &QPushButton::clicked, this, [this]() {
        if (m_newScan->isEnabled())
        {
            m_tabs->setCurrentWidget(m_overview);
            m_overview->focusScanTarget();
        }
    });
    connect(m_open, &QPushButton::clicked, this, [this]() {
        chooseProject();
    });
    connect(m_retry, &QPushButton::clicked, this, [this]() {
        openProject(m_requestedPath);
    });
    connect(m_cancel, &QPushButton::clicked, this, [this]() {
        if (m_creatingProject)
        {
            return;
        }
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
        updateStatus();
        updateSampleDocument();
    }
}

// 目录与详情沿用 Monitor 风险中心的共享模型宿主及详情布局。
QWidget* ActionAnalyzeWorkspace::createProjectBrowser()
{
    auto* page = new QWidget(m_tabs); // 项目目录与详情的实际页签。
    auto* layout = new QVBoxLayout(page); // 放置局部工具带和目录分栏。
    layout->setContentsMargins(0, 0, 0, 0);
    // 宽窗并排显示采样操作，窄窗使用与项目工具带相同的换行布局。
    auto* toolbar = new QWidget(page); // 当前采样的恢复入口。
    auto* tools = new ks::ui::FlowLayout(toolbar, 8, 8, 6); // 按可用宽度换行。
    ks::ui::StylePrimaryToolbar(toolbar);
    m_sampleRetry = new QPushButton(toolbar);
    ks::ui::SetThemeButtonIcon(m_sampleRetry, QIcon(QStringLiteral(":/Icon/process_refresh.svg")));
    tools->addWidget(m_sampleRetry);
    m_sampleClue = new QComboBox(toolbar);
    m_sampleClue->setObjectName(QStringLiteral("action_analyze_sample_clue"));
    m_sampleClue->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_sampleClue->setMinimumContentsLength(23);
    m_sampleClue->hide();
    tools->addWidget(m_sampleClue);
    m_sampleArchive = new QPushButton(toolbar);
    m_sampleArchive->setObjectName(QStringLiteral("action_analyze_sample_archive"));
    ks::ui::SetThemeButtonIcon(m_sampleArchive, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
    tools->addWidget(m_sampleArchive);
    ks::ui::NormalizeToolbarLayout(tools);
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
    connect(m_sampleArchive, &QPushButton::clicked, this, [this]() {
        // 显式请求以此刻选中的项目与采样为准。活动操作的真实状态在总览可查看。
        if (sampleArchiveEligibility().enabled())
        {
            const SampleRequest selected{m_project.manifestPath, m_project.id, m_selected}; // 此刻的冻结采样。
            const int choice = m_sampleClue->currentIndex(); // 首项定位最新线索，后续项使用明确的原始坐标。
            const SampleSensitiveClue* clue = nullptr; // 无已核验证据时仅打开采样。
            if (!m_sampleAnalysisIssue && !m_displayedClues.isEmpty())
            {
                clue = choice > 0 && choice <= m_displayedClues.size()
                    ? &m_displayedClues.at(choice - 1) : &m_displayedClues.constLast();
            }
            if (m_overview->openSampleArchive(selected, clue))
            {
                m_tabs->setCurrentWidget(m_overview);
            }
        }
    });
    return page;
}

// 用文件选择器输入新项目的目录名称。实际创建由共享项目文档完成。
void ActionAnalyzeWorkspace::chooseNewProject()
{
    if (m_readingProject)
    {
        return;
    }
    const QString base = m_project.manifestPath.isEmpty() ? QDir::homePath() :
        QFileInfo(QFileInfo(m_project.manifestPath).absolutePath()).absolutePath(); // 当前项目的上一级目录。
    const QString directory = QFileDialog::getSaveFileName(this,
        sourceText(QStringLiteral("输入新项目的文件夹名称")), base, {}, nullptr,
        QFileDialog::DontConfirmOverwrite); // 共享创建器拒绝已存在的目标目录。
    if (!directory.isEmpty())
    {
        openProject(QDir(directory).absoluteFilePath(QStringLiteral("project.ksaproj")), true);
    }
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

// 选择已存在的清单，或先原子提交新清单再读取。同一任务返回结果和失败位置。
void ActionAnalyzeWorkspace::openProject(const QString& path, bool create)
{
    if (path.isEmpty())
    {
        return;
    }
    m_requestedPath = path;
    m_readingProject = true;
    m_creatingProject = create;
    m_projectCanceled = false;
    m_projectProblem = {};
    updateStatus();
    const auto accepted = m_projectRead->submit<QString, ProjectSnapshot>(path, // 零表示未受理任务。
        [create](const QString& selected, const ks::ui::AsyncOperationToken& token) {
            const auto canceled = [&token]() { return token.isCanceled(); }; // 项目工作拥有唯一代次。
            return create ? CreateProjectCatalog(selected, canceled) : ReadProjectCatalog(selected, canceled);
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
                m_creatingProject = false;
                m_projectProblem = {ReadStatus::Unavailable, QStringLiteral("project.ksaproj")};
                updateStatus();
            }
            return commit != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            m_readingProject = false;
            m_creatingProject = false;
            m_projectProblem = {ReadStatus::Unavailable, m_requestedPath};
            updateStatus();
        });
    if (!accepted)
    {
        m_readingProject = false;
        m_creatingProject = false;
        m_projectProblem = {ReadStatus::Unavailable, path};
        updateStatus();
    }
}

// 仅在读取成功后替换目录。同项目刷新使用稳定 UUID 恢复选择。
void ActionAnalyzeWorkspace::applyProject(const ProjectSnapshot& snapshot)
{
    m_readingProject = false;
    m_creatingProject = false;
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
        m_verifiedSample.reset();
        m_sampleDetails = {};
        m_sampleAnalysis.reset();
        m_sampleAnalysisIssue.reset();
    }
    ks::ui::DetailLayoutRegistry::prepareDataRebuild(m_fields);
    m_project = snapshot;
    m_breakpoints->setProjectContext(m_project);
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
        m_verifiedSample.reset();
        m_sampleAnalysis.reset();
        m_sampleAnalysisIssue.reset();
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

    struct SelectedSampleResult
    {
        SampleDetails details; // 选中目录行的描述与冻结配置。
        std::optional<ArchivedSampleAnalysis> analysis; // 通过身份核验后读取的归档预览。
    };
    const SampleRequest request{m_project.manifestPath, m_project.id, m_selected}; // 同一请求绑定两种只读结果。
    m_sampleRead->submit<SampleRequest, SelectedSampleResult>(request,
        [](const SampleRequest& selected, const ks::ui::AsyncOperationToken& token) {
            const auto canceled = [&token]() { return token.isCanceled(); }; // 两步共用代次和取消门禁。
            SelectedSampleResult result; // 先核验目录行，再接触其归档。
            result.details = ReadSampleDetails(selected, canceled);
            if (result.details.problem.status == ReadStatus::Ready && !canceled())
            {
                result.analysis = ReadArchivedSampleAnalysis(selected, canceled);
            }
            return result;
        },
        [this, request](const SelectedSampleResult& result, quint64) {
            m_readingSample = false;
            m_sampleProblem = result.details.problem;
            // 本次失败单独显示，最后验证成功的同一采样配置仍可查看。
            if (result.details.problem.status == ReadStatus::Ready)
            {
                m_sampleDetails = result.details;
                m_hasVerifiedSample = true;
                m_verifiedSample = request;
            }
            // 回读质量下降时保留同一样本的旧分类和其真实水位，另记本次状态。
            if (result.analysis)
            {
                const auto& analysis = *result.analysis; // 本次后台回执。
                const bool keepPrior = m_sampleAnalysis && m_sampleAnalysis->verified &&
                    (!analysis.verified || analysis.lastSegment < m_sampleAnalysis->lastSegment ||
                        (m_sampleAnalysis->end == SegmentEnd::Complete && analysis.end != SegmentEnd::Complete));
                if (keepPrior)
                {
                    m_sampleAnalysisIssue = analysis;
                }
                else
                {
                    m_sampleAnalysis = analysis;
                    m_sampleAnalysisIssue.reset();
                }
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
        document.note(QStringLiteral("从目录选择采样以查看分析结果和冻结配置。"));
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

        // 分析结果紧跟采样身份，配置和分析失败各有自己的回执。
        if (m_sampleAnalysis)
        {
            if (m_readingSample || m_sampleProblem.status != ReadStatus::Ready || m_sampleAnalysisIssue)
            {
                document.note(QStringLiteral("下方保留上次核验的采样分析。"));
            }
            AppendArchivedSampleAnalysis(document, *m_sampleAnalysis);
            if (m_sampleAnalysisIssue)
            {
                document.section(QStringLiteral("本次分析读取状态"));
                AppendArchivedSampleAnalysisStatus(document, *m_sampleAnalysisIssue);
            }
        }

        // 跨读取保留的配置明确标成上次验证结果，避免被当成这一次读回。
        if (m_hasVerifiedSample)
        {
            const auto title = m_readingSample || m_sampleProblem.status != ReadStatus::Ready
                ? QStringLiteral("上次验证的冻结配置") : QStringLiteral("冻结配置");
            document.section(title)
                .field(QStringLiteral("创建时采集状态"), QStringLiteral("未采集"), true)
                .field(QStringLiteral("项目标题"), m_sampleDetails.configurationTitle)
                .field(QStringLiteral("说明"), m_sampleDetails.configurationNotes)
                .field(QStringLiteral("配置语义散列"), m_sampleDetails.configurationHash);
            if (m_sampleDetails.breakpointCount)
            {
                document.field(QStringLiteral("冻结断点定义数"), QString::number(*m_sampleDetails.breakpointCount));
            }
        }
    }
    m_fields->setDocument(document);
    updateSampleClues();
}

// 将同一份采样分析投影为可操作的记录目录，校验未通过时保留已有选项并禁用定位。
void ActionAnalyzeWorkspace::updateSampleClues()
{
    const auto clues = m_sampleAnalysis ? m_sampleAnalysis->recentClues : QList<SampleSensitiveClue>{}; // 最近已核验的窗口。
    const auto automatic = sourceText(QStringLiteral("最新 API 线索")); // 默认使用当前窗口最近的线索。
    const auto available = !clues.isEmpty() && sampleArchiveEligibility().enabled() && !m_sampleAnalysisIssue; // 诊断状态与定位资格分开。
    if (clues != m_displayedClues || m_sampleClue->itemText(0) != automatic)
    {
        const int previousIndex = m_sampleClue->currentIndex() - 1; // 首项没有固定的归档坐标。
        const auto previous = previousIndex >= 0 && previousIndex < m_displayedClues.size()
            ? std::optional<SampleSensitiveClue>(m_displayedClues.at(previousIndex)) : std::nullopt;
        m_displayedClues = clues;
        m_sampleClue->clear();
        m_sampleClue->addItem(automatic);
        // 沿用详情中的归档顺序，显示类别和记录坐标便于对照。
        for (const auto& clue : m_displayedClues)
        {
            m_sampleClue->addItem(ArchivedClueLabel(clue));
        }
        const auto restored = previous ? m_displayedClues.indexOf(*previous) : -1; // 只恢复原始坐标完全一致的选项。
        m_sampleClue->setCurrentIndex(static_cast<int>(restored + 1));
    }
    m_sampleClue->setVisible(!clues.isEmpty());
    m_sampleClue->setEnabled(available);
    m_sampleClue->setAccessibleName(sourceText(QStringLiteral("采样证据定位")));
    m_sampleClue->setToolTip(available
        ? sourceText(QStringLiteral("选择一条线索，再打开采样记录。"))
        : sourceText(QStringLiteral("重新读取采样以核验证据位置。")));
}

// 将当前选区与实际读回的请求比较。返回值同时供按钮状态和点击守卫使用。
ToolbarActionEligibility ActionAnalyzeWorkspace::sampleArchiveEligibility() const
{
    ToolbarArchiveState state; // 只读投影，不构造新的采样或归档对象。
    state.manifestPath = m_project.manifestPath;
    state.selection = {{m_project.id, m_selected.id}, m_selected.descriptionHash};
    state.readingSample = m_readingSample;
    state.sampleReadFailed = m_sampleProblem.status != ReadStatus::Ready;
    if (m_verifiedSample && m_verifiedSample->manifestPath == state.manifestPath)
    {
        const auto& verified = *m_verifiedSample; // 由异步回执确认的请求身份。
        state.verifiedSample = ToolbarArchiveSample{{verified.projectId, verified.sample.id}, verified.sample.descriptionHash};
    }
    return EvaluateToolbarArchiveLocation(state);
}

// 并列更新操作进度、真实发布身份和采样的可用性。
void ActionAnalyzeWorkspace::updateStatus()
{
    using ks::ui::StatusRole;
    const bool hasProject = !m_project.id.isEmpty();
    m_create->setText(sourceText(QStringLiteral("新建行为分析项目")));
    m_create->setToolTip(sourceText(QStringLiteral("在新文件夹中创建行为分析项目。")));
    m_create->setEnabled(!m_readingProject);
    m_open->setText(sourceText(QStringLiteral("打开行为分析项目")));
    m_open->setToolTip(sourceText(QStringLiteral("选择项目清单，以只读方式载入。")));
    m_open->setEnabled(!m_readingProject);
    m_newScan->setText(sourceText(QStringLiteral("新一轮扫描")));
    m_newScan->setEnabled(hasProject && !m_readingProject);
    m_newScan->setToolTip(hasProject
        ? sourceText(QStringLiteral("设置本轮目标，将新采样保存在当前项目中。"))
        : sourceText(QStringLiteral("请先新建或打开行为分析项目。")));
    m_retry->setAccessibleName(sourceText(QStringLiteral("重新读取")));
    m_retry->setToolTip(m_requestedPath.isEmpty()
        ? sourceText(QStringLiteral("请先选择项目清单。"))
        : sourceText(QStringLiteral("重新读取所选项目：%1")).arg(m_requestedPath));
    m_cancel->setAccessibleName(sourceText(QStringLiteral("取消读取")));
    m_cancel->setToolTip(sourceText(QStringLiteral("取消本次读取并保留已显示的项目。")));
    m_cancel->setVisible(m_readingProject && !m_creatingProject);
    m_retry->setEnabled(!m_requestedPath.isEmpty() && !m_readingProject);
    m_sampleRetry->setText(sourceText(QStringLiteral("重新读取采样")));
    m_sampleRetry->setToolTip(sourceText(QStringLiteral("重读选中采样的分析结果与冻结配置。")));
    // 在途读保持按钮可获焦；再次触发时由 Click 处理器忽略。
    m_sampleRetry->setEnabled(!m_selected.id.isEmpty());
    m_sampleArchive->setText(sourceText(QStringLiteral("查看采样记录")));
    const auto archive = sampleArchiveEligibility(); // 由同一冻结身份和读取回执决定是否可打开。
    m_sampleArchive->setEnabled(archive.enabled());
    const QString archiveHint = archive.reason == ToolbarDisabledReason::SampleReadInProgress
        ? sourceText(QStringLiteral("正在读取采样详情…"))
        : archive.reason == ToolbarDisabledReason::SampleReadFailed ? DescribeProblem(m_sampleProblem)
        : sourceText(QStringLiteral("请先选择并读取一项采样。")); // 禁用提示使用真实回执或当前依赖。
    m_sampleArchive->setToolTip(archive.enabled() ? sourceText(QStringLiteral("在总览中查看当前项目所选采样的记录。"))
        : archiveHint);
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
        message = (m_creatingProject ? sourceText(QStringLiteral("正在创建项目：%1"))
            : sourceText(QStringLiteral("正在读取项目：%1"))).arg(m_requestedPath);
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
        message = sourceText(QStringLiteral("新建项目开始扫描，或打开现有项目查看历次采样。"));
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

    // 采样创建描述与归档回执分别呈现。
    QString eventState = sourceText(QStringLiteral("打开归档段以查看离线记录。"));
    if (m_readingSample)
    {
        eventState = sourceText(QStringLiteral("正在读取采样详情…"));
    }
    else if (m_sampleProblem.status != ReadStatus::Ready)
    {
        eventState = DescribeProblem(m_sampleProblem);
    }
    m_overview->setProjectContext(m_project, m_selected.id, eventState);
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
