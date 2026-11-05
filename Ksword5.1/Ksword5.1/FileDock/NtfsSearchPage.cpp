#include "NtfsSearchPage.h"
#include "NtfsFastIndex.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ResultTableHost.h"
#include "../UI/TablePresentation.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ThemeStatusRole.h"

#include <QAbstractTableModel>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QEvent>
#include <QComboBox>
#include <QDateTime>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QTableView>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <iterator>
#include <stdexcept>
#include <utility>

#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace {
using Index = ks::files::NtfsFastIndex;
QString text(const char* source) { return ks::i18n::sourceText(QString::fromUtf8(source)); }
QString sourceKey(const char* source)
{
    return QStringLiteral("source.") + QString::fromLatin1(QCryptographicHash::hash(QByteArray(source), QCryptographicHash::Sha1).toHex().left(16));
}
void bind(QObject* object, const char* source)
{
    ks::i18n::LanguageManager::instance().bindText(object, sourceKey(source), QString::fromUtf8(source));
}
struct StatusText {
    QString source;
    QStringList arguments;
    bool translateLast = false;
    void render(QLabel* label) const {
        QString value = ks::i18n::sourceText(source);
        for (int i = 0; i < arguments.size(); ++i)
            value = value.arg(translateLast && i == arguments.size() - 1 ? ks::i18n::LanguageManager::instance().displayText(arguments[i]) : arguments[i]);
        label->setText(value);
    }
    void set(QLabel* label, const char* message, QStringList values = {}, bool lastIsSource = false) {
        source = QString::fromUtf8(message); arguments = std::move(values); translateLast = lastIsSource; render(label);
    }
};
QString bytes(quint64 value)
{
    static const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"};
    double number = static_cast<double>(value);
    int unit = 0;
    while (number >= 1024.0 && unit < 6) { number /= 1024.0; ++unit; }
    return QStringLiteral("%1 %2").arg(number, 0, 'f', unit ? 2 : 0).arg(QString::fromLatin1(units[unit]));
}
// Large immutable snapshots are retired on the pool, never destroyed in a paint or selection callback.
template<class T> void retire(std::shared_ptr<T> previous)
{
    if (previous) QThreadPool::globalInstance()->start(QRunnable::create([previous = std::move(previous)] {}));
}
struct SearchRow { quint64 reference = 0; QString name, path; bool directory = false, known = false; quint64 logical = 0, allocated = 0; };
struct SearchResult { QVector<SearchRow> rows; quint64 matches = 0; bool cancelled = false; };
class SearchModel final : public QAbstractTableModel {
public:
    explicit SearchModel(QObject* parent) : QAbstractTableModel(parent) {}
    ~SearchModel() override { retire(std::move(m_data)); }
    void retranslate() { emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1); }
    void setResult(std::shared_ptr<const SearchResult> data) { beginResetModel(); auto old = std::move(m_data); m_data = std::move(data); endResetModel(); retire(std::move(old)); }
    const SearchRow* row(int n) const { return m_data && n >= 0 && n < m_data->rows.size() ? &m_data->rows[n] : nullptr; }
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() || !m_data ? 0 : int(m_data->rows.size()); }
    int columnCount(const QModelIndex& = {}) const override { return 5; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        const char* headers[] = {"名称", "完整路径", "类型", "逻辑大小", "占用空间"};
        return section >= 0 && section < 5 ? text(headers[section]) : QVariant();
    }
    QVariant data(const QModelIndex& index, int role) const override {
        const auto* item = row(index.row());
        if (!index.isValid() || !item) return {};
        if (role == Qt::UserRole) return index.column() == 3 ? QVariant::fromValue(item->logical) : QVariant::fromValue(item->allocated);
        if (role == Qt::ToolTipRole) return item->path;
        if (role != Qt::DisplayRole) return {};
        switch (index.column()) {
        case 0: return item->name;
        case 1: return item->path.isEmpty() ? text("路径不可解析") : item->path;
        case 2: return item->directory ? text("目录") : text("文件");
        case 3: return item->directory ? QVariant() : item->known ? QVariant(bytes(item->logical)) : QVariant(text("未计量"));
        case 4: return item->directory ? QVariant() : item->known ? QVariant(bytes(item->allocated)) : QVariant(text("未计量"));
        }
        return {};
    }
private:
    std::shared_ptr<const SearchResult> m_data;
};
void configureTable(QTableView* view, QAbstractItemModel* model, const QStringList& ids)
{
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::ExtendedSelection);
    view->setWordWrap(false);
    view->verticalHeader()->hide();
    view->setModel(model);
    view->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    view->horizontalHeader()->setStretchLastSection(true);
    view->setSortingEnabled(false); // Sorting is prepared off the UI thread.
    QList<ks::ui::ResultTableColumn> columns;
    for (int i = 0; i < ids.size(); ++i) columns.append({i, ids[i]});
    ks::ui::ResultTableCapabilities capabilities;
    capabilities.headerClickSorting = false;
    capabilities.actionBar = ks::ui::TableActionBarMode::Compact;
    ks::ui::ResultTableHost::ensure(view)->bindModel(model, columns, capabilities);
    ks::ui::ApplyTablePresentation(view);
}
}

struct NtfsSearchPage::State {
    ks::ui::AsyncOperation *indexOperation = nullptr, *searchOperation = nullptr, *volumeOperation = nullptr;
    QComboBox *volume = nullptr, *searchType = nullptr;
    QPushButton *build = nullptr, *refresh = nullptr, *cancel = nullptr, *search = nullptr, *locate = nullptr, *discover = nullptr;
    QCheckBox *fullPath = nullptr, *wildcard = nullptr;
    QLineEdit* query = nullptr;
    QLabel *indexStatus = nullptr, *searchStatus = nullptr, *workflowHint = nullptr, *resultSource = nullptr, *indexDetails = nullptr, *coverageHint = nullptr;
    QProgressBar* progress = nullptr;
    QTimer* progressTimer = nullptr;
    QTableView* results = nullptr;
    SearchModel* searchModel = nullptr;
    Index::Cancel cancelToken;
    std::shared_ptr<std::atomic<quint64>> processed, total;
    Index::Snapshot snapshot;
    QDateTime sampledAt;
    bool indexing = false, discovering = false, incremental = false, indexFailed = false, journalInvalid = false;
    QString volumeMessage = QStringLiteral("正在查询 NTFS 卷…");
    StatusText indexText{QStringLiteral("尚未建立索引"), {}, false};
    StatusText searchText{QStringLiteral("建立索引后可搜索"), {}, false};
};

NtfsSearchPage::NtfsSearchPage(QWidget* parent) : QWidget(parent), m_state(std::make_unique<State>())
{
    auto& s = *m_state;
    s.indexOperation = new ks::ui::AsyncOperation(this);
    s.volumeOperation = new ks::ui::AsyncOperation(this);
    s.searchOperation = new ks::ui::AsyncOperation(this);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    auto* workspace = new ks::ui::ParameterWorkspace(this, 320);
    layout->addWidget(workspace);
    ks::ui::StyleWorkspacePage(this, 0);
    ks::ui::StyleWorkspaceContentFrame(this, 6);

    auto* indexGroup = new QGroupBox(this); bind(indexGroup, "1. 选择磁盘");
    auto* indexLayout = new QVBoxLayout(indexGroup);
    s.volume = new QComboBox(indexGroup);
    s.volume->setObjectName(QStringLiteral("ntfs_volume"));
    s.volume->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    s.volume->setMinimumContentsLength(6);
    s.volume->addItem(text("正在查询 NTFS 卷…"), QString());
    auto* volumeLabel = new QLabel(indexGroup); bind(volumeLabel, "搜索磁盘："); volumeLabel->setBuddy(s.volume);
    indexLayout->addWidget(volumeLabel); indexLayout->addWidget(s.volume);
    s.discover = new QPushButton(indexGroup); bind(s.discover, "刷新磁盘列表"); indexLayout->addWidget(s.discover);
    auto* scope = new QLabel(indexGroup); bind(scope, "首次搜索会先读取所选磁盘的文件列表，以后可直接搜索。需要管理员权限；仅支持本地 NTFS 磁盘。");
    scope->setWordWrap(true); indexLayout->addWidget(scope);
    ks::ui::StyleParameterSection(indexGroup); workspace->parameters()->addWidget(indexGroup);

    auto* searchGroup = new QGroupBox(this); bind(searchGroup, "2. 搜索文件");
    auto* searchLayout = new QVBoxLayout(searchGroup);
    auto* queryLabel = new QLabel(searchGroup); bind(queryLabel, "文件名或关键词："); searchLayout->addWidget(queryLabel);
    s.query = new QLineEdit(searchGroup); s.query->setObjectName(QStringLiteral("ntfs_query"));
    queryLabel->setBuddy(s.query); s.query->setClearButtonEnabled(true);
    ks::i18n::LanguageManager::instance().bindPlaceholder(s.query, sourceKey("例如：报告、.pdf"), QStringLiteral("例如：报告、.pdf")); ks::ui::StyleSearchField(s.query); searchLayout->addWidget(s.query);
    auto* queryHint = new QLabel(searchGroup); bind(queryHint, "默认查找名称中包含关键词的文件。不区分大小写；留空可浏览全部文件。"); queryHint->setWordWrap(true); searchLayout->addWidget(queryHint);
    s.fullPath = new QCheckBox(searchGroup); bind(s.fullPath, "搜索完整路径（含文件夹名）"); searchLayout->addWidget(s.fullPath);
    s.wildcard = new QCheckBox(searchGroup); bind(s.wildcard, "使用通配符（例如 *.log、报告?.docx）"); searchLayout->addWidget(s.wildcard);
    auto* typeLabel = new QLabel(searchGroup); bind(typeLabel, "结果类型："); searchLayout->addWidget(typeLabel);
    s.searchType = new QComboBox(searchGroup); typeLabel->setBuddy(s.searchType); s.searchType->addItems({text("文件和目录"), text("仅文件"), text("仅目录")});
    for (int i = 0; i < 3; ++i) { const char* labels[] = {"文件和目录", "仅文件", "仅目录"}; ks::i18n::LanguageManager::instance().bindComboBoxItem(s.searchType, i, sourceKey(labels[i]), QString::fromUtf8(labels[i])); } searchLayout->addWidget(s.searchType);
    ks::ui::StyleParameterSection(searchGroup); workspace->parameters()->addWidget(searchGroup);
    s.workflowHint = new QLabel(this); s.workflowHint->setObjectName(QStringLiteral("ntfs_workflow_hint")); s.workflowHint->setWordWrap(true); s.workflowHint->setTextFormat(Qt::PlainText);
    workspace->parameters()->addWidget(s.workflowHint);

    auto* maintenance = new QGroupBox(this); bind(maintenance, "索引维护与说明");
    auto* maintenanceLayout = new QVBoxLayout(maintenance);
    auto* maintenanceHint = new QLabel(maintenance); bind(maintenanceHint, "文件发生变化后，点击“更新文件列表”。更新不可用或失败时，可重新扫描磁盘。所有操作只读取文件信息。"); maintenanceHint->setWordWrap(true); maintenanceLayout->addWidget(maintenanceHint);
    s.refresh = new QPushButton(maintenance); bind(s.refresh, "更新文件列表"); maintenanceLayout->addWidget(s.refresh);
    s.build = new QPushButton(maintenance); bind(s.build, "加载文件列表"); maintenanceLayout->addWidget(s.build);
    auto* note = new QLabel(maintenance); bind(note, "文件列表来自 MFT，更新使用 USN 变更日志，不创建或修改日志。最多显示 50,000 条搜索结果，匹配总数另行显示。硬链接可按各名称搜索。"); note->setWordWrap(true); maintenanceLayout->addWidget(note);
    s.indexDetails = new QLabel(maintenance); s.indexDetails->setWordWrap(true); s.indexDetails->setTextFormat(Qt::PlainText); s.indexDetails->setTextInteractionFlags(Qt::TextSelectableByMouse); maintenanceLayout->addWidget(s.indexDetails);
    ks::ui::StyleParameterSection(maintenance); workspace->parameters()->addWidget(ks::ui::FoldParameterSection(maintenance));
    workspace->parameters()->addStretch();
    s.search = new QPushButton(this); s.search->setObjectName(QStringLiteral("ntfs_search")); bind(s.search, "扫描并搜索"); ks::ui::ApplyFlatButtonTheme(s.search, ks::ui::FlatButtonTone::Accent);
    s.cancel = new QPushButton(this); bind(s.cancel, "停止");
    workspace->actions()->addWidget(s.search, 1); workspace->actions()->addWidget(s.cancel); ks::ui::NormalizeToolbarRow(workspace->actions());

    s.indexStatus = new QLabel(text("尚未建立索引"), this); s.indexStatus->setWordWrap(true);
    s.indexStatus->setObjectName(QStringLiteral("ntfs_index_status"));
    s.indexStatus->setTextFormat(Qt::PlainText); s.indexStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
    s.progress = new QProgressBar(this); s.progress->setRange(0, 100); s.progress->setValue(0); s.progress->hide();

    auto* resultGroup = new QWidget(this);
    auto* resultGroupLayout = new QVBoxLayout(resultGroup);
    resultGroupLayout->setContentsMargins(0, 0, 0, 0); resultGroupLayout->setSpacing(6);
    workspace->results()->addWidget(resultGroup, 1);
    auto* resultHeader = new QWidget(resultGroup); ks::ui::StylePrimaryToolbar(resultHeader);
    auto* headerLayout = new QVBoxLayout(resultHeader); headerLayout->setContentsMargins(8, 4, 8, 4);
    s.resultSource = new QLabel(resultHeader); s.resultSource->setObjectName(QStringLiteral("ntfs_result_source")); s.resultSource->setWordWrap(true); s.resultSource->setTextFormat(Qt::PlainText); headerLayout->addWidget(s.resultSource);
    headerLayout->addWidget(s.indexStatus); headerLayout->addWidget(s.progress); resultGroupLayout->addWidget(resultHeader);
    s.coverageHint = new QLabel(resultHeader); s.coverageHint->setWordWrap(true); s.coverageHint->setTextFormat(Qt::PlainText); ks::ui::ApplyStatusRole(s.coverageHint, ks::ui::StatusRole::Warning); headerLayout->addWidget(s.coverageHint);
    auto* searchPage = new QWidget(resultGroup);
    resultGroupLayout->addWidget(searchPage, 1);
    auto* resultLayout = new QVBoxLayout(searchPage); resultLayout->setContentsMargins(0, 0, 0, 0); resultLayout->setSpacing(6);
    auto* searchToolbar = new QWidget(searchPage); ks::ui::StylePrimaryToolbar(searchToolbar);
    auto* searchBar = new QHBoxLayout(searchToolbar); searchBar->setContentsMargins(8, 4, 8, 4);
    s.searchStatus = new QLabel(text("建立索引后可搜索"), searchPage); s.searchStatus->setWordWrap(true); searchBar->addWidget(s.searchStatus, 1);
    s.searchStatus->setTextFormat(Qt::PlainText);
    s.locate = new QPushButton(searchPage); bind(s.locate, "打开所在文件夹"); searchBar->addWidget(s.locate); ks::ui::NormalizeToolbarRow(searchBar); resultLayout->addWidget(searchToolbar);
    auto* resultHint = new QLabel(searchPage); bind(resultHint, "双击结果可在文件管理中定位；也可选中一行后点击“打开所在文件夹”。"); resultHint->setWordWrap(true); resultLayout->addWidget(resultHint);
    s.results = new ks::ui::TableActionTableView(searchPage); s.searchModel = new SearchModel(s.results);
    configureTable(s.results, s.searchModel, {"name", "path", "type", "logical", "allocated"});
    s.results->setColumnWidth(0, 200); s.results->setColumnWidth(1, 400); s.results->setColumnWidth(3, 130); resultLayout->addWidget(s.results, 1);

    workspace->finish();
    updateUnavailableResults("先选择磁盘，输入文件名或关键词，再点击“扫描并搜索”。");
    for (auto* operation : {s.indexOperation, s.searchOperation, s.volumeOperation})
        operation->setStateChangedCallback([this] { updateButtons(); });

    s.progressTimer = new QTimer(this); s.progressTimer->setInterval(200);
    connect(s.progressTimer, &QTimer::timeout, this, [this] {
        auto& state = *m_state;
        if (state.cancelToken && state.cancelToken->load()) return;
        const quint64 count = state.processed->load(), total = state.total->load();
        state.indexText.set(state.indexStatus, "已读取 %1 / %2 条文件记录", {QString::number(count), QString::number(total)});
        state.progress->setRange(0, total ? 100 : 0);
        if (total) state.progress->setValue(int(std::min<long double>(100, 100.0L * count / total)));
    });
    connect(s.discover, &QPushButton::clicked, this, &NtfsSearchPage::discoverVolumes);
    connect(s.build, &QPushButton::clicked, this, [this] { startIndex(false); });
    connect(s.refresh, &QPushButton::clicked, this, [this] { startIndex(true); });
    connect(s.cancel, &QPushButton::clicked, this, &NtfsSearchPage::cancelOperations);
    const auto requestSearch = [this] { startSearch(); };
    connect(s.search, &QPushButton::clicked, this, requestSearch);
    connect(s.query, &QLineEdit::returnPressed, this, requestSearch);
    connect(s.locate, &QPushButton::clicked, this, &NtfsSearchPage::locateSelected);
    connect(s.results, &QTableView::doubleClicked, this, [this] { locateSelected(); });
    connect(s.results->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { updateButtons(); });
    connect(s.volume, &QComboBox::currentIndexChanged, this, [this] {
        auto& state = *m_state;
        if (!state.discovering && !state.indexing) {
            state.searchOperation->cancel();
        }
        updateButtons();
    });
    updateButtons();
    discoverVolumes();
}

NtfsSearchPage::~NtfsSearchPage()
{
    if (m_state->cancelToken) m_state->cancelToken->store(true);
    m_state->indexOperation->close(); m_state->searchOperation->close(); m_state->volumeOperation->close();
    retire(std::move(m_state->snapshot));
}

void NtfsSearchPage::discoverVolumes()
{
    auto& s = *m_state;
    if (s.indexing || s.discovering) return;
    s.discovering = true;
    if (!s.snapshot && !s.indexFailed) {
        s.indexText.set(s.indexStatus, "正在查询 NTFS 卷，请稍候…");
        ks::ui::ApplyStatusRole(s.indexStatus, ks::ui::StatusRole::Info);
    }
    updateButtons();
    using Volumes = QVector<QPair<QString, QString>>;
    s.volumeOperation->submit<int, Volumes>(0,
        [](int, const ks::ui::AsyncOperationToken& token) {
            Volumes volumes;
#ifdef Q_OS_WIN
            struct ThreadErrorModeGuard {
                DWORD previous = 0;
                bool changed = SetThreadErrorMode(SEM_FAILCRITICALERRORS, &previous) != FALSE;
                ~ThreadErrorModeGuard() { if (changed) SetThreadErrorMode(previous, nullptr); }
            } errorMode;
            wchar_t roots[4096]{};
            const DWORD length = GetLogicalDriveStringsW(DWORD(std::size(roots)), roots);
            if (!length || length >= std::size(roots)) throw std::runtime_error("GetLogicalDriveStringsW failed");
            for (const wchar_t* root = roots; *root; root += wcslen(root) + 1) {
                if (token.isCanceled()) break;
                const UINT type = GetDriveTypeW(root);
                if (type != DRIVE_FIXED && type != DRIVE_REMOVABLE) continue;
                wchar_t name[261]{}, filesystem[64]{};
                if (!GetVolumeInformationW(root, name, DWORD(std::size(name)), nullptr, nullptr, nullptr,
                    filesystem, DWORD(std::size(filesystem))) || _wcsicmp(filesystem, L"NTFS") != 0) continue;
                const QString path = QString::fromWCharArray(root);
                volumes.append({path + QStringLiteral("  ") + QString::fromWCharArray(name), path});
            }
#else
            Q_UNUSED(token);
#endif
            return volumes;
        },
        [this](const Volumes& volumes, std::uint64_t) {
            auto& state = *m_state;
            const QString selected = state.volume->currentData().toString();
            state.volume->clear();
            for (const auto& volume : volumes) state.volume->addItem(volume.first, volume.second);
            if (volumes.isEmpty()) { state.volumeMessage = QStringLiteral("没有可用的 NTFS 卷"); state.volume->addItem(ks::i18n::sourceText(state.volumeMessage), QString()); }
            const int previous = state.volume->findData(selected);
            if (previous >= 0) state.volume->setCurrentIndex(previous);
            state.discovering = false;
            if (!state.snapshot && !state.indexFailed) {
                state.indexText.set(state.indexStatus, volumes.isEmpty()
                    ? "未找到本地 NTFS 磁盘；请连接磁盘后点击“刷新磁盘列表”。"
                    : "选择磁盘，输入文件名或关键词，然后点击“扫描并搜索”。");
                ks::ui::ApplyStatusRole(state.indexStatus, volumes.isEmpty() ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Idle);
            }
            updateButtons(); return true;
        },
        [this](std::exception_ptr) {
            auto& state = *m_state; state.discovering = false;
            state.volumeMessage = QStringLiteral("卷查询失败，请刷新重试");
            state.volume->clear(); state.volume->addItem(ks::i18n::sourceText(state.volumeMessage), QString());
            state.indexText.set(state.indexStatus, "磁盘查询失败；请点击“刷新磁盘列表”重试。");
            ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Error);
            updateButtons();
        });
}

void NtfsSearchPage::updateUnavailableResults(const char* message)
{
    auto& s = *m_state;
    if (s.snapshot) return; // A failed refresh never removes the last usable snapshot.
    s.searchText.set(s.searchStatus, message);
}

void NtfsSearchPage::cancelOperations()
{
    auto& s = *m_state;
    if (s.indexing && s.cancelToken && !s.cancelToken->exchange(true)) {
        s.indexText.set(s.indexStatus, "正在取消，请等待当前读取返回");
        ks::ui::ApplyStatusRole(s.indexStatus, ks::ui::StatusRole::Info);
    }
    if (s.searchOperation->isBusy()) {
        s.searchOperation->cancel();
        s.searchText.set(s.searchStatus, "搜索已停止；可修改条件后重新搜索。");
    }
    updateButtons();
}

void NtfsSearchPage::updateButtons()
{
    auto& s = *m_state;
    const bool volumeAvailable = !s.volume->currentData().toString().isEmpty();
    s.volume->setEnabled(!s.indexing && !s.discovering && volumeAvailable);
    s.discover->setEnabled(!s.indexing && !s.discovering);
    s.build->setEnabled(!s.indexing && !s.discovering && volumeAvailable);
    const bool sameVolume = hasSelectedVolumeIndex();
    s.refresh->setEnabled(!s.indexing && !s.discovering && !s.journalInvalid && sameVolume && s.snapshot->journalAvailable);
    const bool searching = s.searchOperation->isBusy();
    s.cancel->setEnabled((s.indexing && s.cancelToken && !s.cancelToken->load()) || searching);
    s.build->setText(text(s.indexing && !s.incremental ? "正在扫描磁盘…"
        : sameVolume || s.indexFailed ? "重新扫描磁盘" : "加载文件列表"));
    s.refresh->setText(text(s.indexing && s.incremental ? "正在更新文件列表…" : "更新文件列表"));
    s.discover->setText(text(s.discovering ? "正在查询磁盘…" : "刷新磁盘列表"));
    s.search->setText(text(s.indexing ? "正在准备文件列表…" : searching ? "正在搜索…" : sameVolume ? "搜索" : "扫描并搜索"));
    s.search->setEnabled(volumeAvailable && !s.discovering && !s.indexing && !searching);
    const auto* row = s.searchModel->row(s.results->currentIndex().row());
    s.locate->setEnabled(sameVolume && row && !row->path.isEmpty());
    const QString needsIndex = text("请先点击“扫描并搜索”加载所选磁盘的文件列表。");
    s.search->setToolTip(s.indexing || searching ? text("任务正在后台运行；可点击“停止”取消。")
        : !sameVolume ? text("先扫描所选磁盘，再按当前关键词搜索；不会修改磁盘文件。") : text("搜索当前磁盘的文件列表；也可在输入框按 Enter。"));
    s.locate->setToolTip(!sameVolume ? needsIndex : !row ? text("请先选择一个搜索结果，或双击结果直接定位。")
        : row->path.isEmpty() ? text("此 MFT 记录的完整路径无法解析，不能定位。") : row->path);
    s.build->setToolTip(s.indexing ? text("任务正在后台运行；可点击“停止”取消。")
        : s.discovering ? text("正在查询磁盘，请等待列表返回。")
        : !volumeAvailable ? text("请先刷新磁盘列表并选择本地 NTFS 磁盘。") : text("重新读取所选磁盘的完整文件列表。"));
    s.refresh->setToolTip(s.indexing ? text("任务正在后台运行；可点击“停止”取消。")
        : s.discovering ? text("正在查询磁盘，请等待列表返回。")
        : !sameVolume ? needsIndex
        : s.journalInvalid || !s.snapshot->journalAvailable ? text("文件变更记录不可用，请点击“重新扫描磁盘”更新完整列表。")
        : text("读取上次扫描后的文件变更，更新当前磁盘的文件列表。"));
    s.cancel->setToolTip(text("停止当前扫描或搜索；保留上一次可用结果。"));
    if (s.discovering) s.workflowHint->setText(text("正在查找可搜索的磁盘，请稍候。"));
    else if (!volumeAvailable) s.workflowHint->setText(text("没有可搜索的磁盘，请刷新磁盘列表。"));
    else if (s.indexing) s.workflowHint->setText(text("正在准备文件列表，完成后自动显示搜索结果。可以点击“停止”取消。"));
    else if (!sameVolume) s.workflowHint->setText(text("下一步：输入关键词，点击“扫描并搜索”。留空可浏览文件列表。"));
    else s.workflowHint->setText(text("文件列表已就绪。输入关键词后点击“搜索”或按 Enter；双击结果可定位文件。"));
    s.resultSource->setVisible(bool(s.snapshot));
    s.indexDetails->setVisible(bool(s.snapshot));
    s.coverageHint->setVisible(s.snapshot && s.snapshot->namesIncompleteCount != 0);
    if (s.snapshot) {
        s.indexDetails->setText(ks::i18n::LanguageManager::instance().displayText(s.snapshot->status));
        s.coverageHint->setText(text("注意：%1 个文件的名称可能不完整，搜索结果可能遗漏这些名称。")
            .arg(s.snapshot->namesIncompleteCount));
    }
    if (s.snapshot) s.resultSource->setText(sameVolume
        ? text("当前结果来自磁盘 %1").arg(s.snapshot->volumeRoot)
        : text("仍显示磁盘 %1 的上次结果。所选磁盘 %2 尚未加载，请点击“扫描并搜索”。")
            .arg(s.snapshot->volumeRoot, s.volume->currentData().toString()));
}

bool NtfsSearchPage::hasSelectedVolumeIndex() const
{
    const auto& s = *m_state;
    return s.snapshot && QString::compare(s.snapshot->volumeRoot,
        s.volume->currentData().toString(), Qt::CaseInsensitive) == 0;
}

void NtfsSearchPage::startIndex(bool incremental)
{
    auto& s = *m_state;
    if (s.indexing || s.discovering || s.volume->currentData().toString().isEmpty()) return;
    s.searchOperation->cancel();
    struct Request {
        QString volume;
        Index::Snapshot previous;
        Index::Cancel cancel;
        std::shared_ptr<std::atomic<quint64>> processed, total;
    };
    struct Result { Index::Snapshot snapshot; QDateTime sampledAt; };
    s.cancelToken = std::make_shared<std::atomic_bool>(false);
    s.processed = std::make_shared<std::atomic<quint64>>(0);
    s.total = std::make_shared<std::atomic<quint64>>(0);
    Request request{s.volume->currentData().toString(), incremental && s.snapshot ? s.snapshot : Index::Snapshot(),
        s.cancelToken, s.processed, s.total};
    s.indexing = true; s.incremental = incremental; s.indexFailed = false;
    s.progress->setRange(0, 0); s.progress->show(); s.progressTimer->start();
    s.indexText.set(s.indexStatus, incremental ? "正在更新文件列表…" : "正在读取磁盘文件列表，完成后自动搜索…");
    ks::ui::ApplyStatusRole(s.indexStatus, ks::ui::StatusRole::Info);
    updateUnavailableResults("正在准备文件列表；完成后会自动按当前关键词搜索。"); updateButtons();
    s.indexOperation->submit<Request, Result>(std::move(request),
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            Result result;
            if (token.isCanceled()) return result;
            const auto progress = [processed = request.processed, total = request.total](quint64 done, quint64 count) {
                processed->store(done); total->store(count);
            };
            result.snapshot = request.previous ? Index::refresh(request.previous, request.cancel, progress)
                : Index::build(request.volume, request.cancel, progress);
            result.sampledAt = QDateTime::currentDateTime();
            return result;
        },
        [this](const Result& result, std::uint64_t) {
            auto& state = *m_state;
            state.indexing = false; state.progressTimer->stop(); state.progress->hide();
            if ((result.snapshot && result.snapshot->cancelled) || (state.cancelToken && state.cancelToken->load())) {
                state.indexText.set(state.indexStatus, state.snapshot ? "已停止；保留上一次可用文件列表。" : "扫描已停止；点击“扫描并搜索”可重试。");
                ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Idle);
                updateUnavailableResults("扫描已停止；点击“扫描并搜索”可重试。"); updateButtons(); return true;
            }
            if (!result.snapshot || !result.snapshot->complete) {
                state.indexFailed = true;
                if (result.snapshot && result.snapshot->rebuildRequired) state.journalInvalid = true;
                if (!result.snapshot) state.indexText.set(state.indexStatus, "未能加载文件列表；点击“扫描并搜索”可重试。");
                else state.indexText.set(state.indexStatus, result.snapshot->rebuildRequired ? "文件变更记录已失效；请展开“索引维护与说明”，重新扫描磁盘。%1"
                    : state.snapshot ? "更新失败；保留上一次文件列表。%1" : "未能读取文件列表：%1 请检查管理员权限与磁盘状态，再点击“扫描并搜索”重试。", {result.snapshot->error}, true);
                ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Error);
                updateUnavailableResults("文件列表未能加载；查看上方原因，再点击“扫描并搜索”重试。"); updateButtons(); return true;
            }
            state.journalInvalid = false;
            auto old = std::move(state.snapshot); state.snapshot = result.snapshot; retire(std::move(old));
            state.sampledAt = result.sampledAt;
            ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Success);
            state.indexText.set(state.indexStatus, "已加载 %1：%2 条文件记录；%3 个文件大小未知；更新于 %4。",
                {result.snapshot->volumeRoot, QString::number(result.snapshot->entries.size()), QString::number(result.snapshot->unknownSizeCount),
                 state.sampledAt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))});
            startSearch(); updateButtons(); return true;
        },
        [this](std::exception_ptr) {
            auto& state = *m_state; state.indexing = false; state.progressTimer->stop(); state.progress->hide();
            state.indexFailed = true;
            state.indexText.set(state.indexStatus, state.snapshot ? "加载任务失败；保留上一次文件列表，可重新扫描磁盘。"
                : "文件列表加载失败；请检查管理员权限与磁盘状态，再点击“扫描并搜索”重试。");
            ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Error);
            updateUnavailableResults("文件列表未能加载；查看上方原因，再点击“扫描并搜索”重试。"); updateButtons();
        });
}

void NtfsSearchPage::startSearch()
{
    auto& s = *m_state;
    if (s.indexing || s.discovering || s.volume->currentData().toString().isEmpty() || s.searchOperation->isBusy()) return;
    if (!hasSelectedVolumeIndex()) { startIndex(false); return; }
    struct Request { Index::Snapshot snapshot; QString query; bool fullPath, wildcard; int type; };
    Request request{s.snapshot, s.query->text(), s.fullPath->isChecked(), s.wildcard->isChecked(), s.searchType->currentIndex()};
    s.searchText.set(s.searchStatus, "正在搜索索引…");
    s.searchOperation->submit<Request, SearchResult>(std::move(request),
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            SearchResult result;
            const auto& snapshot = *request.snapshot;
            QRegularExpression pattern;
            if (request.wildcard) pattern = QRegularExpression(QRegularExpression::wildcardToRegularExpression(request.query), QRegularExpression::CaseInsensitiveOption);
            auto matches = [&request, &pattern](const QString& candidate) {
                return request.query.isEmpty() || (request.wildcard ? pattern.match(candidate).hasMatch() : candidate.contains(request.query, Qt::CaseInsensitive));
            };
            for (auto it = snapshot.entries.cbegin(); it != snapshot.entries.cend(); ++it) {
                if (token.isCanceled()) { result.cancelled = true; return result; }
                if ((request.type == 1 && it->isDirectory()) || (request.type == 2 && !it->isDirectory())) continue;
                const QVector<ks::files::NtfsIndexName> names = it->names.isEmpty()
                    ? QVector<ks::files::NtfsIndexName>{{it->parentReference, it->name}} : it->names;
                for (const auto& name : names) {
                    QString path;
                    if (request.fullPath) {
                        if (name.parentReference == it.key()) path = snapshot.volumeRoot;
                        else {
                            path = Index::fullPath(snapshot, name.parentReference);
                            if (!path.isEmpty()) { if (!path.endsWith(QLatin1Char('\\'))) path += QLatin1Char('\\'); path += name.name; }
                        }
                    }
                    if (!matches(request.fullPath ? path : name.name)) continue;
                    ++result.matches;
                    if (result.rows.size() >= 50000) continue;
                    if (!request.fullPath) {
                        if (name.parentReference == it.key()) path = snapshot.volumeRoot;
                        else {
                            path = Index::fullPath(snapshot, name.parentReference);
                            if (!path.isEmpty()) { if (!path.endsWith(QLatin1Char('\\'))) path += QLatin1Char('\\'); path += name.name; }
                        }
                    }
                    result.rows.append({it.key(), name.name, path, it->isDirectory(), it->sizeKnown, it->logicalBytes, it->allocatedBytes});
                }
            }
            std::sort(result.rows.begin(), result.rows.end(), [](const SearchRow& a, const SearchRow& b) {
                const int name = QString::compare(a.name, b.name, Qt::CaseInsensitive);
                return name == 0 ? a.path < b.path : name < 0;
            });
            return result;
        },
        [this](const SearchResult& result, std::uint64_t generation) {
            if (result.cancelled) return true;
            const auto prepared = std::make_shared<const SearchResult>(result);
            const auto action = [this, prepared, generation] {
                auto& state = *m_state;
                if (!state.searchOperation->isCurrent(generation)) return;
                state.searchModel->setResult(prepared);
                state.searchText.set(state.searchStatus, "匹配 %1 条，显示 %2 条；索引卷 %3",
                    {QString::number(prepared->matches), QString::number(prepared->rows.size()), state.snapshot->volumeRoot});
                updateButtons(); state.searchOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("ntfs-search"),
                {ks::ui::ResultTableHost::ensure(m_state->results)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) { m_state->searchText.set(m_state->searchStatus, "搜索失败，请重试"); });
}

void NtfsSearchPage::locateSelected()
{
    if (!hasSelectedVolumeIndex()) return;
    const auto* row = m_state->searchModel->row(m_state->results->currentIndex().row());
    if (row && !row->path.isEmpty()) emit locatePathRequested(row->path);
}

void NtfsSearchPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() != QEvent::LanguageChange || !m_state || !m_state->searchModel) return;
    auto& state = *m_state;
    state.indexText.render(state.indexStatus);
    state.searchText.render(state.searchStatus);
    if (state.volume->count() == 1 && state.volume->currentData().toString().isEmpty())
        state.volume->setItemText(0, ks::i18n::sourceText(state.volumeMessage));
    state.searchModel->retranslate();
    state.results->viewport()->update();
    updateButtons();
}
