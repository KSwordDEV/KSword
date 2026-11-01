#include "NtfsSearchPage.h"
#include "NtfsFastIndex.h"
#include "NtfsSpaceMapWidget.h"
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

#include <QAbstractItemModel>
#include <QAbstractTableModel>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QEvent>
#include <QComboBox>
#include <QDateTime>
#include <QFormLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QRegularExpression>
#include <QRunnable>
#include <QSet>
#include <QSplitter>
#include <QTableView>
#include <QTabWidget>
#include <QThreadPool>
#include <QTimer>
#include <QTreeView>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <limits>
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
using Entry = ks::files::NtfsIndexEntry;
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
quint64 addBytes(quint64 a, quint64 b)
{
    return b > std::numeric_limits<quint64>::max() - a ? std::numeric_limits<quint64>::max() : a + b;
}
// Large immutable snapshots are retired on the pool, never destroyed in a paint or selection callback.
template<class T> void retire(std::shared_ptr<T> previous)
{
    if (previous) QThreadPool::globalInstance()->start(QRunnable::create([previous = std::move(previous)] {}));
}
struct Totals { quint64 logical = 0, allocated = 0, files = 0, unknown = 0; };
struct Directory {
    quint64 reference = 0, parent = 0;
    int row = 0;
    QString name, path;
    QVector<quint64> directories;
    Totals totals;
};
struct Projection {
    Index::Snapshot snapshot;
    QHash<quint64, Directory> directories;
    QHash<quint64, QVector<quint64>> children;
    quint64 root = 0;
    QDateTime sampledAt;
};
using ProjectionPtr = std::shared_ptr<const Projection>;

ProjectionPtr project(Index::Snapshot snapshot, const Index::Cancel& cancel)
{
    auto result = std::make_shared<Projection>();
    result->snapshot = std::move(snapshot);
    result->root = result->snapshot->rootReference;
    result->sampledAt = QDateTime::currentDateTime();
    const auto& source = *result->snapshot;
    Directory root;
    root.reference = result->root;
    root.name = source.volumeRoot;
    root.path = source.volumeRoot;
    result->directories.insert(root.reference, root);
    for (auto it = source.entries.cbegin(); it != source.entries.cend(); ++it) {
        if (cancel->load()) return {};
        if (!it->isDirectory() || it.key() == result->root) continue;
        Directory node;
        node.reference = it.key(); node.name = it->name;
        node.path = Index::fullPath(source, it.key());
        node.parent = node.path.isEmpty() ? result->root : it->parentReference;
        result->directories.insert(it.key(), std::move(node));
    }
    for (auto it = result->directories.begin(); it != result->directories.end(); ++it) {
        if (it.key() == result->root) continue;
        if (it->parent == it.key() || !result->directories.contains(it->parent)) it->parent = result->root;
    }
    for (auto it = source.entries.cbegin(); it != source.entries.cend(); ++it) {
        if (cancel->load()) return {};
        if (it.key() == result->root) continue;
        quint64 parent = it->isDirectory() ? result->directories.value(it.key()).parent : it->parentReference;
        if (!result->directories.contains(parent)) parent = result->root;
        result->children[parent].append(it.key());
        if (it->isDirectory()) result->directories[parent].directories.append(it.key());
        else {
            auto& total = result->directories[parent].totals;
            ++total.files;
            if (it->sizeKnown) {
                total.logical = addBytes(total.logical, it->logicalBytes);
                total.allocated = addBytes(total.allocated, it->allocatedBytes);
            } else ++total.unknown;
        }
    }
    QHash<quint64, qsizetype> pending;
    QVector<quint64> ready;
    for (auto it = result->directories.begin(); it != result->directories.end(); ++it) {
        auto& children = it->directories;
        std::sort(children.begin(), children.end(), [&result](quint64 a, quint64 b) {
            return QString::compare(result->directories[a].name, result->directories[b].name, Qt::CaseInsensitive) < 0;
        });
        for (int row = 0; row < children.size(); ++row) result->directories[children[row]].row = row;
        pending.insert(it.key(), children.size());
        if (children.isEmpty()) ready.append(it.key());
    }
    // Leaf-to-root reduction counts a hard-linked record once using its canonical parent.
    while (!ready.isEmpty()) {
        if (cancel->load()) return {};
        const quint64 id = ready.takeLast();
        if (id == result->root) continue;
        const auto& child = result->directories[id];
        auto& parent = result->directories[child.parent];
        parent.totals.logical = addBytes(parent.totals.logical, child.totals.logical);
        parent.totals.allocated = addBytes(parent.totals.allocated, child.totals.allocated);
        parent.totals.files = addBytes(parent.totals.files, child.totals.files);
        parent.totals.unknown = addBytes(parent.totals.unknown, child.totals.unknown);
        if (--pending[child.parent] == 0) ready.append(child.parent);
    }
    return result;
}

class DirectoryModel final : public QAbstractItemModel {
public:
    explicit DirectoryModel(QObject* parent) : QAbstractItemModel(parent) {}
    ~DirectoryModel() override { retire(std::move(m_data)); }
    void retranslate() { emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1); }
    void setProjection(ProjectionPtr data) { beginResetModel(); auto old = std::move(m_data); m_data = std::move(data); endResetModel(); retire(std::move(old)); }
    QModelIndex index(int row, int column, const QModelIndex& parent = {}) const override {
        if (!m_data || row < 0 || column < 0 || column >= 4 || (parent.isValid() && parent.column() != 0)) return {};
        if (!parent.isValid()) return row == 0 ? createIndex(0, column, quintptr(m_data->root)) : QModelIndex();
        const auto it = m_data->directories.constFind(quint64(parent.internalId()));
        if (it == m_data->directories.cend() || row >= it->directories.size()) return {};
        return createIndex(row, column, quintptr(it->directories[row]));
    }
    QModelIndex parent(const QModelIndex& child) const override {
        if (!child.isValid() || !m_data || quint64(child.internalId()) == m_data->root) return {};
        const auto it = m_data->directories.constFind(quint64(child.internalId()));
        if (it == m_data->directories.cend()) return {};
        const auto p = m_data->directories.constFind(it->parent);
        return p == m_data->directories.cend() ? QModelIndex() : createIndex(p->row, 0, quintptr(p->reference));
    }
    int rowCount(const QModelIndex& parent = {}) const override {
        if (!m_data || (parent.isValid() && parent.column() != 0)) return 0;
        if (!parent.isValid()) return 1;
        auto it = m_data->directories.constFind(quint64(parent.internalId()));
        return it == m_data->directories.cend() ? 0 : int(it->directories.size());
    }
    int columnCount(const QModelIndex& = {}) const override { return 4; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        const char* headers[] = {"目录", "逻辑大小", "占用空间", "文件数"};
        return section >= 0 && section < 4 ? text(headers[section]) : QVariant();
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || !m_data) return {};
        const auto it = m_data->directories.constFind(quint64(index.internalId()));
        if (it == m_data->directories.cend()) return {};
        if (role == Qt::ToolTipRole) return it->path;
        if (role != Qt::DisplayRole) return {};
        switch (index.column()) {
        case 0: return it->name;
        case 1: return bytes(it->totals.logical);
        case 2: return bytes(it->totals.allocated);
        case 3: return QString::number(it->totals.files);
        }
        return {};
    }
private:
    ProjectionPtr m_data;
};

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
struct ExtensionRow { QString extension; quint64 logical = 0, allocated = 0, files = 0, unknown = 0; };
struct SpaceResult {
    quint64 reference = 0;
    NtfsSpaceMapWidget::DataPtr map;
    QVector<ExtensionRow> extensions;
    Totals totals;
    QString path;
};
class ExtensionModel final : public QAbstractTableModel {
public:
    explicit ExtensionModel(QObject* parent) : QAbstractTableModel(parent) {}
    ~ExtensionModel() override { retire(std::move(m_data)); }
    void retranslate() { emit headerDataChanged(Qt::Horizontal, 0, columnCount() - 1); }
    void setResult(std::shared_ptr<const SpaceResult> data) { beginResetModel(); auto old = std::move(m_data); m_data = std::move(data); endResetModel(); retire(std::move(old)); }
    int rowCount(const QModelIndex& parent = {}) const override { return parent.isValid() || !m_data ? 0 : int(m_data->extensions.size()); }
    int columnCount(const QModelIndex& = {}) const override { return 5; }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole) return {};
        const char* headers[] = {"扩展名", "逻辑大小", "占用空间", "文件数", "未计量文件"};
        return section >= 0 && section < 5 ? text(headers[section]) : QVariant();
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || !m_data || index.row() >= m_data->extensions.size() || role != Qt::DisplayRole) return {};
        const auto& item = m_data->extensions[index.row()];
        switch (index.column()) {
        case 0: return item.extension.isEmpty() ? text("无扩展名") : item.extension;
        case 1: return bytes(item.logical);
        case 2: return bytes(item.allocated);
        case 3: return QString::number(item.files);
        case 4: return QString::number(item.unknown);
        }
        return {};
    }
private:
    std::shared_ptr<const SpaceResult> m_data;
};
QString extension(const QString& name)
{
    const qsizetype dot = name.lastIndexOf(QLatin1Char('.'));
    return dot <= 0 ? QString() : name.mid(dot).toLower();
}
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
    ks::ui::AsyncOperation *indexOperation = nullptr, *searchOperation = nullptr, *spaceOperation = nullptr, *volumeOperation = nullptr;
    QComboBox *volume = nullptr, *searchType = nullptr, *mapMetric = nullptr;
    QPushButton *build = nullptr, *refresh = nullptr, *cancel = nullptr, *search = nullptr, *locate = nullptr, *up = nullptr, *discover = nullptr;
    QCheckBox *fullPath = nullptr, *wildcard = nullptr;
    QLineEdit* query = nullptr;
    QLabel *indexStatus = nullptr, *searchStatus = nullptr, *spaceStatus = nullptr, *mapPath = nullptr, *workflowHint = nullptr, *resultSource = nullptr, *indexDetails = nullptr, *coverageHint = nullptr;
    QProgressBar* progress = nullptr;
    QTimer* progressTimer = nullptr;
    QTabWidget* tabs = nullptr;
    QTableView *results = nullptr, *extensions = nullptr;
    QTreeView* directories = nullptr;
    SearchModel* searchModel = nullptr;
    ExtensionModel* extensionModel = nullptr;
    DirectoryModel* directoryModel = nullptr;
    NtfsSpaceMapWidget* map = nullptr;
    Index::Cancel cancelToken;
    std::shared_ptr<std::atomic<quint64>> processed, total;
    ProjectionPtr projection;
    quint64 currentDirectory = 0;
    quint64 displayedDirectory = 0;
    QString displayedDirectoryPath;
    quint64 selectedReference = 0;
    QString selectedPath;
    bool indexing = false, discovering = false, incremental = false, indexFailed = false, journalInvalid = false;
    QString volumeMessage = QStringLiteral("正在查询 NTFS 卷…");
    StatusText indexText{QStringLiteral("尚未建立索引"), {}, false};
    StatusText searchText{QStringLiteral("建立索引后可搜索"), {}, false};
    StatusText spaceText{QStringLiteral("尚无空间统计"), {}, false};
};

NtfsSearchPage::NtfsSearchPage(QWidget* parent) : QWidget(parent), m_state(std::make_unique<State>())
{
    auto& s = *m_state;
    s.indexOperation = new ks::ui::AsyncOperation(this);
    s.volumeOperation = new ks::ui::AsyncOperation(this);
    s.searchOperation = new ks::ui::AsyncOperation(this);
    s.spaceOperation = new ks::ui::AsyncOperation(this);
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
    auto* note = new QLabel(maintenance); bind(note, "文件列表来自 MFT，更新使用 USN 变更日志，不创建或修改日志。最多显示 50,000 条搜索结果，匹配总数另行显示。硬链接可按各名称搜索；空间按文件记录仅计一次。"); note->setWordWrap(true); maintenanceLayout->addWidget(note);
    auto* accounting = new QLabel(maintenance); bind(accounting, "空间表示默认数据流的 MFT 逻辑大小或分配大小，不包括备用数据流、目录索引等未计量元数据及空闲空间。未计量文件不纳入面积，统计并非卷已用空间的精确总量。"); accounting->setWordWrap(true); maintenanceLayout->addWidget(accounting);
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
    resultGroupLayout->setContentsMargins(0, 0, 0, 0); resultGroupLayout->setSpacing(0);
    workspace->results()->addWidget(resultGroup, 1);
    auto* resultHeader = new QWidget(resultGroup);
    auto* headerLayout = new QVBoxLayout(resultHeader); headerLayout->setContentsMargins(8, 4, 8, 4);
    s.resultSource = new QLabel(resultHeader); s.resultSource->setObjectName(QStringLiteral("ntfs_result_source")); s.resultSource->setWordWrap(true); s.resultSource->setTextFormat(Qt::PlainText); headerLayout->addWidget(s.resultSource);
    headerLayout->addWidget(s.indexStatus); headerLayout->addWidget(s.progress); resultGroupLayout->addWidget(resultHeader);
    s.coverageHint = new QLabel(resultHeader); s.coverageHint->setWordWrap(true); s.coverageHint->setTextFormat(Qt::PlainText); ks::ui::ApplyStatusRole(s.coverageHint, ks::ui::StatusRole::Warning); headerLayout->addWidget(s.coverageHint);
    s.tabs = new QTabWidget(resultGroup); ks::ui::StyleJoinedResultTabs(s.tabs, resultHeader);
    resultGroupLayout->addWidget(s.tabs, 1);
    auto* searchPage = new QWidget(s.tabs);
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
    s.tabs->addTab(searchPage, text("搜索结果"));
    ks::i18n::LanguageManager::instance().bindTab(s.tabs, searchPage, sourceKey("搜索结果"), QStringLiteral("搜索结果"));

    auto* spacePage = new QWidget(s.tabs);
    auto* spaceLayout = new QVBoxLayout(spacePage); spaceLayout->setContentsMargins(0, 0, 0, 0); spaceLayout->setSpacing(6);
    auto* spaceToolbar = new QWidget(spacePage); ks::ui::StylePrimaryToolbar(spaceToolbar);
    auto* spaceToolbarLayout = new QVBoxLayout(spaceToolbar); spaceToolbarLayout->setContentsMargins(8, 4, 8, 4); spaceToolbarLayout->setSpacing(6);
    auto* spaceBar = new QHBoxLayout;
    s.up = new QPushButton(spacePage); bind(s.up, "上一级"); spaceBar->addWidget(s.up);
    s.mapMetric = new QComboBox(spacePage); s.mapMetric->addItems({text("按占用空间"), text("按逻辑大小")});
    for (int i = 0; i < 2; ++i) { const char* labels[] = {"按占用空间", "按逻辑大小"}; ks::i18n::LanguageManager::instance().bindComboBoxItem(s.mapMetric, i, sourceKey(labels[i]), QString::fromUtf8(labels[i])); } spaceBar->addWidget(s.mapMetric);
    s.mapPath = new QLabel(spacePage); s.mapPath->setTextFormat(Qt::PlainText); s.mapPath->setTextInteractionFlags(Qt::TextSelectableByMouse); s.mapPath->setWordWrap(true); spaceBar->addWidget(s.mapPath, 1);
    ks::ui::NormalizeToolbarRow(spaceBar); spaceToolbarLayout->addLayout(spaceBar);
    s.spaceStatus = new QLabel(text("尚无空间统计"), spacePage); s.spaceStatus->setTextFormat(Qt::PlainText); s.spaceStatus->setWordWrap(true); spaceToolbarLayout->addWidget(s.spaceStatus);
    spaceLayout->addWidget(spaceToolbar);
    auto* counting = new QLabel(spacePage); bind(counting, "方块越大，占用越多；双击目录可进入。这里只统计文件的默认数据流，不等于磁盘全部已用空间。"); counting->setWordWrap(true); spaceLayout->addWidget(counting);
    auto* split = new QSplitter(Qt::Vertical, spacePage);
    auto* tables = new QSplitter(Qt::Horizontal, split);
    s.directories = new QTreeView(tables); s.directoryModel = new DirectoryModel(s.directories); s.directories->setModel(s.directoryModel); s.directories->setUniformRowHeights(true); s.directories->setSelectionBehavior(QAbstractItemView::SelectRows); s.directories->setColumnWidth(0, 260); s.directories->setProperty(ks::ui::TableActionBarModeProperty, int(ks::ui::TableActionBarMode::None)); ks::ui::ApplyTablePresentation(s.directories);
    s.extensions = new ks::ui::TableActionTableView(tables); s.extensionModel = new ExtensionModel(s.extensions); configureTable(s.extensions, s.extensionModel, {"extension", "logical", "allocated", "files", "unknown"});
    s.map = new NtfsSpaceMapWidget(split); split->setStretchFactor(0, 1); split->setStretchFactor(1, 2); spaceLayout->addWidget(split, 1);
    s.tabs->addTab(spacePage, text("空间分布"));
    ks::i18n::LanguageManager::instance().bindTab(s.tabs, spacePage, sourceKey("空间分布"), QStringLiteral("空间分布"));
    workspace->finish();
    updateUnavailableResults("先选择磁盘，输入文件名或关键词，再点击“扫描并搜索”。");
    for (auto* operation : {s.indexOperation, s.searchOperation, s.spaceOperation, s.volumeOperation})
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
    const auto requestSearch = [this] { m_state->tabs->setCurrentIndex(0); startSearch(); };
    connect(s.search, &QPushButton::clicked, this, requestSearch);
    connect(s.query, &QLineEdit::returnPressed, this, requestSearch);
    connect(s.locate, &QPushButton::clicked, this, &NtfsSearchPage::locateSelected);
    connect(s.results, &QTableView::doubleClicked, this, [this] { locateSelected(); });
    connect(s.results->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { updateButtons(); });
    connect(s.volume, &QComboBox::currentIndexChanged, this, [this] {
        auto& state = *m_state;
        if (!state.discovering && !state.indexing) {
            state.searchOperation->cancel(); state.spaceOperation->cancel(); restoreSpaceDirectory();
        }
        updateButtons();
    });
    connect(s.directories, &QTreeView::clicked, this, [this](const QModelIndex& i) { showDirectory(quint64(i.internalId())); });
    connect(s.up, &QPushButton::clicked, this, [this] { const auto& state = *m_state; if (state.projection && state.currentDirectory != state.projection->root) showDirectory(state.projection->directories.value(state.currentDirectory).parent); });
    connect(s.mapMetric, &QComboBox::currentIndexChanged, this, [this] { showDirectory(m_state->currentDirectory); });
    s.map->activated = [this](quint64 id) {
        auto& state = *m_state;
        if (!hasSelectedVolumeIndex()) return;
        auto it = state.projection->snapshot->entries.constFind(id);
        if (it != state.projection->snapshot->entries.cend() && it->isDirectory()) showDirectory(id);
        else if (it != state.projection->snapshot->entries.cend()) emit locatePathRequested(Index::fullPath(*state.projection->snapshot, id));
    };
    s.map->selected = [this](quint64 id) {
        auto& state = *m_state;
        if (!hasSelectedVolumeIndex()) return;
        const auto it = state.projection->snapshot->entries.constFind(id);
        if (it != state.projection->snapshot->entries.cend()) state.mapPath->setText(Index::fullPath(*state.projection->snapshot, id));
    };
    updateButtons();
    discoverVolumes();
}

NtfsSearchPage::~NtfsSearchPage()
{
    if (m_state->cancelToken) m_state->cancelToken->store(true);
    m_state->indexOperation->close(); m_state->searchOperation->close(); m_state->spaceOperation->close(); m_state->volumeOperation->close();
    retire(std::move(m_state->projection));
}

void NtfsSearchPage::discoverVolumes()
{
    auto& s = *m_state;
    if (s.indexing || s.discovering) return;
    s.discovering = true;
    if (!s.projection && !s.indexFailed) {
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
            if (!state.projection && !state.indexFailed) {
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
    if (s.projection) return; // A failed refresh never removes the last usable snapshot.
    s.searchText.set(s.searchStatus, message);
    s.spaceText.set(s.spaceStatus, message);
    s.map->setEmptyMessage(QString::fromUtf8(message));
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
    if (s.spaceOperation->isBusy()) {
        s.spaceOperation->cancel();
        restoreSpaceDirectory();
        s.spaceText.set(s.spaceStatus, "MFT 空间汇总已取消；可重新选择目录或计量方式。");
        s.map->setEmptyMessage(QStringLiteral("MFT 空间汇总已取消；可重新选择目录或计量方式。"));
    }
    updateButtons();
}

void NtfsSearchPage::restoreSpaceDirectory()
{
    auto& s = *m_state;
    s.currentDirectory = s.displayedDirectory ? s.displayedDirectory : s.projection ? s.projection->root : 0;
    s.mapPath->setText(s.displayedDirectoryPath);
}

void NtfsSearchPage::updateButtons()
{
    auto& s = *m_state;
    const bool volumeAvailable = !s.volume->currentData().toString().isEmpty();
    s.volume->setEnabled(!s.indexing && !s.discovering && volumeAvailable);
    s.discover->setEnabled(!s.indexing && !s.discovering);
    s.build->setEnabled(!s.indexing && !s.discovering && volumeAvailable);
    const bool sameVolume = hasSelectedVolumeIndex();
    s.refresh->setEnabled(!s.indexing && !s.discovering && !s.journalInvalid && sameVolume && s.projection->snapshot->journalAvailable);
    const bool searching = s.searchOperation->isBusy(), summarizing = s.spaceOperation->isBusy();
    s.cancel->setEnabled((s.indexing && s.cancelToken && !s.cancelToken->load()) || searching || summarizing);
    s.build->setText(text(s.indexing && !s.incremental ? "正在扫描磁盘…"
        : sameVolume || s.indexFailed ? "重新扫描磁盘" : "加载文件列表"));
    s.refresh->setText(text(s.indexing && s.incremental ? "正在更新文件列表…" : "更新文件列表"));
    s.discover->setText(text(s.discovering ? "正在查询磁盘…" : "刷新磁盘列表"));
    s.search->setText(text(s.indexing ? "正在准备文件列表…" : searching ? "正在搜索…" : sameVolume ? "搜索" : "扫描并搜索"));
    s.search->setEnabled(volumeAvailable && !s.discovering && !s.indexing && !searching);
    s.mapMetric->setEnabled(sameVolume);
    s.directories->setEnabled(sameVolume);
    s.map->setEnabled(sameVolume);
    const auto* row = s.searchModel->row(s.results->currentIndex().row());
    s.locate->setEnabled(sameVolume && row && !row->path.isEmpty());
    s.up->setEnabled(sameVolume && s.currentDirectory != s.projection->root);
    const QString needsIndex = text("请先点击“扫描并搜索”加载所选磁盘的文件列表。");
    s.search->setToolTip(s.indexing || searching ? text("任务正在后台运行；可点击“停止”取消。")
        : !sameVolume ? text("先扫描所选磁盘，再按当前关键词搜索；不会修改磁盘文件。") : text("搜索当前磁盘的文件列表；也可在输入框按 Enter。"));
    s.mapMetric->setToolTip(!sameVolume ? needsIndex : QString());
    s.directories->setToolTip(!sameVolume ? needsIndex : QString());
    s.up->setToolTip(!sameVolume ? needsIndex : s.currentDirectory == s.projection->root ? text("已位于 MFT 索引卷的根目录。") : QString());
    s.locate->setToolTip(!sameVolume ? needsIndex : !row ? text("请先选择一个搜索结果，或双击结果直接定位。")
        : row->path.isEmpty() ? text("此 MFT 记录的完整路径无法解析，不能定位。") : row->path);
    s.build->setToolTip(s.indexing ? text("任务正在后台运行；可点击“停止”取消。")
        : s.discovering ? text("正在查询磁盘，请等待列表返回。")
        : !volumeAvailable ? text("请先刷新磁盘列表并选择本地 NTFS 磁盘。") : text("重新读取所选磁盘的完整文件列表。"));
    s.refresh->setToolTip(s.indexing ? text("任务正在后台运行；可点击“停止”取消。")
        : s.discovering ? text("正在查询磁盘，请等待列表返回。")
        : !sameVolume ? needsIndex
        : s.journalInvalid || !s.projection->snapshot->journalAvailable ? text("文件变更记录不可用，请点击“重新扫描磁盘”更新完整列表。")
        : text("读取上次扫描后的文件变更，更新当前磁盘的文件列表。"));
    s.cancel->setToolTip(text("停止当前扫描、搜索或空间统计；保留上一次可用结果。"));
    if (s.discovering) s.workflowHint->setText(text("正在查找可搜索的磁盘，请稍候。"));
    else if (!volumeAvailable) s.workflowHint->setText(text("没有可搜索的磁盘，请刷新磁盘列表。"));
    else if (s.indexing) s.workflowHint->setText(text("正在准备文件列表，完成后自动显示搜索结果。可以点击“停止”取消。"));
    else if (!sameVolume) s.workflowHint->setText(text("下一步：输入关键词，点击“扫描并搜索”。留空可加载文件列表并查看空间分布。"));
    else s.workflowHint->setText(text("文件列表已就绪。输入关键词后点击“搜索”或按 Enter；双击结果可定位文件。"));
    s.resultSource->setVisible(bool(s.projection));
    s.indexDetails->setVisible(bool(s.projection));
    s.coverageHint->setVisible(s.projection && s.projection->snapshot->namesIncompleteCount != 0);
    if (s.projection) {
        s.indexDetails->setText(ks::i18n::LanguageManager::instance().displayText(s.projection->snapshot->status));
        s.coverageHint->setText(text("注意：%1 个文件的名称可能不完整，搜索结果可能遗漏这些名称。")
            .arg(s.projection->snapshot->namesIncompleteCount));
    }
    if (s.projection) s.resultSource->setText(sameVolume
        ? text("当前结果来自磁盘 %1").arg(s.projection->snapshot->volumeRoot)
        : text("仍显示磁盘 %1 的上次结果。所选磁盘 %2 尚未加载，请点击“扫描并搜索”。")
            .arg(s.projection->snapshot->volumeRoot, s.volume->currentData().toString()));
}

bool NtfsSearchPage::hasSelectedVolumeIndex() const
{
    const auto& s = *m_state;
    return s.projection && QString::compare(s.projection->snapshot->volumeRoot,
        s.volume->currentData().toString(), Qt::CaseInsensitive) == 0;
}

void NtfsSearchPage::startIndex(bool incremental)
{
    auto& s = *m_state;
    if (s.indexing || s.discovering || s.volume->currentData().toString().isEmpty()) return;
    s.searchOperation->cancel(); s.spaceOperation->cancel(); restoreSpaceDirectory();
    struct Request {
        QString volume;
        Index::Snapshot previous;
        Index::Cancel cancel;
        std::shared_ptr<std::atomic<quint64>> processed, total;
    };
    struct Result { Index::Snapshot snapshot; ProjectionPtr projection; };
    s.cancelToken = std::make_shared<std::atomic_bool>(false);
    s.processed = std::make_shared<std::atomic<quint64>>(0);
    s.total = std::make_shared<std::atomic<quint64>>(0);
    Request request{s.volume->currentData().toString(), incremental && s.projection ? s.projection->snapshot : Index::Snapshot(),
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
            if (result.snapshot && result.snapshot->complete && !result.snapshot->cancelled && !request.cancel->load())
                result.projection = project(result.snapshot, request.cancel);
            return result;
        },
        [this](const Result& result, std::uint64_t) {
            auto& state = *m_state;
            state.indexing = false; state.progressTimer->stop(); state.progress->hide();
            if ((result.snapshot && result.snapshot->cancelled) || (state.cancelToken && state.cancelToken->load())) {
                state.indexText.set(state.indexStatus, state.projection ? "已停止；保留上一次可用文件列表。" : "扫描已停止；点击“扫描并搜索”可重试。");
                ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Idle);
                updateUnavailableResults("扫描已停止；点击“扫描并搜索”可重试。"); updateButtons(); return true;
            }
            if (!result.snapshot || !result.snapshot->complete || !result.projection) {
                state.indexFailed = true;
                if (result.snapshot && result.snapshot->rebuildRequired) state.journalInvalid = true;
                if (!result.snapshot) state.indexText.set(state.indexStatus, "未能加载文件列表；点击“扫描并搜索”可重试。");
                else state.indexText.set(state.indexStatus, result.snapshot->rebuildRequired ? "文件变更记录已失效；请展开“索引维护与说明”，重新扫描磁盘。%1"
                    : state.projection ? "更新失败；保留上一次文件列表。%1" : "未能读取文件列表：%1 请检查管理员权限与磁盘状态，再点击“扫描并搜索”重试。", {result.snapshot->error}, true);
                ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Error);
                updateUnavailableResults("文件列表未能加载；查看上方原因，再点击“扫描并搜索”重试。"); updateButtons(); return true;
            }
            // No old directory tile may be interpreted through a replacement
            // snapshot while its new projection is still being prepared.
            state.spaceOperation->cancel();
            state.journalInvalid = false;
            state.displayedDirectory = 0; state.displayedDirectoryPath.clear();
            state.extensionModel->setResult({}); state.map->setData({});
            auto old = std::move(state.projection); state.projection = result.projection; retire(std::move(old));
            ks::ui::ApplyStatusRole(state.indexStatus, ks::ui::StatusRole::Success);
            state.directoryModel->setProjection(state.projection); state.directories->expandToDepth(0);
            state.indexText.set(state.indexStatus, "已加载 %1：%2 条文件记录；%3 个文件大小未知；更新于 %4。",
                {result.snapshot->volumeRoot, QString::number(result.snapshot->entries.size()), QString::number(result.snapshot->unknownSizeCount),
                 state.projection->sampledAt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))});
            showDirectory(state.projection->root); startSearch(); updateButtons(); return true;
        },
        [this](std::exception_ptr) {
            auto& state = *m_state; state.indexing = false; state.progressTimer->stop(); state.progress->hide();
            state.indexFailed = true;
            state.indexText.set(state.indexStatus, state.projection ? "加载任务失败；保留上一次文件列表，可重新扫描磁盘。"
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
    struct Request { ProjectionPtr projection; QString query; bool fullPath, wildcard; int type; };
    Request request{s.projection, s.query->text(), s.fullPath->isChecked(), s.wildcard->isChecked(), s.searchType->currentIndex()};
    s.searchText.set(s.searchStatus, "正在搜索索引…");
    s.searchOperation->submit<Request, SearchResult>(std::move(request),
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            SearchResult result;
            const auto& snapshot = *request.projection->snapshot;
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
                    {QString::number(prepared->matches), QString::number(prepared->rows.size()), state.projection->snapshot->volumeRoot});
                updateButtons(); state.searchOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("ntfs-search"),
                {ks::ui::ResultTableHost::ensure(m_state->results)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) { m_state->searchText.set(m_state->searchStatus, "搜索失败，请重试"); });
}

void NtfsSearchPage::showDirectory(quint64 reference)
{
    auto& s = *m_state;
    if (!hasSelectedVolumeIndex() || !s.projection->directories.contains(reference)) return;
    struct Request { ProjectionPtr projection; quint64 reference; bool allocated; };
    Request request{s.projection, reference, s.mapMetric->currentIndex() == 0};
    s.currentDirectory = reference;
    s.mapPath->setText(s.projection->directories[reference].path);
    s.spaceText.set(s.spaceStatus, "正在汇总空间分布…");
    s.map->setEmptyMessage(QStringLiteral("正在汇总空间分布…")); updateButtons();
    s.spaceOperation->submit<Request, SpaceResult>(std::move(request),
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            SpaceResult result;
            result.reference = request.reference;
            const auto& projection = *request.projection;
            const auto& snapshot = *projection.snapshot;
            const auto& directory = projection.directories[request.reference];
            result.path = directory.path; result.totals = directory.totals;
            const auto direct = projection.children.value(request.reference);
            QVector<NtfsSpaceMapWidget::Item> mapItems;
            for (quint64 id : direct) {
                if (token.isCanceled()) return SpaceResult();
                const auto it = snapshot.entries.constFind(id);
                if (it == snapshot.entries.cend()) continue;
                quint64 size = request.allocated ? it->allocatedBytes : it->logicalBytes;
                if (it->isDirectory()) { const auto& t = projection.directories[id].totals; size = request.allocated ? t.allocated : t.logical; }
                else if (!it->sizeKnown) continue;
                if (!size) continue;
                mapItems.append({id, it->name, Index::fullPath(snapshot, id), extension(it->name), size, it->isDirectory()});
            }
            std::sort(mapItems.begin(), mapItems.end(), [](const auto& a, const auto& b) { return a.bytes > b.bytes; });
            result.map = NtfsSpaceMapWidget::prepare(std::move(mapItems));
            QHash<QString, ExtensionRow> extensions;
            QVector<quint64> pending{request.reference};
            while (!pending.isEmpty()) {
                if (token.isCanceled()) return SpaceResult();
                const quint64 parent = pending.takeLast();
                for (quint64 id : projection.children.value(parent)) {
                    const auto it = snapshot.entries.constFind(id);
                    if (it == snapshot.entries.cend()) continue;
                    if (it->isDirectory()) { pending.append(id); continue; }
                    const QString suffix = extension(it->name);
                    auto& row = extensions[suffix]; row.extension = suffix; ++row.files;
                    if (it->sizeKnown) { row.logical = addBytes(row.logical, it->logicalBytes); row.allocated = addBytes(row.allocated, it->allocatedBytes); }
                    else ++row.unknown;
                }
            }
            result.extensions.reserve(extensions.size());
            for (const auto& row : extensions) result.extensions.append(row);
            std::sort(result.extensions.begin(), result.extensions.end(), [allocated = request.allocated](const auto& a, const auto& b) { return allocated ? a.allocated > b.allocated : a.logical > b.logical; });
            return result;
        },
        [this](const SpaceResult& result, std::uint64_t generation) {
            const auto prepared = std::make_shared<const SpaceResult>(result);
            const auto action = [this, prepared, generation] {
                auto& state = *m_state;
                if (!state.spaceOperation->isCurrent(generation)) return;
                state.extensionModel->setResult(prepared);
                state.map->setData(prepared->map);
                state.map->setEmptyMessage(QString());
                state.displayedDirectory = prepared->reference;
                state.displayedDirectoryPath = prepared->path;
                state.mapPath->setText(prepared->path);
                state.spaceText.set(state.spaceStatus, "文件 %1；已计量逻辑大小 %2；已计量占用 %3；未计量 %4；快照 %5",
                    {QString::number(prepared->totals.files), bytes(prepared->totals.logical), bytes(prepared->totals.allocated),
                     QString::number(prepared->totals.unknown), state.projection->sampledAt.toString(QStringLiteral("HH:mm:ss"))});
                state.spaceOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("ntfs-space"),
                {ks::ui::ResultTableHost::ensure(m_state->extensions)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            restoreSpaceDirectory();
            m_state->spaceText.set(m_state->spaceStatus, "MFT 空间汇总失败；请重新选择目录或计量方式重试。");
            m_state->map->setEmptyMessage(QStringLiteral("MFT 空间汇总失败；请重新选择目录或计量方式重试。"));
            updateButtons();
        });
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
    if (event->type() != QEvent::LanguageChange || !m_state || !m_state->directoryModel) return;
    auto& state = *m_state;
    state.indexText.render(state.indexStatus);
    state.searchText.render(state.searchStatus);
    state.spaceText.render(state.spaceStatus);
    if (state.volume->count() == 1 && state.volume->currentData().toString().isEmpty())
        state.volume->setItemText(0, ks::i18n::sourceText(state.volumeMessage));
    state.searchModel->retranslate(); state.extensionModel->retranslate(); state.directoryModel->retranslate();
    state.results->viewport()->update(); state.extensions->viewport()->update(); state.directories->viewport()->update();
    state.map->update();
    updateButtons();
}
