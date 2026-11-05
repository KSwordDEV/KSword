#include "DiskSpacePage.h"
#include "DirectorySpaceScanner.h"
#include "DirectoryScopePicker.h"
#include "../UI/SegmentedControl.h"
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
#include <QCryptographicHash>
#include <QEvent>
#include <QTabBar>
#include <QDateTime>
#include <QDir>
#include <QHeaderView>
#include <QLabel>
#include <QProgressBar>
#include <QPushButton>
#include <QRunnable>
#include <QSet>
#include <QSignalBlocker>
#include <QSplitter>
#include <QTableView>
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
    QModelIndex indexForReference(quint64 reference) const {
        if (!m_data) return {};
        const auto it = m_data->directories.constFind(reference);
        return it == m_data->directories.cend() ? QModelIndex() : createIndex(it->row, 0, quintptr(reference));
    }
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


namespace {
QString normalizedFolder(const QString& path)
{
    QString result = QDir::toNativeSeparators(QDir::cleanPath(QDir::fromNativeSeparators(path.trimmed())));
    if (!result.endsWith(QLatin1Char('\\'))) result += QLatin1Char('\\');
    return result;
}

// Select directories by identity, then choose one in-scope name per file.
// A file whose canonical hard link is outside the requested folder must still
// count when another name belongs to this folder.
Index::Snapshot scopeMftSnapshot(const Index::Snapshot& source, const QString& folder, const Index::Cancel& cancel)
{
    if (!source || !source->complete || source->cancelled) return {};
    const QString requested = normalizedFolder(folder);
    quint64 root = 0;
    if (QString::compare(requested, normalizedFolder(source->volumeRoot), Qt::CaseInsensitive) == 0)
        root = source->rootReference;
    else for (auto it = source->entries.cbegin(); it != source->entries.cend(); ++it) {
        if (cancel->load()) return {};
        if (it->isDirectory() && QString::compare(normalizedFolder(Index::fullPath(*source, it.key())), requested, Qt::CaseInsensitive) == 0) {
            root = it.key(); break;
        }
    }
    if (!root) return {};
    QHash<quint64, QVector<quint64>> children;
    for (auto it = source->entries.cbegin(); it != source->entries.cend(); ++it) {
        if (cancel->load()) return {};
        if (it->isDirectory() && it.key() != root && it.key() != it->parentReference)
            children[it->parentReference].append(it.key());
    }
    QSet<quint64> directories;
    QVector<quint64> pending{root};
    while (!pending.isEmpty()) {
        if (cancel->load()) return {};
        const auto id = pending.takeLast();
        if (directories.contains(id)) continue;
        directories.insert(id);
        const auto entry = source->entries.constFind(id);
        // Keep the directory itself visible, but never project a linked or
        // offline target as if its contents had been scanned in this scope.
        constexpr quint32 skippedDirectoryAttributes = 0x400U | 0x1000U | 0x40000U | 0x400000U;
        if (entry != source->entries.cend() && !(entry->attributes & skippedDirectoryAttributes))
            pending += children.value(id);
    }
    auto result = std::make_shared<ks::files::NtfsIndexSnapshot>();
    result->volumeRoot = requested;
    result->rootReference = root;
    result->volumeSerial = source->volumeSerial;
    result->status = source->status;
    for (auto it = source->entries.cbegin(); it != source->entries.cend(); ++it) {
        if (cancel->load()) return {};
        Entry entry = it.value();
        if (entry.isDirectory()) {
            if (!directories.contains(it.key())) continue;
            if (it.key() == root) { entry.parentReference = root; entry.name = requested; }
        } else {
            QVector<ks::files::NtfsIndexName> names = entry.names;
            if (names.isEmpty()) names.append({entry.parentReference, entry.name});
            names.erase(std::remove_if(names.begin(), names.end(), [&directories, &source](const auto& name) {
                const auto parent = source->entries.constFind(name.parentReference);
                return !directories.contains(name.parentReference) || parent == source->entries.cend()
                    || (parent->attributes & (0x400U | 0x1000U | 0x40000U | 0x400000U));
            }), names.end());
            if (names.isEmpty()) continue;
            std::sort(names.begin(), names.end(), [](const auto& a, const auto& b) {
                return a.parentReference == b.parentReference ? a.name < b.name : a.parentReference < b.parentReference;
            });
            entry.parentReference = names.first().parentReference;
            entry.name = names.first().name;
            entry.names = std::move(names);
            if (!entry.sizeKnown) ++result->unknownSizeCount;
        }
        if (entry.hasAttributeList && !entry.attributeListResident) ++result->namesIncompleteCount;
        result->entries.insert(it.key(), std::move(entry));
    }
    result->complete = true;
    return result;
}

struct ScanResult {
    Index::Snapshot snapshot;
    ProjectionPtr projection;
    QString error;
    quint64 skippedDirectories = 0, skippedReparsePoints = 0, duplicateFiles = 0;
};
}

struct DiskSpacePage::State {
    ks::ui::AsyncOperation *scanOperation = nullptr, *spaceOperation = nullptr, *extensionOperation = nullptr;
    DirectoryScopePicker* folder = nullptr;
    QTabBar *mode = nullptr, *mapMetric = nullptr;
    QPushButton *scan = nullptr, *cancel = nullptr, *up = nullptr, *locate = nullptr;
    QLabel *scanStatus = nullptr, *source = nullptr, *coverage = nullptr, *spaceStatus = nullptr, *mapPath = nullptr, *extensionStatus = nullptr;
    QProgressBar* progress = nullptr;
    QTimer* progressTimer = nullptr;
    QTreeView* directories = nullptr;
    QTableView* extensions = nullptr;
    DirectoryModel* directoryModel = nullptr;
    ExtensionModel* extensionModel = nullptr;
    NtfsSpaceMapWidget* map = nullptr;
    Index::Cancel cancelToken;
    std::shared_ptr<std::atomic<quint64>> processed, total;
    ProjectionPtr projection;
    QString scannedFolder, selectedPath, displayedDirectoryPath;
    int scannedMode = 0, displayedMetric = 0;
    quint64 currentDirectory = 0, displayedDirectory = 0;
    quint64 skippedDirectories = 0, skippedReparsePoints = 0, duplicateFiles = 0;
    bool scanning = false;
    StatusText scanText{QStringLiteral("先在左侧目录树选择磁盘或文件夹，再点击“开始扫描”。"), {}, false};
    StatusText spaceText{QStringLiteral("尚无空间统计"), {}, false};
    StatusText extensionText{QStringLiteral("正在统计文件类型…"), {}, false};
};

DiskSpacePage::DiskSpacePage(QWidget* parent) : QWidget(parent), m_state(std::make_unique<State>())
{
    auto& s = *m_state;
    setObjectName(QStringLiteral("disk_space_page"));
    s.scanOperation = new ks::ui::AsyncOperation(this);
    s.spaceOperation = new ks::ui::AsyncOperation(this);
    s.extensionOperation = new ks::ui::AsyncOperation(this);
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    ks::ui::StyleWorkspacePage(this, 0);
    ks::ui::StyleWorkspaceContentFrame(this, 6);
    auto* workspace = new ks::ui::ParameterWorkspace(this, 320);
    layout->addWidget(workspace);

    // The directory browser owns scrolling. It must receive the available
    // height, rather than becoming a fixed tree inside a scrolling form.
    auto* scopePanel = new QWidget(this);
    auto* scopeLayout = new QVBoxLayout(scopePanel);
    scopeLayout->setContentsMargins(0, 0, 0, 0); scopeLayout->setSpacing(8);
    auto* scopeTitle = new QLabel(scopePanel); bind(scopeTitle, "扫描范围"); scopeLayout->addWidget(scopeTitle);
    s.folder = new DirectoryScopePicker(scopePanel);
    scopeLayout->addWidget(s.folder, 1);
    auto* methodLabel = new QLabel(scopePanel); bind(methodLabel, "扫描方式"); scopeLayout->addWidget(methodLabel);
    s.mode = new QTabBar(scopePanel); s.mode->setObjectName(QStringLiteral("disk_space_mode"));
    s.mode->setExpanding(true); s.mode->setUsesScrollButtons(false); s.mode->setElideMode(Qt::ElideRight);
    s.mode->addTab(text("普通文件遍历")); s.mode->addTab(text("MFT 快速扫描"));
    ks::ui::InstallSegmentedTabBar(s.mode); scopeLayout->addWidget(s.mode);
    ks::i18n::LanguageManager::instance().bindToolTip(s.mode,
        sourceKey("普通遍历支持当前账户可访问的文件系统，只扫描所选范围，不进入目录链接或联接点。MFT 模式需要管理员权限和本地 NTFS，会读取所在卷的索引，再显示所选范围。"),
        QStringLiteral("普通遍历支持当前账户可访问的文件系统，只扫描所选范围，不进入目录链接或联接点。MFT 模式需要管理员权限和本地 NTFS，会读取所在卷的索引，再显示所选范围。"));
    workspace->setParameterViewport(scopePanel);
    s.scan = new QPushButton(this); s.scan->setObjectName(QStringLiteral("disk_space_scan")); bind(s.scan, "开始扫描");
    ks::ui::ApplyFlatButtonTheme(s.scan, ks::ui::FlatButtonTone::Accent);
    s.cancel = new QPushButton(this); s.cancel->setObjectName(QStringLiteral("disk_space_stop")); bind(s.cancel, "停止");
    workspace->actions()->addWidget(s.scan, 1); workspace->actions()->addWidget(s.cancel); ks::ui::NormalizeToolbarRow(workspace->actions());

    auto* header = new QWidget(this); ks::ui::StylePrimaryToolbar(header);
    auto* headerLayout = new QVBoxLayout(header); headerLayout->setContentsMargins(8, 4, 8, 4); headerLayout->setSpacing(6);
    s.source = new QLabel(header); s.source->setObjectName(QStringLiteral("disk_space_source")); s.source->setTextFormat(Qt::PlainText); s.source->setWordWrap(true); headerLayout->addWidget(s.source);
    s.scanStatus = new QLabel(header); s.scanStatus->setObjectName(QStringLiteral("disk_space_status")); s.scanStatus->setTextFormat(Qt::PlainText); s.scanStatus->setWordWrap(true); s.scanStatus->setTextInteractionFlags(Qt::TextSelectableByMouse); headerLayout->addWidget(s.scanStatus);
    s.coverage = new QLabel(header); s.coverage->setObjectName(QStringLiteral("disk_space_coverage")); s.coverage->setTextFormat(Qt::PlainText); s.coverage->setWordWrap(true); ks::ui::ApplyStatusRole(s.coverage, ks::ui::StatusRole::Warning); headerLayout->addWidget(s.coverage);
    s.progress = new QProgressBar(header); s.progress->setRange(0, 0); s.progress->hide(); headerLayout->addWidget(s.progress);
    workspace->results()->addWidget(header);

    auto* toolbar = new QWidget(this); ks::ui::StylePrimaryToolbar(toolbar);
    auto* toolbarLayout = new QVBoxLayout(toolbar); toolbarLayout->setContentsMargins(8, 4, 8, 4); toolbarLayout->setSpacing(6);
    auto* tools = new QHBoxLayout;
    s.up = new QPushButton(toolbar); bind(s.up, "上一级"); tools->addWidget(s.up);
    s.mapMetric = new QTabBar(toolbar); s.mapMetric->setObjectName(QStringLiteral("disk_space_metric"));
    s.mapMetric->setExpanding(false); s.mapMetric->setUsesScrollButtons(false); s.mapMetric->setElideMode(Qt::ElideRight);
    s.mapMetric->addTab(text("占用空间")); s.mapMetric->addTab(text("逻辑大小"));
    ks::ui::InstallSegmentedTabBar(s.mapMetric);
    tools->addWidget(s.mapMetric); tools->addStretch();
    s.locate = new QPushButton(toolbar); bind(s.locate, "打开所在文件夹"); tools->addWidget(s.locate); ks::ui::NormalizeToolbarRow(tools); toolbarLayout->addLayout(tools);
    s.mapPath = new QLabel(toolbar); s.mapPath->setTextFormat(Qt::PlainText); s.mapPath->setWordWrap(true); s.mapPath->setTextInteractionFlags(Qt::TextSelectableByMouse); toolbarLayout->addWidget(s.mapPath);
    s.spaceStatus = new QLabel(toolbar); s.spaceStatus->setTextFormat(Qt::PlainText); s.spaceStatus->setWordWrap(true); toolbarLayout->addWidget(s.spaceStatus);
    ks::i18n::LanguageManager::instance().bindToolTip(s.mapMetric,
        sourceKey("空间表示文件默认数据流的逻辑大小或分配大小；不包括备用数据流、目录索引等元数据及空闲空间，不等于磁盘全部已用空间。硬链接在扫描范围内只计一次；无法访问或计量的项目会单独提示。"),
        QStringLiteral("空间表示文件默认数据流的逻辑大小或分配大小；不包括备用数据流、目录索引等元数据及空闲空间，不等于磁盘全部已用空间。硬链接在扫描范围内只计一次；无法访问或计量的项目会单独提示。"));
    workspace->results()->addWidget(toolbar);

    auto* split = new QSplitter(Qt::Vertical, this);
    auto* tables = new QSplitter(Qt::Horizontal, split);
    s.directories = new QTreeView(tables); s.directories->setObjectName(QStringLiteral("disk_space_directories"));
    s.directoryModel = new DirectoryModel(s.directories); s.directories->setModel(s.directoryModel); s.directories->setUniformRowHeights(true); s.directories->setSelectionBehavior(QAbstractItemView::SelectRows); s.directories->setColumnWidth(0, 260); s.directories->setProperty(ks::ui::TableActionBarModeProperty, int(ks::ui::TableActionBarMode::None)); ks::ui::ApplyTablePresentation(s.directories);
    auto* extensionPanel = new QWidget(tables);
    auto* extensionLayout = new QVBoxLayout(extensionPanel); extensionLayout->setContentsMargins(0, 0, 0, 0); extensionLayout->setSpacing(6);
    s.extensionStatus = new QLabel(extensionPanel); s.extensionStatus->setTextFormat(Qt::PlainText); s.extensionStatus->setWordWrap(true); s.extensionStatus->hide(); extensionLayout->addWidget(s.extensionStatus);
    s.extensions = new ks::ui::TableActionTableView(extensionPanel); s.extensions->setObjectName(QStringLiteral("disk_space_extensions")); s.extensionModel = new ExtensionModel(s.extensions); configureTable(s.extensions, s.extensionModel, {"extension", "logical", "allocated", "files", "unknown"}); extensionLayout->addWidget(s.extensions, 1);
    s.map = new NtfsSpaceMapWidget(split); s.map->setObjectName(QStringLiteral("disk_space_map"));
    split->setStretchFactor(0, 1); split->setStretchFactor(1, 2); workspace->results()->addWidget(split, 1);
    workspace->finish();
    s.scanText.render(s.scanStatus); s.spaceText.render(s.spaceStatus);
    s.map->setEmptyMessage(QStringLiteral("先在左侧目录树选择磁盘或文件夹，再点击“开始扫描”。"));
    s.progressTimer = new QTimer(this); s.progressTimer->setInterval(200);
    connect(s.progressTimer, &QTimer::timeout, this, [this] {
        auto& state = *m_state;
        if (!state.scanning || !state.processed || (state.cancelToken && state.cancelToken->load())) return;
        const auto done = state.processed->load(), count = state.total->load();
        state.scanText.set(state.scanStatus, "已读取 %1 / %2 条文件记录", {QString::number(done), count ? QString::number(count) : text("未知")});
        state.progress->setRange(0, count ? 100 : 0);
        if (count) state.progress->setValue(int(std::min<long double>(100, 100.0L * done / count)));
    });
    for (auto* operation : {s.scanOperation, s.spaceOperation, s.extensionOperation})
        operation->setStateChangedCallback([this] { updateButtons(); });
    connect(s.scan, &QPushButton::clicked, this, &DiskSpacePage::startScan);
    connect(s.cancel, &QPushButton::clicked, this, &DiskSpacePage::cancelOperations);
    s.folder->selectionChanged = [this](const QString&) { updateButtons(); };
    connect(s.mode, &QTabBar::currentChanged, this, [this] { updateButtons(); });
    connect(s.up, &QPushButton::clicked, this, [this] { const auto& state = *m_state; if (state.projection && state.currentDirectory != state.projection->root) showDirectory(state.projection->directories.value(state.currentDirectory).parent); });
    connect(s.mapMetric, &QTabBar::currentChanged, this, [this] { showDirectory(m_state->currentDirectory); });
    connect(s.directories->selectionModel(), &QItemSelectionModel::currentChanged, this,
        [this](const QModelIndex& index) { if (index.isValid()) showDirectory(quint64(index.internalId())); });
    connect(s.locate, &QPushButton::clicked, this, [this] { if (!m_state->selectedPath.isEmpty()) emit locatePathRequested(m_state->selectedPath); });
    s.map->activated = [this](quint64 id) {
        auto& state = *m_state;
        if (!state.projection || state.scanning) return;
        const auto it = state.projection->snapshot->entries.constFind(id);
        if (it == state.projection->snapshot->entries.cend()) return;
        if (it->isDirectory()) showDirectory(id);
        else emit locatePathRequested(Index::fullPath(*state.projection->snapshot, id));
    };
    s.map->selected = [this](quint64 id) {
        auto& state = *m_state;
        if (!state.projection || state.scanning) return;
        state.selectedPath = Index::fullPath(*state.projection->snapshot, id);
        state.mapPath->setText(state.selectedPath); updateButtons();
    };
    updateButtons();
}

DiskSpacePage::~DiskSpacePage()
{
    if (m_state->cancelToken) m_state->cancelToken->store(true);
    m_state->scanOperation->close(); m_state->spaceOperation->close(); m_state->extensionOperation->close();
    retire(std::move(m_state->projection));
}

void DiskSpacePage::updateButtons()
{
    auto& s = *m_state;
    const bool ready = bool(s.projection) && !s.scanning;
    s.folder->setEnabled(!s.scanning); s.mode->setEnabled(!s.scanning);
    s.scan->setEnabled(!s.scanning && !s.folder->selectedPath().trimmed().isEmpty());
    s.scan->setText(text(s.scanning ? "正在扫描…" : "开始扫描"));
    s.cancel->setEnabled((s.scanning && s.cancelToken && !s.cancelToken->load()) || s.spaceOperation->isBusy() || s.extensionOperation->isBusy());
    s.up->setEnabled(ready && s.currentDirectory != s.projection->root);
    s.mapMetric->setEnabled(ready); s.directories->setEnabled(ready); s.map->setEnabled(ready && !s.spaceOperation->isBusy());
    s.locate->setEnabled(ready && !s.spaceOperation->isBusy() && !s.selectedPath.isEmpty());
    s.source->setVisible(bool(s.projection));
    if (s.projection) {
        const bool matches = s.mode->currentIndex() == s.scannedMode && QString::compare(normalizedFolder(s.folder->selectedPath()), s.scannedFolder, Qt::CaseInsensitive) == 0;
        s.source->setText(text(matches ? "当前结果：%1；%2；扫描于 %3" : "上次结果：%1；%2；扫描于 %3。新范围或方式尚未扫描。")
            .arg(s.scannedFolder, text(s.scannedMode == 0 ? "普通文件遍历" : "MFT 快速扫描"), s.projection->sampledAt.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
        s.coverage->setText(text("跳过目录 %1；跳过重解析点 %2；重复硬链接 %3；大小未知 %4；名称可能不完整 %5。")
            .arg(s.skippedDirectories).arg(s.skippedReparsePoints).arg(s.duplicateFiles).arg(s.projection->snapshot->unknownSizeCount).arg(s.projection->snapshot->namesIncompleteCount));
    }
    s.coverage->setVisible(s.projection && (s.skippedDirectories || s.skippedReparsePoints || s.projection->snapshot->unknownSizeCount || s.projection->snapshot->namesIncompleteCount));
}

void DiskSpacePage::startScan()
{
    auto& s = *m_state;
    if (s.scanning || s.folder->selectedPath().trimmed().isEmpty()) return;
    s.spaceOperation->cancel(); s.extensionOperation->cancel(); s.extensionStatus->hide(); restoreSpaceDirectory();
    struct Request { QString folder; int mode; Index::Cancel cancel; std::shared_ptr<std::atomic<quint64>> processed, total; };
    s.cancelToken = std::make_shared<std::atomic_bool>(false);
    s.processed = std::make_shared<std::atomic<quint64>>(0); s.total = std::make_shared<std::atomic<quint64>>(0);
    Request request{s.folder->selectedPath().trimmed(), s.mode->currentIndex(), s.cancelToken, s.processed, s.total};
    const QString requestedFolder = normalizedFolder(request.folder); const int requestedMode = request.mode;
    s.scanning = true; s.progress->setRange(0, 0); s.progress->show(); s.progressTimer->start();
    s.scanText.set(s.scanStatus, "正在扫描所选范围…"); ks::ui::ApplyStatusRole(s.scanStatus, ks::ui::StatusRole::Info); updateButtons();
    s.scanOperation->submit<Request, ScanResult>(std::move(request),
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            ScanResult result;
            if (token.isCanceled() || request.cancel->load()) return result;
            const auto progress = [processed = request.processed, total = request.total](quint64 done, quint64 count) { processed->store(done); total->store(count); };
            if (!QDir::isAbsolutePath(QDir::fromNativeSeparators(request.folder))) {
                result.error = QStringLiteral("扫描范围必须是存在的文件夹绝对路径。"); return result;
            }
            if (request.mode == 0) {
                const auto scan = ks::files::DirectorySpaceScanner::scan(request.folder, request.cancel, progress);
                result.snapshot = scan.snapshot; result.error = scan.error;
                result.skippedDirectories = scan.skippedDirectories; result.skippedReparsePoints = scan.skippedReparsePoints; result.duplicateFiles = scan.duplicateFiles;
            } else {
#ifdef Q_OS_WIN
                struct ErrorMode {
                    DWORD previous = 0;
                    bool changed = SetThreadErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX, &previous) != FALSE;
                    ~ErrorMode() { if (changed) SetThreadErrorMode(previous, nullptr); }
                } errorMode;
                const auto folder = QDir::toNativeSeparators(request.folder).toStdWString();
                const DWORD rootAttributes = GetFileAttributesW(folder.c_str());
                if (rootAttributes == INVALID_FILE_ATTRIBUTES || !(rootAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    result.error = QStringLiteral("扫描范围必须是存在的文件夹绝对路径。"); return result;
                }
                if (rootAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE | 0x00040000U | 0x00400000U)) {
                    result.error = QStringLiteral("所选目录是重解析点或脱机目录，请选择实际的本地文件夹。"); return result;
                }
                wchar_t volume[32768]{}, filesystem[64]{};
                if (!GetVolumePathNameW(folder.c_str(), volume, DWORD(std::size(volume)))
                    || (GetDriveTypeW(volume) != DRIVE_FIXED && GetDriveTypeW(volume) != DRIVE_REMOVABLE)
                    || !GetVolumeInformationW(volume, nullptr, 0, nullptr, nullptr, nullptr, filesystem, DWORD(std::size(filesystem)))
                    || _wcsicmp(filesystem, L"NTFS") != 0) {
                    result.error = QStringLiteral("MFT 模式仅支持本地 NTFS 卷；可切换为普通文件遍历。"); return result;
                }
                const auto snapshot = Index::build(QString::fromWCharArray(volume), request.cancel, progress);
                if (!snapshot || !snapshot->complete || snapshot->cancelled) {
                    result.snapshot = snapshot;
                    if (snapshot) result.error = snapshot->error;
                    return result;
                }
                result.snapshot = scopeMftSnapshot(snapshot, request.folder, request.cancel);
                if (!result.snapshot && !request.cancel->load()) result.error = QStringLiteral("所选文件夹未在 MFT 索引中找到；请检查路径或切换为普通文件遍历。");
                if (result.snapshot) for (const auto& entry : result.snapshot->entries) {
                    if (entry.isDirectory() && (entry.attributes & (0x400U | 0x1000U | 0x40000U | 0x400000U))) ++result.skippedReparsePoints;
                }
#else
                result.error = QStringLiteral("MFT 模式仅支持本地 NTFS 卷；可切换为普通文件遍历。");
#endif
            }
            if (result.snapshot && result.snapshot->complete && !result.snapshot->cancelled && !request.cancel->load())
                result.projection = project(result.snapshot, request.cancel);
            return result;
        },
        [this, requestedFolder, requestedMode](const ScanResult& result, std::uint64_t generation) {
            auto& state = *m_state;
            state.progressTimer->stop(); state.progress->hide();
            if (state.cancelToken->load() || (result.snapshot && result.snapshot->cancelled)) {
                state.scanning = false;
                state.scanText.set(state.scanStatus, "扫描已停止；保留上一次结果，点击“开始扫描”可重试。");
                ks::ui::ApplyStatusRole(state.scanStatus, ks::ui::StatusRole::Idle); updateButtons(); return true;
            }
            if (!result.projection) {
                state.scanning = false;
                state.scanText.set(state.scanStatus, "扫描失败：%1。请检查范围、权限或扫描方式后重试。", {result.error}, true);
                ks::ui::ApplyStatusRole(state.scanStatus, ks::ui::StatusRole::Error); updateButtons(); return true;
            }
            const auto prepared = std::make_shared<const ScanResult>(result);
            const auto action = [this, prepared, requestedFolder, requestedMode, generation] {
                auto& state = *m_state;
                if (!state.scanOperation->isCurrent(generation)) return;
                if (state.cancelToken->load()) {
                    state.scanning = false;
                    state.scanText.set(state.scanStatus, "扫描已停止；保留上一次结果，点击“开始扫描”可重试。");
                    ks::ui::ApplyStatusRole(state.scanStatus, ks::ui::StatusRole::Idle);
                    updateButtons(); state.scanOperation->completeDeferred(generation); return;
                }
                state.extensionModel->setResult({}); state.map->setData({});
                state.displayedDirectory = 0; state.displayedDirectoryPath.clear(); state.selectedPath.clear();
                auto old = std::move(state.projection); state.projection = prepared->projection; retire(std::move(old));
                state.scannedFolder = requestedFolder; state.scannedMode = requestedMode;
                state.skippedDirectories = prepared->skippedDirectories; state.skippedReparsePoints = prepared->skippedReparsePoints; state.duplicateFiles = prepared->duplicateFiles;
                state.directoryModel->setProjection(state.projection); state.directories->expandToDepth(0);
                state.scanning = false;
                state.scanText.set(state.scanStatus, "扫描完成：%1 条记录；可选择目录查看空间分布。", {QString::number(prepared->snapshot->entries.size())});
                ks::ui::ApplyStatusRole(state.scanStatus, prepared->skippedDirectories || prepared->skippedReparsePoints || prepared->snapshot->unknownSizeCount || prepared->snapshot->namesIncompleteCount ? ks::ui::StatusRole::Warning : ks::ui::StatusRole::Success);
                showDirectory(state.projection->root); updateButtons(); state.scanOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("disk-space-scan"), {ks::ui::ResultTableHost::ensure(state.extensions)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            auto& state = *m_state; state.scanning = false; state.progressTimer->stop(); state.progress->hide();
            state.scanText.set(state.scanStatus, "扫描任务失败；保留上一次结果，请重新扫描。"); ks::ui::ApplyStatusRole(state.scanStatus, ks::ui::StatusRole::Error); updateButtons();
        });
}

void DiskSpacePage::cancelOperations()
{
    auto& s = *m_state;
    if (s.scanning && s.cancelToken && !s.cancelToken->exchange(true)) {
        s.scanText.set(s.scanStatus, "正在取消，请等待当前读取返回");
        ks::ui::ApplyStatusRole(s.scanStatus, ks::ui::StatusRole::Info);
    }
    if (s.spaceOperation->isBusy()) {
        s.spaceOperation->cancel(); restoreSpaceDirectory();
        s.spaceText.set(s.spaceStatus, "空间统计已停止；可重新选择目录或计量方式。");
        s.map->setEmptyMessage(QStringLiteral("空间统计已停止；可重新选择目录或计量方式。"));
    }
    if (s.extensionOperation->isBusy()) {
        s.extensionOperation->cancel();
        s.extensionText.set(s.extensionStatus, "文件类型统计已停止。"); s.extensionStatus->show();
    }
    updateButtons();
}

void DiskSpacePage::restoreSpaceDirectory()
{
    auto& s = *m_state;
    s.currentDirectory = s.displayedDirectory ? s.displayedDirectory : s.projection ? s.projection->root : 0;
    if (s.displayedDirectory) { const QSignalBlocker blocker(s.mapMetric); s.mapMetric->setCurrentIndex(s.displayedMetric); }
    {
        const QSignalBlocker selectionGuard(s.directories->selectionModel());
        s.directories->setCurrentIndex(s.directoryModel->indexForReference(s.currentDirectory));
    }
    s.selectedPath = s.displayedDirectoryPath;
    s.mapPath->setText(s.displayedDirectoryPath);
}

void DiskSpacePage::showDirectory(quint64 reference)
{
    auto& s = *m_state;
    if (!s.projection || s.scanning || !s.projection->directories.contains(reference)) return;
    s.extensionOperation->cancel(); s.extensionStatus->hide();
    struct Request { ProjectionPtr projection; quint64 reference; bool allocated; };
    Request request{s.projection, reference, s.mapMetric->currentIndex() == 0};
    s.currentDirectory = reference;
    s.selectedPath = s.projection->directories[reference].path;
    s.mapPath->setText(s.selectedPath);
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
            return result;
        },
        [this](const SpaceResult& result, std::uint64_t generation) {
            const auto prepared = std::make_shared<const SpaceResult>(result);
            const auto action = [this, prepared, generation] {
                auto& state = *m_state;
                if (!state.spaceOperation->isCurrent(generation)) return;
                state.extensionModel->setResult({});
                state.map->setData(prepared->map);
                state.map->setEmptyMessage(QString());
                state.displayedDirectory = prepared->reference;
                {
                    const QSignalBlocker selectionGuard(state.directories->selectionModel());
                    const auto index = state.directoryModel->indexForReference(prepared->reference);
                    state.directories->setCurrentIndex(index);
                    state.directories->scrollTo(index);
                }
                state.displayedMetric = state.mapMetric->currentIndex();
                state.displayedDirectoryPath = prepared->path;
                state.selectedPath = prepared->path;
                state.mapPath->setText(prepared->path);
                state.spaceText.set(state.spaceStatus, "文件 %1；已计量逻辑大小 %2；已计量占用 %3；未计量 %4；快照 %5",
                    {QString::number(prepared->totals.files), bytes(prepared->totals.logical), bytes(prepared->totals.allocated),
                     QString::number(prepared->totals.unknown), state.projection->sampledAt.toString(QStringLiteral("HH:mm:ss"))});
                loadDirectoryExtensions(prepared->reference, state.mapMetric->currentIndex() == 0);
                state.spaceOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("ntfs-space"),
                {ks::ui::ResultTableHost::ensure(m_state->extensions)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            restoreSpaceDirectory();
            m_state->spaceText.set(m_state->spaceStatus, "空间汇总失败；请重新选择目录或计量方式重试。");
            m_state->map->setEmptyMessage(QStringLiteral("空间汇总失败；请重新选择目录或计量方式重试。"));
            updateButtons();
        });
}

void DiskSpacePage::loadDirectoryExtensions(quint64 reference, bool allocated)
{
    auto& s = *m_state;
    const auto projection = s.projection;
    struct Request { ProjectionPtr projection; quint64 reference; bool allocated; };
    s.extensionText.set(s.extensionStatus, "正在统计文件类型…"); s.extensionStatus->show();
    s.extensionOperation->submit<Request, SpaceResult>({projection, reference, allocated},
        [](const Request& request, const ks::ui::AsyncOperationToken& token) {
            SpaceResult result; result.reference = request.reference;
            const auto& projection = *request.projection;
            const auto& snapshot = *projection.snapshot;
            QHash<QString, ExtensionRow> extensions;
            QVector<quint64> pending{request.reference};
            while (!pending.isEmpty()) {
                if (token.isCanceled()) return SpaceResult();
                const quint64 parent = pending.takeLast();
                for (quint64 id : projection.children.value(parent)) {
                    if (token.isCanceled()) return SpaceResult();
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
        [this, projection, reference, allocated](const SpaceResult& result, std::uint64_t generation) {
            const auto prepared = std::make_shared<const SpaceResult>(result);
            const auto action = [this, projection, reference, allocated, prepared, generation] {
                auto& state = *m_state;
                if (!state.extensionOperation->isCurrent(generation)) return;
                if (state.projection == projection && state.displayedDirectory == reference
                    && state.currentDirectory == reference && (state.mapMetric->currentIndex() == 0) == allocated) {
                    state.extensionModel->setResult(prepared);
                    state.extensionStatus->hide();
                }
                state.extensionOperation->completeDeferred(generation);
            };
            const auto submission = ks::ui::ResultTableHost::submitGroup(this, QStringLiteral("ntfs-extensions"),
                {ks::ui::ResultTableHost::ensure(m_state->extensions)}, action);
            return submission != ks::ui::UiCommitSubmission::Deferred;
        },
        [this](std::exception_ptr) {
            m_state->extensionText.set(m_state->extensionStatus, "文件类型统计失败；请重新选择目录或计量方式重试。");
            m_state->extensionStatus->show();
        });
}

void DiskSpacePage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() != QEvent::LanguageChange || !m_state || !m_state->directoryModel) return;
    auto& state = *m_state;
    state.mode->setTabText(0, text("普通文件遍历")); state.mode->setTabText(1, text("MFT 快速扫描"));
    state.mapMetric->setTabText(0, text("占用空间")); state.mapMetric->setTabText(1, text("逻辑大小"));
    state.scanText.render(state.scanStatus); state.spaceText.render(state.spaceStatus); state.extensionText.render(state.extensionStatus);
    state.directoryModel->retranslate(); state.extensionModel->retranslate();
    state.directories->viewport()->update(); state.extensions->viewport()->update(); state.map->refreshAppearance();
    updateButtons();
}
