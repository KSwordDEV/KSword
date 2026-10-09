#include "PoolAllocationAnalysisWidget.h"
#include "../UI/CodeTextEdit.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include <QAbstractTableModel>
#include <QComboBox>
#include <QEvent>
#include <QFileDialog>
#include <QFileInfo>
#include <QFontDatabase>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QLocale>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QTableView>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <array>
#include <limits>
#include <map>
#include <new>
#include <thread>
#include <tuple>
#include <unordered_set>
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

namespace {
using namespace ks::evidence::pool;
QString L(const char* text) { return ks::i18n::packedSourceText(QString::fromUtf8(text)); }
QString N(std::uint64_t value) { return QLocale().toString(static_cast<qulonglong>(value)); }
QString H(std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 0, 16); }
QString tagText(std::uint32_t tag) {
    QString text;
    for (int byte = 0; byte < 4; ++byte) {
        const auto ch = static_cast<unsigned char>((tag >> (byte * 8)) & 255);
        text += ch >= 32 && ch <= 126 ? QChar(ch) : QChar('.');
    }
    return QStringLiteral("%1 (%2)").arg(text, H(tag));
}
using ImageIndex = std::unordered_map<std::uint64_t, const TraceImage*>;
const TraceImage* imageForId(const ImageIndex& images, std::uint64_t id) {
    if (id == 0) return nullptr;
    const auto it = images.find(id);
    return it == images.end() ? nullptr : it->second;
}
const TraceImage* sourceImage(const ImageIndex& images, const std::unordered_set<std::uint64_t>& kernelImages, const Group& group) {
    const TraceImage* fallback = nullptr;
    for (std::size_t frame = 0; frame < group.frameImageIds.size() && frame < group.stack.size(); ++frame) {
        const auto* image = imageForId(images, group.frameImageIds[frame]);
        if (!image || group.stack[frame] < image->base || group.stack[frame] - image->base >= image->size) continue;
        if (!fallback) fallback = image;
        // A source index, not driver blame: allocation helpers commonly occupy
        // the first frame, so prefer a mapped frame beyond known kernel images.
        if (kernelImages.find(image->id) == kernelImages.end()) return image;
    }
    return fallback;
}
QString imageLabel(const TraceImage* image) {
    return image ? QString::fromStdWString(image->path) : L("Unknown historical module");
}
QString sessionText(std::uint32_t sessionId) {
    return sessionId == 0xffffffffU ? L("ordinary pool") : L("session %1").arg(N(sessionId));
}
QString groupLabel(const ImageIndex& images, const std::unordered_set<std::uint64_t>& kernelImages, const Group& group) {
    return L("Group %1 | tag %2 | pool %3 | %4 | %5")
        .arg(N(group.groupId), tagText(group.tag), N(group.poolType), sessionText(group.sessionId), imageLabel(sourceImage(images, kernelImages, group)));
}
std::uint64_t addSaturated(std::uint64_t a, std::uint64_t b) {
    return b > (std::numeric_limits<std::uint64_t>::max)() - a
        ? (std::numeric_limits<std::uint64_t>::max)() : a + b;
}
constexpr int groupIdsRole = Qt::UserRole + 1;
constexpr int sortRole = Qt::UserRole + 2;
constexpr int filterRole = Qt::UserRole + 3;
bool isLocalFixedPath(const QString& path) {
#ifdef Q_OS_WIN
    // Reject UNC, device syntax, relative paths and mapped network drives before
    // QFileInfo can issue a remote request on the UI thread.
    if (path.size() < 3 || !path[0].isLetter() || path[1] != QChar(':')
        || (path[2] != QChar('\\') && path[2] != QChar('/'))) return false;
    const std::wstring root = path.left(2).toStdWString() + L"\\";
    return GetDriveTypeW(root.c_str()) == DRIVE_FIXED;
#else
    return QFileInfo(path).isAbsolute();
#endif
}
}

class PoolAllocationTableModel final : public QAbstractTableModel {
public:
    struct Row {
        QString source, search;
        std::vector<std::uint64_t> groupIds;
        std::array<std::uint64_t, 8> counters{};
        std::array<bool, 8> saturated{};
    };
    explicit PoolAllocationTableModel(QObject* parent) : QAbstractTableModel(parent) {}
    int rowCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : static_cast<int>(rows.size());
    }
    int columnCount(const QModelIndex& parent = {}) const override { return parent.isValid() ? 0 : 9; }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
        const auto& row = rows[static_cast<std::size_t>(index.row())];
        if (role == groupIdsRole) {
            QVariantList ids;
            for (const auto id : row.groupIds) ids.push_back(QVariant::fromValue(static_cast<qulonglong>(id)));
            return ids;
        }
        if (role == filterRole) return row.search;
        if (role == sortRole) return index.column() == 0 ? QVariant(row.source)
            : QVariant::fromValue(static_cast<qulonglong>(row.counters[static_cast<std::size_t>(index.column() - 1)]));
        if (role == Qt::DisplayRole || role == Qt::ToolTipRole) {
            if (index.column() == 0) return row.source;
            const auto column = static_cast<std::size_t>(index.column() - 1);
            if (role == Qt::ToolTipRole && row.saturated[column])
                return L("Aggregated value exceeds the 64-bit range; the displayed value is a lower bound.");
            return (row.saturated[column] ? QStringLiteral("\u2265") : QString()) + N(row.counters[column]);
        }
        if (role == Qt::TextAlignmentRole && index.column() != 0) return static_cast<int>(Qt::AlignRight | Qt::AlignVCenter);
        return {};
    }
    QVariant headerData(int section, Qt::Orientation orientation, int role) const override {
        if (orientation != Qt::Horizontal || (role != Qt::DisplayRole && role != Qt::ToolTipRole))
            return QAbstractTableModel::headerData(section, orientation, role);
        static const char* headers[] = {"Allocation source", "Observed bytes", "Observed count",
            "Paired release bytes", "Paired release count", "No observed free bytes",
            "No observed free count", "Uncertain bytes", "Uncertain count"};
        return section >= 0 && section < 9 ? L(headers[section]) : QVariant();
    }
    void replace(std::vector<Row> replacement) {
        beginResetModel(); rows = std::move(replacement); endResetModel();
    }
    void retranslate() { emit headerDataChanged(Qt::Horizontal, 0, 8); }
    std::vector<Row> rows;
};

// A tag or module can contain ten thousand stacks. Format only the visible
// combo entries instead of materializing ten thousand translated Qt items.
class PoolStackListModel final : public QAbstractListModel {
public:
    explicit PoolStackListModel(QObject* parent) : QAbstractListModel(parent) {}
    int rowCount(const QModelIndex& parent = {}) const override {
        return parent.isValid() ? 0 : static_cast<int>(groups.size());
    }
    QVariant data(const QModelIndex& index, int role) const override {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()) return {};
        const auto& group = *groups[static_cast<std::size_t>(index.row())];
        if (role == Qt::UserRole) return QVariant::fromValue(static_cast<qulonglong>(group.groupId));
        if (role == Qt::DisplayRole || role == Qt::ToolTipRole) return groupLabel(*images, *kernelImages, group);
        return {};
    }
    void replace(std::vector<const Group*> replacement, const ImageIndex* imageIndex,
        const std::unordered_set<std::uint64_t>* kernelIndex) {
        beginResetModel(); groups = std::move(replacement); images = imageIndex; kernelImages = kernelIndex; endResetModel();
    }
    std::vector<const Group*> groups;
    const ImageIndex* images = nullptr;
    const std::unordered_set<std::uint64_t>* kernelImages = nullptr;
};

struct PoolAllocationAnalysisWidget::ReadJob {
    std::atomic_bool cancel{false}, done{false};
    TraceReadResult result;
};
struct PoolAllocationAnalysisWidget::ResolveJob {
    std::atomic_bool cancel{false}, done{false};
    std::uint64_t groupId = 0;
    std::shared_ptr<const TraceReadResult> trace;
    Group group;
    std::vector<std::wstring> symbols;
};

PoolAllocationAnalysisWidget::PoolAllocationAnalysisWidget(QWidget* parent) : QWidget(parent) {
    m_reader = [](const std::wstring& path, const std::atomic_bool& cancel) {
        return ReadPoolAllocationTrace(path, cancel);
    };
    m_resolver = [](const TraceReadResult& trace, const Group& group, const std::atomic_bool& cancel) {
        return ResolvePoolTraceStack(trace, group, cancel);
    };
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    m_note = new QLabel(this); m_note->setWordWrap(true); m_note->setObjectName(QStringLiteral("pool_analysis_note"));
    layout->addWidget(m_note);
    auto* actions = new ks::ui::FlowLayout(nullptr, 0);
    m_open = new QPushButton(this); m_open->setObjectName(QStringLiteral("pool_analysis_open"));
    m_cancel = new QPushButton(this); m_cancel->setObjectName(QStringLiteral("pool_analysis_cancel"));
    actions->addWidget(m_open); actions->addWidget(m_cancel);
    layout->addLayout(actions);
    auto* filters = new QHBoxLayout;
    m_grouping = new QComboBox(this); m_grouping->setObjectName(QStringLiteral("pool_analysis_grouping"));
    m_grouping->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_grouping->setMinimumContentsLength(8); m_grouping->setMinimumWidth(0);
    m_grouping->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    m_grouping->addItems({QString(), QString(), QString()});
    m_filter = new QLineEdit(this); m_filter->setObjectName(QStringLiteral("pool_analysis_filter")); m_filter->setMinimumWidth(0);
    filters->addWidget(m_grouping, 2); filters->addWidget(m_filter, 3); layout->addLayout(filters);
    m_status = new QLabel(this); m_status->setWordWrap(true); m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status->setObjectName(QStringLiteral("pool_analysis_status")); layout->addWidget(m_status);
    m_summary = new QLabel(this); m_summary->setWordWrap(true); m_summary->setObjectName(QStringLiteral("pool_analysis_summary"));
    layout->addWidget(m_summary);
    auto* split = new QSplitter(Qt::Vertical, this);
    m_table = new QTableView(split); m_table->setObjectName(QStringLiteral("pool_analysis_table"));
    m_model = new PoolAllocationTableModel(this);
    m_proxy = new QSortFilterProxyModel(this); m_proxy->setSourceModel(m_model); m_proxy->setSortRole(sortRole);
    m_proxy->setFilterRole(filterRole); m_proxy->setFilterKeyColumn(0); m_proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_table->setModel(m_proxy); m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection); m_table->setSortingEnabled(true);
    m_table->sortByColumn(5, Qt::DescendingOrder); m_table->setAlternatingRowColors(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers); m_table->verticalHeader()->hide();
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setDefaultSectionSize(145); m_table->setColumnWidth(0, 270);
    auto* detail = new QWidget(split); auto* detailLayout = new QVBoxLayout(detail);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    m_stacks = new QComboBox(detail); m_stacks->setObjectName(QStringLiteral("pool_analysis_stacks"));
    m_stackModel = new PoolStackListModel(this); m_stacks->setModel(m_stackModel);
    m_stacks->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_stacks->setMinimumContentsLength(10); m_stacks->setMinimumWidth(0); detailLayout->addWidget(m_stacks);
    m_stacks->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    auto* detailActions = new ks::ui::FlowLayout(nullptr, 0);
    m_resolve = new QPushButton(detail); m_resolve->setObjectName(QStringLiteral("pool_analysis_resolve"));
    m_module = new QPushButton(detail); m_module->setObjectName(QStringLiteral("pool_analysis_module"));
    detailActions->addWidget(m_resolve); detailActions->addWidget(m_module); detailLayout->addLayout(detailActions);
    m_frames = new CodeTextEdit(detail);
    static_cast<CodeTextEdit*>(m_frames)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText); m_frames->setObjectName(QStringLiteral("pool_analysis_frames"));
    m_frames->setReadOnly(true); m_frames->setLineWrapMode(QPlainTextEdit::NoWrap);
    detailLayout->addWidget(m_frames, 1); split->addWidget(m_table); split->addWidget(detail);
    split->setStretchFactor(0, 2); split->setStretchFactor(1, 1); layout->addWidget(split, 1);
    connect(m_open, &QPushButton::clicked, this, [this] {
        QPointer<PoolAllocationAnalysisWidget> guard(this);
        const auto path = QFileDialog::getOpenFileName(this, L("Open pool allocation ETL"), QString(), L("ETL files (*.etl)"));
        if (guard && !path.isEmpty()) guard->analyzeFile(path);
    });
    connect(m_cancel, &QPushButton::clicked, this, [this] { cancelJobs(); updateControls(); updateSummary(); });
    connect(m_grouping, &QComboBox::currentIndexChanged, this, [this] { rebuildRows(); });
    connect(m_filter, &QLineEdit::textChanged, m_proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(m_table->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this] { selectRow(); });
    connect(m_stacks, &QComboBox::currentIndexChanged, this, [this] { selectStack(); });
    connect(m_resolve, &QPushButton::clicked, this, [this] { resolveStack(); });
    connect(m_module, &QPushButton::clicked, this, [this] {
        const auto callback = m_openModuleDetails;
        const auto path = m_modulePath;
        if (callback && isLocalFixedPath(path) && QFileInfo(path).isFile()) callback(path);
        // The navigation callback may destroy its originating Dock/widget.
    });
    m_poll = new QTimer(this); m_poll->setInterval(75);
    connect(m_poll, &QTimer::timeout, this, [this] { pollJobs(); });
    retranslate(); updateControls();
}

PoolAllocationAnalysisWidget::~PoolAllocationAnalysisWidget() { cancelJobs(); clearStackModel(); }

void PoolAllocationAnalysisWidget::setOpenModuleDetails(std::function<void(const QString&)> callback) {
    m_openModuleDetails = std::move(callback); updateControls();
}
void PoolAllocationAnalysisWidget::setProvidersForTesting(ReadProvider reader, ResolveProvider resolver) {
    if (reader) m_reader = std::move(reader);
    if (resolver) m_resolver = std::move(resolver);
}
void PoolAllocationAnalysisWidget::cancelJobs() {
    m_pendingPath.clear();
    if (m_readJob) m_readJob->cancel.store(true, std::memory_order_relaxed);
    if (m_resolveJob) m_resolveJob->cancel.store(true, std::memory_order_relaxed);
}
void PoolAllocationAnalysisWidget::analyzeFile(const QString& path) {
    if (path.isEmpty()) return;
    if (m_readJob) {
        m_readJob->cancel.store(true, std::memory_order_relaxed);
        m_pendingPath = path; updateSummary(); updateControls(); return;
    }
    startRead(path);
}
void PoolAllocationAnalysisWidget::startRead(const QString& path) {
    if (m_resolveJob) m_resolveJob->cancel.store(true, std::memory_order_relaxed);
    clearStackModel(); m_result.reset(); indexResult(); m_path = path; m_symbols.clear(); m_symbolGroupId = 0; rebuildRows();
    auto job = std::make_shared<ReadJob>(); m_readJob = job;
    const auto reader = m_reader; const auto file = path.toStdWString();
    // Worker owns only plain/shared data; it never accesses this or Qt widgets.
    try {
        std::thread([job, reader, file] {
            try { job->result = reader(file, job->cancel); }
            catch (const std::bad_alloc&) { job->result.status = 8; }
            catch (...) { job->result.status = 31; }
            job->done.store(true, std::memory_order_release);
        }).detach();
    } catch (...) { job->result.status = 31; job->done.store(true, std::memory_order_release); }
    m_poll->start(); updateSummary(); updateControls();
}
void PoolAllocationAnalysisWidget::pollJobs() {
    if (m_readJob && m_readJob->done.load(std::memory_order_acquire)) {
        auto job = std::move(m_readJob);
        if (!m_pendingPath.isEmpty()) {
            const auto path = m_pendingPath; m_pendingPath.clear(); startRead(path);
        } else {
            if (job->cancel.load(std::memory_order_relaxed)) {
                job->result.cancelled = true; job->result.analysis.cancelled = true;
            }
            clearStackModel(); m_result = std::make_shared<const TraceReadResult>(std::move(job->result)); indexResult(); rebuildRows();
        }
    }
    if (m_resolveJob && m_resolveJob->done.load(std::memory_order_acquire)) {
        auto job = std::move(m_resolveJob);
        const auto* group = selectedGroup();
        if (!job->cancel.load(std::memory_order_relaxed) && m_result == job->trace && group && group->groupId == job->groupId) {
            m_symbols = std::move(job->symbols); m_symbolGroupId = job->groupId; showStack();
        }
    }
    if (!m_readJob && !m_resolveJob) m_poll->stop();
    updateControls(); updateSummary();
}
void PoolAllocationAnalysisWidget::setResultForTesting(TraceReadResult result) {
    cancelJobs(); m_readJob.reset(); m_resolveJob.reset(); m_symbols.clear(); m_symbolGroupId = 0;
    clearStackModel(); m_result = std::make_shared<const TraceReadResult>(std::move(result)); indexResult(); rebuildRows(); updateSummary(); updateControls();
}
void PoolAllocationAnalysisWidget::clearStackModel() {
    const QSignalBlocker blocked(m_stacks);
    m_stackModel->replace({}, &m_images, &m_kernelImages);
}
void PoolAllocationAnalysisWidget::indexResult() {
    m_images.clear(); m_kernelImages.clear(); m_groups.clear();
    if (!m_result) return;
    for (const auto& image : m_result->images) {
        m_images.emplace(image.id, &image);
        auto path = QString::fromStdWString(image.path); path.replace(QChar('\\'), QChar('/'));
        const auto name = path.section(QChar('/'), -1).toLower();
        if (name == QStringLiteral("ntoskrnl.exe") || name == QStringLiteral("ntkrnlmp.exe")
            || name == QStringLiteral("ntkrnlpa.exe") || name == QStringLiteral("ntkrpamp.exe")
            || name == QStringLiteral("ntkrla57.exe") || name == QStringLiteral("hal.dll")) m_kernelImages.insert(image.id);
    }
    for (const auto& group : m_result->analysis.groups) m_groups.emplace(group.groupId, &group);
}
void PoolAllocationAnalysisWidget::rebuildRows() {
    std::vector<PoolAllocationTableModel::Row> rows;
    std::map<std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>, std::size_t> rowByKey;
    std::vector<std::unordered_set<std::uint64_t>> rowImages;
    if (m_result) {
        const auto mode = m_grouping->currentIndex();
        for (const auto& group : m_result->analysis.groups) {
            const auto* image = sourceImage(m_images, m_kernelImages, group);
            const auto key = mode == 0 ? std::make_tuple(static_cast<std::uint64_t>(group.tag), static_cast<std::uint64_t>(group.poolType), static_cast<std::uint64_t>(group.sessionId))
                : mode == 1 ? std::make_tuple(group.groupId, std::uint64_t{0}, std::uint64_t{0})
                : std::make_tuple(image ? image->id : std::uint64_t{0}, std::uint64_t{0}, std::uint64_t{0});
            auto found = rowByKey.find(key);
            if (found == rowByKey.end()) {
                PoolAllocationTableModel::Row row;
                row.source = mode == 0 ? L("Tag %1 | pool %2 | %3").arg(tagText(group.tag), N(group.poolType), sessionText(group.sessionId))
                    : mode == 1 ? groupLabel(m_images, m_kernelImages, group)
                    : L("Historical stack source: %1 | image %2").arg(imageLabel(image), N(image ? image->id : 0));
                row.search = row.source + QChar(' ');
                found = rowByKey.emplace(key, rows.size()).first; rows.push_back(std::move(row)); rowImages.emplace_back();
            }
            auto& row = rows[found->second]; row.groupIds.push_back(group.groupId);
            const std::array<std::uint64_t, 8> counters{group.allocatedBytes, group.allocatedCount,
                group.pairedFreedBytes, group.pairedFreedCount, group.outstandingBytes,
                group.outstandingCount, group.uncertainBytes, group.uncertainCount};
            for (std::size_t column = 0; column < counters.size(); ++column) {
                row.saturated[column] = row.saturated[column]
                    || counters[column] > (std::numeric_limits<std::uint64_t>::max)() - row.counters[column];
                row.counters[column] = addSaturated(row.counters[column], counters[column]);
            }
            row.search += tagText(group.tag) + QChar(' ') + sessionText(group.sessionId) + QChar(' ');
            // Keep the table projection bounded to groups and unique historical
            // module names. The full million-frame budget is formatted only for
            // a selected stack, avoiding a giant synchronous item/string fill.
            for (const auto id : group.frameImageIds)
                if (rowImages[found->second].insert(id).second)
                    if (const auto* frameImage = imageForId(m_images, id))
                        row.search += QString::fromStdWString(frameImage->path) + QChar(' ');
        }
    }
    m_model->replace(std::move(rows));
    if (m_proxy->rowCount() != 0) m_table->selectRow(0); else selectRow();
    updateControls();
}
void PoolAllocationAnalysisWidget::selectRow() {
    const QSignalBlocker blocked(m_stacks);
    std::vector<const Group*> groups;
    const auto selected = m_table->selectionModel()->selectedRows();
    if (m_result && !selected.isEmpty()) {
        const auto ids = selected.front().data(groupIdsRole).toList();
        for (const auto& id : ids) {
            const auto groupId = id.toULongLong();
            const auto it = m_groups.find(groupId);
            if (it != m_groups.end()) groups.push_back(it->second);
        }
    }
    m_stackModel->replace(std::move(groups), &m_images, &m_kernelImages);
    selectStack();
}
const Group* PoolAllocationAnalysisWidget::selectedGroup() const {
    if (!m_result || m_stacks->currentIndex() < 0) return nullptr;
    const auto id = m_stacks->currentData().toULongLong();
    const auto it = m_groups.find(id);
    return it == m_groups.end() ? nullptr : it->second;
}
void PoolAllocationAnalysisWidget::selectStack() {
    if (m_resolveJob) m_resolveJob->cancel.store(true, std::memory_order_relaxed);
    m_symbols.clear(); m_symbolGroupId = 0; showStack(); updateControls();
}
void PoolAllocationAnalysisWidget::showStack() {
    m_modulePath.clear();
    const auto* group = selectedGroup();
    if (!group) { m_frames->clear(); return; }
    QStringList lines;
    lines << groupLabel(m_images, m_kernelImages, *group);
    lines << L("Observed %1 bytes / %2 allocations; paired release %3 bytes / %4; no observed free %5 bytes / %6; uncertain %7 bytes / %8.")
        .arg(N(group->allocatedBytes), N(group->allocatedCount), N(group->pairedFreedBytes), N(group->pairedFreedCount),
            N(group->outstandingBytes), N(group->outstandingCount), N(group->uncertainBytes), N(group->uncertainCount));
    lines << L("Historical timestamp %1; event PID %2; event TID %3.")
        .arg(N(group->representativeTimestamp), N(group->representativePid), N(group->representativeTid));
    if (group->stack.empty()) lines << L("No allocation stack was recorded for this group.");
    if (const auto* source = sourceImage(m_images, m_kernelImages, *group)) {
        const auto path = QString::fromStdWString(source->path);
        if (isLocalFixedPath(path)) {
            const QFileInfo file(path);
            if (file.isFile()) m_modulePath = file.absoluteFilePath();
        }
    }
    for (std::size_t frame = 0; frame < group->stack.size(); ++frame) {
        const auto address = group->stack[frame];
        const auto* image = frame < group->frameImageIds.size() ? imageForId(m_images, group->frameImageIds[frame]) : nullptr;
        QString origin = L("Unknown historical module");
        if (image && address >= image->base && address - image->base < image->size) {
            origin = L("%1 + %2 [image %3]").arg(QString::fromStdWString(image->path), H(address - image->base), N(image->id));
        }
        QString line = QStringLiteral("%1  %2  %3").arg(N(frame), H(address), origin);
        if (m_symbolGroupId == group->groupId && frame < m_symbols.size() && !m_symbols[frame].empty())
            line += QStringLiteral("  ") + QString::fromStdWString(m_symbols[frame]);
        lines << line;
    }
    m_frames->setPlainText(lines.join(QChar('\n')));
}
void PoolAllocationAnalysisWidget::resolveStack() {
    const auto* group = selectedGroup();
    if (!group || group->stack.empty() || m_resolveJob || m_readJob) return;
    auto job = std::make_shared<ResolveJob>(); job->trace = m_result; job->group = *group; job->groupId = group->groupId;
    const auto resolver = m_resolver; m_resolveJob = job;
    try {
        std::thread([job, resolver] {
            try { job->symbols = resolver(*job->trace, job->group, job->cancel); } catch (...) {}
            job->done.store(true, std::memory_order_release);
        }).detach();
    } catch (...) { job->done.store(true, std::memory_order_release); }
    m_poll->start(); updateSummary(); updateControls();
}
void PoolAllocationAnalysisWidget::updateControls() {
    const bool busy = m_readJob || m_resolveJob;
    m_open->setEnabled(!m_readJob);
    m_cancel->setEnabled(busy);
    m_resolve->setEnabled(!busy && selectedGroup() && !selectedGroup()->stack.empty());
    m_module->setEnabled(!m_readJob && m_openModuleDetails && !m_modulePath.isEmpty());
    m_module->setToolTip(m_modulePath.isEmpty() ? L("No reliable local module path is available.") : m_modulePath);
    m_stacks->setEnabled(m_stacks->count() > 0);
}
void PoolAllocationAnalysisWidget::updateSummary() {
    if (m_readJob) m_status->setText(m_readJob->cancel.load() ? L("Cancelling pool trace analysis...") : L("Analyzing pool trace: %1").arg(m_path));
    else if (m_resolveJob) m_status->setText(m_resolveJob->cancel.load() ? L("Cancelling local symbol lookup...") : L("Resolving the selected stack with local symbols only..."));
    else if (!m_result) m_status->setText(L("Open an ETL or finish a pool allocation capture to analyze it."));
    else if (!m_result->completed || m_result->status != 0 || m_result->cancelled || m_result->timedOut)
        m_status->setText(L("Pool trace analysis is incomplete. Win32 status: %1.").arg(N(m_result->status)));
    else if (!m_result->analysis.coverageComplete || !m_result->analysis.stackCoverageComplete
        || !m_result->analysis.lifetimePairingAvailable || !m_result->lossCountsKnown
        || m_result->imageHistoryTruncated || m_result->fileChanged)
        m_status->setText(L("Pool trace replay finished with incomplete evidence. Observed outstanding allocations do not prove a leak."));
    else m_status->setText(L("Pool trace analysis finished. Observed outstanding allocations do not prove a leak."));
    if (m_result && !m_readJob && !m_resolveJob && !m_result->analysis.lifetimePairingAvailable)
        m_status->setText(m_status->text() + QChar(' ') + L("Lifetime pairing is unavailable because event loss positions are unknown."));
    if (!m_result) { m_summary->clear(); return; }
    const auto& result = *m_result; const auto& stats = result.analysis.stats;
    auto loss = result.lossCountsKnown
        ? L("events %1 / buffers %2").arg(N(result.eventsLost), N(result.buffersLost)) : L("Unknown loss counts");
    loss += QStringLiteral(" / ") + L("loss markers %1").arg(N(result.lossMarkers));
    m_summary->setText(L("Coverage gaps: loss %1; unmatched frees %2; address reuse %3; missing stacks %4; ambiguous stacks %5; decode failures %6; limits %7; cancelled %8; timeout %9; image history truncated %10; file changed %11; gap flags %12.")
        .arg(loss, N(stats.unmatchedFrees), N(stats.addressReuses), N((std::max)(stats.missingStacks, result.missingStackEvents)),
            N(result.ambiguousStackEvents), N((std::max)(stats.decodeFailures, result.unsupportedPoolEvents)), N(stats.capacityRejected),
            N(result.cancelled || result.analysis.cancelled ? 1 : 0), N(result.timedOut ? 1 : 0),
            N(result.imageHistoryTruncated ? 1 : 0), N(result.fileChanged ? 1 : 0), H(result.analysis.gapReasons)));
}
void PoolAllocationAnalysisWidget::retranslate() {
    m_note->setText(L("Analyze only events retained in this ETL. Allocations before capture or overwritten by circular buffers are unknown. Unpaired allocations do not prove a leak. Historical modules show stack origins, not responsibility."));
    m_open->setText(L("Open ETL")); m_cancel->setText(L("Cancel analysis"));
    { const QSignalBlocker blocked(m_grouping);
      m_grouping->setItemText(0, L("By pool tag")); m_grouping->setItemText(1, L("By complete stack")); m_grouping->setItemText(2, L("By historical stack module")); }
    m_grouping->setToolTip(L("Module grouping uses the first mapped stack module outside ntoskrnl and HAL, falling back to the kernel image or unknown. Every underlying stack remains available below."));
    m_filter->setPlaceholderText(L("Filter tag or historical module"));
    m_resolve->setText(L("Resolve local symbols")); m_module->setText(L("Open module details"));
    m_model->retranslate(); rebuildRows(); updateSummary(); updateControls();
}
void PoolAllocationAnalysisWidget::changeEvent(QEvent* event) {
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange) retranslate();
}
