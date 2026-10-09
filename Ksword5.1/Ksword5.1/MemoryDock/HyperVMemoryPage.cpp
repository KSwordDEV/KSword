#include "HyperVMemoryPage.h"
#include "../UI/StructuredFieldView.h"
#include "PhysicalPageScan.h"
#include "MemoryAttributionChart.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"
#include <QEvent>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <limits>
#include <thread>

namespace {
using namespace ksword::hyperv;
QString L(const char* text) { return ks::i18n::packedSourceText(QString::fromUtf8(text)); }
QString bytes(Bytes amount)
{
    if (!amount) { return L("Unavailable"); }
    const bool gib = *amount >= (1ULL << 30);
    return (gib ? QStringLiteral("%1 GiB") : QStringLiteral("%1 MiB"))
        .arg(static_cast<double>(*amount) / (gib ? (1ULL << 30) : (1ULL << 20)), 0, 'f', 2);
}
QString status(std::uint32_t value) { return QStringLiteral("0x%1").arg(value, 8, 16, QLatin1Char('0')); }
QString label(const Partition& row)
{
    if (!row.name.isEmpty()) { return row.name; }
    if (!row.owner.isEmpty()) { return row.owner + QStringLiteral(" / ") + row.id; }
    return row.counterInstance.isEmpty() ? row.id : row.counterInstance;
}
QString metricLabel(Metric value)
{
    switch (value) {
    case Metric::VidPhysical: return L("VID physical allocation");
    case Metric::VidRemote: return L("VID remote NUMA pages");
    case Metric::DynamicPhysical: return L("Dynamic Memory physical allocation");
    case Metric::GuestVisible: return L("Guest-visible capacity");
    case Metric::HypervisorTotal: return L("Hypervisor total pages");
    case Metric::ChildDeposited: return L("Child partition deposited pages");
    case Metric::RootDeposited: return L("Root partition deposited pages");
    case Metric::ChildGpa: return L("Child partition GPA pages");
    case Metric::RootGpa: return L("Root partition GPA pages");
    case Metric::ChildTlb: return L("Child partition virtual TLB pages");
    case Metric::RootTlb: return L("Root partition virtual TLB pages");
    case Metric::BalancerAvailable: return L("Balancer available memory");
    case Metric::BalancerAvailableForBalancing: return L("Memory available for balancing");
    }
    return {};
}
QString role(Metric value)
{
    switch (value) {
    case Metric::VidPhysical: return L("Partition physical allocation; the chart uses only non-total VID instances.");
    case Metric::VidRemote: return L("Subset of VID allocation on remote NUMA nodes; do not add again.");
    case Metric::DynamicPhysical: return L("Alternative view of VM allocation; may be absent for utility VMs.");
    case Metric::GuestVisible: return L("Capacity visible to the guest, not additional host usage.");
    case Metric::HypervisorTotal: return L("Hypervisor boot and deposited pages; includes deposited-page components below.");
    case Metric::ChildDeposited: case Metric::RootDeposited: return L("Pages deposited with the hypervisor; overlap its total-page counter.");
    case Metric::ChildGpa: case Metric::RootGpa: return L("Guest physical address-space coverage; not a separate resident allocation.");
    case Metric::ChildTlb: case Metric::RootTlb: return L("Translation bookkeeping; its overlap with other host counters is not resolved.");
    case Metric::BalancerAvailable: case Metric::BalancerAvailableForBalancing: return L("Available capacity reported by the balancer, not memory consumption.");
    }
    return {};
}
QString state(const Partition& row)
{
    if (row.state == QStringLiteral("Running") || (row.wmi && !row.hcs && row.state == QStringLiteral("2"))) { return L("Running"); }
    if (row.wmi && !row.hcs && row.state == QStringLiteral("3")) { return L("Off"); }
    return row.state.isEmpty() ? L("Unavailable") : row.state;
}
QString identity(const Partition& row)
{
    if (row.conflictingVid) { return L("Conflicting VID aliases"); }
    if (row.ambiguous) { return L("Ambiguous instance name"); }
    if (!row.inventoryMatched) { return L("Counter only; owner unresolved"); }
    QStringList sources;
    if (row.hcs) { sources << QStringLiteral("HCS"); }
    if (row.wmi) { sources << QStringLiteral("WMI"); }
    return sources.join(QStringLiteral(" + "));
}
QTableWidget* table(QWidget* parent)
{
    auto* view = new ks::ui::VisibleTableWidget(parent);
    view->setEditTriggers(QAbstractItemView::NoEditTriggers);
    view->setSelectionBehavior(QAbstractItemView::SelectRows);
    view->setSelectionMode(QAbstractItemView::SingleSelection);
    view->verticalHeader()->hide();
    view->horizontalHeader()->setStretchLastSection(true);
    view->setAlternatingRowColors(true);
    return view;
}
void headers(QTableWidget* view, const QStringList& labels)
{
    view->setColumnCount(static_cast<int>(labels.size()));
    view->setHorizontalHeaderLabels(labels);
}
void text(QTableWidget* view, int row, int column, const QString& value)
{
    auto* item = new QTableWidgetItem(value);
    item->setToolTip(value);
    view->setItem(row, column, item);
}
void amount(QTableWidget* view, int row, int column, Bytes value)
{
    if (!value) { text(view, row, column, L("Unavailable")); return; }
    auto* item = new ks::ui::NumericTableItem(bytes(value), static_cast<qulonglong>(*value));
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    item->setToolTip(L("%1 bytes").arg(*value));
    view->setItem(row, column, item);
}
Bytes hypervisorBytes(const Snapshot& snapshot)
{
    for (const auto& sample : snapshot.counters) { if (sample.metric == Metric::HypervisorTotal && sample.bytes) { return sample.bytes; } }
    return {};
}
bool wmiComplete(const Snapshot& snapshot)
{
    for (const auto& source : snapshot.sources) { if (source.name == QStringLiteral("Hyper-V WMI inventory")) { return source.complete; } }
    return false;
}
QString vbsState(const Snapshot& snapshot)
{
    if (!snapshot.vbsKnown) { return L("Unavailable"); }
    switch (snapshot.vbsState) {
    case 0: return L("Not enabled");
    case 1: return L("Enabled, not running");
    case 2: return L("Running");
    default: return QString::number(snapshot.vbsState);
    }
}
QString sourceName(const QString& source)
{
    const auto prefix = QStringLiteral("HCS properties: ");
    return source.startsWith(prefix) ? L("HCS memory properties: %1").arg(source.mid(prefix.size())) : ks::i18n::packedSourceText(source);
}
}

HyperVMemoryPage::HyperVMemoryPage(QWidget* parent) : QWidget(parent)
{
    // 页面自带内部滚动壳：固定高度的归因图加五页签约四百五十像素，嵌在系统内存审计页里
    // 放不下时在本页内滚动。根布局建在壳的内容容器上。
    auto* root = new QVBoxLayout(ks::ui::EnablePageInnerScroll(this));
    root->setContentsMargins(0, 0, 0, 0);
    auto* actions = new QHBoxLayout;
    m_collect = new QPushButton(this); m_cancel = new QPushButton(this); m_export = new QPushButton(this);
    m_filter = new QLineEdit(this); m_filter->setClearButtonEnabled(true);
    actions->addWidget(m_collect); actions->addWidget(m_cancel); actions->addWidget(m_filter, 1); actions->addWidget(m_export);
    root->addLayout(actions);
    m_summary = new QLabel(this); m_summary->setWordWrap(true); m_summary->setTextFormat(Qt::PlainText);
    m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse); root->addWidget(m_summary);
    m_progress = new QProgressBar(this); m_progress->setTextVisible(false); m_progress->setMaximumHeight(5); root->addWidget(m_progress);
    m_chart = new MemoryAttributionChart(this); root->addWidget(m_chart);
    m_tabs = new QTabWidget(this);
    auto* split = new QSplitter(Qt::Vertical, m_tabs);
    m_partitions = table(split); m_detail = new ks::ui::StructuredFieldView(split);

    split->addWidget(m_partitions); split->addWidget(m_detail); split->setStretchFactor(0, 3); split->setStretchFactor(1, 1);
    m_tabs->addTab(split, {});
    m_host = table(m_tabs); m_tabs->addTab(m_host, {});
    m_processes = table(m_tabs); m_tabs->addTab(m_processes, {});
    m_sources = table(m_tabs); m_tabs->addTab(m_sources, {});
    m_evidence = new ks::ui::StructuredFieldView(m_tabs);
     m_tabs->addTab(m_evidence, {});
    root->addWidget(m_tabs, 1);
    connect(m_collect, &QPushButton::clicked, this, [this] { startCollection(); });
    connect(m_cancel, &QPushButton::clicked, this, [this] { if (m_job) { m_job->cancel.store(true); } });
    connect(m_export, &QPushButton::clicked, this, [this] { exportEvidence(); });
    connect(m_filter, &QLineEdit::textChanged, this, [this] { rebuildPartitions(); });
    connect(m_partitions, &QTableWidget::itemSelectionChanged, this, [this] {
        const auto* item = m_partitions->item(m_partitions->currentRow(), 0);
        if (item) { showPartition(item->data(Qt::UserRole).toInt()); }
    });
    m_chart->selected = [this](int key) {
        m_filter->clear(); m_tabs->setCurrentIndex(0);
        for (int row = 0; row < m_partitions->rowCount(); ++row) {
            const auto* item = m_partitions->item(row, 0);
            if (item && item->data(Qt::UserRole).toInt() == key) { m_partitions->setCurrentCell(row, 0); m_partitions->scrollToItem(item); break; }
        }
    };
    auto* timer = new QTimer(this); timer->setInterval(150);
    connect(timer, &QTimer::timeout, this, [this] { poll(); }); timer->start();
    retranslate(); rebuild();
}
HyperVMemoryPage::~HyperVMemoryPage() { if (m_job) { m_job->cancel.store(true); } }
void HyperVMemoryPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_collect) { retranslate(); rebuild(); }
}
void HyperVMemoryPage::setSnapshotContext(const QString& time, std::uint64_t remainder)
{
    m_latestContext.snapshotTime = time; m_latestContext.snapshotRemainder = remainder;
}
void HyperVMemoryPage::setPfnContext(const std::shared_ptr<ksword::pfn::Scan>& scan)
{
    if (!scan) { return; }
    const auto& accounting = scan->accounting;
    m_latestContext.pfnTime = scan->finished;
    m_latestContext.pfnDriverLocked.reset(); m_latestContext.pfnUnknown.reset(); m_latestContext.pfnUnscanned.reset();
    if (accounting.valid) {
        m_latestContext.pfnDriverLocked = accounting.inUse(ksword::pfn::Use::DriverLocked) * ksword::pfn::pageBytes;
        m_latestContext.pfnUnknown = accounting.inUse(ksword::pfn::Use::Unknown) * ksword::pfn::pageBytes;
    }
    if (accounting.expected) { m_latestContext.pfnUnscanned = (accounting.notScanned() + accounting.unreadable) * ksword::pfn::pageBytes; }
}
void HyperVMemoryPage::startCollection()
{
    if (m_job) { return; }
    m_jobContext = m_latestContext;
    try {
        m_job = std::make_shared<Job>();
        std::thread([job = m_job] { collect(job); }).detach();
    } catch (...) { m_job.reset(); m_summary->setText(L("Unable to start the Hyper-V evidence worker.")); return; }
    m_collect->setEnabled(false); m_cancel->setEnabled(true); m_export->setEnabled(false);
    m_progress->setRange(0, 0); poll();
}
void HyperVMemoryPage::poll()
{
    if (!m_job) { return; }
    if (m_job->done.load()) {
        std::shared_ptr<Snapshot> result;
        { std::lock_guard<std::mutex> lock(m_job->mutex); result = m_job->result; }
        m_job.reset(); m_collect->setEnabled(true); m_cancel->setEnabled(false); m_progress->setRange(0, 1); m_progress->setValue(1);
        if (!result) { m_summary->setText(L("Hyper-V collection did not return a snapshot.")); m_export->setEnabled(bool(m_snapshot)); return; }
        m_previous = m_snapshot; m_snapshot = std::move(result); m_resultContext = m_jobContext;
        rebuild(); return;
    }
    constexpr const char* phases[]{"Starting Hyper-V evidence collection", "Reading host and partition counters", "Reading Hyper-V inventory and VBS state", "Reading HCS utility VM memory", "Reading host process memory"};
    const auto phase = std::min<unsigned>(m_job->phase.load(), 4);
    m_summary->setText(m_job->cancel.load() ? L("Cancelling; waiting for the current provider call to return.")
        : L("%1. Existing results below are from the previous sample.").arg(L(phases[phase])));
}
void HyperVMemoryPage::retranslate()
{
    m_collect->setText(L("Collect Hyper-V evidence")); m_cancel->setText(L("Cancel collection")); m_export->setText(L("Export evidence"));
    m_filter->setPlaceholderText(L("Filter partition, owner, GUID, or runtime ID"));
    m_collect->setToolTip(L("Read VID, Hyper-V WMI, HCS, VBS and host process evidence. Repeat to compare allocations over time."));
    m_tabs->setTabText(0, L("Partitions and utility VMs")); m_tabs->setTabText(1, L("Host memory evidence"));
    m_tabs->setTabText(2, L("Visible host processes")); m_tabs->setTabText(3, L("Provider coverage")); m_tabs->setTabText(4, L("Interpretation and snapshot context"));
    headers(m_partitions, {L("Partition / VM"), L("Owner"), L("State"), L("VID physical"), L("HCS node memory"), L("VID delta"), L("Dynamic physical"), L("Guest-visible capacity"), L("Deposited pages"), L("Identity evidence")});
    headers(m_host, {L("Metric"), L("Instance"), L("Bytes"), L("Status"), L("Accounting role")});
    headers(m_processes, {L("Process"), L("PID"), L("Working set"), L("Private commit"), L("Partition evidence")});
    headers(m_sources, {L("Source"), L("Coverage"), L("Rows"), L("Status")});
}
void HyperVMemoryPage::rebuildPartitions()
{
    m_partitions->setSortingEnabled(false); m_partitions->setRowCount(0); m_detail->setDocument({});
    if (!m_snapshot) { return; }
    const auto filter = m_filter->text().trimmed();
    for (std::size_t index = 0; index < m_snapshot->partitions.size(); ++index) {
        const auto& entry = m_snapshot->partitions[index];
        const auto search = label(entry) + QLatin1Char(' ') + entry.owner + QLatin1Char(' ') + entry.id + QLatin1Char(' ') + entry.runtimeId;
        if (!filter.isEmpty() && !search.contains(filter, Qt::CaseInsensitive)) { continue; }
        const int row = m_partitions->rowCount(); m_partitions->insertRow(row);
        text(m_partitions, row, 0, label(entry)); m_partitions->item(row, 0)->setData(Qt::UserRole, static_cast<int>(index));
        text(m_partitions, row, 1, entry.owner.isEmpty() ? L("Unavailable") : entry.owner); text(m_partitions, row, 2, state(entry));
        amount(m_partitions, row, 3, entry.conflictingVid ? Bytes{} : entry.vidBytes); amount(m_partitions, row, 4, entry.hcsNodeBytes);
        text(m_partitions, row, 5, L("Unavailable"));
        if (m_previous && entry.vidBytes && !entry.conflictingVid && !m_snapshot->vidConflict && !m_previous->vidConflict) {
            for (const auto& before : m_previous->partitions) {
                if (before.key != entry.key || before.runtimeId.compare(entry.runtimeId, Qt::CaseInsensitive) != 0 || !before.vidBytes || before.conflictingVid) { continue; }
                if (*entry.vidBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max()) || *before.vidBytes > static_cast<std::uint64_t>(std::numeric_limits<qint64>::max())) { break; }
                const auto delta = static_cast<qint64>(*entry.vidBytes) - static_cast<qint64>(*before.vidBytes);
                auto* item = new ks::ui::NumericTableItem((delta < 0 ? QStringLiteral("-") : QStringLiteral("+")) + bytes(static_cast<std::uint64_t>(delta < 0 ? -delta : delta)), delta);
                item->setToolTip(L("VID allocation change since %1; matching partition identity.").arg(m_previous->finished)); m_partitions->setItem(row, 5, item); break;
            }
        }
        amount(m_partitions, row, 6, entry.dynamicBytes); amount(m_partitions, row, 7, entry.guestVisibleBytes); amount(m_partitions, row, 8, entry.depositedBytes);
        text(m_partitions, row, 9, identity(entry));
    }
    m_partitions->resizeColumnsToContents();
    m_partitions->setColumnWidth(0, std::min(360, m_partitions->columnWidth(0)));
    if (m_partitions->rowCount()) { m_partitions->setCurrentCell(0, 0); showPartition(m_partitions->item(0, 0)->data(Qt::UserRole).toInt()); }
}
void HyperVMemoryPage::showPartition(int index)
{
    if (!m_snapshot || index < 0 || static_cast<std::size_t>(index) >= m_snapshot->partitions.size()) { return; }
    const auto& row = m_snapshot->partitions[index];
    ks::ui::FieldDocument lines;
    lines.field(QStringLiteral("Partition"), QStringLiteral("%1").arg(label(row)));
    lines.field(QStringLiteral("ID"), QStringLiteral("%1").arg(row.id));
    lines.field(QStringLiteral("Runtime ID"), QStringLiteral("%1").arg(row.runtimeId));
    lines.field(QStringLiteral("Owner"), QStringLiteral("%1").arg(row.owner));
    lines.field(QStringLiteral("Identity evidence"), QStringLiteral("%1").arg(identity(row)));
    if (row.hcs && !row.wmi && wmiComplete(*m_snapshot)) { lines.note(QStringLiteral("This HCS compute system is absent from the ordinary Hyper-V WMI VM inventory.")); }
    if (row.vidBytes && row.hcsNodeBytes && !row.conflictingVid) {
        lines.note((*row.vidBytes == *row.hcsNodeBytes ? L("VID and HCS node memory agree: %1. Two observations of the same allocation; counted once.").arg(bytes(row.vidBytes))
            : L("VID reports %1; HCS reports %2. Sampling time or provider scope differs; do not add them.").arg(bytes(row.vidBytes), bytes(row.hcsNodeBytes))));
    }
    if (!row.hostingSystemId.isEmpty()) { lines.field(QStringLiteral("Hosting compute system"), QStringLiteral("%1. Container memory may overlap its host VM.").arg(QStringLiteral("%1").arg(row.hostingSystemId))); }
    lines.field(QStringLiteral("WMI capacity"), QStringLiteral("%1").arg(bytes(row.wmiCapacity)));
    lines.field(QStringLiteral("HCS private working set"), QStringLiteral("%1").arg(bytes(row.hcsPrivateWs)));
    lines.field(QStringLiteral("HCS commit"), QStringLiteral("%1.").arg(QStringLiteral("%1").arg(bytes(row.hcsCommit))));
    for (const auto counterIndex : row.counterIndices) {
        const auto& sample = m_snapshot->counters[counterIndex];
        lines.section(QStringLiteral("Counter"));
        lines.field(QStringLiteral("Metric"), metricLabel(sample.metric));
        lines.field(QStringLiteral("Bytes"), bytes(sample.bytes));
        lines.field(QStringLiteral("SampledAt"), sample.sampledAt);
        lines.field(QStringLiteral("Path"), sample.path);
    }
    if (!row.memoryEvidence.isEmpty()) { lines.section(QStringLiteral("Memory evidence"));
        const auto buildNode = [](const auto& self, const QString& name, const QJsonValue& value) -> ks::ui::FieldNode {
            ks::ui::FieldNode node;
            node.name = name;
            if (value.isObject()) {
                node.kind = ks::ui::FieldNode::Kind::Section;
                const auto object = value.toObject();
                for (auto it = object.constBegin(); it != object.constEnd(); ++it) node.children.append(self(self, it.key(), it.value()));
            } else if (value.isArray()) {
                node.kind = ks::ui::FieldNode::Kind::Section;
                const auto array = value.toArray();
                for (qsizetype i = 0; i < array.size(); ++i) node.children.append(self(self, QString::number(i), array[i]));
            } else if (value.isBool()) node.value = value.toBool() ? QStringLiteral("true") : QStringLiteral("false");
            else if (value.isDouble()) node.value = QString::number(value.toDouble(), 'g', 17);
            else if (value.isString()) node.value = value.toString();
            else node.value = QStringLiteral("null");
            return node;
        };
        auto& section = lines.nodes.last();
        for (auto it = row.memoryEvidence.constBegin(); it != row.memoryEvidence.constEnd(); ++it) section.children.append(buildNode(buildNode, it.key(), it.value())); }
    m_detail->setDocument(lines);
}
void HyperVMemoryPage::rebuild()
{
    m_cancel->setEnabled(bool(m_job)); m_collect->setEnabled(!m_job); m_export->setEnabled(bool(m_snapshot) && !m_job);
    if (!m_job) { m_progress->setRange(0, 1); m_progress->setValue(m_snapshot ? 1 : 0); }
    if (!m_snapshot) {
        m_summary->setText(L("Find VM and utility-VM allocations that a process list cannot fully explain. Collect a sample to link partition counters to WSL, containers and registered VMs."));
        m_chart->setSegments({}, L("Hyper-V partition allocations")); return;
    }
    const auto& snapshot = *m_snapshot;
    std::vector<MemoryAttributionChart::Segment> segments;
    for (std::size_t i = 0; i < snapshot.partitions.size(); ++i) {
        const auto& entry = snapshot.partitions[i];
        if (entry.vidBytes && !entry.conflictingVid && !snapshot.vidConflict) { segments.push_back({label(entry), *entry.vidBytes, static_cast<int>(i)}); }
    }
    m_chart->setSegments(std::move(segments), L("VID partition allocations only; click a segment for ownership evidence."));
    const auto valid = std::count_if(snapshot.counters.begin(), snapshot.counters.end(), [](const Counter& sample) { return sample.bytes.has_value(); });
    QStringList summary{L("Observed VM allocation: %1 | Owner unresolved: %2 | Hypervisor overhead counter: %3")
        .arg(bytes(snapshot.observedVidBytes), bytes(snapshot.unresolvedVidBytes), bytes(hypervisorBytes(snapshot))),
        L("Sample: %1 | Counters available: %2 / %3. These views overlap and cannot be added to the PFN ledger.").arg(snapshot.finished).arg(valid).arg(snapshot.counters.size())};
    if (snapshot.cancelled || snapshot.timedOut || snapshot.resourceFailure) { summary << L("Partial collection: cancelled, timed out, or resource-limited. Missing values are not zero."); }
    if (snapshot.vidConflict) { summary << L("VID identity conflict: aggregate and chart withheld to prevent double counting."); }
    m_summary->setText(summary.join(QLatin1Char('\n')));
    rebuildPartitions();
    m_host->setSortingEnabled(false); m_host->setRowCount(static_cast<int>(snapshot.counters.size()));
    for (int row = 0; row < m_host->rowCount(); ++row) {
        const auto& sample = snapshot.counters[row];
        text(m_host, row, 0, metricLabel(sample.metric)); text(m_host, row, 1, sample.instance); amount(m_host, row, 2, sample.bytes);
        text(m_host, row, 3, status(sample.status)); text(m_host, row, 4, role(sample.metric));
        m_host->item(row, 0)->setToolTip(sample.path + QLatin1Char('\n') + sample.explanation + QLatin1Char('\n') + sample.sampledAt);
    }
    m_host->resizeColumnsToContents(); m_host->setColumnWidth(4, 450);
    m_processes->setSortingEnabled(false); m_processes->setRowCount(static_cast<int>(snapshot.processes.size()));
    for (int row = 0; row < m_processes->rowCount(); ++row) {
        const auto& process = snapshot.processes[row];
        text(m_processes, row, 0, process.name); text(m_processes, row, 1, QString::number(process.pid));
        amount(m_processes, row, 2, process.workingSet); amount(m_processes, row, 3, process.privateCommit);
        QStringList matches;
        for (const auto& partition : snapshot.partitions) { if (partition.wmi && partition.workerPid == process.pid && process.pid) { matches << label(partition); } }
        text(m_processes, row, 4, matches.size() == 1 ? L("WMI worker PID: %1 (sampled separately)").arg(matches.front()) : L("Separate process view; no proven per-PID physical ownership"));
    }
    m_processes->resizeColumnsToContents();
    m_sources->setSortingEnabled(false); m_sources->setRowCount(static_cast<int>(snapshot.sources.size()));
    for (int row = 0; row < m_sources->rowCount(); ++row) {
        const auto& source = snapshot.sources[row];
        text(m_sources, row, 0, sourceName(source.name)); text(m_sources, row, 1, source.complete ? L("Complete") : L("Partial / unavailable"));
        text(m_sources, row, 2, QString::number(source.rows)); text(m_sources, row, 3, status(source.status));
    }
    m_sources->resizeColumnsToContents();
    ks::ui::FieldDocument evidence;
    evidence.note(QStringLiteral("VID allocation, HCS node memory, Dynamic Memory, process working sets and PFN Driver Locked can describe overlapping physical pages. Only VID instances are aggregated in this view; no amount is deducted from the PFN Unknown category."));
    evidence.note(QStringLiteral("No counter instance or access denied means unavailable, not zero. Registered VM inventory alone can omit WSL and container utility VMs. A large VM allocation does not prove a leak or identify the guest process using it."));
    evidence.field(QStringLiteral("Collection interval"), QStringLiteral("%1 to %2 (%3 ms). Providers are sampled sequentially, not atomically.").arg(QStringLiteral("%1").arg(snapshot.started)).arg(QStringLiteral("%1").arg(snapshot.finished)).arg(QStringLiteral("%1").arg(snapshot.elapsedMs)));
    evidence.field(QStringLiteral("VID instance sum"), QStringLiteral("%1").arg(bytes(snapshot.observedVidBytes)));
    evidence.field(QStringLiteral("provider _Total"), QStringLiteral("%1. _Total is a cross-check and is never added again.").arg(QStringLiteral("%1").arg(bytes(snapshot.vidTotalBytes))));
    evidence.field(QStringLiteral("Hypervisor"), QStringLiteral("%1").arg(snapshot.hypervisorPresent ? snapshot.hypervisorVendor : L("Not detected")));
    evidence.field(QStringLiteral("VBS status"), QStringLiteral("%1. VBS status does not supply a VTL1/Secure Kernel byte count.").arg(QStringLiteral("%1").arg(vbsState(snapshot))));
    evidence.field(QStringLiteral("Host physical memory"), QStringLiteral("%1").arg(bytes(snapshot.total ? Bytes(snapshot.total) : Bytes{})));
    evidence.field(QStringLiteral("available before / after"), QStringLiteral("%1 / %2").arg(QStringLiteral("%1").arg(bytes(snapshot.total ? Bytes(snapshot.available) : Bytes{}))).arg(QStringLiteral("%1").arg(bytes(snapshot.totalAfter ? Bytes(snapshot.availableAfter) : Bytes{}))));
    evidence.field(QStringLiteral("installed RAM"), QStringLiteral("%1.").arg(QStringLiteral("%1").arg(bytes(snapshot.installed ? Bytes(snapshot.installed) : Bytes{}))));
    evidence.field(QStringLiteral("Fast snapshot at"), QStringLiteral("Fast snapshot at %1: remainder %2. PFN snapshot at %3: Driver Locked %4").arg(QStringLiteral("%1").arg(m_resultContext.snapshotTime)).arg(QStringLiteral("%1").arg(bytes(m_resultContext.snapshotRemainder))).arg(QStringLiteral("%1").arg(m_resultContext.pfnTime)).arg(QStringLiteral("%1").arg(bytes(m_resultContext.pfnDriverLocked))));
    evidence.field(QStringLiteral("Unknown"), QStringLiteral("Unknown %1").arg(QStringLiteral("%1").arg(bytes(m_resultContext.pfnUnknown))));
    evidence.field(QStringLiteral("unreadable / unscanned"), QStringLiteral("unreadable / unscanned %1. Context only").arg(QStringLiteral("%1").arg(bytes(m_resultContext.pfnUnscanned))));
    evidence.note(QStringLiteral("different sample times and scopes."));
    evidence.note(QStringLiteral("Repeat collection after a workload changes to compare VID allocation for the same partition identity. KSword does not stop VMs, trim memory, or change virtualization settings."));
    std::uint64_t wsl = 0, processWs = 0; bool haveWsl = false, haveProcess = false;
    for (const auto& entry : snapshot.partitions) { if (entry.owner.compare(QStringLiteral("WSL"), Qt::CaseInsensitive) == 0 && entry.vidBytes && !entry.conflictingVid) { wsl += *entry.vidBytes; haveWsl = true; } }
    for (const auto& entry : snapshot.processes) { if (entry.name.compare(QStringLiteral("vmmemWSL"), Qt::CaseInsensitive) == 0 && entry.workingSet) { processWs += *entry.workingSet; haveProcess = true; } }
    if (haveWsl && haveProcess && !snapshot.vidConflict) {
        const auto comparison = L("WSL-owned VID allocation: %1; vmmemWSL process working set: %2. The process view does not represent the entire VM allocation. This is a scope comparison, not a per-PID ownership join.").arg(bytes(wsl), bytes(processWs));
        evidence.note(comparison); m_summary->setText(m_summary->text() + QLatin1Char('\n') + comparison);
    }
    if (snapshot.observedVidBytes && snapshot.vidTotalBytes && snapshot.observedVidBytes != snapshot.vidTotalBytes) {
        evidence.note(L("VID instances and _Total disagree. Inventory churn, missing instances or provider scope may explain the difference; the sample is not a complete partition census."));
    }
    m_evidence->setDocument(evidence);
    if (m_job) { poll(); }
}
void HyperVMemoryPage::exportEvidence()
{
    if (!m_snapshot) { return; }
    const auto path = QFileDialog::getSaveFileName(this, L("Export Hyper-V memory evidence"), QStringLiteral("hyperv-memory-evidence.json"), L("JSON files (*.json)"));
    if (path.isEmpty()) { return; }
    auto object = toJson(*m_snapshot, m_resultContext);
    object.insert(QStringLiteral("interpretation"), m_evidence->plainText());
    if (m_previous) { object.insert(QStringLiteral("previous_sample"), toJson(*m_previous)); }
    QSaveFile file(path); const auto data = QJsonDocument(object).toJson(QJsonDocument::Indented);
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) { m_summary->setText(L("Failed to export Hyper-V evidence: %1").arg(file.errorString())); }
    else { m_summary->setText(L("Hyper-V evidence saved to %1").arg(path)); }
}
