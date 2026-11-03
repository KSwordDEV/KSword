#include "../UI/MemoryPageNavigationSchema.h"
#include "HyperVMemoryPage.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/PageControlStyle.h"
#include "../UI/StructuredFieldView.h"
#include "PhysicalPageScan.h"
#include "MemoryAttributionChart.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableRowFilterSupport.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/MetricAreaWindow.h"
#include "../UI/FlowLayout.h"
#include <QEvent>
#include <QShowEvent>
#include <QThreadPool>
#include <QAbstractTableModel>
#include <QTableView>
#include <QItemSelectionModel>
#include <QSignalBlocker>
#include <map>
#include <numeric>
#include <array>
#include <QFileDialog>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QProgressBar>
#include <QPointer>
#include "../UI/AsyncCleanupRegistry.h"
#include <QPushButton>
#include <QSaveFile>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QVBoxLayout>
#include <algorithm>
#include <cmath>
#include <limits>
#include <thread>

namespace {
using namespace ksword::hyperv;

thread_local const ks::i18n::SourceTextSnapshot* hyperText = nullptr;
QString T(const QString& text) { return hyperText ? hyperText->packedSourceText(text) : ks::i18n::packedSourceText(text); }
QString L(const char* text) { return T(QString::fromUtf8(text)); }
struct HyperTextScope {
    const ks::i18n::SourceTextSnapshot* prior;
    explicit HyperTextScope(const ks::i18n::SourceTextSnapshot& text):prior(hyperText){hyperText=&text;}
    ~HyperTextScope(){hyperText=prior;}
};
template<class Value>void retireHyperValue(Value value){if(value)QThreadPool::globalInstance()->start([value=std::move(value)]{});}

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
    return source.startsWith(prefix) ? L("HCS memory properties: %1").arg(source.mid(prefix.size())) : T(source);
}
}


struct HyperPreparedData {
    struct Cell {QString text,tooltip;QVariant number;};
    struct Row {std::vector<Cell> cells;int source=-1;};
    std::shared_ptr<const Snapshot> snapshot,previous;
    std::array<std::vector<Row>,4> tables;
    std::vector<QString> search;
    std::vector<MemoryAttributionChart::Segment> segments;
    QString summary;
    ks::ui::FieldDocument interpretation;
};
namespace {
using HyperCell=HyperPreparedData::Cell;using HyperRow=HyperPreparedData::Row;
HyperCell hyperCell(QString text,QString tip={}) {return {text,tip.isEmpty()?text:tip,{}};}
HyperCell hyperAmount(Bytes value) {return value ? HyperCell{bytes(value),L("%1 bytes").arg(*value),QVariant::fromValue(static_cast<qulonglong>(*value))}:hyperCell(L("Unavailable"));}
ks::ui::FieldDocument buildHyperInterpretation(const Snapshot& snapshot,const Context& context,QString* scopeComparison=nullptr) {
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
    evidence.field(QStringLiteral("Fast snapshot at"), QStringLiteral("Fast snapshot at %1: remainder %2. PFN snapshot at %3: Driver Locked %4").arg(QStringLiteral("%1").arg(context.snapshotTime)).arg(QStringLiteral("%1").arg(bytes(context.snapshotRemainder))).arg(QStringLiteral("%1").arg(context.pfnTime)).arg(QStringLiteral("%1").arg(bytes(context.pfnDriverLocked))));
    evidence.field(QStringLiteral("Unknown"), QStringLiteral("Unknown %1").arg(QStringLiteral("%1").arg(bytes(context.pfnUnknown))));
    evidence.field(QStringLiteral("unreadable / unscanned"), QStringLiteral("unreadable / unscanned %1. Context only").arg(QStringLiteral("%1").arg(bytes(context.pfnUnscanned))));
    evidence.note(QStringLiteral("different sample times and scopes."));
    evidence.note(QStringLiteral("Repeat collection after a workload changes to compare VID allocation for the same partition identity. KSword does not stop VMs, trim memory, or change virtualization settings."));
    std::uint64_t wsl = 0, processWs = 0; bool haveWsl = false, haveProcess = false;
    for (const auto& entry : snapshot.partitions) { if (entry.owner.compare(QStringLiteral("WSL"), Qt::CaseInsensitive) == 0 && entry.vidBytes && !entry.conflictingVid) { wsl += *entry.vidBytes; haveWsl = true; } }
    for (const auto& entry : snapshot.processes) { if (entry.name.compare(QStringLiteral("vmmemWSL"), Qt::CaseInsensitive) == 0 && entry.workingSet) { processWs += *entry.workingSet; haveProcess = true; } }
    if (haveWsl && haveProcess && !snapshot.vidConflict) {
        const auto comparison = L("WSL-owned VID allocation: %1; vmmemWSL process working set: %2. The process view does not represent the entire VM allocation. This is a scope comparison, not a per-PID ownership join.").arg(bytes(wsl), bytes(processWs));
        evidence.note(comparison);if(scopeComparison)*scopeComparison=comparison;
    }
    if (snapshot.observedVidBytes && snapshot.vidTotalBytes && snapshot.observedVidBytes != snapshot.vidTotalBytes) {
        evidence.note(L("VID instances and _Total disagree. Inventory churn, missing instances or provider scope may explain the difference; the sample is not a complete partition census."));
    }
    return evidence;
}
ks::ui::FieldDocument buildHyperDetail(const Snapshot& snapshot,int index,const std::atomic_bool& cancel) {
    const auto& row = snapshot.partitions[index];
    ks::ui::FieldDocument lines;
    lines.field(QStringLiteral("Partition"), QStringLiteral("%1").arg(label(row)));
    lines.field(QStringLiteral("ID"), QStringLiteral("%1").arg(row.id));
    lines.field(QStringLiteral("Runtime ID"), QStringLiteral("%1").arg(row.runtimeId));
    lines.field(QStringLiteral("Owner"), QStringLiteral("%1").arg(row.owner));
    lines.field(QStringLiteral("Identity evidence"), QStringLiteral("%1").arg(identity(row)));
    if (row.hcs && !row.wmi && wmiComplete(snapshot)) { lines.note(QStringLiteral("This HCS compute system is absent from the ordinary Hyper-V WMI VM inventory.")); }
    if (row.vidBytes && row.hcsNodeBytes && !row.conflictingVid) {
        lines.note((*row.vidBytes == *row.hcsNodeBytes ? L("VID and HCS node memory agree: %1. Two observations of the same allocation; counted once.").arg(bytes(row.vidBytes))
            : L("VID reports %1; HCS reports %2. Sampling time or provider scope differs; do not add them.").arg(bytes(row.vidBytes), bytes(row.hcsNodeBytes))));
    }
    if (!row.hostingSystemId.isEmpty()) { lines.field(QStringLiteral("Hosting compute system"), QStringLiteral("%1. Container memory may overlap its host VM.").arg(QStringLiteral("%1").arg(row.hostingSystemId))); }
    lines.field(QStringLiteral("WMI capacity"), QStringLiteral("%1").arg(bytes(row.wmiCapacity)));
    lines.field(QStringLiteral("HCS private working set"), QStringLiteral("%1").arg(bytes(row.hcsPrivateWs)));
    lines.field(QStringLiteral("HCS commit"), QStringLiteral("%1.").arg(QStringLiteral("%1").arg(bytes(row.hcsCommit))));
    for (const auto counterIndex : row.counterIndices) {
        const auto& sample = snapshot.counters[counterIndex];
        lines.section(QStringLiteral("Counter"));
        lines.field(QStringLiteral("Metric"), metricLabel(sample.metric));
        lines.field(QStringLiteral("Bytes"), bytes(sample.bytes));
        lines.field(QStringLiteral("SampledAt"), sample.sampledAt);
        lines.field(QStringLiteral("Path"), sample.path);
    }
    if (!row.memoryEvidence.isEmpty()) { lines.section(QStringLiteral("Memory evidence"));
        const auto buildNode = [&cancel](const auto& self, const QString& name, const QJsonValue& value) -> ks::ui::FieldNode {
            ks::ui::FieldNode node;
            if(cancel.load(std::memory_order_relaxed))return node;
            node.name = name;
            if (value.isObject()) {
                node.kind = ks::ui::FieldNode::Kind::Section;node.initiallyExpanded=false;
                const auto object = value.toObject();
                for (auto it = object.constBegin(); it != object.constEnd(); ++it) node.children.append(self(self, it.key(), it.value()));
            } else if (value.isArray()) {
                node.kind = ks::ui::FieldNode::Kind::Section;node.initiallyExpanded=false;
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
    return lines;
}

std::shared_ptr<const HyperPreparedData> buildHyperData(std::shared_ptr<const Snapshot> snapshot,
    std::shared_ptr<const Snapshot> previous,const Context& context,const ks::i18n::SourceTextSnapshot& text,const std::atomic_bool& cancel) {
    const HyperTextScope scope(text);auto data=std::make_shared<HyperPreparedData>();data->snapshot=std::move(snapshot);data->previous=std::move(previous);
    const auto& snap=*data->snapshot;
    std::map<std::pair<QString,QString>,const Partition*> prior;
    if(data->previous)for(const auto& before:data->previous->partitions)if(before.vidBytes&&!before.conflictingVid)prior.emplace(std::make_pair(before.key,before.runtimeId.toCaseFolded()),&before);
    std::map<std::uint32_t,QStringList> processOwners;
    for(std::size_t i=0;i<snap.partitions.size();++i) {
        if(cancel.load(std::memory_order_relaxed))return {};
        const auto& entry=snap.partitions[i];const auto name=label(entry);
        if(entry.wmi&&entry.workerPid)processOwners[entry.workerPid].push_back(name);
        HyperRow row;row.source=static_cast<int>(i);row.cells={hyperCell(name),hyperCell(entry.owner.isEmpty()?L("Unavailable"):entry.owner),hyperCell(state(entry)),
            hyperAmount(entry.conflictingVid?Bytes{}:entry.vidBytes),hyperAmount(entry.hcsNodeBytes),hyperCell(L("Unavailable")),hyperAmount(entry.dynamicBytes),hyperAmount(entry.guestVisibleBytes),hyperAmount(entry.depositedBytes),hyperCell(identity(entry))};
        if(data->previous&&entry.vidBytes&&!entry.conflictingVid&&!snap.vidConflict&&!data->previous->vidConflict) {
            const auto found=prior.find({entry.key,entry.runtimeId.toCaseFolded()});
            if(found!=prior.end()&&*entry.vidBytes<=std::uint64_t((std::numeric_limits<qint64>::max)())&&*found->second->vidBytes<=std::uint64_t((std::numeric_limits<qint64>::max)())) {
                const auto delta=static_cast<qint64>(*entry.vidBytes)-static_cast<qint64>(*found->second->vidBytes);
                row.cells[5]={(delta<0?QStringLiteral("-"):QStringLiteral("+"))+bytes(std::uint64_t(delta<0?-delta:delta)),L("VID allocation change since %1; matching partition identity.").arg(data->previous->finished),QVariant::fromValue(delta)};
            }
        }
        data->tables[0].push_back(std::move(row));data->search.push_back(name+QLatin1Char(' ')+entry.owner+QLatin1Char(' ')+entry.id+QLatin1Char(' ')+entry.runtimeId);
        if(entry.vidBytes&&!entry.conflictingVid&&!snap.vidConflict)data->segments.push_back({name,*entry.vidBytes,static_cast<int>(i)});
    }
    for(std::size_t i=0;i<snap.counters.size();++i) {
        if(cancel.load(std::memory_order_relaxed))return {};
        const auto& sample=snap.counters[i];HyperRow row;row.source=static_cast<int>(i);
        row.cells={hyperCell(metricLabel(sample.metric),sample.path+QLatin1Char('\n')+sample.explanation+QLatin1Char('\n')+sample.sampledAt),hyperCell(sample.instance),hyperAmount(sample.bytes),hyperCell(status(sample.status)),hyperCell(role(sample.metric))};data->tables[1].push_back(std::move(row));
    }
    for(std::size_t i=0;i<snap.processes.size();++i) {
        if(cancel.load(std::memory_order_relaxed))return {};
        const auto& process=snap.processes[i];const auto found=processOwners.find(process.pid);
        const auto match=found!=processOwners.end()&&found->second.size()==1?L("WMI worker PID: %1 (sampled separately)").arg(found->second.front()):L("Separate process view; no proven per-PID physical ownership");
        data->tables[2].push_back({{hyperCell(process.name),hyperCell(QString::number(process.pid)),hyperAmount(process.workingSet),hyperAmount(process.privateCommit),hyperCell(match)},static_cast<int>(i)});
    }
    for(std::size_t i=0;i<snap.sources.size();++i) {
        if(cancel.load(std::memory_order_relaxed))return {};
        const auto& source=snap.sources[i];data->tables[3].push_back({{hyperCell(sourceName(source.name)),hyperCell(source.complete?L("Complete"):L("Partial / unavailable")),hyperCell(QString::number(source.rows)),hyperCell(status(source.status))},static_cast<int>(i)});
    }
    const auto valid=std::count_if(snap.counters.begin(),snap.counters.end(),[](const Counter& sample){return sample.bytes.has_value();});
    QStringList summary{L("Observed VM allocation: %1 | Owner unresolved: %2 | Hypervisor overhead counter: %3").arg(bytes(snap.observedVidBytes),bytes(snap.unresolvedVidBytes),bytes(hypervisorBytes(snap))),L("Sample: %1 | Counters available: %2 / %3. These views overlap and cannot be added to the PFN ledger.").arg(snap.finished).arg(valid).arg(snap.counters.size())};
    if(snap.cancelled||snap.timedOut||snap.resourceFailure)summary<<L("Partial collection: cancelled, timed out, or resource-limited. Missing values are not zero.");
    if(snap.vidConflict)summary<<L("VID identity conflict: aggregate and chart withheld to prevent double counting.");
    QString scopeComparison;data->interpretation=buildHyperInterpretation(snap,context,&scopeComparison);
    if(!scopeComparison.isEmpty())summary<<scopeComparison;
    data->summary=summary.join(QLatin1Char('\n'));return data;
}
}
struct HyperViewData {std::shared_ptr<const HyperPreparedData> source;std::vector<std::size_t> partitions;int selected=-1;};
namespace {
std::shared_ptr<const HyperViewData> filterHyperData(std::shared_ptr<const HyperPreparedData> source,const QString& filter,const QString& selected,int requested,const std::atomic_bool& cancel) {
    auto view=std::make_shared<HyperViewData>();view->source=std::move(source);
    for(std::size_t i=0;i<view->source->search.size();++i){if(cancel.load(std::memory_order_relaxed))return {};if(filter.isEmpty()||view->source->search[i].contains(filter,Qt::CaseInsensitive)) {
        if(static_cast<int>(i)==requested||(requested<0&&view->source->snapshot->partitions[i].key==selected))view->selected=static_cast<int>(view->partitions.size());view->partitions.push_back(i);
    }}
    if(view->selected<0&&!view->partitions.empty())view->selected=0;return view;
}
}
class HyperTableModel final:public QAbstractTableModel {
public:
    explicit HyperTableModel(QObject*parent):QAbstractTableModel(parent){}
    std::shared_ptr<const HyperViewData> view;int table=0;QStringList titles;
    int rowCount(const QModelIndex&parent={})const override{return parent.isValid()||!view?0:table==0?static_cast<int>(view->partitions.size()):static_cast<int>(view->source->tables[table].size());}
    int columnCount(const QModelIndex&parent={})const override{return parent.isValid()?0:titles.size();}
    const HyperRow* row(int index)const{if(!view||index<0||index>=rowCount())return nullptr;return &view->source->tables[table][table==0?view->partitions[index]:index];}
    QVariant data(const QModelIndex&index,int role)const override {
        const auto*r=row(index.row());if(!index.isValid()||!r||index.column()<0||index.column()>=static_cast<int>(r->cells.size()))return {};
        const auto&cell=r->cells[index.column()];if(role==Qt::DisplayRole)return cell.text;if(role==Qt::ToolTipRole)return cell.tooltip;
        if(role==Qt::UserRole||role==ks::ui::NumericSortRole)return cell.number;
        if(role==Qt::TextAlignmentRole&&cell.number.isValid())return static_cast<int>(Qt::AlignRight|Qt::AlignVCenter);return {};
    }
    QVariant headerData(int section,Qt::Orientation orientation,int role)const override{return orientation==Qt::Horizontal&&(role==Qt::DisplayRole||role==Qt::ToolTipRole)?titles.value(section):QAbstractTableModel::headerData(section,orientation,role);}
    void headers(const QStringList&replacement){titles=replacement;emit headerDataChanged(Qt::Horizontal,0,titles.size()-1);}
    void replace(std::shared_ptr<const HyperViewData> replacement,int kind){beginResetModel();auto old=std::move(view);view=std::move(replacement);table=kind;endResetModel();retireHyperValue(std::move(old));}
};
namespace {
QTableView* table(QWidget*parent){auto*view=new ks::ui::TableActionTableView(parent);view->setModel(new HyperTableModel(view));view->setProperty("ks_i18n_preserve_model_data",true);view->model()->setProperty("ks_i18n_preserve_model_data",true);ks::ui::SetTableColumnAutoFitEnabled(view,false);ks::ui::SetTableRowFilterBusinessOwnership(view,ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);view->setEditTriggers(QAbstractItemView::NoEditTriggers);view->setSelectionBehavior(QAbstractItemView::SelectRows);view->setSelectionMode(QAbstractItemView::SingleSelection);view->verticalHeader()->hide();view->horizontalHeader()->setStretchLastSection(true);view->horizontalHeader()->setDefaultSectionSize(150);view->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);view->setAlternatingRowColors(true);return view;}
void headers(QTableView*view,const QStringList& labels){static_cast<HyperTableModel*>(view->model())->headers(labels);}
}
struct HyperVMemoryPage::ProjectionJob {
    std::atomic_bool cancel{false},done{false};bool failed=false;std::uint64_t version=0;
    std::shared_ptr<const Snapshot> snapshot;std::shared_ptr<const HyperViewData> view;
};
struct HyperVMemoryPage::DetailJob {
    std::atomic_bool cancel{false},done{false};bool failed=false;std::uint64_t locale=0;int index=-1;
    std::shared_ptr<const Snapshot> snapshot;ks::ui::FieldDocument document;
};

struct HyperVMemoryPage::ExportJob {
    std::atomic_bool done{false};
    // 0: cancellable; 1: atomic commit claimed; 2: cancellation accepted.
    std::atomic_int phase{0};
    QString path, error;
    bool saved = false;
    std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> shutdownLease;
};

HyperVMemoryPage::HyperVMemoryPage(QWidget* parent) : QWidget(parent)
{
    // 页面自带内部滚动壳：固定高度的归因图加五页签约四百五十像素，嵌在系统内存审计页里
    // 放不下时在本页内滚动。根布局建在壳的内容容器上。
    auto* root = new QVBoxLayout(ks::ui::EnablePageInnerScroll(this));
    root->setContentsMargins(0, 0, 0, 0);
    // 归因图与采集摘要组成结果头，内部图表保持原绘制和高度，结果页签紧随其后。
    auto* resultGroup = new QWidget(this);
    auto* resultLayout = new QVBoxLayout(resultGroup);
    resultLayout->setContentsMargins(0, 0, 0, 0);
    resultLayout->setSpacing(0);
    root->addWidget(resultGroup, 1);
    auto* resultHeader = new QWidget(resultGroup);
    auto* headerLayout = new QVBoxLayout(resultHeader);
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(6);
    // 采集与筛选共用一条轻工具带，归因图和证据页保持原有高度分配。
    auto* collectionToolbar = new QWidget(this); // 采集控制容器由内层布局重新接管。
    ks::ui::StylePrimaryToolbar(collectionToolbar);
    auto* actions = new QHBoxLayout(collectionToolbar);
    actions->setContentsMargins(8, 4, 8, 4);
    m_collect = new QPushButton(this); m_cancel = new QPushButton(this); m_export = new QPushButton(this);
    m_filter = new QLineEdit(this); m_filter->setClearButtonEnabled(true);
    ks::ui::StyleSearchField(m_filter);
    actions->addWidget(m_collect); actions->addWidget(m_cancel); actions->addWidget(m_filter, 1); actions->addWidget(m_export);
    ks::ui::NormalizeToolbarRow(actions);
    ks::ui::ApplyFlatButtonTheme(m_collect, ks::ui::FlatButtonTone::Accent);
    ks::ui::ApplyFlatButtonTheme(m_cancel, ks::ui::FlatButtonTone::Neutral);
    ks::ui::ApplyFlatButtonTheme(m_export, ks::ui::FlatButtonTone::Neutral);
    headerLayout->addWidget(collectionToolbar);
    auto* metricTools = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    m_metricAreaButton = new QPushButton(this); metricTools->addWidget(m_metricAreaButton);
    ks::ui::NormalizeToolbarControl(m_metricAreaButton); headerLayout->addLayout(metricTools);
    connect(m_metricAreaButton, &QPushButton::clicked, this, [this] { openMetricAreaView(); });
    m_summary = new QLabel(this); m_summary->setWordWrap(true); m_summary->setTextFormat(Qt::PlainText);
    m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse); headerLayout->addWidget(m_summary);
    m_progress = new QProgressBar(this); m_progress->setTextVisible(false); m_progress->setMaximumHeight(5); headerLayout->addWidget(m_progress);
    m_chart = new MemoryAttributionChart(this); headerLayout->addWidget(m_chart);
    resultLayout->addWidget(resultHeader);
    m_tabs = new QTabWidget(this);
    ks::ui::StyleJoinedResultTabs(m_tabs, resultHeader);
    auto* split = new QSplitter(Qt::Vertical, m_tabs);
    m_partitions = table(split); m_detail = new ks::ui::StructuredFieldView(split);m_detail->setValueModelProjection();

    split->addWidget(m_partitions); split->addWidget(m_detail); split->setStretchFactor(0, 3); split->setStretchFactor(1, 1);
    m_tabs->addTab(split, {});
    m_host = table(m_tabs); m_tabs->addTab(m_host, {});
    m_processes = table(m_tabs); m_tabs->addTab(m_processes, {});
    m_sources = table(m_tabs); m_tabs->addTab(m_sources, {});
    // 分区/进程明细保留复制导出；页面自有 VID 差值与证据导出，无需四份快照栏。
    ks::ui::SetTableActionBarMode(m_partitions, ks::ui::TableActionBarMode::Compact);
    ks::ui::SetTableActionBarMode(m_processes, ks::ui::TableActionBarMode::Compact);
    ks::ui::SetTableActionBarMode(m_host, ks::ui::TableActionBarMode::None);
    ks::ui::SetTableActionBarMode(m_sources, ks::ui::TableActionBarMode::None);
    m_evidence = new ks::ui::StructuredFieldView(m_tabs);m_evidence->setValueModelProjection();
     m_tabs->addTab(m_evidence, {});
    resultLayout->addWidget(m_tabs, 1);
    connect(m_collect, &QPushButton::clicked, this, [this] { startCollection(); });
    connect(m_cancel, &QPushButton::clicked, this, [this] {
        if (m_job) { m_job->cancel.store(true); }
        if (m_exportJob) { int active = 0; m_exportJob->phase.compare_exchange_strong(active, 2); }
    });
    connect(m_export, &QPushButton::clicked, this, [this] { exportEvidence(); });

    m_projectionDebounce=new QTimer(this);m_projectionDebounce->setSingleShot(true);m_projectionDebounce->setInterval(120);
    connect(m_projectionDebounce,&QTimer::timeout,this,[this]{pollProjection();});
    connect(m_filter,&QLineEdit::textChanged,this,[this]{requestProjection();});
    connect(m_tabs,&QTabWidget::currentChanged,this,[this]{bindCurrentProjection();pollProjection();updateMetricAreaAction();});
    connect(m_partitions->selectionModel(),&QItemSelectionModel::selectionChanged,this,[this]{
        const auto*row=static_cast<HyperTableModel*>(m_partitions->model())->row(m_partitions->currentIndex().row());if(row)showPartition(row->source);
    });
    m_chart->selected=[this](int key){m_requestedPartition=key;m_filter->clear();requestProjection();m_tabs->setCurrentIndex(0);};
    m_partitions->setColumnWidth(0,270);m_partitions->setColumnWidth(9,300);m_host->setColumnWidth(4,450);
    auto* timer = new QTimer(this); timer->setInterval(150);
    connect(timer, &QTimer::timeout, this, [this] { poll();pollProjection(); }); timer->start();
    retranslate(); rebuild();
}
HyperVMemoryPage::~HyperVMemoryPage()
{
    m_detail->setDocument({});m_evidence->setDocument({});
    if(m_projectionJob)m_projectionJob->cancel.store(true);if(m_detailJob)m_detailJob->cancel.store(true);
    for(auto*view:{m_partitions,m_host,m_processes,m_sources})retireHyperValue(std::move(static_cast<HyperTableModel*>(view->model())->view));
    retireHyperValue(std::move(m_readyView));retireHyperValue(std::move(m_prepared));retireHyperValue(std::move(m_detailSnapshot));retireHyperValue(std::move(m_snapshot));retireHyperValue(std::move(m_previous));retireHyperValue(std::move(m_projectionJob));retireHyperValue(std::move(m_detailJob));

    if (m_job) { m_job->cancel.store(true); }
    retireHyperValue(std::move(m_job));
    if (m_exportJob) { int active = 0; m_exportJob->phase.compare_exchange_strong(active, 2); }
}
void HyperVMemoryPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_collect) { ++m_localeVersion;retranslate();requestProjection(true); }
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
    if (m_job || m_exportJob) { return; }
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
    if (m_exportJob) {
        if (!m_exportJob->done.load()) {
            m_cancel->setEnabled(m_exportJob->phase.load() == 0);
            return;
        }
        const auto job = std::move(m_exportJob);
        m_collect->setEnabled(true); m_cancel->setEnabled(false); m_export->setEnabled(bool(m_snapshot));
        m_cancel->setText(L("Cancel collection"));
        m_progress->setRange(0, 1); m_progress->setValue(job->saved ? 1 : 0);
        m_summary->setText(job->saved ? L("Hyper-V evidence saved to %1").arg(job->path)
            : job->phase.load() == 2 ? L("Evidence export cancelled")
            : L("Failed to export Hyper-V evidence: %1").arg(job->error));
    }
    if (!m_job) { return; }
    if (m_job->done.load()) {
        std::shared_ptr<Snapshot> result;
        { std::lock_guard<std::mutex> lock(m_job->mutex); result = m_job->result; }
        m_job.reset(); m_collect->setEnabled(true); m_cancel->setEnabled(false); m_progress->setRange(0, 1); m_progress->setValue(1);
        if (!result) { m_summary->setText(L("Hyper-V collection did not return a snapshot.")); m_export->setEnabled(bool(m_snapshot)); return; }
        retireHyperValue(std::move(m_previous));m_previous = m_snapshot; m_snapshot = std::move(result); m_resultContext = m_jobContext;
        rebuild(); return;
    }
    constexpr const char* phases[]{"Starting Hyper-V evidence collection", "Reading host and partition counters", "Reading Hyper-V inventory and VBS state", "Reading HCS utility VM memory", "Reading host process memory"};
    const auto phase = std::min<unsigned>(m_job->phase.load(), 4);
    m_summary->setText(m_job->cancel.load() ? L("Cancelling; waiting for the current provider call to return.")
        : L("%1. Existing results below are from the previous sample.").arg(L(phases[phase])));
}
void HyperVMemoryPage::retranslate()
{
    m_metricAreaButton->setText(ks::i18n::sourceText(QStringLiteral("矩形面积视图")));
    updateMetricAreaAction();
    m_collect->setText(L("Collect Hyper-V evidence")); m_cancel->setText(m_exportJob ? L("Cancel") : L("Cancel collection")); m_export->setText(L("Export evidence"));
    m_filter->setPlaceholderText(L("Filter partition, owner, GUID, or runtime ID"));
    m_collect->setToolTip(L("Read VID, Hyper-V WMI, HCS, VBS and host process evidence. Repeat to compare allocations over time."));
    m_tabs->setTabText(0, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::HyperV, 0)); m_tabs->setTabText(1, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::HyperV, 1));
    m_tabs->setTabText(2, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::HyperV, 2)); m_tabs->setTabText(3, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::HyperV, 3)); m_tabs->setTabText(4, ks::ui::MemoryNavigationTabTitle(ks::ui::MemoryNavigationGroup::HyperV, 4));
    headers(m_partitions, {L("Partition / VM"), L("Owner"), L("State"), L("VID physical"), L("HCS node memory"), L("VID delta"), L("Dynamic physical"), L("Guest-visible capacity"), L("Deposited pages"), L("Identity evidence")});
    headers(m_host, {L("Metric"), L("Instance"), L("Bytes"), L("Status"), L("Accounting role")});
    headers(m_processes, {L("Process"), L("PID"), L("Working set"), L("Private commit"), L("Partition evidence")});
    headers(m_sources, {L("Source"), L("Coverage"), L("Rows"), L("Status")});
}

void HyperVMemoryPage::rebuildPartitions(){requestProjection();}
void HyperVMemoryPage::rebuild() {
    m_cancel->setEnabled(bool(m_job)||(m_exportJob&&m_exportJob->phase.load()==0));m_collect->setEnabled(!m_job&&!m_exportJob);m_export->setEnabled(bool(m_snapshot)&&!m_job&&!m_exportJob);
    if(!m_job&&!m_exportJob){m_progress->setRange(0,1);m_progress->setValue(m_snapshot?1:0);}
    if(!m_snapshot){m_summary->setText(L("Find VM and utility-VM allocations that a process list cannot fully explain. Collect a sample to link partition counters to WSL, containers and registered VMs."));m_chart->setSegments({},L("Hyper-V partition allocations"));return;}
    requestProjection(true);
}
void HyperVMemoryPage::requestProjection(bool rebuild) {
    ++m_projectionVersion;m_rebuildProjection=m_rebuildProjection||rebuild;if(m_projectionJob)m_projectionJob->cancel.store(true);
    if(m_detailJob)m_detailJob->cancel.store(true);m_projectionDebounce->start();
    m_chart->setEnabled(false);if(m_snapshot&&!m_job&&!m_exportJob)m_summary->setText(L("Updating Hyper-V memory tables..."));
    for(auto*view:{m_partitions,m_host,m_processes,m_sources})view->setEnabled(false);
}
void HyperVMemoryPage::pollProjection() {
    if(m_projectionJob&&m_projectionJob->done.load(std::memory_order_acquire)) {
        if(m_projectionJob->version!=m_projectionVersion||m_projectionJob->snapshot!=m_snapshot)retireHyperValue(std::move(m_projectionJob));
        else if(isVisible()) {
            auto job=std::move(m_projectionJob);m_publishedVersion=job->version;
            if(job->view){auto oldView=std::move(m_readyView);m_readyView=job->view;retireHyperValue(std::move(oldView));auto old=std::move(m_prepared);m_prepared=job->view->source;m_rebuildProjection=false;m_summary->setText(m_prepared->summary);m_chart->setSegments(m_prepared->segments,L("VID partition allocations only; click a segment for ownership evidence."));m_chart->setEnabled(true);
                const QPointer<HyperVMemoryPage>guard(this);bindCurrentProjection();if(!guard)return;retireHyperValue(std::move(old));}
            else m_summary->setText(L("Hyper-V table projection failed."));retireHyperValue(std::move(job));
        }
    }
    if(!m_projectionJob&&m_snapshot&&m_publishedVersion!=m_projectionVersion&&isVisible()&&!m_projectionDebounce->isActive()) {
        auto job=std::make_shared<ProjectionJob>();job->version=m_projectionVersion;job->snapshot=m_snapshot;m_projectionJob=job;
        const auto cached=m_rebuildProjection?std::shared_ptr<const HyperPreparedData>{}:m_prepared;const auto previous=m_previous;const auto context=m_resultContext;
        const auto text=ks::i18n::LanguageManager::instance().sourceTextSnapshot();const auto filter=m_filter->text().trimmed();const auto requested=m_requestedPartition;
        QString selected;const auto*row=static_cast<HyperTableModel*>(m_partitions->model())->row(m_partitions->currentIndex().row());
        const auto*model=static_cast<HyperTableModel*>(m_partitions->model());
        if(row&&model->view)selected=model->view->source->snapshot->partitions[row->source].key;
        try{std::thread([job,cached,previous,context,text,filter,selected,requested]{try{auto prepared=cached?cached:buildHyperData(job->snapshot,previous,context,text,job->cancel);if(prepared&&!job->cancel.load())job->view=filterHyperData(std::move(prepared),filter,selected,requested,job->cancel);}catch(...){job->failed=true;}job->done.store(true,std::memory_order_release);}).detach();}catch(...){job->failed=true;job->done.store(true,std::memory_order_release);}
    }
    if(m_detailJob&&m_detailJob->done.load(std::memory_order_acquire)) {
        if(m_detailJob->cancel.load()||m_detailJob->snapshot!=m_snapshot||m_detailJob->index!=m_shownPartition||m_detailJob->locale!=m_localeVersion)retireHyperValue(std::move(m_detailJob));
        else if(isVisible()&&m_tabs->currentIndex()==0) {
            auto job=std::move(m_detailJob);retireHyperValue(std::move(m_detailSnapshot));m_detailSnapshot=job->snapshot;m_detailLocale=job->locale;
            if(!job->failed)m_detail->setDocument(job->document);else{ks::ui::FieldDocument failed;failed.note(L("Hyper-V table projection failed."));m_detail->setDocument(failed);}retireHyperValue(std::move(job));
        }
    }
    if(m_shownPartition>=0&&!m_detailJob&&(m_detailSnapshot!=m_snapshot||m_detailLocale!=m_localeVersion)&&isVisible()&&m_tabs->currentIndex()==0)showPartition(m_shownPartition);
}
void HyperVMemoryPage::bindCurrentProjection() {
    if(!isVisible()||!m_prepared||m_publishedVersion!=m_projectionVersion)return;
    const int kind=m_tabs->currentIndex();if(kind<0||kind>4||m_boundVersions[kind]==m_publishedVersion)return;
    m_boundVersions[kind]=m_publishedVersion;
    if(kind==4){m_evidence->setDocument(m_prepared->interpretation);return;}
    QTableView*views[]={m_partitions,m_host,m_processes,m_sources};auto*view=views[kind];auto*model=static_cast<HyperTableModel*>(view->model());
    // Each tab binds the same immutable filtered view; it is retained after the
    // job is consumed, so a hidden tab needs no new preparation on return.
    const auto preparedView=m_readyView;
    const QPointer<HyperVMemoryPage>guard(this);QSignalBlocker blocked(view->selectionModel());model->replace(preparedView,kind);if(!guard){blocked.dismiss();return;}view->setEnabled(true);
    if(kind==0){m_requestedPartition=-1;const auto selected=preparedView->selected;if(selected>=0){view->setCurrentIndex(model->index(selected,0));showPartition(model->row(selected)->source);}else{m_shownPartition=-1;retireHyperValue(std::move(m_detailSnapshot));m_detail->setDocument({});}}
    refreshMetricAreaView(kind); updateMetricAreaAction();
}
void HyperVMemoryPage::updateMetricAreaAction()
{
    if (!m_metricAreaButton || !m_tabs) return;
    const int kind = m_tabs->currentIndex();
    QTableView* views[]{m_partitions, m_host, m_processes, m_sources};
    m_metricAreaButton->setEnabled(kind >= 0 && kind < 4 && bool(static_cast<HyperTableModel*>(views[kind]->model())->view));
    const auto callback = metricAreaStateChanged; if (callback) callback();
}
bool HyperVMemoryPage::hasMetricAreaData() const
{
    if (!m_tabs) return false;
    const int kind = m_tabs->currentIndex(); if (kind < 0 || kind >= 4) return false;
    QTableView* views[]{m_partitions, m_host, m_processes, m_sources};
    return bool(static_cast<HyperTableModel*>(views[kind]->model())->view);
}
void HyperVMemoryPage::openMetricAreaView()
{
    const int kind = m_tabs->currentIndex(); if (kind < 0 || kind >= 4) return;
    QTableView* views[]{m_partitions, m_host, m_processes, m_sources};
    if (!static_cast<HyperTableModel*>(views[kind]->model())->view) return;
    if (!m_metricAreaWindows[kind]) {
        auto* window = new ks::ui::MetricAreaWindow(this); m_metricAreaWindows[kind] = window;
        window->modeChanged = [this, kind](int) { refreshMetricAreaView(kind); };
        window->appearanceChanged = [this, kind] { refreshMetricAreaView(kind); };
    }
    refreshMetricAreaView(kind);
    const auto window = m_metricAreaWindows[kind]; window->show(); window->raise(); window->activateWindow();
}
void HyperVMemoryPage::refreshMetricAreaView(const int kind)
{
    if (kind < 0 || kind >= 4) return;
    const auto window = m_metricAreaWindows[kind]; if (!window) return;
    QTableView* views[]{m_partitions, m_host, m_processes, m_sources};
    auto* model = static_cast<HyperTableModel*>(views[kind]->model());
    const auto committed = model->view; if (!committed) return;
    const auto snapshot = committed->source->snapshot;
    const std::array<int, 6> partitionColumns{3, 4, 5, 6, 7, 8};
    QStringList modes;
    if (kind == 0) for (int column : partitionColumns) modes.append(model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString());
    else if (kind == 1) for (int metric = 0; metric <= static_cast<int>(Metric::BalancerAvailableForBalancing); ++metric) modes.append(metricLabel(static_cast<Metric>(metric)));
    else if (kind == 2) modes = {L("Working set"), L("Private commit")};
    else modes = {L("Provider row counts")};
    const int mode = qBound(0, window->currentMode(), static_cast<int>(modes.size()) - 1);
    window->setModes(modes, mode);
    window->setSubject(L("Current Hyper-V table"), kind == 2 ? L("Process") : kind == 3 ? L("Source") : L("Partition / instance"), kind == 2 ? QStringLiteral("PID") : QString(),
        L("Click a rectangle to select the source row. Metrics are separate views and cannot be added to the PFN ledger; double-click zooms in."));
    std::vector<ks::ui::MetricAreaNode> nodes;
    for (int row = 0; row < model->rowCount(); ++row) {
        const auto* rowData = model->row(row); if (!rowData || rowData->source < 0) continue;
        const auto index = static_cast<std::size_t>(rowData->source);
        if (kind == 1) {
            const auto& counter = snapshot->counters[index];
            if (static_cast<int>(counter.metric) != mode || counter.instance.compare(QStringLiteral("_Total"), Qt::CaseInsensitive) == 0) continue;
        }
        const int column = kind == 0 ? partitionColumns[mode] : kind == 2 ? mode + 2 : 2;
        QVariant raw = kind == 3 ? QVariant::fromValue(snapshot->sources[index].rows) : rowData->cells[column].number;
        if (kind == 0 && (mode == 0 || mode == 2) && snapshot->vidConflict) raw = {};
        ks::ui::MetricAreaNode node;
        node.key = QString::number(index);
        node.name = kind == 1 ? rowData->cells[1].text : rowData->cells[0].text;
        node.identity = kind == 2 ? rowData->cells[1].text : QString();
        node.known = raw.isValid(); node.weight = std::fabs(raw.toDouble());
        node.value = node.known ? rowData->cells[column].text : L("Unavailable"); node.tooltip = node.name + QLatin1Char('\n') + modes[mode] + QStringLiteral(": ") + node.value;
        if (kind == 0) node.key = snapshot->partitions[index].key + QLatin1Char('|') + snapshot->partitions[index].runtimeId;
        else node.key += QLatin1Char('|') + snapshot->finished;
        nodes.push_back(std::move(node));
    }
    QString stateText = L("Committed Hyper-V table | Collection %1 to %2 | Metrics are not additive physical ownership.").arg(snapshot->started, snapshot->finished);
    if (kind == 0 && mode == 2) stateText += QLatin1Char('\n') + L("Area uses the absolute change; the displayed value retains its sign.");
    if (kind == 1) stateText += QLatin1Char('\n') + L("_Total counter rows are excluded to avoid adding an aggregate to its instances.");
    if (kind == 3) stateText += QLatin1Char('\n') + L("Area is a count of provider rows, not memory bytes.");
    if (kind == 0 && snapshot->vidConflict) stateText += QLatin1Char('\n') + L("VID identity conflict: aggregate and chart withheld to prevent double counting.");
    if (m_job) stateText += QLatin1Char('\n') + L("Collection is running; the previous committed table remains visible.");
    window->setPresentation(modes[mode], stateText, std::move(nodes));
    const QPointer<HyperVMemoryPage> owner(this);
    window->itemActivated = [owner, committed, kind](const QString& key) {
        if (!owner) return;
        QTableView* views[]{owner->m_partitions, owner->m_host, owner->m_processes, owner->m_sources};
        auto* model = static_cast<HyperTableModel*>(views[kind]->model()); if (model->view != committed) return;
        for (int row = 0; row < model->rowCount(); ++row) {
            const auto* rowData = model->row(row); if (!rowData || rowData->source < 0) continue;
            const auto index = static_cast<std::size_t>(rowData->source);
            const QString rowKey = kind == 0 ? committed->source->snapshot->partitions[index].key + QLatin1Char('|') + committed->source->snapshot->partitions[index].runtimeId
                : QString::number(index) + QLatin1Char('|') + committed->source->snapshot->finished;
            if (rowKey == key) {
                owner->m_tabs->setCurrentIndex(kind);
                if (!owner || static_cast<HyperTableModel*>(views[kind]->model())->view != committed) return;
                views[kind]->selectRow(row); break;
            }
        }
    };
}
void HyperVMemoryPage::showPartition(int index) {
    if(m_publishedVersion!=m_projectionVersion||!m_prepared||m_prepared->snapshot!=m_snapshot)return;
    if(!m_snapshot||index<0||index>=static_cast<int>(m_snapshot->partitions.size()))return;
    if(m_shownPartition!=index){m_shownPartition=index;retireHyperValue(std::move(m_detailSnapshot));if(m_detailJob)m_detailJob->cancel.store(true);}
    if(!isVisible()||m_tabs->currentIndex()!=0||(m_detailSnapshot==m_snapshot&&m_detailLocale==m_localeVersion))return;
    // Selection changes must not present the previous partition's document as
    // the newly selected object while its canonical HCS fields are prepared.
    if(!m_detailJob||m_detailJob->index!=index||m_detailJob->snapshot!=m_snapshot) {
        ks::ui::FieldDocument pending;pending.note(L("Reading HCS utility VM memory"));
        const QPointer<HyperVMemoryPage>guard(this);m_detail->setDocument(pending, true);if(!guard)return;
    }
    if(m_detailJob)return;
    auto job=std::make_shared<DetailJob>();job->index=index;job->snapshot=m_snapshot;job->locale=m_localeVersion;m_detailJob=job;
    const auto text=ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    try{std::thread([job,text]{try{const HyperTextScope scope(text);job->document=buildHyperDetail(*job->snapshot,job->index,job->cancel);}catch(...){job->failed=true;}job->done.store(true,std::memory_order_release);}).detach();}catch(...){job->failed=true;job->done.store(true,std::memory_order_release);}
}
void HyperVMemoryPage::showEvent(QShowEvent*event){QWidget::showEvent(event);bindCurrentProjection();pollProjection();}
void HyperVMemoryPage::exportEvidence()
{
    if (!m_snapshot || m_job || m_exportJob) { return; }
    // 保存对话框可处理嵌套事件；先冻结证据和身份，返回后再核验页面生命期。
    const std::shared_ptr<const Snapshot> snapshot = m_snapshot, previous = m_previous;
    const auto context = m_resultContext;
    const auto frozenText=ks::i18n::LanguageManager::instance().sourceTextSnapshot();
    const QPointer<HyperVMemoryPage> page(this);
    const auto path = QFileDialog::getSaveFileName(this, L("Export Hyper-V memory evidence"), QStringLiteral("hyperv-memory-evidence.json"), L("JSON files (*.json)"));
    if (!page || path.isEmpty() || m_job || m_exportJob) { return; }
    const auto job = std::make_shared<ExportJob>();
    job->path = path;
    const auto workerFailure = L("Evidence export worker failed");
    job->shutdownLease = ks::ui::AsyncCleanupRegistry::global().acquire([weak = std::weak_ptr<ExportJob>(job)] {
        if (const auto activeJob = weak.lock()) { int active = 0; activeJob->phase.compare_exchange_strong(active, 2); }
    });
    if (!job->shutdownLease) { m_summary->setText(L("Failed to export Hyper-V evidence: %1").arg(workerFailure)); return; }
    m_exportJob = job;
    m_collect->setEnabled(false); m_export->setEnabled(false); m_cancel->setEnabled(true);
    m_cancel->setText(L("Cancel")); m_summary->setText(L("Export evidence")); m_progress->setRange(0, 0);
    try { std::thread([job, snapshot, previous, context, frozenText, workerFailure] {
        try {
            if (job->phase.load() != 2) {
                const HyperTextScope scope(frozenText);
                const auto interpretation=buildHyperInterpretation(*snapshot,context).toPlainText([frozenText](const QString& value){return frozenText.sourceText(value);});
                auto object = toJson(*snapshot, context);
                object.insert(QStringLiteral("interpretation"), interpretation);
                if (previous) { object.insert(QStringLiteral("previous_sample"), toJson(*previous)); }
                const auto data = QJsonDocument(object).toJson(QJsonDocument::Indented);
                QSaveFile file(job->path);
                if (job->phase.load() != 2) {
                    if (!file.open(QIODevice::WriteOnly)) { job->error = file.errorString(); }
                    else {
                        qsizetype offset = 0;
                        while (offset < data.size() && job->phase.load() != 2) {
                            const auto count = std::min<qsizetype>(65536, data.size() - offset);
                            if (file.write(data.constData() + offset, count) != count) { job->error = file.errorString(); break; }
                            offset += count;
                        }
                        int active = 0;
                        if (offset == data.size() && job->phase.compare_exchange_strong(active, 1)) {
                            job->saved = file.commit();
                            if (!job->saved) { job->error = file.errorString(); }
                        }
                    }
                }
            }
        } catch (...) { job->error = workerFailure; }
        job->done.store(true);
        job->shutdownLease.reset();
    }).detach(); } catch (...) { job->error = workerFailure; job->done.store(true); job->shutdownLease.reset(); }
}
