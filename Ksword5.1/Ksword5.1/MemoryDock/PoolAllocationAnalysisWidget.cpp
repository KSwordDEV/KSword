#include "PoolAllocationAnalysisWidget.h"
#include "../UI/StructuredFieldView.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/FlowLayout.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableColumnAutoFit.h"
#include "../UI/TableRowFilterSupport.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/MetricAreaWindow.h"
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
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QShowEvent>
#include <QThreadPool>
#include <QScrollBar>
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


// Every pointer in these indices is owned by trace. All scans, aggregation,
// search preparation and ordering run on plain worker values.
struct PoolPreparedProjection {
    struct Row {
        QString source, search;
        std::vector<const Group*> groups;
        std::array<std::uint64_t, 8> counters{};
        std::array<bool, 8> saturated{};
    };
    std::shared_ptr<const TraceReadResult> trace;
    ImageIndex images;
    std::unordered_set<std::uint64_t> kernelImages;
    std::unordered_map<std::uint64_t, const Group*> groups;
    std::array<std::vector<Row>, 3> modes;
};
namespace {
template<class T> void retirePoolValue(T value) {
    if (value) QThreadPool::globalInstance()->start([value = std::move(value)] {});
}
std::shared_ptr<const PoolPreparedProjection> preparePoolProjection(
    std::shared_ptr<const TraceReadResult> trace, const ks::i18n::SourceTextSnapshot& text,
    const QLocale& locale, const std::atomic_bool& cancel) {
    auto out = std::make_shared<PoolPreparedProjection>(); out->trace = std::move(trace);
    if (!out->trace) return out;
    const auto tr = [&text](const char* source) { return text.packedSourceText(QString::fromUtf8(source)); };
    const auto n = [&locale](std::uint64_t value) { return locale.toString(static_cast<qulonglong>(value)); };
    const auto session = [&](std::uint32_t id) { return id == 0xffffffffU ? tr("ordinary pool") : tr("session %1").arg(n(id)); };
    const auto imageName = [&](const TraceImage* image) { return image ? QString::fromStdWString(image->path) : tr("Unknown historical module"); };
    for (const auto& image : out->trace->images) {
        if (cancel.load(std::memory_order_relaxed)) return {};
        out->images.emplace(image.id, &image);
        auto path = QString::fromStdWString(image.path); path.replace(QChar('\\'), QChar('/'));
        const auto name = path.section(QChar('/'), -1).toLower();
        if (name == QStringLiteral("ntoskrnl.exe") || name == QStringLiteral("ntkrnlmp.exe")
            || name == QStringLiteral("ntkrnlpa.exe") || name == QStringLiteral("ntkrpamp.exe")
            || name == QStringLiteral("ntkrla57.exe") || name == QStringLiteral("hal.dll")) out->kernelImages.insert(image.id);
    }
    std::array<std::map<std::tuple<std::uint64_t,std::uint64_t,std::uint64_t>, std::size_t>,3> rowByKey;
    std::array<std::vector<std::unordered_set<std::uint64_t>>,3> rowImages;
    for (const auto& group : out->trace->analysis.groups) {
        if (cancel.load(std::memory_order_relaxed)) return {};
        out->groups.emplace(group.groupId, &group);
        const auto* image = sourceImage(out->images, out->kernelImages, group);
        const std::array<std::uint64_t,8> counters{group.allocatedBytes,group.allocatedCount,group.pairedFreedBytes,group.pairedFreedCount,
            group.outstandingBytes,group.outstandingCount,group.uncertainBytes,group.uncertainCount};
        // Deduplicate each stack once, then reuse it across all three modes.
        std::unordered_set<std::uint64_t> imageIds(group.frameImageIds.begin(),group.frameImageIds.end());
        for (int mode=0;mode<3;++mode) {
            auto& rows=out->modes[mode];
            const auto key=mode==0 ? std::make_tuple(std::uint64_t(group.tag),std::uint64_t(group.poolType),std::uint64_t(group.sessionId))
                : mode==1 ? std::make_tuple(group.groupId,std::uint64_t{0},std::uint64_t{0})
                : std::make_tuple(image?image->id:std::uint64_t{0},std::uint64_t{0},std::uint64_t{0});
            auto found=rowByKey[mode].find(key);
            if (found==rowByKey[mode].end()) {
                PoolPreparedProjection::Row row;
                row.source=mode==0 ? tr("Tag %1 | pool %2 | %3").arg(tagText(group.tag),n(group.poolType),session(group.sessionId))
                    : mode==1 ? tr("Group %1 | tag %2 | pool %3 | %4 | %5").arg(n(group.groupId),tagText(group.tag),n(group.poolType),session(group.sessionId),imageName(image))
                    : tr("Historical stack source: %1 | image %2").arg(imageName(image),n(image?image->id:0));
                row.search=row.source+QChar(' ');
                found=rowByKey[mode].emplace(key,rows.size()).first;rows.push_back(std::move(row));rowImages[mode].emplace_back();
            }
            auto& row=rows[found->second];row.groups.push_back(&group);
            for(std::size_t column=0;column<counters.size();++column) {
                row.saturated[column]=row.saturated[column] || counters[column]>(std::numeric_limits<std::uint64_t>::max)()-row.counters[column];
                row.counters[column]=addSaturated(row.counters[column],counters[column]);
            }
            row.search+=tagText(group.tag)+QChar(' ')+session(group.sessionId)+QChar(' ');
            for(const auto id:imageIds) if(rowImages[mode][found->second].insert(id).second)
                if(const auto* frame=imageForId(out->images,id)) row.search+=QString::fromStdWString(frame->path)+QChar(' ');
        }
    }
    return out;
}
struct PoolViewRows {
    std::shared_ptr<const PoolPreparedProjection> source;
    int mode=0;
    std::vector<std::size_t> indices;
    int selected=-1, selectedStack=0;
};
std::shared_ptr<const PoolViewRows> filterPoolProjection(std::shared_ptr<const PoolPreparedProjection> source,
    int mode,const QString& filter,int column,Qt::SortOrder order,std::uint64_t selected,const std::atomic_bool& cancel) {
    auto out=std::make_shared<PoolViewRows>();out->source=std::move(source);out->mode=mode;
    const auto& rows=out->source->modes[mode];out->indices.reserve(rows.size());
    for(std::size_t i=0;i<rows.size();++i) {
        if(cancel.load(std::memory_order_relaxed)) return {};
        if(filter.isEmpty()||rows[i].search.contains(filter,Qt::CaseInsensitive))out->indices.push_back(i);
    }
    std::stable_sort(out->indices.begin(),out->indices.end(),[&](std::size_t a,std::size_t b) {
        const auto& x=rows[a];const auto& y=rows[b];
        const int compare=column==0 ? QString::compare(x.source,y.source,Qt::CaseSensitive)
            : x.counters[column-1]<y.counters[column-1] ? -1 : x.counters[column-1]>y.counters[column-1] ? 1 : 0;
        return order==Qt::AscendingOrder?compare<0:compare>0;
    });
    if(cancel.load(std::memory_order_relaxed))return {};
    if(selected) for(std::size_t i=0;i<out->indices.size();++i) {
        const auto& groups=rows[out->indices[i]].groups;
        for(std::size_t stack=0;stack<groups.size();++stack)if(groups[stack]->groupId==selected){out->selected=static_cast<int>(i);out->selectedStack=static_cast<int>(stack);}
    }
    if(out->selected<0&&!out->indices.empty())out->selected=0;
    return out;
}
}
class PoolAllocationTableModel final : public QAbstractTableModel {
public:
    explicit PoolAllocationTableModel(QObject* parent):QAbstractTableModel(parent){}
    std::shared_ptr<const PoolViewRows> view;
    std::function<void(int,Qt::SortOrder)> sortRequest;
    const PoolPreparedProjection::Row* row(int index)const {
        return view&&index>=0&&index<static_cast<int>(view->indices.size())?&view->source->modes[view->mode][view->indices[index]]:nullptr;
    }
    int rowCount(const QModelIndex& parent={})const override{return parent.isValid()||!view?0:static_cast<int>(view->indices.size());}
    int columnCount(const QModelIndex& parent={})const override{return parent.isValid()?0:9;}
    QVariant data(const QModelIndex& index,int role)const override {
        const auto* r=row(index.row());if(!index.isValid()||!r||index.column()<0||index.column()>=9)return {};
        if(role==filterRole)return r->search;
        if(role==sortRole||role==Qt::UserRole)return index.column()==0?QVariant(r->source):QVariant::fromValue(static_cast<qulonglong>(r->counters[index.column()-1]));
        if(role==Qt::DisplayRole||role==Qt::ToolTipRole) {
            if(index.column()==0)return r->source;const auto c=index.column()-1;
            if(role==Qt::ToolTipRole&&r->saturated[c])return L("Aggregated value exceeds the 64-bit range; the displayed value is a lower bound.");
            return (r->saturated[c]?QStringLiteral("\u2265"):QString())+N(r->counters[c]);
        }
        if(role==Qt::TextAlignmentRole&&index.column()!=0)return static_cast<int>(Qt::AlignRight|Qt::AlignVCenter);return {};
    }
    QVariant headerData(int section,Qt::Orientation orientation,int role)const override {
        if(orientation!=Qt::Horizontal||(role!=Qt::DisplayRole&&role!=Qt::ToolTipRole))return QAbstractTableModel::headerData(section,orientation,role);
        static const char* headers[]={"Allocation source","Observed bytes","Observed count","Paired release bytes","Paired release count","No observed free bytes","No observed free count","Uncertain bytes","Uncertain count"};
        return section>=0&&section<9?L(headers[section]):QVariant();
    }
    void sort(int column,Qt::SortOrder order)override{if(column>=0&&column<9&&sortRequest)sortRequest(column,order);}
    void replace(std::shared_ptr<const PoolViewRows> replacement){beginResetModel();auto old=std::move(view);view=std::move(replacement);endResetModel();retirePoolValue(std::move(old));}
    void retranslate(){emit headerDataChanged(Qt::Horizontal,0,8);}
};
class PoolStackListModel final : public QAbstractListModel {
public:
    explicit PoolStackListModel(QObject* parent):QAbstractListModel(parent){}
    std::shared_ptr<const PoolViewRows> owner;const PoolPreparedProjection::Row* row=nullptr;
    int rowCount(const QModelIndex& parent={})const override{return parent.isValid()||!row?0:static_cast<int>(row->groups.size());}
    const Group* group(int i)const{return row&&i>=0&&i<static_cast<int>(row->groups.size())?row->groups[i]:nullptr;}
    QVariant data(const QModelIndex& index,int role)const override {
        const auto* g=group(index.row());if(!index.isValid()||!g||!owner)return {};
        if(role==Qt::UserRole)return QVariant::fromValue(static_cast<qulonglong>(g->groupId));
        if(role==Qt::DisplayRole||role==Qt::ToolTipRole)return groupLabel(owner->source->images,owner->source->kernelImages,*g);return {};
    }
    void replace(std::shared_ptr<const PoolViewRows> replacement,const PoolPreparedProjection::Row* r) {
        beginResetModel();auto old=std::move(owner);owner=std::move(replacement);row=r;endResetModel();retirePoolValue(std::move(old));
    }
};
struct PoolAllocationAnalysisWidget::ReadJob {
    std::atomic_bool cancel{false},done{false};
    std::shared_ptr<const TraceReadResult> result;
};
struct PoolAllocationAnalysisWidget::ProjectionJob {
    std::atomic_bool cancel{false},done{false};bool failed=false;
    std::uint64_t version=0;std::shared_ptr<const TraceReadResult> trace;
    std::shared_ptr<const PoolViewRows> view;
};
struct PoolAllocationAnalysisWidget::ResolveJob {
    std::atomic_bool cancel{false}, done{false};
    std::uint64_t groupId = 0;
    std::shared_ptr<const TraceReadResult> trace;
    Group group;
    std::vector<std::wstring> symbols;
};
struct PoolAllocationAnalysisWidget::MetricAreaJob {
    std::atomic_bool cancel{false}, done{false};
    bool failed = false;
    int mode = 0;
    QStringList labels;
    QString state;
    std::shared_ptr<const PoolViewRows> view;
    std::vector<ks::ui::MetricAreaNode> nodes;
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
    auto* actions = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    m_open = new QPushButton(this); m_open->setObjectName(QStringLiteral("pool_analysis_open"));
    m_cancel = new QPushButton(this); m_cancel->setObjectName(QStringLiteral("pool_analysis_cancel"));
    actions->addWidget(m_open); actions->addWidget(m_cancel);
    m_areaButton = new QPushButton(this); actions->addWidget(m_areaButton);
    ks::ui::NormalizeToolbarControl(m_areaButton);
    connect(m_areaButton, &QPushButton::clicked, this, [this] { openMetricAreaView(); });
    // 换行工具行仅统一单个按钮，保持自动换行能力。
    ks::ui::NormalizeToolbarControl(m_open);
    ks::ui::NormalizeToolbarControl(m_cancel);
    layout->addLayout(actions);
    auto* filters = new QHBoxLayout;
    m_grouping = new QComboBox(this); m_grouping->setObjectName(QStringLiteral("pool_analysis_grouping"));
    m_grouping->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_grouping->setMinimumContentsLength(8); m_grouping->setMinimumWidth(0);
    m_grouping->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    m_grouping->addItems({QString(), QString(), QString()});
    ks::ui::StylePrimaryCombo(m_grouping);
    m_filter = new QLineEdit(this); m_filter->setObjectName(QStringLiteral("pool_analysis_filter")); m_filter->setMinimumWidth(0);
    ks::ui::StyleSearchField(m_filter);
    filters->addWidget(m_grouping, 2); filters->addWidget(m_filter, 3); layout->addLayout(filters);
    ks::ui::NormalizeToolbarRow(filters);
    m_status = new QLabel(this); m_status->setWordWrap(true); m_status->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_status->setObjectName(QStringLiteral("pool_analysis_status")); layout->addWidget(m_status);
    m_summary = new QLabel(this); m_summary->setWordWrap(true); m_summary->setObjectName(QStringLiteral("pool_analysis_summary"));
    layout->addWidget(m_summary);
    auto* split = new QSplitter(Qt::Vertical, this);
    m_table = new QTableView(split); m_table->setObjectName(QStringLiteral("pool_analysis_table"));
    // ETL 的静态聚合结果没有实时快照语义，仅保留紧凑复制/导出。
    ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::Compact);
    m_model = new PoolAllocationTableModel(this);
    m_table->setModel(m_model);
    connect(m_model, &QAbstractItemModel::modelReset, this, [this] { refreshMetricAreaView(); updateControls(); }, Qt::QueuedConnection);
    m_table->setProperty("ks_i18n_preserve_model_data",true);m_model->setProperty("ks_i18n_preserve_model_data",true);
    ks::ui::SetTableColumnAutoFitEnabled(m_table,false);
    ks::ui::SetTableRowFilterBusinessOwnership(m_table,ks::ui::TableRowFilterBusinessOwnership::ExclusiveSharedIdentity);
 m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::SingleSelection); m_table->setSortingEnabled(true);
    m_table->sortByColumn(5, Qt::DescendingOrder); m_table->setAlternatingRowColors(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers); m_table->verticalHeader()->hide();
    m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_table->horizontalHeader()->setDefaultSectionSize(145); m_table->setColumnWidth(0, 270);
    auto* detail = new QWidget(split); auto* detailLayout = new QVBoxLayout(detail);
    detailLayout->setContentsMargins(0, 0, 0, 0);
    m_stacks = new QComboBox(detail); m_stacks->setObjectName(QStringLiteral("pool_analysis_stacks"));
    m_stackModel = new PoolStackListModel(this); m_stacks->setModel(m_stackModel);m_stacks->setProperty("ks_i18n_preserve_model_data",true);m_stackModel->setProperty("ks_i18n_preserve_model_data",true);
    m_stacks->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_stacks->setMinimumContentsLength(10); m_stacks->setMinimumWidth(0); detailLayout->addWidget(m_stacks);
    m_stacks->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    ks::ui::StylePrimaryCombo(m_stacks);
    auto* detailActions = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    m_resolve = new QPushButton(detail); m_resolve->setObjectName(QStringLiteral("pool_analysis_resolve"));
    m_module = new QPushButton(detail); m_module->setObjectName(QStringLiteral("pool_analysis_module"));
    detailActions->addWidget(m_resolve); detailActions->addWidget(m_module); detailLayout->addLayout(detailActions);
    ks::ui::NormalizeToolbarControl(m_resolve);
    ks::ui::NormalizeToolbarControl(m_module);
    // ETL 导入和帧定位是实际动作，显式保留中性实底及热主题绑定。
    for (QPushButton* button : {m_open, m_cancel, m_resolve, m_module})
    {
        ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
    }
    m_frames = new ks::ui::StructuredFieldView(detail);
    m_frames->setObjectName(QStringLiteral("pool_analysis_frames"));
     detailLayout->addWidget(m_frames, 1); split->addWidget(m_table); split->addWidget(detail);
    split->setStretchFactor(0, 2); split->setStretchFactor(1, 1); layout->addWidget(split, 1);
    connect(m_open, &QPushButton::clicked, this, [this] {
        QPointer<PoolAllocationAnalysisWidget> guard(this);
        const auto path = QFileDialog::getOpenFileName(this, L("Open pool allocation ETL"), QString(), L("ETL files (*.etl)"));
        if (guard && !path.isEmpty()) guard->analyzeFile(path);
    });
    connect(m_cancel, &QPushButton::clicked, this, [this] { cancelJobs(); updateControls(); updateSummary(); });
    m_projectionDebounce = new QTimer(this); m_projectionDebounce->setSingleShot(true); m_projectionDebounce->setInterval(120);
    connect(m_projectionDebounce, &QTimer::timeout, this, [this] { pollJobs(); });
    m_model->sortRequest = [this](int column, Qt::SortOrder order) {
        if (m_sortColumn == column && m_sortOrder == order) return;
        m_sortColumn = column; m_sortOrder = order; requestProjection();
    };
    connect(m_grouping, &QComboBox::currentIndexChanged, this, [this] { requestProjection(); });
    connect(m_filter, &QLineEdit::textChanged, this, [this] { requestProjection(); });
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

PoolAllocationAnalysisWidget::~PoolAllocationAnalysisWidget() {
    cancelJobs();if(m_projectionJob)m_projectionJob->cancel.store(true,std::memory_order_relaxed);
    if (m_areaJob) m_areaJob->cancel.store(true);
    // QObject child teardown owns the models; destruction emits no reset/selection
    // signals. Drop their heavy value owners onto workers before deleting them.
    m_stackModel->row=nullptr;retirePoolValue(std::move(m_stackModel->owner));retirePoolValue(std::move(m_model->view));
    retirePoolValue(std::move(m_prepared));retirePoolValue(std::move(m_result));
    retirePoolValue(std::move(m_readJob));retirePoolValue(std::move(m_resolveJob));retirePoolValue(std::move(m_projectionJob));
}

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
    const QPointer<PoolAllocationAnalysisWidget> guard(this);clearProjection();if(!guard)return; m_path = path; m_symbols.clear(); m_symbolGroupId = 0;
    auto job = std::make_shared<ReadJob>(); m_readJob = job;
    const auto reader = m_reader; const auto file = path.toStdWString();
    // Worker owns only plain/shared data; it never accesses this or Qt widgets.
    try {
        std::thread([job, reader, file] {
            TraceReadResult result;
            try { result = reader(file, job->cancel); }
            catch (const std::bad_alloc&) { result.status = 8; }
            catch (...) { result.status = 31; }
            if (job->cancel.load(std::memory_order_relaxed)) { result.cancelled = true; result.analysis.cancelled = true; }
            try { job->result = std::make_shared<const TraceReadResult>(std::move(result)); } catch (...) {}
            job->done.store(true, std::memory_order_release);
        }).detach();
    } catch (...) { TraceReadResult result; result.status = 31; job->result = std::make_shared<const TraceReadResult>(std::move(result)); job->done.store(true, std::memory_order_release); }
    m_poll->start(); updateSummary(); updateControls();
}

void PoolAllocationAnalysisWidget::pollJobs() {
    if (m_areaJob && !m_areaWindow) m_areaJob->cancel.store(true);
    if (m_areaJob && m_areaJob->done.load()) {
        auto job = std::move(m_areaJob);
        if (m_areaWindow && !job->cancel.load() && m_model->view == job->view && m_areaWindow->currentMode() == job->mode) {
            if (!job->failed) {
                m_areaWindow->setPresentation(job->labels[job->mode], job->state, std::move(job->nodes));
                m_areaPresentedView = job->view; m_areaPresentedMode = job->mode; m_areaPresentedLabels = job->labels;
                const QPointer<PoolAllocationAnalysisWidget> owner(this);
                m_areaWindow->itemActivated = [owner, view = job->view](const QString& key) {
                    if (!owner || owner->m_model->view != view) return;
                    bool valid = false; const auto index = key.section(QLatin1Char('|'), -1).toULongLong(&valid);
                    if (!valid) return;
                    for (std::size_t row = 0; row < view->indices.size(); ++row)
                        if (view->indices[row] == index) { owner->m_table->selectRow(static_cast<int>(row)); break; }
                };
            } else m_areaWindow->updateState(L("Pool area projection failed; the previous chart is retained."));
        }
    }
    if (m_readJob && m_readJob->done.load(std::memory_order_acquire)) {
        auto job=std::move(m_readJob);
        if(!m_pendingPath.isEmpty()) {const auto path=m_pendingPath;m_pendingPath.clear();startRead(path);}
        else {m_result=std::move(job->result);if(!m_result){TraceReadResult failed;failed.status=8;m_result=std::make_shared<const TraceReadResult>(std::move(failed));}requestProjection(true);}
        retirePoolValue(std::move(job));
    }
    if(m_projectionJob&&m_projectionJob->done.load(std::memory_order_acquire)) {
        // Completed values can wait while hidden. Collection and cleanup never do.
        if(m_projectionJob->version!=m_projectionVersion||m_projectionJob->trace!=m_result)retirePoolValue(std::move(m_projectionJob));
        else if(isVisible()) {
            auto job=std::move(m_projectionJob);m_projectionFailed=job->failed;
            if(job->view) {
                const auto scroll=m_table->verticalScrollBar()->value();
                auto old=std::move(m_prepared);m_prepared=job->view->source;m_rebuildProjection=false;
                const QPointer<PoolAllocationAnalysisWidget> guard(this);
                QSignalBlocker tableBlocked(m_table->selectionModel());
                m_model->replace(job->view);if(!guard){tableBlocked.dismiss();return;}
                m_publishedVersion=job->version;m_table->setEnabled(true);
                if(job->view->selected>=0)m_table->selectRow(job->view->selected);
                selectRow();if(!guard){tableBlocked.dismiss();return;}
                m_table->verticalScrollBar()->setValue(scroll);retirePoolValue(std::move(old));
            } else {m_publishedVersion=job->version;m_table->setEnabled(true);}
            retirePoolValue(std::move(job));
        }
    }
    if(!m_projectionJob&&m_result&&m_publishedVersion!=m_projectionVersion&&isVisible()&&!m_projectionDebounce->isActive()) {
        auto job=std::make_shared<ProjectionJob>();job->version=m_projectionVersion;job->trace=m_result;m_projectionJob=job;
        const auto cached=m_rebuildProjection?std::shared_ptr<const PoolPreparedProjection>{}:m_prepared;
        const auto text=ks::i18n::LanguageManager::instance().sourceTextSnapshot();const QLocale locale;
        const auto mode=m_grouping->currentIndex();const auto filter=m_filter->text();const auto column=m_sortColumn;const auto order=m_sortOrder;
        const auto* selected=selectedGroup();const auto groupId=selected?selected->groupId:0;
        try {std::thread([job,cached,text,locale,mode,filter,column,order,groupId] {
            try {
                auto prepared=cached?cached:preparePoolProjection(job->trace,text,locale,job->cancel);
                if(prepared&&!job->cancel.load(std::memory_order_relaxed))job->view=filterPoolProjection(std::move(prepared),mode,filter,column,order,groupId,job->cancel);
            }catch(...){job->failed=true;}
            job->done.store(true,std::memory_order_release);
        }).detach();}catch(...){job->failed=true;job->done.store(true,std::memory_order_release);}
    }
    if(m_resolveJob&&m_resolveJob->done.load(std::memory_order_acquire)) {
        auto job=std::move(m_resolveJob);const auto* group=selectedGroup();
        if(!job->cancel.load(std::memory_order_relaxed)&&m_result==job->trace&&group&&group->groupId==job->groupId) {
            m_symbols=std::move(job->symbols);m_symbolGroupId=job->groupId;if(isVisible())showStack();
        }
        retirePoolValue(std::move(job));
    }
    if(!m_readJob&&!m_resolveJob&&(!m_projectionJob||m_projectionJob->done.load(std::memory_order_acquire))&&
        (!isVisible()||m_publishedVersion==m_projectionVersion) && !m_areaJob)m_poll->stop();
    updateControls();updateSummary();
}
void PoolAllocationAnalysisWidget::requestProjection(bool rebuild) {
    ++m_projectionVersion;m_rebuildProjection=m_rebuildProjection||rebuild;m_projectionFailed=false;
    if(!m_result)m_publishedVersion=m_projectionVersion;
    if(m_projectionJob)m_projectionJob->cancel.store(true,std::memory_order_relaxed);
    m_table->setEnabled(!m_result);m_stacks->setEnabled(!m_result);m_projectionDebounce->start();m_poll->start();
}
void PoolAllocationAnalysisWidget::rebuildRows(){requestProjection();}
void PoolAllocationAnalysisWidget::setResultForTesting(TraceReadResult result) {
    cancelJobs();retirePoolValue(std::move(m_readJob));retirePoolValue(std::move(m_resolveJob));
    const QPointer<PoolAllocationAnalysisWidget> guard(this);clearProjection();if(!guard)return;m_symbols.clear();m_symbolGroupId=0;m_result=std::make_shared<const TraceReadResult>(std::move(result));requestProjection(true);updateSummary();updateControls();
}
void PoolAllocationAnalysisWidget::clearStackModel() {
    const QPointer<PoolAllocationAnalysisWidget> guard(this);QSignalBlocker blocked(m_stacks);m_stackModel->replace({},nullptr);if(!guard)blocked.dismiss();
}
void PoolAllocationAnalysisWidget::clearProjection() {
    if (m_areaJob) m_areaJob->cancel.store(true);
    if (m_areaWindow) m_areaWindow->updateState(L("Pool history is loading; the previous committed area view is retained."));
    ++m_projectionVersion;m_publishedVersion=m_projectionVersion;
    if(m_projectionJob)m_projectionJob->cancel.store(true,std::memory_order_relaxed);
    const QPointer<PoolAllocationAnalysisWidget> guard(this);clearStackModel();if(!guard)return;
    m_model->replace({});if(!guard)return;retirePoolValue(std::move(m_prepared));retirePoolValue(std::move(m_result));
    m_modulePath.clear();m_frames->setDocument({});if(!guard)return;
    m_rebuildProjection=false;m_projectionFailed=false;m_table->setEnabled(true);
}
void PoolAllocationAnalysisWidget::selectRow() {
    const QPointer<PoolAllocationAnalysisWidget> guard(this);
    QSignalBlocker blocked(m_stacks);
    const auto selected=m_table->selectionModel()->selectedRows();
    const auto* row=selected.isEmpty()?nullptr:m_model->row(selected.front().row());
    m_stackModel->replace(m_model->view,row);if(!guard){blocked.dismiss();return;}
    if(row&&!row->groups.empty())m_stacks->setCurrentIndex(m_model->view->selected==selected.front().row()?m_model->view->selectedStack:0);
    selectStack();if(!guard)blocked.dismiss();
}
const Group* PoolAllocationAnalysisWidget::selectedGroup()const {
    return m_stackModel->group(m_stacks->currentIndex());
}
void PoolAllocationAnalysisWidget::selectStack() {
    if (m_resolveJob) m_resolveJob->cancel.store(true, std::memory_order_relaxed);
    m_symbols.clear(); m_symbolGroupId = 0; const QPointer<PoolAllocationAnalysisWidget> guard(this); showStack(); if(guard)updateControls();
}
void PoolAllocationAnalysisWidget::showStack() {
    m_modulePath.clear();
    const auto* group = selectedGroup();
    if (!group) { m_frames->setDocument({}); return; }
    ks::ui::FieldDocument lines;
    lines.section(groupLabel(m_prepared->images, m_prepared->kernelImages, *group));
    lines.field(QStringLiteral("Observed bytes / allocations"), QStringLiteral("%1 / %2").arg(N(group->allocatedBytes), N(group->allocatedCount)));
    lines.field(QStringLiteral("Paired release bytes / allocations"), QStringLiteral("%1 / %2").arg(N(group->pairedFreedBytes), N(group->pairedFreedCount)));
    lines.field(QStringLiteral("No observed free bytes / allocations"), QStringLiteral("%1 / %2").arg(N(group->outstandingBytes), N(group->outstandingCount)));
    lines.field(QStringLiteral("Uncertain bytes / allocations"), QStringLiteral("%1 / %2").arg(N(group->uncertainBytes), N(group->uncertainCount)));
    lines.field(QStringLiteral("Historical timestamp"), N(group->representativeTimestamp));
    lines.field(QStringLiteral("Event PID / TID"), QStringLiteral("%1 / %2").arg(N(group->representativePid), N(group->representativeTid)));
    if (group->stack.empty()) lines.note(L("No allocation stack was recorded for this group."));
    if (const auto* source = sourceImage(m_prepared->images, m_prepared->kernelImages, *group)) {
        const auto path = QString::fromStdWString(source->path);
        if (isLocalFixedPath(path)) {
            const QFileInfo file(path);
            if (file.isFile()) m_modulePath = file.absoluteFilePath();
        }
    }
    for (std::size_t frame = 0; frame < group->stack.size(); ++frame) {
        const auto address = group->stack[frame];
        const auto* image = frame < group->frameImageIds.size() ? imageForId(m_prepared->images, group->frameImageIds[frame]) : nullptr;
        QString origin = L("Unknown historical module");
        if (image && address >= image->base && address - image->base < image->size) {
            origin = L("%1 + %2 [image %3]").arg(QString::fromStdWString(image->path), H(address - image->base), N(image->id));
        }
        lines.section(QStringLiteral("#%1").arg(N(frame)));
        lines.field(QStringLiteral("Address"), H(address));
        lines.field(QStringLiteral("Historical module"), origin);
        if (m_symbolGroupId == group->groupId && frame < m_symbols.size() && !m_symbols[frame].empty())
            lines.field(QStringLiteral("Symbol"), QString::fromStdWString(m_symbols[frame]));
    }
    m_frames->setDocument(lines);
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
    const bool busy = m_readJob || m_resolveJob || m_publishedVersion != m_projectionVersion;
    m_open->setEnabled(!m_readJob);
    m_cancel->setEnabled(m_readJob || m_resolveJob);
    m_resolve->setEnabled(!busy && selectedGroup() && !selectedGroup()->stack.empty());
    m_module->setEnabled(!m_readJob && m_openModuleDetails && !m_modulePath.isEmpty());
    m_module->setToolTip(m_modulePath.isEmpty() ? L("No reliable local module path is available.") : m_modulePath);
    m_stacks->setEnabled(m_stacks->count() > 0 && m_publishedVersion == m_projectionVersion);
    m_areaButton->setEnabled(bool(m_model->view));
}
void PoolAllocationAnalysisWidget::updateSummary() {
    if (m_projectionFailed) m_status->setText(L("Pool table projection failed."));
    else if (m_readJob) m_status->setText(m_readJob->cancel.load() ? L("Cancelling pool trace analysis...") : L("Analyzing pool trace: %1").arg(m_path));
    else if (m_resolveJob) m_status->setText(m_resolveJob->cancel.load() ? L("Cancelling local symbol lookup...") : L("Resolving the selected stack with local symbols only..."));
    else if (m_result && m_publishedVersion != m_projectionVersion) m_status->setText(L("Updating pool allocation table..."));
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
    m_areaButton->setText(ks::i18n::sourceText(QStringLiteral("矩形面积视图")));
    m_note->setText(L("Analyze only events retained in this ETL. Allocations before capture or overwritten by circular buffers are unknown. Unpaired allocations do not prove a leak. Historical modules show stack origins, not responsibility."));
    m_open->setText(L("Open ETL")); m_cancel->setText(L("Cancel analysis"));
    { const QSignalBlocker blocked(m_grouping);
      m_grouping->setItemText(0, L("By pool tag")); m_grouping->setItemText(1, L("By complete stack")); m_grouping->setItemText(2, L("By historical stack module")); }
    m_grouping->setToolTip(L("Module grouping uses the first mapped stack module outside ntoskrnl and HAL, falling back to the kernel image or unknown. Every underlying stack remains available below."));
    m_filter->setPlaceholderText(L("Filter tag or historical module"));
    m_resolve->setText(L("Resolve local symbols")); m_module->setText(L("Open module details"));
    m_model->retranslate(); requestProjection(true); updateSummary(); updateControls();
}
void PoolAllocationAnalysisWidget::openMetricAreaView()
{
    if (!m_model->view) return;
    if (!m_areaWindow) {
        auto* window = new ks::ui::MetricAreaWindow(this); m_areaWindow = window;
        m_areaPresentedView.reset(); m_areaPresentedMode = -1; m_areaPresentedLabels.clear();
        window->modeChanged = [this](int) { refreshMetricAreaView(); };
        window->appearanceChanged = [this] { refreshMetricAreaView(); };
    }
    refreshMetricAreaView(); m_areaWindow->show(); m_areaWindow->raise(); m_areaWindow->activateWindow();
}
void PoolAllocationAnalysisWidget::refreshMetricAreaView()
{
    if (!m_areaWindow || !m_model->view) return;
    const auto view = m_model->view;
    const std::array<int, 8> columns{5, 1, 2, 3, 4, 6, 7, 8};
    QStringList labels; for (int column : columns) labels.append(m_model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString());
    const int mode = qBound(0, m_areaWindow->currentMode(), 7);
    m_areaWindow->setModes(labels, mode);
    m_areaWindow->setSubject(L("Current pool history table"), L("Allocation source"), QString(),
        L("One metric from the filtered ETL history is shown at a time. Counts and bytes are separate; neither is unique resident physical ownership."));
    if (!m_areaJob && m_areaPresentedView.lock().get() == view.get() && m_areaPresentedMode == mode && m_areaPresentedLabels == labels) return;
    if (m_areaJob && m_areaJob->view == view && m_areaJob->mode == mode && m_areaJob->labels == labels) return;
    if (m_areaJob) m_areaJob->cancel.store(true);
    auto job = std::make_shared<MetricAreaJob>(); job->view = view; job->mode = mode; job->labels = labels;
    job->state = m_status->text() + QLatin1Char('\n') + L("Areas are observed history, not proof of a leak. Saturated lower-bound values are listed without an area.");
    m_areaJob = job; m_poll->start();
    const QLocale locale;
    try { std::thread([job, column = columns[mode], locale] {
        try {
            const auto& rows = job->view->source->modes[job->view->mode];
            job->nodes.reserve(job->view->indices.size());
            const QString prefix = QString::number(reinterpret_cast<quintptr>(job->view->source->trace.get()))
                + QLatin1Char('|') + QString::number(job->view->mode) + QLatin1Char('|');
            for (const auto index : job->view->indices) {
                if (job->cancel.load()) break;
                const auto& row = rows[index]; const auto counter = static_cast<std::size_t>(column - 1);
                ks::ui::MetricAreaNode node;
                node.key = prefix + QString::number(index); node.name = row.source;
                node.known = !row.saturated[counter]; node.weight = static_cast<double>(row.counters[counter]);
                node.value = (row.saturated[counter] ? QStringLiteral("\u2265") : QString()) + locale.toString(static_cast<qulonglong>(row.counters[counter]));
                node.tooltip = row.search + QLatin1Char('\n') + job->labels[job->mode] + QStringLiteral(": ") + node.value;
                job->nodes.push_back(std::move(node));
            }
        } catch (...) { job->failed = true; }
        job->done.store(true);
    }).detach(); } catch (...) { job->failed = true; job->done.store(true); }
}
void PoolAllocationAnalysisWidget::changeEvent(QEvent* event) {
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange) retranslate();
}

void PoolAllocationAnalysisWidget::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    m_poll->start(); pollJobs();
    if (m_publishedVersion == m_projectionVersion) showStack();
}
