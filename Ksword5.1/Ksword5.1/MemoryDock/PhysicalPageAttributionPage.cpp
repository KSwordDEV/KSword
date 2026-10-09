#include "PhysicalPageAttributionPage.h"
#include "../UI/CodeEditorWidget.h"
#include "MemoryAttributionChart.h"
#include "MemoryConsumerEvidencePage.h"
#include "PhysicalPageConsumers.h"
#include "../ArkDriverClient/ArkDriverPfn.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AdaptivePageScroll.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"
#include <QDateTime>
#include <QCheckBox>
#include <QCryptographicHash>
#include <QEvent>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSpinBox>
#include <QSplitter>
#include <QTabWidget>
#include <QTimer>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>
#include <array>
#include <thread>

namespace {
using namespace ksword::pfn;
QString L(const char* text) { return ks::i18n::packedSourceText(QString::fromUtf8(text)); }
constexpr std::array<const char*, useCount> useNames{
    "Process private", "Mapped file / cache", "Shareable / pagefile section", "Page tables",
    "Paged pool", "Nonpaged pool", "System PTE", "Session private", "Metafile",
    "AWE", "Driver locked / MDL", "Kernel stacks", "Image pages", "Compression process private", "Free / zeroed (no owner)", "True unknown"
};
constexpr std::array<const char*, 8> stateNames{
    "Zeroed", "Free", "Standby", "Modified", "Modified no-write", "Bad", "Active", "Transition"
};
QString bytes(std::uint64_t amount)
{
    if (amount >= (1ULL << 30)) { return QStringLiteral("%1 GiB").arg(static_cast<double>(amount) / (1ULL << 30), 0, 'f', 2); }
    return QStringLiteral("%1 MiB").arg(static_cast<double>(amount) / (1ULL << 20), 0, 'f', 2);
}
QString hex(std::uint64_t value) { return QStringLiteral("0x%1").arg(value, 0, 16); }
QString status(long value) { return QStringLiteral("0x%1").arg(static_cast<quint32>(value), 8, 16, QLatin1Char('0')); }
template<class Values> QJsonArray proofValues(const Values& values)
{
    QJsonArray result; for (const auto value : values) { result.append(hex(value)); } return result;
}
QJsonObject witnessJson(const MappingWitnessProof& proof)
{
    return {{QStringLiteral("mappingStatus"), status(proof.mappingStatus)}, {QStringLiteral("entryStatus"), status(proof.entryStatus)},
        {QStringLiteral("nativeStatus"), status(proof.nativeStatus)}, {QStringLiteral("pfn"), hex(proof.pfn)},
        {QStringLiteral("nativeFrame"), hex(proof.nativeFrame)}, {QStringLiteral("nativeBacking"), hex(proof.nativeBacking)},
        {QStringLiteral("pageSize"), static_cast<qint64>(proof.pageSize)}, {QStringLiteral("regionKind"), static_cast<qint64>(proof.regionKind)},
        {QStringLiteral("allocationBase"), hex(proof.allocationBase)}, {QStringLiteral("regionBase"), hex(proof.regionBase)},
        {QStringLiteral("regionSize"), QString::number(proof.regionSize)}, {QStringLiteral("nativeQueried"), proof.nativeQueried},
        {QStringLiteral("regionQueried"), proof.regionQueried}};
}
QJsonObject objectQueryJson(const ObjectQueryProof& proof)
{
    return {{QStringLiteral("provider"), static_cast<int>(proof.provider)}, {QStringLiteral("transportOk"), proof.transportOk},
        {QStringLiteral("matchingView"), proof.matchingView}, {QStringLiteral("ioStatus"), status(proof.ioStatus)},
        {QStringLiteral("lastStatus"), status(proof.lastStatus)}, {QStringLiteral("version"), static_cast<qint64>(proof.version)},
        {QStringLiteral("queryFlags"), static_cast<qint64>(proof.queryFlags)}, {QStringLiteral("queryStatus"), static_cast<qint64>(proof.queryStatus)},
        {QStringLiteral("fieldFlags"), static_cast<qint64>(proof.fieldFlags)}, {QStringLiteral("queryPid"), static_cast<qint64>(proof.queryPid)},
        {QStringLiteral("capabilityMask"), hex(proof.capabilityMask)}, {QStringLiteral("sectionObject"), hex(proof.sectionObject)},
        {QStringLiteral("controlArea"), hex(proof.controlArea)}, {QStringLiteral("viewPid"), static_cast<qint64>(proof.viewPid)},
        {QStringLiteral("viewType"), static_cast<qint64>(proof.viewType)}, {QStringLiteral("viewKind"), static_cast<qint64>(proof.viewKind)},
        {QStringLiteral("viewStart"), hex(proof.viewStart)}, {QStringLiteral("viewEnd"), hex(proof.viewEnd)},
        {QStringLiteral("viewControlArea"), hex(proof.viewControlArea)}, {QStringLiteral("offsets"), proofValues(proof.offsets)}};
}
QJsonObject objectEvidenceJson(const std::shared_ptr<const ObjectEvidence>& proof)
{
    if (!proof) { return {{QStringLiteral("available"), false}}; }
    return {{QStringLiteral("available"), true}, {QStringLiteral("before"), objectQueryJson(proof->before)},
        {QStringLiteral("after"), objectQueryJson(proof->after)}, {QStringLiteral("witnessBefore"), witnessJson(proof->witnessBefore)},
        {QStringLiteral("witnessAfter"), witnessJson(proof->witnessAfter)}};
}
QJsonObject translationJson(const TranslationProof& proof)
{
    return {{QStringLiteral("transportOk"), proof.transportOk}, {QStringLiteral("resolved"), proof.resolved},
        {QStringLiteral("ioStatus"), status(proof.ioStatus)}, {QStringLiteral("lookupStatus"), status(proof.lookupStatus)},
        {QStringLiteral("walkStatus"), status(proof.walkStatus)}, {QStringLiteral("version"), static_cast<qint64>(proof.version)},
        {QStringLiteral("queryStatus"), static_cast<qint64>(proof.queryStatus)}, {QStringLiteral("fieldFlags"), static_cast<qint64>(proof.fieldFlags)},
        {QStringLiteral("cr3"), hex(proof.cr3)}, {QStringLiteral("physicalAddress"), hex(proof.physicalAddress)},
        {QStringLiteral("entries"), proofValues(proof.entries)}};
}
QJsonObject stackJson(const StackProof& proof)
{
    return {{QStringLiteral("transportOk"), proof.transportOk}, {QStringLiteral("ioStatus"), status(proof.ioStatus)},
        {QStringLiteral("lastStatus"), status(proof.lastStatus)}, {QStringLiteral("version"), static_cast<qint64>(proof.version)},
        {QStringLiteral("fieldFlags"), static_cast<qint64>(proof.fieldFlags)}, {QStringLiteral("threadObject"), hex(proof.threadObject)},
        {QStringLiteral("processObject"), hex(proof.processObject)}, {QStringLiteral("cidThread"), hex(proof.cidThread)},
        {QStringLiteral("cidProcess"), hex(proof.cidProcess)}, {QStringLiteral("limit"), hex(proof.limit)}, {QStringLiteral("base"), hex(proof.base)},
        {QStringLiteral("sources"), proofValues(proof.sources)}, {QStringLiteral("offsets"), proofValues(proof.offsets)}};
}
QJsonObject poolJson(const PoolProof& proof)
{
    return {{QStringLiteral("matchingAllocation"), proof.matchingAllocation}, {QStringLiteral("addressAndFlags"), hex(proof.addressAndFlags)},
        {QStringLiteral("bytes"), QString::number(proof.bytes)}, {QStringLiteral("tag"), static_cast<qint64>(proof.tag)}};
}
QString backingProof(const ksword::pfn::Backing& backing)
{
    if (!backing.regionInformationKnown) { return L("Backing type unverified"); }
    if (backing.mappedPageFile) { return L("Pagefile backing explicitly observed"); }
    if (backing.mappedImage) { return L("Image backing explicitly observed"); }
    if (backing.mappedDataFile) { return L("Data-file backing explicitly observed"); }
    if (backing.mappedPhysical) { return L("Physical mapping explicitly observed"); }
    return L("Observed allocation; Section identity unresolved");
}
QString objectProof(const ksword::pfn::Backing& backing)
{
    using Source = ksword::pfn::MappingObjectSource;
    if (backing.objectSource == Source::ObservedAllocation) { return L("Observed allocation; Section identity unresolved"); }
    return L("Section %1 | ControlArea %2 | creator unavailable").arg(hex(backing.sectionObject), hex(backing.controlArea));
}
QTableWidget* table(QWidget* parent)
{
    auto* value = new ks::ui::VisibleTableWidget(parent);
    value->setEditTriggers(QAbstractItemView::NoEditTriggers);
    value->setSelectionBehavior(QAbstractItemView::SelectRows);
    value->setSelectionMode(QAbstractItemView::SingleSelection);
    value->verticalHeader()->hide();
    value->horizontalHeader()->setStretchLastSection(true);
    value->setAlternatingRowColors(true);
    return value;
}
void headers(QTableWidget* table, const QStringList& labels)
{
    table->setColumnCount(static_cast<int>(labels.size()));
    table->setHorizontalHeaderLabels(labels);
}
void number(QTableWidget* table, int row, int column, std::uint64_t value, bool memory = true)
{
    auto* item = new ks::ui::NumericTableItem(memory ? bytes(value) : QString::number(value), static_cast<qulonglong>(value));
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    table->setItem(row, column, item);
}
}

struct PhysicalPageAttributionPage::Inspection {
    std::atomic_bool done{false};
    long status = 0;
    std::uint64_t pfn = 0;
    ksword::pfn::Identity identity;
    QString sampledAt;
    ksword::pfn::Use use = ksword::pfn::Use::Unknown;
    long ownerStatus = 0;
    bool ownerResolved = false;
    bool ownerHintObserved = false;
    QString ownerName;
    std::uint32_t ownerPid = 0;
};

struct PhysicalPageAttributionPage::ExportJob {
    std::atomic_bool cancel{false}, done{false};
    std::atomic<std::uint64_t> rows{0};
    QString path, error;
    bool saved = false;
};

PhysicalPageAttributionPage::PhysicalPageAttributionPage(QWidget* parent) : QWidget(parent)
{
    // 页面自带内部滚动壳：固定高度的归因图加四页签表格约五百像素，嵌在系统内存审计页里
    // 放不下时在本页内滚动，不再把外层的审计页撑高。根布局建在壳的内容容器上。
    auto* root = new QVBoxLayout(ks::ui::EnablePageInnerScroll(this));
    root->setContentsMargins(0, 0, 0, 0);
    auto* actions = new QHBoxLayout;
    m_scanButton = new QPushButton(this);
    m_cancelButton = new QPushButton(this);
    m_mappingButton = new QPushButton(this);
    m_exportButton = new QPushButton(this);
    m_retainRaw = new QCheckBox(this);
    m_exportMappings = new QCheckBox(this); m_exportMappings->setChecked(true);
    m_budget = new QSpinBox(this);
    m_budget->setRange(15, 600);
    m_budget->setValue(90);
    m_filter = new QLineEdit(this);
    m_filter->setClearButtonEnabled(true);
    actions->addWidget(m_scanButton);
    actions->addWidget(m_cancelButton);
    actions->addWidget(m_mappingButton);
    actions->addWidget(m_retainRaw);
    actions->addWidget(m_budget);
    actions->addStretch();
    root->addLayout(actions);
    auto* filters = new QHBoxLayout;
    filters->addWidget(m_filter, 1);
    filters->addWidget(m_exportButton);
    filters->addWidget(m_exportMappings);
    root->addLayout(filters);
    m_summary = new QLabel(this);
    m_summary->setWordWrap(true);
    m_summary->setTextInteractionFlags(Qt::TextSelectableByMouse);
    root->addWidget(m_summary);
    m_progress = new QProgressBar(this);
    m_progress->setRange(0, 1000);
    m_progress->setTextVisible(false);
    m_progress->setMaximumHeight(5);
    root->addWidget(m_progress);
    m_chart = new MemoryAttributionChart(this);
    root->addWidget(m_chart);
    m_tabs = new QTabWidget(this);
    m_categories = table(m_tabs);
    m_categories->horizontalHeader()->setSortIndicator(2, Qt::DescendingOrder);
    m_groups = table(m_tabs);
    m_tabs->addTab(m_categories, {});
    m_tabs->addTab(m_groups, {});
    auto* pages = new QWidget(m_tabs);
    auto* pageLayout = new QVBoxLayout(pages);
    pageLayout->setContentsMargins(0, 0, 0, 0);
    auto* lookup = new QHBoxLayout;
    m_pfn = new QLineEdit(pages);
    m_inspectButton = new QPushButton(pages);
    lookup->addWidget(m_pfn, 1);
    lookup->addWidget(m_inspectButton);
    pageLayout->addLayout(lookup);
    auto* pageSplit = new QSplitter(Qt::Horizontal, pages);
    m_examples = table(pageSplit);
    m_mappings = table(pageSplit);
    pageSplit->addWidget(m_examples);
    pageSplit->addWidget(m_mappings);
    pageSplit->setStretchFactor(1, 2);
    pageLayout->addWidget(pageSplit, 1);
    m_pageEvidence = new CodeEditorWidget(pages);
    m_pageEvidence->setReadOnly(true);
    m_pageEvidence->setMinimumHeight(120);
    m_pageEvidence->setMaximumHeight(180);
    pageLayout->addWidget(m_pageEvidence);
    m_tabs->addTab(pages, {});
    m_evidence = new CodeEditorWidget(m_tabs);
    m_evidence->setReadOnly(true);
    m_tabs->addTab(m_evidence, {});
    m_ownerCoverage = table(m_tabs); m_tabs->addTab(m_ownerCoverage, {});
    m_objects = table(m_tabs); m_tabs->addTab(m_objects, {});
    m_pageConsumers = table(m_tabs); m_tabs->addTab(m_pageConsumers, {});
    m_consumerPage = new MemoryConsumerEvidencePage(m_tabs); m_tabs->addTab(m_consumerPage, {});
    m_consumerPage->openModuleDetails = [this](const QString& path) {
        const auto handler = openModuleDetails;
        if (handler) { handler(path); }
    };
    root->addWidget(m_tabs, 1);
    connect(m_scanButton, &QPushButton::clicked, this, [this] { startScan(); });
    connect(m_cancelButton, &QPushButton::clicked, this, [this] {
        if (m_job) { m_job->cancel.store(true); }
        if (m_mappingJob) { m_mappingJob->cancel.store(true); }
        if (m_exportJob) { m_exportJob->cancel.store(true); }
    });
    connect(m_mappingButton, &QPushButton::clicked, this, [this] { startMappings(); });
    connect(m_inspectButton, &QPushButton::clicked, this, [this] { inspectPfn(); });
    connect(m_pfn, &QLineEdit::returnPressed, this, [this] { inspectPfn(); });
    connect(m_exportButton, &QPushButton::clicked, this, [this] { exportEvidence(); });
    connect(m_filter, &QLineEdit::textChanged, this, [this] { rebuildGroups(); });
    connect(m_categories, &QTableWidget::cellClicked, this, [this](int row, int) {
        if (const auto* item = m_categories->item(row, 0)) { selectCategory(item->data(Qt::UserRole).toInt()); }
    });
    connect(m_groups, &QTableWidget::cellDoubleClicked, this, [this](int row, int) {
        const auto* item = m_groups->item(row, 0);
        if (!item) { return; }
        m_pfn->setText(hex(item->data(Qt::UserRole).toULongLong()));
        m_tabs->setCurrentIndex(2);
        inspectPfn();
    });
    connect(m_examples, &QTableWidget::cellClicked, this, [this](int row, int) {
        const auto* item = m_examples->item(row, 0);
        if (!item) { return; }
        m_pfn->setText(item->text());
        inspectPfn();
    });
    m_chart->selected = [this](int key) {
        if (key >= 0 && key < static_cast<int>(useCount)) { selectCategory(key); m_tabs->setCurrentIndex(2); }
        else { m_tabs->setCurrentIndex(key == 17 ? 0 : 3); }
    };
    auto* timer = new QTimer(this);
    timer->setInterval(150);
    connect(timer, &QTimer::timeout, this, [this] { poll(); });
    timer->start();
    retranslate();
    rebuild();
}

PhysicalPageAttributionPage::~PhysicalPageAttributionPage()
{
    if (m_job) { m_job->cancel.store(true); }
    if (m_mappingJob) { m_mappingJob->cancel.store(true); }
    if (m_exportJob) { m_exportJob->cancel.store(true); }
}

void PhysicalPageAttributionPage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange && m_scanButton) { retranslate(); rebuild(); }
}

void PhysicalPageAttributionPage::retranslate()
{
    m_scanButton->setText(L("Scan physical pages"));
    m_cancelButton->setText(L("Cancel scan"));
    m_mappingButton->setText(L("Resolve PFN mappings"));
    m_mappingButton->setToolTip(L("Optional, slower R0 scan of accessible process working sets. Resolves file paths, observed sharing, large pages and locked pages without adding references to physical totals."));
    m_budget->setSuffix(L(" s"));
    m_budget->setToolTip(L("Time budget for mapping resolution; at most two million mapping references are retained."));
    m_exportButton->setText(L("Export PFN evidence"));
    m_retainRaw->setText(L("Retain raw PFN identities"));
    m_retainRaw->setToolTip(L("Optional bounded-memory JSONL capture of every queried PFN and source status. It writes disk evidence and records observer overhead; disabled scans cannot later export identities that were not retained."));
    m_exportMappings->setText(L("Export all retained mappings"));
    m_filter->setPlaceholderText(L("Filter backing identity, process or PID"));
    m_pfn->setPlaceholderText(L("PFN number, decimal or 0x hexadecimal (not a byte address)"));
    m_inspectButton->setText(L("Inspect PFN"));
    m_tabs->setTabText(0, L("Usage by page state"));
    m_tabs->setTabText(1, L("Largest backing identities"));
    m_tabs->setTabText(2, L("PFN and mappings"));
    m_tabs->setTabText(3, L("Coverage and evidence"));
    m_tabs->setTabText(4, L("Consumer coverage"));
    m_tabs->setTabText(5, L("Objects and observed consumers"));
    m_tabs->setTabText(6, L("Page-table, stack and pool consumers"));
    m_tabs->setTabText(7, L("GPU and allocation history"));
    headers(m_ownerCoverage, {L("Primary classification"), L("Observed bytes"), L("Consumer resolved"), L("Consumer unresolved"), L("Not applicable"), L("Object key observed")});
    headers(m_objects, {L("Process"), L("PID"), L("Allocation base"), L("Backing file"), L("Backing proof"), L("Object evidence"), L("Status")});
    headers(m_pageConsumers, {L("Consumer kind"), L("PFN"), L("PID"), L("TID"), L("Virtual address witness"), L("Allocation / object evidence"), L("Validation boundary")});
    QStringList categoryHeaders{L("Primary classification"), L("In-use pages"), L("Unique bytes")};
    for (const char* name : stateNames) { categoryHeaders << L(name); }
    headers(m_categories, categoryHeaders);
    headers(m_groups, {L("Primary classification"), L("Backing / owner evidence"), L("PID"), L("Unique bytes"), L("Active"), L("First PFN")});
    headers(m_examples, {L("PFN sample"), L("Physical state"), L("Physical address")});
    headers(m_mappings, {L("PID"), L("Virtual address"), L("Process"), L("Backing file"), L("Page size"), L("Locked"), L("Windows share count (capped)"), L("Backing proof"), L("Object evidence"), L("Native backing evidence")});
}

QString PhysicalPageAttributionPage::classificationName(ksword::pfn::Use use)
{
    const auto index = static_cast<std::size_t>(use);
    return index < useNames.size() ? L(useNames[index]) : L("True unknown");
}

void PhysicalPageAttributionPage::focusCategory(int use)
{
    if (use < 0 || use >= static_cast<int>(ksword::pfn::useCount)) { return; }
    selectCategory(use);
    m_tabs->setCurrentIndex(2);
}

void PhysicalPageAttributionPage::startScan()
{
    if (m_job || m_mappingJob || m_exportJob) { return; }
    QString rawEvidencePath;
    if (m_retainRaw->isChecked()) {
        const QPointer<PhysicalPageAttributionPage> page(this);
        const QString path = QFileDialog::getSaveFileName(this, L("Retain raw PFN evidence"), QStringLiteral("pfn-raw.jsonl"), L("JSONL files (*.jsonl)"));
        if (page.isNull()) { return; }
        if (path.isEmpty()) { return; }
        rawEvidencePath = path;
    }
    if (m_job || m_mappingJob || m_exportJob) { return; }
    m_job = std::make_shared<ScanJob>();
    m_job->rawEvidencePath = rawEvidencePath;
    // Workers own only shared state; page destruction never invalidates a callback.
    const auto job = m_job;
    try { std::thread([job] { collectPhysicalPages(job); }).detach(); }
    catch (...) { m_job.reset(); m_summary->setText(L("Unable to start the scan worker.")); return; }
    poll();
}

void PhysicalPageAttributionPage::startMappings()
{
    if (m_job || m_mappingJob || m_exportJob) { return; }
    m_mappingJob = std::make_shared<MappingJob>();
    if (m_scan) { m_mappingJob->ledgerContextEpoch = m_scan->epoch; }
    const auto job = m_mappingJob;
    const auto seconds = static_cast<unsigned>(m_budget->value());
    try { std::thread([job, seconds] { collectPhysicalMappings(job, seconds); }).detach(); }
    catch (...) { m_mappingJob.reset(); m_summary->setText(L("Unable to start the scan worker.")); return; }
    poll();
}

void PhysicalPageAttributionPage::poll()
{
    if (m_job && m_job->done.load()) {
        { std::lock_guard<std::mutex> lock(m_job->mutex); m_lastAttempt = m_job->result; }
        m_job.reset();
        m_latestAttemptFailed = !m_lastAttempt || !m_lastAttempt->accounting.expected ||
            m_lastAttempt->resourceFailure || !m_lastAttempt->accounting.valid || !m_lastAttempt->accounting.reconciles();
        if (!m_latestAttemptFailed || !m_scan) {
            m_scan = m_lastAttempt;
            m_mappingScan.reset();
        }
        if (m_lastAttempt) {
            m_auditHistory.push_back(m_lastAttempt->auditSample);
            if (m_auditHistory.size() > 3) { m_auditHistory.erase(m_auditHistory.begin()); }
        } else { m_auditHistory.clear(); }
        const auto callback = snapshotReady;
        const auto snapshot = m_lastAttempt;
        const QPointer<PhysicalPageAttributionPage> guardedPage(this);
        if (callback) { callback(snapshot); }
        if (!guardedPage) { return; }
        rebuild();
    }
    if (m_mappingJob && m_mappingJob->done.load()) {
        { std::lock_guard<std::mutex> lock(m_mappingJob->mutex); m_mappingScan = m_mappingJob->result; }
        m_mappingJob.reset();
        rebuild();
        bool ok = false;
        const auto pfn = m_pfn->text().toULongLong(&ok, 0);
        if (ok) { showMappings(pfn); }
    }
    if (m_exportJob && m_exportJob->done.load()) {
        const auto result = std::move(m_exportJob);
        m_summary->setText(result->saved ? L("PFN evidence saved: %1").arg(result->path) : L("Evidence export failed: %1").arg(ks::i18n::packedSourceText(result->error)));
    }
    const bool busy = m_job || m_mappingJob || m_exportJob;
    m_scanButton->setEnabled(!busy);
    m_mappingButton->setEnabled(!busy && m_scan && m_scan->accounting.valid != 0);
    m_cancelButton->setEnabled(busy);
    m_exportButton->setEnabled(m_scan != nullptr && !busy);
    m_retainRaw->setEnabled(!busy); m_exportMappings->setEnabled(!busy);
    if (m_job) {
        const auto total = m_job->total.load();
        const auto visited = m_job->visited.load();
        m_summary->setText(L("Scanning PFNs: %1 / %2. Previous results remain a separate snapshot.").arg(bytes(visited * pageBytes), bytes(total * pageBytes)));
        m_progress->setValue(total ? static_cast<int>(visited * 1000 / total) : 0);
    } else if (m_mappingJob) {
        m_summary->setText(L("Resolving mappings: %1 resident references checked. Physical totals are unchanged.").arg(m_mappingJob->tested.load()));
    } else if (m_exportJob) {
        m_summary->setText(L("Exporting retained evidence: %1 mapping rows. Physical totals are unchanged.").arg(m_exportJob->rows.load()));
    }
    if (m_inspection && m_inspection->done.load()) {
        const auto result = std::move(m_inspection);
        m_inspectButton->setEnabled(true);
        if (result->status < 0 || result->identity.frame == ~0ULL) {
            m_pageEvidence->setReportText(L("PFN query unavailable: %1").arg(status(result->status)));
        } else {
            const auto use = result->use;
            QString description = L("PFN %1 | physical %2 | %3 | %4\nOwner key %5 | backing / VA %6 | sampled %7")
                .arg(hex(result->pfn), hex(result->pfn * pageBytes), L(useNames[static_cast<std::size_t>(use)]),
                    L(stateNames[state(result->identity)]),
                    nativeUse(result->identity) == 0 && state(result->identity) >= 2 && processKey(result->identity)
                        ? hex(processKey(result->identity)) : L("Unavailable"),
                    hex(result->identity.backing), result->sampledAt);
            description += L("\nMapping observations were collected separately and can change while the system runs. A Windows share count is capped and is not the complete list of owners.");
            if (nativeUse(result->identity) == 0 && inUseState(state(result->identity))) {
                description += L("\nFresh source hint status %1 | hint observed %2 | candidate %3 | process lifetime unverified")
                    .arg(status(result->ownerStatus), result->ownerHintObserved ? L("Yes") : L("No"), result->ownerHintObserved ? result->ownerName : L("Unresolved"));
            }
            if (nativeUse(result->identity) == 0 && inUseState(state(result->identity)) && !result->ownerHintObserved) {
                description += L("\nPrivate-source identity could not be validated during this inspection.");
            }
            m_pageEvidence->setReportText(description);
        }
        showMappings(result->pfn);
    }
}

void PhysicalPageAttributionPage::rebuild()
{
    if (!m_scan) {
        m_summary->setText(m_latestAttemptFailed ? L("Collection failed because a worker could not retain its result.")
            : L("Run a PFN scan to replace the snapshot remainder with physical-page evidence. No scan has completed yet."));
        m_chart->setSegments({}, L("Physical page attribution"));
        return;
    }
    const auto& scan = *m_scan;
    const auto& counts = scan.accounting;
    const auto unknown = counts.inUse(Use::Unknown);
    std::uint64_t known = 0;
    std::vector<MemoryAttributionChart::Segment> segments;
    for (std::size_t i = 0; i < useCount; ++i) {
        const auto amount = counts.inUse(static_cast<Use>(i));
        if (i != static_cast<std::size_t>(Use::Unknown)) { known += amount; }
        if (amount) { segments.push_back({L(useNames[i]), amount * pageBytes, static_cast<int>(i)}); }
    }
    if (counts.availablePages) { segments.push_back({L("Available"), counts.availablePages * pageBytes, 17}); }
    if (counts.bad()) { segments.push_back({L("Bad"), counts.bad() * pageBytes, -1}); }
    if (counts.unreadable) { segments.push_back({L("Query failed"), counts.unreadable * pageBytes, -2}); }
    if (counts.notScanned()) { segments.push_back({L("Not scanned"), counts.notScanned() * pageBytes, -3}); }
    m_chart->setSegments(std::move(segments), L("One physical page, one category. Click a category to inspect PFNs."));
    m_summary->setText(L("%1 | NT RAM %2 | attributed in use %3 | true unknown %4 | unreadable / unscanned %5 | coverage %6%")
        .arg(scan.complete ? L("Scan complete") : L("Partial / unavailable"), bytes(counts.expected * pageBytes), bytes(known * pageBytes),
            bytes(unknown * pageBytes), bytes((counts.unreadable + counts.notScanned()) * pageBytes))
        .arg(counts.expected ? 100.0 * static_cast<double>(counts.valid) / static_cast<double>(counts.expected) : 0.0, 0, 'f', 2));
    if (!counts.expected) {
        m_summary->setText(L("PFN scan unavailable: %1. No unknown-byte total can be calculated.").arg(status(scan.rangesStatus)));
    }
    m_summary->setText(m_summary->text() + QStringLiteral("\n") + L("Known use, owner unresolved: %1").arg(bytes(scan.ownerCoverage.knownInUseUnresolved() * pageBytes)));
    if (!scan.semanticsValidated) { m_summary->setText(m_summary->text() + QStringLiteral("\n") + L("Classification semantics have not been validated on this Windows build.")); }
    if (m_latestAttemptFailed && m_lastAttempt != m_scan) {
        m_summary->setText(L("Latest PFN attempt failed; showing the previous ledger.") + QStringLiteral("\n") + m_summary->text());
    }
    m_progress->setValue(counts.expected ? static_cast<int>(counts.valid * 1000 / counts.expected) : 0);
    m_categories->setSortingEnabled(false);
    m_categories->setRowCount(static_cast<int>(useCount));
    for (std::size_t i = 0; i < useCount; ++i) {
        const int row = static_cast<int>(i);
        auto* label = new QTableWidgetItem(L(useNames[i]));
        label->setData(Qt::UserRole, row);
        m_categories->setItem(row, 0, label);
        number(m_categories, row, 1, counts.inUse(static_cast<Use>(i)), false);
        number(m_categories, row, 2, counts.inUse(static_cast<Use>(i)) * pageBytes);
        for (unsigned list = 0; list < 8; ++list) { number(m_categories, row, static_cast<int>(list) + 3, counts.byUseAndState[i][list] * pageBytes); }
    }
    m_categories->setSortingEnabled(true);
    m_categories->resizeColumnsToContents();
    m_ownerCoverage->setSortingEnabled(false);
    m_ownerCoverage->setRowCount(static_cast<int>(useCount));
    for (std::size_t i = 0; i < useCount; ++i) {
        const int row = static_cast<int>(i);
        m_ownerCoverage->setItem(row, 0, new QTableWidgetItem(L(useNames[i])));
        const auto sum = [](const auto& states) { std::uint64_t value = 0; for (const auto pages : states) { value += pages; } return value * pageBytes; };
        number(m_ownerCoverage, row, 1, sum(counts.byUseAndState[i]));
        number(m_ownerCoverage, row, 2, sum(scan.ownerCoverage.resolved[i]));
        number(m_ownerCoverage, row, 3, sum(scan.ownerCoverage.unresolved[i]));
        number(m_ownerCoverage, row, 4, sum(scan.ownerCoverage.notApplicable[i]));
        number(m_ownerCoverage, row, 5, sum(scan.ownerCoverage.objectKeyKnown[i]));
    }
    m_ownerCoverage->setSortingEnabled(true); m_ownerCoverage->resizeColumnsToContents();
    m_objects->setRowCount(0);
    m_pageConsumers->setRowCount(0);
    if (m_mappingScan) {
        for (const auto& object : m_mappingScan->backing) {
            const int row = m_objects->rowCount(); if (row >= 300) { break; }
            m_objects->insertRow(row);
            m_objects->setItem(row, 0, new QTableWidgetItem(object.process));
            number(m_objects, row, 1, object.pid, false);
            m_objects->setItem(row, 2, new QTableWidgetItem(hex(object.allocationBase)));
            m_objects->setItem(row, 3, new QTableWidgetItem(object.path.isEmpty() ? L("Unresolved") : object.path));
            m_objects->setItem(row, 4, new QTableWidgetItem(backingProof(object)));
            m_objects->setItem(row, 5, new QTableWidgetItem(objectProof(object)));
            m_objects->setItem(row, 6, new QTableWidgetItem(L("Path Win32 %1 | object status %2").arg(object.pathError).arg(status(object.objectStatus))));
        }
        if (m_mappingScan->consumers) {
            for (const auto& consumer : m_mappingScan->consumers->relations) {
                const int row = m_pageConsumers->rowCount(); if (row >= 300) { break; }
                m_pageConsumers->insertRow(row);
                QString kind;
                switch (consumer.kind) {
                case ConsumerKind::PageTable: kind = L("Page-table address space"); break;
                case ConsumerKind::KernelStack: kind = L("Kernel-stack thread observation"); break;
                case ConsumerKind::BigPool: kind = L("Big Pool allocation observation"); break;
                }
                m_pageConsumers->setItem(row, 0, new QTableWidgetItem(kind));
                m_pageConsumers->setItem(row, 1, new QTableWidgetItem(hex(consumer.pfn)));
                number(m_pageConsumers, row, 2, consumer.pid, false);
                number(m_pageConsumers, row, 3, consumer.tid, false);
                m_pageConsumers->setItem(row, 4, new QTableWidgetItem(hex(consumer.virtualAddress)));
                m_pageConsumers->setItem(row, 5, new QTableWidgetItem(L("TID %1 | thread object %2 | table levels %3 | pool tag %4")
                    .arg(consumer.tid).arg(hex(consumer.threadObject)).arg(consumer.tableLevels).arg(hex(consumer.tag))));
                m_pageConsumers->setItem(row, 6, new QTableWidgetItem(L("Process rechecked %1 | thread rechecked %2 | thread lifetime %3 | driver module %4")
                    .arg(consumer.processIdentityRevalidated ? L("Yes") : L("No"), consumer.threadObjectRevalidated ? L("Yes") : L("No"),
                        consumer.threadCreationTimeKnown ? L("Available") : L("Unavailable"), consumer.driverModuleKnown ? L("Available") : L("Unresolved"))));
            }
        }
        m_objects->resizeColumnsToContents();
        m_pageConsumers->resizeColumnsToContents();
    }
    rebuildGroups();
    if (m_selectedCategory >= 0) { selectCategory(m_selectedCategory); }
    QStringList evidence;
    evidence << L("Observation domain %1 | epoch %2 | Windows %3.%4.%5 | process/native architecture %6/%7")
        .arg(scan.domain, scan.epoch).arg(scan.windowsMajor).arg(scan.windowsMinor).arg(scan.windowsBuild).arg(scan.processArchitecture, scan.nativeArchitecture);
    evidence << L("Native ABI %1 | observed %2 | semantics validated %3. R3 and R0 are access paths to the same Memory Manager provider.")
        .arg(scan.nativeAbi, scan.nativeAbiObserved ? L("Yes") : L("No"), scan.semanticsValidated ? L("Yes") : L("No"));
    evidence << L("Known-use consumer unresolved %1. This is separate from type-unknown and already belongs to existing categories.")
        .arg(bytes(scan.ownerCoverage.knownInUseUnresolved() * pageBytes));
    evidence << L("Raw identity retention %1 | retained pages %2 | finalized %3 | complete %4 | file %5")
        .arg(scan.rawEvidenceRequested ? L("Yes") : L("No")).arg(scan.rawEvidenceLedgerPages)
        .arg(scan.rawEvidenceFinalized ? L("Yes") : L("No"), scan.rawEvidenceComplete ? L("Yes") : L("No"), scan.rawEvidencePath.isEmpty() ? L("Unavailable") : scan.rawEvidencePath);
    if (scan.rawEvidenceFailed) { evidence << L("Raw evidence failed: %1").arg(scan.rawEvidenceError); }
    evidence << L("Observer process WS before/after/max %1/%2/%3; private bytes %4/%5/%6. Whole-process samples include other UI activity and are not an isolated allocation measurement.")
        .arg(bytes(scan.observerWorkingSetBefore), bytes(scan.observerWorkingSetAfter), bytes(scan.observerWorkingSetMax),
            bytes(scan.observerPrivateBefore), bytes(scan.observerPrivateAfter), bytes(scan.observerPrivateMax));
    evidence << L("Observer samples available before/after %1/%2 | encoded raw buffer peak %3 | batch timing retention overflow %4")
        .arg(scan.observerMemoryBeforeKnown ? L("Yes") : L("No"), scan.observerMemoryAfterKnown ? L("Yes") : L("No"))
        .arg(bytes(scan.rawBufferPeakBytes)).arg(scan.batchTimingOverflow);
    bool qualified = false;
    if (m_auditHistory.size() == 3) {
        const std::array<AuditCriterionSample, 3> samples{m_auditHistory[0], m_auditHistory[1], m_auditHistory[2]};
        qualified = proposedThreeScanCriterion(samples);
    }
    evidence << L("Proposed three-capture 64 MiB type-unknown criterion: %1. Requires a validated Windows build, complete coverage and exact ledger reconciliation; consumer attribution is separate.")
        .arg(qualified ? L("Passed") : L("Not established"));
    if (m_latestAttemptFailed && m_lastAttempt != m_scan) {
        evidence << L("Latest PFN attempt failed; showing the previous ledger.");
        if (m_lastAttempt) {
            evidence << L("Failed attempt %1 | range status %2 | page status %3")
                .arg(m_lastAttempt->finished, status(m_lastAttempt->rangesStatus), status(m_lastAttempt->lastPageStatus));
        }
    }
    evidence << L("Collection interval: %1 to %2 (%3 ms)").arg(scan.started, scan.finished).arg(scan.elapsedMs);
    evidence << L("Native batches %1 | R0 batches %2 | failed batches %3").arg(scan.nativeBatches).arg(scan.driverBatches).arg(scan.failedBatches);
    evidence << L("Recovery queries %1 | recovered physical pages %2. Retries do not add pages to the ledger.")
        .arg(scan.recoveryQueries).arg(scan.recoveredPages);
    evidence << L("Private owner resolved %1 | unresolved %2 | conflicting owner keys %3 | owner recheck %4")
        .arg(bytes(scan.resolvedPrivatePages * pageBytes), bytes(scan.unresolvedPrivatePages * pageBytes))
        .arg(scan.ownerConflicts).arg(scan.ownersRechecked ? status(scan.ownersRecheckStatus) : L("Not scanned"));
    evidence << L("Owner names are endpoint observations, not a frozen lifetime. Conflicting keys remain unnamed; missing names do not become unknown uses.");
    for (unsigned nativeUse = 0; nativeUse < counts.unknownByNativeUse.size(); ++nativeUse) {
        const auto& states = counts.unknownByNativeUse[nativeUse];
        const auto amount = states[3] + states[4] + states[6] + states[7];
        if (amount) { evidence << L("Unknown native use %1: %2").arg(nativeUse).arg(bytes(amount * pageBytes)); }
    }
    evidence << L("Range status %1 | owner status %2 | page status %3").arg(status(scan.rangesStatus), status(scan.ownersStatus), status(scan.lastPageStatus));
    evidence << L("Ledger reconciliation: %1. Unknown, unreadable and unscanned are separate; none is assigned to a guessed owner.")
        .arg(counts.reconciles() && counts.expected ? L("Passed") : L("Unavailable / failed"));
    evidence << L("Windows usable before / after: %1 / %2. PFN range total: %3.").arg(bytes(scan.totalBefore), bytes(scan.totalAfter), bytes(counts.expected * pageBytes));
    const auto difference = static_cast<qint64>(counts.expected * pageBytes) - static_cast<qint64>(scan.totalBefore);
    evidence << L("PFN range minus Windows usable: %1 bytes (different scopes or changing memory; not an owner).").arg(difference);
    evidence << L("Available before / after: %1 / %2. The scan is time-skewed, not an atomic snapshot.").arg(bytes(scan.availableBefore), bytes(scan.availableAfter));
    evidence << L("Installed minus Windows usable: %1. This is an aggregate reserved estimate, not a map of firmware pages.")
        .arg(scan.totalBefore && scan.installed >= scan.totalBefore ? bytes(scan.installed - scan.totalBefore) : L("Unavailable"));
    evidence << L("Hypervisor present: %1 | Secure kernel running: %2. Their physical byte counts are not exposed by this query.")
        .arg(scan.hypervisor ? L("Yes") : L("No"), scan.secureKnown ? (scan.secureKernel ? L("Yes") : L("No")) : L("Unavailable"));
    evidence << L("Pinned %1 | non-tradeable %2. These are overlapping attributes, not additional physical consumption.").arg(bytes(counts.pinned * pageBytes), bytes(counts.nonTradeable * pageBytes));
    evidence << L("File/cache names are resolved from observed process mappings. A file key without a path still has a known primary classification.");
    evidence << L("Private-source names are hints. Compression classification requires an authoritative store identity; no such provider is currently available.");
    evidence << L("PFN database, secure memory and inaccessible mappings are not guessed from residual bytes or hard-coded private offsets. Existing snapshot counters remain diagnostic only.");
    evidence << L("The table shows up to 300 matching backing identities; export retains all collected groups. PFN samples are bounded to 256 per category and do not limit the accounting scan.");
    if (scan.groupedOverflowPages) { evidence << L("Backing-group retention limit reached: %1 still-counted pages lack a retained group.").arg(scan.groupedOverflowPages); }
    if (scan.rangesChanged) { evidence << L("RAM ranges changed or could not be rechecked; treat this scan as partial."); }
    if (scan.cancelled) { evidence << L("Scan cancelled. Remaining pages are explicitly unscanned."); }
    if (scan.resourceFailure) { evidence << L("Collection failed because a worker could not retain its result."); }
    if (m_mappingScan) {
        const auto& maps = *m_mappingScan;
        evidence << L("Mappings sampled %1 | tested %2 | distinct observed PFNs %3 | failures %4 | processes scanned %5/%6 | inaccessible %7")
            .arg(maps.sampledAt).arg(maps.tested).arg(maps.distinct).arg(maps.failed).arg(maps.scannedProcesses).arg(maps.processes).arg(maps.inaccessible);
        evidence << L("Observed large-page bytes %1 | locked bytes %2 | multiply mapped bytes %3. All are subsets, never added to the PFN ledger.")
            .arg(bytes(maps.large * pageBytes), bytes(maps.locked * pageBytes), bytes(maps.multiplyMapped * pageBytes));
        evidence << L("PFNs with incompatible native identities %1. Multiple references are interval observations; simultaneous sharing is unverified.").arg(maps.identityConflicted);
        evidence << L("Mapping coverage includes accessible virtual regions within the time and page budget. AWE and large pages are probed; inaccessible or unvisited mappings remain unverified.");
        evidence << L("Mapping limits: 16 million virtual pages probed, 2 million retained references, and the selected time budget. These limits can leave owner coverage incomplete.");
        evidence << L("Virtual pages probed %1 | region query failures %2 | working-set query failures %3 | changed mappings %4 | conflicting file keys %5")
            .arg(maps.virtualPagesProbed).arg(maps.regionQueryFailures).arg(maps.workingSetQueryFailures).arg(maps.changedMappings).arg(maps.conflictingFileKeys);
        evidence << L("Ordinary working sets scanned %1/%2 | supplemental region scans completed %3/%2")
            .arg(maps.workingSetProcesses).arg(maps.processes).arg(maps.scannedProcesses);
        evidence << L("Mapping observer WS before / after %1 / %2 | private before / after %3 / %4 | samples %5. Maxima are sampled observations.")
            .arg(maps.observerBeforeKnown ? bytes(maps.observerWorkingSetBefore) : L("Unavailable"), maps.observerAfterKnown ? bytes(maps.observerWorkingSetAfter) : L("Unavailable"),
                maps.observerBeforeKnown ? bytes(maps.observerPrivateBefore) : L("Unavailable"), maps.observerAfterKnown ? bytes(maps.observerPrivateAfter) : L("Unavailable")).arg(maps.observerMemorySamples);
        evidence << L("Mapping observation domain %1 | epoch %2 | PFN ledger context %3 | interval %4 to %5")
            .arg(maps.domain, maps.epoch, maps.ledgerContextEpoch, maps.sampledAt, maps.finished);
        evidence << L("Verified object relations %1 | object queries %2 | object budget reached %3. Creators and anonymous Section identity are not inferred from mapped allocations.")
            .arg(maps.verifiedObjectRelations).arg(maps.objectQueries).arg(maps.objectBudgetReached ? L("Yes") : L("No"));
        evidence << L("Cache-only filename provider %1 | anonymous Section provider %2. Missing capabilities remain explicit.")
            .arg(status(maps.cacheFileNameProviderStatus), status(maps.anonymousSectionProviderStatus));
        if (maps.consumers) {
            const auto& consumers = *maps.consumers;
            evidence << L("Independent page consumers %1 distinct PFNs | candidates %2 | failures %3 | rejected %4 | interval %5 to %6")
                .arg(consumers.distinct).arg(consumers.candidatePages).arg(consumers.failed).arg(consumers.rejected).arg(consumers.started, consumers.finished);
            evidence << L("Page-table provider %1 | kernel-stack provider %2 | Big Pool provider %3 | thread creation identity %4 | lock owner provider %5")
                .arg(status(consumers.tableStatus), status(consumers.stackStatus), status(consumers.bigPoolStatus),
                    consumers.threadCreationProviderAvailable ? L("Available") : L("Unavailable"), consumers.lockOwnerProviderAvailable ? L("Available") : L("Unavailable"));
            evidence << L("These relations retain native PFN witnesses and source identities. Thread objects are endpoint observations; pool tags do not identify a unique driver, and these bytes are not added to the physical ledger.");
        }
        evidence << L("Mapping status %1 | driver available %2 | cancelled %3 | budget reached %4")
            .arg(status(maps.status), maps.driverAvailable ? L("Yes") : L("No"), maps.cancelled ? L("Yes") : L("No"), maps.budgetReached ? L("Yes") : L("No"));
    } else { evidence << L("Mapping resolution has not run. Large-page and per-PFN reference coverage is unavailable."); }
    m_evidence->setReportText(evidence.join(QLatin1Char('\n')));
}

void PhysicalPageAttributionPage::rebuildGroups()
{
    m_groups->setRowCount(0);
    if (!m_scan) { return; }
    const QString filter = m_filter->text().trimmed();
    for (const auto& group : m_scan->groups) {
        QString owner = group.name.isEmpty() ? (group.key ? hex(group.key) : L("Unavailable")) : group.name;
        if (group.use == Use::Private && !group.name.isEmpty() && !group.ownerLifetimeVerified) {
            owner += L(" [source hint; lifetime unverified]");
        }
        const QString kind = L(useNames[static_cast<std::size_t>(group.use)]);
        if (!filter.isEmpty() && !(owner + kind + QString::number(group.pid)).contains(filter, Qt::CaseInsensitive)) { continue; }
        const int row = m_groups->rowCount();
        if (row >= 300) { break; }
        m_groups->insertRow(row);
        auto* item = new QTableWidgetItem(kind);
        item->setData(Qt::UserRole, QVariant::fromValue<qulonglong>(group.firstPfn));
        m_groups->setItem(row, 0, item);
        auto* ownerItem = new QTableWidgetItem(owner);
        QString ownerEvidence = L("Collection interval: %1 to %2 (%3 ms)").arg(m_scan->started, m_scan->finished).arg(m_scan->elapsedMs);
        if (group.pid) {
            ownerEvidence += QStringLiteral("\n") + L("Owner seen before / after: %1 / %2")
                .arg(group.ownerSeenBefore ? L("Yes") : L("No"), group.ownerSeenAfter ? L("Yes") : L("No"));
            ownerEvidence += QStringLiteral("\n") + L("Process lifetime verified: %1 | creation time: %2")
                .arg(group.ownerLifetimeVerified ? L("Yes") : L("No"), group.ownerCreateTime ? QString::number(group.ownerCreateTime) : L("Unavailable"));
        }
        if (m_mappingScan) { ownerEvidence += QStringLiteral("\n") + L("Mapping observations sampled at %1.").arg(m_mappingScan->sampledAt); }
        ownerItem->setToolTip(ownerEvidence);
        m_groups->setItem(row, 1, ownerItem);
        if (group.pid) { number(m_groups, row, 2, group.pid, false); }
        else { m_groups->setItem(row, 2, new QTableWidgetItem(L("Unavailable"))); }
        number(m_groups, row, 3, group.pages * pageBytes);
        number(m_groups, row, 4, group.activePages * pageBytes);
        m_groups->setItem(row, 5, new QTableWidgetItem(hex(group.firstPfn)));
    }
    m_groups->resizeColumnsToContents();
}

void PhysicalPageAttributionPage::selectCategory(int use)
{
    if (!m_scan || use < 0 || use >= static_cast<int>(useCount)) { return; }
    m_selectedCategory = use;
    const auto& examples = m_scan->examples[static_cast<std::size_t>(use)];
    m_examples->setRowCount(static_cast<int>(examples.size()));
    for (std::size_t i = 0; i < examples.size(); ++i) {
        const int row = static_cast<int>(i);
        m_examples->setItem(row, 0, new QTableWidgetItem(hex(examples[i].first)));
        m_examples->setItem(row, 1, new QTableWidgetItem(L(stateNames[state(examples[i].second)])));
        m_examples->setItem(row, 2, new QTableWidgetItem(hex(examples[i].first * pageBytes)));
    }
    m_examples->resizeColumnsToContents();
}

void PhysicalPageAttributionPage::inspectPfn()
{
    if (m_inspection) { return; }
    bool ok = false;
    const auto pfn = m_pfn->text().trimmed().toULongLong(&ok, 0);
    if (!ok || !m_scan || std::none_of(m_scan->ranges.begin(), m_scan->ranges.end(), [pfn](const Range& range) { return pfn >= range.first && pfn - range.first < range.count; })) {
        m_pageEvidence->setReportText(L("Enter a PFN inside a collected NT RAM range. Physical address holes are not RAM."));
        return;
    }
    m_inspection = std::make_shared<Inspection>();
    m_inspection->pfn = pfn;
    const auto job = m_inspection;
    m_inspectButton->setEnabled(false);
    try { std::thread([job] {
        try {
            ksword::ark::PfnQueryClient client;
            std::vector<KSWORD_ARK_PFN_IDENTITY> pages;
            job->status = client.pages(job->pfn, 1, pages);
            if (!pages.empty()) { job->identity = {pages[0].frame, pages[0].backing}; }
            job->use = classify(job->identity);
            if (job->status >= 0 && nativeUse(job->identity) == 0 && inUseState(state(job->identity))) {
                const auto original = job->identity;
                std::vector<KSWORD_ARK_PFN_OWNER> beforeOwners, afterOwners;
                const auto beforeStatus = client.owners(beforeOwners);
                job->ownerStatus = client.owners(afterOwners);
                pages.clear();
                job->status = client.pages(job->pfn, 1, pages);
                if (!pages.empty()) { job->identity = {pages[0].frame, pages[0].backing}; }
                job->use = classify(job->identity);
                const auto key = processKey(job->identity);
                const auto findOwner = [key](const auto& owners, QString& name, std::uint32_t& pid) {
                    bool found = false;
                    for (const auto& owner : owners) {
                        if (!key || owner.processKey != key) { continue; }
                        const auto end = std::find(std::begin(owner.imageName), std::end(owner.imageName), '\0');
                        const auto candidate = QString::fromLatin1(owner.imageName, static_cast<qsizetype>(end - owner.imageName));
                        if (found && (pid != owner.processId || candidate.compare(name, Qt::CaseInsensitive) != 0)) { return false; }
                        found = true; pid = owner.processId; name = candidate;
                    }
                    return found && !name.isEmpty();
                };
                QString beforeName, afterName; std::uint32_t beforePid = 0, afterPid = 0;
                job->ownerHintObserved = job->status >= 0 && beforeStatus >= 0 && job->ownerStatus >= 0
                    && original.frame == job->identity.frame && original.backing == job->identity.backing
                    && findOwner(beforeOwners, beforeName, beforePid) && findOwner(afterOwners, afterName, afterPid)
                    && beforePid == afterPid && beforeName.compare(afterName, Qt::CaseInsensitive) == 0;
                if (job->ownerHintObserved) {
                    // Endpoint names are hints: this on-demand query does not
                    // hold a process lifetime lease across its observations.
                    job->ownerPid = afterPid; job->ownerName = afterName;
                    job->ownerResolved = false;
                    job->use = classify(job->identity);
                }
                if (beforeStatus < 0 && job->ownerStatus >= 0) { job->ownerStatus = beforeStatus; }
            }
            job->sampledAt = QDateTime::currentDateTime().toString(Qt::ISODateWithMs);
        } catch (...) { job->status = static_cast<long>(0xC000009AUL); }
        job->done.store(true);
    }).detach(); } catch (...) { m_inspection.reset(); m_inspectButton->setEnabled(true); }
}

void PhysicalPageAttributionPage::showMappings(std::uint64_t pfn)
{
    m_mappings->setRowCount(0);
    if (!m_mappingScan) { return; }
    const auto& rows = m_mappingScan->rows;
    auto first = std::lower_bound(rows.begin(), rows.end(), pfn, [](const Mapping& row, auto value) { return row.pfn < value; });
    auto last = first;
    while (last != rows.end() && last->pfn == pfn) { ++last; }
    m_pageEvidence->appendReportText(L("Observed mappings for this PFN: %1 (sampled %2; first 300 shown).").arg(std::distance(first, last)).arg(m_mappingScan->sampledAt));
    for (auto entry = first; entry != last && m_mappings->rowCount() < 300; ++entry) {
        const int row = m_mappings->rowCount();
        m_mappings->insertRow(row);
        const auto& backing = m_mappingScan->backing[entry->backingIndex];
        number(m_mappings, row, 0, entry->pid, false);
        m_mappings->setItem(row, 1, new QTableWidgetItem(hex(entry->address)));
        m_mappings->setItem(row, 2, new QTableWidgetItem(backing.process));
        m_mappings->setItem(row, 3, new QTableWidgetItem(backing.path));
        number(m_mappings, row, 4, entry->pageSize);
        m_mappings->setItem(row, 5, new QTableWidgetItem(entry->attributesKnown ? (entry->locked ? L("Yes") : L("No")) : L("Unavailable")));
        if (entry->attributesKnown) { number(m_mappings, row, 6, entry->shareCount, false); }
        else { m_mappings->setItem(row, 6, new QTableWidgetItem(L("Unavailable"))); }
        QString proof = backingProof(backing);
        if (entry->nativeIdentityKnown && nativeUse({entry->nativeFrame, entry->nativeBacking}) == 0
            && (backing.kind == MEM_MAPPED || backing.kind == MEM_IMAGE)) { proof += QStringLiteral(" | ") + L("Private mapped copy"); }
        m_mappings->setItem(row, 7, new QTableWidgetItem(proof));
        m_mappings->setItem(row, 8, new QTableWidgetItem(objectProof(backing)));
        m_mappings->setItem(row, 9, new QTableWidgetItem(entry->nativeIdentityKnown ? hex(entry->nativeBacking) : L("Unresolved")));
    }
    m_mappings->resizeColumnsToContents();
}

void PhysicalPageAttributionPage::exportEvidence()
{
    if (!m_scan || m_job || m_mappingJob || m_exportJob) { return; }
    const QPointer<PhysicalPageAttributionPage> page(this);
    const QString path = QFileDialog::getSaveFileName(this, L("Export PFN evidence"), QStringLiteral("pfn-evidence.json"), L("JSON files (*.json)"));
    if (page.isNull() || path.isEmpty()) { return; }
    if (!m_scan || m_job || m_mappingJob || m_exportJob) { return; }
    const auto normalizedFile = [](const QString& name) {
        const QFileInfo info(name);
        const QString canonical = info.canonicalFilePath();
        return canonical.isEmpty() ? info.absoluteFilePath() : canonical;
    };
    if (!m_scan->rawEvidencePath.isEmpty() && normalizedFile(path).compare(normalizedFile(m_scan->rawEvidencePath), Qt::CaseInsensitive) == 0) {
        m_summary->setText(L("Choose a manifest path different from the raw PFN evidence file.")); return;
    }
    m_exportJob = std::make_shared<ExportJob>(); m_exportJob->path = path;
    const auto job = m_exportJob;
    const auto scanPtr = m_scan;
    const auto mapsPtr = m_mappingScan;
    const auto lastAttempt = m_lastAttempt;
    const bool latestAttemptFailed = m_latestAttemptFailed, fullMappings = m_exportMappings->isChecked();
    const QString interpretation = m_evidence->text();
    const QJsonObject consumer = m_consumerPage->evidence();
    try { std::thread([job, scanPtr, mapsPtr, lastAttempt, latestAttemptFailed, fullMappings, interpretation, consumer, path] {
        struct Done { std::shared_ptr<ExportJob> job; ~Done() { job->done.store(true); } } done{job};
        try {
    const auto& scan = *scanPtr;
    QJsonObject root;
    root.insert(QStringLiteral("schema"), QStringLiteral("ksword.pfn.evidence"));
    root.insert(QStringLiteral("version"), 2);
    root.insert(QStringLiteral("pageBytes"), static_cast<int>(pageBytes));
    root.insert(QStringLiteral("started"), scan.started);
    root.insert(QStringLiteral("finished"), scan.finished);
    root.insert(QStringLiteral("complete"), scan.complete);
    root.insert(QStringLiteral("latestAttemptFailed"), latestAttemptFailed);
    if (latestAttemptFailed && lastAttempt && lastAttempt != scanPtr) {
        root.insert(QStringLiteral("failedAttemptFinished"), lastAttempt->finished);
        root.insert(QStringLiteral("failedAttemptRangeStatus"), status(lastAttempt->rangesStatus));
        root.insert(QStringLiteral("failedAttemptPageStatus"), status(lastAttempt->lastPageStatus));
    }
    root.insert(QStringLiteral("cancelled"), scan.cancelled);
    root.insert(QStringLiteral("reconciles"), scan.accounting.reconciles());
    root.insert(QStringLiteral("expectedPages"), QString::number(scan.accounting.expected));
    root.insert(QStringLiteral("unreadablePages"), QString::number(scan.accounting.unreadable));
    root.insert(QStringLiteral("unscannedPages"), QString::number(scan.accounting.notScanned()));
    root.insert(QStringLiteral("validPages"), QString::number(scan.accounting.valid));
    root.insert(QStringLiteral("unknownInUsePages"), QString::number(scan.accounting.inUse(Use::Unknown)));
    root.insert(QStringLiteral("recoveryQueries"), QString::number(scan.recoveryQueries));
    root.insert(QStringLiteral("recoveredPages"), QString::number(scan.recoveredPages));
    root.insert(QStringLiteral("resolvedPrivatePages"), QString::number(scan.resolvedPrivatePages));
    root.insert(QStringLiteral("unresolvedPrivatePages"), QString::number(scan.unresolvedPrivatePages));
    root.insert(QStringLiteral("ownerConflicts"), QString::number(scan.ownerConflicts));
    root.insert(QStringLiteral("ownersRechecked"), scan.ownersRechecked);
    root.insert(QStringLiteral("ownersRecheckStatus"), status(scan.ownersRecheckStatus));
    QJsonArray unknownUses;
    for (const auto& row : scan.accounting.unknownByNativeUse) {
        QJsonArray states;
        for (const auto amount : row) { states.append(QString::number(amount)); }
        unknownUses.append(states);
    }
    root.insert(QStringLiteral("unknownPagesByNativeUseAndState"), unknownUses);
    root.insert(QStringLiteral("interpretation"), interpretation);
    QJsonArray categories;
    for (std::size_t i = 0; i < useCount; ++i) {
        QJsonArray states;
        for (const auto pages : scan.accounting.byUseAndState[i]) { states.append(QString::number(pages)); }
        QJsonObject entry;
        entry.insert(QStringLiteral("use"), QString::fromLatin1(useNames[i]));
        entry.insert(QStringLiteral("pagesByState"), states);
        categories.append(entry);
    }
    root.insert(QStringLiteral("categories"), categories);
    QJsonArray ranges;
    for (const auto& range : scan.ranges) {
        QJsonObject entry;
        entry.insert(QStringLiteral("firstPfn"), hex(range.first));
        entry.insert(QStringLiteral("pageCount"), QString::number(range.count));
        ranges.append(entry);
    }
    root.insert(QStringLiteral("ranges"), ranges);
    QJsonArray groups;
    for (const auto& group : scan.groups) {
        QJsonObject entry;
        entry.insert(QStringLiteral("use"), QString::fromLatin1(useNames[static_cast<std::size_t>(group.use)]));
        entry.insert(QStringLiteral("key"), hex(group.key));
        entry.insert(QStringLiteral("pid"), static_cast<qint64>(group.pid));
        entry.insert(QStringLiteral("name"), group.name);
        entry.insert(QStringLiteral("pages"), QString::number(group.pages));
        entry.insert(QStringLiteral("activePages"), QString::number(group.activePages));
        entry.insert(QStringLiteral("ownerSeenBefore"), group.ownerSeenBefore);
        entry.insert(QStringLiteral("ownerSeenAfter"), group.ownerSeenAfter);
        entry.insert(QStringLiteral("ownerLifetimeVerified"), group.ownerLifetimeVerified);
        entry.insert(QStringLiteral("ownerCreateTime"), QString::number(group.ownerCreateTime));
        QJsonArray groupStates;
        for (const auto amount : group.pagesByState) { groupStates.append(QString::number(amount)); }
        entry.insert(QStringLiteral("pagesByState"), groupStates);
        entry.insert(QStringLiteral("firstPfn"), hex(group.firstPfn));
        groups.append(entry);
    }
    root.insert(QStringLiteral("groups"), groups);
    if (mapsPtr) {
        const auto& maps = *mapsPtr;
        QJsonObject mapping;
        mapping.insert(QStringLiteral("sampledAt"), maps.sampledAt);
        mapping.insert(QStringLiteral("virtualPagesProbed"), QString::number(maps.virtualPagesProbed));
        mapping.insert(QStringLiteral("regionQueryFailures"), static_cast<qint64>(maps.regionQueryFailures));
        mapping.insert(QStringLiteral("workingSetQueryFailures"), static_cast<qint64>(maps.workingSetQueryFailures));
        mapping.insert(QStringLiteral("workingSetProcesses"), static_cast<qint64>(maps.workingSetProcesses));
        mapping.insert(QStringLiteral("regionScannedProcesses"), static_cast<qint64>(maps.scannedProcesses));
        mapping.insert(QStringLiteral("changedMappings"), QString::number(maps.changedMappings));
        mapping.insert(QStringLiteral("conflictingFileKeys"), QString::number(maps.conflictingFileKeys));
        mapping.insert(QStringLiteral("cancelled"), maps.cancelled);
        mapping.insert(QStringLiteral("budgetReached"), maps.budgetReached);
        root.insert(QStringLiteral("mappingCoverage"), mapping);
    }

    root.insert(QStringLiteral("domain"), scan.domain);
    root.insert(QStringLiteral("epoch"), scan.epoch);
    root.insert(QStringLiteral("windowsBuild"), static_cast<qint64>(scan.windowsBuild));
    root.insert(QStringLiteral("windowsVersionKnown"), scan.windowsVersionKnown);
    root.insert(QStringLiteral("processArchitecture"), scan.processArchitecture);
    root.insert(QStringLiteral("nativeArchitecture"), scan.nativeArchitecture);
    root.insert(QStringLiteral("nativeAbi"), scan.nativeAbi);
    root.insert(QStringLiteral("nativeAbiObserved"), scan.nativeAbiObserved);
    root.insert(QStringLiteral("semanticsValidated"), scan.semanticsValidated);
    root.insert(QStringLiteral("semanticValidation"), scan.semanticValidation);
    root.insert(QStringLiteral("consumerEvidence"), consumer);
    const auto matrix = [](const auto& values) {
        QJsonArray rows;
        for (const auto& row : values) {
            QJsonArray cells; for (const auto count : row) { cells.append(QString::number(count)); } rows.append(cells);
        }
        return rows;
    };
    root.insert(QStringLiteral("ownerCoverage"), QJsonObject{{QStringLiteral("resolved"), matrix(scan.ownerCoverage.resolved)},
        {QStringLiteral("unresolved"), matrix(scan.ownerCoverage.unresolved)}, {QStringLiteral("notApplicable"), matrix(scan.ownerCoverage.notApplicable)},
        {QStringLiteral("objectKeyKnown"), matrix(scan.ownerCoverage.objectKeyKnown)}, {QStringLiteral("reconciles"), scan.ownerCoverage.reconciles(scan.accounting)}});
    QJsonArray batches;
    for (const auto& batch : scan.batches) {
        QJsonObject row{{QStringLiteral("ordinal"), QString::number(batch.ordinal)}, {QStringLiteral("operation"), batch.operation},
            {QStringLiteral("firstPfn"), hex(batch.firstPfn)}, {QStringLiteral("pageCount"), QString::number(batch.pageCount)},
            {QStringLiteral("started"), batch.started}, {QStringLiteral("finished"), batch.finished},
            {QStringLiteral("startUs"), QString::number(batch.startUs)}, {QStringLiteral("endUs"), QString::number(batch.endUs)},
            {QStringLiteral("status"), status(batch.status)}, {QStringLiteral("selectedPath"), batch.selectedPath},
            {QStringLiteral("driverInvoked"), batch.trace.driverInvoked}, {QStringLiteral("driverAvailable"), batch.trace.driverAvailable},
            {QStringLiteral("driverOperation"), static_cast<qint64>(batch.trace.driverOperation)},
            {QStringLiteral("driverStatus"), status(batch.trace.driverStatus)}, {QStringLiteral("driverTransportStatus"), status(batch.trace.driverTransportStatus)}};
        QJsonArray native;
        for (unsigned i = 0; i < batch.trace.nativeAttemptCount && i < batch.trace.nativeAttempts.size(); ++i) {
            const auto& attempt = batch.trace.nativeAttempts[i];
            native.append(QJsonObject{{QStringLiteral("informationClass"), static_cast<qint64>(attempt.informationClass)},
                {QStringLiteral("abiVersion"), static_cast<qint64>(attempt.abiVersion)}, {QStringLiteral("status"), status(attempt.status)},
                {QStringLiteral("invoked"), attempt.invoked}});
        }
        row.insert(QStringLiteral("nativeAttempts"), native); batches.append(row);
    }
    root.insert(QStringLiteral("queryBatches"), batches);
    root.insert(QStringLiteral("batchTimingOverflow"), QString::number(scan.batchTimingOverflow));
    root.insert(QStringLiteral("groupedOverflowPages"), QString::number(scan.groupedOverflowPages));
    root.insert(QStringLiteral("observer"), QJsonObject{{QStringLiteral("workingSetBefore"), QString::number(scan.observerWorkingSetBefore)},
        {QStringLiteral("workingSetAfter"), QString::number(scan.observerWorkingSetAfter)}, {QStringLiteral("workingSetMax"), QString::number(scan.observerWorkingSetMax)},
        {QStringLiteral("privateBefore"), QString::number(scan.observerPrivateBefore)}, {QStringLiteral("privateAfter"), QString::number(scan.observerPrivateAfter)},
        {QStringLiteral("privateMax"), QString::number(scan.observerPrivateMax)}, {QStringLiteral("beforeKnown"), scan.observerMemoryBeforeKnown},
        {QStringLiteral("afterKnown"), scan.observerMemoryAfterKnown}, {QStringLiteral("samples"), QString::number(scan.observerMemorySamples)},
        {QStringLiteral("rawEncodedBufferPeak"), QString::number(scan.rawBufferPeakBytes)}});
    const QString exportId = QUuid::createUuid().toString(QUuid::Id128);
    QJsonObject raw{{QStringLiteral("requested"), scan.rawEvidenceRequested}, {QStringLiteral("finalized"), scan.rawEvidenceFinalized},
        {QStringLiteral("complete"), scan.rawEvidenceComplete}, {QStringLiteral("failed"), scan.rawEvidenceFailed},
        {QStringLiteral("error"), scan.rawEvidenceError}, {QStringLiteral("ledgerPages"), QString::number(scan.rawEvidenceLedgerPages)}};
    if (scan.rawEvidenceRequested) {
        QFile source(scan.rawEvidencePath);
        const QFileInfo before(scan.rawEvidencePath);
        if (!source.open(QIODevice::ReadOnly) || before.size() != static_cast<qint64>(scan.rawEvidenceBytes)) {
            job->error = QStringLiteral("Retained raw PFN evidence is missing or has changed"); return;
        }
        const auto headerBytes = source.readLine(8 * 1024 * 1024 + 1);
        const auto headerDocument = QJsonDocument::fromJson(headerBytes);
        const auto header = headerDocument.object();
        if (!headerBytes.endsWith('\n') || !headerDocument.isObject()
            || header.value(QStringLiteral("schema")).toString() != QStringLiteral("ksword.pfn.raw")
            || header.value(QStringLiteral("version")).toInt() != 2
            || header.value(QStringLiteral("kind")).toString() != QStringLiteral("header")
            || header.value(QStringLiteral("domain")).toString() != scan.domain
            || header.value(QStringLiteral("epoch")).toString() != scan.epoch || !source.seek(0)) {
            job->error = QStringLiteral("Retained raw PFN evidence belongs to a different or invalid capture"); return;
        }
        const QString sidecar = path + QStringLiteral(".raw-") + exportId + QStringLiteral(".jsonl");
        QSaveFile copy(sidecar); QCryptographicHash hash(QCryptographicHash::Sha256);
        if (!copy.open(QIODevice::WriteOnly)) { job->error = copy.errorString(); return; }
        while (!source.atEnd() && !job->cancel.load()) {
            const auto chunk = source.read(1024 * 1024);
            if (chunk.isEmpty() && source.error() != QFileDevice::NoError) { job->error = source.errorString(); return; }
            if (copy.write(chunk) != chunk.size()) { job->error = copy.errorString(); return; }
            hash.addData(chunk);
        }
        const QFileInfo after(scan.rawEvidencePath);
        if (job->cancel.load()) { job->error = QStringLiteral("Evidence export cancelled"); return; }
        if (after.size() != before.size() || after.lastModified() != before.lastModified()) {
            job->error = QStringLiteral("Retained raw PFN evidence changed during export"); return;
        }
        if (!copy.commit()) { job->error = copy.errorString(); return; }
        raw.insert(QStringLiteral("file"), QFileInfo(sidecar).fileName());
        raw.insert(QStringLiteral("sha256"), QString::fromLatin1(hash.result().toHex()));
        raw.insert(QStringLiteral("bytes"), QString::number(before.size()));
    }
    root.insert(QStringLiteral("rawPfnEvidence"), raw);
    if (mapsPtr) {
        const auto& maps = *mapsPtr;
        QJsonObject metadata{{QStringLiteral("domain"), maps.domain}, {QStringLiteral("epoch"), maps.epoch},
            {QStringLiteral("ledgerContextEpoch"), maps.ledgerContextEpoch}, {QStringLiteral("started"), maps.sampledAt}, {QStringLiteral("finished"), maps.finished},
            {QStringLiteral("retainedRows"), QString::number(maps.rows.size())}, {QStringLiteral("retainedObjects"), QString::number(maps.backing.size())},
            {QStringLiteral("objectQueries"), static_cast<qint64>(maps.objectQueries)}, {QStringLiteral("verifiedObjectRelations"), static_cast<qint64>(maps.verifiedObjectRelations)},
            {QStringLiteral("objectBudgetReached"), maps.objectBudgetReached}, {QStringLiteral("cacheFileNameProviderStatus"), status(maps.cacheFileNameProviderStatus)},
            {QStringLiteral("anonymousSectionProviderStatus"), status(maps.anonymousSectionProviderStatus)},
            {QStringLiteral("cancelled"), maps.cancelled}, {QStringLiteral("budgetReached"), maps.budgetReached},
            {QStringLiteral("failedAllocation"), maps.failedAllocation}, {QStringLiteral("fullRetainedMappingExportRequested"), fullMappings},
            {QStringLiteral("tested"), QString::number(maps.tested)}, {QStringLiteral("failed"), QString::number(maps.failed)},
            {QStringLiteral("distinct"), QString::number(maps.distinct)}, {QStringLiteral("large"), QString::number(maps.large)},
            {QStringLiteral("locked"), QString::number(maps.locked)}, {QStringLiteral("multiplyMapped"), QString::number(maps.multiplyMapped)},
            {QStringLiteral("identityConflicted"), QString::number(maps.identityConflicted)},
            {QStringLiteral("virtualPagesProbed"), QString::number(maps.virtualPagesProbed)}, {QStringLiteral("changedMappings"), QString::number(maps.changedMappings)},
            {QStringLiteral("conflictingFileKeys"), QString::number(maps.conflictingFileKeys)},
            {QStringLiteral("regionQueryFailures"), static_cast<qint64>(maps.regionQueryFailures)}, {QStringLiteral("workingSetQueryFailures"), static_cast<qint64>(maps.workingSetQueryFailures)},
            {QStringLiteral("processes"), static_cast<qint64>(maps.processes)}, {QStringLiteral("inaccessible"), static_cast<qint64>(maps.inaccessible)},
            {QStringLiteral("workingSetProcesses"), static_cast<qint64>(maps.workingSetProcesses)}, {QStringLiteral("regionScannedProcesses"), static_cast<qint64>(maps.scannedProcesses)},
            {QStringLiteral("status"), status(maps.status)}, {QStringLiteral("driverAvailable"), maps.driverAvailable},
            {QStringLiteral("observer"), QJsonObject{{QStringLiteral("known"), maps.observerMemoryKnown},
                {QStringLiteral("beforeKnown"), maps.observerBeforeKnown}, {QStringLiteral("afterKnown"), maps.observerAfterKnown},
                {QStringLiteral("workingSetBefore"), QString::number(maps.observerWorkingSetBefore)}, {QStringLiteral("workingSetAfter"), QString::number(maps.observerWorkingSetAfter)},
                {QStringLiteral("workingSetMax"), QString::number(maps.observerWorkingSetMax)}, {QStringLiteral("privateBefore"), QString::number(maps.observerPrivateBefore)},
                {QStringLiteral("privateAfter"), QString::number(maps.observerPrivateAfter)}, {QStringLiteral("privateMax"), QString::number(maps.observerPrivateMax)},
                {QStringLiteral("samples"), static_cast<qint64>(maps.observerMemorySamples)}, {QStringLiteral("sampledMaximumOnly"), maps.observerMemoryPeakIsSampled}}},
            {QStringLiteral("limits"), QJsonObject{{QStringLiteral("mappingRows"), 2097152}, {QStringLiteral("virtualPageProbes"), 16777216},
                {QStringLiteral("recordBytes"), 8 * 1024 * 1024}, {QStringLiteral("backingChunkRows"), 16}, {QStringLiteral("mappingChunkRows"), 4096}}}};
        if (fullMappings) {
            const QString sidecar = path + QStringLiteral(".mappings-") + exportId + QStringLiteral(".jsonl");
            QSaveFile file(sidecar); QCryptographicHash hash(QCryptographicHash::Sha256);
            if (!file.open(QIODevice::WriteOnly)) { job->error = file.errorString(); return; }
            const auto write = [&](QJsonObject record) {
                record.insert(QStringLiteral("schema"), QStringLiteral("ksword.pfn.mappings"));
                record.insert(QStringLiteral("version"), 1); record.insert(QStringLiteral("domain"), maps.domain);
                record.insert(QStringLiteral("epoch"), maps.epoch); record.insert(QStringLiteral("ledgerContextEpoch"), maps.ledgerContextEpoch);
                const auto data = QJsonDocument(record).toJson(QJsonDocument::Compact) + '\n';
                if (data.size() > 8 * 1024 * 1024 || job->cancel.load() || file.write(data) != data.size()) {
                    job->error = job->cancel.load() ? QStringLiteral("Evidence export cancelled") : QStringLiteral("Mapping evidence write failed or exceeded its record bound");
                    return false;
                }
                hash.addData(data); return true;
            };
            auto header = metadata; header.insert(QStringLiteral("kind"), QStringLiteral("header"));
            if (!write(header)) { return; }
            for (std::size_t first = 0; first < maps.backing.size(); first += 16) {
                QJsonArray rows;
                for (std::size_t i = first; i < std::min(first + 16, maps.backing.size()); ++i) {
                    const auto& b = maps.backing[i];
                    rows.append(QJsonObject{{QStringLiteral("index"), QString::number(i)}, {QStringLiteral("pid"), static_cast<qint64>(b.pid)},
                        {QStringLiteral("processCreateTime"), QString::number(b.processCreateTime)}, {QStringLiteral("process"), b.process},
                        {QStringLiteral("path"), b.path}, {QStringLiteral("regionKind"), static_cast<qint64>(b.kind)},
                        {QStringLiteral("allocationBase"), hex(b.allocationBase)}, {QStringLiteral("regionBase"), hex(b.regionBase)}, {QStringLiteral("regionSize"), QString::number(b.regionSize)},
                        {QStringLiteral("pathStatus"), static_cast<int>(b.pathStatus)}, {QStringLiteral("pathError"), static_cast<qint64>(b.pathError)},
                        {QStringLiteral("regionInformationKnown"), b.regionInformationKnown}, {QStringLiteral("mappedPageFile"), b.mappedPageFile},
                        {QStringLiteral("mappedDataFile"), b.mappedDataFile}, {QStringLiteral("mappedImage"), b.mappedImage}, {QStringLiteral("mappedPhysical"), b.mappedPhysical},
                        {QStringLiteral("objectSource"), static_cast<int>(b.objectSource)}, {QStringLiteral("sectionObject"), hex(b.sectionObject)},
                        {QStringLiteral("controlArea"), hex(b.controlArea)}, {QStringLiteral("objectStatus"), status(b.objectStatus)},
                        {QStringLiteral("objectQueryStatus"), static_cast<qint64>(b.objectQueryStatus)}, {QStringLiteral("objectFieldFlags"), static_cast<qint64>(b.objectFieldFlags)},
                        {QStringLiteral("objectCapabilityMask"), hex(b.objectCapabilityMask)}, {QStringLiteral("creatorKnown"), b.creatorKnown},
                        {QStringLiteral("objectWitnessPfn"), hex(b.objectWitnessPfn)}, {QStringLiteral("objectWitnessVa"), hex(b.objectWitnessVa)},
                        {QStringLiteral("objectEvidence"), objectEvidenceJson(b.objectEvidence)}});
                }
                if (!write(QJsonObject{{QStringLiteral("kind"), QStringLiteral("backing_chunk")}, {QStringLiteral("firstIndex"), QString::number(first)}, {QStringLiteral("rows"), rows}})) { return; }
            }
            for (std::size_t first = 0; first < maps.rows.size(); first += 4096) {
                QJsonArray rows;
                for (std::size_t i = first; i < std::min(first + 4096, maps.rows.size()); ++i) {
                    const auto& m = maps.rows[i];
                    rows.append(QJsonObject{{QStringLiteral("pfn"), hex(m.pfn)}, {QStringLiteral("va"), hex(m.address)},
                        {QStringLiteral("pid"), static_cast<qint64>(m.pid)}, {QStringLiteral("processCreateTime"), QString::number(m.processCreateTime)},
                        {QStringLiteral("backingIndex"), static_cast<qint64>(m.backingIndex)}, {QStringLiteral("pageSize"), QString::number(m.pageSize)},
                        {QStringLiteral("locked"), m.locked}, {QStringLiteral("shared"), m.shared}, {QStringLiteral("shareCount"), static_cast<qint64>(m.shareCount)},
                        {QStringLiteral("attributesKnown"), m.attributesKnown}, {QStringLiteral("pfnRevalidated"), m.pfnRevalidated},
                        {QStringLiteral("nativeIdentityKnown"), m.nativeIdentityKnown}, {QStringLiteral("nativeFrameBefore"), hex(m.nativeFrameBefore)},
                        {QStringLiteral("nativeBackingBefore"), hex(m.nativeBackingBefore)}, {QStringLiteral("nativeFrame"), hex(m.nativeFrame)},
                        {QStringLiteral("nativeBacking"), hex(m.nativeBacking)}, {QStringLiteral("nativeFileKey"), hex(m.nativeFileKey)},
                        {QStringLiteral("nativeBeforeStatus"), status(m.nativeBeforeStatus)}, {QStringLiteral("nativeAfterStatus"), status(m.nativeAfterStatus)},
                        {QStringLiteral("mappingBeforeStatus"), status(m.mappingBeforeStatus)}, {QStringLiteral("mappingAfterStatus"), status(m.mappingAfterStatus)}});
                }
                if (!write(QJsonObject{{QStringLiteral("kind"), QStringLiteral("mapping_chunk")}, {QStringLiteral("firstIndex"), QString::number(first)}, {QStringLiteral("rows"), rows}})) { return; }
                job->rows.store(std::min(first + 4096, maps.rows.size()));
            }
            if (maps.consumers) {
                const auto& c = *maps.consumers;
                QJsonArray rows;
                for (const auto& r : c.relations) {
                    rows.append(QJsonObject{{QStringLiteral("kind"), static_cast<int>(r.kind)}, {QStringLiteral("pfn"), hex(r.pfn)},
                        {QStringLiteral("pid"), static_cast<qint64>(r.pid)}, {QStringLiteral("tid"), static_cast<qint64>(r.tid)},
                        {QStringLiteral("processCreateTime"), QString::number(r.processCreateTime)}, {QStringLiteral("processWitnessVa"), hex(r.processWitnessVa)},
                        {QStringLiteral("processWitnessPfn"), hex(r.processWitnessPfn)}, {QStringLiteral("threadObject"), hex(r.threadObject)},
                        {QStringLiteral("tableLevels"), static_cast<qint64>(r.tableLevels)}, {QStringLiteral("tag"), static_cast<qint64>(r.tag)},
                        {QStringLiteral("allocationVa"), hex(r.allocationVa)}, {QStringLiteral("allocationBytes"), QString::number(r.allocationBytes)},
                        {QStringLiteral("virtualAddress"), hex(r.virtualAddress)},
                        {QStringLiteral("nativeFrameBefore"), hex(r.nativeFrameBefore)}, {QStringLiteral("nativeBackingBefore"), hex(r.nativeBackingBefore)},
                        {QStringLiteral("nativeFrame"), hex(r.nativeFrame)}, {QStringLiteral("nativeBacking"), hex(r.nativeBacking)},
                        {QStringLiteral("processIdentityRevalidated"), r.processIdentityRevalidated}, {QStringLiteral("threadObjectRevalidated"), r.threadObjectRevalidated},
                        {QStringLiteral("threadCreationTimeKnown"), r.threadCreationTimeKnown}, {QStringLiteral("driverModuleKnown"), r.driverModuleKnown},
                        {QStringLiteral("translationBefore"), translationJson(r.translationBefore)}, {QStringLiteral("translationAfter"), translationJson(r.translationAfter)},
                        {QStringLiteral("translationFinal"), translationJson(r.translationFinal)}, {QStringLiteral("processWitnessBefore"), witnessJson(r.processWitnessBefore)},
                        {QStringLiteral("processWitnessAfter"), witnessJson(r.processWitnessAfter)}, {QStringLiteral("stackBefore"), stackJson(r.stackBefore)},
                        {QStringLiteral("stackAfter"), stackJson(r.stackAfter)}, {QStringLiteral("poolBefore"), poolJson(r.poolBefore)}, {QStringLiteral("poolAfter"), poolJson(r.poolAfter)}});
                }
                QJsonObject record{{QStringLiteral("kind"), QStringLiteral("consumer_relations")}, {QStringLiteral("observationEpoch"), c.epoch},
                    {QStringLiteral("observationDomain"), c.domain}, {QStringLiteral("ledgerContextEpoch"), c.ledgerContextEpoch},
                    {QStringLiteral("observationContextOnly"), true}, {QStringLiteral("tableProcesses"), static_cast<qint64>(c.tableProcesses)},
                    {QStringLiteral("threads"), static_cast<qint64>(c.threads)}, {QStringLiteral("bigPoolAllocations"), static_cast<qint64>(c.bigPoolAllocations)},
                    {QStringLiteral("started"), c.started}, {QStringLiteral("finished"), c.finished}, {QStringLiteral("rows"), rows},
                    {QStringLiteral("tableStatus"), status(c.tableStatus)}, {QStringLiteral("stackStatus"), status(c.stackStatus)},
                    {QStringLiteral("bigPoolStatus"), status(c.bigPoolStatus)}, {QStringLiteral("bigPoolRecheckStatus"), status(c.bigPoolRecheckStatus)},
                    {QStringLiteral("candidatePages"), QString::number(c.candidatePages)}, {QStringLiteral("failed"), QString::number(c.failed)},
                    {QStringLiteral("rejected"), QString::number(c.rejected)}, {QStringLiteral("distinct"), QString::number(c.distinct)},
                    {QStringLiteral("budgetReached"), c.budgetReached},
                    {QStringLiteral("cancelled"), c.cancelled}, {QStringLiteral("threadCreationProviderAvailable"), c.threadCreationProviderAvailable},
                    {QStringLiteral("lockOwnerProviderAvailable"), c.lockOwnerProviderAvailable}};
                if (!write(record)) { return; }
            }
            if (!write(QJsonObject{{QStringLiteral("kind"), QStringLiteral("footer")}, {QStringLiteral("retainedRowsWritten"), QString::number(maps.rows.size())},
                {QStringLiteral("retainedObjectsWritten"), QString::number(maps.backing.size())}, {QStringLiteral("retainedExportComplete"), true},
                {QStringLiteral("systemReferenceCoverageComplete"), false}})) { return; }
            if (!file.commit()) { job->error = file.errorString(); return; }
            metadata.insert(QStringLiteral("file"), QFileInfo(sidecar).fileName());
            metadata.insert(QStringLiteral("sha256"), QString::fromLatin1(hash.result().toHex()));
            metadata.insert(QStringLiteral("retainedExportComplete"), true);
        } else { metadata.insert(QStringLiteral("retainedExportComplete"), false); }
        root.insert(QStringLiteral("mappingEvidence"), metadata);
    }

    if (job->cancel.load()) { job->error = QStringLiteral("Evidence export cancelled"); return; }
    QSaveFile file(path); const auto data = QJsonDocument(root).toJson(QJsonDocument::Indented);
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) { job->error = file.errorString(); return; }
    job->saved = true;
        } catch (...) { job->error = QStringLiteral("Evidence export worker failed"); }
    }).detach(); } catch (...) { m_exportJob.reset(); m_summary->setText(L("Unable to start evidence export.")); }
    poll();
}
