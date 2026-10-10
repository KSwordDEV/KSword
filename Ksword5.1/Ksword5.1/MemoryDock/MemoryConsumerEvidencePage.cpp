#include "MemoryConsumerEvidencePage.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/CodeEditorWidget.h"
#include "PoolAllocationAnalysisWidget.h"
#include "../../../shared/evidence/GpuMemoryEvidence.h"
#include "../../../shared/evidence/PoolTraceCapturePolicy.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/TableInteractionSupport.h"
#include <Windows.h>
#include <QDateTime>
#include <QTimeZone>
#include <QEvent>
#include <QFileDialog>
#include <QFile>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QPlainTextEdit>
#include <QPointer>
#include <QProcess>
#include <QPushButton>
#include <QSaveFile>
#include <QSpinBox>
#include <QTabWidget>
#include <QTimer>
#include <QTimeZone>
#include <QTemporaryDir>
#include <QUuid>
#include <QVBoxLayout>
#include <atomic>
#include <mutex>
#include <thread>

namespace {
QString L(const char* text) { return ks::i18n::packedSourceText(QString::fromUtf8(text)); }
QString utc(std::uint64_t value)
{
    constexpr std::uint64_t unixEpoch = 116444736000000000ULL;
    return value >= unixEpoch ? QDateTime::fromMSecsSinceEpoch(static_cast<qint64>((value - unixEpoch) / 10000), QTimeZone::UTC).toString(Qt::ISODateWithMs) : L("Unavailable");
}
QString gpuMetricText(ksword::gpu_memory::Metric value)
{
    using M = ksword::gpu_memory::Metric;
    switch (value) {
    case M::AdapterShared: return L("GPU adapter shared system memory");
    case M::AdapterDedicated: return L("GPU adapter dedicated memory");
    case M::ProcessShared: return L("GPU process shared references");
    case M::ProcessDedicated: return L("GPU process dedicated references");
    }
    return L("Unavailable");
}
QStringList traceArguments(ksword::pool_trace::Action action, const QString& instance, const QString& output, const QString& profile = {})
{
    QStringList result;
    for (const auto& argument : ksword::pool_trace::arguments(action, instance.toStdWString(), output.toStdWString(), profile.toStdWString())) { result.push_back(QString::fromStdWString(argument)); }
    return result;
}
}
struct MemoryConsumerEvidencePage::GpuJob {
    std::atomic_bool cancel{false}, done{false};
    bool failed = false;
    ksword::gpu_memory::Snapshot snapshot;
};
MemoryConsumerEvidencePage::MemoryConsumerEvidencePage(QWidget* parent) : QWidget(parent)
{
    auto* layout = new QVBoxLayout(this);
    auto* controls = new QHBoxLayout;
    m_gpuButton = new QPushButton(this);
    m_traceStart = new QPushButton(this);
    m_traceStop = new QPushButton(this);
    m_duration = new QSpinBox(this);
    m_duration->setRange(5, 600); m_duration->setValue(30);
    controls->addWidget(m_gpuButton); controls->addWidget(m_traceStart);
    controls->addWidget(m_duration); controls->addWidget(m_traceStop);
    controls->addStretch(); layout->addLayout(controls);
    ks::ui::NormalizeToolbarRow(controls);
    m_note = new QLabel(this); m_note->setWordWrap(true); layout->addWidget(m_note);
    m_detailTabs = new QTabWidget(this);
    ks::ui::StylePageTabs(m_detailTabs);
    m_detailTabs->setMinimumSize(0, 0);
    m_detailTabs->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    auto* gpuPage = new QWidget(m_detailTabs);
    auto* gpuLayout = new QVBoxLayout(gpuPage);
    m_gpuStatus = new QLabel(gpuPage); m_gpuStatus->setWordWrap(true); gpuLayout->addWidget(m_gpuStatus);
    m_gpuTable = new ks::ui::VisibleTableWidget(gpuPage);
    // GPU 采样是独立证据清单，仍保留前后快照比较。
    ks::ui::SetTableActionBarMode(m_gpuTable, ks::ui::TableActionBarMode::Full);
    m_gpuTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_gpuTable->setAlternatingRowColors(true);
    m_gpuTable->horizontalHeader()->setStretchLastSection(true);
    gpuLayout->addWidget(m_gpuTable, 1);
    m_detailTabs->addTab(gpuPage, {});
    m_poolAnalysis = new PoolAllocationAnalysisWidget(m_detailTabs);
    m_poolAnalysis->setOpenModuleDetails([this](const QString& path) {
        const auto handler = openModuleDetails;
        if (handler) { handler(path); }
    });
    m_detailTabs->addTab(m_poolAnalysis, {});
    m_traceLog = new CodeEditorWidget(m_detailTabs);
    // 命令输出按原文追加，容量控制由统一外壳负责。
    m_traceLog->setReadOnly(true);
    m_traceLog->setMaximumBlockCount(300); m_detailTabs->addTab(m_traceLog, {});
    layout->addWidget(m_detailTabs, 1);
    m_captureTimer = new QTimer(this); m_captureTimer->setSingleShot(true);
    connect(m_captureTimer, &QTimer::timeout, this, [this] { stopTrace(); });
    m_commandTimer = new QTimer(this); m_commandTimer->setSingleShot(true);
    m_process = new QProcess(this);
    m_process->setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) { args->flags |= CREATE_NO_WINDOW; });
    connect(m_process, &QProcess::readyReadStandardOutput, this, [this] {
        appendCommandOutput(QString::fromLocal8Bit(m_process->readAllStandardOutput()));
    });
    connect(m_process, &QProcess::readyReadStandardError, this, [this] {
        appendCommandOutput(QString::fromLocal8Bit(m_process->readAllStandardError()));
    });
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
        [this](int code, QProcess::ExitStatus exit) { traceFinished(code, exit == QProcess::NormalExit); });
    connect(m_process, &QProcess::errorOccurred, this, [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            m_commandFailedToStart = true; appendCommandOutput(m_process->errorString());
            QTimer::singleShot(0, this, [this] { traceFinished(-1, false); });
        }
    });
    connect(m_commandTimer, &QTimer::timeout, this, [this] {
        if (m_shuttingDown || m_capture.pending == ksword::pool_trace::Command::None) { return; }
        m_commandTimedOut = true;
        appendCommandOutput(L("WPR command timed out; the instance state must be checked or cleaned up."));
        if (m_process->state() == QProcess::NotRunning) { traceFinished(-1, false); }
        else { m_process->kill(); }
    });
    connect(m_gpuButton, &QPushButton::clicked, this, [this] { startGpu(); });
    connect(m_traceStart, &QPushButton::clicked, this, [this] { startTrace(); });
    connect(m_traceStop, &QPushButton::clicked, this, [this] { stopTrace(); });
    auto* poll = new QTimer(this); poll->setInterval(150);
    connect(poll, &QTimer::timeout, this, [this] { pollGpu(); }); poll->start();
    retranslate(); m_traceStop->setEnabled(false);
}
MemoryConsumerEvidencePage::~MemoryConsumerEvidencePage()
{
    m_shuttingDown = true;
    m_captureTimer->stop(); m_commandTimer->stop();
    const auto cleanupAction = m_capture.shutdown();
    if (m_gpuJob) { m_gpuJob->cancel.store(true); }
    // waitForFinished can deliver finished synchronously. No command chain may
    // execute against a page while its destructor is running.
    m_process->disconnect(this);
    if (m_process->state() != QProcess::NotRunning) { m_process->kill(); m_process->waitForFinished(1000); }
    // Release only the UUID-named instance created by this page. Never run a
    // global WPR cancel, trim working sets, or alter tracing registry settings.
    if (cleanupAction != ksword::pool_trace::Action::None && !m_wpr.isEmpty()) {
        QProcess cleanup;
        cleanup.setCreateProcessArgumentsModifier([](QProcess::CreateProcessArguments* args) { args->flags |= CREATE_NO_WINDOW; });
        cleanup.setProgram(m_wpr);
        cleanup.setArguments(traceArguments(cleanupAction, m_instance, m_output));
        m_traceEvidence.insert(QStringLiteral("shutdownCleanupStarted"), cleanup.startDetached());
        m_traceEvidence.insert(QStringLiteral("shutdownCleanupResultKnown"), false);
        persistTrace();
    }
}
void MemoryConsumerEvidencePage::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event->type() == QEvent::LanguageChange) { retranslate(); rebuildGpu(); }
}
void MemoryConsumerEvidencePage::retranslate()
{
    m_gpuButton->setText(L("Collect GPU consumer evidence"));
    m_traceStart->setText(L("Capture pool allocation history"));
    m_detailTabs->setTabText(0, L("GPU consumers"));
    m_detailTabs->setTabText(1, L("Pool allocation analysis"));
    m_detailTabs->setTabText(2, L("Recorder output"));
    m_duration->setSuffix(L(" s"));
    m_note->setText(L("GPU counters are a separate, fallible consumer view. Process sharing is not summed into physical RAM; dedicated metrics can include UMA. Pool tracing requests 32 MiB of circular buffers; actual ETW overhead and event loss remain separate evidence. Only the chosen interval is observed; older allocations and overwritten events are unavailable."));
    if (!m_gpuResult) { m_gpuStatus->setText(L("GPU consumer evidence has not been collected.")); }
    m_gpuTable->setColumnCount(7);
    m_gpuTable->setHorizontalHeaderLabels({L("Consumer metric"), L("Instance"), L("PID observation"), L("Bytes"), L("Status"), L("Process identity"), L("Sample time")});
    updateTraceControls();
}
void MemoryConsumerEvidencePage::startGpu()
{
    if (m_gpuJob) { return; }
    m_gpuJob = std::make_shared<GpuJob>(); const auto job = m_gpuJob;
    m_gpuButton->setEnabled(false);
    try {
        std::thread([job] {
            try { ksword::gpu_memory::collect(job->snapshot, job->cancel); } catch (...) { job->failed = true; }
            job->done.store(true);
        }).detach();
    } catch (...) { m_gpuJob.reset(); m_gpuButton->setEnabled(true); m_traceLog->appendRawText(L("Unable to start the scan worker.")); }
}
void MemoryConsumerEvidencePage::pollGpu()
{
    if (!m_gpuJob || !m_gpuJob->done.load()) { return; }
    m_gpuResult = std::move(m_gpuJob); m_gpuButton->setEnabled(true); rebuildGpu();
}
void MemoryConsumerEvidencePage::rebuildGpu()
{
    if (!m_gpuResult) { return; }
    const auto& snapshot = m_gpuResult->snapshot;
    std::size_t known = 0;
    for (const auto& counter : snapshot.counters) { known += counter.valueKnown ? 1 : 0; }
    const QString status = snapshot.queryAttempted ? QStringLiteral("0x%1").arg(snapshot.queryStatus, 8, 16, QLatin1Char('0')) : L("Not queried");
    m_gpuStatus->setText(L("GPU query status: %1 | valid values %2 / %3. An empty or failed collection does not establish zero GPU memory usage.")
        .arg(status).arg(static_cast<qulonglong>(known)).arg(static_cast<qulonglong>(snapshot.counters.size())));
    m_gpuTable->setSortingEnabled(false); m_gpuTable->setRowCount(0);
    for (const auto& counter : m_gpuResult->snapshot.counters) {
        const int row = m_gpuTable->rowCount(); m_gpuTable->insertRow(row);
        m_gpuTable->setItem(row, 0, new QTableWidgetItem(gpuMetricText(counter.metric)));
        m_gpuTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdWString(counter.instance)));
        const bool process = ksword::gpu_memory::processMetric(counter.metric);
        m_gpuTable->setItem(row, 2, new QTableWidgetItem(counter.pid ? QString::number(counter.pid) : (process ? L("Unresolved") : L("Not applicable"))));
        m_gpuTable->setItem(row, 3, counter.valueKnown ? new ks::ui::NumericTableItem(QString::number(counter.bytes), static_cast<qulonglong>(counter.bytes)) : new QTableWidgetItem(L("Unavailable")));
        m_gpuTable->setItem(row, 4, new QTableWidgetItem(QStringLiteral("0x%1").arg(counter.status, 8, 16, QLatin1Char('0'))));
        m_gpuTable->setItem(row, 5, new QTableWidgetItem(counter.processIdentityKnown ? QString::number(counter.processCreateTime) : (process ? L("Unresolved") : L("Not applicable"))));
        m_gpuTable->setItem(row, 6, new QTableWidgetItem(utc(counter.sampledUtc100ns)));
    }
    m_gpuTable->setSortingEnabled(true); m_gpuTable->resizeColumnsToContents();
    if (m_gpuResult->failed || snapshot.queryStatus || snapshot.truncated || snapshot.cancelled || known < snapshot.counters.size() || snapshot.counters.empty()) {
        m_traceLog->appendRawText(L("GPU consumer collection is incomplete; unobserved values remain unavailable."));
    }
}
void MemoryConsumerEvidencePage::startTrace()
{
    using namespace ksword::pool_trace;
    if (!m_capture.canStart()) { return; }
    const QPointer<MemoryConsumerEvidencePage> guardedPage(this);
    const QString output = QFileDialog::getSaveFileName(this, L("Save pool allocation trace"), QStringLiteral("pool-allocation.etl"), L("ETL files (*.etl)"));
    if (!guardedPage || output.isEmpty() || !m_capture.canStart()) { return; }
    m_output = output;
    wchar_t system[MAX_PATH]{}; const UINT size = GetSystemDirectoryW(system, MAX_PATH);
    if (!size || size >= MAX_PATH) { m_traceLog->appendRawText(L("Windows Performance Recorder is unavailable.")); return; }
    m_wpr = QString::fromWCharArray(system) + QStringLiteral("/wpr.exe");
    if (!QFileInfo::exists(m_wpr)) { m_traceLog->appendRawText(L("Windows Performance Recorder is unavailable.")); return; }
    m_profileDirectory = std::make_unique<QTemporaryDir>();
    if (!m_profileDirectory->isValid()) { m_traceLog->appendRawText(L("The bounded pool profile could not be created.")); return; }
    const QString profilePath = m_profileDirectory->filePath(QStringLiteral("ksword-pool.wprp"));
    QFile profile(profilePath);
    const QByteArray xml(profileXml());
    if (!profile.open(QIODevice::WriteOnly) || profile.write(xml) != xml.size()) {
        m_traceLog->appendRawText(L("The bounded pool profile could not be created.")); return;
    }
    profile.close();
    m_profileSpec = profilePath + QStringLiteral("!KSwordPool");
    m_capture = {};
    m_instance = QStringLiteral("KSwordMemory_") + QUuid::createUuid().toString(QUuid::Id128);
    m_metadataOutput = m_output + QStringLiteral(".metadata-") + m_instance + QStringLiteral(".json");
    QFile reservation(m_metadataOutput);
    if (!reservation.open(QIODevice::WriteOnly | QIODevice::NewOnly)) {
        m_metadataOutput.clear();
        m_traceLog->appendRawText(L("Trace metadata could not be saved; the recording state is not inferred from a missing file."));
        return;
    }
    reservation.close();
    const QFileInfo previous(m_output);
    m_outputExisted = previous.exists(); m_previousOutputSize = previous.size();
    m_previousOutputModified = previous.lastModified().toMSecsSinceEpoch();
    m_captureDuration = m_duration->value();
    m_traceEvidence = {};
    m_traceEvidence.insert(QStringLiteral("schema"), QStringLiteral("ksword.pool.trace"));
    m_traceEvidence.insert(QStringLiteral("version"), 2);
    m_traceEvidence.insert(QStringLiteral("instance"), m_instance);
    m_traceEvidence.insert(QStringLiteral("output"), m_output);
    m_traceEvidence.insert(QStringLiteral("metadataOutput"), m_metadataOutput);
    m_traceEvidence.insert(QStringLiteral("durationSeconds"), m_captureDuration);
    m_traceEvidence.insert(QStringLiteral("profileXml"), QString::fromUtf8(xml));
    m_traceEvidence.insert(QStringLiteral("requestedBufferBytes"), QString::number(requestedBufferBytes));
    m_traceEvidence.insert(QStringLiteral("actualBufferBytesKnown"), false);
    m_traceEvidence.insert(QStringLiteral("eventsLostKnown"), false);
    m_traceEvidence.insert(QStringLiteral("preCaptureAllocationsCovered"), false);
    m_traceEvidence.insert(QStringLiteral("physicalPfnLinkageKnown"), false);
    m_traceEvidence.insert(QStringLiteral("captureIntervalExact"), false);
    runTrace({QStringLiteral("-help"), QStringLiteral("advanced")}, Command::Help);
}
void MemoryConsumerEvidencePage::appendCommandOutput(const QString& output)
{
    m_commandOutput += output;
    if (m_commandOutput.size() > 65536) { m_commandOutput = m_commandOutput.right(65536); m_commandOutputTruncated = true; }
}
void MemoryConsumerEvidencePage::updateTraceControls()
{
    m_traceStart->setEnabled(m_capture.canStart());
    m_traceStop->setEnabled(m_capture.canFinish());
    m_traceStop->setText(m_capture.mayOwnSession && !m_capture.recording() ? L("Retry instance cleanup") : L("Save allocation trace"));
    m_duration->setEnabled(m_capture.canStart());
}
void MemoryConsumerEvidencePage::runTrace(const QStringList& arguments, ksword::pool_trace::Command action)
{
    if (m_shuttingDown || arguments.isEmpty() || !m_capture.begin(action)) { return; }
    m_commandOutput.clear(); m_commandTimedOut = false; m_commandOutputTruncated = false; m_commandFailedToStart = false;
    m_commandStarted = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    updateTraceControls();
    m_process->setProgram(m_wpr); m_process->setArguments(arguments); m_process->start();
    m_commandTimer->start(ksword::pool_trace::commandTimeoutMs(action));
    persistTrace();
}
void MemoryConsumerEvidencePage::stopTrace()
{
    using namespace ksword::pool_trace;
    if (!m_capture.canFinish()) { return; }
    m_captureTimer->stop();
    if (m_capture.recording()) { runTrace(traceArguments(Action::Status, m_instance, m_output), Command::Status); }
    else { runTrace(traceArguments(Action::Cancel, m_instance, m_output), Command::Cancel); }
}
void MemoryConsumerEvidencePage::traceFinished(int exitCode, bool normal)
{
    using namespace ksword::pool_trace;
    const auto action = m_capture.pending;
    if (m_shuttingDown || action == Command::None) { return; }
    m_commandTimer->stop();
    appendCommandOutput(QString::fromLocal8Bit(m_process->readAllStandardOutput()));
    appendCommandOutput(QString::fromLocal8Bit(m_process->readAllStandardError()));
    const bool success = normal && exitCode == 0 && !m_commandTimedOut;
    const bool absent = (normal && noSessionExit(static_cast<std::uint32_t>(exitCode)))
        || (action == Command::Start && m_commandFailedToStart);
    const auto completion = m_commandTimedOut ? Completion::TimedOut : (absent ? Completion::NoSession : (success ? Completion::Success : Completion::Failed));
    const QFileInfo output(m_output);
    const bool outputVerified = verifiedNewOutput(output.isFile(), static_cast<std::uint64_t>(qMax<qint64>(0, output.size())),
        output.lastModified().toMSecsSinceEpoch(), m_outputExisted,
        static_cast<std::uint64_t>(qMax<qint64>(0, m_previousOutputSize)), m_previousOutputModified);
    m_capture.finish(completion, outputVerified);
    QJsonArray commands = m_traceEvidence.value(QStringLiteral("commands")).toArray();
    if (commands.size() < 64) {
        QJsonObject entry; entry.insert(QStringLiteral("action"), static_cast<int>(action));
        entry.insert(QStringLiteral("started"), m_commandStarted);
        entry.insert(QStringLiteral("program"), m_wpr);
        QJsonArray arguments;
        for (const auto& argument : m_process->arguments()) { arguments.append(argument); }
        entry.insert(QStringLiteral("arguments"), arguments);
        entry.insert(QStringLiteral("finished"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
        entry.insert(QStringLiteral("exitCode"), exitCode); entry.insert(QStringLiteral("normalExit"), normal);
        entry.insert(QStringLiteral("timedOut"), m_commandTimedOut);
        entry.insert(QStringLiteral("outputTruncated"), m_commandOutputTruncated);
        entry.insert(QStringLiteral("output"), m_commandOutput); commands.append(entry);
    } else { m_traceEvidence.insert(QStringLiteral("commandRetentionTruncated"), true); }
    m_traceEvidence.insert(QStringLiteral("commands"), commands);
    m_traceLog->appendRawText(m_commandOutput);
    if (action == Command::Help && success && !m_commandOutputTruncated && m_commandOutput.contains(QStringLiteral("-instancename"))) {
        runTrace({QStringLiteral("-profiles"), m_profileDirectory->filePath(QStringLiteral("ksword-pool.wprp"))}, Command::Profiles); return;
    }
    if (action == Command::Profiles && success && !m_commandOutputTruncated && m_commandOutput.contains(QStringLiteral("KSwordPool"))) {
        runTrace({QStringLiteral("-profiledetails"), m_profileSpec}, Command::ProfileDetails); return;
    }
    if (action == Command::ProfileDetails && success && !m_commandOutputTruncated
        && m_commandOutput.contains(QStringLiteral("KSwordPool.Verbose.Memory"))
        && m_commandOutput.contains(QStringLiteral("PoolAllocation")) && m_commandOutput.contains(QStringLiteral("PoolFree"))) {
        m_traceEvidence.insert(QStringLiteral("profileDetails"), m_commandOutput);
        m_traceLog->appendRawText(L("Pool tracing requests 32 MiB of buffers. Actual ETW overhead and event loss are not inferred from this requested budget."));
        runTrace(traceArguments(Action::Start, m_instance, m_output, m_profileSpec), Command::Start); return;
    }
    if (action == Command::Start && success) {
        m_traceEvidence.insert(QStringLiteral("startSucceeded"), true);
        m_traceEvidence.insert(QStringLiteral("started"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
        m_captureTimer->start(m_captureDuration * 1000);
        m_traceLog->appendRawText(L("Pool trace started. Only allocations observed during this interval can provide historical evidence."));
    } else if (action == Command::Status) {
        m_traceEvidence.insert(QStringLiteral("collectorStatusKnown"), success && !m_commandOutputTruncated);
        m_traceEvidence.insert(QStringLiteral("collectorStatus"), m_commandOutput);
        runTrace(traceArguments(Action::Stop, m_instance, m_output), Command::Stop); return;
    } else if (action == Command::Stop && m_capture.stoppedKnown) {
        m_traceEvidence.insert(QStringLiteral("saved"), m_capture.saved);
        m_traceEvidence.insert(QStringLiteral("finished"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs));
        if (m_capture.saved) {
            m_traceEvidence.insert(QStringLiteral("bytes"), QString::number(output.size()));
            m_traceLog->appendRawText(L("Allocation trace saved. Pool analysis shows observed allocations and capture gaps separately from the PFN ledger."));
        } else { m_traceLog->appendRawText(L("The recorder stopped, but a new nonempty ETL was not verified. The capture is not reported as saved.")); }
    } else if (action == Command::Stop && m_capture.mayOwnSession) {
        m_traceLog->appendRawText(L("Stopping or saving failed; releasing only this recording instance."));
        runTrace(traceArguments(Action::Cancel, m_instance, m_output), Command::Cancel); return;
    } else if (action == Command::Start || action == Command::Help || action == Command::Profiles || action == Command::ProfileDetails) {
        m_traceEvidence.insert(QStringLiteral("startSucceeded"), false);
        m_traceLog->appendRawText(L("Pool trace could not start. Check profile support, administrator access and the captured command status."));
        if (m_capture.mayOwnSession) { runTrace(traceArguments(Action::Cancel, m_instance, m_output), Command::Cancel); return; }
    }
    if (action == Command::Cancel && m_capture.mayOwnSession) { m_traceLog->appendRawText(L("Instance cleanup is unverified. Retry instance cleanup to release only this recording.")); }
    updateTraceControls();
    persistTrace();
    if (action == Command::Stop && m_capture.saved) {
        m_detailTabs->setCurrentWidget(m_poolAnalysis);
        m_poolAnalysis->analyzeFile(m_output);
    }
}
void MemoryConsumerEvidencePage::persistTrace()
{
    if (m_metadataOutput.isEmpty()) { return; }
    m_traceEvidence.insert(QStringLiteral("recordingState"), static_cast<int>(m_capture.session));
    m_traceEvidence.insert(QStringLiteral("pendingCommand"), static_cast<int>(m_capture.pending));
    m_traceEvidence.insert(QStringLiteral("mayOwnSession"), m_capture.mayOwnSession);
    m_traceEvidence.insert(QStringLiteral("stoppedKnown"), m_capture.stoppedKnown);
    m_traceEvidence.insert(QStringLiteral("saved"), m_capture.saved);
    QSaveFile file(m_metadataOutput);
    const auto metadataBytes = QJsonDocument(m_traceEvidence).toJson(QJsonDocument::Indented);
    if (!file.open(QIODevice::WriteOnly) || file.write(metadataBytes) != metadataBytes.size() || !file.commit()) {
        m_traceLog->appendRawText(L("Trace metadata could not be saved; the recording state is not inferred from a missing file."));
    }
}
QJsonObject MemoryConsumerEvidencePage::evidence() const
{
    QJsonObject result; result.insert(QStringLiteral("poolTrace"), m_traceEvidence);
    result.insert(QStringLiteral("gpuCollectionInProgress"), static_cast<bool>(m_gpuJob));
    if (!m_gpuResult) { result.insert(QStringLiteral("gpuCollected"), false); return result; }
    result.insert(QStringLiteral("gpuCollected"), true);
    const auto& snapshot = m_gpuResult->snapshot;
    QJsonObject gpu; gpu.insert(QStringLiteral("started"), utc(snapshot.startedUtc100ns));
    gpu.insert(QStringLiteral("finished"), utc(snapshot.finishedUtc100ns));
    gpu.insert(QStringLiteral("queryStatus"), static_cast<qint64>(snapshot.queryStatus));
    gpu.insert(QStringLiteral("queryAttempted"), snapshot.queryAttempted);
    gpu.insert(QStringLiteral("collectionAttempted"), snapshot.collectionAttempted);
    gpu.insert(QStringLiteral("firstCollectionAttempted"), snapshot.firstCollectionAttempted);
    gpu.insert(QStringLiteral("firstCollectionStatus"), static_cast<qint64>(snapshot.firstCollectionStatus));
    gpu.insert(QStringLiteral("failed"), m_gpuResult->failed);
    gpu.insert(QStringLiteral("truncated"), snapshot.truncated); gpu.insert(QStringLiteral("cancelled"), snapshot.cancelled);
    gpu.insert(QStringLiteral("physicalPfnLinkageKnown"), false);
    QJsonArray counters;
    for (const auto& row : snapshot.counters) {
        QJsonObject counter; counter.insert(QStringLiteral("metric"), static_cast<int>(row.metric));
        counter.insert(QStringLiteral("instance"), QString::fromStdWString(row.instance));
        counter.insert(QStringLiteral("path"), QString::fromStdWString(row.path));
        counter.insert(QStringLiteral("valueKnown"), row.valueKnown);
        if (row.valueKnown) { counter.insert(QStringLiteral("bytes"), QString::number(row.bytes)); }
        counter.insert(QStringLiteral("status"), static_cast<qint64>(row.status));
        counter.insert(QStringLiteral("pid"), static_cast<qint64>(row.pid));
        counter.insert(QStringLiteral("processIdentityKnown"), row.processIdentityKnown);
        counter.insert(QStringLiteral("processIdentityApplicable"), ksword::gpu_memory::processMetric(row.metric));
        if (row.processIdentityKnown) { counter.insert(QStringLiteral("processCreateTime"), QString::number(row.processCreateTime)); }
        counter.insert(QStringLiteral("sampledAt"), utc(row.sampledUtc100ns)); counters.append(counter);
    }
    gpu.insert(QStringLiteral("counters"), counters); result.insert(QStringLiteral("gpu"), gpu); return result;
}
