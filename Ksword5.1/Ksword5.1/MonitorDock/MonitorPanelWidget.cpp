#include "../Framework/BackgroundTaskRegistry.h"
#include "MonitorPanelWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../../../shared/ui/KsPainterChart.h"
#include "../../../shared/ui/MetricChartBinding.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/AsyncCleanupRegistry.h"

// ============================================================
// MonitorPanelWidget.cpp
// 作用：
// 1) 实现“监视面板”四宫格性能图（CPU/内存/磁盘/网络）；
// 2) CPU 使用每个逻辑核心单独柱状条展示；
// 3) 采样逻辑与 MonitorDock 解耦，避免 WMI/ETW 页面臃肿。
// ============================================================

#include "../theme.h"

#include <QCoreApplication>
#include <QDateTime>
#include <QEasingCurve>
#include <QEvent>
#include <QFrame>
#include <QGridLayout>
#include <QHideEvent>
#include <QFont>
#include <QLabel>
#include <QList>
#include <QPainter>
#include <QPointer>
#include <QResizeEvent>
#include <QShowEvent>
#include <QSizePolicy>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cmath>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_map>
#include <vector>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Pdh.h>
#include <pdhmsg.h>
#include <iphlpapi.h>
#include <netioapi.h>

#pragma comment(lib, "Pdh.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace
{
    // bytesPerSecondToText 作用：
    // - 把字节每秒速率转换成人类可读文本；
    // - 用于折线图标题中展示“读/写、上/下行”的即时速率。
    QString bytesPerSecondToText(const double bytesPerSecondValue)
    {
        const double safeValue = std::max(0.0, bytesPerSecondValue);
        if (safeValue < 1024.0)
        {
            return QStringLiteral("%1 B/s").arg(safeValue, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(safeValue / 1024.0, 0, 'f', 1);
        }
        if (safeValue < 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(safeValue / (1024.0 * 1024.0), 0, 'f', 2);
        }
        return QStringLiteral("%1 GB/s").arg(safeValue / (1024.0 * 1024.0 * 1024.0), 0, 'f', 2);
    }

    // createNoFrameChartView 作用：
    // - 创建无边框、抗锯齿图表视图；
    // - 统一监视面板视觉风格，避免默认方框边缘过重。
    QChartView* createNoFrameChartView(QChart* chartPtr, QWidget* parentWidget)
    {
        QChartView* chartView = new QChartView(chartPtr, parentWidget);
        chartView->setRenderHint(QPainter::Antialiasing, true);
        chartView->setFrameShape(QFrame::NoFrame);
        chartView->setMinimumHeight(0);
        chartView->setMaximumHeight(QWIDGETSIZE_MAX);
        chartView->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Ignored);
        return chartView;
    }

    // cpuBarColor 作用：返回 CPU 每核柱状图主色。
    QColor cpuBarColor()
    {
        return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu);
    }

    // memoryBarColor 作用：返回内存历史折线主色。
    QColor memoryBarColor()
    {
        return KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory);
    }

    // translucentAreaColor 作用：按主题和透明度生成内存组成面积填充色。
    QColor translucentAreaColor(const QColor& baseColor, const int alphaValue)
    {
        return KswordTheme::WithAlpha(baseColor, alphaValue);
    }

    // monitorPanelTextColor 作用：返回监视器图表标题/图例/轴标签颜色。
    QColor monitorPanelTextColor()
    {
        return KswordTheme::IsDarkModeEnabled()
            ? KswordTheme::WhiteColor()
            : KswordTheme::TextPrimaryColor();
    }

    // monitorPanelMutedTextColor 作用：返回监视器坐标轴次级文字颜色。
    QColor monitorPanelMutedTextColor()
    {
        return KswordTheme::IsDarkModeEnabled()
            ? KswordTheme::WhiteColor()
            : KswordTheme::TextSecondaryColor();
    }

    // MonitorPanelPdhCounterBundle 作用：
    // - 承载后台线程创建好的 PDH 查询与计数器句柄；
    // - 仅在采样线程内部转交句柄，GUI 从不接管原生查询。
    struct MonitorPanelPdhCounterBundle
    {
        void* cpuQueryHandle = nullptr;         // cpuQueryHandle：CPU 查询句柄。
        std::vector<void*> coreCounterHandles;  // coreCounterHandles：每个逻辑核心的计数器句柄。
        void* diskQueryHandle = nullptr;        // diskQueryHandle：磁盘查询句柄。
        void* diskReadCounterHandle = nullptr;  // diskReadCounterHandle：磁盘读取速率计数器句柄。
        void* diskWriteCounterHandle = nullptr; // diskWriteCounterHandle：磁盘写入速率计数器句柄。
    };

    // createMonitorPanelPdhCounters 作用：
    // - 入参 coreCount：逻辑核心数量，决定注册多少个 \Processor(n) 计数器；
    // - 入参 needCpuCounters/needDiskCounters：控件尚未持有对应句柄时才重新创建，避免重试轮空跑；
    // - 处理：在调用线程完成 PdhOpenQueryW/PdhAddEnglishCounterW 与首次基线采集，
    //         进程内第一次调用会顺带加载 perflib 计数器名索引，耗时集中在这里；
    // - 返回：句柄集合，失败字段保持 nullptr 由调用方按空句柄回退。
    MonitorPanelPdhCounterBundle createMonitorPanelPdhCounters(
        const int coreCount,
        const bool needCpuCounters,
        const bool needDiskCounters,
        const std::atomic_bool& stopping)
    {
        MonitorPanelPdhCounterBundle counterBundle;

        // CPU 每核计数器：为每一个核心添加 \Processor(n)\% Processor Time。
        PDH_HQUERY cpuQueryHandle = nullptr;
        if (needCpuCounters && !stopping.load()
            && ::PdhOpenQueryW(nullptr, 0, &cpuQueryHandle) == ERROR_SUCCESS
            && cpuQueryHandle != nullptr)
        {
            std::unique_ptr<void, decltype(&::PdhCloseQuery)> queryOwner(cpuQueryHandle, &::PdhCloseQuery);
            const int safeCoreCount = std::max(0, coreCount);
            counterBundle.coreCounterHandles.reserve(static_cast<std::size_t>(safeCoreCount));
            for (int coreIndex = 0; coreIndex < safeCoreCount; ++coreIndex)
            {
                if (stopping.load()) return counterBundle;
                const QString counterPath = QStringLiteral("\\Processor(%1)\\% Processor Time").arg(coreIndex);
                PDH_HCOUNTER cpuCounterHandle = nullptr;
                const PDH_STATUS addCounterStatus = ::PdhAddEnglishCounterW(
                    cpuQueryHandle,
                    reinterpret_cast<LPCWSTR>(counterPath.utf16()),
                    0,
                    &cpuCounterHandle);
                if (addCounterStatus != ERROR_SUCCESS || cpuCounterHandle == nullptr)
                {
                    // 某核心计数器创建失败时保留 nullptr，占位后续填 0。
                    counterBundle.coreCounterHandles.push_back(nullptr);
                    continue;
                }
                counterBundle.coreCounterHandles.push_back(cpuCounterHandle);
            }

            // 首次 collect 先建立基线，下一次采样得到稳定数据。
            if (stopping.load()) return counterBundle;
            ::PdhCollectQueryData(cpuQueryHandle);
            counterBundle.cpuQueryHandle = queryOwner.release();
        }

        // 磁盘计数器：读取系统总磁盘读写字节每秒速率，失败时整体丢弃。
        PDH_HQUERY diskQueryHandle = nullptr;
        if (needDiskCounters && !stopping.load()
            && ::PdhOpenQueryW(nullptr, 0, &diskQueryHandle) == ERROR_SUCCESS
            && diskQueryHandle != nullptr)
        {
            std::unique_ptr<void, decltype(&::PdhCloseQuery)> queryOwner(diskQueryHandle, &::PdhCloseQuery);
            PDH_HCOUNTER readCounterHandle = nullptr;
            PDH_HCOUNTER writeCounterHandle = nullptr;

            const PDH_STATUS addReadStatus = ::PdhAddEnglishCounterW(
                diskQueryHandle,
                L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                0,
                &readCounterHandle);
            if (stopping.load()) return counterBundle;
            const PDH_STATUS addWriteStatus = ::PdhAddEnglishCounterW(
                diskQueryHandle,
                L"\\PhysicalDisk(_Total)\\Disk Write Bytes/sec",
                0,
                &writeCounterHandle);

            if (addReadStatus == ERROR_SUCCESS
                && addWriteStatus == ERROR_SUCCESS
                && readCounterHandle != nullptr
                && writeCounterHandle != nullptr)
            {
                if (stopping.load()) return counterBundle;
                ::PdhCollectQueryData(diskQueryHandle);
                counterBundle.diskQueryHandle = queryOwner.release();
                counterBundle.diskReadCounterHandle = readCounterHandle;
                counterBundle.diskWriteCounterHandle = writeCounterHandle;
            }
        }

        return counterBundle;
    }


}

// Native state and receipts contain values only. The worker never borrows a QObject.
struct MonitorPanelWidget::SamplingReceipt final
{
    MetricPresentationSample sample;
    bool hasSample = false;
    std::atomic_bool finished{false};
};

struct MonitorPanelWidget::SamplingState final
{
    struct Request
    {
        std::shared_ptr<SamplingReceipt> receipt;
        std::function<void()> completion; // Constructed on GUI; only handed to the existing dispatcher.
    };
    struct NetworkBaseline { std::uint64_t rx = 0, tx = 0, timeMs = 0; };
    SamplingState(int count, std::shared_ptr<ks::ui::AsyncUiDispatcher> target)
        : coreCount(count), dispatcher(std::move(target)) {}

    const int coreCount;
    const std::shared_ptr<ks::ui::AsyncUiDispatcher> dispatcher;
    std::mutex mutex;
    std::condition_variable wake;
    std::optional<Request> pending;
    std::atomic_bool stopping{false}, finished{false};
    void* m_cpuPerfQueryHandle = nullptr;
    std::vector<void*> m_coreCounterHandles;
    void* m_diskPerfQueryHandle = nullptr;
    void* m_diskReadCounterHandle = nullptr;
    void* m_diskWriteCounterHandle = nullptr;
    std::unordered_map<std::uint64_t, NetworkBaseline> networkBaselines;

    void requestStop()
    {
        { std::lock_guard<std::mutex> lock(mutex); stopping.store(true); }
        wake.notify_one();
    }
    bool request(Request value)
    {
        std::lock_guard<std::mutex> lock(mutex);
        if (stopping.load() || pending) return false;
        pending = std::move(value);
        wake.notify_one();
        return true;
    }
    void retireCpuQuery()
    {
        if (m_cpuPerfQueryHandle) ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
        m_cpuPerfQueryHandle = nullptr;
        m_coreCounterHandles.clear();
    }
    void retireDiskQuery()
    {
        if (m_diskPerfQueryHandle) ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle));
        m_diskPerfQueryHandle = nullptr;
        m_diskReadCounterHandle = nullptr;
        m_diskWriteCounterHandle = nullptr;
    }
    void initializeCounters()
    {
        if (m_cpuPerfQueryHandle && m_diskPerfQueryHandle) return;
        auto counters = createMonitorPanelPdhCounters(coreCount,
            m_cpuPerfQueryHandle == nullptr, m_diskPerfQueryHandle == nullptr, stopping);
        if (counters.cpuQueryHandle)
        {
            m_cpuPerfQueryHandle = counters.cpuQueryHandle;
            m_coreCounterHandles = std::move(counters.coreCounterHandles);
        }
        if (counters.diskQueryHandle)
        {
            m_diskPerfQueryHandle = counters.diskQueryHandle;
            m_diskReadCounterHandle = counters.diskReadCounterHandle;
            m_diskWriteCounterHandle = counters.diskWriteCounterHandle;
        }
    }
    bool samplePerCoreCpuUsage(std::vector<double>*, double*);
    bool sampleMemoryUsage(MemoryCompositionSample*) const;
    bool sampleDiskRate(double*, double*);
    bool sampleNetworkRate(double*, double*);
    void collect(MetricPresentationSample& sample)
    {
        initializeCounters();
        if (stopping.load()) return;
        if (!samplePerCoreCpuUsage(&sample.coreUsages, &sample.totalCpuUsage))
        {
            sample.coreUsages.assign(static_cast<std::size_t>(coreCount), 0.0);
            sample.totalCpuUsage = 0.0;
        }
        if (stopping.load()) return;
        sample.memoryValid = sampleMemoryUsage(&sample.memory);
        if (stopping.load()) return;
        sample.diskValid = sampleDiskRate(&sample.diskReadBytesPerSec, &sample.diskWriteBytesPerSec);
        if (stopping.load()) return;
        sample.networkValid = sampleNetworkRate(&sample.networkRxBytesPerSec, &sample.networkTxBytesPerSec);
    }
    void run() noexcept
    {
        try
        {
            for (;;)
            {
                Request value;
                {
                    std::unique_lock<std::mutex> lock(mutex);
                    wake.wait(lock, [this] { return stopping.load() || pending.has_value(); });
                    if (stopping.load()) break;
                    value = std::move(*pending);
                    pending.reset();
                }
                try { collect(value.receipt->sample); }
                catch (...) { value.receipt->sample = {}; } // A failed round is a gap, never a stuck gate.
                value.receipt->sample.sampleTimeMs = QDateTime::currentMSecsSinceEpoch();
                value.receipt->hasSample = !stopping.load();
                value.receipt->finished.store(true, std::memory_order_release);
                if (!stopping.load())
                {
                    try { dispatcher->post(std::move(value.completion)); }
                    catch (...) {} // Receipt is already physically finished; the GUI tick recovers it.
                }
            }
        }
        catch (...) { stopping.store(true); }
        // Retire every pending receipt and native resource on this same worker, before its exit lease returns.
        std::optional<Request> unstarted;
        { std::lock_guard<std::mutex> lock(mutex); stopping.store(true); unstarted = std::move(pending); pending.reset(); }
        if (unstarted) unstarted->receipt->finished.store(true, std::memory_order_release);
        retireCpuQuery();
        retireDiskQuery();
        networkBaselines.clear();
        finished.store(true, std::memory_order_release);
    }
};

bool MonitorPanelWidget::SamplingState::samplePerCoreCpuUsage(
    std::vector<double>* coreUsagesOut,
    double* totalUsageOut)
{
    if (coreUsagesOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }

    if (m_cpuPerfQueryHandle == nullptr)
    {
        return false;
    }

    const PDH_STATUS collectStatus = ::PdhCollectQueryData(
        reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
    if (collectStatus != ERROR_SUCCESS)
    {
        retireCpuQuery();
        return false;
    }

    coreUsagesOut->clear();
    coreUsagesOut->reserve(m_coreCounterHandles.size());

    double usageSum = 0.0;
    int validCoreCount = 0;
    for (void* counterHandleVoid : m_coreCounterHandles)
    {
        if (counterHandleVoid == nullptr)
        {
            coreUsagesOut->push_back(0.0);
            continue;
        }

        PDH_FMT_COUNTERVALUE counterValue{};
        const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
            reinterpret_cast<PDH_HCOUNTER>(counterHandleVoid),
            PDH_FMT_DOUBLE,
            nullptr,
            &counterValue);
        if (readStatus != ERROR_SUCCESS
            || (counterValue.CStatus != PDH_CSTATUS_VALID_DATA && counterValue.CStatus != PDH_CSTATUS_NEW_DATA)
            || !std::isfinite(counterValue.doubleValue))
        {
            coreUsagesOut->push_back(0.0);
            continue;
        }

        const double usageValue = std::clamp(counterValue.doubleValue, 0.0, 100.0);
        coreUsagesOut->push_back(usageValue);
        usageSum += usageValue;
        ++validCoreCount;
    }

    *totalUsageOut = validCoreCount > 0
        ? usageSum / static_cast<double>(validCoreCount)
        : 0.0;
    return true;
}

bool MonitorPanelWidget::SamplingState::sampleMemoryUsage(MemoryCompositionSample* memorySampleOut) const
{
    if (memorySampleOut == nullptr)
    {
        return false;
    }

    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    if (::GlobalMemoryStatusEx(&memoryStatus) == FALSE)
    {
        *memorySampleOut = MemoryCompositionSample{};
        return false;
    }

    const double totalPhysBytes = static_cast<double>(memoryStatus.ullTotalPhys);
    const double availablePhysBytes = static_cast<double>(memoryStatus.ullAvailPhys);
    const double usedPhysBytes = std::max(0.0, totalPhysBytes - availablePhysBytes);
    const double totalCommitBytes = static_cast<double>(memoryStatus.ullTotalPageFile);
    const double availableCommitBytes = static_cast<double>(memoryStatus.ullAvailPageFile);
    const double usedCommitBytes = std::max(0.0, totalCommitBytes - availableCommitBytes);

    MemoryCompositionSample sample{};
    if (totalPhysBytes > 0.0)
    {
        sample.usedPercent = std::clamp(usedPhysBytes * 100.0 / totalPhysBytes, 0.0, 100.0);
        sample.availablePercent = std::clamp(availablePhysBytes * 100.0 / totalPhysBytes, 0.0, 100.0);
    }
    sample.commitPercent = totalCommitBytes > 0.0
        ? std::clamp(usedCommitBytes * 100.0 / totalCommitBytes, 0.0, 100.0)
        : sample.usedPercent;
    sample.standbyPercent = std::clamp(sample.commitPercent - sample.usedPercent, 0.0, 100.0);
    const double totalStackPercent = sample.usedPercent + sample.standbyPercent + sample.availablePercent;
    if (totalStackPercent > 100.0 && totalStackPercent > 0.0)
    {
        sample.availablePercent = std::max(0.0, 100.0 - sample.usedPercent - sample.standbyPercent);
    }

    *memorySampleOut = sample;
    return true;
}

bool MonitorPanelWidget::SamplingState::sampleDiskRate(
    double* readBytesPerSecOut,
    double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (m_diskPerfQueryHandle == nullptr
        || m_diskReadCounterHandle == nullptr
        || m_diskWriteCounterHandle == nullptr)
    {
        return false;
    }

    const PDH_HQUERY diskQueryHandle = reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle);
    const PDH_STATUS collectStatus = ::PdhCollectQueryData(diskQueryHandle);
    if (collectStatus != ERROR_SUCCESS)
    {
        retireDiskQuery();
        return false;
    }

    PDH_FMT_COUNTERVALUE readCounterValue{};
    PDH_FMT_COUNTERVALUE writeCounterValue{};
    const PDH_STATUS readStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskReadCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &readCounterValue);
    const PDH_STATUS writeStatus = ::PdhGetFormattedCounterValue(
        reinterpret_cast<PDH_HCOUNTER>(m_diskWriteCounterHandle),
        PDH_FMT_DOUBLE,
        nullptr,
        &writeCounterValue);
    if (readStatus != ERROR_SUCCESS || writeStatus != ERROR_SUCCESS
        || (readCounterValue.CStatus != PDH_CSTATUS_VALID_DATA && readCounterValue.CStatus != PDH_CSTATUS_NEW_DATA)
        || (writeCounterValue.CStatus != PDH_CSTATUS_VALID_DATA && writeCounterValue.CStatus != PDH_CSTATUS_NEW_DATA)
        || !std::isfinite(readCounterValue.doubleValue) || !std::isfinite(writeCounterValue.doubleValue))
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readCounterValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeCounterValue.doubleValue);
    return true;
}

bool MonitorPanelWidget::SamplingState::sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut)
{
    *rxBytesPerSecOut = 0.0;
    *txBytesPerSecOut = 0.0;
    MIB_IF_TABLE2* table = nullptr;
    if (::GetIfTable2(&table) != NO_ERROR || table == nullptr) return false;
    const std::unique_ptr<MIB_IF_TABLE2, decltype(&::FreeMibTable)> tableOwner(table, &::FreeMibTable);
    const auto now = static_cast<std::uint64_t>(::GetTickCount64());
    std::unordered_map<std::uint64_t, NetworkBaseline> next;
    next.reserve(table->NumEntries);
    for (ULONG index = 0; index < table->NumEntries; ++index)
    {
        const auto& row = table->Table[index];
        // Keep the original up/non-loopback scope; only the baseline is per identity.
        if (row.OperStatus != IfOperStatusUp || row.Type == IF_TYPE_SOFTWARE_LOOPBACK) continue;
        const std::uint64_t identity = row.InterfaceLuid.Value;
        const NetworkBaseline current{row.InOctets, row.OutOctets, now};
        const auto previous = networkBaselines.find(identity);
        if (previous != networkBaselines.end() && now > previous->second.timeMs)
        {
            const double elapsed = static_cast<double>(now - previous->second.timeMs);
            if (current.rx >= previous->second.rx)
                *rxBytesPerSecOut += static_cast<double>(current.rx - previous->second.rx) * 1000.0 / elapsed;
            if (current.tx >= previous->second.tx)
                *txBytesPerSecOut += static_cast<double>(current.tx - previous->second.tx) * 1000.0 / elapsed;
        }
        next.emplace(identity, current);
    }
    networkBaselines.swap(next); // Removed/down devices must establish a new baseline on return.
    return true;
}

MonitorPanelWidget::MonitorPanelWidget(QWidget* parent)
    : QWidget(parent)
{
    // 构造日志使用同一个 kLogEvent，方便按 GUID 追踪整个初始化流程。
    kLogEvent event;
    info << event << "[MonitorPanelWidget] 构造开始。" << eol;

    initializeUi();
    m_samplingDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(this);

    // 采样定时器：
    // - 每秒最多接纳一轮后台采样；
    // - UI 只消费完成值和投影，不执行原生查询。
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(1000);
    ks::ui::BackgroundTaskRegistry::Policy taskPolicy_monitor_metrics;
    taskPolicy_monitor_metrics.canPause = true;
    taskPolicy_monitor_metrics.canChangeInterval = true;
    taskPolicy_monitor_metrics.allowMultipleInstances = false;
    taskPolicy_monitor_metrics.minimumIntervalMs = 50;
    ks::ui::BackgroundTaskRegistry::instance().addTimer(QStringLiteral("monitor.metrics"),
        QStringLiteral("系统指标采样"), QStringLiteral("监控"), m_refreshTimer, std::move(taskPolicy_monitor_metrics));
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        refreshMetrics();
    });
    m_refreshTimer->start();
    refreshMetrics();

    info << event << "[MonitorPanelWidget] 构造完成。" << eol;
}

MonitorPanelWidget::~MonitorPanelWidget()
{
    if (m_samplingDispatcher) m_samplingDispatcher->close();
    if (m_refreshTimer) m_refreshTimer->stop();
    if (m_samplingState) m_samplingState->requestStop();
    m_samplingState.reset(); // The worker/cleanup lease, never QWidget, owns native cleanup.
}

void MonitorPanelWidget::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    updateCompactVisibility();
    adjustChartCellHeights();
}

void MonitorPanelWidget::showEvent(QShowEvent* showEventPointer)
{
    // 映射事件先于 windowState 的平台路径也可正确恢复，不能只查 isMinimized。
    const QPointer<MonitorPanelWidget> owner(this);
    m_presentationExposed = true;
    QWidget::showEvent(showEventPointer);
    if (!owner) return;
    updateCompactVisibility();
    if (m_chartThemeDirty) applyChartTextTheme();
    reconcileMetrics();
    if (!owner) return;
    refreshVisiblePresentation(true);
    if (!owner) return;
    adjustChartCellHeights();
    // Future real geometry changes arrive through resizeEvent; do not guess
    // stability by traversing the same charts again at 0ms and 80ms.
}

void MonitorPanelWidget::hideEvent(QHideEvent* hideEventPointer)
{
    m_presentationExposed = false;
    QWidget::hideEvent(hideEventPointer);
}

void MonitorPanelWidget::changeEvent(QEvent* eventPointer)
{
    QWidget::changeEvent(eventPointer);
    if (eventPointer == nullptr)
    {
        return;
    }

    const QEvent::Type eventType = eventPointer->type();
    if (eventType == QEvent::PaletteChange || eventType == QEvent::ApplicationPaletteChange
        || eventType == QEvent::StyleChange || eventType == QEvent::LanguageChange
        || eventType == QEvent::FontChange || eventType == QEvent::ApplicationFontChange)
    {
        m_chartThemeDirty = true;
        m_chartPresentationDirty = true;
        if (m_presentationExposed && isVisible())
        {
            updateCompactVisibility();
            applyChartTextTheme();
            refreshVisiblePresentation(true);
        }
    }
}

void MonitorPanelWidget::initializeUi()
{
    // 根布局：
    // - 四宫格图表占满整个监视面板；
    // - 间距统一为 6，和全项目 Dock 风格一致。
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(2, 2, 2, 2);
    m_rootLayout->setSpacing(2);

    m_compactSummaryLabel = new QLabel(this);
    m_compactSummaryLabel->setAlignment(Qt::AlignCenter);
    m_compactSummaryLabel->setWordWrap(true);
    m_compactSummaryLabel->setVisible(false);
    m_compactSummaryLabel->setText(ks::i18n::contextText(
        QStringLiteral("monitor.panel.compact.hidden"), QStringLiteral("监视面板高度过低，已隐藏图表。")));
    m_rootLayout->addWidget(m_compactSummaryLabel, 1);

    m_chartGridLayout = new QGridLayout();
    m_chartGridLayout->setContentsMargins(0, 0, 0, 0);
    m_chartGridLayout->setHorizontalSpacing(2);
    m_chartGridLayout->setVerticalSpacing(2);
    m_rootLayout->addLayout(m_chartGridLayout, 1);

    // ===================== CPU 每核柱状图 =====================
    const int logicalCoreCount = static_cast<int>(
        std::max<DWORD>(1, ::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));
    QStringList cpuCategoryTextList;
    cpuCategoryTextList.reserve(logicalCoreCount);

    m_cpuCoreHistoryBarSet = new QBarSet(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.history"), QStringLiteral("历史")));
    QColor cpuHistoryColor = cpuBarColor();
    cpuHistoryColor.setAlpha(86);
    m_cpuCoreHistoryBarSet->setColor(cpuHistoryColor);
    m_cpuCoreHistoryBarSet->setBorderColor(Qt::transparent);

    m_cpuCoreBarSet = new QBarSet(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.current"), QStringLiteral("当前")));
    m_cpuCoreBarSet->setColor(cpuBarColor());
    m_cpuCoreBarSet->setBorderColor(cpuBarColor());

    for (int coreIndex = 0; coreIndex < logicalCoreCount; ++coreIndex)
    {
        m_cpuCoreHistoryBarSet->append(0.0);
        m_cpuCoreBarSet->append(0.0);
        cpuCategoryTextList.push_back(QString::number(coreIndex));
    }
    m_cpuCoreHistoryPercentList.assign(static_cast<std::size_t>(logicalCoreCount), 0.0);

    QBarSeries* cpuBarSeries = new QBarSeries(this);
    cpuBarSeries->append(m_cpuCoreHistoryBarSet);
    cpuBarSeries->append(m_cpuCoreBarSet);

    QChart* cpuChart = new QChart();
    cpuChart->addSeries(cpuBarSeries);
    cpuChart->legend()->hide();
    cpuChart->setBackgroundVisible(false);
    cpuChart->setBackgroundRoundness(0);
    cpuChart->setMargins(QMargins(0, 0, 0, 0));
    cpuChart->setTitle(ks::i18n::contextText(
        QStringLiteral("monitor.panel.cpu.title"), QStringLiteral("CPU 每核心利用率")));

    QBarCategoryAxis* cpuAxisX = new QBarCategoryAxis(cpuChart);
    cpuAxisX->append(cpuCategoryTextList);
    cpuAxisX->setGridLineVisible(false);
    cpuAxisX->setLabelsVisible(logicalCoreCount <= 24);

    QValueAxis* cpuAxisY = new QValueAxis(cpuChart);
    cpuAxisY->setRange(0.0, 100.0);
    cpuAxisY->setLabelsVisible(false);
    cpuAxisY->setGridLineVisible(false);
    cpuAxisY->setMinorGridLineVisible(false);

    cpuChart->addAxis(cpuAxisX, Qt::AlignBottom);
    cpuChart->addAxis(cpuAxisY, Qt::AlignLeft);
    cpuBarSeries->attachAxis(cpuAxisX);
    cpuBarSeries->attachAxis(cpuAxisY);
    m_cpuChartView = createNoFrameChartView(cpuChart, this);

    // ===================== 内存占用与组成合并趋势图 =====================
    m_memoryUsedSeries = new QLineSeries(this);
    m_memoryStandbyTopSeries = new QLineSeries(this);
    m_memoryStandbyBaseSeries = new QLineSeries(this);
    m_memoryAvailableTopSeries = new QLineSeries(this);
    m_memoryAvailableBaseSeries = new QLineSeries(this);
    m_memoryUsageSeries = new QLineSeries(this);

    m_memoryUsedSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.used"), QStringLiteral("已用")));
    m_memoryStandbyTopSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.cached"), QStringLiteral("提交/缓存")));
    m_memoryAvailableTopSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.available"), QStringLiteral("可用")));
    m_memoryUsageSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.usage"), QStringLiteral("占用")));

    // 组成色沿用“已用=蓝 / 提交缓存=橙 / 可用=绿”的语义配色，
    // 但改从主题角色取色：偏移量与磁盘/网络两张图的 Read/Write/Disk 一致，
    // 四张图在深浅主题与自定义强调色下保持成套。
    const QColor memoryUsedColor =
        KswordTheme::AccentColor(KswordTheme::AccentRole::Blue, 30, 4);
    const QColor memoryStandbyColor =
        KswordTheme::AccentColor(KswordTheme::AccentRole::Orange, 40, 14);
    const QColor memoryAvailableColor =
        KswordTheme::AccentColor(KswordTheme::AccentRole::Green, 40, 14);
    QPen memoryUsedPen(memoryUsedColor);
    QPen memoryStandbyPen(memoryStandbyColor);
    QPen memoryAvailablePen(memoryAvailableColor);
    QPen memoryTrendPen(memoryBarColor());
    memoryUsedPen.setWidthF(1.0);
    memoryStandbyPen.setWidthF(1.0);
    memoryAvailablePen.setWidthF(1.0);
    memoryTrendPen.setWidthF(2.6);
    m_memoryUsedSeries->setPen(memoryUsedPen);
    m_memoryStandbyTopSeries->setPen(memoryStandbyPen);
    m_memoryStandbyBaseSeries->setPen(QPen(Qt::transparent));
    m_memoryAvailableTopSeries->setPen(memoryAvailablePen);
    m_memoryAvailableBaseSeries->setPen(QPen(Qt::transparent));
    m_memoryUsageSeries->setPen(memoryTrendPen);

    QAreaSeries* usedAreaSeries = new QAreaSeries(m_memoryUsedSeries);
    usedAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.used"), QStringLiteral("已用")));
    usedAreaSeries->setPen(memoryUsedPen);
    usedAreaSeries->setBrush(QBrush(translucentAreaColor(memoryUsedColor, 82)));

    QAreaSeries* standbyAreaSeries = new QAreaSeries(m_memoryStandbyTopSeries, m_memoryStandbyBaseSeries);
    standbyAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.cached"), QStringLiteral("提交/缓存")));
    standbyAreaSeries->setPen(memoryStandbyPen);
    standbyAreaSeries->setBrush(QBrush(translucentAreaColor(memoryStandbyColor, 76)));

    QAreaSeries* availableAreaSeries = new QAreaSeries(m_memoryAvailableTopSeries, m_memoryAvailableBaseSeries);
    availableAreaSeries->setName(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.available"), QStringLiteral("可用")));
    availableAreaSeries->setPen(memoryAvailablePen);
    availableAreaSeries->setBrush(QBrush(translucentAreaColor(memoryAvailableColor, 58)));

    QChart* memoryTrendChart = new QChart();
    memoryTrendChart->addSeries(usedAreaSeries);
    memoryTrendChart->addSeries(standbyAreaSeries);
    memoryTrendChart->addSeries(availableAreaSeries);
    memoryTrendChart->addSeries(m_memoryUsageSeries);
    memoryTrendChart->legend()->hide();
    memoryTrendChart->setBackgroundVisible(false);
    memoryTrendChart->setBackgroundRoundness(0);
    memoryTrendChart->setMargins(QMargins(0, 0, 0, 0));
    memoryTrendChart->setTitle(ks::i18n::contextText(
        QStringLiteral("monitor.panel.memory.title"), QStringLiteral("内存占用与组成")));

    m_memoryTrendAxisX = new QValueAxis(memoryTrendChart);
    m_memoryTrendAxisX->setRange(0, m_historyLength);
    m_memoryTrendAxisX->setLabelsVisible(false);
    m_memoryTrendAxisX->setGridLineVisible(false);
    m_memoryTrendAxisX->setMinorGridLineVisible(false);
    m_memoryTrendAxisY = new QValueAxis(memoryTrendChart);
    m_memoryTrendAxisY->setRange(0.0, 100.0);
    m_memoryTrendAxisY->setLabelsVisible(false);
    m_memoryTrendAxisY->setGridLineVisible(false);
    m_memoryTrendAxisY->setMinorGridLineVisible(false);

    memoryTrendChart->addAxis(m_memoryTrendAxisX, Qt::AlignBottom);
    memoryTrendChart->addAxis(m_memoryTrendAxisY, Qt::AlignLeft);
    usedAreaSeries->attachAxis(m_memoryTrendAxisX);
    usedAreaSeries->attachAxis(m_memoryTrendAxisY);
    standbyAreaSeries->attachAxis(m_memoryTrendAxisX);
    standbyAreaSeries->attachAxis(m_memoryTrendAxisY);
    availableAreaSeries->attachAxis(m_memoryTrendAxisX);
    availableAreaSeries->attachAxis(m_memoryTrendAxisY);
    m_memoryUsageSeries->attachAxis(m_memoryTrendAxisX);
    m_memoryUsageSeries->attachAxis(m_memoryTrendAxisY);
    m_memoryTrendChartView = createNoFrameChartView(memoryTrendChart, this);

    // ===================== 折线图创建器（磁盘/网络复用） =====================
    auto createLineChartView =
        [this](
            const QString& titleText,
            const QColor& firstColor,
            const QColor& secondColor,
            const QString& firstSeriesName,
            const QString& secondSeriesName,
            QLineSeries** firstSeriesOut,
            QLineSeries** secondSeriesOut,
            QValueAxis** axisXOut,
            QValueAxis** axisYOut,
            QChartView** chartViewOut) {
        QLineSeries* firstSeries = new QLineSeries(this);
        firstSeries->setName(firstSeriesName);
        firstSeries->setColor(firstColor);
        QPen firstPen(firstColor);
        firstPen.setWidthF(2.6);
        firstSeries->setPen(firstPen);

        QLineSeries* secondSeries = new QLineSeries(this);
        secondSeries->setName(secondSeriesName);
        secondSeries->setColor(secondColor);
        QPen secondPen(secondColor);
        secondPen.setWidthF(2.6);
        secondSeries->setPen(secondPen);

        // 区域着色：
        // - 按用户要求给“磁盘读写/网络收发”曲线增加填充区域；
        // - 通过半透明主色增强深浅色主题下的可见性。
        QAreaSeries* firstAreaSeries = new QAreaSeries(firstSeries);
        firstAreaSeries->setName(firstSeriesName);
        firstAreaSeries->setPen(firstPen);
        QColor firstBrushColor = firstColor;
        firstBrushColor.setAlpha(52);
        firstAreaSeries->setBrush(QBrush(firstBrushColor));

        QAreaSeries* secondAreaSeries = new QAreaSeries(secondSeries);
        secondAreaSeries->setName(secondSeriesName);
        secondAreaSeries->setPen(secondPen);
        QColor secondBrushColor = secondColor;
        secondBrushColor.setAlpha(52);
        secondAreaSeries->setBrush(QBrush(secondBrushColor));

        QChart* chart = new QChart();
        chart->addSeries(firstAreaSeries);
        chart->addSeries(secondAreaSeries);
        chart->setBackgroundVisible(false);
        chart->setBackgroundRoundness(0);
        chart->setMargins(QMargins(0, 0, 0, 0));
        chart->setTitle(titleText);
        chart->legend()->hide();

        QValueAxis* axisX = new QValueAxis(chart);
        axisX->setRange(0, m_historyLength);
        axisX->setLabelsVisible(false);
        axisX->setGridLineVisible(false);
        axisX->setMinorGridLineVisible(false);

        QValueAxis* axisY = new QValueAxis(chart);
        axisY->setRange(0.0, 1.0);
        axisY->setLabelsVisible(false);
        axisY->setGridLineVisible(false);
        axisY->setMinorGridLineVisible(false);

        chart->addAxis(axisX, Qt::AlignBottom);
        chart->addAxis(axisY, Qt::AlignLeft);
        firstAreaSeries->attachAxis(axisX);
        firstAreaSeries->attachAxis(axisY);
        secondAreaSeries->attachAxis(axisX);
        secondAreaSeries->attachAxis(axisY);

        if (firstSeriesOut != nullptr)
        {
            *firstSeriesOut = firstSeries;
        }
        if (secondSeriesOut != nullptr)
        {
            *secondSeriesOut = secondSeries;
        }
        if (axisXOut != nullptr)
        {
            *axisXOut = axisX;
        }
        if (axisYOut != nullptr)
        {
            *axisYOut = axisY;
        }
        if (chartViewOut != nullptr)
        {
            *chartViewOut = createNoFrameChartView(chart, this);
        }
    };

    // 磁盘折线图：读/写双线。
    createLineChartView(
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.title"), QStringLiteral("磁盘读写速率")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write),
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.read"), QStringLiteral("读取")),
        ks::i18n::contextText(QStringLiteral("monitor.panel.disk.write"), QStringLiteral("写入")),
        &m_diskReadSeries,
        &m_diskWriteSeries,
        &m_diskAxisX,
        &m_diskAxisY,
        &m_diskChartView);

    // 网络折线图：下/上行双线。
    createLineChartView(
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.title"), QStringLiteral("网络收发速率")),
        KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Network),
        KswordTheme::AccentColor(KswordTheme::AccentRole::Orange, 48, 22),
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.down"), QStringLiteral("下行")),
        ks::i18n::contextText(QStringLiteral("monitor.panel.network.up"), QStringLiteral("上行")),
        &m_networkRxSeries,
        &m_networkTxSeries,
        &m_networkAxisX,
        &m_networkAxisY,
        &m_networkChartView);

    // 把四张图放入 2x2 网格：内存历史用面积颜色直接表达组成比例。
    m_chartGridLayout->addWidget(m_cpuChartView, 0, 0);
    m_chartGridLayout->addWidget(m_memoryTrendChartView, 0, 1);
    m_chartGridLayout->addWidget(m_diskChartView, 1, 0);
    m_chartGridLayout->addWidget(m_networkChartView, 1, 1);
    m_chartGridLayout->setRowStretch(0, 1);
    m_chartGridLayout->setRowStretch(1, 1);
    m_chartGridLayout->setColumnStretch(0, 1);
    m_chartGridLayout->setColumnStretch(1, 1);

    // 初始化阶段先应用文字主题并执行一次高度压缩，避免深色文字过暗和外层滚动条。
    applyChartTextTheme();
    adjustChartCellHeights();
}

void MonitorPanelWidget::refreshMetrics()
{
    const QPointer<MonitorPanelWidget> owner(this);
    reconcileMetrics();
    if (!owner) return;
    if (m_samplingReceipt) return;
    if (m_samplingState && m_samplingState->finished.load(std::memory_order_acquire)) m_samplingState.reset();
    try
    {
        if (!m_samplingState)
        {
            auto state = std::make_shared<SamplingState>(static_cast<int>(m_cpuCoreHistoryPercentList.size()), m_samplingDispatcher);
            const std::weak_ptr<SamplingState> weak(state);
            auto lease = ks::ui::AsyncCleanupRegistry::global().acquire([weak] {
                if (const auto owner = weak.lock()) owner->requestStop();
            });
            if (!lease) return;
            std::thread([state, lease = std::move(lease)]() mutable {
                state->run();
                state.reset();
                lease.reset(); // Native state/callback captures have finished before returning admission.
            }).detach();
            m_samplingState = std::move(state);
        }
        auto receipt = std::make_shared<SamplingReceipt>();
        m_samplingReceipt = receipt;
        const bool accepted = m_samplingState->request({receipt, [this, receipt] {
            if (m_samplingReceipt == receipt) reconcileMetrics();
        }});
        if (!accepted)
        {
            receipt->finished.store(true, std::memory_order_release);
            reconcileMetrics();
        }
    }
    catch (...)
    {
        m_samplingReceipt.reset(); // No physical round was accepted; a later tick retries admission.
    }
}

void MonitorPanelWidget::reconcileMetrics()
{
    const auto receipt = m_samplingReceipt;
    if (!receipt || !receipt->finished.load(std::memory_order_acquire)) return;
    m_samplingReceipt.reset(); // Exactly one consumer; a late posted callback cannot consume a new receipt.
    if (receipt->hasSample) applyMetricSample(std::move(receipt->sample));
}

void MonitorPanelWidget::applyMetricSample(MetricPresentationSample sample)
{
    m_latestPresentation = std::move(sample);
    const auto& perCoreUsageList = m_latestPresentation.coreUsages;
    // 每核历史均值是规范状态，隐藏/仅摘要时也必须逐样本推进。
    for (std::size_t index = 0; index < m_cpuCoreHistoryPercentList.size(); ++index)
    {
        const double usage = index < perCoreUsageList.size() ? perCoreUsageList[index] : 0.0;
        const double previous = m_cpuCoreHistoryPercentList[index];
        m_cpuCoreHistoryPercentList[index] = previous <= 0.0
            ? usage : previous * 0.88 + usage * 0.12;
    }

    // 采样并更新内存合并图：折线表示总占用，面积颜色表示当前时刻组成比例。
    const auto& memorySample = m_latestPresentation.memory;
    m_metricMemoryValid = m_latestPresentation.memoryValid;
    const double memoryUsedTopPercent = memorySample.usedPercent;
    const double memoryStandbyTopPercent = std::clamp(
        memorySample.usedPercent + memorySample.standbyPercent,
        0.0,
        100.0);
    const double memoryAvailableTopPercent = std::clamp(
        memoryStandbyTopPercent + memorySample.availablePercent,
        0.0,
        100.0);

    const double diskReadBytesPerSec = m_latestPresentation.diskReadBytesPerSec;
    const double diskWriteBytesPerSec = m_latestPresentation.diskWriteBytesPerSec;
    const double networkRxBytesPerSec = m_latestPresentation.networkRxBytesPerSec;
    const double networkTxBytesPerSec = m_latestPresentation.networkTxBytesPerSec;
    m_metricDiskValid = m_latestPresentation.diskValid;
    m_metricNetworkValid = m_latestPresentation.networkValid;
    m_metricSampleTimeMs = m_latestPresentation.sampleTimeMs;
    ++m_sampleCounter;
    appendLineSample(m_memoryUsedSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryUsedTopPercent);
    appendLineSample(m_memoryStandbyTopSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryStandbyTopPercent);
    appendLineSample(m_memoryStandbyBaseSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryUsedTopPercent);
    appendLineSample(m_memoryAvailableTopSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryAvailableTopPercent);
    appendLineSample(m_memoryAvailableBaseSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryStandbyTopPercent);
    appendLineSample(m_memoryUsageSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memorySample.usedPercent);
    appendLineSample(m_diskReadSeries, m_diskAxisX, m_diskAxisY, diskReadBytesPerSec);
    appendLineSample(m_diskWriteSeries, m_diskAxisX, m_diskAxisY, diskWriteBytesPerSec);
    appendLineSample(m_networkRxSeries, m_networkAxisX, m_networkAxisY, networkRxBytesPerSec);
    appendLineSample(m_networkTxSeries, m_networkAxisX, m_networkAxisY, networkTxBytesPerSec);

    m_hasMetricSample = true;
    m_chartPresentationDirty = true;
    if (isVisible() && m_presentationExposed)
    {
        updateCompactVisibility();
        refreshVisiblePresentation();
    }
}

void MonitorPanelWidget::refreshVisiblePresentation(const bool snapToLatest)
{
    if (!isVisible() || !m_presentationExposed || m_compactTextOnly || !m_hasMetricSample
        || (!m_chartPresentationDirty && !snapToLatest))
    {
        return;
    }

    if (m_chartThemeDirty) applyChartTextTheme();
    // 全部规范历史先投影，再统一更新共轴与标题，避免首帧混用不同采样。
    const QList<QLineSeries*> lines{
        m_memoryUsedSeries, m_memoryStandbyTopSeries, m_memoryStandbyBaseSeries,
        m_memoryAvailableTopSeries, m_memoryAvailableBaseSeries, m_memoryUsageSeries,
        m_diskReadSeries, m_diskWriteSeries, m_networkRxSeries, m_networkTxSeries
    };
    for (QLineSeries* series : lines)
    {
        if (auto* binding = ks::ui::MetricChartBinding::Find(series); binding && binding->projectionPending())
        {
            binding->refreshSeries();
        }
    }

    if (const auto* binding = ks::ui::MetricChartBinding::Find(m_memoryUsageSeries))
    {
        const auto range = binding->range({ 0.0, 1.0, 1.2, 100.0 });
        if (m_memoryTrendAxisX != nullptr) m_memoryTrendAxisX->setRange(range.minimumX, range.maximumX);
    }
    if (m_memoryTrendAxisY != nullptr) m_memoryTrendAxisY->setRange(0.0, 100.0);
    const auto updatePairRange = [](QLineSeries* first, QLineSeries* second,
        QValueAxis* axisX, QValueAxis* axisY)
    {
        if (first == nullptr || second == nullptr || axisX == nullptr || axisY == nullptr) return;
        const auto range = ks::ui::MetricChartBinding::SharedRange({ first, second },
            ks::ui::MetricXMode::RelativeSlot, { 0.0, 1.0, 1.2, {} });
        axisX->setRange(range.minimumX, range.maximumX);
        axisY->setRange(range.minimumY, range.maximumY);
    };
    updatePairRange(m_diskReadSeries, m_diskWriteSeries, m_diskAxisX, m_diskAxisY);
    updatePairRange(m_networkRxSeries, m_networkTxSeries, m_networkAxisX, m_networkAxisY);

    if (m_cpuCoreBarSet != nullptr)
    {
        for (int index = 0; index < m_cpuCoreBarSet->count(); ++index)
        {
            const auto position = static_cast<std::size_t>(index);
            const double usage = position < m_latestPresentation.coreUsages.size()
                ? m_latestPresentation.coreUsages[position] : 0.0;
            const double history = position < m_cpuCoreHistoryPercentList.size()
                ? m_cpuCoreHistoryPercentList[position] : 0.0;
            if (m_cpuCoreHistoryBarSet != nullptr && index < m_cpuCoreHistoryBarSet->count())
                m_cpuCoreHistoryBarSet->replace(index, history);
            m_cpuCoreBarSet->replace(index, usage);
        }
    }
    if (m_cpuChartView != nullptr && m_cpuChartView->chart() != nullptr)
    {
        m_cpuChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.cpu.title.dynamic"),
                QStringLiteral("CPU 每核心利用率（总体 %1%）"))
            .arg(m_latestPresentation.totalCpuUsage, 0, 'f', 1));
    }

    if (m_memoryTrendChartView != nullptr && m_memoryTrendChartView->chart() != nullptr)
    {
        m_memoryTrendChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.memory.title.dynamic"),
                QStringLiteral("内存占用/组成  占用:%1%  缓存:%2%  可用:%3%"))
            .arg(m_latestPresentation.memory.usedPercent, 0, 'f', 1)
            .arg(m_latestPresentation.memory.standbyPercent, 0, 'f', 1)
            .arg(m_latestPresentation.memory.availablePercent, 0, 'f', 1));
    }

    if (m_diskChartView != nullptr && m_diskChartView->chart() != nullptr)
    {
        m_diskChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.disk.title.dynamic"),
                QStringLiteral("磁盘读写速率  读:%1  写:%2"))
            .arg(bytesPerSecondToText(m_latestPresentation.diskReadBytesPerSec))
            .arg(bytesPerSecondToText(m_latestPresentation.diskWriteBytesPerSec)));
    }
    if (m_networkChartView != nullptr && m_networkChartView->chart() != nullptr)
    {
        m_networkChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.network.title.dynamic"),
                QStringLiteral("网络收发速率  下:%1  上:%2"))
            .arg(bytesPerSecondToText(m_latestPresentation.networkRxBytesPerSec))
            .arg(bytesPerSecondToText(m_latestPresentation.networkTxBytesPerSec)));
    }
    m_chartPresentationDirty = false;
    if (snapToLatest)
    {
        for (QChartView* view : { m_cpuChartView, m_memoryTrendChartView, m_diskChartView, m_networkChartView })
        {
            if (view != nullptr) view->presentLatestWithoutAnimation();
        }
    }
}

void MonitorPanelWidget::appendLineSample(QLineSeries* series, QValueAxis* axisX,
    QValueAxis* axisY, const double value)
{
    if (series == nullptr || axisX == nullptr || axisY == nullptr)
    {
        return;
    }
    bool valid = m_metricMemoryValid; // 内存组成边界默认沿用同一有效位。
    if (series == m_diskReadSeries || series == m_diskWriteSeries)
    {
        valid = m_metricDiskValid;
    }
    else if (series == m_networkRxSeries || series == m_networkTxSeries)
    {
        valid = m_metricNetworkValid;
    }
    auto* binding = ks::ui::MetricChartBinding::ForSeries(series, m_historyLength);
    binding->setXMode(ks::ui::MetricXMode::RelativeSlot); // 保留固定槽位左移的监视面板动画。
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, value, valid }, false);
}

void MonitorPanelWidget::applyChartTextTheme()
{
    if (!m_presentationExposed || !isVisible()) { m_chartThemeDirty = true; return; }
    const QColor primaryTextColor = monitorPanelTextColor();
    const QColor mutedTextColor = monitorPanelMutedTextColor();
    const QBrush primaryTextBrush(primaryTextColor);
    const QBrush mutedTextBrush(mutedTextColor);
    if (m_compactSummaryLabel != nullptr)
    {
        m_compactSummaryLabel->setStyleSheet(QStringLiteral(
            "QLabel{"
            "  color:%1;"
            "  background:transparent;"
            "  font-weight:600;"
            "  padding:4px;"
            "}")
            .arg(primaryTextColor.name(QColor::HexRgb)));
    }

    if (m_compactTextOnly) { m_chartThemeDirty = true; return; }
    m_chartThemeDirty = false;
    // chartList 变量：统一枚举四张图，确保标题/图例在深浅色下都可读。
    const QList<QChart*> chartList{
        m_cpuChartView != nullptr ? m_cpuChartView->chart() : nullptr,
        m_memoryTrendChartView != nullptr ? m_memoryTrendChartView->chart() : nullptr,
        m_diskChartView != nullptr ? m_diskChartView->chart() : nullptr,
        m_networkChartView != nullptr ? m_networkChartView->chart() : nullptr
    };

    QFont titleFont = font();
    titleFont.setPointSizeF(std::max(10.0, titleFont.pointSizeF() + 1.0));
    titleFont.setWeight(QFont::DemiBold);

    QFont legendFont = font();
    legendFont.setPointSizeF(std::max(9.0, legendFont.pointSizeF()));

    for (QChart* chart : chartList)
    {
        if (chart == nullptr)
        {
            continue;
        }

        const bool isCpuBarChart = chart == (m_cpuChartView != nullptr ? m_cpuChartView->chart() : nullptr);

        chart->setTitleBrush(primaryTextBrush);
        chart->setTitleFont(titleFont);
        chart->legend()->hide();
        chart->legend()->setLabelColor(primaryTextColor);
        chart->legend()->setFont(legendFont);
        chart->setAnimationOptions(
            isCpuBarChart ? QChart::SeriesAnimations : QChart::AllAnimations);
        chart->setAnimationDuration(isCpuBarChart ? 120 : 260);
        chart->setAnimationEasingCurve(QEasingCurve::OutCubic);

        const QList<QAbstractAxis*> axisList = chart->axes();
        for (QAbstractAxis* axis : axisList)
        {
            if (axis == nullptr)
            {
                continue;
            }
            axis->setLabelsBrush(mutedTextBrush);
            axis->setTitleBrush(mutedTextBrush);
            axis->setLinePenColor(KswordTheme::BorderStrongColor());
            axis->setGridLineColor(KswordTheme::BorderColor());
        }
    }
}

void MonitorPanelWidget::updateCompactVisibility()
{
    if (!m_presentationExposed || !isVisible()) return;
    // 低高度保护：
    // - 极小高度下标题、plotArea、图例和坐标轴没有足够的可绘制空间；
    // - 直接隐藏所有 chart view，仅保留一行摘要，避免布局震荡或崩溃。
    const bool compactTextOnly = height() > 0 && height() < 200;
    const bool restoreCharts = m_compactTextOnly && !compactTextOnly;
    m_compactTextOnly = compactTextOnly;
    if (compactTextOnly && m_hasMetricSample)
    {
        const auto& sample = m_latestPresentation;
        m_lastCompactSummaryText = ks::i18n::contextText(
            QStringLiteral("monitor.panel.compact.summary"),
            QStringLiteral("CPU %1% | 内存 %2% | 磁盘 读 %3 / 写 %4 | 网络 下 %5 / 上 %6"))
            .arg(sample.totalCpuUsage, 0, 'f', 1)
            .arg(sample.memory.usedPercent, 0, 'f', 1)
            .arg(bytesPerSecondToText(sample.diskReadBytesPerSec))
            .arg(bytesPerSecondToText(sample.diskWriteBytesPerSec))
            .arg(bytesPerSecondToText(sample.networkRxBytesPerSec))
            .arg(bytesPerSecondToText(sample.networkTxBytesPerSec));
    }
    if (m_compactSummaryLabel != nullptr)
    {
        m_compactSummaryLabel->setVisible(compactTextOnly);
        if (!m_lastCompactSummaryText.isEmpty() && m_compactSummaryLabel->text() != m_lastCompactSummaryText)
        {
            m_compactSummaryLabel->setText(m_lastCompactSummaryText);
        }
    }

    const QList<QChartView*> chartViewList{
        m_cpuChartView,
        m_memoryTrendChartView,
        m_diskChartView,
        m_networkChartView
    };
    for (QChartView* chartView : chartViewList)
    {
        if (chartView != nullptr)
        {
            if (chartView->isHidden() != compactTextOnly) chartView->setVisible(!compactTextOnly);
        }
    }
    if (restoreCharts)
    {
        refreshVisiblePresentation(true);
    }
}

void MonitorPanelWidget::adjustChartCellHeights()
{
    if (!m_presentationExposed || !isVisible()) return;
    if (height() > 0 && height() < 200)
    {
        updateCompactVisibility();
        return;
    }
    updateCompactVisibility();

    // applyMaxHeightIfChanged 作用：
    // - 仅收紧图表最大高度，最小高度始终保持 0；
    // - 避免子控件 minimumHeight 反向抬高父容器导致“无限变长”。
    auto applyMaxHeightIfChanged =
        [](QChartView* chartViewPointer, const int heightValue)
        {
            if (chartViewPointer == nullptr || heightValue <= 0)
            {
                return;
            }
            if (chartViewPointer->minimumHeight() == 0
                && chartViewPointer->maximumHeight() == heightValue)
            {
                return;
            }
            chartViewPointer->setMinimumHeight(0);
            chartViewPointer->setMaximumHeight(heightValue);
        };

    // widgetInnerHeight 用途：去掉布局边距后的真实可用高度，防止把边距重复算进图表高度。
    int widgetInnerHeight = height();
    if (m_rootLayout != nullptr)
    {
        const QMargins rootMargins = m_rootLayout->contentsMargins();
        widgetInnerHeight -= (rootMargins.top() + rootMargins.bottom());
    }
    if (m_chartGridLayout != nullptr)
    {
        const QMargins gridMargins = m_chartGridLayout->contentsMargins();
        widgetInnerHeight -= (gridMargins.top() + gridMargins.bottom());
    }

    // 回退值用途：布局尚未稳定时用 geometry/默认值兜底，防止出现 0 高度。
    if (widgetInnerHeight <= 0 && m_chartGridLayout != nullptr)
    {
        widgetInnerHeight = m_chartGridLayout->geometry().height();
    }
    if (widgetInnerHeight <= 0)
    {
        widgetInnerHeight = 180;
    }

    // rowSpacingValue 用途：两行图之间的垂直间距，用于计算每行可用高度。
    const int rowSpacingValue = m_chartGridLayout != nullptr
        ? std::max(0, m_chartGridLayout->verticalSpacing())
        : 0;
    // availableRowsHeight 用途：扣除行间距后可分配给两行图表的总高度。
    const int availableRowsHeight = std::max(2, widgetInnerHeight - rowSpacingValue);
    // chartRowHeight 用途：每一行图表的目标上限高度，保持可压缩且避免“图消失”。
    const int chartRowHeight = std::max(18, availableRowsHeight / 2);

    applyMaxHeightIfChanged(m_cpuChartView, chartRowHeight);
    applyMaxHeightIfChanged(m_memoryTrendChartView, chartRowHeight);
    applyMaxHeightIfChanged(m_diskChartView, chartRowHeight);
    applyMaxHeightIfChanged(m_networkChartView, chartRowHeight);

    // compactMode 用途：低高度时简化标题边距，减少内部布局占用，避免出现滚动条。
    const bool compactMode = (chartRowHeight < 92);
    auto applyChartCompactMode =
        [compactMode](QChartView* chartViewPointer)
        {
            if (chartViewPointer == nullptr || chartViewPointer->chart() == nullptr)
            {
                return;
            }
            QChart* chartPointer = chartViewPointer->chart();
            if (chartPointer->legend() != nullptr)
            {
                chartPointer->legend()->hide();
            }
            if (compactMode)
            {
                chartPointer->setMargins(QMargins(0, 0, 0, 0));
            }
        };
    applyChartCompactMode(m_memoryTrendChartView);
    applyChartCompactMode(m_diskChartView);
    applyChartCompactMode(m_networkChartView);
}
