// 真实 QPainter/Qt 绑定回归；生产采样方法由脚本完整抽取，外部查询不在本夹具执行。
#include "../shared/ui/MetricChartBinding.h"
#include "../Ksword5.1/Ksword5.1/UI/PerformanceChartTheme.h"

#include <QApplication>
#include <QDateTime>
#include <QEventLoop>
#include <QImage>
#include <QMutex>
#include <QPalette>
#include <QTimer>
#include <QVariantAnimation>
#include <cmath>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <vector>
#include <Windows.h>
#include <pdh.h>
#include <pdhmsg.h>

static int checks = 0;
static void check(const bool condition, const char* reason)
{
    if (!condition) throw std::runtime_error(reason);
    ++checks;
}

// 只替换轴动画调度，实际生产采样/模型/系列与绘制均保留。
static void animateLiveValueAxisRange(QValueAxis* axis, double minimum, double maximum)
{
    axis->setRange(minimum, maximum);
}

struct MetricCpuCounterResult
{
    PDH_STATUS readStatus = ERROR_SUCCESS;
    DWORD dataStatus = PDH_CSTATUS_VALID_DATA;
    double value = 0.0;
};
static PDH_STATUS metricCollectStatus = ERROR_SUCCESS;
static std::vector<MetricCpuCounterResult> metricCounterResults;
static PDH_STATUS WINAPI MetricTestCollectQueryData(PDH_HQUERY) { return metricCollectStatus; }
static PDH_STATUS WINAPI MetricTestFormattedCounter(PDH_HCOUNTER counter, DWORD, LPDWORD,
    PPDH_FMT_COUNTERVALUE output)
{
    const auto index = reinterpret_cast<std::uintptr_t>(counter) - 1;
    const auto& result = metricCounterResults.at(index);
    output->CStatus = result.dataStatus;
    output->doubleValue = result.value;
    return result.readStatus;
}
// 注入系统 API 的确定性返回值，完整生产 sampler 的分支和逐核映射由源码决定。
#define PdhCollectQueryData MetricTestCollectQueryData
#define PdhGetFormattedCounterValue MetricTestFormattedCounter
class HardwareDock
{
public:
    struct CoreChartEntry
    {
        QLineSeries* lineSeries = nullptr;
        QLineSeries* baselineSeries = nullptr;
        QValueAxis* axisX = nullptr;
        QValueAxis* axisY = nullptr;
    };
    struct GpuEngineChartEntry { QLineSeries* lineSeries = nullptr; };
    std::vector<GpuEngineChartEntry> m_gpuEngineCharts;
    std::vector<bool> m_metricCoreValid;
    void* m_cpuPerfQueryHandle = reinterpret_cast<void*>(1);
    std::vector<void*> m_coreCounterHandles{ reinterpret_cast<void*>(1) };
    void initializePerformanceCounters() {}
    bool samplePerCoreUsage(std::vector<double>*, double*);
    int m_historyLength = 3;
    int m_sampleCounter = 1;
    qint64 m_metricSampleTimeMs = 1000;
    bool m_metricCpuValid = true, m_metricDiskValid = true, m_metricNetworkValid = true;
    bool m_metricGpuValid = true, m_gpuDedicatedUsageAvailable = true, m_gpuSharedUsageAvailable = true;
    QLineSeries* m_diskReadLineSeries = nullptr;
    QLineSeries* m_diskWriteLineSeries = nullptr;
    QLineSeries* m_networkRxLineSeries = nullptr;
    QLineSeries* m_networkTxLineSeries = nullptr;
    QLineSeries* m_gpuDedicatedMemoryLineSeries = nullptr;
    QLineSeries* m_gpuSharedMemoryLineSeries = nullptr;
    void appendCoreSeriesPoint(CoreChartEntry&, double, bool);
    void appendGeneralSeriesPoint(QLineSeries*, QValueAxis*, QValueAxis*, double, double);
    void appendFilledSeriesPoint(QLineSeries*, QLineSeries*, QValueAxis*, QValueAxis*, double, double, bool = true);
    void updateSharedSeriesAxisRange(QLineSeries*, QLineSeries*, QValueAxis*, QValueAxis*, double);
};
class MonitorPanelWidget
{
public:
    int m_historyLength = 3, m_sampleCounter = 1;
    qint64 m_metricSampleTimeMs = 1000;
    bool m_metricMemoryValid = true, m_metricDiskValid = true, m_metricNetworkValid = true;
    QLineSeries* m_diskReadSeries = nullptr;
    QLineSeries* m_diskWriteSeries = nullptr;
    QLineSeries* m_networkRxSeries = nullptr;
    QLineSeries* m_networkTxSeries = nullptr;
    void appendLineSample(QLineSeries*, QValueAxis*, QValueAxis*, double);
};
class HudPerformancePanel
{
public:
    __PRODUCTION_HUD_TYPES__
    struct GpuEngineChartEntry { QLineSeries* lineSeries = nullptr; };
    std::vector<GpuEngineChartEntry> m_gpuEngineCharts;
    std::vector<int> m_coreChartEntries;
    QMutex m_liveSampleMutex;
    int m_historyLength = 3, m_sampleCounter = 1;
    qint64 m_metricSampleTimeMs = 1000;
    bool m_metricMemoryValid = true, m_metricDiskValid = true, m_metricNetworkValid = true;
    bool m_metricGpuValid = true, m_metricGpuMemoryValid = true, m_gpuMetricMemoryValid = true;
    bool m_testGpuOk = true, m_testGpuMemoryOk = true;
    QLineSeries* m_memoryLineSeries = nullptr;
    QLineSeries* m_diskReadLineSeries = nullptr;
    QLineSeries* m_diskWriteLineSeries = nullptr;
    QLineSeries* m_networkRxLineSeries = nullptr;
    QLineSeries* m_networkTxLineSeries = nullptr;
    QLineSeries* m_gpuDedicatedMemoryLineSeries = nullptr;
    QLineSeries* m_gpuSharedMemoryLineSeries = nullptr;
    QString m_primaryNetworkAdapterName, m_systemVolumeText;
    std::uint64_t m_primaryNetworkLinkBitsPerSecond = 0;
    std::uint64_t m_systemVolumeTotalBytes = 0, m_systemVolumeFreeBytes = 0;
    std::uint64_t m_lastTotalPhysBytes = 0, m_lastAvailPhysBytes = 0;
    double m_gpuUsage3DPercent = 4.0, m_gpuUsageCopyPercent = 2.0;
    double m_gpuUsageVideoEncodePercent = 0.0, m_gpuUsageVideoDecodePercent = 0.0;
    double m_gpuDedicatedUsedGiB = 1.0, m_gpuDedicatedBudgetGiB = 4.0;
    double m_gpuSharedUsedGiB = 2.0, m_gpuSharedBudgetGiB = 8.0;
    QValueAxis* m_testAxisX = nullptr;
    QValueAxis* m_testAxisY = nullptr;
    LiveSampleResult collectLiveSampleResult();
    void applyLiveSampleResult(const LiveSampleResult&);
    // 后端边界替身只提供查询结果，采样结果收集/发布完整使用生产方法。
    void* m_cpuPerfQueryHandle = reinterpret_cast<void*>(1);
    std::vector<void*> m_coreCounterHandles{ reinterpret_cast<void*>(1) };
    void initializePerformanceCounters() {}
    bool samplePerCoreUsage(std::vector<double>*, double*);
    bool sampleMemoryUsage(double* value) { *value = 25.0; return true; }
    bool sampleDiskRate(double* read, double* write) { *read = 1.0; *write = 2.0; return true; }
    bool sampleNetworkRate(double* read, double* write) { *read = 1.0; *write = 2.0; return true; }
    bool sampleGpuUsage(double* value)
    { *value = 4.0; if (m_testGpuOk) m_gpuMetricMemoryValid = m_testGpuMemoryOk; return m_testGpuOk; }
    bool sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>*) { return true; }
    bool sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot*) { return true; }
    void updateView(const std::vector<double>&, double memory, double, double, double, double, double)
    {
        appendGeneralSeriesPoint(m_memoryLineSeries, m_testAxisX, m_testAxisY, memory, 0.0);
        for (const auto& entry : m_gpuEngineCharts)
            appendGeneralSeriesPoint(entry.lineSeries, m_testAxisX, m_testAxisY, m_gpuUsage3DPercent, 0.0);
        appendGeneralSeriesPoint(m_gpuDedicatedMemoryLineSeries, m_testAxisX, m_testAxisY, m_gpuDedicatedUsedGiB, 0.0);
    }
    void updateTaskManagerDetailLabels(const std::vector<double>&, const std::vector<CpuPowerSnapshot>&,
        double, double, double, double, double, double, const SystemPerformanceSnapshot*, bool) {}
    void requestAsyncSensorRefresh() {}
    void requestAsyncStaticInfoRefresh() {}
    void appendGeneralSeriesPoint(QLineSeries*, QValueAxis*, QValueAxis*, double, double);
};

__PRODUCTION_CALLERS__

static void testHistoryModel()
{
    ks::ui::MetricHistory history(3);
    history.append({ 100, 1000, 0.0, true });
    history.append({ 101, 2000, 9000.0, false });
    history.append({ 102, 3500, 10.0, true });
    check(history.samples().size() == 3 && history.samples()[0].value == 0.0
        && history.samples()[0].valid, "real zero lost its validity");
    const auto range = history.axisRange(ks::ui::MetricXMode::ElapsedTime, { 0.0, 1.0, 1.2, {} });
    check(range.minimumX == 0.0 && range.maximumX == 2.5 && range.maximumY == 12.0,
        "missing sample enlarged axis or actual time discarded");
    check(history.select(101) && !history.followsLatest(), "historical stable selection failed");
    history.append({ 103, 4000, 3.0, true });
    check(history.selectedId() == 101 && !history.followsLatest(), "eviction moved surviving anchor by row");
    history.append({ 104, 5000, 4.0, true });
    check(history.selectedId() == 104 && history.followsLatest(), "evicted anchor did not restore latest");
    history.setCapacity(1);
    check(history.samples().size() == 1 && history.samples().front().id == 104, "capacity shrink not immediate");
    history.clear();
    check(history.append({ 0, 6000, 1.0, true }) == 105, "clear reused previous stable identity");
    history.setCapacity(0);
    history.append({ 0, 7000, 1.0, true });
    check(history.samples().empty() && !history.selectedId(), "disabled history retained samples");
    history.setCapacity(3);
    history.append({ 10000000000000000000ULL, 8000, 1.0, true });
    history.append({ 10000000000000000001ULL, 9000, 2.0, true });
    check(history.projectedX(1, ks::ui::MetricXMode::StableId)
        - history.projectedX(0, ks::ui::MetricXMode::StableId) == 1.0,
        "large stable ids lost adjacent coordinate interval");
    const auto latest = history.samples().back().id;
    history.append({ latest, 9100, 7.0, true });
    check(history.samples().size() == 2 && history.samples().back().timestampMs == 9100,
        "same sample identity manufactured an extra row");
    check(history.append({ latest - 5, 9200, 3.0, true }) == 0, "stale source identity rewrote history");

    ks::ui::MetricHistory unknownTime(4);
    unknownTime.append({ 1, 0, 900000.0, true });
    const auto unknownRange = unknownTime.axisRange(ks::ui::MetricXMode::ElapsedTime, { 0.0, 1.0, 1.0, {} });
    check(!unknownRange.hasValidSamples && unknownRange.maximumX == 1.0 && unknownRange.maximumY == 1.0,
        "unknown time manufactured an epoch or peak in elapsed projection");
    unknownTime.append({ 2, 1780000000000LL, 10.0, true });
    unknownTime.append({ 3, 1780000002500LL, 20.0, true });
    check(std::isnan(unknownTime.projectedX(0, ks::ui::MetricXMode::ElapsedTime))
        && unknownTime.samples().front().value == 900000.0 && unknownTime.samples().front().valid,
        "unknown time policy deleted or rewrote raw data");
    const auto knownRange = unknownTime.axisRange(ks::ui::MetricXMode::ElapsedTime, { 0.0, 1.0, 1.0, {} });
    check(knownRange.minimumX == 0.0 && knownRange.maximumX == 2.5 && knownRange.maximumY == 20.0,
        "preloaded unknown time enlarged real elapsed axis");
    check(unknownTime.axisRange(ks::ui::MetricXMode::StableId, { 0.0, 1.0, 1.0, {} }).maximumY == 900000.0,
        "unknown time accidentally invalidated a value in identity projection");
    unknownTime.setCapacity(2);
    check(unknownTime.projectedX(0, ks::ui::MetricXMode::ElapsedTime) == 0.0
        && unknownTime.projectedX(1, ks::ui::MetricXMode::ElapsedTime) == 2.5,
        "unknown placeholder eviction moved known elapsed coordinates");

    QLineSeries prefilled;
    prefilled.replace({ { 0.0, 0.0 }, { 1.0, 0.0 } });
    auto* elapsed = ks::ui::MetricChartBinding::ForSeries(&prefilled, 4);
    elapsed->setXMode(ks::ui::MetricXMode::ElapsedTime);
    elapsed->append({ 3, 1780000000000LL, 5.0, true });
    elapsed->append({ 4, 1780000001000LL, 7.0, true });
    check(std::isnan(prefilled.points().front().x()) && prefilled.points().back().x() == 1.0
        && elapsed->range({ 0.0, 1.0, 1.0, {} }).maximumX == 1.0,
        "real binding rendered prefilled slots as a huge timestamp span");
}

static void testProductionAdapters()
{
    QLineSeries first, second, baseline;
    QValueAxis x, y;
    HardwareDock hardware;
    hardware.m_diskReadLineSeries = &first;
    hardware.m_diskWriteLineSeries = &second;
    hardware.appendFilledSeriesPoint(&first, &baseline, &x, &y, 100.0, 0.0);
    hardware.appendGeneralSeriesPoint(&second, &x, &y, 10.0, 0.0);
    hardware.updateSharedSeriesAxisRange(&first, &second, &x, &y, 0.0);
    check(std::abs(y.max() - 115.0) < .000001, "shared hardware axis clipped larger primary curve");
    hardware.m_sampleCounter = 2;
    hardware.m_metricSampleTimeMs = 2000;
    hardware.m_metricDiskValid = false;
    hardware.appendFilledSeriesPoint(&first, &baseline, &x, &y, 0.0, 0.0);
    check(std::isnan(first.points().back().y()) && std::isnan(baseline.points().back().y()),
        "hardware failed query became fabricated zero/fill baseline");
    auto* source = ks::ui::MetricChartBinding::Find(&first);
    check(source->history()->samples().back().timestampMs == 2000, "production timestamp not stored");
    QLineSeries mirror;
    ks::ui::MetricChartBinding::MirrorSeries(&first, &mirror);
    auto* mirrored = ks::ui::MetricChartBinding::Find(&mirror);
    check(source->history() == mirrored->history(), "mirror copied UI points instead of sharing model");
    hardware.m_sampleCounter = 3;
    hardware.m_metricDiskValid = true;
    hardware.appendFilledSeriesPoint(&first, &baseline, &x, &y, 30.0, 0.0);
    mirrored->refreshSeries();
    check(mirror.points().back() == first.points().back(), "two views projected different latest sample");
    check(source->history()->select(1), "source historical selection failed");
    check(mirrored->history()->selectedId() == 1, "shared mirror lost stable selection");

    MonitorPanelWidget monitor;
    QLineSeries monitorSeries;
    monitor.m_diskReadSeries = &monitorSeries;
    for (int index = 0; index < 5; ++index)
    {
        monitor.m_sampleCounter = index + 1;
        monitor.m_metricSampleTimeMs = 1000 + index * 1000;
        monitor.appendLineSample(&monitorSeries, &x, &y, index * 10.0);
    }
    const auto monitorHistory = ks::ui::MetricChartBinding::Find(&monitorSeries)->history();
    check(monitorSeries.count() == 3 && monitorSeries.points().front().x() == 0.0,
        "monitor bounded relative slots regressed");
    check(monitorHistory->samples().front().id == 3 && monitorHistory->samples().front().timestampMs == 3000,
        "monitor row projection lost stable identity or time");
    HudPerformancePanel hud;
    QLineSeries hudSeries;
    hud.m_memoryLineSeries = &hudSeries;
    hud.appendGeneralSeriesPoint(&hudSeries, &x, &y, 20.0, 0.0);
    check(y.max() == 100.0, "HUD memory percentage lost fixed axis policy");
    hud.m_sampleCounter = 2;
    hud.m_metricMemoryValid = false;
    hud.appendGeneralSeriesPoint(&hudSeries, &x, &y, 0.0, 0.0);
    check(std::isnan(hudSeries.points().back().y()), "HUD failure fabricated a zero sample");
    check(ks::ui::MetricChartBinding::Find(&hudSeries)->history() != source->history(),
        "independent HUD consumer unexpectedly shared a live model instance");

    QLineSeries hardwareGpu, hardwareGpuBase, hardwareDedicated, hardwareDedicatedBase;
    QLineSeries hardwareShared, hardwareSharedBase, deviceMemory, deviceMemoryBase;
    hardware.m_gpuEngineCharts.push_back({ &hardwareGpu });
    hardware.m_gpuDedicatedMemoryLineSeries = &hardwareDedicated;
    hardware.m_gpuSharedMemoryLineSeries = &hardwareShared;
    hardware.m_metricGpuValid = false;
    hardware.appendFilledSeriesPoint(&hardwareGpu, &hardwareGpuBase, &x, &y, 12.0, 0.0);
    check(std::isnan(hardwareGpu.points().back().y()) && std::isnan(hardwareGpuBase.points().back().y()),
        "hardware GPU query failure fabricated valid engine/fill");
    hardware.m_metricGpuValid = true;
    hardware.m_gpuDedicatedUsageAvailable = false;
    hardware.m_gpuSharedUsageAvailable = true;
    hardware.appendFilledSeriesPoint(&hardwareDedicated, &hardwareDedicatedBase, &x, &y, 8.0, 0.0);
    hardware.appendFilledSeriesPoint(&hardwareShared, &hardwareSharedBase, &x, &y, 2.0, 0.0);
    check(std::isnan(hardwareDedicated.points().back().y()) && hardwareShared.points().back().y() == 2.0,
        "dedicated/shared GPU memory validity was conflated");
    hardware.appendFilledSeriesPoint(&deviceMemory, &deviceMemoryBase, &x, &y, 8.0, 0.0, false);
    check(std::isnan(deviceMemory.points().back().y()) && std::isnan(deviceMemoryBase.points().back().y()),
        "per-device GPU memory missing result fabricated area");
    ++hardware.m_sampleCounter;
    hardware.appendFilledSeriesPoint(&hardwareGpu, &hardwareGpuBase, &x, &y, 0.0, 0.0);
    check(hardwareGpu.points().back().y() == 0.0
        && ks::ui::MetricChartBinding::Find(&hardwareGpu)->history()->samples().back().valid,
        "recovered true zero GPU engine sample remained invalid");
}

static void testHudBackendTimeAndGpu()
{
    HudPerformancePanel hud;
    QLineSeries memory, engine, dedicated;
    QValueAxis x, y;
    hud.m_memoryLineSeries = &memory;
    hud.m_gpuEngineCharts.push_back({ &engine });
    hud.m_gpuDedicatedMemoryLineSeries = &dedicated;
    hud.m_testAxisX = &x;
    hud.m_testAxisY = &y;
    const auto before = QDateTime::currentMSecsSinceEpoch();
    const auto collected = hud.collectLiveSampleResult();
    const auto after = QDateTime::currentMSecsSinceEpoch();
    check(collected.sampleTimeMs >= before && collected.sampleTimeMs <= after,
        "HUD collector did not timestamp its actual backend completion");
    check(collected.perCoreOk && collected.totalCpuUsage == 10.0,
        "complete HUD collector did not preserve actual validated per-core backend result");
    QEventLoop queue;
    QTimer::singleShot(30, &queue, [&]() { hud.applyLiveSampleResult(collected); queue.quit(); });
    queue.exec();
    check(QDateTime::currentMSecsSinceEpoch() > collected.sampleTimeMs
        && ks::ui::MetricChartBinding::Find(&memory)->history()->samples().back().timestampMs == collected.sampleTimeMs,
        "queued HUD apply replaced backend time with UI delivery time");
    check(engine.points().back().y() == 4.0 && dedicated.points().back().y() == 1.0,
        "valid HUD engine or DXGI memory result not projected");
    hud.m_testGpuMemoryOk = false;
    const auto memoryFailure = hud.collectLiveSampleResult();
    hud.applyLiveSampleResult(memoryFailure);
    check(memoryFailure.gpuOk && !memoryFailure.gpuMemoryOk && engine.points().back().y() == 4.0
        && std::isnan(dedicated.points().back().y()), "HUD DXGI failure tainted independent GPU engine validity");
    hud.m_testGpuOk = false;
    hud.m_gpuMetricMemoryValid = true; // 模拟上帧有效但本帧早退，收集必须先清除。
    const auto totalFailure = hud.collectLiveSampleResult();
    hud.applyLiveSampleResult(totalFailure);
    check(!totalFailure.gpuOk && !totalFailure.gpuMemoryOk && std::isnan(engine.points().back().y())
        && std::isnan(dedicated.points().back().y()), "HUD GPU early failure reused stale validity/value");
    hud.m_testGpuOk = true;
    hud.m_testGpuMemoryOk = true;
    hud.m_gpuUsage3DPercent = 0.0;
    hud.m_gpuDedicatedUsedGiB = 0.0;
    hud.applyLiveSampleResult(hud.collectLiveSampleResult());
    check(engine.points().back().y() == 0.0 && dedicated.points().back().y() == 0.0,
        "HUD recovered true zero remained a missing GPU sample");
}

static void testCpuCounterValidity()
{
    HardwareDock hardware;
    hardware.m_coreCounterHandles = { reinterpret_cast<void*>(1), reinterpret_cast<void*>(2), nullptr };
    std::vector<double> values;
    double total = 99.0;
    metricCounterResults = { { static_cast<PDH_STATUS>(PDH_INVALID_DATA), PDH_CSTATUS_VALID_DATA, 25.0 },
        { static_cast<PDH_STATUS>(PDH_INVALID_DATA), PDH_CSTATUS_VALID_DATA, 75.0 } };
    check(!hardware.samplePerCoreUsage(&values, &total) && total == 0.0,
        "successful collect with every counter failing fabricated valid zero CPU");
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_INVALID_DATA, 25.0 },
        { ERROR_SUCCESS, PDH_CSTATUS_INVALID_DATA, 75.0 } };
    check(!hardware.samplePerCoreUsage(&values, &total), "CPU ignored per-counter CStatus failure");
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_NEW_DATA, 0.0 },
        { ERROR_SUCCESS, PDH_CSTATUS_INVALID_DATA, 75.0 } };
    check(hardware.samplePerCoreUsage(&values, &total) && total == 0.0 && values.size() == 3,
        "actual valid zero CPU counter rejected or failed/null counter index dropped");
    check(hardware.m_metricCoreValid == std::vector<bool>({ true, false, false }),
        "partial CPU failure lost the valid bit for each actual counter slot");
    QLineSeries validCore, validBaseline, failedCore, failedBaseline;
    QValueAxis x, y;
    HardwareDock::CoreChartEntry validEntry{ &validCore, &validBaseline, &x, &y };
    HardwareDock::CoreChartEntry failedEntry{ &failedCore, &failedBaseline, &x, &y };
    hardware.appendCoreSeriesPoint(validEntry, values[0], hardware.m_metricCoreValid[0]);
    hardware.appendCoreSeriesPoint(failedEntry, values[1], hardware.m_metricCoreValid[1]);
    check(validCore.points().back().y() == 0.0 && std::isnan(failedCore.points().back().y())
        && std::isnan(failedBaseline.points().back().y()),
        "partial failed CPU counter or area baseline became valid zero in production history adapter");
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_VALID_DATA, std::numeric_limits<double>::infinity() },
        { ERROR_SUCCESS, PDH_CSTATUS_VALID_DATA, 60.0 } };
    check(hardware.samplePerCoreUsage(&values, &total) && total == 60.0
        && hardware.m_metricCoreValid == std::vector<bool>({ false, true, false }),
        "nonfinite CPU counter tainted valid aggregate or became a valid sample");
    metricCollectStatus = PDH_INVALID_DATA;
    total = 99.0;
    check(!hardware.samplePerCoreUsage(&values, &total) && total == 0.0
        && hardware.m_metricCoreValid == std::vector<bool>({ false, false, false }),
        "collect failure retained previous per-core validity or aggregate");
    metricCollectStatus = ERROR_SUCCESS;

    HudPerformancePanel hud;
    hud.m_coreCounterHandles = { reinterpret_cast<void*>(1), reinterpret_cast<void*>(2), nullptr };
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_INVALID_DATA, 25.0 },
        { ERROR_SUCCESS, PDH_CSTATUS_INVALID_DATA, 75.0 } };
    check(!hud.samplePerCoreUsage(&values, &total) && total == 0.0,
        "HUD sampler reused all failed CStatus CPU values");
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_NEW_DATA, 0.0 },
        { ERROR_SUCCESS, PDH_CSTATUS_VALID_DATA, std::numeric_limits<double>::quiet_NaN() } };
    check(hud.samplePerCoreUsage(&values, &total) && total == 0.0 && values.size() == 3,
        "HUD sampler confused valid new zero with nonfinite/null failures");
    // 后续完整收集器用稳定的单核后端结果，保留真实来源方法。
    metricCounterResults = { { ERROR_SUCCESS, PDH_CSTATUS_VALID_DATA, 10.0 } };
}

// 在图像中央缺口带直接统计曲线/面积像素，不只断言 NaN 保存。
static int coloredPixels(const QImage& image, const int xBegin, const int xEnd)
{
    int count = 0;
    for (int x = xBegin; x < xEnd; ++x)
    {
        for (int y = image.height() / 4; y < image.height() * 3 / 4; ++y)
        {
            const QColor color = image.pixelColor(x, y);
            if (color.red() < 245 || color.green() < 245 || color.blue() < 245) ++count;
        }
    }
    return count;
}

static void testRealGapPainting(const bool area, const QString& output,
    const bool lowerGap = false, const bool animated = false)
{
    auto* chart = new QChart;
    auto* upper = new QLineSeries;
    auto* lower = new QLineSeries;
    auto* axisX = new QValueAxis;
    auto* axisY = new QValueAxis;
    axisX->setRange(0.0, 4.0);
    axisY->setRange(0.0, 1.0);
    for (QAbstractAxis* axis : { axisX, axisY })
    {
        axis->setLabelsVisible(false);
        axis->setGridLineVisible(false);
        axis->setLineVisible(false);
    }
    chart->addAxis(axisX, Qt::AlignBottom);
    chart->addAxis(axisY, Qt::AlignLeft);
    chart->legend()->hide();
    chart->setBackgroundBrush(Qt::white);
    chart->setPlotAreaBackgroundVisible(false);
    chart->setAnimationOptions(QChart::NoAnimation);
    const double gap = std::numeric_limits<double>::quiet_NaN();
    const QList<QPointF> upperTarget{{0, .6}, {1, .6}, {2, lowerGap ? .6 : gap}, {3, .6}, {4, .6}};
    const QList<QPointF> lowerTarget{{0, .2}, {1, .2}, {2, lowerGap ? gap : .2}, {3, .2}, {4, .2}};
    upper->replace(animated ? QList<QPointF>{{0, .6}, {1, .6}, {2, .6}, {3, .6}, {4, .6}} : upperTarget);
    lower->replace(animated ? QList<QPointF>{{0, .2}, {1, .2}, {2, .2}, {3, .2}, {4, .2}} : lowerTarget);
    if (area)
    {
        auto* series = new QAreaSeries(upper, lower);
        series->setBrush(QColor(200, 20, 20, 160));
        series->setPen(QPen(Qt::blue, 2.0));
        chart->addSeries(series);
        series->attachAxis(axisX);
        series->attachAxis(axisY);
    }
    else
    {
        delete lower;
        upper->setPen(QPen(Qt::blue, 2.0));
        chart->addSeries(upper);
        upper->attachAxis(axisX);
        upper->attachAxis(axisY);
    }
    QChartView view(chart);
    view.resize(300, 140);
    view.setFrameShape(QFrame::NoFrame);
    view.show();
    QApplication::processEvents();
    if (animated)
    {
        chart->setAnimationOptions(QChart::AllAnimations);
        upper->replace(upperTarget);
        if (area) lower->replace(lowerTarget);
        QApplication::processEvents();
        const auto animations = view.findChildren<QVariantAnimation*>();
        check(!animations.empty(), "real chart animation not installed");
        for (QVariantAnimation* animation : animations)
            animation->setCurrentTime(animation->duration() / 2);
    }
    const QImage image = view.grab().toImage();
    check(coloredPixels(image, image.width() * 45 / 100, image.width() * 55 / 100) == 0,
        "QPainter connected or filled across real missing gap");
    check(coloredPixels(image, image.width() / 10, image.width() / 5) > 0
        && coloredPixels(image, image.width() * 8 / 10, image.width() * 9 / 10) > 0,
        "gap fix removed valid segments beside missing sample");
    check(image.save(output), "gap proof image was not written");
}

static void testThemeWithoutSampling()
{
    QChart chart;
    auto* line = new QLineSeries;
    chart.addSeries(line);
    auto* binding = ks::ui::MetricChartBinding::ForSeries(line, 3);
    binding->append({ 77, 9000, 10.0, true });
    const auto samplesBefore = binding->history()->samples();
    const auto* identity = line;
    const QColor penBefore = line->color();
    KswordTheme::SetPrimaryAccentColor(QStringLiteral("#a52ba5"));
    KswordTheme::SetDarkModeEnabled(true);
    ks::ui::RefreshPerformanceChartTheme(&chart, KswordTheme::PerformanceRole::Cpu,
        KswordTheme::PerformanceRole::Memory);
    binding->refreshSeries();
    check(line->color() != penBefore, "actual theme role did not recolor existing series");
    check(line == identity && binding->history()->samples().size() == samplesBefore.size()
        && binding->history()->samples().back().id == samplesBefore.back().id
        && binding->history()->samples().back().timestampMs == samplesBefore.back().timestampMs,
        "theme application resampled history or replaced series identity");
}

int main(int argc, char** argv)
{
    QApplication application(argc, argv);
    try
    {
        testHistoryModel();
        testCpuCounterValidity();
        testProductionAdapters();
        testHudBackendTimeAndGpu();
        testThemeWithoutSampling();
        testRealGapPainting(false, QStringLiteral("metric_history_line_gap.png"));
        testRealGapPainting(true, QStringLiteral("metric_history_area_gap.png"));
        testRealGapPainting(true, QStringLiteral("metric_history_lower_gap.png"), true);
        testRealGapPainting(false, QStringLiteral("metric_history_animated_line_gap.png"), false, true);
        testRealGapPainting(true, QStringLiteral("metric_history_animated_area_gap.png"), false, true);
        std::cout << "METRIC_HISTORY_CHECKS=" << checks << "\nMETRIC_HISTORY_RESULT=PASS\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "METRIC_HISTORY_RESULT=FAIL " << error.what() << '\n';
        return 1;
    }
}
