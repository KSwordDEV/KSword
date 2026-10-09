#pragma once

#include <QWidget>
#include <QColor>
#include <QFutureWatcher>
#include <QMutex>

#include <atomic>
#include <cstdint>
#include <vector>

class PerformanceNavCard;
class QChartView;
class QChart;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineSeries;
class QListWidget;
class QResizeEvent;
class QScrollArea;
class QShowEvent;
class QStackedWidget;
class QTimer;
class QValueAxis;

class HudPerformancePanel final : public QWidget
{
public:
    explicit HudPerformancePanel(QWidget* parent = nullptr);
    ~HudPerformancePanel() override;
    // 输入透明图片与配置背景合成后的颜色，更新文字和图表，不修改采样或布局。
    void setEffectiveBackgroundColor(const QColor& colorValue);
    // 对已有自有图表应用底色对比规则；无需初始化性能采样，方便离屏色彩验证。
    static void applyChartColors(QChart* chart, const QColor& colorValue);

protected:
    void resizeEvent(QResizeEvent* resizeEventPointer) override;
    void showEvent(QShowEvent* showEventPointer) override;

private:
    struct CoreChartEntry
    {
        QWidget* containerWidget = nullptr;
        QLabel* titleLabel = nullptr;
        QWidget* chartWidget = nullptr;
    };

    struct GpuEngineChartEntry
    {
        QString engineKeyText;
        QString displayNameText;
        QLabel* titleLabel = nullptr;
        QChartView* chartView = nullptr;
        QLineSeries* lineSeries = nullptr;
        QValueAxis* axisX = nullptr;
        QValueAxis* axisY = nullptr;
    };

    struct CpuPowerSnapshot
    {
        std::uint32_t coreIndex = 0;
        std::uint32_t currentMhz = 0;
        std::uint32_t maxMhz = 0;
        std::uint32_t limitMhz = 0;
    };

    struct SystemPerformanceSnapshot
    {
        std::uint32_t processCount = 0;
        std::uint32_t threadCount = 0;
        std::uint32_t handleCount = 0;
        std::uint64_t commitTotalBytes = 0;
        std::uint64_t commitLimitBytes = 0;
        std::uint64_t cachedBytes = 0;
        std::uint64_t pagedPoolBytes = 0;
        std::uint64_t nonPagedPoolBytes = 0;
    };

    struct LiveSampleResult
    {
        qint64 sampleTimeMs = 0; // 后台采样完成时刻，UI排队延迟不能改写。
        bool gpuMemoryOk = false; // DXGI显存查询有效性，与引擎计数器gpuOk分开。
        bool perCoreOk = false;
        std::vector<double> coreUsageList;
        double totalCpuUsage = 0.0;
        bool powerInfoOk = false;
        std::vector<CpuPowerSnapshot> powerInfoList;
        bool memoryOk = false;
        double memoryUsagePercent = 0.0;
        std::uint64_t totalPhysBytes = 0;
        std::uint64_t availPhysBytes = 0;
        bool diskOk = false;
        double diskReadBytesPerSec = 0.0;
        double diskWriteBytesPerSec = 0.0;
        bool networkOk = false;
        double networkRxBytesPerSec = 0.0;
        double networkTxBytesPerSec = 0.0;
        bool gpuOk = false;
        double gpuUsagePercent = 0.0;
        bool systemPerfOk = false;
        SystemPerformanceSnapshot systemPerfSnapshot;
        QString primaryNetworkAdapterName;
        std::uint64_t primaryNetworkLinkBitsPerSecond = 0;
        double gpuUsage3DPercent = 0.0;
        double gpuUsageCopyPercent = 0.0;
        double gpuUsageVideoEncodePercent = 0.0;
        double gpuUsageVideoDecodePercent = 0.0;
        double gpuDedicatedUsedGiB = 0.0;
        double gpuDedicatedBudgetGiB = 0.0;
        double gpuSharedUsedGiB = 0.0;
        double gpuSharedBudgetGiB = 0.0;
        QString systemVolumeText;
        std::uint64_t systemVolumeTotalBytes = 0;
        std::uint64_t systemVolumeFreeBytes = 0;
    };

    void initializeUi();
    void initializeSidebarCards();
    void initializeCpuPage();
    void initializeMemoryPage();
    void initializeDiskPage();
    void initializeNetworkPage();
    void initializeGpuPage();
    void initializeCoreCharts();
    void syncSidebarSelection(int selectedRowIndex);
    void adjustChartHeights();

    void initializePerformanceCounters();
    void refreshAllViews();
    void requestLiveRefresh();
    LiveSampleResult collectLiveSampleResult();
    void applyLiveSampleResult(const LiveSampleResult& liveSampleResult);
    bool samplePerCoreUsage(std::vector<double>* coreUsageOut, double* totalUsageOut);
    bool sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut);
    bool sampleMemoryUsage(double* memoryUsagePercentOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    bool sampleGpuUsage(double* gpuUsagePercentOut);
    bool sampleGpuMemoryInfoByDxgi();
    bool sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const;

    void updateView(
        const std::vector<double>& coreUsageList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateSidebarCards(
        double cpuUsagePercent,
        double memoryUsagePercent,
        std::uint64_t totalPhysBytes,
        std::uint64_t availPhysBytes,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateTaskManagerDetailLabels(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent,
        const SystemPerformanceSnapshot* systemPerfSnapshotPointer,
        bool systemPerfOk);
    void appendCoreSeriesPoint(CoreChartEntry& chartEntry, double usagePercent);
    void appendGeneralSeriesPoint(
        QLineSeries* lineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0);
    QString formatRateText(double bytesPerSecondValue) const;

    void requestAsyncStaticInfoRefresh();
    void requestAsyncSensorRefresh();
    void refreshCpuTopologyStaticInfo();
    void refreshSystemVolumeInfo();
    QString buildCpuSensorText(bool forceRefresh);

private:
    QHBoxLayout* m_bodyLayout = nullptr;
    QListWidget* m_sidebarList = nullptr;
    QStackedWidget* m_detailStack = nullptr;
    QTimer* m_refreshTimer = nullptr;
    QFutureWatcher<LiveSampleResult>* m_liveSampleWatcher = nullptr;
    QMutex m_liveSampleMutex;
    bool m_liveSampleInProgress = false;

    PerformanceNavCard* m_cpuNavCard = nullptr;
    PerformanceNavCard* m_memoryNavCard = nullptr;
    PerformanceNavCard* m_diskNavCard = nullptr;
    PerformanceNavCard* m_networkNavCard = nullptr;
    PerformanceNavCard* m_gpuNavCard = nullptr;

    QWidget* m_cpuPage = nullptr;
    QLabel* m_cpuModelLabel = nullptr;
    QLabel* m_cpuSummaryLabel = nullptr;
    QScrollArea* m_coreChartScrollArea = nullptr;
    QWidget* m_coreChartHostWidget = nullptr;
    QGridLayout* m_coreChartGridLayout = nullptr;
    QLabel* m_cpuPrimaryDetailLabel = nullptr;
    QLabel* m_cpuSecondaryDetailLabel = nullptr;

    QWidget* m_memoryPage = nullptr;
    QLabel* m_memoryCapacityLabel = nullptr;
    QLabel* m_memorySummaryLabel = nullptr;
    QChartView* m_memoryChartView = nullptr;
    QLineSeries* m_memoryLineSeries = nullptr;
    QValueAxis* m_memoryAxisX = nullptr;
    QValueAxis* m_memoryAxisY = nullptr;
    QLabel* m_memoryPrimaryDetailLabel = nullptr;
    QLabel* m_memorySecondaryDetailLabel = nullptr;

    QWidget* m_diskPage = nullptr;
    QLabel* m_diskSummaryLabel = nullptr;
    QChartView* m_diskChartView = nullptr;
    QLineSeries* m_diskReadLineSeries = nullptr;
    QLineSeries* m_diskWriteLineSeries = nullptr;
    QValueAxis* m_diskAxisX = nullptr;
    QValueAxis* m_diskAxisY = nullptr;
    QLabel* m_diskDetailLabel = nullptr;

    QWidget* m_networkPage = nullptr;
    QLabel* m_networkSummaryLabel = nullptr;
    QChartView* m_networkChartView = nullptr;
    QLineSeries* m_networkRxLineSeries = nullptr;
    QLineSeries* m_networkTxLineSeries = nullptr;
    QValueAxis* m_networkAxisX = nullptr;
    QValueAxis* m_networkAxisY = nullptr;
    QLabel* m_networkDetailLabel = nullptr;

    QWidget* m_gpuPage = nullptr;
    QLabel* m_gpuAdapterTitleLabel = nullptr;
    QLabel* m_gpuSummaryLabel = nullptr;
    QWidget* m_gpuEngineHostWidget = nullptr;
    QGridLayout* m_gpuEngineGridLayout = nullptr;
    std::vector<GpuEngineChartEntry> m_gpuEngineCharts;
    QChartView* m_gpuDedicatedMemoryChartView = nullptr;
    QLineSeries* m_gpuDedicatedMemoryLineSeries = nullptr;
    QValueAxis* m_gpuDedicatedMemoryAxisX = nullptr;
    QValueAxis* m_gpuDedicatedMemoryAxisY = nullptr;
    QChartView* m_gpuSharedMemoryChartView = nullptr;
    QLineSeries* m_gpuSharedMemoryLineSeries = nullptr;
    QValueAxis* m_gpuSharedMemoryAxisX = nullptr;
    QValueAxis* m_gpuSharedMemoryAxisY = nullptr;
    QLabel* m_gpuDetailLabel = nullptr;

    std::vector<CoreChartEntry> m_coreChartEntries;
    int m_cpuCoreGridColumnCount = 1;
    int m_cpuCoreGridRowCount = 1;

    qint64 m_metricSampleTimeMs = 0; // 本帧共同采样时间，毫秒。
    bool m_metricDiskValid = true; // 磁盘采样有效性，失败保留断点。
    bool m_metricNetworkValid = true; // 网络采样有效性，失败保留断点。
    bool m_metricMemoryValid = true; // 内存查询有效位。
    bool m_metricGpuValid = true; // GPU引擎计数器有效位。
    bool m_gpuMetricMemoryValid = false; // 当前后台DXGI显存查询是否成功。
    bool m_metricGpuMemoryValid = true; // 当前UI帧携带的显存有效位。
    int m_historyLength = 60;
    int m_sampleCounter = 60;
    QString m_cachedSensorText;
    std::atomic_bool m_staticInfoRefreshing{ false };
    std::atomic_bool m_sensorRefreshing{ false };
    std::uint64_t m_lastNetworkRxBytes = 0;
    std::uint64_t m_lastNetworkTxBytes = 0;
    qint64 m_lastNetworkSampleMs = 0;
    QString m_primaryNetworkAdapterName;
    std::uint64_t m_primaryNetworkLinkBitsPerSecond = 0;

    QString m_cpuModelText;
    int m_cpuPackageCount = 0;
    int m_cpuPhysicalCoreCount = 0;
    int m_cpuLogicalCoreCount = 0;
    std::uint64_t m_cpuL1CacheBytes = 0;
    std::uint64_t m_cpuL2CacheBytes = 0;
    std::uint64_t m_cpuL3CacheBytes = 0;
    double m_lastCpuSpeedGhz = 0.0;

    int m_memorySpeedMhz = 0;
    int m_memorySlotUsed = 0;
    int m_memorySlotTotal = 0;
    QString m_memoryFormFactorText;

    QString m_gpuAdapterNameText;
    QString m_gpuDriverVersionText;
    QString m_gpuDriverDateText;
    QString m_gpuPnpDeviceIdText;
    double m_gpuDedicatedMemoryGiB = 0.0;
    double m_gpuUsage3DPercent = 0.0;
    double m_gpuUsageCopyPercent = 0.0;
    double m_gpuUsageVideoEncodePercent = 0.0;
    double m_gpuUsageVideoDecodePercent = 0.0;
    double m_gpuDedicatedUsedGiB = 0.0;
    double m_gpuDedicatedBudgetGiB = 0.0;
    double m_gpuSharedUsedGiB = 0.0;
    double m_gpuSharedBudgetGiB = 0.0;

    QString m_systemVolumeText;
    std::uint64_t m_systemVolumeTotalBytes = 0;
    std::uint64_t m_systemVolumeFreeBytes = 0;
    std::uint64_t m_lastTotalPhysBytes = 0;
    std::uint64_t m_lastAvailPhysBytes = 0;

    double m_diskNavAutoScaleBytesPerSec = 1024.0 * 1024.0;
    double m_networkNavAutoScaleBytesPerSec = 1024.0 * 1024.0;

    void* m_cpuPerfQueryHandle = nullptr;
    std::vector<void*> m_coreCounterHandles;
    void* m_diskPerfQueryHandle = nullptr;
    void* m_diskReadCounterHandle = nullptr;
    void* m_diskWriteCounterHandle = nullptr;
    void* m_gpuPerfQueryHandle = nullptr;
    void* m_gpuCounterHandle = nullptr;
};
