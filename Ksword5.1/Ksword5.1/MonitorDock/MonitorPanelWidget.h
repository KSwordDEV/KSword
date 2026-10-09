#pragma once

// ============================================================
// MonitorPanelWidget.h
// 作用：
// 1) 提供“监视面板”Dock的四宫格性能图（CPU/内存/磁盘/网络）；
// 2) CPU 图按“每个逻辑核心”展示柱状条；
// 3) 采样逻辑独立于 MonitorDock，避免与 WMI/ETW 页面耦合。
// ============================================================

#include "../Framework.h"

#include <QWidget>

#include <cstdint> // std::uint64_t：保存时间戳与累计字节计数。
#include <vector>  // std::vector：保存每核计数器句柄与采样结果。

class QBarSet;
class QChartView;
class QGridLayout;
class QLabel;
class QLineSeries;
class QResizeEvent;
class QShowEvent;
class QEvent;
class QTimer;
class QValueAxis;
class QVBoxLayout;

class MonitorPanelWidget final : public QWidget
{
public:
    // 构造函数作用：
    // - 初始化四宫格图表；
    // - 启动 1 秒刷新定时器。
    // 参数 parent：Qt 父控件。
    explicit MonitorPanelWidget(QWidget* parent = nullptr);

    // 析构函数作用：
    // - 停止刷新定时器；
    // - 释放 PDH 查询句柄，避免资源泄漏。
    ~MonitorPanelWidget() override;

protected:
    // resizeEvent 作用：
    // - Dock 高度变化时重算四宫格图高度；
    // - 尽量避免监视面板出现滚动条。
    void resizeEvent(QResizeEvent* resizeEventPointer) override;

    // showEvent 作用：
    // - 首次展示后触发一次延迟重排；
    // - 解决初始 geometry 尚未稳定时的高度估算偏差。
    void showEvent(QShowEvent* showEventPointer) override;

    // changeEvent 作用：主题、样式或应用调色板变化后立即重刷图表文字颜色。
    void changeEvent(QEvent* eventPointer) override;

private:
    // initializeUi 作用：
    // - 创建 CPU/内存/磁盘/网络图表控件与布局。
    void initializeUi();

    // initializeCounters 作用：
    // - 初始化 CPU 每核与磁盘读写 PDH 计数器。
    void initializeCounters();

    // refreshMetrics 作用：
    // - 执行一次系统采样；
    // - 刷新四张图的可视数据。
    void refreshMetrics();

    // samplePerCoreCpuUsage 作用：
    // - 读取每个逻辑核心的实时利用率；
    // - 输出总 CPU 平均利用率。
    // 参数 coreUsagesOut：每核利用率输出数组。
    // 参数 totalUsageOut：总平均利用率输出值。
    // 返回：true=采样成功，false=采样失败。
    bool samplePerCoreCpuUsage(
        std::vector<double>* coreUsagesOut,
        double* totalUsageOut);

    struct MemoryCompositionSample
    {
        double usedPercent = 0.0;       // usedPercent：物理内存使用百分比。
        double standbyPercent = 0.0;    // standbyPercent：近似缓存/备用百分比。
        double availablePercent = 0.0;  // availablePercent：可用物理内存百分比。
        double commitPercent = 0.0;     // commitPercent：提交量占提交上限百分比。
    };

    // sampleMemoryUsage 作用：
    // - 获取系统内存组成百分比。
    // 参数 memorySampleOut：内存组成输出值。
    // 返回：true=采样成功，false=采样失败。
    bool sampleMemoryUsage(MemoryCompositionSample* memorySampleOut) const;

    // sampleDiskRate 作用：
    // - 获取系统总磁盘读写速率（字节/秒）。
    // 参数 readBytesPerSecOut：读取速率输出值。
    // 参数 writeBytesPerSecOut：写入速率输出值。
    // 返回：true=采样成功，false=采样失败。
    bool sampleDiskRate(
        double* readBytesPerSecOut,
        double* writeBytesPerSecOut);

    // sampleNetworkRate 作用：
    // - 获取系统网络上下行速率（字节/秒）。
    // 参数 rxBytesPerSecOut：下行速率输出值。
    // 参数 txBytesPerSecOut：上行速率输出值。
    // 返回：true=采样成功，false=采样失败。
    bool sampleNetworkRate(
        double* rxBytesPerSecOut,
        double* txBytesPerSecOut);

    // appendLineSample 作用：
    // - 给折线图追加一个采样点；
    // - 自动维护历史长度与轴范围。
    // 参数 series：目标折线序列。
    // 参数 axisX：X 轴对象。
    // 参数 axisY：Y 轴对象。
    // 参数 value：本次采样值。
    void appendLineSample(
        QLineSeries* series,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double value);

    // adjustChartCellHeights 作用：
    // - 按当前 Dock 可用高度压缩四张图；
    // - 统一设置最小/最大高度，防止外层布局因最小高度触发滚动条。
    void adjustChartCellHeights();

    // applyChartTextTheme 作用：
    // - 统一刷新图表标题、图例、坐标轴文字颜色；
    // - 修复深色模式下左下角监视器文字对比度过低。
    void applyChartTextTheme();

    // updateCompactVisibility 作用：
    // - 当 Dock 高度过低时隐藏四张图，仅显示文字摘要；
    // - 避免自绘图表在极小高度下反复布局造成闪烁；
    // - 返回：无返回值，直接更新控件可见性。
    void updateCompactVisibility();

private:
    // 布局控件。
    QVBoxLayout* m_rootLayout = nullptr;   // m_rootLayout：根布局。
    QGridLayout* m_chartGridLayout = nullptr; // m_chartGridLayout：四宫格布局。
    QLabel* m_compactSummaryLabel = nullptr; // m_compactSummaryLabel：低高度时显示的文字摘要。
    QTimer* m_refreshTimer = nullptr;      // m_refreshTimer：性能采样定时器。

    // CPU/内存图控件。
    QChartView* m_cpuChartView = nullptr;     // m_cpuChartView：CPU 每核柱状图。
    QChartView* m_memoryTrendChartView = nullptr; // m_memoryTrendChartView：内存占用与组成合并趋势图。
    QBarSet* m_cpuCoreBarSet = nullptr;       // m_cpuCoreBarSet：CPU 每核当前柱条数据集。
    QBarSet* m_cpuCoreHistoryBarSet = nullptr; // m_cpuCoreHistoryBarSet：CPU 每核历史半透明柱条数据集。
    QLineSeries* m_memoryUsedSeries = nullptr; // m_memoryUsedSeries：已用组成面积上边界。
    QLineSeries* m_memoryStandbyTopSeries = nullptr; // m_memoryStandbyTopSeries：提交/缓存面积上边界。
    QLineSeries* m_memoryStandbyBaseSeries = nullptr; // m_memoryStandbyBaseSeries：提交/缓存面积下边界。
    QLineSeries* m_memoryAvailableTopSeries = nullptr; // m_memoryAvailableTopSeries：可用面积上边界。
    QLineSeries* m_memoryAvailableBaseSeries = nullptr; // m_memoryAvailableBaseSeries：可用面积下边界。
    QLineSeries* m_memoryUsageSeries = nullptr; // m_memoryUsageSeries：内存占用历史折线。
    QValueAxis* m_memoryTrendAxisX = nullptr; // m_memoryTrendAxisX：内存合并趋势 X 轴。
    QValueAxis* m_memoryTrendAxisY = nullptr; // m_memoryTrendAxisY：内存合并趋势 Y 轴。
    std::vector<double> m_cpuCoreHistoryPercentList; // m_cpuCoreHistoryPercentList：每核历史平均占用率。

    // 磁盘/网络图控件。
    QChartView* m_diskChartView = nullptr;    // m_diskChartView：磁盘读写折线图。
    QChartView* m_networkChartView = nullptr; // m_networkChartView：网络上下行折线图。
    QLineSeries* m_diskReadSeries = nullptr;  // m_diskReadSeries：磁盘读速率序列。
    QLineSeries* m_diskWriteSeries = nullptr; // m_diskWriteSeries：磁盘写速率序列。
    QLineSeries* m_networkRxSeries = nullptr; // m_networkRxSeries：网络下行速率序列。
    QLineSeries* m_networkTxSeries = nullptr; // m_networkTxSeries：网络上行速率序列。
    QValueAxis* m_diskAxisX = nullptr;        // m_diskAxisX：磁盘图 X 轴。
    QValueAxis* m_diskAxisY = nullptr;        // m_diskAxisY：磁盘图 Y 轴。
    QValueAxis* m_networkAxisX = nullptr;     // m_networkAxisX：网络图 X 轴。
    QValueAxis* m_networkAxisY = nullptr;     // m_networkAxisY：网络图 Y 轴。

    // 历史采样状态。
    qint64 m_metricSampleTimeMs = 0; // 本帧共同采样时间，毫秒。
    bool m_metricDiskValid = true; // 磁盘采样有效性，失败保留断点。
    bool m_metricNetworkValid = true; // 网络采样有效性，失败保留断点。
    bool m_metricMemoryValid = true; // 内存组成查询有效位。
    int m_historyLength = 60;        // m_historyLength：折线图保留点数。
    int m_sampleCounter = 0;         // m_sampleCounter：当前采样序号。
    QString m_lastCompactSummaryText; // m_lastCompactSummaryText：最近一次采样摘要文本。
    std::uint64_t m_lastNetworkRxBytes = 0; // m_lastNetworkRxBytes：上次网络接收累计字节。
    std::uint64_t m_lastNetworkTxBytes = 0; // m_lastNetworkTxBytes：上次网络发送累计字节。
    qint64 m_lastNetworkSampleMs = 0;       // m_lastNetworkSampleMs：上次网络采样时间戳(ms)。

    // PDH 句柄缓存。
    void* m_cpuPerfQueryHandle = nullptr;       // m_cpuPerfQueryHandle：CPU 查询句柄。
    std::vector<void*> m_coreCounterHandles;    // m_coreCounterHandles：每核 CPU 计数器句柄。
    void* m_diskPerfQueryHandle = nullptr;      // m_diskPerfQueryHandle：磁盘查询句柄。
    void* m_diskReadCounterHandle = nullptr;    // m_diskReadCounterHandle：磁盘读取计数器句柄。
    void* m_diskWriteCounterHandle = nullptr;   // m_diskWriteCounterHandle：磁盘写入计数器句柄。
};
