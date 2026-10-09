#include "MonitorPanelWidget.h"
#include "../Internationalization/LanguageManager.h"
#include "../../../shared/ui/KsPainterChart.h"
#include "../../../shared/ui/MetricChartBinding.h"

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
#include <QFont>
#include <QLabel>
#include <QList>
#include <QMetaObject>
#include <QPainter>
#include <QPointer>
#include <QResizeEvent>
#include <QShowEvent>
#include <QSizePolicy>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Pdh.h>
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
    // - 只保存 void* 值类型，便于整体回投 UI 线程接管，不牵扯任何 QWidget。
    struct MonitorPanelPdhCounterBundle
    {
        void* cpuQueryHandle = nullptr;         // cpuQueryHandle：CPU 查询句柄。
        std::vector<void*> coreCounterHandles;  // coreCounterHandles：每个逻辑核心的计数器句柄。
        void* diskQueryHandle = nullptr;        // diskQueryHandle：磁盘查询句柄。
        void* diskReadCounterHandle = nullptr;  // diskReadCounterHandle：磁盘读取速率计数器句柄。
        void* diskWriteCounterHandle = nullptr; // diskWriteCounterHandle：磁盘写入速率计数器句柄。
    };

    // monitorPanelCounterInitializing 作用：
    // - 标记当前是否已有一轮后台 PDH 初始化在执行；
    // - 防止初始化未完成期间每秒刷新重复投递任务。
    std::atomic_bool monitorPanelCounterInitializing{ false };

    // createMonitorPanelPdhCounters 作用：
    // - 入参 coreCount：逻辑核心数量，决定注册多少个 \Processor(n) 计数器；
    // - 入参 needCpuCounters/needDiskCounters：控件尚未持有对应句柄时才重新创建，避免重试轮空跑；
    // - 处理：在调用线程完成 PdhOpenQueryW/PdhAddEnglishCounterW 与首次基线采集，
    //         进程内第一次调用会顺带加载 perflib 计数器名索引，耗时集中在这里；
    // - 返回：句柄集合，失败字段保持 nullptr 由调用方按空句柄回退。
    MonitorPanelPdhCounterBundle createMonitorPanelPdhCounters(
        const int coreCount,
        const bool needCpuCounters,
        const bool needDiskCounters)
    {
        MonitorPanelPdhCounterBundle counterBundle;

        // CPU 每核计数器：为每一个核心添加 \Processor(n)\% Processor Time。
        PDH_HQUERY cpuQueryHandle = nullptr;
        if (needCpuCounters
            && ::PdhOpenQueryW(nullptr, 0, &cpuQueryHandle) == ERROR_SUCCESS
            && cpuQueryHandle != nullptr)
        {
            const int safeCoreCount = std::max(0, coreCount);
            counterBundle.coreCounterHandles.reserve(static_cast<std::size_t>(safeCoreCount));
            for (int coreIndex = 0; coreIndex < safeCoreCount; ++coreIndex)
            {
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
            ::PdhCollectQueryData(cpuQueryHandle);
            counterBundle.cpuQueryHandle = cpuQueryHandle;
        }

        // 磁盘计数器：读取系统总磁盘读写字节每秒速率，失败时整体丢弃。
        PDH_HQUERY diskQueryHandle = nullptr;
        if (needDiskCounters
            && ::PdhOpenQueryW(nullptr, 0, &diskQueryHandle) == ERROR_SUCCESS
            && diskQueryHandle != nullptr)
        {
            PDH_HCOUNTER readCounterHandle = nullptr;
            PDH_HCOUNTER writeCounterHandle = nullptr;

            const PDH_STATUS addReadStatus = ::PdhAddEnglishCounterW(
                diskQueryHandle,
                L"\\PhysicalDisk(_Total)\\Disk Read Bytes/sec",
                0,
                &readCounterHandle);
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
                ::PdhCollectQueryData(diskQueryHandle);
                counterBundle.diskQueryHandle = diskQueryHandle;
                counterBundle.diskReadCounterHandle = readCounterHandle;
                counterBundle.diskWriteCounterHandle = writeCounterHandle;
            }
            else
            {
                ::PdhCloseQuery(diskQueryHandle);
            }
        }

        return counterBundle;
    }

    // closeMonitorPanelPdhCounters 作用：
    // - 入参 counterBundle：待释放的句柄集合；
    // - 处理：关闭 PDH 查询，供控件已销毁或句柄已由更早一轮接管时丢弃结果；
    // - 返回：无返回值。
    void closeMonitorPanelPdhCounters(const MonitorPanelPdhCounterBundle& counterBundle)
    {
        if (counterBundle.cpuQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.cpuQueryHandle));
        }
        if (counterBundle.diskQueryHandle != nullptr)
        {
            ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.diskQueryHandle));
        }
    }
}

MonitorPanelWidget::MonitorPanelWidget(QWidget* parent)
    : QWidget(parent)
{
    // 构造日志使用同一个 kLogEvent，方便按 GUID 追踪整个初始化流程。
    kLogEvent event;
    info << event << "[MonitorPanelWidget] 构造开始。" << eol;

    initializeUi();
    // 计数器初始化和首帧采样都在后台线程完成，构造阶段只搭图表骨架，主窗口可以先出画面。
    initializeCounters();

    // 采样定时器：
    // - 每秒更新一次性能图；
    // - 使用 UI 线程定时器，避免与图表对象跨线程访问。
    m_refreshTimer = new QTimer(this);
    m_refreshTimer->setInterval(1000);
    connect(m_refreshTimer, &QTimer::timeout, this, [this]() {
        refreshMetrics();
    });
    m_refreshTimer->start();

    info << event << "[MonitorPanelWidget] 构造完成。" << eol;
}

MonitorPanelWidget::~MonitorPanelWidget()
{
    if (m_refreshTimer != nullptr)
    {
        m_refreshTimer->stop();
    }

    // 释放 CPU 查询句柄与每核计数器句柄。
    if (m_cpuPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
        m_cpuPerfQueryHandle = nullptr;
        m_coreCounterHandles.clear();
    }

    // 释放磁盘查询句柄与读写计数器句柄。
    if (m_diskPerfQueryHandle != nullptr)
    {
        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(m_diskPerfQueryHandle));
        m_diskPerfQueryHandle = nullptr;
        m_diskReadCounterHandle = nullptr;
        m_diskWriteCounterHandle = nullptr;
    }
}

void MonitorPanelWidget::resizeEvent(QResizeEvent* resizeEventPointer)
{
    QWidget::resizeEvent(resizeEventPointer);
    updateCompactVisibility();
    adjustChartCellHeights();
}

void MonitorPanelWidget::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
    applyChartTextTheme();
    updateCompactVisibility();
    // 延迟到事件循环末尾再重排，保证首帧也能拿到稳定几何尺寸。
    QTimer::singleShot(0, this, [this]()
    {
        adjustChartCellHeights();
    });
    // Dock 布局在 show 后可能继续调整，补一帧延迟避免底部两张图首帧被压没。
    QTimer::singleShot(80, this, [this]()
    {
        adjustChartCellHeights();
    });
}

void MonitorPanelWidget::changeEvent(QEvent* eventPointer)
{
    QWidget::changeEvent(eventPointer);
    if (eventPointer == nullptr)
    {
        return;
    }

    const QEvent::Type eventType = eventPointer->type();
    if (eventType == QEvent::PaletteChange ||
        eventType == QEvent::ApplicationPaletteChange ||
        eventType == QEvent::StyleChange)
    {
        applyChartTextTheme();
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

void MonitorPanelWidget::initializeCounters()
{
    // 计数器初始化整体异步化：
    // - 进程内第一次 PdhAddEnglishCounterW 需要加载并解析 perflib 计数器名索引，
    //   在主窗口构造链路里同步执行会让启动阶段整个界面卡住；
    // - UI 线程这里只读取核心数量，PDH 调用全部交给线程池，完成后回投接管句柄。
    if (m_cpuPerfQueryHandle != nullptr && m_diskPerfQueryHandle != nullptr)
    {
        return;
    }

    // expectedInitializingValue 用途：CAS 期望值（false=当前没有初始化任务在跑）。
    bool expectedInitializingValue = false;
    if (!monitorPanelCounterInitializing.compare_exchange_strong(expectedInitializingValue, true))
    {
        return;
    }

    // coreCount 必须在 UI 线程读取：QBarSet 属于图表控件，后台线程不允许访问。
    const int coreCount = m_cpuCoreBarSet != nullptr ? std::max(0, m_cpuCoreBarSet->count()) : 0;
    const bool needCpuCounters = m_cpuPerfQueryHandle == nullptr;
    const bool needDiskCounters = m_diskPerfQueryHandle == nullptr;

    // guardedSelf 用途：后台任务可能晚于控件销毁，回投前必须验证生命周期。
    const QPointer<MonitorPanelWidget> guardedSelf(this);
    QThreadPool::globalInstance()->start(
        [guardedSelf, coreCount, needCpuCounters, needDiskCounters]()
        {
            // 后台线程只做纯数据采集，产出的是可跨线程搬运的句柄值类型。
            const MonitorPanelPdhCounterBundle counterBundle = createMonitorPanelPdhCounters(
                coreCount,
                needCpuCounters,
                needDiskCounters);

            // applicationInstance 与事件循环同寿命；工作线程不解引用控件指针。
            QCoreApplication* const applicationInstance = QCoreApplication::instance();
            if (applicationInstance == nullptr)
            {
                closeMonitorPanelPdhCounters(counterBundle);
                monitorPanelCounterInitializing.store(false);
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                applicationInstance,
                [guardedSelf, counterBundle]()
                {
                    if (guardedSelf.isNull())
                    {
                        closeMonitorPanelPdhCounters(counterBundle);
                        monitorPanelCounterInitializing.store(false);
                        return;
                    }

                    // 控件已持有句柄说明更早一轮初始化已完成，本轮结果直接丢弃避免泄漏。
                    if (guardedSelf->m_cpuPerfQueryHandle == nullptr)
                    {
                        guardedSelf->m_cpuPerfQueryHandle = counterBundle.cpuQueryHandle;
                        guardedSelf->m_coreCounterHandles = counterBundle.coreCounterHandles;
                    }
                    else if (counterBundle.cpuQueryHandle != nullptr)
                    {
                        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.cpuQueryHandle));
                    }

                    if (guardedSelf->m_diskPerfQueryHandle == nullptr)
                    {
                        guardedSelf->m_diskPerfQueryHandle = counterBundle.diskQueryHandle;
                        guardedSelf->m_diskReadCounterHandle = counterBundle.diskReadCounterHandle;
                        guardedSelf->m_diskWriteCounterHandle = counterBundle.diskWriteCounterHandle;
                    }
                    else if (counterBundle.diskQueryHandle != nullptr)
                    {
                        ::PdhCloseQuery(reinterpret_cast<PDH_HQUERY>(counterBundle.diskQueryHandle));
                    }

                    // 句柄就绪后立即补一帧，避免初始化窗口期图表长时间停在 0；
                    // 标记放在刷新之后清除，防止刷新内部又立刻投递一轮初始化任务。
                    guardedSelf->refreshMetrics();
                    monitorPanelCounterInitializing.store(false);
                },
                Qt::QueuedConnection);

            if (!invokeOk)
            {
                closeMonitorPanelPdhCounters(counterBundle);
                monitorPanelCounterInitializing.store(false);
            }
        });
}

void MonitorPanelWidget::refreshMetrics()
{
    // 采样 CPU 每核占用与总占用平均值。
    std::vector<double> perCoreUsageList;
    double totalCpuUsage = 0.0;
    if (!samplePerCoreCpuUsage(&perCoreUsageList, &totalCpuUsage))
    {
        perCoreUsageList.assign(static_cast<std::size_t>(
            m_cpuCoreBarSet != nullptr ? std::max(0, m_cpuCoreBarSet->count()) : 0), 0.0);
        totalCpuUsage = 0.0;
    }

    // 更新 CPU 每核柱条数据。
    if (m_cpuCoreBarSet != nullptr)
    {
        const int coreBarCount = m_cpuCoreBarSet->count();
        for (int indexValue = 0; indexValue < coreBarCount; ++indexValue)
        {
            const double usageValue =
                indexValue < static_cast<int>(perCoreUsageList.size())
                ? perCoreUsageList[static_cast<std::size_t>(indexValue)]
                : 0.0;
            const double previousHistoryValue =
                indexValue < static_cast<int>(m_cpuCoreHistoryPercentList.size())
                ? m_cpuCoreHistoryPercentList[static_cast<std::size_t>(indexValue)]
                : 0.0;
            const double historyValue = previousHistoryValue <= 0.0
                ? usageValue
                : previousHistoryValue * 0.88 + usageValue * 0.12;
            if (indexValue < static_cast<int>(m_cpuCoreHistoryPercentList.size()))
            {
                m_cpuCoreHistoryPercentList[static_cast<std::size_t>(indexValue)] = historyValue;
            }
            if (m_cpuCoreHistoryBarSet != nullptr && indexValue < m_cpuCoreHistoryBarSet->count())
            {
                m_cpuCoreHistoryBarSet->replace(indexValue, historyValue);
            }
            m_cpuCoreBarSet->replace(indexValue, usageValue);
        }
    }
    if (m_cpuChartView != nullptr && m_cpuChartView->chart() != nullptr)
    {
        m_cpuChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.cpu.title.dynamic"),
                QStringLiteral("CPU 每核心利用率（总体 %1%）"))
            .arg(totalCpuUsage, 0, 'f', 1));
    }

    // 采样并更新内存合并图：折线表示总占用，面积颜色表示当前时刻组成比例。
    MemoryCompositionSample memorySample{};
    m_metricMemoryValid = sampleMemoryUsage(&memorySample);
    if (!m_metricMemoryValid)
    {
        memorySample = MemoryCompositionSample{};
    }
    const double memoryUsedTopPercent = memorySample.usedPercent;
    const double memoryStandbyTopPercent = std::clamp(
        memorySample.usedPercent + memorySample.standbyPercent,
        0.0,
        100.0);
    const double memoryAvailableTopPercent = std::clamp(
        memoryStandbyTopPercent + memorySample.availablePercent,
        0.0,
        100.0);
    if (m_memoryTrendChartView != nullptr && m_memoryTrendChartView->chart() != nullptr)
    {
        m_memoryTrendChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.memory.title.dynamic"),
                QStringLiteral("内存占用/组成  占用:%1%  缓存:%2%  可用:%3%"))
            .arg(memorySample.usedPercent, 0, 'f', 1)
            .arg(memorySample.standbyPercent, 0, 'f', 1)
            .arg(memorySample.availablePercent, 0, 'f', 1));
    }

    // 采样并更新磁盘/网络折线图。
    double diskReadBytesPerSec = 0.0;
    double diskWriteBytesPerSec = 0.0;
    m_metricDiskValid = sampleDiskRate(&diskReadBytesPerSec, &diskWriteBytesPerSec);
    if (!m_metricDiskValid)
    {
        diskReadBytesPerSec = 0.0;
        diskWriteBytesPerSec = 0.0;
    }

    double networkRxBytesPerSec = 0.0;
    double networkTxBytesPerSec = 0.0;
    m_metricNetworkValid = sampleNetworkRate(&networkRxBytesPerSec, &networkTxBytesPerSec);
    if (!m_metricNetworkValid)
    {
        networkRxBytesPerSec = 0.0;
        networkTxBytesPerSec = 0.0;
    }

    m_metricSampleTimeMs = QDateTime::currentMSecsSinceEpoch(); // 本帧各指标时间一致。
    ++m_sampleCounter;
    appendLineSample(m_memoryUsedSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryUsedTopPercent);
    appendLineSample(m_memoryStandbyTopSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryStandbyTopPercent);
    appendLineSample(m_memoryStandbyBaseSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryUsedTopPercent);
    appendLineSample(m_memoryAvailableTopSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryAvailableTopPercent);
    appendLineSample(m_memoryAvailableBaseSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memoryStandbyTopPercent);
    appendLineSample(m_memoryUsageSeries, m_memoryTrendAxisX, m_memoryTrendAxisY, memorySample.usedPercent);
    if (m_memoryTrendAxisY != nullptr)
    {
        m_memoryTrendAxisY->setRange(0.0, 100.0);
    }
    appendLineSample(m_diskReadSeries, m_diskAxisX, m_diskAxisY, diskReadBytesPerSec);
    appendLineSample(m_diskWriteSeries, m_diskAxisX, m_diskAxisY, diskWriteBytesPerSec);
    appendLineSample(m_networkRxSeries, m_networkAxisX, m_networkAxisY, networkRxBytesPerSec);
    appendLineSample(m_networkTxSeries, m_networkAxisX, m_networkAxisY, networkTxBytesPerSec);

    // 双序列共享 Y 轴，需要按两条线共同最大值修正 Y 范围。
    auto updateAxisRangeByPair = [](
        QLineSeries* firstSeries,
        QLineSeries* secondSeries,
        QValueAxis* axisY) {
        if (firstSeries == nullptr || secondSeries == nullptr || axisY == nullptr)
        {
            return;
        }

        const auto range = ks::ui::MetricChartBinding::SharedRange({ firstSeries, secondSeries },
            ks::ui::MetricXMode::RelativeSlot, { 0.0, 1.0, 1.2, {} });
        axisY->setRange(range.minimumY, range.maximumY);
    };
    updateAxisRangeByPair(m_diskReadSeries, m_diskWriteSeries, m_diskAxisY);
    updateAxisRangeByPair(m_networkRxSeries, m_networkTxSeries, m_networkAxisY);

    if (m_diskChartView != nullptr && m_diskChartView->chart() != nullptr)
    {
        m_diskChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.disk.title.dynamic"),
                QStringLiteral("磁盘读写速率  读:%1  写:%2"))
            .arg(bytesPerSecondToText(diskReadBytesPerSec))
            .arg(bytesPerSecondToText(diskWriteBytesPerSec)));
    }
    if (m_networkChartView != nullptr && m_networkChartView->chart() != nullptr)
    {
        m_networkChartView->chart()->setTitle(
            ks::i18n::contextText(
                QStringLiteral("monitor.panel.network.title.dynamic"),
                QStringLiteral("网络收发速率  下:%1  上:%2"))
            .arg(bytesPerSecondToText(networkRxBytesPerSec))
            .arg(bytesPerSecondToText(networkTxBytesPerSec)));
    }

    m_lastCompactSummaryText = ks::i18n::contextText(
        QStringLiteral("monitor.panel.compact.summary"),
        QStringLiteral("CPU %1% | 内存 %2% | 磁盘 读 %3 / 写 %4 | 网络 下 %5 / 上 %6"))
        .arg(totalCpuUsage, 0, 'f', 1)
        .arg(memorySample.usedPercent, 0, 'f', 1)
        .arg(bytesPerSecondToText(diskReadBytesPerSec))
        .arg(bytesPerSecondToText(diskWriteBytesPerSec))
        .arg(bytesPerSecondToText(networkRxBytesPerSec))
        .arg(bytesPerSecondToText(networkTxBytesPerSec));
    if (m_compactSummaryLabel != nullptr)
    {
        m_compactSummaryLabel->setText(m_lastCompactSummaryText);
    }
    updateCompactVisibility();
}

bool MonitorPanelWidget::samplePerCoreCpuUsage(
    std::vector<double>* coreUsagesOut,
    double* totalUsageOut)
{
    if (coreUsagesOut == nullptr || totalUsageOut == nullptr)
    {
        return false;
    }

    if (m_cpuPerfQueryHandle == nullptr)
    {
        initializeCounters();
    }
    if (m_cpuPerfQueryHandle == nullptr)
    {
        return false;
    }

    const PDH_STATUS collectStatus = ::PdhCollectQueryData(
        reinterpret_cast<PDH_HQUERY>(m_cpuPerfQueryHandle));
    if (collectStatus != ERROR_SUCCESS)
    {
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
        if (readStatus != ERROR_SUCCESS)
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

bool MonitorPanelWidget::sampleMemoryUsage(MemoryCompositionSample* memorySampleOut) const
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

bool MonitorPanelWidget::sampleDiskRate(
    double* readBytesPerSecOut,
    double* writeBytesPerSecOut)
{
    if (readBytesPerSecOut == nullptr || writeBytesPerSecOut == nullptr)
    {
        return false;
    }

    if (m_diskPerfQueryHandle == nullptr)
    {
        initializeCounters();
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
    if (readStatus != ERROR_SUCCESS || writeStatus != ERROR_SUCCESS)
    {
        return false;
    }

    *readBytesPerSecOut = std::max(0.0, readCounterValue.doubleValue);
    *writeBytesPerSecOut = std::max(0.0, writeCounterValue.doubleValue);
    return true;
}

bool MonitorPanelWidget::sampleNetworkRate(
    double* rxBytesPerSecOut,
    double* txBytesPerSecOut)
{
    if (rxBytesPerSecOut == nullptr || txBytesPerSecOut == nullptr)
    {
        return false;
    }

    MIB_IF_TABLE2* ifTablePointer = nullptr;
    const DWORD tableStatus = ::GetIfTable2(&ifTablePointer);
    if (tableStatus != NO_ERROR || ifTablePointer == nullptr)
    {
        return false;
    }

    std::uint64_t totalRxBytes = 0;
    std::uint64_t totalTxBytes = 0;
    for (ULONG rowIndex = 0; rowIndex < ifTablePointer->NumEntries; ++rowIndex)
    {
        const MIB_IF_ROW2& rowValue = ifTablePointer->Table[rowIndex];
        if (rowValue.OperStatus != IfOperStatusUp)
        {
            continue;
        }
        if (rowValue.Type == IF_TYPE_SOFTWARE_LOOPBACK)
        {
            continue;
        }

        totalRxBytes += static_cast<std::uint64_t>(rowValue.InOctets);
        totalTxBytes += static_cast<std::uint64_t>(rowValue.OutOctets);
    }
    ::FreeMibTable(ifTablePointer);

    const qint64 currentSampleMs = QDateTime::currentMSecsSinceEpoch();
    if (m_lastNetworkSampleMs <= 0)
    {
        m_lastNetworkSampleMs = currentSampleMs;
        m_lastNetworkRxBytes = totalRxBytes;
        m_lastNetworkTxBytes = totalTxBytes;
        *rxBytesPerSecOut = 0.0;
        *txBytesPerSecOut = 0.0;
        return true;
    }

    const qint64 elapsedMs = currentSampleMs - m_lastNetworkSampleMs;
    if (elapsedMs <= 0)
    {
        return false;
    }

    const std::uint64_t deltaRxBytes = totalRxBytes >= m_lastNetworkRxBytes
        ? (totalRxBytes - m_lastNetworkRxBytes)
        : 0;
    const std::uint64_t deltaTxBytes = totalTxBytes >= m_lastNetworkTxBytes
        ? (totalTxBytes - m_lastNetworkTxBytes)
        : 0;

    m_lastNetworkSampleMs = currentSampleMs;
    m_lastNetworkRxBytes = totalRxBytes;
    m_lastNetworkTxBytes = totalTxBytes;

    *rxBytesPerSecOut = static_cast<double>(deltaRxBytes) * 1000.0 / static_cast<double>(elapsedMs);
    *txBytesPerSecOut = static_cast<double>(deltaTxBytes) * 1000.0 / static_cast<double>(elapsedMs);
    return true;
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
    binding->append({ static_cast<std::uint64_t>(m_sampleCounter), m_metricSampleTimeMs, value, valid });
    const auto range = binding->range({ 0.0, 1.0, 1.2, {} });
    axisX->setRange(range.minimumX, range.maximumX);
    axisY->setRange(range.minimumY, range.maximumY);
}

void MonitorPanelWidget::applyChartTextTheme()
{
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
    // 低高度保护：
    // - 极小高度下标题、plotArea、图例和坐标轴没有足够的可绘制空间；
    // - 直接隐藏所有 chart view，仅保留一行摘要，避免布局震荡或崩溃。
    const bool compactTextOnly = height() > 0 && height() < 200;
    if (m_compactSummaryLabel != nullptr)
    {
        m_compactSummaryLabel->setVisible(compactTextOnly);
        if (!m_lastCompactSummaryText.isEmpty())
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
            chartView->setVisible(!compactTextOnly);
        }
    }
}

void MonitorPanelWidget::adjustChartCellHeights()
{
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
