#pragma once

// ============================================================
// HardwareDock.h
// 作用：
// 1) 提供“性能监控/硬件概览/处理器/显卡/内存/磁盘活动/设备检查”等顶部 Tab，并让性能监控拥有最高优先级；
// 2) 利用率页按任务管理器风格实现“左侧缩略卡片 + 右侧详情页”；
// 3) 新增的设备审计页默认只读，面向 DevNode、USB、HID、PCI、ACPI 与显示链路 cross-view。
// ============================================================

#include "../Framework.h"
#include "../UI/ThemeColorRemap.h"
#include "../UI/StructuredFieldView.h"

#include <QStringList>
#include <QPointer>
#include <QPoint>
#include <QPalette>
#include <QFont>
#include <QLayout>
#include <QRect>
#include <QVector>
#include <QWidget>

#include <atomic>   // std::atomic_bool：异步探测任务互斥。
#include <cstdint>  // std::uint64_t：保存采样累计值与时间戳。
#include <utility>
#include <vector>   // std::vector：保存每核图表与采样数据。

class DiskMonitorPage;
class MemoryCompositionHistoryWidget;
class HardwarePowerPage;
class HardwareR0EvidencePage;
class HardwareDeviceManagerPage;
class HardwareOtherDevicesPage;
class HardwareHwidDispatchPage;
class HardwareI8042AuditPage;
class PerformanceNavCard;
class QChartView;
class QDialog;
class QAreaSeries;
class QEvent;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineSeries;
class QListWidget;
class QResizeEvent;
class QScrollArea;
class QSplitter;
class QShowEvent;
class QStackedWidget;
class QTabWidget;
class QTableWidget;
class QTimer;
class QValueAxis;
class QVBoxLayout;
class QWidget;

class HardwareDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - parent：Qt 父控件；
    // - 作用：初始化全部硬件页签并启动周期采样。
    explicit HardwareDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止采样定时器并释放 PDH 查询句柄。
    ~HardwareDock() override;

    enum class SamplingScope
    {
        WelcomeOverview, // 首页概览：利用率与静态摘要，不探测 GPU 时钟或 CPU 传感器。
        HardwareDetails  // 用户打开硬件页后：允许兼容性检查通过的遥测与 R0 健康查询。
    };

    // 同一个采样器只升级范围；欢迎页重新绑定不会撤销已打开的硬件详情采样。
    void startPerformanceSampling(SamplingScope scope = SamplingScope::HardwareDetails);

signals:
    // performanceSnapshotChanged 作用：发布与性能监控页相同的聚合采样结果。
    // 磁盘、网络和 GPU 参数由调用方按设备综合值展示；不会复制另一套采样器。
    void performanceSnapshotChanged(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);

    // staticOverviewFieldsChanged：发布硬件 Dock 已异步采集的唯一结构模型。
    void staticOverviewFieldsChanged(const ks::ui::FieldDocument& overviewFields);

protected:
    // eventFilter 作用：仅在性能页分割线释放后同步卡片宽度，拖动过程不重排内容。
    bool eventFilter(QObject* watchedObject, QEvent* eventObject) override;

    // resizeEvent 作用：
    // - 窗口尺寸变化时动态重排“利用率”页图表高度；
    // - 保证任务管理器风格页面尽量不出现滚动条。
    void resizeEvent(QResizeEvent* resizeEventPointer) override;

    // showEvent 作用：
    // - Dock 首次显示后再次触发布局重排；
    // - 修复“利用率->CPU 首次进入高度尚未就绪”导致核心图挤压的问题。
    void showEvent(QShowEvent* showEventPointer) override;

private:
    // CoreChartEntry：
    // - 作用：保存单个逻辑处理器迷你图表所需控件；
    // - 后续刷新时按索引快速更新对应曲线。
    struct CoreChartEntry
    {
        QWidget* containerWidget = nullptr; // containerWidget：单核图容器。
        QLabel* titleLabel = nullptr;       // titleLabel：显示“CPU n”标题。
        QChartView* chartView = nullptr;    // chartView：折线图视图。
        QLineSeries* lineSeries = nullptr;  // lineSeries：该核心利用率曲线。
        QLineSeries* baselineSeries = nullptr; // baselineSeries：沿 X 轴的 0% 基准线，用于填充曲线下方面积。
        QAreaSeries* areaSeries = nullptr;   // areaSeries：折线与 X 轴围成的填充区域。
        QValueAxis* axisX = nullptr;        // axisX：时间轴（隐藏标签）。
        QValueAxis* axisY = nullptr;        // axisY：百分比轴（隐藏标签）。
    };

    // GpuEngineChartEntry：
    // - 作用：保存 GPU 引擎小图所需控件和引擎键名；
    // - 用于在刷新阶段按“3D/Copy/Video Encode/Video Decode”更新。
    struct GpuEngineChartEntry
    {
        QString engineKeyText;          // engineKeyText：引擎内部键名（小写匹配用）。
        QString displayNameText;        // displayNameText：界面标题文本。
        QLabel* titleLabel = nullptr;   // titleLabel：每个引擎小图标题标签。
        QChartView* chartView = nullptr; // chartView：每个引擎小图视图。
        QLineSeries* lineSeries = nullptr; // lineSeries：引擎利用率曲线。
        QLineSeries* baselineSeries = nullptr; // baselineSeries：引擎图 X 轴基准线，用于面积填充闭合。
        QAreaSeries* areaSeries = nullptr; // areaSeries：引擎利用率折线下方填充区域。
        QValueAxis* axisX = nullptr;    // axisX：引擎图 X 轴。
        QValueAxis* axisY = nullptr;    // axisY：引擎图 Y 轴。
    };

    // CpuPowerSnapshot：
    // - 作用：保存 CallNtPowerInformation 返回的每核频率信息；
    // - 字段用于 CPU 详情表逐列展示。
    struct CpuPowerSnapshot
    {
        std::uint32_t coreIndex = 0;  // coreIndex：逻辑处理器编号。
        std::uint32_t currentMhz = 0; // currentMhz：当前频率（MHz）。
        std::uint32_t maxMhz = 0;     // maxMhz：最大频率（MHz）。
        std::uint32_t limitMhz = 0;   // limitMhz：当前限频上限（MHz）。
    };

    // SystemPerformanceSnapshot：
    // - 作用：收敛系统全局性能统计，避免重复调用 Win32 API；
    // - 字段用于 CPU/内存详情页下方参数展示。
    struct SystemPerformanceSnapshot
    {
        std::uint32_t processCount = 0;        // processCount：系统进程总数。
        std::uint32_t threadCount = 0;         // threadCount：系统线程总数。
        std::uint32_t handleCount = 0;         // handleCount：系统句柄总数。
        std::uint64_t commitTotalBytes = 0;    // commitTotalBytes：已提交内存字节。
        std::uint64_t commitLimitBytes = 0;    // commitLimitBytes：可提交上限字节。
        std::uint64_t cachedBytes = 0;         // cachedBytes：系统缓存字节。
        std::uint64_t pagedPoolBytes = 0;      // pagedPoolBytes：分页池字节。
        std::uint64_t nonPagedPoolBytes = 0;   // nonPagedPoolBytes：非分页池字节。
    };

    // UtilizationStatisticSnapshot：
    // - 作用：保存一个历史窗口的统计结果；
    // - 处理：由当前值、均值、峰值、最小值和趋势差组成；
    // - 返回行为：仅承载统计数据，不执行任何采样。
    struct UtilizationStatisticSnapshot
    {
        double currentValue = 0.0;   // currentValue：最近一次采样值。
        double averageValue = 0.0;   // averageValue：窗口均值。
        double peakValue = 0.0;      // peakValue：窗口峰值。
        double minValue = 0.0;       // minValue：窗口最小值。
        double trendDelta = 0.0;    // trendDelta：当前值与窗口起点值的差值。
        int sampleCount = 0;         // sampleCount：参与统计的样本数。
    };

    // DeviceAuditViewSnapshot：
    // - 作用：同时保存硬件设备审计页的文本摘要和完整结构化行；
    // - 处理逻辑：后台线程查询一次 ArkDriverClient wrapper 后生成两种 UI 模型；
    // - 返回行为：结构体本身无函数返回值，字段由 refreshStaticHardwareTexts 消费。
    struct DeviceAuditViewSnapshot
    {
        ks::ui::FieldDocument summaryFields; // 设备审计字段模型，与完整 R0 行快照一起提交。
        QVector<QStringList> rows;    // rows：QTableWidget 展示的全部 R0 设备审计行。
    };

    // UtilizationDeviceKind：
    // - 作用：标识“利用率”左侧卡片对应的详情页类型；
    // - 处理逻辑：CPU/内存固定存在，磁盘/网卡/GPU按设备动态扩展；
    // - 返回行为：枚举本身无返回值，仅用于导航状态同步。
    enum class UtilizationDeviceKind
    {
        Cpu,     // Cpu：CPU固定详情页。
        Memory,  // Memory：内存固定详情页。
        Disk,    // Disk：单个物理磁盘详情页。
        Network, // Network：单个网络接口详情页。
        VirtualNetwork, // VirtualNetwork：虚拟网络汇总详情页。
        Gpu      // Gpu：单个DXGI显卡适配器详情页。
    };

    // UtilizationNavEntry：
    // - 作用：绑定左侧 PerformanceNavCard 与右侧 QStackedWidget 页面；
    // - 输入来源：initializeUtilizationSidebarCards 和动态设备发现逻辑；
    // - 返回行为：结构体仅保存指针和索引，不负责释放 Qt 对象。
    struct UtilizationNavEntry
    {
        PerformanceNavCard* navCard = nullptr;       // navCard：左侧导航卡片控件。
        QWidget* detailPage = nullptr;               // detailPage：右侧详情页控件。
        UtilizationDeviceKind kind = UtilizationDeviceKind::Cpu; // kind：设备类型。
        int deviceIndex = -1;                        // deviceIndex：同类设备数组索引。
    };

    // DiskRateSample：
    // - 作用：保存一次单磁盘 PDH 读写速率采样；
    // - 调用方式：sampleDiskRates 填充列表，刷新阶段按 instanceNameText 匹配页面；
    // - 返回行为：结构体无方法，字段均为输出数据。
    struct DiskRateSample
    {
        QString instanceNameText;       // instanceNameText：PDH PhysicalDisk 实例名。
        QString displayNameText;        // displayNameText：界面展示名，例如“磁盘 0 (C:)”。
        double readBytesPerSec = 0.0;   // readBytesPerSec：读取字节每秒。
        double writeBytesPerSec = 0.0;  // writeBytesPerSec：写入字节每秒。
    };

    // NetworkRateSample：
    // - 作用：保存一次单网卡收发速率采样；
    // - 调用方式：sampleNetworkRates 用 IP 接口 LUID 筛选 GetIfTable2 行并计算增量；
    // - 返回行为：字段直接供 UI 卡片和详情页刷新。
    struct NetworkRateSample
    {
        std::uint64_t interfaceKey = 0;             // interfaceKey：网络接口 LUID 打包键。
        QString displayNameText;                   // displayNameText：网卡别名或描述。
        std::uint64_t linkBitsPerSecond = 0;        // linkBitsPerSecond：链路速率 bit/s。
        bool physical = false;                     // physical：Windows 标记的实体硬件接口。
        bool operational = false;                  // operational：接口当前是否处于连接状态。
        double rxBytesPerSec = 0.0;                 // rxBytesPerSec：接收字节每秒。
        double txBytesPerSec = 0.0;                 // txBytesPerSec：发送字节每秒。
        std::uint64_t totalRxBytes = 0;             // totalRxBytes：系统累计接收字节。
        std::uint64_t totalTxBytes = 0;             // totalTxBytes：系统累计发送字节。
    };

    // GpuUsageSample：
    // - 作用：保存一次单 GPU 的引擎利用率和显存采样；
    // - 调用方式：sampleGpuUsages 先枚举 DXGI 适配器，再合并 PDH GPU Engine 数据；
    // - 返回行为：刷新阶段按 adapterKey 更新对应 GPU 页面。
    struct GpuUsageSample
    {
        std::uint64_t adapterKey = 0;              // adapterKey：DXGI LUID 打包键。
        int adapterIndex = 0;                      // adapterIndex：DXGI 枚举序号。
        QString displayNameText;                  // displayNameText：显卡名称。
        double overallUsagePercent = 0.0;         // overallUsagePercent：总体近似利用率。
        double usage3DPercent = 0.0;              // usage3DPercent：3D 引擎利用率。
        double usageCopyPercent = 0.0;            // usageCopyPercent：Copy 引擎利用率。
        double usageVideoEncodePercent = 0.0;     // usageVideoEncodePercent：视频编码利用率。
        double usageVideoDecodePercent = 0.0;     // usageVideoDecodePercent：视频解码利用率。
        double currentCoreClockMhz = 0.0;         // currentCoreClockMhz：当前 3D 核心频率 MHz。
        double maxCoreClockMhz = 0.0;             // maxCoreClockMhz：驱动报告的最大 3D 核心频率 MHz。
        double currentMemoryClockMhz = 0.0;       // currentMemoryClockMhz：当前显存频率 MHz。
        double maxMemoryClockMhz = 0.0;           // maxMemoryClockMhz：驱动报告的最大显存频率 MHz。
        double dedicatedMemoryGiB = 0.0;          // dedicatedMemoryGiB：专用显存总量 GiB。
        double sharedMemoryGiB = 0.0;             // sharedMemoryGiB：共享系统显存总量 GiB。
        double dedicatedUsedGiB = 0.0;            // dedicatedUsedGiB：专用显存已用 GiB。
        bool dedicatedUsageAvailable = false;     // dedicatedUsageAvailable：系统级专用显存计数器是否有效。
        double dedicatedBudgetGiB = 0.0;          // dedicatedBudgetGiB：专用显存预算 GiB。
        double sharedUsedGiB = 0.0;               // sharedUsedGiB：共享显存已用 GiB。
        bool sharedUsageAvailable = false;        // sharedUsageAvailable：系统级共享显存计数器是否有效。
        double sharedBudgetGiB = 0.0;             // sharedBudgetGiB：共享显存预算 GiB。
    };

    // DiskUtilizationDevice：
    // - 作用：保存一个磁盘卡片、详情页和历史缩略图状态；
    // - 调用方式：ensureDiskUtilizationDevice 在发现新 PDH 实例时创建；
    // - 返回行为：结构体由 HardwareDock 持有，Qt 对象仍走父子树释放。
    struct DiskUtilizationDevice
    {
        QString instanceNameText;                 // instanceNameText：PDH PhysicalDisk 实例名。
        QString displayNameText;                  // displayNameText：左侧卡片标题。
        QWidget* pageWidget = nullptr;            // pageWidget：右侧详情页。
        QLabel* summaryLabel = nullptr;           // summaryLabel：读写摘要。
        QChartView* chartView = nullptr;          // chartView：读写趋势图。
        QLineSeries* readLineSeries = nullptr;    // readLineSeries：读取速率折线。
        QLineSeries* readBaselineSeries = nullptr; // readBaselineSeries：读取折线的 0 轴基准线。
        QAreaSeries* readAreaSeries = nullptr;    // readAreaSeries：读取折线下方填充区域。
        QLineSeries* writeLineSeries = nullptr;   // writeLineSeries：写入速率折线。
        QLineSeries* writeBaselineSeries = nullptr; // writeBaselineSeries：写入折线的 0 轴基准线。
        QAreaSeries* writeAreaSeries = nullptr;   // writeAreaSeries：写入折线下方填充区域。
        QValueAxis* axisX = nullptr;              // axisX：趋势图 X 轴。
        QValueAxis* axisY = nullptr;              // axisY：趋势图 Y 轴。
        QLabel* detailLabel = nullptr;            // detailLabel：参数详情。
        PerformanceNavCard* navCard = nullptr;    // navCard：左侧导航卡片。
        double navAutoScaleBytesPerSec = 1024.0 * 1024.0; // navAutoScaleBytesPerSec：缩略图动态上限。
        std::vector<double> readHistoryBytesPerSec;  // readHistoryBytesPerSec：缩略图读取历史。
        std::vector<double> writeHistoryBytesPerSec; // writeHistoryBytesPerSec：缩略图写入历史。
    };

    // NetworkUtilizationDevice：
    // - 作用：保存一个网卡页面、速率历史和上次累计计数；
    // - 调用方式：sampleNetworkRates 会在 UI 线程内按 LUID 找到或创建；
    // - 返回行为：结构体不返回数据，刷新函数读取字段更新 UI。
    struct NetworkUtilizationDevice
    {
        std::uint64_t interfaceKey = 0;           // interfaceKey：网络接口 LUID 打包键。
        QString displayNameText;                 // displayNameText：网卡展示名。
        std::uint64_t linkBitsPerSecond = 0;      // linkBitsPerSecond：链路速率 bit/s。
        bool physical = false;                    // physical：实体接口独立展示，虚拟接口进入汇总页。
        bool lastOperational = false;             // lastOperational：连接状态变化时重置速率基线。
        std::uint64_t lastRxBytes = 0;            // lastRxBytes：上次累计接收字节。
        std::uint64_t lastTxBytes = 0;            // lastTxBytes：上次累计发送字节。
        qint64 lastSampleMs = 0;                  // lastSampleMs：上次采样时间戳。
        bool hasPreviousSample = false;           // hasPreviousSample：是否已有增量基线。
        QWidget* pageWidget = nullptr;            // pageWidget：右侧详情页。
        QLabel* summaryLabel = nullptr;           // summaryLabel：收发摘要。
        QChartView* chartView = nullptr;          // chartView：收发趋势图。
        QLineSeries* rxLineSeries = nullptr;      // rxLineSeries：接收速率折线。
        QLineSeries* rxBaselineSeries = nullptr;  // rxBaselineSeries：接收折线的 0 轴基准线。
        QAreaSeries* rxAreaSeries = nullptr;      // rxAreaSeries：接收折线下方填充区域。
        QLineSeries* txLineSeries = nullptr;      // txLineSeries：发送速率折线。
        QLineSeries* txBaselineSeries = nullptr;  // txBaselineSeries：发送折线的 0 轴基准线。
        QAreaSeries* txAreaSeries = nullptr;      // txAreaSeries：发送折线下方填充区域。
        QValueAxis* axisX = nullptr;              // axisX：趋势图 X 轴。
        QValueAxis* axisY = nullptr;              // axisY：趋势图 Y 轴。
        QLabel* detailLabel = nullptr;            // detailLabel：参数详情。
        PerformanceNavCard* navCard = nullptr;    // navCard：左侧导航卡片。
        double navAutoScaleBytesPerSec = 1024.0 * 1024.0; // navAutoScaleBytesPerSec：缩略图动态上限。
        std::vector<double> rxHistoryBytesPerSec; // rxHistoryBytesPerSec：缩略图接收历史。
        std::vector<double> txHistoryBytesPerSec; // txHistoryBytesPerSec：缩略图发送历史。
    };

    // GpuUtilizationDevice：
    // - 作用：保存一个 GPU 适配器的详情页、引擎图和显存图控件；
    // - 调用方式：ensureGpuUtilizationDevice 在 DXGI 发现新适配器时创建；
    // - 返回行为：字段由 updateGpuUtilizationDevice 读取并刷新。
    struct GpuUtilizationDevice
    {
        std::uint64_t adapterKey = 0;             // adapterKey：DXGI LUID 打包键。
        bool adapterKeyAssigned = false;          // adapterKeyAssigned：adapterKey 是否已经绑定真实设备。
        int adapterIndex = 0;                     // adapterIndex：DXGI 枚举序号。
        QString displayNameText;                 // displayNameText：显卡名称。
        QWidget* pageWidget = nullptr;            // pageWidget：右侧详情页。
        QLabel* adapterTitleLabel = nullptr;      // adapterTitleLabel：标题区适配器名。
        QLabel* summaryLabel = nullptr;           // summaryLabel：利用率摘要。
        QWidget* engineHostWidget = nullptr;      // engineHostWidget：引擎小图宿主。
        QGridLayout* engineGridLayout = nullptr;  // engineGridLayout：引擎小图网格。
        std::vector<GpuEngineChartEntry> engineCharts; // engineCharts：四类引擎图。
        QChartView* dedicatedMemoryChartView = nullptr; // dedicatedMemoryChartView：专用显存图。
        QLineSeries* dedicatedMemoryLineSeries = nullptr; // dedicatedMemoryLineSeries：专用显存折线。
        QLineSeries* dedicatedMemoryBaselineSeries = nullptr; // dedicatedMemoryBaselineSeries：专用显存 0 轴基准线。
        QAreaSeries* dedicatedMemoryAreaSeries = nullptr; // dedicatedMemoryAreaSeries：专用显存折线填充区域。
        QValueAxis* dedicatedMemoryAxisX = nullptr; // dedicatedMemoryAxisX：专用显存 X 轴。
        QValueAxis* dedicatedMemoryAxisY = nullptr; // dedicatedMemoryAxisY：专用显存 Y 轴。
        QChartView* sharedMemoryChartView = nullptr; // sharedMemoryChartView：共享显存图。
        QLineSeries* sharedMemoryLineSeries = nullptr; // sharedMemoryLineSeries：共享显存折线。
        QLineSeries* sharedMemoryBaselineSeries = nullptr; // sharedMemoryBaselineSeries：共享显存 0 轴基准线。
        QAreaSeries* sharedMemoryAreaSeries = nullptr; // sharedMemoryAreaSeries：共享显存折线填充区域。
        QValueAxis* sharedMemoryAxisX = nullptr;  // sharedMemoryAxisX：共享显存 X 轴。
        QValueAxis* sharedMemoryAxisY = nullptr;  // sharedMemoryAxisY：共享显存 Y 轴。
        QLabel* detailLabel = nullptr;            // detailLabel：参数详情。
        PerformanceNavCard* navCard = nullptr;    // navCard：左侧导航卡片。
    };

private:
    // ===================== UI 初始化 =====================
    void initializeUi();
    void initializeOverviewTab();
    void initializeUtilizationTab();
    void initializeUtilizationSidebarCards();
    void initializeUtilizationCpuSubTab();
    void initializeUtilizationMemorySubTab();
    void initializeUtilizationDiskSubTab();
    void initializeUtilizationNetworkSubTab();
    void initializeUtilizationGpuSubTab();
    void initializeCpuTab();
    void initializePowerTab();
    void initializeR0EvidenceTab();
    void initializeGpuTab();
    void initializeMemoryTab();
    void initializeDiskMonitorTab();
    void initializeDeviceManagerTab();
    void initializeHwidDispatchTab();
    void initializeOtherDevicesTab();
    void initializeDeviceStackTab();
    void initializeKeyboardMouseHidTab();
    void initializeI8042AuditTab();
    void initializeUsbTopologyTab();
    void initializePnpAcpiPciTab();

    // ensureDiskMonitorTabInitialized 作用：
    // - 输入：无，读取 m_diskMonitorHostPage 和 m_diskMonitorPage；
    // - 处理：首次进入“硬盘监控”子 Tab 时创建 DiskMonitorPage，并替换占位内容；
    // - 返回：无返回值，真实页面挂入 Qt 父子树自动释放。
    void ensureDiskMonitorTabInitialized();

    // ensureOtherDevicesTabInitialized 作用：
    // - 输入：无，读取 m_otherDevicesHostPage 和 m_otherDevicesPage；
    // - 处理：首次进入“其他设备”子 Tab 时创建 HardwareOtherDevicesPage；
    // - 返回：无返回值，页面内容直接显示在宿主布局中。
    void ensureOtherDevicesTabInitialized();

    // startInitialSamplingAfterFirstPaint 作用：
    // - 输入：无，依赖 showEvent 首次显示后调用；
    // - 处理：把 PDH/设备采样推迟到首帧绘制后，避免点击硬件 Dock 时阻塞 UI；
    // - 返回：无返回值，完成后启动周期刷新定时器。
    void startInitialSamplingAfterFirstPaint();
    void initializeCoreCharts();
    void initializeConnections();
    void scheduleUtilizationLayoutRefresh();
    // 主题更新只排队一次；按明确设备/引擎角色重算业务颜色，不从旧色猜角色。
    void scheduleUtilizationThemeRefresh();
    void refreshUtilizationThemeColors();
    void refreshUtilizationChartThemeColors(const QPalette* floatingPalette = nullptr);
    void applyInitialUtilizationSplitterSize();
    void syncUtilizationSidebarCardWidths();
    void syncUtilizationSidebarSelection(int selectedRowIndex);
    void adjustUtilizationChartHeights();
    void openUtilizationFloatingWindow(bool sidebarMode);
    void restoreUtilizationFloatingWindow();
    void resizeUtilizationFloatingWindow();
    void captureUtilizationFloatingScale();
    void applyUtilizationFloatingContentScale(bool forceRestyle = false);
    void restoreUtilizationFloatingContentScale();
    void applyUtilizationFloatingTheme();
    void saveUtilizationFloatingPreferences();
    void beginUtilizationWindowPick();
    void finishUtilizationWindowPick(void* pickedWindow);
    void attachUtilizationWindow(void* targetWindow, bool restoreSavedOffset);
    void synchronizeUtilizationFollow();
    void captureUtilizationFollowOffset();
    void stopUtilizationFollow(bool showNormalCard, bool clearSavedTarget);
    void setUtilizationFollowClickThrough(bool enabled);
    void clearUtilizationFollowHooks();
    QWidget* utilizationChartBottomWidget(const UtilizationNavEntry& entry) const;
    std::vector<QWidget*> utilizationDetailWidgets(const UtilizationNavEntry& entry) const;
    PerformanceNavCard* addUtilizationSidebarCard(
        QWidget* detailPage,
        const QString& titleText,
        const QColor& accentColor,
        UtilizationDeviceKind kind,
        int deviceIndex);
    int findDiskUtilizationDeviceIndexByInstance(const QString& instanceNameText) const;
    int ensureDiskUtilizationDevice(const DiskRateSample& sample, int ordinalIndex);
    int findNetworkUtilizationDeviceIndexByKey(std::uint64_t interfaceKey) const;
    int ensureNetworkUtilizationDevice(const NetworkRateSample& sample, int ordinalIndex);
    void ensureVirtualNetworkPage();
    void relayoutVirtualNetworkTiles();
    int findGpuUtilizationDeviceIndexByKey(std::uint64_t adapterKey) const;
    int ensureGpuUtilizationDevice(const GpuUsageSample& sample, int ordinalIndex);
    void createDiskUtilizationDevicePage(DiskUtilizationDevice* devicePointer);
    void createNetworkUtilizationDevicePage(NetworkUtilizationDevice* devicePointer);
    void createGpuUtilizationDevicePage(GpuUtilizationDevice* devicePointer);

    // ===================== 采样与刷新 =====================
    void initializePerformanceCounters();
    void refreshAllViews();
    bool samplePerCoreUsage(
        std::vector<double>* coreUsageOut,
        double* totalUsageOut);
    bool sampleCpuEffectiveSpeed(double* speedGhzOut) const;
    bool sampleCpuPowerInfo(std::vector<CpuPowerSnapshot>* powerInfoOut);
    bool sampleMemoryUsage(double* memoryUsagePercentOut);
    bool sampleDiskRates(std::vector<DiskRateSample>* sampleListOut);
    bool sampleDiskRate(double* readBytesPerSecOut, double* writeBytesPerSecOut);
    bool sampleNetworkRates(std::vector<NetworkRateSample>* sampleListOut);
    bool sampleNetworkRate(double* rxBytesPerSecOut, double* txBytesPerSecOut);
    bool sampleGpuUsages(std::vector<GpuUsageSample>* sampleListOut);
    bool sampleGpuUsage(double* gpuUsagePercentOut);
    bool sampleGpuMemoryInfoByDxgi();
    bool sampleSystemPerformanceSnapshot(SystemPerformanceSnapshot* snapshotOut) const;
    void updateOverviewText(double cpuUsagePercent, double memoryUsagePercent);
    void updateUtilizationView(
        const std::vector<double>& coreUsageList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateUtilizationSidebarCards(
        double cpuUsagePercent,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double gpuUsagePercent);
    void updateAdditionalDiskUtilizationDevices(const std::vector<DiskRateSample>& sampleList);
    void updateAdditionalNetworkUtilizationDevices(const std::vector<NetworkRateSample>& sampleList);
    void updateAdditionalGpuUtilizationDevices(const std::vector<GpuUsageSample>& sampleList);
    void updateDiskUtilizationDevice(DiskUtilizationDevice& device, const DiskRateSample& sample);
    void updateNetworkUtilizationDevice(NetworkUtilizationDevice& device, const NetworkRateSample& sample);
    void updateGpuUtilizationDevice(GpuUtilizationDevice& device, const GpuUsageSample& sample);
    void updateTaskManagerDetailLabels(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList,
        double memoryUsagePercent,
        double diskReadBytesPerSec,
        double diskWriteBytesPerSec,
        double networkRxBytesPerSec,
        double networkTxBytesPerSec,
        double gpuUsagePercent);
    void updateCpuDetailTable(
        const std::vector<double>& coreUsageList,
        const std::vector<CpuPowerSnapshot>& powerInfoList);
    void appendCoreSeriesPoint(
        CoreChartEntry& chartEntry,
        double usagePercent,
        bool sampleValid); // 逐核查询失败与真实0%分别进入历史模型。
    void appendGeneralSeriesPoint(
        QLineSeries* lineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0);
    // appendFilledSeriesPoint 作用：
    // - 同步追加折线采样和 0 轴基准线采样；
    // - 保证 QAreaSeries 的填充区域能随历史窗口一起平移。
    void appendFilledSeriesPoint(
        QLineSeries* lineSeries,
        QLineSeries* baselineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double sampleValue,
        double minAxisYValue = 0.0,
        bool sampleValid = true); // 专用设备查询也可明确记录缺失帧。
    // updateSharedSeriesAxisRange 作用：
    // - 给共用同一坐标轴的两条折线统一计算 X/Y 可见范围；
    // - 用两条曲线的可见历史峰值同步刷新纵向比例。
    void updateSharedSeriesAxisRange(
        QLineSeries* primaryLineSeries,
        QLineSeries* secondaryLineSeries,
        QValueAxis* axisX,
        QValueAxis* axisY,
        double minAxisYValue = 0.0);
    // rebuildDualRateNavCard 作用：
    // - 记录磁盘/网络双速率原始历史；
    // - 按当前可见历史峰值整体重算缩略图比例并整段重绘。
    void rebuildDualRateNavCard(
        PerformanceNavCard* navCard,
        std::vector<double>* primaryHistoryOut,
        std::vector<double>* secondaryHistoryOut,
        double primaryBytesPerSecond,
        double secondaryBytesPerSecond,
        double* upperBoundBytesPerSecondOut,
        const QString& subtitleText);
    QString formatRateText(double bytesPerSecondValue) const;
    void pushBoundedHistorySample(std::vector<double>* historyList, double sampleValue) const;
    UtilizationStatisticSnapshot buildStatisticSnapshot(const std::vector<double>& historyList) const;
    QString buildPercentStatisticLine(const QString& labelText, const UtilizationStatisticSnapshot& snapshot) const;
    QString buildRateStatisticLine(const QString& labelText, const UtilizationStatisticSnapshot& snapshot) const;
    QString buildTrendText(const UtilizationStatisticSnapshot& snapshot, bool percentUnit) const;
    QString buildPressureLevelText(double percentValue) const;
    QString buildR0CpuFeatureBadgeText(std::uint64_t featureMask) const;
    void refreshStaticHardwareTexts(bool forceRefresh);
    void requestAsyncStaticInfoRefresh();
    // requestAsyncDeviceAuditRefresh 作用：
    // - 按位请求当前可见的设备栈/输入栈/USB/PnP 页面，避免周期刷新全量查询；
    // - 重入请求会合并到 pending mask，始终只有一个设备审计工作线程。
    void requestAsyncDeviceAuditRefresh(std::uint32_t refreshMask);
    // applyDeviceAuditRefreshResult 作用：
    // - 在 GUI 线程原子替换三组设备审计缓存并刷新关联表；
    // - 任一关联表菜单打开时延迟完整结果，避免缓存与表行代次错位。
    void applyDeviceAuditRefreshResult(
        std::uint32_t requestedMask,
        DeviceAuditViewSnapshot deviceStackSnapshot,
        DeviceAuditViewSnapshot inputStackSnapshot,
        DeviceAuditViewSnapshot usbTopologySnapshot,
        ks::ui::FieldDocument pnpAcpiPciFields);
    void requestAsyncSensorRefresh();
    void requestAsyncR0HardwareHealthRefresh();
    void refreshCpuTopologyStaticInfo();
    void refreshSystemVolumeInfo();

    // ===================== 文本采集 =====================
    ks::ui::FieldDocument buildOverviewFields() const;
    ks::ui::FieldDocument buildGpuFields() const;
    ks::ui::FieldDocument buildMemoryFields() const;
    QString buildCpuSensorText(bool forceRefresh);
    ks::ui::FieldDocument buildDeviceStackFields() const;
    ks::ui::FieldDocument buildKeyboardMouseHidFields() const;
    ks::ui::FieldDocument buildUsbTopologyFields() const;
    static DeviceAuditViewSnapshot buildDeviceStackAuditViewSnapshot();
    static DeviceAuditViewSnapshot buildKeyboardMouseHidAuditViewSnapshot();
    static DeviceAuditViewSnapshot buildUsbTopologyAuditViewSnapshot();
    static ks::ui::FieldDocument buildPnpAcpiPciFields();

private:
    // DeviceAuditRefreshFlag：静态诊断页按需刷新位，供快速切页时合并请求。
    enum DeviceAuditRefreshFlag : std::uint32_t
    {
        DeviceStackAuditRefresh = 0x00000001U, // DeviceStackAuditRefresh：设备栈页。
        InputStackAuditRefresh = 0x00000002U,  // InputStackAuditRefresh：键鼠/HID 输入栈页。
        UsbTopologyAuditRefresh = 0x00000004U, // UsbTopologyAuditRefresh：USB 拓扑页。
        PnpAcpiPciRefresh = 0x00000008U,       // PnpAcpiPciRefresh：PnP/ACPI/PCI 文本页。
        AllDeviceAuditRefresh = DeviceStackAuditRefresh |
            InputStackAuditRefresh |
            UsbTopologyAuditRefresh |
            PnpAcpiPciRefresh
    };

    // 顶层结构。
    QVBoxLayout* m_rootLayout = nullptr;    // m_rootLayout：根布局。
    QTabWidget* m_sideTabWidget = nullptr;  // m_sideTabWidget：顶部横向硬件页签容器（保留旧成员名避免无关重构）。
    QTimer* m_refreshTimer = nullptr;       // m_refreshTimer：1 秒采样定时器。

    // 概览页。
    QWidget* m_overviewPage = nullptr;           // m_overviewPage：概览 Tab。
    QVBoxLayout* m_overviewLayout = nullptr;     // m_overviewLayout：概览布局。
    QLabel* m_overviewSummaryLabel = nullptr;    // m_overviewSummaryLabel：实时摘要标签。
    ks::ui::StructuredFieldView* m_overviewEditor = nullptr; // m_overviewEditor：静态硬件清单文本。

    // 利用率页（任务管理器风格）。
    QWidget* m_utilizationPage = nullptr;          // m_utilizationPage：利用率 Tab。
    QVBoxLayout* m_utilizationLayout = nullptr;    // m_utilizationLayout：利用率外层布局。
    QSplitter* m_utilizationBodySplitter = nullptr; // m_utilizationBodySplitter：可拖动的左右分栏。
    bool m_utilizationSplitterInitialSizeApplied = false; // m_utilizationSplitterInitialSizeApplied：是否已应用 300px 默认左栏。
    QListWidget* m_utilizationSidebarList = nullptr; // m_utilizationSidebarList：左侧性能卡片列表。
    QStackedWidget* m_utilizationDetailStack = nullptr; // m_utilizationDetailStack：右侧详情页栈。
    QWidget* m_virtualNetworkPage = nullptr; // m_virtualNetworkPage：虚拟网卡共用详情页。
    QScrollArea* m_virtualNetworkScrollArea = nullptr; // m_virtualNetworkScrollArea：虚拟网卡纵向滚动区。
    QWidget* m_virtualNetworkGridHost = nullptr; // m_virtualNetworkGridHost：一至两列网卡卡片宿主。
    QGridLayout* m_virtualNetworkGrid = nullptr; // m_virtualNetworkGrid：按宽度重排虚拟网卡。
    int m_virtualNetworkColumnCount = 0; // m_virtualNetworkColumnCount：上次使用的列数。
    int m_virtualNetworkTileCount = 0; // m_virtualNetworkTileCount：上次布局的虚拟网卡数量。
    std::vector<UtilizationNavEntry> m_utilizationNavEntries; // m_utilizationNavEntries：左侧卡片到右侧页的映射。
    enum class UtilizationFloatingMode { None, Sidebar, Detail };
    UtilizationFloatingMode m_utilizationFloatingMode = UtilizationFloatingMode::None;
    QPointer<QWidget> m_utilizationFloatingWindow;
    QPointer<QWidget> m_utilizationFloatingPage;
    QPointer<QWidget> m_utilizationOriginalMainWindow;
    std::vector<std::pair<QPointer<QWidget>, bool>> m_utilizationHiddenDetailWidgets;
    QList<int> m_utilizationSavedSplitterSizes;
    int m_utilizationSavedDetailIndex = -1;
    QPalette m_utilizationBorrowedPalette;
    ks::ui::ThemeColorSnapshot m_utilizationBorrowedThemeColors;
    bool m_utilizationBorrowedHadPalette = false;
    QFont m_utilizationBorrowedFont;
    bool m_utilizationBorrowedHadFont = false;
    struct FloatingWidgetStyleState
    {
        QPointer<QWidget> widget;
        QString styleSheet;
        QPalette palette;
        bool hadPalette = false;
        int minimumHeight = 0;
        int maximumHeight = QWIDGETSIZE_MAX;
        ks::ui::ThemeColorSnapshot themeColors; // 保存 QSS/palette 时的主主题，用于安全返还。
    };
    struct FloatingLayoutStyleState
    {
        QPointer<QLayout> layout;
        QMargins margins;
        int spacing = 0;
        int horizontalSpacing = 0;
        int verticalSpacing = 0;
    };
    std::vector<FloatingWidgetStyleState> m_utilizationFloatingWidgetStyles;
    std::vector<FloatingLayoutStyleState> m_utilizationFloatingLayoutStyles;
    double m_utilizationFloatingAppliedContentScale = 1.0;
    bool m_utilizationThemeRefreshScheduled = false; // 合并 palette 事件，禁止同步 repolish 重入。
    QSize m_utilizationFloatingBaseSize;
    int m_utilizationFloatingScalePercent = 100;
    int m_utilizationFloatingBackgroundOpacityPercent = 100;
    bool m_utilizationFloatingTopMost = true;
    QString m_utilizationFloatingThemeMode = QStringLiteral("follow_main");
    QString m_utilizationFollowTitle;
    QString m_utilizationFollowExecutable;
    QPoint m_utilizationFollowOffset;
    bool m_utilizationFollowOffsetLogical = false;
    bool m_utilizationFollowClickThrough = false;
    void* m_utilizationFollowTarget = nullptr;
    void* m_utilizationFollowEventHook = nullptr;
    void* m_utilizationFollowForegroundHook = nullptr;
    bool m_utilizationFollowSyncing = false;
    QPointer<QWidget> m_utilizationFollowMirror;
    QPointer<QDialog> m_utilizationPickDialog;
    QTimer* m_utilizationFollowTimer = nullptr;
    QTimer* m_utilizationPreferencesSaveTimer = nullptr;
    QPoint m_utilizationDragStartGlobal;
    QRect m_utilizationResizeStartGeometry;
    Qt::Edges m_utilizationResizeEdges;
    bool m_utilizationDragArmed = false;
    bool m_utilizationDragging = false;

    // 左侧性能卡片。
    PerformanceNavCard* m_cpuNavCard = nullptr;      // m_cpuNavCard：CPU 导航卡片。
    PerformanceNavCard* m_memoryNavCard = nullptr;   // m_memoryNavCard：内存导航卡片。
    PerformanceNavCard* m_diskNavCard = nullptr;     // m_diskNavCard：兼容旧聚合磁盘卡片，当前动态设备模式下为空。
    PerformanceNavCard* m_networkNavCard = nullptr;  // m_networkNavCard：虚拟网络汇总导航卡片。
    PerformanceNavCard* m_gpuNavCard = nullptr;      // m_gpuNavCard：兼容旧聚合GPU卡片，当前动态设备模式下为空。

    // 利用率详情页：CPU。
    QWidget* m_utilizationCpuSubPage = nullptr;    // m_utilizationCpuSubPage：CPU 详情页。
    QLabel* m_cpuModelLabel = nullptr;             // m_cpuModelLabel：CPU 型号标签。
    QLabel* m_utilizationSummaryLabel = nullptr;   // m_utilizationSummaryLabel：CPU 图表说明文本。
    QScrollArea* m_coreChartScrollArea = nullptr;  // m_coreChartScrollArea：CPU 核心图滚动容器。
    QWidget* m_coreChartHostWidget = nullptr;      // m_coreChartHostWidget：CPU 核心图宿主。
    QGridLayout* m_coreChartGridLayout = nullptr;  // m_coreChartGridLayout：CPU 核心图矩阵布局。
    QLabel* m_cpuUtilPrimaryDetailLabel = nullptr; // m_cpuUtilPrimaryDetailLabel：CPU 左侧大字关键指标。
    QLabel* m_cpuUtilSecondaryDetailLabel = nullptr; // m_cpuUtilSecondaryDetailLabel：CPU 右侧第一列硬件参数。
    QLabel* m_cpuUtilTertiaryDetailLabel = nullptr; // m_cpuUtilTertiaryDetailLabel：CPU 右侧第二列缓存与 R0 摘要。

    // 利用率详情页：内存。
    QWidget* m_utilizationMemorySubPage = nullptr;   // m_utilizationMemorySubPage：内存详情页。
    QLabel* m_memoryCapacityLabel = nullptr;         // m_memoryCapacityLabel：内存总量标签。
    QLabel* m_memoryUtilSummaryLabel = nullptr;      // m_memoryUtilSummaryLabel：内存摘要文本。
    MemoryCompositionHistoryWidget* m_memoryCompositionHistoryWidget = nullptr; // m_memoryCompositionHistoryWidget：内存历史与构成合并图。
    QLabel* m_memoryUtilPrimaryDetailLabel = nullptr; // m_memoryUtilPrimaryDetailLabel：内存左侧参数文本。
    QLabel* m_memoryUtilSecondaryDetailLabel = nullptr; // m_memoryUtilSecondaryDetailLabel：内存右侧参数文本。

    // 利用率详情页：磁盘。
    QWidget* m_utilizationDiskSubPage = nullptr;   // m_utilizationDiskSubPage：磁盘详情页。
    QLabel* m_diskUtilSummaryLabel = nullptr;      // m_diskUtilSummaryLabel：磁盘摘要文本。
    QChartView* m_diskUtilChartView = nullptr;     // m_diskUtilChartView：磁盘趋势图视图。
    QLineSeries* m_diskReadLineSeries = nullptr;   // m_diskReadLineSeries：磁盘读速率折线。
    QLineSeries* m_diskReadBaselineSeries = nullptr; // m_diskReadBaselineSeries：磁盘读速率 0 轴基准线。
    QAreaSeries* m_diskReadAreaSeries = nullptr;   // m_diskReadAreaSeries：磁盘读速率填充区域。
    QLineSeries* m_diskWriteLineSeries = nullptr;  // m_diskWriteLineSeries：磁盘写速率折线。
    QLineSeries* m_diskWriteBaselineSeries = nullptr; // m_diskWriteBaselineSeries：磁盘写速率 0 轴基准线。
    QAreaSeries* m_diskWriteAreaSeries = nullptr;  // m_diskWriteAreaSeries：磁盘写速率填充区域。
    QValueAxis* m_diskUtilAxisX = nullptr;         // m_diskUtilAxisX：磁盘图 X 轴。
    QValueAxis* m_diskUtilAxisY = nullptr;         // m_diskUtilAxisY：磁盘图 Y 轴。
    QLabel* m_diskUtilDetailLabel = nullptr;       // m_diskUtilDetailLabel：磁盘参数文本。

    // 利用率详情页：网络。
    QWidget* m_utilizationNetworkSubPage = nullptr; // m_utilizationNetworkSubPage：网络详情页。
    QLabel* m_networkUtilSummaryLabel = nullptr;    // m_networkUtilSummaryLabel：网络摘要文本。
    QChartView* m_networkUtilChartView = nullptr;   // m_networkUtilChartView：网络趋势图视图。
    QLineSeries* m_networkRxLineSeries = nullptr;   // m_networkRxLineSeries：网络下行折线。
    QLineSeries* m_networkRxBaselineSeries = nullptr; // m_networkRxBaselineSeries：网络下行 0 轴基准线。
    QAreaSeries* m_networkRxAreaSeries = nullptr;   // m_networkRxAreaSeries：网络下行填充区域。
    QLineSeries* m_networkTxLineSeries = nullptr;   // m_networkTxLineSeries：网络上行折线。
    QLineSeries* m_networkTxBaselineSeries = nullptr; // m_networkTxBaselineSeries：网络上行 0 轴基准线。
    QAreaSeries* m_networkTxAreaSeries = nullptr;   // m_networkTxAreaSeries：网络上行填充区域。
    QValueAxis* m_networkUtilAxisX = nullptr;       // m_networkUtilAxisX：网络图 X 轴。
    QValueAxis* m_networkUtilAxisY = nullptr;       // m_networkUtilAxisY：网络图 Y 轴。
    QLabel* m_networkUtilDetailLabel = nullptr;     // m_networkUtilDetailLabel：网络参数文本。

    // 利用率详情页：GPU。
    QWidget* m_utilizationGpuSubPage = nullptr;    // m_utilizationGpuSubPage：GPU 详情页。
    QLabel* m_gpuAdapterTitleLabel = nullptr;      // m_gpuAdapterTitleLabel：GPU 标题区适配器文本。
    QLabel* m_gpuUtilSummaryLabel = nullptr;       // m_gpuUtilSummaryLabel：GPU 摘要文本。
    QWidget* m_gpuEngineHostWidget = nullptr;      // m_gpuEngineHostWidget：GPU 引擎小图宿主。
    QGridLayout* m_gpuEngineGridLayout = nullptr;  // m_gpuEngineGridLayout：GPU 引擎小图网格。
    std::vector<GpuEngineChartEntry> m_gpuEngineCharts; // m_gpuEngineCharts：GPU 引擎图列表。
    QChartView* m_gpuDedicatedMemoryChartView = nullptr; // m_gpuDedicatedMemoryChartView：专用显存曲线图。
    QLineSeries* m_gpuDedicatedMemoryLineSeries = nullptr; // m_gpuDedicatedMemoryLineSeries：专用显存使用曲线。
    QLineSeries* m_gpuDedicatedMemoryBaselineSeries = nullptr; // m_gpuDedicatedMemoryBaselineSeries：专用显存 0 轴基准线。
    QAreaSeries* m_gpuDedicatedMemoryAreaSeries = nullptr; // m_gpuDedicatedMemoryAreaSeries：专用显存填充区域。
    QValueAxis* m_gpuDedicatedMemoryAxisX = nullptr; // m_gpuDedicatedMemoryAxisX：专用显存图 X 轴。
    QValueAxis* m_gpuDedicatedMemoryAxisY = nullptr; // m_gpuDedicatedMemoryAxisY：专用显存图 Y 轴。
    QChartView* m_gpuSharedMemoryChartView = nullptr; // m_gpuSharedMemoryChartView：共享显存曲线图。
    QLineSeries* m_gpuSharedMemoryLineSeries = nullptr; // m_gpuSharedMemoryLineSeries：共享显存使用曲线。
    QLineSeries* m_gpuSharedMemoryBaselineSeries = nullptr; // m_gpuSharedMemoryBaselineSeries：共享显存 0 轴基准线。
    QAreaSeries* m_gpuSharedMemoryAreaSeries = nullptr; // m_gpuSharedMemoryAreaSeries：共享显存填充区域。
    QValueAxis* m_gpuSharedMemoryAxisX = nullptr;   // m_gpuSharedMemoryAxisX：共享显存图 X 轴。
    QValueAxis* m_gpuSharedMemoryAxisY = nullptr;   // m_gpuSharedMemoryAxisY：共享显存图 Y 轴。
    QLabel* m_gpuUtilDetailLabel = nullptr;        // m_gpuUtilDetailLabel：GPU 参数文本。

    // 每核图缓存。
    std::vector<CoreChartEntry> m_coreChartEntries; // m_coreChartEntries：每核图控件缓存。
    int m_cpuCoreGridColumnCount = 1;             // m_cpuCoreGridColumnCount：CPU 小图网格列数。
    int m_cpuCoreGridRowCount = 1;                // m_cpuCoreGridRowCount：CPU 小图网格行数。

    // CPU 详情页（原有文本/表格页）。
    QWidget* m_cpuPage = nullptr;             // m_cpuPage：CPU Tab。
    QVBoxLayout* m_cpuLayout = nullptr;       // m_cpuLayout：CPU 布局。
    QLabel* m_cpuDetailLabel = nullptr;       // m_cpuDetailLabel：温度/电压等摘要标签。
    QTableWidget* m_cpuDetailTable = nullptr; // m_cpuDetailTable：每核详情表。
    HardwarePowerPage* m_powerPage = nullptr; // m_powerPage：CPU 电源与性能调节 Tab。
    HardwareR0EvidencePage* m_r0EvidencePage = nullptr; // m_r0EvidencePage：R0 硬件证据页。

    // 显卡与内存页（原有文本页）。
    QWidget* m_gpuPage = nullptr;               // m_gpuPage：显卡 Tab。
    QVBoxLayout* m_gpuLayout = nullptr;         // m_gpuLayout：显卡布局。
    ks::ui::StructuredFieldView* m_gpuEditor = nullptr;    // m_gpuEditor：显卡详情文本。
    QWidget* m_memoryPage = nullptr;            // m_memoryPage：内存 Tab。
    QVBoxLayout* m_memoryLayout = nullptr;      // m_memoryLayout：内存布局。
    ks::ui::StructuredFieldView* m_memoryEditor = nullptr; // m_memoryEditor：内存详情文本。
    QWidget* m_diskMonitorHostPage = nullptr;      // m_diskMonitorHostPage：硬盘监控延迟加载宿主页。
    HardwareDeviceManagerPage* m_deviceManagerPage = nullptr; // m_deviceManagerPage：SetupAPI/CfgMgr 设备管理页。
    HardwareHwidDispatchPage* m_hwidDispatchPage = nullptr; // m_hwidDispatchPage：HWID Dispatch 派遣函数页。
    QWidget* m_otherDevicesHostPage = nullptr;     // m_otherDevicesHostPage：其他设备延迟加载宿主页。
    DiskMonitorPage* m_diskMonitorPage = nullptr;  // m_diskMonitorPage：硬盘监控真实页面，首次进入子 Tab 后创建。
    HardwareOtherDevicesPage* m_otherDevicesPage = nullptr; // m_otherDevicesPage：其他硬件设备真实页面，首次进入子 Tab 后创建。
    QWidget* m_deviceStackPage = nullptr;          // m_deviceStackPage：DevNode/设备栈只读页。
    ks::ui::StructuredFieldView* m_deviceStackEditor = nullptr; // m_deviceStackEditor：DevNode/设备栈文本。
    QTableWidget* m_deviceStackTable = nullptr;     // m_deviceStackTable：DevNode/设备栈 R0 明细表。
    QWidget* m_keyboardMouseHidPage = nullptr;     // m_keyboardMouseHidPage：键鼠/HID 只读页。
    ks::ui::StructuredFieldView* m_keyboardMouseHidEditor = nullptr; // m_keyboardMouseHidEditor：键鼠/HID 文本。
    QTableWidget* m_keyboardMouseHidTable = nullptr; // m_keyboardMouseHidTable：输入设备 R0 明细表。
    HardwareI8042AuditPage* m_i8042AuditPage = nullptr; // m_i8042AuditPage：i8042prt/键鼠类驱动组合审计页。
    QWidget* m_usbTopologyPage = nullptr;          // m_usbTopologyPage：USB 拓扑只读页。
    ks::ui::StructuredFieldView* m_usbTopologyEditor = nullptr; // m_usbTopologyEditor：USB 拓扑文本。
    QTableWidget* m_usbTopologyTable = nullptr;     // m_usbTopologyTable：USB 拓扑 R0 明细表。
    QWidget* m_pnpAcpiPciPage = nullptr;           // m_pnpAcpiPciPage：PnP/ACPI/PCI 只读页。
    ks::ui::StructuredFieldView* m_pnpAcpiPciEditor = nullptr; // m_pnpAcpiPciEditor：PnP/ACPI/PCI 文本。

    // 运行状态缓存。
    qint64 m_metricSampleTimeMs = 0; // 本帧共同采样时间，毫秒。
    bool m_metricDiskValid = true; // 磁盘采样有效性，失败保留断点。
    bool m_metricNetworkValid = true; // 网络采样有效性，失败保留断点。
    bool m_metricCpuValid = true; // 本帧至少一个CPU核有效。
    std::vector<bool> m_metricCoreValid; // 与计数器/核心图索引一致的逐核查询有效位。
    bool m_metricGpuValid = true; // 本帧GPU采样有效位。
    int m_historyLength = 60;                 // m_historyLength：曲线保留点数。
    int m_sampleCounter = 60;                 // m_sampleCounter：采样序号（从历史长度起步避免首段无图）。
    QString m_cachedSensorText;               // m_cachedSensorText：CPU 温度/电压缓存。
    QString m_lastSensorLogSignatureText;     // m_lastSensorLogSignatureText：最近一次传感器日志去重签名。
    ks::ui::FieldDocument m_cachedOverviewFields;       // 概览字段快照。
    ks::ui::FieldDocument m_cachedGpuFields;            // 显卡字段快照。
    ks::ui::FieldDocument m_cachedMemoryFields;         // 内存字段快照。
    ks::ui::FieldDocument m_cachedDeviceStackFields;     // m_cachedDeviceStackFields：DevNode/设备栈缓存。
    ks::ui::FieldDocument m_cachedKeyboardMouseHidFields; // m_cachedKeyboardMouseHidFields：键鼠/HID 缓存。
    ks::ui::FieldDocument m_cachedUsbTopologyFields;     // m_cachedUsbTopologyFields：USB 拓扑缓存。
    QVector<QStringList> m_cachedDeviceStackRows; // m_cachedDeviceStackRows：DevNode/设备栈表格行缓存。
    QVector<QStringList> m_cachedKeyboardMouseHidRows; // m_cachedKeyboardMouseHidRows：键鼠/HID 表格行缓存。
    QVector<QStringList> m_cachedUsbTopologyRows; // m_cachedUsbTopologyRows：USB 拓扑表格行缓存。
    ks::ui::FieldDocument m_cachedPnpAcpiPciFields;      // m_cachedPnpAcpiPciFields：PnP/ACPI/PCI 缓存。
    std::atomic_bool m_staticInfoRefreshing{ false }; // m_staticInfoRefreshing：静态信息异步刷新锁。
    std::atomic_bool m_deviceAuditRefreshing{ false }; // m_deviceAuditRefreshing：设备审计异步刷新锁。
    std::atomic<std::uint32_t> m_pendingDeviceAuditRefreshMask{ 0U }; // m_pendingDeviceAuditRefreshMask：重入时合并的页面刷新位。
    std::atomic_bool m_sensorRefreshing{ false };     // m_sensorRefreshing：传感器异步刷新锁。
    std::atomic_bool m_r0HardwareHealthRefreshing{ false }; // m_r0HardwareHealthRefreshing：R0硬件健康异步刷新锁。
    bool m_initialSamplingStarted = false;            // m_initialSamplingStarted：首次显示时是否已启动首轮采样。
    bool m_hardwareDetailsSamplingEnabled = false;    // 用户实际打开硬件页后才允许详细探测。
    std::uint64_t m_lastNetworkRxBytes = 0;           // m_lastNetworkRxBytes：兼容旧聚合网络采样的累计接收字节。
    std::uint64_t m_lastNetworkTxBytes = 0;           // m_lastNetworkTxBytes：兼容旧聚合网络采样的累计发送字节。
    qint64 m_lastNetworkSampleMs = 0;                 // m_lastNetworkSampleMs：兼容旧聚合网络采样时间戳(ms)。
    QString m_primaryNetworkAdapterName;              // m_primaryNetworkAdapterName：当前主活跃网卡名称。
    std::uint64_t m_primaryNetworkLinkBitsPerSecond = 0; // m_primaryNetworkLinkBitsPerSecond：主网卡链路速率。

    // 任务管理器详情态缓存。
    QString m_cpuModelText;                  // m_cpuModelText：CPU 型号文本。
    int m_cpuPackageCount = 0;               // m_cpuPackageCount：CPU 插槽数量。
    int m_cpuPhysicalCoreCount = 0;          // m_cpuPhysicalCoreCount：物理核心数量。
    int m_cpuLogicalCoreCount = 0;           // m_cpuLogicalCoreCount：逻辑核心数量。
    std::uint64_t m_cpuL1CacheBytes = 0;     // m_cpuL1CacheBytes：L1 缓存总字节。
    std::uint64_t m_cpuL2CacheBytes = 0;     // m_cpuL2CacheBytes：L2 缓存总字节。
    std::uint64_t m_cpuL3CacheBytes = 0;     // m_cpuL3CacheBytes：L3 缓存总字节。
    double m_lastCpuSpeedGhz = 0.0;          // m_lastCpuSpeedGhz：最近一次 CPU 速度（GHz）。
    qint64 m_lastR0HardwareHealthRefreshMs = 0; // m_lastR0HardwareHealthRefreshMs：最近一次 R0 硬件健康刷新时间。
    QString m_r0HardwareHealthSummaryText = QStringLiteral("R0硬件健康: 等待采样"); // m_r0HardwareHealthSummaryText：利用率页 R0 健康摘要。
    QString m_r0HardwareHealthDetailText = QStringLiteral("R0 CPU/MSR/IDT 证据尚未采样。"); // m_r0HardwareHealthDetailText：CPU 详情页 R0 证据明细摘要。
    QString m_r0CpuHardwareSummaryText = QStringLiteral("R0 CPU硬件: 等待采样"); // m_r0CpuHardwareSummaryText：R0 CPUID 摘要。
    QString m_r0CpuHardwareDetailText = QStringLiteral("R0 CPUID 硬件快照尚未采样。"); // m_r0CpuHardwareDetailText：R0 CPU特性明细。
    QString m_r0PhysicalMemorySummaryText = QStringLiteral("R0物理内存: 等待采样"); // m_r0PhysicalMemorySummaryText：R0 物理内存布局摘要。
    QString m_r0PhysicalMemoryDetailText = QStringLiteral("R0 物理内存布局尚未采样。"); // m_r0PhysicalMemoryDetailText：R0 内存 range 统计明细。

    int m_memorySpeedMhz = 0;                // m_memorySpeedMhz：内存主频（MHz）。
    int m_memorySlotUsed = 0;                // m_memorySlotUsed：已用内存插槽数量。
    int m_memorySlotTotal = 0;               // m_memorySlotTotal：总内存插槽数量。
    QString m_memoryFormFactorText;          // m_memoryFormFactorText：内存外形规格文本。

    QString m_gpuAdapterNameText;            // m_gpuAdapterNameText：GPU 适配器名称。
    QString m_gpuDriverVersionText;          // m_gpuDriverVersionText：GPU 驱动版本。
    QString m_gpuDriverDateText;             // m_gpuDriverDateText：GPU 驱动日期文本。
    QString m_gpuPnpDeviceIdText;            // m_gpuPnpDeviceIdText：GPU PNP 设备ID。
    double m_gpuCurrentCoreClockMhz = 0.0;    // m_gpuCurrentCoreClockMhz：当前 GPU 3D 核心频率 MHz。
    double m_gpuMaxCoreClockMhz = 0.0;        // m_gpuMaxCoreClockMhz：最大 GPU 3D 核心频率 MHz。
    double m_gpuCurrentMemoryClockMhz = 0.0;  // m_gpuCurrentMemoryClockMhz：当前显存频率 MHz。
    double m_gpuMaxMemoryClockMhz = 0.0;      // m_gpuMaxMemoryClockMhz：最大显存频率 MHz。
    double m_gpuDedicatedMemoryGiB = 0.0;    // m_gpuDedicatedMemoryGiB：GPU 专用显存（GiB）。
    double m_gpuSharedMemoryGiB = 0.0;       // m_gpuSharedMemoryGiB：GPU 可用共享系统内存（GiB）。
    double m_gpuUsage3DPercent = 0.0;        // m_gpuUsage3DPercent：3D 引擎利用率。
    double m_gpuUsageCopyPercent = 0.0;      // m_gpuUsageCopyPercent：Copy 引擎利用率。
    double m_gpuUsageVideoEncodePercent = 0.0; // m_gpuUsageVideoEncodePercent：视频编码引擎利用率。
    double m_gpuUsageVideoDecodePercent = 0.0; // m_gpuUsageVideoDecodePercent：视频解码引擎利用率。
    double m_gpuDedicatedUsedGiB = 0.0;      // m_gpuDedicatedUsedGiB：专用显存当前使用量。
    bool m_gpuDedicatedUsageAvailable = false; // m_gpuDedicatedUsageAvailable：专用显存系统占用采样是否有效。
    double m_gpuDedicatedBudgetGiB = 0.0;    // m_gpuDedicatedBudgetGiB：专用显存预算上限。
    double m_gpuSharedUsedGiB = 0.0;         // m_gpuSharedUsedGiB：共享显存当前使用量。
    bool m_gpuSharedUsageAvailable = false;  // m_gpuSharedUsageAvailable：共享显存系统占用采样是否有效。
    double m_gpuSharedBudgetGiB = 0.0;       // m_gpuSharedBudgetGiB：共享显存预算上限。

    QString m_systemVolumeText;              // m_systemVolumeText：系统盘卷标文本。
    std::uint64_t m_systemVolumeTotalBytes = 0; // m_systemVolumeTotalBytes：系统盘总容量字节。
    std::uint64_t m_systemVolumeFreeBytes = 0;  // m_systemVolumeFreeBytes：系统盘剩余容量字节。

    double m_diskNavAutoScaleBytesPerSec = 1024.0 * 1024.0; // m_diskNavAutoScaleBytesPerSec：兼容旧聚合磁盘页的动态缩放上限。
    double m_networkNavAutoScaleBytesPerSec = 1024.0 * 1024.0; // m_networkNavAutoScaleBytesPerSec：虚拟网络汇总卡片的动态缩放上限。
    std::vector<double> m_cpuUsageHistoryPercent; // m_cpuUsageHistoryPercent：CPU总体利用率历史，用于窗口统计。
    std::vector<double> m_memoryUsageHistoryPercent; // m_memoryUsageHistoryPercent：内存利用率历史，用于窗口统计。
    std::vector<double> m_gpuUsageHistoryPercent; // m_gpuUsageHistoryPercent：GPU总体利用率历史，用于窗口统计。
    std::vector<double> m_diskAggregateHistoryBytesPerSec; // m_diskAggregateHistoryBytesPerSec：磁盘聚合吞吐历史。
    std::vector<double> m_networkAggregateHistoryBytesPerSec; // m_networkAggregateHistoryBytesPerSec：网络聚合吞吐历史。
    std::vector<double> m_memoryNavUsedHistoryPercent; // m_memoryNavUsedHistoryPercent：内存已用缩略图历史。
    std::vector<double> m_memoryNavCachedHistoryPercent; // m_memoryNavCachedHistoryPercent：内存缓存/池缩略图历史。
    std::vector<double> m_diskNavReadHistoryBytesPerSec; // m_diskNavReadHistoryBytesPerSec：兼容旧聚合磁盘卡片读取历史。
    std::vector<double> m_diskNavWriteHistoryBytesPerSec; // m_diskNavWriteHistoryBytesPerSec：兼容旧聚合磁盘卡片写入历史。
    std::vector<double> m_networkNavRxHistoryBytesPerSec; // m_networkNavRxHistoryBytesPerSec：虚拟网络汇总下行历史。
    std::vector<double> m_networkNavTxHistoryBytesPerSec; // m_networkNavTxHistoryBytesPerSec：虚拟网络汇总上行历史。
    std::vector<DiskUtilizationDevice> m_diskUtilDevices; // m_diskUtilDevices：磁盘利用率多设备页。
    std::vector<NetworkUtilizationDevice> m_networkUtilDevices; // m_networkUtilDevices：网卡利用率多设备页。
    std::vector<GpuUtilizationDevice> m_gpuUtilDevices; // m_gpuUtilDevices：GPU利用率多设备页。

    // PDH 性能计数器句柄（用 void* 规避头文件引入 Windows 细节）。
    void* m_cpuPerfQueryHandle = nullptr;     // m_cpuPerfQueryHandle：PDH 查询句柄。
    std::vector<void*> m_coreCounterHandles;  // m_coreCounterHandles：每核利用率计数器句柄。
    void* m_cpuPerformanceCounterHandle = nullptr; // m_cpuPerformanceCounterHandle：CPU 总体性能百分比计数器。
    void* m_cpuFrequencyCounterHandle = nullptr; // m_cpuFrequencyCounterHandle：CPU 基准频率计数器。
    void* m_diskPerfQueryHandle = nullptr;    // m_diskPerfQueryHandle：磁盘速率查询句柄。
    void* m_diskReadCounterHandle = nullptr;  // m_diskReadCounterHandle：磁盘读速率计数器句柄。
    void* m_diskWriteCounterHandle = nullptr; // m_diskWriteCounterHandle：磁盘写速率计数器句柄。
    void* m_gpuPerfQueryHandle = nullptr;     // m_gpuPerfQueryHandle：GPU 利用率查询句柄。
    void* m_gpuCounterHandle = nullptr;       // m_gpuCounterHandle：GPU 引擎利用率计数器句柄。
    void* m_gpuDedicatedMemoryCounterHandle = nullptr; // m_gpuDedicatedMemoryCounterHandle：系统专用显存占用计数器句柄。
    void* m_gpuSharedMemoryCounterHandle = nullptr; // m_gpuSharedMemoryCounterHandle：系统共享显存占用计数器句柄。
};
