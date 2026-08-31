#pragma once

// ============================================================
// ProcessDock.h
// 作用：
// - 构建“进程”Dock 内的完整 R3 任务管理器界面；
// - 提供异步刷新、树/列表视图、列管理、右键操作等能力；
// - 与 ks::process Win32 封装层解耦，UI 层只做展示与交互。
// ============================================================

#include "../Framework.h"
#include "../ArkDriverClient/ArkDriverTypes.h"
#include "../ksword/process/process_cpu_core_etw_monitor.h"

#include <QColor>
#include <QHash>
#include <QIcon>
#include <QList>
#include <QModelIndex>
#include <QPointer>
#include <QSet>
#include <QSize>
#include <QThreadPool>
#include <QVariant>
#include <QWidget>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

// 前置声明：减少头文件编译开销。
class QComboBox;
class QCheckBox;
class QDoubleSpinBox;
class QFormLayout;
class QGroupBox;
class QHeaderView;
class QImage;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;
class QResizeEvent;
class QShowEvent;
class QSlider;
class QSortFilterProxyModel;
class QTableWidget;
class QTableView;
class QTabWidget;
class QTextEdit;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QHBoxLayout;
class QPoint;
class QWidget;
class CodeEditorWidget;
class ProcessDetailWindow;
class ProcessActivityChartWidget;
class ProcessActivityTimelineSlider;

namespace ks::process
{
    struct CounterSample;
    struct ThreadCounterSample;
    struct ProcessRecord;
    struct SystemThreadRecord;
}

namespace ks::network
{
    class ProcessNetworkEtwMonitor;
}

namespace ks::ui
{
    template<typename RowT>
    class FlatTableModel;
}

class ProcessDock final : public QWidget
{
    Q_OBJECT
    friend class ProcessActivityChartWidget;
    friend class ProcessActivityTimelineSlider;

public:
    // 构造函数作用：
    // - 初始化侧边栏 Tab；
    // - 初始化进程列表与控制栏；
    // - 启动默认监视（性能计数器视图）。
    explicit ProcessDock(QWidget* parent = nullptr);

    // 析构函数作用：
    // - 移除构造阶段安装到 QApplication 的鼠标事件过滤器；
    // - 不返回值，避免 Dock 销毁后仍收到全局点击事件。
    ~ProcessDock() override;

    // refreshThemeVisuals 作用：
    // - 在深浅色切换后，重绘当前列表行着色；
    // - 修复“新增进程高亮色在主题切换后残留”的问题。
    // 调用方式：MainWindow::applyAppearanceSettings 在主题更新后调用。
    // 入参：无。
    // 返回：无。
    void refreshThemeVisuals();

    // requestOpenProcessDetailByPid 作用：
    // - 外部模块按 PID 打开进程详情窗口；
    // - 若已存在对应窗口则复用，不重复创建。
    // 调用方式：MainWindow/FileDock 通过此入口跳转。
    // 参数 pid：目标进程 PID。
    // 返回：无。
    void requestOpenProcessDetailByPid(std::uint32_t pid);

    // requestOpenProcessDetailByIdentity 作用：
    // - 按历史事件保存的 PID+创建时间打开确切进程实例；
    // - 调用方式：MainWindow 的 identity-aware 跳转槽调用；
    // - 入参 pid：历史记录 PID；
    // - 入参 creationTime100ns：捕获时的进程创建时间；
    // - 返回：无；目标已退出、不可验证或 PID 已复用时明确提示并拒绝打开。
    void requestOpenProcessDetailByIdentity(
        std::uint32_t pid,
        std::uint64_t creationTime100ns);

signals:
    // requestFocusProcessProtectByCallback：进程页快捷入口请求主窗口打开统一回调保护页。
    void requestFocusProcessProtectByCallback();

protected:
    // eventFilter 作用：
    // - 捕获进程页内的鼠标点击；
    // - 点击进程表外部或表格空白区时清空当前进程选择，让活动图回到整体视图。
    // 参数 watched：事件接收对象；event：Qt 原始事件。
    // 返回值：true 表示事件已完全处理；false 表示继续交给 Qt 默认流程。
    bool eventFilter(QObject* watched, QEvent* event) override;

    // showEvent 作用：
    // - 在 Dock 首次真正显示时再启动首轮刷新与周期监视；
    // - 避免主窗口启动阶段被进程枚举拖慢。
    void showEvent(QShowEvent* event) override;

    // resizeEvent 作用：
    // - 在 Dock 尺寸变化时请求一次进程表默认列宽自适应；
    // - 不强制隐藏横向滚动条，用户手动拖宽列后允许滚动条按需出现。
    // 调用方式：Qt 在窗口尺寸变化时自动触发。
    // 参数 event：Qt 提供的尺寸变化事件对象（只读使用）。
    // 返回值：无。
    void resizeEvent(QResizeEvent* event) override;

private:
    // TableColumn：统一定义表格列索引，避免硬编码魔法数。
    enum class TableColumn : int
    {
        Name = 0,      // 进程名（含图标）。
        Pid,           // PID。
        Cpu,           // CPU 百分比。
        Ram,           // RAM（MB）。
        Disk,          // DISK（MB/s）。
        Gpu,           // GPU 百分比（R3 PDH GPU Engine 聚合）。
        Net,           // Net（预留）。
        Signature,     // 数字签名状态。
        Path,          // 可执行路径。
        ParentPid,     // 父进程 PID。
        CommandLine,   // 启动参数。
        User,          // 用户名。
        StartTime,     // 启动时间。
        IsAdmin,       // 是否管理员。
        PplLevel,      // 用户态手动刷新得到的 PPL 保护级别枚举。
        Protection,    // R0 读取的保护状态。
        Ppl,           // R0 读取的 PPL 原始字节。
        HandleCount,   // 进程句柄数量。
        HandleTable,   // EPROCESS.ObjectTable 是否可用。
        SectionObject, // EPROCESS.SectionObject 是否可用。
        R0Status,      // R0 扩展字段总体状态。

        // ======== 与 Windows 任务管理器“详细信息”页对齐的补齐列 ========
        // 说明：
        // - 这些列一律追加在既有列之后，保证旧列的逻辑索引不变；
        // - 默认全部隐藏，由“选择列”对话框或表头右键菜单按需开启；
        // - 展示顺序可由用户拖动表头调整，不依赖此处的枚举顺序。
        PackageName,             // 程序包名称（UWP / MSIX 包全名）。
        Status,                  // 状态：运行中 / 已挂起。
        SessionId,               // 会话 ID。
        JobObject,               // 作业对象 ID（归属判定）。
        CpuTime,                 // CPU 时间（内核态 + 用户态累计）。
        CycleTime,               // 周期（累计 CPU 周期数）。
        WorkingSet,              // 工作集(内存)。
        PeakWorkingSet,          // 峰值工作集(内存)。
        WorkingSetDelta,         // 工作集增量(内存)。
        ActivePrivateWorkingSet, // 内存(活动的专用工作集)。
        PrivateWorkingSet,       // 内存(专用工作集)。
        SharedWorkingSet,        // 内存(共享工作集)。
        CommitSize,              // 提交大小。
        PagedPool,               // 分页缓冲池。
        NonPagedPool,            // 非分页缓冲池。
        PageFaults,              // 页面错误。
        PageFaultDelta,          // 页面错误增量。
        BasePriority,            // 基本优先级。
        ThreadCount,             // 线程数量。
        UserObjects,             // 用户对象。
        GdiObjects,              // GDI 对象。
        IoReads,                 // I/O 读取次数。
        IoWrites,                // I/O 写入次数。
        IoOther,                 // I/O 其他次数。
        IoReadBytes,             // I/O 读取字节。
        IoWriteBytes,            // I/O 写入字节。
        IoOtherBytes,            // I/O 其他字节。
        OsContext,               // 操作系统上下文（映像清单 supportedOS）。
        Platform,                // 平台 / 体系结构。
        UacVirtualization,       // UAC 虚拟化。
        Description,             // 描述（映像版本资源 FileDescription）。
        DataExecutionPrevention, // 数据执行保护。
        ControlFlowGuard,        // 控制流保护。
        HardwareStackProtection, // 硬件强制实施的堆栈保护（CET 影子栈）。
        EnterpriseContext,       // 企业上下文。
        DpiAwareness,            // DPI 感知。
        PowerThrottling,         // 电源节流（效率模式）。
        GpuEngine,               // GPU 引擎。
        GpuDedicatedMemory,      // 专用 GPU 内存。
        GpuSharedMemory,         // 共享 GPU 内存。
        ProcessType,             // 类型：应用 / 后台进程 / Windows 进程。
        CpuCore,                 // CPU核心：真实逻辑处理器逐核心占用扇形图。
        Count                    // 列总数。
    };

    // ProcessColumnGroup：
    // - 作用：把列按语义分组，仅用于“选择列”对话框的展示与检索；
    // - 不影响列的逻辑索引，也不参与任何数据读写路径。
    enum class ProcessColumnGroup : int
    {
        General = 0, // 常规：身份、路径、用户、启动信息。
        Performance, // 性能：CPU / GPU / 磁盘 / 网络等实时指标。
        Memory,      // 内存：工作集、提交、缓冲池、页面错误。
        Io,          // I/O：读写次数与字节数。
        Security,    // 安全：签名、完整性、缓解策略、虚拟化。
        Kernel,      // 内核：R0 扩展字段。
        Count        // 分组总数。
    };

    // ThreadTableColumn：线程页表格列索引定义。
    enum class ThreadTableColumn : int
    {
        ThreadId = 0,      // 线程 ID。
        OwnerPid,          // 所属进程 PID。
        ProcessName,       // 所属进程名（含图标）。
        ThreadClass,       // 系统线程 / Ex 工作线程分类。
        StartAddress,      // 线程启动地址。
        Win32StartAddress, // Win32StartAddress（R3 扩展线程信息）。
        TebBaseAddress,    // TEB 基址（R3 扩展线程信息）。
        UserStackBase,     // 用户栈基址（R3 扩展线程信息）。
        UserStackLimit,    // 用户栈边界（R3 扩展线程信息）。
        KernelStack,       // KTHREAD.KernelStack（R0 DynData）。
        KStackBase,        // KTHREAD.StackBase（R0 DynData）。
        KStackLimit,       // KTHREAD.StackLimit（R0 DynData）。
        InitialStack,      // KTHREAD.InitialStack（R0 DynData）。
        ReadOps,           // KTHREAD ReadOperationCount。
        WriteOps,          // KTHREAD WriteOperationCount。
        OtherOps,          // KTHREAD OtherOperationCount。
        ReadBytes,         // KTHREAD ReadTransferCount。
        WriteBytes,        // KTHREAD WriteTransferCount。
        OtherBytes,        // KTHREAD OtherTransferCount。
        ThreadR0Status,    // R0 线程扩展字段状态。
        Priority,          // 动态优先级。
        BasePriority,      // 基础优先级。
        ThreadState,       // 线程状态码（含文本）。
        WaitReason,        // 等待原因码（含文本）。
        KernelTimeMs,      // 内核态累计时间（毫秒）。
        UserTimeMs,        // 用户态累计时间（毫秒）。
        CpuTimeMs,         // CPU 累计时间（毫秒）。
        WaitTimeTick,      // 等待时长计数。
        ContextSwitches,   // 上下文切换次数。
        CreateTime,        // 创建时间。
        ProcessPath,       // 所属进程路径（可为空）。
        CpuPercent,        // 相邻快照线程 CPU 单核占用（0~100）。
        Count              // 列总数。
    };

    // ThreadColumnLayout：线程表 A/B 紧凑列预设；Custom 表示用户已手动调整。
    enum class ThreadColumnLayout : int
    {
        PresetA = 0, // 调度概览：身份、优先级、状态、等待与 CPU/切换统计。
        PresetB,     // 地址诊断：身份、启动/TEB/内核栈地址与 R0 状态。
        Custom       // 表头菜单、拖动或缩放后的自定义布局。
    };

    // ThreadScopeFilter：线程页按 R3 System 归属和 R0 ActiveExWorker 分类筛选。
    enum class ThreadScopeFilter : int
    {
        All = 0,
        System,
        Worker
    };

    // ViewMode：内置视图预设。
    // 说明：
    // - 每个预设都固定包含进程名与 PID，保证任何视图下都能辨认目标；
    // - 预设只决定“默认显示哪些列”，用户在“选择列”里的调整会叠加在预设之上；
    // - 用户自定义视图不属于本枚举，由 m_customViews 单独维护。
    enum class ViewMode : int
    {
        Monitor = 0, // 监视：CPU / 内存 / 磁盘 / GPU / 网络等实时计数器。
        Detail,      // 详细信息：路径、命令行、用户、签名等静态与管理信息。
        Memory,      // 内存分析：工作集、提交、缓冲池与页面错误。
        DiskIo,      // 磁盘 I/O：读写次数与字节数。
        Gpu,         // GPU：占用、引擎与显存。
        Security,    // 安全与策略：签名、提升、虚拟化与各项缓解策略。
        Kernel,      // 内核证据：R0 扩展字段。
        Count        // 内置预设总数。
    };

    // ProcessCustomView：
    // - 作用：保存用户自定义视图的名称与可见列集合；
    // - 持久化在 QSettings 中，跨会话保留；
    // - 应用时同样保证进程名与 PID 一定可见。
    struct ProcessCustomView
    {
        QString name;                    // name：用户输入的视图名称，同时作为配置键。
        std::vector<int> visibleColumns; // visibleColumns：该视图下需要显示的列逻辑索引。
    };

    // ProcessTableRowKind：
    // - Process 表示真实进程行，可作为右键、双击、R0/R3 操作目标；
    // - GroupHeader 表示“应用/后台进程/系统”分类标题，只负责展示和展开；
    // - ApplicationAggregate 表示某个应用的聚合父行，展示汇总指标并把动作展开到全部成员进程。
    enum class ProcessTableRowKind : int
    {
        Process = 0,
        GroupHeader,
        ApplicationAggregate
    };

    // FriendlyProcessGroupType：进程友好视图的三级分类，顺序贴近任务管理器/HUD。
    enum class FriendlyProcessGroupType : int
    {
        Application = 0,
        Background,
        WindowsSystem
    };

    // DisplayRow：列表渲染层的数据结构（带状态标记）。
    struct DisplayRow
    {
        ks::process::ProcessRecord* record = nullptr; // 指向缓存中的实体数据。
        ProcessTableRowKind rowKind = ProcessTableRowKind::Process; // rowKind：真实进程/分类标题/应用聚合。
        FriendlyProcessGroupType friendlyGroupType = FriendlyProcessGroupType::Background; // friendlyGroupType：友好视图分类。
        QString syntheticTitle;                       // syntheticTitle：合成行名称列显示文本；真实进程为空。
        QString expansionKey;                         // expansionKey：合成行展开状态键；真实进程通常为空。
        std::vector<std::string> actionIdentityKeys;   // actionIdentityKeys：应用聚合行对应的全部真实进程标识。
        int depth = 0;                                // 树状列表下的缩进深度。
        bool hasChildren = false;                     // hasChildren：真实树状/友好视图下是否存在子进程。
        bool isNew = false;                           // 本轮新增进程（绿色高亮）。
        bool isExited = false;                        // 本轮退出但保留一轮（灰色高亮）。
        bool isKernelOnly = false;                    // 仅内核枚举可见（疑似隐藏进程，红色高亮）。
    };

    // ProcessTableRow：
    // - 作用：QTableView 模型持有的轻量行对象；
    // - 输入来源：rebuildTable 根据 DisplayRow 和本轮最大占用值生成；
    // - 返回行为：本结构只承载数据，不主动返回 UI 对象。
    struct ProcessTableRow
    {
        ks::process::ProcessRecord record;            // record：表格行持有的进程快照，避免后台刷新替换缓存后悬空。
        std::string identityKey;                      // identityKey：PID+创建时间，用于选择恢复和动作绑定。
        ProcessTableRowKind rowKind = ProcessTableRowKind::Process; // rowKind：控制展示和动作是否允许。
        FriendlyProcessGroupType friendlyGroupType = FriendlyProcessGroupType::Background; // friendlyGroupType：合成行所属分类。
        QString syntheticTitle;                       // syntheticTitle：分类/聚合行的展示标题。
        QString expansionKey;                         // expansionKey：分类/聚合行展开状态键。
        std::vector<std::string> actionIdentityKeys;   // actionIdentityKeys：应用聚合行批量动作的成员标识。
        QList<std::uint32_t> cpuCoreProcessIds;         // cpuCoreProcessIds：逐核心绘制参与汇总的真实 PID 集合。
        int depth = 0;                                // depth：树状显示时的缩进层级。
        bool hasChildren = false;                     // hasChildren：供表示层绘制树状展开提示。
        bool isNew = false;                           // isNew：新增行高亮标记。
        bool isExited = false;                        // isExited：退出保留行高亮标记。
        bool isKernelOnly = false;                    // isKernelOnly：仅内核可见进程高亮标记。
        bool activitySnapshotActive = false;          // activitySnapshotActive：该行是否来自历史时间轴快照。
        double cpuUsageRatio = 0.0;                   // cpuUsageRatio：CPU 单元格蓝色占比高亮比例。
        double ramUsageRatio = 0.0;                   // ramUsageRatio：RAM 单元格蓝色占比高亮比例。
        double diskUsageRatio = 0.0;                  // diskUsageRatio：DISK 单元格蓝色占比高亮比例。
        double gpuUsageRatio = 0.0;                   // gpuUsageRatio：GPU 单元格蓝色占比高亮比例。
        double netUsageRatio = 0.0;                   // netUsageRatio：Net 单元格蓝色占比高亮比例。
        double handleUsageRatio = 0.0;                // handleUsageRatio：句柄数单元格蓝色占比高亮比例。
    };

    using ProcessTableModel = ks::ui::FlatTableModel<ProcessTableRow>;

    // CacheEntry：进程缓存条目（用于复用静态信息和退出保留）。
    struct CacheEntry
    {
        ks::process::ProcessRecord record; // 完整进程记录。
        int missingRounds = 0;             // 连续缺失轮次（1 表示“刚退出，保留显示”）。
        bool isNewInLatestRound = false;   // 最新刷新中是否为新增。
        bool isExitedInLatestRound = false;// 最新刷新中是否为退出保留。
        bool isKernelOnlyInLatestRound = false; // 最新刷新中是否仅内核枚举可见。
        std::uint32_t staticFillAttemptCount = 0; // 静态详情补齐尝试次数（含成功/失败）。
        std::uint32_t staticFillFailureCount = 0; // 静态详情连续失败次数（用于退避重试）。
        // onDemandResolvedFlags：
        // - 已经成功采集过的 ks::process::ProcessDetailDemand 静态位；
        // - 作业归属、缓解策略、UAC 虚拟化、映像说明等字段在进程生命周期内不变，
        //   记录后即可跳过后续每一轮的重复查询，只保留真正动态的 GUI 资源计数。
        std::uint32_t onDemandResolvedFlags = 0;
    };

    // AffinityRestoreRetryState：
    // - 作用：记录某个进程实例恢复持久化亲和性失败后的退避状态；
    // - 调用方式：restorePersistedAffinityForNewProcesses 在下一轮刷新前检查；
    // - 返回行为：本结构只保存连续失败次数和下一次允许尝试的时间。
    struct AffinityRestoreRetryState
    {
        std::uint32_t consecutiveFailureCount = 0U; // consecutiveFailureCount：连续恢复失败次数。
        std::chrono::steady_clock::time_point nextAttemptTime{}; // nextAttemptTime：下一次允许恢复的单调时钟时间。
    };

    // ProcessActionTarget：
    // - 作用：保存一次右键动作绑定的进程快照；
    // - identityKey 用于回写缓存与保持选择，record 是跨线程执行时使用的只读副本。
    struct ProcessActionTarget
    {
        std::string identityKey;            // identityKey：PID+创建时间构成的稳定行标识。
        ks::process::ProcessRecord record;  // record：动作执行线程使用的进程记录副本。
        bool isKernelOnly = false;           // isKernelOnly：仅 R0 可见目标不能依赖 Win32 句柄校验。
    };

    // NetworkTrafficCounters：
    // - 输入：ETW 采集器上报的按 PID 网络累计字节；
    // - 处理：按 PID 累计下行/上行字节；
    // - 返回：作为刷新线程的只读快照，速率由 CounterSample 差分计算。
    struct NetworkTrafficCounters
    {
        std::uint64_t rxBytes = 0; // rxBytes：累计下行字节。
        std::uint64_t txBytes = 0; // txBytes：累计上行字节。
    };

    // RefreshResult：后台线程刷新结果对象。
    struct RefreshResult
    {
        std::unordered_map<std::string, CacheEntry> nextCache;                    // 下一轮缓存。
        std::unordered_map<std::string, ks::process::CounterSample> nextCounters; // 下一轮计数器样本。
        std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> cpuCoreUsageSnapshot; // 后台构造的共享逐核心快照，UI 只移动指针。

        // ======== 统计字段（用于 UI 状态提示 + 详细日志） ========
        std::size_t enumeratedCount = 0;        // 本轮枚举到的“当前存活”进程数。
        std::size_t newProcessCount = 0;        // 本轮新增进程数量。
        std::size_t exitedProcessCount = 0;     // 本轮退出保留数量（灰底保留一轮）。
        std::size_t reusedProcessCount = 0;     // 本轮复用旧缓存的数量。
        std::size_t staticFilledCount = 0;      // 本轮实际补齐静态详情的数量。
        std::size_t staticDeferredCount = 0;    // 本轮因预算或模式延后的静态详情数量。
        std::size_t imagePathFilledCount = 0;   // 本轮额外补齐 imagePath 的数量（用于图标显示）。
        std::uint64_t workerElapsedMs = 0;      // 后台线程本轮构建结果耗时（毫秒）。
        int selectedStrategyIndex = 0;          // UI 选择的策略下标（0/1）。
        ks::process::ProcessEnumStrategy selectedStrategy{}; // 由下标映射的策略枚举。
        ks::process::ProcessEnumStrategy actualStrategy{};   // 实际执行策略（Auto 下可能回退）。
        bool detailModeEnabled = false;         // 本轮是否处于“详细信息视图”。
        bool kernelCompareEnabled = false;      // 本轮是否启用内核进程对比。
        bool kernelQuerySucceeded = false;      // 内核进程查询是否成功。
        std::size_t kernelEnumeratedCount = 0;  // 内核枚举得到的进程数量。
        std::size_t kernelOnlyCount = 0;        // 仅内核可见（疑似隐藏）进程数量。
        std::string kernelQueryDetailText;      // 内核查询诊断文本（错误或统计）。
    };

public:
    // ProcessActivityMetric：进程活动折线图支持切换显示的指标。
    enum class ProcessActivityMetric : int
    {
        Cpu = 0,     // CPU 百分比。
        Memory,      // 内存工作集 MB。
        Disk,        // 磁盘吞吐 MB/s。
        Network,     // 网络吞吐 KB/s。
        Gpu          // GPU 百分比。
    };

    // ProcessActivityProcessPoint：单个采样点中的单进程历史快照。
    //
    // 只保留会随采样变化、且在回看资源占用时有诊断价值的字段；路径、签名、
    // 缓解策略等静态详情仍不重复写入每一个采样点。所有按需字段同时保存其
    // known 标记，防止历史表格把当时未采集到的值误显示为 0。
    struct ProcessActivityProcessPoint
    {
        std::string identityKey;       // identityKey：PID + 创建时间，和表格选择保持一致。
        std::string processName;       // processName：快照悬停展示用短名称。
        std::string imagePath;         // imagePath：采样时的可执行路径，用于历史表格恢复真实图标。
        std::string iconCacheKey;      // iconCacheKey：进程名 + 路径组成的稳定图标缓存键。
        std::uint64_t creationTime100ns = 0; // creationTime100ns：原始进程创建时间，用于历史表格保持 identity。
        std::uint32_t pid = 0;         // pid：快照悬停展示和排查用。
        double cpuPercent = 0.0;       // cpuPercent：该进程采样时 CPU。
        double cpuCorePercent = 0.0;   // cpuCorePercent：该进程单核等效 CPU，可超过 100%。
        double ramMB = 0.0;            // ramMB：该进程采样时申请/提交内存。
        double workingSetMB = 0.0;     // workingSetMB：该进程采样时实际工作集。
        double diskMBps = 0.0;         // diskMBps：该进程采样时磁盘吞吐。
        double netKBps = 0.0;          // netKBps：该进程采样时网络吞吐。
        double netRxKBps = 0.0;        // netRxKBps：该进程采样时网络下行吞吐。
        double netTxKBps = 0.0;        // netTxKBps：该进程采样时网络上行吞吐。
        double gpuPercent = 0.0;       // gpuPercent：该进程采样时 GPU 百分比。

        // 调度、运行状态与对象占用。
        std::uint32_t threadCount = 0;          // threadCount：采样时线程数量。
        std::uint32_t handleCount = 0;          // handleCount：采样时句柄数量。
        std::uint32_t suspendedThreadCount = 0; // suspendedThreadCount：采样时已挂起线程数。
        std::int32_t basePriority = 0;          // basePriority：采样时基础优先级。
        bool processStateKnown = false;         // processStateKnown：运行/挂起状态是否成功判定。
        bool processSuspended = false;          // processSuspended：采样时是否全部挂起。
        bool efficiencyModeSupported = false;   // efficiencyModeSupported：效率模式状态是否可用。
        bool efficiencyModeEnabled = false;     // efficiencyModeEnabled：采样时是否启用效率模式。

        // CPU 与内存占用细项。
        std::uint64_t rawCpuTime100ns = 0;               // rawCpuTime100ns：累计 CPU 时间。
        std::uint64_t cycleTime = 0;                     // cycleTime：累计 CPU 周期数。
        std::uint64_t rawWorkingSetBytes = 0;            // rawWorkingSetBytes：精确工作集字节数。
        std::uint64_t peakWorkingSetBytes = 0;           // peakWorkingSetBytes：峰值工作集。
        std::uint64_t privateWorkingSetBytes = 0;        // privateWorkingSetBytes：专用工作集。
        std::uint64_t sharedWorkingSetBytes = 0;         // sharedWorkingSetBytes：共享工作集。
        std::uint64_t commitSizeBytes = 0;               // commitSizeBytes：提交大小。
        std::uint64_t pagedPoolBytes = 0;                // pagedPoolBytes：分页池用量。
        std::uint64_t nonPagedPoolBytes = 0;             // nonPagedPoolBytes：非分页池用量。
        std::uint64_t pageFaultCount = 0;                // pageFaultCount：累计页面错误。
        std::int64_t workingSetDeltaBytes = 0;           // workingSetDeltaBytes：相邻轮次工作集变化。
        std::int64_t pageFaultDeltaCount = 0;            // pageFaultDeltaCount：相邻轮次页面错误变化。
        bool cycleTimeKnown = false;                     // cycleTimeKnown：CPU 周期数是否可用。
        bool memoryDetailKnown = false;                  // memoryDetailKnown：内存细项是否可用。
        bool privateWorkingSetKnown = false;             // privateWorkingSetKnown：专用/共享工作集是否可用。

        // I/O 与 GUI 资源计数。
        std::uint64_t ioReadOperationCount = 0;          // ioReadOperationCount：累计 I/O 读取次数。
        std::uint64_t ioWriteOperationCount = 0;         // ioWriteOperationCount：累计 I/O 写入次数。
        std::uint64_t ioOtherOperationCount = 0;         // ioOtherOperationCount：累计其他 I/O 次数。
        std::uint64_t ioReadTransferBytes = 0;           // ioReadTransferBytes：累计读取字节数。
        std::uint64_t ioWriteTransferBytes = 0;          // ioWriteTransferBytes：累计写入字节数。
        std::uint64_t ioOtherTransferBytes = 0;          // ioOtherTransferBytes：累计其他 I/O 字节数。
        std::uint32_t gdiObjectCount = 0;                // gdiObjectCount：采样时 GDI 对象数。
        std::uint32_t userObjectCount = 0;               // userObjectCount：采样时 USER 对象数。
        bool ioDetailKnown = false;                      // ioDetailKnown：I/O 细项是否可用。
        bool guiResourceKnown = false;                   // guiResourceKnown：GUI 资源是否已采集。

        // GPU 显存与当前占用引擎。
        std::uint64_t gpuDedicatedMemoryBytes = 0;       // gpuDedicatedMemoryBytes：专用显存占用。
        std::uint64_t gpuSharedMemoryBytes = 0;          // gpuSharedMemoryBytes：共享显存占用。
        std::string gpuEngineText;                       // gpuEngineText：采样时占用最高的 GPU 引擎。
        bool gpuMemoryKnown = false;                     // gpuMemoryKnown：GPU 显存计数是否可用。
    };

    // ProcessActivitySample：一次进程列表活动采样。
    struct ProcessActivitySample
    {
        std::uint64_t sequence = 0;           // sequence：记录内单调递增序号。
        std::uint64_t elapsedMs = 0;          // elapsedMs：距本次记录开始的毫秒数。
        std::int64_t unixMilliseconds = 0;    // unixMilliseconds：本地时间戳，便于 UI 格式化。
        double totalCpuPercent = 0.0;         // totalCpuPercent：全局聚合 CPU。
        double totalMemoryMB = 0.0;           // totalMemoryMB：全局聚合工作集。
        double totalDiskMBps = 0.0;           // totalDiskMBps：全局聚合磁盘吞吐。
        double totalNetKBps = 0.0;            // totalNetKBps：全局聚合网络吞吐。
        double totalGpuPercent = 0.0;         // totalGpuPercent：全局聚合 GPU。
        std::vector<ProcessActivityProcessPoint> processes; // processes：该时刻仍存活的进程快照。
    };

private:
    // ======== UI 初始化相关 ========
    void initializeUi();
    void initializeTopControls();
    void initializeProcessActivityPanel();
    void initializeProcessTable();
    void initializeCreateProcessPage();
    void initializeThreadPage();
    // initializeCrossViewPage 作用：
    // - 创建 ProcessDock 的 R0 Cross-View 证据页；
    // - 页面展示进程/线程来源矩阵和异常 flags；
    // - 不提供 DKOM 修复、结束进程或任意写按钮。
    void initializeCrossViewPage();
    void initializeConnections();
    void initializeThreadPageConnections();
    // initializeCrossViewConnections 作用：
    // - 连接 Cross-View 刷新、过滤和表格选择事件；
    // - 所有 R0 查询都通过 ArkDriverClient；
    // - 返回值：无。
    void initializeCrossViewConnections();
    void initializeTimer();
    // applyAdaptiveColumnWidths 作用：
    // - 将进程表列设置为可交互宽度模式；
    // - 请求全局表格列宽自适应器按 viewport 压缩默认列宽；
    // - 不返回值，也不修改横向/纵向滚动条策略。
    void applyAdaptiveColumnWidths();
    int refreshIntervalMillisecondsFromInput() const;
    void applyRefreshIntervalInput();
    void initializeCreateProcessConnections();
    void focusProcessSearchBox(bool selectAllText);
    QString currentProcessSearchText() const;
    bool processRecordMatchesSearch(const ks::process::ProcessRecord& processRecord) const;

    // ======== 刷新与渲染 ========
    void requestAsyncRefresh(bool forceRefresh);
    void applyRefreshResult(RefreshResult refreshResult, bool forceUiRefresh);
    // restorePersistedAffinityForNewProcesses 作用：
    // - 为本轮新发现或上次恢复失败的进程实例恢复用户保存的 CPU 亲和性规则；
    // - 成功或明确不存在规则后完成记账，暂时失败则按有上限的指数退避重试。
    void restorePersistedAffinityForNewProcesses(RefreshResult& refreshResult);
    void rebuildTable();
    bool shouldRebuildProcessTableForRefresh(bool forceUiRefresh) const;
    void requestAsyncThreadRefresh(bool forceRefresh);
    void rebuildThreadTable();
    void applyThreadColumnLayout(ThreadColumnLayout layout);
    void clearThreadColumnPresetSelection();
    void updateThreadColumnPresetButtons();
    // refreshCrossViewAsync 作用：
    // - 异步查询 R0 process/thread cross-view 证据；
    // - 结果回填到 m_processCrossViewCache / m_threadCrossViewCache；
    // - 返回值：无。
    void refreshCrossViewAsync();
    // rebuildCrossViewTables 作用：
    // - 按当前搜索框和缓存重绘 PID/TID 来源矩阵；
    // - 只做 UI 投影，不再次查询驱动；
    // - 返回值：无。
    void rebuildCrossViewTables();
    // showCrossViewDetailForCurrentRow 作用：
    // - 展示当前选中的进程或线程 cross-view 详情；
    // - 参数 preferThreadTable 为 true 时优先读取线程表；
    // - 返回值：无。
    void showCrossViewDetailForCurrentRow(bool preferThreadTable);
    std::vector<DisplayRow> buildDisplayOrder() const;
    std::vector<DisplayRow> buildTreeDisplayOrder() const;
    std::vector<DisplayRow> buildListDisplayOrder() const;
    std::vector<DisplayRow> buildFriendlyDisplayOrder() const;
    // buildFriendlyGroupTypeByPid 作用：
    // - 在任意视图模式下算出每个 PID 的“应用 / 后台进程 / Windows 进程”归类；
    // - 供任务管理器对齐的“类型”列在树状与列表视图下也能给出正确取值；
    // - 只有该列可见时才会被调用，避免为不显示的列做窗口枚举。
    // 返回：PID 到分组类型的映射。
    std::unordered_map<std::uint32_t, FriendlyProcessGroupType> buildFriendlyGroupTypeByPid() const;
    std::vector<DisplayRow> buildActivitySnapshotDisplayOrder() const;
    void applyR0ColumnAvailability(const std::vector<DisplayRow>& displayRows);

    // ======== 视图控制 ========
    void applyViewMode(ViewMode viewMode);
    void applyDefaultColumnWidths();
    bool isTreeModeEnabled() const;
    bool isFriendlyViewEnabled() const;
    ViewMode currentViewMode() const;

    // ======== 视图预设与自定义视图 ========
    // defaultVisibleColumnsForViewMode 作用：
    // - 返回某个内置预设默认显示的列集合；
    // - 是 applyViewMode 与“恢复默认”共用的唯一事实来源。
    // 参数 viewMode：目标预设。
    // 返回：该预设的列逻辑索引集合（一定包含进程名与 PID）。
    static std::vector<int> defaultVisibleColumnsForViewMode(ViewMode viewMode);

    // viewModeDisplayName 作用：返回内置预设在下拉框中的显示名称。
    static QString viewModeDisplayName(ViewMode viewMode);

    // currentCustomViewIndex 作用：
    // - 返回当前选中的自定义视图下标；
    // - 返回 -1 表示当前选中的是内置预设。
    int currentCustomViewIndex() const;

    // applyCustomView 作用：
    // - 按下标应用某个自定义视图的列集合；
    // - 参数 customIndex：m_customViews 中的下标；越界时忽略。
    void applyCustomView(int customIndex);

    // rebuildViewModeComboItems 作用：
    // - 依据内置预设与当前自定义视图列表重建下拉项；
    // - 重建期间屏蔽信号，避免触发多余的视图切换与刷新。
    void rebuildViewModeComboItems();

    // saveCurrentColumnsAsCustomView 作用：
    // - 把当前可见列保存为一个命名的自定义视图；同名时覆盖；
    // - 参数 viewName：用户输入的名称（调用方负责去空白与非空校验）；
    // - 返回：保存后该视图在 m_customViews 中的下标。
    int saveCurrentColumnsAsCustomView(const QString& viewName);

    // removeCustomView 作用：删除指定下标的自定义视图并回落到监视视图。
    void removeCustomView(int customIndex);

    // loadCustomViewsFromSettings / saveCustomViewsToSettings 作用：
    // - 在 QSettings 中读写用户自定义视图列表。
    void loadCustomViewsFromSettings();
    void saveCustomViewsToSettings() const;

    // isStaticDetailIntensiveViewActive 作用：
    // - 判断当前可见列是否包含路径 / 命令行 / 用户 / 签名 / 描述这类需要打开进程的静态字段；
    // - 后台刷新据此决定静态详情预算，避免把预算判定写死在“详细信息视图”上；
    // - 返回：true 表示需要更高的静态详情补齐预算。
    bool isStaticDetailIntensiveViewActive() const;

    // ======== 表格交互 ========
    void showTableContextMenu(const QPoint& localPosition);
    void showThreadTableContextMenu(const QPoint& localPosition);
    void showThreadHeaderContextMenu(const QPoint& localPosition);
    void showHeaderContextMenu(const QPoint& localPosition);

    // ======== 进程表列管理（添加/减少列） ========
    // showColumnChooserDialog 作用：
    // - 打开“选择列”对话框，让用户按分组勾选需要显示的列；
    // - 支持关键字搜索、全选、全不选与恢复当前视图默认；
    // - 确定后写入用户列覆盖并立即应用，同时持久化到配置。
    // 参数：无。
    // 返回值：无。
    void showColumnChooserDialog();

    // setProcessColumnVisible 作用：
    // - 统一的列显隐入口，负责写入用户覆盖、更新表格并刷新采集需求；
    // - 参数 columnIndex：目标列逻辑索引；
    // - 参数 visible：true 显示，false 隐藏；
    // - 参数 persistImmediately：true 时立即写入配置，批量修改时可传 false 最后统一保存；
    // - 返回值：无。
    void setProcessColumnVisible(int columnIndex, bool visible, bool persistImmediately = true);

    // applyUserColumnVisibilityOverrides 作用：
    // - 在视图预设铺好基础显隐后，把用户的逐列选择叠加回去；
    // - 这样切换“监视/详细”视图不会丢掉用户自己添加的列；
    // - 返回值：无。
    void applyUserColumnVisibilityOverrides();

    // resetProcessColumnsToViewDefault 作用：
    // - 清空用户列覆盖，让进程表回到当前视图模式的默认列集合；
    // - 返回值：无。
    void resetProcessColumnsToViewDefault();

    // loadProcessColumnLayoutFromSettings / saveProcessColumnLayoutToSettings 作用：
    // - 在 QSettings 中读写用户的列显隐选择，使配置跨会话保留；
    // - 只保存“与视图默认不同”的项，避免默认列集合调整后被旧配置钉死；
    // - 返回值：无。
    void loadProcessColumnLayoutFromSettings();
    void saveProcessColumnLayoutToSettings() const;

    // currentProcessDetailDemandFlags 作用：
    // - 按当前可见列计算 ks::process::ProcessDetailDemand 位图；
    // - 后台刷新据此决定是否为 GDI/作业/缓解策略/显存等字段付出额外采集成本；
    // - 返回值：需求位图；没有任何按需列可见时返回 None。
    std::uint32_t currentProcessDetailDemandFlags() const;

    // isProcessColumnVisible 作用：
    // - 判断某列当前是否可见，供采集需求计算与对话框初始化复用；
    // - 参数 column：目标列；
    // - 返回值：true 表示该列当前显示。
    bool isProcessColumnVisible(TableColumn column) const;

    // processColumnGroupOf / processColumnGroupTitle 作用：
    // - 提供“选择列”对话框所需的分组信息；
    // - 仅影响对话框展示，不参与数据读写。
    static ProcessColumnGroup processColumnGroupOf(TableColumn column);
    static QString processColumnGroupTitle(ProcessColumnGroup group);

    // processColumnDisplayName 作用：
    // - 返回某列在当前语言下的表头名称（不含 CPU/RAM 汇总后缀）；
    // - 列表头文本表定义在 ProcessDock.cpp 的匿名命名空间中，
    //   该函数是其它翻译单元（如列选择对话框）访问列名的唯一入口。
    // 参数 columnIndex：列逻辑索引。
    // 返回：列名；索引越界时返回空串。
    static QString processColumnDisplayName(int columnIndex);
    void copyCurrentCell();
    void copyCurrentRow();
    void copyCurrentThreadCell();
    void copyCurrentThreadRow();
    void openProcessDetailsPlaceholder();
    // openSelectedProcessHotkeyScanner 作用：
    // - 从进程列表右键菜单打开当前进程详情窗口；
    // - 自动切换到“进程热键”页并启动热键扫描；
    // - 仅支持单进程，避免批量菜单误触发多个扫描窗口。
    void openSelectedProcessHotkeyScanner();
    // openSelectedProcessInjectionPage 作用：
    // - 从进程列表右键菜单打开当前进程详情窗口；
    // - 自动切换到“操作”页，直达 DLL/Shellcode 注入区域；
    // - 仅支持单进程，避免批量菜单误触发多个详情窗口。
    void openSelectedProcessInjectionPage();
    // showProcessDetailWindowForRecord 作用：
    // - 按已验证的 identity 与记录复用或创建进程详情窗口；
    // - 入参 identityKey：PID+创建时间稳定键；
    // - 入参 detailRecord：用于详情窗口的进程记录；
    // - 返回：无。
    void showProcessDetailWindowForRecord(
        const std::string& identityKey,
        const ks::process::ProcessRecord& detailRecord);
    void openProcessDetailWindowByPid(std::uint32_t pid);
    void openThreadOwnerProcessDetails();
    // openThreadStackWindow 作用：
    // - 为当前线程列表选中行打开 Phase-8 调用栈窗口；
    // - R3 捕获用户栈，R0 字段只作为内核栈边界辅助诊断。
    void openThreadStackWindow();
    void executeSuspendThreadAction();
    void executeResumeThreadAction();
    void executeR0SuspendThreadAction();
      void executeR0ResumeThreadAction();
      void executeSuspendDriverThreadAction();
      void executeResumeDriverThreadAction();
      void executeTerminateDriverThreadAction(unsigned long terminateMethod);
      void executeExperimentalFirmwareRebootAction();
    void executeTerminateThreadAction();
    void executeR0TerminateThreadAction();
    void updateUsageSummaryInHeader(const std::vector<DisplayRow>& displayRows);

    // ======== 进程活动记录与时间轴 ========
    bool isProcessActivityMetricEnabled(ProcessActivityMetric metric) const;
    bool isProcessActivityRefreshAllowedNow() const;
    bool isProcessActivityRecordingAllowedNow() const;
    template <typename Destination, typename Source>
    static void copyProcessActivityDynamicFields(Destination& destination, const Source& source);
    void appendProcessActivitySample();
    void synchronizeDetailWindowPerformanceHistory(
        ProcessDetailWindow* detailWindow,
        const std::string& identityKey) const;
    void appendProcessActivitySampleToDetailWindows(const ProcessActivitySample& sample);
    bool trimProcessActivitySamples();
    void refreshProcessActivityTimeline(bool indexShiftedLeft = false);
    void refreshProcessActivityChart();
    void updateProcessActivityStatusLabel();
    void previewProcessActivitySnapshotForIndex(int sampleIndex);
    void showProcessActivitySnapshotForIndex(int sampleIndex);
    void commitProcessActivityTimelineIndex(int sampleIndex);
    // handleProcessWindowPickerRelease 作用：
    // - 接收“进程页准星拖拽拾取”释放坐标；
    // - 按窗口页同类逻辑命中鼠标下窗口并解析所属 PID；
    // - 设置进程列表筛选器为 PID，并打开对应进程详细信息窗口。
    // 参数 globalPos：鼠标释放时的全局屏幕坐标。
    // 返回值：无，失败时通过提示框和日志反馈。
    void handleProcessWindowPickerRelease(const QPoint& globalPos);
    bool isProcessActivityTableSnapshotActive() const;
    void rebuildProcessActivityTableSnapshotRecords();
    QString buildProcessActivitySnapshotText(int sampleIndex) const;
    std::vector<std::string> currentProcessActivitySelectionKeys() const;

    // ======== 进程控制动作 ========
    // executeTerminateProcessAction 作用：
    // - 执行“结束进程组合动作”；
    // - 固定顺序执行多种结束原理（TerminateProcess/Nt/WTS/Job/RestartManager/线程终止/调试器/Unmap 等）；
    // - 使用同一个 kLogEvent 串联整次调用链日志并判定目标是否真正退出。
    void executeTerminateProcessAction();
    // executeTerminateAndDeleteImageAction 作用：
    // - 仅允许一个具有完整 PID 创建时间与映像路径的目标；
    // - 结束前锁定同一文件对象，确认原进程退出后才设置删除状态。
    void executeTerminateAndDeleteImageAction();
    // executeTerminateProcessTreeAction 作用：
    // - 仅根据当前 R3 进程快照识别选中进程及其全部后代；
    // - 每个识别出的 PID 独立复用“结束进程组合动作”。
    void executeTerminateProcessTreeAction();
    // executeR0TerminateProcessAction 作用：
    // - 通过 R0 驱动 IOCTL 请求内核态结束目标进程；
    // - 成功/失败细节统一写入日志面板。
    void executeR0TerminateProcessAction();
    // executeR0TerminateProcessTreeAction 作用：
    // - 仅根据当前 R3 进程快照识别选中进程树；
    // - 对树中的每个 PID 单独提交现有结束进程 IOCTL。
    void executeR0TerminateProcessTreeAction();
    // executeR0SuspendProcessAction 作用：
    // - 通过 R0 驱动 IOCTL 请求内核态挂起目标进程；
    // - 成功/失败细节统一写入日志面板。
    void executeR0SuspendProcessAction();
    // executeR0SetPplProtectionAction 作用：
    // - 通过 R0 驱动 IOCTL 请求设置目标进程 PPL 保护层级；
    // - protectionLevel 使用单字节原生层级编码（Signer<<4 | Type）。
    void executeR0SetPplProtectionAction(std::uint8_t protectionLevel, const QString& levelDisplayText);
    // executeR0SetProcessHiddenAction：
    // - 作用：通过 R0 修改/恢复目标进程可见性；隐藏时由 visibilityFlags
    //   选择只改 UniqueProcessId、只摘 ActiveProcessLinks，或兼容旧版双操作。
    // - 参数 hidden：true=隐藏选中进程；false=取消隐藏选中进程。
    // - 参数 visibilityFlags：仅 hidden=true 时生效；恢复时忽略并按驱动记录还原。
    void executeR0SetProcessHiddenAction(bool hidden, unsigned long visibilityFlags = 0UL);
    // executeR0ClearProcessHiddenAction：
    // - 作用：恢复驱动内所有被 Ksword 修改 PID/摘链的进程，并刷新进程列表。
    void executeR0ClearProcessHiddenAction();
    // executeR0SetBreakOnTerminationAction：
    // - 作用：通过 R0 设置或清除 BreakOnTermination 关键进程标记。
    // - 参数 enabled：true=启用；false=关闭。
    void executeR0SetBreakOnTerminationAction(bool enabled);
    // executeR0DisableApcInsertionAction：
    // - 作用：通过 R0 清除目标进程现有线程 ApcQueueable 位。
    void executeR0DisableApcInsertionAction();
    // executeR0DkomRemoveFromCidTableAction：
    // - 作用：通过 R0 从 PspCidTable 删除目标进程 CID 表项。
    void executeR0DkomRemoveFromCidTableAction();
    // executeRefreshPplProtectionLevelAction 作用：
    // - 手动刷新当前可见进程的 PPL 保护级别枚举；
    // - 结果仅写入当前 UI 快照，不参与下一轮缓存复用。
    // 调用方式：进程列表右键菜单或详细视图手动刷新入口调用。
    // 参数：无。
    // 返回值：无。
    void executeRefreshPplProtectionLevelAction();
    // executeTerminateThreadsAction 作用：
    // - 单独执行 TerminateThread(全部线程)（保留给其他入口复用）；
    // - 与“结束进程组合动作”不同，该函数不包含 TerminateProcess 步骤。
    void executeTerminateThreadsAction();
    void executeSuspendAction();
    void executeResumeAction();
    void executeSetCriticalAction(bool enableCritical);
    void executeSetPriorityAction(int priorityActionId);
    // executeSetProcessIntegrityAction 作用：
    // - 输入：integrityRid 为 S-1-16-* Mandatory Label RID，levelDisplayText 为菜单显示文本；
    // - 处理：R0 内核 API 优先写 TokenIntegrityLevel，驱动不可用/旧驱动时回退 R3；
    // - 返回：无返回值，执行结果写入统一动作日志。
    void executeSetProcessIntegrityAction(unsigned long integrityRid, const QString& levelDisplayText);
    // executeSetEfficiencyModeAction 作用：开启/关闭 Windows 进程效率模式。
    void executeSetEfficiencyModeAction(bool enableEfficiencyMode);
    void executeOpenFolderAction();
    // executeOpenMemoryOperationAction 作用：跳转到内存页并附加当前进程，便于继续转储/查看区域。
    void executeOpenMemoryOperationAction();
    void executeFocusHandleAction();
    void executeFocusNetworkAction();
    void executeFocusWindowAction();
    // executeOpenMessageHooksAction：打开非模态窗口，展示作用于目标进程线程的消息 Hook。
    void executeOpenMessageHooksAction(const ks::process::ProcessRecord& targetRecord);

    // ======== 工具函数 ========
    std::string selectedIdentityKey() const;
    ks::process::ProcessRecord* selectedRecord();
    std::vector<ProcessActionTarget> selectedActionTargets() const;
    std::vector<ProcessActionTarget> processTreeActionTargets() const;
    void clearProcessTableSelection();
    void syncTrackedSelectionFromTable();
    QVariant processTableData(const ProcessTableRow& tableRow, int column, int role);
    const ProcessTableRow* processTableRowForViewIndex(const QModelIndex& viewIndex) const;
    QModelIndex processTableViewIndexForIdentityKey(const std::string& identityKey, int column) const;
    std::vector<QModelIndex> selectedProcessTableRowIndexes(bool includeCurrentFallback) const;
    ProcessActionTarget processActionTargetFromTableRow(const ProcessTableRow& tableRow) const;
    void appendProcessActionTargetsFromTableRow(
        const ProcessTableRow& tableRow,
        std::vector<ProcessActionTarget>& actionTargets,
        std::unordered_set<std::string>& visitedIdentitySet) const;
    void dispatchProcessActionTargetsInParallel(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets,
        const std::function<bool(const ProcessActionTarget&, std::string*)>& actionInvoker,
        bool refreshWhenAnySucceeded,
        bool forceAsyncWithTimeout = false,
        bool requireVerifiedProcessIdentity = false);
    void executeTerminateProcessActions(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets,
        bool deleteImageAfterExit = false);
    void executeR0TerminateProcessActions(
        const QString& actionTitle,
        const std::vector<ProcessActionTarget>& actionTargets);
    const ks::process::SystemThreadRecord* selectedThreadRecord() const;
    void bindContextActionToIndex(const QModelIndex& clickedIndex);
    void clearContextActionBinding();
    void bindThreadContextActionToItem(QTreeWidgetItem* clickedItem);
    void clearThreadContextActionBinding();
    bool threadRecordMatchesSearch(const ks::process::SystemThreadRecord& threadRecord) const;
    bool threadRecordMatchesScope(const ks::process::SystemThreadRecord& threadRecord) const;
    QString formatColumnText(const ks::process::ProcessRecord& processRecord, TableColumn column, int depth) const;
    QString formatThreadColumnText(const ks::process::SystemThreadRecord& threadRecord, ThreadTableColumn column) const;
    QString threadStateText(std::uint32_t stateValue) const;
    QString threadWaitReasonText(std::uint32_t waitReasonValue) const;
    QIcon resolveProcessIcon(const ks::process::ProcessRecord& processRecord);
    void queueProcessIconExtractionsForCurrentProcesses();
    void queueProcessIconExtraction(const QString& imagePath);
    void applyProcessIconExtractionResult(
        const QString& imagePath,
        QImage iconImage,
        std::uint64_t extractionGeneration);
    void refreshProcessTableRowsForIcon(const QString& imagePath);
    QIcon blueTintedIcon(const char* iconPath, const QSize& iconSize = QSize(16, 16)) const;
    // tintedProcessTabIcon 作用：按指定颜色重绘进程页 Tab 图标，避免选中态蓝底蓝图标。
    QIcon tintedProcessTabIcon(const char* iconPath, const QColor& tintColor, const QSize& iconSize = QSize(16, 16)) const;
    // refreshSideTabIconContrast 作用：刷新顶部 Tab 选中态图标颜色，提升当前页识别度。
    void refreshSideTabIconContrast();
    QString buildThreadContextMenuStyle() const;
    // showActionResultMessage 作用：统一记录进程动作结果日志（不弹窗），复用同一 kLogEvent 保持调用链连续。
    // 调用方式：在动作函数中创建 kLogEvent 后，将同一个事件对象传入本函数。
    // 参数 title：动作标题；actionOk：动作是否成功；detailText：动作详情；actionEvent：本次动作全链路事件对象。
    // 返回值：无。
    void showActionResultMessage(const QString& title, bool actionOk, const std::string& detailText, const kLogEvent& actionEvent);
    QObject* mainWindowActionReceiver() const;
    bool invokeMainWindowPidSlot(const char* methodName, std::uint32_t pid) const;
    bool invokeMainWindowPidListSlot(const char* methodName, const QString& pidListText) const;
    void connectDetailWindowNavigation(ProcessDetailWindow* detailWindow);
    ks::process::CreateProcessRequest buildCreateProcessRequestFromUi(bool* buildOk, QString* errorTextOut) const;
    // buildTokenPrivilegeEditRequestFromUi 作用：
    // - 只读取 Token 模式和特权表字段，不解析 CreateProcessW 其它输入；
    // - 用于“仅应用令牌调整”按钮，避免无关创建参数阻断调权操作；
    // - 返回值：true 表示 requestOut 已填充 Token 相关字段，false 表示 errorTextOut 保存失败原因。
    bool buildTokenPrivilegeEditRequestFromUi(ks::process::CreateProcessRequest* requestOut, QString* errorTextOut) const;
    void executeCreateProcessRequest();
    void executeApplyTokenPrivilegeEditsOnly();
    void appendCreateResultLine(const QString& lineText);
    void browseCreateProcessApplicationPath();
    void browseCreateProcessCurrentDirectory();
    void resetCreateProcessForm();
    void bindBitmaskEditor(QLineEdit* valueEdit, std::vector<QCheckBox*>* checkBoxList, const QString& fieldDisplayName);
    void syncEditValueFromBitmaskChecks(QLineEdit* valueEdit, const std::vector<QCheckBox*>* checkBoxList);
    void syncBitmaskChecksFromEditValue(QLineEdit* valueEdit, const std::vector<QCheckBox*>* checkBoxList, const QString& fieldDisplayName);
    static std::string buildRulerPrefix(int depth);
    static int toColumnIndex(TableColumn column);
    static int toThreadColumnIndex(ThreadTableColumn column);
    static bool parseUnsignedText(const QString& text, std::uint64_t& valueOut);
    static std::uint32_t parseUInt32WithDefault(const QString& text, std::uint32_t defaultValue, bool* parseOkOut = nullptr);
    static std::uint64_t parseUInt64WithDefault(const QString& text, std::uint64_t defaultValue, bool* parseOkOut = nullptr);
    static QSet<std::uint32_t> collectVisibleWindowPidSet();
    static std::uint32_t findFriendlyApplicationRootPid(
        std::uint32_t pid,
        const std::unordered_map<std::uint32_t, std::uint32_t>& parentPidByPid,
        const QSet<std::uint32_t>& visibleWindowPidSet);
    static bool isFriendlyWindowsSystemProcess(
        const ks::process::ProcessRecord& processRecord,
        const QString& normalizedWindowsDirectoryPath);
    static QString friendlyGroupTitle(FriendlyProcessGroupType groupType, int entryCount);
    // friendlyGroupTypeName 作用：
    // - 返回不含成员计数的分组短名，供任务管理器对齐的“类型”列逐行展示；
    // - 参数 groupType：行所属的友好分组；
    // - 返回：应用 / 后台进程 / Windows 进程文本。
    static QString friendlyGroupTypeName(FriendlyProcessGroupType groupType);
    static QString friendlyExpansionKeyForGroup(FriendlyProcessGroupType groupType);
    static QString friendlyExpansionKeyForApplication(std::uint32_t rootPid);
    static ks::process::ProcessRecord aggregateFriendlyApplicationRecord(
        const std::vector<const CacheEntry*>& applicationEntries,
        std::uint32_t rootPid);

    // ======== 后台线程核心函数（静态） ========
    static RefreshResult buildRefreshResult(
        int strategyIndex,
        bool detailModeEnabled,
        bool queryKernelProcessList,
        int staticDetailFillBudget,
        std::uint32_t detailDemandFlags,
        std::uint64_t refreshTicket,
        const std::unordered_map<std::string, CacheEntry>& previousCache,
        const std::unordered_map<std::string, ks::process::CounterSample>& previousCounters,
        const std::unordered_map<std::uint32_t, NetworkTrafficCounters>& networkTrafficSnapshot,
        std::uint32_t logicalCpuCount);

    // ======== 进程网络吞吐采样 ========
    void ensureProcessNetworkTrafficCaptureStarted();
    void stopProcessNetworkTrafficCapture();
    void pruneProcessNetworkTrafficCounters();
    std::unordered_map<std::uint32_t, NetworkTrafficCounters> snapshotProcessNetworkTrafficCounters() const;

    // ======== 进程/线程逐核心 CPU 采样 ========
    void ensureCpuCoreUsageCaptureStarted();
    void stopCpuCoreUsageCapture();
    void syncCpuCoreUsageToDetailWindow(
        ProcessDetailWindow* detailWindow,
        const ks::process::ProcessRecord& processRecord) const;

private:
    QPointer<QObject> m_mainWindowActionReceiver; // 构造时的 MainWindow 接收者，避免 ADS 重挂载后 parent() 变成 Dock 容器。

    // ======== 顶层布局 ========
    QVBoxLayout* m_rootLayout = nullptr;      // 根布局：只包含顶部 Tab。
    QTabWidget* m_sideTabWidget = nullptr;    // 顶部 tab 栏（North），包含四个进程功能页。
    QWidget* m_processListPage = nullptr;     // “进程列表”页容器。
    QVBoxLayout* m_processPageLayout = nullptr; // 进程页主布局。
    QWidget* m_createProcessPage = nullptr;   // “创建进程”页容器。
    QVBoxLayout* m_createProcessPageLayout = nullptr; // 创建页主布局。
    QWidget* m_threadPage = nullptr;          // “线程列表”页容器。
    QVBoxLayout* m_threadPageLayout = nullptr; // 线程页主布局。
    QWidget* m_crossViewPage = nullptr;       // “Cross-View”页容器。
    QVBoxLayout* m_crossViewPageLayout = nullptr; // Cross-View 页主布局。

    // ======== 控制栏 ========
    QHBoxLayout* m_controlLayout = nullptr;   // 上方“操作按钮”行布局。
    QComboBox* m_viewModeCombo = nullptr;     // 监视视图/详细视图下拉框。
    QPushButton* m_startButton = nullptr;     // 开始监视按钮。
    QPushButton* m_pauseButton = nullptr;     // 暂停监视按钮。
    QCheckBox* m_treeViewCheck = nullptr;     // 树状视图：默认关闭，关闭时展示应用/后台进程/系统分类。
    QLineEdit* m_processSearchLineEdit = nullptr; // 进程搜索框；用于按名称/PID/路径等关键词过滤当前列表。
    QLabel* m_refreshLabel = nullptr;         // 刷新间隔标签。
    QDoubleSpinBox* m_refreshIntervalSpin = nullptr; // 刷新、采样和表格重绘的统一间隔，0.5~60 秒，默认 1 秒。
    QPushButton* m_columnChooserButton = nullptr; // “选择列”按钮：打开添加/减少列对话框。

    // ======== 进程活动记录面板 ========
    QWidget* m_activityPanelWidget = nullptr;       // m_activityPanelWidget：进程活动图表面板。
    ProcessActivityChartWidget* m_activityChartWidget = nullptr; // m_activityChartWidget：时间轴百分比折线图。
    ProcessActivityTimelineSlider* m_activityTimelineSlider = nullptr; // m_activityTimelineSlider：隐藏内部时间轴，公开交互由折线图点击完成。
    QPushButton* m_activityClearButton = nullptr;   // m_activityClearButton：清空当前刷新记录缓存。
    QCheckBox* m_activityListOnlyRefreshCheck = nullptr; // 不记录历史开关：刷新列表但不写入活动记录。
    QPushButton* m_activityCpuButton = nullptr;     // CPU 指标显示按钮。
    QPushButton* m_activityMemoryButton = nullptr;  // 内存指标显示按钮。
    QPushButton* m_activityDiskButton = nullptr;    // 磁盘指标显示按钮。
    QPushButton* m_activityNetworkButton = nullptr; // 网络指标显示按钮。
    QPushButton* m_activityGpuButton = nullptr;     // GPU 指标显示按钮。
    QPushButton* m_activityProcessPickerButton = nullptr; // 准星拖拽按钮：按目标窗口 PID 过滤进程并打开进程详情。
    QLabel* m_activitySnapshotLabel = nullptr;      // 时间轴悬停快照摘要。
    bool m_activityRecordingEnabled = false;        // m_activityRecordingEnabled：由刷新状态派生，刷新即记录。
    bool m_activityTimelinePinnedToLatest = true;   // 时间轴在最右侧时自动吸附最新。
    bool m_activityTimelineSliderUpdating = false;  // 程序更新滑块时屏蔽用户态判定。
    int m_activityTableSnapshotIndex = -1;           // 下方进程表当前绑定的历史样本，-1 表示实时列表。
    std::uint64_t m_activityNextSequence = 0;       // 记录样本序号。
    std::uint64_t m_activityRecordingStartTick100ns = 0; // 本次记录开始 steady tick。
    double m_activityTotalPhysicalMemoryMB = 0.0;    // 物理内存总量，用于把内存指标转换为百分比。
    std::deque<ProcessActivitySample> m_activitySamples; // 有界双端记录缓存，淘汰旧样本时不搬移整个序列。
    std::vector<ks::process::ProcessRecord> m_activityTableSnapshotRecords; // 历史样本映射出的进程表记录。

    // ======== 进程表格 ========
    QTableView* m_processTable = nullptr;     // 进程列表表格视图（支持列拖动/排序/右键）。
    ProcessTableModel* m_processTableModel = nullptr; // 进程列表轻量模型，避免刷新时重建 item。
    QSortFilterProxyModel* m_processSortProxy = nullptr; // 进程列表排序代理，保持数值列排序行为。
    QHash<int, bool> m_userColumnVisibilityOverride; // 用户逐列显隐选择；键为列逻辑索引，缺省表示跟随视图默认。
    std::vector<ProcessCustomView> m_customViews;    // 用户自定义视图列表，持久化在 QSettings。
    bool m_viewModeComboUpdating = false;            // 程序重建下拉项期间屏蔽用户切换处理。
    std::uint32_t m_lastProcessDetailDemandFlags = 0; // 最近一次下发给后台刷新的按需采集位图，用于变更时立即重刷。
    QHash<QString, bool> m_friendlyExpandedStateByKey; // 友好视图分类/应用聚合行展开状态；缺省按展开处理。
    int m_friendlySortColumn = static_cast<int>(TableColumn::Name); // 友好视图内部排序列，默认按进程名 A-Z。
    Qt::SortOrder m_friendlySortOrder = Qt::AscendingOrder; // 友好视图内部排序方向，点击表头切换。
    bool m_friendlySortActive = false; // 是否已经点击表头排序；首次点击任意列固定使用升序。
    bool m_flatListForcedByHeaderSort = false; // 树状视图点表头后进入普通扁平枚举，不改变友好视图复选框。
    mutable std::vector<ks::process::ProcessRecord> m_friendlySyntheticRecords; // 友好视图合成标题/聚合行记录缓存。

    // ======== 线程页控件 ========
    QHBoxLayout* m_threadTopLayout = nullptr; // 线程页顶部操作栏。
    QPushButton* m_threadRefreshButton = nullptr; // 线程页刷新按钮（图标按钮）。
    QWidget* m_threadColumnPresetWidget = nullptr; // A/B 紧凑预设的相邻按钮容器。
    QHBoxLayout* m_threadColumnPresetLayout = nullptr; // 预设按钮零间距布局。
    QPushButton* m_threadColumnPresetAButton = nullptr; // A：调度概览列。
    QPushButton* m_threadColumnPresetBButton = nullptr; // B：地址/诊断列。
    QComboBox* m_threadScopeCombo = nullptr; // 全部 / System / ActiveExWorker 分类筛选。
    QLineEdit* m_threadSearchLineEdit = nullptr; // 线程页搜索框（按 TID/PID/名称过滤）。
    QTreeWidget* m_threadTable = nullptr;     // 线程列表表格（支持右键动作）。
    ThreadColumnLayout m_threadColumnLayout = ThreadColumnLayout::PresetA; // 当前高亮预设，默认 A。
    bool m_threadApplyingColumnLayout = false; // 程序应用预设时屏蔽 header 手动变化信号。

    // ======== Cross-View 页控件 ========
    QHBoxLayout* m_crossViewTopLayout = nullptr; // Cross-View 顶部操作栏。
    QPushButton* m_crossViewRefreshButton = nullptr; // Cross-View 刷新按钮。
    QLineEdit* m_crossViewSearchEdit = nullptr; // Cross-View 全字段过滤框。
    QCheckBox* m_crossViewAnomalyOnlyCheck = nullptr; // 仅显示异常记录。
    QLabel* m_crossViewStatusLabel = nullptr; // Cross-View 查询状态。
    QTableWidget* m_processCrossViewTable = nullptr; // 进程来源矩阵表。
    QTableWidget* m_threadCrossViewTable = nullptr; // 线程来源矩阵表。
    CodeEditorWidget* m_crossViewDetailEdit = nullptr; // Cross-View 详情文本编辑器，只读。

    // ======== 创建进程页 - 通用参数 ========
    QComboBox* m_createMethodCombo = nullptr; // CreateProcessW / Token 路径。
    QLineEdit* m_applicationNameEdit = nullptr;
    QPushButton* m_applicationBrowseButton = nullptr;
    QCheckBox* m_useApplicationNameCheck = nullptr;
    QLineEdit* m_commandLineEdit = nullptr;
    QCheckBox* m_useCommandLineCheck = nullptr;
    QLineEdit* m_currentDirectoryEdit = nullptr;
    QPushButton* m_currentDirectoryBrowseButton = nullptr;
    QCheckBox* m_useCurrentDirectoryCheck = nullptr;
    QPlainTextEdit* m_environmentEditor = nullptr;
    QCheckBox* m_useEnvironmentCheck = nullptr;
    QCheckBox* m_environmentUnicodeCheck = nullptr;
    QCheckBox* m_inheritHandleCheck = nullptr;
    QLineEdit* m_creationFlagsEdit = nullptr;
    std::vector<QCheckBox*> m_creationFlagChecks; // dwCreationFlags 勾选集合。

    // ======== 创建进程页 - SECURITY_ATTRIBUTES ========
    QCheckBox* m_useProcessSecurityCheck = nullptr;
    QLineEdit* m_processSecurityLengthEdit = nullptr;
    QLineEdit* m_processSecurityDescriptorEdit = nullptr;
    QCheckBox* m_processSecurityInheritCheck = nullptr;
    QCheckBox* m_useThreadSecurityCheck = nullptr;
    QLineEdit* m_threadSecurityLengthEdit = nullptr;
    QLineEdit* m_threadSecurityDescriptorEdit = nullptr;
    QCheckBox* m_threadSecurityInheritCheck = nullptr;

    // ======== 创建进程页 - STARTUPINFOW ========
    QCheckBox* m_useStartupInfoCheck = nullptr;
    QLineEdit* m_siCbEdit = nullptr;
    QLineEdit* m_siReservedEdit = nullptr;
    QLineEdit* m_siDesktopEdit = nullptr;
    QLineEdit* m_siTitleEdit = nullptr;
    QLineEdit* m_siXEdit = nullptr;
    QLineEdit* m_siYEdit = nullptr;
    QLineEdit* m_siXSizeEdit = nullptr;
    QLineEdit* m_siYSizeEdit = nullptr;
    QLineEdit* m_siXCountCharsEdit = nullptr;
    QLineEdit* m_siYCountCharsEdit = nullptr;
    QLineEdit* m_siFillAttributeEdit = nullptr;
    QLineEdit* m_siFlagsEdit = nullptr;
    std::vector<QCheckBox*> m_startupFillAttributeChecks; // STARTUPINFO.dwFillAttribute 勾选集合。
    std::vector<QCheckBox*> m_startupFlagChecks; // STARTUPINFO.dwFlags 勾选集合。
    QLineEdit* m_siShowWindowEdit = nullptr;
    QLineEdit* m_siCbReserved2Edit = nullptr;
    QLineEdit* m_siReserved2PtrEdit = nullptr;
    QLineEdit* m_siStdInputEdit = nullptr;
    QLineEdit* m_siStdOutputEdit = nullptr;
    QLineEdit* m_siStdErrorEdit = nullptr;

    // ======== 创建进程页 - PROCESS_INFORMATION ========
    QCheckBox* m_useProcessInfoCheck = nullptr;
    QLineEdit* m_piProcessHandleEdit = nullptr;
    QLineEdit* m_piThreadHandleEdit = nullptr;
    QLineEdit* m_piPidEdit = nullptr;
    QLineEdit* m_piTidEdit = nullptr;

    // ======== 创建进程页 - Token 路径 ========
    QLineEdit* m_tokenSourcePidEdit = nullptr;
    QLineEdit* m_tokenDesiredAccessEdit = nullptr;
    QCheckBox* m_tokenDuplicatePrimaryCheck = nullptr;
    std::vector<QCheckBox*> m_tokenDesiredAccessChecks; // Token DesiredAccess 勾选集合。
    QTableWidget* m_tokenPrivilegeTable = nullptr;
    QPushButton* m_applyTokenPrivilegeButton = nullptr;
    QPushButton* m_resetTokenPrivilegeButton = nullptr;

    // ======== 创建进程页 - 操作与输出 ========
    QPushButton* m_launchProcessButton = nullptr;
    QPushButton* m_resetCreateFormButton = nullptr;
    QTextEdit* m_createResultOutput = nullptr;

    // ======== 刷新调度 ========
    QTimer* m_refreshTimer = nullptr;         // 周期刷新定时器。
    bool m_monitoringEnabled = true;          // 当前是否处于监视状态。
    bool m_refreshInProgress = false;         // 防止并发刷新的互斥标记。
    bool m_autoHideUnavailableR0Columns = false; // 当 R0 扩展整轮不可用时自动隐藏内核专属列。
    std::uint64_t m_refreshTicket = 0;        // 刷新请求序号（防乱序）。
    std::uint32_t m_logicalCpuCount = 1;      // CPU 核心数（CPU 百分比换算）。
    std::chrono::steady_clock::time_point m_lastRefreshStartTime{}; // 主线程记录的刷新开始时刻。
    std::chrono::steady_clock::time_point m_lastCpuCoreUsageSnapshotTime{}; // 最近一次逐核心矩阵结算投递时刻，独立限制为至少 1 秒。
    std::chrono::steady_clock::time_point m_lastProcessTableRebuildTime{}; // 最近一次进程表重绘时间。

    // ======== 数据缓存 ========
    std::unordered_map<std::string, CacheEntry> m_cacheByIdentity; // 进程缓存（PID+CreateTime）。
    std::unordered_set<std::string> m_affinityRestoreCompletedIdentityKeys; // 已成功恢复或明确无规则的进程实例。
    std::unordered_map<std::string, AffinityRestoreRetryState> m_affinityRestoreRetryByIdentity; // 暂时失败且等待重试的进程实例。
    std::unordered_map<std::string, ks::process::CounterSample> m_counterSampleByIdentity; // 差值样本。
    std::unique_ptr<ks::network::ProcessNetworkEtwMonitor> m_processNetworkTrafficService; // 进程页内部 ETW 网络累计器。
    bool m_processNetworkTrafficCaptureStarted = false; // ETW 采集器是否已经尝试启动。
    std::shared_ptr<ks::process::ProcessCpuCoreEtwMonitor> m_cpuCoreUsageService; // 单个系统级 CSwitch 会话；后台快照任务共享生命周期。
    bool m_cpuCoreUsageCaptureStarted = false; // UI 线程状态：本轮监视周期内是否已经投递启动。
    bool m_cpuCoreUsageStopInProgress = false; // UI 线程状态：异步 Stop/join 完成前禁止第二个会话。
    std::shared_ptr<std::atomic_bool> m_cpuCoreUsageCaptureDesired =
        std::make_shared<std::atomic_bool>(false); // 后台 Start 返回后读取的期望状态，解决快速开始/暂停竞态。
    std::shared_ptr<const ks::process::CpuCoreUsageSnapshot> m_latestCpuCoreUsageSnapshot; // 最近区间快照；UI 只交换共享指针，避免复制全量矩阵。
    QHash<QString, QIcon> m_iconCacheByPath;  // 进程图标缓存，避免重复提取。
    QHash<QString, QIcon> m_activityIconCacheByProcessKey; // 历史活动图标缓存：进程名+路径 -> 图标。
    QSet<QString> m_processIconPathsInFlight; // 已投递后台线程池、尚未回传结果的 EXE 路径集合。
    std::uint64_t m_processIconExtractionGeneration = 0; // 图标任务代次，暂停后使旧任务回传结果失效。
    QThreadPool m_processIconExtractionPool; // 专属图标线程池，避免大量 Shell 查询占满通用后台任务池。
    std::unordered_map<std::string, QPointer<ProcessDetailWindow>> m_detailWindowByIdentity; // 详情窗口缓存（同进程复用窗口）。
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> m_detailWindowLastSyncTimeByIdentity; // 详情窗口最近一次同步时间，避免每轮刷新都触发重型解析。
    std::string m_trackedSelectedIdentityKey; // 当前选中进程 identityKey；表格刷新重建后用于恢复高亮。
    std::vector<std::string> m_trackedSelectedIdentityKeys; // 多选进程 identityKey 集合；Ctrl 复选后用于刷新恢复。
    int m_trackedSelectedColumn = 0;          // 当前选中列索引；恢复 currentItem 时尽量保持用户焦点列。
    std::vector<ks::process::SystemThreadRecord> m_threadRecordList; // 线程页最近一次刷新结果缓存。
    std::unordered_map<std::string, ks::process::ThreadCounterSample> m_threadCounterSampleByIdentity; // 线程 CPU 差分基准。
    std::string m_threadDiagnosticText;       // 线程页最近一次刷新诊断文本。
    std::unordered_set<std::uint32_t> m_hiddenProcessPidSet; // 本会话已通过 R0 标记隐藏的 PID 集合。
    std::vector<ksword::ark::ProcessCrossViewEntry> m_processCrossViewCache; // R0 进程 cross-view 缓存。
    std::vector<ksword::ark::ThreadCrossViewEntry> m_threadCrossViewCache; // R0 线程 cross-view 缓存。
    ksword::ark::ProcessCrossViewResult m_lastProcessCrossViewResult; // 最近一次进程 cross-view 元信息。
    ksword::ark::ThreadCrossViewResult m_lastThreadCrossViewResult; // 最近一次线程 cross-view 元信息。
    bool m_crossViewRefreshInProgress = false; // Cross-View 后台查询互斥标记。
    std::uint64_t m_crossViewRefreshTicket = 0; // Cross-View 查询序号。

    // ======== 右键菜单绑定状态 ========
    std::string m_contextActionIdentityKey;      // 当前菜单动作绑定的 identityKey。
    ks::process::ProcessRecord m_contextActionRecord{}; // identity 在刷新中失效时的兜底副本。
    std::vector<ProcessActionTarget> m_contextActionRecords; // 右键菜单绑定的多选进程副本。
    bool m_hasContextActionRecord = false;
    bool m_contextMenuVisible = false;           // 菜单弹出期间用于冻结周期刷新。
    std::uint32_t m_threadContextActionTid = 0;  // 线程右键菜单绑定的 TID。
    std::uint32_t m_threadContextActionPid = 0;  // 线程右键菜单绑定的 PID。
    bool m_threadContextMenuVisible = false;     // 线程菜单弹出期间冻结线程刷新。

    // ======== 线程刷新调度 ========
    bool m_threadRefreshInProgress = false;      // 线程页是否存在进行中的后台刷新任务。
    std::uint64_t m_threadRefreshTicket = 0;     // 线程页刷新序号（用于丢弃过期结果）。
    bool m_initialRefreshScheduled = false;      // 首次显示时是否已安排首轮刷新。
};
