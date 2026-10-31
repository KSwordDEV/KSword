#pragma once

// ============================================================
// MemoryDock.h
// 作用：
// 1) 构建“内存”页面的完整多 Tab 交互界面；
// 2) 提供进程附加、模块查看、内存区域浏览、扫描、十六进制查看；
// 3) 提供断点、书签、R0 内存读写与内核可执行页扫描的基础能力。
// ============================================================

#include "../Framework.h"
#include "MemoryDock.ReadOnlyModels.h"
#include "../UI/AsyncCleanupRegistry.h"
#include "../UI/StructuredFieldView.h"
#include "../ArkDriverClient/ArkDriverTypes.h"
#include "../UI/KernelDisassemblyDialog.h" // ks::ui::DisassemblyRow：驱动读写页反汇编视图的行缓存需要完整类型。
#include "../UI/WindowPickerButton.h" // ks::ui::WindowPickerButton：十字准星拾取按钮，按值出现在成员指针里。
#include "../UI/MemoryWorkbench/WorkbenchContinuation.h"
#include "MemoryAccessBackend.h" // 访问后端枚举与 DDMA 会话：按值出现在成员与返回类型里。
#include "TamperDetectionPage.h" // ksword::memory_dock::TamperDetectionPage：按值出现在成员指针与模块同步调用里。

#include "../UI/PageNavigationCatalog.h"
#include <QVector>     // QVector：保存反汇编解码结果行。
#include <QWidget>

#include <atomic>      // std::atomic：扫描取消标志、并发状态标志。
#include <condition_variable> // std::condition_variable：等待已取消扫描线程退出。
#include <cstdint>     // std::uint32_t / std::uint64_t：PID、地址等固定宽度整数。
#include <functional>  // std::function：下拉框展开期间被推迟的 UI 提交。
#include <memory>      // std::shared_ptr：扫描任务状态在后台线程退出前保持有效。
#include <mutex>       // std::mutex：保护扫描任务计数。
#include <optional>    // std::optional：工作台插入点等"可能没有"的返回值。
#include <string>      // std::string：日志与 Win32 调用时的字符串桥接。
#include <vector>      // std::vector：缓存进程/模块/区域/扫描结果。

// Qt 前置声明：尽量减少头文件编译依赖。
class QAction;
class QCheckBox;
class QComboBox;
class QEvent;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPoint;
class QProgressBar;
class QPushButton;
class QSplitter;
class QSpinBox;
class QStackedWidget;
class QStatusBar;
class QTableWidget;
class QTabWidget;
class QTextEdit;
class QTimer;
class QToolButton;
class QTreeWidget;
class QVBoxLayout;
class CodeEditorWidget;
class SystemMemoryAuditPage;
class DdmaPage;

namespace ks::misc
{
    class HvciBypassPage;
    class RxpfPage;
}

// 项目内 UI 组件前置声明：只用指针，避免把表格组件头拉进本头文件。
namespace ks::ui
{
    class AsyncOperation; // 区域转储后台任务：只持值请求并支持关窗取消。
    class StructuredFieldView;
    class VisibleTableWidget;
    class MemoryWorkbenchView; // 内存工作台视图：懒创建，只用指针。
    class MemoryDebugPage;     // 不附加内存调试页：独立于 Dock 的目标会话。
    struct NavRequest;         // 工作台跳转请求：navigateWorkbench 的参数类型。
}

// Windows 句柄类型前置声明。
typedef void* HANDLE;

// ============================================================
// MemoryDock
// 说明：
// - 该类负责整个“内存页”的 UI 与业务逻辑；
// - 所有函数都在 cpp 中附带详细注释，便于后续维护。
// ============================================================
class MemoryDock final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化全部 UI、连接信号槽、加载初始进程列表。
    // - 参数 parent：Qt 父控件指针，可为空。
    enum class PageScope { Main, ProcessDetail };
    explicit MemoryDock(QWidget* parent = nullptr, PageScope scope = PageScope::Main);

    // 析构函数：
    // - 作用：在控件销毁前释放进程句柄、停止定时器与后台扫描状态。
    ~MemoryDock() override;

    // The existing host status worker publishes actual window observations;
    // DDMA broadcasts never request HVM IO. Hidden pages consume no polling.
    bool needsHvmMemoryAvailability() const;
    quint64 hvmMemoryAvailabilityEpoch() const;
    void invalidateHvmMemoryAvailability();
    void applyHvmMemoryAvailability(quint64 epoch, bool usable, const QString& reason);
    std::function<void()> requestHvmMemoryAvailability;

    // focusProcessForOperations：
    // - 作用：从进程页跳转到内存页后自动定位并附加目标 PID；
    // - 调用方式：MainWindow::focusMemoryDockByPid 调用。
    void focusProcessForOperations(std::uint32_t pid, bool showMessage = false, ks::ui::LeaveCompletion completion = {});

    // focusProcessForSearch：
    // - 作用：附加指定 PID 后切换到“内存搜索”页；
    // - 供进程详情的独立“内存扫描”Tab 复用完整搜索能力。
    void focusProcessForSearch(std::uint32_t pid, bool showMessage = false);

    // ProcessMemoryDestination：模块跨页操作的落点，复用工作台、区域表和搜索参数页。
    enum class ProcessMemoryDestination { Workbench, Regions, Search };
    // openProcessMemoryRange：按 PID/创建时间核验后附加同一进程实例并定位地址。
    // address/size 固定调用方模块范围；Search 只预填参数，不发起扫描。
    // completion 在同步或异步附加及页面准备结束后仅调用一次，false 表示拒绝或失败。
    void openProcessMemoryRange(std::uint32_t pid, std::uint64_t creationTime,
        std::uint64_t address, std::uint64_t size, ProcessMemoryDestination destination,
        ks::ui::LeaveCompletion completion = {});

    // setProcessDetailMemoryScope：
    // - 供进程详情窗口内嵌时使用；
    // - 仅保留进程与模块、内存区域、内存搜索、内存工作台四个页面。
    void setProcessDetailMemoryScope();

    // focusDdmaPage：
    // - 作用：把当前 Tab 切到 DDMA 子页；
    // - 调用方式：MainWindow::focusMemoryDockDdmaPage（右上角 DDMA 指示灯点击）。
    void focusDdmaPage();

    // confirmWorkbenchQuit：
    // - 作用：主窗口关闭前问一次内存工作台（暂存的未提交补丁、未还原的 int3 补丁）；
    // - 调用方式：MainWindow::closeEvent 最前调用（其后半段会停 R0 驱动，晚了 int3 还原必失败）；
    // - Completed 才允许退出；Pending 保留原关闭请求并异步回报许可；Rejected/Busy 放弃本次关闭。
    ks::ui::LeaveEntryStatus confirmWorkbenchQuit(ks::ui::LeaveCompletion completion = {});
    // 全局退出拆成许可和释放两阶段；详情窗仍使用上面的单宿主兼容包装。
    ks::ui::LeaveEntryStatus prepareWorkbenchQuit(ks::ui::LeaveCompletion completion = {});
    bool releaseWorkbenchExecutionForQuit();
    bool workbenchQuitPreparationCurrent();
    // 全局退出被取消时，撤销这次退出专用的保留补丁许可。
    void cancelWorkbenchQuit();

    // canOpenInWorkbench：
    // - 作用：内存工作台当前是否可用（整体开关开启、页签已创建）；
    // - 调用方式：各证据页的右键菜单据此决定是否提供"在内存工作台打开"。
    bool canOpenInWorkbench() const;

    // openAddressInWorkbench：
    // - 作用：切到内存工作台页签并跳到指定地址（证据页右键"在内存工作台打开"的落点）；
    // - 参数 address：目标地址；
    // - 参数 kernelAddress：true=内核虚拟地址（切到内核范围），false=本 Dock 附加进程的地址
    //   （工作台跟随 Dock；若它钉在别的进程上会被带回跟随）；
    // - 返回：true=已跳转；false=工作台不可用或被拒绝（原因在工作台状态条里）。
    bool openAddressInWorkbench(std::uint64_t address, bool kernelAddress = false);

    // requestDumpProcessModule：进程 DLL 菜单复用区域导出的异步、取消与原子保存流程。
    // 输入 PID/创建时间固定进程实例，moduleBase/moduleSize 固定完整映像范围，moduleName 仅供命名。
    // backend 必须为 R3/R0；输出原始内存布局 .bin，不重建 PE，不补零或保留失败的部分文件。
    void requestDumpProcessModule(
        std::uint32_t pid,
        std::uint64_t creationTime,
        std::uint64_t moduleBase,
        std::uint64_t moduleSize,
        const QString& moduleName,
        ksword::memory_backend::MemoryAccessBackend backend);
    // prepareNavigationPages：按需准备工作台与内存调试页的真实控件树，供全局导航索引。
    // singleStep limits full search preparation to one existing page factory.
    // Complete cold bodies can skip an unvisited factory; compatibility callers
    // keep the original default that prepares actual controls.
    bool prepareNavigationPages(bool currentPageOnly = false, bool singleStep = false, bool useColdBodies = false);
    static ks::ui::PageNavigationCatalog navigationCatalog(const MemoryDock* existing = nullptr,
        bool includeColdSearchBody = true);
    QWidget* activateNavigationDescriptor(const QString& id);
    std::function<void(const QString&)> openPoolModuleDetails;

protected:
    // changeEvent：
    // - 作用：在应用调色板变化时重新下发使用语义色的样式；
    // - 参数 eventObject：Qt 传入的事件对象；
    // - 说明：语义色 token 是调用瞬间的快照，不随主题自动更新，必须在这里重下发。
    void changeEvent(QEvent* eventObject) override;

private:
    // applyMemoryDockSemanticStyles：
    // - 作用：给危险操作按钮与状态栏标签下发语义色样式。
    // - 说明：构造期与主题切换共用这一条路径，保证深浅色切换后颜色不会停在旧主题。
    // - 返回：无；控件尚未创建时逐个跳过。
    void applyMemoryDockSemanticStyles();

private:
    // ========================================================
    // 内部数据结构定义（用于表格缓存与跨 Tab 共享状态）
    // ========================================================

    // ProcessEntry：
    // - 作用：保存单个进程行展示所需的数据。
    struct ProcessEntry
    {
        std::uint32_t pid = 0;          // 进程 PID。
        std::uint64_t creationTime100ns = 0; // 同一枚举快照的进程强身份。
        std::uint32_t sessionId = 0;    // 会话 ID。
        QString processName;            // 进程名。
        // CPU 占用率。需要两次采样相减才算得出，所以"这一轮算不出来"是一个真实
        // 且常见的状态（首次刷新、进程刚启动、权限不足取不到 CPU 时间）。用独立
        // 的 valid 位表示，不拿 0.0 当哨兵——0% 是一个完全合法的占用率，两者混同
        // 就等于把"不知道"显示成"空闲"。
        double cpuPercent = 0.0;
        bool cpuPercentValid = false;
        QString imagePath;
        int exactNameCount = 0, foldedNameCount = 0;
        double workingSetMB = 0.0;      // 工作集内存（MB）。
    };

    // ProcessCpuSample：上一轮的 CPU 采样，按 PID 保存，用于算增量。
    struct ProcessCpuSample
    {
        std::uint64_t cpuTime100ns = 0;
        std::uint64_t sampleTime100ns = 0;
        std::uint64_t creationTime100ns = 0;
    };

    // ModuleEntry：
    // - 作用：保存模块表格每一行的数据。
    struct ModuleEntry
    {
        QString moduleName;                     // 模块文件名（路径末尾）。
        QString fullPath;                       // 模块完整路径。
        std::uint64_t baseAddress = 0;          // 模块基址（用于跳转与复制）。
        std::uint64_t sizeBytes = 0;            // 模块大小（字节）。
        QString signatureState;                 // 数字签名状态文本（Signed/Unknown/...）。
        bool signatureTrusted = false;          // 签名是否可信（用于上色）。
        std::uint64_t entryPointOffset = 0;     // 入口点偏移（RVA）。
        QString runningState;                   // 运行状态文本（Running/Suspended/...）。
        QString threadIdText;                   // 代表线程 ID 文本（可能包含多个）。
        std::uint32_t representativeThreadId = 0; // 代表线程 ID（数值动作入口）。
    };

    // RegionEntry：
    // - 作用：保存 VirtualQueryEx 枚举得到的内存区域信息。
    struct RegionEntry
    {
        std::uint64_t baseAddress = 0;  // 区域起始地址。
        std::uint64_t regionSize = 0;   // 区域大小（字节）。
        std::uint32_t protect = 0;      // 保护属性位（PAGE_*）。
        std::uint32_t state = 0;        // 状态（MEM_COMMIT / MEM_RESERVE / MEM_FREE）。
        std::uint32_t type = 0;         // 类型（MEM_IMAGE / MEM_MAPPED / MEM_PRIVATE）。
        QString mappedFilePath;         // 映射文件路径（如果可获取）。
    };

    // SearchValueType：
    // - 作用：定义扫描值的数据类型。
    enum class SearchValueType : int
    {
        Byte = 0,           // 1 字节整数。
        Int16,              // 2 字节整数。
        Int32,              // 4 字节整数。
        Int64,              // 8 字节整数。
        Float32,            // 单精度浮点。
        Float64,            // 双精度浮点。
        ByteArray,          // 字节数组（支持 ?? 通配）。
        StringAscii,        // ASCII 字符串。
        StringUnicode       // Unicode 字符串（UTF-16LE）。
    };

    // SearchCompareMode：
    // - 作用：定义再次扫描过滤条件。
    enum class SearchCompareMode : int
    {
        Equal = 0,          // 等于。
        Greater,            // 大于。
        Less,               // 小于。
        Between,            // 介于（当前值在 [A, B]）。
        Changed,            // 变化。
        Unchanged,          // 未变化。
        Increased,          // 增加。
        Decreased           // 减少。
    };

    // SearchResultEntry：
    // - 作用：保存扫描结果行。
    struct SearchResultEntry
    {
        std::uint64_t address = 0;      // 命中地址。
        QByteArray currentValueBytes;   // 当前值字节。
        QByteArray previousValueBytes;  // 上一轮值字节（再次扫描时有意义）。
        QString noteText;               // 备注文本（可由用户后续填充）。
    };

public:
    // ProcessMemoryEvidenceEntry：
    // - 作用：表示单个虚拟地址的 PTE / 工作集 / 风险证据。
    // - 说明：同时服务 Tab9 / Tab10 的只读展示。
    struct ProcessMemoryEvidenceEntry
    {
        std::uint64_t virtualAddress = 0;   // 虚拟地址。
        std::uint64_t regionBaseAddress = 0; // 区域基址。
        std::uint64_t regionSize = 0;       // 区域大小。
        std::uint32_t protect = 0;          // VirtualQueryEx 保护位。
        std::uint32_t state = 0;            // VirtualQueryEx 状态。
        std::uint32_t type = 0;             // VirtualQueryEx 类型。
        std::uint32_t win32Protection = 0;  // QueryWorkingSetEx 保护位。
        std::uint32_t shareCount = 0;       // 共享计数。
        std::uint32_t node = 0;             // NUMA 节点号。
        bool valid = false;                 // WorkingSet 是否有效。
        bool shared = false;                // WorkingSet 是否共享。
        bool locked = false;                // WorkingSet 是否锁定。
        bool largePage = false;             // WorkingSet 是否大页。
        bool bad = false;                   // WorkingSet 是否坏页。
        QString mappedFilePath;             // 映射文件路径。
        QString riskText;                   // 风险摘要。
        QString detailText;                 // 详情文本。
    };

private:
    // ParsedSearchPattern：
    // - 作用：保存扫描输入解析结果，避免线程内重复解析字符串。
    struct ParsedSearchPattern
    {
        SearchValueType valueType = SearchValueType::Byte; // 数据类型。
        QByteArray exactBytes;         // 精确匹配字节。
        QByteArray wildcardMask;       // 通配掩码（ByteArray 模式使用，1=有效，0=通配）。
        double lowerBound = 0.0;       // 数值下界（Between 或浮点误差比较使用）。
        double upperBound = 0.0;       // 数值上界。
        double epsilon = 0.00001;      // 浮点误差阈值。
    };

private:
    // ========================================================
    // UI 初始化与连接函数
    // ========================================================

    // initializeUi：
    // - 作用：初始化根布局、工具栏、Tab 区域与状态栏。
    // - 返回：无。
    void initializeUi();

    // initializeToolbar：
    // - 作用：初始化顶部全局工具栏。
    // - 返回：无。
    void initializeToolbar();

    // initializeTabs：
    // - 作用：初始化全部 MemoryDock Tab 页。
    // - 返回：无。
    void initializeTabs();
    struct PageFactory;
    static const std::vector<PageFactory>& pageFactories();
    struct LazyPage { QString id; QWidget* widget = nullptr; bool ready = false, constructing = false; };
    std::vector<LazyPage> m_lazyPages;
    bool m_pageConnectionsReady = false;
    QWidget* ensureLazyPage(const QString& id);
    void ensureCurrentLazyPage();
    void initializeProcessConnections();
    void initializeRegionConnections();
    void initializeSearchConnections();
    void initializeKernelExecutableConnections();
    void initializeKernelEvidenceConnections();
    void initializePteConnections();
    void initializeProcessEvidenceConnections();
    void initializeHvciBypassTab();
    void initializeRxpfTab();

    // initializeProcessModuleTab：
    // - 作用：构建 Tab1（进程与模块）界面。
    // - 返回：无。
    void initializeProcessModuleTab();

    // initializeMemoryRegionTab：
    // - 作用：构建 Tab2（内存区域）界面。
    // - 返回：无。
    void initializeMemoryRegionTab();

    // initializeMemorySearchTab：
    // - 作用：构建 Tab3（内存搜索）界面。
    // - 返回：无。
    void initializeMemorySearchTab();

    // initializeKernelExecutableMemoryScanTab：
    // - 作用：构建 Tab7（内核可执行页扫描）界面。
    // - 返回：无。
    void initializeKernelExecutableMemoryScanTab();

    // initializeKernelMemoryEvidenceTab：
    // - 作用：构建 Tab8（内核内存证据）界面。
    // - 处理逻辑：只创建只读查询入口、结果表和详情区，所有 R0 访问交给 ArkDriverClient。
    // - 返回：无。
    void initializeKernelMemoryEvidenceTab();

    // initializeProcessPteTranslateTab：
    // - 作用：构建 Tab9（PTE / VA 翻译）界面。
    // - 处理逻辑：只读取当前附加进程的工作集 / 虚拟内存属性，不提供任何写入动作。
    // - 返回：无。
    static QVector<ks::ui::PageSearchBodyText> coldProcessPteSearchBody();
    static QVector<ks::ui::PageSearchBodyText> coldMemorySearchBody();
    void initializeProcessPteTranslateTab();

    // initializeProcessMemoryEvidenceTab：
    // - 作用：构建 Tab10（进程内存证据）界面。
    // - 处理逻辑：以 VirtualQueryEx / QueryWorkingSetEx 为基础整理只读证据。
    // - 返回：无。
    void initializeProcessMemoryEvidenceTab();

    // initializeSystemMemoryAuditTab：
    // - 作用：构建 Tab11（系统内存审计）界面；
    // - 处理逻辑：聚合物理分布、内核进程快照、Pool Tag 与 Big Pool 证据。
    void initializeSystemMemoryAuditTab();

    // ensureSystemMemoryAuditPage：
    // - 作用：首次切入系统内存审计 Tab 时，把轻量占位页替换为真实页面；
    // - 约束：保持原 Tab 索引、标题、语言绑定和 DDMA 会话接线。
    void ensureSystemMemoryAuditPage();

    // initializeDdmaTab：
    // - 作用：构建 Tab12（DDMA）界面；
    // - 处理逻辑：页面自身负责通道配置，本函数只负责挂载与注册会话变化回调。
    void initializeDdmaTab();

    // initializeTamperDetectionTab：
    // - 作用：挂载“篡改检测”页，并把附加进程与模块列表同步给它。
    void initializeTamperDetectionTab();


    // createBackendSelector：
    // - 作用：创建一个统一样式的"访问后端"下拉框；
    // - 参数 parent：父控件；
    // - 参数 comboOut/hintOut：输出下拉框与配套提示标签；
    // - 说明：三个页面共用这一个构造入口，条目顺序与 MemoryAccessBackend 一致，
    //   避免某个页面自己加一份顺序不同的下拉。
    QWidget* createBackendSelector(
        QWidget* parent,
        QComboBox*& comboOut,
        QLabel*& hintOut);

    // refreshBackendSelectors：
    // - 作用：DDMA 会话变化后刷新各页下拉框的可用性与提示文本；
    // - 说明：DDMA 不可用时不禁用下拉项，而是保留选项并在提示里说明缺哪一步，
    //   否则用户只会看到一个灰掉的选项，不知道要去哪里补配置。
    void refreshBackendSelectors();

    // currentSearchBackend：
    // - 作用：读取各页面当前选中的访问后端；
    // - 返回：控件缺失时一律使用 R3。
    ksword::memory_backend::MemoryAccessBackend currentSearchBackend() const;

    // currentDdmaSession：
    // - 作用：取 DDMA 页维护的会话配置；
    // - 返回：DDMA 页尚未创建时返回一个"未配置"的空会话。
    const ksword::memory_backend::DdmaSession& currentDdmaSession() const;

    // initializeConnections：
    // - 作用：统一连接各控件交互逻辑。
    // - 返回：无。
    void initializeConnections();

    // initializeStatusBar：
    // - 作用：初始化状态栏默认文本。
    // - 返回：无。
    void initializeStatusBar();

    // initializeWorkbenchLivenessTimer：
    // - 作用：初始化工作台目标存活核验定时器（默认 1 秒）。
    // - 返回：无。
    void initializeWorkbenchLivenessTimer();

private:
    // ========================================================
    // 进程与模块（Tab1）相关函数
    // ========================================================

    // refreshProcessList：
    // - 作用：重新枚举系统进程并刷新进程表/下拉框。
    // - 参数 keepSelection：是否尽量保持当前选中 PID。
    // - 返回：无。
    void refreshProcessList(bool keepSelection);

    // updateProcessComboFromCache：
    // - 作用：根据 m_processCache 重建顶部“进程选择”下拉框。
    // - 返回：无。
    void updateProcessComboFromCache();

    // isComboPopupVisible：
    // - 作用：判断单个下拉框是否处在弹层生命周期中；
    // - 参数 comboBox：待检查的下拉框，可为空；
    // - 返回：true 表示弹层正在显示、动画过渡或尚未完成收尾。
    bool isComboPopupVisible(QComboBox* comboBox) const;

    // isProcessComboPopupOpen：
    // - 作用：判断任一“按进程缓存重建”的下拉框弹层是否正在展开；
    // - 说明：顶部进程框与 R0 读写页的目标进程框共用同一份进程缓存，
    //   一次回填会同时重建两者，因此任一展开都必须推迟提交；
    // - 返回：true 表示弹层可见，此时重建下拉框会让弹层挂住鼠标抓取，界面变得点不动。
    bool isProcessComboPopupOpen();

    // deferCommitWhileProcessComboPopupOpen：
    // - 作用：弹层展开期间缓存最新一次进程列表提交，等收起后再落地；
    // - 参数 commitAction：完整的进程缓存/表格/下拉框提交动作；
    // - 返回：true 表示已缓存，调用方应立即返回；false 表示可以直接提交。
    bool deferCommitWhileProcessComboPopupOpen(std::function<void()> commitAction);

    // flushProcessComboDeferredCommit：
    // - 作用：弹层收起后执行被缓存的最新提交；
    // - 返回：无。弹层又被打开时保持缓存继续等待。
    void flushProcessComboDeferredCommit();

    // refreshModuleListForPid：
    // - 作用：按 PID 枚举模块并刷新模块列表。
    // - 参数 pid：目标进程 PID。
    // - 返回：true 表示枚举成功；false 表示失败。
    bool refreshModuleListForPid(std::uint32_t pid);
    void startPendingModuleRefresh();
    void pollModuleRefresh();

    // rebuildModuleTableFromCache：
    // - 作用：按当前过滤条件把 m_moduleCache 重绘到模块表。
    // - 说明：该函数只做“缓存 -> UI”投影，不做 Win32 枚举。
    // - 返回：无。
    void rebuildModuleTableFromCache();
    enum class CoreKind { Modules, Regions, Processes, KernelExecutable, KernelEvidence, PteEvidence, ProcessEvidence, SearchResults };
    struct PreparedProcessSnapshot;
    static void prepareProcessSnapshot(const std::shared_ptr<PreparedProcessSnapshot>& prepared);
    void commitProcessSnapshot(const std::shared_ptr<PreparedProcessSnapshot>& prepared, std::uint64_t generation, std::uint32_t previousPid);
    struct CoreProjectionData {
        CoreKind kind;
        std::shared_ptr<const std::vector<ProcessEntry>> processes;
        std::shared_ptr<const std::vector<ModuleEntry>> modules;
        std::shared_ptr<const std::vector<RegionEntry>> regions;
        QString filter, languageId, statusTemplate;
        ks::i18n::SourceTextSnapshot language;
        std::uint32_t pid = 0;
        std::uint64_t target = 0, localeGeneration = 0;
        bool committed = false, image = false, readable = false;
        int sortColumn = 0;
        Qt::SortOrder sortOrder = Qt::AscendingOrder;
        std::shared_ptr<std::vector<std::size_t>> rows;
        std::shared_ptr<const void> extraSource;
        std::size_t extraCount = 0;
        bool extraRisk = false;
        bool extraDiagnosticRow = true;
        QString extraDiagnostic;
        std::function<bool(std::size_t)> extraMatches;
        std::function<QString(std::size_t)> extraKey;
        std::function<QVariant(std::size_t, int, int)> extraCell;
        QString selectedKey;
        int selectedRow = -1, selectedColumn = 0;
    };
    MemoryTableView* extraCoreTable(CoreKind kind) const;
    void captureKernelExecutableProjection(CoreProjectionData& data) const;
    void captureKernelMemoryProjection(CoreProjectionData& data) const;
    void capturePteProjection(CoreProjectionData& data) const;
    void captureProcessEvidenceProjection(CoreProjectionData& data) const;
    void captureSearchResultProjection(CoreProjectionData& data) const;

    struct CoreProjectionJob;
    struct RegionRefreshJob;
    void initializeCoreProjection(CoreKind kind);
    void requestCoreProjection(CoreKind kind, bool debounce = false);
    void pollCoreProjection();
    void publishCoreProjection(const std::shared_ptr<CoreProjectionData>& data);
    std::shared_ptr<CoreProjectionData> captureCoreRequest(CoreKind kind) const;
    static bool sameCoreRequest(const CoreProjectionData& left, const CoreProjectionData& right);
    static QString coreRowKey(const CoreProjectionData& data, std::size_t row);
    static QVariant coreCell(const CoreProjectionData& data, std::size_t row, int column, int role);
    static void buildCoreProjection(const std::shared_ptr<CoreProjectionJob>& job);
    bool coreProjectionIsCurrent(CoreKind kind) const;
    void startPendingRegionRefresh();
    void pollRegionRefresh();
    void cancelCoreProjection(bool closing);

    // syncTamperDetectionTargets：
    // - 作用：把当前附加进程与模块列表同步给“篡改检测”页；
    // - 说明：附加成功与模块缓存落地两处都要调用。少了任一处，那一页的目标下拉
    //   就会停在上一个进程的模块上——而它会照样跑，只是扫的是别的进程的地址。
    void syncTamperDetectionTargets();
    static std::shared_ptr<const ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot> prepareTamperModuleCandidates(const std::vector<ModuleEntry>& modules);

    // applyProcessTableFilter：
    // - 作用：按 m_processFilterEdit 的关键字隐藏/显示进程表的行，并更新计数标签；
    // - 说明：只隐藏行、不重建表格。重建会丢掉当前选中行，也会和后台刷新的
    //   增量回填（图标是异步补进来的）打架。
    void applyProcessTableFilter();

    // attachToProcess：
    // - 作用：附加目标进程并缓存句柄。
    // - 参数 pid：目标 PID。
    // - 参数 processName：目标进程名（用于状态栏展示）。
    // - 参数 showMessage：是否弹出提示框反馈结果。
    // - 返回：true 附加成功；false 附加失败。
    // openFailure 只在实际 OpenProcess 的读写、只读尝试均失败时调用；取消/忙/身份变化不触发。
    using ProcessOpenFailure = std::function<void(std::uint32_t)>;
    ks::ui::LeaveEntryStatus attachToProcess(std::uint32_t pid, const QString& processName, bool showMessage,
        ks::ui::LeaveCompletion completion = {}, ProcessOpenFailure openFailure = {});
    bool attachToProcessAfterLeave(std::uint32_t pid, const QString& processName, bool showMessage,
        std::uint64_t expectedCreateTime, ProcessOpenFailure openFailure = {});
    bool m_workbenchProcessChangePending = false;

    // detachProcess：
    // - 作用：分离当前进程并清理依赖该句柄的数据。
    // - 返回：无。
    void detachProcess();

    // openProcessHandleForRead：
    // - 作用：按 PID 打开进程句柄（读/查询权限）。
    // - 参数 pid：目标 PID。
    // - 参数 errorTextOut：失败时输出错误文本（可空）。
    // - 返回：成功返回有效 HANDLE；失败返回 nullptr。
    HANDLE openProcessHandleForRead(std::uint32_t pid, QString* errorTextOut = nullptr) const;

    // duplicateAttachedProcessHandleForWorker：
    // - 作用：为后台只读任务复制当前附加进程句柄，避免任务继续使用可被 UI 线程关闭/复用的原句柄。
    // - 参数 errorCodeOut：失败时输出 Win32 错误码（可空）。
    // - 返回：成功返回自动关闭的独立句柄租约；失败返回空 shared_ptr。
    std::shared_ptr<void> duplicateAttachedProcessHandleForWorker(std::uint32_t* errorCodeOut = nullptr) const;

    // showProcessTableContextMenu：
    // - 作用：展示进程列表右键菜单（附加 / Dump 内存）。
    // - 参数 localPosition：鼠标在进程表 viewport 内的坐标。
    // - 返回：无。
    void showProcessTableContextMenu(const QPoint& localPosition);

    // requestDumpProcessMemoryByPid：
    // - 作用：选择 R3/R0/HVM 后端，捕获进程身份并异步执行内存转储。
    // - 参数 pid：要转储的目标进程 PID。
    // - 参数 processName：目标进程名（用于默认文件名和提示）。
    // - 返回：无。
    void requestDumpProcessMemoryByPid(std::uint32_t pid, const QString& processName);

    // dumpProcessMemoryToFile：
    // - 作用：执行真正的内存区域遍历与文件写入。
    // - 参数 pid / processHandle / creationTime：UI 线程捕获的目标身份及独立句柄租约。
    // - 参数 backend：本次导出固定使用的 R3/R0/HVM 读取后端。
    // - 参数 dumpFilePath：输出文件路径。
    // - 参数 progressPid：UI 线程捕获的进度任务编号。
    // - 参数 errorTextOut：失败时输出错误信息。
    // - 返回：true=成功；false=失败。
    static bool dumpProcessMemoryToFile(
        std::uint32_t pid,
        const std::shared_ptr<void>& processHandle,
        std::uint64_t creationTime,
        ksword::memory_backend::MemoryAccessBackend backend,
        const QString& dumpFilePath,
        int progressPid,
        QString& errorTextOut);

private:
    // ========================================================
    // 内存区域（Tab2）相关函数
    // ========================================================

    // refreshMemoryRegionList：
    // - 作用：刷新内存区域缓存并应用过滤展示。
    // - 参数 forceRequery：是否强制重新调用 VirtualQueryEx。
    // - 返回：无。
    void refreshMemoryRegionList(bool forceRequery);
    void requestFirstScanRegions();

    // applyPendingModuleRegionFocus：区域异步模型发布后定位模块地址；不扫描或重建业务数据。
    void applyPendingModuleRegionFocus();
    struct ModuleRegionFocus
    {
        std::uint64_t address = 0; // 要显示的模块地址。
        std::uint64_t attachmentGeneration = 0; // 只允许当前附加上下文消费请求。
    };
    std::optional<ModuleRegionFocus> m_pendingModuleRegionFocus;
    std::uint64_t m_processMemoryNavigationGeneration = 0; // 后到跨页请求使旧异步回调失效。

    // requestDumpMemoryRegion：菜单前冻结进程句柄/创建时间和区域，选择路径后异步导出。
    // pid/processName 用于身份和提示；targetProcess 为独立租约；region/backend 固定导出范围和通道。
    void requestDumpMemoryRegion(
        std::uint32_t pid,
        const QString& processName,
        const std::shared_ptr<void>& targetProcess,
        std::uint64_t creationTime,
        const RegionEntry& region,
        ksword::memory_backend::MemoryAccessBackend backend,
        bool moduleImage = false);

    // tryCancelMemoryRegionDump：提交前原子接受取消；已进入提交阶段时返回 false。
    bool tryCancelMemoryRegionDump();

    // RegionDumpPhase：取消与原子发布共用的值状态，后台不借用页面指针。
    enum class RegionDumpPhase { Reading, CancelRequested, Committing, Committed, Failed };

    // dumpMemoryRegionToFile：后台只读分块导出原始字节，失败/取消不替换已有文件。
    // 输入固定身份、区域、后端、输出路径、进度编号及取消探针；失败写入内部原因码和详情。
    static bool dumpMemoryRegionToFile(
        std::uint32_t pid,
        const std::shared_ptr<void>& targetProcess,
        std::uint64_t creationTime,
        const RegionEntry& region,
        ksword::memory_backend::MemoryAccessBackend backend,
        const QString& dumpFilePath,
        int progressPid,
        const std::function<bool()>& canceled,
        QString& errorTextOut,
        const std::function<bool()>& beginCommit = {},
        const std::function<void(std::uint64_t, std::uint64_t)>& progress = {},
        bool moduleImage = false);

    // enumerateMemoryRegionsByVirtualQuery：
    // - 作用：对附加进程执行 VirtualQueryEx 遍历。
    // - 参数 processHandle：目标进程句柄。
    // - 参数 regionsOut：输出区域数组（调用前会清空）。
    // - 参数 errorTextOut：失败信息输出（可空）。
    // - 返回：true 成功；false 失败。
    bool enumerateMemoryRegionsByVirtualQuery(
        HANDLE processHandle,
        std::vector<RegionEntry>& regionsOut,
        QString* errorTextOut = nullptr) const;

    // applyRegionFilterAndRebuildTable：
    // - 作用：按复选框条件过滤区域并重建 Tab2 表格。
    // - 返回：无。
    void applyRegionFilterAndRebuildTable();

private:
    // ========================================================
    // 内存搜索（Tab3）相关函数
    // ========================================================

    // parseSearchPatternFromUi：
    // - 作用：把 UI 输入解析成可执行扫描的结构体。
    // - 参数 patternOut：输出解析结果。
    // - 参数 errorTextOut：解析失败时输出错误原因。
    // - 返回：true 解析成功；false 解析失败。
    bool parseSearchPatternFromUi(
        ParsedSearchPattern& patternOut,
        QString& errorTextOut) const;

    // collectSearchRegionsFromUi：
    // - 作用：根据“范围选项/过滤选项”确定扫描区域集合。
    // - 参数 regionsOut：输出区域数组。
    // - 参数 errorTextOut：失败原因文本。
    // - 返回：true 成功；false 失败。
    struct FirstScanOptions {
        bool custom = false, image = false, heap = false, stack = false;
        std::uint64_t start = 0, end = UINT64_MAX, generation = 0;
        std::uint32_t pid = 0, threads = 1, chunkKB = 64;
        ksword::memory_backend::MemoryAccessBackend backend{};
        ksword::memory_backend::DdmaSession ddma;
    };
    bool captureFirstScanOptions(FirstScanOptions& options, QString& error) const;
    static bool filterFirstScanRegions(const FirstScanOptions& options, const std::vector<RegionEntry>& source, std::vector<RegionEntry>& rows, QString& error, const std::function<bool()>& cancelled);
    struct FirstScanPreparation;
    std::shared_ptr<FirstScanPreparation> m_firstScanPreparation;
    void acceptFirstScanRegionSnapshot(const std::shared_ptr<const std::vector<RegionEntry>>& rows, std::uint32_t error);
    void pollFirstScanPreparation();
    void finishFirstScanPreparation(const QString& error, bool cancelled = false);
    void cancelFirstScanPreparation();

    // startFirstScan：
    // - 作用：执行“首次扫描”。
    // - 返回：无。
    void startFirstScan();

    // startNextScan：
    // - 作用：执行“再次扫描”。
    // - 返回：无。
    void startNextScan();

    // resetScanState：
    // - 作用：重置扫描状态、清空结果表。
    // - 返回：无。
    void resetScanState();

    // cancelCurrentScan：
    // - 作用：设置扫描取消标志，后台线程会尽快停止。
    // - 返回：无。
    void cancelCurrentScan();

    // cancelMemoryScanTasks：
    // - 作用：请求所有内存扫描停止，解绑 UI 后由物理任务独立完成资源收尾。
    // - 返回：无。
    void cancelMemoryScanTasks();

    // rebuildSearchResultTable：
    // - 作用：按 m_searchResultCache 重建结果表格。
    // - 返回：无。
    void rebuildSearchResultTable();

    // scanMemoryRegionsInBackground：
    // - 作用：后台执行首次扫描并在完成后回主线程提交结果。
    // - 参数 scanRegions：本轮扫描区域。
    // - 参数 pattern：本轮匹配模式。
    // - 返回：无。
    void scanMemoryRegionsInBackground(
        std::vector<RegionEntry> scanRegions,
        const ParsedSearchPattern& pattern, const FirstScanOptions& options);

private:
    // ========================================================
    // 内存查看器（Tab4）相关函数
    // ========================================================

    // jumpToAddress：
    // - 作用：统一的"跳到地址"分发器（实现在 MemoryDock.Workbench.cpp）：
    //   所有模块、区域和搜索结果地址统一交给内存工作台。
    // - 参数 address：目标地址（本 Dock 附加进程的用户态地址）。
    // - 返回：无。
    void jumpToAddress(std::uint64_t address);

    // jumpToModuleBase：
    // - 作用：模块表双击/右键的跳转（实现在 MemoryDock.WorkbenchEntry.cpp）。模块表预览的进程
    //   可能不是附加的进程：先附加模块快照对应的进程实例；打开失败且驱动已加载时，
    //   钉住同一实例并切到标准 R0 进程虚拟读通道。用户取消切换不触发回退。
    // - 参数 baseAddress：模块基址；
    // - 返回：无；导航拒绝原因由工作台状态栏展示。
    void jumpToModuleBase(std::uint64_t baseAddress);
    void probeModuleDriverJump(const ks::ui::NavRequest& request, std::uint64_t navigationGeneration);

    // viewRegionViaDriver：
    // - 作用：区域表"R0读取此区域"的落点：强制标准驱动通道、在工作台里打开区域起点；
    // - 参数 regionBase：区域基址；bytesToRead：来源区域的请求预算（仅用于日志）；
    // - 返回：无；导航拒绝原因由工作台状态栏展示。
    void viewRegionViaDriver(std::uint64_t regionBase, std::uint64_t bytesToRead);

    // addSearchResultsToAddressBook：
    // - 作用：把用户明确选中的搜索结果地址加入共享地址簿（种类=搜索结果，上限见
    //   WorkbenchBookIntake.h，绝不自动灌入）；结果写入搜索页状态栏；
    // - 参数 addresses：要加入的地址（顺序即新增顺序）；
    // - 返回：无。
    void addSearchResultsToAddressBook(const std::vector<std::uint64_t>& addresses);

    // workbenchFocusAddress：工作台十六进制页当前的插入点（仅当工作台跟随本 Dock 的附加进程时有值），
    // 供 PTE 页等取"用户正在看哪里"作为默认地址。
    std::optional<std::uint64_t> workbenchFocusAddress() const;

    // refreshKernelExecutableMemoryScanAsync：
    // - 作用：异步刷新内核可执行页扫描结果。
    // - 返回：无。
    void refreshKernelExecutableMemoryScanAsync();

    // rebuildKernelExecutableMemoryScanTable：
    // - 作用：按当前过滤条件重建可执行页扫描表。
    // - 返回：无。
    void rebuildKernelExecutableMemoryScanTable();

    // showKernelExecutableMemoryDetailByCurrentRow：
    // - 作用：把当前选中行写入详情 CodeEditorWidget。
    // - 返回：无。
    void showKernelExecutableMemoryDetailByCurrentRow();

    // refreshKernelMemoryEvidenceAsync：
    // - 作用：异步查询内核内存证据，包括非模块执行页、BigPool、PTE 权限和 text hash 状态。
    // - 处理逻辑：后台线程调用 ArkDriverClient::queryKernelMemoryEvidence，主线程回填 UI。
    // - 返回：无。
    void refreshKernelMemoryEvidenceAsync();

    // rebuildKernelMemoryEvidenceTable：
    // - 作用：按当前缓存和过滤选项重建内核内存证据表格。
    // - 处理逻辑：只做缓存到 UI 的投影，不执行新的驱动 IOCTL。
    // - 返回：无。
    void rebuildKernelMemoryEvidenceTable();

    // showKernelMemoryEvidenceDetailByCurrentRow：
    // - 作用：把当前选中证据行展开到详情编辑器。
    // - 处理逻辑：通过表格 UserRole 中的虚拟地址反查缓存。
    // - 返回：无。
    void showKernelMemoryEvidenceDetailByCurrentRow();

    // refreshProcessPteTranslateAsync：
    // - 作用：异步采集当前进程的 PTE / VA 翻译信息。
    // - 返回：无。
    void refreshProcessPteTranslateAsync();

    // rebuildProcessPteTranslateTable：
    // - 作用：按当前过滤条件重建 PTE / VA 翻译表格。
    // - 返回：无。
    void rebuildProcessPteTranslateTable();

    // showProcessPteTranslateDetailByCurrentRow：
    // - 作用：把当前选中翻译记录展开到详情编辑器。
    // - 返回：无。
    void showProcessPteTranslateDetailByCurrentRow();

    // refreshProcessMemoryEvidenceAsync：
    // - 作用：异步采集当前进程内存证据。
    // - 返回：无。
    void refreshProcessMemoryEvidenceAsync();

    // rebuildProcessMemoryEvidenceTable：
    // - 作用：按过滤条件重建进程内存证据表。
    // - 返回：无。
    void rebuildProcessMemoryEvidenceTable();

    // showProcessMemoryEvidenceDetailByCurrentRow：
    // - 作用：把当前选中证据记录展开到详情编辑器。
    // - 返回：无。
    void showProcessMemoryEvidenceDetailByCurrentRow();

private:
    // ========================================================
    // 通用辅助函数
    // ========================================================

    // updateStatusBarText：
    // - 作用：更新状态栏（进程名、PID、读写状态）。
    // - 返回：无。
    void updateStatusBarText();

    // parseAddressText：
    // - 作用：解析十进制或十六进制地址字符串。
    // - 参数 text：输入文本。
    // - 参数 valueOut：输出地址数值。
    // - 返回：true 解析成功；false 解析失败。
    static bool parseAddressText(const QString& text, std::uint64_t& valueOut);

    // parseUnsignedNumber：
    // - 作用：解析通用无符号整数（支持 0x 与十进制）。
    // - 参数 text：输入文本。
    // - 参数 valueOut：输出值。
    // - 返回：true 成功；false 失败。
    static bool parseUnsignedNumber(const QString& text, std::uint64_t& valueOut);

    // formatAddress：
    // - 作用：格式化地址为 16 位十六进制文本。
    // - 参数 address：地址值。
    // - 返回：格式化后的 QString。
    static QString formatAddress(std::uint64_t address);

    // formatSize：
    // - 作用：格式化字节大小（B/KB/MB/GB）。
    // - 参数 sizeBytes：字节数。
    // - 返回：可读文本。
    static QString formatSize(std::uint64_t sizeBytes);

    // protectToText：
    // - 作用：把 PAGE_* 保护值转换为简写（R--、RW-、RX 等）。
    // - 参数 protect：Win32 protect 值。
    // - 返回：可读文本。
    static QString protectToText(std::uint32_t protect);

    // stateToText：
    // - 作用：把 MEM_* 状态值转换为可读文本。
    // - 参数 state：Win32 state 值。
    // - 返回：可读文本。
    static QString stateToText(std::uint32_t state);

    // typeToText：
    // - 作用：把 MEM_* 类型值转换为可读文本。
    // - 参数 type：Win32 type 值。
    // - 返回：可读文本。
    static QString typeToText(std::uint32_t type);

    // bytesToDisplayString：
    // - 作用：按数据类型把字节数组转换为可读值字符串。
    // - 参数 bytes：原始字节。
    // - 参数 valueType：目标数据类型。
    // - 返回：格式化后的可读文本。
    static QString bytesToDisplayString(const QByteArray& bytes, SearchValueType valueType);

private:
    // ========================================================
    // 顶层布局与全局控件
    // ========================================================

    QVBoxLayout* m_rootLayout = nullptr;      // 根布局（垂直：工具栏 + Tab + 状态栏）。
    QHBoxLayout* m_toolbarLayout = nullptr;   // 顶部工具栏布局。
    QTabWidget* m_tabWidget = nullptr;        // 五个功能 Tab 的容器。
    QStatusBar* m_statusBar = nullptr;        // 底部状态栏。

    // 工具栏控件。
    QLabel* m_dockTitleLabel = nullptr;       // 页面标题标签（顶部三段头第一段）。
    QLabel* m_dockHeaderStatusLabel = nullptr; // 顶部附加状态摘要（顶部三段头第二段）。
    QComboBox* m_processCombo = nullptr;      // 进程选择下拉框（可输入过滤）。
    ks::ui::WindowPickerButton* m_processPickerButton = nullptr; // 十字准星窗口拾取。
    QLabel* m_processPickerHintLabel = nullptr; // 拾取过程中的实时目标提示，仅拾取时可见。
    bool m_processComboPopupLifecycleActive = false; // 包含 Qt 弹层动画在内的完整展开生命周期。
    // 弹层展开期间缓存的最新进程列表提交；收起后回投，避免重建正在展开的下拉框。
    std::function<void()> m_processComboDeferredCommit;
    QTimer* m_processComboChangeTimer = nullptr;      // 进程下拉框切换去抖定时器。
    std::uint32_t m_pendingModuleRefreshPid = 0;      // 去抖窗口内最后一次选中的 PID。
    QPushButton* m_attachButton = nullptr;    // 附加按钮。
    QPushButton* m_detachButton = nullptr;    // 分离按钮。
    QPushButton* m_refreshButton = nullptr;   // 刷新按钮。
    QPushButton* m_settingsButton = nullptr;  // 设置按钮（线程数、缓存大小）。

    // 状态栏标签。
    QLabel* m_statusProcessLabel = nullptr;   // 显示当前进程名。
    QLabel* m_statusPidLabel = nullptr;       // 显示当前 PID。
    QLabel* m_statusMemoryIoLabel = nullptr;  // 显示当前读写状态。

    // ========================================================
    // Tab1：进程与模块
    // ========================================================

    QWidget* m_tabProcessModule = nullptr;    // Tab1 页面容器。
    MemoryTableView* m_processTable = nullptr;   // 进程列表表格。
    std::shared_ptr<const QHash<std::uint32_t, ProcessCpuSample>> m_previousCpuSamples = ks::memory_detail::ValueStorage<QHash<std::uint32_t, ProcessCpuSample>>();
    std::shared_ptr<const QHash<std::uint32_t, int>> m_processRowsByPid = ks::memory_detail::ValueStorage<QHash<std::uint32_t, int>>();
    ks::memory_detail::CoreListModel* m_processComboModel = nullptr; // 上一轮 CPU 采样，按 PID。
    QLineEdit* m_processFilterEdit = nullptr; // 进程名/PID 过滤输入框。
    QLabel* m_processCountLabel = nullptr;    // 进程表"显示 N / 共 M"计数。
    QLineEdit* m_moduleFilterEdit = nullptr;  // 模块名称过滤输入框。
    QPushButton* m_moduleRefreshButton = nullptr; // 模块刷新按钮。
    QCheckBox* m_moduleSignatureCheck = nullptr;  // 模块刷新时是否校验签名。
    QLabel* m_moduleStatusLabel = nullptr;        // 模块刷新状态标签。
    MemoryTreeView* m_moduleTable = nullptr;         // 模块列表表格（树形表头风格）。

    // ========================================================
    // Tab2：内存区域
    // ========================================================

    QWidget* m_tabRegions = nullptr;          // Tab2 页面容器。
    QPushButton* m_regionRefreshButton = nullptr;    // 手动重新枚举内存区域。
    QLineEdit* m_regionFilterEdit = nullptr;         // 按基址/保护属性/映射文件过滤。
    QLabel* m_regionStatusLabel = nullptr;           // 区域数量与过滤结果摘要。
    QCheckBox* m_regionCommittedOnlyCheck = nullptr; // 仅已提交区域过滤。
    QCheckBox* m_regionImageOnlyCheck = nullptr;     // 仅 IMAGE 类型过滤。
    QCheckBox* m_regionReadableOnlyCheck = nullptr;  // 仅可读区域过滤。
    MemoryTableView* m_regionTable = nullptr;    // 内存区域表格。

    // ========================================================
    // Tab3：内存搜索
    // ========================================================

    QWidget* m_tabSearch = nullptr;           // Tab3 页面容器。
    QComboBox* m_searchTypeCombo = nullptr;   // 数据类型下拉框。
    QLineEdit* m_searchValueEdit = nullptr;   // 搜索值输入框。
    QComboBox* m_searchRangeCombo = nullptr;  // 范围模式下拉框（全内存/自定义）。
    QLineEdit* m_searchRangeStartEdit = nullptr; // 自定义范围起始地址。
    QLineEdit* m_searchRangeEndEdit = nullptr;   // 自定义范围结束地址。
    QCheckBox* m_searchImageOnlyCheck = nullptr; // 仅 IMAGE 区域。
    QCheckBox* m_searchHeapOnlyCheck = nullptr;  // 仅堆区域（当前按 PRIVATE 近似）。
    QCheckBox* m_searchStackOnlyCheck = nullptr; // 仅栈区域（当前预留标记）。
    QPushButton* m_firstScanButton = nullptr; // 首次扫描按钮。
    QPushButton* m_nextScanButton = nullptr;  // 再次扫描按钮。
    QPushButton* m_resetScanButton = nullptr; // 重置扫描按钮。
    QPushButton* m_cancelScanButton = nullptr;// 取消扫描按钮。
    QComboBox* m_nextScanCompareCombo = nullptr; // 再次扫描条件下拉框。
    QLineEdit* m_nextScanValueEdit = nullptr;    // 再次扫描值输入框。
    QLineEdit* m_nextScanValueBEdit = nullptr;   // Between 上界输入框。
    MemoryTableView* m_searchResultTable = nullptr; // 扫描结果表格。
    QProgressBar* m_scanProgressBar = nullptr;   // 扫描进度条。
    QLabel* m_scanStatusLabel = nullptr;         // 扫描状态文本。

    // ========================================================
    // Tab7：内核可执行页扫描
    // ========================================================

    QWidget* m_tabKernelExecutableMemory = nullptr;    // Tab7 页面容器。
    QPushButton* m_kernelExecutableRefreshButton = nullptr; // 刷新按钮。
    QCheckBox* m_kernelExecutableRiskOnlyCheck = nullptr;   // 仅风险项过滤。
    QLineEdit* m_kernelExecutableModuleFilterEdit = nullptr; // 模块路径过滤输入框。
    QLabel* m_kernelExecutableStatusLabel = nullptr;         // 刷新状态标签。
    MemoryTableView* m_kernelExecutableTable = nullptr;         // 可执行页扫描表。
    ks::ui::StructuredFieldView* m_kernelExecutableDetailEditor = nullptr; // 详情编辑器。

    // ========================================================
    // Tab8：内核内存证据
    // ========================================================

    QWidget* m_tabKernelMemoryEvidence = nullptr;            // Tab8 页面容器。
    QPushButton* m_kernelMemoryEvidenceRefreshButton = nullptr; // 内核内存证据刷新按钮。
    QCheckBox* m_kernelMemoryEvidenceRiskOnlyCheck = nullptr; // 仅显示 riskFlags 非零记录。
    QCheckBox* m_kernelMemoryEvidenceIncludeNonModuleCheck = nullptr; // 是否显式包含非模块执行范围扫描。
    QLineEdit* m_kernelMemoryEvidenceFilterEdit = nullptr;   // Owner/detail 本地过滤框。
    QLineEdit* m_kernelMemoryEvidenceStartEdit = nullptr;    // 非模块扫描起始地址。
    QLineEdit* m_kernelMemoryEvidenceEndEdit = nullptr;      // 非模块扫描结束地址。
    QSpinBox* m_kernelMemoryEvidenceMaxRowsSpin = nullptr;   // 单次最大返回行数。
    QLabel* m_kernelMemoryEvidenceStatusLabel = nullptr;     // 查询状态标签。
    MemoryTableView* m_kernelMemoryEvidenceTable = nullptr;     // 证据结果表格。
    ks::ui::StructuredFieldView* m_kernelMemoryEvidenceDetailEditor = nullptr; // 证据详情编辑器。

    // ========================================================
    // Tab9：PTE / VA 翻译
    // ========================================================

    QWidget* m_tabProcessPteTranslate = nullptr;              // Tab9 页面容器。
    QPushButton* m_processPteTranslateRefreshButton = nullptr; // 刷新按钮。
    QCheckBox* m_processPteTranslateRiskOnlyCheck = nullptr;    // 仅风险项过滤。
    QLineEdit* m_processPteTranslateAddressEdit = nullptr;      // VA 输入框。
    QSpinBox* m_processPteTranslatePageCountSpin = nullptr;     // 采样页数。
    QLabel* m_processPteTranslateStatusLabel = nullptr;         // 状态标签。
    MemoryTableView* m_processPteTranslateTable = nullptr;         // 翻译结果表。
    ks::ui::StructuredFieldView* m_processPteTranslateDetailEditor = nullptr; // 详情编辑器。

    // ========================================================
    // Tab10：进程内存证据
    // ========================================================

    QWidget* m_tabProcessMemoryEvidence = nullptr;              // Tab10 页面容器。
    QPushButton* m_processMemoryEvidenceRefreshButton = nullptr; // 刷新按钮。
    QCheckBox* m_processMemoryEvidenceRiskOnlyCheck = nullptr;    // 仅风险项过滤。
    QCheckBox* m_processMemoryEvidenceImageOnlyCheck = nullptr;   // 仅映像区域。
    QLineEdit* m_processMemoryEvidenceStartEdit = nullptr;        // 起始地址。
    QLineEdit* m_processMemoryEvidenceEndEdit = nullptr;          // 结束地址。
    QLineEdit* m_processMemoryEvidenceFilterEdit = nullptr;       // 文本过滤。
    QSpinBox* m_processMemoryEvidenceMaxRowsSpin = nullptr;       // 最大行数。
    QLabel* m_processMemoryEvidenceStatusLabel = nullptr;         // 状态标签。
    MemoryTableView* m_processMemoryEvidenceTable = nullptr;         // 证据结果表。
    ks::ui::StructuredFieldView* m_processMemoryEvidenceDetailEditor = nullptr; // 详情编辑器。

    // ========================================================
    // Tab11：系统内存审计
    // ========================================================

    SystemMemoryAuditPage* m_systemMemoryAuditPage = nullptr; // 系统级物理内存归因页面。
    QWidget* m_systemMemoryAuditPlaceholder = nullptr;       // 首次切页前的轻量占位页。
    bool m_systemMemoryAuditPageConstructing = false;        // 防止切页/刷新重入构造。

    // ========================================================
    // Tab12：DDMA（磁盘直接内存访问）
    // ========================================================

    DdmaPage* m_ddmaPage = nullptr;           // DDMA 通道配置与自检页面。
    ksword::memory_dock::TamperDetectionPage* m_tamperDetectionPage = nullptr; // 多路径交叉篡改检测页。

    // 内存搜索选择自己的访问后端，统一工作台由私有目标会话管理通道。
    QComboBox* m_searchBackendCombo = nullptr;        // Tab3 访问后端。
    QLabel* m_searchBackendHintLabel = nullptr;       // Tab3 后端状态提示。

private:
    // ========================================================
    // 运行时状态与缓存
    // ========================================================

    // MemoryScanTaskState：
    // - 作用：独立保存扫描取消、进度与物理完成状态，避免 detached worker 依赖 QWidget 生命周期；
    // - 生命周期：MemoryDock 与所有已启动扫描任务共同持有。
    struct MemoryScanTaskState
    {
        std::atomic_bool cancelRequested{false}, done{false};
        std::atomic<std::size_t> progressDone{0}, progressTotal{0};
        std::atomic_int progressPercent{-1};
        std::shared_ptr<void> processLease;
        std::shared_ptr<ks::ui::AsyncCleanupRegistry::Lease> cleanupLease;
        std::shared_ptr<const std::vector<SearchResultEntry>> results;
        std::uint64_t elapsedMs = 0, skippedBytes = 0, skippedEntries = 0;
        QString firstReadFailure, failureText;
        bool next = false, cancelled = false;
    };
    std::function<void()> m_scanCompletion;
    int m_scanLastProgress = -1;
    void pollMemoryScanTask();


    HANDLE m_attachedProcessHandle = nullptr; // 当前附加的目标进程句柄。
    std::uint32_t m_attachedPid = 0;          // 当前附加 PID。
    QString m_attachedProcessName;            // 当前附加进程名。
    bool m_canReadWriteMemory = false;        // 当前句柄是否可读写内存。
    std::atomic<std::uint64_t> m_processAttachmentGeneration{ 0 }; // 附加上下文代次（丢弃旧句柄任务结果）。

    std::shared_ptr<const std::vector<ProcessEntry>> m_processCache = ks::memory_detail::ValueStorage<std::vector<ProcessEntry>>(); // 进程缓存（Tab1/工具栏复用）。
    std::shared_ptr<const std::vector<ModuleEntry>> m_moduleCache = ks::memory_detail::ValueStorage<std::vector<ModuleEntry>>();   // 模块缓存（Tab1 使用）。
    std::atomic<bool> m_moduleRefreshInProgress{ false }; // 模块刷新是否进行中（异步任务状态）。
    std::atomic<std::uint64_t> m_moduleRefreshTicket{ 0 }; // 模块刷新票据（丢弃过期结果）。
    struct ModuleRefreshRequest { std::uint32_t pid = 0; std::uint64_t creation = 0; bool signatures = false; };
    struct ModuleRefreshJob;
    std::shared_ptr<ModuleRefreshJob> m_moduleRefreshJob;
    std::shared_ptr<std::atomic_bool> m_moduleRefreshLifetime = std::make_shared<std::atomic_bool>(false);
    std::optional<ModuleRefreshRequest> m_moduleRefreshPending;
    QTimer* m_moduleRefreshPoll = nullptr;
    int m_dumpMemoryProgressPid = 0;        // Dump 内存任务的进度条 PID。
    ks::ui::AsyncOperation* m_regionDumpOperation = nullptr; // QObject 子对象，串行管理区域转储。
    ks::ui::AsyncOperation* m_moduleNavigationOperation = nullptr; // R0 跳转前后台验证一字节真实读取。
    std::shared_ptr<std::atomic<RegionDumpPhase>> m_regionDumpPhase; // 提交与取消的仲裁状态。
    int m_regionDumpProgressPid = 0;         // 区域转储独立进度，避免与整进程 Dump 互相覆盖。
    std::shared_ptr<const std::vector<RegionEntry>> m_regionCache = ks::memory_detail::ValueStorage<std::vector<RegionEntry>>();   // 区域缓存（Tab2/Tab3 复用）。

    std::shared_ptr<const std::vector<SearchResultEntry>> m_searchResultCache = ks::memory_detail::ValueStorage<std::vector<SearchResultEntry>>(); // 扫描结果缓存（Tab3）。
    std::size_t m_searchResultVisibleCount = 0;         // 当前结果表实际显示条数（可能小于缓存总数）。
    SearchValueType m_lastSearchValueType = SearchValueType::Byte; // 最近一次扫描类型。
    std::atomic<bool> m_scanInProgress{ false };       // 当前是否正在扫描。
    std::atomic<bool> m_scanCancelRequested{ false };  // 扫描取消标志。
    std::shared_ptr<MemoryScanTaskState> m_scanTaskState = std::make_shared<MemoryScanTaskState>();
                                                        // m_scanTaskState：跨线程存活的扫描值任务。
    std::uint32_t m_scanThreadCount = 4;               // 扫描线程数（设置可调）。
    std::uint32_t m_scanChunkSizeKB = 1024;            // 单次读取块大小（KB，设置可调）。

    std::shared_ptr<const std::vector<ksword::ark::KernelExecutableMemoryPageEntry>> m_kernelExecutableCache = ks::memory_detail::ValueStorage<std::vector<ksword::ark::KernelExecutableMemoryPageEntry>>(); // Tab7 扫描缓存。
    std::atomic<bool> m_kernelExecutableRefreshInProgress{ false }; // Tab7 是否正在刷新。
    std::atomic<std::uint64_t> m_kernelExecutableRefreshTicket{ 0 }; // Tab7 刷新票据。
    std::size_t m_kernelExecutableVisibleCount = 0; // Tab7 当前可见行数。

    std::shared_ptr<const std::vector<ksword::ark::KernelMemoryEvidenceEntry>> m_kernelMemoryEvidenceCache = ks::memory_detail::ValueStorage<std::vector<ksword::ark::KernelMemoryEvidenceEntry>>(); // Tab8 证据缓存。
    std::atomic<bool> m_kernelMemoryEvidenceRefreshInProgress{ false }; // Tab8 是否正在刷新。
    std::atomic<std::uint64_t> m_kernelMemoryEvidenceRefreshTicket{ 0 }; // Tab8 刷新票据。
    std::size_t m_kernelMemoryEvidenceVisibleCount = 0; // Tab8 当前可见行数。

    std::shared_ptr<const std::vector<ProcessMemoryEvidenceEntry>> m_processPteTranslateCache = ks::memory_detail::ValueStorage<std::vector<ProcessMemoryEvidenceEntry>>(); // Tab9 证据缓存。
    std::atomic<bool> m_processPteTranslateRefreshInProgress{ false }; // Tab9 是否正在刷新。
    std::atomic<std::uint64_t> m_processPteTranslateRefreshTicket{ 0 }; // Tab9 刷新票据。
    std::size_t m_processPteTranslateVisibleCount = 0; // Tab9 当前可见行数。

    std::shared_ptr<const std::vector<ProcessMemoryEvidenceEntry>> m_processMemoryEvidenceCache = ks::memory_detail::ValueStorage<std::vector<ProcessMemoryEvidenceEntry>>(); // Tab10 证据缓存。
    std::atomic<bool> m_processMemoryEvidenceRefreshInProgress{ false }; // Tab10 是否正在刷新。
    std::atomic<std::uint64_t> m_processMemoryEvidenceRefreshTicket{ 0 }; // Tab10 刷新票据。
    std::size_t m_processMemoryEvidenceVisibleCount = 0; // Tab10 当前可见行数。

private:
    // ========================================================
    // 内存工作台页签（实现在 MemoryDock.Workbench.cpp）
    // ========================================================

    // initializeWorkbenchTab：在 initializeTabs 的图标循环之后调用，建空容器并插入页签。
    // 视图本身懒创建（首次切到该页签时由 ensureWorkbenchView 创建），避免拖慢 Dock 构造。
    void initializeWorkbenchTab();
    // initializeMemoryDebugTab：插入独立的不附加内存调试页，页面首次显示才访问系统。
    void initializeMemoryDebugTab();
    // ensureWorkbenchView：幂等地创建视图并完成全部接线；内嵌窗口里恒为空操作。
    void ensureWorkbenchView();
    // connectWorkbenchLiveness：视图与目标存活计时器就绪后幂等接线，目标退出时孤立 int3 记录。
    // 调用方式：任一对象创建后调用；无传入/传出，不新增计时器或枚举任务。
    void connectWorkbenchLiveness();
    // 三个附加/分离钩子：转给视图的 WorkbenchTarget；视图尚未创建时是空操作。
    void workbenchOnAttached();
    void workbenchOnAboutToDetach();
    void workbenchOnDetached();
    // navigateWorkbench：确保视图存在并切到该页签后执行一次跳转；返回是否成功跳转。
    bool navigateWorkbench(const ks::ui::NavRequest& request);
    // workbenchAllowsProcessChange：附加/分离目标进程之前问一次工作台的离开守卫；
    // 视图尚未创建返回 true，守卫被用户否决返回 false。
    ks::ui::LeaveEntryStatus workbenchAllowsProcessChange(ks::ui::LeaveCompletion completion = {});
    ks::ui::LeaveEntryStatus prepareMemoryDebugQuit(ks::ui::LeaveCompletion completion);
    // shutdownWorkbench：析构路径上先于子对象销毁调用：权威视图把设置落盘，并断开对视图的引用。
    void shutdownWorkbench();
    // applyProcessDetailTabVisibility：按"内嵌进程详情窗口"的规则重新设置各页签的显隐
    // （进程与模块/内存区域/内存搜索 + 内存工作台）。
    void applyProcessDetailTabVisibility();

    QWidget* m_tabWorkbench = nullptr;                   // 工作台页签的容器页。
    ks::ui::MemoryDebugPage* m_memoryDebugPage = nullptr; // 独立进程内存会话，不跟随 Dock 附加。
    ks::misc::HvciBypassPage* m_hvciBypassPage = nullptr; // HVCI W^X 绕过实验页。
    ks::misc::RxpfPage* m_rxpfPage = nullptr;             // RXPF 页错误模拟页。
    ks::ui::MemoryWorkbenchView* m_workbenchView = nullptr; // 工作台视图（懒创建，容器页的子对象）。
    QTimer* m_workbenchLivenessTimer = nullptr; // 每秒核验工作台锚定目标。
    bool m_workbenchEmbedded = false;                     // 是否是进程详情窗口里的内嵌实例（视图以内嵌模式创建）。
    int m_navigationPrepareCursor = 0;
    bool m_navigationPagePreparing = false;
    bool m_navigationSkippedColdBodies = false;
    bool m_navigationPagesPrepared = false;               // 导航索引已完成一次嵌套懒页准备。
    bool m_workbenchQuitPrepared = false;                 // 普通工作台退出许可通过后保持冻结。
    bool m_workbenchEnabledBeforeQuit = true;             // 取消退出时恢复该视图自己的原启用状态。

    // 模块表当前缓存对应的进程：模块表可以预览一个并未附加的进程，双击模块基址时必须按
    // 它所属的进程去看（见 jumpToModuleBase）。0 表示缓存为空。
    QTimer* m_coreProjectionPoll = nullptr;
    QTimer* m_coreProjectionDebounce = nullptr;
    std::array<QString, 4> m_extraStatusTemplates;
    std::array<ks::ui::FieldDocument, 4> m_extraDiagnosticDocuments;
    std::array<bool, 8> m_coreInitialized{};
    std::array<int, 8> m_coreSortColumns{0, 0, 0, 0, 0, 0, 0, 0};
    std::array<Qt::SortOrder, 8> m_coreSortOrders{Qt::AscendingOrder, Qt::DescendingOrder, Qt::AscendingOrder, Qt::DescendingOrder, Qt::DescendingOrder, Qt::DescendingOrder, Qt::DescendingOrder, Qt::DescendingOrder};
    std::array<std::shared_ptr<CoreProjectionData>, 8> m_corePublished, m_coreReady, m_coreFailed;
    std::shared_ptr<CoreProjectionJob> m_coreProjectionJob;
    std::shared_ptr<RegionRefreshJob> m_regionRefreshJob, m_regionRefreshPendingJob;
    std::shared_ptr<std::atomic_bool> m_coreProjectionLifetime = std::make_shared<std::atomic_bool>(false);
    std::uint64_t m_coreLocaleGeneration = 0;
    QString m_moduleCacheStatusTemplate;
    std::shared_ptr<const std::vector<RegionEntry>> m_regionSearchSnapshot;
    std::uint64_t m_regionSearchGeneration = UINT64_MAX;
    std::uint32_t m_regionSearchError = 0;
    bool m_regionCachePartial = false;
    std::uint32_t m_regionCacheError = 0;
    std::shared_ptr<const ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot> m_tamperCandidateSnapshot = ks::memory_detail::ValueStorage<ksword::memory_dock::TamperDetectionPage::ModuleCandidateSnapshot>();
    std::uint32_t m_moduleCachePid = 0;
    // 上面那个进程在缓存落地时的创建时间（100ns，0=没取到）：钉住预览进程时用它核对"仍是同一个进程实例"。
    std::uint64_t m_moduleCacheCreateTime = 0;
};
