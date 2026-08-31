#pragma once

// ============================================================
// ProcessDetailWindow.h
// 作用：
// - 提供“进程详细信息”独立窗口（非 Dock、非阻塞）；
// - 每个进程可打开独立窗口，包含详细信息、线程、操作、模块、令牌、PEB、内核回调表等 Tab；
// - 支持模块刷新、右键操作、DLL 注入、Shellcode 注入等能力。
// ============================================================

#include "../Framework.h"
#include "ProcessAffinityModel.h"

#include <QHash>
#include <QIcon>
#include <QPointer>
#include <QSet>
#include <QStringList>
#include <QWidget>

#include <cstdint>
#include <deque>
#include <string>
#include <vector>
#include "../../../shared/driver/KswordArkKeyboardIoctl.h"

#include "../../../shared/driver/KswordArkThreadIoctl.h"

// 前置声明：减少头文件依赖，提升编译速度。
class QCheckBox;
class QButtonGroup;
class QComboBox;
class QEvent;
class QFormLayout;
class QGroupBox;
class QGridLayout;
class QHBoxLayout;
class QLabel;
class QLineEdit;
class QMenu;
class QPushButton;
class QTabWidget;
class QTableWidget;
class QToolButton;
class QTreeWidget;
class QTreeWidgetItem;
class QVBoxLayout;
class QPoint;
class CodeEditorWidget;
class HandleDock;
class MemoryDock;
class NetworkDock;
class OtherDock;

class ProcessDetailWindow final : public QWidget
{
    Q_OBJECT

public:
    // 构造函数作用：
    // - 接收进程基础快照作为窗口初始数据；
    // - 初始化所有 UI 与交互连接；
    // - 启动模块页首次异步刷新。
    explicit ProcessDetailWindow(const ks::process::ProcessRecord& baseRecord, QWidget* parent = nullptr);

    // updateBaseRecord 作用：
    // - 用外部最新进程快照更新窗口展示；
    // - 不会销毁窗口，只刷新显示文本与状态。
    void updateBaseRecord(const ks::process::ProcessRecord& baseRecord);

    // pid 作用：返回当前窗口绑定进程 PID。
    std::uint32_t pid() const;

    // identityKey 作用：返回 PID + 创建时间组成的稳定进程身份，用于与进程列表活动快照精确匹配。
    std::string identityKey() const;

    // PerformanceHistorySample：进程列表活动快照投递到详情窗口的单进程性能样本。
    struct PerformanceHistorySample
    {
        std::int64_t unixMilliseconds = 0; // 采样时刻，供横轴格式化。
        double cpuPercent = 0.0;           // CPU 占用百分比。
        double cpuCorePercent = 0.0;       // CPU 单核等效百分比，可超过 100%。
        double memoryMB = 0.0;             // 工作集内存 MB。
        double diskMBps = 0.0;             // 磁盘吞吐 MB/s。
        double networkRxKBps = 0.0;        // 网络下行 KB/s。
        double networkTxKBps = 0.0;        // 网络上行 KB/s。
        double gpuPercent = 0.0;           // GPU 占用百分比。
    };

    // setPerformanceHistory：用进程列表已有的活动快照替换当前性能历史，供新开详情窗口立即回溯历史数据。
    void setPerformanceHistory(std::vector<PerformanceHistorySample> history);

    // appendPerformanceHistorySample：追加进程列表刚生成的一条活动快照，避免每轮刷新重建整个历史序列。
    void appendPerformanceHistorySample(const PerformanceHistorySample& sample);

    // CpuCoreValue：一个逻辑处理器在本采样区间内的占用。
    struct CpuCoreValue
    {
        std::uint32_t processorIndex = 0;
        std::uint16_t group = 0;
        std::uint16_t number = 0;
        double percent = 0.0;
        bool sampleReady = false;
    };

    // ThreadCpuCoreValue：单线程汇总占用与逐逻辑处理器占用。
    struct ThreadCpuCoreValue
    {
        std::uint32_t threadId = 0;
        double cpuPercent = 0.0;
        std::vector<CpuCoreValue> cores;
    };

    // CpuCoreViewSample：ProcessDock 从 CSwitch ETW 区间快照筛出的当前进程数据。
    struct CpuCoreViewSample
    {
        bool monitorRunning = false;
        bool sampleReady = false;
        bool dataLossDetected = false;
        std::uint64_t eventsLost = 0;
        std::uint64_t contextSwitchEvents = 0;
        QString diagnosticText;
        double processSystemPercent = 0.0;
        double processCoreEquivalentPercent = 0.0;
        std::vector<CpuCoreValue> processCores;
        std::vector<ThreadCpuCoreValue> threads;
    };

    // setCpuCoreViewSample：更新“CPU 核心”页；页面尚未懒加载时只缓存数据。
    void setCpuCoreViewSample(CpuCoreViewSample sample);

    // showHotkeyTabAndRefresh 作用：
    // - 将详情窗口切换到“进程热键”页；
    // - 复用详情页已有热键扫描流程，触发一次异步刷新；
    // - 调用方通常来自进程列表右键菜单，用于把隐藏较深的热键功能变成一键入口。
    // 参数：无。
    // 返回：无。
    void showHotkeyTabAndRefresh();

    // showActionTab 作用：
    // - 将详情窗口切换到“操作”页；
    // - 供进程列表右键菜单直达 DLL/Shellcode 注入区域。
    // 参数：无。
    // 返回：无。
    void showActionTab();

signals:
    // requestOpenProcessByPid 作用：
    // - 在“转到父进程”按钮点击时发出；
    // - 由 ProcessDock 统一接收并打开对应进程详情窗口。
    void requestOpenProcessByPid(std::uint32_t pid);

    // requestOpenHandleDockByPid 作用：
    // - 在“跳转句柄”按钮点击时发出；
    // - 由 ProcessDock 转发给 MainWindow 打开句柄 Dock 并按 PID 过滤。
    void requestOpenHandleDockByPid(std::uint32_t pid);
    void requestOpenMemoryDockByPid(std::uint32_t pid);
    void requestOpenNetworkDockByPid(std::uint32_t pid);
    void requestOpenWindowDockByPid(std::uint32_t pid);
    // requestOpenFileDetailByPath：将当前映像路径交给主窗口的 FileDock，复用既有文件详情窗口。
    void requestOpenFileDetailByPath(const QString& filePath);

private:
    // ModuleRefreshResult：模块页后台刷新结果数据结构。
    struct ModuleRefreshResult
    {
        ks::process::ProcessModuleSnapshot moduleSnapshot; // 模块 + 线程快照。
        std::uint64_t elapsedMs = 0;                       // 后台刷新耗时（毫秒）。
        bool includeSignatureCheck = false;                // 本轮是否执行签名校验。
    };

    // ThreadInspectItem：线程细节页单行数据。
    struct ThreadInspectItem
    {
        std::uint32_t threadId = 0;        // 线程 ID。
        std::uint32_t processId = 0;       // 所属进程 PID。
        QString stateText;                 // 状态文本（运行/结束/未知）。
        int priorityValue = 0;             // 线程优先级值。
        quint64 switchCount = 0;           // 上下文切换计数（当前实现可能为 0）。
        QString startAddressText;          // 线程起始地址（十六进制）。
        QString tebAddressText;            // 线程 TEB 地址（十六进制）。
        QString affinityText;              // 线程亲和性文本。
        QString registerSummaryText;       // 寄存器摘要文本。
        std::uint64_t startAddress = 0;    // 起始地址原始值。
        std::uint64_t win32StartAddress = 0; // Win32StartAddress 原始值。
        std::uint64_t createTime100ns = 0; // 创建时间；驱动线程危险动作的反复用身份字段。
        std::uint64_t tebAddress = 0;      // TEB 地址原始值。
        std::uint64_t userStackBase = 0;   // 用户栈基址。
        std::uint64_t userStackLimit = 0;  // 用户栈边界。
        std::uint64_t r0KernelStack = 0;   // KTHREAD.KernelStack。
        std::uint64_t r0StackBase = 0;     // KTHREAD.StackBase。
        std::uint64_t r0StackLimit = 0;    // KTHREAD.StackLimit。
        std::uint64_t r0InitialStack = 0;  // KTHREAD.InitialStack。
        std::uint32_t r0ThreadStatus = KSWORD_ARK_THREAD_R0_STATUS_UNAVAILABLE; // R0 线程状态。
        std::uint64_t r0CapabilityMask = 0; // R0 capability。
        QString r0RuntimeDetailText;       // R0 运行时详情可读摘要。
        std::uint32_t r0DetailStatus = KSWORD_ARK_DETAIL_STATUS_UNKNOWN; // detail IOCTL 总体状态。
        std::uint32_t r0DetailFieldFlags = 0; // detail IOCTL 实际返回字段位图。
        std::uint64_t r0MissingCapabilityMask = 0; // detail IOCTL 缺失能力位图。
        long r0DetailLastStatus = 0;        // detail IOCTL 最近 NTSTATUS。
        std::uint64_t r0ReadOperationCount = 0; // KTHREAD 读操作计数。
        std::uint64_t r0WriteOperationCount = 0; // KTHREAD 写操作计数。
        std::uint64_t r0OtherOperationCount = 0; // KTHREAD 其他操作计数。
        std::uint64_t r0ReadTransferCount = 0; // KTHREAD 读传输字节。
        std::uint64_t r0WriteTransferCount = 0; // KTHREAD 写传输字节。
        std::uint64_t r0OtherTransferCount = 0; // KTHREAD 其他传输字节。
    };

    // ThreadInspectRefreshResult：线程细节异步刷新结果。
    struct ThreadInspectRefreshResult
    {
        std::vector<ThreadInspectItem> rows; // 线程行数据。
        QString diagnosticText;              // 诊断文本。
        std::uint64_t elapsedMs = 0;         // 刷新耗时（毫秒）。
    };

    // TextRefreshResult：令牌页/PEB 页文本刷新结果。
    struct TextRefreshResult
    {
        QString detailText;               // 展示文本内容。
        QString diagnosticText;           // 诊断文本。
        std::uint64_t elapsedMs = 0;      // 刷新耗时（毫秒）。
    };

    // KernelCallbackInspectItem：PEB.KernelCallbackTable 中的单个用户态回调入口。
    struct KernelCallbackInspectItem
    {
        std::uint32_t index = 0;          // 回调表索引。
        QString callbackName;             // 公开 KERNEL_CALLBACK_TABLE 字段名。
        QString addressText;              // 当前远程回调地址。
        QString moduleText;               // 地址所属模块名，未命中时为空。
        QString modulePath;               // 地址所属模块完整路径，供 tooltip 展示。
        QString moduleOffsetText;         // callback - moduleBase。
        QString protectionText;           // VirtualQueryEx 返回的页面保护属性。
        QString statusText;               // 正常/空/非模块可执行内存等审计状态。
        bool suspicious = false;          // true 时在表格中使用警告色。
    };

    // KernelCallbackRefreshResult：内核回调表页的一次异步读取结果。
    struct KernelCallbackRefreshResult
    {
        std::vector<KernelCallbackInspectItem> rows; // 有效表长内的回调入口。
        QString pebKindText;                        // NativePEB / Wow64PEB。
        QString pebAddressText;                     // 本次读取的 PEB 地址。
        QString tableAddressText;                   // KernelCallbackTable 地址。
        QString diagnosticText;                     // 权限、边界或模块枚举诊断。
        std::uint64_t elapsedMs = 0;                // 刷新耗时（毫秒）。
    };

    // SectionRefreshResult：进程 SectionObject / ControlArea 异步查询结果。
    struct SectionRefreshResult
    {
        QString detailText;              // 展示文本内容。
        QString diagnosticText;          // 诊断文本。
        std::uint64_t elapsedMs = 0;     // 刷新耗时（毫秒）。
    };

    // HotkeyInspectItem：进程热键页单行数据。
    struct HotkeyInspectItem
    {
        QString objectText;              // HWND/HMENU/资源/快捷方式路径。
        std::uint32_t hotkeyId = 0;      // 菜单命令 ID / Accelerator 命令 ID / 0。
        std::uint32_t modifiers = 0;     // MOD_ALT/MOD_CONTROL/MOD_SHIFT/MOD_WIN 位图。
        std::uint32_t virtualKey = 0;    // 虚拟键码，未知时为 0。
        QString hotkeyText;              // 可读快捷键文本。
        std::uint32_t processId = 0;     // 所属进程 ID。
        std::uint32_t threadId = 0;      // 所属窗口线程 ID，非窗口来源为 0。
        QString processName;             // 所属进程名。
        QString sourceText;              // 来源：窗口热键/菜单/Accelerator/.lnk 等。
        QString detailText;              // 额外上下文。
        bool hasR0MutationSnapshot = false; // 是否携带可提交的完整 R0 tagHOTKEY 快照。
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0MutationSnapshot{}; // 编辑/删除的预期值快照。
    };

    // HotkeyInspectRefreshResult：进程热键异步刷新结果。
    struct HotkeyInspectRefreshResult
    {
        std::vector<HotkeyInspectItem> rows; // 热键行数据。
        QString diagnosticText;              // 诊断文本。
        std::uint64_t elapsedMs = 0;         // 刷新耗时（毫秒）。
    };

    // KeyboardHookInspectItem：键盘页钩子表单行数据。
    struct KeyboardHookInspectItem
    {
        QString objectText;       // tagHOOK 对象地址。
        QString typeText;         // WH_KEYBOARD / WH_KEYBOARD_LL。
        QString scopeText;        // 线程链 / 全局链。
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString procedureText;    // 回调地址或 R0 保存的回调偏移。
        QString moduleText;       // 模块基址或 module id。
        QString sourceText;       // 来源链。
        QString flagsText;        // tagHOOK flags。
        QString detailText;       // 链头、next、threadInfo 等诊断字段。
    };

    // KeyboardInspectRefreshResult：键盘页异步刷新结果。
    struct KeyboardInspectRefreshResult
    {
        std::vector<HotkeyInspectItem> hotkeyRows;     // 热键行数据。
        std::vector<KeyboardHookInspectItem> hookRows; // 钩子行数据。
        QString diagnosticText;                        // 诊断文本。
        std::uint64_t elapsedMs = 0;                   // 刷新耗时（毫秒）。
    };

    // StaticDetailRefreshResult：进程静态详情后台补齐结果。
    struct StaticDetailRefreshResult
    {
        ks::process::ProcessRecord processRecord; // 后台读取到的最新进程记录。
        QString diagnosticText;                   // 失败或降级原因。
        std::uint64_t elapsedMs = 0;              // 后台查询耗时（毫秒）。
        bool queryOk = false;                     // true 表示基础静态详情读取成功。
    };

    // DetailOverviewRefreshResult：详细信息页的运行时/安全/GUI 数据后台快照。
    // values 使用稳定键名，避免 UI 控件数量增加时继续膨胀结果结构。
    struct DetailOverviewRefreshResult
    {
        std::string identityKey;             // PID + 创建时间，用于拒绝 PID 复用后的旧结果。
        QHash<QString, QString> values;      // 各详细字段的展示文本。
        QString diagnosticText;              // 权限不足、目标退出等诊断信息。
        std::uint64_t elapsedMs = 0;         // 后台查询耗时（毫秒）。
        bool queryOk = false;                // 至少成功读取一项运行时字段。
    };

    // ActionPrivilegeRefreshResult：操作页令牌特权后台查询结果。
    struct ActionPrivilegeRefreshResult
    {
        std::string identityKey;                              // PID + 创建时间，拒绝 PID 复用后的旧结果。
        std::vector<ks::process::TokenPrivilegeInfo> privileges; // Windows SDK 完整特权目录状态。
        QString diagnosticText;                              // R3/R0 查询失败诊断。
        std::uint64_t ticket = 0;                            // 防止异步结果乱序覆盖。
        bool queryOk = false;                                // 是否成功读取目标令牌。
        bool usedR0 = false;                                 // true 表示 R3 失败后由 R0 查询完成。
    };

private:
    // ======== UI 初始化 ========
    // changeEvent 作用：
    // - 监听调色板/样式变化；
    // - 在深浅色切换后重建内部样式，避免进程详情页残留白底。
    // 调用方式：Qt 自动触发。
    // 参数 event：变更事件对象。
    // 返回：无。
    void changeEvent(QEvent* event) override;

    void initializeUi();
    // applyThemeStyle 作用：
    // - 给详情窗口内部控件统一应用深浅色样式；
    // - 显式强制 Window/Base 颜色，规避 Win11 自动背景接管问题。
    // 调用方式：initializeUi 完成控件创建后调用；changeEvent 中再次调用。
    // 参数：无。
    // 返回：无。
    void applyThemeStyle();
    void initializeDetailTab();
    // initializePerformanceTab 作用：创建性能历史页，图表横向绘制并在滚动内容区纵向排列。
    void initializePerformanceTab();
    void initializeCpuCoreTab();
    void initializeThreadTab();
    void initializeActionTab();
    void initializeModuleTab();
    // initializeEmbeddedHandleTab 作用：创建按需加载的当前进程句柄审计容器。
    void initializeEmbeddedHandleTab();
    // ensureEmbeddedHandleView 作用：首次进入句柄页时创建 HandleDock 并锁定当前 PID。
    void ensureEmbeddedHandleView();
    // initializeEmbeddedMemoryTab 作用：创建精简内存分析的惰性容器。
    void initializeEmbeddedMemoryTab();
    void ensureEmbeddedMemoryView();
    // initializeEmbeddedNetworkTab 作用：创建按当前 PID 过滤的网络连接惰性容器。
    void initializeEmbeddedNetworkTab();
    void ensureEmbeddedNetworkView();
    // initializeSoundSourceTab：
    // - 作用：复用声音来源页并锁定当前进程 PID；
    // - 调用：用户首次进入“声音来源”页时由 ensureTabContentInitialized 调用；
    // - 输入/返回：目标 PID 来自 m_baseRecord，无返回值。
    void initializeSoundSourceTab();
    // initializeEmbeddedWindowTab 作用：创建按当前 PID 过滤的窗口列表惰性容器。
    void initializeEmbeddedWindowTab();
    void ensureEmbeddedWindowView();
    void initializeTokenTab();
    // initializeKernelObjectTab 作用：
    // - 构建 Process Detail Evidence 页面；
    // - 展示 R0 扩展字段、DynData capability、字段来源和可用性；
    // - 仅显示 ObjectTable/SectionObject 可用状态，不在本页直接枚举句柄表或 Section。
    // 调用方式：initializeUi 中创建 m_kernelObjectTab 后调用。
    // 参数：无。
    // 返回：无。
    void initializeKernelObjectTab();
    // initializeHotkeyTab 作用：
    // - 构建“进程热键”页面；
    // - 覆盖窗口激活热键、菜单快捷键、PE Accelerator 资源和 .lnk 快捷方式热键。
    // 调用方式：initializeUi 中创建 m_hotkeyTab 后调用。
    // 参数：无。
    // 返回：无。
    void initializeHotkeyTab();
    // initializeKeyboardTab 作用：
    // - 构建“键盘”页面；
    // - 同时展示热键检测结果和 R0 键盘钩子链枚举结果。
    // 调用方式：initializeUi 中创建 m_keyboardTab 后调用。
    // 参数：无。
    // 返回：无。
    void initializeKeyboardTab();
    // initializePluginTab 作用：
    // - 构建当前进程的独立插件入口；
    // - 菜单直接扫描 plugin\<id>\plugin.json 动态重建，详情窗口不加载插件代码。
    void initializePluginTab();
    // initializeTokenSwitchTab 作用：
    // - 构建“令牌开关”页面；
    // - 提供复选框批量控制 Token 开关位，并提供刷新/应用按钮。
    // 调用方式：initializeUi 中创建 m_tokenSwitchTab 后调用。
    // 参数：无。
    // 返回：无。
    void initializeTokenSwitchTab();
    void initializePebTab();
    // initializeKernelCallbackTab 作用：
    // - 构建 PEB.KernelCallbackTable 独立审计页；
    // - 表格展示回调名、地址、模块偏移、内存保护和异常状态。
    void initializeKernelCallbackTab();
    // ensureTabContentInitialized 作用：仅在用户首次访问页面时构造该页控件，避免开窗阶段同步创建全部功能页。
    void ensureTabContentInitialized(QWidget* tab);
    void initializeConnections();

    // ======== 详情页刷新 ========
    void refreshDetailTabTexts();
    void refreshPerformanceHistoryCharts();
    void refreshCpuCoreView();
    // requestAsyncStaticDetailRefresh 作用：
    // - 在后台补齐路径、命令行、用户、签名等慢字段；
    // - 避免在窗口构造或周期同步时阻塞 UI 线程。
    // 调用方式：构造完成后、外部快照字段不完整时调用。
    // 参数 includeSignatureCheck：true 表示后台允许执行 WinVerifyTrust 签名校验。
    // 返回：无。
    void requestAsyncStaticDetailRefresh(bool includeSignatureCheck);
    // applyStaticDetailRefreshResult 作用：
    // - 在主线程合并后台静态详情结果；
    // - 只使用非空/有效字段覆盖当前缓存。
    // 调用方式：requestAsyncStaticDetailRefresh 的后台任务完成后投递。
    // 参数 refreshResult：后台查询结果。
    // 返回：无。
    void applyStaticDetailRefreshResult(const StaticDetailRefreshResult& refreshResult);
    // requestAsyncDetailOverviewRefresh 作用：后台读取详细页的资源、安全、缓解策略与 GUI 统计。
    void requestAsyncDetailOverviewRefresh();
    // applyDetailOverviewRefreshResult 作用：校验身份后回填详细页的运行时字段。
    void applyDetailOverviewRefreshResult(const DetailOverviewRefreshResult& refreshResult);
    // requestAsyncActionPrivilegeRefresh 作用：后台查询操作页全部令牌特权，R3 失败时允许 R0 回退。
    void requestAsyncActionPrivilegeRefresh();
    // applyActionPrivilegeRefreshResult 作用：在 UI 线程按特权状态更新复选框与按钮。
    void applyActionPrivilegeRefreshResult(const ActionPrivilegeRefreshResult& refreshResult);
    // requestInitialRefreshForCurrentTab 作用：
    // - 按当前 Tab 懒启动首次重型刷新；
    // - 打开窗口时只展示“详细信息”页，不立即扫描模块/PEB/令牌。
    // 调用方式：currentChanged 信号和构造完成后调用。
    // 参数：无。
    // 返回：无。
    void requestInitialRefreshForCurrentTab();
    // refreshKernelObjectTabTexts 作用：
    // - 根据 m_baseRecord 刷新“Process Detail Evidence”页所有标签；
    // - DynData 未命中时显示 Unavailable，避免误导用户可直接进入后续句柄/Section 枚举。
    // 调用方式：refreshDetailTabTexts 和 updateBaseRecord 间接调用。
    // 参数：无。
    // 返回：无。
    void refreshKernelObjectTabTexts();
    void refreshParentProcessSection();
    void updateWindowTitle();
    void requestAsyncThreadInspectRefresh();
    void applyThreadInspectResult(const ThreadInspectRefreshResult& refreshResult);
    void updateThreadInspectStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncSelectedThreadRuntimeSample 作用：
    // - 对线程表当前选中 TID 执行 PDB deep runtime 小字段采样；
    // - 只传 TID/PID 和 JSON offset/size，不把 ETHREAD 地址作为输入；
    // - 后台执行，避免 UI 线程因为旧驱动或大量字段阻塞。
    // 调用方式：线程页“采样PDB字段”按钮触发。
    // 参数：无。
    // 返回：无。
    void requestAsyncSelectedThreadRuntimeSample();
    // openSelectedThreadStackWindow 作用：
    // - 根据线程页当前选中行打开 Phase-8 调用栈窗口；
    // - 使用最近一次线程刷新缓存中的 TID/PID/栈边界构造目标。
    // 调用方式：线程页按钮或表格双击。
    // 参数：无。
    // 返回：无。
    void openSelectedThreadStackWindow();
    // resolveSelectedThreadModulePathForUpload 作用：
    // - 输入为线程表当前行；
    // - 处理时读取 ThreadInspectItem 的 start/win32Start 地址，并在模块缓存中查找所属模块路径；
    // - 返回：命中时为模块文件路径，未命中时返回空字符串且 errorTextOut 写入原因。
    QString resolveSelectedThreadModulePathForUpload(QString* errorTextOut) const;

    // ======== 令牌页/PEB页刷新 ========
    void requestAsyncTokenRefresh();
    void requestAsyncPebRefresh();
    void applyTokenRefreshResult(const TextRefreshResult& refreshResult);
    void applyPebRefreshResult(const TextRefreshResult& refreshResult);
    // requestAsyncKernelCallbackRefresh 作用：后台读取 Native/Wow64 PEB 的 KernelCallbackTable。
    void requestAsyncKernelCallbackRefresh();
    // applyKernelCallbackRefreshResult 作用：在 UI 线程回填内核回调表审计结果。
    void applyKernelCallbackRefreshResult(const KernelCallbackRefreshResult& refreshResult);
    // rebuildKernelCallbackTable 作用：根据最近一次缓存重建回调表格。
    void rebuildKernelCallbackTable();
    // requestAsyncHotkeyRefresh 作用：
    // - 后台扫描当前进程相关热键来源；
    // - 不直接访问驱动，不阻塞详情窗口 UI 线程。
    // 调用方式：热键页首刷或点击刷新按钮。
    // 参数：无。
    // 返回：无。
    void requestAsyncHotkeyRefresh();
    // applyHotkeyRefreshResult 作用：
    // - 在主线程回填热键检测结果；
    // - 重建表格并更新状态标签。
    // 调用方式：requestAsyncHotkeyRefresh 后台任务完成后投递。
    // 参数 refreshResult：后台扫描结果。
    // 返回：无。
    void applyHotkeyRefreshResult(const HotkeyInspectRefreshResult& refreshResult);
    // editSelectedHotkey：验证当前选中来源并通过稳定公开接口写入窗口或 .lnk 热键。
    // deleteSelectedHotkey：删除选中的公开接口热键或快照保护的 R0 RegisterHotKey 项。
    void deleteSelectedHotkey();
    void editSelectedHotkey();
    void rebuildHotkeyTable();
    void updateHotkeyStatusLabel(const QString& statusText, bool refreshing);
    void requestAsyncKeyboardRefresh();
    void applyKeyboardRefreshResult(const KeyboardInspectRefreshResult& refreshResult);
    void rebuildKeyboardHotkeyTable();
    void rebuildKeyboardHookTable();
    void updateKeyboardStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncSectionRefresh 作用：
    // - 通过 ArkDriverClient 异步查询 R0 SectionObject / ControlArea；
    // - 只传 PID，不把 UI 看到的内核地址传回驱动。
    // 调用方式：内核对象页刷新按钮或首次初始化后调用。
    // 参数：无。
    // 返回：无。
    void requestAsyncSectionRefresh();
    // applySectionRefreshResult 作用：
    // - 在主线程回填 Section/ControlArea 详情文本；
    // - 同步刷新状态标签。
    // 调用方式：后台任务完成后 invokeMethod 调用。
    // 参数 refreshResult：后台查询结果。
    // 返回：无。
    void applySectionRefreshResult(const SectionRefreshResult& refreshResult);
    // refreshTokenSwitchStates 作用：
    // - 读取当前目标进程令牌开关状态；
    // - 把读取结果同步到“令牌开关”页的复选框。
    // 调用方式：点击刷新按钮或窗口首次初始化后调用。
    // 参数：无。
    // 返回：无。
    void refreshTokenSwitchStates();
    // applyTokenSwitchStates 作用：
    // - 把“令牌开关”页复选框状态写回目标进程令牌；
    // - 底层通过 NtSetInformationToken（NtSetTokenInformation）逐项应用。
    // 调用方式：点击应用按钮后调用。
    // 参数：无。
    // 返回：无。
    void applyTokenSwitchStates();
    // applyRawTokenInformation 作用：
    // - 从“原始设置”区域读取 TokenInformationClass 与原始负载；
    // - 直接调用 NtSetInformationToken 提交，覆盖所有可尝试的信息类。
    // 调用方式：点击“应用原始设置”按钮后调用。
    // 参数：无。
    // 返回：无。
    void applyRawTokenInformation();

    // ======== 模块页刷新 ========
    void requestAsyncModuleRefresh(bool forceRefresh);
    void applyModuleRefreshResult(const ModuleRefreshResult& refreshResult);
    void rebuildModuleTable();
    void updateModuleStatusLabel(const QString& statusText, bool refreshing);
    // requestAsyncDllHijackScan：只读扫描程序目录与实际加载模块，
    // 使用签名可信的架构匹配系统 DLL 作为基线，不加载任何待检 DLL。
    void requestAsyncDllHijackScan();

    // ======== 模块表右键 ========
    void showModuleContextMenu(const QPoint& localPosition);
    void copyCurrentModuleCell();
    void copyCurrentModuleRow();
    // showCurrentModuleDetailDialog 作用：
    // - 打开当前选中模块的只读详情弹窗；
    // - 输入来自模块表当前行和 m_moduleRecords 缓存；
    // - 返回：无，弹窗关闭后自动释放。
    void showCurrentModuleDetailDialog();
    void openCurrentModuleFolder();
    void unloadCurrentModule();
    void suspendCurrentModuleThread();
    void resumeCurrentModuleThread();
    void terminateCurrentModuleThread();

    // ======== 操作页动作 ========
    void executeTerminateProcessAction();
    // executeTerminateProcessComboAction 作用：
    // - 执行与进程列表右键“结束进程”一致的多方法组合结束动作；
    // - 输入为当前详情页绑定 PID，处理过程按固定方法链逐项尝试；
    // - 返回值：无，动作结果统一写日志。
    void executeTerminateProcessComboAction();
    void executeTerminateThreadsAction();
    void executeR0SuspendSelectedThreadAction();
    void executeR0ResumeSelectedThreadAction();
      void executeDriverThreadAction(unsigned long action, unsigned long terminateMethod = KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NONE);
      void executeExperimentalFirmwareRebootAction();
    void executeR0TerminateSelectedThreadAction();
    void executeSelectedTerminateAction();
    void executeSuspendProcessAction();
    void executeResumeProcessAction();
    void executeSetCriticalAction(bool enableCritical);
    void executeSetPriorityAction();
    // executeApplyActionPrivileges 作用：把操作页有变化的复选框通过指定 R3/R0 路径提交。
    void executeApplyActionPrivileges(bool useR0);
    // refreshActionAffinityControls 作用：读取跨组 CPU Set 亲和性并回填操作页处理器矩阵。
    void refreshActionAffinityControls();
    // confirmActionAffinityRisk 作用：实际应用或持久化前展示明确风险并等待用户继续。
    bool confirmActionAffinityRisk(bool persistenceSave);
    // applyActionAffinityRule 作用：将稳定 group/index 规则映射为 CPU Set 并写入当前进程。
    void applyActionAffinityRule(const ks::process::ProcessAffinityRule& affinityRule);
    // toggleActionAffinityCore 作用：切换一个稳定逻辑处理器坐标，始终保证至少保留一个。
    void toggleActionAffinityCore(
        const ks::process::LogicalProcessorCoordinate& coordinate,
        bool enabled);
    // rebuildActionAffinityCoreButtons 作用：按 processor group 重建动态处理器按钮矩阵。
    void rebuildActionAffinityCoreButtons();
    // updateActionAffinityCoreButtons 作用：依据当前 CPU Set 快照刷新按钮主题色状态。
    void updateActionAffinityCoreButtons();
    // refreshActionAffinityPersistenceControl 作用：读取当前可执行文件的注册表亲和性规则并同步开关状态。
    void refreshActionAffinityPersistenceControl();
    // executeSetPriorityActionById 作用：
    // - 根据菜单/按钮传入的优先级 ID 设置目标进程优先级；
    // - 输入 priorityActionId 对应 Idle/BelowNormal/Normal/AboveNormal/High/Realtime；
    // - 返回值：无，底层调用结果写日志。
    void executeSetPriorityActionById(int priorityActionId);
    // executeSetEfficiencyModeAction 作用：
    // - 开启或关闭目标进程 Windows 效率模式；
    // - 输入 enableEfficiencyMode 为 true 时开启，false 时关闭；
    // - 返回值：无，底层调用结果写日志。
    void executeSetEfficiencyModeAction(bool enableEfficiencyMode);
    // executeOpenProcessFolderAction 作用：
    // - 在资源管理器中定位当前进程映像文件所在位置；
    // - 输入来自 m_baseRecord.pid，不需要额外参数；
    // - 返回值：无，底层调用结果写日志。
    void executeOpenProcessFolderAction();
    // executeRefreshPplProtectionLevelAction 作用：
    // - 通过 R3 ProcessProtectionLevelInfo 刷新当前进程 PPL 枚举；
    // - 输入来自 m_baseRecord.pid，刷新后更新详情页缓存与文本；
    // - 返回值：无，查询结果写日志。
    void executeRefreshPplProtectionLevelAction();
    // executeR0TerminateProcessAction 作用：
    // - 通过 ArkDriverClient 请求 R0 结束当前进程；
    // - 输入来自 m_baseRecord.pid，不直接 DeviceIoControl；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0TerminateProcessAction();
    // executeR0SuspendProcessAction 作用：
    // - 通过 ArkDriverClient 请求 R0 挂起当前进程；
    // - 输入来自 m_baseRecord.pid，不直接 DeviceIoControl；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0SuspendProcessAction();
    // executeR0SetPplProtectionAction 作用：
    // - 通过 ArkDriverClient 设置目标进程 PS_PROTECTION 原始字节；
    // - 输入 protectionLevel 为 Signer<<4 | Type，levelDisplayText 用于日志展示；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0SetPplProtectionAction(std::uint8_t protectionLevel, const QString& levelDisplayText);
    // executeR0SetProcessHiddenAction 作用：
    // - 通过 ArkDriverClient 执行可恢复隐藏/取消隐藏；
    // - 输入 hidden=true 表示隐藏，visibilityFlags 指定改 PID/断链策略；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0SetProcessHiddenAction(bool hidden, unsigned long visibilityFlags = 0UL);
    // executeR0ClearProcessHiddenAction 作用：
    // - 通过 ArkDriverClient 清空驱动内全部可恢复隐藏标记；
    // - 输入无，影响驱动记录的全部目标；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0ClearProcessHiddenAction();
    // executeR0SetBreakOnTerminationAction 作用：
    // - 通过 ArkDriverClient 设置或清除 BreakOnTermination；
    // - 输入 enabled=true 表示启用，false 表示关闭；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0SetBreakOnTerminationAction(bool enabled);
    // executeR0DisableApcInsertionAction 作用：
    // - 通过 ArkDriverClient 清除当前进程现有线程 ApcQueueable 位；
    // - 输入来自 m_baseRecord.pid；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0DisableApcInsertionAction();
    // executeR0DkomRemoveFromCidTableAction 作用：
    // - 通过 ArkDriverClient 从 PspCidTable 删除当前进程 CID 表项；
    // - 输入来自 m_baseRecord.pid；
    // - 返回值：无，驱动调用摘要写日志。
    void executeR0DkomRemoveFromCidTableAction();
    void executeInjectDllAction();
    void executeInjectShellcodeAction();

    // ======== 工具函数 ========
    QIcon resolveProcessIcon(const std::string& processPath, int iconPixelSize);
    QString formatModuleSizeText(std::uint32_t moduleSizeBytes) const;
    QString formatHexText(std::uint64_t value) const;
    // readBinaryFile 作用：读取二进制文件到缓冲区，并沿用调用方传入的同一 kLogEvent 输出过程日志。
    // 调用方式：由注入动作函数传入 actionEvent，以保证“动作+文件读取”日志链路一致。
    // 参数 filePath：文件路径；bufferOut：输出缓冲区；errorTextOut：错误信息；actionEvent：同链路日志事件对象。
    // 返回值：读取成功返回 true，失败返回 false。
    bool readBinaryFile(
        const QString& filePath,
        std::vector<std::uint8_t>& bufferOut,
        std::string& errorTextOut,
        const kLogEvent& actionEvent) const;
    // showActionResultMessage 作用：统一记录动作结果（不弹框），并复用外层传入的同一 kLogEvent 维持调用链。
    // 调用方式：动作函数先创建 kLogEvent，再将该事件对象传入本函数。
    // 参数 title：动作标题；actionOk：动作是否成功；detailText：动作详情；actionEvent：同链路日志事件对象。
    // 返回值：无。
    void showActionResultMessage(const QString& title, bool actionOk, const std::string& detailText, const kLogEvent& actionEvent);
    ks::process::ProcessModuleRecord* selectedModuleRecord();

private:
    // ======== 当前绑定进程基础数据 ========
    ks::process::ProcessRecord m_baseRecord;   // 当前窗口绑定进程快照。
    std::string m_identityKey;                 // PID+CreateTime 组成的 identity 字符串。

    // ======== 根布局与 Tabs ========
    QHBoxLayout* m_rootLayout = nullptr;       // 左侧导航与右侧页面的根布局。
    QWidget* m_tabNavigation = nullptr;        // 左侧单列常显的页面导航按钮容器。
    QButtonGroup* m_tabNavigationButtonGroup = nullptr; // 导航按钮与 Tab 索引的映射。
    QTabWidget* m_tabWidget = nullptr;         // 页面栈与现有切换/懒加载逻辑的容器。
    QSet<QWidget*> m_initializedTabs;           // 已构造控件树的页面，避免重复初始化。
    QSet<QObject*> m_connectedSignalSources;    // 已连接的 sender，支持页面按需构造后补接信号。
    QWidget* m_detailTab = nullptr;            // “详细信息”页。
    QWidget* m_performanceTab = nullptr;       // “性能”页。
    QWidget* m_cpuCoreTab = nullptr;           // “CPU 核心”页。
    QWidget* m_threadTab = nullptr;            // “线程”页。
    QWidget* m_actionTab = nullptr;            // “操作”页。
    QWidget* m_moduleTab = nullptr;            // “模块”页。
    QWidget* m_embeddedHandleTab = nullptr;    // 当前进程“句柄”内嵌审计页。
    QWidget* m_embeddedMemoryTab = nullptr;    // 当前进程精简“内存”内嵌页。
    QWidget* m_embeddedNetworkTab = nullptr;   // 当前进程“网络连接”内嵌页。
    QWidget* m_soundSourceTab = nullptr;       // 当前进程“声音来源”内嵌页。
    QWidget* m_embeddedWindowTab = nullptr;    // 当前进程“窗口列表”内嵌页。
    QWidget* m_tokenTab = nullptr;             // “令牌”页。
    QWidget* m_tokenSwitchTab = nullptr;       // “令牌开关”页。
    QWidget* m_kernelObjectTab = nullptr;      // “Process Detail Evidence”页。
    QWidget* m_hotkeyTab = nullptr;            // “进程热键”页。
    QWidget* m_keyboardTab = nullptr;          // “键盘”页。
    QWidget* m_pluginTab = nullptr;            // “插件”页。
    QWidget* m_pebTab = nullptr;               // “PEB”页。
    QWidget* m_kernelCallbackTab = nullptr;    // “内核回调表”页。

    // ======== 插件页控件 ========
    QToolButton* m_pluginTargetMenuButton = nullptr; // 当前进程的“插件 → <插件名>”入口。
    QMenu* m_pluginTargetMenu = nullptr;             // 由本地 plugin.json 动态重建。

    // ======== 详细信息页控件 ========
    QVBoxLayout* m_detailLayout = nullptr;     // 详细页总布局。
    QLabel* m_processIconLabel = nullptr;      // 顶部进程图标（40px）。
    QLabel* m_processTitleLabel = nullptr;     // 顶部标题（进程名 + PID）。
    QLineEdit* m_pathLineEdit = nullptr;       // 程序路径（只读）。
    QPushButton* m_copyPathButton = nullptr;   // 复制路径按钮。
    QPushButton* m_openPathFolderButton = nullptr; // 打开路径按钮。
    QPushButton* m_openFileDetailButton = nullptr; // 转到文件详细信息窗口。
    QPushButton* m_refreshDetailOverviewButton = nullptr; // 刷新详细页运行时字段。
    QLabel* m_detailOverviewStatusLabel = nullptr; // 详细页运行时字段刷新状态。
    QLineEdit* m_commandLineEdit = nullptr;    // 启动命令行（只读）。
    QPushButton* m_copyCommandButton = nullptr; // 复制命令行按钮。
    QLabel* m_parentIconLabel = nullptr;       // 父进程图标（20px）。
    QLabel* m_parentInfoLabel = nullptr;       // 父进程名 + PID。
    QPushButton* m_detailOpenHandleDockButton = nullptr; // 详情页跳转到句柄 Dock。
    QPushButton* m_openHandleDockButton = nullptr; // 操作页跳转到句柄 Dock。
    QPushButton* m_openMemoryDockButton = nullptr; // 跳转到内存 Dock。
    QPushButton* m_openNetworkDockButton = nullptr; // 跳转到网络 Dock。
    QPushButton* m_openWindowDockButton = nullptr; // 跳转到窗口 Dock。
    QPushButton* m_gotoParentButton = nullptr; // 转到父进程按钮。

    QLabel* m_detailStartTimeValue = nullptr;  // 启动时间值。
    QLabel* m_detailUserValue = nullptr;       // 用户值。
    QLabel* m_detailAdminValue = nullptr;      // 是否管理员值。
    QLabel* m_detailArchitectureValue = nullptr; // 架构值。
    QLabel* m_detailPriorityValue = nullptr;   // 优先级值。
    QLabel* m_detailSessionValue = nullptr;    // 会话 ID 值。
    QLabel* m_detailThreadCountValue = nullptr; // 线程数值。
    QLabel* m_detailHandleCountValue = nullptr; // 句柄数值。
    QLabel* m_detailCpuValue = nullptr;        // CPU 当前占用值。
    QLabel* m_detailCpuCoreValue = nullptr;    // CPU 单核等效占用值。
    QLabel* m_detailRamValue = nullptr;        // RAM 当前占用值。
    QLabel* m_detailDiskValue = nullptr;       // DISK 当前占用值。
    QLabel* m_detailSignatureValue = nullptr;  // 数字签名状态值。
    QHash<QString, QLabel*> m_detailExtraValues; // 详细页扩展字段的值控件映射。
    DetailOverviewRefreshResult m_detailOverviewResult; // 最近一次运行时扩展字段快照。
    bool m_detailOverviewRefreshing = false;   // 扩展字段后台查询是否进行中。
    std::uint64_t m_detailOverviewRefreshTicket = 0; // 防止异步回填乱序。

    // ======== 性能页控件与历史 ========
    QLabel* m_performanceHistoryStatusLabel = nullptr; // 性能页历史范围与样本数状态。
    QWidget* m_performanceCpuChart = nullptr;          // CPU 图表。
    QWidget* m_performanceCpuCoreChart = nullptr;      // CPU 单核等效图表。
    QWidget* m_performanceMemoryChart = nullptr;       // 内存图表。
    QWidget* m_performanceDiskChart = nullptr;         // 磁盘图表。
    QWidget* m_performanceNetworkChart = nullptr;      // 网络收发图表。
    QWidget* m_performanceGpuChart = nullptr;          // GPU 图表。
    std::deque<PerformanceHistorySample> m_performanceHistory; // 当前详情窗口的定长历史序列。

    // ======== CPU 核心页控件与区间快照 ========
    QLabel* m_cpuCoreTitleLabel = nullptr;             // 页面标题，主题切换时刷新前景色。
    QLabel* m_cpuCoreDescriptionLabel = nullptr;       // 页面说明，主题切换时刷新次级文本色。
    QLabel* m_cpuCoreStatusLabel = nullptr;            // ETW 运行/采样/丢事件状态。
    QLabel* m_cpuCoreSystemValueLabel = nullptr;       // 进程全系统归一化占用汇总。
    QLabel* m_cpuCoreEquivalentValueLabel = nullptr;   // 进程单核等效占用汇总。
    QWidget* m_processCpuCoreGrid = nullptr;            // 当前进程逐逻辑处理器折线矩阵。
    QWidget* m_threadCpuCoreGrid = nullptr;             // 按总占用排序、可点击展开的线程折线矩阵。
    CpuCoreViewSample m_cpuCoreViewSample;              // 页面未构造时也保留最新快照。

    // ======== 线程页控件 ========
    QVBoxLayout* m_threadLayout = nullptr;     // 线程页总布局。
    QPushButton* m_refreshThreadInspectButton = nullptr; // 刷新线程细节按钮。
    QPushButton* m_sampleThreadRuntimeButton = nullptr; // 当前线程 PDB 字段采样按钮。
    QLabel* m_threadInspectStatusLabel = nullptr; // 线程细节刷新状态。
    QTableWidget* m_threadInspectTable = nullptr; // 线程细节表格。
    CodeEditorWidget* m_threadRuntimeSampleOutput = nullptr; // 当前线程 PDB deep 采样详情。

    // ======== 操作页控件 ========
    QVBoxLayout* m_actionLayout = nullptr;     // 操作页总布局。
    QComboBox* m_terminateActionCombo = nullptr; // 结束方案下拉框。
    QPushButton* m_executeTerminateActionButton = nullptr; // 执行当前结束方案按钮。
    QPushButton* m_suspendProcessButton = nullptr; // 挂起进程。
    QPushButton* m_resumeProcessButton = nullptr; // 恢复进程。
    QPushButton* m_setCriticalButton = nullptr; // 设为关键进程。
    QPushButton* m_clearCriticalButton = nullptr; // 取消关键进程。

    QGroupBox* m_affinityActionGroup = nullptr; // CPU 亲和性操作区域。
    QLabel* m_affinityDescriptionLabel = nullptr; // 根据实际 processor group 数量显示符号说明。
    QLabel* m_affinityStatusLabel = nullptr; // CPU 亲和性当前模式与操作结果。
    QCheckBox* m_affinityPersistenceCheckBox = nullptr; // 是否为当前完整可执行路径保存 CPU 亲和性规则。
    QPushButton* m_affinityRefreshButton = nullptr; // 重新读取亲和性。
    QPushButton* m_affinityAllCoresButton = nullptr; // 清除 CPU Set 限制并启用全部可用处理器。
    QGridLayout* m_affinityMatrixLayout = nullptr; // 按 processor group 动态排列逻辑处理器。
    std::vector<QToolButton*> m_affinityCoreButtons; // 与亲和性快照 processors 顺序一致的按钮。
    ks::process::ProcessAffinitySnapshot m_actionAffinitySnapshot; // 最近一次跨组亲和性查询快照。
    bool m_actionAffinityReadable = false; // 当前亲和性是否成功读取。

    QGroupBox* m_privilegeActionGroup = nullptr; // 令牌特权复选框区域。
    QLabel* m_actionPrivilegeStatusLabel = nullptr; // 特权查询与应用状态。
    QPushButton* m_actionPrivilegeRefreshButton = nullptr; // 重新查询特权。
    QPushButton* m_applyActionPrivilegeR3Button = nullptr; // 通过 R3 应用变化。
    QPushButton* m_applyActionPrivilegeR0Button = nullptr; // 通过 R0 应用变化。
    std::vector<QCheckBox*> m_actionPrivilegeCheckBoxes; // 与 KnownTokenPrivilegeNames 顺序一致。
    std::vector<ks::process::TokenPrivilegeInfo> m_actionPrivilegeSnapshot; // 最近一次查询快照。
    bool m_actionPrivilegeReadable = false; // 当前快照是否可用于编辑。
    bool m_actionPrivilegeRefreshing = false; // 查询或应用是否正在后台执行。
    bool m_actionPrivilegeInitialRefreshStarted = false; // 操作页首次特权查询是否已启动。
    std::uint64_t m_actionPrivilegeRefreshTicket = 0; // 防止异步结果乱序。

    QComboBox* m_priorityCombo = nullptr;      // 优先级选择框。
    QPushButton* m_applyPriorityButton = nullptr; // 应用优先级按钮。
    QPushButton* m_openProcessFolderButton = nullptr; // 打开进程所在目录按钮。
    QPushButton* m_refreshPplProtectionButton = nullptr; // 手动刷新 PPL 保护级别按钮。
    QPushButton* m_enableEfficiencyModeButton = nullptr; // 开启效率模式按钮。
    QPushButton* m_disableEfficiencyModeButton = nullptr; // 关闭效率模式按钮。
    QPushButton* m_r0TerminateProcessButton = nullptr; // R0 结束进程按钮。
    QPushButton* m_r0SuspendProcessButton = nullptr; // R0 挂起进程按钮。
    QPushButton* m_r0SetPplButton = nullptr; // R0 设置 PPL 层级按钮。
    QPushButton* m_r0VisibilityButton = nullptr; // R0 可恢复隐藏菜单按钮。
    QPushButton* m_r0DangerFlagsButton = nullptr; // R0 危险标志/DKOM 菜单按钮。

    QLineEdit* m_dllPathLineEdit = nullptr;    // DLL 路径输入框。
    QComboBox* m_injectionModeCombo = nullptr; // 注入模式：R3 或 R0 驱动。
    QPushButton* m_browseDllButton = nullptr;  // 浏览 DLL 按钮。
    QPushButton* m_injectDllButton = nullptr;  // 执行 DLL 注入按钮。

    QLineEdit* m_shellcodePathLineEdit = nullptr; // shellcode 文件路径输入框。
    QPushButton* m_browseShellcodeButton = nullptr; // 浏览 shellcode 文件按钮。
    QPushButton* m_injectShellcodeButton = nullptr; // 执行 shellcode 注入按钮。

    // ======== 模块页控件 ========
    QVBoxLayout* m_moduleLayout = nullptr;     // 模块页总布局。
    QHBoxLayout* m_moduleTopBarLayout = nullptr; // 模块页顶部工具栏布局。
    QPushButton* m_refreshModuleButton = nullptr; // 模块刷新按钮。
    QPushButton* m_dllHijackScanButton = nullptr; // 只读 DLL 劫持检测按钮。
    QCheckBox* m_signatureCheckBox = nullptr;  // 是否刷新时做签名校验。
    QLabel* m_moduleStatusLabel = nullptr;     // 模块刷新状态标签。
    QTreeWidget* m_moduleTable = nullptr;      // 模块表格。

    std::vector<ks::process::ProcessModuleRecord> m_moduleRecords; // 当前模块数据缓存。

    // ======== 内嵌句柄审计页 ========
    QVBoxLayout* m_embeddedHandleLayout = nullptr; // 句柄审计页容器布局。
    QLabel* m_embeddedHandlePlaceholder = nullptr; // 首次进入前的轻量提示。
    HandleDock* m_embeddedHandleDock = nullptr;    // 复用完整 HandleDock，按当前 PID 过滤。

    // ======== 内嵌精简内存页 ========
    QVBoxLayout* m_embeddedMemoryLayout = nullptr;
    QLabel* m_embeddedMemoryPlaceholder = nullptr;
    MemoryDock* m_embeddedMemoryDock = nullptr;

    // ======== 内嵌网络连接页 ========
    QVBoxLayout* m_embeddedNetworkLayout = nullptr;
    QLabel* m_embeddedNetworkPlaceholder = nullptr;
    NetworkDock* m_embeddedNetworkDock = nullptr;

    // ======== 内嵌窗口列表页 ========
    QVBoxLayout* m_embeddedWindowLayout = nullptr;
    QLabel* m_embeddedWindowPlaceholder = nullptr;
    OtherDock* m_embeddedWindowDock = nullptr;

    bool m_moduleRefreshing = false;           // 模块刷新进行中标记。
    bool m_moduleInitialRefreshStarted = false; // 模块页首次刷新是否已经按需启动。
    bool m_firstModuleRefreshDone = false;     // 首轮模块刷新是否已完成。
    std::uint64_t m_moduleRefreshTicket = 0;   // 模块刷新序号（防乱序）。
    int m_moduleRefreshProgressPid = 0;        // 首轮模块刷新对应的 kPro 任务 PID。
    bool m_dllHijackScanRunning = false;       // DLL 劫持检测后台任务运行标记。
    std::uint64_t m_dllHijackScanTicket = 0;   // DLL 劫持检测结果防乱序序号。

    // ======== 线程细节刷新状态 ========
    bool m_threadInspectRefreshing = false;        // 线程细节是否正在刷新。
    bool m_threadInspectInitialRefreshStarted = false; // 线程页首次刷新是否已经按需启动。
    std::uint64_t m_threadInspectRefreshTicket = 0;// 线程细节刷新序号。
    bool m_threadRuntimeSampleRefreshing = false;  // 当前线程 PDB 采样是否正在进行。
    std::uint64_t m_threadRuntimeSampleTicket = 0; // 当前线程 PDB 采样防乱序序号。
    int m_threadInspectRefreshProgressPid = 0;     // 线程细节刷新对应进度 PID。
    std::vector<ThreadInspectItem> m_threadInspectRows; // 线程详情页最近一次刷新缓存。

    // ======== Process Detail Evidence 页控件 ========
    QVBoxLayout* m_kernelObjectLayout = nullptr; // Process Detail Evidence 页总布局。
    QLabel* m_kernelObjectR0StatusValue = nullptr; // R0 扩展读取状态。
    QLabel* m_kernelObjectCapabilityValue = nullptr; // DynData capability 位图。
    QLabel* m_kernelObjectProtectionValue = nullptr; // EPROCESS.Protection 原始值。
    QLabel* m_kernelObjectSignatureValue = nullptr; // SignatureLevel 原始值。
    QLabel* m_kernelObjectSectionSignatureValue = nullptr; // SectionSignatureLevel 原始值。
    QLabel* m_kernelObjectHandleTableValue = nullptr; // ObjectTable 可用性和当前指针。
    QLabel* m_kernelObjectSectionObjectValue = nullptr; // SectionObject 可用性和当前指针。
    QLabel* m_kernelObjectImagePathValue = nullptr; // R0 镜像路径。
    QLabel* m_kernelObjectSessionSourceValue = nullptr; // Session 来源。
    QLabel* m_kernelObjectImagePathSourceValue = nullptr; // 镜像路径来源。
    QLabel* m_kernelObjectProtectionSourceValue = nullptr; // Protection 来源。
    QLabel* m_kernelObjectSignatureSourceValue = nullptr; // SignatureLevel 来源。
    QLabel* m_kernelObjectSectionSignatureSourceValue = nullptr; // SectionSignatureLevel 来源。
    QLabel* m_kernelObjectObjectTableSourceValue = nullptr; // ObjectTable 来源。
    QLabel* m_kernelObjectSectionObjectSourceValue = nullptr; // SectionObject 来源。
    QLabel* m_kernelObjectProtectionOffsetValue = nullptr; // Protection 偏移。
    QLabel* m_kernelObjectSignatureOffsetValue = nullptr; // SignatureLevel 偏移。
    QLabel* m_kernelObjectSectionSignatureOffsetValue = nullptr; // SectionSignatureLevel 偏移。
    QLabel* m_kernelObjectObjectTableOffsetValue = nullptr; // ObjectTable 偏移。
    QLabel* m_kernelObjectSectionObjectOffsetValue = nullptr; // SectionObject 偏移。
    QPushButton* m_refreshSectionInfoButton = nullptr; // 刷新 Section/ControlArea 按钮。
    QLabel* m_sectionInfoStatusLabel = nullptr; // Section/ControlArea 查询状态。
    CodeEditorWidget* m_sectionInfoOutput = nullptr; // Section/ControlArea 详情文本输出。
    bool m_sectionInfoRefreshing = false; // Section 查询是否进行中。
    bool m_sectionInfoInitialRefreshStarted = false; // Section 页首次查询是否已经按需启动。
    std::uint64_t m_sectionInfoRefreshTicket = 0; // Section 查询序号。
    int m_sectionInfoRefreshProgressPid = 0; // Section 查询 kPro 任务 PID。

    // ======== 进程热键页控件与状态 ========
    QVBoxLayout* m_hotkeyLayout = nullptr;       // 进程热键页总布局。
    QPushButton* m_deleteHotkeyButton = nullptr;  // 删除当前支持来源的热键。
    QPushButton* m_refreshHotkeyButton = nullptr; // 刷新热键按钮。
    QPushButton* m_editHotkeyButton = nullptr;    // 编辑当前支持来源的热键。
    QLabel* m_hotkeyStatusLabel = nullptr;       // 热键扫描状态。
    QTableWidget* m_hotkeyTable = nullptr;       // 热键结果表。
    bool m_hotkeyRefreshing = false;             // 热键扫描是否进行中。
    bool m_hotkeyInitialRefreshStarted = false;  // 热键页首次扫描是否已经按需启动。
    std::uint64_t m_hotkeyRefreshTicket = 0;     // 热键扫描序号。
    int m_hotkeyRefreshProgressPid = 0;          // 热键扫描 kPro 任务 PID。
    std::vector<HotkeyInspectItem> m_hotkeyRows; // 热键结果缓存。

    // ======== 键盘页控件与状态 ========
    QVBoxLayout* m_keyboardLayout = nullptr;       // 键盘页总布局。
    QPushButton* m_refreshKeyboardButton = nullptr; // 刷新键盘按钮。
    QLabel* m_keyboardStatusLabel = nullptr;       // 键盘页扫描状态。
    QTabWidget* m_keyboardInnerTabWidget = nullptr; // 键盘页内部热键/钩子分栏。
    QTableWidget* m_keyboardHotkeyTable = nullptr; // 键盘页热键表。
    QTableWidget* m_keyboardHookTable = nullptr;   // 键盘钩子结果表。
    bool m_keyboardRefreshing = false;             // 键盘页扫描是否进行中。
    bool m_keyboardInitialRefreshStarted = false;  // 键盘页首次扫描是否已启动。
    std::uint64_t m_keyboardRefreshTicket = 0;     // 键盘页扫描序号。
    int m_keyboardRefreshProgressPid = 0;          // 键盘页扫描 kPro 任务 PID。
    std::vector<HotkeyInspectItem> m_keyboardHotkeyRows; // 键盘页热键缓存。
    std::vector<KeyboardHookInspectItem> m_keyboardHookRows; // 键盘页钩子缓存。

    // ======== 令牌页控件与状态 ========
    QVBoxLayout* m_tokenLayout = nullptr;          // 令牌页布局。
    QPushButton* m_refreshTokenButton = nullptr;   // 刷新令牌信息按钮。
    QLabel* m_tokenStatusLabel = nullptr;          // 令牌页状态文本。
    CodeEditorWidget* m_tokenDetailOutput = nullptr; // 令牌信息输出框（统一文本编辑器组件，只读）。
    bool m_tokenRefreshing = false;                // 令牌页刷新状态。
    bool m_tokenInitialRefreshStarted = false;     // 令牌页首次刷新是否已经按需启动。
    std::uint64_t m_tokenRefreshTicket = 0;        // 令牌页刷新序号。
    int m_tokenRefreshProgressPid = 0;             // 令牌页刷新进度 PID。

    // ======== 令牌开关页控件与状态 ========
    QVBoxLayout* m_tokenSwitchLayout = nullptr;    // 令牌开关页总布局。
    QPushButton* m_refreshTokenSwitchButton = nullptr; // 刷新令牌开关按钮。
    QPushButton* m_applyTokenSwitchButton = nullptr;   // 应用令牌开关按钮。
    QPushButton* m_refreshTokenAllInfoButton = nullptr; // 刷新全部令牌信息按钮（触发全信息类枚举）。
    QLabel* m_tokenSwitchStatusLabel = nullptr;    // 令牌开关应用状态文本。
    bool m_tokenSwitchInitialRefreshStarted = false; // 令牌开关页首次回读是否已经按需启动。
    QCheckBox* m_tokenSandboxInertCheck = nullptr; // SandboxInert 开关。
    QCheckBox* m_tokenVirtualizationAllowedCheck = nullptr; // VirtualizationAllowed 开关。
    QCheckBox* m_tokenVirtualizationEnabledCheck = nullptr; // VirtualizationEnabled 开关。
    QCheckBox* m_tokenUiAccessCheck = nullptr;     // UIAccess 开关。
    QCheckBox* m_tokenMandatoryNoWriteUpCheck = nullptr; // MandatoryPolicy: NoWriteUp 位。
    QCheckBox* m_tokenMandatoryNewProcessMinCheck = nullptr; // MandatoryPolicy: NewProcessMin 位。
    QCheckBox* m_tokenHasRestrictionsCheck = nullptr; // TokenHasRestrictions（class=21）开关。
    QCheckBox* m_tokenIsAppContainerCheck = nullptr;  // TokenIsAppContainer（class=29）开关。
    QCheckBox* m_tokenIsRestrictedCheck = nullptr; // TokenIsRestricted（class=40）开关。
    QCheckBox* m_tokenIsLessPrivilegedAppContainerCheck = nullptr; // TokenIsLessPrivilegedAppContainer（class=46）开关。
    QCheckBox* m_tokenIsSandboxedCheck = nullptr; // TokenIsSandboxed（class=47）开关。
    QCheckBox* m_tokenIsAppSiloCheck = nullptr; // TokenIsAppSilo（class=51）开关。
    QComboBox* m_tokenRawInfoClassCombo = nullptr; // 原始设置：TokenInformationClass 选择框。
    QComboBox* m_tokenRawInputModeCombo = nullptr; // 原始设置：负载输入模式（UInt32/UInt64/HexBytes）。
    QLineEdit* m_tokenRawPayloadEdit = nullptr;    // 原始设置：负载输入文本。
    QPushButton* m_tokenRawApplyButton = nullptr;  // 原始设置：执行 NtSetInformationToken 的按钮。

    // ======== PEB页控件与状态 ========
    QVBoxLayout* m_pebLayout = nullptr;            // PEB 页布局。
    QPushButton* m_refreshPebButton = nullptr;     // 刷新 PEB 信息按钮。
    QPushButton* m_applyPebEditButton = nullptr;   // 应用 PEB 可编辑字段按钮。
    QLabel* m_pebStatusLabel = nullptr;            // PEB 页状态文本。
    QComboBox* m_pebTargetCombo = nullptr;          // PEB 写入目标：NativePEB / Wow64PEB。
    QLineEdit* m_pebCommandLineEdit = nullptr;      // 可编辑 CommandLine。
    QLineEdit* m_pebImagePathEdit = nullptr;        // 可编辑 ImagePathName。
    QLineEdit* m_pebCurrentDirectoryEdit = nullptr; // 可编辑 CurrentDirectory.DosPath。
    QLineEdit* m_pebImageBaseEdit = nullptr;        // 高级：PEB.ImageBaseAddress。
    QLineEdit* m_pebAffinityMaskEdit = nullptr;     // 可编辑进程亲和性掩码。
    QComboBox* m_pebPriorityClassCombo = nullptr;   // 可编辑优先级。
    QLineEdit* m_pebEnvironmentNameEdit = nullptr;  // 环境变量名。
    QLineEdit* m_pebEnvironmentValueEdit = nullptr; // 环境变量值。
    CodeEditorWidget* m_pebReadonlyReasonOutput = nullptr; // 不可直接修改字段说明，支持语言切换重绘。
    CodeEditorWidget* m_pebDetailOutput = nullptr;   // PEB 信息输出框（统一文本编辑器组件，只读）。
    bool m_pebRefreshing = false;                  // PEB 页刷新状态。
    bool m_pebInitialRefreshStarted = false;       // PEB 页首次刷新是否已经按需启动。
    std::uint64_t m_pebRefreshTicket = 0;          // PEB 页刷新序号。
    int m_pebRefreshProgressPid = 0;               // PEB 页刷新进度 PID。

    // ======== PEB.KernelCallbackTable 页控件与状态 ========
    QVBoxLayout* m_kernelCallbackLayout = nullptr; // 内核回调表页布局。
    QPushButton* m_refreshKernelCallbackButton = nullptr; // 刷新内核回调表按钮。
    QLabel* m_kernelCallbackStatusLabel = nullptr; // 内核回调表刷新状态。
    QTableWidget* m_kernelCallbackTable = nullptr; // 内核回调表结果表格。
    bool m_kernelCallbackRefreshing = false;       // 当前是否正在读取回调表。
    bool m_kernelCallbackInitialRefreshStarted = false; // 是否已执行懒加载首刷。
    std::uint64_t m_kernelCallbackRefreshTicket = 0; // 防止旧任务覆盖新结果。
    int m_kernelCallbackRefreshProgressPid = 0;    // 内核回调表进度任务 ID。
    std::vector<KernelCallbackInspectItem> m_kernelCallbackRows; // 最近一次结果缓存。

    // applyPebEditableFields：
    // - 读取 PEB 页编辑区输入；
    // - 尽量写回远程 PEB/ProcessParameters 与进程基础运行属性；
    // - 成功/失败通过状态栏和消息框反馈。
    void applyPebEditableFields();
    // populatePebEditableFieldsFromText：
    // - 从 PEB 刷新文本中提取当前目标 PEB 的可写字段；
    // - 自动填充编辑框，避免用户手工复制长命令行或路径；
    // - 仅更新 UI 控件，无返回值。
    void populatePebEditableFieldsFromText(const QString& detailText);
    bool m_staticDetailRefreshing = false;         // 静态详情后台补齐是否进行中。
    bool m_staticDetailRefreshAttempted = false;   // 静态详情是否已经尝试后台补齐，避免周期刷新重复排队。
    std::uint64_t m_staticDetailRefreshTicket = 0; // 静态详情刷新序号。
    bool m_themeStyleApplying = false;             // 主题样式重建防重入标记，避免 changeEvent 循环触发。

    // 图标缓存：路径 -> 图标，避免重复读取系统图标。
    QHash<QString, QIcon> m_iconCacheByPath;
};
