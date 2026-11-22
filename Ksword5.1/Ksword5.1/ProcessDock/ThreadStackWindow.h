#pragma once

// ============================================================
// ThreadStackWindow.h
// 作用：
// - 提供 Phase-8 “线程调用栈”独立窗口；
// - R3 捕获用户态栈帧并解析模块/符号；
// - R0 与 CLI 共用保存上下文采集；只有真实用户机器帧边界才标完整，APC 回退始终为诊断。
// ============================================================

#include "../Framework.h"
#include "../ArkDriverClient/ArkThreadStackCapture.h"

#include <QDialog>

#include <cstdint>
#include <vector>

class QLabel;
class QPushButton;
class QTreeWidget;
class QVBoxLayout;
class QHBoxLayout;

// ThreadStackTarget 作用：
// - 描述一个待捕获调用栈的线程；
// - ProcessDock 和 ProcessDetailWindow 都可以构造该结构打开窗口。
struct ThreadStackTarget
{
    std::uint32_t processId = 0;        // 目标进程 PID。
    std::uint32_t threadId = 0;         // 目标线程 TID。
    std::uint64_t processCreationTime100ns = 0, threadCreationTime100ns = 0;
    QString processName;                // 进程名，仅展示。
    QString processPath;                // 进程路径，仅展示和符号辅助。
    std::uint64_t startAddress = 0;     // 线程启动地址，仅展示。
    std::uint64_t win32StartAddress = 0;// Win32StartAddress，仅展示。
    std::uint64_t tebBaseAddress = 0;   // TEB 地址，缺失时窗口会尝试重新查询。
    std::uint64_t userStackBase = 0;    // 用户栈基址，缺失时窗口会尝试从 TEB 读取。
    std::uint64_t userStackLimit = 0;   // 用户栈边界，缺失时窗口会尝试从 TEB 读取。
    std::uint64_t r0KernelStack = 0;    // KTHREAD.KernelStack。
    std::uint64_t r0StackBase = 0;      // KTHREAD.StackBase。
    std::uint64_t r0StackLimit = 0;     // KTHREAD.StackLimit。
    std::uint64_t r0InitialStack = 0;   // KTHREAD.InitialStack。
    std::uint32_t r0ThreadStatus = 0;   // R0 线程扩展状态。
    std::uint64_t r0CapabilityMask = 0; // R0 DynData capability。
};

class ThreadStackWindow final : public QDialog
{
public:
    // 构造函数作用：
    // - 接收线程目标信息；
    // - 初始化 UI；
    // - 自动发起一次调用栈捕获。
    // 参数 target：目标线程。
    // 参数 parent：Qt 父对象。
    explicit ThreadStackWindow(const ThreadStackTarget& target, QWidget* parent = nullptr);

    struct StackFrameRow
    {
        std::uint32_t index = 0;      // 帧序号。
        std::uint64_t address = 0;    // 指令地址。
        QString moduleName;           // 模块名。
        QString symbolName;           // 符号名。
        std::uint64_t displacement = 0;// 符号偏移。
        QString modeText;             // User/Kernel boundary/Unavailable。
    };

    struct CaptureResult
    {
        std::vector<StackFrameRow> frames; // 捕获到的栈帧。
        ThreadStackTarget enrichedTarget;  // 补齐后的目标诊断字段。
        QString diagnosticText;            // 失败或降级诊断。
        std::uint64_t elapsedMs = 0;       // 捕获耗时。
        bool ok = false;                   // 是否成功捕获至少一帧。
        bool queriedKernel = false;         // 是否实际尝试在线 R0 采集。
        ksword::ark::VerifiedThreadStackCaptureResult kernel; // 原始回执、独立身份与共用符号投影。
    };

    enum class StackColumn
    {
        Index = 0,
        Address,
        Module,
        Symbol,
        Offset,
        Mode,
        Count
    };

private:
    // 默认采集在线 R0；每次只展示一种来源，禁止拼接 R3、保存上下文与 APC 帧。
    enum class CaptureMode { User, Kernel };
    // initializeUi 作用：创建顶部状态、按钮和栈帧表格。
    void initializeUi();
    // initializeConnections 作用：绑定刷新和复制动作。
    void initializeConnections();
    // requestAsyncCapture 作用：在线程池捕获调用栈，避免阻塞 UI。
    void requestAsyncCapture(CaptureMode mode);
    // applyCaptureResult 作用：在 UI 线程回填捕获结果。
    void applyCaptureResult(std::uint64_t ticket, const CaptureResult& result);
    // rebuildFrameTable 作用：按 m_frames 重建表格。
    void rebuildFrameTable();
    // updateBoundaryText 作用：刷新用户栈/R0 栈边界诊断标签。
    void updateBoundaryText();
    // copyAllFrames 作用：复制全部栈帧为 TSV。
    void copyAllFrames();
    // copyCurrentFrame 作用：复制当前栈帧。
    void copyCurrentFrame();
    // showFrameContextMenu 作用：弹出表格右键菜单。
    void showFrameContextMenu(const QPoint& localPosition);
    // resizeEvent 作用：窗口尺寸变化后重新分配列宽。
    void resizeEvent(QResizeEvent* event) override;
    // applyAdaptiveColumnWidths 作用：设置表格列宽。
    void applyAdaptiveColumnWidths();
    // 输入同次 R0 结果，输出完整边界、部分帧或不可用说明；只在 GUI 线程翻译。
    QString describeKernelCapture(const CaptureResult& result) const;
    // 初始化互补 A/B 列组与原生表头逐列选择；只改变列显隐。
    void initializeColumnViews();

private:
    ThreadStackTarget m_target;             // 当前目标线程。
    std::vector<StackFrameRow> m_frames;    // 当前栈帧缓存。

    QVBoxLayout* m_rootLayout = nullptr;    // 根布局。
    QHBoxLayout* m_toolbarLayout = nullptr; // 顶部按钮布局。
    QPushButton* m_refreshButton = nullptr; // 仅刷新用户态调用栈。
    QPushButton* m_kernelRefreshButton = nullptr; // 在线原始保存内核链，端点不支持时才回退 APC 诊断。
    QPushButton* m_copyButton = nullptr;    // 复制按钮。
    QLabel* m_targetLabel = nullptr;        // 目标线程摘要。
    QLabel* m_boundaryLabel = nullptr;      // 栈边界摘要。
    QLabel* m_statusLabel = nullptr;        // 捕获状态。
    QTreeWidget* m_frameTable = nullptr;    // 栈帧表格。

    bool m_captureInProgress = false;       // 捕获中标记。
    bool m_queriedKernel = false;           // 当前结果是否含一次新采样，而非列表缓存。
    ksword::ark::VerifiedThreadStackCaptureResult m_kernelCapture; // 当前帧表的唯一 R0 来源证据。
    std::uint64_t m_captureTicket = 0;      // 捕获序号。
    int m_captureProgressPid = 0;           // kPro 任务 ID。
};
