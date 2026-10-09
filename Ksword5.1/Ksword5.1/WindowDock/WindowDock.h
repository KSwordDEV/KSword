#pragma once

// ============================================================
// WindowDock.h
// 作用说明：
// 1) 作为唯一的“窗口”页，统一承载窗口管理与窗口审计；
// 2) “窗口管理”页内嵌 OtherDock，恢复窗口列表 / 桌面两个详细视图；
// 3) 其余审计页面向只读审计，覆盖 win32k GUI/session、热键/钩子、剪贴板、GPU/显示；
// 4) 审计明细统一用可排序表格展示全部行，不再只给截断的文本摘要。
// ============================================================

#include "../Framework.h"
#include "../UI/StructuredFieldView.h"

#include <QWidget>
#include <QStringList>
#include <QVector>

#include <atomic> // std::atomic_bool：控制后台刷新任务互斥。

class QLabel;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QVBoxLayout;
class QShowEvent;
class OtherDock; // 复用既有窗口管理（窗口列表 / 桌面）实现，避免重复造轮子。

// ============================================================
// WindowDock
// 说明：
// - “窗口管理”页内嵌 OtherDock，保留其完整的窗口列表与桌面能力；
// - 审计页默认只读，结构化条目统一用表格展示，支持排序与查看全部行；
// - 切换页签不销毁页面对象，避免状态闪烁和重复采样。
// ============================================================
class WindowDock final : public QWidget
{
public:
    // 构造函数：
    // - 作用：创建窗口管理页与若干只读审计页；
    // - 参数 parent：Qt 父控件。
    explicit WindowDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：释放页面对象；审计页没有自动刷新定时器；
    // - 返回：无。
    ~WindowDock() override;

    void focusWindowsByPids(const QVector<quint32>& processIds);

    // refreshThemeVisuals 作用：
    // - 重新生成审计表格、现有单元格和列预设按钮依赖主题颜色的视觉状态；
    // - 保留透明表格策略、行模型、排序和列显隐，不触发任何 R0/R3 查询。
    // 调用方式：MainWindow 的统一主题刷新入口在深浅主题或自定义颜色变化后调用。
    // 传入传出：无。
    void refreshThemeVisuals();

protected:
    // showEvent 作用：
    // - 保留 Qt show 事件链；
    // - 不自动触发审计刷新，避免切换窗口页时反复采样。
    void showEvent(QShowEvent* showEventPointer) override;

private:
    // initializeUi 作用：
    // - 创建顶部工具栏、窗口管理页与各只读审计页；
    // - 返回：无。
    void initializeUi();

    // initializeConnections 作用：
    // - 连接刷新按钮事件；
    // - 返回：无。
    void initializeConnections();

    // requestAsyncRefresh 作用：
    // - 在后台线程采集各审计页快照与表格行模型；
    // - 结果通过 queued connection 回投 UI。
    void requestAsyncRefresh();

    // setRefreshingPlaceholderRows 作用：
    // - 在后台采集开始前写入“正在采集”诊断行；
    // - 这样 R0 wrapper 较慢或暂不可用时，用户不会看到完全空白的审计表；
    // - 返回：无，只更新本对象缓存并立即回填 UI。
    void setRefreshingPlaceholderRows();

    // applyAuditViews 作用：
    // - 在 UI 线程把缓存的摘要文本与表格行写入控件；
    // - 不执行任何额外采集。
    void applyAuditViews();

    // updateSelectedWindowSnapshotDetail 作用：
    // - 输入 currentRow：窗口表当前选中行；
    // - 处理：仅从窗口表可见列读取 HWND/PID/TID/状态并写入详情框；
    // - 返回：无，不触发驱动调用。
    void updateSelectedWindowSnapshotDetail(int currentRow);

    // requestSelectedWindowRuntimeDetail 作用：
    // - 输入：当前窗口表选中行；
    // - 处理：后台按需调用 ArkDriverClient::queryWin32kWindowDetail；
    // - 返回：无，结果回投到 m_windowDetailEditor。
    void requestSelectedWindowRuntimeDetail();

private:
    // 顶层布局与工具栏。
    QVBoxLayout* m_rootLayout = nullptr;    // m_rootLayout：根布局。
    QWidget* m_toolBarWidget = nullptr;     // m_toolBarWidget：顶部工具栏。
    QVBoxLayout* m_toolBarLayout = nullptr; // m_toolBarLayout：顶部工具栏布局。
    QLabel* m_statusLabel = nullptr;        // m_statusLabel：刷新状态提示。
    QPushButton* m_refreshButton = nullptr; // m_refreshButton：手动刷新审计按钮。

    // 页签与页面。
    QTabWidget* m_tabWidget = nullptr;      // m_tabWidget：页签容器。
    OtherDock* m_windowManagementDock = nullptr; // m_windowManagementDock：内嵌窗口管理（窗口列表 / 桌面）。
    QWidget* m_sessionPage = nullptr;       // m_sessionPage：win32k GUI/session 页。
    QWidget* m_hotkeyHookPage = nullptr;    // m_hotkeyHookPage：热键/钩子页。
    QWidget* m_clipboardPage = nullptr;     // m_clipboardPage：剪贴板/message-only 页。
    QWidget* m_displayPage = nullptr;       // m_displayPage：GPU/显示/watchdog 页。

    // 摘要文本编辑器（只读，仅承载非表格的上下文说明）。
    ks::ui::StructuredFieldView* m_sessionSummaryEditor = nullptr;    // m_sessionSummaryEditor：会话/窗口站上下文摘要。
    ks::ui::StructuredFieldView* m_hotkeyHookSummaryEditor = nullptr; // m_hotkeyHookSummaryEditor：热键/钩子上下文摘要。
    ks::ui::StructuredFieldView* m_displaySummaryEditor = nullptr;    // m_displaySummaryEditor：GPU/显示上下文摘要。
    ks::ui::StructuredFieldView* m_windowDetailEditor = nullptr;      // m_windowDetailEditor：当前选中 HWND 的快照/按需详情。

    // 结构化审计表格（可排序，展示全部行）。
    QTableWidget* m_windowsTable = nullptr;     // m_windowsTable：Win32K 窗口表。
    QTableWidget* m_guiThreadsTable = nullptr;  // m_guiThreadsTable：GUI 线程表。
    QTableWidget* m_sessionTable = nullptr;     // m_sessionTable：Win32K session 表。
    QTableWidget* m_hotkeysTable = nullptr;     // m_hotkeysTable：热键表。
    QTableWidget* m_hooksTable = nullptr;       // m_hooksTable：Hook 表。
    QTableWidget* m_clipboardTable = nullptr;   // m_clipboardTable：剪贴板属性/值表。
    QTableWidget* m_deviceTable = nullptr;      // m_deviceTable：GPU/显示/watchdog 设备审计表。

    // 刷新控制。
    std::atomic_bool m_refreshing{ false };     // m_refreshing：后台刷新互斥。
    std::atomic_bool m_windowDetailRefreshing{ false }; // m_windowDetailRefreshing：单 HWND detail 查询互斥。
    QPushButton* m_queryWindowDetailButton = nullptr; // m_queryWindowDetailButton：按需查询选中 HWND detail。

    // 缓存：摘要文本。
    ks::ui::FieldDocument m_cachedSessionSummary;             // m_cachedSessionSummary：会话摘要缓存。
    ks::ui::FieldDocument m_cachedHotkeyHookSummary;          // m_cachedHotkeyHookSummary：热键/钩子摘要缓存。
    ks::ui::FieldDocument m_cachedDisplaySummary;             // m_cachedDisplaySummary：显示摘要缓存。

    // 缓存：表格行模型（每行一组列文本，便于在 UI 线程直接填充）。
    QVector<QStringList> m_cachedWindowsRows;    // m_cachedWindowsRows：窗口表行。
    QVector<QStringList> m_cachedGuiThreadRows;  // m_cachedGuiThreadRows：GUI 线程表行。
    QVector<QStringList> m_cachedSessionRows;    // m_cachedSessionRows：session 表行。
    QVector<QStringList> m_cachedHotkeyRows;     // m_cachedHotkeyRows：热键表行。
    QVector<QStringList> m_cachedHookRows;       // m_cachedHookRows：Hook 表行。
    QVector<QStringList> m_cachedClipboardRows;  // m_cachedClipboardRows：剪贴板表行。
    QVector<QStringList> m_cachedDeviceRows;     // m_cachedDeviceRows：设备审计表行。
};
