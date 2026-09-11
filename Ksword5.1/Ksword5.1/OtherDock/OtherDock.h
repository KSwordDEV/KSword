#pragma once

// ============================================================
// OtherDock.h
// 作用说明：
// 1) 构建“窗口管理”页面，包含窗口列表、筛选、分组和预览区；
// 2) 提供窗口右键操作（激活/置顶/显示隐藏/启用禁用/结束进程等）；
// 3) 支持打开“窗口详细信息”非模态对话框进行深度查看与修改。
// ============================================================

#include "../Framework.h"

#include <QWidget>
#include <QSet>
#include <QVector>

#include <atomic>      // std::atomic_bool：控制后台枚举线程互斥刷新。
#include <vector>      // std::vector：窗口快照容器。

// Qt 前置声明：降低头文件编译耦合。
class QCheckBox;
class CodeEditorWidget;
class QComboBox;
class QLineEdit;
class QPushButton;
class QSplitter;
class QSpinBox;
class QTableWidget;
class QTabWidget;
class QStatusBar;
class QTextEdit;
class QTimer;
class QTreeWidget;
class QTreeWidgetItem;
class QLabel;
class QVBoxLayout;
class QHBoxLayout;
class QPoint;

// ============================================================
// OtherDock
// 说明：
// - 本类聚焦窗口枚举与窗口属性操作；
// - 所有重枚举操作都放后台线程，避免阻塞 UI。
// ============================================================
class OtherDock : public QWidget
{
    Q_OBJECT

public:
    // 构造函数：
    // - 作用：初始化窗口列表页与工具栏，并触发首轮枚举。
    // - 参数 parent：Qt 父控件。
    explicit OtherDock(QWidget* parent = nullptr);

    // 析构函数：
    // - 作用：停止自动刷新定时器，确保后台流程退出安全。
    ~OtherDock() override;

    void focusProcessIds(const QVector<quint32>& processIds);
    void clearExternalProcessFilter();

    // setWindowListOnlyScope：隐藏桌面管理页，供进程详情内嵌窗口列表使用。
    void setWindowListOnlyScope();

    // WindowInfo：
    // - 作用：缓存单个窗口的关键属性，供列表与详情弹窗复用。
    struct WindowInfo
    {
        quint64 hwndValue = 0;              // 窗口句柄（整数形式）。
        quint64 parentHwndValue = 0;        // 父窗口句柄。
        quint64 ownerHwndValue = 0;         // 所有者窗口句柄。
        QString titleText;                  // 窗口标题。
        QString classNameText;              // 窗口类名。
        std::uint32_t processId = 0;        // 所属进程 PID。
        std::uint64_t processCreationTime100ns = 0; // 枚举时进程创建时间，用于防止 PID 复用误操作。
        std::uint32_t threadId = 0;         // 创建线程 TID。
        QString processNameText;            // 进程名。
        QString processImagePathText;       // 进程可执行文件完整路径。
        QRect windowRect;                   // 窗口矩形（屏幕坐标）。
        quint64 styleValue = 0;             // 窗口样式位（WS_*）。
        quint64 exStyleValue = 0;           // 扩展样式位（WS_EX_*）。
        bool visible = false;               // 是否可见。
        bool enabled = false;               // 是否可用。
        bool topMost = false;               // 是否置顶。
        bool minimized = false;             // 是否最小化。
        bool maximized = false;             // 是否最大化。
        bool valid = false;                 // IsWindow 是否有效。
        bool displayAffinityKnown = false;  // 是否成功读取 DisplayAffinity。
        std::uint32_t displayAffinityValue = 0; // DisplayAffinity 原始 WDA_* 值。
        std::uint32_t displayAffinityError = 0; // DisplayAffinity 读取失败时的 Win32 错误。
        int zOrder = 0;                     // 枚举顺序（近似 Z 序）。
        QString enumApiName;                // 枚举来源 API 名称。
        int alphaValue = 255;               // 分层窗口透明度（0-255）。
        bool isChildWindow = false;         // 是否子窗口。
    };

    // CreatedDesktopRecord：
    // - 作用：记录本进程创建并保留的桌面句柄；
    // - 用途：私有 DACL 桌面可能无法再通过名称 OpenDesktopW，切换时需要复用创建返回的句柄；
    // - 生命周期：OtherDock 析构时统一 CloseDesktop，避免泄漏桌面对象引用。
    struct CreatedDesktopRecord
    {
        QString windowStationName;          // 创建时所在窗口站名称。
        QString desktopName;                // 桌面对象名称。
        void* desktopHandle = nullptr;      // HDESK 句柄，头文件内用 void* 避免传播 Windows.h。
        std::uint32_t desiredAccess = 0;    // 创建时请求的 DESKTOP_* 访问掩码。
        bool privateAccess = false;         // 是否使用“其他进程不可访问”的私有 DACL。
        bool inheritableHandle = false;     // 返回句柄是否允许子进程继承。
    };

private:
    // ===================== UI 初始化 ======================
    void initializeUi();
    void initializeConnections();
    void applyViewMode();

    // ===================== 列表刷新 ======================
    void refreshWindowListAsync();
    void rebuildWindowTreeFromSnapshot();
    bool passFilter(const WindowInfo& info) const;
    void updateStatusBar();
    void updatePreviewPanel(const WindowInfo* info);
    // refreshDesktopList：
    // - 作用：刷新“桌面管理”页中的窗口站/桌面清单；
    // - 调用：初始化界面后、点击刷新按钮后、切换成功后调用；
    // - 传入：无；
    // - 传出：无，结果直接写入 m_desktopTable 与 m_desktopStatusLabel。
    void refreshDesktopList();

    // switchToSelectedDesktop：
    // - 作用：切换到表格中当前选中的桌面；
    // - 调用：点击切换按钮或双击桌面行时调用；
    // - 传入：无；
    // - 传出：无，状态结果通过日志与 m_desktopStatusLabel 反馈。
    void switchToSelectedDesktop();

    // showCreateDesktopDialog：
    // - 作用：弹出“新建桌面”参数窗口，收集名称/堆大小/访问掩码/安全描述符等参数；
    // - 调用：点击桌面管理页“新建”按钮或右键菜单“新建桌面”时调用；
    // - 传入：无；
    // - 传出：无，创建结果通过日志、状态栏和桌面列表刷新反馈。
    void showCreateDesktopDialog();

    // showDesktopContextMenu：
    // - 作用：在桌面管理表格中弹出右键菜单；
    // - 调用：用户在桌面表上右键时触发；
    // - 传入 localPos：表格视口坐标；
    // - 传出：无，菜单动作会直接驱动切换/复制/查看详情。
    void showDesktopContextMenu(const QPoint& localPos);

    // ===================== 交互操作 ======================
    void showWindowContextMenu(const QPoint& localPos);
    void exportVisibleRowsToTsv();
    void openWindowDetailDialog(const WindowInfo& info, bool inputSettings = false);
    const WindowInfo* findInfoByHwnd(quint64 hwndValue) const;
    // setCaptureProtectionForSelectedWindow：
    // - 作用：对当前选中的窗口启用/取消防截图保护；
    // - 调用：窗口列表工具栏按钮；
    // - 传入 protectedState：true=启用，false=取消；
    // - 传出：无，结果通过日志、消息框和列表刷新反馈。
    void setCaptureProtectionForSelectedWindow(bool protectedState);

    // setCaptureProtectionForWindow：
    // - 作用：对指定窗口快照执行防截图保护操作；
    // - 调用：右键菜单和选中项工具栏；
    // - 传入 info：目标窗口快照；
    // - 传入 protectedState：true=启用，false=取消。
    void setCaptureProtectionForWindow(const WindowInfo& info, bool protectedState);

    // handleWindowPickerRelease：
    // - 作用：处理“准星拖拽拾取”释放事件，定位鼠标下窗口并弹出详情；
    // - 调用：由窗口列表顶部拾取按钮在鼠标松开时触发；
    // - 传入 globalPos：鼠标松开时的全局屏幕坐标；
    // - 传出：无，成功时直接打开窗口详情对话框。
    void handleWindowPickerRelease(const QPoint& globalPos);

private:
    // 顶层布局与工具栏。
    QVBoxLayout* m_rootLayout = nullptr;          // 根布局。
    QWidget* m_toolBarWidget = nullptr;           // 顶部工具栏容器。
    QHBoxLayout* m_toolBarLayout = nullptr;       // 顶部工具栏布局。
    QPushButton* m_refreshButton = nullptr;       // 刷新按钮。
    QPushButton* m_clearExternalProcessFilterButton = nullptr; // 清除跨页 PID 筛选。
    QCheckBox* m_autoRefreshCheck = nullptr;      // 自动刷新开关。
    QSpinBox* m_autoRefreshIntervalSpin = nullptr; // 自动刷新间隔（ms）。
    QLineEdit* m_filterEdit = nullptr;            // 关键字过滤输入。
    QComboBox* m_filterModeCombo = nullptr;       // 条件过滤下拉框。
    QComboBox* m_enumModeCombo = nullptr;         // 枚举方式下拉框。
    QComboBox* m_groupModeCombo = nullptr;        // 分组方式下拉框。
    QComboBox* m_viewModeCombo = nullptr;         // 显示样式切换。
    QPushButton* m_exportButton = nullptr;        // 导出按钮。

    // 中部主区域：主Tab（窗口列表/桌面管理）。
    QTabWidget* m_contentTabWidget = nullptr;     // 主内容 Tab 容器。
    QWidget* m_windowListPage = nullptr;          // 窗口列表页。
    QVBoxLayout* m_windowListPageLayout = nullptr;// 窗口列表页布局。
    QWidget* m_windowListToolWidget = nullptr;    // 窗口列表页顶部工具条容器。
    QHBoxLayout* m_windowListToolLayout = nullptr;// 窗口列表页顶部工具条布局。
    QPushButton* m_windowPickerButton = nullptr;  // 准星拖拽拾取按钮（释放时按鼠标位置打开窗口详情）。
    QPushButton* m_protectCaptureButton = nullptr; // 对选中窗口启用防截图保护按钮。
    QPushButton* m_unprotectCaptureButton = nullptr; // 对选中窗口取消防截图保护按钮。
    QLabel* m_windowPickerHintLabel = nullptr;    // 准星按钮旁提示文案，说明拖拽用法。

    // 窗口列表页：左树右预览。
    QSplitter* m_mainSplitter = nullptr;          // 左右分割器。
    QTreeWidget* m_windowTree = nullptr;          // 窗口树/列表。
    QWidget* m_previewWidget = nullptr;           // 右侧预览容器。
    QVBoxLayout* m_previewLayout = nullptr;       // 右侧预览布局。
    QLabel* m_thumbnailLabel = nullptr;           // 窗口缩略图。
    QPushButton* m_captureButton = nullptr;       // 截图按钮。
    CodeEditorWidget* m_quickInfoText = nullptr;  // 关键属性摘要文本，支持即时语言重绘。

    // 桌面管理页：枚举窗口站与桌面清单，并展示 SessionId / SID / 切换能力等上下文。
    QWidget* m_desktopPage = nullptr;             // 桌面管理页容器。
    QVBoxLayout* m_desktopPageLayout = nullptr;   // 桌面管理页主布局。
    QHBoxLayout* m_desktopToolLayout = nullptr;   // 桌面管理工具栏布局。
    QPushButton* m_desktopRefreshButton = nullptr;// 刷新桌面列表按钮。
    QPushButton* m_desktopSwitchButton = nullptr; // 切换到选中桌面按钮。
    QPushButton* m_desktopCreateButton = nullptr; // 新建桌面按钮，详细参数在弹窗中设置。
    QTableWidget* m_desktopTable = nullptr;       // 桌面列表表格（窗口站/桌面/SessionId/SID/SID详情/备注）。
    QLabel* m_desktopStatusLabel = nullptr;       // 桌面状态提示标签。
    std::vector<CreatedDesktopRecord> m_createdDesktopHandles; // 本进程创建并保留的桌面句柄记录。

    // 底部状态栏。
    QStatusBar* m_statusBar = nullptr;            // 状态栏。
    QLabel* m_totalLabel = nullptr;               // 窗口总数。
    QLabel* m_visibleLabel = nullptr;             // 可见窗口数。
    QLabel* m_systemLabel = nullptr;              // 系统窗口数。
    QLabel* m_selectedLabel = nullptr;            // 当前选中项信息。

    // 自动刷新定时器。
    QTimer* m_autoRefreshTimer = nullptr;         // 定时刷新控制。

    // 数据缓存。
    std::vector<WindowInfo> m_windowSnapshot;     // 当前窗口快照。
    std::vector<WindowInfo> m_previousSnapshot;   // 上一轮窗口快照。
    std::vector<WindowInfo> m_exitedOneRound;     // 退出窗口保留一轮。
    std::vector<quint64> m_newWindowHandles;      // 新增窗口句柄列表（用于高亮）。
    QSet<quint32> m_externalProcessIdFilterSet;   // 进程页跨视图 PID 筛选。
    int m_refreshProgressPid = 0;                 // 刷新任务进度卡片 PID。
    std::atomic_bool m_refreshRunning{ false };   // 后台刷新进行中标志。
};
