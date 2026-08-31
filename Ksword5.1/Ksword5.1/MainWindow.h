#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTabWidget>
#include <QDockWidget>
#include <QMenu>
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QDragMoveEvent>
#include <QResizeEvent>
#include <QMoveEvent>
#include <QPushButton>
#include <QShowEvent>
#include <QEvent>
#include <QFont>
#include <QTimer>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QString>
#include <QByteArray>
#include <QPixmap>
#include <QToolButton>

#include <functional>
#include <atomic>
#include <memory>
#include <string>
#include <thread>

// ADS头文件
#include "include/ads/DockManager.h"
#include "include/ads/DockWidget.h"
#include "include/ads/DockAreaWidget.h"

// 自定义Dock头文件
#include "WelcomeDock/WelcomeDock.h"
#include "ProcessDock/ProcessDock.h"
#include "NetworkDock/NetworkDock.h"
#include "MemoryDock/MemoryDock.h"
#include "FileDock/FileDock.h"
#include "ScannerDock/ScannerDock.h"
#include "DriverDock/DriverDock.h"
#include "KernelDock/KernelDock.h"
#include "MonitorDock/MonitorDock.h"
#include "MonitorDock/MonitorPanelWidget.h"
#include "HardwareDock/HardwareDock.h"
#include "PrivilegeDock/PrivilegeDock.h"
#include "SettingsDock/SettingsDock.h"
#include "SettingsDock/AppearanceSettings.h"
#include "StartupDock/StartupDock.h"
#include "ServerDock/ServiceDock.h"
#include "WindowDock/WindowDock.h"
#include "RegistryDock/RegistryDock.h"
#include "MiscDock/MiscDock.h"
#include "MinidumpDock/MinidumpDock.h"
#include "句柄/HandleDock.h"

class LogDockWidget; // 前置声明：日志 Dock 面板类型。
class ProgressDockWidget; // 前置声明：当前操作进度面板类型。
class CodeEditorWidget; // 前置声明：即时窗口可复用代码编辑器组件。
namespace ks::ui
{
    class CustomTitleBar; // 前置声明：主窗口自绘标题栏组件。
    class GlobalUiSearchController; // 前置声明：标题栏全局页面搜索控制器。
    class CommandExecutionPopup; // 前置声明：标题栏 CMD 命令选项弹层。
    struct CommandExecutionOptions; // 前置声明：CMD 命令启动选项快照。
    class NotificationCardManager;
}

class QDialog;
class QScreen;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    // StartupProgressCallback 作用：
    // - 主窗口构造期间把细分阶段进度回传给启动画面；
    // - 主函数可传入 lambda，把文字与百分比同步到 splash。
    using StartupProgressCallback = std::function<void(int, const QString&)>;

    // 构造函数作用：
    // - 初始化主窗口菜单、Dock、布局与外观；
    // - 可选地持续回传启动阶段进度给 splash。
    // 参数 parent：Qt 父对象。
    // 参数 startupProgressCallback：启动进度回调；为空时忽略。
    // 参数 startupSystemFont：读取持久化外观配置前捕获的系统字体基线。
    explicit MainWindow(
        QWidget* parent,
        StartupProgressCallback startupProgressCallback,
        const QFont& startupSystemFont);
    ~MainWindow();

public slots:
    // focusHandleDockByPid 作用：
    // - 将“句柄”Dock 置顶并切换 PID 过滤；
    // - 供进程详情窗口发起“跳转到句柄视图”时调用。
    // 调用方式：QMetaObject::invokeMethod(mainWindow, "focusHandleDockByPid", ... )。
    // 入参 pid：目标进程 PID。
    void focusHandleDockByPid(quint32 pid);
    void focusHandleDockByPids(const QString& pidListText);

    // focusProcessProtectByCallback：
    // - 将“内核”Dock 置顶并切换到对象句柄回调的进程保护页；
    // - 供进程页快捷入口调用，不复制回调规则编辑逻辑。
    void focusProcessProtectByCallback();

    // focusMemoryDockByPid 作用：
    // - 将“内存”Dock 置顶并附加目标进程，便于执行内存区域查看与转储。
    // 调用方式：进程页右键菜单“跳转到内存操作”调用。
    // 入参 pid：目标进程 PID。
    void focusMemoryDockByPid(quint32 pid);
    void focusNetworkDockByPids(const QString& pidListText);
    void focusWindowDockByPids(const QString& pidListText);

    // openProcessDetailByPid 作用：
    // - 打开指定 PID 的独立进程详情窗口，不改变当前 Dock 标签；
    // - 供 FileDock 的“占用句柄扫描结果”窗口跳转调用。
    // 调用方式：QMetaObject::invokeMethod(mainWindow, "openProcessDetailByPid", ... )。
    // 入参 pid：目标进程 PID。
    void openProcessDetailByPid(quint32 pid);

    // openProcessDetailByIdentity 作用：
    // - 按 PID+创建时间打开历史记录对应的独立进程详情窗口，不改变当前 Dock 标签；
    // - 调用方式：TableInteractionSupport 的历史事件跳转入口调用；
    // - 入参 pid：历史记录 PID；
    // - 入参 creationTime100ns：捕获时的进程创建时间；
    // - 返回：无；ProcessDock 负责拒绝已退出或 PID 已复用的目标。
    void openProcessDetailByIdentity(
        quint32 pid,
        quint64 creationTime100ns);

    // focusServiceDockByName 作用：
    // - 将“服务”Dock 置顶并按服务名定位到目标行；
    // - 供 StartupDock 的“转到服务管理”入口调用。
    // 入参 serviceNameText：目标服务短名。
    void focusServiceDockByName(const QString& serviceNameText);

    // openFileDetailDockByPath 作用：
    // - 置顶“文件”Dock 并打开指定文件的详情分析窗口；
    // - 供 ServiceDock 的 BinaryPath/ServiceDll 联动调用。
    // 入参 filePath：目标文件路径。
    void openFileDetailDockByPath(const QString& filePath);

    // openFileUnlockerDockByPath 作用：
    // - 由 Shell 右键入口复用 FileDock 内部“文件解锁器(R3/R0)”流程；
    // - 不初始化或切换文件 Dock 页面，避免启动期懒加载文件页影响弹窗显示。
    // - 供系统右键菜单命令启动后的自动联动调用。
    // 入参 filePath：目标文件或目录路径。
    void openFileUnlockerDockByPath(const QString& filePath);

signals:
    // r0DriverServiceStarted：R0 服务确认启动后通知等待中的功能重试其只读查询。
    void r0DriverServiceStarted();

protected:
    // eventFilter 作用：
    // - 监听 ADS 浮动 Dock 窗口的显示与尺寸变化；
    // - 在浮动窗口脱离主窗口后，同步应用主界面同款纯色/背景图填充。
    bool eventFilter(QObject* watchedObject, QEvent* event) override;

    // closeEvent 作用：
    // - 在主窗口关闭时明确触发应用退出；
    // - 避免浮动 Dock 或后台窗口残留导致进程未结束。
    // 调用方式：Qt 关闭窗口时自动回调。
    // 入参 event：关闭事件对象，函数内会 accept 并触发 quit/exit。
    void closeEvent(QCloseEvent* event) override;

    // resizeEvent 作用：
    // - 窗口尺寸变化时重新生成背景画刷，避免背景图拉伸失真；
    // - 在深浅色切换后保持背景覆盖全窗口。
    // 调用方式：Qt 在窗口尺寸改变时自动回调。
    // 入参 event：尺寸变化事件对象。
    void resizeEvent(QResizeEvent* event) override;

    // moveEvent：主窗口跨显示器移动后让屏幕通知跟随新的工作区。
    void moveEvent(QMoveEvent* event) override;

    // showEvent 作用：
    // - 主窗口首次显示后再启动延迟页面补载；
    // - 保证窗口能先出现，再继续补齐剩余 Dock 内容。
    void showEvent(QShowEvent* event) override;

    // changeEvent 作用：
    // - 监听窗口最大化/还原状态变化；
    // - 同步刷新自绘标题栏中的最大化按钮图标状态。
    void changeEvent(QEvent* event) override;

    // nativeEvent 作用：
    // - 处理无边框窗口命中测试（拖动与边缘缩放）；
    // - 在自绘标题栏可拖动区域返回 HTCAPTION。
    // 调用方式：Qt 在 Windows 消息循环中自动回调。
    // 入参 eventType/message/result：原生消息参数。
    // 返回：true=已处理；false=走基类默认处理。
    bool nativeEvent(const QByteArray& eventType, void* message, qintptr* result) override;

private:
    void initMenus();
    // initializeWindowDockMenuActions：
    // - 在辅助 Dock 创建完成后，把 ADS 原生显示/隐藏动作挂到“窗口”菜单；
    // - 菜单复选状态由 CDockWidget::toggleViewAction 自动与 Dock 开关同步。
    void initializeWindowDockMenuActions();
    void initPrivilegeStatusButtons();
    // attachPrivilegeStatusButtonsToPrimaryDockTabBar：
    // - 将全局权限状态按钮组挂到欢迎页所属主功能 Dock 的 Tab 栏右侧；
    // - 布局恢复后调用，欢迎页随用户布局移动/浮动时按钮组随该 Dock Area 移动。
    void attachPrivilegeStatusButtonsToPrimaryDockTabBar();
    void refreshPrivilegeStatusButtons();
    void applyPrivilegeButtonStyle(QPushButton* button, bool activeState);
    void handleR0DriverUnavailable(unsigned long win32Error);
    void handleR0PermissionRequired(unsigned long win32Error);
    void enableR0ForUserRequest();

    // handleUiAccessButtonClicked 作用：
    // - 处理标题栏 UIAccess 按钮点击；
    // - 当前实例已带 UIAccess 时降级回普通用户实例；
    // - 否则按需触发管理员提权，并尝试 SYSTEM TokenUIAccess fallback 启动。
    void handleUiAccessButtonClicked();
    void handleR0StatusButtonClicked();

    // hasUiAccessPrivilege 作用：
    // - 查询当前进程令牌 TokenUIAccess 状态；
    // - 返回 true 表示当前实例已经带 UIAccess 位。
    bool hasUiAccessPrivilege() const;

    // launchSelfWithSystemUiAccessToken 作用：
    // - 获取 SYSTEM 进程令牌，DuplicateTokenEx 为主令牌；
    // - 对复制令牌调用 SetTokenInformation(TokenUIAccess)；
    // - 最后通过 CreateProcessAsUserW 启动自身。
    bool launchSelfWithSystemUiAccessToken(QString* detailTextOut);
    bool queryR0DriverServiceRunning(bool& runningOut, bool fatalOnError);
    bool startR0DriverService();
    bool stopR0DriverService(bool suppressErrorDialog = false);
    // prepareR0DriverServiceStop 作用：
    // - 输入：无；
    // - 处理：在 SCM 停止 KswordARK 前统一收敛 R3 长连接和 R0 运行时状态；
    // - 返回：无返回值；所有清理均为 best-effort，失败只写日志，不阻断真正的停驱请求。
    void prepareR0DriverServiceStop();
    // stopR0RuntimeConsumersBeforeServiceStop 作用：
    // - 输入：无；
    // - 处理：在停止 KswordARK 服务前关闭本进程长期持有的 R0 日志/回调等待句柄；
    // - 返回：无返回值，底层 stop 调用按 best-effort 释放资源。
    void stopR0RuntimeConsumersBeforeServiceStop();
    // startR0RuntimeConsumersAfterServiceStart 作用：
    // - 输入：无；
    // - 处理：在 KswordARK 服务启动或确认运行后恢复日志轮询和回调等待管理器；
    // - 返回：无返回值，重复调用会被各子模块幂等忽略。
    void startR0RuntimeConsumersAfterServiceStart();
    // refreshR0DynDataAfterServiceStart 作用：
    // - 输入：无；
    // - 处理：KswordARK 驱动装载后立即触发 DynData profile pack 匹配与下发；
    // - 返回：无返回值，失败只写日志，R0 功能仍可依赖驱动侧运行时兜底。
    void refreshR0DynDataAfterServiceStart();
    void startR0DriverLogPoller();
    void stopR0DriverLogPoller();
    void runR0DriverLogPollerLoop();
    void dispatchR0DriverLogRecord(const std::string& logRecordText);
    bool showUnsignedDriverFailureDialog(unsigned long errorCode, const QString& operationText);
    bool enableWindowsTestModeAndPromptReboot();
    bool isR0DriverSignatureFailure(unsigned long errorCode) const;
    void showR0FatalError(const QString& stageText, unsigned long errorCode, const QString& detailText = QString());
    void requestAdminElevationRestart(bool enableR0AfterRestart = false);
    bool hasAdminPrivilege() const;
    bool hasDebugPrivilege() const;
    bool hasSystemPrivilege() const;
    bool enableSeDebugPrivilege(std::string& errorTextOut) const;
    void initDockWidgets();
    QWidget* createDockPlaceholderWidget(const QString& titleText) const;
    void ensureDockContentInitialized(ads::CDockWidget* dockWidget);

    // BackdropBlurKind 作用：
    // - 描述“透明背景效果”配置解析后的磨砂实现方式；
    // - Windows 11 上传统 BLURBEHIND(3) 已退化为纯透明且忽略着色，
    //   DWM 云母又与分层透明窗口互斥（整窗发白），
    //   因此系统亚克力是本项目唯一可用的实时磨砂。
    enum class BackdropBlurKind
    {
        None = 0,    // None：不加磨砂，透明区域直接透出后方内容。
        Acrylic,     // Acrylic：ACCENT_ENABLE_ACRYLICBLURBEHIND，模糊+饱和度+噪点。
    };

    // applyMainWindowBackdropMaterial 作用：
    // - 下发/关闭主窗口的系统亚克力材质（SetWindowCompositionAttribute）；
    // - 透明模式下按“透明背景效果”选项启用，让透明区域呈现磨砂质感；
    // - 着色层不透明度取自 m_currentAppearanceSettings.acrylicTintOpacityPercent，
    //   模糊半径无法由此接口调整（ACCENT_POLICY 不含半径字段，由 DWM 内部固定）。
    // 入参 blurKind：解析后的材质种类；仅 Acrylic 会启用系统材质。
    // 返回：true=系统亚克力已生效（着色由系统合成，根容器不再另画着色层）。
    bool applyMainWindowBackdropMaterial(BackdropBlurKind blurKind);

    // scheduleWindowBackdropRefresh 作用：
    // - 窗口缩放、状态、激活变化或跨显示器后合并调度一次组合特性重下发；
    // - 失焦、最小化恢复与换屏都可能让系统把亚克力降级为静态回退色，
    //   需要重新下发才能恢复；
    // - 同屏移动不调用：DWM 会自动按新位置重采样后方内容（实测三种处理方式
    //   结果完全一致），继续刷新只会白白付出一次整树重绘；
    // - 仅在亚克力已生效时执行，并按节流窗口合并连续事件。
    void scheduleWindowBackdropRefresh();

    // refreshWindowBackdropMaterial 作用：
    // - 按当前“透明背景效果”配置决定是否启用毛玻璃，并同步根容器着色策略；
    // - 首次外观应用发生在原生窗口创建之前，因此 showEvent 需要再调用一次，
    //   否则启动时勾选的毛玻璃要等到下一次主题变更才会生效。
    void refreshWindowBackdropMaterial();

    // refreshBackgroundImageBlurCache 作用：
    // - 按“玻璃模糊半径”设置重建背景图的模糊副本，半径为 0 时清空副本；
    // - 主窗口根容器与浮动 Dock 画刷都通过 cachedBackgroundImage 取图，
    //   在这里统一生成既保证两者观感一致，又避免每次重绘都重新模糊；
    // - 系统亚克力的模糊半径由 DWM 内部固定（ACCENT_POLICY 无半径字段），
    //   因此可调半径只能作用于这一层自绘模糊。
    void refreshBackgroundImageBlurCache();

    // configureDockWidgetPersistentIdentity 作用：
    // - 为每个 ADS Dock 设置稳定 objectName；
    // - ADS saveState/restoreState 依赖 objectName 匹配 Dock，不能依赖可变标题文本；
    // - 入参 dockWidget：待配置的 Dock；dockKey：稳定英文 key。
    void configureDockWidgetPersistentIdentity(ads::CDockWidget* dockWidget, const QString& dockKey) const;

    // restoreDockLayoutFromConfig 作用：
    // - 在默认 Dock 拓扑创建完毕后读取布局配置；
    // - 成功时恢复用户上次拖拽/浮动/Tab 激活状态；
    // - 返回 true 表示恢复成功，false 表示没有配置或恢复失败。
    bool restoreDockLayoutFromConfig();

    // saveDockLayoutToConfig 作用：
    // - 退出前保存 ADS DockManager 布局状态；
    // - 配置文件保存到应用程序 exe 所在目录的 config/ksword_ads_layout.bin；
    // - 返回 true 表示写入成功。
    bool saveDockLayoutToConfig() const;

    // resolveDockLayoutConfigPath 作用：
    // - 统一生成 ADS 布局配置文件绝对路径；
    // - 写入落点固定为应用程序 exe 所在目录的 config 文件夹，不回退源码树。
    QString resolveDockLayoutConfigPath() const;

    // showSettingsPanelFromMenu：
    // - 作用：从顶部菜单栏打开设置内容，替代主 Dock Tab 中的“设置”页签。
    // - showLanguageTab=true 时直接定位到语言设置页。
    void showSettingsPanelFromMenu(bool showLanguageTab = false);
    void toggleLogOutputWindow();
    void persistLogOutputWindowGeometry();
    void restoreLogOutputWindowGeometry();
    // showLicenseFromMenu 作用：读取程序同目录 LICENSE 文件并展示许可证内容。
    void showLicenseFromMenu();

    // buildTitleActionButtonStyle 作用：
    // - 统一生成标题栏左侧功能按钮样式；
    // - 在深浅主题切换后可重复应用，避免标题栏菜单文字颜色漂移。
    // 返回：可直接设置到 QToolButton 的样式文本。
    QString buildTitleActionButtonStyle() const;

    // refreshTitleActionButtonStyles 作用：
    // - 根据当前主题刷新“许可证/插件/窗口/日志/设置”标题栏功能按钮；
    // - 解决深色模式切换后旧浅色样式残留的问题。
    void refreshTitleActionButtonStyles();

    void initializeNextDeferredDock();

    // ensureVisibleLazyDocksInitialized 作用：
    // - 输入 reasonText：触发原因，写入日志便于排查启动黑屏；
    // - 处理：扫描 ADS 当前/可见惰性 Dock，占位页若已进入显示路径则立即挂载真实内容；
    // - 返回：无返回值。
    void ensureVisibleLazyDocksInitialized(const QString& reasonText);

    // repairKernelDockAfterLayoutRestore 作用：
    // - 输入 reasonText：触发来源，写入日志便于排查内核 Dock 启动黑屏；
    // - 处理：确认 ADS 内核 Dock 挂载的是 KernelDock 实例而不是占位页/空壳，并触发当前内部页重绘；
    // - 返回：无返回值。
    void repairKernelDockAfterLayoutRestore(const QString& reasonText);

    // reportStartupProgress 作用：
    // - 安全调用启动进度回调；
    // - 让 MainWindow 内部各阶段都能主动更新 splash 文案。
    // 入参 progressPercent：阶段进度百分比。
    // 入参 textKey：语言包中的稳定位置键。
    // 入参 fallbackText：语言包不可用时的产品兜底文本。
    void reportStartupProgress(
        int progressPercent,
        const QString& textKey,
        const QString& fallbackText) const;

    // initAppearanceSettings 作用：
    // - 读取 SettingsDock/JSON 的外观配置；
    // - 绑定系统深浅色变化回调；
    // - 启动时立即应用一次外观。
    // 调用方式：MainWindow 构造末尾调用。
    void initAppearanceSettings();

    // updateBugcheckDiagnosticsEntryVisibility 作用：把持久化配置与本次安装状态同步到杂项页入口。
    // 调用方式：杂项页构造后、设置页修改自动安装选项或安装 IOCTL 成功后调用。
    // 返回：无。
    void updateBugcheckDiagnosticsEntryVisibility();

    // installBugcheckDiagnosticsAfterServiceStart 作用：自动安装已启用时，在 R0 服务运行后后台发送安装 IOCTL。
    // 调用方式：startR0RuntimeConsumersAfterServiceStart 内部调用；返回：无，失败只记录日志。
    void installBugcheckDiagnosticsAfterServiceStart();

    // reattachDetachedFeatureDocks 作用：
    // - 把布局恢复后仍游离在浮动容器里的主功能 Dock 收回主 Dock 区；
    // - 用户的布局配置是在旧版本保存的，其中不含后来新增的 Dock，
    //   ADS restoreState 不会为它们安置位置，结果就是"新功能默认以窗口弹出"；
    // - 每次新增主功能 Dock 都会遇到同一问题，因此做成通用修复而不是特判。
    // 调用方式：restoreDockLayoutFromConfig 之后调用一次。
    void reattachDetachedFeatureDocks();

    // checkRecentCrashDumps 作用：
    // - 启动稳定后检查系统近 24 小时内是否产生过新的崩溃转储；
    // - 有则弹窗询问是否立即解析，弹窗内含"不再检查"选项；
    // - 同一个转储只询问一次，记录写入外观配置。
    // 调用方式：showEvent 的延迟任务里调用一次；设置关闭时直接返回。
    void checkRecentCrashDumps();

    // openMinidumpDockWithFile 作用：
    // - 激活"转储分析"页（必要时先完成懒加载），并让它解析指定文件；
    // - 该页已并入"杂项"Dock，函数内部会先激活杂项页再切到转储分析子页。
    // 入参 filePath：转储文件完整路径。
    void openMinidumpDockWithFile(const QString& filePath);

    // activateMiscDockForMergedTab 作用：
    // - 激活"杂项"Dock 并确保其内容控件已完成懒加载；
    // - 供"扫描器/转储分析/插件"这些已并入杂项页的入口复用。
    // 入参 tabDisplayName：目标子页显示名，仅用于失败时的日志定位。
    // 返回：杂项页内容控件；返回 nullptr 表示 Dock 尚不可用。
    MiscDock* activateMiscDockForMergedTab(const QString& tabDisplayName);

    void setupDockLayout();

    // initCustomTitleBar 作用：
    // - 初始化主窗口自绘标题栏并替代系统标题栏；
    // - 绑定置顶/窗口控制/命令输入三类交互信号。
    void initCustomTitleBar();

    // initGlobalUiSearchController 作用：
    // - 创建标题栏“搜索”模式的全局页面搜索控制器；
    // - 注入 Dock 列表、懒加载初始化与 Dock 置前激活回调；
    // - 连接标题栏搜索文本与输入模式信号。
    // 调用方式：initCustomTitleBar 完成标题栏创建后调用一次。
    void initGlobalUiSearchController();

    // collectSearchableDockWidgets 作用：
    // - 汇总参与全局页面搜索的 Dock 列表（主功能 Dock + 辅助 Dock）；
    // - 顺序即结果排列顺序，空指针由搜索侧忽略。
    QList<ads::CDockWidget*> collectSearchableDockWidgets() const;

    // activateDockForSearchNavigation 作用：
    // - 搜索结果激活时把目标 Dock 置前：先补齐懒加载内容，
    //   关闭态 Dock 先恢复显示，再在置顶保护下 raise 为当前页签。
    // 入参 dockWidget：目标 Dock，空指针直接忽略。
    void activateDockForSearchNavigation(ads::CDockWidget* dockWidget);

    // syncCustomTitleBarMaximizedState 作用：
    // - 统一计算主窗口“是否处于最大化态”并刷新标题栏第二按钮图标；
    // - 兼容 Qt 状态与 Win32 Zoomed 状态，避免切换瞬间图标不一致。
    void syncCustomTitleBarMaximizedState();

    // ensureNativeFramelessWindowStyle 作用：
    // - 在无边框模式下补齐 Win32 可缩放/可最大化样式位；
    // - 修复 Win+↑/Win+↓ 与系统最大化链路偶发失效问题。
    void ensureNativeFramelessWindowStyle();

    // applyNativeWindowFrameVisualStyle 作用：
    // - 向 DWM 同步当前深浅色状态并关闭系统可见边框；
    // - 修复主窗口在焦点切换时瞬间闪出白色边框的问题。
    // 调用方式：窗口句柄创建完成后、主题切换后调用。
    void applyNativeWindowFrameVisualStyle();

    // initResizeBorderOverlays 作用：
    // - 创建四条独立的 3px 主题蓝色边框控件；
    // - 不修改根容器背景或布局，避免颜色透传污染标题栏/菜单栏。
    void initResizeBorderOverlays();

    // updateResizeBorderOverlays 作用：
    // - 根据当前窗口尺寸重新摆放四条 3px 边框；
    // - 最大化时隐藏边框，窗口化时显示并置顶。
    void updateResizeBorderOverlays();

    // applyResizeBorderOverlayStyle 作用：
    // - 按当前主题主蓝色刷新四条边框控件样式；
    // - 主题切换后可重复调用。
    void applyResizeBorderOverlayStyle();

    // handleResizeBorderOverlayEvent 作用：
    // - 处理四条边框控件的鼠标移动与按下；
    // - 左键按下时桥接为 Win32 原生边框缩放消息。
    bool handleResizeBorderOverlayEvent(QObject* watchedObject, QEvent* event);

    // ensureStartupWindowVisibleOnScreen 作用：
    // - 在主窗口首次 show 后，把窗口尺寸与位置约束到当前可见屏幕；
    // - 修复低分辨率/高缩放下窗口初始区域落到屏幕外或整体超出可视区域的问题；
    // - 仅修正普通窗口态，最大化态保持系统接管。
    void ensureStartupWindowVisibleOnScreen();

    // isWindowActuallyMaximized 作用：
    // - 综合 Qt 状态与 Win32 IsZoomed 判断真实最大化状态；
    // - 避免仅依赖 isMaximized() 造成“按钮状态漂移”。
    bool isWindowActuallyMaximized() const;

    // setWindowMaximizedBySystemCommand 作用：
    // - 通过 Win32 原生窗口状态 API 执行最大化/还原；
    // - 避免在标题栏双击鼠标消息处理中同步 SendMessage 重入，造成闪动与状态错乱。
    // 入参 targetMaximizedState：true=最大化，false=还原。
    void setWindowMaximizedBySystemCommand(bool targetMaximizedState);

    // setPinnedWindowState 作用：
    // - 设置主窗口置顶状态并同步标题栏图钉图标；
    // - 内部使用 SetWindowPos 切换 HWND_TOPMOST/HWND_NOTOPMOST。
    // 入参 pinnedState：目标置顶状态。
    // 入参 emitLog：是否记录状态切换日志。
    void setPinnedWindowState(bool pinnedState, bool emitLog = true);

    // togglePinnedWindowState 作用：
    // - 在当前置顶状态基础上做取反切换。
    void togglePinnedWindowState();

    // persistPinnedWindowPreference 作用：
    // - 将右上角图钉手动切换后的置顶偏好保存到设置 JSON；
    // - 下次启动和设置页复用同一字段。
    void persistPinnedWindowPreference();

    // setCaptureProtectionState 作用：
    // - 设置主窗口截屏屏蔽状态并同步标题栏眼睛图标；
    // - Windows 10 20H2+ 优先使用 WDA_EXCLUDEFROMCAPTURE 隐藏窗口；
    // - 旧系统回退 WDA_MONITOR，让截图/录屏里显示黑屏。
    // 入参 protectedState：true=启用截屏屏蔽，false=允许截屏。
    // 入参 emitLog：是否记录状态切换日志。
    void setCaptureProtectionState(bool protectedState, bool emitLog = true);

    // toggleCaptureProtectionState 作用：
    // - 在当前截屏屏蔽状态基础上做取反切换。
    void toggleCaptureProtectionState();

    // executeCommandInNewConsole 作用：
    // - 使用 CREATE_NEW_CONSOLE 打开可见 cmd 并执行 /K 命令；
    // - 没有弹层实例时回退到当前用户、当前权限和可见 CMD 窗口。
    // 入参 commandText：要执行的命令文本（用户输入）。
    void executeCommandInNewConsole(const QString& commandText);

    // executeCommandWithOptions 作用：
    // - 按标题栏 CMD 弹层给出的目录、用户、权限和窗口选项启动命令；
    // - 普通 CreateProcess、令牌 CreateProcessAsUser 与 UAC runas 均在这里统一收口。
    // 入参 commandText：要执行的命令文本；
    // 入参 options：弹层当前选项快照。
    void executeCommandWithOptions(
        const QString& commandText,
        const ks::ui::CommandExecutionOptions& options);

    // applyAppearanceSettings 作用：
    // - 把主题模式、背景图、透明度应用到主窗口；
    // - 强制设置窗口背景色，规避 Win11 自动接管背景问题。
    // 调用方式：初始化、设置页变更、系统颜色变化时调用。
    // 入参 settings：外观配置结构体。
    // 入参 triggerReason：触发来源文本（日志用途）。
    void applyAppearanceSettings(const ks::settings::AppearanceSettings& settings, const QString& triggerReason);

    // refreshThemeDependentVisuals 作用：
    // - 统一重建所有直接依赖深浅主题或自定义主题色的专用控件样式；
    // - 避免新增主题色消费者时只接入深浅主题变化而遗漏自定义颜色热更新。
    // 调用方式：applyAppearanceSettings 在主题视觉种子变化且主窗口 QSS 更新后调用。
    // 入参 darkModeEnabled：当前最终生效的深色模式状态；传出：无。
    void refreshThemeDependentVisuals(bool darkModeEnabled);

    // isDarkModeEffective 作用：
    // - 根据“手动深浅色/跟随系统”计算当前最终是否深色。
    // 调用方式：应用样式或重建背景时调用。
    // 入参 settings：外观配置结构体。
    // 返回：true=深色；false=浅色。
    bool isDarkModeEffective(const ks::settings::AppearanceSettings& settings) const;

    // rebuildWindowBackgroundBrush 作用：
    // - 把当前纯色、背景图与透明度交给主窗口背景宿主；
    // - 实际缩放和居中在背景宿主 paintEvent 中按真实 rect 完成。
    // 调用方式：外观设置变更时调用。
    void rebuildWindowBackgroundBrush(bool includeBackgroundImage = true);

    // queueBackgroundImageValidation 作用：
    // - 仅在背景路径变化时，把路径探测与图片解码投递到线程池；
    // - UI 线程立即切换到“尚未就绪”的缓存状态，不访问 UNC 或离线盘。
    // 入参 rawImagePath：配置中原始背景路径；传出：无。
    void queueBackgroundImageValidation(const QString& rawImagePath);

    // isCachedBackgroundImageReady 作用：
    // - 只比较内存中的路径键、就绪标记和像素缓存，不执行文件系统调用；
    // - 供主题、滚动条、Dock 惰性初始化和浮动容器刷新安全复用。
    // 入参 rawImagePath：待匹配的配置路径；返回：缓存图片是否可直接使用。
    bool isCachedBackgroundImageReady(const QString& rawImagePath) const;

    // shouldRenderTransparentDockContent 作用：
    // - 判断 Dock 内容根控件是否必须放弃自绘实底；
    // - 背景图就绪要透出图片，启用透明窗口背景时要透出云母材质或桌面；
    // - 两者任一成立都不能让 Dock 画不透明背景，否则底层视觉被整块盖住。
    // 返回：true=内容层应保持透明。
    bool shouldRenderTransparentDockContent() const;

    // cachedBackgroundImage 作用：返回已在线程池完成解码的背景像素缓存。
    // 入参 rawImagePath：待匹配的配置路径；返回：可用图片指针，否则为空。
    const QPixmap* cachedBackgroundImage(const QString& rawImagePath) const;

    // applyFloatingDockContainerAppearance 作用：
    // - 把当前主题色、背景图与样式同步到指定浮动 Dock 容器；
    // - 解决“拖出后浮动窗口背景变成纯黑未填充”的问题。
    void applyFloatingDockContainerAppearance(ads::CFloatingDockContainer* floatingWidget) const;

    // buildAppearanceOverlayStyleSheet 作用：
    // - 生成深色/浅色覆盖样式字符串，叠加在基础 QSS 之后。
    // 调用方式：applyAppearanceSettings 内部调用。
    // 入参 darkModeEnabled：是否使用深色样式。
    // 入参 enableDockContentTransparency：是否强制 Dock 内容层透明；
    //   背景图可用或窗口启用透明背景（云母/直透）时都必须为 true，
    //   否则 Dock 会以不透明表面盖住底层背景图或系统材质。
    // 返回：拼接后的 QSS 片段。
    QString buildAppearanceOverlayStyleSheet(
        const ks::settings::AppearanceSettings& settings,
        bool darkModeEnabled,
        bool enableDockContentTransparency) const;

    // ADS Dock Manager
    QWidget* m_mainRootContainer = nullptr; // m_mainRootContainer：主窗口根容器（承载标题栏+Dock 管理器）。
    QVBoxLayout* m_mainRootLayout = nullptr; // m_mainRootLayout：主窗口根容器纵向布局。
    ads::CDockManager* m_pDockManager = nullptr; // m_pDockManager：ADS Dock 管理器主对象。
    QWidget* m_resizeBorderTop = nullptr; // m_resizeBorderTop：顶部 3px 主题蓝色缩放边框。
    QWidget* m_resizeBorderBottom = nullptr; // m_resizeBorderBottom：底部 3px 主题蓝色缩放边框。
    QWidget* m_resizeBorderLeft = nullptr; // m_resizeBorderLeft：左侧 3px 主题蓝色缩放边框。
    QWidget* m_resizeBorderRight = nullptr; // m_resizeBorderRight：右侧 3px 主题蓝色缩放边框。
    QWidget* m_resizeCornerBottomLeft = nullptr; // m_resizeCornerBottomLeft：左下角 6x6 主题蓝色三角形缩放提示。
    QWidget* m_resizeCornerBottomRight = nullptr; // m_resizeCornerBottomRight：右下角 6x6 主题蓝色三角形缩放提示。

    // Dock Widgets
    ads::CDockWidget* m_dockWelcome = nullptr; // m_dockWelcome：欢迎页 Dock。
    ads::CDockWidget* m_dockProcess = nullptr; // m_dockProcess：进程页 Dock。
    ads::CDockWidget* m_dockNetwork = nullptr; // m_dockNetwork：网络页 Dock。
    ads::CDockWidget* m_dockMemory = nullptr; // m_dockMemory：内存页 Dock。
    ads::CDockWidget* m_dockFile = nullptr; // m_dockFile：文件页 Dock。
    ads::CDockWidget* m_dockDriver = nullptr; // m_dockDriver：驱动页 Dock。
    ads::CDockWidget* m_dockKernel = nullptr; // m_dockKernel：内核页 Dock。
    ads::CDockWidget* m_dockMonitorTab = nullptr; // m_dockMonitorTab：监控页 Dock。
    ads::CDockWidget* m_dockPrivilege = nullptr; // m_dockPrivilege：权限页 Dock。
    ads::CDockWidget* m_dockWindow = nullptr; // m_dockWindow：窗口页 Dock。
    ads::CDockWidget* m_dockRegistry = nullptr; // m_dockRegistry：注册表页 Dock。
    ads::CDockWidget* m_dockHandle = nullptr;
    ads::CDockWidget* m_dockStartup = nullptr; // m_dockStartup：启动项页 Dock。
    ads::CDockWidget* m_dockService = nullptr;
    ads::CDockWidget* m_dockMisc = nullptr;
    ads::CDockWidget* m_dockHardware = nullptr; // m_dockHardware：硬件页 Dock。
    ads::CDockWidget* m_dockCurrentOp = nullptr; // m_dockCurrentOp：底部“当前任务”辅助 Dock。
    ads::CDockWidget* m_dockLog = nullptr; // m_dockLog：底部“日志窗口”辅助 Dock。
    ads::CDockWidget* m_dockImmediate = nullptr; // 已禁用，保留成员以便后续恢复 Dock 代码。
    ads::CDockWidget* m_dockMonitor = nullptr; // m_dockMonitor：底部“监视面板”辅助 Dock。

    // 自定义Widgets
    WelcomeDock* m_welcomeWidget = nullptr; // m_welcomeWidget：欢迎页内容控件。
    ProcessDock* m_processWidget = nullptr; // m_processWidget：进程页内容控件。
    NetworkDock* m_networkWidget = nullptr; // m_networkWidget：网络页内容控件。
    MemoryDock* m_memoryWidget = nullptr; // m_memoryWidget：内存页内容控件。
    FileDock* m_fileWidget = nullptr; // m_fileWidget：文件页内容控件。
    FileDock* m_shellUnlockerFileDock = nullptr; // m_shellUnlockerFileDock：Shell 右键文件解锁器隐藏宿主。
    DriverDock* m_driverWidget = nullptr; // m_driverWidget：驱动页内容控件。
    KernelDock* m_kernelWidget = nullptr; // m_kernelWidget：内核页内容控件。
    MonitorDock* m_monitorWidget = nullptr; // m_monitorWidget：监控页内容控件。
    MonitorPanelWidget* m_monitorPanelWidget = nullptr; // m_monitorPanelWidget：监视面板性能图内容控件。
    HardwareDock* m_hardwareWidget = nullptr; // m_hardwareWidget：硬件页内容控件。
    PrivilegeDock* m_privilegeWidget = nullptr; // m_privilegeWidget：权限页内容控件。
    StartupDock* m_startupWidget = nullptr; // m_startupWidget：启动项页内容控件。
    ServiceDock* m_serviceWidget = nullptr;
    MiscDock* m_miscWidget = nullptr;
    WindowDock* m_windowWidget = nullptr; // m_windowWidget：窗口页内容控件。
    RegistryDock* m_registryWidget = nullptr; // m_registryWidget：注册表页内容控件。
    HandleDock* m_handleWidget = nullptr;
    LogDockWidget* m_logWidget = nullptr; // 非模态“日志输出”独立窗口的日志面板。
    LogDockWidget* m_dockLogWidget = nullptr; // ADS“日志窗口”中的独立日志视图。
    ProgressDockWidget* m_progressWidget = nullptr; // ADS“当前任务”中的任务进度面板。
    CodeEditorWidget* m_immediateEditorWidget = nullptr; // 已禁用，保留即时窗口实现。
    QDialog* m_logOutputWindow = nullptr;
    ks::ui::NotificationCardManager* m_notificationCardManager = nullptr;
    ks::ui::CustomTitleBar* m_customTitleBar = nullptr; // m_customTitleBar：主窗口自绘标题栏组件。
    ks::ui::GlobalUiSearchController* m_globalUiSearchController = nullptr; // m_globalUiSearchController：标题栏全局页面搜索控制器。
    ks::ui::CommandExecutionPopup* m_commandExecutionPopup = nullptr; // m_commandExecutionPopup：标题栏 CMD 选项弹层。
    bool m_windowPinned = false;                        // m_windowPinned：主窗口当前是否置顶。
    bool m_captureProtectionEnabled = false;            // m_captureProtectionEnabled：主窗口当前是否启用截屏屏蔽。

    // 主功能 Dock Tab 栏右侧权限按钮（纯文字）：
    // - UIAccess：SYSTEM TokenUIAccess fallback 与普通用户实例回退；
    // - Admin：管理员权限状态与提权入口；
    // - Debug：SeDebugPrivilege 状态与申请入口；
    // - System：是否 LocalSystem 身份；
    // - R0：驱动服务快捷开关。
    QWidget* m_privilegeButtonContainer = nullptr;
    QToolButton* m_licenseMenuButton = nullptr;  // m_licenseMenuButton：标题栏左侧“许可证”按钮。
    QToolButton* m_pluginMenuButton = nullptr;   // m_pluginMenuButton：标题栏左侧“插件”入口按钮。
    QToolButton* m_windowMenuButton = nullptr;   // m_windowMenuButton：标题栏“窗口”下拉菜单入口。
    QMenu* m_windowMenu = nullptr;               // m_windowMenu：辅助 Dock 显示/隐藏复选菜单。
    QToolButton* m_logMenuButton = nullptr;      // m_logMenuButton：标题栏“日志”窗口切换入口。
    QToolButton* m_settingsMenuButton = nullptr; // m_settingsMenuButton：标题栏左侧“设置”入口按钮。
    QPushButton* m_uiAccessStatusButton = nullptr; // m_uiAccessStatusButton：触发 UIAccess fallback 或降级回普通实例的入口。
    QPushButton* m_adminStatusButton = nullptr;
    QPushButton* m_debugStatusButton = nullptr;
    QPushButton* m_systemStatusButton = nullptr;
    QPushButton* m_r0StatusButton = nullptr;
    bool m_r0DriverServiceRunning = false;      // m_r0DriverServiceRunning：KswordARK 驱动服务当前是否运行。
    bool m_r0UnavailablePromptArmed = false;   // 主窗口显示后才允许 R0 缺失提示，避免启动后台探测造成无意义弹窗。
    bool m_r0UnavailablePromptShowing = false; // 合并同一时间到达的多个 Dock/后台 R0 请求。
    bool m_r0PermissionPromptShowing = false; // 合并短时间内多个 R0 IOCTL 权限不足提示。
    bool m_suppressR0PromptsForSession = false; // “本次不再提醒”仅在当前进程内生效。
    // m_r0NotificationLifetime：让已排队的 R0 通知在窗口析构开始后自行失效。
    std::shared_ptr<std::atomic_bool> m_r0NotificationLifetime =
        std::make_shared<std::atomic_bool>(true);
    std::atomic_bool m_r0DriverLogPollerRunning{ false }; // m_r0DriverLogPollerRunning：R0 日志轮询线程运行标记。
    std::unique_ptr<std::thread> m_r0DriverLogPollerThread; // m_r0DriverLogPollerThread：R0 日志轮询线程对象。
    QTimer* m_privilegeStatusTimer = nullptr;
    QTimer* m_logWindowGeometrySaveTimer = nullptr;

    // m_startupSystemFont 作用：保存任何用户外观配置生效前的系统字体基线。
    QFont m_startupSystemFont;
    // m_currentAppearanceSettings 作用：缓存当前外观配置（主题/背景图/透明度）。
    ks::settings::AppearanceSettings m_currentAppearanceSettings;
    QString m_backgroundImageCacheKey; // m_backgroundImageCacheKey：当前异步验证对应的原始路径键。
    QString m_backgroundImageResolvedPath; // m_backgroundImageResolvedPath：线程池解析后的实际路径，仅供诊断。
    QPixmap m_backgroundImagePixmap; // m_backgroundImagePixmap：UI 线程持有的已解码背景像素。
    QPixmap m_backgroundImageBlurredPixmap; // m_backgroundImageBlurredPixmap：按当前半径模糊后的副本；半径为 0 时为空。
    int m_backgroundImageBlurRadiusApplied = -1; // m_backgroundImageBlurRadiusApplied：副本对应的模糊强度（-1=尚未生成）。
    quint64 m_backgroundImageBlurSourceCacheKey = 0; // m_backgroundImageBlurSourceCacheKey：生成副本时的源图 cacheKey。
    quint64 m_backgroundImageValidationGeneration = 0; // m_backgroundImageValidationGeneration：淘汰过期异步结果的代次。
    bool m_backgroundImageReady = false; // m_backgroundImageReady：当前路径是否已验证并成功解码。
    bool m_backgroundReadinessRefreshPending = false; // m_backgroundReadinessRefreshPending：异步结果是否要求重建视觉。
    int m_backdropMaterialState = -1; // m_backdropMaterialState：已下发的模糊种类缓存（-1 未初始化，其余为 BackdropBlurKind 值）。
    bool m_backdropRefreshQueued = false; // m_backdropRefreshQueued：是否已排队一次亚克力重采样。
    QScreen* m_lastKnownScreen = nullptr; // m_lastKnownScreen：上次 moveEvent 时所在屏幕，用于只在换屏时重下发组合特性。
    StartupProgressCallback m_startupProgressCallback; // m_startupProgressCallback：主窗口启动阶段进度回调。
    bool m_startupWindowVisibilityAdjusted = false; // m_startupWindowVisibilityAdjusted：是否已完成首次显示区域修正。
    bool m_deferredDockInitializationStarted = false; // m_deferredDockInitializationStarted：是否已启动显示后补载流程。
    bool m_dockLayoutRestoredFromConfig = false;     // m_dockLayoutRestoredFromConfig：启动时是否已从配置恢复 ADS 布局。
    bool m_pendingR0DynDataRefresh = false;          // m_pendingR0DynDataRefresh：KernelDock 惰性创建后是否需要补跑 DynData 刷新。
    bool m_bugcheckDiagnosticsInstalledForSession = false; // m_bugcheckDiagnosticsInstalledForSession：当前驱动生命周期内是否已成功安装蓝屏诊断。
    bool m_bugcheckDiagnosticsEntryRequestedForSession = false; // m_bugcheckDiagnosticsEntryRequestedForSession：用户本次操作是否已请求显示诊断入口。
    std::size_t m_nextDeferredDockIndex = 0;          // m_nextDeferredDockIndex：下一个待补载 Dock 队列索引。
    std::vector<ads::CDockWidget*> m_deferredDockLoadQueue; // m_deferredDockLoadQueue：显示后依次补载的 Dock 队列。
};

#endif // MAINWINDOW_H
