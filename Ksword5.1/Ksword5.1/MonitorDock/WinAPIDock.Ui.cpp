#include "MonitorNavigationSchema.h"
#include "WinAPIDock.h"
#include "WinAPIEventTableModel.h"
#include "WinAPIEventTimeline.h"
#include "WinAPIParameterEditor.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/DetailLayoutHost.h"
#include "../UI/StructuredFieldView.h"
#include "../UI/MemoryWorkbench/HexView.h"
#include "../UI/TablePresentation.h"
#include "../UI/TableColumnAutoFit.h"
#include <QSpinBox>
#include <QSettings>
#include <QStandardPaths>
#include <QDir>
#include "../UI/CodeTextEdit.h"
#include "../UI/ThemeItemForeground.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/FlowLayout.h"
#include "../UI/SegmentedControl.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeBinding.h"
#include <QGridLayout>
#include <QGroupBox>
#include "../UI/ThemeStatusRole.h"
#include "../theme.h"

// ============================================================
// WinAPIDock.Ui.cpp
// 作用：
// 1) 集中构建 WinAPI Dock 的控件层次与布局；
// 2) 保持头文件简洁，避免 UI 代码继续堆大；
// 3) 为按钮统一设置语义 SVG、tooltip 和共享主题状态样式。
// ============================================================

#include <QAbstractItemView>
#include <QCheckBox>
#include <QComboBox>
#include <QCompleter>
#include <QFormLayout>
#include <QFrame>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QSet>
#include <QPlainTextEdit>
#include <QPointer>
#include <QPushButton>
#include <QSize>
#include <QSplitter>
#include <QTableWidget>
#include <QTableView>
#include <QTreeWidget>
#include <QTimer>
#include <QTabWidget>
#include <QToolButton>
#include <QStringList>
#include <QVBoxLayout>

namespace
{
    // configureActionIcon：只接入本页审核过的单色 SVG，进程的多色 Shell 图标不走这里。
    // resourcePath 是资源库原始轮廓；按钮状态和当前底面在绘制时由共享主题引擎读取。
    void configureActionIcon(QPushButton* buttonPointer, const QString& resourcePath)
    {
        if (buttonPointer == nullptr)
        {
            return;
        }
        buttonPointer->setProperty("ksword_theme_icon_managed", true);
        buttonPointer->setIcon(ks::ui::MakeThemeButtonAccentIcon(QIcon(resourcePath), QColor(), buttonPointer));
        buttonPointer->setIconSize(QSize(16, 16));
        buttonPointer->setCursor(Qt::PointingHandCursor);
    }

    // configureIconButton：
    // - 作用：统一设置“仅图标按钮”的图标、提示与尺寸；
    // - 调用：刷新、浏览、开始、停止、导出等简单语义按钮都走这里；
    // - 返回：无返回值，控件为空时直接跳过。
    void configureIconButton(
        QPushButton* buttonPointer,
        const QString& resourcePath,
        const QString& toolTipText)
    {
        if (buttonPointer == nullptr)
        {
            return;
        }

        configureActionIcon(buttonPointer, resourcePath);
        buttonPointer->setText(QString());
        buttonPointer->setToolTip(toolTipText);
        buttonPointer->setAccessibleName(toolTipText);
        KswordTheme::ApplyCompactIconButtonMetrics(buttonPointer);
        // 工具行按字体统一高度，图标动作随之保持方形。
        ks::ui::NormalizeToolbarControl(buttonPointer);
    }

    // createPanelFrame：
    // - 作用：创建无描边配置容器，由参数工作区统一提供底面；
    // - 调用：顶部进程选择、左侧 Agent、右侧 Fake Success 三块配置区域复用；
    // - 返回：不绘制额外外框的 QFrame，父对象由调用方传入。
    QFrame* createPanelFrame(QWidget* parentWidget)
    {
        QFrame* const framePointer = new QFrame(parentWidget);
        framePointer->setFrameShape(QFrame::NoFrame);
        framePointer->setFrameShadow(QFrame::Plain);
        return framePointer;
    }


}

void WinAPIDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(8);

    // 配置独立滚动，生命周期动作固定，事件结果不再被多列配置区挤压。
    auto* workspace = new ks::ui::ParameterWorkspace(this, 500);
    m_rootLayout->addWidget(workspace, 1);

    // 顶部进程选择：用户先输入进程名/PID，再从带图标的下拉候选中选中目标。
    m_processPanel = createPanelFrame(workspace);
    QGridLayout* const processPanelLayout = new QGridLayout(m_processPanel);
    processPanelLayout->setContentsMargins(8, 8, 8, 8);
    processPanelLayout->setSpacing(8);

    QLabel* const processTitleLabel = new QLabel(QStringLiteral("目标进程"), m_processPanel);
    ks::ui::StylePrimarySectionTitle(processTitleLabel);

    m_processCombo = new QComboBox(m_processPanel);
    m_processCombo->setEditable(true);
    m_processCombo->setInsertPolicy(QComboBox::NoInsert);
    m_processCombo->setMaxVisibleItems(24);
    m_processCombo->setMinimumWidth(0);
    m_processCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_processCombo->setMinimumContentsLength(18);
    m_processCombo->setStyleSheet(blueInputStyle());
    m_processCombo->setToolTip(QStringLiteral("输入进程名、PID 或路径片段后选择目标。未选择候选时，也可直接输入数字 PID。"));
    if (m_processCombo->lineEdit() != nullptr)
    {
        m_processCombo->lineEdit()->setPlaceholderText(QStringLiteral("输入进程名 / PID / 路径，然后从下拉列表选择"));
        m_processCombo->lineEdit()->setClearButtonEnabled(true);
    }
    if (m_processCombo->completer() != nullptr)
    {
        m_processCombo->completer()->setCaseSensitivity(Qt::CaseInsensitive);
        m_processCombo->completer()->setFilterMode(Qt::MatchContains);
        m_processCombo->completer()->setCompletionMode(QCompleter::PopupCompletion);
    }

    m_processRefreshButton = new QPushButton(m_processPanel);
    configureIconButton(
        m_processRefreshButton,
        QStringLiteral(":/Icon/process_refresh.svg"),
        QStringLiteral("刷新进程候选列表"));

    m_processStatusLabel = new QLabel(QStringLiteral("● 输入进程名或刷新候选列表"), m_processPanel);
    ks::ui::ApplyStatusRole(m_processStatusLabel, ks::ui::StatusRole::Idle);

    processPanelLayout->addWidget(processTitleLabel, 0, 0, 1, 2);
    processPanelLayout->addWidget(m_processCombo, 1, 0);
    processPanelLayout->addWidget(m_processRefreshButton, 1, 1);
    m_processStatusLabel->setWordWrap(true);
    processPanelLayout->addWidget(m_processStatusLabel, 2, 0, 1, 2);
    processPanelLayout->setColumnStretch(0, 1);
    ks::ui::NormalizeToolbarControl(m_processCombo);
    ks::ui::NormalizeToolbarControl(m_processRefreshButton);
    workspace->parameters()->addWidget(m_processPanel);

    auto* sessionGroup = new QGroupBox(QStringLiteral("WinAPI Agent 会话"), workspace);
    m_sessionPanel = sessionGroup;
    auto* sessionPanelLayout = new QVBoxLayout(sessionGroup);
    sessionPanelLayout->setContentsMargins(0, 0, 0, 0);
    sessionPanelLayout->setSpacing(8);

    QVBoxLayout* const sessionConfigurationColumnsLayout = new QVBoxLayout();
    sessionConfigurationColumnsLayout->setContentsMargins(0, 0, 0, 0);
    sessionConfigurationColumnsLayout->setSpacing(8);

    QWidget* const sessionConfigurationLeftColumn = new QWidget(m_sessionPanel);
    QVBoxLayout* const sessionConfigurationLeftLayout = new QVBoxLayout(sessionConfigurationLeftColumn);
    sessionConfigurationLeftLayout->setContentsMargins(0, 0, 0, 0);
    sessionConfigurationLeftLayout->setSpacing(8);

    QFormLayout* const sessionFormLayout = new QFormLayout();
    sessionFormLayout->setContentsMargins(0, 0, 0, 0);
    sessionFormLayout->setHorizontalSpacing(8);
    sessionFormLayout->setVerticalSpacing(8);
    sessionFormLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);

    QWidget* const dllPathRowWidget = new QWidget(sessionConfigurationLeftColumn);
    QHBoxLayout* const dllPathLayout = new QHBoxLayout(dllPathRowWidget);
    dllPathLayout->setContentsMargins(0, 0, 0, 0);
    dllPathLayout->setSpacing(6);
    m_agentDllPathEdit = new QLineEdit(dllPathRowWidget);
    m_agentDllPathEdit->setText(defaultDllPathHint());
    m_agentDllPathEdit->setToolTip(QStringLiteral("Agent DLL 路径；安装监控时根据目标进程位数自动选择同目录下的 APIMonitor_x86.dll 或 APIMonitor_x64.dll。"));
    m_agentDllPathEdit->setStyleSheet(blueInputStyle());

    m_browseAgentDllButton = new QPushButton(dllPathRowWidget);
    configureIconButton(
        m_browseAgentDllButton,
        QStringLiteral(":/Icon/process_open_folder.svg"),
        QStringLiteral("浏览 Agent DLL 路径"));

    dllPathLayout->addWidget(m_agentDllPathEdit, 1);
    dllPathLayout->addWidget(m_browseAgentDllButton, 0);
    sessionFormLayout->addRow(QStringLiteral("Agent DLL"), dllPathRowWidget);

    m_manualPidEdit = new QLineEdit(sessionConfigurationLeftColumn);
    m_manualPidEdit->setPlaceholderText(QStringLiteral("可留空；填写后覆盖顶部进程选择"));
    m_manualPidEdit->setToolTip(QStringLiteral("高级兜底：当下拉候选没有目标时，可直接输入 PID。填写后优先使用这里的 PID。"));
    m_manualPidEdit->setStyleSheet(blueInputStyle());
    sessionFormLayout->addRow(QStringLiteral("目标 PID（高级）"), m_manualPidEdit);
    sessionConfigurationLeftLayout->addLayout(sessionFormLayout);

    QFrame* const categoryFrame = createPanelFrame(sessionConfigurationLeftColumn);
    QVBoxLayout* const categoryLayout = new QVBoxLayout(categoryFrame);
    categoryLayout->setContentsMargins(8, 8, 8, 8);
    categoryLayout->setSpacing(6);

    QLabel* const categoryTitleLabel = new QLabel(QStringLiteral("Hook 分类"), categoryFrame);
    categoryLayout->addWidget(categoryTitleLabel, 0);

    m_hookFileCheck = new QCheckBox(QStringLiteral("文件 API"), categoryFrame);
    m_hookRegistryCheck = new QCheckBox(QStringLiteral("注册表 API"), categoryFrame);
    m_hookNetworkCheck = new QCheckBox(QStringLiteral("网络 API"), categoryFrame);
    m_hookProcessCheck = new QCheckBox(QStringLiteral("进程 API"), categoryFrame);
    m_hookMemoryCheck = new QCheckBox(QStringLiteral("内存 API"), categoryFrame);
    m_hookThreadCheck = new QCheckBox(QStringLiteral("线程 API"), categoryFrame);
    m_hookServiceCheck = new QCheckBox(QStringLiteral("服务 API"), categoryFrame);
    m_hookSecurityCheck = new QCheckBox(QStringLiteral("权限 API"), categoryFrame);
    m_hookCryptoCheck = new QCheckBox(QStringLiteral("加密 API"), categoryFrame);
    m_hookComCheck = new QCheckBox(QStringLiteral("COM API"), categoryFrame);
    m_hookWindowCheck = new QCheckBox(QStringLiteral("窗口 API"), categoryFrame);
    m_hookGuiCheck = new QCheckBox(QStringLiteral("GUI API"), categoryFrame);
    m_hookGuiCheck->setToolTip(QStringLiteral("GDI、绘图与 DC 调用单独采集，默认关闭；窗口生命周期、消息和菜单属于窗口 API。"));
    m_hookLoaderCheck = new QCheckBox(QStringLiteral("加载器 API"), categoryFrame);
    m_hookClipboardCheck = new QCheckBox(QStringLiteral("剪贴板 API"), categoryFrame);
    m_autoInjectChildCheck = new QCheckBox(QStringLiteral("自动注入子进程"), categoryFrame);
    auto* callStackOptionsRow = new QWidget(categoryFrame);
    m_captureCallStackCheck = new QCheckBox(QStringLiteral("采集强类型调用栈"), callStackOptionsRow);
    m_rawFallbackCheck = new QCheckBox(QStringLiteral("Raw 兜底 Hook（强类型优先）"), categoryFrame);
    m_rawDefaultDenyListCheck = new QCheckBox(QStringLiteral("启用默认高频/高风险黑名单"), categoryFrame);
    auto* rawConfigurationFrame = new QGroupBox(QStringLiteral("Raw 兜底配置"), m_sessionPanel);
    QVBoxLayout* const rawConfigurationLayout = new QVBoxLayout(rawConfigurationFrame);
    rawConfigurationLayout->setContentsMargins(8, 8, 8, 8);
    rawConfigurationLayout->setSpacing(6);



    auto* moduleListEditor = new CodeTextEdit(rawConfigurationFrame);
    auto* denyListEditor = new CodeTextEdit(rawConfigurationFrame);
    moduleListEditor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    denyListEditor->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
    moduleListEditor->setLineNumbersVisible(false);
    moduleListEditor->setCompactMode(true);
    denyListEditor->setLineNumbersVisible(false);
    denyListEditor->setCompactMode(true);
    m_rawModuleListEdit = moduleListEditor;
    m_rawDenyListEdit = denyListEditor;

    m_hookFileCheck->setChecked(true);
    m_hookRegistryCheck->setChecked(true);
    m_hookNetworkCheck->setChecked(true);
    m_hookProcessCheck->setChecked(true);
    m_hookMemoryCheck->setChecked(true);
    m_hookThreadCheck->setChecked(true);
    m_hookServiceCheck->setChecked(true);
    m_hookSecurityCheck->setChecked(true);
    m_hookCryptoCheck->setChecked(true);
    m_hookComCheck->setChecked(true);
    m_hookWindowCheck->setChecked(true);
    m_hookGuiCheck->setChecked(false);
    m_hookLoaderCheck->setChecked(false);
    m_hookClipboardCheck->setChecked(false);
    m_autoInjectChildCheck->setChecked(false);
    m_captureCallStackCheck->setChecked(false);
    m_rawFallbackCheck->setChecked(true);
    m_rawDefaultDenyListCheck->setChecked(true);
    m_rawModuleListEdit->setPlainText(defaultRawHookModulesText());
    m_rawDenyListEdit->clear();
    m_rawModuleListEdit->setStyleSheet(blueInputStyle());
    m_rawDenyListEdit->setStyleSheet(blueInputStyle());
    m_rawModuleListEdit->setFixedHeight(76);
    m_rawDenyListEdit->setFixedHeight(76);
    m_rawModuleListEdit->setPlaceholderText(QStringLiteral("ntdll.dll;KernelBase.dll;ws2_32.dll;wininet.dll;..."));
    m_rawDenyListEdit->setPlaceholderText(QStringLiteral("额外规则，例如 MyHotApi;SomePrefix*；默认黑名单由上方复选框控制"));

    m_hookFileCheck->setToolTip(QStringLiteral("CreateFileW / ReadFile / WriteFile 等文件访问相关 API。"));
    m_hookRegistryCheck->setToolTip(QStringLiteral("RegOpenKeyExW / RegQueryValueExW / RegSetValueExW / RegDeleteValueW / RegEnum* 等注册表相关 API。"));
    m_hookNetworkCheck->setToolTip(QStringLiteral("connect / WSAConnect / send / WSASend / sendto / recv / WSARecv / recvfrom 等网络相关 API。"));
    m_hookProcessCheck->setToolTip(QStringLiteral("CreateProcessW 等进程控制相关 API。"));
    m_hookLoaderCheck->setToolTip(QStringLiteral("LoadLibraryW / LoadLibraryExW 等模块加载相关 API。该类 Hook 对 GUI 进程稳定性风险更高，默认关闭。"));
    m_hookClipboardCheck->setToolTip(QStringLiteral("OpenClipboard / GetClipboardData / SetClipboardData / OleGetClipboard 等剪贴板相关 API。独立于「进程 API」分类，也是「剪贴板保护」杂项页复用的同一套 Hook。"));
    m_autoInjectChildCheck->setToolTip(QStringLiteral("启用后，Agent 会在受支持的 CreateProcess 系列调用成功时自动注入子进程，并继续监控后代；支持 x86 与 x64 进程，自动选择对应 Agent。"));
    m_captureCallStackCheck->setToolTip(QStringLiteral("可增加监控开销；仅采集强类型调用，最多 8 帧，可能含监控内部帧或因详情空间不足而缺失。"));
    m_rawFallbackCheck->setToolTip(QStringLiteral("对强类型表未覆盖的已加载模块导出安装 Raw ABI 入口 Hook。强类型 Hook 优先，Raw 只记录模块/函数/地址等兜底信息。"));
    m_rawDefaultDenyListCheck->setToolTip(QStringLiteral("Raw 黑名单只影响兜底 Hook；强类型 Hook 不受影响。建议长期保持开启，避免字符串、堆、锁、时间等高频基础 API 刷爆日志。关闭后，下方额外黑名单仍然生效。"));
    m_rawModuleListEdit->setToolTip(QStringLiteral("分号分隔模块名。Agent 只扫描已加载模块，后续 LoadLibrary 后会重试补装。"));
    m_rawDenyListEdit->setToolTip(QStringLiteral("用户额外黑名单，分号分隔函数名，支持 prefix*。内置默认黑名单由上方复选框控制，不需要复制到这里。当前内置默认：%1").arg(defaultRawHookDenyListText()));

    auto* categoryChoices = new QWidget(categoryFrame);
    categoryChoices->setObjectName(QStringLiteral("winapi_hook_category_choices"));
    auto* categoryFlow = new ks::ui::FlowLayout(categoryChoices, 0, 12, 6);
    categoryFlow->addWidget(m_hookFileCheck);
    categoryFlow->addWidget(m_hookRegistryCheck);
    categoryFlow->addWidget(m_hookNetworkCheck);
    categoryFlow->addWidget(m_hookProcessCheck);
    categoryFlow->addWidget(m_hookMemoryCheck);
    categoryFlow->addWidget(m_hookThreadCheck);
    categoryFlow->addWidget(m_hookServiceCheck);
    categoryFlow->addWidget(m_hookSecurityCheck);
    categoryFlow->addWidget(m_hookCryptoCheck);
    categoryFlow->addWidget(m_hookComCheck);
    categoryFlow->addWidget(m_hookWindowCheck);
    categoryFlow->addWidget(m_hookGuiCheck);
    categoryFlow->addWidget(m_hookLoaderCheck);
    categoryFlow->addWidget(m_hookClipboardCheck);
    categoryLayout->addWidget(categoryChoices, 0);
    categoryLayout->addWidget(m_autoInjectChildCheck, 0);
    auto* callStackOptionsLayout = new ks::ui::FlowLayout(callStackOptionsRow, 0, 6, 6);
    callStackOptionsLayout->addWidget(m_captureCallStackCheck);
    auto* captureModeHelp = new QLabel(callStackOptionsRow);
    captureModeHelp->setObjectName(QStringLiteral("winapi_capture_mode_help"));
    captureModeHelp->setAlignment(Qt::AlignCenter);
    captureModeHelp->setFixedSize(KswordTheme::CompactIconButtonSize());
    captureModeHelp->setAccessibleName(QStringLiteral("强类型与 Raw 的区别"));
    captureModeHelp->setToolTip(QStringLiteral("<qt><p>这里的“强类型”是本项目的采集方式约定，不是 Windows 官方的 API 分类。</p><p><b>强类型：</b>项目已明确该 API 的函数签名，并实现生成或专用包装器；按接口实现记录有语义的参数或指针地址、返回值和耗时，部分接口还可解析字符串等内容。</p><p><b>Raw：</b>对强类型定义表之外的导出使用通用入口钩子，记录函数、地址及原始寄存器/栈槽。槽位不等于已知参数，不自动读取指针内容，也不采集返回值或耗时。</p><p><b>本开关：</b>仅为强类型调用额外采集最多 8 帧调用栈；可能包含监控内部帧，也可能受详情容量限制而缺失。Raw 只有入口调用位置，不提供此调用栈。</p><p>实际安装情况请查看“API 覆盖”；勾选分类不代表该类所有 API 都已覆盖。</p></qt>"));
    const QPointer<QLabel> helpTarget(captureModeHelp);
    ks::ui::BindWidgetTheme(captureModeHelp, [helpTarget]() {
        if (helpTarget)
            helpTarget->setPixmap(ks::ui::MakeThemeAccentIcon(QIcon(QStringLiteral(":/Icon/winapi_capture_help.svg")))
                .pixmap(KswordTheme::CompactIconSize()));
    });
    callStackOptionsLayout->addWidget(captureModeHelp);
    categoryLayout->addWidget(callStackOptionsRow, 0);
    categoryLayout->addWidget(m_rawFallbackCheck, 0);
    categoryLayout->addWidget(m_rawDefaultDenyListCheck, 0);
    sessionConfigurationLeftLayout->addWidget(categoryFrame, 0);

    rawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 模块目录（; 分隔）"), rawConfigurationFrame), 0);
    rawConfigurationLayout->addWidget(m_rawModuleListEdit, 0);
    rawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 额外黑名单（exact / prefix*）"), rawConfigurationFrame), 0);
    rawConfigurationLayout->addWidget(m_rawDenyListEdit, 0);


    sessionConfigurationColumnsLayout->addWidget(sessionConfigurationLeftColumn);
    sessionConfigurationColumnsLayout->addWidget(ks::ui::FoldParameterSection(rawConfigurationFrame));
    sessionPanelLayout->addLayout(sessionConfigurationColumnsLayout);

    QHBoxLayout* const sessionButtonLayout = workspace->actions();
    sessionButtonLayout->setSpacing(6);

    m_startButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_startButton,
        QStringLiteral(":/Icon/process_start.svg"),
        QStringLiteral("启动 WinAPI 监控"));

    m_r0InjectCheck = new QCheckBox(QStringLiteral("R0注入"), m_sessionPanel);
    m_r0InjectCheck->setObjectName(QStringLiteral("win_api_r0_injection"));
    m_r0InjectCheck->setToolTip(QStringLiteral("使用驱动为目标进程加载 Agent；需要可用的 R0 驱动。"));
    const QString monitorSettingsRoot = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    m_r0InjectCheck->setChecked(false);
    if (!monitorSettingsRoot.isEmpty()) {
        QSettings monitorSettings(QDir(monitorSettingsRoot).filePath(QStringLiteral("api-monitor-view.ini")), QSettings::IniFormat);
        m_r0InjectCheck->setChecked(monitorSettings.value(QStringLiteral("use_r0_injection"), false).toBool());
    }

    m_pauseEventsCheck = new QCheckBox(QStringLiteral("暂停"), m_sessionPanel);
    m_pauseEventsCheck->setToolTip(QStringLiteral("暂停时停止接收事件，并由 Agent 暂时移除 Hook；恢复时重新安装 Hook。"));

    m_stopButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_stopButton,
        QStringLiteral(":/Icon/process_stop.svg"),
        QStringLiteral("停止 WinAPI 监控"));

    m_terminateHookButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_terminateHookButton,
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("手动终止目标进程中的 Hook"));

    m_exportButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_exportButton,
        QStringLiteral(":/Icon/log_export.svg"),
        QStringLiteral("导出筛选事件为 CSV 或 TSV，包含 A/B 视图的全部列"));

    m_clearEventButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_clearEventButton,
        QStringLiteral(":/Icon/log_clear.svg"),
        QStringLiteral("清空当前事件表"));

    sessionButtonLayout->addWidget(m_startButton, 0);
    sessionButtonLayout->addWidget(m_r0InjectCheck, 0);
    sessionButtonLayout->addWidget(m_pauseEventsCheck, 0);
    sessionButtonLayout->addWidget(m_stopButton, 0);
    sessionButtonLayout->addWidget(m_terminateHookButton, 0);

    sessionButtonLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(sessionButtonLayout);


    m_sessionStatusLabel = new QLabel(QStringLiteral("● 空闲"), m_sessionPanel);
    ks::ui::ApplyStatusRole(m_sessionStatusLabel, ks::ui::StatusRole::Idle);
    m_sessionStatusLabel->setWordWrap(true);
    workspace->results()->addWidget(m_sessionStatusLabel);
    ks::ui::StyleParameterSection(sessionGroup);
    workspace->parameters()->addWidget(sessionGroup);

    auto* archiveGroup = new QGroupBox(QStringLiteral("事件保留与归档"), workspace);
    auto* archiveLayout = new QVBoxLayout(archiveGroup);
    auto* archiveForm = new QFormLayout();
    archiveForm->setRowWrapPolicy(QFormLayout::WrapLongRows);
    m_eventMemoryBudget = new QSpinBox(archiveGroup);
    m_eventMemoryBudget->setRange(16, 65536);
    m_eventMemoryBudget->setSuffix(QStringLiteral(" MiB"));
    m_eventMemoryBudget->setKeyboardTracking(false);
    const QString settingsRoot = QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation);
    QSettings archiveSettings(QDir(settingsRoot).filePath(QStringLiteral("api-monitor-view.ini")), QSettings::IniFormat);
    m_eventMemoryBudget->setValue(archiveSettings.value(QStringLiteral("memoryMiB"), 512).toInt());
    m_eventArchive.setMemoryCapacity(static_cast<std::size_t>(m_eventMemoryBudget->value()) * 1024 * 1024);
    archiveForm->addRow(QStringLiteral("文本预算："), m_eventMemoryBudget);
    archiveLayout->addLayout(archiveForm);
    m_diskArchiveStatus = new QLabel(QStringLiteral("归档：等待开始监控"), archiveGroup);
    m_diskArchiveStatus->setWordWrap(true);
    m_diskArchiveStatus->setTextInteractionFlags(Qt::TextSelectableByMouse);
    archiveLayout->addWidget(m_diskArchiveStatus);
    m_openDiskArchiveButton = new QPushButton(QStringLiteral("打开归档目录"), archiveGroup);
    m_openDiskArchiveButton->setEnabled(false);
    archiveLayout->addWidget(m_openDiskArchiveButton, 0, Qt::AlignLeft);
    ks::ui::StyleParameterSection(archiveGroup);
    workspace->parameters()->addWidget(archiveGroup);

    auto* fakeSuccessPanel = new QGroupBox(QStringLiteral("Fake Success（命中 API 直接伪返回）"), workspace);
    QVBoxLayout* const fakeSuccessLayout = new QVBoxLayout(fakeSuccessPanel);
    fakeSuccessLayout->setContentsMargins(8, 8, 8, 8);
    fakeSuccessLayout->setSpacing(6);

    QFormLayout* const fakeFormLayout = new QFormLayout();
    fakeFormLayout->setContentsMargins(0, 0, 0, 0);
    fakeFormLayout->setHorizontalSpacing(8);
    fakeFormLayout->setVerticalSpacing(6);
    fakeFormLayout->setRowWrapPolicy(QFormLayout::WrapLongRows);

    m_fakeModuleEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeApiEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeReturnValueEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeLastErrorValueEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeX86StackBytesEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeReturnTypeCombo = new QComboBox(fakeSuccessPanel);
    m_fakeLastErrorKindCombo = new QComboBox(fakeSuccessPanel);
    m_fakeRawFallbackCheck = new QCheckBox(QStringLiteral("启用 Fake Raw 兜底（未强类型导出仅伪造标量返回值）"), fakeSuccessPanel);

    m_fakeModuleEdit->setPlaceholderText(QStringLiteral("KernelBase.dll"));
    m_fakeApiEdit->setPlaceholderText(QStringLiteral("CreateFileW"));
    // 精确匹配口径挂到对应输入框，避免面板顶部再压一段常驻说明。
    m_fakeModuleEdit->setToolTip(QStringLiteral("精确匹配模块名，需要带扩展名。"));
    m_fakeApiEdit->setToolTip(QStringLiteral("精确匹配导出名，区分 A/W 后缀。"));
    m_fakeReturnValueEdit->setPlaceholderText(QStringLiteral("0 / 1 / 0x0 / 0xFFFFFFFFFFFFFFFF"));
    m_fakeLastErrorValueEdit->setPlaceholderText(QStringLiteral("0 表示 ERROR_SUCCESS"));
    m_fakeReturnValueEdit->setText(QStringLiteral("0"));
    m_fakeLastErrorValueEdit->setText(QStringLiteral("0"));
    m_fakeModuleEdit->setStyleSheet(blueInputStyle());
    m_fakeApiEdit->setStyleSheet(blueInputStyle());
    m_fakeReturnValueEdit->setStyleSheet(blueInputStyle());
    m_fakeLastErrorValueEdit->setStyleSheet(blueInputStyle());
    m_fakeX86StackBytesEdit->setStyleSheet(blueInputStyle());
    m_fakeX86StackBytesEdit->setPlaceholderText(QStringLiteral("留空：已知签名自动计算"));
    m_fakeX86StackBytesEdit->setToolTip(QStringLiteral("仅用于 32 位 Fake：留空时使用已知 API 签名；未知导出必须填写。stdcall 填写参数占用的栈字节数，cdecl 填 0；不支持 fastcall 或浮点/结构返回。"));

    m_fakeReturnTypeCombo->addItem(QStringLiteral("Scalar / RAX"), QStringLiteral("scalar"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("BOOL"), QStringLiteral("bool"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("HANDLE / PVOID"), QStringLiteral("handle"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("DWORD / UINT / int"), QStringLiteral("dword"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("NTSTATUS"), QStringLiteral("ntstatus"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("HRESULT"), QStringLiteral("hresult"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("LSTATUS"), QStringLiteral("lstatus"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("SOCKET / int (WSA)"), QStringLiteral("socket"));
    m_fakeReturnTypeCombo->setToolTip(QStringLiteral("模板只影响展示和结果码语义；只伪造标量返回值，不写 out 参数。Fake 路径会先上报事件，再跳过原 API 并返回指定值。"));
    m_fakeReturnTypeCombo->setStyleSheet(blueInputStyle());

    m_fakeLastErrorKindCombo->addItem(QStringLiteral("不修改 LastError"), QStringLiteral("none"));
    m_fakeLastErrorKindCombo->addItem(QStringLiteral("SetLastError"), QStringLiteral("win32"));
    m_fakeLastErrorKindCombo->addItem(QStringLiteral("WSASetLastError"), QStringLiteral("wsa"));
    m_fakeLastErrorKindCombo->setToolTip(QStringLiteral("可选：Fake 返回前后设置 Win32 LastError 或 WSAError。"));
    m_fakeLastErrorKindCombo->setStyleSheet(blueInputStyle());
    m_fakeRawFallbackCheck->setChecked(false);
    m_fakeRawFallbackCheck->setToolTip(QStringLiteral("关闭时，仅强类型表覆盖的 API 可 Fake Success；开启后，未强类型覆盖的 module!api 也可伪造标量返回值，32 位未知导出必须填写栈清理字节数。"));

    fakeFormLayout->addRow(QStringLiteral("模块"), m_fakeModuleEdit);
    fakeFormLayout->addRow(QStringLiteral("API"), m_fakeApiEdit);
    fakeFormLayout->addRow(QStringLiteral("返回模板"), m_fakeReturnTypeCombo);
    fakeFormLayout->addRow(QStringLiteral("返回值"), m_fakeReturnValueEdit);
    fakeFormLayout->addRow(QStringLiteral("错误码类型"), m_fakeLastErrorKindCombo);
    fakeFormLayout->addRow(QStringLiteral("错误码值"), m_fakeLastErrorValueEdit);
    fakeFormLayout->addRow(QStringLiteral("32 位栈清理字节"), m_fakeX86StackBytesEdit);
    fakeSuccessLayout->addLayout(fakeFormLayout);
    fakeSuccessLayout->addWidget(m_fakeRawFallbackCheck, 0);

    auto* fakeButtonLayout = new QGridLayout();
    fakeButtonLayout->setContentsMargins(0, 0, 0, 0);
    fakeButtonLayout->setSpacing(6);
    m_fakeAddRuleButton = new QPushButton(QStringLiteral("添加规则"), fakeSuccessPanel);
    m_fakeRemoveRuleButton = new QPushButton(QStringLiteral("删除选中"), fakeSuccessPanel);
    m_fakeApplyRuleButton = new QPushButton(QStringLiteral("应用规则并启动"), fakeSuccessPanel);
    m_fakeStopRuleButton = new QPushButton(QStringLiteral("停止会话"), fakeSuccessPanel);
    // Fake Success 保留解释性文字，用同一套图标区分增删规则与会话启停。
    configureActionIcon(m_fakeAddRuleButton, QStringLiteral(":/Icon/plus.svg"));
    configureActionIcon(m_fakeRemoveRuleButton, QStringLiteral(":/Icon/log_clear.svg"));
    configureActionIcon(m_fakeApplyRuleButton, QStringLiteral(":/Icon/process_start.svg"));
    configureActionIcon(m_fakeStopRuleButton, QStringLiteral(":/Icon/process_stop.svg"));
    m_fakeAddRuleButton->setToolTip(QStringLiteral("把上方输入加入规则表；启动 WinAPI 监控时写入 Agent 配置并生效。"));
    m_fakeRemoveRuleButton->setToolTip(QStringLiteral("删除规则表当前选中的 Fake Success 规则。"));
    m_fakeApplyRuleButton->setToolTip(QStringLiteral("用当前规则表写入配置并启动 WinAPI Agent。若会话已运行，请先停止再应用。"));
    m_fakeStopRuleButton->setToolTip(QStringLiteral("停止当前 WinAPI Agent 会话；Fake Success 不支持运行中热更新。"));
    // 规则动作按两列排列，保留真实确认/停止入口，不压缩成四个挤在一起的按钮。
    fakeButtonLayout->addWidget(m_fakeAddRuleButton, 0, 0);
    fakeButtonLayout->addWidget(m_fakeRemoveRuleButton, 0, 1);
    fakeButtonLayout->addWidget(m_fakeApplyRuleButton, 1, 0);
    fakeButtonLayout->addWidget(m_fakeStopRuleButton, 1, 1);
    for (QPushButton* button : { m_fakeAddRuleButton, m_fakeRemoveRuleButton, m_fakeApplyRuleButton, m_fakeStopRuleButton })
        ks::ui::NormalizeToolbarControl(button);
    fakeSuccessLayout->addLayout(fakeButtonLayout);

    m_fakeRuleTable = new ks::ui::VisibleTableWidget(fakeSuccessPanel);
    // 返回规则是本页配置，添加/删除由本页按钮负责。
    ks::ui::SetTableActionBarMode(m_fakeRuleTable, ks::ui::TableActionBarMode::None);
    m_fakeRuleTable->setColumnCount(FakeRuleColumnCount);
    m_fakeRuleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_fakeRuleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_fakeRuleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_fakeRuleTable->setAlternatingRowColors(true);
    m_fakeRuleTable->setHorizontalHeaderLabels(
        QStringList{
            QStringLiteral("模块"),
            QStringLiteral("API"),
            QStringLiteral("返回模板"),
            QStringLiteral("返回值"),
            QStringLiteral("错误类型"),
            QStringLiteral("错误值"),
            QStringLiteral("32 位栈清理字节")
        });
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnModule, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnApi, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnReturnType, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnReturnValue, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnLastErrorKind, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnLastErrorValue, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnX86StackBytes, QHeaderView::Stretch);
    m_fakeRuleTable->setMaximumHeight(170);
    fakeSuccessLayout->addWidget(m_fakeRuleTable, 0);

    m_fakeRuleStatusLabel = new QLabel(QStringLiteral("规则：0 条；启动会话时应用。"), fakeSuccessPanel);
    ks::ui::ApplyStatusRole(m_fakeRuleStatusLabel, ks::ui::StatusRole::Idle);
    fakeSuccessLayout->addWidget(m_fakeRuleStatusLabel, 0);
    fakeSuccessLayout->addStretch(1);

    workspace->parameters()->addWidget(ks::ui::FoldParameterSection(fakeSuccessPanel));

    m_filterPanel = new QWidget(this);
    ks::ui::StylePrimaryToolbar(m_filterPanel);
    QHBoxLayout* const filterLayout = new QHBoxLayout(m_filterPanel);
    filterLayout->setContentsMargins(8, 6, 8, 6);
    filterLayout->setSpacing(6);

    m_eventFilterEdit = new QLineEdit(m_filterPanel);
    m_eventFilterEdit->setPlaceholderText(QStringLiteral("过滤 API / 分类 / 结果 / 详情"));
    m_eventFilterEdit->setStyleSheet(blueInputStyle());
    ks::ui::StyleSearchField(m_eventFilterEdit);

    m_eventFilterClearButton = new QPushButton(m_filterPanel);
    configureIconButton(
        m_eventFilterClearButton,
        QStringLiteral(":/Icon/log_cancel_track.svg"),
        QStringLiteral("清空事件过滤条件"));

    m_eventKeepBottomCheck = new QCheckBox(QStringLiteral("保持贴底"), m_filterPanel);
    m_eventKeepBottomCheck->setChecked(true);
    m_eventKeepBottomCheck->setToolTip(QStringLiteral("新事件到来时自动滚动到最底部。"));
    m_showEventDetails = new QCheckBox(QStringLiteral("显示详情"), m_filterPanel);
    m_showEventDetails->setChecked(false);

    m_eventFilterStatusLabel = new QLabel(QStringLiteral("筛选结果：0 / 0"), m_filterPanel);
    ks::ui::ApplyStatusRole(m_eventFilterStatusLabel, ks::ui::StatusRole::Idle);

    filterLayout->addWidget(m_eventFilterEdit, 1);
    filterLayout->addWidget(m_eventFilterClearButton, 0);
    filterLayout->addWidget(m_eventKeepBottomCheck, 0);
    filterLayout->addWidget(m_showEventDetails, 0);
    filterLayout->addWidget(m_eventFilterStatusLabel, 0);
    filterLayout->addWidget(m_exportButton);
    filterLayout->addWidget(m_clearEventButton);
    ks::ui::NormalizeToolbarRow(filterLayout);
    // 只连接事件过滤条与结果Tab，不更改参数工作区标题等其它组件之间的间距。
    QWidget* const eventResults = new QWidget(this);
    auto* const eventResultsLayout = new QVBoxLayout(eventResults);
    eventResultsLayout->setContentsMargins(0, 0, 0, 0);
    eventResultsLayout->setSpacing(0);
    eventResultsLayout->addWidget(m_filterPanel);
    workspace->results()->addWidget(eventResults, 1);

    m_eventTable = new ks::ui::TableActionTableView(this);
    m_eventModel = new WinAPIEventTableModel(m_eventTable);
    m_eventProxy = new WinAPIEventFilterModel(m_eventTable);
    m_eventProxy->setSourceModel(m_eventModel);
    m_eventTable->setModel(m_eventProxy);
    m_eventTable->setProperty("ks_i18n_preserve_model_data", true);
    ks::ui::SetTableActionBarMode(m_eventTable, ks::ui::TableActionBarMode::Full);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_eventTable->setAlternatingRowColors(true);
    ks::ui::InstallThemeItemForegroundDelegate(m_eventTable);
    m_eventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_eventTable->setWordWrap(false);
    m_eventTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    m_eventTable->verticalHeader()->setDefaultSectionSize(22);
    m_eventTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    // The event table has well-defined columns; sampling empty rows compresses B to unreadable widths.
    ks::ui::SetTableColumnAutoFitEnabled(m_eventTable, false);
    m_eventTable->setColumnWidth(EventColumnTime100ns,
        m_eventTable->fontMetrics().horizontalAdvance(QStringLiteral("00:00:00.000")) + 24);
    m_eventTable->setColumnWidth(EventColumnCategory, 72);
    m_eventTable->setColumnWidth(EventColumnApi, 190);
    m_eventTable->setColumnWidth(EventColumnResult, 100);
    m_eventTable->setColumnWidth(EventColumnPidTid, 112);
    m_eventTable->setColumnWidth(EventColumnDetail, 440);
    const auto widthFor = [this](const QString& sample) { return m_eventTable->fontMetrics().horizontalAdvance(sample) + 28; };
    m_eventTable->setColumnWidth(ks::monitor::Pid, widthFor(QStringLiteral("4294967295")));
    m_eventTable->setColumnWidth(ks::monitor::Tid, widthFor(QStringLiteral("4294967295")));
    m_eventTable->setColumnWidth(ks::monitor::Duration, widthFor(QStringLiteral("99999.9999 ms")));
    m_eventTable->setColumnWidth(ks::monitor::CallerModule, widthFor(QStringLiteral("combase.dll [snapshot]")));
    m_eventTable->setColumnWidth(ks::monitor::CallerAddress, widthFor(QStringLiteral("0xFFFFFFFFFFFFFFFF")));
    m_eventTable->setColumnWidth(ks::monitor::MemoryKind, widthFor(QStringLiteral("uncommitted [snapshot]")));
    m_eventTable->setColumnWidth(ks::monitor::CaptureKind, widthFor(QStringLiteral("采集方式")));
    m_eventTable->setAutoFillBackground(false);
    m_eventTable->setAttribute(Qt::WA_StyledBackground, true);
    if (m_eventTable->viewport() != nullptr)
    {
        m_eventTable->viewport()->setAutoFillBackground(false);
        m_eventTable->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    m_resultTabs = new QTabWidget(this);
    ks::ui::StyleJoinedResultTabs(m_resultTabs, m_filterPanel);
    auto* eventPage = new QWidget(m_resultTabs);
    auto* eventPageLayout = new QVBoxLayout(eventPage);
    eventPageLayout->setContentsMargins(0, 0, 0, 0); eventPageLayout->setSpacing(6);
    m_apiTimeline = new WinAPIEventTimeline(eventPage, m_eventModel, m_eventProxy, m_eventTable, m_eventKeepBottomCheck);
    eventPageLayout->addWidget(m_apiTimeline);
    auto* eventSplitter = new QSplitter(Qt::Vertical, eventPage);
    eventSplitter->addWidget(m_eventTable);
    auto* detailPane = new QWidget(eventSplitter);
    auto* detailLayout = new QVBoxLayout(detailPane);
    detailLayout->setContentsMargins(0, 0, 0, 0); detailLayout->setSpacing(6);
    auto* detailActions = new QWidget(detailPane);
    auto* detailActionsLayout = new QHBoxLayout(detailActions);
    detailActionsLayout->setContentsMargins(0, 0, 0, 0);
    m_eventDetails = new ks::ui::StructuredFieldView(detailActions);
    m_eventDetails->setDocumentOnly();
    if (auto* search = m_eventDetails->findChild<QLineEdit*>()) search->hide();
    detailActionsLayout->addWidget(m_eventDetails);
    detailActions->setMaximumHeight(m_eventDetails->fontMetrics().height() + 24);
    detailLayout->addWidget(detailActions, 0);
    auto* detailColumns = new QSplitter(Qt::Horizontal, detailPane);
    detailColumns->setChildrenCollapsible(false);
    const auto makeFields = [detailColumns](const QString& title) {
        auto* pane = new QWidget(detailColumns);
        pane->setMinimumWidth(0); pane->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
        auto* column = new QVBoxLayout(pane); column->setContentsMargins(0, 0, 0, 0); column->setSpacing(4);
        column->addWidget(new QLabel(title, pane));
        auto* tree = new QTreeWidget(pane);
        tree->setColumnCount(2); tree->setHeaderLabels({QStringLiteral("名称"), QStringLiteral("值")});
        tree->setRootIsDecorated(false); tree->setAlternatingRowColors(true);
        tree->setMinimumWidth(0); tree->header()->setSectionResizeMode(0, QHeaderView::Interactive);
        tree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
        tree->setColumnWidth(0, tree->fontMetrics().horizontalAdvance(QStringLiteral("调用者模块")) + 64);
        ks::ui::ApplyTablePresentation(tree);
        column->addWidget(tree, 1);
        return tree;
    };
    m_eventProperties = makeFields(QStringLiteral("属性"));
    m_eventParameters = makeFields(QStringLiteral("参数"));
    auto* hexPane = new QWidget(detailColumns);
    hexPane->setMinimumWidth(0); hexPane->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    auto* hexLayout = new QVBoxLayout(hexPane); hexLayout->setContentsMargins(0, 0, 0, 0); hexLayout->setSpacing(4);
    hexLayout->addWidget(new QLabel(QStringLiteral("未分配 HEX / ASCII"), hexPane));
    m_eventHex = new ks::ui::HexView(hexPane);
    m_eventHex->setEditable(false); m_eventHex->setInspectorVisible(false);
    m_eventHex->setBytesPerRow(8);
    m_eventHex->setStatusBarVisible(false); m_eventHex->setMinimumWidth(0);
    hexLayout->addWidget(m_eventHex, 1);
    detailColumns->setStretchFactor(0, 4); detailColumns->setStretchFactor(1, 4); detailColumns->setStretchFactor(2, 3);
    detailColumns->setSizes({420, 420, 340});
    detailLayout->addWidget(detailColumns, 1);
    eventSplitter->addWidget(detailPane);
    eventPageLayout->addWidget(eventSplitter, 1);
    m_parameterEditor = new WinAPIParameterEditor(eventPage);
    m_parameterEditor->hide(); eventPageLayout->addWidget(m_parameterEditor);
    m_eventDetailHost = ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_eventTable, m_eventDetails, eventPage, eventSplitter, m_eventTable, detailPane);
    if (m_eventDetailHost) m_eventDetailHost->setBottomDetailWeight(450);
    // The detail checkbox remains independent of the two column presets.
    auto* viewA = new QToolButton(m_filterPanel); viewA->setText(QStringLiteral("A")); viewA->setCheckable(true);
    auto* viewB = new QToolButton(m_filterPanel); viewB->setText(QStringLiteral("B")); viewB->setCheckable(true);
    viewA->setToolTip(QStringLiteral("调用视图")); viewB->setToolTip(QStringLiteral("来源视图"));
    ks::ui::NormalizeToolbarControl(viewA); ks::ui::NormalizeToolbarControl(viewB);
    auto* columnModes = new QHBoxLayout(); columnModes->setContentsMargins(0, 0, 0, 0); columnModes->setSpacing(0);
    columnModes->addWidget(viewA); columnModes->addWidget(viewB);
    filterLayout->insertLayout(filterLayout->indexOf(m_eventFilterStatusLabel), columnModes);
    ks::ui::InstallSegmentedButtons(columnModes, {viewA, viewB});
    const auto applyColumns = [this, viewA, viewB](bool sourceView) {
        const QSet<int> common{ks::monitor::Time, ks::monitor::Api,
            ks::monitor::Pid, ks::monitor::Tid};
        const QSet<int> calls{ks::monitor::Sequence, ks::monitor::Module, ks::monitor::Summary, ks::monitor::ReturnValue, ks::monitor::Status,
            ks::monitor::ProcessName};
        const QSet<int> origins{ks::monitor::CallerModule, ks::monitor::CallerAddress, ks::monitor::MemoryKind,
            ks::monitor::Duration, ks::monitor::CaptureKind};
        for (int column = 0; column < EventColumnCount; ++column) {
            if (column == EventColumnDetail) continue;
            m_eventTable->setColumnHidden(column, !common.contains(column)
                && !(sourceView ? origins : calls).contains(column));
        }
        m_eventTable->setColumnHidden(EventColumnDetail, !m_showEventDetails->isChecked());
        viewA->setChecked(!sourceView); viewB->setChecked(sourceView);
    };
    connect(viewA, &QToolButton::clicked, this, [applyColumns]() { applyColumns(false); });
    connect(viewB, &QToolButton::clicked, this, [applyColumns]() { applyColumns(true); });
    auto* eventHeader = m_eventTable->horizontalHeader();
    eventHeader->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(eventHeader, &QHeaderView::customContextMenuRequested, this, [this, eventHeader, viewA, viewB](const QPoint& point) {
        QMenu menu(this); menu.setStyleSheet(KswordTheme::ContextMenuStyle());
        for (int column = 0; column < EventColumnCount; ++column) {
            auto* action = menu.addAction(m_eventModel->headerData(column, Qt::Horizontal).toString());
            action->setCheckable(true); action->setChecked(!m_eventTable->isColumnHidden(column)); action->setData(column);
        }
        if (auto* action = menu.exec(eventHeader->mapToGlobal(point))) {
            const int column = action->data().toInt();
            if (column == EventColumnDetail) m_showEventDetails->setChecked(action->isChecked());
            else { m_eventTable->setColumnHidden(column, !action->isChecked()); viewA->setChecked(false); viewB->setChecked(false); }
        }
    });
    applyColumns(false);
    ks::monitor::AddMonitorNavigationTab(m_resultTabs, eventPage, QStringLiteral("winapi-events"));
    QWidget* coveragePanel = new QWidget(m_resultTabs);
    auto* coverageLayout = new QVBoxLayout(coveragePanel);
    auto* coverageFilterLayout = new QHBoxLayout();
    m_coveragePidCombo = new QComboBox(coveragePanel);
    ks::ui::StylePrimaryCombo(m_coveragePidCombo);
    m_coveragePidCombo->setToolTip(QStringLiteral("选择覆盖快照的进程 PID"));
    m_coverageFilterEdit = new QLineEdit(coveragePanel);
    m_coverageFilterEdit->setPlaceholderText(QStringLiteral("筛选 API / Hook 类型 / 覆盖状态 / 原因"));
    m_coverageFilterEdit->setStyleSheet(blueInputStyle());
    ks::ui::StyleSearchField(m_coverageFilterEdit);
    coverageFilterLayout->addWidget(m_coveragePidCombo);
    coverageFilterLayout->addWidget(m_coverageFilterEdit, 1);
    ks::ui::NormalizeToolbarRow(coverageFilterLayout);
    coverageLayout->addLayout(coverageFilterLayout);
    m_coverageStatusLabel = new QLabel(QStringLiteral("覆盖快照：等待 Agent 完整快照"), coveragePanel);
    coverageLayout->addWidget(m_coverageStatusLabel);
    auto* coverageBoundary = new QLabel(QStringLiteral("覆盖边界：任意 COM 方法、直接系统调用、启动监控前的调用及未识别的原生异步完成路径。Raw 仅采集入口。"), coveragePanel);
    coverageBoundary->setWordWrap(true);
    coverageLayout->addWidget(coverageBoundary);
    m_coverageTable = new ks::ui::TableActionTableView(coveragePanel);
    // API 覆盖为辅助能力快照，紧凑导出可保留原始状态。
    ks::ui::SetTableActionBarMode(m_coverageTable, ks::ui::TableActionBarMode::Compact);
    initializeCoverageTable();
    m_coverageTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_coverageTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_coverageTable->setAlternatingRowColors(true);
    m_coverageTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_coverageTable->horizontalHeader()->setStretchLastSection(true);
    m_coverageTable->setColumnWidth(3, 240);
    m_coverageTable->setColumnWidth(4, 120);
    m_coverageTable->setColumnWidth(5, 140);
    auto* coverageSplitter = new QSplitter(Qt::Vertical, coveragePanel);
    coverageSplitter->addWidget(m_coverageTable);
    coverageSplitter->addWidget(createEventRulesPanel(coverageSplitter));
    coverageSplitter->setStretchFactor(0, 2); coverageSplitter->setStretchFactor(1, 1);
    coverageLayout->addWidget(coverageSplitter, 1);
    ks::monitor::AddMonitorNavigationTab(m_resultTabs, coveragePanel, QStringLiteral("winapi-coverage"));
    eventResultsLayout->addWidget(m_resultTabs, 1);
    workspace->finish();

    // 参数已有统一输入面，结果工具行只登记明确动作，避免套第二层高亮配置底板。
    for (QPushButton* button : {m_processRefreshButton, m_browseAgentDllButton,
        m_stopButton, m_exportButton, m_clearEventButton, m_eventFilterClearButton,
        m_fakeAddRuleButton, m_fakeRemoveRuleButton, m_fakeStopRuleButton})
    {
        ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
    }
    for (QPushButton* button : {m_startButton, m_fakeApplyRuleButton})
    {
        ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Accent,
            ks::ui::FlatButtonAppearance::Solid);
    }
    ks::ui::ApplyFlatButtonTheme(m_terminateHookButton, ks::ui::FlatButtonTone::Danger,
        ks::ui::FlatButtonAppearance::Solid);
    connect(m_resultTabs, &QTabWidget::currentChanged, this, [this](int index) { if (index == 1 && m_coverageDirty) updateCoverageView(); });
    connect(m_coveragePidCombo, &QComboBox::currentIndexChanged, this, [this]() { updateCoverageView(); });
    connect(m_coverageFilterEdit, &QLineEdit::textChanged, this, [this]() { updateCoverageView(); });

    m_uiFlushTimer = new QTimer(this);
    m_uiFlushTimer->setInterval(120);


}
