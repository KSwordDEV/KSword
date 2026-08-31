#include "WinAPIDock.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

// ============================================================
// WinAPIDock.Ui.cpp
// 作用：
// 1) 集中构建 WinAPI Dock 的控件层次与布局；
// 2) 保持头文件简洁，避免 UI 代码继续堆大；
// 3) 为按钮统一设置图标、tooltip 和蓝色主题样式。
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
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSize>
#include <QSplitter>
#include <QStyle>
#include <QTableWidget>
#include <QTimer>
#include <QToolButton>
#include <QStringList>
#include <QVBoxLayout>

namespace
{
    // configureIconButton：
    // - 作用：统一设置“仅图标按钮”的图标、提示与尺寸；
    // - 调用：刷新、浏览、开始、停止、导出等简单语义按钮都走这里；
    // - 返回：无返回值，控件为空时直接跳过。
    void configureIconButton(
        QPushButton* buttonPointer,
        const QIcon& iconValue,
        const QString& toolTipText)
    {
        if (buttonPointer == nullptr)
        {
            return;
        }

        buttonPointer->setIcon(iconValue);
        buttonPointer->setText(QString());
        buttonPointer->setToolTip(toolTipText);
        buttonPointer->setFixedWidth(34);
        buttonPointer->setIconSize(QSize(18, 18));
    }

    // createPanelFrame：
    // - 作用：创建统一的浅边框面板，减少顶层布局中裸控件带来的视觉割裂；
    // - 调用：顶部进程选择、左侧 Agent、右侧 Fake Success 三块配置区域复用；
    // - 返回：已设置 StyledPanel 的 QFrame，父对象由调用方传入。
    QFrame* createPanelFrame(QWidget* parentWidget)
    {
        QFrame* const framePointer = new QFrame(parentWidget);
        framePointer->setFrameShape(QFrame::StyledPanel);
        framePointer->setFrameShadow(QFrame::Plain);
        return framePointer;
    }

    // createSectionTitle：
    // - 作用：生成配置区标题标签；
    // - 调用：Agent 会话和 Fake Success 面板顶部；
    // - 返回：带统一强调色样式的 QLabel。
    QLabel* createSectionTitle(
        const QString& titleText,
        QWidget* parentWidget,
        const QString& styleSheetText)
    {
        QLabel* const titleLabel = new QLabel(titleText, parentWidget);
        titleLabel->setStyleSheet(styleSheetText);
        return titleLabel;
    }
}

void WinAPIDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(8, 8, 8, 8);
    m_rootLayout->setSpacing(8);

    QFrame* const sessionCollapseFrame = createPanelFrame(this);
    QVBoxLayout* const sessionCollapseLayout = new QVBoxLayout(sessionCollapseFrame);
    sessionCollapseLayout->setContentsMargins(6, 6, 6, 6);
    sessionCollapseLayout->setSpacing(8);

    m_sessionCollapseButton = new QToolButton(sessionCollapseFrame);
    m_sessionCollapseButton->setCheckable(true);
    m_sessionCollapseButton->setChecked(true);
    m_sessionCollapseButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_sessionCollapseButton->setArrowType(Qt::DownArrow);
    m_sessionCollapseButton->setText(QStringLiteral("WinAPI Monitor 配置（目标进程 / Agent / Fake Success）"));
    m_sessionCollapseButton->setToolTip(QStringLiteral("展开或折叠上方所有配置；结果表始终保留在最下方。"));
    sessionCollapseLayout->addWidget(m_sessionCollapseButton, 0);

    m_sessionCollapseContent = new QWidget(sessionCollapseFrame);
    QVBoxLayout* const sessionCollapseContentLayout = new QVBoxLayout(m_sessionCollapseContent);
    sessionCollapseContentLayout->setContentsMargins(0, 0, 0, 0);
    sessionCollapseContentLayout->setSpacing(8);
    sessionCollapseLayout->addWidget(m_sessionCollapseContent, 0);
    m_rootLayout->addWidget(sessionCollapseFrame, 0);

    // 顶部进程选择：用户先输入进程名/PID，再从带图标的下拉候选中选中目标。
    m_processPanel = createPanelFrame(m_sessionCollapseContent);
    QHBoxLayout* const processPanelLayout = new QHBoxLayout(m_processPanel);
    processPanelLayout->setContentsMargins(8, 8, 8, 8);
    processPanelLayout->setSpacing(8);

    QLabel* const processTitleLabel = new QLabel(QStringLiteral("目标进程"), m_processPanel);
    processTitleLabel->setStyleSheet(buildStatusStyle(KswordTheme::PrimaryBlueHex));

    m_processIconLabel = new QLabel(m_processPanel);
    m_processIconLabel->setFixedSize(24, 24);
    m_processIconLabel->setAlignment(Qt::AlignCenter);
    m_processIconLabel->setPixmap(QIcon(QStringLiteral(":/Icon/process_main.svg")).pixmap(20, 20));
    m_processIconLabel->setToolTip(QStringLiteral("当前匹配/选中进程图标。"));

    m_processCombo = new QComboBox(m_processPanel);
    m_processCombo->setEditable(true);
    m_processCombo->setInsertPolicy(QComboBox::NoInsert);
    m_processCombo->setMaxVisibleItems(24);
    m_processCombo->setMinimumWidth(360);
    m_processCombo->setSizeAdjustPolicy(QComboBox::AdjustToMinimumContentsLengthWithIcon);
    m_processCombo->setMinimumContentsLength(36);
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
        style()->standardIcon(QStyle::SP_BrowserReload),
        QStringLiteral("刷新进程候选列表"));
    m_processRefreshButton->setStyleSheet(blueButtonStyle());

    m_processStatusLabel = new QLabel(QStringLiteral("● 输入进程名或刷新候选列表"), m_processPanel);
    m_processStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    processPanelLayout->addWidget(processTitleLabel, 0);
    processPanelLayout->addWidget(m_processIconLabel, 0);
    processPanelLayout->addWidget(m_processCombo, 1);
    processPanelLayout->addWidget(m_processRefreshButton, 0);
    processPanelLayout->addWidget(m_processStatusLabel, 0);
    sessionCollapseContentLayout->addWidget(m_processPanel, 0);

    // 下方左右布局：左侧是普通 WinAPI Agent 会话，右侧是 Fake Success 规则。
    m_topSplitter = new QSplitter(Qt::Horizontal, m_sessionCollapseContent);
    m_topSplitter->setChildrenCollapsible(false);
    sessionCollapseContentLayout->addWidget(m_topSplitter, 0);

    m_sessionPanel = createPanelFrame(nullptr);
    QVBoxLayout* const sessionPanelLayout = new QVBoxLayout(m_sessionPanel);
    sessionPanelLayout->setContentsMargins(8, 8, 8, 8);
    sessionPanelLayout->setSpacing(8);

    sessionPanelLayout->addWidget(
        createSectionTitle(
            QStringLiteral("WinAPI Agent 会话"),
            m_sessionPanel,
            buildStatusStyle(KswordTheme::PrimaryBlueHex)),
        0);

    QHBoxLayout* const sessionConfigurationColumnsLayout = new QHBoxLayout();
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

    QWidget* const dllPathRowWidget = new QWidget(sessionConfigurationLeftColumn);
    QHBoxLayout* const dllPathLayout = new QHBoxLayout(dllPathRowWidget);
    dllPathLayout->setContentsMargins(0, 0, 0, 0);
    dllPathLayout->setSpacing(6);
    m_agentDllPathEdit = new QLineEdit(dllPathRowWidget);
    m_agentDllPathEdit->setText(defaultDllPathHint());
    m_agentDllPathEdit->setToolTip(QStringLiteral("需要注入到目标进程中的 APIMonitor_x64.dll 路径。"));
    m_agentDllPathEdit->setStyleSheet(blueInputStyle());

    m_browseAgentDllButton = new QPushButton(dllPathRowWidget);
    configureIconButton(
        m_browseAgentDllButton,
        style()->standardIcon(QStyle::SP_DirOpenIcon),
        QStringLiteral("浏览 Agent DLL 路径"));
    m_browseAgentDllButton->setStyleSheet(blueButtonStyle());

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
    m_hookLoaderCheck = new QCheckBox(QStringLiteral("加载器 API"), categoryFrame);
    m_autoInjectChildCheck = new QCheckBox(QStringLiteral("自动注入子进程"), categoryFrame);
    m_rawFallbackCheck = new QCheckBox(QStringLiteral("Raw 兜底 Hook（强类型优先）"), categoryFrame);
    m_rawDefaultDenyListCheck = new QCheckBox(QStringLiteral("启用默认高频/高风险黑名单"), categoryFrame);
    QFrame* const rawConfigurationFrame = createPanelFrame(m_sessionPanel);
    QVBoxLayout* const rawConfigurationLayout = new QVBoxLayout(rawConfigurationFrame);
    rawConfigurationLayout->setContentsMargins(8, 8, 8, 8);
    rawConfigurationLayout->setSpacing(6);

    QLabel* const rawConfigurationTitleLabel = new QLabel(QStringLiteral("Raw 兜底配置"), rawConfigurationFrame);
    rawConfigurationLayout->addWidget(rawConfigurationTitleLabel, 0);

    m_rawModuleListEdit = new QPlainTextEdit(rawConfigurationFrame);
    m_rawDenyListEdit = new QPlainTextEdit(rawConfigurationFrame);

    m_hookFileCheck->setChecked(true);
    m_hookRegistryCheck->setChecked(true);
    m_hookNetworkCheck->setChecked(true);
    m_hookProcessCheck->setChecked(true);
    m_hookLoaderCheck->setChecked(false);
    m_autoInjectChildCheck->setChecked(false);
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
    m_autoInjectChildCheck->setToolTip(QStringLiteral("启用后，Agent 会在 CreateProcessW 成功时把同一个 APIMonitor_x64.dll 注入到新子进程；仅支持 x64 子进程。"));
    m_rawFallbackCheck->setToolTip(QStringLiteral("对强类型表未覆盖的已加载模块导出安装 Raw ABI 入口 Hook。强类型 Hook 优先，Raw 只记录模块/函数/地址等兜底信息。"));
    m_rawDefaultDenyListCheck->setToolTip(QStringLiteral("Raw 黑名单只影响兜底 Hook；强类型 Hook 不受影响。建议长期保持开启，避免字符串、堆、锁、时间等高频基础 API 刷爆日志。关闭后，下方额外黑名单仍然生效。"));
    m_rawModuleListEdit->setToolTip(QStringLiteral("分号分隔模块名。Agent 只扫描已加载模块，后续 LoadLibrary 后会重试补装。"));
    m_rawDenyListEdit->setToolTip(QStringLiteral("用户额外黑名单，分号分隔函数名，支持 prefix*。内置默认黑名单由上方复选框控制，不需要复制到这里。当前内置默认：%1").arg(defaultRawHookDenyListText()));

    categoryLayout->addWidget(m_hookFileCheck, 0);
    categoryLayout->addWidget(m_hookRegistryCheck, 0);
    categoryLayout->addWidget(m_hookNetworkCheck, 0);
    categoryLayout->addWidget(m_hookProcessCheck, 0);
    categoryLayout->addWidget(m_hookLoaderCheck, 0);
    categoryLayout->addWidget(m_autoInjectChildCheck, 0);
    categoryLayout->addWidget(m_rawFallbackCheck, 0);
    categoryLayout->addWidget(m_rawDefaultDenyListCheck, 0);
    sessionConfigurationLeftLayout->addWidget(categoryFrame, 0);

    rawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 模块目录（; 分隔）"), rawConfigurationFrame), 0);
    rawConfigurationLayout->addWidget(m_rawModuleListEdit, 0);
    rawConfigurationLayout->addWidget(new QLabel(QStringLiteral("Raw 额外黑名单（exact / prefix*）"), rawConfigurationFrame), 0);
    rawConfigurationLayout->addWidget(m_rawDenyListEdit, 0);
    rawConfigurationLayout->addStretch(1);

    sessionConfigurationColumnsLayout->addWidget(sessionConfigurationLeftColumn, 1);
    sessionConfigurationColumnsLayout->addWidget(rawConfigurationFrame, 1);
    sessionPanelLayout->addLayout(sessionConfigurationColumnsLayout);

    QHBoxLayout* const sessionButtonLayout = new QHBoxLayout();
    sessionButtonLayout->setSpacing(6);

    m_startButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_startButton,
        style()->standardIcon(QStyle::SP_MediaPlay),
        QStringLiteral("启动 WinAPI 监控"));
    m_startButton->setStyleSheet(blueButtonStyle());

    m_stopButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_stopButton,
        style()->standardIcon(QStyle::SP_MediaStop),
        QStringLiteral("停止 WinAPI 监控"));
    m_stopButton->setStyleSheet(blueButtonStyle());

    m_terminateHookButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_terminateHookButton,
        style()->standardIcon(QStyle::SP_BrowserStop),
        QStringLiteral("手动终止目标进程中的 Hook"));
    m_terminateHookButton->setStyleSheet(blueButtonStyle());

    m_exportButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_exportButton,
        style()->standardIcon(QStyle::SP_DialogSaveButton),
        QStringLiteral("导出当前可见事件为 TSV"));
    m_exportButton->setStyleSheet(blueButtonStyle());

    m_clearEventButton = new QPushButton(m_sessionPanel);
    configureIconButton(
        m_clearEventButton,
        style()->standardIcon(QStyle::SP_DialogResetButton),
        QStringLiteral("清空当前事件表"));
    m_clearEventButton->setStyleSheet(blueButtonStyle());

    sessionButtonLayout->addWidget(m_startButton, 0);
    sessionButtonLayout->addWidget(m_stopButton, 0);
    sessionButtonLayout->addWidget(m_terminateHookButton, 0);
    sessionButtonLayout->addWidget(m_exportButton, 0);
    sessionButtonLayout->addWidget(m_clearEventButton, 0);
    sessionButtonLayout->addStretch(1);
    sessionPanelLayout->addLayout(sessionButtonLayout);

    m_sessionStatusLabel = new QLabel(QStringLiteral("● 空闲"), m_sessionPanel);
    m_sessionStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
    sessionPanelLayout->addWidget(m_sessionStatusLabel, 0);
    sessionPanelLayout->addStretch(1);

    QWidget* const fakeSuccessPanel = createPanelFrame(nullptr);
    QVBoxLayout* const fakeSuccessLayout = new QVBoxLayout(fakeSuccessPanel);
    fakeSuccessLayout->setContentsMargins(8, 8, 8, 8);
    fakeSuccessLayout->setSpacing(6);

    fakeSuccessLayout->addWidget(
        createSectionTitle(
            QStringLiteral("Fake Success（命中 API 直接伪返回）"),
            fakeSuccessPanel,
            buildStatusStyle(KswordTheme::PrimaryBlueHex)),
        0);

    QFormLayout* const fakeFormLayout = new QFormLayout();
    fakeFormLayout->setContentsMargins(0, 0, 0, 0);
    fakeFormLayout->setHorizontalSpacing(8);
    fakeFormLayout->setVerticalSpacing(6);

    m_fakeModuleEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeApiEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeReturnValueEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeLastErrorValueEdit = new QLineEdit(fakeSuccessPanel);
    m_fakeReturnTypeCombo = new QComboBox(fakeSuccessPanel);
    m_fakeLastErrorKindCombo = new QComboBox(fakeSuccessPanel);
    m_fakeRawFallbackCheck = new QCheckBox(QStringLiteral("启用 Fake Raw 兜底（未强类型导出仅伪造 RAX）"), fakeSuccessPanel);

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

    m_fakeReturnTypeCombo->addItem(QStringLiteral("Scalar / RAX"), QStringLiteral("scalar"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("BOOL"), QStringLiteral("bool"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("HANDLE / PVOID"), QStringLiteral("handle"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("DWORD / UINT / int"), QStringLiteral("dword"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("NTSTATUS"), QStringLiteral("ntstatus"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("HRESULT"), QStringLiteral("hresult"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("LSTATUS"), QStringLiteral("lstatus"));
    m_fakeReturnTypeCombo->addItem(QStringLiteral("SOCKET / int (WSA)"), QStringLiteral("socket"));
    m_fakeReturnTypeCombo->setToolTip(QStringLiteral("模板只影响展示和结果码语义；v1 只伪造标量返回值，不写 out 参数。Fake 路径会先上报事件，再跳过原 API 并返回指定 RAX。"));
    m_fakeReturnTypeCombo->setStyleSheet(blueInputStyle());

    m_fakeLastErrorKindCombo->addItem(QStringLiteral("不修改 LastError"), QStringLiteral("none"));
    m_fakeLastErrorKindCombo->addItem(QStringLiteral("SetLastError"), QStringLiteral("win32"));
    m_fakeLastErrorKindCombo->addItem(QStringLiteral("WSASetLastError"), QStringLiteral("wsa"));
    m_fakeLastErrorKindCombo->setToolTip(QStringLiteral("可选：Fake 返回前后设置 Win32 LastError 或 WSAError。"));
    m_fakeLastErrorKindCombo->setStyleSheet(blueInputStyle());
    m_fakeRawFallbackCheck->setChecked(false);
    m_fakeRawFallbackCheck->setToolTip(QStringLiteral("关闭时，仅强类型表覆盖的 API 可 Fake Success；开启后，规则表里未强类型覆盖的 module!api 也会用通用 x64 RAX stub 直接返回。"));

    fakeFormLayout->addRow(QStringLiteral("模块"), m_fakeModuleEdit);
    fakeFormLayout->addRow(QStringLiteral("API"), m_fakeApiEdit);
    fakeFormLayout->addRow(QStringLiteral("返回模板"), m_fakeReturnTypeCombo);
    fakeFormLayout->addRow(QStringLiteral("返回值"), m_fakeReturnValueEdit);
    fakeFormLayout->addRow(QStringLiteral("错误码类型"), m_fakeLastErrorKindCombo);
    fakeFormLayout->addRow(QStringLiteral("错误码值"), m_fakeLastErrorValueEdit);
    fakeSuccessLayout->addLayout(fakeFormLayout);
    fakeSuccessLayout->addWidget(m_fakeRawFallbackCheck, 0);

    QHBoxLayout* const fakeButtonLayout = new QHBoxLayout();
    fakeButtonLayout->setContentsMargins(0, 0, 0, 0);
    fakeButtonLayout->setSpacing(6);
    m_fakeAddRuleButton = new QPushButton(QStringLiteral("添加规则"), fakeSuccessPanel);
    m_fakeRemoveRuleButton = new QPushButton(QStringLiteral("删除选中"), fakeSuccessPanel);
    m_fakeApplyRuleButton = new QPushButton(QStringLiteral("应用规则并启动"), fakeSuccessPanel);
    m_fakeStopRuleButton = new QPushButton(QStringLiteral("停止会话"), fakeSuccessPanel);
    m_fakeAddRuleButton->setToolTip(QStringLiteral("把上方输入加入规则表；启动 WinAPI 监控时写入 Agent 配置并生效。"));
    m_fakeRemoveRuleButton->setToolTip(QStringLiteral("删除规则表当前选中的 Fake Success 规则。"));
    m_fakeApplyRuleButton->setToolTip(QStringLiteral("用当前规则表写入配置并启动 WinAPI Agent。若会话已运行，请先停止再应用。"));
    m_fakeStopRuleButton->setToolTip(QStringLiteral("停止当前 WinAPI Agent 会话；Fake Success 不支持运行中热更新。"));
    m_fakeAddRuleButton->setStyleSheet(blueButtonStyle());
    m_fakeRemoveRuleButton->setStyleSheet(blueButtonStyle());
    m_fakeApplyRuleButton->setStyleSheet(blueButtonStyle());
    m_fakeStopRuleButton->setStyleSheet(blueButtonStyle());
    fakeButtonLayout->addWidget(m_fakeAddRuleButton, 0);
    fakeButtonLayout->addWidget(m_fakeRemoveRuleButton, 0);
    fakeButtonLayout->addWidget(m_fakeApplyRuleButton, 0);
    fakeButtonLayout->addWidget(m_fakeStopRuleButton, 0);
    fakeButtonLayout->addStretch(1);
    fakeSuccessLayout->addLayout(fakeButtonLayout);

    m_fakeRuleTable = new ks::ui::VisibleTableWidget(fakeSuccessPanel);
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
            QStringLiteral("错误值")
        });
    m_fakeRuleTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnModule, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnApi, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnReturnType, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnReturnValue, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnLastErrorKind, QHeaderView::ResizeToContents);
    m_fakeRuleTable->horizontalHeader()->setSectionResizeMode(FakeRuleColumnLastErrorValue, QHeaderView::Stretch);
    m_fakeRuleTable->setStyleSheet(blueInputStyle());
    m_fakeRuleTable->setMaximumHeight(170);
    fakeSuccessLayout->addWidget(m_fakeRuleTable, 0);

    m_fakeRuleStatusLabel = new QLabel(QStringLiteral("规则：0 条；启动会话时应用。"), fakeSuccessPanel);
    m_fakeRuleStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));
    fakeSuccessLayout->addWidget(m_fakeRuleStatusLabel, 0);
    fakeSuccessLayout->addStretch(1);

    m_topSplitter->addWidget(m_sessionPanel);
    m_topSplitter->addWidget(fakeSuccessPanel);
    m_topSplitter->setStretchFactor(0, 1);
    m_topSplitter->setStretchFactor(1, 1);

    m_filterPanel = new QWidget(this);
    QHBoxLayout* const filterLayout = new QHBoxLayout(m_filterPanel);
    filterLayout->setContentsMargins(0, 0, 0, 0);
    filterLayout->setSpacing(6);

    m_eventFilterEdit = new QLineEdit(m_filterPanel);
    m_eventFilterEdit->setPlaceholderText(QStringLiteral("过滤 API / 分类 / 结果 / 详情"));
    m_eventFilterEdit->setStyleSheet(blueInputStyle());

    m_eventFilterClearButton = new QPushButton(m_filterPanel);
    configureIconButton(
        m_eventFilterClearButton,
        style()->standardIcon(QStyle::SP_DialogResetButton),
        QStringLiteral("清空事件过滤条件"));
    m_eventFilterClearButton->setStyleSheet(blueButtonStyle());

    m_eventKeepBottomCheck = new QCheckBox(QStringLiteral("保持贴底"), m_filterPanel);
    m_eventKeepBottomCheck->setChecked(true);
    m_eventKeepBottomCheck->setToolTip(QStringLiteral("新事件到来时自动滚动到最底部。"));

    m_eventFilterStatusLabel = new QLabel(QStringLiteral("筛选结果：0 / 0"), m_filterPanel);
    m_eventFilterStatusLabel->setStyleSheet(buildStatusStyle(monitorIdleColorHex()));

    filterLayout->addWidget(m_eventFilterEdit, 1);
    filterLayout->addWidget(m_eventFilterClearButton, 0);
    filterLayout->addWidget(m_eventKeepBottomCheck, 0);
    filterLayout->addWidget(m_eventFilterStatusLabel, 0);
    m_rootLayout->addWidget(m_filterPanel, 0);

    m_eventTable = new ks::ui::VisibleTableWidget(this);
    m_eventTable->setColumnCount(EventColumnCount);
    m_eventTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_eventTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_eventTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_eventTable->setAlternatingRowColors(true);
    m_eventTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_eventTable->setHorizontalHeaderLabels(
        QStringList{
            QStringLiteral("时间(100ns)"),
            QStringLiteral("分类"),
            QStringLiteral("API"),
            QStringLiteral("结果"),
            QStringLiteral("PID/TID"),
            QStringLiteral("详情")
        });
    m_eventTable->horizontalHeader()->setStyleSheet(blueHeaderStyle());
    m_eventTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_eventTable->setColumnWidth(EventColumnTime100ns, 160);
    m_eventTable->setColumnWidth(EventColumnCategory, 72);
    m_eventTable->setColumnWidth(EventColumnApi, 190);
    m_eventTable->setColumnWidth(EventColumnResult, 100);
    m_eventTable->setColumnWidth(EventColumnPidTid, 112);
    m_eventTable->setColumnWidth(EventColumnDetail, 440);
    m_eventTable->setStyleSheet(blueInputStyle());
    m_eventTable->setAutoFillBackground(false);
    m_eventTable->setAttribute(Qt::WA_StyledBackground, true);
    if (m_eventTable->viewport() != nullptr)
    {
        m_eventTable->viewport()->setAutoFillBackground(false);
        m_eventTable->viewport()->setAttribute(Qt::WA_StyledBackground, true);
    }
    m_rootLayout->addWidget(m_eventTable, 1);

    m_uiFlushTimer = new QTimer(this);
    m_uiFlushTimer->setInterval(120);

    connect(m_sessionCollapseButton, &QToolButton::toggled, this, [this](const bool checked) {
        if (m_sessionCollapseContent != nullptr)
        {
            m_sessionCollapseContent->setVisible(checked);
        }
        if (m_sessionCollapseButton != nullptr)
        {
            m_sessionCollapseButton->setArrowType(checked ? Qt::DownArrow : Qt::RightArrow);
        }
    });
}
