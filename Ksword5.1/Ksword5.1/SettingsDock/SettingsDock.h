#pragma once

#include "AppearanceSettings.h"

#include <QWidget>

class QButtonGroup;
class QCheckBox;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QRadioButton;
class QSlider;
class QSpinBox;
class QTabWidget;
class QToolButton;
class QVBoxLayout;

class SettingsDock : public QWidget
{
    Q_OBJECT

public:
    // 构造函数作用：
    // - 初始化“设置”页签容器；
    // - 加载外观 JSON 配置并同步到 UI；
    // - 对外发出外观设置变化信号。
    // 调用方式：MainWindow 创建 SettingsDock 时自动调用。
    // 入参 parent：Qt 父对象指针。
    explicit SettingsDock(QWidget* parent = nullptr);

    // applySettings 作用：保存当前设置并发出变更信号；由对话框固定操作栏调用。
    void applySettings();

    // currentAppearanceSettings 作用：
    // - 返回当前内存中的外观设置快照。
    // 调用方式：MainWindow 初始化时读取一次默认设置。
    // 返回：AppearanceSettings 配置结构体副本。
    ks::settings::AppearanceSettings currentAppearanceSettings() const;

    // showLanguageSettingsTab 作用：切换到“语言”页签，供欢迎页快捷入口调用。
    void showLanguageSettingsTab();

protected:
    void changeEvent(QEvent* event) override;

signals:
    // appearanceSettingsChanged 作用：
    // - 当用户点击“应用”并保存成功后通知主窗口；
    // - 主题/背景会立即应用，启动相关选项用于下次启动。
    // 调用方式：内部保存成功后 emit。
    // 入参 settings：最新界面与启动配置。
    void appearanceSettingsChanged(const ks::settings::AppearanceSettings& settings);

    // pendingChangesChanged 作用：同步对话框固定“应用”按钮的可用状态。
    void pendingChangesChanged(bool hasPendingChanges);

    // bugcheckDiagnosticsAutoInstallChanged 作用：通知主窗口更新本次已加载配置与页面入口显示状态。
    void bugcheckDiagnosticsAutoInstallChanged(bool enabled);

    // bugcheckDiagnosticsInstalledForSession 作用：本次安装完成后显示蓝屏诊断入口并上传运行期资源。
    void bugcheckDiagnosticsInstalledForSession();

    // bugcheckDiagnosticsInstallationStarted 作用：用户明确请求本次安装后立即显示入口，便于查看状态和失败原因。
    void bugcheckDiagnosticsInstallationStarted();

private:
    // initializeUi 作用：
    // - 构建 SettingsDock 的根布局与 Tab 容器。
    // 调用方式：构造函数内部调用。
    void initializeUi();

    // initializeAppearanceTab 作用：
    // - 创建“外观 / 语言 / 启动”三个标签页控件，并保持一套统一的保存逻辑。
    // 调用方式：initializeUi 内部调用。
    void initializeAppearanceTab();

    // initializeFeaturesTab 作用：
    // - 创建“功能”标签页，承载 R0 功能提示等运行行为开关；
    // - 控件沿用统一的“应用”保存流程。
    // 调用方式：initializeAppearanceTab 后、读取配置前调用。
    void initializeFeaturesTab();

    // initializeOnlineScanTab 作用：
    // - 创建“在线扫描”标签页控件（VirusTotal/ThreatBook API Key 输入与保存按钮）。
    // 调用方式：initializeUi 后、读取配置前调用。
    // 返回：无。
    void initializeOnlineScanTab();

    // initializeBugcheckDiagnosticsControls 作用：在“功能”标签追加配置化蓝屏诊断的三种操作。
    // 调用方式：initializeFeaturesTab 创建完已有分组后调用。
    // 入参 featuresRootLayout：功能页根布局，必须非空；返回：无。
    void initializeBugcheckDiagnosticsControls(QVBoxLayout* featuresRootLayout);

    // refreshBugcheckDiagnosticsStatusText 作用：根据持久化配置和当前异步操作状态刷新说明文本。
    // 调用方式：初始化、配置保存、安装完成及语言切换后调用；传入传出：无。
    void refreshBugcheckDiagnosticsStatusText();

    // setBugcheckDiagnosticsAutoInstall 作用：只写入自动安装开关，不提交同页其它待应用设置。
    // 调用方式：点击自动安装或取消自动安装按钮时调用。
    // 入参 enabled：true=后续驱动成功启动后安装；false=后续驱动不安装；返回：无。
    void setBugcheckDiagnosticsAutoInstall(bool enabled);

    // installBugcheckDiagnosticsForCurrentSession 作用：后台发送 R0 安装 IOCTL，仅影响当前驱动生命周期。
    // 调用方式：点击“本次安装”按钮时调用；返回：无，结果通过状态文本和信号反馈。
    void installBugcheckDiagnosticsForCurrentSession();

    // setBugcheckDiagnosticsControlsBusy 作用：安装期间禁用三个操作，防止并发 BGP 扫描与回调注册。
    // 调用方式：后台任务发出前和回投完成后调用；入参 busy：是否正在安装；返回：无。
    void setBugcheckDiagnosticsControlsBusy(bool busy);

    // bindAppearanceSignals 作用：
    // - 绑定外观页所有控件事件到“待应用”流程；
    // - 仅在点击应用按钮后才触发保存与生效。
    // 调用方式：initializeAppearanceTab 末尾调用。
    void bindAppearanceSignals();

    // bindOnlineScanSignals 作用：
    // - 绑定在线扫描 API Key 输入框和保存按钮；
    // - 输入变更只标记待保存，点击保存后复用统一设置落盘流程。
    // 调用方式：initializeOnlineScanTab 末尾调用。
    // 返回：无。
    void bindOnlineScanSignals();

    // loadSettingsFromJson 作用：
    // - 读取 JSON 配置并刷新 UI。
    // 调用方式：构造函数末尾调用。
    void loadSettingsFromJson();

    // applySettingsToUi 作用：
    // - 把配置结构体回填到各控件显示。
    // 调用方式：loadSettingsFromJson/内部回滚时调用。
    // 入参 settings：待显示的界面与启动配置。
    void applySettingsToUi(const ks::settings::AppearanceSettings& settings);

    // collectSettingsFromUi 作用：
    // - 从控件读取用户输入，组装配置结构体。
    // 调用方式：保存前调用。
    // 返回：由当前 UI 生成的配置结构体。
    ks::settings::AppearanceSettings collectSettingsFromUi() const;

    // markPendingChanges 作用：
    // - 标记当前 UI 有未应用改动；
    // - 刷新“应用按钮”可用态与提示文案。
    // 调用方式：任意设置控件值变化后调用。
    // 入参 triggerReason：触发原因文本（调试与日志辅助）。
    void markPendingChanges(const QString& triggerReason);

    // updateApplyButtonState 作用：
    // - 根据 m_hasPendingChanges 更新应用按钮状态；
    // - 统一维护“是否有待应用改动”的视觉反馈。
    // 调用方式：标记待应用后、保存成功后、加载配置后调用。
    void updateApplyButtonState();

    // updateSystemDefaultFontItemText 作用：
    // - 按当前语言刷新字体下拉框第 0 项“系统默认”的显示文本；
    // - 只修改显示角色，稳定的 Qt::UserRole 空字符串语义保持不变。
    // 调用方式：初始化字体列表及 LanguageChange 时调用；传入传出：无。
    void updateSystemDefaultFontItemText();

    // saveAndEmitFromUi 作用：
    // - 从 UI 采集配置并写入 JSON；
    // - 保存成功后发出变更信号。
    // 调用方式：用户交互触发时调用。
    // 入参 triggerReason：触发原因文本（用于日志）。
    void saveAndEmitFromUi(const QString& triggerReason);

    // updateThemeButtonStyle 作用：
    // - 根据当前选中状态更新主题按钮样式高亮。
    // 调用方式：按钮点击后、配置加载后调用。
    void updateThemeButtonStyle();

    // updateThemeColorPreview 作用：刷新当前主题色预览与“恢复默认”按钮状态。
    // 调用方式：载入配置、选择颜色或恢复默认后调用。
    void updateThemeColorPreview();

    // chooseCustomThemeColor 作用：先展示极端颜色风险提示，再打开颜色选择器。
    // 调用方式：点击“自定义主题色”按钮时调用。
    void chooseCustomThemeColor();

    // resetThemeColorToDefault 作用：清除自定义主题色，恢复内置默认主题色。
    // 调用方式：点击“一键复原”按钮时调用。
    void resetThemeColorToDefault();

    // updateMainBackgroundColorPreview 作用：刷新独立主背景色预览与恢复按钮状态。
    // 调用方式：载入配置、切换主题、选择颜色或恢复默认后调用。
    void updateMainBackgroundColorPreview();

    // chooseCustomMainBackgroundColor 作用：打开主背景色选择器，不改变主题强调色。
    // 调用方式：点击“自定义主背景色”按钮时调用。
    void chooseCustomMainBackgroundColor();

    // resetMainBackgroundColorToDefault 作用：清除自定义主背景色并恢复跟随深浅主题。
    // 调用方式：点击“恢复默认背景色”按钮时调用。
    void resetMainBackgroundColorToDefault();

    // updateOpacityValueLabel 作用：
    // - 同步透明度百分比文本标签。
    // 调用方式：滑条值变化时调用。
    // 入参 opacityPercent：0~100 透明度值。
    void updateOpacityValueLabel(int opacityPercent);

    // openBackgroundFileDialog 作用：
    // - 打开文件选择对话框，供用户挑选背景图路径。
    // 调用方式：点击“浏览背景图”按钮时调用。
    void openBackgroundFileDialog();

    // resetBackgroundPathToDefault 作用：
    // - 把背景图路径恢复为默认 Style/ksword_background.png。
    // 调用方式：点击“恢复默认背景路径”按钮时调用。
    void resetBackgroundPathToDefault();

    // launchTaskmgrHijackScript 作用：
    // - 从程序当前目录启动 TaskmgrHijack.ps1；
    // - install=true 时写入 taskmgr.exe IFEO Debugger，install=false 时移除该配置；
    // - 脚本自身负责在非管理员环境下触发 UAC 提权。
    // 调用方式：点击“映像劫持任务管理器”或“还原任务管理器”按钮时调用。
    // 入参 install：true=安装映像劫持；false=卸载并还原任务管理器。
    // 返回：无返回值；启动失败会弹窗并写日志。
    void launchTaskmgrHijackScript(bool install);

    // parseWindowScaleFactorFromUi 作用：
    // - 从输入框解析并校正启动窗口缩放因子；
    // - 非法输入会自动回退到 1.0。
    // 调用方式：collectSettingsFromUi 内部调用。
    // 返回：合法缩放因子（0.50~2.00）。
    double parseWindowScaleFactorFromUi() const;

private:
    // m_tabWidget 作用：设置页签容器，当前至少包含“外观”页。
    QTabWidget* m_tabWidget = nullptr;

    // m_appearanceTab 作用：外观设置页 QWidget 容器。
    QWidget* m_appearanceTab = nullptr;

    // m_languageTab 作用：界面语言设置页 QWidget 容器。
    QWidget* m_languageTab = nullptr;

    // m_startupTab 作用：启动行为设置页 QWidget 容器。
    QWidget* m_startupTab = nullptr;

    // m_featuresTab 作用：功能设置页 QWidget 容器。
    QWidget* m_featuresTab = nullptr;

    // m_onlineScanTab 作用：在线扫描 API Key 设置页 QWidget 容器。
    QWidget* m_onlineScanTab = nullptr;

    // m_themeButtonGroup 作用：三种主题按钮的互斥分组。
    QButtonGroup* m_themeButtonGroup = nullptr;

    // m_detailSchemeButtonGroup：四种严格命中详情布局的全局互斥单选组。
    QButtonGroup* m_detailSchemeButtonGroup = nullptr;

    // m_languageCombo 作用：列出 languages 目录中发现并通过校验的语言包。
    QComboBox* m_languageCombo = nullptr;

    // m_textAntialiasingCheckBox 作用：控制应用默认字体是否启用文本抗锯齿。
    QCheckBox* m_textAntialiasingCheckBox = nullptr;

    // m_fontCombo 作用：
    // - 第 0 项以空 itemData 表示“系统默认”，其余项保存系统字体 family；
    // - 显示文本可以随语言变化，但持久化语义不依赖翻译文本。
    QComboBox* m_fontCombo = nullptr;

    // m_followSystemButton 作用：选择“跟随系统主题”模式。
    QToolButton* m_followSystemButton = nullptr;

    // m_lightModeButton 作用：选择“浅色主题”模式。
    QToolButton* m_lightModeButton = nullptr;

    // m_darkModeButton 作用：选择“深色主题”模式。
    QToolButton* m_darkModeButton = nullptr;

    // m_themeColorPreviewLabel 作用：显示当前主主题色及其 #RRGGBB 值。
    QLabel* m_themeColorPreviewLabel = nullptr;

    // m_chooseThemeColorButton / m_resetThemeColorButton：主题色选择与一键恢复按钮。
    QPushButton* m_chooseThemeColorButton = nullptr;
    QPushButton* m_resetThemeColorButton = nullptr;

    // 主背景色与主题强调色独立保存；预览标签展示当前待应用的实际 RGB 值。
    QLabel* m_mainBackgroundColorPreviewLabel = nullptr;
    QPushButton* m_chooseMainBackgroundColorButton = nullptr;
    QPushButton* m_resetMainBackgroundColorButton = nullptr;

    // m_backgroundPathEdit 作用：编辑背景图路径文本。
    QLineEdit* m_backgroundPathEdit = nullptr;

    // m_browseBackgroundButton 作用：打开背景图文件选择器。
    QToolButton* m_browseBackgroundButton = nullptr;

    // m_resetBackgroundButton 作用：恢复默认背景图路径。
    QToolButton* m_resetBackgroundButton = nullptr;

    // m_backgroundOpacitySlider 作用：调整背景图透明度。
    QSlider* m_backgroundOpacitySlider = nullptr;

    // m_backgroundOpacityValueLabel 作用：显示透明度百分比文本。
    QLabel* m_backgroundOpacityValueLabel = nullptr;

    // m_backgroundTransparencyCheckBox 作用：让背景图自身的透明区域透出窗口后方。
    QCheckBox* m_backgroundTransparencyCheckBox = nullptr;

    // m_backgroundTranslucencyMaterialCombo 作用：选择透明背景效果（自动/云母/直透桌面）。
    QComboBox* m_backgroundTranslucencyMaterialCombo = nullptr;

    // m_backgroundBlurRadiusSlider 作用：调整背景图自绘玻璃模糊的半径强度。
    QSlider* m_backgroundBlurRadiusSlider = nullptr;

    // m_backgroundBlurRadiusValueLabel 作用：显示当前模糊半径强度百分比。
    QLabel* m_backgroundBlurRadiusValueLabel = nullptr;

    // m_acrylicTintOpacitySlider 作用：调整磨砂玻璃着色层不透明度。
    QSlider* m_acrylicTintOpacitySlider = nullptr;

    // m_acrylicTintOpacityValueLabel 作用：显示磨砂着色不透明度百分比。
    QLabel* m_acrylicTintOpacityValueLabel = nullptr;

    // m_desktopTintOpacitySlider 作用：调整直透桌面模式着色层不透明度。
    QSlider* m_desktopTintOpacitySlider = nullptr;

    // m_desktopTintOpacityValueLabel 作用：显示直透着色不透明度百分比。
    QLabel* m_desktopTintOpacityValueLabel = nullptr;

    // 日志通知设置：控制右侧通知卡片的开关、等级、时长与堆叠位置。
    QCheckBox* m_notificationCardsEnabledCheckBox = nullptr;
    QComboBox* m_notificationMinimumLevelCombo = nullptr;
    QSpinBox* m_notificationLogDisplaySecondsSpin = nullptr;
    QSpinBox* m_notificationMaximumVisibleLogCardsSpin = nullptr;
    QCheckBox* m_notificationLogHeightLimitCheckBox = nullptr;
    QSpinBox* m_notificationLogMaximumLinesSpin = nullptr;
    QComboBox* m_notificationDisplayPlacementCombo = nullptr;
    QComboBox* m_notificationStackDirectionCombo = nullptr;

    // m_startupMaximizedCheckBox 作用：设置下次启动时是否默认最大化显示。
    QCheckBox* m_startupMaximizedCheckBox = nullptr;

    // m_startupTopMostCheckBox 作用：设置启动后是否默认启用最高级窗口置顶。
    QCheckBox* m_startupTopMostCheckBox = nullptr;

    // m_startupAutoAdminCheckBox 作用：设置下次启动时是否先尝试申请管理员权限。
    QCheckBox* m_startupAutoAdminCheckBox = nullptr;

    // m_preventMultipleInstancesCheckBox 作用：设置普通启动时是否防止同时运行多个实例。
    QCheckBox* m_preventMultipleInstancesCheckBox = nullptr;

    // m_unlockerShellContextMenuCheckBox 作用：设置是否启用系统右键“文件解锁器”菜单。
    QCheckBox* m_unlockerShellContextMenuCheckBox = nullptr;

    // m_suppressR0FeaturePromptsCheckBox 作用：设置是否关闭 R0 驱动未启用或权限不足时的自动提示。
    QCheckBox* m_suppressR0FeaturePromptsCheckBox = nullptr;

    // m_dumpAutoCheckCheckBox 作用：设置启动后是否检查系统近期的新崩溃转储。
    QCheckBox* m_dumpAutoCheckCheckBox = nullptr;

    // m_bugcheckDiagnosticsStatusLabel 作用：展示自动安装配置和当前会话安装结果。
    QLabel* m_bugcheckDiagnosticsStatusLabel = nullptr;

    // m_enableBugcheckDiagnosticsAutoInstallButton 作用：写入后续驱动启动时自动安装的配置项。
    QPushButton* m_enableBugcheckDiagnosticsAutoInstallButton = nullptr;

    // m_disableBugcheckDiagnosticsAutoInstallButton 作用：移除后续驱动启动时自动安装的配置项。
    QPushButton* m_disableBugcheckDiagnosticsAutoInstallButton = nullptr;

    // m_installBugcheckDiagnosticsForSessionButton 作用：向当前已经加载的驱动发送一次安装 IOCTL。
    QPushButton* m_installBugcheckDiagnosticsForSessionButton = nullptr;

    // m_bugcheckDiagnosticsInstallBusy 作用：记录异步安装 IOCTL 是否仍在执行。
    bool m_bugcheckDiagnosticsInstallBusy = false;

    // m_installTaskmgrHijackButton 作用：调用当前目录 TaskmgrHijack.ps1 安装 taskmgr.exe IFEO 映像劫持。
    QPushButton* m_installTaskmgrHijackButton = nullptr;

    // m_uninstallTaskmgrHijackButton 作用：调用当前目录 TaskmgrHijack.ps1 移除 taskmgr.exe IFEO 映像劫持。
    QPushButton* m_uninstallTaskmgrHijackButton = nullptr;

    // m_scrollBarWidthCombo 作用：设置全局滚动条宽度（窄/宽）。
    QComboBox* m_scrollBarWidthCombo = nullptr;

    // m_scrollBarAutoHideCheckBox 作用：设置滚动条是否弱显示/悬停显示。
    QCheckBox* m_scrollBarAutoHideCheckBox = nullptr;

    // m_smoothScrollingCheckBox 作用：设置全局滚动区域是否启用滚轮缓动。
    QCheckBox* m_smoothScrollingCheckBox = nullptr;

    // m_sliderWheelAdjustCheckBox 作用：设置滚轮是否可直接调整滑块值。
    QCheckBox* m_sliderWheelAdjustCheckBox = nullptr;

    // m_startupWindowScaleSpin 作用：设置下次启动主窗口的缩放百分比（50~200，重启生效）。
    QSpinBox* m_startupWindowScaleSpin = nullptr;

    // m_startupWindowScaleHintLabel 作用：说明缩放的生效时机与系统缩放的叠加关系。
    QLabel* m_startupWindowScaleHintLabel = nullptr;

    // m_virusTotalApiKeyEdit 作用：编辑 VirusTotal 在线扫描 API Key。
    QLineEdit* m_virusTotalApiKeyEdit = nullptr;

    // m_threatBookApiKeyEdit 作用：编辑 ThreatBook（微步在线）在线扫描 API Key。
    QLineEdit* m_threatBookApiKeyEdit = nullptr;

    // m_applySettingsButton 作用：统一提交当前设置改动并触发实际生效。


    // m_saveOnlineScanKeysButton 作用：在线扫描页单独保存 API Key 的按钮。
    QPushButton* m_saveOnlineScanKeysButton = nullptr;

    // m_currentAppearanceSettings 作用：缓存当前有效界面与启动配置。
    ks::settings::AppearanceSettings m_currentAppearanceSettings;

    // m_pendingCustomThemeColor 作用：保存尚未点击“应用”的自定义主题色色值；空值表示默认色。
    QString m_pendingCustomThemeColor;

    // m_pendingCustomMainBackgroundColor 作用：保存尚未应用的独立主背景色；空值表示跟随深浅主题。
    QString m_pendingCustomMainBackgroundColor;

    // m_isApplyingUiState 作用：标记“正在回填 UI”，防止触发递归保存。
    bool m_isApplyingUiState = false;

    // m_hasPendingChanges 作用：标记是否存在“未点击应用”的待生效改动。
    bool m_hasPendingChanges = false;
};
