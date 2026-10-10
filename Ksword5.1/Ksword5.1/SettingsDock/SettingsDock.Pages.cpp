#include "SettingsDock.h"
#include "./SettingsDock.Layout.h"
#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemePreviewWidget.h"
#include "../UI/FlowLayout.h"
#include "../theme.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QFontDatabase>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRadioButton>
#include <QSlider>
#include <QSpinBox>
#include <QTabWidget>
#include <QToolButton>

// 语言页独立滚动，语言包枚举和保存仍沿用既有 LanguageManager。
void SettingsDock::initializeLanguageTab()
{
    m_languageTab = new QWidget(m_tabWidget);
    auto* languageRootLayout = new QVBoxLayout(m_languageTab);
    ks::ui::StyleSecondaryContentLayout(languageRootLayout);
    auto& languageManager = ks::i18n::LanguageManager::instance();
    // ===== 界面语言分组 =====
    QGroupBox* languageGroupBox = new QGroupBox(QStringLiteral("界面语言"), m_languageTab);
    languageManager.bindText(languageGroupBox, QStringLiteral("settings.language.group"), QStringLiteral("界面语言"));
    QVBoxLayout* languageLayout = new QVBoxLayout(languageGroupBox);
    languageLayout->setSpacing(8);

    QHBoxLayout* languageSelectLayout = new QHBoxLayout();
    QLabel* languageLabel = new QLabel(QStringLiteral("显示语言"), languageGroupBox);
    languageManager.bindText(languageLabel, QStringLiteral("settings.language.label"), QStringLiteral("显示语言"));
    languageSelectLayout->addWidget(languageLabel, 0);
    m_languageCombo = new QComboBox(languageGroupBox);
    m_languageCombo->addItem(QStringLiteral("跟随系统"), QStringLiteral("system"));
    languageManager.bindComboBoxItem(
        m_languageCombo,
        0,
        QStringLiteral("language.name.system"),
        QStringLiteral("跟随系统"));
    const QList<ks::i18n::LanguageInfo> availableLanguages = languageManager.availableLanguages();
    for (const ks::i18n::LanguageInfo& languageInfo : availableLanguages)
    {
        const QString displayName = languageInfo.nativeName.isEmpty()
            ? languageInfo.name
            : languageInfo.nativeName;
        m_languageCombo->addItem(displayName, languageInfo.id);
        languageManager.bindComboBoxItem(
            m_languageCombo,
            m_languageCombo->count() - 1,
            QStringLiteral("language.name.%1").arg(languageInfo.id),
            displayName);
    }
    languageManager.bindToolTip(
        m_languageCombo,
        QStringLiteral("settings.language.tooltip"),
        QStringLiteral("选择界面语言；保存后立即切换"));
    languageSelectLayout->addWidget(m_languageCombo, 1);
    languageSelectLayout->removeWidget(languageLabel);
    auto* languageForm = ks::settings::ui::Form(languageLayout);
    languageForm->addRow(languageLabel, ks::settings::ui::ControlRow(languageSelectLayout, languageGroupBox));
    ks::settings::ui::Section(languageGroupBox);
    languageRootLayout->addWidget(languageGroupBox);
    languageRootLayout->addStretch();

    m_languageTab = ks::settings::ui::ScrollPage(m_languageTab);
    m_tabWidget->addTab(m_languageTab, QStringLiteral("语言"));
    languageManager.bindTab(m_tabWidget, m_languageTab, QStringLiteral("settings.tab.language"), QStringLiteral("语言"));
}

// 启动页保留重启生效选项和显式系统集成动作，各分区独立排列。
void SettingsDock::initializeStartupTab()
{
    m_startupTab = new QWidget(m_tabWidget);
    auto* startupRootLayout = new QVBoxLayout(m_startupTab);
    ks::ui::StyleSecondaryContentLayout(startupRootLayout);
    auto& languageManager = ks::i18n::LanguageManager::instance();
    // ===== 启动行为分组 =====
    QGroupBox* startupGroupBox = new QGroupBox(QStringLiteral("启动行为"), m_startupTab);
    languageManager.bindText(startupGroupBox, QStringLiteral("settings.startup.group"), QStringLiteral("启动行为"));
    QVBoxLayout* startupLayout = new QVBoxLayout(startupGroupBox);
    startupLayout->setSpacing(8);

    QLabel* startupHintLabel = new QLabel(
        QStringLiteral("设置应用下次启动时的窗口显示方式与权限申请行为。"),
        startupGroupBox);
    startupHintLabel->setWordWrap(true);
    languageManager.bindText(startupHintLabel, QStringLiteral("settings.startup.hint"), QStringLiteral("设置应用下次启动时的窗口显示方式与权限申请行为。"));
    startupLayout->addWidget(startupHintLabel);
    auto* startupForm = ks::settings::ui::Form(startupLayout, 220);

    // m_startupMaximizedCheckBox 作用：控制“下次启动时是否直接最大化显示”。
    m_startupMaximizedCheckBox = new QCheckBox(QStringLiteral("启动时最大化"), startupGroupBox);
    languageManager.bindText(m_startupMaximizedCheckBox, QStringLiteral("settings.startup.maximized"), QStringLiteral("启动时最大化"));
    m_startupMaximizedCheckBox->setToolTip(QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    languageManager.bindToolTip(m_startupMaximizedCheckBox, QStringLiteral("settings.startup.maximized.tooltip"), QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    ks::settings::ui::ToggleRow(startupForm, m_startupMaximizedCheckBox,
        QStringLiteral("settings.startup.maximized"), QStringLiteral("启动时最大化"));

    // m_startupTopMostCheckBox 作用：控制“启动后是否自动设置 HWND_TOPMOST 最高级置顶”。
    m_startupTopMostCheckBox = new QCheckBox(QStringLiteral("启动后默认最高级置顶"), startupGroupBox);
    languageManager.bindText(m_startupTopMostCheckBox, QStringLiteral("settings.startup.topmost"), QStringLiteral("启动后默认最高级置顶"));
    m_startupTopMostCheckBox->setToolTip(
        QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    languageManager.bindToolTip(m_startupTopMostCheckBox, QStringLiteral("settings.startup.topmost.tooltip"), QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    ks::settings::ui::ToggleRow(startupForm, m_startupTopMostCheckBox,
        QStringLiteral("settings.startup.topmost"), QStringLiteral("启动后默认最高级置顶"));

    // m_startupAutoAdminCheckBox 作用：控制“启动图出现前是否先尝试 UAC 提权”。
    m_startupAutoAdminCheckBox = new QCheckBox(QStringLiteral("启动时自动请求管理员权限"), startupGroupBox);
    languageManager.bindText(m_startupAutoAdminCheckBox, QStringLiteral("settings.startup.admin"), QStringLiteral("启动时自动请求管理员权限"));
    m_startupAutoAdminCheckBox->setToolTip(
        QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    languageManager.bindToolTip(m_startupAutoAdminCheckBox, QStringLiteral("settings.startup.admin.tooltip"), QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    ks::settings::ui::ToggleRow(startupForm, m_startupAutoAdminCheckBox,
        QStringLiteral("settings.startup.admin"), QStringLiteral("启动时自动请求管理员权限"));

    // m_startupAutoInstallR0DriverCheckBox 作用：控制主窗口首次显示后是否自动安装并启动 KswordARK 驱动。
    m_startupAutoInstallR0DriverCheckBox = new QCheckBox(QStringLiteral("启动时自动安装驱动"), startupGroupBox);
    languageManager.bindText(m_startupAutoInstallR0DriverCheckBox, QStringLiteral("settings.startup.auto_install_r0"), QStringLiteral("启动时自动安装驱动"));
    m_startupAutoInstallR0DriverCheckBox->setToolTip(
        QStringLiteral("下次启动时自动尝试安装并启动 KswordARK 驱动；权限不足时会显示错误，但不会额外请求管理员重启"));
    languageManager.bindToolTip(m_startupAutoInstallR0DriverCheckBox, QStringLiteral("settings.startup.auto_install_r0.tooltip"), QStringLiteral("下次启动时自动尝试安装并启动 KswordARK 驱动；权限不足时会显示错误，但不会额外请求管理员重启"));
    ks::settings::ui::ToggleRow(startupForm, m_startupAutoInstallR0DriverCheckBox,
        QStringLiteral("settings.startup.auto_install_r0"), QStringLiteral("启动时自动安装驱动"));

    // m_preventMultipleInstancesCheckBox 作用：控制普通启动是否激活已有窗口并退出新进程。
    m_preventMultipleInstancesCheckBox = new QCheckBox(QStringLiteral("防止多开"), startupGroupBox);
    languageManager.bindText(m_preventMultipleInstancesCheckBox, QStringLiteral("settings.startup.prevent_multiple_instances"), QStringLiteral("防止多开"));
    m_preventMultipleInstancesCheckBox->setToolTip(
        QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    languageManager.bindToolTip(m_preventMultipleInstancesCheckBox, QStringLiteral("settings.startup.prevent_multiple_instances.tooltip"), QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    ks::settings::ui::ToggleRow(startupForm, m_preventMultipleInstancesCheckBox,
        QStringLiteral("settings.startup.prevent_multiple_instances"), QStringLiteral("防止多开"));

    // m_unlockerShellContextMenuCheckBox 作用：控制是否启用系统右键“文件解锁器”菜单。
    m_unlockerShellContextMenuCheckBox = new QCheckBox(QStringLiteral("启用系统右键“文件解锁器”菜单"), startupGroupBox);
    languageManager.bindText(m_unlockerShellContextMenuCheckBox, QStringLiteral("settings.startup.unlocker"), QStringLiteral("启用系统右键“文件解锁器”菜单"));
    m_unlockerShellContextMenuCheckBox->setToolTip(
        QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    languageManager.bindToolTip(m_unlockerShellContextMenuCheckBox, QStringLiteral("settings.startup.unlocker.tooltip"), QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    ks::settings::ui::ToggleRow(startupForm, m_unlockerShellContextMenuCheckBox,
        QStringLiteral("settings.startup.unlocker"), QStringLiteral("启用系统右键“文件解锁器”菜单"));

    QLabel* taskmgrHijackHintLabel = new QLabel(
        QStringLiteral("将系统任务管理器入口切换到 Ksword。此操作需要管理员权限。"),
        startupGroupBox);
    taskmgrHijackHintLabel->setWordWrap(true);
    languageManager.bindText(taskmgrHijackHintLabel, QStringLiteral("settings.startup.taskmgr_hint"), QStringLiteral("将系统任务管理器入口切换到 Ksword。此操作需要管理员权限。"));
    startupLayout->addWidget(taskmgrHijackHintLabel);

    QHBoxLayout* taskmgrHijackButtonLayout = new QHBoxLayout();
    taskmgrHijackButtonLayout->setSpacing(8);

    // m_installTaskmgrHijackButton 作用：将 taskmgr.exe IFEO Debugger 指向当前 Ksword5.1.exe。
    m_installTaskmgrHijackButton = new QPushButton(QStringLiteral("用 Ksword 替代任务管理器"), startupGroupBox);
    languageManager.bindText(m_installTaskmgrHijackButton, QStringLiteral("settings.startup.taskmgr_install"), QStringLiteral("用 Ksword 替代任务管理器"));
    m_installTaskmgrHijackButton->setMinimumWidth(146);
    m_installTaskmgrHijackButton->setFixedHeight(30);
    m_installTaskmgrHijackButton->setToolTip(
        QStringLiteral("打开任务管理器时改为启动 Ksword"));
    languageManager.bindToolTip(m_installTaskmgrHijackButton, QStringLiteral("settings.startup.taskmgr_install.tooltip"), QStringLiteral("打开任务管理器时改为启动 Ksword"));
    taskmgrHijackButtonLayout->addWidget(m_installTaskmgrHijackButton, 0);

    // m_uninstallTaskmgrHijackButton 作用：移除 taskmgr.exe IFEO Debugger，还原系统任务管理器。
    m_uninstallTaskmgrHijackButton = new QPushButton(QStringLiteral("恢复系统任务管理器"), startupGroupBox);
    languageManager.bindText(m_uninstallTaskmgrHijackButton, QStringLiteral("settings.startup.taskmgr_uninstall"), QStringLiteral("恢复系统任务管理器"));
    m_uninstallTaskmgrHijackButton->setMinimumWidth(126);
    m_uninstallTaskmgrHijackButton->setFixedHeight(30);
    m_uninstallTaskmgrHijackButton->setToolTip(
        QStringLiteral("恢复任务管理器的默认启动方式"));
    languageManager.bindToolTip(m_uninstallTaskmgrHijackButton, QStringLiteral("settings.startup.taskmgr_uninstall.tooltip"), QStringLiteral("恢复任务管理器的默认启动方式"));
    taskmgrHijackButtonLayout->addWidget(m_uninstallTaskmgrHijackButton, 0);
    taskmgrHijackButtonLayout->addStretch(1);
    startupLayout->addLayout(taskmgrHijackButtonLayout);
    ks::ui::NormalizeToolbarRow(taskmgrHijackButtonLayout);

    // 启动窗口缩放设置：重启后生效，用于统一控制主窗口 UI 缩放。
    QHBoxLayout* startupScaleLayout = new QHBoxLayout();
    startupScaleLayout->setSpacing(6);
    QLabel* startupScaleLabel = new QLabel(QStringLiteral("窗口缩放"), startupGroupBox);
    languageManager.bindText(startupScaleLabel, QStringLiteral("settings.startup.scale"), QStringLiteral("窗口缩放"));
    startupScaleLayout->addWidget(startupScaleLabel, 0);

    // m_startupWindowScaleSpin 作用：设置下次启动的主窗口缩放百分比。
    // 这里刻意不再用“缩放因子 1.00”这种倍率输入框：倍率是内部表示，
    // 用户脑子里的量是百分比（和 Windows 显示设置一致）；旧的纯文本框
    // 既没有校验器也不展示可用范围，输入 150（当成百分比）会被静默钳到 2.00。
    // 步进框把范围、步长和单位都摆在界面上，越界根本输入不进去。
    m_startupWindowScaleSpin = new QSpinBox(startupGroupBox);
    m_startupWindowScaleSpin->setRange(
        qRound(ks::settings::MinimumWindowScaleFactor * 100.0),
        qRound(ks::settings::MaximumWindowScaleFactor * 100.0));
    m_startupWindowScaleSpin->setSingleStep(5);
    m_startupWindowScaleSpin->setSuffix(QStringLiteral(" %"));
    m_startupWindowScaleSpin->setValue(100);
    m_startupWindowScaleSpin->setKeyboardTracking(false);
    m_startupWindowScaleSpin->setToolTip(
        QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    languageManager.bindToolTip(m_startupWindowScaleSpin, QStringLiteral("settings.startup.scale.tooltip"), QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    startupScaleLayout->addWidget(m_startupWindowScaleSpin, 0);
    startupScaleLayout->addStretch(1);
    startupScaleLayout->removeWidget(startupScaleLabel);
    startupForm->addRow(startupScaleLabel, ks::settings::ui::ControlRow(startupScaleLayout, startupGroupBox));

    // m_startupWindowScaleHintLabel 作用：说明生效时机与系统缩放的关系。
    // 具体百分比已经由步进框自己显示，这里不再重复。
    m_startupWindowScaleHintLabel = new QLabel(
        QStringLiteral("重启后生效；最终大小是系统显示缩放与此处设置相乘的结果。"),
        startupGroupBox);
    m_startupWindowScaleHintLabel->setWordWrap(true);
    languageManager.bindText(
        m_startupWindowScaleHintLabel,
        QStringLiteral("settings.startup.scale_hint"),
        QStringLiteral("重启后生效；最终大小是系统显示缩放与此处设置相乘的结果。"));
    startupForm->addRow(QString(), m_startupWindowScaleHintLabel);

    ks::settings::ui::Section(startupGroupBox);
    startupRootLayout->addWidget(startupGroupBox);
    startupRootLayout->addStretch();

    m_startupTab = ks::settings::ui::ScrollPage(m_startupTab);
    m_tabWidget->addTab(m_startupTab, QStringLiteral("启动"));
    languageManager.bindTab(m_tabWidget, m_startupTab, QStringLiteral("settings.tab.startup"), QStringLiteral("启动"));
}

// 外观的通知和权限显示属于低频选项，放在主配色与交互区域之后。
void SettingsDock::initializeAppearanceSupplement(QVBoxLayout* appearanceRootLayout)
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    // ===== 权限按钮排分组 =====
    QGroupBox* privilegeGroupBox = new QGroupBox(QStringLiteral("权限状态按钮"), m_appearanceTab);
    languageManager.bindText(
        privilegeGroupBox,
        QStringLiteral("settings.privilege_buttons.group"),
        QStringLiteral("权限状态按钮"));
    QVBoxLayout* privilegeLayout = new QVBoxLayout(privilegeGroupBox);
    privilegeLayout->setSpacing(8);

    QLabel* privilegeHintLabel = new QLabel(
        QStringLiteral("选择右上角显示哪些权限等级。取消勾选只是不再显示，不会改变任何能力。"),
        privilegeGroupBox);
    privilegeHintLabel->setWordWrap(true);
    languageManager.bindText(
        privilegeHintLabel,
        QStringLiteral("settings.privilege_buttons.hint"),
        QStringLiteral("选择右上角显示哪些权限等级。取消勾选只是不再显示，不会改变任何能力。"));
    privilegeLayout->addWidget(privilegeHintLabel);
    auto* privilegeOptions = new QWidget(privilegeGroupBox); // 权限开关不缩短名称，窄时自动换行。
    auto* privilegeFlow = new ks::ui::FlowLayout(privilegeOptions, 0, 16, 8);
    privilegeLayout->addWidget(privilegeOptions);

    m_privilegeUiAccessCheckBox = new QCheckBox(QStringLiteral("UIAccess（跨权限窗口置顶）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeUiAccessCheckBox,
        QStringLiteral("settings.privilege_buttons.uiaccess"),
        QStringLiteral("UIAccess（跨权限窗口置顶）"));
    privilegeFlow->addWidget(m_privilegeUiAccessCheckBox);

    m_privilegeAdminCheckBox = new QCheckBox(QStringLiteral("Admin（管理员）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeAdminCheckBox,
        QStringLiteral("settings.privilege_buttons.admin"),
        QStringLiteral("Admin（管理员）"));
    privilegeFlow->addWidget(m_privilegeAdminCheckBox);

    m_privilegeDebugCheckBox = new QCheckBox(QStringLiteral("Debug（调试特权）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeDebugCheckBox,
        QStringLiteral("settings.privilege_buttons.debug"),
        QStringLiteral("Debug（调试特权）"));
    privilegeFlow->addWidget(m_privilegeDebugCheckBox);

    m_privilegeSystemCheckBox = new QCheckBox(QStringLiteral("System（系统账户）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeSystemCheckBox,
        QStringLiteral("settings.privilege_buttons.system"),
        QStringLiteral("System（系统账户）"));
    privilegeFlow->addWidget(m_privilegeSystemCheckBox);

    m_privilegeR0CheckBox = new QCheckBox(QStringLiteral("R0（内核驱动）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeR0CheckBox,
        QStringLiteral("settings.privilege_buttons.r0"),
        QStringLiteral("R0（内核驱动）"));
    privilegeFlow->addWidget(m_privilegeR0CheckBox);

    m_privilegeHvmCheckBox = new QCheckBox(QStringLiteral("R-1（硬件虚拟化）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeHvmCheckBox,
        QStringLiteral("settings.privilege_buttons.hvm"),
        QStringLiteral("R-1（硬件虚拟化）"));
    privilegeFlow->addWidget(m_privilegeHvmCheckBox);

    m_privilegeDdmaCheckBox = new QCheckBox(QStringLiteral("DDMA（磁盘直接内存访问）"), privilegeGroupBox);
    languageManager.bindText(
        m_privilegeDdmaCheckBox,
        QStringLiteral("settings.privilege_buttons.ddma"),
        QStringLiteral("DDMA（磁盘直接内存访问）"));
    // 整串写在一行：跨行拼接会被 i18n 审计当成多个独立源串，逐段都要词条。
    m_privilegeDdmaCheckBox->setToolTip(QStringLiteral("显示 DDMA 常驻虚扇区指示灯。亮起代表磁盘上有一块扇区正被当作 DMA 中转站占用。"));
    privilegeFlow->addWidget(m_privilegeDdmaCheckBox);

    QHBoxLayout* hvmNameLayout = new QHBoxLayout();
    hvmNameLayout->setSpacing(6);
    QLabel* hvmNameLabel = new QLabel(QStringLiteral("虚拟化按钮显示为"), privilegeGroupBox);
    languageManager.bindText(
        hvmNameLabel,
        QStringLiteral("settings.privilege_buttons.hvm_name"),
        QStringLiteral("虚拟化按钮显示为"));
    hvmNameLayout->addWidget(hvmNameLabel, 0);
    m_hvmDisplayNameCombo = new QComboBox(privilegeGroupBox);
    // 两个都是体系结构术语，不随界面语言变化，所以条目文本不绑词条。
    m_hvmDisplayNameCombo->addItem(
        QStringLiteral("HVM"),
        static_cast<int>(ks::settings::HvmDisplayName::Hvm));
    m_hvmDisplayNameCombo->addItem(
        QStringLiteral("R-1"),
        static_cast<int>(ks::settings::HvmDisplayName::RingMinusOne));
    // 整串写在一行：跨行拼接会被 i18n 审计当成多个独立源串，逐段都要词条。
    m_hvmDisplayNameCombo->setToolTip(
        QStringLiteral("HVM 是硬件虚拟化名称，R-1 是按权限分层的称呼。只影响右上角按钮。"));
    hvmNameLayout->addWidget(m_hvmDisplayNameCombo, 1);
    hvmNameLayout->removeWidget(hvmNameLabel);
    auto* privilegeForm = ks::settings::ui::Form(privilegeLayout, 176);
    privilegeForm->addRow(hvmNameLabel, ks::settings::ui::ControlRow(hvmNameLayout, privilegeGroupBox));
    ks::settings::ui::Section(privilegeGroupBox);

    // ===== 日志通知分组 =====
    QGroupBox* notificationGroupBox = new QGroupBox(QStringLiteral("日志通知"), m_appearanceTab);
    languageManager.bindText(notificationGroupBox, QStringLiteral("settings.notification.group"), QStringLiteral("日志通知"));
    QVBoxLayout* notificationLayout = new QVBoxLayout(notificationGroupBox);
    notificationLayout->setSpacing(8);

    QLabel* notificationHintLabel = new QLabel(
        QStringLiteral("在右侧以不抢焦点的卡片显示日志和运行中任务。"),
        notificationGroupBox);
    notificationHintLabel->setWordWrap(true);
    languageManager.bindText(notificationHintLabel, QStringLiteral("settings.notification.hint"), QStringLiteral("在右侧以不抢焦点的卡片显示日志和运行中任务。"));
    notificationLayout->addWidget(notificationHintLabel);
    auto* notificationForm = ks::settings::ui::Form(notificationLayout);

    m_notificationCardsEnabledCheckBox = new QCheckBox(QStringLiteral("启用右侧通知卡片"), notificationGroupBox);
    languageManager.bindText(m_notificationCardsEnabledCheckBox, QStringLiteral("settings.notification.enabled"), QStringLiteral("启用右侧通知卡片"));
    ks::settings::ui::ToggleRow(notificationForm, m_notificationCardsEnabledCheckBox,
        QStringLiteral("settings.notification.enabled"), QStringLiteral("启用右侧通知卡片"));

    QHBoxLayout* notificationLevelLayout = new QHBoxLayout();
    QLabel* notificationLevelLabel = new QLabel(QStringLiteral("最低日志级别"), notificationGroupBox);
    languageManager.bindText(notificationLevelLabel, QStringLiteral("settings.notification.minimum_level"), QStringLiteral("最低日志级别"));
    notificationLevelLayout->addWidget(notificationLevelLabel, 0);
    m_notificationMinimumLevelCombo = new QComboBox(notificationGroupBox);
    m_notificationMinimumLevelCombo->addItem(QStringLiteral("调试 Debug"), 0);
    m_notificationMinimumLevelCombo->addItem(QStringLiteral("信息 Info"), 1);
    m_notificationMinimumLevelCombo->addItem(QStringLiteral("警告 Warn"), 2);
    m_notificationMinimumLevelCombo->addItem(QStringLiteral("错误 Error"), 3);
    m_notificationMinimumLevelCombo->addItem(QStringLiteral("致命 Fatal"), 4);
    languageManager.bindComboBoxItem(m_notificationMinimumLevelCombo, 0, QStringLiteral("settings.notification.level.debug"), QStringLiteral("调试 Debug"));
    languageManager.bindComboBoxItem(m_notificationMinimumLevelCombo, 1, QStringLiteral("settings.notification.level.info"), QStringLiteral("信息 Info"));
    languageManager.bindComboBoxItem(m_notificationMinimumLevelCombo, 2, QStringLiteral("settings.notification.level.warn"), QStringLiteral("警告 Warn"));
    languageManager.bindComboBoxItem(m_notificationMinimumLevelCombo, 3, QStringLiteral("settings.notification.level.error"), QStringLiteral("错误 Error"));
    languageManager.bindComboBoxItem(m_notificationMinimumLevelCombo, 4, QStringLiteral("settings.notification.level.fatal"), QStringLiteral("致命 Fatal"));
    notificationLevelLayout->addWidget(m_notificationMinimumLevelCombo, 1);
    notificationLevelLayout->removeWidget(notificationLevelLabel);
    notificationForm->addRow(notificationLevelLabel,
        ks::settings::ui::ControlRow(notificationLevelLayout, notificationGroupBox));

    QHBoxLayout* notificationDurationLayout = new QHBoxLayout();
    QLabel* notificationDurationLabel = new QLabel(QStringLiteral("日志展示秒数"), notificationGroupBox);
    languageManager.bindText(notificationDurationLabel, QStringLiteral("settings.notification.duration"), QStringLiteral("日志展示秒数"));
    notificationDurationLayout->addWidget(notificationDurationLabel, 0);
    m_notificationLogDisplaySecondsSpin = new QSpinBox(notificationGroupBox);
    m_notificationLogDisplaySecondsSpin->setRange(0, 60);
    m_notificationLogDisplaySecondsSpin->setSuffix(QStringLiteral(" 秒"));
    m_notificationLogDisplaySecondsSpin->setToolTip(QStringLiteral("0 表示日志卡片常驻，直到因空间不足被替换。"));
    languageManager.bindToolTip(m_notificationLogDisplaySecondsSpin, QStringLiteral("settings.notification.duration.tooltip"), QStringLiteral("0 表示日志卡片常驻，直到因空间不足被替换。"));
    notificationDurationLayout->addWidget(m_notificationLogDisplaySecondsSpin, 1);
    notificationDurationLayout->removeWidget(notificationDurationLabel);
    notificationForm->addRow(notificationDurationLabel,
        ks::settings::ui::ControlRow(notificationDurationLayout, notificationGroupBox));

    QHBoxLayout* notificationMaximumCountLayout = new QHBoxLayout();
    QLabel* notificationMaximumCountLabel = new QLabel(QStringLiteral("同时显示最多日志条数"), notificationGroupBox);
    languageManager.bindText(notificationMaximumCountLabel, QStringLiteral("settings.notification.maximum_count"), QStringLiteral("同时显示最多日志条数"));
    notificationMaximumCountLayout->addWidget(notificationMaximumCountLabel, 0);
    m_notificationMaximumVisibleLogCardsSpin = new QSpinBox(notificationGroupBox);
    m_notificationMaximumVisibleLogCardsSpin->setRange(0, 100);
    m_notificationMaximumVisibleLogCardsSpin->setToolTip(QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    languageManager.bindToolTip(m_notificationMaximumVisibleLogCardsSpin, QStringLiteral("settings.notification.maximum_count.tooltip"), QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    notificationMaximumCountLayout->addWidget(m_notificationMaximumVisibleLogCardsSpin, 1);
    notificationMaximumCountLayout->removeWidget(notificationMaximumCountLabel);
    notificationForm->addRow(notificationMaximumCountLabel,
        ks::settings::ui::ControlRow(notificationMaximumCountLayout, notificationGroupBox));

    m_notificationLogHeightLimitCheckBox = new QCheckBox(QStringLiteral("限制单条日志卡片高度"), notificationGroupBox);
    languageManager.bindText(m_notificationLogHeightLimitCheckBox, QStringLiteral("settings.notification.height_limit.enabled"), QStringLiteral("限制单条日志卡片高度"));
    ks::settings::ui::ToggleRow(notificationForm, m_notificationLogHeightLimitCheckBox,
        QStringLiteral("settings.notification.height_limit.enabled"), QStringLiteral("限制单条日志卡片高度"));

    QHBoxLayout* notificationMaximumLinesLayout = new QHBoxLayout();
    QLabel* notificationMaximumLinesLabel = new QLabel(QStringLiteral("最高文字行数"), notificationGroupBox);
    languageManager.bindText(notificationMaximumLinesLabel, QStringLiteral("settings.notification.height_limit.lines"), QStringLiteral("最高文字行数"));
    notificationMaximumLinesLayout->addWidget(notificationMaximumLinesLabel, 0);
    m_notificationLogMaximumLinesSpin = new QSpinBox(notificationGroupBox);
    m_notificationLogMaximumLinesSpin->setRange(1, 50);
    m_notificationLogMaximumLinesSpin->setSuffix(QStringLiteral(" 行"));
    languageManager.bindSuffix(m_notificationLogMaximumLinesSpin, QStringLiteral("settings.notification.height_limit.lines.suffix"), QStringLiteral(" 行"));
    m_notificationLogMaximumLinesSpin->setToolTip(QStringLiteral("超出时可通过卡片标题栏的小箭头展开完整日志。"));
    languageManager.bindToolTip(m_notificationLogMaximumLinesSpin, QStringLiteral("settings.notification.height_limit.lines.tooltip"), QStringLiteral("超出时可通过卡片标题栏的小箭头展开完整日志。"));
    notificationMaximumLinesLayout->addWidget(m_notificationLogMaximumLinesSpin, 1);
    notificationMaximumLinesLayout->removeWidget(notificationMaximumLinesLabel);
    notificationForm->addRow(notificationMaximumLinesLabel,
        ks::settings::ui::ControlRow(notificationMaximumLinesLayout, notificationGroupBox));

    QHBoxLayout* notificationPlacementLayout = new QHBoxLayout();
    QLabel* notificationPlacementLabel = new QLabel(QStringLiteral("显示位置"), notificationGroupBox);
    languageManager.bindText(notificationPlacementLabel, QStringLiteral("settings.notification.placement"), QStringLiteral("显示位置"));
    notificationPlacementLayout->addWidget(notificationPlacementLabel, 0);
    m_notificationDisplayPlacementCombo = new QComboBox(notificationGroupBox);
    m_notificationDisplayPlacementCombo->addItem(QStringLiteral("屏幕右侧"), static_cast<int>(ks::settings::NotificationDisplayPlacement::Screen));
    m_notificationDisplayPlacementCombo->addItem(QStringLiteral("Ksword 主窗口内"), static_cast<int>(ks::settings::NotificationDisplayPlacement::MainWindow));
    languageManager.bindComboBoxItem(m_notificationDisplayPlacementCombo, 0, QStringLiteral("settings.notification.placement.screen"), QStringLiteral("屏幕右侧"));
    languageManager.bindComboBoxItem(m_notificationDisplayPlacementCombo, 1, QStringLiteral("settings.notification.placement.window"), QStringLiteral("Ksword 主窗口内"));
    notificationPlacementLayout->addWidget(m_notificationDisplayPlacementCombo, 1);
    notificationPlacementLayout->removeWidget(notificationPlacementLabel);
    notificationForm->addRow(notificationPlacementLabel,
        ks::settings::ui::ControlRow(notificationPlacementLayout, notificationGroupBox));

    QHBoxLayout* notificationStackLayout = new QHBoxLayout();
    QLabel* notificationStackLabel = new QLabel(QStringLiteral("堆叠方向"), notificationGroupBox);
    languageManager.bindText(notificationStackLabel, QStringLiteral("settings.notification.stack_direction"), QStringLiteral("堆叠方向"));
    notificationStackLayout->addWidget(notificationStackLabel, 0);
    m_notificationStackDirectionCombo = new QComboBox(notificationGroupBox);
    m_notificationStackDirectionCombo->addItem(QStringLiteral("右下向右上"), static_cast<int>(ks::settings::NotificationStackDirection::BottomUp));
    m_notificationStackDirectionCombo->addItem(QStringLiteral("右上向右下"), static_cast<int>(ks::settings::NotificationStackDirection::TopDown));
    languageManager.bindComboBoxItem(m_notificationStackDirectionCombo, 0, QStringLiteral("settings.notification.stack.bottom_up"), QStringLiteral("右下向右上"));
    languageManager.bindComboBoxItem(m_notificationStackDirectionCombo, 1, QStringLiteral("settings.notification.stack.top_down"), QStringLiteral("右上向右下"));
    notificationStackLayout->addWidget(m_notificationStackDirectionCombo, 1);
    notificationStackLayout->removeWidget(notificationStackLabel);
    notificationForm->addRow(notificationStackLabel,
        ks::settings::ui::ControlRow(notificationStackLayout, notificationGroupBox));

    ks::settings::ui::Section(notificationGroupBox);
    appearanceRootLayout->addWidget(ks::ui::CreateSecondaryColumns(
        notificationGroupBox, privilegeGroupBox, m_appearanceTab, 1000, 3, 2));

}

void SettingsDock::initializeFeaturesTab()
{
    m_featuresTab = new QWidget(m_tabWidget);
    QVBoxLayout* featuresRootLayout = new QVBoxLayout(m_featuresTab);
    ks::ui::StyleSecondaryContentLayout(featuresRootLayout);
    // 功能页按完整分区留白，避免相邻标题与上一组开关挤在一起。
    featuresRootLayout->setSpacing(24);

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();
    QGroupBox* r0PromptGroupBox = new QGroupBox(QStringLiteral("R0 功能提示"), m_featuresTab);
    languageManager.bindText(
        r0PromptGroupBox,
        QStringLiteral("settings.features.r0.group"),
        QStringLiteral("R0 功能提示"));
    QVBoxLayout* r0PromptLayout = new QVBoxLayout(r0PromptGroupBox);
    r0PromptLayout->setSpacing(8);

    QLabel* r0PromptHintLabel = new QLabel(
        QStringLiteral("勾选后，R0 驱动未启用或当前权限不足时不再自动弹出提示；仍可通过标题栏 R0 按钮手动管理驱动。"),
        r0PromptGroupBox);
    r0PromptHintLabel->setWordWrap(true);
    languageManager.bindText(
        r0PromptHintLabel,
        QStringLiteral("settings.features.r0.hint"),
        QStringLiteral("勾选后，R0 驱动未启用或当前权限不足时不再自动弹出提示；仍可通过标题栏 R0 按钮手动管理驱动。"));
    r0PromptLayout->addWidget(r0PromptHintLabel);

    m_suppressR0FeaturePromptsCheckBox = new QCheckBox(
        QStringLiteral("永远不提示 R0 功能"),
        r0PromptGroupBox);
    languageManager.bindText(
        m_suppressR0FeaturePromptsCheckBox,
        QStringLiteral("settings.features.r0.suppress_prompts"),
        QStringLiteral("永远不提示 R0 功能"));
    m_suppressR0FeaturePromptsCheckBox->setToolTip(
        QStringLiteral("关闭 R0 驱动未启用和权限不足时的自动提示"));
    languageManager.bindToolTip(
        m_suppressR0FeaturePromptsCheckBox,
        QStringLiteral("settings.features.r0.suppress_prompts.tooltip"),
        QStringLiteral("关闭 R0 驱动未启用和权限不足时的自动提示"));
    r0PromptLayout->addWidget(m_suppressR0FeaturePromptsCheckBox);

    ks::settings::ui::Section(r0PromptGroupBox);
    featuresRootLayout->addWidget(r0PromptGroupBox);

    // ---- 崩溃转储自动检查 ----
    QGroupBox* dumpCheckGroupBox = new QGroupBox(QStringLiteral("崩溃转储检查"), m_featuresTab);
    languageManager.bindText(
        dumpCheckGroupBox,
        QStringLiteral("settings.features.dump.group"),
        QStringLiteral("崩溃转储检查"));
    QVBoxLayout* dumpCheckLayout = new QVBoxLayout(dumpCheckGroupBox);
    dumpCheckLayout->setSpacing(8);

    QLabel* dumpCheckHintLabel = new QLabel(
        QStringLiteral("启动后检查系统近 24 小时内是否产生过新的崩溃转储，有则询问是否立即解析。"
            "检查只读取文件名与时间，不会打开转储内容；同一个转储只会询问一次。"),
        dumpCheckGroupBox);
    dumpCheckHintLabel->setWordWrap(true);
    languageManager.bindText(
        dumpCheckHintLabel,
        QStringLiteral("settings.features.dump.hint"),
        QStringLiteral("启动后检查系统近 24 小时内是否产生过新的崩溃转储，有则询问是否立即解析。"
            "检查只读取文件名与时间，不会打开转储内容；同一个转储只会询问一次。"));
    dumpCheckLayout->addWidget(dumpCheckHintLabel);

    m_dumpAutoCheckCheckBox = new QCheckBox(
        QStringLiteral("启动时检查新的崩溃转储"),
        dumpCheckGroupBox);
    languageManager.bindText(
        m_dumpAutoCheckCheckBox,
        QStringLiteral("settings.features.dump.auto_check"),
        QStringLiteral("启动时检查新的崩溃转储"));
    m_dumpAutoCheckCheckBox->setToolTip(
        QStringLiteral("关闭后不再自动检查，仍可随时在“转储分析”页手动打开转储文件"));
    languageManager.bindToolTip(
        m_dumpAutoCheckCheckBox,
        QStringLiteral("settings.features.dump.auto_check.tooltip"),
        QStringLiteral("关闭后不再自动检查，仍可随时在“转储分析”页手动打开转储文件"));
    dumpCheckLayout->addWidget(m_dumpAutoCheckCheckBox);

    ks::settings::ui::Section(dumpCheckGroupBox);
    featuresRootLayout->addWidget(dumpCheckGroupBox);
    initializeBugcheckDiagnosticsControls(featuresRootLayout);
    featuresRootLayout->addStretch();
    m_featuresTab = ks::settings::ui::ScrollPage(m_featuresTab);
    m_tabWidget->addTab(m_featuresTab, QStringLiteral("功能"));
    languageManager.bindTab(
        m_tabWidget,
        m_featuresTab,
        QStringLiteral("settings.tab.features"),
        QStringLiteral("功能"));

    connect(
        m_suppressR0FeaturePromptsCheckBox,
        &QCheckBox::toggled,
        this,
        [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
        });

    connect(
        m_dumpAutoCheckCheckBox,
        &QCheckBox::toggled,
        this,
        [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
        });
}

