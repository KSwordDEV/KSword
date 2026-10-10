#include "SettingsDock.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/FlatButtonTheme.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../theme.h"
#include "../UI/ThemePreviewWidget.h"

#include <QButtonGroup>
#include <QCheckBox>
#include <QColorDialog>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QFileInfo>
#include <QFileDialog>
#include <QFontDatabase>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QProcess>
#include <QPixmap>
#include <QPushButton>
#include <QRadioButton>
#include <QSlider>
#include <QSpinBox>
#include <QStringList>
#include <QStyleHints>
#include <QTabWidget>
#include <QToolButton>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cmath>
#include <string>
#include <vector>

namespace
{
    // ToolTip 与图标常量：统一维护设置页按钮文案，避免硬编码分散。
    constexpr wchar_t kUnlockerKeyName[] = L"Ksword.FileUnlocker";

    // windowScalePercentFromFactor / windowScaleFactorFromPercent 作用：
    // - 设置页按百分比呈现窗口缩放（与 Windows 显示设置一致），配置文件仍然存倍率；
    // - 两个方向都过一遍 normalizeWindowScaleFactor，保证界面可选范围与落盘范围一致。
    // 入参/返回：百分比整数（50~200）与缩放倍率（0.50~2.00）互转。
    int windowScalePercentFromFactor(const double scaleFactor)
    {
        return static_cast<int>(std::lround(
            ks::settings::normalizeWindowScaleFactor(scaleFactor) * 100.0));
    }

    double windowScaleFactorFromPercent(const int scalePercent)
    {
        return ks::settings::normalizeWindowScaleFactor(
            static_cast<double>(scalePercent) / 100.0);
    }

    // selectedThemeUsesDarkBackground 作用：为尚未应用的主题按钮状态计算默认主背景预览。
    // 跟随系统与MainWindow使用同一平台来源，避免当前强制浅色掩盖系统深色。
    bool selectedThemeUsesDarkBackground(const QButtonGroup* themeButtonGroup)
    {
        if (themeButtonGroup != nullptr)
        {
            const int checkedThemeId = themeButtonGroup->checkedId();
            if (checkedThemeId == static_cast<int>(ks::settings::ThemeMode::Dark))
            {
                return true;
            }
            if (checkedThemeId == static_cast<int>(ks::settings::ThemeMode::Light))
            {
                return false;
            }
        }
        const QStyleHints* styleHints = QGuiApplication::styleHints(); // 系统当前的真实配色方案。
        return styleHints != nullptr && styleHints->colorScheme() == Qt::ColorScheme::Dark;
    }

    std::wstring queryCurrentExecutablePath()
    {
        std::vector<wchar_t> pathBuffer(1024, L'\0');
        while (pathBuffer.size() < 32768)
        {
            ::SetLastError(ERROR_SUCCESS);
            const DWORD copiedLength = ::GetModuleFileNameW(
                nullptr,
                pathBuffer.data(),
                static_cast<DWORD>(pathBuffer.size()));
            const DWORD lastError = ::GetLastError();
            if (copiedLength == 0)
            {
                return std::wstring();
            }
            if (copiedLength < pathBuffer.size() && lastError != ERROR_INSUFFICIENT_BUFFER)
            {
                return std::wstring(pathBuffer.data(), copiedLength);
            }
            pathBuffer.resize(pathBuffer.size() * 2, L'\0');
        }
        return std::wstring();
    }

    bool writeRegistryString(
        HKEY rootKey,
        const std::wstring& subKeyPath,
        const wchar_t* valueName,
        const std::wstring& valueText)
    {
        HKEY keyHandle = nullptr;
        const LONG createResult = ::RegCreateKeyExW(
            rootKey,
            subKeyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &keyHandle,
            nullptr);
        if (createResult != ERROR_SUCCESS)
        {
            return false;
        }

        const DWORD valueSizeBytes = static_cast<DWORD>((valueText.size() + 1) * sizeof(wchar_t));
        const LONG setResult = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueText.c_str()),
            valueSizeBytes);
        ::RegCloseKey(keyHandle);
        return setResult == ERROR_SUCCESS;
    }

    void deleteRegistryTreeBestEffort(HKEY rootKey, const std::wstring& subKeyPath)
    {
        ::RegDeleteTreeW(rootKey, subKeyPath.c_str());
    }

    bool registerUnlockerContextMenuNow(const std::wstring& executablePath)
    {
        if (executablePath.empty())
        {
            return false;
        }

        const std::wstring commandForFile = L"\"" + executablePath + L"\" --unlock \"%1\"";
        const std::wstring baseStar = L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring baseDirectory = L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring baseDrive = L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring menuText = ks::i18n::contextText(
            QStringLiteral("main.unlocker.menu"),
            QStringLiteral("使用 Ksword 文件解锁器(R3/R0)")).toStdWString();

        // 解锁器只对“选中的文件/文件夹/驱动器”有意义，因此不再注册 Directory\Background：
        // 该位置是桌面和文件夹空白处的右键菜单，没有选中目标，菜单项纯属噪音。
        // 旧版本写过这个键，注册时顺带清掉，避免升级后残留在桌面右键上。
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));

        return
            writeRegistryString(HKEY_CURRENT_USER, baseStar, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseStar, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseStar + L"\\command", nullptr, commandForFile)
            && writeRegistryString(HKEY_CURRENT_USER, baseDirectory, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseDirectory, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseDirectory + L"\\command", nullptr, commandForFile)
            && writeRegistryString(HKEY_CURRENT_USER, baseDrive, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseDrive, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseDrive + L"\\command", nullptr, commandForFile);
    }

    void unregisterUnlockerContextMenuNow()
    {
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName));
        // Directory\Background 已不再注册，但仍要删：旧版本装过的用户需要被清理干净。
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));
    }
}

SettingsDock::SettingsDock(QWidget* parent)
    : QWidget(parent)
{
    // 构造日志事件：用于追踪“设置页初始化”整个调用链。
    kLogEvent settingsInitEvent;
    info << settingsInitEvent << "[SettingsDock] 开始初始化设置页 UI。" << eol;

    initializeUi();
    initializeAppearanceTab();
    initializeLanguageTab();
    initializeStartupTab();
    initializeFeaturesTab();
    initializeOnlineScanTab();
    bindAppearanceSignals();
    loadSettingsFromJson();

    info << settingsInitEvent << "[SettingsDock] 设置页初始化完成，界面与启动配置已加载。" << eol;
}

ks::settings::AppearanceSettings SettingsDock::currentAppearanceSettings() const
{
    return m_currentAppearanceSettings;
}

void SettingsDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event == nullptr)
    {
        return;
    }
    if (event->type() == QEvent::LanguageChange)
    {
        updateSystemDefaultFontItemText();
        refreshBugcheckDiagnosticsStatusText();
        updateApplyButtonState();
    }
    // 跟随系统模式下深浅色由系统翻转，不经过“应用”按钮，
    // 这里补一次重下发，避免主题按钮自身停在旧主题的快照配色上。
    if (event->type() == QEvent::ApplicationPaletteChange && m_themeButtonGroup != nullptr)
    {
        updateThemeButtonStyle();
        updateMainBackgroundColorPreview();
    }
}

void SettingsDock::initializeUi()
{
    // rootLayout 作用：SettingsDock 根布局，仅承载可滚动的设置页签内容。
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(8);

    // m_tabWidget 作用：设置页签容器，后续可扩展更多标签页。
    m_tabWidget = new QTabWidget(this);
    ks::ui::StyleSecondaryTabs(m_tabWidget);
    m_tabWidget->setTabPosition(QTabWidget::North);
    rootLayout->addWidget(m_tabWidget);

    setLayout(rootLayout);
}

void SettingsDock::showLanguageSettingsTab()
{
    if (m_tabWidget != nullptr && m_languageTab != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_languageTab);
    }
}

void SettingsDock::bindAppearanceSignals()
{
    // 即使主窗口当前强制主题，未应用的“跟随系统”预览也要响应系统切换。
    if (QStyleHints* styleHints = QGuiApplication::styleHints())
    {
        connect(styleHints, &QStyleHints::colorSchemeChanged, this, [this]() {
            updateMainBackgroundColorPreview();
        });
    }
    if (m_languageCombo != nullptr)
    {
        connect(m_languageCombo, &QComboBox::currentIndexChanged, this, [this](const int /*index*/) {
            markPendingChanges(QStringLiteral("界面语言变化"));
        });
    }

    connect(m_themeButtonGroup, &QButtonGroup::idClicked, this, [this](int /*clickedId*/) {
        updateThemeButtonStyle();
        updateMainBackgroundColorPreview();
        markPendingChanges(QStringLiteral("主题按钮切换"));
        });

    connect(m_chooseThemeColorButton, &QPushButton::clicked, this, [this]() {
        chooseCustomThemeColor();
        });

    connect(m_resetThemeColorButton, &QPushButton::clicked, this, [this]() {
        resetThemeColorToDefault();
        });

    connect(m_chooseMainBackgroundColorButton, &QPushButton::clicked, this, [this]() {
        chooseCustomMainBackgroundColor();
        });

    connect(m_resetMainBackgroundColorButton, &QPushButton::clicked, this, [this]() {
        resetMainBackgroundColorToDefault();
        });

    connect(m_fontCombo, &QComboBox::currentIndexChanged, this, [this](const int /*fontIndex*/) {
        markPendingChanges(QString());
        });

    connect(m_textAntialiasingCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QString());
        });

    // 权限按钮排：七个开关与一个称呼下拉，任一变化都进同一个待应用标记。
    for (QCheckBox* privilegeCheckBox : {
             m_privilegeUiAccessCheckBox,
             m_privilegeAdminCheckBox,
             m_privilegeDebugCheckBox,
             m_privilegeSystemCheckBox,
             m_privilegeR0CheckBox,
             m_privilegeHvmCheckBox,
             m_privilegeDdmaCheckBox})
    {
        if (privilegeCheckBox == nullptr)
        {
            continue;
        }
        connect(privilegeCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
            markPendingChanges(QString());
            });
    }
    if (m_hvmDisplayNameCombo != nullptr)
    {
        connect(m_hvmDisplayNameCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
            markPendingChanges(QString());
            });
    }

    connect(m_backgroundPathEdit, &QLineEdit::editingFinished, this, [this]() {
        markPendingChanges(QStringLiteral("背景路径编辑完成"));
        });

    connect(m_backgroundOpacitySlider, &QSlider::valueChanged, this, [this](const int value) {
        updateOpacityValueLabel(value);
        if (!m_isApplyingUiState)
        {
            markPendingChanges(QStringLiteral("背景透明度变化"));
        }
        });

    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QString());
        });

    connect(m_backgroundTranslucencyMaterialCombo, &QComboBox::currentIndexChanged, this, [this](const int /*itemIndex*/) {
        markPendingChanges(QString());
        });

    connect(m_backgroundBlurRadiusSlider, &QSlider::valueChanged, this, [this](const int value) {
        m_backgroundBlurRadiusValueLabel->setText(QStringLiteral("%1%").arg(value));
        if (!m_isApplyingUiState)
        {
            markPendingChanges(QStringLiteral("玻璃模糊半径变化"));
        }
        });

    connect(m_acrylicTintOpacitySlider, &QSlider::valueChanged, this, [this](const int value) {
        m_acrylicTintOpacityValueLabel->setText(QStringLiteral("%1%").arg(value));
        if (!m_isApplyingUiState)
        {
            markPendingChanges(QStringLiteral("磨砂着色不透明度变化"));
        }
        });

    connect(m_desktopTintOpacitySlider, &QSlider::valueChanged, this, [this](const int value) {
        m_desktopTintOpacityValueLabel->setText(QStringLiteral("%1%").arg(value));
        if (!m_isApplyingUiState)
        {
            markPendingChanges(QStringLiteral("直透着色不透明度变化"));
        }
        });

    connect(m_browseBackgroundButton, &QToolButton::clicked, this, [this]() {
        openBackgroundFileDialog();
        });

    connect(m_resetBackgroundButton, &QToolButton::clicked, this, [this]() {
        resetBackgroundPathToDefault();
        });

    connect(m_startupMaximizedCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时最大化开关切换"));
        });

    connect(m_startupTopMostCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动后默认最高级置顶开关切换"));
        });

    connect(m_startupAutoAdminCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时自动请求管理员权限开关切换"));
        });

    connect(m_startupAutoInstallR0DriverCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("启动时自动安装驱动开关切换"));
        });

    connect(m_preventMultipleInstancesCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("防止多开开关切换"));
        });

    connect(m_unlockerShellContextMenuCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("系统右键文件解锁器开关切换"));
        });

    connect(m_installTaskmgrHijackButton, &QPushButton::clicked, this, [this]() {
        launchTaskmgrHijackScript(true);
        });

    connect(m_uninstallTaskmgrHijackButton, &QPushButton::clicked, this, [this]() {
        launchTaskmgrHijackScript(false);
        });

    connect(m_smoothScrollingCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("全局平滑滚动开关切换"));
        });

    connect(m_sliderWheelAdjustCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("控件与标签页滚轮操作开关切换"));
        });

    connect(m_detailSchemeCombo, QOverload<int>::of(&QComboBox::activated), this, [this](const int) {
        markPendingChanges(QStringLiteral("详情页显示方案切换"));
        });

    connect(m_notificationCardsEnabledCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("通知卡片开关切换"));
        });
    connect(m_notificationMinimumLevelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知最低日志级别切换"));
        });
    connect(m_notificationLogDisplaySecondsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知日志展示秒数切换"));
        });
    connect(m_notificationMaximumVisibleLogCardsSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知同时显示日志条数切换"));
        });
    connect(m_notificationLogHeightLimitCheckBox, &QCheckBox::toggled, this, [this](const bool checked) {
        if (m_notificationLogMaximumLinesSpin != nullptr)
        {
            m_notificationLogMaximumLinesSpin->setEnabled(checked);
        }
        markPendingChanges(QStringLiteral("通知日志卡片高度限制切换"));
        });
    connect(m_notificationLogMaximumLinesSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知日志卡片最高文字行数切换"));
        });
    connect(m_notificationDisplayPlacementCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知显示位置切换"));
        });
    connect(m_notificationStackDirectionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("通知堆叠方向切换"));
        });

    connect(m_startupWindowScaleSpin, QOverload<int>::of(&QSpinBox::valueChanged), this, [this](int) {
        if (!m_isApplyingUiState)
        {
            markPendingChanges(QStringLiteral("启动窗口缩放变化"));
        }
        });

}

void SettingsDock::applySettings()
{
    saveAndEmitFromUi(QStringLiteral("点击应用按钮"));
}

void SettingsDock::loadSettingsFromJson()
{
    m_currentAppearanceSettings = ks::settings::loadAppearanceSettings();
    applySettingsToUi(m_currentAppearanceSettings);
    m_hasPendingChanges = false;
    updateApplyButtonState();
    emit appearanceSettingsChanged(m_currentAppearanceSettings);
}

void SettingsDock::applySettingsToUi(const ks::settings::AppearanceSettings& settings)
{
    m_isApplyingUiState = true;

    if (m_languageCombo != nullptr)
    {
        const int languageIndex = m_languageCombo->findData(settings.uiLanguage, Qt::UserRole, Qt::MatchFixedString);
        if (languageIndex >= 0)
        {
            m_languageCombo->setCurrentIndex(languageIndex);
        }
    }

    // selectedButton 作用：根据主题模式找到对应按钮并置为选中。
    QAbstractButton* selectedButton = m_themeButtonGroup->button(static_cast<int>(settings.themeMode));
    if (selectedButton != nullptr)
    {
        selectedButton->setChecked(true);
    }
    else if (m_followSystemButton != nullptr)
    {
        m_followSystemButton->setChecked(true);
    }

    if (m_fontCombo != nullptr)
    {
        // configuredFontFamily 用途：空值稳定映射到第 0 项“系统默认”。
        const QString configuredFontFamily = settings.fontFamily.trimmed();
        int fontIndex = m_fontCombo->findData(
            configuredFontFamily,
            Qt::UserRole,
            Qt::MatchFixedString);
        if (fontIndex < 0 && !configuredFontFamily.isEmpty())
        {
            // 配置字体暂未安装时保留 family，避免一次应用就静默覆盖用户配置。
            m_fontCombo->addItem(configuredFontFamily, configuredFontFamily);
            fontIndex = m_fontCombo->count() - 1;
            m_fontCombo->setItemData(fontIndex, QFont(configuredFontFamily), Qt::FontRole);
        }
        m_fontCombo->setCurrentIndex(fontIndex >= 0 ? fontIndex : 0);
    }

    m_pendingCustomThemeColor = settings.customThemeColor;
    updateThemeColorPreview();
    m_pendingCustomMainBackgroundColor = settings.customMainBackgroundColor;
    updateMainBackgroundColorPreview();

    m_backgroundPathEdit->setText(settings.backgroundImagePath);
    m_backgroundOpacitySlider->setValue(settings.backgroundOpacityPercent);
    if (m_backgroundTransparencyCheckBox != nullptr)
    {
        m_backgroundTransparencyCheckBox->setChecked(settings.backgroundTransparencyEnabled);
    }
    if (m_backgroundTranslucencyMaterialCombo != nullptr)
    {
        // 历史取值 mica/blur 已无对应项：它们都表示“磨砂”，
        // 因此回显到 acrylic，与材质决策里的迁移规则保持一致，
        // 否则 findData 返回 -1 会让旧用户被静默改成“自动”。
        QString materialKey = settings.backgroundTranslucencyMaterial.trimmed().toLower();
        if (materialKey == QStringLiteral("mica") || materialKey == QStringLiteral("blur"))
        {
            materialKey = QStringLiteral("acrylic");
        }
        const int materialIndex = m_backgroundTranslucencyMaterialCombo->findData(materialKey);
        m_backgroundTranslucencyMaterialCombo->setCurrentIndex(materialIndex >= 0 ? materialIndex : 0);
        m_backgroundTranslucencyMaterialCombo->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (m_backgroundBlurRadiusSlider != nullptr)
    {
        // 模糊半径作用于背景图自绘层，与窗口是否透明无关，因此不跟随透明开关禁用。
        m_backgroundBlurRadiusSlider->setValue(settings.backgroundBlurRadiusPercent);
    }
    if (m_acrylicTintOpacitySlider != nullptr)
    {
        m_acrylicTintOpacitySlider->setValue(settings.acrylicTintOpacityPercent);
        m_acrylicTintOpacitySlider->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (m_desktopTintOpacitySlider != nullptr)
    {
        m_desktopTintOpacitySlider->setValue(settings.desktopTintOpacityPercent);
        m_desktopTintOpacitySlider->setEnabled(settings.backgroundTransparencyEnabled);
    }
    if (m_textAntialiasingCheckBox != nullptr)
    {
        m_textAntialiasingCheckBox->setChecked(settings.textAntialiasingEnabled);
    }
    if (m_privilegeUiAccessCheckBox != nullptr)
    {
        m_privilegeUiAccessCheckBox->setChecked(settings.privilegeButtonUiAccessVisible);
    }
    if (m_privilegeAdminCheckBox != nullptr)
    {
        m_privilegeAdminCheckBox->setChecked(settings.privilegeButtonAdminVisible);
    }
    if (m_privilegeDebugCheckBox != nullptr)
    {
        m_privilegeDebugCheckBox->setChecked(settings.privilegeButtonDebugVisible);
    }
    if (m_privilegeSystemCheckBox != nullptr)
    {
        m_privilegeSystemCheckBox->setChecked(settings.privilegeButtonSystemVisible);
    }
    if (m_privilegeR0CheckBox != nullptr)
    {
        m_privilegeR0CheckBox->setChecked(settings.privilegeButtonR0Visible);
    }
    if (m_privilegeHvmCheckBox != nullptr)
    {
        m_privilegeHvmCheckBox->setChecked(settings.privilegeButtonHvmVisible);
    }
    if (m_privilegeDdmaCheckBox != nullptr)
    {
        m_privilegeDdmaCheckBox->setChecked(settings.privilegeButtonDdmaVisible);
    }
    if (m_hvmDisplayNameCombo != nullptr)
    {
        const int hvmNameIndex = m_hvmDisplayNameCombo->findData(
            static_cast<int>(settings.hvmDisplayName));
        m_hvmDisplayNameCombo->setCurrentIndex(hvmNameIndex >= 0 ? hvmNameIndex : 0);
    }

    if (m_startupMaximizedCheckBox != nullptr)
    {
        m_startupMaximizedCheckBox->setChecked(settings.launchMaximizedOnStartup);
    }

    if (m_startupTopMostCheckBox != nullptr)
    {
        m_startupTopMostCheckBox->setChecked(settings.startupTopMostEnabled);
    }

    if (m_startupAutoAdminCheckBox != nullptr)
    {
        m_startupAutoAdminCheckBox->setChecked(settings.autoRequestAdminOnStartup);
    }
    if (m_startupAutoInstallR0DriverCheckBox != nullptr)
    {
        m_startupAutoInstallR0DriverCheckBox->setChecked(settings.startupAutoInstallR0Driver);
    }
    if (m_preventMultipleInstancesCheckBox != nullptr)
    {
        m_preventMultipleInstancesCheckBox->setChecked(settings.preventMultipleInstances);
    }
    if (m_unlockerShellContextMenuCheckBox != nullptr)
    {
        m_unlockerShellContextMenuCheckBox->setChecked(settings.unlockerShellContextMenuEnabled);
    }
    if (m_suppressR0FeaturePromptsCheckBox != nullptr)
    {
        m_suppressR0FeaturePromptsCheckBox->setChecked(settings.suppressR0FeaturePrompts);
    }
    if (m_dumpAutoCheckCheckBox != nullptr)
    {
        m_dumpAutoCheckCheckBox->setChecked(settings.dumpAutoCheckEnabled);
    }
    if (m_dumpAutoCheckCheckBox != nullptr)
    {
        m_dumpAutoCheckCheckBox->setChecked(settings.dumpAutoCheckEnabled);
    }

    if (m_smoothScrollingCheckBox != nullptr)
    {
        m_smoothScrollingCheckBox->setChecked(settings.smoothScrollingEnabled);
    }
    if (m_sliderWheelAdjustCheckBox != nullptr)
    {
        m_sliderWheelAdjustCheckBox->setChecked(settings.sliderWheelAdjustEnabled);
    }

    if (m_notificationCardsEnabledCheckBox != nullptr)
    {
        m_notificationCardsEnabledCheckBox->setChecked(settings.notificationCardsEnabled);
    }
    if (m_notificationMinimumLevelCombo != nullptr)
    {
        const int index = m_notificationMinimumLevelCombo->findData(settings.notificationMinimumLevel);
        m_notificationMinimumLevelCombo->setCurrentIndex(index >= 0 ? index : 2);
    }
    if (m_notificationLogDisplaySecondsSpin != nullptr)
    {
        m_notificationLogDisplaySecondsSpin->setValue(settings.notificationLogDisplaySeconds);
    }
    if (m_notificationMaximumVisibleLogCardsSpin != nullptr)
    {
        m_notificationMaximumVisibleLogCardsSpin->setValue(settings.notificationMaximumVisibleLogCards);
    }
    if (m_notificationLogHeightLimitCheckBox != nullptr)
    {
        m_notificationLogHeightLimitCheckBox->setChecked(settings.notificationLogHeightLimitEnabled);
    }
    if (m_notificationLogMaximumLinesSpin != nullptr)
    {
        m_notificationLogMaximumLinesSpin->setValue(settings.notificationLogMaximumLines);
        m_notificationLogMaximumLinesSpin->setEnabled(
            m_notificationLogHeightLimitCheckBox != nullptr
            && m_notificationLogHeightLimitCheckBox->isChecked());
    }
    if (m_notificationDisplayPlacementCombo != nullptr)
    {
        const int index = m_notificationDisplayPlacementCombo->findData(
            static_cast<int>(settings.notificationDisplayPlacement));
        m_notificationDisplayPlacementCombo->setCurrentIndex(index >= 0 ? index : 0);
    }
    if (m_notificationStackDirectionCombo != nullptr)
    {
        const int index = m_notificationStackDirectionCombo->findData(
            static_cast<int>(settings.notificationStackDirection));
        m_notificationStackDirectionCombo->setCurrentIndex(index >= 0 ? index : 0);
    }

    if (m_startupWindowScaleSpin != nullptr)
    {
        m_startupWindowScaleSpin->setValue(
            windowScalePercentFromFactor(settings.startupWindowScaleFactor));
    }

    if (m_detailSchemeCombo != nullptr)
    {
        const int detailIndex = m_detailSchemeCombo->findData(static_cast<int>(settings.detailDisplayScheme));
        m_detailSchemeCombo->setCurrentIndex(detailIndex >= 0 ? detailIndex : 0);
    }

    // 在线扫描 API Key 回填：
    // - 设置页只显示用户保存过的 Key；
    // - PasswordEchoOnEdit 会在未编辑时隐藏文本，避免旁观泄露。
    if (m_virusTotalApiKeyEdit != nullptr)
    {
        m_virusTotalApiKeyEdit->setText(settings.virusTotalApiKey);
    }
    if (m_threatBookApiKeyEdit != nullptr)
    {
        m_threatBookApiKeyEdit->setText(settings.threatBookApiKey);
    }

    updateOpacityValueLabel(settings.backgroundOpacityPercent);
    // 显式回填三个玻璃观感标签：setValue 在值未变化时不发 valueChanged，
    // 只靠信号会让“配置值恰好等于滑块初值”的情况停留在构造时的占位文本。
    if (m_backgroundBlurRadiusValueLabel != nullptr)
    {
        m_backgroundBlurRadiusValueLabel->setText(
            QStringLiteral("%1%").arg(settings.backgroundBlurRadiusPercent));
    }
    if (m_acrylicTintOpacityValueLabel != nullptr)
    {
        m_acrylicTintOpacityValueLabel->setText(
            QStringLiteral("%1%").arg(settings.acrylicTintOpacityPercent));
    }
    if (m_desktopTintOpacityValueLabel != nullptr)
    {
        m_desktopTintOpacityValueLabel->setText(
            QStringLiteral("%1%").arg(settings.desktopTintOpacityPercent));
    }
    updateThemeButtonStyle();

    m_isApplyingUiState = false;
    m_hasPendingChanges = false;
    updateApplyButtonState();
}

ks::settings::AppearanceSettings SettingsDock::collectSettingsFromUi() const
{
    ks::settings::AppearanceSettings collectedSettings = m_currentAppearanceSettings;

    // 危险确认策略由深层功能菜单维护；保存其它设置时保留磁盘中的最新值。
    collectedSettings.suppressDangerousActionConfirmations =
        ks::settings::dangerousActionConfirmationsSuppressed();

    collectedSettings.uiLanguage = (m_languageCombo != nullptr && m_languageCombo->currentIndex() >= 0)
        ? m_languageCombo->currentData().toString()
        : m_currentAppearanceSettings.uiLanguage;
    collectedSettings.customThemeColor = m_pendingCustomThemeColor;
    collectedSettings.customMainBackgroundColor = m_pendingCustomMainBackgroundColor;

    // checkedThemeId 作用：读取当前选中的主题按钮 ID。
    const int checkedThemeId = m_themeButtonGroup->checkedId();
    if (checkedThemeId == static_cast<int>(ks::settings::ThemeMode::Light))
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::Light;
    }
    else if (checkedThemeId == static_cast<int>(ks::settings::ThemeMode::Dark))
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::Dark;
    }
    else
    {
        collectedSettings.themeMode = ks::settings::ThemeMode::FollowSystem;
    }

    const QString rawPathText = m_backgroundPathEdit->text().trimmed();
    collectedSettings.backgroundImagePath = rawPathText.isEmpty()
        ? QStringLiteral("Style/ksword_background.png")
        : rawPathText;

    collectedSettings.backgroundOpacityPercent = m_backgroundOpacitySlider->value();
    collectedSettings.backgroundTransparencyEnabled = m_backgroundTransparencyCheckBox != nullptr
        && m_backgroundTransparencyCheckBox->isChecked();
    collectedSettings.backgroundTranslucencyMaterial = m_backgroundTranslucencyMaterialCombo != nullptr
        ? m_backgroundTranslucencyMaterialCombo->currentData().toString()
        : m_currentAppearanceSettings.backgroundTranslucencyMaterial;
    collectedSettings.backgroundBlurRadiusPercent = m_backgroundBlurRadiusSlider != nullptr
        ? m_backgroundBlurRadiusSlider->value()
        : m_currentAppearanceSettings.backgroundBlurRadiusPercent;
    collectedSettings.acrylicTintOpacityPercent = m_acrylicTintOpacitySlider != nullptr
        ? m_acrylicTintOpacitySlider->value()
        : m_currentAppearanceSettings.acrylicTintOpacityPercent;
    collectedSettings.desktopTintOpacityPercent = m_desktopTintOpacitySlider != nullptr
        ? m_desktopTintOpacitySlider->value()
        : m_currentAppearanceSettings.desktopTintOpacityPercent;
    // 启动页字段已不再由设置页编辑；保存其它设置时保留当前内存值，避免意外覆盖旧配置。
    collectedSettings.startupDefaultTabKey = m_currentAppearanceSettings.startupDefaultTabKey;
    collectedSettings.launchMaximizedOnStartup =
        (m_startupMaximizedCheckBox != nullptr) && m_startupMaximizedCheckBox->isChecked();
    collectedSettings.startupTopMostEnabled =
        (m_startupTopMostCheckBox != nullptr) && m_startupTopMostCheckBox->isChecked();
    collectedSettings.autoRequestAdminOnStartup =
        (m_startupAutoAdminCheckBox != nullptr) && m_startupAutoAdminCheckBox->isChecked();
    collectedSettings.startupAutoInstallR0Driver =
        (m_startupAutoInstallR0DriverCheckBox != nullptr)
        && m_startupAutoInstallR0DriverCheckBox->isChecked();
    collectedSettings.preventMultipleInstances =
        (m_preventMultipleInstancesCheckBox == nullptr) || m_preventMultipleInstancesCheckBox->isChecked();
    collectedSettings.startupWindowScaleFactor = parseWindowScaleFactorFromUi();
    // 该开关来自启动前弹窗，不在设置页编辑；这里保留内存值，避免保存时被覆盖。
    collectedSettings.startupScaleRecommendPromptDisabled =
        m_currentAppearanceSettings.startupScaleRecommendPromptDisabled;
    collectedSettings.unlockerShellContextMenuEnabled =
        (m_unlockerShellContextMenuCheckBox != nullptr) && m_unlockerShellContextMenuCheckBox->isChecked();
    collectedSettings.suppressR0FeaturePrompts =
        (m_suppressR0FeaturePromptsCheckBox != nullptr)
        && m_suppressR0FeaturePromptsCheckBox->isChecked();
    collectedSettings.dumpAutoCheckEnabled =
        (m_dumpAutoCheckCheckBox == nullptr) || m_dumpAutoCheckCheckBox->isChecked();
    // 已提示转储的记录由启动检查流程写入，设置页只透传，避免保存设置时被清空。
    collectedSettings.dumpAutoCheckPromptedPath =
        m_currentAppearanceSettings.dumpAutoCheckPromptedPath;
    collectedSettings.dumpAutoCheckPromptedTimeMsec =
        m_currentAppearanceSettings.dumpAutoCheckPromptedTimeMsec;
    collectedSettings.smoothScrollingEnabled =
        (m_smoothScrollingCheckBox != nullptr) && m_smoothScrollingCheckBox->isChecked();
    collectedSettings.sliderWheelAdjustEnabled =
        (m_sliderWheelAdjustCheckBox != nullptr) && m_sliderWheelAdjustCheckBox->isChecked();
    const int detailSchemeId = m_detailSchemeCombo != nullptr
        ? m_detailSchemeCombo->currentData().toInt()
        : static_cast<int>(m_currentAppearanceSettings.detailDisplayScheme);
    if (detailSchemeId >= static_cast<int>(ks::settings::DetailDisplayScheme::BottomCollapsed) &&
        detailSchemeId <= static_cast<int>(ks::settings::DetailDisplayScheme::Floating))
    {
        collectedSettings.detailDisplayScheme =
            static_cast<ks::settings::DetailDisplayScheme>(detailSchemeId);
    }
    collectedSettings.fontFamily = m_fontCombo != nullptr
        ? m_fontCombo->currentData(Qt::UserRole).toString().trimmed()
        : m_currentAppearanceSettings.fontFamily;
    collectedSettings.textAntialiasingEnabled =
        (m_textAntialiasingCheckBox != nullptr) && m_textAntialiasingCheckBox->isChecked();
    /*
     * 权限按钮可见性：控件缺失时保留当前值，而不是当作"没勾选"。
     *
     * 其余复选框用的是 `(ptr != nullptr) && isChecked()`，控件不在就得到 false。
     * 那个写法在这里会变成"设置页没构造好 = 把整排按钮藏掉"，是个用界面故障
     * 去改用户配置的行为。默认全显示，所以缺省必须回到当前值。
     */
    collectedSettings.privilegeButtonUiAccessVisible =
        (m_privilegeUiAccessCheckBox != nullptr)
            ? m_privilegeUiAccessCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonUiAccessVisible;
    collectedSettings.privilegeButtonAdminVisible =
        (m_privilegeAdminCheckBox != nullptr)
            ? m_privilegeAdminCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonAdminVisible;
    collectedSettings.privilegeButtonDebugVisible =
        (m_privilegeDebugCheckBox != nullptr)
            ? m_privilegeDebugCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonDebugVisible;
    collectedSettings.privilegeButtonSystemVisible =
        (m_privilegeSystemCheckBox != nullptr)
            ? m_privilegeSystemCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonSystemVisible;
    collectedSettings.privilegeButtonR0Visible =
        (m_privilegeR0CheckBox != nullptr)
            ? m_privilegeR0CheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonR0Visible;
    collectedSettings.privilegeButtonHvmVisible =
        (m_privilegeHvmCheckBox != nullptr)
            ? m_privilegeHvmCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonHvmVisible;
    collectedSettings.privilegeButtonDdmaVisible =
        (m_privilegeDdmaCheckBox != nullptr)
            ? m_privilegeDdmaCheckBox->isChecked()
            : m_currentAppearanceSettings.privilegeButtonDdmaVisible;
    collectedSettings.hvmDisplayName =
        (m_hvmDisplayNameCombo != nullptr)
            ? static_cast<ks::settings::HvmDisplayName>(
                  m_hvmDisplayNameCombo->currentData().toInt())
            : m_currentAppearanceSettings.hvmDisplayName;
    collectedSettings.notificationCardsEnabled =
        (m_notificationCardsEnabledCheckBox != nullptr) && m_notificationCardsEnabledCheckBox->isChecked();
    collectedSettings.notificationMinimumLevel =
        m_notificationMinimumLevelCombo != nullptr
        ? m_notificationMinimumLevelCombo->currentData().toInt()
        : m_currentAppearanceSettings.notificationMinimumLevel;
    collectedSettings.notificationLogDisplaySeconds =
        m_notificationLogDisplaySecondsSpin != nullptr
        ? m_notificationLogDisplaySecondsSpin->value()
        : m_currentAppearanceSettings.notificationLogDisplaySeconds;
    collectedSettings.notificationMaximumVisibleLogCards =
        m_notificationMaximumVisibleLogCardsSpin != nullptr
        ? m_notificationMaximumVisibleLogCardsSpin->value()
        : m_currentAppearanceSettings.notificationMaximumVisibleLogCards;
    collectedSettings.notificationLogHeightLimitEnabled =
        (m_notificationLogHeightLimitCheckBox != nullptr)
        && m_notificationLogHeightLimitCheckBox->isChecked();
    collectedSettings.notificationLogMaximumLines =
        m_notificationLogMaximumLinesSpin != nullptr
        ? m_notificationLogMaximumLinesSpin->value()
        : m_currentAppearanceSettings.notificationLogMaximumLines;
    collectedSettings.notificationDisplayPlacement =
        m_notificationDisplayPlacementCombo != nullptr
        ? static_cast<ks::settings::NotificationDisplayPlacement>(m_notificationDisplayPlacementCombo->currentData().toInt())
        : m_currentAppearanceSettings.notificationDisplayPlacement;
    collectedSettings.notificationStackDirection =
        m_notificationStackDirectionCombo != nullptr
        ? static_cast<ks::settings::NotificationStackDirection>(m_notificationStackDirectionCombo->currentData().toInt())
        : m_currentAppearanceSettings.notificationStackDirection;
    // 在线扫描 API Key：
    // - 从在线扫描标签页读取；
    // - 保存时统一 trim，OnlineScan 运行时只读取配置，不硬编码密钥。
    collectedSettings.virusTotalApiKey = (m_virusTotalApiKeyEdit != nullptr)
        ? m_virusTotalApiKeyEdit->text().trimmed()
        : m_currentAppearanceSettings.virusTotalApiKey;
    collectedSettings.threatBookApiKey = (m_threatBookApiKeyEdit != nullptr)
        ? m_threatBookApiKeyEdit->text().trimmed()
        : m_currentAppearanceSettings.threatBookApiKey;

    return collectedSettings;
}

void SettingsDock::markPendingChanges(const QString& triggerReason)
{
    Q_UNUSED(triggerReason);
    if (m_isApplyingUiState)
    {
        return;
    }

    m_hasPendingChanges = true;
    updateApplyButtonState();
}

void SettingsDock::updateSystemDefaultFontItemText()
{
    if (m_fontCombo == nullptr || m_fontCombo->count() <= 0)
    {
        return;
    }

    // systemDefaultData 用途：验证第 0 项仍是稳定的空 family 语义。
    const QString systemDefaultData =
        m_fontCombo->itemData(0, Qt::UserRole).toString();
    if (!systemDefaultData.isEmpty())
    {
        return;
    }
    m_fontCombo->setItemText(
        0,
        ks::i18n::text(
            QStringLiteral("settings.font.system_default"),
            QStringLiteral("系统默认")));
}

void SettingsDock::updateApplyButtonState()
{
    emit pendingChangesChanged(m_hasPendingChanges);

    // 在线扫描页保存按钮与外观页“应用”按钮共用同一个待保存状态，
    // 这样用户在任意设置页点击保存都会落盘完整配置。
    if (m_saveOnlineScanKeysButton != nullptr)
    {
        m_saveOnlineScanKeysButton->setEnabled(m_hasPendingChanges);
        m_saveOnlineScanKeysButton->setToolTip(
            m_hasPendingChanges
            ? ks::i18n::text(QStringLiteral("settings.online.save.pending"), QStringLiteral("保存当前 API Key 与其它待提交设置"))
            : ks::i18n::text(QStringLiteral("settings.online.save.clean"), QStringLiteral("当前 API Key 已保存，无待提交改动")));
    }
}

void SettingsDock::updateThemeColorPreview()
{
    updateThemeComponentPreview();
    if (m_chooseThemeColorButton == nullptr)
    {
        return;
    }

    const QColor previewColor = m_pendingCustomThemeColor.isEmpty()
        ? KswordTheme::DefaultPrimaryAccentColor()
        : QColor(m_pendingCustomThemeColor);
    const QString colorText = previewColor.name(QColor::HexRgb).toUpper();
    if (m_chooseThemeColorButton != nullptr)
    {
        QPixmap swatch(16, 16); // 预览色块使用用户待应用颜色，按钮正文继续使用当前主题文字色。
        swatch.fill(previewColor);
        m_chooseThemeColorButton->setIcon(QIcon(swatch));
        m_chooseThemeColorButton->setText(colorText);
    }

    if (m_resetThemeColorButton != nullptr)
    {
        m_resetThemeColorButton->setEnabled(!m_pendingCustomThemeColor.isEmpty());
    }
}

void SettingsDock::updateThemeComponentPreview(const QString& accentOverride,
    const QString& backgroundOverride)
{
    if (m_themeComponentPreview == nullptr)
    {
        return;
    }
    // null覆盖值表示未提供临时颜色；空但非null仍可明确预览默认配色。
    m_themeComponentPreview->setPreview(selectedThemeUsesDarkBackground(m_themeButtonGroup),
        accentOverride.isNull() ? m_pendingCustomThemeColor : accentOverride,
        backgroundOverride.isNull() ? m_pendingCustomMainBackgroundColor : backgroundOverride);
}

void SettingsDock::chooseCustomThemeColor()
{
    const QMessageBox::StandardButton warningResult = QMessageBox::warning(
        this,
        ks::i18n::text(
            QStringLiteral("settings.theme.color.warning.title"),
            QStringLiteral("自定义主题色提示")),
        ks::i18n::text(
            QStringLiteral("settings.theme.color.warning.message"),
            QStringLiteral("当前界面所有颜色均基于偏移量设计，便于修改主题色；但尚未覆盖测试所有颜色组合。若选择过于极端的颜色，部分界面仍可能无法正常显示。是否继续？")),
        QMessageBox::Ok | QMessageBox::Cancel,
        QMessageBox::Cancel);
    if (warningResult != QMessageBox::Ok)
    {
        return;
    }

    const QColor initialColor = m_pendingCustomThemeColor.isEmpty()
        ? KswordTheme::DefaultPrimaryAccentColor()
        : QColor(m_pendingCustomThemeColor);
    // 非原生选色器保证拖动时发出currentColorChanged，只临时更新预览框。
    QColorDialog colorDialog(initialColor, this);
    colorDialog.setWindowTitle(ks::i18n::text(
            QStringLiteral("settings.theme.color.dialog.title"),
            QStringLiteral("选择主题色")));
    colorDialog.setOptions(QColorDialog::ShowAlphaChannel | QColorDialog::DontUseNativeDialog);
    connect(&colorDialog, &QColorDialog::currentColorChanged, this, [this](const QColor& color) {
        if (color.isValid())
        {
            updateThemeComponentPreview(color.name(QColor::HexRgb));
        }
    });
    if (colorDialog.exec() != QDialog::Accepted)
    {
        updateThemeComponentPreview();
        return;
    }

    const QColor selectedColor = colorDialog.currentColor(); // 接受后才写入待应用配置。
    if (!selectedColor.isValid())
    {
        updateThemeComponentPreview();
        return;
    }
    m_pendingCustomThemeColor = selectedColor.name(QColor::HexRgb).toUpper();
    updateThemeColorPreview();
    markPendingChanges(QStringLiteral("custom theme color selected"));
}

void SettingsDock::resetThemeColorToDefault()
{
    if (m_pendingCustomThemeColor.isEmpty())
    {
        return;
    }

    m_pendingCustomThemeColor.clear();
    updateThemeColorPreview();
    markPendingChanges(QStringLiteral("custom theme color restored"));
}

void SettingsDock::updateMainBackgroundColorPreview()
{
    updateThemeComponentPreview();
    if (m_chooseMainBackgroundColorButton == nullptr)
    {
        return;
    }

    const QColor previewColor = m_pendingCustomMainBackgroundColor.isEmpty()
        ? KswordTheme::DefaultMainBackgroundColor(
            selectedThemeUsesDarkBackground(m_themeButtonGroup))
        : QColor(m_pendingCustomMainBackgroundColor);
    const QString colorText = previewColor.name(QColor::HexRgb).toUpper();
    if (m_chooseMainBackgroundColorButton != nullptr)
    {
        QPixmap swatch(16, 16); // 主背景色与主题强调色独立预览及保存。
        swatch.fill(previewColor);
        m_chooseMainBackgroundColorButton->setIcon(QIcon(swatch));
        m_chooseMainBackgroundColorButton->setText(colorText);
    }

    if (m_resetMainBackgroundColorButton != nullptr)
    {
        m_resetMainBackgroundColorButton->setEnabled(
            !m_pendingCustomMainBackgroundColor.isEmpty());
    }
}

void SettingsDock::chooseCustomMainBackgroundColor()
{
    const QColor initialColor = m_pendingCustomMainBackgroundColor.isEmpty()
        ? KswordTheme::DefaultMainBackgroundColor(
            selectedThemeUsesDarkBackground(m_themeButtonGroup))
        : QColor(m_pendingCustomMainBackgroundColor);
    QColorDialog colorDialog(initialColor, this); // 与主体色共用实时预览、取消还原流程。
    colorDialog.setWindowTitle(ks::i18n::text(
            QStringLiteral("settings.background.color.dialog.title"),
            QStringLiteral("选择主背景色")));
    colorDialog.setOption(QColorDialog::DontUseNativeDialog);
    connect(&colorDialog, &QColorDialog::currentColorChanged, this, [this](const QColor& color) {
        if (color.isValid())
        {
            updateThemeComponentPreview(QString(), color.name(QColor::HexRgb));
        }
    });
    if (colorDialog.exec() != QDialog::Accepted)
    {
        updateThemeComponentPreview();
        return;
    }

    const QColor selectedColor = colorDialog.currentColor(); // 接受后才写入待应用背景。
    if (!selectedColor.isValid())
    {
        updateThemeComponentPreview();
        return;
    }
    m_pendingCustomMainBackgroundColor = selectedColor.name(QColor::HexRgb).toUpper();
    updateMainBackgroundColorPreview();
    markPendingChanges(QStringLiteral("custom main background color selected"));
}

void SettingsDock::resetMainBackgroundColorToDefault()
{
    if (m_pendingCustomMainBackgroundColor.isEmpty())
    {
        return;
    }

    m_pendingCustomMainBackgroundColor.clear();
    updateMainBackgroundColorPreview();
    markPendingChanges(QStringLiteral("custom main background color restored"));
}

void SettingsDock::saveAndEmitFromUi(const QString& triggerReason)
{
    if (m_isApplyingUiState)
    {
        return;
    }

    // settingsEvent 作用：本次“设置变更”调用链统一日志事件对象。
    kLogEvent settingsEvent;
    const ks::settings::AppearanceSettings nextSettings = collectSettingsFromUi();
    const bool unlockerShellContextMenuChanged =
        nextSettings.unlockerShellContextMenuEnabled != m_currentAppearanceSettings.unlockerShellContextMenuEnabled;
    const bool sameScaleFactor =
        std::fabs(nextSettings.startupWindowScaleFactor - m_currentAppearanceSettings.startupWindowScaleFactor) < 0.0001;

    if (nextSettings.themeMode == m_currentAppearanceSettings.themeMode
        && nextSettings.customThemeColor.compare(m_currentAppearanceSettings.customThemeColor, Qt::CaseInsensitive) == 0
        && nextSettings.customMainBackgroundColor.compare(
            m_currentAppearanceSettings.customMainBackgroundColor,
            Qt::CaseInsensitive) == 0
        && nextSettings.uiLanguage.compare(m_currentAppearanceSettings.uiLanguage, Qt::CaseInsensitive) == 0
        && nextSettings.backgroundImagePath == m_currentAppearanceSettings.backgroundImagePath
        && nextSettings.backgroundOpacityPercent == m_currentAppearanceSettings.backgroundOpacityPercent
        && nextSettings.backgroundTransparencyEnabled == m_currentAppearanceSettings.backgroundTransparencyEnabled
        && nextSettings.backgroundTranslucencyMaterial == m_currentAppearanceSettings.backgroundTranslucencyMaterial
        && nextSettings.backgroundBlurRadiusPercent == m_currentAppearanceSettings.backgroundBlurRadiusPercent
        && nextSettings.acrylicTintOpacityPercent == m_currentAppearanceSettings.acrylicTintOpacityPercent
        && nextSettings.desktopTintOpacityPercent == m_currentAppearanceSettings.desktopTintOpacityPercent
        && nextSettings.launchMaximizedOnStartup == m_currentAppearanceSettings.launchMaximizedOnStartup
        && nextSettings.startupTopMostEnabled == m_currentAppearanceSettings.startupTopMostEnabled
        && nextSettings.autoRequestAdminOnStartup == m_currentAppearanceSettings.autoRequestAdminOnStartup
        && nextSettings.startupAutoInstallR0Driver == m_currentAppearanceSettings.startupAutoInstallR0Driver
        && nextSettings.preventMultipleInstances == m_currentAppearanceSettings.preventMultipleInstances
        && sameScaleFactor
        && nextSettings.startupScaleRecommendPromptDisabled == m_currentAppearanceSettings.startupScaleRecommendPromptDisabled
        && nextSettings.unlockerShellContextMenuEnabled == m_currentAppearanceSettings.unlockerShellContextMenuEnabled
        && nextSettings.suppressR0FeaturePrompts == m_currentAppearanceSettings.suppressR0FeaturePrompts
        && nextSettings.smoothScrollingEnabled == m_currentAppearanceSettings.smoothScrollingEnabled
        && nextSettings.sliderWheelAdjustEnabled == m_currentAppearanceSettings.sliderWheelAdjustEnabled
        && nextSettings.detailDisplayScheme == m_currentAppearanceSettings.detailDisplayScheme
        && nextSettings.fontFamily.compare(m_currentAppearanceSettings.fontFamily, Qt::CaseInsensitive) == 0
        && nextSettings.textAntialiasingEnabled == m_currentAppearanceSettings.textAntialiasingEnabled
        && nextSettings.privilegeButtonUiAccessVisible == m_currentAppearanceSettings.privilegeButtonUiAccessVisible
        && nextSettings.privilegeButtonAdminVisible == m_currentAppearanceSettings.privilegeButtonAdminVisible
        && nextSettings.privilegeButtonDebugVisible == m_currentAppearanceSettings.privilegeButtonDebugVisible
        && nextSettings.privilegeButtonSystemVisible == m_currentAppearanceSettings.privilegeButtonSystemVisible
        && nextSettings.privilegeButtonR0Visible == m_currentAppearanceSettings.privilegeButtonR0Visible
        && nextSettings.privilegeButtonHvmVisible == m_currentAppearanceSettings.privilegeButtonHvmVisible
        && nextSettings.privilegeButtonDdmaVisible == m_currentAppearanceSettings.privilegeButtonDdmaVisible
        && nextSettings.hvmDisplayName == m_currentAppearanceSettings.hvmDisplayName
        && nextSettings.notificationCardsEnabled == m_currentAppearanceSettings.notificationCardsEnabled
        && nextSettings.notificationMinimumLevel == m_currentAppearanceSettings.notificationMinimumLevel
        && nextSettings.notificationLogDisplaySeconds == m_currentAppearanceSettings.notificationLogDisplaySeconds
        && nextSettings.notificationMaximumVisibleLogCards == m_currentAppearanceSettings.notificationMaximumVisibleLogCards
        && nextSettings.notificationLogHeightLimitEnabled == m_currentAppearanceSettings.notificationLogHeightLimitEnabled
        && nextSettings.notificationLogMaximumLines == m_currentAppearanceSettings.notificationLogMaximumLines
        && nextSettings.notificationDisplayPlacement == m_currentAppearanceSettings.notificationDisplayPlacement
        && nextSettings.notificationStackDirection == m_currentAppearanceSettings.notificationStackDirection
        && nextSettings.virusTotalApiKey == m_currentAppearanceSettings.virusTotalApiKey
        && nextSettings.threatBookApiKey == m_currentAppearanceSettings.threatBookApiKey)
    {
        m_hasPendingChanges = false;
        updateApplyButtonState();
        return;
    }

    QString saveErrorText;
    const bool saveOk = ks::settings::saveAppearanceSettings(nextSettings, &saveErrorText);
    if (!saveOk)
    {
        err << settingsEvent
            << "[SettingsDock] 保存外观设置失败，触发来源="
            << triggerReason.toStdString()
            << "，错误="
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    if (unlockerShellContextMenuChanged)
    {
        if (nextSettings.unlockerShellContextMenuEnabled)
        {
            const std::wstring executablePath = queryCurrentExecutablePath();
            const bool registerOk = registerUnlockerContextMenuNow(executablePath);
            if (!registerOk)
            {
                warn << settingsEvent
                    << "[SettingsDock] 系统右键文件解锁器菜单即时注册失败，将保留配置并在下次启动重试。"
                    << eol;
            }
            else
            {
                info << settingsEvent
                    << "[SettingsDock] 系统右键文件解锁器菜单已即时注册。"
                    << eol;
            }
        }
        else
        {
            // 取消勾选必须立即移除 HKCU\Software\Classes 下的所有 shell 菜单（含旧版遗留项），
            // 不能只写配置等待下次启动，否则用户会看到右键菜单仍然残留。
            unregisterUnlockerContextMenuNow();
            info << settingsEvent
                << "[SettingsDock] 系统右键文件解锁器菜单已即时移除。"
                << eol;
        }
    }

    const bool languageChanged =
        nextSettings.uiLanguage.compare(m_currentAppearanceSettings.uiLanguage, Qt::CaseInsensitive) != 0;
    m_currentAppearanceSettings = nextSettings;
    if (languageChanged)
    {
        QString languageErrorText;
        if (!ks::i18n::LanguageManager::instance().setLanguage(
            m_currentAppearanceSettings.uiLanguage,
            &languageErrorText))
        {
            warn << settingsEvent
                << "[SettingsDock] Failed to apply language pack: "
                << languageErrorText
                << eol;
        }
    }
    m_isApplyingUiState = true;
    if (m_startupWindowScaleSpin != nullptr)
    {
        m_startupWindowScaleSpin->setValue(
            windowScalePercentFromFactor(m_currentAppearanceSettings.startupWindowScaleFactor));
    }
    if (m_virusTotalApiKeyEdit != nullptr)
    {
        m_virusTotalApiKeyEdit->setText(m_currentAppearanceSettings.virusTotalApiKey);
    }
    if (m_threatBookApiKeyEdit != nullptr)
    {
        m_threatBookApiKeyEdit->setText(m_currentAppearanceSettings.threatBookApiKey);
    }
    m_isApplyingUiState = false;
    m_hasPendingChanges = false;
    updateApplyButtonState();

    info << settingsEvent
        << "[SettingsDock] 外观设置已保存，触发来源="
        << triggerReason.toStdString()
        << "，主题模式="
        << ks::settings::themeModeToJsonText(m_currentAppearanceSettings.themeMode).toStdString()
        << ", customThemeColor="
        << (m_currentAppearanceSettings.customThemeColor.isEmpty()
            ? "default"
            : m_currentAppearanceSettings.customThemeColor.toStdString())
        << ", customMainBackgroundColor="
        << (m_currentAppearanceSettings.customMainBackgroundColor.isEmpty()
            ? "default"
            : m_currentAppearanceSettings.customMainBackgroundColor.toStdString())
        << "，界面语言="
        << m_currentAppearanceSettings.uiLanguage.toStdString()
        << "，背景路径="
        << m_currentAppearanceSettings.backgroundImagePath.toStdString()
        << "，透明度="
        << m_currentAppearanceSettings.backgroundOpacityPercent
        << "%，启动时最大化="
        << (m_currentAppearanceSettings.launchMaximizedOnStartup ? "true" : "false")
        << "，启动后默认最高级置顶="
        << (m_currentAppearanceSettings.startupTopMostEnabled ? "true" : "false")
        << "，启动时自动请求管理员权限="
        << (m_currentAppearanceSettings.autoRequestAdminOnStartup ? "true" : "false")
        << "，启动时自动安装驱动="
        << (m_currentAppearanceSettings.startupAutoInstallR0Driver ? "true" : "false")
        << "，防止多开="
        << (m_currentAppearanceSettings.preventMultipleInstances ? "true" : "false")
        << "，启动窗口缩放因子="
        << m_currentAppearanceSettings.startupWindowScaleFactor
        << "，小屏缩放提示不再弹出="
        << (m_currentAppearanceSettings.startupScaleRecommendPromptDisabled ? "true" : "false")
        << "，系统右键文件解锁器菜单="
        << (m_currentAppearanceSettings.unlockerShellContextMenuEnabled ? "true" : "false")
        << "，全局平滑滚动="
        << (m_currentAppearanceSettings.smoothScrollingEnabled ? "true" : "false")
        << "，滚轮调整滑块="
        << (m_currentAppearanceSettings.sliderWheelAdjustEnabled ? "true" : "false")
        << "，详情页显示方案="
        << ks::settings::detailDisplaySchemeToJsonText(
            m_currentAppearanceSettings.detailDisplayScheme).toStdString()
        << "，VirusTotal API Key已配置="
        << (!m_currentAppearanceSettings.virusTotalApiKey.trimmed().isEmpty() ? "true" : "false")
        << "，ThreatBook API Key已配置="
        << (!m_currentAppearanceSettings.threatBookApiKey.trimmed().isEmpty() ? "true" : "false")
        << eol;

    emit appearanceSettingsChanged(m_currentAppearanceSettings);

    // appearanceSettingsChanged 是直连信号，返回时全局主题已经切换完成。
    // SurfaceMuted/PrimaryBlueSubtle 在 palette 里没有等价物，只能在这里重取快照重下发，
    // 否则这排主题按钮会停在切换前的旧配色上。
    updateThemeButtonStyle();

    QMessageBox::information(
        this,
        ks::i18n::text(
            QStringLiteral("settings.apply.success.title"),
            QStringLiteral("应用")),
        ks::i18n::text(
            QStringLiteral("settings.apply.success.message"),
            QStringLiteral("当前设置已应用，无待提交改动")));
}

void SettingsDock::updateThemeButtonStyle()
{
    // 主题选择以纯色强调当前模式，保留按钮组 checked 状态及原尺寸。
    const QString normalStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
        + QStringLiteral("QToolButton{border-radius:2px;}");
    const QString checkedStyle = ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Accent)
        + QStringLiteral("QToolButton{border-radius:2px;}");

    const QList<QAbstractButton*> themeButtons = m_themeButtonGroup->buttons();
    for (QAbstractButton* themeButton : themeButtons)
    {
        QToolButton* themedToolButton = qobject_cast<QToolButton*>(themeButton);
        if (themedToolButton == nullptr)
        {
            continue;
        }
        themedToolButton->setStyleSheet(themedToolButton->isChecked() ? checkedStyle : normalStyle);
    }
}

void SettingsDock::updateOpacityValueLabel(const int opacityPercent)
{
    m_backgroundOpacityValueLabel->setText(QStringLiteral("%1%").arg(opacityPercent));
}

void SettingsDock::launchTaskmgrHijackScript(const bool install)
{
    if (!ks::ui::isCurrentProcessElevated())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("任务管理器映像劫持"));
        return;
    }

    // scriptPath 作用：
    // - 固定从应用当前目录查找 TaskmgrHijack.ps1，匹配 Release 包复制脚本的部署方式；
    // - 不回退仓库路径，避免发布包和开发目录行为不一致。
    const QString applicationDirectoryPath = QCoreApplication::applicationDirPath();
    const QString scriptPath = QDir(applicationDirectoryPath).absoluteFilePath(QStringLiteral("TaskmgrHijack.ps1"));
    const QFileInfo scriptFileInfo(scriptPath);
    if (!scriptFileInfo.exists() || !scriptFileInfo.isFile())
    {
        const QString errorText = QStringLiteral("未找到任务管理器映像劫持脚本。\n\n路径：%1").arg(scriptPath);
        kLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] TaskmgrHijack.ps1 不存在，无法执行任务管理器映像劫持动作: "
            << scriptPath.toStdString()
            << eol;
        QMessageBox::warning(this, QStringLiteral("任务管理器映像劫持"), errorText);
        return;
    }

    // targetExePath 作用：
    // - 安装时显式传入当前 Ksword 主程序路径，避免 PowerShell 工作目录变化导致脚本找不到 Ksword5.1.exe；
    // - 卸载时不需要 TargetExe，保持脚本参数语义最小化。
    const QString targetExePath = QDir::toNativeSeparators(QCoreApplication::applicationFilePath());
    QStringList argumentList;
    argumentList
        << QStringLiteral("-NoProfile")
        << QStringLiteral("-ExecutionPolicy")
        << QStringLiteral("Bypass")
        << QStringLiteral("-File")
        << QDir::toNativeSeparators(scriptPath)
        << (install ? QStringLiteral("-Install") : QStringLiteral("-Uninstall"));
    if (install)
    {
        argumentList << QStringLiteral("-TargetExe") << targetExePath;
    }

    // powershellProcess 作用：
    // - 异步启动脚本，避免设置对话框阻塞；
    // - 脚本内部 Ensure-Administrator 会在需要时重新 RunAs，并在管理员窗口继续执行。
    QProcess* powershellProcess = new QProcess(this);
    powershellProcess->setProgram(QStringLiteral("powershell.exe"));
    powershellProcess->setArguments(argumentList);
    powershellProcess->setWorkingDirectory(applicationDirectoryPath);

    connect(powershellProcess, &QProcess::errorOccurred, this,
        [this, powershellProcess, install](const QProcess::ProcessError processError) {
            const QString errorText = powershellProcess->errorString();
            kLogEvent settingsEvent;
            err << settingsEvent
                << "[SettingsDock] 启动 TaskmgrHijack.ps1 失败, action="
                << (install ? "install" : "uninstall")
                << ", processError="
                << static_cast<int>(processError)
                << ", error="
                << errorText.toStdString()
                << eol;
            QMessageBox::warning(
                this,
                QStringLiteral("任务管理器映像劫持"),
                QStringLiteral("启动 PowerShell 脚本失败。\n\n%1").arg(errorText));
        });
    connect(powershellProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished), this,
        [powershellProcess, install](const int exitCode, const QProcess::ExitStatus exitStatus) {
            kLogEvent settingsEvent;
            info << settingsEvent
                << "[SettingsDock] TaskmgrHijack.ps1 进程结束, action="
                << (install ? "install" : "uninstall")
                << ", exitCode="
                << exitCode
                << ", exitStatus="
                << static_cast<int>(exitStatus)
                << eol;
            powershellProcess->deleteLater();
        });

    powershellProcess->start();
    if (!powershellProcess->waitForStarted(3000))
    {
        const QString errorText = powershellProcess->errorString();
        kLogEvent settingsEvent;
        err << settingsEvent
            << "[SettingsDock] TaskmgrHijack.ps1 未能启动, action="
            << (install ? "install" : "uninstall")
            << ", error="
            << errorText.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("任务管理器映像劫持"),
            QStringLiteral("启动 PowerShell 脚本失败。\n\n%1").arg(errorText));
        powershellProcess->deleteLater();
        return;
    }

    kLogEvent settingsEvent;
    info << settingsEvent
        << "[SettingsDock] 已启动 TaskmgrHijack.ps1, action="
        << (install ? "install" : "uninstall")
        << ", script="
        << scriptPath.toStdString()
        << ", targetExe="
        << targetExePath.toStdString()
        << eol;
}

double SettingsDock::parseWindowScaleFactorFromUi() const
{
    if (m_startupWindowScaleSpin == nullptr)
    {
        return ks::settings::normalizeWindowScaleFactor(
            m_currentAppearanceSettings.startupWindowScaleFactor);
    }

    // 步进框只能产出合法百分比，不再需要解析文本和容错回退。
    return windowScaleFactorFromPercent(m_startupWindowScaleSpin->value());
}

void SettingsDock::openBackgroundFileDialog()
{
    const QString selectedFilePath = QFileDialog::getOpenFileName(
        this,
        QStringLiteral("选择背景图片"),
        m_backgroundPathEdit->text(),
        QStringLiteral("图片文件 (*.png *.jpg *.jpeg *.bmp *.webp);;所有文件 (*.*)"));

    if (selectedFilePath.isEmpty())
    {
        return;
    }

    m_backgroundPathEdit->setText(selectedFilePath);
    markPendingChanges(QStringLiteral("浏览按钮选择背景图"));
}

void SettingsDock::resetBackgroundPathToDefault()
{
    m_backgroundPathEdit->setText(QStringLiteral("Style/ksword_background.png"));
    markPendingChanges(QStringLiteral("恢复默认背景路径"));
}
