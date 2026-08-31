#include "SettingsDock.h"

#include "../Framework.h"
#include "../Internationalization/LanguageManager.h"
#include "../Framework/PrivilegeElevationPrompt.h"
#include "../theme.h"

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
#include <QPushButton>
#include <QRadioButton>
#include <QSlider>
#include <QSpinBox>
#include <QStringList>
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
    constexpr const char* IconThemeFollowSystem = ":/Icon/settings_theme_system.svg";
    constexpr const char* IconThemeLight = ":/Icon/settings_theme_light.svg";
    constexpr const char* IconThemeDark = ":/Icon/settings_theme_dark.svg";
    constexpr const char* IconBrowseBackground = ":/Icon/settings_background_browse.svg";
    constexpr const char* IconResetBackground = ":/Icon/settings_background_reset.svg";
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
    // 跟随系统时复用当前已生效的主题状态，强制主题时直接读取按钮 ID。
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
        return KswordTheme::IsDarkModeEnabled();
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
    initializeFeaturesTab();
    initializeOnlineScanTab();
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
    }
}

void SettingsDock::initializeUi()
{
    // rootLayout 作用：SettingsDock 根布局，仅承载可滚动的设置页签内容。
    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(10, 10, 10, 10);
    rootLayout->setSpacing(8);

    // m_tabWidget 作用：设置页签容器，后续可扩展更多标签页。
    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setTabPosition(QTabWidget::North);
    rootLayout->addWidget(m_tabWidget);

    setLayout(rootLayout);
}

void SettingsDock::initializeAppearanceTab()
{
    // 将原“外观、语言与启动”长页拆为三个页签，避免单一设置页超过可用高度。
    m_appearanceTab = new QWidget(m_tabWidget);
    QVBoxLayout* appearanceRootLayout = new QVBoxLayout(m_appearanceTab);
    appearanceRootLayout->setContentsMargins(8, 8, 8, 8);
    appearanceRootLayout->setSpacing(12);

    m_languageTab = new QWidget(m_tabWidget);
    QVBoxLayout* languageRootLayout = new QVBoxLayout(m_languageTab);
    languageRootLayout->setContentsMargins(8, 8, 8, 8);
    languageRootLayout->setSpacing(12);

    m_startupTab = new QWidget(m_tabWidget);
    QVBoxLayout* startupRootLayout = new QVBoxLayout(m_startupTab);
    startupRootLayout->setContentsMargins(8, 8, 8, 8);
    startupRootLayout->setSpacing(12);

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

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
    languageLayout->addLayout(languageSelectLayout);
    languageRootLayout->addWidget(languageGroupBox);
    languageRootLayout->addStretch();

    // ===== 主题模式分组 =====
    QGroupBox* themeGroupBox = new QGroupBox(QStringLiteral("主题模式"), m_appearanceTab);
    languageManager.bindText(themeGroupBox, QStringLiteral("settings.theme.group"), QStringLiteral("主题模式"));
    QVBoxLayout* themeLayout = new QVBoxLayout(themeGroupBox);
    themeLayout->setSpacing(8);

    QLabel* themeHintLabel = new QLabel(QStringLiteral("可选择跟随系统、浅色或深色主题。"), themeGroupBox);
    languageManager.bindText(themeHintLabel, QStringLiteral("settings.theme.hint"), QStringLiteral("可选择跟随系统、浅色或深色主题。"));
    themeLayout->addWidget(themeHintLabel);

    QHBoxLayout* themeButtonLayout = new QHBoxLayout();
    themeButtonLayout->setSpacing(10);
    m_themeButtonGroup = new QButtonGroup(themeGroupBox);
    m_themeButtonGroup->setExclusive(true);

    // m_followSystemButton 作用：主题跟随系统按钮（图标 + 悬停说明）。
    m_followSystemButton = new QToolButton(themeGroupBox);
    m_followSystemButton->setIcon(QIcon(QString::fromUtf8(IconThemeFollowSystem)));
    m_followSystemButton->setCheckable(true);
    KswordTheme::ApplyStandardIconButtonMetrics(m_followSystemButton);
    m_followSystemButton->setToolTip(QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));
    languageManager.bindToolTip(m_followSystemButton, QStringLiteral("settings.theme.system.tooltip"), QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));

    // m_lightModeButton 作用：强制浅色主题按钮（图标 + 悬停说明）。
    m_lightModeButton = new QToolButton(themeGroupBox);
    m_lightModeButton->setIcon(QIcon(QString::fromUtf8(IconThemeLight)));
    m_lightModeButton->setCheckable(true);
    KswordTheme::ApplyStandardIconButtonMetrics(m_lightModeButton);
    m_lightModeButton->setToolTip(QStringLiteral("强制浅色模式（白底深色字）"));
    languageManager.bindToolTip(m_lightModeButton, QStringLiteral("settings.theme.light.tooltip"), QStringLiteral("强制浅色模式（白底深色字）"));

    // m_darkModeButton 作用：强制深色主题按钮（图标 + 悬停说明）。
    m_darkModeButton = new QToolButton(themeGroupBox);
    m_darkModeButton->setIcon(QIcon(QString::fromUtf8(IconThemeDark)));
    m_darkModeButton->setCheckable(true);
    KswordTheme::ApplyStandardIconButtonMetrics(m_darkModeButton);
    m_darkModeButton->setToolTip(QStringLiteral("强制深色模式（黑底白字）"));
    languageManager.bindToolTip(m_darkModeButton, QStringLiteral("settings.theme.dark.tooltip"), QStringLiteral("强制深色模式（黑底白字）"));

    m_themeButtonGroup->addButton(m_followSystemButton, static_cast<int>(ks::settings::ThemeMode::FollowSystem));
    m_themeButtonGroup->addButton(m_lightModeButton, static_cast<int>(ks::settings::ThemeMode::Light));
    m_themeButtonGroup->addButton(m_darkModeButton, static_cast<int>(ks::settings::ThemeMode::Dark));

    themeButtonLayout->addWidget(m_followSystemButton);
    themeButtonLayout->addWidget(m_lightModeButton);
    themeButtonLayout->addWidget(m_darkModeButton);
    themeButtonLayout->addStretch();
    themeLayout->addLayout(themeButtonLayout);

    // ===== 自定义主题色分组 =====
    QGroupBox* themeColorGroupBox = new QGroupBox(QStringLiteral("主题色"), themeGroupBox);
    languageManager.bindText(themeColorGroupBox, QStringLiteral("settings.theme.color.group"), QStringLiteral("主题色"));
    QVBoxLayout* themeColorLayout = new QVBoxLayout(themeColorGroupBox);
    themeColorLayout->setSpacing(6);

    QLabel* themeColorHintLabel = new QLabel(
        QStringLiteral("自定义主主题色会保留现有深浅主题偏移；修改前会显示兼容性提示。"),
        themeColorGroupBox);
    themeColorHintLabel->setWordWrap(true);
    languageManager.bindText(
        themeColorHintLabel,
        QStringLiteral("settings.theme.color.hint"),
        QStringLiteral("自定义主主题色会保留现有深浅主题偏移；修改前会显示兼容性提示。"));
    themeColorLayout->addWidget(themeColorHintLabel);

    QHBoxLayout* themeColorActionLayout = new QHBoxLayout();
    themeColorActionLayout->setSpacing(6);
    m_themeColorPreviewLabel = new QLabel(themeColorGroupBox);
    m_themeColorPreviewLabel->setMinimumWidth(112);
    m_themeColorPreviewLabel->setAlignment(Qt::AlignCenter);
    themeColorActionLayout->addWidget(m_themeColorPreviewLabel, 0);

    m_chooseThemeColorButton = new QPushButton(QStringLiteral("自定义主题色"), themeColorGroupBox);
    languageManager.bindText(m_chooseThemeColorButton, QStringLiteral("settings.theme.color.choose"), QStringLiteral("自定义主题色"));
    themeColorActionLayout->addWidget(m_chooseThemeColorButton, 0);

    m_resetThemeColorButton = new QPushButton(QStringLiteral("一键复原"), themeColorGroupBox);
    languageManager.bindText(m_resetThemeColorButton, QStringLiteral("settings.theme.color.reset"), QStringLiteral("一键复原"));
    themeColorActionLayout->addWidget(m_resetThemeColorButton, 0);
    themeColorActionLayout->addStretch();
    themeColorLayout->addLayout(themeColorActionLayout);
    themeLayout->addWidget(themeColorGroupBox);

    QHBoxLayout* fontLayout = new QHBoxLayout();
    fontLayout->setSpacing(6);
    QLabel* fontLabel = new QLabel(QStringLiteral("设置字体"), themeGroupBox);
    languageManager.bindText(fontLabel, QStringLiteral("settings.font.label"), QStringLiteral("设置字体"));
    fontLayout->addWidget(fontLabel, 0);
    m_fontCombo = new QComboBox(themeGroupBox);
    // 第 0 项 itemData 固定为空字符串；显示文字通过独立刷新函数本地化。
    m_fontCombo->addItem(QString(), QString());
    updateSystemDefaultFontItemText();
    // fontFamilies 用途：快照系统当前安装字体，并为每项保存稳定 family 数据。
    const QStringList fontFamilies = QFontDatabase::families();
    for (const QString& fontFamily : fontFamilies)
    {
        const int fontIndex = m_fontCombo->count();
        m_fontCombo->addItem(fontFamily, fontFamily);
        m_fontCombo->setItemData(fontIndex, QFont(fontFamily), Qt::FontRole);
    }
    m_fontCombo->setToolTip(QStringLiteral("选择系统中已安装的字体；点击“应用”后立即生效"));
    languageManager.bindToolTip(
        m_fontCombo,
        QStringLiteral("settings.font.tooltip"),
        QStringLiteral("选择系统中已安装的字体；点击“应用”后立即生效"));
    fontLayout->addWidget(m_fontCombo, 1);
    themeLayout->addLayout(fontLayout);

    m_textAntialiasingCheckBox = new QCheckBox(QStringLiteral("启用文本抗锯齿"), themeGroupBox);
    languageManager.bindText(
        m_textAntialiasingCheckBox,
        QStringLiteral("settings.text_antialiasing.enabled"),
        QStringLiteral("启用文本抗锯齿"));
    m_textAntialiasingCheckBox->setToolTip(
        QStringLiteral("启用后使用平滑字体渲染；关闭时使用无抗锯齿字体渲染。"));
    languageManager.bindToolTip(
        m_textAntialiasingCheckBox,
        QStringLiteral("settings.text_antialiasing.enabled.tooltip"),
        QStringLiteral("启用后使用平滑字体渲染；关闭时使用无抗锯齿字体渲染。"));
    themeLayout->addWidget(m_textAntialiasingCheckBox);
    appearanceRootLayout->addWidget(themeGroupBox);

    // ===== 窗口背景分组 =====
    QGroupBox* backgroundGroupBox = new QGroupBox(QStringLiteral("窗口背景"), m_appearanceTab);
    languageManager.bindText(backgroundGroupBox, QStringLiteral("settings.background.group"), QStringLiteral("窗口背景"));
    QVBoxLayout* backgroundLayout = new QVBoxLayout(backgroundGroupBox);
    backgroundLayout->setSpacing(8);

    QLabel* mainBackgroundColorHintLabel = new QLabel(
        QStringLiteral("主背景色可独立于主题色自定义；恢复默认后随浅色/深色模式切换。"),
        backgroundGroupBox);
    mainBackgroundColorHintLabel->setWordWrap(true);
    languageManager.bindText(
        mainBackgroundColorHintLabel,
        QStringLiteral("settings.background.color.hint"),
        QStringLiteral("主背景色可独立于主题色自定义；恢复默认后随浅色/深色模式切换。"));
    backgroundLayout->addWidget(mainBackgroundColorHintLabel);

    QHBoxLayout* mainBackgroundColorActionLayout = new QHBoxLayout();
    mainBackgroundColorActionLayout->setSpacing(6);
    m_mainBackgroundColorPreviewLabel = new QLabel(backgroundGroupBox);
    m_mainBackgroundColorPreviewLabel->setMinimumWidth(112);
    m_mainBackgroundColorPreviewLabel->setAlignment(Qt::AlignCenter);
    mainBackgroundColorActionLayout->addWidget(m_mainBackgroundColorPreviewLabel, 0);

    m_chooseMainBackgroundColorButton = new QPushButton(
        QStringLiteral("自定义主背景色"),
        backgroundGroupBox);
    languageManager.bindText(
        m_chooseMainBackgroundColorButton,
        QStringLiteral("settings.background.color.choose"),
        QStringLiteral("自定义主背景色"));
    mainBackgroundColorActionLayout->addWidget(m_chooseMainBackgroundColorButton, 0);

    m_resetMainBackgroundColorButton = new QPushButton(
        QStringLiteral("恢复默认背景色"),
        backgroundGroupBox);
    languageManager.bindText(
        m_resetMainBackgroundColorButton,
        QStringLiteral("settings.background.color.reset"),
        QStringLiteral("恢复默认背景色"));
    mainBackgroundColorActionLayout->addWidget(m_resetMainBackgroundColorButton, 0);
    mainBackgroundColorActionLayout->addStretch();
    backgroundLayout->addLayout(mainBackgroundColorActionLayout);

    QLabel* pathHintLabel = new QLabel(
        QStringLiteral("选择一张图片作为窗口背景（支持 PNG/JPG/BMP）。"),
        backgroundGroupBox);
    pathHintLabel->setWordWrap(true);
    languageManager.bindText(pathHintLabel, QStringLiteral("settings.background.path_hint"), QStringLiteral("选择一张图片作为窗口背景（支持 PNG/JPG/BMP）。"));
    backgroundLayout->addWidget(pathHintLabel);

    QHBoxLayout* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);

    // m_backgroundPathEdit 作用：用户输入背景图路径文本。
    m_backgroundPathEdit = new QLineEdit(backgroundGroupBox);
    m_backgroundPathEdit->setPlaceholderText(QStringLiteral("Style/ksword_background.png"));
    pathLayout->addWidget(m_backgroundPathEdit, 1);

    // m_browseBackgroundButton 作用：打开文件对话框选择背景图。
    m_browseBackgroundButton = new QToolButton(backgroundGroupBox);
    m_browseBackgroundButton->setIcon(QIcon(QString::fromUtf8(IconBrowseBackground)));
    KswordTheme::ApplyStandardIconButtonMetrics(m_browseBackgroundButton);
    m_browseBackgroundButton->setToolTip(QStringLiteral("浏览背景图文件"));
    languageManager.bindToolTip(m_browseBackgroundButton, QStringLiteral("settings.background.browse.tooltip"), QStringLiteral("浏览背景图文件"));
    pathLayout->addWidget(m_browseBackgroundButton);

    // m_resetBackgroundButton 作用：恢复默认背景路径。
    m_resetBackgroundButton = new QToolButton(backgroundGroupBox);
    m_resetBackgroundButton->setIcon(QIcon(QString::fromUtf8(IconResetBackground)));
    KswordTheme::ApplyStandardIconButtonMetrics(m_resetBackgroundButton);
    m_resetBackgroundButton->setToolTip(QStringLiteral("恢复默认背景路径"));
    languageManager.bindToolTip(m_resetBackgroundButton, QStringLiteral("settings.background.reset.tooltip"), QStringLiteral("恢复默认背景路径"));
    pathLayout->addWidget(m_resetBackgroundButton);

    backgroundLayout->addLayout(pathLayout);

    QLabel* opacityHintLabel = new QLabel(QStringLiteral("背景图透明度（0% 仅纯色背景，100% 仅背景图）"), backgroundGroupBox);
    languageManager.bindText(opacityHintLabel, QStringLiteral("settings.background.opacity"), QStringLiteral("背景图透明度（0% 仅纯色背景，100% 仅背景图）"));
    backgroundLayout->addWidget(opacityHintLabel);

    QHBoxLayout* opacityLayout = new QHBoxLayout();
    opacityLayout->setSpacing(6);

    // m_backgroundOpacitySlider 作用：控制背景图透明度数值。
    m_backgroundOpacitySlider = new QSlider(Qt::Horizontal, backgroundGroupBox);
    m_backgroundOpacitySlider->setRange(0, 100);
    m_backgroundOpacitySlider->setSingleStep(1);
    m_backgroundOpacitySlider->setPageStep(5);
    m_backgroundOpacitySlider->setToolTip(QStringLiteral("拖动调整背景图透明度"));
    languageManager.bindToolTip(m_backgroundOpacitySlider, QStringLiteral("settings.background.opacity.tooltip"), QStringLiteral("拖动调整背景图透明度"));
    opacityLayout->addWidget(m_backgroundOpacitySlider, 1);

    // m_backgroundOpacityValueLabel 作用：展示当前透明度百分比。
    m_backgroundOpacityValueLabel = new QLabel(QStringLiteral("35%"), backgroundGroupBox);
    m_backgroundOpacityValueLabel->setMinimumWidth(48);
    opacityLayout->addWidget(m_backgroundOpacityValueLabel);

    backgroundLayout->addLayout(opacityLayout);

    // m_backgroundTransparencyCheckBox 作用：切换窗口透明背景（背景图 alpha 穿透 / 云母材质）。
    m_backgroundTransparencyCheckBox = new QCheckBox(QStringLiteral("透明窗口背景（重启后生效）"), backgroundGroupBox);
    languageManager.bindText(m_backgroundTransparencyCheckBox, QStringLiteral("settings.background.transparency"), QStringLiteral("透明窗口背景（重启后生效）"));
    m_backgroundTransparencyCheckBox->setToolTip(QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    languageManager.bindToolTip(m_backgroundTransparencyCheckBox, QStringLiteral("settings.background.transparency.tooltip"), QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    backgroundLayout->addWidget(m_backgroundTransparencyCheckBox);

    // 透明背景效果选择行：勾选透明后可用，运行时立即切换材质，无需重启。
    QHBoxLayout* translucencyMaterialLayout = new QHBoxLayout();
    translucencyMaterialLayout->setSpacing(6);
    QLabel* translucencyMaterialLabel = new QLabel(QStringLiteral("透明背景效果"), backgroundGroupBox);
    languageManager.bindText(translucencyMaterialLabel, QStringLiteral("settings.background.translucency_material"), QStringLiteral("透明背景效果"));
    translucencyMaterialLayout->addWidget(translucencyMaterialLabel);

    // m_backgroundTranslucencyMaterialCombo 作用：选择透明背景的呈现方式（自动/磨砂/直透）。
    m_backgroundTranslucencyMaterialCombo = new QComboBox(backgroundGroupBox);
    m_backgroundTranslucencyMaterialCombo->addItem(QStringLiteral("自动（有背景图直透，无图磨砂）"), QStringLiteral("auto"));
    m_backgroundTranslucencyMaterialCombo->addItem(QStringLiteral("磨砂玻璃"), QStringLiteral("acrylic"));
    m_backgroundTranslucencyMaterialCombo->addItem(QStringLiteral("直透桌面（完全透明）"), QStringLiteral("desktop"));
    m_backgroundTranslucencyMaterialCombo->setToolTip(QStringLiteral("磨砂玻璃：由系统实时模糊窗口后方内容并叠加主题着色。直透桌面：透明区域清晰地直接看到桌面。自动：设置了背景图时直透，没有背景图时用磨砂玻璃。修改后立即生效。"));
    languageManager.bindToolTip(m_backgroundTranslucencyMaterialCombo, QStringLiteral("settings.background.translucency_material.tooltip"), QStringLiteral("磨砂玻璃：由系统实时模糊窗口后方内容并叠加主题着色。直透桌面：透明区域清晰地直接看到桌面。自动：设置了背景图时直透，没有背景图时用磨砂玻璃。修改后立即生效。"));
    languageManager.bindComboBoxItem(m_backgroundTranslucencyMaterialCombo, 0, QStringLiteral("settings.background.translucency_material.auto"), QStringLiteral("自动（有背景图直透，无图磨砂）"));
    languageManager.bindComboBoxItem(m_backgroundTranslucencyMaterialCombo, 1, QStringLiteral("settings.background.translucency_material.acrylic"), QStringLiteral("磨砂玻璃"));
    languageManager.bindComboBoxItem(m_backgroundTranslucencyMaterialCombo, 2, QStringLiteral("settings.background.translucency_material.desktop"), QStringLiteral("直透桌面（完全透明）"));
    translucencyMaterialLayout->addWidget(m_backgroundTranslucencyMaterialCombo, 1);
    backgroundLayout->addLayout(translucencyMaterialLayout);

    // ===== 玻璃观感三滑块 =====
    // 说明：磨砂玻璃由系统合成，其模糊半径在 Windows 内部固定（未公开的 ACCENT_POLICY
    // 没有半径字段），因此“玻璃模糊半径”作用于应用自绘的背景图模糊层；
    // 两个着色不透明度则分别对应磨砂着色（系统混合）与直透着色（自绘兜底）。
    QLabel* blurRadiusHintLabel = new QLabel(
        QStringLiteral("玻璃模糊半径（作用于背景图；0% 不模糊）"),
        backgroundGroupBox);
    blurRadiusHintLabel->setWordWrap(true);
    languageManager.bindText(
        blurRadiusHintLabel,
        QStringLiteral("settings.background.blur_radius"),
        QStringLiteral("玻璃模糊半径（作用于背景图；0% 不模糊）"));
    backgroundLayout->addWidget(blurRadiusHintLabel);

    QHBoxLayout* blurRadiusLayout = new QHBoxLayout();
    blurRadiusLayout->setSpacing(6);

    // m_backgroundBlurRadiusSlider 作用：控制背景图自绘玻璃模糊的半径强度。
    m_backgroundBlurRadiusSlider = new QSlider(Qt::Horizontal, backgroundGroupBox);
    m_backgroundBlurRadiusSlider->setRange(0, 100);
    m_backgroundBlurRadiusSlider->setSingleStep(1);
    m_backgroundBlurRadiusSlider->setPageStep(5);
    m_backgroundBlurRadiusSlider->setToolTip(QStringLiteral("把背景图模糊成毛玻璃质感，数值越大越糊。仅作用于背景图：磨砂玻璃是由 Windows 合成的，它的模糊半径由系统固定，应用无法调整。修改后立即生效。"));
    languageManager.bindToolTip(
        m_backgroundBlurRadiusSlider,
        QStringLiteral("settings.background.blur_radius.tooltip"),
        QStringLiteral("把背景图模糊成毛玻璃质感，数值越大越糊。仅作用于背景图：磨砂玻璃是由 Windows 合成的，它的模糊半径由系统固定，应用无法调整。修改后立即生效。"));
    blurRadiusLayout->addWidget(m_backgroundBlurRadiusSlider, 1);

    // m_backgroundBlurRadiusValueLabel 作用：展示当前模糊半径强度。
    m_backgroundBlurRadiusValueLabel = new QLabel(QStringLiteral("0%"), backgroundGroupBox);
    m_backgroundBlurRadiusValueLabel->setMinimumWidth(48);
    blurRadiusLayout->addWidget(m_backgroundBlurRadiusValueLabel);

    backgroundLayout->addLayout(blurRadiusLayout);

    QLabel* acrylicTintHintLabel = new QLabel(
        QStringLiteral("磨砂着色不透明度（越低越通透，越高文字越清晰）"),
        backgroundGroupBox);
    acrylicTintHintLabel->setWordWrap(true);
    languageManager.bindText(
        acrylicTintHintLabel,
        QStringLiteral("settings.background.acrylic_tint"),
        QStringLiteral("磨砂着色不透明度（越低越通透，越高文字越清晰）"));
    backgroundLayout->addWidget(acrylicTintHintLabel);

    QHBoxLayout* acrylicTintLayout = new QHBoxLayout();
    acrylicTintLayout->setSpacing(6);

    // m_acrylicTintOpacitySlider 作用：控制磨砂玻璃着色层的不透明度。
    m_acrylicTintOpacitySlider = new QSlider(Qt::Horizontal, backgroundGroupBox);
    m_acrylicTintOpacitySlider->setRange(0, 100);
    m_acrylicTintOpacitySlider->setSingleStep(1);
    m_acrylicTintOpacitySlider->setPageStep(5);
    m_acrylicTintOpacitySlider->setToolTip(QStringLiteral("“磨砂玻璃”效果上叠加的主题着色浓度。调到 0% 接近纯模糊，调高则更接近实色背景、前景文字更易读。仅在透明背景效果为磨砂玻璃时生效，修改后立即生效。"));
    languageManager.bindToolTip(
        m_acrylicTintOpacitySlider,
        QStringLiteral("settings.background.acrylic_tint.tooltip"),
        QStringLiteral("“磨砂玻璃”效果上叠加的主题着色浓度。调到 0% 接近纯模糊，调高则更接近实色背景、前景文字更易读。仅在透明背景效果为磨砂玻璃时生效，修改后立即生效。"));
    acrylicTintLayout->addWidget(m_acrylicTintOpacitySlider, 1);

    // m_acrylicTintOpacityValueLabel 作用：展示磨砂着色不透明度。
    m_acrylicTintOpacityValueLabel = new QLabel(QStringLiteral("75%"), backgroundGroupBox);
    m_acrylicTintOpacityValueLabel->setMinimumWidth(48);
    acrylicTintLayout->addWidget(m_acrylicTintOpacityValueLabel);

    backgroundLayout->addLayout(acrylicTintLayout);

    QLabel* desktopTintHintLabel = new QLabel(
        QStringLiteral("直透着色不透明度（0% 几乎完全看到桌面）"),
        backgroundGroupBox);
    desktopTintHintLabel->setWordWrap(true);
    languageManager.bindText(
        desktopTintHintLabel,
        QStringLiteral("settings.background.desktop_tint"),
        QStringLiteral("直透着色不透明度（0% 几乎完全看到桌面）"));
    backgroundLayout->addWidget(desktopTintHintLabel);

    QHBoxLayout* desktopTintLayout = new QHBoxLayout();
    desktopTintLayout->setSpacing(6);

    // m_desktopTintOpacitySlider 作用：控制直透桌面模式下自绘着色层的不透明度。
    m_desktopTintOpacitySlider = new QSlider(Qt::Horizontal, backgroundGroupBox);
    m_desktopTintOpacitySlider->setRange(0, 100);
    m_desktopTintOpacitySlider->setSingleStep(1);
    m_desktopTintOpacitySlider->setPageStep(5);
    m_desktopTintOpacitySlider->setToolTip(QStringLiteral("“直透桌面”时窗口自绘的主题着色浓度。调到 0% 几乎完全透出桌面（仍保留最低限度的鼠标响应），调高则界面更实、文字更易读。没有背景图时生效，修改后立即生效。"));
    languageManager.bindToolTip(
        m_desktopTintOpacitySlider,
        QStringLiteral("settings.background.desktop_tint.tooltip"),
        QStringLiteral("“直透桌面”时窗口自绘的主题着色浓度。调到 0% 几乎完全透出桌面（仍保留最低限度的鼠标响应），调高则界面更实、文字更易读。没有背景图时生效，修改后立即生效。"));
    desktopTintLayout->addWidget(m_desktopTintOpacitySlider, 1);

    // m_desktopTintOpacityValueLabel 作用：展示直透着色不透明度。
    m_desktopTintOpacityValueLabel = new QLabel(QStringLiteral("65%"), backgroundGroupBox);
    m_desktopTintOpacityValueLabel->setMinimumWidth(48);
    desktopTintLayout->addWidget(m_desktopTintOpacityValueLabel);

    backgroundLayout->addLayout(desktopTintLayout);

    // 组合框与两个着色滑块的可用性跟随透明总开关；初始状态由 applySettingsToUi 同步。
    // 模糊半径作用于背景图自绘层，不依赖窗口透明，因此始终可用。
    m_backgroundTranslucencyMaterialCombo->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_backgroundTranslucencyMaterialCombo, &QWidget::setEnabled);
    m_acrylicTintOpacitySlider->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_acrylicTintOpacitySlider, &QWidget::setEnabled);
    m_desktopTintOpacitySlider->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_desktopTintOpacitySlider, &QWidget::setEnabled);
    appearanceRootLayout->addWidget(backgroundGroupBox);

    // ===== 交互与滚动分组 =====
    QGroupBox* interactionGroupBox = new QGroupBox(QStringLiteral("交互与滚动"), m_appearanceTab);
    languageManager.bindText(interactionGroupBox, QStringLiteral("settings.interaction.group"), QStringLiteral("交互与滚动"));
    QVBoxLayout* interactionLayout = new QVBoxLayout(interactionGroupBox);
    interactionLayout->setSpacing(8);

    QLabel* interactionHintLabel = new QLabel(
        QStringLiteral("调整全局滚动，以及滚轮是否直接调整滑块。"),
        interactionGroupBox);
    interactionHintLabel->setWordWrap(true);
    languageManager.bindText(interactionHintLabel, QStringLiteral("settings.interaction.hint"), QStringLiteral("调整全局滚动，以及滚轮是否直接调整滑块。"));
    interactionLayout->addWidget(interactionHintLabel);

    QHBoxLayout* scrollBarWidthLayout = new QHBoxLayout();
    scrollBarWidthLayout->setSpacing(6);
    QLabel* scrollBarWidthLabel = new QLabel(QStringLiteral("滚动条宽度"), interactionGroupBox);
    languageManager.bindText(scrollBarWidthLabel, QStringLiteral("settings.scrollbar.width"), QStringLiteral("滚动条宽度"));
    scrollBarWidthLayout->addWidget(scrollBarWidthLabel, 0);
    m_scrollBarWidthCombo = new QComboBox(interactionGroupBox);
    m_scrollBarWidthCombo->addItem(QStringLiteral("窄版（默认，遮挡更少）"), false);
    m_scrollBarWidthCombo->addItem(QStringLiteral("宽版（旧版大小）"), true);
    languageManager.bindComboBoxItem(m_scrollBarWidthCombo, 0, QStringLiteral("settings.scrollbar.narrow"), QStringLiteral("窄版（默认，遮挡更少）"));
    languageManager.bindComboBoxItem(m_scrollBarWidthCombo, 1, QStringLiteral("settings.scrollbar.wide"), QStringLiteral("宽版（旧版大小）"));
    scrollBarWidthLayout->addWidget(m_scrollBarWidthCombo, 1);
    interactionLayout->addLayout(scrollBarWidthLayout);

    m_scrollBarAutoHideCheckBox = new QCheckBox(QStringLiteral("滚动条自动隐藏（悬停时展开）"), interactionGroupBox);
    languageManager.bindText(m_scrollBarAutoHideCheckBox, QStringLiteral("settings.scrollbar.auto_hide"), QStringLiteral("滚动条自动隐藏（悬停时展开）"));
    m_scrollBarAutoHideCheckBox->setToolTip(QStringLiteral("启用后滚动条默认缩到很窄，鼠标悬停时展开到当前宽度档位"));
    languageManager.bindToolTip(m_scrollBarAutoHideCheckBox, QStringLiteral("settings.scrollbar.auto_hide.tooltip"), QStringLiteral("启用后滚动条默认缩到很窄，鼠标悬停时展开到当前宽度档位"));
    interactionLayout->addWidget(m_scrollBarAutoHideCheckBox);

    m_smoothScrollingCheckBox = new QCheckBox(
        QStringLiteral("启用全局平滑滚动"),
        interactionGroupBox);
    languageManager.bindText(
        m_smoothScrollingCheckBox,
        QStringLiteral("settings.scroll.smooth"),
        QStringLiteral("启用全局平滑滚动"));
    m_smoothScrollingCheckBox->setToolTip(
        QStringLiteral("对表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    languageManager.bindToolTip(
        m_smoothScrollingCheckBox,
        QStringLiteral("settings.scroll.smooth.tooltip"),
        QStringLiteral("对表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    interactionLayout->addWidget(m_smoothScrollingCheckBox);

    m_sliderWheelAdjustCheckBox = new QCheckBox(QStringLiteral("允许滚轮直接调整滑块"), interactionGroupBox);
    languageManager.bindText(m_sliderWheelAdjustCheckBox, QStringLiteral("settings.slider.wheel"), QStringLiteral("允许滚轮直接调整滑块"));
    m_sliderWheelAdjustCheckBox->setToolTip(QStringLiteral("关闭后，鼠标滚轮经过滑块时优先滚动页面，不再误改滑块值"));
    languageManager.bindToolTip(m_sliderWheelAdjustCheckBox, QStringLiteral("settings.slider.wheel.tooltip"), QStringLiteral("关闭后，鼠标滚轮经过滑块时优先滚动页面，不再误改滑块值"));
    interactionLayout->addWidget(m_sliderWheelAdjustCheckBox);

    appearanceRootLayout->addWidget(interactionGroupBox);

    // ===== 详情页显示方案分组 =====
    // 该设置只作用于严格命中页面，选择后点击“应用”会立即重排已创建页面。
    QGroupBox* detailSchemeGroupBox = new QGroupBox(
        QStringLiteral("详情页显示方案"),
        m_appearanceTab);
    languageManager.bindText(
        detailSchemeGroupBox,
        QStringLiteral("settings.detail_layout.group"),
        QStringLiteral("详情页显示方案"));
    QVBoxLayout* detailSchemeLayout = new QVBoxLayout(detailSchemeGroupBox);
    detailSchemeLayout->setSpacing(6);

    QLabel* detailSchemeHintLabel = new QLabel(
        QStringLiteral("统一设置表格当前行详情的显示位置；点击应用后立即生效。"),
        detailSchemeGroupBox);
    detailSchemeHintLabel->setWordWrap(true);
    languageManager.bindText(
        detailSchemeHintLabel,
        QStringLiteral("settings.detail_layout.hint"),
        QStringLiteral("统一设置表格当前行详情的显示位置；点击应用后立即生效。"));
    detailSchemeLayout->addWidget(detailSchemeHintLabel);

    m_detailSchemeButtonGroup = new QButtonGroup(detailSchemeGroupBox);
    m_detailSchemeButtonGroup->setExclusive(true);
    const auto addDetailSchemeRadio = [this, detailSchemeGroupBox, detailSchemeLayout, &languageManager](
        const ks::settings::DetailDisplayScheme scheme,
        const QString& textKey,
        const QString& fallbackText)
        {
            // 每项使用 QRadioButton：显示明确文字，避免四种布局只靠图标难以分辨。
            QRadioButton* radioButton = new QRadioButton(fallbackText, detailSchemeGroupBox);
            languageManager.bindText(radioButton, textKey, fallbackText);
            m_detailSchemeButtonGroup->addButton(radioButton, static_cast<int>(scheme));
            detailSchemeLayout->addWidget(radioButton);
        };
    addDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::BottomCollapsed,
        QStringLiteral("settings.detail_layout.bottom_collapsed"),
        QStringLiteral("下方折叠（默认）"));
    addDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::Right,
        QStringLiteral("settings.detail_layout.right"),
        QStringLiteral("表格右侧"));
    addDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::Embedded,
        QStringLiteral("settings.detail_layout.embedded"),
        QStringLiteral("行内嵌入"));
    addDetailSchemeRadio(
        ks::settings::DetailDisplayScheme::Floating,
        QStringLiteral("settings.detail_layout.floating"),
        QStringLiteral("独立窗口"));
    appearanceRootLayout->addWidget(detailSchemeGroupBox);

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

    // m_startupMaximizedCheckBox 作用：控制“下次启动时是否直接最大化显示”。
    m_startupMaximizedCheckBox = new QCheckBox(QStringLiteral("启动时最大化"), startupGroupBox);
    languageManager.bindText(m_startupMaximizedCheckBox, QStringLiteral("settings.startup.maximized"), QStringLiteral("启动时最大化"));
    m_startupMaximizedCheckBox->setToolTip(QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    languageManager.bindToolTip(m_startupMaximizedCheckBox, QStringLiteral("settings.startup.maximized.tooltip"), QStringLiteral("下次启动主窗口时直接以最大化状态显示"));
    startupLayout->addWidget(m_startupMaximizedCheckBox);

    // m_startupTopMostCheckBox 作用：控制“启动后是否自动设置 HWND_TOPMOST 最高级置顶”。
    m_startupTopMostCheckBox = new QCheckBox(QStringLiteral("启动后默认最高级置顶"), startupGroupBox);
    languageManager.bindText(m_startupTopMostCheckBox, QStringLiteral("settings.startup.topmost"), QStringLiteral("启动后默认最高级置顶"));
    m_startupTopMostCheckBox->setToolTip(
        QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    languageManager.bindToolTip(m_startupTopMostCheckBox, QStringLiteral("settings.startup.topmost.tooltip"), QStringLiteral("启动后保持窗口置顶；可用右上角图钉临时切换"));
    startupLayout->addWidget(m_startupTopMostCheckBox);

    // m_startupAutoAdminCheckBox 作用：控制“启动图出现前是否先尝试 UAC 提权”。
    m_startupAutoAdminCheckBox = new QCheckBox(QStringLiteral("启动时自动请求管理员权限"), startupGroupBox);
    languageManager.bindText(m_startupAutoAdminCheckBox, QStringLiteral("settings.startup.admin"), QStringLiteral("启动时自动请求管理员权限"));
    m_startupAutoAdminCheckBox->setToolTip(
        QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    languageManager.bindToolTip(m_startupAutoAdminCheckBox, QStringLiteral("settings.startup.admin.tooltip"), QStringLiteral("下次启动时请求管理员权限；若取消或失败，将以普通权限继续"));
    startupLayout->addWidget(m_startupAutoAdminCheckBox);

    // m_preventMultipleInstancesCheckBox 作用：控制普通启动是否激活已有窗口并退出新进程。
    m_preventMultipleInstancesCheckBox = new QCheckBox(QStringLiteral("防止多开"), startupGroupBox);
    languageManager.bindText(m_preventMultipleInstancesCheckBox, QStringLiteral("settings.startup.prevent_multiple_instances"), QStringLiteral("防止多开"));
    m_preventMultipleInstancesCheckBox->setToolTip(
        QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    languageManager.bindToolTip(m_preventMultipleInstancesCheckBox, QStringLiteral("settings.startup.prevent_multiple_instances.tooltip"), QStringLiteral("开启时，普通启动会激活已有窗口；管理员和 SYSTEM 权限切换不受影响"));
    startupLayout->addWidget(m_preventMultipleInstancesCheckBox);

    // m_unlockerShellContextMenuCheckBox 作用：控制是否启用系统右键“文件解锁器”菜单。
    m_unlockerShellContextMenuCheckBox = new QCheckBox(QStringLiteral("启用系统右键“文件解锁器”菜单"), startupGroupBox);
    languageManager.bindText(m_unlockerShellContextMenuCheckBox, QStringLiteral("settings.startup.unlocker"), QStringLiteral("启用系统右键“文件解锁器”菜单"));
    m_unlockerShellContextMenuCheckBox->setToolTip(
        QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    languageManager.bindToolTip(m_unlockerShellContextMenuCheckBox, QStringLiteral("settings.startup.unlocker.tooltip"), QStringLiteral("点击“应用”后，在系统右键菜单中添加或移除文件解锁器"));
    startupLayout->addWidget(m_unlockerShellContextMenuCheckBox);

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
        windowScalePercentFromFactor(ks::settings::MinimumWindowScaleFactor),
        windowScalePercentFromFactor(ks::settings::MaximumWindowScaleFactor));
    m_startupWindowScaleSpin->setSingleStep(5);
    m_startupWindowScaleSpin->setSuffix(QStringLiteral(" %"));
    m_startupWindowScaleSpin->setValue(100);
    m_startupWindowScaleSpin->setKeyboardTracking(false);
    m_startupWindowScaleSpin->setToolTip(
        QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    languageManager.bindToolTip(m_startupWindowScaleSpin, QStringLiteral("settings.startup.scale.tooltip"), QStringLiteral("主窗口界面缩放，重启后生效；与系统显示缩放叠加。"));
    startupScaleLayout->addWidget(m_startupWindowScaleSpin, 0);
    startupScaleLayout->addStretch(1);
    startupLayout->addLayout(startupScaleLayout);

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
    startupLayout->addWidget(m_startupWindowScaleHintLabel);

    startupRootLayout->addWidget(startupGroupBox);
    startupRootLayout->addStretch();

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

    m_notificationCardsEnabledCheckBox = new QCheckBox(QStringLiteral("启用右侧通知卡片"), notificationGroupBox);
    languageManager.bindText(m_notificationCardsEnabledCheckBox, QStringLiteral("settings.notification.enabled"), QStringLiteral("启用右侧通知卡片"));
    notificationLayout->addWidget(m_notificationCardsEnabledCheckBox);

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
    notificationLayout->addLayout(notificationLevelLayout);

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
    notificationLayout->addLayout(notificationDurationLayout);

    QHBoxLayout* notificationMaximumCountLayout = new QHBoxLayout();
    QLabel* notificationMaximumCountLabel = new QLabel(QStringLiteral("同时显示最多日志条数"), notificationGroupBox);
    languageManager.bindText(notificationMaximumCountLabel, QStringLiteral("settings.notification.maximum_count"), QStringLiteral("同时显示最多日志条数"));
    notificationMaximumCountLayout->addWidget(notificationMaximumCountLabel, 0);
    m_notificationMaximumVisibleLogCardsSpin = new QSpinBox(notificationGroupBox);
    m_notificationMaximumVisibleLogCardsSpin->setRange(0, 100);
    m_notificationMaximumVisibleLogCardsSpin->setToolTip(QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    languageManager.bindToolTip(m_notificationMaximumVisibleLogCardsSpin, QStringLiteral("settings.notification.maximum_count.tooltip"), QStringLiteral("0 表示不限制，仍会在可用空间不足时按现有逻辑替换最旧日志。"));
    notificationMaximumCountLayout->addWidget(m_notificationMaximumVisibleLogCardsSpin, 1);
    notificationLayout->addLayout(notificationMaximumCountLayout);

    m_notificationLogHeightLimitCheckBox = new QCheckBox(QStringLiteral("限制单条日志卡片高度"), notificationGroupBox);
    languageManager.bindText(m_notificationLogHeightLimitCheckBox, QStringLiteral("settings.notification.height_limit.enabled"), QStringLiteral("限制单条日志卡片高度"));
    notificationLayout->addWidget(m_notificationLogHeightLimitCheckBox);

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
    notificationLayout->addLayout(notificationMaximumLinesLayout);

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
    notificationLayout->addLayout(notificationPlacementLayout);

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
    notificationLayout->addLayout(notificationStackLayout);

    appearanceRootLayout->addWidget(notificationGroupBox);

    appearanceRootLayout->addStretch();
    m_tabWidget->addTab(m_appearanceTab, QStringLiteral("外观"));
    languageManager.bindTab(m_tabWidget, m_appearanceTab, QStringLiteral("settings.tab.appearance"), QStringLiteral("外观"));
    m_tabWidget->addTab(m_languageTab, QStringLiteral("语言"));
    languageManager.bindTab(m_tabWidget, m_languageTab, QStringLiteral("settings.tab.language"), QStringLiteral("语言"));
    m_tabWidget->addTab(m_startupTab, QStringLiteral("启动"));
    languageManager.bindTab(m_tabWidget, m_startupTab, QStringLiteral("settings.tab.startup"), QStringLiteral("启动"));

    bindAppearanceSignals();
    updateThemeButtonStyle();
    updateApplyButtonState();
}

void SettingsDock::showLanguageSettingsTab()
{
    if (m_tabWidget != nullptr && m_languageTab != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_languageTab);
    }
}

void SettingsDock::initializeFeaturesTab()
{
    m_featuresTab = new QWidget(m_tabWidget);
    QVBoxLayout* featuresRootLayout = new QVBoxLayout(m_featuresTab);
    featuresRootLayout->setContentsMargins(8, 8, 8, 8);
    featuresRootLayout->setSpacing(12);

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

    featuresRootLayout->addWidget(dumpCheckGroupBox);
    initializeBugcheckDiagnosticsControls(featuresRootLayout);
    featuresRootLayout->addStretch();
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

void SettingsDock::bindAppearanceSignals()
{
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

    connect(m_scrollBarWidthCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        markPendingChanges(QStringLiteral("滚动条宽度切换"));
        });

    connect(m_scrollBarAutoHideCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("滚动条自动隐藏开关切换"));
        });

    connect(m_smoothScrollingCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("全局平滑滚动开关切换"));
        });

    connect(m_sliderWheelAdjustCheckBox, &QCheckBox::toggled, this, [this](const bool /*checkedState*/) {
        markPendingChanges(QStringLiteral("滑块滚轮调节开关切换"));
        });

    connect(m_detailSchemeButtonGroup, &QButtonGroup::idClicked, this, [this](const int) {
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

    if (m_scrollBarWidthCombo != nullptr)
    {
        const int scrollBarWidthIndex = m_scrollBarWidthCombo->findData(settings.useWideScrollBars);
        m_scrollBarWidthCombo->setCurrentIndex(scrollBarWidthIndex >= 0 ? scrollBarWidthIndex : 0);
    }
    if (m_scrollBarAutoHideCheckBox != nullptr)
    {
        m_scrollBarAutoHideCheckBox->setChecked(settings.scrollBarAutoHideEnabled);
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

    if (m_detailSchemeButtonGroup != nullptr)
    {
        QAbstractButton* detailSchemeButton = m_detailSchemeButtonGroup->button(
            static_cast<int>(settings.detailDisplayScheme));
        if (detailSchemeButton == nullptr)
        {
            detailSchemeButton = m_detailSchemeButtonGroup->button(
                static_cast<int>(ks::settings::DetailDisplayScheme::BottomCollapsed));
        }
        if (detailSchemeButton != nullptr)
        {
            detailSchemeButton->setChecked(true);
        }
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
    collectedSettings.useWideScrollBars =
        (m_scrollBarWidthCombo != nullptr) && m_scrollBarWidthCombo->currentData().toBool();
    collectedSettings.scrollBarAutoHideEnabled =
        (m_scrollBarAutoHideCheckBox != nullptr) && m_scrollBarAutoHideCheckBox->isChecked();
    collectedSettings.smoothScrollingEnabled =
        (m_smoothScrollingCheckBox != nullptr) && m_smoothScrollingCheckBox->isChecked();
    collectedSettings.sliderWheelAdjustEnabled =
        (m_sliderWheelAdjustCheckBox != nullptr) && m_sliderWheelAdjustCheckBox->isChecked();
    const int detailSchemeId = m_detailSchemeButtonGroup != nullptr
        ? m_detailSchemeButtonGroup->checkedId()
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
    if (m_themeColorPreviewLabel == nullptr)
    {
        return;
    }

    const QColor previewColor = m_pendingCustomThemeColor.isEmpty()
        ? KswordTheme::DefaultPrimaryAccentColor()
        : QColor(m_pendingCustomThemeColor);
    const QColor readableTextColor = KswordTheme::EnsureTextContrast(
        KswordTheme::WhiteColor(),
        previewColor);
    const QString colorText = previewColor.name(QColor::HexRgb).toUpper();
    m_themeColorPreviewLabel->setText(colorText);
    m_themeColorPreviewLabel->setStyleSheet(
        QStringLiteral("QLabel{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px;font-weight:600;}")
        .arg(colorText)
        .arg(KswordTheme::ThemeColorName(readableTextColor))
        .arg(KswordTheme::BorderHex()));

    if (m_resetThemeColorButton != nullptr)
    {
        m_resetThemeColorButton->setEnabled(!m_pendingCustomThemeColor.isEmpty());
    }
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
    const QColor selectedColor = QColorDialog::getColor(
        initialColor,
        this,
        ks::i18n::text(
            QStringLiteral("settings.theme.color.dialog.title"),
            QStringLiteral("选择主题色")),
        QColorDialog::ShowAlphaChannel);
    if (!selectedColor.isValid())
    {
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
    if (m_mainBackgroundColorPreviewLabel == nullptr)
    {
        return;
    }

    const QColor previewColor = m_pendingCustomMainBackgroundColor.isEmpty()
        ? KswordTheme::DefaultMainBackgroundColor(
            selectedThemeUsesDarkBackground(m_themeButtonGroup))
        : QColor(m_pendingCustomMainBackgroundColor);
    const QColor readableTextColor = KswordTheme::EnsureTextContrast(
        KswordTheme::TextPrimaryColor(),
        previewColor);
    const QString colorText = previewColor.name(QColor::HexRgb).toUpper();
    m_mainBackgroundColorPreviewLabel->setText(colorText);
    m_mainBackgroundColorPreviewLabel->setStyleSheet(
        QStringLiteral("QLabel{background:%1;color:%2;border:1px solid %3;border-radius:3px;padding:5px;font-weight:600;}")
        .arg(colorText)
        .arg(KswordTheme::ThemeColorName(readableTextColor))
        .arg(KswordTheme::BorderHex()));

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
    const QColor selectedColor = QColorDialog::getColor(
        initialColor,
        this,
        ks::i18n::text(
            QStringLiteral("settings.background.color.dialog.title"),
            QStringLiteral("选择主背景色")));
    if (!selectedColor.isValid())
    {
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
        && nextSettings.preventMultipleInstances == m_currentAppearanceSettings.preventMultipleInstances
        && sameScaleFactor
        && nextSettings.startupScaleRecommendPromptDisabled == m_currentAppearanceSettings.startupScaleRecommendPromptDisabled
        && nextSettings.unlockerShellContextMenuEnabled == m_currentAppearanceSettings.unlockerShellContextMenuEnabled
        && nextSettings.suppressR0FeaturePrompts == m_currentAppearanceSettings.suppressR0FeaturePrompts
        && nextSettings.useWideScrollBars == m_currentAppearanceSettings.useWideScrollBars
        && nextSettings.scrollBarAutoHideEnabled == m_currentAppearanceSettings.scrollBarAutoHideEnabled
        && nextSettings.smoothScrollingEnabled == m_currentAppearanceSettings.smoothScrollingEnabled
        && nextSettings.sliderWheelAdjustEnabled == m_currentAppearanceSettings.sliderWheelAdjustEnabled
        && nextSettings.detailDisplayScheme == m_currentAppearanceSettings.detailDisplayScheme
        && nextSettings.fontFamily.compare(m_currentAppearanceSettings.fontFamily, Qt::CaseInsensitive) == 0
        && nextSettings.textAntialiasingEnabled == m_currentAppearanceSettings.textAntialiasingEnabled
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
        << "，防止多开="
        << (m_currentAppearanceSettings.preventMultipleInstances ? "true" : "false")
        << "，启动窗口缩放因子="
        << m_currentAppearanceSettings.startupWindowScaleFactor
        << "，小屏缩放提示不再弹出="
        << (m_currentAppearanceSettings.startupScaleRecommendPromptDisabled ? "true" : "false")
        << "，系统右键文件解锁器菜单="
        << (m_currentAppearanceSettings.unlockerShellContextMenuEnabled ? "true" : "false")
        << "，宽滚动条="
        << (m_currentAppearanceSettings.useWideScrollBars ? "true" : "false")
        << "，滚动条自动隐藏="
        << (m_currentAppearanceSettings.scrollBarAutoHideEnabled ? "true" : "false")
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
    const bool darkModeEnabled = KswordTheme::IsDarkModeEnabled();
    const QString normalStyle = darkModeEnabled
        ? QStringLiteral(
            "QToolButton{"
            "  border:1px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}"
            "QToolButton:hover{"
            "  background:%3;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::SurfaceMutedColorHex())
        : QStringLiteral(
            "QToolButton{"
            "  border:1px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}"
            "QToolButton:hover{"
            "  background:%3;"
            "}")
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::PrimaryBlueSubtleHex())
            .arg(KswordTheme::PrimaryBlueSubtleHex());

    const QString checkedStyle = darkModeEnabled
        ? QStringLiteral(
            "QToolButton{"
            "  border:2px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::PrimaryBlueSubtleHex())
        : QStringLiteral(
            "QToolButton{"
            "  border:2px solid %1;"
            "  border-radius:2px;"
            "  background:%2;"
            "}")
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::PrimaryBlueSubtleHex());

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
