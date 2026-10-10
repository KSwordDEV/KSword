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

void SettingsDock::initializeAppearanceTab()
{
    // 配色、背景与透明效果在左列，预览和交互在右列；窄窗口按原顺序纵向排列。
    m_appearanceTab = new QWidget(m_tabWidget);
    QVBoxLayout* appearanceRootLayout = new QVBoxLayout(m_appearanceTab);
    ks::ui::StyleSecondaryContentLayout(appearanceRootLayout);
    // 分区间留白大于区内行距，让标题自然形成阅读停顿，控件行仍保持紧凑。
    appearanceRootLayout->setSpacing(24);
    auto* primaryColumn = new QWidget(m_appearanceTab); // 常用配色设置列。
    auto* primaryLayout = new QVBoxLayout(primaryColumn);
    primaryLayout->setContentsMargins(0, 0, 0, 0);
    primaryLayout->setSpacing(24);
    auto* secondaryColumn = new QWidget(m_appearanceTab); // 样例预览和交互设置列。
    auto* secondaryLayout = new QVBoxLayout(secondaryColumn);
    secondaryLayout->setContentsMargins(0, 0, 0, 0);
    secondaryLayout->setSpacing(24);

    ks::i18n::LanguageManager& languageManager = ks::i18n::LanguageManager::instance();

    // ===== 主题模式分组 =====
    QGroupBox* themeGroupBox = new QGroupBox(QStringLiteral("主题模式"), m_appearanceTab);
    languageManager.bindText(themeGroupBox, QStringLiteral("settings.theme.group"), QStringLiteral("主题模式"));
    QVBoxLayout* themeLayout = new QVBoxLayout(themeGroupBox);
    themeLayout->setSpacing(8);

    QHBoxLayout* themeButtonLayout = new QHBoxLayout();
    themeButtonLayout->setSpacing(0);
    m_themeButtonGroup = new QButtonGroup(themeGroupBox);
    m_themeButtonGroup->setExclusive(true);

    // m_followSystemButton 作用：主题跟随系统按钮（图标 + 悬停说明）。
    m_followSystemButton = new QToolButton(themeGroupBox);
    m_followSystemButton->setIcon(QIcon(QString::fromUtf8(":/Icon/settings_theme_system.svg")));
    m_followSystemButton->setCheckable(true);
    m_followSystemButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    languageManager.bindText(m_followSystemButton, QStringLiteral("settings.theme.mode.system"), QStringLiteral("跟随系统"));
    ks::ui::NormalizeToolbarControl(m_followSystemButton);
    m_followSystemButton->setToolTip(QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));
    languageManager.bindToolTip(m_followSystemButton, QStringLiteral("settings.theme.system.tooltip"), QStringLiteral("跟随系统主题（Windows 深浅切换时自动同步）"));

    // m_lightModeButton 作用：强制浅色主题按钮（图标 + 悬停说明）。
    m_lightModeButton = new QToolButton(themeGroupBox);
    m_lightModeButton->setIcon(QIcon(QString::fromUtf8(":/Icon/settings_theme_light.svg")));
    m_lightModeButton->setCheckable(true);
    m_lightModeButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    languageManager.bindText(m_lightModeButton, QStringLiteral("settings.theme.mode.light"), QStringLiteral("浅色"));
    ks::ui::NormalizeToolbarControl(m_lightModeButton);
    m_lightModeButton->setToolTip(QStringLiteral("强制浅色模式（白底深色字）"));
    languageManager.bindToolTip(m_lightModeButton, QStringLiteral("settings.theme.light.tooltip"), QStringLiteral("强制浅色模式（白底深色字）"));

    // m_darkModeButton 作用：强制深色主题按钮（图标 + 悬停说明）。
    m_darkModeButton = new QToolButton(themeGroupBox);
    m_darkModeButton->setIcon(QIcon(QString::fromUtf8(":/Icon/settings_theme_dark.svg")));
    m_darkModeButton->setCheckable(true);
    m_darkModeButton->setToolButtonStyle(Qt::ToolButtonTextOnly);
    languageManager.bindText(m_darkModeButton, QStringLiteral("settings.theme.mode.dark"), QStringLiteral("深色"));
    ks::ui::NormalizeToolbarControl(m_darkModeButton);
    m_darkModeButton->setToolTip(QStringLiteral("强制深色模式（黑底白字）"));
    languageManager.bindToolTip(m_darkModeButton, QStringLiteral("settings.theme.dark.tooltip"), QStringLiteral("强制深色模式（黑底白字）"));

    m_themeButtonGroup->addButton(m_followSystemButton, static_cast<int>(ks::settings::ThemeMode::FollowSystem));
    m_themeButtonGroup->addButton(m_lightModeButton, static_cast<int>(ks::settings::ThemeMode::Light));
    m_themeButtonGroup->addButton(m_darkModeButton, static_cast<int>(ks::settings::ThemeMode::Dark));

    themeButtonLayout->addWidget(m_followSystemButton);
    themeButtonLayout->addWidget(m_lightModeButton);
    themeButtonLayout->addWidget(m_darkModeButton);
    themeButtonLayout->addStretch();
    auto* themeForm = ks::settings::ui::Form(themeLayout);
    themeForm->addRow(ks::settings::ui::Label(themeGroupBox,
        QStringLiteral("settings.theme.group"), QStringLiteral("主题模式")),
        ks::settings::ui::ControlRow(themeButtonLayout, themeGroupBox));
    ks::ui::NormalizeToolbarRow(themeButtonLayout, 0);

    // ===== 自定义主题色分组 =====
    QWidget* themeColorGroupBox = new QWidget(themeGroupBox); // 主题色是一行，不嵌套第二层分区。
    QVBoxLayout* themeColorLayout = new QVBoxLayout(themeColorGroupBox);
    themeColorLayout->setContentsMargins(0, 0, 0, 0);
    themeColorLayout->setSpacing(0);

    QHBoxLayout* themeColorActionLayout = new QHBoxLayout();
    themeColorActionLayout->setSpacing(6);

    m_chooseThemeColorButton = new QPushButton(QStringLiteral("自定义主题色"), themeColorGroupBox);
    languageManager.bindToolTip(m_chooseThemeColorButton,
        QStringLiteral("settings.theme.color.hint"),
        QStringLiteral("自定义主主题色会保留现有深浅主题偏移；修改前会显示兼容性提示。"));
    themeColorActionLayout->addWidget(m_chooseThemeColorButton, 0);

    m_resetThemeColorButton = new QPushButton(QStringLiteral("一键复原"), themeColorGroupBox);
    languageManager.bindText(m_resetThemeColorButton, QStringLiteral("settings.theme.color.reset"), QStringLiteral("一键复原"));
    themeColorActionLayout->addWidget(m_resetThemeColorButton, 0);
    themeColorActionLayout->addStretch();
    themeColorLayout->addLayout(themeColorActionLayout);
    ks::ui::NormalizeToolbarRow(themeColorActionLayout);
    themeForm->addRow(ks::settings::ui::Label(themeGroupBox,
        QStringLiteral("settings.theme.color.group"), QStringLiteral("主题色")), themeColorGroupBox);

    // 配色预览紧邻主体色设置；样例颜色来自未应用种子，保留原应用/取消语义。
    QGroupBox* previewGroupBox = new QGroupBox(themeGroupBox);
    languageManager.bindText(previewGroupBox, QStringLiteral("settings.theme.preview.group"),
        QStringLiteral("配色预览"));
    QVBoxLayout* previewLayout = new QVBoxLayout(previewGroupBox); // 限定预览与说明的局部布局。
    QLabel* previewHint = new QLabel(previewGroupBox); // 说明当前展示的是待应用配色。
    previewHint->setWordWrap(true);
    languageManager.bindText(previewHint, QStringLiteral("settings.theme.preview.hint"),
        QStringLiteral("预览待应用的主题、主体色和背景色；点击“应用”后才会改变主界面。"));
    previewLayout->addWidget(previewHint);
    m_themeComponentPreview = new ks::ui::ThemePreviewWidget(previewGroupBox);
    previewLayout->addWidget(m_themeComponentPreview);
    secondaryLayout->addWidget(previewGroupBox);
    ks::settings::ui::Section(previewGroupBox);

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
    fontLayout->removeWidget(fontLabel);
    themeForm->addRow(fontLabel, ks::settings::ui::ControlRow(fontLayout, themeGroupBox));

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
    ks::settings::ui::ToggleRow(themeForm, m_textAntialiasingCheckBox,
        QStringLiteral("settings.text_antialiasing.enabled"), QStringLiteral("启用文本抗锯齿"));
    primaryLayout->addWidget(themeGroupBox);
    ks::settings::ui::Section(themeGroupBox);

    // ===== 窗口背景分组 =====
    QGroupBox* backgroundGroupBox = new QGroupBox(QStringLiteral("窗口背景"), m_appearanceTab);
    languageManager.bindText(backgroundGroupBox, QStringLiteral("settings.background.group"), QStringLiteral("窗口背景"));
    QVBoxLayout* backgroundLayout = new QVBoxLayout(backgroundGroupBox);
    backgroundLayout->setSpacing(8);
    auto* backgroundForm = ks::settings::ui::Form(backgroundLayout);

    QHBoxLayout* mainBackgroundColorActionLayout = new QHBoxLayout();
    mainBackgroundColorActionLayout->setSpacing(6);

    m_chooseMainBackgroundColorButton = new QPushButton(
        QStringLiteral("自定义主背景色"),
        backgroundGroupBox);
    languageManager.bindToolTip(m_chooseMainBackgroundColorButton,
        QStringLiteral("settings.background.color.hint"),
        QStringLiteral("主背景色可独立于主题色自定义；恢复默认后随浅色/深色模式切换。"));
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
    backgroundForm->addRow(ks::settings::ui::Label(backgroundGroupBox,
        QStringLiteral("settings.background.color.short"), QStringLiteral("主背景色")),
        ks::settings::ui::ControlRow(mainBackgroundColorActionLayout, backgroundGroupBox));
    ks::ui::NormalizeToolbarRow(mainBackgroundColorActionLayout);

    QHBoxLayout* pathLayout = new QHBoxLayout();
    pathLayout->setSpacing(6);

    // m_backgroundPathEdit 作用：用户输入背景图路径文本。
    m_backgroundPathEdit = new QLineEdit(backgroundGroupBox);
    m_backgroundPathEdit->setPlaceholderText(QStringLiteral("Style/ksword_background.png"));
    languageManager.bindToolTip(m_backgroundPathEdit,
        QStringLiteral("settings.background.path_hint"),
        QStringLiteral("选择一张图片作为窗口背景（支持 PNG/JPG/BMP）。"));
    pathLayout->addWidget(m_backgroundPathEdit, 1);

    // m_browseBackgroundButton 作用：打开文件对话框选择背景图。
    m_browseBackgroundButton = new QToolButton(backgroundGroupBox);
    m_browseBackgroundButton->setIcon(QIcon(QString::fromUtf8(":/Icon/settings_background_browse.svg")));
    KswordTheme::ApplyStandardIconButtonMetrics(m_browseBackgroundButton);
    m_browseBackgroundButton->setToolTip(QStringLiteral("浏览背景图文件"));
    languageManager.bindToolTip(m_browseBackgroundButton, QStringLiteral("settings.background.browse.tooltip"), QStringLiteral("浏览背景图文件"));
    pathLayout->addWidget(m_browseBackgroundButton);

    // m_resetBackgroundButton 作用：恢复默认背景路径。
    m_resetBackgroundButton = new QToolButton(backgroundGroupBox);
    m_resetBackgroundButton->setIcon(QIcon(QString::fromUtf8(":/Icon/settings_background_reset.svg")));
    KswordTheme::ApplyStandardIconButtonMetrics(m_resetBackgroundButton);
    m_resetBackgroundButton->setToolTip(QStringLiteral("恢复默认背景路径"));
    languageManager.bindToolTip(m_resetBackgroundButton, QStringLiteral("settings.background.reset.tooltip"), QStringLiteral("恢复默认背景路径"));
    pathLayout->addWidget(m_resetBackgroundButton);

    backgroundForm->addRow(ks::settings::ui::Label(backgroundGroupBox,
        QStringLiteral("settings.background.path.short"), QStringLiteral("背景图")),
        ks::settings::ui::ControlRow(pathLayout, backgroundGroupBox));
    ks::ui::NormalizeToolbarRow(pathLayout);

    QHBoxLayout* opacityLayout = new QHBoxLayout();
    opacityLayout->setSpacing(6);

    // m_backgroundOpacitySlider 作用：控制背景图透明度数值。
    m_backgroundOpacitySlider = new QSlider(Qt::Horizontal, backgroundGroupBox);
    m_backgroundOpacitySlider->setRange(0, 100);
    m_backgroundOpacitySlider->setSingleStep(1);
    m_backgroundOpacitySlider->setPageStep(5);
    m_backgroundOpacitySlider->setToolTip(QStringLiteral("拖动调整背景图透明度"));
    languageManager.bindToolTip(m_backgroundOpacitySlider, QStringLiteral("settings.background.opacity"),
        QStringLiteral("背景图透明度（0% 仅纯色背景，100% 仅背景图）"));
    opacityLayout->addWidget(m_backgroundOpacitySlider, 1);

    // m_backgroundOpacityValueLabel 作用：展示当前透明度百分比。
    m_backgroundOpacityValueLabel = new QLabel(QStringLiteral("35%"), backgroundGroupBox);
    m_backgroundOpacityValueLabel->setMinimumWidth(48);
    opacityLayout->addWidget(m_backgroundOpacityValueLabel);

    backgroundForm->addRow(ks::settings::ui::Label(backgroundGroupBox,
        QStringLiteral("settings.background.opacity.short"), QStringLiteral("背景图透明度")),
        ks::settings::ui::ControlRow(opacityLayout, backgroundGroupBox));

    // 透明窗口效果单独成区，避免把系统合成参数与图片参数混在一起。
    auto* transparencyGroupBox = new QGroupBox(m_appearanceTab);
    languageManager.bindText(transparencyGroupBox,
        QStringLiteral("settings.background.transparency.group"), QStringLiteral("透明窗口"));
    auto* transparencyLayout = new QVBoxLayout(transparencyGroupBox);
    auto* transparencyForm = ks::settings::ui::Form(transparencyLayout);

    // m_backgroundTransparencyCheckBox 作用：切换窗口透明背景（背景图 alpha 穿透 / 云母材质）。
    m_backgroundTransparencyCheckBox = new QCheckBox(QStringLiteral("透明窗口背景（重启后生效）"), backgroundGroupBox);
    languageManager.bindText(m_backgroundTransparencyCheckBox, QStringLiteral("settings.background.transparency"), QStringLiteral("透明窗口背景（重启后生效）"));
    m_backgroundTransparencyCheckBox->setToolTip(QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    languageManager.bindToolTip(m_backgroundTransparencyCheckBox, QStringLiteral("settings.background.transparency.tooltip"), QStringLiteral("勾选后窗口背景变为透明：设置了背景图时，图片中透明的部分（需要带透明通道的 PNG）直接显示后面的桌面；没有背景图时，窗口呈现磨砂玻璃效果。具体呈现方式可在下方“透明背景效果”中选择。重启 Ksword 后生效。"));
    ks::settings::ui::ToggleRow(transparencyForm, m_backgroundTransparencyCheckBox,
        QStringLiteral("settings.background.transparency"), QStringLiteral("透明窗口背景（重启后生效）"));

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
    translucencyMaterialLayout->removeWidget(translucencyMaterialLabel);
    transparencyForm->addRow(translucencyMaterialLabel,
        ks::settings::ui::ControlRow(translucencyMaterialLayout, transparencyGroupBox));

    // ===== 玻璃观感三滑块 =====
    // 说明：磨砂玻璃由系统合成，其模糊半径在 Windows 内部固定（未公开的 ACCENT_POLICY
    // 没有半径字段），因此“玻璃模糊半径”作用于应用自绘的背景图模糊层；
    // 两个着色不透明度则分别对应磨砂着色（系统混合）与直透着色（自绘兜底）。

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

    backgroundForm->addRow(ks::settings::ui::Label(backgroundGroupBox,
        QStringLiteral("settings.background.blur_radius.short"), QStringLiteral("背景图模糊半径")),
        ks::settings::ui::ControlRow(blurRadiusLayout, backgroundGroupBox));

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

    transparencyForm->addRow(ks::settings::ui::Label(transparencyGroupBox,
        QStringLiteral("settings.background.acrylic_tint.short"), QStringLiteral("磨砂着色不透明度")),
        ks::settings::ui::ControlRow(acrylicTintLayout, transparencyGroupBox));

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

    transparencyForm->addRow(ks::settings::ui::Label(transparencyGroupBox,
        QStringLiteral("settings.background.desktop_tint.short"), QStringLiteral("直透着色不透明度")),
        ks::settings::ui::ControlRow(desktopTintLayout, transparencyGroupBox));

    // 组合框与两个着色滑块的可用性跟随透明总开关；初始状态由 applySettingsToUi 同步。
    // 模糊半径作用于背景图自绘层，不依赖窗口透明，因此始终可用。
    m_backgroundTranslucencyMaterialCombo->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_backgroundTranslucencyMaterialCombo, &QWidget::setEnabled);
    m_acrylicTintOpacitySlider->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_acrylicTintOpacitySlider, &QWidget::setEnabled);
    m_desktopTintOpacitySlider->setEnabled(m_backgroundTransparencyCheckBox->isChecked());
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled, m_desktopTintOpacitySlider, &QWidget::setEnabled);
    primaryLayout->addWidget(backgroundGroupBox);
    primaryLayout->addWidget(transparencyGroupBox);
    ks::settings::ui::Section(backgroundGroupBox);
    ks::settings::ui::Section(transparencyGroupBox);
    // 总开关关闭时，参数标签和数值一起降低强调，仍保留禁用项的位置与说明。
    const auto syncTransparencyLabels = [transparencyForm, this](bool enabled)
    {
        for (int row = 1; row < transparencyForm->rowCount(); ++row)
        {
            QLayoutItem* labelItem = transparencyForm->itemAt(row, QFormLayout::LabelRole);
            if (labelItem != nullptr && labelItem->widget() != nullptr)
            {
                labelItem->widget()->setEnabled(enabled);
            }
        }
        m_acrylicTintOpacityValueLabel->setEnabled(enabled);
        m_desktopTintOpacityValueLabel->setEnabled(enabled);
    };
    connect(m_backgroundTransparencyCheckBox, &QCheckBox::toggled,
        this, syncTransparencyLabels);
    syncTransparencyLabels(m_backgroundTransparencyCheckBox->isChecked());

    // ===== 交互与滚动分组 =====
    QGroupBox* interactionGroupBox = new QGroupBox(QStringLiteral("交互与滚动"), m_appearanceTab);
    languageManager.bindText(interactionGroupBox, QStringLiteral("settings.interaction.group"), QStringLiteral("交互与滚动"));
    QVBoxLayout* interactionLayout = new QVBoxLayout(interactionGroupBox);
    interactionLayout->setSpacing(8);
    auto* interactionForm = ks::settings::ui::Form(interactionLayout, 176);

    m_smoothScrollingCheckBox = new QCheckBox(
        QStringLiteral("启用全局平滑滚动"),
        interactionGroupBox);
    languageManager.bindText(
        m_smoothScrollingCheckBox,
        QStringLiteral("settings.scroll.smooth"),
        QStringLiteral("启用全局平滑滚动"));
    m_smoothScrollingCheckBox->setToolTip(
        QStringLiteral("对标签栏、表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    languageManager.bindToolTip(
        m_smoothScrollingCheckBox,
        QStringLiteral("settings.scroll.smooth.tooltip"),
        QStringLiteral("对标签栏、表格、列表、文本区和滚动页的鼠标滚轮滚动使用缓动动画"));
    ks::settings::ui::ToggleRow(interactionForm, m_smoothScrollingCheckBox,
        QStringLiteral("settings.scroll.smooth"), QStringLiteral("启用全局平滑滚动"));

    m_sliderWheelAdjustCheckBox = new QCheckBox(QStringLiteral("允许滚轮调整控件值和切换标签页"), interactionGroupBox);
    languageManager.bindText(m_sliderWheelAdjustCheckBox, QStringLiteral("settings.slider.wheel"), QStringLiteral("允许滚轮调整控件值和切换标签页"));
    m_sliderWheelAdjustCheckBox->setToolTip(QStringLiteral("默认关闭：滚轮在标签栏上只滚动标签，不切换页面；在滑块、下拉框和数值输入框上只滚动页面。启用后允许滚轮调值和切换标签页；展开的下拉列表仍可滚动"));
    languageManager.bindToolTip(m_sliderWheelAdjustCheckBox, QStringLiteral("settings.slider.wheel.tooltip"), QStringLiteral("默认关闭：滚轮在标签栏上只滚动标签，不切换页面；在滑块、下拉框和数值输入框上只滚动页面。启用后允许滚轮调值和切换标签页；展开的下拉列表仍可滚动"));
    ks::settings::ui::ToggleRow(interactionForm, m_sliderWheelAdjustCheckBox,
        QStringLiteral("settings.slider.wheel"), QStringLiteral("允许滚轮调整控件值和切换标签页"));

    secondaryLayout->addWidget(interactionGroupBox);
    ks::settings::ui::Section(interactionGroupBox);

    // 详情位置沿用稳定枚举值，用下拉代替四行单选，保持宽页信息密度。
    m_detailSchemeCombo = new QComboBox(interactionGroupBox);
    const auto addDetailScheme = [this, &languageManager](
        ks::settings::DetailDisplayScheme scheme, const QString& key, const QString& fallback)
    {
        m_detailSchemeCombo->addItem(fallback, static_cast<int>(scheme));
        languageManager.bindComboBoxItem(m_detailSchemeCombo,
            m_detailSchemeCombo->count() - 1, key, fallback);
    };
    addDetailScheme(ks::settings::DetailDisplayScheme::BottomCollapsed,
        QStringLiteral("settings.detail_layout.bottom_collapsed"), QStringLiteral("下方折叠（默认）"));
    addDetailScheme(ks::settings::DetailDisplayScheme::Right,
        QStringLiteral("settings.detail_layout.right"), QStringLiteral("表格右侧"));
    addDetailScheme(ks::settings::DetailDisplayScheme::Embedded,
        QStringLiteral("settings.detail_layout.embedded"), QStringLiteral("行内嵌入"));
    addDetailScheme(ks::settings::DetailDisplayScheme::Floating,
        QStringLiteral("settings.detail_layout.floating"), QStringLiteral("独立窗口"));
    languageManager.bindToolTip(m_detailSchemeCombo,
        QStringLiteral("settings.detail_layout.hint"),
        QStringLiteral("统一设置表格当前行详情的显示位置；点击应用后立即生效。"));
    interactionForm->addRow(ks::settings::ui::Label(interactionGroupBox,
        QStringLiteral("settings.detail_layout.group"), QStringLiteral("详情页显示方案")), m_detailSchemeCombo);
    ks::ui::NormalizeToolbarControl(m_detailSchemeCombo);
    ks::ui::StyleSecondaryForm(interactionForm, 176);

    // 两列使用统一自适应容器。附属开关继续在同页可见，不折叠或增加标签页。
    primaryLayout->addStretch();
    secondaryLayout->addStretch();
    appearanceRootLayout->addWidget(ks::ui::CreateSecondaryColumns(
        primaryColumn, secondaryColumn, m_appearanceTab, 1000, 3, 2));
    initializeAppearanceSupplement(appearanceRootLayout);
    m_appearanceTab = ks::settings::ui::ScrollPage(m_appearanceTab);

    appearanceRootLayout->addStretch();
    m_tabWidget->addTab(m_appearanceTab, QStringLiteral("外观"));
    languageManager.bindTab(m_tabWidget, m_appearanceTab, QStringLiteral("settings.tab.appearance"), QStringLiteral("外观"));

}

