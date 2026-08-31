#pragma once

// ============================================================
// AppearanceSettings.h
// 作用：
// - 定义“界面与启动设置”数据结构（主题模式、背景图路径、透明度、启动默认页签、启动行为）；
// - 定义 JSON 读写与路径解析函数，供 SettingsDock/MainWindow 复用；
// - 统一默认值，避免多处硬编码。
// ============================================================

#include <QString>

namespace ks::settings
{
    // ThemeMode：主题模式枚举。
    // FollowSystem：跟随系统；Light：浅色；Dark：深色。
    enum class ThemeMode
    {
        FollowSystem = 0,
        Light = 1,
        Dark = 2
    };

    // NotificationDisplayPlacement：通知卡片的承载区域。
    // Screen：显示在主窗口所在显示器的工作区；MainWindow：显示在主窗口 Dock 客户区内。
    enum class NotificationDisplayPlacement
    {
        Screen = 0,
        MainWindow = 1
    };

    // NotificationStackDirection：右侧通知卡片的堆叠方向。
    enum class NotificationStackDirection
    {
        BottomUp = 0,
        TopDown = 1
    };

    // DetailDisplayScheme：严格命中页面的统一详情布局方案。
    // BottomCollapsed：表格下方折叠；Right：表格右侧；
    // Embedded：在数据行后插入详情行；Floating：每个页面使用独立详情窗口。
    enum class DetailDisplayScheme
    {
        BottomCollapsed = 0,
        Right = 1,
        Embedded = 2,
        Floating = 3
    };

    // AppearanceSettings：界面与启动设置结构体。
    // themeMode：当前主题策略；
    // customThemeColor：用户自定义的主主题色（#RRGGBB）；空值表示使用内置默认色。
    // customMainBackgroundColor：用户自定义的主背景色（#RRGGBB）；空值表示跟随当前深浅主题。
    // backgroundImagePath：背景图路径（可相对可绝对）；
    // backgroundOpacityPercent：背景图透明度（0~100）；
    // backgroundTransparencyEnabled：是否让背景图片自身的 alpha 透明区域透出窗口后方；
    // backgroundTranslucencyMaterial：透明背景效果
    // （auto=有图直透无图磨砂，acrylic=始终亚克力磨砂，desktop=始终直透桌面；
    //   blur/mica 为历史取值，按 acrylic 处理）；
    // backgroundBlurRadiusPercent：玻璃模糊半径强度（0~100，0=不模糊）；
    //   作用于窗口背景图的自绘高斯模糊，主窗口与浮动 Dock 共用同一张模糊底图。
    //   注意：系统亚克力（磨砂玻璃）的模糊半径由 Windows DWM 内部固定，
    //   SetWindowCompositionAttribute 的 ACCENT_POLICY 不提供半径字段，无法调整。
    // acrylicTintOpacityPercent：磨砂玻璃着色层不透明度（0~100）；
    //   由组合特性的 gradientColor alpha 直接混合到系统模糊结果上，越低越通透。
    // desktopTintOpacityPercent：直透模式着色层不透明度（0~100）；
    //   系统磨砂未生效时由根容器自绘，0 表示几乎完全直透（仍保留 1/255 命中底线）。
    // startupDefaultTabKey：应用启动时默认激活的主页签 key（如 welcome/process/network）；
    // launchMaximizedOnStartup：下次启动时是否默认最大化显示；
    // startupTopMostEnabled：启动后是否自动启用最高级置顶，手动图钉切换会同步保存；
    // autoRequestAdminOnStartup：下次启动时是否在启动图出现前先尝试申请管理员权限；
    // preventMultipleInstances：普通启动时是否防止多开；权限切换重启依然允许接管。
    // startupWindowScaleFactor：主窗口启动缩放因子（1.0=100%，重启后生效）；
    // startupScaleRecommendPromptDisabled：小屏推荐缩放提示是否不再弹出。
    // unlockerShellContextMenuEnabled：是否启用“系统右键-文件解锁器”菜单（下次启动生效）。
    // useWideScrollBars：是否使用宽滚动条（false=默认窄版）；
    // scrollBarAutoHideEnabled：滚动条是否启用自动隐藏/悬停展开；
    // smoothScrollingEnabled：是否对全局滚动区域启用滚轮缓动；
    // sliderWheelAdjustEnabled：是否允许滚轮直接调整滑块值。
    // fontFamily：应用界面字体族；空值表示沿用系统默认字体。
    // textAntialiasingEnabled：是否以应用默认字体启用文本抗锯齿。
    // dumpAutoCheckEnabled：启动后是否检查系统近期是否产生过新的崩溃转储。
    // dumpAutoCheckPromptedPath / dumpAutoCheckPromptedTimeMsec：
    //   已经问过用户的那个转储的路径与修改时间，用来避免同一个转储反复弹窗；
    //   时间一并记录是因为 MEMORY.DMP 路径固定、内容会被后一次崩溃覆盖，
    //   只比路径会漏掉新转储。
    // suppressR0FeaturePrompts：是否关闭 R0 驱动未启用或权限不足时的自动提示。
    // suppressDangerousActionConfirmations：是否跳过危险操作的重复模态确认；风险信息、预检和审计不受影响。
    // bugcheckDiagnosticsAutoInstallEnabled：驱动启动成功后，R3 是否发送蓝屏诊断安装 IOCTL。
    // false 时不触发 BGP 扫描、不注册诊断回调，除非本次会话由用户明确安装。
    // virusTotalApiKey：VirusTotal 在线扫描 API Key，供 OnlineScan 模块运行时读取。
    // threatBookApiKey：ThreatBook（微步在线）在线扫描 API Key，供 OnlineScan 模块运行时读取。
    struct AppearanceSettings
    {
        ThemeMode themeMode = ThemeMode::FollowSystem;
        QString customThemeColor;
        QString customMainBackgroundColor;
        QString uiLanguage = QStringLiteral("system");
        QString backgroundImagePath = QStringLiteral("Style/ksword_background.png");
        int backgroundOpacityPercent = 35;
        bool backgroundTransparencyEnabled = false;
        QString backgroundTranslucencyMaterial = QStringLiteral("auto");
        int backgroundBlurRadiusPercent = 0;
        int acrylicTintOpacityPercent = 75;
        int desktopTintOpacityPercent = 65;
        QString startupDefaultTabKey = QStringLiteral("welcome");
        bool launchMaximizedOnStartup = true;
        bool startupTopMostEnabled = false;
        bool autoRequestAdminOnStartup = true;
        bool preventMultipleInstances = true;
        double startupWindowScaleFactor = 1.0;
        bool startupScaleRecommendPromptDisabled = false;
        bool unlockerShellContextMenuEnabled = false;
        bool useWideScrollBars = false;
        bool scrollBarAutoHideEnabled = false;
        bool smoothScrollingEnabled = true;
        bool sliderWheelAdjustEnabled = false;
        DetailDisplayScheme detailDisplayScheme = DetailDisplayScheme::BottomCollapsed;
        QString fontFamily;
        bool textAntialiasingEnabled = true;
        bool notificationCardsEnabled = true;
        int notificationMinimumLevel = 2; // Warn，数值与 kLogLevel 的严重度顺序保持一致。
        int notificationLogDisplaySeconds = 10;
        int notificationMaximumVisibleLogCards = 0; // 0 表示不限制，由可用显示空间决定。
        bool notificationLogHeightLimitEnabled = true;
        int notificationLogMaximumLines = 5;
        NotificationDisplayPlacement notificationDisplayPlacement = NotificationDisplayPlacement::Screen;
        NotificationStackDirection notificationStackDirection = NotificationStackDirection::BottomUp;
        bool dumpAutoCheckEnabled = true;
        QString dumpAutoCheckPromptedPath;
        qint64 dumpAutoCheckPromptedTimeMsec = 0;
        bool suppressR0FeaturePrompts = false;
        bool suppressDangerousActionConfirmations = false;
        bool bugcheckDiagnosticsAutoInstallEnabled = false;
        QString logWindowGeometryBase64;
        QString virusTotalApiKey;
        QString threatBookApiKey;
    };

    // tintAlphaFromOpacityPercent 作用：
    // - 把 0~100 的着色不透明度换算成 0~255 的 alpha 通道值；
    // - 磨砂着色（系统 gradientColor）与直透着色（根容器自绘）共用同一映射，
    //   避免设置页显示的百分比和实际绘制的 alpha 各算一套而对不上。
    // 调用方式：绘制着色层或下发组合特性前调用。
    // 入参 opacityPercent：着色不透明度百分比，越界自动钳制到 0~100。
    // 返回：0~255 的 alpha 值。
    int tintAlphaFromOpacityPercent(int opacityPercent);

    // themeModeToJsonText 作用：
    // - 把主题枚举转成 JSON 存档文本。
    // 调用方式：保存配置前调用。
    // 入参 mode：主题枚举值。
    // 返回：可写入 JSON 的字符串。
    QString themeModeToJsonText(ThemeMode mode);

    // themeModeFromJsonText 作用：
    // - 把 JSON 文本还原为主题枚举。
    // 调用方式：读取配置后调用。
    // 入参 jsonText：JSON 中的主题字段。
    // 返回：解析后的主题枚举，非法值回退 FollowSystem。
    ThemeMode themeModeFromJsonText(const QString& jsonText);

    // detailDisplaySchemeToJsonText / detailDisplaySchemeFromJsonText：
    // - 在稳定 JSON 文本与详情布局枚举之间转换；
    // - 未知文本统一回退为默认的下方折叠方案。
    // 调用方式：AppearanceSettings JSON 读写与设置日志使用。
    // 入参 scheme/jsonText：布局枚举或配置文本；返回：对应文本或合法枚举。
    QString detailDisplaySchemeToJsonText(DetailDisplayScheme scheme);
    DetailDisplayScheme detailDisplaySchemeFromJsonText(const QString& jsonText);

    // appearanceSettingsJsonRelativePath 作用：
    // - 返回外观配置 JSON 的默认相对路径。
    // 调用方式：构建读写路径时调用。
    // 返回：例如 Style/appearance_settings.json。
    QString appearanceSettingsJsonRelativePath();

    // resolveSettingsJsonPathForRead 作用：
    // - 获取读取 JSON 时优先使用的绝对路径。
    // 调用方式：loadAppearanceSettings 内部调用。
    // 返回：最终用于读文件的绝对路径。
    QString resolveSettingsJsonPathForRead();

    // settingsJsonFileExistsForRead 作用：
    // - 判断启动时是否已经存在可读取的配置文件；
    // - 供 main 区分“首次启动”与“按已有配置启动”。
    // 返回：true=存在配置文件；false=不存在。
    bool settingsJsonFileExistsForRead();

    // resolveSettingsJsonPathForWrite 作用：
    // - 获取保存 JSON 时使用的绝对路径。
    // 调用方式：saveAppearanceSettings 内部调用。
    // 返回：最终用于写文件的绝对路径。
    QString resolveSettingsJsonPathForWrite();

    // resolveBackgroundImagePathForLoad 作用：
    // - 把“用户输入路径”解析为可加载图片的绝对路径。
    // 调用方式：MainWindow 应用背景图时调用。
    // 入参 imagePathText：配置中的路径文本（相对或绝对）。
    // 返回：绝对路径（若原路径为空则返回空字符串）。
    QString resolveBackgroundImagePathForLoad(const QString& imagePathText);

    // loadAppearanceSettings 作用：
    // - 从 JSON 读取界面与启动设置；
    // - 文件不存在或解析失败时回退默认值。
    // 调用方式：程序启动时调用。
    // 返回：界面与启动配置结构体。
    AppearanceSettings loadAppearanceSettings();

    // saveAppearanceSettings 作用：
    // - 把界面与启动设置写入 JSON 文件（自动创建目录）。
    // 调用方式：用户在设置页修改后调用；深层危险确认策略菜单也复用该持久化入口。
    // 入参 settings：待保存配置；
    // 入参 errorTextOut：可选错误文本输出指针。
    // 返回：true=保存成功；false=保存失败。
    bool saveAppearanceSettings(const AppearanceSettings& settings, QString* errorTextOut = nullptr);

    // dangerousActionConfirmationsSuppressed 作用：
    // - 返回当前持久设置是否允许跳过危险操作的重复模态确认；
    // - 仅影响 UI 模态框，不绕过驱动确认令牌、SafetyPolicy、目标复核或审计。
    // 调用方式：危险操作入口在决定是否弹窗前调用。
    // 返回：true=可跳过重复模态确认；false=仍需逐次询问。
    bool dangerousActionConfirmationsSuppressed();

    // MinimumWindowScaleFactor / MaximumWindowScaleFactor 作用：
    // - 窗口缩放因子的唯一合法区间，normalizeWindowScaleFactor 按此钳制；
    // - 设置页据此生成可选范围，避免界面限制与落盘钳制各写一份而失配。
    inline constexpr double MinimumWindowScaleFactor = 0.50;
    inline constexpr double MaximumWindowScaleFactor = 2.00;

    // normalizeWindowScaleFactor 作用：
    // - 统一校正窗口缩放因子到合法范围；
    // - 非法值（NaN/Inf/<=0）回退为 1.0。
    // 调用方式：读取配置、保存配置、启动前应用缩放时调用。
    // 入参 rawScaleFactor：原始缩放因子值。
    // 返回：合法缩放因子（范围 MinimumWindowScaleFactor~MaximumWindowScaleFactor）。
    double normalizeWindowScaleFactor(double rawScaleFactor);
}
