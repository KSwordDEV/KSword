#include "WelcomeDock.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/UI.css/UI_css.h"
#include "../theme.h"
#include <QColor>
#include <QEvent>
#include <QHideEvent>
#include <QPainter>
#include <QPaintEvent>
#include <QPixmap>
#include <QShowEvent>
#include <QTimer>

namespace
{
    // WelcomeRgbBorderButton 作用：
    // - 常规背景、文字及交互状态继续交给 QPushButton/QSS 绘制；
    // - RGB 动画每帧只更新边框颜色并重绘按钮，不重复解析整段样式表。
    class WelcomeRgbBorderButton final : public QPushButton
    {
    public:
        using QPushButton::QPushButton;

        // setBorderColor 作用：更新当前 RGB 边框颜色；相同颜色不触发重复绘制。
        void setBorderColor(const QColor& borderColor)
        {
            if (m_borderColor == borderColor)
            {
                return;
            }
            m_borderColor = borderColor;
            update();
        }

    protected:
        // paintEvent 作用：在 QPushButton 完成基础绘制后叠加当前 RGB 圆角边框。
        void paintEvent(QPaintEvent* event) override
        {
            QPushButton::paintEvent(event);

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(m_borderColor, 3.0));

            // borderRect 用途：让 3px 画笔完全落在按钮内部，避免边缘被裁剪。
            constexpr qreal halfPenWidth = 1.5;
            const QRectF borderRect =
                QRectF(rect()).adjusted(halfPenWidth, halfPenWidth, -halfPenWidth, -halfPenWidth);
            painter.drawRoundedRect(borderRect, 9.0, 9.0);
        }

    private:
        QColor m_borderColor = QColor::fromHsv(0, 255, 255); // 当前 RGB 边框颜色。
    };

    // kReleaseVersionText 作用：
    // - 欢迎页显示的版本号文本；
    // - 由发布脚本按注释标记替换。
    const QString kReleaseVersionText = QStringLiteral("5.1.4.3正式版"); // RELEASE_META_VERSION_MARKER

    // kReleaseBuildTimeText 作用：
    // - 欢迎页显示的精确编译时间；
    // - 由发布脚本按注释标记替换。
    const QString kReleaseBuildTimeText = QStringLiteral("2026-08-17 22:41:10.119 +08:00"); // RELEASE_META_BUILD_TIME_MARKER

    // kQQGroupInviteUrl 作用：QQ 群按钮点击后打开的官方加群邀请链接。
    const QString kQQGroupInviteUrl = QStringLiteral("https://qm.qq.com/q/5tWNPfIxkk");

    // kPplControlRepositoryUrl 作用：参考项目按钮点击后打开 PPLcontrol 仓库。
    const QString kPplControlRepositoryUrl = QStringLiteral("https://github.com/itm4n/PPLcontrol");

    // kSystemInformerRepositoryUrl 作用：参考项目按钮点击后打开 System Informer 仓库。
    const QString kSystemInformerRepositoryUrl = QStringLiteral("https://github.com/winsiderss/systeminformer");

    // kSkt64RepositoryUrl 作用：参考项目按钮点击后打开 SKT64 仓库。
    const QString kSkt64RepositoryUrl = QStringLiteral("https://github.com/PspExitThread/SKT64");

    // welcomeLogoResourcePath 作用：
    // - 根据当前有效界面语言选择欢迎页图片；
    // - 中文语言使用中文版本，其余语言使用英文版本。
    QString welcomeLogoResourcePath()
    {
        const QString currentLanguageId =
            ks::i18n::LanguageManager::instance().currentLanguageId();
        return currentLanguageId.startsWith(QStringLiteral("zh"), Qt::CaseInsensitive)
            ? QStringLiteral(":/Image/Resource/Logo/KswordHome-ZH.png")
            : QStringLiteral(":/Image/Resource/Logo/KswordHome-En.png");
    }
}

WelcomeDock::WelcomeDock(QWidget* parent) : QWidget(parent) {
    // ==== 1. 初始化组件 ====
    // 左侧图片：显示项目主 Logo；本构造函数仅初始化 UI，无返回值。
    m_leftImage = new QLabel(this);
    // 固定为图片原始尺寸，避免布局伸缩导致 Logo 模糊或变形。
    m_leftImage->setFixedSize(655, 250);
    // 关闭自动扩展，保持欢迎页视觉中心稳定。
    m_leftImage->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    m_leftImage->setAlignment(Qt::AlignCenter);

    // 语言设置入口：固定放在 Logo 下方，并以 RGB 循环边框突出显示。
    m_languageSettingsBtn = new WelcomeRgbBorderButton(
        QStringLiteral("🌍language setting 语言设置"),
        this);
    m_languageSettingsBtn->setObjectName(QStringLiteral("welcomeLanguageSettingsButton"));
    m_languageSettingsBtn->setMinimumHeight(48);
    m_languageSettingsBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_languageSettingsBtn->setCursor(Qt::PointingHandCursor);
    initializeLanguageButtonStyle();
    updateLanguageButtonRgbBorder();

    m_languageButtonColorTimer = new QTimer(this);
    m_languageButtonColorTimer->setInterval(80);
    m_languageButtonColorTimer->setTimerType(Qt::CoarseTimer);
    connect(m_languageButtonColorTimer, &QTimer::timeout, this, [this]() {
        m_languageButtonHue = (m_languageButtonHue + 4) % 360;
        updateLanguageButtonRgbBorder();
    });

    // 版权信息：展示团队信息、版本号和编译时间。
    m_copyright = new QLabel(this);
    // 欢迎页发布信息：
    // - 版本号使用更大字号；
    // - 编译时间在下方备注显示，便于定位发布批次。
    m_copyright->setText(
        QStringLiteral(
            "Ksword Dev 卡利剑ARK工具开发团队 保留所有权利。<br>"
            "<span style='font-size:18px;font-weight:700;'>当前版本：%1</span><br>"
            "<span style='font-size:12px;'>编译时间：%2</span><br>")
        .arg(kReleaseVersionText, kReleaseBuildTimeText));
    m_copyright->setStyleSheet("line-height: 1.8;");
    m_copyright->setWordWrap(true); // 开启自动换行
    m_copyright->setTextInteractionFlags(Qt::TextSelectableByMouse); // 允许选中
    m_copyright->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    // 限制最大高度，避免发布信息在小窗口内挤占按钮区域。
    m_copyright->setMaximumHeight(140); // 发布信息增加“版本+编译时间”后提高可视高度，避免文本被裁切。

    // 贡献者信息：放在现有发布信息下方，避免改变顶部 Logo 与版本区的识别位置。
    m_contributors = new QLabel(this);
    // 文本格式：使用 HTML 加粗标题，名单保持纯文本便于后续追加。
    m_contributors->setText(QStringLiteral(
        "<b>贡献者：</b>WangWei_CM.，OB_BUFF，PipExitThread"));
    // 自动换行：当 Dock 宽度较窄时，贡献者名单可自然折行。
    m_contributors->setWordWrap(true);
    // 允许复制：用户可以直接复制贡献者名单。
    m_contributors->setTextInteractionFlags(Qt::TextSelectableByMouse);
    // 高度策略：仅占用文本所需高度，不挤压参考项目按钮。
    m_contributors->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    // 参考项目标题：与贡献者区域保持同一层级，提示下方按钮会打开外部仓库。
    m_referenceTitle = new QLabel(QStringLiteral("<b>参考项目：</b>"), this);
    // 标题高度固定在内容高度范围内，避免空白过多。
    m_referenceTitle->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    // 标题文本无需换行，但保留富文本显示能力。
    m_referenceTitle->setTextFormat(Qt::RichText);

    // 捐赠者信息：放在欢迎页底部扩展信息末尾，用于公开感谢当前捐赠者。
    m_donors = new QLabel(this);
    // 文本格式：使用 HTML 加粗标题，名单保持纯文本，便于后续追加更多捐赠者。
    m_donors->setText(QStringLiteral("<b>捐赠者：</b>长空落日,Extrella_Explorer,Txt Text,Mapleleaf,存钱买油条（云舟API）,Solicom,東雪蓮可爱捏,JIAN2486,NtKrnl64,一花一树叶,hzh"));
    // 自动换行：当 Dock 宽度较窄时，捐赠者名单可自然折行。
    m_donors->setWordWrap(true);
    // 允许复制：用户可以直接复制捐赠者名单。
    m_donors->setTextInteractionFlags(Qt::TextSelectableByMouse);
    // 高度策略：仅占用文本所需高度，不挤压上方按钮区域。
    m_donors->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    // 按钮样式：根据当前深浅色状态选择欢迎页按钮样式。
    // welcomeButtonStyle 作用：根据当前深浅色状态选择欢迎页按钮样式。
    const QString welcomeButtonStyle = KswordTheme::IsDarkModeEnabled() ? QSS_Buttons_Dark : QSS_Buttons_Light;

    // Github 按钮：保留项目仓库入口。
    m_githubBtn = new QPushButton("Github仓库", this);
    m_githubBtn->setStyleSheet(welcomeButtonStyle);
    m_githubBtn->setToolTip("打开项目 Github 仓库主页");

    // QQ 群按钮：保留项目交流群入口。
    m_qqBtn = new QPushButton("QQ群", this);
	m_qqBtn->setStyleSheet(welcomeButtonStyle);
    m_qqBtn->setToolTip("加入项目 QQ 交流群");

    // PPLcontrol 参考按钮：点击后打开上游参考仓库。
    m_pplControlBtn = new QPushButton("PPLcontrol", this);
    m_pplControlBtn->setStyleSheet(welcomeButtonStyle);
    m_pplControlBtn->setToolTip(QStringLiteral("打开 PPLcontrol 参考项目仓库"));

    // System Informer 参考按钮：点击后打开上游参考仓库。
    m_systemInformerBtn = new QPushButton("System Informer", this);
    m_systemInformerBtn->setStyleSheet(welcomeButtonStyle);
    m_systemInformerBtn->setToolTip(QStringLiteral("打开 System Informer 参考项目仓库"));

    // SKT64 参考按钮：点击后打开上游参考仓库。
    m_skt64Btn = new QPushButton("SKT64", this);
    m_skt64Btn->setStyleSheet(welcomeButtonStyle);
    m_skt64Btn->setToolTip(QStringLiteral("打开 SKT64 参考项目仓库"));

    // ==== 2. 布局管理 ====
    // 按钮布局：保留 Github 与 QQ 群，作为项目自身入口。
    m_btnLayout = new QHBoxLayout();
    m_btnLayout->addWidget(m_githubBtn, 1); // 占1份宽度
    m_btnLayout->addWidget(m_qqBtn, 1);
    m_btnLayout->setSpacing(10); // 按钮间距

    // 参考项目布局：三个按钮等宽展示，点击后均通过默认浏览器打开。
    m_referenceLayout = new QHBoxLayout();
    m_referenceLayout->addWidget(m_pplControlBtn, 1);
    m_referenceLayout->addWidget(m_systemInformerBtn, 1);
    m_referenceLayout->addWidget(m_skt64Btn, 1);
    // 参考按钮间距与项目入口按钮一致，保持欢迎页视觉节奏。
    m_referenceLayout->setSpacing(10);

    // 左侧布局：按 Logo、版权发布信息、按钮区排列。
    m_leftLayout = new QVBoxLayout();
    m_leftLayout->addWidget(m_leftImage);
    m_leftLayout->addWidget(m_languageSettingsBtn);
    m_leftLayout->addWidget(m_copyright);
    m_leftLayout->addLayout(m_btnLayout);
    // 贡献者：添加在现有项目入口下面，满足“在现有的东西下面加”的位置要求。
    m_leftLayout->addWidget(m_contributors);
    // 参考项目标题：放在贡献者下面，明确按钮含义。
    m_leftLayout->addWidget(m_referenceTitle);
    // 参考项目按钮：作为可点击仓库入口，不使用普通文本链接。
    m_leftLayout->addLayout(m_referenceLayout);
    // 捐赠者：放在欢迎页扩展信息最下方、弹性留白之前。
    m_leftLayout->addWidget(m_donors);
    // 底部留白由 stretch 承担，避免重复添加按钮布局。
    m_leftLayout->addStretch(1);
    m_leftLayout->setSpacing(20); // 组件间距
    m_leftLayout->setContentsMargins(20, 20, 20, 20); // 左布局内边距

    // 主布局：移除右侧用户区后，只承载欢迎主体内容。
    m_mainLayout = new QHBoxLayout(this);
    m_mainLayout->addLayout(m_leftLayout, 1); // 主体内容占满欢迎页宽度。
    m_mainLayout->setContentsMargins(0, 0, 0, 0); // 主布局无边距（消除白边）
    setLayout(m_mainLayout);

    // 构造期直接按当前语言生成欢迎页；后续 LanguageChange 会走同一入口。
    retranslateUi();

    // ==== 3. 信号连接 ====
    // 语言设置按钮：由主窗口复用顶部设置对话框，并直接定位到语言页签。
    connect(
        m_languageSettingsBtn,
        &QPushButton::clicked,
        this,
        &WelcomeDock::languageSettingsRequested);

    // Github 按钮：点击后交给系统默认浏览器打开项目仓库；无返回值。
    connect(m_githubBtn, &QPushButton::clicked, this, [=]() {
        QDesktopServices::openUrl(QUrl("https://github.com/WangWei-CM/KSword"));
        });

    // QQ 群按钮：点击后交给系统默认浏览器打开加群页面；无返回值。
    connect(m_qqBtn, &QPushButton::clicked, this, [=]() {
        QDesktopServices::openUrl(QUrl(kQQGroupInviteUrl));
        });

    // PPLcontrol 参考按钮：点击后打开参考仓库；无返回值。
    connect(m_pplControlBtn, &QPushButton::clicked, this, [=]() {
        QDesktopServices::openUrl(QUrl(kPplControlRepositoryUrl));
        });

    // System Informer 参考按钮：点击后打开参考仓库；无返回值。
    connect(m_systemInformerBtn, &QPushButton::clicked, this, [=]() {
        QDesktopServices::openUrl(QUrl(kSystemInformerRepositoryUrl));
        });

    // SKT64 参考按钮：点击后打开参考仓库；无返回值。
    connect(m_skt64Btn, &QPushButton::clicked, this, [=]() {
        QDesktopServices::openUrl(QUrl(kSkt64RepositoryUrl));
        });
}

void WelcomeDock::initializeLanguageButtonStyle()
{
    if (m_languageSettingsBtn == nullptr)
    {
        return;
    }

    // 静态样式使用动态 palette 角色；主背景色或主题模式变化时无需重建控件。
    // 透明边框为自绘 RGB 边框预留固定布局空间。
    m_languageSettingsBtn->setStyleSheet(QStringLiteral(
        "QPushButton#welcomeLanguageSettingsButton{"
        "  background-color:%1;"
        "  color:%2;"
        "  border:3px solid transparent;"
        "  border-radius:10px;"
        "  padding:8px 16px;"
        "  font-size:16px;"
        "  font-weight:700;"
        "}"
        "QPushButton#welcomeLanguageSettingsButton:hover{"
        "  background-color:%3;"
        "}"
        "QPushButton#welcomeLanguageSettingsButton:pressed{"
        "  background-color:%4;"
        "  padding-top:9px;"
        "  padding-bottom:7px;"
        "}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::SurfaceAltHex())
        .arg(KswordTheme::BorderHex()));
}

void WelcomeDock::updateLanguageButtonRgbBorder()
{
    if (m_languageSettingsBtn == nullptr)
    {
        return;
    }

    // 按钮始终由本类创建为 WelcomeRgbBorderButton；仅更新颜色并触发局部重绘。
    auto* rgbBorderButton = static_cast<WelcomeRgbBorderButton*>(m_languageSettingsBtn);
    rgbBorderButton->setBorderColor(QColor::fromHsv(m_languageButtonHue, 255, 255));
}

void WelcomeDock::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);
    if (event != nullptr && event->type() == QEvent::LanguageChange)
    {
        retranslateUi();
    }
}

void WelcomeDock::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    updateLanguageButtonRgbBorder();
    if (m_languageButtonColorTimer != nullptr && !m_languageButtonColorTimer->isActive())
    {
        m_languageButtonColorTimer->start();
    }
}

void WelcomeDock::hideEvent(QHideEvent* event)
{
    if (m_languageButtonColorTimer != nullptr)
    {
        m_languageButtonColorTimer->stop();
    }
    QWidget::hideEvent(event);
}

void WelcomeDock::retranslateUi()
{
    const auto welcomeText = [](const char* key, const QString& sourceText) {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    };

    if (m_leftImage != nullptr)
    {
        const QPixmap localizedLogo(welcomeLogoResourcePath());
        if (!localizedLogo.isNull())
        {
            // 直接设置原图，不调用 scaled，保持图片清晰且不变形。
            m_leftImage->setPixmap(localizedLogo);
        }
        else
        {
            m_leftImage->clear();
            m_leftImage->setText(welcomeText(
                "welcome.logo_fallback",
                QStringLiteral("左侧图片区域")));
        }
    }

    if (m_copyright != nullptr)
    {
        m_copyright->setText(
            welcomeText(
                "welcome.release_info",
                QStringLiteral(
                    "Ksword Dev 卡利剑ARK工具开发团队 保留所有权利。<br>"
                    "<span style='font-size:18px;font-weight:700;'>当前版本：%1</span><br>"
                    "<span style='font-size:12px;'>编译时间：%2</span><br>"))
            .arg(kReleaseVersionText, kReleaseBuildTimeText));
    }
    if (m_contributors != nullptr)
    {
        m_contributors->setText(
            welcomeText(
                "welcome.contributors",
                QStringLiteral("<b>贡献者：</b>%1"))
            .arg(QStringLiteral("WangWei_CM.，OB_BUFF，PipExitThread")));
    }
    if (m_referenceTitle != nullptr)
    {
        m_referenceTitle->setText(welcomeText(
            "welcome.reference_projects",
            QStringLiteral("<b>参考项目：</b>")));
    }
    if (m_donors != nullptr)
    {
        m_donors->setText(
            welcomeText(
                "welcome.donors",
                QStringLiteral("<b>捐赠者：</b>%1"))
            .arg(QStringLiteral("Mapleleaf,存钱买油条（云舟API）,Extrella_Explorer,NtKrnl64,一花一树叶,hzh")));
    }

    if (m_githubBtn != nullptr)
    {
        m_githubBtn->setText(welcomeText(
            "welcome.github",
            QStringLiteral("Github仓库")));
        m_githubBtn->setToolTip(welcomeText(
            "welcome.github.tooltip",
            QStringLiteral("打开项目 Github 仓库主页")));
    }
    if (m_languageSettingsBtn != nullptr)
    {
        m_languageSettingsBtn->setText(welcomeText(
            "welcome.language_settings",
            QStringLiteral("🌍language setting 语言设置")));
        m_languageSettingsBtn->setToolTip(welcomeText(
            "welcome.language_settings.tooltip",
            QStringLiteral("打开设置中的语言设置")));
    }
    if (m_qqBtn != nullptr)
    {
        m_qqBtn->setText(welcomeText(
            "welcome.qq_group",
            QStringLiteral("QQ群")));
        m_qqBtn->setToolTip(welcomeText(
            "welcome.qq_group.tooltip",
            QStringLiteral("加入项目 QQ 交流群")));
    }
    if (m_pplControlBtn != nullptr)
    {
        m_pplControlBtn->setText(QStringLiteral("PPLcontrol"));
        m_pplControlBtn->setToolTip(welcomeText(
            "welcome.pplcontrol.tooltip",
            QStringLiteral("打开 PPLcontrol 参考项目仓库")));
    }
    if (m_systemInformerBtn != nullptr)
    {
        m_systemInformerBtn->setText(QStringLiteral("System Informer"));
        m_systemInformerBtn->setToolTip(welcomeText(
            "welcome.system_informer.tooltip",
            QStringLiteral("打开 System Informer 参考项目仓库")));
    }
    if (m_skt64Btn != nullptr)
    {
        m_skt64Btn->setText(QStringLiteral("SKT64"));
        m_skt64Btn->setToolTip(welcomeText(
            "welcome.skt64.tooltip",
            QStringLiteral("打开 SKT64 参考项目仓库")));
    }
}
