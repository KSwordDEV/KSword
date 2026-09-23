#include "WelcomeDock.h"

#include "../HardwareDock/HardwareDock.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/PerformanceNavCard.h"
#include "../UI/UI.css/UI_css.h"
#include "../theme.h"

#include <QColor>
#include <QDateTime>
#include <QDesktopServices>
#include <QEvent>
#include <QFrame>
#include <QGuiApplication>
#include <QGridLayout>
#include <QHideEvent>
#include <QLabel>
#include <QPainter>
#include <QPainterPath>
#include <QPaintEvent>
#include <QPixmap>
#include <QPushButton>
#include <QScrollArea>
#include <QShowEvent>
#include <QStorageInfo>
#include <QSysInfo>
#include <QTimer>
#include <QToolButton>
#include <QThread>
#include <QUrl>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>
#include <array>

namespace
{
    struct ContributorLink
    {
        QString displayName;
        QString targetUrl;
    };

    // contributorEntries 作用：把开发者/贡献者名单集中放在源文件前部，避免名单散落在布局代码中。
    // 每个人最多注册两个链接；链接为空时仍保留数据位，但不显示对应按钮。
    struct ContributorEntry
    {
        QString displayName;
        QString description;
        QString avatarResourcePath;
        ContributorLink firstLink;
        ContributorLink secondLink;
    };

    const std::array<ContributorEntry, 2> contributorEntries = {{
        {QStringLiteral("WangWei_CM."), QStringLiteral("一个臭写C++的"),
         QStringLiteral(":/Image/Resource/Logo/WangWei_CM..jpg"),
         {QStringLiteral("网站 ->"), QString()}, {QStringLiteral("Bilibili ->"), QString("https://space.bilibili.com/1627165457?spm_id_from=333.337.0.0")}},
        {QStringLiteral("OB_BUFF"), QString(),
         QStringLiteral(":/Image/Resource/Logo/OB_BUFF.png"),
         {QStringLiteral("网站 ->"), QString()}, {QStringLiteral("Bilibili ->"), QString("https://b23.tv/IBNf1DA")}},
    }};

    // donorNames 作用：集中维护公开感谢名单；后续补充捐赠者只需修改这一处。
    const std::array<QString, 11> donorNames = {{
        QStringLiteral("长空落日"), QStringLiteral("Extrella_Explorer"),
        QStringLiteral("Txt Text"), QStringLiteral("Mapleleaf"),
        QStringLiteral("存钱买油条（云舟API）"), QStringLiteral("Solicom"),
        QStringLiteral("東雪蓮可爱捏"), QStringLiteral("JIAN2486"),
        QStringLiteral("NtKrnl64"), QStringLiteral("一花一树叶"), QStringLiteral("hzh")
    }};

    const QString kReleaseVersionText = QStringLiteral("5.1.4.3-Pre"); // RELEASE_META_VERSION_MARKER
    const QString kReleaseBuildTimeText = QStringLiteral("2026-08-17 22:41:10.119 +08:00"); // RELEASE_META_BUILD_TIME_MARKER
    const QString kQQGroupInviteUrl = QStringLiteral("https://qm.qq.com/q/5tWNPfIxkk");
    const QString kPplControlRepositoryUrl = QStringLiteral("https://github.com/itm4n/PPLcontrol");
    const QString kSystemInformerRepositoryUrl = QStringLiteral("https://github.com/winsiderss/systeminformer");
    const QString kSkt64RepositoryUrl = QStringLiteral("https://github.com/PspExitThread/SKT64");

    QString welcomeLogoResourcePath()
    {
        const QString languageId = ks::i18n::LanguageManager::instance().currentLanguageId();
        return languageId.startsWith(QStringLiteral("zh"), Qt::CaseInsensitive)
            ? QStringLiteral(":/Image/Resource/Logo/KswordHome-ZH.png")
            : QStringLiteral(":/Image/Resource/Logo/KswordHome-En.png");
    }

    QString formatRate(const double bytesPerSec)
    {
        const double value = std::max(0.0, bytesPerSec);
        if (value >= 1024.0 * 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 GB/s").arg(value / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
        }
        if (value >= 1024.0 * 1024.0)
        {
            return QStringLiteral("%1 MB/s").arg(value / (1024.0 * 1024.0), 0, 'f', 1);
        }
        if (value >= 1024.0)
        {
            return QStringLiteral("%1 KB/s").arg(value / 1024.0, 0, 'f', 1);
        }
        return QStringLiteral("%1 B/s").arg(value, 0, 'f', 0);
    }

    QString formatGiB(const quint64 bytes)
    {
        return QStringLiteral("%1 GB").arg(
            static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }

    QStringList overviewSectionValues(const QString& overviewText, const QString& sectionName)
    {
        QStringList values;
        const QStringList lines = overviewText.split(QChar('\n'));
        const QString sectionMarker = QStringLiteral("[%1]").arg(sectionName);
        bool inSection = false;
        for (const QString& rawLine : lines)
        {
            // PowerShell Format-Table 使用制表符和连续空格作为列间距。欢迎页不是表格，
            // 保留这些空白会把一行硬件名称拉成数个不对齐的“假列”。
            const QString line = rawLine.simplified();
            if (line == sectionMarker)
            {
                inSection = true;
                continue;
            }
            if (inSection && line.startsWith(QChar('[')))
            {
                break;
            }
            if (!inSection || line.isEmpty() || line.startsWith(QChar('<')))
            {
                continue;
            }
            // Format-Table 输出的字段名和分隔线不是硬件值；截图中的 BIOS/主板/GPU
            // 正是因为旧逻辑取到了这一行才显示成 Manufacturer/Name 等表头。
            if (line.startsWith(QStringLiteral("---")) ||
                line.contains(QStringLiteral("Manufacturer"), Qt::CaseInsensitive) ||
                line.contains(QStringLiteral("SMBIOSBIOSVersion"), Qt::CaseInsensitive) ||
                line.contains(QStringLiteral("AdapterRAM"), Qt::CaseInsensitive) ||
                line.contains(QStringLiteral("VideoProcessor"), Qt::CaseInsensitive) ||
                line.contains(QStringLiteral("DriverVersion"), Qt::CaseInsensitive) ||
                (sectionName == QStringLiteral("网卡设备(物理)") &&
                    line.startsWith(QStringLiteral("Name"), Qt::CaseInsensitive) &&
                    line.contains(QStringLiteral("AdapterType"), Qt::CaseInsensitive)))
            {
                continue;
            }
            values.push_back(line);
        }
        return values;
    }

    QString firstOverviewValue(const QString& overviewText, const QString& sectionName)
    {
        const QStringList values = overviewSectionValues(overviewText, sectionName);
        return values.isEmpty() ? QStringLiteral("N/A") : values.front();
    }

    QString secondOverviewValue(const QString& overviewText, const QString& sectionName)
    {
        const QStringList values = overviewSectionValues(overviewText, sectionName);
        return values.size() > 1 ? values.at(1) : QStringLiteral("N/A");
    }

    QString welcomeOutlineButtonStyle()
    {
        return QStringLiteral(
            "QPushButton{background:transparent;color:%1;border:1px solid #409EFF;"
            "border-radius:5px;padding:7px 12px;}"
            "QPushButton:hover{background:transparent;border-color:#64B5F6;}"
            "QPushButton:pressed{background:transparent;border-color:#1976D2;}")
            .arg(KswordTheme::TextPrimaryHex());
    }

    class WelcomeRgbBorderButton final : public QPushButton
    {
    public:
        using QPushButton::QPushButton;

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
        void paintEvent(QPaintEvent* event) override
        {
            QPushButton::paintEvent(event);
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);
            painter.setBrush(Qt::NoBrush);
            painter.setPen(QPen(m_borderColor, 3.0));
            painter.drawRoundedRect(
                QRectF(rect()).adjusted(1.5, 1.5, -1.5, -1.5), 9.0, 9.0);
        }

    private:
        QColor m_borderColor = QColor::fromHsv(0, 255, 255);
    };
}

WelcomeDock::WelcomeDock(QWidget* parent)
    : QWidget(parent)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumSize(0, 0);

    const auto welcomeText = [](const char* key, const QString& sourceText) {
        return ks::i18n::contextText(QString::fromLatin1(key), sourceText);
    };

    m_leftImage = new QLabel(this);
    m_leftImage->setAlignment(Qt::AlignCenter);
    m_leftImage->setMinimumSize(0, 0);
    m_leftImage->setMaximumSize(655, 250);
    m_leftImage->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_leftImage->setScaledContents(true);

    m_languageSettingsBtn = new WelcomeRgbBorderButton(this);
    m_languageSettingsBtn->setObjectName(QStringLiteral("welcomeLanguageSettingsButton"));
    m_languageSettingsBtn->setMinimumSize(0, 48);
    m_languageSettingsBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_languageSettingsBtn->setCursor(Qt::PointingHandCursor);
    initializeLanguageButtonStyle();

    m_languageButtonColorTimer = new QTimer(this);
    m_languageButtonColorTimer->setInterval(80);
    connect(m_languageButtonColorTimer, &QTimer::timeout, this, [this]() {
        m_languageButtonHue = (m_languageButtonHue + 4) % 360;
        updateLanguageButtonRgbBorder();
    });

    m_copyright = new QLabel(this);
    m_copyright->setWordWrap(true);
    m_copyright->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    m_copyright->setTextInteractionFlags(Qt::TextSelectableByMouse);

    m_contributors = new QLabel(this);
    m_referenceTitle = new QLabel(this);
    m_donors = new QLabel(this);
    // 兼容旧的公开字段，实际展示由右侧可滚动折叠区承载，避免未入布局的 QLabel 覆盖新界面。
    m_contributors->setVisible(false);
    m_referenceTitle->setVisible(false);
    m_donors->setVisible(false);

    const QString buttonStyle = welcomeOutlineButtonStyle();
    const auto makeButton = [this, &buttonStyle](QPushButton** buttonOut) {
        QPushButton* button = new QPushButton(this);
        button->setStyleSheet(buttonStyle);
        button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        button->setMinimumSize(0, 42);
        if (buttonOut != nullptr)
        {
            *buttonOut = button;
        }
        return button;
    };
    makeButton(&m_githubBtn);
    makeButton(&m_qqBtn);
    makeButton(&m_pplControlBtn);
    makeButton(&m_systemInformerBtn);
    makeButton(&m_skt64Btn);

    m_btnLayout = new QHBoxLayout();
    m_btnLayout->setContentsMargins(0, 0, 0, 0);
    m_btnLayout->setSpacing(8);
    m_btnLayout->addWidget(m_qqBtn, 1);
    m_btnLayout->addWidget(m_githubBtn, 1);

    m_referenceLayout = new QHBoxLayout();
    m_referenceLayout->setContentsMargins(0, 0, 0, 0);
    m_referenceLayout->setSpacing(8);
    m_referenceLayout->addWidget(m_pplControlBtn, 1);
    m_referenceLayout->addWidget(m_systemInformerBtn, 1);
    m_referenceLayout->addWidget(m_skt64Btn, 1);

    m_leftLayout = new QVBoxLayout();
    m_leftLayout->setContentsMargins(0, 0, 0, 0);
    m_leftLayout->addWidget(m_leftImage, 1);

    m_mainLayout = new QHBoxLayout();
    m_mainLayout->setContentsMargins(0, 0, 0, 0);
    m_mainLayout->setSpacing(18);
    m_mainLayout->addLayout(m_leftLayout, 1);
    QVBoxLayout* headerRightLayout = new QVBoxLayout();
    headerRightLayout->setContentsMargins(0, 0, 0, 0);
    headerRightLayout->setSpacing(8);
    headerRightLayout->addWidget(m_copyright, 1);
    headerRightLayout->addWidget(m_languageSettingsBtn, 0);
    m_mainLayout->addLayout(headerRightLayout, 1);

    QVBoxLayout* rootLayout = new QVBoxLayout(this);
    rootLayout->setContentsMargins(16, 14, 16, 14);
    rootLayout->setSpacing(12);
    rootLayout->addLayout(m_mainLayout, 0);

    initializePerformanceCards();
    rootLayout->addLayout(m_performanceLayout, 0);

    QHBoxLayout* lowerLayout = new QHBoxLayout();
    lowerLayout->setContentsMargins(0, 0, 0, 0);
    lowerLayout->setSpacing(18);

    // 兼容旧字段但不再用一段换行文本排版；系统摘要改为项目名/内容两列网格。
    m_systemInfo = new QLabel(this);
    m_systemInfo->setVisible(false);
    m_systemInfoPanel = new QWidget(this);
    m_systemInfoPanel->setAttribute(Qt::WA_TranslucentBackground, true);
    m_systemInfoPanel->setStyleSheet(QStringLiteral("background:transparent;"));
    // 面板本身占满左下区域，网格内容再固定贴到顶部；否则动态添加字段时
    // sizeHint 只按初始化时的少量行计算，后续字段会被裁掉或挤到异常位置。
    m_systemInfoPanel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_systemInfoLayout = new QGridLayout(m_systemInfoPanel);
    m_systemInfoLayout->setContentsMargins(0, 0, 0, 0);
    m_systemInfoLayout->setHorizontalSpacing(14);
    m_systemInfoLayout->setVerticalSpacing(4);
    m_systemInfoLayout->setAlignment(Qt::AlignTop);
    m_systemInfoLayout->setColumnMinimumWidth(0, 144);
    m_systemInfoLayout->setColumnStretch(0, 0);
    m_systemInfoLayout->setColumnStretch(1, 1);
    lowerLayout->addWidget(m_systemInfoPanel, 1);

    QVBoxLayout* rightLayout = new QVBoxLayout();
    rightLayout->setContentsMargins(0, 0, 0, 0);
    rightLayout->setSpacing(8);
    rightLayout->addLayout(m_btnLayout);
    rightLayout->addLayout(m_referenceLayout);
    initializeContributorCollapse();
    rightLayout->addWidget(m_contributorsCollapse);
    rightLayout->addWidget(m_contributorsScroll, 1);
    rightLayout->addWidget(m_donorsCollapse);
    rightLayout->addWidget(m_donorsScroll, 1);
    lowerLayout->addLayout(rightLayout, 1);
    rootLayout->addLayout(lowerLayout, 1);

    connect(m_languageSettingsBtn, &QPushButton::clicked, this, &WelcomeDock::languageSettingsRequested);
    connect(m_githubBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(QStringLiteral("https://github.com/WangWei-CM/KSword")));
    });
    connect(m_qqBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kQQGroupInviteUrl));
    });
    connect(m_pplControlBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kPplControlRepositoryUrl));
    });
    connect(m_systemInformerBtn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kSystemInformerRepositoryUrl));
    });
    connect(m_skt64Btn, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl(kSkt64RepositoryUrl));
    });

    retranslateUi();
    updateCollapseState(true);
    // 首屏只依赖 Win32/Qt 可立即取得的信息；硬件 Dock 的异步静态采样完成后会补全
    // BIOS、主板、GPU 和物理网卡，避免欢迎页数秒内空白。
    updateSystemInfoFromHardwareText(QString());
}

void WelcomeDock::initializePerformanceCards()
{
    m_performanceLayout = new QHBoxLayout();
    m_performanceLayout->setContentsMargins(0, 0, 0, 0);
    m_performanceLayout->setSpacing(10);

    const std::array<KswordTheme::PerformanceRole, 5> roles = {{
        KswordTheme::PerformanceRole::Cpu,
        KswordTheme::PerformanceRole::Memory,
        KswordTheme::PerformanceRole::Gpu,
        KswordTheme::PerformanceRole::Disk,
        KswordTheme::PerformanceRole::Network
    }};
    for (const auto role : roles)
    {
        PerformanceNavCard* card = new PerformanceNavCard(this);
        card->setMinimumSize(0, 84);
        card->setMaximumHeight(118);
        card->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        card->setAccentColor(KswordTheme::PerformanceColor(role));
        m_performanceCards.push_back(card);
        m_performanceLayout->addWidget(card, 1);
    }
}

void WelcomeDock::initializeContributorCollapse()
{
    // 折叠标题常态不描边，只在 hover/展开时才亮出边框，避免首页一上来就是两个蓝框。
    const QString headerStyle = QStringLiteral(
        "QToolButton{background:transparent;color:%1;border:1px solid transparent;padding:7px 12px;"
        "font-size:16px;font-weight:600;text-align:center;}"
        "QToolButton:hover{background:transparent;border-color:#64B5F6;}"
        "QToolButton:checked{background:transparent;border-color:#409EFF;}")
        .arg(KswordTheme::TextPrimaryHex());

    m_contributorsCollapse = new QToolButton(this);
    m_contributorsCollapse->setCheckable(true);
    m_contributorsCollapse->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_contributorsCollapse->setStyleSheet(headerStyle);
    m_contributorsCollapse->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    m_donorsCollapse = new QToolButton(this);
    m_donorsCollapse->setCheckable(true);
    m_donorsCollapse->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_donorsCollapse->setStyleSheet(headerStyle);
    m_donorsCollapse->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);

    m_contributorsBody = new QWidget(this);
    m_contributorsBody->setAttribute(Qt::WA_TranslucentBackground, true);
    m_contributorsBody->setStyleSheet(QStringLiteral("background:transparent;"));
    QVBoxLayout* contributorsLayout = new QVBoxLayout(m_contributorsBody);
    contributorsLayout->setContentsMargins(4, 4, 4, 4);
    contributorsLayout->setSpacing(6);
    for (const ContributorEntry& entry : contributorEntries)
    {
        QWidget* row = new QWidget(m_contributorsBody);
        row->setAttribute(Qt::WA_TranslucentBackground, true);
        row->setStyleSheet(QStringLiteral("background:transparent;"));
        QHBoxLayout* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(0, 0, 0, 0);
        rowLayout->setSpacing(8);

        QLabel* avatar = new QLabel(row);
        avatar->setText(QStringLiteral("头像"));
        avatar->setAlignment(Qt::AlignCenter);
        constexpr int avatarSize = 64;
        avatar->setFixedSize(avatarSize, avatarSize);
        avatar->setStyleSheet(QStringLiteral(
            "border:2px solid %1;border-radius:32px;color:%2;background:%3;")
            .arg(KswordTheme::BorderHex(), KswordTheme::TextPrimaryHex(), KswordTheme::SurfaceAltHex()));
        const QPixmap sourceAvatar(entry.avatarResourcePath);
        if (!sourceAvatar.isNull())
        {
            QPixmap circularAvatar(avatarSize, avatarSize);
            circularAvatar.fill(Qt::transparent);
            QPainter avatarPainter(&circularAvatar);
            avatarPainter.setRenderHint(QPainter::Antialiasing);
            QPainterPath circularClip;
            circularClip.addEllipse(0, 0, avatarSize, avatarSize);
            avatarPainter.setClipPath(circularClip);
            avatarPainter.drawPixmap(0, 0, sourceAvatar.scaled(
                avatarSize, avatarSize, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation));
            avatar->setPixmap(circularAvatar);
            avatar->setText(QString());
        }
        rowLayout->addWidget(avatar, 0, Qt::AlignTop);

        QVBoxLayout* detailLayout = new QVBoxLayout();
        detailLayout->setContentsMargins(0, 0, 0, 0);
        detailLayout->setSpacing(2);
        QLabel* nameLabel = new QLabel(entry.displayName, row);
        nameLabel->setStyleSheet(QStringLiteral("font-size:15px;font-weight:600;"));
        detailLayout->addWidget(nameLabel);
        if (!entry.description.isEmpty())
        {
            detailLayout->addWidget(new QLabel(entry.description, row));
        }
        // 链接独立为右侧按钮列，姓名和签名不会再被按钮挤到下一行。
        QVBoxLayout* linksLayout = new QVBoxLayout();
        linksLayout->setContentsMargins(0, 0, 0, 0);
        linksLayout->setSpacing(6);
        const std::array<ContributorLink, 2> links = {{entry.firstLink, entry.secondLink}};
        for (const ContributorLink& link : links)
        {
            QPushButton* linkButton = new QPushButton(link.displayName, row);
            linkButton->setStyleSheet(welcomeOutlineButtonStyle());
            linkButton->setVisible(!link.targetUrl.trimmed().isEmpty());
            linkButton->setSizePolicy(QSizePolicy::Maximum, QSizePolicy::Fixed);
            linksLayout->addWidget(linkButton);
            if (!link.targetUrl.trimmed().isEmpty())
            {
                const QUrl targetUrl(link.targetUrl);
                connect(linkButton, &QPushButton::clicked, row, [targetUrl]() {
                    QDesktopServices::openUrl(targetUrl);
                });
            }
        }
        rowLayout->addLayout(detailLayout, 1);
        rowLayout->addLayout(linksLayout, 0);
        contributorsLayout->addWidget(row);
    }
    contributorsLayout->addStretch(1);

    m_donorsBody = new QWidget(this);
    m_donorsBody->setAttribute(Qt::WA_TranslucentBackground, true);
    m_donorsBody->setStyleSheet(QStringLiteral("background:transparent;"));
    QVBoxLayout* donorsLayout = new QVBoxLayout(m_donorsBody);
    donorsLayout->setContentsMargins(8, 6, 8, 6);
    donorsLayout->setSpacing(3);
    for (const QString& donorName : donorNames)
    {
        donorsLayout->addWidget(new QLabel(donorName, m_donorsBody));
    }
    donorsLayout->addStretch(1);

    const auto makeScrollArea = [](QWidget* body, QWidget* parent) {
        QScrollArea* scrollArea = new QScrollArea(parent);
        scrollArea->setAttribute(Qt::WA_TranslucentBackground, true);
        scrollArea->viewport()->setAttribute(Qt::WA_TranslucentBackground, true);
        scrollArea->setWidget(body);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setStyleSheet(QStringLiteral(
            "QScrollArea{background:transparent;border:none;}"
            "QScrollArea > QWidget{background:transparent;}"));
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        return scrollArea;
    };
    m_contributorsScroll = makeScrollArea(m_contributorsBody, this);
    m_donorsScroll = makeScrollArea(m_donorsBody, this);

    connect(m_contributorsCollapse, &QToolButton::clicked, this, [this]() {
        updateCollapseState(true);
    });
    connect(m_donorsCollapse, &QToolButton::clicked, this, [this]() {
        updateCollapseState(false);
    });
}

void WelcomeDock::updateCollapseState(const bool contributorsExpanded)
{
    if (m_contributorsCollapse == nullptr || m_donorsCollapse == nullptr)
    {
        return;
    }
    m_contributorsCollapse->setChecked(contributorsExpanded);
    m_donorsCollapse->setChecked(!contributorsExpanded);
    m_contributorsCollapse->setArrowType(contributorsExpanded ? Qt::DownArrow : Qt::RightArrow);
    m_donorsCollapse->setArrowType(contributorsExpanded ? Qt::RightArrow : Qt::DownArrow);
    if (m_contributorsScroll != nullptr)
    {
        m_contributorsScroll->setVisible(contributorsExpanded);
    }
    if (m_donorsScroll != nullptr)
    {
        m_donorsScroll->setVisible(!contributorsExpanded);
    }
}

void WelcomeDock::setHardwareDock(HardwareDock* hardwareDock)
{
    if (m_hardwareDock == hardwareDock)
    {
        return;
    }
    if (m_hardwareDock != nullptr)
    {
        disconnect(m_hardwareDock, nullptr, this, nullptr);
    }
    m_hardwareDock = hardwareDock;
    if (m_hardwareDock == nullptr)
    {
        return;
    }
    connect(m_hardwareDock, &HardwareDock::performanceSnapshotChanged,
        this, &WelcomeDock::updatePerformanceSnapshot);
    connect(m_hardwareDock, &HardwareDock::staticOverviewChanged,
        this, &WelcomeDock::updateSystemInfoFromHardwareText);
    // 欢迎页只需要用户态性能卡片；禁止它在首屏触发需要 KswordARK 驱动的 R0 健康查询。
    m_hardwareDock->startPerformanceSampling(false);
}

void WelcomeDock::updatePerformanceSnapshot(
    const double cpuUsagePercent, const double memoryUsagePercent,
    const double diskReadBytesPerSec, const double diskWriteBytesPerSec,
    const double networkRxBytesPerSec, const double networkTxBytesPerSec,
    const double gpuUsagePercent)
{
    if (m_performanceCards.size() < 5)
    {
        return;
    }
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);
    const double usedMemoryGiB = static_cast<double>(
        memoryStatus.ullTotalPhys - memoryStatus.ullAvailPhys) / (1024.0 * 1024.0 * 1024.0);
    const double totalMemoryGiB = static_cast<double>(memoryStatus.ullTotalPhys) /
        (1024.0 * 1024.0 * 1024.0);

    m_performanceCards[0]->setSubtitleText(QStringLiteral("%1%").arg(cpuUsagePercent, 0, 'f', 0));
    m_performanceCards[0]->appendSample(cpuUsagePercent);
    m_performanceCards[1]->setSubtitleText(QStringLiteral("用 %1/%2 GB / 余 %3%")
        .arg(usedMemoryGiB, 0, 'f', 1).arg(totalMemoryGiB, 0, 'f', 1)
        .arg(std::clamp(100.0 - memoryUsagePercent, 0.0, 100.0), 0, 'f', 0));
    m_performanceCards[1]->appendSample(memoryUsagePercent);
    m_performanceCards[2]->setSubtitleText(QStringLiteral("%1% 综合").arg(gpuUsagePercent, 0, 'f', 0));
    m_performanceCards[2]->appendSample(gpuUsagePercent);

    const double diskTotal = std::max(0.0, diskReadBytesPerSec) + std::max(0.0, diskWriteBytesPerSec);
    m_diskDisplayScale = std::max(1024.0 * 1024.0,
        std::max(m_diskDisplayScale * 0.92, diskTotal * 1.25));
    m_performanceCards[3]->setSubtitleText(QStringLiteral("读 %1 / 写 %2")
        .arg(formatRate(diskReadBytesPerSec), formatRate(diskWriteBytesPerSec)));
    m_performanceCards[3]->appendSample(std::clamp(diskTotal / m_diskDisplayScale * 100.0, 0.0, 100.0));

    const double networkTotal = std::max(0.0, networkRxBytesPerSec) + std::max(0.0, networkTxBytesPerSec);
    m_networkDisplayScale = std::max(1024.0 * 1024.0,
        std::max(m_networkDisplayScale * 0.92, networkTotal * 1.25));
    m_performanceCards[4]->setSubtitleText(QStringLiteral("下 %1 / 上 %2")
        .arg(formatRate(networkRxBytesPerSec), formatRate(networkTxBytesPerSec)));
    m_performanceCards[4]->appendSample(std::clamp(networkTotal / m_networkDisplayScale * 100.0, 0.0, 100.0));
}

void WelcomeDock::updateSystemInfoFromHardwareText(const QString& overviewText)
{
    MEMORYSTATUSEX memoryStatus{};
    memoryStatus.dwLength = sizeof(memoryStatus);
    ::GlobalMemoryStatusEx(&memoryStatus);
    const QStorageInfo systemStorage = QStorageInfo::root();
    const QString monitorText = QGuiApplication::primaryScreen() != nullptr
        ? QStringLiteral("%1 (%2 x %3)")
            .arg(QGuiApplication::primaryScreen()->name())
            .arg(QGuiApplication::primaryScreen()->size().width())
            .arg(QGuiApplication::primaryScreen()->size().height())
        : QStringLiteral("N/A");
    const QString cpuText = firstOverviewValue(overviewText, QStringLiteral("处理器"));
    const QString boardText = firstOverviewValue(overviewText, QStringLiteral("主板"));
    const QString biosText = firstOverviewValue(overviewText, QStringLiteral("BIOS"));
    const QString gpuText = firstOverviewValue(overviewText, QStringLiteral("显卡设备"));
    const QString secondGpuText = secondOverviewValue(overviewText, QStringLiteral("显卡设备"));
    const QString networkText = firstOverviewValue(overviewText, QStringLiteral("网卡设备(物理)"));
    const QString logicalProcessorText = QString::number(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
    const QString bootTimeText = QDateTime::fromMSecsSinceEpoch(
        QDateTime::currentMSecsSinceEpoch() - static_cast<qint64>(::GetTickCount64()))
        .toString(Qt::ISODate);
    struct SystemInfoRow
    {
        QString label;
        QString value;
    };
    const auto translatedLabel = [](const QString& key, const QString& fallback) {
        return ks::i18n::contextText(key, fallback);
    };
    const QString pendingCollection = ks::i18n::contextText(
        QStringLiteral("待采集"), QStringLiteral("待采集"));
    const std::array<SystemInfoRow, 18> rows = {{
        {translatedLabel(QStringLiteral("welcome.hardware.field.system_version"), QStringLiteral("系统版本：")), QSysInfo::prettyProductName()},
        {translatedLabel(QStringLiteral("welcome.hardware.field.internal_version"), QStringLiteral("内部版本：")), QSysInfo::kernelVersion()},
        {translatedLabel(QStringLiteral("welcome.hardware.field.cpu"), QStringLiteral("CPU：")), cpuText == QStringLiteral("N/A") ? pendingCollection : cpuText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.cpu_threads"), QStringLiteral("CPU核心/线程：")), logicalProcessorText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.memory_usage"), QStringLiteral("内存：")), QStringLiteral("%1%").arg(memoryStatus.dwMemoryLoad)},
        {translatedLabel(QStringLiteral("welcome.hardware.field.memory_total"), QStringLiteral("物理内存总量：")), formatGiB(memoryStatus.ullTotalPhys)},
        {translatedLabel(QStringLiteral("welcome.hardware.field.bios"), QStringLiteral("BIOS：")), biosText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.motherboard"), QStringLiteral("主板：")), boardText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.gpu0"), QStringLiteral("显卡0：")), gpuText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.gpu1"), QStringLiteral("显卡1：")), secondGpuText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.monitor"), QStringLiteral("显示器：")), monitorText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.system_drive"), QStringLiteral("系统盘：")), QStringLiteral("%1  %2/%3 GB").arg(systemStorage.rootPath()).arg(formatGiB(systemStorage.bytesAvailable())).arg(formatGiB(systemStorage.bytesTotal()))},
        {translatedLabel(QStringLiteral("welcome.hardware.field.network"), QStringLiteral("网络接口：")), networkText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.computer_name"), QStringLiteral("计算机名：")), QSysInfo::machineHostName()},
        {translatedLabel(QStringLiteral("welcome.hardware.field.kernel_type"), QStringLiteral("内核类型：")), QSysInfo::kernelType()},
        {translatedLabel(QStringLiteral("welcome.hardware.field.system_architecture"), QStringLiteral("系统架构：")), QSysInfo::currentCpuArchitecture()},
        {translatedLabel(QStringLiteral("welcome.hardware.field.system_boot"), QStringLiteral("系统启动：")), bootTimeText},
        {translatedLabel(QStringLiteral("welcome.hardware.field.qt_version"), QStringLiteral("Qt版本：")), QStringLiteral(QT_VERSION_STR)},
    }};
    if (m_systemInfo != nullptr)
    {
        QStringList compatibilityLines;
        compatibilityLines.reserve(static_cast<qsizetype>(rows.size()));
        for (const SystemInfoRow& row : rows)
        {
            compatibilityLines.append(QStringLiteral("%1 %2").arg(row.label, row.value));
        }
        m_systemInfo->setText(compatibilityLines.join(QChar('\n')));
    }
    if (m_systemInfoLayout != nullptr)
    {
        while (QLayoutItem* item = m_systemInfoLayout->takeAt(0))
        {
            if (QWidget* widget = item->widget())
            {
                delete widget;
            }
            delete item;
        }

        int rowIndex = 0;
        for (const SystemInfoRow& row : rows)
        {
            QLabel* nameLabel = new QLabel(row.label, m_systemInfoPanel);
            nameLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            nameLabel->setContentsMargins(0, 0, 0, 0);
            nameLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
            nameLabel->setStyleSheet(QStringLiteral("color:%1;font-weight:600;")
                .arg(KswordTheme::TextSecondaryHex()));
            QLabel* valueLabel = new QLabel(row.value, m_systemInfoPanel);
            // 异步硬件详情比首屏占位值长得多；若允许换行，详情到达时会突然把
            // 左下信息区撑高。固定单行高度，完整文本则通过悬浮提示保留。
            valueLabel->setWordWrap(false);
            valueLabel->setAlignment(Qt::AlignLeft | Qt::AlignTop);
            valueLabel->setContentsMargins(0, 0, 0, 0);
            valueLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
            valueLabel->setToolTip(row.value);
            valueLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
            valueLabel->setStyleSheet(QStringLiteral("color:%1;")
                .arg(KswordTheme::TextPrimaryHex()));
            const int rowHeight = std::max(nameLabel->fontMetrics().height(),
                valueLabel->fontMetrics().height()) + 2;
            nameLabel->setFixedHeight(rowHeight);
            valueLabel->setFixedHeight(rowHeight);
            // 不要给网格单元格设置 AlignLeft：那会令 QLabel 仅按内容宽度占位，
            // 使右列无法获得左下区域的剩余宽度，硬件型号会被过早换行。
            // 文本自身已通过 QLabel::setAlignment 左对齐，单元格应横向填满。
            m_systemInfoLayout->addWidget(nameLabel, rowIndex, 0, Qt::AlignTop);
            m_systemInfoLayout->addWidget(valueLabel, rowIndex, 1, Qt::AlignTop);
            ++rowIndex;
        }
        m_systemInfoLayout->invalidate();
        m_systemInfoPanel->updateGeometry();
    }
}

void WelcomeDock::initializeLanguageButtonStyle()
{
    if (m_languageSettingsBtn == nullptr)
    {
        return;
    }
    m_languageSettingsBtn->setStyleSheet(QStringLiteral(
        "QPushButton#welcomeLanguageSettingsButton{background:transparent;color:%1;border:3px solid transparent;"
        "border-radius:10px;padding:8px 16px;font-size:16px;font-weight:700;}"
        "QPushButton#welcomeLanguageSettingsButton:hover{background:transparent;}"
        "QPushButton#welcomeLanguageSettingsButton:pressed{background:transparent;}")
        .arg(KswordTheme::TextPrimaryHex()));
}

void WelcomeDock::updateLanguageButtonRgbBorder()
{
    if (m_languageSettingsBtn != nullptr)
    {
        static_cast<WelcomeRgbBorderButton*>(m_languageSettingsBtn)->setBorderColor(
            QColor(QStringLiteral("#409EFF")));
    }
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
        const QPixmap logo(welcomeLogoResourcePath());
        if (!logo.isNull())
        {
            m_leftImage->setPixmap(logo);
        }
        else
        {
            m_leftImage->setText(welcomeText("welcome.logo_fallback", QStringLiteral("左侧图片区域")));
        }
    }
    if (m_copyright != nullptr)
    {
        m_copyright->setText(welcomeText(
            "welcome.release_info",
            QStringLiteral(
                "Ksword Dev 卡利剑ARK工具开发团队 保留所有权利。<br>"
                "<span style='font-size:22px;font-weight:700;'>当前版本：%1</span><br>"
                "<span style='font-size:14px;'>编译时间：%2</span>"))
            .arg(kReleaseVersionText, kReleaseBuildTimeText));
    }
    if (m_languageSettingsBtn != nullptr)
    {
        m_languageSettingsBtn->setText(welcomeText("welcome.language_settings", QStringLiteral("Language Settings ->")));
        m_languageSettingsBtn->setToolTip(welcomeText(
            "welcome.language_settings.tooltip", QStringLiteral("打开设置中的语言设置")));
    }
    if (m_githubBtn != nullptr)
    {
        m_githubBtn->setText(welcomeText("welcome.github", QStringLiteral("Github仓库 ->")));
        m_githubBtn->setToolTip(welcomeText(
            "welcome.github.tooltip", QStringLiteral("打开项目 Github 仓库主页")));
    }
    if (m_qqBtn != nullptr)
    {
        m_qqBtn->setText(welcomeText("welcome.qq_group", QStringLiteral("QQ群 ->")));
        m_qqBtn->setToolTip(welcomeText("welcome.qq_group.tooltip", QStringLiteral("加入项目 QQ 交流群")));
    }
    if (m_pplControlBtn != nullptr)
    {
        m_pplControlBtn->setText(QStringLiteral("PPLcontrol"));
        m_pplControlBtn->setToolTip(welcomeText(
            "welcome.pplcontrol.tooltip", QStringLiteral("打开 PPLcontrol 参考项目仓库")));
    }
    if (m_systemInformerBtn != nullptr)
    {
        m_systemInformerBtn->setText(QStringLiteral("System Informer"));
        m_systemInformerBtn->setToolTip(welcomeText(
            "welcome.system_informer.tooltip", QStringLiteral("打开 System Informer 参考项目仓库")));
    }
    if (m_skt64Btn != nullptr)
    {
        m_skt64Btn->setText(QStringLiteral("SKT64"));
        m_skt64Btn->setToolTip(welcomeText(
            "welcome.skt64.tooltip", QStringLiteral("打开 SKT64 参考项目仓库")));
    }
    if (m_contributorsCollapse != nullptr)
    {
        m_contributorsCollapse->setText(welcomeText("welcome.contributors.header", QStringLiteral("贡献者")));
    }
    if (m_donorsCollapse != nullptr)
    {
        m_donorsCollapse->setText(welcomeText("welcome.donors.header", QStringLiteral("捐赠者")));
    }
    if (m_performanceCards.size() >= 5)
    {
        m_performanceCards[0]->setTitleText(welcomeText("hardware.utilization.card.cpu", QStringLiteral("CPU")));
        m_performanceCards[1]->setTitleText(welcomeText("hardware.utilization.card.memory", QStringLiteral("内存")));
        m_performanceCards[2]->setTitleText(welcomeText("hardware.utilization.card.gpu", QStringLiteral("GPU")));
        m_performanceCards[3]->setTitleText(welcomeText("hardware.utilization.card.disk.prefix", QStringLiteral("磁盘")));
        m_performanceCards[4]->setTitleText(welcomeText("hardware.utilization.card.network.prefix", QStringLiteral("以太网")));
    }
}
