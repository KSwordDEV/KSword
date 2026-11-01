#include "ProcessDetailWindow.InternalCommon.h"
#include "../UI/TableContextMenu.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeBinding.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"
#include "ProcessAffinityUtils.h"
#include "ProcessAffinityPersistence.h"
#include "ThreadAffinityMenu.h"
#include "../句柄/HandleDock.h"
#include "../MemoryDock/MemoryDock.h"
#include "../NetworkDock/NetworkDock.h"
#include "../OtherDock/OtherDock.h"
#include "../MiscDock/SoundSource/SoundSourcePage.h"
#include "../UI/VisibleTableWidget.h"
#include <QSignalBlocker>
#include <QSaveFile>
#include "../UI/TableInteractionSupport.h"
#include "../UI/DetailLayoutRegistry.h"
#include "../UI/DetailDialogChrome.h"
#include "../UI/DetailPresentation.h"
#include "../UI/PrimaryPageStyle.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/FlowLayout.h"
#include "../PluginHost.h"

#include <QTimer>
#include <QStackedWidget>
#include <QCloseEvent>
#include <QEasingCurve>
#include <QHash>
#include <QMouseEvent>
#include <QPaintEvent>
#include <QResizeEvent>
#include <QVariantAnimation>
#include <QScopedValueRollback>

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.BaseAndUi.cpp
// 作用：
// - 负责构造/基础数据合并、多个 Tab 的 UI 初始化以及基础信号连接。
// - 聚焦“窗口骨架与静态展示数据”逻辑。
// ============================================================

namespace
{
    constexpr char kProcessDetailThemePalette[] = "ksword_process_detail_theme_palette"; // 最近业务主题的目标调色板。
    constexpr char kProcessDetailThemeStyle[] = "ksword_process_detail_theme_style"; // 最近业务主题的目标根样式。

    // 业务窗口独占根主题，Window用于页底，Surface只用于字段/卡片，不从自身旧palette派生。
    QPalette processDetailThemePalette(const QWidget* window)
    {
        QPalette colors = qApp ? qApp->palette() : window->palette();
        colors.setColor(QPalette::Window, KswordTheme::WindowColor());
        colors.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        colors.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        colors.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        colors.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        colors.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        colors.setColor(QPalette::Mid, KswordTheme::BorderColor());
        colors.setColor(QPalette::Highlight, KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));
        colors.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
        return colors;
    }

    // 只对真实改变的局部主题写QSS，避免标题/状态反复触发子控件polish。
    void applyProcessDetailLocalStyle(QWidget* widget, const QString& style)
    {
        if (widget && widget->styleSheet() != style)
        {
            widget->setStyleSheet(style);
        }
    }

    // 进程图标只在路径、主题或像素倍率变化时重新生成；缺失路径由既有后台静态查询补齐。
    // label 保存自己的显示键，不改变进程身份与共享的路径图标缓存。
    bool processDetailIconNeedsRefresh(QLabel* label, const QString& path)
    {
        const QVariant previousPath = label->property("ksword_detail_icon_path");
        const quint64 generation = KswordTheme::ThemeSeedGeneration;
        const qreal pixelRatio = label->devicePixelRatioF();
        if (previousPath.isValid() && previousPath.toString() == path
            && label->property("ksword_detail_icon_theme").toULongLong() == generation
            && label->property("ksword_detail_icon_dpr").toReal() == pixelRatio)
        {
            return false;
        }
        label->setProperty("ksword_detail_icon_path", path);
        label->setProperty("ksword_detail_icon_theme", QVariant::fromValue(generation));
        label->setProperty("ksword_detail_icon_dpr", pixelRatio);
        return true;
    }

    bool generalSignatureStateUndecided(const QString& state)
    {
        return state.isEmpty() || state == QStringLiteral("Unknown") || state == QStringLiteral("Unavailable")
            || state == QStringLiteral("Pending") || state == QStringLiteral("No Access")
            || state == QStringLiteral("KernelOnly(Hidden?)") || state == QStringLiteral("CIDTable(可能为误报)")
            || state == QStringLiteral("历史快照");
    }

    constexpr int kInitialDetailDataRefreshDelayMs = 350;
    constexpr int kAffinityMatrixColumnCount = 6;

    // 内嵌 Dock 懒加载的分帧间隔：
    // - 第一段只等一帧，让 Tab 切换与占位文本先完成绘制；
    // - 后续段落用 0ms 继续排队，保证每段之间都能回到事件循环处理绘制与输入。
    constexpr int kEmbeddedViewBuildFirstStageDelayMs = 16;
    constexpr int kEmbeddedViewBuildNextStageDelayMs = 0;

    // 内嵌 Dock 构建排队标记的动态属性名：
    // - 懒加载改成分帧后，Dock 指针在排队期间仍为空；
    // - 用页面容器控件自身的动态属性记录“已排队”，随页面一起销毁，无需窗口类新增成员。
    constexpr char kEmbeddedViewBuildPendingProperty[] = "kswordEmbeddedViewBuildPending";

    // markEmbeddedViewBuildPending 作用：
    // - 入参：内嵌页的容器控件指针；
    // - 处理：容器尚未排队时打上排队标记，用于抑制用户来回切页造成的重复构建；
    // - 返回：true 表示本次调用抢到了构建资格，false 表示已有排队中的构建任务。
    bool markEmbeddedViewBuildPending(QWidget* const embeddedTabWidget)
    {
        if (embeddedTabWidget == nullptr)
        {
            return false;
        }

        if (embeddedTabWidget->property(kEmbeddedViewBuildPendingProperty).toBool())
        {
            return false;
        }

        embeddedTabWidget->setProperty(kEmbeddedViewBuildPendingProperty, true);
        return true;
    }

    // clearEmbeddedViewBuildPending 作用：
    // - 入参：内嵌页的容器控件指针；
    // - 处理：构建流程走完（或中途放弃）后清除排队标记；
    // - 返回：无。
    void clearEmbeddedViewBuildPending(QWidget* const embeddedTabWidget)
    {
        if (embeddedTabWidget != nullptr)
        {
            embeddedTabWidget->setProperty(kEmbeddedViewBuildPendingProperty, false);
        }
    }

    constexpr char kEmbeddedViewContextPendingProperty[] = "ksword_embedded_context_pending";

    bool isCurrentEmbeddedPage(QWidget* tab, QTabWidget* tabs)
    {
        return tab != nullptr && tabs != nullptr && tabs->currentWidget() == tab
            && tab->isVisible() && !tab->window()->isMinimized();
    }

    // attachEmbeddedDockToTabLayout 作用：
    // - 入参：内嵌页布局、占位标签成员引用、已构建完成的 Dock 控件；
    // - 处理：移除并延迟销毁占位标签，再把 Dock 按拉伸因子 1 挂进页面布局；
    // - 返回：无。占位标签指针会被置空，避免重复移除。
    void attachEmbeddedDockToTabLayout(
        QVBoxLayout* const embeddedTabLayout,
        QLabel*& embeddedPlaceholderLabel,
        QWidget* const embeddedDockWidget)
    {
        if (embeddedTabLayout == nullptr || embeddedDockWidget == nullptr)
        {
            return;
        }

        if (embeddedPlaceholderLabel != nullptr)
        {
            embeddedTabLayout->removeWidget(embeddedPlaceholderLabel);
            embeddedPlaceholderLabel->deleteLater();
            embeddedPlaceholderLabel = nullptr;
        }

        // 内嵌 Dock 的复杂控件树不能把自身 minimumSizeHint 反向传播到详情窗口。
        // 页面仍会把全部可用空间分给 Dock，超出部分由 Dock 内部表格和滚动区承载。
        embeddedDockWidget->setMinimumSize(0, 0);
        embeddedDockWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        embeddedTabLayout->addWidget(embeddedDockWidget, 1);
    }

    QWidget* createScrollableTabContent(
        QWidget* const tabPage,
        QVBoxLayout*& contentLayout,
        const int contentMargin,
        const int contentSpacing)
    {
        // 为纵向表单页建立可缩放滚动壳：内容尺寸不足时铺满页面，尺寸过大时显示滚动条。
        if (tabPage == nullptr)
        {
            contentLayout = nullptr;
            return nullptr;
        }

        auto* outerLayout = new QVBoxLayout(tabPage);
        outerLayout->setContentsMargins(0, 0, 0, 0);
        outerLayout->setSpacing(0);

        auto* scrollArea = new QScrollArea(tabPage);
        scrollArea->setWidgetResizable(true);
        scrollArea->setFrameShape(QFrame::NoFrame);
        scrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        scrollArea->setMinimumSize(0, 0);
        scrollArea->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);

        auto* contentWidget = new QWidget(scrollArea);
        contentLayout = new QVBoxLayout(contentWidget);
        contentLayout->setContentsMargins(
            contentMargin,
            contentMargin,
            contentMargin,
            contentMargin);
        contentLayout->setSpacing(contentSpacing);
        scrollArea->setWidget(contentWidget);
        outerLayout->addWidget(scrollArea, 1);
        return contentWidget;
    }

    QString buildAffinityCoreButtonStyle()
    {
        // CPU 核心继续用 checked 表示选中，禁用态交给共享主题。
        return ks::ui::BuildFlatButtonStyle()
            + QStringLiteral("QToolButton{min-width:42px;min-height:28px;padding:2px 6px;border-radius:4px;}");
    }

    QString detailProcessFieldSourceText(const std::uint32_t sourceValue)
    {
        // sourceValue 用途：共享协议中的 Phase-2 字段来源枚举。
        // 返回值：直接给详情页展示的稳定文本。
        switch (sourceValue)
        {
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PUBLIC_API:
            return QStringLiteral("Public API");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_SYSTEM_INFORMER_DYNDATA:
            return QStringLiteral("System Informer DynData");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_RUNTIME_PATTERN:
            return QStringLiteral("Runtime pattern");
        case KSWORD_ARK_PROCESS_FIELD_SOURCE_PDB_PROFILE:
            return QStringLiteral("PDB profile");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString detailProcessR0StatusText(const std::uint32_t statusValue)
    {
        // statusValue 用途：R0 枚举行的扩展读取总体状态。
        // 返回值：详情页状态文本，便于和 ProcessDock 列保持一致。
        switch (statusValue)
        {
        case KSWORD_ARK_PROCESS_R0_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_PROCESS_R0_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_PROCESS_R0_STATUS_DYNDATA_MISSING:
            return QStringLiteral("DynData missing");
        case KSWORD_ARK_PROCESS_R0_STATUS_READ_FAILED:
            return QStringLiteral("Read failed");
        default:
            return QStringLiteral("Unavailable");
        }
    }

    QString detailProcessByteHexText(const std::uint8_t byteValue)
    {
        // byteValue 用途：Protection/SignatureLevel 等单字节内核字段。
        // 返回值：0xNN 大写十六进制文本。
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(byteValue), 2, 16, QChar('0'))
            .toUpper();
    }

    QString detailProcessOffsetText(const std::uint32_t offsetValue)
    {
        // offsetValue 用途：EPROCESS 字段偏移。
        // 返回值：不可用时明确显示 Unavailable，可用时显示 0xNN。
        if (offsetValue == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE || offsetValue == 0x0000FFFFUL)
        {
            return QStringLiteral("Unavailable");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned int>(offsetValue), 0, 16)
            .toUpper();
    }

    QString detailProcessPointerText(
        const QString& availableLabel,
        const bool available,
        const std::uint64_t addressValue,
        const std::uint32_t sourceValue)
    {
        // availableLabel 用途：传入 HandleTable/SectionObject 等领域语义。
        // 返回值：先展示“available”结论，再附带地址和来源。
        if (!available)
        {
            return QStringLiteral("Unavailable (%1)").arg(detailProcessFieldSourceText(sourceValue));
        }
        if (addressValue == 0U)
        {
            return QStringLiteral("%1: null (%2)")
                .arg(availableLabel)
                .arg(detailProcessFieldSourceText(sourceValue));
        }
        const QString addressText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(addressValue), 0, 16)
            .toUpper();
        return QStringLiteral("%1: 0x%2 (%3)")
            .arg(availableLabel)
            .arg(addressText.mid(2))
            .arg(detailProcessFieldSourceText(sourceValue));
    }

    QString detailProcessCapabilityText(const std::uint64_t capabilityMask)
    {
        // capabilityMask 用途：R0 枚举时附带的 DynData capability 快照。
        // 返回值：十六进制位图 + Phase-2 关心的能力名称。
        QStringList capabilityNames;
        if ((capabilityMask & KSW_CAP_PROCESS_OBJECT_TABLE) != 0U)
        {
            capabilityNames << QStringLiteral("ProcessObjectTable");
        }
        if ((capabilityMask & KSW_CAP_SECTION_CONTROL_AREA) != 0U)
        {
            capabilityNames << QStringLiteral("SectionControlArea");
        }
        if ((capabilityMask & KSW_CAP_PROCESS_PROTECTION_PATCH) != 0U)
        {
            capabilityNames << QStringLiteral("ProcessProtectionPatch");
        }
        if (capabilityNames.isEmpty())
        {
            capabilityNames << QStringLiteral("None/Unavailable");
        }
        const QString maskText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(capabilityMask), 0, 16)
            .toUpper();
        return QStringLiteral("%1 (%2)")
            .arg(maskText)
            .arg(capabilityNames.join(QStringLiteral(", ")));
    }

    constexpr std::uint64_t kWindowsEpochOffset100ns = 116444736000000000ULL;
    constexpr ULONG kProcessInfoClassDebugPort = 7UL;
    constexpr ULONG kProcessInfoClassBreakOnTermination = 29UL;
    constexpr ULONG kProcessInfoClassSubsystem = 75UL;

    using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(
        HANDLE,
        PROCESSINFOCLASS,
        PVOID,
        ULONG,
        PULONG);

    QString detailBoolText(const bool value)
    {
        return value ? QStringLiteral("Enabled") : QStringLiteral("Disabled");
    }

    QString detailUnavailableText()
    {
        return QStringLiteral("Unavailable");
    }

    QString detailBytesText(const std::uint64_t value)
    {
        constexpr double kKiB = 1024.0;
        constexpr double kMiB = kKiB * 1024.0;
        constexpr double kGiB = kMiB * 1024.0;
        const double byteValue = static_cast<double>(value);
        if (byteValue >= kGiB)
        {
            return QStringLiteral("%1 GiB (%2 bytes)")
                .arg(byteValue / kGiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        if (byteValue >= kMiB)
        {
            return QStringLiteral("%1 MiB (%2 bytes)")
                .arg(byteValue / kMiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        if (byteValue >= kKiB)
        {
            return QStringLiteral("%1 KiB (%2 bytes)")
                .arg(byteValue / kKiB, 2, 'f', 2)
                .arg(static_cast<qulonglong>(value));
        }
        return QStringLiteral("%1 bytes").arg(static_cast<qulonglong>(value));
    }

    QString detailDurationText(const std::uint64_t duration100ns)
    {
        const std::uint64_t totalSeconds = duration100ns / 10000000ULL;
        const std::uint64_t dayValue = totalSeconds / 86400ULL;
        const std::uint64_t hourValue = (totalSeconds % 86400ULL) / 3600ULL;
        const std::uint64_t minuteValue = (totalSeconds % 3600ULL) / 60ULL;
        const std::uint64_t secondValue = totalSeconds % 60ULL;
        return QStringLiteral("%1d %2h %3m %4s")
            .arg(static_cast<qulonglong>(dayValue))
            .arg(static_cast<qulonglong>(hourValue))
            .arg(static_cast<qulonglong>(minuteValue))
            .arg(static_cast<qulonglong>(secondValue));
    }

    QString detailUptimeText(const std::uint64_t creationTime100ns)
    {
        if (creationTime100ns <= kWindowsEpochOffset100ns)
        {
            return detailUnavailableText();
        }
        const qint64 creationMs = static_cast<qint64>(
            (creationTime100ns - kWindowsEpochOffset100ns) / 10000ULL);
        const qint64 nowMs = QDateTime::currentDateTimeUtc().toMSecsSinceEpoch();
        if (nowMs < creationMs)
        {
            return detailUnavailableText();
        }
        return detailDurationText(static_cast<std::uint64_t>(nowMs - creationMs) * 10000ULL);
    }

    QString detailAffinityText(const ULONG_PTR affinityMask)
    {
        QStringList coreIndexList;
        for (int bitIndex = 0; bitIndex < static_cast<int>(sizeof(ULONG_PTR) * 8U); ++bitIndex)
        {
            const ULONG_PTR currentBit = static_cast<ULONG_PTR>(1ULL) << bitIndex;
            if ((affinityMask & currentBit) != 0U)
            {
                coreIndexList << QString::number(bitIndex);
            }
        }
        const QString maskText = QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(affinityMask), 0, 16)
            .toUpper();
        return coreIndexList.isEmpty()
            ? maskText
            : QStringLiteral("%1 (CPU %2)").arg(maskText, coreIndexList.join(','));
    }

    QString detailIntegrityText(const DWORD integrityRid)
    {
        if (integrityRid >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            return QStringLiteral("System");
        }
        if (integrityRid >= SECURITY_MANDATORY_HIGH_RID)
        {
            return QStringLiteral("High");
        }
        if (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID + 0x1000UL)
        {
            return QStringLiteral("Medium Plus");
        }
        if (integrityRid >= SECURITY_MANDATORY_MEDIUM_RID)
        {
            return QStringLiteral("Medium");
        }
        if (integrityRid >= SECURITY_MANDATORY_LOW_RID)
        {
            return QStringLiteral("Low");
        }
        if (integrityRid != 0U)
        {
            return QStringLiteral("Untrusted");
        }
        return detailUnavailableText();
    }

    QString detailElevationTypeText(const TOKEN_ELEVATION_TYPE elevationType)
    {
        switch (elevationType)
        {
        case TokenElevationTypeFull:
            return QStringLiteral("Full");
        case TokenElevationTypeLimited:
            return QStringLiteral("Limited");
        case TokenElevationTypeDefault:
        default:
            return QStringLiteral("Default");
        }
    }

    bool detailReadTokenInformation(
        const HANDLE tokenHandle,
        const TOKEN_INFORMATION_CLASS informationClass,
        std::vector<std::uint8_t>& bufferOut)
    {
        bufferOut.clear();
        DWORD requiredBytes = 0;
        if (::GetTokenInformation(tokenHandle, informationClass, nullptr, 0, &requiredBytes) != FALSE ||
            ::GetLastError() != ERROR_INSUFFICIENT_BUFFER || requiredBytes == 0U)
        {
            return false;
        }
        bufferOut.resize(requiredBytes);
        return ::GetTokenInformation(
            tokenHandle,
            informationClass,
            bufferOut.data(),
            requiredBytes,
            &requiredBytes) != FALSE;
    }

    template <typename TValue>
    bool detailQueryNtProcessInformation(
        const NtQueryInformationProcessFn queryFunction,
        const HANDLE processHandle,
        const ULONG informationClass,
        TValue& valueOut)
    {
        if (queryFunction == nullptr || processHandle == nullptr || processHandle == INVALID_HANDLE_VALUE)
        {
            return false;
        }
        const NTSTATUS statusValue = queryFunction(
            processHandle,
            static_cast<PROCESSINFOCLASS>(informationClass),
            &valueOut,
            static_cast<ULONG>(sizeof(TValue)),
            nullptr);
        return statusValue >= 0;
    }

    struct DetailWindowCountContext
    {
        DWORD targetPid = 0;
        std::uint32_t count = 0;
    };

    BOOL CALLBACK countDetailTopLevelWindowProc(const HWND windowHandle, const LPARAM contextValue)
    {
        auto* context = reinterpret_cast<DetailWindowCountContext*>(contextValue);
        if (context == nullptr || windowHandle == nullptr)
        {
            return TRUE;
        }
        DWORD ownerPid = 0;
        ::GetWindowThreadProcessId(windowHandle, &ownerPid);
        if (ownerPid == context->targetPid)
        {
            ++context->count;
        }
        return TRUE;
    }

    std::uint32_t detailTopLevelWindowCount(const DWORD pidValue)
    {
        DetailWindowCountContext context{};
        context.targetPid = pidValue;
        ::EnumWindows(countDetailTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));
        return context.count;
    }

    QString detailThreadDesktopText(const DWORD pidValue)
    {
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return detailUnavailableText();
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        QString desktopText;
        if (::Thread32First(snapshotHandle, &threadEntry) != FALSE)
        {
            do
            {
                if (threadEntry.th32OwnerProcessID != pidValue)
                {
                    continue;
                }
                const HDESK desktopHandle = ::GetThreadDesktop(threadEntry.th32ThreadID);
                if (desktopHandle == nullptr)
                {
                    continue;
                }
                wchar_t desktopName[256] = {};
                DWORD returnedBytes = 0;
                if (::GetUserObjectInformationW(
                    desktopHandle,
                    UOI_NAME,
                    desktopName,
                    static_cast<DWORD>(sizeof(desktopName)),
                    &returnedBytes) != FALSE)
                {
                    desktopText = QString::fromWCharArray(desktopName);
                    break;
                }
            } while (::Thread32Next(snapshotHandle, &threadEntry) != FALSE);
        }
        ::CloseHandle(snapshotHandle);
        return desktopText.trimmed().isEmpty() ? detailUnavailableText() : desktopText;
    }

    QString detailSubsystemText(const ULONG subsystemType)
    {
        switch (subsystemType)
        {
        case 0:
            return QStringLiteral("Unknown (0)");
        case 1:
            return QStringLiteral("Win32 (1)");
        case 2:
            return QStringLiteral("Windows GUI (2)");
        case 3:
            return QStringLiteral("Windows CUI (3)");
        default:
            return QStringLiteral("%1").arg(subsystemType);
        }
    }

    constexpr const char* DetailChartExposureProperty = "ksword_detail_chart_exposed";
    bool detailChartPageExposed(const QWidget* page)
    {
        // Native spontaneous Hide need not clear QWidget::isVisible().
        return page != nullptr && page->isVisible()
            && page->property(DetailChartExposureProperty).toBool()
            && !page->window()->isMinimized();
    }

    class ProcessPerformanceHistoryChartWidget final : public QWidget
    {
    public:
        using Sample = ProcessDetailWindow::PerformanceHistorySample;
        using History = std::vector<Sample>;
        using HistorySnapshot = std::shared_ptr<const History>;

        struct Series
        {
            QString label;
            QColor color;
            double Sample::*valueMember = nullptr;
        };

        explicit ProcessPerformanceHistoryChartWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setMinimumHeight(168);
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setContextMenuPolicy(Qt::DefaultContextMenu);
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, false);
            m_seriesAnimation = new QVariantAnimation(this);
            m_seriesAnimation->setDuration(260);
            m_seriesAnimation->setEasingCurve(QEasingCurve::OutCubic);
            m_seriesAnimation->setStartValue(0.0);
            m_seriesAnimation->setEndValue(1.0);
            connect(m_seriesAnimation, &QVariantAnimation::valueChanged, this, [this](const QVariant& value) {
                m_animationProgress = value.toDouble();
                update();
            });
        }

        const HistorySnapshot& historySnapshot() const
        {
            return m_history;
        }

        // 比较规范样本本身，不能只用首尾时间判断：历史替换可修正中间样本。
        static bool historyMatches(const HistorySnapshot& snapshot, const std::deque<Sample>& history)
        {
            if (!snapshot || snapshot->size() != history.size())
            {
                return false;
            }
            const auto sameValue = [](const double left, const double right) {
                return left == right || (std::isnan(left) && std::isnan(right));
            };
            for (std::size_t index = 0; index < history.size(); ++index)
            {
                const Sample& left = (*snapshot)[index];
                const Sample& right = history[index];
                if (left.unixMilliseconds != right.unixMilliseconds
                    || !sameValue(left.cpuPercent, right.cpuPercent)
                    || !sameValue(left.cpuCorePercent, right.cpuCorePercent)
                    || !sameValue(left.memoryMB, right.memoryMB)
                    || !sameValue(left.diskMBps, right.diskMBps)
                    || !sameValue(left.networkRxKBps, right.networkRxKBps)
                    || !sameValue(left.networkTxKBps, right.networkTxKBps)
                    || !sameValue(left.gpuPercent, right.gpuPercent))
                {
                    return false;
                }
            }
            return true;
        }

        void setChartData(
            HistorySnapshot history,
            std::vector<Series> series,
            const QString& unitText,
            const double fixedMaximum,
            const QString& emptyText,
            const QString& timeHeader,
            const QString& copyLatestText,
            const QString& copyHistoryText,
            const double axisStep = 0.0)
        {
            bool projectionChanged = m_history != history || m_series.size() != series.size()
                || m_fixedMaximum != fixedMaximum || m_axisStep != axisStep;
            for (std::size_t index = 0; !projectionChanged && index < series.size(); ++index)
            {
                projectionChanged = m_series[index].valueMember != series[index].valueMember;
            }
            if (projectionChanged)
            {
                m_previousPointCount = pointCount();
                m_historyWindowShifted = m_history && history
                    && m_previousPointCount == history->size()
                    && m_previousPointCount > 1U
                    && history->front().unixMilliseconds > m_history->front().unixMilliseconds;
                m_previousLatestValues.clear();
                for (const Series& oldSeries : m_series)
                {
                    if (m_previousPointCount > 0U && oldSeries.valueMember != nullptr)
                    {
                        m_previousLatestValues.push_back(m_history->back().*oldSeries.valueMember);
                    }
                }
                m_history = std::move(history);
            }
            m_series = std::move(series);
            m_unitText = unitText;
            m_fixedMaximum = fixedMaximum;
            m_axisStep = axisStep;
            m_emptyText = emptyText;
            m_timeHeader = timeHeader;
            m_copyLatestText = copyLatestText;
            m_copyHistoryText = copyHistoryText;
            if (!projectionChanged)
            {
                // 主题/语言只更新画笔与文案；不复制历史、不改横轴、不重启采样插值。
                update();
                return;
            }
            m_axisMaximum = chartMaximum();
            m_linePathsValid = false;
            m_seriesAnimation->stop();
            // 隐藏和空图只保存完整历史，避免无可见帧时仍启动260ms动画计时器。
            if (isVisible() && pointCount() > 0U)
            {
                m_animationProgress = 0.0;
                m_seriesAnimation->start();
            }
            else
            {
                m_animationProgress = 1.0;
                update();
            }
        }

    protected:
        // 切页后立即收尾旧动画；原始曲线数据仍留存，重新显示由窗口提交最新快照。
        bool event(QEvent* eventPointer) override
        {
            if (eventPointer != nullptr && eventPointer->type() == QEvent::Hide && m_seriesAnimation != nullptr)
            {
                m_seriesAnimation->stop();
                m_animationProgress = 1.0;
            }
            return QWidget::event(eventPointer);
        }

        void paintEvent(QPaintEvent* eventPointer) override
        {
            (void)eventPointer;

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const QColor borderColor = KswordTheme::BorderColor();
            const QColor textColor = KswordTheme::TextSecondaryColor();
            const QRectF plotRect = chartRect();
            painter.setPen(QPen(borderColor, 1.0));
            painter.setBrush(Qt::NoBrush);
            painter.drawRect(plotRect);

            if (pointCount() == 0U || m_series.empty())
            {
                painter.setPen(textColor);
                painter.drawText(plotRect, Qt::AlignCenter, m_emptyText);
                return;
            }

            const double axisMaximum = m_axisMaximum;
            drawGrid(painter, plotRect, axisMaximum, borderColor, textColor);
            drawLines(painter, plotRect, axisMaximum);
            drawLegend(painter, textColor);
            drawTimeRange(painter, plotRect, textColor);
        }

        void contextMenuEvent(QContextMenuEvent* eventPointer) override
        {
            if (eventPointer == nullptr || pointCount() == 0U || m_series.empty())
            {
                return;
            }

            QMenu menu(this);
            menu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* const copyLatestAction = menu.addAction(m_copyLatestText);
            QAction* const copyHistoryAction = menu.addAction(m_copyHistoryText);
            QAction* const selectedAction = menu.exec(eventPointer->globalPos());
            if (QApplication::clipboard() == nullptr)
            {
                return;
            }
            if (selectedAction == copyLatestAction)
            {
                QApplication::clipboard()->setText(latestValuesText());
            }
            else if (selectedAction == copyHistoryAction)
            {
                QApplication::clipboard()->setText(historyText());
            }
        }

    private:
        std::size_t pointCount() const
        {
            return m_history ? m_history->size() : 0U;
        }

        QRectF chartRect() const
        {
            return QRectF(rect()).adjusted(62.0, 24.0, -12.0, -29.0);
        }

        double chartMaximum() const
        {
            if (m_fixedMaximum > 0.0)
            {
                return m_fixedMaximum;
            }

            double maximum = 0.0;
            for (const Series& series : m_series)
            {
                if (series.valueMember == nullptr || !m_history)
                {
                    continue;
                }
                for (const Sample& sample : *m_history)
                {
                    maximum = std::max(maximum, std::max(0.0, sample.*series.valueMember));
                }
            }
            if (m_axisStep > 0.0)
            {
                return std::max(m_axisStep, std::ceil(maximum / m_axisStep) * m_axisStep);
            }
            if (maximum <= 0.0)
            {
                return 1.0;
            }
            return std::max(1.0, std::ceil(maximum * 1.1));
        }

        QString valueText(const double value) const
        {
            const int precision = value >= 100.0 ? 0 : (value >= 10.0 ? 1 : 2);
            const QString numberText = QString::number(std::max(0.0, value), 'f', precision);
            if (m_unitText == QStringLiteral("%"))
            {
                return numberText + m_unitText;
            }
            return numberText + QLatin1Char(' ') + m_unitText;
        }

        QString timeText(const qint64 timestamp) const
        {
            return QDateTime::fromMSecsSinceEpoch(timestamp).toString(QStringLiteral("HH:mm:ss"));
        }

        void drawGrid(
            QPainter& painter,
            const QRectF& plotRect,
            const double axisMaximum,
            const QColor& borderColor,
            const QColor& textColor) const
        {
            painter.setPen(QPen(borderColor, 1.0, Qt::DotLine));
            for (int gridIndex = 0; gridIndex <= 4; ++gridIndex)
            {
                const double ratio = static_cast<double>(gridIndex) / 4.0;
                const double y = plotRect.bottom() - plotRect.height() * ratio;
                painter.drawLine(QPointF(plotRect.left(), y), QPointF(plotRect.right(), y));
                painter.setPen(textColor);
                painter.drawText(
                    QRectF(2.0, y - 9.0, plotRect.left() - 7.0, 18.0),
                    Qt::AlignRight | Qt::AlignVCenter,
                    valueText(axisMaximum * ratio));
                painter.setPen(QPen(borderColor, 1.0, Qt::DotLine));
            }
        }

        double animatedXRatio(const std::size_t pointIndex, const std::size_t pointCount) const
        {
            if (pointCount <= 1U)
            {
                return 0.0;
            }

            const double targetRatio =
                static_cast<double>(pointIndex) / static_cast<double>(pointCount - 1U);
            double startRatio = targetRatio;
            if (m_historyWindowShifted && m_previousPointCount == pointCount)
            {
                startRatio = pointIndex + 1U < pointCount
                    ? static_cast<double>(pointIndex + 1U) / static_cast<double>(pointCount - 1U)
                    : 1.0;
            }
            else if (m_previousPointCount + 1U == pointCount && m_previousPointCount > 1U)
            {
                startRatio = pointIndex < m_previousPointCount
                    ? static_cast<double>(pointIndex) / static_cast<double>(m_previousPointCount - 1U)
                    : 1.0;
            }

            return startRatio + (targetRatio - startRatio) * m_animationProgress;
        }

        // 路径只依赖数据、坐标与动画进度；普通expose/滚动/换色不再重复投影1800点。
        void ensureLinePaths(const QRectF& plotRect, const double axisMaximum)
        {
            const qreal pixelRatio = devicePixelRatioF();
            if (m_linePathsValid && m_cachedPlotRect == plotRect
                && m_cachedAxisMaximum == axisMaximum && m_cachedPixelRatio == pixelRatio
                && m_cachedAnimationProgress == m_animationProgress)
            {
                return;
            }
            m_cachedLinePaths.clear();
            m_cachedLinePaths.reserve(m_series.size());
            m_cachedPlotRect = plotRect;
            m_cachedAxisMaximum = axisMaximum;
            m_cachedPixelRatio = pixelRatio;
            m_cachedAnimationProgress = m_animationProgress;
            m_linePathsValid = true;
            const std::size_t pointCount = this->pointCount();
            if (pointCount == 0U)
            {
                return;
            }

            for (std::size_t seriesIndex = 0; seriesIndex < m_series.size(); ++seriesIndex)
            {
                const Series& series = m_series[seriesIndex];
                m_cachedLinePaths.emplace_back();
                QPainterPath& linePath = m_cachedLinePaths.back();
                if (series.valueMember == nullptr)
                {
                    continue;
                }
                const std::size_t seriesPointCount = pointCount;
                for (std::size_t pointIndex = 0; pointIndex < seriesPointCount; ++pointIndex)
                {
                    const double x = plotRect.left()
                        + plotRect.width() * animatedXRatio(pointIndex, seriesPointCount);
                    double displayValue = (*m_history)[pointIndex].*series.valueMember;
                    if (pointIndex + 1U == seriesPointCount && m_animationProgress < 1.0)
                    {
                        const double startValue = seriesIndex < m_previousLatestValues.size()
                            ? m_previousLatestValues[seriesIndex] : displayValue;
                        displayValue = startValue + (displayValue - startValue) * m_animationProgress;
                    }
                    const double valueRatio = std::min(
                        1.0,
                        std::max(0.0, displayValue) / axisMaximum);
                    const double y = plotRect.bottom() - plotRect.height() * valueRatio;
                    if (pointIndex == 0U)
                    {
                        linePath.moveTo(x, y);
                    }
                    else
                    {
                        linePath.lineTo(x, y);
                    }
                }
            }
        }

        void drawLines(QPainter& painter, const QRectF& plotRect, const double axisMaximum)
        {
            ensureLinePaths(plotRect, axisMaximum);
            for (std::size_t seriesIndex = 0; seriesIndex < m_cachedLinePaths.size(); ++seriesIndex)
            {
                painter.setPen(QPen(m_series[seriesIndex].color, 2.0));
                painter.setBrush(Qt::NoBrush);
                painter.drawPath(m_cachedLinePaths[seriesIndex]);
            }
        }

        void drawLegend(QPainter& painter, const QColor& textColor) const
        {
            double x = 8.0;
            constexpr double y = 12.0;
            painter.setPen(textColor);
            for (const Series& series : m_series)
            {
                painter.setPen(QPen(series.color, 2.0));
                painter.drawLine(QPointF(x, y), QPointF(x + 15.0, y));
                x += 20.0;
                painter.setPen(textColor);
                const QFontMetrics metrics(painter.font());
                painter.drawText(QPointF(x, y + 4.0), series.label);
                x += static_cast<double>(metrics.horizontalAdvance(series.label)) + 16.0;
            }
        }

        void drawTimeRange(QPainter& painter, const QRectF& plotRect, const QColor& textColor) const
        {
            if (pointCount() == 0U)
            {
                return;
            }
            painter.setPen(textColor);
            const QRectF leftTextRect(plotRect.left(), plotRect.bottom() + 5.0, 120.0, 18.0);
            const QRectF rightTextRect(plotRect.right() - 120.0, plotRect.bottom() + 5.0, 120.0, 18.0);
            painter.drawText(leftTextRect, Qt::AlignLeft | Qt::AlignVCenter, timeText(m_history->front().unixMilliseconds));
            painter.drawText(rightTextRect, Qt::AlignRight | Qt::AlignVCenter, timeText(m_history->back().unixMilliseconds));
        }

        QString latestValuesText() const
        {
            if (pointCount() == 0U)
            {
                return QString();
            }
            QStringList lines;
            lines << (m_timeHeader + QStringLiteral(": ") + timeText(m_history->back().unixMilliseconds));
            for (const Series& series : m_series)
            {
                if (series.valueMember != nullptr)
                {
                    lines << (series.label + QStringLiteral(": ") + valueText(m_history->back().*series.valueMember));
                }
            }
            return lines.join(QLatin1Char('\n'));
        }

        QString historyText() const
        {
            QStringList headerFields;
            headerFields << m_timeHeader;
            for (const Series& series : m_series)
            {
                headerFields << series.label;
            }

            QStringList lines;
            lines << headerFields.join(QLatin1Char('\t'));
            for (std::size_t pointIndex = 0; pointIndex < pointCount(); ++pointIndex)
            {
                QStringList rowFields;
                rowFields << timeText((*m_history)[pointIndex].unixMilliseconds);
                for (const Series& series : m_series)
                {
                    rowFields << valueText(series.valueMember != nullptr ? (*m_history)[pointIndex].*series.valueMember : 0.0);
                }
                lines << rowFields.join(QLatin1Char('\t'));
            }
            return lines.join(QLatin1Char('\n'));
        }

        HistorySnapshot m_history;
        std::vector<Series> m_series;
        QString m_unitText;
        QString m_emptyText;
        QString m_timeHeader;
        QString m_copyLatestText;
        QString m_copyHistoryText;
        double m_fixedMaximum = 0.0;
        double m_axisStep = 0.0;
        double m_axisMaximum = 1.0;
        std::vector<QPainterPath> m_cachedLinePaths;
        QRectF m_cachedPlotRect;
        double m_cachedAxisMaximum = 1.0;
        double m_cachedAnimationProgress = 1.0;
        qreal m_cachedPixelRatio = 0.0;
        bool m_linePathsValid = false;
        std::vector<double> m_previousLatestValues;
        std::size_t m_previousPointCount = 0U;
        bool m_historyWindowShifted = false;
        QVariantAnimation* m_seriesAnimation = nullptr;
        double m_animationProgress = 1.0;
    };

    // CpuCoreUsageGridWidget：
    // - 复用 HardwareDock 的“近方形小折线矩阵”视觉结构展示逐逻辑处理器占用；
    // - 单个自绘控件代替表格和大量 QLabel，核心数较多时仍保持轻量；
    // - 高度随宽度和核心数量自动收敛，页面只产生纵向滚动，不再出现超宽核心表。
    class CpuCoreUsageGridWidget final : public QWidget
    {
    public:
        explicit CpuCoreUsageGridWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setMinimumSize(0, kCellHeight);
        }

        void setCoreValues(
            std::vector<ProcessDetailWindow::CpuCoreValue> coreValues,
            const bool multipleProcessorGroups)
        {
            m_coreValues = std::move(coreValues);
            m_multipleProcessorGroups = multipleProcessorGroups;
            QSet<std::uint32_t> liveProcessorIndexes;
            for (const ProcessDetailWindow::CpuCoreValue& core : m_coreValues)
            {
                liveProcessorIndexes.insert(core.processorIndex);
                std::deque<double>& history = m_historyByProcessorIndex[core.processorIndex];
                history.push_back(core.sampleReady ? std::clamp(core.percent, 0.0, 100.0) : 0.0);
                while (history.size() > kHistoryLength)
                {
                    history.pop_front();
                }
            }
            for (auto historyIt = m_historyByProcessorIndex.begin();
                 historyIt != m_historyByProcessorIndex.end();)
            {
                if (!liveProcessorIndexes.contains(historyIt->first))
                {
                    historyIt = m_historyByProcessorIndex.erase(historyIt);
                }
                else
                {
                    ++historyIt;
                }
            }
            // 隐藏时仍记录每个核心的历史；可见布局留到Show，固定高度不重复通知父布局。
            if (isVisible())
            {
                synchronizeHeight();
                update();
            }
        }

        QSize sizeHint() const override
        {
            constexpr int kReferenceWidth = 820;
            return QSize(kReferenceWidth, contentHeightForWidth(kReferenceWidth));
        }

        bool hasHeightForWidth() const override
        {
            return true;
        }

        int heightForWidth(const int availableWidth) const override
        {
            return contentHeightForWidth(availableWidth);
        }

    protected:
        bool event(QEvent* eventPointer) override
        {
            const bool handled = QWidget::event(eventPointer);
            if (eventPointer != nullptr &&
                (eventPointer->type() == QEvent::Resize || eventPointer->type() == QEvent::Show))
            {
                synchronizeHeight();
            }
            return handled;
        }

        void paintEvent(QPaintEvent* eventPointer) override
        {
            const QRegion exposedRegion = eventPointer != nullptr
                ? eventPointer->region() : QRegion(rect());
            if (exposedRegion.isEmpty())
            {
                return;
            }
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const int columnCount = gridColumnCount(width());
            const qreal cellWidth = std::max<qreal>(
                1.0,
                (static_cast<qreal>(width()) - kGridSpacing * (columnCount - 1))
                    / static_cast<qreal>(columnCount));
            const QColor cpuColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu);
            const QColor cardColor = KswordTheme::SurfaceAltColor();
            const QColor borderColor = KswordTheme::BorderColor();
            const QColor primaryTextColor = KswordTheme::TextPrimaryColor();
            const QColor secondaryTextColor = KswordTheme::TextSecondaryColor();

            // Derive candidate rows/columns from the dirty bounds, then respect disjoint regions.
            // Include the antialias halo and integer rounding of fractional cell bounds.
            const QRectF exposedBounds = QRectF(exposedRegion.boundingRect()).adjusted(-2.0, -2.0, 2.0, 2.0);
            const int coreCount = static_cast<int>(m_coreValues.size());
            const int rowCount = (coreCount + columnCount - 1) / columnCount;
            const int firstRow = std::max(0, static_cast<int>(std::floor(exposedBounds.top() / (kCellHeight + kGridSpacing))));
            const int lastRow = std::min(rowCount - 1, static_cast<int>(std::floor(exposedBounds.bottom() / (kCellHeight + kGridSpacing))));
            const int firstColumn = std::max(0, static_cast<int>(std::floor(exposedBounds.left() / (cellWidth + kGridSpacing))));
            const int lastColumn = std::min(columnCount - 1, static_cast<int>(std::floor(exposedBounds.right() / (cellWidth + kGridSpacing))));
            for (int row = firstRow; row <= lastRow; ++row)
            {
                for (int column = firstColumn; column <= lastColumn; ++column)
                {
                    const int index = row * columnCount + column;
                    if (index >= coreCount)
                    {
                        break;
                    }
                    const QRectF cellRect(
                        column * (cellWidth + kGridSpacing),
                        row * (kCellHeight + kGridSpacing),
                        cellWidth,
                        kCellHeight);
                    // QPainter clips pixels automatically; skip path/text generation as well.
                    if (!exposedRegion.intersects(cellRect.adjusted(-1.0, -1.0, 1.0, 1.0).toAlignedRect()))
                    {
                        continue;
                    }
                    const ProcessDetailWindow::CpuCoreValue& core =
                        m_coreValues[static_cast<std::size_t>(index)];

                    painter.setPen(QPen(borderColor, 1.0));
                    painter.setBrush(cardColor);
                    painter.drawRoundedRect(cellRect.adjusted(0.5, 0.5, -0.5, -0.5), 4.0, 4.0);

                    const QRectF contentRect = cellRect.adjusted(8.0, 5.0, -8.0, -8.0);
                    QFont labelFont = painter.font();
                    labelFont.setWeight(QFont::DemiBold);
                    painter.setFont(labelFont);
                    painter.setPen(secondaryTextColor);
                    painter.drawText(contentRect, Qt::AlignLeft | Qt::AlignTop, coordinateText(core));

                    QFont valueFont = painter.font();
                    valueFont.setWeight(QFont::Bold);
                    painter.setFont(valueFont);
                    painter.setPen(core.sampleReady ? primaryTextColor : secondaryTextColor);
                    painter.drawText(
                        contentRect,
                        Qt::AlignRight | Qt::AlignTop,
                        core.sampleReady
                            ? QString::number(core.percent, 'f', core.percent >= 10.0 ? 1 : 2)
                                + QStringLiteral("%")
                            : QStringLiteral("—"));

                    const QRectF plotRect = cellRect.adjusted(7.0, 27.0, -7.0, -7.0);
                    drawHistoryLine(
                        painter,
                        plotRect,
                        m_historyByProcessorIndex[core.processorIndex],
                        cpuColor,
                        borderColor);
                }
            }

            if (m_coreValues.empty())
            {
                painter.setPen(secondaryTextColor);
                painter.drawText(rect(), Qt::AlignCenter, QStringLiteral("—"));
            }
        }

    private:
        static constexpr int kCellHeight = 82;
        static constexpr int kGridSpacing = 6;
        static constexpr std::size_t kHistoryLength = 30U;

        static void drawHistoryLine(
            QPainter& painter,
            const QRectF& plotRect,
            const std::deque<double>& history,
            const QColor& lineColor,
            const QColor& borderColor)
        {
            painter.save();
            painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
            painter.setPen(QPen(KswordTheme::WithAlpha(borderColor, 90), 1.0, Qt::DotLine));
            painter.drawLine(
                QPointF(plotRect.left(), plotRect.center().y()),
                QPointF(plotRect.right(), plotRect.center().y()));
            painter.drawRect(plotRect);
            if (history.empty())
            {
                painter.restore();
                return;
            }

            QPainterPath linePath;
            const std::size_t leadingEmptySamples = kHistoryLength > history.size()
                ? kHistoryLength - history.size()
                : 0U;
            for (std::size_t index = 0; index < history.size(); ++index)
            {
                const double xRatio = kHistoryLength <= 1U
                    ? 0.0
                    : static_cast<double>(leadingEmptySamples + index)
                        / static_cast<double>(kHistoryLength - 1U);
                const double yRatio = std::clamp(history[index] / 100.0, 0.0, 1.0);
                const QPointF point(
                    plotRect.left() + plotRect.width() * xRatio,
                    plotRect.bottom() - plotRect.height() * yRatio);
                if (index == 0U)
                {
                    linePath.moveTo(point);
                }
                else
                {
                    linePath.lineTo(point);
                }
            }
            painter.setPen(QPen(lineColor, 1.6));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
            painter.restore();
        }

        int gridColumnCount(const int availableWidth) const
        {
            const int coreCount = std::max(1, static_cast<int>(m_coreValues.size()));
            const int idealColumns = std::max(
                1,
                static_cast<int>(std::ceil(std::sqrt(static_cast<double>(coreCount)))));
            const int widthLimitedColumns = std::max(1, (std::max(1, availableWidth) + kGridSpacing) / 86);
            return std::clamp(std::min(idealColumns, widthLimitedColumns), 1, coreCount);
        }

        int contentHeightForWidth(const int availableWidth) const
        {
            const int columnCount = gridColumnCount(availableWidth);
            const int itemCount = std::max(1, static_cast<int>(m_coreValues.size()));
            const int rowCount = std::max(1, (itemCount + columnCount - 1) / columnCount);
            return rowCount * kCellHeight + (rowCount - 1) * kGridSpacing;
        }

        QString coordinateText(const ProcessDetailWindow::CpuCoreValue& core) const
        {
            return m_multipleProcessorGroups
                ? QStringLiteral("G%1:L%2").arg(core.group).arg(core.number)
                : QStringLiteral("L%1").arg(core.number);
        }

        void synchronizeHeight()
        {
            const int targetHeight = contentHeightForWidth(std::max(1, width()));
            if (minimumHeight() != targetHeight || maximumHeight() != targetHeight)
            {
                setFixedHeight(targetHeight);
            }
        }

        std::vector<ProcessDetailWindow::CpuCoreValue> m_coreValues;
        std::unordered_map<std::uint32_t, std::deque<double>> m_historyByProcessorIndex;
        bool m_multipleProcessorGroups = false;
    };

    // CpuThreadUsageCardGridWidget：线程默认折叠，点击后展开逐核心历史折线矩阵。
    class CpuThreadUsageCardGridWidget final : public QWidget
    {
    public:
        explicit CpuThreadUsageCardGridWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
            setMinimumSize(0, kCollapsedCardHeight);
            setCursor(Qt::PointingHandCursor);
        }

        void setThreadValues(
            std::vector<ProcessDetailWindow::ThreadCpuCoreValue> threadValues,
            const bool multipleProcessorGroups)
        {
            m_threadValues = std::move(threadValues);
            m_cardLayoutDirty = true;
            QSet<std::uint32_t> liveThreadIds;
            for (const ProcessDetailWindow::ThreadCpuCoreValue& thread : m_threadValues)
            {
                liveThreadIds.insert(thread.threadId);
                CoreHistoryMap& coreHistory = m_historyByThreadId[thread.threadId];
                QSet<std::uint32_t> liveProcessorIndexes;
                for (const ProcessDetailWindow::CpuCoreValue& core : thread.cores)
                {
                    liveProcessorIndexes.insert(core.processorIndex);
                    auto historyIt = coreHistory.find(core.processorIndex);
                    if (historyIt == coreHistory.end()
                        && (!core.sampleReady || core.percent <= 0.005))
                    {
                        continue;
                    }
                    if (historyIt == coreHistory.end())
                    {
                        historyIt = coreHistory.emplace(
                            core.processorIndex,
                            std::deque<double>{}).first;
                    }
                    std::deque<double>& history = historyIt->second;
                    history.push_back(
                        core.sampleReady ? std::clamp(core.percent, 0.0, 100.0) : 0.0);
                    while (history.size() > kHistoryLength)
                    {
                        history.pop_front();
                    }
                }
                for (auto coreIt = coreHistory.begin(); coreIt != coreHistory.end();)
                {
                    if (!liveProcessorIndexes.contains(coreIt->first))
                    {
                        coreIt = coreHistory.erase(coreIt);
                    }
                    else
                    {
                        ++coreIt;
                    }
                }
            }
            for (auto threadIt = m_historyByThreadId.begin(); threadIt != m_historyByThreadId.end();)
            {
                if (!liveThreadIds.contains(threadIt->first))
                {
                    m_expandedThreadIds.remove(threadIt->first);
                    threadIt = m_historyByThreadId.erase(threadIt);
                }
                else
                {
                    ++threadIt;
                }
            }
            m_multipleProcessorGroups = multipleProcessorGroups;
            m_sortPending = true;
            // 线程历史与展开状态持续维护，只有显示顺序与尺寸计算按可见性合并。
            if (isVisible())
            {
                synchronizeVisibleValues();
                update();
            }
        }

        QSize sizeHint() const override
        {
            constexpr int kReferenceWidth = 820;
            return QSize(kReferenceWidth, contentHeightForWidth(kReferenceWidth));
        }

        bool hasHeightForWidth() const override
        {
            return true;
        }

        int heightForWidth(const int availableWidth) const override
        {
            return contentHeightForWidth(availableWidth);
        }

    protected:
        bool event(QEvent* eventPointer) override
        {
            const bool handled = QWidget::event(eventPointer);
            if (eventPointer != nullptr && eventPointer->type() == QEvent::Show)
            {
                synchronizeVisibleValues();
            }
            else if (eventPointer != nullptr && eventPointer->type() == QEvent::Resize)
            {
                synchronizeHeight();
            }
            return handled;
        }

        void paintEvent(QPaintEvent* eventPointer) override
        {
            const QRegion exposedRegion = eventPointer != nullptr
                ? eventPointer->region() : QRegion(rect());
            if (exposedRegion.isEmpty())
            {
                return;
            }
            ensureCardLayout(std::max(1, width()));
            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, true);

            const QColor cpuColor = KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu);
            const QColor cardColor = KswordTheme::SurfaceAltColor();
            const QColor borderColor = KswordTheme::BorderColor();
            const QColor primaryTextColor = KswordTheme::TextPrimaryColor();
            const QColor secondaryTextColor = KswordTheme::TextSecondaryColor();
            const QRectF exposedBounds = QRectF(exposedRegion.boundingRect()).adjusted(-2.0, -2.0, 2.0, 2.0);
            const int firstCardIndex = std::max(0, static_cast<int>(std::upper_bound(
                m_cardTops.cbegin(), m_cardTops.cend(), exposedBounds.top()) - m_cardTops.cbegin()) - 1);

            for (int index = firstCardIndex; index < static_cast<int>(m_threadValues.size()); ++index)
            {
                const ProcessDetailWindow::ThreadCpuCoreValue& thread =
                    m_threadValues[static_cast<std::size_t>(index)];
                const bool expanded = m_expandedThreadIds.contains(thread.threadId);
                const qreal cardTop = m_cardTops[static_cast<std::size_t>(index)];
                const qreal currentCardHeight = m_cardTops[static_cast<std::size_t>(index) + 1U]
                    - cardTop - kGridSpacing;
                const QRectF cardRect(0.0, cardTop, static_cast<qreal>(width()), currentCardHeight);
                if (cardRect.top() > exposedBounds.bottom())
                {
                    break;
                }
                if (!exposedRegion.intersects(cardRect.adjusted(-1.0, -1.0, 1.0, 1.0).toAlignedRect()))
                {
                    continue;
                }

                painter.setPen(QPen(borderColor, 1.0));
                painter.setBrush(cardColor);
                painter.drawRoundedRect(cardRect.adjusted(0.5, 0.5, -0.5, -0.5), 5.0, 5.0);

                const QRectF arrowRect(cardRect.left() + 10.0, cardRect.top() + 14.0, 13.0, 13.0);
                QPainterPath arrowPath;
                if (expanded)
                {
                    arrowPath.moveTo(arrowRect.left(), arrowRect.top() + 3.0);
                    arrowPath.lineTo(arrowRect.right(), arrowRect.top() + 3.0);
                    arrowPath.lineTo(arrowRect.center().x(), arrowRect.bottom());
                }
                else
                {
                    arrowPath.moveTo(arrowRect.left() + 3.0, arrowRect.top());
                    arrowPath.lineTo(arrowRect.right(), arrowRect.center().y());
                    arrowPath.lineTo(arrowRect.left() + 3.0, arrowRect.bottom());
                }
                arrowPath.closeSubpath();
                painter.setPen(Qt::NoPen);
                painter.setBrush(secondaryTextColor);
                painter.drawPath(arrowPath);

                const QRectF headerRect(
                    cardRect.left() + 31.0,
                    cardRect.top() + 6.0,
                    cardRect.width() - 43.0,
                    kCollapsedCardHeight - 12.0);
                QFont titleFont = painter.font();
                titleFont.setWeight(QFont::DemiBold);
                painter.setFont(titleFont);
                painter.setPen(primaryTextColor);
                painter.drawText(
                    headerRect,
                    Qt::AlignLeft | Qt::AlignVCenter,
                    QStringLiteral("TID %1").arg(thread.threadId));
                painter.setPen(cpuColor);
                painter.drawText(
                    headerRect,
                    Qt::AlignRight | Qt::AlignVCenter,
                    QString::number(thread.cpuPercent, 'f', thread.cpuPercent >= 10.0 ? 1 : 2)
                        + QStringLiteral("%"));

                if (!expanded)
                {
                    continue;
                }

                painter.setPen(QPen(borderColor, 1.0));
                painter.drawLine(
                    QPointF(cardRect.left() + 10.0, cardRect.top() + kCollapsedCardHeight),
                    QPointF(cardRect.right() - 10.0, cardRect.top() + kCollapsedCardHeight));

                const int columnCount = expandedCoreColumnCount(
                    static_cast<int>(thread.cores.size()),
                    width());
                const qreal bodyLeft = cardRect.left() + kExpandedBodyPadding;
                const qreal bodyTop = cardRect.top() + kCollapsedCardHeight + kExpandedBodyPadding;
                const qreal bodyWidth = std::max<qreal>(
                    1.0,
                    cardRect.width() - 2.0 * kExpandedBodyPadding);
                const qreal coreCardWidth = std::max<qreal>(
                    1.0,
                    (bodyWidth - kCoreGridSpacing * (columnCount - 1))
                        / static_cast<qreal>(columnCount));
                const auto threadHistoryIt = m_historyByThreadId.find(thread.threadId);
                const int coreCount = static_cast<int>(thread.cores.size());
                const int rowCount = (coreCount + columnCount - 1) / columnCount;
                const int firstRow = std::max(0, static_cast<int>(std::floor((exposedBounds.top() - bodyTop) / (kCoreChartHeight + kCoreGridSpacing))));
                const int lastRow = std::min(rowCount - 1, static_cast<int>(std::floor((exposedBounds.bottom() - bodyTop) / (kCoreChartHeight + kCoreGridSpacing))));
                const int firstColumn = std::max(0, static_cast<int>(std::floor((exposedBounds.left() - bodyLeft) / (coreCardWidth + kCoreGridSpacing))));
                const int lastColumn = std::min(columnCount - 1, static_cast<int>(std::floor((exposedBounds.right() - bodyLeft) / (coreCardWidth + kCoreGridSpacing))));
                for (int row = firstRow; row <= lastRow; ++row)
                {
                    for (int column = firstColumn; column <= lastColumn; ++column)
                    {
                        const int coreIndex = row * columnCount + column;
                        if (coreIndex >= coreCount)
                        {
                            break;
                        }
                        const QRectF coreCardRect(
                            bodyLeft + column * (coreCardWidth + kCoreGridSpacing),
                            bodyTop + row * (kCoreChartHeight + kCoreGridSpacing),
                            coreCardWidth,
                            kCoreChartHeight);
                        if (!exposedRegion.intersects(coreCardRect.adjusted(-1.0, -1.0, 1.0, 1.0).toAlignedRect()))
                        {
                            continue;
                        }
                        const ProcessDetailWindow::CpuCoreValue& core =
                            thread.cores[static_cast<std::size_t>(coreIndex)];
                        const std::deque<double>* history = nullptr;
                        if (threadHistoryIt != m_historyByThreadId.end())
                        {
                            const auto coreHistoryIt = threadHistoryIt->second.find(core.processorIndex);
                            if (coreHistoryIt != threadHistoryIt->second.end())
                            {
                                history = &coreHistoryIt->second;
                            }
                        }
                        drawCoreChart(
                            painter,
                            coreCardRect,
                            core,
                            history,
                            cpuColor,
                            borderColor,
                            primaryTextColor,
                            secondaryTextColor);
                    }
                }
            }

            if (m_threadValues.empty())
            {
                painter.setPen(secondaryTextColor);
                painter.drawText(rect(), Qt::AlignCenter, QStringLiteral("—"));
            }
        }

        void mousePressEvent(QMouseEvent* eventPointer) override
        {
            if (eventPointer == nullptr || eventPointer->button() != Qt::LeftButton)
            {
                QWidget::mousePressEvent(eventPointer);
                return;
            }

            ensureCardLayout(std::max(1, width()));
            const qreal clickY = eventPointer->position().y();
            const int index = std::max(0, static_cast<int>(std::upper_bound(
                m_cardTops.cbegin(), m_cardTops.cend(), clickY) - m_cardTops.cbegin()) - 1);
            if (index < static_cast<int>(m_threadValues.size()))
            {
                const ProcessDetailWindow::ThreadCpuCoreValue& thread =
                    m_threadValues[static_cast<std::size_t>(index)];
                const qreal top = m_cardTops[static_cast<std::size_t>(index)];
                const qreal height = m_cardTops[static_cast<std::size_t>(index) + 1U] - top - kGridSpacing;
                const QRectF cardRect(0.0, top, static_cast<qreal>(width()), height);
                if (cardRect.contains(eventPointer->position()))
                {
                    if (m_expandedThreadIds.contains(thread.threadId))
                    {
                        m_expandedThreadIds.remove(thread.threadId);
                    }
                    else
                    {
                        m_expandedThreadIds.insert(thread.threadId);
                    }
                    m_cardLayoutDirty = true;
                    synchronizeHeight();
                    updateGeometry();
                    update();
                    eventPointer->accept();
                    return;
                }
            }
            QWidget::mousePressEvent(eventPointer);
        }

    private:
        using CoreHistoryMap = std::unordered_map<std::uint32_t, std::deque<double>>;

        // 首次可见或收到可见样本时排序一次；高度真正变化时setFixedHeight自行通知布局。
        void synchronizeVisibleValues()
        {
            if (m_sortPending)
            {
                std::stable_sort(m_threadValues.begin(), m_threadValues.end(),
                    [](const ProcessDetailWindow::ThreadCpuCoreValue& left,
                       const ProcessDetailWindow::ThreadCpuCoreValue& right) {
                        if (left.cpuPercent != right.cpuPercent)
                        {
                            return left.cpuPercent > right.cpuPercent;
                        }
                        return left.threadId < right.threadId;
                    });
                m_sortPending = false;
                m_cardLayoutDirty = true;
            }
            synchronizeHeight();
        }

        static constexpr int kCollapsedCardHeight = 44;
        static constexpr int kGridSpacing = 8;
        static constexpr int kCoreGridSpacing = 6;
        static constexpr int kCoreChartHeight = 72;
        static constexpr int kExpandedBodyPadding = 8;
        static constexpr std::size_t kHistoryLength = 30U;

        int expandedCoreColumnCount(const int coreCountValue, const int availableWidth) const
        {
            const int coreCount = std::max(1, coreCountValue);
            const int idealColumns = std::max(
                1,
                static_cast<int>(std::ceil(std::sqrt(static_cast<double>(coreCount)))));
            const int innerWidth = std::max(1, availableWidth - 2 * kExpandedBodyPadding);
            const int widthLimitedColumns = std::max(
                1,
                (innerWidth + kCoreGridSpacing) / 105);
            return std::clamp(std::min(idealColumns, widthLimitedColumns), 1, coreCount);
        }

        int expandedBodyHeight(
            const ProcessDetailWindow::ThreadCpuCoreValue& thread,
            const int availableWidth) const
        {
            const int coreCount = std::max(1, static_cast<int>(thread.cores.size()));
            const int columnCount = expandedCoreColumnCount(coreCount, availableWidth);
            const int rowCount = std::max(1, (coreCount + columnCount - 1) / columnCount);
            return 2 * kExpandedBodyPadding
                + rowCount * kCoreChartHeight
                + (rowCount - 1) * kCoreGridSpacing;
        }

        int cardHeight(
            const ProcessDetailWindow::ThreadCpuCoreValue& thread,
            const int availableWidth) const
        {
            return kCollapsedCardHeight
                + (m_expandedThreadIds.contains(thread.threadId)
                    ? expandedBodyHeight(thread, availableWidth)
                    : 0);
        }

        // One prefix layout serves painting, hit testing and the current-width height query.
        // It contains positions only; all histories and stable thread identities stay in their existing maps.
        void ensureCardLayout(const int availableWidth) const
        {
            if (!m_cardLayoutDirty && m_cardLayoutWidth == availableWidth)
            {
                return;
            }
            m_cardTops.resize(m_threadValues.size() + 1U);
            qreal top = 0.0;
            for (std::size_t index = 0; index < m_threadValues.size(); ++index)
            {
                m_cardTops[index] = top;
                top += cardHeight(m_threadValues[index], availableWidth) + kGridSpacing;
            }
            m_cardTops.back() = top;
            m_cardLayoutWidth = availableWidth;
            m_cardLayoutDirty = false;
        }

        int contentHeightForWidth(const int availableWidth) const
        {
            if (m_threadValues.empty())
            {
                return kCollapsedCardHeight;
            }
            // sizeHint may ask about its 820px reference; do not evict the visible-width index for it.
            if (availableWidth != std::max(1, width()))
            {
                int height = (static_cast<int>(m_threadValues.size()) - 1) * kGridSpacing;
                for (const ProcessDetailWindow::ThreadCpuCoreValue& thread : m_threadValues)
                {
                    height += cardHeight(thread, availableWidth);
                }
                return height;
            }
            ensureCardLayout(availableWidth);
            return static_cast<int>(m_cardTops.back() - kGridSpacing);
        }

        QString coordinateText(const ProcessDetailWindow::CpuCoreValue& core) const
        {
            return m_multipleProcessorGroups
                ? QStringLiteral("G%1:L%2").arg(core.group).arg(core.number)
                : QStringLiteral("L%1").arg(core.number);
        }

        static void drawHistoryLine(
            QPainter& painter,
            const QRectF& plotRect,
            const std::deque<double>* history,
            const QColor& lineColor,
            const QColor& borderColor)
        {
            painter.save();
            painter.setClipRect(plotRect.adjusted(-1.0, -1.0, 1.0, 1.0));
            painter.setPen(QPen(KswordTheme::WithAlpha(borderColor, 90), 1.0, Qt::DotLine));
            painter.drawLine(
                QPointF(plotRect.left(), plotRect.center().y()),
                QPointF(plotRect.right(), plotRect.center().y()));
            painter.drawRect(plotRect);
            if (history == nullptr || history->empty())
            {
                painter.restore();
                return;
            }

            QPainterPath linePath;
            const std::size_t leadingEmptySamples = kHistoryLength > history->size()
                ? kHistoryLength - history->size()
                : 0U;
            for (std::size_t index = 0; index < history->size(); ++index)
            {
                const double xRatio = kHistoryLength <= 1U
                    ? 0.0
                    : static_cast<double>(leadingEmptySamples + index)
                        / static_cast<double>(kHistoryLength - 1U);
                const double yRatio = std::clamp((*history)[index] / 100.0, 0.0, 1.0);
                const QPointF point(
                    plotRect.left() + plotRect.width() * xRatio,
                    plotRect.bottom() - plotRect.height() * yRatio);
                if (index == 0U)
                {
                    linePath.moveTo(point);
                }
                else
                {
                    linePath.lineTo(point);
                }
            }
            painter.setPen(QPen(lineColor, 1.4));
            painter.setBrush(Qt::NoBrush);
            painter.drawPath(linePath);
            painter.restore();
        }

        void drawCoreChart(
            QPainter& painter,
            const QRectF& cardRect,
            const ProcessDetailWindow::CpuCoreValue& core,
            const std::deque<double>* history,
            const QColor& lineColor,
            const QColor& borderColor,
            const QColor& primaryTextColor,
            const QColor& secondaryTextColor) const
        {
            painter.setPen(QPen(borderColor, 1.0));
            painter.setBrush(KswordTheme::SurfaceColor());
            painter.drawRoundedRect(cardRect.adjusted(0.5, 0.5, -0.5, -0.5), 4.0, 4.0);

            QFont coreFont = painter.font();
            coreFont.setWeight(QFont::DemiBold);
            painter.setFont(coreFont);
            painter.setPen(secondaryTextColor);
            painter.drawText(
                cardRect.adjusted(6.0, 3.0, -6.0, -cardRect.height() + 22.0),
                Qt::AlignLeft | Qt::AlignVCenter,
                coordinateText(core));
            painter.setPen(core.sampleReady ? primaryTextColor : secondaryTextColor);
            painter.drawText(
                cardRect.adjusted(6.0, 3.0, -6.0, -cardRect.height() + 22.0),
                Qt::AlignRight | Qt::AlignVCenter,
                core.sampleReady
                    ? QString::number(core.percent, 'f', core.percent >= 10.0 ? 1 : 2)
                        + QStringLiteral("%")
                    : QStringLiteral("—"));
            drawHistoryLine(
                painter,
                cardRect.adjusted(6.0, 24.0, -6.0, -6.0),
                history,
                lineColor,
                borderColor);
        }

        void synchronizeHeight()
        {
            const int targetHeight = contentHeightForWidth(std::max(1, width()));
            if (minimumHeight() != targetHeight || maximumHeight() != targetHeight)
            {
                setFixedHeight(targetHeight);
            }
        }

        std::vector<ProcessDetailWindow::ThreadCpuCoreValue> m_threadValues;
        std::unordered_map<std::uint32_t, CoreHistoryMap> m_historyByThreadId;
        QSet<std::uint32_t> m_expandedThreadIds;
        mutable std::vector<qreal> m_cardTops;
        mutable int m_cardLayoutWidth = -1;
        mutable bool m_cardLayoutDirty = true;
        bool m_sortPending = false; // 隐藏期间多个样本只需在Show时提交最终排序。
        bool m_multipleProcessorGroups = false;
    };
}

void ProcessDetailWindow::rebuildActionAffinityCoreButtons()
{
    if (m_affinityMatrixLayout == nullptr)
    {
        return;
    }

    while (QLayoutItem* const layoutItem =
           m_affinityMatrixLayout->takeAt(0))
    {
        if (QWidget* const childWidget = layoutItem->widget())
        {
            childWidget->deleteLater();
        }
        delete layoutItem;
    }
    m_affinityCoreButtons.clear();
    const bool includeProcessorGroup =
        m_actionAffinityReadable &&
        ks::process::logicalProcessorGroupCount(
            m_actionAffinitySnapshot.processors) > 1U;
    if (m_affinityDescriptionLabel != nullptr)
    {
        QString descriptionText = ks::i18n::text(
            QStringLiteral("process.detail.affinity.description"),
            QString());
        if (includeProcessorGroup)
        {
            descriptionText += QStringLiteral("\n") + ks::i18n::text(
                QStringLiteral(
                    "process.detail.affinity.description.multigroup"),
                QString());
        }
        m_affinityDescriptionLabel->setText(descriptionText);
    }
    if (!m_actionAffinityReadable)
    {
        return;
    }

    const QString affinityCoreButtonStyle =
        buildAffinityCoreButtonStyle();
    std::uint16_t currentGroup =
        std::numeric_limits<std::uint16_t>::max();
    int matrixRow = 0;
    int matrixColumn = 0;
    for (const ks::process::LogicalProcessorState& processor :
         m_actionAffinitySnapshot.processors)
    {
        if (processor.coordinate.group != currentGroup)
        {
            if (matrixColumn != 0)
            {
                ++matrixRow;
            }
            currentGroup = processor.coordinate.group;
            matrixColumn = 0;
            if (includeProcessorGroup)
            {
                QLabel* const groupLabel = new QLabel(
                    ks::i18n::text(
                        QStringLiteral("process.detail.affinity.group"),
                        QString())
                        .arg(currentGroup),
                    m_affinityActionGroup);
                groupLabel->setStyleSheet(
                    QStringLiteral("color:%1;font-weight:700;")
                        .arg(KswordTheme::TextSecondaryHex()));
                m_affinityMatrixLayout->addWidget(
                    groupLabel,
                    matrixRow++,
                    0,
                    1,
                    kAffinityMatrixColumnCount);
            }
        }

        QToolButton* const coreButton =
            new QToolButton(m_affinityActionGroup);
        const QString identityText = QString::fromStdString(
            ks::process::processorDisplayIdentityText(
                processor.coordinate,
                includeProcessorGroup));
        const QString topologyText =
            QString::fromStdString(processor.topologyLabel);
        coreButton->setText(
            topologyText.isEmpty()
                ? identityText
                : identityText + QStringLiteral("\n") + topologyText);
        coreButton->setCheckable(true);
        coreButton->setAutoRaise(false);
        coreButton->setFocusPolicy(Qt::NoFocus);
        coreButton->setStyleSheet(affinityCoreButtonStyle);
        QString processorToolTip = ks::i18n::text(
                QStringLiteral("process.detail.affinity.core_tooltip"),
                QString())
                .arg(identityText, topologyText);
        if (processor.constrainedByHardAffinity)
        {
            processorToolTip += QStringLiteral("\n") +
                ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.constraint_tooltip"),
                    QString());
        }
        else if (!processor.available)
        {
            processorToolTip += QStringLiteral("\n") +
                ks::i18n::text(
                    QStringLiteral(
                        "process.detail.affinity.allocated_tooltip"),
                    QString());
        }
        coreButton->setToolTip(processorToolTip);
        const ks::process::LogicalProcessorCoordinate coordinate =
            processor.coordinate;
        connect(
            coreButton,
            &QToolButton::clicked,
            this,
            [this, coordinate](const bool enabled)
            {
                toggleActionAffinityCore(coordinate, enabled);
            });
        m_affinityMatrixLayout->addWidget(
            coreButton,
            matrixRow,
            matrixColumn);
        m_affinityCoreButtons.push_back(coreButton);
        ++matrixColumn;
        if (matrixColumn == kAffinityMatrixColumnCount)
        {
            matrixColumn = 0;
            ++matrixRow;
        }
    }
    m_affinityMatrixLayout->setColumnStretch(
        kAffinityMatrixColumnCount,
        1);
}

// closeEvent：只处理已创建的工作台，不为关闭而懒加载；确认时拒绝重入与全局退出中的重复关闭。
void ProcessDetailWindow::closeEvent(QCloseEvent* event)
{
    if (m_workbenchCloseApproved)
    {
        m_workbenchCloseApproved = false;
        setProperty("ksword_memory_detail_close_guard_active", false);
        if (m_embeddedMemoryDock && !m_embeddedMemoryDock->workbenchQuitPreparationCurrent())
        {
            m_embeddedMemoryDock->cancelWorkbenchQuit();
            if (event) event->ignore();
            return;
        }
        QWidget::closeEvent(event);
        return;
    }
    if ((qApp && qApp->property("ksword_memory_quit_guard_active").toBool())
        || property("ksword_memory_detail_close_guard_active").toBool())
    {
        if (event) event->ignore();
        return;
    }
    if (m_embeddedMemoryDock)
    {
        const QPointer<ProcessDetailWindow> self(this);
        const QPointer<MemoryDock> dock(m_embeddedMemoryDock);
        const auto ticket = ++m_workbenchCloseTicket;
        setProperty("ksword_memory_detail_close_guard_active", true);
        m_workbenchClosePending = true;
        const auto status = dock->confirmWorkbenchQuit([self, dock, ticket](bool allowed) {
            if (!self || !self->m_workbenchClosePending || ticket != self->m_workbenchCloseTicket) return;
            self->m_workbenchClosePending = false;
            if (!allowed || !dock || self->m_embeddedMemoryDock != dock || !dock->workbenchQuitPreparationCurrent())
            {
                if (!self) return;
                self->setProperty("ksword_memory_detail_close_guard_active", false);
                if (dock) dock->cancelWorkbenchQuit();
                return;
            }
            if (!self) return;
            self->m_workbenchCloseApproved = true;
            QTimer::singleShot(0, self, [self, ticket]() {
                if (self && ticket == self->m_workbenchCloseTicket && self->m_workbenchCloseApproved) self->close();
            });
        });
        if (!self) { if (event) event->ignore(); return; }
        if (status == ks::ui::LeaveEntryStatus::Pending)
        {
            QObject::connect(dock, &QObject::destroyed, self, [self, ticket, dockAddress = dock.data()]() {
                if (self && ticket == self->m_workbenchCloseTicket)
                {
                    ++self->m_workbenchCloseTicket;
                    self->m_workbenchClosePending = false;
                    if (self->m_embeddedMemoryDock == dockAddress) self->m_embeddedMemoryDock = nullptr;
                    self->setProperty("ksword_memory_detail_close_guard_active", false);
                }
            });
            if (event) event->ignore();
            return;
        }
        m_workbenchClosePending = false;
        setProperty("ksword_memory_detail_close_guard_active", false);
        if (status != ks::ui::LeaveEntryStatus::Completed)
        {
            if (event) event->ignore();
            return;
        }
    }
    QWidget::closeEvent(event);
}

ProcessDetailWindow::ProcessDetailWindow(const ks::process::ProcessRecord& baseRecord, QWidget* parent)
    : QWidget(parent)
    , m_baseRecord(baseRecord)
{
    // 声明根QSS业务所有权要早于所有主题与框架入口，避免两方轮流覆盖根样式。
    setProperty("ksword_detail_theme_owner", true);
    // 构造入口日志：记录目标 PID 与 identity 关键字段。
    kLogEvent ctorStartEvent;
    info << ctorStartEvent
        << "[ProcessDetailWindow] 构造开始, pid="
        << m_baseRecord.pid
        << ", createTime100ns="
        << m_baseRecord.creationTime100ns
        << eol;

    // 详情窗口是独立顶层窗口：非 Dock、非模态，不阻塞主界面。
    setWindowFlag(Qt::Window, true);
    setWindowModality(Qt::NonModal);
    setAttribute(Qt::WA_DeleteOnClose, true);
    // 保留原有“客户区约 75%”的初始宽度，但不再设置 maximumWidth。
    // 初始尺寸和最低尺寸只受目标屏幕可用区域约束，用户之后可以自由拖大或最大化。
    constexpr int kPreferredWindowWidth = 1160;
    const int initialWindowWidth = std::min(
        kPreferredWindowWidth,
        calculateStandaloneWindowInitialWidth(
            parent,
            this,
            0.75,
            kPreferredWindowWidth));
    ks::ui::applyResponsiveWindowGeometry(
        this,
        parent,
        QSize(initialWindowWidth, 760),
        QSize(720, 640),
        0.9);

    // identity 用于日志和窗口复用定位。
    m_identityKey = ks::process::BuildProcessIdentityKey(
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns);

    // 构造阶段不做同步静态详情查询：
    // - QueryProcessStaticDetailByPid 会读取命令行、令牌、签名等慢字段；
    // - WinVerifyTrust 在证书链/网络策略异常时可能明显阻塞 UI；
    // - 打开窗口必须先返回事件循环，缺失字段交给后台任务补齐。
    const bool needStaticQuery =
        m_baseRecord.imagePath.empty() ||
        m_baseRecord.commandLine.empty() ||
        m_baseRecord.userName.empty() ||
        m_baseRecord.signatureState.empty() ||
        m_baseRecord.signatureState == "Pending";
    if (needStaticQuery && m_baseRecord.pid != 0)
    {
        kLogEvent ctorStaticQueryDeferredEvent;
        info << ctorStaticQueryDeferredEvent
            << "[ProcessDetailWindow] 构造阶段跳过同步静态查询，改为后台补齐, pid="
            << m_baseRecord.pid
            << eol;
    }

    // 按“建 UI -> 连信号 -> 延迟填充 -> 首次异步刷新”顺序初始化。
    // 完整详情会读取图标、父进程、令牌与缓解策略。窗口显示稳定后再开始，避免开窗时抢占 UI 线程。
    initializeUi();
    initializeConnections();
    QTimer::singleShot(kInitialDetailDataRefreshDelayMs, this, [this]() {
        refreshDetailTabTexts();
        requestAsyncStaticDetailRefresh(true);
        requestAsyncDetailOverviewRefresh();
        requestInitialRefreshForCurrentTab();
    });

    // 构造结束日志：标记窗口初始化链路完成。
    kLogEvent ctorFinishEvent;
    info << ctorFinishEvent
        << "[ProcessDetailWindow] 构造完成, pid="
        << m_baseRecord.pid
        << ", identity="
        << m_identityKey
        << eol;
}

void ProcessDetailWindow::updateBaseRecord(const ks::process::ProcessRecord& baseRecord)
{
    // 更新入口日志：记录新快照 PID 与旧 identity。
    kLogEvent updateRecordStartEvent;
    info << updateRecordStartEvent
        << "[ProcessDetailWindow] updateBaseRecord: 开始更新, incomingPid="
        << baseRecord.pid
        << ", oldIdentity="
        << m_identityKey
        << eol;

    const std::string oldIdentityKey = m_identityKey;

    // 外部推送新快照时：
    // 1) 先保留已有的“已补齐字段”；
    // 2) 再合并新快照；
    // 3) 必要时补查静态详情，避免字段被空值覆盖。
    ks::process::ProcessRecord mergedRecord = baseRecord;
    if (mergedRecord.imagePath.empty()) mergedRecord.imagePath = m_baseRecord.imagePath;
    if (mergedRecord.commandLine.empty()) mergedRecord.commandLine = m_baseRecord.commandLine;
    if (mergedRecord.userName.empty()) mergedRecord.userName = m_baseRecord.userName;
    if (mergedRecord.startTimeText.empty()) mergedRecord.startTimeText = m_baseRecord.startTimeText;
    if (mergedRecord.signatureState.empty()) mergedRecord.signatureState = m_baseRecord.signatureState;
    if (mergedRecord.signaturePublisher.empty()) mergedRecord.signaturePublisher = m_baseRecord.signaturePublisher;
    if (mergedRecord.r0FieldFlags == 0U) mergedRecord.r0FieldFlags = m_baseRecord.r0FieldFlags;
    if (mergedRecord.r0ImagePath.empty()) mergedRecord.r0ImagePath = m_baseRecord.r0ImagePath;
    if (mergedRecord.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_UNAVAILABLE) mergedRecord.r0Status = m_baseRecord.r0Status;
    if (mergedRecord.r0DynDataCapabilityMask == 0U) mergedRecord.r0DynDataCapabilityMask = m_baseRecord.r0DynDataCapabilityMask;
    if (mergedRecord.r0ProtectionSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0ProtectionSource = m_baseRecord.r0ProtectionSource;
    if (mergedRecord.r0SignatureLevelSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SignatureLevelSource = m_baseRecord.r0SignatureLevelSource;
    if (mergedRecord.r0SectionSignatureLevelSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SectionSignatureLevelSource = m_baseRecord.r0SectionSignatureLevelSource;
    if (mergedRecord.r0ObjectTableSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0ObjectTableSource = m_baseRecord.r0ObjectTableSource;
    if (mergedRecord.r0SectionObjectSource == KSWORD_ARK_PROCESS_FIELD_SOURCE_UNAVAILABLE) mergedRecord.r0SectionObjectSource = m_baseRecord.r0SectionObjectSource;
    if (mergedRecord.r0ProtectionOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0ProtectionOffset = m_baseRecord.r0ProtectionOffset;
    if (mergedRecord.r0SignatureLevelOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SignatureLevelOffset = m_baseRecord.r0SignatureLevelOffset;
    if (mergedRecord.r0SectionSignatureLevelOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SectionSignatureLevelOffset = m_baseRecord.r0SectionSignatureLevelOffset;
    if (mergedRecord.r0ObjectTableOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0ObjectTableOffset = m_baseRecord.r0ObjectTableOffset;
    if (mergedRecord.r0SectionObjectOffset == KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE) mergedRecord.r0SectionObjectOffset = m_baseRecord.r0SectionObjectOffset;
    if (mergedRecord.r0ObjectTableAddress == 0U) mergedRecord.r0ObjectTableAddress = m_baseRecord.r0ObjectTableAddress;
    if (mergedRecord.r0SectionObjectAddress == 0U) mergedRecord.r0SectionObjectAddress = m_baseRecord.r0SectionObjectAddress;
    mergedRecord.r0Protection = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0Protection : m_baseRecord.r0Protection;
    mergedRecord.r0SignatureLevel = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0SignatureLevel : m_baseRecord.r0SignatureLevel;
    mergedRecord.r0SectionSignatureLevel = (mergedRecord.r0FieldFlags != 0U) ? mergedRecord.r0SectionSignatureLevel : m_baseRecord.r0SectionSignatureLevel;
    mergedRecord.signatureTrusted = mergedRecord.signatureTrusted || m_baseRecord.signatureTrusted;

    const bool needStaticQuery =
        mergedRecord.imagePath.empty() ||
        mergedRecord.commandLine.empty() ||
        mergedRecord.userName.empty() ||
        mergedRecord.signatureState.empty() ||
        mergedRecord.signatureState == "Pending";
    const bool shouldTryStaticBackgroundRefresh =
        needStaticQuery &&
        mergedRecord.pid != 0 &&
        !m_staticDetailRefreshing &&
        !m_staticDetailRefreshAttempted;
    if (needStaticQuery && mergedRecord.pid != 0)
    {
        // updateBaseRecord 可能由 ProcessDock 周期刷新触发。
        // 这里不能同步调用 QueryProcessStaticDetailByPid，否则打开详情窗口后每轮刷新都可能卡 UI。
        kLogEvent updateRecordStaticDeferredEvent;
        dbg << updateRecordStaticDeferredEvent
            << "[ProcessDetailWindow] updateBaseRecord: 静态信息缺失，保留现有值并等待后台补齐, pid="
            << mergedRecord.pid
            << eol;
    }

    m_baseRecord = mergedRecord;
    m_identityKey = ks::process::BuildProcessIdentityKey(
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns);
    const bool identityChanged = m_identityKey != oldIdentityKey;
    if (identityChanged)
    {
        // 同一窗口如果被复用于新 identity，需要重置一次性后台刷新状态。
        // 否则旧进程的首刷标记会阻止新进程数据按需加载。
        m_staticDetailRefreshing = false;
        m_staticDetailRefreshAttempted = false;
        ++m_staticDetailRefreshTicket;
        m_detailOverviewRefreshing = false;
        ++m_detailOverviewRefreshTicket;
        m_detailOverviewResult = DetailOverviewRefreshResult{};
        ++m_threadInspectRefreshTicket;
        m_threadInspectRefreshing = false;
        m_threadInspectRows.reset();
        m_threadInspectPublishedRows.reset();
        if (m_threadInspectTable) m_threadInspectTable->clearRows();
        m_threadInspectInitialRefreshStarted = false;
        m_moduleInitialRefreshStarted = false;
        m_tokenInitialRefreshStarted = false;
        m_tokenSwitchInitialRefreshStarted = false;
        m_sectionInfoInitialRefreshStarted = false;
        m_hotkeyRows.reset();
        m_keyboardHotkeyRows.reset();
        m_keyboardHookRows.reset();
        m_hotkeyRefreshing = false;
        m_keyboardRefreshing = false;
        m_keyboardRefreshPending = false;
        if (m_hotkeyTable) m_hotkeyTable->clearRows();
        if (m_keyboardHotkeyTable) m_keyboardHotkeyTable->clearRows();
        if (m_keyboardHookTable) m_keyboardHookTable->clearRows();
        m_hotkeyInitialRefreshStarted = false;
        m_keyboardInitialRefreshStarted = false;
        m_pebInitialRefreshStarted = false;
        ++m_hotkeyRefreshTicket;
        ++m_keyboardRefreshTicket;
        m_performanceHistory.clear();
        m_cpuCoreViewSample = CpuCoreViewSample{};
        // 身份切换清掉旧图形的数据；隐藏页保留dirty，不能在新对象上显示旧进程曲线。
        refreshPerformanceHistoryCharts();
        refreshCpuCoreView(true);
    }
    refreshDetailTabTexts();
    if (shouldTryStaticBackgroundRefresh || identityChanged)
    {
        requestAsyncStaticDetailRefresh(true);
    }
    if (identityChanged)
    {
        requestAsyncDetailOverviewRefresh();
    }
    requestInitialRefreshForCurrentTab();

    // 更新结束日志：输出新 identity 与关键字段状态。
    kLogEvent updateRecordFinishEvent;
    info << updateRecordFinishEvent
        << "[ProcessDetailWindow] updateBaseRecord: 完成, pid="
        << m_baseRecord.pid
        << ", newIdentity="
        << m_identityKey
        << ", signatureState="
        << m_baseRecord.signatureState
        << eol;
}

std::uint32_t ProcessDetailWindow::pid() const
{
    return m_baseRecord.pid;
}

std::string ProcessDetailWindow::identityKey() const
{
    return m_identityKey;
}

void ProcessDetailWindow::setPerformanceHistory(std::vector<PerformanceHistorySample> history)
{
    constexpr std::size_t kMaximumHistorySamples = 1800U;
    if (history.size() > kMaximumHistorySamples)
    {
        history.erase(history.begin(), history.end() - static_cast<std::ptrdiff_t>(kMaximumHistorySamples));
    }

    m_performanceHistory.clear();
    for (const PerformanceHistorySample& sample : history)
    {
        if (sample.unixMilliseconds > 0)
        {
            m_performanceHistory.push_back(sample);
        }
    }
    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::appendPerformanceHistorySample(const PerformanceHistorySample& sample)
{
    if (sample.unixMilliseconds <= 0)
    {
        return;
    }

    m_performanceHistory.push_back(sample);
    constexpr std::size_t kMaximumHistorySamples = 1800U;
    while (m_performanceHistory.size() > kMaximumHistorySamples)
    {
        m_performanceHistory.pop_front();
    }
    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::setCpuCoreViewSample(CpuCoreViewSample sample)
{
    // 页面采用懒加载；尚未构造控件时只保存最新区间，首次进入即可直接展示。
    m_cpuCoreViewSample = std::move(sample);
    refreshCpuCoreView(true);
}

void ProcessDetailWindow::scheduleChartPresentationRestore()
{
    if (m_chartPresentationRestoreQueued)
    {
        return;
    }
    m_chartPresentationRestoreQueued = true;
    QTimer::singleShot(0, this, [this]() {
        m_chartPresentationRestoreQueued = false;
        if (m_performanceChartsDirty && detailChartPageExposed(m_performanceTab))
        {
            refreshPerformanceHistoryCharts();
        }
        if (m_cpuCorePresentationDirty && detailChartPageExposed(m_cpuCoreTab))
        {
            refreshCpuCoreView();
        }
    });
}

bool ProcessDetailWindow::eventFilter(QObject* watched, QEvent* event)
{
    if (event != nullptr && event->type() == QEvent::Show
        && (watched == m_embeddedHandleTab || watched == m_embeddedMemoryTab
            || watched == m_embeddedNetworkTab || watched == m_embeddedWindowTab))
    {
        QTimer::singleShot(0, this, [this] { requestInitialRefreshForCurrentTab(); });
    }
    if (event != nullptr && (watched == m_performanceTab || watched == m_cpuCoreTab))
    {
        if (event->type() == QEvent::Hide)
        {
            watched->setProperty(DetailChartExposureProperty, false);
            if (watched == m_performanceTab) m_performanceChartsDirty = true;
            else m_cpuCorePresentationDirty = true;
        }
        else if (event->type() == QEvent::Show)
        {
            watched->setProperty(DetailChartExposureProperty, true);
            // Populate an ordinary first Show before paint, then cover native restore ordering.
            if (watched == m_performanceTab && m_performanceChartsDirty)
            {
                refreshPerformanceHistoryCharts();
            }
            else if (watched == m_cpuCoreTab && m_cpuCorePresentationDirty)
            {
                refreshCpuCoreView();
            }
            scheduleChartPresentationRestore();
        }
    }
    return QWidget::eventFilter(watched, event);
}

void ProcessDetailWindow::changeEvent(QEvent* event)
{
    QWidget::changeEvent(event);

    // 自己写palette/QSS产生的同步事件不能落到数据刷新路径。
    if (event == nullptr || m_themeStyleApplying)
    {
        return;
    }

    if (event->type() == QEvent::WindowStateChange)
    {
        // Also retry after state publication: a native Show can precede clearing Minimized.
        scheduleChartPresentationRestore();
        return;
    }

    if (event->type() == QEvent::LanguageChange)
    {
        // 只有语言变化重建译文；普通样式事件不能重新读取图标、文件和对象详情。
        refreshDetailTabTexts();
        refreshPerformanceHistoryCharts();
        refreshCpuCoreView();
        return;
    }

    if (event->type() == QEvent::WindowStateChange && !isMinimized())
    {
        QTimer::singleShot(0, this, [this] { requestInitialRefreshForCurrentTab(); });
    }

    const bool isThemeEvent =
        (event->type() == QEvent::PaletteChange) ||
        (event->type() == QEvent::ApplicationPaletteChange) ||
        (event->type() == QEvent::StyleChange);
    if (!isThemeEvent)
    {
        return;
    }

    const QPalette desiredPalette = processDetailThemePalette(this);
    const QString desiredStyle = buildProcessDetailRootStyle();
    const bool themeChanged = !property(kProcessDetailThemePalette).isValid()
        || property(kProcessDetailThemePalette).value<QPalette>() != desiredPalette
        || property(kProcessDetailThemeStyle).toString() != desiredStyle;
    if (themeChanged || styleSheet() != desiredStyle || palette() != desiredPalette)
    {
        applyThemeStyle();
    }
    if (!themeChanged)
    {
        return; // 同一主题下的StyleChange没有状态数据或文字需要重建。
    }

    if (m_threadInspectStatusLabel != nullptr)
    {
        updateThreadInspectStatusLabel(m_threadInspectStatusLabel->text(), m_threadInspectRefreshing);
    }

    if (m_moduleTable != nullptr && m_moduleRecords) rebuildModuleTable();

    if (m_moduleStatusLabel != nullptr)
    {
        updateModuleStatusLabel(m_moduleStatusLabel->text(), m_moduleRefreshing);
        if (!m_moduleRefreshing && (!m_moduleRecords || m_moduleRecords->empty()))
        {
            m_moduleStatusLabel->setStyleSheet(buildStateLabelStyle(statusErrorColor(), 700));
        }
    }

    if (m_tokenStatusLabel != nullptr)
    {
        m_tokenStatusLabel->setStyleSheet(
            m_tokenRefreshing
            ? buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700)
            : buildStateLabelStyle(statusIdleColor(), 600));
    }

    if (m_tokenSwitchStatusLabel != nullptr)
    {
        const QString statusText = m_tokenSwitchStatusLabel->text();
        if (statusText.contains(QStringLiteral("失败")) || statusText.contains(QStringLiteral("失败项")))
        {
            m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else if (statusText.contains(QStringLiteral("完成")) || statusText.contains(QStringLiteral("成功")))
        {
            m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
        else
        {
            m_tokenSwitchStatusLabel->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
        }
    }

    if (m_pebStatusLabel != nullptr)
    {
        const bool hasDiagnostic = m_pebStatusLabel->text().contains(QStringLiteral(" | "));
        if (m_pebRefreshing)
        {
            m_pebStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
        }
        else if (hasDiagnostic)
        {
            m_pebStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            m_pebStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }

    if (m_hotkeyStatusLabel != nullptr)
    {
        const QString statusText = m_hotkeyStatusLabel->text();
        if (m_hotkeyRefreshing)
        {
            m_hotkeyStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
        }
        else if (statusText.contains(QStringLiteral("无公开API")) || statusText.contains(QStringLiteral("失败")))
        {
            m_hotkeyStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            m_hotkeyStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }

    if (m_keyboardStatusLabel != nullptr)
    {
        const QString statusText = m_keyboardStatusLabel->text();
        if (m_keyboardRefreshing)
        {
            m_keyboardStatusLabel->setStyleSheet(buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
        }
        else if (statusText.contains(QStringLiteral("失败")) || statusText.contains(QStringLiteral("不可用")))
        {
            m_keyboardStatusLabel->setStyleSheet(buildStateLabelStyle(statusWarningColor(), 700));
        }
        else
        {
            m_keyboardStatusLabel->setStyleSheet(buildStateLabelStyle(statusIdleColor(), 600));
        }
    }
}

void ProcessDetailWindow::applyThemeStyle()
{
    if (m_themeStyleApplying)
    {
        return;
    }
    QScopedValueRollback<bool> applying(m_themeStyleApplying, true); // 所有退出路径自动释放主题重入门禁。

    // 显式设置窗口调色板：
    // - Win11 下必须手动强制窗口背景，避免被系统自动接管为亮色。
    const QPalette themedPalette = processDetailThemePalette(this);
    const QString rootStyle = buildProcessDetailRootStyle();
    const bool colorsChanged = !property(kProcessDetailThemePalette).isValid()
        || property(kProcessDetailThemePalette).value<QPalette>() != themedPalette;
    if (palette() != themedPalette)
    {
        setPalette(themedPalette);
    }
    setAutoFillBackground(true);
    setAttribute(Qt::WA_StyledBackground, true);
    if (styleSheet() != rootStyle)
    {
        setStyleSheet(rootStyle);
    }

    // 内容页与共享外框共用Window底板；内部卡片/字段保持独立Surface层。
    const std::vector<QWidget*> tabPageList{
        m_detailTab,
        m_performanceTab,
        m_cpuCoreTab,
        m_threadTab,
        m_actionTab,
        m_moduleTab,
        m_tokenTab,
        m_tokenSwitchTab,
        m_kernelObjectTab,
        m_hotkeyTab,
        m_keyboardTab,
        m_pluginTab,
        m_pebTab
    };
    for (QWidget* tabPage : tabPageList)
    {
        if (tabPage == nullptr)
        {
            continue;
        }
        if (tabPage->palette() != themedPalette)
        {
            tabPage->setPalette(themedPalette);
        }
        tabPage->setAutoFillBackground(true);
        tabPage->setAttribute(Qt::WA_StyledBackground, true);
    }

    if (colorsChanged && m_processCpuCoreGrid != nullptr)
    {
        m_processCpuCoreGrid->update();
    }
    if (colorsChanged && m_threadCpuCoreGrid != nullptr)
    {
        m_threadCpuCoreGrid->update();
    }

    if (m_cpuCoreTitleLabel != nullptr)
    {
        applyProcessDetailLocalStyle(m_cpuCoreTitleLabel, QStringLiteral("font-size:16px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
    }
    if (m_cpuCoreDescriptionLabel != nullptr)
    {
        applyProcessDetailLocalStyle(m_cpuCoreDescriptionLabel, QStringLiteral("color:%1;")
            .arg(KswordTheme::TextSecondaryHex()));
    }
    const QString cpuCoreSummaryStyle = QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue).name());
    if (m_cpuCoreSystemValueLabel != nullptr)
    {
        applyProcessDetailLocalStyle(m_cpuCoreSystemValueLabel, cpuCoreSummaryStyle);
    }
    if (m_cpuCoreEquivalentValueLabel != nullptr)
    {
        applyProcessDetailLocalStyle(m_cpuCoreEquivalentValueLabel, cpuCoreSummaryStyle);
    }
    if (colorsChanged)
    {
        refreshPerformanceHistoryCharts(); // 已构造的曲线配色跟随主题，隐藏时仅保留dirty。
        refreshCpuCoreView(); // 真正换色才刷新颜色相关读数，普通StyleChange不重新构建核心卡片。
    }

    if (m_signatureCheckBox != nullptr)
    {
        applyProcessDetailLocalStyle(m_signatureCheckBox, QStringLiteral(
            "QCheckBox { color:%1; font-weight:600; }")
            .arg(KswordTheme::TextPrimaryHex()));
    }

    if (m_tokenRawInfoClassCombo != nullptr || m_tokenRawInputModeCombo != nullptr)
    {
        const QString comboStyle = KswordTheme::ThemedComboBoxStyle();
        if (m_tokenRawInfoClassCombo != nullptr)
        {
            applyProcessDetailLocalStyle(m_tokenRawInfoClassCombo, comboStyle);
        }
        if (m_tokenRawInputModeCombo != nullptr)
        {
            applyProcessDetailLocalStyle(m_tokenRawInputModeCombo, comboStyle);
        }
    }

    setProperty(kProcessDetailThemePalette, QVariant::fromValue(themedPalette));
    setProperty(kProcessDetailThemeStyle, rootStyle);
}

void ProcessDetailWindow::initializeUi()
{
    // UI 初始化入口日志：用于排查窗口初始化顺序。
    kLogEvent initUiEvent;
    info << initUiEvent
        << "[ProcessDetailWindow] initializeUi: 创建根布局和Tab容器。"
        << eol;

    // 根窗口对象名用于样式选择器精确命中。
    setObjectName(QStringLiteral("ProcessDetailWindowRoot"));

    // 页面区保留 QTabWidget，避免影响现有页面跳转、currentChanged 与惰性刷新逻辑。
    // 原生 QTabBar 隐藏后，以左侧单列导航提供全部页面入口。
    auto* windowLayout = new QVBoxLayout(this);
    ks::ui::ConfigureDetailDialogRoot(this);
    auto* summaryHeader = new QWidget(this);
    summaryHeader->setObjectName(QLatin1String("ksword_process_detail_header"));
    summaryHeader->setProperty("ksword_detail_header", true);
    summaryHeader->setAttribute(Qt::WA_StyledBackground);
    auto* summaryLayout = new QVBoxLayout(summaryHeader);
    summaryLayout->setContentsMargins(16, 14, 16, 14);
    summaryLayout->setSpacing(8);
    windowLayout->addWidget(summaryHeader);
    auto* body = new QWidget(this);
    m_rootLayout = new QHBoxLayout(body);
    m_rootLayout->setContentsMargins(0, 0, 0, 0);
    m_rootLayout->setSpacing(0);
    windowLayout->addWidget(body, 1);

    m_tabNavigation = new QWidget(this);
    m_tabNavigation->setObjectName(QStringLiteral("ProcessDetailTabNavigation"));

    m_tabNavigation->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);
    auto* tabNavigationLayout = new QVBoxLayout(m_tabNavigation);
    tabNavigationLayout->setContentsMargins(10, 16, 10, 16);
    tabNavigationLayout->setSpacing(5);

    m_tabWidget = new QTabWidget(this);
    m_tabWidget->setProperty("ksword_detail_tabs", true);
    // QTabWidget 会取所有已构造页面中最大的 minimumSizeHint。详情页采用懒加载，
    // 若沿用默认尺寸策略，新页面创建时会把该提示传播给顶层窗口并触发自动扩张。
    m_tabWidget->setMinimumSize(0, 0);
    m_tabWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    m_tabWidget->tabBar()->hide();
    m_tabNavigationButtonGroup = new QButtonGroup(this);
    m_tabNavigationButtonGroup->setExclusive(true);
    auto* navigationScroll = new QScrollArea(this);
    navigationScroll->setObjectName(QStringLiteral("ProcessDetailNavigationScroll"));
    navigationScroll->setWidgetResizable(true);
    navigationScroll->setFrameShape(QFrame::NoFrame);
    navigationScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    navigationScroll->setWidget(m_tabNavigation);
    ks::ui::ConfigureDetailNavigation(navigationScroll, m_tabNavigation);
    m_rootLayout->addWidget(navigationScroll);
    m_rootLayout->addWidget(m_tabWidget, 1);

    // 先创建轻量页面容器，实际控件树在用户首次进入时构造。
    m_detailTab = new QWidget(m_tabWidget);
    m_performanceTab = new QWidget(m_tabWidget);
    m_cpuCoreTab = new QWidget(m_tabWidget);
    m_threadTab = new QWidget(m_tabWidget);
    m_actionTab = new QWidget(m_tabWidget);
    m_moduleTab = new QWidget(m_tabWidget);
    m_embeddedHandleTab = new QWidget(m_tabWidget);
    m_embeddedMemoryTab = new QWidget(m_tabWidget);
    m_embeddedNetworkTab = new QWidget(m_tabWidget);
    m_soundSourceTab = new QWidget(m_tabWidget);
    m_embeddedWindowTab = new QWidget(m_tabWidget);
    m_tokenTab = new QWidget(m_tabWidget);
    m_tokenSwitchTab = new QWidget(m_tabWidget);
    m_kernelObjectTab = new QWidget(m_tabWidget);
    m_hotkeyTab = new QWidget(m_tabWidget);
    m_keyboardTab = new QWidget(m_tabWidget);
    m_pluginTab = new QWidget(m_tabWidget);
    m_pebTab = new QWidget(m_tabWidget);
    m_kernelCallbackTab = new QWidget(m_tabWidget);

    // QTabWidget 先显示新页，再发 currentChanged 触发惰性构造。
    // 在轻量页壳上提前监听，才能记录首次 Show，避免图表和汇总读数一直被可见性守卫跳过。
    m_performanceTab->installEventFilter(this);
    m_cpuCoreTab->installEventFilter(this);

    m_detailTab->setObjectName(QStringLiteral("ProcessDetailTab_Detail"));
    m_performanceTab->setObjectName(QStringLiteral("ProcessDetailTab_Performance"));
    m_cpuCoreTab->setObjectName(QStringLiteral("ProcessDetailTab_CpuCore"));
    m_threadTab->setObjectName(QStringLiteral("ProcessDetailTab_Thread"));
    m_actionTab->setObjectName(QStringLiteral("ProcessDetailTab_Action"));
    m_moduleTab->setObjectName(QStringLiteral("ProcessDetailTab_Module"));
    m_embeddedHandleTab->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedHandle"));
    m_embeddedMemoryTab->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedMemory"));
    m_embeddedNetworkTab->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedNetwork"));
    m_soundSourceTab->setObjectName(QStringLiteral("ProcessDetailTab_SoundSource"));
    m_embeddedWindowTab->setObjectName(QStringLiteral("ProcessDetailTab_EmbeddedWindow"));
    m_tokenTab->setObjectName(QStringLiteral("ProcessDetailTab_Token"));
    m_tokenSwitchTab->setObjectName(QStringLiteral("ProcessDetailTab_TokenSwitch"));
    m_kernelObjectTab->setObjectName(QStringLiteral("ProcessDetailTab_ProcessDetailEvidence"));
    m_hotkeyTab->setObjectName(QStringLiteral("ProcessDetailTab_Hotkey"));
    m_keyboardTab->setObjectName(QStringLiteral("ProcessDetailTab_Keyboard"));
    m_pluginTab->setObjectName(QStringLiteral("ProcessDetailTab_Plugin"));
    m_pebTab->setObjectName(QStringLiteral("ProcessDetailTab_Peb"));
    m_kernelCallbackTab->setObjectName(QStringLiteral("ProcessDetailTab_KernelCallbackTable"));

    // 详细信息是默认页，保留在开窗阶段构建；其余页面均由左侧导航首次访问触发构造。
    initializeDetailTab();
    m_initializedTabs.insert(m_detailTab);

    // 为 Tab 指定图标与标题文本。
    m_tabWidget->addTab(m_detailTab, QIcon(":/Icon/process_details.svg"), "详细信息");
    m_tabWidget->addTab(
        m_performanceTab,
        QIcon(":/Icon/process_performance.svg"),
        ks::i18n::text(QStringLiteral("process.detail.tab.performance"), QString()));
    m_tabWidget->addTab(
        m_cpuCoreTab,
        QIcon(":/Icon/process_performance.svg"),
        ks::i18n::text(QStringLiteral("process.detail.tab.cpu_core"), QString()));
    m_tabWidget->addTab(m_threadTab, QIcon(":/Icon/process_tree.svg"), "线程");
    m_tabWidget->addTab(m_actionTab, QIcon(":/Icon/process_priority.svg"), "操作");
    m_tabWidget->addTab(m_moduleTab, QIcon(":/Icon/process_list.svg"), "模块");
    m_tabWidget->addTab(m_embeddedHandleTab, QIcon(":/Icon/handle_refresh.svg"), "句柄");
    m_tabWidget->addTab(m_embeddedMemoryTab, QIcon(":/Icon/process_list.svg"), "内存");
    m_tabWidget->addTab(m_embeddedNetworkTab, QIcon(":/Icon/process_details.svg"), "网络连接");
    m_tabWidget->addTab(m_soundSourceTab, QIcon(":/Icon/sound_source.svg"), "声音来源");
    m_tabWidget->addTab(m_embeddedWindowTab, QIcon(":/Icon/process_tree.svg"), "窗口列表");
    m_tabWidget->addTab(m_tokenTab, QIcon(":/Icon/process_critical.svg"), "令牌");
    m_tabWidget->addTab(m_tokenSwitchTab, QIcon(":/Icon/process_start.svg"), "令牌开关");
    m_tabWidget->addTab(m_kernelObjectTab, QIcon(":/Icon/process_critical.svg"), "Process Detail Evidence");
    m_tabWidget->addTab(m_hotkeyTab, QIcon(":/Icon/process_hotkey.svg"), "进程热键");
    m_tabWidget->addTab(m_keyboardTab, QIcon(":/Icon/process_hotkey.svg"), "键盘");
    m_tabWidget->addTab(m_pluginTab, QIcon(":/Icon/process_start.svg"), "插件");
    m_tabWidget->addTab(m_pebTab, QIcon(":/Icon/process_tree.svg"), "PEB");
    m_tabWidget->addTab(m_kernelCallbackTab, QIcon(":/Icon/process_hotkey.svg"), "内核回调表");
    // addTab 在首个页面加入时会重新显示 QTabBar，因此必须在页面齐备后再次隐藏。
    m_tabWidget->tabBar()->hide();

    for (int tabIndex = 0; tabIndex < m_tabWidget->count(); ++tabIndex)
    {
        auto* navigationButton = new QToolButton(m_tabNavigation);
        // 左侧导航保留互斥选中，统一普通/checked/disabled 纯色状态。
        ks::ui::ApplyDetailNavigationButtonTheme(navigationButton);
        navigationButton->setCheckable(true);
        navigationButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        navigationButton->setIcon(m_tabWidget->tabIcon(tabIndex));
        navigationButton->setIconSize(QSize(18, 18));
        navigationButton->setText(m_tabWidget->tabText(tabIndex));
        navigationButton->setToolTip(m_tabWidget->tabText(tabIndex));
        navigationButton->setMinimumHeight(38);
        navigationButton->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
        m_tabNavigationButtonGroup->addButton(navigationButton, tabIndex);
        tabNavigationLayout->addWidget(navigationButton);
    }
    tabNavigationLayout->addStretch(1);
    // 导航按类型排序；保留 QTabWidget 的原索引、惰性初始化和既有跳转逻辑。
    using NavKind = ks::ui::DetailNavigationKind;
    ks::ui::SetDetailTabGroups(m_tabWidget, {
        {NavKind::General, {0}}, {NavKind::Performance, {1, 2}},
        {NavKind::Resources, {3, 5, 6, 7, 8, 9, 10}}, {NavKind::Security, {11, 12}},
        {NavKind::Internals, {17, 13, 18}}, {NavKind::Interaction, {4, 14, 15}},
        {NavKind::Extensions, {16}}});
    ks::ui::ArrangeDetailNavigationGroups(m_tabNavigation, m_tabWidget, m_tabNavigationButtonGroup);

    m_tabWidget->setCurrentWidget(m_detailTab);
    if (QAbstractButton* currentNavigationButton =
            m_tabNavigationButtonGroup->button(m_tabWidget->currentIndex()))
    {
        currentNavigationButton->setChecked(true);
    }

    // 所有控件创建完毕后统一套用主题样式。
    applyThemeStyle();

    updateWindowTitle();
}

void ProcessDetailWindow::ensureTabContentInitialized(QWidget* const tab)
{
    if (tab == nullptr || m_initializedTabs.contains(tab))
    {
        if (tab != nullptr && tab->isVisible())
        {
            ks::ui::PrepareWidgetThemeBindingsForShow(tab);
        }
        return;
    }
    // 首帧完成守卫只覆盖真正构造；已建页仍通过共享 dirty 快速入口准备。
    const ks::ui::ScopedWidgetThemePreparation prepareMountedTab(tab);

    // 先标记，防止初始化中发生 tab 事件时递归重复创建控件树。
    m_initializedTabs.insert(tab);
    if (tab == m_threadTab)
    {
        initializeThreadTab();
    }
    else if (tab == m_performanceTab)
    {
        initializePerformanceTab();
    }
    else if (tab == m_cpuCoreTab)
    {
        initializeCpuCoreTab();
    }
    else if (tab == m_actionTab)
    {
        initializeActionTab();
    }
    else if (tab == m_moduleTab)
    {
        initializeModuleTab();
    }
    else if (tab == m_embeddedHandleTab)
    {
        initializeEmbeddedHandleTab();
    }
    else if (tab == m_embeddedMemoryTab)
    {
        initializeEmbeddedMemoryTab();
    }
    else if (tab == m_embeddedNetworkTab)
    {
        initializeEmbeddedNetworkTab();
    }
    else if (tab == m_soundSourceTab)
    {
        initializeSoundSourceTab();
    }
    else if (tab == m_embeddedWindowTab)
    {
        initializeEmbeddedWindowTab();
    }
    else if (tab == m_tokenTab)
    {
        initializeTokenTab();
    }
    else if (tab == m_tokenSwitchTab)
    {
        initializeTokenSwitchTab();
    }
    else if (tab == m_kernelObjectTab)
    {
        initializeKernelObjectTab();
        refreshKernelObjectTabTexts();
    }
    else if (tab == m_hotkeyTab)
    {
        initializeHotkeyTab();
    }
    else if (tab == m_keyboardTab)
    {
        initializeKeyboardTab();
    }
    else if (tab == m_pluginTab)
    {
        initializePluginTab();
    }
    else if (tab == m_pebTab)
    {
        initializePebTab();
    }
    else if (tab == m_kernelCallbackTab)
    {
        initializeKernelCallbackTab();
    }

    // 新页面创建后补接其信号与统一主题，已存在控件不会重复连接。
    initializeConnections();
    applyThemeStyle();
}

void ProcessDetailWindow::initializePluginTab()
{
    // 插件页只提供“进程上下文 -> 独立插件进程”这一条链路：
    // - 只读取 plugin.json 的宿主清单字段；
    // - 不把 Python、DLL 或模型载入详情窗口；
    // - 每次展开菜单时由 Ksword 重新发现兼容插件，避免缓存过期。
    auto* layout = new QVBoxLayout(m_pluginTab);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(10);

    auto* titleLabel = new QLabel(QStringLiteral("进程插件"), m_pluginTab);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px; font-weight:700; color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    layout->addWidget(titleLabel);

    auto* descriptionLabel = new QLabel(
        QStringLiteral("选择适用于当前进程的插件进行分析。"),
        m_pluginTab);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    layout->addWidget(descriptionLabel);

    auto* actionLayout = new QHBoxLayout();
    m_pluginTargetMenuButton = new QToolButton(m_pluginTab);
    m_pluginTargetMenuButton->setText(QStringLiteral("插件"));
    m_pluginTargetMenuButton->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    m_pluginTargetMenuButton->setPopupMode(QToolButton::InstantPopup);
    m_pluginTargetMenuButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_pluginTargetMenuButton->setStyleSheet(buildBlueButtonStyle());
    m_pluginTargetMenu = new QMenu(m_pluginTargetMenuButton);
    m_pluginTargetMenuButton->setMenu(m_pluginTargetMenu);
    actionLayout->addWidget(m_pluginTargetMenuButton);

    auto* managerButton = new QPushButton(QStringLiteral("插件管理"), m_pluginTab);
    managerButton->setStyleSheet(buildBlueButtonStyle());
    actionLayout->addWidget(managerButton);
    actionLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(actionLayout);
    layout->addLayout(actionLayout);
    layout->addStretch(1);

    connect(m_pluginTargetMenu, &QMenu::aboutToShow, this, [this]() {
        ks::plugin_host::InvocationContext context;
        context.targetKind = ks::plugin_host::TargetKind::Process;
        context.processId = m_baseRecord.pid;
        context.processName = QString::fromStdString(m_baseRecord.processName);
        // 详情窗口保留原记录身份；进程退出后同一 PID 的新进程不能继承这个菜单。
        context.processCreateTime100ns = m_baseRecord.creationTime100ns;
        context.filePath = QString::fromStdString(
            m_baseRecord.imagePath.empty() ? m_baseRecord.r0ImagePath : m_baseRecord.imagePath);
        ks::plugin_host::populateTargetMenu(m_pluginTargetMenu, this, context);
    });
    connect(managerButton, &QPushButton::clicked, this, [this]() {
        ks::plugin_host::showPluginManager(this);
    });
}

void ProcessDetailWindow::showActionTab()
{
    // 进程列表右键直达入口：
    // - 输入：无，目标进程来自当前详情窗口绑定的 m_baseRecord；
    // - 处理：切到“操作”页，并把焦点放到 DLL 路径输入框，便于直接选择注入文件；
    // - 返回：无。若控件尚未初始化，则只记录日志并保持当前页。
    if (m_tabWidget != nullptr && m_actionTab != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_actionTab);
    }

    if (m_dllPathLineEdit != nullptr)
    {
        m_dllPathLineEdit->setFocus(Qt::OtherFocusReason);
    }

    kLogEvent actionTabEntryEvent;
    info << actionTabEntryEvent
        << "[ProcessDetailWindow] showActionTab: pid="
        << m_baseRecord.pid
        << eol;
}

void ProcessDetailWindow::requestInitialRefreshForCurrentTab()
{
    // 懒加载策略：
    // - 详情页只显示构造时已有的轻量字段；
    // - 线程/模块/令牌/PEB/Section 等重型查询等用户切到对应页后再启动；
    // - 每页自动首刷只执行一次，用户点击刷新按钮仍可手动刷新。
    if (m_tabWidget == nullptr)
    {
        return;
    }

    QWidget* const currentTab = m_tabWidget->currentWidget();
    if (currentTab == nullptr)
    {
        return;
    }
    const QPointer<ProcessDetailWindow> lifetime(this); // 首帧主题回调可以关闭详情根。
    const QPointer<QTabWidget> requestedTabs(m_tabWidget); // 防止回调替换或销毁原导航宿主。
    const QPointer<QWidget> requestedTab(currentTab); // 当前页身份在准备后仍须一致。
    ensureTabContentInitialized(currentTab);
    if (lifetime == nullptr || requestedTabs == nullptr || requestedTab == nullptr
        || requestedTabs.data() != m_tabWidget || requestedTabs->currentWidget() != requestedTab.data())
    {
        return;
    }

    if (currentTab == m_threadTab)
    {
        if (!m_threadInspectInitialRefreshStarted)
        {
            requestAsyncThreadInspectRefresh();
        }
        return;
    }

    if (currentTab == m_moduleTab)
    {
        if (!m_moduleInitialRefreshStarted)
        {
            requestAsyncModuleRefresh(true);
        }
        return;
    }

    if (currentTab == m_actionTab)
    {
        if (!m_actionPrivilegeInitialRefreshStarted)
        {
            requestAsyncActionPrivilegeRefresh();
        }
        return;
    }

    if (currentTab == m_tokenTab)
    {
        if (!m_tokenInitialRefreshStarted)
        {
            requestAsyncTokenRefresh();
        }
        return;
    }

    if (currentTab == m_tokenSwitchTab)
    {
        if (!m_tokenSwitchInitialRefreshStarted)
        {
            refreshTokenSwitchStates();
        }
        return;
    }

    if (currentTab == m_kernelObjectTab)
    {
        if (!m_sectionInfoInitialRefreshStarted)
        {
            requestAsyncSectionRefresh();
        }
        return;
    }

    if (currentTab == m_hotkeyTab)
    {
        if (!m_hotkeyInitialRefreshStarted)
        {
            requestAsyncHotkeyRefresh(false);
        }
        return;
    }

    if (currentTab == m_keyboardTab)
    {
        if (!m_keyboardInitialRefreshStarted)
        {
            requestAsyncKeyboardRefresh(false);
        }
        return;
    }

    if (currentTab == m_pebTab && !m_pebInitialRefreshStarted)
    {
        requestAsyncPebRefresh();
        return;
    }

    if (currentTab == m_embeddedHandleTab)
    {
        ensureEmbeddedHandleView();
        return;
    }

    if (currentTab == m_embeddedMemoryTab)
    {
        ensureEmbeddedMemoryView();
        return;
    }

    if (currentTab == m_embeddedNetworkTab)
    {
        ensureEmbeddedNetworkView();
        return;
    }

    if (currentTab == m_embeddedWindowTab)
    {
        ensureEmbeddedWindowView();
        return;
    }

    if (currentTab == m_kernelCallbackTab && !m_kernelCallbackInitialRefreshStarted)
    {
        requestAsyncKernelCallbackRefresh();
    }
}

void ProcessDetailWindow::initializeEmbeddedHandleTab()
{
    m_embeddedHandleTab->installEventFilter(this);
    // 只创建轻量容器；HandleDock 自身包含多张表和异步枚举，首次切页时再构造。
    m_embeddedHandleLayout = new QVBoxLayout(m_embeddedHandleTab);
    m_embeddedHandleLayout->setContentsMargins(0, 0, 0, 0);
    m_embeddedHandleLayout->setSpacing(0);

    m_embeddedHandlePlaceholder = new QLabel(
        QStringLiteral("句柄审计视图将在首次进入本页时加载。"),
        m_embeddedHandleTab);
    m_embeddedHandlePlaceholder->setAlignment(Qt::AlignCenter);
    m_embeddedHandlePlaceholder->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_embeddedHandleLayout->addWidget(m_embeddedHandlePlaceholder, 1);
}

void ProcessDetailWindow::ensureEmbeddedHandleView()
{
    if (m_embeddedHandleLayout == nullptr || !isCurrentEmbeddedPage(m_embeddedHandleTab, m_tabWidget)) return;
    if (m_embeddedHandleDock != nullptr && !m_embeddedHandleTab->property(kEmbeddedViewContextPendingProperty).toBool()) return;
    if (!markEmbeddedViewBuildPending(m_embeddedHandleTab)) return;

    const QPointer<QWidget> page(m_embeddedHandleTab);
    const std::uint32_t targetProcessId = m_baseRecord.pid;
    const std::uint64_t creationTime = m_baseRecord.creationTime100ns;
    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this, page, targetProcessId, creationTime]
    {
        if (!page || page != m_embeddedHandleTab || !isCurrentEmbeddedPage(page, m_tabWidget)
            || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
        {
            clearEmbeddedViewBuildPending(page);
            return;
        }
        const ks::ui::ScopedWidgetThemePreparation prepareMountedTab(page);
        if (m_embeddedHandleDock == nullptr)
        {
            m_embeddedHandleDock = new HandleDock(page);
            m_embeddedHandleDock->hide();
            attachEmbeddedDockToTabLayout(m_embeddedHandleLayout, m_embeddedHandlePlaceholder, m_embeddedHandleDock);
            page->setProperty(kEmbeddedViewContextPendingProperty, true);
            m_embeddedHandleDock->show();
        }
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, page, targetProcessId, creationTime]
        {
            if (!page || page != m_embeddedHandleTab || !isCurrentEmbeddedPage(page, m_tabWidget)
                || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
            {
                // A mounted page keeps its pending context for the next real Show.
                clearEmbeddedViewBuildPending(page);
                return;
            }
            if (m_embeddedHandleDock != nullptr)
            {
                m_embeddedHandleDock->focusProcessId(targetProcessId, false);
                page->setProperty(kEmbeddedViewContextPendingProperty, false);
            }
            clearEmbeddedViewBuildPending(page);
        });
    });
}

void ProcessDetailWindow::initializeEmbeddedMemoryTab()
{
    m_embeddedMemoryTab->installEventFilter(this);
    m_embeddedMemoryLayout = new QVBoxLayout(m_embeddedMemoryTab);
    m_embeddedMemoryLayout->setContentsMargins(0, 0, 0, 0);
    m_embeddedMemoryLayout->setSpacing(0);
    m_embeddedMemoryPlaceholder = new QLabel(
        QStringLiteral("内存管理视图将在首次进入本页时加载。"),
        m_embeddedMemoryTab);
    m_embeddedMemoryPlaceholder->setAlignment(Qt::AlignCenter);
    m_embeddedMemoryPlaceholder->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_embeddedMemoryLayout->addWidget(m_embeddedMemoryPlaceholder, 1);
}

void ProcessDetailWindow::ensureEmbeddedMemoryView()
{
    if (m_embeddedMemoryLayout == nullptr || !isCurrentEmbeddedPage(m_embeddedMemoryTab, m_tabWidget)) return;
    if (m_embeddedMemoryDock != nullptr && !m_embeddedMemoryTab->property(kEmbeddedViewContextPendingProperty).toBool())
    {
        applyPendingModuleMemoryAction();
        return;
    }
    if (!markEmbeddedViewBuildPending(m_embeddedMemoryTab)) return;

    const QPointer<QWidget> page(m_embeddedMemoryTab);
    const std::uint32_t targetProcessId = m_baseRecord.pid;
    const std::uint64_t creationTime = m_baseRecord.creationTime100ns;
    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this, page, targetProcessId, creationTime]
    {
        if (!page || page != m_embeddedMemoryTab || !isCurrentEmbeddedPage(page, m_tabWidget)
            || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
        {
            clearEmbeddedViewBuildPending(page);
            return;
        }
        const ks::ui::ScopedWidgetThemePreparation prepareMountedTab(page);
        if (m_embeddedMemoryDock == nullptr)
        {
            m_embeddedMemoryDock = new MemoryDock(page, MemoryDock::PageScope::ProcessDetail);
            m_embeddedMemoryDock->hide();
            attachEmbeddedDockToTabLayout(m_embeddedMemoryLayout, m_embeddedMemoryPlaceholder, m_embeddedMemoryDock);
            m_embeddedMemoryDock->setProcessDetailMemoryScope();
            page->setProperty(kEmbeddedViewContextPendingProperty, true);
            m_embeddedMemoryDock->show();
        }
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, page, targetProcessId, creationTime]
        {
            if (!page || page != m_embeddedMemoryTab || !isCurrentEmbeddedPage(page, m_tabWidget)
                || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
            {
                // A mounted page keeps its pending context for the next real Show.
                clearEmbeddedViewBuildPending(page);
                return;
            }
            if (m_embeddedMemoryDock != nullptr)
            {
                // 模块导航自行核验实例并附加，普通首显仍沿用原来的区域页落点。
                if (m_pendingModuleMemoryRequest)
                {
                    applyPendingModuleMemoryAction();
                }
                else
                {
                    m_embeddedMemoryDock->focusProcessForOperations(targetProcessId, false);
                }
                if (!page)
                {
                    return;
                }
                page->setProperty(kEmbeddedViewContextPendingProperty, false);
            }
            clearEmbeddedViewBuildPending(page);
        });
    });
}

void ProcessDetailWindow::initializeEmbeddedNetworkTab()
{
    m_embeddedNetworkTab->installEventFilter(this);
    m_embeddedNetworkLayout = new QVBoxLayout(m_embeddedNetworkTab);
    m_embeddedNetworkLayout->setContentsMargins(0, 0, 0, 0);
    m_embeddedNetworkLayout->setSpacing(0);
    m_embeddedNetworkPlaceholder = new QLabel(
        QStringLiteral("网络连接视图将在首次进入本页时加载。"),
        m_embeddedNetworkTab);
    m_embeddedNetworkPlaceholder->setAlignment(Qt::AlignCenter);
    m_embeddedNetworkPlaceholder->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_embeddedNetworkLayout->addWidget(m_embeddedNetworkPlaceholder, 1);
}

void ProcessDetailWindow::ensureEmbeddedNetworkView()
{
    if (m_embeddedNetworkLayout == nullptr || !isCurrentEmbeddedPage(m_embeddedNetworkTab, m_tabWidget)) return;
    if (m_embeddedNetworkDock != nullptr && !m_embeddedNetworkTab->property(kEmbeddedViewContextPendingProperty).toBool()) return;
    if (!markEmbeddedViewBuildPending(m_embeddedNetworkTab)) return;

    const QPointer<QWidget> page(m_embeddedNetworkTab);
    const std::uint32_t targetProcessId = m_baseRecord.pid;
    const std::uint64_t creationTime = m_baseRecord.creationTime100ns;
    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this, page, targetProcessId, creationTime]
    {
        if (!page || page != m_embeddedNetworkTab || !isCurrentEmbeddedPage(page, m_tabWidget)
            || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
        {
            clearEmbeddedViewBuildPending(page);
            return;
        }
        const ks::ui::ScopedWidgetThemePreparation prepareMountedTab(page);
        if (m_embeddedNetworkDock == nullptr)
        {
            m_embeddedNetworkDock = new NetworkDock(page, NetworkDock::ConstructScope::ProcessConnections);
            m_embeddedNetworkDock->hide();
            attachEmbeddedDockToTabLayout(m_embeddedNetworkLayout, m_embeddedNetworkPlaceholder, m_embeddedNetworkDock);
        m_embeddedNetworkDock->setProcessDetailConnectionScope();
            page->setProperty(kEmbeddedViewContextPendingProperty, true);
            m_embeddedNetworkDock->show();
        }
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, page, targetProcessId, creationTime]
        {
            if (!page || page != m_embeddedNetworkTab || !isCurrentEmbeddedPage(page, m_tabWidget)
                || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
            {
                // A mounted page keeps its pending context for the next real Show.
                clearEmbeddedViewBuildPending(page);
                return;
            }
            if (m_embeddedNetworkDock != nullptr)
            {
                m_embeddedNetworkDock->focusConnectionsByPids(QVector<quint32>{ targetProcessId });
                page->setProperty(kEmbeddedViewContextPendingProperty, false);
            }
            clearEmbeddedViewBuildPending(page);
        });
    });
}

void ProcessDetailWindow::initializeSoundSourceTab()
{
    // 进程详情只传入当前 PID；页面内部仍使用与杂项页一致的后台采样和 R0 核验。
    auto* soundSourceLayout = new QVBoxLayout(m_soundSourceTab);
    soundSourceLayout->setContentsMargins(0, 0, 0, 0);
    soundSourceLayout->setSpacing(0);

    auto* soundSourcePage = new ks::misc::SoundSourcePage(
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns,
        m_soundSourceTab);
    soundSourceLayout->addWidget(soundSourcePage, 1);
}

void ProcessDetailWindow::initializeEmbeddedWindowTab()
{
    m_embeddedWindowTab->installEventFilter(this);
    m_embeddedWindowLayout = new QVBoxLayout(m_embeddedWindowTab);
    m_embeddedWindowLayout->setContentsMargins(0, 0, 0, 0);
    m_embeddedWindowLayout->setSpacing(0);
    m_embeddedWindowPlaceholder = new QLabel(
        QStringLiteral("窗口列表视图将在首次进入本页时加载。"),
        m_embeddedWindowTab);
    m_embeddedWindowPlaceholder->setAlignment(Qt::AlignCenter);
    m_embeddedWindowPlaceholder->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_embeddedWindowLayout->addWidget(m_embeddedWindowPlaceholder, 1);
}

void ProcessDetailWindow::ensureEmbeddedWindowView()
{
    if (m_embeddedWindowLayout == nullptr || !isCurrentEmbeddedPage(m_embeddedWindowTab, m_tabWidget)) return;
    if (m_embeddedWindowDock != nullptr && !m_embeddedWindowTab->property(kEmbeddedViewContextPendingProperty).toBool()) return;
    if (!markEmbeddedViewBuildPending(m_embeddedWindowTab)) return;

    const QPointer<QWidget> page(m_embeddedWindowTab);
    const std::uint32_t targetProcessId = m_baseRecord.pid;
    const std::uint64_t creationTime = m_baseRecord.creationTime100ns;
    QTimer::singleShot(kEmbeddedViewBuildFirstStageDelayMs, this, [this, page, targetProcessId, creationTime]
    {
        if (!page || page != m_embeddedWindowTab || !isCurrentEmbeddedPage(page, m_tabWidget)
            || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
        {
            clearEmbeddedViewBuildPending(page);
            return;
        }
        const ks::ui::ScopedWidgetThemePreparation prepareMountedTab(page);
        if (m_embeddedWindowDock == nullptr)
        {
            m_embeddedWindowDock = new OtherDock(page, OtherDock::PageScope::WindowListOnly, QVector<quint32>{targetProcessId});
            m_embeddedWindowDock->hide();
            attachEmbeddedDockToTabLayout(m_embeddedWindowLayout, m_embeddedWindowPlaceholder, m_embeddedWindowDock);
        m_embeddedWindowDock->setWindowListOnlyScope();
            page->setProperty(kEmbeddedViewContextPendingProperty, true);
            m_embeddedWindowDock->show();
        }
        QTimer::singleShot(kEmbeddedViewBuildNextStageDelayMs, this, [this, page, targetProcessId, creationTime]
        {
            if (!page || page != m_embeddedWindowTab || !isCurrentEmbeddedPage(page, m_tabWidget)
                || targetProcessId != m_baseRecord.pid || creationTime != m_baseRecord.creationTime100ns)
            {
                // A mounted page keeps its pending context for the next real Show.
                clearEmbeddedViewBuildPending(page);
                return;
            }
            if (m_embeddedWindowDock != nullptr)
            {
                m_embeddedWindowDock->focusProcessIds(QVector<quint32>{ targetProcessId });
                page->setProperty(kEmbeddedViewContextPendingProperty, false);
            }
            clearEmbeddedViewBuildPending(page);
        });
    });
}

void ProcessDetailWindow::requestAsyncStaticDetailRefresh(const bool includeSignatureCheck)
{
    // 静态详情补齐防重入：
    // - 周期刷新可能频繁调用 updateBaseRecord；
    // - 同一个窗口只允许一个后台静态详情任务，避免签名校验堆积。
    const std::uint32_t currentPid = m_baseRecord.pid;
    const std::uint64_t currentCreationTime = m_baseRecord.creationTime100ns;
    if (currentPid == 0 || m_staticDetailRefreshing || m_staticDetailRefreshAttempted)
    {
        return;
    }

    const bool needStaticQuery =
        m_baseRecord.imagePath.empty() ||
        m_baseRecord.commandLine.empty() ||
        m_baseRecord.userName.empty() ||
        m_baseRecord.startTimeText.empty() ||
        m_baseRecord.architectureText.empty() ||
        m_baseRecord.priorityText.empty() ||
        m_baseRecord.signatureState.empty() ||
        m_baseRecord.signatureState == "Pending";
    if (!needStaticQuery)
    {
        return;
    }

    m_staticDetailRefreshing = true;
    m_staticDetailRefreshAttempted = true;
    const std::uint64_t ticketValue = ++m_staticDetailRefreshTicket;
    const std::uint32_t pidValue = currentPid;
    const std::uint64_t creationTimeValue = currentCreationTime;
    const std::string identityKeyValue = ks::process::BuildProcessIdentityKey(
        pidValue,
        creationTimeValue);
    QPointer<ProcessDetailWindow> guardThis(this);

    kLogEvent requestStaticDetailEvent;
    info << requestStaticDetailEvent
        << "[ProcessDetailWindow] requestAsyncStaticDetailRefresh: 后台补齐静态详情, pid="
        << pidValue
        << ", includeSignature="
        << (includeSignatureCheck ? "true" : "false")
        << eol;

    QRunnable* refreshTask = QRunnable::create(
        [guardThis, ticketValue, pidValue, creationTimeValue, identityKeyValue, includeSignatureCheck]()
        {
            StaticDetailRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();
            refreshResult.processRecord.pid = pidValue;
            refreshResult.processRecord.creationTime100ns = creationTimeValue;
            refreshResult.processRecord.processName = ks::process::GetProcessNameByPID(pidValue);

            // 动态计数器只补轻量数值；签名校验由 FillProcessStaticDetails 的参数控制。
            ks::process::RefreshProcessDynamicCounters(refreshResult.processRecord);
            if (creationTimeValue != 0 &&
                refreshResult.processRecord.creationTime100ns != 0 &&
                refreshResult.processRecord.creationTime100ns != creationTimeValue)
            {
                // PID 已经复用：丢弃本轮结果，避免把新进程信息写回旧窗口。
                QMetaObject::invokeMethod(
            qApp,
                    [guardThis, ticketValue, identityKeyValue]()
                    {
                        if (guardThis == nullptr || guardThis->m_staticDetailRefreshTicket != ticketValue)
                        {
                            return;
                        }
                        const std::string currentIdentityKey = ks::process::BuildProcessIdentityKey(
                            guardThis->m_baseRecord.pid,
                            guardThis->m_baseRecord.creationTime100ns);
                        if (currentIdentityKey == identityKeyValue)
                        {
                            guardThis->m_staticDetailRefreshing = false;
                            guardThis->m_staticDetailRefreshAttempted = true;
                        }
                    },
                    Qt::QueuedConnection);
                return;
            }
            refreshResult.queryOk = ks::process::FillProcessStaticDetails(
                refreshResult.processRecord,
                includeSignatureCheck);
            if (creationTimeValue == 0 && refreshResult.processRecord.creationTime100ns != 0)
            {
                // 轻量开窗记录没有创建时间时，保持 identity 为 PID#0。
                // 这样 ProcessDock 的窗口缓存键不会在后台补齐后漂移。
                refreshResult.processRecord.creationTime100ns = creationTimeValue;
            }
            if (!refreshResult.queryOk)
            {
                refreshResult.diagnosticText = QStringLiteral("静态详情读取失败或权限不足");
            }
            if (refreshResult.processRecord.processName.empty())
            {
                refreshResult.processRecord.processName = "PID_" + std::to_string(pidValue);
            }

            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
            qApp,
                [guardThis, ticketValue, identityKeyValue, includeSignatureCheck, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->m_staticDetailRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    const std::string currentIdentityKey = ks::process::BuildProcessIdentityKey(
                        guardThis->m_baseRecord.pid,
                        guardThis->m_baseRecord.creationTime100ns);
                    if (currentIdentityKey != identityKeyValue)
                    {
                        // 目标进程 identity 已变化时丢弃旧结果，并允许新 identity 重新排队补齐。
                        guardThis->m_staticDetailRefreshing = false;
                        guardThis->m_staticDetailRefreshAttempted = false;
                        guardThis->requestAsyncStaticDetailRefresh(includeSignatureCheck);
                        return;
                    }
                    guardThis->applyStaticDetailRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyStaticDetailRefreshResult(const StaticDetailRefreshResult& refreshResult)
{
    // 后台静态详情回填：
    // - 只合并有效字段，避免权限不足结果清空用户当前看到的缓存字段；
    // - 保留 R0 扩展字段，因为它们可能来自进程列表或驱动枚举。
    m_staticDetailRefreshing = false;
    if (refreshResult.processRecord.pid != m_baseRecord.pid)
    {
        return;
    }

    const ks::process::ProcessRecord& queriedRecord = refreshResult.processRecord;
    if (!queriedRecord.processName.empty()) m_baseRecord.processName = queriedRecord.processName;
    if (!queriedRecord.imagePath.empty()) m_baseRecord.imagePath = queriedRecord.imagePath;
    if (!queriedRecord.commandLine.empty()) m_baseRecord.commandLine = queriedRecord.commandLine;
    if (!queriedRecord.userName.empty()) m_baseRecord.userName = queriedRecord.userName;
    if (!queriedRecord.startTimeText.empty()) m_baseRecord.startTimeText = queriedRecord.startTimeText;
    if (!queriedRecord.architectureText.empty()) m_baseRecord.architectureText = queriedRecord.architectureText;
    if (!queriedRecord.priorityText.empty()) m_baseRecord.priorityText = queriedRecord.priorityText;
    if (!queriedRecord.signatureState.empty()) m_baseRecord.signatureState = queriedRecord.signatureState;
    if (!queriedRecord.signaturePublisher.empty()) m_baseRecord.signaturePublisher = queriedRecord.signaturePublisher;
    m_baseRecord.signatureTrusted = queriedRecord.signatureTrusted;
    m_baseRecord.isAdmin = queriedRecord.isAdmin;
    if (queriedRecord.parentPid != 0) m_baseRecord.parentPid = queriedRecord.parentPid;
    if (queriedRecord.sessionId != 0) m_baseRecord.sessionId = queriedRecord.sessionId;
    if (queriedRecord.threadCount != 0) m_baseRecord.threadCount = queriedRecord.threadCount;
    if (queriedRecord.handleCount != 0) m_baseRecord.handleCount = queriedRecord.handleCount;
    if (queriedRecord.creationTime100ns != 0) m_baseRecord.creationTime100ns = queriedRecord.creationTime100ns;
    if (queriedRecord.staticDetailsReady) m_baseRecord.staticDetailsReady = true;

    m_identityKey = ks::process::BuildProcessIdentityKey(
        m_baseRecord.pid,
        m_baseRecord.creationTime100ns);
    refreshDetailTabTexts();

    kLogEvent applyStaticDetailEvent;
    (refreshResult.queryOk ? info : warn) << applyStaticDetailEvent
        << "[ProcessDetailWindow] applyStaticDetailRefreshResult: 完成, pid="
        << m_baseRecord.pid
        << ", queryOk="
        << (refreshResult.queryOk ? "true" : "false")
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::requestAsyncDetailOverviewRefresh()
{
    const std::uint32_t pidValue = m_baseRecord.pid;
    if (pidValue == 0U || m_detailOverviewRefreshing)
    {
        return;
    }

    m_detailOverviewRefreshing = true;
    const std::uint64_t ticketValue = ++m_detailOverviewRefreshTicket;
    const std::string identityKeyValue = m_identityKey;
    if (m_refreshDetailOverviewButton != nullptr)
    {
        m_refreshDetailOverviewButton->setEnabled(false);
    }
    if (m_detailOverviewStatusLabel != nullptr)
    {
        m_detailOverviewStatusLabel->setText(ks::i18n::text(
            QStringLiteral("process.detail.status.loading"),
            QStringLiteral("● 正在读取运行时详细数据...")));
        m_detailOverviewStatusLabel->setStyleSheet(
            buildStateLabelStyle(KswordTheme::PrimaryBlueColor, 700));
    }

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create([guardThis, pidValue, identityKeyValue, ticketValue]() {
        DetailOverviewRefreshResult refreshResult{};
        refreshResult.identityKey = identityKeyValue;
        const auto beginTime = std::chrono::steady_clock::now();
        const auto putValue = [&refreshResult](const QString& key, const QString& value) {
            refreshResult.values.insert(key, value.trimmed().isEmpty() ? detailUnavailableText() : value);
        };

        putValue(QStringLiteral("gui_top_level_windows"), QString::number(detailTopLevelWindowCount(pidValue)));
        const QString desktopText = detailThreadDesktopText(pidValue);
        putValue(QStringLiteral("thread_desktop"), desktopText);

        DWORD sessionId = 0;
        if (::ProcessIdToSessionId(pidValue, &sessionId) != FALSE)
        {
            putValue(QStringLiteral("window_station"),
                desktopText == detailUnavailableText()
                    ? QStringLiteral("Session %1 (not available)").arg(sessionId)
                    : QStringLiteral("WinSta0 (inferred, session %1)").arg(sessionId));
        }
        else
        {
            putValue(QStringLiteral("window_station"), detailUnavailableText());
        }

        HANDLE processHandle = ::OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            FALSE,
            pidValue);
        if (processHandle == nullptr)
        {
            processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pidValue);
        }

        if (processHandle == nullptr)
        {
            refreshResult.diagnosticText = QStringLiteral("OpenProcess failed (%1)").arg(::GetLastError());
        }
        else
        {
            PROCESS_MEMORY_COUNTERS_EX memoryCounters{};
            if (::GetProcessMemoryInfo(
                processHandle,
                reinterpret_cast<PPROCESS_MEMORY_COUNTERS>(&memoryCounters),
                sizeof(memoryCounters)) != FALSE)
            {
                putValue(QStringLiteral("peak_working_set"), detailBytesText(memoryCounters.PeakWorkingSetSize));
                putValue(QStringLiteral("page_faults"), QString::number(memoryCounters.PageFaultCount));
                refreshResult.queryOk = true;
            }

            FILETIME creationTime{};
            FILETIME exitTime{};
            FILETIME kernelTime{};
            FILETIME userTime{};
            if (::GetProcessTimes(processHandle, &creationTime, &exitTime, &kernelTime, &userTime) != FALSE)
            {
                ULARGE_INTEGER kernelTimeValue{};
                kernelTimeValue.LowPart = kernelTime.dwLowDateTime;
                kernelTimeValue.HighPart = kernelTime.dwHighDateTime;
                ULARGE_INTEGER userTimeValue{};
                userTimeValue.LowPart = userTime.dwLowDateTime;
                userTimeValue.HighPart = userTime.dwHighDateTime;
                putValue(QStringLiteral("kernel_cpu_time"), detailDurationText(kernelTimeValue.QuadPart));
                putValue(QStringLiteral("user_cpu_time"), detailDurationText(userTimeValue.QuadPart));
                refreshResult.queryOk = true;
            }

            IO_COUNTERS ioCounters{};
            if (::GetProcessIoCounters(processHandle, &ioCounters) != FALSE)
            {
                putValue(QStringLiteral("io_read_ops"), QString::number(static_cast<qulonglong>(ioCounters.ReadOperationCount)));
                putValue(QStringLiteral("io_write_ops"), QString::number(static_cast<qulonglong>(ioCounters.WriteOperationCount)));
                putValue(QStringLiteral("io_other_ops"), QString::number(static_cast<qulonglong>(ioCounters.OtherOperationCount)));
                putValue(QStringLiteral("io_read_bytes"), detailBytesText(ioCounters.ReadTransferCount));
                putValue(QStringLiteral("io_write_bytes"), detailBytesText(ioCounters.WriteTransferCount));
                putValue(QStringLiteral("io_other_bytes"), detailBytesText(ioCounters.OtherTransferCount));
                refreshResult.queryOk = true;
            }

            ULONG_PTR processAffinity = 0;
            ULONG_PTR systemAffinity = 0;
            if (::GetProcessAffinityMask(processHandle, &processAffinity, &systemAffinity) != FALSE)
            {
                putValue(QStringLiteral("cpu_affinity"), detailAffinityText(processAffinity));
                refreshResult.queryOk = true;
            }

            putValue(QStringLiteral("gdi_objects"), QString::number(::GetGuiResources(processHandle, GR_GDIOBJECTS)));
            putValue(QStringLiteral("user_objects"), QString::number(::GetGuiResources(processHandle, GR_USEROBJECTS)));

            BOOL inJobObject = FALSE;
            if (::IsProcessInJob(processHandle, nullptr, &inJobObject) != FALSE)
            {
                putValue(QStringLiteral("job_object"), detailBoolText(inJobObject != FALSE));
                refreshResult.queryOk = true;
            }

            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle) != FALSE)
            {
                std::vector<std::uint8_t> tokenBuffer;
                if (detailReadTokenInformation(tokenHandle, TokenIntegrityLevel, tokenBuffer) &&
                    tokenBuffer.size() >= sizeof(TOKEN_MANDATORY_LABEL))
                {
                    const auto* mandatoryLabel = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(tokenBuffer.data());
                    DWORD integrityRid = 0;
                    if (mandatoryLabel->Label.Sid != nullptr &&
                        *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) > 0)
                    {
                        integrityRid = *::GetSidSubAuthority(
                            mandatoryLabel->Label.Sid,
                            *::GetSidSubAuthorityCount(mandatoryLabel->Label.Sid) - 1);
                    }
                    putValue(QStringLiteral("integrity_level"), detailIntegrityText(integrityRid));
                }

                TOKEN_ELEVATION_TYPE elevationType = TokenElevationTypeDefault;
                DWORD returnedBytes = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenElevationType,
                    &elevationType,
                    sizeof(elevationType),
                    &returnedBytes) != FALSE)
                {
                    putValue(QStringLiteral("elevation_type"), detailElevationTypeText(elevationType));
                }

                DWORD appContainerValue = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenIsAppContainer,
                    &appContainerValue,
                    sizeof(appContainerValue),
                    &returnedBytes) != FALSE)
                {
                    putValue(QStringLiteral("app_container"), detailBoolText(appContainerValue != 0U));
                }

                DWORD virtualizationValue = 0;
                if (::GetTokenInformation(
                    tokenHandle,
                    TokenVirtualizationEnabled,
                    &virtualizationValue,
                    sizeof(virtualizationValue),
                    &returnedBytes) != FALSE)
                {
                    putValue(QStringLiteral("token_virtualization"), detailBoolText(virtualizationValue != 0U));
                }
                ::CloseHandle(tokenHandle);
                refreshResult.queryOk = true;
            }

            HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
            const NtQueryInformationProcessFn ntQueryProcess = reinterpret_cast<NtQueryInformationProcessFn>(
                ntdllModule != nullptr ? ::GetProcAddress(ntdllModule, "NtQueryInformationProcess") : nullptr);
            ULONG_PTR debugPort = 0;
            if (detailQueryNtProcessInformation(ntQueryProcess, processHandle, kProcessInfoClassDebugPort, debugPort))
            {
                putValue(
                    QStringLiteral("debug_port"),
                    debugPort == 0U
                        ? QStringLiteral("None")
                        : QStringLiteral("Attached (0x%1)")
                            .arg(static_cast<qulonglong>(debugPort), 0, 16)
                            .toUpper());
            }
            ULONG criticalValue = 0;
            if (detailQueryNtProcessInformation(ntQueryProcess, processHandle, kProcessInfoClassBreakOnTermination, criticalValue))
            {
                putValue(QStringLiteral("critical_process"), detailBoolText(criticalValue != 0U));
            }
            ULONG subsystemType = 0;
            if (detailQueryNtProcessInformation(ntQueryProcess, processHandle, kProcessInfoClassSubsystem, subsystemType))
            {
                putValue(QStringLiteral("subsystem"), detailSubsystemText(subsystemType));
            }

            PROCESS_MITIGATION_DEP_POLICY depPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_dep"),
                    depPolicy.Enable != 0U
                        ? (depPolicy.Permanent != FALSE ? QStringLiteral("Enabled (permanent)") : QStringLiteral("Enabled"))
                        : QStringLiteral("Disabled"));
            }
            PROCESS_MITIGATION_ASLR_POLICY aslrPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (aslrPolicy.EnableBottomUpRandomization != 0U) enabledModes << QStringLiteral("Bottom-up");
                if (aslrPolicy.EnableForceRelocateImages != 0U) enabledModes << QStringLiteral("Force relocate");
                if (aslrPolicy.EnableHighEntropy != 0U) enabledModes << QStringLiteral("High entropy");
                if (aslrPolicy.DisallowStrippedImages != 0U) enabledModes << QStringLiteral("Disallow stripped images");
                putValue(QStringLiteral("mitigation_aslr"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (cfgPolicy.EnableControlFlowGuard != 0U) enabledModes << QStringLiteral("CFG");
                if (cfgPolicy.EnableExportSuppression != 0U) enabledModes << QStringLiteral("Export suppression");
                if (cfgPolicy.StrictMode != 0U) enabledModes << QStringLiteral("Strict mode");
                if (cfgPolicy.EnableXfg != 0U) enabledModes << QStringLiteral("XFG");
                putValue(QStringLiteral("mitigation_cfg"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (dynamicCodePolicy.ProhibitDynamicCode != 0U) enabledModes << QStringLiteral("Prohibit dynamic code");
                if (dynamicCodePolicy.AllowThreadOptOut != 0U) enabledModes << QStringLiteral("Allow thread opt-out");
                if (dynamicCodePolicy.AllowRemoteDowngrade != 0U) enabledModes << QStringLiteral("Allow remote downgrade");
                putValue(QStringLiteral("mitigation_dynamic_code"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPointPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessExtensionPointDisablePolicy, &extensionPointPolicy, sizeof(extensionPointPolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_extension_points"), detailBoolText(extensionPointPolicy.DisableExtensionPoints != 0U));
            }
            PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy)) != FALSE)
            {
                QStringList enabledModes;
                if (imageLoadPolicy.NoRemoteImages != 0U) enabledModes << QStringLiteral("No remote images");
                if (imageLoadPolicy.NoLowMandatoryLabelImages != 0U) enabledModes << QStringLiteral("No low-label images");
                if (imageLoadPolicy.PreferSystem32Images != 0U) enabledModes << QStringLiteral("Prefer System32");
                putValue(QStringLiteral("mitigation_image_load"), enabledModes.isEmpty() ? QStringLiteral("Disabled") : enabledModes.join(QStringLiteral(", ")));
            }
            PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_strict_handles"), detailBoolText(strictHandlePolicy.RaiseExceptionOnInvalidHandleReference != 0U));
            }
            PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY systemCallPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessSystemCallDisablePolicy, &systemCallPolicy, sizeof(systemCallPolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_win32k"), detailBoolText(systemCallPolicy.DisallowWin32kSystemCalls != 0U));
            }
            PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcessPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessChildProcessPolicy, &childProcessPolicy, sizeof(childProcessPolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_child_process"), detailBoolText(childProcessPolicy.NoChildProcessCreation != 0U));
            }
            PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY shadowStackPolicy{};
            if (::GetProcessMitigationPolicy(processHandle, ProcessUserShadowStackPolicy, &shadowStackPolicy, sizeof(shadowStackPolicy)) != FALSE)
            {
                putValue(QStringLiteral("mitigation_shadow_stack"), detailBoolText(shadowStackPolicy.EnableUserShadowStack != 0U));
            }

            ::CloseHandle(processHandle);
        }

        std::uint32_t protectionLevel = 0;
        std::string protectionText;
        if (ks::process::QueryProcessProtectionLevelByPid(
            pidValue,
            &protectionLevel,
            &protectionText,
            nullptr))
        {
            putValue(QStringLiteral("ppl_protection"), QString::fromStdString(protectionText));
            refreshResult.queryOk = true;
        }

        refreshResult.elapsedMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - beginTime).count());
        QMetaObject::invokeMethod(
            qApp,
            [guardThis, refreshResult, ticketValue]() {
                if (guardThis == nullptr || guardThis->m_detailOverviewRefreshTicket != ticketValue)
                {
                    return;
                }
                guardThis->applyDetailOverviewRefreshResult(refreshResult);
            },
            Qt::QueuedConnection);
    });
    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyDetailOverviewRefreshResult(const DetailOverviewRefreshResult& refreshResult)
{
    m_detailOverviewRefreshing = false;
    if (refreshResult.identityKey != m_identityKey)
    {
        return;
    }

    m_detailOverviewResult = refreshResult;
    if (m_refreshDetailOverviewButton != nullptr)
    {
        m_refreshDetailOverviewButton->setEnabled(m_baseRecord.pid != 0U);
    }
    if (m_detailOverviewStatusLabel != nullptr)
    {
        const QString statusText = refreshResult.queryOk
            ? ks::i18n::text(
                QStringLiteral("process.detail.status.completed"),
                QStringLiteral("● 运行时详细数据已刷新 %1 ms")).arg(refreshResult.elapsedMs)
            : ks::i18n::text(
                QStringLiteral("process.detail.status.failed"),
                QStringLiteral("● 运行时详细数据不可用：%1"))
                .arg(refreshResult.diagnosticText.isEmpty() ? detailUnavailableText() : refreshResult.diagnosticText);
        m_detailOverviewStatusLabel->setText(statusText);
        m_detailOverviewStatusLabel->setStyleSheet(buildStateLabelStyle(
            refreshResult.queryOk ? signatureTrustedColor() : signatureUntrustedColor(),
            700));
    }
    refreshDetailTabTexts();
}

void ProcessDetailWindow::initializeDetailTab()
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    const auto configureCopyableLabel = [](QLabel* label) {
        label->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    };
    // 页级容器不再包裹第二层滚动；只有卡片正文或树视图自身滚动。
    QWidget* detailContent = m_detailTab;
    m_detailLayout = new QVBoxLayout(detailContent);
    m_detailLayout->setContentsMargins(16, 12, 16, 12);
    m_detailLayout->setSpacing(10);
    QWidget* summaryHeader = findChild<QWidget*>(QLatin1String("ksword_process_detail_header"));
    auto* summaryLayout = qobject_cast<QVBoxLayout*>(summaryHeader->layout());
    // 顶部：40px 图标 + 进程名与 PID。
    QHBoxLayout* titleLayout = new QHBoxLayout();
    m_processIconLabel = new QLabel(m_detailTab);
    m_processIconLabel->setFixedSize(40, 40);
    m_processTitleLabel = new QLabel(m_detailTab);
    m_processTitleLabel->setStyleSheet(
        QStringLiteral("font-size:18px; font-weight:700; color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    configureCopyableLabel(m_processTitleLabel);
    titleLayout->addWidget(m_processIconLabel, 0, Qt::AlignTop);
    titleLayout->addWidget(m_processTitleLabel, 1);
    titleLayout->addStretch(1);
    summaryLayout->addLayout(titleLayout);

    // 路径行：只读输入框 + 复制 + 打开文件夹 + 现有文件详情窗口入口。
    QHBoxLayout* pathLayout = new QHBoxLayout();
    auto* pathLabel = new QLabel(m_detailTab);
    languageManager.bindText(pathLabel, QStringLiteral("process.detail.label.image_path"), QStringLiteral("程序路径:"));
    configureCopyableLabel(pathLabel);
    pathLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    pathLayout->addWidget(pathLabel);
    m_pathLineEdit = new QLineEdit(m_detailTab);
    m_pathLineEdit->setReadOnly(true);
    ks::ui::StyleStandaloneInput(m_pathLineEdit);
    m_copyPathButton = new QPushButton(QIcon(":/Icon/process_copy_cell.svg"), QString(), m_detailTab);
    m_openPathFolderButton = new QPushButton(QIcon(":/Icon/process_open_folder.svg"), QString(), m_detailTab);
    m_openFileDetailButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_detailTab);
    languageManager.bindText(m_copyPathButton, QStringLiteral("process.detail.action.copy"), QStringLiteral("复制"));
    languageManager.bindText(m_openPathFolderButton, QStringLiteral("process.detail.action.open_folder"), QStringLiteral("打开文件夹"));
    languageManager.bindText(m_openFileDetailButton, QStringLiteral("process.detail.action.open_file_detail"), QStringLiteral("转到文件详细信息"));
    pathLayout->addWidget(m_pathLineEdit, 1);

    m_pathLineEdit->setMinimumWidth(0);
    m_pathLineEdit->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    pathLayout->addWidget(m_copyPathButton);
    pathLayout->addWidget(m_openPathFolderButton);
    pathLayout->addWidget(m_openFileDetailButton);
    // 进程身份与文件动作位于全宽摘要栏，切换资源/安全页时仍然可见。
    summaryLayout->addLayout(pathLayout);

    // 命令行行：只读输入框 + 复制。
    QHBoxLayout* commandLayout = new QHBoxLayout();
    auto* commandLabel = new QLabel(m_detailTab);
    languageManager.bindText(commandLabel, QStringLiteral("process.detail.label.command_line"), QStringLiteral("启动命令行:"));
    configureCopyableLabel(commandLabel);
    commandLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    commandLayout->addWidget(commandLabel);
    m_commandLineEdit = new QLineEdit(m_detailTab);
    m_commandLineEdit->setReadOnly(true);
    m_commandLineEdit->setMinimumWidth(0);
    m_commandLineEdit->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    ks::ui::StyleStandaloneInput(m_commandLineEdit);
    m_copyCommandButton = new QPushButton(QIcon(":/Icon/process_copy_cell.svg"), QString(), m_detailTab);
    languageManager.bindText(m_copyCommandButton, QStringLiteral("process.detail.action.copy"), QStringLiteral("复制"));
    commandLayout->addWidget(m_commandLineEdit, 1);
    commandLayout->addWidget(m_copyCommandButton);
    m_detailLayout->addLayout(commandLayout);

    // 父进程行：20px 图标 + 名称 PID + 转到父进程按钮（存在时显示）。
    QHBoxLayout* parentLayout = new QHBoxLayout();
    auto* parentLabel = new QLabel(m_detailTab);
    languageManager.bindText(parentLabel, QStringLiteral("process.detail.label.parent_process"), QStringLiteral("父进程:"));
    configureCopyableLabel(parentLabel);
    parentLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    m_parentIconLabel = new QLabel(m_detailTab);
    m_parentIconLabel->setFixedSize(20, 20);
    m_parentInfoLabel = new QLabel(m_detailTab);
    m_parentInfoLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    configureCopyableLabel(m_parentInfoLabel);
    m_detailOpenHandleDockButton = new QPushButton(QIcon(":/Icon/process_list.svg"), ks::i18n::sourceText(QStringLiteral("查看句柄")), m_detailTab);
    m_detailOpenHandleDockButton->setToolTip(QStringLiteral("跳转到句柄 Dock，并按当前 PID 过滤"));
    m_gotoParentButton = new QPushButton(QIcon(":/Icon/process_details.svg"), QString(), m_detailTab);
    languageManager.bindText(m_gotoParentButton, QStringLiteral("process.detail.action.goto_parent"), QStringLiteral("转到父进程"));
    m_gotoParentButton->setVisible(false);
    parentLayout->addWidget(parentLabel);
    parentLayout->addWidget(m_parentIconLabel);
    parentLayout->addWidget(m_parentInfoLabel, 1);
    parentLayout->addWidget(m_detailOpenHandleDockButton);
    parentLayout->addWidget(m_gotoParentButton);
    m_detailLayout->addLayout(parentLayout);

    QHBoxLayout* detailActionLayout = new QHBoxLayout();
    m_refreshDetailOverviewButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), m_detailTab);
    m_refreshDetailOverviewButton->setToolTip(ks::i18n::text(
        QStringLiteral("process.detail.action.refresh"), QStringLiteral("刷新运行时详细数据")));
    m_refreshDetailOverviewButton->setFixedWidth(30);
    m_detailOverviewStatusLabel = new QLabel(m_detailTab);
    languageManager.bindText(m_detailOverviewStatusLabel, QStringLiteral("process.detail.status.waiting"), QStringLiteral("● 等待读取运行时详细数据"));
    configureCopyableLabel(m_detailOverviewStatusLabel);
    auto* pageTitle = new QLabel(ks::i18n::sourceText(QStringLiteral("详细信息")), m_detailTab);
    QFont pageTitleFont = pageTitle->font();
    pageTitleFont.setBold(true);
    pageTitle->setFont(pageTitleFont);
    detailActionLayout->addWidget(pageTitle);
    m_detailLayout->addLayout(detailActionLayout);
    m_detailLayout->addWidget(m_detailOverviewStatusLabel);

    for (auto* button : {m_copyPathButton, m_openPathFolderButton, m_openFileDetailButton,
        m_copyCommandButton, m_detailOpenHandleDockButton, m_gotoParentButton, m_refreshDetailOverviewButton})
    {
        ks::ui::ApplyFlatButtonTheme(button, ks::ui::FlatButtonTone::Neutral,
            ks::ui::FlatButtonAppearance::Solid);
        ks::ui::NormalizeToolbarControl(button);
    }
    // 进程概览与其它详情窗口复用同一文档卡片框架，不再维护独立投影布局。
    m_generalFields = new ks::ui::StructuredFieldView(detailContent);
    m_detailLayout->addWidget(ks::ui::CreateDetailFieldProjection(m_generalFields, detailContent), 1);
    detailActionLayout->addWidget(m_refreshDetailOverviewButton);
    // 路径与运行时操作行使用共同几何；父进程图标保留 20px，仅调整按钮。
    ks::ui::NormalizeToolbarRow(pathLayout);
    ks::ui::NormalizeToolbarRow(commandLayout);
    parentLayout->setSpacing(8);
    ks::ui::NormalizeToolbarRow(detailActionLayout);
}


void ProcessDetailWindow::initializePerformanceTab()
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    const auto configureCopyableLabel = [&languageManager](QLabel* label) {
        if (label == nullptr)
        {
            return;
        }
        label->setTextInteractionFlags(Qt::TextSelectableByMouse);
        label->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(label, &QWidget::customContextMenuRequested, label,
            [label, &languageManager](const QPoint& localPosition) {
                QMenu menu(label);
                menu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* const copyAction = menu.addAction(languageManager.text(
                    QStringLiteral("process.detail.action.copy"),
                    QString()));
                if (menu.exec(label->mapToGlobal(localPosition)) == copyAction &&
                    QApplication::clipboard() != nullptr)
                {
                    QApplication::clipboard()->setText(label->text());
                }
            });
    };
    auto* layout = new QVBoxLayout(m_performanceTab);
    layout->setContentsMargins(14, 14, 14, 14);
    layout->setSpacing(8);

    auto* titleLabel = new QLabel(m_performanceTab);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px; font-weight:700; color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    languageManager.bindText(titleLabel, QStringLiteral("process.detail.performance.title"), QString());
    configureCopyableLabel(titleLabel);
    layout->addWidget(titleLabel);

    auto* descriptionLabel = new QLabel(m_performanceTab);
    descriptionLabel->setWordWrap(true);
    descriptionLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    languageManager.bindText(descriptionLabel, QStringLiteral("process.detail.performance.description"), QString());
    configureCopyableLabel(descriptionLabel);
    layout->addWidget(descriptionLabel);

    m_performanceHistoryStatusLabel = new QLabel(m_performanceTab);
    m_performanceHistoryStatusLabel->setWordWrap(true);
    m_performanceHistoryStatusLabel->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    configureCopyableLabel(m_performanceHistoryStatusLabel);
    layout->addWidget(m_performanceHistoryStatusLabel);

    auto* chartScrollArea = new QScrollArea(m_performanceTab);
    chartScrollArea->setWidgetResizable(true);
    chartScrollArea->setFrameShape(QFrame::NoFrame);
    auto* chartContent = new QWidget(chartScrollArea);
    chartContent->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::MinimumExpanding);
    auto* chartLayout = new QVBoxLayout(chartContent);
    chartLayout->setContentsMargins(0, 0, 0, 0);
    chartLayout->setSpacing(10);
    chartLayout->setAlignment(Qt::AlignTop);

    const auto addChart = [&languageManager, chartContent, chartLayout](
        QWidget*& chartTarget,
        const QString& titleKey) {
        auto* group = new QGroupBox(chartContent);
        languageManager.bindText(group, titleKey, QString());
        group->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(group, &QWidget::customContextMenuRequested, group,
            [group, &languageManager](const QPoint& localPosition) {
                QMenu menu(group);
                menu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* const copyAction = menu.addAction(languageManager.text(
                    QStringLiteral("process.detail.action.copy"),
                    QString()));
                if (menu.exec(group->mapToGlobal(localPosition)) == copyAction &&
                    QApplication::clipboard() != nullptr)
                {
                    QApplication::clipboard()->setText(group->title());
                }
            });
        auto* groupLayout = new QVBoxLayout(group);
        groupLayout->setContentsMargins(9, 17, 9, 9);
        chartTarget = new ProcessPerformanceHistoryChartWidget(group);
        groupLayout->addWidget(chartTarget);
        chartLayout->addWidget(group);
    };

    addChart(m_performanceCpuChart, QStringLiteral("process.detail.performance.chart.cpu"));
    addChart(m_performanceCpuCoreChart, QStringLiteral("process.detail.performance.chart.cpu_core"));
    addChart(m_performanceMemoryChart, QStringLiteral("process.detail.performance.chart.memory"));
    addChart(m_performanceDiskChart, QStringLiteral("process.detail.performance.chart.disk"));
    addChart(m_performanceNetworkChart, QStringLiteral("process.detail.performance.chart.network"));
    addChart(m_performanceGpuChart, QStringLiteral("process.detail.performance.chart.gpu"));
    chartLayout->addStretch(1);
    chartScrollArea->setWidget(chartContent);
    chartScrollArea->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    layout->addWidget(chartScrollArea, 1);

    refreshPerformanceHistoryCharts();
}

void ProcessDetailWindow::refreshPerformanceHistoryCharts()
{
    m_performanceChartsDirty = true;
    // 数据入队和1800点裁剪仍在每次样本更新执行；只有不可见的图形转换延后。
    if (m_performanceHistoryStatusLabel == nullptr || !detailChartPageExposed(m_performanceTab))
    {
        return;
    }
    m_performanceChartsDirty = false;

    const auto text = [](const QString& key) {
        return ks::i18n::text(key, QString());
    };
    using Chart = ProcessPerformanceHistoryChartWidget;
    const auto* primaryChart = static_cast<Chart*>(m_performanceCpuChart);
    Chart::HistorySnapshot history = primaryChart != nullptr
        ? primaryChart->historySnapshot() : Chart::HistorySnapshot{};
    if (!Chart::historyMatches(history, m_performanceHistory))
    {
        // 六图共用一份完整不可变快照，不再分解成八向量和六份时间轴。
        history = std::make_shared<const Chart::History>(
            m_performanceHistory.cbegin(), m_performanceHistory.cend());
    }

    const QString timeHeader = text(QStringLiteral("process.detail.performance.header.time"));
    const QString emptyText = text(QStringLiteral("process.detail.performance.chart.empty"));
    const QString copyLatestText = text(QStringLiteral("process.detail.performance.action.copy_current"));
    const QString copyHistoryText = text(QStringLiteral("process.detail.performance.action.copy_history"));
    const auto setChartData = [&history, &emptyText, &timeHeader, &copyLatestText, &copyHistoryText](
        QWidget* chartWidget,
        std::vector<ProcessPerformanceHistoryChartWidget::Series> series,
        const QString& unitText,
        const double fixedMaximum,
        const double axisStep = 0.0) {
        auto* chart = static_cast<ProcessPerformanceHistoryChartWidget*>(chartWidget);
        if (chart == nullptr)
        {
            return;
        }
        chart->setChartData(
            history,
            std::move(series),
            unitText,
            fixedMaximum,
            emptyText,
            timeHeader,
            copyLatestText,
            copyHistoryText,
            axisStep);
    };

    setChartData(
        m_performanceCpuChart,
        { ProcessPerformanceHistoryChartWidget::Series{
            text(QStringLiteral("process.detail.performance.series.cpu")),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu),
            &Chart::Sample::cpuPercent } },
        QStringLiteral("%"),
        100.0);
    setChartData(
        m_performanceCpuCoreChart,
        { ProcessPerformanceHistoryChartWidget::Series{
            text(QStringLiteral("process.detail.performance.series.cpu_core")),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Cpu),
            &Chart::Sample::cpuCorePercent } },
        QStringLiteral("%"),
        0.0,
        100.0);
    setChartData(
        m_performanceMemoryChart,
        { ProcessPerformanceHistoryChartWidget::Series{
            text(QStringLiteral("process.detail.performance.series.memory")),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Memory),
            &Chart::Sample::memoryMB } },
        QStringLiteral("MB"),
        0.0);
    setChartData(
        m_performanceDiskChart,
        { ProcessPerformanceHistoryChartWidget::Series{
            text(QStringLiteral("process.detail.performance.series.disk")),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Disk),
            &Chart::Sample::diskMBps } },
        QStringLiteral("MB/s"),
        0.0);
    setChartData(
        m_performanceNetworkChart,
        {
            ProcessPerformanceHistoryChartWidget::Series{
                text(QStringLiteral("process.detail.performance.series.network_rx")),
                KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Read),
                &Chart::Sample::networkRxKBps },
            ProcessPerformanceHistoryChartWidget::Series{
                text(QStringLiteral("process.detail.performance.series.network_tx")),
                KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Write),
                &Chart::Sample::networkTxKBps }
        },
        QStringLiteral("KB/s"),
        0.0);
    setChartData(
        m_performanceGpuChart,
        { ProcessPerformanceHistoryChartWidget::Series{
            text(QStringLiteral("process.detail.performance.series.gpu")),
            KswordTheme::PerformanceColor(KswordTheme::PerformanceRole::Gpu),
            &Chart::Sample::gpuPercent } },
        QStringLiteral("%"),
        100.0);

    // 空历史同样已经提交到六个图表，避免身份切换/清空后残留上一对象的曲线。
    if (history->empty())
    {
        m_performanceHistoryStatusLabel->setText(text(QStringLiteral("process.detail.performance.status.empty")));
        return;
    }
    const QString beginTime = QDateTime::fromMSecsSinceEpoch(history->front().unixMilliseconds).toString(QStringLiteral("HH:mm:ss"));
    const QString endTime = QDateTime::fromMSecsSinceEpoch(history->back().unixMilliseconds).toString(QStringLiteral("HH:mm:ss"));
    m_performanceHistoryStatusLabel->setText(
        text(QStringLiteral("process.detail.performance.status.samples"))
            .arg(static_cast<qulonglong>(m_performanceHistory.size()))
            .arg(beginTime)
            .arg(endTime));
}

void ProcessDetailWindow::initializeCpuCoreTab()
{
    auto& languageManager = ks::i18n::LanguageManager::instance();
    QVBoxLayout* layout = nullptr;
    QWidget* const contentWidget = createScrollableTabContent(m_cpuCoreTab, layout, 12, 10);
    if (contentWidget == nullptr || layout == nullptr)
    {
        return;
    }

    m_cpuCoreTitleLabel = new QLabel(contentWidget);
    m_cpuCoreTitleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    languageManager.bindText(
        m_cpuCoreTitleLabel,
        QStringLiteral("process.detail.cpu_core.title"),
        QStringLiteral("进程与线程 CPU 核心视图"));
    layout->addWidget(m_cpuCoreTitleLabel);

    m_cpuCoreDescriptionLabel = new QLabel(contentWidget);
    m_cpuCoreDescriptionLabel->setWordWrap(true);
    m_cpuCoreDescriptionLabel->setStyleSheet(QStringLiteral("color:%1;")
        .arg(KswordTheme::TextSecondaryHex()));
    languageManager.bindText(
        m_cpuCoreDescriptionLabel,
        QStringLiteral("process.detail.cpu_core.description"),
        QStringLiteral("基于线程上下文切换区间统计真实运行核心；单组使用 Lx，多组使用 Gx:Ly。"));
    layout->addWidget(m_cpuCoreDescriptionLabel);

    m_cpuCoreStatusLabel = new QLabel(contentWidget);
    m_cpuCoreStatusLabel->setWordWrap(true);
    layout->addWidget(m_cpuCoreStatusLabel);

    auto* equivalentGroup = new QGroupBox(contentWidget);
    languageManager.bindText(
        equivalentGroup,
        QStringLiteral("process.detail.cpu_core.group.summary"),
        QStringLiteral("进程汇总"));
    auto* equivalentLayout = new QHBoxLayout(equivalentGroup);
    auto* systemTitleLabel = new QLabel(equivalentGroup);
    languageManager.bindText(
        systemTitleLabel,
        QStringLiteral("process.detail.cpu_core.summary.system"),
        QStringLiteral("CPU 占用"));
    m_cpuCoreSystemValueLabel = new QLabel(QStringLiteral("0.00%"), equivalentGroup);
    m_cpuCoreSystemValueLabel->setStyleSheet(QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue).name()));
    auto* equivalentTitleLabel = new QLabel(equivalentGroup);
    languageManager.bindText(
        equivalentTitleLabel,
        QStringLiteral("process.detail.field.cpu_core"),
        QStringLiteral("CPU 单核等效"));
    m_cpuCoreEquivalentValueLabel = new QLabel(QStringLiteral("0.00%"), equivalentGroup);
    m_cpuCoreEquivalentValueLabel->setStyleSheet(QStringLiteral("font-size:20px;font-weight:700;color:%1;")
        .arg(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue).name()));
    equivalentLayout->addWidget(systemTitleLabel);
    equivalentLayout->addWidget(m_cpuCoreSystemValueLabel);
    equivalentLayout->addSpacing(24);
    equivalentLayout->addWidget(equivalentTitleLabel);
    equivalentLayout->addWidget(m_cpuCoreEquivalentValueLabel);
    equivalentLayout->addStretch(1);
    layout->addWidget(equivalentGroup);

    auto* processGroup = new QGroupBox(contentWidget);
    languageManager.bindText(
        processGroup,
        QStringLiteral("process.detail.cpu_core.group.process"),
        QStringLiteral("进程逐核心占用"));
    auto* processLayout = new QVBoxLayout(processGroup);
    processLayout->setContentsMargins(8, 10, 8, 8);
    processLayout->setSpacing(0);
    m_processCpuCoreGrid = new CpuCoreUsageGridWidget(processGroup);
    processLayout->addWidget(m_processCpuCoreGrid);
    layout->addWidget(processGroup);

    auto* threadGroup = new QGroupBox(contentWidget);
    languageManager.bindText(
        threadGroup,
        QStringLiteral("process.detail.cpu_core.group.thread"),
        QStringLiteral("线程逐核心占用"));
    auto* threadLayout = new QVBoxLayout(threadGroup);
    threadLayout->setContentsMargins(8, 10, 8, 8);
    threadLayout->setSpacing(6);
    auto* threadUsageHintLabel = new QLabel(threadGroup);
    threadUsageHintLabel->setWordWrap(true);
    threadUsageHintLabel->setStyleSheet(QStringLiteral("color:%1;")
        .arg(KswordTheme::TextSecondaryHex()));
    languageManager.bindText(
        threadUsageHintLabel,
        QStringLiteral("process.detail.cpu_core.thread_hint"),
        QStringLiteral("此百分比统计了线程在每个核心的占用时间（线程所在的核心可能发生跳变）（单个线程不可能同时使用多个核心）"));
    threadLayout->addWidget(threadUsageHintLabel);
    m_threadCpuCoreGrid = new CpuThreadUsageCardGridWidget(threadGroup);
    threadLayout->addWidget(m_threadCpuCoreGrid);
    layout->addWidget(threadGroup);
    layout->addStretch(1);

    refreshCpuCoreView(true);
}

void ProcessDetailWindow::refreshCpuCoreView(const bool appendHistory)
{
    m_cpuCorePresentationDirty = true;
    if (m_cpuCoreStatusLabel == nullptr ||
        m_processCpuCoreGrid == nullptr ||
        m_threadCpuCoreGrid == nullptr)
    {
        return;
    }

    const CpuCoreViewSample& sample = m_cpuCoreViewSample;
    // 新采样必须记录，包括隐藏期间；换主题、换语言和重新显示只刷新外观。
    if (appendHistory)
    {
        const bool multipleProcessorGroups = !sample.processCores.empty() && std::any_of(
            sample.processCores.cbegin(), sample.processCores.cend(),
            [&sample](const CpuCoreValue& core) {
                return core.group != sample.processCores.front().group;
            });
        static_cast<CpuCoreUsageGridWidget*>(m_processCpuCoreGrid)->setCoreValues(
            sample.processCores, multipleProcessorGroups);
        static_cast<CpuThreadUsageCardGridWidget*>(m_threadCpuCoreGrid)->setThreadValues(
            sample.threads, multipleProcessorGroups);
    }
    if (!detailChartPageExposed(m_cpuCoreTab))
    {
        return;
    }
    m_cpuCorePresentationDirty = false;
    if (m_cpuCoreSystemValueLabel != nullptr)
    {
        m_cpuCoreSystemValueLabel->setText(
            QString::number(sample.processSystemPercent, 'f', 2) + QStringLiteral("%"));
    }
    if (m_cpuCoreEquivalentValueLabel != nullptr)
    {
        m_cpuCoreEquivalentValueLabel->setText(
            QString::number(sample.processCoreEquivalentPercent, 'f', 2) + QStringLiteral("%"));
    }

    QString statusText;
    QColor statusColor = statusSecondaryColor();
    if (!sample.monitorRunning)
    {
        statusText = sample.diagnosticText.trimmed().isEmpty()
            ? ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.unavailable"), QString())
            : ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.failed"), QString())
                .arg(sample.diagnosticText);
        statusColor = KswordTheme::ErrorColor();
    }
    else if (!sample.sampleReady)
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.sampling"), QString());
        statusColor = KswordTheme::PrimaryBlueColor;
    }
    else if (sample.dataLossDetected)
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.loss"), QString())
            .arg(static_cast<qulonglong>(sample.eventsLost));
        statusColor = statusWarningColor();
    }
    else
    {
        statusText = ks::i18n::text(QStringLiteral("process.detail.cpu_core.status.ready"), QString())
            .arg(static_cast<qulonglong>(sample.contextSwitchEvents));
        statusColor = signatureTrustedColor();
    }
    m_cpuCoreStatusLabel->setText(statusText);
    applyProcessDetailLocalStyle(m_cpuCoreStatusLabel, buildStateLabelStyle(statusColor, 600));
}

void ProcessDetailWindow::initializeThreadTab()
{
    // 线程页初始化日志：把线程枚举与寄存器摘要单独放到独立标签。
    kLogEvent initThreadTabEvent;
    info << initThreadTabEvent
        << "[ProcessDetailWindow] initializeThreadTab: 构建线程信息页面。"
        << eol;

    m_threadLayout = new QVBoxLayout(m_threadTab);
    m_threadLayout->setContentsMargins(6, 6, 6, 6);
    m_threadLayout->setSpacing(8);

    QGroupBox* threadGroup = new QGroupBox("线程枚举与上下文摘要", m_threadTab);
    QVBoxLayout* threadGroupLayout = new QVBoxLayout(threadGroup);
    threadGroupLayout->setContentsMargins(8, 8, 8, 8);
    threadGroupLayout->setSpacing(6);

    // 顶部工具栏：
    // - 刷新按钮保留明确文字，避免仅靠图标无法分辨“线程刷新”语义；
    // - 状态标签放在右侧，持续反馈本轮刷新耗时与诊断信息。
    QHBoxLayout* threadTopBarLayout = new QHBoxLayout();
    m_refreshThreadInspectButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新线程", threadGroup);
    m_refreshThreadInspectButton->setToolTip("异步刷新线程枚举、TEB、起始地址与寄存器摘要");
    m_sampleThreadRuntimeButton = new QPushButton(QIcon(":/Icon/process_tree.svg"), "采样PDB字段", threadGroup);
    m_sampleThreadRuntimeButton->setToolTip("只读采样当前选中线程的 PDB deep runtime 字段，不批量扫描全部线程");
    auto* openThreadStackButton = new QPushButton(QIcon(":/Icon/process_threads.svg"), "查看调用栈", threadGroup);
    openThreadStackButton->setToolTip("打开当前选中线程的 Phase-8 调用栈窗口");
    m_threadInspectStatusLabel = new QLabel("● 尚未刷新", threadGroup);
    m_threadInspectStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    threadTopBarLayout->addWidget(m_refreshThreadInspectButton);
    threadTopBarLayout->addWidget(m_sampleThreadRuntimeButton);
    threadTopBarLayout->addWidget(openThreadStackButton);
    threadTopBarLayout->addWidget(m_threadInspectStatusLabel, 1);
    threadGroupLayout->addLayout(threadTopBarLayout);

    // 线程表格：
    // - 继续沿用原有列定义和刷新逻辑；
    // - 仅把显示位置从“详细信息页底部”迁移到独立标签。
    QVector<ks::ui::ImmutableTableHeader> threadHeaders;
    for (const auto& header : ThreadInspectHeaders) threadHeaders.push_back(ks::ui::ImmutableTableHeader(header));
    m_threadInspectTable = new ks::ui::ImmutableValueTable(threadGroup, std::move(threadHeaders));
    // 当前进程的线程详情是辅助清单，保留复制导出而非整套对比栏。
    ks::ui::SetTableActionBarMode(m_threadInspectTable, ks::ui::TableActionBarMode::Compact);
    m_threadInspectTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_threadInspectTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_threadInspectTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_threadInspectTable->setAlternatingRowColors(true);
    m_threadInspectTable->verticalHeader()->setVisible(false);
    m_threadInspectTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_threadInspectTable->horizontalHeader()->setStretchLastSection(true);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::ThreadId), 96);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::State), 82);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::Priority), 72);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::SwitchCount), 96);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::StartAddress), 130);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::TebAddress), 130);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::Affinity), 108);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::StackBoundary), 260);
    m_threadInspectTable->setColumnWidth(toThreadColumnIndex(ThreadRowColumn::RuntimeDetail), 360);
    m_threadInspectTable->setContextMenuPolicy(Qt::CustomContextMenu);
    threadGroupLayout->addWidget(m_threadInspectTable, 1);

    // 当前线程 deep PDB 采样详情：
    // - 默认只显示选中行的可读 runtime detail；
    // - 点击“采样PDB字段”后后台调用 thread runtime field sampler；
    // - 原生结构字段保留复制/搜索和四种详情布局。
    m_threadRuntimeSampleOutput = new ks::ui::StructuredFieldView(threadGroup);
    m_threadRuntimeSampleOutput->setMaximumHeight(220);
    m_threadRuntimeSampleOutput->setDocument(fieldNotice(QStringLiteral(
        "选择线程行后可查看 R0 runtime detail；点击“采样PDB字段”可按需读取 thread_detail deep JSON 小字段。")));
    threadGroupLayout->addWidget(m_threadRuntimeSampleOutput, 0);

    ks::ui::DetailLayoutRegistry::registerStructuredHost(
        m_threadInspectTable, m_threadRuntimeSampleOutput, threadGroup);

    m_threadLayout->addWidget(threadGroup, 1);

    const QString buttonStyle = buildBlueButtonStyle();
    m_refreshThreadInspectButton->setStyleSheet(buttonStyle);
    m_sampleThreadRuntimeButton->setStyleSheet(buttonStyle);
    openThreadStackButton->setStyleSheet(buttonStyle);
    ks::ui::NormalizeToolbarRow(threadTopBarLayout);
    connect(m_sampleThreadRuntimeButton, &QPushButton::clicked, this, [this]() {
        requestAsyncSelectedThreadRuntimeSample();
        });
    connect(openThreadStackButton, &QPushButton::clicked, this, [this]() {
        openSelectedThreadStackWindow();
        });
    m_threadInspectTable->currentRowChanged = [this]() {
        if (m_threadInspectRefreshing || m_threadInspectTable->isPreparing() || !m_threadInspectPublishedRows) return;
        const int currentRow = m_threadInspectTable->currentRow();
        // 选中行详情：
        // - 输入：当前表格行；
        // - 处理：从缓存中取 ThreadInspectItem，展示固定 detail IOCTL 可读摘要；
        // - 返回：无，不执行新的驱动调用。
        if (m_threadRuntimeSampleOutput == nullptr)
        {
            return;
        }
        if (m_threadInspectTable == nullptr || currentRow < 0)
        {
            m_threadRuntimeSampleOutput->setDocument(fieldNotice(QStringLiteral("请选择一条线程记录查看 runtime detail。")));
            return;
        }
        const QModelIndex threadIdItem =
            m_threadInspectTable->model()->index(currentRow, toThreadColumnIndex(ThreadRowColumn::ThreadId));
        const std::size_t cacheIndex = threadIdItem.isValid()
            ? static_cast<std::size_t>(threadIdItem.data(Qt::UserRole).toULongLong())
            : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
        if (cacheIndex >= m_threadInspectPublishedRows->size())
        {
            m_threadRuntimeSampleOutput->setDocument(fieldNotice(QStringLiteral("当前线程行缺少缓存详情，请刷新线程页。")));
            return;
        }

        const ThreadInspectItem& rowItem = (*m_threadInspectPublishedRows)[cacheIndex];
        const auto threadDetailStatusName = [](const std::uint32_t statusValue) -> QString
        {
            switch (statusValue)
            {
            case KSWORD_ARK_DETAIL_STATUS_OK:
                return QStringLiteral("OK");
            case KSWORD_ARK_DETAIL_STATUS_PARTIAL:
                return QStringLiteral("Partial");
            case KSWORD_ARK_DETAIL_STATUS_UNSUPPORTED:
                return QStringLiteral("Unsupported");
            case KSWORD_ARK_DETAIL_STATUS_LOOKUP_FAILED:
                return QStringLiteral("LookupFailed");
            case KSWORD_ARK_DETAIL_STATUS_CAPABILITY_MISSING:
                return QStringLiteral("CapabilityMissing");
            case KSWORD_ARK_DETAIL_STATUS_READ_FAILED:
                return QStringLiteral("ReadFailed");
            default:
                return QStringLiteral("Status(%1)").arg(statusValue);
            }
        };
        const auto threadStatusHexText = [](const long statusValue) -> QString
        {
            return QStringLiteral("0x%1")
                .arg(static_cast<quint32>(statusValue), 8, 16, QChar('0'))
                .toUpper();
        };
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("Thread Runtime Detail"));
        document.field(QStringLiteral("TID/PID"), QStringLiteral("%1/%2").arg(rowItem.threadId).arg(rowItem.processId));
        document.field(QStringLiteral("Start/Win32Start"), QStringLiteral("%1 / %2")
            .arg(uint64ToHex(rowItem.startAddress))
            .arg(uint64ToHex(rowItem.win32StartAddress)));
        document.field(QStringLiteral("TEB"), QStringLiteral("%1").arg(uint64ToHex(rowItem.tebAddress)));
        document.field(QStringLiteral("R0 stack"), QStringLiteral("Kernel=%1 Limit=%2 Base=%3 Initial=%4")
            .arg(uint64ToHex(rowItem.r0KernelStack))
            .arg(uint64ToHex(rowItem.r0StackLimit))
            .arg(uint64ToHex(rowItem.r0StackBase))
            .arg(uint64ToHex(rowItem.r0InitialStack)));
        document.field(QStringLiteral("I/O ops"), QStringLiteral("R/W/O=%1/%2/%3")
            .arg(static_cast<qulonglong>(rowItem.r0ReadOperationCount))
            .arg(static_cast<qulonglong>(rowItem.r0WriteOperationCount))
            .arg(static_cast<qulonglong>(rowItem.r0OtherOperationCount)));
        document.field(QStringLiteral("I/O bytes"), QStringLiteral("R/W/O=%1/%2/%3")
            .arg(static_cast<qulonglong>(rowItem.r0ReadTransferCount))
            .arg(static_cast<qulonglong>(rowItem.r0WriteTransferCount))
            .arg(static_cast<qulonglong>(rowItem.r0OtherTransferCount)));
        document.field(QStringLiteral("DetailStatus"), QStringLiteral("%1").arg(threadDetailStatusName(rowItem.r0DetailStatus)));
        document.field(QStringLiteral("MissingCapability"), QStringLiteral("%1")
            .arg(uint64ToHex(rowItem.r0MissingCapabilityMask)));
        document.field(QStringLiteral("LastStatus"), QStringLiteral("%1").arg(threadStatusHexText(rowItem.r0DetailLastStatus)));
        document.field(QStringLiteral("说明"), QStringLiteral("%1").arg(
            rowItem.r0RuntimeDetailText.trimmed().isEmpty()
            ? QStringLiteral("线程 runtime detail 暂不可用。")
            : rowItem.r0RuntimeDetailText));
        document.note(QStringLiteral("\n点击“采样PDB字段”可对当前 TID 按需读取 thread_detail deep offset 小字段。"));
        m_threadRuntimeSampleOutput->setDocument(document);
        };
    m_threadInspectTable->rowDoubleClicked = [this](int) { openSelectedThreadStackWindow(); };
    connect(m_threadInspectTable, &QTableView::customContextMenuRequested, this, [this](const QPoint& localPosition)
    {
        // 线程表右键菜单：
        // - 输入：用户在表格上的点击位置；
        // - 处理：选中点击行，复制当前行的可见文本；
        // - 返回：无，只写剪贴板，不执行线程操作。
        if (m_threadInspectTable == nullptr)
        {
            return;
        }

        const QModelIndex clickedIndex = m_threadInspectTable->indexAt(localPosition);
        if (clickedIndex.isValid())
        {
            m_threadInspectTable->setCurrentIndex(clickedIndex);
        }

        QMenu menu(m_threadInspectTable);
        menu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* copyRowAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
            QStringLiteral("复制当前行"));
        // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
        ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
        copyRowAction->setEnabled(m_threadInspectTable->currentRow() >= 0);
        const int selectedThreadRow = m_threadInspectTable->currentRow();
        const QModelIndex selectedThreadIdItem =
            selectedThreadRow >= 0
                ? m_threadInspectTable->model()->index(
                    selectedThreadRow,
                    toThreadColumnIndex(ThreadRowColumn::ThreadId))
                : QModelIndex();
        const std::size_t selectedThreadCacheIndex = selectedThreadIdItem.isValid()
            ? static_cast<std::size_t>(selectedThreadIdItem.data(Qt::UserRole).toULongLong())
            : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
        const ThreadInspectItem* const selectedThreadAffinityTarget =
            selectedThreadCacheIndex < m_threadInspectPublishedRows->size()
                ? &(*m_threadInspectPublishedRows)[selectedThreadCacheIndex]
                : nullptr;
        QMenu* const affinityMenu = ks::process::addThreadAffinitySubMenu(
            &menu,
            QIcon(QStringLiteral(":/Icon/process_priority.svg")),
            selectedThreadAffinityTarget != nullptr
                ? selectedThreadAffinityTarget->processId
                : 0U,
            selectedThreadAffinityTarget != nullptr
                ? selectedThreadAffinityTarget->threadId
                : 0U,
            selectedThreadAffinityTarget != nullptr
                ? selectedThreadAffinityTarget->createTime100ns
                : 0U,
            buildProcessDetailMenuStyle(),
            [this](const bool actionOk, const QString& resultText)
            {
                if (m_threadInspectStatusLabel != nullptr)
                {
                    m_threadInspectStatusLabel->setText(resultText);
                    m_threadInspectStatusLabel->setStyleSheet(buildStateLabelStyle(
                        actionOk ? statusIdleColor() : statusWarningColor(),
                        actionOk ? 600 : 700));
                }
                kLogEvent actionEvent;
                (actionOk ? info : err) << actionEvent
                    << "[ProcessDetailWindow] thread affinity update: pid="
                    << m_baseRecord.pid
                    << ", actionOk="
                    << (actionOk ? "true" : "false")
                    << ", detail="
                    << resultText.toStdString()
                    << eol;
                requestAsyncThreadInspectRefresh();
            });
        QAction* r0SuspendThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_suspend"),
                QStringLiteral("R0挂起线程")));
        QAction* r0ResumeThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_resume.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_resume"),
                QStringLiteral("R0恢复线程")));
        QAction* suspendDriverThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_suspend"),
                QStringLiteral("ZwSuspendThread / NtSuspendThread（实验性）")));
        QAction* resumeDriverThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_resume.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_resume"),
                QStringLiteral("ZwResumeThread / NtResumeThread（实验性）")));
        QMenu* terminateDriverThreadMenu = menu.addMenu(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate_experimental"),
                QStringLiteral("结束驱动线程（实验性原始 API）")));
        QAction* terminateDriverThreadPspAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.psp"),
                QStringLiteral("PspTerminateThreadByPointer（实验性/未文档化）")));
        QAction* terminateDriverThreadZwAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.zw"),
                QStringLiteral("ZwTerminateThread / NtTerminateThread（实验性）")));
        QAction* terminateDriverThreadNormalApcAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.normal_apc"),
                QStringLiteral("KeInsertQueueApc → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
        QAction* terminateDriverThreadSpecialApcAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.driver_terminate.special_apc"),
                QStringLiteral("KeInsertQueueApc → Special Kernel APC → Normal Kernel APC → PsTerminateSystemThread（实验性）")));
        terminateDriverThreadMenu->addSeparator();
        QAction* firmwareRebootAction = terminateDriverThreadMenu->addAction(
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.hal_return_to_firmware"),
                QStringLiteral("HalReturnToFirmware(HalRebootRoutine)（实验性/整机动作）")));
        QAction* r0TerminateThreadAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_terminate.svg")),
            ks::i18n::contextText(
                QStringLiteral("process.thread.menu.r0_terminate"),
                QStringLiteral("R0结束线程")));
        const bool hasR0ThreadControlTarget =
            m_threadInspectTable->currentRow() >= 0 && m_baseRecord.pid > 4U;
        if (affinityMenu != nullptr &&
            (selectedThreadAffinityTarget == nullptr ||
                selectedThreadAffinityTarget->processId != m_baseRecord.pid ||
                selectedThreadAffinityTarget->threadId == 0U ||
                selectedThreadAffinityTarget->createTime100ns == 0U))
        {
            affinityMenu->setEnabled(false);
            affinityMenu->setToolTip(ks::i18n::contextText(
                QStringLiteral("process.thread.menu.affinity.unavailable"),
                QStringLiteral("无法读取此线程的 CPU Set 亲和性。")));
        }
        r0SuspendThreadAction->setEnabled(hasR0ThreadControlTarget);
        r0ResumeThreadAction->setEnabled(hasR0ThreadControlTarget);
        r0TerminateThreadAction->setEnabled(hasR0ThreadControlTarget);
        bool hasDriverThreadTarget = false;
        if (m_threadInspectTable->currentRow() >= 0 && m_baseRecord.pid == 4U)
        {
            const QModelIndex selectedThreadIdItem = m_threadInspectTable->model()->index(
                m_threadInspectTable->currentRow(),
                toThreadColumnIndex(ThreadRowColumn::ThreadId));
            const std::size_t selectedCacheIndex = selectedThreadIdItem.isValid()
                ? static_cast<std::size_t>(selectedThreadIdItem.data(Qt::UserRole).toULongLong())
                : static_cast<std::size_t>(m_threadInspectPublishedRows->size());
            hasDriverThreadTarget =
                selectedCacheIndex < m_threadInspectPublishedRows->size() &&
                (*m_threadInspectPublishedRows)[selectedCacheIndex].threadId != 0U &&
                (*m_threadInspectPublishedRows)[selectedCacheIndex].createTime100ns != 0ULL &&
                ((*m_threadInspectPublishedRows)[selectedCacheIndex].startAddress != 0ULL ||
                 (*m_threadInspectPublishedRows)[selectedCacheIndex].win32StartAddress != 0ULL);
        }
        suspendDriverThreadAction->setVisible(hasDriverThreadTarget);
        resumeDriverThreadAction->setVisible(hasDriverThreadTarget);
        terminateDriverThreadMenu->menuAction()->setVisible(hasDriverThreadTarget);
        menu.addSeparator();
        QAction* uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
            &menu,
            this,
            [this]() -> ks::online_scan::SandboxUploadTarget
            {
                // 输入：线程表当前行。
                // 处理：解析线程所属模块路径，不回退到进程 EXE。
                // 返回：待上传模块路径和来源说明。
                ks::online_scan::SandboxUploadTarget uploadTarget;
                QString errorText;
                uploadTarget.filePath = resolveSelectedThreadModulePathForUpload(&errorText);
                uploadTarget.sourceText = QStringLiteral("进程详情线程模块 PID=%1").arg(m_baseRecord.pid);
                uploadTarget.errorText = errorText;
                return uploadTarget;
            });
        if (uploadVirusTotalAction != nullptr)
        {
            uploadVirusTotalAction->setEnabled(m_threadInspectTable->currentRow() >= 0);
        }

        QAction* selectedAction = menu.exec(m_threadInspectTable->viewport()->mapToGlobal(localPosition));
        if (selectedAction == uploadVirusTotalAction)
        {
            return;
        }
        if (selectedAction == r0SuspendThreadAction)
        {
            executeR0SuspendSelectedThreadAction();
            return;
        }
        if (selectedAction == r0ResumeThreadAction)
        {
            executeR0ResumeSelectedThreadAction();
            return;
        }
        if (selectedAction == suspendDriverThreadAction)
        {
            executeDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_ACTION_SUSPEND);
            return;
        }
        if (selectedAction == resumeDriverThreadAction)
        {
            executeDriverThreadAction(KSWORD_ARK_DRIVER_THREAD_ACTION_RESUME);
            return;
        }
        if (selectedAction == terminateDriverThreadPspAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_PSP_BY_POINTER);
            return;
        }
        if (selectedAction == terminateDriverThreadZwAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_ZW_OR_NT);
            return;
        }
        if (selectedAction == terminateDriverThreadNormalApcAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_NORMAL_APC);
            return;
        }
        if (selectedAction == terminateDriverThreadSpecialApcAction)
        {
            executeDriverThreadAction(
                KSWORD_ARK_DRIVER_THREAD_ACTION_TERMINATE,
                KSWORD_ARK_DRIVER_THREAD_TERMINATE_METHOD_SPECIAL_TO_NORMAL_APC);
            return;
        }
        if (selectedAction == firmwareRebootAction)
        {
            executeExperimentalFirmwareRebootAction();
            return;
        }
        if (selectedAction == r0TerminateThreadAction)
        {
            executeR0TerminateSelectedThreadAction();
            return;
        }
        if (selectedAction != copyRowAction)
        {
            return;
        }

        const int rowIndex = m_threadInspectTable->currentRow();
        if (rowIndex < 0 || QApplication::clipboard() == nullptr)
        {
            return;
        }

        QStringList rowFields;
        rowFields.reserve(m_threadInspectTable->columnCount());
        for (int columnIndex = 0; columnIndex < m_threadInspectTable->columnCount(); ++columnIndex)
        {
            const QModelIndex item = m_threadInspectTable->model()->index(rowIndex, columnIndex);
            rowFields.push_back(item.isValid() ? item.data().toString() : QString());
        }
        QApplication::clipboard()->setText(rowFields.join('\t'));
    });
}

void ProcessDetailWindow::initializeActionTab()
{
    // 操作页初始化日志：确认动作按钮区域构建。
    kLogEvent initActionTabEvent;
    info << initActionTabEvent
        << "[ProcessDetailWindow] initializeActionTab: 构建进程操作页面。"
        << eol;

    QWidget* const actionContent = createScrollableTabContent(
        m_actionTab,
        m_actionLayout,
        6,
        10);

    // buildTextActionButton 作用：
    // - 为操作页生成统一文字按钮；
    // - 输入 buttonText 作为用户直接可见的按钮含义，toolTipText 作为补充解释；
    // - 返回 QPushButton，不使用图标-only 形态，避免操作面板含义不直观。
    const auto buildTextActionButton =
        [](const QString& buttonText, const QString& toolTipText, QWidget* parentWidget) -> QPushButton*
    {
        QPushButton* actionButton = new QPushButton(buttonText, parentWidget);
        actionButton->setMinimumWidth(72);
        actionButton->setToolTip(toolTipText);
        ks::ui::NormalizeToolbarControl(actionButton);
        return actionButton;
    };

    // 结束与控制组：
    // - “结束方案”改为下拉选择，避免四个宽按钮铺满整行；
    // - 运行控制与关键进程操作改为紧凑图标按钮，保留 tooltip 解释语义。
    QGroupBox* controlGroup = new QGroupBox("结束与控制", actionContent);
    QGridLayout* controlLayout = new QGridLayout(controlGroup);
    controlLayout->setHorizontalSpacing(8);
    controlLayout->setVerticalSpacing(8);

    m_terminateActionCombo = new QComboBox(controlGroup);
    for (std::size_t index = 0; index < ks::process::TerminateMethodTable().size(); ++index)
    {
        m_terminateActionCombo->addItem(
            QIcon(":/Icon/process_terminate.svg"),
            QString::fromUtf8(ks::process::TerminateMethodTable()[index].methodName),
            static_cast<int>(index));
    }
    m_terminateActionCombo->addItem(
        QIcon(":/Icon/process_terminate.svg"),
        ks::i18n::sourceText(QStringLiteral("R0 驱动结束（四步：清保护 → ZwTerminate → 逐线程 → 清零内存）")),
        static_cast<int>(ks::process::TerminateMethodTable().size()));
    // 组合链使用独立 ID，保留已有单方法及 R0 选项的 ID 和默认选择。
    m_terminateActionCombo->addItem(
        QIcon(":/Icon/process_terminate.svg"),
        ks::i18n::sourceText(QStringLiteral("结束进程(组合方法链)")),
        static_cast<int>(ks::process::TerminateMethodTable().size()) + 1);
    m_terminateActionCombo->setToolTip("选择结束当前进程的执行方案");
    m_executeTerminateActionButton = buildTextActionButton(
        QStringLiteral("执行"),
        QStringLiteral("执行当前选中的结束方案"),
        controlGroup);

    m_suspendProcessCheck = new QCheckBox(QStringLiteral("挂起"), controlGroup);
    m_suspendProcessCheck->setToolTip(
        QStringLiteral("勾上挂起当前进程，取消勾选恢复。勾选态反映进程当前是否处于挂起，不表示是谁挂的。"));
    m_setCriticalButton = buildTextActionButton(
        QStringLiteral("设为关键"),
        QStringLiteral("把当前进程设为关键进程"),
        controlGroup);
    m_clearCriticalButton = buildTextActionButton(
        QStringLiteral("取消关键"),
        QStringLiteral("取消当前进程的关键进程标记"),
        controlGroup);
    m_priorityCombo = new QComboBox(controlGroup);
    m_priorityCombo->addItem("Idle", 0);
    m_priorityCombo->addItem("Below Normal", 1);
    m_priorityCombo->addItem("Normal", 2);
    m_priorityCombo->addItem("Above Normal", 3);
    m_priorityCombo->addItem("High", 4);
    m_priorityCombo->addItem("Realtime", 5);
    m_priorityCombo->setCurrentIndex(2);
    m_priorityCombo->setToolTip("选择当前进程的新优先级");
    m_applyPriorityButton = buildTextActionButton(
        QStringLiteral("应用"),
        QStringLiteral("应用当前选中的进程优先级"),
        controlGroup);

    controlLayout->addWidget(new QLabel("结束方案", controlGroup), 0, 0);
    controlLayout->addWidget(m_terminateActionCombo, 0, 1, 1, 3);
    controlLayout->addWidget(m_executeTerminateActionButton, 0, 4);
    controlLayout->addWidget(new QLabel("运行控制", controlGroup), 1, 0);
    controlLayout->addWidget(m_suspendProcessCheck, 1, 1, 1, 2);
    controlLayout->addWidget(new QLabel("关键进程", controlGroup), 2, 0);
    controlLayout->addWidget(m_setCriticalButton, 2, 1);
    controlLayout->addWidget(m_clearCriticalButton, 2, 2);
    controlLayout->addWidget(new QLabel("优先级", controlGroup), 3, 0);
    controlLayout->addWidget(m_priorityCombo, 3, 1, 1, 3);
    controlLayout->addWidget(m_applyPriorityButton, 3, 4);
    m_actionLayout->addWidget(controlGroup);

    // CPU 亲和性：
    // - 以 6 列矩阵展示稳定逻辑处理器身份；仅多组时显示 Gx 前缀和分组标题；
    // - 仅在“操作”页首次进入后读取实际 CPU Set，保持详情窗口首次打开的轻量路径；
    // - 每个按钮独立切换，蓝色主题背景代表该逻辑处理器已启用。
    m_affinityActionGroup = new QGroupBox(
        ks::i18n::text(QStringLiteral("process.detail.affinity.title"), QString()),
        actionContent);
    QVBoxLayout* affinityGroupLayout = new QVBoxLayout(m_affinityActionGroup);
    affinityGroupLayout->setContentsMargins(10, 10, 10, 10);
    affinityGroupLayout->setSpacing(8);

    const auto installCopyMenu = [](QWidget* widget, const std::function<QString()>& textProvider)
    {
        if (widget == nullptr)
        {
            return;
        }
        widget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(widget, &QWidget::customContextMenuRequested, widget,
            [widget, textProvider](const QPoint& localPosition)
            {
                const QString copyText = textProvider ? textProvider().trimmed() : QString();
                if (copyText.isEmpty())
                {
                    return;
                }
                QMenu contextMenu(widget);
                contextMenu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* copyAction = contextMenu.addAction(
                    ks::i18n::text(QStringLiteral("process.detail.action.copy"), QString()));
                if (contextMenu.exec(widget->mapToGlobal(localPosition)) == copyAction)
                {
                    QApplication::clipboard()->setText(copyText);
                }
            });
    };

    m_affinityDescriptionLabel = new QLabel(
        ks::i18n::text(QStringLiteral("process.detail.affinity.description"), QString()),
        m_affinityActionGroup);
    m_affinityDescriptionLabel->setWordWrap(true);
    m_affinityDescriptionLabel->setMinimumWidth(0);
    m_affinityDescriptionLabel->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    m_affinityDescriptionLabel->setTextInteractionFlags(
        Qt::TextSelectableByMouse);
    m_affinityDescriptionLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    installCopyMenu(m_affinityDescriptionLabel, [this]()
    {
        return m_affinityDescriptionLabel != nullptr
            ? m_affinityDescriptionLabel->text()
            : QString();
    });
    affinityGroupLayout->addWidget(m_affinityDescriptionLabel);

    m_affinityPersistenceCheckBox = new QCheckBox(
        ks::i18n::text(QStringLiteral("process.detail.affinity.persistence"), QString()),
        m_affinityActionGroup);
    m_affinityPersistenceCheckBox->setToolTip(
        ks::i18n::text(QStringLiteral("process.detail.affinity.persistence.tooltip"), QString()));
    affinityGroupLayout->addWidget(m_affinityPersistenceCheckBox);

    QHBoxLayout* affinityTopLayout = new QHBoxLayout();
    affinityTopLayout->setContentsMargins(0, 0, 0, 0);
    affinityTopLayout->setSpacing(8);
    m_affinityStatusLabel = new QLabel(m_affinityActionGroup);
    m_affinityStatusLabel->setWordWrap(true);
    m_affinityStatusLabel->setMinimumWidth(0);
    m_affinityStatusLabel->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    m_affinityStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    installCopyMenu(m_affinityStatusLabel, [this]()
    {
        return m_affinityStatusLabel != nullptr ? m_affinityStatusLabel->text() : QString();
    });
    m_affinityRefreshButton = buildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.affinity.refresh"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.affinity.refresh"), QString()),
        m_affinityActionGroup);
    m_affinityAllCoresButton = buildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.affinity.all_cores"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.affinity.all_cores"), QString()),
        m_affinityActionGroup);
    affinityTopLayout->addWidget(m_affinityStatusLabel, 1);
    affinityTopLayout->addWidget(m_affinityRefreshButton);
    affinityTopLayout->addWidget(m_affinityAllCoresButton);
    ks::ui::NormalizeToolbarRow(affinityTopLayout);
    affinityGroupLayout->addLayout(affinityTopLayout);

    m_affinityMatrixLayout = new QGridLayout();
    m_affinityMatrixLayout->setContentsMargins(0, 0, 0, 0);
    m_affinityMatrixLayout->setHorizontalSpacing(6);
    m_affinityMatrixLayout->setVerticalSpacing(6);
    m_affinityCoreButtons.clear();
    affinityGroupLayout->addLayout(m_affinityMatrixLayout);
    m_actionLayout->addWidget(m_affinityActionGroup);

    connect(m_affinityRefreshButton, &QPushButton::clicked, this, [this]()
    {
        refreshActionAffinityControls();
    });
    connect(m_affinityAllCoresButton, &QPushButton::clicked, this, [this]()
    {
        if (!m_actionAffinityReadable ||
            m_actionAffinitySnapshot.processors.empty())
        {
            refreshActionAffinityControls();
            return;
        }
        ks::process::ProcessAffinityRule affinityRule;
        affinityRule.selectAllAvailable = true;
        applyActionAffinityRule(affinityRule);
    });
    connect(m_affinityPersistenceCheckBox, &QCheckBox::toggled, this, [this](const bool enabled)
    {
        if (enabled && !confirmActionAffinityRisk(true))
        {
            const QSignalBlocker signalBlocker(
                m_affinityPersistenceCheckBox);
            m_affinityPersistenceCheckBox->setChecked(false);
            return;
        }

        std::string detailText;
        const bool persistenceOk = enabled
            ? (m_actionAffinityReadable &&
                ks::process::savePersistedProcessAffinityRule(
                    m_baseRecord.imagePath,
                    ks::process::affinityRuleFromSnapshot(
                        m_actionAffinitySnapshot),
                    &detailText))
            : ks::process::removePersistedProcessAffinityRule(
                m_baseRecord.imagePath,
                &detailText);
        if (!persistenceOk)
        {
            const QSignalBlocker signalBlocker(m_affinityPersistenceCheckBox);
            m_affinityPersistenceCheckBox->setChecked(!enabled);
            kLogEvent persistenceEvent;
            warn << persistenceEvent
                << "[ProcessDetailWindow] CPU affinity persistence toggle failed, pid="
                << m_baseRecord.pid
                << ", enabled=" << (enabled ? "true" : "false")
                << ", detail=" << detailText
                << eol;
        }
        if (m_affinityStatusLabel != nullptr)
        {
            m_affinityStatusLabel->setText(
                persistenceOk
                    ? ks::i18n::text(
                        enabled
                            ? QStringLiteral("process.detail.affinity.persistence.saved")
                            : QStringLiteral("process.detail.affinity.persistence.removed"),
                        QString())
                    : ks::i18n::text(
                        QStringLiteral(
                            "process.detail.affinity.persistence.update_failed"),
                        QString()));
            m_affinityStatusLabel->setStyleSheet(buildStateLabelStyle(
                persistenceOk ? statusIdleColor() : statusWarningColor(),
                persistenceOk ? 600 : 700));
        }
    });
    QTimer::singleShot(0, this, [this]()
    {
        refreshActionAffinityControls();
    });

    // 令牌特权区域：
    // - 使用复选框表达启用/禁用状态，查询失败或令牌中不存在的项显示为灰色；
    // - R3/R0 使用独立应用按钮，便于用户明确选择通信层；
    // - 所有复选框右键都提供复制特权名称，保持详情页内容可复制。
    m_privilegeActionGroup = new QGroupBox(
        ks::i18n::text(QStringLiteral("process.detail.privileges.title"), QString()),
        actionContent);
    QVBoxLayout* privilegeGroupLayout = new QVBoxLayout(m_privilegeActionGroup);
    privilegeGroupLayout->setContentsMargins(10, 10, 10, 10);
    privilegeGroupLayout->setSpacing(8);

    QLabel* privilegeDescriptionLabel = new QLabel(
        ks::i18n::text(QStringLiteral("process.detail.privileges.description"), QString()),
        m_privilegeActionGroup);
    privilegeDescriptionLabel->setWordWrap(true);
    privilegeDescriptionLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    privilegeDescriptionLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    installCopyMenu(privilegeDescriptionLabel, [privilegeDescriptionLabel]()
    {
        return privilegeDescriptionLabel->text();
    });
    privilegeGroupLayout->addWidget(privilegeDescriptionLabel);

    QHBoxLayout* privilegeActionTopLayout = new QHBoxLayout();
    privilegeActionTopLayout->setContentsMargins(0, 0, 0, 0);
    privilegeActionTopLayout->setSpacing(8);
    m_actionPrivilegeStatusLabel = new QLabel(m_privilegeActionGroup);
    m_actionPrivilegeStatusLabel->setWordWrap(true);
    m_actionPrivilegeStatusLabel->setMinimumWidth(0);
    m_actionPrivilegeStatusLabel->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    m_actionPrivilegeStatusLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_actionPrivilegeStatusLabel->setStyleSheet(
        buildStateLabelStyle(statusSecondaryColor(), 600));
    installCopyMenu(m_actionPrivilegeStatusLabel, [this]()
    {
        return m_actionPrivilegeStatusLabel != nullptr
            ? m_actionPrivilegeStatusLabel->text()
            : QString();
    });
    m_actionPrivilegeRefreshButton = buildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.refresh"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.refresh"), QString()),
        m_privilegeActionGroup);
    m_applyActionPrivilegeR3Button = buildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r3"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r3.tooltip"), QString()),
        m_privilegeActionGroup);
    m_applyActionPrivilegeR0Button = buildTextActionButton(
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r0"), QString()),
        ks::i18n::text(QStringLiteral("process.detail.privileges.apply_r0.tooltip"), QString()),
        m_privilegeActionGroup);
    // 首次查询完成前禁用，避免在没有可比较快照时提交 R0 变化。
    m_applyActionPrivilegeR0Button->setEnabled(false);
    privilegeActionTopLayout->addWidget(m_actionPrivilegeStatusLabel, 1);
    privilegeActionTopLayout->addWidget(m_actionPrivilegeRefreshButton);
    privilegeActionTopLayout->addWidget(m_applyActionPrivilegeR3Button);
    privilegeActionTopLayout->addWidget(m_applyActionPrivilegeR0Button);
    ks::ui::NormalizeToolbarRow(privilegeActionTopLayout);
    privilegeGroupLayout->addLayout(privilegeActionTopLayout);

    QGridLayout* privilegeGridLayout = new QGridLayout();
    privilegeGridLayout->setContentsMargins(0, 0, 0, 0);
    privilegeGridLayout->setHorizontalSpacing(16);
    privilegeGridLayout->setVerticalSpacing(4);
    const std::vector<std::string>& knownPrivilegeNames =
        ks::process::KnownTokenPrivilegeNames();
    m_actionPrivilegeCheckBoxes.clear();
    m_actionPrivilegeCheckBoxes.reserve(knownPrivilegeNames.size());
    for (std::size_t privilegeIndex = 0U;
         privilegeIndex < knownPrivilegeNames.size();
         ++privilegeIndex)
    {
        QCheckBox* privilegeCheckBox = new QCheckBox(
            QString::fromLatin1(knownPrivilegeNames[privilegeIndex].c_str()),
            m_privilegeActionGroup);
        privilegeCheckBox->setEnabled(false);
        privilegeCheckBox->setToolTip(
            ks::i18n::text(QStringLiteral("process.detail.privileges.waiting"), QString()));
        privilegeCheckBox->setContextMenuPolicy(Qt::CustomContextMenu);
        connect(privilegeCheckBox, &QWidget::customContextMenuRequested,
            privilegeCheckBox, [privilegeCheckBox](const QPoint& localPosition)
        {
            QMenu copyMenu(privilegeCheckBox);
            copyMenu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* copyAction = copyMenu.addAction(
                ks::i18n::text(QStringLiteral("process.detail.action.copy"), QString()));
            if (copyMenu.exec(privilegeCheckBox->mapToGlobal(localPosition)) == copyAction)
            {
                QApplication::clipboard()->setText(privilegeCheckBox->text());
            }
        });
        m_actionPrivilegeCheckBoxes.push_back(privilegeCheckBox);
        privilegeGridLayout->addWidget(
            privilegeCheckBox,
            static_cast<int>(privilegeIndex / 3U),
            static_cast<int>(privilegeIndex % 3U));
    }
    privilegeGridLayout->setColumnStretch(3, 1);
    privilegeGroupLayout->addLayout(privilegeGridLayout);
    m_actionLayout->addWidget(m_privilegeActionGroup);

    QGroupBox* gotoGroup = new QGroupBox(QStringLiteral("转到"), actionContent);
    QGridLayout* gotoLayout = new QGridLayout(gotoGroup);
    gotoLayout->setHorizontalSpacing(8);
    gotoLayout->setVerticalSpacing(8);
    m_openHandleDockButton = buildTextActionButton(
        QStringLiteral("句柄"), QStringLiteral("打开句柄页并按当前 PID 过滤"), gotoGroup);
    m_openMemoryDockButton = buildTextActionButton(
        QStringLiteral("内存"), QStringLiteral("打开内存页并附加当前 PID"), gotoGroup);
    m_openNetworkDockButton = buildTextActionButton(
        QStringLiteral("网络"), QStringLiteral("打开连接管理页并按当前 PID 过滤"), gotoGroup);
    m_openWindowDockButton = buildTextActionButton(
        QStringLiteral("窗口"), QStringLiteral("打开窗口页并按当前 PID 过滤"), gotoGroup);
    gotoLayout->addWidget(m_openHandleDockButton, 0, 0);
    gotoLayout->addWidget(m_openMemoryDockButton, 0, 1);
    gotoLayout->addWidget(m_openNetworkDockButton, 0, 2);
    gotoLayout->addWidget(m_openWindowDockButton, 0, 3);
    gotoLayout->setColumnStretch(4, 1);
    m_actionLayout->addWidget(gotoGroup);

    // 补充操作组：
    // - 与进程列表右键菜单对齐，把详情页原先遗漏的效率模式、PPL 刷新和 R0 能力放进来；
    // - R0 按钮使用明确文字和对应业务图标，菜单弹出项在点击时动态生成。
    QGroupBox* extendedActionGroup = new QGroupBox(QStringLiteral("右键菜单同步能力"), actionContent);
    QGridLayout* extendedActionLayout = new QGridLayout(extendedActionGroup);
    extendedActionLayout->setHorizontalSpacing(8);
    extendedActionLayout->setVerticalSpacing(8);

    m_openProcessFolderButton = buildTextActionButton(
        QStringLiteral("打开目录"),
        QStringLiteral("打开当前进程所在目录"),
        extendedActionGroup);
    m_refreshPplProtectionButton = buildTextActionButton(
        QStringLiteral("刷新PPL"),
        QStringLiteral("手动刷新当前进程 PPL 保护级别"),
        extendedActionGroup);
    m_efficiencyModeCheck = new QCheckBox(QStringLiteral("效率模式"), extendedActionGroup);
    m_efficiencyModeCheck->setToolTip(
        QStringLiteral("勾上开启当前进程效率模式（绿叶），取消勾选关闭。本机或该进程不支持时勾选无效，详情页的效率模式一行会显示不可用。"));

    // buildR0MenuButton 作用：
    // - 为 R0 功能创建“明确文字 + 业务图标”的按钮；
    // - 输入 buttonText 为可见文字，iconPath 为业务图标，toolTipText 为补充说明；
    // - 返回按钮对象，调用方负责接入布局和 clicked 处理。
    const auto buildR0MenuButton =
        [](const QString& buttonText, const QString& iconPath, const QString& toolTipText, QWidget* parentWidget) -> QPushButton*
    {
        QPushButton* actionButton = new QPushButton(
            buildProcessDetailR0ActionIcon(iconPath),
            buttonText,
            parentWidget);
        actionButton->setMinimumHeight(32);
        actionButton->setMinimumWidth(92);
        actionButton->setIconSize(QSize(16, 16));
        actionButton->setToolTip(toolTipText);
        return actionButton;
    };

    m_r0TerminateProcessButton = buildR0MenuButton(
        QStringLiteral("R0结束"),
        QStringLiteral(":/Icon/process_terminate.svg"),
        QStringLiteral("通过 R0 驱动结束当前进程"),
        extendedActionGroup);
    m_r0SuspendProcessButton = buildR0MenuButton(
        QStringLiteral("R0挂起"),
        QStringLiteral(":/Icon/process_suspend.svg"),
        QStringLiteral("通过 R0 驱动挂起当前进程"),
        extendedActionGroup);
    m_r0SetPplButton = buildR0MenuButton(
        QStringLiteral("R0 保护"),
        QStringLiteral(":/Icon/process_critical.svg"),
        QStringLiteral("通过 R0 驱动设置当前进程 PPL/PP 保护层级"),
        extendedActionGroup);
    m_r0VisibilityButton = buildR0MenuButton(
        QStringLiteral("R0隐藏"),
        QStringLiteral(":/Icon/process_details.svg"),
        QStringLiteral("通过 R0 驱动隐藏/恢复当前进程"),
        extendedActionGroup);
    m_r0DangerFlagsButton = buildR0MenuButton(
        QStringLiteral("R0危险"),
        QStringLiteral(":/Icon/process_uncritical.svg"),
        QStringLiteral("R0 BreakOnTermination / APC / DKOM 高风险操作"),
        extendedActionGroup);

    extendedActionLayout->addWidget(new QLabel(QStringLiteral("辅助"), extendedActionGroup), 0, 0);
    extendedActionLayout->addWidget(m_openProcessFolderButton, 0, 1);
    extendedActionLayout->addWidget(m_refreshPplProtectionButton, 0, 2);
    extendedActionLayout->addWidget(new QLabel(QStringLiteral("效率模式"), extendedActionGroup), 1, 0);
    extendedActionLayout->addWidget(m_efficiencyModeCheck, 1, 1, 1, 2);
    extendedActionLayout->addWidget(new QLabel(QStringLiteral("R0"), extendedActionGroup), 2, 0);
    extendedActionLayout->addWidget(m_r0TerminateProcessButton, 2, 1);
    extendedActionLayout->addWidget(m_r0SuspendProcessButton, 2, 2);
    extendedActionLayout->addWidget(m_r0SetPplButton, 2, 3);
    extendedActionLayout->addWidget(m_r0VisibilityButton, 2, 4);
    extendedActionLayout->addWidget(m_r0DangerFlagsButton, 2, 5);
    extendedActionLayout->setColumnStretch(6, 1);
    m_actionLayout->addWidget(extendedActionGroup);

    // 注入与载入组：
    // - 把 DLL / Shellcode 两套操作收成统一两行；
    // - 浏览与执行按钮使用文字按钮，保证操作面板不再依赖图标表达含义。
    QGroupBox* injectGroup = new QGroupBox("注入与载入", actionContent);
    QGridLayout* injectLayout = new QGridLayout(injectGroup);
    injectLayout->setHorizontalSpacing(8);
    injectLayout->setVerticalSpacing(8);

    m_injectionModeCombo = new QComboBox(injectGroup);
    m_injectionModeCombo->addItem(QStringLiteral("R3"), 0);
    m_injectionModeCombo->addItem(
        buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_details.svg")),
        QStringLiteral("R0驱动"),
        1);
    m_injectionModeCombo->setToolTip(QStringLiteral("选择 DLL / Shellcode 注入执行方式。R0驱动模式通过 KswordARK 驱动完成远端分配、写入和建线程。"));

    m_dllPathLineEdit = new QLineEdit(injectGroup);
    m_dllPathLineEdit->setPlaceholderText("请选择要注入的 DLL 路径");
    m_browseDllButton = buildTextActionButton(
        QStringLiteral("浏览"),
        QStringLiteral("浏览并选择 DLL 文件"),
        injectGroup);
    m_injectDllButton = buildTextActionButton(
        QStringLiteral("注入"),
        QStringLiteral("执行 DLL 注入"),
        injectGroup);

    m_shellcodePathLineEdit = new QLineEdit(injectGroup);
    m_shellcodePathLineEdit->setPlaceholderText("请选择原始 shellcode 二进制文件");
    m_browseShellcodeButton = buildTextActionButton(
        QStringLiteral("浏览"),
        QStringLiteral("浏览并选择 shellcode 文件"),
        injectGroup);
    m_injectShellcodeButton = buildTextActionButton(
        QStringLiteral("执行"),
        QStringLiteral("执行 shellcode 注入"),
        injectGroup);

    injectLayout->addWidget(new QLabel("模式", injectGroup), 0, 0);
    injectLayout->addWidget(m_injectionModeCombo, 0, 1, 1, 3);
    injectLayout->addWidget(new QLabel("DLL", injectGroup), 1, 0);
    injectLayout->addWidget(m_dllPathLineEdit, 1, 1);
    injectLayout->addWidget(m_browseDllButton, 1, 2);
    injectLayout->addWidget(m_injectDllButton, 1, 3);
    injectLayout->addWidget(new QLabel("Shellcode", injectGroup), 2, 0);
    injectLayout->addWidget(m_shellcodePathLineEdit, 2, 1);
    injectLayout->addWidget(m_browseShellcodeButton, 2, 2);
    injectLayout->addWidget(m_injectShellcodeButton, 2, 3);
    m_actionLayout->addWidget(injectGroup);

    m_actionLayout->addStretch(1);

    // 统一按钮主题样式：
    // - 组合框继续使用项目蓝色描边；
    // - 紧凑按钮沿用统一蓝色按钮皮肤，避免局部控件风格割裂。
    const QString buttonStyle = buildBlueButtonStyle();
    const QString comboStyle = KswordTheme::ThemedComboBoxStyle();
    m_terminateActionCombo->setStyleSheet(comboStyle);
    m_priorityCombo->setStyleSheet(comboStyle);
    m_injectionModeCombo->setStyleSheet(comboStyle);

    const std::vector<QPushButton*> actionButtons{
        m_executeTerminateActionButton,
        m_setCriticalButton,
        m_clearCriticalButton,
        m_applyPriorityButton,
        m_affinityRefreshButton,
        m_affinityAllCoresButton,
        m_actionPrivilegeRefreshButton,
        m_applyActionPrivilegeR3Button,
        m_applyActionPrivilegeR0Button,
        m_openProcessFolderButton,
        m_refreshPplProtectionButton,
        m_r0TerminateProcessButton,
        m_r0SuspendProcessButton,
        m_r0SetPplButton,
        m_r0VisibilityButton,
        m_r0DangerFlagsButton,
        m_browseDllButton,
        m_injectDllButton,
        m_browseShellcodeButton,
        m_injectShellcodeButton
    };
    for (QPushButton* buttonItem : actionButtons)
    {
        if (buttonItem != nullptr)
        {
            buttonItem->setStyleSheet(buttonStyle);
            ks::ui::NormalizeToolbarControl(buttonItem);
        }
    }
    // 明确操作页的网格参数复用共享字段主题，不让组合框或路径输入继承透明底。
    ks::ui::StyleParameterFields(actionContent);
}

void ProcessDetailWindow::initializeModuleTab()
{
    // 模块页初始化日志：确认模块表与工具栏创建。
    kLogEvent initModuleTabEvent;
    info << initModuleTabEvent
        << "[ProcessDetailWindow] initializeModuleTab: 构建模块页面。"
        << eol;

    m_moduleLayout = new QVBoxLayout(m_moduleTab);
    m_moduleLayout->setContentsMargins(6, 6, 6, 6);
    m_moduleLayout->setSpacing(6);

    // 顶部工具栏：刷新按钮 + 签名校验选项 + 状态标签。
    m_moduleTopBarLayout = new QHBoxLayout();
    m_moduleTopBarLayout->setContentsMargins(0, 0, 0, 0);
    m_moduleTopBarLayout->setSpacing(8);
    m_refreshModuleButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新模块", m_moduleTab);
    m_dllHijackScanButton = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("DLL 劫持检测")),
        m_moduleTab);
    m_dllHijackScanButton->setToolTip(ks::i18n::sourceText(
        QStringLiteral("只读比较程序目录 DLL 与架构匹配、签名可信的系统 DLL；不会加载待检 DLL")));
    // 快速与深度拆成两个按钮：模式差别只有"比对多大范围"，用隐藏的修饰键表达
    // 等于要求用户先知道有这回事。
    m_injectionTraceButton = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("快速注入检查")),
        m_moduleTab);
    // 注意：字面量必须写成一行。i18n 审计把相邻字符串拼接的**每一段**都当成独立
    // 待翻译文本，拆行会凭空多出一堆半句词条。
    m_injectionTraceButton->setToolTip(ks::i18n::sourceText(
        QStringLiteral("只读检查：有没有来路不明的可执行内存、模块清单对不对得上、线程从哪里开始跑。只比对当前正在使用的代码页，一般几秒出结果。不挂起进程、不改内存权限。结果只说明看到了什么，不会给出“已注入/未注入”的判定。")));
    m_injectionTraceDeepButton = new QPushButton(
        QIcon(":/Icon/process_details.svg"),
        ks::i18n::sourceText(QStringLiteral("深度注入检查")),
        m_moduleTab);
    m_injectionTraceDeepButton->setToolTip(ks::i18n::sourceText(
        QStringLiteral("和快速检查用的是同一套判据，区别只在比对范围：深度会把每个模块的可执行代码整段与磁盘上的原文件比一遍，因此能查出“暂时没在运行、但已经被改过”的代码，代价是最长可能跑上一两分钟。同样是只读检查。")));
    m_signatureCheckBox = new QCheckBox("刷新时校验签名", m_moduleTab);
    m_signatureCheckBox->setChecked(true);
    m_signatureCheckBox->setStyleSheet(QStringLiteral(
        "QCheckBox { color:%1; font-weight:600; }")
        .arg(KswordTheme::TextPrimaryHex()));
    m_moduleStatusLabel = new QLabel("● 等待首次刷新", m_moduleTab);
    m_moduleStatusLabel->setWordWrap(true);
    m_moduleStatusLabel->setMinimumWidth(0);
    m_moduleStatusLabel->setToolTip(m_moduleStatusLabel->text());
    m_moduleStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    m_moduleTopBarLayout->addWidget(m_refreshModuleButton);
    m_moduleTopBarLayout->addWidget(m_dllHijackScanButton);
    m_moduleTopBarLayout->addWidget(m_injectionTraceButton);
    m_moduleTopBarLayout->addWidget(m_injectionTraceDeepButton);
    auto* moduleAreaButton = new QPushButton(ks::i18n::sourceText(QStringLiteral("矩形面积视图")), m_moduleTab);
    ks::i18n::LanguageManager::instance().bindText(moduleAreaButton,
        QStringLiteral("process.modules.metric_area.open"), QStringLiteral("矩形面积视图"));
    connect(moduleAreaButton, &QPushButton::clicked, this, &ProcessDetailWindow::openModuleAreaWindow);
    m_moduleTopBarLayout->addWidget(m_signatureCheckBox);
    m_moduleFilterEdit = new QLineEdit(m_moduleTab);
    // 模块树专用文本过滤，颜色绑定不改变原来的过滤信号和尺寸。
    ks::ui::StyleSearchField(m_moduleFilterEdit);
    m_moduleFilterEdit->setClearButtonEnabled(true);
    m_moduleFilterEdit->setPlaceholderText(ks::i18n::sourceText(
        QStringLiteral("按模块路径过滤关键字")));
    m_moduleFilterEdit->setToolTip(ks::i18n::sourceText(
        QStringLiteral("按模块路径过滤关键字")));
    m_moduleFilterEdit->setMinimumWidth(220);
    m_moduleTopBarLayout->addStretch(1);
    ks::ui::NormalizeToolbarRow(m_moduleTopBarLayout);
    m_moduleLayout->addLayout(m_moduleTopBarLayout);
    auto* moduleViewTools = new ks::ui::FlowLayout(nullptr, 0, 8, 8);
    moduleViewTools->addWidget(moduleAreaButton);
    moduleViewTools->addExpandingWidget(m_moduleFilterEdit, 220);
    ks::ui::NormalizeToolbarControl(moduleAreaButton);
    ks::ui::NormalizeToolbarControl(m_moduleFilterEdit);
    m_moduleLayout->addLayout(moduleViewTools);
    m_moduleLayout->addWidget(m_moduleStatusLabel);

    // 模块列表表格。
    QVector<ks::ui::ImmutableTableHeader> moduleHeaders;
    for (const auto& header : ModuleHeaders) moduleHeaders.push_back(ks::ui::ImmutableTableHeader(header));
    m_moduleTable = new ks::ui::ImmutableValueTable(m_moduleTab, std::move(moduleHeaders));
    // Use the committed visible model, including asynchronous filtering/sorting.
    connect(m_moduleTable->model(), &QAbstractItemModel::modelReset, this,
        &ProcessDetailWindow::refreshModuleAreaWindow, Qt::QueuedConnection);
    connect(m_moduleTable->model(), &QAbstractItemModel::layoutChanged, this,
        &ProcessDetailWindow::refreshModuleAreaWindow, Qt::QueuedConnection);
    ks::ui::SetTableActionBarMode(m_moduleTable, ks::ui::TableActionBarMode::Compact);
    m_moduleTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_moduleTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_moduleTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_moduleTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_moduleTable->sortByColumn(toModuleColumnIndex(ModuleColumn::Path), Qt::AscendingOrder);
    m_moduleTable->setAlternatingRowColors(true);
    m_moduleLayout->addWidget(m_moduleTable, 1);

    // 列宽初始化。
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::Path), 560);
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::Size), 110);
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::Signature), 260);
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::EntryOffset), 120);
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::State), 90);
    m_moduleTable->setColumnWidth(toModuleColumnIndex(ModuleColumn::ThreadId), 180);

    // 表头蓝色主题。

    m_refreshModuleButton->setStyleSheet(buildBlueButtonStyle());
    m_dllHijackScanButton->setStyleSheet(buildBlueButtonStyle());
    m_injectionTraceButton->setStyleSheet(buildBlueButtonStyle());
    m_injectionTraceDeepButton->setStyleSheet(buildBlueButtonStyle());
}

void ProcessDetailWindow::initializeTokenTab()
{
    // 令牌页初始化：专门展示 SID/特权/完整性级别等信息。
    kLogEvent initTokenTabEvent;
    info << initTokenTabEvent
        << "[ProcessDetailWindow] initializeTokenTab: 构建令牌信息页面。"
        << eol;

    m_tokenLayout = new QVBoxLayout(m_tokenTab);
    m_tokenLayout->setContentsMargins(6, 6, 6, 6);
    m_tokenLayout->setSpacing(6);

    QHBoxLayout* tokenTopBarLayout = new QHBoxLayout();
    m_refreshTokenButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新令牌", m_tokenTab);
    m_refreshTokenButton->setToolTip("异步刷新用户 SID、组、特权、完整性级别等令牌信息");
    m_tokenStatusLabel = new QLabel("● 尚未刷新", m_tokenTab);
    m_tokenStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    tokenTopBarLayout->addWidget(m_refreshTokenButton);
    tokenTopBarLayout->addWidget(m_tokenStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(tokenTopBarLayout);
    m_tokenLayout->addLayout(tokenTopBarLayout);

    m_tokenDetailOutput = new ks::ui::StructuredFieldView(m_tokenTab);
    m_tokenDetailOutput->setDocument(fieldNotice(QStringLiteral("令牌详细信息将在此处显示。")));
    m_tokenLayout->addWidget(m_tokenDetailOutput, 1);

    const QString buttonStyle = buildBlueButtonStyle();
    m_refreshTokenButton->setStyleSheet(buttonStyle);
}

void ProcessDetailWindow::initializeKernelObjectTab()
{
    // Process Detail Evidence 页初始化：
    // - 展示 Phase-2 进程扩展信息；
    // - 不执行句柄表/Section 枚举，避免 DynData 缺失时误触后续高风险路径。
    kLogEvent initKernelObjectTabEvent;
    info << initKernelObjectTabEvent
        << "[ProcessDetailWindow] initializeKernelObjectTab: 构建 Process Detail Evidence 页面。"
        << eol;

    // 事实概览、专业监视与复杂报告分工明确；报告视口不再嵌入整页滚动形成双重滚动。
    auto* evidenceRoot = new QVBoxLayout(m_kernelObjectTab);
    evidenceRoot->setContentsMargins(0, 0, 0, 0); // 唯一四边留白由内部导航共享外壳接管。
    auto* evidenceTabs = new QTabWidget(m_kernelObjectTab);
    evidenceTabs->setObjectName(QStringLiteral("ksword_process_evidence_tabs"));
    evidenceTabs->setProperty("ksword_detail_nested_tabs", true);
    evidenceTabs->setMinimumSize(0, 0);
    evidenceTabs->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    ks::ui::StyleChildPageTabs(evidenceTabs); // 详情自身导航之下的子级采用共享紧凑导航层级。
    ks::ui::StylePageTabsContentFrame(evidenceTabs, 6);
    evidenceRoot->addWidget(evidenceTabs, 1);
    auto* overviewPage = new QWidget(evidenceTabs); // 原有运行状态和字段来源，继续独立自然滚动。
    auto* watchPage = new QWidget(evidenceTabs); // 原 HVM 监视动作与依赖状态，不改变业务调用。
    auto* reportPage = new QWidget(evidenceTabs); // 固定工具行和唯一树正文视口。
    evidenceTabs->addTab(overviewPage, QStringLiteral("概览"));
    evidenceTabs->addTab(watchPage, QStringLiteral("字段监视"));
    evidenceTabs->addTab(reportPage, QStringLiteral("结构报告"));
    evidenceTabs->setCurrentWidget(reportPage); // 当前入口主要用于查字段，直接进入正文，概览和专业监视仍可切换。
    if (auto* stack = evidenceTabs->findChild<QStackedWidget*>(QString(), Qt::FindDirectChildrenOnly))
    {
        stack->setMinimumSize(0, 0);
        stack->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
    }
    auto* watchLayout = new QVBoxLayout(watchPage);
    watchLayout->setContentsMargins(0, 0, 0, 0);
    auto* reportLayout = new QVBoxLayout(reportPage);
    reportLayout->setContentsMargins(0, 0, 0, 0);
    reportLayout->setSpacing(8);
    QWidget* const kernelObjectContent = createScrollableTabContent(
        overviewPage,
        m_kernelObjectLayout,
        0,
        8);

    QGroupBox* summaryGroup = new QGroupBox(QStringLiteral("R0 扩展摘要"), kernelObjectContent);
    QFormLayout* summaryFormLayout = new QFormLayout(summaryGroup);
    summaryFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    summaryFormLayout->setHorizontalSpacing(18);
    summaryFormLayout->setVerticalSpacing(6);

    m_kernelObjectR0StatusValue = new QLabel(summaryGroup);
    m_kernelObjectCapabilityValue = new QLabel(summaryGroup);
    m_kernelObjectImagePathValue = new QLabel(summaryGroup);
    m_kernelObjectR0StatusValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectCapabilityValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectImagePathValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectImagePathValue->setWordWrap(true);

    summaryFormLayout->addRow(QStringLiteral("R0 状态"), m_kernelObjectR0StatusValue);
    summaryFormLayout->addRow(QStringLiteral("DynData Capability"), m_kernelObjectCapabilityValue);
    summaryFormLayout->addRow(QStringLiteral("R0 镜像路径"), m_kernelObjectImagePathValue);
    m_kernelObjectLayout->addWidget(summaryGroup);

    QGroupBox* objectGroup = new QGroupBox(QStringLiteral("对象字段可用性"), kernelObjectContent);
    QFormLayout* objectFormLayout = new QFormLayout(objectGroup);
    objectFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    objectFormLayout->setHorizontalSpacing(18);
    objectFormLayout->setVerticalSpacing(6);

    m_kernelObjectHandleTableValue = new QLabel(objectGroup);
    m_kernelObjectSectionObjectValue = new QLabel(objectGroup);
    m_kernelObjectHandleTableValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectSectionObjectValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    objectFormLayout->addRow(QStringLiteral("HandleTable"), m_kernelObjectHandleTableValue);
    objectFormLayout->addRow(QStringLiteral("SectionObject"), m_kernelObjectSectionObjectValue);
    m_kernelObjectLayout->addWidget(objectGroup);

    QGroupBox* protectionGroup = new QGroupBox(QStringLiteral("保护与签名字段"), kernelObjectContent);
    QFormLayout* protectionFormLayout = new QFormLayout(protectionGroup);
    protectionFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    protectionFormLayout->setHorizontalSpacing(18);
    protectionFormLayout->setVerticalSpacing(6);

    m_kernelObjectProtectionValue = new QLabel(protectionGroup);
    m_kernelObjectSignatureValue = new QLabel(protectionGroup);
    m_kernelObjectSectionSignatureValue = new QLabel(protectionGroup);
    m_kernelObjectProtectionValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectSignatureValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    m_kernelObjectSectionSignatureValue->setTextInteractionFlags(Qt::TextSelectableByMouse);
    protectionFormLayout->addRow(QStringLiteral("EPROCESS.Protection"), m_kernelObjectProtectionValue);
    protectionFormLayout->addRow(QStringLiteral("SignatureLevel"), m_kernelObjectSignatureValue);
    protectionFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), m_kernelObjectSectionSignatureValue);
    m_kernelObjectLayout->addWidget(protectionGroup);

    QGroupBox* sourceGroup = new QGroupBox(QStringLiteral("字段来源"), kernelObjectContent);
    QFormLayout* sourceFormLayout = new QFormLayout(sourceGroup);
    sourceFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    sourceFormLayout->setHorizontalSpacing(18);
    sourceFormLayout->setVerticalSpacing(6);

    m_kernelObjectSessionSourceValue = new QLabel(sourceGroup);
    m_kernelObjectImagePathSourceValue = new QLabel(sourceGroup);
    m_kernelObjectProtectionSourceValue = new QLabel(sourceGroup);
    m_kernelObjectSignatureSourceValue = new QLabel(sourceGroup);
    m_kernelObjectSectionSignatureSourceValue = new QLabel(sourceGroup);
    m_kernelObjectObjectTableSourceValue = new QLabel(sourceGroup);
    m_kernelObjectSectionObjectSourceValue = new QLabel(sourceGroup);
    sourceFormLayout->addRow(QStringLiteral("Session"), m_kernelObjectSessionSourceValue);
    sourceFormLayout->addRow(QStringLiteral("ImagePath"), m_kernelObjectImagePathSourceValue);
    sourceFormLayout->addRow(QStringLiteral("Protection"), m_kernelObjectProtectionSourceValue);
    sourceFormLayout->addRow(QStringLiteral("SignatureLevel"), m_kernelObjectSignatureSourceValue);
    sourceFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), m_kernelObjectSectionSignatureSourceValue);
    sourceFormLayout->addRow(QStringLiteral("ObjectTable"), m_kernelObjectObjectTableSourceValue);
    sourceFormLayout->addRow(QStringLiteral("SectionObject"), m_kernelObjectSectionObjectSourceValue);
    m_kernelObjectLayout->addWidget(sourceGroup);

    QGroupBox* offsetGroup = new QGroupBox(QStringLiteral("EPROCESS 偏移"), kernelObjectContent);
    QFormLayout* offsetFormLayout = new QFormLayout(offsetGroup);
    offsetFormLayout->setLabelAlignment(Qt::AlignRight | Qt::AlignVCenter);
    offsetFormLayout->setHorizontalSpacing(18);
    offsetFormLayout->setVerticalSpacing(6);

    m_kernelObjectProtectionOffsetValue = new QLabel(offsetGroup);
    m_kernelObjectSignatureOffsetValue = new QLabel(offsetGroup);
    m_kernelObjectSectionSignatureOffsetValue = new QLabel(offsetGroup);
    m_kernelObjectObjectTableOffsetValue = new QLabel(offsetGroup);
    m_kernelObjectSectionObjectOffsetValue = new QLabel(offsetGroup);
    offsetFormLayout->addRow(QStringLiteral("Protection"), m_kernelObjectProtectionOffsetValue);
    offsetFormLayout->addRow(QStringLiteral("SignatureLevel"), m_kernelObjectSignatureOffsetValue);
    offsetFormLayout->addRow(QStringLiteral("SectionSignatureLevel"), m_kernelObjectSectionSignatureOffsetValue);
    offsetFormLayout->addRow(QStringLiteral("ObjectTable"), m_kernelObjectObjectTableOffsetValue);
    offsetFormLayout->addRow(QStringLiteral("SectionObject"), m_kernelObjectSectionObjectOffsetValue);
    m_kernelObjectLayout->addWidget(offsetGroup);

    /*
     * HVM 内存监视入口。
     *
     * 这一页上面那几组回答的是「现在长什么样」，这一组回答的是「下一次是谁
     * 动的」。四个按钮对应四个不同的问题，不是同一件事的四个粒度：
     *
     *   ActiveProcessLinks  谁把这个进程从活动链表里摘了（进程隐藏）
     *   Token 槽位          谁把这个进程的令牌整个换掉了（token stealing）
     *   保护与签名          谁改了 PPL 保护级别
     *   进程名              谁改了 ImageFileName
     *
     * 地址一律是 EPROCESS 基址加上**驱动回报的**字段偏移。这与在 R3 写死
     * 0x4B8 之类的常数不是同一回事：偏移由 DynData 在 R0 解析并随响应带回，
     * 用户态只负责相加；偏移问不出来时是一个明确的哨兵值，按钮会禁用并说明
     * 原因，而不是拿一个缺省值去算出一个看起来合法的地址。
     *
     * 每次点击都重新问一次 R0，而不是复用「刷新 Section」那一次的结果：
     * 进程可能已经退出，EPROCESS 可能已经被回收，用旧地址装监视会盯到一页
     * 已经属于别人的内存上。
     */
    QGroupBox* const watchGroup =
        new QGroupBox(QStringLiteral("HVM 内存监视（下一次是谁动的）"), kernelObjectContent);
    QVBoxLayout* const watchGroupLayout = new QVBoxLayout(watchGroup);
    watchGroupLayout->setContentsMargins(8, 8, 8, 8);
    watchGroupLayout->setSpacing(6);

    QLabel* const watchHint = new QLabel(
        QStringLiteral("对 EPROCESS 的单个字段建立首次访问监视：命中时记下访问者的 RIP、模块与地址空间，原访问照常完成，常驻不会退出。硬件实际监视的是该字段所在的整个 4 KiB 页——EPROCESS 是池分配的大结构，会横跨多页，所以每个字段都按它自己的地址单独装，不存在“监视整个 EPROCESS”这回事。"),
        watchGroup);
    watchHint->setWordWrap(true);
    watchGroupLayout->addWidget(watchHint);

    QGridLayout* const watchButtons = new QGridLayout();
    m_watchActiveProcessLinksButton = new QPushButton(
        QStringLiteral("监视 ActiveProcessLinks"), watchGroup);
    m_watchActiveProcessLinksButton->setToolTip(
        QStringLiteral("谁把这个进程从活动进程链表里摘出去——进程隐藏最直接的那一步。监视的是这个进程自己的 LIST_ENTRY（两个指针，16 字节）。"));
    m_watchTokenSlotButton = new QPushButton(
        QStringLiteral("监视 Token 槽位"), watchGroup);
    m_watchTokenSlotButton->setToolTip(
        QStringLiteral("谁把这个进程的令牌整个换掉了（token stealing）。盯的是 EPROCESS 里那个 EX_FAST_REF 槽位本身，不是它指向的令牌对象——换令牌改的正是这 8 字节。"));
    m_watchTokenObjectButton = new QPushButton(
        QStringLiteral("监视令牌对象所在页"), watchGroup);
    m_watchTokenObjectButton->setToolTip(
        QStringLiteral("谁改了这个令牌自身的内容（特权位、完整性级别）。注意令牌对象可以被多个进程共享引用，所以这一页上的命中不一定来自本进程；要问“本进程的令牌被换了吗”，用上面那个槽位监视。"));
    m_watchProtectionButton = new QPushButton(
        QStringLiteral("监视保护与签名级别"), watchGroup);
    m_watchProtectionButton->setToolTip(
        QStringLiteral("谁改了 PPL 保护级别。三个字节（SignatureLevel / SectionSignatureLevel / Protection）在所有已知 profile 上都相邻，这里按驱动回报的三个偏移取最小值起头、覆盖到最大值，不写死顺序也不写死长度。"));
    m_watchImageNameButton = new QPushButton(
        QStringLiteral("监视进程名"), watchGroup);
    m_watchImageNameButton->setToolTip(
        QStringLiteral("谁改了 EPROCESS 里那个短进程名。它常被用来让进程在只看这个字段的工具里改头换面。"));
    m_watchProcessPteButton = new QPushButton(
        QStringLiteral("监视 EPROCESS 所在页的页表项"), watchGroup);
    m_watchProcessPteButton->setToolTip(
        QStringLiteral("谁改了 EPROCESS 基址那一页的映射。盯的不是结构本身，而是指向它的那一项 PTE——整页被重映射时结构内容一个字节都不用改。"));
    watchButtons->addWidget(m_watchActiveProcessLinksButton, 0, 0);
    watchButtons->addWidget(m_watchTokenSlotButton, 0, 1);
    watchButtons->addWidget(m_watchTokenObjectButton, 0, 2);
    watchButtons->addWidget(m_watchProtectionButton, 1, 0);
    watchButtons->addWidget(m_watchImageNameButton, 1, 1);
    watchButtons->addWidget(m_watchProcessPteButton, 1, 2);
    // 网格动作采用同一按钮尺寸与间距，说明和证据内容保持自然高度。
    watchButtons->setHorizontalSpacing(8);
    watchButtons->setVerticalSpacing(8);
    for (QPushButton* button : {m_watchActiveProcessLinksButton, m_watchTokenSlotButton,
        m_watchTokenObjectButton, m_watchProtectionButton, m_watchImageNameButton, m_watchProcessPteButton})
    {
        ks::ui::NormalizeToolbarControl(button);
    }
    watchGroupLayout->addLayout(watchButtons);

    m_watchStatusLabel = new QLabel(QString(), watchGroup);
    m_watchStatusLabel->setWordWrap(true);
    watchGroupLayout->addWidget(m_watchStatusLabel);
    watchLayout->addWidget(watchGroup);
    watchLayout->addStretch(1);

    // 六个按钮共用一条路径，只有"取哪个字段"不同。
    connect(m_watchActiveProcessLinksButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::ActiveProcessLinks); });
    connect(m_watchTokenSlotButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::TokenSlot); });
    connect(m_watchTokenObjectButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::TokenObject); });
    connect(m_watchProtectionButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::Protection); });
    connect(m_watchImageNameButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::ImageFileName); });
    connect(m_watchProcessPteButton, &QPushButton::clicked, this,
        [this]() { startKernelFieldWatch(KernelFieldWatchTarget::ProcessObjectPte); });

    // 报告标题与动作固定；内部的分区卡片由共享报告绘制，不再额外套一层 GroupBox。
    auto* sectionGroup = new QWidget(reportPage);
    QVBoxLayout* sectionGroupLayout = new QVBoxLayout(sectionGroup);
    sectionGroupLayout->setContentsMargins(0, 0, 0, 0);
    sectionGroupLayout->setSpacing(8);

    auto* reportTools = new QWidget(sectionGroup);
    QHBoxLayout* sectionTopBarLayout = new QHBoxLayout(reportTools);
    sectionTopBarLayout->setContentsMargins(0, 0, 0, 0);
    m_refreshSectionInfoButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), reportTools);
    KswordTheme::ApplyCompactIconButtonMetrics(m_refreshSectionInfoButton);
    m_refreshSectionInfoButton->setToolTip(QStringLiteral("通过 R0 查询当前进程 SectionObject、ControlArea 和映射摘要"));
    m_sectionInfoStatusLabel = new QLabel(QStringLiteral("● 尚未刷新"), reportTools);
    m_sectionInfoStatusLabel->setMaximumWidth(140);
    m_sectionInfoStatusLabel->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Preferred);
    m_sectionInfoStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    sectionTopBarLayout->addWidget(m_refreshSectionInfoButton);
    sectionTopBarLayout->addWidget(m_sectionInfoStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(sectionTopBarLayout);

    m_sectionInfoOutput = new ks::ui::StructuredFieldView(sectionGroup);
    m_sectionInfoOutput->setProperty("ksword_complex_report_source", true);
    m_sectionInfoOutput->setDocument(fieldNotice(QStringLiteral("Section/ControlArea 查询结果将在此处显示。")));
    sectionGroupLayout->addWidget(ks::ui::CreateDetailFieldProjection(m_sectionInfoOutput, sectionGroup, true, reportTools), 1);
    reportLayout->addWidget(sectionGroup, 1);

    m_kernelObjectLayout->addStretch(1);
}

void ProcessDetailWindow::initializeTokenSwitchTab()
{
    // 令牌设置页初始化：
    // - 第一部分提供常用开关复选框（快速设置）；
    // - 第二部分提供原始 NtSetInformationToken 入口（覆盖全部信息类）。
    kLogEvent initTokenSwitchTabEvent;
    info << initTokenSwitchTabEvent
        << "[ProcessDetailWindow] initializeTokenSwitchTab: 构建完整令牌设置页面。"
        << eol;

    QWidget* const tokenSwitchContent = createScrollableTabContent(
        m_tokenSwitchTab,
        m_tokenSwitchLayout,
        6,
        8);

    // 顶部工具栏按钮：
    // - 刷新开关：只刷新快捷开关复选框；
    // - 应用开关：提交快捷开关；
    // - 刷新全部：触发令牌详情页“全信息类枚举”刷新。
    QHBoxLayout* tokenSwitchTopBarLayout = new QHBoxLayout();
    m_refreshTokenSwitchButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), tokenSwitchContent);
    m_refreshTokenSwitchButton->setToolTip(QStringLiteral("刷新当前进程令牌的各项开关状态"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_refreshTokenSwitchButton);
    m_applyTokenSwitchButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), tokenSwitchContent);
    m_applyTokenSwitchButton->setToolTip(QStringLiteral("把下方复选框状态写回目标进程令牌"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_applyTokenSwitchButton);
    m_refreshTokenAllInfoButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QString(), tokenSwitchContent);
    m_refreshTokenAllInfoButton->setToolTip(QStringLiteral("刷新完整令牌信息（包含全部 TokenInformationClass 枚举）"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_refreshTokenAllInfoButton);
    m_tokenSwitchStatusLabel = new QLabel(QStringLiteral("● 尚未刷新令牌开关"), tokenSwitchContent);
    m_tokenSwitchStatusLabel->setWordWrap(true);
    m_tokenSwitchStatusLabel->setMinimumWidth(0);
    m_tokenSwitchStatusLabel->setSizePolicy(
        QSizePolicy::Ignored,
        QSizePolicy::Preferred);
    m_tokenSwitchStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    tokenSwitchTopBarLayout->addWidget(m_refreshTokenSwitchButton);
    tokenSwitchTopBarLayout->addWidget(m_applyTokenSwitchButton);
    tokenSwitchTopBarLayout->addWidget(m_refreshTokenAllInfoButton);
    tokenSwitchTopBarLayout->addWidget(m_tokenSwitchStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(tokenSwitchTopBarLayout);
    m_tokenSwitchLayout->addLayout(tokenSwitchTopBarLayout);

    // 快捷开关组：
    // - 对应常见 Token 布尔位与 MandatoryPolicy 位；
    // - 适合“一眼可见 + 一键应用”的高频修改场景。
    QGroupBox* tokenSwitchGroup = new QGroupBox(QStringLiteral("Token 快捷开关"), tokenSwitchContent);
    QGridLayout* tokenSwitchGridLayout = new QGridLayout(tokenSwitchGroup);
    tokenSwitchGridLayout->setHorizontalSpacing(12);
    tokenSwitchGridLayout->setVerticalSpacing(8);

    m_tokenSandboxInertCheck = new QCheckBox(QStringLiteral("SandboxInert"), tokenSwitchGroup);
    m_tokenSandboxInertCheck->setToolTip(QStringLiteral("TokenSandBoxInert：沙箱惰性开关，常用于兼容旧进程策略"));
    m_tokenVirtualizationAllowedCheck = new QCheckBox(QStringLiteral("VirtualizationAllowed"), tokenSwitchGroup);
    m_tokenVirtualizationAllowedCheck->setToolTip(QStringLiteral("TokenVirtualizationAllowed：是否允许 UAC 虚拟化"));
    m_tokenVirtualizationEnabledCheck = new QCheckBox(QStringLiteral("VirtualizationEnabled"), tokenSwitchGroup);
    m_tokenVirtualizationEnabledCheck->setToolTip(QStringLiteral("TokenVirtualizationEnabled：是否启用 UAC 虚拟化"));
    m_tokenUiAccessCheck = new QCheckBox(QStringLiteral("UIAccess"), tokenSwitchGroup);
    m_tokenUiAccessCheck->setToolTip(QStringLiteral("TokenUIAccess：是否允许跨完整性级别访问部分 UI"));
    m_tokenMandatoryNoWriteUpCheck = new QCheckBox(QStringLiteral("MandatoryPolicy.NoWriteUp"), tokenSwitchGroup);
    m_tokenMandatoryNoWriteUpCheck->setToolTip(QStringLiteral("TokenMandatoryPolicy 位 0：禁止低完整性向高完整性写入"));
    m_tokenMandatoryNewProcessMinCheck = new QCheckBox(QStringLiteral("MandatoryPolicy.NewProcessMin"), tokenSwitchGroup);
    m_tokenMandatoryNewProcessMinCheck->setToolTip(QStringLiteral("TokenMandatoryPolicy 位 1：新进程最小化完整性策略"));

    tokenSwitchGridLayout->addWidget(m_tokenSandboxInertCheck, 0, 0);
    tokenSwitchGridLayout->addWidget(m_tokenVirtualizationAllowedCheck, 0, 1);
    tokenSwitchGridLayout->addWidget(m_tokenVirtualizationEnabledCheck, 1, 0);
    tokenSwitchGridLayout->addWidget(m_tokenUiAccessCheck, 1, 1);
    tokenSwitchGridLayout->addWidget(m_tokenMandatoryNoWriteUpCheck, 2, 0);
    tokenSwitchGridLayout->addWidget(m_tokenMandatoryNewProcessMinCheck, 2, 1);
    m_tokenSwitchLayout->addWidget(tokenSwitchGroup);

    // 常用信息类（布尔语义）组：
    // - 这些项都来自 TokenInformationClass 下拉中的高频类；
    // - 通过复选框直接读写，减少“选类 + 填值”的重复操作。
    QGroupBox* tokenCommonClassGroup =
        new QGroupBox(QStringLiteral("Token 常用信息类（布尔语义）"), tokenSwitchContent);
    QGridLayout* tokenCommonClassGridLayout = new QGridLayout(tokenCommonClassGroup);
    tokenCommonClassGridLayout->setHorizontalSpacing(12);
    tokenCommonClassGridLayout->setVerticalSpacing(8);

    m_tokenHasRestrictionsCheck =
        new QCheckBox(QStringLiteral("HasRestrictions"), tokenCommonClassGroup);
    m_tokenHasRestrictionsCheck->setToolTip(
        QStringLiteral("TokenHasRestrictions（class=21）：是否存在限制 SID / 限制策略"));
    m_tokenIsAppContainerCheck =
        new QCheckBox(QStringLiteral("IsAppContainer"), tokenCommonClassGroup);
    m_tokenIsAppContainerCheck->setToolTip(
        QStringLiteral("TokenIsAppContainer（class=29）：当前令牌是否为 AppContainer"));
    m_tokenIsRestrictedCheck =
        new QCheckBox(QStringLiteral("IsRestricted"), tokenCommonClassGroup);
    m_tokenIsRestrictedCheck->setToolTip(
        QStringLiteral("TokenIsRestricted（class=40）：当前令牌是否受限制"));
    m_tokenIsLessPrivilegedAppContainerCheck =
        new QCheckBox(QStringLiteral("IsLessPrivilegedAppContainer"), tokenCommonClassGroup);
    m_tokenIsLessPrivilegedAppContainerCheck->setToolTip(
        QStringLiteral("TokenIsLessPrivilegedAppContainer（class=46）：是否为低权限 AppContainer"));
    m_tokenIsSandboxedCheck =
        new QCheckBox(QStringLiteral("IsSandboxed"), tokenCommonClassGroup);
    m_tokenIsSandboxedCheck->setToolTip(
        QStringLiteral("TokenIsSandboxed（class=47）：当前令牌是否被沙箱化"));
    m_tokenIsAppSiloCheck =
        new QCheckBox(QStringLiteral("IsAppSilo"), tokenCommonClassGroup);
    m_tokenIsAppSiloCheck->setToolTip(
        QStringLiteral("TokenIsAppSilo（class=51）：当前令牌是否属于 AppSilo"));

    tokenCommonClassGridLayout->addWidget(m_tokenHasRestrictionsCheck, 0, 0);
    tokenCommonClassGridLayout->addWidget(m_tokenIsAppContainerCheck, 0, 1);
    tokenCommonClassGridLayout->addWidget(m_tokenIsRestrictedCheck, 1, 0);
    tokenCommonClassGridLayout->addWidget(m_tokenIsLessPrivilegedAppContainerCheck, 1, 1);
    tokenCommonClassGridLayout->addWidget(m_tokenIsSandboxedCheck, 2, 0);
    tokenCommonClassGridLayout->addWidget(m_tokenIsAppSiloCheck, 2, 1);
    m_tokenSwitchLayout->addWidget(tokenCommonClassGroup);

    // 原始设置组：
    // - 允许用户选择任意 TokenInformationClass；
    // - 负载支持 UInt32/UInt64/HexBytes，直接进入 NtSetInformationToken。
    QGroupBox* rawSetGroup = new QGroupBox(QStringLiteral("原始 NtSetInformationToken（全部信息类）"), tokenSwitchContent);
    QGridLayout* rawSetLayout = new QGridLayout(rawSetGroup);
    rawSetLayout->setHorizontalSpacing(10);
    rawSetLayout->setVerticalSpacing(8);

    m_tokenRawInfoClassCombo = new QComboBox(rawSetGroup);
    m_tokenRawInfoClassCombo->setToolTip(QStringLiteral("选择要传给 NtSetInformationToken 的 TokenInformationClass"));
    const auto tokenInfoClassNameById = [](const int classId) -> QString
    {
        switch (classId)
        {
        case 1: return QStringLiteral("TokenUser");
        case 2: return QStringLiteral("TokenGroups");
        case 3: return QStringLiteral("TokenPrivileges");
        case 4: return QStringLiteral("TokenOwner");
        case 5: return QStringLiteral("TokenPrimaryGroup");
        case 6: return QStringLiteral("TokenDefaultDacl");
        case 7: return QStringLiteral("TokenSource");
        case 8: return QStringLiteral("TokenType");
        case 9: return QStringLiteral("TokenImpersonationLevel");
        case 10: return QStringLiteral("TokenStatistics");
        case 11: return QStringLiteral("TokenRestrictedSids");
        case 12: return QStringLiteral("TokenSessionId");
        case 13: return QStringLiteral("TokenGroupsAndPrivileges");
        case 14: return QStringLiteral("TokenSessionReference");
        case 15: return QStringLiteral("TokenSandBoxInert");
        case 16: return QStringLiteral("TokenAuditPolicy");
        case 17: return QStringLiteral("TokenOrigin");
        case 18: return QStringLiteral("TokenElevationType");
        case 19: return QStringLiteral("TokenLinkedToken");
        case 20: return QStringLiteral("TokenElevation");
        case 21: return QStringLiteral("TokenHasRestrictions");
        case 22: return QStringLiteral("TokenAccessInformation");
        case 23: return QStringLiteral("TokenVirtualizationAllowed");
        case 24: return QStringLiteral("TokenVirtualizationEnabled");
        case 25: return QStringLiteral("TokenIntegrityLevel");
        case 26: return QStringLiteral("TokenUIAccess");
        case 27: return QStringLiteral("TokenMandatoryPolicy");
        case 28: return QStringLiteral("TokenLogonSid");
        case 29: return QStringLiteral("TokenIsAppContainer");
        case 30: return QStringLiteral("TokenCapabilities");
        case 31: return QStringLiteral("TokenAppContainerSid");
        case 32: return QStringLiteral("TokenAppContainerNumber");
        case 33: return QStringLiteral("TokenUserClaimAttributes");
        case 34: return QStringLiteral("TokenDeviceClaimAttributes");
        case 35: return QStringLiteral("TokenRestrictedUserClaimAttributes");
        case 36: return QStringLiteral("TokenRestrictedDeviceClaimAttributes");
        case 37: return QStringLiteral("TokenDeviceGroups");
        case 38: return QStringLiteral("TokenRestrictedDeviceGroups");
        case 39: return QStringLiteral("TokenSecurityAttributes");
        case 40: return QStringLiteral("TokenIsRestricted");
        case 41: return QStringLiteral("TokenProcessTrustLevel");
        case 42: return QStringLiteral("TokenPrivateNameSpace");
        case 43: return QStringLiteral("TokenSingletonAttributes");
        case 44: return QStringLiteral("TokenBnoIsolation");
        case 45: return QStringLiteral("TokenChildProcessFlags");
        case 46: return QStringLiteral("TokenIsLessPrivilegedAppContainer");
        case 47: return QStringLiteral("TokenIsSandboxed");
        case 48: return QStringLiteral("TokenOriginatingProcessTrustLevel");
        case 49: return QStringLiteral("TokenLoggingInformation");
        case 50: return QStringLiteral("TokenLearningMode");
        case 51: return QStringLiteral("TokenIsAppSilo");
        default: return QStringLiteral("TokenClass%1").arg(classId);
        }
    };
    for (int classId = 1; classId <= 80; ++classId)
    {
        const QString itemText = QStringLiteral("[%1] %2")
            .arg(classId)
            .arg(tokenInfoClassNameById(classId));
        m_tokenRawInfoClassCombo->addItem(itemText, classId);
    }
    m_tokenRawInfoClassCombo->setCurrentIndex(14);

    m_tokenRawInputModeCombo = new QComboBox(rawSetGroup);
    m_tokenRawInputModeCombo->setToolTip(QStringLiteral("选择原始负载解释方式"));
    m_tokenRawInputModeCombo->addItem(QStringLiteral("UInt32"), QStringLiteral("u32"));
    m_tokenRawInputModeCombo->addItem(QStringLiteral("UInt64"), QStringLiteral("u64"));
    m_tokenRawInputModeCombo->addItem(QStringLiteral("HexBytes"), QStringLiteral("hex"));

    m_tokenRawPayloadEdit = new QLineEdit(rawSetGroup);
    m_tokenRawPayloadEdit->setPlaceholderText(QStringLiteral("示例：UInt32=1；UInt64=0x10；HexBytes=01 00 00 00"));
    m_tokenRawPayloadEdit->setToolTip(QStringLiteral("原始输入内容，按当前输入模式解析后直接传给 NtSetInformationToken"));

    m_tokenRawApplyButton = new QPushButton(QIcon(":/Icon/process_start.svg"), QString(), rawSetGroup);
    m_tokenRawApplyButton->setToolTip(QStringLiteral("应用原始 NtSetInformationToken 设置"));
    KswordTheme::ApplyStandardIconButtonMetrics(m_tokenRawApplyButton);

    rawSetLayout->addWidget(new QLabel(QStringLiteral("信息类"), rawSetGroup), 0, 0);
    rawSetLayout->addWidget(m_tokenRawInfoClassCombo, 0, 1, 1, 2);
    rawSetLayout->addWidget(new QLabel(QStringLiteral("输入模式"), rawSetGroup), 1, 0);
    rawSetLayout->addWidget(m_tokenRawInputModeCombo, 1, 1, 1, 2);
    rawSetLayout->addWidget(new QLabel(QStringLiteral("原始负载"), rawSetGroup), 2, 0);
    rawSetLayout->addWidget(m_tokenRawPayloadEdit, 2, 1);
    rawSetLayout->addWidget(m_tokenRawApplyButton, 2, 2);
    m_tokenSwitchLayout->addWidget(rawSetGroup);

    QLabel* tokenSwitchHintLabel = new QLabel(
        QStringLiteral("提示：可先点“刷新全部令牌信息”查看所有 TokenInformationClass 的当前状态，再按快捷或原始模式应用。"),
        tokenSwitchContent);
    tokenSwitchHintLabel->setStyleSheet(QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    m_tokenSwitchLayout->addWidget(tokenSwitchHintLabel);
    m_tokenSwitchLayout->addStretch(1);

    // 页面样式：
    // - 图标按钮统一蓝色皮肤；
    // - 原始设置组合框使用同一套描边/高亮风格。
    const QString buttonStyle = buildBlueButtonStyle();
    m_refreshTokenSwitchButton->setStyleSheet(buttonStyle);
    m_applyTokenSwitchButton->setStyleSheet(buttonStyle);
    m_refreshTokenAllInfoButton->setStyleSheet(buttonStyle);
    m_tokenRawApplyButton->setStyleSheet(buttonStyle);
    ks::ui::NormalizeToolbarControl(m_tokenRawApplyButton);

    const QString comboStyle = KswordTheme::ThemedComboBoxStyle();
    m_tokenRawInfoClassCombo->setStyleSheet(comboStyle);
    m_tokenRawInputModeCombo->setStyleSheet(comboStyle);
    // 原始令牌参数沿用现有解析与权限校验，只统一输入和长选项的呈现。
    ks::ui::StyleParameterFields(tokenSwitchContent);
}

void ProcessDetailWindow::initializePebTab()
{
    // PEB 页初始化：展示 PEB 地址、参数块、环境变量等。
    kLogEvent initPebTabEvent;
    info << initPebTabEvent
        << "[ProcessDetailWindow] initializePebTab: 构建 PEB 信息页面。"
        << eol;

    m_pebLayout = new QVBoxLayout(m_pebTab);
    m_pebLayout->setContentsMargins(6, 6, 6, 6);
    m_pebLayout->setSpacing(6);

    // 参数、固定执行区和只读结果由共享骨架分别承载，详情兼容层不再重排内部滚动。
    auto* workspace = new ks::ui::ParameterWorkspace(m_pebTab, 500); // PEB 参数与现场结果同屏。
    workspace->useWideParameterLayout(55);
    m_pebLayout->addWidget(workspace, 1);

    m_refreshPebButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), "刷新PEB", m_pebTab);
    m_refreshPebButton->setToolTip("异步刷新 PEB、命令行、当前目录、环境块与安全标志");
    m_applyPebEditButton = new QPushButton(QIcon(":/Icon/process_settings.svg"), QStringLiteral("应用修改"), m_pebTab);
    m_applyPebEditButton->setToolTip(QStringLiteral("把可编辑字段写回目标进程。字符串字段优先写入现有缓冲区；空间不足时会尝试远程分配新缓冲区。"));
    m_pebStatusLabel = new QLabel("● 尚未刷新", m_pebTab);
    m_pebStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    m_pebStatusLabel->setWordWrap(true);
    workspace->actions()->addWidget(m_refreshPebButton);
    workspace->actions()->addWidget(m_applyPebEditButton);
    workspace->actions()->addStretch(1);
    workspace->results()->addWidget(m_pebStatusLabel);
    ks::ui::ApplyFlatButtonTheme(m_applyPebEditButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);

    // 自然高度表单允许长标签换行；窄窗口由参数正文滚动，不截掉字段或拉大行间空白。
    auto* editableGroup = new QGroupBox(QStringLiteral("PEB 可编辑字段（R3 写入目标进程内存）"), workspace);
    auto* editableForm = new QFormLayout(editableGroup); // 所有输入保留原对象和写入信号。
    ks::ui::ConfigureDetailForm(editableForm);

    m_pebTargetCombo = new QComboBox(editableGroup);
    m_pebTargetCombo->addItem(QStringLiteral("NativePEB"), QStringLiteral("NativePEB"));
    m_pebTargetCombo->addItem(QStringLiteral("Wow64PEB"), QStringLiteral("Wow64PEB"));
    m_pebTargetCombo->setToolTip(QStringLiteral("选择写入 Native PEB 还是 Wow64 PEB。32 位目标通常需要同步修改 Wow64PEB。"));

    m_pebCommandLineEdit = new QLineEdit(editableGroup);
    m_pebImagePathEdit = new QLineEdit(editableGroup);
    m_pebCurrentDirectoryEdit = new QLineEdit(editableGroup);
    m_pebEnvironmentNameEdit = new QLineEdit(editableGroup);
    m_pebEnvironmentValueEdit = new QLineEdit(editableGroup);
    m_pebImageBaseEdit = new QLineEdit(editableGroup);
    m_pebAffinityMaskEdit = new QLineEdit(editableGroup);
    m_pebPriorityClassCombo = new QComboBox(editableGroup);

    m_pebCommandLineEdit->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.CommandLine"));
    m_pebImagePathEdit->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.ImagePathName"));
    m_pebCurrentDirectoryEdit->setPlaceholderText(QStringLiteral("RTL_USER_PROCESS_PARAMETERS.CurrentDirectory.DosPath"));
    m_pebEnvironmentNameEdit->setPlaceholderText(QStringLiteral("例如 PATH / TEMP / 自定义变量名"));
    m_pebEnvironmentValueEdit->setPlaceholderText(QStringLiteral("变量值；为空表示写成 NAME=，不会删除旧环境块条目"));
    m_pebImageBaseEdit->setPlaceholderText(QStringLiteral("高级：PEB.ImageBaseAddress，例如 0x7C0000"));
    m_pebAffinityMaskEdit->setPlaceholderText(QStringLiteral("进程亲和性掩码，例如 0xFFFFFFFF"));

    m_pebImageBaseEdit->setToolTip(QStringLiteral("危险字段：只修改 PEB.ImageBaseAddress 指针，不会重映射模块。错误值可能误导目标进程或工具。"));
    m_pebAffinityMaskEdit->setToolTip(QStringLiteral("调用 SetProcessAffinityMask，属于真实进程属性，不是 PEB 字段。"));

    m_pebPriorityClassCombo->addItem(QStringLiteral("不修改"), 0u);
    m_pebPriorityClassCombo->addItem(QStringLiteral("IDLE"), static_cast<unsigned int>(IDLE_PRIORITY_CLASS));
    m_pebPriorityClassCombo->addItem(QStringLiteral("BELOW_NORMAL"), static_cast<unsigned int>(BELOW_NORMAL_PRIORITY_CLASS));
    m_pebPriorityClassCombo->addItem(QStringLiteral("NORMAL"), static_cast<unsigned int>(NORMAL_PRIORITY_CLASS));
    m_pebPriorityClassCombo->addItem(QStringLiteral("ABOVE_NORMAL"), static_cast<unsigned int>(ABOVE_NORMAL_PRIORITY_CLASS));
    m_pebPriorityClassCombo->addItem(QStringLiteral("HIGH"), static_cast<unsigned int>(HIGH_PRIORITY_CLASS));
    m_pebPriorityClassCombo->addItem(QStringLiteral("REALTIME"), static_cast<unsigned int>(REALTIME_PRIORITY_CLASS));

    editableForm->addRow(QStringLiteral("目标PEB"), m_pebTargetCombo);
    editableForm->addRow(QStringLiteral("CommandLine"), m_pebCommandLineEdit);
    editableForm->addRow(QStringLiteral("ImagePathName"), m_pebImagePathEdit);
    editableForm->addRow(QStringLiteral("CurrentDirectory"), m_pebCurrentDirectoryEdit);
    editableForm->addRow(QStringLiteral("环境变量名"), m_pebEnvironmentNameEdit);
    editableForm->addRow(QStringLiteral("环境变量值"), m_pebEnvironmentValueEdit);
    editableForm->addRow(QStringLiteral("ImageBaseAddress"), m_pebImageBaseEdit);
    editableForm->addRow(QStringLiteral("AffinityMask"), m_pebAffinityMaskEdit);
    editableForm->addRow(QStringLiteral("PriorityClass"), m_pebPriorityClassCombo);
    ks::ui::StyleParameterSection(editableGroup);
    workspace->parameters()->addWidget(editableGroup);

    // 显式投影复用规范字段文档、搜索、复制和导出，摘要独立滚动并占据结果区剩余空间。
    m_pebDetailOutput = new ks::ui::StructuredFieldView(workspace);
    m_pebDetailOutput->setDocument(fieldNotice(QStringLiteral("PEB 与地址空间摘要将在此处显示。")));
    workspace->results()->addWidget(ks::ui::CreateDetailFieldProjection(m_pebDetailOutput, workspace), 1);

    // 不可写字段的解释默认展示，纳入已有参数滚动区；不再控制已隐藏的数据源来折叠投影。
    m_pebReadonlyReasonOutput = new ks::ui::StructuredFieldView(workspace);
    ks::ui::FieldDocument readonlyFields;
    readonlyFields.section(QStringLiteral("不可直接修改/不建议直接修改"));
    readonlyFields.field(QStringLiteral("KernelCpuMs/UserCpuMs/WorkingSet/PrivateUsage/IO计数/PageFaultCount"), QStringLiteral("系统统计计数，只能由内核/调度器/内存管理器更新。"), true);
    readonlyFields.field(QStringLiteral("VirtualAddressRegionPreview"), QStringLiteral("地址空间枚举结果；应通过 VirtualAllocEx/VirtualProtectEx/Unmap/Map 等专门操作改变。"), true);
    readonlyFields.field(QStringLiteral("RegionCount/CommitBytes/MappedBytes/ImageBytes/PrivateBytes"), QStringLiteral("统计结果，不是单一字段。"), true);
    readonlyFields.field(QStringLiteral("HeapCount/HeapBlock"), QStringLiteral("需要堆管理器一致性，不在 PEB 页直接写。"), true);
    readonlyFields.field(QStringLiteral("ProcessParameters/Environment"), QStringLiteral("本页会按需更新字符串字段/环境项，不建议手工乱改指针。"), true);
    m_pebReadonlyReasonOutput->setDocument(readonlyFields);
    workspace->parameters()->addWidget(ks::ui::CreateDetailFieldProjection(
        m_pebReadonlyReasonOutput, workspace, false));
    workspace->finish(); // 共享输入底色、行高和圆角在首帧前统一接入。
}

void ProcessDetailWindow::initializeKernelCallbackTab()
{
    // PEB.KernelCallbackTable 独立审计页：
    // - 不与 PEB 大文本刷新绑定，切到本页时才读取远程内存；
    // - 表格固定支持复制单元格、当前行和全部内容。
    m_kernelCallbackLayout = new QVBoxLayout(m_kernelCallbackTab);
    m_kernelCallbackLayout->setContentsMargins(6, 6, 6, 6);
    m_kernelCallbackLayout->setSpacing(6);

    auto* topBarLayout = new QHBoxLayout();
    m_refreshKernelCallbackButton = new QPushButton(
        QIcon(":/Icon/process_refresh.svg"),
        QStringLiteral("刷新内核回调表"),
        m_kernelCallbackTab);
    m_refreshKernelCallbackButton->setToolTip(QStringLiteral(
        "异步读取 PEB.KernelCallbackTable，并核对回调地址所属模块与内存保护属性。\n"
        "读取来源为 NativePEB 或 Wow64PEB 中的用户态内核回调表。"));
    m_refreshKernelCallbackButton->setStyleSheet(buildBlueButtonStyle());
    topBarLayout->addWidget(m_refreshKernelCallbackButton);

    m_kernelCallbackFilterEdit = new QLineEdit(m_kernelCallbackTab);
    ks::ui::StyleSearchField(m_kernelCallbackFilterEdit);
    m_kernelCallbackFilterEdit->setClearButtonEnabled(true);
    m_kernelCallbackFilterEdit->setPlaceholderText(ks::i18n::sourceText(
        QStringLiteral("按索引/回调名称/地址/模块/保护属性/状态筛选")));
    m_kernelCallbackFilterEdit->setToolTip(ks::i18n::sourceText(
        QStringLiteral("按索引/回调名称/地址/模块/保护属性/状态筛选")));
    m_kernelCallbackFilterEdit->setMinimumWidth(260);
    topBarLayout->addWidget(m_kernelCallbackFilterEdit);

    m_kernelCallbackStatusLabel = new QLabel(QStringLiteral("● 尚未刷新"), m_kernelCallbackTab);
    m_kernelCallbackStatusLabel->setStyleSheet(buildStateLabelStyle(statusSecondaryColor(), 600));
    topBarLayout->addWidget(m_kernelCallbackStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(topBarLayout);
    m_kernelCallbackLayout->addLayout(topBarLayout);

    m_kernelCallbackTable = new ks::ui::VisibleTableWidget(m_kernelCallbackTab);
    // 回调地址变更需要保留现场对比，区别于只读状态字段。
    ks::ui::SetTableActionBarMode(m_kernelCallbackTable, ks::ui::TableActionBarMode::Full);
    m_kernelCallbackTable->setColumnCount(7);
    m_kernelCallbackTable->setHorizontalHeaderLabels(QStringList()
        << QStringLiteral("索引")
        << QStringLiteral("回调名称")
        << QStringLiteral("地址")
        << QStringLiteral("模块")
        << QStringLiteral("模块偏移")
        << QStringLiteral("保护属性")
        << QStringLiteral("状态"));
    if (QTableWidgetItem* const callbackStateHeaderItem = m_kernelCallbackTable->horizontalHeaderItem(6))
    {
        callbackStateHeaderItem->setToolTip(QStringLiteral(
            "非模块可执行地址、不可执行地址和读取失败项会标为异常。"));
    }
    m_kernelCallbackTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_kernelCallbackTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_kernelCallbackTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_kernelCallbackTable->setAlternatingRowColors(true);
    m_kernelCallbackTable->setSortingEnabled(true);
    m_kernelCallbackTable->setContextMenuPolicy(Qt::CustomContextMenu);
    m_kernelCallbackTable->verticalHeader()->setVisible(false);
    m_kernelCallbackTable->horizontalHeader()->setStretchLastSection(true);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(4, QHeaderView::ResizeToContents);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(5, QHeaderView::ResizeToContents);
    m_kernelCallbackTable->horizontalHeader()->setSectionResizeMode(6, QHeaderView::ResizeToContents);
    m_kernelCallbackLayout->addWidget(m_kernelCallbackTable, 1);

    connect(
        m_kernelCallbackTable,
        &QTableWidget::customContextMenuRequested,
        this,
        [this](const QPoint& localPosition)
        {
            if (m_kernelCallbackTable == nullptr)
            {
                return;
            }

            if (QTableWidgetItem* clickedItem = m_kernelCallbackTable->itemAt(localPosition))
            {
                m_kernelCallbackTable->setCurrentItem(clickedItem);
            }

            QMenu menu(m_kernelCallbackTable);
            menu.setStyleSheet(buildProcessDetailMenuStyle());
            QAction* copyCellAction = menu.addAction(QStringLiteral("复制当前单元格"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyCellAction, ks::ui::TableContextActionRole::CopyCell);
            QAction* copyRowAction = menu.addAction(QStringLiteral("复制当前行"));
            // 声明业务菜单已提供此能力，避免共享表格菜单追加重复项。
            ks::ui::SetTableContextActionRole(copyRowAction, ks::ui::TableContextActionRole::CopyRows);
            QAction* copyAllAction = menu.addAction(QStringLiteral("复制全部"));
            const int currentRow = m_kernelCallbackTable->currentRow();
            const int currentColumn = m_kernelCallbackTable->currentColumn();
            copyCellAction->setEnabled(currentRow >= 0 && currentColumn >= 0);
            copyRowAction->setEnabled(currentRow >= 0);
            copyAllAction->setEnabled(m_kernelCallbackTable->rowCount() > 0);

            QAction* selectedAction = menu.exec(m_kernelCallbackTable->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            if (selectedAction == copyCellAction)
            {
                const QTableWidgetItem* item = m_kernelCallbackTable->item(currentRow, currentColumn);
                QApplication::clipboard()->setText(item != nullptr ? item->text() : QString());
                return;
            }

            const auto rowText = [this](const int rowIndex)
            {
                QStringList values;
                for (int columnIndex = 0; columnIndex < m_kernelCallbackTable->columnCount(); ++columnIndex)
                {
                    const QTableWidgetItem* item = m_kernelCallbackTable->item(rowIndex, columnIndex);
                    values << (item != nullptr ? item->text() : QString());
                }
                return values.join('\t');
            };

            if (selectedAction == copyRowAction)
            {
                QApplication::clipboard()->setText(rowText(currentRow));
                return;
            }

            QStringList allLines;
            QStringList headers;
            for (int columnIndex = 0; columnIndex < m_kernelCallbackTable->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = m_kernelCallbackTable->horizontalHeaderItem(columnIndex);
                headers << (headerItem != nullptr ? headerItem->text() : QString());
            }
            allLines << headers.join('\t');
            for (int rowIndex = 0; rowIndex < m_kernelCallbackTable->rowCount(); ++rowIndex)
            {
                allLines << rowText(rowIndex);
            }
            QApplication::clipboard()->setText(allLines.join('\n'));
        });
}

void ProcessDetailWindow::initializeConnections()
{
    // 页面按需构造后会再次调用本函数。局部 connect 包装器按 sender 去重，
    // 既能跳过尚未创建的控件，也不会为已存在控件重复连接同一信号。
    const auto connect = [this](auto* sender, const auto signal, QObject* context, const auto& callback) {
        if (sender == nullptr || m_connectedSignalSources.contains(sender))
        {
            return;
        }
        QObject::connect(sender, signal, context, callback);
        m_connectedSignalSources.insert(sender);
    };

    // 连接初始化日志：用于确认所有已创建页面的按钮信号都已挂接。
    kLogEvent initConnectionsEvent;
    info << initConnectionsEvent
        << "[ProcessDetailWindow] initializeConnections: 开始连接信号槽。"
        << eol;

    // 复制路径按钮。
    connect(m_copyPathButton, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_pathLineEdit->text());
        kLogEvent logEvent;
        dbg << logEvent << "[ProcessDetailWindow] 复制程序路径, pid=" << m_baseRecord.pid << eol;
    });

    // 打开路径按钮。
    connect(m_openPathFolderButton, &QPushButton::clicked, this, [this]() {
        std::string detailText;
        const bool actionOk = ks::process::OpenFolderByPath(m_baseRecord.imagePath, &detailText);
        // 打开路径属于同一动作链，复用同一个 kLogEvent 传入结果函数。
        kLogEvent actionEvent;
        (actionOk ? info : err) << actionEvent
            << "[ProcessDetailWindow] 打开程序路径, pid="
            << m_baseRecord.pid
            << ", actionOk="
            << (actionOk ? "true" : "false")
            << ", detail="
            << detailText
            << eol;
        showActionResultMessage("打开程序路径", actionOk, detailText, actionEvent);
    });

    // 转到文件详情：由 ProcessDock 转发到 MainWindow::openFileDetailDockByPath，复用 FileDock 的非模态详情窗。
    connect(m_openFileDetailButton, &QPushButton::clicked, this, [this]() {
        const QString imagePath = QString::fromStdString(m_baseRecord.imagePath).trimmed();
        if (!imagePath.isEmpty() && QFileInfo(imagePath).isFile())
        {
            emit requestOpenFileDetailByPath(imagePath);
        }
    });

    connect(m_refreshDetailOverviewButton, &QPushButton::clicked, this, [this]() {
        requestAsyncDetailOverviewRefresh();
    });

    // 复制命令行按钮。
    connect(m_copyCommandButton, &QPushButton::clicked, this, [this]() {
        QApplication::clipboard()->setText(m_commandLineEdit->text());
        kLogEvent logEvent;
        dbg << logEvent << "[ProcessDetailWindow] 复制命令行, pid=" << m_baseRecord.pid << eol;
    });

    // 转到父进程按钮。
    connect(m_gotoParentButton, &QPushButton::clicked, this, [this]() {
        const QVariant parentPidVariant = m_gotoParentButton->property("parent_pid");
        if (!parentPidVariant.isValid())
        {
            return;
        }
        const std::uint32_t parentPid = parentPidVariant.toUInt();
        emit requestOpenProcessByPid(parentPid);
    });

    // 跳转句柄按钮：把当前 PID 转发给外部（MainWindow）打开句柄 Dock。
    connect(m_openHandleDockButton, &QPushButton::clicked, this, [this]() {
        if (m_baseRecord.pid == 0)
        {
            return;
        }
        emit requestOpenHandleDockByPid(m_baseRecord.pid);
    });
    connect(m_detailOpenHandleDockButton, &QPushButton::clicked, this, [this]() {
        if (m_baseRecord.pid != 0U)
        {
            emit requestOpenHandleDockByPid(m_baseRecord.pid);
        }
    });
    connect(m_openMemoryDockButton, &QPushButton::clicked, this, [this]() {
        if (m_baseRecord.pid != 0U)
        {
            emit requestOpenMemoryDockByPid(m_baseRecord.pid);
        }
    });
    connect(m_openNetworkDockButton, &QPushButton::clicked, this, [this]() {
        if (m_baseRecord.pid != 0U)
        {
            emit requestOpenNetworkDockByPid(m_baseRecord.pid);
        }
    });
    connect(m_openWindowDockButton, &QPushButton::clicked, this, [this]() {
        if (m_baseRecord.pid != 0U)
        {
            emit requestOpenWindowDockByPid(m_baseRecord.pid);
        }
    });

    // 线程细节刷新按钮。
    connect(m_refreshThreadInspectButton, &QPushButton::clicked, this, [this]() {
        requestAsyncThreadInspectRefresh();
    });

    // 令牌页刷新按钮。
    connect(m_refreshTokenButton, &QPushButton::clicked, this, [this]() {
        requestAsyncTokenRefresh();
    });

    // 令牌开关页刷新按钮：回读当前 token 开关值并同步复选框。
    connect(m_refreshTokenSwitchButton, &QPushButton::clicked, this, [this]() {
        refreshTokenSwitchStates();
    });

    // 令牌开关页应用按钮：把复选框状态写回目标 token。
    connect(m_applyTokenSwitchButton, &QPushButton::clicked, this, [this]() {
        applyTokenSwitchStates();
    });

    // 令牌设置页“刷新全部信息”按钮：触发令牌详情全量刷新（含全部信息类枚举）。
    connect(m_refreshTokenAllInfoButton, &QPushButton::clicked, this, [this]() {
        requestAsyncTokenRefresh();
    });

    // 令牌设置页“原始应用”按钮：按当前 class + payload 直接调用 NtSetInformationToken。
    connect(m_tokenRawApplyButton, &QPushButton::clicked, this, [this]() {
        applyRawTokenInformation();
    });

    // PEB 页刷新按钮。
    connect(m_refreshPebButton, &QPushButton::clicked, this, [this]() {
        requestAsyncPebRefresh();
    });
    connect(m_applyPebEditButton, &QPushButton::clicked, this, [this]() {
        applyPebEditableFields();
    });
    connect(m_refreshKernelCallbackButton, &QPushButton::clicked, this, [this]() {
        requestAsyncKernelCallbackRefresh();
    });
    connect(m_kernelCallbackFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        filterKernelCallbackTable(filterText);
    });
    // 内核回调页是懒加载的；首次连接阶段表格尚未创建，等页面初始化后再连接。
    if (m_kernelCallbackTable != nullptr && m_kernelCallbackTable->horizontalHeader() != nullptr)
    {
        connect(
            m_kernelCallbackTable->horizontalHeader(),
            &QHeaderView::sortIndicatorChanged,
            this,
            [this](int, Qt::SortOrder) {
                filterKernelCallbackTable(
                    m_kernelCallbackFilterEdit != nullptr ? m_kernelCallbackFilterEdit->text() : QString());
            });
    }
    connect(m_pebTargetCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) {
        if (m_pebDetailOutput != nullptr)
        {
            populatePebEditableFieldsFromSnapshot();
        }
    });

    // Section/ControlArea 刷新按钮：只传 PID 给 ArkDriverClient，避免 UI 回传内核地址。
    connect(m_refreshSectionInfoButton, &QPushButton::clicked, this, [this]() {
        requestAsyncSectionRefresh();
    });

    // 进程热键页刷新按钮。
    connect(m_refreshHotkeyButton, &QPushButton::clicked, this, [this]() {
        requestAsyncHotkeyRefresh();
    });

    // 键盘页刷新按钮：热键与键盘钩子一起刷新。
    connect(m_refreshKeyboardButton, &QPushButton::clicked, this, [this]() {
        requestAsyncKeyboardRefresh();
    });

    // 导航区负责选择页，QTabWidget 继续作为唯一的页面状态来源。
    // 这样外部调用 setCurrentWidget 的入口和键盘页等内部跳转均可同步更新按钮状态。
    connect(m_tabNavigationButtonGroup, &QButtonGroup::idClicked, this, [this](const int tabIndex) {
        if (m_tabWidget != nullptr && tabIndex >= 0 && tabIndex < m_tabWidget->count())
        {
            m_tabWidget->setCurrentIndex(tabIndex);
        }
    });

    // Tab 首次切换时再启动对应重型刷新，并回写左侧导航区的选中态：
    // - 进程详情窗口打开路径只构建 UI 和轻量文本；
    // - 这样用户能立即看到窗口，后台扫描不会同时挤占线程池与 UI 回填。
    connect(m_tabWidget, &QTabWidget::currentChanged, this, [this](const int tabIndex) {
        const QPointer<ProcessDetailWindow> lifetime(this); // 统一准备允许主题回调关闭详情窗。
        const QPointer<QTabWidget> requestedTabs(m_tabWidget); // 保留本次切页的真实导航宿主。
        const QPointer<QWidget> requestedTab(requestedTabs != nullptr ? requestedTabs->widget(tabIndex) : nullptr);
        if (requestedTabs != nullptr)
        {
            ensureTabContentInitialized(requestedTab.data());
        }
        if (lifetime == nullptr || requestedTabs == nullptr || requestedTab == nullptr
            || requestedTabs.data() != m_tabWidget || requestedTabs->currentWidget() != requestedTab.data())
        {
            return; // 析构或回调换页后不能再操作旧导航，也不能启动旧页首刷。
        }
        if (m_tabNavigationButtonGroup != nullptr)
        {
            if (QAbstractButton* navigationButton = m_tabNavigationButtonGroup->button(tabIndex))
            {
                navigationButton->setChecked(true);
            }
        }
        requestInitialRefreshForCurrentTab();
    });

    // 操作页按钮连接：
    // - 结束方案统一走下拉框调度，避免保留多个重复大按钮；
    // - 其余控制动作保持原有执行函数不变。
    connect(m_executeTerminateActionButton, &QPushButton::clicked, this, [this]() { executeSelectedTerminateAction(); });
    // 用 clicked 而不是 toggled：toggled 连 setChecked 的程序化改动也会发出，
    // 而刷新时每次都要按最新读数 setChecked 一次——那样会在刷新里反复触发挂起
    // 与恢复。clicked 只在用户点击时发出。
    connect(m_suspendProcessCheck, &QCheckBox::clicked, this, [this](const bool checked) {
        if (checked) { executeSuspendProcessAction(); }
        else { executeResumeProcessAction(); }
    });
    connect(m_setCriticalButton, &QPushButton::clicked, this, [this]() { executeSetCriticalAction(true); });
    connect(m_clearCriticalButton, &QPushButton::clicked, this, [this]() { executeSetCriticalAction(false); });
    connect(m_applyPriorityButton, &QPushButton::clicked, this, [this]() { executeSetPriorityAction(); });
    connect(m_actionPrivilegeRefreshButton, &QPushButton::clicked, this, [this]() { requestAsyncActionPrivilegeRefresh(); });
    connect(m_applyActionPrivilegeR3Button, &QPushButton::clicked, this, [this]() { executeApplyActionPrivileges(false); });
    connect(m_applyActionPrivilegeR0Button, &QPushButton::clicked, this, [this]() { executeApplyActionPrivileges(true); });
    connect(m_openProcessFolderButton, &QPushButton::clicked, this, [this]() { executeOpenProcessFolderAction(); });
    connect(m_refreshPplProtectionButton, &QPushButton::clicked, this, [this]() { executeRefreshPplProtectionLevelAction(); });
    connect(m_efficiencyModeCheck, &QCheckBox::clicked, this, [this](const bool checked) {
        executeSetEfficiencyModeAction(checked);
    });
    connect(m_r0TerminateProcessButton, &QPushButton::clicked, this, [this]() { executeR0TerminateProcessAction(); });
    connect(m_r0SuspendProcessButton, &QPushButton::clicked, this, [this]() { executeR0SuspendProcessAction(); });

    // R0 PPL 菜单：
    // - 菜单内容与进程列表右键菜单保持一致；
    // - 每次点击按钮时动态创建局部 QMenu，避免窗口生命周期内持有陈旧 QAction。
    connect(m_r0SetPplButton, &QPushButton::clicked, this, [this]() {
        QMenu r0PplMenu(this);
        r0PplMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* noneAction = r0PplMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("关闭进程保护 (0x00)"));
        noneAction->setData(0x00U);

        // 与进程列表右键菜单同构：signer 列表共用，PPL(Type=1) 与 PP(Type=2) 分两组展示。
        struct ProcessProtectionSignerPreset
        {
            int signerValue = 0;           // signerValue：Signer 数值。
            const char* signerName = "";   // signerName：菜单展示名称。
            const char* meaningText = "";  // meaningText：菜单展示释义。
        };
        const ProcessProtectionSignerPreset presetList[] =
        {
            { 1, "Authenticode", "签名代码（Authenticode）" },
            { 2, "CodeGen", "动态代码生成" },
            { 3, "Antimalware", "反恶意软件" },
            { 4, "Lsa", "本地安全机构" },
            { 5, "Windows", "Windows 组件" },
            { 6, "WinTcb", "可信计算基础（最高）" },
            { 7, "WinSystem", "系统 signer（System 进程同级）" }
        };
        struct ProcessProtectionTypePreset
        {
            unsigned int typeValue = 0;            // typeValue：PS_PROTECTION 类型位。
            const char* sectionTextUtf8 = "";      // sectionTextUtf8：分组标题。
        };
        const ProcessProtectionTypePreset typeList[] =
        {
            { 1U, "PPL 轻量保护（Type=1）" },
            { 2U, "PP 完整保护（Type=2，更强）" }
        };
        for (const ProcessProtectionTypePreset& typeEntry : typeList)
        {
            r0PplMenu.addSection(QString::fromUtf8(typeEntry.sectionTextUtf8));
            for (const ProcessProtectionSignerPreset& presetEntry : presetList)
            {
                const unsigned int protectionLevel =
                    (static_cast<unsigned int>(presetEntry.signerValue) << 4U) | typeEntry.typeValue;
                const QString protectionLevelHexText = QStringLiteral("0x%1")
                    .arg(protectionLevel, 2, 16, QChar('0'))
                    .toUpper();
                QAction* presetAction = r0PplMenu.addAction(
                    buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
                    QStringLiteral("%1 (%2) → %3 [%4]")
                    .arg(QString::fromLatin1(presetEntry.signerName))
                    .arg(presetEntry.signerValue)
                    .arg(QString::fromUtf8(presetEntry.meaningText))
                    .arg(protectionLevelHexText));
                presetAction->setData(protectionLevel);
            }
        }

        QAction* selectedAction = r0PplMenu.exec(m_r0SetPplButton->mapToGlobal(QPoint(0, m_r0SetPplButton->height())));
        if (selectedAction == nullptr)
        {
            return;
        }
        const unsigned int levelValue = selectedAction->data().toUInt();
        if (levelValue > 0xFFU)
        {
            kLogEvent actionEvent;
            warn << actionEvent
                << "[ProcessDetailWindow] R0 进程保护层级菜单值无效, levelValue="
                << levelValue
                << eol;
            showActionResultMessage(
                QStringLiteral("R0设置进程保护层级"),
                false,
                std::string("invalid PPL level value"),
                actionEvent);
            return;
        }
        executeR0SetPplProtectionAction(
            static_cast<std::uint8_t>(levelValue),
            selectedAction->text());
    });

    // R0 可恢复隐藏菜单：
    // - 通过 ArkDriverClient 发送可恢复隐藏/恢复请求；
    // - 菜单项显式 tooltip 说明具体内核侧变更策略。
    connect(m_r0VisibilityButton, &QPushButton::clicked, this, [this]() {
        QMenu visibilityMenu(this);
        visibilityMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* hideUnlinkOnlyAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            QStringLiteral("隐藏当前进程：只断链"));
        QAction* hidePatchPidOnlyAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("隐藏当前进程：只改PID"));
        QAction* hideLegacyBothAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("隐藏当前进程：改PID+断链(旧版高风险)"));
        visibilityMenu.addSeparator();
        QAction* unhideProcessAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_resume.svg")),
            QStringLiteral("取消隐藏当前进程"));
        QAction* clearHiddenAction = visibilityMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/log_clear.svg")),
            QStringLiteral("清空全部隐藏标记"));
        hideUnlinkOnlyAction->setToolTip(QStringLiteral("只摘除 ActiveProcessLinks，不修改 PID；更容易按原 PID 找回和恢复。"));
        hidePatchPidOnlyAction->setToolTip(QStringLiteral("只修改 UniqueProcessId，不摘链；高风险，可能影响按原 PID 查找目标。"));
        hideLegacyBothAction->setToolTip(QStringLiteral("兼容旧版：同时修改 UniqueProcessId 并摘除 ActiveProcessLinks；风险最高。"));
        unhideProcessAction->setToolTip(QStringLiteral("恢复由 Ksword 记录的 UniqueProcessId 和进程链表位置。"));
        clearHiddenAction->setToolTip(QStringLiteral("恢复所有由 Ksword 摘链的进程，并清空驱动内记录。"));

        QAction* selectedAction = visibilityMenu.exec(m_r0VisibilityButton->mapToGlobal(QPoint(0, m_r0VisibilityButton->height())));
        if (selectedAction == hideUnlinkOnlyAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_UNLINK_ACTIVE_LIST);
        }
        else if (selectedAction == hidePatchPidOnlyAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_PATCH_UNIQUE_PID);
        }
        else if (selectedAction == hideLegacyBothAction)
        {
            executeR0SetProcessHiddenAction(true, KSWORD_ARK_PROCESS_VISIBILITY_FLAG_LEGACY_BOTH);
        }
        else if (selectedAction == unhideProcessAction)
        {
            executeR0SetProcessHiddenAction(false);
        }
        else if (selectedAction == clearHiddenAction)
        {
            executeR0ClearProcessHiddenAction();
        }
    });

    // R0 危险标志/DKOM 菜单：
    // - BreakOnTermination/APC/DKOM 与列表右键菜单能力对齐；
    // - 高风险确认在动作函数内部完成，菜单本身只负责分发。
    connect(m_r0DangerFlagsButton, &QPushButton::clicked, this, [this]() {
        QMenu dangerMenu(this);
        dangerMenu.setStyleSheet(buildProcessDetailMenuStyle());
        QAction* enableBreakAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_critical.svg")),
            QStringLiteral("启用 BreakOnTermination"));
        QAction* disableBreakAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("关闭 BreakOnTermination"));
        QAction* disableApcAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_suspend.svg")),
            QStringLiteral("禁止APC插入(现有线程)"));
        dangerMenu.addSeparator();
        QAction* dkomCidRemoveAction = dangerMenu.addAction(
            buildProcessDetailR0ActionIcon(QStringLiteral(":/Icon/process_uncritical.svg")),
            QStringLiteral("DKOM从PspCidTable删除"));
        enableBreakAction->setToolTip(QStringLiteral("调用 ZwSetInformationProcess(ProcessBreakOnTermination=1)。"));
        disableBreakAction->setToolTip(QStringLiteral("调用 ZwSetInformationProcess(ProcessBreakOnTermination=0)。"));
        disableApcAction->setToolTip(QStringLiteral("清除目标进程现有线程 ETHREAD ApcQueueable 位。"));
        dkomCidRemoveAction->setToolTip(QStringLiteral("从 PspCidTable 清零目标 EPROCESS 的 CID 表项；高风险且不可通过本菜单恢复。"));

        QAction* selectedAction = dangerMenu.exec(m_r0DangerFlagsButton->mapToGlobal(QPoint(0, m_r0DangerFlagsButton->height())));
        if (selectedAction == enableBreakAction)
        {
            executeR0SetBreakOnTerminationAction(true);
        }
        else if (selectedAction == disableBreakAction)
        {
            executeR0SetBreakOnTerminationAction(false);
        }
        else if (selectedAction == disableApcAction)
        {
            executeR0DisableApcInsertionAction();
        }
        else if (selectedAction == dkomCidRemoveAction)
        {
            executeR0DkomRemoveFromCidTableAction();
        }
    });
    connect(m_injectDllButton, &QPushButton::clicked, this, [this]() { executeInjectDllAction(); });
    connect(m_injectShellcodeButton, &QPushButton::clicked, this, [this]() { executeInjectShellcodeAction(); });

    // 浏览 DLL 路径。
    connect(m_browseDllButton, &QPushButton::clicked, this, [this]() {
        const QString filePath = QFileDialog::getOpenFileName(
            this,
            "选择要注入的 DLL",
            QString(),
            "DLL Files (*.dll);;All Files (*)");
        if (!filePath.isEmpty())
        {
            m_dllPathLineEdit->setText(filePath);
        }
    });

    // 浏览 shellcode 文件路径。
    connect(m_browseShellcodeButton, &QPushButton::clicked, this, [this]() {
        const QString filePath = QFileDialog::getOpenFileName(
            this,
            "选择 shellcode 文件",
            QString(),
            "Binary Files (*.bin *.dat);;All Files (*)");
        if (!filePath.isEmpty())
        {
            m_shellcodePathLineEdit->setText(filePath);
        }
    });

    // 模块刷新按钮。
    connect(m_refreshModuleButton, &QPushButton::clicked, this, [this]() {
        kLogEvent logEvent;
        info << logEvent
            << "[ProcessDetailWindow] 用户点击“刷新模块”, pid=" << m_baseRecord.pid
            << eol;
        requestAsyncModuleRefresh(true);
    });
    connect(m_moduleFilterEdit, &QLineEdit::textChanged, this, [this](const QString& filterText) {
        filterModuleTable(filterText);
    });

    // DLL 劫持检测始终在后台只读执行，不复用注入/加载路径。
    connect(m_dllHijackScanButton, &QPushButton::clicked, this, [this]() {
        requestAsyncDllHijackScan();
    });

    // 注入痕迹检查同样是只读采集。两个按钮的判据完全相同（归一化 profile 是同一份），
    // 只差比较范围：深度把全部可执行映像范围都比一遍，因此更慢。
    connect(m_injectionTraceButton, &QPushButton::clicked, this, [this]() {
        requestAsyncInjectionTraceScan(false);
    });
    connect(m_injectionTraceDeepButton, &QPushButton::clicked, this, [this]() {
        requestAsyncInjectionTraceScan(true);
    });

    // 模块表右键菜单。
    connect(m_moduleTable, &QTableView::customContextMenuRequested, this, [this](const QPoint& localPosition) {
        showModuleContextMenu(localPosition);
    });
}

void ProcessDetailWindow::refreshDetailTabTexts()
{
    if (m_generalFields == nullptr) return;
    const QString path = QString::fromStdString(m_baseRecord.imagePath);
    // 数值快照通常不改变图标；只在真实显示键变化时查图标并栅格化。
    const QString iconKey = QString::fromStdString(m_identityKey) + QLatin1Char('\n') + path;
    if (processDetailIconNeedsRefresh(m_processIconLabel, iconKey))
    {
        m_processIconLabel->setPixmap(resolveProcessIcon(m_baseRecord.imagePath, 40).pixmap(40, 40));
    }
    m_processTitleLabel->setText(QStringLiteral("%1  ·  PID %2")
        .arg(QString::fromStdString(m_baseRecord.processName)).arg(m_baseRecord.pid));
    // QLineEdit::setText还会重置选择/撤销状态；相同路径与命令行不反复回填。
    if (m_pathLineEdit->text() != path)
    {
        m_pathLineEdit->setText(path);
    }
    const QString commandLine = QString::fromStdString(m_baseRecord.commandLine);
    if (m_commandLineEdit->text() != commandLine)
    {
        m_commandLineEdit->setText(commandLine);
    }
    m_detailOpenHandleDockButton->setVisible(m_baseRecord.pid != 0);
    const QFileInfo imageInfo(path);
    m_openFileDetailButton->setEnabled(imageInfo.exists() && imageInfo.isFile());
    QHash<QString, QString> values = m_detailOverviewResult.values;
    values.insert(QStringLiteral("pid"), QString::number(m_baseRecord.pid));
    values.insert(QStringLiteral("parent_pid"), m_baseRecord.parentPid ? QString::number(m_baseRecord.parentPid) : detailUnavailableText());
    values.insert(QStringLiteral("uptime"), detailUptimeText(m_baseRecord.creationTime100ns));
    values.insert(QStringLiteral("gpu"), formatDoubleText(m_baseRecord.gpuPercent, 2) + QStringLiteral("%"));
    values.insert(QStringLiteral("network_rx"), formatDoubleText(m_baseRecord.netRxKBps, 2) + QStringLiteral(" KB/s"));
    values.insert(QStringLiteral("network_tx"), formatDoubleText(m_baseRecord.netTxKBps, 2) + QStringLiteral(" KB/s"));
    values.insert(QStringLiteral("working_set"), m_baseRecord.dynamicCountersReady ? detailBytesText(m_baseRecord.rawWorkingSetBytes) : detailUnavailableText());
    values.insert(QStringLiteral("private_commit"), m_baseRecord.dynamicCountersReady ? detailBytesText(m_baseRecord.rawPrivateBytes) : detailUnavailableText());
    values.insert(QStringLiteral("efficiency_mode"), m_baseRecord.efficiencyModeSupported ? detailBoolText(m_baseRecord.efficiencyModeEnabled) : detailUnavailableText());
    if (m_baseRecord.protectionLevelKnown && !m_baseRecord.protectionLevelText.empty())
        values.insert(QStringLiteral("ppl_protection"), QString::fromStdString(m_baseRecord.protectionLevelText));
    const auto value = [&values](const QString& key) {
        const QString result = values.value(key); return result.trimmed().isEmpty() ? detailUnavailableText() : result;
    };
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("概览与资源"));
    document.field(QStringLiteral("PID"), value(QStringLiteral("pid")), true);
    document.field(QStringLiteral("CPU 占用"), formatDoubleText(m_baseRecord.cpuPercent, 2) + QStringLiteral("%"), true);
    document.field(QStringLiteral("工作集"), value(QStringLiteral("working_set")), true);
    document.field(QStringLiteral("GPU 占用"), value(QStringLiteral("gpu")), true);
    document.field(QStringLiteral("线程数量"), QString::number(m_baseRecord.threadCount), true);
    document.field(QStringLiteral("句柄数量"), QString::number(m_baseRecord.handleCount), true);
    document.field(QStringLiteral("架构"), QString::fromStdString(m_baseRecord.architectureText), true);
    document.field(QStringLiteral("用户"), QString::fromStdString(m_baseRecord.userName));
    document.field(QStringLiteral("数字签名"), QString::fromStdString(m_baseRecord.signatureState), true);
    ks::ui::FieldNode publisherTrust;
    publisherTrust.name = QStringLiteral("受信任的发布者");
    const bool signaturePending = generalSignatureStateUndecided(QString::fromStdString(m_baseRecord.signatureState));
    publisherTrust.value = signaturePending ? QStringLiteral("Unknown")
        : m_baseRecord.signatureTrusted ? QStringLiteral("是") : QStringLiteral("否");
    publisherTrust.translateValue = true;
    document.nodes.last().children.last().children.push_back(publisherTrust);
    document.section(QStringLiteral("身份与资源详情"));
    document.field(QStringLiteral("父 PID"), value(QStringLiteral("parent_pid")), true);
    document.field(QStringLiteral("启动时间"), QString::fromStdString(m_baseRecord.startTimeText), true);
    document.field(QStringLiteral("运行时长"), value(QStringLiteral("uptime")), true);
    document.field(QStringLiteral("管理员"), m_baseRecord.isAdmin ? QStringLiteral("是") : QStringLiteral("否"), true);
    document.field(QStringLiteral("完整性级别"), value(QStringLiteral("integrity_level")), true);
    document.field(QStringLiteral("提升类型"), value(QStringLiteral("elevation_type")), true);
    document.field(QStringLiteral("Session ID"), QString::number(m_baseRecord.sessionId), true);
    document.field(QStringLiteral("优先级"), QString::fromStdString(m_baseRecord.priorityText), true);
    document.field(QStringLiteral("CPU 单核等效"), formatDoubleText(m_baseRecord.cpuCorePercent, 2) + QStringLiteral("%"), true);
    document.field(QStringLiteral("DISK 吞吐"), formatDoubleText(m_baseRecord.diskMBps, 2) + QStringLiteral(" MB/s"), true);
    document.field(QStringLiteral("网络下行"), value(QStringLiteral("network_rx")), true);
    document.field(QStringLiteral("网络上行"), value(QStringLiteral("network_tx")), true);
    document.field(QStringLiteral("私有提交"), value(QStringLiteral("private_commit")), true);
    document.field(QStringLiteral("峰值工作集"), value(QStringLiteral("peak_working_set")), true);
    document.field(QStringLiteral("页错误"), value(QStringLiteral("page_faults")), true);
    document.section(QStringLiteral("I/O 与 GUI 资源"));
    document.field(QStringLiteral("读取操作"), value(QStringLiteral("io_read_ops")), true);
    document.field(QStringLiteral("写入操作"), value(QStringLiteral("io_write_ops")), true);
    document.field(QStringLiteral("其他 I/O 操作"), value(QStringLiteral("io_other_ops")), true);
    document.field(QStringLiteral("读取字节"), value(QStringLiteral("io_read_bytes")), true);
    document.field(QStringLiteral("写入字节"), value(QStringLiteral("io_write_bytes")), true);
    document.field(QStringLiteral("其他 I/O 字节"), value(QStringLiteral("io_other_bytes")), true);
    document.field(QStringLiteral("内核 CPU 时间"), value(QStringLiteral("kernel_cpu_time")), true);
    document.field(QStringLiteral("用户 CPU 时间"), value(QStringLiteral("user_cpu_time")), true);
    document.field(QStringLiteral("GDI 对象"), value(QStringLiteral("gdi_objects")), true);
    document.field(QStringLiteral("USER 对象"), value(QStringLiteral("user_objects")), true);
    document.field(QStringLiteral("顶层窗口"), value(QStringLiteral("gui_top_level_windows")), true);
    document.field(QStringLiteral("Job 对象"), value(QStringLiteral("job_object")), true);
    document.section(QStringLiteral("运行环境"));
    document.field(QStringLiteral("CPU 亲和性"), value(QStringLiteral("cpu_affinity")), true);
    document.field(QStringLiteral("效率模式"), value(QStringLiteral("efficiency_mode")), true);
    document.field(QStringLiteral("子系统"), value(QStringLiteral("subsystem")), true);
    const QString threadDesktop = value(QStringLiteral("thread_desktop"));
    const QString windowStation = value(QStringLiteral("window_station"));
    document.field(QStringLiteral("线程桌面"), threadDesktop, threadDesktop == detailUnavailableText());
    document.field(QStringLiteral("窗口站"), windowStation, windowStation == detailUnavailableText());
    document.section(QStringLiteral("安全状态与缓解策略"));
    document.field(QStringLiteral("PPL 保护级别"), value(QStringLiteral("ppl_protection")), true);
    document.field(QStringLiteral("关键进程"), value(QStringLiteral("critical_process")), true);
    document.field(QStringLiteral("调试端口"), value(QStringLiteral("debug_port")), true);
    document.field(QStringLiteral("AppContainer"), value(QStringLiteral("app_container")), true);
    document.field(QStringLiteral("令牌虚拟化"), value(QStringLiteral("token_virtualization")), true);
    document.field(QStringLiteral("DEP"), value(QStringLiteral("mitigation_dep")), true);
    document.field(QStringLiteral("ASLR"), value(QStringLiteral("mitigation_aslr")), true);
    document.field(QStringLiteral("CFG / XFG"), value(QStringLiteral("mitigation_cfg")), true);
    document.field(QStringLiteral("动态代码限制"), value(QStringLiteral("mitigation_dynamic_code")), true);
    document.field(QStringLiteral("扩展点禁用"), value(QStringLiteral("mitigation_extension_points")), true);
    document.field(QStringLiteral("映像加载限制"), value(QStringLiteral("mitigation_image_load")), true);
    document.field(QStringLiteral("严格句柄检查"), value(QStringLiteral("mitigation_strict_handles")), true);
    document.field(QStringLiteral("Win32k 调用禁用"), value(QStringLiteral("mitigation_win32k")), true);
    document.field(QStringLiteral("子进程创建限制"), value(QStringLiteral("mitigation_child_process")), true);
    document.field(QStringLiteral("用户影子栈 (CET)"), value(QStringLiteral("mitigation_shadow_stack")), true);
    if (!m_detailOverviewResult.diagnosticText.trimmed().isEmpty())
    { document.section(QStringLiteral("诊断")); document.nodes.last().initiallyExpanded = false; document.note(m_detailOverviewResult.diagnosticText); }
    m_generalFields->setDocument(document);
    if (m_suspendProcessCheck != nullptr)
    {
        const QSignalBlocker blocker(m_suspendProcessCheck);
        m_suspendProcessCheck->setChecked(m_baseRecord.processStateKnown && m_baseRecord.processSuspended);
    }
    if (m_efficiencyModeCheck != nullptr)
    {
        const QSignalBlocker blocker(m_efficiencyModeCheck);
        m_efficiencyModeCheck->setChecked(m_baseRecord.efficiencyModeSupported && m_baseRecord.efficiencyModeEnabled);
    }
    refreshParentProcessSection();
    refreshKernelObjectTabTexts();
    updateWindowTitle();
}

void ProcessDetailWindow::refreshKernelObjectTabTexts()
{
    // 内核对象页刷新：
    // - 所有字段都来自当前 ProcessRecord 缓存；
    // - 不在 UI 刷新时额外请求 R0，避免详情窗口无意触发内核枚举。
    if (m_kernelObjectTab == nullptr)
    {
        return;
    }

    const bool protectionPresent =
        (m_baseRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_PROTECTION_PRESENT) != 0U;
    const bool signaturePresent =
        (m_baseRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SIGNATURE_LEVEL_PRESENT) != 0U;
    const bool sectionSignaturePresent =
        (m_baseRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_SIGNATURE_LEVEL_PRESENT) != 0U;
    const bool objectTableAvailable =
        (m_baseRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_OBJECT_TABLE_AVAILABLE) != 0U;
    const bool sectionObjectAvailable =
        (m_baseRecord.r0FieldFlags & KSWORD_ARK_PROCESS_FIELD_SECTION_OBJECT_AVAILABLE) != 0U;

    if (m_kernelObjectR0StatusValue != nullptr)
    {
        m_kernelObjectR0StatusValue->setText(detailProcessR0StatusText(m_baseRecord.r0Status));
        applyProcessDetailLocalStyle(m_kernelObjectR0StatusValue,
            buildStateLabelStyle(
                m_baseRecord.r0Status == KSWORD_ARK_PROCESS_R0_STATUS_OK
                ? statusIdleColor()
                : statusWarningColor(),
                700));
    }

    if (m_kernelObjectCapabilityValue != nullptr)
    {
        m_kernelObjectCapabilityValue->setText(detailProcessCapabilityText(m_baseRecord.r0DynDataCapabilityMask));
    }
    if (m_kernelObjectImagePathValue != nullptr)
    {
        m_kernelObjectImagePathValue->setText(
            QString::fromStdString(m_baseRecord.r0ImagePath.empty() ? std::string("-") : m_baseRecord.r0ImagePath));
    }

    if (m_kernelObjectHandleTableValue != nullptr)
    {
        m_kernelObjectHandleTableValue->setText(detailProcessPointerText(
            QStringLiteral("HandleTable available"),
            objectTableAvailable,
            m_baseRecord.r0ObjectTableAddress,
            m_baseRecord.r0ObjectTableSource));
        applyProcessDetailLocalStyle(m_kernelObjectHandleTableValue,
            buildStateLabelStyle(objectTableAvailable ? statusIdleColor() : statusSecondaryColor(), 700));
    }
    if (m_kernelObjectSectionObjectValue != nullptr)
    {
        m_kernelObjectSectionObjectValue->setText(detailProcessPointerText(
            QStringLiteral("SectionObject available"),
            sectionObjectAvailable,
            m_baseRecord.r0SectionObjectAddress,
            m_baseRecord.r0SectionObjectSource));
        applyProcessDetailLocalStyle(m_kernelObjectSectionObjectValue,
            buildStateLabelStyle(sectionObjectAvailable ? statusIdleColor() : statusSecondaryColor(), 700));
    }

    if (m_kernelObjectProtectionValue != nullptr)
    {
        m_kernelObjectProtectionValue->setText(protectionPresent
            ? detailProcessByteHexText(m_baseRecord.r0Protection)
            : QStringLiteral("Unavailable"));
    }
    if (m_kernelObjectSignatureValue != nullptr)
    {
        m_kernelObjectSignatureValue->setText(signaturePresent
            ? detailProcessByteHexText(m_baseRecord.r0SignatureLevel)
            : QStringLiteral("Unavailable"));
    }
    if (m_kernelObjectSectionSignatureValue != nullptr)
    {
        m_kernelObjectSectionSignatureValue->setText(sectionSignaturePresent
            ? detailProcessByteHexText(m_baseRecord.r0SectionSignatureLevel)
            : QStringLiteral("Unavailable"));
    }

    if (m_kernelObjectSessionSourceValue != nullptr) m_kernelObjectSessionSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0SessionSource));
    if (m_kernelObjectImagePathSourceValue != nullptr) m_kernelObjectImagePathSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0ImagePathSource));
    if (m_kernelObjectProtectionSourceValue != nullptr) m_kernelObjectProtectionSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0ProtectionSource));
    if (m_kernelObjectSignatureSourceValue != nullptr) m_kernelObjectSignatureSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0SignatureLevelSource));
    if (m_kernelObjectSectionSignatureSourceValue != nullptr) m_kernelObjectSectionSignatureSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0SectionSignatureLevelSource));
    if (m_kernelObjectObjectTableSourceValue != nullptr) m_kernelObjectObjectTableSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0ObjectTableSource));
    if (m_kernelObjectSectionObjectSourceValue != nullptr) m_kernelObjectSectionObjectSourceValue->setText(detailProcessFieldSourceText(m_baseRecord.r0SectionObjectSource));

    if (m_kernelObjectProtectionOffsetValue != nullptr) m_kernelObjectProtectionOffsetValue->setText(detailProcessOffsetText(m_baseRecord.r0ProtectionOffset));
    if (m_kernelObjectSignatureOffsetValue != nullptr) m_kernelObjectSignatureOffsetValue->setText(detailProcessOffsetText(m_baseRecord.r0SignatureLevelOffset));
    if (m_kernelObjectSectionSignatureOffsetValue != nullptr) m_kernelObjectSectionSignatureOffsetValue->setText(detailProcessOffsetText(m_baseRecord.r0SectionSignatureLevelOffset));
    if (m_kernelObjectObjectTableOffsetValue != nullptr) m_kernelObjectObjectTableOffsetValue->setText(detailProcessOffsetText(m_baseRecord.r0ObjectTableOffset));
    if (m_kernelObjectSectionObjectOffsetValue != nullptr) m_kernelObjectSectionObjectOffsetValue->setText(detailProcessOffsetText(m_baseRecord.r0SectionObjectOffset));
}

void ProcessDetailWindow::refreshParentProcessSection()
{
    // 父进程区域刷新日志：记录父 PID。
    kLogEvent refreshParentEvent;
    dbg << refreshParentEvent
        << "[ProcessDetailWindow] refreshParentProcessSection: parentPid="
        << m_baseRecord.parentPid
        << eol;

    if (m_baseRecord.parentPid == 0)
    {
        m_gotoParentButton->setVisible(false);
        if (m_gotoParentButton->property("parent_pid").isValid())
        {
            m_gotoParentButton->setProperty("parent_pid", QVariant());
        }
        m_parentInfoLabel->setText("无父进程信息");
        if (processDetailIconNeedsRefresh(m_parentIconLabel, QString()))
        {
            m_parentIconLabel->setPixmap(QIcon(":/Icon/process_main.svg").pixmap(20, 20));
        }
        return;
    }

    const std::uint32_t parentPid = m_baseRecord.parentPid;
    const std::string parentName = ks::process::GetProcessNameByPID(parentPid);
    const bool parentAlive = !parentName.empty();
    // 保留每轮父进程活性检查，但不再先隐藏又显示同一个按钮触发两次整行布局。
    m_gotoParentButton->setVisible(parentAlive);
    const QVariant parentPidValue = parentAlive ? QVariant::fromValue(parentPid) : QVariant();
    if (m_gotoParentButton->property("parent_pid") != parentPidValue)
    {
        m_gotoParentButton->setProperty("parent_pid", parentPidValue);
    }

    if (parentAlive)
    {
        m_parentInfoLabel->setText(
            QString("%1 (PID: %2)")
            .arg(QString::fromStdString(parentName))
            .arg(parentPid));
        const std::string parentPath = ks::process::QueryProcessPathByPid(parentPid);
        const QString parentIconKey = QString::number(parentPid) + QLatin1Char('\n')
            + QString::fromStdString(parentPath);
        if (processDetailIconNeedsRefresh(m_parentIconLabel, parentIconKey))
        {
            m_parentIconLabel->setPixmap(resolveProcessIcon(parentPath, 20).pixmap(20, 20));
        }
        kLogEvent refreshParentAliveEvent;
        dbg << refreshParentAliveEvent
            << "[ProcessDetailWindow] refreshParentProcessSection: 父进程可访问, parentPid="
            << parentPid
            << eol;
    }
    else
    {
        m_parentInfoLabel->setText(QString("父进程已退出或不可访问 (PID: %1)").arg(parentPid));
        if (processDetailIconNeedsRefresh(m_parentIconLabel, QString()))
        {
            m_parentIconLabel->setPixmap(QIcon(":/Icon/process_main.svg").pixmap(20, 20));
        }
        kLogEvent refreshParentDeadEvent;
        info << refreshParentDeadEvent
            << "[ProcessDetailWindow] refreshParentProcessSection: 父进程不可访问, parentPid="
            << parentPid
            << eol;
    }
}

void ProcessDetailWindow::updateWindowTitle()
{
    const QString desiredTitle = QString("进程详细信息 - %1 (PID %2)")
        .arg(QString::fromStdString(m_baseRecord.processName.empty() ? "Unknown" : m_baseRecord.processName))
        .arg(m_baseRecord.pid);
    if (windowTitle() == desiredTitle)
    {
        return;
    }
    // 标题更新日志：便于多窗口场景排查标题错乱。
    kLogEvent updateTitleEvent;
    dbg << updateTitleEvent
        << "[ProcessDetailWindow] updateWindowTitle: pid="
        << m_baseRecord.pid
        << eol;

    setWindowTitle(desiredTitle);
}

