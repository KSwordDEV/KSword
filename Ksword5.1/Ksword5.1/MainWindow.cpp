#include "MainWindow.h"
#include "Framework/PrivilegeElevationPrompt.h"
#include "MinidumpDock/DumpAutoCheck.h"
#include <QMenu>
#include <QAction>
#include <QEasingCurve>
#include <QAbstractScrollArea>
#include <QAbstractItemView>
#include <QAbstractItemModel>
#include <QAbstractSlider>
#include <QComboBox>
#include <QTextEdit>
#include <QTextStream>
#include <QTabWidget>
#include <QTabBar>
#include <QToolButton>
#include <QTimer>
#include <QApplication>
#include <QCoreApplication>
#include <QCheckBox>
#include <QDir>
#include <QElapsedTimer>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QGuiApplication>
#include <QHeaderView>
#include <QScreen>
#include <QSet>
#include <QWindow>
#include <QWidget>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QList>
#include <QMargins>
#include <QPainter>
#include <QPaintEvent>
#include <QPalette>
#include <QPen>
#include <QPointF>
#include <QPixmap>
#include <QPointer>
#include <QProgressBar>
#include <QPushButton>
#include <QPropertyAnimation>
#include <QRectF>
#include <QResizeEvent>
#include <QSizePolicy>
#include <QScrollBar>
#include <QScrollArea>
#include <QImageReader>
#include <QImage>
#include <QThreadPool>
#include <QDialog>
#include <QIODevice>
#include <QMessageBox>
#include <QMetaObject>
#include <QMouseEvent>
#include <QProcess>
#include <QStringList>
#include <QToolTip>
#include <QStyleHints>
#include <QStyle>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QProxyStyle>
#include <QTableView>
#include <QEvent>
#include <QEventLoop>
#include <QVariant>
#include <QWheelEvent>
#pragma warning(disable: 4996)
#include "UI/UI.css/UI_css.h"
#include "Framework.h"
#include "Framework/LogDockWidget.h"
#include "Framework/NotificationCardManager.h"
#include "Framework/ProgressDockWidget.h"
#include "Framework/CustomTitleBar.h"
#include "include/ads/AutoHideTab.h"
#include "include/ads/DockComponentsFactory.h"
#include "include/ads/DockAreaTitleBar.h"
#include "include/ads/DockAreaWidget.h"
#include "include/ads/DockWidgetTab.h"
#include "include/ads/FloatingDockContainer.h"
#include "ArkDriverClient/ArkDriverClient.h"
#include "KernelDock/KernelDock.CallbackPromptManager.h"
#include "PluginHost.h"
#include "Internationalization/LanguageManager.h"
#include "UI/CodeEditorWidget.h"
#include "UI/DetailLayoutRegistry.h"
#include "UI/GlobalDialogTheme.h"
#include "UI/GlobalUiBaseStyle.h"
#include "UI/GlobalUiSearch.h"
#include "UI/CommandExecutionPopup.h"
#include "UI/WindowChrome.h"
#include "UI/SvgThemeIconManager.h"
#include "UI/SmoothScrollSupport.h"
#include "UI/ThemedMessageBox.h"
#include "theme.h"
#include "ksword/process/process.h"
#include "../../shared/crash/WinCrashHandler.h"
#include "../../shared/KswordArkLogProtocol.h"
// 驱动启动阶段记录的键名与阶段枚举，R0/R3 共用同一份定义。
#include "../../shared/KswordArkStartupProtocol.h"
#include <windows.h>
// 菜单栏权限按钮涉及 Windows 令牌权限查询与提权动作。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <dwmapi.h>
#include <shellapi.h>
#include <sddl.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath>
#include <functional>
#include <limits>
#include <utility>
#include <unordered_map>
#include <cstring>
#include <vector>
#include <TlHelp32.h>

#pragma comment(lib, "Dwmapi.lib")

namespace
{
    constexpr wchar_t kKswordPrivilegeRestartArgument[] = L"--ksword-privilege-restart";
    constexpr wchar_t kKswordEnableR0AfterElevationArgument[] = L"--ksword-enable-r0-after-elevation";
    constexpr wchar_t kKswordMainWindowPropertyName[] = L"KswordARK.MainWindow.Singleton.Release";
    constexpr ULONG_PTR kUnlockerCopyDataMessageId = 0x4B535755; // "KSWU"：Ksword shell unlocker IPC。

    // kDockLayoutConfigFileVersion 作用：
    // - 作为 ADS saveState/restoreState 的版本号；
    // - Dock 集合或默认布局发生不兼容变化时递增，可自动放弃旧布局。
    constexpr int kDockLayoutConfigFileVersion = 6;

    // kDockLayoutConfigFileName 作用：
    // - 定义用户拖拽后的 ADS 布局配置文件名；
    // - 文件落在 exe 同级 config 目录，便于发行包独立携带配置。
    constexpr const char* kDockLayoutConfigFileName = "ksword_ads_layout.bin";

    // kLazyDockPlaceholderProgressBarObjectName / kLazyDockPlaceholderStageLabelObjectName 作用：
    // - 懒加载占位页里进度条与阶段文案的稳定 objectName；
    // - 占位页由 createDockPlaceholderWidget 建好后就交给了 ADS，
    //   初始化各阶段只能靠 findChild 反查这两个控件，因此名字必须固定。
    constexpr const char* kLazyDockPlaceholderProgressBarObjectName = "ksLazyDockProgressBar";
    constexpr const char* kLazyDockPlaceholderStageLabelObjectName = "ksLazyDockStageLabel";

    // kKswordDockTabPropertyName 作用：
    // - 给 ADS 主 Dock 标签打动态属性，供最终兜底 QSS 精准选择；
    // - 避免泛化 QWidget:hover 影响 Dock 内容区其它控件。
    constexpr const char* kKswordDockTabPropertyName = "kswordDockTab";

    // kKswordAutoHideTabPropertyName 作用：
    // - 给 ADS 自动隐藏侧边标签打动态属性；
    // - 与主 Dock 标签使用相同悬停色，但保持选择器独立。
    constexpr const char* kKswordAutoHideTabPropertyName = "kswordAutoHideTab";

    constexpr const char* kKswordProcessUiAccessPropertyName = "ksword_process_uiaccess_enabled";
    constexpr const char* kKswordMainWindowTopMostPropertyName = "ksword_main_window_topmost";
    constexpr const char* kKswordMainWindowHwndPropertyName = "ksword_main_window_hwnd";
    constexpr const char* kKswordCustomTableDelegatePropertyName = "ksword_preserve_custom_table_delegate";
    constexpr const char* kKswordTableSelectionOutlineDelegatePropertyName = "ksword_table_selection_outline_delegate";
    constexpr const char* kKswordTableSelectionOutlineStylePropertyName = "ksword_table_selection_outline_style";
    constexpr const char* kKswordComboPopupAutoThemedPropertyName = "ksword_combo_popup_auto_themed";
    constexpr const char* kKswordComboPopupThemeUpdatePendingPropertyName = "ksword_combo_popup_theme_update_pending";
    constexpr int kResizeBorderOverlayWidth = 3;
    constexpr int kResizeCornerTriangleLeg = 6;

    QVector<quint32> parseProcessPidListText(const QString& pidListText)
    {
        QString normalizedText = pidListText;
        normalizedText.replace(',', ' ');
        normalizedText.replace(';', ' ');
        normalizedText.replace('\n', ' ');
        normalizedText.replace('\t', ' ');

        QVector<quint32> processIds;
        QSet<quint32> seenPidSet;
        for (const QString& token : normalizedText.split(' ', Qt::SkipEmptyParts))
        {
            bool parseOk = false;
            const quint32 processId = token.toUInt(&parseOk, 10);
            if (parseOk && processId != 0U && !seenPidSet.contains(processId))
            {
                seenPidSet.insert(processId);
                processIds.push_back(processId);
            }
        }
        return processIds;
    }

    constexpr int kBugcheckBitmapMaxWidth =
        static_cast<int>(KSWORD_ARK_BUGCHECK_BITMAP_MAX_WIDTH);
    constexpr int kBugcheckBitmapMaxHeight =
        static_cast<int>(KSWORD_ARK_BUGCHECK_BITMAP_MAX_HEIGHT);
    constexpr int kBugcheckLogoWidth = 240;
    constexpr int kBugcheckLogoHeight = 84;
    static_assert(kBugcheckLogoWidth <= kBugcheckBitmapMaxWidth);
    static_assert(kBugcheckLogoHeight <= kBugcheckBitmapMaxHeight);
    constexpr QRgb kBugcheckBitmapBackground = qRgba(5, 15, 33, 255);
    constexpr QRgb kBugcheckBitmapLightText = qRgba(226, 232, 244, 255);

    std::uint32_t detectBugcheckBrandColor(const QImage& image)
    {
        std::uint64_t redTotal = 0;
        std::uint64_t greenTotal = 0;
        std::uint64_t blueTotal = 0;
        std::uint64_t sampleCount = 0;

        for (int y = 0; y < image.height(); ++y)
        {
            for (int x = 0; x < image.width(); ++x)
            {
                const QColor color = image.pixelColor(x, y);
                if (color.alpha() < 32 || color.blue() < 96 ||
                    color.blue() < color.red() + 24 ||
                    color.blue() < color.green() + 8)
                {
                    continue;
                }
                redTotal += static_cast<std::uint64_t>(color.red());
                greenTotal += static_cast<std::uint64_t>(color.green());
                blueTotal += static_cast<std::uint64_t>(color.blue());
                ++sampleCount;
            }
        }

        if (sampleCount == 0)
        {
            return 0x0078D4U;
        }
        return
            (static_cast<std::uint32_t>(redTotal / sampleCount) << 16) |
            (static_cast<std::uint32_t>(greenTotal / sampleCount) << 8) |
            static_cast<std::uint32_t>(blueTotal / sampleCount);
    }

    [[maybe_unused]] void queueBugcheckBitmapUpload()
    {
        // The branding packet is optional. Keep decoding and driver I/O away
        // from the UI thread and intentionally discard every failure result.
        QThreadPool::globalInstance()->start([]()
        {
            QImage source(QStringLiteral(":/Image/Resource/Logo/KswordHome-En.png"));
            if (source.isNull())
            {
                return;
            }

            if (source.width() != kBugcheckLogoWidth ||
                source.height() != kBugcheckLogoHeight)
            {
                source = source.scaled(
                    kBugcheckLogoWidth,
                    kBugcheckLogoHeight,
                    Qt::IgnoreAspectRatio,
                    Qt::SmoothTransformation);
                if (source.isNull())
                {
                    return;
                }
            }

            const std::uint32_t brandColor = detectBugcheckBrandColor(source);
            QImage darkCompatibleSource = source.convertToFormat(QImage::Format_ARGB32);
            if (darkCompatibleSource.isNull())
            {
                return;
            }
            for (int y = 0; y < darkCompatibleSource.height(); ++y)
            {
                QRgb* const row = reinterpret_cast<QRgb*>(darkCompatibleSource.scanLine(y));
                for (int x = 0; x < darkCompatibleSource.width(); ++x)
                {
                    const QColor color = QColor::fromRgba(row[x]);
                    if (color.alpha() != 0 && color.red() < 72 &&
                        color.green() < 72 && color.blue() < 72)
                    {
                        row[x] = qRgba(
                            qRed(kBugcheckBitmapLightText),
                            qGreen(kBugcheckBitmapLightText),
                            qBlue(kBugcheckBitmapLightText),
                            color.alpha());
                    }
                }
            }
            QImage bitmap(source.size(), QImage::Format_ARGB32);
            if (bitmap.isNull())
            {
                return;
            }
            bitmap.fill(kBugcheckBitmapBackground);
            {
                QPainter painter(&bitmap);
                painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
                painter.drawImage(0, 0, darkCompatibleSource);
            }

            const std::uint32_t width = static_cast<std::uint32_t>(bitmap.width());
            const std::uint32_t height = static_cast<std::uint32_t>(bitmap.height());
            const std::uint32_t stride = width * 4U;
            if (bitmap.bytesPerLine() < static_cast<qsizetype>(stride))
            {
                return;
            }

            std::vector<std::uint8_t> pixels(
                static_cast<std::size_t>(stride) * height);
            for (std::uint32_t y = 0; y < height; ++y)
            {
                std::memcpy(
                    pixels.data() + static_cast<std::size_t>(y) * stride,
                    bitmap.constScanLine(static_cast<int>(y)),
                    stride);
            }

            (void)ksword::ark::DriverClient().setBugcheckBitmap(
                width,
                height,
                stride,
                brandColor,
                pixels);
        });
    }

    constexpr int kBugcheckVerdictWidth =
        static_cast<int>(KSWORD_ARK_BUGCHECK_VERDICT_MAX_WIDTH);
    constexpr int kBugcheckVerdictMaxHeight =
        static_cast<int>(KSWORD_ARK_BUGCHECK_VERDICT_MAX_HEIGHT);
    constexpr int kBugcheckVerdictPadding = 8;

    QImage renderBugcheckVerdictCard(const QString& text, const QFont& systemFont)
    {
        constexpr int textFlags =
            Qt::AlignLeft | Qt::AlignVCenter | Qt::TextWordWrap;
        QFont verdictFont = systemFont;
        QRect textBounds;

        verdictFont.setWeight(QFont::DemiBold);
        for (int pixelSize = 18; pixelSize >= 12; --pixelSize)
        {
            verdictFont.setPixelSize(pixelSize);
            const QFontMetrics metrics(verdictFont);
            textBounds = metrics.boundingRect(
                QRect(
                    0,
                    0,
                    kBugcheckVerdictWidth - kBugcheckVerdictPadding * 2,
                    2048),
                textFlags,
                text);
            if (textBounds.height() + kBugcheckVerdictPadding * 2 <=
                kBugcheckVerdictMaxHeight)
            {
                break;
            }
        }

        const int cardHeight = std::clamp(
            textBounds.height() + kBugcheckVerdictPadding * 2,
            48,
            kBugcheckVerdictMaxHeight);
        QImage card(
            kBugcheckVerdictWidth,
            cardHeight,
            QImage::Format_ARGB32);
        if (card.isNull())
        {
            return {};
        }

        card.fill(kBugcheckBitmapBackground);
        QPainter painter(&card);
        painter.setRenderHint(QPainter::TextAntialiasing, true);
        painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
        painter.setFont(verdictFont);
        painter.setPen(QColor::fromRgba(kBugcheckBitmapLightText));
        painter.drawText(
            QRect(
                kBugcheckVerdictPadding,
                kBugcheckVerdictPadding,
                card.width() - kBugcheckVerdictPadding * 2,
                card.height() - kBugcheckVerdictPadding * 2),
            textFlags,
            text);
        painter.end();
        return card;
    }

    bool appendBugcheckVerdictBitmap(
        std::vector<ksword::ark::BugcheckVerdictBitmap>& resources,
        const std::uint32_t language,
        const std::uint32_t classification,
        const QString& text,
        const QFont& systemFont)
    {
        const QImage card = renderBugcheckVerdictCard(text, systemFont);
        if (card.isNull())
        {
            return false;
        }

        ksword::ark::BugcheckVerdictBitmap resource;
        resource.language = language;
        resource.classification = classification;
        resource.width = static_cast<std::uint32_t>(card.width());
        resource.height = static_cast<std::uint32_t>(card.height());
        resource.stride = resource.width * 4U;
        if (card.bytesPerLine() < static_cast<qsizetype>(resource.stride))
        {
            return false;
        }
        resource.bgraPixels.resize(
            static_cast<std::size_t>(resource.stride) * resource.height);
        for (std::uint32_t y = 0; y < resource.height; ++y)
        {
            std::memcpy(
                resource.bgraPixels.data() +
                    static_cast<std::size_t>(y) * resource.stride,
                card.constScanLine(static_cast<int>(y)),
                resource.stride);
        }
        resources.push_back(std::move(resource));
        return true;
    }

    void queueBugcheckVerdictResourceUpload()
    {
        const QFont systemFont =
            QFontDatabase::systemFont(QFontDatabase::GeneralFont);
        QThreadPool::globalInstance()->start([systemFont]()
        {
            const std::array<std::uint32_t, 4> classifications{
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_OURS,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_MICROSOFT,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_THIRD_PARTY,
                KSWORD_ARK_BUGCHECK_VERDICT_CLASS_UNKNOWN
            };
            const std::array<QString, 4> chineseTexts{
                QStringLiteral("这是KswordARK的问题，我们非常抱歉。请您尽快将MiniDump发送给开发者以取得修复。"),
                QStringLiteral("这不是KswordARK的问题，而是微软的屎山代码发力了。向技术人员发送MiniDump或此页面的照片。"),
                QStringLiteral("这不是KswordARK的问题，也不是微软的问题，而是第三方驱动程序的问题。向技术人员发送MiniDump或此页面的照片。"),
                QStringLiteral("这不是任何人的问题，你电脑就是炸了。重启、重装、重买。")
            };
            const std::array<QString, 4> englishTexts{
                QStringLiteral("This is a KswordARK problem. We are very sorry. Please send the MiniDump to the developers as soon as possible so it can be fixed."),
                QStringLiteral("This is not a KswordARK problem. Microsoft's spaghetti code struck again. Send the MiniDump or a photo of this page to technical support."),
                QStringLiteral("This is neither a KswordARK nor a Microsoft problem. A third-party driver is responsible. Send the MiniDump or a photo of this page to technical support."),
                QStringLiteral("This is nobody's fault. Your computer just exploded. Restart it, reinstall it, or buy a new one.")
            };

            std::vector<ksword::ark::BugcheckVerdictBitmap> resources;
            resources.reserve(KSWORD_ARK_BUGCHECK_VERDICT_RESOURCE_COUNT);
            for (std::size_t index = 0; index < classifications.size(); ++index)
            {
                if (!appendBugcheckVerdictBitmap(
                        resources,
                        KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_CHINESE,
                        classifications[index],
                        chineseTexts[index],
                        systemFont) ||
                    !appendBugcheckVerdictBitmap(
                        resources,
                        KSWORD_ARK_BUGCHECK_VERDICT_LANGUAGE_ENGLISH,
                        classifications[index],
                        englishTexts[index],
                        systemFont))
                {
                    return;
                }
            }
            (void)ksword::ark::DriverClient().setBugcheckVerdictResources(
                resources);
        });
    }

    // makeNativeMouseLParam：
    // - 输入 globalPoint：Qt 鼠标事件提供的全局坐标；
    // - 处理：按 Win32 鼠标消息格式打包 signed x/y；
    // - 返回：可直接传给 WM_NCLBUTTONDOWN 的 LPARAM。
    LPARAM makeNativeMouseLParam(const QPoint& globalPoint)
    {
        return MAKELPARAM(
            static_cast<SHORT>(globalPoint.x()),
            static_cast<SHORT>(globalPoint.y()));
    }

    // isNativeResizeHitTestCode：
    // - 输入：Windows 非客户区命中测试返回值；
    // - 处理：判断是否属于八个边框/角落缩放命中；
    // - 返回：true 表示后续 WM_NCLBUTTONDOWN 必须交给 DefWindowProc 启动系统缩放。
    bool isNativeResizeHitTestCode(const WPARAM hitTestCode)
    {
        return hitTestCode == HTLEFT
            || hitTestCode == HTRIGHT
            || hitTestCode == HTTOP
            || hitTestCode == HTBOTTOM
            || hitTestCode == HTTOPLEFT
            || hitTestCode == HTTOPRIGHT
            || hitTestCode == HTBOTTOMLEFT
            || hitTestCode == HTBOTTOMRIGHT;
    }

    // cursorForResizeHitTestCode：
    // - 输入 hitTestCode：Win32 边框缩放命中值；
    // - 处理：转换为 Qt 光标形状；
    // - 返回：对应缩放光标，非缩放命中返回箭头。
    Qt::CursorShape cursorForResizeHitTestCode(const WPARAM hitTestCode)
    {
        switch (hitTestCode)
        {
        case HTLEFT:
        case HTRIGHT:
            return Qt::SizeHorCursor;
        case HTTOP:
        case HTBOTTOM:
            return Qt::SizeVerCursor;
        case HTTOPLEFT:
        case HTBOTTOMRIGHT:
            return Qt::SizeFDiagCursor;
        case HTTOPRIGHT:
        case HTBOTTOMLEFT:
            return Qt::SizeBDiagCursor;
        default:
            return Qt::ArrowCursor;
        }
    }

    // ResizeCornerTriangleWidget 作用：
    // - 输入：构造时指定左下角或右下角；
    // - 处理：在独立 6x6 overlay 控件内绘制一个直角三角形提示区域；
    // - 返回：构造函数无返回；paintEvent 无返回，仅负责视觉绘制。
    class ResizeCornerTriangleWidget final : public QWidget
    {
    public:
        enum class Corner
        {
            BottomLeft,
            BottomRight
        };

        explicit ResizeCornerTriangleWidget(const Corner corner, QWidget* parent = nullptr)
            : QWidget(parent)
            , m_corner(corner)
        {
            setAttribute(Qt::WA_NoSystemBackground, true);
            setAttribute(Qt::WA_TranslucentBackground, true);
            setAutoFillBackground(false);
            setMouseTracking(true);
        }

    protected:
        void paintEvent(QPaintEvent* event) override
        {
            Q_UNUSED(event);

            QPainter painter(this);
            painter.setRenderHint(QPainter::Antialiasing, false);
            painter.setPen(Qt::NoPen);
            painter.setBrush(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));

            const int right = std::max(0, width() - 1);
            const int bottom = std::max(0, height() - 1);
            QPoint trianglePoints[3];
            if (m_corner == Corner::BottomLeft)
            {
                trianglePoints[0] = QPoint(0, bottom);
                trianglePoints[1] = QPoint(0, 0);
                trianglePoints[2] = QPoint(right, bottom);
            }
            else
            {
                trianglePoints[0] = QPoint(right, bottom);
                trianglePoints[1] = QPoint(right, 0);
                trianglePoints[2] = QPoint(0, bottom);
            }

            painter.drawPolygon(trianglePoints, 3);
        }

    private:
        Corner m_corner; // m_corner：标记当前控件绘制左下角还是右下角三角形。
    };

    // dockTabHoverFillColor 作用：
    // - 返回 Dock 标签悬停时强制填充的背景色；
    // - 普通标签 hover 使用弱强调底，当前选中标签 hover 继续使用活动强调底；
    // - 避免浅色模式下选中 Dock 被 hover 补绘覆盖成淡蓝色。
    // 入参 activeTab：true 表示当前标签为 ADS 选中标签。
    // 返回：当前主题和标签状态对应的 hover 背景 QColor。
    QColor dockTabHoverFillColor(const bool activeTab)
    {
        if (activeTab)
        {
            return KswordTheme::ActiveTabBackgroundColor();
        }
        return KswordTheme::PrimaryBlueSubtleColor();
    }

    // dockTabTextColor 作用：
    // - 返回 ADS Dock 标签文字的最终颜色；
    // - 选中标签根据实际活动背景自动选择可读文字色；
    // - 未选中标签沿用当前主题主文字色。
    // 入参 activeTab：true=当前选中标签；false=普通标签。
    // 返回：可直接写入 QWidget/QLabel palette 与局部样式表的 QColor。
    QColor dockTabTextColor(const bool activeTab)
    {
        if (!activeTab)
        {
            return KswordTheme::TextPrimaryColor();
        }

        // 活动标签使用专用前景色，按混合后的实际背景重新计算对比度。
        return KswordTheme::ActiveTabTextColor();
    }

    // shouldTemporarilyDropTopMostForDockSwitch：
    // - 输入：无显式输入，读取 QApplication 全局属性；
    // - 处理：只有当前进程具备 UIAccess 且主窗口全局处于 TOPMOST 时才需要临时取消；
    // - 返回：true 表示 Dock 切换前后应执行 NOTOPMOST/TOPMOST 保护，false 表示完全不干预。
    bool shouldTemporarilyDropTopMostForDockSwitch()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        return appInstance != nullptr
            && appInstance->property(kKswordProcessUiAccessPropertyName).toBool()
            && appInstance->property(kKswordMainWindowTopMostPropertyName).toBool();
    }

    // mainWindowHandleFromGlobalProperty：
    // - 输入：无显式输入，读取 QApplication 上缓存的主窗口 HWND；
    // - 处理：把 qulonglong 属性还原成 HWND，并用 IsWindow 校验；
    // - 返回：有效主窗口句柄；缺失或失效时返回 nullptr。
    HWND mainWindowHandleFromGlobalProperty()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return nullptr;
        }

        const HWND windowHandle = reinterpret_cast<HWND>(
            static_cast<quintptr>(appInstance->property(kKswordMainWindowHwndPropertyName).toULongLong()));
        return (windowHandle != nullptr && ::IsWindow(windowHandle) != FALSE) ? windowHandle : nullptr;
    }

    // setMainWindowTemporaryTopMost：
    // - 输入：topMostState 为 true 时恢复 TOPMOST，false 时临时降到 NOTOPMOST；
    // - 处理：仅调整主窗口 Win32 z-order，不修改 m_windowPinned、不改设置、不同步标题栏图钉；
    // - 返回：SetWindowPos 成功返回 true，否则 false。
    bool setMainWindowTemporaryTopMost(const bool topMostState)
    {
        const HWND windowHandle = mainWindowHandleFromGlobalProperty();
        if (windowHandle == nullptr)
        {
            return false;
        }

        return ::SetWindowPos(
            windowHandle,
            topMostState ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER) != FALSE;
    }

    // withTemporaryNonTopMostForDockSwitch：
    // - 输入：switchOperation 为实际 Dock 切换动作；
    // - 处理：仅在 UIAccess+TOPMOST 组合下，切换前临时 NOTOPMOST，切换后恢复 TOPMOST；
    // - 返回：无返回值；switchOperation 为空时只执行一次保护判断不做动作。
    void withTemporaryNonTopMostForDockSwitch(const std::function<void()>& switchOperation)
    {
        const bool shouldDropTopMost = shouldTemporarilyDropTopMostForDockSwitch();
        if (shouldDropTopMost)
        {
            setMainWindowTemporaryTopMost(false);
        }

        if (switchOperation)
        {
            switchOperation();
        }

        if (shouldDropTopMost)
        {
            QTimer::singleShot(0, []()
                {
                    if (shouldTemporarilyDropTopMostForDockSwitch())
                    {
                        setMainWindowTemporaryTopMost(true);
                    }
                });
        }
    }

    // applyDockTabTextColor 作用：
    // - 对 ADS 标签本体和内部 QLabel/CElidingLabel 直接写文字色；
    // - 绕过父级 QSS 选择器对 ADS 内部标签控件不生效或被 hover 规则覆盖的问题。
    // 入参 tabWidget：ADS 主标签或自动隐藏侧边标签。
    // 入参 activeTab：true=选中标签；false=普通标签。
    // 返回：无返回值；仅在颜色变化时更新 palette/styleSheet，避免 StyleChange 风暴。
    void applyDockTabTextColor(QWidget* tabWidget, const bool activeTab)
    {
        if (tabWidget == nullptr)
        {
            return;
        }

        const QColor finalTextColor = dockTabTextColor(activeTab);
        const QString finalTextColorName = finalTextColor.name(QColor::HexRgb).toUpper();

        if (tabWidget->property("kswordDockTabTextColor").toString() != finalTextColorName)
        {
            QPalette tabPalette = tabWidget->palette();
            tabPalette.setColor(QPalette::WindowText, finalTextColor);
            tabPalette.setColor(QPalette::Text, finalTextColor);
            tabPalette.setColor(QPalette::ButtonText, finalTextColor);
            tabWidget->setPalette(tabPalette);
            tabWidget->setProperty("kswordDockTabTextColor", finalTextColorName);
        }

        const QString labelStyle = QStringLiteral(
            "color:%1 !important;"
            "background-color:transparent !important;"
            "background:transparent !important;"
            "font-weight:%2;")
            .arg(finalTextColorName)
            .arg(activeTab ? QStringLiteral("700") : QStringLiteral("600"));

        const QList<QLabel*> labelChildren = tabWidget->findChildren<QLabel*>();
        for (QLabel* labelWidget : labelChildren)
        {
            if (labelWidget == nullptr)
            {
                continue;
            }

            QPalette labelPalette = labelWidget->palette();
            labelPalette.setColor(QPalette::WindowText, finalTextColor);
            labelPalette.setColor(QPalette::Text, finalTextColor);
            labelPalette.setColor(QPalette::ButtonText, finalTextColor);
            labelWidget->setPalette(labelPalette);

            if (labelWidget->styleSheet() != labelStyle)
            {
                labelWidget->setStyleSheet(labelStyle);
            }
        }
    }

    // configureDockTabStyleSurface 作用：
    // - 对 ADS 标签及其直接子控件启用 QSS/hover 背景绘制所需属性；
    // - 这是一次性初始化，不在事件过滤器中修改 stylesheet，避免 StyleChange 递归。
    // 入参 tabWidget：ADS 标签 QWidget；propertyName：要写入的动态属性名。
    // 返回：无返回值。
    void configureDockTabStyleSurface(QWidget* tabWidget, const char* propertyName)
    {
        if (tabWidget == nullptr || propertyName == nullptr)
        {
            return;
        }

        tabWidget->setProperty(propertyName, true);
        tabWidget->setAttribute(Qt::WA_Hover, true);
        tabWidget->setAttribute(Qt::WA_StyledBackground, true);
        tabWidget->setAutoFillBackground(false);
        tabWidget->setMouseTracking(true);

        // 子 QLabel/QWidget 是 ADS 标签文字与图标的实际承载层；
        // 只处理直接子级，避免误改 Dock 内容页内的业务控件。
        const QList<QWidget*> directChildren =
            tabWidget->findChildren<QWidget*>(QString(), Qt::FindDirectChildrenOnly);
        for (QWidget* childWidget : directChildren)
        {
            if (childWidget == nullptr)
            {
                continue;
            }
            childWidget->setAttribute(Qt::WA_Hover, true);
            childWidget->setAttribute(Qt::WA_StyledBackground, true);
            childWidget->setAutoFillBackground(false);
        }
    }

    // configureAdsDockTabVisualIdentity 作用：
    // - 同时标记一个 CDockWidget 的主标签和自动隐藏侧边标签；
    // - 用于创建后、布局恢复后、浮动窗口同步外观时的安全兜底。
    // 入参 dockWidget：待处理的 ADS Dock；为空时直接返回。
    // 返回：无返回值。
    void configureAdsDockTabVisualIdentity(ads::CDockWidget* dockWidget)
    {
        if (dockWidget == nullptr)
        {
            return;
        }

        configureDockTabStyleSurface(dockWidget->tabWidget(), kKswordDockTabPropertyName);
        configureDockTabStyleSurface(dockWidget->sideTabWidget(), kKswordAutoHideTabPropertyName);
    }

    // refreshAdsDockTabVisualIdentities 作用：
    // - 扫描某个根窗口下已经存在的 ADS 标签并补齐动态属性；
    // - 适用于 restoreState 或浮动窗口创建后产生/迁移的标签。
    // 入参 rootWidget：扫描根节点；为空时直接返回。
    // 返回：无返回值。
    void refreshAdsDockTabVisualIdentities(QWidget* rootWidget)
    {
        if (rootWidget == nullptr)
        {
            return;
        }

        const QList<ads::CDockWidgetTab*> dockTabs =
            rootWidget->findChildren<ads::CDockWidgetTab*>();
        for (ads::CDockWidgetTab* dockTab : dockTabs)
        {
            configureDockTabStyleSurface(dockTab, kKswordDockTabPropertyName);
            applyDockTabTextColor(dockTab, dockTab->property("activeTab").toBool());
        }

        const QList<ads::CAutoHideTab*> autoHideTabs =
            rootWidget->findChildren<ads::CAutoHideTab*>();
        for (ads::CAutoHideTab* autoHideTab : autoHideTabs)
        {
            configureDockTabStyleSurface(autoHideTab, kKswordAutoHideTabPropertyName);
            applyDockTabTextColor(autoHideTab, autoHideTab->property("activeTab").toBool());
        }
    }

    // updateLazyDockPlaceholderProgress 作用：
    // - 把懒加载各阶段的进度与文案刷到占位页的进度条上；
    // - 页面构造独占 UI 线程期间事件循环不会转，普通 update() 排的重绘要等到
    //   构造结束才会画（那时占位页已被替换，等于没显示过），因此这里必须
    //   repaint() 立即出图；repaint 是同步绘制、不派发事件，
    //   不存在 processEvents 那种把延迟初始化重入进来的风险。
    // 入参 dockWidget：正在初始化的 Dock；为空或占位页不可见时静默返回。
    // 入参 stageText：当前阶段文案，直接显示给用户。
    // 入参 progressPercent：0~100 的进度值，越界会被钳制。
    // 返回：无返回值。
    void updateLazyDockPlaceholderProgress(
        ads::CDockWidget* dockWidget,
        const QString& stageText,
        const int progressPercent)
    {
        if (dockWidget == nullptr)
        {
            return;
        }

        // placeholderWidget 用途：当前仍挂在 Dock 上的占位页；
        // 真实内容挂载后这里拿到的就不再是占位页，findChild 自然查不到进度条。
        QWidget* const placeholderWidget = dockWidget->widget();
        if (placeholderWidget == nullptr || !placeholderWidget->isVisible())
        {
            return;
        }

        QProgressBar* const loadProgressBar = placeholderWidget->findChild<QProgressBar*>(
            QString::fromLatin1(kLazyDockPlaceholderProgressBarObjectName));
        QLabel* const stageLabel = placeholderWidget->findChild<QLabel*>(
            QString::fromLatin1(kLazyDockPlaceholderStageLabelObjectName));
        if (loadProgressBar == nullptr && stageLabel == nullptr)
        {
            return;
        }

        if (loadProgressBar != nullptr)
        {
            loadProgressBar->setValue(qBound(0, progressPercent, 100));
        }
        if (stageLabel != nullptr)
        {
            stageLabel->setText(stageText);
        }
        placeholderWidget->repaint();
    }

    bool isDockWidgetActiveForLazyInitialization(
        ads::CDockWidget* dockWidget,
        ads::CDockWidget* focusedDockWidget)
    {
        if (dockWidget == nullptr)
        {
            return false;
        }

        if (dockWidget == focusedDockWidget || dockWidget->isCurrentTab())
        {
            return true;
        }

        ads::CDockAreaWidget* dockAreaWidget = dockWidget->dockAreaWidget();
        if (dockAreaWidget != nullptr)
        {
            return dockAreaWidget->isVisible() && dockAreaWidget->currentDockWidget() == dockWidget;
        }

        return dockWidget->isVisible();
    }

    // KswordAdsDockWidgetTab 作用：
    // - 替代 ADS 默认 CDockWidgetTab；
    // - 在 hover 时由标签自身补画深色背景，绕过 ADS/系统默认样式偶发白底。
    // 输入：构造时接收所属 CDockWidget 与可选父 QWidget。
    // 处理：初始化 QSS 识别属性；hover/leave 时只触发 repaint，不改 stylesheet。
    // 返回：构造函数无返回；event 返回基类事件处理结果；paintEvent 无返回。
    class KswordAdsDockWidgetTab final : public ads::CDockWidgetTab
    {
    public:
        explicit KswordAdsDockWidgetTab(ads::CDockWidget* dockWidget, QWidget* parent = nullptr)
            : ads::CDockWidgetTab(dockWidget, parent)
        {
            configureDockTabStyleSurface(this, kKswordDockTabPropertyName);
            syncDockTabTextColor();
            QObject::connect(
                this,
                &ads::CDockWidgetTab::activeTabChanged,
                this,
                [this]()
                {
                    syncDockTabTextColor();
                    update();
                });
        }

    protected:
        bool event(QEvent* eventObject) override
        {
            const bool shouldGuardDockSwitch =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::MouseButtonPress ||
                    eventObject->type() == QEvent::MouseButtonRelease) &&
                static_cast<QMouseEvent*>(eventObject)->button() == Qt::LeftButton &&
                !property("activeTab").toBool();
            const bool shouldRepaintAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::Enter ||
                    eventObject->type() == QEvent::Leave ||
                    eventObject->type() == QEvent::HoverEnter ||
                    eventObject->type() == QEvent::HoverLeave ||
                    eventObject->type() == QEvent::HoverMove);
            const bool shouldSyncTextAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::DynamicPropertyChange ||
                    eventObject->type() == QEvent::PaletteChange ||
                    eventObject->type() == QEvent::ApplicationPaletteChange ||
                    eventObject->type() == QEvent::StyleChange ||
                    eventObject->type() == QEvent::Polish ||
                    eventObject->type() == QEvent::Show);

            bool handled = false;
            if (shouldGuardDockSwitch)
            {
                withTemporaryNonTopMostForDockSwitch([this, eventObject, &handled]()
                    {
                        handled = ads::CDockWidgetTab::event(eventObject);
                    });
            }
            else
            {
                handled = ads::CDockWidgetTab::event(eventObject);
            }
            if (shouldSyncTextAfterEvent)
            {
                syncDockTabTextColor();
            }
            if (shouldRepaintAfterEvent)
            {
                update();
            }
            return handled;
        }

        void paintEvent(QPaintEvent* paintEventObject) override
        {
            ads::CDockWidgetTab::paintEvent(paintEventObject);
            if (!isEnabled() || !underMouse())
            {
                return;
            }

            // 在基类 QFrame/QSS 绘制之后补一层实色背景，盖掉 ADS/系统默认白底；
            // 选中标签必须保持主蓝底，避免浅色模式 hover 时变成淡蓝底。
            // 子 QLabel 会在父控件 paintEvent 返回后再绘制，因此文字不会被遮住。
            const bool activeTab = property("activeTab").toBool();
            QPainter painter(this);
            painter.setPen(Qt::NoPen);
            painter.setBrush(dockTabHoverFillColor(activeTab));
            painter.drawRect(paintEventObject != nullptr ? paintEventObject->rect() : rect());
        }

    private:
        // syncDockTabTextColor 作用：
        // - 读取 ADS activeTab 属性；
        // - 将当前主题下应使用的文字色同步到标签本体和内部 QLabel。
        // 输入：无显式入参；依赖当前对象 activeTab 动态属性和全局主题状态。
        // 返回：无返回值。
        void syncDockTabTextColor()
        {
            applyDockTabTextColor(this, property("activeTab").toBool());
        }
    };

    // KswordAdsAutoHideTab 作用：
    // - 替代 ADS 默认自动隐藏标签；
    // - 保持 ADS 原绘制逻辑，只补齐 hover/QSS 属性并在 hover 变化时触发 repaint。
    // 输入：构造时接收所属 CDockWidget 与可选父 QWidget。
    // 处理：设置 Dock 关联与样式属性；不修改 stylesheet。
    // 返回：构造函数无返回；event 返回基类事件处理结果。
    class KswordAdsAutoHideTab final : public ads::CAutoHideTab
    {
    public:
        explicit KswordAdsAutoHideTab(ads::CDockWidget* dockWidget, QWidget* parent = nullptr)
            : ads::CAutoHideTab(parent)
        {
            setDockWidget(dockWidget);
            configureDockTabStyleSurface(this, kKswordAutoHideTabPropertyName);
            syncDockTabTextColor();
        }

    protected:
        bool event(QEvent* eventObject) override
        {
            const bool shouldRepaintAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::Enter ||
                    eventObject->type() == QEvent::Leave ||
                    eventObject->type() == QEvent::HoverEnter ||
                    eventObject->type() == QEvent::HoverLeave ||
                    eventObject->type() == QEvent::HoverMove);
            const bool shouldSyncTextAfterEvent =
                eventObject != nullptr &&
                (eventObject->type() == QEvent::DynamicPropertyChange ||
                    eventObject->type() == QEvent::PaletteChange ||
                    eventObject->type() == QEvent::ApplicationPaletteChange ||
                    eventObject->type() == QEvent::StyleChange ||
                    eventObject->type() == QEvent::Polish ||
                    eventObject->type() == QEvent::Show);

            const bool handled = ads::CAutoHideTab::event(eventObject);
            if (shouldSyncTextAfterEvent)
            {
                syncDockTabTextColor();
            }
            if (shouldRepaintAfterEvent)
            {
                update();
            }
            return handled;
        }

    private:
        // syncDockTabTextColor 作用：
        // - 读取 ADS activeTab 属性；
        // - 将当前主题下应使用的文字色同步到自动隐藏标签本体和内部 QLabel。
        // 输入：无显式入参；依赖当前对象 activeTab 动态属性和全局主题状态。
        // 返回：无返回值。
        void syncDockTabTextColor()
        {
            applyDockTabTextColor(this, property("activeTab").toBool());
        }
    };

    // KswordAdsDockComponentsFactory 作用：
    // - 让 ADS 在创建 Dock 标签时使用 Ksword 自定义标签类；
    // - 保留 ADS 其它组件的默认工厂行为，降低改动面。
    // 输入：ADS 在创建标签时传入所属 CDockWidget。
    // 处理：返回自定义主标签/自动隐藏标签实例。
    // 返回：新建的 CDockWidgetTab 或 CAutoHideTab，所有权交给 ADS。
    class KswordAdsDockComponentsFactory final : public ads::CDockComponentsFactory
    {
    public:
        ads::CDockWidgetTab* createDockWidgetTab(ads::CDockWidget* dockWidget) const override
        {
            return new KswordAdsDockWidgetTab(dockWidget);
        }

        ads::CAutoHideTab* createDockWidgetSideTab(ads::CDockWidget* dockWidget) const override
        {
            return new KswordAdsAutoHideTab(dockWidget);
        }
    };

    // ensureKswordAdsDockComponentsFactoryInstalled 作用：
    // - 在 CDockManager 创建前安装一次自定义 ADS 组件工厂；
    // - 防止默认 CDockWidgetTab 在深色 hover 下继续暴露系统白底。
    // 返回：无返回值；重复调用会被静态标志忽略。
    void ensureKswordAdsDockComponentsFactoryInstalled()
    {
        static bool installed = false;
        if (installed)
        {
            return;
        }

        ads::CDockComponentsFactory::setFactory(new KswordAdsDockComponentsFactory());
        installed = true;
    }

    // Windows ZBID 常量：
    // - ZBID_DEFAULT：普通桌面窗口 band；
    // - ZBID_UIACCESS：UIAccess 令牌可尝试使用的辅助功能 band；
    // - 这里动态调用 SetWindowBand，避免旧系统/受限系统没有导出时直接链接失败。
    constexpr DWORD kWindowBandDefault = 0;
    constexpr DWORD kWindowBandUiAccess = 2;

    using SetWindowBandFunction = BOOL(WINAPI*)(HWND, HWND, DWORD);

    // resolveSetWindowBandFunction 作用：
    // - 从 user32.dll 动态解析 SetWindowBand；
    // - 该 API 不参与静态链接，失败时顶多退回 HWND_TOPMOST。
    // 返回：函数指针；不可用时返回 nullptr。
    SetWindowBandFunction resolveSetWindowBandFunction()
    {
        // cachedFunction 用途：缓存动态解析结果，避免每次图钉切换重复查询 user32 导出表。
        static const SetWindowBandFunction cachedFunction = []() -> SetWindowBandFunction {
            HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
            if (user32ModuleHandle == nullptr)
            {
                user32ModuleHandle = ::LoadLibraryW(L"user32.dll");
            }
            if (user32ModuleHandle == nullptr)
            {
                return nullptr;
            }

            return reinterpret_cast<SetWindowBandFunction>(
                ::GetProcAddress(user32ModuleHandle, "SetWindowBand"));
        }();
        return cachedFunction;
    }

    // isCurrentProcessUiAccessTokenEnabled 作用：
    // - 查询当前进程令牌是否已经启用 TokenUIAccess；
    // - 只有带 UIAccess 时才尝试 UIAccess band，避免普通权限无意义调用。
    // 返回：true=当前实例已带 UIAccess；false=普通令牌或查询失败。
    bool isCurrentProcessUiAccessTokenEnabled()
    {
        // enabled 用途：TokenUIAccess 在进程生命周期内固定，首次查询后缓存结果即可。
        static const bool enabled = []() -> bool {
            HANDLE tokenHandle = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
            {
                return false;
            }

            DWORD uiAccessValue = 0;
            DWORD returnedLength = 0;
            const BOOL queryOk = ::GetTokenInformation(
                tokenHandle,
                TokenUIAccess,
                &uiAccessValue,
                sizeof(uiAccessValue),
                &returnedLength);
            ::CloseHandle(tokenHandle);
            return queryOk != FALSE && uiAccessValue != 0;
        }();
        return enabled;
    }

    // tryApplyUiAccessWindowBand 作用：
    // - 当当前进程已经带 UIAccess 位时，尝试把窗口放入 UIAccess band；
    // - 取消置顶时尝试恢复 DEFAULT band；
    // - 这是 best-effort：系统策略拒绝时仍保留 HWND_TOPMOST/NOTOPMOST 主路径。
    // 入参 windowHandle：主窗口 HWND；
    // 入参 pinnedState：true=尝试 UIAccess+TopMost，false=尝试恢复默认 band。
    // 返回：true=成功切换 band；false=未启用 UIAccess、API 不可用或系统拒绝。
    bool tryApplyUiAccessWindowBand(const HWND windowHandle, const bool pinnedState)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return false;
        }

        if (!isCurrentProcessUiAccessTokenEnabled())
        {
            return false;
        }

        const SetWindowBandFunction setWindowBand = resolveSetWindowBandFunction();
        if (setWindowBand == nullptr)
        {
            return false;
        }

        // targetBand 用途：置顶时尝试 UIAccess band，取消置顶时回落普通 DEFAULT band。
        const DWORD targetBand = pinnedState ? kWindowBandUiAccess : kWindowBandDefault;
        // insertAfterHandle 用途：UIAccess band 内仍要求尽量排到最前；恢复默认时取消置顶。
        const HWND insertAfterHandle = pinnedState ? HWND_TOPMOST : HWND_NOTOPMOST;
        return setWindowBand(windowHandle, insertAfterHandle, targetBand) != FALSE;
    }

    // applyHighestPermittedTopMostLevel 作用：
    // - 在当前进程权限允许范围内把主窗口提升到最高可达置顶层级；
    // - UIAccess 令牌优先尝试 UIAccess band + HWND_TOPMOST，普通令牌退回 HWND_TOPMOST；
    // - 额外尝试 BringWindowToTop/SetForegroundWindow，把同层级排序尽量推到最前；
    // - 前台权限可能被系统策略拒绝，拒绝时不影响 HWND_TOPMOST 结果。
    // 调用方式：MainWindow::setPinnedWindowState 内部调用。
    // 入参 windowHandle：主窗口 HWND；
    // 入参 pinnedState：true=置顶并尽量提升到顶层，false=取消置顶；
    // 入参 errorCodeOut：SetWindowPos 失败时输出 GetLastError。
    // 入参 uiAccessBandAppliedOut：可选输出是否成功应用 UIAccess band。
    // 返回：true=核心置顶/取消置顶成功，false=SetWindowPos 失败。
    bool applyHighestPermittedTopMostLevel(
        const HWND windowHandle,
        const bool pinnedState,
        DWORD* errorCodeOut,
        bool* uiAccessBandAppliedOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (uiAccessBandAppliedOut != nullptr)
        {
            *uiAccessBandAppliedOut = false;
        }

        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_WINDOW_HANDLE;
            }
            return false;
        }

        // UIAccess band 用途：若当前实例已带 UIAccess，先尝试更高的辅助功能窗口 band。
        // 失败不作为核心错误，因为普通 HWND_TOPMOST 仍是公开稳定兜底路径。
        const bool uiAccessBandApplied = tryApplyUiAccessWindowBand(windowHandle, pinnedState);
        if (uiAccessBandAppliedOut != nullptr)
        {
            *uiAccessBandAppliedOut = uiAccessBandApplied;
        }

        // insertAfterHandle 用途：选择 Win32 公开 z-order 中当前权限可操作的最高置顶层级。
        const HWND insertAfterHandle = pinnedState ? HWND_TOPMOST : HWND_NOTOPMOST;
        // setWindowPositionFlags 用途：构造期也可能调用置顶，禁止 SWP_SHOWWINDOW 提前显示半初始化窗口。
        const UINT setWindowPositionFlags = SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE;

        const BOOL setTopMostResult = ::SetWindowPos(
            windowHandle,
            insertAfterHandle,
            0,
            0,
            0,
            0,
            setWindowPositionFlags);
        if (setTopMostResult == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        if (pinnedState)
        {
            // 当前权限若允许前台切换，则把窗口移动到同层级最前；失败不回滚置顶状态。
            ::BringWindowToTop(windowHandle);
            ::SetForegroundWindow(windowHandle);
        }
        return true;
    }

    // isKswordPopupTopMostTrackingEnabled 作用：
    // - 输入：无；
    // - 处理：从 QApplication 属性读取主窗口当前是否置顶；
    // - 返回：true 表示后续弹出的 QDialog/QMenu 也应保持 TOPMOST，避免被主窗口遮住。
    bool isKswordPopupTopMostTrackingEnabled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        return appInstance != nullptr
            && appInstance->property(kKswordMainWindowTopMostPropertyName).toBool();
    }

    // applyTopMostToTopLevelWidget 作用：
    // - 输入 widget：Qt 顶层窗口；topMostState：目标置顶状态；
    // - 处理：把弹窗、新建工具窗、详情窗等顶层窗口同步为 TOPMOST/NOTOPMOST；
    // - 返回：无返回值；失败静默，因为置顶同步不应阻断原有窗口生命周期。
    void applyTopMostToTopLevelWidget(QWidget* widget, const bool topMostState)
    {
        if (widget == nullptr || !widget->isWindow())
        {
            return;
        }

        const HWND windowHandle = reinterpret_cast<HWND>(widget->winId());
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return;
        }

        (void)::SetWindowPos(
            windowHandle,
            topMostState ? HWND_TOPMOST : HWND_NOTOPMOST,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_NOOWNERZORDER);
    }

    // syncTopMostForAllAuxiliaryTopLevelWidgets 作用：
    // - 输入 mainWindow：主窗口指针；topMostState：目标置顶状态；
    // - 处理：遍历当前 Qt 顶层窗口，除主窗口外统一继承或取消置顶；
    // - 返回：无返回值。
    void syncTopMostForAllAuxiliaryTopLevelWidgets(QWidget* mainWindow, const bool topMostState)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        const QWidgetList topLevelWidgetList = appInstance->topLevelWidgets();
        for (QWidget* widget : topLevelWidgetList)
        {
            if (widget == nullptr || widget == mainWindow)
            {
                continue;
            }
            applyTopMostToTopLevelWidget(widget, topMostState);
        }
    }

    // applyAppBarAwareMaximizedBounds 作用：
    // - 输入 windowHandle：收到 WM_GETMINMAXINFO 的顶层窗口句柄；
    // - 输入 minMaxInfo：系统传入的最大化尺寸/位置结构；
    // - 处理：读取窗口所在显示器的 rcMonitor 与 rcWork，并把最大化矩形限制到 rcWork；
    // - 返回：true 表示已经写入 AppBar/任务栏感知的最大化约束，false 表示参数或系统查询失败。
    bool applyAppBarAwareMaximizedBounds(
        const HWND windowHandle,
        MINMAXINFO* const minMaxInfo)
    {
        if (windowHandle == nullptr ||
            ::IsWindow(windowHandle) == FALSE ||
            minMaxInfo == nullptr)
        {
            return false;
        }

        // monitorHandle 用途：选择离当前窗口最近的显示器，兼容多屏与窗口跨屏场景。
        const HMONITOR monitorHandle = ::MonitorFromWindow(
            windowHandle,
            MONITOR_DEFAULTTONEAREST);
        if (monitorHandle == nullptr)
        {
            return false;
        }

        // monitorInfo 用途：
        // - rcMonitor 是完整物理显示器矩形；
        // - rcWork 是扣除任务栏/AppBar 后的可用工作区。
        MONITORINFO monitorInfo = {};
        monitorInfo.cbSize = sizeof(monitorInfo);
        if (::GetMonitorInfoW(monitorHandle, &monitorInfo) == FALSE)
        {
            return false;
        }

        const RECT& monitorRect = monitorInfo.rcMonitor;
        const RECT& workRect = monitorInfo.rcWork;
        const LONG workWidth = workRect.right - workRect.left;
        const LONG workHeight = workRect.bottom - workRect.top;
        if (workWidth <= 0 || workHeight <= 0)
        {
            return false;
        }

        // ptMaxPosition 是相对当前 monitor 左上角的最大化偏移：
        // - 顶部 AppBar 时 rcWork.top > rcMonitor.top，这里会把 Y 修正为任务栏高度；
        // - 底部任务栏时 top 通常为 0，只缩小高度，不改变 Y。
        minMaxInfo->ptMaxPosition.x = workRect.left - monitorRect.left;
        minMaxInfo->ptMaxPosition.y = workRect.top - monitorRect.top;

        // ptMaxSize 是最大化后的客户外框尺寸，必须与工作区尺寸一致。
        // 若只改高度而不改 ptMaxPosition，就会出现顶部遮挡、底部空隙的问题。
        minMaxInfo->ptMaxSize.x = workWidth;
        minMaxInfo->ptMaxSize.y = workHeight;

        // ptMaxTrackSize 限制用户拖拽/系统最大化时的最大跟踪尺寸，和工作区保持一致。
        minMaxInfo->ptMaxTrackSize.x = workWidth;
        minMaxInfo->ptMaxTrackSize.y = workHeight;
        return true;
    }

    // comboBoxForPopupView 作用：
    // - 输入：QComboBox 弹出列表使用的 QAbstractItemView；
    // - 处理：先按 QObject 父链定位所属组合框，再以 QApplication 控件集合兜底；
    // - 返回：所属组合框，无法确认时返回 nullptr。
    QComboBox* comboBoxForPopupView(QAbstractItemView* const itemView)
    {
        if (itemView == nullptr)
        {
            return nullptr;
        }

        for (QObject* currentObject = itemView; currentObject != nullptr; currentObject = currentObject->parent())
        {
            if (QComboBox* const comboBox = qobject_cast<QComboBox*>(currentObject))
            {
                return comboBox;
            }
        }

        QWidget* const popupWindow = itemView->window();
        if (popupWindow == nullptr || !popupWindow->windowFlags().testFlag(Qt::Popup))
        {
            return nullptr;
        }

        const QWidgetList allWidgetList = QApplication::allWidgets();
        for (QWidget* const widget : allWidgetList)
        {
            QComboBox* const comboBox = qobject_cast<QComboBox*>(widget);
            if (comboBox != nullptr && comboBox->view() == itemView)
            {
                return comboBox;
            }
        }
        return nullptr;
    }

    // applyOpaqueComboPopupPalette 作用：
    // - 输入：组合框 Popup 容器、列表视图或 viewport；
    // - 处理：写入不透明背景与完整前景/选中态调色板，并启用背景填充；
    // - 返回：无。QSS 不生效或平台 style 回退时，调色板仍能避免黑底。
    void applyOpaqueComboPopupPalette(QWidget* const targetWidget)
    {
        if (targetWidget == nullptr)
        {
            return;
        }

        const QColor backgroundColor = KswordTheme::SurfaceColor();
        QPalette popupPalette = targetWidget->palette();
        popupPalette.setColor(QPalette::Window, backgroundColor);
        popupPalette.setColor(QPalette::Base, backgroundColor);
        popupPalette.setColor(QPalette::AlternateBase, backgroundColor);
        popupPalette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        popupPalette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        popupPalette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        popupPalette.setColor(QPalette::Highlight, KswordTheme::ControlAccentColor());
        popupPalette.setColor(
            QPalette::HighlightedText,
            KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
        popupPalette.setColor(QPalette::Mid, KswordTheme::BorderColor());
        if (targetWidget->palette() != popupPalette)
        {
            targetWidget->setPalette(popupPalette);
        }
        if (!targetWidget->autoFillBackground())
        {
            targetWidget->setAutoFillBackground(true);
        }
        if (!targetWidget->testAttribute(Qt::WA_StyledBackground))
        {
            targetWidget->setAttribute(Qt::WA_StyledBackground, true);
        }
    }

    // comboPopupViewStyle 作用：
    // - 生成直接写入 QComboBox Popup 视图的局部样式；
    // - Popup 是独立顶层窗口，不能依赖 MainWindow 的后代选择器继承背景；
    // - 所有组合框使用当前主题的不透明列表底色；已有直接 Popup 样式的业务控件仍会保留其专用视图规则。
    QString comboPopupViewStyle()
    {
        return KswordTheme::ThemedComboBoxPopupViewStyle();
    }

    // applyOpaqueComboPopupTheme 作用：
    // - 输入：任意 QComboBox；
    // - 处理：直接主题化其 Popup QFrame、列表视图及 viewport；
    // - 返回：无。绕开 Qt Popup 顶层窗口不继承主窗口 QSS 的限制。
    void applyOpaqueComboPopupTheme(QComboBox* const comboBox)
    {
        if (comboBox == nullptr)
        {
            return;
        }

        QAbstractItemView* const itemView = comboBox->view();
        if (itemView == nullptr)
        {
            return;
        }

        QWidget* const popupContainer = itemView->window();
        const bool hasDedicatedPopupContainer =
            popupContainer != nullptr &&
            popupContainer != comboBox &&
            popupContainer->windowFlags().testFlag(Qt::Popup);

        const bool autoThemed = itemView->property(kKswordComboPopupAutoThemedPropertyName).toBool();
        if (!autoThemed && !itemView->styleSheet().trimmed().isEmpty())
        {
            return;
        }

        if (hasDedicatedPopupContainer)
        {
            applyOpaqueComboPopupPalette(popupContainer);
            const QString popupContainerStyle = QStringLiteral(
                "QFrame{"
                "  background-color:%1 !important;"
                "  color:%2 !important;"
                "  border:1px solid %3 !important;"
                "}")
                .arg(KswordTheme::SurfaceColorHex())
                .arg(KswordTheme::TextPrimaryColorHex())
                .arg(KswordTheme::BorderColorHex());
            if (popupContainer->styleSheet() != popupContainerStyle)
            {
                popupContainer->setStyleSheet(popupContainerStyle);
            }
        }

        applyOpaqueComboPopupPalette(itemView);
        const QString itemViewStyle = comboPopupViewStyle();
        if (itemView->styleSheet() != itemViewStyle)
        {
            itemView->setStyleSheet(itemViewStyle);
        }
        applyOpaqueComboPopupPalette(itemView->viewport());
        itemView->setProperty(kKswordComboPopupAutoThemedPropertyName, true);
    }

    // scheduleOpaqueComboPopupTheme 作用：
    // - QComboBox Popup 的 Show 事件发生在 QWidgetPrivate::showChildren 遍历内部子对象期间；
    // - palette/QSS 可能触发 repolish 并重建滚动条等子控件，因此必须等当前 Show 分发完成后再更新；
    // - 以组合框动态属性合并同一轮 Popup 容器、视图及 viewport 产生的重复 Show 事件。
    void scheduleOpaqueComboPopupTheme(QComboBox* const comboBox)
    {
        if (comboBox == nullptr ||
            comboBox->property(kKswordComboPopupThemeUpdatePendingPropertyName).toBool())
        {
            return;
        }

        comboBox->setProperty(kKswordComboPopupThemeUpdatePendingPropertyName, true);
        const QPointer<QComboBox> guardedComboBox(comboBox);
        QTimer::singleShot(0, comboBox, [guardedComboBox]()
        {
            if (guardedComboBox.isNull())
            {
                return;
            }
            guardedComboBox->setProperty(kKswordComboPopupThemeUpdatePendingPropertyName, false);
            applyOpaqueComboPopupTheme(guardedComboBox.data());
        });
    }

    // GlobalComboPopupThemeFilter 作用：
    // - 监听应用范围内的控件显示事件；
    // - 对新建、懒加载和主题切换后的普通组合框，在当前 Show 分发结束后更新 Popup 主题；
    // - 组合框本体可保留业务局部样式，但只要 Popup 没有直接样式就统一补齐不透明列表表面。
    class GlobalComboPopupThemeFilter final : public QObject
    {
    public:
        explicit GlobalComboPopupThemeFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (eventObject->type() != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* const watchedWidget = qobject_cast<QWidget*>(watchedObject);
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(watchedObject);
            if (itemView == nullptr)
            {
                if (watchedWidget != nullptr)
                {
                    itemView = watchedWidget->findChild<QAbstractItemView*>();
                }
            }

            scheduleOpaqueComboPopupTheme(comboBoxForPopupView(itemView));
            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // GlobalContextMenuThemeFilter 作用：
    // - 在应用层拦截所有 QMenu 的显示/样式变化事件；
    // - 对“未显式设置样式”的菜单自动套用统一主题样式，避免遗漏单点 setStyleSheet。
    class GlobalContextMenuThemeFilter final : public QObject
    {
    public:
        explicit GlobalContextMenuThemeFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            if (eventType != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QMenu* menuWidget = qobject_cast<QMenu*>(watchedObject);
            if (menuWidget == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // 仅自动处理“未显式设置样式”的菜单；已手工定制的菜单保持原样。
            // 对自动处理过的菜单，每次显示都刷新一次，保证深浅色切换后立即生效。
            const bool autoThemedByKsword =
                menuWidget->property("ksword_auto_context_menu_themed").toBool();
            const bool noExplicitMenuStyle = menuWidget->styleSheet().trimmed().isEmpty();
            if (noExplicitMenuStyle || autoThemedByKsword)
            {
                menuWidget->setStyleSheet(KswordTheme::ContextMenuStyle());
                menuWidget->setProperty("ksword_auto_context_menu_themed", true);
            }
            if (isKswordPopupTopMostTrackingEnabled())
            {
                applyTopMostToTopLevelWidget(menuWidget, true);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // GlobalTopLevelTopMostFilter 作用：
    // - 输入：QApplication 全局事件流；
    // - 处理：主窗口置顶时，对所有后续显示的顶层窗口同步 HWND_TOPMOST；
    // - 返回：始终交回 Qt 默认处理，不吞事件。
    class GlobalTopLevelTopMostFilter final : public QObject
    {
    public:
        explicit GlobalTopLevelTopMostFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            if (eventType != QEvent::Show && eventType != QEvent::WindowActivate)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWidget* widget = qobject_cast<QWidget*>(watchedObject);
            if (widget == nullptr || widget->isWindow() == false)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (isKswordPopupTopMostTrackingEnabled())
            {
                applyTopMostToTopLevelWidget(widget, true);
            }

            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    QIcon contrastIconForSelectedTab(const QIcon& sourceIcon)
    {
        if (sourceIcon.isNull())
        {
            return sourceIcon;
        }

        // 原生 QTabBar 没有 QSS 图标着色能力，这里按当前图标蒙版生成白色版本。
        const QSize iconSize(16, 16);
        QPixmap sourcePixmap = sourceIcon.pixmap(iconSize);
        if (sourcePixmap.isNull())
        {
            return sourceIcon;
        }

        QPixmap contrastPixmap(iconSize);
        contrastPixmap.fill(Qt::transparent);
        QPainter painter(&contrastPixmap);
        painter.setRenderHint(QPainter::Antialiasing, true);
        painter.drawPixmap(0, 0, sourcePixmap);
        painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
        painter.fillRect(contrastPixmap.rect(), KswordTheme::OnAccentColor());
        painter.end();
        return QIcon(contrastPixmap);
    }

    class GlobalTabIconContrastFilter final : public QObject
    {
    public:
        explicit GlobalTabIconContrastFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QTabBar* tabBar = qobject_cast<QTabBar*>(watchedObject);
            if (tabBar == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            const QEvent::Type eventType = eventObject->type();
            if (eventType == QEvent::Destroy)
            {
                m_originalIconsByTabBar.erase(tabBar);
                m_displayIconsByTabBar.erase(tabBar);
                m_contrastIconsByTabBar.erase(tabBar);
                return QObject::eventFilter(watchedObject, eventObject);
            }
            if (eventType == QEvent::Show
                || eventType == QEvent::Polish
                || eventType == QEvent::StyleChange)
            {
                configureAdaptiveTabBar(tabBar);
            }
            if (eventType != QEvent::Show
                && eventType != QEvent::Polish
                && eventType != QEvent::StyleChange
                && eventType != QEvent::PaletteChange
                && eventType != QEvent::LayoutRequest
                && eventType != QEvent::ChildAdded
                && eventType != QEvent::ChildRemoved)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            refreshTabBarIcons(tabBar);
            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        void configureAdaptiveTabBar(QTabBar* tabBar)
        {
            if (tabBar == nullptr || tabBar->property("ksword_adaptive_tabbar_configured").toBool())
            {
                return;
            }

            tabBar->setProperty("ksword_adaptive_tabbar_configured", true);
            tabBar->setExpanding(false);
            tabBar->setUsesScrollButtons(true);
            tabBar->setElideMode(Qt::ElideNone);
            QObject::connect(tabBar, &QTabBar::currentChanged, tabBar, [this, tabBar](int)
            {
                refreshTabBarIcons(tabBar);
            });

            // 仅在首次配置后执行一次“回到最左”的初始化，确保启动时空间不足也先显示最左侧 Tab。
            // 后续窗口缩放不再重复执行，避免影响用户手动滚动位置。
            if (!tabBar->property("ksword_initial_left_edge_synced").toBool())
            {
                tabBar->setProperty("ksword_initial_left_edge_synced", true);
                QTimer::singleShot(0, tabBar, [tabBar]() {
                    const QList<QToolButton*> scrollButtons = tabBar->findChildren<QToolButton*>();
                    for (QToolButton* button : scrollButtons)
                    {
                        if (button == nullptr || !button->isVisible() || !button->isEnabled())
                        {
                            continue;
                        }
                        if (button->arrowType() == Qt::LeftArrow)
                        {
                            while (button->isEnabled())
                            {
                                button->click();
                            }
                            break;
                        }
                    }
                });
            }
        }

        void refreshTabBarIcons(QTabBar* tabBar)
        {
            if (tabBar == nullptr || tabBar->count() <= 0)
            {
                return;
            }

            QList<QIcon>& originalIconList = m_originalIconsByTabBar[tabBar];
            QList<QIcon>& displayIconList = m_displayIconsByTabBar[tabBar];
            QList<QIcon>& contrastIconList = m_contrastIconsByTabBar[tabBar];
            while (originalIconList.size() < tabBar->count())
            {
                originalIconList.push_back(QIcon());
                displayIconList.push_back(QIcon());
                contrastIconList.push_back(QIcon());
            }
            while (originalIconList.size() > tabBar->count())
            {
                originalIconList.removeLast();
                displayIconList.removeLast();
                contrastIconList.removeLast();
            }

            const int selectedIndex = tabBar->currentIndex();
            for (int tabIndex = 0; tabIndex < tabBar->count(); ++tabIndex)
            {
                const QIcon currentIcon = tabBar->tabIcon(tabIndex);
                const bool currentIconWasAppliedByFilter = !displayIconList[tabIndex].isNull()
                    && currentIcon.cacheKey() == displayIconList[tabIndex].cacheKey();
                if (originalIconList[tabIndex].isNull())
                {
                    originalIconList[tabIndex] = currentIcon;
                    contrastIconList[tabIndex] = QIcon();
                }
                else if (tabIndex != selectedIndex
                    && !currentIconWasAppliedByFilter
                    && !currentIcon.isNull()
                    && currentIcon.cacheKey() != originalIconList[tabIndex].cacheKey())
                {
                    originalIconList[tabIndex] = currentIcon;
                    contrastIconList[tabIndex] = QIcon();
                }

                const QIcon originalIcon = originalIconList[tabIndex];
                if (originalIcon.isNull())
                {
                    continue;
                }
                if (contrastIconList[tabIndex].isNull())
                {
                    contrastIconList[tabIndex] = contrastIconForSelectedTab(originalIcon);
                }

                const QIcon displayIcon = tabIndex == selectedIndex
                    ? contrastIconList[tabIndex]
                    : originalIcon;
                if (currentIcon.cacheKey() != displayIcon.cacheKey())
                {
                    tabBar->setTabIcon(tabIndex, displayIcon);
                }
                displayIconList[tabIndex] = displayIcon;
            }
        }

        std::unordered_map<QTabBar*, QList<QIcon>> m_originalIconsByTabBar;
        std::unordered_map<QTabBar*, QList<QIcon>> m_displayIconsByTabBar;
        std::unordered_map<QTabBar*, QList<QIcon>> m_contrastIconsByTabBar;
    };

    class GlobalSliderWheelFilter final : public QObject
    {
    public:
        explicit GlobalSliderWheelFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (watchedObject == nullptr || eventObject == nullptr || eventObject->type() != QEvent::Wheel)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            QWheelEvent* wheelEvent = static_cast<QWheelEvent*>(eventObject);
            if (trySmoothScroll(watchedObject, wheelEvent))
            {
                return true;
            }

            QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
            const bool sliderWheelAdjustEnabled = appInstance != nullptr
                && appInstance->property("ksword_slider_wheel_adjust_enabled").toBool();
            if (sliderWheelAdjustEnabled)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // 只禁止 QSlider 这类“数值滑块”的滚轮调值，不能拦截 QScrollBar，否则页面滚动会失效。
            if (qobject_cast<QScrollBar*>(watchedObject) != nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            if (qobject_cast<QAbstractSlider*>(watchedObject) == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            eventObject->ignore();
            return true;
        }

    private:
        bool trySmoothScroll(QObject* watchedObject, QWheelEvent* wheelEvent)
        {
            if (wheelEvent == nullptr || wheelEvent->modifiers().testFlag(Qt::ControlModifier))
            {
                return false;
            }

            if (isItemViewWheelEvent(watchedObject))
            {
                return false;
            }

            if (isSmoothScrollDisabled(watchedObject))
            {
                return false;
            }

            QScrollBar* targetScrollBar = findTargetScrollBar(watchedObject, wheelEvent);
            if (targetScrollBar == nullptr || targetScrollBar->minimum() == targetScrollBar->maximum())
            {
                return false;
            }

            const int wheelDelta = !wheelEvent->pixelDelta().isNull()
                ? wheelEvent->pixelDelta().y()
                : wheelEvent->angleDelta().y() / 8;
            if (wheelDelta == 0)
            {
                return false;
            }

            // 动画步长保持克制：让滚轮有平滑过渡，但不拖慢大量表格的快速浏览。
            const int lineStep = std::max(18, targetScrollBar->singleStep() * 3);
            const int targetValue = std::clamp(
                targetScrollBar->value() - wheelDelta * lineStep / 15,
                targetScrollBar->minimum(),
                targetScrollBar->maximum());
            animateScrollBar(targetScrollBar, targetValue);
            wheelEvent->accept();
            return true;
        }

        bool isItemViewWheelEvent(QObject* watchedObject) const
        {
            // isItemViewWheelEvent 作用：
            // - 判断滚轮事件是否来自 QTableView/QTableWidget/QTreeView/QListView 等 item view 或其 viewport/滚动条子控件；
            // - item view 的滚动条 value 往往是“行号/项号”，不是像素，不能用全局像素平滑算法放大处理；
            // - 返回 true 时交回 Qt 默认 wheelEvent，让表格/树/列表按自身 singleStep/pageStep 正常滚动。
            // 参数 watchedObject：QApplication 全局事件过滤器收到的事件源。
            // 返回值：true=应跳过全局 smooth-scroll；false=可以继续尝试全局 smooth-scroll。
            QObject* currentObject = watchedObject;
            while (currentObject != nullptr)
            {
                if (qobject_cast<QAbstractItemView*>(currentObject) != nullptr)
                {
                    return true;
                }

                QWidget* currentWidget = qobject_cast<QWidget*>(currentObject);
                currentObject = currentWidget != nullptr
                    ? currentWidget->parentWidget()
                    : currentObject->parent();
            }
            return false;
        }

        bool isSmoothScrollDisabled(QObject* watchedObject) const
        {
            // isSmoothScrollDisabled 作用：
            // - 允许高频表格局部关闭全局滚轮动画，恢复 Qt 默认滚动；
            // - 输入为 QApplication 事件过滤器收到的 watchedObject；
            // - 处理时沿 QWidget 父链查找属性，兼容 viewport、表格本体和滚动条三类命中点；
            // - 返回 true 表示不接管滚轮事件，不创建 QPropertyAnimation。
            QObject* currentObject = watchedObject;
            while (currentObject != nullptr)
            {
                if (currentObject->property("ksword_disable_smooth_scroll").toBool())
                {
                    return true;
                }

                QWidget* currentWidget = qobject_cast<QWidget*>(currentObject);
                currentObject = currentWidget != nullptr
                    ? currentWidget->parentWidget()
                    : currentObject->parent();
            }
            return false;
        }

        QScrollBar* findTargetScrollBar(QObject* watchedObject, QWheelEvent* wheelEvent) const
        {
            if (qobject_cast<QAbstractSlider*>(watchedObject) != nullptr
                && qobject_cast<QScrollBar*>(watchedObject) == nullptr)
            {
                return nullptr;
            }

            QScrollBar* directScrollBar = qobject_cast<QScrollBar*>(watchedObject);
            if (directScrollBar != nullptr)
            {
                return directScrollBar;
            }

            QWidget* sourceWidget = qobject_cast<QWidget*>(watchedObject);
            QWidget* currentWidget = sourceWidget;
            while (currentWidget != nullptr)
            {
                QAbstractScrollArea* scrollArea = qobject_cast<QAbstractScrollArea*>(currentWidget);
                if (scrollArea != nullptr)
                {
                    return chooseScrollBar(scrollArea, wheelEvent);
                }
                currentWidget = currentWidget->parentWidget();
            }
            return nullptr;
        }

        QScrollBar* chooseScrollBar(QAbstractScrollArea* scrollArea, QWheelEvent* wheelEvent) const
        {
            if (scrollArea == nullptr || wheelEvent == nullptr)
            {
                return nullptr;
            }

            if (std::abs(wheelEvent->angleDelta().x()) > std::abs(wheelEvent->angleDelta().y()))
            {
                QScrollBar* horizontalScrollBar = scrollArea->horizontalScrollBar();
                if (horizontalScrollBar != nullptr && horizontalScrollBar->minimum() != horizontalScrollBar->maximum())
                {
                    return horizontalScrollBar;
                }
            }
            return scrollArea->verticalScrollBar();
        }

        void animateScrollBar(QScrollBar* targetScrollBar, const int targetValue)
        {
            if (targetScrollBar == nullptr)
            {
                return;
            }

            QPointer<QPropertyAnimation>& animationRef = m_scrollAnimationByBar[targetScrollBar];
            if (animationRef == nullptr)
            {
                animationRef = new QPropertyAnimation(targetScrollBar, "value", targetScrollBar);
                animationRef->setDuration(110);
                animationRef->setEasingCurve(QEasingCurve::OutCubic);
            }

            animationRef->stop();
            animationRef->setStartValue(targetScrollBar->value());
            animationRef->setEndValue(targetValue);
            animationRef->start();
        }

        std::unordered_map<QScrollBar*, QPointer<QPropertyAnimation>> m_scrollAnimationByBar;
    };

    // TableSelectionOutlineDelegate 作用：
    // - 接管未定制 delegate 的 QTableView/QTableWidget 选中绘制；
    // - 清除 Qt 默认的 Highlight 填充，保留模型自身的背景色；
    // - 选中时绘制 3px 主题色整行边框。
    class TableSelectionOutlineDelegate final : public QStyledItemDelegate
    {
    public:
        explicit TableSelectionOutlineDelegate(QTableView* tableView)
            : QStyledItemDelegate(tableView)
            , m_tableView(tableView)
        {
        }

        void paint(QPainter* painter, const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QStyleOptionViewItem itemOption(option);
            const bool rowSelected = (itemOption.state & QStyle::State_Selected) != 0;

            // QSS 的 transparent 背景不会阻止原生 style 使用 Highlight 填充。
            // 在调用基类前清除选中状态，才可保留交替行色及模型 BackgroundRole。
            itemOption.state &= ~QStyle::State_Selected;
            itemOption.state &= ~QStyle::State_HasFocus;
            QStyledItemDelegate::paint(painter, itemOption, index);

            if (rowSelected)
            {
                drawRowSelectionOutline(painter, option, index);
            }
        }

    private:
        void drawRowSelectionOutline(
            QPainter* painter,
            const QStyleOptionViewItem& option,
            const QModelIndex& index) const
        {
            if (painter == nullptr || m_tableView == nullptr || !index.isValid())
            {
                return;
            }

            QHeaderView* headerView = m_tableView->horizontalHeader();
            const QAbstractItemModel* model = index.model();
            if (headerView == nullptr || model == nullptr)
            {
                return;
            }

            int firstVisibleVisualIndex = std::numeric_limits<int>::max();
            int lastVisibleVisualIndex = std::numeric_limits<int>::min();
            const int columnCount = model->columnCount(index.parent());
            for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
            {
                if (m_tableView->isColumnHidden(columnIndex))
                {
                    continue;
                }

                const int visualIndex = headerView->visualIndex(columnIndex);
                if (visualIndex < 0)
                {
                    continue;
                }
                firstVisibleVisualIndex = std::min(firstVisibleVisualIndex, visualIndex);
                lastVisibleVisualIndex = std::max(lastVisibleVisualIndex, visualIndex);
            }

            const int currentVisualIndex = headerView->visualIndex(index.column());
            if (currentVisualIndex < 0 ||
                firstVisibleVisualIndex == std::numeric_limits<int>::max() ||
                lastVisibleVisualIndex == std::numeric_limits<int>::min())
            {
                return;
            }

            const QRect borderRect = option.rect.adjusted(0, 1, -1, -2);
            if (!borderRect.isValid())
            {
                return;
            }

            painter->save();
            painter->setRenderHint(QPainter::Antialiasing, false);
            painter->setBrush(Qt::NoBrush);
            painter->setPen(QPen(KswordTheme::PrimaryBlueColor, 3.0));
            painter->drawLine(borderRect.topLeft(), borderRect.topRight());
            painter->drawLine(borderRect.bottomLeft(), borderRect.bottomRight());
            if (currentVisualIndex == firstVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topLeft(), borderRect.bottomLeft());
            }
            if (currentVisualIndex == lastVisibleVisualIndex)
            {
                painter->drawLine(borderRect.topRight(), borderRect.bottomRight());
            }
            painter->restore();
        }

        QPointer<QTableView> m_tableView;
    };

    // TableSelectionOutlineProxyStyle 作用：
    // - 在原生 style 层统一移除 QTableView/QTableWidget 的默认选中填充；
    // - 作为 delegate 的兜底，覆盖第三方或运行期替换 delegate 后重新出现的 Highlight；
    // - 处理 CE_ItemViewItem 与 PE_PanelItemViewRow，不干预 QHeaderView 的 CE_Header* 绘制和调色板。
    class TableSelectionOutlineProxyStyle final : public QProxyStyle
    {
    public:
        TableSelectionOutlineProxyStyle()
            : QProxyStyle(QStringLiteral("windowsvista"))
        {
        }

        void drawControl(
            const ControlElement element,
            const QStyleOption* option,
            QPainter* painter,
            const QWidget* widget = nullptr) const override
        {
            if (element == CE_ItemViewItem &&
                option != nullptr &&
                qobject_cast<const QTableView*>(widget) != nullptr)
            {
                if (const auto* itemOption = qstyleoption_cast<const QStyleOptionViewItem*>(option))
                {
                    QStyleOptionViewItem unselectedOption(*itemOption);
                    unselectedOption.state &= ~QStyle::State_Selected;
                    unselectedOption.state &= ~QStyle::State_HasFocus;
                    QProxyStyle::drawControl(element, &unselectedOption, painter, widget);
                    return;
                }
            }

            QProxyStyle::drawControl(element, option, painter, widget);
        }

        void drawPrimitive(
            const PrimitiveElement element,
            const QStyleOption* option,
            QPainter* painter,
            const QWidget* widget = nullptr) const override
        {
            // QTableView 会在 delegate 绘制前先绘制 PE_PanelItemViewRow。
            // QStyleSheetStyle 遇到透明 item 背景时会回退到该基础 style，
            // 因而仅在 CE_ItemViewItem 清除 State_Selected 仍会留下 Highlight 整行填充。
            if (element == PE_PanelItemViewRow &&
                option != nullptr &&
                qobject_cast<const QTableView*>(widget) != nullptr)
            {
                if (const auto* itemOption = qstyleoption_cast<const QStyleOptionViewItem*>(option))
                {
                    QStyleOptionViewItem unselectedOption(*itemOption);
                    unselectedOption.state &= ~QStyle::State_Selected;
                    unselectedOption.state &= ~QStyle::State_HasFocus;
                    QProxyStyle::drawPrimitive(element, &unselectedOption, painter, widget);
                    return;
                }
            }

            QProxyStyle::drawPrimitive(element, option, painter, widget);
        }
    };

    // GlobalTableSelectionOutlineFilter 作用：
    // - 在 QTableView/QTableWidget 首次显示前安装统一 delegate；
    // - 后续懒加载 Dock 和弹窗创建的表格自动获得同一选中态；
    // - 带专用 delegate 的表格通过动态属性明确跳过，避免破坏编辑或自定义绘制。
    class GlobalTableSelectionOutlineFilter final : public QObject
    {
    public:
        explicit GlobalTableSelectionOutlineFilter(QObject* parent = nullptr)
            : QObject(parent)
        {
        }

        static void installDelegateForTable(QTableView* tableView)
        {
            if (tableView == nullptr)
            {
                return;
            }

            if (!tableView->property(kKswordTableSelectionOutlineStylePropertyName).toBool())
            {
                auto* selectionOutlineStyle = new TableSelectionOutlineProxyStyle();
                selectionOutlineStyle->setParent(tableView);
                tableView->setStyle(selectionOutlineStyle);
                tableView->setProperty(kKswordTableSelectionOutlineStylePropertyName, true);
            }

            if (tableView->property(kKswordCustomTableDelegatePropertyName).toBool() ||
                tableView->property(kKswordTableSelectionOutlineDelegatePropertyName).toBool())
            {
                return;
            }

            tableView->setItemDelegate(new TableSelectionOutlineDelegate(tableView));
            tableView->setProperty(kKswordTableSelectionOutlineDelegatePropertyName, true);
        }

    protected:
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (eventObject == nullptr || eventObject->type() != QEvent::Show)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            installDelegateForTable(qobject_cast<QTableView*>(watchedObject));
            return QObject::eventFilter(watchedObject, eventObject);
        }
    };

    // ensureGlobalContextMenuThemeFilterInstalled 作用：
    // - 安装一次应用级 QMenu 主题过滤器；
    // - 让所有后续创建的右键菜单自动获得深浅色背景兜底。
    void ensureGlobalContextMenuThemeFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalContextMenuThemeFilter* contextMenuThemeFilter = nullptr;
        if (contextMenuThemeFilter == nullptr)
        {
            contextMenuThemeFilter = new GlobalContextMenuThemeFilter(appInstance);
            appInstance->installEventFilter(contextMenuThemeFilter);
        }

        static GlobalTopLevelTopMostFilter* topLevelTopMostFilter = nullptr;
        if (topLevelTopMostFilter == nullptr)
        {
            topLevelTopMostFilter = new GlobalTopLevelTopMostFilter(appInstance);
            appInstance->installEventFilter(topLevelTopMostFilter);
        }
    }

    // ensureGlobalComboPopupThemeFilterInstalled 作用：
    // - 安装一次应用级组合框 Popup 主题过滤器；
    // - 同时刷新已创建组合框，保证主题切换后下一次展开立即使用不透明背景。
    void ensureGlobalComboPopupThemeFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalComboPopupThemeFilter* comboPopupThemeFilter = nullptr;
        if (comboPopupThemeFilter == nullptr)
        {
            comboPopupThemeFilter = new GlobalComboPopupThemeFilter(appInstance);
            appInstance->installEventFilter(comboPopupThemeFilter);
        }

        const QWidgetList allWidgetList = appInstance->allWidgets();
        for (QWidget* const widget : allWidgetList)
        {
            applyOpaqueComboPopupTheme(qobject_cast<QComboBox*>(widget));
        }
    }

    void ensureGlobalSliderWheelFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalTabIconContrastFilter* tabIconContrastFilter = nullptr;
        if (tabIconContrastFilter == nullptr)
        {
            tabIconContrastFilter = new GlobalTabIconContrastFilter(appInstance);
            appInstance->installEventFilter(tabIconContrastFilter);
        }

        static GlobalSliderWheelFilter* sliderWheelFilter = nullptr;
        if (sliderWheelFilter == nullptr)
        {
            sliderWheelFilter = new GlobalSliderWheelFilter(appInstance);
            appInstance->installEventFilter(sliderWheelFilter);
        }
    }

    void ensureGlobalTableSelectionOutlineFilterInstalled()
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        static GlobalTableSelectionOutlineFilter* tableSelectionOutlineFilter = nullptr;
        if (tableSelectionOutlineFilter == nullptr)
        {
            tableSelectionOutlineFilter = new GlobalTableSelectionOutlineFilter(appInstance);
            appInstance->installEventFilter(tableSelectionOutlineFilter);
        }

        for (QWidget* widget : appInstance->allWidgets())
        {
            GlobalTableSelectionOutlineFilter::installDelegateForTable(
                qobject_cast<QTableView*>(widget));
        }
    }

    // applyApplicationFontToItemViews 作用：
    // - 对表格、树和列表显式刷新当前应用字体，解决局部 QSS 导致字体继承停留在启动默认值的问题；
    // - 标记 ksword_preserve_custom_font 的控件保持专用字体，例如十六进制编辑器的等宽字体；
    // - 调用方式：每次 applyAppearanceSettings 更新 QApplication 字体后调用。
    // 入参 applicationFont：当前应用字体族与抗锯齿策略；无返回值。
    void applyApplicationFontToItemViews(const QFont& applicationFont)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            return;
        }

        constexpr const char* preserveCustomFontProperty = "ksword_preserve_custom_font";
        for (QWidget* widget : appInstance->allWidgets())
        {
            QAbstractItemView* itemView = qobject_cast<QAbstractItemView*>(widget);
            if (itemView == nullptr)
            {
                continue;
            }

            if (itemView->property(preserveCustomFontProperty).toBool())
            {
                continue;
            }

            itemView->setFont(applicationFont);
        }
    }

    // RuntimeAppearanceProgress 作用：
    // - 在运行期主题、背景或字体切换前复用原生 kSplash；
    // - kSplash 使用独立 Win32 分层窗口同步绘制，即使 Qt 主线程正在重设样式也能保留可见进度；
    // - 析构时自动隐藏窗口，避免异常路径或后续提前返回遗留启动页。
    class RuntimeAppearanceProgress final
    {
    public:
        explicit RuntimeAppearanceProgress(const bool shouldShow)
        {
            if (!shouldShow)
            {
                return;
            }

            m_visible = kSplash.show(progressText(
                QStringLiteral("main.runtime_appearance.progress.start"),
                QStringLiteral("正在应用界面设置...")).toUtf8().toStdString());
        }

        ~RuntimeAppearanceProgress()
        {
            if (m_visible)
            {
                kSplash.hide();
            }
        }

        RuntimeAppearanceProgress(const RuntimeAppearanceProgress&) = delete;
        RuntimeAppearanceProgress& operator=(const RuntimeAppearanceProgress&) = delete;

        void update(const int progressPercent, const QString& textKey, const QString& fallbackText) const
        {
            if (!m_visible)
            {
                return;
            }

            kSplash.progress(
                progressText(textKey, fallbackText).toUtf8().toStdString(),
                progressPercent);
        }

    private:
        static QString progressText(const QString& textKey, const QString& fallbackText)
        {
            return ks::i18n::contextText(textKey, fallbackText);
        }

        bool m_visible = false;
    };

    // kTooltipStyleBeginMarker / kTooltipStyleEndMarker 作用：
    // - 在 QApplication 样式表中标记“Tooltip 主题片段”的起止位置；
    // - 便于主题切换时精准替换旧 Tooltip 样式，避免重复拼接。
    constexpr const char* kTooltipStyleBeginMarker = "/*KSWORD_TOOLTIP_STYLE_BEGIN*/";
    constexpr const char* kTooltipStyleEndMarker = "/*KSWORD_TOOLTIP_STYLE_END*/";
    // kContextMenuStyleBeginMarker / kContextMenuStyleEndMarker 作用：
    // - 在 QApplication 样式表中标记“右键菜单主题片段”的起止位置；
    // - 便于主题切换时替换旧菜单样式，避免重复拼接与样式污染。
    constexpr const char* kContextMenuStyleBeginMarker = "/*KSWORD_CONTEXT_MENU_STYLE_BEGIN*/";
    constexpr const char* kContextMenuStyleEndMarker = "/*KSWORD_CONTEXT_MENU_STYLE_END*/";
    // kControlContrastStyleBeginMarker / kControlContrastStyleEndMarker 作用：
    // - 标记复选框、单选框和滑块的全局高对比样式；
    // - 主题或自定义颜色变化时替换旧片段，避免重复追加。
    constexpr const char* kControlContrastStyleBeginMarker = "/*KSWORD_CONTROL_CONTRAST_STYLE_BEGIN*/";
    constexpr const char* kControlContrastStyleEndMarker = "/*KSWORD_CONTROL_CONTRAST_STYLE_END*/";
    // kComboBoxStyleBeginMarker / kComboBoxStyleEndMarker 作用：
    // - 标记组合框本体、箭头区和 Popup 列表的全局不透明主题样式；
    // - 主背景或主题色变化时替换旧片段，避免应用级 QSS 重复追加。
    constexpr const char* kComboBoxStyleBeginMarker = "/*KSWORD_COMBOBOX_STYLE_BEGIN*/";
    constexpr const char* kComboBoxStyleEndMarker = "/*KSWORD_COMBOBOX_STYLE_END*/";
    // kDeferredDockLoadIntervalMs 作用：
    // - 控制“显示后补载”节流间隔；
    // - 避免 0ms 连续补载把 UI 线程再次打满。
    constexpr int kDeferredDockLoadIntervalMs = 60;
    // kDwmUseImmersiveDarkModeAttribute 作用：
    // - 兼容不同 SDK 头文件是否声明该枚举值；
    // - 用于告诉 DWM 当前窗口应按深色还是浅色边框策略处理。
    constexpr DWORD kDwmUseImmersiveDarkModeAttribute = 20;
    // kDwmBorderColorAttribute 作用：
    // - 指向 Win11 边框颜色属性编号；
    // - 用于关闭系统默认白色可见边框。
    constexpr DWORD kDwmBorderColorAttribute = 34;
    // kDwmColorNone 作用：
    // - 传给 DWMWA_BORDER_COLOR 后表示“不绘制可见边框”；
    // - 保留阴影与缩放能力，仅移除闪白边线。
    constexpr DWORD kDwmColorNone = 0xFFFFFFFE;
    // 窗口组合特性（SetWindowCompositionAttribute）相关声明：
    // - DWM 云母要求窗口不透明，和 Qt 的 WA_TranslucentBackground 分层窗口互斥，
    //   强行启用会让 DWM 回退到系统浅色 fallback 底（表现为整窗发白）；
    // - Acrylic 通过组合特性作用于分层窗口，是本项目唯一走系统合成的模糊。
    // kWindowCompositionAttributeAccentPolicy 作用：WCA_ACCENT_POLICY 特性编号。
    constexpr DWORD kWindowCompositionAttributeAccentPolicy = 19;
    // kAccentDisabled / kAccentEnableAcrylicBlurBehind 作用：ACCENT_STATE 取值。
    // - ACRYLIC(4)：模糊 + 饱和度 + 噪点，由 DWM 合成；
    // - 传统 BLURBEHIND(3) 在 Windows 11 上已退化为纯透明且忽略着色，不可用。
    constexpr DWORD kAccentDisabled = 0;
    constexpr DWORD kAccentEnableAcrylicBlurBehind = 4;
    // kBackdropRefreshThrottleMs 作用：
    // - 亚克力重采样的合并窗口（毫秒）；
    // - 拖动与缩放会连续触发几何事件，节流后只在动作稳定时下发一次组合特性。
    constexpr int kBackdropRefreshThrottleMs = 40;
    // AccentPolicyData 说明：对应未公开的 ACCENT_POLICY 结构体布局。
    // 注意：该结构没有模糊半径字段，亚克力的模糊强度由 DWM 内部固定，
    // 因此“玻璃模糊半径”设置只能作用于自绘的背景图模糊层。
    struct AccentPolicyData
    {
        DWORD accentState = 0;   // accentState：ACCENT_STATE 枚举值。
        DWORD accentFlags = 0;   // accentFlags：边框绘制标志，本项目不需要。
        DWORD gradientColor = 0; // gradientColor：着色色值，排布为 0xAABBGGRR。
        DWORD animationId = 0;   // animationId：动画标识，保持 0。
    };

    // WindowCompositionAttributeData 说明：对应未公开的 WINDOWCOMPOSITIONATTRIBDATA。
    struct WindowCompositionAttributeData
    {
        DWORD attribute = 0;          // attribute：WCA_* 特性编号。
        void* dataPointer = nullptr;  // dataPointer：特性数据指针。
        SIZE_T dataSizeBytes = 0;     // dataSizeBytes：特性数据字节数。
    };
    // WDA_* 兼容常量：
    // - WDA_EXCLUDEFROMCAPTURE 在 Windows 10 20H2+ 支持，截图/录屏中直接隐藏窗口；
    // - WDA_MONITOR 是旧系统可用回退，截图/录屏中窗口区域显示为黑屏；
    // - WDA_NONE 用于关闭截屏屏蔽，恢复正常捕获。
    constexpr DWORD kWindowDisplayAffinityAllowCapture = 0x00000000;
    constexpr DWORD kWindowDisplayAffinityMonitorOnly = 0x00000001;
    constexpr DWORD kWindowDisplayAffinityExcludeFromCapture = 0x00000011;
    constexpr wchar_t kR0DriverServiceName[] = L"KswordARK";
    constexpr wchar_t kR0DriverDisplayName[] = L"KswordARK Driver Service";
    constexpr DWORD kR0ServiceStartWaitTimeoutMs = 9000;
    constexpr DWORD kR0ServiceStopWaitTimeoutMs = 30000;
    constexpr int kR0LogConnectRetrySleepMs = 260;
    constexpr int kR0LogIdlePollSleepMs = 120;
    constexpr char kR0LogPrefixDebug[] = "[Debug]";
    constexpr char kR0LogPrefixInfo[] = "[Info]";
    constexpr char kR0LogPrefixWarn[] = "[Warn]";
    constexpr char kR0LogPrefixError[] = "[Error]";
    constexpr char kR0LogPrefixFatal[] = "[Fatal]";

    // r0StartupStageText 作用：
    // - 输入：驱动写入 Parameters 的 KSWORD_ARK_START_STAGE 阶段号；
    // - 处理：映射为用户能直接转述给开发者的阶段名；
    // - 返回：阶段名；未知阶段返回空串。
    QString r0StartupStageText(const DWORD stageValue)
    {
        switch (stageValue)
        {
        case KswordArkStartStageEnteredDriverEntry:
            return QStringLiteral("进入驱动入口");
        case KswordArkStartStageOsVersionCheck:
            return QStringLiteral("系统版本检查");
        case KswordArkStartStageWdfDriverCreate:
            return QStringLiteral("创建 WDF 驱动对象");
        case KswordArkStartStageControlInitAllocate:
            return QStringLiteral("分配控制设备初始化结构");
        case KswordArkStartStageDeviceAssignName:
            return QStringLiteral("指派控制设备名");
        case KswordArkStartStageDeviceCreate:
            return QStringLiteral("创建控制设备");
        case KswordArkStartStageLogChannel:
            return QStringLiteral("初始化日志通道");
        case KswordArkStartStageDebugOutput:
            return QStringLiteral("初始化内核调试输出缓冲");
        case KswordArkStartStageSymbolicLink:
            return QStringLiteral("创建符号链接");
        case KswordArkStartStageDefaultQueue:
            return QStringLiteral("创建默认 I/O 队列");
        case KswordArkStartStageCallbackRuntimeAllocate:
            return QStringLiteral("分配回调运行时");
        case KswordArkStartStageCallbackWaitQueue:
            return QStringLiteral("创建用户询问队列");
        case KswordArkStartStageRegistryCallback:
            return QStringLiteral("注册注册表回调");
        case KswordArkStartStageProcessCallback:
            return QStringLiteral("注册进程回调");
        case KswordArkStartStageThreadCallback:
            return QStringLiteral("注册线程回调");
        case KswordArkStartStageImageCallback:
            return QStringLiteral("注册映像加载回调");
        case KswordArkStartStageObjectCallback:
            return QStringLiteral("注册对象句柄回调");
        case KswordArkStartStageControlDevicePublish:
            return QStringLiteral("发布控制设备");
        case KswordArkStartStageReady:
            return QStringLiteral("启动完成");
        default:
            return QString();
        }
    }

    // describeR0StartupBreadcrumb 作用：
    // - 输入：无；直接读取 Services\KswordARK\Parameters 下驱动留下的启动记录；
    // - 处理：把阶段号与原始 NTSTATUS 组装成可直接贴进 issue 的一段文字；
    // - 返回：诊断文本；没有任何记录时返回明确的“未进入驱动入口”结论。
    //
    // SCM 只会把内核返回的失败折叠成 Win32 31，无法区分 WDF 队列失败和内核回调
    // 注册失败；这段记录是把 31 还原成具体阶段与原始状态的唯一途径。
    QString describeR0StartupBreadcrumb()
    {
        HKEY parametersKey = nullptr;
        const LSTATUS openResult = ::RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            KSWORD_ARK_STARTUP_PARAMETERS_PATH,
            0,
            KEY_QUERY_VALUE | KEY_WOW64_64KEY,
            &parametersKey);
        if (openResult != ERROR_SUCCESS)
        {
            return QStringLiteral("驱动未留下启动记录，说明本次加载没有进入驱动入口，应优先检查 KswordARK.sys 的签名、Code Integrity 策略与系统版本。");
        }

        const auto readDword = [parametersKey](const wchar_t* const valueName, DWORD& valueOut) {
            DWORD valueType = 0;
            DWORD valueData = 0;
            DWORD valueBytes = static_cast<DWORD>(sizeof(valueData));
            const LSTATUS queryResult = ::RegQueryValueExW(
                parametersKey,
                valueName,
                nullptr,
                &valueType,
                reinterpret_cast<LPBYTE>(&valueData),
                &valueBytes);
            if (queryResult != ERROR_SUCCESS || valueType != REG_DWORD)
            {
                return false;
            }
            valueOut = valueData;
            return true;
        };

        DWORD stageValue = 0;
        DWORD statusValue = 0;
        const bool hasStage = readDword(KSWORD_ARK_STARTUP_VALUE_STAGE, stageValue);
        const bool hasStatus = readDword(KSWORD_ARK_STARTUP_VALUE_STATUS, statusValue);

        wchar_t buildBuffer[128] = {};
        DWORD buildType = 0;
        DWORD buildBytes = static_cast<DWORD>(sizeof(buildBuffer));
        QString buildText;
        if (::RegQueryValueExW(
            parametersKey,
            KSWORD_ARK_STARTUP_VALUE_BUILD,
            nullptr,
            &buildType,
            reinterpret_cast<LPBYTE>(buildBuffer),
            &buildBytes) == ERROR_SUCCESS && buildType == REG_SZ)
        {
            buildBuffer[std::size(buildBuffer) - 1] = L'\0';
            buildText = QString::fromWCharArray(buildBuffer);
        }

        DWORD osBuildValue = 0;
        const bool hasOsBuild = readDword(KSWORD_ARK_STARTUP_VALUE_OS_BUILD, osBuildValue);
        ::RegCloseKey(parametersKey);

        if (!hasStage)
        {
            return QStringLiteral("驱动留下的启动记录不完整，无法确定失败阶段。");
        }

        const QString stageName = r0StartupStageText(stageValue);
        QString detailText = QStringLiteral("驱动最后到达的启动阶段：%1（stage=%2）")
            .arg(stageName.isEmpty() ? QStringLiteral("未知阶段") : stageName)
            .arg(stageValue);
        if (hasStatus)
        {
            detailText += QStringLiteral("\n驱动内部状态：0x%1")
                .arg(statusValue, 8, 16, QLatin1Char('0'));
        }
        if (!buildText.isEmpty())
        {
            detailText += QStringLiteral("\n驱动构建：%1").arg(buildText);
        }
        if (hasOsBuild && osBuildValue != 0)
        {
            detailText += QStringLiteral("\n系统内部版本：%1").arg(osBuildValue);
        }
        return detailText;
    }

    // sharedR0DriverLogEvent 作用：
    // - 统一承载 R3 进程内“驱动日志转发”链路的 GUID；
    // - 满足“所有驱动输出走同一个 kLogEvent”要求。
    kLogEvent& sharedR0DriverLogEvent()
    {
        static kLogEvent sharedEvent;
        return sharedEvent;
    }

    // startsWithLiteral 作用：
    // - 判断文本是否以固定前缀开头（区分大小写）；
    // - 仅用于日志等级标签解析。
    bool startsWithLiteral(const std::string& text, const char* prefixText)
    {
        if (prefixText == nullptr)
        {
            return false;
        }

        const std::size_t prefixLength = std::strlen(prefixText);
        if (text.size() < prefixLength)
        {
            return false;
        }
        return text.compare(0, prefixLength, prefixText) == 0;
    }

    // serviceStateToText 作用：
    // - 输入：Win32 服务状态枚举值；
    // - 处理：把原始状态码映射为稳定的调试文本；
    // - 返回：用于 UI 和日志展示的状态名。
    QString serviceStateToText(const DWORD serviceState);

    class ScopedServiceHandle final
    {
    public:
        ScopedServiceHandle() = default;
        explicit ScopedServiceHandle(const SC_HANDLE handle)
            : m_handle(handle)
        {
        }

        ScopedServiceHandle(const ScopedServiceHandle&) = delete;
        ScopedServiceHandle& operator=(const ScopedServiceHandle&) = delete;

        ScopedServiceHandle(ScopedServiceHandle&& other) noexcept
            : m_handle(other.m_handle)
        {
            other.m_handle = nullptr;
        }

        ScopedServiceHandle& operator=(ScopedServiceHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        ~ScopedServiceHandle()
        {
            reset();
        }

        void reset(const SC_HANDLE newHandle = nullptr)
        {
            if (m_handle != nullptr)
            {
                ::CloseServiceHandle(m_handle);
            }
            m_handle = newHandle;
        }

        SC_HANDLE get() const
        {
            return m_handle;
        }

        bool isValid() const
        {
            return m_handle != nullptr;
        }

    private:
        SC_HANDLE m_handle = nullptr;
    };

    class ScopedHandle final
    {
    public:
        // 构造函数：
        // - 输入：Windows 内核对象句柄；
        // - 处理：保存句柄并在析构时自动 CloseHandle；
        // - 返回：无返回值。
        explicit ScopedHandle(const HANDLE handleValue = nullptr)
            : m_handle(handleValue)
        {
        }

        ScopedHandle(const ScopedHandle&) = delete;
        ScopedHandle& operator=(const ScopedHandle&) = delete;

        // 移动构造：
        // - 输入：另一个句柄托管对象；
        // - 处理：转移句柄所有权，避免两个对象重复关闭同一句柄；
        // - 返回：无返回值。
        ScopedHandle(ScopedHandle&& other) noexcept
            : m_handle(other.m_handle)
        {
            other.m_handle = nullptr;
        }

        // 移动赋值：
        // - 输入：另一个句柄托管对象；
        // - 处理：关闭当前旧句柄，再接管对方句柄；
        // - 返回：当前对象引用。
        ScopedHandle& operator=(ScopedHandle&& other) noexcept
        {
            if (this != &other)
            {
                reset();
                m_handle = other.m_handle;
                other.m_handle = nullptr;
            }
            return *this;
        }

        // 析构函数：
        // - 输入：无；
        // - 处理：关闭仍由对象持有的句柄；
        // - 返回：无返回值。
        ~ScopedHandle()
        {
            reset();
        }

        // reset：
        // - 输入：新的句柄，默认空句柄；
        // - 处理：关闭旧句柄并保存新句柄；
        // - 返回：无返回值。
        void reset(const HANDLE newHandle = nullptr)
        {
            if (m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE)
            {
                ::CloseHandle(m_handle);
            }
            m_handle = newHandle;
        }

        // release：
        // - 输入：无；
        // - 处理：放弃托管但不关闭句柄；
        // - 返回：原始句柄，调用方接管关闭责任。
        HANDLE release()
        {
            const HANDLE oldHandle = m_handle;
            m_handle = nullptr;
            return oldHandle;
        }

        // get：
        // - 输入：无；
        // - 处理：返回当前原始句柄；
        // - 返回：HANDLE，可能为空。
        HANDLE get() const
        {
            return m_handle;
        }

        // isValid：
        // - 输入：无；
        // - 处理：判断句柄是否可用于 Win32 API；
        // - 返回：true 表示非空且非 INVALID_HANDLE_VALUE。
        bool isValid() const
        {
            return m_handle != nullptr && m_handle != INVALID_HANDLE_VALUE;
        }

    private:
        HANDLE m_handle = nullptr; // m_handle：当前托管的 Win32 句柄。
    };

    class ScopedThreadImpersonation final
    {
    public:
        ScopedThreadImpersonation() = default;
        ScopedThreadImpersonation(const ScopedThreadImpersonation&) = delete;
        ScopedThreadImpersonation& operator=(const ScopedThreadImpersonation&) = delete;

        // 析构函数：
        // - 输入：无；
        // - 处理：如果当前对象启用了线程模拟，则自动 RevertToSelf；
        // - 返回：无返回值。
        ~ScopedThreadImpersonation()
        {
            reset();
        }

        // impersonate：
        // - 输入：可模拟的令牌句柄；
        // - 处理：让当前线程进入该令牌的安全上下文；
        // - 返回：true 表示模拟成功。
        bool impersonate(const HANDLE tokenHandle, DWORD* const errorCodeOut)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_SUCCESS;
            }
            reset();
            if (tokenHandle == nullptr)
            {
                if (errorCodeOut != nullptr)
                {
                    *errorCodeOut = ERROR_INVALID_HANDLE;
                }
                return false;
            }
            if (::ImpersonateLoggedOnUser(tokenHandle) == FALSE)
            {
                if (errorCodeOut != nullptr)
                {
                    *errorCodeOut = ::GetLastError();
                }
                return false;
            }
            m_active = true;
            return true;
        }

        // reset：
        // - 输入：无；
        // - 处理：撤销当前线程模拟，恢复调用线程自身身份；
        // - 返回：无返回值。
        void reset()
        {
            if (m_active)
            {
                ::RevertToSelf();
                m_active = false;
            }
        }

    private:
        bool m_active = false; // m_active：记录析构时是否需要撤销线程模拟。
    };

    QString formatWin32ErrorText(const DWORD errorCode)
    {
        if (errorCode == ERROR_SUCCESS)
        {
            return QStringLiteral("成功");
        }

        LPWSTR messageBuffer = nullptr;
        const DWORD messageLength = ::FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            reinterpret_cast<LPWSTR>(&messageBuffer),
            0,
            nullptr);

        QString messageText;
        if (messageLength > 0 && messageBuffer != nullptr)
        {
            messageText = QString::fromWCharArray(messageBuffer, static_cast<int>(messageLength)).trimmed();
        }
        if (messageBuffer != nullptr)
        {
            ::LocalFree(messageBuffer);
        }
        if (messageText.isEmpty())
        {
            messageText = QStringLiteral("未知系统错误");
        }
        return messageText;
    }

    QString quoteWin32CommandLineArgument(const std::wstring& argumentText)
    {
        // argumentText 用途：把 exe 路径包装为 CreateProcessAsUserW 可安全解析的命令行参数。
        QString escapedText = QString::fromStdWString(argumentText);
        escapedText.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(escapedText);
    }

    // containsQtArgument 作用：
    // - 输入 argumentList：QCoreApplication 参数列表；argumentText：内部参数名；
    // - 处理：跳过 exe 路径，只做大小写不敏感的完整参数匹配；
    // - 返回：已存在该参数返回 true，否则返回 false。
    bool containsQtArgument(const QStringList& argumentList, const QString& argumentText)
    {
        for (int index = 1; index < argumentList.size(); ++index)
        {
            if (QString::compare(argumentList.at(index), argumentText, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        return false;
    }

    // argumentsWithPrivilegeRestartMarker 作用：
    // - 输入 argumentList：当前 Qt 参数；
    // - 处理：为 UIAccess/Admin 权限切换重启追加内部标记参数，避免新实例被防多开直接拦截；
    // - 返回：包含内部标记的参数列表；若已存在则原样返回。
    QStringList argumentsWithPrivilegeRestartMarker(QStringList argumentList)
    {
        const QString markerText = QString::fromWCharArray(kKswordPrivilegeRestartArgument);
        if (!containsQtArgument(argumentList, markerText))
        {
            argumentList.push_back(markerText);
        }
        return argumentList;
    }

    // argumentsWithPrivilegeRestartTakeover 作用：
    // - 输入 argumentList：当前 Qt 参数；predecessorProcessId：即将退出的旧实例 PID；
    // - 处理：替换可能由更早重启遗留的等待 PID，并附加本次权限切换接管参数；
    // - 返回：新实例可用于等待同一可执行文件父进程退出的参数列表。
    QStringList argumentsWithPrivilegeRestartTakeover(
        QStringList argumentList,
        const DWORD predecessorProcessId)
    {
        argumentList = argumentsWithPrivilegeRestartMarker(std::move(argumentList));
        const QString waitPidArgument =
            QString::fromWCharArray(ks::crash::kCrashRestartWaitPidArgument);
        for (int index = 1; index < argumentList.size();)
        {
            if (QString::compare(
                    argumentList.at(index),
                    waitPidArgument,
                    Qt::CaseInsensitive) != 0)
            {
                ++index;
                continue;
            }

            argumentList.removeAt(index);
            if (index < argumentList.size())
            {
                bool isProcessId = false;
                (void)argumentList.at(index).toULongLong(&isProcessId);
                if (isProcessId)
                {
                    argumentList.removeAt(index);
                }
            }
        }
        argumentList.push_back(waitPidArgument);
        argumentList.push_back(QString::number(predecessorProcessId));
        return argumentList;
    }

    QString formatWin32StepFailure(const QString& stepText, const DWORD errorCode)
    {
        // stepText 用途：描述失败 API 或阶段，便于 UI 与日志直接定位。
        return QStringLiteral("%1 失败，错误码：%2，系统信息：%3")
            .arg(stepText)
            .arg(errorCode)
            .arg(formatWin32ErrorText(errorCode));
    }

    QString privilegeNameToDisplayText(const wchar_t* const privilegeName)
    {
        // privilegeName 用途：把 Win32 权限常量转换成 QString，便于诊断输出。
        if (privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromWCharArray(privilegeName);
    }

    bool enableTokenPrivilege(
        const HANDLE tokenHandle,
        const wchar_t* const privilegeName,
        DWORD* const errorCodeOut)
    {
        // errorCodeOut 用途：向调用方返回 LookupPrivilegeValue/AdjustTokenPrivileges 的失败原因。
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr || privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        // privilegeLuid 用途：把权限名解析成当前系统中的 LUID。
        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        // tokenPrivileges 用途：只启用一个目标权限，不改动其它权限状态。
        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            sizeof(tokenPrivileges),
            nullptr,
            nullptr) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        const DWORD adjustError = ::GetLastError();
        if (adjustError != ERROR_SUCCESS)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = adjustError;
            }
            return false;
        }
        return true;
    }

    bool enableCurrentProcessPrivilege(const wchar_t* const privilegeName, DWORD* const errorCodeOut);

    QString tryEnableCurrentProcessPrivilegeForUiAccess(const wchar_t* const privilegeName)
    {
        // privilegeName 用途：指定为 UIAccess fallback 准备的当前进程权限。
        DWORD privilegeError = ERROR_SUCCESS;
        const bool enableOk = enableCurrentProcessPrivilege(privilegeName, &privilegeError);
        if (enableOk)
        {
            return QStringLiteral("%1：已启用").arg(privilegeNameToDisplayText(privilegeName));
        }
        return QStringLiteral("%1：未启用（%2，%3）")
            .arg(privilegeNameToDisplayText(privilegeName))
            .arg(privilegeError)
            .arg(formatWin32ErrorText(privilegeError));
    }

    bool queryTokenSessionId(const HANDLE tokenHandle, DWORD* const sessionIdOut, DWORD* const errorCodeOut)
    {
        // sessionIdOut 用途：返回令牌所属 Session，决定新进程能否显示在当前交互桌面。
        if (sessionIdOut != nullptr)
        {
            *sessionIdOut = 0;
        }
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr || sessionIdOut == nullptr)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        DWORD returnLength = 0;
        DWORD tokenSessionId = 0;
        if (::GetTokenInformation(
            tokenHandle,
            TokenSessionId,
            &tokenSessionId,
            sizeof(tokenSessionId),
            &returnLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        *sessionIdOut = tokenSessionId;
        return true;
    }

    bool tokenBelongsToLocalSystem(const HANDLE tokenHandle, DWORD* const errorCodeOut)
    {
        // errorCodeOut 用途：保留查询失败原因；返回 false 不一定代表“不是 SYSTEM”。
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (tokenHandle == nullptr)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_HANDLE;
            }
            return false;
        }

        DWORD requiredLength = 0;
        ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredLength);
        if (requiredLength == 0)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        // userBuffer 用途：保存 TOKEN_USER，可变长度结构必须用动态缓冲区承接。
        std::vector<BYTE> userBuffer(requiredLength, 0);
        if (::GetTokenInformation(
            tokenHandle,
            TokenUser,
            userBuffer.data(),
            requiredLength,
            &requiredLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
        DWORD systemSidLength = static_cast<DWORD>(std::size(systemSidBuffer));
        if (::CreateWellKnownSid(
            WinLocalSystemSid,
            nullptr,
            systemSidBuffer,
            &systemSidLength) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
        return ::EqualSid(tokenUser->User.Sid, systemSidBuffer) != FALSE;
    }

    bool findSystemProcessTokenCandidate(
        const DWORD currentSessionId,
        DWORD* const processIdOut,
        QString* const processNameOut,
        DWORD* const processSessionIdOut,
        QString* const detailTextOut)
    {
        // processIdOut/processNameOut/processSessionIdOut 用途：返回最适合作为 SYSTEM 令牌源的进程。
        if (processIdOut != nullptr)
        {
            *processIdOut = 0;
        }
        if (processNameOut != nullptr)
        {
            processNameOut->clear();
        }
        if (processSessionIdOut != nullptr)
        {
            *processSessionIdOut = 0;
        }
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        // candidateRank 用途：
        // - 0 表示尚未找到；
        // - 数值越大优先级越高，同 Session 的 winlogon.exe 最优。
        int bestRank = 0;
        DWORD bestPid = 0;
        DWORD bestSessionId = 0;
        QString bestProcessName;

        ScopedHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshotHandle.isValid())
        {
            const DWORD errorCode = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateToolhelp32Snapshot"), errorCode);
            }
            return false;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle.get(), &processEntry) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("Process32FirstW"), errorCode);
            }
            return false;
        }

        do
        {
            // processSessionId 用途：优先选择当前交互 Session 的 winlogon，降低不可见启动概率。
            DWORD processSessionId = 0;
            if (::ProcessIdToSessionId(processEntry.th32ProcessID, &processSessionId) == FALSE)
            {
                processSessionId = 0;
            }

            int rank = 0;
            const bool sameSession = processSessionId == currentSessionId;
            if (_wcsicmp(processEntry.szExeFile, L"winlogon.exe") == 0)
            {
                rank = sameSession ? 40 : 30;
            }
            else if (_wcsicmp(processEntry.szExeFile, L"services.exe") == 0)
            {
                rank = sameSession ? 20 : 10;
            }

            if (rank > bestRank)
            {
                bestRank = rank;
                bestPid = processEntry.th32ProcessID;
                bestSessionId = processSessionId;
                bestProcessName = QString::fromWCharArray(processEntry.szExeFile);
            }
        } while (::Process32NextW(snapshotHandle.get(), &processEntry) != FALSE);

        if (bestPid == 0)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = QStringLiteral("没有找到可用的 SYSTEM 令牌源进程（优先 winlogon.exe，其次 services.exe）。");
            }
            return false;
        }

        if (processIdOut != nullptr)
        {
            *processIdOut = bestPid;
        }
        if (processNameOut != nullptr)
        {
            *processNameOut = bestProcessName;
        }
        if (processSessionIdOut != nullptr)
        {
            *processSessionIdOut = bestSessionId;
        }
        return true;
    }

    // findExplorerProcessInSession 作用：
    // - 输入 currentSessionId：当前交互 Session；
    // - 处理：遍历进程快照，寻找同 Session 的 explorer.exe；
    // - 返回：true 表示找到可用候选，并输出 PID/进程名。
    bool findExplorerProcessInSession(
        const DWORD currentSessionId,
        DWORD* const processIdOut,
        QString* const processNameOut,
        QString* const detailTextOut)
    {
        if (processIdOut != nullptr)
        {
            *processIdOut = 0;
        }
        if (processNameOut != nullptr)
        {
            processNameOut->clear();
        }
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        ScopedHandle snapshotHandle(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        if (!snapshotHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateToolhelp32Snapshot"), ::GetLastError());
            }
            return false;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize = sizeof(processEntry);
        if (::Process32FirstW(snapshotHandle.get(), &processEntry) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("Process32FirstW"), ::GetLastError());
            }
            return false;
        }

        do
        {
            DWORD processSessionId = 0;
            if (::ProcessIdToSessionId(processEntry.th32ProcessID, &processSessionId) == FALSE)
            {
                continue;
            }
            if (processSessionId != currentSessionId)
            {
                continue;
            }
            if (_wcsicmp(processEntry.szExeFile, L"explorer.exe") != 0)
            {
                continue;
            }

            if (processIdOut != nullptr)
            {
                *processIdOut = processEntry.th32ProcessID;
            }
            if (processNameOut != nullptr)
            {
                *processNameOut = QString::fromWCharArray(processEntry.szExeFile);
            }
            return true;
        } while (::Process32NextW(snapshotHandle.get(), &processEntry) != FALSE);

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("当前 Session 未找到 explorer.exe。");
        }
        return false;
    }

    // quoteQStringCommandLineArgument 作用：
    // - 输入 argumentText：Qt 字符串参数；
    // - 处理：使用最小 Win32 命令行转义包裹双引号；
    // - 返回：可拼入 CreateProcessAsUserW commandLine 的参数片段。
    QString quoteQStringCommandLineArgument(QString argumentText)
    {
        argumentText.replace(QStringLiteral("\""), QStringLiteral("\\\""));
        return QStringLiteral("\"%1\"").arg(argumentText);
    }

    // launchSelfAsUnelevatedFromExplorer 作用：
    // - 输入 argumentList：当前 QApplication 参数列表；
    // - 处理：复制同 Session explorer.exe 的主令牌启动自身，从 UIAccess/SYSTEM 回到普通用户态；
    // - 返回：true 表示普通实例已经创建，false 表示调用方可回退 ShellExecute。
    bool launchSelfAsUnelevatedFromExplorer(const QStringList& argumentList, QString* detailTextOut)
    {
        if (detailTextOut != nullptr)
        {
            detailTextOut->clear();
        }

        wchar_t executablePathBuffer[MAX_PATH] = {};
        const DWORD executablePathLength = ::GetModuleFileNameW(nullptr, executablePathBuffer, MAX_PATH);
        if (executablePathLength == 0 || executablePathLength >= MAX_PATH)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("GetModuleFileNameW"), ::GetLastError());
            }
            return false;
        }

        DWORD currentSessionId = 0;
        if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("ProcessIdToSessionId"), ::GetLastError());
            }
            return false;
        }

        DWORD explorerPid = 0;
        QString explorerName;
        QString findDetailText;
        if (!findExplorerProcessInSession(currentSessionId, &explorerPid, &explorerName, &findDetailText))
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = findDetailText;
            }
            return false;
        }

        ScopedHandle explorerProcessHandle(::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, explorerPid));
        if (!explorerProcessHandle.isValid())
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("OpenProcess(%1)").arg(explorerName), ::GetLastError());
            }
            return false;
        }

        HANDLE rawExplorerTokenHandle = nullptr;
        if (::OpenProcessToken(explorerProcessHandle.get(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &rawExplorerTokenHandle) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("OpenProcessToken(%1)").arg(explorerName), ::GetLastError());
            }
            return false;
        }
        ScopedHandle explorerTokenHandle(rawExplorerTokenHandle);

        SECURITY_ATTRIBUTES securityAttributes{};
        securityAttributes.nLength = sizeof(securityAttributes);
        HANDLE rawPrimaryTokenHandle = nullptr;
        if (::DuplicateTokenEx(
            explorerTokenHandle.get(),
            MAXIMUM_ALLOWED,
            &securityAttributes,
            SecurityImpersonation,
            TokenPrimary,
            &rawPrimaryTokenHandle) == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(explorer)"), ::GetLastError());
            }
            return false;
        }
        ScopedHandle primaryTokenHandle(rawPrimaryTokenHandle);

        const QStringList launchArgumentList = argumentsWithPrivilegeRestartMarker(argumentList);
        QString commandLineText = quoteQStringCommandLineArgument(QString::fromWCharArray(executablePathBuffer));
        for (int index = 1; index < launchArgumentList.size(); ++index)
        {
            commandLineText += QLatin1Char(' ');
            commandLineText += quoteQStringCommandLineArgument(launchArgumentList.at(index));
        }

        std::wstring mutableCommandLine = commandLineText.toStdWString();
        STARTUPINFOW startupInfo{};
        startupInfo.cb = sizeof(startupInfo);
        PROCESS_INFORMATION processInfo{};
        const BOOL createOk = ::CreateProcessAsUserW(
            primaryTokenHandle.get(),
            nullptr,
            mutableCommandLine.data(),
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo);
        if (createOk == FALSE)
        {
            if (detailTextOut != nullptr)
            {
                *detailTextOut = formatWin32StepFailure(QStringLiteral("CreateProcessAsUserW(explorer token)"), ::GetLastError());
            }
            return false;
        }

        if (processInfo.hThread != nullptr)
        {
            ::CloseHandle(processInfo.hThread);
        }
        if (processInfo.hProcess != nullptr)
        {
            ::CloseHandle(processInfo.hProcess);
        }

        if (detailTextOut != nullptr)
        {
            *detailTextOut = QStringLiteral("已通过 explorer.exe 普通用户令牌启动新实例，PID=%1。").arg(processInfo.dwProcessId);
        }
        return true;
    }

    QString serviceStateToText(const DWORD serviceState)
    {
        switch (serviceState)
        {
        case SERVICE_STOPPED: return QStringLiteral("STOPPED");
        case SERVICE_START_PENDING: return QStringLiteral("START_PENDING");
        case SERVICE_STOP_PENDING: return QStringLiteral("STOP_PENDING");
        case SERVICE_RUNNING: return QStringLiteral("RUNNING");
        case SERVICE_CONTINUE_PENDING: return QStringLiteral("CONTINUE_PENDING");
        case SERVICE_PAUSE_PENDING: return QStringLiteral("PAUSE_PENDING");
        case SERVICE_PAUSED: return QStringLiteral("PAUSED");
        default: return QStringLiteral("UNKNOWN");
        }
    }

    bool queryServiceStatus(const SC_HANDLE serviceHandle, SERVICE_STATUS_PROCESS& statusOut, DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        DWORD bytesNeeded = 0;
        if (::QueryServiceStatusEx(
            serviceHandle,
            SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&statusOut),
            sizeof(statusOut),
            &bytesNeeded) == FALSE)
        {
            errorCodeOut = ::GetLastError();
            return false;
        }
        return true;
    }

    bool waitServiceState(
        const SC_HANDLE serviceHandle,
        const DWORD targetState,
        const DWORD timeoutMs,
        SERVICE_STATUS_PROCESS& latestStatusOut,
        DWORD& errorCodeOut)
    {
        errorCodeOut = ERROR_SUCCESS;
        const ULONGLONG deadline = ::GetTickCount64() + timeoutMs;
        while (true)
        {
            if (!queryServiceStatus(serviceHandle, latestStatusOut, errorCodeOut))
            {
                return false;
            }
            if (latestStatusOut.dwCurrentState == targetState)
            {
                return true;
            }
            if (::GetTickCount64() >= deadline)
            {
                return false;
            }

            DWORD waitMs = latestStatusOut.dwWaitHint / 10;
            if (waitMs < 120)
            {
                waitMs = 120;
            }
            if (waitMs > 500)
            {
                waitMs = 500;
            }
            ::Sleep(waitMs);
        }
    }

    // buildServiceWaitDetailText 作用：
    // - 输入：SCM 返回的 SERVICE_STATUS_PROCESS 与等待总时长；
    // - 处理：把 STOP_PENDING/START_PENDING 排障所需字段聚合成稳定中文文本；
    // - 返回：可直接放入 R0 错误弹窗“详细信息”的 QString。
    QString buildServiceWaitDetailText(
        const SERVICE_STATUS_PROCESS& status,
        const DWORD timeoutMs)
    {
        return QStringLiteral("当前状态：%1\nCheckPoint：%2\nWaitHint：%3 ms\n等待上限：%4 ms\nWin32ExitCode：%5\nServiceSpecificExitCode：%6")
            .arg(serviceStateToText(status.dwCurrentState))
            .arg(status.dwCheckPoint)
            .arg(status.dwWaitHint)
            .arg(timeoutMs)
            .arg(status.dwWin32ExitCode)
            .arg(status.dwServiceSpecificExitCode);
    }

    bool isRunningLikeServiceState(const DWORD serviceState)
    {
        return serviceState == SERVICE_RUNNING ||
            serviceState == SERVICE_START_PENDING ||
            serviceState == SERVICE_CONTINUE_PENDING;
    }

    // enableCurrentProcessPrivilege 作用：
    // - 尝试为当前进程启用指定权限（例如 SeLoadDriverPrivilege）；
    // - 用于 NtUnloadDriver 调用前的权限准备。
    bool enableCurrentProcessPrivilege(const wchar_t* const privilegeName, DWORD* const errorCodeOut)
    {
        if (errorCodeOut != nullptr)
        {
            *errorCodeOut = ERROR_SUCCESS;
        }
        if (privilegeName == nullptr || privilegeName[0] == L'\0')
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ERROR_INVALID_PARAMETER;
            }
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            return false;
        }

        LUID privilegeLuid{};
        if (::LookupPrivilegeValueW(nullptr, privilegeName, &privilegeLuid) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            ::CloseHandle(tokenHandle);
            return false;
        }

        TOKEN_PRIVILEGES tokenPrivileges{};
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = privilegeLuid;
        tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (::AdjustTokenPrivileges(
            tokenHandle,
            FALSE,
            &tokenPrivileges,
            0,
            nullptr,
            nullptr) == FALSE)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = ::GetLastError();
            }
            ::CloseHandle(tokenHandle);
            return false;
        }

        const DWORD adjustError = ::GetLastError();
        ::CloseHandle(tokenHandle);
        if (adjustError != ERROR_SUCCESS)
        {
            if (errorCodeOut != nullptr)
            {
                *errorCodeOut = adjustError;
            }
            return false;
        }

        return true;
    }

    // tryNtUnloadDriverByServiceName 作用：
    // - 通过 NtUnloadDriver 直接尝试卸载指定服务名对应的驱动；
    // - 返回 true 表示 NTSTATUS 成功（>=0）。
    bool tryNtUnloadDriverByServiceName(
        const wchar_t* const serviceName,
        long* const ntStatusOut)
    {
        if (ntStatusOut != nullptr)
        {
            *ntStatusOut = 0L;
        }
        if (serviceName == nullptr || serviceName[0] == L'\0')
        {
            return false;
        }

        const HMODULE ntdllModule = ::GetModuleHandleW(L"ntdll.dll");
        if (ntdllModule == nullptr)
        {
            return false;
        }

        using NtUnloadDriverFn = long (NTAPI*)(PUNICODE_STRING);
        const NtUnloadDriverFn ntUnloadDriverFn =
            reinterpret_cast<NtUnloadDriverFn>(::GetProcAddress(ntdllModule, "NtUnloadDriver"));
        if (ntUnloadDriverFn == nullptr)
        {
            return false;
        }

        std::wstring registryServicePath = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        registryServicePath += serviceName;

        UNICODE_STRING registryPathUnicode{};
        registryPathUnicode.Buffer = const_cast<PWSTR>(registryServicePath.c_str());
        registryPathUnicode.Length = static_cast<USHORT>(registryServicePath.size() * sizeof(wchar_t));
        registryPathUnicode.MaximumLength = registryPathUnicode.Length;

        const long ntStatus = ntUnloadDriverFn(&registryPathUnicode);
        if (ntStatusOut != nullptr)
        {
            *ntStatusOut = ntStatus;
        }
        return ntStatus >= 0;
    }

    // R0ServiceOperationOutcome 作用：
    // - 输入：无；由后台线程执行 SCM 操作时逐字段填充；
    // - 处理：把一次 R0 驱动服务启停的全部结论压成纯值类型，满足“跨线程只回投值类型”的约束；
    // - 返回：各字段含义见成员注释，UI 线程拿到后才决定弹框与状态刷新。
    struct R0ServiceOperationOutcome
    {
        bool succeeded = false;                  // succeeded：SCM 侧是否已到达目标状态。
        bool alreadyInTargetState = false;       // alreadyInTargetState：进入时服务就已处于目标状态（不写“已创建并启动”日志）。
        bool startServiceCallFailed = false;     // startServiceCallFailed：失败发生在 StartServiceW 本身，errorCode 可用于签名失败判定。
        bool usedDirectNtUnloadFallback = false; // usedDirectNtUnloadFallback：停驱走了 NtUnloadDriver 直卸回退。
        DWORD errorCode = ERROR_SUCCESS;         // errorCode：失败时的 Win32 错误码。
        QString stageText;                       // stageText：失败阶段描述，可直接作为 R0 错误框标题行。
        QString detailText;                      // detailText：失败排障详情，可直接进错误框“详细信息”。
    };

    // g_r0ServiceOperationInFlight 作用：
    // - 输入：无；
    // - 处理：R0 启停改为后台执行后，用进程级门闩挡掉重复点击造成的并发 SCM 操作；
    //         MainWindow 是单实例窗口，这里用文件级静态状态即可覆盖全部入口；
    // - 返回：无；true 表示线程池里已经有一次启停任务在跑。
    std::atomic_bool g_r0ServiceOperationInFlight{ false };

    // executeR0ServiceStopOnWorker 作用：
    // - 输入：无；服务名固定取 kR0DriverServiceName；
    // - 处理：在任意线程完成 SCM 连接 / ControlService / 等待 SERVICE_STOPPED / DeleteService 全过程，
    //         全程不触碰任何 QWidget，也不读写 MainWindow 成员；
    // - 返回：纯值类型结论；失败原因由 stageText / errorCode / detailText 描述。
    R0ServiceOperationOutcome executeR0ServiceStopOnWorker()
    {
        R0ServiceOperationOutcome operationOutcome;

        ScopedServiceHandle scmHandle(::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT));
        if (!scmHandle.isValid())
        {
            operationOutcome.errorCode = ::GetLastError();
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：无法连接服务控制管理器。");
            return operationOutcome;
        }

        ScopedServiceHandle serviceHandle(::OpenServiceW(
            scmHandle.get(),
            kR0DriverServiceName,
            SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE));
        if (!serviceHandle.isValid())
        {
            const DWORD openError = ::GetLastError();
            if (openError == ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.succeeded = true;
                operationOutcome.alreadyInTargetState = true;
                return operationOutcome;
            }
            operationOutcome.errorCode = openError;
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：无法打开驱动服务。");
            return operationOutcome;
        }

        SERVICE_STATUS_PROCESS currentStatus{};
        DWORD queryError = ERROR_SUCCESS;
        if (!queryServiceStatus(serviceHandle.get(), currentStatus, queryError))
        {
            operationOutcome.errorCode = queryError;
            operationOutcome.stageText = QStringLiteral("R0 卸载失败：读取驱动服务状态失败。");
            return operationOutcome;
        }

        if (currentStatus.dwCurrentState != SERVICE_STOPPED)
        {
            if (currentStatus.dwCurrentState != SERVICE_STOP_PENDING)
            {
                SERVICE_STATUS ignoredStatus{};
                if (::ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &ignoredStatus) == FALSE)
                {
                    const DWORD stopError = ::GetLastError();
                    if (stopError != ERROR_SERVICE_NOT_ACTIVE)
                    {
                        // 命中 1052（不接受 STOP 控制）时，回退到 NtUnloadDriver 直卸路径。
                        if (stopError == ERROR_INVALID_SERVICE_CONTROL)
                        {
                            DWORD privilegeError = ERROR_SUCCESS;
                            const bool privilegeOk =
                                enableCurrentProcessPrivilege(SE_LOAD_DRIVER_NAME, &privilegeError);

                            long ntUnloadStatus = 0;
                            const bool unloadOk = tryNtUnloadDriverByServiceName(
                                kR0DriverServiceName,
                                &ntUnloadStatus);
                            if (!unloadOk)
                            {
                                operationOutcome.errorCode = stopError;
                                operationOutcome.stageText =
                                    QStringLiteral("R0 卸载失败：ControlService 返回 1052，且 NtUnloadDriver 回退失败。");
                                operationOutcome.detailText =
                                    QStringLiteral("enablePrivilegeOk=%1, privilegeError=%2, ntUnloadStatus=0x%3")
                                    .arg(privilegeOk ? QStringLiteral("true") : QStringLiteral("false"))
                                    .arg(privilegeError)
                                    .arg(static_cast<qulonglong>(static_cast<unsigned long>(ntUnloadStatus)), 8, 16, QChar('0'));
                                return operationOutcome;
                            }

                            operationOutcome.usedDirectNtUnloadFallback = true;
                            currentStatus.dwCurrentState = SERVICE_STOPPED;
                        }
                        else
                        {
                            operationOutcome.errorCode = stopError;
                            operationOutcome.stageText = QStringLiteral("R0 卸载失败：停止驱动服务失败。");
                            return operationOutcome;
                        }
                    }
                }
            }

            if (!operationOutcome.usedDirectNtUnloadFallback)
            {
                SERVICE_STATUS_PROCESS latestStatus{};
                DWORD waitError = ERROR_SUCCESS;
                if (!waitServiceState(
                    serviceHandle.get(),
                    SERVICE_STOPPED,
                    kR0ServiceStopWaitTimeoutMs,
                    latestStatus,
                    waitError))
                {
                    if (waitError != ERROR_SUCCESS)
                    {
                        operationOutcome.errorCode = waitError;
                        operationOutcome.stageText = QStringLiteral("R0 卸载失败：等待服务停止时查询状态失败。");
                    }
                    else
                    {
                        operationOutcome.errorCode = ERROR_TIMEOUT;
                        operationOutcome.stageText = QStringLiteral("R0 卸载失败：等待服务停止超时。");
                        operationOutcome.detailText =
                            buildServiceWaitDetailText(latestStatus, kR0ServiceStopWaitTimeoutMs);
                    }
                    return operationOutcome;
                }
            }
        }

        if (::DeleteService(serviceHandle.get()) == FALSE)
        {
            const DWORD deleteError = ::GetLastError();
            if (deleteError != ERROR_SERVICE_MARKED_FOR_DELETE &&
                deleteError != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.errorCode = deleteError;
                operationOutcome.stageText = QStringLiteral("R0 卸载失败：删除驱动服务失败。");
                return operationOutcome;
            }
        }

        operationOutcome.succeeded = true;
        return operationOutcome;
    }

    // executeR0ServiceStartOnWorker 作用：
    // - 输入 nativeDriverPath：UI 线程已校验存在的 KswordARK.sys 本地路径（值传递，避免跨线程共享）；
    // - 处理：在任意线程完成 SCM 连接 / CreateService 或 ChangeServiceConfig / StartService /
    //         等待 SERVICE_RUNNING 全过程，全程不触碰任何 QWidget；
    // - 返回：纯值类型结论；startServiceCallFailed 为 true 时由 UI 线程再判定是否属于签名失败。
    R0ServiceOperationOutcome executeR0ServiceStartOnWorker(const QString& nativeDriverPath)
    {
        R0ServiceOperationOutcome operationOutcome;

        ScopedServiceHandle scmHandle(::OpenSCManagerW(
            nullptr,
            SERVICES_ACTIVE_DATABASE,
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE));
        if (!scmHandle.isValid())
        {
            operationOutcome.errorCode = ::GetLastError();
            operationOutcome.stageText = QStringLiteral("R0 启动失败：无法连接服务控制管理器。");
            return operationOutcome;
        }

        ScopedServiceHandle serviceHandle(::OpenServiceW(
            scmHandle.get(),
            kR0DriverServiceName,
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE));
        if (!serviceHandle.isValid())
        {
            const DWORD openError = ::GetLastError();
            if (openError != ERROR_SERVICE_DOES_NOT_EXIST)
            {
                operationOutcome.errorCode = openError;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：无法打开已有驱动服务。");
                return operationOutcome;
            }

            const std::wstring driverPathWide = nativeDriverPath.toStdWString();
            serviceHandle.reset(::CreateServiceW(
                scmHandle.get(),
                kR0DriverServiceName,
                kR0DriverDisplayName,
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_CHANGE_CONFIG | DELETE,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                driverPathWide.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr));
            if (!serviceHandle.isValid())
            {
                operationOutcome.errorCode = ::GetLastError();
                operationOutcome.stageText = QStringLiteral("R0 启动失败：创建驱动服务失败。");
                operationOutcome.detailText = QStringLiteral("驱动路径：%1").arg(nativeDriverPath);
                return operationOutcome;
            }
        }
        else
        {
            const std::wstring driverPathWide = nativeDriverPath.toStdWString();
            if (::ChangeServiceConfigW(
                serviceHandle.get(),
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                driverPathWide.c_str(),
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                kR0DriverDisplayName) == FALSE)
            {
                operationOutcome.errorCode = ::GetLastError();
                operationOutcome.stageText = QStringLiteral("R0 启动失败：更新驱动服务配置失败。");
                return operationOutcome;
            }
        }

        SERVICE_STATUS_PROCESS currentStatus{};
        DWORD queryError = ERROR_SUCCESS;
        if (!queryServiceStatus(serviceHandle.get(), currentStatus, queryError))
        {
            operationOutcome.errorCode = queryError;
            operationOutcome.stageText = QStringLiteral("R0 启动失败：读取服务状态失败。");
            return operationOutcome;
        }

        if (isRunningLikeServiceState(currentStatus.dwCurrentState))
        {
            operationOutcome.succeeded = true;
            operationOutcome.alreadyInTargetState = true;
            return operationOutcome;
        }

        if (::StartServiceW(serviceHandle.get(), 0, nullptr) == FALSE)
        {
            const DWORD startError = ::GetLastError();
            if (startError == ERROR_SERVICE_ALREADY_RUNNING)
            {
                operationOutcome.succeeded = true;
                operationOutcome.alreadyInTargetState = true;
                return operationOutcome;
            }

            // 签名/完整性校验失败与普通启动失败共用同一个错误码出口，
            // 具体走哪种提示由 UI 线程用 MainWindow::isR0DriverSignatureFailure 判定。
            operationOutcome.errorCode = startError;
            operationOutcome.startServiceCallFailed = true;

            // SCM 的错误码本身不区分失败原因，必须带上驱动自己留下的阶段记录，
            // 用户才能在 issue 里直接给出可定位的信息。
            operationOutcome.stageText = QStringLiteral("R0 启动失败：驱动服务启动失败。");
            operationOutcome.detailText = QStringLiteral("驱动路径：%1\n%2")
                .arg(nativeDriverPath)
                .arg(describeR0StartupBreadcrumb());
            return operationOutcome;
        }

        SERVICE_STATUS_PROCESS latestStatus{};
        DWORD waitError = ERROR_SUCCESS;
        if (!waitServiceState(
            serviceHandle.get(),
            SERVICE_RUNNING,
            kR0ServiceStartWaitTimeoutMs,
            latestStatus,
            waitError))
        {
            if (waitError != ERROR_SUCCESS)
            {
                operationOutcome.errorCode = waitError;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：等待服务运行时查询状态失败。");
            }
            else
            {
                operationOutcome.errorCode = ERROR_TIMEOUT;
                operationOutcome.stageText = QStringLiteral("R0 启动失败：等待驱动进入运行态超时。");
                operationOutcome.detailText =
                    QStringLiteral("当前状态：%1").arg(serviceStateToText(latestStatus.dwCurrentState));
            }
            return operationOutcome;
        }

        operationOutcome.succeeded = true;
        return operationOutcome;
    }

    // dispatchR0ServiceStopToWorker 作用：
    // - 输入 completionCallback：停驱结束后在 UI 线程执行的结果处理回调；
    // - 处理：把整段 SCM 停止/等待/删除丢进全局线程池，完成后把值类型结论回投到 UI 线程；
    // - 返回：无返回值；调用方立即返回，不再被 waitServiceState 的 ::Sleep 轮询冻住界面。
    void dispatchR0ServiceStopToWorker(
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback)
    {
        QThreadPool::globalInstance()->start(
            [completionCallback = std::move(completionCallback)]()
            {
                const R0ServiceOperationOutcome operationOutcome = executeR0ServiceStopOnWorker();
                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    appInstance,
                    [completionCallback, operationOutcome]()
                    {
                        completionCallback(operationOutcome);
                    });
            });
    }

    // dispatchR0ServiceStartToWorker 作用：
    // - 输入 nativeDriverPath：已校验存在的驱动文件路径；completionCallback：UI 线程结果处理回调；
    // - 处理：把整段 SCM 创建/启动/等待运行态丢进全局线程池，完成后把值类型结论回投到 UI 线程；
    // - 返回：无返回值；调用方立即返回，启动超时上限不再体现为界面冻结。
    void dispatchR0ServiceStartToWorker(
        const QString& nativeDriverPath,
        std::function<void(const R0ServiceOperationOutcome&)> completionCallback)
    {
        QThreadPool::globalInstance()->start(
            [nativeDriverPath, completionCallback = std::move(completionCallback)]()
            {
                const R0ServiceOperationOutcome operationOutcome =
                    executeR0ServiceStartOnWorker(nativeDriverPath);
                QCoreApplication* const appInstance = QCoreApplication::instance();
                if (appInstance == nullptr)
                {
                    return;
                }
                QMetaObject::invokeMethod(
                    appInstance,
                    [completionCallback, operationOutcome]()
                    {
                        completionCallback(operationOutcome);
                    });
            });
    }

    // buildPrivilegeButtonStyle 作用：
    // - 按“当前是否具备权限”生成按钮样式；
    // - true  -> 蓝底白字；
    // - false -> 白底蓝字。
    QString buildPrivilegeButtonStyle(const bool activeState)
    {
        const QString backgroundColor = activeState
            ? KswordTheme::PrimaryBlueHex
            : KswordTheme::SurfaceHex();
        const QString textColor = activeState
            ? KswordTheme::OnAccentHex()
            : (KswordTheme::IsDarkModeEnabled() ? KswordTheme::TextPrimaryHex() : KswordTheme::PrimaryBlueHex);
        const QString hoverColor = activeState
            ? KswordTheme::PrimaryBlueSolidHoverHex()
            : KswordTheme::PrimaryBlueSolidHoverHex();
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%6;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%5;"
            "  color:%6;"
            "}")
            .arg(backgroundColor)
            .arg(textColor)
            .arg(KswordTheme::PrimaryBlueBorderHex)
            .arg(hoverColor)
            .arg(KswordTheme::PrimaryBluePressedHex)
            .arg(KswordTheme::OnAccentHex());
    }

    // buildR0ButtonStyle 作用：
    // - R0 专用样式；
    // - true  -> 蓝底，字体按深浅主题自动黑/白；
    // - false -> 黑/白底蓝字。
    QString buildR0ButtonStyle(const bool activeState)
    {
        const QString adaptiveTextColor = KswordTheme::OnAccentHex();
        const QString backgroundColor = activeState
            ? KswordTheme::PrimaryBlueHex
            : KswordTheme::SurfaceHex();
        const QString textColor = activeState
            ? adaptiveTextColor
            : KswordTheme::PrimaryBlueHex;
        const QString hoverColor = activeState
            ? KswordTheme::PrimaryBlueSolidHoverHex()
            : KswordTheme::PrimaryBlueSubtleHex();
        const QString pressedColor = activeState
            ? KswordTheme::PrimaryBluePressedHex
            : KswordTheme::ThemeColorName(KswordTheme::PrimaryBlueSurfacePressedColor());
        return QStringLiteral(
            "QPushButton {"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  border-radius:3px;"
            "  padding:2px 8px;"
            "  font-weight:600;"
            "}"
            "QPushButton:hover {"
            "  background:%4;"
            "  color:%5;"
            "  border:1px solid %4;"
            "}"
            "QPushButton:pressed {"
            "  background:%6;"
            "  color:%5;"
            "}")
            .arg(backgroundColor)
            .arg(textColor)
            .arg(KswordTheme::PrimaryBlueBorderHex)
            .arg(hoverColor)
            .arg(activeState ? adaptiveTextColor : KswordTheme::TextPrimaryColorHex())
            .arg(pressedColor);
    }

    // normalizeOpacityPercent 作用：
    // - 把透明度值限制在 0~100 范围，防止非法参数影响绘制。
    // 调用方式：生成背景画刷前调用。
    // 入参 rawOpacityPercent：原始透明度值。
    // 返回：合法透明度值。
    int normalizeOpacityPercent(const int rawOpacityPercent)
    {
        if (rawOpacityPercent < 0)
        {
            return 0;
        }
        if (rawOpacityPercent > 100)
        {
            return 100;
        }
        return rawOpacityPercent;
    }

    // kMaxBlurSourceEdgePixels 作用：
    // - 模糊前把背景图长边降采样到该上限；
    // - 盒式模糊的代价随像素数线性增长，4K 壁纸直接模糊会让设置页拖动滑块时肉眼卡顿；
    // - 模糊结果本身是低频信号，绘制时再放大回窗口尺寸不会暴露降采样损失。
    constexpr int kMaxBlurSourceEdgePixels = 1280;
    // kMaxBlurRadiusRatio 作用：
    // - 100% 模糊强度对应的半径占降采样图长边的比例；
    // - 用比例而非固定像素，保证不同分辨率的背景图在同一档位下观感一致。
    constexpr double kMaxBlurRadiusRatio = 0.06;
    // kBlurPassCount 作用：
    // - 盒式模糊的叠加遍数；三遍即可把方形核收敛到肉眼无法分辨的高斯近似。
    constexpr int kBlurPassCount = 3;

    // applyBoxBlurPass 作用：
    // - 对 ARGB32_Premultiplied 图像执行一次“水平 + 垂直”盒式模糊；
    // - 预乘 alpha 下各通道可独立做线性平均，因此逐通道滑动窗口即可，
    //   不需要先反预乘（反预乘会在近全透明像素上放大量化误差）。
    // 调用方式：buildBlurredPixmap 内部按遍数循环调用。
    // 入参 targetImage：就地模糊的图像，必须是 Format_ARGB32_Premultiplied；
    // 入参 radiusPixels：单遍模糊半径（像素），<=0 时直接返回。
    void applyBoxBlurPass(QImage& targetImage, const int radiusPixels)
    {
        if (radiusPixels <= 0
            || targetImage.isNull()
            || targetImage.format() != QImage::Format_ARGB32_Premultiplied)
        {
            return;
        }

        const int imageWidth = targetImage.width();
        const int imageHeight = targetImage.height();
        if (imageWidth <= 0 || imageHeight <= 0)
        {
            return;
        }

        // blurAxis 作用：沿单一方向做滑动窗口平均。
        // 水平与垂直只差“下一个像素”与“下一条线”的字节步长，因此共用同一段实现，
        // 避免两份几乎相同的边界处理代码各自漂移。
        const auto blurAxis = [](uchar* const imageBits,
            const int lineCount,
            const int lineLength,
            const int lineStrideBytes,
            const int pixelStrideBytes,
            const int passRadiusPixels)
            {
                if (lineLength <= 1)
                {
                    return;
                }

                // windowSize 用途：盒式窗口覆盖的像素数，中心像素两侧各 passRadiusPixels 个。
                const int windowSize = passRadiusPixels * 2 + 1;
                std::vector<QRgb> lineBuffer(static_cast<size_t>(lineLength));

                for (int lineIndex = 0; lineIndex < lineCount; ++lineIndex)
                {
                    uchar* const lineStart =
                        imageBits + static_cast<size_t>(lineIndex) * static_cast<size_t>(lineStrideBytes);

                    // 先把整条线拷进缓冲：滑动窗口会边写边读，原地读取会取到已被覆盖的新值。
                    for (int offset = 0; offset < lineLength; ++offset)
                    {
                        lineBuffer[static_cast<size_t>(offset)] = *reinterpret_cast<const QRgb*>(
                            lineStart + static_cast<size_t>(offset) * static_cast<size_t>(pixelStrideBytes));
                    }

                    // 初始化窗口：越界位置按边缘像素补齐（clamp），
                    // 否则窗口在两端只累加了部分像素，会沿图片边框留下一圈暗带。
                    int sumRed = 0;
                    int sumGreen = 0;
                    int sumBlue = 0;
                    int sumAlpha = 0;
                    for (int windowOffset = -passRadiusPixels; windowOffset <= passRadiusPixels; ++windowOffset)
                    {
                        const QRgb samplePixel =
                            lineBuffer[static_cast<size_t>(std::clamp(windowOffset, 0, lineLength - 1))];
                        sumRed += qRed(samplePixel);
                        sumGreen += qGreen(samplePixel);
                        sumBlue += qBlue(samplePixel);
                        sumAlpha += qAlpha(samplePixel);
                    }

                    for (int offset = 0; offset < lineLength; ++offset)
                    {
                        *reinterpret_cast<QRgb*>(
                            lineStart + static_cast<size_t>(offset) * static_cast<size_t>(pixelStrideBytes)) =
                            qRgba(
                                sumRed / windowSize,
                                sumGreen / windowSize,
                                sumBlue / windowSize,
                                sumAlpha / windowSize);

                        const QRgb leavingPixel =
                            lineBuffer[static_cast<size_t>(std::clamp(offset - passRadiusPixels, 0, lineLength - 1))];
                        const QRgb enteringPixel =
                            lineBuffer[static_cast<size_t>(std::clamp(offset + passRadiusPixels + 1, 0, lineLength - 1))];
                        sumRed += qRed(enteringPixel) - qRed(leavingPixel);
                        sumGreen += qGreen(enteringPixel) - qGreen(leavingPixel);
                        sumBlue += qBlue(enteringPixel) - qBlue(leavingPixel);
                        sumAlpha += qAlpha(enteringPixel) - qAlpha(leavingPixel);
                    }
                }
            };

        // bytesPerLine 可能带行末填充，因此纵向遍历必须以它为步长，不能假定 width*4。
        const int bytesPerLine = static_cast<int>(targetImage.bytesPerLine());
        uchar* const imageBits = targetImage.bits();
        if (imageBits == nullptr)
        {
            return;
        }
        blurAxis(imageBits, imageHeight, imageWidth, bytesPerLine, 4, radiusPixels);
        blurAxis(imageBits, imageWidth, imageHeight, 4, bytesPerLine, radiusPixels);
    }

    // buildBlurredPixmap 作用：
    // - 按 0~100 的“玻璃模糊半径”强度生成背景图的模糊副本；
    // - 供主窗口根容器与浮动 Dock 画刷共用，保证两处观感一致且只模糊一次。
    // 调用方式：MainWindow::refreshBackgroundImageBlurCache 在半径或源图变化时调用。
    // 入参 sourcePixmap：已解码的背景图原件；
    // 入参 blurRadiusPercent：模糊强度百分比（0~100）。
    // 返回：模糊后的位图；强度为 0 或源图为空时返回空位图，表示应直接使用原图。
    QPixmap buildBlurredPixmap(const QPixmap& sourcePixmap, const int blurRadiusPercent)
    {
        const int normalizedPercent = normalizeOpacityPercent(blurRadiusPercent);
        if (sourcePixmap.isNull() || normalizedPercent <= 0)
        {
            return QPixmap();
        }

        QImage workingImage = sourcePixmap.toImage();
        if (workingImage.isNull())
        {
            return QPixmap();
        }

        const int sourceLongEdge = std::max(workingImage.width(), workingImage.height());
        if (sourceLongEdge > kMaxBlurSourceEdgePixels)
        {
            workingImage = (workingImage.width() >= workingImage.height())
                ? workingImage.scaledToWidth(kMaxBlurSourceEdgePixels, Qt::SmoothTransformation)
                : workingImage.scaledToHeight(kMaxBlurSourceEdgePixels, Qt::SmoothTransformation);
        }
        if (workingImage.format() != QImage::Format_ARGB32_Premultiplied)
        {
            workingImage = workingImage.convertToFormat(QImage::Format_ARGB32_Premultiplied);
        }
        if (workingImage.isNull())
        {
            return QPixmap();
        }

        // totalRadiusPixels 用途：本次强度对应的总模糊半径；
        // 分摊到多遍盒式模糊后，单遍半径至少为 1，否则整个循环等于空转。
        const int workingLongEdge = std::max(workingImage.width(), workingImage.height());
        const int totalRadiusPixels = static_cast<int>(std::lround(
            static_cast<double>(workingLongEdge)
            * kMaxBlurRadiusRatio
            * (static_cast<double>(normalizedPercent) / 100.0)));
        if (totalRadiusPixels <= 0)
        {
            return QPixmap();
        }
        const int passRadiusPixels = std::max(1, totalRadiusPixels / kBlurPassCount);

        for (int passIndex = 0; passIndex < kBlurPassCount; ++passIndex)
        {
            applyBoxBlurPass(workingImage, passRadiusPixels);
        }
        return QPixmap::fromImage(workingImage);
    }

    // MainWindowBackgroundWidget 作用：
    // - 作为主窗口根容器的唯一背景绘制者；
    // - 每次绘制都按当前真实 rect 执行“居中、等比覆盖”，避免启动阶段预测窗口尺寸。
    // kTranslucentTintAlpha 作用：
    // - 穿透模式无背景图时主题着色层的默认不透明度（0~255）；
    // - 仅作为外观配置抵达前的初值，运行期由“直透着色不透明度”设置覆盖；
    // - 数值越低桌面透出越多，越高前景可读性越强。
    constexpr int kTranslucentTintAlpha = 165;

    class MainWindowBackgroundWidget final : public QWidget
    {
    public:
        explicit MainWindowBackgroundWidget(QWidget* parent = nullptr)
            : QWidget(parent)
        {
            setAutoFillBackground(false);
            setAttribute(Qt::WA_StyledBackground, false);
            setAttribute(Qt::WA_OpaquePaintEvent, true);
        }

        void setBackground(
            const QColor& baseColor,
            const QPixmap* sourceImage,
            const int imageOpacityPercent)
        {
            const int normalizedOpacityPercent = normalizeOpacityPercent(imageOpacityPercent);
            const quint64 sourceImageCacheKey = sourceImage == nullptr ? 0 : sourceImage->cacheKey();
            if (m_baseColor == baseColor
                && m_imageOpacityPercent == normalizedOpacityPercent
                && m_sourceImageCacheKey == sourceImageCacheKey)
            {
                return;
            }

            m_baseColor = baseColor;
            m_imageOpacityPercent = normalizedOpacityPercent;
            m_sourceImageCacheKey = sourceImageCacheKey;
            m_sourceImage = sourceImage == nullptr ? QPixmap() : *sourceImage;
            update();
        }

        // setTranslucentMode 作用：
        // - 切换“背景透明穿透”的绘制模式；
        // - 穿透时底色层不再填充，由背景图自身 alpha 或系统材质决定透明度；
        // - 需要顶层窗口已启用 WA_TranslucentBackground 才有实际穿透效果。
        // 入参 translucentEnabled：是否进入穿透绘制。
        // 入参 paintTintWhenNoImage：无背景图时是否自绘着色层；
        //   亚克力已由系统合成着色时必须传 false，否则两层着色叠加会发浑。
        // 入参 tintAlpha：自绘着色层的不透明度（0~255），来自“直透着色不透明度”设置。
        void setTranslucentMode(
            const bool translucentEnabled,
            const bool paintTintWhenNoImage,
            const int tintAlpha)
        {
            // hitTestSafeTintAlpha 用途：分层窗口对 alpha==0 的像素做输入穿透，
            // 直透强度调到 0 时若真按 0 绘制，整窗会失去鼠标响应，因此下限钳到 1。
            const int hitTestSafeTintAlpha = std::clamp(tintAlpha, 1, 255);
            if (m_translucentMode == translucentEnabled
                && m_paintTintWhenNoImage == paintTintWhenNoImage
                && m_tintAlpha == hitTestSafeTintAlpha)
            {
                return;
            }
            m_translucentMode = translucentEnabled;
            m_paintTintWhenNoImage = paintTintWhenNoImage;
            m_tintAlpha = hitTestSafeTintAlpha;
            // 穿透绘制会留下透明像素，必须放弃“完全不透明绘制”性能假设。
            setAttribute(Qt::WA_OpaquePaintEvent, !translucentEnabled);
            update();
        }


    protected:
        void paintEvent(QPaintEvent* event) override
        {
            QPainter painter(this);
            if (event != nullptr)
            {
                painter.setClipRegion(event->region());
            }

            // hasBackgroundImage 用途：穿透模式下区分两种绘制路径。
            const bool hasBackgroundImage = !m_sourceImage.isNull() && m_imageOpacityPercent > 0;
            if (m_translucentMode)
            {
                // hitTestFloorColor 用途：代替“完全透明”的底色。
                // 分层窗口对 alpha==0 的像素做输入穿透（鼠标事件直接投给后方窗口），
                // 因此穿透绘制的最低 alpha 必须为 1：视觉上不可分辨，
                // 但保证整窗仍可接收鼠标消息。
                QColor hitTestFloorColor = m_baseColor;
                hitTestFloorColor.setAlpha(1);

                painter.setCompositionMode(QPainter::CompositionMode_Source);
                if (hasBackgroundImage)
                {
                    // 有背景图：底色层近乎完全透明，由图片自身 alpha 决定穿透程度。
                    painter.fillRect(rect(), hitTestFloorColor);
                }
                else if (m_paintTintWhenNoImage)
                {
                    // 无背景图且系统磨砂不可用（含用户选择的“直透桌面”）：
                    // 自绘半透明着色层，不透明度由“直透着色不透明度”设置决定，
                    // 低值偏向直透桌面，高值偏向前景文字可读。
                    QColor tintColor = m_baseColor;
                    tintColor.setAlpha(m_tintAlpha);
                    painter.fillRect(rect(), tintColor);
                }
                else
                {
                    // 无背景图且系统亚克力已生效：着色由系统合成，
                    // 这里只保留输入命中的 alpha 下限。
                    painter.fillRect(rect(), hitTestFloorColor);
                }
                painter.setCompositionMode(QPainter::CompositionMode_SourceOver);
            }
            else
            {
                painter.fillRect(rect(), m_baseColor);
            }

            if (m_sourceImage.isNull() || m_imageOpacityPercent <= 0 || rect().isEmpty())
            {
                return;
            }

            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(m_imageOpacityPercent) / 100.0);
            painter.drawPixmap(
                coverTargetRectFor(m_sourceImage.size()),
                m_sourceImage,
                QRectF(QPointF(0, 0), m_sourceImage.size()));
        }

    private:
        // coverTargetRectFor 作用：
        // - 计算“居中、等比覆盖”铺满当前控件时源图应绘制到的目标矩形。
        // 入参 sourceSize：源图尺寸。
        // 返回：目标绘制矩形（可能超出控件边界，由居中裁剪产生覆盖效果）。
        QRectF coverTargetRectFor(const QSize& sourceSize) const
        {
            QSizeF scaledSize(sourceSize);
            scaledSize.scale(QSizeF(rect().size()), Qt::KeepAspectRatioByExpanding);
            return QRectF(
                (static_cast<double>(rect().width()) - scaledSize.width()) / 2.0,
                (static_cast<double>(rect().height()) - scaledSize.height()) / 2.0,
                scaledSize.width(),
                scaledSize.height());
        }

        QColor m_baseColor = Qt::black;
        QPixmap m_sourceImage;
        int m_imageOpacityPercent = 0;
        quint64 m_sourceImageCacheKey = 0;
        bool m_translucentMode = false;      // m_translucentMode：背景透明区域是否穿透窗口。
        bool m_paintTintWhenNoImage = true;  // m_paintTintWhenNoImage：无背景图时是否自绘着色兜底。
        int m_tintAlpha = kTranslucentTintAlpha; // m_tintAlpha：自绘着色层不透明度，由外观设置下发。
    };

    // buildBackgroundBrush 作用：
    // - 按“纯色底 + 可选背景图 + 透明度”组合一张画刷贴图；
    // - 仅供仍使用独立调色板的浮动 Dock 容器绘制。
    // 调用方式：MainWindow::applyFloatingDockContainerAppearance 调用。
    // 入参 windowSize：目标窗口尺寸；
    // 入参 baseColor：主题基底色（深色黑、浅色白）；
    // 入参 sourceImage：已在线程池解码并由 UI 线程转换的缓存图片；可为空。
    // 入参 imageOpacityPercent：背景图透明度（0~100）。
    // 返回：可直接设置到 QPalette::Window 的画刷。
    QBrush buildBackgroundBrush(
        const QSize& windowSize,
        const QColor& baseColor,
        const QPixmap* sourceImage,
        const int imageOpacityPercent)
    {
        const QSize safeSize = windowSize.isValid() ? windowSize : QSize(1, 1);
        const int normalizedOpacityPercent = normalizeOpacityPercent(imageOpacityPercent);
        // effectiveSourceImage 用途：透明度为零时跳过合成，同时不访问任何文件路径。
        const QPixmap* effectiveSourceImage = normalizedOpacityPercent > 0 ? sourceImage : nullptr;
        const quint64 sourceImageCacheKey =
            effectiveSourceImage == nullptr ? 0 : effectiveSourceImage->cacheKey();

        // 主窗口 resize 期间通常会连续收到相同尺寸或相邻布局事件。
        // 缓存最近一次合成图，避免重复分配整窗像素缓冲并再次进行平滑缩放。
        static QSize cachedSize;
        static QColor cachedBaseColor;
        static int cachedOpacityPercent = -1;
        static quint64 cachedSourceImageCacheKey = 0;
        static QPixmap cachedComposedPixmap;
        const bool cacheHit =
            cachedSize == safeSize
            && cachedBaseColor == baseColor
            && cachedOpacityPercent == normalizedOpacityPercent
            && cachedSourceImageCacheKey == sourceImageCacheKey
            && !cachedComposedPixmap.isNull();
        if (cacheHit)
        {
            return QBrush(cachedComposedPixmap);
        }

        QPixmap composedPixmap(safeSize);
        composedPixmap.fill(baseColor);
        if (effectiveSourceImage != nullptr)
        {
            QPainter painter(&composedPixmap);
            painter.setRenderHint(QPainter::SmoothPixmapTransform, true);
            painter.setOpacity(static_cast<double>(normalizedOpacityPercent) / 100.0);

            // scaledImageSize 作用：按“覆盖整个窗口”策略计算缩放尺寸。
            QSizeF scaledImageSize = effectiveSourceImage->size();
            scaledImageSize.scale(safeSize, Qt::KeepAspectRatioByExpanding);

            const QRectF targetRect(
                (static_cast<double>(safeSize.width()) - scaledImageSize.width()) / 2.0,
                (static_cast<double>(safeSize.height()) - scaledImageSize.height()) / 2.0,
                scaledImageSize.width(),
                scaledImageSize.height());

            painter.drawPixmap(
                targetRect,
                *effectiveSourceImage,
                QRectF(QPointF(0, 0), effectiveSourceImage->size()));
        }

        cachedSize = safeSize;
        cachedBaseColor = baseColor;
        cachedOpacityPercent = normalizedOpacityPercent;
        cachedSourceImageCacheKey = sourceImageCacheKey;
        cachedComposedPixmap = composedPixmap;
        return QBrush(composedPixmap);
    }

    // buildGlobalTooltipStyleBlock 作用：
    // - 生成全局 Tooltip 样式片段；
    // - 片段带起止标记，供 applyGlobalApplicationStyleBlocks 做替换更新。
    // 调用方式：applyAppearanceSettings 内部调用。
    // 入参 darkModeEnabled：当前是否深色模式。
    // 返回：可直接拼接到 QApplication 样式表的 Tooltip 片段。
    QString buildGlobalTooltipStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        // tooltipRule 作用：QToolTip 规则本体，统一深浅色背景与文字。
        const QString tooltipRule = QStringLiteral(
            "QToolTip{"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  padding:4px 6px;"
            "  border-radius:3px;"
            "}")
            .arg(KswordTheme::SurfaceColorHex())
            .arg(KswordTheme::TextPrimaryColorHex())
            .arg(KswordTheme::BorderColorHex());

        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kTooltipStyleBeginMarker))
            .arg(tooltipRule)
            .arg(QString::fromLatin1(kTooltipStyleEndMarker));
    }

    // buildGlobalContextMenuStyleBlock 作用：
    // - 生成全局右键菜单样式片段，兜底所有标准输入控件右键菜单；
    // - 修复独立顶层窗口中输入框右键菜单在深浅色切换后背景不一致的问题。
    // 调用方式：applyAppearanceSettings 内部调用。
    // 入参 darkModeEnabled：当前是否深色模式。
    // 返回：可直接拼接到 QApplication 样式表的 QMenu 片段。
    QString buildGlobalContextMenuStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        const QString menuBackgroundColor = KswordTheme::SurfaceColorHex();
        const QString menuTextColor = KswordTheme::TextPrimaryColorHex();
        const QString menuBorderColor = KswordTheme::BorderColorHex();
        const QString disabledTextColor = KswordTheme::TextDisabledColorHex();

        const QString contextMenuRule = QStringLiteral(
            "QMenu{"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "  border:1px solid %3 !important;"
            "  padding:3px;"
            "}"
            "QMenu::item{"
            "  color:%2 !important;"
            "  padding:5px 18px 5px 14px;"
            "  background-color:transparent !important;"
            "}"
            "QMenu::item:selected{"
            "  background-color:%4 !important;"
            "  color:%6 !important;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5 !important;"
            "  background-color:transparent !important;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background-color:%3;"
            "  margin:2px 6px;"
            "}")
            .arg(menuBackgroundColor)
            .arg(menuTextColor)
            .arg(menuBorderColor)
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(disabledTextColor)
            .arg(KswordTheme::OnAccentHex());

        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kContextMenuStyleBeginMarker))
            .arg(contextMenuRule)
            .arg(QString::fromLatin1(kContextMenuStyleEndMarker));
    }

    // buildGlobalControlContrastStyleBlock 作用：
    // - 为复选框、单选框、可勾选视图项和滑块提供完整的状态图形；
    // - 所有活动边界相对控件表面至少保持 3:1 非文本对比度；
    // - 勾号、半选横线和单选圆点按实际填充色选择黑/白图形。
    QString buildGlobalControlContrastStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);

        const QColor accentColor = KswordTheme::ControlAccentColor();
        const QColor accentHoverColor = KswordTheme::ControlAccentHoverColor();
        const QColor accentPressedColor = KswordTheme::ControlAccentPressedColor();
        const QColor disabledFillColor = KswordTheme::ControlDisabledFillColor();
        const auto glyphPath = [](const QColor& fillColor, const QString& whitePath, const QString& blackPath) {
            return KswordTheme::MaximumContrastMonochromeColor(fillColor) == KswordTheme::WhiteColor()
                ? whitePath
                : blackPath;
        };

        const QString whiteCheckPath = QStringLiteral(":/Icon/ks_control_check_white.svg");
        const QString blackCheckPath = QStringLiteral(":/Icon/ks_control_check_black.svg");
        const QString whiteDashPath = QStringLiteral(":/Icon/ks_control_dash_white.svg");
        const QString blackDashPath = QStringLiteral(":/Icon/ks_control_dash_black.svg");
        const QString whiteRadioPath = QStringLiteral(":/Icon/ks_control_radio_white.svg");
        const QString blackRadioPath = QStringLiteral(":/Icon/ks_control_radio_black.svg");

        QString controlStyle = QString::fromLatin1(
            "\n__BEGIN_MARKER__\n"
            "QCheckBox,QRadioButton{spacing:6px;}"
            "QCheckBox:disabled,QRadioButton:disabled{color:__DISABLED_TEXT__; }"
            "QCheckBox::indicator,QGroupBox::indicator,QListView::indicator,QTreeView::indicator,QTableView::indicator{"
            "  width:15px;height:15px;"
            "  border:2px solid __OUTLINE__;"
            "  border-radius:3px;"
            "  background:__SURFACE__;"
            "  image:none;"
            "}"
            "QCheckBox::indicator:unchecked:hover,QGroupBox::indicator:unchecked:hover,QListView::indicator:unchecked:hover,QTreeView::indicator:unchecked:hover,QTableView::indicator:unchecked:hover{"
            "  border-color:__ACCENT__;background:__SURFACE_ALT__;"
            "}"
            "QCheckBox::indicator:checked,QGroupBox::indicator:checked,QListView::indicator:checked,QTreeView::indicator:checked,QTableView::indicator:checked{"
            "  border-color:__ACCENT__;background:__ACCENT__;image:url(__CHECK_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate,QGroupBox::indicator:indeterminate,QListView::indicator:indeterminate,QTreeView::indicator:indeterminate,QTableView::indicator:indeterminate{"
            "  border-color:__ACCENT__;background:__ACCENT__;image:url(__DASH_ICON__);"
            "}"
            "QCheckBox::indicator:checked:hover,QGroupBox::indicator:checked:hover,QListView::indicator:checked:hover,QTreeView::indicator:checked:hover,QTableView::indicator:checked:hover{"
            "  border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__CHECK_HOVER_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:hover,QGroupBox::indicator:indeterminate:hover,QListView::indicator:indeterminate:hover,QTreeView::indicator:indeterminate:hover,QTableView::indicator:indeterminate:hover{"
            "  border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__DASH_HOVER_ICON__);"
            "}"
            "QCheckBox::indicator:checked:pressed,QGroupBox::indicator:checked:pressed,QListView::indicator:checked:pressed,QTreeView::indicator:checked:pressed,QTableView::indicator:checked:pressed{"
            "  border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__CHECK_PRESSED_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:pressed,QGroupBox::indicator:indeterminate:pressed,QListView::indicator:indeterminate:pressed,QTreeView::indicator:indeterminate:pressed,QTableView::indicator:indeterminate:pressed{"
            "  border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__DASH_PRESSED_ICON__);"
            "}"
            "QCheckBox::indicator:disabled,QGroupBox::indicator:disabled,QListView::indicator:disabled,QTreeView::indicator:disabled,QTableView::indicator:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__SURFACE_MUTED__;image:none;"
            "}"
            "QCheckBox::indicator:checked:disabled,QGroupBox::indicator:checked:disabled,QListView::indicator:checked:disabled,QTreeView::indicator:checked:disabled,QTableView::indicator:checked:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__CHECK_DISABLED_ICON__);"
            "}"
            "QCheckBox::indicator:indeterminate:disabled,QGroupBox::indicator:indeterminate:disabled,QListView::indicator:indeterminate:disabled,QTreeView::indicator:indeterminate:disabled,QTableView::indicator:indeterminate:disabled{"
            "  border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__DASH_DISABLED_ICON__);"
            "}"
            "QRadioButton::indicator{"
            "  width:15px;height:15px;"
            "  border:2px solid __OUTLINE__;"
            "  border-radius:8px;"
            "  background:__SURFACE__;"
            "  image:none;"
            "}"
            "QRadioButton::indicator:unchecked:hover{border-color:__ACCENT__;background:__SURFACE_ALT__; }"
            "QRadioButton::indicator:checked{border-color:__ACCENT__;background:__ACCENT__;image:url(__RADIO_ICON__); }"
            "QRadioButton::indicator:checked:hover{border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__;image:url(__RADIO_HOVER_ICON__); }"
            "QRadioButton::indicator:checked:pressed{border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__;image:url(__RADIO_PRESSED_ICON__); }"
            "QRadioButton::indicator:disabled{border-color:__DISABLED_OUTLINE__;background:__SURFACE_MUTED__;image:none; }"
            "QRadioButton::indicator:checked:disabled{border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__;image:url(__RADIO_DISABLED_ICON__); }"
            "QSlider::groove:horizontal{height:4px;border:1px solid __OUTLINE__;border-radius:2px;background:__SURFACE_MUTED__; }"
            "QSlider::groove:vertical{width:4px;border:1px solid __OUTLINE__;border-radius:2px;background:__SURFACE_MUTED__; }"
            "QSlider::handle:horizontal{width:14px;margin:-6px 0;border:2px solid __OUTLINE__;border-radius:8px;background:__ACCENT__; }"
            "QSlider::handle:vertical{height:14px;margin:0 -6px;border:2px solid __OUTLINE__;border-radius:8px;background:__ACCENT__; }"
            "QSlider::handle:horizontal:hover,QSlider::handle:vertical:hover{border-color:__ACCENT_HOVER__;background:__ACCENT_HOVER__; }"
            "QSlider::handle:horizontal:pressed,QSlider::handle:vertical:pressed{border-color:__ACCENT_PRESSED__;background:__ACCENT_PRESSED__; }"
            "QSlider::handle:horizontal:disabled,QSlider::handle:vertical:disabled{border-color:__DISABLED_OUTLINE__;background:__DISABLED_FILL__; }"
            "__END_MARKER__\n");

        controlStyle.replace(QStringLiteral("__BEGIN_MARKER__"), QString::fromLatin1(kControlContrastStyleBeginMarker));
        controlStyle.replace(QStringLiteral("__END_MARKER__"), QString::fromLatin1(kControlContrastStyleEndMarker));
        controlStyle.replace(QStringLiteral("__SURFACE__"), KswordTheme::SurfaceColorHex());
        controlStyle.replace(QStringLiteral("__SURFACE_ALT__"), KswordTheme::SurfaceAltColorHex());
        controlStyle.replace(QStringLiteral("__SURFACE_MUTED__"), KswordTheme::SurfaceMutedColorHex());
        controlStyle.replace(QStringLiteral("__OUTLINE__"), KswordTheme::ControlOutlineHex());
        controlStyle.replace(QStringLiteral("__ACCENT__"), KswordTheme::ThemeColorName(accentColor));
        controlStyle.replace(QStringLiteral("__ACCENT_HOVER__"), KswordTheme::ThemeColorName(accentHoverColor));
        controlStyle.replace(QStringLiteral("__ACCENT_PRESSED__"), KswordTheme::ThemeColorName(accentPressedColor));
        controlStyle.replace(QStringLiteral("__DISABLED_TEXT__"), KswordTheme::TextDisabledColorHex());
        controlStyle.replace(QStringLiteral("__DISABLED_OUTLINE__"), KswordTheme::ControlDisabledOutlineHex());
        controlStyle.replace(QStringLiteral("__DISABLED_FILL__"), KswordTheme::ThemeColorName(disabledFillColor));
        controlStyle.replace(QStringLiteral("__CHECK_ICON__"), glyphPath(accentColor, whiteCheckPath, blackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_HOVER_ICON__"), glyphPath(accentHoverColor, whiteCheckPath, blackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_PRESSED_ICON__"), glyphPath(accentPressedColor, whiteCheckPath, blackCheckPath));
        controlStyle.replace(QStringLiteral("__CHECK_DISABLED_ICON__"), glyphPath(disabledFillColor, whiteCheckPath, blackCheckPath));
        controlStyle.replace(QStringLiteral("__DASH_ICON__"), glyphPath(accentColor, whiteDashPath, blackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_HOVER_ICON__"), glyphPath(accentHoverColor, whiteDashPath, blackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_PRESSED_ICON__"), glyphPath(accentPressedColor, whiteDashPath, blackDashPath));
        controlStyle.replace(QStringLiteral("__DASH_DISABLED_ICON__"), glyphPath(disabledFillColor, whiteDashPath, blackDashPath));
        controlStyle.replace(QStringLiteral("__RADIO_ICON__"), glyphPath(accentColor, whiteRadioPath, blackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_HOVER_ICON__"), glyphPath(accentHoverColor, whiteRadioPath, blackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_PRESSED_ICON__"), glyphPath(accentPressedColor, whiteRadioPath, blackRadioPath));
        controlStyle.replace(QStringLiteral("__RADIO_DISABLED_ICON__"), glyphPath(disabledFillColor, whiteRadioPath, blackRadioPath));
        return controlStyle;
    }

    // buildGlobalComboBoxStyleBlock 作用：
    // - 生成 QApplication 级组合框样式，使主窗口、独立 Dock、对话框共用同一不透明控件表面；
    // - 具体颜色由 KswordTheme::ThemedComboBoxStyle 统一提供，主背景色和主题色变化时一并刷新。
    QString buildGlobalComboBoxStyleBlock(const bool darkModeEnabled)
    {
        Q_UNUSED(darkModeEnabled);
        return QStringLiteral("\n%1\n%2\n%3\n")
            .arg(QString::fromLatin1(kComboBoxStyleBeginMarker))
            .arg(KswordTheme::ThemedComboBoxStyle())
            .arg(QString::fromLatin1(kComboBoxStyleEndMarker));
    }

    // replaceMarkedStyleBlock 作用：
    // - 在已有 QApplication 样式表文本中替换一个带起止标记的样式块；
    // - 没有旧块时追加新块，旧块损坏时也按追加处理，避免误删其它 QSS；
    // - 返回值：true 表示 styleSheetText 被修改。
    bool replaceMarkedStyleBlock(
        QString& styleSheetText,
        const char* const beginMarker,
        const char* const endMarker,
        const QString& replacementBlock)
    {
        if (beginMarker == nullptr || endMarker == nullptr)
        {
            return false;
        }

        const QString beginMarkerText = QString::fromLatin1(beginMarker);
        const QString endMarkerText = QString::fromLatin1(endMarker);
        const int beginMarkerIndex = styleSheetText.indexOf(beginMarkerText);

        if (beginMarkerIndex >= 0)
        {
            const int endMarkerIndex = styleSheetText.indexOf(endMarkerText, beginMarkerIndex);
            if (endMarkerIndex >= 0)
            {
                const int removeLength = (endMarkerIndex - beginMarkerIndex) + endMarkerText.length();
                const QString oldBlock = styleSheetText.mid(beginMarkerIndex, removeLength);
                if (oldBlock == replacementBlock)
                {
                    return false;
                }
                styleSheetText.replace(beginMarkerIndex, removeLength, replacementBlock);
                return true;
            }
        }

        if (!styleSheetText.endsWith(QLatin1Char('\n')))
        {
            styleSheetText += QLatin1Char('\n');
        }
        styleSheetText += replacementBlock;
        return true;
    }

    // applyGlobalApplicationStyleBlocks 作用：
    // - 合并更新 QApplication 级别 Tooltip/QMenu/交互控件/组合框样式块；
    // - 只在最终样式表内容确实变化时调用一次 QApplication::setStyleSheet；
    // - 避免原先 Tooltip 与 QMenu 分别 setStyleSheet 导致启动阶段全局 repolish 两次。
    // 调用方式：applyAppearanceSettings 内部调用。
    // 入参 tooltipStyleBlock/contextMenuStyleBlock/controlContrastStyleBlock/comboBoxStyleBlock：已带标记的 QSS 片段。
    // 返回：实际触发 QApplication::setStyleSheet 时返回 true。
    bool applyGlobalApplicationStyleBlocks(
        const QString& baseControlStyleBlock,
        const QString& tooltipStyleBlock,
        const QString& contextMenuStyleBlock,
        const QString& controlContrastStyleBlock,
        const QString& comboBoxStyleBlock,
        qint64* elapsedMsOut = nullptr,
        int* widgetCountOut = nullptr,
        int* styleLengthOut = nullptr)
    {
        QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (appInstance == nullptr)
        {
            if (elapsedMsOut != nullptr)
            {
                *elapsedMsOut = 0;
            }
            if (widgetCountOut != nullptr)
            {
                *widgetCountOut = 0;
            }
            if (styleLengthOut != nullptr)
            {
                *styleLengthOut = 0;
            }
            return false;
        }

        QString appStyleSheetText = appInstance->styleSheet();
        const QString oldStyleSheetText = appStyleSheetText;

        // 基线块最先替换：首次追加时位于样式表最前，专用样式块和局部样式仍可覆盖。
        replaceMarkedStyleBlock(
            appStyleSheetText,
            ks::ui::kBaseControlStyleBeginMarker,
            ks::ui::kBaseControlStyleEndMarker,
            baseControlStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kTooltipStyleBeginMarker,
            kTooltipStyleEndMarker,
            tooltipStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kContextMenuStyleBeginMarker,
            kContextMenuStyleEndMarker,
            contextMenuStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kControlContrastStyleBeginMarker,
            kControlContrastStyleEndMarker,
            controlContrastStyleBlock);
        replaceMarkedStyleBlock(
            appStyleSheetText,
            kComboBoxStyleBeginMarker,
            kComboBoxStyleEndMarker,
            comboBoxStyleBlock);

        if (styleLengthOut != nullptr)
        {
            *styleLengthOut = appStyleSheetText.length();
        }
        if (widgetCountOut != nullptr)
        {
            *widgetCountOut = appInstance->allWidgets().size();
        }
        if (appStyleSheetText == oldStyleSheetText)
        {
            if (elapsedMsOut != nullptr)
            {
                *elapsedMsOut = 0;
            }
            return false;
        }

        QElapsedTimer applyTimer;
        applyTimer.start();
        appInstance->setStyleSheet(appStyleSheetText);
        if (elapsedMsOut != nullptr)
        {
            *elapsedMsOut = applyTimer.elapsed();
        }
        return true;
    }

    // configureSingleInstanceMessageReception 作用：
    // - 输入：mainWindowHandle 为 Qt 主窗口对应的原生 HWND；
    // - 处理：给窗口设置稳定识别属性，并允许低完整性/普通权限实例投递 WM_COPYDATA；
    // - 返回：无返回值，失败仅影响单实例 Shell 解锁转发兼容性，不阻断主程序启动。
    void configureSingleInstanceMessageReception(HWND mainWindowHandle)
    {
        if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
        {
            return;
        }

        (void)::SetPropW(
            mainWindowHandle,
            kKswordMainWindowPropertyName,
            reinterpret_cast<HANDLE>(static_cast<UINT_PTR>(1)));

        // ChangeWindowMessageFilterEx 作用：
        // - 当主程序以管理员运行，而资源管理器右键菜单以普通权限拉起第二实例时；
        // - Windows UIPI 默认会拦截跨完整性级别消息，导致 WM_COPYDATA 送不到已有主窗口；
        // - 这里只放行本功能需要的 WM_COPYDATA，不扩大为任意自定义消息。
        CHANGEFILTERSTRUCT filterStatus{};
        filterStatus.cbSize = sizeof(filterStatus);
        (void)::ChangeWindowMessageFilterEx(
            mainWindowHandle,
            WM_COPYDATA,
            MSGFLT_ALLOW,
            &filterStatus);
    }

    // clearSingleInstanceMessageReception 作用：
    // - 输入：mainWindowHandle 为 Qt 主窗口对应的原生 HWND；
    // - 处理：窗口销毁前移除用于单实例识别的属性；
    // - 返回：无返回值。
    void clearSingleInstanceMessageReception(HWND mainWindowHandle)
    {
        if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
        {
            return;
        }

        (void)::RemovePropW(mainWindowHandle, kKswordMainWindowPropertyName);
    }
}

MainWindow::MainWindow(
    QWidget* parent,
    StartupProgressCallback startupProgressCallback,
    const QFont& startupSystemFont)
    : QMainWindow(parent)
    , m_startupSystemFont(startupSystemFont)
    , m_startupProgressCallback(startupProgressCallback)
{
    // 安装全局 QMenu 主题过滤器：
    // - 统一兜底所有右键菜单背景；
    // - 避免后续新增菜单遗漏 setStyleSheet 导致浅色模式黑底。
    ensureGlobalContextMenuThemeFilterInstalled();
    ensureGlobalComboPopupThemeFilterInstalled();
    ensureGlobalSliderWheelFilterInstalled();
    ensureGlobalTableSelectionOutlineFilterInstalled();

    // 记录主窗口启动日志，便于验证日志系统与 UI 联动是否生效。
    // 注意：使用 kLogEvent，避免与 QObject::event 命名冲突。
    kLogEvent startupEvent;
    info << startupEvent << "MainWindow 构造开始，准备初始化 Dock 系统。" << eol;

    // 启动阶段细分：
    // - 主窗口外壳；
    // - 菜单；
    // - 权限按钮；
    // - Dock 内容；
    // - 外观系统。
    // 提前读取一次外观配置，便于在 initDockWidgets 阶段确定启动默认页签的预加载策略。
    m_currentAppearanceSettings = ks::settings::loadAppearanceSettings();

    // 三个主题种子必须早于任何页面构造，不能等到下面的 initAppearanceSettings：
    // 大量页面在构造期就把 KswordTheme::*ColorHex() 求值成固定色串进自己的 QSS，
    // 而控件自身的 setStyleSheet 压得过之后重建的全局 QSS。种子设晚了，
    // 启动即预加载的页面（如启动默认页所在的 Dock）会永久停在浅色/默认强调色上。
    // 这里只写种子，palette 与全局样式块仍由 initAppearanceSettings 统一下发。
    KswordTheme::SetDarkModeEnabled(isDarkModeEffective(m_currentAppearanceSettings));
    KswordTheme::SetPrimaryAccentColor(m_currentAppearanceSettings.customThemeColor);
    KswordTheme::SetMainBackgroundColor(m_currentAppearanceSettings.customMainBackgroundColor);

    reportStartupProgress(
        32,
        QStringLiteral("main.startup.progress.main_window_framework"),
        QStringLiteral("正在准备主界面..."));

    // 背景穿透（per-pixel alpha）必须在原生窗口创建前声明：
    // - 运行期切换需要销毁并重建 HWND，会丢失单实例属性、DWM 样式等句柄绑定状态；
    // - 因此该设置只在启动时读取一次，运行期修改由外观设置页提示重启生效。
    if (m_currentAppearanceSettings.backgroundTransparencyEnabled)
    {
        setAttribute(Qt::WA_TranslucentBackground, true);
    }

    // 启用无边框模式：
    // - 由自绘标题栏接管最小化/最大化/关闭/置顶操作；
    // - 保留系统菜单与最小化/最大化能力，便于原生行为兼容。
    setWindowFlag(Qt::FramelessWindowHint, true);
    setWindowFlag(Qt::WindowSystemMenuHint, true);
    setWindowFlag(Qt::WindowMinMaxButtonsHint, true);

    // Dock 全局配置：
    // - 仅允许声明了 DockWidgetClosable 的辅助 Dock 显示活动标签关闭按钮；
    // - 主功能 Dock 继续在各自 feature 中禁用关闭，区域菜单/浮动/关闭按钮仍保持隐藏。
    ads::CDockManager::setConfigFlag(ads::CDockManager::ActiveTabHasCloseButton, true);
    ads::CDockManager::setConfigFlag(ads::CDockManager::AllTabsHaveCloseButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasCloseButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasUndockButton, false);
    ads::CDockManager::setConfigFlag(ads::CDockManager::DockAreaHasTabsMenuButton, false);
    // 自定义 ADS 标签工厂必须早于 CDockManager/DockWidget 创建；
    // 否则默认 CDockWidgetTab 已经实例化，后续再换工厂无法修复当前标签的 hover 白底。
    ensureKswordAdsDockComponentsFactoryInstalled();

    // 创建主窗口根容器：
    // - 第 0 行放自绘标题栏；
    // - 第 1 行放 ADS Dock 管理器；
    // - 统一规避 setMenuWidget 在无边框场景下的可见性不稳定问题。
    m_mainRootContainer = new MainWindowBackgroundWidget(this);
    m_mainRootContainer->setObjectName(QStringLiteral("ksMainRootContainer"));

    m_mainRootLayout = new QVBoxLayout(m_mainRootContainer);
    m_mainRootLayout->setContentsMargins(0, 0, 0, 0);
    m_mainRootLayout->setSpacing(0);

    m_pDockManager = new ads::CDockManager(m_mainRootContainer);
    m_mainRootLayout->addWidget(m_pDockManager, 1);
    setCentralWidget(m_mainRootContainer);
    initResizeBorderOverlays();

    // 浮动窗口创建后立即挂接事件过滤器：
    // - 让脱离主窗口的 Dock 容器也能同步背景图与纯色底；
    // - 后续 resize/show 时统一走 MainWindow 的外观同步逻辑。
    connect(
        m_pDockManager,
        &ads::CDockManager::floatingWidgetCreated,
        this,
        [this](ads::CFloatingDockContainer* floatingWidget)
        {
            if (floatingWidget == nullptr)
            {
                return;
            }
            floatingWidget->installEventFilter(this);
            applyFloatingDockContainerAppearance(floatingWidget);
        });

    // 显式要求“最后一个窗口关闭后退出应用”。
    // 说明：用户要求主窗口关闭时进程必须结束，这里先设置 Qt 全局退出策略。
    QApplication::setQuitOnLastWindowClosed(true);

    // 设置窗口标题和大小
    setWindowTitle("KswordARK-5.1-Release");
    resize(1024, 768);
    configureSingleInstanceMessageReception(reinterpret_cast<HWND>(winId()));

    // 初始化自绘标题栏：
    // - 替代系统标题栏；
    // - 承载置顶按钮、命令输入框和窗口控制按钮。
    reportStartupProgress(
        38,
        QStringLiteral("main.startup.progress.custom_title_bar"),
        QStringLiteral("正在准备主界面..."));
    initCustomTitleBar();

    // 初始化标题栏功能入口。
    reportStartupProgress(
        44,
        QStringLiteral("main.startup.progress.menu"),
        QStringLiteral("正在准备主界面..."));
    initMenus();

    // 初始化权限状态按钮：
    // - UIAccess / Admin / Debug / System / R0；
    // - 在 Dock 布局恢复后挂载到主功能 Tab 栏右侧。
    reportStartupProgress(
        46,
        QStringLiteral("main.startup.progress.privilege_status"),
        QStringLiteral("正在准备主界面..."));
    initPrivilegeStatusButtons();
    startR0RuntimeConsumersAfterServiceStart();

    // 初始化Dock Widgets
    reportStartupProgress(
        48,
        QStringLiteral("main.startup.progress.page_components"),
        QStringLiteral("正在加载功能模块..."));
    initDockWidgets();

    // 设置Dock布局
    reportStartupProgress(
        74,
        QStringLiteral("main.startup.progress.dock_layout"),
        QStringLiteral("正在恢复界面布局..."));
    setupDockLayout();

    // 初始化外观设置：
    // - 读取 JSON；
    // - 绑定系统深浅色变化；
    // - 应用窗口背景色/背景图/文本颜色。
    reportStartupProgress(
        84,
        QStringLiteral("main.startup.progress.theme_appearance"),
        QStringLiteral("正在应用界面设置..."));
    initAppearanceSettings();

    // 记录初始化完成日志，方便用户在“日志输出”面板直接看到结果。
    // 注意：使用 kLogEvent，避免与 QObject::event 命名冲突。
    kLogEvent readyEvent;
    info << readyEvent << "MainWindow 初始化完成，日志面板已加载。" << eol;
    reportStartupProgress(
        93,
        QStringLiteral("main.startup.progress.main_window_ready"),
        QStringLiteral("即将完成..."));
}

MainWindow::~MainWindow()
{
    // 先使已进入 Qt 队列的通知失效，再等待工作线程已经复制的 handler 归还租约。
    // 返回后不会再有线程使用 this 投递新事件，随后才能安全拆除窗口成员。
    m_r0NotificationLifetime->store(false, std::memory_order_release);
    ksword::ark::DriverClient::clearR0NotificationHandlersAndWait();
    clearSingleInstanceMessageReception(reinterpret_cast<HWND>(winId()));
    CallbackPromptManager::shutdownGlobalManager();
    stopR0DriverLogPoller();
    // ADS会自动管理内存，无需手动删除
}

void MainWindow::reportStartupProgress(
    const int progressPercent,
    const QString& textKey,
    const QString& fallbackText) const
{
    // 安全回调策略：
    // - 未传入回调则静默跳过；
    // - 有回调时先按当前有效语言解析位置键，再把结果转发给主函数。
    if (!m_startupProgressCallback)
    {
        return;
    }

    m_startupProgressCallback(
        progressPercent,
        ks::i18n::contextText(textKey, fallbackText));
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    // 关闭事件日志：用于排查“窗口关闭但进程仍驻留”的问题。
    kLogEvent closeEventLog;
    info << closeEventLog << "[MainWindow] 收到关闭事件，准备退出进程。" << eol;

    // 退出时优先保存 ADS 布局，确保用户拖拽/浮动/激活 Tab 状态下次启动可恢复。
    saveDockLayoutToConfig();
    persistLogOutputWindowGeometry();
    if (m_notificationCardManager != nullptr)
    {
        m_notificationCardManager->clearCards();
    }

    // 停止权限状态定时器，避免退出阶段继续触发 UI 更新。
    if (m_privilegeStatusTimer != nullptr)
    {
        m_privilegeStatusTimer->stop();
    }
    prepareR0DriverServiceStop();
    CallbackPromptManager::shutdownGlobalManager();

    // 关闭窗口时自动停止 R0 驱动：
    // - 先静默查询服务状态；
    // - 若在运行则把整段 SCM 停驱交给线程池，UI 线程立刻把窗口藏起来，
    //   不再让“SCM 卡在 STOP_PENDING”把关闭动作硬拖到 30 秒的假死。
    bool r0RunningBeforeExit = false;
    if (queryR0DriverServiceRunning(r0RunningBeforeExit, false) && r0RunningBeforeExit)
    {
        if (event != nullptr)
        {
            // 这里必须 ignore：一旦 accept，Qt 会按 quitOnLastWindowClosed 在停驱回调
            // 执行前就结束事件循环，回调与日志都会丢失。
            event->ignore();
        }
        hide();

        // 异步关闭流程只推进一次：窗口隐藏后若再收到关闭请求，直接返回，
        // 避免重复派发停驱任务和重复排兜底定时器。
        static bool asyncShutdownStarted = false;
        if (asyncShutdownStarted)
        {
            return;
        }
        asyncShutdownStarted = true;

        dispatchR0ServiceStopToWorker(
            [](const R0ServiceOperationOutcome& operationOutcome)
            {
                kLogEvent autoStopEvent;
                if (operationOutcome.succeeded)
                {
                    info << autoStopEvent << "[MainWindow][R0] 关闭窗口时已自动停止并删除驱动服务。" << eol;
                }
                else
                {
                    warn << autoStopEvent << "[MainWindow][R0] 关闭窗口时自动停驱失败（已静默处理）。" << eol;
                }
                QApplication::quit();
                QCoreApplication::exit(0);
            });

        // 兜底定时器：后台停驱异常挂住时也必须退出，避免窗口已隐藏却留下常驻进程。
        // 超时上限取“停驱等待上限 + 2 秒余量”，正常路径永远比它先触发退出。
        QTimer::singleShot(
            static_cast<int>(kR0ServiceStopWaitTimeoutMs) + 2000,
            QCoreApplication::instance(),
            []()
            {
                QApplication::quit();
                QCoreApplication::exit(0);
            });
        return;
    }

    // 接受关闭事件并主动触发应用退出。
    // 这里同时调用 quit 与 exit(0)，确保事件循环尽快结束。
    if (event != nullptr)
    {
        event->accept();
    }
    QApplication::quit();
    QCoreApplication::exit(0);

    kLogEvent closeFinishLog;
    info << closeFinishLog << "[MainWindow] 已提交退出请求 (exit code=0)。" << eol;
}

void MainWindow::initResizeBorderOverlays()
{
    if (m_resizeBorderTop != nullptr)
    {
        return;
    }

    // createBorderOverlay：
    // - 输入 parentWidget：四条边框的父窗口，这里固定为 MainWindow 本体；
    // - 处理：创建独立 overlay 控件，不进入主布局，不改变根容器背景；
    // - 返回：初始化好的 3px 蓝色边框控件。
    auto createBorderOverlay = [this](const QString& objectNameText) -> QWidget*
        {
            QWidget* borderWidget = new QWidget(this);
            borderWidget->setObjectName(objectNameText);
            borderWidget->setAttribute(Qt::WA_StyledBackground, true);
            borderWidget->setMouseTracking(true);
            borderWidget->installEventFilter(this);
            borderWidget->raise();
            return borderWidget;
        };

    m_resizeBorderTop = createBorderOverlay(QStringLiteral("ksResizeBorderTop"));
    m_resizeBorderBottom = createBorderOverlay(QStringLiteral("ksResizeBorderBottom"));
    m_resizeBorderLeft = createBorderOverlay(QStringLiteral("ksResizeBorderLeft"));
    m_resizeBorderRight = createBorderOverlay(QStringLiteral("ksResizeBorderRight"));
    m_resizeCornerBottomLeft = new ResizeCornerTriangleWidget(
        ResizeCornerTriangleWidget::Corner::BottomLeft,
        this);
    m_resizeCornerBottomLeft->setObjectName(QStringLiteral("ksResizeCornerBottomLeft"));
    m_resizeCornerBottomLeft->installEventFilter(this);
    m_resizeCornerBottomLeft->setCursor(Qt::SizeBDiagCursor);
    m_resizeCornerBottomLeft->raise();
    m_resizeCornerBottomRight = new ResizeCornerTriangleWidget(
        ResizeCornerTriangleWidget::Corner::BottomRight,
        this);
    m_resizeCornerBottomRight->setObjectName(QStringLiteral("ksResizeCornerBottomRight"));
    m_resizeCornerBottomRight->installEventFilter(this);
    m_resizeCornerBottomRight->setCursor(Qt::SizeFDiagCursor);
    m_resizeCornerBottomRight->raise();

    applyResizeBorderOverlayStyle();
    updateResizeBorderOverlays();
}

void MainWindow::updateResizeBorderOverlays()
{
    const std::array<QWidget*, 6> overlayWidgets = {
        m_resizeBorderTop,
        m_resizeBorderBottom,
        m_resizeBorderLeft,
        m_resizeBorderRight,
        m_resizeCornerBottomLeft,
        m_resizeCornerBottomRight
    };

    // updateResizeBorderOverlays 可能被早期 resize/show 状态同步触发；
    // 在 initResizeBorderOverlays 完成前直接返回，避免空指针访问。
    for (QWidget* overlayWidget : overlayWidgets)
    {
        if (overlayWidget == nullptr)
        {
            return;
        }
    }

    // 最大化布局补偿：
    // - Windows 为带 WS_THICKFRAME 的最大化窗口把不可见 resize frame 扩到工作区外；
    // - HWND 与 Qt backing store 保持系统原样，只把标题栏和 Dock 内容向内收口；
    // - 边距使用 Qt 逻辑像素，避免高 DPI 下把原生物理像素重复放大。
    QMargins maximizedLayoutMargins;
#ifdef Q_OS_WIN
    if (m_mainRootLayout != nullptr
        && isWindowActuallyMaximized()
        && testAttribute(Qt::WA_WState_Created))
    {
        const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
        if (mainWindowHandle != nullptr && ::IsWindow(mainWindowHandle) != FALSE)
        {
            UINT windowDpi = ::GetDpiForWindow(mainWindowHandle);
            if (windowDpi == 0)
            {
                windowDpi = USER_DEFAULT_SCREEN_DPI;
            }
            const int nativePaddedBorder =
                ::GetSystemMetricsForDpi(SM_CXPADDEDBORDER, windowDpi);
            const int nativeFrameX =
                ::GetSystemMetricsForDpi(SM_CXSIZEFRAME, windowDpi) + nativePaddedBorder;
            const int nativeFrameY =
                ::GetSystemMetricsForDpi(SM_CYSIZEFRAME, windowDpi) + nativePaddedBorder;
            const qreal deviceScale = std::max<qreal>(1.0, devicePixelRatioF());
            const int layoutInsetX = std::max(
                0,
                static_cast<int>(std::lround(static_cast<qreal>(nativeFrameX) / deviceScale)));
            const int layoutInsetY = std::max(
                0,
                static_cast<int>(std::lround(static_cast<qreal>(nativeFrameY) / deviceScale)));
            maximizedLayoutMargins = QMargins(
                layoutInsetX,
                layoutInsetY,
                layoutInsetX,
                layoutInsetY);
        }
    }
#endif
    if (m_mainRootLayout != nullptr
        && m_mainRootLayout->contentsMargins() != maximizedLayoutMargins)
    {
        m_mainRootLayout->setContentsMargins(maximizedLayoutMargins);
    }

    const bool shouldShowBorders =
        !isWindowActuallyMaximized()
        && width() > (kResizeBorderOverlayWidth * 2)
        && height() > (kResizeBorderOverlayWidth * 2);

    for (QWidget* overlayWidget : overlayWidgets)
    {
        overlayWidget->setVisible(shouldShowBorders);
        if (shouldShowBorders)
        {
            overlayWidget->raise();
        }
    }

    if (!shouldShowBorders)
    {
        return;
    }

    const int border = kResizeBorderOverlayWidth;
    m_resizeBorderTop->setGeometry(0, 0, width(), border);
    m_resizeBorderBottom->setGeometry(0, height() - border, width(), border);
    m_resizeBorderLeft->setGeometry(0, border, border, std::max(0, height() - border * 2));
    m_resizeBorderRight->setGeometry(width() - border, border, border, std::max(0, height() - border * 2));
    m_resizeCornerBottomLeft->setGeometry(
        0,
        height() - kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg);
    m_resizeCornerBottomRight->setGeometry(
        width() - kResizeCornerTriangleLeg,
        height() - kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg,
        kResizeCornerTriangleLeg);
}

void MainWindow::applyResizeBorderOverlayStyle()
{
    const QString borderStyleText = QStringLiteral(
        "background:%1;"
        "border:none;").arg(KswordTheme::PrimaryBlueBorderHex);

    const std::array<QWidget*, 4> borderWidgets = {
        m_resizeBorderTop,
        m_resizeBorderBottom,
        m_resizeBorderLeft,
        m_resizeBorderRight
    };
    for (QWidget* borderWidget : borderWidgets)
    {
        if (borderWidget != nullptr)
        {
            borderWidget->setStyleSheet(borderStyleText);
        }
    }
    if (m_resizeCornerBottomLeft != nullptr)
    {
        m_resizeCornerBottomLeft->update();
    }
    if (m_resizeCornerBottomRight != nullptr)
    {
        m_resizeCornerBottomRight->update();
    }
}

bool MainWindow::handleResizeBorderOverlayEvent(QObject* watchedObject, QEvent* event)
{
    if (event == nullptr || watchedObject == nullptr)
    {
        return false;
    }

    QWidget* const borderWidget = qobject_cast<QWidget*>(watchedObject);
    if (borderWidget == nullptr)
    {
        return false;
    }

    auto resolveOverlayHitTest = [this, watchedObject, borderWidget](const QPoint& localPoint) -> WPARAM
        {
            if (watchedObject == m_resizeBorderTop)
            {
                if (localPoint.x() < kResizeBorderOverlayWidth)
                {
                    return HTTOPLEFT;
                }
                if (localPoint.x() >= borderWidget->width() - kResizeBorderOverlayWidth)
                {
                    return HTTOPRIGHT;
                }
                return HTTOP;
            }
            if (watchedObject == m_resizeBorderBottom)
            {
                if (localPoint.x() < kResizeBorderOverlayWidth)
                {
                    return HTBOTTOMLEFT;
                }
                if (localPoint.x() >= borderWidget->width() - kResizeBorderOverlayWidth)
                {
                    return HTBOTTOMRIGHT;
                }
                return HTBOTTOM;
            }
            if (watchedObject == m_resizeBorderLeft)
            {
                return HTLEFT;
            }
            if (watchedObject == m_resizeBorderRight)
            {
                return HTRIGHT;
            }
            if (watchedObject == m_resizeCornerBottomLeft)
            {
                return HTBOTTOMLEFT;
            }
            if (watchedObject == m_resizeCornerBottomRight)
            {
                return HTBOTTOMRIGHT;
            }
            return HTNOWHERE;
        };

    WPARAM defaultHitTestCode = HTNOWHERE;
    if (watchedObject == m_resizeBorderTop)
    {
        defaultHitTestCode = HTTOP;
    }
    else if (watchedObject == m_resizeBorderBottom)
    {
        defaultHitTestCode = HTBOTTOM;
    }
    else if (watchedObject == m_resizeBorderLeft)
    {
        defaultHitTestCode = HTLEFT;
    }
    else if (watchedObject == m_resizeBorderRight)
    {
        defaultHitTestCode = HTRIGHT;
    }
    else if (watchedObject == m_resizeCornerBottomLeft)
    {
        defaultHitTestCode = HTBOTTOMLEFT;
    }
    else if (watchedObject == m_resizeCornerBottomRight)
    {
        defaultHitTestCode = HTBOTTOMRIGHT;
    }
    else
    {
        return false;
    }

    if (event->type() == QEvent::MouseMove)
    {
        QMouseEvent* const mouseEvent = static_cast<QMouseEvent*>(event);
        const WPARAM hitTestCode = mouseEvent != nullptr
            ? resolveOverlayHitTest(mouseEvent->position().toPoint())
            : defaultHitTestCode;
        borderWidget->setCursor(cursorForResizeHitTestCode(hitTestCode));
        return false;
    }

    if (event->type() == QEvent::Leave)
    {
        borderWidget->unsetCursor();
        return false;
    }

    if (event->type() != QEvent::MouseButtonPress)
    {
        return false;
    }

    QMouseEvent* const mouseEvent = static_cast<QMouseEvent*>(event);
    if (mouseEvent == nullptr || mouseEvent->button() != Qt::LeftButton)
    {
        return false;
    }

    const WPARAM hitTestCode = resolveOverlayHitTest(mouseEvent->position().toPoint());
    if (!isNativeResizeHitTestCode(hitTestCode))
    {
        return false;
    }

    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr
        || ::IsWindow(mainWindowHandle) == FALSE
        || ::IsZoomed(mainWindowHandle) != FALSE)
    {
        return false;
    }

    // 四条 overlay 边框缩放入口：
    // - 输入：鼠标左键按在独立 3px 蓝色边框控件；
    // - 处理：桥接为原生 WM_NCLBUTTONDOWN + HT*；
    // - 返回：true 表示系统接管拖动缩放，Qt 不再继续分发该事件。
    const QPoint globalPoint = mouseEvent->globalPosition().toPoint();
    ::ReleaseCapture();
    ::SendMessageW(
        mainWindowHandle,
        WM_NCLBUTTONDOWN,
        hitTestCode,
        makeNativeMouseLParam(globalPoint));
    mouseEvent->accept();
    return true;
}

bool MainWindow::eventFilter(QObject* watchedObject, QEvent* event)
{
    if (handleResizeBorderOverlayEvent(watchedObject, event))
    {
        return true;
    }

    ads::CFloatingDockContainer* floatingWidget =
        qobject_cast<ads::CFloatingDockContainer*>(watchedObject);
    if (floatingWidget != nullptr && event != nullptr)
    {
        if (event->type() == QEvent::Show || event->type() == QEvent::Resize)
        {
            applyFloatingDockContainerAppearance(floatingWidget);
        }
    }

    if (watchedObject == m_logOutputWindow && event != nullptr)
    {
        if ((event->type() == QEvent::Move || event->type() == QEvent::Resize || event->type() == QEvent::Hide)
            && m_logWindowGeometrySaveTimer != nullptr)
        {
            m_logWindowGeometrySaveTimer->start();
        }
    }

    return QMainWindow::eventFilter(watchedObject, event);
}

void MainWindow::resizeEvent(QResizeEvent* event)
{
    QMainWindow::resizeEvent(event);
    updateResizeBorderOverlays();
    scheduleWindowBackdropRefresh();
    if (m_mainRootContainer != nullptr)
    {
        // 背景宿主在 paintEvent 中按当前真实 rect 计算缩放与居中位置。
        m_mainRootContainer->update();
    }
    if (m_notificationCardManager != nullptr)
    {
        m_notificationCardManager->onHostGeometryChanged();
    }
}

void MainWindow::moveEvent(QMoveEvent* event)
{
    QMainWindow::moveEvent(event);
    // 同屏移动不再重下发组合特性：
    // - DWM 的亚克力在合成器里模糊窗口“后方”的内容，与应用自己画的像素无关，
    //   窗口移动时它会自动按新位置重采样，应用侧不需要踢它；
    // - 而每次刷新都会跟一次根容器重绘，透明模式下所有 Dock 内容都是透明的，
    //   父控件重绘会连带重画整棵 Dock 树，实测单次约 41ms，
    //   在 40ms 节流下等于持续打满 UI 线程，直接造成拖动掉帧。
    // 跨显示器仍刷新一次：换屏会按新 DPI 重建窗口表面，组合特性可能随之失效。
    QScreen* const currentScreen = screen();
    if (currentScreen != m_lastKnownScreen)
    {
        m_lastKnownScreen = currentScreen;
        scheduleWindowBackdropRefresh();
    }
    if (m_notificationCardManager != nullptr)
    {
        m_notificationCardManager->onHostGeometryChanged();
    }
}

void MainWindow::showEvent(QShowEvent* event)
{
    QMainWindow::showEvent(event);

    // 主窗口真正可交互后再接管 R0 缺失通知。启动期存在日志轮询等 best-effort
    // 探测，它们不应在用户尚未操作任何内核功能时弹出“启用 R0”对话框。
    if (!m_r0UnavailablePromptArmed)
    {
        m_r0UnavailablePromptArmed = true;
        // weakLifetime 在窗口成员销毁后仍可安全检查，不依赖 QObject 裸指针存活。
        const std::weak_ptr<std::atomic_bool> weakLifetime = m_r0NotificationLifetime;
        ksword::ark::DriverClient::setR0UnavailableHandler([this, weakLifetime](const unsigned long win32Error)
            {
                const std::shared_ptr<std::atomic_bool> lifetime = weakLifetime.lock();
                if (!lifetime || !lifetime->load(std::memory_order_acquire))
                {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, weakLifetime, win32Error]()
                    {
                        const std::shared_ptr<std::atomic_bool> queuedLifetime = weakLifetime.lock();
                        if (!queuedLifetime || !queuedLifetime->load(std::memory_order_acquire))
                        {
                            return;
                        }
                        handleR0DriverUnavailable(win32Error);
                    }, Qt::QueuedConnection);
            });
        ksword::ark::DriverClient::setR0PermissionRequiredHandler([this, weakLifetime](const unsigned long win32Error)
            {
                const std::shared_ptr<std::atomic_bool> lifetime = weakLifetime.lock();
                if (!lifetime || !lifetime->load(std::memory_order_acquire))
                {
                    return;
                }
                QMetaObject::invokeMethod(this, [this, weakLifetime, win32Error]()
                    {
                        const std::shared_ptr<std::atomic_bool> queuedLifetime = weakLifetime.lock();
                        if (!queuedLifetime || !queuedLifetime->load(std::memory_order_acquire))
                        {
                            return;
                        }
                        handleR0PermissionRequired(win32Error);
                    }, Qt::QueuedConnection);
            });

        const QString enableAfterElevationArgument =
            QString::fromWCharArray(kKswordEnableR0AfterElevationArgument);
        if (QCoreApplication::arguments().contains(enableAfterElevationArgument, Qt::CaseInsensitive))
        {
            QTimer::singleShot(0, this, [this]()
                {
                    enableR0ForUserRequest();
                });
        }
    }

    ensureNativeFramelessWindowStyle();
    applyNativeWindowFrameVisualStyle();
    // 初始化阶段的外观应用早于原生窗口创建，组合特性调用会被跳过；
    // 这里在窗口句柄可用后补一次，确保启动即勾选的毛玻璃立刻生效。
    refreshWindowBackdropMaterial();
    syncCustomTitleBarMaximizedState();
    updateResizeBorderOverlays();
    if (m_notificationCardManager != nullptr)
    {
        m_notificationCardManager->onHostGeometryChanged();
    }

    {
        kLogEvent showEventLog;
        const QRect currentFrameRect = frameGeometry();
        info << showEventLog
            << "[MainWindow] showEvent 触发。 spontaneous="
            << ((event != nullptr && event->spontaneous()) ? "true" : "false")
            << ", visible="
            << (isVisible() ? "true" : "false")
            << ", minimized="
            << (isMinimized() ? "true" : "false")
            << ", frame="
            << currentFrameRect.x()
            << ","
            << currentFrameRect.y()
            << " "
            << currentFrameRect.width()
            << "x"
            << currentFrameRect.height()
            << eol;
    }

    // 首次显示可见性修正：
    // - 低分辨率或高缩放下，Qt/Win32 组合后的初始几何有机会落到屏幕外；
    // - 这里在 show 后异步校正一次，确保主窗口至少能落在当前可见区域内。
    if (!m_startupWindowVisibilityAdjusted)
    {
        m_startupWindowVisibilityAdjusted = true;
        QTimer::singleShot(0, this, [this]()
            {
                ensureStartupWindowVisibleOnScreen();
            });
    }

    if (m_deferredDockInitializationStarted)
    {
        QTimer::singleShot(0, this, [this]()
            {
                ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-repeat"));
                repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-repeat"));
            });
        return;
    }

    m_deferredDockInitializationStarted = true;
    QTimer::singleShot(0, this, [this]()
        {
            ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-deferred-0"));
            repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-deferred-0"));
        });
    QTimer::singleShot(250, this, [this]()
        {
            ensureVisibleLazyDocksInitialized(QStringLiteral("showEvent-deferred-250"));
            repairKernelDockAfterLayoutRestore(QStringLiteral("showEvent-deferred-250"));
        });
    // 崩溃转储检查排在最后：它会弹模态框，必须等首屏和懒加载都稳定下来再问，
    // 否则用户一打开程序就被一个盖住空白界面的对话框拦住。
    QTimer::singleShot(1500, this, [this]()
        {
            checkRecentCrashDumps();
        });

    // 懒加载策略修正：
    // - 旧逻辑会在主窗口 show 后继续把所有未初始化 Dock 逐个补载；
    // - 这会让“懒加载”退化成“延后但仍全量加载”，启动后首屏持续卡顿；
    // - 现在改为仅在用户真正切到对应 Dock，或代码显式跳转该 Dock 时，再初始化内容。
    // 说明：visibilityChanged / focusXXXDock / raiseStartupDockByKey 已经覆盖按需初始化入口。
    Q_UNUSED(kDeferredDockLoadIntervalMs);
}

void MainWindow::changeEvent(QEvent* event)
{
    QMainWindow::changeEvent(event);

    if (event != nullptr
        && event->type() == QEvent::WindowStateChange)
    {
        syncCustomTitleBarMaximizedState();
        updateResizeBorderOverlays();
        scheduleWindowBackdropRefresh();
        if (m_notificationCardManager != nullptr)
        {
            m_notificationCardManager->onHostGeometryChanged();
        }
    }

    // 激活状态变化同样要重采样：窗口重新获得焦点时，
    // 系统可能已经把毛玻璃降级为静态回退色，需要再下发一次恢复。
    if (event != nullptr && event->type() == QEvent::ActivationChange)
    {
        scheduleWindowBackdropRefresh();
    }
}

void MainWindow::ensureStartupWindowVisibleOnScreen()
{
    // 最大化窗口交给系统管理：
    // - 避免把最大化态错误改回普通窗口态；
    // - 这里只处理“窗口已 show 但普通态不可见/越界”的情况。
    if (isWindowActuallyMaximized())
    {
        return;
    }

    // targetFrameRect 用途：以顶层 frame 几何为准，保证标题栏和边框也在可见区域内。
    QRect targetFrameRect = frameGeometry();
    if (!targetFrameRect.isValid() || targetFrameRect.width() <= 0 || targetFrameRect.height() <= 0)
    {
        targetFrameRect = geometry();
    }
    if (!targetFrameRect.isValid() || targetFrameRect.width() <= 0 || targetFrameRect.height() <= 0)
    {
        return;
    }

    // targetScreen 用途：优先使用窗口当前所在屏幕；若中心点不在任何屏幕内，则回退主屏。
    QScreen* targetScreen = nullptr;
    if (windowHandle() != nullptr)
    {
        targetScreen = windowHandle()->screen();
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::screenAt(targetFrameRect.center());
    }
    if (targetScreen == nullptr)
    {
        targetScreen = QGuiApplication::primaryScreen();
    }
    if (targetScreen == nullptr)
    {
        return;
    }

    // availableRect 用途：当前屏幕的可用工作区，不覆盖任务栏。
    const QRect availableRect = targetScreen->availableGeometry();
    if (!availableRect.isValid() || availableRect.width() <= 0 || availableRect.height() <= 0)
    {
        return;
    }

    // 先裁剪窗口尺寸：
    // - 防止低分辨率下默认 1024x768 超出工作区；
    // - 保留最小 320x240，避免把窗口缩到不可操作。
    const int adjustedWidth = std::clamp(targetFrameRect.width(), 320, availableRect.width());
    const int adjustedHeight = std::clamp(targetFrameRect.height(), 240, availableRect.height());

    // 再裁剪窗口位置：
    // - 只要有一部分落屏外，就把左上角拉回可见区域；
    // - 保证整个 frameRect 都能处于 availableRect 范围内。
    const int adjustedLeft = std::clamp(
        targetFrameRect.left(),
        availableRect.left(),
        availableRect.right() - adjustedWidth + 1);
    const int adjustedTop = std::clamp(
        targetFrameRect.top(),
        availableRect.top(),
        availableRect.bottom() - adjustedHeight + 1);

    const QRect adjustedFrameRect(adjustedLeft, adjustedTop, adjustedWidth, adjustedHeight);
    if (adjustedFrameRect == targetFrameRect)
    {
        kLogEvent noAdjustEvent;
        info << noAdjustEvent
            << "[MainWindow] 首次显示区域检查完成，无需修正。 frame="
            << targetFrameRect.x()
            << ","
            << targetFrameRect.y()
            << " "
            << targetFrameRect.width()
            << "x"
            << targetFrameRect.height()
            << eol;
        return;
    }

    // 使用 frameGeometry 差值反推出 client 几何：
    // - move/resize 直接作用于 QWidget 客户区；
    // - 这样可以把 frame 目标位置尽量精确映射回 Qt 几何。
    const QRect currentClientRect = geometry();
    const int frameOffsetX = targetFrameRect.left() - currentClientRect.left();
    const int frameOffsetY = targetFrameRect.top() - currentClientRect.top();
    const int clientWidthDelta = targetFrameRect.width() - currentClientRect.width();
    const int clientHeightDelta = targetFrameRect.height() - currentClientRect.height();

    const QRect adjustedClientRect(
        adjustedFrameRect.left() - frameOffsetX,
        adjustedFrameRect.top() - frameOffsetY,
        std::max(1, adjustedFrameRect.width() - clientWidthDelta),
        std::max(1, adjustedFrameRect.height() - clientHeightDelta));

    {
        kLogEvent adjustEvent;
        warn << adjustEvent
            << "[MainWindow] 首次显示区域已修正。 old_frame="
            << targetFrameRect.x()
            << ","
            << targetFrameRect.y()
            << " "
            << targetFrameRect.width()
            << "x"
            << targetFrameRect.height()
            << ", new_frame="
            << adjustedFrameRect.x()
            << ","
            << adjustedFrameRect.y()
            << " "
            << adjustedFrameRect.width()
            << "x"
            << adjustedFrameRect.height()
            << eol;
    }

    setGeometry(adjustedClientRect);
}

void MainWindow::syncCustomTitleBarMaximizedState()
{
    if (m_customTitleBar == nullptr)
    {
        return;
    }

    // maximizedState 用途：统一记录当前窗口是否处于最大化态，供标题栏图标刷新。
    const bool maximizedState = isWindowActuallyMaximized();
    m_customTitleBar->setMaximizedState(maximizedState);
}

void MainWindow::ensureNativeFramelessWindowStyle()
{
#ifdef Q_OS_WIN
    // mainWindowHandle 用途：获取主窗口原生句柄，用于补齐 Win32 样式位。
    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
    {
        return;
    }

    // currentStyleValue 用途：保存当前窗口样式，供增量合并必需样式位。
    const LONG_PTR currentStyleValue = ::GetWindowLongPtrW(mainWindowHandle, GWL_STYLE);
    // requiredStyleMask 用途：无边框窗口仍需具备的系统交互能力掩码。
    //
    // 即使客户区由自绘标题栏完全接管，也必须保留 WS_CAPTION：Windows
    // 会用它判断窗口是否具备常规的最小化/最大化语义，DWM 的还原、最大化、
    // 最小化过渡动画以及 Aero Snap 才会按普通窗口路径运行。标准非客户区
    // 仍由 WM_NCCALCSIZE 返回 0 移除，因此不会重新显示系统标题栏。
    const LONG_PTR requiredStyleMask =
        WS_CAPTION | WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX | WS_SYSMENU;
    // updatedStyleValue 用途：保留 Qt/Win32 其它样式，仅补齐系统窗口语义。
    const LONG_PTR updatedStyleValue = currentStyleValue | requiredStyleMask;

    if (updatedStyleValue != currentStyleValue)
    {
        ::SetWindowLongPtrW(mainWindowHandle, GWL_STYLE, updatedStyleValue);
        ::SetWindowPos(
            mainWindowHandle,
            nullptr,
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
    }
#endif
}

void MainWindow::applyNativeWindowFrameVisualStyle()
{
#ifdef Q_OS_WIN
    // 未创建原生窗口句柄时不主动触发 winId，避免在构造早期引入额外重入。
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return;
    }

    // mainWindowHandle 用途：向 DWM 写入主窗口无边框视觉属性。
    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
    {
        return;
    }

    // darkModeEnabled 用途：根据当前外观配置决定 DWM 是否启用沉浸式深色边框策略。
    const bool darkModeEnabled = isDarkModeEffective(m_currentAppearanceSettings);
    // immersiveDarkModeValue 用途：DwmSetWindowAttribute 所需 BOOL 入参。
    const BOOL immersiveDarkModeValue = darkModeEnabled ? TRUE : FALSE;
    // borderColorValue 用途：要求 DWM 不再绘制系统默认白色边框。
    const DWORD borderColorValue = kDwmColorNone;

    const HRESULT darkModeResult = ::DwmSetWindowAttribute(
        mainWindowHandle,
        kDwmUseImmersiveDarkModeAttribute,
        &immersiveDarkModeValue,
        sizeof(immersiveDarkModeValue));
    const HRESULT borderColorResult = ::DwmSetWindowAttribute(
        mainWindowHandle,
        kDwmBorderColorAttribute,
        &borderColorValue,
        sizeof(borderColorValue));

    // darkModeUnsupported / borderColorUnsupported 用途：
    // - 标记当前系统仅仅是不支持新属性，而不是发生异常；
    // - 避免旧系统在每次启动时输出无意义告警。
    const bool darkModeUnsupported = (darkModeResult == E_INVALIDARG);
    const bool borderColorUnsupported = (borderColorResult == E_INVALIDARG);
    if ((!SUCCEEDED(darkModeResult) && !darkModeUnsupported)
        || (!SUCCEEDED(borderColorResult) && !borderColorUnsupported))
    {
        kLogEvent frameVisualEvent;
        warn << frameVisualEvent
            << "[MainWindow] DWM 边框样式同步失败, dark_hr=0x"
            << std::hex
            << static_cast<unsigned long>(darkModeResult)
            << ", border_hr=0x"
            << static_cast<unsigned long>(borderColorResult)
            << std::dec
            << eol;
    }
#endif
}

bool MainWindow::applyMainWindowBackdropMaterial(const BackdropBlurKind blurKind)
{
    const bool enableSystemAccent = (blurKind == BackdropBlurKind::Acrylic);
#ifdef Q_OS_WIN
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return false;
    }
    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
    {
        return false;
    }

    // setWindowCompositionAttribute 用途：
    // - user32 的未导出组合特性入口，是唯一能给“分层透明窗口”加模糊的可用接口；
    // - DWM 的云母（DWMWA_SYSTEMBACKDROP_TYPE）要求窗口本身不透明，
    //   与 Qt 的 WA_TranslucentBackground 分层表面冲突，会回退成系统浅色底（表现为发白），
    //   因此这里改用组合特性提供的模糊，Windows 10 1803+ 与 Windows 11 均可用。
    using SetWindowCompositionAttributeFunction = BOOL(WINAPI*)(HWND, void*);
    static SetWindowCompositionAttributeFunction setWindowCompositionAttribute =
        []() -> SetWindowCompositionAttributeFunction {
            HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
            if (user32ModuleHandle == nullptr)
            {
                return nullptr;
            }
            return reinterpret_cast<SetWindowCompositionAttributeFunction>(
                ::GetProcAddress(user32ModuleHandle, "SetWindowCompositionAttribute"));
        }();
    if (setWindowCompositionAttribute == nullptr)
    {
        return false;
    }

    // requestedState 用途：把材质种类映射为可比较的缓存值。
    const int requestedState = static_cast<int>(blurKind);
    // 从未启用过亚克力时无需关闭：避免不用系统材质的用户每次启动都触碰未公开接口。
    if (!enableSystemAccent && m_backdropMaterialState < 0)
    {
        m_backdropMaterialState = requestedState;
        return false;
    }
    // m_backdropMaterialState 缓存已下发的种类：-1 未初始化，其余为 BackdropBlurKind。
    // 亚克力需要在主题色变化与窗口移动时重下发（重采样）；
    // 已关闭且仍要关闭时无需重复下发。
    if (!enableSystemAccent
        && m_backdropMaterialState != static_cast<int>(BackdropBlurKind::Acrylic))
    {
        m_backdropMaterialState = requestedState;
        return false;
    }
    m_backdropMaterialState = requestedState;

    // tintColor 用途：亚克力自带的着色层，由组合特性直接混合到模糊结果上，
    // 因此启用后根容器不再另画着色，避免出现双层叠加导致的浑浊。
    const QColor tintColor = KswordTheme::MainBackgroundColor();
    // acrylicTintAlpha 用途：着色层不透明度，由“磨砂着色不透明度”设置决定；
    // 越低越通透（更接近纯模糊），越高前景文字可读性越强。
    const int acrylicTintAlpha = ks::settings::tintAlphaFromOpacityPercent(
        m_currentAppearanceSettings.acrylicTintOpacityPercent);
    // gradientColorValue 采用 0xAABBGGRR 排布，注意与常见的 ARGB 顺序相反。
    const DWORD gradientColorValue =
        (static_cast<DWORD>(acrylicTintAlpha) << 24)
        | (static_cast<DWORD>(tintColor.blue()) << 16)
        | (static_cast<DWORD>(tintColor.green()) << 8)
        | static_cast<DWORD>(tintColor.red());

    AccentPolicyData accentPolicy{};
    accentPolicy.accentState =
        enableSystemAccent ? kAccentEnableAcrylicBlurBehind : kAccentDisabled;
    accentPolicy.accentFlags = 0;
    accentPolicy.gradientColor = enableSystemAccent ? gradientColorValue : 0;
    accentPolicy.animationId = 0;

    WindowCompositionAttributeData compositionData{};
    compositionData.attribute = kWindowCompositionAttributeAccentPolicy;
    compositionData.dataPointer = &accentPolicy;
    compositionData.dataSizeBytes = sizeof(accentPolicy);

    const BOOL applyOk = setWindowCompositionAttribute(mainWindowHandle, &compositionData);

    kLogEvent backdropEvent;
    info << backdropEvent
        << "[MainWindow] 窗口模糊材质切换, kind="
        << (blurKind == BackdropBlurKind::Acrylic ? "acrylic" : "none")
        << ", ok="
        << (applyOk != FALSE ? "true" : "false")
        << eol;
    return enableSystemAccent && applyOk != FALSE;
#else
    Q_UNUSED(blurKind);
    return false;
#endif
}

bool MainWindow::isWindowActuallyMaximized() const
{
#ifdef Q_OS_WIN
    // Windows 下以 HWND 的 Zoomed 状态作为唯一真实来源：
    // - 自绘标题栏/无边框窗口曾经混用 Qt::WindowMaximized 与 IsZoomed；
    // - 最大化标题栏拖拽还原后，Qt 状态有机会残留 WindowMaximized；
    // - 若继续 OR Qt 状态，会导致按钮图标、命中测试和最大化按钮目标态全部卡死。
    if (!testAttribute(Qt::WA_WState_Created))
    {
        return (windowState() & Qt::WindowMaximized) != 0 || isMaximized();
    }

    const HWND mainWindowHandle = reinterpret_cast<HWND>(const_cast<MainWindow*>(this)->winId());
    if (mainWindowHandle != nullptr && ::IsWindow(mainWindowHandle) != FALSE)
    {
        return ::IsZoomed(mainWindowHandle) != FALSE;
    }
#endif

    // 非 Windows 或 HWND 尚不可用时回退 Qt 状态。
    return (windowState() & Qt::WindowMaximized) != 0 || isMaximized();
}

void MainWindow::setWindowMaximizedBySystemCommand(const bool targetMaximizedState)
{
#ifdef Q_OS_WIN
    // mainWindowHandle 用途：执行原生最大化/还原时使用的窗口句柄。
    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle != nullptr && ::IsWindow(mainWindowHandle) != FALSE)
    {
        // currentMaximizedState 用途：记录当前真实最大化态，避免重复发送相同命令。
        const bool currentMaximizedState = (::IsZoomed(mainWindowHandle) != FALSE);
        if (targetMaximizedState != currentMaximizedState)
        {
            // 使用 ShowWindow 切换窗口状态：
            // - 避免在标题栏鼠标消息处理期间同步 SendMessage(WM_SYSCOMMAND) 造成重入；
            // - 修复“先跳到左上角再闪回”和双击后标题栏拖动链路失效的问题。
            ::ShowWindow(
                mainWindowHandle,
                targetMaximizedState ? SW_MAXIMIZE : SW_RESTORE);
        }
    }
    else
    {
        if (targetMaximizedState)
        {
            showMaximized();
        }
        else
        {
            showNormal();
        }
    }
#else
    if (targetMaximizedState)
    {
        showMaximized();
    }
    else
    {
        showNormal();
    }
#endif

    syncCustomTitleBarMaximizedState();
    // 二次同步只保留 0ms 一次：
    // - 覆盖“系统命令异步切换窗口态”的下一轮事件循环；
    // - 避免多次延迟同步导致体感卡顿或图标抖动。
    QTimer::singleShot(0, this, [this]()
        {
            syncCustomTitleBarMaximizedState();
        });
}

bool MainWindow::nativeEvent(const QByteArray& eventType, void* message, qintptr* result)
{
    Q_UNUSED(eventType);

#ifdef Q_OS_WIN
    if (message == nullptr || result == nullptr)
    {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    MSG* nativeMessage = reinterpret_cast<MSG*>(message);
    if (nativeMessage == nullptr)
    {
        return QMainWindow::nativeEvent(eventType, message, result);
    }

    if (nativeMessage->message == WM_COPYDATA)
    {
        const COPYDATASTRUCT* const copyData =
            reinterpret_cast<const COPYDATASTRUCT*>(nativeMessage->lParam);
        if (copyData != nullptr
            && copyData->dwData == kUnlockerCopyDataMessageId
            && copyData->lpData != nullptr
            && copyData->cbData >= sizeof(wchar_t))
        {
            const std::size_t wcharCount =
                static_cast<std::size_t>(copyData->cbData / sizeof(wchar_t));
            const wchar_t* const pathBuffer = reinterpret_cast<const wchar_t*>(copyData->lpData);
            QString unlockPath = QString::fromWCharArray(pathBuffer, static_cast<int>(wcharCount));
            const int nullIndex = unlockPath.indexOf(QChar::Null);
            if (nullIndex >= 0)
            {
                unlockPath.truncate(nullIndex);
            }
            unlockPath = QDir::toNativeSeparators(unlockPath.trimmed());

            if (!unlockPath.isEmpty())
            {
                kLogEvent event;
                info << event
                    << "[MainWindow] 收到单实例文件解锁请求: path="
                    << unlockPath.toStdString()
                    << eol;
                QTimer::singleShot(0, this, [this, unlockPath]()
                    {
                        this->raise();
                        this->activateWindow();
                        openFileUnlockerDockByPath(unlockPath);
                    });
            }

            *result = TRUE;
            return true;
        }
    }

    if (nativeMessage->message == WM_GETMINMAXINFO)
    {
        // WM_GETMINMAXINFO 作用：
        // - 系统在最大化/拖拽到屏幕边缘前询问窗口最大尺寸和位置；
        // - 自绘无边框窗口若不主动写入 rcWork，相邻 AppBar 可能只缩小高度却仍从 (0,0) 开始。
        MINMAXINFO* const minMaxInfo = reinterpret_cast<MINMAXINFO*>(nativeMessage->lParam);
        if (applyAppBarAwareMaximizedBounds(nativeMessage->hwnd, minMaxInfo))
        {
            *result = 0;
            return true;
        }
    }

    if (nativeMessage->message == WM_NCCALCSIZE)
    {
        // WM_NCCALCSIZE 双分支统一返回 0：
        // - wParam=TRUE：窗口尺寸/状态变化时，让整块窗口都成为客户区；
        // - wParam=FALSE：窗口初始创建阶段同样移除默认非客户区，修复 Win11 左/上透明残留带。
        // 说明：这里不做额外矩形改写，保持现有可缩放与最大化行为不变。
        *result = 0;
        return true;
    }

    if (nativeMessage->message == WM_NCLBUTTONDOWN)
    {
        // 对 HTCAPTION 与边框缩放命中显式转发给 DefWindowProc：
        // - Qt 无边框窗口不会总是替我们走完原生非客户区语义；
        // - HTCAPTION 用于启动系统移动/最大化拖下还原；
        // - HTLEFT/HTRIGHT/... 用于启动系统边框缩放；
        // - 如果只转发 HTCAPTION，命中测试虽然返回了边框，拖边仍不会 resize。
        if (nativeMessage->wParam == HTCAPTION
            || isNativeResizeHitTestCode(nativeMessage->wParam))
        {
            *result = ::DefWindowProcW(
                nativeMessage->hwnd,
                nativeMessage->message,
                nativeMessage->wParam,
                nativeMessage->lParam);
            return true;
        }
    }

    if (nativeMessage->message == WM_NCLBUTTONDBLCLK)
    {
        // HTCAPTION 双击手动切换最大化/还原：
        // - 保留系统标题栏语义；
        // - 同时避免 Qt/无边框窗口把双击吞掉导致无反应。
        if (nativeMessage->wParam == HTCAPTION)
        {
            const bool targetMaximizedState =
                (nativeMessage->hwnd != nullptr && ::IsWindow(nativeMessage->hwnd) != FALSE)
                ? (::IsZoomed(nativeMessage->hwnd) == FALSE)
                : !isWindowActuallyMaximized();
            setWindowMaximizedBySystemCommand(targetMaximizedState);
            *result = 0;
            return true;
        }
    }

    if (nativeMessage->message == WM_NCACTIVATE)
    {
        // 焦点切换时要求系统跳过默认非客户区重绘，避免瞬间刷出白色边框。
        *result = ::DefWindowProcW(
            nativeMessage->hwnd,
            nativeMessage->message,
            nativeMessage->wParam,
            static_cast<LPARAM>(-1));
        return true;
    }

    if (nativeMessage->message == WM_SIZE)
    {
        // WM_SIZE 作用：
        // - 原生 HTCAPTION 拖拽、Win+方向键、Aero Snap、ShowWindow 都会经由此消息落地；
        // - 这里不改变窗口状态，只在下一轮事件循环同步标题栏按钮图标；
        // - 尤其覆盖“最大化窗口从标题栏拖下来”时 Qt WindowStateChange 不稳定触发的问题。
        if (nativeMessage->wParam == SIZE_MAXIMIZED || nativeMessage->wParam == SIZE_RESTORED)
        {
            QTimer::singleShot(0, this, [this]()
                {
                    syncCustomTitleBarMaximizedState();
                    updateResizeBorderOverlays();
                });
        }
    }

    if (nativeMessage->message == WM_NCHITTEST)
    {
        // maximizedInNativeMessage 用途：使用当前消息窗口句柄直接判定最大化状态，避免重入。
        const bool maximizedInNativeMessage =
            (nativeMessage->hwnd != nullptr && ::IsWindow(nativeMessage->hwnd) != FALSE)
            ? (::IsZoomed(nativeMessage->hwnd) != FALSE)
            : isWindowActuallyMaximized();

        const LPARAM pointData = nativeMessage->lParam;
        const POINT screenPoint = {
            static_cast<LONG>(static_cast<short>(LOWORD(pointData))),
            static_cast<LONG>(static_cast<short>(HIWORD(pointData)))
        };
        const QPoint screenQPoint(screenPoint.x, screenPoint.y);
        const QPoint localPoint = mapFromGlobal(screenQPoint);
        // windowRectValue 用途：读取顶层窗口的屏幕坐标矩形，供边框缩放命中使用。
        RECT windowRectValue = {};
        if (nativeMessage->hwnd == nullptr
            || ::GetWindowRect(nativeMessage->hwnd, &windowRectValue) == FALSE)
        {
            return QMainWindow::nativeEvent(eventType, message, result);
        }
        // frameLocalPoint 用途：把屏幕坐标转换为相对整个顶层窗口左上角的坐标。
        const QPoint frameLocalPoint(
            screenPoint.x - windowRectValue.left,
            screenPoint.y - windowRectValue.top);
        // frameWidthValue/frameHeightValue 用途：保存顶层窗口当前尺寸，供右边/下边缩放命中判断。
        const int frameWidthValue = windowRectValue.right - windowRectValue.left;
        const int frameHeightValue = windowRectValue.bottom - windowRectValue.top;
        const int borderWidth = std::max(
            8,
            static_cast<int>(
                ::GetSystemMetrics(SM_CXSIZEFRAME)
                + ::GetSystemMetrics(SM_CXPADDEDBORDER)));

        // 边缘缩放命中优先：
        // - 必须先于标题栏拖动命中，否则标题栏会吞掉上边/左右边缩放区域；
        // - 这是“窗口无法调整大小”的直接原因。
        if (!maximizedInNativeMessage)
        {
            const bool hitLeft = frameLocalPoint.x() >= 0 && frameLocalPoint.x() < borderWidth;
            const bool hitRight =
                frameLocalPoint.x() <= frameWidthValue
                && frameLocalPoint.x() > (frameWidthValue - borderWidth);
            const bool hitTop = frameLocalPoint.y() >= 0 && frameLocalPoint.y() < borderWidth;
            const bool hitBottom =
                frameLocalPoint.y() <= frameHeightValue
                && frameLocalPoint.y() > (frameHeightValue - borderWidth);

            if (hitTop && hitLeft)
            {
                *result = HTTOPLEFT;
                return true;
            }
            if (hitTop && hitRight)
            {
                *result = HTTOPRIGHT;
                return true;
            }
            if (hitBottom && hitLeft)
            {
                *result = HTBOTTOMLEFT;
                return true;
            }
            if (hitBottom && hitRight)
            {
                *result = HTBOTTOMRIGHT;
                return true;
            }
            if (hitLeft)
            {
                *result = HTLEFT;
                return true;
            }
            if (hitRight)
            {
                *result = HTRIGHT;
                return true;
            }
            if (hitTop)
            {
                *result = HTTOP;
                return true;
            }
            if (hitBottom)
            {
                *result = HTBOTTOM;
                return true;
            }
        }

        // 兼容处理：若仍存在顶端负坐标带（非客户区残留），直接按可拖动标题栏返回。
        if (localPoint.y() < 0 && localPoint.y() >= -borderWidth)
        {
            *result = HTCAPTION;
            return true;
        }

        // 自绘标题栏命中：
        // - 边框缩放已在上方优先处理，这里只处理真正标题栏可拖动区；
        // - 返回 HTCAPTION 后，Windows DefWindowProc 会接管移动、双击、Aero Snap；
        // - 最大化窗口从标题栏拖下来也会走系统原生“还原并继续移动”语义；
        // - 右侧窗口按钮、命令输入框、用户名徽标由 isPointInDraggableRegion 排除，继续保留 Qt 点击。
        if (m_customTitleBar != nullptr
            && m_customTitleBar->isVisible()
            && m_customTitleBar->isEnabled())
        {
            const QPoint titleBarLocalPoint = m_customTitleBar->mapFromGlobal(screenQPoint);
            if (m_customTitleBar->isPointInDraggableRegion(titleBarLocalPoint))
            {
                *result = HTCAPTION;
                return true;
            }
        }

    }
#endif

    return QMainWindow::nativeEvent(eventType, message, result);
}

void MainWindow::initCustomTitleBar()
{
    if (m_customTitleBar != nullptr)
    {
        return;
    }

    m_customTitleBar = new ks::ui::CustomTitleBar(this);
    m_customTitleBar->setPinnedState(m_windowPinned);
    m_customTitleBar->setCaptureProtectionState(m_captureProtectionEnabled);
    syncCustomTitleBarMaximizedState();
    m_customTitleBar->setDarkModeEnabled(KswordTheme::IsDarkModeEnabled());
    if (m_mainRootLayout != nullptr && m_mainRootContainer != nullptr)
    {
        m_customTitleBar->setParent(m_mainRootContainer);
        m_mainRootLayout->insertWidget(0, m_customTitleBar, 0);
    }
    else
    {
        // 兜底：若根容器尚未就绪，退回 QMainWindow 的 menuWidget 挂载方式。
        setMenuWidget(m_customTitleBar);
    }
    m_customTitleBar->show();

    connect(m_customTitleBar, &ks::ui::CustomTitleBar::requestTogglePinned, this, [this]() {
        togglePinnedWindowState();
    });
    connect(m_customTitleBar, &ks::ui::CustomTitleBar::requestToggleCaptureProtection, this, [this]() {
        toggleCaptureProtectionState();
    });
    connect(m_customTitleBar, &ks::ui::CustomTitleBar::requestMinimizeWindow, this, [this]() {
        showMinimized();
    });
    connect(m_customTitleBar, &ks::ui::CustomTitleBar::requestToggleMaximizeWindow, this, [this]() {
        // targetMaximizedState 用途：根据真实状态计算下一目标状态（最大化或还原）。
        const bool targetMaximizedState = !isWindowActuallyMaximized();
        setWindowMaximizedBySystemCommand(targetMaximizedState);
    });
    connect(m_customTitleBar, &ks::ui::CustomTitleBar::requestCloseWindow, this, [this]() {
        close();
    });
    connect(m_customTitleBar, &ks::ui::CustomTitleBar::commandSubmitted, this, [this](const QString& commandText) {
        executeCommandInNewConsole(commandText);
    });

    initGlobalUiSearchController();

    kLogEvent initTitleBarEvent;
    info << initTitleBarEvent << "[MainWindow] 自绘标题栏初始化完成。" << eol;

    // 首帧自检：
    // - setMenuWidget 后下一轮事件循环检查标题栏是否可见；
    // - 同步记录挂载状态与尺寸，便于排查“标题栏未显示”问题。
    QTimer::singleShot(0, this, [this]()
        {
            if (m_customTitleBar == nullptr)
            {
                return;
            }

            // mountedAsMenuWidget 作用：确认自绘标题栏是否挂到 QMainWindow 菜单位。
            const bool mountedAsMenuWidget = (menuWidget() == m_customTitleBar);
            // mountedInRootLayout 作用：确认自绘标题栏是否挂到根容器纵向布局第 0 行。
            const bool mountedInRootLayout =
                (m_mainRootLayout != nullptr && m_mainRootLayout->indexOf(m_customTitleBar) >= 0);
            if (!m_customTitleBar->isVisible())
            {
                m_customTitleBar->show();
            }

            kLogEvent titleBarCheckEvent;
            info << titleBarCheckEvent
                << "[MainWindow] 自绘标题栏挂载检查, mounted="
                << (mountedAsMenuWidget ? "true" : "false")
                << ", mounted_layout="
                << (mountedInRootLayout ? "true" : "false")
                << ", visible="
                << (m_customTitleBar->isVisible() ? "true" : "false")
                << ", size="
                << m_customTitleBar->width()
                << "x"
                << m_customTitleBar->height()
                << eol;
        });
}

void MainWindow::initGlobalUiSearchController()
{
    if (m_customTitleBar == nullptr || m_globalUiSearchController != nullptr)
    {
        return;
    }

    // 弹层宿主是主窗口本体：无边框窗口下用子控件弹层可避免焦点被独立窗口抢走。
    m_globalUiSearchController = new ks::ui::GlobalUiSearchController(
        this,
        m_customTitleBar->titleInputLineEdit(),
        m_customTitleBar->titleInputAnchorWidget(),
        this);
    m_commandExecutionPopup = new ks::ui::CommandExecutionPopup(
        this,
        m_customTitleBar->titleInputAnchorWidget(),
        m_customTitleBar->titleInputLineEdit(),
        this);
    connect(
        m_customTitleBar,
        &ks::ui::CustomTitleBar::inputModeChanged,
        this,
        [this](const bool searchModeActive) {
            if (m_commandExecutionPopup != nullptr)
            {
                m_commandExecutionPopup->setCommandModeActive(!searchModeActive);
            }
        });
    connect(
        m_commandExecutionPopup,
        &ks::ui::CommandExecutionPopup::executeRequested,
        this,
        [this](const QString& commandText, const ks::ui::CommandExecutionOptions& options) {
            executeCommandWithOptions(commandText, options);
        });
    m_globalUiSearchController->setDockListProvider([this]() {
        return collectSearchableDockWidgets();
    });
    m_globalUiSearchController->setDockPreparer([this](ads::CDockWidget* dockWidget) {
        ensureDockContentInitialized(dockWidget);
    });
    m_globalUiSearchController->setDockActivator([this](ads::CDockWidget* dockWidget) {
        activateDockForSearchNavigation(dockWidget);
    });
    connect(
        m_globalUiSearchController,
        &ks::ui::GlobalUiSearchController::requestSearchInputActivation,
        m_customTitleBar,
        &ks::ui::CustomTitleBar::activateSearchInput);
    connect(
        m_globalUiSearchController,
        &ks::ui::GlobalUiSearchController::searchScopeDisplayTextChanged,
        m_customTitleBar,
        &ks::ui::CustomTitleBar::setSearchScopeDisplayText);
    m_customTitleBar->setSearchScopeDisplayText(
        m_globalUiSearchController->searchScopeDisplayText());
    m_globalUiSearchController->setSearchInputActive(
        m_customTitleBar->isSearchInputModeActive());

    connect(
        m_customTitleBar,
        &ks::ui::CustomTitleBar::searchTextEdited,
        m_globalUiSearchController,
        &ks::ui::GlobalUiSearchController::handleQueryEdited);
    connect(
        m_customTitleBar,
        &ks::ui::CustomTitleBar::inputModeChanged,
        m_globalUiSearchController,
        &ks::ui::GlobalUiSearchController::setSearchInputActive);
}

QList<ads::CDockWidget*> MainWindow::collectSearchableDockWidgets() const
{
    // 顺序即结果排列顺序：主功能 Dock 在前，辅助 Dock 在后。
    return QList<ads::CDockWidget*>{
        m_dockWelcome,
        m_dockProcess,
        m_dockNetwork,
        m_dockMemory,
        m_dockFile,
        m_dockDriver,
        m_dockKernel,
        m_dockMonitorTab,
        m_dockHardware,
        m_dockPrivilege,
        m_dockWindow,
        m_dockRegistry,
        m_dockHandle,
        m_dockStartup,
        m_dockService,
        m_dockMisc,
        m_dockLog,
        m_dockMonitor,
        m_dockCurrentOp
    };
}

void MainWindow::activateDockForSearchNavigation(ads::CDockWidget* dockWidget)
{
    if (dockWidget == nullptr)
    {
        return;
    }

    ensureDockContentInitialized(dockWidget);
    withTemporaryNonTopMostForDockSwitch([dockWidget]()
        {
            if (dockWidget->isClosed())
            {
                // 辅助 Dock（日志/监视/任务）允许关闭，激活前先恢复显示。
                dockWidget->toggleView(true);
            }
            dockWidget->raise();
        });
}

void MainWindow::setPinnedWindowState(const bool pinnedState, const bool emitLog)
{
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
        const qulonglong mainWindowHandleValue =
            static_cast<qulonglong>(reinterpret_cast<quintptr>(mainWindowHandle));
        appInstance->setProperty(
            kKswordMainWindowHwndPropertyName,
            QVariant(mainWindowHandleValue));
    }

    if (m_windowPinned == pinnedState)
    {
        if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
        {
            appInstance->setProperty(kKswordMainWindowTopMostPropertyName, m_windowPinned);
        }
        syncTopMostForAllAuxiliaryTopLevelWidgets(this, m_windowPinned);
        if (m_customTitleBar != nullptr)
        {
            m_customTitleBar->setPinnedState(m_windowPinned);
        }
        return;
    }

    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
    {
        kLogEvent failedEvent;
        err << failedEvent << "[MainWindow] 置顶切换失败：主窗口句柄无效。" << eol;
        return;
    }

    DWORD errorCode = ERROR_SUCCESS;
    bool uiAccessBandApplied = false;
    const bool setTopMostResult = applyHighestPermittedTopMostLevel(
        mainWindowHandle,
        pinnedState,
        &errorCode,
        &uiAccessBandApplied);
    if (!setTopMostResult)
    {
        kLogEvent failedEvent;
        err << failedEvent
            << "[MainWindow] 最高级置顶切换失败, targetPinned="
            << (pinnedState ? "true" : "false")
            << ", errorCode="
            << errorCode
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("窗口置顶"),
            QStringLiteral("置顶状态切换失败，错误码：%1").arg(errorCode));
        return;
    }

    m_windowPinned = pinnedState;
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordMainWindowTopMostPropertyName, m_windowPinned);
    }
    syncTopMostForAllAuxiliaryTopLevelWidgets(this, m_windowPinned);
    if (m_customTitleBar != nullptr)
    {
        m_customTitleBar->setPinnedState(m_windowPinned);
    }

    if (emitLog)
    {
        kLogEvent pinEvent;
        info << pinEvent
            << "[MainWindow] 置顶状态已切换到当前权限允许的最高层级, pinned="
            << (m_windowPinned ? "true" : "false")
            << ", uiAccessBand="
            << (uiAccessBandApplied ? "true" : "false")
            << eol;
    }
}

void MainWindow::togglePinnedWindowState()
{
    setPinnedWindowState(!m_windowPinned, true);
    persistPinnedWindowPreference();
}

void MainWindow::persistPinnedWindowPreference()
{
    // pinnedSettings 作用：复制当前外观设置并只更新置顶启动偏好，避免覆盖其它设置项。
    ks::settings::AppearanceSettings pinnedSettings = m_currentAppearanceSettings;
    if (pinnedSettings.startupTopMostEnabled == m_windowPinned)
    {
        return;
    }

    pinnedSettings.startupTopMostEnabled = m_windowPinned;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(pinnedSettings, &saveErrorText))
    {
        kLogEvent pinPersistFailedEvent;
        err << pinPersistFailedEvent
            << "[MainWindow] 保存窗口置顶偏好失败，错误="
            << saveErrorText.toStdString()
            << eol;
        return;
    }

    m_currentAppearanceSettings = pinnedSettings;
    kLogEvent pinPersistEvent;
    info << pinPersistEvent
        << "[MainWindow] 已保存窗口置顶启动偏好, startupTopMost="
        << (m_currentAppearanceSettings.startupTopMostEnabled ? "true" : "false")
        << eol;
}

void MainWindow::setCaptureProtectionState(const bool protectedState, const bool emitLog)
{
    if (m_captureProtectionEnabled == protectedState)
    {
        if (m_customTitleBar != nullptr)
        {
            m_customTitleBar->setCaptureProtectionState(m_captureProtectionEnabled);
        }
        return;
    }

    const HWND mainWindowHandle = reinterpret_cast<HWND>(winId());
    if (mainWindowHandle == nullptr || ::IsWindow(mainWindowHandle) == FALSE)
    {
        kLogEvent failedEvent;
        err << failedEvent << "[MainWindow] 截屏屏蔽切换失败：主窗口句柄无效。" << eol;
        return;
    }

    // 目标策略：
    // - 开启时先请求 WDA_EXCLUDEFROMCAPTURE，Windows 10 20H2+ 会从截图/录屏中隐藏窗口；
    // - 若系统或窗口组合不支持，则回退 WDA_MONITOR，旧系统会在截图/录屏中显示黑屏；
    // - 关闭时写入 WDA_NONE，恢复正常捕获。
    DWORD appliedAffinity = kWindowDisplayAffinityAllowCapture;
    BOOL setAffinityResult = FALSE;
    if (protectedState)
    {
        appliedAffinity = kWindowDisplayAffinityExcludeFromCapture;
        setAffinityResult = ::SetWindowDisplayAffinity(mainWindowHandle, appliedAffinity);
        if (setAffinityResult == FALSE)
        {
            appliedAffinity = kWindowDisplayAffinityMonitorOnly;
            setAffinityResult = ::SetWindowDisplayAffinity(mainWindowHandle, appliedAffinity);
        }
    }
    else
    {
        appliedAffinity = kWindowDisplayAffinityAllowCapture;
        setAffinityResult = ::SetWindowDisplayAffinity(mainWindowHandle, appliedAffinity);
    }

    if (setAffinityResult == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        kLogEvent failedEvent;
        err << failedEvent
            << "[MainWindow] 截屏屏蔽切换失败, targetProtected="
            << (protectedState ? "true" : "false")
            << ", errorCode="
            << errorCode
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("截屏屏蔽"),
            QStringLiteral("截屏屏蔽切换失败，错误码：%1").arg(errorCode));
        return;
    }

    m_captureProtectionEnabled = protectedState;
    if (m_customTitleBar != nullptr)
    {
        m_customTitleBar->setCaptureProtectionState(m_captureProtectionEnabled);
    }

    if (emitLog)
    {
        kLogEvent captureProtectionEvent;
        info << captureProtectionEvent
            << "[MainWindow] 截屏屏蔽状态已切换, protected="
            << (m_captureProtectionEnabled ? "true" : "false")
            << ", affinity=0x"
            << std::hex
            << static_cast<unsigned long>(appliedAffinity)
            << std::dec
            << eol;
    }
}

void MainWindow::toggleCaptureProtectionState()
{
    setCaptureProtectionState(!m_captureProtectionEnabled, true);
}

void MainWindow::executeCommandInNewConsole(const QString& commandText)
{
    // 默认入口保留原有“回车直接打开可见 CMD”的行为；有弹层时沿用用户上次选择。
    ks::ui::CommandExecutionOptions options;
    options.workingDirectory = QDir::currentPath();
    if (m_commandExecutionPopup != nullptr)
    {
        options = m_commandExecutionPopup->currentOptions();
    }
    executeCommandWithOptions(commandText, options);
}

void MainWindow::executeCommandWithOptions(
    const QString& commandText,
    const ks::ui::CommandExecutionOptions& options)
{
    const QString trimmedCommandText = commandText.trimmed();
    if (trimmedCommandText.isEmpty())
    {
        return;
    }

    // workingDirectoryText 作用：把弹层输入规范化成 CreateProcess 可接受的目录。
    QString workingDirectoryText = options.workingDirectory.trimmed();
    if (workingDirectoryText.isEmpty())
    {
        workingDirectoryText = QDir::currentPath();
    }
    workingDirectoryText = QDir::toNativeSeparators(workingDirectoryText);
    const QFileInfo workingDirectoryInfo(workingDirectoryText);
    if (!workingDirectoryInfo.isDir())
    {
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.directory.invalid.title"), QStringLiteral("执行目录无效")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.directory.invalid.message"),
                QStringLiteral("目录不存在或不可访问：%1"))
                .arg(workingDirectoryText));
        return;
    }

    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::ProcessToken
        && options.tokenSourcePid == 0U)
    {
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.token.invalid.title"), QStringLiteral("令牌 PID 无效")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.token.invalid.message"),
                QStringLiteral("请输入有效的进程 PID。")));
        return;
    }

    // SYSTEM 用户权限较高：执行入口统一再次确认，避免任何信号直连路径绕过弹层确认。
    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::System)
    {
        const QMessageBox::StandardButton answer = QMessageBox::question(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.system.confirm.title"), QStringLiteral("确认 SYSTEM 用户")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.system.confirm.message"),
                QStringLiteral("即将以 SYSTEM 用户执行命令，命令可能访问当前用户无法访问的系统资源。\n\n是否继续？")),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (answer != QMessageBox::Yes)
        {
            return;
        }
    }

    kLogEvent commandEvent;
    info << commandEvent
        << "[MainWindow] 标题栏命令执行请求, command="
        << trimmedCommandText.toStdString()
        << eol;

    // commandInterpreterPath 作用：使用系统 ComSpec，避免发行包目录中的同名文件劫持命令解释器。
    QString commandInterpreterPath = qEnvironmentVariable("ComSpec").trimmed();
    if (commandInterpreterPath.isEmpty())
    {
        commandInterpreterPath = QStringLiteral("C:\\Windows\\System32\\cmd.exe");
    }
    commandInterpreterPath = QDir::toNativeSeparators(commandInterpreterPath);

    // commandSwitchText 作用：可见窗口使用 /K 保持交互，后台模式使用 /C 执行后退出。
    const QString commandSwitchText = options.openConsoleWindow
        ? QStringLiteral("/K")
        : QStringLiteral("/C");
    const QString commandLineText = QStringLiteral("\"%1\" %2 %3")
        .arg(commandInterpreterPath)
        .arg(commandSwitchText)
        .arg(trimmedCommandText);

    // 管理员选项通过 ShellExecuteEx 的 runas 动词触发标准 UAC，不伪造或绕过安全边界。
    const bool currentUserSelected = options.userMode
        == ks::ui::CommandExecutionOptions::UserMode::CurrentUser;
    const bool administratorRequested = options.privilegeMode
        == ks::ui::CommandExecutionOptions::PrivilegeMode::Administrator;
    if (currentUserSelected && administratorRequested && !hasAdminPrivilege())
    {
        const std::wstring commandInterpreterPathWide = commandInterpreterPath.toStdWString();
        const std::wstring commandParametersWide =
            (commandSwitchText + QStringLiteral(" ") + trimmedCommandText).toStdWString();
        const std::wstring workingDirectoryWide = workingDirectoryText.toStdWString();

        SHELLEXECUTEINFOW shellExecuteInfo{};
        shellExecuteInfo.cbSize = sizeof(shellExecuteInfo);
        shellExecuteInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
        shellExecuteInfo.lpVerb = L"runas";
        shellExecuteInfo.lpFile = commandInterpreterPathWide.c_str();
        shellExecuteInfo.lpParameters = commandParametersWide.c_str();
        shellExecuteInfo.lpDirectory = workingDirectoryWide.c_str();
        shellExecuteInfo.nShow = options.openConsoleWindow ? SW_SHOWNORMAL : SW_HIDE;

        if (::ShellExecuteExW(&shellExecuteInfo) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            err << commandEvent
                << "[MainWindow] 标题栏命令执行失败, errorCode="
                << errorCode
                << eol;
            QMessageBox::warning(
                this,
                ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
                ks::i18n::text(
                    QStringLiteral("cmd.popup.execute_failed.message"),
                    QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                    .arg(errorCode)
                    .arg(QStringLiteral("UAC 可能已取消。")));
            return;
        }

        const DWORD processId = shellExecuteInfo.hProcess != nullptr
            ? ::GetProcessId(shellExecuteInfo.hProcess)
            : 0U;
        if (shellExecuteInfo.hProcess != nullptr)
        {
            ::CloseHandle(shellExecuteInfo.hProcess);
        }
        info << commandEvent
            << "[MainWindow] 标题栏命令执行已启动, pid="
            << processId
            << eol;
        return;
    }

    // tokenSourcePid 作用：选择令牌模式时记录 SYSTEM、指定进程或普通 Shell 的源 PID。
    DWORD tokenSourcePid = 0U;
    if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::System)
    {
        tokenSourcePid = 4U;
    }
    else if (options.userMode == ks::ui::CommandExecutionOptions::UserMode::ProcessToken)
    {
        tokenSourcePid = options.tokenSourcePid;
    }
    else if (options.privilegeMode
        == ks::ui::CommandExecutionOptions::PrivilegeMode::Standard
        && hasAdminPrivilege())
    {
        // 已提升实例用 Explorer 令牌回到普通用户；普通实例直接创建即可保持普通权限。
        DWORD shellProcessId = 0U;
        const HWND shellWindow = ::GetShellWindow();
        if (shellWindow != nullptr)
        {
            ::GetWindowThreadProcessId(shellWindow, &shellProcessId);
        }
        if (shellProcessId == 0U)
        {
            const DWORD errorCode = ERROR_NOT_FOUND;
            err << commandEvent
                << "[MainWindow] 标题栏命令执行失败, errorCode="
                << errorCode
                << eol;
            QMessageBox::warning(
                this,
                ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
                ks::i18n::text(
                    QStringLiteral("cmd.popup.execute_failed.message"),
                    QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                    .arg(errorCode)
                    .arg(QStringLiteral("未找到交互式 Shell 进程，无法获取普通用户令牌。")));
            return;
        }
        tokenSourcePid = shellProcessId;
    }

    ks::process::CreateProcessRequest request;
    request.useApplicationName = true;
    request.applicationName = commandInterpreterPath.toStdString();
    request.useCommandLine = true;
    request.commandLine = commandLineText.toStdString();
    request.creationFlags = (options.openConsoleWindow ? CREATE_NEW_CONSOLE : CREATE_NO_WINDOW)
        | CREATE_UNICODE_ENVIRONMENT;
    request.useCurrentDirectory = true;
    request.currentDirectory = workingDirectoryText.toStdString();
    request.startupInfo.useValue = true;
    request.startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    request.startupInfo.wShowWindow = static_cast<std::uint16_t>(
        options.openConsoleWindow ? SW_SHOWNORMAL : SW_HIDE);
    request.tokenModeEnabled = tokenSourcePid != 0U;
    request.tokenSourcePid = tokenSourcePid;

    ks::process::CreateProcessResult result;
    if (!ks::process::LaunchProcess(request, &result))
    {
        const DWORD errorCode = result.win32Error != 0U
            ? static_cast<DWORD>(result.win32Error)
            : ERROR_GEN_FAILURE;
        err << commandEvent
            << "[MainWindow] 标题栏命令执行失败, errorCode="
            << errorCode
            << eol;
        QMessageBox::warning(
            this,
            ks::i18n::text(QStringLiteral("cmd.popup.execute_failed.title"), QStringLiteral("执行命令失败")),
            ks::i18n::text(
                QStringLiteral("cmd.popup.execute_failed.message"),
                QStringLiteral("无法启动 cmd.exe。\n错误码：%1\n%2"))
                .arg(errorCode)
                .arg(QString::fromStdString(result.detailText)));
        return;
    }

    info << commandEvent
        << "[MainWindow] 标题栏命令执行已启动, pid="
        << result.dwProcessId
        << eol;
}

void MainWindow::initMenus()
{
    if (m_licenseMenuButton != nullptr || m_customTitleBar == nullptr)
    {
        return;
    }

    // 标题栏左侧功能入口：只保留常用的五项操作，不再额外占用一行菜单栏。
    auto* titleActionContainer = new QWidget(m_customTitleBar);
    titleActionContainer->setFixedHeight(22);
    auto* titleActionLayout = new QHBoxLayout(titleActionContainer);
    titleActionLayout->setContentsMargins(2, 0, 0, 0);
    titleActionLayout->setSpacing(2);

    const auto configureTitleActionButton = [](QToolButton* button)
    {
        button->setToolButtonStyle(Qt::ToolButtonTextOnly);
        button->setAutoRaise(true);
        button->setFixedHeight(22);
        button->setFocusPolicy(Qt::NoFocus);
    };

    m_licenseMenuButton = new QToolButton(titleActionContainer);
    m_licenseMenuButton->setObjectName(QStringLiteral("ksLicenseMenuButton"));
    m_licenseMenuButton->setText(QStringLiteral("许可证"));
    m_licenseMenuButton->setToolTip(QStringLiteral("查看软件许可证"));
    ks::i18n::LanguageManager::instance().bindText(m_licenseMenuButton, QStringLiteral("menu.license"), QStringLiteral("许可证"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_licenseMenuButton, QStringLiteral("menu.license.tooltip"), QStringLiteral("查看软件许可证"));
    configureTitleActionButton(m_licenseMenuButton);
    connect(m_licenseMenuButton, &QToolButton::clicked, this, &MainWindow::showLicenseFromMenu);

    m_pluginMenuButton = new QToolButton(titleActionContainer);
    m_pluginMenuButton->setObjectName(QStringLiteral("ksPluginMenuButton"));
    m_pluginMenuButton->setText(QStringLiteral("插件"));
    m_pluginMenuButton->setToolTip(QStringLiteral("浏览、安装和管理插件"));
    ks::i18n::LanguageManager::instance().bindText(m_pluginMenuButton, QStringLiteral("menu.plugins"), QStringLiteral("插件"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_pluginMenuButton, QStringLiteral("menu.plugins.tooltip"), QStringLiteral("浏览、安装和管理插件"));
    configureTitleActionButton(m_pluginMenuButton);
    connect(m_pluginMenuButton, &QToolButton::clicked, this, [this]() {
        ks::plugin_host::showPluginManager(this);
    });

    m_windowMenuButton = new QToolButton(titleActionContainer);
    m_windowMenuButton->setObjectName(QStringLiteral("ksWindowMenuButton"));
    m_windowMenuButton->setText(QStringLiteral("窗口"));
    m_windowMenuButton->setToolTip(QStringLiteral("显示或隐藏 Dock 窗口"));
    ks::i18n::LanguageManager::instance().bindText(
        m_windowMenuButton,
        QStringLiteral("menu.window"),
        QStringLiteral("窗口"));
    ks::i18n::LanguageManager::instance().bindToolTip(
        m_windowMenuButton,
        QStringLiteral("menu.window.tooltip"),
        QStringLiteral("显示或隐藏 Dock 窗口"));
    configureTitleActionButton(m_windowMenuButton);
    m_windowMenuButton->setPopupMode(QToolButton::InstantPopup);
    m_windowMenu = new QMenu(m_windowMenuButton);
    m_windowMenu->setObjectName(QStringLiteral("ksWindowMenu"));
    m_windowMenuButton->setMenu(m_windowMenu);

    m_logMenuButton = new QToolButton(titleActionContainer);
    m_logMenuButton->setObjectName(QStringLiteral("ksLogMenuButton"));
    m_logMenuButton->setText(QStringLiteral("日志输出"));
    m_logMenuButton->setToolTip(QStringLiteral("显示或隐藏非模态日志输出窗口"));
    ks::i18n::LanguageManager::instance().bindText(m_logMenuButton, QStringLiteral("menu.log"), QStringLiteral("日志输出"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_logMenuButton, QStringLiteral("menu.log.tooltip"), QStringLiteral("显示或隐藏非模态日志输出窗口"));
    configureTitleActionButton(m_logMenuButton);
    connect(m_logMenuButton, &QToolButton::clicked, this, &MainWindow::toggleLogOutputWindow);

    m_settingsMenuButton = new QToolButton(titleActionContainer);
    m_settingsMenuButton->setObjectName(QStringLiteral("ksSettingsMenuButton"));
    m_settingsMenuButton->setText(QStringLiteral("设置"));
    m_settingsMenuButton->setToolTip(QStringLiteral("打开界面与启动设置"));
    ks::i18n::LanguageManager::instance().bindText(m_settingsMenuButton, QStringLiteral("menu.settings"), QStringLiteral("设置"));
    ks::i18n::LanguageManager::instance().bindToolTip(m_settingsMenuButton, QStringLiteral("menu.settings.tooltip"), QStringLiteral("打开界面、语言与启动设置"));
    configureTitleActionButton(m_settingsMenuButton);
    connect(m_settingsMenuButton, &QToolButton::clicked, this, [this]() {
        showSettingsPanelFromMenu();
    });

    titleActionLayout->addWidget(m_licenseMenuButton);
    titleActionLayout->addWidget(m_pluginMenuButton);
    titleActionLayout->addWidget(m_windowMenuButton);
    titleActionLayout->addWidget(m_logMenuButton);
    titleActionLayout->addWidget(m_settingsMenuButton);
    m_customTitleBar->setCustomLeftWidget(titleActionContainer);
    refreshTitleActionButtonStyles();
}

void MainWindow::initializeWindowDockMenuActions()
{
    if (m_windowMenu == nullptr || m_dockLog == nullptr || m_dockMonitor == nullptr || m_dockCurrentOp == nullptr)
    {
        return;
    }

    // 直接使用 ADS 的原生 toggle action：菜单勾选、Dock 标题栏关闭、浮动和布局恢复
    // 都由同一份可见状态驱动，避免维护第二套布尔状态。
    m_windowMenu->clear();
    m_dockLog->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
    m_dockMonitor->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
    m_dockCurrentOp->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);

    QAction* logDockAction = m_dockLog->toggleViewAction();
    QAction* monitorPanelAction = m_dockMonitor->toggleViewAction();
    QAction* currentTasksAction = m_dockCurrentOp->toggleViewAction();
    ks::i18n::LanguageManager::instance().bindText(
        logDockAction,
        QStringLiteral("dock.log_window"),
        QStringLiteral("日志窗口"));
    ks::i18n::LanguageManager::instance().bindText(
        monitorPanelAction,
        QStringLiteral("dock.monitor_panel"),
        QStringLiteral("监视面板"));
    ks::i18n::LanguageManager::instance().bindText(
        currentTasksAction,
        QStringLiteral("dock.current_tasks"),
        QStringLiteral("当前任务"));
    m_windowMenu->addAction(logDockAction);
    m_windowMenu->addAction(monitorPanelAction);
    m_windowMenu->addAction(currentTasksAction);
}

QString MainWindow::buildTitleActionButtonStyle() const
{
    // 标题栏功能按钮样式按当前主题实时生成，避免主题切换后保留旧颜色。
    const bool darkModeEnabled = KswordTheme::IsDarkModeEnabled();
    const QString hoverColor = KswordTheme::RgbaColorName(
        KswordTheme::PrimaryBlueColor,
        darkModeEnabled ? 56 : 36);
    const QString pressedColor = KswordTheme::RgbaColorName(
        KswordTheme::PrimaryBlueColor,
        darkModeEnabled ? 87 : 62);
    const QString textColor = KswordTheme::TextPrimaryColorHex();
    const QString borderColor = KswordTheme::RgbaColorName(
        KswordTheme::PrimaryBlueColor,
        darkModeEnabled ? 117 : 82);

    return QStringLiteral(
        "QToolButton{"
        "  background:transparent !important;"
        "  color:%1 !important;"
        "  border:1px solid transparent !important;"
        "  border-radius:4px;"
        "  margin:0;"
        "  padding:1px 5px;"
        "  font-weight:600;"
        "  text-align:left;"
        "}"
        "QToolButton:hover{"
        "  background:%2 !important;"
        "  color:%1 !important;"
        "  border-color:%4 !important;"
        "}"
        "QToolButton:pressed{"
        "  background:%3 !important;"
        "  color:%1 !important;"
        "  border-color:%4 !important;"
        "}"
        "QToolButton::menu-indicator{"
        "  image:none;"
        "  width:0;"
        "  height:0;"
        "}")
        .arg(textColor)
        .arg(hoverColor)
        .arg(pressedColor)
        .arg(borderColor);
}

void MainWindow::refreshTitleActionButtonStyles()
{
    // 标题栏功能按钮刷新：主题切换后所有按钮都重新套用同一份 QSS。
    const QString titleActionButtonStyle = buildTitleActionButtonStyle();
    const QList<QToolButton*> topActionButtonList{
        m_licenseMenuButton,
        m_pluginMenuButton,
        m_windowMenuButton,
        m_logMenuButton,
        m_settingsMenuButton
    };
    for (QToolButton* button : topActionButtonList)
    {
        if (button != nullptr)
        {
            button->setStyleSheet(titleActionButtonStyle);
        }
    }
}

void MainWindow::showLicenseFromMenu()
{
    const QDir applicationDirectory(QCoreApplication::applicationDirPath());
    const QStringList licenseFileNames{
        QStringLiteral("LICENSE"),
        QStringLiteral("LICENSE.txt"),
        QStringLiteral("license")
    };
    QString licensePath = applicationDirectory.absoluteFilePath(licenseFileNames.constFirst());
    for (const QString& licenseFileName : licenseFileNames)
    {
        const QString candidatePath = applicationDirectory.absoluteFilePath(licenseFileName);
        if (QFileInfo(candidatePath).isFile())
        {
            licensePath = candidatePath;
            break;
        }
    }
    QString licenseText;
    const auto appendLegalDocument = [&licenseText](const QString& filePath)
    {
        QFile legalFile(filePath);
        if (!legalFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            return false;
        }

        QTextStream legalStream(&legalFile);
        legalStream.setEncoding(QStringConverter::Utf8);
        const QString documentText = legalStream.readAll();
        if (!licenseText.isEmpty())
        {
            licenseText += QStringLiteral("\n\n===== %1 =====\n\n")
                .arg(QFileInfo(filePath).fileName());
        }
        licenseText += documentText;
        return true;
    };

    if (!appendLegalDocument(licensePath))
    {
        if (!licenseText.isEmpty())
        {
            licenseText += QString::fromLatin1("\n\n===== LICENSE =====\n\n");
        }
        licenseText += QStringLiteral("未找到程序同目录的 LICENSE 文件：\n%1").arg(QDir::toNativeSeparators(licensePath));
    }

    const QStringList supplementaryLegalFiles{
        QStringLiteral("COMMUNITY_COVENANT.md")
    };
    for (const QString& legalFileName : supplementaryLegalFiles)
    {
        const QString legalFilePath = applicationDirectory.absoluteFilePath(legalFileName);
        if (QFileInfo(legalFilePath).isFile())
        {
            appendLegalDocument(legalFilePath);
        }
    }

    QDialog licenseDialog(this);
    licenseDialog.setWindowTitle(QStringLiteral("许可证"));
    licenseDialog.resize(760, 560);
    licenseDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}"
        "QTextEdit{background:%1;color:%2;border:1px solid %3;}"
        "QPushButton{padding:4px 14px;}" )
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        .arg(KswordTheme::BorderHex()));

    QVBoxLayout dialogLayout(&licenseDialog);
    dialogLayout.setContentsMargins(8, 8, 8, 8);
    dialogLayout.setSpacing(8);

    QTextEdit licenseEditor(&licenseDialog);
    licenseEditor.setReadOnly(true);
    // 许可证正文属于原始法律文本；仅本地缺失提示需要按当前界面语言显示。
    const QString licenseDisplayText = licenseText.trimmed().isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("LICENSE 文件为空。"))
        : licenseText;
    licenseEditor.setPlainText(licenseDisplayText);
    dialogLayout.addWidget(&licenseEditor, 1);

    QPushButton closeButton(QStringLiteral("关闭"), &licenseDialog);
    connect(&closeButton, &QPushButton::clicked, &licenseDialog, &QDialog::accept);
    dialogLayout.addWidget(&closeButton, 0, Qt::AlignRight);

    licenseDialog.exec();
}
void MainWindow::showSettingsPanelFromMenu(bool showLanguageTab)
{
    QDialog settingsDialog(this);
    settingsDialog.setWindowTitle(QStringLiteral("设置"));
    settingsDialog.setModal(false);
    settingsDialog.resize(760, 640);
    settingsDialog.setStyleSheet(QStringLiteral(
        "QDialog{background:%1;color:%2;}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::TextPrimaryHex())
        + KswordTheme::ThemedComboBoxStyle());

    QVBoxLayout dialogLayout(&settingsDialog);
    dialogLayout.setContentsMargins(8, 8, 8, 8);
    dialogLayout.setSpacing(6);

    // 设置面板改为顶部菜单即时对话框，每次打开读取当前 JSON，避免占用主 Tab 栏空间。
    auto* settingsScrollArea = new QScrollArea(&settingsDialog);
    settingsScrollArea->setWidgetResizable(true);
    settingsScrollArea->setFrameShape(QFrame::NoFrame);
    settingsScrollArea->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    settingsScrollArea->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);

    auto* settingsPanel = new SettingsDock();
    settingsScrollArea->setWidget(settingsPanel);
    if (showLanguageTab)
    {
        settingsPanel->showLanguageSettingsTab();
    }
    connect(
        settingsPanel,
        &SettingsDock::appearanceSettingsChanged,
        this,
        [this](const ks::settings::AppearanceSettings& settings) {
            applyAppearanceSettings(settings, QStringLiteral("顶部菜单设置变更"));
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsAutoInstallChanged,
        this,
        [this](const bool enabled)
        {
            m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled = enabled;
            updateBugcheckDiagnosticsEntryVisibility();
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsInstallationStarted,
        this,
        [this]()
        {
            m_bugcheckDiagnosticsEntryRequestedForSession = true;
            updateBugcheckDiagnosticsEntryVisibility();
        });
    connect(
        settingsPanel,
        &SettingsDock::bugcheckDiagnosticsInstalledForSession,
        this,
        [this]()
        {
            m_bugcheckDiagnosticsInstalledForSession = true;
            updateBugcheckDiagnosticsEntryVisibility();
            queueBugcheckVerdictResourceUpload();
        });
    dialogLayout.addWidget(settingsScrollArea, 1);

    // 固定操作栏不放入滚动区域，保证“应用/取消”始终可见。
    auto* actionLayout = new QHBoxLayout();
    actionLayout->addStretch(1);
    auto* cancelButton = new QPushButton(QStringLiteral("取消"), &settingsDialog);
    auto* applyButton = new QPushButton(QStringLiteral("应用"), &settingsDialog);
    auto& languageManager = ks::i18n::LanguageManager::instance();
    languageManager.bindText(cancelButton, QStringLiteral("common.cancel"), QStringLiteral("取消"));
    languageManager.bindText(applyButton, QStringLiteral("settings.apply"), QStringLiteral("应用"));
    languageManager.bindToolTip(applyButton, QStringLiteral("settings.apply.tooltip"), QStringLiteral("应用当前设置改动"));
    cancelButton->setMinimumWidth(72);
    applyButton->setMinimumWidth(72);
    cancelButton->setFixedHeight(30);
    applyButton->setFixedHeight(30);
    applyButton->setEnabled(false);
    actionLayout->addWidget(cancelButton);
    actionLayout->addWidget(applyButton);
    dialogLayout.addLayout(actionLayout);

    connect(applyButton, &QPushButton::clicked, settingsPanel, &SettingsDock::applySettings);
    connect(cancelButton, &QPushButton::clicked, &settingsDialog, &QDialog::reject);
    connect(settingsPanel, &SettingsDock::pendingChangesChanged, applyButton, &QPushButton::setEnabled);

    settingsDialog.exec();
}

void MainWindow::toggleLogOutputWindow()
{
    if (m_logOutputWindow == nullptr)
    {
        return;
    }

    if (m_logOutputWindow->isVisible())
    {
        persistLogOutputWindowGeometry();
        m_logOutputWindow->hide();
        return;
    }

    if (m_logWidget != nullptr)
    {
        m_logWidget->refreshNow();
    }
    m_logOutputWindow->show();
    m_logOutputWindow->raise();
    m_logOutputWindow->activateWindow();
}

void MainWindow::persistLogOutputWindowGeometry()
{
    if (m_logOutputWindow == nullptr || !m_logOutputWindow->geometry().isValid())
    {
        return;
    }

    const QString encodedGeometry = QString::fromLatin1(m_logOutputWindow->saveGeometry().toBase64());
    if (encodedGeometry == m_currentAppearanceSettings.logWindowGeometryBase64)
    {
        return;
    }

    m_currentAppearanceSettings.logWindowGeometryBase64 = encodedGeometry;
    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(m_currentAppearanceSettings, &saveErrorText))
    {
        kLogEvent geometryEvent;
        warn << geometryEvent
            << "[MainWindow] 保存日志窗口几何信息失败: "
            << saveErrorText.toStdString()
            << eol;
    }
}

void MainWindow::restoreLogOutputWindowGeometry()
{
    if (m_logOutputWindow == nullptr)
    {
        return;
    }

    const QByteArray encodedGeometry = QByteArray::fromBase64(
        m_currentAppearanceSettings.logWindowGeometryBase64.toLatin1());
    bool restored = !encodedGeometry.isEmpty() && m_logOutputWindow->restoreGeometry(encodedGeometry);
    if (restored)
    {
        const QRect restoredRect = m_logOutputWindow->frameGeometry();
        bool intersectsAvailableScreen = false;
        for (QScreen* screen : QGuiApplication::screens())
        {
            if (screen != nullptr && screen->availableGeometry().intersects(restoredRect))
            {
                intersectsAvailableScreen = true;
                break;
            }
        }
        if (intersectsAvailableScreen)
        {
            return;
        }
        restored = false;
    }

    if (!restored)
    {
        m_logOutputWindow->resize(900, 620);
        const QRect hostRect = frameGeometry();
        m_logOutputWindow->move(
            hostRect.center() - QPoint(m_logOutputWindow->width() / 2, m_logOutputWindow->height() / 2));
    }
}

void MainWindow::initPrivilegeStatusButtons()
{
    // 防重复初始化：若已创建容器则只刷新一次状态。
    if (m_privilegeButtonContainer != nullptr)
    {
        refreshPrivilegeStatusButtons();
        return;
    }

    // 权限状态组在 Dock 布局恢复后挂到主功能 Tab 栏；初始化期先由主窗口托管。
    m_privilegeButtonContainer = new QWidget(this);
    QHBoxLayout* buttonLayout = new QHBoxLayout(m_privilegeButtonContainer);
    buttonLayout->setContentsMargins(0, 0, 4, 0);
    buttonLayout->setSpacing(6);

    // 按钮文本采用纯文字，满足用户要求；UIAccess 放在最左侧用于切换 TokenUIAccess fallback。
    m_uiAccessStatusButton = new QPushButton("UIAccess", m_privilegeButtonContainer);
    m_adminStatusButton = new QPushButton("Admin", m_privilegeButtonContainer);
    m_debugStatusButton = new QPushButton("Debug", m_privilegeButtonContainer);
    m_systemStatusButton = new QPushButton("System", m_privilegeButtonContainer);
    m_r0StatusButton = new QPushButton("R0", m_privilegeButtonContainer);

    // 统一按钮尺寸，保证右上角布局整齐。
    const std::array<QPushButton*, 5> statusButtons{
        m_uiAccessStatusButton,
        m_adminStatusButton,
        m_debugStatusButton,
        m_systemStatusButton,
        m_r0StatusButton
    };
    for (QPushButton* statusButton : statusButtons)
    {
        if (statusButton == nullptr)
        {
            continue;
        }
        statusButton->setFixedHeight(22);
        statusButton->setMinimumWidth(56);
        buttonLayout->addWidget(statusButton);
    }
    if (m_uiAccessStatusButton != nullptr)
    {
        m_uiAccessStatusButton->setMinimumWidth(74);
    }

    // 权限状态按钮 tooltip：这排按钮同时是“状态指示灯 + 快捷操作”，逐个说明含义与点击行为。
    m_uiAccessStatusButton->setToolTip(QStringLiteral("UIAccess：跨权限窗口置顶能力状态。点击后重启程序并尝试启用/关闭该能力。"));
    m_adminStatusButton->setToolTip(QStringLiteral("Admin：当前是否以管理员权限运行。非管理员时点击会以管理员身份重启程序。"));
    m_debugStatusButton->setToolTip(QStringLiteral("Debug：调试特权（SeDebugPrivilege）状态，用于访问受保护进程。点击申请该特权（需要管理员）。"));
    m_systemStatusButton->setToolTip(QStringLiteral("System：当前是否以 LocalSystem 系统账户运行。点击查看当前身份说明。"));
    m_r0StatusButton->setToolTip(QStringLiteral("R0：KswordARK 内核驱动服务状态。点击启动或停止驱动（内核功能都依赖它）。"));

    // UIAccess 按钮：
    // - 当前实例已带 UIAccess 时降级回普通用户实例；
    // - 未带 UIAccess 时按需提权，并尝试 SYSTEM TokenUIAccess fallback 启动。
    connect(m_uiAccessStatusButton, &QPushButton::clicked, this, [this]() {
        handleUiAccessButtonClicked();
    });

    // Admin 按钮：
    // - 已是管理员：仅提示当前状态；
    // - 非管理员：立刻触发 runas 重启提权。
    connect(m_adminStatusButton, &QPushButton::clicked, this, [this]() {
        if (hasAdminPrivilege())
        {
            QMessageBox::information(this, "Admin", "当前已是管理员权限。");
            refreshPrivilegeStatusButtons();
            return;
        }

        kLogEvent logEvent;
        warn << logEvent << "[MainWindow] Admin 按钮触发提权重启。" << eol;
        requestAdminElevationRestart();
    });

    // Debug 按钮：
    // - 非管理员：按需求先执行 Admin 提权动作；
    // - 已管理员：申请 SeDebugPrivilege。
    connect(m_debugStatusButton, &QPushButton::clicked, this, [this]() {
        if (!hasAdminPrivilege())
        {
            kLogEvent logEvent;
            warn << logEvent << "[MainWindow] Debug 按钮检测到非管理员，转为执行 Admin 提权。" << eol;
            requestAdminElevationRestart();
            return;
        }

        std::string errorText;
        const bool enableOk = enableSeDebugPrivilege(errorText);
        if (enableOk)
        {
            kLogEvent logEvent;
            info << logEvent << "[MainWindow] SeDebugPrivilege 申请成功。" << eol;
            QMessageBox::information(this, "Debug", "SeDebugPrivilege 已启用。");
        }
        else
        {
            kLogEvent logEvent;
            err << logEvent << "[MainWindow] SeDebugPrivilege 申请失败: " << errorText << eol;
            // privilegePromptHandled：权限恢复提示已展示时抑制旧 Debug 失败框。
            const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                QStringLiteral("启用 SeDebugPrivilege"),
                QString::fromStdString(errorText));
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(
                    this,
                    "Debug",
                    QString("SeDebugPrivilege 启用失败。\n%1").arg(QString::fromStdString(errorText)));
            }
        }
        refreshPrivilegeStatusButtons();
    });

    // System 按钮仅展示状态，点击给出提示（普通用户态无法直接“切到 SYSTEM”）。
    connect(m_systemStatusButton, &QPushButton::clicked, this, [this]() {
        if (hasSystemPrivilege())
        {
            QMessageBox::information(this, "System", "当前进程已经是 LocalSystem 身份。");
        }
        else
        {
            HANDLE hToken = NULL;          // 当前进程的令牌句柄
            LUID Luid;                     // 特权局部唯一标识符
            TOKEN_PRIVILEGES tp;           // 令牌特权结构体

            // 打开当前进程的令牌，要求调整特权与查询权限
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
            {
                kLogEvent logEvent;
                err << logEvent << "OpenProcessToken failed, error: " << GetLastError() << eol;
                return 1;
            }

            // 查找 SE_DEBUG_NAME 特权的 LUID
            if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &Luid))
            {
                kLogEvent logEvent;
                err << logEvent << "LookupPrivilegeValue failed, error: " << GetLastError() << eol;
                CloseHandle(hToken);
                return 1;
            }

            // 设置特权属性为启用
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = Luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            // 调整令牌特权
            if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL))
            {
                kLogEvent logEvent;
                err << logEvent << "AdjustTokenPrivileges failed, error: " << GetLastError() << eol;
                CloseHandle(hToken);
                return 1;
            }
            // 检查特权是否真正被启用（AdjustTokenPrivileges 可能成功但未全部分配）
            if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
            {
                kLogEvent logEvent;
                err << logEvent << "AdjustTokenPrivileges: SeDebugPrivilege not assigned" << eol;
                CloseHandle(hToken);
                return 1;
            }
            CloseHandle(hToken);  // 特权已启用，关闭临时句柄

            // ========== 第二步：枚举进程，获取 lsass.exe 和 winlogon.exe 的 PID ==========
            DWORD idL = 0;                     // 存放 lsass.exe 的进程ID
            DWORD idW = 0;                     // 存放 winlogon.exe 的进程ID
            PROCESSENTRY32W pe = { sizeof(PROCESSENTRY32W) };  // 进程快照条目（宽字符）
            HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  // 进程快照句柄
            if (hSnapshot == INVALID_HANDLE_VALUE)
            {
                kLogEvent logEvent;
                err << logEvent << "CreateToolhelp32Snapshot failed, error: " << GetLastError() << eol;
                return 1;
            }

            // 遍历进程快照，匹配目标进程名
            if (Process32FirstW(hSnapshot, &pe))
            {
                do
                {
                    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0)
                    {
                        idL = pe.th32ProcessID;
                        kLogEvent logEvent;
                        info << logEvent << "Found lsass.exe with PID: " << idL << eol;
                    }
                    else if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0)
                    {
                        idW = pe.th32ProcessID;
                        kLogEvent logEvent;
                        info << logEvent << "Found winlogon.exe with PID: " << idW << eol;
                    }
                } while (Process32NextW(hSnapshot, &pe));
            }
            CloseHandle(hSnapshot);

            // ========== 第三步：打开目标进程（优先 lsass，其次 winlogon） ==========
            HANDLE hProcess = NULL;          // 目标进程句柄
            if (idL != 0)
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idL);
            if (!hProcess && idW != 0)
                hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, idW);
            if (!hProcess)
            {
                kLogEvent logEvent;
                err << logEvent << "Failed to open target process (lsass/winlogon), error: " << GetLastError() << eol;
                return 1;
            }
            {
                kLogEvent logEvent;
                info << logEvent << "Opened target process" << eol;
            }

            // ========== 第四步：打开目标进程的令牌 ==========
            HANDLE hTokenx = NULL;           // 目标进程的令牌句柄
            if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hTokenx))
            {
                kLogEvent logEvent;
                err << logEvent << "OpenProcessToken on target process failed, error: " << GetLastError() << eol;
                CloseHandle(hProcess);
                return 1;
            }

            // ========== 第五步：复制令牌，获得可用的主令牌 ==========
            HANDLE hNewToken = NULL;         // 复制得到的新令牌句柄
            if (!DuplicateTokenEx(hTokenx, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &hNewToken))
            {
                kLogEvent logEvent;
                err << logEvent << "DuplicateTokenEx failed, error: " << GetLastError() << eol;
                CloseHandle(hTokenx);
                CloseHandle(hProcess);
                return 1;
            }
            CloseHandle(hTokenx);
            CloseHandle(hProcess);

            // ========== 第六步：获取当前程序自身的路径 ==========
            std::wstring selfPath = ks::process::GetCurrentProcessPath();
            if (selfPath.empty())
            {
                kLogEvent logEvent;
                err << logEvent <<"Failed to get current process path" << eol;
                CloseHandle(hNewToken);
                return 1;
            }
            {
                kLogEvent logEvent;
                // pathUtf8 用途：把 UTF-16 路径转换为 UTF-8，避免日志流(std::ostringstream)直接输出 std::wstring 导致编译错误。
                const std::string pathUtf8 = ks::str::Utf16ToUtf8(selfPath);
                info << logEvent << "Current process path: " << pathUtf8 << eol;
            }

            // ========== 第七步：使用复制得到的令牌启动自身 ==========
            STARTUPINFOW si = { sizeof(STARTUPINFOW) };
            PROCESS_INFORMATION pi = { 0 };
            // 为 lpDesktop 使用可写缓冲区（避免 const wchar_t* 赋值给 LPWSTR 的编译错误）
            wchar_t desktop[] = L"winsta0\\default";
            si.lpDesktop = desktop;          // 显示在交互式桌面

            // SYSTEM 权限切换必须携带内部重启标记，否则默认开启的防多开会让新实例立即退出。
            const QStringList launchArgumentList = argumentsWithPrivilegeRestartTakeover(
                QCoreApplication::arguments(),
                ::GetCurrentProcessId());
            QString commandLineText = quoteQStringCommandLineArgument(QString::fromStdWString(selfPath));
            for (int index = 1; index < launchArgumentList.size(); ++index)
            {
                commandLineText += QLatin1Char(' ');
                commandLineText += quoteQStringCommandLineArgument(launchArgumentList.at(index));
            }
            std::wstring commandLineWide = commandLineText.toStdWString();

            if (!CreateProcessWithTokenW(hNewToken, LOGON_NETCREDENTIALS_ONLY, selfPath.c_str(), commandLineWide.data(),
                NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
            {
                kLogEvent logEvent;
                err << logEvent << "CreateProcessWithTokenW failed, error: " << GetLastError() << eol;
                CloseHandle(hNewToken);
                return 1;
            }

            {
                kLogEvent logEvent;
                info << logEvent << "Successfully started new instance of the program. New PID: " << pi.dwProcessId << eol;
            }

            // 清理资源
            CloseHandle(hNewToken);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            close();
        }

        // Qt ignores the slot return value, but early failure paths in this
        // lambda return an int for legacy flow control. Return a final success
        // value so every compiler-visible path is explicit and warning-free.
        return 0;
    });

    // R0 按钮：
    // - 启动前先查询服务状态；
    // - 运行中则停止并卸载服务；
    // - 未运行则从当前 exe 目录加载 KswordARK.sys。
    connect(m_r0StatusButton, &QPushButton::clicked, this, [this]() {
        handleR0StatusButtonClicked();
    });

    // 定时刷新权限状态，保证按钮颜色与实际权限一致。
    m_privilegeStatusTimer = new QTimer(this);
    m_privilegeStatusTimer->setInterval(1500);
    connect(m_privilegeStatusTimer, &QTimer::timeout, this, [this]() {
        refreshPrivilegeStatusButtons();
    });
    m_privilegeStatusTimer->start();

    // 启动时执行一次 R0 服务状态查询，作为按钮初始态来源。
    queryR0DriverServiceRunning(m_r0DriverServiceRunning, true);
    refreshPrivilegeStatusButtons();
}

void MainWindow::attachPrivilegeStatusButtonsToPrimaryDockTabBar()
{
    if (m_privilegeButtonContainer == nullptr || m_dockWelcome == nullptr)
    {
        return;
    }

    ads::CDockAreaWidget* const mainDockArea = m_dockWelcome->dockAreaWidget();
    if (mainDockArea == nullptr || mainDockArea->titleBar() == nullptr)
    {
        return;
    }

    ads::CDockAreaTitleBar* const titleBar = mainDockArea->titleBar();
    if (m_privilegeButtonContainer->parentWidget() == titleBar
        && titleBar->indexOf(m_privilegeButtonContainer) >= 0)
    {
        return;
    }

    // 追加到 ADS 标题栏布局末尾：TabBar 自行占据中间可伸缩空间，权限按钮组固定贴右。
    titleBar->insertWidget(-1, m_privilegeButtonContainer);
    m_privilegeButtonContainer->show();
}

void MainWindow::handleR0DriverUnavailable(const unsigned long win32Error)
{
    // 所有 ArkDriverClient 调用都会汇聚到这里。只在窗口已可交互时提示，且把短时间内
    // 多个页面/后台任务的失败合并为一个选择，避免用户刚打开一个 R0 页面就被连续打断。
    if (!m_r0UnavailablePromptArmed || m_r0UnavailablePromptShowing)
    {
        return;
    }

    bool serviceRunning = false;
    if (!queryR0DriverServiceRunning(serviceRunning, false))
    {
        return;
    }
    if (serviceRunning)
    {
        m_r0DriverServiceRunning = true;
        refreshPrivilegeStatusButtons();
        return;
    }

    m_r0DriverServiceRunning = false;
    if (m_suppressR0PromptsForSession || m_currentAppearanceSettings.suppressR0FeaturePrompts)
    {
        refreshPrivilegeStatusButtons();
        return;
    }
    m_r0UnavailablePromptShowing = true;

    const bool isAdmin = hasAdminPrivilege();
    QMessageBox prompt(this);
    prompt.setIcon(QMessageBox::Warning);
    prompt.setWindowTitle(ks::i18n::text(
        QStringLiteral("r0.enable_required.title"),
        QStringLiteral("需要启用 R0")));
    prompt.setText(ks::i18n::text(
        QStringLiteral("r0.enable_required.message"),
        QStringLiteral("当前操作需要 R0 驱动，但 KswordARK 驱动服务尚未启用。\n\n是否现在启用 R0？")));
    prompt.setInformativeText(ks::i18n::text(
        QStringLiteral("r0.enable_required.hint"),
        QStringLiteral("启用后可继续使用依赖内核权限的功能；R0 状态按钮会显示为已启用。")));
    QCheckBox* const suppressForSessionCheckBox = new QCheckBox(
        ks::i18n::text(
            QStringLiteral("r0.enable_required.suppress_session"),
            QStringLiteral("本次不再提醒")));
    prompt.setCheckBox(suppressForSessionCheckBox);
    QPushButton* const enableButton = prompt.addButton(
        ks::i18n::text(
            isAdmin
            ? QStringLiteral("r0.enable_required.enable_now")
            : QStringLiteral("r0.enable_required.elevate_and_enable"),
            isAdmin ? QStringLiteral("启用 R0") : QStringLiteral("以管理员身份重启并启用 R0")),
        QMessageBox::AcceptRole);
    prompt.addButton(
        ks::i18n::text(QStringLiteral("r0.enable_required.cancel"), QStringLiteral("暂不启用")),
        QMessageBox::RejectRole);
    prompt.exec();

    m_r0UnavailablePromptShowing = false;
    if (suppressForSessionCheckBox->isChecked())
    {
        m_suppressR0PromptsForSession = true;
    }
    if (prompt.clickedButton() != enableButton)
    {
        refreshPrivilegeStatusButtons();
        return;
    }

    if (!isAdmin)
    {
        requestAdminElevationRestart(true);
        return;
    }

    enableR0ForUserRequest();
    Q_UNUSED(win32Error);
}

void MainWindow::handleR0PermissionRequired(const unsigned long win32Error)
{
    if (!m_r0UnavailablePromptArmed
        || m_r0PermissionPromptShowing
        || hasAdminPrivilege()
        || m_suppressR0PromptsForSession
        || m_currentAppearanceSettings.suppressR0FeaturePrompts)
    {
        return;
    }
    m_r0PermissionPromptShowing = true;
    (void)ks::ui::requestAdministratorRestartForFeature(this, QStringLiteral("当前内核功能"));
    m_r0PermissionPromptShowing = false;
    Q_UNUSED(win32Error);
}

void MainWindow::enableR0ForUserRequest()
{
    // 作用：
    // - 输入：无；
    // - 处理：R0 启动已改为后台执行，这里只负责派发；成功后的状态同步、失败提示、
    //         按钮可用性都由 startR0DriverService 内部回投的回调统一处理；
    // - 返回：无返回值。
    if (!startR0DriverService())
    {
        refreshPrivilegeStatusButtons();
    }
}

void MainWindow::refreshPrivilegeStatusButtons()
{
    // 读取当前权限状态。
    const bool adminEnabled = hasAdminPrivilege();
    const bool debugEnabled = hasDebugPrivilege();
    const bool systemEnabled = hasSystemPrivilege();
    const bool uiAccessEnabled = hasUiAccessPrivilege();
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordProcessUiAccessPropertyName, uiAccessEnabled);
    }

    // R0 状态位：
    // - R0：检查 KswordARK 驱动服务是否处于运行态。
    const bool r0Enabled = m_r0DriverServiceRunning;

    // 按状态更新按钮样式与提示文本。
    applyPrivilegeButtonStyle(m_uiAccessStatusButton, uiAccessEnabled);
    applyPrivilegeButtonStyle(m_adminStatusButton, adminEnabled);
    applyPrivilegeButtonStyle(m_debugStatusButton, debugEnabled);
    applyPrivilegeButtonStyle(m_systemStatusButton, systemEnabled);
    if (m_r0StatusButton != nullptr)
    {
        m_r0StatusButton->setStyleSheet(buildR0ButtonStyle(r0Enabled));
    }

    if (m_uiAccessStatusButton != nullptr)
    {
        if (uiAccessEnabled)
        {
            m_uiAccessStatusButton->setToolTip("UIAccess 已启用");
        }
        else
        {
            m_uiAccessStatusButton->setToolTip("UIAccess：点击重新启动并尝试启用跨权限界面访问");
        }
    }
    if (m_adminStatusButton != nullptr)
    {
        m_adminStatusButton->setToolTip(adminEnabled ? "管理员权限已启用" : "点击提权到管理员（重启当前程序）");
    }
    if (m_debugStatusButton != nullptr)
    {
        m_debugStatusButton->setToolTip(debugEnabled ? "SeDebugPrivilege 已启用" : "点击启用 SeDebugPrivilege");
    }
    if (m_systemStatusButton != nullptr)
    {
        m_systemStatusButton->setToolTip(systemEnabled ? "当前运行身份：LocalSystem" : "当前运行身份：非 LocalSystem");
    }
    if (m_r0StatusButton != nullptr)
    {
        m_r0StatusButton->setToolTip(r0Enabled
            ? "R0 已启用：KswordARK 驱动服务正在运行（点击卸载）"
            : "R0 未启用：点击创建并启动 KswordARK 驱动服务");
    }

    // 仅在状态变化时写日志，避免定时器造成日志刷屏。
    static bool hasPreviousState = false;
    static bool previousUiAccessToken = false;
    static bool previousAdmin = false;
    static bool previousDebug = false;
    static bool previousSystem = false;
    static bool previousR0 = false;
    if (!hasPreviousState ||
        previousAdmin != adminEnabled ||
        previousUiAccessToken != uiAccessEnabled ||
        previousDebug != debugEnabled ||
        previousSystem != systemEnabled ||
        previousR0 != r0Enabled)
    {
        hasPreviousState = true;
        previousUiAccessToken = uiAccessEnabled;
        previousAdmin = adminEnabled;
        previousDebug = debugEnabled;
        previousSystem = systemEnabled;
        previousR0 = r0Enabled;

        kLogEvent logEvent;
        info << logEvent
            << "[MainWindow] 权限状态刷新, uiAccessToken=" << (uiAccessEnabled ? "true" : "false")
            << ", admin=" << (adminEnabled ? "true" : "false")
            << ", debug=" << (debugEnabled ? "true" : "false")
            << ", system=" << (systemEnabled ? "true" : "false")
            << ", r0=" << (r0Enabled ? "true" : "false")
            << eol;
    }
}

void MainWindow::applyPrivilegeButtonStyle(QPushButton* button, const bool activeState)
{
    if (button == nullptr)
    {
        return;
    }
    button->setStyleSheet(buildPrivilegeButtonStyle(activeState));
}

bool MainWindow::hasUiAccessPrivilege() const
{
    // tokenHandle 用途：查询当前进程令牌中的 TokenUIAccess 标志。
    ScopedHandle tokenHandle;
    HANDLE rawTokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &rawTokenHandle) == FALSE)
    {
        if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
        {
            appInstance->setProperty(kKswordProcessUiAccessPropertyName, false);
        }
        return false;
    }
    tokenHandle.reset(rawTokenHandle);

    DWORD returnLength = 0;
    DWORD uiAccessValue = 0;
    const BOOL queryOk = ::GetTokenInformation(
        tokenHandle.get(),
        TokenUIAccess,
        &uiAccessValue,
        sizeof(uiAccessValue),
        &returnLength);
    const bool uiAccessEnabled = queryOk != FALSE && uiAccessValue != 0;
    if (QApplication* appInstance = qobject_cast<QApplication*>(QCoreApplication::instance()))
    {
        appInstance->setProperty(kKswordProcessUiAccessPropertyName, uiAccessEnabled);
    }
    return uiAccessEnabled;
}

bool MainWindow::launchSelfWithSystemUiAccessToken(QString* detailTextOut)
{
    if (detailTextOut != nullptr)
    {
        detailTextOut->clear();
    }

    // detailLineList 用途：记录每个关键步骤，成功和失败都能回显给用户。
    QStringList detailLineList;
    auto failWithDetail = [&](const QString& failureText) {
        detailLineList << failureText;
        if (detailTextOut != nullptr)
        {
            *detailTextOut = detailLineList.join(QStringLiteral("\n"));
        }
        return false;
    };

    if (!hasAdminPrivilege())
    {
        detailLineList << QStringLiteral("当前进程不是提升管理员，无法可靠打开 SYSTEM 进程令牌。");
        if (detailTextOut != nullptr)
        {
            *detailTextOut = detailLineList.join(QStringLiteral("\n"));
        }
        return false;
    }

    // 先尽量启用调用链所需权限；部分权限普通管理员令牌里可能没有，记录但不中断。
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_DEBUG_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_ASSIGNPRIMARYTOKEN_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_INCREASE_QUOTA_NAME);
    detailLineList << tryEnableCurrentProcessPrivilegeForUiAccess(SE_TCB_NAME);

    DWORD currentSessionId = 0;
    if (::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId) == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("ProcessIdToSessionId(GetCurrentProcessId)"), errorCode));
    }
    detailLineList << QStringLiteral("当前进程 SessionId：%1").arg(currentSessionId);

    DWORD sourceProcessId = 0;
    DWORD sourceSessionId = 0;
    QString sourceProcessName;
    QString findDetailText;
    if (!findSystemProcessTokenCandidate(
        currentSessionId,
        &sourceProcessId,
        &sourceProcessName,
        &sourceSessionId,
        &findDetailText))
    {
        return failWithDetail(findDetailText);
    }
    detailLineList << QStringLiteral("选定 SYSTEM 令牌源：%1，PID=%2，SessionId=%3")
        .arg(sourceProcessName)
        .arg(sourceProcessId)
        .arg(sourceSessionId);

    // sourceProcessHandle 用途：打开 SYSTEM 进程，后续只读取并复制其令牌。
    ScopedHandle sourceProcessHandle(::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        sourceProcessId));
    if (!sourceProcessHandle.isValid())
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("OpenProcess(%1)").arg(sourceProcessName), errorCode));
    }

    // sourceTokenHandle 用途：承接 SYSTEM 进程原始令牌，保持最小权限以降低 OpenProcessToken 失败概率。
    HANDLE rawSourceTokenHandle = nullptr;
    const DWORD sourceTokenAccess = TOKEN_DUPLICATE | TOKEN_QUERY;
    if (::OpenProcessToken(sourceProcessHandle.get(), sourceTokenAccess, &rawSourceTokenHandle) == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("OpenProcessToken(%1)").arg(sourceProcessName), errorCode));
    }
    ScopedHandle sourceTokenHandle(rawSourceTokenHandle);

    DWORD tokenUserError = ERROR_SUCCESS;
    if (!tokenBelongsToLocalSystem(sourceTokenHandle.get(), &tokenUserError))
    {
        return failWithDetail(QStringLiteral("令牌源不是 LocalSystem，或无法验证令牌用户：%1，%2")
            .arg(tokenUserError)
            .arg(formatWin32ErrorText(tokenUserError)));
    }

    DWORD sourceTokenSessionId = 0;
    DWORD sourceTokenSessionError = ERROR_SUCCESS;
    if (queryTokenSessionId(sourceTokenHandle.get(), &sourceTokenSessionId, &sourceTokenSessionError))
    {
        detailLineList << QStringLiteral("源令牌 SessionId：%1").arg(sourceTokenSessionId);
    }
    else
    {
        detailLineList << QStringLiteral("源令牌 SessionId 查询失败：%1，%2")
            .arg(sourceTokenSessionError)
            .arg(formatWin32ErrorText(sourceTokenSessionError));
    }

    SECURITY_ATTRIBUTES securityAttributes{};
    securityAttributes.nLength = sizeof(securityAttributes);

    // systemImpersonationTokenHandle 用途：
    // - 把 SYSTEM 源令牌复制成模拟令牌；
    // - 后续当前线程临时进入 SYSTEM 上下文，提高 SetTokenInformation/CreateProcessAsUserW 成功率。
    HANDLE rawSystemImpersonationTokenHandle = nullptr;
    if (::DuplicateTokenEx(
        sourceTokenHandle.get(),
        MAXIMUM_ALLOWED,
        &securityAttributes,
        SecurityImpersonation,
        TokenImpersonation,
        &rawSystemImpersonationTokenHandle) == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(TokenImpersonation)"), errorCode));
    }
    ScopedHandle systemImpersonationTokenHandle(rawSystemImpersonationTokenHandle);

    ScopedThreadImpersonation systemImpersonation;
    DWORD impersonationError = ERROR_SUCCESS;
    if (!systemImpersonation.impersonate(systemImpersonationTokenHandle.get(), &impersonationError))
    {
        return failWithDetail(formatWin32StepFailure(QStringLiteral("ImpersonateLoggedOnUser(SYSTEM)"), impersonationError));
    }
    detailLineList << QStringLiteral("ImpersonateLoggedOnUser：当前线程已临时模拟 SYSTEM。");

    for (const wchar_t* const privilegeName : { SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME })
    {
        DWORD enableError = ERROR_SUCCESS;
        const bool enableOk = enableTokenPrivilege(systemImpersonationTokenHandle.get(), privilegeName, &enableError);
        detailLineList << QStringLiteral("SYSTEM 模拟令牌 %1：%2")
            .arg(privilegeNameToDisplayText(privilegeName))
            .arg(enableOk
                ? QStringLiteral("已启用")
                : QStringLiteral("未启用（%1，%2）").arg(enableError).arg(formatWin32ErrorText(enableError)));
    }

    // duplicatedTokenHandle 用途：复制得到的主令牌，后续会在它上面设置 SessionId 和 TokenUIAccess。
    HANDLE rawDuplicatedTokenHandle = nullptr;
    if (::DuplicateTokenEx(
        sourceTokenHandle.get(),
        MAXIMUM_ALLOWED,
        &securityAttributes,
        SecurityImpersonation,
        TokenPrimary,
        &rawDuplicatedTokenHandle) == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("DuplicateTokenEx(TokenPrimary)"), errorCode));
    }
    ScopedHandle duplicatedTokenHandle(rawDuplicatedTokenHandle);
    detailLineList << QStringLiteral("DuplicateTokenEx：已获得 SYSTEM 主令牌。");

    // 为复制令牌启用常见权限；失败不直接中断，因为令牌可能仍可用于创建进程。
    for (const wchar_t* const privilegeName : { SE_ASSIGNPRIMARYTOKEN_NAME, SE_INCREASE_QUOTA_NAME, SE_TCB_NAME })
    {
        DWORD enableError = ERROR_SUCCESS;
        const bool enableOk = enableTokenPrivilege(duplicatedTokenHandle.get(), privilegeName, &enableError);
        detailLineList << QStringLiteral("复制令牌 %1：%2")
            .arg(privilegeNameToDisplayText(privilegeName))
            .arg(enableOk
                ? QStringLiteral("已启用")
                : QStringLiteral("未启用（%1，%2）").arg(enableError).arg(formatWin32ErrorText(enableError)));
    }

    if (sourceSessionId != currentSessionId)
    {
        // TokenSessionId 用途：尽量把 SYSTEM 令牌放回当前交互 Session，避免新实例启动到不可见会话。
        DWORD sessionIdForToken = currentSessionId;
        if (::SetTokenInformation(
            duplicatedTokenHandle.get(),
            TokenSessionId,
            &sessionIdForToken,
            sizeof(sessionIdForToken)) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            return failWithDetail(formatWin32StepFailure(QStringLiteral("SetTokenInformation(TokenSessionId)"), errorCode));
        }
        else
        {
            detailLineList << QStringLiteral("SetTokenInformation(TokenSessionId)：已设置为当前 Session %1。")
                .arg(currentSessionId);
        }
    }

    // uiAccessValue 用途：按用户指定方案直接对复制后的 SYSTEM 主令牌打开 TokenUIAccess 标志。
    DWORD uiAccessValue = 1;
    if (::SetTokenInformation(
        duplicatedTokenHandle.get(),
        TokenUIAccess,
        &uiAccessValue,
        sizeof(uiAccessValue)) == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("SetTokenInformation(TokenUIAccess)"), errorCode));
    }
    detailLineList << QStringLiteral("SetTokenInformation(TokenUIAccess)：已请求启用。");

    DWORD verifiedUiAccessValue = 0;
    DWORD verifiedLength = 0;
    if (::GetTokenInformation(
        duplicatedTokenHandle.get(),
        TokenUIAccess,
        &verifiedUiAccessValue,
        sizeof(verifiedUiAccessValue),
        &verifiedLength) == FALSE ||
        verifiedUiAccessValue == 0)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(QStringLiteral("TokenUIAccess 设置后校验失败：%1，%2")
            .arg(errorCode)
            .arg(formatWin32ErrorText(errorCode)));
    }
    detailLineList << QStringLiteral("TokenUIAccess 校验：复制令牌已带 UIAccess 位。");

    const std::wstring selfPath = ks::process::GetCurrentProcessPath();
    if (selfPath.empty())
    {
        return failWithDetail(QStringLiteral("无法获取当前程序路径。"));
    }

    QString commandLineText = quoteWin32CommandLineArgument(selfPath);
    commandLineText += QLatin1Char(' ');
    commandLineText += QString::fromWCharArray(kKswordPrivilegeRestartArgument);
    std::wstring commandLineWide = commandLineText.toStdWString();
    std::wstring applicationPathWide = selfPath;

    // startupInfo 用途：指定交互桌面，保证新进程窗口出现在默认桌面。
    STARTUPINFOW startupInfo{};
    startupInfo.cb = sizeof(startupInfo);
    wchar_t desktopName[] = L"winsta0\\default";
    startupInfo.lpDesktop = desktopName;
    PROCESS_INFORMATION processInformation{};
    const DWORD creationFlags = CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT;
    const BOOL createOk = ::CreateProcessAsUserW(
        duplicatedTokenHandle.get(),
        applicationPathWide.c_str(),
        commandLineWide.data(),
        nullptr,
        nullptr,
        FALSE,
        creationFlags,
        nullptr,
        nullptr,
        &startupInfo,
        &processInformation);
    if (createOk == FALSE)
    {
        const DWORD errorCode = ::GetLastError();
        return failWithDetail(formatWin32StepFailure(QStringLiteral("CreateProcessAsUserW"), errorCode));
    }

    ScopedHandle newProcessHandle(processInformation.hProcess);
    ScopedHandle newThreadHandle(processInformation.hThread);
    detailLineList << QStringLiteral("CreateProcessAsUserW：成功启动新实例，PID=%1。")
        .arg(processInformation.dwProcessId);

    // 显式撤销模拟，保证后续 UI 提示和 Qt 退出流程回到当前进程原身份。
    systemImpersonation.reset();
    detailLineList << QStringLiteral("RevertToSelf：已撤销当前线程 SYSTEM 模拟。");

    if (detailTextOut != nullptr)
    {
        *detailTextOut = detailLineList.join(QStringLiteral("\n"));
    }
    return true;
}

void MainWindow::handleUiAccessButtonClicked()
{
    // 当前实例已经带 UIAccess 时，按钮语义为回到普通用户实例；该路径不依赖任何签名证书。
    if (hasUiAccessPrivilege())
    {
        QString launchDetailText;
        const bool launchOk = launchSelfAsUnelevatedFromExplorer(QCoreApplication::arguments(), &launchDetailText);
        if (!launchOk)
        {
            kLogEvent logEvent;
            err << logEvent
                << "[MainWindow][UIAccess] 从 UIAccess 降级重启普通实例失败: "
                << launchDetailText.toStdString()
                << eol;
            QMessageBox::warning(
                this,
                QStringLiteral("UIAccess"),
                QStringLiteral("普通权限重启失败，当前实例保持运行。\n\n%1").arg(launchDetailText));
            refreshPrivilegeStatusButtons();
            return;
        }

        kLogEvent logEvent;
        info << logEvent
            << "[MainWindow][UIAccess] 当前实例已带 UIAccess，已启动普通权限实例并准备正常退出: "
            << launchDetailText.toStdString()
            << eol;
        close();
        return;
    }

    if (!hasAdminPrivilege())
    {
        QMessageBox::warning(
            this,
            QStringLiteral("UIAccess"),
            QStringLiteral(
                "启用 UIAccess 需要管理员权限。\n\n"
                "程序将先以管理员身份重新启动；重启后请再次点击 UIAccess。"));
        requestAdminElevationRestart();
        return;
    }

    QString launchDetailText;
    const bool launchOk = launchSelfWithSystemUiAccessToken(&launchDetailText);
    if (!launchOk)
    {
        kLogEvent logEvent;
        err << logEvent
            << "[MainWindow][UIAccess] SYSTEM TokenUIAccess fallback 启动失败: "
            << launchDetailText.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("UIAccess 启动失败"),
            launchDetailText);
        refreshPrivilegeStatusButtons();
        return;
    }

    {
        kLogEvent logEvent;
        info << logEvent
            << "[MainWindow][UIAccess] SYSTEM TokenUIAccess fallback 启动成功: "
            << launchDetailText.toStdString()
            << eol;
    }
    // 成功路径不弹框，避免重复打断；详细步骤已经写入日志。
    refreshPrivilegeStatusButtons();
    QApplication::quit();
}

void MainWindow::startR0DriverLogPoller()
{
    if (m_r0DriverLogPollerRunning.exchange(true))
    {
        return;
    }

    try
    {
        m_r0DriverLogPollerThread = std::make_unique<std::thread>([this]()
            {
                runR0DriverLogPollerLoop();
            });
    }
    catch (...)
    {
        m_r0DriverLogPollerRunning.store(false);
        m_r0DriverLogPollerThread.reset();

        kLogEvent& logEvent = sharedR0DriverLogEvent();
        err << logEvent << "[MainWindow][R0Log] 轮询线程创建失败。" << eol;
    }
}

void MainWindow::prepareR0DriverServiceStop()
{
    // 停驱前统一清理入口：
    // 输入：无。
    // 处理：
    // - 先关闭本进程长期持有的日志/回调等待句柄；
    // - 再尽力通知驱动取消待决策回调、停止并清空文件监控运行态；
    // - 这些 IOCTL 失败不阻断 SCM stop，因为服务可能已经在停止或旧驱动不支持对应能力。
    // 返回：无返回值；清理结果只进入日志，真正的停驱结果由后台 SCM 任务回投后再应用。
    stopR0RuntimeConsumersBeforeServiceStop();

    const auto logBestEffortCleanupResult =
        [](const char* operationName, const ksword::ark::IoResult& ioResult)
        {
            kLogEvent cleanupEvent;
            if (ioResult.ok)
            {
                info << cleanupEvent
                    << "[MainWindow][R0] 停驱前清理完成: "
                    << operationName
                    << ", "
                    << ioResult.message
                    << eol;
                return;
            }

            const DWORD win32Error = static_cast<DWORD>(ioResult.win32Error);
            if (win32Error == ERROR_FILE_NOT_FOUND ||
                win32Error == ERROR_PATH_NOT_FOUND ||
                win32Error == ERROR_INVALID_HANDLE ||
                win32Error == ERROR_DEVICE_NOT_CONNECTED ||
                win32Error == ERROR_SERVICE_NOT_ACTIVE)
            {
                dbg << cleanupEvent
                    << "[MainWindow][R0] 停驱前清理跳过: "
                    << operationName
                    << ", error="
                    << win32Error
                    << ", message="
                    << ioResult.message
                    << eol;
                return;
            }

            warn << cleanupEvent
                << "[MainWindow][R0] 停驱前清理失败但继续停驱: "
                << operationName
                << ", error="
                << win32Error
                << ", message="
                << ioResult.message
                << eol;
        };

    const ksword::ark::DriverClient driverClient;
    logBestEffortCleanupResult(
        "cancel-pending-callback-decisions",
        driverClient.cancelAllPendingCallbackDecisions());
    logBestEffortCleanupResult(
        "file-monitor-stop",
        driverClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_STOP));
    logBestEffortCleanupResult(
        "file-monitor-clear",
        driverClient.controlFileMonitor(KSWORD_ARK_FILE_MONITOR_ACTION_CLEAR));
}

void MainWindow::stopR0RuntimeConsumersBeforeServiceStop()
{
    // 手动 R0 卸载前必须先收敛本进程持有的驱动设备句柄：
    // - 日志轮询线程长期打开 \\.\KswordARKLog；
    // - 回调弹窗管理器的 worker 长期持有 overlapped 等待句柄；
    // - 如果这些句柄不先关闭，SCM 停止内核驱动时可能长期卡在 STOP_PENDING。
    // 输入：无。
    // 处理：按关闭窗口路径的资源释放顺序停止 R0 消费者，但不删除全局管理器对象。
    // 返回：无返回值；各子模块 stop 函数均为幂等 best-effort。
    stopR0DriverLogPoller();

    if (CallbackPromptManager* callbackPromptManager = CallbackPromptManager::globalManager())
    {
        callbackPromptManager->stop();
    }
}

void MainWindow::updateBugcheckDiagnosticsEntryVisibility()
{
    const bool shouldShowEntry =
        m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled ||
        m_bugcheckDiagnosticsInstalledForSession ||
        m_bugcheckDiagnosticsEntryRequestedForSession;
    if (m_miscWidget != nullptr)
    {
        // 杂项页使用隐藏而非删除的 Tab，自动安装取消后已构造页面仍能安全析构。
        m_miscWidget->setBugcheckDiagnosticsVisible(shouldShowEntry);
    }
}

void MainWindow::installBugcheckDiagnosticsAfterServiceStart()
{
    if (!m_r0DriverServiceRunning ||
        !m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled)
    {
        return;
    }

    // BGP 解析和预生成可能耗时，自动安装与手动安装都在工作线程等待 R0 IOCTL。
    const QPointer<MainWindow> guardedSelf(this);
    QThreadPool::globalInstance()->start(
        [guardedSelf]()
        {
            const ksword::ark::BugcheckDiagnosticsResult result =
                ksword::ark::DriverClient().configureBugcheckDiagnostics(
                    KSWORD_ARK_BUGCHECK_DIAGNOSTICS_ACTION_INSTALL);
            QCoreApplication* const application = QCoreApplication::instance();
            if (application == nullptr)
            {
                return;
            }

            if (!guardedSelf.isNull())
            {
                QMetaObject::invokeMethod(
                    guardedSelf,
                    [guardedSelf, result]()
                {
                    if (guardedSelf == nullptr)
                    {
                        return;
                    }

                    kLogEvent logEvent;
                    if (result.io.ok &&
                        result.response.status ==
                            KSWORD_ARK_BUGCHECK_DIAGNOSTICS_STATUS_OK)
                    {
                        guardedSelf->m_bugcheckDiagnosticsInstalledForSession = true;
                        guardedSelf->updateBugcheckDiagnosticsEntryVisibility();
                        queueBugcheckVerdictResourceUpload();
                        info << logEvent
                            << "[MainWindow][R0] 已按配置安装蓝屏诊断, callbackMask=0x"
                            << std::hex
                            << result.response.callbackMask
                            << std::dec
                            << eol;
                    }
                    else
                    {
                        warn << logEvent
                            << "[MainWindow][R0] 自动安装蓝屏诊断失败, win32="
                            << result.io.win32Error
                            << ", protocol="
                            << result.response.status
                            << ", ntstatus=0x"
                            << std::hex
                            << static_cast<unsigned long>(result.response.lastStatus)
                            << std::dec
                            << eol;
                    }
                },
                Qt::QueuedConnection);
            }
        });
}

void MainWindow::startR0RuntimeConsumersAfterServiceStart()
{
    // R0 启动或确认运行后恢复本进程运行时消费者：
    // - 日志轮询线程负责把 R0 日志转发到应用日志；
    // - 回调弹窗管理器负责长期等待 R0 callback decision 事件。
    // 输入：无。
    // 处理：复用各模块幂等 start 语义，避免重复启动线程。
    // 返回：无返回值；启动失败只写日志，不影响主流程状态查询。
    if (!m_r0DriverServiceRunning)
    {
        // 启动期不能为日志轮询/回调等待等后台消费者反复探测一个未启用的设备。
        // 用户真正触发 R0 功能时，ArkDriverClient 才会给出明确的启用提示。
        return;
    }

    // 蓝屏诊断资源只能在诊断安装成功后上传，避免默认启动触碰未初始化的 BGP 路径。
    installBugcheckDiagnosticsAfterServiceStart();
    startR0DriverLogPoller();

    if (CallbackPromptManager* callbackPromptManager = CallbackPromptManager::ensureGlobalManager(this))
    {
        callbackPromptManager->setHostWindow(this);
        callbackPromptManager->start();
    }

    refreshR0DynDataAfterServiceStart();
}

void MainWindow::refreshR0DynDataAfterServiceStart()
{
    // R0 服务启动后立即把本地 PDB profile pack 下发到驱动：
    // - 复用 KernelDock 现有的 profile 匹配、v3 typed item 解析和 APPLY_DYN_PROFILE_EX；
    // - 不再为了后台刷新强行创建 KernelDock UI，避免启动期拉起重页面；
    // - KernelDock 尚未初始化时只记录待刷新标记，首次打开内核页后再补跑；
    // - 失败只进入日志/KernelDock 状态，具体 R0 功能仍有驱动侧运行时偏移兜底。
    QTimer::singleShot(0, this, [this]() {
        kLogEvent logEvent;
        if (m_dockKernel == nullptr || m_kernelWidget == nullptr)
        {
            m_pendingR0DynDataRefresh = true;
            info << logEvent
                << "[MainWindow][R0] DynData 自动刷新已延后：KernelDock UI 尚未初始化。"
                << eol;
            return;
        }
        if (!m_dockKernel->property("ks_lazy_initialized").toBool() ||
            m_dockKernel->property("ks_lazy_initializing").toBool())
        {
            m_pendingR0DynDataRefresh = true;
            info << logEvent
                << "[MainWindow][R0] DynData 自动刷新已延后：KernelDock 正在惰性初始化。"
                << eol;
            return;
        }

        info << logEvent
            << "[MainWindow][R0] 驱动已装载，开始自动刷新 DynData profile。"
            << eol;
        m_kernelWidget->requestDynDataRefresh();
        });
}

void MainWindow::stopR0DriverLogPoller()
{
    m_r0DriverLogPollerRunning.store(false);
    if (m_r0DriverLogPollerThread != nullptr && m_r0DriverLogPollerThread->joinable())
    {
        // The worker owns a synchronous log-device ReadFile; cancel it before joining.
        (void)::CancelSynchronousIo(m_r0DriverLogPollerThread->native_handle());
        m_r0DriverLogPollerThread->join();
    }
    m_r0DriverLogPollerThread.reset();
}

void MainWindow::runR0DriverLogPollerLoop()
{
    ksword::ark::DriverHandle logDeviceHandle;
    std::string pendingPayloadText;
    pendingPayloadText.reserve(2048);
    bool waitingDeviceLogged = false;
    static const std::string endMarkerText = KSWORD_ARK_LOG_END_MARKER;
    const ksword::ark::DriverClient driverClient;

    kLogEvent& logEvent = sharedR0DriverLogEvent();
    info << logEvent << "[MainWindow][R0Log] 轮询线程已启动。" << eol;

    while (m_r0DriverLogPollerRunning.load())
    {
        if (!logDeviceHandle.isValid())
        {
            // 通过 ArkDriverClient 统一打开 KswordARK 日志设备，避免 MainWindow
            // 直接散落 CreateFileW(\\.\KswordARKLog) 访问；返回值仍是 RAII 句柄。
            logDeviceHandle = driverClient.open(GENERIC_READ);

            if (!logDeviceHandle.isValid())
            {
                if (!waitingDeviceLogged)
                {
                    waitingDeviceLogged = true;
                    dbg << logEvent << "[MainWindow][R0Log] 等待日志设备上线：" << "path=\\\\.\\KswordARKLog" << eol;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogConnectRetrySleepMs));
                continue;
            }

            waitingDeviceLogged = false;
            info << logEvent << "[MainWindow][R0Log] 已连接驱动日志设备。" << eol;
        }

        char readBuffer[1024] = { 0 };
        DWORD bytesRead = 0;
        if (::ReadFile(logDeviceHandle.native(), readBuffer, static_cast<DWORD>(sizeof(readBuffer)), &bytesRead, nullptr) != FALSE)
        {
            if (bytesRead == 0U)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogIdlePollSleepMs));
                continue;
            }

            pendingPayloadText.append(readBuffer, bytesRead);
            while (true)
            {
                const std::size_t markerPosition = pendingPayloadText.find(endMarkerText);
                if (markerPosition == std::string::npos)
                {
                    break;
                }

                const std::string recordText = pendingPayloadText.substr(0, markerPosition);
                pendingPayloadText.erase(0, markerPosition + endMarkerText.size());
                dispatchR0DriverLogRecord(recordText);
            }
            continue;
        }

        const DWORD readError = ::GetLastError();
        if (readError == ERROR_NO_MORE_ITEMS ||
            readError == ERROR_NO_DATA ||
            readError == ERROR_HANDLE_EOF)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogIdlePollSleepMs));
            continue;
        }

        warn << logEvent
            << "[MainWindow][R0Log] 读取日志设备失败, error="
            << readError
            << ", 将重新连接。"
            << eol;
        logDeviceHandle.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(kR0LogConnectRetrySleepMs));
    }

    logDeviceHandle.reset();

    info << logEvent << "[MainWindow][R0Log] 轮询线程已退出。" << eol;
}

void MainWindow::dispatchR0DriverLogRecord(const std::string& logRecordText)
{
    if (logRecordText.empty())
    {
        return;
    }

    std::string payloadText = logRecordText;
    LogStream* outputStream = &info;
    std::size_t prefixLength = 0U;

    if (startsWithLiteral(payloadText, kR0LogPrefixDebug))
    {
        outputStream = &dbg;
        prefixLength = std::strlen(kR0LogPrefixDebug);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixInfo))
    {
        outputStream = &info;
        prefixLength = std::strlen(kR0LogPrefixInfo);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixWarn))
    {
        outputStream = &warn;
        prefixLength = std::strlen(kR0LogPrefixWarn);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixError))
    {
        outputStream = &err;
        prefixLength = std::strlen(kR0LogPrefixError);
    }
    else if (startsWithLiteral(payloadText, kR0LogPrefixFatal))
    {
        outputStream = &fatal;
        prefixLength = std::strlen(kR0LogPrefixFatal);
    }

    if (prefixLength > 0U && payloadText.size() >= prefixLength)
    {
        payloadText.erase(0, prefixLength);
    }

    kLogEvent& logEvent = sharedR0DriverLogEvent();
    (*outputStream) << logEvent << "[R0] " << payloadText << eol;
}

void MainWindow::showR0FatalError(
    const QString& stageText,
    const unsigned long errorCode,
    const QString& detailText)
{
    const DWORD win32ErrorCode = static_cast<DWORD>(errorCode);
    QString messageText = stageText.trimmed();
    if (win32ErrorCode != ERROR_SUCCESS)
    {
        messageText += QStringLiteral("\n\n错误码：%1").arg(win32ErrorCode);
        messageText += QStringLiteral("\n系统信息：%1").arg(formatWin32ErrorText(win32ErrorCode));
    }
    if (!detailText.trimmed().isEmpty())
    {
        messageText += QStringLiteral("\n\n详细信息：\n%1").arg(detailText.trimmed());
    }

    kLogEvent logEvent;
    fatal << logEvent
        << "[MainWindow][R0][Fatal] stage=" << stageText.toStdString()
        << ", error=" << win32ErrorCode
        << ", detail=" << detailText.toStdString()
        << eol;

    QMessageBox::critical(this, QStringLiteral("R0 操作失败"), messageText);
}

bool MainWindow::isR0DriverSignatureFailure(const unsigned long errorCode) const
{
    return errorCode == ERROR_INVALID_IMAGE_HASH ||
        errorCode == ERROR_DRIVER_BLOCKED;
}

bool MainWindow::queryR0DriverServiceRunning(bool& runningOut, const bool fatalOnError)
{
    runningOut = false;

    ScopedServiceHandle scmHandle(::OpenSCManagerW(nullptr, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT));
    if (!scmHandle.isValid())
    {
        const DWORD scmError = ::GetLastError();
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), scmError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：无法连接服务控制管理器。"),
                scmError);
        }
        return false;
    }

    ScopedServiceHandle serviceHandle(::OpenServiceW(
        scmHandle.get(),
        kR0DriverServiceName,
        SERVICE_QUERY_STATUS));
    if (!serviceHandle.isValid())
    {
        const DWORD openError = ::GetLastError();
        if (openError == ERROR_SERVICE_DOES_NOT_EXIST)
        {
            runningOut = false;
            return true;
        }
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), openError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：无法打开服务。"),
                openError,
                QStringLiteral("目标服务名：%1").arg(QString::fromWCharArray(kR0DriverServiceName)));
        }
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    DWORD queryError = ERROR_SUCCESS;
    if (!queryServiceStatus(serviceHandle.get(), status, queryError))
    {
        if (fatalOnError)
        {
            if (ks::ui::promptForPrivilegeFailure(this, QStringLiteral("查询 R0 服务状态"), queryError))
            {
                return false;
            }
            showR0FatalError(
                QStringLiteral("查询 KswordARK 驱动服务状态失败：读取服务状态失败。"),
                queryError);
        }
        return false;
    }

    runningOut = isRunningLikeServiceState(status.dwCurrentState);
    return true;
}

bool MainWindow::stopR0DriverService(const bool suppressErrorDialog)
{
    // 作用：
    // - 入参 suppressErrorDialog：true 表示静默停驱，失败只写日志不弹错误框；
    // - 处理：UI 线程只做“收敛本进程持有的驱动句柄 + 派发”，SCM 停止/等待/删除整段交给线程池；
    //         SCM 卡在 STOP_PENDING 时最长要等 30 秒，放在 UI 线程会让界面连重绘都停掉；
    // - 返回：true 表示停驱请求已成功派发；真正的停驱结论由回投到 UI 线程的回调应用。
    if (g_r0ServiceOperationInFlight.exchange(true))
    {
        // 已有一次 R0 启停在后台执行，重复请求直接丢弃，避免并发操作同一个 SCM 服务。
        return false;
    }

    // 停驱前的句柄收敛必须留在 UI 线程：它要停掉日志轮询线程与回调弹窗管理器，
    // 这些对象的生命周期由主窗口持有，不能在工作线程上碰。
    prepareR0DriverServiceStop();
    if (m_r0StatusButton != nullptr)
    {
        m_r0StatusButton->setEnabled(false);
    }

    // guardedSelf 用途：后台任务可能晚于主窗口销毁，回投前必须验证生命周期。
    const QPointer<MainWindow> guardedSelf(this);
    dispatchR0ServiceStopToWorker(
        [guardedSelf, suppressErrorDialog](const R0ServiceOperationOutcome& operationOutcome)
        {
            g_r0ServiceOperationInFlight.store(false);
            if (guardedSelf == nullptr)
            {
                return;
            }
            if (guardedSelf->m_r0StatusButton != nullptr)
            {
                guardedSelf->m_r0StatusButton->setEnabled(true);
            }

            if (operationOutcome.succeeded)
            {
                guardedSelf->m_r0DriverServiceRunning = false;
                // 本次安装只绑定当前内核驱动映像，服务卸载成功后入口随之恢复配置态可见性。
                guardedSelf->m_bugcheckDiagnosticsInstalledForSession = false;
                guardedSelf->m_bugcheckDiagnosticsEntryRequestedForSession = false;
                guardedSelf->updateBugcheckDiagnosticsEntryVisibility();
                kLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 已停止并删除 KswordARK 驱动服务。" << eol;
                guardedSelf->refreshPrivilegeStatusButtons();
                return;
            }

            if (suppressErrorDialog)
            {
                kLogEvent logEvent;
                err << logEvent
                    << "[MainWindow][R0][AutoStop] stage="
                    << operationOutcome.stageText.toStdString()
                    << ", error="
                    << operationOutcome.errorCode
                    << ", detail="
                    << operationOutcome.detailText.toStdString()
                    << eol;
            }
            else if (!ks::ui::promptForPrivilegeFailure(
                guardedSelf.data(),
                QStringLiteral("卸载 R0"),
                operationOutcome.errorCode))
            {
                guardedSelf->showR0FatalError(
                    operationOutcome.stageText,
                    operationOutcome.errorCode,
                    operationOutcome.detailText);
            }
            guardedSelf->refreshPrivilegeStatusButtons();
        });
    return true;
}

bool MainWindow::showUnsignedDriverFailureDialog(
    const unsigned long errorCode,
    const QString& operationText)
{
    const DWORD win32ErrorCode = static_cast<DWORD>(errorCode);
    const bool darkModeEnabled = KswordTheme::IsDarkModeEnabled();
    const QString adaptiveTextColor = KswordTheme::OnAccentHex();

    QDialog decisionDialog(this);
    decisionDialog.setModal(true);
    decisionDialog.setWindowTitle(QStringLiteral("KswordARK 驱动签名校验失败"));
    decisionDialog.setObjectName(QStringLiteral("ksUnsignedDriverFailureDialog"));
    decisionDialog.setMinimumWidth(680);
    decisionDialog.setStyleSheet(KswordTheme::OpaqueDialogStyle(decisionDialog.objectName()));

    QVBoxLayout* rootLayout = new QVBoxLayout(&decisionDialog);
    rootLayout->setContentsMargins(16, 16, 16, 16);
    rootLayout->setSpacing(10);

    QLabel* failureReasonLabel = new QLabel(
        QStringLiteral(
            "驱动加载失败，失败原因是系统拒绝了未通过数字签名校验的内核驱动。\n\n"
            "操作阶段：%1\n错误码：%2\n系统信息：%3")
        .arg(operationText)
        .arg(win32ErrorCode)
        .arg(formatWin32ErrorText(win32ErrorCode)),
        &decisionDialog);
    failureReasonLabel->setWordWrap(true);
    failureReasonLabel->setTextInteractionFlags(Qt::TextSelectableByMouse);
    rootLayout->addWidget(failureReasonLabel);

    QLabel* signatureMechanismLabel = new QLabel(
        QStringLiteral(
            "Windows 已阻止当前驱动。请改用可信签名的 KswordARK.sys；"
            "开发或测试环境也可以选择启用测试模式。"),
        &decisionDialog);
    signatureMechanismLabel->setWordWrap(true);
    rootLayout->addWidget(signatureMechanismLabel);

    QLabel* actionTitleLabel = new QLabel(QStringLiteral("我可以做什么？"), &decisionDialog);
    actionTitleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;"));
    rootLayout->addWidget(actionTitleLabel);

    QLabel* testModeDescriptionLabel = new QLabel(
        QStringLiteral(
            "测试模式仅用于开发或测试，会降低系统对内核驱动的保护，"
            "并可能与反作弊软件冲突。开启或关闭后都需要重启电脑。"),
        &decisionDialog);
    testModeDescriptionLabel->setWordWrap(true);
    rootLayout->addWidget(testModeDescriptionLabel);

    QPushButton* continueR3Button = new QPushButton(QStringLiteral("退出并继续使用R3功能"), &decisionDialog);
    continueR3Button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    continueR3Button->setMinimumHeight(42);
    continueR3Button->setStyleSheet(QStringLiteral(
        "QPushButton{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %1;"
        "  border-radius:4px;"
        "  font-weight:700;"
        "}"
        "QPushButton:hover{"
        "  background:%4;"
        "}"
        "QPushButton:pressed{"
        "  background:%3;"
        "}")
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(adaptiveTextColor)
        .arg(KswordTheme::PrimaryBluePressedHex)
        .arg(KswordTheme::PrimaryBlueSolidHoverHex()));
    rootLayout->addWidget(continueR3Button);

    QPushButton* enableTestModeButton = new QPushButton(QStringLiteral("开启测试模式"), &decisionDialog);
    enableTestModeButton->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    enableTestModeButton->setMinimumHeight(42);
    enableTestModeButton->setStyleSheet(QStringLiteral(
        "QPushButton{"
        "  background:%1;"
        "  color:%2;"
        "  border:1px solid %2;"
        "  border-radius:4px;"
        "  font-weight:700;"
        "}"
        "QPushButton:hover{"
        "  background:%3;"
        "}"
        "QPushButton:pressed{"
        "  background:%4;"
        "}")
        .arg(KswordTheme::SurfaceHex())
        .arg(KswordTheme::PrimaryBlueHex)
        .arg(KswordTheme::PrimaryBlueSubtleHex())
        .arg(KswordTheme::ThemeColorName(KswordTheme::PrimaryBlueSurfacePressedColor())));
    rootLayout->addWidget(enableTestModeButton);

    bool enableTestMode = false;
    connect(continueR3Button, &QPushButton::clicked, &decisionDialog, [&decisionDialog]() {
        decisionDialog.done(QDialog::Rejected);
    });
    connect(enableTestModeButton, &QPushButton::clicked, &decisionDialog, [&decisionDialog, &enableTestMode]() {
        enableTestMode = true;
        decisionDialog.done(QDialog::Accepted);
    });

    decisionDialog.exec();
    if (!enableTestMode)
    {
        return true;
    }
    return enableWindowsTestModeAndPromptReboot();
}

bool MainWindow::enableWindowsTestModeAndPromptReboot()
{
    if (!hasAdminPrivilege())
    {
        (void)ks::ui::requestAdministratorRestartForFeature(
            this,
            QStringLiteral("开启 Windows 测试模式"));
        return false;
    }

    QProcess* bcdeditProcess = new QProcess(this);
    QTimer* timeoutTimer = new QTimer(bcdeditProcess);
    timeoutTimer->setSingleShot(true);
    timeoutTimer->setInterval(15000);
    connect(timeoutTimer, &QTimer::timeout, this, [bcdeditProcess]()
    {
        if (bcdeditProcess->state() != QProcess::NotRunning)
        {
            bcdeditProcess->setProperty("ksword_bcdedit_timed_out", true);
            bcdeditProcess->kill();
        }
    });
    connect(bcdeditProcess, &QProcess::errorOccurred, this, [this, bcdeditProcess](QProcess::ProcessError error)
    {
        if (error != QProcess::FailedToStart || bcdeditProcess->property("ksword_bcdedit_handled").toBool()) return;
        bcdeditProcess->setProperty("ksword_bcdedit_handled", true);
        showR0FatalError(
            QStringLiteral("开启测试模式失败：无法启动 bcdedit。"),
            ERROR_GEN_FAILURE,
            bcdeditProcess->errorString());
        bcdeditProcess->deleteLater();
    });
    connect(bcdeditProcess, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this, bcdeditProcess, timeoutTimer](int exitCode, QProcess::ExitStatus exitStatus)
        {
            if (bcdeditProcess->property("ksword_bcdedit_handled").toBool()) return;
            bcdeditProcess->setProperty("ksword_bcdedit_handled", true);
            timeoutTimer->stop();
            if (bcdeditProcess->property("ksword_bcdedit_timed_out").toBool())
            {
                showR0FatalError(
                    QStringLiteral("开启测试模式失败：bcdedit 执行超时。"),
                    ERROR_TIMEOUT);
                bcdeditProcess->deleteLater();
                return;
            }

            const QString standardOutput = QString::fromLocal8Bit(bcdeditProcess->readAllStandardOutput()).trimmed();
            const QString standardError = QString::fromLocal8Bit(bcdeditProcess->readAllStandardError()).trimmed();
            if (exitStatus != QProcess::NormalExit || exitCode != 0)
            {
                QString detailText = QStringLiteral("退出码：%1").arg(exitCode);
                if (!standardOutput.isEmpty()) detailText += QStringLiteral("\nstdout：%1").arg(standardOutput);
                if (!standardError.isEmpty()) detailText += QStringLiteral("\nstderr：%1").arg(standardError);
                showR0FatalError(
                    QStringLiteral("开启测试模式失败：bcdedit 返回错误。"),
                    ERROR_GEN_FAILURE,
                    detailText);
                bcdeditProcess->deleteLater();
                return;
            }

            QMessageBox rebootDialog(this);
            rebootDialog.setIcon(QMessageBox::Question);
            rebootDialog.setWindowTitle(QStringLiteral("测试模式已设置"));
            rebootDialog.setText(QStringLiteral("已执行 bcdedit /set testsigning on。"));
            rebootDialog.setInformativeText(QStringLiteral("需要重启电脑后才会生效。你可以选择稍后重启或现在重启。"));
            QPushButton* rebootLaterButton = rebootDialog.addButton(QStringLiteral("稍后重启"), QMessageBox::RejectRole);
            QPushButton* rebootNowButton = rebootDialog.addButton(QStringLiteral("现在重启"), QMessageBox::AcceptRole);
            rebootDialog.exec();

            if (rebootDialog.clickedButton() == rebootNowButton)
            {
                if (!QProcess::startDetached(QStringLiteral("shutdown"), { QStringLiteral("/r"), QStringLiteral("/t"), QStringLiteral("0") }))
                {
                    showR0FatalError(
                        QStringLiteral("立即重启失败：无法调用 shutdown 命令。"),
                        ERROR_GEN_FAILURE);
                }
            }
            else if (rebootDialog.clickedButton() == rebootLaterButton)
            {
                kLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 用户选择稍后重启，测试模式将在下次重启后生效。" << eol;
            }
            bcdeditProcess->deleteLater();
        });
    bcdeditProcess->start(
        QStringLiteral("bcdedit"),
        { QStringLiteral("/set"), QStringLiteral("testsigning"), QStringLiteral("on") });
    timeoutTimer->start();
    return true;
}

bool MainWindow::startR0DriverService()
{
    // 作用：
    // - 输入：无；驱动固定取当前 exe 目录下的 KswordARK.sys；
    // - 处理：UI 线程只做驱动文件校验与派发，SCM 创建/配置/启动/等待运行态整段交给线程池；
    //         启动等待上限是 9 秒，放在 UI 线程会把整个界面冻住；
    // - 返回：true 表示启动请求已成功派发；真正的启动结论由回投到 UI 线程的回调应用。
    if (g_r0ServiceOperationInFlight.exchange(true))
    {
        // 已有一次 R0 启停在后台执行，重复请求直接丢弃，避免并发操作同一个 SCM 服务。
        return false;
    }

    const QString driverPath = QDir(QCoreApplication::applicationDirPath()).absoluteFilePath(QStringLiteral("KswordARK.sys"));
    const QString nativeDriverPath = QDir::toNativeSeparators(driverPath);
    const QFileInfo driverFileInfo(driverPath);
    if (!driverFileInfo.exists() || !driverFileInfo.isFile())
    {
        // 驱动文件缺失是立即可判的失败，不必为它派发后台任务。
        g_r0ServiceOperationInFlight.store(false);
        m_r0DriverServiceRunning = false;
        showR0FatalError(
            QStringLiteral("R0 启动失败：当前程序目录下不存在 KswordARK.sys。"),
            ERROR_FILE_NOT_FOUND,
            QStringLiteral("期望路径：%1").arg(nativeDriverPath));
        return false;
    }

    if (m_r0StatusButton != nullptr)
    {
        m_r0StatusButton->setEnabled(false);
    }

    // guardedSelf 用途：后台任务可能晚于主窗口销毁，回投前必须验证生命周期。
    const QPointer<MainWindow> guardedSelf(this);
    dispatchR0ServiceStartToWorker(
        nativeDriverPath,
        [guardedSelf](const R0ServiceOperationOutcome& operationOutcome)
        {
            g_r0ServiceOperationInFlight.store(false);
            if (guardedSelf == nullptr)
            {
                return;
            }
            if (guardedSelf->m_r0StatusButton != nullptr)
            {
                guardedSelf->m_r0StatusButton->setEnabled(true);
            }

            if (!operationOutcome.succeeded)
            {
                guardedSelf->m_r0DriverServiceRunning = false;
                if (operationOutcome.startServiceCallFailed
                    && guardedSelf->isR0DriverSignatureFailure(operationOutcome.errorCode))
                {
                    kLogEvent logEvent;
                    fatal << logEvent
                        << "[MainWindow][R0][Fatal] 驱动签名校验失败, error="
                        << operationOutcome.errorCode
                        << eol;
                    guardedSelf->showUnsignedDriverFailureDialog(
                        operationOutcome.errorCode,
                        QStringLiteral("启动 KswordARK 驱动服务"));
                }
                else if (!ks::ui::promptForPrivilegeFailure(
                    guardedSelf.data(),
                    QStringLiteral("启用 R0"),
                    operationOutcome.errorCode))
                {
                    guardedSelf->showR0FatalError(
                        operationOutcome.stageText,
                        operationOutcome.errorCode,
                        operationOutcome.detailText);
                }
                guardedSelf->refreshPrivilegeStatusButtons();
                return;
            }

            guardedSelf->m_r0DriverServiceRunning = true;
            guardedSelf->startR0RuntimeConsumersAfterServiceStart();
            emit guardedSelf->r0DriverServiceStarted();
            if (!operationOutcome.alreadyInTargetState)
            {
                kLogEvent logEvent;
                info << logEvent << "[MainWindow][R0] 已创建并启动 KswordARK 驱动服务。" << eol;
            }
            guardedSelf->refreshPrivilegeStatusButtons();
        });
    return true;
}

void MainWindow::handleR0StatusButtonClicked()
{
    // 作用：
    // - 输入：无；
    // - 处理：先做一次轻量的 SCM 状态查询，再按当前状态派发后台启停任务；
    //         UI 线程不再等待 SCM，按钮可用性与最终状态由启停回调统一刷新；
    // - 返回：无返回值。
    bool runningNow = false;
    if (!queryR0DriverServiceRunning(runningNow, true))
    {
        return;
    }
    m_r0DriverServiceRunning = runningNow;

    const bool dispatchOk = runningNow
        ? stopR0DriverService()
        : startR0DriverService();
    if (!dispatchOk)
    {
        refreshPrivilegeStatusButtons();
    }
}

void MainWindow::requestAdminElevationRestart(const bool enableR0AfterRestart)
{
    // 获取当前可执行文件路径，作为 runas 重启目标。
    wchar_t exePathBuffer[MAX_PATH] = {};
    const DWORD pathLength = ::GetModuleFileNameW(nullptr, exePathBuffer, static_cast<DWORD>(std::size(exePathBuffer)));
    if (pathLength == 0 || pathLength >= std::size(exePathBuffer))
    {
        const DWORD lastError = ::GetLastError();
        QMessageBox::warning(this, "Admin", QString("读取当前程序路径失败，错误码: %1").arg(lastError));
        return;
    }

    QString elevationParameters = QString::fromWCharArray(kKswordPrivilegeRestartArgument);
    if (enableR0AfterRestart)
    {
        elevationParameters += QLatin1Char(' ');
        elevationParameters += QString::fromWCharArray(kKswordEnableR0AfterElevationArgument);
    }
    const std::wstring elevationParametersWide = elevationParameters.toStdWString();

    // 使用 ShellExecute("runas") 触发 UAC 提权；R0 请求会带内部参数，让提升后的实例
    // 直接执行用户刚刚确认的启用动作，而不是要求用户重启后再重复点击一次。
    HINSTANCE shellResult = ::ShellExecuteW(
        nullptr,
        L"runas",
        exePathBuffer,
        elevationParametersWide.c_str(),
        nullptr,
        SW_SHOWNORMAL);
    if (reinterpret_cast<std::intptr_t>(shellResult) <= 32)
    {
        QMessageBox::warning(this, "Admin", "提权启动失败，可能被用户取消或系统策略阻止。");
        return;
    }

    // 新进程启动成功后，当前实例退出。
    kLogEvent logEvent;
    info << logEvent << "[MainWindow] 已触发管理员重启，当前实例即将退出。" << eol;
    QApplication::quit();
}

bool MainWindow::hasAdminPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    TOKEN_ELEVATION tokenElevation{};
    DWORD returnLength = 0;
    const BOOL queryOk = ::GetTokenInformation(
        tokenHandle,
        TokenElevation,
        &tokenElevation,
        sizeof(tokenElevation),
        &returnLength);
    ::CloseHandle(tokenHandle);
    return queryOk != FALSE && tokenElevation.TokenIsElevated != 0;
}

bool MainWindow::hasDebugPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    DWORD requiredLength = 0;
    ::GetTokenInformation(tokenHandle, TokenPrivileges, nullptr, 0, &requiredLength);
    if (requiredLength == 0)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    std::vector<BYTE> privilegeBuffer(requiredLength, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenPrivileges,
        privilegeBuffer.data(),
        requiredLength,
        &requiredLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    LUID debugLuid{};
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugLuid) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    const TOKEN_PRIVILEGES* tokenPrivileges = reinterpret_cast<const TOKEN_PRIVILEGES*>(privilegeBuffer.data());
    for (DWORD privilegeIndex = 0; privilegeIndex < tokenPrivileges->PrivilegeCount; ++privilegeIndex)
    {
        const LUID_AND_ATTRIBUTES& privilegeItem = tokenPrivileges->Privileges[privilegeIndex];
        if (privilegeItem.Luid.LowPart == debugLuid.LowPart &&
            privilegeItem.Luid.HighPart == debugLuid.HighPart)
        {
            const bool enabled = (privilegeItem.Attributes & SE_PRIVILEGE_ENABLED) != 0;
            ::CloseHandle(tokenHandle);
            return enabled;
        }
    }

    ::CloseHandle(tokenHandle);
    return false;
}

bool MainWindow::hasSystemPrivilege() const
{
    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
    {
        return false;
    }

    DWORD requiredLength = 0;
    ::GetTokenInformation(tokenHandle, TokenUser, nullptr, 0, &requiredLength);
    if (requiredLength == 0)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    std::vector<BYTE> userBuffer(requiredLength, 0);
    if (::GetTokenInformation(
        tokenHandle,
        TokenUser,
        userBuffer.data(),
        requiredLength,
        &requiredLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    BYTE systemSidBuffer[SECURITY_MAX_SID_SIZE] = {};
    DWORD systemSidLength = static_cast<DWORD>(std::size(systemSidBuffer));
    if (::CreateWellKnownSid(
        WinLocalSystemSid,
        nullptr,
        systemSidBuffer,
        &systemSidLength) == FALSE)
    {
        ::CloseHandle(tokenHandle);
        return false;
    }

    const TOKEN_USER* tokenUser = reinterpret_cast<const TOKEN_USER*>(userBuffer.data());
    const bool isSystem = (::EqualSid(tokenUser->User.Sid, systemSidBuffer) != FALSE);
    ::CloseHandle(tokenHandle);
    return isSystem;
}

bool MainWindow::enableSeDebugPrivilege(std::string& errorTextOut) const
{
    errorTextOut.clear();

    HANDLE tokenHandle = nullptr;
    if (::OpenProcessToken(
        ::GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &tokenHandle) == FALSE)
    {
        errorTextOut = "OpenProcessToken failed, error=" + std::to_string(::GetLastError());
        return false;
    }

    LUID debugLuid{};
    if (::LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &debugLuid) == FALSE)
    {
        errorTextOut = "LookupPrivilegeValue(SE_DEBUG_NAME) failed, error=" + std::to_string(::GetLastError());
        ::CloseHandle(tokenHandle);
        return false;
    }

    TOKEN_PRIVILEGES tokenPrivileges{};
    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = debugLuid;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (::AdjustTokenPrivileges(
        tokenHandle,
        FALSE,
        &tokenPrivileges,
        sizeof(tokenPrivileges),
        nullptr,
        nullptr) == FALSE)
    {
        errorTextOut = "AdjustTokenPrivileges failed, error=" + std::to_string(::GetLastError());
        ::CloseHandle(tokenHandle);
        return false;
    }

    const DWORD adjustError = ::GetLastError();
    ::CloseHandle(tokenHandle);
    if (adjustError != ERROR_SUCCESS)
    {
        errorTextOut = "AdjustTokenPrivileges returned error=" + std::to_string(adjustError);
        return false;
    }
    return true;
}

QWidget* MainWindow::createDockPlaceholderWidget(const QString& titleText) const
{
    QWidget* placeholderWidget = new QWidget();
    placeholderWidget->setObjectName(QStringLiteral("ksLazyDockPlaceholder_%1").arg(titleText));
    placeholderWidget->setAutoFillBackground(false);
    placeholderWidget->setAttribute(Qt::WA_StyledBackground, false);
    // 进度条的槽与块必须在这里显式声明：
    // - 上面的 QWidget{background:transparent !important} 会连 QProgressBar 一起命中，
    //   不带 !important 的全局进度条基线样式会被它压掉，槽变成完全透明；
    // - 因此这里用同等强度的 !important 重新指定槽色与块色，不依赖层叠顺序。
    placeholderWidget->setStyleSheet(
        QStringLiteral(
            "QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "QLabel{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "QProgressBar{"
            "  background-color:%1 !important;"
            "  border:none !important;"
            "  border-radius:3px;"
            "}"
            "QProgressBar::chunk{"
            "  background-color:%2 !important;"
            "  border-radius:3px;"
            "}")
        .arg(KswordTheme::SurfaceMutedColorHex(), KswordTheme::ControlAccentHex()));

    auto* placeholderLayout = new QVBoxLayout(placeholderWidget);
    placeholderLayout->setContentsMargins(24, 24, 24, 24);
    placeholderLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("%1 页面正在初始化...").arg(titleText), placeholderWidget);
    titleLabel->setStyleSheet(QStringLiteral("font-size:16px;font-weight:700;"));
    titleLabel->setAlignment(Qt::AlignCenter);
    placeholderLayout->addStretch(1);
    placeholderLayout->addWidget(titleLabel);

    // 阶段文案与进度条：初始化各阶段由 updateLazyDockPlaceholderProgress 同步刷新。
    // 首次创建时留空/归零，页面尚未开始加载，不该显示任何进度。
    QLabel* stageLabel = new QLabel(placeholderWidget);
    stageLabel->setObjectName(QString::fromLatin1(kLazyDockPlaceholderStageLabelObjectName));
    stageLabel->setAlignment(Qt::AlignCenter);
    stageLabel->setStyleSheet(QStringLiteral("font-size:12px;color:%1;").arg(KswordTheme::TextSecondaryHex()));
    placeholderLayout->addSpacing(12);
    placeholderLayout->addWidget(stageLabel);

    // 进度条水平居中且不铺满整页：整行拉伸的进度条在宽 Dock 上观感很差。
    auto* progressRowLayout = new QHBoxLayout();
    progressRowLayout->setContentsMargins(0, 0, 0, 0);
    QProgressBar* loadProgressBar = new QProgressBar(placeholderWidget);
    loadProgressBar->setObjectName(QString::fromLatin1(kLazyDockPlaceholderProgressBarObjectName));
    loadProgressBar->setRange(0, 100);
    loadProgressBar->setValue(0);
    loadProgressBar->setTextVisible(false);
    loadProgressBar->setFixedHeight(6);
    loadProgressBar->setFixedWidth(260);
    progressRowLayout->addStretch(1);
    progressRowLayout->addWidget(loadProgressBar);
    progressRowLayout->addStretch(1);
    placeholderLayout->addLayout(progressRowLayout);

    placeholderLayout->addStretch(1);
    return placeholderWidget;
}

void MainWindow::ensureDockContentInitialized(ads::CDockWidget* dockWidget)
{
    if (dockWidget == nullptr)
    {
        return;
    }
    if (dockWidget->property("ks_lazy_initialized").toBool())
    {
        return;
    }
    if (dockWidget->property("ks_lazy_initializing").toBool())
    {
        kLogEvent lazyDockReentryEvent;
        dbg << lazyDockReentryEvent
            << "[MainWindow][LazyDock] 跳过重入初始化, dock="
            << dockWidget->property("ks_lazy_key").toString().toStdString()
            << eol;
        return;
    }

    const QString dockKey = dockWidget->property("ks_lazy_key").toString().trimmed().toLower();
    const QString dockTitleText = dockWidget->windowTitle().trimmed().isEmpty()
        ? dockKey
        : dockWidget->windowTitle().trimmed();
    dockWidget->setProperty("ks_lazy_initializing", true);
    const int progressPid = kPro.add(this, "页面", QStringLiteral("打开%1页").arg(dockTitleText).toStdString());
    kPro.set(progressPid, QStringLiteral("准备加载%1页").arg(dockTitleText).toStdString(), 0, 8.0f);

    // 重页面的构造函数会独占 UI 线程几十到几百毫秒，期间连重绘都不会发生，
    // 所以进度必须在进入构造之前就同步画出来，用户等待时看到的才是“正在加载”，
    // 而不是上一页的残影。
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("准备加载%1页").arg(dockTitleText),
        8);

    const bool isNetworkDock = (dockKey == QStringLiteral("network"));
    const bool isKernelDock = (dockKey == QStringLiteral("kernel"));
    QWidget* realWidget = nullptr;

    // 这一阶段的画面是用户实际盯着的那一帧：紧接着的页面构造会把 UI 线程占满，
    // 期间进度条停在此处不动是真实情况，不做假动画去掩饰。
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("正在创建%1页内容").arg(dockTitleText),
        30);

    if (dockKey == QStringLiteral("process"))
    {
        if (m_processWidget == nullptr)
        {
            m_processWidget = new ProcessDock(this);
            connect(
                m_processWidget,
                &ProcessDock::requestFocusProcessProtectByCallback,
                this,
                &MainWindow::focusProcessProtectByCallback);
        }
        realWidget = m_processWidget;
    }
    else if (dockKey == QStringLiteral("network"))
    {
        if (m_networkWidget == nullptr) { m_networkWidget = new NetworkDock(this); }
        realWidget = m_networkWidget;
    }
    else if (dockKey == QStringLiteral("memory"))
    {
        if (m_memoryWidget == nullptr) { m_memoryWidget = new MemoryDock(this); }
        realWidget = m_memoryWidget;
    }
    else if (dockKey == QStringLiteral("file"))
    {
        if (m_fileWidget == nullptr) { m_fileWidget = new FileDock(this); }
        realWidget = m_fileWidget;
    }
    else if (dockKey == QStringLiteral("driver"))
    {
        if (m_driverWidget == nullptr)
        {
            m_driverWidget = new DriverDock(this);
            if (m_kernelWidget != nullptr)
            {
                m_driverWidget->attachKswordSelfDriverPage(
                    m_kernelWidget->kswordSelfDriverPage(),
                    m_kernelWidget);
            }
        }
        realWidget = m_driverWidget;
    }
    else if (dockKey == QStringLiteral("kernel"))
    {
        if (m_kernelWidget == nullptr)
        {
            m_kernelWidget = new KernelDock(this);
            if (m_driverWidget != nullptr)
            {
                m_driverWidget->attachKswordSelfDriverPage(
                    m_kernelWidget->kswordSelfDriverPage(),
                    m_kernelWidget);
            }
        }
        realWidget = m_kernelWidget;
    }
    else if (dockKey == QStringLiteral("monitor"))
    {
        if (m_monitorWidget == nullptr) { m_monitorWidget = new MonitorDock(this); }
        realWidget = m_monitorWidget;
    }
    else if (dockKey == QStringLiteral("hardware"))
    {
        if (m_hardwareWidget == nullptr) { m_hardwareWidget = new HardwareDock(this); }
        realWidget = m_hardwareWidget;
    }
    else if (dockKey == QStringLiteral("privilege"))
    {
        if (m_privilegeWidget == nullptr) { m_privilegeWidget = new PrivilegeDock(this); }
        realWidget = m_privilegeWidget;
    }
    else if (dockKey == QStringLiteral("window"))
    {
        if (m_windowWidget == nullptr) { m_windowWidget = new WindowDock(this); }
        realWidget = m_windowWidget;
    }
    else if (dockKey == QStringLiteral("registry"))
    {
        if (m_registryWidget == nullptr) { m_registryWidget = new RegistryDock(this); }
        realWidget = m_registryWidget;
    }
    else if (dockKey == QStringLiteral("handle"))
    {
        if (m_handleWidget == nullptr) { m_handleWidget = new HandleDock(this); }
        realWidget = m_handleWidget;
    }
    else if (dockKey == QStringLiteral("startup"))
    {
        if (m_startupWidget == nullptr) { m_startupWidget = new StartupDock(this); }
        realWidget = m_startupWidget;
    }
    else if (dockKey == QStringLiteral("service"))
    {
        if (m_serviceWidget == nullptr) { m_serviceWidget = new ServiceDock(this); }
        realWidget = m_serviceWidget;
    }
    else if (dockKey == QStringLiteral("misc"))
    {
        // 扫描器 / 转储分析 / 插件已并入杂项页，不再各自占用顶层 Dock，
        // 它们随杂项页内部的页签懒加载，这里只需构造杂项容器本身。
        if (m_miscWidget == nullptr) { m_miscWidget = new MiscDock(this); }
        m_miscWidget->setBugcheckDiagnosticsVisible(
            m_currentAppearanceSettings.bugcheckDiagnosticsAutoInstallEnabled ||
            m_bugcheckDiagnosticsInstalledForSession ||
            m_bugcheckDiagnosticsEntryRequestedForSession);
        realWidget = m_miscWidget;
    }
    if (realWidget == nullptr)
    {
        kPro.set(progressPid, QStringLiteral("%1页无需加载").arg(dockTitleText).toStdString(), 0, 100.0f);
        // 这个 Dock 没有可加载的真实内容，占位页会一直留在界面上：
        // 进度条必须归零并清空阶段文案，否则会永久停在 30%，看起来像卡死。
        updateLazyDockPlaceholderProgress(dockWidget, QString(), 0);
        dockWidget->setProperty("ks_lazy_initializing", false);
        return;
    }

    kPro.set(progressPid, QStringLiteral("正在创建%1页内容").arg(dockTitleText).toStdString(), 0, 45.0f);

    // KernelDock 挂载策略：
    // - 没有背景图时保持根控件自绘，避免 ADS 恢复布局后露出黑色父容器；
    // - 有背景图时允许根控件透明，把底图透出来，仅由全局 QSS 保持表格/树/列表可读。
    realWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    if (isKernelDock)
    {
        const bool allowWallpaperThroughKernelDock = shouldRenderTransparentDockContent();
        realWidget->setAutoFillBackground(!allowWallpaperThroughKernelDock);
        realWidget->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThroughKernelDock);
    }
    else
    {
        realWidget->setAutoFillBackground(false);
        realWidget->setAttribute(Qt::WA_StyledBackground, false);
        realWidget->setStyleSheet(
            realWidget->styleSheet()
            + QStringLiteral(
                "QWidget{"
                "  background:transparent;"
                "  background-color:transparent;"
                "}"));
    }

    const bool shouldSuppressOuterScrollArea =
        isNetworkDock || (dockKey == QStringLiteral("hardware")) || isKernelDock;
    if (isNetworkDock)
    {
        // 网络页额外要求：
        // 1) 不再让 ADS 自动包一层外部 QScrollArea；
        // 2) 把整个网络 Dock 的最小高度抬到 300，便于验证问题是否位于最外层 Dock 容器。
        realWidget->setMinimumHeight(300);
        dockWidget->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidgetMinimumSize);
        dockWidget->setMinimumHeight(300);
        dockWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    }

    kPro.set(progressPid, QStringLiteral("正在挂载%1页").arg(dockTitleText).toStdString(), 0, 72.0f);
    // 占位页最后一次刷新：挂载真实内容后它就被 takeWidget 摘下并 deleteLater，
    // 因此 100% 那一帧没有意义，不再往上刷。
    updateLazyDockPlaceholderProgress(
        dockWidget,
        QStringLiteral("正在挂载%1页").arg(dockTitleText),
        80);
    QWidget* oldWidget = dockWidget->takeWidget();
    dockWidget->setWidget(
        realWidget,
        shouldSuppressOuterScrollArea ? ads::CDockWidget::ForceNoScrollArea : ads::CDockWidget::AutoScrollArea);
    dockWidget->setProperty("ks_lazy_initialized", true);
    dockWidget->setProperty("ks_lazy_initializing", false);
    configureAdsDockTabVisualIdentity(dockWidget);
    if (oldWidget != nullptr)
    {
        oldWidget->deleteLater();
    }

    if (realWidget == m_processWidget)
    {
        m_processWidget->refreshThemeVisuals();
    }

    // 真实内容挂载后继续继承 Dock 控件树的调色板：
    // - 主窗口背景改由根容器 paintEvent 绘制后，MainWindow 的 Window/Base 画刷只含主题纯色；
    // - 若在这里把该调色板显式复制给新内容，QAbstractScrollArea 等子控件会在首次挂载时刷出黑/白实底；
    // - Dock 再次切换时样式重新生效，因此旧行为表现为“首次初始化后黑底，切走再回来恢复透明”。
    // 延迟补载时只做局部刷新，不全局重算外观。
    realWidget->update();
    dockWidget->update();
    kPro.set(progressPid, QStringLiteral("%1页加载完成").arg(dockTitleText).toStdString(), 0, 100.0f);

    if (realWidget == m_kernelWidget && m_pendingR0DynDataRefresh)
    {
        m_pendingR0DynDataRefresh = false;
        QPointer<KernelDock> kernelDockGuard(m_kernelWidget);
        QTimer::singleShot(0, this, [kernelDockGuard]()
            {
                if (kernelDockGuard != nullptr)
                {
                    kernelDockGuard->requestDynDataRefresh();
                }
            });
    }
}

void MainWindow::configureDockWidgetPersistentIdentity(
    ads::CDockWidget* dockWidget,
    const QString& dockKey) const
{
    if (dockWidget == nullptr)
    {
        return;
    }

    // normalizedKey 用途：生成稳定、语言无关的 ADS objectName。
    const QString normalizedKey = dockKey.trimmed().toLower();
    if (normalizedKey.isEmpty())
    {
        return;
    }

    dockWidget->setObjectName(QStringLiteral("ksDock_%1").arg(normalizedKey));
    dockWidget->setProperty("ks_dock_layout_key", normalizedKey);
}

QString MainWindow::resolveDockLayoutConfigPath() const
{
    // applicationDirectoryPath 用途：固定指向当前 exe 所在目录，不向源码目录回退。
    const QString applicationDirectoryPath = QDir::cleanPath(QCoreApplication::applicationDirPath());
    const QDir rootDirectory(applicationDirectoryPath);
    return QDir::cleanPath(
        rootDirectory.absoluteFilePath(
            QStringLiteral("config/%1").arg(QString::fromLatin1(kDockLayoutConfigFileName))));
}

bool MainWindow::restoreDockLayoutFromConfig()
{
    if (m_pDockManager == nullptr)
    {
        return false;
    }

    const QString layoutConfigPath = resolveDockLayoutConfigPath();
    QFile layoutFile(layoutConfigPath);
    if (!layoutFile.exists())
    {
        kLogEvent layoutEvent;
        info << layoutEvent
            << "[MainWindow][ADS] 未发现布局配置，使用默认 Dock 布局。 path="
            << layoutConfigPath.toStdString()
            << eol;
        return false;
    }

    if (!layoutFile.open(QIODevice::ReadOnly))
    {
        kLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 打开布局配置失败，使用默认 Dock 布局。 path="
            << layoutConfigPath.toStdString()
            << eol;
        return false;
    }

    const QByteArray savedStateBytes = layoutFile.readAll();
    layoutFile.close();
    if (savedStateBytes.isEmpty())
    {
        kLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 布局配置为空，使用默认 Dock 布局。 path="
            << layoutConfigPath.toStdString()
            << eol;
        return false;
    }

    QElapsedTimer restoreTimer;
    restoreTimer.start();
    const bool restoreOk = m_pDockManager->restoreState(
        savedStateBytes,
        kDockLayoutConfigFileVersion);
    const qint64 restoreElapsedMs = restoreTimer.elapsed();
    m_dockLayoutRestoredFromConfig = restoreOk;

    kLogEvent layoutEvent;
    (restoreOk ? info : warn) << layoutEvent
        << "[MainWindow][ADS] 布局配置恢复"
        << (restoreOk ? "成功" : "失败")
        << "。 path="
        << layoutConfigPath.toStdString()
        << ", bytes="
        << savedStateBytes.size()
        << ", elapsedMs="
        << restoreElapsedMs
        << eol;
    if (restoreOk)
    {
        // ADS 恢复当前激活 Dock 时不会重新触发用户点击事件：
        // 如果恢复到惰性占位页（典型是上次退出时停在“内核”Dock），排到事件循环首轮加载，
        // 避免在“整理 Dock 布局”阶段同步创建重页面。
        QTimer::singleShot(0, this, [this]()
            {
                ensureVisibleLazyDocksInitialized(QStringLiteral("restoreDockLayout-deferred-0"));
                repairKernelDockAfterLayoutRestore(QStringLiteral("restoreDockLayout-deferred-0"));
            });
        QTimer::singleShot(250, this, [this]()
            {
                repairKernelDockAfterLayoutRestore(QStringLiteral("restoreDockLayout-deferred-250"));
            });
    }
    return restoreOk;
}

bool MainWindow::saveDockLayoutToConfig() const
{
    if (m_pDockManager == nullptr)
    {
        return false;
    }

    const QString layoutConfigPath = resolveDockLayoutConfigPath();
    const QFileInfo layoutFileInfo(layoutConfigPath);
    QDir layoutDirectory(layoutFileInfo.absolutePath());
    if (!layoutDirectory.exists() && !layoutDirectory.mkpath(QStringLiteral(".")))
    {
        kLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 创建布局配置目录失败。 dir="
            << layoutDirectory.absolutePath().toStdString()
            << eol;
        return false;
    }

    const QByteArray stateBytes = m_pDockManager->saveState(kDockLayoutConfigFileVersion);
    if (stateBytes.isEmpty())
    {
        kLogEvent layoutEvent;
        warn << layoutEvent << "[MainWindow][ADS] 当前布局状态为空，跳过保存。" << eol;
        return false;
    }

    QFile layoutFile(layoutConfigPath);
    if (!layoutFile.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        kLogEvent layoutEvent;
        warn << layoutEvent
            << "[MainWindow][ADS] 打开布局配置写入失败。 path="
            << layoutConfigPath.toStdString()
            << eol;
        return false;
    }

    const qint64 writtenBytes = layoutFile.write(stateBytes);
    layoutFile.close();
    const bool saveOk = (writtenBytes == stateBytes.size());
    kLogEvent layoutEvent;
    (saveOk ? info : warn) << layoutEvent
        << "[MainWindow][ADS] 布局配置保存"
        << (saveOk ? "成功" : "失败")
        << "。 path="
        << layoutConfigPath.toStdString()
        << ", bytes="
        << writtenBytes
        << eol;
    return saveOk;
}

void MainWindow::initializeNextDeferredDock()
{
    while (m_nextDeferredDockIndex < m_deferredDockLoadQueue.size())
    {
        ads::CDockWidget* dockWidget = m_deferredDockLoadQueue[m_nextDeferredDockIndex++];
        if (dockWidget == nullptr || dockWidget->property("ks_lazy_initialized").toBool())
        {
            continue;
        }

        ensureDockContentInitialized(dockWidget);
        QTimer::singleShot(kDeferredDockLoadIntervalMs, this, [this]()
            {
                initializeNextDeferredDock();
            });
        return;
    }

    reportStartupProgress(
        98,
        QStringLiteral("main.startup.progress.remaining_pages_complete"),
        QStringLiteral("启动完成。"));
}

void MainWindow::ensureVisibleLazyDocksInitialized(const QString& reasonText)
{
    if (m_pDockManager == nullptr)
    {
        return;
    }

    const QList<ads::CDockWidget*> candidateDockList{
        m_dockWelcome,
        m_dockProcess,
        m_dockNetwork,
        m_dockMemory,
        m_dockFile,
        m_dockDriver,
        m_dockKernel,
        m_dockMonitorTab,
        m_dockHardware,
        m_dockPrivilege,
        m_dockWindow,
        m_dockRegistry,
        m_dockHandle,
        m_dockStartup,
        m_dockService,
        m_dockMisc
    };

    ads::CDockWidget* focusedDockWidget = m_pDockManager->focusedDockWidget();
    for (ads::CDockWidget* dockWidget : candidateDockList)
    {
        if (dockWidget == nullptr || dockWidget->property("ks_lazy_initialized").toBool())
        {
            continue;
        }

        // 没有 ks_lazy_key 的 Dock（例如始终预建的欢迎页）本来就没有惰性内容，
        // 放进补载流程只会白跑一遍进度条条目。
        if (!dockWidget->property("ks_lazy_key").isValid())
        {
            continue;
        }

        if (!isDockWidgetActiveForLazyInitialization(dockWidget, focusedDockWidget))
        {
            continue;
        }

        kLogEvent lazyDockEvent;
        info << lazyDockEvent
            << "[MainWindow][LazyDock] 可见惰性 Dock 触发即时加载, reason="
            << reasonText.toStdString()
            << ", dock="
            << dockWidget->property("ks_lazy_key").toString().toStdString()
            << ", current="
            << (dockWidget->isCurrentTab() ? "true" : "false")
            << ", visible="
            << (dockWidget->isVisible() ? "true" : "false")
            << eol;
        ensureDockContentInitialized(dockWidget);

        if (!dockWidget->property("ks_lazy_initialized").toBool())
        {
            // 这一轮什么都没建（例如 dockKey 没有对应实现），不占用本轮配额，
            // 也绝不能在这里排重试，否则会变成无限自调度。
            continue;
        }

        // 分片补载：一次事件循环只允许构造一个重页面。
        // 多个可见惰性 Dock（分屏或多标签同时可见）如果在同一次调用里连续构造，
        // 各页几十到几百毫秒的构造成本会叠加成一次长阻塞；把剩余 Dock 让到下一轮
        // 事件循环，至少能保证两页之间界面还能重绘和响应输入。
        // guardedSelf 用途：延迟调度可能晚于主窗口销毁，回调前必须验证生命周期。
        const QPointer<MainWindow> guardedSelf(this);
        QTimer::singleShot(0, this, [guardedSelf, reasonText]()
            {
                if (guardedSelf == nullptr)
                {
                    return;
                }
                guardedSelf->ensureVisibleLazyDocksInitialized(reasonText);
            });
        return;
    }
}

void MainWindow::repairKernelDockAfterLayoutRestore(const QString& reasonText)
{
    if (m_dockKernel == nullptr)
    {
        return;
    }

    ads::CDockWidget* focusedDockWidget = (m_pDockManager != nullptr)
        ? m_pDockManager->focusedDockWidget()
        : nullptr;
    if (!isDockWidgetActiveForLazyInitialization(m_dockKernel, focusedDockWidget))
    {
        kLogEvent repairSkipEvent;
        info << repairSkipEvent
            << "[MainWindow][KernelDockRepair] skip inactive kernel dock, reason="
            << reasonText.toStdString()
            << ", initialized="
            << (m_dockKernel->property("ks_lazy_initialized").toBool() ? "true" : "false")
            << ", current="
            << (m_dockKernel->isCurrentTab() ? "true" : "false")
            << ", visible="
            << (m_dockKernel->isVisible() ? "true" : "false")
            << eol;
        return;
    }

    if (m_kernelWidget == nullptr)
    {
        ensureDockContentInitialized(m_dockKernel);
        if (m_kernelWidget == nullptr)
        {
            return;
        }
    }

    QWidget* mountedWidget = m_dockKernel->widget();
    const bool needsRemount = (mountedWidget != m_kernelWidget);
    if (needsRemount)
    {
        // 内核 Dock 是唯一已观察到 ADS 恢复后黑屏的主 Dock。这里不依赖 visible/current
        // 判断，直接确保 Dock 内容是 KernelDock 本体，避免恢复到旧占位页或空容器。
        // 背景图模式下不能再强制根控件自绘实底，否则会把主窗口背景图挡住。
        QWidget* oldWidget = m_dockKernel->takeWidget();
        const bool allowWallpaperThroughKernelDock = shouldRenderTransparentDockContent();
        m_kernelWidget->setAutoFillBackground(!allowWallpaperThroughKernelDock);
        m_kernelWidget->setAttribute(Qt::WA_StyledBackground, !allowWallpaperThroughKernelDock);
        m_kernelWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        m_dockKernel->setWidget(m_kernelWidget, ads::CDockWidget::ForceNoScrollArea);
        m_dockKernel->setProperty("ks_lazy_initialized", true);
        if (oldWidget != nullptr && oldWidget != m_kernelWidget)
        {
            oldWidget->deleteLater();
        }
        mountedWidget = m_dockKernel->widget();
    }

    if (m_kernelWidget != nullptr)
    {
        m_kernelWidget->ensureCurrentTabReadyForDisplay();
        m_kernelWidget->show();
        m_kernelWidget->raise();
        m_kernelWidget->updateGeometry();
        m_kernelWidget->update();
    }

    m_dockKernel->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidget);
    m_dockKernel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_dockKernel->updateGeometry();
    m_dockKernel->update();

    kLogEvent repairEvent;
    info << repairEvent
        << "[MainWindow][KernelDockRepair] reason="
        << reasonText.toStdString()
        << ", remount="
        << (needsRemount ? "true" : "false")
        << ", dockVisible="
        << (m_dockKernel->isVisible() ? "true" : "false")
        << ", dockCurrent="
        << (m_dockKernel->isCurrentTab() ? "true" : "false")
        << ", dockSize="
        << m_dockKernel->size().width()
        << "x"
        << m_dockKernel->size().height()
        << ", widgetMatches="
        << ((mountedWidget == m_kernelWidget) ? "true" : "false")
        << ", kernelVisible="
        << ((m_kernelWidget != nullptr && m_kernelWidget->isVisible()) ? "true" : "false")
        << ", kernelSize="
        << (m_kernelWidget != nullptr ? m_kernelWidget->size().width() : 0)
        << "x"
        << (m_kernelWidget != nullptr ? m_kernelWidget->size().height() : 0)
        << ", kernelState="
        << (m_kernelWidget != nullptr ? m_kernelWidget->displayStateSummary().toStdString() : std::string("null"))
        << eol;
}

void MainWindow::initDockWidgets()
{
    const QString startupDockKey = m_currentAppearanceSettings.startupDefaultTabKey.trimmed().toLower();
    const auto shouldEagerLoad = [&startupDockKey](const QString& dockKey) -> bool
        {
            return dockKey == QStringLiteral("welcome") ||
                (startupDockKey == QStringLiteral("winapi") && dockKey == QStringLiteral("monitor")) ||
                dockKey == startupDockKey;
        };

    // 首屏优先：欢迎页和启动默认页签；设置改由顶部菜单即时打开。
    reportStartupProgress(
        50,
        QStringLiteral("main.startup.progress.first_page"),
        QStringLiteral("正在加载功能模块..."));
    m_welcomeWidget = new WelcomeDock(this);
    connect(
        m_welcomeWidget,
        &WelcomeDock::languageSettingsRequested,
        this,
        [this]() {
            showSettingsPanelFromMenu(true);
        });
    if (shouldEagerLoad(QStringLiteral("process")))
    {
        m_processWidget = new ProcessDock(this);
        connect(
            m_processWidget,
            &ProcessDock::requestFocusProcessProtectByCallback,
            this,
            &MainWindow::focusProcessProtectByCallback);
    }
    if (shouldEagerLoad(QStringLiteral("network"))) { m_networkWidget = new NetworkDock(this); }
    if (shouldEagerLoad(QStringLiteral("memory"))) { m_memoryWidget = new MemoryDock(this); }
    if (shouldEagerLoad(QStringLiteral("file"))) { m_fileWidget = new FileDock(this); }
    if (shouldEagerLoad(QStringLiteral("driver"))) { m_driverWidget = new DriverDock(this); }
    // KernelDock 不再参与主 Dock 惰性占位：
    // - 它是启动恢复黑屏的唯一复现场景；
    // - 真实创建成本可控，且能避免 ADS restoreState 把占位页/空容器恢复为当前页。
    m_kernelWidget = new KernelDock(this);
    if (m_driverWidget != nullptr)
    {
        m_driverWidget->attachKswordSelfDriverPage(
            m_kernelWidget->kswordSelfDriverPage(),
            m_kernelWidget);
    }
    if (shouldEagerLoad(QStringLiteral("monitor"))) { m_monitorWidget = new MonitorDock(this); }
    if (shouldEagerLoad(QStringLiteral("hardware"))) { m_hardwareWidget = new HardwareDock(this); }
    if (shouldEagerLoad(QStringLiteral("privilege"))) { m_privilegeWidget = new PrivilegeDock(this); }
    if (shouldEagerLoad(QStringLiteral("window"))) { m_windowWidget = new WindowDock(this); }
    if (shouldEagerLoad(QStringLiteral("registry"))) { m_registryWidget = new RegistryDock(this); }
    if (shouldEagerLoad(QStringLiteral("handle"))) { m_handleWidget = new HandleDock(this); }
    if (shouldEagerLoad(QStringLiteral("startup"))) { m_startupWidget = new StartupDock(this); }
    if (shouldEagerLoad(QStringLiteral("service"))) { m_serviceWidget = new ServiceDock(this); }
    if (shouldEagerLoad(QStringLiteral("misc")))
    {
        m_miscWidget = new MiscDock(this);
        updateBugcheckDiagnosticsEntryVisibility();
    }

    reportStartupProgress(
        60,
        QStringLiteral("main.startup.progress.auxiliary_components"),
        QStringLiteral("正在加载功能模块..."));
    // “即时窗口”继续保留实现代码但不注册到 ADS。
    // 日志输出独立窗口继续常驻；三个辅助 Dock 各自持有独立内容控件。
    m_logOutputWindow = new QDialog(this);
    m_logOutputWindow->setObjectName(QStringLiteral("ksLogOutputWindow"));
    m_logOutputWindow->setWindowTitle(ks::i18n::text(QStringLiteral("dock.log"), QStringLiteral("日志输出")));
    m_logOutputWindow->setWindowModality(Qt::NonModal);
    m_logOutputWindow->setModal(false);
    m_logOutputWindow->setAttribute(Qt::WA_DeleteOnClose, false);
    m_logOutputWindow->resize(900, 620);
    ks::i18n::LanguageManager::instance().bindWindowTitle(
        m_logOutputWindow,
        QStringLiteral("dock.log"),
        QStringLiteral("日志输出"));
    QVBoxLayout* logWindowLayout = new QVBoxLayout(m_logOutputWindow);
    logWindowLayout->setContentsMargins(8, 8, 8, 8);
    logWindowLayout->setSpacing(0);
    m_logWidget = new LogDockWidget(m_logOutputWindow);
    logWindowLayout->addWidget(m_logWidget, 1);
    m_logOutputWindow->installEventFilter(this);
    m_logWindowGeometrySaveTimer = new QTimer(this);
    m_logWindowGeometrySaveTimer->setSingleShot(true);
    m_logWindowGeometrySaveTimer->setInterval(300);
    connect(m_logWindowGeometrySaveTimer, &QTimer::timeout, this, &MainWindow::persistLogOutputWindowGeometry);
    restoreLogOutputWindowGeometry();
    m_logOutputWindow->hide();

    m_notificationCardManager = new ks::ui::NotificationCardManager(this, m_pDockManager, this);
    m_notificationCardManager->applySettings(m_currentAppearanceSettings);

    // 创建 Dock 容器前再推进一次启动进度，避免长时间停留在单一文案。
    reportStartupProgress(
        68,
        QStringLiteral("main.startup.progress.dock_containers"),
        QStringLiteral("正在加载功能模块..."));

    // 使用辅助函数创建Dock Widgets。
    auto createDockWidget = [this](
        QWidget* widget,
        const QString& title,
        const QString& dockKey,
        const ads::CDockWidget::eInsertMode insertMode = ads::CDockWidget::AutoScrollArea) -> ads::CDockWidget* {
        const bool isKernelDock = (dockKey == QStringLiteral("kernel"));
        ads::CDockWidget* dock = new ads::CDockWidget(title);
        configureDockWidgetPersistentIdentity(dock, dockKey);
        ks::i18n::LanguageManager::instance().bindWindowTitle(
            dock,
            QStringLiteral("dock.%1").arg(dockKey),
            title);
        dock->setWidget(widget, insertMode);
        // DockWidgetClosable 禁用：统一去掉每个 Dock 标签旁边的关闭叉。
        dock->setFeature(ads::CDockWidget::DockWidgetClosable, false);
        dock->setFeature(ads::CDockWidget::DockWidgetMovable, true);
        dock->setFeature(ads::CDockWidget::DockWidgetFloatable, true);

        // Dock 背景属性初始化：
        // - 默认关闭 Dock 与内容根控件的自动背景填充；
        // - 避免背景图模式下被黑/白纯色底覆盖。
        dock->setAutoFillBackground(false);
        dock->setAttribute(Qt::WA_StyledBackground, false);
        if (widget != nullptr)
        {
            // 透明背景模式下即使是 KernelDock 也不能自绘实底，否则盖住云母材质。
            const bool isRealKernelContent = isKernelDock
                && widget == m_kernelWidget
                && !shouldRenderTransparentDockContent();
            // KernelDock paints its own tab surface.  Do not convert it to a transparent root here,
            // otherwise a restored startup kernel dock can inherit the dark ADS background before
            // its internal pages get a chance to repaint.
            widget->setAutoFillBackground(isRealKernelContent);
            widget->setAttribute(Qt::WA_StyledBackground, isRealKernelContent);
        }
        configureAdsDockTabVisualIdentity(dock);
        return dock;
        };

    auto createLazyDockWidget = [this, &createDockWidget](
        ads::CDockWidget*& dockOut,
        QWidget* eagerWidget,
        const QString& title,
        const QString& dockKey)
        {
            const bool isNetworkDock = (dockKey == QStringLiteral("network"));
            const bool isKernelDock = (dockKey == QStringLiteral("kernel"));
            const bool shouldSuppressOuterScrollArea =
                isNetworkDock || (dockKey == QStringLiteral("hardware")) || isKernelDock;
            QWidget* dockContentWidget = eagerWidget;
            if (dockContentWidget == nullptr)
            {
                dockContentWidget = createDockPlaceholderWidget(title);
            }

            dockContentWidget->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            dockOut = createDockWidget(
                dockContentWidget,
                title,
                dockKey,
                shouldSuppressOuterScrollArea ? ads::CDockWidget::ForceNoScrollArea : ads::CDockWidget::AutoScrollArea);
            dockOut->setProperty("ks_lazy_key", dockKey);
            dockOut->setProperty("ks_lazy_initialized", eagerWidget != nullptr);
            if (isNetworkDock)
            {
                dockContentWidget->setMinimumHeight(300);
                dockOut->setMinimumSizeHintMode(ads::CDockWidget::MinimumSizeHintFromDockWidgetMinimumSize);
                dockOut->setMinimumHeight(300);
                dockOut->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
            }
            connect(dockOut, &ads::CDockWidget::visibilityChanged, this, [this, dockOut](const bool visible)
                {
                    if (visible)
                    {
                        QTimer::singleShot(0, this, [this, dockOut]() {
                            ensureDockContentInitialized(dockOut);
                            });
                    }
                });

            if (eagerWidget == nullptr)
            {
                m_deferredDockLoadQueue.push_back(dockOut);
            }
        };

    // setupDockTabText 作用：统一主 Dock Tab 的文本省略策略，并允许按内容自适应宽度。
    const auto setupDockTabText = [](ads::CDockWidget* dockWidget) {
        if (dockWidget == nullptr || dockWidget->tabWidget() == nullptr)
        {
            return;
        }

        ads::CDockWidgetTab* tabWidget = dockWidget->tabWidget();
        tabWidget->setElideMode(Qt::ElideNone);
        tabWidget->setMinimumWidth(0);
        tabWidget->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    };

    // 创建所有 Dock 壳；重页面若未预加载，则先挂占位页并排入显示后补载队列。
    m_dockWelcome = createDockWidget(m_welcomeWidget, ks::i18n::text(QStringLiteral("dock.welcome"), QStringLiteral("欢迎")), QStringLiteral("welcome"));
    createLazyDockWidget(m_dockProcess, m_processWidget, ks::i18n::text(QStringLiteral("dock.process"), QStringLiteral("进程")), QStringLiteral("process"));
    createLazyDockWidget(m_dockNetwork, m_networkWidget, ks::i18n::text(QStringLiteral("dock.network"), QStringLiteral("网络")), QStringLiteral("network"));
    createLazyDockWidget(m_dockMemory, m_memoryWidget, ks::i18n::text(QStringLiteral("dock.memory"), QStringLiteral("内存")), QStringLiteral("memory"));
    createLazyDockWidget(m_dockFile, m_fileWidget, ks::i18n::text(QStringLiteral("dock.file"), QStringLiteral("文件")), QStringLiteral("file"));
    createLazyDockWidget(m_dockDriver, m_driverWidget, ks::i18n::text(QStringLiteral("dock.driver"), QStringLiteral("驱动")), QStringLiteral("driver"));
    createLazyDockWidget(m_dockKernel, m_kernelWidget, ks::i18n::text(QStringLiteral("dock.kernel"), QStringLiteral("内核")), QStringLiteral("kernel"));
    createLazyDockWidget(m_dockMonitorTab, m_monitorWidget, ks::i18n::text(QStringLiteral("dock.monitor"), QStringLiteral("监控")), QStringLiteral("monitor"));
    createLazyDockWidget(m_dockHardware, m_hardwareWidget, ks::i18n::text(QStringLiteral("dock.hardware"), QStringLiteral("硬件")), QStringLiteral("hardware"));
    createLazyDockWidget(m_dockPrivilege, m_privilegeWidget, ks::i18n::text(QStringLiteral("dock.privilege"), QStringLiteral("权限")), QStringLiteral("privilege"));
    createLazyDockWidget(m_dockWindow, m_windowWidget, ks::i18n::text(QStringLiteral("dock.window"), QStringLiteral("窗口")), QStringLiteral("window"));
    createLazyDockWidget(m_dockRegistry, m_registryWidget, ks::i18n::text(QStringLiteral("dock.registry"), QStringLiteral("注册表")), QStringLiteral("registry"));
    createLazyDockWidget(m_dockHandle, m_handleWidget, ks::i18n::text(QStringLiteral("dock.handle"), QStringLiteral("句柄")), QStringLiteral("handle"));
    createLazyDockWidget(m_dockStartup, m_startupWidget, ks::i18n::text(QStringLiteral("dock.startup"), QStringLiteral("启动项")), QStringLiteral("startup"));
    createLazyDockWidget(m_dockService, m_serviceWidget, ks::i18n::text(QStringLiteral("dock.service"), QStringLiteral("服务")), QStringLiteral("service"));
    createLazyDockWidget(m_dockMisc, m_miscWidget, ks::i18n::text(QStringLiteral("dock.misc"), QStringLiteral("杂项")), QStringLiteral("misc"));

    // 三个辅助 Dock 始终创建并注册，关闭时只隐藏内容实例，确保菜单状态和 ADS 布局可恢复。
    m_dockLogWidget = new LogDockWidget(this);
    m_monitorPanelWidget = new MonitorPanelWidget(this);
    m_progressWidget = new ProgressDockWidget(this);
    m_dockLog = createDockWidget(
        m_dockLogWidget,
        ks::i18n::text(QStringLiteral("dock.log_window"), QStringLiteral("日志窗口")),
        QStringLiteral("log_window"),
        ads::CDockWidget::ForceNoScrollArea);
    m_dockMonitor = createDockWidget(
        m_monitorPanelWidget,
        ks::i18n::text(QStringLiteral("dock.monitor_panel"), QStringLiteral("监视面板")),
        QStringLiteral("monitor_panel"),
        ads::CDockWidget::ForceNoScrollArea);
    m_dockCurrentOp = createDockWidget(
        m_progressWidget,
        ks::i18n::text(QStringLiteral("dock.current_tasks"), QStringLiteral("当前任务")),
        QStringLiteral("current_tasks"),
        ads::CDockWidget::ForceNoScrollArea);
    for (ads::CDockWidget* auxiliaryDock : { m_dockLog, m_dockMonitor, m_dockCurrentOp })
    {
        auxiliaryDock->setFeature(ads::CDockWidget::DockWidgetClosable, true);
        auxiliaryDock->setFeature(ads::CDockWidget::DockWidgetDeleteOnClose, false);
        auxiliaryDock->setToggleViewActionMode(ads::CDockWidget::ActionModeToggle);
        setupDockTabText(auxiliaryDock);
        configureAdsDockTabVisualIdentity(auxiliaryDock);
    }
    initializeWindowDockMenuActions();

    QList<ads::CDockWidget*> mainDockTabList{
        m_dockWelcome,
        m_dockProcess,
        m_dockNetwork,
        m_dockMemory,
        m_dockFile,
        m_dockDriver,
        m_dockKernel,
        m_dockMonitorTab,
        m_dockHardware,
        m_dockPrivilege,
        m_dockWindow,
        m_dockRegistry,
        m_dockHandle,
        m_dockStartup,
        m_dockService,
        m_dockMisc
    };
    for (ads::CDockWidget* dockWidget : mainDockTabList)
    {
        setupDockTabText(dockWidget);
        configureAdsDockTabVisualIdentity(dockWidget);
    }

    // 主功能页签不进入窗口菜单；菜单仅承载三个可关闭的辅助 Dock。
    reportStartupProgress(
        72,
        QStringLiteral("main.startup.progress.skip_view_menu"),
        QStringLiteral("正在加载功能模块..."));
}
#define ADS_TABIFY_DOCK_WIDGET_AVAILABLE
void MainWindow::setupDockLayout()
{
    QElapsedTimer layoutTimer;
    layoutTimer.start();

    // 1. 初始化DockManager（若未在构造函数中初始化）
    if (!m_pDockManager) {
        QWidget* dockParentWidget = (m_mainRootContainer != nullptr)
            ? m_mainRootContainer
            : this;
        m_pDockManager = new ads::CDockManager(dockParentWidget);
        if (m_mainRootLayout != nullptr && m_mainRootContainer != nullptr)
        {
            m_mainRootLayout->addWidget(m_pDockManager, 1);
            if (centralWidget() != m_mainRootContainer)
            {
                setCentralWidget(m_mainRootContainer);
            }
        }
        else
        {
            setCentralWidget(m_pDockManager);
        }
    }

    const bool mainWindowUpdatesWereEnabled = updatesEnabled();
    const bool dockManagerUpdatesWereEnabled = m_pDockManager->updatesEnabled();
    setUpdatesEnabled(false);
    m_pDockManager->setUpdatesEnabled(false);

    reportStartupProgress(
        76,
        QStringLiteral("main.startup.progress.register_main_docks"),
        QStringLiteral("正在加载功能模块..."));

    // 2. 左侧区域：先添加第一个DockWidget，获取其所在的DockArea
    auto leftDockArea = m_pDockManager->addDockWidget(ads::LeftDockWidgetArea, m_dockWelcome);

    // 3. 使用正确的方法将其他DockWidget添加到同一个DockArea形成标签页
    // 方法1: 使用addDockWidgetTabToArea（推荐）
    m_pDockManager->addDockWidgetTabToArea(m_dockProcess, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockNetwork, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockMemory, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockFile, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockDriver, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockKernel, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockMonitorTab, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockHardware, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockPrivilege, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockWindow, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockRegistry, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockHandle, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockStartup, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockService, leftDockArea);
    m_pDockManager->addDockWidgetTabToArea(m_dockMisc, leftDockArea);

    // 方法2: 或者使用addDockWidget并指定CenterDockWidgetArea
    // m_pDockManager->addDockWidget(ads::CenterDockWidgetArea, m_dockProcess, leftDockArea);

    reportStartupProgress(
        78,
        QStringLiteral("main.startup.progress.register_auxiliary_docks"),
        QStringLiteral("正在加载功能模块..."));

    // 4. 辅助 Dock 默认位于底部，按“日志窗口｜监视面板｜当前任务”以 2:2:1 横向排列。
    // 首次启动先关闭三者，但保留停靠位置；版本 6 布局恢复会覆盖此默认可见状态。
    auto bottomLogArea = m_pDockManager->addDockWidget(
        ads::BottomDockWidgetArea,
        m_dockLog);
    auto bottomMonitorArea = m_pDockManager->addDockWidget(
        ads::RightDockWidgetArea,
        m_dockMonitor,
        bottomLogArea);
    m_pDockManager->addDockWidget(
        ads::RightDockWidgetArea,
        m_dockCurrentOp,
        bottomMonitorArea);
    m_pDockManager->setSplitterSizes(leftDockArea, { 3, 1 });
    m_pDockManager->setSplitterSizes(bottomLogArea, { 2, 2, 1 });
    m_dockLog->toggleView(false);
    m_dockMonitor->toggleView(false);
    m_dockCurrentOp->toggleView(false);

    // 5. 设置默认显示的标签页
    withTemporaryNonTopMostForDockSwitch([this]()
        {
            m_dockWelcome->raise();
        });

    // 默认 Dock 拓扑整理完毕后立即恢复更新，再让 ADS 创建保存状态中的浮动顶层窗口：
    // - restoreState() 会把部分 Dock 从 m_pDockManager 脱离并创建独立顶层窗口；
    // - 若它们诞生于 updatesEnabled=false 的控件树中，恢复后会保留禁用绘制状态；
    // - 此时鼠标命中和右键菜单仍正常，窗口客户区却始终保持黑色。
    setUpdatesEnabled(mainWindowUpdatesWereEnabled);
    m_pDockManager->setUpdatesEnabled(dockManagerUpdatesWereEnabled);

    // 6. 默认布局搭建完成后再恢复用户布局：
    // - ADS restoreState 要求所有 DockWidget 已注册；
    // - objectName 已在 initDockWidgets 中固定为英文 key，避免中文标题变化破坏恢复。
    reportStartupProgress(
        80,
        QStringLiteral("main.startup.progress.restore_dock_layout"),
        QStringLiteral("正在恢复界面布局..."));
    restoreDockLayoutFromConfig();
    // 旧布局配置里没有后来新增的 Dock，ADS 不会安置它们，必须在这里收回主标签区。
    reattachDetachedFeatureDocks();
    attachPrivilegeStatusButtonsToPrimaryDockTabBar();
    reportStartupProgress(
        82,
        QStringLiteral("main.startup.progress.refresh_dock_tabs"),
        QStringLiteral("正在恢复界面布局..."));
    refreshAdsDockTabVisualIdentities(m_pDockManager);

    // 对恢复出来的独立顶层窗口再做一次显式校正：
    // ADS 版本差异可能让 dockContainer 保留恢复阶段的更新禁用标记。
    // 只处理本次布局恢复产生的浮动容器，不遍历或改写 Dock 内容控件。
    if (dockManagerUpdatesWereEnabled)
    {
        const QList<ads::CFloatingDockContainer*> floatingWidgets = m_pDockManager->floatingWidgets();
        for (ads::CFloatingDockContainer* floatingWidget : floatingWidgets)
        {
            if (floatingWidget == nullptr)
            {
                continue;
            }
            floatingWidget->installEventFilter(this);
            floatingWidget->setUpdatesEnabled(true);
            if (ads::CDockContainerWidget* dockContainer = floatingWidget->dockContainer(); dockContainer != nullptr)
            {
                dockContainer->setUpdatesEnabled(true);
                dockContainer->updateGeometry();
                dockContainer->update();
            }
            floatingWidget->updateGeometry();
            floatingWidget->update();
        }
    }
    m_pDockManager->updateGeometry();
    m_pDockManager->update();

    kLogEvent layoutTimingEvent;
    info << layoutTimingEvent
        << "[MainWindow][StartupTiming] setupDockLayout elapsedMs="
        << layoutTimer.elapsed()
        << eol;
}

void MainWindow::focusHandleDockByPid(const quint32 pid)
{
    // 跳转入口日志：记录来源请求 PID，便于串联调用链审计。
    kLogEvent focusHandleEvent;
    info << focusHandleEvent
        << "[MainWindow] focusHandleDockByPid: pid="
        << pid
        << eol;

    if (m_dockHandle != nullptr)
    {
        ensureDockContentInitialized(m_dockHandle);
    }
    if (m_handleWidget != nullptr)
    {
        m_handleWidget->focusProcessId(static_cast<std::uint32_t>(pid), true);
    }
    if (m_dockHandle != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                m_dockHandle->raise();
            });
        m_dockHandle->setVisible(true);
    }
}

void MainWindow::focusHandleDockByPids(const QString& pidListText)
{
    const QVector<quint32> processIds = parseProcessPidListText(pidListText);
    if (processIds.isEmpty())
    {
        return;
    }
    if (m_dockHandle != nullptr)
    {
        ensureDockContentInitialized(m_dockHandle);
    }
    if (m_handleWidget != nullptr)
    {
        m_handleWidget->focusProcessIds(processIds, true);
    }
    if (m_dockHandle != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { m_dockHandle->raise(); });
        m_dockHandle->setVisible(true);
    }
}

void MainWindow::focusProcessProtectByCallback()
{
    if (m_dockKernel != nullptr)
    {
        ensureDockContentInitialized(m_dockKernel);
    }
    if (m_kernelWidget == nullptr || m_dockKernel == nullptr)
    {
        return;
    }

    m_kernelWidget->focusProcessProtectTab();
    withTemporaryNonTopMostForDockSwitch([this]()
        {
            m_dockKernel->raise();
        });
    m_dockKernel->setVisible(true);
}

void MainWindow::focusMemoryDockByPid(const quint32 pid)
{
    // 跳转入口日志：记录目标 PID，并确保内存 Dock 惰性加载完成。
    kLogEvent focusMemoryEvent;
    info << focusMemoryEvent
        << "[MainWindow] focusMemoryDockByPid: pid="
        << pid
        << eol;

    if (m_dockMemory != nullptr)
    {
        ensureDockContentInitialized(m_dockMemory);
    }
    if (m_memoryWidget != nullptr)
    {
        m_memoryWidget->focusProcessForOperations(static_cast<std::uint32_t>(pid), false);
    }
    if (m_dockMemory != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                m_dockMemory->raise();
            });
        m_dockMemory->setVisible(true);
    }
}

void MainWindow::focusNetworkDockByPids(const QString& pidListText)
{
    const QVector<quint32> processIds = parseProcessPidListText(pidListText);
    if (processIds.isEmpty())
    {
        return;
    }
    if (m_dockNetwork != nullptr)
    {
        ensureDockContentInitialized(m_dockNetwork);
    }
    if (m_networkWidget != nullptr)
    {
        m_networkWidget->focusConnectionsByPids(processIds);
    }
    if (m_dockNetwork != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { m_dockNetwork->raise(); });
        m_dockNetwork->setVisible(true);
    }
}

void MainWindow::focusWindowDockByPids(const QString& pidListText)
{
    const QVector<quint32> processIds = parseProcessPidListText(pidListText);
    if (processIds.isEmpty())
    {
        return;
    }
    if (m_dockWindow != nullptr)
    {
        ensureDockContentInitialized(m_dockWindow);
    }
    if (m_windowWidget != nullptr)
    {
        m_windowWidget->focusWindowsByPids(processIds);
    }
    if (m_dockWindow != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]() { m_dockWindow->raise(); });
        m_dockWindow->setVisible(true);
    }
}

void MainWindow::openProcessDetailByPid(const quint32 pid)
{
    // 跳转入口日志：记录来自外部模块的 PID 跳转请求。
    kLogEvent openProcessDetailEvent;
    info << openProcessDetailEvent
        << "[MainWindow] openProcessDetailByPid: pid="
        << pid
        << eol;

    // 进程页仍负责详情窗口复用和进程 identity 校验，但这里只初始化其内容，
    // 不激活进程 Dock，避免从其他 Dock 打开独立详情窗口时切走当前页签。
    if (m_dockProcess != nullptr)
    {
        ensureDockContentInitialized(m_dockProcess);
    }
    if (m_processWidget != nullptr)
    {
        m_processWidget->requestOpenProcessDetailByPid(static_cast<std::uint32_t>(pid));
    }
}

void MainWindow::openProcessDetailByIdentity(
    const quint32 pid,
    const quint64 creationTime100ns)
{
    // openProcessDetailEvent：记录历史事件携带的完整进程 identity。
    kLogEvent openProcessDetailEvent;
    info << openProcessDetailEvent
        << "[MainWindow] openProcessDetailByIdentity: pid="
        << pid
        << ", creationTime100ns="
        << creationTime100ns
        << eol;

    // 进程页仍负责详情窗口复用和历史 identity 校验，但这里只初始化其内容，
    // 不激活进程 Dock，避免从其他 Dock 打开独立详情窗口时切走当前页签。
    if (m_dockProcess != nullptr)
    {
        ensureDockContentInitialized(m_dockProcess);
    }
    if (m_processWidget != nullptr)
    {
        m_processWidget->requestOpenProcessDetailByIdentity(
            static_cast<std::uint32_t>(pid),
            static_cast<std::uint64_t>(creationTime100ns));
    }
    // 历史目标失效时 ProcessDock 会弹出明确提示；详情请求不改变当前 Dock 标签。
}

void MainWindow::focusServiceDockByName(const QString& serviceNameText)
{
    const QString normalizedServiceName = serviceNameText.trimmed();
    kLogEvent focusServiceEvent;
    info << focusServiceEvent
        << "[MainWindow] focusServiceDockByName: service="
        << normalizedServiceName.toStdString()
        << eol;

    if (m_dockService != nullptr)
    {
        ensureDockContentInitialized(m_dockService);
    }
    if (m_serviceWidget != nullptr && !normalizedServiceName.isEmpty())
    {
        m_serviceWidget->focusServiceByName(normalizedServiceName);
    }
    if (m_dockService != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                m_dockService->raise();
            });
        m_dockService->setVisible(true);
    }
}

void MainWindow::openFileDetailDockByPath(const QString& filePath)
{
    const QString normalizedFilePath = QDir::toNativeSeparators(filePath.trimmed());
    if (normalizedFilePath.isEmpty())
    {
        return;
    }

    kLogEvent openFileDetailEvent;
    info << openFileDetailEvent
        << "[MainWindow] openFileDetailDockByPath: file="
        << normalizedFilePath.toStdString()
        << eol;

    if (m_dockFile != nullptr)
    {
        ensureDockContentInitialized(m_dockFile);
    }
    if (m_fileWidget != nullptr)
    {
        m_fileWidget->openFileDetailByPath(normalizedFilePath);
    }
    if (m_dockFile != nullptr)
    {
        withTemporaryNonTopMostForDockSwitch([this]()
            {
                m_dockFile->raise();
            });
        m_dockFile->setVisible(true);
    }
}

void MainWindow::openFileUnlockerDockByPath(const QString& filePath)
{
    const QString normalizedFilePath = QDir::toNativeSeparators(filePath.trimmed());
    if (normalizedFilePath.isEmpty())
    {
        return;
    }

    kLogEvent unlockFileEvent;
    info << unlockFileEvent
        << "[MainWindow] openFileUnlockerDockByPath: path="
        << normalizedFilePath.toStdString()
        << eol;

    const QFileInfo targetFileInfo(normalizedFilePath);
    if (!targetFileInfo.exists() || (!targetFileInfo.isFile() && !targetFileInfo.isDir()))
    {
        warn << unlockFileEvent
            << "[MainWindow] openFileUnlockerDockByPath canceled: invalid path="
            << normalizedFilePath.toStdString()
            << eol;
        QMessageBox::warning(
            this,
            QStringLiteral("Ksword 文件解锁器"),
            QStringLiteral("目标路径不存在或不是文件/目录：\n%1").arg(normalizedFilePath));
        return;
    }

    // Shell 右键入口必须复用 FileDock 内部“文件解锁器(R3/R0)”同一套流程。
    // 已打开文件页时直接复用真实 FileDock；否则使用隐藏宿主，避免启动期切换文件页造成黑屏。
    FileDock* unlockerHost = m_fileWidget;
    if (unlockerHost == nullptr)
    {
        if (m_shellUnlockerFileDock == nullptr)
        {
            m_shellUnlockerFileDock = new FileDock(this);
            m_shellUnlockerFileDock->setObjectName(QStringLiteral("ShellUnlockerFileDockHost"));
            m_shellUnlockerFileDock->setAttribute(Qt::WA_DontShowOnScreen, true);
            m_shellUnlockerFileDock->hide();
        }
        unlockerHost = m_shellUnlockerFileDock;
    }

    this->raise();
    this->activateWindow();
    unlockerHost->unlockFileByPath(targetFileInfo.absoluteFilePath());

    info << unlockFileEvent
        << "[MainWindow] openFileUnlockerDockByPath delegated to FileDock unlocker."
        << eol;
}

void MainWindow::reattachDetachedFeatureDocks()
{
    if (m_pDockManager == nullptr || m_dockWelcome == nullptr)
    {
        return;
    }

    // 主 Dock 区以欢迎页为锚：它一定在保存的布局里，是唯一稳定的参照。
    ads::CDockAreaWidget* const mainArea = m_dockWelcome->dockAreaWidget();
    if (mainArea == nullptr)
    {
        return;
    }

    // 只处理左侧标签栏里的主功能 Dock。日志/监控/当前操作属于底部区域，
    // 用户把它们拖成浮动窗口是正常用法，不能一并收回。
    const QList<ads::CDockWidget*> featureDocks = {
        m_dockProcess, m_dockNetwork, m_dockMemory, m_dockFile,
        m_dockDriver, m_dockKernel, m_dockMonitorTab,
        m_dockHardware, m_dockPrivilege, m_dockWindow, m_dockRegistry,
        m_dockHandle, m_dockStartup, m_dockService, m_dockMisc
    };

    QStringList reattachedKeys;
    for (ads::CDockWidget* const dockWidget : featureDocks)
    {
        if (dockWidget == nullptr || dockWidget == m_dockWelcome)
        {
            continue;
        }
        // 判据是"所在容器不是主容器"，而不是 isFloating()：
        // 恢复出来的 Dock 可能落在某个浮动容器的标签组里，此时它自身不算浮动，
        // 但对用户来说同样是"独立窗口弹出来了"。
        ads::CDockContainerWidget* const container = dockWidget->dockContainer();
        if (container != nullptr && container == m_pDockManager)
        {
            continue;
        }

        m_pDockManager->addDockWidgetTabToArea(dockWidget, mainArea);
        reattachedKeys.append(dockWidget->property("ks_lazy_key").toString());
    }

    if (reattachedKeys.isEmpty())
    {
        return;
    }

    kLogEvent layoutEvent;
    info << layoutEvent
        << "[MainWindow][ADS] 已把游离的功能页收回主标签区（旧布局配置中不含这些页）: "
        << reattachedKeys.join(QStringLiteral(",")).toStdString()
        << eol;
}

void MainWindow::openMinidumpDockWithFile(const QString& filePath)
{
    const QString normalizedPath = QDir::toNativeSeparators(filePath.trimmed());
    if (normalizedPath.isEmpty())
    {
        return;
    }

    // 转储分析已并入杂项页：先激活杂项 Dock 并补上它的内容，
    // 再让杂项页把“转储分析”子页构造出来并切过去。
    MiscDock* const miscDock = activateMiscDockForMergedTab(QStringLiteral("转储分析"));
    if (miscDock == nullptr)
    {
        kLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 杂项页未能初始化，无法自动解析转储: "
            << normalizedPath.toStdString()
            << eol;
        return;
    }

    MinidumpDock* const minidumpPage = miscDock->activateMinidumpTab();
    if (minidumpPage == nullptr)
    {
        kLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 转储分析子页未能初始化，无法自动解析: "
            << normalizedPath.toStdString()
            << eol;
        return;
    }
    minidumpPage->openDumpFile(normalizedPath);
}

MiscDock* MainWindow::activateMiscDockForMergedTab(const QString& tabDisplayName)
{
    // 输入：并入杂项页的子页显示名，仅用于日志定位。
    // 处理：激活杂项 Dock 并确保其内容控件已构造。
    // 返回：杂项页内容控件；返回 nullptr 表示 Dock 尚不可用，调用方应放弃跳转。
    if (m_dockMisc == nullptr)
    {
        return nullptr;
    }

    // 杂项页同样是懒加载的，先补内容再激活，避免拿到占位控件。
    ensureDockContentInitialized(m_dockMisc);
    m_dockMisc->toggleView(true);
    m_dockMisc->raise();
    m_dockMisc->setAsCurrentTab();

    if (m_miscWidget == nullptr)
    {
        kLogEvent jumpEvent;
        warn << jumpEvent
            << "[MainWindow] 杂项页内容未初始化，跳转失败: "
            << tabDisplayName.toStdString()
            << eol;
    }
    return m_miscWidget;
}

void MainWindow::checkRecentCrashDumps()
{
    if (!m_currentAppearanceSettings.dumpAutoCheckEnabled)
    {
        return;
    }

    const ks::minidump::RecentDumpInfo recent = ks::minidump::FindRecentDump(24);
    if (!recent.found)
    {
        return;
    }

    // 同一个转储只问一次。路径和时间一起比：MEMORY.DMP 路径固定、
    // 内容会被下一次崩溃覆盖，只比路径会漏掉真正的新转储。
    const qint64 recentTimeMsec = recent.modifiedTime.toMSecsSinceEpoch();
    if (m_currentAppearanceSettings.dumpAutoCheckPromptedPath.compare(
            recent.filePath, Qt::CaseInsensitive) == 0 &&
        m_currentAppearanceSettings.dumpAutoCheckPromptedTimeMsec == recentTimeMsec)
    {
        return;
    }

    {
        kLogEvent dumpEvent;
        info << dumpEvent
            << "[MainWindow] 发现近期崩溃转储: "
            << recent.filePath.toStdString()
            << " 时间 " << recent.modifiedTime.toString(Qt::ISODate).toStdString()
            << " 窗口内共 " << recent.totalRecentCount << " 个"
            << eol;
    }

    // sizeText：按 MB 展示，小于 1 MB 时保留一位小数，避免显示成 0 MB。
    const double sizeMegabytes = static_cast<double>(recent.fileSizeBytes) / (1024.0 * 1024.0);
    const QString sizeText = sizeMegabytes >= 1.0
        ? QStringLiteral("%1 MB").arg(sizeMegabytes, 0, 'f', 1)
        : QStringLiteral("%1 KB").arg(recent.fileSizeBytes / 1024.0, 0, 'f', 1);

    QString bodyText = ks::i18n::text(
        QStringLiteral("mainwindow.dump.found.body"),
        QStringLiteral(
            "检测到系统在最近 24 小时内产生了新的崩溃转储：\n\n"
            "文件：%1\n时间：%2\n大小：%3\n\n"
            "是否现在解析它？"))
        .arg(recent.filePath)
        .arg(recent.modifiedTime.toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")))
        .arg(sizeText);
    if (recent.totalRecentCount > 1)
    {
        bodyText += ks::i18n::text(
            QStringLiteral("mainwindow.dump.found.multiple"),
            QStringLiteral("\n\n（窗口内共有 %1 个转储，这里列出的是最新的一个。）"))
            .arg(recent.totalRecentCount);
    }

    QMessageBox messageBox(this);
    messageBox.setIcon(QMessageBox::Question);
    messageBox.setWindowTitle(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.title"),
            QStringLiteral("发现新的崩溃转储")));
    messageBox.setText(bodyText);

    QCheckBox* const disableCheckBox = new QCheckBox(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.disable"),
            QStringLiteral("不再检查新的崩溃转储（可在设置-功能中重新开启）")),
        &messageBox);
    messageBox.setCheckBox(disableCheckBox);

    QPushButton* const parseButton = messageBox.addButton(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.parse"), QStringLiteral("立即解析")),
        QMessageBox::AcceptRole);
    messageBox.addButton(
        ks::i18n::text(QStringLiteral("mainwindow.dump.found.later"), QStringLiteral("以后再说")),
        QMessageBox::RejectRole);
    messageBox.exec();

    // 无论选哪个都记下"已经问过这一个"，否则下次启动会重复打扰。
    ks::settings::AppearanceSettings updatedSettings = m_currentAppearanceSettings;
    updatedSettings.dumpAutoCheckPromptedPath = recent.filePath;
    updatedSettings.dumpAutoCheckPromptedTimeMsec = recentTimeMsec;
    if (disableCheckBox->isChecked())
    {
        updatedSettings.dumpAutoCheckEnabled = false;
    }

    QString saveErrorText;
    if (!ks::settings::saveAppearanceSettings(updatedSettings, &saveErrorText))
    {
        kLogEvent dumpEvent;
        warn << dumpEvent
            << "[MainWindow] 保存转储检查状态失败: "
            << saveErrorText.toStdString()
            << eol;
    }
    // 设置页是打开设置对话框时才构造的局部对象，构造时会重新读 JSON，
    // 因此这里写完文件即可，不需要额外同步某个常驻实例。
    m_currentAppearanceSettings = updatedSettings;

    if (messageBox.clickedButton() == parseButton)
    {
        openMinidumpDockWithFile(recent.filePath);
    }
}

void MainWindow::initAppearanceSettings()
{
    // appearanceInitEvent 作用：统一追踪外观系统初始化流程日志。
    kLogEvent appearanceInitEvent;
    info << appearanceInitEvent << "[MainWindow] 开始初始化外观设置系统。" << eol;

    // raiseStartupDockByKey 作用：
    // - 按配置 key 激活启动默认主页签；
    // - key 非法或目标 Dock 不可用时自动回退到欢迎页。
    const auto raiseStartupDockByKey = [this](const QString& startupDockKey, const QString& triggerReason) {
        const QString normalizedKey = startupDockKey.trimmed().toLower();
        ads::CDockWidget* targetDock = nullptr;
        QString targetName = QStringLiteral("欢迎");

        if (normalizedKey == QStringLiteral("process"))
        {
            targetDock = m_dockProcess;
            targetName = QStringLiteral("进程");
        }
        else if (normalizedKey == QStringLiteral("network"))
        {
            targetDock = m_dockNetwork;
            targetName = QStringLiteral("网络");
        }
        else if (normalizedKey == QStringLiteral("memory"))
        {
            targetDock = m_dockMemory;
            targetName = QStringLiteral("内存");
        }
        else if (normalizedKey == QStringLiteral("file"))
        {
            targetDock = m_dockFile;
            targetName = QStringLiteral("文件");
        }
        else if (normalizedKey == QStringLiteral("driver"))
        {
            targetDock = m_dockDriver;
            targetName = QStringLiteral("驱动");
        }
        else if (normalizedKey == QStringLiteral("kernel"))
        {
            targetDock = m_dockKernel;
            targetName = QStringLiteral("内核");
        }
        else if (normalizedKey == QStringLiteral("monitor"))
        {
            targetDock = m_dockMonitorTab;
            targetName = QStringLiteral("监控");
        }
        else if (normalizedKey == QStringLiteral("hardware"))
        {
            targetDock = m_dockHardware;
            targetName = QStringLiteral("硬件");
        }
        else if (normalizedKey == QStringLiteral("privilege"))
        {
            targetDock = m_dockPrivilege;
            targetName = QStringLiteral("权限");
        }
        else if (normalizedKey == QStringLiteral("settings"))
        {
            // 旧配置可能仍保存 settings；设置已移动到顶部菜单，启动时回退欢迎页避免自动弹窗。
            targetDock = m_dockWelcome;
            targetName = QStringLiteral("欢迎");
        }
        else if (normalizedKey == QStringLiteral("window"))
        {
            targetDock = m_dockWindow;
            targetName = QStringLiteral("窗口");
        }
        else if (normalizedKey == QStringLiteral("registry"))
        {
            targetDock = m_dockRegistry;
            targetName = QStringLiteral("注册表");
        }
        else if (normalizedKey == QStringLiteral("handle"))
        {
            targetDock = m_dockHandle;
            targetName = QStringLiteral("句柄");
        }
        else if (normalizedKey == QStringLiteral("startup"))
        {
            targetDock = m_dockStartup;
            targetName = QStringLiteral("启动项");
        }
        else if (normalizedKey == QStringLiteral("service"))
        {
            targetDock = m_dockService;
            targetName = QStringLiteral("服务");
        }
        else if (normalizedKey == QStringLiteral("misc"))
        {
            targetDock = m_dockMisc;
            targetName = QStringLiteral("杂项");
        }
        else if (normalizedKey == QStringLiteral("winapi"))
        {
            targetDock = m_dockMonitorTab;
            targetName = QStringLiteral("监控/WinAPI");
        }
        else
        {
            targetDock = m_dockWelcome;
            targetName = QStringLiteral("欢迎");
        }

        if (targetDock == nullptr)
        {
            targetDock = m_dockWelcome;
            targetName = QStringLiteral("欢迎");
        }

        if (targetDock != nullptr)
        {
            ensureDockContentInitialized(targetDock);
            if (normalizedKey == QStringLiteral("winapi") && m_monitorWidget != nullptr)
            {
                m_monitorWidget->activateMonitorTab(QStringLiteral("winapi"));
            }
            withTemporaryNonTopMostForDockSwitch([targetDock]()
                {
                    targetDock->raise();
                });
            kLogEvent startupDockEvent;
            info << startupDockEvent
                << "[MainWindow] 已激活启动默认页签, trigger="
                << triggerReason.toStdString()
                << ", key="
                << normalizedKey.toStdString()
                << ", tab="
                << targetName.toStdString()
                << eol;
        }
    };

    // 启动画面细分：
    // - 设置页改为顶部菜单按需创建；
    // - 初始化时直接从 JSON 读取外观配置，再应用首轮主题样式。
    reportStartupProgress(
        86,
        QStringLiteral("main.startup.progress.read_appearance"),
        QStringLiteral("正在应用界面设置..."));
    m_currentAppearanceSettings = ks::settings::loadAppearanceSettings();

    QStyleHints* styleHints = QGuiApplication::styleHints();
    if (styleHints != nullptr)
    {
        connect(styleHints, &QStyleHints::colorSchemeChanged, this, [this](Qt::ColorScheme /*newScheme*/) {
            if (m_currentAppearanceSettings.themeMode == ks::settings::ThemeMode::FollowSystem)
            {
                applyAppearanceSettings(m_currentAppearanceSettings, QStringLiteral("系统颜色方案变化"));
            }
            });
    }

    reportStartupProgress(
        89,
        QStringLiteral("main.startup.progress.apply_main_style"),
        QStringLiteral("正在应用界面设置..."));
    applyAppearanceSettings(m_currentAppearanceSettings, QStringLiteral("初始化加载"));
    if (!m_dockLayoutRestoredFromConfig)
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.activate_startup_tab"),
            QStringLiteral("正在恢复界面布局..."));
        raiseStartupDockByKey(m_currentAppearanceSettings.startupDefaultTabKey, QStringLiteral("初始化加载"));
    }
    else
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.reuse_dock_layout"),
            QStringLiteral("正在恢复界面布局..."));
        info << appearanceInitEvent << "[MainWindow] 已恢复 ADS 布局，跳过启动默认页签覆盖。" << eol;
    }
    info << appearanceInitEvent << "[MainWindow] 外观设置系统初始化完成。" << eol;
}

void MainWindow::applyAppearanceSettings(
    const ks::settings::AppearanceSettings& settings,
    const QString& triggerReason)
{
    kLogEvent appearanceApplyEvent;
    QElapsedTimer appearanceApplyTimer;
    appearanceApplyTimer.start();

    const ks::settings::AppearanceSettings previousSettings = m_currentAppearanceSettings;
    const bool isInitialAppearanceApply = (triggerReason == QStringLiteral("初始化加载"));
    const bool darkModeEnabled = isDarkModeEffective(settings);
    const bool themeColorChanged =
        isInitialAppearanceApply
        || previousSettings.customThemeColor.compare(settings.customThemeColor, Qt::CaseInsensitive) != 0;
    const bool mainBackgroundColorChanged =
        isInitialAppearanceApply
        || previousSettings.customMainBackgroundColor.compare(
            settings.customMainBackgroundColor,
            Qt::CaseInsensitive) != 0;
    // 必须在读取任一 AccentColor 前更新种子，确保调色板、QSS 与绘制控件使用同一主题色。
    KswordTheme::SetPrimaryAccentColor(settings.customThemeColor);
    // 主背景使用独立种子，不参与强调色偏移；空值继续跟随当前深浅主题。
    KswordTheme::SetMainBackgroundColor(settings.customMainBackgroundColor);
    // 系统颜色方案通知已抵达时，previousSettings 再计算会得到新颜色方案；
    // 直接读取主题模块当前状态，才能识别 FollowSystem 的真实深浅色切换。
    const bool effectiveThemeChanged =
        isInitialAppearanceApply || KswordTheme::IsDarkModeEnabled() != darkModeEnabled;
    // themeVisualRefreshRequired 用途：作为所有专用主题控件的唯一重建条件。
    // 深浅主题、强调色或独立主背景色任一变化，都必须进入同一刷新入口。
    const bool themeVisualRefreshRequired =
        effectiveThemeChanged || themeColorChanged || mainBackgroundColorChanged;
    const bool backgroundPathChanged =
        isInitialAppearanceApply
        || previousSettings.backgroundImagePath.compare(
            settings.backgroundImagePath,
            Qt::CaseInsensitive) != 0;
    const bool backgroundChanged =
        mainBackgroundColorChanged
        || backgroundPathChanged
        || previousSettings.backgroundOpacityPercent != settings.backgroundOpacityPercent
        || previousSettings.backgroundTranslucencyMaterial.compare(
            settings.backgroundTranslucencyMaterial,
            Qt::CaseInsensitive) != 0
        // 玻璃观感三项都在 rebuildWindowBackgroundBrush 链路里生效（模糊副本、
        // 系统着色 gradientColor、根容器自绘着色），因此并入同一个背景刷新条件。
        || previousSettings.backgroundBlurRadiusPercent != settings.backgroundBlurRadiusPercent
        || previousSettings.acrylicTintOpacityPercent != settings.acrylicTintOpacityPercent
        || previousSettings.desktopTintOpacityPercent != settings.desktopTintOpacityPercent;
    // 背景穿透依赖启动时的 WA_TranslucentBackground 声明，运行期只提示重启生效。
    const bool backgroundTransparencyChanged =
        !isInitialAppearanceApply
        && previousSettings.backgroundTransparencyEnabled != settings.backgroundTransparencyEnabled;
    if (backgroundTransparencyChanged)
    {
        kLogEvent transparencyNoticeEvent;
        warn << transparencyNoticeEvent
            << "[MainWindow] 背景穿透设置已保存，重启 Ksword 后生效。"
            << eol;
    }
    const bool fontChanged =
        isInitialAppearanceApply
        || previousSettings.fontFamily.compare(settings.fontFamily, Qt::CaseInsensitive) != 0
        || previousSettings.textAntialiasingEnabled != settings.textAntialiasingEnabled;
    const bool scrollBarStyleChanged =
        isInitialAppearanceApply
        || previousSettings.useWideScrollBars != settings.useWideScrollBars
        || previousSettings.scrollBarAutoHideEnabled != settings.scrollBarAutoHideEnabled;
    const bool sliderWheelChanged =
        isInitialAppearanceApply
        || previousSettings.sliderWheelAdjustEnabled != settings.sliderWheelAdjustEnabled;
    const bool smoothScrollingChanged =
        isInitialAppearanceApply
        || previousSettings.smoothScrollingEnabled != settings.smoothScrollingEnabled;
    const bool topMostChanged =
        isInitialAppearanceApply
        || previousSettings.startupTopMostEnabled != settings.startupTopMostEnabled;
    const bool notificationSettingsChanged =
        isInitialAppearanceApply
        || previousSettings.notificationCardsEnabled != settings.notificationCardsEnabled
        || previousSettings.notificationMinimumLevel != settings.notificationMinimumLevel
        || previousSettings.notificationLogDisplaySeconds != settings.notificationLogDisplaySeconds
        || previousSettings.notificationDisplayPlacement != settings.notificationDisplayPlacement
        || previousSettings.notificationStackDirection != settings.notificationStackDirection;
    const bool runtimeProgressRequired =
        !isInitialAppearanceApply
        && (themeVisualRefreshRequired || backgroundChanged || fontChanged);

    m_currentAppearanceSettings = settings;
    ks::ui::DetailLayoutRegistry::applyGlobalScheme(settings.detailDisplayScheme);
    if (smoothScrollingChanged)
    {
        ks::ui::SetGlobalSmoothScrollingEnabled(settings.smoothScrollingEnabled);
    }
    RuntimeAppearanceProgress runtimeProgress(runtimeProgressRequired);

    // previousBackgroundImageReady 用途：路径切换前只读取内存缓存，判断透明策略是否变化。
    const bool previousBackgroundImageReady =
        isCachedBackgroundImageReady(previousSettings.backgroundImagePath);
    // backgroundReadinessChanged 用途：消费异步验证完成标记，使就绪结果触发一次视觉重建。
    const bool backgroundReadinessChanged = m_backgroundReadinessRefreshPending;
    m_backgroundReadinessRefreshPending = false;
    if (isInitialAppearanceApply || backgroundPathChanged)
    {
        runtimeProgress.update(
            8,
            QStringLiteral("main.runtime_appearance.progress.background"),
            QStringLiteral("正在应用界面设置..."));
        // 只有路径首次加载或真实变化时才异步验证；主题与滚动条变化不会进入文件系统。
        queueBackgroundImageValidation(settings.backgroundImagePath);
    }
    // windowTranslucencyActive 用途：窗口是否在启动时声明了 per-pixel 透明。
    // 该状态在进程生命周期内固定，运行期改配置只提示重启。
    const bool windowTranslucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    // enableDockContentTransparency 用途：决定 Dock 内容层是否透明。
    // 背景图就绪要透出图片；启用透明窗口背景时同样必须透明，
    // 否则 Dock 的不透明表面会盖住云母材质，只剩菜单栏区域可见。
    const bool enableDockContentTransparency =
        isCachedBackgroundImageReady(settings.backgroundImagePath) || windowTranslucencyActive;
    const bool dockTransparencyChanged =
        isInitialAppearanceApply
        || backgroundReadinessChanged
        || (previousBackgroundImageReady || windowTranslucencyActive) != enableDockContentTransparency;
    const bool mainStyleRefreshRequired =
        themeVisualRefreshRequired
        || dockTransparencyChanged
        || scrollBarStyleChanged;
    const bool backgroundRefreshRequired =
        isInitialAppearanceApply
        || effectiveThemeChanged
        || backgroundChanged
        || backgroundReadinessChanged;
    const bool floatingDockRefreshRequired = mainStyleRefreshRequired || backgroundRefreshRequired;
    qint64 globalAppStyleApplyMs = 0;
    int globalAppStyleWidgetCount = 0;
    int globalAppStyleLength = 0;
    qint64 styleSheetApplyElapsedMs = 0;
    ks::ui::SvgThemeIconApplyResult svgThemeIconApplyResult;
    bool globalAppStyleChanged = false;
    bool mainStyleSheetChanged = false;

    if (topMostChanged)
    {
        setPinnedWindowState(m_currentAppearanceSettings.startupTopMostEnabled, false);
    }

    if (themeVisualRefreshRequired)
    {
        runtimeProgress.update(
            16,
            QStringLiteral("main.runtime_appearance.progress.theme"),
            QStringLiteral("正在应用界面设置..."));

        KswordTheme::SetDarkModeEnabled(darkModeEnabled);
        const QColor windowBackgroundColor = KswordTheme::MainBackgroundColor();
        const QColor windowTextColor = KswordTheme::MainBackgroundTextColor();
        const QColor textColor = KswordTheme::TextPrimaryColor();
        const QColor baseColor = KswordTheme::SurfaceColor();
        const QColor alternateBaseColor = KswordTheme::SurfaceAltColor();
        const QColor midColor = KswordTheme::BorderColor();

        // Windows 11 背景控制要求：
        // 即使是纯黑/纯白，也必须显式设置 Window 颜色，避免系统接管背景。
        QPalette mainPalette = palette();
        mainPalette.setColor(QPalette::Window, windowBackgroundColor);
        mainPalette.setColor(QPalette::WindowText, windowTextColor);
        mainPalette.setColor(QPalette::Base, baseColor);
        mainPalette.setColor(QPalette::AlternateBase, alternateBaseColor);
        mainPalette.setColor(QPalette::Mid, midColor);
        mainPalette.setColor(QPalette::Midlight, KswordTheme::BorderStrongColor());
        mainPalette.setColor(QPalette::Dark, KswordTheme::PaletteDarkColor());
        mainPalette.setColor(QPalette::Text, textColor);
        mainPalette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        mainPalette.setColor(QPalette::Button, alternateBaseColor);
        mainPalette.setColor(QPalette::ButtonText, textColor);
        mainPalette.setColor(QPalette::ToolTipBase, baseColor);
        mainPalette.setColor(QPalette::ToolTipText, textColor);
        mainPalette.setColor(QPalette::Highlight, KswordTheme::PrimaryBlueColor);
        mainPalette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
        QApplication::setPalette(mainPalette);
        setPalette(mainPalette);
        // 背景穿透模式下主窗口不能自绘不透明底，否则穿透像素被 palette 底色盖住。
        setAutoFillBackground(!testAttribute(Qt::WA_TranslucentBackground));

        QPalette toolTipPalette = mainPalette;
        toolTipPalette.setColor(QPalette::ToolTipBase, baseColor);
        toolTipPalette.setColor(QPalette::ToolTipText, textColor);
        QToolTip::setPalette(toolTipPalette);

        globalAppStyleChanged = applyGlobalApplicationStyleBlocks(
            ks::ui::BuildGlobalBaseControlStyleBlock(),
            buildGlobalTooltipStyleBlock(darkModeEnabled),
            buildGlobalContextMenuStyleBlock(darkModeEnabled),
            buildGlobalControlContrastStyleBlock(darkModeEnabled),
            buildGlobalComboBoxStyleBlock(darkModeEnabled),
            &globalAppStyleApplyMs,
            &globalAppStyleWidgetCount,
            &globalAppStyleLength);
        if (globalAppStyleChanged || isInitialAppearanceApply)
        {
            dbg << appearanceApplyEvent
                << "[MainWindow] QApplication 全局 Tooltip/QMenu 样式"
                << (globalAppStyleChanged ? "已应用" : "未变化跳过")
                << ", elapsedMs=" << globalAppStyleApplyMs
                << ", widgetCount=" << globalAppStyleWidgetCount
                << ", styleLength=" << globalAppStyleLength
                << eol;
        }

        // 深浅色变化时，已打开的标准和自定义对话框也应同步主题。
        ks::ui::RefreshGlobalMessageBoxTheme();
        ks::ui::RefreshGlobalDialogTheme();
        // 已打开的原生标题栏子窗口同步染色，保持标题栏与主题背景一体。
        ks::ui::RefreshAllWindowChrome();

        if (m_pDockManager != nullptr)
        {
            QPalette dockPalette = m_pDockManager->palette();
            dockPalette.setColor(QPalette::Window, windowBackgroundColor);
            dockPalette.setColor(QPalette::WindowText, windowTextColor);
            dockPalette.setColor(QPalette::Text, textColor);
            m_pDockManager->setPalette(dockPalette);
            // 透明背景模式下 DockManager 不能自绘不透明底，否则整块盖住云母材质。
            m_pDockManager->setAutoFillBackground(!testAttribute(Qt::WA_TranslucentBackground));
        }
    }

    if (fontChanged)
    {
        runtimeProgress.update(
            46,
            QStringLiteral("main.runtime_appearance.progress.font"),
            QStringLiteral("正在应用界面设置..."));

        const QString requestedFontFamily = settings.fontFamily.trimmed();
        // applicationFont 用途：空 family 恢复启动时系统基线；具体 family 继续沿用当前字体其它属性。
        QFont applicationFont = requestedFontFamily.isEmpty()
            ? m_startupSystemFont
            : QApplication::font();
        if (!requestedFontFamily.isEmpty())
        {
            applicationFont.setFamily(requestedFontFamily);
        }
        const QFont::StyleStrategy requestedFontStyleStrategy = settings.textAntialiasingEnabled
            ? QFont::PreferAntialias
            : QFont::NoAntialias;
        applicationFont.setStyleStrategy(requestedFontStyleStrategy);
        // applicationFontChanged 用途：比较完整字体，确保从自定义字体恢复全部系统基线属性。
        const bool applicationFontChanged = QApplication::font() != applicationFont;
        if (applicationFontChanged)
        {
            QApplication::setFont(applicationFont);
        }
        applyApplicationFontToItemViews(applicationFont);
        QToolTip::setFont(QApplication::font());
    }

    // 把滚轮和文本渲染策略写入全局属性。无关配置保存时不再写入这些属性。
    if ((sliderWheelChanged || fontChanged)
        && qobject_cast<QApplication*>(QCoreApplication::instance()) != nullptr)
    {
        QApplication* const appInstance = qobject_cast<QApplication*>(QCoreApplication::instance());
        if (sliderWheelChanged)
        {
            appInstance->setProperty("ksword_slider_wheel_adjust_enabled", settings.sliderWheelAdjustEnabled);
        }
        if (fontChanged)
        {
            appInstance->setProperty("ksword_text_antialiasing_enabled", settings.textAntialiasingEnabled);
        }
    }

    if (mainStyleRefreshRequired)
    {
        runtimeProgress.update(
            66,
            QStringLiteral("main.runtime_appearance.progress.refresh"),
            QStringLiteral("正在应用界面设置..."));

        const QString appearanceStyleSheet =
            QSS_MainWindow_TabWidget
            + QSS_MainWindow_dockStyle
            + buildAppearanceOverlayStyleSheet(
                m_currentAppearanceSettings,
                darkModeEnabled,
                enableDockContentTransparency);

        QElapsedTimer styleSheetApplyTimer;
        styleSheetApplyTimer.start();
        mainStyleSheetChanged = (styleSheet() != appearanceStyleSheet);
        if (mainStyleSheetChanged)
        {
            setStyleSheet(appearanceStyleSheet);
        }
        ensureGlobalTableSelectionOutlineFilterInstalled();
        ensureGlobalComboPopupThemeFilterInstalled();
        applyResizeBorderOverlayStyle();
        updateResizeBorderOverlays();
        if (m_pDockManager != nullptr)
        {
            if (!m_pDockManager->styleSheet().isEmpty())
            {
                m_pDockManager->setStyleSheet(QString());
            }
            m_pDockManager->setAttribute(Qt::WA_StyledBackground, false);
            refreshAdsDockTabVisualIdentities(m_pDockManager);
        }
        styleSheetApplyElapsedMs = styleSheetApplyTimer.elapsed();
    }

    if (isInitialAppearanceApply)
    {
        reportStartupProgress(
            90,
            QStringLiteral("main.startup.progress.refresh_theme_widgets"),
            QStringLiteral("正在应用界面设置..."));
    }

    if (!isInitialAppearanceApply && dockTransparencyChanged)
    {
        repairKernelDockAfterLayoutRestore(QStringLiteral("applyAppearanceSettings"));
    }

    if (m_customTitleBar != nullptr && topMostChanged && !themeVisualRefreshRequired)
    {
        m_customTitleBar->setPinnedState(m_windowPinned);
    }

    if (backgroundRefreshRequired)
    {
        runtimeProgress.update(
            78,
            QStringLiteral("main.runtime_appearance.progress.background"),
            QStringLiteral("正在应用界面设置..."));
        rebuildWindowBackgroundBrush(true);
    }
    if (floatingDockRefreshRequired && m_pDockManager != nullptr)
    {
        const QList<ads::CFloatingDockContainer*> floatingWidgets = m_pDockManager->floatingWidgets();
        for (ads::CFloatingDockContainer* floatingWidget : floatingWidgets)
        {
            applyFloatingDockContainerAppearance(floatingWidget);
            if (floatingWidget != nullptr)
            {
                floatingWidget->update();
            }
        }
    }
    if (m_notificationCardManager != nullptr)
    {
        if (notificationSettingsChanged)
        {
            m_notificationCardManager->applySettings(m_currentAppearanceSettings);
        }
    }
    if (themeVisualRefreshRequired)
    {
        refreshThemeDependentVisuals(darkModeEnabled);

        runtimeProgress.update(
            88,
            QStringLiteral("main.runtime_appearance.progress.svg_icons"),
            QStringLiteral("正在集中适配 SVG 图标..."));
        QApplication* const applicationPointer =
            qobject_cast<QApplication*>(QCoreApplication::instance());
        const bool usesDefaultThemeColor =
            KswordTheme::PrimaryBlueColor == KswordTheme::DefaultPrimaryAccentColor();
        // SVG 图标批处理必须在各面板重建主题视觉后执行，避免后续刷新覆盖着色结果。
        // 回调只更新启动画面的文本与进度，不改变主题加载次序。
        const auto svgProgressCallback =
            [this, isInitialAppearanceApply](const int processedCount, const int totalCount)
            {
                if (!isInitialAppearanceApply)
                {
                    return;
                }
                const int svgProgressValue =
                    totalCount > 0
                    ? 88 + qBound(
                        0,
                        static_cast<int>(
                            (static_cast<qint64>(processedCount) * 3) /
                            totalCount),
                        3)
                    : 91;
                reportStartupProgress(
                    svgProgressValue,
                    totalCount > 0
                        ? QStringLiteral("main.startup.progress.recolor_svg_icons_count")
                        : QStringLiteral("main.startup.progress.recolor_svg_icons_skipped"),
                    totalCount > 0
                        ? QStringLiteral("正在集中适配 SVG 图标（%1/%2）...")
                            .arg(processedCount)
                            .arg(totalCount)
                        : QStringLiteral("默认主题色无需重新着色 SVG 图标。"));
            };
        svgThemeIconApplyResult =
            ks::ui::SvgThemeIconManager::instance().applyToApplication(
                applicationPointer,
                KswordTheme::PrimaryBlueColor,
                usesDefaultThemeColor,
                svgProgressCallback);
    }

    if (isInitialAppearanceApply)
    {
        reportStartupProgress(
            92,
            QStringLiteral("main.startup.progress.queue_kernel_dock_check"),
            QStringLiteral("即将完成..."));
        QTimer::singleShot(0, this, [this]()
            {
                repairKernelDockAfterLayoutRestore(QStringLiteral("applyAppearanceSettings-deferred-0"));
            });
    }

    runtimeProgress.update(
        100,
        QStringLiteral("main.runtime_appearance.progress.complete"),
        QStringLiteral("正在应用界面设置..."));

    const QString effectiveModeText = darkModeEnabled ? QStringLiteral("dark") : QStringLiteral("light");
    info << appearanceApplyEvent
        << "[MainWindow] 已应用外观设置，触发来源="
        << triggerReason.toStdString()
        << "，theme_mode="
        << ks::settings::themeModeToJsonText(settings.themeMode).toStdString()
        << "，effective_mode="
        << effectiveModeText.toStdString()
        << "，background_path="
        << settings.backgroundImagePath.toStdString()
        << "，opacity="
        << settings.backgroundOpacityPercent
        << "%, themeChanged="
        << (effectiveThemeChanged ? "true" : "false")
        << ", backgroundChanged="
        << (backgroundChanged ? "true" : "false")
        << ", mainBackgroundColorChanged="
        << (mainBackgroundColorChanged ? "true" : "false")
        << ", fontChanged="
        << (fontChanged ? "true" : "false")
        << ", mainStyleRefresh="
        << (mainStyleRefreshRequired ? "true" : "false")
        << ", styleChanged="
        << (mainStyleSheetChanged ? "true" : "false")
        << ", svgIconVisited="
        << svgThemeIconApplyResult.visitedWidgetCount
        << ", svgIconChanged="
        << svgThemeIconApplyResult.recoloredIconCount
        << ", svgIconCacheHits="
        << svgThemeIconApplyResult.cacheHitCount
        << ", svgIconDefaultSkipped="
        << (svgThemeIconApplyResult.skippedDefaultTheme ? "true" : "false")
        << ", svgIconElapsedMs="
        << svgThemeIconApplyResult.elapsedMilliseconds
        << "，styleElapsedMs="
        << styleSheetApplyElapsedMs
        << "，elapsedMs="
        << appearanceApplyTimer.elapsed()
        << eol;
}

void MainWindow::refreshThemeDependentVisuals(const bool darkModeEnabled)
{
    // 专用主题刷新统一从这里分发；调用者已先更新 KswordTheme 种子与主窗口 QSS。
    // 各刷新函数只重建视觉状态，不触发后台数据枚举或改变功能配置。
    if (m_processWidget != nullptr)
    {
        m_processWidget->refreshThemeVisuals();
    }
    if (m_windowWidget != nullptr)
    {
        m_windowWidget->refreshThemeVisuals();
    }

    if (m_customTitleBar != nullptr)
    {
        // 即使深浅状态未变，也要调用该入口以重建依赖自定义主题色的标题栏 QSS。
        m_customTitleBar->setDarkModeEnabled(darkModeEnabled);
        m_customTitleBar->setPinnedState(m_windowPinned);
        m_customTitleBar->setCaptureProtectionState(m_captureProtectionEnabled);
        syncCustomTitleBarMaximizedState();
    }

    // 原生框架、权限按钮和标题栏动作按钮均读取当前主题模块状态。
    applyNativeWindowFrameVisualStyle();
    refreshPrivilegeStatusButtons();
    refreshTitleActionButtonStyles();

    if (m_progressWidget != nullptr)
    {
        m_progressWidget->refreshThemeVisuals();
    }
    if (m_notificationCardManager != nullptr)
    {
        m_notificationCardManager->refreshVisuals();
    }
}

bool MainWindow::isDarkModeEffective(const ks::settings::AppearanceSettings& settings) const
{
    if (settings.themeMode == ks::settings::ThemeMode::Dark)
    {
        return true;
    }
    if (settings.themeMode == ks::settings::ThemeMode::Light)
    {
        return false;
    }

    QStyleHints* styleHints = QGuiApplication::styleHints();
    if (styleHints == nullptr)
    {
        return false;
    }
    return styleHints->colorScheme() == Qt::ColorScheme::Dark;
}

void MainWindow::queueBackgroundImageValidation(const QString& rawImagePath)
{
    // cacheKey 用途：只做内存比较；trimmed 不会访问 UNC 或离线盘。
    const QString cacheKey = rawImagePath.trimmed();
    ++m_backgroundImageValidationGeneration;
    // validationGeneration 用途：后台任务返回时淘汰已被更新路径取代的旧结果。
    const quint64 validationGeneration = m_backgroundImageValidationGeneration;
    m_backgroundImageCacheKey = cacheKey;
    m_backgroundImageResolvedPath.clear();
    m_backgroundImagePixmap = QPixmap();
    m_backgroundImageReady = false;
    // 模糊副本属于旧图，换路径时必须一并作废，否则新图解码前会短暂显示上一张的模糊结果。
    m_backgroundImageBlurredPixmap = QPixmap();
    m_backgroundImageBlurRadiusApplied = -1;
    m_backgroundImageBlurSourceCacheKey = 0;
    if (cacheKey.isEmpty())
    {
        return;
    }

    // guardedWindow 用途：后台任务可能晚于主窗口销毁，回投前必须验证生命周期。
    const QPointer<MainWindow> guardedWindow(this);
    QThreadPool::globalInstance()->start(
        [guardedWindow, rawImagePath, cacheKey, validationGeneration]()
        {
            // 以下路径解析、QFileInfo 探测和图片解码全部在线程池执行。
            // 不可达 UNC 只会占用后台任务，不会阻塞 Qt UI 事件循环。
            const QString resolvedImagePath =
                ks::settings::resolveBackgroundImagePathForLoad(rawImagePath);
            QImage decodedImage;
            if (!resolvedImagePath.trimmed().isEmpty())
            {
                // imageFileInfo 用途：验证目标存在、为普通文件且当前可读。
                const QFileInfo imageFileInfo(resolvedImagePath);
                if (imageFileInfo.exists()
                    && imageFileInfo.isFile()
                    && imageFileInfo.isReadable())
                {
                    decodedImage.load(resolvedImagePath);
                }
            }

            QCoreApplication* const appInstance = QCoreApplication::instance();
            if (appInstance == nullptr)
            {
                return;
            }
            QMetaObject::invokeMethod(
                appInstance,
                [guardedWindow,
                    cacheKey,
                    resolvedImagePath,
                    validationGeneration,
                    decodedImage]()
                {
                    if (guardedWindow == nullptr)
                    {
                        return;
                    }
                    MainWindow* const mainWindow = guardedWindow.data();
                    const bool resultIsCurrent =
                        mainWindow->m_backgroundImageValidationGeneration == validationGeneration
                        && mainWindow->m_backgroundImageCacheKey.compare(
                            cacheKey,
                            Qt::CaseInsensitive) == 0;
                    if (!resultIsCurrent)
                    {
                        return;
                    }

                    mainWindow->m_backgroundImageResolvedPath = resolvedImagePath;
                    mainWindow->m_backgroundImagePixmap = decodedImage.isNull()
                        ? QPixmap()
                        : QPixmap::fromImage(decodedImage);
                    // nextReady 用途：只有路径验证和图片解码均成功才允许透明 Dock。
                    const bool nextReady = !mainWindow->m_backgroundImagePixmap.isNull();
                    const bool readinessChanged =
                        mainWindow->m_backgroundImageReady != nextReady;
                    mainWindow->m_backgroundImageReady = nextReady;
                    if (!readinessChanged)
                    {
                        return;
                    }

                    // 异步结果只设置一次性重建标记；再次应用同一设置不会重新验证路径。
                    mainWindow->m_backgroundReadinessRefreshPending = true;
                    mainWindow->applyAppearanceSettings(
                        mainWindow->m_currentAppearanceSettings,
                        QStringLiteral("背景图异步验证完成"));
                },
                Qt::QueuedConnection);
        });
}

bool MainWindow::isCachedBackgroundImageReady(const QString& rawImagePath) const
{
    // requestedCacheKey 用途：仅规范首尾空白，不解析路径也不查询文件系统。
    const QString requestedCacheKey = rawImagePath.trimmed();
    return !requestedCacheKey.isEmpty()
        && m_backgroundImageCacheKey.compare(requestedCacheKey, Qt::CaseInsensitive) == 0
        && m_backgroundImageReady
        && !m_backgroundImagePixmap.isNull();
}

bool MainWindow::shouldRenderTransparentDockContent() const
{
    return isCachedBackgroundImageReady(m_currentAppearanceSettings.backgroundImagePath)
        || testAttribute(Qt::WA_TranslucentBackground);
}

const QPixmap* MainWindow::cachedBackgroundImage(const QString& rawImagePath) const
{
    if (!isCachedBackgroundImageReady(rawImagePath))
    {
        return nullptr;
    }
    // 模糊副本只在“玻璃模糊半径”>0 且已由 refreshBackgroundImageBlurCache 生成时替换原图；
    // 主窗口根容器与浮动 Dock 画刷都走这里，因此两者永远取到同一张底图。
    return m_backgroundImageBlurredPixmap.isNull()
        ? &m_backgroundImagePixmap
        : &m_backgroundImageBlurredPixmap;
}

void MainWindow::scheduleWindowBackdropRefresh()
{
    // 只有系统亚克力正在生效时才需要按窗口位置重采样；其余状态直接忽略。
    if (m_backdropMaterialState != static_cast<int>(BackdropBlurKind::Acrylic)
        || m_backdropRefreshQueued)
    {
        return;
    }

    // 拖动与缩放会连续产生事件，这里合并成一次延迟刷新：
    // - 既能在动作结束后拿到正确画面，也不会在拖动过程中反复下发组合特性。
    m_backdropRefreshQueued = true;
    QTimer::singleShot(kBackdropRefreshThrottleMs, this, [this]()
        {
            m_backdropRefreshQueued = false;
            if (m_backdropMaterialState != static_cast<int>(BackdropBlurKind::Acrylic))
            {
                return;
            }
            // 只重新下发组合特性，恢复可能被系统降级掉的材质状态。
            // 这里不再触发根容器重绘：亚克力由 DWM 在合成器里生成，
            // 应用侧像素一个都没变，而透明模式下的整树重绘实测约 41ms。
            // 真正需要重画背景的场景（尺寸变化）由 resizeEvent 自己 update。
            refreshWindowBackdropMaterial();
        });
}

void MainWindow::refreshWindowBackdropMaterial()
{
    // translucencyActive 用途：窗口是否在启动时声明了 per-pixel 透明。
    const bool translucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    const int normalizedOpacityPercent = normalizeOpacityPercent(
        m_currentAppearanceSettings.backgroundOpacityPercent);
    // sourceImage 用途：只读取解码缓存，材质决策不访问文件系统。
    const QPixmap* sourceImage = normalizedOpacityPercent > 0
        ? cachedBackgroundImage(m_currentAppearanceSettings.backgroundImagePath)
        : nullptr;

    // 材质决策按用户显式选择：
    // - acrylic：始终亚克力磨砂；desktop：始终直透桌面；
    // - auto（默认）：有背景图直透，无背景图用亚克力磨砂。
    // 兼容：旧配置值 blur/mica 都曾表示“磨砂”，统一迁移到亚克力——
    // Windows 11 上传统 BLURBEHIND 已退化为纯透明，亚克力是唯一真实磨砂。
    const QString translucencyMaterialMode =
        m_currentAppearanceSettings.backgroundTranslucencyMaterial.trimmed().toLower();
    BackdropBlurKind blurKind = BackdropBlurKind::None;
    if (translucencyActive)
    {
        if (translucencyMaterialMode == QStringLiteral("acrylic")
            || translucencyMaterialMode == QStringLiteral("blur")
            || translucencyMaterialMode == QStringLiteral("mica"))
        {
            blurKind = BackdropBlurKind::Acrylic;
        }
        else if (translucencyMaterialMode == QStringLiteral("desktop"))
        {
            blurKind = BackdropBlurKind::None;
        }
        else
        {
            blurKind = (sourceImage == nullptr)
                ? BackdropBlurKind::Acrylic
                : BackdropBlurKind::None;
        }
    }

    // acrylicMaterialActive 用途：系统亚克力是否真正生效。
    // 生效时着色由系统合成，根容器必须近乎完全透明；
    // 未生效（旧系统或调用失败）则回退为自绘着色层，保证前景文字仍然可读。
    const bool acrylicMaterialActive = applyMainWindowBackdropMaterial(blurKind);
    if (m_mainRootContainer != nullptr)
    {
        static_cast<MainWindowBackgroundWidget*>(m_mainRootContainer)->setTranslucentMode(
            translucencyActive,
            !acrylicMaterialActive,
            ks::settings::tintAlphaFromOpacityPercent(
                m_currentAppearanceSettings.desktopTintOpacityPercent));
    }
}

void MainWindow::refreshBackgroundImageBlurCache()
{
    const int blurRadiusPercent = normalizeOpacityPercent(
        m_currentAppearanceSettings.backgroundBlurRadiusPercent);
    // sourceCacheKey 用途：换图或重新解码后 cacheKey 必然变化，据此淘汰过期模糊副本；
    // 只比较半径会让“路径变了但半径没变”的场景继续用旧图的模糊结果。
    const quint64 sourceCacheKey = m_backgroundImagePixmap.isNull()
        ? 0
        : m_backgroundImagePixmap.cacheKey();
    if (m_backgroundImageBlurRadiusApplied == blurRadiusPercent
        && m_backgroundImageBlurSourceCacheKey == sourceCacheKey)
    {
        return;
    }

    m_backgroundImageBlurRadiusApplied = blurRadiusPercent;
    m_backgroundImageBlurSourceCacheKey = sourceCacheKey;
    // 半径为 0 时不生成副本：cachedBackgroundImage 会回落到解码原图，零额外内存与耗时。
    m_backgroundImageBlurredPixmap = (blurRadiusPercent > 0)
        ? buildBlurredPixmap(m_backgroundImagePixmap, blurRadiusPercent)
        : QPixmap();
}

void MainWindow::rebuildWindowBackgroundBrush(const bool includeBackgroundImage)
{
    // 纯色底与背景图合成都使用独立主背景色；未自定义时回退当前深浅主题默认色。
    const QColor baseColor = KswordTheme::MainBackgroundColor();

    // 模糊副本必须先于任何 cachedBackgroundImage 取图刷新：
    // 本次调用链里的根容器、浮动 Dock 与材质决策都会读取该缓存。
    refreshBackgroundImageBlurCache();

    const int normalizedOpacityPercent = normalizeOpacityPercent(
        m_currentAppearanceSettings.backgroundOpacityPercent);
    // sourceImage 用途：只读取异步解码缓存，主题刷新不会再次访问原始路径。
    const QPixmap* sourceImage = includeBackgroundImage && normalizedOpacityPercent > 0
        ? cachedBackgroundImage(m_currentAppearanceSettings.backgroundImagePath)
        : nullptr;

    // translucencyActive 用途：窗口在启动时按配置声明了 per-pixel 透明；
    // 此时底色层交给根容器按穿透模式绘制，主窗口自身不再填充不透明背景。
    const bool translucencyActive = testAttribute(Qt::WA_TranslucentBackground);
    refreshWindowBackdropMaterial();
    if (m_mainRootContainer != nullptr)
    {
        static_cast<MainWindowBackgroundWidget*>(m_mainRootContainer)->setBackground(
            baseColor,
            sourceImage,
            normalizedOpacityPercent);
    }

    QPalette mainPalette = palette();
    mainPalette.setColor(QPalette::Window, baseColor);
    setPalette(mainPalette);
    setAutoFillBackground(!translucencyActive);

    if (m_pDockManager != nullptr)
    {
        QPalette dockPalette = m_pDockManager->palette();
        dockPalette.setColor(QPalette::Window, baseColor);
        m_pDockManager->setPalette(dockPalette);
        // DockManager 只负责透明内容层，背景统一由根容器绘制。
        m_pDockManager->setAutoFillBackground(false);
    }
}

void MainWindow::applyFloatingDockContainerAppearance(ads::CFloatingDockContainer* floatingWidget) const
{
    if (floatingWidget == nullptr)
    {
        return;
    }

    const bool darkModeEnabled = isDarkModeEffective(m_currentAppearanceSettings);
    const QColor baseColor = KswordTheme::MainBackgroundColor();
    const bool enableDockContentTransparency =
        isCachedBackgroundImageReady(m_currentAppearanceSettings.backgroundImagePath);
    // sourceImage 用途：浮动容器复用线程池解码结果，不执行路径探测或文件加载。
    const QPixmap* sourceImage =
        cachedBackgroundImage(m_currentAppearanceSettings.backgroundImagePath);

    // floatingSize 用途：浮动容器当前尺寸；无效时至少给 1x1，避免画刷构造失败。
    const QSize floatingSize = floatingWidget->size().isValid() ? floatingWidget->size() : QSize(1, 1);
    const QBrush backgroundBrush = buildBackgroundBrush(
        floatingSize,
        baseColor,
        sourceImage,
        m_currentAppearanceSettings.backgroundOpacityPercent);

    QPalette floatingPalette = floatingWidget->palette();
    floatingPalette.setColor(QPalette::Window, baseColor);
    floatingPalette.setBrush(QPalette::Window, backgroundBrush);
    floatingPalette.setColor(
        QPalette::WindowText,
        KswordTheme::MainBackgroundTextColor());
    floatingWidget->setPalette(floatingPalette);
    floatingWidget->setAutoFillBackground(true);
    floatingWidget->setAttribute(Qt::WA_StyledBackground, false);

    // 浮动窗口是独立顶层窗口，不继承 MainWindow 的局部样式表；
    // 这里显式复用同一套外观样式，确保 Tab/TitleBar/内容区规则一致。
    const QString appearanceStyleSheet =
        QSS_MainWindow_TabWidget
        + QSS_MainWindow_dockStyle
        + buildAppearanceOverlayStyleSheet(
            m_currentAppearanceSettings,
            darkModeEnabled,
            enableDockContentTransparency);
    floatingWidget->setStyleSheet(appearanceStyleSheet);
    refreshAdsDockTabVisualIdentities(floatingWidget);

    ads::CDockContainerWidget* dockContainer = floatingWidget->dockContainer();
    if (dockContainer != nullptr)
    {
        QPalette dockContainerPalette = dockContainer->palette();
        dockContainerPalette.setColor(QPalette::Window, baseColor);
        dockContainerPalette.setBrush(QPalette::Window, backgroundBrush);
        dockContainer->setPalette(dockContainerPalette);
        dockContainer->setAutoFillBackground(true);
        dockContainer->setAttribute(Qt::WA_StyledBackground, false);
    }
}

QString MainWindow::buildAppearanceOverlayStyleSheet(
    const ks::settings::AppearanceSettings& settings,
    const bool darkModeEnabled,
    const bool enableDockContentTransparency) const
{
    // tooltipStyle 作用：
    // - 强制全局提示框采用主题化背景和文字；
    // - 修复深色模式下 Tooltip 仍为白底的问题。
    const int scrollBarHoverExtentPx = settings.useWideScrollBars ? 12 : 7;
    const int scrollBarExtentPx = settings.scrollBarAutoHideEnabled ? 3 : scrollBarHoverExtentPx;
    const int scrollBarRadiusPx = 0;
    const QString windowBackgroundText = KswordTheme::MainBackgroundColorHex();
    const QString windowTextColor = KswordTheme::MainBackgroundTextColorHex();
    const QString surfaceBackgroundText = KswordTheme::SurfaceColorHex();
    const QString surfaceAltBackgroundText = KswordTheme::SurfaceAltColorHex();
    const QString surfaceMutedBackgroundText = KswordTheme::SurfaceMutedColorHex();
    const QString borderColorText = KswordTheme::BorderColorHex();
    const QString borderStrongColorText = KswordTheme::BorderStrongColorHex();
    const QString primaryTextColor = KswordTheme::TextPrimaryColorHex();
    const QString disabledTextColor = KswordTheme::TextDisabledColorHex();
    const QString selectedTextColor = KswordTheme::OnAccentHex();
    const QString activeThemeColor = KswordTheme::PrimaryBlueHex;
    const QString activeThemeHoverColor = KswordTheme::ControlAccentHoverHex();
    const QString activeThemePressedColor = KswordTheme::ControlAccentPressedHex();
    const QString controlAccentTextColor = KswordTheme::ThemeColorName(
        KswordTheme::MaximumContrastMonochromeColor(KswordTheme::ControlAccentColor()));
    const QString subtleThemeColor = KswordTheme::PrimaryBlueSubtleHex();
    const QColor scrollBarBaseColor = settings.scrollBarAutoHideEnabled
        ? KswordTheme::EnsureTextContrast(
            KswordTheme::BlendColors(
                KswordTheme::SurfaceColor(),
                KswordTheme::ControlAccentColor(),
                160),
            KswordTheme::SurfaceColor(),
            3.0)
        : KswordTheme::ControlAccentColor();
    const QString scrollBarHandleColor = KswordTheme::ThemeColorName(scrollBarBaseColor);
    const QString scrollBarHandleHoverColor = KswordTheme::ControlAccentHoverHex();
    const QString panelBackgroundColor = KswordTheme::RgbaColorName(
        KswordTheme::SurfaceColor(),
        darkModeEnabled ? 240 : 242);
    const QString panelBorderColor = borderColorText;
    const QString inactiveTabColor = surfaceAltBackgroundText;
    const QString inactiveTabTextColor = primaryTextColor;
    const QString activeTabColor = KswordTheme::ActiveTabBackgroundHex();
    const QString activeTabTextColor = KswordTheme::ActiveTabTextHex();
    // normalTabHoverColor 作用：
    // - 只控制普通 QTabBar 的未选中悬停态；
    // - 浅色模式使用明确的浅灰色，避免继承/回退到黑色背景；
    // - ADS Dock tab 继续使用下面的 dockTabChildHoverColor，不在这里改动。
    const QString normalTabHoverColor = KswordTheme::ThemeColorName(
        darkModeEnabled ? KswordTheme::PrimaryBlueSubtleColor() : KswordTheme::SurfaceMutedColor());
    // dockActiveTabTextColor 作用：
    // - 只控制 ADS Dock 选中标签文字；
    // - 深浅模式统一使用白字，修复深色活动背景上的低对比文字；
    // - 普通 QTabBar 仍沿用 activeTabTextColor，避免扩大样式影响面。
    const QString dockActiveTabTextColor = KswordTheme::ThemeColorName(
        dockTabTextColor(true));
    const QString tabHoverColor = darkModeEnabled
        ? KswordTheme::ThemeColorName(KswordTheme::PrimaryBlueSubtleColor())
        : subtleThemeColor;
    // dockTabChildHoverColor 作用：
    // - ADS Dock 标签内部常由 QLabel/QWidget 组合绘制；
    // - 深色模式下如果子控件继续透明或继承错误 palette，会露出近白底；
    // - 因此 hover 时父子统一使用明确背景色，避免半透明/调色板回退。
    const QString dockTabChildHoverColor = tabHoverColor;
    const QString tooltipStyle = QStringLiteral(
        "QToolTip{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:1px solid %3 !important;"
        "  padding:4px 6px;"
        "  border-radius:3px;"
        "}")
        .arg(surfaceBackgroundText)
        .arg(primaryTextColor)
        .arg(borderStrongColorText);

    // dockBackgroundPolicyStyle 作用：
    // - 背景图可用时：Dock 相关容器全部透明，让底图完整透出；
    // - 背景图不可用时：保持 DockManager 使用 palette(window) 作为背景底色。
    const QString dockBackgroundPolicyStyle = enableDockContentTransparency
        ? QStringLiteral(
            "QDockWidget,"
            "QDockWidget::title,"
            "QDockWidget > QWidget,"
            "ads--CDockManager,"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CDockAreaTitleBar,"
            "ads--CFloatingDockContainer,"
            "ads--CDockAreaTabBar{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}")
        : QStringLiteral(
            "ads--CDockManager{"
            "  background-color:palette(window) !important;"
            "  color:%1 !important;"
            "}"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CFloatingDockContainer{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "ads--CDockAreaTitleBar{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}");

    // rootStyle 作用：
    // - 主窗口继续使用 palette(window)（含背景图画刷）作为底图来源；
    // - 再叠加 Dock 背景策略样式。
    const QString rootStyle = QStringLiteral(
        "QMainWindow{"
        "  background-color:palette(window) !important;"
        "  color:%1;"
        "}")
        .arg(windowTextColor)
        + dockBackgroundPolicyStyle.arg(
            windowTextColor);

    // depthOverlayStyle 作用：
    // - 为 Dock 面板、分组、表格和 Tab 增加边界/圆角/轻阴影感；
    // - 让当前 Tab 使用与图标错开的深浅对比色，避免蓝色图标在蓝底上不可见。
    const QString depthOverlayStyle = QStringLiteral(
        "ads--CDockAreaWidget{"
        "  border:1px solid %1 !important;"
        "  border-radius:8px;"
        "  background:%2 !important;"
        "}"
        "ads--CDockAreaTitleBar{"
        "  border-bottom:none !important;"
        "  padding:0px;"
        "}"
        "QGroupBox,QFrame#card,QWidget#card{"
        "  border:1px solid %1;"
        "  border-radius:8px;"
        "  background:%2;"
        "  margin-top:12px;"
        "}"
        "QGroupBox{"
        "  padding-top:6px;"
        "}"
        "QGroupBox::title{"
        "  subcontrol-origin:margin;"
        "  subcontrol-position:top left;"
        "  left:10px;"
        "  padding:0px 4px;"
        "  background:%2;"
        "  color:%3;"
        "}"
        "QTabWidget::pane{"
        "  border:none !important;"
        "  border-radius:0px;"
        "  background:%2 !important;"
        "  top:0px;"
        "}"
        "QHeaderView::section{"
        "  font-weight:600;"
        "  min-height:24px;"
        "}")
        .arg(panelBorderColor)
        .arg(panelBackgroundColor)
        .arg(primaryTextColor);

    // scrollBarOverlayStyle 作用：
    // - 全局改为透明轨道，减少遮挡；
    // - 根据设置切换窄/宽滚动条，并支持默认弱显示、悬停增强。
    const QString scrollBarOverlayStyle = QStringLiteral(
        "QScrollBar:vertical{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  width:%1px !important;"
        "  margin:0px;"
        "}"
        "QScrollBar:horizontal{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  height:%1px !important;"
        "  margin:0px;"
        "}"
        "QScrollBar:vertical:hover{"
        "  width:%5px !important;"
        "}"
        "QScrollBar:horizontal:hover{"
        "  height:%5px !important;"
        "}"
        "QScrollBar::handle:vertical{"
        "  background-color:%3 !important;"
        "  min-height:24px;"
        "  border-radius:%2px;"
        "}"
        "QScrollBar::handle:horizontal{"
        "  background-color:%3 !important;"
        "  min-width:24px;"
        "  border-radius:%2px;"
        "}"
        "QScrollBar::handle:vertical:hover,QScrollBar::handle:horizontal:hover{"
        "  background-color:%4 !important;"
        "}"
        "QScrollBar::add-line,QScrollBar::sub-line,QScrollBar::add-page,QScrollBar::sub-page{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  width:0px;"
        "  height:0px;"
        "}")
        .arg(scrollBarExtentPx)
        .arg(scrollBarRadiusPx)
        .arg(scrollBarHandleColor)
        .arg(scrollBarHandleHoverColor)
        .arg(scrollBarHoverExtentPx);

    // sharedOverlayStyle 作用：
    // - 统一 hover/pressed 与 Tab 高亮；
    // - 当前 Tab 采用反差色，避免图标与选中底色混在一起。
    const QString buttonInteractionStyle = QStringLiteral(
        "QPushButton,QToolButton{"
        "  background-color:%4 !important;"
        "  color:%5 !important;"
        "  border:1px solid %6 !important;"
        "}"
        "QPushButton:hover,QToolButton:hover{"
        "  background-color:%1 !important;"
        "  color:%3 !important;"
        "  border-color:%1 !important;"
        "}"
        "QPushButton:pressed,QToolButton:pressed{"
        "  background-color:%2 !important;"
        "  color:%3 !important;"
        "  border-color:%2 !important;"
        "}"
        "QPushButton:disabled,QToolButton:disabled{"
        "  background-color:%7 !important;"
        "  color:%8 !important;"
        "  border-color:%6 !important;"
        "}")
        .arg(activeThemeHoverColor)
        .arg(activeThemePressedColor)
        .arg(controlAccentTextColor)
        .arg(darkModeEnabled ? surfaceAltBackgroundText : subtleThemeColor)
        .arg(primaryTextColor)
        .arg(borderStrongColorText)
        .arg(surfaceMutedBackgroundText)
        .arg(disabledTextColor);

    // tabStyle 作用：统一普通 Tab 与 ADS Dock Tab 的颜色、边距和选中态。
    // 字号不在这里设置，保证所有 Tab 栏继承 Qt 默认应用字号。
    const QString tabStyle = QStringLiteral(
        "QTabBar{"
        "  border:none !important;"
        "}"
        "QTabBar::tab{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "  border-radius:0px !important;"
        "  padding:3px 12px;"
        "  min-height:22px;"
        "  margin:0px;"
        "}"
        "QTabBar::tab:left,QTabBar::tab:right{"
        "  padding:5px 6px;"
        "}"
        "QTabBar::tab:selected{"
        "  background-color:%4 !important;"
        "  color:%5 !important;"
        "  font-weight:700;"
        "}"
        "QTabBar::tab:hover:!selected{"
        "  background-color:%9 !important;"
        "  background:%9 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabBar::tab:hover:!selected,"
        "QMainWindow QTabBar::tab:pressed:!selected{"
        "  background-color:%9 !important;"
        "  background:%9 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabBar::tab:selected:hover,"
        "QMainWindow QTabBar::tab:selected:pressed{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%5 !important;"
        "}"
        "ads--CDockAreaTabBar{"
        "  background:transparent !important;"
        "  border:none !important;"
        "  padding:0px;"
        "}"
        "ads--CDockWidgetTab,ads--CAutoHideTab{"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "  border-radius:0px !important;"
        "  padding:3px 12px;"
        "  margin:0px;"
        "  min-height:22px;"
        "}"
        "ads--CDockWidgetTab QLabel,ads--CAutoHideTab QLabel{"
        "  color:%2 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"],ads--CAutoHideTab[activeTab=\"true\"]{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%8 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"] QLabel,"
        "ads--CDockWidgetTab[activeTab=\"true\"] QWidget,"
        "ads--CAutoHideTab[activeTab=\"true\"] QLabel,"
        "ads--CAutoHideTab[activeTab=\"true\"] QWidget{"
        "  color:%8 !important;"
        "  background-color:transparent !important;"
        "  background:transparent !important;"
        "  font-weight:700;"
        "}"
        "ads--CDockWidgetTab:hover,"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover,"
        "ads--CAutoHideTab:hover,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "}"
        "ads--CDockWidgetTab:hover[activeTab=\"false\"],"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover[activeTab=\"false\"],"
        "ads--CAutoHideTab:hover[activeTab=\"false\"],"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover[activeTab=\"false\"]{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "}"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover{"
        "  background-color:%6 !important;"
        "  background:%6 !important;"
        "  color:%2 !important;"
        "  border:none !important;"
        "}"
        "ads--CDockWidgetTab:hover QLabel,ads--CDockWidgetTab:hover QWidget,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover QLabel,"
        "ads--CDockWidgetTab[kswordDockTab=\"true\"]:hover QWidget,"
        "ads--CAutoHideTab:hover QLabel,ads--CAutoHideTab:hover QWidget,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover QLabel,"
        "ads--CAutoHideTab[kswordAutoHideTab=\"true\"]:hover QWidget,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QLabel,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CDockWidgetTab:hover QWidget,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QLabel,"
        "ads--CDockAreaWidget ads--CDockAreaTitleBar ads--CAutoHideTab:hover QWidget{"
        "  color:%2 !important;"
        "  background-color:%7 !important;"
        "  background:%7 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover{"
        "  background-color:%4 !important;"
        "  background:%4 !important;"
        "  color:%8 !important;"
        "}"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover QLabel,"
        "ads--CDockWidgetTab[activeTab=\"true\"]:hover QWidget,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover QLabel,"
        "ads--CAutoHideTab[activeTab=\"true\"]:hover QWidget{"
        "  color:%8 !important;"
        "  background-color:transparent !important;"
        "  background:transparent !important;"
        "}"
        "ads--CDockAreaTitleBar QToolButton,ads--CDockAreaTitleBar QPushButton{"
        "  border:none !important;"
        "  background:transparent !important;"
        "}")
        .arg(inactiveTabColor)
        .arg(inactiveTabTextColor)
        .arg(panelBorderColor)
        .arg(activeTabColor)
        .arg(activeTabTextColor)
        .arg(tabHoverColor)
        .arg(dockTabChildHoverColor)
        .arg(dockActiveTabTextColor)
        .arg(normalTabHoverColor);

    const QString sharedOverlayStyle = depthOverlayStyle
        + scrollBarOverlayStyle
        + buttonInteractionStyle
        + tabStyle;    // dockContentTransparentStyle 作用：
    // - 背景图可用时，把 Dock 内容区域常见容器背景全部改为透明；
    // - 修复“Dock 面板整体仍是黑底/白底，背景图只能从缝隙看到”的问题。
    // 注意：该片段只作用于 ads--CDockWidget 后代，不影响菜单栏等全局区域。
    const QString dockContentTransparentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget,"
            "ads--CDockWidget > QWidget,"
            "ads--CDockWidget QFrame,"
            "ads--CDockWidget QTabWidget::pane,"
            "ads--CDockWidget QStackedWidget,"
            "ads--CDockWidget QStackedWidget > QWidget,"
            "ads--CDockWidget QSplitter,"
            "ads--CDockWidget QSplitter::handle,"
            "ads--CDockWidget QScrollArea,"
            "ads--CDockWidget QAbstractScrollArea,"
            "ads--CDockWidget QAbstractScrollArea::viewport,"
            "ads--CDockWidget QTableView,"
            "ads--CDockWidget QTableWidget,"
            "ads--CDockWidget QTreeView,"
            "ads--CDockWidget QTreeWidget,"
            "ads--CDockWidget QListView,"
            "ads--CDockWidget QListWidget,"
            "ads--CDockWidget QTextEdit,"
            "ads--CDockWidget QPlainTextEdit,"
            "ads--CDockWidget QGroupBox{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}"
            "ads--CDockWidget QTableView,"
            "ads--CDockWidget QTableWidget,"
            "ads--CDockWidget QTreeView,"
            "ads--CDockWidget QTreeWidget,"
            "ads--CDockWidget QListView,"
            "ads--CDockWidget QListWidget{"
            "  alternate-background-color:transparent !important;"
            "}")
        : QString();

    // finalDockAreaTransparentStyle 作用：
    // - 作为背景图模式下的最后一道 Dock 区域透明兜底规则；
    // - 覆盖 depthOverlayStyle 中 ads--CDockAreaWidget 的半透明面板底色；
    // - 避免切换到某些 Dock 后共享 DockArea 被重新刷成纯色，导致背景图像“传染式”消失；
    // - 不覆盖 ads--CDockWidgetTab 本身，保留 Dock 标签页选中态和悬停态的主题色。
    const QString finalDockAreaTransparentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockManager,"
            "ads--CDockContainerWidget,"
            "ads--CDockAreaWidget,"
            "ads--CDockAreaWidget > QWidget,"
            "ads--CDockAreaTitleBar,"
            "ads--CDockAreaTabBar,"
            "ads--CDockWidget,"
            "ads--CDockWidget > QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "}")
        : QString();

    // kernelDockContainerStyle 作用：
    // - 无背景图：内核 Dock 根容器保持主题实底，防止 ADS 恢复布局后露出黑色父容器；
    // - 有背景图：根容器、Tab pane、StackedWidget 改为透明，让主窗口背景图透出。
    // 返回：仅控制内核 Dock 外层/页面容器背景，不触碰表格/树/列表等内容视图。
    const QString kernelDockContainerStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget#ksDock_kernel,"
            "ads--CDockWidget#ksDock_kernel > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTabWidget::pane,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget > QWidget{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%1 !important;"
            "}")
            .arg(primaryTextColor)
        : QStringLiteral(
            "ads--CDockWidget#ksDock_kernel,"
            "ads--CDockWidget#ksDock_kernel > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTabWidget::pane,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QStackedWidget > QWidget{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  color:%2 !important;"
            "}")
            .arg(surfaceBackgroundText)
            .arg(primaryTextColor);

    // kernelDockContentStyle 作用：
    // - 背景图模式下，内核 Dock 内的表格/树/列表也透明，避免整块表格遮住背景图；
    // - 无背景图时保留主题实底，继续保持普通主题观感。
    const QString kernelDockContentStyle = enableDockContentTransparency
        ? QStringLiteral(
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea > QWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QAbstractScrollArea::viewport{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  alternate-background-color:transparent !important;"
            "  color:%1 !important;"
            "  gridline-color:%2 !important;"
            "}")
            .arg(primaryTextColor)
            .arg(borderColorText)
        : QStringLiteral(
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTableWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QTreeWidget,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListView,"
            "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot QListWidget{"
            "  background:%1 !important;"
            "  background-color:%1 !important;"
            "  alternate-background-color:%2 !important;"
            "  color:%3 !important;"
            "  gridline-color:%4 !important;"
            "}")
            .arg(surfaceBackgroundText)
            .arg(surfaceAltBackgroundText)
            .arg(primaryTextColor)
            .arg(borderColorText);

    // 对象命名空间总览底部的结构视图是详情文本的派生呈现，不应被 KernelDock
    // 的通用表格实底规则覆盖；保持透明，让它继承详情区域的底色。
    const QString objectNamespaceStructuredViewStyle = QStringLiteral(
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea::viewport,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QScrollArea QWidget,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QTreeWidget,"
        "ads--CDockWidget#ksDock_kernel QWidget#KernelDockRoot "
        "#ks_object_namespace_detail_editor QTreeWidget::viewport{"
        "  background:transparent !important;"
        "  background-color:transparent !important;"
        "  alternate-background-color:transparent !important;"
        "}");

    const QString kernelDockStyle = kernelDockContainerStyle
        + kernelDockContentStyle
        + objectNamespaceStructuredViewStyle;

    // tabPluginOpaqueStyle 作用：
    // - 让「插件」页始终保持主题实底，不参与 Dock 内容透明。
    // 为什么必须排除：
    // - Tab 型插件通过 WA_NativeWindow 原生子窗口承载（ksExternalPluginNativeSurface），
    //   外部插件进程的窗口被 SetParent 到这块 surface 上；
    // - 原生子窗口不参与 Qt 的分层合成，父链一旦被刷成透明，
    //   插件画面就会变成黑块/残影/整块不刷新。
    // - PluginHost 自己设过实底（createTabPluginContainer），但那是普通声明，
    //   压不过上面几段带 !important 的透明规则，因此这里用同样带 !important
    //   且更具体（带 #objectName）的选择器把背景收回来。
    // 锚点说明：
    // - 插件页已并入「杂项」Dock，不再有独立的 ksDock_plugin，
    //   因此改为锚定杂项页里的插件宿主占位控件 ksMiscPluginHost 及其整棵子树；
    // - 只覆盖这一棵子树，杂项页的其它子页仍然正常参与内容透明。
    const QString tabPluginOpaqueStyle = QStringLiteral(
        "QWidget#ksMiscPluginHost,"
        "QWidget#ksMiscPluginHost QWidget,"
        "QWidget#ksTabPluginContainer,"
        "QWidget#ksTabPluginEmptyState,"
        "QWidget#ksExternalPluginNativeSurface,"
        "QTabWidget#ksTabPluginHost::pane{"
        "  background:%1 !important;"
        "  background-color:%1 !important;"
        "  color:%2 !important;"
        "}")
        .arg(surfaceBackgroundText)
        .arg(primaryTextColor);
    // finalOrdinaryTabHoverStyle 作用：
    // - 作为普通 QTabWidget/QTabBar 的最终 hover/pressed 兜底；
    // - 深色模式使用深灰、浅色模式使用浅灰，避免基础 QSS 或平台 palette 反向回退；
    // - 选择器刻意避开 ads--CDockWidgetTab/ads--CAutoHideTab，所以不影响 ADS Dock 标签。
    const QString ordinaryTabHoverColor = darkModeEnabled
        ? KswordTheme::SurfaceMutedColorHex()
        : KswordTheme::SurfaceAltColorHex();
    const QString finalOrdinaryTabHoverStyle = QStringLiteral(
        "QMainWindow QTabWidget QTabBar::tab:hover:!selected,"
        "QMainWindow QTabWidget QTabBar::tab:pressed:!selected,"
        "QTabWidget QTabBar::tab:hover:!selected,"
        "QTabWidget QTabBar::tab:pressed:!selected{"
        "  background-color:%1 !important;"
        "  background:%1 !important;"
        "  color:%2 !important;"
        "}"
        "QMainWindow QTabWidget QTabBar::tab:selected:hover,"
        "QMainWindow QTabWidget QTabBar::tab:selected:pressed,"
        "QTabWidget QTabBar::tab:selected:hover,"
        "QTabWidget QTabBar::tab:selected:pressed{"
        "  background-color:%3 !important;"
        "  background:%3 !important;"
        "  color:%4 !important;"
        "}")
        .arg(ordinaryTabHoverColor)
        .arg(primaryTextColor)
        .arg(activeTabColor)
        .arg(activeTabTextColor);

    if (!darkModeEnabled)
    {
        return rootStyle
            + QStringLiteral(
                "QMenuBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
                "QMenuBar::item{background:transparent;color:__WINDOW_TEXT__;padding:2px 7px;}"
                "QMenuBar::item:selected{background:%2;color:__WINDOW_TEXT__;}"
                "QMenuBar::item:pressed{background:__LIGHT_MENUBAR_PRESSED__;color:__WINDOW_TEXT__;}"
                "QStatusBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
                "QLineEdit,QSpinBox,QDoubleSpinBox{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QTextEdit,QPlainTextEdit,QTableWidget,QTreeWidget,QListWidget{"
                "  background-color:%1 !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QPushButton,QToolButton{"
                "  background-color:%2 !important;"
                "  color:%3 !important;"
                "  border:1px solid %5 !important;"
                "}"
                "QTableView,QTableWidget,QTreeView,QTreeWidget,QListView,QListWidget{"
                "  background:%1 !important;"
                "  alternate-background-color:%6 !important;"
                "  color:%3 !important;"
                "  gridline-color:%4;"
                "}"
                "QTreeView::item:selected,QTreeWidget::item:selected{"
                "  background:%7 !important;"
                "  color:%8 !important;"
                "}"
                "QHeaderView::section{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  color:%3 !important;"
                "  border:1px solid %4;"
                "}"
                "QTableCornerButton::section{"
                "  background:transparent !important;"
                "  background-color:transparent !important;"
                "  border:none !important;"
                "}"
                "QScrollBar:vertical,QScrollBar:horizontal{"
                "  background:%9 !important;"
                "  border:none !important;"
                "}")
                .arg(surfaceBackgroundText)
                .arg(subtleThemeColor)
                .arg(primaryTextColor)
                .arg(borderColorText)
                .arg(borderStrongColorText)
                .arg(surfaceAltBackgroundText)
                .arg(activeThemeColor)
                .arg(selectedTextColor)
                .arg(windowBackgroundText)
                .replace(QStringLiteral("__WINDOW_BACKGROUND__"), windowBackgroundText)
                .replace(QStringLiteral("__WINDOW_TEXT__"), windowTextColor)
                .replace(QStringLiteral("__LIGHT_MENUBAR_PRESSED__"), surfaceMutedBackgroundText)
            + sharedOverlayStyle
            + tooltipStyle
            + dockContentTransparentStyle
            + finalDockAreaTransparentStyle
            + kernelDockStyle
            + tabPluginOpaqueStyle
            + finalOrdinaryTabHoverStyle;
    }

    return rootStyle
        + QStringLiteral(
            "QMenuBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
            "QMenuBar::item{background:transparent;color:__WINDOW_TEXT__;padding:2px 7px;}"
            "QMenuBar::item:selected{background:%9;color:__WINDOW_TEXT__;}"
            "QMenuBar::item:pressed{background:%10;color:%8;}"
            "QStatusBar{background-color:__WINDOW_BACKGROUND__;color:__WINDOW_TEXT__;}"
            "QLineEdit,QSpinBox,QDoubleSpinBox{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QTextEdit,QPlainTextEdit,QTableWidget,QTreeWidget,QListWidget{"
            "  background-color:%2 !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QPushButton,QToolButton{"
            "  background-color:%6 !important;"
            "  color:%3 !important;"
            "  border:1px solid %5 !important;"
            "}"
            "QTableView,QTableWidget,QTreeView,QTreeWidget,QListView,QListWidget{"
            "  background:%2 !important;"
            "  alternate-background-color:%6 !important;"
            "  color:%3 !important;"
            "  gridline-color:%4;"
            "}"
            "QTreeView::item:selected,QTreeWidget::item:selected{"
            "  background:%7 !important;"
            "  color:%8 !important;"
            "}"
            "QHeaderView::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  color:%3 !important;"
            "  border:1px solid %4;"
            "}"
            "QTableCornerButton::section{"
            "  background:transparent !important;"
            "  background-color:transparent !important;"
            "  border:none !important;"
            "}"
            "QScrollBar:vertical,QScrollBar:horizontal{"
            "  background:%1 !important;"
            "  border:none !important;"
            "}")
            .arg(windowBackgroundText)
            .arg(surfaceBackgroundText)
            .arg(primaryTextColor)
            .arg(borderColorText)
            .arg(borderStrongColorText)
            .arg(surfaceAltBackgroundText)
            .arg(activeThemeColor)
            .arg(selectedTextColor)
            .arg(KswordTheme::RgbaColorName(KswordTheme::PrimaryBlueColor, 71))
            .arg(KswordTheme::RgbaColorName(KswordTheme::PrimaryBlueColor, 97))
            .replace(QStringLiteral("__WINDOW_BACKGROUND__"), windowBackgroundText)
            .replace(QStringLiteral("__WINDOW_TEXT__"), windowTextColor)
        + sharedOverlayStyle
        + tooltipStyle
        + dockContentTransparentStyle
        + finalDockAreaTransparentStyle
        + kernelDockStyle
        + tabPluginOpaqueStyle
        + finalOrdinaryTabHoverStyle;
}
