#include "ProcessDetailWindow.InternalCommon.h"

// ============================================================
// ProcessDetailWindow.cpp
// 作用：
// - 提供 ProcessDetailWindow 多个实现文件共享的内部常量与工具函数；
// - 保持其它 cpp 专注于成员函数，不再通过 .inc 做文本拼接。
// ============================================================

namespace process_detail_window_internal
{
    // 线程细节表头：与开发计划字段一一对应。
    const QStringList ThreadInspectHeaders{
        "ThreadID",
        "状态",
        "优先级",
        "上下文切换",
        "起始地址",
        "TEB地址",
        "亲和性",
        "寄存器",
        "R0栈边界",
        "R0详情"
    };

    int toThreadColumnIndex(const ThreadRowColumn column)
    {
        return static_cast<int>(column);
    }

    // 模块表头文本。
    const QStringList ModuleHeaders{
        "模块路径",
        "大小",
        "数字签名",
        "入口偏移量",
        "运行状态",
        "ThreadID"
    };

    int toModuleColumnIndex(const ModuleColumn column)
    {
        return static_cast<int>(column);
    }

    // 统一按钮样式全部走动态主题角色，详情窗口开着时切换深浅色也会跟随。
    QString buildBlueButtonStyle()
    {
        return KswordTheme::ThemedButtonStyle();
    }

    QString buildProcessDetailRootStyle()
    {
        // Native tables and headers are owned by the shared UI baseline.
        // This window adds only its sidebar and lightweight property sections.
        return QStringLiteral(
            "QWidget#ProcessDetailWindowRoot{background:%1;color:%2;}"
            "QWidget#ProcessDetailWindowRoot QGroupBox{"
            "border:0;border-top:1px solid %3;margin-top:16px;padding-top:12px;"
            "background:transparent;color:%2;}"
            "QWidget#ProcessDetailWindowRoot QGroupBox::title{"
            "subcontrol-origin:margin;left:0;padding:0 8px 0 0;color:%2;}"
            "QWidget#ProcessDetailWindowRoot QTabWidget::pane{border:0;background:%1;}"
            "QScrollArea#ProcessDetailNavigationScroll{background:%4;border:0;}"
            "QWidget#ProcessDetailTabNavigation{background:%4;border:0;}"
            "QWidget#ProcessDetailTabNavigation QToolButton{"
            "background:transparent;color:%2;border:0;border-radius:7px;"
            "text-align:left;padding:8px 10px;min-height:22px;}"
            "QWidget#ProcessDetailTabNavigation QToolButton:checked{"
            "background:%6;color:%5;border:0;}"
            "QWidget#ProcessDetailTabNavigation QToolButton:hover:!checked{background:%7;}"
            "QWidget#ProcessDetailWindowRoot QLineEdit[readOnly=\"true\"]{"
            "background:transparent;border:0;border-bottom:1px solid %3;border-radius:0;padding:5px 3px;}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::SurfaceAltHex())
            .arg(KswordTheme::PrimaryBlueHex)
            .arg(KswordTheme::PrimaryBlueSubtleHex())
            .arg(KswordTheme::SurfaceAltHex());
    }

    QString buildProcessDetailMenuStyle()
    {
        // 菜单样式必须显式声明背景/文字/选中/禁用态，避免透明父控件导致黑底黑字。
        return QStringLiteral(
            "QMenu{"
            "  background:%1;"
            "  color:%2;"
            "  border:1px solid %3;"
            "  padding:4px;"
            "}"
            "QMenu::item{"
            "  padding:5px 24px 5px 24px;"
            "  background:transparent;"
            "}"
            "QMenu::item:selected{"
            "  background:%4;"
            "  color:%6;"
            "}"
            "QMenu::item:disabled{"
            "  color:%5;"
            "  background:%1;"
            "}"
            "QMenu::separator{"
            "  height:1px;"
            "  background:%3;"
            "  margin:3px 6px;"
            "}")
            .arg(KswordTheme::SurfaceHex())
            .arg(KswordTheme::TextPrimaryHex())
            .arg(KswordTheme::BorderHex())
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue))
            .arg(KswordTheme::TextSecondaryHex())
            .arg(KswordTheme::OnAccentDynamicHex());
    }

    QIcon buildProcessDetailR0ActionIcon(const QString& iconPath)
    {
        // R0 按钮使用对应业务图标；按钮文字本身明确标出 R0 来源。
        constexpr QSize detailR0IconSize(18, 18);
        QPixmap iconPixmap(iconPath);
        if (!iconPixmap.isNull())
        {
            iconPixmap = iconPixmap.scaled(
                detailR0IconSize,
                Qt::KeepAspectRatio,
                Qt::SmoothTransformation);
        }
        if (iconPixmap.isNull())
        {
            iconPixmap = QPixmap(detailR0IconSize);
            iconPixmap.fill(Qt::transparent);
        }

        return QIcon(iconPixmap);
    }

    QString buildStateLabelStyle(const QColor& textColor, const int fontWeight)
    {
        return QStringLiteral("color:%1; font-weight:%2;")
            .arg(textColor.name(QColor::HexRgb))
            .arg(fontWeight);
    }

    QColor statusIdleColor()
    {
        return KswordTheme::SuccessColor();
    }

    QColor statusWarningColor()
    {
        return KswordTheme::WarningColor();
    }

    QColor statusErrorColor()
    {
        return KswordTheme::ErrorColor();
    }

    QColor statusSecondaryColor()
    {
        return KswordTheme::TextSecondaryColor();
    }

    QColor signatureTrustedColor()
    {
        return KswordTheme::SuccessColor();
    }

    QColor signatureUntrustedColor()
    {
        return KswordTheme::ErrorColor();
    }

    QString formatDoubleText(const double value, const int precision)
    {
        return QString::number(value, 'f', precision);
    }

    QString uint64ToHex(const std::uint64_t value)
    {
        return QString("0x%1").arg(static_cast<qulonglong>(value), 0, 16).toUpper();
    }

    QString convertSidToText(PSID sid)
    {
        if (sid == nullptr)
        {
            return QStringLiteral("<null sid>");
        }

        WCHAR accountName[256] = {};
        WCHAR domainName[256] = {};
        DWORD accountNameLength = static_cast<DWORD>(std::size(accountName));
        DWORD domainNameLength = static_cast<DWORD>(std::size(domainName));
        SID_NAME_USE sidType = SidTypeUnknown;
        const BOOL accountOk = LookupAccountSidW(
            nullptr,
            sid,
            accountName,
            &accountNameLength,
            domainName,
            &domainNameLength,
            &sidType);

        LPWSTR sidTextRaw = nullptr;
        const BOOL sidTextOk = ConvertSidToStringSidW(sid, &sidTextRaw);
        QString sidText = sidTextOk && sidTextRaw != nullptr
            ? QString::fromWCharArray(sidTextRaw)
            : QStringLiteral("N/A");
        if (sidTextRaw != nullptr)
        {
            LocalFree(sidTextRaw);
            sidTextRaw = nullptr;
        }

        if (accountOk == FALSE)
        {
            return QString("SID=%1").arg(sidText);
        }

        return QString("%1\\%2 (SID=%3)")
            .arg(QString::fromWCharArray(domainName))
            .arg(QString::fromWCharArray(accountName))
            .arg(sidText);
    }

    QString readRemoteUnicodeString(HANDLE processHandle, const UNICODE_STRING& remoteUnicode)
    {
        if (processHandle == nullptr || remoteUnicode.Length == 0 || remoteUnicode.Buffer == nullptr)
        {
            return QString();
        }

        std::vector<wchar_t> buffer(
            static_cast<std::size_t>(remoteUnicode.Length / sizeof(wchar_t)) + 1,
            L'\0');
        SIZE_T bytesRead = 0;
        const BOOL readOk = ReadProcessMemory(
            processHandle,
            remoteUnicode.Buffer,
            buffer.data(),
            remoteUnicode.Length,
            &bytesRead);
        if (readOk == FALSE || bytesRead == 0)
        {
            return QString();
        }

        return QString::fromWCharArray(buffer.data());
    }

    int calculateStandaloneWindowInitialWidth(
        QWidget* candidateParent,
        QWidget* fallbackWindow,
        const double ratio,
        const int fallbackWidth)
    {
        // 输入：
        // - candidateParent：优先参考的客户区控件，通常是打开独立窗口的 Dock/主窗口。
        // - fallbackWindow：当前独立窗口，用于在无父控件时定位屏幕。
        // - ratio：初始宽度比例，本需求调用侧固定传 0.75。
        // - fallbackWidth：所有来源都不可用时的默认宽度。
        // 处理：
        // - 先定位目标屏幕，再把所有候选宽度都钳制到该屏幕可用宽度以内；
        // - 优先使用 parent contentsRect，避免窗口装饰/边框参与计算；
        // - 其次使用当前活动窗口客户区；
        // - 最后退回屏幕 availableGeometry。
        // 返回：按比例计算出的初始宽度；仅在完全无法判断时使用回退宽度。
        int clientWidth = 0;
        if (candidateParent != nullptr && candidateParent->contentsRect().width() > 0)
        {
            clientWidth = candidateParent->contentsRect().width();
        }

        if (clientWidth <= 0)
        {
            QWidget* activeWindow = QApplication::activeWindow();
            if (activeWindow != nullptr &&
                activeWindow != fallbackWindow &&
                activeWindow->contentsRect().width() > 0)
            {
                clientWidth = activeWindow->contentsRect().width();
            }
        }

        QScreen* targetScreen = nullptr;
        if (candidateParent != nullptr && candidateParent->windowHandle() != nullptr)
        {
            targetScreen = candidateParent->windowHandle()->screen();
        }
        if (targetScreen == nullptr && fallbackWindow != nullptr && fallbackWindow->windowHandle() != nullptr)
        {
            targetScreen = fallbackWindow->windowHandle()->screen();
        }
        if (targetScreen == nullptr)
        {
            targetScreen = QApplication::primaryScreen();
        }
        if (clientWidth <= 0 && targetScreen != nullptr)
        {
            clientWidth = targetScreen->availableGeometry().width();
        }

        const int boundedFallbackWidth = std::max(1, fallbackWidth);
        if (clientWidth <= 0 || ratio <= 0.0)
        {
            return boundedFallbackWidth;
        }

        const int screenWidth = (targetScreen != nullptr)
            ? targetScreen->availableGeometry().width()
            : 0;
        if (screenWidth > 0)
        {
            // 初始宽度不按超出目标屏幕的客户区计算。
            clientWidth = std::min(clientWidth, screenWidth);
        }

        return std::max(1, static_cast<int>(std::floor(static_cast<double>(clientWidth) * ratio)));
    }
}
