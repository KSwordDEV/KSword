#include "OtherDock.h"
#include "../UI/CodeTextEdit.h"
#include "WindowCaptureProtection.h"
#include "WindowListInteraction.h"
#include "../Framework/PrivilegeElevationPrompt.h"

// ============================================================
// OtherDock.WindowProtection.cpp
// 作用说明：
// 1) 连接窗口列表页的防截图保护 UI 操作；
// 2) 将选中窗口 HWND 交给 WindowCaptureProtection helper；
// 3) 统一输出日志、消息框和刷新动作。
// ============================================================

#include <QMessageBox>
#include <QString>
#include <QTreeWidget>
#include <QTreeWidgetItem>

#include <iomanip>

namespace
{
    // formatHwndText 作用：
    // - 将 HWND 整数值格式化为大写十六进制；
    // - 调用：消息框与日志摘要中展示目标窗口。
    QString formatHwndText(const quint64 hwndValue)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(hwndValue), 0, 16)
            .toUpper();
    }

    // affinityText 作用：
    // - 将 helper 返回的 affinity 值转换成 UI 文本；
    // - 传入 affinityValue：WDA_* 原始数值。
    QString affinityText(const std::uint32_t affinityValue)
    {
        return QString::fromStdString(ks::window::DisplayAffinityName(affinityValue));
    }

    // buildProtectionMessage 作用：
    // - 生成用户可读的成功/失败摘要；
    // - 传入 result：防截图写入结果；
    // - 传出：QString 消息正文。
    QString buildProtectionMessage(const ks::window::CaptureProtectionResult& result)
    {
        const QString actionText = result.requestedProtection
            ? QStringLiteral("启用防截图保护")
            : QStringLiteral("取消防截图保护");
        const QString routeText = result.usedRemoteThread
            ? QStringLiteral("跨进程远程调用")
            : QStringLiteral("本进程直接调用");

        QString messageText;
        messageText += result.success
            ? QStringLiteral("%1成功。\n").arg(actionText)
            : QStringLiteral("%1失败。\n").arg(actionText);
        messageText += QStringLiteral("选择窗口: %1\n").arg(formatHwndText(result.requestedHwnd));
        messageText += QStringLiteral("实际窗口: %1\n").arg(formatHwndText(result.appliedHwnd));
        messageText += QStringLiteral("目标 PID: %1\n").arg(result.processId);
        messageText += QStringLiteral("调用路径: %1\n").arg(routeText);
        const QString affinityHexText =
            QString::number(static_cast<qulonglong>(result.appliedAffinity), 16).toUpper();
        messageText += QStringLiteral("DisplayAffinity: 0x%1 (%2)\n")
            .arg(affinityHexText)
            .arg(affinityText(result.appliedAffinity));

        if (result.usedRootWindow)
        {
            messageText += QStringLiteral("说明: 选中的是子窗口，已对所属顶层窗口执行。\n");
        }
        if (!result.success)
        {
            messageText += QStringLiteral("错误码: %1\n").arg(result.win32Error);
            messageText += QStringLiteral("诊断: %1\n").arg(QString::fromStdString(result.detail));
            messageText += QStringLiteral("限制: 更高权限、受保护进程、32 位目标进程或非顶层窗口可能被系统拒绝。");
        }
        return messageText;
    }
}

void OtherDock::setCaptureProtectionForSelectedWindows(const bool protectedState)
{
    const auto windows = selectedWindowSnapshots();
    if (windows.empty())
    {
        QMessageBox::information(this, QStringLiteral("窗口防截图保护"),
            QStringLiteral("请先选中一个窗口。"));
        return;
    }
    setCaptureProtectionForWindows(windows, protectedState);
}

void OtherDock::setCaptureProtectionForWindows(
    const std::vector<WindowInfo>& windows, const bool protectedState)
{
    QSet<quint64> processedRoots;
    int succeeded = 0;
    QStringList failures;
    for (const auto& window : windows)
    {
        if (!window.valid || !ks::window::windowIdentityMatches(
            window.hwndValue, window.processId, window.threadId, window.processCreationTime100ns))
        {
            failures.push_back(formatHwndText(window.hwndValue));
            continue;
        }
        const HWND hwnd = reinterpret_cast<HWND>(static_cast<quintptr>(window.hwndValue));
        const HWND root = ::GetAncestor(hwnd, GA_ROOT);
        const quint64 rootValue = root
            ? static_cast<quint64>(reinterpret_cast<quintptr>(root)) : window.hwndValue;
        if (processedRoots.contains(rootValue)) continue;
        processedRoots.insert(rootValue);
        // Keep the single-window diagnostic dialog, but batch feedback only once.
        const bool ok = setCaptureProtectionForWindow(window, protectedState, windows.size() == 1);
        if (ok) ++succeeded;
        else failures.push_back(formatHwndText(window.hwndValue));
    }
    refreshWindowListAsync();
    if (windows.size() > 1 || processedRoots.isEmpty())
    {
        const QString message = QStringLiteral("操作：%1\n成功：%2\n失败或已失效：%3\n%4")
            .arg(protectedState ? QStringLiteral("启用防截图保护") : QStringLiteral("取消防截图保护"))
            .arg(succeeded).arg(failures.size()).arg(failures.join('\n'));
        if (failures.empty()) QMessageBox::information(this, QStringLiteral("窗口防截图保护"), message);
        else QMessageBox::warning(this, QStringLiteral("窗口防截图保护"), message);
    }
}

bool OtherDock::setCaptureProtectionForWindow(
    const WindowInfo& windowInfo,
    const bool protectedState,
    const bool showFeedback)
{
    kLogEvent actionEvent;
    info << actionEvent
        << "[OtherDock] 开始窗口防截图保护操作, hwnd="
        << formatHwndText(windowInfo.hwndValue).toStdString()
        << ", pid="
        << windowInfo.processId
        << ", targetProtected="
        << (protectedState ? "true" : "false")
        << eol;

    const ks::window::CaptureProtectionResult result =
        ks::window::SetWindowCaptureProtection(windowInfo.hwndValue, protectedState);
    const QString messageText = buildProtectionMessage(result);

    if (result.success)
    {
        info << actionEvent
            << "[OtherDock] 窗口防截图保护操作成功, requestedHwnd="
            << formatHwndText(result.requestedHwnd).toStdString()
            << ", appliedHwnd="
            << formatHwndText(result.appliedHwnd).toStdString()
            << ", remote="
            << (result.usedRemoteThread ? "true" : "false")
            << ", affinity=0x"
            << std::hex
            << result.appliedAffinity
            << std::dec
            << eol;
        if (showFeedback) QMessageBox::information(
            this,
            QStringLiteral("窗口防截图保护"),
            messageText);
    }
    else
    {
        // privilegePromptHandled：先消费结构化 Win32 错误，未命中时再检查文字详情。
        bool privilegePromptHandled = showFeedback && ks::ui::promptForPrivilegeFailure(
            this,
            result.requestedProtection ? QStringLiteral("启用窗口防截图保护") : QStringLiteral("取消窗口防截图保护"),
            result.win32Error);
        if (showFeedback && !privilegePromptHandled)
        {
            privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                this,
                result.requestedProtection ? QStringLiteral("启用窗口防截图保护") : QStringLiteral("取消窗口防截图保护"),
                QString::fromStdString(result.detail));
        }
        err << actionEvent
            << "[OtherDock] 窗口防截图保护操作失败, requestedHwnd="
            << formatHwndText(result.requestedHwnd).toStdString()
            << ", appliedHwnd="
            << formatHwndText(result.appliedHwnd).toStdString()
            << ", remote="
            << (result.usedRemoteThread ? "true" : "false")
            << ", error="
            << result.win32Error
            << ", detail="
            << result.detail
            << eol;
        if (showFeedback && !privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("窗口防截图保护"),
                messageText);
        }
    }

    return result.success;
}

// WindowLayerDiagnostics.inl is intentionally included here so the feature is
// compiled once without expanding the already large OtherDock.cpp translation unit.
#include "WindowLayerDiagnostics.inl"
