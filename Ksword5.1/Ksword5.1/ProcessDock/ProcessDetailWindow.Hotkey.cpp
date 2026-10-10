#include "ProcessDetailWindow.InternalCommon.h"
#include "ProcessHotkeyEnumerator.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/PageControlStyle.h"

#include <algorithm>
#include <atomic>
#include <limits>
#include <thread>

#include <QInputDialog>

using namespace process_detail_window_internal;

// ============================================================
// ProcessDetailWindow.Hotkey.cpp
// 作用：
// - 负责“进程热键”页 UI、异步扫描和结果回填；
// - 当前实现只使用稳定 R3 API/资源解析，不在 Dock 层直接访问 KswordARK 设备。
// ============================================================

namespace
{
    constexpr int kHotkeyRowIndexRole = Qt::UserRole + 1;

    QString hotkeyUiText(const QString& key, const QString& fallback)
    {
        return ks::i18n::contextText(key, fallback);
    }

    struct HotkeyCandidate
    {
        QString objectText;
        std::uint32_t hotkeyId = 0;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
        QString hotkeyText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString processName;
        QString sourceText;
        QString detailText;
        bool hasR0MutationSnapshot = false;
        KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY r0MutationSnapshot{};
    };

    struct KeyboardHookCandidate
    {
        QString objectText;
        QString typeText;
        QString scopeText;
        std::uint32_t processId = 0;
        std::uint32_t threadId = 0;
        QString procedureText;
        QString moduleText;
        QString sourceText;
        QString flagsText;
        QString detailText;
    };

    void appendDiagnostic(QString& diagnosticText, const QString& message)
    {
        const QString trimmedMessage = message.trimmed();
        if (trimmedMessage.isEmpty())
        {
            return;
        }

        if (!diagnosticText.trimmed().isEmpty())
        {
            diagnosticText += QStringLiteral(" | ");
        }
        diagnosticText += trimmedMessage;
    }

    QString keyboardIoMessageText(const std::string& messageText)
    {
        // 输入：ArkDriverClient 返回的键盘热键/钩子 io.message。
        // 处理：把底层 DeviceIoControl、unsupported 和空消息翻译成界面可读说明。
        // 返回：用于进程热键页诊断栏的中文短句。
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString rawText = QString::fromStdString(messageText).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持键盘热键/钩子审计入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供键盘热键/钩子审计入口");
        }
        return rawText;
    }

    QString keyboardMutationFailureText(
        const ksword::ark::KeyboardHotkeyMutationResult& result)
    {
        if (!result.io.ok)
        {
            return QString::fromStdString(result.io.message);
        }
        switch (result.response.status)
        {
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_INVALID_REQUEST:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.invalid_request"), QStringLiteral("驱动拒绝了无效的热键变更请求。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFIRMATION_REQUIRED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.confirmation_required"), QStringLiteral("驱动要求重新确认此高风险操作。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSUPPORTED_BUILD:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unsupported_build"), QStringLiteral("当前 win32kfull.sys 身份或内部布局与已验证版本不一致，驱动已安全拒绝。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CALLER_CONTEXT_REQUIRED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.caller_context"), QStringLiteral("必须从当前交互式桌面的 GUI 线程执行此操作。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_STALE_SNAPSHOT:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.stale_snapshot"), QStringLiteral("热键对象或链表已变化，请刷新后重试。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_UNSAFE_TARGET:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unsafe_target"), QStringLiteral("目标不是可安全修改的普通独立热键项。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_CONFLICT:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.conflict"), QStringLiteral("目标组合已由另一个 RegisterHotKey 项占用。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OPERATION_FAILED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.operation_failed"), QStringLiteral("驱动写后验证失败；若已开始写入，已尝试回滚。"));
        case KSWORD_ARK_KEYBOARD_MUTATION_STATUS_SAFETY_DENIED:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.safety_denied"), QStringLiteral("统一安全策略未允许内核修改操作。"));
        default:
            return hotkeyUiText(QStringLiteral("process.hotkey.r0.unknown_failure"), QStringLiteral("驱动返回未知变更状态：%1。"))
                .arg(result.response.status);
        }
    }

    QString hex64Text(const std::uint64_t value)
    {
        if (value == 0U)
        {
            return QStringLiteral("0x0");
        }
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    QString pointerText(const void* value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(value)), 0, 16)
            .toUpper();
    }

    QString normalizedFilePath(const QString& pathText)
    {
        const QString trimmedPath = pathText.trimmed();
        if (trimmedPath.isEmpty())
        {
            return QString();
        }

        const QFileInfo fileInfo(trimmedPath);
        const QString normalizedPath = fileInfo.exists()
            ? fileInfo.canonicalFilePath()
            : fileInfo.absoluteFilePath();
        return QDir::fromNativeSeparators(normalizedPath).toLower();
    }

    QString windowTitleText(HWND windowHandle)
    {
        const int titleLength = ::GetWindowTextLengthW(windowHandle);
        if (titleLength <= 0)
        {
            return QString();
        }

        std::vector<wchar_t> titleBuffer(static_cast<std::size_t>(titleLength) + 1U, L'\0');
        const int copiedLength = ::GetWindowTextW(
            windowHandle,
            titleBuffer.data(),
            static_cast<int>(titleBuffer.size()));
        if (copiedLength <= 0)
        {
            return QString();
        }
        return QString::fromWCharArray(titleBuffer.data(), copiedLength);
    }

    std::uint32_t hotkeyModifiersFromHotkeyf(const std::uint32_t hotkeyf)
    {
        std::uint32_t modifiers = 0;
        if ((hotkeyf & HOTKEYF_ALT) != 0U) modifiers |= MOD_ALT;
        if ((hotkeyf & HOTKEYF_CONTROL) != 0U) modifiers |= MOD_CONTROL;
        if ((hotkeyf & HOTKEYF_SHIFT) != 0U) modifiers |= MOD_SHIFT;
        return modifiers;
    }

    QString virtualKeyName(const std::uint32_t virtualKey)
    {
        if (virtualKey >= 'A' && virtualKey <= 'Z')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= '0' && virtualKey <= '9')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= VK_F1 && virtualKey <= VK_F24)
        {
            return QStringLiteral("F%1").arg(virtualKey - VK_F1 + 1U);
        }

        switch (virtualKey)
        {
        case VK_BACK: return QStringLiteral("Backspace");
        case VK_TAB: return QStringLiteral("Tab");
        case VK_RETURN: return QStringLiteral("Enter");
        case VK_ESCAPE: return QStringLiteral("Esc");
        case VK_SPACE: return QStringLiteral("Space");
        case VK_PRIOR: return QStringLiteral("PageUp");
        case VK_NEXT: return QStringLiteral("PageDown");
        case VK_END: return QStringLiteral("End");
        case VK_HOME: return QStringLiteral("Home");
        case VK_LEFT: return QStringLiteral("Left");
        case VK_UP: return QStringLiteral("Up");
        case VK_RIGHT: return QStringLiteral("Right");
        case VK_DOWN: return QStringLiteral("Down");
        case VK_INSERT: return QStringLiteral("Insert");
        case VK_DELETE: return QStringLiteral("Delete");
        case VK_SNAPSHOT: return QStringLiteral("PrintScreen");
        case VK_PAUSE: return QStringLiteral("Pause");
        case VK_APPS: return QStringLiteral("Apps");
        case VK_OEM_PLUS: return QStringLiteral("+");
        case VK_OEM_MINUS: return QStringLiteral("-");
        case VK_OEM_COMMA: return QStringLiteral(",");
        case VK_OEM_PERIOD: return QStringLiteral(".");
        default:
            break;
        }

        const UINT scanCode = ::MapVirtualKeyW(virtualKey, MAPVK_VK_TO_VSC);
        if (scanCode != 0U)
        {
            LONG keyNameParam = static_cast<LONG>(scanCode << 16);
            switch (virtualKey)
            {
            case VK_INSERT:
            case VK_DELETE:
            case VK_HOME:
            case VK_END:
            case VK_PRIOR:
            case VK_NEXT:
            case VK_LEFT:
            case VK_RIGHT:
            case VK_UP:
            case VK_DOWN:
                keyNameParam |= (1L << 24);
                break;
            default:
                break;
            }

            wchar_t keyNameBuffer[64] = {};
            if (::GetKeyNameTextW(keyNameParam, keyNameBuffer, static_cast<int>(std::size(keyNameBuffer))) > 0)
            {
                return QString::fromWCharArray(keyNameBuffer);
            }
        }

        return QStringLiteral("VK_0x%1")
            .arg(static_cast<unsigned int>(virtualKey), 2, 16, QChar('0'))
            .toUpper();
    }

    QString hotkeyTextFromParts(
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        const QString& keyOverride = QString())
    {
        QStringList parts;
        if ((modifiers & MOD_CONTROL) != 0U) parts << QStringLiteral("Ctrl");
        if ((modifiers & MOD_SHIFT) != 0U) parts << QStringLiteral("Shift");
        if ((modifiers & MOD_ALT) != 0U) parts << QStringLiteral("Alt");
        if ((modifiers & MOD_WIN) != 0U) parts << QStringLiteral("Win");
        parts << (keyOverride.trimmed().isEmpty() ? virtualKeyName(virtualKey) : keyOverride.trimmed());
        return parts.join(QStringLiteral("+"));
    }

    std::uint32_t hotkeyfFromModifiers(const std::uint32_t modifiers)
    {
        std::uint32_t hotkeyf = 0;
        if ((modifiers & MOD_ALT) != 0U) hotkeyf |= HOTKEYF_ALT;
        if ((modifiers & MOD_CONTROL) != 0U) hotkeyf |= HOTKEYF_CONTROL;
        if ((modifiers & MOD_SHIFT) != 0U) hotkeyf |= HOTKEYF_SHIFT;
        return hotkeyf;
    }

    QString keyboardEnumStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("win32k not found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND:
            return QStringLiteral("pattern not found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE:
            return QStringLiteral("session unavailable");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("buffer truncated");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED:
            return QStringLiteral("read failed");
        default:
            return QStringLiteral("Unknown");
        }
    }

    QString keyboardHotkeySourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE:
            return QStringLiteral("R0 RegisterHotKey");
        default:
            return QStringLiteral("R0 Unknown");
        }
    }

    QString keyboardHookSourceText(const std::uint32_t sourceValue)
    {
        switch (sourceValue)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN:
            return QStringLiteral("R0 Thread Hook Chain");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN:
            return QStringLiteral("R0 Global Hook Chain");
        default:
            return QStringLiteral("R0 Unknown Hook Chain");
        }
    }

    QString keyboardHookScopeText(const std::uint32_t scopeValue)
    {
        switch (scopeValue)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD:
            return QStringLiteral("线程");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL:
            return QStringLiteral("全局/桌面");
        default:
            return QStringLiteral("未知");
        }
    }

    QString keyboardHookTypeText(const std::uint32_t typeValue)
    {
        switch (typeValue)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD:
            return QStringLiteral("WH_KEYBOARD");
        case KSWORD_ARK_KEYBOARD_HOOK_TYPE_KEYBOARD_LL:
            return QStringLiteral("WH_KEYBOARD_LL");
        default:
            return QStringLiteral("WH_%1").arg(typeValue);
        }
    }

    bool parseHotkeyToken(const QString& tokenText, std::uint32_t& virtualKeyOut, QString& keyTextOut)
    {
        QString token = tokenText.trimmed();
        token.remove(QLatin1Char('&'));
        token = token.trimmed();
        if (token.isEmpty())
        {
            return false;
        }

        const QString upperToken = token.toUpper();
        if (upperToken.size() == 1)
        {
            const QChar ch = upperToken.at(0);
            if ((ch >= QLatin1Char('A') && ch <= QLatin1Char('Z')) ||
                (ch >= QLatin1Char('0') && ch <= QLatin1Char('9')))
            {
                virtualKeyOut = static_cast<std::uint32_t>(ch.unicode());
                keyTextOut = QString(ch);
                return true;
            }
        }

        if (upperToken.size() >= 2 && upperToken.at(0) == QLatin1Char('F'))
        {
            bool ok = false;
            const int functionIndex = upperToken.mid(1).toInt(&ok);
            if (ok && functionIndex >= 1 && functionIndex <= 24)
            {
                virtualKeyOut = static_cast<std::uint32_t>(VK_F1 + functionIndex - 1);
                keyTextOut = QStringLiteral("F%1").arg(functionIndex);
                return true;
            }
        }

        static const std::unordered_map<std::string, std::uint32_t> keyNameMap{
            {"ESC", VK_ESCAPE},
            {"ESCAPE", VK_ESCAPE},
            {"TAB", VK_TAB},
            {"ENTER", VK_RETURN},
            {"RETURN", VK_RETURN},
            {"SPACE", VK_SPACE},
            {"BACKSPACE", VK_BACK},
            {"BKSP", VK_BACK},
            {"DEL", VK_DELETE},
            {"DELETE", VK_DELETE},
            {"INS", VK_INSERT},
            {"INSERT", VK_INSERT},
            {"HOME", VK_HOME},
            {"END", VK_END},
            {"PGUP", VK_PRIOR},
            {"PAGEUP", VK_PRIOR},
            {"PGDN", VK_NEXT},
            {"PAGEDOWN", VK_NEXT},
            {"LEFT", VK_LEFT},
            {"RIGHT", VK_RIGHT},
            {"UP", VK_UP},
            {"DOWN", VK_DOWN},
            {"PRINTSCREEN", VK_SNAPSHOT},
            {"PRTSC", VK_SNAPSHOT},
            {"PAUSE", VK_PAUSE},
            {"APPS", VK_APPS},
            {"PLUS", VK_OEM_PLUS},
            {"MINUS", VK_OEM_MINUS},
            {"COMMA", VK_OEM_COMMA},
            {"PERIOD", VK_OEM_PERIOD}
        };

        const auto it = keyNameMap.find(upperToken.toStdString());
        if (it == keyNameMap.end())
        {
            return false;
        }

        virtualKeyOut = it->second;
        keyTextOut = virtualKeyName(virtualKeyOut);
        return true;
    }

    bool parseHotkeyText(const QString& sourceText, std::uint32_t& modifiersOut, std::uint32_t& virtualKeyOut)
    {
        QString text = sourceText.trimmed();
        if (text.isEmpty())
        {
            return false;
        }

        text.replace(QStringLiteral("Control"), QStringLiteral("Ctrl"), Qt::CaseInsensitive);
        text.replace(QStringLiteral("Windows"), QStringLiteral("Win"), Qt::CaseInsensitive);
        const QStringList parts = text.split(QLatin1Char('+'), Qt::SkipEmptyParts);
        if (parts.isEmpty())
        {
            return false;
        }

        std::uint32_t modifiers = 0;
        for (int index = 0; index + 1 < parts.size(); ++index)
        {
            const QString modifierText = parts.at(index).trimmed().toUpper();
            if (modifierText == QStringLiteral("CTRL"))
            {
                modifiers |= MOD_CONTROL;
            }
            else if (modifierText == QStringLiteral("SHIFT"))
            {
                modifiers |= MOD_SHIFT;
            }
            else if (modifierText == QStringLiteral("ALT"))
            {
                modifiers |= MOD_ALT;
            }
            else if (modifierText == QStringLiteral("WIN"))
            {
                modifiers |= MOD_WIN;
            }
            else
            {
                return false;
            }
        }

        QString keyText;
        std::uint32_t virtualKey = 0;
        if (!parseHotkeyToken(parts.last(), virtualKey, keyText))
        {
            return false;
        }

        modifiersOut = modifiers;
        virtualKeyOut = virtualKey;
        return true;
    }

    void appendCandidate(std::vector<HotkeyCandidate>& rows, QSet<QString>& dedupeSet, HotkeyCandidate row)
    {
        if (row.hotkeyText.trimmed().isEmpty() && row.virtualKey != 0U)
        {
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
        }
        if (row.hotkeyText.trimmed().isEmpty())
        {
            return;
        }

        const QString dedupeKey = QStringLiteral("%1|%2|%3|%4|%5|%6|%7")
            .arg(row.sourceText)
            .arg(row.objectText)
            .arg(row.hotkeyId)
            .arg(row.modifiers)
            .arg(row.virtualKey)
            .arg(row.threadId)
            .arg(row.detailText);
        if (dedupeSet.contains(dedupeKey))
        {
            return;
        }
        dedupeSet.insert(dedupeKey);
        rows.push_back(std::move(row));
    }

    struct WindowCollectorContext
    {
        std::uint32_t targetPid = 0;
        QSet<qulonglong>* seenWindows = nullptr;
        std::vector<HWND>* windows = nullptr;
    };

    BOOL CALLBACK collectTopLevelWindowProc(HWND windowHandle, LPARAM parameter)
    {
        auto* context = reinterpret_cast<WindowCollectorContext*>(parameter);
        if (context == nullptr || context->seenWindows == nullptr || context->windows == nullptr)
        {
            return TRUE;
        }

        DWORD processId = 0;
        ::GetWindowThreadProcessId(windowHandle, &processId);
        if (processId != context->targetPid)
        {
            return TRUE;
        }

        const qulonglong key = static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(windowHandle));
        if (!context->seenWindows->contains(key))
        {
            context->seenWindows->insert(key);
            context->windows->push_back(windowHandle);
        }
        return TRUE;
    }

    std::vector<DWORD> collectThreadIdsForProcess(const std::uint32_t processId)
    {
        std::vector<DWORD> threadIds;
        HANDLE snapshotHandle = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshotHandle == INVALID_HANDLE_VALUE)
        {
            return threadIds;
        }

        THREADENTRY32 threadEntry{};
        threadEntry.dwSize = sizeof(threadEntry);
        BOOL hasThread = ::Thread32First(snapshotHandle, &threadEntry);
        while (hasThread != FALSE)
        {
            if (threadEntry.th32OwnerProcessID == processId)
            {
                threadIds.push_back(threadEntry.th32ThreadID);
            }
            hasThread = ::Thread32Next(snapshotHandle, &threadEntry);
        }

        ::CloseHandle(snapshotHandle);
        return threadIds;
    }

    std::vector<HWND> collectWindowsForProcess(const std::uint32_t processId)
    {
        std::vector<HWND> windows;
        QSet<qulonglong> seenWindows;
        WindowCollectorContext context{ processId, &seenWindows, &windows };
        ::EnumWindows(collectTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));

        const std::vector<DWORD> threadIds = collectThreadIdsForProcess(processId);
        for (const DWORD threadId : threadIds)
        {
            ::EnumThreadWindows(threadId, collectTopLevelWindowProc, reinterpret_cast<LPARAM>(&context));
        }

        return windows;
    }

    void collectWindowActivationHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet)
    {
        const std::vector<HWND> windows = collectWindowsForProcess(processId);
        for (HWND windowHandle : windows)
        {
            DWORD ownerProcessId = 0;
            const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
            DWORD_PTR resultValue = 0;
            const LRESULT sendOk = ::SendMessageTimeoutW(
                windowHandle,
                WM_GETHOTKEY,
                0,
                0,
                SMTO_ABORTIFHUNG | SMTO_BLOCK,
                100,
                &resultValue);
            if (sendOk == 0 || resultValue == 0)
            {
                continue;
            }

            const std::uint32_t virtualKey = static_cast<std::uint32_t>(LOBYTE(LOWORD(resultValue)));
            const std::uint32_t hotkeyf = static_cast<std::uint32_t>(HIBYTE(LOWORD(resultValue)));
            if (virtualKey == 0U)
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = QStringLiteral("HWND=%1").arg(pointerText(windowHandle));
            row.hotkeyId = 0;
            row.modifiers = hotkeyModifiersFromHotkeyf(hotkeyf);
            row.virtualKey = virtualKey;
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
            row.processId = processId;
            row.threadId = threadId;
            row.processName = processName;
            row.sourceText = QStringLiteral("窗口热键");
            row.detailText = windowTitleText(windowHandle);
            appendCandidate(rows, dedupeSet, std::move(row));
        }
    }

    void collectMenuHotkeysRecursive(
        HMENU menuHandle,
        HWND windowHandle,
        const QString& menuPath,
        const std::uint32_t processId,
        const std::uint32_t threadId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        const int depth)
    {
        if (menuHandle == nullptr || depth > 12)
        {
            return;
        }

        const int itemCount = ::GetMenuItemCount(menuHandle);
        if (itemCount <= 0)
        {
            return;
        }

        for (int index = 0; index < itemCount; ++index)
        {
            wchar_t textBuffer[512] = {};
            MENUITEMINFOW itemInfo{};
            itemInfo.cbSize = sizeof(itemInfo);
            itemInfo.fMask = MIIM_STRING | MIIM_SUBMENU | MIIM_ID;
            itemInfo.dwTypeData = textBuffer;
            itemInfo.cch = static_cast<UINT>(std::size(textBuffer));
            if (::GetMenuItemInfoW(menuHandle, static_cast<UINT>(index), TRUE, &itemInfo) == FALSE)
            {
                continue;
            }

            const QString rawText = QString::fromWCharArray(textBuffer).trimmed();
            const QString itemPath = menuPath.isEmpty()
                ? rawText
                : QStringLiteral("%1 > %2").arg(menuPath, rawText);

            const int tabIndex = rawText.indexOf(QLatin1Char('\t'));
            if (tabIndex >= 0 && tabIndex + 1 < rawText.size())
            {
                const QString shortcutText = rawText.mid(tabIndex + 1).trimmed();
                std::uint32_t modifiers = 0;
                std::uint32_t virtualKey = 0;
                if (parseHotkeyText(shortcutText, modifiers, virtualKey))
                {
                    HotkeyCandidate row{};
                    row.objectText = QStringLiteral("HWND=%1 HMENU=%2")
                        .arg(pointerText(windowHandle), pointerText(menuHandle));
                    row.hotkeyId = itemInfo.wID;
                    row.modifiers = modifiers;
                    row.virtualKey = virtualKey;
                    row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
                    row.processId = processId;
                    row.threadId = threadId;
                    row.processName = processName;
                    row.sourceText = QStringLiteral("菜单快捷键");
                    row.detailText = itemPath;
                    appendCandidate(rows, dedupeSet, std::move(row));
                }
            }

            if (itemInfo.hSubMenu != nullptr)
            {
                collectMenuHotkeysRecursive(
                    itemInfo.hSubMenu,
                    windowHandle,
                    itemPath,
                    processId,
                    threadId,
                    processName,
                    rows,
                    dedupeSet,
                    depth + 1);
            }
        }
    }

    void collectMenuHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet)
    {
        const std::vector<HWND> windows = collectWindowsForProcess(processId);
        for (HWND windowHandle : windows)
        {
            DWORD ownerProcessId = 0;
            const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, &ownerProcessId);
            HMENU menuHandle = ::GetMenu(windowHandle);
            if (menuHandle == nullptr)
            {
                continue;
            }
            collectMenuHotkeysRecursive(
                menuHandle,
                windowHandle,
                windowTitleText(windowHandle),
                processId,
                threadId,
                processName,
                rows,
                dedupeSet,
                0);
        }
    }

    QStringList shortcutSearchRoots()
    {
        QStringList roots;
        const auto appendRoot = [&roots](const QString& pathText)
        {
            const QString cleaned = QDir::fromNativeSeparators(pathText.trimmed());
            if (!cleaned.isEmpty() && QDir(cleaned).exists() && !roots.contains(cleaned, Qt::CaseInsensitive))
            {
                roots << cleaned;
            }
        };

        appendRoot(QStandardPaths::writableLocation(QStandardPaths::DesktopLocation));
        appendRoot(QStringLiteral("C:/Users/Public/Desktop"));

        const QString appData = qEnvironmentVariable("APPDATA");
        if (!appData.isEmpty())
        {
            appendRoot(QDir::fromNativeSeparators(appData + QStringLiteral("/Microsoft/Windows/Start Menu/Programs")));
            appendRoot(QDir::fromNativeSeparators(appData + QStringLiteral("/Microsoft/Internet Explorer/Quick Launch")));
        }

        const QString programData = qEnvironmentVariable("PROGRAMDATA");
        if (!programData.isEmpty())
        {
            appendRoot(QDir::fromNativeSeparators(programData + QStringLiteral("/Microsoft/Windows/Start Menu/Programs")));
        }

        return roots;
    }

    bool shortcutTargetMatchesProcess(
        const QString& shortcutTarget,
        const QString& processImagePath,
        const QString& processName)
    {
        const QString normalizedTarget = normalizedFilePath(shortcutTarget);
        const QString normalizedProcessImage = normalizedFilePath(processImagePath);
        if (!normalizedTarget.isEmpty() &&
            !normalizedProcessImage.isEmpty() &&
            normalizedTarget == normalizedProcessImage)
        {
            return true;
        }

        if (!normalizedProcessImage.isEmpty())
        {
            return false;
        }

        if (!processName.trimmed().isEmpty())
        {
            const QString targetName = QFileInfo(shortcutTarget).fileName();
            if (!targetName.isEmpty() && targetName.compare(processName, Qt::CaseInsensitive) == 0)
            {
                return true;
            }
        }
        return false;
    }

    struct ShellShortcutHotkeyCandidate
    {
        QString shortcutPath;
        QString targetPath;
        std::uint32_t modifiers = 0;
        std::uint32_t virtualKey = 0;
    };

    void collectShellShortcutHotkeyCandidates(
        std::vector<ShellShortcutHotkeyCandidate>& candidates,
        QString& diagnosticText)
    {
        HRESULT comResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool needsUninitialize = SUCCEEDED(comResult);
        const bool comUsable = SUCCEEDED(comResult) || comResult == RPC_E_CHANGED_MODE;
        if (!comUsable)
        {
            diagnosticText += QStringLiteral(" | ShellLink COM初始化失败:0x%1")
                .arg(static_cast<unsigned long>(comResult), 0, 16);
            return;
        }

        const QStringList roots = shortcutSearchRoots();
        for (const QString& rootPath : roots)
        {
            QDirIterator shortcutIterator(
                rootPath,
                QStringList{ QStringLiteral("*.lnk") },
                QDir::Files,
                QDirIterator::Subdirectories);
            while (shortcutIterator.hasNext())
            {
                const QString shortcutPath = shortcutIterator.next();
                IShellLinkW* shellLink = nullptr;
                HRESULT createResult = ::CoCreateInstance(
                    CLSID_ShellLink,
                    nullptr,
                    CLSCTX_INPROC_SERVER,
                    IID_PPV_ARGS(&shellLink));
                if (FAILED(createResult) || shellLink == nullptr)
                {
                    continue;
                }

                IPersistFile* persistFile = nullptr;
                HRESULT queryResult = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
                if (SUCCEEDED(queryResult) && persistFile != nullptr)
                {
                    const std::wstring shortcutPathW = shortcutPath.toStdWString();
                    HRESULT loadResult = persistFile->Load(shortcutPathW.c_str(), STGM_READ);
                    if (SUCCEEDED(loadResult))
                    {
                        WORD hotkeyValue = 0;
                        wchar_t targetPathBuffer[MAX_PATH] = {};
                        WIN32_FIND_DATAW findData{};
                        shellLink->GetHotkey(&hotkeyValue);
                        shellLink->GetPath(
                            targetPathBuffer,
                            static_cast<int>(std::size(targetPathBuffer)),
                            &findData,
                            SLGP_UNCPRIORITY);

                        const QString targetPath = QString::fromWCharArray(targetPathBuffer).trimmed();
                        if (hotkeyValue != 0 && !targetPath.isEmpty())
                        {
                            ShellShortcutHotkeyCandidate candidate{};
                            candidate.shortcutPath = shortcutPath;
                            candidate.targetPath = targetPath;
                            candidate.modifiers = hotkeyModifiersFromHotkeyf(HIBYTE(hotkeyValue));
                            candidate.virtualKey = LOBYTE(hotkeyValue);
                            candidates.push_back(std::move(candidate));
                        }
                    }
                    persistFile->Release();
                }
                shellLink->Release();
            }
        }

        if (needsUninitialize)
        {
            ::CoUninitialize();
        }
    }

    void appendShellShortcutHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        const std::vector<ShellShortcutHotkeyCandidate>& candidates)
    {
        for (const ShellShortcutHotkeyCandidate& candidate : candidates)
        {
            if (!shortcutTargetMatchesProcess(candidate.targetPath, processImagePath, processName))
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = candidate.shortcutPath;
            row.hotkeyId = 0;
            row.modifiers = candidate.modifiers;
            row.virtualKey = candidate.virtualKey;
            row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey);
            row.processId = processId;
            row.threadId = 0;
            row.processName = processName;
            row.sourceText = QStringLiteral("快捷方式热键");
            row.detailText = candidate.targetPath;
            appendCandidate(rows, dedupeSet, std::move(row));
        }
    }

    void collectShellShortcutHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        QString& diagnosticText)
    {
        std::vector<ShellShortcutHotkeyCandidate> candidates;
        collectShellShortcutHotkeyCandidates(candidates, diagnosticText);
        appendShellShortcutHotkeys(
            processId,
            processName,
            processImagePath,
            rows,
            dedupeSet,
            candidates);
    }

    struct AcceleratorResourceEntry
    {
        std::uint16_t flags = 0;
        std::uint16_t key = 0;
        std::uint16_t commandId = 0;
        std::uint16_t padding = 0;
    };
    static_assert(sizeof(AcceleratorResourceEntry) == 8U, "PE accelerator resource entries must be 8 bytes");

    QString acceleratorCharacterText(const std::uint16_t keyValue)
    {
        if (keyValue == 0U || keyValue > 0xFFU)
        {
            return QString();
        }

        const char ansiCharacter = static_cast<char>(keyValue & 0xFFU);
        wchar_t unicodeCharacter = L'\0';
        if (::MultiByteToWideChar(
                CP_ACP,
                MB_ERR_INVALID_CHARS,
                &ansiCharacter,
                1,
                &unicodeCharacter,
                1) != 1)
        {
            return QString();
        }

        const QChar character(static_cast<ushort>(unicodeCharacter));
        return character.isPrint() ? QString(character).toUpper() : QString();
    }

    struct AcceleratorEnumContext
    {
        HMODULE moduleHandle = nullptr;
        QString modulePath;
        std::uint32_t processId = 0;
        QString processName;
        std::vector<HotkeyCandidate>* rows = nullptr;
        QSet<QString>* dedupeSet = nullptr;
    };

    QString acceleratorResourceNameText(LPCWSTR resourceName)
    {
        if (IS_INTRESOURCE(resourceName))
        {
            return QStringLiteral("#%1").arg(static_cast<qulonglong>(reinterpret_cast<std::uintptr_t>(resourceName)));
        }
        return QString::fromWCharArray(resourceName);
    }

    BOOL CALLBACK enumerateAcceleratorResourceProc(
        HMODULE moduleHandle,
        LPCWSTR resourceType,
        LPWSTR resourceName,
        LONG_PTR parameter)
    {
        Q_UNUSED(resourceType);

        auto* context = reinterpret_cast<AcceleratorEnumContext*>(parameter);
        if (context == nullptr || context->rows == nullptr || context->dedupeSet == nullptr)
        {
            return TRUE;
        }

        HRSRC resourceHandle = ::FindResourceW(moduleHandle, resourceName, RT_ACCELERATOR);
        if (resourceHandle == nullptr)
        {
            return TRUE;
        }

        const DWORD resourceBytes = ::SizeofResource(moduleHandle, resourceHandle);
        if (resourceBytes < sizeof(AcceleratorResourceEntry))
        {
            return TRUE;
        }

        HGLOBAL loadedResource = ::LoadResource(moduleHandle, resourceHandle);
        const auto* resourceData = static_cast<const unsigned char*>(::LockResource(loadedResource));
        if (resourceData == nullptr)
        {
            return TRUE;
        }

        // RT_ACCELERATOR uses ACCELTABLEENTRY (four WORDs, eight bytes), not the
        // runtime ACCEL structure. Advancing by sizeof(ACCEL) misaligns every row
        // after the first and produces bogus VK=0/garbled key names.
        const std::size_t entryCount = resourceBytes / sizeof(AcceleratorResourceEntry);
        const QString resourceNameText = acceleratorResourceNameText(resourceName);
        for (std::size_t index = 0; index < entryCount; ++index)
        {
            AcceleratorResourceEntry acceleratorEntry{};
            std::memcpy(
                &acceleratorEntry,
                resourceData + index * sizeof(AcceleratorResourceEntry),
                sizeof(acceleratorEntry));

            const bool isLastEntry = (acceleratorEntry.flags & 0x0080U) != 0U;
            if ((acceleratorEntry.flags & ~0x009FU) != 0U)
            {
                if (isLastEntry) break;
                continue;
            }

            const std::uint16_t flags = acceleratorEntry.flags & 0x007FU;
            std::uint32_t modifiers = 0;
            if ((flags & FCONTROL) != 0U) modifiers |= MOD_CONTROL;
            if ((flags & FSHIFT) != 0U) modifiers |= MOD_SHIFT;
            if ((flags & FALT) != 0U) modifiers |= MOD_ALT;

            std::uint32_t virtualKey = 0;
            QString keyOverride;
            if ((flags & FVIRTKEY) != 0U)
            {
                virtualKey = acceleratorEntry.key;
            }
            else
            {
                keyOverride = acceleratorCharacterText(acceleratorEntry.key);
                if (!keyOverride.isEmpty())
                {
                    const SHORT vkScan = ::VkKeyScanW(keyOverride.at(0).unicode());
                    if (vkScan != -1)
                    {
                        virtualKey = LOBYTE(vkScan);
                    }
                }
            }

            if (virtualKey != 0U || !keyOverride.isEmpty())
            {
                HotkeyCandidate row{};
                row.objectText = QStringLiteral("%1:%2")
                    .arg(context->modulePath, resourceNameText);
                row.hotkeyId = acceleratorEntry.commandId;
                row.modifiers = modifiers;
                row.virtualKey = virtualKey;
                row.hotkeyText = hotkeyTextFromParts(row.modifiers, row.virtualKey, keyOverride);
                row.processId = context->processId;
                row.threadId = 0;
                row.processName = context->processName;
                row.sourceText = QStringLiteral("PE Accelerator");
                row.detailText = QStringLiteral("entry=%1 flags=0x%2")
                    .arg(static_cast<qulonglong>(index))
                    .arg(static_cast<unsigned int>(acceleratorEntry.flags), 4, 16, QChar('0'))
                    .toUpper();
                appendCandidate(*context->rows, *context->dedupeSet, std::move(row));
            }

            if (isLastEntry)
            {
                break;
            }
        }

        return TRUE;
    }

    void collectAcceleratorResourceHotkeys(
        const std::uint32_t processId,
        const QString& processName,
        const QString& processImagePath,
        std::vector<HotkeyCandidate>& rows,
        QSet<QString>& dedupeSet,
        QString& diagnosticText)
    {
        QStringList modulePaths;
        const auto appendModulePath = [&modulePaths](const QString& pathText)
        {
            const QString normalizedPath = normalizedFilePath(pathText);
            if (!normalizedPath.isEmpty() && QFileInfo(pathText).exists() && !modulePaths.contains(pathText, Qt::CaseInsensitive))
            {
                modulePaths << pathText;
            }
        };

        appendModulePath(processImagePath);
        const ks::process::ProcessModuleSnapshot moduleSnapshot =
            ks::process::EnumerateProcessModulesAndThreads(processId, false);
        for (const ks::process::ProcessModuleRecord& moduleRecord : moduleSnapshot.modules)
        {
            appendModulePath(QString::fromStdString(moduleRecord.modulePath));
            if (modulePaths.size() >= 96)
            {
                diagnosticText += QStringLiteral(" | Accelerator模块扫描已限制为前96个模块");
                break;
            }
        }

        for (const QString& modulePath : modulePaths)
        {
            const std::wstring modulePathW = modulePath.toStdWString();
            HMODULE moduleHandle = ::LoadLibraryExW(
                modulePathW.c_str(),
                nullptr,
                LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE);
            if (moduleHandle == nullptr)
            {
                continue;
            }

            AcceleratorEnumContext context{};
            context.moduleHandle = moduleHandle;
            context.modulePath = modulePath;
            context.processId = processId;
            context.processName = processName;
            context.rows = &rows;
            context.dedupeSet = &dedupeSet;
            ::EnumResourceNamesW(
                moduleHandle,
                RT_ACCELERATOR,
                enumerateAcceleratorResourceProc,
                reinterpret_cast<LONG_PTR>(&context));
            ::FreeLibrary(moduleHandle);
        }
    }

    void collectDriverHotkeyTable(
        const std::uint32_t processId,
        const QString& processName,
        std::vector<HotkeyCandidate>& rows,
        QString& diagnosticText)
    {
        const unsigned long flags =
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_SYSTEM |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS;
        const ksword::ark::KeyboardHotkeyEnumResult driverResult =
            ksword::ark::DriverClient().enumerateKeyboardHotkeys(processId, flags, 2048UL);
        if (!driverResult.io.ok)
        {
            appendDiagnostic(
                diagnosticText,
                QStringLiteral("R0热键不可用:%1").arg(keyboardIoMessageText(driverResult.io.message)));
            return;
        }

        appendDiagnostic(
            diagnosticText,
            QStringLiteral("R0热键:%1 total=%2 returned=%3")
                .arg(keyboardEnumStatusText(driverResult.status))
                .arg(driverResult.totalCount)
                .arg(driverResult.entries.size()));

        for (const ksword::ark::KeyboardHotkeyEntry& entry : driverResult.entries)
        {
            if (entry.processId != 0U && entry.processId != processId)
            {
                continue;
            }

            HotkeyCandidate row{};
            row.objectText = QStringLiteral("tagHOTKEY %1").arg(hex64Text(entry.hotkeyObject));
            row.hotkeyId = entry.hotkeyId;
            row.modifiers = entry.modifiers;
            row.virtualKey = entry.virtualKey;
            row.r0MutationSnapshot.source = entry.source;
            row.r0MutationSnapshot.status = entry.status;
            row.r0MutationSnapshot.flags = entry.flags;
            row.r0MutationSnapshot.bucketIndex = entry.bucketIndex;
            row.r0MutationSnapshot.depth = entry.depth;
            row.r0MutationSnapshot.modifiers = entry.modifiers;
            row.r0MutationSnapshot.modifierFlags2 = entry.modifierFlags2;
            row.r0MutationSnapshot.virtualKey = entry.virtualKey;
            row.r0MutationSnapshot.hotkeyId = entry.hotkeyId;
            row.r0MutationSnapshot.processId = entry.processId;
            row.r0MutationSnapshot.threadId = entry.threadId;
            row.r0MutationSnapshot.hotkeyObject = entry.hotkeyObject;
            row.r0MutationSnapshot.nextHotkeyObject = entry.nextHotkeyObject;
            row.r0MutationSnapshot.sessionGlobals = entry.sessionGlobals;
            row.r0MutationSnapshot.threadInfo = entry.threadInfo;
            row.r0MutationSnapshot.windowHandle = entry.windowHandle;
            row.r0MutationSnapshot.destinationHandle = entry.destinationHandle;
            row.r0MutationSnapshot.callbackAddress = entry.callbackAddress;
            row.r0MutationSnapshot.childListFlink = entry.childListFlink;
            row.r0MutationSnapshot.childListBlink = entry.childListBlink;
            row.r0MutationSnapshot.snapshotHash = entry.snapshotHash;
            row.r0MutationSnapshot.objectSize = entry.objectSize;
            row.r0MutationSnapshot.entryFlags = entry.entryFlags;
            row.hasR0MutationSnapshot =
                (entry.entryFlags & KSWORD_ARK_KEYBOARD_HOTKEY_ENTRY_FLAG_MUTABLE) != 0UL;
            row.hotkeyText = hotkeyTextFromParts(entry.modifiers, entry.virtualKey);
            row.processId = entry.processId == 0U ? processId : entry.processId;
            row.threadId = entry.threadId;
            row.processName = entry.processId == 0U || entry.processId == processId
                ? processName
                : QString::fromStdString(ks::process::GetProcessNameByPID(entry.processId));
            row.sourceText = keyboardHotkeySourceText(entry.source);
            row.detailText = QStringLiteral(
                "status=%1 bucket=%2 depth=%3 next=%4 threadInfo=%5 thread=%6 hwnd=%7 flags2=0x%8 %9")
                .arg(keyboardEnumStatusText(entry.status))
                .arg(entry.bucketIndex)
                .arg(entry.depth)
                .arg(hex64Text(entry.nextHotkeyObject))
                .arg(hex64Text(entry.threadInfo))
                .arg(hex64Text(entry.threadObject))
                .arg(hex64Text(entry.windowObject))
                .arg(entry.modifierFlags2, 0, 16)
                .arg(QString::fromStdWString(entry.detail))
                .toUpper();
            rows.push_back(std::move(row));
        }
    }

    std::vector<KeyboardHookCandidate> collectDriverKeyboardHooks(
        const std::uint32_t processId,
        QString& diagnosticText)
    {
        std::vector<KeyboardHookCandidate> rows;
        const unsigned long flags =
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_THREAD_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_GLOBAL_HOOKS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_INCLUDE_DIAGNOSTICS |
            KSWORD_ARK_KEYBOARD_ENUM_FLAG_FILTER_PROCESS;
        const ksword::ark::KeyboardHookEnumResult driverResult =
            ksword::ark::DriverClient().enumerateKeyboardHooks(processId, flags, 2048UL);
        if (!driverResult.io.ok)
        {
            appendDiagnostic(
                diagnosticText,
                QStringLiteral("R0键盘钩子不可用:%1").arg(keyboardIoMessageText(driverResult.io.message)));
            return rows;
        }

        appendDiagnostic(
            diagnosticText,
            QStringLiteral("R0键盘钩子:%1 total=%2 returned=%3")
                .arg(keyboardEnumStatusText(driverResult.status))
                .arg(driverResult.totalCount)
                .arg(driverResult.entries.size()));

        rows.reserve(driverResult.entries.size());
        for (const ksword::ark::KeyboardHookEntry& entry : driverResult.entries)
        {
            KeyboardHookCandidate row{};
            row.objectText = QStringLiteral("tagHOOK %1").arg(hex64Text(entry.hookObject));
            row.typeText = keyboardHookTypeText(entry.hookType);
            row.scopeText = keyboardHookScopeText(entry.hookScope);
            row.processId = entry.processId;
            row.threadId = entry.threadId;
            row.procedureText = entry.procedureAddress != 0U
                ? hex64Text(entry.procedureAddress)
                : QStringLiteral("offset=%1").arg(hex64Text(entry.procedureOffset));
            row.moduleText = entry.moduleBase != 0U
                ? hex64Text(entry.moduleBase)
                : QStringLiteral("moduleId=%1").arg(entry.moduleId);
            row.sourceText = keyboardHookSourceText(entry.source);
            row.flagsText = QStringLiteral("0x%1").arg(entry.flags, 0, 16).toUpper();
            row.detailText = QStringLiteral(
                "status=%1 chain=%2 next=%3 threadInfo=%4 targetThreadInfo=%5 desktop=%6 last=0x%7 %8")
                .arg(keyboardEnumStatusText(entry.status))
                .arg(hex64Text(entry.chainHead))
                .arg(hex64Text(entry.nextHookObject))
                .arg(hex64Text(entry.threadInfo))
                .arg(hex64Text(entry.targetThreadInfo))
                .arg(hex64Text(entry.desktopInfo))
                .arg(static_cast<unsigned long>(static_cast<std::uint32_t>(entry.lastStatus)), 0, 16)
                .arg(QString::fromStdWString(entry.detail))
                .toUpper();
            rows.push_back(std::move(row));
        }

        return rows;
    }

    std::vector<HotkeyCandidate> collectUserModeHotkeysForProcess(
        const std::uint32_t processId,
        QString processName,
        QString processImagePath,
        QString& diagnosticText,
        const std::vector<ShellShortcutHotkeyCandidate>* const sharedShortcutCandidates = nullptr)
    {
        if (processName.trimmed().isEmpty())
        {
            processName = QString::fromStdString(ks::process::GetProcessNameByPID(processId));
        }
        if (processImagePath.trimmed().isEmpty())
        {
            processImagePath = QString::fromStdString(ks::process::QueryProcessPathByPid(processId));
        }

        std::vector<HotkeyCandidate> rows;
        QSet<QString> dedupeSet;

        collectWindowActivationHotkeys(processId, processName, rows, dedupeSet);
        collectMenuHotkeys(processId, processName, rows, dedupeSet);
        collectAcceleratorResourceHotkeys(processId, processName, processImagePath, rows, dedupeSet, diagnosticText);
        if (sharedShortcutCandidates != nullptr)
        {
            appendShellShortcutHotkeys(
                processId,
                processName,
                processImagePath,
                rows,
                dedupeSet,
                *sharedShortcutCandidates);
        }
        else
        {
            collectShellShortcutHotkeys(processId, processName, processImagePath, rows, dedupeSet, diagnosticText);
        }

        std::sort(
            rows.begin(),
            rows.end(),
            [](const HotkeyCandidate& left, const HotkeyCandidate& right)
            {
                if (left.hotkeyText != right.hotkeyText) return left.hotkeyText < right.hotkeyText;
                if (left.sourceText != right.sourceText) return left.sourceText < right.sourceText;
                return left.objectText < right.objectText;
            });

        return rows;
    }

    std::vector<HotkeyCandidate> collectHotkeysForProcess(
        const std::uint32_t processId,
        QString processName,
        QString processImagePath,
        QString& diagnosticText)
    {
        std::vector<HotkeyCandidate> rows = collectUserModeHotkeysForProcess(
            processId,
            std::move(processName),
            std::move(processImagePath),
            diagnosticText);
        QString resolvedProcessName;
        if (!rows.empty())
        {
            resolvedProcessName = rows.front().processName;
        }
        if (resolvedProcessName.isEmpty())
        {
            resolvedProcessName = QString::fromStdString(ks::process::GetProcessNameByPID(processId));
        }
        collectDriverHotkeyTable(processId, resolvedProcessName, rows, diagnosticText);

        std::sort(
            rows.begin(),
            rows.end(),
            [](const HotkeyCandidate& left, const HotkeyCandidate& right)
            {
                if (left.hotkeyText != right.hotkeyText) return left.hotkeyText < right.hotkeyText;
                if (left.sourceText != right.sourceText) return left.sourceText < right.sourceText;
                return left.objectText < right.objectText;
            });
        return rows;
    }

    QTableWidgetItem* createHotkeyCell(const QString& textValue)
    {
        auto* item = new QTableWidgetItem(textValue);
        item->setFlags(item->flags() & ~Qt::ItemIsEditable);
        return item;
    }

    void configureHotkeyTableGeometry(QTableWidget* tableWidget)
    {
        // 输入：
        // - tableWidget：进程热键页或键盘页中的热键/钩子结果表。
        // 处理：
        // - 表格列宽总和可能超过详情窗初始宽度，尤其“详情/对象”字段包含长路径或 R0 诊断；
        // - 禁止表头最后一列自动拉伸反向扩大 sizeHint；
        // - 固定表格自身最小宽度为 0，让超出的列通过水平滚动条访问。
        // 返回：无，直接调整表格几何策略。
        if (tableWidget == nullptr || tableWidget->horizontalHeader() == nullptr)
        {
            return;
        }

        tableWidget->setMinimumWidth(0);
        tableWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
        tableWidget->setSizeAdjustPolicy(QAbstractScrollArea::AdjustIgnored);
        tableWidget->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        tableWidget->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        tableWidget->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
        tableWidget->horizontalHeader()->setStretchLastSection(false);
    }

    QString compactStatusText(const QString& statusText)
    {
        // 输入：完整状态文本，可能包含很长的 R0 诊断串。
        // 处理：只压缩显示文本，不丢失 tooltip 中的完整诊断。
        // 返回：适合放入单行 QLabel 的短文本。
        constexpr int kStatusTextLimit = 160;
        const QString trimmedText = statusText.trimmed();
        if (trimmedText.size() <= kStatusTextLimit)
        {
            return trimmedText;
        }
        return QStringLiteral("%1...")
            .arg(trimmedText.left(kStatusTextLimit - 3));
    }

    QString hotkeyTableCellText(QTableWidget* tableWidget, const int rowIndex, const int columnIndex)
    {
        // hotkeyTableCellText 作用：
        // - 输入：热键/钩子审计表格以及目标行列；
        // - 处理：只读取当前单元格显示文本，不访问任何底层审计对象；
        // - 返回：单元格不存在时返回空字符串，方便拼接 TSV。
        if (tableWidget == nullptr)
        {
            return QString();
        }

        const QTableWidgetItem* cellItem = tableWidget->item(rowIndex, columnIndex);
        return cellItem != nullptr ? cellItem->text() : QString();
    }

    void copyHotkeyTableCurrentRow(QTableWidget* tableWidget)
    {
        // copyHotkeyTableCurrentRow 作用：
        // - 输入：进程详情中的热键或键盘钩子表格；
        // - 处理：把当前行所有可见列按 TSV 写入剪贴板；
        // - 返回：无。该右键动作只复制审计证据，不触发任何修改操作。
        if (tableWidget == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = tableWidget->currentRow();
        if (rowIndex < 0 || rowIndex >= tableWidget->rowCount())
        {
            return;
        }

        QStringList rowFields;
        rowFields.reserve(tableWidget->columnCount());
        for (int columnIndex = 0; columnIndex < tableWidget->columnCount(); ++columnIndex)
        {
            rowFields.push_back(hotkeyTableCellText(tableWidget, rowIndex, columnIndex));
        }
        QApplication::clipboard()->setText(rowFields.join(QLatin1Char('\t')));
    }

    quint32 hotkeyTableProcessId(
        const QTableWidget* tableWidget,
        const int rowIndex,
        const int processIdColumn)
    {
        if (tableWidget == nullptr || rowIndex < 0 || processIdColumn < 0)
        {
            return 0U;
        }

        const QTableWidgetItem* processIdItem = tableWidget->item(rowIndex, processIdColumn);
        bool ok = false;
        const qulonglong processId = processIdItem != nullptr
            ? processIdItem->text().trimmed().toULongLong(&ok)
            : 0ULL;
        return ok && processId <= std::numeric_limits<quint32>::max()
            ? static_cast<quint32>(processId)
            : 0U;
    }

    bool isEditableHotkeySource(const QString& sourceText)
    {
        return sourceText == QStringLiteral("窗口热键") ||
               sourceText == QStringLiteral("快捷方式热键") ||
               sourceText == QStringLiteral("R0 RegisterHotKey");
    }

    bool setWindowActivationHotkey(
        const QString& objectText,
        const std::uint32_t processId,
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        QString& errorText,
        bool& conflictDetected)
    {
        conflictDetected = false;
        static const QRegularExpression handlePattern(QStringLiteral("^HWND=0x([0-9A-Fa-f]+)$"));
        const QRegularExpressionMatch handleMatch = handlePattern.match(objectText.trimmed());
        bool handleOk = false;
        const qulonglong handleValue = handleMatch.hasMatch()
            ? handleMatch.captured(1).toULongLong(&handleOk, 16)
            : 0ULL;
        HWND windowHandle = handleOk
            ? reinterpret_cast<HWND>(static_cast<std::uintptr_t>(handleValue))
            : nullptr;
        DWORD ownerProcessId = 0;
        if (windowHandle == nullptr ||
            ::IsWindow(windowHandle) == FALSE ||
            ::GetWindowThreadProcessId(windowHandle, &ownerProcessId) == 0U ||
            ownerProcessId != processId)
        {
            errorText = QStringLiteral("stale or invalid HWND");
            return false;
        }

        const WORD hotkeyValue = virtualKey == 0U
            ? 0U
            : MAKEWORD(
                static_cast<BYTE>(virtualKey),
                static_cast<BYTE>(hotkeyfFromModifiers(modifiers)));
        DWORD_PTR messageResult = 0;
        ::SetLastError(ERROR_SUCCESS);
        const LRESULT sendResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_SETHOTKEY,
            hotkeyValue,
            0,
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            500,
            &messageResult);
        const LRESULT hotkeyResult = static_cast<LRESULT>(messageResult);
        if (sendResult == 0 || hotkeyResult <= 0)
        {
            errorText = QStringLiteral("WM_SETHOTKEY result=%1, Win32=%2")
                .arg(hotkeyResult)
                .arg(::GetLastError());
            return false;
        }

        conflictDetected = hotkeyResult == 2;
        return true;
    }

    bool setShellShortcutHotkey(
        const QString& objectText,
        const std::uint32_t modifiers,
        const std::uint32_t virtualKey,
        QString& errorText)
    {
        const QString shortcutPath = QDir::toNativeSeparators(objectText.trimmed());
        if (shortcutPath.isEmpty() || !QFileInfo::exists(shortcutPath))
        {
            errorText = QStringLiteral("shortcut file no longer exists");
            return false;
        }

        const HRESULT initializeResult = ::CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        const bool uninitializeCom = SUCCEEDED(initializeResult);
        if (FAILED(initializeResult) && initializeResult != RPC_E_CHANGED_MODE)
        {
            errorText = QStringLiteral("CoInitializeEx HRESULT=0x%1")
                .arg(static_cast<unsigned long>(initializeResult), 8, 16, QChar('0'))
                .toUpper();
            return false;
        }

        IShellLinkW* shellLink = nullptr;
        IPersistFile* persistFile = nullptr;
        HRESULT operationResult = ::CoCreateInstance(
            CLSID_ShellLink,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_PPV_ARGS(&shellLink));
        if (SUCCEEDED(operationResult) && shellLink != nullptr)
        {
            operationResult = shellLink->QueryInterface(IID_PPV_ARGS(&persistFile));
        }
        else if (SUCCEEDED(operationResult))
        {
            operationResult = E_POINTER;
        }
        const std::wstring shortcutPathW = shortcutPath.toStdWString();
        if (SUCCEEDED(operationResult) && persistFile != nullptr)
        {
            operationResult = persistFile->Load(shortcutPathW.c_str(), STGM_READWRITE);
        }
        else if (SUCCEEDED(operationResult))
        {
            operationResult = E_NOINTERFACE;
        }
        if (SUCCEEDED(operationResult))
        {
            const WORD hotkeyValue = virtualKey == 0U
                ? 0U
                : MAKEWORD(
                    static_cast<BYTE>(virtualKey),
                    static_cast<BYTE>(hotkeyfFromModifiers(modifiers)));
            operationResult = shellLink->SetHotkey(hotkeyValue);
        }
        if (SUCCEEDED(operationResult))
        {
            operationResult = persistFile->Save(shortcutPathW.c_str(), TRUE);
        }

        if (persistFile != nullptr) persistFile->Release();
        if (shellLink != nullptr) shellLink->Release();
        if (uninitializeCom) ::CoUninitialize();

        if (FAILED(operationResult))
        {
            errorText = QStringLiteral("ShellLink HRESULT=0x%1")
                .arg(static_cast<unsigned long>(operationResult), 8, 16, QChar('0'))
                .toUpper();
            return false;
        }
        return true;
    }

    void installHotkeyTableContextMenu(QTableWidget* tableWidget, const int processIdColumn)
    {
        // installHotkeyTableContextMenu 作用：
        // - 输入：需要补齐右键复制能力的热键/钩子表格；
        // - 处理：安装现有样式的右键菜单，并在点击处同步当前行；
        // - 返回：无。菜单提供复制与按当前行 PID 打开进程详情。
        if (tableWidget == nullptr)
        {
            return;
        }

        tableWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(
            tableWidget,
            &QTableWidget::customContextMenuRequested,
            tableWidget,
            [tableWidget, processIdColumn](const QPoint& localPosition)
            {
                const QModelIndex clickedIndex = tableWidget->indexAt(localPosition);
                if (clickedIndex.isValid())
                {
                    tableWidget->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                }

                QMenu contextMenu(tableWidget);
                contextMenu.setStyleSheet(buildProcessDetailMenuStyle());
                QAction* copyRowAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_copy_row.svg")),
                    QStringLiteral("复制当前行"));
                copyRowAction->setEnabled(tableWidget->currentRow() >= 0);
                const quint32 processId = hotkeyTableProcessId(
                    tableWidget,
                    tableWidget->currentRow(),
                    processIdColumn);
                QAction* openProcessAction = contextMenu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processId != 0U);

                QAction* selectedAction = contextMenu.exec(tableWidget->viewport()->mapToGlobal(localPosition));
                if (selectedAction == copyRowAction)
                {
                    copyHotkeyTableCurrentRow(tableWidget);
                }
                else if (selectedAction == openProcessAction)
                {
                    ks::ui::OpenProcessDetailByPid(processId);
                }
            });
    }
}

std::vector<ks::process::UserModeHotkeyRecord> ks::process::EnumerateUserModeHotkeysForProcess(
    const std::uint32_t processId,
    QString processName,
    QString processImagePath,
    QString* const diagnosticTextOut)
{
    QString diagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
    const std::vector<HotkeyCandidate> candidates = collectUserModeHotkeysForProcess(
        processId,
        std::move(processName),
        std::move(processImagePath),
        diagnosticText);

    std::vector<UserModeHotkeyRecord> records;
    records.reserve(candidates.size());
    for (const HotkeyCandidate& candidate : candidates)
    {
        UserModeHotkeyRecord record{};
        record.objectText = candidate.objectText;
        record.hotkeyId = candidate.hotkeyId;
        record.modifiers = candidate.modifiers;
        record.virtualKey = candidate.virtualKey;
        record.hotkeyText = candidate.hotkeyText;
        record.processId = candidate.processId;
        record.threadId = candidate.threadId;
        record.processName = candidate.processName;
        record.sourceText = candidate.sourceText;
        record.detailText = candidate.detailText;
        records.push_back(std::move(record));
    }

    if (diagnosticTextOut != nullptr)
    {
        *diagnosticTextOut = diagnosticText;
    }
    return records;
}

void ks::process::EnumerateUserModeHotkeysForProcesses(
    const std::vector<UserModeHotkeyProcessTarget>& targets,
    const UserModeHotkeyBatchCallback& progressCallback,
    QString* const diagnosticTextOut)
{
    QString sharedDiagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
    std::vector<ShellShortcutHotkeyCandidate> sharedShortcutCandidates;
    collectShellShortcutHotkeyCandidates(sharedShortcutCandidates, sharedDiagnosticText);

    const std::uint32_t totalProcessCount = static_cast<std::uint32_t>(targets.size());
    if (totalProcessCount == 0U)
    {
        if (diagnosticTextOut != nullptr)
        {
            *diagnosticTextOut = sharedDiagnosticText;
        }
        return;
    }

    const unsigned int hardwareConcurrency = std::thread::hardware_concurrency();
    const unsigned int workerCount = std::min<unsigned int>(
        totalProcessCount,
        std::clamp(hardwareConcurrency == 0U ? 2U : hardwareConcurrency / 2U, 2U, 4U));
    std::atomic_size_t nextTargetIndex{ 0U };
    std::atomic_uint32_t completedProcessCount{ 0U };
    std::vector<std::thread> workers;
    workers.reserve(workerCount);

    for (unsigned int workerIndex = 0U; workerIndex < workerCount; ++workerIndex)
    {
        workers.emplace_back([&targets,
                              &progressCallback,
                              &sharedShortcutCandidates,
                              &nextTargetIndex,
                              &completedProcessCount,
                              totalProcessCount]()
        {
            for (;;)
            {
                const std::size_t targetIndex = nextTargetIndex.fetch_add(1U);
                if (targetIndex >= targets.size())
                {
                    return;
                }

                const UserModeHotkeyProcessTarget& target = targets.at(targetIndex);
                QString diagnosticText = QStringLiteral("R3 窗口/菜单/资源/.lnk");
                const std::vector<HotkeyCandidate> candidates = collectUserModeHotkeysForProcess(
                    target.processId,
                    target.processName,
                    target.processImagePath,
                    diagnosticText,
                    &sharedShortcutCandidates);

                UserModeHotkeyBatchProgress progress{};
                progress.completedProcessCount = completedProcessCount.fetch_add(1U) + 1U;
                progress.totalProcessCount = totalProcessCount;
                progress.processName = target.processName;
                progress.diagnosticText = diagnosticText;
                progress.records.reserve(candidates.size());
                for (const HotkeyCandidate& candidate : candidates)
                {
                    UserModeHotkeyRecord record{};
                    record.objectText = candidate.objectText;
                    record.hotkeyId = candidate.hotkeyId;
                    record.modifiers = candidate.modifiers;
                    record.virtualKey = candidate.virtualKey;
                    record.hotkeyText = candidate.hotkeyText;
                    record.processId = candidate.processId;
                    record.threadId = candidate.threadId;
                    record.processName = candidate.processName;
                    record.sourceText = candidate.sourceText;
                    record.detailText = candidate.detailText;
                    progress.records.push_back(std::move(record));
                }

                if (progressCallback)
                {
                    progressCallback(std::move(progress));
                }
            }
        });
    }

    for (std::thread& worker : workers)
    {
        worker.join();
    }

    if (diagnosticTextOut != nullptr)
    {
        *diagnosticTextOut = sharedDiagnosticText;
    }
}

void ProcessDetailWindow::initializeHotkeyTab()
{
    kLogEvent initHotkeyTabEvent;
    info << initHotkeyTabEvent
        << "[ProcessDetailWindow] initializeHotkeyTab: 构建进程热键页面。"
        << eol;

    m_hotkeyLayout = new QVBoxLayout(m_hotkeyTab);
    m_hotkeyLayout->setContentsMargins(6, 6, 6, 6);
    m_hotkeyLayout->setSpacing(8);

    QGroupBox* hotkeyGroup = new QGroupBox(QStringLiteral("进程热键检测"), m_hotkeyTab);
    QVBoxLayout* hotkeyGroupLayout = new QVBoxLayout(hotkeyGroup);
    hotkeyGroupLayout->setContentsMargins(8, 8, 8, 8);
    hotkeyGroupLayout->setSpacing(6);

    QHBoxLayout* topBarLayout = new QHBoxLayout();
    m_refreshHotkeyButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新热键"), hotkeyGroup);
    m_refreshHotkeyButton->setToolTip(QStringLiteral("扫描当前进程的窗口热键、菜单快捷键、Accelerator资源、快捷方式热键和R0热键表"));
    m_editHotkeyButton = new QPushButton(
        hotkeyUiText(QStringLiteral("process.hotkey.edit"), QStringLiteral("编辑热键")),
        hotkeyGroup);
    m_editHotkeyButton->setToolTip(hotkeyUiText(
        QStringLiteral("process.hotkey.edit.tooltip"),
        QStringLiteral("修改选中的窗口激活热键或 .lnk 快捷方式热键；双击行也可编辑")));
    m_editHotkeyButton->setEnabled(false);
    m_deleteHotkeyButton = new QPushButton(
        hotkeyUiText(QStringLiteral("process.hotkey.delete"), QStringLiteral("删除热键")),
        hotkeyGroup);
    m_deleteHotkeyButton->setToolTip(hotkeyUiText(
        QStringLiteral("process.hotkey.delete.tooltip"),
        QStringLiteral("删除选中的窗口、快捷方式或可安全修改的 R0 RegisterHotKey 热键")));
    m_deleteHotkeyButton->setEnabled(false);
    m_hotkeyStatusLabel = new QLabel(QStringLiteral("● 尚未刷新"), hotkeyGroup);
    m_hotkeyStatusLabel->setMinimumWidth(0);
    m_hotkeyStatusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_hotkeyStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    topBarLayout->addWidget(m_refreshHotkeyButton);
    topBarLayout->addWidget(m_editHotkeyButton);
    topBarLayout->addWidget(m_hotkeyStatusLabel, 1);
    topBarLayout->addWidget(m_deleteHotkeyButton);
    ks::ui::NormalizeToolbarRow(topBarLayout);
    hotkeyGroupLayout->addLayout(topBarLayout);

    m_hotkeyTable = new ks::ui::VisibleTableWidget(hotkeyGroup);
    // 热键管理已提供编辑/删除动作，小清单只保留复制导出。
    ks::ui::SetTableActionBarMode(m_hotkeyTable, ks::ui::TableActionBarMode::Compact);
    m_hotkeyTable->setColumnCount(9);
    m_hotkeyTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("热键ID"),
        QStringLiteral("热键"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("进程名"),
        QStringLiteral("来源"),
        QStringLiteral("VK/Mod"),
        QStringLiteral("详情")
    });
    m_hotkeyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_hotkeyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_hotkeyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_hotkeyTable->setAlternatingRowColors(true);
    m_hotkeyTable->setSortingEnabled(true);
    m_hotkeyTable->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(m_hotkeyTable);
    m_hotkeyTable->setColumnWidth(0, 260);
    m_hotkeyTable->setColumnWidth(1, 80);
    m_hotkeyTable->setColumnWidth(2, 130);
    m_hotkeyTable->setColumnWidth(3, 80);
    m_hotkeyTable->setColumnWidth(4, 80);
    m_hotkeyTable->setColumnWidth(5, 120);
    m_hotkeyTable->setColumnWidth(6, 130);
    m_hotkeyTable->setColumnWidth(7, 120);
    installHotkeyTableContextMenu(m_hotkeyTable, 3);
    connect(m_editHotkeyButton, &QPushButton::clicked, this, [this]() {
        editSelectedHotkey();
    });
    connect(m_deleteHotkeyButton, &QPushButton::clicked, this, [this]() {
        deleteSelectedHotkey();
    });
    connect(m_hotkeyTable, &QTableWidget::itemSelectionChanged, this, [this]() {
        if (m_editHotkeyButton != nullptr)
        {
            m_editHotkeyButton->setEnabled(!m_hotkeyRefreshing && m_hotkeyTable->currentRow() >= 0);
        }
        if (m_deleteHotkeyButton != nullptr)
        {
            m_deleteHotkeyButton->setEnabled(!m_hotkeyRefreshing && m_hotkeyTable->currentRow() >= 0);
        }
    });
    connect(m_hotkeyTable, &QTableWidget::cellDoubleClicked, this, [this](const int, const int) {
        editSelectedHotkey();
    });
    hotkeyGroupLayout->addWidget(m_hotkeyTable, 1);

    m_hotkeyLayout->addWidget(hotkeyGroup, 1);

    const QString buttonStyle = buildBlueButtonStyle();
    m_refreshHotkeyButton->setStyleSheet(buttonStyle);
    m_editHotkeyButton->setStyleSheet(buttonStyle);
    m_deleteHotkeyButton->setStyleSheet(buttonStyle);
}

void ProcessDetailWindow::editSelectedHotkey()
{
    const QString titleText = hotkeyUiText(
        QStringLiteral("process.hotkey.edit.title"),
        QStringLiteral("编辑热键"));
    if (m_hotkeyTable == nullptr || m_hotkeyTable->currentRow() < 0)
    {
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.select_row"),
                QStringLiteral("请先选择一条热键记录。")));
        return;
    }

    const QTableWidgetItem* rowIdentityItem = m_hotkeyTable->item(m_hotkeyTable->currentRow(), 0);
    bool rowIndexOk = false;
    const qulonglong rowIndexValue = rowIdentityItem != nullptr
        ? rowIdentityItem->data(kHotkeyRowIndexRole).toULongLong(&rowIndexOk)
        : 0ULL;
    if (!rowIndexOk || rowIndexValue >= m_hotkeyRows.size())
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.stale"),
                QStringLiteral("所选记录已失效，请刷新后重试。")));
        return;
    }

    const HotkeyInspectItem row = m_hotkeyRows.at(static_cast<std::size_t>(rowIndexValue));
    const bool isR0Hotkey = row.sourceText == QStringLiteral("R0 RegisterHotKey");
    if (!isEditableHotkeySource(row.sourceText))
    {
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.unsupported"),
                QStringLiteral("此来源是只读审计数据。当前仅支持修改窗口激活热键、.lnk 快捷方式热键和通过安全快照验证的 R0 RegisterHotKey 项。")));
        return;
    }
    if (isR0Hotkey && !row.hasR0MutationSnapshot)
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.not_mutable"),
                QStringLiteral("该 R0 热键不是普通独立项，或枚举时未取得完整对象快照，因此不能修改。")));
        return;
    }

    bool accepted = false;
    const QString editedText = QInputDialog::getText(
        this,
        titleText,
        hotkeyUiText(
            QStringLiteral("process.hotkey.edit.prompt"),
            QStringLiteral("输入新热键（例如 Ctrl+Alt+K；留空可清除）：")),
        QLineEdit::Normal,
        row.hotkeyText,
        &accepted).trimmed();
    if (!accepted)
    {
        return;
    }

    if (isR0Hotkey && editedText.isEmpty())
    {
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.use_delete"),
                QStringLiteral("R0 热键请使用“删除热键”按钮删除；编辑操作必须提供新的组合。")));
        return;
    }
    std::uint32_t modifiers = 0;
    std::uint32_t virtualKey = 0;
    if (!editedText.isEmpty() && !parseHotkeyText(editedText, modifiers, virtualKey))
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.invalid"),
                QStringLiteral("无法识别该热键。请使用 Ctrl、Shift、Alt 加字母、数字、F1-F24 或常用功能键。")));
        return;
    }
    if (isR0Hotkey)
    {
        modifiers |= row.modifiers & MOD_NOREPEAT;
    }
    if (!isR0Hotkey && (modifiers & MOD_WIN) != 0U)
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.win_unsupported"),
                QStringLiteral("Windows 键不受 WM_SETHOTKEY 或 .lnk 热键字段支持，请改用 Ctrl、Shift 或 Alt。")));
        return;
    }

    if (isR0Hotkey)
    {
        const QString confirmText = hotkeyUiText(
            QStringLiteral("process.hotkey.r0.edit.confirm"),
            QStringLiteral("这会在内核 USER 临界区内修改 RegisterHotKey 对象。驱动只接受完全一致的快照，并验证除组合键及必要链指针外的所有字节保持不变。\n\n确认将 %1 修改为 %2？"))
            .arg(row.hotkeyText, hotkeyTextFromParts(modifiers, virtualKey));
        if (QMessageBox::warning(
                this,
                titleText,
                confirmText,
                QMessageBox::Yes | QMessageBox::No,
                QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }

        const ksword::ark::KeyboardHotkeyMutationResult mutationResult =
            ksword::ark::DriverClient().mutateKeyboardHotkey(
                row.r0MutationSnapshot,
                KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_EDIT,
                modifiers,
                virtualKey);
        if (!mutationResult.io.ok ||
            mutationResult.response.status != KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK ||
            (mutationResult.response.responseFlags &
                KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_OTHER_BYTES_SAME) == 0UL)
        {
            QMessageBox::critical(
                this,
                titleText,
                hotkeyUiText(QStringLiteral("process.hotkey.edit.failed"), QStringLiteral("热键修改失败：%1"))
                    .arg(keyboardMutationFailureText(mutationResult)));
            return;
        }
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(QStringLiteral("process.hotkey.edit.success"), QStringLiteral("热键已修改为 %1。"))
                .arg(hotkeyTextFromParts(modifiers, virtualKey)));
        requestAsyncHotkeyRefresh();
        return;
    }

    QString errorText;
    bool conflictDetected = false;
    const bool updateSucceeded = row.sourceText == QStringLiteral("窗口热键")
        ? setWindowActivationHotkey(row.objectText, row.processId, modifiers, virtualKey, errorText, conflictDetected)
        : setShellShortcutHotkey(row.objectText, modifiers, virtualKey, errorText);
    if (!updateSucceeded)
    {
        QMessageBox::critical(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.failed"),
                QStringLiteral("热键修改失败：%1")).arg(errorText));
        return;
    }

    const QString resultText = editedText.isEmpty()
        ? hotkeyUiText(
            QStringLiteral("process.hotkey.edit.cleared"),
            QStringLiteral("热键已清除。"))
        : hotkeyUiText(
            QStringLiteral("process.hotkey.edit.success"),
            QStringLiteral("热键已修改为 %1。")).arg(hotkeyTextFromParts(modifiers, virtualKey));
    QMessageBox::information(
        this,
        titleText,
        conflictDetected
            ? resultText + QStringLiteral("\n") + hotkeyUiText(
                QStringLiteral("process.hotkey.edit.window_conflict"),
                QStringLiteral("提示：系统报告另一个窗口使用了相同热键。"))
            : resultText);
    requestAsyncHotkeyRefresh();
}


void ProcessDetailWindow::deleteSelectedHotkey()
{
    const QString titleText = hotkeyUiText(
        QStringLiteral("process.hotkey.delete.title"),
        QStringLiteral("删除热键"));
    if (m_hotkeyTable == nullptr || m_hotkeyTable->currentRow() < 0)
    {
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.select_row"),
                QStringLiteral("请先选择一条热键记录。")));
        return;
    }

    const QTableWidgetItem* rowIdentityItem = m_hotkeyTable->item(m_hotkeyTable->currentRow(), 0);
    bool rowIndexOk = false;
    const qulonglong rowIndexValue = rowIdentityItem != nullptr
        ? rowIdentityItem->data(kHotkeyRowIndexRole).toULongLong(&rowIndexOk)
        : 0ULL;
    if (!rowIndexOk || rowIndexValue >= m_hotkeyRows.size())
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.edit.stale"),
                QStringLiteral("所选记录已失效，请刷新后重试。")));
        return;
    }

    const HotkeyInspectItem row = m_hotkeyRows.at(static_cast<std::size_t>(rowIndexValue));
    const bool isR0Hotkey = row.sourceText == QStringLiteral("R0 RegisterHotKey");
    if (!isEditableHotkeySource(row.sourceText))
    {
        QMessageBox::information(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.delete.unsupported"),
                QStringLiteral("该来源是只读审计数据，不能删除。")));
        return;
    }
    if (isR0Hotkey && !row.hasR0MutationSnapshot)
    {
        QMessageBox::warning(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.r0.not_mutable"),
                QStringLiteral("该 R0 热键不是普通独立项，或枚举时未取得完整对象快照，因此不能修改。")));
        return;
    }

    const QString confirmText = isR0Hotkey
        ? hotkeyUiText(
            QStringLiteral("process.hotkey.r0.delete.confirm"),
            QStringLiteral("这会在内核 USER 临界区内调用 win32k 的标准热键删除路径。驱动会重新验证完整对象快照，并拒绝回调、占位或含子项的对象。\n\n确认删除 %1（%2）？"))
            .arg(row.hotkeyText, row.objectText)
        : hotkeyUiText(
            QStringLiteral("process.hotkey.delete.confirm"),
            QStringLiteral("确认删除 %1（%2）？"))
            .arg(row.hotkeyText, row.objectText);
    const QMessageBox::StandardButton confirmed = isR0Hotkey
        ? QMessageBox::warning(
            this,
            titleText,
            confirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No)
        : QMessageBox::question(
            this,
            titleText,
            confirmText,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if (confirmed != QMessageBox::Yes)
    {
        return;
    }

    QString errorText;
    if (isR0Hotkey)
    {
        const ksword::ark::KeyboardHotkeyMutationResult mutationResult =
            ksword::ark::DriverClient().mutateKeyboardHotkey(
                row.r0MutationSnapshot,
                KSWORD_ARK_KEYBOARD_MUTATION_OPERATION_DELETE);
        if (!mutationResult.io.ok ||
            mutationResult.response.status != KSWORD_ARK_KEYBOARD_MUTATION_STATUS_OK ||
            (mutationResult.response.responseFlags &
                KSWORD_ARK_KEYBOARD_MUTATION_RESPONSE_CHANGED) == 0UL)
        {
            errorText = keyboardMutationFailureText(mutationResult);
        }
    }
    else
    {
        bool conflictDetected = false;
        const bool deleted = row.sourceText == QStringLiteral("窗口热键")
            ? setWindowActivationHotkey(row.objectText, row.processId, 0U, 0U, errorText, conflictDetected)
            : setShellShortcutHotkey(row.objectText, 0U, 0U, errorText);
        if (!deleted && errorText.isEmpty())
        {
            errorText = hotkeyUiText(
                QStringLiteral("process.hotkey.delete.operation_failed"),
                QStringLiteral("公开接口未能清除该热键。"));
        }
    }

    if (!errorText.isEmpty())
    {
        QMessageBox::critical(
            this,
            titleText,
            hotkeyUiText(
                QStringLiteral("process.hotkey.delete.failed"),
                QStringLiteral("热键删除失败：%1")).arg(errorText));
        return;
    }
    QMessageBox::information(
        this,
        titleText,
        hotkeyUiText(QStringLiteral("process.hotkey.delete.success"), QStringLiteral("热键已删除。")));
    requestAsyncHotkeyRefresh();
}
void ProcessDetailWindow::showHotkeyTabAndRefresh()
{
    // 右键菜单直达入口：
    // - 输入：无，目标进程来自当前详情窗口绑定的 m_baseRecord；
    // - 处理：先切到“进程热键”页，再复用已有异步热键刷新函数；
    // - 返回：无。若控件尚未初始化或扫描正在进行，则保持当前安全状态。
    if (m_tabWidget != nullptr && m_hotkeyTab != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_hotkeyTab);
    }

    if (!m_hotkeyRefreshing)
    {
        requestAsyncHotkeyRefresh();
    }

    kLogEvent hotkeyEntryEvent;
    info << hotkeyEntryEvent
        << "[ProcessDetailWindow] showHotkeyTabAndRefresh: pid="
        << m_baseRecord.pid
        << eol;
}

void ProcessDetailWindow::updateHotkeyStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_hotkeyStatusLabel == nullptr)
    {
        return;
    }

    m_hotkeyStatusLabel->setToolTip(statusText);
    m_hotkeyStatusLabel->setText(compactStatusText(statusText));
    if (refreshing)
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

void ProcessDetailWindow::requestAsyncHotkeyRefresh()
{
    if (m_hotkeyRefreshing || m_baseRecord.pid == 0)
    {
        return;
    }

    m_hotkeyInitialRefreshStarted = true;
    m_hotkeyRefreshing = true;
    const std::uint64_t ticketValue = ++m_hotkeyRefreshTicket;
    const std::uint32_t pidValue = m_baseRecord.pid;
    const QString processNameText = QString::fromStdString(m_baseRecord.processName);
    const QString processImagePathText = QString::fromStdString(m_baseRecord.imagePath);

    if (m_refreshHotkeyButton != nullptr)
    {
        m_refreshHotkeyButton->setEnabled(false);
    }
    if (m_editHotkeyButton != nullptr)
    {
        m_editHotkeyButton->setEnabled(false);
    }
    updateHotkeyStatusLabel(QStringLiteral("● 正在扫描进程热键..."), true);

    if (m_deleteHotkeyButton != nullptr)
    {
        m_deleteHotkeyButton->setEnabled(false);
    }
    if (m_hotkeyRefreshProgressPid == 0)
    {
        m_hotkeyRefreshProgressPid = kPro.addReusable(this, "进程详情", "扫描进程热键");
    }
    kPro.set(m_hotkeyRefreshProgressPid, "枚举窗口/菜单/资源/快捷方式", 0, 20.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create(
        [guardThis, ticketValue, pidValue, processNameText, processImagePathText]()
        {
            HotkeyInspectRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();

            QString diagnosticText = QStringLiteral("R3窗口/菜单/资源/.lnk + R0 win32k热键表");
            const std::vector<HotkeyCandidate> candidates = collectHotkeysForProcess(
                pidValue,
                processNameText,
                processImagePathText,
                diagnosticText);

            refreshResult.rows.reserve(candidates.size());
            for (const HotkeyCandidate& candidate : candidates)
            {
                HotkeyInspectItem row{};
                row.objectText = candidate.objectText;
                row.hotkeyId = candidate.hotkeyId;
                row.modifiers = candidate.modifiers;
                row.virtualKey = candidate.virtualKey;
                row.hotkeyText = candidate.hotkeyText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.processName = candidate.processName;
                row.sourceText = candidate.sourceText;
                row.detailText = candidate.detailText;
                row.hasR0MutationSnapshot = candidate.hasR0MutationSnapshot;
                row.r0MutationSnapshot = candidate.r0MutationSnapshot;
                refreshResult.rows.push_back(std::move(row));
            }

            refreshResult.diagnosticText = diagnosticText;
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticketValue, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->m_hotkeyRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyHotkeyRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });

    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyHotkeyRefreshResult(const HotkeyInspectRefreshResult& refreshResult)
{
    QPointer<ProcessDetailWindow> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("process-detail-hotkey-snapshot-apply"),
            {m_hotkeyTable, m_keyboardHotkeyTable},
            [guardThis, refreshResult]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyHotkeyRefreshResult(refreshResult);
                }
            }))
    {
        return;
    }

    m_hotkeyRefreshing = false;
    if (m_refreshHotkeyButton != nullptr)
    {
        m_refreshHotkeyButton->setEnabled(true);
    }

    m_hotkeyRows = refreshResult.rows;
    m_keyboardHotkeyRows = refreshResult.rows;
    rebuildHotkeyTable();
    rebuildKeyboardHotkeyTable();

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 热键:%2")
        .arg(refreshResult.elapsedMs)
        .arg(static_cast<qulonglong>(refreshResult.rows.size()));
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateHotkeyStatusLabel(statusText, false);

    if (m_hotkeyRefreshProgressPid > 0)
    {
        kPro.set(m_hotkeyRefreshProgressPid, "进程热键扫描完成", 100, 1.0f);
    }

    kLogEvent hotkeyRefreshDoneEvent;
    info << hotkeyRefreshDoneEvent
        << "[ProcessDetailWindow] 进程热键扫描完成, pid="
        << m_baseRecord.pid
        << ", rows="
        << refreshResult.rows.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildHotkeyTable()
{
    if (m_hotkeyTable == nullptr)
    {
        return;
    }

    m_hotkeyTable->setSortingEnabled(false);
    m_hotkeyTable->setRowCount(0);

    for (std::size_t rowCacheIndex = 0; rowCacheIndex < m_hotkeyRows.size(); ++rowCacheIndex)
    {
        const HotkeyInspectItem& rowItem = m_hotkeyRows.at(rowCacheIndex);
        const int row = m_hotkeyTable->rowCount();
        m_hotkeyTable->insertRow(row);

        const QString idText = rowItem.hotkeyId == 0U
            ? QStringLiteral("0")
            : QStringLiteral("0x%1").arg(rowItem.hotkeyId, 0, 16).toUpper();
        const QString threadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);
        const QString vkModText = QStringLiteral("VK=0x%1 MOD=0x%2")
            .arg(rowItem.virtualKey, 2, 16, QChar('0'))
            .arg(rowItem.modifiers, 2, 16, QChar('0'))
            .toUpper();

        m_hotkeyTable->setItem(row, 0, createHotkeyCell(rowItem.objectText));
        m_hotkeyTable->setItem(row, 1, createHotkeyCell(idText));
        m_hotkeyTable->setItem(row, 2, createHotkeyCell(rowItem.hotkeyText));
        m_hotkeyTable->setItem(row, 3, createHotkeyCell(QString::number(rowItem.processId)));
        m_hotkeyTable->setItem(row, 4, createHotkeyCell(threadText));
        m_hotkeyTable->setItem(row, 5, createHotkeyCell(rowItem.processName));
        m_hotkeyTable->setItem(row, 6, createHotkeyCell(rowItem.sourceText));
        m_hotkeyTable->setItem(row, 7, createHotkeyCell(vkModText));
        m_hotkeyTable->setItem(row, 8, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < m_hotkeyTable->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = m_hotkeyTable->item(row, column);
            if (cellItem != nullptr)
            {
                cellItem->setData(kHotkeyRowIndexRole, static_cast<qulonglong>(rowCacheIndex));
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    m_hotkeyTable->setSortingEnabled(true);
}

void ProcessDetailWindow::initializeKeyboardTab()
{
    kLogEvent initKeyboardTabEvent;
    info << initKeyboardTabEvent
        << "[ProcessDetailWindow] initializeKeyboardTab: 构建键盘页面。"
        << eol;

    m_keyboardLayout = new QVBoxLayout(m_keyboardTab);
    m_keyboardLayout->setContentsMargins(6, 6, 6, 6);
    m_keyboardLayout->setSpacing(8);

    QGroupBox* keyboardGroup = new QGroupBox(QStringLiteral("键盘检测"), m_keyboardTab);
    QVBoxLayout* keyboardGroupLayout = new QVBoxLayout(keyboardGroup);
    keyboardGroupLayout->setContentsMargins(8, 8, 8, 8);
    keyboardGroupLayout->setSpacing(6);

    QHBoxLayout* topBarLayout = new QHBoxLayout();
    m_refreshKeyboardButton = new QPushButton(QIcon(":/Icon/process_refresh.svg"), QStringLiteral("刷新键盘"), keyboardGroup);
    m_refreshKeyboardButton->setToolTip(QStringLiteral("扫描热键表和 WH_KEYBOARD/WH_KEYBOARD_LL 钩子链"));
    m_keyboardStatusLabel = new QLabel(QStringLiteral("● 尚未刷新"), keyboardGroup);
    m_keyboardStatusLabel->setMinimumWidth(0);
    m_keyboardStatusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_keyboardStatusLabel->setStyleSheet(
        QStringLiteral("color:%1; font-weight:600;")
        .arg(KswordTheme::TextSecondaryHex()));
    topBarLayout->addWidget(m_refreshKeyboardButton);
    topBarLayout->addWidget(m_keyboardStatusLabel, 1);
    ks::ui::NormalizeToolbarRow(topBarLayout);
    keyboardGroupLayout->addLayout(topBarLayout);

    m_keyboardInnerTabWidget = new QTabWidget(keyboardGroup);
    ks::ui::StylePageTabs(m_keyboardInnerTabWidget);
    QWidget* hotkeyPage = new QWidget(m_keyboardInnerTabWidget);
    QWidget* hookPage = new QWidget(m_keyboardInnerTabWidget);
    m_keyboardTab->setMinimumWidth(0);
    m_keyboardTab->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    keyboardGroup->setMinimumWidth(0);
    keyboardGroup->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    m_keyboardInnerTabWidget->setMinimumWidth(0);
    m_keyboardInnerTabWidget->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    hotkeyPage->setMinimumWidth(0);
    hotkeyPage->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    hookPage->setMinimumWidth(0);
    hookPage->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Expanding);
    auto* hotkeyLayout = new QVBoxLayout(hotkeyPage);
    auto* hookLayout = new QVBoxLayout(hookPage);
    hotkeyLayout->setContentsMargins(0, 0, 0, 0);
    hookLayout->setContentsMargins(0, 0, 0, 0);

    m_keyboardHotkeyTable = new ks::ui::VisibleTableWidget(hotkeyPage);
    ks::ui::SetTableActionBarMode(m_keyboardHotkeyTable, ks::ui::TableActionBarMode::Compact);
    m_keyboardHotkeyTable->setColumnCount(9);
    m_keyboardHotkeyTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("热键ID"),
        QStringLiteral("热键"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("进程名"),
        QStringLiteral("来源"),
        QStringLiteral("VK/Mod"),
        QStringLiteral("详情")
    });
    m_keyboardHotkeyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_keyboardHotkeyTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_keyboardHotkeyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_keyboardHotkeyTable->setAlternatingRowColors(true);
    m_keyboardHotkeyTable->setSortingEnabled(true);
    m_keyboardHotkeyTable->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(m_keyboardHotkeyTable);
    m_keyboardHotkeyTable->setColumnWidth(0, 260);
    m_keyboardHotkeyTable->setColumnWidth(1, 80);
    m_keyboardHotkeyTable->setColumnWidth(2, 130);
    m_keyboardHotkeyTable->setColumnWidth(3, 80);
    m_keyboardHotkeyTable->setColumnWidth(4, 80);
    m_keyboardHotkeyTable->setColumnWidth(5, 120);
    m_keyboardHotkeyTable->setColumnWidth(6, 150);
    m_keyboardHotkeyTable->setColumnWidth(7, 120);
    installHotkeyTableContextMenu(m_keyboardHotkeyTable, 3);
    hotkeyLayout->addWidget(m_keyboardHotkeyTable, 1);

    m_keyboardHookTable = new ks::ui::VisibleTableWidget(hookPage);
    // Hook 链具有独立取证意义，保留完整快照功能。
    ks::ui::SetTableActionBarMode(m_keyboardHookTable, ks::ui::TableActionBarMode::Full);
    m_keyboardHookTable->setColumnCount(10);
    m_keyboardHookTable->setHorizontalHeaderLabels(QStringList{
        QStringLiteral("对象"),
        QStringLiteral("类型"),
        QStringLiteral("范围"),
        QStringLiteral("进程ID"),
        QStringLiteral("线程ID"),
        QStringLiteral("函数/偏移"),
        QStringLiteral("模块"),
        QStringLiteral("来源"),
        QStringLiteral("Flags"),
        QStringLiteral("详情")
    });
    m_keyboardHookTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_keyboardHookTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_keyboardHookTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_keyboardHookTable->setAlternatingRowColors(true);
    m_keyboardHookTable->setSortingEnabled(true);
    m_keyboardHookTable->verticalHeader()->setVisible(false);
    configureHotkeyTableGeometry(m_keyboardHookTable);
    m_keyboardHookTable->setColumnWidth(0, 180);
    m_keyboardHookTable->setColumnWidth(1, 120);
    m_keyboardHookTable->setColumnWidth(2, 90);
    m_keyboardHookTable->setColumnWidth(3, 80);
    m_keyboardHookTable->setColumnWidth(4, 80);
    m_keyboardHookTable->setColumnWidth(5, 150);
    m_keyboardHookTable->setColumnWidth(6, 130);
    m_keyboardHookTable->setColumnWidth(7, 160);
    m_keyboardHookTable->setColumnWidth(8, 80);
    installHotkeyTableContextMenu(m_keyboardHookTable, 3);
    hookLayout->addWidget(m_keyboardHookTable, 1);

    m_keyboardInnerTabWidget->addTab(hotkeyPage, QIcon(":/Icon/process_hotkey.svg"), QStringLiteral("热键"));
    m_keyboardInnerTabWidget->addTab(hookPage, QIcon(":/Icon/process_critical.svg"), QStringLiteral("键盘钩子"));
    keyboardGroupLayout->addWidget(m_keyboardInnerTabWidget, 1);
    m_keyboardLayout->addWidget(keyboardGroup, 1);

    m_refreshKeyboardButton->setStyleSheet(buildBlueButtonStyle());
}

void ProcessDetailWindow::updateKeyboardStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_keyboardStatusLabel == nullptr)
    {
        return;
    }

    m_keyboardStatusLabel->setToolTip(statusText);
    m_keyboardStatusLabel->setText(compactStatusText(statusText));
    if (refreshing)
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

void ProcessDetailWindow::requestAsyncKeyboardRefresh()
{
    if (m_keyboardRefreshing || m_baseRecord.pid == 0)
    {
        return;
    }

    m_keyboardInitialRefreshStarted = true;
    m_keyboardRefreshing = true;
    const std::uint64_t ticketValue = ++m_keyboardRefreshTicket;
    const std::uint32_t pidValue = m_baseRecord.pid;
    const QString processNameText = QString::fromStdString(m_baseRecord.processName);
    const QString processImagePathText = QString::fromStdString(m_baseRecord.imagePath);

    if (m_refreshKeyboardButton != nullptr)
    {
        m_refreshKeyboardButton->setEnabled(false);
    }
    updateKeyboardStatusLabel(QStringLiteral("● 正在扫描键盘热键与钩子..."), true);

    if (m_keyboardRefreshProgressPid == 0)
    {
        m_keyboardRefreshProgressPid = kPro.addReusable(this, "进程详情", "扫描键盘");
    }
    kPro.set(m_keyboardRefreshProgressPid, "枚举热键表和键盘钩子链", 0, 20.0f);

    QPointer<ProcessDetailWindow> guardThis(this);
    auto* refreshTask = QRunnable::create(
        [guardThis, ticketValue, pidValue, processNameText, processImagePathText]()
        {
            KeyboardInspectRefreshResult refreshResult{};
            const auto beginTime = std::chrono::steady_clock::now();

            QString diagnosticText = QStringLiteral("R3窗口/菜单/资源/.lnk + R0 win32k热键/钩子");
            const std::vector<HotkeyCandidate> hotkeyCandidates = collectHotkeysForProcess(
                pidValue,
                processNameText,
                processImagePathText,
                diagnosticText);
            refreshResult.hotkeyRows.reserve(hotkeyCandidates.size());
            for (const HotkeyCandidate& candidate : hotkeyCandidates)
            {
                HotkeyInspectItem row{};
                row.objectText = candidate.objectText;
                row.hotkeyId = candidate.hotkeyId;
                row.modifiers = candidate.modifiers;
                row.virtualKey = candidate.virtualKey;
                row.hotkeyText = candidate.hotkeyText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.processName = candidate.processName;
                row.sourceText = candidate.sourceText;
                row.detailText = candidate.detailText;
                row.hasR0MutationSnapshot = candidate.hasR0MutationSnapshot;
                row.r0MutationSnapshot = candidate.r0MutationSnapshot;
                refreshResult.hotkeyRows.push_back(std::move(row));
            }

            const std::vector<KeyboardHookCandidate> hookCandidates =
                collectDriverKeyboardHooks(pidValue, diagnosticText);
            refreshResult.hookRows.reserve(hookCandidates.size());
            for (const KeyboardHookCandidate& candidate : hookCandidates)
            {
                KeyboardHookInspectItem row{};
                row.objectText = candidate.objectText;
                row.typeText = candidate.typeText;
                row.scopeText = candidate.scopeText;
                row.processId = candidate.processId;
                row.threadId = candidate.threadId;
                row.procedureText = candidate.procedureText;
                row.moduleText = candidate.moduleText;
                row.sourceText = candidate.sourceText;
                row.flagsText = candidate.flagsText;
                row.detailText = candidate.detailText;
                refreshResult.hookRows.push_back(std::move(row));
            }

            refreshResult.diagnosticText = diagnosticText;
            refreshResult.elapsedMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - beginTime).count());

            QMetaObject::invokeMethod(
                guardThis,
                [guardThis, ticketValue, refreshResult]()
                {
                    if (guardThis == nullptr || guardThis->m_keyboardRefreshTicket != ticketValue)
                    {
                        return;
                    }
                    guardThis->applyKeyboardRefreshResult(refreshResult);
                },
                Qt::QueuedConnection);
        });

    refreshTask->setAutoDelete(true);
    QThreadPool::globalInstance()->start(refreshTask);
}

void ProcessDetailWindow::applyKeyboardRefreshResult(const KeyboardInspectRefreshResult& refreshResult)
{
    QPointer<ProcessDetailWindow> guardThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
            this,
            QStringLiteral("process-detail-keyboard-snapshot-apply"),
            {m_hotkeyTable, m_keyboardHotkeyTable, m_keyboardHookTable},
            [guardThis, refreshResult]()
            {
                if (guardThis != nullptr)
                {
                    guardThis->applyKeyboardRefreshResult(refreshResult);
                }
            }))
    {
        return;
    }

    m_keyboardRefreshing = false;
    if (m_refreshKeyboardButton != nullptr)
    {
        m_refreshKeyboardButton->setEnabled(true);
    }

    m_keyboardHotkeyRows = refreshResult.hotkeyRows;
    m_keyboardHookRows = refreshResult.hookRows;
    m_hotkeyRows = refreshResult.hotkeyRows;
    rebuildKeyboardHotkeyTable();
    rebuildKeyboardHookTable();
    rebuildHotkeyTable();

    QString statusText = QStringLiteral("● 刷新完成 %1 ms | 热键:%2 | 键盘钩子:%3")
        .arg(refreshResult.elapsedMs)
        .arg(static_cast<qulonglong>(refreshResult.hotkeyRows.size()))
        .arg(static_cast<qulonglong>(refreshResult.hookRows.size()));
    if (!refreshResult.diagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(
            " | 存在诊断；详情已写入日志。");
    }
    updateKeyboardStatusLabel(statusText, false);
    if (m_hotkeyStatusLabel != nullptr)
    {
        updateHotkeyStatusLabel(statusText, false);
    }

    if (m_keyboardRefreshProgressPid > 0)
    {
        kPro.set(m_keyboardRefreshProgressPid, "键盘扫描完成", 100, 1.0f);
    }

    kLogEvent keyboardRefreshDoneEvent;
    info << keyboardRefreshDoneEvent
        << "[ProcessDetailWindow] 键盘扫描完成, pid="
        << m_baseRecord.pid
        << ", hotkeys="
        << refreshResult.hotkeyRows.size()
        << ", hooks="
        << refreshResult.hookRows.size()
        << ", elapsedMs="
        << refreshResult.elapsedMs
        << ", diagnostic="
        << refreshResult.diagnosticText.toStdString()
        << eol;
}

void ProcessDetailWindow::rebuildKeyboardHotkeyTable()
{
    if (m_keyboardHotkeyTable == nullptr)
    {
        return;
    }

    m_keyboardHotkeyTable->setSortingEnabled(false);
    m_keyboardHotkeyTable->setRowCount(0);

    for (const HotkeyInspectItem& rowItem : m_keyboardHotkeyRows)
    {
        const int row = m_keyboardHotkeyTable->rowCount();
        m_keyboardHotkeyTable->insertRow(row);

        const QString idText = rowItem.hotkeyId == 0U
            ? QStringLiteral("0")
            : QStringLiteral("0x%1").arg(rowItem.hotkeyId, 0, 16).toUpper();
        const QString threadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);
        const QString vkModText = QStringLiteral("VK=0x%1 MOD=0x%2")
            .arg(rowItem.virtualKey, 2, 16, QChar('0'))
            .arg(rowItem.modifiers, 2, 16, QChar('0'))
            .toUpper();

        m_keyboardHotkeyTable->setItem(row, 0, createHotkeyCell(rowItem.objectText));
        m_keyboardHotkeyTable->setItem(row, 1, createHotkeyCell(idText));
        m_keyboardHotkeyTable->setItem(row, 2, createHotkeyCell(rowItem.hotkeyText));
        m_keyboardHotkeyTable->setItem(row, 3, createHotkeyCell(QString::number(rowItem.processId)));
        m_keyboardHotkeyTable->setItem(row, 4, createHotkeyCell(threadText));
        m_keyboardHotkeyTable->setItem(row, 5, createHotkeyCell(rowItem.processName));
        m_keyboardHotkeyTable->setItem(row, 6, createHotkeyCell(rowItem.sourceText));
        m_keyboardHotkeyTable->setItem(row, 7, createHotkeyCell(vkModText));
        m_keyboardHotkeyTable->setItem(row, 8, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < m_keyboardHotkeyTable->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = m_keyboardHotkeyTable->item(row, column);
            if (cellItem != nullptr)
            {
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    m_keyboardHotkeyTable->setSortingEnabled(true);
}

void ProcessDetailWindow::rebuildKeyboardHookTable()
{
    if (m_keyboardHookTable == nullptr)
    {
        return;
    }

    m_keyboardHookTable->setSortingEnabled(false);
    m_keyboardHookTable->setRowCount(0);

    for (const KeyboardHookInspectItem& rowItem : m_keyboardHookRows)
    {
        const int row = m_keyboardHookTable->rowCount();
        m_keyboardHookTable->insertRow(row);
        const QString threadText = rowItem.threadId == 0U
            ? QStringLiteral("-")
            : QString::number(rowItem.threadId);

        m_keyboardHookTable->setItem(row, 0, createHotkeyCell(rowItem.objectText));
        m_keyboardHookTable->setItem(row, 1, createHotkeyCell(rowItem.typeText));
        m_keyboardHookTable->setItem(row, 2, createHotkeyCell(rowItem.scopeText));
        m_keyboardHookTable->setItem(row, 3, createHotkeyCell(QString::number(rowItem.processId)));
        m_keyboardHookTable->setItem(row, 4, createHotkeyCell(threadText));
        m_keyboardHookTable->setItem(row, 5, createHotkeyCell(rowItem.procedureText));
        m_keyboardHookTable->setItem(row, 6, createHotkeyCell(rowItem.moduleText));
        m_keyboardHookTable->setItem(row, 7, createHotkeyCell(rowItem.sourceText));
        m_keyboardHookTable->setItem(row, 8, createHotkeyCell(rowItem.flagsText));
        m_keyboardHookTable->setItem(row, 9, createHotkeyCell(rowItem.detailText));

        for (int column = 0; column < m_keyboardHookTable->columnCount(); ++column)
        {
            QTableWidgetItem* cellItem = m_keyboardHookTable->item(row, column);
            if (cellItem != nullptr)
            {
                cellItem->setToolTip(cellItem->text());
            }
        }
    }

    m_keyboardHookTable->setSortingEnabled(true);
}
