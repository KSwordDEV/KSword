#include "WindowDock.h"
#include "../UI/FlatButtonTheme.h"
#include "WindowEventHookTab.h"
#include "WindowGlobalHotkeyTab.h"
#include "WindowGuiHandleTab.h"
#include "WindowTimerTab.h"
#include "../UI/TableInteractionSupport.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../OnlineScan/SandboxUploadActions.h"
#include "../OtherDock/OtherDock.h"
#include "../Internationalization/LanguageManager.h"
#include "../ksword/process/process.h"
#include "../ksword/profile/ProfileJsonLoader.h"
#include "../ksword/log/log.h"
#include "../theme.h"

#include <QAbstractItemView>
#include <QApplication>
#include <QAction>
#include <QBrush>
#include <QClipboard>
#include <QColor>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QFileIconProvider>
#include <QGuiApplication>
#include <QHash>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QIcon>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QLabel>
#include <QList>
#include <QMenu>
#include <QMetaObject>
#include <QMimeData>
#include <QModelIndex>
#include <QMutex>
#include <QMutexLocker>
#include <QPalette>
#include <QPoint>
#include <QPointer>
#include <QPushButton>
#include <QSizePolicy>
#include <QRect>
#include <QScreen>
#include <QShowEvent>
#include <QStringList>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThread>
#include <QVBoxLayout>
#include <QVariant>
#include <QWidget>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <iterator>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#pragma comment(lib, "Version.lib")

namespace
{
    // kColumnPresetSelectedProperty 作用：标识 A/B 列预设按钮的当前选中态。
    // 该内部属性名不是用户可见文本，集中定义可避免误入 i18n 语言包。
    constexpr char kColumnPresetSelectedProperty[] = {
        'k', 's', 'w', 'o', 'r', 'd',
        'C', 'o', 'l', 'u', 'm', 'n',
        'P', 'r', 'e', 's', 'e', 't',
        'S', 'e', 'l', 'e', 'c', 't', 'e', 'd',
        '\0'
    };

    enum HotkeyTableColumn : int
    {
        HotkeyColumnName = 0,
        HotkeyColumnProcessThread,
        HotkeyColumnDisplay,
        HotkeyColumnPath,
        HotkeyColumnDescription,
        HotkeyColumnObject,
        HotkeyColumnId,
        HotkeyColumnVirtualKey,
        HotkeyColumnModifiers,
        HotkeyColumnProcessId,
        HotkeyColumnThreadId,
        HotkeyColumnSession,
        HotkeyColumnHwnd,
        HotkeyColumnNext,
        HotkeyColumnThreadInfo,
        HotkeyColumnDepth,
        HotkeyColumnSource,
        HotkeyColumnStatus,
        HotkeyColumnLastStatus,
        HotkeyColumnDiagnostic,
        HotkeyColumnCount
    };

    struct HotkeyProcessDisplayInfo
    {
        QString processName;
        QString imagePath;
        QString description;
    };

    // boolText 作用：
    // - 把布尔值转换为“是/否”；
    // - 供只读审计页直接展示。
    QString boolText(const bool value)
    {
        return value ? QStringLiteral("是") : QStringLiteral("否");
    }

    // formatHwndText 作用：
    // - 把 HWND 转成可读十六进制文本；
    // - 空句柄统一显示 0x0。
    QString formatHwndText(const HWND windowHandle)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(reinterpret_cast<quintptr>(windowHandle)), 0, 16)
            .toUpper();
    }

    // formatUInt64Hex 作用：
    // - 把 R0 返回的诊断地址、capability mask 和 flags 转成十六进制；
    // - 输入 value：无符号 64 位数值；
    // - 返回：仅用于文本展示，不作为后续操作凭据。
    QString formatUInt64Hex(const std::uint64_t value)
    {
        return QStringLiteral("0x%1")
            .arg(static_cast<qulonglong>(value), 0, 16)
            .toUpper();
    }

    // parseUInt64Text 作用：
    // - 输入 text：表格中的十六进制或十进制文本；
    // - 处理：支持 0x 前缀，遇到 N/A、<empty> 等不可解析文本返回 fallback；
    // - 返回：解析后的 64 位数值，供按需详情查询使用。
    std::uint64_t parseUInt64Text(const QString& text, const std::uint64_t fallback)
    {
        QString trimmedText = text.trimmed();
        if (trimmedText.isEmpty() ||
            trimmedText == QStringLiteral("N/A") ||
            trimmedText.startsWith(QChar('<')))
        {
            return fallback;
        }

        int base = 10;
        if (trimmedText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            trimmedText = trimmedText.mid(2);
            base = 16;
        }

        bool ok = false;
        const qulonglong parsedValue = trimmedText.toULongLong(&ok, base);
        return ok ? static_cast<std::uint64_t>(parsedValue) : fallback;
    }

    // parseUInt32Text 作用：
    // - 输入 text：表格中的 PID/TID 文本；
    // - 处理：复用 parseUInt64Text 并裁剪到 32 位；
    // - 返回：解析失败返回 fallback。
    std::uint32_t parseUInt32Text(const QString& text, const std::uint32_t fallback)
    {
        const std::uint64_t parsedValue = parseUInt64Text(text, fallback);
        return parsedValue <= 0xFFFFFFFFULL ? static_cast<std::uint32_t>(parsedValue) : fallback;
    }

    // formatNtStatusText 作用：
    // - 把驱动返回的 NTSTATUS/Win32 状态统一显示为十六进制；
    // - 输入 statusValue：R0/R3 返回的 32 位状态值；
    // - 返回：带常见含义的短文本，避免表格只显示难读的十进制负数。
    QString formatNtStatusText(const long statusValue)
    {
        const std::uint32_t unsignedStatus =
            static_cast<std::uint32_t>(statusValue);
        QString nameText;
        switch (unsignedStatus)
        {
        case 0x00000000UL:
            nameText = QStringLiteral("STATUS_SUCCESS");
            break;
        case 0xC00000BBUL:
            nameText = QStringLiteral("STATUS_NOT_SUPPORTED");
            break;
        case 0xC0000010UL:
            nameText = QStringLiteral("STATUS_INVALID_DEVICE_REQUEST");
            break;
        case 0xC000000DUL:
            nameText = QStringLiteral("STATUS_INVALID_PARAMETER");
            break;
        case 0xC0000023UL:
            nameText = QStringLiteral("STATUS_BUFFER_TOO_SMALL");
            break;
        case 0xC0000001UL:
            nameText = QStringLiteral("STATUS_UNSUCCESSFUL");
            break;
        default:
            nameText = QStringLiteral("NTSTATUS");
            break;
        }

        return QStringLiteral("0x%1 (%2)")
            .arg(static_cast<qulonglong>(unsignedStatus), 8, 16, QChar('0'))
            .arg(nameText)
            .toUpper();
    }

    // hotkeyModifierText 作用：
    // - 把 RegisterHotKey 风格的 modifiers 位转换成 Alt/Ctrl/Shift/Win；
    // - 输入 modifiers：R0 热键行中的修饰键位图；
    // - 返回：人可读修饰键组合，并保留原始十六进制方便复制审计。
    QString hotkeyModifierText(const std::uint32_t modifiers)
    {
        QStringList parts;
        if ((modifiers & MOD_ALT) != 0U)
        {
            parts.push_back(QStringLiteral("Alt"));
        }
        if ((modifiers & MOD_CONTROL) != 0U)
        {
            parts.push_back(QStringLiteral("Ctrl"));
        }
        if ((modifiers & MOD_SHIFT) != 0U)
        {
            parts.push_back(QStringLiteral("Shift"));
        }
        if ((modifiers & MOD_WIN) != 0U)
        {
            parts.push_back(QStringLiteral("Win"));
        }
        constexpr std::uint32_t kModNoRepeat = 0x4000U;
        if ((modifiers & kModNoRepeat) != 0U)
        {
            parts.push_back(QStringLiteral("NoRepeat"));
        }
        if (parts.isEmpty())
        {
            parts.push_back(QStringLiteral("<无修饰键>"));
        }
        return QStringLiteral("%1 (%2)")
            .arg(parts.join('+'))
            .arg(formatUInt64Hex(modifiers));
    }

    // virtualKeyName 作用：
    // - 把 RegisterHotKey 的 VK 数值按 WinUser.h 固定值解析成人可读键名；
    // - 字母、数字和 F1-F24 按区间处理，其余常用 VK 使用显式映射；
    // - 未知值保留 VK_0xNN，避免把无法识别的键误标成别的按键。
    QString virtualKeyName(const std::uint32_t virtualKey)
    {
        if (virtualKey >= '0' && virtualKey <= '9')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= 'A' && virtualKey <= 'Z')
        {
            return QString(QChar(static_cast<ushort>(virtualKey)));
        }
        if (virtualKey >= VK_NUMPAD0 && virtualKey <= VK_NUMPAD9)
        {
            return QStringLiteral("Num%1").arg(virtualKey - VK_NUMPAD0);
        }
        if (virtualKey >= VK_F1 && virtualKey <= VK_F24)
        {
            return QStringLiteral("F%1").arg(virtualKey - VK_F1 + 1U);
        }

        switch (virtualKey)
        {
        case VK_LBUTTON: return QStringLiteral("MouseLeft");
        case VK_RBUTTON: return QStringLiteral("MouseRight");
        case VK_CANCEL: return QStringLiteral("Break");
        case VK_MBUTTON: return QStringLiteral("MouseMiddle");
        case VK_XBUTTON1: return QStringLiteral("MouseX1");
        case VK_XBUTTON2: return QStringLiteral("MouseX2");
        case VK_BACK: return QStringLiteral("Backspace");
        case VK_TAB: return QStringLiteral("Tab");
        case VK_CLEAR: return QStringLiteral("Clear");
        case VK_RETURN: return QStringLiteral("Enter");
        case VK_SHIFT: return QStringLiteral("Shift");
        case VK_CONTROL: return QStringLiteral("Ctrl");
        case VK_MENU: return QStringLiteral("Alt");
        case VK_PAUSE: return QStringLiteral("Pause");
        case VK_CAPITAL: return QStringLiteral("CapsLock");
        case VK_KANA: return QStringLiteral("Kana/Hangul");
        case VK_IME_ON: return QStringLiteral("ImeOn");
        case VK_JUNJA: return QStringLiteral("Junja");
        case VK_FINAL: return QStringLiteral("Final");
        case VK_HANJA: return QStringLiteral("Hanja/Kanji");
        case VK_IME_OFF: return QStringLiteral("ImeOff");
        case VK_ESCAPE: return QStringLiteral("Esc");
        case VK_CONVERT: return QStringLiteral("Convert");
        case VK_NONCONVERT: return QStringLiteral("NonConvert");
        case VK_ACCEPT: return QStringLiteral("Accept");
        case VK_MODECHANGE: return QStringLiteral("ModeChange");
        case VK_SPACE: return QStringLiteral("Space");
        case VK_PRIOR: return QStringLiteral("PageUp");
        case VK_NEXT: return QStringLiteral("PageDown");
        case VK_END: return QStringLiteral("End");
        case VK_HOME: return QStringLiteral("Home");
        case VK_LEFT: return QStringLiteral("Left");
        case VK_UP: return QStringLiteral("Up");
        case VK_RIGHT: return QStringLiteral("Right");
        case VK_DOWN: return QStringLiteral("Down");
        case VK_SELECT: return QStringLiteral("Select");
        case VK_PRINT: return QStringLiteral("Print");
        case VK_EXECUTE: return QStringLiteral("Execute");
        case VK_SNAPSHOT: return QStringLiteral("Snapshot");
        case VK_INSERT: return QStringLiteral("Insert");
        case VK_DELETE: return QStringLiteral("Delete");
        case VK_HELP: return QStringLiteral("Help");
        case VK_LWIN: return QStringLiteral("LeftWin");
        case VK_RWIN: return QStringLiteral("RightWin");
        case VK_APPS: return QStringLiteral("Apps");
        case VK_SLEEP: return QStringLiteral("Sleep");
        case VK_MULTIPLY: return QStringLiteral("NumMultiply");
        case VK_ADD: return QStringLiteral("NumAdd");
        case VK_SEPARATOR: return QStringLiteral("NumSeparator");
        case VK_SUBTRACT: return QStringLiteral("NumSubtract");
        case VK_DECIMAL: return QStringLiteral("NumDecimal");
        case VK_DIVIDE: return QStringLiteral("NumDivide");
        case VK_NUMLOCK: return QStringLiteral("NumLock");
        case VK_SCROLL: return QStringLiteral("ScrollLock");
        case VK_LSHIFT: return QStringLiteral("LeftShift");
        case VK_RSHIFT: return QStringLiteral("RightShift");
        case VK_LCONTROL: return QStringLiteral("LeftCtrl");
        case VK_RCONTROL: return QStringLiteral("RightCtrl");
        case VK_LMENU: return QStringLiteral("LeftAlt");
        case VK_RMENU: return QStringLiteral("RightAlt");
        case VK_BROWSER_BACK: return QStringLiteral("BrowserBack");
        case VK_BROWSER_FORWARD: return QStringLiteral("BrowserForward");
        case VK_BROWSER_REFRESH: return QStringLiteral("BrowserRefresh");
        case VK_BROWSER_STOP: return QStringLiteral("BrowserStop");
        case VK_BROWSER_SEARCH: return QStringLiteral("BrowserSearch");
        case VK_BROWSER_FAVORITES: return QStringLiteral("BrowserFavorites");
        case VK_BROWSER_HOME: return QStringLiteral("BrowserHome");
        case VK_VOLUME_MUTE: return QStringLiteral("VolumeMute");
        case VK_VOLUME_DOWN: return QStringLiteral("VolumeDown");
        case VK_VOLUME_UP: return QStringLiteral("VolumeUp");
        case VK_MEDIA_NEXT_TRACK: return QStringLiteral("MediaNext");
        case VK_MEDIA_PREV_TRACK: return QStringLiteral("MediaPrevious");
        case VK_MEDIA_STOP: return QStringLiteral("MediaStop");
        case VK_MEDIA_PLAY_PAUSE: return QStringLiteral("MediaPlayPause");
        case VK_LAUNCH_MAIL: return QStringLiteral("LaunchMail");
        case VK_LAUNCH_MEDIA_SELECT: return QStringLiteral("LaunchMedia");
        case VK_LAUNCH_APP1: return QStringLiteral("LaunchApp1");
        case VK_LAUNCH_APP2: return QStringLiteral("LaunchApp2");
        case VK_OEM_1: return QStringLiteral(";");
        case VK_OEM_PLUS: return QStringLiteral("+");
        case VK_OEM_COMMA: return QStringLiteral(",");
        case VK_OEM_MINUS: return QStringLiteral("-");
        case VK_OEM_PERIOD: return QStringLiteral(".");
        case VK_OEM_2: return QStringLiteral("/");
        case VK_OEM_3: return QStringLiteral("`");
        case VK_OEM_4: return QStringLiteral("[");
        case VK_OEM_5: return QStringLiteral("\\");
        case VK_OEM_6: return QStringLiteral("]");
        case VK_OEM_7: return QStringLiteral("'");
        case VK_OEM_8: return QStringLiteral("OEM8");
        case VK_OEM_102: return QStringLiteral("OEM102");
        case VK_PROCESSKEY: return QStringLiteral("ProcessKey");
        case VK_PACKET: return QStringLiteral("Packet");
        case VK_ATTN: return QStringLiteral("Attn");
        case VK_CRSEL: return QStringLiteral("CrSel");
        case VK_EXSEL: return QStringLiteral("ExSel");
        case VK_EREOF: return QStringLiteral("EraseEof");
        case VK_PLAY: return QStringLiteral("Play");
        case VK_ZOOM: return QStringLiteral("Zoom");
        case VK_NONAME: return QStringLiteral("NoName");
        case VK_PA1: return QStringLiteral("Pa1");
        case VK_OEM_CLEAR: return QStringLiteral("OemClear");
        default:
            return QStringLiteral("VK_0x%1")
                .arg(virtualKey, 2, 16, QChar('0'))
                .toUpper();
        }
    }

    // hotkeyDisplayText 作用：组合修饰键与硬编码 VK 名称，生成 OpenARK 风格的人读热键。
    QString hotkeyDisplayText(const std::uint32_t modifiers, const std::uint32_t virtualKey)
    {
        QStringList parts;
        if ((modifiers & MOD_WIN) != 0U) parts.push_back(QStringLiteral("Win"));
        if ((modifiers & MOD_CONTROL) != 0U) parts.push_back(QStringLiteral("Ctrl"));
        if ((modifiers & MOD_ALT) != 0U) parts.push_back(QStringLiteral("Alt"));
        if ((modifiers & MOD_SHIFT) != 0U) parts.push_back(QStringLiteral("Shift"));
        parts.push_back(virtualKeyName(virtualKey));
        return parts.join(QChar('+'));
    }

    QString rawVirtualKeyText(const std::uint32_t virtualKey)
    {
        const QString hexText = QStringLiteral("0x%1")
            .arg(virtualKey, 2, 16, QChar('0'))
            .toUpper();
        return QStringLiteral("%1 (%2)").arg(hexText, virtualKeyName(virtualKey));
    }

    // queryFileDescription 作用：从进程映像版本资源读取 FileDescription，失败时返回空文本。
    QString queryFileDescription(const QString& imagePath)
    {
        if (imagePath.trimmed().isEmpty())
        {
            return QString();
        }

        DWORD ignoredHandle = 0;
        const DWORD versionBytes = ::GetFileVersionInfoSizeW(
            reinterpret_cast<LPCWSTR>(imagePath.utf16()),
            &ignoredHandle);
        if (versionBytes == 0U)
        {
            return QString();
        }

        std::vector<std::uint8_t> versionBuffer(versionBytes, 0U);
        if (::GetFileVersionInfoW(
            reinterpret_cast<LPCWSTR>(imagePath.utf16()),
            0,
            versionBytes,
            versionBuffer.data()) == FALSE)
        {
            return QString();
        }

        struct LanguageCodePage
        {
            WORD language;
            WORD codePage;
        };
        LanguageCodePage* translations = nullptr;
        UINT translationBytes = 0;
        if (::VerQueryValueW(
            versionBuffer.data(),
            L"\\VarFileInfo\\Translation",
            reinterpret_cast<LPVOID*>(&translations),
            &translationBytes) != FALSE &&
            translations != nullptr)
        {
            const UINT translationCount = translationBytes / sizeof(LanguageCodePage);
            for (UINT index = 0; index < translationCount; ++index)
            {
                const QString queryPath = QStringLiteral("\\StringFileInfo\\%1%2\\FileDescription")
                    .arg(translations[index].language, 4, 16, QChar('0'))
                    .arg(translations[index].codePage, 4, 16, QChar('0'));
                wchar_t* description = nullptr;
                UINT descriptionChars = 0;
                if (::VerQueryValueW(
                    versionBuffer.data(),
                    reinterpret_cast<LPCWSTR>(queryPath.utf16()),
                    reinterpret_cast<LPVOID*>(&description),
                    &descriptionChars) != FALSE &&
                    description != nullptr &&
                    descriptionChars > 1U)
                {
                    return QString::fromWCharArray(description).trimmed();
                }
            }
        }

        constexpr const wchar_t* fallbackQueries[] = {
            L"\\StringFileInfo\\040904B0\\FileDescription",
            L"\\StringFileInfo\\000004B0\\FileDescription"
        };
        for (const wchar_t* queryPath : fallbackQueries)
        {
            wchar_t* description = nullptr;
            UINT descriptionChars = 0;
            if (::VerQueryValueW(
                versionBuffer.data(),
                queryPath,
                reinterpret_cast<LPVOID*>(&description),
                &descriptionChars) != FALSE &&
                description != nullptr &&
                descriptionChars > 1U)
            {
                return QString::fromWCharArray(description).trimmed();
            }
        }
        return QString();
    }

    HotkeyProcessDisplayInfo queryHotkeyProcessDisplayInfo(const std::uint32_t processId)
    {
        HotkeyProcessDisplayInfo displayInfo;
        if (processId == 0U)
        {
            return displayInfo;
        }

        displayInfo.imagePath = QString::fromStdString(ks::process::QueryProcessPathByPid(processId));
        if (!displayInfo.imagePath.isEmpty())
        {
            displayInfo.processName = QFileInfo(displayInfo.imagePath).fileName();
            displayInfo.description = queryFileDescription(displayInfo.imagePath);
        }
        if (displayInfo.processName.isEmpty())
        {
            displayInfo.processName = QString::fromStdString(ks::process::GetProcessNameByPID(processId));
        }
        return displayInfo;
    }

    QString processThreadDisplayText(const std::uint32_t processId, const std::uint32_t threadId)
    {
        return QStringLiteral("%1.%2")
            .arg(processId)
            .arg(threadId == 0U ? QStringLiteral("-") : QString::number(threadId));
    }

    // keyboardSourceText 作用：
    // - 把旧 keyboard fallback 与 win32k PDB 行中的 source 转成来源名；
    // - 输入 source：KSWORD_ARK_KEYBOARD_SOURCE_* 或兼容值；
    // - 返回：来源说明，未知值保留数字。
    QString keyboardSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_HOTKEY_TABLE:
            return QStringLiteral("win32k HotkeyTable");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_THREAD_HOOK_CHAIN:
            return QStringLiteral("win32k ThreadHookChain");
        case KSWORD_ARK_KEYBOARD_SOURCE_WIN32K_GLOBAL_HOOK_CHAIN:
            return QStringLiteral("win32k GlobalHookChain");
        default:
            return QStringLiteral("Source(%1)").arg(source);
        }
    }

    // hookScopeText 作用：
    // - 把 Hook scope 数值转换成线程/全局等可读分类；
    // - 输入 scope：KSWORD_ARK_KEYBOARD_HOOK_SCOPE_*；
    // - 返回：表格“范围”列文本。
    QString hookScopeText(const std::uint32_t scope)
    {
        switch (scope)
        {
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_THREAD:
            return QStringLiteral("Thread");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_GLOBAL:
            return QStringLiteral("Global");
        case KSWORD_ARK_KEYBOARD_HOOK_SCOPE_UNKNOWN:
            return QStringLiteral("Unknown");
        default:
            return QStringLiteral("Scope(%1)").arg(scope);
        }
    }

    // hookTypeText 作用：
    // - 把 Win32 Hook 类型值转换成 WH_* 名称；
    // - 输入 hookType：R0 Hook 行中的类型；
    // - 返回：表格“类型”列文本，未知类型保留原始数字。
    QString hookTypeText(const std::uint32_t hookType)
    {
        switch (hookType)
        {
        case 0xFFFFFFFFUL:
            return QStringLiteral("WH_MSGFILTER(-1)");
        case 0UL:
            return QStringLiteral("WH_JOURNALRECORD");
        case 1UL:
            return QStringLiteral("WH_JOURNALPLAYBACK");
        case 2UL:
            return QStringLiteral("WH_KEYBOARD");
        case 3UL:
            return QStringLiteral("WH_GETMESSAGE");
        case 4UL:
            return QStringLiteral("WH_CALLWNDPROC");
        case 5UL:
            return QStringLiteral("WH_CBT");
        case 6UL:
            return QStringLiteral("WH_SYSMSGFILTER");
        case 7UL:
            return QStringLiteral("WH_MOUSE");
        case 8UL:
            return QStringLiteral("WH_HARDWARE");
        case 9UL:
            return QStringLiteral("WH_DEBUG");
        case 10UL:
            return QStringLiteral("WH_SHELL");
        case 11UL:
            return QStringLiteral("WH_FOREGROUNDIDLE");
        case 12UL:
            return QStringLiteral("WH_CALLWNDPROCRET");
        case 13UL:
            return QStringLiteral("WH_KEYBOARD_LL");
        case 14UL:
            return QStringLiteral("WH_MOUSE_LL");
        default:
            return QStringLiteral("WH_TYPE(%1)").arg(hookType);
        }
    }

    QString messageHookFlagsText(const std::uint32_t flags)
    {
        QStringList names;
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL) != 0U)
        {
            names << QStringLiteral("GLOBAL");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI) != 0U)
        {
            names << QStringLiteral("ANSI");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP) != 0U)
        {
            names << QStringLiteral("NEED_SKIP");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG) != 0U)
        {
            names << QStringLiteral("HUNG");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED) != 0U)
        {
            names << QStringLiteral("FAULTED");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY) != 0U)
        {
            names << QStringLiteral("NO_DELAY");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL) != 0U)
        {
            names << QStringLiteral("WOW64_DLL");
        }
        if ((flags & KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED) != 0U)
        {
            names << QStringLiteral("DESTROYED");
        }
        const std::uint32_t knownMask =
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_GLOBAL |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_ANSI |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NEED_SKIP |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_HUNG |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_FAULTED |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_NO_DELAY |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_WOW64_DLL |
            KSWORD_ARK_WIN32K_MESSAGE_HOOK_FLAG_DESTROYED;
        if ((flags & ~knownMask) != 0U)
        {
            names << formatUInt64Hex(flags & ~knownMask);
        }
        if (names.isEmpty())
        {
            names << QStringLiteral("0");
        }
        return QStringLiteral("%1 (%2)")
            .arg(names.join(QStringLiteral(" | ")))
            .arg(formatUInt64Hex(flags));
    }

    QString messageHookLayoutSourceText(const std::uint32_t source)
    {
        switch (source)
        {
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_VALIDATED_DISASSEMBLY:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.exact"),
                QStringLiteral("精确 PE 身份"));
        case KSWORD_ARK_WIN32K_MESSAGE_HOOK_LAYOUT_SOURCE_NEAREST_PREVIOUS:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.previous"),
                QStringLiteral("最近旧版回退"));
        default:
            return ks::i18n::contextText(
                QStringLiteral("window.message_hook.layout.unknown"),
                QStringLiteral("未知"));
        }
    }

    QString win32kAtomName(const std::uint32_t atomValue)
    {
        if (atomValue == 0U || atomValue > 0xFFFFU)
        {
            return {};
        }
        wchar_t buffer[512]{};
        const UINT chars = ::GlobalGetAtomNameW(
            static_cast<ATOM>(atomValue),
            buffer,
            static_cast<int>(std::size(buffer)));
        return chars == 0U
            ? QString()
            : QString::fromWCharArray(buffer, static_cast<qsizetype>(chars));
    }

    // deviceAuditStatusText 作用：
    // - 把设备/GPU/Watchdog 审计状态转换成文字；
    // - 输入 status：KSWORD_ARK_DEVICE_AUDIT_STATUS_*；
    // - 返回：表格状态列文本。
    QString deviceAuditStatusText(const std::uint32_t status)
    {
        switch (status)
        {
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNAVAILABLE:
            return QStringLiteral("Unavailable");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_PARTIAL:
            return QStringLiteral("Partial");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_NOT_FOUND:
            return QStringLiteral("NotFound");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("Truncated");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_QUERY_FAILED:
            return QStringLiteral("QueryFailed");
        case KSWORD_ARK_DEVICE_AUDIT_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        default:
            return QStringLiteral("Status(%1)").arg(status);
        }
    }

    // deviceAuditRowKindText 作用：
    // - 把设备审计 rowKind 转成 summary/device 文本；
    // - 输入 rowKind：R0 返回的行类型；
    // - 返回：表格“种类”列文本。
    QString deviceAuditRowKindText(const std::uint32_t rowKind)
    {
        switch (rowKind)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DRIVER_SUMMARY:
            return QStringLiteral("DriverSummary");
        case KSWORD_ARK_DEVICE_AUDIT_ROW_KIND_DEVICE_ROW:
            return QStringLiteral("DeviceRow");
        default:
            return QStringLiteral("RowKind(%1)").arg(rowKind);
        }
    }

    // deviceAuditRoleText 作用：
    // - 把设备栈角色转换成 PDO/FDO/filter/display/watchdog 等文本；
    // - 输入 role：KSWORD_ARK_DEVICE_AUDIT_ROLE_*；
    // - 返回：表格“角色”列文本。
    QString deviceAuditRoleText(const std::uint32_t role)
    {
        switch (role)
        {
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_PDO:
            return QStringLiteral("PDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_FDO:
            return QStringLiteral("FDO");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UPPER_FILTER:
            return QStringLiteral("UpperFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_LOWER_FILTER:
            return QStringLiteral("LowerFilter");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CLASS_DRIVER:
            return QStringLiteral("ClassDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_BUS_DRIVER:
            return QStringLiteral("BusDriver");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_COMPOSITE:
            return QStringLiteral("Composite");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_INTERFACE:
            return QStringLiteral("Interface");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_CONTROLLER:
            return QStringLiteral("Controller");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_DISPLAY:
            return QStringLiteral("Display");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_WATCHDOG:
            return QStringLiteral("Watchdog");
        case KSWORD_ARK_DEVICE_AUDIT_ROLE_UNKNOWN:
            return QStringLiteral("Unknown");
        default:
            return QStringLiteral("Role(%1)").arg(role);
        }
    }

    // stdWideToQString 作用：
    // - 把 ArkDriverClient 的 std::wstring 明细字段转换为 QString；
    // - 输入 value：R3 client 保存的宽字符串；
    // - 返回：空值统一显示 <empty>，避免表格单元格完全空白。
    QString stdWideToQString(const std::wstring& value)
    {
        if (value.empty())
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromStdWString(value);
    }

    // win32kJsonString 作用：
    // - 输入 object/name/fallback；
    // - 处理：从 win32k public deep JSON 对象中读取字符串字段；
    // - 返回：字段存在时返回原值，否则返回 fallback。
    QString win32kJsonString(
        const QJsonObject& object,
        const QString& name,
        const QString& fallback)
    {
        const QJsonValue value = object.value(name);
        return value.isString() ? value.toString() : fallback;
    }

    // win32kJsonInt 作用：
    // - 输入 object/name/fallback；
    // - 处理：读取 JSON number，避免 UI 里只显示空白；
    // - 返回：整数值，失败时返回 fallback。
    int win32kJsonInt(
        const QJsonObject& object,
        const QString& name,
        const int fallback)
    {
        const QJsonValue value = object.value(name);
        return value.isDouble() ? value.toInt(fallback) : fallback;
    }

    // findWin32kPublicDeepJsonPath 作用：
    // - 输入无；
    // - 处理：按 Release 布局和开发工作目录布局查找 win32k public deep JSON；
    // - 返回：文件路径，找不到时返回空字符串。
    QString findWin32kPublicDeepJsonPath()
    {
        QStringList candidateDirectories;
        const QString applicationDirectory = QCoreApplication::applicationDirPath();
        const QString currentDirectory = QDir::currentPath();
        candidateDirectories.push_back(
            QDir(applicationDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(applicationDirectory).filePath(QStringLiteral("../profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(currentDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
        candidateDirectories.push_back(
            QDir(currentDirectory).filePath(QStringLiteral("Ksword5.1/Ksword5.1/profiles/pdb_deep_offsets")));

        for (const QString& directoryText : candidateDirectories)
        {
            QDir directory(directoryText);
            if (!directory.exists())
            {
                continue;
            }

            QStringList fileNames = directory.entryList(
                QStringList{ QStringLiteral("win32k_gui_public_*_deep_offsets.json.qz") },
                QDir::Files,
                QDir::Name);
            if (fileNames.isEmpty())
            {
                fileNames = directory.entryList(
                    QStringList{ QStringLiteral("win32k_gui_public_*_deep_offsets.json") },
                    QDir::Files,
                    QDir::Name);
            }
            if (!fileNames.isEmpty())
            {
                return directory.absoluteFilePath(fileNames.first());
            }
        }
        return QString();
    }

    // appendWin32kPublicSymbolExamples 作用：
    // - 输入输出 lines：详情文本行；moduleObject：一个 win32k-family PDB 模块；
    // - 处理：按符号组提取少量 public symbol 示例，避免详情页只剩统计摘要；
    // - 返回：无，直接追加人读文本。
    void appendWin32kPublicSymbolExamples(
        ks::ui::FieldDocument& lines,
        const QJsonObject& moduleObject,
        const QString& groupName,
        const int maxExamples)
    {
        const QJsonArray symbolArray = moduleObject.value(QStringLiteral("publicSymbols")).toArray();
        QStringList examples;
        for (const QJsonValue& symbolValue : symbolArray)
        {
            const QJsonObject symbolObject = symbolValue.toObject();
            if (win32kJsonString(symbolObject, QStringLiteral("group"), QString()) != groupName)
            {
                continue;
            }

            examples.push_back(QStringLiteral("%1 @ %2")
                .arg(win32kJsonString(symbolObject, QStringLiteral("name"), QStringLiteral("<unnamed>")))
                .arg(win32kJsonString(symbolObject, QStringLiteral("sectionOffset"), QStringLiteral("<no section>"))));
            if (examples.size() >= maxExamples)
            {
                break;
            }
        }

        if (!examples.isEmpty())
        {
            lines.field(QStringLiteral("publicSymbols[%1]").arg(groupName),
                examples.join(QStringLiteral(" | ")));
        }
    }

    // appendWin32kRuntimeDomainExamples 作用：
    // - 输入 lines：输出文本行，domainObject：runtimeDetailCatalog.domains 下的单个域；
    // - 处理：从 publicSymbolExamples 中按 group 取少量代表符号；
    // - 返回：无，直接追加到详情文本，避免窗口详情只停留在 readiness 摘要。
    void appendWin32kRuntimeDomainExamples(
        ks::ui::FieldDocument& lines,
        const QJsonObject& domainObject,
        const QString& groupName,
        const int maxExamples)
    {
        const QJsonObject examplesObject =
            domainObject.value(QStringLiteral("publicSymbolExamples")).toObject();
        const QJsonArray exampleArray = examplesObject.value(groupName).toArray();
        QStringList examples;
        for (const QJsonValue& exampleValue : exampleArray)
        {
            const QJsonObject exampleObject = exampleValue.toObject();
            const QString moduleName =
                win32kJsonString(exampleObject, QStringLiteral("moduleName"), QStringLiteral("<module>"));
            const QString symbolName =
                win32kJsonString(exampleObject, QStringLiteral("name"), QStringLiteral("<symbol>"));
            const QString sectionOffset =
                win32kJsonString(exampleObject, QStringLiteral("sectionOffset"), QStringLiteral("<section>"));
            examples.push_back(QStringLiteral("%1!%2 @ %3")
                .arg(moduleName)
                .arg(symbolName)
                .arg(sectionOffset));
            if (examples.size() >= maxExamples)
            {
                break;
            }
        }

        if (!examples.isEmpty())
        {
            lines.field(QStringLiteral("examples[%1]").arg(groupName),
                examples.join(QStringLiteral(" | ")));
        }
    }

    // appendWin32kRuntimeCatalogPreview 作用：
    // - 输入 lines：输出文本行，rootObject：win32k public deep JSON 根对象；
    // - 处理：展示 window/gui-thread/hotkey/hook/desktop 五个 runtime 域的结构化 readiness；
    // - 返回：无。该函数只读 JSON，不触发驱动调用。
    void appendWin32kRuntimeCatalogPreview(
        ks::ui::FieldDocument& lines,
        const QJsonObject& rootObject)
    {
        const QJsonObject catalogObject =
            rootObject.value(QStringLiteral("runtimeDetailCatalog")).toObject();
        if (catalogObject.isEmpty())
        {
            lines.field(QStringLiteral("RuntimeDetailCatalog"), QStringLiteral("<缺失，旧版 win32k public deep JSON>"));
            return;
        }

        lines.section(QStringLiteral("Win32K Runtime Detail Catalog"));
        lines.field(QStringLiteral("ReadyDomains/BlockedDomains"), QStringLiteral("%1 / %2")
            .arg(win32kJsonInt(catalogObject, QStringLiteral("readyDomainCount"), 0))
            .arg(win32kJsonInt(catalogObject, QStringLiteral("blockedDomainCount"), 0)));
        lines.field(QStringLiteral("CatalogReady"), QStringLiteral("%1")
            .arg(catalogObject.value(QStringLiteral("ready")).toBool(false)
                ? QStringLiteral("是")
                : QStringLiteral("否")));

        const QJsonObject domainsObject =
            catalogObject.value(QStringLiteral("domains")).toObject();
        for (auto iterator = domainsObject.constBegin(); iterator != domainsObject.constEnd(); ++iterator)
        {
            const QString domainId = iterator.key();
            const QJsonObject domainObject = iterator.value().toObject();
            const QString displayName =
                win32kJsonString(domainObject, QStringLiteral("displayName"), domainId);
            QStringList missingTypes;
            for (const QJsonValue& missingValue : domainObject.value(QStringLiteral("missingPrivateTypes")).toArray())
            {
                if (missingValue.isString())
                {
                    missingTypes.push_back(missingValue.toString());
                }
            }

            QStringList groupParts;
            const QJsonObject groupCounts =
                domainObject.value(QStringLiteral("publicSymbolGroups")).toObject();
            for (auto groupIterator = groupCounts.constBegin(); groupIterator != groupCounts.constEnd(); ++groupIterator)
            {
                groupParts.push_back(QStringLiteral("%1=%2")
                    .arg(groupIterator.key())
                    .arg(groupIterator.value().toInt(0)));
            }

            lines.note(QStringLiteral("  Domain[%1] %2").arg(domainId, displayName));
            lines.note(QStringLiteral("    ready=%1; concreteFields=%2; publicEvidence=%3")
                .arg(domainObject.value(QStringLiteral("ready")).toBool(false)
                    ? QStringLiteral("是")
                    : QStringLiteral("否"))
                .arg(win32kJsonInt(domainObject, QStringLiteral("concreteFieldCount"), 0))
                .arg(domainObject.value(QStringLiteral("publicEvidenceAvailable")).toBool(false)
                    ? QStringLiteral("是")
                    : QStringLiteral("否")));
            lines.field(QStringLiteral("missingPrivateTypes"), QStringLiteral("%1")
                .arg(missingTypes.isEmpty()
                    ? QStringLiteral("<none>")
                    : missingTypes.join(QStringLiteral(", "))));
            lines.field(QStringLiteral("publicSymbolGroups"), QStringLiteral("%1")
                .arg(groupParts.isEmpty()
                    ? QStringLiteral("<none>")
                    : groupParts.join(QStringLiteral("; "))));
            lines.field(QStringLiteral("intendedUse"), QStringLiteral("%1")
                .arg(win32kJsonString(domainObject, QStringLiteral("intendedUse"), QStringLiteral("<none>"))));
            const QString blockedBy =
                win32kJsonString(domainObject, QStringLiteral("blockedBy"), QString());
            if (!blockedBy.isEmpty())
            {
                lines.field(QStringLiteral("blockedBy"), QStringLiteral("%1").arg(blockedBy));
            }

            for (auto groupIterator = groupCounts.constBegin(); groupIterator != groupCounts.constEnd(); ++groupIterator)
            {
                appendWin32kRuntimeDomainExamples(lines, domainObject, groupIterator.key(), 2);
            }
        }
    }

    // win32kPublicPdbCatalogPreview 作用：
    // - 读取随程序发布的 win32k public PDB deep JSON；
    // - 展示 public symbol/公开类型统计、私有 GUI layout 缺口和代表符号；
    // - 返回：适合单 HWND 详情区展示的多行文本，不触发 R0 调用。
    ks::ui::FieldDocument win32kPublicPdbCatalogPreview()
    {
        static QMutex cacheMutex;
        static ks::ui::FieldDocument cachedText;
        {
            QMutexLocker locker(&cacheMutex);
            if (!cachedText.isEmpty())
            {
                return cachedText;
            }
        }

        const auto storeAndReturn = [](const ks::ui::FieldDocument& text) -> ks::ui::FieldDocument
        {
            QMutexLocker locker(&cacheMutex);
            cachedText = text;
            return cachedText;
        };

        const QString jsonPath = findWin32kPublicDeepJsonPath();
        if (jsonPath.isEmpty())
        {
            return storeAndReturn(ks::ui::FieldDocument{}.note(QStringLiteral(
                "[Win32K Public PDB Catalog]\n"
                "未找到 profiles/pdb_deep_offsets/win32k_gui_public_*_deep_offsets.json；"
                "窗口详情只能显示 R0 readiness，无法展示 public symbol 事实库。")));
        }

        QJsonParseError parseError{};
        QString readErrorText;
        const QJsonDocument document = ks::profile::readProfileJsonDocument(jsonPath, &parseError, &readErrorText);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            return storeAndReturn(ks::ui::FieldDocument{}.note(QStringLiteral(
                "[Win32K Public PDB Catalog]\n"
                "win32k public deep JSON 解析失败：%1；文件=%2")
                .arg(readErrorText.isEmpty() ? parseError.errorString() : readErrorText)
                .arg(jsonPath)));
        }

        const QJsonObject rootObject = document.object();
        const QJsonObject statsObject = rootObject.value(QStringLiteral("stats")).toObject();
        ks::ui::FieldDocument lines;
        lines.section(QStringLiteral("Win32K Public PDB Catalog"));
        lines.field(QStringLiteral("Source"), QStringLiteral("%1").arg(jsonPath));
        lines.field(QStringLiteral("Modules/PublicSymbols/PublicFields"), QStringLiteral("%1 / %2 / %3")
            .arg(win32kJsonInt(statsObject, QStringLiteral("moduleCount"), 0))
            .arg(win32kJsonInt(statsObject, QStringLiteral("publicSymbolCount"), 0))
            .arg(win32kJsonInt(statsObject, QStringLiteral("fieldCount"), 0)));
        lines.field(QStringLiteral("PrivateGuiLayoutReady"), QStringLiteral("%1")
            .arg(statsObject.value(QStringLiteral("privateTypeReady")).toBool(false) ? QStringLiteral("是") : QStringLiteral("否")));

        // runtimeDetailCatalog 是生成器新写入的结构化能力目录：
        // - 它把窗口、GUI 线程、热键、Hook、Desktop/Session 拆成独立域；
        // - UI 详情区据此展示缺失 private type 和可用 public symbol 示例；
        // - 这样用户能看到“为什么不能深读”和“当前已经有哪些具体证据”。
        appendWin32kRuntimeCatalogPreview(lines, rootObject);

        const QJsonObject missingByModule =
            rootObject.value(QStringLiteral("missingPrivateTypesByModule")).toObject();
        for (auto iterator = missingByModule.constBegin(); iterator != missingByModule.constEnd(); ++iterator)
        {
            QStringList missingTypes;
            const QJsonArray missingArray = iterator.value().toArray();
            for (const QJsonValue& missingValue : missingArray)
            {
                if (missingValue.isString())
                {
                    missingTypes.push_back(missingValue.toString());
                }
            }
            lines.field(QStringLiteral("MissingPrivateTypes[%1]").arg(iterator.key()),
                missingTypes.isEmpty() ? QStringLiteral("<none>") : missingTypes.join(QStringLiteral(", ")));
        }

        lines.field(QStringLiteral("说明"), QStringLiteral("publicSymbols 可用于函数/模块归因；tagWND/tagTHREADINFO/tagQ/tagHOOK/tagHOTKEY 字段读取仍需要 private PDB 或经验证 profile。"));

        const QJsonArray moduleArray = rootObject.value(QStringLiteral("modules")).toArray();
        for (const QJsonValue& moduleValue : moduleArray)
        {
            const QJsonObject moduleObject = moduleValue.toObject();
            const QJsonObject sourceObject = moduleObject.value(QStringLiteral("source")).toObject();
            const QJsonObject moduleStatsObject = moduleObject.value(QStringLiteral("stats")).toObject();
            lines.field(QStringLiteral("Module"), QStringLiteral("%1 PDB=%2 Age=%3 PublicSymbols=%4 Fields=%5")
                .arg(win32kJsonString(moduleObject, QStringLiteral("moduleName"), QStringLiteral("<module>")))
                .arg(win32kJsonString(sourceObject, QStringLiteral("pdbGuid"), QStringLiteral("<guid>")))
                .arg(win32kJsonInt(sourceObject, QStringLiteral("pdbAge"), 0))
                .arg(win32kJsonInt(moduleStatsObject, QStringLiteral("publicSymbolCount"), 0))
                .arg(win32kJsonInt(moduleStatsObject, QStringLiteral("fieldCount"), 0)));
            appendWin32kPublicSymbolExamples(lines, moduleObject, QStringLiteral("window_object"), 3);
            appendWin32kPublicSymbolExamples(lines, moduleObject, QStringLiteral("gui_thread_queue"), 3);
            appendWin32kPublicSymbolExamples(lines, moduleObject, QStringLiteral("hotkey_hook"), 3);
            appendWin32kPublicSymbolExamples(lines, moduleObject, QStringLiteral("desktop_session"), 2);
        }

        const QJsonArray notesArray = rootObject.value(QStringLiteral("notes")).toArray();
        for (const QJsonValue& noteValue : notesArray)
        {
            if (noteValue.isString())
            {
                lines.field(QStringLiteral("Note"), QStringLiteral("%1").arg(noteValue.toString()));
            }
        }

        return storeAndReturn(lines);
    }

    // win32kPrivateLayoutLimitationText 作用：
    // - 说明 public win32k PDB 当前缺少 tagWND/tagTHREADINFO/tagQ 等私有结构；
    // - 输入：无；
    // - 返回：适合摘要区和表格明细列展示的人读说明。
    QString win32kPrivateLayoutLimitationText()
    {
        return QStringLiteral(
            "当前 public win32k PDB 只提供公共符号/部分类型，缺少 tagWND、tagTHREADINFO、tagQ、tagHOOK、tagHOTKEY、tagDESKTOP 等私有 GUI layout；"
            "因此 R0 单窗口详情只能报告模块/profile/capability readiness，不能安全读取 tagWND 字段。");
    }

    // readableDriverDetailText 作用：
    // - 输入 rawDetail：R0/R3 wrapper 返回的原始 detail 文本，fallbackText：空值替代说明；
    // - 处理：把常见英文 IOCTL/unsupported/profile/capability 日志折叠为中文可读解释；
    // - 返回：适合放入表格“明细”末列的短文本，避免直接暴露 DeviceIoControl 原始日志。
    QString readableDriverDetailText(
        const QString& rawDetail,
        const QString& fallbackText = QStringLiteral("驱动未提供额外明细"))
    {
        QString detailText = rawDetail.trimmed();
        detailText.replace(QChar('\r'), QChar(' '));
        detailText.replace(QChar('\n'), QChar(' '));
        detailText = detailText.simplified();

        if (detailText.isEmpty() ||
            detailText == QStringLiteral("<empty>") ||
            detailText == QStringLiteral("<none>") ||
            detailText == QStringLiteral("无额外说明"))
        {
            return fallbackText;
        }
        if (detailText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动调用失败或当前 R3/R0 协议版本不匹配");
        }
        if (detailText.contains(QStringLiteral("tagWND"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("not wired"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("not been wired"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("waiting for"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("private"), Qt::CaseInsensitive)))
        {
            return win32kPrivateLayoutLimitationText();
        }
        if (detailText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            detailText.contains(QStringLiteral("not supported"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动/协议暂不支持该只读审计入口");
        }
        if (detailText.contains(QStringLiteral("profile"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("missing"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("not found"), Qt::CaseInsensitive)))
        {
            return QStringLiteral("缺少匹配的 PDB/DynData profile，已降级为可用字段展示");
        }
        if (detailText.contains(QStringLiteral("capability"), Qt::CaseInsensitive) &&
            (detailText.contains(QStringLiteral("missing"), Qt::CaseInsensitive) ||
             detailText.contains(QStringLiteral("denied"), Qt::CaseInsensitive)))
        {
            return QStringLiteral("DynData capability 未满足，相关深度字段暂不可用");
        }
        if (detailText.contains(QStringLiteral("buffer"), Qt::CaseInsensitive) &&
            detailText.contains(QStringLiteral("trunc"), Qt::CaseInsensitive))
        {
            return QStringLiteral("结果过多，当前缓冲区内只展示截断后的前部证据");
        }
        return detailText;
    }

    // auditStateText 作用：
    // - 将新 R0 variable audit wrapper 的状态归一成 ok/unsupported/unavailable；
    // - 输入 result：带 io/unsupported 字段的结果结构；
    // - 返回：给表格诊断行展示的短状态。
    template <typename TResult>
    QString auditStateText(const TResult& result)
    {
        if (result.io.ok)
        {
            return QStringLiteral("ok");
        }
        if (result.unsupported)
        {
            return QStringLiteral("unsupported");
        }
        return QStringLiteral("unavailable");
    }

    // auditMessageText 作用：
    // - 汇总 IO 状态、返回行数和错误消息；
    // - 输入 name：wrapper 名，result：ArkDriverClient 结果；
    // - 返回：可放进“明细”列的一行诊断文本。
    template <typename TResult>
    QString auditMessageText(const QString& name, const TResult& result)
    {
        const QString messageText = QString::fromStdString(result.io.message).trimmed().isEmpty()
            ? QStringLiteral("<empty>")
            : QString::fromStdString(result.io.message);
        const bool isWin32kAudit =
            name.contains(QStringLiteral("Win32k"), Qt::CaseInsensitive) ||
            name.contains(QStringLiteral("win32k"), Qt::CaseInsensitive);

        QString readableStateText;
        if (result.io.ok)
        {
            if (isWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING)
            {
                readableStateText = QStringLiteral("驱动入口可用，但缺少对应 win32k PDB profile/字段映射，当前不会返回结构化行");
            }
            else if (isWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND)
            {
                readableStateText = QStringLiteral("驱动入口可用，但未定位 win32k/win32kbase/win32kfull 模块");
            }
            else if (isWin32kAudit &&
                result.status == KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED)
            {
                readableStateText = QStringLiteral("驱动入口可用，但底层枚举模式/Session 不匹配，当前不会返回结构化行");
            }
            else
            {
                readableStateText = result.returnedCount == 0U
                    ? QStringLiteral("驱动接口可用，但本次没有返回结构化行")
                    : QStringLiteral("驱动接口可用，已返回结构化行");
            }
        }
        else if (result.unsupported)
        {
            readableStateText = QStringLiteral("当前驱动未提供这个 win32k 审计入口");
        }
        else
        {
            readableStateText = QStringLiteral("驱动接口暂不可用，页面使用本地只读 fallback");
        }

        const QString readableMessageText =
            messageText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive)
            ? QStringLiteral("驱动调用失败或版本不匹配，已保留本地证据行")
            : (messageText == QStringLiteral("<empty>") ? QStringLiteral("无额外驱动消息") : messageText);

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；最近状态 %5；说明：%6")
            .arg(name)
            .arg(readableStateText)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(formatNtStatusText(result.lastStatus))
            .arg(readableMessageText);
    }

    // win32kEmptyStateText 作用：
    // - 输入 result：Win32K 结构化枚举结果；
    // - 处理：把“IOCTL 成功但没有行”的根因拆成缺 profile、模块缺失、空结果等；
    // - 返回：表格状态列文本，避免把 profile-gated 空响应误显示为 ok。
    template <typename TResult>
    QString win32kEmptyStateText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return result.unsupported ? QStringLiteral("unsupported") : QStringLiteral("unavailable");
        }
        switch (result.status)
        {
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING:
            return QStringLiteral("profile-missing");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("win32k-not-found");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED:
            return QStringLiteral("unsupported");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("truncated");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED:
            return QStringLiteral("enum-failed");
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return result.returnedCount == 0U ? QStringLiteral("empty") : QStringLiteral("ok");
        default:
            return QStringLiteral("status-%1").arg(result.status);
        }
    }

    // keyboardMessageText 作用：
    // - 汇总旧 keyboard hotkey/hook wrapper 的状态；
    // - 输入 name：wrapper 名，result：Keyboard 枚举结果；
    // - 返回：可放进 fallback 诊断行的一行文本。
    template <typename TResult>
    QString keyboardMessageText(const QString& name, const TResult& result)
    {
        const QString messageText = QString::fromStdString(result.io.message).trimmed().isEmpty()
            ? QStringLiteral("<empty>")
            : QString::fromStdString(result.io.message);

        const QString readableStateText = result.io.ok
            ? (result.returnedCount == 0U
                ? QStringLiteral("键盘审计 fallback 可用，但未返回热键/Hook 行")
                : QStringLiteral("键盘审计 fallback 已返回结构化行"))
            : QStringLiteral("键盘审计 fallback 当前不可用");
        const QString readableMessageText =
            messageText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive)
            ? QStringLiteral("旧键盘审计接口调用失败或驱动未注册该入口")
            : (messageText == QStringLiteral("<empty>") ? QStringLiteral("无额外驱动消息") : messageText);

        return QStringLiteral("%1：%2；驱动报告 %3/%4 行；最近状态 %5；说明：%6")
            .arg(name)
            .arg(readableStateText)
            .arg(result.returnedCount)
            .arg(result.totalCount)
            .arg(formatNtStatusText(result.lastStatus))
            .arg(readableMessageText);
    }

    // keyboardEmptyStateText 作用：
    // - 输入 result：旧 keyboard fallback 枚举结果；
    // - 处理：把 pattern/session/unsupported 等状态转为短文本；
    // - 返回：热键/Hook 表 fallback 状态列文本。
    template <typename TResult>
    QString keyboardEmptyStateText(const TResult& result)
    {
        if (!result.io.ok)
        {
            return QStringLiteral("keyboard-unavailable");
        }
        switch (result.status)
        {
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_OK:
            return result.returnedCount == 0U ? QStringLiteral("keyboard-empty") : QStringLiteral("keyboard-ok");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_UNSUPPORTED:
            return QStringLiteral("keyboard-unsupported");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("keyboard-win32k-not-found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_PATTERN_NOT_FOUND:
            return QStringLiteral("keyboard-pattern-not-found");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_SESSION_UNAVAILABLE:
            return QStringLiteral("keyboard-session-unavailable");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("keyboard-truncated");
        case KSWORD_ARK_KEYBOARD_ENUM_STATUS_READ_FAILED:
            return QStringLiteral("keyboard-read-failed");
        default:
            return QStringLiteral("keyboard-status-%1").arg(result.status);
        }
    }

    // clipboardSnapshotRows 作用：
    // - 输入 clipboardObject：当前 UI 线程可访问的剪贴板对象；
    // - 处理：只生成类型化摘要，避免用户刚复制的审计表 TSV 被误显示成“剪贴板审计真实内容”；
    // - 返回：剪贴板页键值行，不抓取消息、不安装 hook、不解析敏感 payload。
    QVector<QStringList> clipboardSnapshotRows(const QClipboard* clipboardObject)
    {
        QVector<QStringList> rows;
        rows.reserve(8);
        if (clipboardObject == nullptr)
        {
            rows.push_back(QStringList{ QStringLiteral("ClipboardAvailable"), QStringLiteral("否") });
            rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("QApplication::clipboard 不可用，无法读取 UI 会话剪贴板摘要。") });
            return rows;
        }

        const QMimeData* mimeData = clipboardObject->mimeData(QClipboard::Clipboard);
        rows.push_back(QStringList{ QStringLiteral("ClipboardAvailable"), QStringLiteral("是") });
        rows.push_back(QStringList{ QStringLiteral("OwnsClipboard"), boolText(clipboardObject->ownsClipboard()) });
        if (mimeData == nullptr)
        {
            rows.push_back(QStringList{ QStringLiteral("MimeData"), QStringLiteral("<无>") });
            rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("剪贴板当前没有可读 MIME 数据。") });
            return rows;
        }

        rows.push_back(QStringList{ QStringLiteral("HasText"), boolText(mimeData->hasText()) });
        rows.push_back(QStringList{ QStringLiteral("HasHtml"), boolText(mimeData->hasHtml()) });
        rows.push_back(QStringList{ QStringLiteral("HasImage"), boolText(mimeData->hasImage()) });
        rows.push_back(QStringList{ QStringLiteral("HasUrls"), boolText(mimeData->hasUrls()) });
        rows.push_back(QStringList{ QStringLiteral("Formats"), mimeData->formats().join(QStringLiteral("; ")) });

        if (mimeData->hasText())
        {
            QString textPreview = mimeData->text();
            const bool looksLikeAuditTableRow =
                textPreview.contains(QChar('\t')) &&
                (textPreview.contains(QStringLiteral("queryWin32k"), Qt::CaseInsensitive) ||
                 textPreview.contains(QStringLiteral("<无Hook行>"), Qt::CaseInsensitive) ||
                 textPreview.contains(QStringLiteral("<无热键行>"), Qt::CaseInsensitive));
            if (looksLikeAuditTableRow)
            {
                rows.push_back(QStringList{
                    QStringLiteral("TextPreview"),
                    QStringLiteral("<已隐藏：当前剪贴板像是本工具表格复制行，避免和剪贴板审计结果混淆>") });
            }
            else
            {
                textPreview.replace(QChar('\r'), QChar(' '));
                textPreview.replace(QChar('\n'), QChar(' '));
                textPreview = textPreview.simplified();
                if (textPreview.size() > 160)
                {
                    textPreview = textPreview.left(160) + QStringLiteral("...");
                }
                rows.push_back(QStringList{ QStringLiteral("TextPreview"), textPreview.isEmpty() ? QStringLiteral("<空文本>") : textPreview });
            }
        }
        else
        {
            rows.push_back(QStringList{ QStringLiteral("TextPreview"), QStringLiteral("<非文本剪贴板>") });
        }

        rows.push_back(QStringList{ QStringLiteral("MessageOnly窗口"), QStringLiteral("建议在“窗口管理”窗口列表中 cross-view 标注") });
        rows.push_back(QStringList{ QStringLiteral("说明"), QStringLiteral("只读读取剪贴板 MIME 摘要；不做消息抓取，不展示疑似审计表复制行。") });
        return rows;
    }

    QString wideArrayToQString(const wchar_t* const bufferPointer, const std::size_t maxChars);

    // win32kRuntimeStatusText 作用：
    // - 把单 HWND runtime detail 的状态转换为人可读短文本；
    // - 输入 statusValue：KSWORD_ARK_WIN32K_STATUS_*；
    // - 返回：用于窗口表“明细”列的稳定说明。
    QString win32kRuntimeStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_WIN32K_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_STATUS_PARTIAL:
            return QStringLiteral("Partial（部分字段可用）");
        case KSWORD_ARK_WIN32K_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported（驱动/协议不支持）");
        case KSWORD_ARK_WIN32K_STATUS_PROFILE_MISSING:
            return QStringLiteral("ProfileMissing（缺少PDB profile）");
        case KSWORD_ARK_WIN32K_STATUS_WIN32K_NOT_FOUND:
            return QStringLiteral("Win32kNotFound（模块未找到）");
        case KSWORD_ARK_WIN32K_STATUS_BUFFER_TRUNCATED:
            return QStringLiteral("BufferTruncated（结果被截断）");
        case KSWORD_ARK_WIN32K_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed（读取失败）");
        case KSWORD_ARK_WIN32K_STATUS_ENUM_FAILED:
            return QStringLiteral("EnumFailed（枚举失败）");
        case KSWORD_ARK_WIN32K_STATUS_UNKNOWN:
            return QStringLiteral("Unknown（未初始化）");
        default:
            return QStringLiteral("Status(%1)").arg(statusValue);
        }
    }

    // win32kRectText 作用：
    // - 把 R0 返回的 RECT 转成短文本；
    // - 输入 rect：窗口或 client 矩形；
    // - 返回：left,top,width,height 形式，便于读表。
    QString win32kRectText(const KSWORD_ARK_WIN32K_RECT& rect)
    {
        const long width = rect.right - rect.left;
        const long height = rect.bottom - rect.top;
        return QStringLiteral("[%1,%2 %3x%4]")
            .arg(rect.left)
            .arg(rect.top)
            .arg(width)
            .arg(height);
    }

    // win32kReadStatusText 作用：
    // - 把 title/class 等字段级读取状态转换成可读文本；
    // - 输入 statusValue：KSWORD_ARK_WIN32K_READ_STATUS_*；
    // - 返回：字段读取结果说明。
    QString win32kReadStatusText(const std::uint32_t statusValue)
    {
        switch (statusValue)
        {
        case KSWORD_ARK_WIN32K_READ_STATUS_NOT_REQUESTED:
            return QStringLiteral("NotRequested");
        case KSWORD_ARK_WIN32K_READ_STATUS_OK:
            return QStringLiteral("OK");
        case KSWORD_ARK_WIN32K_READ_STATUS_UNSUPPORTED:
            return QStringLiteral("Unsupported");
        case KSWORD_ARK_WIN32K_READ_STATUS_PROFILE_MISSING:
            return QStringLiteral("ProfileMissing");
        case KSWORD_ARK_WIN32K_READ_STATUS_READ_FAILED:
            return QStringLiteral("ReadFailed");
        case KSWORD_ARK_WIN32K_READ_STATUS_TRUNCATED:
            return QStringLiteral("Truncated");
        default:
            return QStringLiteral("ReadStatus(%1)").arg(statusValue);
        }
    }

    // win32kWindowSnapshotDetailText 作用：
    // - 把单行窗口快照转换成面向人的审计摘要；
    // - 输入 entry：R0 win32k window 行，runtimeDetailText：可选单 HWND detail；
    // - 返回：表格末列明细，不再直接塞驱动原始日志。
    QString win32kWindowSnapshotDetailText(
        const KSWORD_ARK_WIN32K_WINDOW_ENTRY& entry,
        const QString& runtimeDetailText)
    {
        const QString snapshotText =
            readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("窗口快照未提供额外驱动说明"));
        return QStringLiteral(
            "快照：%1；fieldFlags=%2；tagWND=%3；threadInfo=%4；desktop=%5；"
            "windowRect=%6；clientRect=%7；titleRead=%8；classRead=%9；%10；驱动说明=%11")
            .arg(win32kRuntimeStatusText(entry.status))
            .arg(formatUInt64Hex(entry.fieldFlags))
            .arg(formatUInt64Hex(entry.tagWnd))
            .arg(formatUInt64Hex(entry.threadInfo))
            .arg(formatUInt64Hex(entry.desktopObject))
            .arg(win32kRectText(entry.windowRect))
            .arg(win32kRectText(entry.clientRect))
            .arg(win32kReadStatusText(entry.titleStatus))
            .arg(win32kReadStatusText(entry.classStatus))
            .arg(runtimeDetailText)
            .arg(snapshotText);
    }

    // win32kWindowRuntimeDetailText 作用：
    // - 调用 ArkDriverClient 单 HWND detail wrapper 并生成可读摘要；
    // - 输入 hwnd/processId/threadId：窗口快照行中的身份字段；
    // - 返回：只读诊断文本，不安装 hook、不读取消息 payload。
    ks::ui::FieldDocument win32kWindowRuntimeDocument(
        const std::uint64_t hwnd,
        const std::uint32_t processId,
        const std::uint32_t threadId)
    {
        const ksword::ark::Win32kWindowRuntimeDetailResult detailResult =
            ksword::ark::DriverClient().queryWin32kWindowDetail(hwnd, processId, threadId);
        if (!detailResult.io.ok)
        {
            const QString rawMessage =
                QString::fromStdString(detailResult.io.message).trimmed();
            if (detailResult.unsupported)
            {
                return ks::ui::FieldDocument{}.note(QStringLiteral("单窗口详情：当前驱动未提供该 IOCTL。"));
            }
            if (rawMessage.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
            {
                return ks::ui::FieldDocument{}.note(QStringLiteral("单窗口详情：驱动调用失败或版本不匹配。"));
            }
            return ks::ui::FieldDocument{}.note(QStringLiteral("单窗口详情：%1")
                .arg(rawMessage.isEmpty() ? QStringLiteral("暂不可用。") : rawMessage));
        }

        const KSWORD_ARK_WIN32K_WINDOW_DETAIL_RESPONSE& response = detailResult.response;
        ks::ui::FieldDocument detail;
        detail.section(QStringLiteral("Win32K Window Runtime Detail"));
        detail.field(QStringLiteral("状态"), win32kRuntimeStatusText(response.status));
        detail.field(QStringLiteral("HWND"), formatUInt64Hex(response.hwnd));
        detail.field(QStringLiteral("PID"), QString::number(response.processId));
        detail.field(QStringLiteral("TID"), QString::number(response.threadId));
        detail.field(QStringLiteral("tagWND"), formatUInt64Hex(response.tagWnd));
        detail.field(QStringLiteral("threadInfo"), formatUInt64Hex(response.threadInfo));
        detail.field(QStringLiteral("queue"), formatUInt64Hex(response.queueObject));
        detail.field(QStringLiteral("desktop"), formatUInt64Hex(response.desktopObject));
        detail.field(QStringLiteral("capability"), formatUInt64Hex(response.capabilityMask));
        detail.field(QStringLiteral("missing"), formatUInt64Hex(response.missingCapabilityMask));
        detail.field(QStringLiteral("fieldFlags"), formatUInt64Hex(response.fieldFlags));
        detail.note(readableDriverDetailText(wideArrayToQString(response.detail,
            KSWORD_ARK_RUNTIME_DETAIL_TEXT_CHARS), QStringLiteral("单窗口详情未提供额外驱动说明")));
        return detail;
    }

    // tableCopyMenuStyle 作用：
    // - 为新增右键菜单提供不透明背景，避免继承透明/黑底黑字；
    // - 输入：无；
    // - 返回：QMenu 样式表。
    QString tableCopyMenuStyle()
    {
        return KswordTheme::ContextMenuStyle();
    }

    // auditTableStyle 作用：
    // - 为 WindowDock 新增审计表格显式设置不透明背景、文字色和选中态；
    // - 输入：无；
    // - 返回：可直接应用到 QTableWidget 的样式文本，避免继承父级透明/深色样式后“有行但看起来空白”。
    QString auditTableStyle()
    {
        // 这里使用真实 #RRGGBB，而不是 palette(base) 这类动态 role：
        // - 某些父级 Dock 样式会把 palette role 继续继承成透明或异常颜色；
        // - 用户反馈“表格完全不显示”时，行模型已经有兜底数据，最需要先保证绘制层可见；
        // - 返回值只影响审计表外观，不改变表格数据和任何 R0/R3 查询逻辑。
        const QString surfaceColor = KswordTheme::SurfaceColorHex();
        const QString surfaceAltColor = KswordTheme::SurfaceAltColorHex();
        const QString borderColor = KswordTheme::BorderColorHex();
        const QString textColor = KswordTheme::TextPrimaryColorHex();

        return QStringLiteral(
            "QTableWidget{"
            "  background-color:%1;"
            "  alternate-background-color:%2;"
            "  color:%3;"
            "  gridline-color:%4;"
            "}"
            "QTableWidget::item{"
            "  color:%3;"
            "  padding:3px 5px;"
            "}"
            "QHeaderView::section{"
            "  background:transparent; /* %2 */"
            "  background-color:transparent;"
            "  color:%3;"
            "  border:1px solid %4;"
            "  padding:4px 6px;"
            "}")
            .arg(surfaceColor)
            .arg(surfaceAltColor)
            .arg(textColor)
            .arg(borderColor)
            .arg(KswordTheme::AccentHex(KswordTheme::AccentRole::Blue));
    }

    // transparentAuditTableStyle 作用：
    // - 为 WindowDock 的透明结构化表格保留父级 Tab 页背景；
    // - 表格本体、viewport 和交替行均不绘制独立底色，避免遮住 Dock 背景；
    // - 返回：可直接应用到 QTableWidget 的透明样式文本。
    QString transparentAuditTableStyle()
    {
        const QString borderColor = KswordTheme::BorderColorHex();
        const QString textColor = KswordTheme::TextPrimaryColorHex();

        return QStringLiteral(
            "QTableWidget{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  alternate-background-color:transparent;"
            "  color:%1;"
            "  gridline-color:%2;"
            "}"
            "QTableWidget::viewport{"
            "  background:transparent;"
            "  background-color:transparent;"
            "}"
            "QTableWidget::item{"
            "  color:%1;"
            "  padding:3px 5px;"
            "}"
            "QHeaderView::section{"
            "  background:transparent;"
            "  background-color:transparent;"
            "  color:%1;"
            "  border:1px solid %2;"
            "  padding:4px 6px;"
            "}")
            .arg(textColor)
            .arg(borderColor);
    }

    // applyAuditTablePalette 作用：
    // - 输入 table：WindowDock 审计页中的只读表格；
    // - 处理：同时写 QPalette 和 viewport 背景，避免父级透明 Dock 或异常 QSS 让表格“有行但看不见”；
    // - 返回：无，只影响控件绘制，不改变任何 R0/R3 数据路径。
    void applyAuditTablePalette(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        const bool usesTransparentBackground =
            table->property("ksword_transparent_audit_table").toBool();
        QPalette tablePalette = table->palette();
        tablePalette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        tablePalette.setColor(QPalette::AlternateBase, KswordTheme::SurfaceAltColor());
        tablePalette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        tablePalette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        tablePalette.setColor(QPalette::HighlightedText, KswordTheme::OnAccentColor());
        tablePalette.setColor(QPalette::Highlight, KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));
        table->setPalette(tablePalette);
        table->setAlternatingRowColors(!usesTransparentBackground);
        table->setAutoFillBackground(!usesTransparentBackground);
        table->setAttribute(Qt::WA_StyledBackground, usesTransparentBackground);
        if (table->viewport() != nullptr)
        {
            table->viewport()->setPalette(tablePalette);
            table->viewport()->setAutoFillBackground(!usesTransparentBackground);
            table->viewport()->setAttribute(Qt::WA_StyledBackground, usesTransparentBackground);
        }
    }

    // applyTransparentAuditTableBackground 作用：
    // - 输入 table：需要穿透父级背景的 WindowDock 审计表；
    // - 处理：写入持久化属性、透明 QSS 和绘制属性；
    // - 返回：无。后续刷新调用 applyAuditTablePalette 时会保留透明状态。
    void applyTransparentAuditTableBackground(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setProperty("ksword_transparent_audit_table", true);
        table->setStyleSheet(transparentAuditTableStyle());
        applyAuditTablePalette(table);
    }

    // copyTableCurrentRow 作用：
    // - 把当前表格行按 TSV 复制到剪贴板；
    // - 输入 table：目标表格；
    // - 返回：无，失败时静默保持 UI 稳定。
    void copyTableCurrentRow(QTableWidget* table)
    {
        if (table == nullptr || QApplication::clipboard() == nullptr)
        {
            return;
        }

        const int rowIndex = table->currentRow();
        if (rowIndex < 0 || rowIndex >= table->rowCount())
        {
            return;
        }

        QStringList fields;
        fields.reserve(table->columnCount());
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            const QTableWidgetItem* item = table->item(rowIndex, columnIndex);
            fields.push_back(item != nullptr ? item->text() : QString());
        }
        QApplication::clipboard()->setText(fields.join('\t'));
    }

    // installTableCopyMenu 作用：
    // - 给只读表格安装“复制当前行”右键菜单；
    // - 各业务表显式设置 ksword_process_detail_pid_column 时，按该列 PID 添加“转到进程详细信息”；
    // - 如果表格设置了 kswordSandboxPidColumn 属性，则额外添加“上传到沙箱 -> VT”并按该列 PID 上传进程 EXE；
    // - 输入 table：需要安装菜单的表格；
    // - 返回：无，菜单 action 只读，不触发任何系统修改。
    void installTableCopyMenu(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return;
        }

        table->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(table, &QTableWidget::customContextMenuRequested, table, [table](const QPoint& localPosition)
        {
            const QModelIndex clickedIndex = table->indexAt(localPosition);
            if (clickedIndex.isValid())
            {
                table->setCurrentCell(clickedIndex.row(), clickedIndex.column());
                table->selectRow(clickedIndex.row());
            }

            QMenu menu(table);
            menu.setStyleSheet(tableCopyMenuStyle());
            QAction* copyRowAction = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            copyRowAction->setEnabled(table->currentRow() >= 0);

            QAction* openProcessAction = nullptr;
            quint32 processId = 0U;
            const QVariant processDetailPidColumnValue = table->property("ksword_process_detail_pid_column");
            if (processDetailPidColumnValue.isValid())
            {
                const int processDetailPidColumn = processDetailPidColumnValue.toInt();
                const QTableWidgetItem* processIdItem =
                    processDetailPidColumn >= 0 && processDetailPidColumn < table->columnCount() && table->currentRow() >= 0
                    ? table->item(table->currentRow(), processDetailPidColumn)
                    : nullptr;
                bool processIdOk = false;
                processId = processIdItem != nullptr
                    ? processIdItem->text().trimmed().toUInt(&processIdOk, 10)
                    : 0U;
                openProcessAction = menu.addAction(
                    QIcon(QStringLiteral(":/Icon/process_details.svg")),
                    QStringLiteral("转到进程详细信息"));
                openProcessAction->setEnabled(processIdOk && processId != 0U);
            }

            QAction* uploadVirusTotalAction = nullptr;
            const int sandboxPidColumn = table->property("kswordSandboxPidColumn").toInt();
            if (sandboxPidColumn >= 0 && sandboxPidColumn < table->columnCount())
            {
                menu.addSeparator();
                uploadVirusTotalAction = ks::online_scan::addVirusTotalSandboxMenu(
                    &menu,
                    table,
                    [table, sandboxPidColumn]() -> ks::online_scan::SandboxUploadTarget
                    {
                        // 输入：WindowDock 表格当前行和配置的 PID 列。
                        // 处理：从 PID 列解析 GUI 线程/窗口所属进程。
                        // 返回：空 filePath 表示让统一层按 PID 查询 EXE。
                        ks::online_scan::SandboxUploadTarget uploadTarget;
                        const int rowIndex = table != nullptr ? table->currentRow() : -1;
                        const QTableWidgetItem* pidItem =
                            (table != nullptr && rowIndex >= 0) ? table->item(rowIndex, sandboxPidColumn) : nullptr;
                        std::uint32_t pidValue = 0;
                        if (pidItem == nullptr || !ks::online_scan::tryParsePidFromText(pidItem->text(), &pidValue))
                        {
                            uploadTarget.errorText = QStringLiteral("当前窗口/GUI线程行没有可解析的 PID。");
                            return uploadTarget;
                        }

                        uploadTarget.filePath = QString::fromStdString(ks::process::QueryProcessPathByPid(pidValue));
                        uploadTarget.sourceText = QStringLiteral("窗口/GUI线程 PID=%1").arg(pidValue);
                        return uploadTarget;
                    });
                if (uploadVirusTotalAction != nullptr)
                {
                    uploadVirusTotalAction->setEnabled(table->currentRow() >= 0);
                }
            }

            QAction* selectedAction = menu.exec(table->viewport()->mapToGlobal(localPosition));
            if (selectedAction == copyRowAction)
            {
                copyTableCurrentRow(table);
            }
            else if (selectedAction == openProcessAction)
            {
                ks::ui::OpenProcessDetailByPid(processId);
            }
        });
    }

    // containsColumnIndex 作用：
    // - 输入 columnGroup：预设列号集合，columnIndex：候选列号；
    // - 处理：判断该列是否属于当前 A/B 预设；
    // - 返回：true 表示应显示该列。
    bool containsColumnIndex(const QVector<int>& columnGroup, const int columnIndex)
    {
        return std::find(columnGroup.begin(), columnGroup.end(), columnIndex) != columnGroup.end();
    }

    // buildColumnPresetButtonStyle 作用：
    // - 输入 selected：按钮是否对应当前列组；
    // - 处理：选中时使用主题主色背景，未选中时使用中性纯色背景和主题文字；
    // - 返回：QPushButton stylesheet 文本。
    QString buildColumnPresetButtonStyle(const bool selected)
    {
        // A/B 仍按业务预设决定强调状态，手工布局回到中性色，保留24px宽度。
        return ks::ui::BuildFlatButtonStyle(selected ? ks::ui::FlatButtonTone::Accent : ks::ui::FlatButtonTone::Neutral)
            + QStringLiteral("QPushButton{min-width:24px;max-width:24px;padding:3px 0;border-radius:0;font-weight:700;}");
    }

    // updateColumnPresetButtons 作用：
    // - 输入 table：目标表格，buttonA/buttonB：列组按钮；
    // - 处理：按表格属性刷新按钮着色，自定义列布局时两者均不着色；
    // - 返回：无。
    void updateColumnPresetButtons(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr)
        {
            return;
        }

        const QString presetText = table->property("kswordColumnPreset").toString();
        // 按钮属性用途：保存当前选中态，主题刷新时无需重新捕获局部 lambda 指针。
        const bool buttonASelected = presetText == QStringLiteral("A");
        const bool buttonBSelected = presetText == QStringLiteral("B");
        buttonA->setProperty(kColumnPresetSelectedProperty, buttonASelected);
        buttonB->setProperty(kColumnPresetSelectedProperty, buttonBSelected);
        buttonA->setStyleSheet(buildColumnPresetButtonStyle(buttonASelected));
        buttonB->setStyleSheet(buildColumnPresetButtonStyle(buttonBSelected));
    }

    // applyColumnPresetToTable 作用：
    // - 输入 table：目标表格，columnGroup：要显示的列，presetText：A/B 名称；
    // - 处理：仅切换列显隐，不改动行模型、排序和刷新状态；
    // - 返回：无。
    void applyColumnPresetToTable(
        QTableWidget* table,
        const QVector<int>& columnGroup,
        const QString& presetText,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr)
        {
            return;
        }

        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            table->setColumnHidden(columnIndex, !containsColumnIndex(columnGroup, columnIndex));
        }
        table->setProperty("kswordColumnPreset", presetText);
        updateColumnPresetButtons(table, buttonA, buttonB);
    }

    // visibleColumnCount 作用：
    // - 输入 table：目标表格；
    // - 处理：统计未隐藏列，避免右键菜单隐藏最后一列；
    // - 返回：可见列数量。
    int visibleColumnCount(QTableWidget* table)
    {
        if (table == nullptr)
        {
            return 0;
        }

        int count = 0;
        for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
        {
            if (!table->isColumnHidden(columnIndex))
            {
                ++count;
            }
        }
        return count;
    }

    // createColumnPresetButton 作用：
    // - 输入 parentWidget：父控件，buttonText：A/B 文本，tooltipText：悬停说明；
    // - 处理：创建左右紧贴的短按钮；
    // - 返回：由 Qt 父子树释放的 QPushButton。
    QPushButton* createColumnPresetButton(
        QWidget* parentWidget,
        const QString& buttonText,
        const QString& tooltipText)
    {
        QPushButton* button = new QPushButton(buttonText, parentWidget);
        button->setToolTip(tooltipText);
        button->setCursor(Qt::PointingHandCursor);
        // 该动态属性标识由 WindowDock 主题刷新统一管理的 A/B 列预设按钮。
        button->setProperty(kColumnPresetSelectedProperty, false);
        button->setStyleSheet(buildColumnPresetButtonStyle(false));
        return button;
    }

    // installHeaderColumnMenu 作用：
    // - 输入 table：目标表格，buttonA/buttonB：列组按钮；
    // - 处理：在表头安装显式主题样式右键菜单，允许逐列勾选显示；
    // - 返回：无，手动改列后设置为 Custom 状态。
    void installHeaderColumnMenu(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB)
    {
        if (table == nullptr || table->horizontalHeader() == nullptr)
        {
            return;
        }

        QHeaderView* headerView = table->horizontalHeader();
        headerView->setContextMenuPolicy(Qt::CustomContextMenu);
        QObject::connect(headerView, &QHeaderView::customContextMenuRequested, table, [table, headerView, buttonA, buttonB](const QPoint& localPosition)
        {
            QMenu menu(table);
            menu.setStyleSheet(tableCopyMenuStyle());
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QTableWidgetItem* headerItem = table->horizontalHeaderItem(columnIndex);
                const QString headerText = headerItem != nullptr
                    ? headerItem->text()
                    : QStringLiteral("Column %1").arg(columnIndex);
                QAction* columnAction = menu.addAction(headerText);
                columnAction->setCheckable(true);
                columnAction->setChecked(!table->isColumnHidden(columnIndex));
                columnAction->setData(columnIndex);
            }

            QAction* selectedAction = menu.exec(headerView->viewport()->mapToGlobal(localPosition));
            if (selectedAction == nullptr)
            {
                return;
            }

            const int columnIndex = selectedAction->data().toInt();
            const bool shouldShow = selectedAction->isChecked();
            if (!shouldShow && visibleColumnCount(table) <= 1)
            {
                table->setColumnHidden(columnIndex, false);
                return;
            }

            table->setColumnHidden(columnIndex, !shouldShow);
            table->setProperty("kswordColumnPreset", QStringLiteral("Custom"));
            updateColumnPresetButtons(table, buttonA, buttonB);
        });
    }

    // installColumnPresetControls 作用：
    // - 输入 table：目标表格，buttonA/buttonB：列组按钮，groupA/groupB：两组精简列；
    // - 处理：绑定 A/B 切换和表头列菜单，默认应用 A 组；
    // - 返回：无。
    void installColumnPresetControls(
        QTableWidget* table,
        QPushButton* buttonA,
        QPushButton* buttonB,
        const QVector<int>& groupA,
        const QVector<int>& groupB)
    {
        if (table == nullptr || buttonA == nullptr || buttonB == nullptr)
        {
            return;
        }

        QObject::connect(buttonA, &QPushButton::clicked, table, [table, buttonA, buttonB, groupA]()
        {
            applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB);
        });
        QObject::connect(buttonB, &QPushButton::clicked, table, [table, buttonA, buttonB, groupB]()
        {
            applyColumnPresetToTable(table, groupB, QStringLiteral("B"), buttonA, buttonB);
        });
        installHeaderColumnMenu(table, buttonA, buttonB);
        applyColumnPresetToTable(table, groupA, QStringLiteral("A"), buttonA, buttonB);
    }

    // wideArrayToQString 作用：
    // - 把 shared/driver 固定 wchar_t 缓冲区转成 QString；
    // - 输入 bufferPointer：固定字符串首地址，maxChars：最大字符数；
    // - 返回：去除尾部 NUL 后的文本，空值显示 <empty>。
    QString wideArrayToQString(const wchar_t* const bufferPointer, const std::size_t maxChars)
    {
        if (bufferPointer == nullptr || maxChars == 0U)
        {
            return QStringLiteral("<empty>");
        }

        std::size_t textLength = 0U;
        while (textLength < maxChars && bufferPointer[textLength] != L'\0')
        {
            ++textLength;
        }

        if (textLength == 0U)
        {
            return QStringLiteral("<empty>");
        }
        return QString::fromWCharArray(bufferPointer, static_cast<int>(textLength));
    }

    // appendIoSummary 作用：
    // - 为每个 ArkDriverClient wrapper 追加统一 IO/unsupported/可读说明摘要；
    // - 输入 text：输出文本，name：wrapper 名称，result：R0 wrapper 结果；
    // - 返回：无，直接追加到 text。
    template <typename TResult>
    void appendIoSummary(ks::ui::FieldDocument& text, const QString& name, const TResult& result)
    {
        text.section(name);
        text.field(QStringLiteral("io.ok"), QStringLiteral("%1").arg(boolText(result.io.ok)));
        text.field(QStringLiteral("unsupported"), QStringLiteral("%1").arg(boolText(result.unsupported)));
        text.field(QStringLiteral("status"), QStringLiteral("%1").arg(result.status));
        text.field(QStringLiteral("lastStatus"), QStringLiteral("%1").arg(result.lastStatus));
        text.field(QStringLiteral("returnedCount/totalCount"), QStringLiteral("%1 / %2")
            .arg(result.returnedCount)
            .arg(result.totalCount));
        text.field(QStringLiteral("entrySize"), QStringLiteral("%1").arg(result.entrySize));
        text.field(QStringLiteral("说明"), QStringLiteral("%1")
            .arg(auditMessageText(name, result)));
    }

    // appendKeyboardIoSummary 作用：
    // - 为旧 keyboard hotkey/hook wrapper 追加可读诊断摘要；
    // - 输入 text：输出文本，name：wrapper 名称，result：Keyboard 枚举结果；
    // - 返回：无，直接追加到 text。
    template <typename TResult>
    void appendKeyboardIoSummary(ks::ui::FieldDocument& text, const QString& name, const TResult& result)
    {
        text.section(name);
        text.field(QStringLiteral("io.ok"), QStringLiteral("%1").arg(boolText(result.io.ok)));
        text.field(QStringLiteral("status"), QStringLiteral("%1").arg(result.status));
        text.field(QStringLiteral("lastStatus"), QStringLiteral("%1").arg(result.lastStatus));
        text.field(QStringLiteral("returnedCount/totalCount"), QStringLiteral("%1 / %2")
            .arg(result.returnedCount)
            .arg(result.totalCount));
        text.field(QStringLiteral("说明"), QStringLiteral("%1")
            .arg(keyboardMessageText(name, result)));
    }

    // appendWin32kProfileHeader 作用：
    // - 展示 win32k profile / module / capability readiness（不含逐行 session，session 行交给表格）；
    // - 输入 text：输出文本，result：queryWin32kProfileStatus 返回；
    // - 返回：无。
    void appendWin32kProfileHeader(ks::ui::FieldDocument& text, const ksword::ark::Win32kProfileStatusResult& result)
    {
        appendIoSummary(text, QStringLiteral("queryWin32kProfileStatus"), result);
        text.field(QStringLiteral("capabilityMask"), QStringLiteral("%1").arg(formatUInt64Hex(result.capabilityMask)));
        text.field(QStringLiteral("missingCapabilityMask"), QStringLiteral("%1").arg(formatUInt64Hex(result.missingCapabilityMask)));
        text.field(QStringLiteral("userGetSiloGlobals"), QStringLiteral("%1").arg(formatUInt64Hex(result.userGetSiloGlobals)));

        const auto appendModule = [&text](const QString& title, const KSWORD_ARK_WIN32K_MODULE_STATE& moduleState)
        {
            text.section(title);
            text.field(QStringLiteral("loaded"), QString::number(moduleState.loaded));
            text.field(QStringLiteral("profileState"), QString::number(moduleState.profileState));
            text.field(QStringLiteral("imageBase"), formatUInt64Hex(moduleState.imageBase));
            text.field(QStringLiteral("imageSize"), QString::number(moduleState.imageSize));
            text.field(QStringLiteral("moduleName"), wideArrayToQString(moduleState.moduleName, KSWORD_ARK_WIN32K_MODULE_NAME_CHARS));
        };
        appendModule(QStringLiteral("win32k"), result.win32k);
        appendModule(QStringLiteral("win32kbase"), result.win32kbase);
        appendModule(QStringLiteral("win32kfull"), result.win32kfull);
    }

    // 以下 build*Rows：把 R0 结构化条目转成“逐行列文本”，覆盖全部行，不做截断。
    // - 在后台线程构造 QStringList（不触碰任何控件），随后回投 UI 线程填充表格。

    QVector<QStringList> buildWindowsRows(const ksword::ark::Win32kWindowsResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_WINDOW_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                formatUInt64Hex(entry.hwnd),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                wideArrayToQString(entry.title, KSWORD_ARK_WIN32K_TITLE_CHARS),
                wideArrayToQString(entry.className, KSWORD_ARK_WIN32K_CLASS_CHARS),
                formatUInt64Hex(entry.style),
                formatUInt64Hex(entry.exStyle),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                formatUInt64Hex(entry.parentHwnd),
                formatUInt64Hex(entry.ownerHwnd) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - 输入：当前交互桌面上的顶层 HWND；
        // - 处理：EnumWindows 只读枚举，不读取消息内容、不安装 hook；
        // - 输出：让窗口审计表即使 R0 暂无 tagWND 行也展示具体窗口证据。
        struct EnumContext
        {
            QVector<QStringList>* rows = nullptr;       // rows：输出行集合。
            const ksword::ark::Win32kWindowsResult* r0 = nullptr; // r0：用于补充 R0 状态。
            int limit = 512;                             // limit：避免桌面异常时无限扩张。
        };

        EnumContext context{ &rows, &result, 512 };
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                EnumContext* contextPointer = reinterpret_cast<EnumContext*>(lParam);
                if (contextPointer == nullptr || contextPointer->rows == nullptr)
                {
                    return FALSE;
                }
                if (contextPointer->rows->size() >= contextPointer->limit)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                DWORD sessionId = 0;
                ::ProcessIdToSessionId(processId, &sessionId);

                wchar_t titleBuffer[256] = {};
                wchar_t classBuffer[256] = {};
                ::GetWindowTextW(windowHandle, titleBuffer, static_cast<int>(_countof(titleBuffer)));
                ::GetClassNameW(windowHandle, classBuffer, static_cast<int>(_countof(classBuffer)));

                const LONG_PTR styleRaw = ::GetWindowLongPtrW(windowHandle, GWL_STYLE);
                const LONG_PTR exStyleRaw = ::GetWindowLongPtrW(windowHandle, GWL_EXSTYLE);
                const std::uint64_t styleValue = static_cast<std::uint64_t>(static_cast<ULONG_PTR>(styleRaw));
                const std::uint64_t exStyleValue = static_cast<std::uint64_t>(static_cast<ULONG_PTR>(exStyleRaw));
                contextPointer->rows->push_back(QStringList{
                    formatHwndText(windowHandle),
                    QString::number(processId),
                    QString::number(threadId),
                    QString::number(sessionId),
                    QString::fromWCharArray(titleBuffer).trimmed().isEmpty()
                        ? QStringLiteral("<无标题>")
                        : QString::fromWCharArray(titleBuffer).trimmed(),
                    QString::fromWCharArray(classBuffer).trimmed().isEmpty()
                        ? QStringLiteral("<无类名>")
                        : QString::fromWCharArray(classBuffer).trimmed(),
                    formatUInt64Hex(styleValue),
                    formatUInt64Hex(exStyleValue),
                    QStringLiteral("R3"),
                    formatNtStatusText(contextPointer->r0 != nullptr ? contextPointer->r0->lastStatus : 0),
                    formatHwndText(::GetParent(windowHandle)),
                    formatHwndText(::GetWindow(windowHandle, GW_OWNER)) });
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无窗口行>"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("<empty>"), QStringLiteral("<empty>"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), auditStateText(result),
                formatNtStatusText(result.lastStatus), QStringLiteral("N/A"), QStringLiteral("N/A") });
        }
        return rows;
    }

    QVector<QStringList> buildGuiThreadRows(const ksword::ark::Win32kGuiThreadsResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_GUI_THREAD_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                QString::number(entry.threadId),
                QString::number(entry.processId),
                QString::number(entry.sessionId),
                QString::number(entry.queueStatus),
                formatUInt64Hex(entry.activeHwnd),
                formatUInt64Hex(entry.focusHwnd),
                formatUInt64Hex(entry.captureHwnd),
                formatUInt64Hex(entry.caretHwnd),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - 输入：顶层窗口所属线程；
        // - 处理：按唯一 TID 调用 GetGUIThreadInfo，失败时仍写诊断行；
        // - 输出：GUI 线程表展示真实 TID/PID/session，而不是空白。
        struct ThreadContext
        {
            QVector<QStringList>* rows = nullptr;       // rows：输出行集合。
            QVector<DWORD> knownThreads;                // knownThreads：去重用 TID。
            const ksword::ark::Win32kGuiThreadsResult* r0 = nullptr; // r0：R0 状态。
            int limit = 512;                             // limit：最大线程行数。
        };

        ThreadContext context{ &rows, {}, &result, 512 };
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                ThreadContext* contextPointer = reinterpret_cast<ThreadContext*>(lParam);
                if (contextPointer == nullptr || contextPointer->rows == nullptr)
                {
                    return FALSE;
                }
                if (contextPointer->rows->size() >= contextPointer->limit)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                if (threadId == 0 ||
                    std::find(contextPointer->knownThreads.begin(), contextPointer->knownThreads.end(), threadId) != contextPointer->knownThreads.end())
                {
                    return TRUE;
                }
                contextPointer->knownThreads.push_back(threadId);

                DWORD sessionId = 0;
                ::ProcessIdToSessionId(processId, &sessionId);
                GUITHREADINFO guiThreadInfo{};
                guiThreadInfo.cbSize = sizeof(guiThreadInfo);
                const bool guiReady = ::GetGUIThreadInfo(threadId, &guiThreadInfo) != FALSE;
                const DWORD lastError = guiReady ? 0UL : ::GetLastError();
                contextPointer->rows->push_back(QStringList{
                    QString::number(threadId),
                    QString::number(processId),
                    QString::number(sessionId),
                    guiReady ? formatUInt64Hex(guiThreadInfo.flags) : QStringLiteral("N/A"),
                    guiReady ? formatHwndText(guiThreadInfo.hwndActive) : QStringLiteral("N/A"),
                    guiReady ? formatHwndText(guiThreadInfo.hwndFocus) : QStringLiteral("N/A"),
                    guiReady ? formatHwndText(guiThreadInfo.hwndCapture) : QStringLiteral("N/A"),
                    guiReady ? formatHwndText(guiThreadInfo.hwndCaret) : QStringLiteral("N/A"),
                    guiReady ? QStringLiteral("R3") : QStringLiteral("R3_FAIL"),
                    QStringLiteral("Win32=%1").arg(lastError) });
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无GUI线程行>"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), QStringLiteral("N/A"),
                QStringLiteral("N/A"), QStringLiteral("N/A"), auditStateText(result),
                formatNtStatusText(result.lastStatus) });
        }
        return rows;
    }

    QVector<QStringList> buildSessionRows(const ksword::ark::Win32kProfileStatusResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_SESSION_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                QString::number(entry.sessionId),
                win32kRuntimeStatusText(entry.status),
                QString::number(entry.processCount),
                QString::number(entry.guiThreadCount),
                formatUInt64Hex(entry.capabilityMask) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        // R3 fallback：
        // - 输入：当前桌面顶层窗口；
        // - 处理：统计唯一 PID/TID，给 session readiness 表提供本地上下文；
        // - 输出：根因诊断行，避免 R0 session 条目为空时表格空白。
        struct SessionContext
        {
            QVector<DWORD> processIds; // processIds：窗口所属进程去重集合。
            QVector<DWORD> threadIds;  // threadIds：窗口所属线程去重集合。
        };
        SessionContext context;
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                SessionContext* contextPointer = reinterpret_cast<SessionContext*>(lParam);
                if (contextPointer == nullptr)
                {
                    return FALSE;
                }

                DWORD processId = 0;
                const DWORD threadId = ::GetWindowThreadProcessId(windowHandle, &processId);
                if (processId != 0 &&
                    std::find(contextPointer->processIds.begin(), contextPointer->processIds.end(), processId) == contextPointer->processIds.end())
                {
                    contextPointer->processIds.push_back(processId);
                }
                if (threadId != 0 &&
                    std::find(contextPointer->threadIds.begin(), contextPointer->threadIds.end(), threadId) == contextPointer->threadIds.end())
                {
                    contextPointer->threadIds.push_back(threadId);
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&context));

        DWORD currentSessionId = 0;
        ::ProcessIdToSessionId(::GetCurrentProcessId(), &currentSessionId);
        rows.push_back(QStringList{
            QString::number(currentSessionId),
            auditStateText(result),
            QString::number(context.processIds.size()),
            QString::number(context.threadIds.size()),
            formatUInt64Hex(result.capabilityMask) });
        return rows;
    }

    QVector<QStringList> buildHotkeyRows(
        const ksword::ark::Win32kHotkeysPdbResult& result,
        const ksword::ark::KeyboardHotkeyEnumResult* const fallbackResult)
    {
        QVector<QStringList> rows;
        QHash<std::uint32_t, HotkeyProcessDisplayInfo> processInfoCache;
        const auto processInfoForPid = [&processInfoCache](const std::uint32_t processId) -> HotkeyProcessDisplayInfo
        {
            const auto cachedInfo = processInfoCache.constFind(processId);
            if (cachedInfo != processInfoCache.cend())
            {
                return cachedInfo.value();
            }
            const HotkeyProcessDisplayInfo displayInfo = queryHotkeyProcessDisplayInfo(processId);
            processInfoCache.insert(processId, displayInfo);
            return displayInfo;
        };

        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_HOTKEY_ENTRY& entry : result.entries)
        {
            const QString driverDetailText = readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("热键快照未提供额外驱动说明"));
            const HotkeyProcessDisplayInfo processInfo = processInfoForPid(entry.processId);

            rows.push_back(QStringList{
                processInfo.processName,
                processThreadDisplayText(entry.processId, entry.threadId),
                hotkeyDisplayText(entry.modifiers, entry.virtualKey),
                processInfo.imagePath,
                processInfo.description,
                formatUInt64Hex(entry.hotkeyObject),
                formatUInt64Hex(entry.hotkeyId),
                rawVirtualKeyText(entry.virtualKey),
                hotkeyModifierText(entry.modifiers),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                formatUInt64Hex(entry.hwnd),
                formatUInt64Hex(entry.nextHotkeyObject),
                formatUInt64Hex(entry.threadInfo),
                QString::number(entry.depth),
                keyboardSourceText(entry.source),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                QStringLiteral("flags=%1；tagWND=%2；desktop=%3；%4")
                    .arg(formatUInt64Hex(entry.flags))
                    .arg(formatUInt64Hex(entry.tagWnd))
                    .arg(formatUInt64Hex(entry.desktopObject))
                    .arg(driverDetailText) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        if (fallbackResult != nullptr && !fallbackResult->entries.empty())
        {
            rows.reserve(static_cast<int>(fallbackResult->entries.size()));
            for (const ksword::ark::KeyboardHotkeyEntry& entry : fallbackResult->entries)
            {
                const QString driverDetailText = readableDriverDetailText(
                    stdWideToQString(entry.detail),
                    QStringLiteral("键盘热键 fallback 未提供额外驱动说明"));
                const HotkeyProcessDisplayInfo processInfo = processInfoForPid(entry.processId);

                rows.push_back(QStringList{
                    processInfo.processName,
                    processThreadDisplayText(entry.processId, entry.threadId),
                    hotkeyDisplayText(entry.modifiers, entry.virtualKey),
                    processInfo.imagePath,
                    processInfo.description,
                    formatUInt64Hex(entry.hotkeyObject),
                    formatUInt64Hex(entry.hotkeyId),
                    rawVirtualKeyText(entry.virtualKey),
                    hotkeyModifierText(entry.modifiers),
                    QString::number(entry.processId),
                    QString::number(entry.threadId),
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.windowObject),
                    formatUInt64Hex(entry.nextHotkeyObject),
                    formatUInt64Hex(entry.threadInfo),
                    QString::number(entry.depth),
                    keyboardSourceText(entry.source),
                    QStringLiteral("KeyboardFallback(%1)").arg(entry.status),
                    formatNtStatusText(entry.lastStatus),
                    QStringLiteral("bucket=%1；threadObject=%2；flags=%3；%4；PDB=%5")
                        .arg(entry.bucketIndex)
                        .arg(formatUInt64Hex(entry.threadObject))
                        .arg(formatUInt64Hex(entry.flags))
                        .arg(driverDetailText)
                        .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result)) });
            }
            return rows;
        }

        // 空结果诊断：
        // - 状态列必须展示 profile/fallback 的真实根因，不能把 IOCTL header 成功误写成 ok；
        // - 明细列保留完整 wrapper 说明，方便判断是缺 win32k profile、pattern 未匹配还是会话不可用。
        const QString pdbStateText = win32kEmptyStateText(result);
        const QString fallbackStateText = fallbackResult != nullptr
            ? keyboardEmptyStateText(*fallbackResult)
            : QStringLiteral("keyboard-not-queried");
        const QString emptyDetailText = fallbackResult != nullptr
            ? QStringLiteral("PDB=%1；fallback=%2；解释：未枚举到结构化热键行不等于系统无热键，当前路径受 profile/字段映射或 keyboard fallback 模式匹配限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result))
                .arg(keyboardMessageText(QStringLiteral("enumerateKeyboardHotkeys"), *fallbackResult))
            : QStringLiteral("PDB=%1；fallback 未执行；解释：未枚举到结构化热键行不等于系统无热键，当前路径受 profile/字段映射限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHotkeysPdb"), result));
        QStringList emptyRow;
        emptyRow.reserve(HotkeyColumnCount);
        for (int column = 0; column < HotkeyColumnCount; ++column)
        {
            emptyRow.push_back(QStringLiteral("N/A"));
        }
        emptyRow[HotkeyColumnName] = QStringLiteral("<无热键行>");
        emptyRow[HotkeyColumnStatus] = QStringLiteral("%1 / %2").arg(pdbStateText).arg(fallbackStateText);
        emptyRow[HotkeyColumnLastStatus] = formatNtStatusText(result.lastStatus);
        emptyRow[HotkeyColumnDiagnostic] = emptyDetailText;
        rows.push_back(std::move(emptyRow));
        return rows;
    }

    QVector<QStringList> buildHookRows(
        const ksword::ark::Win32kHooksPdbResult& result,
        const ksword::ark::KeyboardHookEnumResult* const fallbackResult)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_WIN32K_HOOK_ENTRY& entry : result.entries)
        {
            const QString driverDetailText = readableDriverDetailText(
                wideArrayToQString(entry.detail, KSWORD_ARK_WIN32K_DETAIL_CHARS),
                QStringLiteral("Hook快照未提供额外驱动说明"));
            const QString moduleName = win32kAtomName(entry.moduleAtom);
            const QString moduleAtomText = entry.moduleAtom == 0U
                ? QString()
                : QStringLiteral("%1 (%2)")
                    .arg(formatUInt64Hex(entry.moduleAtom), moduleName);
            const QString processPath = entry.processId == 0U
                ? QString()
                : QString::fromStdString(ks::process::QueryProcessPathByPid(entry.processId));

            rows.push_back(QStringList{
                hookTypeText(entry.hookType),
                hookScopeText(entry.hookScope),
                QString::number(entry.processId),
                QString::number(entry.threadId),
                QString::number(entry.sessionId),
                entry.targetProcessId == 0U ? QString() : QString::number(entry.targetProcessId),
                entry.targetThreadId == 0U ? QString() : QString::number(entry.targetThreadId),
                entry.targetSessionId == 0U ? QString() : QString::number(entry.targetSessionId),
                formatUInt64Hex(entry.procedureAddress),
                formatUInt64Hex(entry.procedureOffset),
                QString::number(static_cast<std::int32_t>(entry.moduleId)),
                moduleAtomText,
                moduleName,
                processPath,
                formatUInt64Hex(entry.hookHandle),
                formatUInt64Hex(entry.hookObject),
                formatUInt64Hex(entry.chainHead),
                formatUInt64Hex(entry.nextHookObject),
                formatUInt64Hex(entry.threadInfo),
                formatUInt64Hex(entry.targetThreadInfo),
                formatUInt64Hex(entry.desktopObject),
                messageHookFlagsText(entry.flags),
                keyboardSourceText(entry.source),
                win32kRuntimeStatusText(entry.status),
                formatNtStatusText(entry.lastStatus),
                QStringLiteral("fieldFlags=%1; moduleBase=%2; layout=%3; profileFull=%4/%5; currentFull=%6/%7; %8")
                    .arg(formatUInt64Hex(entry.fieldFlags))
                    .arg(formatUInt64Hex(entry.moduleBase))
                    .arg(messageHookLayoutSourceText(result.layout.source))
                    .arg(formatUInt64Hex(result.layout.timeDateStamp))
                    .arg(formatUInt64Hex(result.layout.imageSize))
                    .arg(formatUInt64Hex(result.win32kfullTimeDateStamp))
                    .arg(formatUInt64Hex(result.win32kfullImageSize))
                    .arg(driverDetailText) });
        }

        if (!rows.isEmpty())
        {
            return rows;
        }

        if (fallbackResult != nullptr && !fallbackResult->entries.empty())
        {
            rows.reserve(static_cast<int>(fallbackResult->entries.size()));
            for (const ksword::ark::KeyboardHookEntry& entry : fallbackResult->entries)
            {
                const QString driverDetailText = readableDriverDetailText(
                    stdWideToQString(entry.detail),
                    QStringLiteral("键盘 Hook fallback 未提供额外驱动说明"));
                const QString processPath = entry.processId == 0U
                    ? QString()
                    : QString::fromStdString(ks::process::QueryProcessPathByPid(entry.processId));

                rows.push_back(QStringList{
                    hookTypeText(entry.hookType),
                    hookScopeText(entry.hookScope),
                    QString::number(entry.processId),
                    QString::number(entry.threadId),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.procedureAddress),
                    formatUInt64Hex(entry.procedureOffset),
                    QString::number(static_cast<std::int32_t>(entry.moduleId)),
                    QStringLiteral("N/A"),
                    QStringLiteral("N/A"),
                    processPath,
                    QStringLiteral("N/A"),
                    formatUInt64Hex(entry.hookObject),
                    formatUInt64Hex(entry.chainHead),
                    formatUInt64Hex(entry.nextHookObject),
                    formatUInt64Hex(entry.threadInfo),
                    formatUInt64Hex(entry.targetThreadInfo),
                    formatUInt64Hex(entry.desktopInfo),
                    messageHookFlagsText(entry.flags),
                    keyboardSourceText(entry.source),
                    QStringLiteral("KeyboardFallback(%1)").arg(entry.status),
                    formatNtStatusText(entry.lastStatus),
                    QStringLiteral("moduleId=%1；procedureOffset=%2；flags=%3；%4；PDB=%5")
                        .arg(entry.moduleId)
                        .arg(formatUInt64Hex(entry.procedureOffset))
                        .arg(formatUInt64Hex(entry.flags))
                        .arg(driverDetailText)
                        .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result)) });
            }
            return rows;
        }

        // 空结果诊断：
        // - Hook 链枚举依赖 win32k profile 或旧 keyboard fallback，二者任一受限都要在状态列直说；
        // - 这样用户复制表格时不会再看到“ok + 0 行”这种误导性组合。
        const QString pdbStateText = win32kEmptyStateText(result);
        const QString fallbackStateText = fallbackResult != nullptr
            ? keyboardEmptyStateText(*fallbackResult)
            : QStringLiteral("keyboard-not-queried");
        const QString emptyDetailText = fallbackResult != nullptr
            ? QStringLiteral("PDB=%1；fallback=%2；解释：未枚举到结构化 Hook 行不等于系统无 Hook，当前路径受 profile/字段映射、Session 或 fallback 模式匹配限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result))
                .arg(keyboardMessageText(QStringLiteral("enumerateKeyboardHooks"), *fallbackResult))
            : QStringLiteral("PDB=%1；fallback 未执行；解释：未枚举到结构化 Hook 行不等于系统无 Hook，当前路径受 profile/字段映射限制。")
                .arg(auditMessageText(QStringLiteral("queryWin32kHooksPdb"), result));
        QStringList emptyRow;
        for (int column = 0; column < 26; ++column)
        {
            emptyRow << QStringLiteral("N/A");
        }
        emptyRow[0] = QStringLiteral("<无消息Hook行>");
        emptyRow[23] = QStringLiteral("%1 / %2").arg(pdbStateText).arg(fallbackStateText);
        emptyRow[24] = formatNtStatusText(result.lastStatus);
        emptyRow[25] = emptyDetailText + QStringLiteral(" driver=") + stdWideToQString(result.detail);
        rows.push_back(emptyRow);
        return rows;
    }

    QVector<QStringList> buildDeviceRows(const ksword::ark::DeviceAuditResult& result)
    {
        QVector<QStringList> rows;
        rows.reserve(static_cast<int>(result.entries.size()));
        for (const KSWORD_ARK_DEVICE_AUDIT_ENTRY& entry : result.entries)
        {
            rows.push_back(QStringList{
                deviceAuditRowKindText(entry.rowKind),
                deviceAuditRoleText(entry.roleHint),
                deviceAuditStatusText(entry.status),
                formatUInt64Hex(entry.riskFlags),
                wideArrayToQString(entry.driverName, KSWORD_ARK_DEVICE_AUDIT_DRIVER_NAME_CHARS),
                wideArrayToQString(entry.deviceName, KSWORD_ARK_DEVICE_AUDIT_DEVICE_NAME_CHARS),
                formatUInt64Hex(entry.driverObjectAddress),
                formatUInt64Hex(entry.deviceObjectAddress),
                formatUInt64Hex(entry.attachedDeviceAddress),
                formatUInt64Hex(entry.nextDeviceObjectAddress),
                QString::number(entry.relationDepth),
                QString::number(entry.attachedDepth),
                QString::number(entry.confidence),
                formatUInt64Hex(entry.fieldFlags),
                formatNtStatusText(entry.lastStatus),
                wideArrayToQString(entry.serviceName, KSWORD_ARK_DEVICE_AUDIT_SERVICE_NAME_CHARS),
                wideArrayToQString(entry.imagePath, KSWORD_ARK_DEVICE_AUDIT_IMAGE_PATH_CHARS) });
        }
        if (rows.isEmpty())
        {
            rows.push_back(QStringList{
                QStringLiteral("<无设备行>"),
                QStringLiteral("N/A"),
                auditStateText(result),
                formatUInt64Hex(result.responseFlags),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                QStringLiteral("N/A"),
                formatNtStatusText(result.lastStatus),
                QStringLiteral("N/A"),
                QStringLiteral("N/A") });
        }
        return rows;
    }

    // queryUserObjectName 作用：
    // - 读取窗口站或桌面对象的名字；
    // - 失败时返回 <未知>，保持页面只读稳态。
    QString queryUserObjectName(HANDLE userObjectHandle)
    {
        if (userObjectHandle == nullptr)
        {
            return QStringLiteral("<未知>");
        }

        wchar_t buffer[256] = {};
        DWORD requiredSize = 0;
        if (::GetUserObjectInformationW(userObjectHandle, UOI_NAME, buffer, sizeof(buffer), &requiredSize) == FALSE)
        {
            return QStringLiteral("<未知>");
        }
        return QString::fromWCharArray(buffer).trimmed().isEmpty()
            ? QStringLiteral("<未知>")
            : QString::fromWCharArray(buffer).trimmed();
    }

    // countTopLevelWindows 作用：
    // - 统计桌面上的顶层窗口总数；
    // - 只读审计页用作窗口树粗粒度 cross-view 指标。
    int countTopLevelWindows()
    {
        int windowCount = 0;
        ::EnumWindows(
            [](HWND, LPARAM lParam) -> BOOL
            {
                int* countPointer = reinterpret_cast<int*>(lParam);
                if (countPointer != nullptr)
                {
                    ++(*countPointer);
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&windowCount));
        return windowCount;
    }

    // countCurrentProcessTopLevelWindows 作用：
    // - 统计当前进程拥有的顶层窗口数量；
    // - 用于窗口树/会话 cross-view 的本进程视角摘要。
    int countCurrentProcessTopLevelWindows()
    {
        int windowCount = 0;
        ::EnumWindows(
            [](HWND windowHandle, LPARAM lParam) -> BOOL
            {
                DWORD processId = 0;
                ::GetWindowThreadProcessId(windowHandle, &processId);
                if (processId == ::GetCurrentProcessId())
                {
                    int* countPointer = reinterpret_cast<int*>(lParam);
                    if (countPointer != nullptr)
                    {
                        ++(*countPointer);
                    }
                }
                return TRUE;
            },
            reinterpret_cast<LPARAM>(&windowCount));
        return windowCount;
    }

    // populateTable 作用：
    // - 把行模型写入 QTableWidget，单元格只读、保持排序开关；
    // - 输入 table：目标表格，rows：每行的列文本；
    // - 返回：无。
    void populateTable(QTableWidget* table, const QVector<QStringList>& rows)
    {
        if (table == nullptr)
        {
            return;
        }
        const bool wasSorting = table->isSortingEnabled();
        const bool usesTransparentBackground =
            table->property("ksword_transparent_audit_table").toBool();
        table->setSortingEnabled(false);
        table->setVisible(true);
        table->clearContents();
        applyAuditTablePalette(table);
        table->setRowCount(rows.size());
        bool hasProcessIconColumn = false;
        bool hasProcessPathColumn = false;
        const int processIconColumn = table->property("kswordProcessIconColumn").toInt(&hasProcessIconColumn);
        const int processPathColumn = table->property("kswordProcessPathColumn").toInt(&hasProcessPathColumn);
        static QFileIconProvider fileIconProvider;
        static QHash<QString, QIcon> processIconCache;
        for (int rowIndex = 0; rowIndex < rows.size(); ++rowIndex)
        {
            const QStringList& columns = rows.at(rowIndex);
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                const QString cellText = columnIndex < columns.size() ? columns.at(columnIndex) : QString();
                QTableWidgetItem* item = new QTableWidgetItem(cellText);
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                item->setToolTip(cellText);
                // 单元格前景/背景：
                // - 透明审计表不写入 item 背景刷，让每格穿透到父级 Tab 页；
                // - 其它审计表保留交替底色，保证独立页面的行可读性；
                // - item 仍由 QTableWidget 接管生命周期。
                item->setForeground(QBrush(KswordTheme::TextPrimaryColor()));
                if (!usesTransparentBackground)
                {
                    item->setBackground(QBrush(
                        (rowIndex % 2) == 0
                        ? KswordTheme::SurfaceColor()
                        : KswordTheme::SurfaceAltColor()));
                }
                if (hasProcessIconColumn &&
                    hasProcessPathColumn &&
                    columnIndex == processIconColumn &&
                    processPathColumn >= 0 &&
                    processPathColumn < columns.size() &&
                    !cellText.startsWith(QChar('<')) &&
                    cellText != QStringLiteral("N/A"))
                {
                    const QString imagePath = columns.at(processPathColumn).trimmed();
                    const QString cacheKey = QDir::fromNativeSeparators(imagePath).toLower();
                    QIcon processIcon = processIconCache.value(cacheKey);
                    if (processIcon.isNull() && QFileInfo::exists(imagePath))
                    {
                        processIcon = fileIconProvider.icon(QFileInfo(imagePath));
                    }
                    if (processIcon.isNull())
                    {
                        processIcon = QIcon(QStringLiteral(":/Icon/process_main.svg"));
                    }
                    processIconCache.insert(cacheKey, processIcon);
                    item->setIcon(processIcon);
                }
                table->setItem(rowIndex, columnIndex, item);
            }
        }
        table->setSortingEnabled(wasSorting);
        table->resizeRowsToContents();
        if (table->viewport() != nullptr)
        {
            table->viewport()->update();
        }
    }

    // buildPendingRows 作用：
    // - 为刷新中的表格生成一行占位诊断；
    // - 输入 table：目标表格，用于读取列数；primaryText：首列状态；detailText：末列说明；
    // - 返回：一行 QStringList，列数与表格一致，方便 populateTable 立即展示。
    QVector<QStringList> buildPendingRows(
        QTableWidget* table,
        const QString& primaryText,
        const QString& detailText)
    {
        const int columnCount = table != nullptr ? table->columnCount() : 0;
        if (columnCount <= 0)
        {
            return {};
        }

        QStringList row;
        row.reserve(columnCount);
        for (int columnIndex = 0; columnIndex < columnCount; ++columnIndex)
        {
            row.push_back(QStringLiteral("N/A"));
        }

        row[0] = primaryText;
        row[columnCount - 1] = detailText;
        return QVector<QStringList>{ row };
    }

    // ensureNonEmptyAuditRows 作用：
    // - 输入 table：目标表格，rows：即将写入的行模型，primaryText/detailText：兜底诊断；
    // - 处理：当后台/本地枚举路径意外产生空行模型时，补一行可读诊断；
    // - 返回：无，直接更新 rows，保证关键审计表不会以 rowCount=0 的空白形态显示。
    void ensureNonEmptyAuditRows(
        QTableWidget* table,
        QVector<QStringList>& rows,
        const QString& primaryText,
        const QString& detailText)
    {
        if (!rows.isEmpty())
        {
            return;
        }

        QVector<QStringList> fallbackRows = buildPendingRows(table, primaryText, detailText);
        if (!fallbackRows.isEmpty())
        {
            rows = std::move(fallbackRows);
        }
    }
}

WindowDock::WindowDock(QWidget* parent)
    : QWidget(parent)
{
    initializeUi();
    initializeConnections();

    // 初始状态：
    // - 窗口列表页由内嵌 OtherDock 保持原有行为；
    // - 本文件新增的 R0/R3 审计页默认不自动采集，等待用户点击“刷新审计”；
    // - 这样热键、Hook、GPU 等重型审计不会在切换窗口页时反复触发。
    const QString manualRefreshText =
        QStringLiteral("审计页默认不自动刷新；窗口列表保留原有刷新行为；点击顶部“刷新审计”后采集本页 R0/R3 审计数据。");
    m_cachedSessionSummary = ks::ui::FieldDocument{}.note(QStringLiteral("[win32k GUI/session]\n%1\n").arg(manualRefreshText));
    m_cachedHotkeyHookSummary = ks::ui::FieldDocument{}.note(QStringLiteral("[Hotkey / Hook]\n%1\n").arg(manualRefreshText));
    m_cachedDisplaySummary = ks::ui::FieldDocument{}.note(QStringLiteral("[GPU / Display / Watchdog]\n%1\n").arg(manualRefreshText));
    m_cachedWindowsRows = buildPendingRows(m_windowsTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    m_cachedGuiThreadRows = buildPendingRows(m_guiThreadsTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    if (m_windowsTable != nullptr)
    {
        m_windowsTable->setProperty("kswordSandboxPidColumn", 1);
        m_windowsTable->setProperty("ksword_process_detail_pid_column", 1);
    }
    if (m_guiThreadsTable != nullptr)
    {
        m_guiThreadsTable->setProperty("kswordSandboxPidColumn", 1);
        m_guiThreadsTable->setProperty("ksword_process_detail_pid_column", 1);
    }
    m_cachedSessionRows = buildPendingRows(m_sessionTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    m_cachedHotkeyRows = buildPendingRows(m_hotkeysTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    m_cachedHookRows = buildPendingRows(m_hooksTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    m_cachedClipboardRows = buildPendingRows(m_clipboardTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    m_cachedDeviceRows = buildPendingRows(m_deviceTable, QStringLiteral("<等待刷新>"), manualRefreshText);
    applyAuditViews();
    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("窗口列表可独立刷新；审计页等待手动刷新。"));
    }
}

WindowDock::~WindowDock()
{
}

void WindowDock::focusWindowsByPids(const QVector<quint32>& processIds)
{
    if (m_tabWidget != nullptr && m_windowManagementDock != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_windowManagementDock);
        m_windowManagementDock->focusProcessIds(processIds);
    }
}

void WindowDock::refreshThemeVisuals()
{
    // auditTables 用途：只包含 WindowDock 自己的审计表，避免覆盖内嵌 OtherDock 的表格策略。
    const QVector<QTableWidget*> auditTables = {
        m_windowsTable,
        m_guiThreadsTable,
        m_sessionTable,
        m_hotkeysTable,
        m_hooksTable,
        m_clipboardTable,
        m_deviceTable
    };

    for (QTableWidget* const table : auditTables)
    {
        if (table == nullptr)
        {
            continue;
        }

        // usesTransparentBackground 用途：主题刷新后保留原有背景穿透语义。
        const bool usesTransparentBackground =
            table->property("ksword_transparent_audit_table").toBool();
        table->setStyleSheet(
            usesTransparentBackground
                ? transparentAuditTableStyle()
                : auditTableStyle());
        applyAuditTablePalette(table);

        // 已存在的 item 保存了创建时的 QBrush，必须逐项更新，不能只依赖新 palette。
        for (int rowIndex = 0; rowIndex < table->rowCount(); ++rowIndex)
        {
            for (int columnIndex = 0; columnIndex < table->columnCount(); ++columnIndex)
            {
                QTableWidgetItem* const item = table->item(rowIndex, columnIndex);
                if (item == nullptr)
                {
                    continue;
                }

                item->setForeground(QBrush(KswordTheme::TextPrimaryColor()));
                item->setBackground(
                    usesTransparentBackground
                        ? QBrush()
                        : QBrush(
                            (rowIndex % 2) == 0
                                ? KswordTheme::SurfaceColor()
                                : KswordTheme::SurfaceAltColor()));
            }
        }
        if (table->viewport() != nullptr)
        {
            table->viewport()->update();
        }
        table->update();
    }

    // presetButtons 用途：刷新所有通过动态属性标识的 A/B 按钮，不改变其选中状态。
    const QList<QPushButton*> presetButtons = findChildren<QPushButton*>();
    for (QPushButton* const button : presetButtons)
    {
        if (button == nullptr
            || !button->property(kColumnPresetSelectedProperty).isValid())
        {
            continue;
        }
        button->setStyleSheet(
            buildColumnPresetButtonStyle(
                button->property(kColumnPresetSelectedProperty).toBool()));
    }

    if (m_queryWindowDetailButton != nullptr)
    {
        m_queryWindowDetailButton->setStyleSheet(ks::ui::BuildFlatButtonStyle() + QStringLiteral("QPushButton,QToolButton{border-radius:3px;padding:4px 10px;font-weight:600;}"));
    }
}

void WindowDock::showEvent(QShowEvent* showEventPointer)
{
    QWidget::showEvent(showEventPointer);
}

void WindowDock::initializeUi()
{
    m_rootLayout = new QVBoxLayout(this);
    m_rootLayout->setContentsMargins(4, 4, 4, 4);
    m_rootLayout->setSpacing(6);

    m_toolBarWidget = new QWidget(this);
    m_toolBarLayout = new QVBoxLayout(m_toolBarWidget);
    m_toolBarLayout->setContentsMargins(0, 0, 0, 0);
    m_toolBarLayout->setSpacing(4);

    QHBoxLayout* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);
    headerLayout->setSpacing(8);

    QLabel* titleLabel = new QLabel(QStringLiteral("窗口"), m_toolBarWidget);
    titleLabel->setStyleSheet(
        QStringLiteral("font-size:18px;font-weight:700;color:%1;")
        .arg(KswordTheme::TextPrimaryHex()));
    headerLayout->addWidget(titleLabel, 0);

    m_statusLabel = new QLabel(QStringLiteral("正在准备窗口审计快照..."), m_toolBarWidget);
    m_statusLabel->setWordWrap(true);
    m_statusLabel->setMinimumWidth(0);
    m_statusLabel->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    m_statusLabel->setStyleSheet(
        QStringLiteral("font-size:13px;color:%1;")
        .arg(KswordTheme::TextSecondaryHex()));
    headerLayout->addWidget(m_statusLabel, 1);

    m_refreshButton = new QPushButton(QStringLiteral("刷新审计"), m_toolBarWidget);
    m_refreshButton->setToolTip(QStringLiteral("重新采集 Win32K、热键/钩子与 GPU/Display/Watchdog 只读审计数据"));
    headerLayout->addWidget(m_refreshButton, 0);
    ks::ui::NormalizeToolbarControl(m_refreshButton);

    m_toolBarLayout->addLayout(headerLayout);
    m_rootLayout->addWidget(m_toolBarWidget, 0);

    m_tabWidget = new QTabWidget(this);
    // 窗口 Dock 的根子页统一放到顶部横排，保留所有现有页面和 currentIndex 状态源。
    m_tabWidget->setTabPosition(QTabWidget::North);
    ks::ui::StylePageTabs(m_tabWidget);
    m_rootLayout->addWidget(m_tabWidget, 1);

    // 配置只读结构化表格：可排序、行选择、内容自适应列宽、末列拉伸。
    const auto configureTable = [](QTableWidget* table)
    {
        // 表格可视性保护：
        // - WindowDock 被嵌入到 Dock/透明父容器时，默认 palette 可能被父级样式污染；
        // - 这里显式设置背景、文字、选中态和最小高度，保证有行模型时一定可读可见。
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setSelectionMode(QAbstractItemView::SingleSelection);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers);
        table->setAlternatingRowColors(true);
        table->setSortingEnabled(true);
        table->setWordWrap(false);
        table->setTextElideMode(Qt::ElideRight);
        table->setMinimumHeight(120);
        table->setStyleSheet(auditTableStyle());
        applyAuditTablePalette(table);
        table->verticalHeader()->setVisible(false);
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
        table->horizontalHeader()->setStretchLastSection(true);
        installTableCopyMenu(table);
    };

    // 创建“标题 + 表格”分组，便于在一个页面里堆叠多张表。
    const auto makeTableGroup =
        [this, &configureTable](
            const QString& title,
            const QStringList& headers,
            const QVector<int>& groupA,
            const QVector<int>& groupB,
            QTableWidget** tableOut) -> QWidget*
    {
        QWidget* group = new QWidget(m_tabWidget);
        QVBoxLayout* groupLayout = new QVBoxLayout(group);
        groupLayout->setContentsMargins(0, 0, 0, 0);
        groupLayout->setSpacing(3);

        QLabel* groupTitle = new QLabel(title, group);
        groupTitle->setStyleSheet(
            QStringLiteral("font-size:13px;font-weight:600;color:%1;")
            .arg(KswordTheme::TextSecondaryHex()));
        groupLayout->addWidget(groupTitle, 0);

        QHBoxLayout* presetLayout = new QHBoxLayout();
        presetLayout->setContentsMargins(0, 0, 0, 0);
        presetLayout->setSpacing(0);

        QPushButton* groupAButton = createColumnPresetButton(
            group,
            QStringLiteral("A"),
            QStringLiteral("显示 A 组精简列：偏向对象身份、状态和常用定位字段。"));
        QPushButton* groupBButton = createColumnPresetButton(
            group,
            QStringLiteral("B"),
            QStringLiteral("显示 B 组精简列：偏向地址、来源、flags、路径或诊断字段。"));
        presetLayout->addWidget(groupAButton, 0);
        presetLayout->addWidget(groupBButton, 0);
        presetLayout->addStretch(1);
        // A/B 为同一个分段选择器，保留紧贴关系。
        ks::ui::NormalizeToolbarRow(presetLayout, 0);
        groupLayout->addLayout(presetLayout, 0);

        QTableWidget* table = new ks::ui::VisibleTableWidget(group);
        table->setColumnCount(headers.size());
        table->setHorizontalHeaderLabels(headers);
        configureTable(table);
        installColumnPresetControls(table, groupAButton, groupBButton, groupA, groupB);
        groupLayout->addWidget(table, 1);

        if (tableOut != nullptr)
        {
            *tableOut = table;
        }
        return group;
    };

    // 只读摘要编辑器：仅承载非表格的上下文说明。
    // 现在摘要与表格会被放入内层页签，不再限制最大高度，避免文本框被压扁。
    const auto makeSummaryEditor = [this](QWidget* parentWidget) -> ks::ui::StructuredFieldView*
    {
        ks::ui::StructuredFieldView* editor = new ks::ui::StructuredFieldView(parentWidget);
        editor->setMinimumHeight(180);
        return editor;
    };

    // 页面公共头：标题 + “只读审计页”提示。
    const auto makePageHeader = [this](QWidget* pageWidget, QVBoxLayout* pageLayout, const QString& titleText)
    {
        QLabel* pageTitleLabel = new QLabel(titleText, pageWidget);
        pageTitleLabel->setStyleSheet(
            QStringLiteral("font-size:18px;font-weight:700;color:%1;")
            .arg(KswordTheme::TextPrimaryHex()));
        pageLayout->addWidget(pageTitleLabel, 0);
    };

    // makeInnerTabWidget 作用：
    // - 输入 parentWidget：当前外层审计页；
    // - 处理：创建一个紧凑的内部页签容器，把每个表格/文本框拆到独立页签；
    // - 返回：可直接 addTab 的 QTabWidget，避免多个大控件纵向堆叠后被压缩到不可见。
    const auto makeInnerTabWidget = [](QWidget* parentWidget) -> QTabWidget*
    {
        QTabWidget* innerTabWidget = new QTabWidget(parentWidget);
        innerTabWidget->setTabPosition(QTabWidget::North);
        innerTabWidget->setDocumentMode(true);
        innerTabWidget->setUsesScrollButtons(true);
        ks::ui::StylePageTabs(innerTabWidget);
        return innerTabWidget;
    };

    // makeEditorTabPage 作用：
    // - 输入 innerTabWidget：内部页签容器；
    // - 处理：创建只承载一个文本编辑器的页，保证文本详情不与表格争抢高度；
    // - 返回：文本页 QWidget，editorOut 返回创建出的编辑器指针。
    const auto makeEditorTabPage =
        [this, &makeSummaryEditor](QTabWidget* innerTabWidget, ks::ui::StructuredFieldView** editorOut) -> QWidget*
    {
        QWidget* editorPage = new QWidget(innerTabWidget);
        QVBoxLayout* editorLayout = new QVBoxLayout(editorPage);
        editorLayout->setContentsMargins(4, 4, 4, 4);
        editorLayout->setSpacing(4);

        ks::ui::StructuredFieldView* editor = makeSummaryEditor(editorPage);
        editorLayout->addWidget(editor, 1);
        if (editorOut != nullptr)
        {
            *editorOut = editor;
        }
        return editorPage;
    };

    // ===== Tab 1：窗口管理（内嵌 OtherDock，恢复窗口列表 / 桌面详细视图）=====
    m_windowManagementDock = new OtherDock(m_tabWidget);
    const int windowManagementTabIndex =
        m_tabWidget->addTab(m_windowManagementDock, QStringLiteral("窗口列表 / 桌面"));
    m_tabWidget->setTabToolTip(
        windowManagementTabIndex,
        QStringLiteral("原窗口列表与桌面管理入口在这里：包含窗口树、窗口详情、窗口站/桌面枚举和桌面切换。"));

    const int guiHandleTabIndex = m_tabWidget->addTab(
        new WindowGuiHandleTab(m_tabWidget),
        QStringLiteral("GUI句柄"));
    m_tabWidget->setTabToolTip(
        guiHandleTabIndex,
        QStringLiteral("只读枚举当前 Session 的 USER Handle 共享表，显示对象类型、地址与窗口所有者信息。"));

    const int timerTabIndex = m_tabWidget->addTab(
        new WindowTimerTab(m_tabWidget),
        ks::i18n::contextText(QStringLiteral("window.timer.tab"), QStringLiteral("窗口定时器")));
    m_tabWidget->setTabToolTip(
        timerTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.timer.tab.tooltip"),
            QStringLiteral("只读遍历 win32k gTimerHashTable，显示定时器对象、间隔、Flags、回调和 PID/TID 归属。")));

    const int globalHotkeyTabIndex = m_tabWidget->addTab(
        new WindowGlobalHotkeyTab(m_tabWidget),
        ks::i18n::contextText(QStringLiteral("window.global_hotkey.tab"), QStringLiteral("全部热键")));
    m_tabWidget->setTabToolTip(
        globalHotkeyTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.global_hotkey.tab.tooltip"),
            QStringLiteral("只读汇总全部进程的窗口热键、菜单快捷键、PE Accelerator 和快捷方式热键。")));

    const int eventHookTabIndex = m_tabWidget->addTab(
        new WindowEventHookTab(m_tabWidget),
        ks::i18n::contextText(QStringLiteral("window.event_hook.tab"), QStringLiteral("事件 Hook")));
    m_tabWidget->setTabToolTip(
        eventHookTabIndex,
        ks::i18n::contextText(
            QStringLiteral("window.event_hook.tab.tooltip"),
            QStringLiteral("只读遍历 win32kbase!gpWinEventHooks，显示事件范围、Flags、回调和 PID/TID 归属。")));

    // ===== Tab 2：win32k GUI / Session =====
    m_sessionPage = new QWidget(m_tabWidget);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(m_sessionPage);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        makePageHeader(m_sessionPage, pageLayout, QStringLiteral("win32k GUI / Session"));

        QTabWidget* innerTabWidget = makeInnerTabWidget(m_sessionPage);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            makeEditorTabPage(innerTabWidget, &m_sessionSummaryEditor),
            QStringLiteral("摘要"));

        innerTabWidget->addTab(makeTableGroup(
            QStringLiteral("Win32K 窗口（HWND / tagWND cross-view，全部行）"),
            QStringList{ QStringLiteral("HWND"), QStringLiteral("PID"), QStringLiteral("TID"),
                         QStringLiteral("Session"), QStringLiteral("标题"), QStringLiteral("类名"),
                         QStringLiteral("Style"), QStringLiteral("ExStyle"), QStringLiteral("状态"),
                         QStringLiteral("LastStatus"), QStringLiteral("父HWND"), QStringLiteral("所有者") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 8 },
            QVector<int>{ 0, 1, 6, 7, 9, 10, 11 },
            &m_windowsTable),
            QStringLiteral("窗口表"));
        applyTransparentAuditTableBackground(m_windowsTable);
        ks::ui::SetTableActionBarMode(m_windowsTable, ks::ui::TableActionBarMode::Full);
        innerTabWidget->addTab(makeTableGroup(
            QStringLiteral("GUI 线程（tagQ / focus / capture / caret）"),
            QStringList{ QStringLiteral("TID"), QStringLiteral("PID"), QStringLiteral("Session"),
                         QStringLiteral("队列状态"), QStringLiteral("ActiveHWND"), QStringLiteral("FocusHWND"),
                         QStringLiteral("CaptureHWND"), QStringLiteral("CaretHWND"), QStringLiteral("状态"),
                         QStringLiteral("LastStatus") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 8 },
            QVector<int>{ 0, 1, 6, 7, 8, 9 },
            &m_guiThreadsTable),
            QStringLiteral("GUI线程"));
        applyTransparentAuditTableBackground(m_guiThreadsTable);
        ks::ui::SetTableActionBarMode(m_guiThreadsTable, ks::ui::TableActionBarMode::Full);
        innerTabWidget->addTab(makeTableGroup(
            QStringLiteral("Session 就绪状态"),
            QStringList{ QStringLiteral("SessionId"), QStringLiteral("状态"), QStringLiteral("进程数"),
                         QStringLiteral("GUI线程数"), QStringLiteral("Capability") },
            QVector<int>{ 0, 1, 2, 3 },
            QVector<int>{ 0, 1, 4 },
            &m_sessionTable),
            QStringLiteral("Session"));
        applyTransparentAuditTableBackground(m_sessionTable);
        // Session 就绪概要是少量诊断行，紧凑复制/导出足够。
        ks::ui::SetTableActionBarMode(m_sessionTable, ks::ui::TableActionBarMode::Compact);

        // 当前窗口详情：
        // - 默认只展示窗口表可见列快照，帮助用户确认当前选中 HWND；
        // - 点击按钮后才调用单 HWND detail IOCTL，避免批量刷新时逐窗口阻塞。
        QWidget* detailPage = new QWidget(innerTabWidget);
        QVBoxLayout* detailPageLayout = new QVBoxLayout(detailPage);
        detailPageLayout->setContentsMargins(4, 4, 4, 4);
        detailPageLayout->setSpacing(6);
        QHBoxLayout* detailToolLayout = new QHBoxLayout();
        detailToolLayout->setContentsMargins(0, 0, 0, 0);
        detailToolLayout->setSpacing(6);
        m_queryWindowDetailButton = new QPushButton(QIcon(QStringLiteral(":/Icon/process_tree.svg")), QStringLiteral("查询选中窗口详情"), detailPage);
        m_queryWindowDetailButton->setToolTip(QStringLiteral("只对当前选中 HWND 按需查询 win32k window detail，不批量扫描全部窗口"));
        detailToolLayout->addWidget(m_queryWindowDetailButton, 0);
        QLabel* detailHintLabel = new QLabel(QStringLiteral("详情区：先显示快照，按需补充单 HWND runtime readiness/tagWND 诊断。"), detailPage);
        detailHintLabel->setStyleSheet(
            QStringLiteral("font-size:13px;color:%1;")
            .arg(KswordTheme::TextSecondaryHex()));
        detailToolLayout->addWidget(detailHintLabel, 1);
        ks::ui::NormalizeToolbarRow(detailToolLayout);
        detailPageLayout->addLayout(detailToolLayout);

        m_windowDetailEditor = new ks::ui::StructuredFieldView(detailPage);
        m_windowDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择 Win32K 窗口行查看快照；需要更深诊断时点击“查询选中窗口详情”。")));
        detailPageLayout->addWidget(m_windowDetailEditor, 1);
        innerTabWidget->addTab(detailPage, QStringLiteral("窗口详情"));
    }
    m_tabWidget->addTab(m_sessionPage, QStringLiteral("GUI/Session"));

    // ===== Tab 3：热键 / 钩子 =====
    m_hotkeyHookPage = new QWidget(m_tabWidget);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(m_hotkeyHookPage);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        makePageHeader(m_hotkeyHookPage, pageLayout, QStringLiteral("Hotkey / Hook"));

        QTabWidget* innerTabWidget = makeInnerTabWidget(m_hotkeyHookPage);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            makeEditorTabPage(innerTabWidget, &m_hotkeyHookSummaryEditor),
            QStringLiteral("摘要"));

        innerTabWidget->addTab(makeTableGroup(
            QStringLiteral("热键（只读审计，不删除热键）"),
            QStringList{ QStringLiteral("名称"), QStringLiteral("进程ID.线程ID"), QStringLiteral("热键"),
                         QStringLiteral("路径"), QStringLiteral("描述"), QStringLiteral("热键对象地址"),
                         QStringLiteral("热键ID"), QStringLiteral("VK"), QStringLiteral("修饰键"),
                         QStringLiteral("PID"), QStringLiteral("TID"), QStringLiteral("Session"),
                         QStringLiteral("HWND"),
                         QStringLiteral("NextHotkey"), QStringLiteral("ThreadInfo"),
                         QStringLiteral("Depth"), QStringLiteral("Source"),
                         QStringLiteral("状态"), QStringLiteral("LastStatus"),
                         QStringLiteral("诊断") },
            QVector<int>{ HotkeyColumnName, HotkeyColumnProcessThread, HotkeyColumnDisplay,
                          HotkeyColumnPath, HotkeyColumnDescription, HotkeyColumnObject, HotkeyColumnId },
            QVector<int>{ HotkeyColumnName, HotkeyColumnVirtualKey, HotkeyColumnModifiers,
                          HotkeyColumnProcessId, HotkeyColumnThreadId, HotkeyColumnSession,
                          HotkeyColumnHwnd, HotkeyColumnNext, HotkeyColumnThreadInfo,
                          HotkeyColumnDepth, HotkeyColumnSource, HotkeyColumnStatus,
                          HotkeyColumnLastStatus, HotkeyColumnDiagnostic },
            &m_hotkeysTable),
            QStringLiteral("热键表"));
        applyTransparentAuditTableBackground(m_hotkeysTable);
        ks::ui::SetTableActionBarMode(m_hotkeysTable, ks::ui::TableActionBarMode::Full);
        if (m_hotkeysTable != nullptr)
        {
            m_hotkeysTable->setProperty("kswordProcessIconColumn", HotkeyColumnName);
            m_hotkeysTable->setProperty("kswordProcessPathColumn", HotkeyColumnPath);
            m_hotkeysTable->setProperty("ksword_process_detail_pid_column", HotkeyColumnProcessId);
            m_hotkeysTable->setIconSize(QSize(16, 16));
        }
        innerTabWidget->addTab(makeTableGroup(
            QStringLiteral("消息 Hook（只读审计，不 remove/unlink hook 链）"),
            QStringList{ QStringLiteral("类型"), QStringLiteral("范围"), QStringLiteral("所有者 PID"),
                         QStringLiteral("所有者 TID"), QStringLiteral("Session"), QStringLiteral("目标 PID"),
                         QStringLiteral("目标 TID"), QStringLiteral("目标 Session"), QStringLiteral("Procedure"),
                         QStringLiteral("ProcedureOffset"), QStringLiteral("ModuleId"), QStringLiteral("ModuleAtom"),
                         QStringLiteral("模块名"), QStringLiteral("进程路径"), QStringLiteral("HookHandle"),
                         QStringLiteral("HookObject"), QStringLiteral("ChainHead"), QStringLiteral("NextHook"),
                         QStringLiteral("OwnerThreadInfo"), QStringLiteral("TargetThreadInfo"),
                         QStringLiteral("Desktop"), QStringLiteral("Flags"), QStringLiteral("Source"),
                         QStringLiteral("状态"), QStringLiteral("LastStatus"), QStringLiteral("诊断") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 6, 8, 12, 14, 15, 23 },
            QVector<int>{ 0, 8, 9, 11, 13, 15, 16, 17, 18, 19, 21, 25 },
            &m_hooksTable),
            QStringLiteral("消息 Hook 表"));
        applyTransparentAuditTableBackground(m_hooksTable);
        ks::ui::SetTableActionBarMode(m_hooksTable, ks::ui::TableActionBarMode::Full);
        if (m_hooksTable != nullptr)
        {
            m_hooksTable->setProperty("ksword_process_detail_pid_column", 2);
        }
    }
    m_tabWidget->addTab(m_hotkeyHookPage, QStringLiteral("热键/钩子"));

    // ===== Tab 4：剪贴板 / Message-Only =====
    m_clipboardPage = new QWidget(m_tabWidget);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(m_clipboardPage);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        makePageHeader(m_clipboardPage, pageLayout, QStringLiteral("Clipboard / Message-Only"));

        QTabWidget* innerTabWidget = makeInnerTabWidget(m_clipboardPage);
        pageLayout->addWidget(innerTabWidget, 1);

        QWidget* group = makeTableGroup(
            QStringLiteral("剪贴板上下文（只读，不做消息抓取）"),
            QStringList{ QStringLiteral("属性"), QStringLiteral("值") },
            QVector<int>{ 0, 1 },
            QVector<int>{ 0, 1 },
            &m_clipboardTable);
        applyTransparentAuditTableBackground(m_clipboardTable);
        // 剪贴板是键值上下文，无须通用快照栏占用属性区。
        ks::ui::SetTableActionBarMode(m_clipboardTable, ks::ui::TableActionBarMode::None);
        innerTabWidget->addTab(group, QStringLiteral("剪贴板表"));
    }
    m_tabWidget->addTab(m_clipboardPage, QStringLiteral("剪贴板"));

    // ===== Tab 5：GPU / Display / Watchdog =====
    m_displayPage = new QWidget(m_tabWidget);
    {
        QVBoxLayout* pageLayout = new QVBoxLayout(m_displayPage);
        pageLayout->setContentsMargins(4, 4, 4, 4);
        pageLayout->setSpacing(6);
        makePageHeader(m_displayPage, pageLayout, QStringLiteral("GPU / Display / Watchdog"));

        QTabWidget* innerTabWidget = makeInnerTabWidget(m_displayPage);
        pageLayout->addWidget(innerTabWidget, 1);

        innerTabWidget->addTab(
            makeEditorTabPage(innerTabWidget, &m_displaySummaryEditor),
            QStringLiteral("摘要"));

        QWidget* group = makeTableGroup(
            QStringLiteral("设备审计（不禁用设备 / 不卸载驱动 / 不 detach stack，全部行）"),
            QStringList{ QStringLiteral("种类"), QStringLiteral("角色"), QStringLiteral("状态"),
                         QStringLiteral("风险"), QStringLiteral("驱动名"), QStringLiteral("设备名"),
                         QStringLiteral("DriverObject"), QStringLiteral("DeviceObject"),
                         QStringLiteral("AttachedDevice"), QStringLiteral("NextDevice"),
                         QStringLiteral("RelationDepth"), QStringLiteral("AttachedDepth"),
                         QStringLiteral("Confidence"), QStringLiteral("FieldFlags"),
                         QStringLiteral("LastStatus"), QStringLiteral("Service"),
                         QStringLiteral("ImagePath") },
            QVector<int>{ 0, 1, 2, 3, 4, 5, 10, 11 },
            QVector<int>{ 0, 2, 6, 7, 8, 9, 14, 16 },
            &m_deviceTable);
        applyTransparentAuditTableBackground(m_deviceTable);
        ks::ui::SetTableActionBarMode(m_deviceTable, ks::ui::TableActionBarMode::Full);
        innerTabWidget->addTab(group, QStringLiteral("设备表"));
    }
    m_tabWidget->addTab(m_displayPage, QStringLiteral("显示"));
}

void WindowDock::initializeConnections()
{
    if (m_refreshButton != nullptr)
    {
        connect(m_refreshButton, &QPushButton::clicked, this, [this]()
        {
            requestAsyncRefresh();
        });
    }
    if (m_queryWindowDetailButton != nullptr)
    {
        connect(m_queryWindowDetailButton, &QPushButton::clicked, this, [this]()
        {
            requestSelectedWindowRuntimeDetail();
        });
    }
    if (m_windowsTable != nullptr)
    {
        connect(m_windowsTable, &QTableWidget::currentCellChanged, this, [this](int currentRow, int, int, int)
        {
            updateSelectedWindowSnapshotDetail(currentRow);
        });
    }
}

void WindowDock::setRefreshingPlaceholderRows()
{
    // 这些即时行只说明当前正在采集，不替代后续真实 R0/R3 行。
    // 目的：避免后台查询期间，GUI/Session 与热键/钩子页出现完全空表。
    // 处理：窗口/GUI线程/Session 先用本地 Win32 只读枚举生成具体行，
    //       热键/Hook 暂无纯 R3 安全枚举路径时至少生成明确诊断行。
    const QString pendingDetailText = QStringLiteral("正在收集窗口信息，请稍候...");

    ksword::ark::Win32kWindowsResult localWindowsResult;
    localWindowsResult.io.message = "R0 refresh is pending; showing local EnumWindows fallback rows.";

    ksword::ark::Win32kGuiThreadsResult localGuiThreadsResult;
    localGuiThreadsResult.io.message = "R0 refresh is pending; showing local GetGUIThreadInfo fallback rows.";

    ksword::ark::Win32kProfileStatusResult localProfileResult;
    localProfileResult.io.message = "R0 refresh is pending; showing local session fallback row.";

    ksword::ark::Win32kHotkeysPdbResult pendingHotkeyResult;
    pendingHotkeyResult.io.message = "R0 hotkey snapshot is still refreshing; no pure R3 system hotkey table is available.";

    ksword::ark::Win32kHooksPdbResult pendingHookResult;
    pendingHookResult.io.message = "R0 hook snapshot is still refreshing; no pure R3 global hook chain is available.";

    m_cachedSessionSummary =
        ks::ui::FieldDocument{}.note(QStringLiteral("[win32k GUI/session]\n正在刷新结构化窗口、GUI线程和Session审计行...\n"));
    m_cachedHotkeyHookSummary =
        ks::ui::FieldDocument{}.note(QStringLiteral("[Hotkey / Hook]\n正在刷新热键与Hook只读审计行...\n"));
    m_cachedDisplaySummary =
        ks::ui::FieldDocument{}.note(QStringLiteral("[GPU / Display / Watchdog]\n正在刷新显示设备只读审计行...\n"));

    m_cachedWindowsRows = buildWindowsRows(localWindowsResult);
    m_cachedGuiThreadRows = buildGuiThreadRows(localGuiThreadsResult);
    m_cachedSessionRows = buildSessionRows(localProfileResult);
    m_cachedHotkeyRows = buildHotkeyRows(pendingHotkeyResult, nullptr);
    m_cachedHookRows = buildHookRows(pendingHookResult, nullptr);
    m_cachedClipboardRows = buildPendingRows(
        m_clipboardTable,
        QStringLiteral("<采集中>"),
        QStringLiteral("正在读取 UI 线程剪贴板快照。"));
    m_cachedDeviceRows = buildPendingRows(
        m_deviceTable,
        QStringLiteral("<采集中>"),
        pendingDetailText);

    applyAuditViews();
}

void WindowDock::requestAsyncRefresh()
{
    // 一轮窗口审计会同步替换七张关联表；任一表格菜单打开时，启动阶段的
    // 占位缓存和七表提交都必须作为一个整体延后。
    const QPointer<WindowDock> deferredGuard(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this,
        QStringLiteral("window-audit-refresh-start"),
        {
            m_windowsTable,
            m_guiThreadsTable,
            m_sessionTable,
            m_hotkeysTable,
            m_hooksTable,
            m_clipboardTable,
            m_deviceTable
        },
        [deferredGuard]()
        {
            if (!deferredGuard.isNull())
            {
                deferredGuard->requestAsyncRefresh();
            }
        }))
    {
        return;
    }

    bool expectedFlag = false;
    if (!m_refreshing.compare_exchange_strong(expectedFlag, true))
    {
        return;
    }

    if (m_statusLabel != nullptr)
    {
        m_statusLabel->setText(QStringLiteral("正在采集窗口审计快照..."));
    }
    setRefreshingPlaceholderRows();

    // UI线程快照：
    // - 输入：当前 Qt GUI 线程可安全访问的剪贴板与屏幕对象；
    // - 处理：在启动后台线程之前复制成普通值；
    // - 返回：后台线程只消费这些快照，避免构造期/刷新期 BlockingQueuedConnection 卡住。
    const QVector<QStringList> clipboardSnapshot =
        clipboardSnapshotRows(QApplication::clipboard());

    QString primaryScreenName = QStringLiteral("<无>");
    QRect primaryScreenGeometry;
    double primaryScreenDpi = 0.0;
    const QScreen* primaryScreen = QGuiApplication::primaryScreen();
    if (primaryScreen != nullptr)
    {
        primaryScreenName = primaryScreen->name();
        primaryScreenGeometry = primaryScreen->geometry();
        primaryScreenDpi = primaryScreen->logicalDotsPerInch();
    }

    QPointer<WindowDock> safeThis(this);
    std::thread([safeThis, clipboardSnapshot, primaryScreenName, primaryScreenGeometry, primaryScreenDpi]()
    {
        // reportRefreshFailure 作用：
        // - 输入 failureText：后台线程捕获到的异常或失败描述；
        // - 处理：通过 queued connection 回到 UI 线程写入可读诊断行；
        // - 返回：无，但一定释放 m_refreshing，避免一次异常后刷新按钮永久失效。
        const auto reportRefreshFailure = [safeThis](const QString& failureText)
        {
            if (safeThis.isNull())
            {
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, failureText]()
                {
                    const auto commitFailure = [safeThis, failureText]()
                    {
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    const ks::ui::FieldDocument summaryText = ks::ui::FieldDocument{}.note(QStringLiteral(
                        "[Window audit refresh]\n"
                        "后台刷新异常，已保留/写入诊断行，用户可再次点击刷新。\n"
                        "原因: %1\n").arg(failureText));

                    safeThis->m_cachedSessionSummary = summaryText;
                    safeThis->m_cachedHotkeyHookSummary = summaryText;
                    safeThis->m_cachedDisplaySummary = summaryText;
                    safeThis->m_cachedWindowsRows = buildPendingRows(
                        safeThis->m_windowsTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedGuiThreadRows = buildPendingRows(
                        safeThis->m_guiThreadsTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedSessionRows = buildPendingRows(
                        safeThis->m_sessionTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedHotkeyRows = buildPendingRows(
                        safeThis->m_hotkeysTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedHookRows = buildPendingRows(
                        safeThis->m_hooksTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedClipboardRows = buildPendingRows(
                        safeThis->m_clipboardTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->m_cachedDeviceRows = buildPendingRows(
                        safeThis->m_deviceTable,
                        QStringLiteral("<刷新异常>"),
                        failureText);
                    safeThis->applyAuditViews();
                    kLogEvent failureEvent;
                    warn << failureEvent
                        << "[WindowDock] audit refresh failed, detail="
                        << failureText.toStdString()
                        << eol;
                    if (safeThis->m_statusLabel != nullptr)
                    {
                        safeThis->m_statusLabel->setText(QStringLiteral(
                            "窗口审计刷新异常；详情已写入日志。"));
                    }
                    safeThis->m_refreshing.store(false);
                    };

                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        safeThis.data(),
                        QStringLiteral("window-audit-failure-apply"),
                        {
                            safeThis->m_windowsTable,
                            safeThis->m_guiThreadsTable,
                            safeThis->m_sessionTable,
                            safeThis->m_hotkeysTable,
                            safeThis->m_hooksTable,
                            safeThis->m_clipboardTable,
                            safeThis->m_deviceTable
                        },
                        commitFailure))
                    {
                        return;
                    }
                    commitFailure();
                },
                Qt::QueuedConnection);

            if (!invokeOk && !safeThis.isNull())
            {
                safeThis->m_refreshing.store(false);
            }
        };

        try
        {
            // ArkDriverClient 只读 wrapper：
            // - 作用：统一通过 R3 client 访问 R0 PDB 审计结果；
            // - 处理：在后台线程顺序采集，避免阻塞 UI；
            // - 返回：各 result 只用于文本/表格展示，不触发任何写入动作。
            const ksword::ark::DriverClient arkDriverClient;
            const ksword::ark::Win32kProfileStatusResult win32kProfileResult =
                arkDriverClient.queryWin32kProfileStatus();
            const ksword::ark::Win32kWindowsResult win32kWindowsResult =
                arkDriverClient.queryWin32kWindows();
            const ksword::ark::Win32kGuiThreadsResult win32kGuiThreadsResult =
                arkDriverClient.queryWin32kGuiThreads();
            const ksword::ark::Win32kHotkeysPdbResult win32kHotkeysResult =
                arkDriverClient.queryWin32kHotkeysPdb();
            const ksword::ark::Win32kHooksPdbResult win32kHooksResult =
                arkDriverClient.queryWin32kHooksPdb();
            ksword::ark::KeyboardHotkeyEnumResult keyboardHotkeysFallbackResult{};
            ksword::ark::KeyboardHookEnumResult keyboardHooksFallbackResult{};
            bool keyboardHotkeysFallbackQueried = false;
            bool keyboardHooksFallbackQueried = false;
            if (win32kHotkeysResult.entries.empty())
            {
                keyboardHotkeysFallbackQueried = true;
                keyboardHotkeysFallbackResult = arkDriverClient.enumerateKeyboardHotkeys();
            }
            if (win32kHooksResult.entries.empty())
            {
                keyboardHooksFallbackQueried = true;
                keyboardHooksFallbackResult = arkDriverClient.enumerateKeyboardHooks();
            }
            const ksword::ark::DeviceAuditResult gpuAuditResult =
                arkDriverClient.queryGpuDisplayWatchdogAudit();

            // 会话页摘要：本地 session/窗口站/桌面 + R0 profile/module 概要（逐行 session 交给表格）。
            ks::ui::FieldDocument sessionSummary;
            {
                GUITHREADINFO guiThreadInfo{};
                guiThreadInfo.cbSize = sizeof(guiThreadInfo);
                const bool guiInfoReady = ::GetGUIThreadInfo(::GetCurrentThreadId(), &guiThreadInfo) != FALSE;

                sessionSummary.section(QStringLiteral("win32k GUI/session"));
                DWORD sessionId = 0;
                ::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionId);
                sessionSummary.field(QStringLiteral("SessionId"), QStringLiteral("%1").arg(sessionId));
                sessionSummary.field(QStringLiteral("LogicalProcessorCount"), QStringLiteral("%1").arg(::GetActiveProcessorCount(ALL_PROCESSOR_GROUPS)));
                sessionSummary.field(QStringLiteral("ForegroundWindow"), QStringLiteral("%1").arg(formatHwndText(::GetForegroundWindow())));
                sessionSummary.field(QStringLiteral("ActiveWindow"), QStringLiteral("%1").arg(formatHwndText(::GetActiveWindow())));
                sessionSummary.field(QStringLiteral("DesktopWindow"), QStringLiteral("%1").arg(formatHwndText(::GetDesktopWindow())));
                sessionSummary.field(QStringLiteral("TopLevelWindowCount"), QStringLiteral("%1").arg(countTopLevelWindows()));
                sessionSummary.field(QStringLiteral("CurrentProcessTopLevelWindowCount"), QStringLiteral("%1").arg(countCurrentProcessTopLevelWindows()));
                sessionSummary.field(QStringLiteral("GUIThreadInfoReady"), QStringLiteral("%1").arg(boolText(guiInfoReady)));
                if (guiInfoReady)
                {
                    sessionSummary.field(QStringLiteral("Focus"), QStringLiteral("%1").arg(formatHwndText(guiThreadInfo.hwndFocus)));
                    sessionSummary.field(QStringLiteral("Capture"), QStringLiteral("%1").arg(formatHwndText(guiThreadInfo.hwndCapture)));
                    sessionSummary.field(QStringLiteral("Caret"), QStringLiteral("%1").arg(formatHwndText(guiThreadInfo.hwndCaret)));
                    sessionSummary.field(QStringLiteral("MenuOwner"), QStringLiteral("%1").arg(formatHwndText(guiThreadInfo.hwndMenuOwner)));
                }

                sessionSummary.note(QStringLiteral("\n[窗口站/桌面]\n"));
                sessionSummary.field(QStringLiteral("当前窗口站"), QStringLiteral("%1").arg(queryUserObjectName(::GetProcessWindowStation())));
                sessionSummary.field(QStringLiteral("当前桌面"), QStringLiteral("%1").arg(queryUserObjectName(::GetThreadDesktop(::GetCurrentThreadId()))));
                sessionSummary.field(QStringLiteral("说明"), QStringLiteral("详细窗口列表与桌面切换见“窗口管理”页；本页仅做只读审计，不做消息截获、不做输入抓取。"));
                sessionSummary.field(QStringLiteral("Win32K private layout"), QStringLiteral("%1")
                    .arg(win32kPrivateLayoutLimitationText()));

                sessionSummary.note(QStringLiteral("\n[R0 Win32K PDB profile 概要]\n"));
                appendWin32kProfileHeader(sessionSummary, win32kProfileResult);

                appendIoSummary(sessionSummary, QStringLiteral("queryWin32kWindows"), win32kWindowsResult);

                appendIoSummary(sessionSummary, QStringLiteral("queryWin32kGuiThreads"), win32kGuiThreadsResult);
            }

            // 热键/钩子页摘要。
            ks::ui::FieldDocument hotkeyHookSummary = ks::ui::FieldDocument{}.note(
                QStringLiteral("[Hotkey / Hook]\n")
                + QStringLiteral("系统级 Hook 链表：无官方通用枚举接口，R0 PDB 路径仅做只读链表快照。\n")
                + QStringLiteral("Hotkey: 只读审计，不删除热键；Hook: 只读审计，不 remove/unlink hook 链。\n")
                + QStringLiteral("风险标记: 不执行安装/卸载/截获。\n\n"));
            appendIoSummary(hotkeyHookSummary, QStringLiteral("queryWin32kHotkeysPdb"), win32kHotkeysResult);
            if (keyboardHotkeysFallbackQueried)
            {

                appendKeyboardIoSummary(hotkeyHookSummary, QStringLiteral("enumerateKeyboardHotkeys fallback"), keyboardHotkeysFallbackResult);
            }

            appendIoSummary(hotkeyHookSummary, QStringLiteral("queryWin32kHooksPdb"), win32kHooksResult);
            if (keyboardHooksFallbackQueried)
            {

                appendKeyboardIoSummary(hotkeyHookSummary, QStringLiteral("enumerateKeyboardHooks fallback"), keyboardHooksFallbackResult);
            }

            // 剪贴板页：
            // - 输入：UI 线程预先生成的 MIME 摘要行；
            // - 处理：后台线程只转发普通 QStringList，不再读取 QApplication::clipboard；
            // - 输出：避免复制热键/Hook 表格后被误展示为 ClipboardPreview 真实审计内容。
            const QVector<QStringList> clipboardRows = clipboardSnapshot;

            // 显示页摘要。
            ks::ui::FieldDocument displaySummary;
            {
                displaySummary.section(QStringLiteral("GPU / Display / Watchdog"));
                displaySummary.field(QStringLiteral("PrimaryScreen"), QStringLiteral("%1").arg(primaryScreenName));
                displaySummary.field(QStringLiteral("ScreenGeometry"), QStringLiteral("[%1,%2,%3,%4]")
                    .arg(primaryScreenGeometry.left()).arg(primaryScreenGeometry.top())
                    .arg(primaryScreenGeometry.width()).arg(primaryScreenGeometry.height()));
                displaySummary.field(QStringLiteral("DPI"), QStringLiteral("%1").arg(primaryScreenDpi));
                displaySummary.field(QStringLiteral("Watchdog"), QStringLiteral("仅记录显示状态，不做输入抓取。\n"));
                appendIoSummary(displaySummary, QStringLiteral("queryGpuDisplayWatchdogAudit"), gpuAuditResult);
                displaySummary.field(QStringLiteral("profileFlags"), QStringLiteral("%1").arg(formatUInt64Hex(gpuAuditResult.profileFlags)));
                displaySummary.field(QStringLiteral("responseFlags"), QStringLiteral("%1").arg(formatUInt64Hex(gpuAuditResult.responseFlags)));
                displaySummary.field(QStringLiteral("target/driver/device count"), QStringLiteral("%1 / %2 / %3")
                    .arg(gpuAuditResult.targetCount).arg(gpuAuditResult.driverCount).arg(gpuAuditResult.deviceCount));
            }

            // 表格行模型在后台线程构造（纯数据，不触碰控件）。
            const QVector<QStringList> windowsRows = buildWindowsRows(win32kWindowsResult);
            const QVector<QStringList> guiThreadRows = buildGuiThreadRows(win32kGuiThreadsResult);
            const QVector<QStringList> sessionRows = buildSessionRows(win32kProfileResult);
            const QVector<QStringList> hotkeyRows = buildHotkeyRows(
                win32kHotkeysResult,
                keyboardHotkeysFallbackQueried ? &keyboardHotkeysFallbackResult : nullptr);
            const QVector<QStringList> hookRows = buildHookRows(
                win32kHooksResult,
                keyboardHooksFallbackQueried ? &keyboardHooksFallbackResult : nullptr);
            const QVector<QStringList> deviceRows = buildDeviceRows(gpuAuditResult);

            if (safeThis.isNull())
            {
                return;
            }

            const bool invokeOk = QMetaObject::invokeMethod(
                safeThis.data(),
                [safeThis, sessionSummary, hotkeyHookSummary, displaySummary,
                 windowsRows, guiThreadRows, sessionRows, hotkeyRows, hookRows, deviceRows, clipboardRows]()
                {
                    const auto commitSnapshot = [
                        safeThis,
                        sessionSummary,
                        hotkeyHookSummary,
                        displaySummary,
                        windowsRows,
                        guiThreadRows,
                        sessionRows,
                        hotkeyRows,
                        hookRows,
                        deviceRows,
                        clipboardRows]()
                    {
                    if (safeThis.isNull())
                    {
                        return;
                    }

                    safeThis->m_cachedSessionSummary = sessionSummary;
                    safeThis->m_cachedHotkeyHookSummary = hotkeyHookSummary;
                    safeThis->m_cachedDisplaySummary = displaySummary;
                    safeThis->m_cachedWindowsRows = windowsRows;
                    safeThis->m_cachedGuiThreadRows = guiThreadRows;
                    safeThis->m_cachedSessionRows = sessionRows;
                    safeThis->m_cachedHotkeyRows = hotkeyRows;
                    safeThis->m_cachedHookRows = hookRows;
                    safeThis->m_cachedDeviceRows = deviceRows;
                    safeThis->m_cachedClipboardRows = clipboardRows;
                    safeThis->applyAuditViews();
                    if (safeThis->m_statusLabel != nullptr)
                    {
                        safeThis->m_statusLabel->setText(
                            QStringLiteral("最近刷新：%1")
                            .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss"))));
                    }
                    safeThis->m_refreshing.store(false);
                    };

                    if (safeThis.isNull())
                    {
                        return;
                    }
                    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
                        safeThis.data(),
                        QStringLiteral("window-audit-seven-table-apply"),
                        {
                            safeThis->m_windowsTable,
                            safeThis->m_guiThreadsTable,
                            safeThis->m_sessionTable,
                            safeThis->m_hotkeysTable,
                            safeThis->m_hooksTable,
                            safeThis->m_clipboardTable,
                            safeThis->m_deviceTable
                        },
                        commitSnapshot))
                    {
                        return;
                    }
                    commitSnapshot();
                },
                Qt::QueuedConnection);

            if (!invokeOk && !safeThis.isNull())
            {
                safeThis->m_refreshing.store(false);
            }
        }
        catch (const std::exception& exceptionObject)
        {
            reportRefreshFailure(QString::fromLocal8Bit(exceptionObject.what()));
        }
        catch (...)
        {
            reportRefreshFailure(QStringLiteral("未知异常"));
        }
    }).detach();
}

void WindowDock::applyAuditViews()
{
    // 表格空白硬保护：
    // - 输入：后台线程或刷新占位阶段生成的缓存行；
    // - 处理：关键审计页即使遇到异常空结果，也补成一行诊断而不是 0 行空表；
    // - 返回：无，后续 populateTable 统一写入表格。
    ensureNonEmptyAuditRows(
        m_windowsTable,
        m_cachedWindowsRows,
        QStringLiteral("<无窗口行模型>"),
        QStringLiteral("窗口审计没有生成任何行；请重新刷新或检查 R0/R3 fallback 状态。"));
    ensureNonEmptyAuditRows(
        m_guiThreadsTable,
        m_cachedGuiThreadRows,
        QStringLiteral("<无GUI线程行模型>"),
        QStringLiteral("GUI 线程审计没有生成任何行；请重新刷新或检查 GetGUIThreadInfo/R0 状态。"));
    ensureNonEmptyAuditRows(
        m_sessionTable,
        m_cachedSessionRows,
        QStringLiteral("<无Session行模型>"),
        QStringLiteral("Session 审计没有生成任何行；请重新刷新或检查当前交互 Session。"));
    ensureNonEmptyAuditRows(
        m_hotkeysTable,
        m_cachedHotkeyRows,
        QStringLiteral("<无热键行模型>"),
        QStringLiteral("热键审计没有生成任何行；R0/PDB 与 keyboard fallback 均未返回可展示数据。"));
    ensureNonEmptyAuditRows(
        m_hooksTable,
        m_cachedHookRows,
        QStringLiteral("<无Hook行模型>"),
        QStringLiteral("Hook 审计没有生成任何行；R0/PDB 与 keyboard fallback 均未返回可展示数据。"));
    ensureNonEmptyAuditRows(
        m_clipboardTable,
        m_cachedClipboardRows,
        QStringLiteral("<无剪贴板行模型>"),
        QStringLiteral("剪贴板审计没有生成任何行；请重新刷新或检查当前 UI 会话剪贴板状态。"));
    ensureNonEmptyAuditRows(
        m_deviceTable,
        m_cachedDeviceRows,
        QStringLiteral("<无显示设备行模型>"),
        QStringLiteral("GPU/Display/Watchdog 审计没有生成任何行；请重新刷新或检查 R0 设备审计状态。"));

    if (m_sessionSummaryEditor != nullptr && !m_cachedSessionSummary.isEmpty())
    {
        m_sessionSummaryEditor->setDocument(m_cachedSessionSummary);
    }
    if (m_hotkeyHookSummaryEditor != nullptr && !m_cachedHotkeyHookSummary.isEmpty())
    {
        m_hotkeyHookSummaryEditor->setDocument(m_cachedHotkeyHookSummary);
    }
    if (m_displaySummaryEditor != nullptr && !m_cachedDisplaySummary.isEmpty())
    {
        m_displaySummaryEditor->setDocument(m_cachedDisplaySummary);
    }

    populateTable(m_windowsTable, m_cachedWindowsRows);
    populateTable(m_guiThreadsTable, m_cachedGuiThreadRows);
    populateTable(m_sessionTable, m_cachedSessionRows);
    populateTable(m_hotkeysTable, m_cachedHotkeyRows);
    populateTable(m_hooksTable, m_cachedHookRows);
    populateTable(m_clipboardTable, m_cachedClipboardRows);
    populateTable(m_deviceTable, m_cachedDeviceRows);

    if (m_windowsTable != nullptr && m_windowsTable->rowCount() > 0 && m_windowsTable->currentRow() < 0)
    {
        m_windowsTable->setCurrentCell(0, 0);
    }
    updateSelectedWindowSnapshotDetail(m_windowsTable != nullptr ? m_windowsTable->currentRow() : -1);
}

void WindowDock::updateSelectedWindowSnapshotDetail(const int currentRow)
{
    // 选中窗口快照详情：
    // - 输入 currentRow：窗口表当前行；
    // - 处理：从可见列生成多行说明，不访问驱动；
    // - 返回：无，详情区仅作为只读展示。
    if (m_windowDetailEditor == nullptr)
    {
        return;
    }
    if (m_windowsTable == nullptr || currentRow < 0 || currentRow >= m_windowsTable->rowCount())
    {
        m_windowDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请选择 Win32K 窗口行查看快照；需要更深诊断时点击“查询选中窗口详情”。")));
        if (m_queryWindowDetailButton != nullptr)
        {
            m_queryWindowDetailButton->setEnabled(false);
        }
        return;
    }

    const auto cellText = [this, currentRow](const int columnIndex) -> QString
    {
        const QTableWidgetItem* item = m_windowsTable->item(currentRow, columnIndex);
        return item != nullptr ? item->text() : QString();
    };

    const QString hwndText = cellText(0);
    const QString processIdText = cellText(1);
    const QString threadIdText = cellText(2);
    const std::uint64_t hwndValue = parseUInt64Text(hwndText, 0U);
    ks::ui::FieldDocument snapshot;
    snapshot.section(QStringLiteral("Win32K Window Snapshot"));
    for (int column = 0; column < m_windowsTable->columnCount(); ++column)
    {
        const auto* header = m_windowsTable->horizontalHeaderItem(column);
        snapshot.field(header ? header->text() : QString::number(column), cellText(column));
    }
    snapshot.note(QStringLiteral("SnapshotDetail: GUI/Session 窗口表仅保留可见字段；tagWND/profile/capability 详情请使用下方按需查询。"));
    snapshot.note(QStringLiteral("提示：批量刷新不会逐 HWND 查询 detail；如需查看 tagWND readiness/能力缺口，请点击“查询选中窗口详情”。"));
    m_windowDetailEditor->setDocument(snapshot);

    if (m_queryWindowDetailButton != nullptr)
    {
        m_queryWindowDetailButton->setEnabled(hwndValue != 0U && !m_windowDetailRefreshing.load());
    }
}

void WindowDock::requestSelectedWindowRuntimeDetail()
{
    // 单 HWND runtime detail：
    // - 输入来自当前窗口表选中行；
    // - 处理：后台只读调用 ArkDriverClient wrapper，不在 UI 线程阻塞；
    // - 返回：无，结果通过 queued connection 写入详情编辑器。
    if (m_windowsTable == nullptr || m_windowDetailEditor == nullptr)
    {
        return;
    }

    const int currentRow = m_windowsTable->currentRow();
    if (currentRow < 0 || currentRow >= m_windowsTable->rowCount())
    {
        m_windowDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("请先选择一条 Win32K 窗口行。")));
        return;
    }

    const auto cellText = [this, currentRow](const int columnIndex) -> QString
    {
        const QTableWidgetItem* item = m_windowsTable->item(currentRow, columnIndex);
        return item != nullptr ? item->text() : QString();
    };

    const std::uint64_t hwndValue = parseUInt64Text(cellText(0), 0U);
    const std::uint32_t processId = parseUInt32Text(cellText(1), 0U);
    const std::uint32_t threadId = parseUInt32Text(cellText(2), 0U);
    if (hwndValue == 0U)
    {
        m_windowDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前行没有有效 HWND，不能执行单窗口 detail 查询。")));
        return;
    }

    bool expectedRefreshing = false;
    if (!m_windowDetailRefreshing.compare_exchange_strong(expectedRefreshing, true))
    {
        m_windowDetailEditor->setDocument(ks::ui::FieldDocument{}.note(QStringLiteral("当前已有单窗口 detail 查询正在进行，请稍候。")));
        return;
    }

    updateSelectedWindowSnapshotDetail(currentRow);
    const ks::ui::FieldDocument snapshot = m_windowDetailEditor->document();
    if (m_queryWindowDetailButton != nullptr)
    {
        m_queryWindowDetailButton->setEnabled(false);
    }
    auto pending = snapshot;
    pending.section(QStringLiteral("Win32K Window Runtime Detail"));
    pending.note(QStringLiteral("正在后台按需查询 HWND=%1 ...").arg(formatUInt64Hex(hwndValue)));
    m_windowDetailEditor->setDocument(pending);

    QPointer<WindowDock> safeThis(this);
    std::thread([safeThis, hwndValue, processId, threadId, snapshot]()
    {
        auto detail = snapshot;
        const auto runtime = win32kWindowRuntimeDocument(hwndValue, processId, threadId);
        const auto catalog = win32kPublicPdbCatalogPreview();
        detail.nodes += runtime.nodes;
        detail.nodes += catalog.nodes;
        if (safeThis.isNull())
        {
            return;
        }

        const bool invokeOk = QMetaObject::invokeMethod(
            safeThis.data(),
            [safeThis, hwndValue, detail]()
            {
                if (safeThis.isNull())
                {
                    return;
                }
                safeThis->m_windowDetailRefreshing.store(false);
                if (safeThis->m_queryWindowDetailButton != nullptr)
                {
                    safeThis->m_queryWindowDetailButton->setEnabled(true);
                }
                if (safeThis->m_windowDetailEditor != nullptr)
                {
                    const int row = safeThis->m_windowsTable->currentRow();
                    const auto* item = row >= 0 ? safeThis->m_windowsTable->item(row, 0) : nullptr;
                    if (item && parseUInt64Text(item->text(), 0U) == hwndValue)
                        safeThis->m_windowDetailEditor->setDocument(detail);
                }
            },
            Qt::QueuedConnection);

        if (!invokeOk && !safeThis.isNull())
        {
            safeThis->m_windowDetailRefreshing.store(false);
        }
    }).detach();
}
