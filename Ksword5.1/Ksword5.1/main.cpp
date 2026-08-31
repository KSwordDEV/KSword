#include "MainWindow.h"

#include <QtCore/QByteArray>
#include <QtCore/QCoreApplication>
#include <QtCore/QEvent>
#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtGui/QFont>
#include <QtWidgets/QMessageBox>
#include <QtWidgets/QApplication>
#include <QtWidgets/QWidget>

#include "Framework.h"
#include "UI/ThemedMessageBox.h"
#include "UI/GlobalDialogTheme.h"
#include "UI/GlobalRefreshShortcut.h"
#include "UI/WindowChrome.h"
#include "UI/TableColumnAutoFit.h"
#include "UI/TableInteractionSupport.h"
#include "UI/SmoothScrollSupport.h"
#include "UI/TextSearchReplaceSupport.h"
#include "Internationalization/LanguageManager.h"
#include "../../shared/crash/WinCrashHandler.h"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <CommCtrl.h>
#include <shellapi.h>

#include <algorithm>
#include <cstdio>
#include <cmath>
#include <cwctype>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Comctl32.lib")

namespace
{
    constexpr wchar_t kUnlockerKeyName[] = L"Ksword.FileUnlocker";
    constexpr wchar_t kKswordMainWindowPropertyName[] = L"KswordARK.MainWindow.Singleton.Release";
    constexpr wchar_t kPrivilegeRestartArgument[] = L"--ksword-privilege-restart";
    constexpr ULONG_PTR kUnlockerCopyDataMessageId = 0x4B535755; // "KSWU"：Ksword shell unlocker IPC。
    constexpr DWORD kRestartPredecessorWaitTimeoutMs = 35000;

    // disableQtPopupScrollEffects 作用：
    // - 禁用 Qt 内建菜单/组合框滚动动画，阻止创建 QRollEffect 临时窗口；
    // - 该路径的定时器曾在 QWidgetPrivate::showChildren 中解引用损坏的子对象指针并崩溃；
    // - 保留淡入淡出和应用自身动画，不扩大视觉行为变更范围。
    void disableQtPopupScrollEffects()
    {
        QApplication::setEffectEnabled(Qt::UI_AnimateMenu, false);
        QApplication::setEffectEnabled(Qt::UI_AnimateCombo, false);
    }

    // localizedStartupText 作用：
    // - 让原生首启对话框、启动画面和 Qt 启动期弹窗共用 LanguageManager；
    // - 在 QApplication 创建前也可使用已经发现的语言包。
    QString localizedStartupText(const QString& textKey, const QString& fallbackText)
    {
        return ks::i18n::contextText(textKey, fallbackText);
    }

    // updateStartupSplash 作用：按当前有效语言更新原生启动画面。
    void updateStartupSplash(
        const bool splashReady,
        const int progressPercent,
        const QString& textKey,
        const QString& fallbackText)
    {
        if (!splashReady)
        {
            return;
        }
        kSplash.progress(
            localizedStartupText(textKey, fallbackText).toUtf8().toStdString(),
            progressPercent);
    }

    // kStartupScaleRecommendedLogicalWidth 作用：
    // - 定义启动分辨率审查的最低建议逻辑宽度；
    // - 低于该宽度时才弹出缩放推荐对话框。
    constexpr int kStartupScaleRecommendedLogicalWidth = 1920;

    // queryCurrentDirectoryPath 作用：
    // - 在 QApplication 创建前直接读取当前工作目录；
    // - 用于启动追踪中确认双击启动时的工作目录是否符合预期。
    // 返回：当前工作目录绝对路径；失败返回空字符串。
    std::wstring queryCurrentDirectoryPath()
    {
        std::vector<wchar_t> directoryBuffer(1024, L'\0');
        while (directoryBuffer.size() < 32768)
        {
            const DWORD copiedLength = ::GetCurrentDirectoryW(
                static_cast<DWORD>(directoryBuffer.size()),
                directoryBuffer.data());
            if (copiedLength == 0)
            {
                return std::wstring();
            }
            if (copiedLength < directoryBuffer.size())
            {
                return std::wstring(directoryBuffer.data(), copiedLength);
            }
            directoryBuffer.resize(static_cast<std::size_t>(copiedLength) + 1, L'\0');
        }
        return std::wstring();
    }

    // ExistingKswordWindowSearchContext 说明：
    // - 输入：由 EnumWindows 回调读写；
    // - 处理逻辑：记录当前进程 PID，并在其它进程的顶层可见窗口中匹配 Ksword 主窗口标记；
    // - 返回行为：foundWindow 非空表示发现已运行实例。
    struct ExistingKswordWindowSearchContext
    {
        DWORD currentProcessId = 0; // currentProcessId：当前启动实例 PID，用于排除自身窗口。
        HWND foundWindow = nullptr; // foundWindow：发现的已有 Ksword 主窗口句柄。
    };

    // enumExistingKswordWindowProc 作用：
    // - 输入：Win32 顶层窗口枚举回调参数；
    // - 处理：跳过不可见窗口/当前进程窗口，只按窗口属性识别 Ksword 主窗口；
    // - 说明：不再按窗口标题兜底，避免资源管理器等普通窗口标题撞名导致误判单实例。
    // - 返回：TRUE 继续枚举；FALSE 表示已找到目标并停止枚举。
    BOOL CALLBACK enumExistingKswordWindowProc(HWND windowHandle, LPARAM parameter)
    {
        auto* context = reinterpret_cast<ExistingKswordWindowSearchContext*>(parameter);
        if (context == nullptr || windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return TRUE;
        }
        if (::IsWindowVisible(windowHandle) == FALSE)
        {
            return TRUE;
        }

        DWORD processId = 0;
        (void)::GetWindowThreadProcessId(windowHandle, &processId);
        if (processId == 0 || processId == context->currentProcessId)
        {
            return TRUE;
        }

        if (::GetPropW(windowHandle, kKswordMainWindowPropertyName) != nullptr)
        {
            context->foundWindow = windowHandle;
            return FALSE;
        }
        return TRUE;
    }

    // findExistingKswordMainWindow 作用：
    // - 输入：无；
    // - 处理：在 QApplication 创建前枚举系统顶层窗口，寻找已经运行的 Ksword 主窗口；
    // - 返回：找到则返回 HWND，否则返回 nullptr。
    HWND findExistingKswordMainWindow()
    {
        ExistingKswordWindowSearchContext context;
        context.currentProcessId = ::GetCurrentProcessId();
        (void)::EnumWindows(enumExistingKswordWindowProc, reinterpret_cast<LPARAM>(&context));
        return context.foundWindow;
    }

    // hasCommandLineArgument 作用：
    // - 输入 argumentText：需要查找的内部命令行参数；
    // - 处理：使用 CommandLineToArgvW 按 Win32 规则解析当前命令行，避免手写拆分误判引号；
    // - 返回：找到完全匹配参数返回 true，否则返回 false。
    bool hasCommandLineArgument(const wchar_t* argumentText)
    {
        if (argumentText == nullptr || argumentText[0] == L'\0')
        {
            return false;
        }

        int argumentCount = 0;
        LPWSTR* argumentVector = ::CommandLineToArgvW(::GetCommandLineW(), &argumentCount);
        if (argumentVector == nullptr)
        {
            return false;
        }

        bool found = false;
        for (int argumentIndex = 1; argumentIndex < argumentCount; ++argumentIndex)
        {
            if (_wcsicmp(argumentVector[argumentIndex], argumentText) == 0)
            {
                found = true;
                break;
            }
        }
        ::LocalFree(argumentVector);
        return found;
    }

    // collectUnlockPathsFromCommandLine：
    // - 输入：无，直接解析当前进程命令行；
    // - 处理：收集所有 "--unlock <path>" 参数，供单实例转发和正常启动流程复用；
    // - 返回：按命令行顺序返回待解锁路径列表。
    std::vector<std::wstring> collectUnlockPathsFromCommandLine()
    {
        std::vector<std::wstring> unlockPathList;
        int argumentCount = 0;
        LPWSTR* argumentVector = ::CommandLineToArgvW(::GetCommandLineW(), &argumentCount);
        if (argumentVector == nullptr)
        {
            return unlockPathList;
        }

        for (int argumentIndex = 1; argumentIndex < argumentCount; ++argumentIndex)
        {
            if (_wcsicmp(argumentVector[argumentIndex], L"--unlock") != 0)
            {
                continue;
            }
            if ((argumentIndex + 1) >= argumentCount)
            {
                break;
            }

            const wchar_t* const pathText = argumentVector[argumentIndex + 1];
            if (pathText != nullptr && pathText[0] != L'\0')
            {
                unlockPathList.emplace_back(pathText);
            }
            argumentIndex += 1;
        }

        ::LocalFree(argumentVector);
        return unlockPathList;
    }

    // sendUnlockPathToExistingMainWindow：
    // - 输入：windowHandle 为已有 Ksword 主窗口句柄，unlockPath 为 Shell 右键传入路径；
    // - 处理：通过 WM_COPYDATA 把路径交给已有实例，由已有实例执行文件解锁器；
    // - 返回：消息成功送达返回 true，失败返回 false。
    bool sendUnlockPathToExistingMainWindow(HWND windowHandle, const std::wstring& unlockPath)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE || unlockPath.empty())
        {
            return false;
        }

        COPYDATASTRUCT copyData{};
        copyData.dwData = kUnlockerCopyDataMessageId;
        copyData.cbData = static_cast<DWORD>((unlockPath.size() + 1) * sizeof(wchar_t));
        copyData.lpData = const_cast<wchar_t*>(unlockPath.c_str());

        DWORD_PTR sendResult = 0;
        const LRESULT messageResult = ::SendMessageTimeoutW(
            windowHandle,
            WM_COPYDATA,
            0,
            reinterpret_cast<LPARAM>(&copyData),
            SMTO_ABORTIFHUNG | SMTO_BLOCK,
            3000,
            &sendResult);
        return messageResult != 0;
    }

    // appendInternalArgumentIfMissing 作用：
    // - 输入 parameterText：已有命令行参数；argumentText：需要追加的内部参数；
    // - 处理：当前参数中没有该内部标记时追加，避免多轮权限重启重复堆叠；
    // - 返回：可直接交给 ShellExecuteW/CreateProcessW 的参数字符串。
    std::wstring appendInternalArgumentIfMissing(
        const std::wstring& parameterText,
        const wchar_t* argumentText)
    {
        if (argumentText == nullptr || argumentText[0] == L'\0')
        {
            return parameterText;
        }
        if (hasCommandLineArgument(argumentText))
        {
            return parameterText;
        }

        std::wstring resultText = parameterText;
        if (!resultText.empty())
        {
            resultText += L" ";
        }
        resultText += argumentText;
        return resultText;
    }

    // activateExistingKswordMainWindow 作用：
    // - 输入 windowHandle：已有 Ksword 主窗口；
    // - 处理：如果最小化则恢复，再尽量前置并激活；
    // - 返回：无返回值，失败不阻断当前实例退出。
    void activateExistingKswordMainWindow(HWND windowHandle)
    {
        if (windowHandle == nullptr || ::IsWindow(windowHandle) == FALSE)
        {
            return;
        }
        if (::IsIconic(windowHandle) != FALSE)
        {
            (void)::ShowWindow(windowHandle, SW_RESTORE);
        }
        else
        {
            (void)::ShowWindow(windowHandle, SW_SHOWNORMAL);
        }
        (void)::SetForegroundWindow(windowHandle);
        (void)::BringWindowToTop(windowHandle);
    }

    // buildStartupTraceFilePath 作用：
    // - 为“启动原生追踪”选择稳定输出文件；
    // - 优先写入 %TEMP%，便于即使控制台秒退也能保留日志。
    // 返回：追踪日志文件完整路径。
    std::wstring buildStartupTraceFilePath()
    {
        wchar_t tempPathBuffer[MAX_PATH] = {};
        const DWORD tempLength = ::GetTempPathW(MAX_PATH, tempPathBuffer);
        if (tempLength > 0 && tempLength < MAX_PATH)
        {
            std::wstring tempDirectory(tempPathBuffer, tempLength);
            if (!tempDirectory.empty() && tempDirectory.back() != L'\\' && tempDirectory.back() != L'/')
            {
                tempDirectory.push_back(L'\\');
            }
            return tempDirectory + L"Ksword5.1-startup-trace.log";
        }

        const std::wstring currentDirectory = queryCurrentDirectoryPath();
        if (!currentDirectory.empty())
        {
            return currentDirectory + L"\\Ksword5.1-startup-trace.log";
        }
        return L"Ksword5.1-startup-trace.log";
    }

    // appendStartupTraceFile 作用：
    // - 把原生启动追踪文本附加写入文件；
    // - 避免控制台窗口闪退时丢失关键定位信息。
    // 入参 traceLineText：已带换行的一整行追踪文本（UTF-8）。
    void appendStartupTraceFile(const std::string& traceLineText)
    {
        const std::wstring traceFilePath = buildStartupTraceFilePath();
        FILE* traceFileHandle = nullptr;
        if (_wfopen_s(&traceFileHandle, traceFilePath.c_str(), L"ab") != 0 || traceFileHandle == nullptr)
        {
            return;
        }

        std::fwrite(traceLineText.data(), 1, traceLineText.size(), traceFileHandle);
        std::fclose(traceFileHandle);
    }

    // startupTraceRaw 作用：
    // - 在 kLog 之外提供一条“原生启动追踪”旁路；
    // - 同时写控制台、OutputDebugStringA 与临时文件；
    // - 用于定位“main 早期即退出，kLog 尚未来得及显示”的问题。
    // 入参 traceText：单行追踪文本（不含换行）。
    void startupTraceRaw(const std::string& traceText)
    {
        SYSTEMTIME localTime = {};
        ::GetLocalTime(&localTime);

        char timePrefixBuffer[64] = {};
        std::snprintf(
            timePrefixBuffer,
            sizeof(timePrefixBuffer),
            "[trace][%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            static_cast<unsigned int>(localTime.wYear),
            static_cast<unsigned int>(localTime.wMonth),
            static_cast<unsigned int>(localTime.wDay),
            static_cast<unsigned int>(localTime.wHour),
            static_cast<unsigned int>(localTime.wMinute),
            static_cast<unsigned int>(localTime.wSecond),
            static_cast<unsigned int>(localTime.wMilliseconds));

        std::string fullTraceLine = std::string(timePrefixBuffer) + traceText + "\r\n";
        appendStartupTraceFile(fullTraceLine);
        ::OutputDebugStringA(fullTraceLine.c_str());

    }

    // queryCurrentExecutablePath 作用：
    // - 动态获取当前进程可执行文件绝对路径；
    // - 兼容长路径，避免固定 MAX_PATH 缓冲区截断问题。
    // 返回：成功返回非空绝对路径，失败返回空字符串。
    std::wstring queryCurrentExecutablePath()
    {
        std::vector<wchar_t> pathBuffer(1024, L'\0');
        while (pathBuffer.size() < 32768)
        {
            ::SetLastError(ERROR_SUCCESS);
            const DWORD copiedLength = ::GetModuleFileNameW(
                nullptr,
                pathBuffer.data(),
                static_cast<DWORD>(pathBuffer.size()));
            const DWORD lastError = ::GetLastError();
            if (copiedLength == 0)
            {
                return std::wstring();
            }

            if (copiedLength > 0
                && copiedLength < pathBuffer.size()
                && lastError != ERROR_INSUFFICIENT_BUFFER)
            {
                return std::wstring(pathBuffer.data(), copiedLength);
            }

            pathBuffer.resize(pathBuffer.size() * 2, L'\0');
        }
        return std::wstring();
    }

    // resolveExecutableDirectoryPath 作用：
    // - 从 exe 完整路径解析工作目录；
    // - CreateProcess 显式传入目录，避免自动重启后当前目录漂移。
    // 入参 executablePath：当前 exe 绝对路径。
    // 返回：exe 所在目录，无法解析时返回空字符串。
    std::wstring resolveExecutableDirectoryPath(const std::wstring& executablePath)
    {
        const std::size_t slashPosition = executablePath.find_last_of(L"\\/");
        if (slashPosition == std::wstring::npos)
        {
            return std::wstring();
        }
        return executablePath.substr(0, slashPosition);
    }

    bool writeRegistryString(
        HKEY rootKey,
        const std::wstring& subKeyPath,
        const wchar_t* valueName,
        const std::wstring& valueText)
    {
        HKEY keyHandle = nullptr;
        const LONG createResult = ::RegCreateKeyExW(
            rootKey,
            subKeyPath.c_str(),
            0,
            nullptr,
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            nullptr,
            &keyHandle,
            nullptr);
        if (createResult != ERROR_SUCCESS)
        {
            return false;
        }

        const DWORD valueSizeBytes = static_cast<DWORD>((valueText.size() + 1) * sizeof(wchar_t));
        const LONG setResult = ::RegSetValueExW(
            keyHandle,
            valueName,
            0,
            REG_SZ,
            reinterpret_cast<const BYTE*>(valueText.c_str()),
            valueSizeBytes);
        ::RegCloseKey(keyHandle);
        return setResult == ERROR_SUCCESS;
    }

    void deleteRegistryTreeBestEffort(HKEY rootKey, const std::wstring& subKeyPath)
    {
        ::RegDeleteTreeW(rootKey, subKeyPath.c_str());
    }

    bool registerUnlockerContextMenu(const std::wstring& executablePath)
    {
        const std::wstring commandForFile = L"\"" + executablePath + L"\" --unlock \"%1\"";

        const std::wstring baseStar = L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring baseDirectory = L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring baseDrive = L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName);
        const std::wstring menuText = ks::i18n::contextText(
            QStringLiteral("main.unlocker.menu"),
            QStringLiteral("使用 Ksword 文件解锁器(R3/R0)")).toStdWString();

        // 解锁器只对“选中的文件/文件夹/驱动器”有意义，因此不再注册 Directory\Background：
        // 该位置是桌面和文件夹空白处的右键菜单，没有选中目标，菜单项纯属噪音。
        // 旧版本写过这个键，注册时顺带清掉，避免升级后残留在桌面右键上。
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));

        const bool starOk =
            writeRegistryString(HKEY_CURRENT_USER, baseStar, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseStar, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseStar + L"\\command", nullptr, commandForFile);
        const bool directoryOk =
            writeRegistryString(HKEY_CURRENT_USER, baseDirectory, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseDirectory, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseDirectory + L"\\command", nullptr, commandForFile);
        const bool driveOk =
            writeRegistryString(HKEY_CURRENT_USER, baseDrive, nullptr, menuText.c_str())
            && writeRegistryString(HKEY_CURRENT_USER, baseDrive, L"Icon", executablePath)
            && writeRegistryString(HKEY_CURRENT_USER, baseDrive + L"\\command", nullptr, commandForFile);

        return starOk && directoryOk && driveOk;
    }

    void unregisterUnlockerContextMenu()
    {
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\*\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\shell\\" + std::wstring(kUnlockerKeyName));
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Drive\\shell\\" + std::wstring(kUnlockerKeyName));
        // Directory\Background 已不再注册，但仍要删：旧版本装过的用户需要被清理干净。
        deleteRegistryTreeBestEffort(
            HKEY_CURRENT_USER,
            L"Software\\Classes\\Directory\\Background\\shell\\" + std::wstring(kUnlockerKeyName));
    }

    // kNativeAppIconResourceName 作用：
    // - 指向 AppIcon.rc 内声明的主图标资源名；
    // - 用于把原生图标同步到 Qt 主窗口标题栏和任务栏。
    constexpr wchar_t kNativeAppIconResourceName[] = L"IDI_APP_ICON";

    // isCurrentProcessElevated 作用：
    // - 判断当前进程是否已经运行在管理员权限下；
    // - 供“启动时自动请求管理员权限”逻辑复用。
    // 返回：true=已提权；false=普通权限。
    bool isCurrentProcessElevated()
    {
        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
        {
            return false;
        }

        // tokenElevation 作用：承接 TokenElevation 查询结果。
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

    // tryEnableStartupProcessPrivileges：
    // - 输入：无，直接作用于当前进程 token；
    // - 处理：管理员启动后逐项启用进程相关特权，覆盖权限页中 30-52 行常用系统特权；
    // - 返回：true 表示至少一个目标权限已成功启用；false 表示当前非管理员、打开令牌失败或全部失败。
    bool tryEnableStartupProcessPrivileges()
    {
        if (!isCurrentProcessElevated())
        {
            startupTraceRaw("startup process privileges skipped: process is not elevated");
            kLogEvent event;
            warn << event
                << "[main] 启动期进程权限批量申请跳过：当前进程不是管理员。"
                << eol;
            return false;
        }

        HANDLE tokenHandle = nullptr;
        if (::OpenProcessToken(
            ::GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &tokenHandle) == FALSE)
        {
            const DWORD errorCode = ::GetLastError();
            startupTraceRaw(
                std::string("startup process privileges OpenProcessToken failed, error=")
                + std::to_string(errorCode));
            kLogEvent event;
            err << event
                << "[main] 启动期进程权限批量申请失败：OpenProcessToken error="
                << errorCode
                << eol;
            return false;
        }

        int enabledCount = 0;
        int notAssignedCount = 0;
        int failedCount = 0;
        std::string failedDetailText;

        for (const std::string& privilegeNameText : ks::process::KnownTokenPrivilegeNames())
        {
            const std::wstring privilegeName(privilegeNameText.begin(), privilegeNameText.end());
            LUID privilegeLuid{};
            if (::LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &privilegeLuid) == FALSE)
            {
                const DWORD errorCode = ::GetLastError();
                ++failedCount;
                failedDetailText += privilegeNameText + ":LookupPrivilegeValue=" + std::to_string(errorCode) + ";";
                continue;
            }

            TOKEN_PRIVILEGES tokenPrivileges{};
            tokenPrivileges.PrivilegeCount = 1;
            tokenPrivileges.Privileges[0].Luid = privilegeLuid;
            tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            ::SetLastError(ERROR_SUCCESS);
            if (::AdjustTokenPrivileges(
                tokenHandle,
                FALSE,
                &tokenPrivileges,
                sizeof(tokenPrivileges),
                nullptr,
                nullptr) == FALSE)
            {
                const DWORD errorCode = ::GetLastError();
                ++failedCount;
                failedDetailText += privilegeNameText + ":AdjustTokenPrivileges=" + std::to_string(errorCode) + ";";
                continue;
            }

            const DWORD adjustError = ::GetLastError();
            if (adjustError == ERROR_SUCCESS)
            {
                ++enabledCount;
                continue;
            }

            if (adjustError == ERROR_NOT_ALL_ASSIGNED)
            {
                ++notAssignedCount;
            }
            else
            {
                ++failedCount;
            }
            failedDetailText += privilegeNameText + ":AdjustResult=" + std::to_string(adjustError) + ";";
        }

        ::CloseHandle(tokenHandle);

        startupTraceRaw(
            std::string("startup process privileges finished: enabled=")
            + std::to_string(enabledCount)
            + ", not_assigned="
            + std::to_string(notAssignedCount)
            + ", failed="
            + std::to_string(failedCount)
            + ", detail="
            + failedDetailText);

        kLogEvent event;
        info << event
            << "[main] 启动期进程权限批量申请完成，enabled="
            << enabledCount
            << ", notAssigned="
            << notAssignedCount
            << ", failed="
            << failedCount
            << eol;

        if (enabledCount <= 0)
        {
            kLogEvent failEvent;
            err << failEvent
                << "[main] 启动期进程权限批量申请没有成功启用任何目标权限。"
                << eol;
            return false;
        }

        return true;
    }

    // extractCurrentProcessParameterText 作用：
    // - 从当前命令行提取“exe 之后”的参数文本；
    // - runas 重启时原样透传，避免行为差异。
    // 返回：可传入 ShellExecuteW 的参数字符串。
    std::wstring extractCurrentProcessParameterText()
    {
        const wchar_t* commandLineText = ::GetCommandLineW();
        if (commandLineText == nullptr)
        {
            return std::wstring();
        }

        // cursorPointer 作用：遍历命令行并定位到第一个参数起始位置。
        const wchar_t* cursorPointer = commandLineText;
        bool insideQuotes = false;
        while (*cursorPointer != L'\0')
        {
            if (*cursorPointer == L'"')
            {
                insideQuotes = !insideQuotes;
            }
            else if (!insideQuotes && std::iswspace(static_cast<wint_t>(*cursorPointer)) != 0)
            {
                break;
            }
            ++cursorPointer;
        }

        while (std::iswspace(static_cast<wint_t>(*cursorPointer)) != 0)
        {
            ++cursorPointer;
        }

        return std::wstring(cursorPointer);
    }

    // tryLaunchElevatedSelfBeforeSplash 作用：
    // - 在启动页出现前尝试 runas 拉起管理员实例；
    // - 成功则当前普通权限实例直接退出，避免双开。
    // 返回：true=管理员实例已拉起；false=失败，继续普通启动。
    bool tryLaunchElevatedSelfBeforeSplash()
    {
        const std::wstring executablePath = queryCurrentExecutablePath();
        if (executablePath.empty())
        {
            return false;
        }

        // parameterText 作用：保存当前命令行参数，传递给新启动实例。
        const std::wstring parameterText = appendInternalArgumentIfMissing(
            extractCurrentProcessParameterText(),
            kPrivilegeRestartArgument);
        const std::wstring executableDirectory = resolveExecutableDirectoryPath(executablePath);
        HINSTANCE shellResult = ::ShellExecuteW(
            nullptr,
            L"runas",
            executablePath.c_str(),
            parameterText.empty() ? nullptr : parameterText.c_str(),
            executableDirectory.empty() ? nullptr : executableDirectory.c_str(),
            SW_SHOWNORMAL);
        return reinterpret_cast<INT_PTR>(shellResult) > 32;
    }

    // tryCreateRestartedSelfBeforeSplash 作用：
    // - 在 QApplication 创建前使用 CreateProcessW 重新启动当前程序；
    // - 只依赖配置文件承载缩放结果，不通过参数传递缩放状态；
    // - 当前进程只负责启动新实例，退出由 main 根据返回值执行。
    // 返回：true=新实例已拉起；false=启动失败，调用方继续当前启动流程。
    bool tryCreateRestartedSelfBeforeSplash()
    {
        const std::wstring executablePath = queryCurrentExecutablePath();
        if (executablePath.empty())
        {
            return false;
        }

        // commandLineText 作用：CreateProcessW 要求可写命令行缓冲区。
        std::wstring commandLineText = L"\"" + executablePath + L"\"";
        const std::wstring parameterText = appendInternalArgumentIfMissing(
            extractCurrentProcessParameterText(),
            kPrivilegeRestartArgument);
        if (!parameterText.empty())
        {
            commandLineText += L" ";
            commandLineText += parameterText;
        }

        const std::wstring executableDirectory = resolveExecutableDirectoryPath(executablePath);
        STARTUPINFOW startupInfo = {};
        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_SHOWNORMAL;

        PROCESS_INFORMATION processInformation = {};
        const BOOL createOk = ::CreateProcessW(
            executablePath.c_str(),
            &commandLineText[0],
            nullptr,
            nullptr,
            FALSE,
            0,
            nullptr,
            executableDirectory.empty() ? nullptr : executableDirectory.c_str(),
            &startupInfo,
            &processInformation);
        if (createOk == FALSE)
        {
            return false;
        }

        ::CloseHandle(processInformation.hThread);
        ::CloseHandle(processInformation.hProcess);
        return true;
    }

    // initializeProcessDpiAwareness 作用：
    // - 在主函数最早阶段设置进程 DPI 感知；
    // - 保证启动页与 Qt 主窗口的缩放行为稳定。
    void initializeProcessDpiAwareness()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using SetDpiAwarenessContextFunction = BOOL(WINAPI*)(DPI_AWARENESS_CONTEXT);
            const SetDpiAwarenessContextFunction setContextFunction =
                reinterpret_cast<SetDpiAwarenessContextFunction>(
                    ::GetProcAddress(user32ModuleHandle, "SetProcessDpiAwarenessContext"));
            if (setContextFunction != nullptr)
            {
                if (setContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2))
                {
                    return;
                }
                if (setContextFunction(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE))
                {
                    return;
                }
            }
        }

        // 旧系统回退方案：至少启用系统 DPI 感知。
        ::SetProcessDPIAware();
    }

    // querySystemScalePercent 作用：
    // - 读取当前系统缩放百分比（100/125/150...）；
    // - 新系统优先 GetDpiForSystem，旧系统回退 GDI 计算。
    // 返回：系统缩放百分比（最小 100）。
    int querySystemScalePercent()
    {
        HMODULE user32ModuleHandle = ::GetModuleHandleW(L"user32.dll");
        if (user32ModuleHandle != nullptr)
        {
            using GetDpiForSystemFunction = UINT(WINAPI*)();
            const GetDpiForSystemFunction getDpiForSystemFunction =
                reinterpret_cast<GetDpiForSystemFunction>(
                    ::GetProcAddress(user32ModuleHandle, "GetDpiForSystem"));
            if (getDpiForSystemFunction != nullptr)
            {
                const UINT dpiValue = getDpiForSystemFunction();
                if (dpiValue >= 96U)
                {
                    const int scalePercent = static_cast<int>(
                        std::lround((static_cast<double>(dpiValue) * 100.0) / 96.0));
                    return std::max(100, scalePercent);
                }
            }
        }

        HDC screenDeviceContext = ::GetDC(nullptr);
        if (screenDeviceContext == nullptr)
        {
            return 100;
        }
        const int logPixelsX = ::GetDeviceCaps(screenDeviceContext, LOGPIXELSX);
        ::ReleaseDC(nullptr, screenDeviceContext);
        if (logPixelsX <= 0)
        {
            return 100;
        }
        const int scalePercent = static_cast<int>(
            std::lround((static_cast<double>(logPixelsX) * 100.0) / 96.0));
        return std::max(100, scalePercent);
    }

    // buildPercentText 作用：
    // - 把比例值转为百分比文本；
    // - 供启动前推荐缩放弹窗显示。
    // 入参 ratioValue：比例值（1.0=100%）。
    // 返回：宽字符串百分比文本。
    std::wstring buildPercentText(const double ratioValue)
    {
        const int percentValue = static_cast<int>(std::lround(ratioValue * 100.0));
        return std::to_wstring(percentValue) + L"%";
    }

    // showStartupScaleRecommendationDialog 作用：
    // - 在首次低分辨率启动前提示是否应用推荐缩放；
    // - 仅提供“应用推荐缩放”与“保持当前缩放”两种结果。
    // 入参 logicalClientWidth：按“物理像素/系统缩放”得到的可用宽度。
    // 入参 currentScaleFactor：当前配置缩放因子。
    // 入参 recommendedScaleFactor：推荐缩放因子。
    // 出参 applyRecommendedOut：是否应用推荐值。
    // 返回：true=弹窗成功返回；false=弹窗调用失败。
    bool showStartupScaleRecommendationDialog(
        const int logicalClientWidth,
        const double currentScaleFactor,
        const double recommendedScaleFactor,
        bool* applyRecommendedOut)
    {
        if (applyRecommendedOut == nullptr)
        {
            return false;
        }
        *applyRecommendedOut = false;

        const std::wstring currentScaleText = buildPercentText(currentScaleFactor);
        const std::wstring recommendedScaleText = buildPercentText(recommendedScaleFactor);
        const QString dialogContentSourceTemplate = QStringLiteral(
            "当前可用宽度约 %1px，小于推荐的 %2px。\n"
            "当前缩放：%3\n"
            "推荐缩放：%4\n\n"
            "是否应用推荐缩放？Ksword 将保存设置并立即重启。" );
        const QString dialogContentText = localizedStartupText(
            QStringLiteral("main.scale.dialog.content"),
            dialogContentSourceTemplate)
            .arg(logicalClientWidth)
            .arg(kStartupScaleRecommendedLogicalWidth)
            .arg(QString::fromStdWString(currentScaleText))
            .arg(QString::fromStdWString(recommendedScaleText));
        const std::wstring applyAndRestartText = localizedStartupText(
            QStringLiteral("main.scale.dialog.apply"), QStringLiteral("应用并重启")).toStdWString();
        const std::wstring keepCurrentSettingsText = localizedStartupText(
            QStringLiteral("main.scale.dialog.keep"), QStringLiteral("保持当前设置")).toStdWString();
        const std::wstring dialogContentTextWide = dialogContentText.toStdWString();
        const std::wstring dialogTitleText = localizedStartupText(
            QStringLiteral("main.scale.dialog.title"), QStringLiteral("Ksword5.1 启动缩放建议")).toStdWString();
        const std::wstring mainInstructionText = localizedStartupText(
            QStringLiteral("main.scale.dialog.instruction"), QStringLiteral("检测到当前显示可用宽度偏小")).toStdWString();

        // dialogButtons 作用：TaskDialog 自定义按钮集合。
        TASKDIALOG_BUTTON dialogButtons[] =
        {
            { IDYES, applyAndRestartText.c_str() },
            { IDNO, keepCurrentSettingsText.c_str() }
        };

        TASKDIALOGCONFIG dialogConfig = {};
        dialogConfig.cbSize = sizeof(dialogConfig);
        dialogConfig.hInstance = ::GetModuleHandleW(nullptr);
        dialogConfig.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
        dialogConfig.pszWindowTitle = dialogTitleText.c_str();
        dialogConfig.pszMainInstruction = mainInstructionText.c_str();
        dialogConfig.pszContent = dialogContentTextWide.c_str();
        dialogConfig.pButtons = dialogButtons;
        dialogConfig.cButtons = ARRAYSIZE(dialogButtons);
        dialogConfig.nDefaultButton = IDYES;

        int pressedButtonId = 0;
        const HRESULT dialogResult = ::TaskDialogIndirect(
            &dialogConfig,
            &pressedButtonId,
            nullptr,
            nullptr);
        if (FAILED(dialogResult))
        {
            return false;
        }

        *applyRecommendedOut = (pressedButtonId == IDYES);
        return true;
    }

    // maybeApplyStartupScaleRecommendation 作用：
    // - 仅在“没有检测到配置文件”且低分辨率时提示推荐缩放；
    // - 把用户选择直接写回 startupSettings，随后由当前进程继续完成 Qt 初始化；
    // - 最佳努力保存配置文件，但保存失败时也不能阻断主窗口启动。
    // 调用方式：QApplication 创建前调用。
    // 入参 startupSettings：启动配置对象（按需被更新）。
    // 返回：true=当前进程已被其它实例接管，应立即退出；false=继续当前启动流程。
    bool maybeApplyStartupScaleRecommendation(ks::settings::AppearanceSettings* startupSettings)
    {
        startupTraceRaw("enter maybeApplyStartupScaleRecommendation");
        if (startupSettings == nullptr)
        {
            startupTraceRaw("maybeApplyStartupScaleRecommendation: startupSettings is null");
            return false;
        }

        // scaleDecisionEvent 作用：串联启动缩放决策链路日志。
        kLogEvent scaleDecisionEvent;
        if (ks::settings::settingsJsonFileExistsForRead())
        {
            startupTraceRaw("maybeApplyStartupScaleRecommendation: settings file exists, skip first-run prompt");
            info << scaleDecisionEvent
                << "[main] 已检测到配置文件，按配置文件直接启动。"
                << eol;
            return false;
        }

        const int physicalScreenWidth = std::max(1, ::GetSystemMetrics(SM_CXSCREEN));
        const int systemScalePercent = querySystemScalePercent();
        const int logicalClientWidth = static_cast<int>(
            std::lround((static_cast<double>(physicalScreenWidth) * 100.0) / static_cast<double>(systemScalePercent)));
        if (logicalClientWidth >= kStartupScaleRecommendedLogicalWidth)
        {
            startupTraceRaw(
                std::string("maybeApplyStartupScaleRecommendation: logical width >= threshold, logicalWidth=")
                + std::to_string(logicalClientWidth)
                + ", threshold="
                + std::to_string(kStartupScaleRecommendedLogicalWidth));
            info << scaleDecisionEvent
                << "[main] 可用宽度满足要求，跳过推荐缩放。 logicalWidth="
                << logicalClientWidth
                << ", systemScalePercent="
                << systemScalePercent
                << eol;
            return false;
        }

        const double currentScaleFactor = ks::settings::normalizeWindowScaleFactor(
            startupSettings->startupWindowScaleFactor);
        const double recommendedScaleFactor = ks::settings::normalizeWindowScaleFactor(
            std::min(
                1.0,
                static_cast<double>(logicalClientWidth) / static_cast<double>(kStartupScaleRecommendedLogicalWidth)));
        if (recommendedScaleFactor >= currentScaleFactor - 0.0001)
        {
            startupTraceRaw(
                std::string("maybeApplyStartupScaleRecommendation: recommended scale not smaller than current, current=")
                + std::to_string(currentScaleFactor)
                + ", recommended="
                + std::to_string(recommendedScaleFactor));
            info << scaleDecisionEvent
                << "[main] 当前缩放已不大于推荐值，无需提示。 current="
                << currentScaleFactor
                << ", recommended="
                << recommendedScaleFactor
                << eol;
            return false;
        }

        bool applyRecommendedScale = false;
        const bool promptHandled = showStartupScaleRecommendationDialog(
            logicalClientWidth,
            currentScaleFactor,
            recommendedScaleFactor,
            &applyRecommendedScale);
        startupTraceRaw(
            std::string("maybeApplyStartupScaleRecommendation: dialog returned, handled=")
            + (promptHandled ? "true" : "false")
            + ", applyRecommendedScale="
            + (applyRecommendedScale ? "true" : "false"));
        if (!promptHandled)
        {
            warn << scaleDecisionEvent
                << "[main] 首次启动缩放推荐弹窗调用失败，改为按当前缩放继续启动。"
                << eol;
            return false;
        }

        // 直接更新内存中的启动配置：
        // - “应用推荐缩放”会让后续 QT_SCALE_FACTOR 使用推荐值；
        // - “保持当前设置”则沿用当前缩放，但同样落盘首启配置，避免重复弹窗。
        startupSettings->startupWindowScaleFactor = applyRecommendedScale
            ? recommendedScaleFactor
            : currentScaleFactor;
        startupSettings->startupScaleRecommendPromptDisabled = false;

        QString saveErrorText;
        const bool saveOk = ks::settings::saveAppearanceSettings(*startupSettings, &saveErrorText);
        startupTraceRaw(
            std::string("maybeApplyStartupScaleRecommendation: saveAppearanceSettings returned ")
            + (saveOk ? "true" : "false"));
        if (!saveOk)
        {
            // 保存失败只影响“下次启动是否仍会再次提示”：
            // - 当前这次启动仍可继续；
            // - 不能因为配置文件写入失败就让主窗口完全不出来。
            warn << scaleDecisionEvent
                << "[main] 首次启动缩放配置保存失败，本次按内存中的缩放继续启动, error="
                << saveErrorText.toStdString()
                << eol;
            return false;
        }

        info << scaleDecisionEvent
            << "[main] 首次启动缩放配置已写入, logicalWidth="
            << logicalClientWidth
            << ", current="
            << currentScaleFactor
            << ", recommended="
            << recommendedScaleFactor
            << ", applied="
            << (applyRecommendedScale ? "true" : "false")
            << eol;

        // 当前函数运行时 QApplication 尚未创建：
        // - 后续 main 仍会根据 startupSettings 设置 QT_SCALE_FACTOR；
        // - 因此这里无需重启，直接继续当前启动链即可。
        info << scaleDecisionEvent
            << "[main] 首次启动缩放决策完成，继续当前实例启动。"
            << eol;
        startupTraceRaw("leave maybeApplyStartupScaleRecommendation with false");
        return false;
    }

    // applyQtScaleFactorEnvironment 作用：
    // - 在 QApplication 创建前设置 QT_SCALE_FACTOR；
    // - 该值会参与整个 Qt 主窗口缩放计算。
    // 入参 scaleFactor：目标缩放因子（0.50~2.00）。
    void applyQtScaleFactorEnvironment(const double scaleFactor)
    {
        const double normalizedScaleFactor = ks::settings::normalizeWindowScaleFactor(scaleFactor);
        const QByteArray scaleFactorText = QByteArray::number(normalizedScaleFactor, 'f', 3);
        qputenv("QT_SCALE_FACTOR", scaleFactorText);

        kLogEvent scaleEnvEvent;
        info << scaleEnvEvent
            << "[main] 已设置 QT_SCALE_FACTOR="
            << scaleFactorText.toStdString()
            << eol;
    }

    // loadSharedIconFromResource 作用：
    // - 按指定尺寸从可执行文件资源加载共享图标；
    // - 供主窗口设置任务栏/标题栏图标。
    // 入参 widthValue/heightValue：目标图标尺寸。
    // 返回：图标句柄；失败返回 nullptr。
    HICON loadSharedIconFromResource(const int widthValue, const int heightValue)
    {
        return reinterpret_cast<HICON>(
            ::LoadImageW(
                ::GetModuleHandleW(nullptr),
                kNativeAppIconResourceName,
                IMAGE_ICON,
                widthValue,
                heightValue,
                LR_DEFAULTCOLOR | LR_SHARED));
    }

    // applyNativeAppIconToWidget 作用：
    // - 把 AppIcon.rc 图标显式同步到 Qt 顶层窗口；
    // - 修复“窗口图标未跟随 exe 图标”的问题。
    // 入参 targetWidget：目标顶层窗口。
    void applyNativeAppIconToWidget(QWidget* targetWidget)
    {
        if (targetWidget == nullptr)
        {
            return;
        }

        const HWND targetWindowHandle = reinterpret_cast<HWND>(targetWidget->winId());
        if (targetWindowHandle == nullptr)
        {
            return;
        }

        const int bigIconWidth = ::GetSystemMetrics(SM_CXICON);
        const int bigIconHeight = ::GetSystemMetrics(SM_CYICON);
        const int smallIconWidth = ::GetSystemMetrics(SM_CXSMICON);
        const int smallIconHeight = ::GetSystemMetrics(SM_CYSMICON);

        HICON bigIconHandle = loadSharedIconFromResource(bigIconWidth, bigIconHeight);
        HICON smallIconHandle = loadSharedIconFromResource(smallIconWidth, smallIconHeight);

        if (bigIconHandle != nullptr)
        {
            ::SendMessageW(
                targetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_BIG),
                reinterpret_cast<LPARAM>(bigIconHandle));
        }
        if (smallIconHandle != nullptr)
        {
            ::SendMessageW(
                targetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_SMALL),
                reinterpret_cast<LPARAM>(smallIconHandle));
            ::SendMessageW(
                targetWindowHandle,
                WM_SETICON,
                static_cast<WPARAM>(ICON_SMALL2),
                reinterpret_cast<LPARAM>(smallIconHandle));
        }
    }

    // FirstFrameSplashHider 作用：
    // - 等待主窗口中央背景宿主收到首次 Paint；
    // - 把隐藏动作排到该次 Paint 完成之后，避免启动页在背景真正绘制前消失；
    // - 提供定时兜底，规避平台消息差异导致的漏判。
    class FirstFrameSplashHider final : public QObject
    {
    public:
        // 构造函数作用：
        // - 保存主窗口和启动页控制器指针；
        // - 后续由 eventFilter 与定时器统一执行隐藏。
        // 入参 targetWindow：主窗口对象。
        // 入参 splashWindow：启动页控制器对象。
        FirstFrameSplashHider(
            MainWindow* targetWindow,
            kStartupSplash* splashWindow)
            : QObject(targetWindow)
            , m_targetWindow(targetWindow)
            , m_targetCentralWidget(targetWindow != nullptr ? targetWindow->centralWidget() : nullptr)
            , m_splashWindow(splashWindow)
        {
            // 启动兜底：窗口进入可见状态后若事件链漏判，1.5 秒后也强制收起启动页。
            QTimer::singleShot(1500, this, [this]()
                {
                    if (m_hidden || m_targetWindow == nullptr)
                    {
                        return;
                    }
                    if (m_targetWindow->isVisible() && !m_targetWindow->isMinimized())
                    {
                        hideSplashAndDetach();
                    }
                });
        }

    protected:
        // eventFilter 作用：
        // - 捕获首帧相关事件后隐藏启动页；
        // - 同时监听主窗口与中央控件，避免仅监听主窗导致漏判。
        bool eventFilter(QObject* watchedObject, QEvent* eventObject) override
        {
            if (m_hidden || eventObject == nullptr || m_targetWindow == nullptr)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // watchedTargetWindow 作用：判断本次事件是否来自主窗口。
            const bool watchedTargetWindow = (watchedObject == m_targetWindow);
            // watchedTargetCentral 作用：判断本次事件是否来自中央内容控件。
            const bool watchedTargetCentral = (watchedObject == m_targetCentralWidget);
            if (!watchedTargetWindow && !watchedTargetCentral)
            {
                return QObject::eventFilter(watchedObject, eventObject);
            }

            // eventType 作用：统一承接本次事件类型，便于扩展首帧判定条件。
            const QEvent::Type eventType = eventObject->type();
            const bool isBackgroundPaint =
                eventType == QEvent::Paint
                && (watchedTargetCentral || (m_targetCentralWidget == nullptr && watchedTargetWindow));

            if (!m_hidden
                && !m_hideQueued
                && isBackgroundPaint
                && m_targetWindow->isVisible()
                && !m_targetWindow->isMinimized())
            {
                m_hideQueued = true;
                QTimer::singleShot(0, this, [this]()
                    {
                        if (m_hidden || m_targetWindow == nullptr)
                        {
                            return;
                        }
                        if (m_targetWindow->isVisible() && !m_targetWindow->isMinimized())
                        {
                            hideSplashAndDetach();
                            return;
                        }
                        m_hideQueued = false;
                    });
            }
            return QObject::eventFilter(watchedObject, eventObject);
        }

    private:
        // hideSplashAndDetach 作用：
        // - 执行一次性隐藏动作并移除事件过滤器；
        // - 保证启动页只隐藏一次，避免重复调用。
        void hideSplashAndDetach()
        {
            m_hidden = true;
            if (m_splashWindow != nullptr)
            {
                m_splashWindow->progress("启动完成", 100);
                m_splashWindow->hide();
            }
            if (m_targetWindow != nullptr)
            {
                m_targetWindow->removeEventFilter(this);
            }
            if (m_targetCentralWidget != nullptr)
            {
                m_targetCentralWidget->removeEventFilter(this);
            }

        }

        MainWindow* m_targetWindow = nullptr;     // m_targetWindow：主窗口对象指针。
        QWidget* m_targetCentralWidget = nullptr; // m_targetCentralWidget：主窗口中央内容控件指针。
        kStartupSplash* m_splashWindow = nullptr; // m_splashWindow：启动页控制器指针。
        bool m_hidden = false;                    // m_hidden：是否已经执行过隐藏动作。
        bool m_hideQueued = false;                // m_hideQueued：是否已把隐藏动作排到首次背景绘制之后。
    };
}

int main(int argc, char* argv[])
{
    // 启动流程：
    // 1) 初始化 DPI 感知；
    // 2) 读取配置并处理推荐缩放；
    // 3) 按配置处理自动提权；
    // 4) 设置 QT_SCALE_FACTOR；
    // 5) 显示 Framework 启动页并创建主窗口。
    ks::crash::Configuration crashConfiguration;
    crashConfiguration.productName = L"KswordARK";
    crashConfiguration.dumpFilePrefix = L"Ksword5.1";
    crashConfiguration.preferLauncherReporter = true;
    ks::crash::InstallCrashHandler(crashConfiguration);
    const bool crashRestartWait =
        ks::crash::WaitForCrashRestartTargetFromCommandLine(
            kRestartPredecessorWaitTimeoutMs);
    startupTraceRaw("startup trace initialized without console binding");
    initializeProcessDpiAwareness();
    startupTraceRaw("initializeProcessDpiAwareness finished");

    const std::vector<std::wstring> startupUnlockPathList = collectUnlockPathsFromCommandLine();
    // startupSettings 需在防多开判定前读取：用户关闭“防止多开”后，新启动必须直接继续创建实例。
    ks::settings::AppearanceSettings startupSettings = ks::settings::loadAppearanceSettings();
    const bool privilegeRestartLaunch = hasCommandLineArgument(kPrivilegeRestartArgument);
    const bool skipSingleInstanceLaunch = crashRestartWait;
    if (startupSettings.preventMultipleInstances && !privilegeRestartLaunch && !skipSingleInstanceLaunch)
    {
        if (HWND existingWindowHandle = findExistingKswordMainWindow())
        {
            if (!startupUnlockPathList.empty())
            {
                startupTraceRaw("existing Ksword main window found, forwarding unlock request and exiting current instance");
                bool allUnlockRequestsForwarded = true;
                for (const std::wstring& unlockPath : startupUnlockPathList)
                {
                    if (!sendUnlockPathToExistingMainWindow(existingWindowHandle, unlockPath))
                    {
                        allUnlockRequestsForwarded = false;
                    }
                }

                if (!allUnlockRequestsForwarded && !isCurrentProcessElevated())
                {
                    // 兜底策略：
                    // - 正常路径应由已有主窗口的 ChangeWindowMessageFilterEx 放行 WM_COPYDATA；
                    // - 如果目标实例较旧/窗口尚未完成初始化/系统策略导致发送失败，普通权限实例不应直接丢弃路径；
                    // - 尝试提权重启，至少让文件解锁请求能进入一个具备管理员权限的新实例。
                    startupTraceRaw("unlock forwarding failed from non-elevated process, trying elevated relaunch fallback");
                    if (tryLaunchElevatedSelfBeforeSplash())
                    {
                        startupTraceRaw("unlock forwarding fallback elevated relaunch succeeded");
                        return 0;
                    }
                }
            }
            else
            {
                startupTraceRaw("existing Ksword main window found, activating it and exiting current instance");
            }
            activateExistingKswordMainWindow(existingWindowHandle);
            return 0;
        }
    }
    else if (privilegeRestartLaunch)
    {
        startupTraceRaw("privilege restart marker found, skipping single-instance check");
    }
    else if (skipSingleInstanceLaunch)
    {
        startupTraceRaw("verified crash restart predecessor exited, skipping single-instance check");
    }
    else if (!startupSettings.preventMultipleInstances)
    {
        startupTraceRaw("prevent multiple instances disabled in settings, skipping single-instance check");
    }

    if (!startupUnlockPathList.empty() && !privilegeRestartLaunch && !isCurrentProcessElevated())
    {
        // Shell 文件解锁入口必须尽早提权：
        // - 文件占用扫描依赖管理员权限和 SeDebugPrivilege，否则系统/高权限进程句柄容易漏报；
        // - 这里位于 splash/QApplication 创建前，避免普通权限实例先初始化 UI 再重启造成闪烁；
        // - 参数由 tryLaunchElevatedSelfBeforeSplash 原样透传，并追加内部重启标记防止循环。
        startupTraceRaw("unlock startup requested without elevation, launching elevated self before splash");
        kLogEvent unlockElevationEvent;
        info << unlockElevationEvent
            << "[main] 检测到文件解锁参数且当前不是管理员，准备立即提权重启。"
            << eol;
        const bool elevatedLaunchStarted = tryLaunchElevatedSelfBeforeSplash();
        if (elevatedLaunchStarted)
        {
            startupTraceRaw("unlock elevated relaunch succeeded, exiting current instance");
            warn << unlockElevationEvent
                << "[main] 文件解锁管理员实例已启动，当前普通权限实例退出。"
                << eol;
            return 0;
        }
        warn << unlockElevationEvent
            << "[main] 文件解锁管理员实例未能启动，将继续当前实例启动。"
            << eol;
    }

    {
        kLogEvent startupMainEvent;
        info << startupMainEvent
            << "[main] 进入主函数。 argc="
            << argc
            << eol;
    }

    // startupSettings 作用：缓存本次启动所需配置快照。
    const std::wstring executablePathForTrace = queryCurrentExecutablePath();
    const std::wstring currentDirectoryForTrace = queryCurrentDirectoryPath();
    const QString settingsReadPath = ks::settings::resolveSettingsJsonPathForRead();
    const bool settingsFileExists = ks::settings::settingsJsonFileExistsForRead();
    startupTraceRaw(
        std::string("startup paths: cwd=")
        + QString::fromStdWString(currentDirectoryForTrace).toUtf8().toStdString()
        + ", exe="
        + QString::fromStdWString(executablePathForTrace).toUtf8().toStdString()
        + ", settings_path="
        + settingsReadPath.toUtf8().toStdString()
        + ", settings_exists="
        + (settingsFileExists ? "true" : "false"));

    QString preQtLanguageMessage;
    (void)ks::i18n::LanguageManager::instance().initialize(
        startupSettings.uiLanguage,
        &preQtLanguageMessage);
    startupTraceRaw(
        std::string("startup settings loaded: scale_factor=")
        + std::to_string(startupSettings.startupWindowScaleFactor)
        + ", startup_tab="
        + startupSettings.startupDefaultTabKey.toUtf8().toStdString()
        + ", startup_maximized="
        + (startupSettings.launchMaximizedOnStartup ? "true" : "false")
        + ", auto_admin="
        + (startupSettings.autoRequestAdminOnStartup ? "true" : "false")
        + ", prevent_multiple_instances="
        + (startupSettings.preventMultipleInstances ? "true" : "false"));
    {
        kLogEvent settingsEvent;
        info << settingsEvent
            << "[main] 启动配置已加载。 startup_tab="
            << startupSettings.startupDefaultTabKey
            << ", startup_maximized="
            << (startupSettings.launchMaximizedOnStartup ? "true" : "false")
            << ", auto_admin="
            << (startupSettings.autoRequestAdminOnStartup ? "true" : "false")
            << ", prevent_multiple_instances="
            << (startupSettings.preventMultipleInstances ? "true" : "false")
            << ", startup_scale_factor="
            << startupSettings.startupWindowScaleFactor
            << ", scale_prompt_disabled="
            << (startupSettings.startupScaleRecommendPromptDisabled ? "true" : "false")
            << eol;
    }

    startupTraceRaw("before maybeApplyStartupScaleRecommendation");
    if (maybeApplyStartupScaleRecommendation(&startupSettings))
    {
        startupTraceRaw("maybeApplyStartupScaleRecommendation returned true, exiting current instance");
        kLogEvent restartTakeoverEvent;
        warn << restartTakeoverEvent
            << "[main] maybeApplyStartupScaleRecommendation 返回 true，当前实例提前退出。"
            << eol;
        return 0;
    }

    if (startupSettings.autoRequestAdminOnStartup && !isCurrentProcessElevated())
    {
        startupTraceRaw("autoRequestAdminOnStartup enabled and process not elevated");
        kLogEvent adminRequestEvent;
        info << adminRequestEvent
            << "[main] 检测到启用自动管理员请求，准备在 splash 前尝试提权重启。"
            << eol;
        const bool elevatedLaunchStarted = tryLaunchElevatedSelfBeforeSplash();
        if (elevatedLaunchStarted)
        {
            startupTraceRaw("tryLaunchElevatedSelfBeforeSplash succeeded, exiting current instance");
            warn << adminRequestEvent
                << "[main] 管理员实例已启动，当前普通权限实例退出。"
                << eol;
            return 0;
        }
        warn << adminRequestEvent
            << "[main] 自动管理员请求未拉起新实例，将继续当前实例启动。"
            << eol;
    }

    // 管理员实例需要在主窗口创建前尽早启用常用进程令牌特权：
    // - 带 admin/--ksword-privilege-restart 参数启动时不会经过按钮点击流程；
    // - 因此在 QApplication 创建前统一批量申请权限页 30-52 行特权，避免进程/句柄/R0/备份还原等功能降级。
    startupTraceRaw("before startup process privilege request");
    (void)tryEnableStartupProcessPrivileges();
    startupTraceRaw("after startup process privilege request");

    startupTraceRaw("before applyQtScaleFactorEnvironment");
    applyQtScaleFactorEnvironment(startupSettings.startupWindowScaleFactor);
    startupTraceRaw("after applyQtScaleFactorEnvironment");

    const bool splashReady = kSplash.show(
        localizedStartupText(
            QStringLiteral("main.startup.progress.starting"),
            QStringLiteral("正在启动..."))
            .toUtf8()
            .toStdString());
    startupTraceRaw(std::string("kSplash.show finished, result=") + (splashReady ? "true" : "false"));
    {
        kLogEvent splashEvent;
        info << splashEvent
            << "[main] 启动画面 show 结果="
            << (splashReady ? "true" : "false")
            << eol;
    }
    if (splashReady)
    {
        updateStartupSplash(
            splashReady,
            6,
            QStringLiteral("main.startup.progress.qt_runtime"),
            QStringLiteral("正在准备运行环境..."));
    }

    startupTraceRaw("before QApplication construction");
    QApplication app(argc, argv);
    startupTraceRaw("QApplication constructed");
    disableQtPopupScrollEffects();

    // 组织名/应用名必须在任何 QSettings 之前设置：默认构造的 QSettings 会取这两个值定位
    // HKCU\Software\<组织>\<应用>。组织名为空时 Qt 的 Windows 注册表后端直接置 AccessError，
    // 读永远拿默认值、写被静默丢弃——本程序此前正是这种状态，导致
    // “不再弹出此类操作的确认提示”勾了也不生效、插件自动更新开关与插件许可证接受记录同样存不上。
    // 这里补上后，上述三条链路才真正可用；键名沿用各调用点已有的分组前缀，不做迁移。
    QCoreApplication::setOrganizationName(QStringLiteral("Ksword"));
    QCoreApplication::setApplicationName(QStringLiteral("Ksword5.1"));

    // startupSystemFont 作用：
    // - 在读取并应用任何持久化字体 family 前保存 Qt/系统提供的完整字体基线；
    // - 后续“系统默认”恢复必须使用该值，不能从已被配置污染的 QApplication::font() 反推。
    const QFont startupSystemFont = app.font();
    // startupApplicationFont 作用：
    // - 在 MainWindow 与各 Dock/表格创建前恢复已保存字体；
    // - 避免表格先绑定系统默认字体，随后再改 QApplication 字体时只更新部分控件。
    QFont startupApplicationFont = startupSystemFont;
    const QString startupFontFamily = startupSettings.fontFamily.trimmed();
    if (!startupFontFamily.isEmpty())
    {
        startupApplicationFont.setFamily(startupFontFamily);
    }
    startupApplicationFont.setStyleStrategy(
        startupSettings.textAntialiasingEnabled
        ? QFont::PreferAntialias
        : QFont::NoAntialias);
    QApplication::setFont(startupApplicationFont);

    QString languageLoadMessage;
    const bool languagePackLoaded = ks::i18n::LanguageManager::instance().initialize(
        startupSettings.uiLanguage,
        &languageLoadMessage);
    {
        kLogEvent languageEvent;
        info << languageEvent
            << "[main] Language system initialized. requested="
            << startupSettings.uiLanguage
            << ", active="
            << ks::i18n::LanguageManager::instance().currentLanguageId()
            << ", loaded="
            << (languagePackLoaded ? "true" : "false")
            << ", detail="
            << languageLoadMessage
            << eol;
    }
    const std::wstring crashTitle = localizedStartupText(
        QStringLiteral("main.crash.title"),
        QStringLiteral("KswordARK 崩溃")).toStdWString();
    const std::wstring crashInstruction = localizedStartupText(
        QStringLiteral("main.crash.instruction"),
        QStringLiteral("KswordARK 因未处理的异常停止运行。")).toStdWString();
    const std::wstring crashExceptionCode = localizedStartupText(
        QStringLiteral("main.crash.exception_code"),
        QStringLiteral("异常")).toStdWString();
    const std::wstring crashExceptionAddress = localizedStartupText(
        QStringLiteral("main.crash.exception_address"),
        QStringLiteral("地址")).toStdWString();
    const std::wstring crashDumpPath = localizedStartupText(
        QStringLiteral("main.crash.dump_path"),
        QStringLiteral("转储文件")).toStdWString();
    const std::wstring crashDumpUnavailable = localizedStartupText(
        QStringLiteral("main.crash.dump_unavailable"),
        QStringLiteral("转储文件未能写入。")).toStdWString();
    const std::wstring crashRestartQuestion = localizedStartupText(
        QStringLiteral("main.crash.restart_question"),
        QStringLiteral("选择“是”重新启动 KswordARK，选择“否”退出。")).toStdWString();
    const std::wstring crashRepeated = localizedStartupText(
        QStringLiteral("main.crash.repeated"),
        QStringLiteral("程序刚刚重启后再次崩溃，建议先退出并检查转储文件。")).toStdWString();
    const std::wstring crashRestartFailed = localizedStartupText(
        QStringLiteral("main.crash.restart_failed"),
        QStringLiteral("重新启动 KswordARK 失败，程序即将退出。")).toStdWString();
    ks::crash::DialogText crashDialogText;
    crashDialogText.title = crashTitle.c_str();
    crashDialogText.instruction = crashInstruction.c_str();
    crashDialogText.exceptionCodeLabel = crashExceptionCode.c_str();
    crashDialogText.exceptionAddressLabel = crashExceptionAddress.c_str();
    crashDialogText.dumpPathLabel = crashDumpPath.c_str();
    crashDialogText.dumpUnavailableText = crashDumpUnavailable.c_str();
    crashDialogText.restartQuestion = crashRestartQuestion.c_str();
    crashDialogText.repeatedCrashText = crashRepeated.c_str();
    crashDialogText.restartFailedText = crashRestartFailed.c_str();
    ks::crash::UpdateCrashDialogText(crashDialogText);
    ks::ui::InstallGlobalMessageBoxTheme(&app);
    startupTraceRaw("InstallGlobalMessageBoxTheme finished");
    ks::ui::InstallGlobalDialogTheme(&app);
    startupTraceRaw("InstallGlobalDialogTheme finished");
    ks::ui::InstallWindowChrome(&app);
    startupTraceRaw("InstallWindowChrome finished");
    ks::ui::InstallGlobalRefreshShortcut(&app);
    startupTraceRaw("InstallGlobalRefreshShortcut finished");
    ks::ui::InstallGlobalTableColumnAutoFit(&app);
    startupTraceRaw("InstallGlobalTableColumnAutoFit finished");
    ks::ui::InstallGlobalTableInteractionSupport(&app);
    ks::ui::InstallGlobalSmoothScrollSupport(&app);
    // 全应用多行文本框统一支持 Ctrl+F 查找 / Ctrl+H 替换（含正则开关）。
    ks::ui::InstallGlobalTextSearchReplaceSupport(&app);
    const QStringList argumentList = QCoreApplication::arguments();
    startupTraceRaw(
        std::string("QCoreApplication::arguments fetched, count=")
        + std::to_string(argumentList.size()));
    {
        kLogEvent argumentEvent;
        info << argumentEvent
            << "[main] QApplication 已创建。 argument_count="
            << argumentList.size()
            << eol;
    }

    const bool shouldRegisterUnlockerMenu = argumentList.contains(QStringLiteral("--register-unlocker-context-menu"));
    const bool shouldUnregisterUnlockerMenu = argumentList.contains(QStringLiteral("--unregister-unlocker-context-menu"));
    if (shouldRegisterUnlockerMenu || shouldUnregisterUnlockerMenu)
    {
        if (shouldUnregisterUnlockerMenu)
        {
            unregisterUnlockerContextMenu();
            startupSettings.unlockerShellContextMenuEnabled = false;
            QString saveErrorText;
            ks::settings::saveAppearanceSettings(startupSettings, &saveErrorText);
            QMessageBox::information(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.removed"),
                    QStringLiteral("已移除系统右键菜单中的“Ksword 文件解锁器(R3/R0)”项。")));
            return 0;
        }

        const std::wstring executablePath = queryCurrentExecutablePath();
        if (executablePath.empty())
        {
            QMessageBox::warning(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.path_failed"),
                    QStringLiteral("读取程序路径失败，无法注册系统右键菜单。")));
            return 1;
        }

        const bool registerOk = registerUnlockerContextMenu(executablePath);
        if (registerOk)
        {
            startupSettings.unlockerShellContextMenuEnabled = true;
            QString saveErrorText;
            ks::settings::saveAppearanceSettings(startupSettings, &saveErrorText);
            QMessageBox::information(
                nullptr,
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.title"),
                    QStringLiteral("Ksword 文件解锁器")),
                localizedStartupText(
                    QStringLiteral("main.unlocker.dialog.registered"),
                    QStringLiteral("已注册系统右键菜单，可在文件/目录/磁盘和目录空白处右键触发。")));
            return 0;
        }

        QMessageBox::warning(
            nullptr,
            localizedStartupText(
                QStringLiteral("main.unlocker.dialog.title"),
                QStringLiteral("Ksword 文件解锁器")),
            localizedStartupText(
                QStringLiteral("main.unlocker.dialog.register_failed"),
                QStringLiteral("注册系统右键菜单失败，请确认当前账户对 HKCU\\Software\\Classes 具备写入权限。")));
        return 1;
    }

    // 常规启动下：根据设置页开关同步系统右键“文件解锁器”菜单。
    {
        const std::wstring executablePath = queryCurrentExecutablePath();
        if (!executablePath.empty())
        {
            if (startupSettings.unlockerShellContextMenuEnabled)
            {
                registerUnlockerContextMenu(executablePath);
            }
            else
            {
                unregisterUnlockerContextMenu();
            }
        }
    }

    QStringList unlockPathList;
    for (const std::wstring& unlockPath : startupUnlockPathList)
    {
        unlockPathList.push_back(QString::fromStdWString(unlockPath));
    }

    // startupProgressCallback 作用：
    // - 接收 MainWindow 构造阶段回调；
    // - 持续回写启动页文案和进度百分比。
    const MainWindow::StartupProgressCallback startupProgressCallback =
        [splashReady](const int progressPercent, const QString& statusText)
        {
            if (!splashReady)
            {
                return;
            }
            kSplash.progress(statusText.toUtf8().toStdString(), progressPercent);
            kLogEvent splashProgressEvent;
            info << splashProgressEvent
                << "[main] StartupProgressCallback progress="
                << progressPercent
                << ", status="
                << statusText
                << eol;
        };

    if (splashReady)
    {
        updateStartupSplash(
            splashReady,
            18,
            QStringLiteral("main.startup.progress.prepare_environment"),
            QStringLiteral("正在准备运行环境..."));
        updateStartupSplash(
            splashReady,
            28,
            QStringLiteral("main.startup.progress.create_main_window"),
            QStringLiteral("正在准备主界面..."));
    }

    MainWindow window(nullptr, startupProgressCallback, startupSystemFont);
    startupTraceRaw("MainWindow constructed");
    {
        kLogEvent windowConstructEvent;
        info << windowConstructEvent
            << "[main] MainWindow 构造已完成。 visible="
            << (window.isVisible() ? "true" : "false")
            << ", geometry="
            << window.geometry().x()
            << ","
            << window.geometry().y()
            << " "
            << window.geometry().width()
            << "x"
            << window.geometry().height()
            << eol;
    }
    FirstFrameSplashHider firstFrameHider(&window, &kSplash);
    window.installEventFilter(&firstFrameHider);
    if (window.centralWidget() != nullptr)
    {
        window.centralWidget()->installEventFilter(&firstFrameHider);
    }

    if (splashReady)
    {
        updateStartupSplash(
            splashReady,
            95,
            QStringLiteral("main.startup.progress.show_main_window"),
            QStringLiteral("即将完成..."));
    }

    if (startupSettings.launchMaximizedOnStartup)
    {
        window.showMaximized();
    }
    else
    {
        window.show();
    }

    // 启动主窗口前置：
    // - 仅在主窗口首次 show/showMaximized 完成后执行一次；
    // - 让正常启动与 --unlock 启动都获得一致的前台激活行为。
    window.raise();
    window.activateWindow();

    startupTraceRaw("window.show invoked");
    {
        kLogEvent showEvent;
        const QRect visibleGeometry = window.frameGeometry();
        info << showEvent
            << "[main] 已调用 window.show()。 isVisible="
            << (window.isVisible() ? "true" : "false")
            << ", isMinimized="
            << (window.isMinimized() ? "true" : "false")
            << ", frame="
            << visibleGeometry.x()
            << ","
            << visibleGeometry.y()
            << " "
            << visibleGeometry.width()
            << "x"
            << visibleGeometry.height()
            << eol;
    }
    applyNativeAppIconToWidget(&window);

    if (!unlockPathList.isEmpty())
    {
        const QStringList pendingUnlockPathList = unlockPathList;
        QTimer::singleShot(1600, &window, [&window, pendingUnlockPathList]()
            {
                kSplash.hide();
                for (const QString& targetPath : pendingUnlockPathList)
                {
                    QTimer::singleShot(0, &window, [&window, targetPath]()
                        {
                            window.openFileUnlockerDockByPath(targetPath);
                        });
                }
            });
    }

    if (splashReady)
    {
        updateStartupSplash(
            splashReady,
            98,
            QStringLiteral("main.startup.progress.wait_first_frame"),
            QStringLiteral("即将完成..."));

        // 兜底策略：
        // - 若首帧事件异常未触发；
        // - 4 秒后静默强制隐藏启动页，避免兜底动作产生面向用户的警告通知。
        QTimer::singleShot(4000, &window, []()
            {
                kSplash.hide();
            });
    }

    QTimer::singleShot(200, &window, [&window]()
        {
            kLogEvent firstSnapshotEvent;
            const QRect snapshotFrame = window.frameGeometry();
            info << firstSnapshotEvent
                << "[main] 启动后 200ms 窗口快照。 visible="
                << (window.isVisible() ? "true" : "false")
                << ", minimized="
                << (window.isMinimized() ? "true" : "false")
                << ", active="
                << (window.isActiveWindow() ? "true" : "false")
                << ", frame="
                << snapshotFrame.x()
                << ","
                << snapshotFrame.y()
                << " "
                << snapshotFrame.width()
                << "x"
                << snapshotFrame.height()
                << eol;
        });

    QTimer::singleShot(1200, &window, [&window]()
        {
            kLogEvent secondSnapshotEvent;
            const QRect snapshotFrame = window.frameGeometry();
            info << secondSnapshotEvent
                << "[main] 启动后 1200ms 窗口快照。 visible="
                << (window.isVisible() ? "true" : "false")
                << ", minimized="
                << (window.isMinimized() ? "true" : "false")
                << ", active="
                << (window.isActiveWindow() ? "true" : "false")
                << ", frame="
                << snapshotFrame.x()
                << ","
                << snapshotFrame.y()
                << " "
                << snapshotFrame.width()
                << "x"
                << snapshotFrame.height()
                << eol;
        });

    const int exitCode = app.exec();
    startupTraceRaw(std::string("QApplication::exec returned, exitCode=") + std::to_string(exitCode));
    {
        kLogEvent exitLoopEvent;
        info << exitLoopEvent
            << "[main] QApplication::exec() 已返回。 exitCode="
            << exitCode
            << eol;
    }
    kSplash.hide();
    return exitCode;
}
