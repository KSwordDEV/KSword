#include "SosHotkeyLauncher.h"
#include "../shared/rescue/RescueDesktopWin32.h"

#include <QCoreApplication>
#include <QDebug>
#include <QDir>
#include <QFileInfo>
#include <QStringList>

#include <array>
#include <chrono>
#include <vector>

namespace
{
    constexpr UINT kSosLaunchMessage = WM_APP + 0x0515;      // 钩子线程内部启动消息。
    constexpr ULONGLONG kLaunchDebounceMs = 3000ULL;         // 防止 SOS 连续触发重复拉起。
    constexpr int kHookReadyWaitMs = 2000;                   // start 等待钩子线程初始化的时间。

    // buildMutableCommandLine：
    // - 输入 executablePath：要启动的 exe 路径；
    // - 处理：构造 CreateProcessW 需要的可写命令行缓冲区；
    // - 返回：以 NUL 结尾的 wchar_t 缓冲区。
    std::vector<wchar_t> buildMutableCommandLine(
        const std::wstring& executablePath, const std::wstring& clientPath)
    {
        // Taskbar 的独立监护入口负责创建桌面，SOS Hook 线程只派发启动请求。
        std::wstring commandLineText = L"\"" + executablePath + L"\" "
            + ks::rescue::kHostArgument + L" \"" + clientPath + L"\"";
        std::vector<wchar_t> commandLineBuffer(commandLineText.begin(), commandLineText.end());
        commandLineBuffer.push_back(L'\0');
        return commandLineBuffer;
    }
}

SosHotkeyLauncher* SosHotkeyLauncher::s_activeInstance = nullptr;

SosHotkeyLauncher::SosHotkeyLauncher(const QString& applicationDirectoryPath)
    : SosHotkeyLauncher(applicationDirectoryPath, {}, {})
{
}

SosHotkeyLauncher::SosHotkeyLauncher(const QString& applicationDirectoryPath,
    const QString& rescueHostPath, std::function<void(DWORD)> launchFailure,
    std::function<void(bool)> launchActivity)
    : m_launchFailure(std::move(launchFailure)), m_launchActivity(std::move(launchActivity))
{
    // executablePath 用途：保存主程序路径，后续钩子线程直接使用 Win32 API 启动。
    const QString executablePath = resolveKswordExecutablePath(applicationDirectoryPath);
    const QFileInfo executableInfo(executablePath);

    m_kswordExecutablePath = QDir::toNativeSeparators(executableInfo.absoluteFilePath()).toStdWString();
    m_kswordWorkingDirectory = QDir::toNativeSeparators(executableInfo.absolutePath()).toStdWString();
    m_rescueHostExecutablePath = QDir::toNativeSeparators(
        rescueHostPath.isEmpty() ? QCoreApplication::applicationFilePath() : rescueHostPath).toStdWString();
}

void SosHotkeyLauncher::requestLaunch()
{
    const DWORD threadId = m_hookThreadId.load(std::memory_order_acquire);
    if (threadId != 0
        && ::PostThreadMessageW(threadId, kSosLaunchMessage, 0, 0))
    {
        return;
    }
    if (m_launchFailure) m_launchFailure(ERROR_NOT_READY);
}

SosHotkeyLauncher::~SosHotkeyLauncher()
{
    // 析构时必须先退出消息循环，再释放对象，避免静态钩子回调访问悬空实例。
    stop();
    if (m_rescueHostProcess != nullptr)
    {
        // 监护进程独立存活到救援实例退出；Taskbar 退出只释放自己的引用。
        ::CloseHandle(m_rescueHostProcess);
    }
}

bool SosHotkeyLauncher::start(bool monitorKeyboard)
{
    if (m_hookThread.joinable())
    {
        return m_hookInstalled.load();
    }

    // s_activeInstance 用途：WH_KEYBOARD_LL 是 C 回调，必须通过静态指针转发到对象状态机。
    s_activeInstance = this;
    m_monitorKeyboard = monitorKeyboard;
    m_stopRequested.store(false);
    m_hookThreadId.store(0, std::memory_order_release);
    m_threadReady = false;

    try
    {
        m_hookThread = std::thread(&SosHotkeyLauncher::hookThreadMain, this);
    }
    catch (...)
    {
        s_activeInstance = nullptr;
        qWarning() << "[Taskbar][SOS] 键盘钩子线程创建失败。";
        return false;
    }

    std::unique_lock<std::mutex> stateLock(m_stateMutex);
    const bool hookReady = m_stateCondition.wait_for(
        stateLock,
        std::chrono::milliseconds(kHookReadyWaitMs),
        [this]() {
            return m_threadReady;
        });
    stateLock.unlock();

    // 只有线程明确完成初始化且钩子安装失败时才同步回收；超时路径保持原有
    // 非阻塞语义，由 stop()/析构负责等待，避免在消息队列尚未创建时死锁。
    return hookReady && (!m_monitorKeyboard || m_hookInstalled.load(std::memory_order_acquire));
}

void SosHotkeyLauncher::stop()
{
    m_stopRequested.store(true);

    // hookThreadId 用途：向专用线程投递退出消息，解除 GetMessageW 阻塞。
    const DWORD hookThreadId = m_hookThreadId.load(std::memory_order_acquire);
    if (hookThreadId != 0)
    {
        ::PostThreadMessageW(hookThreadId, WM_QUIT, 0, 0);
    }

    if (m_hookThread.joinable())
    {
        m_hookThread.join();
    }
    m_hookThreadId.store(0, std::memory_order_release);

    if (s_activeInstance == this)
    {
        s_activeInstance = nullptr;
    }
}

LRESULT CALLBACK SosHotkeyLauncher::lowLevelKeyboardProc(
    const int code,
    const WPARAM wParam,
    const LPARAM lParam)
{
    SosHotkeyLauncher* const instance = s_activeInstance;
    if (code == HC_ACTION && instance != nullptr &&
        (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
    {
        const KBDLLHOOKSTRUCT* const keyboardEvent =
            reinterpret_cast<const KBDLLHOOKSTRUCT*>(lParam);
        if (keyboardEvent != nullptr)
        {
            instance->handleKeyDown(keyboardEvent->vkCode, keyboardEvent->flags);
        }
    }

    return ::CallNextHookEx(
        instance != nullptr ? instance->m_keyboardHook : nullptr,
        code,
        wParam,
        lParam);
}

void SosHotkeyLauncher::hookThreadMain()
{
    MSG queuedMessage{};
    ::PeekMessageW(&queuedMessage, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    m_hookThreadId.store(::GetCurrentThreadId(), std::memory_order_release);

    // 线程优先级用途：让 SOS 低级键盘钩子尽量早于普通 UI 工作响应。
    ::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_HIGHEST);

    // m_keyboardHook 用途：全局 WH_KEYBOARD_LL 钩子，不注入其它进程。
    m_keyboardHook = m_monitorKeyboard ? ::SetWindowsHookExW(
        WH_KEYBOARD_LL,
        &SosHotkeyLauncher::lowLevelKeyboardProc,
        ::GetModuleHandleW(nullptr),
        0) : nullptr;
    m_hookInstalled.store(m_keyboardHook != nullptr);

    {
        std::lock_guard<std::mutex> stateLock(m_stateMutex);
        m_threadReady = true;
    }
    m_stateCondition.notify_all();

    if (m_monitorKeyboard && m_keyboardHook == nullptr)
    {
        qWarning() << "[Taskbar][SOS] WH_KEYBOARD_LL 安装失败, error=" << ::GetLastError();
    }

    if (m_keyboardHook) qInfo() << "[Taskbar][SOS] SOS Enter 键盘钩子已启动。";

    while (!m_stopRequested.load())
    {
        const DWORD count = m_rescueHostProcess ? 1 : 0;
        const DWORD wait = ::MsgWaitForMultipleObjectsEx(count, count ? &m_rescueHostProcess : nullptr,
            INFINITE, QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (wait == WAIT_FAILED) break;
        if (count && wait == WAIT_OBJECT_0)
        {
            DWORD exitCode = ERROR_GEN_FAILURE;
            if (!::GetExitCodeProcess(m_rescueHostProcess, &exitCode)) exitCode = ::GetLastError();
            ::CloseHandle(m_rescueHostProcess);
            m_rescueHostProcess = nullptr;
            m_lastLaunchTickMs = 0;
            if (m_launchActivity) m_launchActivity(false);
            if (exitCode != ERROR_SUCCESS && m_launchFailure) m_launchFailure(exitCode);
            continue;
        }
        MSG message{};
        while (::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE))
        {
            if (message.message == WM_QUIT) { m_stopRequested.store(true); break; }
            if (message.message == kSosLaunchMessage) launchKswordFromHookThread();
            else { ::TranslateMessage(&message); ::DispatchMessageW(&message); }
        }
    }

    if (m_keyboardHook != nullptr)
    {
        ::UnhookWindowsHookEx(m_keyboardHook);
        m_keyboardHook = nullptr;
    }
    m_hookInstalled.store(false);
    m_hookThreadId.store(0, std::memory_order_release);
    qInfo() << "[Taskbar][SOS] SOS Enter 键盘钩子已停止。";
}

void SosHotkeyLauncher::handleKeyDown(const DWORD vkCode, const DWORD flags)
{
    if ((flags & LLKHF_INJECTED) != 0)
    {
        return;
    }
    if (ignoredModifierKey(vkCode))
    {
        return;
    }

    // sequenceKeys 用途：只匹配固定 S O S Enter，不缓存或输出其它按键。
    static constexpr std::array<DWORD, 4> sequenceKeys = {
        static_cast<DWORD>('S'),
        static_cast<DWORD>('O'),
        static_cast<DWORD>('S'),
        static_cast<DWORD>(VK_RETURN)
    };

    if (vkCode == sequenceKeys[static_cast<std::size_t>(m_sequenceIndex)])
    {
        ++m_sequenceIndex;
        if (m_sequenceIndex >= static_cast<int>(sequenceKeys.size()))
        {
            m_sequenceIndex = 0;
            postLaunchRequest();
        }
        return;
    }

    // mismatch 处理：如果当前键又是 S，则作为新序列开头；否则清零。
    m_sequenceIndex = (vkCode == static_cast<DWORD>('S')) ? 1 : 0;
}

void SosHotkeyLauncher::launchKswordFromHookThread()
{
    const std::lock_guard<std::mutex> launchLock(m_launchMutex);
    if (m_rescueHostProcess != nullptr)
    {
        // 活动会话期间不创建第二个私有桌面或并发启动第三个 KSword 实例。
        if (::WaitForSingleObject(m_rescueHostProcess, 0) == WAIT_TIMEOUT)
        {
            return;
        }
        ::CloseHandle(m_rescueHostProcess);
        m_rescueHostProcess = nullptr;
    }
    const ULONGLONG nowTickMs = ::GetTickCount64();
    if (m_lastLaunchTickMs != 0 &&
        nowTickMs - m_lastLaunchTickMs < kLaunchDebounceMs)
    {
        return;
    }

    if (m_kswordExecutablePath.empty())
    {
        qWarning() << "[Taskbar][SOS] Ksword5.1.exe 路径为空，无法启动。";
        if (m_launchFailure) m_launchFailure(ERROR_FILE_NOT_FOUND);
        return;
    }

    STARTUPINFOW startupInfo{};
    PROCESS_INFORMATION processInfo{};
    startupInfo.cb = sizeof(startupInfo);

    std::vector<wchar_t> commandLineBuffer = buildMutableCommandLine(
        m_rescueHostExecutablePath, m_kswordExecutablePath);
    const BOOL createOk = ::CreateProcessW(
        m_rescueHostExecutablePath.c_str(),
        commandLineBuffer.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_NEW_PROCESS_GROUP,
        nullptr,
        m_kswordWorkingDirectory.empty() ? nullptr : m_kswordWorkingDirectory.c_str(),
        &startupInfo,
        &processInfo);

    if (createOk == FALSE)
    {
        const DWORD error = ::GetLastError();
        qWarning() << "[Taskbar][SOS] 启动 Ksword5.1.exe 失败, error=" << error;
        if (m_launchFailure) m_launchFailure(error);
        return;
    }

    ::CloseHandle(processInfo.hThread);
    m_rescueHostProcess = processInfo.hProcess;
    m_lastLaunchTickMs = nowTickMs;
    if (m_launchActivity) m_launchActivity(true);
    qInfo() << "[Taskbar][SOS] 已启动独立救援桌面监护进程，PID=" << processInfo.dwProcessId;
}

QString SosHotkeyLauncher::resolveKswordExecutablePath(const QString& applicationDirectoryPath)
{
    const QDir applicationDirectory(applicationDirectoryPath);
    const QString currentDirectoryPath = QDir::currentPath();

    // candidates 用途：优先支持发行包同目录，再兼容源码树 Taskbar\x64\Release 输出。
    const QStringList candidates = {
        applicationDirectory.filePath(QStringLiteral("Ksword5.1.exe")),
        applicationDirectory.filePath(QStringLiteral("../Ksword5.1.exe")),
        applicationDirectory.filePath(QStringLiteral("../../../Ksword5.1/Ksword5.1/x64/Release/Ksword5.1.exe")),
        QDir(currentDirectoryPath).filePath(QStringLiteral("Ksword5.1.exe"))
    };

    for (const QString& candidatePath : candidates)
    {
        const QFileInfo candidateInfo(QDir::cleanPath(candidatePath));
        if (candidateInfo.exists() && candidateInfo.isFile())
        {
            return candidateInfo.absoluteFilePath();
        }
    }

    return QFileInfo(QDir::cleanPath(candidates.first())).absoluteFilePath();
}

bool SosHotkeyLauncher::ignoredModifierKey(const DWORD vkCode)
{
    switch (vkCode)
    {
    case VK_SHIFT:
    case VK_LSHIFT:
    case VK_RSHIFT:
    case VK_CONTROL:
    case VK_LCONTROL:
    case VK_RCONTROL:
    case VK_MENU:
    case VK_LMENU:
    case VK_RMENU:
    case VK_CAPITAL:
    case VK_LWIN:
    case VK_RWIN:
        return true;
    default:
        return false;
    }
}

void SosHotkeyLauncher::postLaunchRequest()
{
    if (m_hookThreadId.load(std::memory_order_acquire) == 0)
    {
        return;
    }

    ::PostThreadMessageW(m_hookThreadId, kSosLaunchMessage, 0, 0);
}
