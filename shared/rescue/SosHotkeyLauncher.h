#ifndef SOSHOTKEYLAUNCHER_H
#define SOSHOTKEYLAUNCHER_H

#include <QString>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <functional>

// SosHotkeyLauncher：
// - 作用：在 Taskbar 或普通主程序中安装全局低级键盘钩子；
// - 检测固定序列 S、O、S、Enter；
// - 命中后由独立监护进程在私有救援桌面启动 Ksword5.1，不记录其它键盘输入。
class SosHotkeyLauncher final
{
public:
    // 构造函数：
    // - 输入 applicationDirectoryPath：Taskbar.exe 所在目录；
    // - 处理：解析 Ksword5.1.exe 候选路径，启动该 exe 的监护入口；
    // - 返回：无。
    explicit SosHotkeyLauncher(const QString& applicationDirectoryPath);
    // 输入已知 KSword 路径和启动回调，供主程序直接使用自己的 exe。
    SosHotkeyLauncher(const QString& kswordExecutablePath,
        std::function<void(DWORD)> launchFailure, std::function<void(bool)> launchActivity);

    // 析构函数：
    // - 处理：停止钩子线程并注销 WH_KEYBOARD_LL；
    // - 返回：无。
    ~SosHotkeyLauncher();

    // start：
    // - 输入：无；
    // - 处理：启动专用高优先级键盘钩子线程；
    // - 返回：true 表示线程创建成功，false 表示已经失败。
    bool start(bool monitorKeyboard = true);

    // stop：
    // - 输入：无；
    // - 处理：请求钩子线程退出并等待结束；
    // - 返回：无。
    void stop();

    // 菜单与 SOS 共用独立线程启动入口；钩子不可用时仍允许菜单直接派发监护进程。
    void requestLaunch();
    bool isRunning() const { return m_hookInstalled.load(std::memory_order_acquire); }

private:
    // lowLevelKeyboardProc：
    // - 输入：Windows 低级键盘钩子参数；
    // - 处理：只把键按下事件交给当前实例状态机；
    // - 返回：CallNextHookEx 的结果。
    static LRESULT CALLBACK lowLevelKeyboardProc(int code, WPARAM wParam, LPARAM lParam);

    // hookThreadMain：
    // - 输入：无；
    // - 处理：设置线程优先级、安装钩子并运行消息循环；
    // - 返回：无。
    void hookThreadMain();

    // handleKeyDown：
    // - 输入 vkCode/flags：Windows 虚拟键码和低级钩子标志；
    // - 处理：推进 SOS Enter 状态机；
    // - 返回：无。
    void handleKeyDown(DWORD vkCode, DWORD flags);

    // launchKswordFromHookThread：
    // - 输入：无；
    // - 处理：从钩子线程启动 Ksword5.1.exe；
    // - 返回：无。
    void launchKswordFromHookThread();

    // resolveKswordExecutablePath：
    // - 输入 applicationDirectoryPath：Taskbar.exe 所在目录；
    // - 处理：兼容发行包同目录和源码构建输出目录；
    // - 返回：主程序 exe 路径，找不到时回退同目录候选。
    static QString resolveKswordExecutablePath(const QString& applicationDirectoryPath);

    // ignoredModifierKey：
    // - 输入 vkCode：Windows 虚拟键码；
    // - 处理：识别不应打断 SOS 序列的修饰键；
    // - 返回：true 表示忽略该键。
    static bool ignoredModifierKey(DWORD vkCode);

    // postLaunchRequest：
    // - 输入：无；
    // - 处理：从钩子回调向钩子线程消息循环投递启动请求；
    // - 返回：无。
    void postLaunchRequest();

private:
    static SosHotkeyLauncher* s_activeInstance;      // 当前唯一活动实例，供静态钩子回调转发。

    std::thread m_hookThread;                        // 专用键盘钩子线程。
    std::atomic_bool m_stopRequested{ false };       // 线程退出请求标记。
    std::atomic_bool m_hookInstalled{ false };       // WH_KEYBOARD_LL 是否安装成功。
    bool m_monitorKeyboard = true;

    std::mutex m_stateMutex;                         // 线程启动状态互斥锁。
    std::condition_variable m_stateCondition;        // start 等待线程就绪的条件变量。
    bool m_threadReady = false;                      // 钩子线程是否完成初始化。

    std::atomic<DWORD> m_hookThreadId{ 0 };           // 钩子线程 ID，用于 PostThreadMessage。
    HHOOK m_keyboardHook = nullptr;                  // SetWindowsHookExW 返回的键盘钩子句柄。
    int m_sequenceIndex = 0;                         // 当前已匹配 SOS Enter 序列的位置。

    std::wstring m_kswordExecutablePath;             // 监护进程和救援实例使用的 KSword exe 绝对路径。
    std::wstring m_kswordWorkingDirectory;           // 主程序启动工作目录。
    HANDLE m_rescueHostProcess = nullptr;            // 避免重复 SOS 创建并发救援会话。
    std::function<void(DWORD)> m_launchFailure;
    std::function<void(bool)> m_launchActivity;
};

#endif
