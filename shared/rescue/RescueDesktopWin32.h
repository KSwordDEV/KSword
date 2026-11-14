#pragma once
#include <functional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <string>

// 本模块只封装 Win32 救援桌面，不涉及 R0 协议或 Windows 的 Winlogon 桌面。
namespace ks::rescue
{
    // USER32 windows/hooks on the entry thread must not prevent desktop binding.
    // The callback, its hooks and its cleanup all run on the fresh thread.
    DWORD RunDesktopSessionOnFreshThread(const std::function<DWORD()>& session);
    inline constexpr wchar_t kSessionGuardName[] = L"Local\\KSword.Rescue.Session";
    inline constexpr wchar_t kClientArgument[] = L"--ksword-rescue-desktop";
    inline constexpr wchar_t kDesktopPrefix[] = L"KSword.Rescue.";
    inline constexpr int kReturnHotkeyId = 0x4b53;

    // ClientHandles：只将救援桌面、就绪/返回事件和监护进程同步句柄交给子进程。
    struct ClientHandles
    {
        HDESK desktop = nullptr; // 子进程唯一继承的桌面。
        HANDLE ready = nullptr; // 子进程完成窗口及输入防护初始化后置位。
        HANDLE leave = nullptr; // 请求返回原桌面，双方均可置位。
        HANDLE host = nullptr; // 仅允许等待监护进程退出，不授予写进程权限。
    };

    // 输入完整消息/Hook 标志，返回是否应拒绝该输入；硬件 HID 来源不能在 R3 中鉴真。
    bool IsMouseMessage(UINT message);
    bool IsKeyboardMessage(UINT message);
    bool RejectInjectedMouse(DWORD flags);
    bool RejectInjectedKeyboard(DWORD flags);
    bool AcceptInputSource(UINT message, const INPUT_MESSAGE_SOURCE& source);

    // 输入桌面句柄，读取对象名或是否为当前输入桌面；失败分别返回空串/false。
    std::wstring DesktopName(HDESK desktop);
    bool IsInputDesktop(HDESK desktop);

    // 创建私有、可继承桌面。显式 OWNER RIGHTS 拒绝 ACE 同时关闭所有者的隐式改 ACL 权限。
    // 输入唯一名称，输出已授权的创建句柄；其他进程按名称打开将被 DACL 拒绝。
    HDESK CreatePrivateDesktop(const std::wstring& name);

    // 用明确的继承白名单创建救援客户端；输入路径/原桌面名/四个句柄，输出进程句柄及错误码。
    bool LaunchClient(const std::wstring& executable, const std::wstring& originalName,
        const ClientHandles& handles, PROCESS_INFORMATION& process, DWORD& error);
}
