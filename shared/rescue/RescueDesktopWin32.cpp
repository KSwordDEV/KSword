#include "RescueDesktopWin32.h"

#include <sddl.h>
#include <array>
#include <vector>
#include <thread>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "User32.lib")

namespace ks::rescue
{
    DWORD RunDesktopSessionOnFreshThread(const std::function<DWORD()>& session)
    {
        DWORD result = ERROR_GEN_FAILURE;
        try
        {
            std::thread worker([&]() {
                try { result = session(); }
                catch (...) { result = ERROR_UNHANDLED_EXCEPTION; }
            });
            worker.join();
        }
        catch (...) { result = ERROR_NOT_ENOUGH_MEMORY; }
        return result;
    }

    bool IsMouseMessage(const UINT message)
    {
        // 客户区与非客户区都要检查，否则标题栏、缩放边框仍可能接受伪造点击。
        return (message >= WM_MOUSEFIRST && message <= WM_MOUSELAST)
            || (message >= WM_NCMOUSEMOVE && message <= WM_NCMBUTTONDBLCLK)
            || (message >= WM_NCXBUTTONDOWN && message <= WM_NCXBUTTONDBLCLK);
    }

    bool IsKeyboardMessage(const UINT message)
    {
        // 同时包括系统键和字符消息，避免直接发送 WM_CHAR 绕过按键检查。
        return message >= WM_KEYFIRST && message <= WM_KEYLAST;
    }

    bool RejectInjectedMouse(const DWORD flags)
    {
        return (flags & (LLMHF_INJECTED | LLMHF_LOWER_IL_INJECTED)) != 0;
    }

    bool RejectInjectedKeyboard(const DWORD flags)
    {
        return (flags & (LLKHF_INJECTED | LLKHF_LOWER_IL_INJECTED)) != 0;
    }

    bool AcceptInputSource(const UINT message, const INPUT_MESSAGE_SOURCE& source)
    {
        // IMO_HARDWARE 也可能来自 UIAccess 注入，所以监护线程还会检查低级 Hook 注入位。
        // 来源未知、SendMessage/PostMessage 和系统合成输入不作为可信操作放行。
        if (source.originId != IMO_HARDWARE)
        {
            return false;
        }
        if (IsMouseMessage(message))
        {
            return source.deviceType == IMDT_MOUSE;
        }
        return IsKeyboardMessage(message) && source.deviceType == IMDT_KEYBOARD;
    }

    std::wstring DesktopName(const HDESK desktop)
    {
        // 桌面对象名长度由 Windows 返回，缓冲区额外保留一个终止字符。
        DWORD byteCount = 0; // UOI_NAME 所需字节数。
        ::GetUserObjectInformationW(desktop, UOI_NAME, nullptr, 0, &byteCount);
        if (byteCount == 0 || byteCount > 65536)
        {
            return {};
        }
        std::vector<wchar_t> buffer(byteCount / sizeof(wchar_t) + 1, L'\0');
        if (!::GetUserObjectInformationW(desktop, UOI_NAME, buffer.data(), byteCount, &byteCount))
        {
            return {};
        }
        return buffer.data();
    }

    bool IsInputDesktop(const HDESK desktop)
    {
        // 使用持有句柄的 UOI_IO 检查，私有 DACL 会拒绝重新 OpenInputDesktop。
        BOOL active = FALSE; // 是否正在接收用户输入。
        DWORD byteCount = 0; // Windows 返回的实际属性长度。
        return ::GetUserObjectInformationW(desktop, UOI_IO, &active, sizeof(active), &byteCount)
            && active != FALSE;
    }

    HDESK CreatePrivateDesktop(const std::wstring& name)
    {
        PSECURITY_DESCRIPTOR descriptor = nullptr; // LocalAlloc 分配的自相对安全描述符。
        if (!::ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:P(D;;GA;;;OW)", SDDL_REVISION_1, &descriptor, nullptr))
        {
            return nullptr;
        }
        // 创建者获得返回句柄；DACL 无允许 ACE，且所有者也不能按名称重新取得改 ACL 权限。
        SECURITY_ATTRIBUTES security{}; // 桌面句柄仅在后面的创建白名单内继承。
        security.nLength = sizeof(security);
        security.lpSecurityDescriptor = descriptor;
        security.bInheritHandle = TRUE;
        constexpr ACCESS_MASK access = DESKTOP_CREATEWINDOW | DESKTOP_CREATEMENU
            | DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS | DESKTOP_ENUMERATE
            | DESKTOP_SWITCHDESKTOP | DESKTOP_HOOKCONTROL;
        const HDESK desktop = ::CreateDesktopW(name.c_str(), nullptr, nullptr, 0, access, &security);
        const DWORD error = ::GetLastError(); // LocalFree 不得覆盖创建失败的原始错误码。
        ::LocalFree(descriptor);
        ::SetLastError(error);
        return desktop;
    }

    bool LaunchClient(const std::wstring& executable, const std::wstring& originalName,
        const ClientHandles& handles, PROCESS_INFORMATION& process, DWORD& error)
    {
        // HANDLE_LIST 保证只有救援桌面被继承，不暴露原桌面及其他 Taskbar 资源。
        std::array<HANDLE, 4> inherited{ handles.desktop, handles.ready, handles.leave, handles.host };
        SIZE_T bytes = 0; // 启动属性表分配长度。
        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
        std::vector<unsigned char> storage(bytes); // 属性表生存期覆盖 CreateProcess。
        auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
        if (!::InitializeProcThreadAttributeList(attributes, 1, 0, &bytes))
        {
            error = ::GetLastError();
            return false;
        }
        const BOOL whitelistOk = ::UpdateProcThreadAttribute(attributes, 0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited.data(), sizeof(inherited), nullptr, nullptr);
        if (!whitelistOk)
        {
            error = ::GetLastError();
            ::DeleteProcThreadAttributeList(attributes);
            return false;
        }

        // 桌面名和句柄均为本进程生成；原桌面名称禁止引号，避免影响内部参数边界。
        if (originalName.find(L'"') != std::wstring::npos || originalName.empty())
        {
            error = ERROR_INVALID_NAME;
            ::DeleteProcThreadAttributeList(attributes);
            return false;
        }
        const auto number = [](const HANDLE handle)
        {
            return std::to_wstring(reinterpret_cast<ULONG_PTR>(handle));
        };
        const std::wstring desktopName = DesktopName(handles.desktop); // 白名单桌面的精确对象名。
        std::wstring command = L"\"" + executable + L"\" " + kClientArgument
            + L" \"" + desktopName + L"\" " + number(handles.desktop) + L" "
            + number(handles.ready) + L" " + number(handles.leave) + L" " + number(handles.host)
            + L" \"" + originalName + L"\"";
        std::vector<wchar_t> writable(command.begin(), command.end()); // CreateProcess 可写命令行。
        writable.push_back(L'\0');
        STARTUPINFOEXW startup{}; // 指定继承白名单，不依赖默认桌面的按名称访问。
        startup.StartupInfo.cb = sizeof(startup);
        startup.lpAttributeList = attributes;
        const std::wstring directory = executable.substr(0, executable.find_last_of(L"\\/"));
        const BOOL created = ::CreateProcessW(executable.c_str(), writable.data(), nullptr, nullptr,
            TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT, nullptr,
            directory.c_str(), &startup.StartupInfo, &process);
        error = created ? ERROR_SUCCESS : ::GetLastError();
        ::DeleteProcThreadAttributeList(attributes);
        return created != FALSE;
    }
}
