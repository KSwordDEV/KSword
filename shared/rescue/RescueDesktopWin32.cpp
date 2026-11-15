#include "RescueDesktopWin32.h"

#include <bcrypt.h>
#include <sddl.h>
#include <array>
#include <vector>
#include <thread>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "User32.lib")

namespace ks::rescue
{
    // 输入阶段、Win32 错误和值，追加到 exe 同目录 logs；不在输入 Hook 内调用，保留 LastError。
    void LogStage(const wchar_t* stage, const DWORD error,
        const DWORD value, const std::wstring& detail)
    {
        const DWORD savedError = ::GetLastError(); // 诊断不能覆盖调用方正在处理的 API 错误。
        std::array<wchar_t, 32768> path{}; // 当前 exe 路径，用于定位发行目录中的日志。
        const DWORD length = ::GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        if (length != 0 && length < path.size())
        {
            const std::wstring executable(path.data(), length); // 避免使用不可控的当前工作目录。
            const std::wstring directory = executable.substr(0, executable.find_last_of(L"\\/")) + L"\\logs";
            ::CreateDirectoryW(directory.c_str(), nullptr);
            const std::wstring filename = directory + L"\\sos-rescue-"
                + std::to_wstring(::GetCurrentProcessId()) + L".log";
            const HANDLE file = ::CreateFileW(filename.c_str(), FILE_APPEND_DATA,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL, nullptr);
            if (file != INVALID_HANDLE_VALUE)
            {
                // 只记录启动状态、错误和桌面名称，不保存键盘输入或继承句柄值。
                const std::wstring line = std::to_wstring(::GetTickCount64()) + L" " + stage
                    + L" error=" + std::to_wstring(error) + L" value=" + std::to_wstring(value)
                    + (detail.empty() ? L"" : L" detail=" + detail) + L"\r\n";
                const int bytes = ::WideCharToMultiByte(CP_UTF8, 0, line.data(),
                    static_cast<int>(line.size()), nullptr, 0, nullptr, nullptr);
                if (bytes > 0)
                {
                    std::vector<char> utf8(static_cast<size_t>(bytes)); // 跨语言系统也能读取桌面名。
                    ::WideCharToMultiByte(CP_UTF8, 0, line.data(), static_cast<int>(line.size()),
                        utf8.data(), bytes, nullptr, nullptr);
                    DWORD written = 0; // WriteFile 的实际追加长度。
                    ::WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
                }
                ::CloseHandle(file);
            }
        }
        ::SetLastError(savedError);
    }

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

    DWORD BindClientDesktop(const HDESK desktop, const std::wstring& expectedName)
    {
        if (expectedName.rfind(kDesktopPrefix, 0) != 0)
        {
            LogStage(L"client.desktop_arguments_invalid", ERROR_INVALID_NAME);
            return ERROR_INVALID_NAME;
        }
        const std::wstring inheritedName = DesktopName(desktop); // 核对真实继承对象，而非只相信命令行。
        if (inheritedName.empty())
        {
            LogStage(L"client.inherited_desktop_invalid", ERROR_INVALID_HANDLE);
            return ERROR_INVALID_HANDLE;
        }
        if (inheritedName != expectedName)
        {
            LogStage(L"client.inherited_desktop_mismatch", ERROR_INVALID_DATA, 0, inheritedName);
            return ERROR_INVALID_DATA;
        }

        const DWORD threadId = ::GetCurrentThreadId(); // 后续创建 Qt 窗口的线程。
        const std::wstring currentName = DesktopName(::GetThreadDesktop(threadId));
        if (currentName == expectedName)
        {
            // 初始桌面的系统句柄可能不同于继承句柄，已有窗口时重复绑定也可返回 ERROR_BUSY。
            return ERROR_SUCCESS;
        }
        if (!::SetThreadDesktop(desktop))
        {
            const DWORD error = ::GetLastError();
            LogStage(L"client.desktop_bind_failed", error, 0, currentName);
            return error;
        }

        // 显式绑定仅在尚未连到目标桌面时发生，成功后读回实际对象。
        const std::wstring boundName = DesktopName(::GetThreadDesktop(threadId));
        if (boundName != expectedName)
        {
            LogStage(L"client.desktop_mismatch", ERROR_INVALID_DATA, 0, boundName);
            return ERROR_INVALID_DATA;
        }
        return ERROR_SUCCESS;
    }

    HDESK CreatePrivateDesktop()
    {
        // CreateDesktopW may open an existing object and ignore our security descriptor.
        // Keep the name unpredictable until Windows has created the desktop.
        std::array<UCHAR, 16> randomBytes{};
        if (BCryptGenRandom(nullptr, randomBytes.data(), static_cast<ULONG>(randomBytes.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        {
            ::SetLastError(ERROR_GEN_FAILURE);
            return nullptr;
        }
        constexpr wchar_t hex[] = L"0123456789abcdef";
        std::wstring name = kDesktopPrefix;
        for (const UCHAR byte : randomBytes)
        {
            name += hex[byte >> 4];
            name += hex[byte & 0x0f];
        }

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
        const std::wstring desktopName = DesktopName(handles.desktop); // 给客户端核对继承的桌面身份。
        if (desktopName.empty() || originalName.empty() || originalName.find(L'"') != std::wstring::npos)
        {
            error = ERROR_INVALID_NAME;
            return false;
        }

        // HANDLE_LIST 只交付本次会话的四个句柄，原桌面和监护进程的其余句柄留在监护端。
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

        // 传递本次创建的桌面名和句柄，供客户端核验绑定。
        const auto number = [](const HANDLE handle)
        {
            return std::to_wstring(reinterpret_cast<ULONG_PTR>(handle));
        };
        std::wstring command = L"\"" + executable + L"\" " + kClientArgument
            + L" \"" + desktopName + L"\" " + number(handles.desktop) + L" "
            + number(handles.ready) + L" " + number(handles.leave) + L" " + number(handles.host)
            + L" \"" + originalName + L"\"";
        std::vector<wchar_t> writable(command.begin(), command.end()); // CreateProcess 可写命令行。
        writable.push_back(L'\0');
        STARTUPINFOEXW startup{}; // 指定继承白名单，不依赖默认桌面的按名称访问。
        startup.StartupInfo.cb = sizeof(startup);
        // 空字符串让首次 USER32 连接从继承句柄选择桌面。
        // 省略该字段时现场回归读到的是 Default。传桌面名则会触发 DACL 拒绝按名打开。
        wchar_t inheritDesktop[] = L"";
        startup.StartupInfo.lpDesktop = inheritDesktop;
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
