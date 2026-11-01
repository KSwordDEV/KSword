#pragma once

// ============================================================
// shared/WinApiMonitorProtocol.h
// 作用：
// 1) 定义 Ksword 主程序与 APIMonitor_x64 DLL 共用的协议常量；
// 2) 统一命名管道、配置文件、停止标记文件的命名规则；
// 3) 定义固定长度事件包，避免 UI 与 Agent 在结构布局上漂移。
// ============================================================

#include <cstdint>
#include <atomic>
#include <iterator>
#include <string>
#include <type_traits>
#include <vector>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <Aclapi.h>
#include <Sddl.h>

namespace ks::winapi_monitor
{
    // A kernel object lease works across UI/background threads and KSword instances.
    // CloseHandle releases ownership regardless of the thread that acquired it.
    class SessionLease
    {
    public:
        SessionLease() = default;
        ~SessionLease() { reset(); }
        SessionLease(const SessionLease&) = delete;
        SessionLease& operator=(const SessionLease&) = delete;
        SessionLease(SessionLease&& other) noexcept : m_handle(other.m_handle), m_pid(other.m_pid)
        { other.m_handle = nullptr; other.m_pid = 0; }
        SessionLease& operator=(SessionLease&& other) noexcept
        {
            if (this != &other) { reset(); m_handle = other.m_handle; m_pid = other.m_pid;
                other.m_handle = nullptr; other.m_pid = 0; }
            return *this;
        }
        bool acquire(std::uint32_t pid, DWORD* error)
        {
            if (m_handle && m_pid == pid) return true;
            if (m_handle || !pid) { if (error) *error = ERROR_BUSY; return false; }
            const std::wstring name = L"Global\\KswordApiMonSessionLease_" + std::to_wstring(pid);
            HANDLE handle = ::CreateEventW(nullptr, TRUE, FALSE, name.c_str());
            const DWORD status = ::GetLastError();
            if (!handle || status == ERROR_ALREADY_EXISTS)
            {
                if (handle) ::CloseHandle(handle);
                if (error) *error = handle ? ERROR_BUSY : status;
                return false;
            }
            m_handle = handle; m_pid = pid;
            if (error) *error = ERROR_SUCCESS;
            return true;
        }
        void reset() { if (m_handle) ::CloseHandle(m_handle); m_handle = nullptr; m_pid = 0; }
        std::uint32_t pid() const { return m_pid; }
    private:
        HANDLE m_handle = nullptr;
        std::uint32_t m_pid = 0;
    };

    // kProtocolVersion：
    // - 作用：协议版本号；
    // - 调用：UI 和 Agent 在收发事件包时都可用于快速校验结构兼容性。
    inline constexpr std::uint32_t kProtocolVersion = 0x20261003U;

    // kMaxModuleNameChars / kMaxApiNameChars / kMaxDetailChars：
    // - 作用：定义固定长度宽字符缓冲大小；
    // - 说明：采用固定长度是为了便于命名管道直接传输整包结构。
    inline constexpr std::size_t kMaxModuleNameChars = 32;
    inline constexpr std::size_t kMaxApiNameChars = 64;
    inline constexpr std::size_t kMaxDetailChars = 320;

    // kDefaultRawHookModules：
    // - 输入：无；
    // - 处理：作为 UI 和 Agent 共享的 Raw Fallback 默认模块目录，覆盖常见 Win32/网络/COM/加密/服务相关 DLL；
    //   ntdll 的 syscall/CRT-adjacent 导出不适合通用 Raw hook，仍由强类型 Nt* 表和精确 Fake Success 规则覆盖。
    // - 返回：以分号分隔的模块名文本，调用方按需拆分成可编辑列表。
    inline constexpr const wchar_t* kDefaultRawHookModules =
        L"KernelBase.dll;kernel32.dll;advapi32.dll;user32.dll;gdi32.dll;gdi32full.dll;"
        L"ws2_32.dll;wininet.dll;winhttp.dll;iphlpapi.dll;dnsapi.dll;netapi32.dll;secur32.dll;"
        L"rpcrt4.dll;ole32.dll;oleaut32.dll;combase.dll;shell32.dll;shlwapi.dll;crypt32.dll;"
        L"bcrypt.dll;ncrypt.dll;wintrust.dll;urlmon.dll;psapi.dll;wtsapi32.dll;version.dll;"
        L"userenv.dll;profapi.dll;samcli.dll;wldap32.dll;setupapi.dll;cfgmgr32.dll;wevtapi.dll;tdh.dll";

    // kDefaultRawHookDenyList：
    // - 输入：无；
    // - 处理：Raw Fallback 默认排除高频/基础运行时/同步/loader/内存字符串类 API，支持调用方按 exact 或 prefix* 匹配；
    // - 返回：以分号分隔的函数名/通配前缀列表；强类型 Hook 不受该黑名单影响。
    // - 说明：该列表是“内置默认黑名单”，由 raw_use_default_denylist 单独控制；raw_denylist 仅承载用户额外规则。
    inline constexpr const wchar_t* kDefaultRawHookDenyList =
        L"Rtl*;Ldr*;memcpy;memmove;memset;memcmp;memchr;CopyMemory;MoveMemory;ZeroMemory;FillMemory;SecureZeroMemory;"
        L"str*;_str*;wcs*;_wcs*;mbs*;_mbs*;lstr*;strlen;strcmp;strncmp;sprintf*;swprintf*;vsprintf*;vswprintf*;"
        L"StringCch*;StringCb*;RtlAllocateHeap;RtlFreeHeap;RtlReAllocateHeap;HeapAlloc;HeapFree;HeapReAlloc;HeapSize;"
        L"HeapValidate;HeapCompact;HeapWalk;GetProcessHeap;GetProcessHeaps;LocalAlloc;LocalFree;LocalReAlloc;"
        L"GlobalAlloc;GlobalFree;GlobalReAlloc;malloc;free;calloc;realloc;GetLastError;SetLastError;RtlGetLastWin32Error;"
        L"RtlSetLastWin32Error;EnterCriticalSection;LeaveCriticalSection;TryEnterCriticalSection;"
        L"InitializeCriticalSection*;DeleteCriticalSection;AcquireSRWLock*;ReleaseSRWLock*;"
        L"Nt*;Zw*;WaitForSingleObject;WaitForSingleObjectEx;WaitForMultipleObjects;WaitForMultipleObjectsEx;"
        L"WaitOnAddress;WakeByAddress*;Sleep;SleepEx;"
        L"QueryPerformanceCounter;QueryPerformanceFrequency;"
        L"GetTickCount;GetTickCount64;GetSystemTime*;GetLocalTime;GetTimeZoneInformation*;"
        L"TlsGetValue;TlsSetValue;FlsGetValue;FlsSetValue;Interlocked*;GetCurrentProcess*;GetCurrentThread*;"
        L"GetModuleHandle*;GetModuleFileName*;CloseHandle;EncodePointer;DecodePointer;IsBad*;"
        L"GetProcAddress;LoadLibrary*;FreeLibrary";

    // EventCategory：
    // - 作用：统一标记 API 事件所属大类；
    // - 调用：UI 侧按 category 渲染颜色、过滤和统计。
    enum class EventCategory : std::uint32_t
    {
        Unknown = 0,
        File = 1,
        Registry = 2,
        Network = 3,
        Process = 4,
        Loader = 5,
        Internal = 6,
        // Clipboard：剪贴板保护专用分类，独立于 Process 之外，方便"剪贴板保护"
        // 页面按 category 过滤自己的事件，不用跟通用进程类事件混在一起。
        // 只追加不改已有数值，保持旧 Agent/旧 UI 组合的协议兼容。
        Clipboard = 7
    };

    enum class EventKind : std::uint32_t
    {
        ApiCall = 0, IoSubmit = 1, IoWait = 2, IoComplete = 3, IoCancel = 4,
        CoverageBegin = 16, CoverageItem = 17, CoverageEnd = 18
    };
    enum class HookKind : std::uint32_t { Strong = 0, Raw = 1, Fake = 2, DynamicExtension = 3 };
    enum class CoverageState : std::uint32_t
    {
        Installed = 0, SharedEntry = 1, CategoryDisabled = 2, WaitingModule = 3,
        ExportMissing = 4, RuleExcluded = 5, RetryableFailure = 6, Unsupported = 7, Removed = 8
    };
    inline std::uint64_t sessionIdentity(const std::wstring& text)
    {
        if (text.empty()) return 0;
        std::uint64_t value = 14695981039346656037ULL;
        for (const wchar_t ch : text) { value ^= static_cast<std::uint16_t>(ch); value *= 1099511628211ULL; }
        return value != 0 ? value : 1;
    }
    inline bool isCoverageEvent(const std::uint32_t kind)
    { return kind >= static_cast<std::uint32_t>(EventKind::CoverageBegin) && kind <= static_cast<std::uint32_t>(EventKind::CoverageEnd); }

    enum class EventResultKind : std::uint32_t { StatusCode = 0, EntryOnly = 1 };

    // ApiMonitorEventPacket：
    // - 作用：命名管道中传输的固定长度事件包；
    // - 调用：Agent 填充后整包 WriteFile，UI 整包 ReadFile 后直接解析。
    struct ApiMonitorEventPacket
    {
        std::uint32_t size = sizeof(ApiMonitorEventPacket);     // size：当前结构大小。
        std::uint32_t version = kProtocolVersion;               // version：协议版本号。
        std::uint32_t pid = 0;                                  // pid：触发 API 的进程 ID。
        std::uint32_t tid = 0;                                  // tid：触发 API 的线程 ID。
        std::uint64_t timestamp100ns = 0;                       // timestamp100ns：FILETIME 基准时间戳。
        std::uint32_t category = 0;                             // category：EventCategory 数值。
        std::int32_t resultCode = 0;                            // resultCode：Win32/LSTATUS/WSA 错误码。
        wchar_t moduleName[kMaxModuleNameChars] = {};           // moduleName：API 所属模块名。
        wchar_t apiName[kMaxApiNameChars] = {};                 // apiName：API 名称。
        wchar_t detailText[kMaxDetailChars] = {};               // detailText：压缩后的详情文本。
        std::uint32_t resultKind = static_cast<std::uint32_t>(EventResultKind::StatusCode);
        std::uint32_t eventKind = static_cast<std::uint32_t>(EventKind::ApiCall);
        std::uint32_t apiId = 0;
        std::uint32_t coverageState = 0;
        std::uint32_t hookKind = 0;
        std::uint32_t snapshotIndex = 0;
        std::uint32_t snapshotCount = 0;
        std::uint64_t sessionIdentity = 0;
        std::uint64_t operationId = 0;
        // Coverage packets: this snapshot revision. HooksRemoved: the final
        // required revision (0 from older agents means unknown).
        std::uint64_t snapshotRevision = 0;
        std::uint64_t hookAddress = 0;
        char definitionSha256[65] = {};
    };

    static_assert(sizeof(ApiMonitorEventPacket) == 1000, "Windows event packet ABI mismatch");

    static_assert(
        std::is_trivially_copyable_v<ApiMonitorEventPacket>,
        "ApiMonitorEventPacket 必须可平凡复制，便于直接通过管道收发。");

    // Byte pipes have no message boundaries. Read only available bytes, so an idle
    // reader can observe stop even if cancellation races with starting its next read.
    inline bool readEventPacket(HANDLE pipe, ApiMonitorEventPacket* packet, const std::atomic_bool& stop)
    {
        if (!packet) return false;
        DWORD offset = 0;
        while (offset < sizeof(*packet) && !stop.load())
        {
            DWORD available = 0;
            if (!::PeekNamedPipe(pipe, nullptr, 0, nullptr, &available, nullptr)) return false;
            if (available == 0) { ::Sleep(10); continue; }
            const DWORD remaining = static_cast<DWORD>(sizeof(*packet)) - offset;
            const DWORD requested = available < remaining ? available : remaining;
            DWORD received = 0;
            if (!::ReadFile(pipe, reinterpret_cast<unsigned char*>(packet) + offset, requested, &received, nullptr)
                || received == 0) return false;
            offset += received;
        }
        return offset == sizeof(*packet);
    }

    // trimTrailingSlash：
    // - 作用：把目录尾部多余的 '\\' 或 '/' 去掉；
    // - 调用：拼接会话目录、配置文件路径前统一规范化。
    inline std::wstring trimTrailingSlash(const std::wstring& pathText)
    {
        std::wstring normalizedText = pathText;
        while (!normalizedText.empty())
        {
            const wchar_t lastChar = normalizedText.back();
            if (lastChar != L'\\' && lastChar != L'/')
            {
                break;
            }
            normalizedText.pop_back();
        }
        return normalizedText;
    }

    // joinPath：
    // - 作用：用 Windows 风格拼接目录与文件名；
    // - 调用：构造会话目录、INI 路径、停止标记文件路径。
    inline std::wstring joinPath(const std::wstring& leftPath, const std::wstring& rightPath)
    {
        if (leftPath.empty())
        {
            return rightPath;
        }

        const std::wstring normalizedLeft = trimTrailingSlash(leftPath);
        if (normalizedLeft.empty())
        {
            return rightPath;
        }
        return normalizedLeft + L"\\" + rightPath;
    }

    // queryTempDirectory：
    // - 作用：返回所有账户都能解析到的机器临时目录；
    // - 调用：UI 写配置和停止标记文件、Agent 读取会话配置时复用。
    // - 说明：不能使用调用者自己的 GetTempPathW。注入到 SYSTEM、DWM
    //   或服务账户后，目标进程会得到另一套 TEMP，Agent 将永远找不到 UI 写的 INI。
    inline std::wstring queryTempDirectory()
    {
        wchar_t windowsBuffer[4096] = {};
        const DWORD charCount = ::GetWindowsDirectoryW(
            windowsBuffer,
            static_cast<DWORD>(std::size(windowsBuffer)));
        if (charCount == 0 || charCount >= std::size(windowsBuffer))
        {
            return std::wstring(L".");
        }
        return joinPath(trimTrailingSlash(std::wstring(windowsBuffer, charCount)), L"Temp");
    }

    // buildSessionDirectory：
    // - 作用：返回 WinAPI 监控会话目录；
    // - 调用：所有 pid 相关的会话文件都放在该目录下，避免散落在 Temp 根目录。
    inline std::wstring buildSessionDirectory()
    {
        return joinPath(queryTempDirectory(), L"KswordApiMon");
    }

    inline bool queryProcessUserSid(
        const std::uint32_t pidValue,
        std::vector<unsigned char>* const sidOut,
        std::wstring* const errorTextOut = nullptr)
    {
        if (sidOut == nullptr || pidValue == 0)
        {
            if (errorTextOut) *errorTextOut = L"invalid process SID query arguments.";
            return false;
        }
        sidOut->clear();
        const HANDLE process = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pidValue);
        if (!process)
        {
            if (errorTextOut) *errorTextOut = L"OpenProcess for session SID failed. error=" + std::to_wstring(::GetLastError());
            return false;
        }
        HANDLE token = nullptr;
        bool ok = ::OpenProcessToken(process, TOKEN_QUERY, &token) != FALSE;
        DWORD error = ok ? ERROR_SUCCESS : ::GetLastError();
        if (ok)
        {
            DWORD bytes = 0;
            (void)::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
            if (bytes == 0)
            {
                error = ::GetLastError();
                ok = false;
            }
            else
            {
                std::vector<unsigned char> buffer(bytes);
                if (!::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes))
                {
                    error = ::GetLastError();
                    ok = false;
                }
                else
                {
                    const auto* const user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
                    if (!::IsValidSid(user->User.Sid))
                    {
                        error = ERROR_INVALID_SID;
                        ok = false;
                    }
                    else
                    {
                        const DWORD sidBytes = ::GetLengthSid(user->User.Sid);
                        sidOut->resize(sidBytes);
                        ok = ::CopySid(sidBytes, sidOut->data(), user->User.Sid) != FALSE;
                        error = ok ? ERROR_SUCCESS : ::GetLastError();
                    }
                }
            }
        }
        if (token) ::CloseHandle(token);
        ::CloseHandle(process);
        if (!ok && errorTextOut) *errorTextOut = L"query target process SID failed. error=" + std::to_wstring(error);
        ::SetLastError(error);
        return ok;
    }

    inline bool currentProcessUserSidString(std::wstring* const sidTextOut)
    {
        if (sidTextOut == nullptr) return false;
        sidTextOut->clear();
        HANDLE token = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        DWORD bytes = 0;
        (void)::GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
        std::vector<unsigned char> buffer(bytes);
        const bool queried = bytes != 0 && ::GetTokenInformation(token, TokenUser, buffer.data(), bytes, &bytes) != FALSE;
        bool converted = false;
        if (queried)
        {
            const auto* const user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
            LPWSTR text = nullptr;
            if (::ConvertSidToStringSidW(user->User.Sid, &text))
            {
                *sidTextOut = text;
                ::LocalFree(text);
                converted = true;
            }
        }
        ::CloseHandle(token);
        return converted;
    }

    inline bool addSessionDirectoryReader(const std::uint32_t pidValue, std::wstring* const errorTextOut = nullptr)
    {
        std::vector<unsigned char> sid;
        if (!queryProcessUserSid(pidValue, &sid, errorTextOut)) return false;
        const std::wstring root = buildSessionDirectory();
        if (!::CreateDirectoryW(root.c_str(), nullptr) && ::GetLastError() != ERROR_ALREADY_EXISTS)
        {
            if (errorTextOut) *errorTextOut = L"create monitor session directory failed. error=" + std::to_wstring(::GetLastError());
            return false;
        }
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = FILE_TRAVERSE | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid.data());
        PACL existing = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        DWORD aclError = ::GetNamedSecurityInfoW(
            const_cast<LPWSTR>(root.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &existing, nullptr, &descriptor);
        if (aclError == ERROR_SUCCESS)
        {
            PACL updated = nullptr;
            aclError = ::SetEntriesInAclW(1, &access, existing, &updated);
            if (aclError == ERROR_SUCCESS)
            {
                const DWORD setError = ::SetNamedSecurityInfoW(
                    const_cast<LPWSTR>(root.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, updated, nullptr);
                aclError = setError;
            }
            if (updated) ::LocalFree(updated);
        }
        if (descriptor) ::LocalFree(descriptor);
        if (aclError != ERROR_SUCCESS)
        {
            if (errorTextOut) *errorTextOut = L"build monitor session ACL failed. error=" + std::to_wstring(aclError);
            return false;
        }
        return true;
    }

    inline bool grantSessionFileRead(const std::wstring& path, const std::uint32_t pidValue,
        std::wstring* const errorTextOut = nullptr)
    {
        std::vector<unsigned char> sid;
        if (!queryProcessUserSid(pidValue, &sid, errorTextOut)) return false;
        EXPLICIT_ACCESSW access{};
        access.grfAccessPermissions = FILE_GENERIC_READ | SYNCHRONIZE;
        access.grfAccessMode = GRANT_ACCESS;
        access.grfInheritance = NO_INHERITANCE;
        access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        access.Trustee.TrusteeType = TRUSTEE_IS_USER;
        access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(sid.data());
        PACL existing = nullptr;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        DWORD aclError = ::GetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, &existing, nullptr, &descriptor);
        PACL updated = nullptr;
        if (aclError == ERROR_SUCCESS)
            aclError = ::SetEntriesInAclW(1, &access, existing, &updated);
        if (aclError != ERROR_SUCCESS)
        {
            if (descriptor) ::LocalFree(descriptor);
            if (errorTextOut) *errorTextOut = L"build monitor file ACL failed. error=" + std::to_wstring(aclError);
            return false;
        }
        const DWORD setError = ::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(path.c_str()), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
            nullptr, nullptr, updated, nullptr);
        if (updated) ::LocalFree(updated);
        if (descriptor) ::LocalFree(descriptor);
        if (setError != ERROR_SUCCESS)
        {
            if (errorTextOut) *errorTextOut = L"set monitor file ACL failed. error=" + std::to_wstring(setError);
            return false;
        }
        return true;
    }

    // buildPipeNameForPid：
    // - 作用：按 PID 生成固定命名管道名；
    // - 调用：UI 作为客户端连接，Agent 作为服务端创建。
    inline std::wstring buildPipeNameForPid(const std::uint32_t pidValue)
    {
        return std::wstring(L"\\\\.\\pipe\\KswordApiMon_") + std::to_wstring(pidValue);
    }

    // buildConfigPathForPid：
    // - 作用：按 PID 生成会话 INI 配置文件路径；
    // - 调用：UI 启动监控前写入，Agent 注入后读取。
    inline std::wstring buildConfigPathForPid(const std::uint32_t pidValue)
    {
        return joinPath(
            buildSessionDirectory(),
            std::wstring(L"config_") + std::to_wstring(pidValue) + L".ini");
    }

    // buildStopFlagPathForPid：
    // - 作用：按 PID 生成“停止标记”文件路径；
    // - 调用：UI 停止监控时创建该文件，Agent 后台轮询检测并卸载 Hook。
    inline std::wstring buildStopFlagPathForPid(const std::uint32_t pidValue)
    {
        return joinPath(
            buildSessionDirectory(),
            std::wstring(L"stop_") + std::to_wstring(pidValue) + L".flag");
    }

    // eventCategoryToText：
    // - 作用：把事件分类枚举转换为可读宽字符串；
    // - 调用：UI 渲染表格、Agent 生成内部诊断文本时复用。
    inline std::wstring eventCategoryToText(const EventCategory categoryValue)
    {
        switch (categoryValue)
        {
        case EventCategory::File:
            return L"文件";
        case EventCategory::Registry:
            return L"注册表";
        case EventCategory::Network:
            return L"网络";
        case EventCategory::Process:
            return L"进程";
        case EventCategory::Loader:
            return L"加载器";
        case EventCategory::Internal:
            return L"内部";
        case EventCategory::Clipboard:
            return L"剪贴板";
        default:
            break;
        }
        return L"未知";
    }
}
