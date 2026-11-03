#pragma once
#include "../../shared/ApiMonitorInjectionProtocol.h"

// ============================================================
// core/MonitorConfig.h
// 作用：
// 1) 定义 Agent 运行时使用的会话配置结构；
// 2) 负责从 Temp\KswordApiMon\config_<pid>.ini 读取监控参数；
// 3) 提供停止标记文件检测，供后台线程轮询退出。
// ============================================================

#include "pch.h"
#include "../WinApiMonitorProtocol.h"

namespace apimon
{
    enum class FakeSuccessReturnType : std::uint32_t
    {
        Scalar = 0,
        Bool = 1,
        Handle = 2,
        Dword = 3,
        NtStatus = 4,
        HResult = 5,
        LStatus = 6,
        SocketInt = 7
    };

    enum class FakeSuccessLastErrorKind : std::uint32_t
    {
        None = 0,
        Win32 = 1,
        Wsa = 2
    };

    // ClipboardPolicyAction：
    // - 剪贴板读/写/枚举三个方向各自独立取值；
    // - 数值故意与驱动协议 KSWORD_ARK_CLIPBOARD_POLICY_ACTION_* 一致（尽管本
    //   Agent 从不直接链接驱动协议头，只是约定同一套编码），主程序在把驱动
    //   查回来的规则解析成这个进程的会话 INI 时不用做额外映射表。
    enum class ClipboardPolicyAction : std::uint32_t
    {
        Allow = 0,
        Block = 1,
        LogOnly = 2
    };

    struct FakeSuccessRule
    {
        std::optional<unsigned> x86StackBytes; // Optional seventh rule field; zero means caller cleanup.
        std::wstring moduleName;                                    // moduleName：规则匹配的模块名，含或不含 .dll 均可由匹配层规范化。
        std::wstring apiName;                                       // apiName：规则匹配的导出 API 名，大小写不敏感。
        FakeSuccessReturnType returnType = FakeSuccessReturnType::Scalar; // returnType：UI 模板选择后的返回语义。
        std::uint64_t returnValue = 0;                              // returnValue：写入 RAX 的标量返回值。
        FakeSuccessLastErrorKind lastErrorKind = FakeSuccessLastErrorKind::None; // lastErrorKind：是否设置 Win32/WSA 错误码。
        std::uint32_t lastErrorValue = 0;                           // lastErrorValue：SetLastError/WSASetLastError 的值。
    };

    // MonitorConfig：
    // - 作用：保存当前目标进程 API 监控配置；
    // - 字段：覆盖命名管道名、停止标记路径、各分类启停和详情长度上限。
    struct MonitorConfig
    {
        std::uint32_t targetPid = 0;            // targetPid：当前被注入进程 PID。
        std::wstring configPath;                // configPath：INI 配置文件完整路径。
        std::wstring pipeName;                  // pipeName：命名管道名。
        std::wstring rootStopFlagPath;
        std::wstring stopFlagPath;              // stopFlagPath：停止标记文件路径。
        std::wstring sessionId;                 // sessionId：UI 为每次启动生成的唯一会话标识，用于捕获短暂 stop/start 的配置切换。
        std::wstring pauseEventName;            // Session-wide read-only pause control, shared with child agents.
        std::wstring agentDllPath;              // agentDllPath：当前 APIMonitor_x64.dll 路径，供子进程自动注入复用。
        std::wstring controllerSid;             // controllerSid：创建会话的控制端 SID，用于 DWM/服务账户管道 ACL。
        ks::winapi_monitor::InjectionEndpoint injectionEndpoint;
        bool enableFile = true;                 // enableFile：是否启用文件 API Hook。
        bool enableRegistry = true;             // enableRegistry：是否启用注册表 API Hook。
        bool enableNetwork = true;              // enableNetwork：是否启用网络 API Hook。
        bool enableProcess = true;              // enableProcess：是否启用进程 API Hook。
        bool enableLoader = true;               // enableLoader：是否启用加载器 API Hook。
        bool autoInjectChild = false;           // autoInjectChild：CreateProcessW 成功后是否自动注入新子进程。
        bool captureCallStack = false;           // Optional bounded strong-hook stack; off by default.
        bool enableRawFallback = false;         // enableRawFallback：是否对强类型表之外的导出安装 Raw ABI 兜底 Hook。
        bool rawUseDefaultDenyList = true;      // rawUseDefaultDenyList：是否启用内置高频/高风险 API 黑名单。
        std::vector<std::wstring> rawModuleList;// rawModuleList：Raw 兜底扫描的模块名目录。
        std::vector<std::wstring> rawDenyList;  // rawDenyList：用户额外 Raw Hook 黑名单；默认黑名单由 rawUseDefaultDenyList 单独控制。
        bool fakeSuccessEnabled = false;        // fakeSuccessEnabled：是否启用 Fake Success 规则，让命中 API 跳过原函数。
        bool fakeSuccessRawFallback = false;    // fakeSuccessRawFallback：是否允许未强类型覆盖 API 使用通用 RAX fake-return stub。
        std::vector<FakeSuccessRule> fakeSuccessRules; // fakeSuccessRules：按 module!api 精确匹配的伪返回规则。
        std::wstring fakeSuccessRulesText;      // fakeSuccessRulesText：原始规则文本，用于自动注入子进程继承。
        std::size_t detailLimitChars = 256;     // detailLimitChars：详情文本截断长度。
        bool valid = false;                     // valid：当前配置是否通过基本校验。

        // enableClipboard：剪贴板保护总开关。关闭时 Win32/OLE/win32u 三层剪贴板 hook
        // 全部不安装，与其它 enableXxx 分类字段同级，但剪贴板 hook 不算进通用监控分类，
        // 单独一个开关，因为它服务的是"剪贴板保护"这一具体功能而不是泛用 API 监控。
        bool enableClipboard = false;
        // clipboardReadAction/WriteAction/EnumAction：三个方向各自独立的策略动作，
        // 由主程序按当前受管进程身份从驱动策略表解析后写进这个进程的会话 INI；
        // ClipboardGuardHook.cpp 里的每个 hook 调用时都读取一次，支持热更新。
        ClipboardPolicyAction clipboardReadAction = ClipboardPolicyAction::Allow;
        ClipboardPolicyAction clipboardWriteAction = ClipboardPolicyAction::Allow;
        ClipboardPolicyAction clipboardEnumAction = ClipboardPolicyAction::Allow;
    };

    bool LoadMonitorConfigForCurrentProcess(MonitorConfig* configOut, std::wstring* errorTextOut);
    bool IsStopFlagPresent(const MonitorConfig& configValue);
}
