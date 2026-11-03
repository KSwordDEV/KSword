#include "pch.h"
#include "HookTargets.h"
#include "HookEngine.h"
#include "ClipboardGuardHook.h"
#include "ClipboardGuardVTableHook.h"
#include "ClipboardGuardWin32u.h"
#include "../MonitorAgent.h"
#include "../core/MonitorPipe.h"
#include "../core/MonitorCoverage.h"
#include "../core/MonitorDiagnostics.h"
#include "../core/MonitorAsyncIo.h"
#include "ContextThunk.h"
#include "ExportCatalog.h"
#include "RawAbiSnapshot.h"
#include "HookCallStack.h"
#include "../../shared/ApiMonitorInjection.h"
#ifdef _M_IX86
#include "../../APIMonitor_x86/hook/EntryStubs.h"
#endif

#include <WinReg.h>
#include <bcrypt.h>
#include <evntrace.h>
#include <evntprov.h>
#include <ncrypt.h>
#include <objbase.h>
#include <psapi.h>
#include <rpc.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <urlmon.h>
#include <wincrypt.h>
#include <windns.h>
#include <winhttp.h>
#include <winioctl.h>
#include <mswsock.h>
#include <wininet.h>
#include <winsvc.h>
#include <winternl.h>
#include <wintrust.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif
#ifndef FSCTL_REQUEST_FILTER_OPLOCK
#define FSCTL_REQUEST_FILTER_OPLOCK CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

typedef enum _KS_FILE_INFORMATION_CLASS
{
    KsFileBasicInformation = 4,
    KsFileRenameInformation = 10,
    KsFileDispositionInformation = 13,
    KsFilePositionInformation = 14,
    KsFileEndOfFileInformation = 20,
    KsFileDispositionInformationEx = 64,
    KsFileRenameInformationEx = 65
} KS_FILE_INFORMATION_CLASS;

typedef enum _KS_KEY_INFORMATION_CLASS
{
    KsKeyBasicInformation = 0,
    KsKeyNodeInformation = 1,
    KsKeyFullInformation = 2,
    KsKeyNameInformation = 3,
    KsKeyCachedInformation = 4,
    KsKeyFlagsInformation = 5,
    KsKeyVirtualizationInformation = 6,
    KsKeyHandleTagsInformation = 7,
    KsKeyTrustInformation = 8,
    KsKeyLayerInformation = 9
} KS_KEY_INFORMATION_CLASS;

typedef enum _KS_KEY_VALUE_INFORMATION_CLASS
{
    KsKeyValueBasicInformation = 0,
    KsKeyValueFullInformation = 1,
    KsKeyValuePartialInformation = 2,
    KsKeyValueFullInformationAlign64 = 3,
    KsKeyValuePartialInformationAlign64 = 4,
    KsKeyValueLayerInformation = 5
} KS_KEY_VALUE_INFORMATION_CLASS;

typedef struct _KS_CLIENT_ID
{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} KS_CLIENT_ID, *PKS_CLIENT_ID;

struct KS_ALPC_PORT_ATTRIBUTES;
struct KS_PORT_MESSAGE;
struct KS_ALPC_MESSAGE_ATTRIBUTES;

namespace apimon
{
    namespace
    {
        using KsIoApcRoutine = VOID(NTAPI*)(PVOID, PIO_STATUS_BLOCK, ULONG);
        using HostEntPtr = hostent*;
        struct ExtensionContext;
#include "ApiMonitorDeclarations.inc"
#ifdef _M_IX86
#include "ApiMonitorStackAbi.inc"
#endif




        // 剪贴板相关的原函数指针类型定义已迁移到 hook/ClipboardGuardHook.h。




        // 剪贴板相关的 InlineHookRecord 已迁移到 hook/ClipboardGuardHook.cpp。

        std::mutex g_hookOperationMutex;
        bool g_coverageRemovalInProgress = false;

        const wchar_t* FsctlCodeToText(const ULONG fsControlCode)
        {
            switch (fsControlCode)
            {
            case FSCTL_REQUEST_OPLOCK:
                return L"FSCTL_REQUEST_OPLOCK";
            case FSCTL_REQUEST_BATCH_OPLOCK:
                return L"FSCTL_REQUEST_BATCH_OPLOCK";
            case FSCTL_REQUEST_FILTER_OPLOCK:
                return L"FSCTL_REQUEST_FILTER_OPLOCK";
            case FSCTL_OPLOCK_BREAK_ACKNOWLEDGE:
                return L"FSCTL_OPLOCK_BREAK_ACKNOWLEDGE";
            case FSCTL_OPBATCH_ACK_CLOSE_PENDING:
                return L"FSCTL_OPBATCH_ACK_CLOSE_PENDING";
            case FSCTL_OPLOCK_BREAK_NOTIFY:
                return L"FSCTL_OPLOCK_BREAK_NOTIFY";
            case FSCTL_REQUEST_OPLOCK_LEVEL_1:
                return L"FSCTL_REQUEST_OPLOCK_LEVEL_1";
            case FSCTL_REQUEST_OPLOCK_LEVEL_2:
                return L"FSCTL_REQUEST_OPLOCK_LEVEL_2";
            default:
                return L"UNKNOWN_FSCTL";
            }
        }

        // 剪贴板相关的原函数指针定义已迁移到 hook/ClipboardGuardHook.cpp。


        thread_local bool g_hookReentryGuard = false;

        class ScopedHookGuard
        {
        public:
            explicit ScopedHookGuard(const bool allowCallStack = true)
            {
                m_bypass = IsInlineHookInternalBypassActive() || g_hookReentryGuard;
                if (!m_bypass)
                {
                    g_hookReentryGuard = true;
                    if (allowCallStack && ActiveConfig().captureCallStack) CaptureHookCallStack();
                }
            }

            ~ScopedHookGuard()
            {
                if (!m_bypass)
                {
                    ClearHookCallStack();
                    g_hookReentryGuard = false;
                }
            }

            bool bypass() const
            {
                return m_bypass;
            }

        private:
            bool m_bypass = false;
        };

        using CoveragePacket = ks::winapi_monitor::ApiMonitorEventPacket;
        using CoverageState = ks::winapi_monitor::CoverageState;
        using HookKind = ks::winapi_monitor::HookKind;
        auto& g_rawCoverageObservations = *new std::unordered_map<std::wstring, CoveragePacket>;
        auto& g_removedCoverageRows = *new std::vector<CoveragePacket>;
        CoveragePacket MakeCoverageRow(const wchar_t* module, const wchar_t* api, HookKind kind,
            CoverageState state, const wchar_t* detail, const InlineHookRecord* record = nullptr);
        void CaptureRemovedRawCoverage();
        void CaptureRemovedFakeCoverage();
        void PublishConfiguredCoverage();

        struct HookBinding
        {
            const wchar_t* moduleName;                              // moduleName：导出所在模块名。
            const char* procName;                                   // procName：导出函数名。
            ks::winapi_monitor::EventCategory categoryValue;        // categoryValue：对应监控分类。
            InlineHookRecord* hookRecord;                           // hookRecord：该 API 对应的 Hook 状态记录。
            void* hookAddress;                                      // hookAddress：Hooked wrapper 函数地址。
            void** originalOut;                                     // originalOut：Trampoline 返回地址。
        };

        struct RawHookBinding
        {
            std::uint32_t apiId = 0;
            std::wstring moduleName;                                // moduleName：Raw Hook 目标模块名。
            std::string procName;                                   // procName：Raw Hook 目标导出名。
            std::wstring procNameWide;                              // procNameWide：事件上报使用的宽字符导出名。
            ks::winapi_monitor::EventCategory categoryValue = ks::winapi_monitor::EventCategory::Process; // categoryValue：按模块粗略归类。
            InlineHookRecord hookRecord{};                          // hookRecord：Raw Hook inline patch 状态。
            void* originalAddress = nullptr;                        // originalAddress：InstallInlineHook 生成的 trampoline。
            void* entryStubAddress = nullptr;                       // entryStubAddress：动态生成的通用入口 stub。
        };

        struct FakeSuccessRuntimeRule
        {
            std::optional<unsigned> x86StackBytes;
            std::uint32_t apiId = 0;
            std::wstring moduleName;                                // moduleName：事件上报使用的模块名。
            std::wstring installModuleName;                         // installModuleName：传给 GetModuleHandleW 的模块名，默认补齐 .dll。
            std::wstring apiName;                                   // apiName：事件上报使用的 API 名。
            std::string apiNameAnsi;                                // apiNameAnsi：传给 GetProcAddress 的 ANSI 导出名。
            std::wstring matchKey;                                  // matchKey：规范化 module!api 精确匹配键。
            ks::winapi_monitor::EventCategory categoryValue = ks::winapi_monitor::EventCategory::Process; // categoryValue：事件分类。
            FakeSuccessReturnType returnType = FakeSuccessReturnType::Scalar; // returnType：返回值模板。
            FakeSuccessLastErrorKind lastErrorKind = FakeSuccessLastErrorKind::None; // lastErrorKind：错误码写入方式。
            std::uint64_t returnValue = 0;                          // returnValue：写入 RAX 的返回值。
            std::uint32_t lastErrorValue = 0;                       // lastErrorValue：Win32/WSA 错误码。
            InlineHookRecord hookRecord{};                          // hookRecord：Fake 专用 inline patch 状态。
            void* originalAddress = nullptr;                        // originalAddress：安装时仍生成 trampoline，但 fake 路径不会跳入。
            void* entryStubAddress = nullptr;                       // entryStubAddress：动态生成的 fake return stub。
        };

        // RawBindings：
        // - 输入：无；
        // - 处理：返回进程内唯一 Raw Hook 动态绑定集合，集合本身故意泄漏到进程结束；
        // - 返回：可手动 clear 的 vector 引用。
        // - 原因：目标进程退出阶段仍可能有被 hook API 被 CRT/loader 调用，自动析构会让入口 stub 指向已释放上下文。
        std::vector<std::unique_ptr<RawHookBinding>>& RawBindings()
        {
            static auto* const bindingList = new std::vector<std::unique_ptr<RawHookBinding>>();
            return *bindingList;
        }

        // RawHookKeys：
        // - 输入：无；
        // - 处理：返回 Raw module!export 去重集合，集合本身故意泄漏到进程结束；
        // - 返回：可手动 clear 的 unordered_set 引用。
        std::unordered_set<std::wstring>& RawHookKeys()
        {
            static auto* const keySet = new std::unordered_set<std::wstring>();
            return *keySet;
        }

        // FakeSuccessRules：
        // - 输入：无；
        // - 处理：返回 Fake Success 规则集合，集合本身不参与 C++ 静态析构；
        // - 返回：可手动 clear 的 vector 引用。
        // - 原因：fake entry stub 持有 FakeSuccessRuntimeRule*，进程退出未显式 Stop 时不能让自动析构提前释放该上下文。
        std::vector<std::unique_ptr<FakeSuccessRuntimeRule>>& FakeSuccessRules()
        {
            static auto* const ruleList = new std::vector<std::unique_ptr<FakeSuccessRuntimeRule>>();
            return *ruleList;
        }

        // FakeSuccessRuleMap：
        // - 输入：无；
        // - 处理：返回 module!api 到 Fake 规则的快速索引，映射本身不参与 C++ 静态析构；
        // - 返回：可手动 clear 的 unordered_map 引用。
        std::unordered_map<std::wstring, FakeSuccessRuntimeRule*>& FakeSuccessRuleMap()
        {
            static auto* const ruleMap = new std::unordered_map<std::wstring, FakeSuccessRuntimeRule*>();
            return *ruleMap;
        }

        std::wstring ProcNameToWide(const char* procNamePointer)
        {
            if (procNamePointer == nullptr)
            {
                return std::wstring();
            }

            std::wstring wideText;
            while (*procNamePointer != '\0')
            {
                wideText.push_back(static_cast<wchar_t>(*procNamePointer));
                ++procNamePointer;
            }
            return wideText;
        }

        void AppendHookFailureText(
            std::wstring* detailTextOut,
            const HookBinding& bindingValue,
            const InlineHookInstallResult installResult,
            const std::wstring& errorText)
        {
            if (detailTextOut == nullptr)
            {
                return;
            }

            if (!detailTextOut->empty())
            {
                detailTextOut->append(L" | ");
            }

            detailTextOut->append(bindingValue.moduleName != nullptr ? bindingValue.moduleName : L"<module>");
            detailTextOut->append(L"!");
            detailTextOut->append(ProcNameToWide(bindingValue.procName));
            detailTextOut->append(
                installResult == InlineHookInstallResult::RetryableFailure
                ? L": retryable failure - "
                : L": disabled - ");
            detailTextOut->append(errorText.empty() ? L"unknown reason" : errorText);
        }

        std::wstring SafeWideText(const wchar_t* textPointer)
        {
            return textPointer != nullptr ? std::wstring(textPointer) : std::wstring();
        }

        // AnsiToWide 作用：
        // - 输入：textPointer 为可空 ANSI/系统代码页字符串；
        // - 处理：用 CP_ACP 转成宽字符串，失败时退化为逐字节扩展；
        // - 返回：用于 UI 展示的宽字符串，不抛出异常。
        std::wstring AnsiToWide(const char* const textPointer)
        {
            if (textPointer == nullptr)
            {
                return std::wstring();
            }

            const int requiredChars = ::MultiByteToWideChar(CP_ACP, 0, textPointer, -1, nullptr, 0);
            if (requiredChars > 0)
            {
                std::wstring wideText(static_cast<std::size_t>(requiredChars), L'\0');
                const int convertedChars = ::MultiByteToWideChar(
                    CP_ACP,
                    0,
                    textPointer,
                    -1,
                    wideText.data(),
                    requiredChars);
                if (convertedChars > 0 && !wideText.empty())
                {
                    wideText.resize(static_cast<std::size_t>(convertedChars - 1));
                    return wideText;
                }
            }

            std::wstring fallbackText;
            for (const unsigned char* scanPointer = reinterpret_cast<const unsigned char*>(textPointer);
                *scanPointer != '\0';
                ++scanPointer)
            {
                fallbackText.push_back(static_cast<wchar_t>(*scanPointer));
            }
            return fallbackText;
        }

        std::wstring ToLowerWide(std::wstring textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const wchar_t ch) { return static_cast<wchar_t>(::towlower(ch)); });
            return textValue;
        }

        std::string ToLowerAnsi(std::string textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const unsigned char ch) { return static_cast<char>(::tolower(ch)); });
            return textValue;
        }

        // MakeRawHookKey 作用：
        // - 输入：模块名和导出名；
        // - 处理：统一大小写并拼接成 module!api 键；
        // - 返回：Raw 绑定去重和强类型覆盖判断使用的稳定 key。
        std::wstring MakeRawHookKey(const std::wstring& moduleName, const std::string& procName)
        {
            return ToLowerWide(moduleName) + L"!" + ToLowerWide(AnsiToWide(procName.c_str()));
        }

        std::wstring NormalizeModuleNameForMatch(std::wstring moduleName)
        {
            moduleName = ToLowerWide(moduleName);
            if (moduleName.size() > 4 && moduleName.substr(moduleName.size() - 4) == L".dll")
            {
                moduleName.resize(moduleName.size() - 4);
            }
            return moduleName;
        }

        std::wstring MakeFakeSuccessKey(const std::wstring& moduleName, const std::wstring& apiName)
        {
            return NormalizeModuleNameForMatch(moduleName) + L"!" + ToLowerWide(apiName);
        }

        std::wstring MakeFakeSuccessKey(const std::wstring& moduleName, const std::string& apiName)
        {
            return MakeFakeSuccessKey(moduleName, AnsiToWide(apiName.c_str()));
        }

        // UnicodeStringToWide 作用：
        // - 输入：unicodePointer 为可空 UNICODE_STRING；
        // - 处理：按 Length 字节数复制 Buffer，不要求源字符串 NUL 结尾；
        // - 返回：用于 Nt* 事件详情的宽字符串。
        std::wstring UnicodeStringToWide(const UNICODE_STRING* const unicodePointer)
        {
            if (unicodePointer == nullptr
                || unicodePointer->Buffer == nullptr
                || unicodePointer->Length == 0)
            {
                return std::wstring();
            }

            return std::wstring(
                unicodePointer->Buffer,
                unicodePointer->Buffer + (unicodePointer->Length / sizeof(wchar_t)));
        }

        std::wstring HexValue(const std::uint64_t value)
        {
            wchar_t textBuffer[32] = {};
            ::swprintf_s(textBuffer, L"0x%llX", static_cast<unsigned long long>(value));
            return std::wstring(textBuffer);
        }

        std::wstring HandleText(const HANDLE handleValue)
        {
            return HexValue(reinterpret_cast<std::uint64_t>(handleValue));
        }

        // Read only the bounded visible prefix, avoiding no-access/guard pages and tagged pointers.
        template <typename Char, std::size_t kCount>
        void AppendCapturedText(wchar_t(&targetBuffer)[kCount], const Char* textPointer, std::size_t maxInputChars)
        {
            if (!textPointer || kCount == 0) return;
            std::size_t write = 0;
            while (write < kCount && targetBuffer[write]) ++write;
            if (write == kCount) { targetBuffer[kCount - 1] = 0; return; }
            bool unreadable = false;
            std::uintptr_t readableEnd = 0;
            __try {
                for (std::size_t input = 0; input < maxInputChars && write + 1 < kCount; ++input) {
                    const auto address = reinterpret_cast<std::uintptr_t>(textPointer) + input * sizeof(Char);
                    if (address < reinterpret_cast<std::uintptr_t>(textPointer) || address > UINTPTR_MAX - sizeof(Char))
                    { unreadable = true; break; }
                    if (address >= readableEnd || readableEnd - address < sizeof(Char)) {
                        MEMORY_BASIC_INFORMATION info{};
                        if (!::VirtualQuery(reinterpret_cast<void*>(address), &info, sizeof(info)) || info.State != MEM_COMMIT
                            || (info.Protect & (PAGE_NOACCESS | PAGE_GUARD))) { unreadable = true; break; }
                        readableEnd = reinterpret_cast<std::uintptr_t>(info.BaseAddress) + info.RegionSize;
                        if (readableEnd <= address || readableEnd - address < sizeof(Char)) { unreadable = true; break; }
                    }
                    const Char value = *reinterpret_cast<const Char*>(address);
                    if (!value) break;
                    if constexpr (sizeof(Char) == 1) targetBuffer[write++] = static_cast<unsigned char>(value);
                    else targetBuffer[write++] = value;
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) { unreadable = true; }
            if (unreadable) {
                constexpr wchar_t marker[] = L"<unreadable>";
                for (std::size_t i = 0; marker[i] && write + 1 < kCount; ++i) targetBuffer[write++] = marker[i];
            }
            targetBuffer[write] = 0;
        }

        // AppendWideText 作用：
        // - 输入：targetBuffer 为栈上定长缓冲，textPointer 为可空宽字符串；
        // - 处理：从当前 NUL 结尾处追加最多 maxInputChars 个字符，溢出时安全截断；
        // - 返回：无返回值，调用者直接使用 targetBuffer。
        template <std::size_t kCount>
        void AppendWideText(
            wchar_t(&targetBuffer)[kCount],
            const wchar_t* textPointer,
            const std::size_t maxInputChars = static_cast<std::size_t>(-1))
        {
            AppendCapturedText(targetBuffer, textPointer, maxInputChars);
        }

        // AppendAnsiText 作用：
        // - 输入：targetBuffer 为宽字符详情缓冲，textPointer 为可空窄字符串；
        // - 处理：逐字节扩展为 wchar_t 并安全截断，避免 Hook 热路径调用堆分配转换；
        // - 返回：无返回值，目标缓冲保存尽力追加后的 NUL 结尾文本。
        template <std::size_t kCount>
        void AppendAnsiText(
            wchar_t(&targetBuffer)[kCount],
            const char* const textPointer,
            const std::size_t maxInputChars = static_cast<std::size_t>(-1))
        {
            AppendCapturedText(targetBuffer, textPointer, maxInputChars);
        }

        // AppendUnsignedText 前置声明：
        // - 输入：固定宽字符详情缓冲和无符号整数；
        // - 处理：真实实现位于下方，供前面的模板 helper 在实例化时可见；
        // - 返回：无返回值，声明本身不改变运行逻辑。
        template <std::size_t kCount>
        void AppendUnsignedText(wchar_t(&targetBuffer)[kCount], const unsigned long long value);

        // AppendHexText 前置声明：
        // - 输入：固定宽字符详情缓冲和十六进制值；
        // - 处理：解决模板两阶段查找中 AppendObjectNameText 先引用后定义的问题；
        // - 返回：无返回值，真实格式化逻辑仍由下方实现完成。
        template <std::size_t kCount>
        void AppendHexText(wchar_t(&targetBuffer)[kCount], const std::uint64_t value);

        // AppendUnicodeStringText 作用：
        // - 输入：unicodePointer 为可空 UNICODE_STRING；
        // - 处理：按 Length 限定追加，不依赖 Buffer 以 NUL 结尾；
        // - 返回：无返回值，适合 NtCreateFile/NtOpenKey 等 Nt* 详情拼接。
        template <std::size_t kCount>
        void AppendUnicodeStringText(
            wchar_t(&targetBuffer)[kCount],
            const UNICODE_STRING* const unicodePointer)
        {
            if (!unicodePointer) return;
            UNICODE_STRING value{};
            if (!ReadExportMemory(unicodePointer, &value, sizeof(value)) || (value.Length & 1) || value.Length > value.MaximumLength)
            { AppendWideText(targetBuffer, L"<unreadable>"); return; }
            AppendWideText(targetBuffer, value.Buffer, value.Length / sizeof(wchar_t));
        }

        // AppendObjectNameText 作用：
        // - 输入：objectAttributesPointer 为 Nt* OBJECT_ATTRIBUTES；
        // - 处理：追加 ObjectName 文本或句柄根提示，避免解引用其它复杂内核对象状态；
        // - 返回：无返回值，目标缓冲包含 path=<name> 或 rootHandle=<handle>。
        template <std::size_t kCount>
        void AppendObjectNameText(
            wchar_t(&targetBuffer)[kCount],
            const OBJECT_ATTRIBUTES* const objectAttributesPointer)
        {
            if (objectAttributesPointer == nullptr)
            {
                AppendWideText(targetBuffer, L"<null>");
                return;
            }

            if (objectAttributesPointer->RootDirectory != nullptr)
            {
                AppendWideText(targetBuffer, L"root=");
                AppendHexText(targetBuffer, reinterpret_cast<std::uint64_t>(objectAttributesPointer->RootDirectory));
                AppendWideText(targetBuffer, L"\\");
            }
            AppendUnicodeStringText(targetBuffer, objectAttributesPointer->ObjectName);
        }

        // AppendUnsignedText 作用：
        // - 输入：value 为要追加的无符号整数；
        // - 处理：先格式化到小栈缓冲，再追加到目标缓冲；
        // - 返回：无返回值，失败时保持已有文本并追加空串。
        template <std::size_t kCount>
        void AppendUnsignedText(wchar_t(&targetBuffer)[kCount], const unsigned long long value)
        {
            wchar_t numberBuffer[32] = {};
            (void)::swprintf_s(numberBuffer, L"%llu", value);
            AppendWideText(targetBuffer, numberBuffer);
        }

        // AppendHexText 作用：
        // - 输入：value 为要追加的指针/掩码值；
        // - 处理：格式化为 0x 前缀十六进制字符串；
        // - 返回：无返回值，目标缓冲空间不足时安全截断。
        template <std::size_t kCount>
        void AppendHexText(wchar_t(&targetBuffer)[kCount], const std::uint64_t value)
        {
            wchar_t numberBuffer[32] = {};
            (void)::swprintf_s(numberBuffer, L"0x%llX", static_cast<unsigned long long>(value));
            AppendWideText(targetBuffer, numberBuffer);
        }

        // AppendRegistryRootText 作用：
        // - 输入：rootKey 为注册表根键或普通 HKEY 句柄；
        // - 处理：常见根键输出 HKxx，普通句柄输出十六进制；
        // - 返回：无返回值，追加到调用者提供的详情缓冲。
        template <std::size_t kCount>
        void AppendRegistryRootText(wchar_t(&targetBuffer)[kCount], const HKEY rootKey)
        {
            if (rootKey == HKEY_CLASSES_ROOT) { AppendWideText(targetBuffer, L"HKCR"); return; }
            if (rootKey == HKEY_CURRENT_USER) { AppendWideText(targetBuffer, L"HKCU"); return; }
            if (rootKey == HKEY_LOCAL_MACHINE) { AppendWideText(targetBuffer, L"HKLM"); return; }
            if (rootKey == HKEY_USERS) { AppendWideText(targetBuffer, L"HKU"); return; }
            if (rootKey == HKEY_CURRENT_CONFIG) { AppendWideText(targetBuffer, L"HKCC"); return; }
            AppendHexText(targetBuffer, reinterpret_cast<std::uint64_t>(rootKey));
        }

        // BuildRegOpenDetail 作用：
        // - 输入：注册表打开 API 的关键参数；
        // - 处理：在固定栈缓冲中拼接 key/sam 详情，不触发堆分配；
        // - 返回：无返回值，detailBuffer 保存可直接发送的 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildRegOpenDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const REGSAM samDesired)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendWideText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" sam=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(samDesired));
        }

        // BuildRegOpenDetailA 作用：
        // - 输入：ANSI 注册表打开 API 的根键、子键和访问掩码；
        // - 处理：根键用 HKxx/句柄表示，子键逐字节扩展为宽字符；
        // - 返回：无返回值，detailBuffer 保存可直接发送的详情文本。
        template <std::size_t kCount>
        void BuildRegOpenDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const REGSAM samDesired)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendAnsiText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" sam=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(samDesired));
        }

        // BuildRegCreateDetail 作用：
        // - 输入：注册表创建 API 的关键参数与 disposition；
        // - 处理：只记录稳定小字段，避免在注册表锁上下文中做复杂解析；
        // - 返回：无返回值，detailBuffer 保存固定长度详情。
        template <std::size_t kCount>
        void BuildRegCreateDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const DWORD optionsValue,
            const DWORD dispositionValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendWideText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(optionsValue));
            AppendWideText(detailBuffer, L" disposition=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dispositionValue));
        }

        // BuildRegCreateDetailA 作用：
        // - 输入：ANSI 注册表创建 API 的关键参数；
        // - 处理：保持与 W 版相同字段，避免 UI 侧需要额外解析；
        // - 返回：无返回值，detailBuffer 保存固定长度摘要。
        template <std::size_t kCount>
        void BuildRegCreateDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const DWORD optionsValue,
            const DWORD dispositionValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendAnsiText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(optionsValue));
            AppendWideText(detailBuffer, L" disposition=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dispositionValue));
        }

        // BuildRegSetValueDetail 作用：
        // - 输入：注册表写值 API 的句柄、值名、类型和数据长度；
        // - 处理：不读取 dataPointer 内容，避免触发页错误或复制敏感大数据；
        // - 返回：无返回值，detailBuffer 保存可发送的摘要文本。
        template <std::size_t kCount>
        void BuildRegSetValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const wchar_t* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" value=");
            AppendWideText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegSetValueDetailA 作用：
        // - 输入：ANSI 注册表写值 API 的句柄、值名、类型和长度；
        // - 处理：只记录值名和元数据，不复制 dataPointer；
        // - 返回：无返回值，detailBuffer 保存可发送的摘要。
        template <std::size_t kCount>
        void BuildRegSetValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const char* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" value=");
            AppendAnsiText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegValueDetail 作用：
        // - 输入：注册表值操作常见参数；
        // - 处理：拼接 hkey/value/type/size 摘要，适用于查询、删除和枚举值；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾详情。
        template <std::size_t kCount>
        void BuildRegValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const prefixText,
            const HKEY keyHandle,
            const wchar_t* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, prefixText != nullptr ? prefixText : L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" value=");
            AppendWideText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegValueDetailA 作用：
        // - 输入：ANSI 注册表值操作参数；
        // - 处理：拼接 hkey/value/type/size 摘要，值名按窄字符扩展；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildRegValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const prefixText,
            const HKEY keyHandle,
            const char* const valueNamePointer,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, prefixText != nullptr ? prefixText : L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" value=");
            AppendAnsiText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegGetValueDetail 作用：
        // - 输入：RegGetValueW 的 hkey/subkey/value/flags/type/size；
        // - 处理：拼接查询来源和输出摘要，不读取返回数据内容；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildRegGetValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const wchar_t* const subKeyPointer,
            const wchar_t* const valueNamePointer,
            const DWORD flagsValue,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" subkey=");
            AppendWideText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" value=");
            AppendWideText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegGetValueDetailA 作用：
        // - 输入：RegGetValueA 的 hkey/subkey/value/flags/type/size；
        // - 处理：字段与 W 版保持一致，字符串按 ANSI 扩展；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildRegGetValueDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const char* const subKeyPointer,
            const char* const valueNamePointer,
            const DWORD flagsValue,
            const DWORD typeValue,
            const DWORD dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" subkey=");
            AppendAnsiText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" value=");
            AppendAnsiText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(typeValue));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(dataSize));
        }

        // BuildRegSubKeyDetail 作用：
        // - 输入：注册表子键操作的根键、子键名和访问掩码；
        // - 处理：输出 key=<root>\<subkey> view=<sam> 的短文本；
        // - 返回：无返回值，目标缓冲空间不足时自动截断。
        template <std::size_t kCount>
        void BuildRegSubKeyDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const wchar_t* const subKeyPointer,
            const REGSAM viewValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendWideText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" view=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(viewValue));
        }

        // BuildRegSubKeyDetailA 作用：
        // - 输入：ANSI 子键操作的根键、子键和视图掩码；
        // - 处理：输出 key=<root>\<subkey> view=<sam>；
        // - 返回：无返回值，目标缓冲空间不足时安全截断。
        template <std::size_t kCount>
        void BuildRegSubKeyDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY rootKey,
            const char* const subKeyPointer,
            const REGSAM viewValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"key=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L"\\");
            AppendAnsiText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" view=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(viewValue));
        }

        // BuildRegEnumKeyDetail 作用：
        // - 输入：枚举子键结果中的索引、名称和名称长度；
        // - 处理：输出 hkey/index/name/nameLen 摘要；
        // - 返回：无返回值，失败时名称可能为空但仍保留索引。
        template <std::size_t kCount>
        void BuildRegEnumKeyDetail(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const DWORD indexValue,
            const wchar_t* const namePointer,
            const DWORD nameLength)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(indexValue));
            AppendWideText(detailBuffer, L" name=");
            AppendWideText(detailBuffer, namePointer, nameLength);
            AppendWideText(detailBuffer, L" nameLen=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(nameLength));
        }

        // BuildRegEnumKeyDetailA 作用：
        // - 输入：RegEnumKeyExA 的句柄、索引、名称和名称长度；
        // - 处理：保留枚举索引和返回名称，名称按 ANSI 字节扩展；
        // - 返回：无返回值，detailBuffer 保存枚举摘要。
        template <std::size_t kCount>
        void BuildRegEnumKeyDetailA(
            wchar_t(&detailBuffer)[kCount],
            const HKEY keyHandle,
            const DWORD indexValue,
            const char* const namePointer,
            const DWORD nameLength)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(indexValue));
            AppendWideText(detailBuffer, L" name=");
            AppendAnsiText(detailBuffer, namePointer, nameLength);
            AppendWideText(detailBuffer, L" nameLen=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(nameLength));
        }

        // BuildFilePathDetailW 作用：
        // - 输入：pathPointer 为可空宽路径，其它字段为文件 API 元数据；
        // - 处理：生成 path/access/share/disposition/flags 统一摘要；
        // - 返回：无返回值，detailBuffer 保存文件事件详情。
        template <std::size_t kCount>
        void BuildFilePathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const pathPointer,
            const DWORD desiredAccess,
            const DWORD shareMode,
            const DWORD creationDisposition,
            const DWORD flagsAndAttributes,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"path=");
            AppendWideText(detailBuffer, pathPointer);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" share=");
            AppendHexText(detailBuffer, shareMode);
            AppendWideText(detailBuffer, L" disposition=");
            AppendUnsignedText(detailBuffer, creationDisposition);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsAndAttributes);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // BuildFilePathDetailA 作用：
        // - 输入：pathPointer 为可空 ANSI 路径，其它字段为文件 API 元数据；
        // - 处理：与 W 版字段保持一致，路径按 ANSI 字节扩展；
        // - 返回：无返回值，detailBuffer 保存文件事件详情。
        template <std::size_t kCount>
        void BuildFilePathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const pathPointer,
            const DWORD desiredAccess,
            const DWORD shareMode,
            const DWORD creationDisposition,
            const DWORD flagsAndAttributes,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"path=");
            AppendAnsiText(detailBuffer, pathPointer);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" share=");
            AppendHexText(detailBuffer, shareMode);
            AppendWideText(detailBuffer, L" disposition=");
            AppendUnsignedText(detailBuffer, creationDisposition);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsAndAttributes);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // BuildTwoPathDetailW 作用：
        // - 输入：sourcePointer/targetPointer 为移动、复制等双路径 API 的路径；
        // - 处理：输出 src/dst/flags 的短摘要；
        // - 返回：无返回值，detailBuffer 保存可发送文本。
        template <std::size_t kCount>
        void BuildTwoPathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const sourcePointer,
            const wchar_t* const targetPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"src=");
            AppendWideText(detailBuffer, sourcePointer);
            AppendWideText(detailBuffer, L" dst=");
            AppendWideText(detailBuffer, targetPointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
        }

        // BuildTwoPathDetailA 作用：
        // - 输入：sourcePointer/targetPointer 为 ANSI 双路径 API 的路径；
        // - 处理：输出 src/dst/flags，路径按窄字符扩展；
        // - 返回：无返回值，detailBuffer 保存可发送文本。
        template <std::size_t kCount>
        void BuildTwoPathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const sourcePointer,
            const char* const targetPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"src=");
            AppendAnsiText(detailBuffer, sourcePointer);
            AppendWideText(detailBuffer, L" dst=");
            AppendAnsiText(detailBuffer, targetPointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
        }

        // BuildSinglePathDetailW 作用：
        // - 输入：pathPointer 为可空宽路径，flagsValue 为可选参数；
        // - 处理：输出 path/flags 摘要；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildSinglePathDetailW(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const pathPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"path=");
            AppendWideText(detailBuffer, pathPointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
        }

        // BuildSinglePathDetailA 作用：
        // - 输入：pathPointer 为可空 ANSI 路径，flagsValue 为可选参数；
        // - 处理：输出 path/flags 摘要，路径按窄字符扩展；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildSinglePathDetailA(
            wchar_t(&detailBuffer)[kCount],
            const char* const pathPointer,
            const DWORD flagsValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"path=");
            AppendAnsiText(detailBuffer, pathPointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
        }

        // BuildHandleTransferDetail 作用：
        // - 输入：handleValue、请求字节数、实际字节数和可选偏移；
        // - 处理：为 NtReadFile/NtWriteFile 生成统一详情；
        // - 返回：无返回值，detailBuffer 保存 NUL 结尾文本。
        template <std::size_t kCount>
        void BuildHandleTransferDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE handleValue,
            const unsigned long requestLength,
            const unsigned long long actualLength,
            const LARGE_INTEGER* const byteOffsetPointer, const bool actualKnown = true)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
            AppendWideText(detailBuffer, L" request=");
            AppendUnsignedText(detailBuffer, requestLength);
            AppendWideText(detailBuffer, L" transferred=");
            if (actualKnown) AppendUnsignedText(detailBuffer, actualLength);
            else AppendWideText(detailBuffer, L"unknown");
            if (byteOffsetPointer != nullptr)
            {
                AppendWideText(detailBuffer, L" offset=");
                AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(
                    byteOffsetPointer->QuadPart < 0 ? 0 : byteOffsetPointer->QuadPart));
            }
        }

        // BuildNtObjectPathDetail 作用：
        // - 输入：Nt* OBJECT_ATTRIBUTES 与若干掩码字段；
        // - 处理：输出 path/access/share/options/disposition；
        // - 返回：无返回值，detailBuffer 保存底层对象路径摘要。
        template <std::size_t kCount>
        void BuildNtObjectPathDetail(
            wchar_t(&detailBuffer)[kCount],
            const OBJECT_ATTRIBUTES* const objectAttributesPointer,
            const ACCESS_MASK desiredAccess,
            const ULONG shareAccess,
            const ULONG createDisposition,
            const ULONG createOptions)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"path=");
            AppendObjectNameText(detailBuffer, objectAttributesPointer);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" share=");
            AppendHexText(detailBuffer, shareAccess);
            AppendWideText(detailBuffer, L" disposition=");
            AppendUnsignedText(detailBuffer, createDisposition);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, createOptions);
        }

        // BuildNtKeyValueDetail 作用：
        // - 输入：keyHandle、valueNamePointer、type/size；
        // - 处理：不读取 value 数据，仅记录名称与元数据；
        // - 返回：无返回值，detailBuffer 保存 Nt 注册表值操作摘要。
        template <std::size_t kCount>
        void BuildNtKeyValueDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE keyHandle,
            const UNICODE_STRING* const valueNamePointer,
            const ULONG typeValue,
            const ULONG dataSize)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" value=");
            AppendUnicodeStringText(detailBuffer, valueNamePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, typeValue);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, dataSize);
        }

        // BuildProcessHandleDetail 作用：
        // - 输入：进程句柄、访问掩码、PID 和返回句柄；
        // - 处理：统一输出 process/access/pid/handle 字段；
        // - 返回：无返回值，detailBuffer 保存进程事件摘要。
        template <std::size_t kCount>
        void BuildProcessHandleDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE processHandle,
            const ACCESS_MASK accessMask,
            const std::uint64_t processId,
            const HANDLE resultHandle)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, accessMask);
            AppendWideText(detailBuffer, L" pid=");
            AppendUnsignedText(detailBuffer, processId);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
        }

        // BuildRemoteMemoryDetail 作用：
        // - 输入：目标进程句柄、地址、长度、保护或分配标志；
        // - 处理：为跨进程内存 API 生成稳定字段；
        // - 返回：无返回值，detailBuffer 保存内存操作摘要。
        template <std::size_t kCount>
        void BuildRemoteMemoryDetail(
            wchar_t(&detailBuffer)[kCount],
            const HANDLE processHandle,
            const void* const baseAddress,
            const std::uint64_t sizeValue,
            const ULONG firstFlags,
            const ULONG secondFlags)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" base=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(baseAddress));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, firstFlags);
            AppendWideText(detailBuffer, L" protect=");
            AppendHexText(detailBuffer, secondFlags);
        }

        // SumWsaBufferLength 作用：
        // - 输入：Winsock WSABUF 数组和元素数量；
        // - 处理：累加 len 字段并防止空指针访问；
        // - 返回：总请求字节数，超过 uint64 时自然截断到 uint64 范围。
        std::uint64_t SumWsaBufferLength(const WSABUF* bufferPointer, DWORD bufferCount)
        {
            std::uint64_t totalLength = 0;
            __try { for (DWORD i = 0; bufferPointer && i < (std::min)(bufferCount, 1024UL); ++i) totalLength += bufferPointer[i].len; }
            __except (EXCEPTION_EXECUTE_HANDLER) { return 0; }
            return totalLength;
        }

        // AppendSocketAddress 作用：
        // - 输入：sockaddr 与长度；
        // - 处理：尽量用 GetNameInfoW 转成 host:port，失败时输出 <unknown>；
        // - 返回：无返回值，直接追加到 detailBuffer。
        template <std::size_t kCount>
        void AppendSocketAddress(wchar_t(&detailBuffer)[kCount], const sockaddr* const addressPointer, const int addressLength)
        {
            if (addressPointer == nullptr || addressLength <= 0)
            {
                AppendWideText(detailBuffer, L"<null>");
                return;
            }

            wchar_t hostBuffer[NI_MAXHOST] = {};
            wchar_t serviceBuffer[NI_MAXSERV] = {};
            sockaddr_storage address{};
            if (addressLength > sizeof(address)) { AppendWideText(detailBuffer, L"<unknown>"); return; }
            __try { std::memcpy(&address, addressPointer, addressLength); }
            __except (EXCEPTION_EXECUTE_HANDLER) { AppendWideText(detailBuffer, L"<unreadable>"); return; }
            const int resultValue = ::GetNameInfoW(
                reinterpret_cast<const sockaddr*>(&address),
                addressLength,
                hostBuffer,
                NI_MAXHOST,
                serviceBuffer,
                NI_MAXSERV,
                NI_NUMERICHOST | NI_NUMERICSERV);
            if (resultValue != 0)
            {
                AppendWideText(detailBuffer, L"<unknown>");
                return;
            }

            AppendWideText(detailBuffer, hostBuffer);
            AppendWideText(detailBuffer, L":");
            AppendWideText(detailBuffer, serviceBuffer);
        }

        // BuildSocketDetail 作用：
        // - 输入：socket、请求长度、实际传输长度、flags 和可选地址；
        // - 处理：生成网络事件摘要，不读取网络缓冲内容；
        // - 返回：无返回值，detailBuffer 保存可发送文本。
        template <std::size_t kCount>
        void BuildSocketDetail(
            wchar_t(&detailBuffer)[kCount],
            const wchar_t* const verbText,
            const SOCKET socketValue,
            const std::uint64_t requestLength,
            const long long transferLength,
            const DWORD flagsValue,
            const sockaddr* const addressPointer = nullptr,
            const int addressLength = 0,
            const bool transferKnown = true, const bool flagsKnown = true)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            if (verbText != nullptr && verbText[0] != L'\0')
            {
                AppendWideText(detailBuffer, L" ");
                AppendWideText(detailBuffer, verbText);
            }
            AppendWideText(detailBuffer, L" request=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(requestLength));
            AppendWideText(detailBuffer, L" transferred=");
            if (transferKnown) AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(transferLength < 0 ? 0 : transferLength));
            else AppendWideText(detailBuffer, L"unknown");
            AppendWideText(detailBuffer, L" flags=");
            if (flagsKnown) AppendHexText(detailBuffer, static_cast<std::uint64_t>(flagsValue));
            else AppendWideText(detailBuffer, L"unknown");
            if (addressPointer != nullptr)
            {
                AppendWideText(detailBuffer, L" remote=");
                AppendSocketAddress(detailBuffer, addressPointer, addressLength);
            }
        }

        bool CategoryEnabled(const ks::winapi_monitor::EventCategory categoryValue)
        {
            const MonitorConfig& configValue = ActiveConfig();
            switch (categoryValue)
            {
            case ks::winapi_monitor::EventCategory::File:
                return configValue.enableFile;
            case ks::winapi_monitor::EventCategory::Registry:
                return configValue.enableRegistry;
            case ks::winapi_monitor::EventCategory::Network:
                return configValue.enableNetwork;
            case ks::winapi_monitor::EventCategory::Process:
                return configValue.enableProcess;
            case ks::winapi_monitor::EventCategory::Loader:
                // Loader hook 还承担“后加载模块补装”职责：
                // - enableLoader 控制是否上报 LoadLibrary 事件；
                // - 注册表/网络/Shell32 进程启动模块可能晚于 Agent 注入加载，因此启用这些分类时也要安装加载器 hook。
                return configValue.enableLoader || configValue.enableRegistry || configValue.enableNetwork || configValue.enableProcess
                    || configValue.autoInjectChild || configValue.enableClipboard || configValue.enableRawFallback || configValue.fakeSuccessEnabled;
            case ks::winapi_monitor::EventCategory::Clipboard:
                // 剪贴板 hook 默认关闭：必须显式 enableClipboard，
                // 不能像其它分类一样落到下面的 default true，否则普通 API 监控会话
                // 会在用户没打开"剪贴板保护"时也悄悄装上剪贴板 hook。
                return configValue.enableClipboard;
            default:
                break;
            }
            return true;
        }

        std::wstring TrimDetail(const std::wstring& detailText)
        {
            const std::size_t detailLimit = std::min<std::size_t>(
                ActiveConfig().detailLimitChars,
                ks::winapi_monitor::kMaxDetailChars - 1);
            return detailText.size() > detailLimit ? detailText.substr(0, detailLimit) : detailText;
        }

        std::wstring FormatRegistryRoot(const HKEY rootKey)
        {
            if (rootKey == HKEY_CLASSES_ROOT) { return L"HKCR"; }
            if (rootKey == HKEY_CURRENT_USER) { return L"HKCU"; }
            if (rootKey == HKEY_LOCAL_MACHINE) { return L"HKLM"; }
            if (rootKey == HKEY_USERS) { return L"HKU"; }
            if (rootKey == HKEY_CURRENT_CONFIG) { return L"HKCC"; }
            return HandleText(rootKey);
        }

        std::wstring FormatSocketAddress(const sockaddr* addressPointer, const int addressLength)
        {
            if (addressPointer == nullptr || addressLength <= 0)
            {
                return L"<null>";
            }

            wchar_t hostBuffer[NI_MAXHOST] = {};
            wchar_t serviceBuffer[NI_MAXSERV] = {};
            const int resultValue = ::GetNameInfoW(
                addressPointer,
                addressLength,
                hostBuffer,
                NI_MAXHOST,
                serviceBuffer,
                NI_MAXSERV,
                NI_NUMERICHOST | NI_NUMERICSERV);
            if (resultValue != 0)
            {
                return L"<unknown>";
            }
            return std::wstring(hostBuffer) + L":" + serviceBuffer;
        }

        // SendRawEventWithStatus 作用：
        // - 输入：category/module/api/status/detail 为已格式化事件；
        // - 处理：把 NTSTATUS/HRESULT/DWORD 统一截断为协议 resultCode；
        // - 返回：SendMonitorEventRaw 的返回值。
        bool SendRawEventWithStatus(
            const ks::winapi_monitor::EventCategory categoryValue,
            const wchar_t* const moduleName,
            const wchar_t* const apiName,
            const long statusValue,
            const wchar_t* const detailText,
            const ks::winapi_monitor::EventResultKind resultKind = ks::winapi_monitor::EventResultKind::StatusCode,
            const std::uint32_t apiId = 0)
        {
            if (categoryValue == ks::winapi_monitor::EventCategory::File && !ActiveConfig().enableFile) return false;
            return SendMonitorEventRaw(
                categoryValue,
                moduleName,
                apiName,
                static_cast<std::int32_t>(statusValue),
                detailText, resultKind, ks::winapi_monitor::EventKind::ApiCall, 0, apiId);
        }

        struct ApiCallClock
        {
            LARGE_INTEGER start{};
            bool valid = false;
        };

        struct ApiCallDuration
        {
            std::uint64_t ticks100ns = 0;
            bool valid = false;
        };

        // Timing calls must not change the LastError seen by the original API
        // or by its caller. A failed or backwards clock is explicitly absent.
        ApiCallClock BeginApiCallClock()
        {
            const DWORD lastError = ::GetLastError();
            ApiCallClock clock;
            clock.valid = ::QueryPerformanceCounter(&clock.start) != FALSE;
            ::SetLastError(lastError);
            return clock;
        }

        ApiCallDuration EndApiCallClock(const ApiCallClock& clock)
        {
            const DWORD lastError = ::GetLastError();
            LARGE_INTEGER end{}, frequency{};
            const bool valid = clock.valid && ::QueryPerformanceCounter(&end)
                && ::QueryPerformanceFrequency(&frequency)
                && frequency.QuadPart > 0 && end.QuadPart >= clock.start.QuadPart;
            ApiCallDuration result;
            if (valid)
            {
                const double ticks = static_cast<double>(end.QuadPart - clock.start.QuadPart)
                    * 10000000.0 / static_cast<double>(frequency.QuadPart);
                if (ticks >= 0.0 && ticks < 18446744073709551616.0)
                {
                    result.ticks100ns = static_cast<std::uint64_t>(ticks);
                    result.valid = true;
                }
            }
            ::SetLastError(lastError);
            return result;
        }

        template<typename T>
        std::uint64_t ApiReturnBits(const T value)
        {
            static_assert(std::is_trivially_copyable_v<T> && sizeof(T) <= sizeof(std::uint64_t));
            std::uint64_t bits = 0;
            std::memcpy(&bits, &value, sizeof(value));
            return bits;
        }

        bool SendRawEventWithMetrics(const ks::winapi_monitor::EventCategory categoryValue,
            const wchar_t* moduleName, const wchar_t* apiName, const long statusValue,
            const wchar_t* detailText, const bool hasReturn, const std::uint64_t returnBits,
            const ApiCallDuration& duration, const std::uint32_t apiId = 0, const std::uint64_t operationId = 0)
        {
            if (categoryValue == ks::winapi_monitor::EventCategory::File && !ActiveConfig().enableFile) return false;
            return SendMonitorEventRawWithMetrics(categoryValue, moduleName, apiName,
                static_cast<std::int32_t>(statusValue), detailText,
                hasReturn, returnBits, duration.valid, duration.ticks100ns, apiId,
                ks::winapi_monitor::EventResultKind::StatusCode, operationId);
        }

        bool SendFileEventWithReturn(const wchar_t* apiName, const long status,
            const wchar_t* detail, const HANDLE returnHandle, const ApiCallDuration& duration)
        {
            if (!ActiveConfig().enableFile) return false;
            return SendMonitorEventRawWithMetrics(ks::winapi_monitor::EventCategory::File,
                L"KernelBase", apiName, static_cast<std::int32_t>(status), detail,
                true, ApiReturnBits(returnHandle), duration.valid, duration.ticks100ns);
        }

        ks::winapi_monitor::EventCategory InferRawHookCategory(const std::wstring& moduleName, const std::string& procName);
        void EmitRawStubByte(unsigned char* codePointer, std::size_t& offsetValue, unsigned char byteValue);
        void EmitRawStubU64(unsigned char* codePointer, std::size_t& offsetValue, std::uint64_t value);

        std::string WideToAnsiExportName(const std::wstring& textValue)
        {
            // WideToAnsiExportName 作用：
            // - 输入：UI/INI 中保存的 API 导出名宽字符串；
            // - 处理：按系统代码页转成 GetProcAddress 需要的窄字符串，失败时仅保留 ASCII；
            // - 返回：可传给 GetProcAddress 的导出名，无法转换时返回空串。
            if (textValue.empty())
            {
                return std::string();
            }

            const int requiredBytes = ::WideCharToMultiByte(
                CP_ACP,
                0,
                textValue.c_str(),
                -1,
                nullptr,
                0,
                nullptr,
                nullptr);
            if (requiredBytes > 0)
            {
                std::string ansiText(static_cast<std::size_t>(requiredBytes), '\0');
                const int convertedBytes = ::WideCharToMultiByte(
                    CP_ACP,
                    0,
                    textValue.c_str(),
                    -1,
                    ansiText.data(),
                    requiredBytes,
                    nullptr,
                    nullptr);
                if (convertedBytes > 0 && !ansiText.empty())
                {
                    ansiText.resize(static_cast<std::size_t>(convertedBytes - 1));
                    return ansiText;
                }
            }

            std::string fallbackText;
            for (const wchar_t ch : textValue)
            {
                if (ch == L'\0')
                {
                    break;
                }
                if (ch < 0x20 || ch > 0x7E)
                {
                    return std::string();
                }
                fallbackText.push_back(static_cast<char>(ch));
            }
            return fallbackText;
        }

        std::wstring BuildInstallModuleName(const std::wstring& moduleName)
        {
            // BuildInstallModuleName 作用：
            // - 输入：用户配置的模块名，可以含 .dll，也可以只写 KernelBase 这样的短名；
            // - 处理：安装 Hook 时保留已有扩展名，无扩展名时补齐 .dll；
            // - 返回：GetModuleHandleW 可直接尝试匹配的模块名。
            std::wstring installName = moduleName;
            if (installName.find(L'.') == std::wstring::npos)
            {
                installName.append(L".dll");
            }
            return installName;
        }

        FakeSuccessRuntimeRule* FindFakeSuccessRule(const std::wstring& moduleName, const std::string& procName)
        {
            const MonitorConfig& configValue = ActiveConfig();
            auto& ruleMap = FakeSuccessRuleMap();
            if (!configValue.fakeSuccessEnabled || ruleMap.empty())
            {
                return nullptr;
            }

            const auto iterator = ruleMap.find(MakeFakeSuccessKey(moduleName, procName));
            return iterator != ruleMap.end() ? iterator->second : nullptr;
        }

        template <std::size_t kCount>
        void AppendFakeSuccessDetail(wchar_t(&detailBuffer)[kCount], const FakeSuccessRuntimeRule& ruleValue)
        {
            AppendWideText(detailBuffer, L"FakeSuccess=1 original=skipped returnType=");
            switch (ruleValue.returnType)
            {
            case FakeSuccessReturnType::Bool: AppendWideText(detailBuffer, L"BOOL"); break;
            case FakeSuccessReturnType::Handle: AppendWideText(detailBuffer, L"HANDLE/PVOID"); break;
            case FakeSuccessReturnType::Dword: AppendWideText(detailBuffer, L"DWORD/UINT/int"); break;
            case FakeSuccessReturnType::NtStatus: AppendWideText(detailBuffer, L"NTSTATUS"); break;
            case FakeSuccessReturnType::HResult: AppendWideText(detailBuffer, L"HRESULT"); break;
            case FakeSuccessReturnType::LStatus: AppendWideText(detailBuffer, L"LSTATUS"); break;
            case FakeSuccessReturnType::SocketInt: AppendWideText(detailBuffer, L"SOCKET/int(WSA)"); break;
            default: AppendWideText(detailBuffer, L"Scalar"); break;
            }
            AppendWideText(detailBuffer, L" return=");
            AppendHexText(detailBuffer, ruleValue.returnValue);
            if (ruleValue.lastErrorKind != FakeSuccessLastErrorKind::None)
            {
                AppendWideText(detailBuffer, ruleValue.lastErrorKind == FakeSuccessLastErrorKind::Wsa ? L" WSAError=" : L" LastError=");
                AppendUnsignedText(detailBuffer, ruleValue.lastErrorValue);
            }
        }

        std::int32_t FakeSuccessResultCode(const FakeSuccessRuntimeRule& ruleValue)
        {
            if (ruleValue.lastErrorKind != FakeSuccessLastErrorKind::None && ruleValue.lastErrorValue != 0)
            {
                return static_cast<std::int32_t>(ruleValue.lastErrorValue);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::Bool)
            {
                return ruleValue.returnValue != 0 ? 0 : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::Handle)
            {
                return (ruleValue.returnValue != 0 && static_cast<std::uintptr_t>(ruleValue.returnValue) != UINTPTR_MAX)
                    ? 0
                    : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            if (ruleValue.returnType == FakeSuccessReturnType::SocketInt)
            {
                return static_cast<std::uint32_t>(ruleValue.returnValue & 0xFFFFFFFFULL) != 0xFFFFFFFFU
                    ? 0
                    : static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
            }
            return static_cast<std::int32_t>(ruleValue.returnValue & 0xFFFFFFFFULL);
        }

        std::uint64_t FakeSuccessEnter(FakeSuccessRuntimeRule* const ruleValue)
        {
            if (ruleValue == nullptr)
            {
                return 0;
            }

            const DWORD previousLastError = ::GetLastError();
            ScopedHookGuard guardValue(false);
            if (!guardValue.bypass())
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                AppendFakeSuccessDetail(detailBuffer, *ruleValue);
                SendRawEventWithStatus(
                    ruleValue->categoryValue,
                    ruleValue->moduleName.c_str(),
                    ruleValue->apiName.c_str(),
                    FakeSuccessResultCode(*ruleValue),
                    detailBuffer, ks::winapi_monitor::EventResultKind::StatusCode, ruleValue->apiId);
            }

            if (ruleValue->lastErrorKind == FakeSuccessLastErrorKind::Win32)
            {
                ::SetLastError(ruleValue->lastErrorValue);
            }
            else if (ruleValue->lastErrorKind == FakeSuccessLastErrorKind::Wsa)
            {
                ::SetLastError(previousLastError);
                ::WSASetLastError(static_cast<int>(ruleValue->lastErrorValue));
            }
            else
            {
                ::SetLastError(previousLastError);
            }

            return ruleValue->returnValue;
        }

        // BuildFakeSuccessRuleIndex 作用：
        // - 输入：ActiveConfig 中由 UI 写入的 Fake Success 规则；
        // - 处理：规范化 module!api 匹配键，补齐安装模块名，转换 ANSI 导出名，并按“首条规则优先”建立索引；
        // - 返回：无返回值，FakeSuccessRules/FakeSuccessRuleMap 保存本会话可安装的运行时规则。
        void BuildFakeSuccessRuleIndex()
        {
            auto& ruleList = FakeSuccessRules();
            auto& ruleMap = FakeSuccessRuleMap();
            ruleList.clear();
            ruleMap.clear();

            const MonitorConfig& configValue = ActiveConfig();
            if (!configValue.fakeSuccessEnabled)
            {
                return;
            }

            for (const FakeSuccessRule& sourceRule : configValue.fakeSuccessRules)
            {
                const std::wstring matchKey = MakeFakeSuccessKey(sourceRule.moduleName, sourceRule.apiName);
                if (matchKey.empty() || ruleMap.find(matchKey) != ruleMap.end())
                {
                    continue;
                }

                std::string ansiApiName = WideToAnsiExportName(sourceRule.apiName);
                if (ansiApiName.empty())
                {
                    continue;
                }

                auto runtimeRule = std::make_unique<FakeSuccessRuntimeRule>();
                runtimeRule->moduleName = sourceRule.moduleName;
                runtimeRule->installModuleName = BuildInstallModuleName(sourceRule.moduleName);
                runtimeRule->apiName = sourceRule.apiName;
                runtimeRule->apiNameAnsi = std::move(ansiApiName);
                runtimeRule->matchKey = matchKey;
                runtimeRule->apiId = RuntimeApiId(runtimeRule->installModuleName.c_str(), runtimeRule->apiName.c_str());
                runtimeRule->categoryValue = InferRawHookCategory(runtimeRule->installModuleName, runtimeRule->apiNameAnsi);
                runtimeRule->returnType = sourceRule.returnType;
                runtimeRule->returnValue = sourceRule.returnValue;
                runtimeRule->x86StackBytes = sourceRule.x86StackBytes;
                runtimeRule->lastErrorKind = sourceRule.lastErrorKind;
                runtimeRule->lastErrorValue = sourceRule.lastErrorValue;

                FakeSuccessRuntimeRule* const rulePointer = runtimeRule.get();
                ruleMap.emplace(rulePointer->matchKey, rulePointer);
                ruleList.push_back(std::move(runtimeRule));
            }
        }

        // BuildFakeSuccessEntryStub 作用：
        // - 输入：ruleValue 指向一条 Fake Success 运行时规则；
        // - 处理：生成 x64 小型 detour stub，调用 FakeSuccessEnter(rule) 上报事件并取得 RAX 返回值；
        // - 返回：可执行内存地址，作为 InstallInlineHook 的 detourAddress，失败返回 nullptr。
        void* BuildFakeSuccessEntryStub(FakeSuccessRuntimeRule* const ruleValue)
        {
#ifdef _M_IX86
            if (!ruleValue) return nullptr;
            for (const auto& abi : kApiStackAbi) {
                if (NormalizeModuleNameForMatch(ruleValue->installModuleName) == NormalizeModuleNameForMatch(abi.module)
                    && _wcsicmp(ruleValue->apiName.c_str(), abi.name) == 0)
                {
                    if (ruleValue->x86StackBytes && *ruleValue->x86StackBytes != abi.stackBytes) {
                        ruleValue->hookRecord.lastFailure = L"explicit x86 cleanup conflicts with the known API ABI"; return nullptr;
                    }
                    return BuildX86FakeStub(ruleValue, reinterpret_cast<void*>(&FakeSuccessEnter), abi.stackBytes);
                }
            }
            if (ruleValue->x86StackBytes)
                return BuildX86FakeStub(ruleValue, reinterpret_cast<void*>(&FakeSuccessEnter), *ruleValue->x86StackBytes);
            ruleValue->hookRecord.lastFailure = L"x86 Fake requires a known ABI or explicit stack byte count";
            return nullptr;
#else
            if (ruleValue == nullptr)
            {
                return nullptr;
            }

            constexpr std::size_t kFakeStubBytes = 64;
            unsigned char* const codePointer = static_cast<unsigned char*>(::VirtualAlloc(
                nullptr,
                kFakeStubBytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE));
            if (codePointer == nullptr)
            {
                return nullptr;
            }

            std::size_t offsetValue = 0;
            const auto emit = [codePointer, &offsetValue](const unsigned char byteValue) {
                EmitRawStubByte(codePointer, offsetValue, byteValue);
            };

            emit(0x48); emit(0x83); emit(0xEC); emit(0x28); // sub rsp, 0x28：对齐栈并提供 32 字节 shadow space。
            emit(0x48); emit(0xB9);                         // mov rcx, ruleValue：Windows x64 第一个参数。
            EmitRawStubU64(codePointer, offsetValue, reinterpret_cast<std::uint64_t>(ruleValue));
            emit(0x48); emit(0xB8);                         // mov rax, FakeSuccessEnter。
            EmitRawStubU64(codePointer, offsetValue, reinterpret_cast<std::uint64_t>(&FakeSuccessEnter));
            emit(0xFF); emit(0xD0);                         // call rax：返回值留在 RAX。
            emit(0x48); emit(0x83); emit(0xC4); emit(0x28); // add rsp, 0x28：恢复调用者栈。
            emit(0xC3);                                     // ret：直接返回到原 API 调用者，原函数完全不执行。

            ::FlushInstructionCache(::GetCurrentProcess(), codePointer, offsetValue);
            return codePointer;
#endif
        }

        void FreeFakeSuccessEntryStub(void* const stubAddress)
        {
            // FreeFakeSuccessEntryStub 作用：
            // - 输入：BuildFakeSuccessEntryStub 返回的可执行内存；
            // - 处理：释放动态 stub，调用方必须先卸载 inline hook；
            // - 返回：无返回值。
            if (stubAddress != nullptr)
            {
                detail::ReleaseCodePage(stubAddress);
            }
        }

        void AppendFakeSuccessFailureText(
            std::wstring* const detailTextOut,
            const FakeSuccessRuntimeRule& ruleValue,
            const InlineHookInstallResult installResult,
            const std::wstring& errorText)
        {
            // AppendFakeSuccessFailureText 作用：
            // - 输入：安装失败的规则、失败类型和 HookEngine 诊断文本；
            // - 处理：追加到 InstallConfiguredHooks 的聚合错误里，便于 UI 内部事件显示；
            // - 返回：无返回值，detailTextOut 为空时静默跳过。
            if (detailTextOut == nullptr)
            {
                return;
            }
            if (!detailTextOut->empty())
            {
                detailTextOut->append(L" | ");
            }

            detailTextOut->append(ruleValue.moduleName);
            detailTextOut->append(L"!");
            detailTextOut->append(ruleValue.apiName);
            detailTextOut->append(
                installResult == InlineHookInstallResult::RetryableFailure
                ? L": fake retryable failure - "
                : L": fake disabled - ");
            detailTextOut->append(errorText.empty() ? L"unknown reason" : errorText);
        }

        bool TryInstallFakeSuccessRule(
            FakeSuccessRuntimeRule& ruleValue,
            const std::optional<ks::winapi_monitor::EventCategory> categoryOverride,
            std::wstring* const detailTextOut)
        {
            // TryInstallFakeSuccessRule 作用：
            // - 输入：运行时规则，可选分类覆盖用于强类型绑定命中时保持分类更准确；
            // - 处理：为规则生成 fake-return stub，并把目标导出 inline patch 到该 stub；
            // - 返回：当前规则已安装或本次安装成功返回 true，失败返回 false。
            if (categoryOverride.has_value())
            {
                ruleValue.categoryValue = categoryOverride.value();
            }
            if (ruleValue.hookRecord.installed || ruleValue.hookRecord.permanentlyDisabled)
            {
                return ruleValue.hookRecord.installed;
            }
            if (ruleValue.entryStubAddress == nullptr)
            {
                ruleValue.entryStubAddress = BuildFakeSuccessEntryStub(&ruleValue);
                if (ruleValue.entryStubAddress == nullptr)
                {
                    ruleValue.hookRecord.permanentlyDisabled = true;
                    AppendFakeSuccessFailureText(
                        detailTextOut,
                        ruleValue,
                        InlineHookInstallResult::PermanentFailure,
                        ruleValue.hookRecord.lastFailure.empty() ? L"VirtualAlloc for fake-return stub failed." : ruleValue.hookRecord.lastFailure);
                    return false;
                }
            }

            std::wstring errorText;
            const InlineHookInstallResult installResult = InstallInlineHook(
                ruleValue.installModuleName.c_str(),
                ruleValue.apiNameAnsi.c_str(),
                ruleValue.entryStubAddress,
                &ruleValue.hookRecord,
                &ruleValue.originalAddress,
                &errorText);
            if (installResult == InlineHookInstallResult::Installed)
            {
                return true;
            }
            if (installResult == InlineHookInstallResult::PermanentFailure)
            {
                ruleValue.hookRecord.permanentlyDisabled = true;
            }
            AppendFakeSuccessFailureText(detailTextOut, ruleValue, installResult, errorText);
            return false;
        }

        // RawHookEnter 作用：
        // - 输入：bindingValue 为动态 stub 传入的 Raw Hook 元数据；
        // - 处理：在不解析参数语义的前提下上报 module/api/target/trampoline，并用全局 reentry guard 避免日志链路递归；
        // - 返回：无返回值，动态 stub 随后恢复寄存器并跳入 trampoline 继续执行原函数。
        void RawHookEnter(RawHookBinding* const bindingValue, const std::uintptr_t* const savedFrame)
        {
            if (bindingValue == nullptr)
            {
                return;
            }

            ScopedHookGuard guardValue(false);
            if (guardValue.bypass())
            {
                return;
            }

            const DWORD savedError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"Raw ABI fallback target=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bindingValue->hookRecord.targetAddress));
            AppendWideText(detailBuffer, L" trampoline=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(bindingValue->originalAddress));
            const auto arguments = CaptureRawAbi(savedFrame);
            if (arguments.returnAddress != 0)
            {
                AppendWideText(detailBuffer, L" caller=");
                AppendHexText(detailBuffer, arguments.returnAddress);
            }
#ifdef _M_IX86
            AppendWideText(detailBuffer, L" strongTyped=0 params=raw abi=x86 ECX=");
            AppendHexText(detailBuffer, arguments.registers[0]);
            AppendWideText(detailBuffer, L" EDX=");
            AppendHexText(detailBuffer, arguments.registers[1]);
#else
            AppendWideText(detailBuffer, L" strongTyped=0 params=raw abi=x64 RCX=");
            AppendHexText(detailBuffer, arguments.registers[0]);
            AppendWideText(detailBuffer, L" RDX=");
            AppendHexText(detailBuffer, arguments.registers[1]);
            AppendWideText(detailBuffer, L" R8=");
            AppendHexText(detailBuffer, arguments.registers[2]);
            AppendWideText(detailBuffer, L" R9=");
            AppendHexText(detailBuffer, arguments.registers[3]);
#endif
            AppendWideText(detailBuffer, L" stackSlots=[");
            for (unsigned i = 0; i < arguments.stackCount; ++i)
            {
                if (i) AppendWideText(detailBuffer, L",");
                AppendHexText(detailBuffer, arguments.stack[i]);
            }
            AppendWideText(detailBuffer, L"]");
            SendRawEventWithStatus(
                bindingValue->categoryValue,
                bindingValue->moduleName.c_str(),
                bindingValue->procNameWide.c_str(),
                0,
                detailBuffer, ks::winapi_monitor::EventResultKind::EntryOnly, bindingValue->apiId);
            ::SetLastError(savedError);
        }

        // EmitRawStubByte/EmitRawStubU32/EmitRawStubU64 作用：
        // - 输入：动态代码缓冲和待写入数值；
        // - 处理：顺序写入 x64 Raw Hook stub 指令字节；
        // - 返回：无返回值，offsetValue 推进到下一条指令位置。
        void EmitRawStubByte(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char byteValue)
        {
            codePointer[offsetValue++] = byteValue;
        }

        void EmitRawStubU32(unsigned char* const codePointer, std::size_t& offsetValue, const std::uint32_t value)
        {
            std::memcpy(codePointer + offsetValue, &value, sizeof(value));
            offsetValue += sizeof(value);
        }

        void EmitRawStubU64(unsigned char* const codePointer, std::size_t& offsetValue, const std::uint64_t value)
        {
            std::memcpy(codePointer + offsetValue, &value, sizeof(value));
            offsetValue += sizeof(value);
        }

        void EmitRawStubMovdquStore(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char xmmIndex, const unsigned char stackOffset)
        {
            EmitRawStubByte(codePointer, offsetValue, 0xF3);
            EmitRawStubByte(codePointer, offsetValue, 0x0F);
            EmitRawStubByte(codePointer, offsetValue, 0x7F);
            EmitRawStubByte(codePointer, offsetValue, static_cast<unsigned char>(0x44U + (xmmIndex * 0x08U)));
            EmitRawStubByte(codePointer, offsetValue, 0x24);
            EmitRawStubByte(codePointer, offsetValue, stackOffset);
        }

        void EmitRawStubMovdquLoad(unsigned char* const codePointer, std::size_t& offsetValue, const unsigned char xmmIndex, const unsigned char stackOffset)
        {
            EmitRawStubByte(codePointer, offsetValue, 0xF3);
            EmitRawStubByte(codePointer, offsetValue, 0x0F);
            EmitRawStubByte(codePointer, offsetValue, 0x6F);
            EmitRawStubByte(codePointer, offsetValue, static_cast<unsigned char>(0x44U + (xmmIndex * 0x08U)));
            EmitRawStubByte(codePointer, offsetValue, 0x24);
            EmitRawStubByte(codePointer, offsetValue, stackOffset);
        }

        // BuildRawEntryStub 作用：
        // - 输入：bindingValue 指向 Raw Hook 元数据，stub 通过该指针读取 trampoline；
        // - 处理：生成 x64 通用入口桩，保存整数参数寄存器和 XMM0-XMM5，调用 RawHookEnter 后跳转到 trampoline；
        // - 返回：可作为 InstallInlineHook hookAddress 的可执行内存地址，失败返回 nullptr。
        void* BuildRawEntryStub(RawHookBinding* const bindingValue)
        {
#ifdef _M_IX86
            return bindingValue ? BuildX86RawStub(bindingValue, reinterpret_cast<void*>(&RawHookEnter), &bindingValue->originalAddress) : nullptr;
#else
            if (bindingValue == nullptr)
            {
                return nullptr;
            }

            constexpr std::size_t kRawStubBytes = 256;
            unsigned char* const codePointer = static_cast<unsigned char*>(::VirtualAlloc(
                nullptr,
                kRawStubBytes,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE));
            if (codePointer == nullptr)
            {
                return nullptr;
            }

            std::size_t offsetValue = 0;
            const auto emit = [codePointer, &offsetValue](const unsigned char byteValue) {
                EmitRawStubByte(codePointer, offsetValue, byteValue);
            };

            emit(0x50);                         // push rax
            emit(0x51);                         // push rcx
            emit(0x52);                         // push rdx
            emit(0x41); emit(0x50);             // push r8
            emit(0x41); emit(0x51);             // push r9
            emit(0x41); emit(0x52);             // push r10
            emit(0x41); emit(0x53);             // push r11
            emit(0x48); emit(0x81); emit(0xEC); // sub rsp, 0xA0
            EmitRawStubU32(codePointer, offsetValue, 0x000000A0U);

            EmitRawStubMovdquStore(codePointer, offsetValue, 0, 0x20);
            EmitRawStubMovdquStore(codePointer, offsetValue, 1, 0x30);
            EmitRawStubMovdquStore(codePointer, offsetValue, 2, 0x40);
            EmitRawStubMovdquStore(codePointer, offsetValue, 3, 0x50);
            EmitRawStubMovdquStore(codePointer, offsetValue, 4, 0x60);
            EmitRawStubMovdquStore(codePointer, offsetValue, 5, 0x70);

            emit(0x48); emit(0xB9);             // mov rcx, bindingValue
            EmitRawStubU64(codePointer, offsetValue, reinterpret_cast<std::uint64_t>(bindingValue));
            emit(0x48); emit(0x8D); emit(0x94); emit(0x24); // lea rdx, [rsp+0xA0]: saved entry frame
            EmitRawStubU32(codePointer, offsetValue, 0x000000A0U);
            emit(0x48); emit(0xB8);             // mov rax, RawHookEnter
            EmitRawStubU64(codePointer, offsetValue, reinterpret_cast<std::uint64_t>(&RawHookEnter));
            emit(0xFF); emit(0xD0);             // call rax

            EmitRawStubMovdquLoad(codePointer, offsetValue, 0, 0x20);
            EmitRawStubMovdquLoad(codePointer, offsetValue, 1, 0x30);
            EmitRawStubMovdquLoad(codePointer, offsetValue, 2, 0x40);
            EmitRawStubMovdquLoad(codePointer, offsetValue, 3, 0x50);
            EmitRawStubMovdquLoad(codePointer, offsetValue, 4, 0x60);
            EmitRawStubMovdquLoad(codePointer, offsetValue, 5, 0x70);

            emit(0x48); emit(0x81); emit(0xC4); // add rsp, 0xA0
            EmitRawStubU32(codePointer, offsetValue, 0x000000A0U);
            emit(0x41); emit(0x5B);             // pop r11
            emit(0x41); emit(0x5A);             // pop r10
            emit(0x41); emit(0x59);             // pop r9
            emit(0x41); emit(0x58);             // pop r8
            emit(0x5A);                         // pop rdx
            emit(0x59);                         // pop rcx
            emit(0x58);                         // pop rax
            emit(0x49); emit(0xBB);             // mov r11, &bindingValue->originalAddress
            EmitRawStubU64(codePointer, offsetValue, reinterpret_cast<std::uint64_t>(&bindingValue->originalAddress));
            emit(0x4D); emit(0x8B); emit(0x1B); // mov r11, [r11]
            emit(0x41); emit(0xFF); emit(0xE3); // jmp r11

            ::FlushInstructionCache(::GetCurrentProcess(), codePointer, offsetValue);
            return codePointer;
#endif
        }

        void FreeRawEntryStub(void* const stubAddress)
        {
            if (stubAddress != nullptr)
            {
                detail::ReleaseCodePage(stubAddress);
            }
        }

        bool NetworkCompletionObserver(const HookBinding& binding)
        {
            if (!ActiveConfig().enableNetwork) return false;
            const char* name = binding.procName;
            return strcmp(name, "CloseHandle") == 0 || strcmp(name, "CreateIoCompletionPort") == 0
                || strcmp(name, "GetOverlappedResult") == 0 || strcmp(name, "GetOverlappedResultEx") == 0
                || strcmp(name, "GetQueuedCompletionStatus") == 0 || strcmp(name, "GetQueuedCompletionStatusEx") == 0
                || strcmp(name, "SetFileCompletionNotificationModes") == 0
                || strcmp(name, "CancelIo") == 0 || strcmp(name, "CancelIoEx") == 0;
        }

        bool TryInstallBinding(HookBinding& bindingValue, std::wstring* detailTextOut)
        {
            FakeSuccessRuntimeRule* const fakeRule = FindFakeSuccessRule(bindingValue.moduleName, bindingValue.procName);
            if (fakeRule != nullptr)
            {
                return TryInstallFakeSuccessRule(*fakeRule, bindingValue.categoryValue, detailTextOut);
            }

            const bool childCreation = ActiveConfig().autoInjectChild &&
                (std::strcmp(bindingValue.procName, "CreateProcessA") == 0
                 || std::strcmp(bindingValue.procName, "CreateProcessW") == 0
                 || std::strcmp(bindingValue.procName, "CreateProcessAsUserA") == 0
                 || std::strcmp(bindingValue.procName, "CreateProcessAsUserW") == 0
                 || std::strcmp(bindingValue.procName, "CreateProcessWithTokenW") == 0
                 || std::strcmp(bindingValue.procName, "CreateProcessWithLogonW") == 0);
            if ((!CategoryEnabled(bindingValue.categoryValue) && !childCreation && !NetworkCompletionObserver(bindingValue))
                || bindingValue.hookRecord->installed
                || bindingValue.hookRecord->permanentlyDisabled)
            {
                return bindingValue.hookRecord->installed;
            }

            std::wstring errorText;
            const InlineHookInstallResult installResult = InstallInlineHook(
                bindingValue.moduleName,
                bindingValue.procName,
                bindingValue.hookAddress,
                bindingValue.hookRecord,
                bindingValue.originalOut,
                &errorText);
            if (installResult == InlineHookInstallResult::Installed)
            {
                return true;
            }
            if (installResult == InlineHookInstallResult::PermanentFailure)
            {
                bindingValue.hookRecord->permanentlyDisabled = true;
            }
            AppendHookFailureText(detailTextOut, bindingValue, installResult, errorText);
            return false;
        }

        // SendLoaderEventIfEnabled 作用：
        // - 输入：LoadLibrary API 名、路径、结果和错误码；
        // - 处理：仅在 UI 勾选加载器分类时上报，避免“补装所需加载器 hook”强制制造事件噪声；
        // - 返回：无返回值，保留调用者负责恢复 LastError。
        void SendLoaderEventIfEnabled(
            const wchar_t* const apiName,
            const std::wstring& fileNameText,
            const HMODULE moduleHandle,
            const DWORD lastError,
            const std::wstring& extraText,
            const ApiCallDuration& duration)
        {
            if (!ActiveConfig().enableLoader)
            {
                return;
            }

            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Loader,
                L"Kernel32",
                apiName,
                moduleHandle != nullptr ? 0 : static_cast<std::int32_t>(lastError),
                TrimDetail(L"path=" + fileNameText + extraText).c_str(), true, ApiReturnBits(moduleHandle), duration);
        }

        // JoinIniList 作用：
        // - 输入：MonitorConfig 中已拆分的 Raw 模块/黑名单列表；
        // - 处理：按 INI 单行格式重新用分号拼接，供自动注入子进程继承父进程 Raw 配置；
        // - 返回：可直接写入 config_<pid>.ini 的列表文本。
        std::wstring JoinIniList(const std::vector<std::wstring>& itemList)
        {
            std::wstring joinedText;
            for (const std::wstring& itemText : itemList)
            {
                if (itemText.empty())
                {
                    continue;
                }
                if (!joinedText.empty())
                {
                    joinedText.append(L";");
                }
                joinedText.append(itemText);
            }
            return joinedText;
        }

        // WriteChildMonitorConfig 作用：
        // - 输入：childPidValue 为新子进程 PID，configValue 为父进程当前监控配置；
        // - 处理：生成子进程专属 INI，沿用当前分类开关、DLL 路径和自动注入策略；
        // - 返回：成功写入返回 true，失败返回 false 并填充 errorTextOut。
        bool WriteChildMonitorConfig(
            const DWORD childPidValue,
            const MonitorConfig& configValue,
            std::wstring* const errorTextOut)
        {
            if (errorTextOut != nullptr)
            {
                errorTextOut->clear();
            }
            if (childPidValue == 0 || configValue.agentDllPath.empty())
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"child pid or agent dll path is empty.";
                }
                return false;
            }

            std::wstring sessionError;
            if (!ks::winapi_monitor::addSessionDirectoryReader(childPidValue, &sessionError))
            {
                if (errorTextOut != nullptr) *errorTextOut = sessionError;
                return false;
            }

            const std::wstring childConfigPath = ks::winapi_monitor::buildConfigPathForPid(childPidValue);
            const std::wstring childStopPath = ks::winapi_monitor::buildStopFlagPathForPid(childPidValue);
            const std::wstring temporaryPath = childConfigPath + L".tmp_" + std::to_wstring(::GetCurrentThreadId());

            HANDLE fileHandle = ::CreateFileW(
                temporaryPath.c_str(),
                GENERIC_WRITE,
                FILE_SHARE_READ,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"CreateFileW child config failed. error=" + std::to_wstring(::GetLastError());
                }
                return false;
            }

            const std::wstring configText =
                L"[monitor]\r\n"
                L"pipe_name=" + ks::winapi_monitor::buildPipeNameForPid(childPidValue) + L"\r\n"
                L"stop_flag_path=" + childStopPath + L"\r\n"
                L"root_stop_flag_path=" + (configValue.rootStopFlagPath.empty() ? configValue.stopFlagPath : configValue.rootStopFlagPath) + L"\r\n"
                L"pause_event_name=" + configValue.pauseEventName + L"\r\n"
                L"session_id=" + configValue.sessionId + L"_" + std::to_wstring(childPidValue) + L"_" + std::to_wstring(::GetTickCount64()) + L"\r\n"
                L"controller_sid=" + configValue.controllerSid + L"\r\n"
                L"agent_dll_path=" + configValue.agentDllPath + L"\r\n"
                L"injection_broker_pipe=" + configValue.injectionEndpoint.pipeName + L"\r\n"
                L"injection_broker_token=" + configValue.injectionEndpoint.token + L"\r\n"
                L"injection_broker_pid=" + std::to_wstring(configValue.injectionEndpoint.hostPid) + L"\r\n"
                L"injection_broker_creation=" + std::to_wstring(configValue.injectionEndpoint.hostCreation) + L"\r\n"
                L"enable_file=" + std::to_wstring(configValue.enableFile ? 1 : 0) + L"\r\n"
                L"enable_registry=" + std::to_wstring(configValue.enableRegistry ? 1 : 0) + L"\r\n"
                L"enable_network=" + std::to_wstring(configValue.enableNetwork ? 1 : 0) + L"\r\n"
                L"enable_process=" + std::to_wstring(configValue.enableProcess ? 1 : 0) + L"\r\n"
                L"enable_loader=" + std::to_wstring(configValue.enableLoader ? 1 : 0) + L"\r\n"
                L"enable_clipboard=" + std::to_wstring(configValue.enableClipboard ? 1 : 0) + L"\r\n"
                L"clipboard_read_action=" + std::to_wstring(static_cast<unsigned>(configValue.clipboardReadAction)) + L"\r\n"
                L"clipboard_write_action=" + std::to_wstring(static_cast<unsigned>(configValue.clipboardWriteAction)) + L"\r\n"
                L"clipboard_enum_action=" + std::to_wstring(static_cast<unsigned>(configValue.clipboardEnumAction)) + L"\r\n"
                L"auto_inject_child=" + std::to_wstring(configValue.autoInjectChild ? 1 : 0) + L"\r\n"
                L"capture_call_stack=" + std::to_wstring(configValue.captureCallStack ? 1 : 0) + L"\r\n"
                L"enable_raw_fallback=" + std::to_wstring(configValue.enableRawFallback ? 1 : 0) + L"\r\n"
                L"raw_use_default_denylist=" + std::to_wstring(configValue.rawUseDefaultDenyList ? 1 : 0) + L"\r\n"
                L"raw_modules=" + JoinIniList(configValue.rawModuleList) + L"\r\n"
                L"raw_denylist=" + JoinIniList(configValue.rawDenyList) + L"\r\n"
                L"fake_success_enabled=" + std::to_wstring(configValue.fakeSuccessEnabled ? 1 : 0) + L"\r\n"
                L"fake_success_raw_fallback=" + std::to_wstring(configValue.fakeSuccessRawFallback ? 1 : 0) + L"\r\n"
                L"fake_success_rules=" + configValue.fakeSuccessRulesText + L"\r\n"
                L"detail_limit=" + std::to_wstring(configValue.detailLimitChars) + L"\r\n";

            const wchar_t unicodeBom = static_cast<wchar_t>(0xFEFF);
            DWORD bomBytesWritten = 0;
            const BOOL bomWriteOk = ::WriteFile(
                fileHandle,
                &unicodeBom,
                sizeof(unicodeBom),
                &bomBytesWritten,
                nullptr);

            DWORD bytesWritten = 0;
            const BOOL writeOk = ::WriteFile(
                fileHandle,
                configText.data(),
                static_cast<DWORD>(configText.size() * sizeof(wchar_t)),
                &bytesWritten,
                nullptr);
            const DWORD writeError = ::GetLastError();
            ::CloseHandle(fileHandle);

            if (bomWriteOk == FALSE
                || bomBytesWritten != sizeof(unicodeBom)
                || writeOk == FALSE
                || bytesWritten != configText.size() * sizeof(wchar_t))
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = L"WriteFile child config failed. error=" + std::to_wstring(writeError);
                }
                (void)::DeleteFileW(temporaryPath.c_str());
                return false;
            }
            if (!::MoveFileExW(temporaryPath.c_str(), childConfigPath.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            {
                if (errorTextOut) *errorTextOut = L"Atomic child config commit failed. error=" + std::to_wstring(::GetLastError());
                (void)::DeleteFileW(temporaryPath.c_str());
                return false;
            }
            if (!ks::winapi_monitor::grantSessionFileRead(childConfigPath, childPidValue, errorTextOut))
            {
                return false;
            }
            if (::GetFileAttributesW(childStopPath.c_str()) != INVALID_FILE_ATTRIBUTES && !::DeleteFileW(childStopPath.c_str()))
            {
                if (errorTextOut) *errorTextOut = L"Could not remove child stop flag. error=" + std::to_wstring(::GetLastError());
                return false;
            }
            return true;
        }

        // InjectAgentIntoChildProcess 作用：
        // - 输入：childPidValue 为子进程 PID，dllPath 为匹配子进程位数的 Agent 路径；
        // - 处理：请求主程序会话注入服务，保持目标位数与进程身份校验；
        // - 返回：注入成功返回 true，失败返回 false 并填充 errorTextOut。
        bool InjectAgentIntoChildProcess(
            const DWORD childPidValue,
            const HANDLE childProcess,
            const MonitorConfig& config,
            std::wstring* const errorTextOut)
        {
            return ks::winapi_monitor::requestChildInjection(config.injectionEndpoint, childPidValue,
                ks::winapi_monitor::processCreationIdentity(childProcess), errorTextOut);
        }

        // AutoInjectChildIfRequested 作用：
        // - 输入：CreateProcessW 结果和 PROCESS_INFORMATION；
        // - 处理：配置启用时为子进程写配置并注入当前 Agent；
        // - 返回：无返回值，成功/失败均以内部事件上报。
        void AutoInjectChildIfRequested(
            const BOOL createResult,
            const PROCESS_INFORMATION* const processInfoPointer)
        {
            const MonitorConfig& configValue = ActiveConfig();
            if (createResult == FALSE
                || StopRequested() || IsStopFlagPresent(configValue)
                || !configValue.autoInjectChild
                || processInfoPointer == nullptr
                || processInfoPointer->dwProcessId == 0
                || configValue.agentDllPath.empty())
            {
                return;
            }

            std::wstring errorText;
            ks::winapi_monitor::SessionLease childLease;
            DWORD leaseError = 0;
            bool successValue = childLease.acquire(processInfoPointer->dwProcessId, &leaseError);
            if (!successValue) errorText = L"Child Agent session is already owned or unavailable. error=" + std::to_wstring(leaseError);
            MonitorConfig childConfig = configValue;
            if (successValue) successValue = ks::winapi_monitor::resolveAgentPath(
                processInfoPointer->dwProcessId, configValue.agentDllPath, &childConfig.agentDllPath, &errorText);
            if (successValue) successValue = WriteChildMonitorConfig(processInfoPointer->dwProcessId, childConfig, &errorText);
            if (successValue)
            {
                successValue = InjectAgentIntoChildProcess(processInfoPointer->dwProcessId, processInfoPointer->hProcess, childConfig, &errorText);
            }

            // The UI takes over the lease after receiving this notification.
            childLease.reset();
            SendMonitorEvent(
                ks::winapi_monitor::EventCategory::Internal,
                L"Agent",
                successValue ? L"AutoInjectChild" : L"AutoInjectChildFailed",
                successValue ? 0 : 1,
                TrimDetail(
                    L"childPid=" + std::to_wstring(processInfoPointer->dwProcessId)
                    + (successValue ? L" injected" : (L" error=" + errorText))));
        }

        // AutoInjectChildFromCreateProcessAIfRequested 作用：
        // - 输入：CreateProcessA 的返回值和 PROCESS_INFORMATION；
        // - 处理：复用 W 版子进程配置写入与注入逻辑；
        // - 返回：无返回值，成功/失败均由内部事件反映。
        void AutoInjectChildFromCreateProcessAIfRequested(
            const BOOL createResult,
            const PROCESS_INFORMATION* const processInfoPointer)
        {
            AutoInjectChildIfRequested(createResult, processInfoPointer);
        }


        void RetryPendingHooksFromHook();

        // HookedLdrLoadDll 作用：
        // - 输入：ntdll LdrLoadDll 的原始参数；
        // - 处理：先调用原函数，再在成功加载模块后补装延迟 Hook；
        // - 返回：保持原始 NTSTATUS，不改写加载器语义。
        NTSTATUS NTAPI HookedLdrLoadDll(PWSTR searchPathPointer, PULONG dllCharacteristicsPointer, PUNICODE_STRING dllNamePointer, PHANDLE moduleHandlePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_ldrLoadDllOriginal(searchPathPointer, dllCharacteristicsPointer, dllNamePointer, moduleHandlePointer);
            }

            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ldrLoadDllOriginal(searchPathPointer, dllCharacteristicsPointer, dllNamePointer, moduleHandlePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedError = ::GetLastError();
            if (NT_SUCCESS(statusValue))
            {
                RetryPendingHooksFromHook();
            }
            if (ActiveConfig().enableLoader)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                AppendWideText(detailBuffer, L"path=");
                AppendUnicodeStringText(detailBuffer, dllNamePointer);
                AppendWideText(detailBuffer, L" search=");
                if (searchPathPointer && reinterpret_cast<std::uintptr_t>(searchPathPointer) <= 0xFFFF)
                {
                    AppendWideText(detailBuffer, L"tagged:");
                    AppendHexText(detailBuffer, reinterpret_cast<std::uintptr_t>(searchPathPointer));
                }
                else AppendWideText(detailBuffer, searchPathPointer);
                AppendWideText(detailBuffer, L" flags=");
                ULONG flags = 0;
                if (dllCharacteristicsPointer) (void)ReadExportMemory(dllCharacteristicsPointer, &flags, sizeof(flags));
                AppendHexText(detailBuffer, flags);
                AppendWideText(detailBuffer, L" handle=");
                HANDLE module = nullptr;
                if (NT_SUCCESS(statusValue) && moduleHandlePointer) (void)ReadExportMemory(moduleHandlePointer, &module, sizeof(module));
                AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(module));
                SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Loader, L"ntdll", L"LdrLoadDll", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            }
            ::SetLastError(savedError);
            return statusValue;
        }

        HMODULE WINAPI HookedLoadLibraryA(const LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_loadLibraryAOriginal(fileNamePointer);
            }

            const std::wstring fileNameText = AnsiToWide(fileNamePointer);
            const auto callClock = BeginApiCallClock();
            HMODULE moduleHandle = g_loadLibraryAOriginal(fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                RetryPendingHooksFromHook();
            }
            SendLoaderEventIfEnabled(L"LoadLibraryA", fileNameText, moduleHandle, lastError, std::wstring(), duration);
            ::SetLastError(lastError);
            return moduleHandle;
        }

        HMODULE WINAPI HookedLoadLibraryW(const LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_loadLibraryWOriginal(fileNamePointer);
            }

            const std::wstring fileNameText = SafeWideText(fileNamePointer);
            const auto callClock = BeginApiCallClock();
            HMODULE moduleHandle = g_loadLibraryWOriginal(fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                RetryPendingHooksFromHook();
            }
            SendLoaderEventIfEnabled(L"LoadLibraryW", fileNameText, moduleHandle, lastError, std::wstring(), duration);
            ::SetLastError(lastError);
            return moduleHandle;
        }

        HMODULE WINAPI HookedLoadLibraryExA(const LPCSTR fileNamePointer, HANDLE fileHandle, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_loadLibraryExAOriginal(fileNamePointer, fileHandle, flagsValue);
            }

            const std::wstring fileNameText = AnsiToWide(fileNamePointer);
            const auto callClock = BeginApiCallClock();
            HMODULE moduleHandle = g_loadLibraryExAOriginal(fileNamePointer, fileHandle, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                RetryPendingHooksFromHook();
            }
            SendLoaderEventIfEnabled(L"LoadLibraryExA", fileNameText, moduleHandle, lastError, L" flags=" + HexValue(flagsValue), duration);
            ::SetLastError(lastError);
            return moduleHandle;
        }

        HMODULE WINAPI HookedLoadLibraryExW(const LPCWSTR fileNamePointer, HANDLE fileHandle, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_loadLibraryExWOriginal(fileNamePointer, fileHandle, flagsValue);
            }

            const std::wstring fileNameText = SafeWideText(fileNamePointer);
            const auto callClock = BeginApiCallClock();
            HMODULE moduleHandle = g_loadLibraryExWOriginal(fileNamePointer, fileHandle, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            if (moduleHandle != nullptr)
            {
                RetryPendingHooksFromHook();
            }
            SendLoaderEventIfEnabled(L"LoadLibraryExW", fileNameText, moduleHandle, lastError, L" flags=" + HexValue(flagsValue), duration);
            ::SetLastError(lastError);
            return moduleHandle;
        }

        HANDLE WINAPI HookedCreateFileA(LPCSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_createFileAOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            }

            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_createFileAOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            const DWORD lastError = ::GetLastError();
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildFilePathDetailA(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, flagsAndAttributes, resultHandle);
            SendFileEventWithReturn(L"CreateFileA", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, resultHandle, duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        HANDLE WINAPI HookedCreateFileW(LPCWSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, LPSECURITY_ATTRIBUTES securityAttributes, DWORD creationDisposition, DWORD flagsAndAttributes, HANDLE templateFile)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_createFileWOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            }

            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_createFileWOriginal(fileNamePointer, desiredAccess, shareMode, securityAttributes, creationDisposition, flagsAndAttributes, templateFile);
            const DWORD lastError = ::GetLastError();
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildFilePathDetailW(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, flagsAndAttributes, resultHandle);
            SendFileEventWithReturn(L"CreateFileW", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, resultHandle, duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        HANDLE WINAPI HookedCreateFile2(LPCWSTR fileNamePointer, DWORD desiredAccess, DWORD shareMode, DWORD creationDisposition, LPCREATEFILE2_EXTENDED_PARAMETERS createExParamsPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_createFile2Original(fileNamePointer, desiredAccess, shareMode, creationDisposition, createExParamsPointer);
            }

            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_createFile2Original(fileNamePointer, desiredAccess, shareMode, creationDisposition, createExParamsPointer);
            const DWORD lastError = ::GetLastError();
            const auto duration = EndApiCallClock(callClock);
            const DWORD flagsValue = createExParamsPointer != nullptr ? createExParamsPointer->dwFileFlags : 0;
            const DWORD attributesValue = createExParamsPointer != nullptr ? createExParamsPointer->dwFileAttributes : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildFilePathDetailW(detailBuffer, fileNamePointer, desiredAccess, shareMode, creationDisposition, flagsValue | attributesValue, resultHandle);
            SendFileEventWithReturn(L"CreateFile2", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, resultHandle, duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        #include "AsyncIoHandlers.inc"
        #include "WinsockExtensionHandlers.inc"

        BOOL WINAPI HookedReadFile(HANDLE fileHandle, LPVOID bufferPointer, DWORD bytesToRead, LPDWORD bytesReadPointer, LPOVERLAPPED overlappedPointer)
        {
            if (IsMonitorPipeHandle(fileHandle))
            {
                return g_readFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_readFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            }

            const DWORD incomingError = ::GetLastError();
            auto operation = BeginIo(reinterpret_cast<std::uintptr_t>(fileHandle), overlappedPointer,
                L"KernelBase", L"ReadFile", ks::winapi_monitor::EventCategory::File, bytesToRead);
            ::SetLastError(incomingError);
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_readFileOriginal(fileHandle, bufferPointer, bytesToRead, bytesReadPointer, overlappedPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            DWORD transferred = 0;
            const bool transferredKnown = resultValue != FALSE && !overlappedPointer && TrySafeIoValue(bytesReadPointer, &transferred);
            FinishIo(operation, resultValue || lastError == ERROR_IO_PENDING,
                !resultValue && lastError == ERROR_IO_PENDING, resultValue ? 0 : lastError, transferred, transferredKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildHandleTransferDetail(detailBuffer, fileHandle, bytesToRead, transferred, nullptr, transferredKnown);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"ReadFile", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedWriteFile(HANDLE fileHandle, LPCVOID bufferPointer, DWORD bytesToWrite, LPDWORD bytesWrittenPointer, LPOVERLAPPED overlappedPointer)
        {
            if (IsMonitorPipeHandle(fileHandle))
            {
                return g_writeFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_writeFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            }

            const DWORD incomingError = ::GetLastError();
            auto operation = BeginIo(reinterpret_cast<std::uintptr_t>(fileHandle), overlappedPointer,
                L"KernelBase", L"WriteFile", ks::winapi_monitor::EventCategory::File, bytesToWrite);
            ::SetLastError(incomingError);
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_writeFileOriginal(fileHandle, bufferPointer, bytesToWrite, bytesWrittenPointer, overlappedPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            DWORD transferred = 0;
            const bool transferredKnown = resultValue != FALSE && !overlappedPointer && TrySafeIoValue(bytesWrittenPointer, &transferred);
            FinishIo(operation, resultValue || lastError == ERROR_IO_PENDING,
                !resultValue && lastError == ERROR_IO_PENDING, resultValue ? 0 : lastError, transferred, transferredKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildHandleTransferDetail(detailBuffer, fileHandle, bytesToWrite, transferred, nullptr, transferredKnown);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"WriteFile", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedDeviceIoControl 作用：
        // - 输入：设备句柄、IOCTL 控制码、输入/输出缓冲与重叠结构；
        // - 处理：调用原始 DeviceIoControl 后记录控制码和传输规模，覆盖驱动通信/设备控制行为；
        // - 返回：保持原始 BOOL 结果，并恢复调用者可见的 LastError。
        BOOL WINAPI HookedDeviceIoControl(
            HANDLE deviceHandle,
            DWORD ioControlCode,
            LPVOID inBufferPointer,
            DWORD inBufferSize,
            LPVOID outBufferPointer,
            DWORD outBufferSize,
            LPDWORD bytesReturnedPointer,
            LPOVERLAPPED overlappedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_deviceIoControlOriginal(deviceHandle, ioControlCode, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer);
            }

            const DWORD incomingError = ::GetLastError();
            auto operation = BeginIo(reinterpret_cast<std::uintptr_t>(deviceHandle), overlappedPointer,
                L"KernelBase", L"DeviceIoControl", ks::winapi_monitor::EventCategory::File, outBufferSize);
            ::SetLastError(incomingError);
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_deviceIoControlOriginal(deviceHandle, ioControlCode, inBufferPointer, inBufferSize, outBufferPointer, outBufferSize, bytesReturnedPointer, overlappedPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            DWORD transferred = 0;
            const bool transferredKnown = resultValue != FALSE && !overlappedPointer && TrySafeIoValue(bytesReturnedPointer, &transferred);
            FinishIo(operation, resultValue || lastError == ERROR_IO_PENDING,
                !resultValue && lastError == ERROR_IO_PENDING, resultValue ? 0 : lastError, transferred, transferredKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(deviceHandle));
            AppendWideText(detailBuffer, L" code=");
            AppendHexText(detailBuffer, ioControlCode);
            AppendWideText(detailBuffer, L" in=");
            AppendUnsignedText(detailBuffer, inBufferSize);
            AppendWideText(detailBuffer, L" out=");
            AppendUnsignedText(detailBuffer, outBufferSize);
            AppendWideText(detailBuffer, L" returned=");
            if (transferredKnown) AppendUnsignedText(detailBuffer, transferred);
            else AppendWideText(detailBuffer, L"unknown");
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"DeviceIoControl", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }







        BOOL WINAPI HookedMoveFileExW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_moveFileExWOriginal(existingFileNamePointer, newFileNamePointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_moveFileExWOriginal(existingFileNamePointer, newFileNamePointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"MoveFileExW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedMoveFileExA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_moveFileExAOriginal(existingFileNamePointer, newFileNamePointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_moveFileExAOriginal(existingFileNamePointer, newFileNamePointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"MoveFileExA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCopyFileW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, BOOL failIfExists)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_copyFileWOriginal(existingFileNamePointer, newFileNamePointer, failIfExists); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_copyFileWOriginal(existingFileNamePointer, newFileNamePointer, failIfExists);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, failIfExists ? 1 : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CopyFileW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCopyFileA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, BOOL failIfExists)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_copyFileAOriginal(existingFileNamePointer, newFileNamePointer, failIfExists); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_copyFileAOriginal(existingFileNamePointer, newFileNamePointer, failIfExists);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, failIfExists ? 1 : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CopyFileA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCopyFileExW(LPCWSTR existingFileNamePointer, LPCWSTR newFileNamePointer, LPPROGRESS_ROUTINE progressRoutinePointer, LPVOID dataPointer, LPBOOL cancelPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_copyFileExWOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_copyFileExWOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailW(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CopyFileExW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCopyFileExA(LPCSTR existingFileNamePointer, LPCSTR newFileNamePointer, LPPROGRESS_ROUTINE progressRoutinePointer, LPVOID dataPointer, LPBOOL cancelPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_copyFileExAOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_copyFileExAOriginal(existingFileNamePointer, newFileNamePointer, progressRoutinePointer, dataPointer, cancelPointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailA(detailBuffer, existingFileNamePointer, newFileNamePointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CopyFileExA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetFileAttributesW(LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFileAttributesWOriginal(fileNamePointer); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getFileAttributesWOriginal(fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFileAttributesW", resultValue != INVALID_FILE_ATTRIBUTES ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetFileAttributesA(LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFileAttributesAOriginal(fileNamePointer); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getFileAttributesAOriginal(fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFileAttributesA", resultValue != INVALID_FILE_ATTRIBUTES ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedGetFileAttributesExW(LPCWSTR fileNamePointer, GET_FILEEX_INFO_LEVELS infoLevelValue, LPVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFileAttributesExWOriginal(fileNamePointer, infoLevelValue, fileInformationPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_getFileAttributesExWOriginal(fileNamePointer, infoLevelValue, fileInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, static_cast<DWORD>(infoLevelValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFileAttributesExW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedGetFileAttributesExA(LPCSTR fileNamePointer, GET_FILEEX_INFO_LEVELS infoLevelValue, LPVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFileAttributesExAOriginal(fileNamePointer, infoLevelValue, fileInformationPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_getFileAttributesExAOriginal(fileNamePointer, infoLevelValue, fileInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, static_cast<DWORD>(infoLevelValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFileAttributesExA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedSetFileAttributesW(LPCWSTR fileNamePointer, DWORD fileAttributes)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_setFileAttributesWOriginal(fileNamePointer, fileAttributes); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_setFileAttributesWOriginal(fileNamePointer, fileAttributes);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, fileAttributes);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"SetFileAttributesW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedSetFileAttributesA(LPCSTR fileNamePointer, DWORD fileAttributes)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_setFileAttributesAOriginal(fileNamePointer, fileAttributes); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_setFileAttributesAOriginal(fileNamePointer, fileAttributes);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, fileAttributes);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"SetFileAttributesA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        HANDLE WINAPI HookedFindFirstFileExW(LPCWSTR fileNamePointer, FINDEX_INFO_LEVELS infoLevelValue, LPVOID findFileDataPointer, FINDEX_SEARCH_OPS searchOpValue, LPVOID searchFilterPointer, DWORD additionalFlags)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_findFirstFileExWOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_findFirstFileExWOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, fileNamePointer, additionalFlags);
            AppendWideText(detailBuffer, L" info=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoLevelValue));
            AppendWideText(detailBuffer, L" search=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(searchOpValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"FindFirstFileExW", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        HANDLE WINAPI HookedFindFirstFileExA(LPCSTR fileNamePointer, FINDEX_INFO_LEVELS infoLevelValue, LPVOID findFileDataPointer, FINDEX_SEARCH_OPS searchOpValue, LPVOID searchFilterPointer, DWORD additionalFlags)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_findFirstFileExAOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_findFirstFileExAOriginal(fileNamePointer, infoLevelValue, findFileDataPointer, searchOpValue, searchFilterPointer, additionalFlags);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, fileNamePointer, additionalFlags);
            AppendWideText(detailBuffer, L" info=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(infoLevelValue));
            AppendWideText(detailBuffer, L" search=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(searchOpValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"FindFirstFileExA", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        BOOL WINAPI HookedCreateDirectoryW(LPCWSTR pathNamePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createDirectoryWOriginal(pathNamePointer, securityAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_createDirectoryWOriginal(pathNamePointer, securityAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailW(detailBuffer, pathNamePointer, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CreateDirectoryW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCreateDirectoryA(LPCSTR pathNamePointer, LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createDirectoryAOriginal(pathNamePointer, securityAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_createDirectoryAOriginal(pathNamePointer, securityAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSinglePathDetailA(detailBuffer, pathNamePointer, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CreateDirectoryA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedSetFileInformationByHandle(HANDLE fileHandle, FILE_INFO_BY_HANDLE_CLASS fileInformationClass, LPVOID fileInformationPointer, DWORD bufferSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_setFileInformationByHandleOriginal(fileHandle, fileInformationClass, fileInformationPointer, bufferSize); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_setFileInformationByHandleOriginal(fileHandle, fileInformationClass, fileInformationPointer, bufferSize);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, bufferSize);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"SetFileInformationByHandle", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCreateProcessA(LPCSTR applicationNamePointer, LPSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCSTR currentDirectoryPointer, LPSTARTUPINFOA startupInfoPointer, LPPROCESS_INFORMATION processInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_createProcessAOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            }

            const std::wstring appNameText = AnsiToWide(applicationNamePointer);
            const std::wstring commandLineText = AnsiToWide(commandLinePointer);
            const std::wstring currentDirectoryText = AnsiToWide(currentDirectoryPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_createProcessAOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            const DWORD childPid = (resultValue != FALSE && processInfoPointer != nullptr) ? processInfoPointer->dwProcessId : 0;
            AutoInjectChildFromCreateProcessAIfRequested(resultValue, processInfoPointer);
            if (ActiveConfig().enableProcess) SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"CreateProcessA", resultValue != FALSE ? 0 : static_cast<std::int32_t>(lastError), TrimDetail(L"app=" + appNameText + L" cmd=" + commandLineText + L" cwd=" + currentDirectoryText + L" flags=" + HexValue(creationFlags) + L" inherit=" + std::to_wstring(inheritHandles != FALSE) + L" childPid=" + std::to_wstring(childPid)).c_str(), true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCreateProcessW(LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_createProcessWOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            }

            const std::wstring appNameText = SafeWideText(applicationNamePointer);
            const std::wstring commandLineText = commandLinePointer != nullptr ? std::wstring(commandLinePointer) : std::wstring();
            const std::wstring currentDirectoryText = SafeWideText(currentDirectoryPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_createProcessWOriginal(applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInfoPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            const DWORD childPid = (resultValue != FALSE && processInfoPointer != nullptr) ? processInfoPointer->dwProcessId : 0;
            AutoInjectChildIfRequested(resultValue, processInfoPointer);
            if (ActiveConfig().enableProcess) SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"CreateProcessW", resultValue != FALSE ? 0 : static_cast<std::int32_t>(lastError), TrimDetail(L"app=" + appNameText + L" cmd=" + commandLineText + L" cwd=" + currentDirectoryText + L" flags=" + HexValue(creationFlags) + L" inherit=" + std::to_wstring(inheritHandles != FALSE) + L" childPid=" + std::to_wstring(childPid)).c_str(), true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        HANDLE WINAPI HookedOpenProcess(DWORD desiredAccess, BOOL inheritHandle, DWORD processId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_openProcessOriginal(desiredAccess, inheritHandle, processId); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_openProcessOriginal(desiredAccess, inheritHandle, processId);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildProcessHandleDetail(detailBuffer, nullptr, desiredAccess, processId, resultHandle);
            AppendWideText(detailBuffer, L" inherit=");
            AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1 : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"OpenProcess", resultHandle != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        BOOL WINAPI HookedTerminateProcess(HANDLE processHandle, UINT exitCode)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_terminateProcessOriginal(processHandle, exitCode); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_terminateProcessOriginal(processHandle, exitCode);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" exit=");
            AppendUnsignedText(detailBuffer, exitCode);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"TerminateProcess", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES threadAttributesPointer, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPDWORD threadIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createThreadOriginal(threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_createThreadOriginal(threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"start=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress));
            AppendWideText(detailBuffer, L" param=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, creationFlags);
            AppendWideText(detailBuffer, L" tid=");
            AppendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"CreateThread", resultHandle != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        HANDLE WINAPI HookedCreateRemoteThread(HANDLE processHandle, LPSECURITY_ATTRIBUTES threadAttributesPointer, SIZE_T stackSize, LPTHREAD_START_ROUTINE startAddress, LPVOID parameterPointer, DWORD creationFlags, LPDWORD threadIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createRemoteThreadOriginal(processHandle, threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_createRemoteThreadOriginal(processHandle, threadAttributesPointer, stackSize, startAddress, parameterPointer, creationFlags, threadIdPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" start=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startAddress));
            AppendWideText(detailBuffer, L" param=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parameterPointer));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, creationFlags);
            AppendWideText(detailBuffer, L" tid=");
            AppendUnsignedText(detailBuffer, threadIdPointer != nullptr ? *threadIdPointer : 0);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"CreateRemoteThread", resultHandle != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        LPVOID WINAPI HookedVirtualAllocEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD allocationType, DWORD protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_virtualAllocExOriginal(processHandle, addressPointer, sizeValue, allocationType, protectValue); }
            const auto callClock = BeginApiCallClock();
            LPVOID resultPointer = g_virtualAllocExOriginal(processHandle, addressPointer, sizeValue, allocationType, protectValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, resultPointer != nullptr ? resultPointer : addressPointer, static_cast<std::uint64_t>(sizeValue), allocationType, protectValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"VirtualAllocEx", resultPointer != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultPointer), duration);
            ::SetLastError(lastError);
            return resultPointer;
        }

        BOOL WINAPI HookedVirtualFreeEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD freeType)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_virtualFreeExOriginal(processHandle, addressPointer, sizeValue, freeType); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_virtualFreeExOriginal(processHandle, addressPointer, sizeValue, freeType);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, addressPointer, static_cast<std::uint64_t>(sizeValue), freeType, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"VirtualFreeEx", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedVirtualProtectEx(HANDLE processHandle, LPVOID addressPointer, SIZE_T sizeValue, DWORD newProtect, PDWORD oldProtectPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_virtualProtectExOriginal(processHandle, addressPointer, sizeValue, newProtect, oldProtectPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_virtualProtectExOriginal(processHandle, addressPointer, sizeValue, newProtect, oldProtectPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, addressPointer, static_cast<std::uint64_t>(sizeValue), oldProtectPointer != nullptr ? *oldProtectPointer : 0, newProtect);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"VirtualProtectEx", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedWriteProcessMemory(HANDLE processHandle, LPVOID baseAddress, LPCVOID bufferPointer, SIZE_T sizeValue, SIZE_T* bytesWrittenPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_writeProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_writeProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            AppendWideText(detailBuffer, L" written=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesWrittenPointer != nullptr ? *bytesWrittenPointer : 0));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"WriteProcessMemory", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedReadProcessMemory(HANDLE processHandle, LPCVOID baseAddress, LPVOID bufferPointer, SIZE_T sizeValue, SIZE_T* bytesReadPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_readProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_readProcessMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            AppendWideText(detailBuffer, L" read=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(bytesReadPointer != nullptr ? *bytesReadPointer : 0));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"ReadProcessMemory", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedOpenThread 作用：
        // - 输入：线程访问掩码、继承标志和线程 ID；
        // - 处理：记录线程句柄打开，补齐后续 Suspend/Resume/Context/APC 链路上游；
        // - 返回：保持 OpenThread 原始 HANDLE，并恢复 LastError。
        HANDLE WINAPI HookedOpenThread(DWORD desiredAccess, BOOL inheritHandle, DWORD threadId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_openThreadOriginal(desiredAccess, inheritHandle, threadId); }
            const auto callClock = BeginApiCallClock();
            HANDLE resultHandle = g_openThreadOriginal(desiredAccess, inheritHandle, threadId);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"tid=");
            AppendUnsignedText(detailBuffer, threadId);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" inherit=");
            AppendUnsignedText(detailBuffer, inheritHandle != FALSE ? 1 : 0);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"OpenThread", resultHandle != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }

        // HookedSuspendThread 作用：
        // - 输入：目标线程句柄；
        // - 处理：记录线程挂起操作和原始挂起计数，覆盖调试/注入常见控制面；
        // - 返回：保持 SuspendThread 返回值，并恢复 LastError。
        DWORD WINAPI HookedSuspendThread(HANDLE threadHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_suspendThreadOriginal(threadHandle); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_suspendThreadOriginal(threadHandle);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" previous=");
            AppendUnsignedText(detailBuffer, resultValue == static_cast<DWORD>(-1) ? 0 : resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"SuspendThread", resultValue != static_cast<DWORD>(-1) ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedResumeThread 作用：
        // - 输入：目标线程句柄；
        // - 处理：记录线程恢复操作和原始挂起计数；
        // - 返回：保持 ResumeThread 返回值，并恢复 LastError。
        DWORD WINAPI HookedResumeThread(HANDLE threadHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_resumeThreadOriginal(threadHandle); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_resumeThreadOriginal(threadHandle);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" previous=");
            AppendUnsignedText(detailBuffer, resultValue == static_cast<DWORD>(-1) ? 0 : resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"ResumeThread", resultValue != static_cast<DWORD>(-1) ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedQueueUserAPC 作用：
        // - 输入：APC 函数地址、线程句柄和参数；
        // - 处理：记录用户态 APC 排队，覆盖 QueueUserAPC 注入路径；
        // - 返回：保持 QueueUserAPC 的 DWORD 结果并恢复 LastError。
        DWORD WINAPI HookedQueueUserAPC(PAPCFUNC apcRoutinePointer, HANDLE threadHandle, ULONG_PTR dataValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_queueUserAPCOriginal(apcRoutinePointer, threadHandle, dataValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_queueUserAPCOriginal(apcRoutinePointer, threadHandle, dataValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" apc=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            AppendWideText(detailBuffer, L" data=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(dataValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"QueueUserAPC", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedGetThreadContext 作用：
        // - 输入：线程句柄和 CONTEXT 输出缓冲；
        // - 处理：记录线程上下文读取，便于识别调试/劫持前置动作；
        // - 返回：保持原始 BOOL 结果，并恢复 LastError。
        BOOL WINAPI HookedGetThreadContext(HANDLE threadHandle, LPCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getThreadContextOriginal(threadHandle, contextPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_getThreadContextOriginal(threadHandle, contextPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"GetThreadContext", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedSetThreadContext 作用：
        // - 输入：线程句柄和 CONTEXT 输入缓冲；
        // - 处理：记录线程上下文写入，覆盖 SetThreadContext 注入/劫持路径；
        // - 返回：保持原始 BOOL 结果，并恢复 LastError。
        BOOL WINAPI HookedSetThreadContext(HANDLE threadHandle, const CONTEXT* contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_setThreadContextOriginal(threadHandle, contextPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_setThreadContextOriginal(threadHandle, contextPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
#if defined(_M_X64)
            AppendWideText(detailBuffer, L" rip=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->Rip : 0);
#endif
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"SetThreadContext", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        UINT WINAPI HookedWinExec(LPCSTR commandLinePointer, UINT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_winExecOriginal(commandLinePointer, showCommand); }
            const auto callClock = BeginApiCallClock();
            const UINT resultValue = g_winExecOriginal(commandLinePointer, showCommand);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"cmd=");
            AppendAnsiText(detailBuffer, commandLinePointer);
            AppendWideText(detailBuffer, L" show=");
            AppendUnsignedText(detailBuffer, showCommand);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Kernel32", L"WinExec", resultValue > 31 ? 0 : resultValue, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedShellExecuteExW(SHELLEXECUTEINFOW* executeInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_shellExecuteExWOriginal(executeInfoPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_shellExecuteExWOriginal(executeInfoPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"file=");
            AppendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpFile : nullptr);
            AppendWideText(detailBuffer, L" verb=");
            AppendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpVerb : nullptr);
            AppendWideText(detailBuffer, L" params=");
            AppendWideText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpParameters : nullptr);
            AppendWideText(detailBuffer, L" process=");
            AppendHexText(detailBuffer, executeInfoPointer != nullptr ? reinterpret_cast<std::uint64_t>(executeInfoPointer->hProcess) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Shell32", L"ShellExecuteExW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedShellExecuteExA(SHELLEXECUTEINFOA* executeInfoPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_shellExecuteExAOriginal(executeInfoPointer); }
            const auto callClock = BeginApiCallClock();
            const BOOL resultValue = g_shellExecuteExAOriginal(executeInfoPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"file=");
            AppendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpFile : nullptr);
            AppendWideText(detailBuffer, L" verb=");
            AppendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpVerb : nullptr);
            AppendWideText(detailBuffer, L" params=");
            AppendAnsiText(detailBuffer, executeInfoPointer != nullptr ? executeInfoPointer->lpParameters : nullptr);
            AppendWideText(detailBuffer, L" process=");
            AppendHexText(detailBuffer, executeInfoPointer != nullptr ? reinterpret_cast<std::uint64_t>(executeInfoPointer->hProcess) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Shell32", L"ShellExecuteExA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }


#define APIMON_REG_SEND(ApiName, StatusValue, DetailBuffer, Duration) \
        SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"Advapi32", ApiName, static_cast<std::int32_t>(StatusValue), DetailBuffer, true, ApiReturnBits(StatusValue), Duration)

        LSTATUS WINAPI HookedRegOpenKeyW(HKEY rootKey, LPCWSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regOpenKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regOpenKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegOpenKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegOpenKeyA(HKEY rootKey, LPCSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regOpenKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regOpenKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegOpenKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegOpenKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regOpenKeyExWOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regOpenKeyExWOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegOpenDetail(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegOpenKeyExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegOpenKeyExA(HKEY rootKey, LPCSTR subKeyPointer, DWORD optionsValue, REGSAM samDesired, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regOpenKeyExAOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regOpenKeyExAOriginal(rootKey, subKeyPointer, optionsValue, samDesired, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegOpenDetailA(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegOpenKeyExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCreateKeyW(HKEY rootKey, LPCWSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCreateKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCreateKeyWOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, 0, 0);
            APIMON_REG_SEND(L"RegCreateKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCreateKeyA(HKEY rootKey, LPCSTR subKeyPointer, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCreateKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCreateKeyAOriginal(rootKey, subKeyPointer, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, 0, 0);
            APIMON_REG_SEND(L"RegCreateKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCreateKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, DWORD reservedValue, LPWSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCreateKeyExWOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCreateKeyExWOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegCreateDetail(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0);
            APIMON_REG_SEND(L"RegCreateKeyExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCreateKeyExA(HKEY rootKey, LPCSTR subKeyPointer, DWORD reservedValue, LPSTR classPointer, DWORD optionsValue, REGSAM samDesired, const LPSECURITY_ATTRIBUTES securityAttributes, PHKEY resultKeyPointer, LPDWORD dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCreateKeyExAOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCreateKeyExAOriginal(rootKey, subKeyPointer, reservedValue, classPointer, optionsValue, samDesired, securityAttributes, resultKeyPointer, dispositionPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegCreateDetailA(detailBuffer, rootKey, subKeyPointer, optionsValue, dispositionPointer != nullptr ? *dispositionPointer : 0);
            APIMON_REG_SEND(L"RegCreateKeyExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegQueryValueExW(HKEY keyHandle, LPCWSTR valueNamePointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regQueryValueExWOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regQueryValueExWOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegQueryValueExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegQueryValueExA(HKEY keyHandle, LPCSTR valueNamePointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regQueryValueExAOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regQueryValueExAOriginal(keyHandle, valueNamePointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegQueryValueExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegGetValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer, DWORD flagsValue, LPDWORD typePointer, PVOID dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regGetValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regGetValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegGetValueDetail(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegGetValueW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegGetValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer, DWORD flagsValue, LPDWORD typePointer, PVOID dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regGetValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regGetValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegGetValueDetailA(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, flagsValue, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            APIMON_REG_SEND(L"RegGetValueA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSetValueExW(HKEY keyHandle, LPCWSTR valueNamePointer, DWORD reservedValue, DWORD typeValue, const BYTE* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSetValueExWOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSetValueExWOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSetValueDetail(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetValueExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSetValueExA(HKEY keyHandle, LPCSTR valueNamePointer, DWORD reservedValue, DWORD typeValue, const BYTE* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSetValueExAOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSetValueExAOriginal(keyHandle, valueNamePointer, reservedValue, typeValue, dataPointer, dataSize);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSetValueDetailA(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetValueExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSetKeyValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer, DWORD typeValue, const void* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSetKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSetKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegGetValueDetail(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, 0, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetKeyValueW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSetKeyValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer, DWORD typeValue, const void* dataPointer, DWORD dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSetKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSetKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer, typeValue, dataPointer, dataSize);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegGetValueDetailA(detailBuffer, keyHandle, subKeyPointer, valueNamePointer, 0, typeValue, dataSize);
            APIMON_REG_SEND(L"RegSetKeyValueA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteValueW(HKEY keyHandle, LPCWSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteValueWOriginal(keyHandle, valueNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteValueWOriginal(keyHandle, valueNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            APIMON_REG_SEND(L"RegDeleteValueW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteValueA(HKEY keyHandle, LPCSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteValueAOriginal(keyHandle, valueNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteValueAOriginal(keyHandle, valueNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            APIMON_REG_SEND(L"RegDeleteValueA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteKeyW(HKEY rootKey, LPCWSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyWOriginal(rootKey, subKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyWOriginal(rootKey, subKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteKeyA(HKEY rootKey, LPCSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyAOriginal(rootKey, subKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyAOriginal(rootKey, subKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteKeyExW(HKEY rootKey, LPCWSTR subKeyPointer, REGSAM samDesired, DWORD reservedValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyExWOriginal(rootKey, subKeyPointer, samDesired, reservedValue); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyExWOriginal(rootKey, subKeyPointer, samDesired, reservedValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegDeleteKeyExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteKeyExA(HKEY rootKey, LPCSTR subKeyPointer, REGSAM samDesired, DWORD reservedValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyExAOriginal(rootKey, subKeyPointer, samDesired, reservedValue); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyExAOriginal(rootKey, subKeyPointer, samDesired, reservedValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, samDesired);
            APIMON_REG_SEND(L"RegDeleteKeyExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteTreeW(HKEY rootKey, LPCWSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteTreeWOriginal(rootKey, subKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteTreeWOriginal(rootKey, subKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteTreeW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegDeleteTreeA(HKEY rootKey, LPCSTR subKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteTreeAOriginal(rootKey, subKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteTreeAOriginal(rootKey, subKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            APIMON_REG_SEND(L"RegDeleteTreeA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCopyTreeW(HKEY rootKey, LPCWSTR subKeyPointer, HKEY destKey)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCopyTreeWOriginal(rootKey, subKeyPointer, destKey); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCopyTreeWOriginal(rootKey, subKeyPointer, destKey);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            AppendWideText(detailBuffer, L" dest=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destKey));
            APIMON_REG_SEND(L"RegCopyTreeW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCopyTreeA(HKEY rootKey, LPCSTR subKeyPointer, HKEY destKey)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCopyTreeAOriginal(rootKey, subKeyPointer, destKey); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCopyTreeAOriginal(rootKey, subKeyPointer, destKey);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            AppendWideText(detailBuffer, L" dest=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(destKey));
            APIMON_REG_SEND(L"RegCopyTreeA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegLoadKeyW(HKEY rootKey, LPCWSTR subKeyPointer, LPCWSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regLoadKeyWOriginal(rootKey, subKeyPointer, fileNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regLoadKeyWOriginal(rootKey, subKeyPointer, fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetail(detailBuffer, rootKey, subKeyPointer, 0);
            AppendWideText(detailBuffer, L" file=");
            AppendWideText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegLoadKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegLoadKeyA(HKEY rootKey, LPCSTR subKeyPointer, LPCSTR fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regLoadKeyAOriginal(rootKey, subKeyPointer, fileNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regLoadKeyAOriginal(rootKey, subKeyPointer, fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegSubKeyDetailA(detailBuffer, rootKey, subKeyPointer, 0);
            AppendWideText(detailBuffer, L" file=");
            AppendAnsiText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegLoadKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSaveKeyW(HKEY keyHandle, LPCWSTR fileNamePointer, const LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSaveKeyWOriginal(keyHandle, fileNamePointer, securityAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSaveKeyWOriginal(keyHandle, fileNamePointer, securityAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" file=");
            AppendWideText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegSaveKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegSaveKeyA(HKEY keyHandle, LPCSTR fileNamePointer, const LPSECURITY_ATTRIBUTES securityAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regSaveKeyAOriginal(keyHandle, fileNamePointer, securityAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regSaveKeyAOriginal(keyHandle, fileNamePointer, securityAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" file=");
            AppendAnsiText(detailBuffer, fileNamePointer);
            APIMON_REG_SEND(L"RegSaveKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegRenameKey(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR newNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regRenameKeyOriginal(keyHandle, subKeyPointer, newNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regRenameKeyOriginal(keyHandle, subKeyPointer, newNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" subkey=");
            AppendWideText(detailBuffer, subKeyPointer);
            AppendWideText(detailBuffer, L" new=");
            AppendWideText(detailBuffer, newNamePointer);
            APIMON_REG_SEND(L"RegRenameKey", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegEnumKeyExW(HKEY keyHandle, DWORD indexValue, LPWSTR namePointer, LPDWORD nameLengthPointer, LPDWORD reservedPointer, LPWSTR classPointer, LPDWORD classLengthPointer, PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regEnumKeyExWOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regEnumKeyExWOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegEnumKeyDetail(detailBuffer, keyHandle, indexValue, statusValue == ERROR_SUCCESS ? namePointer : nullptr, statusValue == ERROR_SUCCESS && nameLengthPointer != nullptr ? *nameLengthPointer : 0);
            APIMON_REG_SEND(L"RegEnumKeyExW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegEnumKeyExA(HKEY keyHandle, DWORD indexValue, LPSTR namePointer, LPDWORD nameLengthPointer, LPDWORD reservedPointer, LPSTR classPointer, LPDWORD classLengthPointer, PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regEnumKeyExAOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regEnumKeyExAOriginal(keyHandle, indexValue, namePointer, nameLengthPointer, reservedPointer, classPointer, classLengthPointer, lastWriteTimePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegEnumKeyDetailA(detailBuffer, keyHandle, indexValue, statusValue == ERROR_SUCCESS ? namePointer : nullptr, statusValue == ERROR_SUCCESS && nameLengthPointer != nullptr ? *nameLengthPointer : 0);
            APIMON_REG_SEND(L"RegEnumKeyExA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegEnumValueW(HKEY keyHandle, DWORD indexValue, LPWSTR valueNamePointer, LPDWORD valueNameLengthPointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regEnumValueWOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regEnumValueWOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetail(detailBuffer, L"hkey=", keyHandle, statusValue == ERROR_SUCCESS ? valueNamePointer : nullptr, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, indexValue);
            APIMON_REG_SEND(L"RegEnumValueW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegEnumValueA(HKEY keyHandle, DWORD indexValue, LPSTR valueNamePointer, LPDWORD valueNameLengthPointer, LPDWORD reservedPointer, LPDWORD typePointer, LPBYTE dataPointer, LPDWORD dataSizePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regEnumValueAOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regEnumValueAOriginal(keyHandle, indexValue, valueNamePointer, valueNameLengthPointer, reservedPointer, typePointer, dataPointer, dataSizePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, statusValue == ERROR_SUCCESS ? valueNamePointer : nullptr, typePointer != nullptr ? *typePointer : 0, dataSizePointer != nullptr ? *dataSizePointer : 0);
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, indexValue);
            APIMON_REG_SEND(L"RegEnumValueA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        LSTATUS WINAPI HookedRegCloseKey(HKEY keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regCloseKeyOriginal(keyHandle); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regCloseKeyOriginal(keyHandle);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            APIMON_REG_SEND(L"RegCloseKey", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegQueryInfoKeyW 作用：
        // - 输入：注册表键句柄和统计信息输出缓冲；
        // - 处理：记录子键/值数量查询，补齐枚举类注册表 API 覆盖；
        // - 返回：保持 RegQueryInfoKeyW 的 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegQueryInfoKeyW(
            HKEY keyHandle,
            LPWSTR classPointer,
            LPDWORD classLengthPointer,
            LPDWORD reservedPointer,
            LPDWORD subKeyCountPointer,
            LPDWORD maxSubKeyLengthPointer,
            LPDWORD maxClassLengthPointer,
            LPDWORD valueCountPointer,
            LPDWORD maxValueNameLengthPointer,
            LPDWORD maxValueLengthPointer,
            LPDWORD securityDescriptorLengthPointer,
            PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_regQueryInfoKeyWOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            }

            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regQueryInfoKeyWOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" subKeys=");
            AppendUnsignedText(detailBuffer, subKeyCountPointer != nullptr ? *subKeyCountPointer : 0);
            AppendWideText(detailBuffer, L" values=");
            AppendUnsignedText(detailBuffer, valueCountPointer != nullptr ? *valueCountPointer : 0);
            APIMON_REG_SEND(L"RegQueryInfoKeyW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegQueryInfoKeyA 作用：
        // - 输入：ANSI 版本 RegQueryInfoKey 参数；
        // - 处理：记录键统计信息查询结果；
        // - 返回：保持原始 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegQueryInfoKeyA(
            HKEY keyHandle,
            LPSTR classPointer,
            LPDWORD classLengthPointer,
            LPDWORD reservedPointer,
            LPDWORD subKeyCountPointer,
            LPDWORD maxSubKeyLengthPointer,
            LPDWORD maxClassLengthPointer,
            LPDWORD valueCountPointer,
            LPDWORD maxValueNameLengthPointer,
            LPDWORD maxValueLengthPointer,
            LPDWORD securityDescriptorLengthPointer,
            PFILETIME lastWriteTimePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_regQueryInfoKeyAOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            }

            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regQueryInfoKeyAOriginal(keyHandle, classPointer, classLengthPointer, reservedPointer, subKeyCountPointer, maxSubKeyLengthPointer, maxClassLengthPointer, valueCountPointer, maxValueNameLengthPointer, maxValueLengthPointer, securityDescriptorLengthPointer, lastWriteTimePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" subKeys=");
            AppendUnsignedText(detailBuffer, subKeyCountPointer != nullptr ? *subKeyCountPointer : 0);
            AppendWideText(detailBuffer, L" values=");
            AppendUnsignedText(detailBuffer, valueCountPointer != nullptr ? *valueCountPointer : 0);
            APIMON_REG_SEND(L"RegQueryInfoKeyA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegFlushKey 作用：
        // - 输入：注册表键句柄；
        // - 处理：记录强制落盘操作，该行为常用于持久化确认；
        // - 返回：保持 RegFlushKey 的 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegFlushKey(HKEY keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regFlushKeyOriginal(keyHandle); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regFlushKeyOriginal(keyHandle);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            APIMON_REG_SEND(L"RegFlushKey", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegDeleteKeyValueW 作用：
        // - 输入：键句柄、可选子键和值名；
        // - 处理：记录组合删除值 API，补齐 RegDeleteValue/RegDeleteTree 之间的空白；
        // - 返回：保持原始 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegDeleteKeyValueW(HKEY keyHandle, LPCWSTR subKeyPointer, LPCWSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyValueWOriginal(keyHandle, subKeyPointer, valueNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetail(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            AppendWideText(detailBuffer, L" sub=");
            AppendWideText(detailBuffer, subKeyPointer);
            APIMON_REG_SEND(L"RegDeleteKeyValueW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegDeleteKeyValueA 作用：
        // - 输入：ANSI 版本键句柄、可选子键和值名；
        // - 处理：记录组合删除值 API；
        // - 返回：保持原始 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegDeleteKeyValueA(HKEY keyHandle, LPCSTR subKeyPointer, LPCSTR valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regDeleteKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regDeleteKeyValueAOriginal(keyHandle, subKeyPointer, valueNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRegValueDetailA(detailBuffer, L"hkey=", keyHandle, valueNamePointer, 0, 0);
            AppendWideText(detailBuffer, L" sub=");
            AppendAnsiText(detailBuffer, subKeyPointer);
            APIMON_REG_SEND(L"RegDeleteKeyValueA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegConnectRegistryW 作用：
        // - 输入：远程机器名、根键和结果句柄指针；
        // - 处理：记录远程注册表连接行为；
        // - 返回：保持原始 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegConnectRegistryW(LPCWSTR machineNamePointer, HKEY rootKey, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regConnectRegistryWOriginal(machineNamePointer, rootKey, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regConnectRegistryWOriginal(machineNamePointer, rootKey, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"machine=");
            AppendWideText(detailBuffer, machineNamePointer);
            AppendWideText(detailBuffer, L" root=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L" result=");
            AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0);
            APIMON_REG_SEND(L"RegConnectRegistryW", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        // HookedRegConnectRegistryA 作用：
        // - 输入：ANSI 版本远程机器名、根键和结果句柄指针；
        // - 处理：记录远程注册表连接行为；
        // - 返回：保持原始 LSTATUS，并恢复 LastError。
        LSTATUS WINAPI HookedRegConnectRegistryA(LPCSTR machineNamePointer, HKEY rootKey, PHKEY resultKeyPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_regConnectRegistryAOriginal(machineNamePointer, rootKey, resultKeyPointer); }
            const auto callClock = BeginApiCallClock();
            const LSTATUS statusValue = g_regConnectRegistryAOriginal(machineNamePointer, rootKey, resultKeyPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"machine=");
            AppendAnsiText(detailBuffer, machineNamePointer);
            AppendWideText(detailBuffer, L" root=");
            AppendRegistryRootText(detailBuffer, rootKey);
            AppendWideText(detailBuffer, L" result=");
            AppendHexText(detailBuffer, resultKeyPointer != nullptr ? reinterpret_cast<std::uint64_t>(*resultKeyPointer) : 0);
            APIMON_REG_SEND(L"RegConnectRegistryA", statusValue, detailBuffer, duration);
            ::SetLastError(lastError);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtCreateFile(PHANDLE fileHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PLARGE_INTEGER allocationSizePointer, ULONG fileAttributes, ULONG shareAccess, ULONG createDisposition, ULONG createOptions, PVOID eaBufferPointer, ULONG eaLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, allocationSizePointer, fileAttributes, shareAccess, createDisposition, createOptions, eaBufferPointer, eaLength); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, allocationSizePointer, fileAttributes, shareAccess, createDisposition, createOptions, eaBufferPointer, eaLength);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, shareAccess, createDisposition, createOptions);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, fileHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*fileHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtCreateFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtOpenFile(PHANDLE fileHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, ULONG shareAccess, ULONG openOptions)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, shareAccess, openOptions); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenFileOriginal(fileHandlePointer, desiredAccess, objectAttributesPointer, ioStatusBlockPointer, shareAccess, openOptions);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, shareAccess, 0, openOptions);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, fileHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*fileHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtOpenFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtReadFile(HANDLE fileHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID bufferPointer, ULONG lengthValue, PLARGE_INTEGER byteOffsetPointer, PULONG keyPointer)
        {
            if (IsMonitorPipeHandle(fileHandle))
            {
                return g_ntReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntReadFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildHandleTransferDetail(detailBuffer, fileHandle, lengthValue, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0, byteOffsetPointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtReadFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtWriteFile(HANDLE fileHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID bufferPointer, ULONG lengthValue, PLARGE_INTEGER byteOffsetPointer, PULONG keyPointer)
        {
            if (IsMonitorPipeHandle(fileHandle))
            {
                return g_ntWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            }
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntWriteFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, bufferPointer, lengthValue, byteOffsetPointer, keyPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildHandleTransferDetail(detailBuffer, fileHandle, lengthValue, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0, byteOffsetPointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtWriteFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtSetInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID fileInformationPointer, ULONG lengthValue, KS_FILE_INFORMATION_CLASS fileInformationClass)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSetInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSetInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtSetInformationFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtQueryInformationFile(HANDLE fileHandle, PIO_STATUS_BLOCK ioStatusBlockPointer, PVOID fileInformationPointer, ULONG lengthValue, KS_FILE_INFORMATION_CLASS fileInformationClass)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryInformationFileOriginal(fileHandle, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtQueryInformationFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtDeleteFile(POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntDeleteFileOriginal(objectAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntDeleteFileOriginal(objectAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtDeleteFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtQueryAttributesFile(POBJECT_ATTRIBUTES objectAttributesPointer, PVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryAttributesFileOriginal(objectAttributesPointer, fileInformationPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryAttributesFileOriginal(objectAttributesPointer, fileInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtQueryAttributesFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtQueryFullAttributesFile(POBJECT_ATTRIBUTES objectAttributesPointer, PVOID fileInformationPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryFullAttributesFileOriginal(objectAttributesPointer, fileInformationPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryFullAttributesFileOriginal(objectAttributesPointer, fileInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, 0, 0, 0, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtQueryFullAttributesFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtDeviceIoControlFile 作用：
        // - 输入：文件/设备句柄、事件/APC、IO_STATUS_BLOCK、控制码和缓冲区长度；
        // - 处理：记录直接 ntdll 设备控制调用，覆盖绕过 KernelBase DeviceIoControl 的路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtDeviceIoControlFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            ULONG ioControlCode,
            PVOID inputBufferPointer,
            ULONG inputBufferLength,
            PVOID outputBufferPointer,
            ULONG outputBufferLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_ntDeviceIoControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, ioControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            }

            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntDeviceIoControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, ioControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" code=");
            AppendHexText(detailBuffer, ioControlCode);
            AppendWideText(detailBuffer, L" in=");
            AppendUnsignedText(detailBuffer, inputBufferLength);
            AppendWideText(detailBuffer, L" out=");
            AppendUnsignedText(detailBuffer, outputBufferLength);
            AppendWideText(detailBuffer, L" info=");
            AppendUnsignedText(detailBuffer, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtDeviceIoControlFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtFsControlFile 作用：
        // - 输入：文件句柄、控制码和缓冲区长度；
        // - 处理：记录文件系统控制调用，例如重解析点、卷控制和管道控制；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtFsControlFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            ULONG fsControlCode,
            PVOID inputBufferPointer,
            ULONG inputBufferLength,
            PVOID outputBufferPointer,
            ULONG outputBufferLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_ntFsControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fsControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            }

            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntFsControlFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fsControlCode, inputBufferPointer, inputBufferLength, outputBufferPointer, outputBufferLength);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"fsctlName=");
            AppendWideText(detailBuffer, FsctlCodeToText(fsControlCode));
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" code=");
            AppendHexText(detailBuffer, fsControlCode);
            AppendWideText(detailBuffer, L" status=");
            AppendHexText(detailBuffer, static_cast<std::uint32_t>(statusValue));
            AppendWideText(detailBuffer, L" in=");
            AppendUnsignedText(detailBuffer, inputBufferLength);
            AppendWideText(detailBuffer, L" out=");
            AppendUnsignedText(detailBuffer, outputBufferLength);
            AppendWideText(detailBuffer, L" info=");
            AppendUnsignedText(detailBuffer, ioStatusBlockPointer != nullptr ? static_cast<unsigned long long>(ioStatusBlockPointer->Information) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtFsControlFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryDirectoryFile 作用：
        // - 输入：目录句柄、查询缓冲、信息类、可选文件名和重启标志；
        // - 处理：记录直接目录枚举调用，补齐 FindFirstFileEx 以下的 Nt 层枚举；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryDirectoryFile(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            PVOID fileInformationPointer,
            ULONG lengthValue,
            KS_FILE_INFORMATION_CLASS fileInformationClass,
            BOOLEAN returnSingleEntry,
            PUNICODE_STRING fileNamePointer,
            BOOLEAN restartScan)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_ntQueryDirectoryFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, returnSingleEntry, fileNamePointer, restartScan);
            }

            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryDirectoryFileOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, returnSingleEntry, fileNamePointer, restartScan);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" pattern=");
            AppendUnicodeStringText(detailBuffer, fileNamePointer);
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, lengthValue);
            AppendWideText(detailBuffer, L" single=");
            AppendUnsignedText(detailBuffer, returnSingleEntry ? 1 : 0);
            AppendWideText(detailBuffer, L" restart=");
            AppendUnsignedText(detailBuffer, restartScan ? 1 : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtQueryDirectoryFile", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryDirectoryFileEx 作用：
        // - 输入：扩展目录查询参数，包括 QueryFlags 和可选文件名；
        // - 处理：记录现代 NtQueryDirectoryFileEx 枚举路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryDirectoryFileEx(
            HANDLE fileHandle,
            HANDLE eventHandle,
            KsIoApcRoutine apcRoutinePointer,
            PVOID apcContextPointer,
            PIO_STATUS_BLOCK ioStatusBlockPointer,
            PVOID fileInformationPointer,
            ULONG lengthValue,
            KS_FILE_INFORMATION_CLASS fileInformationClass,
            ULONG queryFlags,
            PUNICODE_STRING fileNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_ntQueryDirectoryFileExOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, queryFlags, fileNamePointer);
            }

            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryDirectoryFileExOriginal(fileHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, fileInformationPointer, lengthValue, fileInformationClass, queryFlags, fileNamePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" pattern=");
            AppendUnicodeStringText(detailBuffer, fileNamePointer);
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(fileInformationClass));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, queryFlags);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"ntdll", L"NtQueryDirectoryFileEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtCreateKey(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG titleIndex, PUNICODE_STRING classPointer, ULONG createOptions, PULONG dispositionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, titleIndex, classPointer, createOptions, dispositionPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, titleIndex, classPointer, createOptions, dispositionPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, dispositionPointer != nullptr ? *dispositionPointer : 0, createOptions);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtCreateKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtOpenKey(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenKeyOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, 0, 0);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtOpenKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtOpenKeyEx(PHANDLE keyHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, ULONG openOptions)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenKeyExOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, openOptions); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenKeyExOriginal(keyHandlePointer, desiredAccess, objectAttributesPointer, openOptions);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtObjectPathDetail(detailBuffer, objectAttributesPointer, desiredAccess, 0, 0, openOptions);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, keyHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*keyHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtOpenKeyEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtSetValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer, ULONG titleIndex, ULONG typeValue, PVOID dataPointer, ULONG dataSize)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSetValueKeyOriginal(keyHandle, valueNamePointer, titleIndex, typeValue, dataPointer, dataSize); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSetValueKeyOriginal(keyHandle, valueNamePointer, titleIndex, typeValue, dataPointer, dataSize);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, typeValue, dataSize);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtSetValueKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtQueryValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer, KS_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, PVOID keyValueInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryValueKeyOriginal(keyHandle, valueNamePointer, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryValueKeyOriginal(keyHandle, valueNamePointer, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, static_cast<ULONG>(keyValueInformationClass), resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtQueryValueKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtEnumerateKey(HANDLE keyHandle, ULONG indexValue, KS_KEY_INFORMATION_CLASS keyInformationClass, PVOID keyInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntEnumerateKeyOriginal(keyHandle, indexValue, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntEnumerateKeyOriginal(keyHandle, indexValue, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, indexValue);
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtEnumerateKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtEnumerateValueKey(HANDLE keyHandle, ULONG indexValue, KS_KEY_VALUE_INFORMATION_CLASS keyValueInformationClass, PVOID keyValueInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntEnumerateValueKeyOriginal(keyHandle, indexValue, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntEnumerateValueKeyOriginal(keyHandle, indexValue, keyValueInformationClass, keyValueInformationPointer, lengthValue, resultLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" index=");
            AppendUnsignedText(detailBuffer, indexValue);
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyValueInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtEnumerateValueKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtDeleteKey(HANDLE keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntDeleteKeyOriginal(keyHandle); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntDeleteKeyOriginal(keyHandle);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtDeleteKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtDeleteValueKey(HANDLE keyHandle, PUNICODE_STRING valueNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntDeleteValueKeyOriginal(keyHandle, valueNamePointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntDeleteValueKeyOriginal(keyHandle, valueNamePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildNtKeyValueDetail(detailBuffer, keyHandle, valueNamePointer, 0, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtDeleteValueKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtFlushKey(HANDLE keyHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntFlushKeyOriginal(keyHandle); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntFlushKeyOriginal(keyHandle);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtFlushKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtRenameKey(HANDLE keyHandle, PUNICODE_STRING newNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntRenameKeyOriginal(keyHandle, newNamePointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntRenameKeyOriginal(keyHandle, newNamePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" new=");
            AppendUnicodeStringText(detailBuffer, newNamePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtRenameKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtLoadKey(POBJECT_ATTRIBUTES targetKeyPointer, POBJECT_ATTRIBUTES sourceFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntLoadKeyOriginal(targetKeyPointer, sourceFilePointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntLoadKeyOriginal(targetKeyPointer, sourceFilePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"target=");
            AppendObjectNameText(detailBuffer, targetKeyPointer);
            AppendWideText(detailBuffer, L" source=");
            AppendObjectNameText(detailBuffer, sourceFilePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtLoadKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtSaveKey(HANDLE keyHandle, HANDLE fileHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSaveKeyOriginal(keyHandle, fileHandle); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSaveKeyOriginal(keyHandle, fileHandle);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" file=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtSaveKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryKey 作用：
        // - 输入：键句柄、信息类和输出缓冲长度；
        // - 处理：记录直接 Nt 层键元数据查询；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryKey(HANDLE keyHandle, KS_KEY_INFORMATION_CLASS keyInformationClass, PVOID keyInformationPointer, ULONG lengthValue, PULONG resultLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryKeyOriginal(keyHandle, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryKeyOriginal(keyHandle, keyInformationClass, keyInformationPointer, lengthValue, resultLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(keyInformationClass));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, resultLengthPointer != nullptr ? *resultLengthPointer : lengthValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtQueryKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryMultipleValueKey 作用：
        // - 输入：键句柄、值条目数组、条目数量和值缓冲长度；
        // - 处理：记录批量查询多个注册表值的 Nt 层路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryMultipleValueKey(HANDLE keyHandle, PVOID valueEntriesPointer, ULONG entryCount, PVOID valueBufferPointer, PULONG bufferLengthPointer, PULONG requiredBufferLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryMultipleValueKeyOriginal(keyHandle, valueEntriesPointer, entryCount, valueBufferPointer, bufferLengthPointer, requiredBufferLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryMultipleValueKeyOriginal(keyHandle, valueEntriesPointer, entryCount, valueBufferPointer, bufferLengthPointer, requiredBufferLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" entries=");
            AppendUnsignedText(detailBuffer, entryCount);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, bufferLengthPointer != nullptr ? *bufferLengthPointer : 0);
            AppendWideText(detailBuffer, L" required=");
            AppendUnsignedText(detailBuffer, requiredBufferLengthPointer != nullptr ? *requiredBufferLengthPointer : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtQueryMultipleValueKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtNotifyChangeKey 作用：
        // - 输入：键句柄、事件/APC、过滤掩码、是否递归和缓冲信息；
        // - 处理：记录注册表变更通知订阅，覆盖监视型行为；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtNotifyChangeKey(HANDLE keyHandle, HANDLE eventHandle, KsIoApcRoutine apcRoutinePointer, PVOID apcContextPointer, PIO_STATUS_BLOCK ioStatusBlockPointer, ULONG completionFilter, BOOLEAN watchTree, PVOID bufferPointer, ULONG bufferSize, BOOLEAN asynchronous)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntNotifyChangeKeyOriginal(keyHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, completionFilter, watchTree, bufferPointer, bufferSize, asynchronous); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntNotifyChangeKeyOriginal(keyHandle, eventHandle, apcRoutinePointer, apcContextPointer, ioStatusBlockPointer, completionFilter, watchTree, bufferPointer, bufferSize, asynchronous);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" filter=");
            AppendHexText(detailBuffer, completionFilter);
            AppendWideText(detailBuffer, L" tree=");
            AppendUnsignedText(detailBuffer, watchTree ? 1 : 0);
            AppendWideText(detailBuffer, L" async=");
            AppendUnsignedText(detailBuffer, asynchronous ? 1 : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtNotifyChangeKey", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtLoadKey2 作用：
        // - 输入：目标键对象、源 hive 文件对象和加载标志；
        // - 处理：记录带 flags 的 hive 加载路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtLoadKey2(POBJECT_ATTRIBUTES targetKeyPointer, POBJECT_ATTRIBUTES sourceFilePointer, ULONG flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntLoadKey2Original(targetKeyPointer, sourceFilePointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntLoadKey2Original(targetKeyPointer, sourceFilePointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"target=");
            AppendObjectNameText(detailBuffer, targetKeyPointer);
            AppendWideText(detailBuffer, L" source=");
            AppendObjectNameText(detailBuffer, sourceFilePointer);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtLoadKey2", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtSaveKeyEx 作用：
        // - 输入：键句柄、文件句柄和保存格式标志；
        // - 处理：记录扩展 hive 保存路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtSaveKeyEx(HANDLE keyHandle, HANDLE fileHandle, ULONG formatValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSaveKeyExOriginal(keyHandle, fileHandle, formatValue); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSaveKeyExOriginal(keyHandle, fileHandle, formatValue);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"hkey=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(keyHandle));
            AppendWideText(detailBuffer, L" file=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" format=");
            AppendHexText(detailBuffer, formatValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtSaveKeyEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtLoadDriver 作用：
        // - 输入：注册表服务项路径 UNICODE_STRING；
        // - 处理：记录原生驱动加载请求，归入注册表/持久化相关监控；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtLoadDriver(PUNICODE_STRING serviceNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntLoadDriverOriginal(serviceNamePointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntLoadDriverOriginal(serviceNamePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"service=");
            AppendUnicodeStringText(detailBuffer, serviceNamePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtLoadDriver", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtUnloadDriver 作用：
        // - 输入：注册表服务项路径 UNICODE_STRING；
        // - 处理：记录原生驱动卸载请求；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtUnloadDriver(PUNICODE_STRING serviceNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntUnloadDriverOriginal(serviceNamePointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntUnloadDriverOriginal(serviceNamePointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"service=");
            AppendUnicodeStringText(detailBuffer, serviceNamePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Registry, L"ntdll", L"NtUnloadDriver", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtOpenProcess(PHANDLE processHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PKS_CLIENT_ID clientIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenProcessOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenProcessOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildProcessHandleDetail(detailBuffer, nullptr, desiredAccess, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->UniqueProcess) : 0, processHandlePointer != nullptr ? *processHandlePointer : nullptr);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtOpenProcess", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtOpenThread(PHANDLE threadHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PKS_CLIENT_ID clientIdPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenThreadOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenThreadOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, clientIdPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"pid=");
            AppendHexText(detailBuffer, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->UniqueProcess) : 0);
            AppendWideText(detailBuffer, L" tid=");
            AppendHexText(detailBuffer, clientIdPointer != nullptr ? reinterpret_cast<std::uint64_t>(clientIdPointer->UniqueThread) : 0);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" handle=");
            AppendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtOpenThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtTerminateProcess(HANDLE processHandle, NTSTATUS exitStatus)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntTerminateProcessOriginal(processHandle, exitStatus); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntTerminateProcessOriginal(processHandle, exitStatus);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" exit=");
            AppendHexText(detailBuffer, static_cast<std::uint32_t>(exitStatus));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtTerminateProcess", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtCreateUserProcess(PHANDLE processHandlePointer, PHANDLE threadHandlePointer, ACCESS_MASK processDesiredAccess, ACCESS_MASK threadDesiredAccess, POBJECT_ATTRIBUTES processObjectAttributesPointer, POBJECT_ATTRIBUTES threadObjectAttributesPointer, ULONG processFlags, ULONG threadFlags, PVOID processParametersPointer, PVOID createInfoPointer, PVOID attributeListPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateUserProcessOriginal(processHandlePointer, threadHandlePointer, processDesiredAccess, threadDesiredAccess, processObjectAttributesPointer, threadObjectAttributesPointer, processFlags, threadFlags, processParametersPointer, createInfoPointer, attributeListPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateUserProcessOriginal(processHandlePointer, threadHandlePointer, processDesiredAccess, threadDesiredAccess, processObjectAttributesPointer, threadObjectAttributesPointer, processFlags, threadFlags, processParametersPointer, createInfoPointer, attributeListPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"processAccess=");
            AppendHexText(detailBuffer, processDesiredAccess);
            AppendWideText(detailBuffer, L" threadAccess=");
            AppendHexText(detailBuffer, threadDesiredAccess);
            AppendWideText(detailBuffer, L" processFlags=");
            AppendHexText(detailBuffer, processFlags);
            AppendWideText(detailBuffer, L" threadFlags=");
            AppendHexText(detailBuffer, threadFlags);
            AppendWideText(detailBuffer, L" process=");
            AppendHexText(detailBuffer, processHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*processHandlePointer) : 0);
            AppendWideText(detailBuffer, L" thread=");
            AppendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtCreateUserProcess", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtCreateProcessEx(PHANDLE processHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, HANDLE parentProcessHandle, ULONG flagsValue, HANDLE sectionHandle, HANDLE debugPortHandle, HANDLE exceptionPortHandle, BOOLEAN inJob)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateProcessExOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, parentProcessHandle, flagsValue, sectionHandle, debugPortHandle, exceptionPortHandle, inJob); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateProcessExOriginal(processHandlePointer, desiredAccess, objectAttributesPointer, parentProcessHandle, flagsValue, sectionHandle, debugPortHandle, exceptionPortHandle, inJob);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"parent=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(parentProcessHandle));
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" process=");
            AppendHexText(detailBuffer, processHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*processHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtCreateProcessEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE threadHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, HANDLE processHandle, PVOID startRoutinePointer, PVOID argumentPointer, ULONG createFlags, SIZE_T zeroBits, SIZE_T stackSize, SIZE_T maximumStackSize, PVOID attributeListPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateThreadExOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, processHandle, startRoutinePointer, argumentPointer, createFlags, zeroBits, stackSize, maximumStackSize, attributeListPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateThreadExOriginal(threadHandlePointer, desiredAccess, objectAttributesPointer, processHandle, startRoutinePointer, argumentPointer, createFlags, zeroBits, stackSize, maximumStackSize, attributeListPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" start=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(startRoutinePointer));
            AppendWideText(detailBuffer, L" arg=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argumentPointer));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, createFlags);
            AppendWideText(detailBuffer, L" thread=");
            AppendHexText(detailBuffer, threadHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*threadHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtCreateThreadEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtAllocateVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, ULONG_PTR zeroBits, PSIZE_T regionSizePointer, ULONG allocationType, ULONG protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntAllocateVirtualMemoryOriginal(processHandle, baseAddressPointer, zeroBits, regionSizePointer, allocationType, protectValue); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntAllocateVirtualMemoryOriginal(processHandle, baseAddressPointer, zeroBits, regionSizePointer, allocationType, protectValue);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, allocationType, protectValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtAllocateVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtFreeVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, PSIZE_T regionSizePointer, ULONG freeType)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntFreeVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, freeType); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntFreeVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, freeType);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, freeType, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtFreeVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtProtectVirtualMemory(HANDLE processHandle, PVOID* baseAddressPointer, PSIZE_T regionSizePointer, ULONG newProtect, PULONG oldProtectPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntProtectVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, newProtect, oldProtectPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntProtectVirtualMemoryOriginal(processHandle, baseAddressPointer, regionSizePointer, newProtect, oldProtectPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddressPointer != nullptr ? *baseAddressPointer : nullptr, regionSizePointer != nullptr ? static_cast<std::uint64_t>(*regionSizePointer) : 0, oldProtectPointer != nullptr ? *oldProtectPointer : 0, newProtect);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtProtectVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID bufferPointer, SIZE_T sizeValue, PSIZE_T bytesWrittenPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntWriteVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntWriteVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesWrittenPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            AppendWideText(detailBuffer, L" written=");
            AppendUnsignedText(detailBuffer, bytesWrittenPointer != nullptr ? static_cast<unsigned long long>(*bytesWrittenPointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtWriteVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE processHandle, PVOID baseAddress, PVOID bufferPointer, SIZE_T sizeValue, PSIZE_T bytesReadPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntReadVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntReadVirtualMemoryOriginal(processHandle, baseAddress, bufferPointer, sizeValue, bytesReadPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(sizeValue), 0, 0);
            AppendWideText(detailBuffer, L" read=");
            AppendUnsignedText(detailBuffer, bytesReadPointer != nullptr ? static_cast<unsigned long long>(*bytesReadPointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtReadVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtMapViewOfSection(HANDLE sectionHandle, HANDLE processHandle, PVOID* baseAddressPointer, ULONG_PTR zeroBits, SIZE_T commitSize, PLARGE_INTEGER sectionOffsetPointer, PSIZE_T viewSizePointer, DWORD inheritDisposition, ULONG allocationType, ULONG protectValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntMapViewOfSectionOriginal(sectionHandle, processHandle, baseAddressPointer, zeroBits, commitSize, sectionOffsetPointer, viewSizePointer, inheritDisposition, allocationType, protectValue); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntMapViewOfSectionOriginal(sectionHandle, processHandle, baseAddressPointer, zeroBits, commitSize, sectionOffsetPointer, viewSizePointer, inheritDisposition, allocationType, protectValue);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"section=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sectionHandle));
            AppendWideText(detailBuffer, L" process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" base=");
            AppendHexText(detailBuffer, baseAddressPointer != nullptr ? reinterpret_cast<std::uint64_t>(*baseAddressPointer) : 0);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, viewSizePointer != nullptr ? static_cast<unsigned long long>(*viewSizePointer) : 0);
            AppendWideText(detailBuffer, L" protect=");
            AppendHexText(detailBuffer, protectValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtMapViewOfSection", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtUnmapViewOfSection(HANDLE processHandle, PVOID baseAddress)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntUnmapViewOfSectionOriginal(processHandle, baseAddress); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntUnmapViewOfSectionOriginal(processHandle, baseAddress);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, 0, 0, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtUnmapViewOfSection", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        NTSTATUS NTAPI HookedNtDuplicateObject(HANDLE sourceProcessHandle, HANDLE sourceHandle, HANDLE targetProcessHandle, PHANDLE targetHandlePointer, ACCESS_MASK desiredAccess, ULONG handleAttributes, ULONG optionsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntDuplicateObjectOriginal(sourceProcessHandle, sourceHandle, targetProcessHandle, targetHandlePointer, desiredAccess, handleAttributes, optionsValue); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntDuplicateObjectOriginal(sourceProcessHandle, sourceHandle, targetProcessHandle, targetHandlePointer, desiredAccess, handleAttributes, optionsValue);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"sourceProcess=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceProcessHandle));
            AppendWideText(detailBuffer, L" sourceHandle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(sourceHandle));
            AppendWideText(detailBuffer, L" targetProcess=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(targetProcessHandle));
            AppendWideText(detailBuffer, L" targetHandle=");
            AppendHexText(detailBuffer, targetHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*targetHandlePointer) : 0);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, optionsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtDuplicateObject", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryInformationProcess 作用：
        // - 输入：进程句柄、信息类和输出缓冲长度；
        // - 处理：记录直接进程信息查询，覆盖 PEB/调试/保护级别等原生查询路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryInformationProcess(HANDLE processHandle, ULONG processInformationClass, PVOID processInformationPointer, ULONG processInformationLength, PULONG returnLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength, returnLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength, returnLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, processInformationClass);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, returnLengthPointer != nullptr ? *returnLengthPointer : processInformationLength);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtQueryInformationProcess", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtSetInformationProcess 作用：
        // - 输入：进程句柄、信息类和输入缓冲长度；
        // - 处理：记录直接进程属性修改，例如保护/调试/优先级相关设置；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtSetInformationProcess(HANDLE processHandle, ULONG processInformationClass, PVOID processInformationPointer, ULONG processInformationLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSetInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSetInformationProcessOriginal(processHandle, processInformationClass, processInformationPointer, processInformationLength);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"process=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(processHandle));
            AppendWideText(detailBuffer, L" class=");
            AppendUnsignedText(detailBuffer, processInformationClass);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, processInformationLength);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtSetInformationProcess", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueryVirtualMemory 作用：
        // - 输入：进程句柄、基址、信息类和输出缓冲长度；
        // - 处理：记录原生虚拟内存查询，补齐 VirtualQueryEx/Nt 层路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueryVirtualMemory(HANDLE processHandle, PVOID baseAddress, ULONG memoryInformationClass, PVOID memoryInformationPointer, SIZE_T memoryInformationLength, PSIZE_T returnLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueryVirtualMemoryOriginal(processHandle, baseAddress, memoryInformationClass, memoryInformationPointer, memoryInformationLength, returnLengthPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueryVirtualMemoryOriginal(processHandle, baseAddress, memoryInformationClass, memoryInformationPointer, memoryInformationLength, returnLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildRemoteMemoryDetail(detailBuffer, processHandle, baseAddress, static_cast<std::uint64_t>(returnLengthPointer != nullptr ? *returnLengthPointer : memoryInformationLength), memoryInformationClass, 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtQueryVirtualMemory", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtCreateSection 作用：
        // - 输入：Section 结果句柄、访问掩码、对象属性、最大大小、保护、属性和文件句柄；
        // - 处理：记录 Section 创建，覆盖 section-map 注入链路的前置步骤；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtCreateSection(PHANDLE sectionHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer, PLARGE_INTEGER maximumSizePointer, ULONG sectionPageProtection, ULONG allocationAttributes, HANDLE fileHandle)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntCreateSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer, maximumSizePointer, sectionPageProtection, allocationAttributes, fileHandle); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntCreateSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer, maximumSizePointer, sectionPageProtection, allocationAttributes, fileHandle);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"section=");
            AppendHexText(detailBuffer, sectionHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*sectionHandlePointer) : 0);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" protect=");
            AppendHexText(detailBuffer, sectionPageProtection);
            AppendWideText(detailBuffer, L" attrs=");
            AppendHexText(detailBuffer, allocationAttributes);
            AppendWideText(detailBuffer, L" file=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtCreateSection", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtOpenSection 作用：
        // - 输入：Section 结果句柄、访问掩码和对象属性；
        // - 处理：记录打开已存在 Section 对象；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtOpenSection(PHANDLE sectionHandlePointer, ACCESS_MASK desiredAccess, POBJECT_ATTRIBUTES objectAttributesPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntOpenSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntOpenSectionOriginal(sectionHandlePointer, desiredAccess, objectAttributesPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"object=");
            AppendObjectNameText(detailBuffer, objectAttributesPointer);
            AppendWideText(detailBuffer, L" access=");
            AppendHexText(detailBuffer, desiredAccess);
            AppendWideText(detailBuffer, L" section=");
            AppendHexText(detailBuffer, sectionHandlePointer != nullptr ? reinterpret_cast<std::uint64_t>(*sectionHandlePointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtOpenSection", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueueApcThread 作用：
        // - 输入：线程句柄、APC 例程和三个参数；
        // - 处理：记录原生 APC 排队，覆盖绕过 QueueUserAPC 的注入路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueueApcThread(HANDLE threadHandle, PVOID apcRoutinePointer, PVOID argument1Pointer, PVOID argument2Pointer, PVOID argument3Pointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueueApcThreadOriginal(threadHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueueApcThreadOriginal(threadHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" apc=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            AppendWideText(detailBuffer, L" arg1=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argument1Pointer));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtQueueApcThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtQueueApcThreadEx 作用：
        // - 输入：线程句柄、Reserve 句柄、APC 例程和三个参数；
        // - 处理：记录扩展 APC 排队路径；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtQueueApcThreadEx(HANDLE threadHandle, HANDLE reserveHandle, PVOID apcRoutinePointer, PVOID argument1Pointer, PVOID argument2Pointer, PVOID argument3Pointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntQueueApcThreadExOriginal(threadHandle, reserveHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntQueueApcThreadExOriginal(threadHandle, reserveHandle, apcRoutinePointer, argument1Pointer, argument2Pointer, argument3Pointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" reserve=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(reserveHandle));
            AppendWideText(detailBuffer, L" apc=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(apcRoutinePointer));
            AppendWideText(detailBuffer, L" arg1=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(argument1Pointer));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtQueueApcThreadEx", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtSuspendThread 作用：
        // - 输入：线程句柄和可选旧挂起计数输出；
        // - 处理：记录 Nt 层线程挂起；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtSuspendThread(HANDLE threadHandle, PULONG previousSuspendCountPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSuspendThreadOriginal(threadHandle, previousSuspendCountPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSuspendThreadOriginal(threadHandle, previousSuspendCountPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" previous=");
            AppendUnsignedText(detailBuffer, previousSuspendCountPointer != nullptr ? *previousSuspendCountPointer : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtSuspendThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtResumeThread 作用：
        // - 输入：线程句柄和可选旧挂起计数输出；
        // - 处理：记录 Nt 层线程恢复；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtResumeThread(HANDLE threadHandle, PULONG previousSuspendCountPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntResumeThreadOriginal(threadHandle, previousSuspendCountPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntResumeThreadOriginal(threadHandle, previousSuspendCountPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" previous=");
            AppendUnsignedText(detailBuffer, previousSuspendCountPointer != nullptr ? *previousSuspendCountPointer : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtResumeThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtGetContextThread 作用：
        // - 输入：线程句柄和 CONTEXT 输出缓冲；
        // - 处理：记录 Nt 层上下文读取；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtGetContextThread(HANDLE threadHandle, PCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntGetContextThreadOriginal(threadHandle, contextPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntGetContextThreadOriginal(threadHandle, contextPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtGetContextThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedNtSetContextThread 作用：
        // - 输入：线程句柄和 CONTEXT 输入缓冲；
        // - 处理：记录 Nt 层上下文写入；
        // - 返回：保持原始 NTSTATUS。
        NTSTATUS NTAPI HookedNtSetContextThread(HANDLE threadHandle, PCONTEXT contextPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ntSetContextThreadOriginal(threadHandle, contextPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ntSetContextThreadOriginal(threadHandle, contextPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"thread=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(threadHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->ContextFlags : 0);
#if defined(_M_X64)
            AppendWideText(detailBuffer, L" rip=");
            AppendHexText(detailBuffer, contextPointer != nullptr ? contextPointer->Rip : 0);
#endif
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"ntdll", L"NtSetContextThread", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedSocket 作用：
        // - 输入：协议族、socket 类型和协议号；
        // - 处理：记录基础 socket 创建，补齐 connect/send 前的网络对象创建行为；
        // - 返回：保持原始 SOCKET，并在失败时恢复 WSA 错误码。
        SOCKET WSAAPI HookedSocket(int addressFamily, int socketType, int protocolValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_socketOriginal(addressFamily, socketType, protocolValue); }
            const auto callClock = BeginApiCallClock();
            const SOCKET resultSocket = g_socketOriginal(addressFamily, socketType, protocolValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultSocket != INVALID_SOCKET ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"af=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            AppendWideText(detailBuffer, L" proto=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            AppendWideText(detailBuffer, L" socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(resultSocket));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"socket", errorValue, detailBuffer, true, ApiReturnBits(resultSocket), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultSocket;
        }

        // HookedWSASocketW 作用：
        // - 输入：协议族、类型、协议、协议信息、组和标志；
        // - 处理：记录扩展 socket 创建，包含 overlapped/flag 信息；
        // - 返回：保持原始 SOCKET，并在失败时恢复 WSA 错误码。
        SOCKET WSAAPI HookedWSASocketW(int addressFamily, int socketType, int protocolValue, LPWSAPROTOCOL_INFOW protocolInfoPointer, GROUP groupValue, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_wsaSocketWOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const SOCKET resultSocket = g_wsaSocketWOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultSocket != INVALID_SOCKET ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"af=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            AppendWideText(detailBuffer, L" proto=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(resultSocket));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"WSASocketW", errorValue, detailBuffer, true, ApiReturnBits(resultSocket), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultSocket;
        }

        // HookedWSASocketA 作用：
        // - 输入：ANSI 版本 WSASocket 参数；
        // - 处理：记录扩展 socket 创建；
        // - 返回：保持原始 SOCKET，并在失败时恢复 WSA 错误码。
        SOCKET WSAAPI HookedWSASocketA(int addressFamily, int socketType, int protocolValue, LPWSAPROTOCOL_INFOA protocolInfoPointer, GROUP groupValue, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_wsaSocketAOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const SOCKET resultSocket = g_wsaSocketAOriginal(addressFamily, socketType, protocolValue, protocolInfoPointer, groupValue, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultSocket != INVALID_SOCKET ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"af=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(addressFamily));
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(socketType));
            AppendWideText(detailBuffer, L" proto=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(protocolValue));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(resultSocket));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"WSASocketA", errorValue, detailBuffer, true, ApiReturnBits(resultSocket), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultSocket;
        }

        // HookedCloseSocket 作用：
        // - 输入：socket 句柄；
        // - 处理：记录网络句柄关闭；
        // - 返回：保持 closesocket 的 int 结果，并在失败时恢复 WSA 错误码。
        int WSAAPI HookedCloseSocket(SOCKET socketValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_closeSocketOriginal(socketValue); }
            const auto callClock = BeginApiCallClock();
            const int resultValue = g_closeSocketOriginal(socketValue);
            const auto duration = EndApiCallClock(callClock);
            const int savedWsa = ::WSAGetLastError();
            const DWORD savedWin32 = ::GetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            if (resultValue == 0) RetireIoResource(socketValue);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"closesocket", errorValue, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        // HookedShutdown 作用：
        // - 输入：socket 句柄和关闭方向；
        // - 处理：记录主动半关闭/全关闭操作；
        // - 返回：保持 shutdown 的 int 结果，并在失败时恢复 WSA 错误码。
        int WSAAPI HookedShutdown(SOCKET socketValue, int howValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_shutdownOriginal(socketValue, howValue); }
            const auto callClock = BeginApiCallClock();
            const int resultValue = g_shutdownOriginal(socketValue, howValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            AppendWideText(detailBuffer, L" how=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(howValue));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Ws2_32", L"shutdown", errorValue, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedConnect(SOCKET socketValue, const sockaddr* namePointer, int nameLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_connectOriginal(socketValue, namePointer, nameLength);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_connectOriginal(socketValue, namePointer, nameLength);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"connect", socketValue, 0, 0, 0, namePointer, nameLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"connect",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedWSAConnect(SOCKET socketValue, const sockaddr* namePointer, int nameLength, LPWSABUF callerDataPointer, LPWSABUF calleeDataPointer, LPQOS socketQosPointer, LPQOS groupQosPointer)
        {
            (void)callerDataPointer;
            (void)calleeDataPointer;
            (void)socketQosPointer;
            (void)groupQosPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_wsaConnectOriginal(socketValue, namePointer, nameLength, callerDataPointer, calleeDataPointer, socketQosPointer, groupQosPointer);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_wsaConnectOriginal(socketValue, namePointer, nameLength, callerDataPointer, calleeDataPointer, socketQosPointer, groupQosPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"connect", socketValue, 0, 0, 0, namePointer, nameLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"WSAConnect",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedSend(SOCKET socketValue, const char* bufferPointer, int bufferLength, int flagsValue)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_sendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_sendOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue >= 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"send", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), resultValue, static_cast<DWORD>(flagsValue));
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"send",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedWSASend(SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesSentPointer, DWORD flagsValue, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_wsaSendOriginal(socketValue, buffersPointer, bufferCount, bytesSentPointer, flagsValue, overlappedPointer, completionRoutinePointer);
            }

            const DWORD incomingWin32 = ::GetLastError();
            const int incomingWsa = ::WSAGetLastError();
            const std::uint64_t requestLength = SumWsaBufferLength(buffersPointer, bufferCount);
            auto operation = BeginIo(socketValue, overlappedPointer, L"Ws2_32", L"WSASend",
                ks::winapi_monitor::EventCategory::Network, requestLength, completionRoutinePointer != nullptr);
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(operation, nullptr, completionRoutinePointer));
            if (completionRoutinePointer && !replacement) operation.reset();
            ::WSASetLastError(incomingWsa); ::SetLastError(incomingWin32);
            const auto callClock = BeginApiCallClock();
            const int resultValue = g_wsaSendOriginal(socketValue, buffersPointer, bufferCount, bytesSentPointer, flagsValue, overlappedPointer, replacement ? replacement : completionRoutinePointer);
            const auto duration = EndApiCallClock(callClock);
            const int savedWsa = ::WSAGetLastError();
            const DWORD savedWin32 = ::GetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            DWORD sentValue = 0;
            const bool sentKnown = resultValue == 0 && !overlappedPointer && TrySafeIoValue(bytesSentPointer, &sentValue);
            FinishIo(operation, resultValue == 0 || errorValue == WSA_IO_PENDING,
                resultValue != 0 && errorValue == WSA_IO_PENDING, errorValue, sentValue, sentKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"send", socketValue, requestLength, sentValue, flagsValue, nullptr, 0, sentKnown, true);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"WSASend",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedSendTo(SOCKET socketValue, const char* bufferPointer, int bufferLength, int flagsValue, const sockaddr* toPointer, int toLength)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_sendToOriginal(socketValue, bufferPointer, bufferLength, flagsValue, toPointer, toLength);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_sendToOriginal(socketValue, bufferPointer, bufferLength, flagsValue, toPointer, toLength);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue >= 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"sendto", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), resultValue, static_cast<DWORD>(flagsValue), toPointer, toLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"sendto",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedRecv(SOCKET socketValue, char* bufferPointer, int bufferLength, int flagsValue)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_recvOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_recvOriginal(socketValue, bufferPointer, bufferLength, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue >= 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"recv", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), resultValue, static_cast<DWORD>(flagsValue));
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"recv",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedWSARecv(SOCKET socketValue, LPWSABUF buffersPointer, DWORD bufferCount, LPDWORD bytesReceivedPointer, LPDWORD flagsPointer, LPWSAOVERLAPPED overlappedPointer, LPWSAOVERLAPPED_COMPLETION_ROUTINE completionRoutinePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_wsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, completionRoutinePointer);
            }

            const DWORD incomingWin32 = ::GetLastError();
            const int incomingWsa = ::WSAGetLastError();
            const std::uint64_t requestLength = SumWsaBufferLength(buffersPointer, bufferCount);
            auto operation = BeginIo(socketValue, overlappedPointer, L"Ws2_32", L"WSARecv",
                ks::winapi_monitor::EventCategory::Network, requestLength, completionRoutinePointer != nullptr);
            auto replacement = reinterpret_cast<LPWSAOVERLAPPED_COMPLETION_ROUTINE>(PrepareIoCallback(operation, nullptr, completionRoutinePointer));
            if (completionRoutinePointer && !replacement) operation.reset();
            ::WSASetLastError(incomingWsa); ::SetLastError(incomingWin32);
            const auto callClock = BeginApiCallClock();
            const int resultValue = g_wsaRecvOriginal(socketValue, buffersPointer, bufferCount, bytesReceivedPointer, flagsPointer, overlappedPointer, replacement ? replacement : completionRoutinePointer);
            const auto duration = EndApiCallClock(callClock);
            const int savedWsa = ::WSAGetLastError();
            const DWORD savedWin32 = ::GetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            DWORD receivedValue = 0, flagsValue = 0;
            const bool receivedKnown = resultValue == 0 && !overlappedPointer && TrySafeIoValue(bytesReceivedPointer, &receivedValue);
            const bool flagsKnown = resultValue == 0 && !overlappedPointer && TrySafeIoValue(flagsPointer, &flagsValue);
            FinishIo(operation, resultValue == 0 || errorValue == WSA_IO_PENDING,
                resultValue != 0 && errorValue == WSA_IO_PENDING, errorValue, receivedValue, receivedKnown);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"recv", socketValue, requestLength, receivedValue, flagsValue, nullptr, 0, receivedKnown, flagsKnown);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"WSARecv",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedRecvFrom(SOCKET socketValue, char* bufferPointer, int bufferLength, int flagsValue, sockaddr* fromPointer, int* fromLengthPointer)
        {
            (void)bufferPointer;
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_recvFromOriginal(socketValue, bufferPointer, bufferLength, flagsValue, fromPointer, fromLengthPointer);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_recvFromOriginal(socketValue, bufferPointer, bufferLength, flagsValue, fromPointer, fromLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue >= 0 ? 0 : savedWsa;
            const int fromLength = fromLengthPointer != nullptr ? *fromLengthPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"recvfrom", socketValue, static_cast<std::uint64_t>(bufferLength < 0 ? 0 : bufferLength), resultValue, static_cast<DWORD>(flagsValue), fromPointer, fromLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"recvfrom",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedBind(SOCKET socketValue, const sockaddr* namePointer, int nameLength)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_bindOriginal(socketValue, namePointer, nameLength);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_bindOriginal(socketValue, namePointer, nameLength);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"bind", socketValue, 0, 0, 0, namePointer, nameLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"bind",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        int WSAAPI HookedListen(SOCKET socketValue, int backlogValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_listenOriginal(socketValue, backlogValue);
            }

            const auto callClock = BeginApiCallClock();
            const int resultValue = g_listenOriginal(socketValue, backlogValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultValue == 0 ? 0 : savedWsa;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, L"socket=");
            AppendHexText(detailBuffer, static_cast<std::uint64_t>(socketValue));
            AppendWideText(detailBuffer, L" backlog=");
            AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(backlogValue < 0 ? 0 : backlogValue));
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"listen",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultValue;
        }

        SOCKET WSAAPI HookedAccept(SOCKET socketValue, sockaddr* addressPointer, int* addressLengthPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass())
            {
                return g_acceptOriginal(socketValue, addressPointer, addressLengthPointer);
            }

            const auto callClock = BeginApiCallClock();
            const SOCKET resultSocket = g_acceptOriginal(socketValue, addressPointer, addressLengthPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD savedWin32 = ::GetLastError();
            const int savedWsa = ::WSAGetLastError();
            const int errorValue = resultSocket != INVALID_SOCKET ? 0 : savedWsa;
            const int addressLength = addressLengthPointer != nullptr ? *addressLengthPointer : 0;
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildSocketDetail(detailBuffer, L"accept", socketValue, 0, static_cast<long long>(resultSocket == INVALID_SOCKET ? 0 : resultSocket), 0, addressPointer, addressLength);
            SendRawEventWithMetrics(
                ks::winapi_monitor::EventCategory::Network,
                L"Ws2_32",
                L"accept",
                errorValue,
                detailBuffer, true, ApiReturnBits(resultSocket), duration);
            ::WSASetLastError(savedWsa); ::SetLastError(savedWin32);
            return resultSocket;
        }


        // AppendProcNameText 作用：
        // - 输入：namePointer 为 GetProcAddress 形式的函数名，可能是 MAKEINTRESOURCEA 风格序号；
        // - 处理：优先输出 name=文本，序号输入输出 ordinal=<id>，避免把低地址序号当字符串解引用；
        // - 返回：无返回值，目标缓冲追加安全可显示的过程名摘要。
        template <std::size_t kCount>
        void AppendProcNameText(wchar_t(&detailBuffer)[kCount], const char* const namePointer)
        {
            if (namePointer == nullptr)
            {
                AppendWideText(detailBuffer, L"name=<null>");
                return;
            }
            if (HIWORD(reinterpret_cast<ULONG_PTR>(namePointer)) == 0)
            {
                AppendWideText(detailBuffer, L"ordinal=");
                AppendUnsignedText(detailBuffer, static_cast<unsigned long long>(LOWORD(reinterpret_cast<ULONG_PTR>(namePointer))));
                return;
            }
            AppendWideText(detailBuffer, L"name=");
            AppendAnsiText(detailBuffer, namePointer);
        }

        // AppendAnsiStringText 作用：
        // - 输入：ansiPointer 为 ntdll ANSI_STRING，可为空；
        // - 处理：按 Length 复制窄字符，避免依赖 Buffer 以 NUL 结束；
        // - 返回：无返回值，目标缓冲追加可截断的过程名文本。
        template <std::size_t kCount>
        void AppendAnsiStringText(wchar_t(&detailBuffer)[kCount], const ANSI_STRING* const ansiPointer)
        {
            if (ansiPointer == nullptr || ansiPointer->Buffer == nullptr || ansiPointer->Length == 0)
            {
                return;
            }
            AppendAnsiText(detailBuffer, ansiPointer->Buffer, ansiPointer->Length);
        }

        // BuildSimpleHandleDetail 作用：
        // - 输入：fieldName 为字段名，handleValue 为待记录句柄；
        // - 处理：生成 field=<hex> 统一详情，复用在 CloseHandle/NtClose/ServiceHandle 等生命周期 API；
        // - 返回：无返回值，detailBuffer 保存固定长度摘要。
        template <std::size_t kCount, typename HandleType>
        void BuildSimpleHandleDetail(wchar_t(&detailBuffer)[kCount], const wchar_t* const fieldName, const HandleType handleValue)
        {
            detailBuffer[0] = L'\0';
            AppendWideText(detailBuffer, fieldName != nullptr ? fieldName : L"handle");
            AppendWideText(detailBuffer, L"=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
        }

        // EmitWin32BoolEvent 作用：
        // - 输入：分类、模块、API、BOOL 结果、LastError 和详情；
        // - 处理：把 BOOL 成功归一为 resultCode=0，失败用 LastError，并恢复调用者线程 LastError；
        // - 返回：无返回值，原函数返回值由 Hooked wrapper 自行返回。
        void EmitWin32BoolEvent(
            const ks::winapi_monitor::EventCategory categoryValue,
            const wchar_t* const moduleName,
            const wchar_t* const apiName,
            const BOOL resultValue,
            const DWORD lastError,
            const wchar_t* const detailText)
        {
            SendRawEventWithStatus(categoryValue, moduleName, apiName, resultValue != FALSE ? 0 : lastError, detailText);
            ::SetLastError(lastError);
        }











        // HookedCloseHandle 作用：
        // - 输入：任意 Win32 HANDLE；
        // - 处理：记录句柄关闭，补齐对象生命周期尾部，便于和 Open/Create/Duplicate 类事件串联；
        // - 返回：保持 CloseHandle 原始 BOOL 结果，并恢复 LastError。


        // HookedDuplicateHandle 作用：
        // - 输入：源/目标进程、源句柄、目标输出句柄、访问掩码和选项；
        // - 处理：记录跨进程句柄复制，覆盖提权、注入和句柄窃取常见前置动作；
        // - 返回：保持 DuplicateHandle 原始 BOOL 结果，并恢复 LastError。


        // HookedCreateFileMappingW 作用：
        // - 输入：文件句柄、保护属性、大小和映射名；
        // - 处理：记录 section/file mapping 创建，补齐 MapViewOfFile 与 NtCreateSection 之间的 Win32 层；
        // - 返回：保持 CreateFileMappingW 原始 HANDLE，并恢复 LastError。


        // HookedCreateFileMappingA 作用：
        // - 输入：ANSI 映射名版本 CreateFileMapping；
        // - 处理：记录文件映射创建参数，映射名按窄字符扩展；
        // - 返回：保持原始 HANDLE，并恢复 LastError。


        // HookedOpenFileMappingW/A 作用：记录命名 mapping 打开；返回原始 HANDLE。



        // HookedMapViewOfFile/Ex 作用：记录映射视图落点和大小；返回原始基址指针。



        // HookedUnmapViewOfFile/FlushViewOfFile 作用：记录映射视图生命周期和回写动作；返回原始 BOOL。





        // HookedFreeLibrary/GetProcAddress/LdrGetProcedureAddress 作用：
        // - 输入：加载器卸载、导出解析和 ntdll 层过程解析参数；
        // - 处理：记录动态解析链路，弥补只看目标 API 调用但看不到“解析意图”的缺口；
        // - 返回：保持原始返回值和 LastError/NTSTATUS。


        FARPROC WINAPI HookedGetProcAddress(HMODULE moduleHandle, LPCSTR procNamePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getProcAddressOriginal(moduleHandle, procNamePointer); }
            const auto callClock = BeginApiCallClock();
            const FARPROC resultPointer = g_getProcAddressOriginal(moduleHandle, procNamePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"module=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            AppendWideText(detailBuffer, L" ");
            AppendProcNameText(detailBuffer, procNamePointer);
            AppendWideText(detailBuffer, L" address=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultPointer));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Loader, L"Kernel32", L"GetProcAddress", resultPointer != nullptr ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultPointer), duration);
            ::SetLastError(lastError);
            return resultPointer;
        }

        NTSTATUS NTAPI HookedLdrGetProcedureAddress(HMODULE moduleHandle, PANSI_STRING procNamePointer, WORD ordinalValue, PVOID* functionPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_ldrGetProcedureAddressOriginal(moduleHandle, procNamePointer, ordinalValue, functionPointer); }
            const auto callClock = BeginApiCallClock();
            const NTSTATUS statusValue = g_ldrGetProcedureAddressOriginal(moduleHandle, procNamePointer, ordinalValue, functionPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"module=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            AppendWideText(detailBuffer, L" name=");
            AppendAnsiStringText(detailBuffer, procNamePointer);
            AppendWideText(detailBuffer, L" ordinal=");
            AppendUnsignedText(detailBuffer, ordinalValue);
            AppendWideText(detailBuffer, L" address=");
            AppendHexText(detailBuffer, functionPointer != nullptr ? reinterpret_cast<std::uint64_t>(*functionPointer) : 0);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Loader, L"ntdll", L"LdrGetProcedureAddress", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedReg*Transacted/Restore/Unload/Notify 作用：补齐 advapi32 注册表变体；返回原始 LSTATUS。
















        // HookedNtClose/native registry variants 作用：补齐 ntdll 句柄关闭和高级注册表 native API；返回原始 NTSTATUS。










        // HookedToken* 作用：
        // - 输入：Token 打开、复制、提权和带 Token 创建进程的关键参数；
        // - 处理：补齐权限提升、令牌窃取和用户上下文切换行为的 Win32 层观测；
        // - 返回：保持原始 BOOL 结果，并恢复 LastError。





        BOOL WINAPI HookedCreateProcessAsUserW(HANDLE tokenHandle, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer)
        {
            ScopedHookGuard guard;
            if (guard.bypass()) return g_createProcessAsUserWOriginal(tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL result = g_createProcessAsUserWOriginal(tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            AutoInjectChildIfRequested(result, processInformationPointer);
            if (ActiveConfig().enableProcess)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                { AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" app="); AppendWideText(detailBuffer, applicationNamePointer); AppendWideText(detailBuffer, L" cmd="); AppendWideText(detailBuffer, commandLinePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, creationFlags); AppendWideText(detailBuffer, L" childPid="); AppendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); }
                SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"CreateProcessAsUserW", result ? 0 : lastError, detailBuffer, true, ApiReturnBits(result), duration);
            }
            ::SetLastError(lastError);
            return result;
        }
        BOOL WINAPI HookedCreateProcessAsUserA(HANDLE tokenHandle, LPCSTR applicationNamePointer, LPSTR commandLinePointer, LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles, DWORD creationFlags, LPVOID environmentPointer, LPCSTR currentDirectoryPointer, LPSTARTUPINFOA startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer)
        {
            ScopedHookGuard guard;
            if (guard.bypass()) return g_createProcessAsUserAOriginal(tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL result = g_createProcessAsUserAOriginal(tokenHandle, applicationNamePointer, commandLinePointer, processAttributes, threadAttributes, inheritHandles, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            AutoInjectChildIfRequested(result, processInformationPointer);
            if (ActiveConfig().enableProcess)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                { AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" app="); AppendAnsiText(detailBuffer, applicationNamePointer); AppendWideText(detailBuffer, L" cmd="); AppendAnsiText(detailBuffer, commandLinePointer); AppendWideText(detailBuffer, L" flags="); AppendHexText(detailBuffer, creationFlags); AppendWideText(detailBuffer, L" childPid="); AppendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); }
                SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"CreateProcessAsUserA", result ? 0 : lastError, detailBuffer, true, ApiReturnBits(result), duration);
            }
            ::SetLastError(lastError);
            return result;
        }
        BOOL WINAPI HookedCreateProcessWithTokenW(HANDLE tokenHandle, DWORD logonFlags, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer)
        {
            ScopedHookGuard guard;
            if (guard.bypass()) return g_createProcessWithTokenWOriginal(tokenHandle, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL result = g_createProcessWithTokenWOriginal(tokenHandle, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            AutoInjectChildIfRequested(result, processInformationPointer);
            if (ActiveConfig().enableProcess)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                { AppendWideText(detailBuffer, L"token="); AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(tokenHandle)); AppendWideText(detailBuffer, L" logonFlags="); AppendHexText(detailBuffer, logonFlags); AppendWideText(detailBuffer, L" app="); AppendWideText(detailBuffer, applicationNamePointer); AppendWideText(detailBuffer, L" cmd="); AppendWideText(detailBuffer, commandLinePointer); AppendWideText(detailBuffer, L" childPid="); AppendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); }
                SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"CreateProcessWithTokenW", result ? 0 : lastError, detailBuffer, true, ApiReturnBits(result), duration);
            }
            ::SetLastError(lastError);
            return result;
        }



        // HookedService* 作用：
        // - 输入：SCM/Service 打开、创建、配置、启动、控制、删除和关闭参数；
        // - 处理：补齐服务安装与驱动服务控制路径的 Advapi32 层观测；
        // - 返回：保持原始 SC_HANDLE/BOOL 结果，并恢复 LastError。















        // HookedWs2Extended 作用：
        // - 输入：扩展 Winsock 控制、面向地址的 WSASendTo/WSARecvFrom、名称解析参数；
        // - 处理：补齐基础 send/recv/connect 之外的高频网络路径；
        // - 返回：保持原始 Winsock 返回值，并恢复 WSA 错误码。






        // HookedDnsQueryW/A 作用：记录 DNSAPI 显式解析请求；返回原始 DNS_STATUS。
        DNS_STATUS WINAPI HookedDnsQueryW(PCWSTR namePointer, WORD typeValue, DWORD optionsValue, PVOID extraPointer, PDNS_RECORDW* queryResultsPointer, PVOID* reservedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_dnsQueryWOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer); }
            const auto callClock = BeginApiCallClock();
            const DNS_STATUS statusValue = g_dnsQueryWOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"name=");
            AppendWideText(detailBuffer, namePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, typeValue);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, optionsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Dnsapi", L"DnsQuery_W", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        DNS_STATUS WINAPI HookedDnsQueryA(PCSTR namePointer, WORD typeValue, DWORD optionsValue, PVOID extraPointer, PDNS_RECORDA* queryResultsPointer, PVOID* reservedPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_dnsQueryAOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer); }
            const auto callClock = BeginApiCallClock();
            const DNS_STATUS statusValue = g_dnsQueryAOriginal(namePointer, typeValue, optionsValue, extraPointer, queryResultsPointer, reservedPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"name=");
            AppendAnsiText(detailBuffer, namePointer);
            AppendWideText(detailBuffer, L" type=");
            AppendUnsignedText(detailBuffer, typeValue);
            AppendWideText(detailBuffer, L" options=");
            AppendHexText(detailBuffer, optionsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Dnsapi", L"DnsQuery_A", statusValue, detailBuffer, true, ApiReturnBits(statusValue), duration);
            return statusValue;
        }

        // HookedWinHttp/WinInet 作用：
        // - 输入：HTTP session/connect/request/read/write/close 参数；
        // - 处理：补齐只 hook Winsock 时看不到 URL/host/verb 的高层网络语义；
        // - 返回：保持原始 HINTERNET/BOOL，并恢复 LastError。





















        // HookedCrypto/COM 作用：
        // - 输入：CryptoAPI/CNG/COM 关键对象创建、加解密、随机数和类工厂参数；
        // - 处理：补齐安全敏感库调用面，详情只记录算法/长度/句柄，不复制明文或密钥内容；
        // - 返回：保持原始 BOOL/NTSTATUS/HRESULT 结果。






















        // HookedLocalMemory 作用：
        // - 输入：当前进程 VirtualAlloc/Free/Protect 参数；
        // - 处理：补齐非 Ex 本地内存分配、释放和权限修改，覆盖自解密/动态代码生成常见路径；
        // - 返回：保持原始返回值并恢复 LastError。




        // HookedToolhelpAndModule 作用：
        // - 输入：Toolhelp 快照和模块枚举/模块路径查询参数；
        // - 处理：补齐模块枚举和加载器探测链路；
        // - 返回：保持原始 HANDLE/BOOL/DWORD 语义。
        HANDLE WINAPI HookedCreateToolhelp32Snapshot(DWORD flagsValue, DWORD processId)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createToolhelp32SnapshotOriginal(flagsValue, processId); }
            const auto callClock = BeginApiCallClock();
            const HANDLE resultHandle = g_createToolhelp32SnapshotOriginal(flagsValue, processId);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" pid=");
            AppendUnsignedText(detailBuffer, processId);
            AppendWideText(detailBuffer, L" snapshot=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(resultHandle));
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Kernel32", L"CreateToolhelp32Snapshot", resultHandle != INVALID_HANDLE_VALUE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultHandle), duration);
            ::SetLastError(lastError);
            return resultHandle;
        }









        DWORD WINAPI HookedGetModuleFileNameW(HMODULE moduleHandle, LPWSTR fileNamePointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getModuleFileNameWOriginal(moduleHandle, fileNamePointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getModuleFileNameWOriginal(moduleHandle, fileNamePointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"module=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" path=");
            AppendWideText(detailBuffer, resultValue != 0 ? fileNamePointer : nullptr, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Loader, L"Kernel32", L"GetModuleFileNameW", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetModuleFileNameA(HMODULE moduleHandle, LPSTR fileNamePointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getModuleFileNameAOriginal(moduleHandle, fileNamePointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getModuleFileNameAOriginal(moduleHandle, fileNamePointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"module=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(moduleHandle));
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" path=");
            if (resultValue != 0) { AppendAnsiText(detailBuffer, fileNamePointer, resultValue); }
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Loader, L"Kernel32", L"GetModuleFileNameA", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        // HookedFileExtras 作用：记录硬链接、文件替换、EOF 设置和文件锁操作；返回原始 BOOL。








        // HookedShellExecuteW/A 作用：
        // - 输入：ShellExecute 目标、参数、目录和显示方式；
        // - 处理：补齐 ShellExecuteEx 之外的老式 Shell 启动入口；
        // - 返回：保持原始 HINSTANCE 语义，<=32 视作失败并恢复 LastError。
        HINSTANCE WINAPI HookedShellExecuteW(HWND windowHandle, LPCWSTR operationPointer, LPCWSTR filePointer, LPCWSTR parametersPointer, LPCWSTR directoryPointer, INT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_shellExecuteWOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand); }
            const auto callClock = BeginApiCallClock();
            const HINSTANCE resultValue = g_shellExecuteWOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"op=");
            AppendWideText(detailBuffer, operationPointer);
            AppendWideText(detailBuffer, L" file=");
            AppendWideText(detailBuffer, filePointer);
            AppendWideText(detailBuffer, L" params=");
            AppendWideText(detailBuffer, parametersPointer);
            AppendWideText(detailBuffer, L" cwd=");
            AppendWideText(detailBuffer, directoryPointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Shell32", L"ShellExecuteW", reinterpret_cast<INT_PTR>(resultValue) > 32 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        HINSTANCE WINAPI HookedShellExecuteA(HWND windowHandle, LPCSTR operationPointer, LPCSTR filePointer, LPCSTR parametersPointer, LPCSTR directoryPointer, INT showCommand)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_shellExecuteAOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand); }
            const auto callClock = BeginApiCallClock();
            const HINSTANCE resultValue = g_shellExecuteAOriginal(windowHandle, operationPointer, filePointer, parametersPointer, directoryPointer, showCommand);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"op=");
            AppendAnsiText(detailBuffer, operationPointer);
            AppendWideText(detailBuffer, L" file=");
            AppendAnsiText(detailBuffer, filePointer);
            AppendWideText(detailBuffer, L" params=");
            AppendAnsiText(detailBuffer, parametersPointer);
            AppendWideText(detailBuffer, L" cwd=");
            AppendAnsiText(detailBuffer, directoryPointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Shell32", L"ShellExecuteA", reinterpret_cast<INT_PTR>(resultValue) > 32 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOL WINAPI HookedCreateProcessWithLogonW(LPCWSTR userNamePointer, LPCWSTR domainPointer, LPCWSTR passwordPointer, DWORD logonFlags, LPCWSTR applicationNamePointer, LPWSTR commandLinePointer, DWORD creationFlags, LPVOID environmentPointer, LPCWSTR currentDirectoryPointer, LPSTARTUPINFOW startupInfoPointer, LPPROCESS_INFORMATION processInformationPointer)
        {
            ScopedHookGuard guard;
            if (guard.bypass()) return g_createProcessWithLogonWOriginal(userNamePointer, domainPointer, passwordPointer, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto callClock = BeginApiCallClock();
            const BOOL result = g_createProcessWithLogonWOriginal(userNamePointer, domainPointer, passwordPointer, logonFlags, applicationNamePointer, commandLinePointer, creationFlags, environmentPointer, currentDirectoryPointer, startupInfoPointer, processInformationPointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            AutoInjectChildIfRequested(result, processInformationPointer);
            if (ActiveConfig().enableProcess)
            {
                wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
                { AppendWideText(detailBuffer, L"user="); AppendWideText(detailBuffer, domainPointer); AppendWideText(detailBuffer, L"\\"); AppendWideText(detailBuffer, userNamePointer); AppendWideText(detailBuffer, L" logonFlags="); AppendHexText(detailBuffer, logonFlags); AppendWideText(detailBuffer, L" app="); AppendWideText(detailBuffer, applicationNamePointer); AppendWideText(detailBuffer, L" cmd="); AppendWideText(detailBuffer, commandLinePointer); AppendWideText(detailBuffer, L" childPid="); AppendUnsignedText(detailBuffer, processInformationPointer != nullptr ? processInformationPointer->dwProcessId : 0); }
                SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"CreateProcessWithLogonW", result ? 0 : lastError, detailBuffer, true, ApiReturnBits(result), duration);
            }
            ::SetLastError(lastError);
            return result;
        }

        // HookedServiceQuery 作用：记录服务二级配置、状态和枚举，补齐服务创建/启动之外的 SCM 侦察面；返回原始 BOOL。








        // HookedHttpQueryExtras 作用：记录 WinHTTP/WinINet 查询、选项设置和 URL 直连入口；返回原始结果。











        HRESULT WINAPI HookedURLDownloadToFileW(LPUNKNOWN callerPointer, LPCWSTR urlPointer, LPCWSTR fileNamePointer, DWORD reservedValue, LPBINDSTATUSCALLBACK callbackPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_urlDownloadToFileWOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer); }
            const auto callClock = BeginApiCallClock();
            const HRESULT resultValue = g_urlDownloadToFileWOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"url=");
            AppendWideText(detailBuffer, urlPointer);
            AppendWideText(detailBuffer, L" file=");
            AppendWideText(detailBuffer, fileNamePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Urlmon", L"URLDownloadToFileW", resultValue, detailBuffer, true, ApiReturnBits(resultValue), duration);
            return resultValue;
        }

        HRESULT WINAPI HookedURLDownloadToFileA(LPUNKNOWN callerPointer, LPCSTR urlPointer, LPCSTR fileNamePointer, DWORD reservedValue, LPBINDSTATUSCALLBACK callbackPointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_urlDownloadToFileAOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer); }
            const auto callClock = BeginApiCallClock();
            const HRESULT resultValue = g_urlDownloadToFileAOriginal(callerPointer, urlPointer, fileNamePointer, reservedValue, callbackPointer);
            const auto duration = EndApiCallClock(callClock);
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"url=");
            AppendAnsiText(detailBuffer, urlPointer);
            AppendWideText(detailBuffer, L" file=");
            AppendAnsiText(detailBuffer, fileNamePointer);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Network, L"Urlmon", L"URLDownloadToFileA", resultValue, detailBuffer, true, ApiReturnBits(resultValue), duration);
            return resultValue;
        }

        // HookedCryptoLifecycle 作用：记录密钥导入/导出/销毁以及 CNG 密钥创建导入销毁；不记录密钥内容。










        void WINAPI HookedCoUninitialize()
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { g_coUninitializeOriginal(); return; }
            const auto callClock = BeginApiCallClock();
            g_coUninitializeOriginal();
            const DWORD savedError = ::GetLastError();
            const auto duration = EndApiCallClock(callClock);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Ole32", L"CoUninitialize", 0, L"", false, 0, duration);
            ::SetLastError(savedError);
        }

        // HookedThirdBatchProcess 作用：
        // - 输入：注入扩展、同步对象、环境变量、DLL 搜索路径和 User32 hook 参数；
        // - 处理：继续沿用“先调用原函数，再记录结果并恢复错误码”的 APIMonitor 旧模式；
        // - 返回：保持各 WinAPI 原始返回语义。


        BOOLEAN WINAPI HookedCreateSymbolicLinkW(LPCWSTR linkPointer, LPCWSTR targetPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createSymbolicLinkWOriginal(linkPointer, targetPointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOLEAN resultValue = g_createSymbolicLinkWOriginal(linkPointer, targetPointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailW(detailBuffer, linkPointer, targetPointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CreateSymbolicLinkW", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        BOOLEAN WINAPI HookedCreateSymbolicLinkA(LPCSTR linkPointer, LPCSTR targetPointer, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_createSymbolicLinkAOriginal(linkPointer, targetPointer, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const BOOLEAN resultValue = g_createSymbolicLinkAOriginal(linkPointer, targetPointer, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            BuildTwoPathDetailA(detailBuffer, linkPointer, targetPointer, flagsValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"CreateSymbolicLinkA", resultValue != FALSE ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetFinalPathNameByHandleW(HANDLE fileHandle, LPWSTR filePathPointer, DWORD filePathSize, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFinalPathNameByHandleWOriginal(fileHandle, filePathPointer, filePathSize, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getFinalPathNameByHandleWOriginal(fileHandle, filePathPointer, filePathSize, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"file=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" path=");
            if (resultValue != 0 && resultValue < filePathSize) { AppendWideText(detailBuffer, filePathPointer, resultValue); }
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFinalPathNameByHandleW", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetFinalPathNameByHandleA(HANDLE fileHandle, LPSTR filePathPointer, DWORD filePathSize, DWORD flagsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getFinalPathNameByHandleAOriginal(fileHandle, filePathPointer, filePathSize, flagsValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getFinalPathNameByHandleAOriginal(fileHandle, filePathPointer, filePathSize, flagsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"file=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(fileHandle));
            AppendWideText(detailBuffer, L" flags=");
            AppendHexText(detailBuffer, flagsValue);
            AppendWideText(detailBuffer, L" path=");
            if (resultValue != 0 && resultValue < filePathSize) { AppendAnsiText(detailBuffer, filePathPointer, resultValue); }
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::File, L"KernelBase", L"GetFinalPathNameByHandleA", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }






















        DWORD WINAPI HookedWaitForSingleObject(HANDLE handleValue, DWORD millisecondsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_waitForSingleObjectOriginal(handleValue, millisecondsValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_waitForSingleObjectOriginal(handleValue, millisecondsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"handle=");
            AppendHexText(detailBuffer, reinterpret_cast<std::uint64_t>(handleValue));
            AppendWideText(detailBuffer, L" timeout=");
            AppendUnsignedText(detailBuffer, millisecondsValue);
            AppendWideText(detailBuffer, L" result=");
            AppendHexText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"WaitForSingleObject", resultValue != WAIT_FAILED ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedWaitForMultipleObjects(DWORD countValue, const HANDLE* handlesPointer, BOOL waitAll, DWORD millisecondsValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_waitForMultipleObjectsOriginal(countValue, handlesPointer, waitAll, millisecondsValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_waitForMultipleObjectsOriginal(countValue, handlesPointer, waitAll, millisecondsValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"count=");
            AppendUnsignedText(detailBuffer, countValue);
            AppendWideText(detailBuffer, L" waitAll=");
            AppendUnsignedText(detailBuffer, waitAll != FALSE ? 1ULL : 0ULL);
            AppendWideText(detailBuffer, L" timeout=");
            AppendUnsignedText(detailBuffer, millisecondsValue);
            AppendWideText(detailBuffer, L" result=");
            AppendHexText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"WaitForMultipleObjects", resultValue != WAIT_FAILED ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }





        DWORD WINAPI HookedGetEnvironmentVariableW(LPCWSTR namePointer, LPWSTR bufferPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getEnvironmentVariableWOriginal(namePointer, bufferPointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getEnvironmentVariableWOriginal(namePointer, bufferPointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"name=");
            AppendWideText(detailBuffer, namePointer);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" resultLen=");
            AppendUnsignedText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"GetEnvironmentVariableW", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedGetEnvironmentVariableA(LPCSTR namePointer, LPSTR bufferPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_getEnvironmentVariableAOriginal(namePointer, bufferPointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_getEnvironmentVariableAOriginal(namePointer, bufferPointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"name=");
            AppendAnsiText(detailBuffer, namePointer);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" resultLen=");
            AppendUnsignedText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"GetEnvironmentVariableA", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }



        DWORD WINAPI HookedExpandEnvironmentStringsW(LPCWSTR sourcePointer, LPWSTR destinationPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_expandEnvironmentStringsWOriginal(sourcePointer, destinationPointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_expandEnvironmentStringsWOriginal(sourcePointer, destinationPointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"src=");
            AppendWideText(detailBuffer, sourcePointer);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" resultLen=");
            AppendUnsignedText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"ExpandEnvironmentStringsW", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }

        DWORD WINAPI HookedExpandEnvironmentStringsA(LPCSTR sourcePointer, LPSTR destinationPointer, DWORD sizeValue)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_expandEnvironmentStringsAOriginal(sourcePointer, destinationPointer, sizeValue); }
            const auto callClock = BeginApiCallClock();
            const DWORD resultValue = g_expandEnvironmentStringsAOriginal(sourcePointer, destinationPointer, sizeValue);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"src=");
            AppendAnsiText(detailBuffer, sourcePointer);
            AppendWideText(detailBuffer, L" size=");
            AppendUnsignedText(detailBuffer, sizeValue);
            AppendWideText(detailBuffer, L" resultLen=");
            AppendUnsignedText(detailBuffer, resultValue);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"KernelBase", L"ExpandEnvironmentStringsA", resultValue != 0 ? 0 : lastError, detailBuffer, true, ApiReturnBits(resultValue), duration);
            ::SetLastError(lastError);
            return resultValue;
        }












        // HookedFourthBatchDiscovery 作用：
        // - 输入：PSAPI 进程/模块枚举、User32 窗口发现、GDI 屏幕采集和剪贴板参数；
        // - 处理：记录侦察、桌面交互和截屏/剪贴板访问行为，不复制敏感缓冲区内容；
        // - 返回：保持原始 WinAPI 返回值，并恢复 LastError。






















        // 剪贴板 8 个 Win32 平导出 hook（含本段原有的 5 个）与 2 个 OLE 平导出 hook
        // 的函数体、原函数指针、InlineHookRecord 全部迁移到 hook/ClipboardGuardHook.cpp——
        // 那五个需要在调用前先判定策略、按需短路原函数，不再适合复用
        // APIMON_SIMPLE_BOOL_HOOK/APIMON_SIMPLE_HANDLE_HOOK 这两个"无条件调用原函数
        // 再上报"的宏。g_bindings[] 里对应条目见下方 Clipboard 分类。

        // HookedFourthBatchTelemetry 作用：
        // - 输入：ETW session/provider/trace 句柄与控制参数；
        // - 处理：记录用户态事件跟踪启停、provider 注册和事件写入入口；
        // - 返回：保持 ETW 原始 ULONG 状态码，ERROR_SUCCESS 为成功。






        TRACEHANDLE WINAPI HookedOpenTraceW(PEVENT_TRACE_LOGFILEW logFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_openTraceWOriginal(logFilePointer); }
            const auto callClock = BeginApiCallClock();
            const TRACEHANDLE traceHandle = g_openTraceWOriginal(logFilePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"logfile=");
            AppendWideText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LogFileName : nullptr);
            AppendWideText(detailBuffer, L" logger=");
            AppendWideText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LoggerName : nullptr);
            AppendWideText(detailBuffer, L" trace=");
            AppendHexText(detailBuffer, traceHandle);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"OpenTraceW", traceHandle != INVALID_PROCESSTRACE_HANDLE ? 0 : lastError, detailBuffer, true, ApiReturnBits(traceHandle), duration);
            ::SetLastError(lastError);
            return traceHandle;
        }

        TRACEHANDLE WINAPI HookedOpenTraceA(PEVENT_TRACE_LOGFILEA logFilePointer)
        {
            ScopedHookGuard guardValue;
            if (guardValue.bypass()) { return g_openTraceAOriginal(logFilePointer); }
            const auto callClock = BeginApiCallClock();
            const TRACEHANDLE traceHandle = g_openTraceAOriginal(logFilePointer);
            const auto duration = EndApiCallClock(callClock);
            const DWORD lastError = ::GetLastError();
            wchar_t detailBuffer[ks::winapi_monitor::kMaxDetailChars] = {};
            AppendWideText(detailBuffer, L"logfile=");
            AppendAnsiText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LogFileName : nullptr);
            AppendWideText(detailBuffer, L" logger=");
            AppendAnsiText(detailBuffer, logFilePointer != nullptr ? logFilePointer->LoggerName : nullptr);
            AppendWideText(detailBuffer, L" trace=");
            AppendHexText(detailBuffer, traceHandle);
            SendRawEventWithMetrics(ks::winapi_monitor::EventCategory::Process, L"Advapi32", L"OpenTraceA", traceHandle != INVALID_PROCESSTRACE_HANDLE ? 0 : lastError, detailBuffer, true, ApiReturnBits(traceHandle), duration);
            ::SetLastError(lastError);
            return traceHandle;
        }







        // HookedFourthBatchTrustCrypto 作用：记录签名/证书/DPAPI 和 CNG Key Storage 入口；不记录密钥或明文内容。






















        // HookedFourthBatchRpcNative 作用：
        // - 输入：RPC endpoint/binding 枚举参数和 ntdll token/object/sync/query 参数；
        // - 处理：补齐 RPC 发现面与 native 层对象/令牌/同步调用面；
        // - 返回：保持 RPC_STATUS 或 NTSTATUS 原始语义。
























        // HookedFifthBatchSecurity 作用：
        // - 输入：登录、令牌、凭据、LSA 和 EventLog 参数；
        // - 处理：补齐账号认证、凭据访问、本机安全策略枚举和日志读写行为面，不记录密码/凭据内容；
        // - 返回：保持 Win32 BOOL/HANDLE 或 NTSTATUS 原始语义。




































        // HookedFifthBatchInventory 作用：
        // - 输入：NetAPI、IP Helper、WTS、Job Object 和 SSPI/Secur32 参数；
        // - 处理：补齐域/共享/会话枚举、网络连接表枚举、终端会话枚举、进程 Job 控制和认证上下文行为；
        // - 返回：保持各 API 原始状态码、BOOL、HANDLE 或 void 语义。













































        // HookedSixthBatchEnumerationPathsNetwork 作用：
        // - 输入：Toolhelp 枚举、进程镜像查询、路径解析/临时文件、管道/邮槽、Winsock 扩展和 HTTP 查询参数；
        // - 处理：补齐进程/线程/堆侦察、路径落点、IPC 创建、socket 配置和 HTTP 元数据访问面；
        // - 返回：保持各 API 原始返回值，必要时恢复 LastError/WSAError。





























































        // HookedSixthBatchNativeObjectSync 作用：
        // - 输入：ntdll 对象目录、符号链接和 semaphore 原生对象参数；
        // - 处理：补齐 Win32 同步/路径枚举背后的 Object Manager 层访问与命名对象解析行为；
        // - 返回：保持各 API 原始 NTSTATUS，并将对象名、访问掩码、计数和输出句柄写入事件详情。









        // HookBinding g_bindings：
        // - 输入：静态白名单中的模块/导出名/分类和 Hooked wrapper 元数据；
        // - 处理：InstallConfiguredHooks 遍历该表安装 inline hook，LoadLibrary/LdrLoadDll 后会重试延迟模块；
        // - 返回：本表本身无返回值，是所有已支持 API 覆盖面的权威来源。
        #include "ApiCaptureFormatters.inc"
#include "ApiMonitorWrappers.inc"
#include "ApiMonitorBindings.inc"

        bool StartsWithWide(const std::wstring& textValue, const std::wstring& prefixValue)
        {
            return textValue.size() >= prefixValue.size()
                && std::equal(prefixValue.begin(), prefixValue.end(), textValue.begin());
        }

        bool IsStrongTypedExport(const std::wstring& moduleName, const std::string& procName)
        {
            // Binding identities never change. Normalize the 641 definitions
            // once, instead of rebuilding all their keys for every Raw export.
            // Keep the immutable index through DLL teardown like the bindings.
            static const auto* const keys = [] {
                auto index = std::make_unique<std::unordered_set<std::wstring>>();
                index->reserve(std::size(g_bindings));
                for (const auto& binding : g_bindings)
                    if (binding.moduleName && binding.procName)
                        index->insert(MakeRawHookKey(binding.moduleName, binding.procName));
                return index.release();
            }();
            return keys->count(MakeRawHookKey(moduleName, procName)) != 0;
        }

        bool IsUnsafeRawFallbackModule(const std::wstring& moduleName)
        {
            // IsUnsafeRawFallbackModule 作用：
            // - 输入：Raw Fallback 配置中的模块名；
            // - 处理：识别不适合通用 ABI 兜底 hook 的底层模块；
            // - 返回：true 表示 Raw 枚举应跳过该模块，强类型 hook 和精确 Fake Success 不受影响。
            // - 原因：ntdll 导出包含 syscall、loader、运行时和内部调度面；即使排除 Nt/Rtl/Ldr 前缀，
            //   剩余导出仍可能在 CRT/loader/异常处理路径被高频调用，通用 Raw trampoline 风险过高。
            return NormalizeModuleNameForMatch(moduleName) == L"ntdll";
        }

        bool MatchesRawDenyPattern(const std::string& procName, const std::wstring& patternText)
        {
            if (procName.empty() || patternText.empty())
            {
                return false;
            }

            const std::wstring lowerProcName = ToLowerWide(AnsiToWide(procName.c_str()));
            std::wstring lowerPattern = ToLowerWide(patternText);
            if (!lowerPattern.empty() && lowerPattern.back() == L'*')
            {
                lowerPattern.pop_back();
                return !lowerPattern.empty() && StartsWithWide(lowerProcName, lowerPattern);
            }
            return lowerProcName == lowerPattern;
        }

        std::vector<std::wstring> SplitRawDenyPatternText(const wchar_t* const patternText)
        {
            // SplitRawDenyPatternText 作用：
            // - 输入：共享协议中的内置 Raw 黑名单文本；
            // - 处理：按分号、逗号或换行拆分，并去掉每项首尾空白；
            // - 返回：可供 MatchesRawDenyPattern 逐项匹配的规则列表。
            std::vector<std::wstring> patternList;
            if (patternText == nullptr || patternText[0] == L'\0')
            {
                return patternList;
            }

            std::wstring currentPattern;
            const auto flushPattern = [&patternList, &currentPattern]() {
                const auto firstIt = std::find_if_not(
                    currentPattern.begin(),
                    currentPattern.end(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
                const auto lastIt = std::find_if_not(
                    currentPattern.rbegin(),
                    currentPattern.rend(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
                if (firstIt < lastIt)
                {
                    patternList.emplace_back(firstIt, lastIt);
                }
                currentPattern.clear();
            };

            for (const wchar_t ch : std::wstring(patternText))
            {
                if (ch == L';' || ch == L',' || ch == L'\r' || ch == L'\n')
                {
                    flushPattern();
                    continue;
                }
                currentPattern.push_back(ch);
            }
            flushPattern();
            return patternList;
        }

        const std::vector<std::wstring>& DefaultRawDenyPatterns()
        {
            // DefaultRawDenyPatterns 作用：
            // - 输入：无；
            // - 处理：懒加载共享默认黑名单，避免每次枚举导出都重复拆分字符串；
            // - 返回：进程内只读规则列表，调用方不得修改。
            static const std::vector<std::wstring> defaultPatternList =
                SplitRawDenyPatternText(ks::winapi_monitor::kDefaultRawHookDenyList);
            return defaultPatternList;
        }

        bool IsRawDeniedByConfig(const std::string& procName)
        {
            const MonitorConfig& configValue = ActiveConfig();
            if (configValue.rawUseDefaultDenyList)
            {
                for (const std::wstring& patternText : DefaultRawDenyPatterns())
                {
                    if (MatchesRawDenyPattern(procName, patternText))
                    {
                        return true;
                    }
                }
            }

            // 用户额外黑名单始终生效：
            // - 默认黑名单可以被用户关闭；
            // - 下方自定义规则仍然用于兜底 Raw Hook，便于临时压制某个目标进程的噪声 API。
            for (const std::wstring& patternText : configValue.rawDenyList)
            {
                if (MatchesRawDenyPattern(procName, patternText))
                {
                    return true;
                }
            }
            return false;
        }

        bool ExportNameLooksHookable(const std::string& procName)
        {
            if (procName.empty())
            {
                return false;
            }
            if (procName[0] == '?' || procName[0] == '_')
            {
                return false;
            }
            for (const unsigned char ch : procName)
            {
                if (ch < 0x20 || ch >= 0x7F)
                {
                    return false;
                }
            }
            return true;
        }

        ks::winapi_monitor::EventCategory InferRawHookCategory(const std::wstring& moduleName, const std::string& procName)
        {
            const std::wstring moduleLower = ToLowerWide(moduleName);
            const std::string procLower = ToLowerAnsi(procName);
            if (moduleLower == L"ws2_32.dll" || moduleLower == L"wininet.dll" || moduleLower == L"winhttp.dll"
                || moduleLower == L"iphlpapi.dll" || moduleLower == L"dnsapi.dll" || moduleLower == L"netapi32.dll"
                || moduleLower == L"urlmon.dll" || moduleLower == L"wldap32.dll")
            {
                return ks::winapi_monitor::EventCategory::Network;
            }
            if (procLower.rfind("reg", 0) == 0 || procLower.find("key") != std::string::npos)
            {
                return ks::winapi_monitor::EventCategory::Registry;
            }
            if (procLower.find("file") != std::string::npos || procLower.find("directory") != std::string::npos
                || procLower.find("path") != std::string::npos || procLower.find("pipe") != std::string::npos)
            {
                return ks::winapi_monitor::EventCategory::File;
            }
            if (procLower.find("library") != std::string::npos || procLower.find("module") != std::string::npos
                || procLower.rfind("ldr", 0) == 0)
            {
                return ks::winapi_monitor::EventCategory::Loader;
            }
            return ks::winapi_monitor::EventCategory::Process;
        }



        bool HookSessionStopping()
        {
            if(StopRequested())return true;
            if(IsStopFlagPresent(ActiveConfig())){RequestStop();return true;}
            return false;
        }

        bool TryInstallRawHookBinding(RawHookBinding& bindingValue)
        {
            if (!CategoryEnabled(bindingValue.categoryValue)) return bindingValue.hookRecord.installed;
            if (bindingValue.hookRecord.installed || bindingValue.hookRecord.permanentlyDisabled)
            {
                return bindingValue.hookRecord.installed;
            }
            if (bindingValue.entryStubAddress == nullptr)
            {
                bindingValue.entryStubAddress = BuildRawEntryStub(&bindingValue);
                if (bindingValue.entryStubAddress == nullptr)
                {
                    bindingValue.hookRecord.permanentlyDisabled = true;
                    return false;
                }
            }

            std::wstring ignoredErrorText;
            const InlineHookInstallResult installResult = InstallInlineHook(
                bindingValue.moduleName.c_str(),
                bindingValue.procName.c_str(),
                bindingValue.entryStubAddress,
                &bindingValue.hookRecord,
                &bindingValue.originalAddress,
                &ignoredErrorText);
            if (installResult == InlineHookInstallResult::Installed)
            {
                return true;
            }
            if (installResult == InlineHookInstallResult::PermanentFailure)
            {
                bindingValue.hookRecord.permanentlyDisabled = true;
            }
            return false;
        }

        bool InstallFakeSuccessHooks(std::wstring* const detailTextOut)
        {
            // InstallFakeSuccessHooks 作用：
            // - 输入：已由 BuildFakeSuccessRuleIndex 准备好的 Fake Success 规则集合；
            // - 处理：仅在 fake_success_raw_fallback=1 时补装未被强类型表覆盖的精确 module!api 规则；
            // - 返回：至少一条 Fake Success 规则已安装/安装成功时返回 true。
            const MonitorConfig& configValue = ActiveConfig();
            auto& ruleList = FakeSuccessRules();
            if (!configValue.fakeSuccessEnabled || !configValue.fakeSuccessRawFallback || ruleList.empty())
            {
                return false;
            }

            bool installedAny = false;
            for (std::unique_ptr<FakeSuccessRuntimeRule>& rulePointer : ruleList)
            {
                if(HookInstallationCancelled())break;
                if (rulePointer == nullptr)
                {
                    continue;
                }
                installedAny = TryInstallFakeSuccessRule(*rulePointer, std::nullopt, detailTextOut) || installedAny;
            }
            return installedAny;
        }

        bool UninstallFakeSuccessHooks()
        {
            auto& entries = FakeSuccessRules();
            bool removed = true;
            for (auto& entry : entries)
                if (entry) removed = UninstallInlineHook(&entry->hookRecord) && removed;
            if (!removed) return false;
            CaptureRemovedFakeCoverage();
            // Intentionally retain contexts and entry stubs for in-flight calls until process exit.
            for (auto& entry : entries) (void)entry.release();
            entries.clear();
            FakeSuccessRuleMap().clear();
            return true;
        }

        void DiscoverRawHookBindingsForLoadedModules()
        {
            const MonitorConfig& configValue = ActiveConfig();
            if (!configValue.enableRawFallback)
            {
                for (const auto& module : configValue.rawModuleList)
                    g_rawCoverageObservations[MakeRawHookKey(module, "*")] = MakeCoverageRow(module.c_str(), L"*", HookKind::Raw,
                        CoverageState::CategoryDisabled, L"Raw monitoring disabled");
                return;
            }

            constexpr std::size_t kMaxRawExportsPerModule = 768;
            std::vector<std::string> exportNameList;
            for (const std::wstring& moduleName : configValue.rawModuleList)
            {
                if (moduleName.empty())
                {
                    continue;
                }
                const auto moduleKey = MakeRawHookKey(moduleName, "*");
                if (IsUnsafeRawFallbackModule(moduleName))
                {
                    g_rawCoverageObservations[moduleKey] = MakeCoverageRow(moduleName.c_str(), L"*", HookKind::Raw,
                        CoverageState::RuleExcluded, L"module excluded by Raw safety policy");
                    continue;
                }

                HMODULE moduleHandle = ::GetModuleHandleW(moduleName.c_str());
                if (moduleHandle == nullptr)
                {
                    g_rawCoverageObservations[moduleKey] = MakeCoverageRow(moduleName.c_str(), L"*", HookKind::Raw,
                        CoverageState::WaitingModule, L"Raw module not loaded");
                    continue;
                }
                g_rawCoverageObservations.erase(moduleKey);
                if (!EnumerateNamedExports(moduleHandle, &exportNameList))
                {
                    continue;
                }

                std::size_t acceptedCount = 0;
                for (const std::string& exportName : exportNameList)
                {
                    const auto observationKey = MakeRawHookKey(moduleName, exportName);
                    const auto observationApi = AnsiToWide(exportName.c_str());
                    if (!ExportNameLooksHookable(exportName)
                        || IsStrongTypedExport(moduleName, exportName)
                        || (configValue.fakeSuccessRawFallback && FindFakeSuccessRule(moduleName, exportName) != nullptr)
                        || IsRawDeniedByConfig(exportName))
                    {
                        g_rawCoverageObservations[observationKey] = MakeCoverageRow(moduleName.c_str(), observationApi.c_str(),
                            HookKind::Raw, CoverageState::RuleExcluded,
                            IsStrongTypedExport(moduleName, exportName) ? L"Strong definition owns this export; see its actual installation state" : L"export excluded by Raw/Fake rules");
                        continue;
                    }
                    if (IsNativeRuntimeHookTarget(reinterpret_cast<void*>(::GetProcAddress(moduleHandle, exportName.c_str()))))
                    {
                        g_rawCoverageObservations[observationKey] = MakeCoverageRow(moduleName.c_str(), observationApi.c_str(),
                            HookKind::Raw, CoverageState::RuleExcluded, L"Raw target resolves into excluded native runtime (ntdll)");
                        continue;
                    }
                    if (acceptedCount >= kMaxRawExportsPerModule)
                    {
                        g_rawCoverageObservations[observationKey] = MakeCoverageRow(moduleName.c_str(), observationApi.c_str(),
                            HookKind::Raw, CoverageState::RetryableFailure, L"waiting for next installation batch");
                        continue;
                    }

                    const std::wstring rawKey = MakeRawHookKey(moduleName, exportName);
                    auto& rawKeySet = RawHookKeys();
                    auto& rawBindingList = RawBindings();
                    if (rawKeySet.find(rawKey) != rawKeySet.end())
                    {
                        continue;
                    }

                    auto bindingPointer = std::make_unique<RawHookBinding>();
                    bindingPointer->moduleName = moduleName;
                    bindingPointer->procName = exportName;
                    bindingPointer->procNameWide = AnsiToWide(exportName.c_str());
                    bindingPointer->categoryValue = InferRawHookCategory(moduleName, exportName);
                    bindingPointer->apiId = RuntimeApiId(moduleName.c_str(), bindingPointer->procNameWide.c_str());
                    rawKeySet.insert(rawKey);
                    rawBindingList.push_back(std::move(bindingPointer));
                    ++acceptedCount;
                }
            }
        }

        bool InstallRawFallbackHooks()
        {
            const MonitorConfig& configValue = ActiveConfig();
            if (!configValue.enableRawFallback)
            {
                DiscoverRawHookBindingsForLoadedModules();
                return false;
            }

            DiscoverRawHookBindingsForLoadedModules();

            bool installedAny = false;
            APIMON_DIAG_MARK("raw-begin",RawBindings().size(),0);
#if KSWORD_APIMON_DIAGNOSTICS
            std::size_t diagnosticIndex = 0;
#endif
            for (std::unique_ptr<RawHookBinding>& bindingPointer : RawBindings())
            {
                if(HookInstallationCancelled())break;
                if (bindingPointer == nullptr)
                {
                    continue;
                }
                installedAny = TryInstallRawHookBinding(*bindingPointer) || installedAny;
#if KSWORD_APIMON_DIAGNOSTICS
                if ((++diagnosticIndex % 256) == 0)
                    APIMON_DIAG_MARK("raw-progress",diagnosticIndex,IsStopFlagPresent(ActiveConfig()) ? 1 : 0);
#endif
            }
            APIMON_DIAG_MARK("raw-end",RawBindings().size(),0);
            return installedAny;
        }

        bool UninstallRawFallbackHooks()
        {
            auto& entries = RawBindings();
            bool removed = true;
            for (auto& entry : entries)
                if (entry) removed = UninstallInlineHook(&entry->hookRecord) && removed;
            if (!removed) return false;
            CaptureRemovedRawCoverage();
            // Intentionally retain contexts and entry stubs for in-flight calls until process exit.
            for (auto& entry : entries) (void)entry.release();
            entries.clear();
            RawHookKeys().clear();
            return true;
        }

#include "ApiCoverageReporting.inc"

        // RetryPendingHooksUnlocked 作用：
        // - 输入：detailTextOut 可选，用于接收本轮仍无法安装的 Hook 诊断；
        // - 处理：在调用者已经持有 g_hookOperationMutex 时补装尚未安装的可重试 Hook；
        // - 返回：无返回值，调用方可用诊断文本判断本轮是否仍有待重试失败。
        void RetryPendingHooksUnlocked(std::wstring* detailTextOut)
        {
            ScopedHookInstallCancellation cancellation(&HookSessionStopping);
            if(HookInstallationCancelled())return;
            InlineHookInstallBatch batch;
            if (detailTextOut != nullptr)
            {
                detailTextOut->clear();
            }
            for (HookBinding& bindingValue : g_bindings)
            {
                if(HookInstallationCancelled())break;
                (void)TryInstallBinding(bindingValue, detailTextOut);
            }
            (void)InstallFakeSuccessHooks(detailTextOut);
            (void)InstallRawFallbackHooks();
            RetryExtensionHooks();
            (void)batch.commit();
            PublishConfiguredCoverage();
        }

        // RetryPendingHooksFromHook 作用：
        // - 输入：无；
        // - Processing: after the LoadLibrary/LdrLoadDll hooked wrapper returns, try to acquire the hook lock.
        // - 返回：无返回值，锁正忙时跳过本轮补装。
        void RetryPendingHooksFromHook()
        {
            const std::unique_lock<std::mutex> lock(g_hookOperationMutex,std::try_to_lock);
            if (lock.owns_lock())
            {
                ScopedInlineHookInternalBypass hookOperationBypassScope;
                try {RetryPendingHooksUnlocked(nullptr);}
                catch (...) {
                    RequestStop();
                    try {SendMonitorEventRaw(ks::winapi_monitor::EventCategory::Internal,L"Agent",L"AgentFailure",
                        ERROR_UNHANDLED_EXCEPTION,L"Hook retry exception; monitoring stop requested.");}catch(...) {}
                }
            }
        }

    }

    bool InstallConfiguredHooks(std::wstring* errorTextOut)
    {
        const std::lock_guard<std::mutex> lock(g_hookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        ScopedHookInstallCancellation cancellation(&HookSessionStopping);
        InlineHookInstallBatch batch;
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }

        bool hasEnabledCategory = false;
        bool installedAny = false;
        std::wstring failureText;
        g_coverageRemovalInProgress = false;
        g_removedCoverageRows.clear();
        g_rawCoverageObservations.clear();
        BuildFakeSuccessRuleIndex();
        for (HookBinding& bindingValue : g_bindings)
        {
            if(HookInstallationCancelled())break;
            hasEnabledCategory = CategoryEnabled(bindingValue.categoryValue) || hasEnabledCategory;
            installedAny = TryInstallBinding(bindingValue, &failureText) || installedAny;
        }
        hasEnabledCategory = ActiveConfig().enableRawFallback
            || (ActiveConfig().fakeSuccessEnabled && !FakeSuccessRules().empty())
            || hasEnabledCategory;
        if(!HookInstallationCancelled())installedAny = InstallFakeSuccessHooks(&failureText) || installedAny;
        if(!HookInstallationCancelled())installedAny = InstallRawFallbackHooks() || installedAny;
        // tier2：win32u 层剪贴板深度防御。只有 enableClipboard 打开、且策略里
        // 至少一个方向是 BLOCK 时才会真正装上任何东西，函数内部自行判定，
        // 这里无条件调用即可（与上面两行同一惯例）。
        if (ActiveConfig().enableClipboard && !HookInstallationCancelled())
        {
            SyncClipboardWin32uHooks();
        }
        const bool committed=batch.commit();
        installedAny=HasActiveInlineHookEntries();
        if(!committed)failureText+=L" | batch entry changed, cancelled or thread context unsafe; retry required";
        PublishConfiguredCoverage();
        if(HookInstallationCancelled())return false;
        if (!hasEnabledCategory)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"No hook category is enabled in current config.";
            }
            return false;
        }
        if (!installedAny && errorTextOut != nullptr)
        {
            *errorTextOut = failureText.empty()
                ? std::wstring(L"No hook installed successfully.")
                : failureText;
            return false;
        }
        if (installedAny && errorTextOut != nullptr)
        {
            *errorTextOut = failureText;
        }
        return installedAny;
    }

    bool UninstallConfiguredHooks()
    {
        const std::lock_guard<std::mutex> lock(g_hookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        g_coverageRemovalInProgress = true;
        if(!RestoreAllInlineHookEntries())return false;
        bool removed = true;
        for (HookBinding& binding : g_bindings)
            removed = UninstallInlineHook(binding.hookRecord) && removed;
        removed = UninstallExtensionHooks() && removed;
        removed = UninstallRawFallbackHooks() && removed;
        removed = UninstallFakeSuccessHooks() && removed;
        removed = UninstallAllClipboardWin32uHooks() && removed;
        if (removed) UninstallAllClipboardDataObjectVTableHooks();
        PublishConfiguredCoverage();
        return removed;
    }
    void RetryPendingHooks(std::wstring* detailTextOut)
    {
        const std::lock_guard<std::mutex> lock(g_hookOperationMutex);
        ScopedInlineHookInternalBypass hookOperationBypassScope;
        RetryPendingHooksUnlocked(detailTextOut);
    }
}

