#include "pch.h"
#include "ClipboardGuardCommon.h"

#include "../core/MonitorPipe.h"

namespace apimon
{
    namespace
    {
        // ---- 策略原子镜像：只放值类型，允许高频无锁热更新 ----
        std::atomic<std::uint32_t> g_clipboardReadActionAtomic{ static_cast<std::uint32_t>(ClipboardPolicyAction::Allow) };
        std::atomic<std::uint32_t> g_clipboardWriteActionAtomic{ static_cast<std::uint32_t>(ClipboardPolicyAction::Allow) };
        std::atomic<std::uint32_t> g_clipboardEnumActionAtomic{ static_cast<std::uint32_t>(ClipboardPolicyAction::Allow) };

        // ---- 事件序号：关联事件表一行与调用栈持久化文件里的对应记录 ----
        std::atomic<std::uint64_t> g_clipboardEventSequence{ 0 };

        // AppendDetailField 作用：往 detail 文本追加一个 " key=value" 片段，
        // 首个字段前不加空格。所有字段都用这个小工具拼，保证分隔符一致。
        void AppendDetailField(std::wstring& detailText, const wchar_t* const keyName, const std::wstring& valueText)
        {
            if (!detailText.empty())
            {
                detailText.push_back(L' ');
            }
            detailText.append(keyName);
            detailText.push_back(L'=');
            detailText.append(valueText);
        }

        void AppendDetailFieldU64(std::wstring& detailText, const wchar_t* const keyName, const unsigned long long valueNumber)
        {
            AppendDetailField(detailText, keyName, std::to_wstring(valueNumber));
        }

        // StandardClipboardFormatName 作用：
        // - 输入：formatValue 为 CF_* 常量；
        // - 处理：标准格式直接查静态表，避免每次都调 GetClipboardFormatNameW（
        //   标准格式本来就查不出名字，白跑一次系统调用）；
        // - 返回：标准格式对应的可读名字，非标准格式返回 nullptr。
        const wchar_t* StandardClipboardFormatName(const UINT formatValue)
        {
            switch (formatValue)
            {
            case CF_TEXT: return L"CF_TEXT";
            case CF_BITMAP: return L"CF_BITMAP";
            case CF_METAFILEPICT: return L"CF_METAFILEPICT";
            case CF_SYLK: return L"CF_SYLK";
            case CF_DIF: return L"CF_DIF";
            case CF_TIFF: return L"CF_TIFF";
            case CF_OEMTEXT: return L"CF_OEMTEXT";
            case CF_DIB: return L"CF_DIB";
            case CF_PALETTE: return L"CF_PALETTE";
            case CF_PENDATA: return L"CF_PENDATA";
            case CF_RIFF: return L"CF_RIFF";
            case CF_WAVE: return L"CF_WAVE";
            case CF_UNICODETEXT: return L"CF_UNICODETEXT";
            case CF_ENHMETAFILE: return L"CF_ENHMETAFILE";
            case CF_HDROP: return L"CF_HDROP";
            case CF_LOCALE: return L"CF_LOCALE";
            case CF_DIBV5: return L"CF_DIBV5";
            default: return nullptr;
            }
        }

        // BuildClipboardFormatText 作用：
        // - 输入：formatValue，0 表示"本次调用不针对具体格式"（比如 OpenClipboard）；
        // - 处理：标准格式走静态表；非标准格式尝试 GetClipboardFormatNameW（已注册的
        //   自定义格式，例如浏览器/编辑器私有格式都会有名字）；都失败就只报数值；
        // - 返回：给事件详情展示用的格式文本，不含空格（保持 key=value 拼接不歧义）。
        std::wstring BuildClipboardFormatText(const UINT formatValue)
        {
            if (formatValue == 0)
            {
                return L"-";
            }
            if (const wchar_t* const standardName = StandardClipboardFormatName(formatValue))
            {
                return standardName;
            }
            wchar_t nameBuffer[256] = {};
            const int copiedChars = ::GetClipboardFormatNameW(formatValue, nameBuffer, static_cast<int>(std::size(nameBuffer)) - 1);
            if (copiedChars > 0)
            {
                // 自定义格式名可能含空格，替换成下划线，避免破坏 detail 的 key=value 分词。
                std::wstring nameText(nameBuffer, static_cast<std::size_t>(copiedChars));
                std::replace(nameText.begin(), nameText.end(), L' ', L'_');
                return nameText;
            }
            wchar_t hexBuffer[16] = {};
            swprintf_s(hexBuffer, L"0x%X", formatValue);
            return hexBuffer;
        }

        // CurrentProcessIntegrityLevelText 作用：
        // - 处理：查询本进程令牌的强制完整性级别 SID，取最后一个子权限（RID）分档；
        //   结果和进程生命周期绑定，只需要算一次，用函数局部 static 缓存；
        // - 返回：Untrusted/Low/Medium/High/System 之一，查询失败返回 Unknown。
        const wchar_t* CurrentProcessIntegrityLevelText()
        {
            static const wchar_t* const cachedText = []() -> const wchar_t*
            {
                HANDLE tokenHandle = nullptr;
                if (::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &tokenHandle) == FALSE)
                {
                    return L"Unknown";
                }
                DWORD requiredBytes = 0;
                ::GetTokenInformation(tokenHandle, TokenIntegrityLevel, nullptr, 0, &requiredBytes);
                std::vector<unsigned char> labelBuffer(requiredBytes);
                const BOOL queryOk = (requiredBytes != 0) && ::GetTokenInformation(
                    tokenHandle, TokenIntegrityLevel, labelBuffer.data(), requiredBytes, &requiredBytes);
                ::CloseHandle(tokenHandle);
                if (queryOk == FALSE || labelBuffer.empty())
                {
                    return L"Unknown";
                }

                const auto* const labelValue = reinterpret_cast<const TOKEN_MANDATORY_LABEL*>(labelBuffer.data());
                const PSID sidValue = labelValue->Label.Sid;
                const UCHAR subAuthorityCount = *::GetSidSubAuthorityCount(sidValue);
                if (subAuthorityCount == 0)
                {
                    return L"Unknown";
                }
                const DWORD ridValue = *::GetSidSubAuthority(sidValue, static_cast<DWORD>(subAuthorityCount - 1U));
                if (ridValue < SECURITY_MANDATORY_LOW_RID) return L"Untrusted";
                if (ridValue < SECURITY_MANDATORY_MEDIUM_RID) return L"Low";
                if (ridValue < SECURITY_MANDATORY_HIGH_RID) return L"Medium";
                if (ridValue < SECURITY_MANDATORY_SYSTEM_RID) return L"High";
                return L"System";
            }();
            return cachedText;
        }

        // CurrentProcessSessionId 作用：查询并缓存本进程所属的终端服务会话号。
        DWORD CurrentProcessSessionId()
        {
            static const DWORD cachedSessionId = []() -> DWORD
            {
                DWORD sessionIdValue = 0;
                if (::ProcessIdToSessionId(::GetCurrentProcessId(), &sessionIdValue) == FALSE)
                {
                    return static_cast<DWORD>(-1);
                }
                return sessionIdValue;
            }();
            return cachedSessionId;
        }

        // ResolveClipboardOwnerText 作用：
        // - 处理：GetClipboardOwner 拿到"最后一次成功 SetClipboardData 的窗口"，
        //   反查其 PID 和进程名——不要求打开剪贴板，随时可调用；
        // - 返回："-" 表示没有所有者或解析失败，否则 "PID(进程名)"，进程名解析
        //   失败时只给 PID（例如目标是受保护进程，OpenProcess 会被拒绝）。
        std::wstring ResolveClipboardOwnerText()
        {
            const HWND ownerWindow = ::GetClipboardOwner();
            if (ownerWindow == nullptr)
            {
                return L"-";
            }
            DWORD ownerPid = 0;
            ::GetWindowThreadProcessId(ownerWindow, &ownerPid);
            if (ownerPid == 0)
            {
                return L"-";
            }

            std::wstring ownerText = std::to_wstring(ownerPid);
            const HANDLE processHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid);
            if (processHandle != nullptr)
            {
                wchar_t imagePathBuffer[MAX_PATH] = {};
                DWORD bufferChars = static_cast<DWORD>(std::size(imagePathBuffer));
                if (::QueryFullProcessImageNameW(processHandle, 0, imagePathBuffer, &bufferChars) != FALSE)
                {
                    const std::wstring fullPath(imagePathBuffer, bufferChars);
                    const std::size_t lastSlash = fullPath.find_last_of(L"\\/");
                    const std::wstring fileName = (lastSlash == std::wstring::npos) ? fullPath : fullPath.substr(lastSlash + 1U);
                    ownerText += L"(" + fileName + L")";
                }
                ::CloseHandle(processHandle);
            }
            return ownerText;
        }

        // TryComputeTextHandleSizeAndHash 作用：
        // - 输入：formatValue 决定要不要取；dataHandle 是 GetClipboardData 的返回值；
        // - 处理：只对已知一定是 HGLOBAL 承载的三个文本格式取 size + FNV-1a 哈希，
        //   其余格式（位图/元文件/HDROP 等句柄类型不同）一律跳过——对非 HGLOBAL
        //   句柄调用 GlobalLock/GlobalSize 是未定义行为，可能崩溃目标进程；
        // - 返回：true 表示 sizeOut/hashOut 已填好；false 表示不适用或读取失败。
        bool TryComputeTextHandleSizeAndHash(
            const UINT formatValue,
            const HANDLE dataHandle,
            std::size_t* const sizeOut,
            std::uint32_t* const hashOut)
        {
            if (dataHandle == nullptr || sizeOut == nullptr || hashOut == nullptr)
            {
                return false;
            }
            if (formatValue != CF_TEXT && formatValue != CF_UNICODETEXT && formatValue != CF_OEMTEXT)
            {
                return false;
            }

            const SIZE_T byteSize = ::GlobalSize(dataHandle);
            if (byteSize == 0)
            {
                return false;
            }
            const void* const lockedPointer = ::GlobalLock(dataHandle);
            if (lockedPointer == nullptr)
            {
                return false;
            }

            // FNV-1a 32 位：只用于"内容是否变化"的粗粒度审计比对，不追求密码学强度，
            // 换来的好处是不用引入额外哈希库、单趟线性扫描即可。
            std::uint32_t hashValue = 2166136261U;
            const auto* const byteData = static_cast<const unsigned char*>(lockedPointer);
            for (SIZE_T byteIndex = 0; byteIndex < byteSize; ++byteIndex)
            {
                hashValue ^= byteData[byteIndex];
                hashValue *= 16777619U;
            }
            ::GlobalUnlock(dataHandle);

            *sizeOut = static_cast<std::size_t>(byteSize);
            *hashOut = hashValue;
            return true;
        }

        constexpr USHORT kMaxCapturedFrames = 32;
        constexpr unsigned long long kStackLogMaxBytes = 4ULL * 1024ULL * 1024ULL;

        // BuildStackLogPathForCurrentProcess 作用：调用栈持久化文件路径，
        // 复用与 config/pipe 相同的会话目录约定，按 PID 区分不同受保护进程。
        std::wstring BuildStackLogPathForCurrentProcess()
        {
            return ks::winapi_monitor::joinPath(
                ks::winapi_monitor::buildSessionDirectory(),
                L"clipboard_stacks_" + std::to_wstring(::GetCurrentProcessId()) + L".log");
        }

        // ResolveFrameModuleOffsetText 作用：
        // - 输入：frameAddress 是调用栈里一帧的返回地址；
        // - 处理：反查地址所属模块基址与文件名，只做"模块名+偏移"，不接 DbgHelp/PDB——
        //   既避免仓库明确禁止的联网取符号，也避免往任意被注入的目标进程里引入
        //   重量级符号解析开销；
        // - 返回："user32.dll+0x1A2B" 形式的文本，反查失败退化为裸地址。
        std::wstring ResolveFrameModuleOffsetText(const void* const frameAddress)
        {
            HMODULE moduleHandle = nullptr;
            const BOOL foundModule = ::GetModuleHandleExW(
                GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                reinterpret_cast<LPCWSTR>(frameAddress),
                &moduleHandle);
            if (foundModule == FALSE || moduleHandle == nullptr)
            {
                wchar_t addressBuffer[32] = {};
                swprintf_s(addressBuffer, L"0x%p", frameAddress);
                return addressBuffer;
            }

            wchar_t moduleNameBuffer[MAX_PATH] = {};
            const DWORD nameChars = ::GetModuleFileNameW(moduleHandle, moduleNameBuffer, static_cast<DWORD>(std::size(moduleNameBuffer)));
            std::wstring fileName = L"?";
            if (nameChars > 0)
            {
                const std::wstring fullPath(moduleNameBuffer, nameChars);
                const std::size_t lastSlash = fullPath.find_last_of(L"\\/");
                fileName = (lastSlash == std::wstring::npos) ? fullPath : fullPath.substr(lastSlash + 1U);
            }

            const std::uintptr_t offsetValue =
                reinterpret_cast<std::uintptr_t>(frameAddress) - reinterpret_cast<std::uintptr_t>(moduleHandle);
            wchar_t offsetBuffer[24] = {};
            swprintf_s(offsetBuffer, L"0x%llX", static_cast<unsigned long long>(offsetValue));
            return fileName + L"+" + offsetBuffer;
        }

        // CaptureAndPersistClipboardCallStack 作用：
        // - 输入：sequenceNumber 用于和事件表里的行对应；
        // - 处理：抓当前线程调用栈（跳过本函数自己这一帧），逐帧反查模块+偏移，
        //   追加写入本进程专属的调用栈日志文件；文件超过 4MiB 上限先整体清空再写，
        //   保证磁盘占用有界——剪贴板调用频率低，触发这个分支代表长期没人查看过；
        // - 返回：无返回值，任何一步失败都只放弃这次记录。
        void CaptureAndPersistClipboardCallStack(const std::uint64_t sequenceNumber)
        {
            void* frameAddresses[kMaxCapturedFrames] = {};
            const USHORT capturedCount = ::CaptureStackBackTrace(1, kMaxCapturedFrames, frameAddresses, nullptr);
            if (capturedCount == 0)
            {
                return;
            }

            std::wstring logText = L"[SEQ=" + std::to_wstring(sequenceNumber) + L"]\r\n";
            for (USHORT frameIndex = 0; frameIndex < capturedCount; ++frameIndex)
            {
                logText += L"  " + std::to_wstring(frameIndex) + L": " +
                    ResolveFrameModuleOffsetText(frameAddresses[frameIndex]) + L"\r\n";
            }
            logText += L"=====\r\n";

            const std::wstring sessionDirectory = ks::winapi_monitor::buildSessionDirectory();
            ::CreateDirectoryW(sessionDirectory.c_str(), nullptr);
            const std::wstring logPath = BuildStackLogPathForCurrentProcess();

            WIN32_FILE_ATTRIBUTE_DATA fileAttributeData = {};
            if (::GetFileAttributesExW(logPath.c_str(), GetFileExInfoStandard, &fileAttributeData) != FALSE)
            {
                const ULARGE_INTEGER currentSize{ { fileAttributeData.nFileSizeLow, fileAttributeData.nFileSizeHigh } };
                if (currentSize.QuadPart > kStackLogMaxBytes)
                {
                    ::DeleteFileW(logPath.c_str());
                }
            }

            const HANDLE fileHandle = ::CreateFileW(
                logPath.c_str(),
                FILE_APPEND_DATA,
                FILE_SHARE_READ,
                nullptr,
                OPEN_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                return;
            }

            int requiredBytes = ::WideCharToMultiByte(CP_UTF8, 0, logText.c_str(), static_cast<int>(logText.size()), nullptr, 0, nullptr, nullptr);
            std::string utf8Text(static_cast<std::size_t>(requiredBytes), '\0');
            if (requiredBytes > 0)
            {
                ::WideCharToMultiByte(CP_UTF8, 0, logText.c_str(), static_cast<int>(logText.size()), utf8Text.data(), requiredBytes, nullptr, nullptr);
            }
            DWORD writtenBytes = 0;
            ::WriteFile(fileHandle, utf8Text.data(), static_cast<DWORD>(utf8Text.size()), &writtenBytes, nullptr);
            ::CloseHandle(fileHandle);
        }
    }

    void RefreshClipboardPolicyFromConfig(const MonitorConfig& configValue)
    {
        g_clipboardReadActionAtomic.store(static_cast<std::uint32_t>(configValue.clipboardReadAction), std::memory_order_relaxed);
        g_clipboardWriteActionAtomic.store(static_cast<std::uint32_t>(configValue.clipboardWriteAction), std::memory_order_relaxed);
        g_clipboardEnumActionAtomic.store(static_cast<std::uint32_t>(configValue.clipboardEnumAction), std::memory_order_relaxed);
    }

    ClipboardPolicyAction ResolveClipboardAction(const ClipboardOperationKind kind)
    {
        switch (kind)
        {
        case ClipboardOperationKind::Read:
            return static_cast<ClipboardPolicyAction>(g_clipboardReadActionAtomic.load(std::memory_order_relaxed));
        case ClipboardOperationKind::Write:
            return static_cast<ClipboardPolicyAction>(g_clipboardWriteActionAtomic.load(std::memory_order_relaxed));
        case ClipboardOperationKind::Enum:
        default:
            return static_cast<ClipboardPolicyAction>(g_clipboardEnumActionAtomic.load(std::memory_order_relaxed));
        }
    }

    std::uint64_t NextClipboardEventSequence()
    {
        return g_clipboardEventSequence.fetch_add(1ULL, std::memory_order_relaxed);
    }

    void ReportClipboardEvent(
        const ClipboardOperationKind kind,
        const wchar_t* const moduleName,
        const wchar_t* const apiName,
        const UINT formatValue,
        const HANDLE dataHandleForSizeHash,
        const ClipboardPolicyAction actionTaken,
        const bool hasReturnValue, const std::uint64_t returnBits,
        const bool hasDuration, const std::uint64_t duration100ns,
        const bool statusKnown, const std::int32_t statusCode)
    {
        const std::uint64_t sequenceNumber = NextClipboardEventSequence();

        std::wstring detailText;
        AppendDetailField(detailText, L"op",
            kind == ClipboardOperationKind::Read ? L"READ" : (kind == ClipboardOperationKind::Write ? L"WRITE" : L"ENUM"));
        if (hasReturnValue)
            AppendDetailField(detailText, L"return_origin", actionTaken == ClipboardPolicyAction::Block ? L"policy" : L"original");
        AppendDetailField(detailText, L"fmt", BuildClipboardFormatText(formatValue));
        AppendDetailFieldU64(detailText, L"fmtId", formatValue);

        std::size_t textSize = 0;
        std::uint32_t textHash = 0;
        if (TryComputeTextHandleSizeAndHash(formatValue, dataHandleForSizeHash, &textSize, &textHash))
        {
            AppendDetailFieldU64(detailText, L"size", textSize);
            wchar_t hashBuffer[16] = {};
            swprintf_s(hashBuffer, L"%08X", textHash);
            AppendDetailField(detailText, L"hash", hashBuffer);
        }

        if (kind == ClipboardOperationKind::Read)
        {
            // Owner（谁最后写入了正在被读取的内容）只对读操作有意义。
            AppendDetailField(detailText, L"owner", ResolveClipboardOwnerText());
        }
        AppendDetailFieldU64(detailText, L"session", CurrentProcessSessionId());
        AppendDetailField(detailText, L"integrity", CurrentProcessIntegrityLevelText());
        AppendDetailField(detailText, L"action",
            actionTaken == ClipboardPolicyAction::Block ? L"Blocked" :
            (actionTaken == ClipboardPolicyAction::LogOnly ? L"LoggedOnly" : L"Allowed"));
        AppendDetailFieldU64(detailText, L"seq", sequenceNumber);

        // 调用频率低（不是网络/文件那种热路径），每条事件都值得抓一次调用栈，
        // 不需要像"记录剪贴板访问"那样只在开启详细日志时才做。
        CaptureAndPersistClipboardCallStack(sequenceNumber);

        // Legacy vtable reports have no return metadata; preserve their prior policy status.
        const std::int32_t resultCode = actionTaken == ClipboardPolicyAction::Block && !hasReturnValue
            ? static_cast<std::int32_t>(ERROR_ACCESS_DENIED) : statusCode;
        const auto resultKind = statusKnown ? ks::winapi_monitor::EventResultKind::StatusCode
            : ks::winapi_monitor::EventResultKind::StatusUnknown;
        if (hasReturnValue || hasDuration)
            SendMonitorEventRawWithMetrics(ks::winapi_monitor::EventCategory::Clipboard,
                moduleName, apiName, resultCode, detailText.c_str(), hasReturnValue, returnBits, hasDuration, duration100ns, 0, resultKind);
        else
            SendMonitorEventRaw(ks::winapi_monitor::EventCategory::Clipboard, moduleName, apiName, resultCode, detailText.c_str(), resultKind);
    }
}
