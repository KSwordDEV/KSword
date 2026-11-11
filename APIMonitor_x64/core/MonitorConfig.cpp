#include "pch.h"
#include "MonitorConfig.h"

namespace apimon
{
    namespace
    {
        std::vector<std::wstring> SplitIniList(const std::wstring& listText);

        std::wstring QueryIniText(const std::wstring& iniPath, const wchar_t* keyName, const wchar_t* defaultText)
        {
            wchar_t textBuffer[4096] = {};
            const DWORD copiedLength = ::GetPrivateProfileStringW(
                L"monitor",
                keyName,
                defaultText,
                textBuffer,
                static_cast<DWORD>(std::size(textBuffer)),
                iniPath.c_str());
            return std::wstring(textBuffer, copiedLength);
        }

        bool QueryIniBool(const std::wstring& iniPath, const wchar_t* keyName, const bool defaultValue)
        {
            const UINT rawValue = ::GetPrivateProfileIntW(
                L"monitor",
                keyName,
                defaultValue ? 1U : 0U,
                iniPath.c_str());
            return rawValue != 0;
        }

        std::wstring TrimWideCopy(const std::wstring& textValue)
        {
            const auto firstIt = std::find_if_not(
                textValue.begin(),
                textValue.end(),
                [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
            const auto lastIt = std::find_if_not(
                textValue.rbegin(),
                textValue.rend(),
                [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
            if (firstIt >= lastIt)
            {
                return std::wstring();
            }
            return std::wstring(firstIt, lastIt);
        }

        std::wstring ToLowerWideCopy(std::wstring textValue)
        {
            std::transform(
                textValue.begin(),
                textValue.end(),
                textValue.begin(),
                [](const wchar_t ch) { return static_cast<wchar_t>(std::towlower(ch)); });
            return textValue;
        }

        std::vector<std::wstring> SplitWideText(const std::wstring& textValue, const wchar_t delimiter)
        {
            std::vector<std::wstring> partList;
            std::wstring currentPart;
            for (const wchar_t ch : textValue)
            {
                if (ch == delimiter)
                {
                    partList.push_back(TrimWideCopy(currentPart));
                    currentPart.clear();
                    continue;
                }
                currentPart.push_back(ch);
            }
            partList.push_back(TrimWideCopy(currentPart));
            return partList;
        }

        bool ParseUnsignedInteger(const std::wstring& textValue, std::uint64_t* valueOut)
        {
            if (valueOut == nullptr)
            {
                return false;
            }

            const std::wstring normalizedText = TrimWideCopy(textValue);
            if (normalizedText.empty())
            {
                return false;
            }

            wchar_t* endPointer = nullptr;
            errno = 0;
            if (!normalizedText.empty() && normalizedText.front() == L'-')
            {
                const long long parsedValue = std::wcstoll(normalizedText.c_str(), &endPointer, 0);
                if (errno != 0 || endPointer == normalizedText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
                {
                    return false;
                }
                *valueOut = static_cast<std::uint64_t>(parsedValue);
                return true;
            }

            const unsigned long long parsedValue = std::wcstoull(normalizedText.c_str(), &endPointer, 0);
            if (errno != 0 || endPointer == normalizedText.c_str() || (endPointer != nullptr && *endPointer != L'\0'))
            {
                return false;
            }

            *valueOut = static_cast<std::uint64_t>(parsedValue);
            return true;
        }

        FakeSuccessReturnType ParseFakeSuccessReturnType(const std::wstring& textValue)
        {
            const std::wstring lowerText = ToLowerWideCopy(TrimWideCopy(textValue));
            if (lowerText == L"bool")
            {
                return FakeSuccessReturnType::Bool;
            }
            if (lowerText == L"handle" || lowerText == L"pvoid" || lowerText == L"pointer" || lowerText == L"ptr")
            {
                return FakeSuccessReturnType::Handle;
            }
            if (lowerText == L"dword" || lowerText == L"uint" || lowerText == L"int")
            {
                return FakeSuccessReturnType::Dword;
            }
            if (lowerText == L"ntstatus" || lowerText == L"status")
            {
                return FakeSuccessReturnType::NtStatus;
            }
            if (lowerText == L"hresult")
            {
                return FakeSuccessReturnType::HResult;
            }
            if (lowerText == L"lstatus")
            {
                return FakeSuccessReturnType::LStatus;
            }
            if (lowerText == L"socket" || lowerText == L"socketint" || lowerText == L"wsa")
            {
                return FakeSuccessReturnType::SocketInt;
            }
            return FakeSuccessReturnType::Scalar;
        }

        // ParseClipboardPolicyAction 作用：
        // - 输入：INI 里 clipboard_read_action 等键的原始文本，取值 "allow"/"block"/"log_only"
        //   或直接的数字（与驱动协议 KSWORD_ARK_CLIPBOARD_POLICY_ACTION_* 一致）；
        // - 处理：不识别的文本一律按 Allow 处理（fail-open 到"不拦截"而不是 fail-closed，
        //   因为写错配置不该让一个原本没打算保护的进程被误拦)；
        // - 返回：ClipboardPolicyAction 枚举值。
        ClipboardPolicyAction ParseClipboardPolicyAction(const std::wstring& textValue)
        {
            const std::wstring lowerText = ToLowerWideCopy(TrimWideCopy(textValue));
            if (lowerText == L"block" || lowerText == L"1")
            {
                return ClipboardPolicyAction::Block;
            }
            if (lowerText == L"log_only" || lowerText == L"logonly" || lowerText == L"2")
            {
                return ClipboardPolicyAction::LogOnly;
            }
            return ClipboardPolicyAction::Allow;
        }

        FakeSuccessLastErrorKind ParseFakeSuccessLastErrorKind(const std::wstring& textValue)
        {
            const std::wstring lowerText = ToLowerWideCopy(TrimWideCopy(textValue));
            if (lowerText == L"win32" || lowerText == L"last_error" || lowerText == L"lasterror")
            {
                return FakeSuccessLastErrorKind::Win32;
            }
            if (lowerText == L"wsa" || lowerText == L"wsa_error" || lowerText == L"wsaerror")
            {
                return FakeSuccessLastErrorKind::Wsa;
            }
            return FakeSuccessLastErrorKind::None;
        }

        std::vector<FakeSuccessRule> ParseFakeSuccessRules(const std::wstring& ruleText)
        {
            std::vector<FakeSuccessRule> ruleList;
            std::wstring normalizedText = ruleText;
            std::size_t searchOffset = 0;
            while ((searchOffset = normalizedText.find(L";;", searchOffset)) != std::wstring::npos)
            {
                normalizedText.replace(searchOffset, 2, L"\n");
                searchOffset += 1;
            }

            for (const std::wstring& rawLine : SplitIniList(normalizedText))
            {
                const std::vector<std::wstring> partList = SplitWideText(rawLine, L'|');
                if (partList.size() < 6)
                {
                    continue;
                }

                FakeSuccessRule ruleValue;
                ruleValue.moduleName = TrimWideCopy(partList[0]);
                ruleValue.apiName = TrimWideCopy(partList[1]);
                ruleValue.returnType = ParseFakeSuccessReturnType(partList[2]);
                if (ruleValue.moduleName.empty() || ruleValue.apiName.empty())
                {
                    continue;
                }
                if (!ParseUnsignedInteger(partList[3], &ruleValue.returnValue))
                {
                    continue;
                }
                ruleValue.lastErrorKind = ParseFakeSuccessLastErrorKind(partList[4]);

                std::uint64_t lastErrorValue = 0;
                if (ParseUnsignedInteger(partList[5], &lastErrorValue))
                {
                    ruleValue.lastErrorValue = static_cast<std::uint32_t>(lastErrorValue & 0xFFFFFFFFULL);
                }

                ruleList.push_back(std::move(ruleValue));
                if (partList.size() > 6 && !TrimWideCopy(partList[6]).empty()) {
                    std::uint64_t stackBytes = 0;
                    if (!ParseUnsignedInteger(TrimWideCopy(partList[6]), &stackBytes) || stackBytes > 65532 || (stackBytes & 3)) {
                        ruleList.pop_back(); continue;
                    }
                    ruleList.back().x86StackBytes = static_cast<unsigned>(stackBytes);
                }
            }
            return ruleList;
        }

        // SplitIniList 作用：
        // - 输入：INI 中以分号、逗号或换行分隔的列表文本；
        // - 处理：去掉首尾空白并忽略空项，避免 UI 编辑后产生无效 Raw Hook 目标；
        // - 返回：规范化后的字符串数组，不做大小写折叠，匹配阶段再统一处理。
        std::vector<std::wstring> SplitIniList(const std::wstring& listText)
        {
            std::vector<std::wstring> itemList;
            std::wstring currentItem;
            const auto flushItem = [&itemList, &currentItem]() {
                const auto firstIt = std::find_if_not(
                    currentItem.begin(),
                    currentItem.end(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; });
                const auto lastIt = std::find_if_not(
                    currentItem.rbegin(),
                    currentItem.rend(),
                    [](const wchar_t ch) { return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n'; }).base();
                if (firstIt < lastIt)
                {
                    itemList.emplace_back(firstIt, lastIt);
                }
                currentItem.clear();
            };

            for (const wchar_t ch : listText)
            {
                if (ch == L';' || ch == L',' || ch == L'\r' || ch == L'\n')
                {
                    flushItem();
                    continue;
                }
                currentItem.push_back(ch);
            }
            flushItem();
            return itemList;
        }
    }

    bool LoadMonitorConfigForCurrentProcess(MonitorConfig* configOut, std::wstring* errorTextOut)
    {
        if (errorTextOut != nullptr)
        {
            errorTextOut->clear();
        }
        if (configOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"configOut is null.";
            }
            return false;
        }

        MonitorConfig configValue;
        configValue.targetPid = static_cast<std::uint32_t>(::GetCurrentProcessId());
        configValue.configPath = ks::winapi_monitor::buildConfigPathForPid(configValue.targetPid);

        const DWORD fileAttributes = ::GetFileAttributesW(configValue.configPath.c_str());
        if (fileAttributes == INVALID_FILE_ATTRIBUTES || (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Monitor config file does not exist: " + configValue.configPath;
            }
            return false;
        }

        configValue.pipeName = QueryIniText(
            configValue.configPath,
            L"pipe_name",
            ks::winapi_monitor::buildPipeNameForPid(configValue.targetPid).c_str());
        configValue.stopFlagPath = QueryIniText(
            configValue.configPath,
            L"stop_flag_path",
            ks::winapi_monitor::buildStopFlagPathForPid(configValue.targetPid).c_str());
        configValue.rootStopFlagPath = QueryIniText(configValue.configPath, L"root_stop_flag_path", L"");
        configValue.pauseEventName = QueryIniText(configValue.configPath, L"pause_event_name", L"");
        configValue.sessionId = QueryIniText(
            configValue.configPath,
            L"session_id",
            L"");
        configValue.agentDllPath = QueryIniText(
            configValue.configPath,
            L"agent_dll_path",
            L"");
        configValue.controllerSid = QueryIniText(
            configValue.configPath,
            L"controller_sid",
            L"");
        configValue.injectionEndpoint.pipeName = QueryIniText(configValue.configPath, L"injection_broker_pipe", L"");
        configValue.injectionEndpoint.token = QueryIniText(configValue.configPath, L"injection_broker_token", L"");
        configValue.injectionEndpoint.hostPid = ::GetPrivateProfileIntW(L"monitor", L"injection_broker_pid", 0, configValue.configPath.c_str());
        ParseUnsignedInteger(QueryIniText(configValue.configPath, L"injection_broker_creation", L"0"), &configValue.injectionEndpoint.hostCreation);
        configValue.enableFile = QueryIniBool(configValue.configPath, L"enable_file", true);
        configValue.enableRegistry = QueryIniBool(configValue.configPath, L"enable_registry", true);
        configValue.enableNetwork = QueryIniBool(configValue.configPath, L"enable_network", true);
        configValue.enableProcess = QueryIniBool(configValue.configPath, L"enable_process", true);
        configValue.enableMemory = QueryIniBool(configValue.configPath, L"enable_memory", configValue.enableProcess);
        configValue.enableThread = QueryIniBool(configValue.configPath, L"enable_thread", configValue.enableProcess);
        configValue.enableService = QueryIniBool(configValue.configPath, L"enable_service", configValue.enableProcess);
        configValue.enableSecurity = QueryIniBool(configValue.configPath, L"enable_security", configValue.enableProcess);
        configValue.enableCrypto = QueryIniBool(configValue.configPath, L"enable_crypto", configValue.enableProcess);
        configValue.enableCom = QueryIniBool(configValue.configPath, L"enable_com", configValue.enableProcess);
        configValue.enableWindow = QueryIniBool(configValue.configPath, L"enable_window", configValue.enableProcess);
        configValue.enableGui = QueryIniBool(configValue.configPath, L"enable_gui", false);
        configValue.enableLoader = QueryIniBool(configValue.configPath, L"enable_loader", true);
        configValue.autoInjectChild = QueryIniBool(configValue.configPath, L"auto_inject_child", false);
        configValue.captureCallStack = QueryIniBool(configValue.configPath, L"capture_call_stack", false);
        configValue.enableRawFallback = QueryIniBool(configValue.configPath, L"enable_raw_fallback", false);
        configValue.rawUseDefaultDenyList = QueryIniBool(configValue.configPath, L"raw_use_default_denylist", true);
        configValue.rawModuleList = SplitIniList(QueryIniText(
            configValue.configPath,
            L"raw_modules",
            ks::winapi_monitor::kDefaultRawHookModules));
        // rawDenyList 只读取用户额外规则：
        // - 输入：会话 INI 的 raw_denylist；
        // - 处理：不再把内置默认黑名单写入这里，避免 raw_use_default_denylist=false 时误伤用户自定义规则；
        // - 返回：空配置表示“没有额外规则”，内置默认规则由 HookTargets.cpp 在匹配阶段单独合并。
        configValue.rawDenyList = SplitIniList(QueryIniText(
            configValue.configPath,
            L"raw_denylist",
            L""));
        configValue.fakeSuccessEnabled = QueryIniBool(configValue.configPath, L"fake_success_enabled", false);
        configValue.fakeSuccessRawFallback = QueryIniBool(configValue.configPath, L"fake_success_raw_fallback", false);
        configValue.fakeSuccessRulesText = QueryIniText(
            configValue.configPath,
            L"fake_success_rules",
            L"");
        configValue.fakeSuccessRules = ParseFakeSuccessRules(configValue.fakeSuccessRulesText);

        configValue.enableClipboard = QueryIniBool(configValue.configPath, L"enable_clipboard", false);
        configValue.clipboardReadAction = ParseClipboardPolicyAction(
            QueryIniText(configValue.configPath, L"clipboard_read_action", L"allow"));
        configValue.clipboardWriteAction = ParseClipboardPolicyAction(
            QueryIniText(configValue.configPath, L"clipboard_write_action", L"allow"));
        configValue.clipboardEnumAction = ParseClipboardPolicyAction(
            QueryIniText(configValue.configPath, L"clipboard_enum_action", L"allow"));

        const int rawDetailLimit = static_cast<int>(::GetPrivateProfileIntW(
            L"monitor",
            L"detail_limit",
            static_cast<UINT>(ks::winapi_monitor::kMaxDetailChars - 1),
            configValue.configPath.c_str()));
        configValue.detailLimitChars = static_cast<std::size_t>(std::clamp(
            rawDetailLimit,
            64,
            static_cast<int>(ks::winapi_monitor::kMaxDetailChars - 1)));

        configValue.valid = !configValue.pipeName.empty() && !configValue.stopFlagPath.empty();
        if (!configValue.valid)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = L"Monitor config missing required pipe_name or stop_flag_path.";
            }
            return false;
        }

        *configOut = configValue;
        return true;
    }

    bool IsStopFlagPresent(const MonitorConfig& configValue)
    {
        if (configValue.stopFlagPath.empty())
        {
            return false;
        }

        const auto present = [](const std::wstring& path) {
            const DWORD attributes = ::GetFileAttributesW(path.c_str());
            return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
        };
        return present(configValue.stopFlagPath)
            || (!configValue.rootStopFlagPath.empty() && present(configValue.rootStopFlagPath));
    }
}
